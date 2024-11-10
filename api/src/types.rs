// Copyright 2021 The Mwc Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::core::libtx::secp_ser;
use crate::keychain::Identifier;
use crate::libwallet::dalek_ser;
use crate::libwallet::Error;
use crate::libwallet::{
	ParticipantMessages, StoredProofInfo, TxLogEntry, TxLogEntryType, VersionedSlate,
};
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen;
use crate::util::{from_hex, ToHex};
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_libwallet::types::option_duration_as_secs;

use base64;
use chrono::{DateTime, Utc};
use ed25519_dalek::PublicKey as DalekPublicKey;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use rand::{thread_rng, Rng};
use ring::aead;
use serde_json::{self, Value};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Represents a compliant JSON RPC 2.0 id.
/// Valid id: Integer, String.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum JsonId {
	/// Integer Id
	IntId(u32),
	/// String Id
	StrId(String),
}

/// Wrapper for API Tokens
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct Token {
	#[serde(with = "secp_ser::option_seckey_serde")]
	/// Token to XOR mask against the stored wallet seed
	pub keychain_mask: Option<SecretKey>,
}

/// Wrapper for dalek public keys, used as addresses
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct PubAddress {
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	/// Public address
	pub address: DalekPublicKey,
}

/// Wrapper for ECDH Public keys
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct ECDHPubkey {
	/// public key, flattened
	#[serde(with = "secp_ser::pubkey_serde")]
	pub ecdh_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedBody {
	/// nonce used for encryption
	pub nonce: String,
	/// Encrypted base64 body request
	pub body_enc: String,
}

impl EncryptedBody {
	/// Encrypts and encodes json as base 64
	pub fn from_json(json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		let mut to_encrypt = serde_json::to_string(&json_in)
			.map_err(|e| {
				Error::APIEncryption(format!("EncryptedBody Enc: Unable to encode JSON, {}", e))
			})?
			.as_bytes()
			.to_vec();

		let nonce: [u8; 12] = thread_rng().gen();

		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &enc_key.0).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = sealing_key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aad,
			&mut to_encrypt,
		);
		if let Err(e) = res {
			return Err(Error::APIEncryption(format!(
				"EncryptedBody: encryption failed, {}",
				e
			)));
		}

		Ok(EncryptedBody {
			nonce: nonce.to_hex(),
			body_enc: base64::encode(&to_encrypt),
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).map_err(|e| {
			Error::APIEncryption(format!("EncryptedBody: JSON serialization failed, {}", e))
		})?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedBody: JSON String serialization failed, {}",
				e
			))
		})?;
		Ok(res)
	}

	/// Return original request
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		let mut to_decrypt = base64::decode(&self.body_enc).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedBody Dec: Encrypted request contains invalid Base64, {}",
				e
			))
		})?;

		let nonce = from_hex(&self.nonce).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedBody Dec: Encrypted request contains invalid nonce, {}",
				e
			))
		})?;

		if nonce.len() < 12 {
			return Err(Error::APIEncryption(
				"EncryptedBody Dec: Invalid Nonce length".to_string(),
			));
		}
		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &dec_key.0).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		opening_key
			.open_in_place(aead::Nonce::assume_unique_for_key(n), aad, &mut to_decrypt)
			.map_err(|e| {
				Error::APIEncryption(format!("EncryptedBody: decryption failed, {}", e))
			})?;

		for _ in 0..aead::AES_256_GCM.tag_len() {
			to_decrypt.pop();
		}

		let decrypted = String::from_utf8(to_decrypt)
			.map_err(|_| Error::APIEncryption("EncryptedBody Dec: Invalid UTF-8".to_string()))?;

		Ok(serde_json::from_str(&decrypted)
			.map_err(|e| Error::APIEncryption(format!("EncryptedBody Dec: Invalid JSON, {}", e)))?)
	}
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedRequest {
	/// JSON RPC response
	pub jsonrpc: String,
	/// method
	pub method: String,
	/// id
	pub id: JsonId,
	/// Body params, which includes nonce and encrypted request
	pub params: EncryptedBody,
}

impl EncryptedRequest {
	/// from json
	pub fn from_json(id: &JsonId, json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		Ok(EncryptedRequest {
			jsonrpc: "2.0".to_owned(),
			method: "encrypted_request_v3".to_owned(),
			id: id.clone(),
			params: EncryptedBody::from_json(json_in, enc_key)?,
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedRequest: JSON serialization failed, {}",
				e
			))
		})?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedRequest: JSON String serialization failed, {}",
				e
			))
		})?;
		Ok(res)
	}

	/// Return decrypted body
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		self.params.decrypt(dec_key)
	}
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedResponse {
	/// JSON RPC response
	pub jsonrpc: String,
	/// id
	pub id: JsonId,
	/// result
	pub result: HashMap<String, EncryptedBody>,
}

impl EncryptedResponse {
	/// from json
	pub fn from_json(id: &JsonId, json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		let mut result_set = HashMap::new();
		result_set.insert(
			"Ok".to_string(),
			EncryptedBody::from_json(json_in, enc_key)?,
		);
		Ok(EncryptedResponse {
			jsonrpc: "2.0".to_owned(),
			id: id.clone(),
			result: result_set,
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedResponse: JSON serialization failed, {}",
				e
			))
		})?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedResponse: JSON String serialization failed, {}",
				e
			))
		})?;
		Ok(res)
	}

	/// Return decrypted body
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		self.result
			.get("Ok")
			.ok_or(Error::GenericError(format!(
				"Not found expetced 'OK' value at response"
			)))?
			.decrypt(dec_key)
	}
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionError {
	/// code
	pub code: i32,
	/// message
	pub message: String,
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionErrorResponse {
	/// JSON RPC response
	pub jsonrpc: String,
	/// id
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// error
	pub error: EncryptionError,
}

impl EncryptionErrorResponse {
	/// Create new response
	pub fn new(id: u64, code: i32, message: &str) -> Self {
		EncryptionErrorResponse {
			jsonrpc: "2.0".to_owned(),
			id: id,
			error: EncryptionError {
				code: code,
				message: message.to_owned(),
			},
		}
	}

	/// return serialized JSON self
	pub fn as_json_value(&self) -> Value {
		let res = serde_json::to_value(self).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedResponse: JSON serialization failed, {}",
				e
			))
		});
		match res {
			Ok(r) => r,
			// proverbial "should never happen"
			Err(r) => serde_json::json!({
					"json_rpc" : "2.0",
					"id" : "1",
					"error" : {
						"message": format!("internal error serialising json error response {}", r),
						"code": -32000
					}
				}
			),
		}
	}
}

/// TxLogEntry has commits  as pedersen::Commitment.  It is not user friendly,
/// And we can't change TxLogEntry because of relased version. We can only convert for API
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxLogEntryAPI {
	#[serde(default = "TxLogEntryAPI::default_parent_key_id")]
	pub parent_key_id: Identifier,
	#[serde(default)]
	pub id: u32,
	#[serde(default)]
	pub tx_slate_id: Option<Uuid>,
	pub tx_type: TxLogEntryType,
	#[serde(default)]
	pub address: Option<String>,
	/// #[serde(with = "tx_date_format")]
	#[serde(default = "TxLogEntryAPI::default_creation_ts")]
	pub creation_ts: DateTime<Utc>,
	/// Time this tx was confirmed (by this wallet)
	/// #[serde(default, with = "opt_tx_date_format")]
	#[serde(default)]
	pub confirmation_ts: Option<DateTime<Utc>>,
	#[serde(default)]
	pub confirmed: bool,
	#[serde(default = "TxLogEntry::default_output_height")]
	pub output_height: u64,
	#[serde(default)]
	pub num_inputs: usize,
	#[serde(default)]
	pub num_outputs: usize,
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default)]
	pub amount_credited: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default)]
	pub amount_debited: u64,
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub fee: Option<u64>,
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_cutoff_height: Option<u64>,
	#[serde(default)]
	pub messages: Option<ParticipantMessages>,
	#[serde(default)]
	pub stored_tx: Option<String>,
	#[serde(with = "secp_ser::option_commitment_serde")]
	#[serde(default)]
	pub kernel_excess: Option<pedersen::Commitment>,
	#[serde(with = "secp_ser::option_commitment_serde")]
	#[serde(default)]
	pub kernel_offset: Option<pedersen::Commitment>,
	#[serde(default)]
	pub kernel_lookup_min_height: Option<u64>,
	#[serde(default)]
	pub payment_proof: Option<StoredProofInfo>,
	#[serde(default)]
	pub input_commits: Vec<String>,
	/// Output commits as Strings, defined for send & recieve
	#[serde(default)]
	pub output_commits: Vec<String>,
	#[serde(with = "option_duration_as_secs", default)]
	pub reverted_after: Option<Duration>,
}

impl TxLogEntryAPI {
	/// Return a new blank with TS initialised with next entry
	pub fn from_txlogemtry(tle: &TxLogEntry) -> Self {
		TxLogEntryAPI {
			parent_key_id: tle.parent_key_id.clone(),
			tx_type: tle.tx_type.clone(),
			address: tle.address.clone(),
			id: tle.id.clone(),
			tx_slate_id: tle.tx_slate_id.clone(),
			creation_ts: tle.creation_ts.clone(),
			confirmation_ts: tle.confirmation_ts.clone(),
			confirmed: tle.confirmed.clone(),
			output_height: tle.output_height.clone(),
			amount_credited: tle.amount_credited.clone(),
			amount_debited: tle.amount_debited.clone(),
			num_inputs: tle.num_inputs.clone(),
			num_outputs: tle.num_outputs.clone(),
			fee: tle.fee.clone(),
			ttl_cutoff_height: tle.ttl_cutoff_height.clone(),
			messages: tle.messages.clone(),
			stored_tx: tle.stored_tx.clone(),
			kernel_excess: tle.kernel_excess.clone(),
			kernel_offset: tle.kernel_offset.clone(),
			kernel_lookup_min_height: tle.kernel_lookup_min_height.clone(),
			payment_proof: tle.payment_proof.clone(),
			input_commits: tle.input_commits.iter().map(|c| c.0.to_hex()).collect(),
			output_commits: tle.output_commits.iter().map(|c| c.0.to_hex()).collect(),
			reverted_after: tle.reverted_after.clone(),
		}
	}

	fn default_parent_key_id() -> Identifier {
		Identifier::zero()
	}
	fn default_creation_ts() -> DateTime<Utc> {
		Utc::now()
	}
}

/// Information about slatepack
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlatepackInfo {
	/// Slate V3 or V2
	pub slate: VersionedSlate,
	/// Sender address. No receiver address. Wallet can try to decode it to check if receiver this wallet
	/// Sender address is needed to respond back, or for encoding/decoding
	/// If none, slatepack was not encrypted
	pub sender: Option<ProvableAddress>,
	// Receiver address, none for not encrypted
	pub recipient: Option<ProvableAddress>,
	/// The content of the slate.
	pub content: SlatePurpose,
}

#[test]
fn encrypted_request() -> Result<(), Error> {
	use crate::util::from_hex;
	use mwc_wallet_util::mwc_util::static_secp_instance;

	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let shared_key = {
		let sec_key_bytes = from_hex(sec_key_str).unwrap();
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		SecretKey::from_slice(&secp, &sec_key_bytes)?
	};
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"method": "accounts",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		}
	});
	let enc_req =
		EncryptedRequest::from_json(&JsonId::StrId(String::from("1")), &req, &shared_key)?;
	println!("{:?}", enc_req);
	let dec_req = enc_req.decrypt(&shared_key)?;
	println!("{:?}", dec_req);
	assert_eq!(req, dec_req);
	let enc_res = EncryptedResponse::from_json(&JsonId::IntId(1), &req, &shared_key)?;
	println!("{:?}", enc_res);
	println!("{:?}", enc_res.as_json_str()?);
	let dec_res = enc_res.decrypt(&shared_key)?;
	println!("{:?}", dec_res);
	assert_eq!(req, dec_res);
	Ok(())
}
