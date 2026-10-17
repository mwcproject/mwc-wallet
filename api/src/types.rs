// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

use mwc_wallet_libwallet::Error;
use mwc_wallet_libwallet::ser;
use mwc_wallet_libwallet::{ParticipantMessages, TxLogEntry, TxLogEntryType, VersionedSlate};
use mwc_wallet_util::mwc_core::libtx::secp_ser;
use mwc_wallet_util::mwc_crates::base64;
use mwc_wallet_util::mwc_crates::base64::Engine as _;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_keychain::Identifier;

use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_libwallet::types::option_duration_as_secs;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_util::{ToHex, from_hex};

use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_crates::chrono::{DateTime, Utc};
use mwc_wallet_util::mwc_crates::rand::{TryRng, rngs::SysRng};
use mwc_wallet_util::mwc_crates::ring::aead;
use mwc_wallet_util::mwc_crates::serde_json::Value;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::sensitive;
use std::collections::HashMap;
use std::time::Duration;

/// Convert an explicitly supplied slatepack recipient without conflating an
/// invalid address with an absent recipient.
pub(crate) fn slatepack_recipient_public_key(
	recipient: Option<&ProvableAddress>,
) -> Result<Option<ed25519_dalek::VerifyingKey>, Error> {
	recipient
		.map(|address| address.tor_public_key())
		.transpose()
}

/// Represents a compliant JSON RPC 2.0 id.
/// Valid id: Integer, String.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "serde")]
#[serde(untagged)]
pub enum JsonId {
	/// Integer Id
	IntId(u32),
	/// String Id
	StrId(String),
}

/// Wrapper for API Tokens
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
#[serde(transparent)]
pub struct Token {
	#[serde(with = "secp_ser::option_seckey_serde")]
	/// Token to XOR mask against the stored wallet seed
	pub keychain_mask: Option<SecretKey>,
}

/// Wrapper for dalek public keys, used as addresses
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
#[serde(transparent)]
pub struct PubAddress {
	#[serde(with = "ser::dalek_pubkey_serde")]
	/// Public address
	pub address: ed25519_dalek::VerifyingKey,
}

/// Wrapper for ECDH Public keys
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
#[serde(transparent)]
pub struct ECDHPubkey {
	/// public key, flattened
	#[serde(with = "secp_ser::pubkey_serde")]
	pub ecdh_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct EncryptedBody {
	/// nonce used for encryption
	pub nonce: String,
	/// Encrypted base64 body request
	pub body_enc: String,
}

impl EncryptedBody {
	/// Encrypts and encodes json as base 64
	pub fn from_json(json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		Self::from_json_with_aad(json_in, enc_key, &[])
	}

	fn from_json_with_aad(json_in: &Value, enc_key: &SecretKey, aad: &[u8]) -> Result<Self, Error> {
		let mut to_encrypt = sensitive::serialize_json(json_in).map_err(|e| {
			Error::APIEncryption(format!("EncryptedBody Enc: Unable to encode JSON, {}", e))
		})?;

		let mut nonce = [0u8; 12];
		SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
			Error::APIEncryption(format!("Unable to generate encryption nonce, {}", e))
		})?;

		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &enc_key.0)
			.map_err(|e| Error::GenericError(format!("aead key creation error, {}", e)))?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let tag = sealing_key
			.seal_in_place_separate_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::from(aad),
				&mut to_encrypt[..],
			)
			.map_err(|e| Error::APIEncryption(format!("EncryptedBody: encryption failed, {}", e)))?;

		// Join the ciphertext and tag only after all plaintext has been encrypted.
		let sealed = [&to_encrypt[..], tag.as_ref()].concat();

		Ok(EncryptedBody {
			nonce: nonce.to_hex(),
			body_enc: base64::engine::general_purpose::STANDARD.encode(sealed),
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
		self.decrypt_with_aad(dec_key, &[])
	}

	/// Decode the serialized AES-GCM nonce, requiring its exact 96-bit form.
	pub fn nonce_bytes(&self) -> Result<[u8; 12], Error> {
		let nonce = from_hex(&self.nonce).map_err(|e| {
			Error::APIEncryption(format!(
				"EncryptedBody Dec: Encrypted request contains invalid nonce, {}",
				e
			))
		})?;
		nonce.try_into().map_err(|nonce: Vec<u8>| {
			Error::APIEncryption(format!(
				"EncryptedBody Dec: Invalid Nonce length {}, expected 12",
				nonce.len()
			))
		})
	}

	fn decrypt_with_aad(&self, dec_key: &SecretKey, aad: &[u8]) -> Result<Value, Error> {
		let mut to_decrypt = Zeroizing::new(
			base64::engine::general_purpose::STANDARD
				.decode(&self.body_enc)
				.map_err(|e| {
					Error::APIEncryption(format!(
						"EncryptedBody Dec: Encrypted request contains invalid Base64, {}",
						e
					))
				})?,
		);
		let nonce = self.nonce_bytes()?;
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &dec_key.0)
			.map_err(|e| Error::GenericError(format!("aead key creation error, {}", e)))?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let plaintext_len = opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::from(aad),
				&mut *to_decrypt,
			)
			.map_err(|e| Error::APIEncryption(format!("EncryptedBody: decryption failed, {}", e)))?
			.len();
		to_decrypt.truncate(plaintext_len);

		Ok(serde_json::from_slice(&to_decrypt)
			.map_err(|e| Error::APIEncryption(format!("EncryptedBody Dec: Invalid JSON, {}", e)))?)
	}
}

fn append_aad_field(aad: &mut Vec<u8>, value: &[u8]) {
	aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
	aad.extend_from_slice(value);
}

fn rpc_aad(direction: &[u8], jsonrpc: &str, method: &str, id: &JsonId) -> Vec<u8> {
	let mut aad = Vec::new();
	append_aad_field(&mut aad, b"mwc-owner-api-v3");
	append_aad_field(&mut aad, direction);
	append_aad_field(&mut aad, jsonrpc.as_bytes());
	append_aad_field(&mut aad, method.as_bytes());
	match id {
		JsonId::IntId(value) => {
			append_aad_field(&mut aad, b"integer");
			append_aad_field(&mut aad, &value.to_be_bytes());
		}
		JsonId::StrId(value) => {
			append_aad_field(&mut aad, b"string");
			append_aad_field(&mut aad, value.as_bytes());
		}
	}
	aad
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
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
		let jsonrpc = "2.0".to_owned();
		let method = "encrypted_request_v3".to_owned();
		let aad = rpc_aad(b"request", &jsonrpc, &method, id);
		Ok(EncryptedRequest {
			jsonrpc,
			method,
			id: id.clone(),
			params: EncryptedBody::from_json_with_aad(json_in, enc_key, &aad)?,
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
		let aad = rpc_aad(b"request", &self.jsonrpc, &self.method, &self.id);
		self.params.decrypt_with_aad(dec_key, &aad)
	}
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
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
		let jsonrpc = "2.0".to_owned();
		let aad = rpc_aad(b"response", &jsonrpc, "encrypted_response_v3", id);
		let mut result_set = HashMap::new();
		result_set.insert(
			"Ok".to_string(),
			EncryptedBody::from_json_with_aad(json_in, enc_key, &aad)?,
		);
		Ok(EncryptedResponse {
			jsonrpc,
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
		let aad = rpc_aad(
			b"response",
			&self.jsonrpc,
			"encrypted_response_v3",
			&self.id,
		);
		self.result
			.get("Ok")
			.ok_or(Error::GenericError(format!(
				"Not found expetced 'OK' value at response"
			)))?
			.decrypt_with_aad(dec_key, &aad)
	}
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct EncryptionError {
	/// code
	pub code: i32,
	/// message
	pub message: String,
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
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
#[serde(crate = "serde")]
pub struct TxLogEntryAPI {
	#[serde(default = "TxLogEntryAPI::default_parent_key_id")]
	pub parent_key_id: Identifier,
	#[serde(default)]
	pub id: u32,
	#[serde(default)]
	pub tx_slate_id: Option<Uuid>,
	#[serde(default = "TxLogEntryAPI::default_tx_type")]
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
	pub input_commits: Vec<String>,
	/// Output commits as Strings, defined for send & recieve
	#[serde(default)]
	pub output_commits: Vec<String>,
	#[serde(with = "option_duration_as_secs", default)]
	pub reverted_after: Option<Duration>,
}

impl TxLogEntryAPI {
	/// Return a new blank with TS initialised with next entry
	pub fn from_txlogentry(tle: &TxLogEntry) -> Self {
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

	fn default_tx_type() -> TxLogEntryType {
		TxLogEntryType::TxSent
	}
}

/// Information about slatepack
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
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
fn encrypted_body_preserves_wire_format_and_authenticates_aad() -> Result<(), Error> {
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;

	let secp = Secp256k1::new()?;
	let key = SecretKey::from_slice(&secp, &[42; 32])?;
	let value = serde_json::json!({
		"id": 1,
		"jsonrpc": "2.0",
		"result": {"Ok": "example wallet recovery phrase"},
		"escaped": "\"\n\u{0000}é",
		"numbers": [u64::MAX, i64::MIN],
	});
	let aad = b"test response metadata";
	let encrypted = EncryptedBody::from_json_with_aad(&value, &key, aad)?;

	// Compare with the original ciphertext-plus-tag wire format.
	let mut expected = serde_json::to_vec(&value).unwrap();
	aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key.0).unwrap())
		.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(encrypted.nonce_bytes()?),
			aead::Aad::from(aad),
			&mut expected,
		)
		.unwrap();
	assert_eq!(
		encrypted.body_enc,
		base64::engine::general_purpose::STANDARD.encode(expected)
	);
	assert_eq!(encrypted.decrypt_with_aad(&key, aad)?, value);
	assert!(encrypted.decrypt_with_aad(&key, b"wrong metadata").is_err());
	Ok(())
}

#[test]
fn encrypted_request() -> Result<(), Error> {
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;
	use mwc_wallet_util::mwc_util::from_hex;

	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let shared_key = {
		let sec_key_bytes = from_hex(sec_key_str).unwrap();
		let secp = Secp256k1::new()?;
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
	let mut overlong_nonce = enc_req.clone();
	overlong_nonce.params.nonce.push_str("00");
	assert!(overlong_nonce.decrypt(&shared_key).is_err());
	let mut short_nonce = enc_req.clone();
	short_nonce.params.nonce.truncate(22);
	assert!(short_nonce.decrypt(&shared_key).is_err());
	let mut altered_request_id = enc_req.clone();
	altered_request_id.id = JsonId::StrId("different".to_string());
	assert!(altered_request_id.decrypt(&shared_key).is_err());
	let mut altered_request_method = enc_req.clone();
	altered_request_method.method = "different_method".to_string();
	assert!(altered_request_method.decrypt(&shared_key).is_err());

	let enc_res = EncryptedResponse::from_json(&JsonId::IntId(1), &req, &shared_key)?;
	println!("{:?}", enc_res);
	println!("{:?}", enc_res.as_json_str()?);
	let dec_res = enc_res.decrypt(&shared_key)?;
	println!("{:?}", dec_res);
	assert_eq!(req, dec_res);
	let mut altered_response_id = enc_res;
	altered_response_id.id = JsonId::IntId(2);
	assert!(altered_response_id.decrypt(&shared_key).is_err());
	Ok(())
}

#[test]
fn invalid_slatepack_recipient_is_not_treated_as_absent() {
	let recipient: ProvableAddress = serde_json::from_value(serde_json::json!("invalid")).unwrap();

	assert!(slatepack_recipient_public_key(Some(&recipient)).is_err());
	assert!(slatepack_recipient_public_key(None).unwrap().is_none());
}
