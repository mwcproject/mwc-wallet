// Copyright 2020 The MWC Developers
//
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

use super::base58::Base58;
use crate::error::Error;
use crate::proof::crypto;
use crate::proof::hasher;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use mwc_wallet_util::mwc_crates::sha2::{Digest, Sha512};
use mwc_wallet_util::mwc_crates::x25519_dalek;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_util::OnionV3Address;
use std::convert::TryFrom;
use std::fmt::{self, Display};

/// Address prefixes for mainnet
pub const PROOFABLE_ADDRESS_VERSION_MAINNET: [u8; 2] = [1, 69];
/// Address prefixes for floonet
pub const PROOFABLE_ADDRESS_VERSION_TESTNET: [u8; 2] = [1, 121];

/// Address that can have a proof. Such address need to be able to convertable to
/// the public key
#[derive(Serialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct ProvableAddress {
	/// Public key that is an address
	pub public_key: String,
	/// Place holder for mwc713 backcompability. Value is empty string
	#[serde(default = "ProvableAddress::default_domain")]
	pub domain: String,
	/// Place holder for mwc713 backcompability. Value is None
	#[serde(default = "ProvableAddress::default_port")]
	pub port: Option<u16>,
}

impl Display for ProvableAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.public_key)
	}
}

impl ProvableAddress {
	/// Build an empty instance
	pub fn blank() -> Self {
		Self {
			public_key: String::new(),
			domain: String::new(),
			port: None,
		}
	}

	/// new instance
	pub fn from_str(secp: &Secp256k1, context_id: u32, public_key: &str) -> Result<Self, Error> {
		let address = Self {
			public_key: String::from(public_key),
			domain: String::new(),
			port: None,
		};
		match public_key.len() {
			52 => {
				address.validate_mqs(secp, context_id)?;
			}
			56 => {
				let onion = OnionV3Address::try_from(public_key)?;
				onion.to_ed25519()?;
				if onion.to_ov3_str() != public_key {
					return Err(Error::PaymentProofAddress(
						"Onion payment-proof address is not canonical".to_string(),
					));
				}
			}
			length => {
				return Err(Error::PaymentProofAddress(format!(
					"Payment-proof address has invalid length {}, expected 52-character MQS or 56-character OnionV3",
					length
				)));
			}
		}
		Ok(address)
	}

	/// Create address from public key
	pub fn from_pub_key(
		secp: &Secp256k1,
		context_id: u32,
		public_key: &PublicKey,
	) -> Result<Self, Error> {
		Ok(Self {
			public_key: public_key.to_base58_check(secp, version_bytes(context_id))?,
			domain: String::new(),
			port: None,
		})
	}

	/// Get public key that represent this address
	pub fn public_key(&self, secp: &Secp256k1, context_id: u32) -> Result<PublicKey, Error> {
		PublicKey::from_base58_check(secp, &self.public_key, version_bytes(context_id))
	}

	/// Validate that this is the canonical MQS address for the active network.
	///
	/// Payment proofs use the legacy concatenation
	/// `kernel || sender_address || decimal_amount`. Requiring the sender
	/// address to have this one canonical 52-character encoding fixes the
	/// sender/amount boundary. Do not relax this to variable-length or merely
	/// parseable addresses without also redesigning the proof protocol.
	pub fn validate_mqs(&self, secp: &Secp256k1, context_id: u32) -> Result<PublicKey, Error> {
		if self.public_key.len() != 52 {
			return Err(Error::PaymentProofAddress(format!(
				"MQS payment-proof address has invalid length {}, expected 52",
				self.public_key.len()
			)));
		}
		let public_key = self.public_key(secp, context_id).map_err(|_| {
			Error::PaymentProofAddress(
				"MQS payment-proof address has invalid encoding or belongs to another network"
					.to_string(),
			)
		})?;
		let canonical = public_key.to_base58_check(secp, version_bytes(context_id))?;
		if canonical != self.public_key {
			return Err(Error::PaymentProofAddress(
				"MQS payment-proof address is not canonical".to_string(),
			));
		}
		Ok(public_key)
	}
	/// Create address from public key
	pub fn from_tor_pub_key(public_key: &ed25519_dalek::VerifyingKey) -> Result<Self, Error> {
		Ok(Self {
			public_key: OnionV3Address::from_bytes(*public_key.as_bytes())?.to_ov3_str(),
			domain: String::new(),
			port: None,
		})
	}

	/// Get public key that represent this address
	pub fn tor_public_key(&self) -> Result<ed25519_dalek::VerifyingKey, Error> {
		let addr = OnionV3Address::try_from(self.public_key.as_str())?;
		Ok(addr.to_ed25519()?)
	}

	fn default_domain() -> String {
		String::new()
	}

	fn default_port() -> Option<u16> {
		None
	}

	/// Seralizes option provableAddress as a string.
	pub fn serialize_option_as_string<S>(
		address: &Option<ProvableAddress>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match address {
			Some(address) => serializer.serialize_str(&address.public_key),
			None => serializer.serialize_none(),
		}
	}

	/// Seralizes a provableAddress as a string.
	pub fn serialize_as_string<S>(
		address: &ProvableAddress,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&address.public_key)
	}
}

/// Deserializer from the string and the full data struct...
impl<'de> Deserialize<'de> for ProvableAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(crate = "serde")]
		#[serde(untagged)]
		enum Helper {
			String(String),
			Struct {
				public_key: String,
				#[serde(default = "ProvableAddress::default_domain")]
				domain: String,
				#[serde(default = "ProvableAddress::default_port")]
				port: Option<u16>,
			},
		}

		Ok(match Helper::deserialize(deserializer)? {
			Helper::String(pk) => ProvableAddress {
				public_key: pk,
				domain: ProvableAddress::default_domain(),
				port: ProvableAddress::default_port(),
			},
			Helper::Struct {
				public_key,
				domain,
				port,
			} => ProvableAddress {
				public_key,
				domain,
				port,
			},
		})
	}
}

/// provable address prefix.
pub fn version_bytes(context_id: u32) -> Vec<u8> {
	if global::is_mainnet(context_id) {
		PROOFABLE_ADDRESS_VERSION_MAINNET.to_vec()
	} else {
		PROOFABLE_ADDRESS_VERSION_TESTNET.to_vec()
	}
}

///convert a tor onion address to the pub key
pub fn address_to_pubkey(addr: String) -> String {
	//if it is an onion address, need to remove the http:// or https:// and .onion.
	let mut addr_change = addr;
	if addr_change.starts_with("HTTP://") || addr_change.starts_with("HTTPS://") {
		addr_change = addr_change.replace("HTTP://", "");
		addr_change = addr_change.replace("HTTPS://", "");
	}
	if addr_change.starts_with("http://") || addr_change.starts_with("http://") {
		addr_change = addr_change.replace("http://", "");
		addr_change = addr_change.replace("https://", "");
	}
	if addr_change.ends_with(".ONION") {
		addr_change = addr_change.replace(".ONION", "");
	}
	if addr_change.ends_with(".onion") {
		addr_change = addr_change.replace(".onion", "");
	}
	if addr_change.ends_with(".ONION/") {
		addr_change = addr_change.replace(".ONION/", "");
	}
	if addr_change.ends_with(".onion/") {
		addr_change = addr_change.replace(".onion/", "");
	}
	let addr_to_return = addr_change.into();
	return addr_to_return;
}

/// Format of the requested address.
pub enum ProofAddressType {
	/// MQS address format
	MQS,
	/// Tor v3 (Onion) address format
	Onion,
}

/// provable address public key
pub fn payment_proof_address<K>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	addr_type: ProofAddressType,
	address_index: u32,
) -> Result<ProvableAddress, Error>
where
	K: Keychain,
{
	payment_proof_address_from_index(secp, context_id, keychain, address_index, addr_type)
}

/// provable address public key
pub fn payment_proof_address_from_index<K>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	index: u32,
	addr_type: ProofAddressType,
) -> Result<ProvableAddress, Error>
where
	K: Keychain,
{
	let secret_key = payment_proof_address_secret(secp, context_id, keychain, index)?;

	match addr_type {
		ProofAddressType::MQS => {
			let sender_address_pub_key = crypto::public_key_from_secret_key(secp, &secret_key)?;
			ProvableAddress::from_pub_key(secp, context_id, &sender_address_pub_key)
		}
		ProofAddressType::Onion => {
			let onion_address = OnionV3Address::from_private(&secret_key.0)?;
			let dalek_pubkey = onion_address.to_ov3_str();
			Ok(ProvableAddress::from_str(secp, context_id, &dalek_pubkey)?)
		}
	}
}

/// Current secret that is used for public wallet address
pub fn payment_proof_address_secret<K>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	address_index: u32,
) -> Result<SecretKey, Error>
where
	K: Keychain,
{
	hasher::derive_address_key(secp, context_id, keychain, address_index).map_err(|e| e.into())
}

/// Current secret that is used for public wallet address, DalekSecret type
pub fn payment_proof_address_dalek_secret<K>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	address_index: u32,
) -> Result<ed25519_dalek::SigningKey, Error>
where
	K: Keychain,
{
	let sk = payment_proof_address_secret(secp, context_id, keychain, address_index)?;
	let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&sk.0);
	Ok(dalek_sk)
}

/// Get a payment address as secp Public Key (for MQS)
pub fn payment_proof_address_pubkey<K>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	address_index: u32,
) -> Result<PublicKey, Error>
where
	K: Keychain,
{
	let sender_address_secret_key =
		payment_proof_address_secret(secp, context_id, keychain, address_index)?;
	crypto::public_key_from_secret_key(secp, &sender_address_secret_key)
}

/// Build Tor public Key from the secret
pub fn secret_2_tor_pub(secret: &SecretKey) -> Result<ed25519_dalek::VerifyingKey, Error> {
	let signing = ed25519_dalek::SigningKey::from_bytes(&secret.0);
	let d_pub_key = signing.verifying_key();
	Ok(d_pub_key)
}

/// Conver the Secret to match what tor_pub_2_slatepack_pub calculate
/// Here id explanation https://blog.filippo.io/using-ed25519-keys-for-encryption/
pub fn tor_secret_2_slatepack_secret(
	secret: &ed25519_dalek::SigningKey,
) -> x25519_dalek::StaticSecret {
	let mut hasher = Sha512::new();
	hasher.update(secret.as_bytes());

	// Both halves of the Ed25519 SHA-512 expansion are secret. Finalize
	// directly into zeroizing storage so no unprotected digest result is
	// created, then protect the copied X25519 scalar until StaticSecret owns it.
	let mut expanded = Zeroizing::new([0u8; 64]);
	hasher.finalize_into((&mut *expanded).into());

	let mut x25519_scalar = Zeroizing::new([0u8; 32]);
	x25519_scalar.copy_from_slice(&expanded[..32]);
	x25519_dalek::StaticSecret::from(*x25519_scalar)
}

/// Build slatepack public key from tor public key
/// https://blog.filippo.io/using-ed25519-keys-for-encryption/
pub fn tor_pub_2_slatepack_pub(
	tor_pub_key: &ed25519_dalek::VerifyingKey,
) -> Result<x25519_dalek::PublicKey, Error> {
	if tor_pub_key.is_weak() {
		return Err(Error::ED25519Key(
			"Small-order public keys cannot be used for Slatepack encryption".to_owned(),
		));
	}

	Ok(x25519_dalek::PublicKey::from(
		tor_pub_key.to_montgomery().to_bytes(),
	))
}

#[cfg(test)]
mod tests {
	use super::ProvableAddress;
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;

	#[test]
	fn canonical_mqs_validation_rejects_appended_amount_digit() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::new().unwrap();
		let secret = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let public = PublicKey::from_secret_key(&secp, &secret).unwrap();
		let canonical = ProvableAddress::from_pub_key(&secp, 0, &public).unwrap();
		assert_eq!(canonical.public_key.len(), 52);
		assert!(canonical.validate_mqs(&secp, 0).is_ok());

		let forged = ProvableAddress {
			public_key: format!("{}1", canonical.public_key),
			domain: String::new(),
			port: None,
		};
		assert!(forged.validate_mqs(&secp, 0).is_err());
	}
}
