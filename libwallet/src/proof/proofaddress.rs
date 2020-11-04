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
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::key::SecretKey;
use crate::proof::crypto;
use crate::proof::hasher;
use ed25519_dalek::PublicKey as DalekPublicKey;
use grin_core::global;
use grin_wallet_util::grin_keychain::Keychain;
use grin_wallet_util::OnionV3Address;
use serde::{Deserialize, Deserializer, Serializer};
use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicU32, Ordering};

/// Address prefixes for mainnet
pub const PROOFABLE_ADDRESS_VERSION_MAINNET: [u8; 2] = [1, 69];
/// Address prefixes for floonet
pub const PROOFABLE_ADDRESS_VERSION_TESTNET: [u8; 2] = [1, 121];

lazy_static! {
	/// Wallet address derive index
	static ref ADDRESS_INDEX: AtomicU32 = AtomicU32::new(0);
}

/// Set address derivative index
pub fn set_address_index(addr_idx: u32) {
	ADDRESS_INDEX.store(addr_idx, Ordering::Relaxed);
}
/// Get address derivative index
pub fn get_address_index() -> u32 {
	ADDRESS_INDEX.load(Ordering::Relaxed)
}

/// Address that can have a proof. Such address need to be able to convertable to
/// the public key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvableAddress {
	/// Public key that is an address
	pub public_key: String,
	/// Place holder for mwc713 backcompability. Value is empty string
	pub domain: String,
	/// /// Place holder for mwc713 backcompability. Value is None
	pub port: Option<u16>,
}

impl Display for ProvableAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.public_key)
	}
}

impl ProvableAddress {
	/// new instance
	pub fn from_str(public_key: &str) -> Result<Self, Error> {
		// Just check if it works
		//this can be either PublicKey or DalekPublicKey
		if public_key.len() != 56 {
			PublicKey::from_base58_check(public_key, version_bytes())?;
		}

		Ok(Self {
			public_key: String::from(public_key),
			domain: String::new(),
			port: None,
		})
	}

	/// Create address from public key
	pub fn from_pub_key(public_key: &PublicKey) -> Self {
		Self {
			public_key: public_key.to_base58_check(version_bytes()),
			domain: String::new(),
			port: None,
		}
	}

	/// Get public key that represent this address
	pub fn public_key(&self) -> Result<PublicKey, Error> {
		PublicKey::from_base58_check(&self.public_key, version_bytes())
	}
	/// Create address from public key
	pub fn from_tor_pub_key(public_key: &DalekPublicKey) -> Self {
		Self {
			public_key: OnionV3Address::from_bytes(*public_key.as_bytes()).to_ov3_str(),
			domain: String::new(),
			port: None,
		}
	}

	/// Get public key that represent this address
	pub fn tor_public_key(&self) -> Result<DalekPublicKey, Error> {
		let addr = OnionV3Address::try_from(self.public_key.as_str())?;
		Ok(addr.to_ed25519()?)
	}
}

/// provable address prefix.
pub fn version_bytes() -> Vec<u8> {
	if global::is_mainnet() {
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
	keychain: &K,
	addr_type: ProofAddressType,
) -> Result<ProvableAddress, Error>
where
	K: Keychain,
{
	payment_proof_address_from_index(keychain, get_address_index(), addr_type)
}

/// provable address public key
pub fn payment_proof_address_from_index<K>(
	keychain: &K,
	index: u32,
	addr_type: ProofAddressType,
) -> Result<ProvableAddress, Error>
where
	K: Keychain,
{
	let secret_key = payment_proof_address_secret_from_index(keychain, index)?;

	match addr_type {
		ProofAddressType::MQS => {
			let sender_address_pub_key = crypto::public_key_from_secret_key(&secret_key)?;
			Ok(ProvableAddress::from_pub_key(&sender_address_pub_key))
		}
		ProofAddressType::Onion => {
			let onion_address = OnionV3Address::from_private(&secret_key.0)?;
			let dalek_pubkey = onion_address.to_ov3_str();
			Ok(ProvableAddress::from_str(&dalek_pubkey)?)
		}
	}
}

/// Derive a secret key given a derivation path and index
pub fn payment_proof_address_secret<K>(keychain: &K) -> Result<SecretKey, Error>
where
	K: Keychain,
{
	payment_proof_address_secret_from_index(keychain, get_address_index())
}

/// Derive a secret key given a derivation path and index
pub fn payment_proof_address_secret_from_index<K>(
	keychain: &K,
	index: u32,
) -> Result<SecretKey, Error>
where
	K: Keychain,
{
	hasher::derive_address_key(keychain, index).map_err(|e| e.into())
}

///
pub fn payment_proof_address_pubkey<K>(keychain: &K) -> Result<PublicKey, Error>
where
	K: Keychain,
{
	let sender_address_secret_key = payment_proof_address_secret(keychain)?;
	crypto::public_key_from_secret_key(&sender_address_secret_key)
}

/// ProvableAddress
pub fn proof_address_from_string<'de, D>(deserializer: D) -> Result<ProvableAddress, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Error;

	String::deserialize(deserializer).and_then(|string| {
		ProvableAddress::from_str(&string).map_err(|err| {
			Error::custom(format!(
				"Fail to parse provable address {}, {}",
				string, err
			))
		})
	})
}

/// Seralizes a provableAddress.
pub fn as_string<S>(address: &ProvableAddress, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&address.public_key)
}

/// ProvableAddress
pub fn option_proof_address_from_string<'de, D>(
	deserializer: D,
) -> Result<Option<ProvableAddress>, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Error;

	Option::<String>::deserialize(deserializer).and_then(|res| match res {
		Some(string) => ProvableAddress::from_str(&string)
			.map_err(|err| {
				Error::custom(format!(
					"Fail to parse provable address {}, {}",
					string, err
				))
			})
			.and_then(|address: ProvableAddress| {
				return Ok(Some(address));
			}),
		None => Ok(None),
	})
}

/// Seralizes a provableAddress.
pub fn option_as_string<S>(
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
