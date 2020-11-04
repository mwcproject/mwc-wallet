// Copyright 2019 The Grin Develope;
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

//! Functions defining wallet 'addresses', i.e. ed2559 keys based on
//! a derivation path

use crate::grin_util::from_hex;
use crate::grin_util::secp::key::SecretKey;
use crate::{Error, ErrorKind};

use data_encoding::BASE32;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use sha3::{Digest, Sha3_256};

/// Output ed25519 keypair given an rust_secp256k1 SecretKey
pub fn ed25519_keypair(sec_key: &SecretKey) -> Result<(DalekSecretKey, DalekPublicKey), Error> {
	let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
		Ok(k) => k,
		Err(e) => {
			return Err(ErrorKind::ED25519Key(format!(
				"Unable to build Dalek key, {}",
				e
			)))?
		}
	};
	let d_pub_key: DalekPublicKey = (&d_skey).into();
	Ok((d_skey, d_pub_key))
}

/// Output ed25519 pubkey represented by string
pub fn ed25519_parse_pubkey(pub_key: &str) -> Result<DalekPublicKey, Error> {
	let bytes = from_hex(pub_key).map_err(|e| {
		ErrorKind::AddressDecoding(format!("Can't parse pubkey {}, {}", pub_key, e))
	})?;
	match DalekPublicKey::from_bytes(&bytes) {
		Ok(k) => Ok(k),
		Err(e) => {
			return Err(ErrorKind::AddressDecoding(format!(
				"Not a valid public key {}, {}",
				pub_key, e
			)))?
		}
	}
}

/// Return the ed25519 public key represented in an onion address
pub fn pubkey_from_onion_v3(onion_address: &str) -> Result<DalekPublicKey, Error> {
	let mut input = onion_address.to_uppercase();
	if input.starts_with("HTTP://") || input.starts_with("HTTPS://") {
		input = input.replace("HTTP://", "");
		input = input.replace("HTTPS://", "");
	}
	if input.ends_with(".ONION") {
		input = input.replace(".ONION", "");
	}
	let orig_address_raw = input.clone();
	// for now, just check input is the right length and try and decode from base32
	if input.len() != 56 {
		return Err(ErrorKind::AddressDecoding(format!(
			"Input address {} is wrong length, expected 56 symbols",
			input
		)))?;
	}
	let mut address = BASE32
		.decode(input.as_bytes())
		.map_err(|e| {
			ErrorKind::AddressDecoding(format!("Input address {} is not base 32, {}", input, e))
		})?
		.to_vec();

	address.truncate(32);
	let key = DalekPublicKey::from_bytes(&address).map_err(|e| {
		ErrorKind::AddressDecoding(format!(
			"Provided onion V3 address is invalid (parsing dalek key), {}",
			e
		))
	})?;

	let test_v3 = onion_v3_from_pubkey(&key).map_err(|e| {
		ErrorKind::AddressDecoding(format!(
			"Provided onion V3 address is invalid (converting from pubkey), {}",
			e
		))
	})?;

	if test_v3.to_uppercase() != orig_address_raw.to_uppercase() {
		return Err(ErrorKind::AddressDecoding(
			"Provided onion V3 address is invalid (no match)".to_string(),
		))?;
	}
	Ok(key)
}

/// Generate an onion address from an ed25519_dalek public key
pub fn onion_v3_from_pubkey(pub_key: &DalekPublicKey) -> Result<String, Error> {
	// calculate checksum
	let mut hasher = Sha3_256::new();
	hasher.input(b".onion checksum");
	hasher.input(pub_key.as_bytes());
	hasher.input([0x03u8]);
	let checksum = hasher.result();

	let mut address_bytes = pub_key.as_bytes().to_vec();
	address_bytes.push(checksum[0]);
	address_bytes.push(checksum[1]);
	address_bytes.push(0x03u8);

	let ret = BASE32.encode(&address_bytes);
	Ok(ret.to_lowercase())
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn onion_v3_conversion() {
		let onion_address = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";

		let key = pubkey_from_onion_v3(onion_address).unwrap();
		println!("Key: {:?}", &key);

		let out_address = onion_v3_from_pubkey(&key).unwrap();
		println!("Address: {:?}", &out_address);

		assert_eq!(onion_address, out_address);
	}
}
