// Copyright 2021 The Mwc Develope;
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

use crate::Error;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::safelog::DispUnredacted;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::tor_hscrypto::pk::HsId;
use mwc_wallet_util::mwc_util::from_hex;
use std::convert::TryInto;
use std::str::FromStr;

/// Output ed25519 keypair given an rust_secp256k1 SecretKey
pub fn ed25519_keypair(
	sec_key: &SecretKey,
) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey), Error> {
	let d_skey = ed25519_dalek::SigningKey::from_bytes(&sec_key.0);
	let d_pub_key = (&d_skey).verifying_key();
	Ok((d_skey, d_pub_key))
}

/// Output ed25519 pubkey represented by string
pub fn ed25519_parse_pubkey(pub_key: &str) -> Result<ed25519_dalek::VerifyingKey, Error> {
	let bytes = from_hex(pub_key)
		.map_err(|e| Error::AddressDecoding(format!("Can't parse pubkey {}, {}", pub_key, e)))?;

	let bytes: [u8; 32] = match bytes.try_into() {
		Ok(b) => b,
		Err(_) => {
			return Err(Error::AddressDecoding(format!(
				"Not a valid public key {}, wrong length",
				pub_key
			)))
		}
	};

	match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
		Ok(k) => Ok(k),
		Err(e) => Err(Error::AddressDecoding(format!(
			"Not a valid public key {}, {}",
			pub_key, e
		))),
	}
}

/// Return the ed25519 public key represented in an onion address
pub fn pubkey_from_onion_v3(onion_address: &str) -> Result<ed25519_dalek::VerifyingKey, Error> {
	let mut s = onion_address.trim().to_lowercase();

	// Accept URLs too, like your current code did.
	if let Some(rest) = s.strip_prefix("http://") {
		s = rest.to_string();
	} else if let Some(rest) = s.strip_prefix("https://") {
		s = rest.to_string();
	}

	// If a full URL/path was passed, keep only the host part.
	if let Some((host, _)) = s.split_once('/') {
		s = host.to_string();
	}

	// Normalize to the representation HsId::from_str expects: "... .onion"
	let onion_host = if s.ends_with(".onion") {
		s
	} else {
		format!("{}.onion", s)
	};

	let hsid = HsId::from_str(&onion_host).map_err(|e| {
		Error::AddressDecoding(format!("Provided onion V3 address is invalid, {}", e))
	})?;

	let key_bytes = hsid.as_ref();

	let key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|e| {
		Error::AddressDecoding(format!(
			"Provided onion V3 address is invalid (parsing dalek key), {}",
			e
		))
	})?;

	Ok(key)
}

/// Generate an onion address from an ed25519_dalek public key
pub fn onion_v3_from_pubkey(pub_key: &ed25519_dalek::VerifyingKey) -> String {
	let hsid = HsId::from(*pub_key.as_bytes());
	let onion = DispUnredacted(&hsid).to_string();
	onion.strip_suffix(".onion").unwrap_or(&onion).to_string()
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn onion_v3_conversion() {
		let onion_address = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";

		let key = pubkey_from_onion_v3(onion_address).unwrap();
		println!("Key: {:?}", &key);

		let key2 = pubkey_from_onion_v3(&format!("{}.onion", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("{}.ONION", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("{}.ONioN", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("http://{}", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("https://{}", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("http://{}.onion", onion_address)).unwrap();
		assert_eq!(key, key2);
		let key2 = pubkey_from_onion_v3(&format!("hTTp://{}.onIOn", onion_address)).unwrap();
		assert_eq!(key, key2);

		let out_address = onion_v3_from_pubkey(&key);
		println!("Address: {:?}", &out_address);

		assert_eq!(onion_address, out_address);
	}
}
