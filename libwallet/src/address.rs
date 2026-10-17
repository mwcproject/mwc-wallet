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
use mwc_wallet_util::mwc_util::{OnionV3Address, from_hex};
use std::convert::TryInto;

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
			)));
		}
	};

	let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|e| {
		Error::AddressDecoding(format!("Not a valid public key {}, {}", pub_key, e))
	})?;

	if key.is_weak() {
		return Err(Error::AddressDecoding(format!(
			"Not a valid public key {}, key has small order",
			pub_key
		)));
	}

	Ok(key)
}

/// Return the ed25519 public key represented in an onion address
pub fn pubkey_from_onion_v3(onion_address: &str) -> Result<ed25519_dalek::VerifyingKey, Error> {
	let mut s = onion_address.trim();

	// Accept URLs too, like your current code did.
	if s.get(..7)
		.is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
	{
		s = &s[7..];
	} else if s
		.get(..8)
		.is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
	{
		s = &s[8..];
	}

	// If a full URL/path was passed, keep only the host part.
	if let Some((host, _)) = s.split_once('/') {
		s = host;
	}

	let identity = s
		.len()
		.checked_sub(".onion".len())
		.and_then(|suffix_start| {
			s.get(suffix_start..)
				.filter(|suffix| suffix.eq_ignore_ascii_case(".onion"))
				.and_then(|_| s.get(..suffix_start))
		})
		.unwrap_or(s);

	// Onion v3 identities are exactly 56 RFC 4648 Base32 symbols. Enforce this
	// locally because accepting Unicode case folding or trailing decoded bytes
	// would let malformed strings map to the same canonical identity.
	if identity.len() != 56
		|| !identity
			.bytes()
			.all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
	{
		return Err(Error::AddressDecoding(
			"Provided onion V3 address must contain exactly 56 ASCII Base32 symbols".to_string(),
		));
	}

	// Include the suffix so the shared parser cannot interpret an all-hexadecimal
	// Base32 identity as its legacy raw-public-key form.
	let onion_host = format!("{}.onion", identity);

	let address = OnionV3Address::try_from(onion_host.as_str()).map_err(|e| {
		Error::AddressDecoding(format!("Provided onion V3 address is invalid, {}", e))
	})?;

	address.to_ed25519().map_err(|e| {
		Error::AddressDecoding(format!(
			"Provided onion V3 address contains an invalid public key, {}",
			e
		))
	})
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
	fn parse_pubkey_rejects_weak_key() {
		let identity_key = "0100000000000000000000000000000000000000000000000000000000000000";

		assert!(matches!(
			ed25519_parse_pubkey(identity_key),
			Err(Error::AddressDecoding(message)) if message.contains("small order")
		));
	}

	#[test]
	fn onion_v3_parse_rejects_weak_key() {
		// A checksum-valid Onion v3 address containing the Edwards identity point.
		let weak_address = "aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahmjqd";

		assert!(matches!(
			pubkey_from_onion_v3(weak_address),
			Err(Error::AddressDecoding(message)) if message.contains("weak public key")
		));
	}

	#[test]
	fn onion_v3_parse_rejects_noncanonical_key() {
		// A checksum-valid Onion v3 address containing a non-canonical Edwards
		// encoding of an otherwise non-small-order point.
		let noncanonical_address = "6d7777777777777777777777777777777777777777777777757rzrqd";

		assert!(matches!(
			pubkey_from_onion_v3(noncanonical_address),
			Err(Error::AddressDecoding(message)) if message.contains("not canonical PK")
		));
	}

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
		let key2 = pubkey_from_onion_v3(&format!("http://{}.onion/a/path", onion_address)).unwrap();
		assert_eq!(key, key2);

		assert!(pubkey_from_onion_v3(&format!("{}aa.onion", onion_address)).is_err());
		assert!(pubkey_from_onion_v3(&onion_address.replacen('k', "K", 1)).is_err());

		let out_address = onion_v3_from_pubkey(&key);
		println!("Address: {:?}", &out_address);

		assert_eq!(onion_address, out_address);
	}
}
