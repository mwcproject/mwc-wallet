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

use crate::error::Error;
use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
use mwc_wallet_util::mwc_crates::secp::{Secp256k1, constants};
use mwc_wallet_util::mwc_keychain::base58;

const BASE58_CHECKSUM_LEN: usize = 4;

fn max_base58_public_key_len(version_len: usize) -> Result<usize, Error> {
	// 7/5 is a conservative upper bound for converting base-256 bytes to
	// base58 digits. Include the largest SEC1 representation and checksum;
	// canonical compressed length is enforced after decoding.
	version_len
		.checked_add(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE)
		.and_then(|len| len.checked_add(BASE58_CHECKSUM_LEN))
		.and_then(|len| len.checked_mul(7))
		.map(|len| len / 5)
		.and_then(|len| len.checked_add(1))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"base58 public-key length calculation overflow, version_len={}",
				version_len
			))
		})
}

///
pub trait Base58<T> {
	///need to add documentation
	fn from_base58_check(secp: &Secp256k1, str: &str, version_bytes: Vec<u8>) -> Result<T, Error>;
	///need to add documentation
	fn to_base58_check(&self, secp: &Secp256k1, version: Vec<u8>) -> Result<String, Error>;
}

///
fn to_base58_check(data: &[u8], version: Vec<u8>) -> Result<String, Error> {
	let payload: Vec<u8> = version.iter().chain(data.iter()).map(|x| *x).collect();
	base58::check_encode_slice(payload.as_slice())
		.map_err(|e| Error::Base58Error(format!("Unable encode base58 string, {}", e)))
}

///
fn from_base58_check(data: &str, version_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let payload = base58::from_check(data)
		.map_err(|e| Error::Base58Error(format!("Unable decode base58 string, {}", e)))?;
	let version = payload.get(..version_bytes).ok_or_else(|| {
		Error::Base58Error(format!(
			"base58::from_base58_check, decoded payload is shorter than the requested version, payload_len={} version_len={}",
			payload.len(), version_bytes
		))
	})?;
	let data = payload.get(version_bytes..).ok_or_else(|| {
		Error::Base58Error(format!(
			"base58::from_base58_check, invalid payload boundary, payload_len={} version_len={}",
			payload.len(),
			version_bytes
		))
	})?;
	Ok((version.to_vec(), data.to_vec()))
}

///
pub fn serialize_public_key(secp: &Secp256k1, public_key: &PublicKey) -> Result<Vec<u8>, Error> {
	let ser = public_key.serialize_vec(secp, true)?;
	Ok(ser[..].to_vec())
}

impl Base58<PublicKey> for PublicKey {
	fn from_base58_check(
		secp: &Secp256k1,
		str: &str,
		version_expect: Vec<u8>,
	) -> Result<PublicKey, Error> {
		let n_version = version_expect.len();
		let max_encoded_len = max_base58_public_key_len(n_version)?;
		if str.len() > max_encoded_len {
			return Err(Error::Base58Error(format!(
				"Base58 public key is too long, input_len={} max_len={}",
				str.len(),
				max_encoded_len
			)));
		}
		let (version_actual, key_bytes) = from_base58_check(str, n_version)?;
		if version_actual != version_expect {
			return Err(Error::Base58Error(
				"Address belong to another network".to_string(),
			));
		}
		if key_bytes.len() != constants::COMPRESSED_PUBLIC_KEY_SIZE {
			return Err(Error::Base58Error(format!(
				"Base58 public key has invalid payload length {}, expected {}-byte compressed public key",
				key_bytes.len(),
				constants::COMPRESSED_PUBLIC_KEY_SIZE
			)));
		}
		PublicKey::from_slice(secp, &key_bytes)
			.map_err(|e| Error::Base58Error(format!("Unable to build key from Base58, {}", e)))
	}

	fn to_base58_check(&self, secp: &Secp256k1, version: Vec<u8>) -> Result<String, Error> {
		to_base58_check(serialize_public_key(secp, self)?.as_slice(), version)
	}
}

#[cfg(test)]
mod tests {
	use super::{Base58, from_base58_check, max_base58_public_key_len, to_base58_check};
	use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};

	#[test]
	fn rejects_payload_shorter_than_version_without_panicking() {
		let encoded = to_base58_check(&[], vec![]).expect("empty payload should encode");
		let error = from_base58_check(&encoded, 1).expect_err("short payload must be rejected");
		assert!(error.to_string().contains("payload_len=0 version_len=1"));
	}

	#[test]
	fn rejects_oversized_public_key_before_decoding() {
		let version = vec![1, 69];
		let max_len =
			max_base58_public_key_len(version.len()).expect("length calculation must succeed");
		let oversized = "1".repeat(max_len + 1);
		let secp =
			Secp256k1::with_caps(ContextFlag::None).expect("test secp context must initialize");

		let error = PublicKey::from_base58_check(&secp, &oversized, version)
			.expect_err("oversized public key must be rejected");
		assert!(error.to_string().contains(&format!(
			"input_len={} max_len={}",
			max_len + 1,
			max_len
		)));
	}

	#[test]
	fn decode_error_does_not_echo_untrusted_input() {
		let hostile = "bad\n\u{1b}[31m";
		let error = from_base58_check(hostile, 2).expect_err("invalid base58 must be rejected");
		let rendered = error.to_string();

		assert!(!rendered.contains(hostile));
		assert!(!rendered.contains('\n'));
		assert!(!rendered.contains('\u{1b}'));
	}

	#[test]
	fn rejects_uncompressed_public_key_payload() {
		let secp = Secp256k1::new().expect("secp context must initialize");
		let secret =
			SecretKey::from_slice(&secp, &[1_u8; 32]).expect("test secret key must be valid");
		let public =
			PublicKey::from_secret_key(&secp, &secret).expect("test public key must be valid");
		let version = vec![1, 69];
		let canonical = public
			.to_base58_check(&secp, version.clone())
			.expect("compressed public key must Base58Check-encode");
		let decoded = PublicKey::from_base58_check(&secp, &canonical, version.clone())
			.expect("compressed public-key payload must be accepted");
		assert_eq!(decoded, public);

		let uncompressed = public
			.serialize_vec(&secp, false)
			.expect("uncompressed public key must serialize");
		let encoded = to_base58_check(uncompressed.as_slice(), version.clone())
			.expect("uncompressed payload must Base58Check-encode");

		let error = PublicKey::from_base58_check(&secp, &encoded, version)
			.expect_err("uncompressed public-key payload must be rejected");
		assert!(
			error
				.to_string()
				.contains("invalid payload length 65, expected 33-byte compressed public key")
		);
	}
}
