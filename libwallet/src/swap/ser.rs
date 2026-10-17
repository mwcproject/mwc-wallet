// Copyright 2019 The vault713 Developers
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

use crate::swap::Error;
use mwc_wallet_util::mwc_crates::hex::{self, FromHex};
use mwc_wallet_util::mwc_crates::secp::AggSigSignature;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_util::ToHex;

/// Serialize Vec<u8> as HEX
pub fn bytes_to_hex<S>(key: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(key))
}

/// Deserialize HEX to Vec<u8>
pub fn bytes_from_hex<'a, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let s = String::deserialize(deserializer)?;
	Vec::from_hex(&s).map_err(D::Error::custom)
}

/// Serialize Commitment as HEX string
pub fn commit_to_hex<S>(key: &Commitment, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&hex::encode(key.0.to_vec()))
}

/// Deserialize Commitment from HEX string
fn commit_from_hex_string(s: String) -> Result<Commitment, Error> {
	let v = Vec::from_hex(&s)
		.map_err(|e| Error::Generic(format!("Unable to parse commit from HEX, {}", e)))?;
	Ok(Commitment::from_vec(v)?)
}

/// Serialize Option<Commitment> as a HEX String
pub fn option_commit_to_hex<S>(key: &Option<Commitment>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => commit_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

/// Deserialized HEX string to Option<Commitment>
pub fn option_commit_from_hex<'a, D>(deserializer: D) -> Result<Option<Commitment>, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => commit_from_hex_string(s)
			.map(|p| Some(p))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

/// PublicKey serialize as a HEX string
pub fn pubkey_to_hex<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let secp = Secp256k1::with_caps(ContextFlag::None).map_err(|e| {
		mwc_wallet_util::mwc_crates::serde::ser::Error::custom(format!(
			"Unable create secp context, {}",
			e
		))
	})?;
	let key_ser = key.serialize_vec(&secp, true).map_err(|e| {
		mwc_wallet_util::mwc_crates::serde::ser::Error::custom(format!(
			"Unable serialize public key, {}",
			e
		))
	})?;
	serializer.serialize_str(key_ser.to_hex().as_str())
}

fn pubkey_from_hex_string(s: String) -> Result<PublicKey, Error> {
	let v = Vec::from_hex(&s)
		.map_err(|e| Error::Generic(format!("Unable to parse public key from HEX, {}", e)))?;
	let secp = Secp256k1::with_caps(ContextFlag::None)?;
	let p = PublicKey::from_slice(&secp, &v[..])?;
	Ok(p)
}

/// Deserialize Paulic Key from HEX string
pub fn pubkey_from_hex<'a, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let s = String::deserialize(deserializer)?;
	pubkey_from_hex_string(s).map_err(D::Error::custom)
}

/// Serialize Option<PublicKey> to HEX string
pub fn option_pubkey_to_hex<S>(key: &Option<PublicKey>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => pubkey_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

/// Deserialize Option<PublicKey> from HEX string
pub fn option_pubkey_from_hex<'a, D>(deserializer: D) -> Result<Option<PublicKey>, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => pubkey_from_hex_string(s)
			.map(|p| Some(p))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

/// Serialize SecretKey as HEX string
pub fn seckey_to_hex<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	// The temporary HEX encoding of the secret is zeroized on drop
	let key_hex = Zeroizing::new(hex::encode(&key.0));
	serializer.serialize_str(&key_hex)
}

fn seckey_from_hex_string(s: String) -> Result<SecretKey, Error> {
	let s = Zeroizing::new(s);
	// Decode in place so partial secrets are wiped on errors and never reallocated.
	let mut v = Zeroizing::new([0u8; 32]);
	hex::decode_to_slice(s.as_str(), &mut v[..])
		.map_err(|e| Error::Generic(format!("Unable to parse secret key from HEX, {}", e)))?;
	let secp = Secp256k1::with_caps(ContextFlag::None)?;
	let sk = SecretKey::from_slice(&secp, &v[..])?;
	Ok(sk)
}

/// Deserialize SecretKey from HEX string
pub fn seckey_from_hex<'a, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let s = String::deserialize(deserializer)?;
	seckey_from_hex_string(s).map_err(D::Error::custom)
}

/// Serialize Option<SecretKey> to HEX string
pub fn option_seckey_to_hex<S>(key: &Option<SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match key {
		Some(inner) => seckey_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

/// Deserialize Option<SecretKey> from HEX
pub fn option_seckey_from_hex<'a, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => seckey_from_hex_string(s)
			.map(|s| Some(s))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

/// Serialize Signature to HEX
pub fn sig_to_hex<S>(sig: &AggSigSignature, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let secp = Secp256k1::with_caps(ContextFlag::None).map_err(|e| {
		mwc_wallet_util::mwc_crates::serde::ser::Error::custom(format!(
			"Unable create secp context, {}",
			e
		))
	})?;
	let sig_ser = sig.serialize_compact(&secp).map_err(|e| {
		mwc_wallet_util::mwc_crates::serde::ser::Error::custom(format!(
			"Unable serialize signature, {}",
			e
		))
	})?;
	serializer.serialize_str(sig_ser.to_hex().as_str())
}

fn sig_from_hex_string(secp: &Secp256k1, s: String) -> Result<AggSigSignature, Error> {
	let v = Vec::from_hex(&s)
		.map_err(|e| Error::Generic(format!("Unable to parse signature from HEX, {}", e)))?;
	let sig = AggSigSignature::from_compact(secp, &v[..])?;
	Ok(sig)
}

/// Deseroalize Signature from HEX string
pub fn sig_from_hex<'a, D>(deserializer: D) -> Result<AggSigSignature, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let s = String::deserialize(deserializer)?;
	let secp = Secp256k1::with_caps(ContextFlag::None).map_err(D::Error::custom)?;
	sig_from_hex_string(&secp, s).map_err(D::Error::custom)
}

/// Serialize Option<Signature> to HEX string
pub fn option_sig_to_hex<S>(sig: &Option<AggSigSignature>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match sig {
		Some(inner) => sig_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

/// Deserialize Option<Signature> from HEX string
pub fn option_sig_from_hex<'a, D>(deserializer: D) -> Result<Option<AggSigSignature>, D::Error>
where
	D: Deserializer<'a>,
{
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	let secp = Secp256k1::with_caps(ContextFlag::None).map_err(D::Error::custom)?;
	match opt {
		Some(s) => sig_from_hex_string(&secp, s)
			.map(|sig| Some(sig))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn malformed_hex_errors_do_not_echo_peer_input() {
		let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
		for hostile in [
			"g\n\u{001b}[2J\u{202e}".repeat(1_024),
			"\n\u{001b}".to_string(),
		] {
			let errors = [
				commit_from_hex_string(hostile.clone()).unwrap_err(),
				pubkey_from_hex_string(hostile.clone()).unwrap_err(),
				sig_from_hex_string(&secp, hostile.clone()).unwrap_err(),
			];
			for error in errors {
				let error = error.to_string();
				assert!(!error.contains(&hostile));
				assert!(!error.chars().any(char::is_control));
				assert!(!error.contains('\u{202e}'));
				assert!(error.len() < 256);
			}
		}
	}

	#[test]
	fn secret_key_hex_decoding_preserves_bytes_and_accepts_either_case() {
		for encoded in ["ab".repeat(32), "AB".repeat(32), "aB".repeat(32)] {
			let key = seckey_from_hex_string(encoded).unwrap();
			assert_eq!(key.0, [0xab; 32]);
		}
	}

	#[test]
	fn secret_key_hex_decoding_rejects_malformed_encodings_and_invalid_scalars() {
		for encoded in [
			String::new(),
			"ab".repeat(31),
			"ab".repeat(33),
			"a".repeat(63),
			"ab".repeat(31) + "ag",
			"00".repeat(32),
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".to_string(),
			"ff".repeat(32),
		] {
			assert!(seckey_from_hex_string(encoded).is_err());
		}
	}

	#[test]
	fn invalid_secret_key_error_does_not_echo_secret_source() {
		let secret_source = "not-hex-secret-nonce".to_string();
		let error = seckey_from_hex_string(secret_source.clone()).unwrap_err();
		assert!(!error.to_string().contains(&secret_source));
		assert!(
			error
				.to_string()
				.contains("Unable to parse secret key from HEX")
		);
	}
}
