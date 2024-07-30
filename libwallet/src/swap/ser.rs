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

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::{Slate, VersionedSlate};
use failure::Error;
use grin_wallet_util::grin_util::secp::{ContextFlag, Secp256k1};
use grin_wallet_util::grin_util::ToHex;
use hex::{self, FromHex};
use serde::{Deserialize, Deserializer, Serializer};

/// Slate deserialization
pub fn slate_deser<'a, D>(deserializer: D) -> Result<Slate, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = VersionedSlate::deserialize(deserializer)?;
	// Swaps are not using the slatepacks.
	s.into_slate_plain(true)
		.map_err(|e| D::Error::custom(format!("{}", e)))
}

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
	use serde::de::Error;
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
	let v = Vec::from_hex(&s)?;
	Ok(Commitment::from_vec(v))
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
	use serde::de::Error;
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
	let secp = Secp256k1::with_caps(ContextFlag::None);
	serializer.serialize_str(key.serialize_vec(&secp, true).to_hex().as_str())
}

fn pubkey_from_hex_string(s: String) -> Result<PublicKey, Error> {
	let v = Vec::from_hex(&s)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	let p = PublicKey::from_slice(&secp, &v[..])?;
	Ok(p)
}

/// Deserialize Paulic Key from HEX string
pub fn pubkey_from_hex<'a, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
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
	use serde::de::Error;
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
	serializer.serialize_str(&hex::encode(&key.0))
}

fn seckey_from_hex_string(s: String) -> Result<SecretKey, Error> {
	let v = Vec::from_hex(&s)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	let sk = SecretKey::from_slice(&secp, &v[..])?;
	Ok(sk)
}

/// Deserialize SecretKey from HEX string
pub fn seckey_from_hex<'a, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
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
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	match opt {
		Some(s) => seckey_from_hex_string(s)
			.map(|s| Some(s))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}

/// Serialize Signature to HEX
pub fn sig_to_hex<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let secp = Secp256k1::with_caps(ContextFlag::None);
	serializer.serialize_str(sig.serialize_compact(&secp).to_hex().as_str())
}

fn sig_from_hex_string(secp: &Secp256k1, s: String) -> Result<Signature, Error> {
	let v = Vec::from_hex(&s)?;
	let sig = Signature::from_compact(secp, &v[..])?;
	Ok(sig)
}

/// Deseroalize Signature from HEX string
pub fn sig_from_hex<'a, D>(deserializer: D) -> Result<Signature, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let s = String::deserialize(deserializer)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	sig_from_hex_string(&secp, s).map_err(D::Error::custom)
}

/// Serialize Option<Signature> to HEX string
pub fn option_sig_to_hex<S>(sig: &Option<Signature>, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	match sig {
		Some(inner) => sig_to_hex(&inner, serializer),
		None => serializer.serialize_none(),
	}
}

/// Deserialize Option<Signature> from HEX string
pub fn option_sig_from_hex<'a, D>(deserializer: D) -> Result<Option<Signature>, D::Error>
where
	D: Deserializer<'a>,
{
	use serde::de::Error;
	let opt: Option<String> = Option::deserialize(deserializer)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	match opt {
		Some(s) => sig_from_hex_string(&secp, s)
			.map(|sig| Some(sig))
			.map_err(D::Error::custom),
		None => Ok(None),
	}
}
