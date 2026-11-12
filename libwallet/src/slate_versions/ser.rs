// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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
//! Sane serialization & deserialization of cryptographic structs into hex

/// Serializes an OnionV3Address to and from hex
pub mod option_ov3_serde {
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	use mwc_wallet_util::mwc_util::{OnionV3Address, OnionV3Error};

	///
	pub fn serialize<S>(addr: &Option<OnionV3Address>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match addr {
			Some(a) => serializer.serialize_str(&a.to_string()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OnionV3Address>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(s) => OnionV3Address::try_from(s.as_str())
				.map_err(|err: OnionV3Error| Error::custom(format!("{:?}", err)))
				.and_then(|a| Ok(Some(a))),
			None => Ok(None),
		})
	}
}

/// Serializes an OnionV3Address to and from hex
pub mod ov3_serde {
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryFrom;

	use mwc_wallet_util::mwc_util::{OnionV3Address, OnionV3Error};

	///
	pub fn serialize<S>(addr: &OnionV3Address, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&addr.to_string())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<OnionV3Address, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer).and_then(|s| {
			OnionV3Address::try_from(s.as_str())
				.map_err(|err: OnionV3Error| Error::custom(format!("{:?}", err)))
				.and_then(Ok)
		})
	}
}

/// Serializes an ed25519 PublicKey to and from hex
pub mod dalek_pubkey_serde {
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use mwc_wallet_util::mwc_util::{from_hex, ToHex};
	use std::convert::TryInto;

	///
	pub fn serialize<S>(key: &ed25519_dalek::VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&key.to_bytes().to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<ed25519_dalek::VerifyingKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use mwc_wallet_util::mwc_crates::serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| {
				from_hex(&string).map_err(|err| {
					Error::custom(format!(
						"ed25519_dalek::PublicKey, Unable to parse HEX {}, {}",
						string, err
					))
				})
			})
			.and_then(|bytes: Vec<u8>| {
				let blen = bytes.len();
				let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
					Error::custom(format!(
						"Unable to build ed25519_dalek::PublicKey, wrong length {}",
						blen
					))
				})?;

				ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|err| {
					Error::custom(format!("Unable to build ed25519_dalek::PublicKey, {}", err))
				})
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_pubkey_serde {
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryInto;

	use mwc_wallet_util::mwc_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(
		key: &Option<ed25519_dalek::VerifyingKey>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => serializer.serialize_str(&key.to_bytes().to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(
		deserializer: D,
	) -> Result<Option<ed25519_dalek::VerifyingKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| {
					Error::custom(format!(
						"ed25519_dalek::PublicKey, Unable to parse HEX {}, {}",
						string, err
					))
				})
				.and_then(|bytes: Vec<u8>| {
					let blen = bytes.len();
					let b: [u8; 32] = bytes.try_into().map_err(|_| {
						Error::custom(format!(
							"Unable to build ed25519_dalek::PublicKey, wrong length {}",
							blen
						))
					})?;
					ed25519_dalek::VerifyingKey::from_bytes(&b)
						.map(Some)
						.map_err(|err| {
							Error::custom(format!(
								"Unable to build ed25519_dalek::PublicKey, {}",
								err
							))
						})
				}),
			None => Ok(None),
		})
	}
}

/// Serializes an ed25519_dalek::Signature to and from hex
pub mod dalek_sig_serde {
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryInto;

	use mwc_wallet_util::mwc_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(sig: &ed25519_dalek::Signature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&sig.to_bytes().as_ref().to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<ed25519_dalek::Signature, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer)
			.and_then(|string| from_hex(&string).map_err(|err| Error::custom(err.to_string())))
			.and_then(|bytes: Vec<u8>| {
				let blen = bytes.len();
				let b: [u8; 64] = bytes.try_into().map_err(|_| {
					Error::custom(format!(
						"Unable to build ed25519_dalek::Signature, wrong length {}",
						blen
					))
				})?;
				Ok(ed25519_dalek::Signature::from_bytes(&b))
			})
	}
}

/// Serializes an Option<ed25519_dalek::PublicKey> to and from hex
pub mod option_dalek_sig_serde {
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::convert::TryInto;

	use mwc_wallet_util::mwc_util::{from_hex, ToHex};

	///
	pub fn serialize<S>(
		sig: &Option<ed25519_dalek::Signature>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match sig {
			Some(s) => serializer.serialize_str(&s.to_bytes().as_ref().to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(
		deserializer: D,
	) -> Result<Option<ed25519_dalek::Signature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| {
					Error::custom(format!(
						"ed25519_dalek::PublicKey, Unable to parse HEX {}, {}",
						string, err
					))
				})
				.and_then(|bytes: Vec<u8>| {
					let blen = bytes.len();
					let b: [u8; 64] = bytes.try_into().map_err(|_| {
						Error::custom(format!(
							"Unable to build ed25519_dalek::Signature, wrong length {}",
							blen
						))
					})?;
					Ok(Some(ed25519_dalek::Signature::from_bytes(&b)))
				}),
			None => Ok(None),
		})
	}
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;
	use mwc_wallet_util::mwc_crates::ed25519_dalek::{self, Signer};
	use mwc_wallet_util::mwc_crates::secp::{self, ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
	use mwc_wallet_util::mwc_crates::serde_json;

	#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
	#[serde(crate = "serde")]
	struct SerTest {
		#[serde(with = "dalek_pubkey_serde")]
		pub pub_key: ed25519_dalek::VerifyingKey,
		#[serde(with = "option_dalek_pubkey_serde")]
		pub pub_key_opt: Option<ed25519_dalek::VerifyingKey>,
		#[serde(with = "dalek_sig_serde")]
		pub sig: ed25519_dalek::Signature,
		#[serde(with = "option_dalek_sig_serde")]
		pub sig_opt: Option<ed25519_dalek::Signature>,
	}

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	struct OptionalPubkey {
		#[serde(with = "option_dalek_pubkey_serde")]
		pub_key: Option<ed25519_dalek::VerifyingKey>,
	}

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	struct Signature {
		#[serde(with = "dalek_sig_serde")]
		sig: ed25519_dalek::Signature,
	}

	#[derive(Deserialize)]
	#[serde(crate = "serde")]
	struct OptionalSignature {
		#[serde(with = "option_dalek_sig_serde")]
		sig: Option<ed25519_dalek::Signature>,
	}

	impl SerTest {
		pub fn random() -> SerTest {
			let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
			let sec_key = secp::key::SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
			let d_skey = ed25519_dalek::SigningKey::from_bytes(&sec_key.0);
			let d_pub_key: ed25519_dalek::VerifyingKey = d_skey.verifying_key();

			let d_sig = d_skey.sign("test sig".as_bytes());
			println!("D sig: {:?}", d_sig);

			SerTest {
				pub_key: d_pub_key.clone(),
				pub_key_opt: Some(d_pub_key),
				sig: d_sig.clone(),
				sig_opt: Some(d_sig),
			}
		}
	}

	#[test]
	fn ser_dalek_primitives() {
		for _ in 0..10 {
			let s = SerTest::random();
			println!("Before Serialization: {:?}", s);
			let serialized = serde_json::to_string_pretty(&s).unwrap();
			println!("JSON: {}", serialized);
			let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
			println!("After Serialization: {:?}", deserialized);
			println!();
			assert_eq!(s, deserialized);
		}
	}

	#[test]
	fn malformed_dalek_lengths_are_rejected() {
		for len in [31, 33] {
			let json = format!(r#"{{"pub_key":"{}"}}"#, "00".repeat(len));
			assert!(serde_json::from_str::<OptionalPubkey>(&json)
				.map(|value| value.pub_key)
				.is_err());
		}

		for len in [63, 65] {
			let json = format!(r#"{{"sig":"{}"}}"#, "00".repeat(len));
			assert!(serde_json::from_str::<Signature>(&json)
				.map(|value| value.sig)
				.is_err());
			assert!(serde_json::from_str::<OptionalSignature>(&json)
				.map(|value| value.sig)
				.is_err());
		}
	}
}
