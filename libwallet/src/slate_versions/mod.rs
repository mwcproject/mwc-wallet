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

//! This module contains old slate versions and conversions to the newest slate version
//! Used for serialization and deserialization of slates in a backwards compatible way.
//! Versions earlier than V2 are removed for the 2.0.0 release, but versioning code
//! remains for future needs

use crate::slate::{Slate, SlateCtx};
use crate::slate_versions::v2::SlateV2;
use crate::slate_versions::v3::SlateV3;
use crate::slatepack::SlatePurpose;
use crate::slatepack::Slatepacker;
use crate::Error;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Deserializer, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use std::convert::TryFrom;

pub mod ser;

#[allow(missing_docs)]
pub mod v2;
#[allow(missing_docs)]
pub mod v3;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 3;

/// The mwc block header this slate is intended to be compatible with
pub const MWC_BLOCK_HEADER_VERSION: u16 = 3;

/// Existing versions of the slate
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
#[serde(crate = "serde")]
pub enum SlateVersion {
	/// SP - has a slatepack support
	SP,
	/// V3b (most current) the difference between V3b and V3 is that the way to do payment proof is different
	/// V3b support both mqs public key and dalek public key; V3 only support mqs public key.
	/// they have the same format of slate though.
	V3B,
	/// V3
	V3,
	/// V2 (2.0.0 - Onwards)
	V2,
}

impl SlateVersion {
	/// Iterate over all supported slate versions.
	pub fn iter() -> impl Iterator<Item = SlateVersion> {
		[
			SlateVersion::SP,
			SlateVersion::V3B,
			SlateVersion::V3,
			SlateVersion::V2,
		]
		.iter()
		.cloned()
	}

	/// Convert this version into numeric value
	pub fn to_numeric_version(&self) -> i32 {
		match self {
			SlateVersion::SP => 4,
			SlateVersion::V3 | SlateVersion::V3B => 3,
			SlateVersion::V2 => 2,
		}
	}
}

#[derive(Debug, Serialize, Clone)]
#[serde(crate = "serde")]
#[serde(untagged)]
/// Slate versions are serialized without an enum tag. Deserialization uses
/// the version declared by the slate rather than relying on structural
/// fallbacks, because optional fields make the V2 and V3 structures
/// intentionally overlap.
pub enum VersionedSlate {
	/// Slatepack
	SP(String),
	// V3B is not needed because it is a V3 slate with some optional fields, so it is compatible
	/// Current (3.0.0 Onwards )
	V3(SlateV3),
	/// V2 (2.0.0 - Onwards)
	V2(SlateV2),
}

pub(crate) fn validate_slatepack_recipient_version(
	version: &SlateVersion,
	has_recipient: bool,
) -> Result<(), Error> {
	if has_recipient && *version != SlateVersion::SP {
		return Err(Error::SlatepackEncodeError(format!(
			"Slatepack recipient requires SP version, requested {:?}",
			version
		)));
	}
	Ok(())
}

impl<'de> Deserialize<'de> for VersionedSlate {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = serde_json::Value::deserialize(deserializer)?;
		if let serde_json::Value::String(slatepack) = value {
			return Ok(VersionedSlate::SP(slatepack));
		}

		let version = value
			.get("version_info")
			.and_then(|info| info.get("version"))
			.and_then(serde_json::Value::as_u64)
			.or_else(|| value.get("version").and_then(serde_json::Value::as_u64))
			.ok_or_else(|| {
				serde::de::Error::custom(
					"Unable to determine slate version: missing numeric version_info.version",
				)
			})?;

		match version {
			3 => serde_json::from_value::<SlateV3>(value)
				.map(VersionedSlate::V3)
				.map_err(|e| {
					serde::de::Error::custom(format!("Unable to deserialize SlateV3: {}", e))
				}),
			2 => {
				if matches!(
					value.get("ttl_cutoff_height"),
					Some(ttl_cutoff_height) if !ttl_cutoff_height.is_null()
				) {
					return Err(serde::de::Error::custom(
						"SlateV2 does not support ttl_cutoff_height",
					));
				}

				serde_json::from_value::<SlateV2>(value)
					.map(VersionedSlate::V2)
					.map_err(|e| {
						serde::de::Error::custom(format!("Unable to deserialize SlateV2: {}", e))
					})
			}
			unsupported => Err(serde::de::Error::custom(format!(
				"Unsupported slate version {}",
				unsupported
			))),
		}
	}
}

impl VersionedSlate {
	/// Return slate version
	pub fn version(&self) -> SlateVersion {
		match *self {
			VersionedSlate::SP(_) => SlateVersion::SP,
			VersionedSlate::V3(_) => SlateVersion::V3,
			VersionedSlate::V2(_) => SlateVersion::V2,
		}
	}

	/// Return true is the slate is binary. It can be encrypted or not.
	pub fn is_slatepack(&self) -> bool {
		match self {
			VersionedSlate::SP(_) => true,
			_ => false,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(
		context_id: u32,
		slate: Slate,
		version: SlateVersion,
		content: SlatePurpose,
		sender: ed25519_dalek::VerifyingKey,
		recipient: Option<ed25519_dalek::VerifyingKey>,
		secret: &ed25519_dalek::SigningKey,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<VersionedSlate, Error> {
		validate_slatepack_recipient_version(&version, recipient.is_some())?;
		match version {
			SlateVersion::SP => {
				let armored_slatepack = Slatepacker::encrypt_to_send(
					context_id,
					slate,
					SlateVersion::SP,
					content,
					sender,
					recipient,
					secret,
					#[cfg(feature = "test-support")]
					use_test_rng,
					secp,
				)?;
				Ok(VersionedSlate::SP(armored_slatepack))
			}
			_ => Ok(Self::into_version_plain(context_id, &slate, version)?),
		}
	}

	/// Converting into the low version slate (not packed and encrypted)
	pub fn into_version_plain(
		context_id: u32,
		slate: &Slate,
		version: SlateVersion,
	) -> Result<VersionedSlate, Error> {
		let sl_ctx = SlateCtx {
			slate: slate.clone(),
			network_name: Some(global::get_network_name(context_id)),
		};
		match version {
			SlateVersion::SP => return Err(Error::GenericError("Slate is encrypted".to_string())),
			SlateVersion::V3B | SlateVersion::V3 => Ok(VersionedSlate::V3((&sl_ctx).into())),
			// Left here as a reminder of what needs to be inserted on
			// the release of a new slate
			SlateVersion::V2 => {
				let s = SlateV3::from(&sl_ctx);
				let s = SlateV2::try_from(&s)?;
				Ok(VersionedSlate::V2(s))
			}
		}
	}

	/// Decode into the slate and sender address.
	pub fn into_slatepack(
		&self,
		context_id: u32,
		dec_key: &ed25519_dalek::SigningKey,
		secp: &Secp256k1,
	) -> Result<Slatepacker, Error> {
		match self {
			VersionedSlate::SP(arm_slatepack) => {
				let packer = Slatepacker::decrypt_slatepack(
					context_id,
					arm_slatepack.as_bytes(),
					dec_key,
					secp,
				)?;
				Ok(packer)
			}
			VersionedSlate::V3(s) => Ok(Slatepacker::wrap_slate(
				s.clone()
					.to_slate(Some(global::get_network_name(context_id)), false)?,
			)),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s.clone());
				Ok(Slatepacker::wrap_slate(s.to_slate(
					Some(global::get_network_name(context_id)),
					false,
				)?))
			}
		}
	}

	/// Non encrypted slate conversion
	pub fn into_slate_plain(&self, context_id: u32, fix_kernel: bool) -> Result<Slate, Error> {
		match self {
			VersionedSlate::SP(_) => {
				return Err(Error::GenericError("Slate is encrypted".to_string()))
			}
			VersionedSlate::V3(s) => Ok(s
				.clone()
				.to_slate(Some(global::get_network_name(context_id)), fix_kernel)?),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s.clone());
				Ok(s.to_slate(Some(global::get_network_name(context_id)), false)?)
			}
		}
	}

	/// Convert into the string as Json or as aString armor
	pub fn as_string(&self) -> Result<String, Error> {
		let str = match self {
			VersionedSlate::SP(s) => s.clone(),
			VersionedSlate::V3(s) => serde_json::to_string(&s).map_err(|e| {
				Error::GenericError(format!("Failed convert SlateV3 to Json, {}", e))
			})?,
			VersionedSlate::V2(s) => serde_json::to_string(&s).map_err(|e| {
				Error::GenericError(format!("Failed convert SlateV2 to Json, {}", e))
			})?,
		};
		Ok(str)
	}
}

#[cfg(test)]
mod tests {
	use super::{SlatePurpose, SlateVersion, VersionedSlate};
	use crate::{Error, Slate, SlateCtx};
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;
	use mwc_wallet_util::mwc_crates::serde_json;

	fn v2_slate_value() -> serde_json::Value {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let slate = Slate::blank(2, false).unwrap();
		let versioned = VersionedSlate::into_version_plain(0, &slate, SlateVersion::V2).unwrap();
		serde_json::to_value(versioned).unwrap()
	}

	#[test]
	fn slate_ctx_v2_deserialization_rejects_ttl_cutoff_height() {
		let mut value = v2_slate_value();
		value.as_object_mut().unwrap().insert(
			"ttl_cutoff_height".to_string(),
			serde_json::Value::String("42".to_string()),
		);

		let error = serde_json::from_value::<SlateCtx>(value).unwrap_err();
		assert!(error
			.to_string()
			.contains("SlateV2 does not support ttl_cutoff_height"));
	}

	#[test]
	fn slate_ctx_v2_deserialization_accepts_null_ttl_cutoff_height() {
		let mut value = v2_slate_value();
		value
			.as_object_mut()
			.unwrap()
			.insert("ttl_cutoff_height".to_string(), serde_json::Value::Null);

		let slate_ctx = serde_json::from_value::<SlateCtx>(value).unwrap();
		assert_eq!(slate_ctx.slate.ttl_cutoff_height, None);
	}

	#[test]
	fn recipient_requires_slatepack_version() {
		let secp = Secp256k1::new().unwrap();
		let secret = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
		let sender = secret.verifying_key();
		let recipient = ed25519_dalek::SigningKey::from_bytes(&[8_u8; 32]).verifying_key();
		let error = VersionedSlate::into_version(
			0,
			Slate::blank(2, false).unwrap(),
			SlateVersion::V3,
			SlatePurpose::FullSlate,
			sender,
			Some(recipient),
			&secret,
			#[cfg(feature = "test-support")]
			false,
			&secp,
		)
		.unwrap_err();

		assert!(matches!(error, Error::SlatepackEncodeError(_)));
	}
}
