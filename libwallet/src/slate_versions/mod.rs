// Copyright 2019 The Grin Developers
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

use crate::slate::Slate;
use crate::slate_versions::v2::{CoinbaseV2, SlateV2};
use crate::slate_versions::v3::{CoinbaseV3, SlateV3};
use crate::slatepack::SlatePurpose;
use crate::types::CbData;
use crate::Slatepacker;
use crate::{Error, ErrorKind};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use grin_wallet_util::grin_util::secp::Secp256k1;
use std::convert::TryFrom;

pub mod ser;

#[allow(missing_docs)]
pub mod v2;
#[allow(missing_docs)]
pub mod v3;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 3;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 3;

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
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
	/// Convert this version into numeric value
	pub fn to_numeric_version(&self) -> i32 {
		match self {
			SlateVersion::SP => 4,
			SlateVersion::V3 | SlateVersion::V3B => 3,
			SlateVersion::V2 => 2,
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedSlate {
	/// Slatepack
	SP(String),
	// V3B is not needed because it is a V3 slate with some optional fields, so it is compatible
	/// Current (3.0.0 Onwards )
	V3(SlateV3),
	/// V2 (2.0.0 - Onwards)
	V2(SlateV2),
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
		slate: Slate,
		version: SlateVersion,
		content: SlatePurpose,
		sender: DalekPublicKey,
		recipient: Option<DalekPublicKey>,
		secret: &DalekSecretKey,
		use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<VersionedSlate, Error> {
		match version {
			SlateVersion::SP => {
				let armored_slatepack = Slatepacker::encrypt_to_send(
					slate,
					SlateVersion::SP,
					content,
					sender,
					recipient,
					secret,
					use_test_rng,
					secp,
				)?;
				Ok(VersionedSlate::SP(armored_slatepack))
			}
			_ => Ok(Self::into_version_plain(slate.clone(), version)?),
		}
	}

	/// Converting into the low version slate (not packed and encrypted)
	pub fn into_version_plain(
		slate: Slate,
		version: SlateVersion,
	) -> Result<VersionedSlate, Error> {
		match version {
			SlateVersion::SP => {
				return Err(ErrorKind::GenericError("Slate is encrypted".to_string()).into())
			}
			SlateVersion::V3B | SlateVersion::V3 => Ok(VersionedSlate::V3(slate.into())),
			// Left here as a reminder of what needs to be inserted on
			// the release of a new slate
			SlateVersion::V2 => {
				let s = SlateV3::from(slate);
				let s = SlateV2::try_from(&s)?;
				Ok(VersionedSlate::V2(s))
			}
		}
	}

	/// Decode into the slate and sender address.
	pub fn into_slatepack(
		&self,
		dec_key: &DalekSecretKey,
		height: u64,
		secp: &Secp256k1,
	) -> Result<Slatepacker, Error> {
		match self {
			VersionedSlate::SP(arm_slatepack) => {
				let packer = Slatepacker::decrypt_slatepack(
					arm_slatepack.as_bytes(),
					dec_key,
					height,
					secp,
				)?;
				Ok(packer)
			}
			VersionedSlate::V3(s) => Ok(Slatepacker::wrap_slate(s.clone().to_slate(false)?)),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s.clone());
				Ok(Slatepacker::wrap_slate(s.to_slate(false)?))
			}
		}
	}

	/// Non encrypted slate conversion
	pub fn into_slate_plain(&self, fix_kernel: bool) -> Result<Slate, Error> {
		match self {
			VersionedSlate::SP(_) => {
				return Err(ErrorKind::GenericError("Slate is encrypted".to_string()).into())
			}
			VersionedSlate::V3(s) => Ok(s.clone().to_slate(fix_kernel)?),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s.clone());
				Ok(s.to_slate(false)?)
			}
		}
	}

	/// Convert into the string as Json or as aString armor
	pub fn as_string(&self) -> Result<String, Error> {
		let str = match self {
			VersionedSlate::SP(s) => s.clone(),
			VersionedSlate::V3(s) => serde_json::to_string(&s).map_err(|e| {
				ErrorKind::GenericError(format!("Failed convert SlateV3 to Json, {}", e))
			})?,
			VersionedSlate::V2(s) => serde_json::to_string(&s).map_err(|e| {
				ErrorKind::GenericError(format!("Failed convert SlateV2 to Json, {}", e))
			})?,
		};
		Ok(str)
	}
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedCoinbase {
	/// Current supported coinbase version.
	V3(CoinbaseV3),
	/// Previous
	V2(CoinbaseV2),
}

impl VersionedCoinbase {
	/// convert this coinbase data to a specific versioned representation for the json api.
	pub fn into_version(cb: CbData, version: SlateVersion) -> VersionedCoinbase {
		match version {
			SlateVersion::SP | SlateVersion::V3B | SlateVersion::V3 => {
				VersionedCoinbase::V3(cb.into())
			}
			SlateVersion::V2 => VersionedCoinbase::V2(cb.into()),
		}
	}
}
