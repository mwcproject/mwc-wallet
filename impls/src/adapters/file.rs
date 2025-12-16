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

/// File Output 'plugin' implementation
use std::fs::{metadata, File};
use std::io::{Read, Write};

use crate::adapters::SlateGetData;
use crate::error::Error;
use crate::libwallet::{Slate, SlateVersion, VersionedSlate};
use crate::{SlateGetter, SlatePutter};
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use mwc_wallet_libwallet::slatepack;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use std::path::PathBuf;

#[derive(Clone)]
pub struct PathToSlatePutter {
	context_id: u32,
	path_buf: Option<PathBuf>,
	content: Option<SlatePurpose>,
	sender: Option<DalekPublicKey>,
	recipient: Option<DalekPublicKey>,
	slatepack_format: bool,
}

pub struct PathToSlateGetter {
	context_id: u32,
	// Path to file
	path_buf: Option<PathBuf>,
	// Or the string to read from
	slate_str: Option<String>,
}

impl PathToSlatePutter {
	// Build sender that can save slatepacks
	pub fn build_encrypted(
		context_id: u32,
		path_buf: Option<PathBuf>,
		content: SlatePurpose,
		sender: DalekPublicKey,
		recipient: Option<DalekPublicKey>,
		slatepack_format: bool,
	) -> Self {
		Self {
			context_id,
			path_buf,
			content: Some(content),
			sender: Some(sender),
			recipient: recipient,
			slatepack_format,
		}
	}

	pub fn build_plain(context_id: u32, path_buf: Option<PathBuf>) -> Self {
		Self {
			context_id,
			path_buf,
			content: None,
			sender: None,
			recipient: None,
			slatepack_format: false,
		}
	}
}

impl PathToSlateGetter {
	pub fn build_form_path(context_id: u32, path_buf: PathBuf) -> Self {
		Self {
			context_id,
			path_buf: Some(path_buf),
			slate_str: None,
		}
	}

	pub fn build_form_str(context_id: u32, slate_str: String) -> Self {
		Self {
			context_id,
			path_buf: None,
			slate_str: Some(slate_str),
		}
	}
}

impl SlatePutter for PathToSlatePutter {
	fn put_tx(
		&self,
		slate: &Slate,
		slatepack_secret: Option<&DalekSecretKey>,
		use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<String, Error> {
		let out_slate = {
			if self.recipient.is_some() || self.slatepack_format {
				// recipient is defining enrypted/nonencrypted format. Sender and content are still required.
				if self.sender.is_none() || self.content.is_none() {
					return Err(Error::GenericError(
						"Sender or content are not defined".to_string(),
					));
				}

				if slatepack_secret.is_none() {
					return Err(Error::ArgumentError(
						"slatepack_secret is not defiled for encrypted slatepack".to_string(),
					));
				}

				// Do the slatepack
				VersionedSlate::into_version(
					self.context_id,
					slate.clone(),
					SlateVersion::SP,
					self.content.clone().unwrap(),
					self.sender.clone().unwrap(),
					self.recipient.clone(),
					slatepack_secret.unwrap(),
					use_test_rng,
					secp,
				)
				.map_err(|e| Error::GenericError(format!("Unable to build a slatepack, {}", e)))?
			} else if slate.compact_slate {
				warn!("Transaction contains features that require mwc-wallet 4.0.0 or later");
				warn!("Please ensure the other party is running mwc-wallet v4.0.0 or later before sending");
				VersionedSlate::into_version_plain(self.context_id, slate, SlateVersion::V3)
					.map_err(|e| {
						Error::GenericError(format!("Failed convert Slate to Json, {}", e))
					})?
			} else if slate.payment_proof.is_some() || slate.ttl_cutoff_height.is_some() {
				warn!("Transaction contains features that require mwc-wallet 3.0.0 or later");
				warn!("Please ensure the other party is running mwc-wallet v3.0.0 or later before sending");
				VersionedSlate::into_version_plain(self.context_id, slate, SlateVersion::V3)
					.map_err(|e| {
						Error::GenericError(format!("Failed convert Slate to Json, {}", e))
					})?
			} else {
				let mut s = slate.clone();
				s.version_info.version = 2;
				VersionedSlate::into_version_plain(self.context_id, &s, SlateVersion::V2).map_err(
					|e| Error::GenericError(format!("Failed convert Slate to Json, {}", e)),
				)?
			}
		};

		let slate_str = out_slate
			.as_string()
			.map_err(|e| Error::LibWallet(format!("Unable to convert slate into string, {}", e)))?;

		if let Some(path_buf) = &self.path_buf {
			let file_name = path_buf.to_str().unwrap_or("INVALID PATH");
			let mut pub_tx = File::create(&path_buf)
				.map_err(|e| Error::IO(format!("Unable to create file {}, {}", file_name, e)))?;

			pub_tx.write_all(slate_str.as_bytes()).map_err(|e| {
				Error::IO(format!(
					"Unable to store slate at file {}, {}",
					file_name, e
				))
			})?;

			pub_tx.sync_all().map_err(|e| {
				Error::IO(format!(
					"Unable to store slate at file {}, {}",
					file_name, e
				))
			})?;
		}

		Ok(slate_str)
	}
}

impl SlateGetter for PathToSlateGetter {
	fn get_tx(
		&self,
		slatepack_secret: Option<&DalekSecretKey>,
		secp: &Secp256k1,
	) -> Result<SlateGetData, Error> {
		let content = match &self.slate_str {
			Some(str) => {
				let min_len = slatepack::min_size();
				let max_len = slatepack::max_size(self.context_id);
				let len = str.len() as u64;
				if len < min_len || len > max_len {
					return Err(Error::IO(format!(
						"Slate data had invalid length: {} | min: {}, max: {} |",
						len, min_len, max_len
					)));
				}
				str.clone()
			}
			None => {
				// Reading from the file
				if let Some(path_buf) = &self.path_buf {
					let metadata = metadata(path_buf.as_path()).map_err(|e| {
						Error::IO(format!(
							"Unable to access file {}, {}",
							path_buf.display(),
							e
						))
					})?;
					let len = metadata.len();
					let min_len = slatepack::min_size();
					let max_len = slatepack::max_size(self.context_id);

					let file_name = path_buf.to_str().unwrap_or("INVALID PATH");

					if len < min_len || len > max_len {
						return Err(Error::IO(format!(
							"Data at {} is invalid length: {} | min: {}, max: {} |",
							file_name, len, min_len, max_len
						)));
					}

					let mut pub_tx_f = File::open(&path_buf).map_err(|e| {
						Error::IO(format!("Unable to open file {}, {}", file_name, e))
					})?;
					let mut content = String::new();
					pub_tx_f.read_to_string(&mut content).map_err(|e| {
						Error::IO(format!(
							"Unable to read data from file {}, {}",
							file_name, e
						))
					})?;
					if content.len() < 3 {
						return Err(Error::GenericError(format!("File {} is empty", file_name)));
					}
					content
				} else {
					return Err(Error::GenericError(
						"PathToSlateGetter, not defined slate string or file".to_string(),
					));
				}
			}
		};

		if Slate::deserialize_is_plain(&content) {
			let slate = Slate::deserialize_upgrade_plain(self.context_id, &content)
				.map_err(|e| Error::IO(format!("Unable to build slate from the content, {}", e)))?;
			Ok(SlateGetData::PlainSlate(slate))
		} else {
			if slatepack_secret.is_none() {
				return Err(Error::ArgumentError(
					"slatepack_secret is none for get encrypted slatepack".into(),
				));
			}
			let sp = Slate::deserialize_upgrade_slatepack(
				self.context_id,
				&content,
				slatepack_secret.unwrap(),
				secp,
			)
			.map_err(|e| Error::LibWallet(format!("Unable to deserialize slatepack, {}", e)))?;
			Ok(SlateGetData::Slatepack(sp))
		}
	}
}
