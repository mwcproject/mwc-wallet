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

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::path::MAIN_SEPARATOR;

use rand::{thread_rng, Rng};
use ring::aead;
use ring::pbkdf2;
use serde_json;
use util::ZeroingString;

use crate::util;
use crate::{Error, ErrorKind};
use std::num::NonZeroU32;

pub const SEED_FILE: &str = "wallet.seed";
pub const ROOT_PK_FILE: &str = "wallet.rpk";

#[derive(Clone, Debug, PartialEq)]
pub struct WalletRootPublicKey(Vec<u8>);

pub fn show_root_public_key(phrase: ZeroingString) {
	println!("Your root public key is:");
	println!();
	println!("{}", &*phrase);
	println!();
}

impl WalletRootPublicKey {
	pub fn from_bytes(bytes: &[u8]) -> WalletRootPublicKey {
		WalletRootPublicKey(bytes.to_vec())
	}

	pub fn _from_hex(hex: &str) -> Result<WalletRootPublicKey, Error> {
		let bytes = util::from_hex(hex)
			.map_err(|e| ErrorKind::GenericError(format!("Invalid hex {}, {}", hex, e)))?;
		Ok(WalletRootPublicKey::from_bytes(&bytes))
	}

	pub fn _to_hex(&self) -> String {
		util::to_hex(&self.0)
	}

	pub fn root_pk_file_exists(data_file_dir: &str) -> Result<bool, Error> {
		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE,);
		debug!("Root Public Key file path: {}", seed_file_path);
		if Path::new(seed_file_path).exists() {
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub fn backup_root_pk(data_file_dir: &str) -> Result<String, Error> {
		let rpk_file_name = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE,);

		let mut path = Path::new(rpk_file_name).to_path_buf();
		path.pop();
		let mut backup_rpk_file_name =
			format!("{}{}{}.bak", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE);
		let mut i = 1;
		while Path::new(&backup_rpk_file_name).exists() {
			backup_rpk_file_name = format!(
				"{}{}{}.bak.{}",
				data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE, i
			);
			i += 1;
		}
		path.push(backup_rpk_file_name.clone());
		fs::rename(rpk_file_name, backup_rpk_file_name.as_str()).map_err(|e| {
			ErrorKind::GenericError(format!("Unable rename wallet seed file, {}", e))
		})?;

		warn!("{} backed up as {}", rpk_file_name, backup_rpk_file_name);
		Ok(backup_rpk_file_name)
	}

	// mwc-wallet interface
	pub fn init_file(
		data_file_dir: &str,
		password: util::ZeroingString,
		test_mode: bool,
		root_public_key: util::ZeroingString,
	) -> Result<WalletRootPublicKey, Error> {
		WalletRootPublicKey::init_file_impl(
			data_file_dir,
			password,
			true,
			true,
			None,
			test_mode,
			root_public_key,
		)
	}

	// mwc713 interface

	pub fn init_file_impl(
		data_file_dir: &str,
		password: util::ZeroingString,
		_write_rpk: bool,
		show_rpk: bool,
		_passed_rpk: Option<WalletRootPublicKey>,
		test_mode: bool,
		root_public_key: util::ZeroingString,
	) -> Result<WalletRootPublicKey, Error> {
		// create directory if it doesn't exist
		fs::create_dir_all(data_file_dir)
			.map_err(|e| ErrorKind::IO(format!("Unable create dir {}, {}", data_file_dir, e)))?;

		let rpk_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE,);
		warn!("Generating wallet seed file at: {}", rpk_file_path);
		let exists = WalletRootPublicKey::root_pk_file_exists(data_file_dir)?;
		if exists && !test_mode {
			return Err(ErrorKind::WalletRootPublicKeyExists(format!(
				"Wallet root public key already exists at: {}",
				data_file_dir
			)))?;
		}

		let rpk = WalletRootPublicKey::_from_hex(&*root_public_key)?;
		let enc_seed = EncryptedWalletRootPublicKey::from_root_public_key(&rpk, password)?;
		let enc_seed_json = serde_json::to_string_pretty(&enc_seed).map_err(|e| {
			ErrorKind::Format(format!(
				"EncryptedWalletRootPublicKey to json conversion error, {}",
				e
			))
		})?;
		let mut file = File::create(rpk_file_path).map_err(|e| {
			ErrorKind::IO(format!("Unable to create file {}, {}", rpk_file_path, e))
		})?;
		file.write_all(&enc_seed_json.as_bytes()).map_err(|e| {
			ErrorKind::IO(format!("Unable to save data to {}, {}", rpk_file_path, e))
		})?;
		if show_rpk {
			show_root_public_key(ZeroingString::from(rpk._to_hex()));
		}
		Ok(rpk)
	}

	pub fn from_file(
		data_file_dir: &str,
		password: util::ZeroingString,
	) -> Result<WalletRootPublicKey, Error> {
		// create directory if it doesn't exist
		fs::create_dir_all(data_file_dir)
			.map_err(|e| ErrorKind::IO(format!("Unable to create dir {}, {}", data_file_dir, e)))?;

		let rpk_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE,);

		debug!("Using wallet seed file at: {}", rpk_file_path);

		if Path::new(rpk_file_path).exists() {
			let mut file = File::open(rpk_file_path).map_err(|e| {
				ErrorKind::IO(format!("Unable to open file {}, {}", rpk_file_path, e))
			})?;
			let mut buffer = String::new();
			file.read_to_string(&mut buffer).map_err(|e| {
				ErrorKind::IO(format!("Unable to read from file {}, {}", rpk_file_path, e))
			})?;
			let enc_seed: EncryptedWalletRootPublicKey =
				serde_json::from_str(&buffer).map_err(|e| {
					ErrorKind::Format(format!(
						"Json to EncryptedWalletRootPublicKey conversion error, {}",
						e
					))
				})?;
			let wallet_seed = enc_seed.decrypt(&password)?;
			Ok(wallet_seed)
		} else {
			error!(
				"wallet seed file {} could not be opened (mwc wallet init). \
				 Run \"mwc wallet init\" to initialize a new wallet.",
				rpk_file_path
			);
			Err(ErrorKind::WalletRootPublicKeyDoesntExist.into())
		}
	}

	pub fn delete_root_pk_file(data_file_dir: &str) -> Result<(), Error> {
		let rpk_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, ROOT_PK_FILE,);
		if Path::new(rpk_file_path).exists() {
			debug!("Deleting wallet seed file at: {}", rpk_file_path);
			fs::remove_file(rpk_file_path).map_err(|e| {
				ErrorKind::IO(format!("Unable to remove file {}, {}", rpk_file_path, e))
			})?;
		}
		Ok(())
	}
}

/// Encrypted wallet seed, for storing on disk and decrypting
/// with provided password

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedWalletRootPublicKey {
	encrypted_seed: String,
	/// Salt, not so useful in single case but include anyhow for situations
	/// where someone wants to store many of these
	pub salt: String,
	/// Nonce
	pub nonce: String,
}

impl EncryptedWalletRootPublicKey {
	/// Create a new encrypted seed from the given seed + password
	pub fn from_root_public_key(
		root_public_key: &WalletRootPublicKey,
		password: util::ZeroingString,
	) -> Result<EncryptedWalletRootPublicKey, Error> {
		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);
		let content = root_public_key.0.to_vec();
		let mut enc_bytes = content;
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut enc_bytes,
			)
			.map_err(|e| ErrorKind::Encryption(format!("Seal in place error, {}", e)))?;

		Ok(EncryptedWalletRootPublicKey {
			encrypted_seed: util::to_hex(&enc_bytes),
			salt: util::to_hex(&salt),
			nonce: util::to_hex(&nonce),
		})
	}

	/// Decrypt root public key
	pub fn decrypt(&self, password: &str) -> Result<WalletRootPublicKey, Error> {
		let mut encrypted_seed = util::from_hex(&self.encrypted_seed)
			.map_err(|e| ErrorKind::Encryption(format!("Failed to convert seed HEX, {}", e)))?;
		let salt = util::from_hex(&self.salt)
			.map_err(|e| ErrorKind::Encryption(format!("Failed to convert salt HEX, {}", e)))?;
		let nonce = util::from_hex(&self.nonce)
			.map_err(|e| ErrorKind::Encryption(format!("Failed to convert nonce HEX, {}", e)))?;

		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);

		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(n),
				aad,
				&mut encrypted_seed,
			)
			.map_err(|e| ErrorKind::Encryption(format!("Open in place error, {}", e)))?;

		for _ in 0..aead::AES_256_GCM.tag_len() {
			encrypted_seed.pop();
		}

		Ok(WalletRootPublicKey::from_bytes(&encrypted_seed))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ZeroingString;
	#[test]
	fn wallet_root_pk_encrypt() {
		let password = ZeroingString::from("passwoid");
		let wallet_rpk = ZeroingString::from(
			"03631e0596e299e51a0be8cfe28a610299a0888ddb6a1af00ebd5af966f0ac6bb4",
		);
		let rpk = WalletRootPublicKey::_from_hex(&*wallet_rpk).unwrap();
		println!("WPRK: {:?}", rpk._to_hex());

		// Encrypt rpk
		let mut enc_wallet_seed =
			EncryptedWalletRootPublicKey::from_root_public_key(&rpk, password.clone()).unwrap();
		println!("EWS: {:?}", enc_wallet_seed);

		// Decrypt RPK
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password).unwrap();
		assert_eq!(rpk, decrypted_wallet_seed);
		println!("DPRK: {:?}", decrypted_wallet_seed._to_hex());

		// Wrong password
		let decrypted_wallet_seed = enc_wallet_seed.decrypt("");
		assert!(decrypted_wallet_seed.is_err());

		// Wrong nonce
		enc_wallet_seed.nonce = "wrongnonce".to_owned();
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password);
		assert!(decrypted_wallet_seed.is_err());
	}
}
