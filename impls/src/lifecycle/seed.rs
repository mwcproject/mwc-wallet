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

use mwc_wallet_util::mwc_crates::ring;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use std::fs::{self, File};
use std::io::Read;
use std::path::{MAIN_SEPARATOR, Path};

use mwc_wallet_util::mwc_crates::argon2::{Algorithm, Argon2, Block, Params, Version};
use mwc_wallet_util::mwc_crates::chacha20poly1305::{
	ChaCha20Poly1305,
	aead::{AeadInOut, KeyInit},
};
use mwc_wallet_util::mwc_crates::rand::{TryRng, rngs::SysRng};
use mwc_wallet_util::mwc_crates::ring::pbkdf2;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;

use crate::Error;
use mwc_wallet_util::mwc_crates::log::{debug, error, warn};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{Keychain, mnemonic};
use mwc_wallet_util::mwc_util::{self, ToHex};
use std::io::ErrorKind;
use std::num::NonZeroU32;

pub const SEED_FILE: &str = "wallet.seed";
const VALID_MNEMONIC_ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

#[derive(Clone, PartialEq)]
pub struct WalletSeed(Zeroizing<Vec<u8>>);

pub fn show_recovery_phrase(phrase: mwc_util::ZeroingString) {
	println!("Your recovery phrase is:");
	println!();
	println!("{}", &*phrase);
	println!();
	println!("Please back-up these words in a non-digital format.");
}

fn serialize_seed_file(enc_seed: &EncryptedWalletSeed) -> Result<String, Error> {
	serde_json::to_string_pretty(enc_seed).map_err(|e| {
		Error::Format(format!(
			"EncryptedWalletSeed to json conversion error, {}",
			e
		))
	})
}

fn write_new_seed_file(seed_file_path: &Path, enc_seed: &EncryptedWalletSeed) -> Result<(), Error> {
	let enc_seed_json = serialize_seed_file(enc_seed)?;
	mwc_util::file::write_new_owner_only_file(seed_file_path, enc_seed_json.as_bytes()).map_err(
		|e| {
			if e.kind() == ErrorKind::AlreadyExists {
				Error::WalletSeedExists(seed_file_path.display().to_string())
			} else {
				Error::IO(format!(
					"Unable to create seed file {}, {}",
					seed_file_path.display(),
					e
				))
			}
		},
	)
}

fn replace_seed_file(seed_file_path: &Path, enc_seed: &EncryptedWalletSeed) -> Result<(), Error> {
	let enc_seed_json = serialize_seed_file(enc_seed)?;
	mwc_util::file::replace_owner_only_file(seed_file_path, enc_seed_json.as_bytes()).map_err(|e| {
		Error::IO(format!(
			"Unable to replace seed file {}, {}",
			seed_file_path.display(),
			e
		))
	})
}

impl WalletSeed {
	pub(crate) fn validate_mnemonic_length(seed_length: usize) -> Result<(), Error> {
		if VALID_MNEMONIC_ENTROPY_LENGTHS.contains(&seed_length) {
			Ok(())
		} else {
			Err(Error::ArgumentError(format!(
				"Invalid mnemonic entropy length {}; expected one of 16, 20, 24, 28, or 32 bytes",
				seed_length
			)))
		}
	}

	pub fn from_bytes(bytes: &[u8]) -> WalletSeed {
		WalletSeed(Zeroizing::new(bytes.to_vec()))
	}

	pub fn from_mnemonic(word_list: mwc_util::ZeroingString) -> Result<WalletSeed, Error> {
		let res = mnemonic::to_entropy(&word_list);
		match res {
			Ok(s) => Ok(WalletSeed::from_bytes(&s)),
			Err(e) => Err(Error::Mnemonic(format!(
				"Unable to convert mnemonic passphrase into seed, {}",
				e
			))),
		}
	}

	pub fn to_mnemonic(&self) -> Result<mwc_util::ZeroingString, Error> {
		let result = mnemonic::from_entropy(&self.0);
		match result {
			Ok(r) => Ok(mwc_util::ZeroingString::from(r.to_string())),
			Err(e) => Err(Error::Mnemonic(format!(
				"Unable convert seed to mnemonic, {}",
				e
			))),
		}
	}

	pub fn derive_keychain<K: Keychain>(
		&self,
		secp: &Secp256k1,
		is_floonet: bool,
	) -> Result<K, Error> {
		let result = K::from_seed(secp, &self.0, is_floonet)?;
		Ok(result)
	}

	pub fn init_new(seed_length: usize) -> Result<WalletSeed, Error> {
		WalletSeed::validate_mnemonic_length(seed_length)?;
		let mut seed = vec![0u8; seed_length];
		SysRng
			.try_fill_bytes(&mut seed)
			.map_err(|e| Error::GenericError(format!("Unable to generate wallet seed, {}", e)))?;
		Ok(WalletSeed(Zeroizing::new(seed)))
	}

	pub(crate) fn from_init_args(
		seed_length: usize,
		recovery_phrase: Option<mwc_util::ZeroingString>,
	) -> Result<WalletSeed, Error> {
		match recovery_phrase {
			Some(phrase) => WalletSeed::from_mnemonic(phrase),
			None => WalletSeed::init_new(seed_length),
		}
	}

	fn seed_file_target(
		data_file_dir: &str,
		#[cfg(feature = "test-support")] test_mode: bool,
	) -> Result<(std::path::PathBuf, bool), Error> {
		let data_file_dir_path = Path::new(data_file_dir);
		mwc_util::file::ensure_owner_only_dir_all(data_file_dir_path).map_err(|e| {
			Error::IO(format!(
				"Unable to create owner-only wallet directory {}, {}",
				data_file_dir, e
			))
		})?;

		let seed_file_path = data_file_dir_path.join(SEED_FILE);
		warn!(
			"Generating wallet seed file at: {}",
			seed_file_path.display()
		);
		let exists = WalletSeed::seed_file_exists(data_file_dir)?;
		#[cfg(feature = "test-support")]
		let reject_existing_wallet = !test_mode;
		#[cfg(not(feature = "test-support"))]
		let reject_existing_wallet = true;
		if exists && reject_existing_wallet {
			return Err(Error::WalletSeedExists(format!(
				"Wallet seed already exists at: {}",
				data_file_dir
			)));
		}

		Ok((seed_file_path, exists))
	}

	fn persist_file_at(
		&self,
		seed_file_path: &Path,
		exists: bool,
		password: mwc_util::ZeroingString,
	) -> Result<(), Error> {
		let enc_seed = EncryptedWalletSeed::from_seed(self, password)?;
		if exists {
			replace_seed_file(seed_file_path, &enc_seed)
		} else {
			write_new_seed_file(seed_file_path, &enc_seed)
		}
	}

	pub(crate) fn persist_file(
		&self,
		data_file_dir: &str,
		password: mwc_util::ZeroingString,
		#[cfg(feature = "test-support")] test_mode: bool,
	) -> Result<(), Error> {
		WalletSeed::validate_mnemonic_length(self.0.len())?;
		let (seed_file_path, exists) = WalletSeed::seed_file_target(
			data_file_dir,
			#[cfg(feature = "test-support")]
			test_mode,
		)?;
		self.persist_file_at(&seed_file_path, exists, password)
	}

	pub fn seed_file_exists(data_file_dir: &str) -> Result<bool, Error> {
		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);
		debug!("Seed file path: {}", seed_file_path);
		Path::new(seed_file_path).try_exists().map_err(|e| {
			Error::IO(format!(
				"Unable to check seed file existence at {}, {}",
				seed_file_path, e
			))
		})
	}

	pub fn backup_seed(data_file_dir: &str) -> Result<String, Error> {
		let seed_file_name = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);
		let seed_file = Zeroizing::new(fs::read(seed_file_name).map_err(|e| {
			Error::IO(format!(
				"Unable to read wallet seed file {} for backup, {}",
				seed_file_name, e
			))
		})?);
		let mut suffix: Option<u64> = None;
		let backup_seed_file_name = loop {
			let candidate = match suffix {
				None => format!("{}{}{}.bak", data_file_dir, MAIN_SEPARATOR, SEED_FILE),
				Some(i) => format!("{}{}{}.bak.{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE, i),
			};

			// Atomically reserve a new owner-only backup name, then synchronize the
			// complete backup before the original is removed below.
			match mwc_util::file::write_new_owner_only_file(&candidate, seed_file.as_slice()) {
				Ok(()) => break candidate,
				Err(e) if e.kind() == ErrorKind::AlreadyExists => {
					suffix = Some(match suffix {
						None => 1,
						Some(i) => i.checked_add(1).ok_or_else(|| {
							Error::DataOverflow(format!(
								"WalletSeed::backup_seed, wallet seed backup suffix overflow, suffix={} increment=1",
								i
							))
						})?,
					});
				}
				Err(e) => {
					return Err(Error::IO(format!(
						"Unable to write wallet seed backup {} from {}, {}",
						candidate, seed_file_name, e,
					)));
				}
			}
		};

		// The backup is already durable. Remove the original and synchronize its
		// parent so a successful return also makes that removal durable.
		mwc_wallet_util::file::remove_file_and_sync_parent(seed_file_name).map_err(|e| {
			Error::IO(format!(
				"Wallet seed backup {} was created, but unable to durably remove original file {}, {}",
				backup_seed_file_name, seed_file_name, e
			))
		})?;

		warn!("{} backed up as {}", seed_file_name, backup_seed_file_name);
		Ok(backup_seed_file_name)
	}

	pub fn recover_from_phrase(
		data_file_dir: &str,
		word_list: mwc_util::ZeroingString,
		password: mwc_util::ZeroingString,
	) -> Result<(), Error> {
		let data_file_dir_path = Path::new(data_file_dir);
		debug!("data file dir: {}", data_file_dir);
		mwc_util::file::ensure_existing_owner_only_dir(data_file_dir_path).map_err(|e| {
			if e.kind() == ErrorKind::NotFound {
				Error::WalletDoesntExist(
					data_file_dir.to_owned(),
					"To create a new wallet from a recovery phrase, use 'mwc-wallet init -r'"
						.to_owned(),
				)
			} else {
				Error::IO(format!(
					"Unable to secure wallet directory {}, {}",
					data_file_dir, e
				))
			}
		})?;

		// Accepted risk: recovery is an explicit request to overwrite the current
		// seed. Move the old seed aside first and do not roll it back if validating,
		// encrypting, or writing the replacement later fails. The active wallet.seed
		// may therefore be absent after an error. Loss of access to the old seed is
		// accepted as part of that explicit replacement request; retaining or
		// restoring the backup is the user's responsibility.
		if WalletSeed::seed_file_exists(data_file_dir)? {
			debug!("seed file exists");
			WalletSeed::backup_seed(data_file_dir)?;
		}

		let seed_file_path = data_file_dir_path.join(SEED_FILE);
		let seed = WalletSeed::from_mnemonic(word_list)?;
		let enc_seed = EncryptedWalletSeed::from_seed(&seed, password)?;
		write_new_seed_file(&seed_file_path, &enc_seed)?;
		warn!("Seed created from word list");
		Ok(())
	}

	// mwc-wallet interface
	pub fn init_file(
		data_file_dir: &str,
		seed_length: usize,
		recovery_phrase: Option<mwc_util::ZeroingString>,
		password: mwc_util::ZeroingString,
		show_seed: bool,
		#[cfg(feature = "test-support")] test_mode: bool,
	) -> Result<WalletSeed, Error> {
		WalletSeed::init_file_impl(
			data_file_dir,
			seed_length,
			recovery_phrase,
			password,
			true,
			show_seed,
			None,
			#[cfg(feature = "test-support")]
			test_mode,
		)
	}

	// mwc713 interface

	pub fn init_file_impl(
		data_file_dir: &str,
		seed_length: usize,
		recovery_phrase: Option<mwc_util::ZeroingString>,
		password: mwc_util::ZeroingString,
		write_seed: bool,
		show_seed: bool,
		passed_seed: Option<WalletSeed>,
		#[cfg(feature = "test-support")] test_mode: bool,
	) -> Result<WalletSeed, Error> {
		if let Some(seed) = passed_seed.as_ref() {
			WalletSeed::validate_mnemonic_length(seed.0.len())?;
		} else if recovery_phrase.is_none() {
			WalletSeed::validate_mnemonic_length(seed_length)?;
		}

		let (seed_file_path, exists) = WalletSeed::seed_file_target(
			data_file_dir,
			#[cfg(feature = "test-support")]
			test_mode,
		)?;

		let mut seed = WalletSeed::from_init_args(seed_length, recovery_phrase)?;

		if let Some(s) = passed_seed {
			seed = s;
		}
		let recovery_phrase = if show_seed {
			Some(seed.to_mnemonic()?)
		} else {
			None
		};

		if write_seed {
			seed.persist_file_at(&seed_file_path, exists, password)?;
		}

		if let Some(recovery_phrase) = recovery_phrase {
			show_recovery_phrase(recovery_phrase);
		}

		Ok(seed)
	}

	pub fn from_file(
		data_file_dir: &str,
		password: mwc_util::ZeroingString,
	) -> Result<WalletSeed, Error> {
		mwc_util::file::ensure_owner_only_dir_all(data_file_dir).map_err(|e| {
			Error::IO(format!(
				"Unable to create owner-only wallet directory {}, {}",
				data_file_dir, e
			))
		})?;

		let seed_file_path = Path::new(data_file_dir).join(SEED_FILE);

		debug!("Using wallet seed file at: {}", seed_file_path.display());

		let mut file = match File::open(&seed_file_path) {
			Ok(f) => f,
			Err(e) if e.kind() == ErrorKind::NotFound => {
				error!(
					"wallet seed file {} could not be opened (mwc wallet init). \
					 Run \"mwc wallet init\" to initialize a new wallet.",
					seed_file_path.display()
				);
				return Err(Error::WalletSeedDoesntExist);
			}
			Err(e) => {
				return Err(Error::IO(format!(
					"Unable to open file {}, {}",
					seed_file_path.display(),
					e
				)));
			}
		};
		let mut buffer = String::new();
		file.read_to_string(&mut buffer).map_err(|e| {
			Error::IO(format!(
				"Unable to read from file {}, {}",
				seed_file_path.display(),
				e
			))
		})?;
		// Windows does not permit the migration's atomic rename while the
		// destination is still open. Release the read handle as soon as its
		// contents have been loaded.
		drop(file);
		let enc_seed: EncryptedWalletSeed = serde_json::from_str(&buffer).map_err(|e| {
			Error::Format(format!(
				"Json to EncryptedWalletSeed conversion error, {}",
				e
			))
		})?;
		let wallet_seed = enc_seed.decrypt(&password)?;
		if enc_seed.is_legacy() {
			// Upgrade the on-disk seed file to the current KDF. A failure here
			// must not lock the user out of the wallet, so log and continue
			// with the decrypted seed.
			match EncryptedWalletSeed::from_seed(&wallet_seed, password)
				.and_then(|upgraded| replace_seed_file(&seed_file_path, &upgraded))
			{
				Ok(()) => debug!(
					"Migrated wallet seed file {} to Argon2id KDF",
					seed_file_path.display()
				),
				Err(e) => warn!(
					"Unable to migrate wallet seed file {} to Argon2id KDF, {}",
					seed_file_path.display(),
					e
				),
			}
		}
		Ok(wallet_seed)
	}

	pub fn delete_seed_file(data_file_dir: &str) -> Result<(), Error> {
		let seed_file_path = Path::new(data_file_dir).join(SEED_FILE);
		debug!("Deleting wallet seed file at: {}", seed_file_path.display());
		match mwc_wallet_util::file::remove_file_and_sync_parent(&seed_file_path) {
			Ok(()) => Ok(()),
			Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
			Err(e) => Err(Error::IO(format!(
				"Unable to durably remove file {}, {}",
				seed_file_path.display(),
				e
			))),
		}
	}
}

/// Encrypted wallet seed, for storing on disk and decrypting
/// with provided password

/// KDF algorithm identifier used by current seed files
const KDF_ALGORITHM_ARGON2ID: &str = "argon2id";
/// RFC 9106 recommended Argon2id profile: 64 MiB memory, 3 iterations, 4 lanes
const ARGON2ID_M_COST_KIB: u32 = 64 * 1024;
const ARGON2ID_T_COST: u32 = 3;
const ARGON2ID_P_COST: u32 = 4;
/// Maximum Argon2id resource costs accepted from an untrusted seed file.
/// Raise these only when a higher-cost profile is intentionally supported.
const ARGON2ID_MAX_M_COST_KIB: u32 = 64 * 1024;
const ARGON2ID_MAX_T_COST: u32 = 3;
const ARGON2ID_MAX_P_COST: u32 = 4;
/// PBKDF2 iteration count used by legacy seed files
const LEGACY_PBKDF2_ITERATIONS: u32 = 100;

/// KDF parameters used to derive the seed encryption key from the password.
/// Stored in the seed file so the work factor can be raised without
/// breaking existing wallets. Absent in legacy files, which used
/// PBKDF2-HMAC-SHA512 with 100 iterations.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "serde")]
pub struct KdfParams {
	/// KDF algorithm identifier, currently only "argon2id"
	pub algorithm: String,
	/// Memory cost in KiB
	pub m_cost: u32,
	/// Time cost (iterations)
	pub t_cost: u32,
	/// Parallelism (lanes)
	pub p_cost: u32,
}

impl KdfParams {
	/// Parameters used for newly written seed files
	fn current() -> Self {
		KdfParams {
			algorithm: KDF_ALGORITHM_ARGON2ID.to_owned(),
			m_cost: ARGON2ID_M_COST_KIB,
			t_cost: ARGON2ID_T_COST,
			p_cost: ARGON2ID_P_COST,
		}
	}

	/// Validate the algorithm and enforce application-level resource limits
	/// before constructing Argon2 parameters or allocating its workspace.
	fn validate_supported(&self) -> Result<(), Error> {
		if self.algorithm != KDF_ALGORITHM_ARGON2ID {
			return Err(Error::Encryption(format!(
				"Unsupported wallet seed KDF: {}",
				self.algorithm
			)));
		}

		if self.m_cost > ARGON2ID_MAX_M_COST_KIB
			|| self.t_cost > ARGON2ID_MAX_T_COST
			|| self.p_cost > ARGON2ID_MAX_P_COST
		{
			return Err(Error::Encryption(format!(
				"Argon2id costs exceed supported limits: m_cost={}, t_cost={}, p_cost={}; \
				 maximum supported values are {}, {}, {}",
				self.m_cost,
				self.t_cost,
				self.p_cost,
				ARGON2ID_MAX_M_COST_KIB,
				ARGON2ID_MAX_T_COST,
				ARGON2ID_MAX_P_COST,
			)));
		}

		Ok(())
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "serde")]
pub struct EncryptedWalletSeed {
	encrypted_seed: String,
	/// Salt, not so useful in single case but include anyhow for situations
	/// where someone wants to store many of these
	pub salt: String,
	/// Nonce
	pub nonce: String,
	/// KDF parameters; absent (legacy format) means PBKDF2-HMAC-SHA512
	/// with 100 iterations
	#[serde(default, skip_serializing_if = "Option::is_none")]
	kdf: Option<KdfParams>,
}

impl EncryptedWalletSeed {
	/// Create a new encrypted seed from the given seed + password,
	/// using the current KDF (Argon2id)
	pub fn from_seed(
		seed: &WalletSeed,
		password: mwc_util::ZeroingString,
	) -> Result<EncryptedWalletSeed, Error> {
		Self::from_seed_with_kdf(seed, password, Some(KdfParams::current()))
	}

	/// Create a new encrypted seed using an explicit KDF. `kdf == None`
	/// writes the legacy format (PBKDF2-HMAC-SHA512, 100 iterations).
	fn from_seed_with_kdf(
		seed: &WalletSeed,
		password: mwc_util::ZeroingString,
		kdf: Option<KdfParams>,
	) -> Result<EncryptedWalletSeed, Error> {
		// Legacy files used an 8 byte salt; use 16 bytes for the new format
		let mut salt = vec![0u8; if kdf.is_some() { 16 } else { 8 }];
		let mut nonce = [0u8; 12];
		SysRng.try_fill_bytes(&mut salt).map_err(|e| {
			Error::GenericError(format!("Unable to generate wallet seed salt, {}", e))
		})?;
		SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
			Error::GenericError(format!("Unable to generate wallet seed nonce, {}", e))
		})?;
		let key = Self::derive_key(&salt, password.as_bytes(), kdf.as_ref())?;
		let mut enc_bytes = Zeroizing::new(seed.0.to_vec());
		let sealing_key = ChaCha20Poly1305::new((&*key).into());
		drop(key);
		sealing_key
			.encrypt_in_place((&nonce).into(), &[], &mut *enc_bytes)
			.map_err(|e| Error::Encryption(format!("Seal in place error, {}", e)))?;
		drop(sealing_key);

		Ok(EncryptedWalletSeed {
			encrypted_seed: enc_bytes.to_hex(),
			salt: salt.to_hex(),
			nonce: nonce.to_hex(),
			kdf,
		})
	}

	/// Whether this seed file uses the legacy KDF (PBKDF2-HMAC-SHA512,
	/// 100 iterations) and should be migrated to the current format
	pub fn is_legacy(&self) -> bool {
		self.kdf.is_none()
	}

	/// Derive the seed encryption key from the password. `kdf == None`
	/// means a legacy seed file (PBKDF2-HMAC-SHA512, 100 iterations).
	fn derive_key(
		salt: &[u8],
		password: &[u8],
		kdf: Option<&KdfParams>,
	) -> Result<Zeroizing<[u8; 32]>, Error> {
		let mut key = Zeroizing::new([0u8; 32]);
		match kdf {
			None => {
				pbkdf2::derive(
					ring::pbkdf2::PBKDF2_HMAC_SHA512,
					NonZeroU32::new(LEGACY_PBKDF2_ITERATIONS).ok_or_else(|| {
						Error::Encryption("PBKDF2 iteration count must be non-zero".to_string())
					})?,
					salt,
					password,
					&mut *key,
				);
			}
			Some(p) => {
				p.validate_supported()?;
				let params =
					Params::new(p.m_cost, p.t_cost, p.p_cost, Some(key.len())).map_err(|e| {
						Error::Encryption(format!("Invalid Argon2id parameters, {}", e))
					})?;
				let block_count = params.block_count();
				let mut memory_blocks = Vec::new();
				memory_blocks.try_reserve_exact(block_count).map_err(|e| {
					Error::Encryption(format!("Unable to allocate Argon2id workspace, {}", e))
				})?;
				memory_blocks.resize(block_count, Block::default());
				let mut memory_blocks = Zeroizing::new(memory_blocks);
				Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
					.hash_password_into_with_memory(
						password,
						salt,
						&mut *key,
						memory_blocks.as_mut_slice(),
					)
					.map_err(|e| {
						Error::Encryption(format!("Argon2id key derivation failed, {}", e))
					})?;
			}
		}
		Ok(key)
	}

	/// Decrypt seed
	pub fn decrypt(&self, password: &str) -> Result<WalletSeed, Error> {
		let mut encrypted_seed = Zeroizing::new(
			mwc_util::from_hex(&self.encrypted_seed)
				.map_err(|e| Error::Encryption(format!("Failed to convert seed HEX, {}", e)))?,
		);
		let salt = mwc_util::from_hex(&self.salt)
			.map_err(|e| Error::Encryption(format!("Failed to convert salt HEX, {}", e)))?;
		let nonce = mwc_util::from_hex(&self.nonce)
			.map_err(|e| Error::Encryption(format!("Failed to convert nonce HEX, {}", e)))?;

		let key = Self::derive_key(&salt, password.as_bytes(), self.kdf.as_ref())?;

		let n: [u8; 12] = nonce.try_into().map_err(|_| {
			Error::Encryption("Wallet seed nonce must contain exactly 12 bytes".to_string())
		})?;
		let opening_key = ChaCha20Poly1305::new((&*key).into());
		drop(key);
		opening_key
			.decrypt_in_place((&n).into(), &[], &mut *encrypted_seed)
			.map_err(|e| Error::Encryption(format!("Open in place error, {}", e)))?;
		drop(opening_key);

		// Move the plaintext buffer into the seed instead of copying it,
		// so a single zeroized copy of the entropy remains
		Ok(WalletSeed(encrypted_seed))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_util::ZeroingString;
	use mwc_wallet_util::mwc_crates::ring::aead as ring_aead;

	#[test]
	fn wallet_seed_aead_key_zeroizes_on_drop() {
		fn assert_zeroize_on_drop<T: mwc_wallet_util::mwc_crates::zeroize::ZeroizeOnDrop>() {}

		assert_zeroize_on_drop::<ChaCha20Poly1305>();
	}

	#[test]
	fn wallet_seed_mnemonic_uses_zeroing_string_and_round_trips() {
		fn assert_zeroing_string(_: &ZeroingString) {}

		let seed = WalletSeed::from_bytes(&[0x42; 32]);
		let mnemonic = seed.to_mnemonic().unwrap();
		assert_zeroing_string(&mnemonic);
		assert!(WalletSeed::from_mnemonic(mnemonic).unwrap() == seed);
	}

	#[test]
	fn wallet_seed_aead_is_ring_compatible() {
		let key = [0x42; 32];
		let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
		let plaintext = b"mwc wallet seed AEAD compatibility";

		let mut ring_ciphertext = plaintext.to_vec();
		let ring_unbound_key =
			ring_aead::UnboundKey::new(&ring_aead::CHACHA20_POLY1305, &key).unwrap();
		let ring_sealing_key = ring_aead::LessSafeKey::new(ring_unbound_key);
		ring_sealing_key
			.seal_in_place_append_tag(
				ring_aead::Nonce::assume_unique_for_key(nonce),
				ring_aead::Aad::from(&[]),
				&mut ring_ciphertext,
			)
			.unwrap();

		let mut rustcrypto_ciphertext = plaintext.to_vec();
		let rustcrypto_sealing_key = ChaCha20Poly1305::new((&key).into());
		rustcrypto_sealing_key
			.encrypt_in_place((&nonce).into(), &[], &mut rustcrypto_ciphertext)
			.unwrap();

		assert_eq!(ring_ciphertext, rustcrypto_ciphertext);

		let rustcrypto_opening_key = ChaCha20Poly1305::new((&key).into());
		rustcrypto_opening_key
			.decrypt_in_place((&nonce).into(), &[], &mut ring_ciphertext)
			.unwrap();
		assert_eq!(ring_ciphertext, plaintext);

		let ring_unbound_key =
			ring_aead::UnboundKey::new(&ring_aead::CHACHA20_POLY1305, &key).unwrap();
		let ring_opening_key = ring_aead::LessSafeKey::new(ring_unbound_key);
		let plaintext_len = ring_opening_key
			.open_in_place(
				ring_aead::Nonce::assume_unique_for_key(nonce),
				ring_aead::Aad::from(&[]),
				&mut rustcrypto_ciphertext,
			)
			.unwrap()
			.len();
		rustcrypto_ciphertext.truncate(plaintext_len);
		assert_eq!(rustcrypto_ciphertext, plaintext);
	}

	#[test]
	fn wallet_seed_encrypt() {
		let password = ZeroingString::from("passwoid");
		let wallet_seed = WalletSeed::init_new(32).unwrap();
		let mut enc_wallet_seed =
			EncryptedWalletSeed::from_seed(&wallet_seed, password.clone()).unwrap();
		println!("EWS: {:?}", enc_wallet_seed);
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password).unwrap();
		assert!(wallet_seed == decrypted_wallet_seed);

		// Wrong password
		let decrypted_wallet_seed = enc_wallet_seed.decrypt("");
		assert!(decrypted_wallet_seed.is_err());

		// Wrong nonce
		enc_wallet_seed.nonce = "wrongnonce".to_owned();
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password);
		assert!(decrypted_wallet_seed.is_err());
	}

	#[test]
	fn wallet_seed_legacy_kdf() {
		// Legacy format (no kdf field) must still decrypt with PBKDF2
		let password = ZeroingString::from("legacy_password");
		let wallet_seed = WalletSeed::init_new(32).unwrap();
		let enc_wallet_seed =
			EncryptedWalletSeed::from_seed_with_kdf(&wallet_seed, password.clone(), None).unwrap();
		assert!(enc_wallet_seed.is_legacy());
		let json = serde_json::to_string_pretty(&enc_wallet_seed).unwrap();
		assert!(!json.contains("kdf"));
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password).unwrap();
		assert!(wallet_seed == decrypted_wallet_seed);
	}

	#[test]
	fn deserialized_excessive_argon2id_costs_are_rejected() {
		let excessive_params = [
			KdfParams {
				m_cost: ARGON2ID_MAX_M_COST_KIB + 1,
				..KdfParams::current()
			},
			KdfParams {
				t_cost: ARGON2ID_MAX_T_COST + 1,
				..KdfParams::current()
			},
			KdfParams {
				p_cost: ARGON2ID_MAX_P_COST + 1,
				..KdfParams::current()
			},
			KdfParams {
				m_cost: u32::MAX,
				..KdfParams::current()
			},
			KdfParams {
				t_cost: u32::MAX,
				..KdfParams::current()
			},
			KdfParams {
				p_cost: u32::MAX,
				..KdfParams::current()
			},
		];

		for params in excessive_params {
			let encrypted_seed = EncryptedWalletSeed {
				encrypted_seed: String::new(),
				salt: "00".repeat(16),
				nonce: "00".repeat(12),
				kdf: Some(params),
			};
			let json = serde_json::to_string(&encrypted_seed).unwrap();
			let deserialized: EncryptedWalletSeed = serde_json::from_str(&json).unwrap();
			let error = deserialized
				.decrypt("password")
				.err()
				.expect("excessive Argon2id costs must be rejected");
			let Error::Encryption(message) = error else {
				panic!("unexpected error type: {error}");
			};
			assert!(message.contains("costs exceed supported limits"));
		}
	}

	#[test]
	fn invalid_mnemonic_length_is_rejected_before_filesystem_changes() {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_dir = temp_dir.path().join("wallet");
		let result = WalletSeed::init_file(
			wallet_dir.to_str().unwrap(),
			17,
			None,
			ZeroingString::from("password"),
			false,
			#[cfg(feature = "test-support")]
			false,
		);

		assert!(matches!(result, Err(Error::ArgumentError(_))));
		assert!(!wallet_dir.exists());
	}

	#[test]
	fn wallet_seed_file_is_created_owner_only() {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_dir = temp_dir.path().join("wallet");
		WalletSeed::init_file(
			wallet_dir.to_str().unwrap(),
			16,
			None,
			ZeroingString::from("password"),
			false,
			#[cfg(feature = "test-support")]
			false,
		)
		.unwrap();

		let seed_file = wallet_dir.join(SEED_FILE);
		assert!(seed_file.is_file());

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			assert_eq!(
				fs::metadata(&wallet_dir).unwrap().permissions().mode() & 0o777,
				0o700
			);
			assert_eq!(
				fs::metadata(&seed_file).unwrap().permissions().mode() & 0o777,
				0o600
			);
		}
	}

	#[test]
	fn backup_seed_uses_first_available_name_without_overwriting() {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let data_file_dir = temp_dir.path().to_str().unwrap();
		let seed_file = temp_dir.path().join(SEED_FILE);
		let first_backup = temp_dir.path().join(format!("{}.bak", SEED_FILE));
		let second_backup = temp_dir.path().join(format!("{}.bak.1", SEED_FILE));

		mwc_util::file::write_new_owner_only_file(&first_backup, b"older encrypted seed").unwrap();
		mwc_util::file::write_new_owner_only_file(&seed_file, b"current encrypted seed").unwrap();

		let backup_name = WalletSeed::backup_seed(data_file_dir).unwrap();

		assert_eq!(Path::new(&backup_name), second_backup);
		assert!(!seed_file.exists());
		assert_eq!(fs::read(first_backup).unwrap(), b"older encrypted seed");
		assert_eq!(fs::read(second_backup).unwrap(), b"current encrypted seed");
	}

	#[test]
	fn delete_seed_file_removes_existing_file_and_accepts_missing_file() {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let data_file_dir = temp_dir.path().to_str().unwrap();
		let seed_file = temp_dir.path().join(SEED_FILE);
		fs::write(&seed_file, b"encrypted seed").unwrap();

		WalletSeed::delete_seed_file(data_file_dir).unwrap();
		assert!(!seed_file.exists());
		WalletSeed::delete_seed_file(data_file_dir).unwrap();
	}

	#[cfg(unix)]
	#[test]
	fn delete_seed_file_removes_broken_symlink() {
		use std::os::unix::fs::symlink;

		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let data_file_dir = temp_dir.path().to_str().unwrap();
		let seed_file = temp_dir.path().join(SEED_FILE);
		symlink(temp_dir.path().join("missing-target"), &seed_file).unwrap();
		assert!(fs::symlink_metadata(&seed_file).is_ok());
		assert!(!seed_file.exists());

		WalletSeed::delete_seed_file(data_file_dir).unwrap();
		assert!(matches!(
			fs::symlink_metadata(seed_file),
			Err(e) if e.kind() == ErrorKind::NotFound
		));
	}

	#[test]
	fn wallet_seed_migration() {
		let password = ZeroingString::from("migration_password");
		let wallet_seed = WalletSeed::init_new(32).unwrap();

		// Write a legacy (PBKDF2) seed file
		let legacy_seed =
			EncryptedWalletSeed::from_seed_with_kdf(&wallet_seed, password.clone(), None).unwrap();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_dir = temp_dir.path().join("wallet");
		mwc_util::file::ensure_owner_only_dir_all(&wallet_dir).unwrap();
		let data_file_dir = wallet_dir.to_str().unwrap().to_owned();
		let seed_file_path = wallet_dir.join(SEED_FILE);
		write_new_seed_file(&seed_file_path, &legacy_seed).unwrap();

		// Loading the seed must decrypt it and migrate the file to Argon2id
		let loaded_seed = WalletSeed::from_file(&data_file_dir, password.clone()).unwrap();
		assert!(wallet_seed == loaded_seed);

		let migrated_json = fs::read_to_string(&seed_file_path).unwrap();
		assert!(migrated_json.contains("argon2id"));
		let migrated_seed: EncryptedWalletSeed = serde_json::from_str(&migrated_json).unwrap();
		assert!(!migrated_seed.is_legacy());
		assert!(wallet_seed == migrated_seed.decrypt(&password).unwrap());

		// Loading the migrated file must work and leave it in the new format
		let reloaded_seed = WalletSeed::from_file(&data_file_dir, password).unwrap();
		assert!(wallet_seed == reloaded_seed);
		let migrated_json = fs::read_to_string(&seed_file_path).unwrap();
		assert!(migrated_json.contains("argon2id"));
	}
}
