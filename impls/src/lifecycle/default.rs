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

//! Default wallet lifecycle provider

use crate::LMDBBackend;
use crate::lifecycle::seed::{WalletSeed, show_recovery_phrase};
use mwc_wallet_config::{
	GlobalWalletConfig, GlobalWalletConfigMembers, MQSConfig, MWC_WALLET_DIR, WalletConfig, config,
};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::ethereum::generate_ethereum_wallet;
use mwc_wallet_libwallet::types::{
	FLAG_CONTEXT_CLEARED, FLAG_LEGACY_HEIGHT_IDENTIFIERS_MIGRATED, FLAG_NEW_WALLET,
	FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION, FLAG_PRIVATE_CONTEXTS_SANITIZED,
	FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT,
};
use mwc_wallet_libwallet::{Context, OutputData, TxLogEntryType};
use mwc_wallet_libwallet::{Error, NodeClient, WalletBackend, WalletLCProvider};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::log::{error, info, warn};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::{ChildNumber, Keychain};
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::ZeroingString;
use mwc_wallet_util::mwc_util::file;
use mwc_wallet_util::mwc_util::logger::LoggingConfig;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;

// wallet_data_dir is a directory name (or relative subpath) inside the wallet
// top-level directory. Reject absolute paths and `..` escapes before any path
// is built from it, so the seed and wallet data stay inside the wallet root.
fn check_wallet_data_dir(wallet_data_dir: Option<&str>) -> Result<(), Error> {
	if let Some(dir) = wallet_data_dir {
		config::validate_wallet_data_dir(dir)
			.map_err(|e| Error::Lifecycle(format!("Invalid wallet data directory, {}", e)))?;
	}
	Ok(())
}

pub struct DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	context_id: u32,
	data_dir: String,
	node_client: C,
	backend: Option<Box<dyn WalletBackend<'a, C, K> + 'a>>,
}

impl<'a, C, K> DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create new provider
	pub fn new(context_id: u32, node_client: C) -> Self {
		DefaultLCProvider {
			context_id,
			node_client,
			data_dir: "default".to_owned(),
			backend: None,
		}
	}
}

impl<'a, C, K> WalletLCProvider<'a, C, K> for DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn set_top_level_directory(&mut self, dir: &str) -> Result<(), Error> {
		self.data_dir = dir.to_owned();
		Ok(())
	}

	fn get_top_level_directory(&self) -> Result<String, Error> {
		Ok(self.data_dir.to_owned())
	}

	fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		file_name: &str,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		mqs_config: Option<MQSConfig>,
	) -> Result<(), Error> {
		let mut default_config = GlobalWalletConfig::for_chain(&chain_type);
		let config_file_version = default_config.members.config_file_version.clone();
		let logging = match logging_config {
			Some(l) => Some(l),
			None => default_config.members.logging.clone(),
		};
		let mut wallet = match wallet_config {
			Some(w) => w,
			None => default_config.members.wallet.clone(),
		};
		if let Some(configured_chain_type) = wallet.chain_type.as_ref() {
			if configured_chain_type != chain_type {
				return Err(Error::Lifecycle(format!(
					"Wallet configuration chain type {:?} does not match requested chain type {:?}",
					configured_chain_type, chain_type
				)));
			}
		}
		// `chain_type` is the authoritative network selection for this API. A
		// custom wallet configuration may omit it, but must not override it.
		wallet.chain_type = Some(chain_type.clone());
		let tor = match tor_config {
			Some(t) => Some(t),
			None => default_config.members.tor.clone(),
		};
		let mqs = match mqs_config {
			Some(q) => Some(q),
			None => default_config.members.mqs.clone(),
		};

		let wallet_data_dir = wallet
			.wallet_data_dir
			.clone()
			.unwrap_or(String::from(MWC_WALLET_DIR));
		check_wallet_data_dir(Some(wallet_data_dir.as_str()))?;

		default_config = GlobalWalletConfig {
			members: GlobalWalletConfigMembers {
				config_file_version,
				wallet,
				tor,
				mqs,
				logging,
			},
			..default_config
		};
		let mut config_file_name = PathBuf::from(self.data_dir.clone());
		config_file_name.push(file_name);

		// The root contains wallet configuration and API-secret files. Create it
		// owner-only and validate an existing directory before writing into it.
		let dd = PathBuf::from(self.data_dir.clone());
		file::ensure_owner_only_dir_all(&dd)?;

		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.as_str());

		let config_file_name_str = config_file_name.to_str().ok_or(Error::GenericError(
			"Can't convert config_file_name into string".into(),
		))?;

		if config_file_name.try_exists()? && data_dir_name.try_exists()? {
			let msg = format!(
				"{} already exists in the target directory ({}). Please remove it first",
				file_name, config_file_name_str
			);
			return Err(Error::Lifecycle(msg));
		}

		// just leave as is if file exists but there's no data dir
		if config_file_name.try_exists()? {
			return Ok(());
		}

		let mut abs_path = std::env::current_dir()?;
		abs_path.push(self.data_dir.clone());

		default_config
			.update_paths(&abs_path, Some(wallet_data_dir.as_str()))
			.map_err(|e| {
				Error::GenericError(format!("Unable update wallet data directory, {}", e))
			})?;
		let res = default_config.write_to_file(config_file_name_str, false, "".into(), None);
		if let Err(e) = res {
			let msg = format!(
				"Error creating config file as ({}): {}",
				config_file_name_str, e
			);
			return Err(Error::Lifecycle(msg));
		}

		info!("File {} configured and created", config_file_name_str);

		let mut api_secret_path = PathBuf::from(self.data_dir.clone());
		api_secret_path.push(PathBuf::from(config::NODE_API_SECRET_FILE_NAME));
		if !api_secret_path.try_exists()? {
			config::init_api_secret(&api_secret_path)
				.map_err(|e| Error::GenericError(format!("Unable to init api secret, {}", e)))?;
		} else {
			config::check_api_secret(&api_secret_path)
				.map_err(|e| Error::GenericError(format!("Unable to read api secret, {}", e)))?;
		}

		Ok(())
	}

	// return mnemonic phrase
	fn create_wallet(
		&mut self,
		_name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: usize,
		password: ZeroingString,
		#[cfg(feature = "test-support")] test_mode: bool,
		wallet_data_dir: Option<&str>,
		show_seed: bool,
	) -> Result<ZeroingString, Error> {
		check_wallet_data_dir(wallet_data_dir)?;
		if mnemonic.is_none() {
			WalletSeed::validate_mnemonic_length(mnemonic_length)
				.map_err(|e| Error::Lifecycle(format!("Invalid mnemonic length, {}", e)))?;
		}

		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		let exists = WalletSeed::seed_file_exists(&data_dir_name)
			.map_err(|e| Error::Lifecycle(format!("Error checking for wallet existence, {}", e)))?;
		#[cfg(feature = "test-support")]
		let reject_existing_wallet = !test_mode;
		#[cfg(not(feature = "test-support"))]
		let reject_existing_wallet = true;
		if reject_existing_wallet && exists {
			let msg = format!("Wallet seed already exists at: {}", data_dir_name);
			return Err(Error::WalletSeedExists(msg));
		}
		let seed = WalletSeed::from_init_args(mnemonic_length, mnemonic.clone()).map_err(|e| {
			Error::Lifecycle(format!(
				"Error preparing wallet seed (is mnemonic valid?), {}",
				e
			))
		})?;
		let recovery_phrase = seed
			.to_mnemonic()
			.map_err(|e| Error::Lifecycle(format!("Unable to generate mnemonic phrase, {}", e)))?;
		file::ensure_owner_only_dir_all(data_dir_name).map_err(|e| {
			Error::Lifecycle(format!(
				"Unable to prepare wallet data directory {}, {}",
				data_dir_name, e
			))
		})?;
		// Keep the seed only in zeroizing memory until every fallible backend
		// initialization step is committed. The seed file is the final durable
		// marker that makes this directory an existing wallet.
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(self.context_id, &data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error creating wallet: {}, Data Dir: {}", e, &data_dir_name);
					error!("{}", msg);
					return Err(Error::Lifecycle(msg));
				}
				Ok(d) => d,
			};
		// Save init status of this wallet, to determine whether it needs a full UTXO scan
		let mut batch = wallet.batch_no_mask()?;
		if mnemonic.is_none() {
			batch.save_flag(FLAG_NEW_WALLET)?;
		} else {
			// A failed creation can leave this flag without a seed file. Restoring
			// a mnemonic must clear it so synchronization scans the full history.
			batch.load_flag(FLAG_NEW_WALLET, true)?;
		}
		batch.commit()?;
		info!("Wallet database backend created at {}", data_dir_name);

		seed.persist_file(
			data_dir_name,
			password,
			#[cfg(feature = "test-support")]
			test_mode,
		)
		.map_err(|e| Error::Lifecycle(format!("Error creating wallet seed file, {}", e)))?;
		info!("Wallet seed file created");
		if show_seed {
			show_recovery_phrase(recovery_phrase.clone());
		}
		Ok(recovery_phrase)
	}

	fn open_wallet(
		&mut self,
		secp: &Secp256k1,
		_name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		wallet_data_dir: Option<&str>,
	) -> Result<Option<SecretKey>, Error> {
		check_wallet_data_dir(wallet_data_dir)?;
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		// Validate the seed and secure its directory before the backend can create
		// directories using the process umask. A failed open must not leave a
		// group-writable wallet directory that prevents subsequent creation.
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password).map_err(|e| {
			Error::Lifecycle(format!(
				"Error opening wallet (is password correct?), {}",
				e
			))
		})?;
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(self.context_id, &data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error opening wallet: {}, Data Dir: {}", e, &data_dir_name);
					return Err(Error::Lifecycle(msg));
				}
				Ok(d) => d,
			};

		#[cfg(feature = "swaps")]
		let ethereum_wallet = {
			let mnemonic = wallet_seed.to_mnemonic().map_err(|e| {
				Error::Lifecycle(format!(
					"Unable to derive Ethereum mnemonic from wallet seed, {}",
					e
				))
			})?;
			let mut ethereum_wallet = match global::is_mainnet(self.context_id) {
				true => Some(generate_ethereum_wallet(
					"mainnet",
					&mnemonic,
					"m/44'/0'/0'/0",
				)?),
				false => Some(generate_ethereum_wallet(
					"ropsten",
					&mnemonic,
					"m/44'/0'/0'/0",
				)?),
			};
			// Runtime Ethereum operations use only the derived private key. Do not
			// retain the source recovery phrase or extended private key as additional
			// copies of wallet-wide secret material.
			if let Some(wallet) = ethereum_wallet.as_mut() {
				wallet.discard_recovery_material();
			}
			ethereum_wallet
		};

		let keychain = wallet_seed
			.derive_keychain(secp, global::is_floonet(self.context_id))
			.map_err(|e| Error::Lifecycle(format!("Error deriving keychain, {}", e)))?;

		let mask = wallet.set_keychain(
			secp,
			Box::new(keychain),
			create_mask,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;

		#[cfg(feature = "swaps")]
		wallet.set_ethereum_wallet(secp, ethereum_wallet, mask.as_ref())?;

		{
			// b'P' private contexts used one mask per slate/field but did not bind
			// participant_id, allowing a self-send's two records to reuse the same
			// XOR pads. Re-encrypt every b'P' record in place. The records and
			// completion marker share one LMDB commit, so an interrupted migration
			// is retried from the unchanged old state.
			let mut batch = wallet.batch(secp, mask.as_ref())?;
			if !batch.load_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT, false)? {
				batch.migrate_private_context_xor_keys(secp)?;
				batch.save_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT)?;
			}
			batch.commit()?;
		}

		{
			// One-time, best-effort cleanup of historical durable contexts. Current
			// interactive flows, including self-send, keep signing contexts in a
			// `TxSession`, clear them during finalization before posting, and persist
			// only the completed transaction state after a successful post. Those
			// contexts never reach this iterator.
			//
			// Records encountered here come from workflows that must survive a
			// process boundary (for example file, Slatepack, or invoice exchange), or
			// from legacy/sessionless API use. Separate participant records can share
			// one slate UUID. Collapsing them by UUID below is intentional for this
			// limited storage-hygiene pass: after live unconfirmed sends are excluded,
			// deleting at most one expired record per UUID is sufficient, and an
			// additional expired participant record may remain. This cleanup is not a
			// transaction-correctness or secret-protection boundary; private context
			// scalar fields are XOR-masked when stored.
			let mut batch = wallet.batch(secp, mask.as_ref())?;
			if !batch.load_flag(FLAG_CONTEXT_CLEARED, false)? {
				let mut contexts: HashMap<Uuid, Context> = HashMap::new();
				for (uuid, context) in batch.private_context_iter()? {
					let uuid = Uuid::from_slice(&uuid).map_err(|e| {
						Error::GenericError(format!("Unable to read private context uuid, {}", e))
					})?;
					contexts.insert(uuid, context);
				}

				for tx in batch.tx_log_iter()? {
					if tx.tx_type == TxLogEntryType::TxSent && !tx.confirmed {
						// It is transactions for what we left the data from
						if let Some(slate_id) = &tx.tx_slate_id {
							contexts.remove(slate_id);
						}
					}
				}

				for (uuid, context) in contexts {
					batch.delete_private_context(uuid.as_bytes(), context.participant_id)?;
				}

				batch.save_flag(FLAG_CONTEXT_CLEARED)?;
			}
			batch.commit()?;
		}

		{
			// Older wallets persisted the proof-message height in an unused
			// identifier component. Canonicalize those records before any code
			// attempts strict BIP32 path parsing.
			let mut batch = wallet.batch(secp, mask.as_ref())?;
			if !batch.load_flag(FLAG_LEGACY_HEIGHT_IDENTIFIERS_MIGRATED, false)? {
				batch.migrate_legacy_height_identifiers()?;
				batch.save_flag(FLAG_LEGACY_HEIGHT_IDENTIFIERS_MIGRATED)?;
			}
			batch.commit()?;
		}

		{
			// Older late-lock contexts embedded the complete InitTxArgs, including
			// receiver transport credentials. Deserialize them through the current
			// narrow schema and rewrite the live records once.
			let mut batch = wallet.batch(secp, mask.as_ref())?;
			if !batch.load_flag(FLAG_PRIVATE_CONTEXTS_SANITIZED, false)? {
				batch.sanitize_private_contexts()?;
				batch.save_flag(FLAG_PRIVATE_CONTEXTS_SANITIZED)?;
			}
			batch.commit()?;
		}

		{
			// Cleaning broken root_key_id from outputs. It is old bug that was fixed on Sept 2024, but the data was never fixed.
			let mut batch = wallet.batch(secp, mask.as_ref())?;
			if !batch.load_flag(FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION, false)? {
				let broken_outputs: Vec<OutputData> = batch
					.iter()?
					.filter(|o| {
						// We need to fix last element of path if it is not 0
						if let Ok(path) = o.root_key_id.to_path() {
							u32::try_from(path.path[3])
								.map(|last_id| last_id != 0)
								.unwrap_or(true)
						} else {
							false
						}
					})
					.collect();

				for mut out in broken_outputs {
					let mut path = out.root_key_id.to_path()?;
					path.path[3] = ChildNumber::from(0);
					out.root_key_id = path.to_identifier()?;
					batch.save(out)?;
				}
				batch.save_flag(FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION)?;
			}
			batch.commit()?;
		}

		// `context_id` belongs to one wallet session. Supported workflows release
		// that context before selecting another wallet; this assignment may refresh
		// the backend for the same session, but must never be used as an in-place
		// wallet switch. Context release joins all context-owned listeners before this
		// provider and its context-id-keyed swap storage can disappear. Direct calls
		// must be serialized against context release by their caller.
		self.backend = Some(Box::new(wallet));
		Ok(mask)
	}

	fn close_wallet(&mut self, _name: Option<&str>) -> Result<(), Error> {
		if let Some(b) = self.backend.as_mut() {
			b.close()?
		}
		self.backend = None;
		mwc_wallet_libwallet::proof::tx_proof::clear_proofs_for_context(self.context_id);
		Ok(())
	}

	fn wallet_exists(
		&self,
		_name: Option<&str>,
		wallet_data_dir: Option<&str>,
	) -> Result<bool, Error> {
		check_wallet_data_dir(wallet_data_dir)?;
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		let res = WalletSeed::seed_file_exists(&data_dir_name).map_err(|e| {
			Error::CallbackImpl(format!("Error checking for wallet existence, {}", e))
		})?;
		Ok(res)
	}

	fn get_mnemonic(
		&self,
		_name: Option<&str>,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<ZeroingString, Error> {
		check_wallet_data_dir(wallet_data_dir)?;
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password)
			.map_err(|e| Error::Lifecycle(format!("Error opening wallet seed file, {}", e)))?;
		let res = wallet_seed
			.to_mnemonic()
			.map_err(|e| Error::Lifecycle(format!("Error recovering wallet seed, {}", e)))?;
		Ok(res)
	}

	fn validate_mnemonic(&self, mnemonic: ZeroingString) -> Result<(), Error> {
		match WalletSeed::from_mnemonic(mnemonic) {
			Ok(_) => Ok(()),
			Err(e) => Err(Error::GenericError(format!("Validating mnemonic, {}", e)))?,
		}
	}

	fn recover_from_mnemonic(
		&self,
		mnemonic: ZeroingString,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error> {
		if self.backend.is_some() {
			return Err(Error::Lifecycle(
				"Cannot recover wallet seed while the wallet is open; close it first".to_owned(),
			));
		}
		check_wallet_data_dir(wallet_data_dir)?;
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		WalletSeed::recover_from_phrase(data_dir_name, mnemonic, password)
			.map_err(|e| Error::Lifecycle(format!("Error recovering from mnemonic, {}", e)))?;
		Ok(())
	}

	fn change_password(
		&self,
		_name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error> {
		check_wallet_data_dir(wallet_data_dir)?;
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		// get seed for later check

		let orig_wallet_seed = WalletSeed::from_file(&data_dir_name, old).map_err(|e| {
			Error::Lifecycle(format!(
				"Error opening wallet seed file {}, {}",
				data_dir_name, e
			))
		})?;
		let orig_mnemonic = orig_wallet_seed
			.to_mnemonic()
			.map_err(|e| Error::Lifecycle(format!("Error recovering mnemonic, {}", e)))?;

		// Back up existing seed, and keep track of filename as we're deleting it
		// once the password change is confirmed
		let backup_name = WalletSeed::backup_seed(data_dir_name).map_err(|e| {
			Error::Lifecycle(format!("Error temporarily backing up existing seed, {}", e))
		})?;

		// Delete seed file
		WalletSeed::delete_seed_file(data_dir_name).map_err(|e| {
			Error::Lifecycle(format!(
				"Unable to delete seed file {} for password change, {}",
				data_dir_name, e
			))
		})?;

		// Init a new file
		WalletSeed::init_file(
			data_dir_name,
			0,
			Some(orig_mnemonic),
			new.clone(),
			false,
			#[cfg(feature = "test-support")]
			false,
		)
		.map_err(|e| {
			Error::Lifecycle(format!(
				"Unable to create the replacement seed file {} during password change, {}",
				data_dir_name, e
			))
		})?;
		info!("Wallet seed file created");

		let new_wallet_seed = WalletSeed::from_file(&data_dir_name, new).map_err(|e| {
			Error::Lifecycle(format!(
				"Error opening wallet seed file {}, {}",
				data_dir_name, e
			))
		})?;

		if orig_wallet_seed != new_wallet_seed {
			let msg =
				"New and Old wallet seeds are not equal on password change, not removing backups."
					.to_string();
			return Err(Error::Lifecycle(msg));
		}
		// Removing
		info!("Password change confirmed, removing old seed file.");
		mwc_wallet_util::file::remove_file_and_sync_parent(backup_name)
			.map_err(|e| Error::IO(format!("Failed to durably remove old seed file, {}", e)))?;

		Ok(())
	}

	fn delete_wallet(&self, _name: Option<&str>) -> Result<(), Error> {
		if self.backend.is_some() {
			return Err(Error::Lifecycle(
				"Cannot delete wallet while the wallet is open; close it first".to_owned(),
			));
		}

		// A wrong top-level directory could cause unrelated data to be removed, but
		// this lifecycle provider must honor the directory selected by its caller.
		// The caller is responsible for validating that `data_dir` is the intended
		// wallet root before requesting deletion.
		// Normalize trailing separators and `.` so they cannot hide a terminal
		// directory symlink from symlink_metadata.
		let data_dir_name: PathBuf = PathBuf::from(&self.data_dir).components().collect();
		let metadata = fs::symlink_metadata(&data_dir_name).map_err(|e| {
			Error::IO(format!(
				"Failed to inspect wallet data path {}: {}",
				data_dir_name.display(),
				e
			))
		})?;
		if metadata.file_type().is_symlink() {
			return Err(Error::Lifecycle(format!(
				"Refusing to delete wallet data because configured wallet directory {} is a symbolic link",
				data_dir_name.display()
			)));
		}

		warn!("Removing all wallet data from: {}", data_dir_name.display());
		mwc_wallet_util::file::remove_dir_all_and_sync_parent(data_dir_name)
			.map_err(|e| Error::IO(format!("Failed to durably remove wallet data, {}", e)))?;
		Ok(())
	}

	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error> {
		match self.backend.as_mut() {
			None => Err(Error::Lifecycle("Wallet has not been opened".to_string())),
			Some(w) => Ok(w),
		}
	}

	fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

#[cfg(all(test, feature = "test-support"))]
mod test {
	use super::*;
	use crate::test_framework::LocalWalletClient;
	use mwc_wallet_util::mwc_keychain::ExtKeychain;
	use std::sync::mpsc::channel;

	fn test_provider() -> DefaultLCProvider<'static, LocalWalletClient, ExtKeychain> {
		// The receiver is dropped right away; validation must reject the
		// directory before the node client is ever used.
		let (tx, _rx) = channel();
		DefaultLCProvider::new(0, LocalWalletClient::new("test", tx))
	}

	#[test]
	fn create_config_sets_missing_custom_chain_type() {
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_root = temp_dir.path().join("wallet");
		lc.set_top_level_directory(wallet_root.to_str().unwrap())
			.unwrap();

		let chain_type = global::ChainTypes::Floonet;
		let mut wallet_config = GlobalWalletConfig::for_chain(&chain_type).members.wallet;
		wallet_config.chain_type = None;
		lc.create_config(
			&chain_type,
			"mwc-wallet.toml",
			Some(wallet_config),
			None,
			None,
			None,
		)
		.unwrap();

		let config_path = wallet_root.join("mwc-wallet.toml");
		let config = GlobalWalletConfig::new(config_path.to_str().unwrap()).unwrap();
		assert_eq!(config.members.wallet.chain_type, Some(chain_type));
	}

	#[test]
	fn create_config_rejects_conflicting_custom_chain_type_before_writing() {
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_root = temp_dir.path().join("wallet");
		lc.set_top_level_directory(wallet_root.to_str().unwrap())
			.unwrap();

		let wallet_config = GlobalWalletConfig::for_chain(&global::ChainTypes::Mainnet)
			.members
			.wallet;
		let result = lc.create_config(
			&global::ChainTypes::Floonet,
			"mwc-wallet.toml",
			Some(wallet_config),
			None,
			None,
			None,
		);

		assert!(result.is_err());
		assert!(!wallet_root.exists());
	}

	#[cfg(unix)]
	#[test]
	fn create_config_tightens_wallet_root_permissions() {
		use std::os::unix::fs::PermissionsExt;

		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let wallet_root = temp_dir.path().join("wallet");
		fs::create_dir(&wallet_root).unwrap();
		fs::set_permissions(&wallet_root, fs::Permissions::from_mode(0o755)).unwrap();
		lc.set_top_level_directory(wallet_root.to_str().unwrap())
			.unwrap();

		lc.create_config(
			&global::ChainTypes::Mainnet,
			"mwc-wallet.toml",
			None,
			None,
			None,
			None,
		)
		.unwrap();

		let mode = fs::metadata(&wallet_root).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o700);
	}

	#[test]
	fn create_wallet_rejects_wallet_data_dir_escaping_wallet_root() {
		let mut lc = test_provider();
		let pid = std::process::id();
		let base = std::env::temp_dir().join(format!("mwc_wallet_lc_test_{}", pid));
		let _ = fs::remove_dir_all(&base);
		fs::create_dir_all(&base).unwrap();
		lc.set_top_level_directory(base.to_str().unwrap()).unwrap();

		let escaped = format!("../mwc_lc_escape_{}", pid);
		for bad in [
			escaped.as_str(),
			"/tmp/mwc_lc_escape",
			"a/../../mwc_lc_escape",
			"",
		] {
			let res = lc.create_wallet(
				None,
				None,
				16,
				ZeroingString::from("password"),
				#[cfg(feature = "test-support")]
				false,
				Some(bad),
				false,
			);
			assert!(res.is_err(), "wallet_data_dir {:?} must be rejected", bad);
		}

		// Rejection must happen before anything is written, inside or outside
		// the wallet top-level directory.
		assert!(fs::read_dir(&base).unwrap().next().is_none());
		assert!(
			!base
				.parent()
				.unwrap()
				.join(format!("mwc_lc_escape_{}", pid))
				.exists()
		);
		fs::remove_dir_all(&base).unwrap();
	}

	#[test]
	fn create_wallet_rejects_invalid_mnemonic_length_before_writing() {
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();

		let result = lc.create_wallet(
			None,
			None,
			17,
			ZeroingString::from("password"),
			#[cfg(feature = "test-support")]
			false,
			None,
			false,
		);

		assert!(result.is_err());
		assert!(!temp_dir.path().join(MWC_WALLET_DIR).exists());
	}

	#[test]
	fn create_wallet_backend_failure_does_not_leave_seed_file() {
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();

		let wallet_dir = temp_dir.path().join(MWC_WALLET_DIR);
		file::ensure_owner_only_dir_all(&wallet_dir).unwrap();
		fs::write(wallet_dir.join("db"), b"blocks LMDB directory creation").unwrap();

		let result = lc.create_wallet(
			None,
			None,
			16,
			ZeroingString::from("password"),
			#[cfg(feature = "test-support")]
			false,
			None,
			false,
		);

		assert!(result.is_err());
		assert!(!WalletSeed::seed_file_exists(wallet_dir.to_str().unwrap()).unwrap());
	}

	#[test]
	fn create_wallet_persists_the_returned_seed_after_backend_initialization() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();
		let password = ZeroingString::from("password");

		let recovery_phrase = lc
			.create_wallet(
				None,
				None,
				16,
				password.clone(),
				#[cfg(feature = "test-support")]
				false,
				None,
				false,
			)
			.unwrap();

		let wallet_dir = temp_dir.path().join(MWC_WALLET_DIR);
		let persisted_seed = WalletSeed::from_file(wallet_dir.to_str().unwrap(), password).unwrap();
		let returned_seed = WalletSeed::from_mnemonic(recovery_phrase).unwrap();
		assert!(persisted_seed == returned_seed);

		let mut wallet: LMDBBackend<'_, LocalWalletClient, ExtKeychain> =
			LMDBBackend::new(0, wallet_dir.to_str().unwrap(), lc.node_client.clone()).unwrap();
		let mut batch = wallet.batch_no_mask().unwrap();
		assert!(batch.load_flag(FLAG_NEW_WALLET, false).unwrap());
		batch.commit().unwrap();
	}

	#[test]
	fn create_wallet_restoration_clears_new_wallet_flag_from_incomplete_creation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

		for incomplete_creation in [false, true] {
			let mut lc = test_provider();
			let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
			lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
				.unwrap();
			let wallet_dir = temp_dir.path().join(MWC_WALLET_DIR);
			let data_dir = wallet_dir.to_str().unwrap();
			let password = ZeroingString::from("password");

			if incomplete_creation {
				// Reproduce the durable state left when new-wallet initialization
				// commits but seed persistence fails or the process is interrupted.
				file::ensure_owner_only_dir_all(&wallet_dir).unwrap();
				let mut wallet: LMDBBackend<'_, LocalWalletClient, ExtKeychain> =
					LMDBBackend::new(0, data_dir, lc.node_client.clone()).unwrap();
				let mut batch = wallet.batch_no_mask().unwrap();
				batch.save_flag(FLAG_NEW_WALLET).unwrap();
				batch.commit().unwrap();
			}
			assert!(!WalletSeed::seed_file_exists(data_dir).unwrap());

			let recovery_phrase = lc
				.create_wallet(
					None,
					Some(ZeroingString::from(phrase)),
					16,
					password.clone(),
					#[cfg(feature = "test-support")]
					false,
					None,
					false,
				)
				.unwrap();
			assert_eq!(&*recovery_phrase, phrase);
			let persisted_seed = WalletSeed::from_file(data_dir, password).unwrap();
			let recovered_seed = WalletSeed::from_mnemonic(recovery_phrase).unwrap();
			assert!(persisted_seed == recovered_seed);

			let mut wallet: LMDBBackend<'_, LocalWalletClient, ExtKeychain> =
				LMDBBackend::new(0, data_dir, lc.node_client.clone()).unwrap();
			let mut batch = wallet.batch_no_mask().unwrap();
			assert!(
				!batch.load_flag(FLAG_NEW_WALLET, false).unwrap(),
				"Restored wallets must request a full scan, incomplete_creation={}",
				incomplete_creation
			);
			batch.commit().unwrap();
		}
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn masked_open_requires_mask_for_sanitized_ethereum_wallet() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();
		let password = ZeroingString::from("password");
		lc.create_wallet(
			None,
			None,
			16,
			password.clone(),
			#[cfg(feature = "test-support")]
			false,
			None,
			false,
		)
		.unwrap();

		let secp =
			Secp256k1::with_caps(mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit).unwrap();
		let mask = lc
			.open_wallet(
				&secp,
				None,
				password,
				true,
				#[cfg(feature = "test-support")]
				false,
				None,
			)
			.unwrap()
			.expect("masked open must return its session mask");
		let wrong_mask = SecretKey::from_slice(&secp, &[3u8; 32]).unwrap();

		let wallet = lc.wallet_inst().unwrap();
		assert!(matches!(
			wallet.get_ethereum_wallet(None),
			Err(Error::InvalidKeychainMask)
		));
		assert!(matches!(
			wallet.get_ethereum_wallet(Some(&wrong_mask)),
			Err(Error::InvalidKeychainMask)
		));
		let ethereum_wallet = wallet.get_ethereum_wallet(Some(&mask)).unwrap();
		assert!(ethereum_wallet.password.is_none());
		assert!(ethereum_wallet.mnemonic.is_none());
		assert!(ethereum_wallet.extended_private_key.is_none());
		assert!(ethereum_wallet.private_key.is_some());

		lc.close_wallet(None).unwrap();
	}

	#[cfg(unix)]
	#[test]
	fn delete_wallet_rejects_symlinked_wallet_root() {
		use std::os::unix::fs::symlink;

		for suffix in ["", "/", "/.", "/./"] {
			let mut lc = test_provider();
			let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
			let wallet_root = temp_dir.path().join("wallet-root");
			let wallet_link = temp_dir.path().join("wallet-link");
			fs::create_dir(&wallet_root).unwrap();
			fs::write(wallet_root.join("wallet.seed"), b"encrypted seed").unwrap();
			symlink(&wallet_root, &wallet_link).unwrap();

			let configured_path = format!("{}{}", wallet_link.display(), suffix);
			lc.set_top_level_directory(&configured_path).unwrap();
			let result = lc.delete_wallet(None);

			assert!(matches!(
				result,
				Err(Error::Lifecycle(message)) if message.contains("symbolic link")
			));
			assert_eq!(
				fs::read(wallet_root.join("wallet.seed")).unwrap(),
				b"encrypted seed"
			);
			assert!(fs::symlink_metadata(&wallet_link).unwrap().is_symlink());
		}
	}

	#[test]
	fn delete_wallet_rejects_open_wallet() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();
		let password = ZeroingString::from("password");
		lc.create_wallet(
			None,
			None,
			16,
			password.clone(),
			#[cfg(feature = "test-support")]
			false,
			None,
			false,
		)
		.unwrap();
		let secp =
			Secp256k1::with_caps(mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit).unwrap();
		lc.open_wallet(
			&secp,
			None,
			password,
			false,
			#[cfg(feature = "test-support")]
			false,
			None,
		)
		.unwrap();

		let result = lc.delete_wallet(None);

		assert!(matches!(
			result,
			Err(Error::Lifecycle(message)) if message.contains("close it first")
		));
		assert!(temp_dir.path().join(MWC_WALLET_DIR).exists());

		lc.close_wallet(None).unwrap();
		lc.delete_wallet(None).unwrap();
		assert!(!temp_dir.path().exists());
	}

	#[test]
	fn recover_from_mnemonic_rejects_open_wallet_without_changing_seed_file() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut lc = test_provider();
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		lc.set_top_level_directory(temp_dir.path().to_str().unwrap())
			.unwrap();
		let password = ZeroingString::from("password");
		let recovery_phrase = lc
			.create_wallet(
				None,
				None,
				16,
				password.clone(),
				#[cfg(feature = "test-support")]
				false,
				None,
				false,
			)
			.unwrap();
		let wallet_dir = temp_dir.path().join(MWC_WALLET_DIR);
		let seed_file = wallet_dir.join(crate::lifecycle::seed::SEED_FILE);
		let original_seed_file = fs::read(&seed_file).unwrap();

		let secp =
			Secp256k1::with_caps(mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit).unwrap();
		lc.open_wallet(
			&secp,
			None,
			password.clone(),
			false,
			#[cfg(feature = "test-support")]
			false,
			None,
		)
		.unwrap();

		let result =
			lc.recover_from_mnemonic(recovery_phrase.clone(), password.clone(), None);
		assert!(matches!(
			result,
			Err(Error::Lifecycle(message)) if message.contains("close it first")
		));
		assert_eq!(fs::read(&seed_file).unwrap(), original_seed_file);
		assert!(!wallet_dir
			.join(format!("{}.bak", crate::lifecycle::seed::SEED_FILE))
			.exists());

		lc.close_wallet(None).unwrap();
		lc.recover_from_mnemonic(recovery_phrase, password, None)
			.unwrap();
		assert!(wallet_dir
			.join(format!("{}.bak", crate::lifecycle::seed::SEED_FILE))
			.exists());
	}

	#[test]
	fn wallet_exists_rejects_wallet_data_dir_escaping_wallet_root() {
		let lc = test_provider();
		assert!(lc.wallet_exists(None, Some("../escape")).is_err());
		assert!(lc.wallet_exists(None, Some("/tmp/escape")).is_err());
		assert!(!lc.wallet_exists(None, Some("wallet_data")).unwrap());
		assert!(!lc.wallet_exists(None, None).unwrap());
	}
}
