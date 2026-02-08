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

use crate::config::{
	config, GlobalWalletConfig, GlobalWalletConfigMembers, MQSConfig, WalletConfig, MWC_WALLET_DIR,
};
use crate::core::global;
use crate::keychain::{ChildNumber, Keychain};
#[cfg(feature = "swaps")]
use crate::libwallet::swap::ethereum::generate_ethereum_wallet;
use crate::libwallet::{Error, NodeClient, WalletBackend, WalletLCProvider};
use crate::lifecycle::seed::WalletSeed;
use crate::util::secp::key::SecretKey;
use crate::util::ZeroingString;
use crate::LMDBBackend;
use mwc_wallet_libwallet::types::{
	FLAG_CONTEXT_CLEARED, FLAG_NEW_WALLET, FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION,
};
use mwc_wallet_libwallet::{Context, OutputData, TxLogEntryType};
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::logger::LoggingConfig;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

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
		let wallet = match wallet_config {
			Some(w) => w,
			None => default_config.members.wallet.clone(),
		};
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

		// create top level dir if it doesn't exist
		let dd = PathBuf::from(self.data_dir.clone());
		if !dd.exists() {
			// try create
			fs::create_dir_all(dd)?;
		}

		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.as_str());

		let config_file_name_str = config_file_name.to_str().ok_or(Error::GenericError(
			"Can't convert config_file_name into string".into(),
		))?;

		if config_file_name.exists() && data_dir_name.exists() {
			let msg = format!(
				"{} already exists in the target directory ({}). Please remove it first",
				file_name, config_file_name_str
			);
			return Err(Error::Lifecycle(msg));
		}

		// just leave as is if file exists but there's no data dir
		if config_file_name.exists() {
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
		if !api_secret_path.exists() {
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
		test_mode: bool,
		wallet_data_dir: Option<&str>,
		show_seed: bool,
	) -> Result<ZeroingString, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		let exists = WalletSeed::seed_file_exists(&data_dir_name);
		if !test_mode {
			if let Ok(true) = exists {
				let msg = format!("Wallet seed already exists at: {}", data_dir_name);
				return Err(Error::WalletSeedExists(msg));
			}
		}
		let seed = WalletSeed::init_file(
			&data_dir_name,
			mnemonic_length,
			mnemonic.clone(),
			password,
			show_seed,
			test_mode,
		)
		.map_err(|e| {
			Error::Lifecycle(format!(
				"Error creating wallet seed (is mnemonic valid?), {}",
				e
			))
		})?;

		info!("Wallet seed file created");
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
		}
		batch.commit()?;
		info!("Wallet database backend created at {}", data_dir_name);
		let mnemonic = seed
			.to_mnemonic()
			.map_err(|e| Error::Lifecycle(format!("Unbale to generate mnemonic phrase, {}", e)))?;
		Ok(mnemonic.into())
	}

	fn open_wallet(
		&mut self,
		_name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		use_test_rng: bool,
		wallet_data_dir: Option<&str>,
	) -> Result<Option<SecretKey>, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		let data_dir_name = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(self.context_id, &data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error opening wallet: {}, Data Dir: {}", e, &data_dir_name);
					return Err(Error::Lifecycle(msg));
				}
				Ok(d) => d,
			};
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password.clone()).map_err(|e| {
			Error::Lifecycle(format!(
				"Error opening wallet (is password correct?), {}",
				e
			))
		})?;

		#[cfg(feature = "swaps")]
		if let Ok(mnmenoic) = wallet_seed.to_mnemonic() {
			let ethereum_wallet = match global::is_mainnet(self.context_id) {
				true => Some(generate_ethereum_wallet(
					"mainnet",
					mnmenoic.as_str(),
					&password,
					"m/44'/0'/0'/0",
				)?),
				false => Some(generate_ethereum_wallet(
					"ropsten",
					mnmenoic.as_str(),
					&password,
					"m/44'/0'/0'/0",
				)?),
			};
			wallet.set_ethereum_wallet(ethereum_wallet)?;
		}

		let keychain = wallet_seed
			.derive_keychain(global::is_floonet(self.context_id))
			.map_err(|e| Error::Lifecycle(format!("Error deriving keychain, {}", e)))?;

		let mask = wallet.set_keychain(Box::new(keychain), create_mask, use_test_rng)?;

		{
			// Cleaning dangling contexts.
			let mut batch = wallet.batch(mask.as_ref())?;
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
			// Cleaning broken root_key_id from outputs. It is old bug that was fixed on Sept 2024, but the data was never fixed.
			let mut batch = wallet.batch(mask.as_ref())?;
			if !batch.load_flag(FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION, false)? {
				let broken_outputs: Vec<OutputData> = batch
					.iter()?
					.filter(|o| {
						// We need to fix last element of path if it is not 0
						if let Ok(path) = o.root_key_id.to_path() {
							let last_id = u32::from(path.path[3]);
							last_id != 0
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

		self.backend = Some(Box::new(wallet));
		Ok(mask)
	}

	fn close_wallet(&mut self, _name: Option<&str>) -> Result<(), Error> {
		if let Some(b) = self.backend.as_mut() {
			b.close()?
		}
		self.backend = None;
		Ok(())
	}

	fn wallet_exists(
		&self,
		_name: Option<&str>,
		wallet_data_dir: Option<&str>,
	) -> Result<bool, Error> {
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
		Ok(ZeroingString::from(res))
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
		let _ = WalletSeed::init_file(
			data_dir_name,
			0,
			Some(ZeroingString::from(orig_mnemonic)),
			new.clone(),
			false,
			false,
		);
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
		fs::remove_file(backup_name)
			.map_err(|e| Error::IO(format!("Failed to remove old seed file, {}", e)))?;

		Ok(())
	}

	fn delete_wallet(&self, _name: Option<&str>) -> Result<(), Error> {
		let data_dir_name = PathBuf::from(self.data_dir.clone());
		let data_dir_path = data_dir_name.to_str().ok_or(Error::GenericError(
			"Unable convert data_dir_name into string".into(),
		))?;
		warn!("Removing all wallet data from: {}", data_dir_path);
		fs::remove_dir_all(data_dir_name)
			.map_err(|e| Error::IO(format!("Failed to remove wallet data, {}", e)))?;
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
