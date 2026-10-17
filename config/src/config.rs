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

//! Configuration file management

use crate::comments::{insert_comments, migrate_comments};
use crate::types::{ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers};
use crate::types::{MQSConfig, WalletConfig};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::dirs;
use mwc_wallet_util::mwc_crates::log::{error, info};
use mwc_wallet_util::mwc_crates::rand::{rngs::SysRng, TryRng};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize};
use mwc_wallet_util::mwc_crates::toml;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::file::{self, OwnerOnlyFile};
use mwc_wallet_util::mwc_util::logger::LoggingConfig;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::{Component, Path, PathBuf};

/// Wallet configuration file name
pub const WALLET_CONFIG_FILE_NAME: &str = "mwc-wallet.toml";
const WALLET_LOG_FILE_NAME: &str = "mwc-wallet.log";
const MWC_HOME: &str = ".mwc";
/// Wallet data directory
pub const MWC_WALLET_DIR: &str = "wallet_data";
/// Node API secret
pub const NODE_API_SECRET_FILE_NAME: &str = ".foreign_api_secret";
/// Owner API secret
pub const OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";
const API_SECRET_LEN: usize = 20;
const API_SECRET_MIN_LEN: usize = API_SECRET_LEN - 5;
const API_SECRET_MAX_FILE_SIZE: u64 = 4096;
const API_SECRET_ALPHABET: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const CURRENT_CONFIG_FILE_VERSION: u32 = 2;

#[derive(Deserialize)]
#[serde(crate = "serde")]
struct ConfigVersionHeader {
	#[serde(default)]
	config_file_version: Option<u32>,
}

/// `wallet_data_dir` is a directory name (or relative subpath) located inside
/// the wallet root. It must never be an absolute path (which `PathBuf::push`
/// would silently substitute for the wallet root) or contain parent-directory
/// components that escape the wallet root when the path is resolved. Reject
/// such values before any path is built from them, so wallet seed and
/// database storage always stay inside the owner-only wallet root.
pub fn validate_wallet_data_dir(wallet_data_dir: &str) -> Result<(), ConfigError> {
	let escapes_root = wallet_data_dir.is_empty()
		|| Path::new(wallet_data_dir).components().any(|c| {
			matches!(
				c,
				Component::Prefix(_) | Component::RootDir | Component::ParentDir
			)
		});
	if escapes_root {
		return Err(ConfigError::InvalidConfig(format!(
			"wallet_data_dir must be a relative path inside the wallet directory: {:?}",
			wallet_data_dir
		)));
	}
	Ok(())
}

fn get_mwc_path(
	chain_type: &global::ChainTypes,
	create_path: bool,
) -> Result<PathBuf, ConfigError> {
	// Check if mwc dir exists
	let mut mwc_path = dirs::home_dir()
		.ok_or_else(|| ConfigError::InvalidConfig("Unable to determine home directory".into()))?;
	// A relative HOME would place wallet config and data relative to the
	// process current directory, so it is rejected.
	if !mwc_path.is_absolute() {
		return Err(ConfigError::InvalidConfig(format!(
			"Home directory path is not absolute: {}",
			mwc_path.display()
		)));
	}
	mwc_path.push(MWC_HOME);
	if !create_path && !mwc_path.try_exists()? {
		return Err(ConfigError::PathNotFoundError(String::from(
			mwc_path.to_str().unwrap_or("<INVALID PATH>".into()),
		)));
	}
	// Create (when requested) and validate each level separately: both the
	// .mwc parent and the chain directory must be owner-only directories.
	ensure_secure_mwc_dir(&mwc_path)?;
	mwc_path.push(chain_type.shortname());
	if !create_path && !mwc_path.try_exists()? {
		return Err(ConfigError::PathNotFoundError(String::from(
			mwc_path.to_str().unwrap_or("<INVALID PATH>".into()),
		)));
	}
	ensure_secure_mwc_dir(&mwc_path)?;
	Ok(mwc_path)
}

fn map_dir_error(e: std::io::Error) -> ConfigError {
	if e.kind() == std::io::ErrorKind::InvalidInput
		|| e.kind() == std::io::ErrorKind::PermissionDenied
	{
		ConfigError::InvalidConfig(e.to_string())
	} else {
		ConfigError::FileIOError(e)
	}
}

fn ensure_secure_mwc_dir(path: &Path) -> Result<(), ConfigError> {
	file::ensure_owner_only_dir(path).map_err(map_dir_error)
}

fn prepare_wallet_root(path: &Path, create_path: bool) -> Result<(), ConfigError> {
	if create_path {
		return file::ensure_owner_only_dir_all(path).map_err(map_dir_error);
	}

	file::ensure_existing_owner_only_dir(path).map_err(|e| {
		if e.kind() == std::io::ErrorKind::NotFound {
			ConfigError::PathNotFoundError(path.to_string_lossy().into_owned())
		} else {
			map_dir_error(e)
		}
	})
}

fn check_config_current_dir(path: &str) -> Result<Option<PathBuf>, ConfigError> {
	let mut c = env::current_dir()?;
	c.push(path);
	Ok(c.try_exists()?.then_some(c))
}

fn generate_api_secret() -> Result<Zeroizing<String>, ConfigError> {
	// as u32 is safe because API_SECRET_ALPHABET is a short constant string
	let alphabet_len = API_SECRET_ALPHABET.len() as u32;
	let mut api_secret = String::with_capacity(API_SECRET_LEN);
	while api_secret.len() < API_SECRET_LEN {
		// u32::BITS is 32, so the fixed shift count 32 - 6 = 26 is below the width.
		let idx = SysRng
			.try_next_u32()
			.map_err(|e| ConfigError::InvalidConfig(format!("SysRng error: {}", e)))?
			>> (u32::BITS - 6);
		if idx < alphabet_len {
			// idx as usize is safe. alphabet_len is constanct small number
			let character = API_SECRET_ALPHABET.get(idx as usize).ok_or_else(|| {
				ConfigError::InvalidConfig("API secret alphabet index is invalid".to_string())
			})?;
			api_secret.push(char::from(*character));
		}
	}
	Ok(Zeroizing::new(api_secret))
}

/// Create file with api secret
pub fn init_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let api_secret = generate_api_secret()?;
	file::write_owner_only_file(api_secret_path, api_secret.as_bytes())?;
	Ok(())
}

/// Check that the file contains a usable API secret.
///
/// User-provided secrets are accepted when the first line contains at least
/// 15 UTF-8 bytes (`API_SECRET_LEN - 5`). Additional lines are allowed only
/// when empty. This validation deliberately does not estimate entropy; users
/// who replace the generated secret are responsible for choosing a strong
/// value.
///
/// Empty, short, oversized, or structurally invalid content is replaced with a
/// newly generated secret. Read and UTF-8 decoding errors are returned without
/// deleting the original file.
pub fn check_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let mut api_secret_file = match file::open_owner_only_file_or_exposed(api_secret_path)? {
		OwnerOnlyFile::File(file) => file,
		OwnerOnlyFile::Exposed => {
			error!(
				"api secret {} had unsafe read permissions. We will rotate the secret.",
				api_secret_path.display()
			);
			fs::remove_file(api_secret_path)?;
			init_api_secret(api_secret_path)?;
			return Ok(());
		}
	};
	let file_len = api_secret_file.metadata()?.len();
	if file_len > API_SECRET_MAX_FILE_SIZE {
		error!(
			"api secret {} is too large. We will reset the secret.",
			api_secret_path.display()
		);
		drop(api_secret_file);
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
		return Ok(());
	}

	// file_len as usize is safe becaise file_len <= API_SECRET_MAX_FILE_SIZE
	let mut secret_bytes = Zeroizing::new(vec![0; file_len as usize]);
	api_secret_file.read_exact(&mut secret_bytes[..])?;
	let mut extra = Zeroizing::new([0u8; 1]);
	if api_secret_file.read(&mut extra[..])? != 0 {
		return Err(ConfigError::InvalidConfig(format!(
			"api secret {} changed size while being read",
			api_secret_path.display()
		)));
	}
	let secret_contents = std::str::from_utf8(secret_bytes.as_slice()).map_err(|e| {
		ConfigError::InvalidConfig(format!(
			"api secret {} is not valid UTF-8: {}",
			api_secret_path.display(),
			e
		))
	})?;
	let mut lines_iter = secret_contents.lines();

	let first_line = match lines_iter.next() {
		Some(line) => line,
		None => {
			drop(api_secret_file);
			fs::remove_file(api_secret_path)?;
			init_api_secret(api_secret_path)?;
			return Ok(());
		}
	};

	// The secret is the first line. Any remaining lines must be empty.
	let mut valid_secret_file = !first_line.is_empty();
	for line in lines_iter {
		if !line.is_empty() {
			error!(
				"api secret {} contains unexpected additional content. We will reset the secret.",
				api_secret_path.display()
			);
			valid_secret_file = false;
		}
	}
	if first_line.len() < API_SECRET_MIN_LEN {
		error!(
			"api secret {} is too weak. We will reset the secret.",
			api_secret_path.display()
		);
		valid_secret_file = false;
	}

	if !valid_secret_file {
		info!("api secret {} was reset.", api_secret_path.display());
		drop(api_secret_file);
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
	}

	Ok(())
}

/// Check that the api secret file exists and is valid
fn check_api_secret_file(api_secret_path: &Path) -> Result<(), ConfigError> {
	if !api_secret_path.try_exists()? {
		init_api_secret(&api_secret_path.to_path_buf())
	} else {
		check_api_secret(&api_secret_path.to_path_buf())
	}
}

/// Check the configured api secret file when a path is set
fn check_configured_api_secret_file(api_secret_path: &Option<String>) -> Result<(), ConfigError> {
	if let Some(api_secret_path) = api_secret_path {
		check_api_secret_file(Path::new(api_secret_path))?;
	}
	Ok(())
}

/// Check that the configured api secret files exist and are valid
fn check_configured_api_secret_files(config: &GlobalWalletConfig) -> Result<(), ConfigError> {
	check_configured_api_secret_file(&config.members.wallet.api_secret_path)?;
	check_configured_api_secret_file(&config.members.wallet.node_api_secret_path)?;
	Ok(())
}

/// Handles setup and detection of paths for wallet
pub fn initial_setup_wallet(
	chain_type: &global::ChainTypes,
	data_path: Option<PathBuf>,
	wallet_data_dir: Option<&str>,
	create_path: bool,
) -> Result<GlobalWalletConfig, ConfigError> {
	// Use config file if current directory if it exists, .mwc home otherwise
	let config = if let Some(p) = check_config_current_dir(WALLET_CONFIG_FILE_NAME)? {
		GlobalWalletConfig::new(p.to_str().ok_or(ConfigError::InvalidConfig(
			"Internal error: invalid wallet config file name".into(),
		))?)?
	} else {
		// Check if mwc dir exists
		let mwc_path = match data_path {
			Some(p) => {
				// A caller-specified wallet root holds the seed and api secrets,
				// so create it securely when requested or validate the selected
				// existing directory without creating it.
				prepare_wallet_root(&p, create_path)?;
				p
			}
			None => get_mwc_path(chain_type, create_path)?,
		};

		// Get path to default config file
		let mut config_path = mwc_path.clone();
		config_path.push(WALLET_CONFIG_FILE_NAME);

		// Return defaults only when the file is confirmed absent
		match config_path.try_exists()? {
			false => {
				let mut default_config = GlobalWalletConfig::for_chain(chain_type);
				default_config.config_file_path = Some(config_path);
				// update paths relative to current dir
				default_config.update_paths(&mwc_path, wallet_data_dir)?;
				default_config
			}
			true => {
				GlobalWalletConfig::new(config_path.to_str().ok_or(ConfigError::InvalidConfig(
					"Internal error: invalid wallet config file name".into(),
				))?)?
			}
		}
	};

	check_configured_api_secret_files(&config)?;
	Ok(config)
}

impl Default for GlobalWalletConfigMembers {
	fn default() -> GlobalWalletConfigMembers {
		GlobalWalletConfigMembers {
			config_file_version: Some(CURRENT_CONFIG_FILE_VERSION),
			logging: Some(LoggingConfig::default()),
			tor: Some(TorConfig::default()),
			mqs: Some(MQSConfig::default()),
			wallet: WalletConfig::default(),
		}
	}
}

impl Default for GlobalWalletConfig {
	fn default() -> GlobalWalletConfig {
		GlobalWalletConfig {
			config_file_path: None,
			members: GlobalWalletConfigMembers::default(),
		}
	}
}

impl GlobalWalletConfig {
	/// Same as GlobalConfig::default() but further tweaks parameters to
	/// apply defaults for each chain type
	pub fn for_chain(chain_type: &global::ChainTypes) -> GlobalWalletConfig {
		let mut defaults_conf = GlobalWalletConfig::default();
		let defaults = &mut defaults_conf.members.wallet;
		defaults.chain_type = Some(chain_type.clone());

		match *chain_type {
			global::ChainTypes::Mainnet => {}
			global::ChainTypes::Floonet => {
				defaults.api_listen_port = None; //Some(13415);
				defaults.check_node_api_http_addr = Some("http://127.0.0.1:13413".to_owned());
			}
			global::ChainTypes::UserTesting => {
				defaults.api_listen_port = None; //Some(23415);
				defaults.check_node_api_http_addr = Some("http://127.0.0.1:23413".to_owned());
			}
			global::ChainTypes::AutomatedTesting => {
				defaults.api_listen_port = None;
				defaults.check_node_api_http_addr = None;
			}
		}
		defaults_conf
	}
	/// Requires the path to a config file
	pub fn new(file_path: &str) -> Result<GlobalWalletConfig, ConfigError> {
		let mut return_value = GlobalWalletConfig::default();
		return_value.config_file_path = Some(PathBuf::from(&file_path));

		// Config file path is given but not valid
		let config_file =
			return_value
				.config_file_path
				.clone()
				.ok_or(ConfigError::InvalidConfig(
					"config_file_path is empty".into(),
				))?;
		if !config_file.try_exists()? {
			return Err(ConfigError::FileNotFoundError(
				config_file.to_str().unwrap_or("<EMPTY CONFIG>").to_string(),
			));
		}

		// Try to parse the config file if it exists, explode if it does exist but
		// something's wrong with it
		return_value.read_config()
	}

	/// Read config
	fn read_config(mut self) -> Result<GlobalWalletConfig, ConfigError> {
		let config_file_path = self
			.config_file_path
			.as_mut()
			.ok_or(ConfigError::InvalidConfig(
				"config_file_path is empty".into(),
			))?;
		// The config selects node endpoints and API secret paths, so its contents
		// are only trusted when read from an owner-only regular file. The
		// owner-only writer only runs when the file is (re)written, so a config
		// that needs no write would never have its permissions validated.
		let contents =
			String::from_utf8(file::read_owner_only_file(config_file_path.as_path())?.to_vec())
				.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
		// Security policy: `tor_bridge` is not a secret, including any embedded
		// authentication fields. Its full value may be printed in logs or terminal
		// output, including TOML errors from parsing or migrating the config.
		let migrated = GlobalWalletConfig::migrate_config_file_version_none_to_2(
			contents,
			config_file_path.to_owned(),
		)?;
		let fixed = GlobalWalletConfig::fix_warning_level(migrated);
		let decoded: Result<GlobalWalletConfigMembers, toml::de::Error> = toml::from_str(&fixed);
		match decoded {
			Ok(gc) => {
				self.members = gc;
				Ok(self)
			}
			Err(e) => Err(ConfigError::ParseError(
				self.config_file_path
					.map(|path| path.to_string_lossy().to_string())
					.unwrap_or("<INVALID CONFIG FILE>".into()),
				format!("{}", e),
			)),
		}
	}

	/// Update paths
	pub fn update_paths(
		&mut self,
		wallet_home: &PathBuf,
		wallet_data_dir: Option<&str>,
	) -> Result<(), ConfigError> {
		// The data dir is pushed onto the wallet root below, so it must stay
		// inside it: an absolute path would replace the root and `..` would
		// escape it.
		if let Some(dir) = wallet_data_dir {
			validate_wallet_data_dir(dir)?;
		}
		let mut wallet_path = wallet_home.clone();
		wallet_path.push(wallet_data_dir.unwrap_or(MWC_WALLET_DIR));
		self.members.wallet.data_file_dir = wallet_path
			.to_str()
			.ok_or(ConfigError::InvalidConfig(
				"Unable to build wallet_path".into(),
			))?
			.to_owned();
		let mut secret_path = wallet_home.clone();
		secret_path.push(OWNER_API_SECRET_FILE_NAME);
		self.members.wallet.api_secret_path = Some(
			secret_path
				.to_str()
				.ok_or(ConfigError::InvalidConfig(
					"Unable to build secret_path".into(),
				))?
				.to_owned(),
		);
		let mut node_secret_path = wallet_home.clone();
		node_secret_path.push(NODE_API_SECRET_FILE_NAME);
		self.members.wallet.node_api_secret_path = Some(
			node_secret_path
				.to_str()
				.ok_or(ConfigError::InvalidConfig(
					"Unable to build node_secret_path".into(),
				))?
				.to_owned(),
		);
		let mut log_path = wallet_home.clone();
		log_path.push(WALLET_LOG_FILE_NAME);
		if let Some(logging) = self.members.logging.as_mut() {
			logging.log_file_path = log_path
				.to_str()
				.ok_or_else(|| {
					ConfigError::InvalidConfig("Unable to build log file path".to_string())
				})?
				.to_owned();
		}
		Ok(())
	}

	/// Serialize the configuration while keeping `tor_bridge` on one physical TOML line.
	///
	/// The standard serializer would emit separate nested tables for the bridge
	/// and its transports. To preserve the single-line configuration format:
	///
	/// 1. Clone the members so the original configuration remains unchanged.
	/// 2. Take `tor_bridge` out of the copy, leaving `None` in its place.
	/// 3. Serialize the remaining configuration with the standard TOML serializer.
	/// 4. Serialize the bridge separately as an inline TOML value.
	/// 5. Parse the generated document to locate the actual `[tor]` header. Its
	///    span avoids mistaking text inside a multiline string for a table header.
	/// 6. Insert the bridge assignment immediately after that header, for example:
	///
	/// ```toml
	/// [tor]
	/// tor_bridge = { proxy = "socks5://127.0.0.1:1080" }
	/// ```
	///
	/// If no bridge is configured, steps 4–6 are skipped. Serialization or parsing
	/// failures, or an unexpectedly missing Tor section, return
	/// `ConfigError::SerializationError`; otherwise the completed TOML is returned.
	pub fn ser_config(&self) -> Result<String, ConfigError> {
		// Keep the entire bridge/proxy choice on one physical TOML line. The
		// document serializer otherwise emits nested tables for transports.
		let mut members = self.members.clone();
		let bridge = members.tor.as_mut().and_then(|tor| tor.tor_bridge.take());
		let mut encoded = toml::to_string(&members)
			.map_err(|e| ConfigError::SerializationError(e.to_string()))?;
		if let Some(bridge) = bridge {
			let inline = bridge
				.to_inline_toml()
				.map_err(|e| ConfigError::SerializationError(e.to_string()))?;
			// Use the parsed table header's span: a header-looking substring
			// can also occur inside another setting's multiline string.
			let offset = toml::de::DeTable::parse(&encoded)
				.map_err(|e| ConfigError::SerializationError(e.to_string()))?
				.get_ref()
				.get("tor")
				.map(|table| table.span().end)
				.ok_or_else(|| {
					ConfigError::SerializationError("Serialized Tor section is missing".into())
				})?;
			encoded.insert_str(offset, &format!("\ntor_bridge = {}", inline));
		}
		Ok(encoded)
	}

	/// Write configuration to a file.
	///
	/// # Accepted durability limitation
	///
	/// Serialization and migration-validation errors occur before the target is
	/// opened and leave an existing configuration untouched. The final
	/// `write_owner_only_file` call, however, truncates an existing file before
	/// writing and synchronizing the replacement. A write or sync failure can
	/// therefore leave that file empty or partially rewritten. Because
	/// `config_file_version` is emitted first and missing sections are filled
	/// with defaults on deserialization, such a partial prefix can still parse
	/// as valid TOML, so a later startup may accept it with security-relevant
	/// settings silently omitted. This non-atomic replacement risk is
	/// understood and accepted; the I/O error is returned to the caller, which
	/// may need to restore the configuration.
	pub fn write_to_file(
		&mut self,
		name: &str,
		migration: bool,
		old_config: String,
		old_version: Option<u32>,
	) -> Result<(), ConfigError> {
		let conf_out = self.ser_config()?;
		let commented_config = if migration {
			migrate_comments(old_config, conf_out, old_version)?
		} else {
			let fixed_config = GlobalWalletConfig::fix_log_level(conf_out);
			insert_comments(fixed_config)
		};
		// The config file can reference secrets, so it is written owner-only.
		file::write_owner_only_file(name, commented_config.as_bytes())?;
		Ok(())
	}
	/// This migration does the following:
	/// - Adds "config_file_version = 2"
	/// - Introduce new key config_file_version, [tor.bridge] and [tor.proxy]
	/// - Migrate old config key/value and comments while it does not conflict with newly indroduced key and comments
	fn migrate_config_file_version_none_to_2(
		config_str: String,
		config_file_path: PathBuf,
	) -> Result<String, ConfigError> {
		let fixed_config = GlobalWalletConfig::fix_warning_level(config_str.clone());
		let version_header: ConfigVersionHeader = toml::from_str(&fixed_config).map_err(|e| {
			ConfigError::SerializationError(format!("Failed to serialize config into toml, {}", e))
		})?;
		match version_header.config_file_version {
			Some(CURRENT_CONFIG_FILE_VERSION) => return Ok(config_str),
			Some(found) => {
				return Err(ConfigError::UnsupportedConfigVersion {
					found,
					supported: CURRENT_CONFIG_FILE_VERSION,
				});
			}
			None => {}
		}

		// A missing version is the one explicitly supported legacy form
		// (version 1). Only deserialize it as the legacy/current schema after
		// rejecting unsupported numeric and future versions above.
		let config: GlobalWalletConfigMembers = toml::from_str(&fixed_config).map_err(|e| {
			ConfigError::SerializationError(format!("Failed to serialize config into toml, {}", e))
		})?;
		let adjusted_config = GlobalWalletConfigMembers {
			config_file_version: GlobalWalletConfigMembers::default().config_file_version,
			tor: config.tor.clone().or_else(|| Some(TorConfig::default())),
			..config
		};
		let mut gc = GlobalWalletConfig {
			members: adjusted_config,
			config_file_path: Some(config_file_path.clone()),
		};
		let str_path = config_file_path
			.into_os_string()
			.into_string()
			.map_err(|e| {
				ConfigError::SerializationError(format!("invalid config file path, {:?}", e))
			})?;
		gc.write_to_file(&str_path, true, config_str, config.config_file_version)?;
		let adjusted_config_str = fs::read_to_string(str_path.clone())?;
		Ok(adjusted_config_str)
	}

	// For forwards compatibility old config needs `Warning` log level changed to standard log::Level `WARN`
	pub(crate) fn fix_warning_level(conf: String) -> String {
		let mut fixed = String::with_capacity(conf.len());
		GlobalWalletConfig::push_fixed_logging_level_fields(
			&mut fixed,
			&conf,
			&[("Warning", "WARN")],
		);
		fixed
	}

	// For backwards compatibility only first letter of log level should be capitalised.
	fn fix_log_level(conf: String) -> String {
		// Allocate enough headroom so growing replacements such as WARN -> Warning
		// do not reallocate.
		let mut fixed = String::with_capacity(conf.len().saturating_mul(2));
		GlobalWalletConfig::push_fixed_logging_level_fields(
			&mut fixed,
			&conf,
			&[
				("TRACE", "Trace"),
				("DEBUG", "Debug"),
				("INFO", "Info"),
				("WARN", "Warning"),
				("ERROR", "Error"),
			],
		);
		fixed
	}

	// Rewrites log level values line by line, so only the exact quoted values of
	// the stdout_log_level and file_log_level keys are replaced. Paths, secrets
	// and comments containing a level name are left untouched.
	//
	// Known limitation (accepted): the rewrite tracks neither the current TOML
	// table nor multiline string state. A stdout_log_level/file_log_level entry
	// under another table (e.g. the user-extensible [wallet.swap_electrumx_addr]
	// map), or a matching line inside a multiline string value, would be
	// rewritten as well; in the migration path migrate_comments then parses the
	// already modified text as its baseline, so such a change would not be
	// detected. The read-side fix only reverses `Warning` -> `WARN`, so a
	// rewritten value such as `DEBUG` -> `Debug` stays modified on disk and is
	// never restored on read; only `WARN` round-trips, and only because both
	// rewrites are blind in the same way. This is accepted: in real
	// configurations those keys only occur under [logging] with a single-line
	// level value, and the wallet config does not use multiline strings, so the
	// line-by-line rewrite works well for our usage.
	fn push_fixed_logging_level_fields(
		fixed: &mut String,
		conf: &str,
		replacements: &[(&str, &str)],
	) {
		for line in conf.split_inclusive('\n') {
			GlobalWalletConfig::push_fixed_logging_level_line(fixed, line, replacements);
		}
	}

	fn push_fixed_logging_level_line(
		fixed: &mut String,
		line: &str,
		replacements: &[(&str, &str)],
	) {
		let trimmed = line.trim_start();
		if trimmed.starts_with('#') {
			fixed.push_str(line);
			return;
		}

		let Some(eq_pos) = line.find('=') else {
			fixed.push_str(line);
			return;
		};
		let key = line[..eq_pos].trim();
		if key != "stdout_log_level" && key != "file_log_level" {
			fixed.push_str(line);
			return;
		}

		let value_prefix = &line[eq_pos + 1..];
		let Some(value_offset) = value_prefix.find(|c: char| !c.is_whitespace()) else {
			fixed.push_str(line);
			return;
		};
		let value_pos = eq_pos + 1 + value_offset;
		for (from, to) in replacements {
			for quote in ['"', '\''] {
				let old_value = format!("{}{}{}", quote, from, quote);
				if let Some(rest) = line[value_pos..].strip_prefix(&old_value) {
					if rest
						.chars()
						.next()
						.map(|c| c.is_whitespace() || c == '#')
						.unwrap_or(true)
					{
						fixed.push_str(&line[..value_pos]);
						fixed.push(quote);
						fixed.push_str(to);
						fixed.push(quote);
						fixed.push_str(rest);
						return;
					}
				}
			}
		}

		fixed.push_str(line);
	}
}

#[test]
fn test_fix_log_level() {
	let config = r#"
[logging]
stdout_log_level = "WARN" # keep this comment
file_log_level='ERROR'
log_file_path = "WARN/mwc-wallet.log"

[wallet]
api_secret_path = "WARN-secret"
#stdout_log_level = "WARN"
"#
	.to_string();
	let fixed_config = GlobalWalletConfig::fix_log_level(config);
	assert!(fixed_config.contains("stdout_log_level = \"Warning\" # keep this comment"));
	assert!(fixed_config.contains("file_log_level='Error'"));
	assert!(fixed_config.contains("log_file_path = \"WARN/mwc-wallet.log\""));
	assert!(fixed_config.contains("api_secret_path = \"WARN-secret\""));
	assert!(fixed_config.contains("#stdout_log_level = \"WARN\""));
}

#[test]
fn test_fix_warning_level() {
	let config = r#"
[logging]
stdout_log_level = "Warning" # keep this comment
file_log_level = "Info"
log_file_path = "Warning/mwc-wallet.log"

[wallet]
api_secret_path = "Warning-secret"
#stdout_log_level = "Warning"
"#
	.to_string();
	let fixed_config = GlobalWalletConfig::fix_warning_level(config);
	assert!(fixed_config.contains("stdout_log_level = \"WARN\" # keep this comment"));
	assert!(fixed_config.contains("file_log_level = \"Info\""));
	assert!(fixed_config.contains("log_file_path = \"Warning/mwc-wallet.log\""));
	assert!(fixed_config.contains("api_secret_path = \"Warning-secret\""));
	assert!(fixed_config.contains("#stdout_log_level = \"Warning\""));
}

#[test]
fn for_chain_uses_network_specific_node_addresses() {
	let cases = [
		(global::ChainTypes::Mainnet, "http://127.0.0.1:3413"),
		(global::ChainTypes::Floonet, "http://127.0.0.1:13413"),
		(global::ChainTypes::UserTesting, "http://127.0.0.1:23413"),
	];

	for (chain_type, node_address) in cases {
		let config = GlobalWalletConfig::for_chain(&chain_type);
		assert_eq!(config.members.wallet.chain_type, Some(chain_type));
		assert_eq!(
			config.members.wallet.check_node_api_http_addr.as_deref(),
			Some(node_address)
		);
	}
}

#[test]
fn for_chain_disables_node_address_for_automated_testing() {
	let config = GlobalWalletConfig::for_chain(&global::ChainTypes::AutomatedTesting);

	assert_eq!(
		config.members.wallet.chain_type,
		Some(global::ChainTypes::AutomatedTesting)
	);
	assert_eq!(config.members.wallet.check_node_api_http_addr, None);
}

#[test]
fn fresh_config_documents_optional_mining_node_ip_without_enabling_it() {
	let config = GlobalWalletConfig::default();
	let serialized = config.ser_config().unwrap();
	assert!(!serialized.contains("mining_node_ip"));

	let commented = insert_comments(serialized);
	assert!(commented.contains("#mining_node_ip = \"127.0.0.1\""));
	assert!(!commented.contains("\nmining_node_ip = "));
}

#[test]
fn mining_node_ip_round_trips_as_a_toml_string() {
	let mut config = GlobalWalletConfig::default();
	let mining_node_ip = "192.0.2.10".parse().unwrap();
	config.members.wallet.mining_node_ip = Some(mining_node_ip);

	let serialized = config.ser_config().unwrap();
	assert!(serialized.contains("mining_node_ip = \"192.0.2.10\""));

	let decoded: GlobalWalletConfigMembers = toml::from_str(&serialized).unwrap();
	assert_eq!(decoded.wallet.mining_node_ip, Some(mining_node_ip));
}

#[test]
fn tor_bridge_round_trips_on_one_config_line() {
	let mut config = GlobalWalletConfig::default();
	let tor: TorConfig = toml::from_str(
		r#"tor_bridge = { bridges = ["obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=example iat-mode=0"], transports = [{ protocols = ["obfs4"], path = "/absolute/helper", arguments = ["--label", "quoted\"value", "line\nbreak"], run_on_startup = true }], proxy = "socks5://user:password@127.0.0.1:1080" }"#,
	)
	.unwrap();
	config.members.tor = Some(tor.clone());
	config.members.wallet.api_secret_path = Some("prefix\n[tor]\nsuffix".into());
	let serialized = config.ser_config().unwrap();
	assert_eq!(
		serialized
			.lines()
			.filter(|l| l.starts_with("tor_bridge = "))
			.count(),
		1
	);
	assert!(!serialized.contains("[tor.tor_bridge"));
	assert!(!serialized.contains("[[tor.tor_bridge"));
	let bridge_line = serialized
		.lines()
		.find(|line| line.starts_with("tor_bridge = "))
		.unwrap();
	let one_line_tor: TorConfig = toml::from_str(bridge_line).unwrap();
	assert_eq!(one_line_tor, tor);
	let decoded: GlobalWalletConfigMembers = toml::from_str(&serialized).unwrap();
	assert_eq!(decoded.tor, Some(tor));
	assert_eq!(config.members, decoded);
}

#[test]
fn fresh_config_documents_tor_options_without_enabling_bridges() {
	let config = GlobalWalletConfig::default();
	let commented = insert_comments(config.ser_config().unwrap());
	assert!(commented.contains("Embedded Arti connects directly by default"));
	assert!(!commented
		.lines()
		.any(|line| line.starts_with("tor_bridge = ")));
	let mut examples = 0;
	for line in commented
		.lines()
		.filter_map(|line| line.strip_prefix("# tor_bridge = "))
	{
		let tor: TorConfig = toml::from_str(&format!("tor_bridge = {}", line)).unwrap();
		assert!(tor.tor_bridge.is_some());
		examples += 1;
	}
	assert_eq!(examples, 17);
}

#[test]
fn existing_wallet_root_is_not_created_when_create_path_is_false() {
	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let missing_root = temp_dir.path().join("missing-wallet-root");

	let result = prepare_wallet_root(&missing_root, false);

	assert!(matches!(result, Err(ConfigError::PathNotFoundError(_))));
	assert!(!missing_root.exists());
}

#[cfg(unix)]
#[test]
fn existing_wallet_root_rejects_group_or_other_writable_permissions() {
	use std::os::unix::fs::PermissionsExt;

	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let wallet_root = temp_dir.path().join("unsafe-wallet-root");
	fs::create_dir(&wallet_root).unwrap();
	fs::set_permissions(&wallet_root, fs::Permissions::from_mode(0o777)).unwrap();

	let result = prepare_wallet_root(&wallet_root, false);

	assert!(matches!(result, Err(ConfigError::InvalidConfig(_))));
	assert_eq!(
		fs::metadata(&wallet_root).unwrap().permissions().mode() & 0o777,
		0o777
	);
}

#[cfg(unix)]
#[test]
fn existing_wallet_root_is_validated_and_tightened_without_recreation() {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};

	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let wallet_root = temp_dir.path().join("existing-wallet-root");
	fs::create_dir(&wallet_root).unwrap();
	fs::set_permissions(&wallet_root, fs::Permissions::from_mode(0o755)).unwrap();
	let inode_before = fs::metadata(&wallet_root).unwrap().ino();

	prepare_wallet_root(&wallet_root, false).unwrap();

	let metadata = fs::metadata(&wallet_root).unwrap();
	assert_eq!(metadata.ino(), inode_before);
	assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[cfg(unix)]
#[test]
fn wallet_root_rejects_terminal_symlink_variants_for_both_create_modes() {
	use std::os::unix::fs::{symlink, PermissionsExt};

	for create_path in [false, true] {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let target = temp_dir.path().join("wallet-root-target");
		let link = temp_dir.path().join("wallet-root-link");
		fs::create_dir(&target).unwrap();
		fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
		symlink(&target, &link).unwrap();

		for path in [
			link.clone(),
			PathBuf::from(format!("{}/", link.display())),
			PathBuf::from(format!("{}/.", link.display())),
			PathBuf::from(format!("{}/./", link.display())),
		] {
			assert!(
				prepare_wallet_root(&path, create_path).is_err(),
				"wallet root followed directory symlink {} with create_path={}",
				path.display(),
				create_path
			);
		}
		assert_eq!(
			fs::metadata(&target).unwrap().permissions().mode() & 0o777,
			0o755
		);
	}
}

// Config fixtures must be owner-only, matching what the wallet itself writes.
// Other platforms have no owner-only mode bits to set.
#[cfg(all(test, unix))]
fn make_config_owner_only(path: &Path) {
	use std::os::unix::fs::PermissionsExt;
	fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(all(test, not(unix)))]
fn make_config_owner_only(_path: &Path) {}

#[test]
fn current_config_file_version_is_accepted() {
	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let config_path = temp_dir.path().join(WALLET_CONFIG_FILE_NAME);
	let config_str = format!("config_file_version = {}\n", CURRENT_CONFIG_FILE_VERSION);
	fs::write(&config_path, &config_str).unwrap();
	make_config_owner_only(&config_path);

	let config = GlobalWalletConfig::new(config_path.to_str().unwrap()).unwrap();

	assert_eq!(
		config.members.config_file_version,
		Some(CURRENT_CONFIG_FILE_VERSION)
	);
	assert_eq!(fs::read_to_string(config_path).unwrap(), config_str);
}

#[test]
fn unversioned_config_file_is_migrated_to_current_version() {
	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let config_path = temp_dir.path().join(WALLET_CONFIG_FILE_NAME);
	fs::write(&config_path, "").unwrap();
	make_config_owner_only(&config_path);

	let config = GlobalWalletConfig::new(config_path.to_str().unwrap()).unwrap();

	assert_eq!(
		config.members.config_file_version,
		Some(CURRENT_CONFIG_FILE_VERSION)
	);
	let migrated = fs::read_to_string(config_path).unwrap();
	assert!(migrated.contains(&format!(
		"config_file_version = {}",
		CURRENT_CONFIG_FILE_VERSION
	)));
}

#[test]
fn unversioned_config_migration_preserves_explicit_tor_bridge() {
	let bridge_line = r#"tor_bridge = { bridges = ["webtunnel 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://bridge.example/path"], transports = [{ protocols = ["webtunnel"], path = "/absolute/helper", arguments = ["--flag"], run_on_startup = true }] }"#;
	let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
	let config_path = temp_dir.path().join(WALLET_CONFIG_FILE_NAME);
	let old_config = format!(
		"[wallet]\ndata_file_dir = \".\"\n[tor]\ntor_enabled = false\n{}\n",
		bridge_line
	);
	let old_members: GlobalWalletConfigMembers = toml::from_str(&old_config).unwrap();
	fs::write(&config_path, old_config).unwrap();
	make_config_owner_only(&config_path);
	let migrated = GlobalWalletConfig::new(config_path.to_str().unwrap()).unwrap();
	assert_eq!(migrated.members.tor, old_members.tor);
	let written = fs::read_to_string(config_path).unwrap();
	assert_eq!(
		written
			.lines()
			.filter(|l| l.starts_with("tor_bridge = "))
			.count(),
		1
	);
}

#[test]
fn unsupported_config_file_versions_are_rejected_without_rewriting() {
	for unsupported_version in [1, CURRENT_CONFIG_FILE_VERSION + 1, u32::MAX] {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let config_path = temp_dir.path().join(WALLET_CONFIG_FILE_NAME);
		let config_str = format!(
			"config_file_version = {}\nfuture_security_setting = true\n",
			unsupported_version
		);
		fs::write(&config_path, &config_str).unwrap();
		make_config_owner_only(&config_path);

		let result = GlobalWalletConfig::new(config_path.to_str().unwrap());

		assert!(matches!(
			result,
			Err(ConfigError::UnsupportedConfigVersion {
				found,
				supported: CURRENT_CONFIG_FILE_VERSION
			}) if found == unsupported_version
		));
		assert_eq!(fs::read_to_string(&config_path).unwrap(), config_str);
	}
}

#[cfg(unix)]
#[test]
fn group_or_other_accessible_config_file_is_rejected() {
	use std::os::unix::fs::PermissionsExt;

	// 0o644 exposes the config to group/other readers and 0o664 to group
	// writers; both are rejected before the contents are trusted.
	for mode in [0o644, 0o664] {
		let temp_dir = mwc_wallet_util::mwc_crates::tempfile::TempDir::new().unwrap();
		let config_path = temp_dir.path().join(WALLET_CONFIG_FILE_NAME);
		let config_str = format!("config_file_version = {}\n", CURRENT_CONFIG_FILE_VERSION);
		fs::write(&config_path, &config_str).unwrap();
		fs::set_permissions(&config_path, fs::Permissions::from_mode(mode)).unwrap();

		let result = GlobalWalletConfig::new(config_path.to_str().unwrap());

		assert!(
			matches!(result, Err(ConfigError::FileIOError(_))),
			"config with mode {:o} must be rejected",
			mode
		);
		// A rejected config is left untouched.
		assert_eq!(fs::read_to_string(&config_path).unwrap(), config_str);
	}
}

#[cfg(test)]
fn api_secret_test_path(name: &str) -> PathBuf {
	let mut dir = env::temp_dir();
	let nonce = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_nanos();
	dir.push(format!(
		"mwc_wallet_config_api_secret_{}_{}_{}",
		name,
		std::process::id(),
		nonce
	));
	fs::create_dir_all(&dir).unwrap();
	dir.push(".api_secret");
	dir
}

#[cfg(unix)]
#[test]
fn init_api_secret_creates_owner_only_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("owner_only");

	init_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn init_api_secret_fixes_existing_file_permissions_before_write() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("fix_permissions");
	fs::write(&path, "old-secret").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	init_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	assert_ne!(fs::read_to_string(&path).unwrap(), "old-secret");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rotates_exposed_secret() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("rotate_exposed");
	fs::write(&path, "exposed-secret-value").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	check_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	let secret = fs::read_to_string(&path).unwrap();
	assert_ne!(secret, "exposed-secret-value");
	assert_eq!(secret.len(), API_SECRET_LEN);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_resets_weak_secret() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("reset_weak");
	fs::write(&path, "short").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	check_api_secret(&path).unwrap();

	let secret = fs::read_to_string(&path).unwrap();
	assert_ne!(secret, "short");
	assert_eq!(secret.len(), API_SECRET_LEN);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_allows_documented_empty_trailing_lines() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("empty_trailing_lines");
	let secret = "user_chosen_secret\n\n";
	fs::write(&path, secret).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	check_api_secret(&path).unwrap();

	assert_eq!(fs::read_to_string(&path).unwrap(), secret);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rotates_newline_only_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("newline_only");
	fs::write(&path, "\n").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	check_api_secret(&path).unwrap();

	let secret = fs::read_to_string(&path).unwrap();
	assert_eq!(secret.len(), API_SECRET_LEN);
	assert_ne!(secret, "\n");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rotates_nonempty_additional_line() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("extra_line");
	let invalid = "user_chosen_secret\nunexpected\n";
	fs::write(&path, invalid).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	check_api_secret(&path).unwrap();

	let secret = fs::read_to_string(&path).unwrap();
	assert_eq!(secret.len(), API_SECRET_LEN);
	assert_ne!(secret, invalid);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_preserves_file_on_utf8_error() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("invalid_utf8");
	let invalid = b"user_chosen_secret\n\xff";
	fs::write(&path, invalid).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	assert!(check_api_secret(&path).is_err());
	assert_eq!(fs::read(&path).unwrap(), invalid);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rejects_unsafe_writable_file_without_modifying_it() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("unsafe_writable");
	let secret = "user_chosen_secret";
	fs::write(&path, secret).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

	assert!(check_api_secret(&path).is_err());
	assert_eq!(fs::read_to_string(&path).unwrap(), secret);
	assert_eq!(
		fs::metadata(&path).unwrap().permissions().mode() & 0o777,
		0o666
	);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rejects_symlink_without_modifying_target() {
	use std::os::unix::fs::{symlink, PermissionsExt};

	let path = api_secret_test_path("symlink");
	let target = path.with_file_name("target_secret");
	let secret = "user_chosen_secret";
	fs::write(&target, secret).unwrap();
	fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
	symlink(&target, &path).unwrap();

	assert!(check_api_secret(&path).is_err());
	assert_eq!(fs::read_to_string(&target).unwrap(), secret);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn validate_wallet_data_dir_accepts_relative_paths() {
	assert!(validate_wallet_data_dir("wallet_data").is_ok());
	assert!(validate_wallet_data_dir("wallet1").is_ok());
	assert!(validate_wallet_data_dir("accounts/wallet1").is_ok());
	assert!(validate_wallet_data_dir("./wallet_data").is_ok());
}

#[test]
fn validate_wallet_data_dir_rejects_absolute_and_parent_paths() {
	for bad in [
		"/tmp/wallet",
		"/",
		"..",
		"../wallet",
		"a/../../wallet",
		"wallet/..",
		"",
	] {
		assert!(
			validate_wallet_data_dir(bad).is_err(),
			"wallet_data_dir {:?} must be rejected",
			bad
		);
	}
}

#[test]
fn update_paths_rejects_wallet_data_dir_outside_wallet_root() {
	let home = PathBuf::from("/home/user/.mwc/main");
	for bad in ["/tmp/wallet", "../wallet", "a/../../wallet", ""] {
		let mut config = GlobalWalletConfig::for_chain(&global::ChainTypes::Mainnet);
		assert!(
			config.update_paths(&home, Some(bad)).is_err(),
			"wallet_data_dir {:?} must be rejected",
			bad
		);
	}
}

#[test]
fn update_paths_builds_data_dir_inside_wallet_root() {
	let home = PathBuf::from("/home/user/.mwc/main");

	let mut config = GlobalWalletConfig::for_chain(&global::ChainTypes::Mainnet);
	config.update_paths(&home, Some("wallet1")).unwrap();
	assert_eq!(
		config.members.wallet.data_file_dir,
		"/home/user/.mwc/main/wallet1"
	);

	let mut config = GlobalWalletConfig::for_chain(&global::ChainTypes::Mainnet);
	config.update_paths(&home, None).unwrap();
	assert_eq!(
		config.members.wallet.data_file_dir,
		"/home/user/.mwc/main/wallet_data"
	);
}
