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

//! Public types for config modules

use failure::Fail;
use std::io;
use std::path::PathBuf;

use crate::config::GRIN_WALLET_DIR;
use crate::core::global::ChainTypes;
use crate::util::logger::LoggingConfig;
use std::collections::BTreeMap;

/// Command-line wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletConfig {
	/// Chain parameters (default to Mainnet if none at the moment)
	pub chain_type: Option<ChainTypes>,
	/// The api interface/ip_address that this api server (i.e. this wallet) will run
	/// by default this is 127.0.0.1 (and will not accept connections from external clients)
	pub api_listen_interface: String,
	/// The port this wallet will run on
	pub api_listen_port: u16,
	/// The port this wallet's owner API will run on
	pub owner_api_listen_port: Option<u16>,
	/// Location of the secret for basic auth on the Owner API
	pub api_secret_path: Option<String>,
	/// Location of the node api secret for basic auth on the Grin API
	pub node_api_secret_path: Option<String>,
	/// The api address of a running server node against which transaction inputs
	/// will be checked during send
	pub check_node_api_http_addr: String,
	/// Whether to include foreign API endpoints on the Owner API
	pub owner_api_include_foreign: Option<bool>,
	/// Whether to include the mwcmqs listener
	pub owner_api_include_mqs_listener: Option<bool>,
	///Index used to derive address
	pub grinbox_address_index: Option<u32>,
	/// The directory in which wallet files are stored
	pub data_file_dir: String,
	/// If Some(true), don't cache commits alongside output data
	/// speed improvement, but your commits are in the database
	pub no_commit_cache: Option<bool>,
	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,
	/// Whether to use the black background color scheme for command line
	/// if enabled, wallet command output color will be suitable for black background terminal
	pub dark_background_color_scheme: Option<bool>,
	/// Wallet data directory. Default none is 'wallet_data'
	pub wallet_data_dir: Option<String>,
	/// Electrum nodes for secondary coins
	/// Key: <coin>_[main|test]_[1|2]
	/// Value: url
	pub swap_electrumx_addr: Option<BTreeMap<String, String>>,
}

impl Default for WalletConfig {
	fn default() -> WalletConfig {
		WalletConfig {
			chain_type: Some(ChainTypes::Mainnet),
			api_listen_interface: "127.0.0.1".to_string(),
			api_listen_port: 3415,
			owner_api_listen_port: Some(WalletConfig::default_owner_api_listen_port()),
			api_secret_path: Some(".owner_api_secret".to_string()),
			node_api_secret_path: Some(".api_secret".to_string()),
			check_node_api_http_addr: "http://127.0.0.1:3413".to_string(),
			owner_api_include_foreign: Some(false),
			owner_api_include_mqs_listener: Some(false),
			data_file_dir: ".".to_string(),
			grinbox_address_index: None,
			no_commit_cache: Some(false),
			tls_certificate_file: None,
			tls_certificate_key: None,
			dark_background_color_scheme: Some(true),
			wallet_data_dir: None,
			swap_electrumx_addr: Some(
				[
					("btc_main_1", "btc.main1.swap.mwc.mw:8000"),
					("btc_main_2", "btc.main2.swap.mwc.mw:8000"),
					("btc_test_1", "btc.test1.swap.mwc.mw:8000"),
					("btc_test_2", "btc.test2.swap.mwc.mw:8000"),
					("bch_main_1", "bch.main1.swap.mwc.mw:8000"),
					("bch_main_2", "bch.main2.swap.mwc.mw:8000"),
					("bch_test_1", "bch.test1.swap.mwc.mw:8000"),
					("bch_test_2", "bch.test1.swap.mwc.mw:8000"),
				]
				.iter()
				.cloned()
				.map(|i| (i.0.to_string(), i.1.to_string()))
				.collect::<BTreeMap<String, String>>(),
			),
		}
	}
}

impl WalletConfig {
	/// API Listen address
	pub fn api_listen_addr(&self) -> String {
		format!("{}:{}", self.api_listen_interface, self.api_listen_port)
	}

	/// Default listener port
	pub fn default_owner_api_listen_port() -> u16 {
		3420
	}

	/// Use value from config file, defaulting to sensible value if missing.
	pub fn owner_api_listen_port(&self) -> u16 {
		self.owner_api_listen_port
			.unwrap_or_else(WalletConfig::default_owner_api_listen_port)
	}

	/// Owner API listen address
	pub fn owner_api_listen_addr(&self) -> String {
		format!("127.0.0.1:{}", self.owner_api_listen_port())
	}

	pub fn get_data_path(&self) -> String {
		//mqs feature
		self.wallet_data_dir
			.clone()
			.unwrap_or(GRIN_WALLET_DIR.to_string())
	}
}

/// Error type wrapping config errors.
#[derive(Debug, Fail)]
pub enum ConfigError {
	/// Error with parsing of config file (file_name, message)
	#[fail(display = "Error parsing configuration file at {}, {}", _0, _1)]
	ParseError(String, String),

	/// Error with fileIO while reading config file
	/// (file_name, message)
	#[fail(display = "Config IO error, {}", _0)]
	FileIOError(String),

	/// No file found (file_name)
	#[fail(display = "Configuration file not found: {}", _0)]
	FileNotFoundError(String),

	/// Error serializing config values
	#[fail(display = "Error serializing configuration, {}", _0)]
	SerializationError(String),

	/// Path doesn't exist
	#[fail(display = "Not found expected path {}", _0)]
	PathNotFoundError(String),
}

impl From<io::Error> for ConfigError {
	fn from(error: io::Error) -> ConfigError {
		ConfigError::FileIOError(format!("Error loading config file, {}", error))
	}
}

/// Tor configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TorConfig {
	/// Whether to start tor listener on listener startup (default true)
	pub use_tor_listener: bool,
	/// Just the address of the socks proxy for now
	pub socks_proxy_addr: String,
	/// Send configuration directory
	pub send_config_dir: String,
	/// Whether or not the socks5 proxy is already running
	pub socks_running: bool,
}

impl Default for TorConfig {
	fn default() -> TorConfig {
		TorConfig {
			use_tor_listener: true,
			socks_proxy_addr: "127.0.0.1:59050".to_owned(),
			send_config_dir: ".".into(),
			socks_running: false,
		}
	}
}

/// MQS configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MQSConfig {
	/// mwcmqs domain
	pub mwcmqs_domain: String,
	/// mwcmqs port
	pub mwcmqs_port: u16,
}

impl Default for MQSConfig {
	fn default() -> MQSConfig {
		MQSConfig {
			mwcmqs_domain: "mqs.mwc.mw".to_owned(),
			mwcmqs_port: 443,
		}
	}
}

/// Wallet should be split into a separate configuration file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Wallet members
	pub members: Option<GlobalWalletConfigMembers>,
}

/// Wallet internal members
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfigMembers {
	/// Wallet configuration
	#[serde(default)]
	pub wallet: WalletConfig,
	/// Tor config
	pub tor: Option<TorConfig>,
	/// MQS config
	pub mqs: Option<MQSConfig>,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
