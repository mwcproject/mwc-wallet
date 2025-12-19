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

//! Public types for config modules

use std::io;
use std::path::PathBuf;

use crate::config::MWC_WALLET_DIR;
use crate::core::global::ChainTypes;
use crate::util::logger::LoggingConfig;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_p2p::TorConfig;
use std::collections::BTreeMap;

/// Command-line wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletConfig {
	/// Chain parameters (default to Mainnet if none at the moment)
	pub chain_type: Option<ChainTypes>,
	/// The api interface/ip_address that this api server (i.e. this wallet) will run
	/// by default this is 127.0.0.1 (and will not accept connections from external clients)
	pub api_listen_interface: Option<String>,
	/// The port this wallet will run on
	pub api_listen_port: Option<u16>,
	/// The port for libp2p socks listener to run. If None, libp2p will not be enabled.
	/// libp2p works only with TOR. If tor is not activated, libp2p will not work
	pub libp2p_listen_port: Option<u16>,
	/// The port this wallet's owner API will run on
	pub owner_api_listen_port: Option<u16>,
	/// Location of the secret for basic auth on the Owner API
	pub api_secret_path: Option<String>,
	/// Location of the node api secret for basic auth on the Mwc API
	pub node_api_secret_path: Option<String>,
	/// The api address of a running server node against which transaction inputs
	/// will be checked during send; could be multiple nodes separated by semicolon
	pub check_node_api_http_addr: Option<String>,
	/// Whether to include foreign API endpoints on the Owner API
	pub owner_api_include_foreign: Option<bool>,
	/// Whether to include the mwcmqs listener
	pub owner_api_include_mqs_listener: Option<bool>,
	/// The directory in which wallet files are stored
	pub data_file_dir: String,
	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,
	/// Whether to use the black background color scheme for command line
	/// if enabled, wallet command output color will be suitable for black background terminal
	pub dark_background_color_scheme: Option<bool>,
	/// Wallet data directory. Default none is 'wallet_data'
	pub wallet_data_dir: Option<String>,
	/// Scaling factor from transaction weight to transaction fee
	/// should match tx_fee_base parameter in mwc-server
	pub tx_fee_base: Option<u64>,
	/// Ethereum Swap Contract Address
	pub eth_swap_contract_address: Option<String>,
	/// ERC20 Swap Contract Address
	pub erc20_swap_contract_address: Option<String>,
	/// Ethereum Infura Project Id
	pub eth_infura_project_id: Option<String>,
	/// Electrum nodes for secondary coins
	/// Key: <coin>_[main|test]_[1|2]
	/// Value: url
	pub swap_electrumx_addr: Option<BTreeMap<String, String>>,
}

impl Default for WalletConfig {
	fn default() -> WalletConfig {
		WalletConfig {
			chain_type: Some(ChainTypes::Mainnet),
			api_listen_interface: None, // Some("127.0.0.1".to_string()),
			api_listen_port: None,      // Some(3415),
			libp2p_listen_port: None,   //Some(3418),
			owner_api_listen_port: Some(WalletConfig::default_owner_api_listen_port()),
			api_secret_path: Some(".owner_api_secret".to_string()),
			node_api_secret_path: Some(".api_secret".to_string()),
			check_node_api_http_addr: Some("http://127.0.0.1:3413".to_string()),
			owner_api_include_foreign: Some(false),
			owner_api_include_mqs_listener: Some(false),
			data_file_dir: ".".to_string(),
			tls_certificate_file: None,
			tls_certificate_key: None,
			dark_background_color_scheme: Some(true),
			wallet_data_dir: None,
			eth_swap_contract_address: Some("2FA243fC8f9EAF014f8d6E909157B6A48cEE0bdC".to_string()),
			erc20_swap_contract_address: Some(
				"Dd62a95626453F54E686cF0531bCbf6766150794".to_string(),
			),
			eth_infura_project_id: Some("7f1274674be54d2881bf3c0168bf9855".to_string()),
			swap_electrumx_addr: Some(
				[
					("btc_main_1", "btc.main1.swap.mwc.mw:18337"),
					("btc_main_2", "btc.main2.swap.mwc.mw:18337"),
					("btc_test_1", "btc.test1.swap.mwc.mw:18339"),
					("btc_test_2", "btc.test2.swap.mwc.mw:18339"),
					("bch_main_1", "bch.main1.swap.mwc.mw:18333"),
					("bch_main_2", "bch.main2.swap.mwc.mw:18333"),
					("bch_test_1", "bch.test1.swap.mwc.mw:18335"),
					("bch_test_2", "bch.test1.swap.mwc.mw:18335"),
					("dash_main_1", "dash.main1.swap.mwc.mw:18351"),
					("dash_main_2", "dash.main2.swap.mwc.mw:18351"),
					("dash_test_1", "dash.test1.swap.mwc.mw:18349"),
					("dash_test_2", "dash.test1.swap.mwc.mw:18349"),
					("doge_main_1", "doge.main1.swap.mwc.mw:18359"),
					("doge_main_2", "doge.main2.swap.mwc.mw:18359"),
					("doge_test_1", "doge.test1.swap.mwc.mw:18357"),
					("doge_test_2", "doge.test1.swap.mwc.mw:18357"),
					("ltc_main_1", "ltc.main1.swap.mwc.mw:18343"),
					("ltc_main_2", "ltc.main2.swap.mwc.mw:18343"),
					("ltc_test_1", "ltc.test1.swap.mwc.mw:18341"),
					("ltc_test_2", "ltc.test1.swap.mwc.mw:18341"),
					("zcash_main_1", "zcash.main1.swap.mwc.mw:18355"),
					("zcash_main_2", "zcash.main2.swap.mwc.mw:18355"),
					("zcash_test_1", "zcash.test1.swap.mwc.mw:18353"),
					("zcash_test_2", "zcash.test1.swap.mwc.mw:18353"),
				]
				.iter()
				.cloned()
				.map(|i| (i.0.to_string(), i.1.to_string()))
				.collect::<BTreeMap<String, String>>(),
			),
			tx_fee_base: None,
		}
	}
}

impl WalletConfig {
	/// API Listen address
	pub fn api_listen_addr(&self) -> Option<String> {
		if self.api_listen_interface.is_some() && self.api_listen_port.is_some() {
			Some(format!(
				"{}:{}",
				self.api_listen_interface.clone().unwrap(),
				self.api_listen_port.clone().unwrap()
			))
		} else {
			None
		}
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
			.unwrap_or(MWC_WALLET_DIR.to_string())
	}

	/// Accept fee base
	pub fn tx_fee_base(&self, context_id: u32) -> u64 {
		self.tx_fee_base
			.unwrap_or_else(|| global::get_accept_fee_base(context_id))
	}
}

/// Error type wrapping config errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// Error with parsing of config file (file_name, message)
	#[error("Error parsing configuration file at {0}, {1}")]
	ParseError(String, String),

	/// Error with fileIO while reading config file
	/// (file_name, message)
	#[error("Config IO error, {0}")]
	FileIOError(#[from] io::Error),

	/// No file found (file_name)
	#[error("Configuration file not found: {0}")]
	FileNotFoundError(String),

	/// Error serializing config values
	#[error("Error serializing configuration, {0}")]
	SerializationError(String),

	/// Path doesn't exist
	#[error("Not found expected path {0}")]
	PathNotFoundError(String),

	/// Config mismatch
	#[error("Invalid config {0}")]
	InvalidConfig(String),
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
	/// Config file version (None == version 1)
	#[serde(default)]
	pub config_file_version: Option<u32>,
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

pub fn parse_node_address_string(input: String) -> Vec<String> {
	//parse the nodes address and put them in a vec
	let node_list: Vec<String> = input
		.split(";")
		.map(|s| s.to_string())
		.filter(|s| !s.is_empty())
		.collect();
	node_list
}
