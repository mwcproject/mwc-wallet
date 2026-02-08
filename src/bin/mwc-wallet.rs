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

//! Main for building the binary of a Mwc Reference Wallet

#[macro_use]
extern crate clap;

extern crate mwc_wallet_util;
#[macro_use]
extern crate log;
use crate::config::ConfigError;
use crate::core::global;
use clap::{App, AppSettings};
use mwc_wallet_config as config;
use mwc_wallet_impls::HTTPNodeClient;
use mwc_wallet_util::{mwc_core as core, mwc_node_workflow};
use std::env;
use std::path::PathBuf;

use mwc_wallet::cmd;
use mwc_wallet_config::parse_node_address_string;
use mwc_wallet_util::mwc_util::logger::LoggingConfig;

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub fn info_strings() -> (String, String) {
	(
		format!(
			"This is MWC Wallet version {}{}, built for {} by {}.",
			built_info::PKG_VERSION,
			built_info::GIT_VERSION.map_or_else(|| "".to_owned(), |v| format!(" (git {})", v)),
			built_info::TARGET,
			built_info::RUSTC_VERSION,
		)
		.to_string(),
		format!(
			"Built with profile \"{}\", features \"{}\".",
			built_info::PROFILE,
			built_info::FEATURES_STR,
		)
		.to_string(),
	)
}

fn log_build_info() {
	let (basic_info, detailed_info) = info_strings();
	info!("{}", basic_info);
	debug!("{}", detailed_info);
}

fn main() {
	let exit_code = real_main();
	std::process::exit(exit_code);
}

fn real_main() -> i32 {
	let yml = load_yaml!("mwc-wallet.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.setting(AppSettings::VersionlessSubcommands)
		.get_matches();

	let chain_type = if args.is_present("floonet") {
		global::ChainTypes::Floonet
	} else if args.is_present("usernet") {
		global::ChainTypes::UserTesting
	} else {
		global::ChainTypes::Mainnet
	};

	let mut current_dir = None;
	let mut create_path = false;

	if args.is_present("top_level_dir") {
		let res = args.value_of("top_level_dir");
		match res {
			Some(d) => {
				current_dir = Some(PathBuf::from(d));
			}
			None => {
				warn!("Argument --top_level_dir needs a value. Defaulting to current directory")
			}
		}
	}

	// special cases for certain lifecycle commands
	match args.subcommand() {
		("init", Some(init_args)) => {
			if init_args.is_present("here") {
				current_dir = Some(env::current_dir().unwrap_or_else(|e| {
					panic!("Error creating config file: {}", e);
				}));
			}
			create_path = true;
		}
		_ => {}
	}

	// Load relevant config, try and load a wallet config file
	// Use defaults for configuration if config file not found anywhere
	let config = match config::initial_setup_wallet(&chain_type, current_dir, None, create_path) {
		Ok(c) => c,
		Err(e) => match e {
			ConfigError::PathNotFoundError(m) => {
				println!("Wallet configuration not found at {}. (Run `mwc-wallet init` to create a new wallet)", m);
				return 0;
			}
			m => {
				println!("Unable to load wallet configuration: {} (Run `mwc-wallet init` to create a new wallet)", m);
				return 0;
			}
		},
	};

	//config.members.as_mut().unwrap().wallet.chain_type = Some(chain_type);

	// Load logging config
	let mut l = config
		.members
		.logging
		.clone()
		.unwrap_or(LoggingConfig::default());
	// no logging to stdout if we're running cli
	match args.subcommand() {
		("cli", _) => l.log_to_stdout = true,
		_ => {}
	};
	let logs_rx = match mwc_node_workflow::logging::init_bin_logs(&l) {
		Ok(l) => l,
		Err(e) => {
			println!("Invalid logs configuration, {}", e);
			return 0;
		}
	};
	if logs_rx.is_some() {
		println!("Invalid logs configuration. Looks like config from node was used");
		return 0;
	}

	info!(
		"Using wallet configuration file at {}",
		config
			.config_file_path
			.as_ref()
			.map(|p| p.to_str())
			.flatten()
			.unwrap_or("<INVALID CONFIG FILE PATH>")
	);

	log_build_info();

	let context_id = match mwc_node_workflow::context::allocate_new_context(
		*config
			.members
			.wallet
			.chain_type
			.as_ref()
			.expect("Chain type in mwc-wallet.toml is not set!"),
		config.members.wallet.tx_fee_base.clone(),
		None,
	) {
		Ok(c_id) => c_id,
		Err(e) => {
			println!("Unable to allocate the context. {}", e);
			error!("Unable to allocate the context. {}", e);
			return -1;
		}
	};

	mwc_wallet_workflow::wallet::init_wallet_context(context_id);

	let wallet_config = config.clone().members.wallet;

	let check_node_api_http_addr = match &wallet_config.check_node_api_http_addr {
		Some(s) => s.clone(),
		None => {
			println!("Invalid wallet configuration. check_node_api_http_addr is not defined");
			return 0;
		}
	};

	//parse the nodes address and put them in a vec
	let node_list = parse_node_address_string(check_node_api_http_addr);
	let node_client = match HTTPNodeClient::new(context_id, node_list, None) {
		Ok(client) => client,
		Err(e) => {
			println!("Unable create HTTP client for mwc-node connection, {}", e);
			return 0;
		}
	};

	let res = cmd::wallet_command(context_id, &args, config, node_client);

	// stopping all threads if they exist. We need to be clean them. Currently it is context, enough to release
	mwc_wallet_workflow::wallet::release_wallet_context(context_id);
	let _ = mwc_node_workflow::context::release_context(context_id);

	res
}
