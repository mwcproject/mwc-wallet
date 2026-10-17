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

use crate::cmd::wallet_args;
use mwc_wallet_config::GlobalWalletConfig;
use mwc_wallet_config::parse_node_address_string;
use mwc_wallet_impls::{DefaultLCProvider, HTTPNodeClient};
use mwc_wallet_libwallet::WalletInst;
use mwc_wallet_libwallet::types::bounded_escape_for_display;
use mwc_wallet_util::mwc_crates::clap::ArgMatches;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub(crate) const MIN_COMPAT_NODE_VERSION: &str = "6.0.0";
const MAX_COMMAND_ERROR_BYTES: usize = 4_096;

fn safe_command_error(error: &impl std::fmt::Display) -> String {
	let rendered = error.to_string();
	bounded_escape_for_display(&rendered, MAX_COMMAND_ERROR_BYTES)
}

pub fn wallet_command(
	context_id: u32,
	wallet_args: &ArgMatches<'_>,
	config: GlobalWalletConfig,
	mut node_client: HTTPNodeClient,
) -> i32 {
	// just get defaults from the global config
	let wallet_config = config.members.wallet;

	let tor_config = config.members.tor;
	let mqs_config = config.members.mqs;

	// Check the node version info, and exit with report if we're not compatible
	let global_wallet_args = match wallet_args::parse_global_args(&wallet_config, &wallet_args) {
		Ok(args) => args,
		Err(e) => {
			println!("Error. Can't read configuration file. {}", e);
			return 1;
		}
	};
	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());
	//parse the nodes address and put them in a vec
	let check_node_api_http_addr = match &wallet_config.check_node_api_http_addr {
		Some(s) => s.clone(),
		None => {
			println!("Error. Config wallet check_node_api_http_addr is not defined");
			return 1;
		}
	};

	let node_list = parse_node_address_string(check_node_api_http_addr);
	if let Err(e) = node_client.set_node_url(node_list) {
		println!("Error. Invalid node list. {}", e);
		return 1;
	}

	let res = wallet_args::wallet_command(
		context_id,
		wallet_args,
		wallet_config,
		tor_config,
		mqs_config,
		node_client,
		#[cfg(feature = "test-support")]
		false,
		|_: Arc<
			mwc_wallet_util::Mutex<
				Box<
					dyn WalletInst<
							'static,
							DefaultLCProvider<'static, HTTPNodeClient, _>,
							HTTPNodeClient,
							_,
						> + 'static,
				>,
			>,
		>| {},
	);

	// we need to give log output a chance to catch up before exiting
	thread::sleep(Duration::from_millis(100));

	if let Err(e) = res {
		println!("Wallet command failed: {}", safe_command_error(&e));
		1
	} else {
		println!(
			"Command '{}' completed successfully",
			wallet_args.subcommand().0
		);
		0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn command_error_rendering_is_bounded_and_terminal_safe() {
		let mut hostile = "before\n\u{1b}]52;c;payload\u{7}\u{2066}".to_owned();
		hostile.push_str(&"x".repeat(MAX_COMMAND_ERROR_BYTES * 2));
		let safe = safe_command_error(&hostile);

		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u2066"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{2066}'));
	}
}
