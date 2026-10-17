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

//! Comments for configuration + injection into output .toml
use crate::types::{ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers};
use mwc_wallet_util::mwc_crates::toml;
use std::collections::HashMap;

/// maps entries to Comments that should precede them
fn comments() -> HashMap<String, String> {
	let mut retval = HashMap::new();

	retval.insert(
		"config_file_version".to_string(),
		"
#Version of the Generated Configuration File for the Mwc Wallet (DO NOT EDIT)
"
		.to_string(),
	);

	retval.insert(
		"[wallet]".to_string(),
		"
#########################################
### WALLET CONFIGURATION              ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"[wallet]_END".to_string(),
		"#path of TLS certificate file, self-signed certificates are not supported
#tls_certificate_file = \"\"
#private key for the TLS certificate
#tls_certificate_key = \"\"

#host IP for wallet listener, change to \"0.0.0.0\" to receive mwc coins through http. Use 127.0.0.1 to listen on external tor service or some other proxy
#api_listen_interface = \"127.0.0.1\"

#port for wallet listener
#api_listen_port = 13415

#Additional source IP allowed to call the mining-only build_coinbase RPC.
#Loopback IPv4 and IPv6 addresses are always allowed. Built-in Tor connections are never allowed.
#IPv4 and IPv6 link-local addresses are rejected because their interface scope is ambiguous.
#A local reverse proxy is treated as a local client and must enforce its own equivalent restriction.
#mining_node_ip = \"127.0.0.1\"

# Minimum acceptable fee per unit of transaction weight. Please note that fee can't be lower than
# network has, otherwise your transactions will be rejected.
# If you are running fresh wallet, there is no needs to adjust this value.
# tx_fee_base = 1000
"
			.to_string(),
	);

	retval.insert(
		"owner_api_listen_port".to_string(),
		"
#port for wallet owner api
"
		.to_string(),
	);

	retval.insert(
		"api_secret_path".to_string(),
		"
#path of the secret token used by the API to authenticate the calls
#comment it to disable basic auth by explicit user choice
#WARNING: without this secret, every client that can reach the Owner API,
#including a browser origin able to reach loopback, can invoke state-changing
#Owner RPC methods. Only disable it when your deployment provides the access
#controls you consider appropriate (for example a trusted proxy, firewall,
#process isolation, or an otherwise restricted environment).
"
		.to_string(),
	);
	retval.insert(
		"check_node_api_http_addr".to_string(),
		"
#where the wallet should find a running node
"
		.to_string(),
	);
	retval.insert(
		"node_api_secret_path".to_string(),
		"
#location of the node api secret for basic auth on the Mwc API
"
		.to_string(),
	);
	retval.insert(
		"owner_api_include_foreign".to_string(),
		"
#include the foreign API endpoints on the same port as the owner
#API. Useful for networking environments like AWS ECS that make
#it difficult to access multiple ports on a single service.
"
		.to_string(),
	);
	retval.insert(
		"data_file_dir".to_string(),
		"
#where to find wallet files (seed, data, etc)
"
		.to_string(),
	);
	retval.insert(
		"dark_background_color_scheme".to_string(),
		"
#Whether to use the black background color scheme for command line
"
		.to_string(),
	);

	retval.insert(
		"eth_swap_contract_address".to_string(),
		"
#ethereum atomic swap contract address
"
		.to_string(),
	);
	retval.insert(
		"erc20_swap_contract_address".to_string(),
		"
#erc20 atomic swap contract address
"
		.to_string(),
	);
	retval.insert(
		"eth_infura_project_id".to_string(),
		"
#ethereum infura chain project id
"
		.to_string(),
	);
	retval.insert(
		"mwcbox_address_index".to_string(),
		"
# Address derive index. Every new index will give you a new address that will be used for
# communication with message queue server.
"
		.to_string(),
	);

	retval.insert(
		"[wallet.swap_electrumx_addr]".to_string(),
		"
# Electrum X servers that are used for Atomic Swap operations. Each Secondary Currency need
# its own dedicated Electrum X instance. We highly advise to use your own instance, instead of
# using those community servers.
# For every secondary currency expected 4 instances:
# mainnet primary, mainnet secondary, testnet primary, testnet secondary,
# Key: <coin>_[main|test]_[1|2]
# value: URI
"
		.to_string(),
	);
	retval.insert(
		"[logging]".to_string(),
		"
#########################################
### LOGGING CONFIGURATION             ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"log_to_stdout".to_string(),
		"
#whether to log to stdout
"
		.to_string(),
	);

	retval.insert(
		"stdout_log_level".to_string(),
		"
#log level for stdout: Error, Warning, Info, Debug, Trace
"
		.to_string(),
	);

	retval.insert(
		"log_to_file".to_string(),
		"
#whether to log to a file
"
		.to_string(),
	);

	retval.insert(
		"file_log_level".to_string(),
		"
#log level for file: Error, Warning, Info, Debug, Trace
"
		.to_string(),
	);

	retval.insert(
		"log_file_path".to_string(),
		"
#log file path
"
		.to_string(),
	);

	retval.insert(
		"log_file_append".to_string(),
		"
#whether to append to the log file (true), or replace it on every run (false)
"
		.to_string(),
	);

	retval.insert(
		"log_max_size".to_string(),
		"
#maximum log file size in bytes before performing log rotation
#comment it to disable log rotation
"
		.to_string(),
	);

	retval.insert(
		"log_max_files".to_string(),
		"
#Maximum log files in rotation
"
		.to_string(),
	);

	retval.insert(
		"[tor]".to_string(),
		"
#########################################
### TOR CONFIGURATION                 ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"[tor]_END".to_string(),
		format!(
			"#Enable tor for http method listening. Default is true
#tor_enabled = true

{}",
			mwc_wallet_util::mwc_config::TOR_CONFIG_COMMENTS
		),
	);

	retval.insert(
		"socks_proxy_addr".to_string(),
		"
#Address of the running TOR (SOCKS) server
"
		.to_string(),
	);

	retval.insert(
		"[mqs]".to_string(),
		"
#########################################
### MWCMQS CONFIGURATION              ###
#########################################
"
		.to_string(),
	);

	retval.insert(
		"mwcmqs_domain".to_string(),
		"
#mqs server domain
"
		.to_string(),
	);

	retval.insert(
		"mwcmqs_port".to_string(),
		"
#mqs server port
"
		.to_string(),
	);

	retval
}

fn get_key(line: &str) -> String {
	let line = line.trim();
	if line.starts_with('[') && line.ends_with(']') {
		line.to_owned()
	} else if let Some((key, _)) = line.split_once('=') {
		key.trim().to_owned()
	} else {
		"NOT_FOUND".to_owned()
	}
}

pub fn insert_comments(orig: String) -> String {
	let comments = comments();
	let lines: Vec<&str> = orig.split('\n').collect();
	let mut out_lines = vec![];
	let mut section_ended_comments = None;

	for l in lines {
		let key = get_key(l);

		if key.starts_with('[') {
			if let Some(ln) = section_ended_comments {
				out_lines.push(ln);
				out_lines.push("\n".to_owned());
			}

			let end_key = key.clone() + "_END";
			section_ended_comments = comments.get(&end_key).map(|s| s.clone());
		}

		if let Some(v) = comments.get(&key) {
			out_lines.push(v.to_owned());
		}
		out_lines.push(l.to_owned());
		out_lines.push("\n".to_owned());
	}

	if let Some(ln) = section_ended_comments {
		out_lines.push(ln);
		out_lines.push("\n".to_owned());
	}

	let mut ret_val = String::from("");
	for l in out_lines {
		ret_val.push_str(&l);
	}
	ret_val
}

/// Merge the comments of `old_config` into `new_config`.
///
/// The merged document is validated before it is returned: it must parse as
/// a GlobalWalletConfigMembers and no user-configured value may be lost or
/// altered (see migration_preserves_members). On any validation failure an
/// error is returned so the caller leaves the original config file untouched.
///
/// # Limitations (accepted)
///
/// The merge is intentionally line-based: `get_key` classifies every
/// non-comment line as a table header, a `key = value` line or `NOT_FOUND`,
/// and only recognized key lines are re-emitted. Multiline TOML constructs
/// (`"""` / `'''` strings, arrays spanning several lines) are not supported:
/// their continuation lines are silently dropped or misread as keys, which
/// can alter such a value. The validation does not detect this for a newly
/// introduced section either, because an absent optional section (`None`) is
/// allowed to become populated (see migration_preserves_members).
///
/// This is accepted by design: the wallet configuration is a simple document
/// of single-line `key = value` entries, and we deliberately keep processing
/// it on a line-by-line basis instead of maintaining a full TOML document
/// model.
pub fn migrate_comments(
	old_config: String,
	new_config: String,
	old_version: Option<u32>,
) -> Result<String, ConfigError> {
	// Normalize legacy log level values so the equivalence check below does
	// not trip over the intentional Warning -> WARN migration.
	let old_config = GlobalWalletConfig::fix_warning_level(old_config);
	let comments = comments();
	// Prohibe the key we are basing on to introduce new comments for [tor.proxy]
	let prohibited_key = match old_version {
		None => vec!["[logging]"],
		Some(_) => vec![],
	};
	let mut vec_old_conf = vec![];
	let mut hm_key_cmt_old = HashMap::new();
	let old_conf: Vec<&str> = old_config.split_inclusive('\n').collect();
	// collect old key in a vec and insert old key/comments from the old conf in a hashmap
	let vec_key_old = old_conf
		.iter()
		.filter_map(|line| {
			let line_nospace = line.trim();
			let is_ascii_control = line_nospace.chars().all(|x| x.is_ascii_control());
			match line.trim_start().starts_with('#') || is_ascii_control {
				true => {
					vec_old_conf.push(line.to_owned());
					None
				}
				false => {
					let comments: String =
						vec_old_conf.iter().map(|s| s.chars()).flatten().collect();
					let key = get_key(line_nospace);
					match !(key == "NOT_FOUND") {
						true => {
							vec_old_conf.clear();
							hm_key_cmt_old.insert(key.clone(), comments);
							Some(key)
						}
						false => None,
					}
				}
			}
		})
		.collect::<Vec<String>>();

	let new_conf: Vec<&str> = new_config.split_inclusive('\n').collect();
	// collect new key and the whole key line from the new config
	let vec_key_cmt_new = new_conf
		.iter()
		.filter_map(|line| {
			let line_nospace = line.trim();
			let is_ascii_control = line_nospace.chars().all(|x| x.is_ascii_control());
			match !(line.trim_start().starts_with('#') || is_ascii_control) {
				true => {
					let key = get_key(line_nospace);
					match !(key == "NOT_FOUND") {
						true => Some((key, line_nospace.to_string())),
						false => None,
					}
				}
				false => None,
			}
		})
		.collect::<Vec<(String, String)>>();

	let mut new_config_str = String::from("");
	// Merging old comments in the new config (except if the key is contained in the prohibited vec) with all new introduced key comments
	for (key, key_line) in vec_key_cmt_new {
		// Linear scan over all old keys, so the merge is O(n*m) in the number
		// of config keys. Accepted: migration is a one-time job per config
		// file and the number of keys is small, so maintaining a HashSet
		// index is not worth the extra code.
		let old_key_exist = vec_key_old.iter().any(|old_key| *old_key == key);
		let key_fmt = format!("{}\n", key_line);
		if old_key_exist {
			if prohibited_key.contains(&key.as_str()) {
				// push new config comments
				if let Some(value) = comments.get(&key) {
					new_config_str.push_str(value);
				}
			} else {
				// push old config comments
				if let Some(value) = hm_key_cmt_old.get(&key) {
					new_config_str.push_str(value);
				}
			}
		} else {
			// old key does not exist, we push new comments when available
			if let Some(value) = comments.get(&key) {
				new_config_str.push_str(value);
			}
		}
		// Comments are optional metadata. The new configuration key is not.
		new_config_str.push_str(&key_fmt);
	}

	// Equivalence check, mirroring mwc-node's config migration: the merged
	// document must parse, and no value the wallet actually uses may be lost
	// or altered. A migration may legitimately change the file — it adds the
	// config_file_version stamp, introduces new sections (e.g. tor), and keys
	// unknown to GlobalWalletConfigMembers (obsolete or foreign keys) are
	// dropped by deserialization. What must never happen is a user-set value
	// being silently altered or dropped before the original file is replaced.
	let old_members: GlobalWalletConfigMembers = toml::from_str(&old_config).map_err(|e| {
		ConfigError::SerializationError(format!(
			"Internal error, unable to parse the original config: {}",
			e
		))
	})?;
	let merged_members: GlobalWalletConfigMembers =
		toml::from_str(&new_config_str).map_err(|e| {
			ConfigError::SerializationError(format!(
				"Internal error, migrated config is not valid TOML: {}",
				e
			))
		})?;
	if !migration_preserves_members(&old_members, &merged_members) {
		return Err(ConfigError::InvalidConfig(
			"Internal error, config migration would lose existing settings".into(),
		));
	}
	Ok(new_config_str)
}

/// Check that no user-configured value was lost or altered by the migration.
/// A section that was not set (`None`) may be populated with defaults, but a
/// configured section must survive unchanged. Keys unknown to
/// GlobalWalletConfigMembers are not visible here; they are dropped by
/// deserialization, which is how obsolete keys are retired.
///
/// Note that accepting any content for a previously absent (`None`) section
/// also means that a value garbled by the line-based merge inside a newly
/// introduced section is not detected here. That limitation is accepted; see
/// the `migrate_comments` documentation.
fn migration_preserves_members(
	old: &GlobalWalletConfigMembers,
	merged: &GlobalWalletConfigMembers,
) -> bool {
	fn preserved<T: PartialEq>(old: &Option<T>, merged: &Option<T>) -> bool {
		old.is_none() || old == merged
	}
	old.wallet == merged.wallet
		&& preserved(&old.config_file_version, &merged.config_file_version)
		&& preserved(&old.logging, &merged.logging)
		&& preserved(&old.tor, &merged.tor)
		&& preserved(&old.mqs, &merged.mqs)
}

#[cfg(test)]
mod tests {
	use super::{get_key, migrate_comments};
	use mwc_wallet_util::mwc_crates::toml;

	#[test]
	fn get_key_distinguishes_table_headers_from_brackets_in_values() {
		assert_eq!(get_key("[wallet]"), "[wallet]");
		assert_eq!(get_key("[[wallet.nodes]]"), "[[wallet.nodes]]");
		assert_eq!(
			get_key(r#"api_secret_path = ".secrets/[owner]""#),
			"api_secret_path"
		);
		assert_eq!(
			get_key(r#"api_listen_interface = "[::1]""#),
			"api_listen_interface"
		);
		assert_eq!(get_key(r#"nodes = ["node1", "node2"]"#), "nodes");
	}

	#[test]
	fn migration_preserves_assignment_with_brackets_when_formatting_changes() {
		let old_config =
			"[wallet]\napi_secret_path='.secrets/[owner]'\ndata_file_dir = \".\"\n".to_owned();
		let new_config =
			"[wallet]\napi_secret_path = \".secrets/[owner]\"\ndata_file_dir = \".\"\n".to_owned();

		let migrated =
			migrate_comments(old_config, new_config, Some(1)).expect("migration must succeed");
		let parsed: toml::Value =
			toml::from_str(&migrated).expect("migrated configuration must remain valid TOML");

		assert_eq!(
			parsed
				.get("wallet")
				.and_then(toml::Value::as_table)
				.and_then(|wallet| wallet.get("api_secret_path"))
				.and_then(toml::Value::as_str),
			Some(".secrets/[owner]")
		);
	}

	#[test]
	fn migration_preserves_hash_inside_quoted_value_before_logging() {
		let old_config = "[wallet]\napi_secret_path = \"secret#file\"\ndata_file_dir = \".\"\n\
		                  [logging]\nlog_to_stdout = true\nstdout_log_level = \"WARN\"\n\
		                  log_to_file = true\nfile_log_level = \"Info\"\n\
		                  log_file_path = \"mwc-wallet.log\"\nlog_file_append = true\n"
			.to_owned();
		let new_config = old_config.clone();

		let migrated =
			migrate_comments(old_config, new_config, None).expect("migration must succeed");
		let parsed: toml::Value =
			toml::from_str(&migrated).expect("migrated configuration must remain valid TOML");

		assert_eq!(
			parsed
				.get("wallet")
				.and_then(toml::Value::as_table)
				.and_then(|wallet| wallet.get("api_secret_path"))
				.and_then(toml::Value::as_str),
			Some("secret#file")
		);
	}

	#[test]
	fn migration_keeps_assignment_with_inline_comment() {
		let old_config = "[wallet]\n\
		                  api_secret_path = \"old#secret\" # keep this comment\n\
		                  data_file_dir = \".\"\n"
			.to_owned();
		let new_config = "[wallet]\n\
		                  api_secret_path = \"old#secret\"\n\
		                  data_file_dir = \".\"\n"
			.to_owned();

		let migrated =
			migrate_comments(old_config, new_config, Some(1)).expect("migration must succeed");
		let parsed: toml::Value =
			toml::from_str(&migrated).expect("migrated configuration must remain valid TOML");

		assert_eq!(
			parsed
				.get("wallet")
				.and_then(toml::Value::as_table)
				.and_then(|wallet| wallet.get("api_secret_path"))
				.and_then(toml::Value::as_str),
			Some("old#secret")
		);
	}

	#[test]
	fn migration_emits_keys_without_default_comments() {
		// chain_type and owner_api_include_mqs_listener have no entry in the
		// comments map; the key lines must still be emitted.
		let old_config = "[wallet]\n\
		                  chain_type = \"Mainnet\"\n\
		                  owner_api_include_mqs_listener = false\n\
		                  data_file_dir = \".\"\n"
			.to_owned();
		let new_config = old_config.clone();

		let migrated =
			migrate_comments(old_config, new_config, Some(1)).expect("migration must succeed");
		let parsed: toml::Value =
			toml::from_str(&migrated).expect("migrated configuration must remain valid TOML");
		let wallet = parsed
			.get("wallet")
			.and_then(toml::Value::as_table)
			.expect("wallet table must be present");

		assert_eq!(
			wallet.get("chain_type").and_then(toml::Value::as_str),
			Some("Mainnet")
		);
		assert_eq!(
			wallet
				.get("owner_api_include_mqs_listener")
				.and_then(toml::Value::as_bool),
			Some(false)
		);
	}

	#[test]
	fn migration_rejects_new_config_that_alters_existing_values() {
		let old_config =
			"[wallet]\napi_secret_path = \".secrets/owner\"\ndata_file_dir = \".\"\n".to_owned();
		let new_config =
			"[wallet]\napi_secret_path = \".other/path\"\ndata_file_dir = \".\"\n".to_owned();

		assert!(migrate_comments(old_config, new_config, Some(1)).is_err());
	}

	#[test]
	fn migration_rejects_new_config_that_drops_existing_keys() {
		let old_config =
			"[wallet]\napi_secret_path = \".secrets/owner\"\ndata_file_dir = \".\"\n".to_owned();
		let new_config = "[wallet]\ndata_file_dir = \".\"\n".to_owned();

		assert!(migrate_comments(old_config, new_config, Some(1)).is_err());
	}

	#[test]
	fn migration_allows_introducing_new_sections() {
		// Migration may populate a section that was absent (None -> Some).
		let old_config = "[wallet]\ndata_file_dir = \".\"\n".to_owned();
		let new_config = "[wallet]\ndata_file_dir = \".\"\n\
		                  [mqs]\nmwcmqs_domain = \"mqs.mwc.mw\"\nmwcmqs_port = 443\n"
			.to_owned();

		migrate_comments(old_config, new_config, None).expect("migration must succeed");
	}

	#[test]
	fn migration_tolerates_keys_unknown_to_the_config_struct() {
		// Obsolete or foreign keys are dropped by deserialization (same as
		// mwc-node); they must not block the migration.
		let old_config = "[wallet]\ndata_file_dir = \".\"\nobsolete_key = 1\n".to_owned();
		let new_config = "[wallet]\ndata_file_dir = \".\"\n".to_owned();

		migrate_comments(old_config, new_config, Some(1)).expect("migration must succeed");
	}

	#[test]
	fn migration_rejects_changes_to_a_configured_optional_section() {
		// A configured section (Some) must survive the migration unchanged.
		let old_config = "[wallet]\ndata_file_dir = \".\"\n\
		                  [mqs]\nmwcmqs_domain = \"mqs.mwc.mw\"\nmwcmqs_port = 443\n"
			.to_owned();
		let new_config = "[wallet]\ndata_file_dir = \".\"\n\
		                  [mqs]\nmwcmqs_domain = \"other.mwc.mw\"\nmwcmqs_port = 443\n"
			.to_owned();

		assert!(migrate_comments(old_config, new_config, Some(1)).is_err());
	}
}
