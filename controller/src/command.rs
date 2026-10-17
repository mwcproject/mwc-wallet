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

//! Mwc wallet command-line function implementations

use crate::error::Error;
use crate::{controller, display};
use mwc_wallet_api::{Owner, StoredTxLocator};
use mwc_wallet_config::{MQSConfig, WALLET_CONFIG_FILE_NAME, WalletConfig};
#[cfg(feature = "swaps")]
use mwc_wallet_impls::HttpDataSender;
#[cfg(feature = "swaps")]
use mwc_wallet_impls::adapters::MarketplaceMessageSender;
#[cfg(feature = "swaps")]
use mwc_wallet_impls::adapters::create_swap_message_sender;
#[cfg(feature = "swaps")]
use mwc_wallet_impls::adapters::validate_tor_address;
#[cfg(feature = "swaps")]
use mwc_wallet_impls::tor;
#[cfg(feature = "swaps")]
use mwc_wallet_impls::{Address, MWCMQSAddress, Publisher};
use mwc_wallet_impls::{PathToSlateGetter, PathToSlatePutter, SlatePutter};
use mwc_wallet_impls::{SlateGetter, create_sender};
use mwc_wallet_libwallet::api_impl::owner;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::api_impl::{owner_eth, owner_swap};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::types::Currency;
use mwc_wallet_libwallet::{
	ChainTip, InitTxArgs, IssueInvoiceTxArgs, NodeClient, WalletLCProvider,
};
use mwc_wallet_util::mwc_api::TLSConfig;
use mwc_wallet_util::mwc_core::{core, global};
#[cfg(feature = "swaps")]
use mwc_wallet_util::mwc_crates::chrono::Utc;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_util::{ZeroingString, file, is_console_output_enabled};

use mwc_wallet_libwallet::proof::proofaddress::{self, ProvableAddress};
use mwc_wallet_libwallet::proof::tx_proof::{TxProof, remove_proof_for_slate};
use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::slate_versions::v2::TransactionV2;
use mwc_wallet_libwallet::slate_versions::v3::{TransactionV3, sig_is_blank};
use mwc_wallet_libwallet::slatepack::{SlatePurpose, validate_slatepack_receive_direction};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::fsm::state::StateId;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::trades;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::types::Action;
use mwc_wallet_libwallet::types::{
	TxSession, U64_DATA_IDX_ADDRESS_INDEX, bounded_escape_for_display, escape_for_display,
};
use mwc_wallet_libwallet::{OwnershipProof, Slate, TxLogEntry, WalletInst, wallet_lock};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::file::replace_owner_only_file_with;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_crates::log::{error, info, warn};
use mwc_wallet_util::mwc_crates::qr_code::{EcLevel, QrCode};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_p2p::tor::arti::{is_arti_started, start_arti};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::Read;
#[cfg(feature = "swaps")]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: Option<String>,
	pub api_secret: Option<Zeroizing<String>>,
	pub node_api_secret: Option<Zeroizing<String>>,
	pub password: Option<ZeroingString>,
	pub tls_conf: Option<TLSConfig>,
}

/// Arguments for init command
pub struct InitArgs {
	/// BIP39 recovery phrase length
	pub list_length: usize,
	pub password: ZeroingString,
	pub config: WalletConfig,
	pub recovery_phrase: Option<ZeroingString>,
	pub restore: bool,
}

pub fn init<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_g_args: &GlobalArgs,
	args: InitArgs,
	wallet_data_dir: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;

	// Assume global chain type has already been initialized.
	let chain_type = global::get_chain_type(p.get_context_id());
	p.create_config(&chain_type, WALLET_CONFIG_FILE_NAME, None, None, None, None)?;
	let _ = p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		#[cfg(feature = "test-support")]
		false,
		wallet_data_dir.clone(),
		true,
	)?;

	Ok(())
}

/// Argument for recover
pub struct RecoverArgs {
	pub passphrase: ZeroingString,
}

pub fn recover<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	args: RecoverArgs,
	wallet_data_dir: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	let m = p.get_mnemonic(None, args.passphrase, wallet_data_dir)?;
	mwc_wallet_impls::lifecycle::show_recovery_phrase(m);
	Ok(())
}

pub fn rewind_hash<'a, L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	short_output: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let rewind_hash = api.get_rewind_hash(m)?;
		if short_output {
			println!("Wallet Rewind Hash: {}", &*rewind_hash);
		} else {
			println!();
			println!("Wallet Rewind Hash");
			println!("-------------------------------------");
			println!("{}", &*rewind_hash);
			println!(
				"Warning: this is a viewing credential; rewind matches are not proof of spend ownership."
			);
			println!();
		}
		Ok(())
	})?;
	Ok(())
}

/// Arguments for generate_ownership_proof command
pub struct GenerateOwnershipProofArgs {
	/// Message to sign
	pub message: String,
	/// does need to include public root key
	pub include_public_root_key: bool,
	/// does need to include tor address
	pub include_tor_address: bool,
	/// does need to include MQS address
	pub include_mqs_address: bool,
}

pub fn generate_ownership_proof<'a, L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: GenerateOwnershipProofArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let proof = api.retrieve_ownership_proof(
			m,
			args.message,
			args.include_public_root_key,
			args.include_tor_address,
			args.include_mqs_address,
		)?;

		let proof_json = serde_json::to_string(&proof).map_err(|e| {
			Error::GenericError(format!("Failed convert proof result into json, {}", e))
		})?;

		println!("Ownership Proof: {}", proof_json);
		Ok(())
	})?;
	Ok(())
}

pub fn validate_ownership_proof<'a, L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	proof: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let proof = serde_json::from_str::<OwnershipProof>(proof).map_err(|e| {
			Error::ArgumentError(format!("Unable to decode proof from json, {}", e))
		})?;

		let validation = api.validate_ownership_proof(proof)?;
		println!("Network: {}", validation.network);
		// The signed message is untrusted text. Debug formatting quotes it and
		// escapes newlines and terminal control characters before console output.
		println!("Message: {:?}", validation.message);
		let viewing_key_present = validation.viewing_key.is_some();
		println!(
			"Rewind-Only Viewing Key: {}",
			validation.viewing_key.unwrap_or("Not provided".to_string())
		);
		if viewing_key_present {
			println!(
				"Viewing Key Warning: rewind matches are not proof of spend ownership."
			);
		}
		println!(
			"Tor Address: {}",
			validation.tor_address.unwrap_or("Not provided".to_string())
		);
		println!(
			"MWCMQS Address: {}",
			validation.mqs_address.unwrap_or("Not provided".to_string())
		);
		Ok(())
	})?;
	Ok(())
}

/// Arguments for rewind hash view wallet scan command
pub struct ViewWalletScanArgs {
	pub rewind_hash: Zeroizing<String>,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

pub fn scan_rewind_hash<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	args: ViewWalletScanArgs,
	dark_scheme: bool,
	show_progress: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, None, Some(owner_api), |api, m| {
		let rewind_hash = args.rewind_hash;
		{
			wallet_lock!(api.wallet_inst, w);
			w.w2n_client().reset_cache();
		}
		let node_height = api.node_height(m)?;
		if !node_height.updated_from_node {
			return Err(Error::GenericError(
				"Unable to retrieve chain height from node; view wallet scan requires a reachable node"
					.to_owned(),
			));
		}
		let tip_height = node_height.height;
		let tip = ChainTip {
			height: tip_height,
			hash: node_height.header_hash,
		};
		let start_height = match args.backwards_from_tip {
			// A lookback beyond genesis intentionally starts the scan at genesis.
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!(
			"Starting rewind-hash view scan from height {} ...",
			start_height
		);

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;

		let result = owner::scan_rewind_hash_with_anchor(
			api.wallet_inst.clone(),
			&mut secp,
			rewind_hash,
			Some(start_height),
			tip,
			None,
		);

		// Status-channel progress reporting was removed; `show_progress` now
		// only selects the machine-parseable output format.
		if show_progress {
			// Printing for parser
			match result {
				Ok(res) => {
					println!("View wallet check complete");
					for m in res.output_result {
						println!(
							"ViewOutput: {},{},{},{},{},{},{}",
							m.commit,
							m.mmr_index,
							m.height,
							m.lock_height,
							m.is_coinbase,
							m.num_confirmations(tip_height),
							m.value
						);
					}
					println!("ViewTotal: {}", res.total_balance);
					Ok(())
				}
				Err(e) => {
					println!(
						"View wallet check failed: {}",
						safe_scan_error(&e)
					);
					Err(e.into())
				}
			}
		} else {
			// nice printing
			match result {
				Ok(res) => {
					warn!(
						"Rewind-hash view scan complete; results are not proof of spend ownership"
					);
					if res.total_balance != 0 {
						display::view_wallet_output(&res, tip_height, dark_scheme)?;
					}
					display::view_wallet_balance(&res, tip_height, dark_scheme);
					Ok(())
				}
				Err(e) => {
					error!(
						"View wallet check failed: {}",
						safe_scan_error(&e)
					);
					Err(e.into())
				}
			}
		}
	})?;
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {
	pub method: String,
	pub enable_secondary_socket_listener: bool,
}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	args: &ListenArgs,
	cli_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	match args.method.as_str() {
		"http" => {
			if tor_config.need_start_arti() {
				// We might need to bootstrap tor if it is a first run
				if !is_arti_started() {
					start_arti(
						tor_config,
						std::path::Path::new(&config.data_file_dir),
						true,
						false,
					)
					.map_err(|e| {
						error!("Unable to start TOR core, {}", e);
						Error::from(Error::ListenerError(format!(
							"Unable to start TOR core, {}",
							e
						)))
					})?;
				}
			}

			let foreign_server = controller::foreign_listener(
				owner_api.wallet_inst.clone(),
				keychain_mask,
				config.api_listen_addr(),
				tor_config,
				args.enable_secondary_socket_listener,
				config.mining_node_ip,
			)?;

			if !cli_mode {
				let secondary_required =
					args.enable_secondary_socket_listener && tor_config.is_tor_enabled();
				foreign_server
					.wait_for_listeners(secondary_required)
					.map_err(Error::ListenerError)?;
			}
			// Here we can drop the api_thread because foreign listener has it's own stopper, so
			// resources will not leak. foreign listener is a part of the context (context_id)
		}

		"mwcmqs" => {
			let wallet_inst = owner_api.wallet_inst.clone();
			controller::init_start_mwcmqs_listener(
				wallet_inst,
				mqs_config.clone(),
				keychain_mask,
				!cli_mode,
			)
			.map_err(|e| {
				error!("Unable to start mwcmqs listener, {}", e);
				Error::from(Error::ListenerError(format!(
					"Unable to start mwcmqs listener, {}",
					e
				)))
			})?;
		}
		method => {
			return Err(Error::ArgumentError(format!(
				"No listener for method '{}'",
				method
			)));
		}
	};
	Ok(())
}

struct OwnerMqsCleanup(Option<controller::MqsListenerInstance>);

impl Drop for OwnerMqsCleanup {
	fn drop(&mut self) {
		if let Some(instance) = self.0.take() {
			if let Err(e) = mwc_wallet_impls::stop_mwcmqs_brocker_if_current(
				instance.context_id,
				instance.instance_id,
			) {
				error!("Unable to stop Owner API MWCMQS listener: {}", e);
			}
		}
	}
}

pub fn owner_api<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<SecretKey>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	g_args: &GlobalArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	// keychain mask needs to be a sinlge instance, in case the foreign API is
	// also being run at the same time
	let km = Arc::new(Mutex::new(keychain_mask));

	// Starting MQS first
	let mut mqs_cleanup = OwnerMqsCleanup(None);
	if config.owner_api_include_mqs_listener.unwrap_or(false) {
		mqs_cleanup.0 = Some(controller::init_start_mwcmqs_listener(
			owner_api.wallet_inst.clone(),
			mqs_config.clone(),
			km.clone(),
			false,
			//None,
		)?);
	}

	// Now Owner API
	controller::owner_listener(
		owner_api.wallet_inst.clone(),
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign,
		Some(tor_config.clone()),
	)
	.map_err(|e| Error::LibWallet(format!("Unable to start Listener, {}", e)))?;
	Ok(())
}

/// Arguments for account command
pub struct AccountArgs {
	pub create: Option<String>,
}

pub fn account<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: AccountArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	match args.create {
		None => {
			let res =
				controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
					let acct_mappings = api.accounts(m)?;
					// give logging thread a moment to catch up
					thread::sleep(Duration::from_millis(200));
					display::accounts(acct_mappings);
					Ok(())
				});
			if let Err(e) = res {
				let err_str = format!("Error listing accounts: {}", e);
				error!("{}", err_str);
				return Err(Error::LibWallet(err_str));
			}
		}
		Some(label) => {
			let res =
				controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
					api.create_account_path(m, &label)?;
					thread::sleep(Duration::from_millis(200));
					info!("Account: '{}' Created!", label);
					Ok(())
				});
			if let Err(e) = res {
				thread::sleep(Duration::from_millis(200));
				let err_str = format!("Error creating account '{}': {}", label, e);
				error!("{}", err_str);
				return Err(Error::LibWallet(err_str));
			}
		}
	}
	Ok(())
}

/// Arguments for the send command
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct SendArgs {
	pub amount: u64,
	pub amount_includes_fee: bool,
	pub use_max_amount: bool,
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub method: String,
	pub dest: String,
	/// Apisecret of the receiving wallet, for http(s) sends. Zeroized on drop.
	#[serde(default)]
	pub apisecret: Option<Zeroizing<String>>,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<ProvableAddress>,
	pub ttl_blocks: Option<u64>,
	pub exclude_change_outputs: bool,
	pub minimum_confirmations_change_outputs: u64,
	pub address: Option<String>,          //this is only for file proof.
	pub outputs: Option<HashSet<String>>, // Outputs to use. If None, all outputs can be used
	pub slatepack_recipient: Option<ProvableAddress>, // Destination for slatepack. The address will be the same as for payment_proof_address. The role is different.
	pub late_lock: bool,
	pub min_fee: Option<u64>,
	pub slatepack_qr: bool,
}

const SLATEPACK_SLATE_VERSION: u16 = 4;

fn effective_send_target_slate_version(
	method: &str,
	has_explicit_slatepack_recipient: bool,
	requested_version: Option<u16>,
) -> Option<u16> {
	if method == "http" && has_explicit_slatepack_recipient {
		Some(
			requested_version
				.unwrap_or(SLATEPACK_SLATE_VERSION)
				.max(SLATEPACK_SLATE_VERSION),
		)
	} else {
		requested_version
	}
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	mqs_config: Option<MQSConfig>,
	args: SendArgs,
	dark_scheme: bool,
) -> Result<Option<Uuid>, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut amount = args.amount;
	if args.use_max_amount {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let (validated, wallet_info) =
				api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
			// The API permits Ok(false) when a requested refresh cannot validate
			// against the node. Never derive the maximum
			// send amount from unvalidated, potentially stale wallet state.
			if !validated {
				return Err(Error::GenericError(
					"Unable to validate wallet state against the node, cannot compute the maximum spendable amount"
						.to_string(),
				));
			}
			amount = wallet_info.amount_currently_spendable;
			Ok(())
		})?;
	};

	let wallet_inst = owner_api.wallet_inst.clone();

	let res_tx_uuid =
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let mut res_tx_uuid: Option<Uuid> = None;
			if args.estimate_selection_strategies {
				let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
				for strategy in vec!["smallest", "all"] {
					let init_args = InitTxArgs {
						src_acct_name: None,
						amount: amount,
						amount_includes_fee: Some(args.amount_includes_fee),
						minimum_confirmations: args.minimum_confirmations,
						max_outputs: args.max_outputs,
						num_change_outputs: args.change_outputs,
						selection_strategy_is_use_all: strategy == "all",
						estimate_only: Some(true),
						exclude_change_outputs: Some(args.exclude_change_outputs),
						minimum_confirmations_change_outputs: args
							.minimum_confirmations_change_outputs,
						address: args.address.clone(),
						outputs: args.outputs.clone(),
						min_fee: args.min_fee,
						..Default::default()
					};
					let slate = api.init_send_tx(m, None, &init_args, 1)?;
					strategies.push((strategy, slate.amount, slate.fee));
				}
				display::estimate(amount, strategies, dark_scheme);
			} else {
				// dp_proof is used for MQS message exchange. Sisne MQS has both addresses, proof can be generated for avery transaction
				let do_proof = args.payment_proof_address.is_some();
				let mut init_args = InitTxArgs {
					src_acct_name: None,
					amount: amount,
					amount_includes_fee: Some(args.amount_includes_fee),
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs,
					num_change_outputs: args.change_outputs,
					selection_strategy_is_use_all: args.selection_strategy == "all",
					message: args.message.clone(),
					// An explicit HTTP Slatepack recipient is a security
					// requirement, not a format preference. Force compact slate
					// construction before the unauthenticated peer version
					// response is considered. The HTTP adapter will reject peers
					// that cannot complete the exchange as Slatepack.
					target_slate_version: effective_send_target_slate_version(
						&args.method,
						args.slatepack_recipient.is_some(),
						args.target_slate_version,
					),
					payment_proof_recipient_address: args.payment_proof_address.clone(),
					address: args.address.clone(),
					ttl_blocks: args.ttl_blocks,
					send_args: None,
					exclude_change_outputs: Some(args.exclude_change_outputs),
					minimum_confirmations_change_outputs: args.minimum_confirmations_change_outputs,
					outputs: args.outputs.clone(),
					late_lock: Some(args.late_lock),
					min_fee: args.min_fee,
					..Default::default()
				};

				let (context_id, data_directory) = {
					wallet_lock!(api.wallet_inst, w);
					(w.get_context_id(), w.get_data_file_dir().to_string())
				};

				//if it is mwcmqs, start listner first.
				match args.method.as_str() {
					"mwcmqs" => {
						if mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).is_none() {
							//check to see if mqs_config is there, if not, return error
							let mqs_config_unwrapped;
							match mqs_config {
								Some(s) => {
									mqs_config_unwrapped = s;
								}
								None => {
									return Err(Error::MQSConfig(format!("NO MQS config!")));
								}
							}

							let km = keychain_mask.map(|k| k.clone());

							//start the listener finalize tx
							controller::init_start_mwcmqs_listener(
								wallet_inst.clone(),
								mqs_config_unwrapped,
								Arc::new(Mutex::new(km)),
								false,
								//None,
							)?;
							thread::sleep(Duration::from_millis(2000));
						}
					}
					"slatepack" => {
						// Using at least 4 slate version for slatepacks
						init_args.target_slate_version = Some(std::cmp::max(
							4,
							init_args.target_slate_version.unwrap_or(4),
						));
					}
					_ => {}
				}

				// Creating sender because we need to request other wallet version first
				let sender_info = match args.method.as_str() {
					"http" | "mwcmqs" => {
						let sender = create_sender(
							context_id,
							&args.method,
							&args.dest,
							&args.apisecret.as_ref().map(|s| Arc::new(s.clone())),
							tor_config.as_ref(),
							Path::new(&data_directory),
						)?;
						let other_wallet_version =
							sender.check_other_wallet_version(&args.dest, true)?;
						if let Some(other_wallet_version) = &other_wallet_version {
							if init_args.target_slate_version.is_none() {
								// to_numeric_version() as u16 is safe because to_numeric_version return values are small
								init_args.target_slate_version =
									Some(other_wallet_version.0.to_numeric_version() as u16);
							}
						}
						Some((sender, other_wallet_version))
					}
					_ => None,
				};

				let mut tx_session = TxSession::new();
				let mut tx_receive_session = TxSession::new();
				let mut receive_data = None;
				let mut receive_processing_guard = None;

				let result = api.init_send_tx(m, Some(&mut tx_session), &init_args, 1);

				let mut slate = match result {
					Ok(s) => {
						info!(
							"Tx created: {} mwc to {} (strategy '{}')",
							core::amount_to_hr_string(amount, false),
							args.dest,
							args.selection_strategy,
						);
						s
					}
					Err(e) => {
						info!("Tx not created: {}", e);
						return Err(Error::LibWallet(format!(
							"Unable to create send slate , {}",
							e
						)));
					}
				};

				res_tx_uuid = Some(slate.id.clone());

				let mut recipient: Option<ed25519_dalek::VerifyingKey> = None;
				if let Some(sp_address) = &args.slatepack_recipient {
					recipient = Some(sp_address.tor_public_key()?);
				}

				let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
				let (slatepack_secret, slatepack_sender, authenticated_sender, secp) = {
					wallet_lock!(api.wallet_inst, w);
					let keychain = w.keychain(&secp, keychain_mask)?;
					let address_index: u32 = {
						let mut batch = w.batch(&secp, keychain_mask)?;
						let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
						u32::try_from(index).map_err(|e| {
							Error::DataOverflow(format!(
								"command::send, address index value does not fit into u32, index={} error={}",
								index, e
							))
						})?
					};
					let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
						&secp,
						context_id,
						&keychain,
						address_index,
					)?;
					let slate_pub_key = ed25519_dalek::VerifyingKey::from(&slatepack_secret);
					let authenticated_sender = proofaddress::payment_proof_address_pubkey(
						&secp,
						context_id,
						&keychain,
						address_index,
					)?;
					(slatepack_secret, slate_pub_key, authenticated_sender, secp)
				};

				match args.method.as_str() {
					"file" | "slatepack" => {
						let dest: Option<PathBuf> = if args.dest.is_empty() {
							if args.method == "file" {
								return Err(Error::ArgumentError(
									"Please specify destination for file".to_string(),
								));
							}
							None
						} else {
							Some((&args.dest).into())
						};

						let slatepack_format = args.method == "slatepack";

						// Late lock expected to do the lock at finalize step. Don't do that now
						if !init_args.late_lock.unwrap_or(false) {
							api.tx_lock_outputs(
								m,
								Some(&mut tx_session),
								&slate,
								Some(String::from("file")),
								0,
							)?;
						}

						let slate_str = PathToSlatePutter::build_encrypted(
							context_id,
							dest.clone(),
							SlatePurpose::SendInitial,
							slatepack_sender,
							recipient.clone(),
							slatepack_format,
						)
						.put_tx(
							&slate,
							Some(&slatepack_secret),
							#[cfg(feature = "test-support")]
							false,
							&secp,
						)?;
						let mut generated_files = GeneratedSlateFiles::new();
						if let Some(dest) = dest {
							generated_files.track(dest);
						}

						if !args.dest.is_empty() {
							if is_console_output_enabled() {
								println!(
									"Resulting transaction is successfully stored at : {}",
									args.dest
								);
								println!();
							} else {
								info!(
									"Resulting transaction is successfully stored at : {}",
									args.dest
								);
							}
						}

						if slatepack_format {
							let backup_path = show_slatepack(
								api,
								&slate_str, // encrypted (optionally) slate with a purpose.
								&slate.id,
								&SlatePurpose::SendInitial,
								recipient.is_some(),
								false,
								args.slatepack_qr,
							)?;
							generated_files.track(backup_path);
						}

						// The initial Slate was produced successfully. Persist the
						// staged context and optional input locks only now: the
						// session is saved last by design. `generated_files`
						// removes the destination and Slatepack backup if this
						// save fails, keeping the external file exchange aligned
						// with the staged wallet state.
						{
							wallet_lock!(api.wallet_inst, w);
							tx_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
						}
						generated_files.keep();

						return Ok(res_tx_uuid);
					}
					"self" => {
						if slate.compact_slate {
							return Err(Error::GenericError(
								"command::send, self-send does not support a compact slate"
									.to_string(),
							));
						}
						api.tx_lock_outputs(
							m,
							Some(&mut tx_session),
							&slate,
							Some(String::from("self")),
							0,
						)?;
						let km = match keychain_mask.as_ref() {
							None => None,
							Some(&m) => Some(m.to_owned()),
						};
						controller::foreign_single_use(wallet_inst, km, |api| {
							let receive_result = api.receive_tx(
								&mut tx_receive_session,
								&slate,
								None,
								Some(String::from("self")),
								Some(authenticated_sender),
								&Some(args.dest.clone()),
								None,
								true,
							)?;
							debug_assert!(receive_result.reply_reservation.is_none());
							slate = receive_result.slate;
							receive_processing_guard = Some(receive_result.processing_guard);
							receive_data = receive_result.receive_data;
							if tx_receive_session.get_context_participant().is_some() {
								return Err(Error::GenericError(
									"command::send, receive transaction session participant was already initialized"
										.to_string(),
								));
							}
							Ok(())
						})?;
					}
					_ => {
						let sender_info = match sender_info {
							Some(s) => s,
							None => {
								return Err(Error::GenericError(
									"Internal error. Sender not created".to_string(),
								));
							}
						};

						let (sender, wallet_info) = sender_info;

						let original_slate = slate.clone();
						slate = sender.send_tx(
							true,
							&slate,
							SlatePurpose::SendInitial,
							&slatepack_secret,
							recipient,
							wallet_info,
							&secp,
						)?;
						// Known issue, accepted: for MQS, the broker pushed the
						// authenticated response proof into the global cache while
						// waiting for this response, and only Owner::finalize_tx
						// pops it. If any step below fails (response validation,
						// message verification, locking, finalization or posting),
						// the proof and its message-decryption key stay cached
						// until the time-based retention in tx_proof.rs expires
						// them. We rely on that TTL rather than adding cleanup to
						// every error path below: the cache is bounded and this
						// path requires the local user to initiate the send, so
						// delayed expiry is a minor hygiene issue, not a
						// practical denial of service.
						// Restore back ttl, because it can be gone
						slate.ttl_cutoff_height = original_slate.ttl_cutoff_height.clone();
						original_slate.validate_send_response(&slate)?;
						// Checking is sender didn't do any harm to slate
						api.verify_slate_messages(m, &slate).map_err(|e| {
							error!("Error validating participant messages: {}", e);
							e
						})?;
						// Late lock expected to do the lock at finalize step. Don't do that now
						if !init_args.late_lock.unwrap_or(false) {
							api.tx_lock_outputs(
								m,
								Some(&mut tx_session),
								&slate,
								Some(args.dest.clone()),
								0,
							)?; //this step needs to be done before finalizing the slate
						}
					}
				}

				slate = api.finalize_tx(m, Some(&mut tx_session), &slate, do_proof)?;
				tx_session.validate_tx_log_entry_size()?;
				tx_receive_session.validate_tx_log_entry_size()?;

				// Accepted risk: a post_tx error is ambiguous. HTTPNodeClient
				// retries push_transaction with node failover, so an error means
				// "the wallet stopped trying", not "no node accepted the
				// transaction". The session is dropped on this path by design
				// (see TxSession::save_tx_data): if the transaction was in fact
				// accepted, the wallet keeps no record of it and the inputs are
				// released, so a retry can build a conflicting spend. Persisting
				// the finalized state before posting would make this case
				// recoverable, at the cost of a durable private context; we
				// deliberately do not.
				if let Err(e) = api.post_tx(m, slate.tx_or_err()?, args.fluff) {
					error!("Tx post fail: {}", e);
					return Err(Error::LibWallet(format!("Unable to post slate, {}", e)));
				}

				// The node acknowledged the transaction. Persist sender and
				// optional self-receive state as one wallet transaction. Saving
				// only after the acknowledgement keeps the private context out
				// of durable storage for transactions that never reached a node;
				// the trade-off is that a failure of the save itself still
				// orphans a live transaction (see TxSession::save_tx_data).
				{
					if tx_session.get_context_participant().is_some() {
						return Err(Error::GenericError(
						"command::send, transaction session participant was already initialized"
							.to_string(),
					));
					}
					wallet_lock!(api.wallet_inst, w);
					// Write the sender and (for a self-send) receiver sessions into
					// a single backend batch and commit once. Two independent
					// save_tx_data calls would commit separately, so a failure of
					// the second call could leave the sender side durable while
					// the receiver output and log entry are missing.
					let mut batch = w.batch(&secp, m)?;
					tx_session.save_tx_data_into_batch(&mut *batch, &secp, &slate.id)?;
					if !tx_receive_session.is_empty() {
						tx_receive_session.save_tx_data_into_batch(
							&mut *batch,
							&secp,
							&slate.id,
						)?;
					}
					batch.commit()?;
				}
				if let Some(receive_data) = receive_data {
					mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
				}
				drop(receive_processing_guard);

				info!("slate [{}] finalized successfully", slate.id.to_string());
				if is_console_output_enabled() {
					println!("slate [{}] finalized successfully", slate.id.to_string());
				}
				return Ok(Some(slate.id));
			}
			Ok(res_tx_uuid)
		})?;
	Ok(res_tx_uuid)
}

pub fn fauset_request<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	mqs_config: Option<MQSConfig>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	let mut res_slate = Slate::blank(2, false)?;

	let mut tx_session = TxSession::new();

	let (context_id, data_base_dir) = {
		wallet_lock!(wallet_inst, w);
		(w.get_context_id(), w.get_data_file_dir().to_string())
	};

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (slate, context) = api.generate_invoice_slate(m, amount, Some(&mut tx_session))?;

		if mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).is_none() {
			//check to see if mqs_config is there, if not, return error
			let mqs_config_unwrapped;
			match mqs_config {
				Some(s) => {
					mqs_config_unwrapped = s;
				}
				None => {
					return Err(Error::MQSConfig(format!("NO MQS config!")));
				}
			}

			let km = keychain_mask.map(|k| k.clone());

			//start the listener finalize tx
			controller::init_start_mwcmqs_listener(
				wallet_inst.clone(),
				mqs_config_unwrapped,
				Arc::new(Mutex::new(km)),
				false,
				//None,
			)?;
			thread::sleep(Duration::from_millis(2000));
		}

		let sender = create_sender(
			context_id,
			"mwcmqs",
			"xmgEvZ4MCCGMJnRnNXKHBbHmSGWQchNr9uZpY5J1XXnsCFS45fsU",
			&None,
			None,
			Path::new(&data_base_dir),
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, secp) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, keychain_mask)?;
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::fauset_request, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			(slatepack_secret, secp)
		};

		res_slate = clear_faucet_proof_after_send(
			context_id,
			&slate.id,
			sender.send_tx(
				false,
				&slate,
				SlatePurpose::InvoiceInitial,
				&slatepack_secret,
				None,
				None,
				&secp,
			),
		)?;

		Slate::compare_slates_invoice(&slate, &res_slate)?;

		tx_session.set_context_participant(context, 0);

		Ok(())
	})?;

	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};

	let mut invoice_processing_guard = None;
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		if let Err(e) = api.verify_slate_messages(&res_slate) {
			error!("Error validating participant messages: {}", e);
			return Err(Error::LibWallet(format!(
				"Unable to validate slate messages, {}",
				e
			)));
		}
		let finalize_result = api.finalize_invoice_tx(Some(&mut tx_session), &res_slate, None)?;
		res_slate = finalize_result.slate;
		invoice_processing_guard = Some(finalize_result.processing_guard);
		Ok(())
	})?;
	tx_session.validate_tx_log_entry_size()?;

	// Posting
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let transaction = res_slate.tx_or_err()?;

		if let Err(e) = api.post_tx(m, transaction, true) {
			error!("Tx post error: {}", e);
			return Err(Error::LibWallet(format!("Unable to post slate, {}", e)));
		}

		// The complete transaction was accepted by the node. Persist the staged
		// receive record, output and finalized transaction now. Saving after the
		// post is intentional: the transaction is recorded only once it actually
		// happened, so a reported error always means no transaction was created
		// (see TxSession::save_tx_data).
		{
			if tx_session.get_context_participant().is_some() {
				return Err(Error::GenericError(
					"command::fauset_request, transaction session participant was already initialized"
						.to_string(),
				));
			}
			wallet_lock!(api.wallet_inst, w);
			tx_session.save_tx_data(&secp, &mut **w, m, &res_slate.id)?;
		}
		info!("Transaction finished successfully.");
		Ok(())
	})?;
	drop(invoice_processing_guard);

	Ok(())
}

/// MQS keeps a response proof alive for the normal `Owner::finalize_tx` path.
/// Faucet invoices finalize through `Foreign::finalize_invoice_tx`, which does
/// not consume that proof, so every completion of the synchronous send must
/// discard it before returning to the caller.
fn clear_faucet_proof_after_send<T, E>(
	context_id: u32,
	slate_id: &Uuid,
	send_result: Result<T, E>,
) -> Result<T, E> {
	remove_proof_for_slate(context_id, slate_id);
	send_result
}

/// Files published by a staged file workflow before its `TxSession` is saved.
///
/// File workflows intentionally produce the exchange artifact first so an
/// earlier serialization or publication error does not leave a wallet
/// transaction behind. If the later session save fails, this guard removes
/// those artifacts unless the session was successfully saved. Cleanup is
/// best-effort: it cannot revoke an observed or copied artifact and does not
/// run after a process crash or abort. An atomic replacement can also install
/// its destination and then report a parent-directory sync failure; if that
/// happens before the path is tracked, the installed file remains untracked.
///
/// Rollback removes every tracked path unconditionally. That is safe because
/// tracked paths name workflow artifacts, never user data: slate UUIDs are
/// unique per transaction, the Slatepack backup file name embeds the slate
/// UUID, and the response destination is the output path this run was asked
/// to produce, which a successful run atomically replaces anyway. If a path
/// tracked before its atomic replacement fails before the rename, whatever
/// sits at that designated output destination is a stale workflow artifact,
/// so removing it is intentional. For the same reason the guard records no
/// provenance: it never checks whether a destination existed before this run
/// and never sets prior contents aside — outright deletion of a designated
/// artifact path is the intended behavior, not a risk to be mitigated.
/// See `TxSession::save_tx_data`.
struct GeneratedSlateFiles {
	paths: Vec<PathBuf>,
	preserve: bool,
}

impl GeneratedSlateFiles {
	fn new() -> Self {
		Self {
			paths: Vec::new(),
			preserve: false,
		}
	}

	fn track(&mut self, path: PathBuf) {
		if !self.paths.contains(&path) {
			self.paths.push(path);
		}
	}

	/// Keep every generated file after the staged wallet session is durable.
	fn keep(mut self) {
		self.preserve = true;
	}
}

impl Drop for GeneratedSlateFiles {
	fn drop(&mut self) {
		if self.preserve {
			return;
		}

		#[cfg(unix)]
		let mut removed_parents: Vec<PathBuf> = Vec::new();
		for path in &self.paths {
			match fs::remove_file(path) {
				Ok(()) => {
					#[cfg(unix)]
					{
						let parent = normalized_parent(path);
						if !removed_parents.contains(&parent) {
							removed_parents.push(parent);
						}
					}
				}
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
				Err(e) => warn!(
					"Unable to remove generated Slate file {} after staged workflow failure: {}",
					path.display(),
					e
				),
			}
		}

		// Publication synchronizes the files and their directory entries, so
		// rollback removals must be durable the same way: without a directory
		// sync, a crash or power loss after this destructor returns can restore
		// a removed Slate artifact even though its TxSession was never saved.
		// Sync failures are only reported; rollback stays best-effort and a
		// destructor cannot propagate them.
		#[cfg(unix)]
		for dir in &removed_parents {
			if let Err(e) = File::open(dir).and_then(|dir| dir.sync_all()) {
				warn!(
					"Unable to sync directory {} after removing generated Slate files: {}",
					dir.display(),
					e
				);
			}
		}
	}
}

/// Parent directory of `path`, normalized to `"."` for bare filenames. Mirrors
/// the private helper of the same name in `mwc_util::file`.
#[cfg(unix)]
fn normalized_parent(path: &Path) -> PathBuf {
	match path.parent() {
		Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
		_ => PathBuf::from("."),
	}
}

/// Show slate pack, save it into the historical backup, and return its path.
pub fn show_slatepack<L, C, K>(
	api: &mut Owner<L, C, K>,
	slate_str: &str, // encrypted (optionally) slate with a purpose.
	slate_id: &Uuid,
	slate_purpose: &SlatePurpose,
	is_encrypted: bool,
	show_finalizing_message: bool,
	show_qr: bool,
) -> Result<PathBuf, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	// Output if it is a slatepack, into stdout and backup file
	let tld = api.get_top_level_directory()?;
	if tld.is_empty() {
		return Err(Error::GenericError(
			"Wallet top level directory is not set, unable to store the slatepack backup"
				.to_string(),
		));
	}

	// create a directory to which files will be output
	let slate_dir = PathBuf::from(&tld).join("slatepack");
	file::ensure_owner_only_dir_all(&slate_dir).map_err(|e| {
		Error::IO(format!(
			"Unable to create slate backup directory {}, {}",
			slate_dir.display(),
			e
		))
	})?;
	let out_file_name =
		slate_dir.join(format!("{}.{}.slatepack", slate_id, slate_purpose.to_str()));

	// Best-effort atomic replacement: failures before rename leave the previous
	// backup intact. A parent-directory sync failure occurs after rename, so the
	// new backup may already be installed even though this function returns an
	// error; callers then have no returned path to track for cleanup.
	file::replace_owner_only_file(&out_file_name, slate_str.as_bytes()).map_err(|e| {
		Error::IO(format!(
			"Unable to store slate backup data into file {}, {}",
			out_file_name.display(),
			e
		))
	})?;

	// The slatepack directory may have just been created, in which case its
	// entry in the wallet root is only durable once the wallet root is synced.
	#[cfg(unix)]
	{
		File::open(&tld)
			.and_then(|dir| dir.sync_all())
			.map_err(|e| {
				Error::IO(format!(
					"Unable to sync wallet top level directory {}, {}",
					tld, e
				))
			})?;
	}

	if is_console_output_enabled() {
		println!();
		if !show_finalizing_message {
			println!("Slatepack data follows. Please provide this output to the other party");
		} else {
			println!("Slatepack data follows.");
		}
		println!();
		println!("--- CUT BELOW THIS LINE ---");
		println!();
		println!("{}", slate_str);
		println!("--- CUT ABOVE THIS LINE ---");
		println!();
		println!(
			"Slatepack data was also backed up at {}",
			out_file_name.display()
		);
		println!();
		if show_qr {
			let qr_string = QrCode::with_error_correction_level(slate_str, EcLevel::M)
				.or_else(|_| QrCode::with_error_correction_level(slate_str, EcLevel::L));
			match qr_string {
				Ok(qr_string) => {
					println!("{}", qr_string.to_string(false, 3));
					println!();
				}
				Err(e) => {
					warn!("Unable to generate QR code for the slatepack: {}", e);
					println!(
						"Unable to display the slatepack as a QR code ({}). Please use the slatepack text above.",
						e
					);
					println!();
				}
			}
		}
		if is_encrypted {
			println!("The slatepack data is encrypted for the recipient only");
		} else {
			println!("The slatepack data is NOT encrypted");
		}
		println!();
	}
	Ok(out_file_name)
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub message: Option<String>,
	pub outfile: Option<String>,
	pub slatepack_qr: bool,
}

pub fn receive<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, secp, context_id) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, keychain_mask)?;
			let context_id = w.get_context_id();
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::receive, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			(slatepack_secret, secp, context_id)
		};

		let slate_pkg = match &args.input_file {
			Some(file_name) => PathToSlateGetter::build_form_path(context_id, file_name.into())
				.get_tx(Some(&slatepack_secret), &secp)?,
			None => match &args.input_slatepack_message {
				Some(message) => PathToSlateGetter::build_form_str(context_id, message.clone())
					.get_tx(Some(&slatepack_secret), &secp)?,
				None => {
					return Err(Error::ArgumentError(
						"Please specify 'file' or 'content' argument".to_string(),
					));
				}
			},
		};

		let (mut slate, sender, recipient, content, slatepack_format) = slate_pkg.to_slate()?;
		validate_slatepack_receive_direction(
			sender.as_ref(),
			recipient.as_ref(),
			&slatepack_secret.verifying_key(),
		)?;

		if !(content == SlatePurpose::FullSlate || content == SlatePurpose::SendInitial) {
			return Err(Error::ArgumentError(format!(
				"Wrong slate content. Expecting SendInitial, get {:?}",
				content
			)));
		}

		if let Err(e) = slate.validate_send_initial() {
			error!("Error validating slate participants: {}", e);
			return Err(Error::LibWallet(format!(
				"Unable to validate slate participants, {}",
				e
			)));
		}
		if let Err(e) = api.verify_slate_messages(&slate) {
			error!("Error validating participant messages: {}", e);
			return Err(Error::LibWallet(format!(
				"Unable to validate slate messages, {}",
				e
			)));
		}
		// Stage the receiver record and output while the backend's UUID guard
		// excludes every other supported request for this Slate. The wallet
		// lifecycle allows only one opened backend for a wallet directory, so
		// this in-memory guard covers all supported concurrency. The child-key
		// allocator may advance here, but the TxReceived record and output remain
		// staged until save_tx_data below.
		let mut tx_session = TxSession::new();
		let reply_binding = sender
			.as_ref()
			.filter(|_| slatepack_format)
			.map(ReplyBinding::file);
		let receive_result = api.receive_tx(
			&mut tx_session,
			&slate,
			reply_binding,
			Some(String::from("file")),
			None,
			&g_args.account,
			args.message.clone(),
			false,
		)?;
		slate = receive_result.slate;
		let _processing_guard = receive_result.processing_guard;
		let reply_reservation = receive_result.reply_reservation;
		let receive_data = receive_result.receive_data;

		let mut response_file = args.outfile.clone();
		if response_file.is_none() {
			response_file = args.input_file.map(|n| format!("{}.response", n));
		}

		let slatepack_str = PathToSlatePutter::build_encrypted(
			context_id,
			None,
			SlatePurpose::SendResponse,
			ed25519_dalek::VerifyingKey::from(&slatepack_secret),
			sender.clone(),
			slatepack_format,
		)
		.put_tx(
			&slate,
			Some(&slatepack_secret),
			#[cfg(feature = "test-support")]
			false,
			&secp,
		)?;

		if !slatepack_format && response_file.is_none() && !is_console_output_enabled() {
			return Err(Error::ArgumentError(
				"Please specify 'output' argument, the response slate has nowhere to be stored"
					.to_string(),
			));
		}

		let mut generated_files = GeneratedSlateFiles::new();
		let publish_result: Result<(), Error> = (|| {
			if let Some(response_file) = &response_file {
				let response_path = PathBuf::from(response_file);
				// Track before replacement because the atomic helper can install
				// the new file and then report a directory-sync failure. If it
				// fails before the rename instead, rollback removes the stale
				// artifact at this designated output destination; that is
				// intentional (see GeneratedSlateFiles).
				generated_files.track(response_path.clone());
				file::replace_owner_only_file(&response_path, slatepack_str.as_bytes()).map_err(
					|e| {
						Error::IO(format!(
							"Unable to store response slate at file {}, {}",
							response_path.display(),
							e
						))
					},
				)?;
				if is_console_output_enabled() {
					println!(
						"Response file {} generated, and can be sent back to the transaction originator.",
						response_file
					);
					println!();
				}
			}

			if slatepack_format {
				let backup_path = show_slatepack(
					owner_api,
					&slatepack_str,
					&slate.id,
					&SlatePurpose::SendResponse,
					sender.is_some(),
					false,
					args.slatepack_qr,
				)?;
				generated_files.track(backup_path);
			} else if response_file.is_none() {
				println!();
				println!(
					"Response slate follows. Please provide this output to the transaction originator"
				);
				println!();
				println!("--- CUT BELOW THIS LINE ---");
				println!();
				// Preserve valid, copyable JSON while making terminal controls and
				// bidirectional formatting characters visible.
				println!("{}", escape_for_display(&slatepack_str));
				println!("--- CUT ABOVE THIS LINE ---");
				println!();
			}
			Ok(())
		})();

		if let Err(e) = publish_result {
			return Err(Error::IO(format!(
				"Unable to publish response for receive {}: {}",
				slate.id, e
			)));
		}

		// The response slate was delivered to the sender. Persist the staged
		// receive state only now. The UUID guard returned above covers every
		// supported concurrent receive because a wallet directory may have only
		// one opened backend, and `generated_files` removes file artifacts if
		// this final save fails.
		if !tx_session.is_empty() {
			wallet_lock!(api.wallet_inst, w);
			tx_session.save_tx_data(&secp, &mut **w, keychain_mask, &slate.id)?;
		}
		generated_files.keep();
		if let Some(reservation) = reply_reservation {
			reservation.complete(&slate);
		}
		if let Some(receive_data) = receive_data {
			mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
		}

		Ok(())
	})?;

	Ok(())
}

pub fn unpack<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ReceiveArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, secp, context_id) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, keychain_mask)?;
			let context_id = w.get_context_id();
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::unpack, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			(slatepack_secret, secp, context_id)
		};

		let slate_pkg = match &args.input_file {
			Some(file_name) => PathToSlateGetter::build_form_path(context_id, file_name.into())
				.get_tx(Some(&slatepack_secret), &secp)?,
			None => match &args.input_slatepack_message {
				Some(message) => PathToSlateGetter::build_form_str(context_id, message.clone())
					.get_tx(Some(&slatepack_secret), &secp)?,
				None => {
					return Err(Error::ArgumentError(
						"Please specify 'file' or 'content' argument".to_string(),
					));
				}
			},
		};

		let (slate, sender, recipient, content, _slatepack_format) = slate_pkg.to_slate()?;

		let slate_str = PathToSlatePutter::build_plain(context_id, None).put_tx(
			&slate,
			Some(&slatepack_secret),
			#[cfg(feature = "test-support")]
			false,
			&secp,
		)?;

		// Preserve the exact slate JSON for owner-only file output, but render
		// peer-controlled terminal control characters visibly on the console.
		let slate_for_output = if args.outfile.is_some() {
			slate_str
		} else {
			escape_for_display(&slate_str)
		};

		let mut output = String::new();

		output.push_str("SLATEPACK CONTENTS\n");
		output.push_str(&format!("Slate:     {}\n", slate_for_output));
		output.push_str(&format!("Content:   {:?}\n", content));
		if let Some(sender) = sender {
			output.push_str(&format!(
				"Sender:    {}\n",
				ProvableAddress::from_tor_pub_key(&sender)?.public_key
			));
		} else {
			output.push_str("Sender:    None (Not encrypted)\n");
		}
		if let Some(recipient) = recipient {
			output.push_str(&format!(
				"recipient: {}\n",
				ProvableAddress::from_tor_pub_key(&recipient)?.public_key
			));
		} else {
			output.push_str("recipient: None (Not encrypted)\n");
		}

		match args.outfile.as_deref() {
			Some(outfile) => {
				file::replace_owner_only_file(outfile, output.as_bytes()).map_err(|e| {
					Error::IO(format!(
						"Unable to write unpacked Slatepack data into output file {}, {}",
						outfile, e
					))
				})?;
			}
			None if is_console_output_enabled() => println!("\n{}", output),
			None => {
				return Err(Error::ArgumentError(
					"Console output is disabled; please specify an output file".to_string(),
				));
			}
		}

		Ok(())
	})?;

	Ok(())
}

/// Finalize command args
pub struct FinalizeArgs {
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub fluff: bool,
	pub nopost: bool,
	pub dest: Option<String>,
	// Finalize can't show slatepack because it is too large
	// pub slatepack_qr: bool,
}

pub fn finalize<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: FinalizeArgs,
	is_invoice: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut slate = Slate::blank(2, false)?; // result placeholder, params not important
	let mut content = SlatePurpose::FullSlate;
	let mut sender = None;
	let mut recipient = None;
	let mut slatepack_format = false;

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, secp, context_id) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, m)?;
			let context_id = w.get_context_id();
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::finalize, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			let slatepack_secret = ed25519_dalek::SigningKey::from_bytes(&slatepack_secret.0);
			(slatepack_secret, secp, context_id)
		};

		let slate_pkg = match &args.input_file {
			Some(file_name) => PathToSlateGetter::build_form_path(context_id, file_name.into())
				.get_tx(Some(&slatepack_secret), &secp)?,
			None => match &args.input_slatepack_message {
				Some(message) => PathToSlateGetter::build_form_str(context_id, message.clone())
					.get_tx(Some(&slatepack_secret), &secp)?,
				None => {
					return Err(Error::ArgumentError(
						"Please specify 'file' or 'content' argument".to_string(),
					));
				}
			},
		};

		let (slate2, sender2, recipient2, content2, slatepack_format2) = slate_pkg.to_slate()?;
		// An encrypted response must be addressed to this wallet. ECDH is
		// symmetric, so without this check a peer can build a decryptable
		// envelope naming our key as the sender, and the finalize below
		// would treat our own key as the authenticated counterparty.
		validate_slatepack_receive_direction(
			sender2.as_ref(),
			recipient2.as_ref(),
			&slatepack_secret.verifying_key(),
		)?;
		slate = slate2;
		sender = sender2;
		recipient = recipient2;
		content = content2;
		slatepack_format = slatepack_format2;

		Ok(())
	})?;

	// Note!!! mwc wallet was able to detect if it is invoice by using 'different' participant Ids (issuer use 1, fouset 0)
	//    Unfortunatelly it is breaks mwc713 backward compatibility (issuer Participant Id 0, fouset 1)
	//    We choose backward compatibility as more impotant, that is why we need 'is_invoice' flag to compensate that.

	let mut invoice_processing_guard = None;
	if is_invoice {
		if !(content == SlatePurpose::FullSlate || content == SlatePurpose::InvoiceResponse) {
			return Err(Error::ArgumentError(format!(
				"Wrong slate content. Expecting InvoiceResponse, get {:?}",
				content
			)));
		}

		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			// Cheap structural checks first: they reject an oversized or
			// relabeled participant set before the per-record signature
			// verification loop in verify_slate_messages.
			if let Err(e) = slate.validate_response_participants() {
				error!("Error validating invoice response slate: {}", e);
				return Err(Error::LibWallet(format!(
					"Unable to validate invoice response slate, {}",
					e
				)));
			}
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(Error::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				)));
			}
			let reply_binding = sender
				.as_ref()
				.filter(|_| slatepack_format)
				.map(ReplyBinding::file);
			let finalize_result = api.finalize_invoice_tx_with_output_version(
				None,
				&slate,
				reply_binding,
				if slatepack_format {
					Some(mwc_wallet_libwallet::SlateVersion::SP)
				} else {
					None
				},
			)?;
			slate = finalize_result.slate;
			invoice_processing_guard = Some(finalize_result.processing_guard);
			Ok(())
		})?;
	} else {
		if !(content == SlatePurpose::FullSlate || content == SlatePurpose::SendResponse) {
			return Err(Error::ArgumentError(format!(
				"Wrong slate content. Expecting SendResponse, get {:?}",
				content
			)));
		}

		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			// Cheap structural checks first: they reject an oversized or
			// relabeled participant set before the per-record signature
			// verification loop in verify_slate_messages.
			if let Err(e) = slate.validate_response_participants() {
				error!("Error validating send response slate: {}", e);
				return Err(Error::LibWallet(format!(
					"Unable to validate send response slate, {}",
					e
				)));
			}
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(Error::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				)));
			}
			slate = api.finalize_tx_with_output_version(
				m,
				None,
				&slate,
				true,
				if slatepack_format {
					Some(mwc_wallet_libwallet::SlateVersion::SP)
				} else {
					None
				},
			)?;
			Ok(())
		})?;
	}

	// Produce the requested output (destination file / slatepack display) BEFORE
	// broadcasting. These operations are fallible and only depend on the finalized
	// slate, so if they fail we return before post_tx and no irreversible network
	// action has been taken.
	if args.dest.is_some() || slatepack_format {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let (slatepack_secret, secp, context_id) = {
				wallet_lock!(api.wallet_inst, w);
				let keychain = w.keychain(&secp, m)?;
				let context_id = w.get_context_id();
				let address_index: u32 = {
					let mut batch = w.batch(&secp, keychain_mask)?;
					let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
					u32::try_from(index).map_err(|e| {
						Error::DataOverflow(format!(
							"command::finalize, address index value does not fit into u32, index={} error={}",
							index, e
						))
					})?
				};
				let slatepack_secret = proofaddress::payment_proof_address_secret(
					&secp,
					context_id,
					&keychain,
					address_index,
				)?;
				let slatepack_secret = ed25519_dalek::SigningKey::from_bytes(&slatepack_secret.0);
				(slatepack_secret, secp, context_id)
			};

			let path_buf: Option<PathBuf> = match args.dest {
				Some(d) => Some(d.into()),
				None => None,
			};

			// save to a destination not as a slatepack
			let slatepack_str = PathToSlatePutter::build_encrypted(
				context_id,
				path_buf,
				SlatePurpose::FullSlate,
				ed25519_dalek::VerifyingKey::from(&slatepack_secret),
				sender.clone(),
				slatepack_format,
			)
			.put_tx(
				&slate,
				Some(&slatepack_secret),
				#[cfg(feature = "test-support")]
				false,
				&secp,
			)?;

			if slatepack_format {
				show_slatepack(
					api,
					&slatepack_str, // encrypted (optionally) slate with a purpose.
					&slate.id,
					&SlatePurpose::FullSlate,
					sender.is_some(),
					true,
					false,
				)?;
			}

			Ok(())
		})?;
	}

	// Broadcast LAST: once post_tx succeeds, nothing after it may fail.
	if !args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, slate.tx_or_err()?, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					return Err(Error::LibWallet(format!("Unable to post slate, {}", e)));
				}
			}
		})?;
	}
	drop(invoice_processing_guard);

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
	/// show slatepack as QR code
	pub slatepack_qr: bool,
}

pub fn issue_invoice_tx<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let mut recipient: Option<ed25519_dalek::VerifyingKey> = None;
		if let Some(sp_address) = &args.issue_args.slatepack_recipient {
			recipient = Some(sp_address.tor_public_key()?);
		}

		let mut tx_session = TxSession::new();
		let slate = api.issue_invoice_tx(m, Some(&mut tx_session), &args.issue_args)?;
		tx_session.validate_tx_log_entry_size()?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, tor_address, secp, context_id) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, keychain_mask)?;
			let context_id = w.get_context_id();
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::issue_invoice_tx, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			let slatepack_pk = ed25519_dalek::VerifyingKey::from(&slatepack_secret);
			(slatepack_secret, slatepack_pk, secp, context_id)
		};

		let slatepack_format = recipient.is_some();
		let slate_str = PathToSlatePutter::build_encrypted(
			context_id,
			Some((&args.dest).into()),
			SlatePurpose::InvoiceInitial,
			tor_address,
			recipient.clone(),
			slatepack_format,
		)
		.put_tx(
			&slate,
			Some(&slatepack_secret),
			#[cfg(feature = "test-support")]
			false,
			&secp,
		)?;
		let mut generated_files = GeneratedSlateFiles::new();
		generated_files.track(PathBuf::from(&args.dest));

		if slatepack_format {
			let backup_path = show_slatepack(
				api,
				&slate_str, // encrypted (optionally) slate with a purpose.
				&slate.id,
				&SlatePurpose::InvoiceInitial,
				recipient.is_some(),
				false,
				args.slatepack_qr,
			)?;
			generated_files.track(backup_path);
		}
		// Persist only after apparent delivery. TxSession does not retain a
		// re-exportable initial Slate, so persisting first could leave a pending,
		// undeliverable invoice after an ordinary output failure. File cleanup is
		// best-effort; ambiguous publication or a crash remains the accepted
		// save-last trade-off documented by TxSession::save_tx_data.
		{
			wallet_lock!(api.wallet_inst, w);
			tx_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
		}
		generated_files.keep();

		Ok(())
	})?;
	Ok(())
}

/// Arguments for the process_invoice command
pub struct ProcessInvoiceArgs {
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub method: String,
	pub dest: String,
	pub max_outputs: usize,
	pub input_file: Option<String>,
	pub input_slatepack_message: Option<String>,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
	pub slatepack_qr: bool,
}

/// Process invoice
pub fn process_invoice<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	args: ProcessInvoiceArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let (slatepack_secret, tor_address, secp, context_id, base_dir) = {
		wallet_lock!(owner_api.wallet_inst, w);
		let keychain = w.keychain(&secp, keychain_mask)?;
		let context_id = w.get_context_id();
		let address_index: u32 = {
			let mut batch = w.batch(&secp, keychain_mask)?;
			let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
			u32::try_from(index).map_err(|e| {
				Error::DataOverflow(format!(
					"command::process_invoice, address index value does not fit into u32, index={} error={}",
					index, e
				))
			})?
		};
		let base_dir = w.get_data_file_dir().to_string();
		let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
			&secp,
			context_id,
			&keychain,
			address_index,
		)?;
		let slatepack_pk = ed25519_dalek::VerifyingKey::from(&slatepack_secret);
		(slatepack_secret, slatepack_pk, secp, context_id, base_dir)
	};

	let slate_pkg = match &args.input_file {
		Some(file_name) => PathToSlateGetter::build_form_path(context_id, file_name.into())
			.get_tx(Some(&slatepack_secret), &secp)?,
		None => match &args.input_slatepack_message {
			Some(message) => PathToSlateGetter::build_form_str(context_id, message.clone())
				.get_tx(Some(&slatepack_secret), &secp)?,
			None => {
				return Err(Error::ArgumentError(
					"Please specify 'file' or 'content' argument".to_string(),
				));
			}
		},
	};

	let (slate, sender_pk, recipient, content, _encrypted) = slate_pkg.to_slate()?;
	// An encrypted invoice request must be addressed to this wallet. ECDH is
	// symmetric, so a role-reversed envelope (our key as sender) still decrypts
	// locally; without this check we would sign and lock payer inputs for an
	// exchange the counterparty cannot complete.
	validate_slatepack_receive_direction(sender_pk.as_ref(), recipient.as_ref(), &tor_address)?;

	if !(content == SlatePurpose::FullSlate || content == SlatePurpose::InvoiceInitial) {
		return Err(Error::ArgumentError(format!(
			"Wrong slate content. Expecting InvoiceInitial, get {:?}",
			content
		)));
	}

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
			for strategy in vec!["smallest", "all"] {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: slate.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs,
					num_change_outputs: 1usize,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = api.init_send_tx(m, None, &init_args, 1)?;
				strategies.push((strategy, slate.amount, slate.fee));
			}
			display::estimate(slate.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: 0,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs,
				num_change_outputs: 1usize,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				..Default::default()
			};
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(Error::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				)));
			}

			let mut tx_session = TxSession::new();

			let result = api.process_invoice_tx(m, Some(&mut tx_session), &slate, &init_args);
			let process_result = match result {
				Ok(result) => {
					info!(
						"Invoice processed: {} mwc to {} (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
						args.dest,
						args.selection_strategy,
					);
					result
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(Error::LibWallet(format!(
						"Unable to process invoice, {}",
						e
					)));
				}
			};
			let mut slate = process_result.slate;
			let _processing_guard = process_result.processing_guard;

			match args.method.as_str() {
				"file" => {
					api.tx_lock_outputs(
						m,
						Some(&mut tx_session),
						&slate,
						Some(String::from("file")),
						1,
					)?;

					// Process invoice slate is not required to send anywhere. Let's write it for our records.
					let slatepack_format = sender_pk.is_some();
					let slate_str = PathToSlatePutter::build_encrypted(
						context_id,
						Some((&args.dest).into()),
						SlatePurpose::InvoiceResponse,
						tor_address,
						sender_pk.clone(),
						slatepack_format,
					)
					.put_tx(
						&slate,
						Some(&slatepack_secret),
						#[cfg(feature = "test-support")]
						false,
						&secp,
					)?;
					let mut generated_files = GeneratedSlateFiles::new();
					generated_files.track(PathBuf::from(&args.dest));

					if slatepack_format {
						let backup_path = show_slatepack(
							api,
							&slate_str, // encrypted (optionally) slate with a purpose.
							&slate.id,
							&SlatePurpose::InvoiceResponse,
							sender_pk.is_some(),
							false,
							args.slatepack_qr,
						)?;
						generated_files.track(backup_path);
					}
					// The invoice response slate is ready for the issuer. Persist
					// the staged session only now. If the save fails,
					// `generated_files` removes the response destination and
					// Slatepack backup.
					{
						wallet_lock!(api.wallet_inst, w);
						tx_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
					}
					generated_files.keep();
				}
				"http" => {
					let sender = create_sender(
						context_id,
						args.method.as_str(),
						&args.dest,
						&None,
						tor_config.as_ref(),
						Path::new(&base_dir),
					)?;
					let other_wallet_version =
						sender.check_other_wallet_version(&args.dest, true)?;

					// Retain the locally built response slate; the HTTP-returned
					// slate is counterparty-controlled and the transaction
					// signature does not commit the slate UUID or the
					// participant transcript.
					let sent_slate = slate.clone();
					slate = sender.send_tx(
						false,
						&slate,
						SlatePurpose::InvoiceResponse,
						&slatepack_secret,
						sender_pk,
						other_wallet_version,
						&secp,
					)?;
					// Bind the response to what we sent before locking outputs,
					// posting, or recording the payment under the returned id.
					if let Err(e) = sent_slate.validate_invoice_response(&mut slate) {
						error!("Error validating invoice response slate: {}", e);
						return Err(Error::LibWallet(format!(
							"Unable to validate invoice response slate, {}",
							e
						)));
					}
					if let Err(e) = api.verify_slate_messages(m, &slate) {
						error!("Error validating participant messages: {}", e);
						return Err(Error::LibWallet(format!(
							"Unable to validate slate messages, {}",
							e
						)));
					}
					api.tx_lock_outputs(
						m,
						Some(&mut tx_session),
						&slate,
						Some(args.dest.clone()),
						1,
					)?;
					tx_session.validate_tx_log_entry_size()?;

					if let Err(e) = api.post_tx(m, slate.tx_or_err()?, true) {
						error!("Tx post fail: {}", e);
						return Err(Error::LibWallet(format!("Unable to post slate, {}", e)));
					}
					// The node accepted the transaction. Persist the staged
					// session only now: saving after the post is intentional,
					// so a reported error means no transaction was created
					// (see TxSession::save_tx_data).
					{
						wallet_lock!(api.wallet_inst, w);
						tx_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
					}

					let msg = format!(
						"Invoice slate [{}] finalized and posted successfully",
						slate.id.to_string()
					);
					info!("{}", msg);
					println!("{}", msg);
					return Ok(());
				}
				method => {
					return Err(Error::ArgumentError(format!("Unknown method: {}", method)));
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}
/// Info command args
pub struct InfoArgs {
	pub minimum_confirmations: u64,
}

pub fn info<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: InfoArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;

		let context_id = {
			wallet_lock!(api.wallet_inst, w);
			w.get_context_id()
		};

		display::info(
			context_id,
			&g_args.account,
			&wallet_info,
			validated,
			dark_scheme,
		);
		Ok(())
	})?;
	Ok(())
}

pub struct OutputsArgs {
	pub show_spent: bool,
}

pub fn outputs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: OutputsArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, refresh_height, outputs) =
			api.retrieve_outputs(m, args.show_spent, true, None)?;
		// When validated, refresh_height is the exact node tip the outputs
		// were reconciled against; the displayed height and confirmation
		// counts must come from that same snapshot, not from a second,
		// possibly cached, tip read. When the refresh failed the height is
		// display-only: the data warning is shown in any case.
		let cur_height = if validated {
			refresh_height
		} else {
			api.node_height(m).map(|res| res.height).unwrap_or(0)
		};
		display::outputs(&g_args.account, cur_height, validated, outputs, dark_scheme)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub count: Option<u32>,
	pub show_last_four_days: Option<bool>,
}

pub fn txs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	args: TxsArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		// Note advanced query args not currently supported by command line client
		let (validated, refresh_anchor_height, txs) = api.retrieve_txs(
			m,
			true,
			args.id,
			args.tx_slate_id,
			None,
			args.show_last_four_days,
		)?;
		// The refreshed txs are anchored at the tip the refresh validated against.
		// res.height was sampled before the refresh and may come from the node
		// client's short-lived cache or a different node, so it is only a fallback
		// for when the data was not validated.
		let cur_height = refresh_anchor_height.unwrap_or(res.height);
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		// If view count is specified, restrict the TX list to `txs.len() - count`
		let first_tx = match args.count {
			Some(count) => {
				let count = usize::try_from(count).map_err(|e| {
					Error::DataOverflow(format!(
						"command::txs, transaction display count does not fit usize, count={} error={}",
						count, e
					))
				})?;
				// Asking for more entries than exist intentionally starts at the first entry.
				txs.len().saturating_sub(count)
			}
			None => 0,
		};

		let data_file_dir = {
			wallet_lock!(api.wallet_inst.clone(), w);
			w.get_data_file_dir().to_string()
		};

		display::txs(
			&g_args.account,
			cur_height,
			validated,
			&txs[first_tx..],
			include_status,
			dark_scheme,
			true, // mwc-wallet always show the full info because it is advanced tool
			|tx: &TxLogEntry| match &tx.tx_slate_id {
				Some(slate_id) => {
					TxProof::has_stored_tx_proof(&data_file_dir, &slate_id.to_string())
				}
				None => Ok(false),
			},
		)?;

		// if given a particular transaction id or uuid, also get and display associated
		// inputs/outputs and messages
		let id = if args.id.is_some() {
			args.id
		} else if args.tx_slate_id.is_some() {
			if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == args.tx_slate_id) {
				Some(tx.id)
			} else if validated {
				println!("Could not find a transaction matching given txid.\n");
				None
			} else {
				// Absence in an unvalidated local cache is not authoritative:
				// report the failed validation instead of a plain "not found".
				println!(
					"\nWARNING: Wallet failed to verify data. \
					 The result is from local cache and possibly invalid!"
				);
				return Err(Error::GenericError(
					"transaction list could not be validated against the node; \
					 cannot confirm the transaction is absent"
						.to_owned(),
				));
			}
		} else {
			None
		};

		if id.is_some() {
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, id)?;
			display::outputs(&g_args.account, cur_height, validated, outputs, dark_scheme)?;

			let secp = Secp256k1::with_caps(ContextFlag::None)?;

			// should only be one here, but just in case
			for tx in txs {
				display::tx_messages(&tx, dark_scheme, &secp)?;
			}
		}

		Ok(())
	})?;
	Ok(())
}

/// Post
pub struct PostArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn post<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: PostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let path_buf: PathBuf = (&args.input).into();
	let mut pub_tx_f = File::open(&path_buf)
		.map_err(|e| Error::IO(format!("Unable to open file {}, {}", args.input, e)))?;
	let mut content = String::new();
	pub_tx_f.read_to_string(&mut content).map_err(|e| {
		Error::IO(format!(
			"Unable to read data from file {}, {}",
			args.input, e
		))
	})?;
	if content.len() < 3 {
		return Err(Error::GenericError(format!("File {} is empty", args.input)));
	}

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slatepack_secret, secp, context_id) = {
			wallet_lock!(api.wallet_inst, w);
			let keychain = w.keychain(&secp, keychain_mask)?;
			let context_id = w.get_context_id();
			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"command::post, address index value does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				context_id,
				&keychain,
				address_index,
			)?;
			(slatepack_secret, secp, context_id)
		};

		// TransactionV3 cannot distinguish a real Plain input feature from the
		// placeholder used when a legacy dump contained commitment-only inputs.
		// Posting such a JSON dump is consequently best effort for non-Plain inputs;
		// use `repost` for a wallet-stored transaction because it retains the core
		// commitment-only representation and lets the node validate the real output.
		let tx = match serde_json::from_str::<TransactionV3>(&content) {
			Ok(tx) => Transaction::try_from(tx)?,
			Err(_) => {
				match serde_json::from_str::<TransactionV2>(&content) {
					Ok(tx) => {
						let tx: TransactionV3 = tx.into();
						Transaction::try_from(tx)?
					}
					Err(_) => {
						// Let's try decode as a slate
						let slate_pkg = PathToSlateGetter::build_form_str(context_id, content)
							.get_tx(Some(&slatepack_secret), &secp)?;
						let (slate, _, _, content, _slatepack_format) = slate_pkg.to_slate()?;
						if content != SlatePurpose::FullSlate {
							return Err(Error::LibWallet(format!(
								"Posting can performed for a FullSlate, this slate is {:?}",
								content
							)));
						}
						match slate.tx {
							Some(tx) => tx,
							None => {
								return Err(Error::LibWallet(
									"Slate is empty, no transaction is found".into(),
								));
							}
						}
					}
				}
			}
		};

		api.post_tx(m, &tx, args.fluff)?;
		info!("Posted transaction");
		return Ok(());
	})?;
	Ok(())
}

/// Submit
pub struct SubmitArgs {
	pub input: String,
	pub fluff: bool,
}

pub fn submit<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: SubmitArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let stored_tx = api.load_stored_tx(&args.input)?;
		api.post_tx(m, &stored_tx, args.fluff)?;
		info!("Reposted transaction in file: {}", args.input);
		return Ok(());
	})?;
	Ok(())
}

/// Repost
pub struct RepostArgs {
	pub id: u32,
	pub dump_file: Option<String>,
	pub fluff: bool,
}

fn dump_stored_transaction(transaction: &Transaction, destination: &str) -> Result<(), Error> {
	// This is a best-effort legacy JSON export, not reconstruction of metadata
	// omitted by the stored transaction format. TransactionV3 requires input
	// features, so commitment-only inputs are represented by the documented Plain
	// placeholder. Querying the node here would make old dumps fail once an input
	// is spent and disappears from the UTXO set. The normal repost path below posts
	// the original core Transaction directly and does not use this conversion.
	// A later `post` of this JSON remains best effort when the omitted feature was
	// not Plain; consumers must not interpret the placeholder as recovered data.
	let versioned = TransactionV3::from(transaction);
	let tx_as_str = serde_json::to_string(&versioned)
		.map_err(|e| Error::GenericError(format!("Unable convert Tx to Json, {}", e)))?;
	file::replace_owner_only_file(destination, tx_as_str.as_bytes()).map_err(|e| {
		Error::IO(format!(
			"Unable to save tx to the file {}, {}",
			destination, e
		))
	})
}

pub fn repost<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, refresh_anchor_height, txs) =
			api.retrieve_txs(m, true, Some(args.id), None, None, None)?;
		if !validated {
			return Err(Error::GenericError(
				"Unable to validate wallet state against the node, cannot repost or dump transaction"
					.to_string(),
			));
		}
		let tx = txs.first().ok_or_else(|| {
			Error::GenericError(format!("Transaction with id {} was not found", args.id))
		})?;
		if args.dump_file.is_none() {
			if tx.confirmed {
				return Err(mwc_wallet_libwallet::Error::TransactionAlreadyConfirmed.into());
			}
			// Cancellation is wallet-local, not consensus: the stored finalized
			// transaction can still be accepted by the node while the wallet has
			// unlocked the inputs (which a replacement may already spend).
			if tx.is_cancelled() {
				return Err(mwc_wallet_libwallet::Error::TransactionWasCancelled(
					args.id.to_string(),
				)
				.into());
			}
			// Refresh cancels TTL-expired entries only best-effort; enforce the
			// cutoff here against the anchor of the validation refresh above.
			if let (Some(anchor), Some(cutoff)) = (refresh_anchor_height, tx.ttl_cutoff_height) {
				if anchor >= cutoff {
					return Err(mwc_wallet_libwallet::Error::TransactionExpired.into());
				}
			}
		}
		let locator = StoredTxLocator::from(tx);
		let stored_tx = api.get_stored_tx(m, &locator)?;
		let stored_tx = match stored_tx {
			Some(tx) => tx,
			None => {
				return Err(
					mwc_wallet_libwallet::Error::TransactionBuildingNotCompleted(args.id).into(),
				);
			}
		};

		match args.dump_file {
			None => {
				if stored_tx
					.kernels()
					.first()
					.map(|kernel| sig_is_blank(&kernel.excess_sig))
					.unwrap_or(true)
				{
					return Err(
						mwc_wallet_libwallet::Error::TransactionBuildingNotCompleted(args.id)
							.into(),
					);
				}

				api.post_tx(m, &stored_tx, args.fluff)?;
				info!("Reposted transaction at {}", args.id);
				return Ok(());
			}
			Some(f) => {
				dump_stored_transaction(&stored_tx, &f)?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
	Ok(())
}

const MAX_CANCEL_ERROR_BYTES: usize = 2_048;

fn safe_cancel_error(error: &mwc_wallet_libwallet::Error) -> String {
	let rendered = error.to_string();
	bounded_escape_for_display(&rendered, MAX_CANCEL_ERROR_BYTES)
}

#[cfg(feature = "swaps")]
#[derive(Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
struct MarketplaceCancellationAck {
	cancelled: bool,
}

#[cfg(feature = "swaps")]
#[derive(Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
struct MarketplaceOfferStatusAck {
	running: i64,
}

#[cfg(feature = "swaps")]
fn require_marketplace_cancellation_ack(response: &str) -> Result<(), Error> {
	if !response.trim_start().starts_with('{') {
		return Err(Error::MarketplaceResponse(
			"Marketplace cancellation returned a malformed acknowledgement: expected a top-level JSON object"
				.to_string(),
		));
	}

	let acknowledgement: MarketplaceCancellationAck =
		serde_json::from_str(response).map_err(|e| {
			Error::MarketplaceResponse(format!(
				"Marketplace cancellation returned a malformed acknowledgement: {}",
				bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
			))
		})?;
	if !acknowledgement.cancelled {
		return Err(Error::MarketplaceResponse(
			"Marketplace cancellation was not acknowledged".to_string(),
		));
	}
	Ok(())
}

/// Cancel
pub struct CancelArgs {
	pub tx_id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
	pub tx_id_string: String,
}

pub fn cancel<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CancelArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.cancel_tx(m, args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				// Refresh errors can contain node-controlled text. Render the error
				// once, then bound and escape that rendering before either the log or
				// the interactive CLI can display it.
				let safe_error = safe_cancel_error(&e);
				error!("TX Cancellation failed: {}", safe_error);
				Err(Error::LibWallet(format!(
					"Unable to cancel Transaction {}, {}",
					args.tx_id_string, safe_error
				)))
			}
		}
	})?;
	Ok(())
}

/// wallet check
pub struct CheckArgs {
	pub delete_unconfirmed: bool,
	pub start_height: Option<u64>,
	pub backwards_from_tip: Option<u64>,
}

const MAX_SCAN_ERROR_BYTES: usize = 2_048;

fn safe_scan_error(error: &mwc_wallet_libwallet::Error) -> String {
	let rendered = error.to_string();
	bounded_escape_for_display(&rendered, MAX_SCAN_ERROR_BYTES)
}

pub fn scan<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		match args.backwards_from_tip {
			Some(b) => warn!(
				"Starting output scan {} blocks back from the node tip ...",
				b
			),
			None => match args.start_height {
				Some(s) => warn!("Starting output scan from height {} ...", s),
				None => warn!("Starting output scan from height 1 ..."),
			},
		}
		// A relative lookback is resolved inside the scan against the freshly
		// fetched, verified chain tip the scan is anchored to.
		let result = api.scan(
			m,
			args.start_height,
			args.backwards_from_tip,
			args.delete_unconfirmed,
		);
		match result {
			Ok(_) => {
				warn!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				// Scan errors can embed node-controlled strings (tip/header hashes,
				// response bodies). Bound and escape their display representation
				// before it reaches the terminal or the log.
				error!("Wallet check failed: {}", safe_scan_error(&e));
				Err(e.into())
			}
		}
	})?;
	Ok(())
}

/// Payment Proof Address
pub fn address<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_g_args: &GlobalArgs,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		// Just address at derivation index 0 for now
		let mqs_pub_key = owner::get_mqs_address(api.wallet_inst.clone(), &secp, m)?;
		let tor_pub_key = owner::get_wallet_public_address(api.wallet_inst.clone(), &secp, m)?;

		let context_id = {
			wallet_lock!(api.wallet_inst, w);
			w.get_context_id()
		};

		let mqs_addr = ProvableAddress::from_pub_key(&secp, context_id, &mqs_pub_key)?;
		let tor_addr = ProvableAddress::from_tor_pub_key(&tor_pub_key)?;

		println!();
		println!("MQS public address:       {}", mqs_addr);
		println!("Tor/SlatepackTor address: {}", tor_addr);
		println!();
		Ok(())
	})?;
	Ok(())
}

/// Proof Export Args
pub struct ProofExportArgs {
	pub output_file: String,
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
}

fn write_tx_proof_export<P: AsRef<Path>>(path: P, proof: &TxProof) -> Result<(), Error> {
	let path = path.as_ref();
	replace_owner_only_file_with(path, |replacement| {
		serde_json::to_writer_pretty(replacement, proof).map_err(Into::into)
	})
	.map_err(|e| {
		Error::GenericError(format!(
			"Unable to serialize or save the proof file {}, {}",
			path.display(),
			e
		))
	})
}

pub fn proof_export<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofExportArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.get_stored_tx_proof(m, args.id, args.tx_slate_id);
		match result {
			Ok(p) => {
				write_tx_proof_export(&args.output_file, &p)?;
				warn!("Payment proof exported to {}", args.output_file);
				Ok(())
			}
			Err(e) => {
				error!("Proof export failed: {}", e);
				return Err(Error::GenericError(format!(
					"Unable to retrieve payment proof, {}",
					e
				)));
			}
		}
	})?;
	Ok(())
}

/// Proof Verify Args
pub struct ProofVerifyArgs {
	pub input_file: String,
}

pub fn proof_verify<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_keychain_mask: Option<&SecretKey>,
	args: ProofVerifyArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	//read the file.
	let input = &args.input_file;
	let mut executable_dir = std::env::current_exe().map_err(|e| {
		Error::LibWallet(format!(
			"Unable to resolve the wallet executable path while opening a payment proof: {}",
			e
		))
	})?;
	executable_dir.pop();
	let home_dir = executable_dir.to_str().ok_or_else(|| {
		Error::LibWallet(
			"Wallet executable directory is not valid UTF-8; payment proof path cannot be resolved"
				.to_string(),
		)
	})?;
	let path = Path::new(&input.replace("~", home_dir)).to_path_buf();
	if !path.exists() {
		let msg = format!("Unable to open payment proof file at {}", args.input_file);
		error!("{}", msg);
		return Err(Error::LibWallet(msg));
	}
	let mut file = File::open(path)
		.map_err(|e| Error::LibWallet(format!("Unable to open proof data, {}", e)))?;
	// The proof JSON contains TxProof.key (the slate decryption key). Keep the
	// raw buffer zeroized just like the parsed key is, on every exit path.
	let mut proof = Zeroizing::new(String::new());
	file.read_to_string(&mut *proof)
		.map_err(|e| Error::LibWallet(format!("Unable to read proof data, {}", e)))?;
	let tx_pf: TxProof = serde_json::from_str(proof.as_str())
		.map_err(|e| Error::LibWallet(format!("Unable to deserialize proof data, {}", e)))?;

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;

	let context_id = {
		wallet_lock!(owner_api.wallet_inst, w);
		w.get_context_id()
	};

	match mwc_wallet_libwallet::proof::tx_proof::verify_tx_proof_wrapper(context_id, &tx_pf, &secp)
	{
		Ok(proof_result) => {
			mwc_wallet_libwallet::proof::tx_proof::proof_ok(context_id, &proof_result);
			Ok(())
		}
		Err(e) => {
			error!(
				"Unable to verify proof. {}",
				escape_for_display(&e.to_string())
			);
			Err(Error::LibWallet(format!(
				"Proof not valid: {}",
				escape_for_display(&e.to_string())
			)))
		}
	}
}

pub fn dump_wallet_data<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	file_name: String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.dump_wallet_data(m, file_name.clone());
		match result {
			Ok(_) => {
				warn!("Data dump is finished: {}", file_name);
				Ok(())
			}
			Err(e) => {
				error!("Wallet Data dump failed: {}", e);
				Err(Error::LibWallet(format!("Wallet Data dump failed, {}", e)))
			}
		}
	})?;
	Ok(())
}

#[cfg(feature = "swaps")]
const MAX_SWAP_START_ERROR_DISPLAY_BYTES: usize = 2_048;

#[cfg(feature = "swaps")]
fn safe_swap_start_failure(error: &mwc_wallet_libwallet::Error) -> String {
	format!(
		"Unable to start Swap trade: {}",
		bounded_escape_for_display(&error.to_string(), MAX_SWAP_START_ERROR_DISPLAY_BYTES)
	)
}

#[cfg(feature = "swaps")]
const MAX_SWAP_OPERATION_ERROR_DISPLAY_BYTES: usize = 2_048;

#[cfg(feature = "swaps")]
fn safe_swap_operation_error(error: &mwc_wallet_libwallet::swap::Error) -> String {
	bounded_escape_for_display(&error.to_string(), MAX_SWAP_OPERATION_ERROR_DISPLAY_BYTES)
}

#[cfg(feature = "swaps")]
fn validate_swap_communication_destination(
	secp: &Secp256k1,
	context_id: u32,
	method: &str,
	destination: &str,
) -> Result<(), Error> {
	if destination.is_empty() {
		return Err(Error::ArgumentError(
			"Swap communication destination must not be empty".to_string(),
		));
	}

	match method {
		"mwcmqs" => {
			MWCMQSAddress::from_str(secp, context_id, destination)
				.map_err(|e| Error::ArgumentError(format!("Invalid destination address, {}", e)))?;
		}
		"tor" => {
			validate_tor_address(destination)
				.map_err(|e| Error::ArgumentError(format!("Invalid destination address, {}", e)))?;
		}
		"file" => (),
		_ => {
			return Err(Error::ArgumentError(format!(
				"Unknown communication method value '{}'",
				method
			)));
		}
	}

	Ok(())
}

#[cfg(feature = "swaps")]
fn current_autoswap_source_address(
	secp: &Secp256k1,
	context_id: u32,
	method: &str,
	destination: &str,
) -> Result<String, mwc_wallet_libwallet::swap::Error> {
	validate_swap_communication_destination(secp, context_id, method, destination).map_err(
		|e| {
			mwc_wallet_libwallet::swap::Error::MessageSender(format!(
				"Invalid current swap transport: {}",
				e
			))
		},
	)?;

	match method {
		"mwcmqs" => {
			let broker =
				mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).ok_or_else(|| {
					mwc_wallet_libwallet::swap::Error::MessageSender(
						"mwcmqs listener is not running; start it before retrying autoswap"
							.to_string(),
					)
				})?;
			broker
				.0
				.get_publisher_address()
				.map(|address| address.get_full_name())
				.map_err(|e| {
					mwc_wallet_libwallet::swap::Error::MessageSender(format!(
						"Unable to get the current mwcmqs publisher address: {}",
						e
					))
				})
		}
		"tor" => {
			if !controller::is_foreign_api_running(context_id) {
				return Err(mwc_wallet_libwallet::swap::Error::MessageSender(
					"Tor foreign API is not running; start it before retrying autoswap".to_string(),
				));
			}
			tor::status::get_tor_address(context_id).ok_or_else(|| {
				mwc_wallet_libwallet::swap::Error::MessageSender(
					"Tor listener has no current Onion address; retry after it is ready"
						.to_string(),
				)
			})
		}
		_ => Err(mwc_wallet_libwallet::swap::Error::MessageSender(format!(
			"Autoswap does not support the current communication method '{}'",
			method
		))),
	}
}

#[cfg(feature = "swaps")]
fn apply_offer_transport_identity(
	message: &mut message::Message,
	method: &str,
	from_address: String,
) -> Result<(), mwc_wallet_libwallet::swap::Error> {
	if let message::Update::Offer(offer_update) = &mut message.inner {
		if offer_update.communication_method != method {
			return Err(mwc_wallet_libwallet::swap::Error::InvalidMessageData(
				"Offer communication method does not match the locked outbound transport"
					.to_string(),
			));
		}
		offer_update.from_address = from_address;
	}
	Ok(())
}

// return swap Id
#[cfg(feature = "swaps")]
pub fn swap_start<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: &mwc_wallet_libwallet::api_impl::types::SwapStartArgs,
) -> Result<String, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let context_id = {
		wallet_lock!(owner_api.wallet_inst, w);
		w.get_context_id()
	};

	validate_swap_communication_destination(
		&secp,
		context_id,
		&args.buyer_communication_method,
		&args.buyer_communication_address,
	)?;

	let swap_id = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.swap_start(keychain_mask, args);
		match result {
			Ok(swap_id) => {
				if is_console_output_enabled() {
					println!("Seller Swap trade is created: {}", swap_id);
				}
				Ok(swap_id)
			}
			Err(e) => {
				let safe_failure = safe_swap_start_failure(&e);
				error!("{}", safe_failure);
				Err(Error::LibWallet(safe_failure))
			}
		}
	})?;
	Ok(swap_id)
}

#[cfg(feature = "swaps")]
const MAX_SWAP_OFFER_FILE_DISPLAY_BYTES: usize = 1_024;
#[cfg(feature = "swaps")]
const MAX_SWAP_OFFER_ERROR_DISPLAY_BYTES: usize = 2_048;

#[cfg(feature = "swaps")]
fn safe_swap_offer_failure(file: &str, error: &str) -> String {
	format!(
		"Unable to create a Swap trade from message {}: {}",
		bounded_escape_for_display(file, MAX_SWAP_OFFER_FILE_DISPLAY_BYTES),
		bounded_escape_for_display(error, MAX_SWAP_OFFER_ERROR_DISPLAY_BYTES)
	)
}

#[cfg(feature = "swaps")]
pub fn swap_create_from_offer<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	file: String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.swap_create_from_offer(keychain_mask, file.clone());
		match result {
			Ok(swap_id) => {
				warn!("Buyer Swap trade is created: {}", swap_id);
				Ok(())
			}
			Err(e) => {
				let safe_failure = safe_swap_offer_failure(&file, &e.to_string());
				error!("{}", safe_failure);
				Err(Error::LibWallet(safe_failure))
			}
		}
	})?;
	Ok(())
}

// Swap operation
#[derive(PartialEq)]
#[cfg(feature = "swaps")]
pub enum SwapSubcommand {
	List,
	ListAndCheck,
	Delete,
	Check,
	Process,
	Autoswap,
	Adjust,
	Dump,
	TradeExport,
	TradeImport,
}

/// Arguments for the swap command
#[cfg(feature = "swaps")]
pub struct SwapArgs {
	/// What we want to do with a swap
	pub subcommand: SwapSubcommand,
	/// Swap ID that will are working with
	pub swap_id: Option<String>,
	/// Action to process. Value must match expected
	pub adjust: Vec<String>,
	/// Transport that can be used for interaction
	pub method: Option<String>,
	/// Destination for messages that needed to be send
	pub destination: Option<String>,
	/// Apisecret of the other party of the swap. Zeroized on drop.
	pub apisecret: Option<Zeroizing<String>>,
	/// Secondary currency fee in the currency-specific human-readable unit.
	pub secondary_fee: Option<String>,
	/// File name with message content, if message need to be processed with files
	pub message_file_name: Option<String>,
	/// Refund address for the buyer
	pub buyer_refund_address: Option<String>,
	/// Whether to start listener or not for swap
	pub start_listener: bool,
	/// Secondary address for adjust
	pub secondary_address: Option<String>,
	/// Print output in Json format. Note, it is not for all cases.
	pub json_format: bool,
	/// ElectrumX URI1
	pub electrum_node_uri1: Option<String>,
	/// ElectrumX failover URI2
	pub electrum_node_uri2: Option<String>,
	/// Ethereum swap contract address. For an existing trade this must match its
	/// pinned address; it cannot override the trade.
	pub eth_swap_contract_address: Option<String>,
	/// ERC20 swap contract address. For an existing trade this must match its
	/// pinned address; it cannot override the trade.
	pub erc20_swap_contract_address: Option<String>,
	/// Ethereum Infura Project Id
	pub eth_infura_project_id: Option<String>,
	/// Redirect to users' private ethereum wallet
	pub eth_redirect_to_private_wallet: Option<bool>,
	/// Need to wait for the first backup.
	pub wait_for_backup1: bool,
	/// Assign tag to this trade
	pub tag: Option<String>,
	/// Explicitly discard an undelivered marketplace cancellation while deleting.
	pub discard_pending_marketplace_cancel: bool,
}

/// Eth operation
#[derive(PartialEq)]
#[cfg(feature = "swaps")]
pub enum EthSubcommand {
	Info,
	Send,
}
/// Arguments for the eth command
#[cfg(feature = "swaps")]
pub struct EthArgs {
	/// eth subcommand
	pub subcommand: EthSubcommand,
	/// currency
	pub currency: Currency,
	/// dest address
	pub dest: Option<String>,
	/// amount
	pub amount: Option<String>,
}

// Integrity operation
#[derive(PartialEq)]
#[cfg(feature = "swaps")]
pub enum IntegritySubcommand {
	Check,
	Create,
	Withdraw,
}

/// Arguments for the integrity command
#[cfg(feature = "swaps")]
pub struct IntegrityArgs {
	/// What we want to do with integrity kernels
	pub subcommand: IntegritySubcommand,
	/// Account name for Create and Withdraw.
	pub account: Option<String>,
	/// How much MWC to reserve in case if there are not enough funds.
	pub reserve: Option<u64>,
	/// How much fees to pay
	pub fee: Vec<u64>,
	/// Print output in Json format
	pub json: bool,
}

/// Arguments for the messaging command
#[cfg(feature = "swaps")]
pub struct MessagingArgs {
	/// Show status of the messaging pool
	pub show_status: bool,
	/// Topic to add
	pub add_topic: Option<String>,
	/// The integrity fee to pay or filter
	pub fee: Option<u64>,
	/// The integrity fee transaction Uuid
	pub fee_uuid: Option<Uuid>,
	/// Topic to remove from listening
	pub remove_topic: Option<String>,
	/// Message to start publishing
	pub publish_message: Option<String>,
	/// Topic to start publishing the message
	pub publish_topic: Option<String>,
	/// Message publishing interval in second
	pub publish_interval: Option<u32>,
	/// Withdraw publishing of the message
	pub withdraw_message_id: Option<String>,
	/// Print new messages. If parameter is true - messages will be deleted form the buffer
	pub receive_messages: Option<bool>,
	/// Check if integrity message contexts are expired
	pub check_integrity_expiration: bool,
	/// Retain expired messages
	pub check_integrity_retain: bool,
	/// Print output in Json format
	pub json: bool,
}

/// Arguments for send marketplace message
#[cfg(feature = "swaps")]
pub struct SendMarketplaceMessageArgs {
	/// marketplace command
	pub command: String,
	/// Offer id
	pub offer_id: String,
	/// wallet address to send the message
	pub tor_address: String,
	/// Swap id bound into destructive marketplace commands.
	pub swap_id: Option<Uuid>,
	/// Stable nonce for retrying a durable marketplace notification.
	pub nonce: Option<Uuid>,
	/// Address index pinned when the original marketplace bid was signed.
	pub signing_address_index: Option<u32>,
}

/// Validated application-level result of a marketplace command.
#[cfg(feature = "swaps")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarketplaceMessageOutcome {
	/// Result of checking whether an offer is still published. `None` means the
	/// remote wallet explicitly reported that the offer does not exist.
	OfferChecked { running: Option<u64> },
	/// The remote wallet accepted the request for an available offer.
	OfferAccepted { running: u64 },
	/// The remote wallet explicitly confirmed cancellation.
	CancellationAcknowledged,
}

// For Json we can't use int 64, we have to convert all of them to Strings
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
#[cfg(feature = "swaps")]
pub struct StateEtaInfoString {
	/// True if this is current active state
	pub active: bool,
	/// Name of the state to show for user
	pub name: String,
	/// Starting time
	pub end_time: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
#[cfg(feature = "swaps")]
pub struct SwapJournalRecordString {
	/// Unix timestamp, when event happens
	pub time: String,
	/// Description with what happens at that time.
	pub message: String,
}

#[cfg(feature = "swaps")]
fn warn_pending_marketplace_cancel_failure(failure: String) {
	let failure = bounded_escape_for_display(&failure, 4096);
	warn!("Marketplace cancellation remains pending: {}", failure);
	// Keep direct console diagnostics on stdout, consistently with the rest of
	// the wallet CLI. This is best-effort and must not abort swap processing if
	// the output stream is unavailable.
	if is_console_output_enabled() {
		let _ = writeln!(
			std::io::stdout(),
			"WARNING: Marketplace cancellation remains pending: {}",
			failure
		);
	}
}

#[cfg(feature = "swaps")]
fn warn_marketplace_cancel_completion_uncertain(failure: String) {
	let failure = bounded_escape_for_display(&failure, 4096);
	warn!(
		"Marketplace cancellation completion needs reconciliation: {}",
		failure
	);
	if is_console_output_enabled() {
		let _ = writeln!(
			std::io::stdout(),
			"WARNING: Marketplace cancellation completion needs reconciliation: {}",
			failure
		);
	}
}

#[cfg(feature = "swaps")]
/// Best-effort delivery of durable marketplace cancellation notifications.
///
/// This intentionally returns `()` rather than `Result<(), Error>`. Delivery and
/// durable-completion failures are reported individually. Delivery failures remain pending;
/// a completion-write failure leaves the active record discoverable so a later scan observes
/// either its pending or completed version. Propagating one of those failures would allow an
/// unavailable or uncooperative peer to abort an unrelated, time-critical swap command before
/// it can redeem or refund funds.
fn notify_about_cancelled_swaps<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: &TorConfig,
	cancelled_swaps: Vec<owner_swap::MarketplaceCancelNotification>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	if cancelled_swaps.is_empty() {
		return;
	}

	// Notify peers about the cancellation. This is synchronous: there are no
	// background autoswap threads anymore, so nothing here can outlive the
	// wallet context it uses.
	let secp = match Secp256k1::with_caps(ContextFlag::Commit) {
		Ok(secp) => secp,
		Err(e) => {
			warn_pending_marketplace_cancel_failure(format!(
				"Unable to initialize cancellation notification delivery: {}",
				bounded_escape_for_display(&e.to_string(), 2048)
			));
			return;
		}
	};
	for notification in cancelled_swaps {
		match send_marketplace_message(
			wallet_inst.clone(),
			keychain_mask,
			tor_config,
			SendMarketplaceMessageArgs {
				command: "fail_bidding".to_string(),
				offer_id: notification.offer_id.clone(),
				tor_address: notification.peer_address.clone(),
				swap_id: Some(notification.swap_id),
				nonce: Some(notification.nonce),
				signing_address_index: notification.signing_address_index,
			},
		) {
			Ok(_) => {
				if let Err(e) = owner_swap::complete_marketplace_cancel_notification(
					wallet_inst.clone(),
					&secp,
					keychain_mask,
					&notification,
				) {
					warn_marketplace_cancel_completion_uncertain(format!(
						"Marketplace cancellation for swap {} was delivered but its durable record could not be completed: {}",
						notification.swap_id,
						bounded_escape_for_display(&e.to_string(), 2048)
					));
				}
			}
			Err(e) => warn_pending_marketplace_cancel_failure(format!(
				"Unable to send fail_bidding for swap {} to wallet {}: {}",
				notification.swap_id,
				bounded_escape_for_display(&notification.peer_address, 1024),
				bounded_escape_for_display(&e.to_string(), 2048)
			)),
		}
	}
}

#[cfg(feature = "swaps")]
fn retry_pending_marketplace_cancel_notifications<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: &TorConfig,
	secp: &Secp256k1,
	mut pending: Vec<owner_swap::MarketplaceCancelNotification>,
) where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let scan = match owner_swap::pending_marketplace_cancel_notifications(
		wallet_inst.clone(),
		secp,
		keychain_mask,
	) {
		Ok(scan) => scan,
		Err(e) => {
			warn_pending_marketplace_cancel_failure(format!(
				"Unable to inspect the durable marketplace cancellation outbox: {}",
				bounded_escape_for_display(&e.to_string(), 2048)
			));
			return;
		}
	};
	for failure in scan.failures {
		warn_pending_marketplace_cancel_failure(format!(
			"Unable to inspect swap {} in the durable outbox: {}",
			failure.swap_id,
			bounded_escape_for_display(&failure.error, 2048)
		));
	}

	pending.extend(scan.pending);
	let mut seen = HashSet::new();
	pending.retain(|notification| seen.insert((notification.swap_id, notification.nonce)));
	notify_about_cancelled_swaps(wallet_inst.clone(), keychain_mask, tor_config, pending);
}

#[cfg(feature = "swaps")]
pub fn swap<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	api_listen_addr: Option<String>,
	mqs_config: MQSConfig,
	tor_config: TorConfig,
	args: SwapArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut args = args;
	if let Some(swap_id) = args.swap_id.as_deref() {
		args.swap_id = Some(
			trades::canonical_swap_id(swap_id)
				.map_err(|e| Error::ArgumentError(format!("Invalid 'swap_id' argument: {}", e)))?,
		);
	}

	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};

	let (context_id, base_dir) = {
		wallet_lock!(wallet_inst, w);
		(w.get_context_id(), w.get_data_file_dir().to_string())
	};

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	// A malformed pending record must not prevent the two commands that can
	// repair it. Those branches retry delivery immediately after the repair.
	// Marketplace recovery is also kept out of the pre-dispatch path for
	// time-critical commands. Their action runs first; only then do we scan the
	// nonblocking durable outbox, including cancellations for a replaced winner.
	match &args.subcommand {
		SwapSubcommand::Adjust
		| SwapSubcommand::Delete
		| SwapSubcommand::TradeImport
		| SwapSubcommand::Process
		| SwapSubcommand::Autoswap
		| SwapSubcommand::Check => {}
		_ => retry_pending_marketplace_cancel_notifications(
			wallet_inst.clone(),
			keychain_mask,
			&tor_config,
			&secp,
			Vec::new(),
		),
	}

	match args.subcommand {
		SwapSubcommand::List | SwapSubcommand::ListAndCheck => {
			let result = owner_swap::swap_list(
				wallet_inst.clone(),
				&mut secp,
				keychain_mask,
				args.subcommand == SwapSubcommand::ListAndCheck,
			);
			match result {
				Ok((list, cancelled_swaps)) => {
					notify_about_cancelled_swaps(
						wallet_inst.clone(),
						keychain_mask,
						&tor_config,
						cancelled_swaps,
					);

					if args.json_format {
						let mut res = Vec::new();

						for swap_info in list {
							let item = serde_json::json!({
								"is_seller" : swap_info.is_seller,
								"secondary_address" : swap_info.secondary_address,
								"mwc_amount" : swap_info.mwc_amount,
								"secondary_amount" : swap_info.secondary_amount,
								"secondary_currency" : swap_info.secondary_currency,
								"swap_id": swap_info.swap_id,
								"tag" : swap_info.tag.clone().unwrap_or("".to_string()),
								"state" : swap_info.state.to_string(),
								"state_cmd" : swap_info.state.to_cmd_str(),
								"action" : swap_info.action.unwrap_or(Action::None).to_string(),
								"expiration" : swap_info.expiration.unwrap_or(0).to_string(),
								"start_time" : swap_info.trade_start_time.to_string(),
								"last_process_error" : swap_info.last_error.clone(),
							});
							res.push(item);
						}
						println!("JSON: {}", serde_json::value::Value::Array(res).to_string());
					} else {
						if list.is_empty() {
							println!("You don't have any Swap trades");
						} else {
							display::swap_trades(
								list.iter()
									.map(|v| (v.swap_id.clone(), v.state.to_string()))
									.collect(),
							);
							for swap_info in list.iter().filter(|swap| swap.last_error.is_some()) {
								println!(
									"Swap {} check error: {}",
									swap_info.swap_id,
									bounded_escape_for_display(
										swap_info.last_error.as_deref().unwrap_or_default(),
										MAX_CANCEL_ERROR_BYTES
									)
								);
							}
						}
					}
					Ok(())
				}
				Err(e) => {
					error!("Unable to List Swap trades: {}", e);
					Err(Error::LibWallet(format!(
						"Unable to List Swap trades: {}",
						e
					)))
				}
			}
		}
		SwapSubcommand::Delete => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let result = if args.discard_pending_marketplace_cancel {
				warn!(
					"Explicitly discarding any pending marketplace cancellation for swap {}",
					swap_id
				);
				owner_swap::swap_delete_discarding_pending_marketplace_cancel(
					wallet_inst,
					&secp,
					keychain_mask,
					&swap_id,
				)
			} else {
				owner_swap::swap_delete(wallet_inst, &secp, keychain_mask, &swap_id)
			};
			match result {
				Ok(_) => {
					println!("Swap trade {} was sucessfully deleted.", swap_id);
					Ok(())
				}
				Err(e) => {
					error!("Unable to delete Swap {}: {}", swap_id, e);
					Err(Error::LibWallet(format!(
						"Unable to delete Swap {}: {}",
						swap_id, e
					)))
				}
			}
		}
		SwapSubcommand::Adjust => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			// Checking parameters here. We can't do that at libwallet side
			if let Some(method) = args.method.clone() {
				let destination = args.destination.clone().ok_or(Error::ArgumentError(
					"Please specify '--dest' parameter as well".to_string(),
				))?;
				validate_swap_communication_destination(&secp, context_id, &method, &destination)?;
			}

			let mut secondary_address = None;
			if args.buyer_refund_address.is_some() {
				secondary_address = args.buyer_refund_address.clone();
			}
			if args.secondary_address.is_some() {
				secondary_address = args.secondary_address.clone();
			}

			let mut res_state = StateId::BuyerCancelled;
			for adjust_cmd in args.adjust {
				let result = owner_swap::swap_adjust(
					wallet_inst.clone(),
					&mut secp,
					keychain_mask,
					&swap_id,
					&adjust_cmd,
					args.method.clone(),
					args.destination.clone(),
					secondary_address.clone(),
					args.secondary_fee.clone(),
					args.electrum_node_uri1.clone(),
					args.electrum_node_uri2.clone(),
					args.eth_infura_project_id.clone(),
					args.tag.clone(),
				);
				match result {
					Ok((state, _action)) => {
						res_state = state;
					}
					Err(e) => {
						let safe_error = safe_swap_operation_error(&e);
						error!("Unable to adjust the Swap {}: {}", swap_id, safe_error);
						return Err(Error::LibWallet(format!(
							"Unable to adjust Swap {}: {}",
							swap_id, safe_error
						)));
					}
				}
			}

			println!(
				"Swap trade {} was successfully adjusted. New state: {}",
				swap_id, res_state
			);
			retry_pending_marketplace_cancel_notifications(
				wallet_inst.clone(),
				keychain_mask,
				&tor_config,
				&secp,
				Vec::new(),
			);
			Ok(())
		}
		SwapSubcommand::Check => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let (status, cancelled_swaps) = owner_swap::update_swap_status_snapshot(
				wallet_inst.clone(),
				&mut secp,
				keychain_mask,
				&swap_id,
				args.electrum_node_uri1,
				args.electrum_node_uri2,
				args.eth_swap_contract_address,
				args.erc20_swap_contract_address,
				args.eth_infura_project_id,
				args.wait_for_backup1,
			)
			.map_err(|e| {
				let safe_error = safe_swap_operation_error(&e);
				error!("Unable to check Swap {}: {}", swap_id, safe_error);
				Error::LibWallet(format!("Unable to check Swap {}: {}", swap_id, safe_error))
			})?;

			retry_pending_marketplace_cancel_notifications(
				wallet_inst.clone(),
				keychain_mask,
				&tor_config,
				&secp,
				cancelled_swaps,
			);

			let swap = &status.swap;
			let conf_status = &status.confirmations;
			let lock_height = swap.refund_slate.slate.get_lock_height_check()?;
			let mwc_lock_time = if !conf_status.mwc_observed {
				None
			} else if conf_status.mwc_tip < lock_height {
				let now_timestamp = Utc::now().timestamp();
				let now = u64::try_from(now_timestamp).map_err(|e| {
					Error::DataOverflow(format!(
						"command::swap, system time is before the Unix epoch or does not fit u64, timestamp={} error={}",
						now_timestamp, e
					))
				})?;
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the branch checks mwc_tip < lock_height"
				)]
				let remaining_blocks = lock_height - conf_status.mwc_tip;
				let remaining_seconds = remaining_blocks.checked_mul(60).ok_or_else(|| {
					Error::DataOverflow(format!(
						"command::swap, MWC lock duration overflow, remaining_blocks={} seconds_per_block=60",
						remaining_blocks
					))
				})?;
				Some(now.checked_add(remaining_seconds).ok_or_else(|| {
					Error::DataOverflow(format!(
						"command::swap, MWC lock timestamp overflow, now={} remaining_seconds={}",
						now, remaining_seconds
					))
				})?)
			} else {
				Some(0)
			};

			let road_map_to_print: Vec<StateEtaInfoString> = status
				.roadmap
				.iter()
				.map(|r| StateEtaInfoString {
					active: r.active,
					name: r.name.clone(),
					end_time: r.end_time.map(|r| r.to_string()),
				})
				.collect();
			let journal_records_to_print: Vec<SwapJournalRecordString> = status
				.swap
				.journal
				.iter()
				.map(|j| SwapJournalRecordString {
					time: j.time.to_string(),
					message: j.message.to_string(),
				})
				.collect();

			if args.json_format {
				let secondary_lock_time = swap.get_time_secondary_lock_publish()?;
				let item = serde_json::json!({
					"swapId" : swap.id.to_string(),
					"isSeller" : swap.is_seller(),
					"mwcAmount": core::amount_to_hr_string(swap.primary_amount, true),
					"secondaryCurrency" : swap.secondary_currency.to_string(),
					"secondaryAmount" : swap.secondary_currency.amount_to_hr_string(swap.secondary_amount, true),
					"secondaryAddress" : swap.get_secondary_address(),
					"secondaryFee" : swap.secondary_fee_units.to_string(),
					"secondaryFeeUnits" : swap.secondary_currency.get_fee_units(),
					"mwcConfirmations" : swap.mwc_confirmations,
					"secondaryConfirmations" : swap.secondary_confirmations,
					"messageExchangeTimeLimit" : swap.message_exchange_time_sec,
					"redeemTimeLimit" : swap.redeem_time_sec,
					"sellerLockingFirst" : swap.seller_lock_first,
					"mwcLockHeight" : swap.refund_slate.slate.get_lock_height(),
					"mwcLockTime" : mwc_lock_time.map(|time| time.to_string()),
					"secondaryLockTime" : secondary_lock_time.to_string(),
					"communicationMethod" : swap.communication_method.clone(),
					"communicationAddress" : swap.communication_address.clone(),
					"last_process_error" : swap.get_last_error(),
					"currentAction": status.action.to_string(),
					"roadmap" : road_map_to_print,
					"journal_records" : journal_records_to_print,
					"electrumNodeUri1" : swap.electrum_node_uri1.clone().unwrap_or_default(),
					"electrumNodeUri2" : swap.electrum_node_uri2.clone().unwrap_or_default(),
					"eth_swap_contract_address": swap.eth_swap_contract_address.clone().unwrap_or_default(),
					"erc20_swap_contract_address": swap.erc20_swap_contract_address.clone().unwrap_or_default(),
					"eth_infura_project_id": swap.eth_infura_project_id.clone().unwrap_or_default(),
				});
				println!("JSON: {}", item.to_string());
			} else {
				display::swap_trade(
					swap,
					&status.action,
					&status.time_limit,
					conf_status,
					&status.roadmap,
					&status.swap.journal,
					true,
				)?;
			}
			Ok(())
		}
		SwapSubcommand::Process => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			match (&args.method, &args.destination) {
				(None, None) => (),
				(Some(method), Some(destination)) => {
					validate_swap_communication_destination(
						&secp,
						context_id,
						method,
						destination,
					)?;
					// Values supplied through this owner command have owner provenance.
					// Persist them before processing so libwallet can distinguish them
					// from the transport hint embedded in an incoming offer.
					owner_swap::swap_adjust(
						wallet_inst.clone(),
						&mut secp,
						keychain_mask,
						&swap_id,
						"destination",
						Some(method.clone()),
						Some(destination.clone()),
						None,
						None,
						None,
						None,
						None,
						None,
					)?;
				}
				_ => {
					return Err(Error::ArgumentError(
						"swap --process requires both '--method' and '--dest' when overriding the stored transport"
							.to_string(),
					));
				}
			}

			// Creating message delivery transport as a closure
			// Shared ownership of the secret avoids plaintext clones; it is zeroized
			// when the last reference is dropped.
			let apisecret = args.apisecret.clone().map(Arc::new);
			let swap_id2 = swap_id.clone();
			let wallet_inst2 = wallet_inst.clone();
			let tor_config2 = tor_config.clone();
			let message_sender = move |swap_message: message::Message,
			                           method: String,
			                           dest: String,
			                           secp: &Secp256k1|
			      -> Result<
				(bool, String),
				mwc_wallet_libwallet::swap::Error,
			> {
				let destination_str = format!("{} {}", method, dest);

				// Starting the listener first. For this case we know that they are not started yet
				// And there will be a single call only.
				let from_address = match method.as_str() {
					"mwcmqs" => {
						if mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).is_none() {
							controller::start_mwcmqs_listener(
								wallet_inst2,
								mqs_config.clone(),
								false,
								Arc::new(Mutex::new(km)),
								true,
							)
							.map_err(|e| {
								mwc_wallet_libwallet::swap::Error::MessageSender(format!(
									"Unable to start mwcmqs listener, {}",
									e
								))
							})?;
							thread::sleep(Duration::from_millis(2000));
						}
						mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id)
							.ok_or(mwc_wallet_libwallet::swap::Error::MessageSender(
								"Unable to start mwcmqs listener".to_string(),
							))?
							.0
							.get_publisher_address()
							.map_err(|e| {
								mwc_wallet_libwallet::swap::Error::MessageSender(format!(
									"Unable to get publisher address {}",
									e
								))
							})?
							.get_full_name()
					}
					"tor" => {
						if !controller::is_foreign_api_running(context_id) {
							controller::foreign_listener(
								wallet_inst2,
								Arc::new(Mutex::new(km)),
								api_listen_addr.clone(),
								&tor_config2,
								true,
								None,
							)
							.map_err(|e| {
								mwc_wallet_libwallet::swap::Error::Generic(format!(
									"Failed to start foreign listener, {}",
									e
								))
							})?;
							thread::sleep(Duration::from_millis(2000));
						}
						tor::status::get_tor_address(context_id).ok_or(
							mwc_wallet_libwallet::swap::Error::MessageSender(
								"Tor is not running".to_string(),
							),
						)?
					}
					// File replies require a path selected independently by the peer, so
					// the offer must not advertise our local output path as a return address.
					"file" => String::new(),
					_ => {
						error!(
							"Please specify a method (mwcmqs, tor, or file) for transporting swap messages to the other party with whom you're doing the swap!"
						);
						return Err(mwc_wallet_libwallet::swap::Error::MessageSender(
							"Expected 'method' argument is not found".to_string(),
						));
					}
				};

				let mut swap_message = swap_message;
				apply_offer_transport_identity(&mut swap_message, method.as_str(), from_address)?;

				if method == "file" {
					let msg_str = swap_message.to_json()?;
					file::replace_owner_only_file(&dest, msg_str.as_bytes()).map_err(|e| {
						mwc_wallet_libwallet::swap::Error::MessageSender(format!(
							"Unable to store swap message file {}, {}",
							dest, e
						))
					})?;
					println!("Message is written into the file {}", dest);
					// A file transport counts durable handoff as acknowledgement. The
					// replacement helper synchronizes both the file and its directory.
					return Ok((true, destination_str));
				}

				// File is processed, the online send will be handled here
				let sender = create_swap_message_sender(
					context_id,
					method.as_str(),
					dest.as_str(),
					&apisecret,
					&tor_config2,
					Path::new(&base_dir),
				)
				.map_err(|e| {
					mwc_wallet_libwallet::swap::Error::MessageSender(format!(
						"Unable to create message sender, {}",
						e
					))
				})?;

				let ack = sender
					.send_swap_message(&swap_message, secp)
					.map_err(|e| {
						mwc_wallet_libwallet::swap::Error::MessageSender(format!(
							"Failure in sending swap message {} by {}: {}",
							swap_id2, method, e
						))
					})
					.map_err(|e| {
						mwc_wallet_libwallet::swap::Error::MessageSender(format!(
							"Unable to deliver the message, {}",
							e
						))
					})?;
				Ok((ack, destination_str))
			};

			let result = owner_swap::swap_process(
				wallet_inst.clone(),
				&mut secp,
				keychain_mask,
				&swap_id,
				message_sender,
				args.message_file_name,
				args.buyer_refund_address,
				args.secondary_fee,
				args.secondary_address,
				args.electrum_node_uri1,
				args.electrum_node_uri2,
				args.eth_infura_project_id,
				args.wait_for_backup1,
			);

			match result {
				Ok((_, cancelled_swaps)) => {
					retry_pending_marketplace_cancel_notifications(
						wallet_inst.clone(),
						keychain_mask,
						&tor_config,
						&secp,
						cancelled_swaps,
					);
					Ok(())
				}
				Err(e) => {
					retry_pending_marketplace_cancel_notifications(
						wallet_inst.clone(),
						keychain_mask,
						&tor_config,
						&secp,
						Vec::new(),
					);
					let safe_error = safe_swap_operation_error(&e);
					error!("Unable to process Swap {}: {}", swap_id, safe_error);
					Err(Error::LibWallet(format!(
						"Unable to process Swap {}: {}",
						swap_id, safe_error
					)))
				}
			}
		}
		SwapSubcommand::Autoswap => {
			// One shot mode: a single swap step is executed synchronously.
			// --json_format only selects the output format (JSON status line
			// for scripting, regular trade display otherwise).
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			if args.method.is_some() || args.destination.is_some() {
				return Err(Error::ArgumentError(
					"swap --autoswap doesn't accept 'method' or 'dest' parameters, instead it is using parameters associated with this swap trade.".to_string()));
			}

			let swap = owner_swap::swap_get(wallet_inst.clone(), &secp, keychain_mask, &swap_id)?;

			let wallet_inst2 = wallet_inst.clone();

			if args.start_listener {
				match swap.communication_method.as_str() {
					"mwcmqs" => {
						if mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).is_some() {
							return Err(Error::GenericError("mwcmqs listener is already running, there is no need to specify '--start_listener' parameter".to_string()));
						}

						// Startting MQS
						controller::start_mwcmqs_listener(
							wallet_inst,
							mqs_config.clone(),
							false,
							Arc::new(Mutex::new(km)),
							true,
						)
						.map_err(|e| {
							Error::LibWallet(format!("Unable to start mwcmqs listener, {}", e))
						})?;
						thread::sleep(Duration::from_millis(2000));
					}
					"tor" => {
						// Checking is foreign API is running. It dont't important if it is tor or http.
						if controller::is_foreign_api_running(context_id) {
							return Err(Error::GenericError("tor or http listener is already running, there is no need to specify '--start_listener' parameter".to_string()));
						}
						controller::foreign_listener(
							wallet_inst,
							Arc::new(Mutex::new(km)),
							api_listen_addr.clone(),
							&tor_config,
							true,
							None,
						)?;
						thread::sleep(Duration::from_millis(2000));
					}
					_ => {
						return Err(Error::ArgumentError(format!(
							"Auto Swap doesn't support communication method {}",
							swap.communication_method
						)));
					}
				}
			}

			// Creating message delivery transport as a closure
			// Shared ownership of the secret avoids plaintext clones; it is zeroized
			// when the last reference is dropped.
			let apisecret = args.apisecret.clone().map(Arc::new);
			let swap_id2 = swap_id.clone();
			let tor_config2 = tor_config.clone();
			let base_dir2 = base_dir.clone();
			let message_sender = move |swap_message: message::Message,
			                           method: String,
			                           destination: String,
			                           secp: &Secp256k1|
			      -> Result<
				(bool, String),
				mwc_wallet_libwallet::swap::Error,
			> {
				let from_address = current_autoswap_source_address(
					secp,
					context_id,
					method.as_str(),
					destination.as_str(),
				)?;
				let mut swap_message = swap_message;
				apply_offer_transport_identity(&mut swap_message, method.as_str(), from_address)?;

				// File is processed, the online send will be handled here
				let sender = create_swap_message_sender(
					context_id,
					method.as_str(),
					destination.as_str(),
					&apisecret,
					&tor_config2,
					Path::new(&base_dir2),
				)
				.map_err(|e| {
					mwc_wallet_libwallet::swap::Error::MessageSender(format!(
						"Unable to create message sender, {}",
						e
					))
				})?;

				let ack = sender.send_swap_message(&swap_message, secp).map_err(|e| {
					mwc_wallet_libwallet::swap::Error::MessageSender(format!(
						"Unable to deliver the message {} by {}: {}",
						swap_id2, method, e
					))
				})?;
				Ok((ack, format!("{} {}", method, destination)))
			};

			// Refresh the trade state and execute a single step. There is no
			// background worker anymore, so errors are simply returned to the
			// caller, who can fix the problem and re-run the command.
			let (mut status, mut cancelled_swaps_to_notify) =
				owner_swap::update_swap_status_snapshot(
					wallet_inst2.clone(),
					&mut secp,
					keychain_mask,
					&swap_id,
					args.electrum_node_uri1,
					args.electrum_node_uri2,
					args.eth_swap_contract_address,
					args.erc20_swap_contract_address,
					args.eth_infura_project_id,
					args.wait_for_backup1,
				)?;

			let autoswap_step = (|| -> Result<(), Error> {
				// Autoswap has to be sure that ALL parameters are defined. There are multiple steps and potentioly all of them can be used.
				// We are checking them here because the swap object is known, so the second currency is known. And we can validate the data
				if !status.swap.is_seller() {
					match &args.buyer_refund_address {
						Some(addr) => status
							.swap
							.secondary_currency
							.validate_address(context_id, addr)
							.map_err(|e| {
								Error::ArgumentError(format!(
									"Invalid secondary currency address {}, {}",
									addr, e
								))
							})?,
						None => {
							if status.swap.get_secondary_address().is_empty()
								&& status.swap.secondary_currency.is_btc_family()
							{
								return Err(Error::GenericError(
									"Please define buyer_refund_address for automated swap"
										.to_string(),
								));
							}
						}
					}
				}

				// If action require execution - it must be executed
				if !status.state.is_final_state() && status.action.can_execute() {
					match owner_swap::swap_process(
						wallet_inst2.clone(),
						&mut secp,
						keychain_mask,
						swap_id.as_str(),
						message_sender.clone(),
						args.message_file_name.clone(),
						args.buyer_refund_address.clone(),
						args.secondary_fee.clone(),
						args.secondary_address.clone(),
						None,
						None, // URIs was already updated before. No need to update the same.
						None,
						args.wait_for_backup1,
					) {
						Ok((_, cancelled_swaps)) => {
							cancelled_swaps_to_notify.extend(cancelled_swaps);
							let (post_process_status, cancelled_swaps) =
								owner_swap::update_swap_status_snapshot(
									wallet_inst2.clone(),
									&mut secp,
									keychain_mask,
									&swap_id,
									None,
									None,
									None,
									None,
									None,
									args.wait_for_backup1,
								)?;
							cancelled_swaps_to_notify.extend(cancelled_swaps);
							status = post_process_status;
						}
						Err(e) => {
							let safe_error = safe_swap_operation_error(&e);
							error!("Error during Swap {}: {}", swap_id, safe_error);
							return Err(Error::LibWallet(format!(
								"Unable to process Swap {}: {}",
								swap_id, safe_error
							)));
						}
					}
				}
				Ok(())
			})();

			// Marketplace outbox work is ancillary. Run it only after the
			// time-critical autoswap action has had a chance to execute, and do
			// not replace the result of that action with a notification error.
			retry_pending_marketplace_cancel_notifications(
				wallet_inst2.clone(),
				keychain_mask,
				&tor_config,
				&secp,
				cancelled_swaps_to_notify,
			);
			autoswap_step?;

			if args.json_format {
				let road_map_to_print: Vec<StateEtaInfoString> = status
					.roadmap
					.iter()
					.map(|r| StateEtaInfoString {
						active: r.active,
						name: r.name.clone(),
						end_time: r.end_time.map(|r| r.to_string()),
					})
					.collect();

				let journal_records_to_print: Vec<SwapJournalRecordString> = status
					.swap
					.journal
					.iter()
					.map(|j| SwapJournalRecordString {
						time: j.time.to_string(),
						message: j.message.clone(),
					})
					.collect();

				let item = serde_json::json!({
					"swap_id" : swap_id.clone(),
					"stateCmd" : status.state.to_cmd_str(),
					"last_process_error" : status.swap.get_last_error(),
					"currentAction": status.action.to_string(),
					"currentState" : status.state.to_string(),
					"roadmap" : road_map_to_print,
					"journal_records" : journal_records_to_print,
				});
				println!("JSON: {}", item.to_string());
			} else {
				display::swap_trade(
					&status.swap,
					&status.action,
					&status.time_limit,
					&status.confirmations,
					&status.roadmap,
					&status.swap.journal,
					true,
				)?;
			}

			Ok(())
		}
		SwapSubcommand::Dump => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let result = owner_swap::swap_dump(wallet_inst, &secp, keychain_mask, &swap_id);
			match result {
				Ok(dump_str) => {
					println!("{}", dump_str);
					Ok(())
				}
				Err(e) => {
					error!(
						"Unable to dump the content of the swap file {}.swap: {}",
						swap_id, e
					);
					Err(Error::LibWallet(format!(
						"Unable to dump the content of the swap file {}.swap: {}",
						swap_id, e
					)))
				}
			}
		}
		SwapSubcommand::TradeExport => {
			let swap_id = args.swap_id.ok_or(Error::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			let file_name = args.destination.ok_or(Error::ArgumentError(
				"Not found expected file name for the exported data".to_string(),
			))?;

			let swap_lock = trades::get_swap_lock(context_id, &swap_id)
				.map_err(|e| Error::LibWallet(format!("Unable to export trade data, {}", e)))?;
			let _guard = swap_lock.lock();
			trades::export_trade(
				context_id,
				swap_id.as_str(),
				file_name.as_str(),
				&*swap_lock,
			)
			.map_err(|e| Error::LibWallet(format!("Unable to export trade data, {}", e)))?;

			println!("Swap trade is exported to {}", file_name);
			Ok(())
		}
		SwapSubcommand::TradeImport => {
			let trade_file_name = args.destination.ok_or(Error::ArgumentError(
				"Not found expected file name for the exported data".to_string(),
			))?;

			let swap_id = owner_swap::swap_import_trade(
				wallet_inst.clone(),
				&secp,
				keychain_mask,
				trade_file_name.as_str(),
			)?;
			println!(
				"Swap trade {} is restored from the file {}",
				swap_id, trade_file_name
			);
			retry_pending_marketplace_cancel_notifications(
				wallet_inst.clone(),
				keychain_mask,
				&tor_config,
				&secp,
				Vec::new(),
			);
			Ok(())
		}
	}
}

#[cfg(feature = "swaps")]
pub fn eth<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	args: EthArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	match args.subcommand {
		EthSubcommand::Info => {
			let (address, height, balance) =
				owner_eth::info(wallet_inst.clone(), keychain_mask, args.currency)?;
			display::eth_info(address, height, balance, args.currency);
			Ok(())
		}
		EthSubcommand::Send => {
			let currency = args.currency;
			let dest = args.dest;
			let amount = args.amount;
			let (dest, amount) = match (dest, amount) {
				(Some(dest), Some(amount)) => (dest, amount),
				_ => {
					return Err(Error::ArgumentError(
						"Please specify destination address and amount".to_owned(),
					));
				}
			};

			let tx_hash = owner_eth::transfer(
				wallet_inst.clone(),
				keychain_mask,
				currency,
				dest.clone(),
				&amount,
			)?;
			println!(
				"Transfer {} {} to {} submitted. Transaction hash: {:?}",
				currency, amount, dest, tx_hash
			);
			Ok(())
		}
	}
}

#[cfg(feature = "swaps")]
fn marketplace_message_requires_foreign_api_listener(command: &str) -> bool {
	matches!(command, "accept_offer" | "check_offer")
}

#[cfg(feature = "swaps")]
fn parse_marketplace_message_outcome(
	command: &str,
	offer_id: &str,
	response: &str,
) -> Result<MarketplaceMessageOutcome, Error> {
	match command {
		"accept_offer" | "check_offer" => {
			if !response.trim_start().starts_with('{') {
				return Err(Error::MarketplaceResponse(format!(
					"{} returned a malformed acknowledgement: expected a top-level JSON object",
					command
				)));
			}
			let acknowledgement: MarketplaceOfferStatusAck = serde_json::from_str(response)
				.map_err(|e| {
					Error::MarketplaceResponse(format!(
						"{} returned a malformed acknowledgement: {}",
						command,
						bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
					))
				})?;
			match (command, acknowledgement.running) {
				("check_offer", -1) => {
					Ok(MarketplaceMessageOutcome::OfferChecked { running: None })
				}
				("accept_offer", -1) => {
					Err(Error::MarketplaceOfferUnavailable(offer_id.to_string()))
				}
				("check_offer", running) if running >= 0 => {
					Ok(MarketplaceMessageOutcome::OfferChecked {
						running: Some(running as u64),
					})
				}
				("accept_offer", running) if running >= 0 => {
					Ok(MarketplaceMessageOutcome::OfferAccepted {
						running: running as u64,
					})
				}
				(_, running) => Err(Error::MarketplaceResponse(format!(
					"{} returned an invalid running count {}",
					command, running
				))),
			}
		}
		"fail_bidding" => {
			require_marketplace_cancellation_ack(response)?;
			Ok(MarketplaceMessageOutcome::CancellationAcknowledged)
		}
		_ => Err(Error::ArgumentError(format!(
			"Unknown marketplace command '{}'; expected check_offer, accept_offer, or fail_bidding",
			bounded_escape_for_display(command, 128)
		))),
	}
}

#[cfg(feature = "swaps")]
fn require_matching_marketplace_tor_listener(
	context_id: u32,
	advertised_sender: &str,
) -> Result<(), Error> {
	let active_address =
		controller::get_healthy_foreign_tor_address(context_id).ok_or_else(|| {
			Error::ListenerError(
				"A healthy inbound Tor foreign listener is required for this marketplace command"
					.to_string(),
			)
		})?;
	require_marketplace_listener_identity(&active_address, advertised_sender)
}

#[cfg(feature = "swaps")]
fn require_marketplace_listener_identity(
	active_address: &str,
	advertised_sender: &str,
) -> Result<(), Error> {
	let active_identity = ProvableAddress::from_tor_pub_key(
		&mwc_wallet_libwallet::address::pubkey_from_onion_v3(&active_address).map_err(|e| {
			Error::ListenerError(format!(
				"The active Tor listener published an invalid OnionV3 identity: {}",
				bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
			))
		})?,
	)?
	.to_string();
	if active_identity != advertised_sender {
		return Err(Error::ListenerError(format!(
			"The marketplace message advertises OnionV3 identity {}, but the healthy inbound listener serves {}. Restart the listener with the pinned marketplace address index before retrying",
			bounded_escape_for_display(advertised_sender, 128),
			bounded_escape_for_display(&active_identity, 128)
		)));
	}
	Ok(())
}

/// integrity fee related operations
#[cfg(feature = "swaps")]
pub fn send_marketplace_message<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: &TorConfig,
	args: SendMarketplaceMessageArgs,
) -> Result<MarketplaceMessageOutcome, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	if !matches!(
		args.command.as_str(),
		"check_offer" | "accept_offer" | "fail_bidding"
	) {
		return Err(Error::ArgumentError(format!(
			"Unknown marketplace command '{}'; expected check_offer, accept_offer, or fail_bidding",
			bounded_escape_for_display(&args.command, 128)
		)));
	}

	let (context_id, base_dir) = {
		wallet_lock!(wallet_inst, w);
		(w.get_context_id(), w.get_data_file_dir().to_string())
	};

	let requires_cancellation_ack = args.command == "fail_bidding";

	if requires_cancellation_ack && args.swap_id.is_none() {
		return Err(Error::ArgumentError(
			"fail_bidding requires the exact swap_id".to_string(),
		));
	}

	let dest = validate_tor_address(&args.tor_address).map_err(|e| {
		Error::GenericError(format!(
			"Invalid marketplace Tor address: {}",
			bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
		))
	})?;

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let recipient = ProvableAddress::from_tor_pub_key(
		&mwc_wallet_libwallet::address::pubkey_from_onion_v3(&dest).map_err(|e| {
			Error::GenericError(format!(
				"Unable to decode marketplace Tor address: {}",
				bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
			))
		})?,
	)?
	.to_string();
	let signing_address_index = match args.signing_address_index {
		Some(address_index) => Some(address_index),
		None if args.command == "accept_offer" => {
			Some(owner_swap::get_or_create_marketplace_signing_address_index(
				wallet_inst.clone(),
				&secp,
				keychain_mask,
				&args.offer_id,
				&recipient,
			)?)
		}
		None if requires_cancellation_ack => {
			let swap_id = args.swap_id.ok_or_else(|| {
				Error::ArgumentError("fail_bidding requires the exact swap_id".to_string())
			})?;
			Some(owner_swap::marketplace_signing_address_index_for_swap(
				wallet_inst.clone(),
				&secp,
				keychain_mask,
				swap_id,
				&args.offer_id,
				&recipient,
			)?)
		}
		None => None,
	};
	let command = args.command;
	let offer_id = args.offer_id;
	let message = owner_swap::create_marketplace_message(
		wallet_inst,
		&secp,
		keychain_mask,
		command.clone(),
		recipient,
		offer_id.clone(),
		args.swap_id,
		args.nonce,
		signing_address_index,
	)?;
	if marketplace_message_requires_foreign_api_listener(&command) {
		require_matching_marketplace_tor_listener(context_id, &message.from)?;
	}

	let sender = HttpDataSender::tor_connection(
		context_id,
		&dest,
		None, // It is foreign API, no secret
		tor_config,
		Path::new(&base_dir),
	)
	.map_err(|e| {
		Error::GenericError(format!(
			"Unable to create TOR client to send: {}",
			bounded_escape_for_display(&e.to_string(), MAX_CANCEL_ERROR_BYTES)
		))
	})?;
	if marketplace_message_requires_foreign_api_listener(&command) {
		// Connecting to the remote Onion service can take long enough for the
		// local listener generation to change. Revalidate immediately before
		// advertising this identity to the peer.
		require_matching_marketplace_tor_listener(context_id, &message.from)?;
	}

	let response =
		sender.send_swap_marketplace_message(&serde_json::to_string(&message).map_err(|e| {
			Error::GenericError(format!("Unable to serialize marketplace message, {}", e))
		})?)?;
	let outcome = parse_marketplace_message_outcome(&command, &offer_id, &response)?;
	println!(
		"JSON: {}",
		bounded_escape_for_display(&response, MAX_CANCEL_ERROR_BYTES)
	);
	Ok(outcome)
}

pub fn check_tor_connection<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tor_config: &TorConfig,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let (context_id, base_dir) = {
		wallet_lock!(wallet_inst, w);
		(w.get_context_id(), w.get_data_file_dir().to_string())
	};

	if !controller::is_foreign_api_running(context_id) {
		return Err(Error::GenericError(
			"TOR is not running. Please start tor listener for your wallet".to_string(),
		));
	}

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let tor_pk = owner::get_wallet_public_address(wallet_inst.clone(), &secp, keychain_mask)?;
	let tor_addr = ProvableAddress::from_tor_pub_key(&tor_pk)?;

	let this_tor_address = tor_addr.to_string();
	let dest = format!("http://{}.onion", this_tor_address);

	let sender = create_sender(
		context_id,
		"tor",
		&dest,
		&None,
		Some(tor_config),
		Path::new(&base_dir),
	)?;
	match sender.check_other_wallet_version(&dest, false) {
		Ok(_) => {
			println!("Tor connection online");
			Ok(())
		}
		Err(e) => {
			println!("Tor is offline, {}", e);
			Err(e.into())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_libwallet::proof::tx_proof::{
		ProofInsertResult, pop_proof_for_slate, push_proof_for_slate,
	};
	use mwc_wallet_libwallet::{MAX_PARTICIPANT_MESSAGE_LEN, ParticipantData};
	use mwc_wallet_util::mwc_crates::secp::{AggSigSignature, PublicKey};
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;

	#[cfg(feature = "swaps")]
	#[test]
	fn cancellation_delivery_does_not_require_an_inbound_listener() {
		assert!(!marketplace_message_requires_foreign_api_listener(
			"fail_bidding"
		));
		assert!(marketplace_message_requires_foreign_api_listener(
			"accept_offer"
		));
		assert!(marketplace_message_requires_foreign_api_listener(
			"check_offer"
		));
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn offer_identity_must_match_the_current_transport() {
		let mut offer =
			message::Message::from_json(include_str!("../../libwallet/swap_test/message_1.json"))
				.unwrap();
		let method = match &offer.inner {
			message::Update::Offer(update) => update.communication_method.clone(),
			_ => panic!("fixture message must be an offer"),
		};

		apply_offer_transport_identity(&mut offer, &method, "current-source-address".to_string())
			.unwrap();
		match &offer.inner {
			message::Update::Offer(update) => {
				assert_eq!(update.from_address, "current-source-address")
			}
			_ => unreachable!("fixture message must be an offer"),
		}

		let conflicting_method = if method == "tor" { "mwcmqs" } else { "tor" };
		assert!(matches!(
			apply_offer_transport_identity(
				&mut offer,
				conflicting_method,
				"wrong-source-address".to_string(),
			),
			Err(mwc_wallet_libwallet::swap::Error::InvalidMessageData(_))
		));
		match &offer.inner {
			message::Update::Offer(update) => {
				assert_eq!(update.from_address, "current-source-address")
			}
			_ => unreachable!("fixture message must be an offer"),
		}

		match &mut offer.inner {
			message::Update::Offer(update) => {
				update.communication_method = "file".to_string();
				update.from_address = "stale-local-path".to_string();
			}
			_ => unreachable!("fixture message must be an offer"),
		}
		apply_offer_transport_identity(&mut offer, "file", String::new()).unwrap();
		match &offer.inner {
			message::Update::Offer(update) => {
				assert_eq!(update.communication_method, "file");
				assert!(update.from_address.is_empty());
			}
			_ => unreachable!("fixture message must be an offer"),
		}
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn marketplace_cancellation_ack_requires_exact_true_object() {
		assert!(require_marketplace_cancellation_ack(r#"{"cancelled":true}"#).is_ok());

		for rejected in [
			"",
			"not json",
			r#"[true]"#,
			r#"{"cancelled":false}"#,
			r#"{}"#,
			r#"{"running":0}"#,
			r#"{"cancelled":"true"}"#,
			r#"{"cancelled":true,"extra":1}"#,
			r#"{"cancelled":true,"cancelled":true}"#,
		] {
			assert!(
				require_marketplace_cancellation_ack(rejected).is_err(),
				"unexpectedly accepted {rejected}"
			);
		}
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn marketplace_offer_acknowledgements_are_typed_and_command_specific() {
		assert_eq!(
			parse_marketplace_message_outcome("check_offer", "offer", r#"{"running":3}"#).unwrap(),
			MarketplaceMessageOutcome::OfferChecked { running: Some(3) }
		);
		assert_eq!(
			parse_marketplace_message_outcome("check_offer", "offer", r#"{"running":-1}"#).unwrap(),
			MarketplaceMessageOutcome::OfferChecked { running: None }
		);
		assert_eq!(
			parse_marketplace_message_outcome("accept_offer", "offer", r#"{"running":0}"#).unwrap(),
			MarketplaceMessageOutcome::OfferAccepted { running: 0 }
		);
		assert!(matches!(
			parse_marketplace_message_outcome(
				"accept_offer",
				"missing-offer",
				r#"{"running":-1}"#
			),
			Err(Error::MarketplaceOfferUnavailable(ref offer)) if offer == "missing-offer"
		));

		for rejected in [
			"",
			"   ",
			"not json",
			r#"[]"#,
			r#"{}"#,
			r#"{"running":"0"}"#,
			r#"{"running":-2}"#,
			r#"{"running":0,"extra":true}"#,
			r#"{"running":0,"running":0}"#,
		] {
			assert!(
				parse_marketplace_message_outcome("check_offer", "offer", rejected).is_err(),
				"unexpectedly accepted {rejected}"
			);
		}
		assert!(matches!(
			parse_marketplace_message_outcome("unknown", "offer", r#"{"running":0}"#),
			Err(Error::ArgumentError(_))
		));
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn marketplace_listener_identity_must_match_advertised_sender() {
		let listener_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
		let other_key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
		let listener_address =
			ProvableAddress::from_tor_pub_key(&listener_key.verifying_key())
				.unwrap()
				.to_string();
		let other_address = ProvableAddress::from_tor_pub_key(&other_key.verifying_key())
			.unwrap()
			.to_string();
		let listener_url = format!("http://{}.onion", listener_address);

		assert!(
			require_marketplace_listener_identity(&listener_url, &listener_address).is_ok()
		);
		assert!(require_marketplace_listener_identity(&listener_url, &other_address).is_err());
	}

	#[test]
	fn cancellation_error_rendering_is_bounded_and_terminal_safe() {
		let mut node_text =
			"before\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}forged\u{2029}".to_owned();
		node_text.push_str(&"x".repeat(MAX_CANCEL_ERROR_BYTES * 2));
		let safe = safe_cancel_error(&mwc_wallet_libwallet::Error::Node(node_text));

		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.contains("\\u2028"));
		assert!(safe.contains("\\u2029"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
		assert!(!safe.contains('\u{2028}'));
		assert!(!safe.contains('\u{2029}'));
	}

	#[test]
	fn scan_error_rendering_is_bounded_and_terminal_safe() {
		let mut node_text = "before\n\u{1b}]52;c;payload\u{7}\u{202e}".to_owned();
		node_text.push_str(&"x".repeat(MAX_SCAN_ERROR_BYTES * 2));
		let safe = safe_scan_error(&mwc_wallet_libwallet::Error::Node(node_text));

		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn swap_start_failure_rendering_is_bounded_and_terminal_safe() {
		let mut node_text =
			"before\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}forged\u{2029}".to_owned();
		node_text.push_str(&"x".repeat(MAX_SWAP_START_ERROR_DISPLAY_BYTES * 2));
		let safe = safe_swap_start_failure(&mwc_wallet_libwallet::Error::Node(node_text));

		assert!(safe.starts_with("Unable to start Swap trade: Node API error: before"));
		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.contains("\\u2028"));
		assert!(safe.contains("\\u2029"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
		assert!(!safe.contains('\u{2028}'));
		assert!(!safe.contains('\u{2029}'));
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn swap_operation_error_rendering_is_bounded_and_terminal_safe() {
		let mut peer_text =
			"before\n\u{1b}]52;c;payload\u{7}\u{202e}\u{2028}forged\u{2029}".to_owned();
		peer_text.push_str(&"x".repeat(MAX_SWAP_OPERATION_ERROR_DISPLAY_BYTES * 2));
		let safe = safe_swap_operation_error(
			&mwc_wallet_libwallet::swap::Error::ElectrumNodeClient(peer_text),
		);

		assert!(safe.starts_with("Electrum Node error, before"));
		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.contains("\\u2028"));
		assert!(safe.contains("\\u2029"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
		assert!(!safe.contains('\u{2028}'));
		assert!(!safe.contains('\u{2029}'));
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn swap_offer_failure_rendering_is_bounded_and_terminal_safe() {
		let mut hostile_error = "invalid offer\n\u{1b}]52;c;payload\u{7}\u{202e}".to_owned();
		hostile_error.push_str(&"x".repeat(MAX_SWAP_OFFER_ERROR_DISPLAY_BYTES * 2));
		let safe = safe_swap_offer_failure("offer\n\u{1b}[31m\u{202e}.json", &hostile_error);

		assert!(safe.contains("offer\\u000a\\u001b[31m\\u202e.json"));
		assert!(safe.contains("invalid offer\\u000a\\u001b]52;c;payload\\u0007\\u202e"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
	}

	fn send_slate_with_initiator(compact_slate: bool) -> Slate {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let mut slate = Slate::blank(2, compact_slate).unwrap();
		slate.participant_data.push(ParticipantData {
			id: 0,
			public_blind_excess: public_key,
			public_nonce: public_key,
			part_sig: None,
			message: None,
			message_sig: None,
		});
		slate
	}

	fn send_response_participant(message: Option<String>) -> ParticipantData {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[2_u8; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		ParticipantData {
			id: 1,
			public_blind_excess: public_key,
			public_nonce: public_key,
			part_sig: Some(AggSigSignature::blank()),
			message,
			message_sig: None,
		}
	}

	#[test]
	fn send_response_validation_accepts_compact_participant_delta() {
		let original_slate = send_slate_with_initiator(true);
		let mut response_slate = original_slate.clone();
		response_slate.participant_data.clear();
		response_slate
			.participant_data
			.push(send_response_participant(None));

		assert!(
			original_slate
				.validate_send_response(&response_slate)
				.is_ok()
		);
	}

	#[test]
	fn explicit_http_slatepack_recipient_forces_compact_target_version() {
		assert_eq!(
			effective_send_target_slate_version("http", true, None),
			Some(SLATEPACK_SLATE_VERSION)
		);
		assert_eq!(
			effective_send_target_slate_version("http", true, Some(2)),
			Some(SLATEPACK_SLATE_VERSION)
		);
		assert_eq!(
			effective_send_target_slate_version("http", true, Some(5)),
			Some(5)
		);

		// Preserve legacy negotiation when no explicit HTTP recipient was
		// requested, and preserve MQS's separate transport behavior.
		assert_eq!(
			effective_send_target_slate_version("http", false, None),
			None
		);
		assert_eq!(
			effective_send_target_slate_version("mwcmqs", true, None),
			None
		);
	}

	#[test]
	fn send_response_validation_rejects_missing_or_changed_initiator() {
		let original_plain_slate = send_slate_with_initiator(false);
		let mut missing_plain_participant = original_plain_slate.clone();
		missing_plain_participant.participant_data.clear();
		assert!(
			original_plain_slate
				.validate_send_response(&missing_plain_participant)
				.is_err()
		);

		let original_compact_slate = send_slate_with_initiator(true);
		let mut altered_compact_participant = original_compact_slate.clone();
		altered_compact_participant
			.participant_data
			.push(send_response_participant(None));
		altered_compact_participant.participant_data[0].message = Some("altered".to_string());
		assert!(
			original_compact_slate
				.validate_send_response(&altered_compact_participant)
				.is_err()
		);

		let mut duplicated_compact_participant = original_compact_slate.clone();
		duplicated_compact_participant
			.participant_data
			.push(send_response_participant(None));
		duplicated_compact_participant
			.participant_data
			.push(original_compact_slate.participant_data[0].clone());
		assert!(
			original_compact_slate
				.validate_send_response(&duplicated_compact_participant)
				.is_err()
		);
	}

	#[test]
	fn send_response_validation_rejects_reflection_and_unbounded_participant_data() {
		let original_slate = send_slate_with_initiator(true);

		// An initial slate reflected by the recipient has no receiver record.
		assert!(
			original_slate
				.validate_send_response(&original_slate)
				.is_err()
		);

		let mut changed_declaration = original_slate.clone();
		changed_declaration.num_participants = 3;
		changed_declaration
			.participant_data
			.push(send_response_participant(None));
		assert!(
			original_slate
				.validate_send_response(&changed_declaration)
				.is_err()
		);

		let responder = send_response_participant(None);
		let mut duplicate_responder = original_slate.clone();
		duplicate_responder.participant_data = vec![responder.clone(), responder];
		assert!(
			original_slate
				.validate_send_response(&duplicate_responder)
				.is_err()
		);

		let mut unexpected_responder = original_slate.clone();
		let mut participant_two = send_response_participant(None);
		participant_two.id = 2;
		unexpected_responder
			.participant_data
			.push(send_response_participant(None));
		unexpected_responder.participant_data.push(participant_two);
		assert!(
			original_slate
				.validate_send_response(&unexpected_responder)
				.is_err()
		);

		let mut oversized_message = original_slate.clone();
		oversized_message
			.participant_data
			.push(send_response_participant(Some(
				"x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1),
			)));
		assert!(
			original_slate
				.validate_send_response(&oversized_message)
				.is_err()
		);
	}

	#[test]
	fn send_initial_validation_accepts_two_party_sender_record() {
		assert!(
			send_slate_with_initiator(false)
				.validate_send_initial()
				.is_ok()
		);
		assert!(
			send_slate_with_initiator(true)
				.validate_send_initial()
				.is_ok()
		);
	}

	#[test]
	fn send_initial_validation_rejects_bad_declaration_and_extra_records() {
		let mut changed_declaration = send_slate_with_initiator(false);
		changed_declaration.num_participants = 3;
		assert!(changed_declaration.validate_send_initial().is_err());

		let mut missing_sender = send_slate_with_initiator(false);
		missing_sender.participant_data.clear();
		assert!(missing_sender.validate_send_initial().is_err());

		let mut wrong_sender_id = send_slate_with_initiator(false);
		wrong_sender_id.participant_data[0].id = 1;
		assert!(wrong_sender_id.validate_send_initial().is_err());

		// Excess or duplicate records would enter the aggregate nonce and
		// blind sums while only the first matching record is replaced.
		let mut extra_receiver = send_slate_with_initiator(false);
		extra_receiver
			.participant_data
			.push(send_response_participant(None));
		assert!(extra_receiver.validate_send_initial().is_err());

		let mut duplicate_sender = send_slate_with_initiator(false);
		let sender_record = duplicate_sender.participant_data[0].clone();
		duplicate_sender.participant_data.push(sender_record);
		assert!(duplicate_sender.validate_send_initial().is_err());
	}

	fn test_tx_proof(key: [u8; 32]) -> TxProof {
		TxProof {
			address: ProvableAddress::blank(),
			message: String::new(),
			challenge: String::new(),
			signature: None,
			key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: None,
			slate_message: None,
			tor_proof_signature: None,
			tor_sender_address: None,
			tor_sender_signature: None,
		}
	}

	#[test]
	fn faucet_mqs_send_clears_proof_on_success_and_error() {
		let context_id = u32::MAX;
		let successful_slate_id = Uuid::new_v4();
		assert_eq!(
			push_proof_for_slate(context_id, 1, &successful_slate_id, test_tx_proof([1; 32]),),
			ProofInsertResult::Inserted
		);
		assert_eq!(
			clear_faucet_proof_after_send(
				context_id,
				&successful_slate_id,
				Ok::<_, &'static str>(7),
			),
			Ok(7)
		);
		assert!(pop_proof_for_slate(context_id, &successful_slate_id).is_none());

		let failed_slate_id = Uuid::new_v4();
		assert_eq!(
			push_proof_for_slate(context_id, 1, &failed_slate_id, test_tx_proof([2; 32])),
			ProofInsertResult::Inserted
		);
		assert_eq!(
			clear_faucet_proof_after_send(
				context_id,
				&failed_slate_id,
				Err::<(), _>("send failed"),
			),
			Err("send failed")
		);
		assert!(pop_proof_for_slate(context_id, &failed_slate_id).is_none());
	}

	#[test]
	fn generated_slate_files_are_removed_until_the_session_is_kept() {
		let directory = tempdir().unwrap();
		let rollback_path = directory.path().join("rollback.slatepack");
		file::replace_owner_only_file(&rollback_path, b"generated slate").unwrap();
		{
			let mut generated = GeneratedSlateFiles::new();
			generated.track(rollback_path.clone());
		}
		assert!(!rollback_path.exists());

		let kept_path = directory.path().join("kept.slatepack");
		file::replace_owner_only_file(&kept_path, b"generated slate").unwrap();
		{
			let mut generated = GeneratedSlateFiles::new();
			generated.track(kept_path.clone());
			generated.keep();
		}
		assert_eq!(fs::read(kept_path).unwrap(), b"generated slate");
	}

	#[cfg(unix)]
	#[test]
	fn transaction_dump_replaces_permissive_file_with_owner_only_permissions() {
		use std::os::unix::fs::PermissionsExt;

		let directory = tempdir().unwrap();
		let dump_path = directory.path().join("transaction.json");
		fs::write(&dump_path, b"old transaction").unwrap();
		fs::set_permissions(&dump_path, fs::Permissions::from_mode(0o644)).unwrap();

		dump_stored_transaction(
			&Transaction::empty(),
			dump_path.to_str().expect("temporary path is UTF-8"),
		)
		.unwrap();

		assert_eq!(
			fs::metadata(&dump_path).unwrap().permissions().mode() & 0o777,
			0o600
		);
		let dumped: TransactionV3 = serde_json::from_slice(&fs::read(&dump_path).unwrap()).unwrap();
		assert!(Transaction::try_from(dumped).is_ok());
	}

	#[cfg(unix)]
	#[test]
	fn proof_export_replaces_permissive_file_with_owner_only_permissions() {
		use std::os::unix::fs::PermissionsExt;

		let directory = tempdir().unwrap();
		let proof_path = directory.path().join("payment-proof.json");
		fs::write(&proof_path, b"old proof").unwrap();
		fs::set_permissions(&proof_path, fs::Permissions::from_mode(0o644)).unwrap();

		let proof = test_tx_proof([7; 32]);
		write_tx_proof_export(&proof_path, &proof).unwrap();

		assert_eq!(
			fs::metadata(&proof_path).unwrap().permissions().mode() & 0o777,
			0o600
		);
		let exported: TxProof = serde_json::from_slice(&fs::read(&proof_path).unwrap()).unwrap();
		assert_eq!(exported.key, [7; 32]);
	}
}
