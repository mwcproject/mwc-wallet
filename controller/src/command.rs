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

//! Grin wallet command-line function implementations

use crate::api::TLSConfig;
use crate::apiwallet::Owner;
use crate::config::{MQSConfig, TorConfig, WalletConfig, WALLET_CONFIG_FILE_NAME};
use crate::core::{core, global};
use crate::error::{Error, ErrorKind};
use crate::impls::{create_sender, SlateGetter as _};
use crate::impls::{PathToSlate, SlatePutter};
use crate::keychain;
use crate::libwallet::{InitTxArgs, IssueInvoiceTxArgs, NodeClient, WalletLCProvider};
use crate::util::secp::key::SecretKey;
use crate::util::{Mutex, ZeroingString};
use crate::{controller, display};
use chrono::Utc;
use grin_wallet_impls::adapters::{create_swap_message_sender, validate_tor_address};
use grin_wallet_impls::{Address, MWCMQSAddress, Publisher};
use grin_wallet_libwallet::api_impl::owner_swap;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use grin_wallet_libwallet::proof::tx_proof::TxProof;
use grin_wallet_libwallet::swap::message;
use grin_wallet_libwallet::swap::trades;
use grin_wallet_libwallet::swap::types::Action;
use grin_wallet_libwallet::{Slate, TxLogEntry, WalletInst};
use serde_json as json;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref SWAP_THREADS_RUN:  Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
}

/// Arguments common to all wallet commands
#[derive(Clone)]
pub struct GlobalArgs {
	pub account: String,
	pub api_secret: Option<String>,
	pub node_api_secret: Option<String>,
	pub show_spent: bool,
	pub chain_type: global::ChainTypes,
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
	g_args: &GlobalArgs,
	args: InitArgs,
	wallet_data_dir: Option<&str>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	p.create_config(
		&g_args.chain_type,
		WALLET_CONFIG_FILE_NAME,
		None,
		None,
		None,
		None,
	)?;
	p.create_wallet(
		None,
		args.recovery_phrase,
		args.list_length,
		args.password.clone(),
		false,
		wallet_data_dir.clone(),
	)?;

	let m = p.get_mnemonic(None, args.password, wallet_data_dir)?;
	grin_wallet_impls::lifecycle::show_recovery_phrase(m);
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
	K: keychain::Keychain + 'static,
{
	let mut w_lock = owner_api.wallet_inst.lock();
	let p = w_lock.lc_provider()?;
	let m = p.get_mnemonic(None, args.passphrase, wallet_data_dir)?;
	grin_wallet_impls::lifecycle::show_recovery_phrase(m);
	Ok(())
}

/// Arguments for listen command
pub struct ListenArgs {
	pub method: String,
}

pub fn listen<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	config: &WalletConfig,
	tor_config: &TorConfig,
	mqs_config: &MQSConfig,
	args: &ListenArgs,
	g_args: &GlobalArgs,
	cli_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	match args.method.as_str() {
		"http" => {
			let wallet_inst = owner_api.wallet_inst.clone();
			let config = config.clone();
			let tor_config = tor_config.clone();
			let g_args = g_args.clone();
			let api_thread = thread::Builder::new()
				.name("wallet-http-listener".to_string())
				.spawn(move || {
					let res = controller::foreign_listener(
						wallet_inst,
						keychain_mask,
						&config.api_listen_addr(),
						g_args.tls_conf.clone(),
						tor_config.use_tor_listener,
					);
					if let Err(e) = res {
						error!("Error starting http listener: {}", e);
					}
				});
			if let Ok(t) = api_thread {
				if !cli_mode {
					let r = t.join();
					if let Err(_) = r {
						error!("Error starting http listener");
						return Err(ErrorKind::ListenerError.into());
					}
				}
			}
		}

		"mwcmqs" => {
			let wallet_inst = owner_api.wallet_inst.clone();
			let _ = controller::init_start_mwcmqs_listener(
				wallet_inst,
				mqs_config.clone(),
				keychain_mask,
				!cli_mode,
			)
			.map_err(|e| {
				error!("Unable to start mwcmqs listener, {}", e);
				Error::from(ErrorKind::ListenerError)
			})?;
		}
		method => {
			return Err(
				ErrorKind::ArgumentError(format!("No listener for method '{}'", method)).into(),
			);
		}
	};
	Ok(())
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
	K: keychain::Keychain + 'static,
{
	// keychain mask needs to be a sinlge instance, in case the foreign API is
	// also being run at the same time
	let km = Arc::new(Mutex::new(keychain_mask));

	// Starting MQS first
	if config.owner_api_include_mqs_listener.unwrap_or(false) {
		let _ = controller::init_start_mwcmqs_listener(
			owner_api.wallet_inst.clone(),
			mqs_config.clone(),
			km.clone(),
			false,
			//None,
		)?;
	}


	// Now Owner API
	controller::owner_listener(
		owner_api.wallet_inst.clone(),
		km,
		config.owner_api_listen_addr().as_str(),
		g_args.api_secret.clone(),
		g_args.tls_conf.clone(),
		config.owner_api_include_foreign.clone(),
		Some(tor_config.clone()),
	)
	.map_err(|e| ErrorKind::LibWallet(format!("Unable to start Listener, {}", e)))?;
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
	K: keychain::Keychain + 'static,
{
	if args.create.is_none() {
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let acct_mappings = api.accounts(m)?;
			// give logging thread a moment to catch up
			thread::sleep(Duration::from_millis(200));
			display::accounts(acct_mappings);
			Ok(())
		});
		if let Err(e) = res {
			let err_str = format!("Error listing accounts: {}", e);
			error!("{}", err_str);
			return Err(ErrorKind::LibWallet(err_str).into());
		}
	} else {
		let label = args.create.unwrap();
		let res = controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			api.create_account_path(m, &label)?;
			thread::sleep(Duration::from_millis(200));
			info!("Account: '{}' Created!", label);
			Ok(())
		});
		if let Err(e) = res {
			thread::sleep(Duration::from_millis(200));
			let err_str = format!("Error creating account '{}': {}", label, e);
			error!("{}", err_str);
			return Err(ErrorKind::LibWallet(err_str).into());
		}
	}
	Ok(())
}

/// Arguments for the send command
pub struct SendArgs {
	pub amount: u64,
	pub message: Option<String>,
	pub minimum_confirmations: u64,
	pub selection_strategy: String,
	pub estimate_selection_strategies: bool,
	pub method: String,
	pub dest: String,
	pub apisecret: Option<String>,
	pub change_outputs: usize,
	pub fluff: bool,
	pub max_outputs: usize,
	pub target_slate_version: Option<u16>,
	pub payment_proof_address: Option<ProvableAddress>,
	pub ttl_blocks: Option<u64>,
	pub exclude_change_outputs: bool,
	pub minimum_confirmations_change_outputs: u64,
	pub address: Option<String>,      //this is only for file proof.
	pub outputs: Option<Vec<String>>, // Outputs to use. If None, all outputs can be used
}

pub fn send<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	_config: &WalletConfig,
	keychain_mask: Option<&SecretKey>,
	tor_config: Option<TorConfig>,
	mqs_config: Option<MQSConfig>,
	args: SendArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let wallet_inst = owner_api.wallet_inst.clone();
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
			for strategy in vec!["smallest", "all"] {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: args.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: args.change_outputs as u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					exclude_change_outputs: Some(args.exclude_change_outputs),
					minimum_confirmations_change_outputs: args.minimum_confirmations_change_outputs,
					address: args.address.clone(),
					outputs: args.outputs.clone(),
					..Default::default()
				};
				let slate = api.init_send_tx(m, init_args, 1)?;
				strategies.push((strategy, slate.amount, slate.fee));
			}
			display::estimate(args.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: args.amount,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: args.change_outputs as u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				target_slate_version: args.target_slate_version,
				payment_proof_recipient_address: args.payment_proof_address.clone(),
				address: args.address.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				exclude_change_outputs: Some(args.exclude_change_outputs),
				minimum_confirmations_change_outputs: args.minimum_confirmations_change_outputs,
				outputs: args.outputs.clone(),
				..Default::default()
			};
			let result = api.init_send_tx(m, init_args, 1);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Tx created: {} mwc to {} (strategy '{}')",
						core::amount_to_hr_string(args.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(ErrorKind::LibWallet(format!(
						"Unable to create send slate , {}",
						e
					))
					.into());
				}
			};

			//if it is mwcmqs, start listner first.
			match args.method.as_str() {
				"mwcmqs" => {
					if grin_wallet_impls::adapters::get_mwcmqs_brocker().is_none() {
						//check to see if mqs_config is there, if not, return error
						let mqs_config_unwrapped;
						match mqs_config {
							Some(s) => {
								mqs_config_unwrapped = s;
							}
							None => {
								return Err(ErrorKind::MQSConfig(format!("NO MQS config!")).into());
							}
						}

						let km = match keychain_mask.as_ref() {
							None => None,
							Some(&m) => Some(m.to_owned()),
						};
						//start the listener finalize tx
						let _ = controller::init_start_mwcmqs_listener(
							wallet_inst.clone(),
							mqs_config_unwrapped,
							Arc::new(Mutex::new(km)),
							false,
							//None,
						)?;
						thread::sleep(Duration::from_millis(2000));
					}
				}
				_ => {}
			}

			match args.method.as_str() {
				"file" => {
					PathToSlate((&args.dest).into())
						.put_tx(&slate)
						.map_err(|e| {
							ErrorKind::IO(format!(
								"Unable to store the file at {}, {}",
								args.dest, e
							))
						})?;
					api.tx_lock_outputs(m, &slate, Some(String::from("file")), 0)?;
					return Ok(());
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, Some(String::from("self")), 0)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet_inst, km, |api| {
						slate = api.receive_tx(
							&slate,
							Some(String::from("self")),
							Some(&args.dest),
							None,
						)?;
						Ok(())
					})?;
				}

				method => {
					let original_slate = slate.clone();
					let sender = create_sender(method, &args.dest, &args.apisecret, tor_config)?;
					slate = sender.send_tx(&slate)?;
					// Restore back ttl, because it can be gone
					slate.ttl_cutoff_height = original_slate.ttl_cutoff_height.clone();
					// Checking is sender didn't do any harm to slate
					Slate::compare_slates_send(&original_slate, &slate)?;
					api.verify_slate_messages(m, &slate).map_err(|e| {
						error!("Error validating participant messages: {}", e);
						e
					})?;
					api.tx_lock_outputs(m, &slate, Some(args.dest.clone()), 0)?; //this step needs to be done before finalizing the slate
				}
			}

			slate = api.finalize_tx(m, &slate)?;

			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!("slate [{}] finalized successfully", slate.id.to_string());
					println!("slate [{}] finalized successfully", slate.id.to_string());
					return Ok(());
				}
				Err(e) => {
					error!("Tx sent fail: {}", e);
					return Err(ErrorKind::LibWallet(format!("Unable to post slate, {}", e)).into());
				}
			}
		}
		Ok(())
	})?;
	Ok(())
}

/// Receive command argument
pub struct ReceiveArgs {
	pub input: String,
	pub message: Option<String>,
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
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
		if let Err(e) = api.verify_slate_messages(&slate) {
			error!("Error validating participant messages: {}", e);
			return Err(
				ErrorKind::LibWallet(format!("Unable to validate slate messages, {}", e)).into(),
			);
		}
		slate = api.receive_tx(
			&slate,
			Some(String::from("file")),
			Some(&g_args.account),
			args.message.clone(),
		)?;
		Ok(())
	})?;
	PathToSlate(format!("{}.response", args.input).into()).put_tx(&slate)?;
	info!(
		"Response file {}.response generated, and can be sent back to the transaction originator.",
		args.input
	);
	Ok(())
}

/// Finalize command args
pub struct FinalizeArgs {
	pub input: String,
	pub fluff: bool,
	pub nopost: bool,
	pub dest: Option<String>,
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
	K: keychain::Keychain + 'static,
{
	let mut slate = PathToSlate((&args.input).into()).get_tx()?;

	// Note!!! grin wallet was able to detect if it is invoice by using 'different' participant Ids (issuer use 1, fouset 0)
	//    Unfortunatelly it is breaks mwc713 backward compatibility (issuer Participant Id 0, fouset 1)
	//    We choose backward compatibility as more impotant, that is why we need 'is_invoice' flag to compensate that.

	if is_invoice {
		let km = match keychain_mask.as_ref() {
			None => None,
			Some(&m) => Some(m.to_owned()),
		};
		controller::foreign_single_use(owner_api.wallet_inst.clone(), km, |api| {
			if let Err(e) = api.verify_slate_messages(&slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			slate = api.finalize_invoice_tx(&mut slate)?;
			Ok(())
		})?;
	} else {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			slate = api.finalize_tx(m, &mut slate)?;
			Ok(())
		})?;
	}

	if !args.nopost {
		controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
			let result = api.post_tx(m, &slate.tx, args.fluff);
			match result {
				Ok(_) => {
					info!(
						"Transaction sent successfully, check the wallet again for confirmation."
					);
					Ok(())
				}
				Err(e) => {
					error!("Tx not sent: {}", e);
					return Err(ErrorKind::LibWallet(format!("Unable to post slate, {}", e)).into());
				}
			}
		})?;
	}

	if args.dest.is_some() {
		PathToSlate((&args.dest.unwrap()).into()).put_tx(&slate)?;
	}

	Ok(())
}

/// Issue Invoice Args
pub struct IssueInvoiceArgs {
	/// output file
	pub dest: String,
	/// issue invoice tx args
	pub issue_args: IssueInvoiceTxArgs,
}

pub fn issue_invoice_tx<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let slate = api.issue_invoice_tx(m, args.issue_args)?;
		PathToSlate((&args.dest).into()).put_tx(&slate)?;
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
	pub input: String,
	pub estimate_selection_strategies: bool,
	pub ttl_blocks: Option<u64>,
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
	K: keychain::Keychain + 'static,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;
	let wallet_inst = owner_api.wallet_inst.clone();
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		if args.estimate_selection_strategies {
			let mut strategies: Vec<(&str, u64, u64)> = Vec::new();
			for strategy in vec!["smallest", "all"] {
				let init_args = InitTxArgs {
					src_acct_name: None,
					amount: slate.amount,
					minimum_confirmations: args.minimum_confirmations,
					max_outputs: args.max_outputs as u32,
					num_change_outputs: 1u32,
					selection_strategy_is_use_all: strategy == "all",
					estimate_only: Some(true),
					..Default::default()
				};
				let slate = api.init_send_tx(m, init_args, 1)?;
				strategies.push((strategy, slate.amount, slate.fee));
			}
			display::estimate(slate.amount, strategies, dark_scheme);
		} else {
			let init_args = InitTxArgs {
				src_acct_name: None,
				amount: 0,
				minimum_confirmations: args.minimum_confirmations,
				max_outputs: args.max_outputs as u32,
				num_change_outputs: 1u32,
				selection_strategy_is_use_all: args.selection_strategy == "all",
				message: args.message.clone(),
				ttl_blocks: args.ttl_blocks,
				send_args: None,
				..Default::default()
			};
			if let Err(e) = api.verify_slate_messages(m, &slate) {
				error!("Error validating participant messages: {}", e);
				return Err(ErrorKind::LibWallet(format!(
					"Unable to validate slate messages, {}",
					e
				))
				.into());
			}
			let result = api.process_invoice_tx(m, &slate, init_args);
			let mut slate = match result {
				Ok(s) => {
					info!(
						"Invoice processed: {} mwc to {} (strategy '{}')",
						core::amount_to_hr_string(slate.amount, false),
						args.dest,
						args.selection_strategy,
					);
					s
				}
				Err(e) => {
					info!("Tx not created: {}", e);
					return Err(
						ErrorKind::LibWallet(format!("Unable to process invoice, {}", e)).into(),
					);
				}
			};

			match args.method.as_str() {
				"file" => {
					let slate_putter = PathToSlate((&args.dest).into());
					slate_putter.put_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, Some(String::from("file")), 1)?;
				}
				"self" => {
					api.tx_lock_outputs(m, &slate, Some(String::from("self")), 1)?;
					let km = match keychain_mask.as_ref() {
						None => None,
						Some(&m) => Some(m.to_owned()),
					};
					controller::foreign_single_use(wallet_inst, km, |api| {
						slate = api.finalize_invoice_tx(&slate)?;
						Ok(())
					})?;
				}
				method => {
					let sender = create_sender(method, &args.dest, &None, tor_config)?;
					// We want to lock outputs for original slate. Sender can respond with anyhting. No reasons to check respond if lock works fine for original slate
					let _ = sender.send_tx(&slate)?;
					api.tx_lock_outputs(m, &slate, Some(args.dest.clone()), 1)?;
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
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (validated, wallet_info) =
			api.retrieve_summary_info(m, true, args.minimum_confirmations)?;
		display::info(
			&g_args.account,
			&wallet_info,
			validated || updater_running,
			dark_scheme,
		);
		Ok(())
	})?;
	Ok(())
}

pub fn outputs<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	g_args: &GlobalArgs,
	dark_scheme: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, outputs) = api.retrieve_outputs(m, g_args.show_spent, true, None)?;
		display::outputs(
			&g_args.account,
			res.height,
			validated || updater_running,
			outputs,
			dark_scheme,
		)?;
		Ok(())
	})?;
	Ok(())
}

/// Txs command args
pub struct TxsArgs {
	pub id: Option<u32>,
	pub tx_slate_id: Option<Uuid>,
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
	K: keychain::Keychain + 'static,
{
	let updater_running = owner_api.updater_running.load(Ordering::Relaxed);
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let res = api.node_height(m)?;
		let (validated, txs) = api.retrieve_txs(m, true, args.id, args.tx_slate_id)?;
		let include_status = !args.id.is_some() && !args.tx_slate_id.is_some();
		display::txs(
			&g_args.account,
			res.height,
			validated || updater_running,
			&txs,
			include_status,
			dark_scheme,
			true, // mwc-wallet alwways show the full info because it is advanced tool
			|tx: &TxLogEntry| tx.payment_proof.is_some(), // it is how mwc-wallet address proofs feature
		)?;

		// if given a particular transaction id or uuid, also get and display associated
		// inputs/outputs and messages
		let id = if args.id.is_some() {
			args.id
		} else if args.tx_slate_id.is_some() {
			if let Some(tx) = txs.iter().find(|t| t.tx_slate_id == args.tx_slate_id) {
				Some(tx.id)
			} else {
				println!("Could not find a transaction matching given txid.\n");
				None
			}
		} else {
			None
		};

		if id.is_some() {
			let (_, outputs) = api.retrieve_outputs(m, true, false, id)?;
			display::outputs(
				&g_args.account,
				res.height,
				validated || updater_running,
				outputs,
				dark_scheme,
			)?;
			// should only be one here, but just in case
			for tx in txs {
				display::tx_messages(&tx, dark_scheme)?;
				display::payment_proof(&tx)?;
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
	K: keychain::Keychain + 'static,
{
	let slate = PathToSlate((&args.input).into()).get_tx()?;

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		api.post_tx(m, &slate.tx, args.fluff)?;
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
	K: keychain::Keychain + 'static,
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

pub fn repost<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: RepostArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, Some(args.id), None)?;
		let stored_tx = api.get_stored_tx(m, &txs[0])?;
		if stored_tx.is_none() {
			error!(
				"Transaction with id {} does not have transaction data. Not reposting.",
				args.id
			);
			return Ok(());
		}
		match args.dump_file {
			None => {
				if txs[0].confirmed {
					error!(
						"Transaction with id {} is confirmed. Not reposting.",
						args.id
					);
					return Ok(());
				}
				api.post_tx(m, &stored_tx.unwrap(), args.fluff)?;
				info!("Reposted transaction at {}", args.id);
				return Ok(());
			}
			Some(f) => {
				let mut tx_file = File::create(f.clone()).map_err(|e| {
					ErrorKind::IO(format!("Unable to create tx dump file {}, {}", f, e))
				})?;
				let tx_as_str = json::to_string(&stored_tx).map_err(|e| {
					ErrorKind::GenericError(format!("Unable convert Tx to Json, {}", e))
				})?;
				tx_file.write_all(tx_as_str.as_bytes()).map_err(|e| {
					ErrorKind::IO(format!("Unable to save tx to the file {}, {}", f, e))
				})?;
				tx_file.sync_all().map_err(|e| {
					ErrorKind::IO(format!("Unable to save tx to the file {}, {}", f, e))
				})?;
				info!("Dumped transaction data for tx {} to {}", args.id, f);
				return Ok(());
			}
		}
	})?;
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
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.cancel_tx(m, args.tx_id, args.tx_slate_id);
		match result {
			Ok(_) => {
				info!("Transaction {} Cancelled", args.tx_id_string);
				Ok(())
			}
			Err(e) => {
				error!("TX Cancellation failed: {}", e);
				Err(ErrorKind::LibWallet(format!(
					"Unable to cancel Transaction {}, {}",
					args.tx_id_string, e
				))
				.into())
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

pub fn scan<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: CheckArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let tip_height = api.node_height(m)?.height;
		let start_height = match args.backwards_from_tip {
			Some(b) => tip_height.saturating_sub(b),
			None => match args.start_height {
				Some(s) => s,
				None => 1,
			},
		};
		warn!("Starting output scan from height {} ...", start_height);
		let result = api.scan(m, Some(start_height), args.delete_unconfirmed);
		match result {
			Ok(_) => {
				warn!("Wallet check complete",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet check failed: {}", e);
				error!("Backtrace: {}", e.backtrace().unwrap());
				Err(ErrorKind::LibWallet(format!("Wallet check failed, {}", e)).into())
			}
		}
	})?;
	Ok(())
}

/// Payment Proof Address
pub fn address<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	g_args: &GlobalArgs,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		// Just address at derivation index 0 for now
		let pub_key = api.get_public_proof_address(m)?;
		let addr = ProvableAddress::from_pub_key(&pub_key);

		println!();
		println!("Address for account - {}", g_args.account);
		println!("-------------------------------------");
		println!("{}", addr);
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

pub fn proof_export<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: ProofExportArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, m| {
		let result = api.get_stored_tx_proof(m, args.id);
		match result {
			Ok(p) => {
				// actually export proof
				let mut proof_file = File::create(args.output_file.clone()).map_err(|e| {
					ErrorKind::GenericError(format!(
						"Unable to create file {}, {}",
						args.output_file, e
					))
				})?;
				proof_file
					.write_all(json::to_string_pretty(&p).unwrap().as_bytes())
					.map_err(|e| {
						ErrorKind::GenericError(format!(
							"Unable to save the proof file {}, {}",
							args.output_file, e
						))
					})?;
				proof_file.sync_all().map_err(|e| {
					ErrorKind::GenericError(format!(
						"Unable to save file {}, {}",
						args.output_file, e
					))
				})?;
				warn!("Payment proof exported to {}", args.output_file);
				Ok(())
			}
			Err(e) => {
				error!("Proof export failed: {}", e);
				return Err(ErrorKind::GenericError(format!(
					"Unable to retrieve payment proof, {}",
					e
				))
				.into());
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
	_owner_api: &mut Owner<L, C, K>,
	_keychain_mask: Option<&SecretKey>,
	args: ProofVerifyArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	//read the file.
	let input = &args.input_file;
	let home_dir = std::env::current_exe() //  dirs::home_dir()
		.map(|p| {
			let mut p = p.clone();
			p.pop();
			p.to_str().unwrap().to_string()
		})
		.unwrap_or("~".to_string());
	let path = Path::new(&input.replace("~", &home_dir)).to_path_buf();
	if !path.exists() {
		let msg = format!("Unable to open payment proof file at {}", args.input_file);
		error!("{}", msg);
		return Err(ErrorKind::LibWallet(msg).into());
	}
	let mut file = File::open(path)
		.map_err(|e| ErrorKind::LibWallet(format!("Unable to open proof data, {}", e)))?;
	let mut proof = String::new();
	file.read_to_string(&mut proof)
		.map_err(|e| ErrorKind::LibWallet(format!("Unable to read proof data, {}", e)))?;
	let tx_pf: TxProof = serde_json::from_str(&proof)
		.map_err(|e| ErrorKind::LibWallet(format!("Unable to deserialize proof data, {}", e)))?;

	match grin_wallet_libwallet::proof::tx_proof::verify_tx_proof_wrapper(&tx_pf) {
		Ok((sender, receiver, amount, outputs, kernel)) => {
			grin_wallet_libwallet::proof::tx_proof::proof_ok(
				sender, receiver, amount, outputs, kernel,
			);
			Ok(())
		}
		Err(e) => {
			error!("Unable to verify proof. {}", e);
			Err(ErrorKind::LibWallet(format!("Proof not valid: {}", e)).into())
		}
	}
}

pub fn dump_wallet_data<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	file_name: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.dump_wallet_data(file_name);
		match result {
			Ok(_) => {
				warn!("Data dump is finished, please check the logs for results",);
				Ok(())
			}
			Err(e) => {
				error!("Wallet Data dump failed: {}", e);
				Err(ErrorKind::LibWallet(format!("Wallet Data dump failed, {}", e)).into())
			}
		}
	})?;
	Ok(())
}

/// Arguments for the swap command
pub struct SwapStartArgs {
	/// MWC to send
	pub mwc_amount: u64,
	/// Secondary currency
	pub secondary_currency: String,
	/// BTC to recieve
	pub secondary_amount: String,
	/// Secondary currency redeem address
	pub secondary_redeem_address: String,
	/// Funds locking order. true - seller lock mwc first
	pub seller_lock_first: bool,
	/// Minimum confirmation for outputs. Default is 10
	pub minimum_confirmations: Option<u64>,
	/// Required confirmations for MWC Locking
	pub mwc_confirmations: u64,
	/// Required confirmations for BTC Locking
	pub secondary_confirmations: u64,
	/// Time interval for message exchange session.
	pub message_exchange_time_sec: u64,
	/// Time interval needed to redeem or execute a refund transaction.
	pub redeem_time_sec: u64,
	/// Method how we are sending message to the buyer
	pub buyer_communication_method: String,
	/// Buyer destination address
	pub buyer_communication_address: String,
	/// ElectrumX URI1
	pub electrum_node_uri1: Option<String>,
	/// ElectrumX failover URI2
	pub electrum_node_uri2: Option<String>,
}

pub fn swap_start<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	args: SwapStartArgs,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	match args.buyer_communication_method.as_str() {
		"mwcmqs" => {
			// Validating destination address
			let _ = MWCMQSAddress::from_str(&args.buyer_communication_address).map_err(|e| {
				ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
			})?;
		}
		"tor" => {
			let _ = validate_tor_address(&args.buyer_communication_address).map_err(|e| {
				ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
			})?;
		}
		"file" => (), // not validating the fine name. Files are secondary and testing method.
		_ => {
			return Err(ErrorKind::ArgumentError(format!(
				"Invalid communication method '{}'. Valid methods: mwcmqs, tor, file",
				args.buyer_communication_method
			))
			.into())
		}
	}

	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.swap_start(
			keychain_mask,
			&grin_wallet_libwallet::api_impl::types::SwapStartArgs {
				mwc_amount: args.mwc_amount,
				secondary_currency: args.secondary_currency,
				secondary_amount: args.secondary_amount,
				secondary_redeem_address: args.secondary_redeem_address,
				seller_lock_first: args.seller_lock_first,
				minimum_confirmations: args.minimum_confirmations,
				mwc_confirmations: args.mwc_confirmations,
				secondary_confirmations: args.secondary_confirmations,
				message_exchange_time_sec: args.message_exchange_time_sec,
				redeem_time_sec: args.redeem_time_sec,
				buyer_communication_method: args.buyer_communication_method,
				buyer_communication_address: args.buyer_communication_address,
				electrum_node_uri1: args.electrum_node_uri1,
				electrum_node_uri2: args.electrum_node_uri2,
			},
		);
		match result {
			Ok(swap_id) => {
				println!("Seller Swap trade is created: {}", swap_id);
				Ok(())
			}
			Err(e) => {
				error!("Unable to start Swap trade: {}", e);
				Err(ErrorKind::LibWallet(format!("Unable to start Swap trade: {}", e)).into())
			}
		}
	})?;
	Ok(())
}

pub fn swap_create_from_offer<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Option<&SecretKey>,
	file: String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	controller::owner_single_use(None, keychain_mask, Some(owner_api), |api, _m| {
		let result = api.swap_create_from_offer(keychain_mask, file.clone());
		match result {
			Ok(swap_id) => {
				warn!("Buyer Swap trade is created: {}", swap_id);
				Ok(())
			}
			Err(e) => {
				error!("Unable to create a Swap trade from message {}: {}", file, e);
				Err(ErrorKind::LibWallet(format!(
					"Unable to create a Swap trade from message {}: {}",
					file, e
				))
				.into())
			}
		}
	})?;
	Ok(())
}

// Swap operation
#[derive(PartialEq)]
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
	StopAllAutoSwap,
}

/// Arguments for the swap command
pub struct SwapArgs {
	/// What we want to do with a swap
	pub subcommand: SwapSubcommand,
	/// Swap ID that will are working with
	pub swap_id: Option<String>,
	/// Action to process. Value must match expected
	pub adjust: Option<String>,
	/// Transport that can be used for interaction
	pub method: Option<String>,
	/// Destination for messages that needed to be send
	pub destination: Option<String>,
	/// Apisecret of the other party of the swap
	pub apisecret: Option<String>,
	/// Secondary currency fee. Satoshi per byte.
	pub secondary_fee: Option<f32>,
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
}

// For Json we can't use int 64, we have to convert all of them to Strings
#[derive(Serialize, Deserialize)]
pub struct StateEtaInfoString {
	/// True if this is current active state
	pub active: bool,
	/// Name of the state to show for user
	pub name: String,
	/// Starting time
	pub end_time: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapJournalRecordString {
	/// Unix timestamp, when event happens
	pub time: String,
	/// Description with what happens at that time.
	pub message: String,
}

pub fn swap<L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	api_listen_addr: String,
	mqs_config: Option<MQSConfig>,
	tor_config: Option<TorConfig>,
	tls_conf: Option<TLSConfig>,
	args: SwapArgs,
	cli_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let km = match keychain_mask.as_ref() {
		None => None,
		Some(&m) => Some(m.to_owned()),
	};
	match args.subcommand {
		SwapSubcommand::List | SwapSubcommand::ListAndCheck => {
			let result = owner_swap::swap_list(
				wallet_inst,
				keychain_mask,
				args.subcommand == SwapSubcommand::ListAndCheck,
			);
			match result {
				Ok(list) => {
					if args.json_format {
						let mut res = Vec::new();

						for swap_info in list {
							let item = json::json!({
								"is_seller" : swap_info.is_seller,
								"secondary_address" : swap_info.secondary_address,
								"mwc_amount" : swap_info.mwc_amount,
								"secondary_amount" : swap_info.secondary_amount,
								"secondary_currency" : swap_info.secondary_currency,
								"swap_id": swap_info.swap_id,
								"state" : swap_info.state.to_string(),
								"action" : swap_info.action.unwrap_or(Action::None).to_string(),
								"expiration" : swap_info.expiration.unwrap_or(0).to_string(),
								"start_time" : swap_info.trade_start_time.to_string(),
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
						}
					}
					Ok(())
				}
				Err(e) => {
					error!("Unable to List Swap trades: {}", e);
					Err(ErrorKind::LibWallet(format!("Unable to List Swap trades: {}", e)).into())
				}
			}
		}
		SwapSubcommand::Delete => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let result = owner_swap::swap_delete(wallet_inst, keychain_mask, &swap_id);
			match result {
				Ok(_) => {
					println!("Swap trade {} was sucessfully deleted.", swap_id);
					Ok(())
				}
				Err(e) => {
					error!("Unable to delete Swap {}: {}", swap_id, e);
					Err(
						ErrorKind::LibWallet(format!("Unable to delete Swap {}: {}", swap_id, e))
							.into(),
					)
				}
			}
		}
		SwapSubcommand::Adjust => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			let adjast_cmd = args.adjust.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'adjust' argument".to_string(),
			))?;

			// Checking parameters here. We can't do that at libwallet side
			if let Some(method) = args.method.clone() {
				let destination = args.destination.clone().ok_or(ErrorKind::ArgumentError(
					"Please specify '--dest' parameter as well".to_string(),
				))?;
				match method.as_str() {
					"mwcmqs" => {
						// Validating destination address
						let _ = MWCMQSAddress::from_str(&destination).map_err(|e| {
							ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
						})?;
					}
					"tor" => {
						// Validating tor address
						let _ = validate_tor_address(&destination).map_err(|e| {
							ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
						})?;
					}
					"file" => (),
					_ => {
						return Err(ErrorKind::ArgumentError(format!(
							"Unknown communication method value '{}'",
							method
						))
						.into());
					}
				}
			}

			let mut secondary_address = None;
			if args.buyer_refund_address.is_some() {
				secondary_address = args.buyer_refund_address.clone();
			}
			if args.secondary_address.is_some() {
				secondary_address = args.secondary_address.clone();
			}

			let result = owner_swap::swap_adjust(
				wallet_inst,
				keychain_mask,
				&swap_id,
				&adjast_cmd,
				args.method.clone(),
				args.destination.clone(),
				secondary_address,
				args.secondary_fee,
				args.electrum_node_uri1,
				args.electrum_node_uri2,
			);
			match result {
				Ok((state, _action)) => {
					println!(
						"Swap trade {} was successfully adjusted. New state: {}",
						swap_id, state
					);
					Ok(())
				}
				Err(e) => {
					error!("Unable to adjust the Swap {}: {}", swap_id, e);
					Err(
						ErrorKind::LibWallet(format!("Unable to adjust Swap {}: {}", swap_id, e))
							.into(),
					)
				}
			}
		}
		SwapSubcommand::Check => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let result = owner_swap::swap_get(wallet_inst.clone(), keychain_mask, &swap_id);
			match result {
				Ok(swap) => {
					let conf_status = owner_swap::get_swap_tx_tstatus(
						wallet_inst.clone(),
						keychain_mask,
						&swap_id,
						args.electrum_node_uri1.clone(),
						args.electrum_node_uri2.clone(),
					)?;
					let (_status, action, time_limit, roadmap, journal_records) =
						owner_swap::update_swap_status_action(
							wallet_inst.clone(),
							keychain_mask,
							&swap_id,
							args.electrum_node_uri1,
							args.electrum_node_uri2,
						)?;

					let mwc_lock_time = if conf_status.mwc_tip < swap.refund_slate.lock_height {
						Utc::now().timestamp() as u64
							+ (swap.refund_slate.lock_height - conf_status.mwc_tip) * 60
					} else {
						0
					};

					// RoadMap
					let road_map_to_print: Vec<StateEtaInfoString> = roadmap
						.iter()
						.map(|r| StateEtaInfoString {
							active: r.active,
							name: r.name.clone(),
							end_time: r.end_time.map(|r| r.to_string()),
						})
						.collect();

					let journal_records_to_print: Vec<SwapJournalRecordString> = journal_records
						.iter()
						.map(|j| SwapJournalRecordString {
							time: j.time.to_string(),
							message: j.message.to_string(),
						})
						.collect();

					if args.json_format {
						let item = json::json!({
							"swapId" : swap.id.to_string(),
							"isSeller" : swap.is_seller(),
							"mwcAmount": core::amount_to_hr_string(swap.primary_amount, true),
							"secondaryCurrency" : swap.secondary_currency.to_string(),
							"secondaryAmount" : swap.secondary_currency.amount_to_hr_string(swap.secondary_amount, true),
							"secondaryAddress" : swap.get_secondary_address(),
							"secondaryFee" : swap.secondary_fee.to_string(),
							"secondaryFeeUnits" : swap.secondary_currency.get_fee_units(),
							"mwcConfirmations" : swap.mwc_confirmations,
							"secondaryConfirmations" : swap.secondary_confirmations,
							"messageExchangeTimeLimit" : swap.message_exchange_time_sec,
							"redeemTimeLimit" : swap.redeem_time_sec,
							"sellerLockingFirst" : swap.seller_lock_first,
							"mwcLockHeight" : swap.refund_slate.lock_height,
							"mwcLockTime" : mwc_lock_time.to_string(),
							"secondaryLockTime" : swap.get_time_btc_lock().to_string(),
							"communicationMethod" : swap.communication_method,
							"communicationAddress" : swap.communication_address,

							"currentAction": action.to_string(),
							"roadmap" : road_map_to_print,
							"journal_records" : journal_records_to_print,
						});

						println!("JSON: {}", item.to_string());
					} else {
						display::swap_trade(
							&swap,
							&action,
							&time_limit,
							&conf_status,
							&roadmap,
							&journal_records,
							true,
						)?;
					}
					Ok(())
				}
				Err(e) => {
					error!("Unable to retrieve Swap {}: {}", swap_id, e);
					Err(
						ErrorKind::LibWallet(format!("Unable to retrieve Swap {}: {}", swap_id, e))
							.into(),
					)
				}
			}
		}
		SwapSubcommand::Process => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			if args.method.is_some() || args.destination.is_some() {
				return Err(ErrorKind::ArgumentError(
					"swap --process doesn't accept 'method' or 'dest' parameters, instead it is using parameters associated with this swap trade.".to_string()).into());
			}

			// Creating message delivery transport as a closure
			let apisecret = args.apisecret.clone();
			let swap_id2 = swap_id.clone();
			let wallet_inst2 = wallet_inst.clone();
			let message_sender = move |swap_message: message::Message,
			                           method: String,
			                           dest: String|
			      -> Result<(bool, String), crate::libwallet::Error> {
				let destination_str = format!("{} {}", method, dest);
				let from_address;

				// Starting the listener first. For this case we know that they are not started yet
				// And there will be a single call only.
				match method.as_str() {
					"mwcmqs" => {
						if grin_wallet_impls::adapters::get_mwcmqs_brocker().is_none() {
							let _ = controller::start_mwcmqs_listener(
								wallet_inst2,
								mqs_config.expect("No MQS config found!").clone(),
								false,
								Arc::new(Mutex::new(km)),
								true,
							)
							.map_err(|e| {
								crate::libwallet::ErrorKind::SwapError(format!(
									"Unable to start mwcmqs listener, {}",
									e
								))
							})?;
							thread::sleep(Duration::from_millis(2000));
						}
						from_address = grin_wallet_impls::adapters::get_mwcmqs_brocker()
							.ok_or(crate::libwallet::ErrorKind::SwapError(
								"Unable to start mwcmqs listener".to_string(),
							))?
							.0
							.get_publisher_address()
							.map_err(|e| {
								crate::libwallet::ErrorKind::SwapError(format!(
									"Unable to get publisher address {}",
									e
								))
							})?
							.get_full_name();
					}
					"tor" => {
						if !controller::is_foreign_api_running() {
							let tor_config = tor_config.clone().ok_or(
								crate::libwallet::ErrorKind::GenericError(
									"Tor configuration is not defined".to_string(),
								),
							)?;
							let _api_thread = thread::Builder::new()
								.name("wallet-http-listener".to_string())
								.spawn(move || {
									let res = controller::foreign_listener(
										wallet_inst2,
										Arc::new(Mutex::new(km)),
										&api_listen_addr,
										tls_conf,
										tor_config.use_tor_listener,
									);
									if let Err(e) = res {
										error!("Error starting http listener: {}", e);
									}
								});
							thread::sleep(Duration::from_millis(2000));
						}
						from_address = controller::get_current_tor_address().ok_or(
							crate::libwallet::ErrorKind::GenericError(
								"Tor is not running".to_string(),
							),
						)?;
					}
					"file" => {
						// File, let's process it here
						let msg_str = swap_message.to_json()?;
						let mut file = File::create(dest.clone())?;
						file.write_all(msg_str.as_bytes()).map_err(|e| {
							crate::libwallet::ErrorKind::SwapError(format!(
								"Unable to store message data to the destination file, {}",
								e
							))
						})?;
						println!("Message is written into the file {}", dest);
						return Ok((true, destination_str)); // ack if true, because file is concidered as delivered
					}
					_ => {
						error!("Please specify a method (mwcmqs, tor, or file) for transporting swap messages to the other party with whom you're doing the swap!");
						return Err(crate::libwallet::Error::from(
							crate::libwallet::ErrorKind::SwapError(
								"Expected 'method' argument is not found".to_string(),
							),
						));
					}
				}

				// File is processed, the online send will be handled here
				let sender = create_swap_message_sender(
					method.as_str(),
					dest.as_str(),
					&apisecret,
					tor_config,
				)
				.map_err(|e| {
					crate::libwallet::ErrorKind::SwapError(format!(
						"Unable to create message sender, {}",
						e
					))
				})?;

				let mut swap_message = swap_message;
				if let message::Update::Offer(offer_update) = &mut swap_message.inner {
					offer_update.from_address = from_address;
				}

				let ack = sender
					.send_swap_message(&swap_message)
					.map_err(|e| {
						ErrorKind::LibWallet(format!(
							"Failure in sending swap message {} by {}: {}",
							swap_id2, method, e
						))
					})
					.map_err(|e| {
						crate::libwallet::ErrorKind::SwapError(format!(
							"Unable to deliver the message, {}",
							e
						))
					})?;
				Ok((ack, destination_str))
			};

			let result = owner_swap::swap_process(
				wallet_inst,
				keychain_mask,
				&swap_id,
				message_sender,
				args.message_file_name,
				args.buyer_refund_address,
				args.secondary_fee,
				args.secondary_address,
				args.electrum_node_uri1,
				args.electrum_node_uri2,
			);

			match result {
				Ok(_) => Ok(()),
				Err(e) => {
					error!("Unable to process Swap {}: {}", swap_id, e);
					Err(
						ErrorKind::LibWallet(format!("Unable to process Swap {}: {}", swap_id, e))
							.into(),
					)
				}
			}
		}
		SwapSubcommand::Autoswap => {
			// Note !!!
			// For auto swap --json_format is a trigger for a one shot action.
			let one_shot = args.json_format;

			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			if args.method.is_some() || args.destination.is_some() {
				return Err(ErrorKind::ArgumentError(
					"swap --autoswap doesn't accept 'method' or 'dest' parameters, instead it is using parameters associated with this swap trade.".to_string()).into());
			}

			let swap = owner_swap::swap_get(wallet_inst.clone(), keychain_mask, &swap_id)?;

			let wallet_inst2 = wallet_inst.clone();
			let km2 = km.clone();

			if !one_shot {
				SWAP_THREADS_RUN.swap(false, Ordering::Relaxed);
			}

			if args.start_listener {
				match swap.communication_method.as_str() {
					"mwcmqs" => {
						if grin_wallet_impls::adapters::get_mwcmqs_brocker().is_some() {
							return Err(ErrorKind::GenericError("mwcmqs listener is already running, there is no need to specify '--start_listener' parameter".to_string()).into());
						}

						// Startting MQS
						let _ = controller::start_mwcmqs_listener(
							wallet_inst,
							mqs_config.expect("No MQS config found!").clone(),
							false,
							Arc::new(Mutex::new(km)),
							true,
						)
						.map_err(|e| {
							ErrorKind::LibWallet(format!("Unable to start mwcmqs listener, {}", e))
						})?;
						thread::sleep(Duration::from_millis(2000));
					}
					"tor" => {
						// Checking is foreign API is running. It dont't important if it is tor or http.
						if controller::is_foreign_api_running() {
							return Err(ErrorKind::GenericError("tor or http listener is already running, there is no need to specify '--start_listener' parameter".to_string()).into());
						}

						// Starting tor
						let tor_config = tor_config.clone().ok_or(ErrorKind::GenericError(
							"Tor configuration is not defined".to_string(),
						))?;
						let _api_thread = thread::Builder::new()
							.name("wallet-http-listener".to_string())
							.spawn(move || {
								let res = controller::foreign_listener(
									wallet_inst,
									Arc::new(Mutex::new(km)),
									&api_listen_addr,
									tls_conf,
									tor_config.use_tor_listener,
								);
								if let Err(e) = res {
									error!("Error starting http listener: {}", e);
								}
							});
						thread::sleep(Duration::from_millis(2000));
					}
					_ => {
						return Err(ErrorKind::ArgumentError(format!(
							"Auto Swap doesn't support communication method {}",
							swap.communication_method
						))
						.into());
					}
				}
			}

			// Checking if we are ready to send messages
			let from_address;
			match swap.communication_method.as_str() {
				"mwcmqs" => {
					// Validating destination address
					let _ = MWCMQSAddress::from_str(&swap.communication_address).map_err(|e| {
						ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
					})?;

					if grin_wallet_impls::adapters::get_mwcmqs_brocker().is_none() {
						return Err(ErrorKind::GenericError("mqcmqs listener is not running. Please start it with 'listen' command or '--start_listener' argument".to_string()).into());
					}
					from_address = grin_wallet_impls::adapters::get_mwcmqs_brocker()
						.ok_or(ErrorKind::GenericError(
							"Unable to start mwcmqs listener".to_string(),
						))?
						.0
						.get_publisher_address()
						.map_err(|e| {
							ErrorKind::GenericError(format!(
								"Unable to get publisher address {}",
								e
							))
						})?
						.get_full_name();
				}
				"tor" => {
					// Validating tor address
					let _ = validate_tor_address(&swap.communication_address).map_err(|e| {
						ErrorKind::ArgumentError(format!("Invalid destination address, {}", e))
					})?;

					if !controller::is_foreign_api_running() {
						return Err(ErrorKind::GenericError("tor listener is not running. Please start it with 'listen' command or '--start_listener' argument".to_string()).into());
					}
					from_address = controller::get_current_tor_address()
						.ok_or(ErrorKind::GenericError("Tor is not running".to_string()))?;
				}
				_ => {
					return Err(ErrorKind::ArgumentError(format!(
						"Auto Swap doesn't support communication method {}",
						swap.communication_method
					))
					.into());
				}
			}

			// Creating message delivery transport as a closure
			let apisecret = args.apisecret.clone();
			let swap_id2 = swap_id.clone();
			let message_sender = move |swap_message: message::Message,
			                           method: String,
			                           destination: String|
			      -> Result<(bool, String), crate::libwallet::Error> {
				// File is processed, the online send will be handled here
				let sender = create_swap_message_sender(
					method.as_str(),
					destination.as_str(),
					&apisecret,
					tor_config,
				)
				.map_err(|e| {
					crate::libwallet::ErrorKind::SwapError(format!(
						"Unable to create message sender, {}",
						e
					))
				})?;

				let mut swap_message = swap_message;
				if let message::Update::Offer(offer_update) = &mut swap_message.inner {
					offer_update.from_address = from_address;
				}

				let ack = sender.send_swap_message(&swap_message).map_err(|e| {
					crate::libwallet::ErrorKind::SwapError(format!(
						"Unable to deliver the message {} by {}: {}",
						swap_id2, method, e
					))
				})?;
				Ok((ack, format!("{} {}", method, destination)))
			};

			// Calling mostly for params and environment validation. Also it is a nice chance to print the status of the deal that will be started
			let (mut prev_state, mut prev_action, mut prev_journal_len) = {
				let conf_status = owner_swap::get_swap_tx_tstatus(
					wallet_inst2.clone(),
					keychain_mask,
					&swap_id,
					args.electrum_node_uri1.clone(),
					args.electrum_node_uri2.clone(),
				)?;
				let (state, action, time_limit, roadmap, journal_records) =
					owner_swap::update_swap_status_action(
						wallet_inst2.clone(),
						keychain_mask,
						&swap_id,
						args.electrum_node_uri1,
						args.electrum_node_uri2,
					)?;

				// Autoswap has to be sure that ALL parameters are defined. There are multiple steps and potentioly all of them can be used.
				// We are checking them here because the swap object is known, so the second currency is known. And we can validate the data
				if !swap.is_seller() {
					match &args.buyer_refund_address {
						Some(addr) => {
							swap.secondary_currency
								.validate_address(addr)
								.map_err(|e| {
									ErrorKind::ArgumentError(format!(
										"Invalid secondary currency address {}, {}",
										addr, e
									))
								})?
						}
						None => {
							if swap.get_secondary_address().is_empty() {
								return Err(ErrorKind::GenericError(
									"Please define buyer_refund_address for automated swap"
										.to_string(),
								)
								.into());
							}
						}
					}
				}

				if !args.json_format {
					display::swap_trade(
						&swap,
						&action,
						&time_limit,
						&conf_status,
						&roadmap,
						&journal_records,
						true,
					)?;
				}
				(state, action, journal_records.len())
			};

			if !one_shot {
				println!(
					"Swap started in auto mode.... Status will be displayed as swap progresses."
				);
			}

			// NOTE - we can't process errors with '?' here. We can't exit, we must try forever or until we get a final state
			let swap_id2 = swap_id.clone();
			let fee_satoshi = args.secondary_fee.clone();
			let file_name = args.message_file_name.clone();
			let refund_address = args.buyer_refund_address.clone();
			let secondary_address = args.secondary_address.clone();
			let swap_report_prefix = if cli_mode {
				format!("Swap Trade {}: ", swap_id)
			} else {
				"".to_string()
			};
			let stop_thread_clone = SWAP_THREADS_RUN.clone();
			let json_format_clone = args.json_format.clone();

			debug!("Starting autoswap thread for swap id {}", swap_id);
			let api_thread = thread::Builder::new()
				.name("wallet-auto-swap".to_string())
				.spawn(move || {
					loop {
						// we can't exit by error from the loop.
						let (
							mut curr_state,
							mut curr_action,
							_time_limit,
							roadmap,
							mut journal_records,
						) = match owner_swap::update_swap_status_action(
							wallet_inst2.clone(),
							km2.as_ref(),
							&swap_id2,
							None,None, // URIs are already updated
						) {
							Ok(res) => res,
							Err(e) => {
								error!("Error during Swap {}: {}", swap_id2, e);
								thread::sleep(Duration::from_millis(10000));
								continue;
							}
						};

						// If actin require execution - it must be executed
						let mut was_executed = false;
						if !curr_state.is_final_state() && curr_action.can_execute() {
							match owner_swap::swap_process(
								wallet_inst2.clone(),
								km2.as_ref(),
								swap_id2.as_str(),
								message_sender.clone(),
								file_name.clone(),
								refund_address.clone(),
								fee_satoshi.clone(),
								secondary_address.clone(),
								None, None, // URIs was already updated before. No need to update the same.
							) {
								Ok(res) => {
									curr_state = res.next_state_id;
									if let Some(a) = res.action {
										curr_action = a;
									}
									journal_records = res.journal;
								}
								Err(e) => error!("Error during Swap {}: {}", swap_id2, e),
							}
							// We can execute in the row. Internal guarantees that we will never do retry to the same action unless it is an error
							// The sleep here for possible error
							was_executed = true;
							debug!(
								"Action {} for swap id {} was excecuted",
								curr_action, swap_id2
							);
						}

						if !json_format_clone {
							if prev_journal_len < journal_records.len() {
								for i in prev_journal_len..journal_records.len() {
									println!(
										"{}{}",
										swap_report_prefix, journal_records[i].message
									);
								}
								prev_journal_len = journal_records.len();
							}

							let curr_action_str = if curr_action.is_none() {
								"".to_string()
							} else {
								curr_action.to_string()
							};

							if curr_state != prev_state {
								if curr_action_str.len() > 0 {
									println!("{}{}", swap_report_prefix, curr_action_str);
								} else {
									println!(
										"{}{}. {}",
										swap_report_prefix, curr_state, curr_action_str
									);
								}
								prev_state = curr_state.clone();
								prev_action = curr_action.clone();
							} else if curr_action.to_string() != prev_action.to_string() {
								if curr_action_str.len() > 0 {
									println!("{}{}", swap_report_prefix, curr_action);
								}
								prev_action = curr_action.clone();
							}
						}

						// In case of Json printing, executing one step and exiting.
						if json_format_clone {
							let road_map_to_print: Vec<StateEtaInfoString> = roadmap
								.iter()
								.map(|r| StateEtaInfoString {
									active: r.active,
									name: r.name.clone(),
									end_time: r.end_time.map(|r| r.to_string()),
								})
								.collect();

							let journal_records_to_print: Vec<SwapJournalRecordString> = journal_records
								.iter()
								.map(|j| SwapJournalRecordString {
									time: j.time.to_string(),
									message: j.message.to_string(),
								})
								.collect();

							let item = json::json!({
									"swap_id" : swap_id2.clone(),
									"autowsap_done" : curr_state.is_final_state(),
									"currentAction": curr_action.to_string(),
									"currentState" : curr_state.to_string(),
									"roadmap" : road_map_to_print,
									"journal_records" : journal_records_to_print,
								});
							println!("JSON: {}", item.to_string());
							break;
						}

						// In case of final state - we are exiting.
						if curr_state.is_final_state() {
							println!("{}Swap trade is finished", swap_report_prefix);
							break;
						}

						let seconds_to_sleep = if was_executed {
							10
						} else {
							60
						};

						let mut exited = false;
						for _i in 0..seconds_to_sleep {
							// check if the thread is asked to stop
							if stop_thread_clone.load(Ordering::Relaxed) {
								println!("Auto swap for trade {} is stopped. You can continue with the swap manually by entering individual commands.", swap_id2);
								exited = true;
								break;
							};
							thread::sleep(Duration::from_millis(1000));
						}
						if exited {
							break;
						}
					}
				});

			if let Ok(t) = api_thread {
				if !cli_mode || one_shot {
					let r = t.join();
					if let Err(_) = r {
						error!("Error during running autoswap thread for {}", swap_id);
						return Err(ErrorKind::LibWallet(format!(
							"Error during running autoswap thread for {}",
							swap_id
						))
						.into());
					}
				}
			}
			Ok(())
		}
		SwapSubcommand::StopAllAutoSwap => {
			let mut answer = String::new();
			let input = io::stdin();
			println!("This command is going to stop all the ongoing auto-swap threads. You can continue with the swap manually by entering commands step by step.");
			println!("Do you want to continue? Please answer Yes/No");
			input.read_line(&mut answer).map_err(|e| {
				ErrorKind::LibWallet(format!(
					"Invalid answer to terminating the auto swap threads, {}",
					e
				))
			})?;

			if answer.trim().to_lowercase().starts_with("y") {
				println!("Stopping.....");
				SWAP_THREADS_RUN.swap(true, Ordering::Relaxed);
			}
			Ok(())
		}
		SwapSubcommand::Dump => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;
			let result = owner_swap::swap_dump(wallet_inst, keychain_mask, &swap_id);
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
					Err(ErrorKind::LibWallet(format!(
						"Unable to dump the content of the swap file {}.swap: {}",
						swap_id, e
					))
					.into())
				}
			}
		}
		SwapSubcommand::TradeExport => {
			let swap_id = args.swap_id.ok_or(ErrorKind::ArgumentError(
				"Not found expected 'swap_id' argument".to_string(),
			))?;

			let file_name = args.destination.ok_or(ErrorKind::ArgumentError(
				"Not found expected file name for the exported data".to_string(),
			))?;

			trades::export_trade(swap_id.as_str(), file_name.as_str())
				.map_err(|e| ErrorKind::LibWallet(format!("Unable to export trade data, {}", e)))?;

			println!("Swap trade is exported to {}", file_name);
			Ok(())
		}
		SwapSubcommand::TradeImport => {
			let trade_file_name = args.destination.ok_or(ErrorKind::ArgumentError(
				"Not found expected file name for the exported data".to_string(),
			))?;

			let swap_id = owner_swap::swap_import_trade(
				wallet_inst,
				keychain_mask,
				trade_file_name.as_str(),
			)?;
			println!(
				"Swap trade {} is restored from the file {}",
				swap_id, trade_file_name
			);
			Ok(())
		}
	}
}
