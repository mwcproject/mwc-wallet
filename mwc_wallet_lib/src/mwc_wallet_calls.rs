// Copyright 2025 The MWC Developers
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

use crate::callback_node_client::CallbackNodeClient;
use crate::encode_slatepack::encode_slatepack;
use crate::finalize::finalize;
use crate::post::post;
use crate::receive::receive;
use crate::repost::{get_finalized_transaction, repost};
use crate::scan::{scan, scan_rewind_hash, update_wallet_state};
use crate::wallet_lock;
use lazy_static::lazy_static;
use mwc_wallet_api::{Owner, TxLogEntryAPI};
use mwc_wallet_config::{GlobalWalletConfigMembers, MQSConfig, WalletConfig};
use mwc_wallet_controller::command::{send, SendArgs};
use mwc_wallet_controller::controller::{
	get_foreign_api_health, is_foreign_api_running, stop_foreign_api_running,
};
use mwc_wallet_controller::{command, controller};
use mwc_wallet_impls::adapters::reset_mwcmqs_brocker;
use mwc_wallet_impls::lifecycle::WalletSeed;
use mwc_wallet_impls::{
	get_mwcmqs_brocker, keychain, DefaultLCProvider, DefaultWalletImpl, HttpDataSender,
};
use mwc_wallet_libwallet::foreign::{clean_receive_callback, set_receive_callback, ReceiveData};
use mwc_wallet_libwallet::internal::{keys, tx, updater};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::types::U64_DATA_IDX_ADDRESS_INDEX;
use mwc_wallet_libwallet::{
	foreign, owner, OwnershipProof, OwnershipProofValidation, SlatePurpose, TxProof,
	VersionedSlate, ViewWallet, WalletInst,
};
use mwc_wallet_util::mwc_core::global::ChainTypes;
use mwc_wallet_util::mwc_keychain::Identifier;
use mwc_wallet_util::mwc_node_lib::ffi::LIB_CALLBACKS;
use mwc_wallet_util::mwc_node_workflow::context::{allocate_new_context, release_context};
use mwc_wallet_util::mwc_p2p::tor::arti::is_arti_healthy;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::static_secp_instance;
use mwc_wallet_workflow::wallet::{init_wallet_context, release_wallet_context};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

pub type LibWallet = dyn WalletInst<
	'static,
	DefaultLCProvider<'static, CallbackNodeClient, keychain::ExtKeychain>,
	CallbackNodeClient,
	keychain::ExtKeychain,
>;

pub type WalletArc = Arc<Mutex<Box<LibWallet>>>;

lazy_static! {
	// Full config for all wallet
	static ref WALLET_CONFIG:  RwLock<HashMap<u32,GlobalWalletConfigMembers> > = RwLock::new(HashMap::new());

	static ref WALLET_INSTANCE: RwLock<HashMap<u32,WalletArc> > = RwLock::new(HashMap::new());
}

fn release_wallet(context_id: u32) {
	let _ = (*WALLET_CONFIG)
		.write()
		.expect("RwLock falure")
		.remove(&context_id);
	let _ = (*WALLET_INSTANCE)
		.write()
		.expect("RwLock falure")
		.remove(&context_id);
}

fn get_wallet_config(context_id: u32) -> Result<GlobalWalletConfigMembers, String> {
	Ok((*WALLET_CONFIG)
		.read()
		.expect("RwLock failure")
		.get(&context_id)
		.ok_or("Wallet config is not set. Call 'init_wallet' first".to_string())?
		.clone())
}

pub fn get_wallet_instance(context_id: u32) -> Result<WalletArc, String> {
	let wallet = (*WALLET_INSTANCE)
		.write()
		.expect("RwLock falure")
		.get(&context_id)
		.ok_or("Wallet is not set. Call init,restore or open wallet first".to_string())?
		.clone();
	Ok(wallet)
}

fn create_node_client(callback_name: &String) -> Result<CallbackNodeClient, String> {
	let (cb, context) = (*LIB_CALLBACKS)
		.read()
		.expect("RwLock failure")
		.get(callback_name)
		.ok_or(format!(
			"Callback {} is not found, use 'register_lib_callback' to add it",
			callback_name
		))?
		.clone();

	let node_client = CallbackNodeClient::new(cb, context);
	Ok(node_client)
}

fn create_wallet_instance(
	context_id: u32,
	node_client: CallbackNodeClient,
	config: &WalletConfig,
) -> Result<WalletArc, String> {
	let mut wallet = Box::new(DefaultWalletImpl::<'static, CallbackNodeClient>::new(
		context_id,
		node_client,
	)) as Box<LibWallet>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&config.data_file_dir);
	let wallet = Arc::new(Mutex::new(wallet));

	if (*WALLET_INSTANCE)
		.read()
		.expect("RwLock falure")
		.contains_key(&context_id)
	{
		return Err(format!("Wallet already created for context {}", context_id));
	}

	(*WALLET_INSTANCE)
		.write()
		.expect("RwLock falure")
		.insert(context_id, wallet.clone());
	Ok(wallet)
}

fn zip_file(src_path: &str, dst_path: &str, dst_file_name: &str) -> Result<(), String> {
	let dst_file = File::create(dst_path)
		.map_err(|e| format!("Unable create target zip file {}, {}", dst_path, e))?;

	let mut zip = zip::ZipWriter::new(dst_file);

	let mut src = File::open(src_path)
		.map_err(|e| format!("Unable to open source file {}, {}", src_path, e))?;

	let options = zip::write::SimpleFileOptions::default()
		.compression_method(zip::CompressionMethod::Deflated)
		.unix_permissions(0o600);

	zip.start_file(dst_file_name, options)
		.map_err(|e| format!("Unable to start zip archive, {}", e))?;

	std::io::copy(&mut src, &mut zip)
		.map_err(|e| format!("Failed to write data into zip, {}", e))?;

	zip.finish()
		.map_err(|e| format!("Unable to finalize zip archive, {}", e))?;

	Ok(())
}

fn process_request(input: String) -> Result<Value, String> {
	let input_json: Value = serde_json::from_str(input.as_str())
		.map_err(|e| format!("Unable to parse input as a json, {}", e))?;

	let method = match input_json.get("method") {
		Some(method) => method
			.as_str()
			.ok_or("Invalid 'method' value ")?
			.to_string(),
		None => return Err("Not found input 'method' attribute".into()),
	};

	let params = match input_json.get("params") {
		Some(params) => params.clone(),
		None => return Err("Not found input 'params' attribute".into()),
	};

	let response = match method.as_str() {
		"register_receive_slate_callback" => {
			let callback_name: String = get_param(&params, "callback_name")?;

			let (cb, ctx) = LIB_CALLBACKS
				.read()
				.expect("RwLock failure")
				.get(&callback_name)
				.cloned()
				.ok_or(format!(
					"Callback function {} is not registered",
					callback_name
				))?;

			let callback = move |slate_info: ReceiveData| {
				let slate_info_str = serde_json::to_string(&slate_info)
					.expect("Internal error. ReceiveData not converted into json");
				let c_slate_info_str =
					CString::new(slate_info_str).expect("Unable convert string into C format");
				let c_compatible_ref: *const libc::c_char = c_slate_info_str.as_c_str().as_ptr();
				// Note, c_compatible_ref can't be stored at C code
				cb(ctx as *mut std::ffi::c_void, c_compatible_ref);
			};

			set_receive_callback(Box::new(callback));
			json!({})
		}
		"clean_receive_slate_callback" => {
			clean_receive_callback();
			json!({})
		}
		// Prepare to work with a wallet. Param - wallet config
		"init_wallet" => {
			let mut config: GlobalWalletConfigMembers = get_param(&params, "config")?;
			let context_id = allocate_new_context(
				config.wallet.chain_type.unwrap_or(ChainTypes::Mainnet),
				config.wallet.tx_fee_base,
				None,
				&None,
			)
			.map_err(|e| format!("Failed to allocate a new context. {}", e))?;
			init_wallet_context(context_id);

			if config.tor.is_none() {
				config.tor = Some(TorConfig::default());
			}

			if config.mqs.is_none() {
				config.mqs = Some(MQSConfig::default())
			}

			WALLET_CONFIG
				.write()
				.expect("RwLock failure")
				.insert(context_id, config);
			json!({"context_id" : context_id})
		}
		// Release all resources associated with this wallet.
		"release_wallet" => {
			let context_id = get_param(&params, "context_id")?;
			release_wallet_context(context_id);
			release_wallet(context_id);
			release_context(context_id).map_err(|e| format!("Unable to release context, {}", e))?;
			json!({})
		}
		// Create brand new wallet. Will generate a passphrase for this new instance.
		"create_new_wallet" => {
			let context_id = get_param(&params, "context_id")?;
			let callback_name: String = get_param(&params, "node_client_callback")?;
			let mnemonic_length: usize = get_param(&params, "mnemonic_length")?;
			let password: String = get_param(&params, "password")?;
			let config: GlobalWalletConfigMembers = get_wallet_config(context_id)?;

			// convert mnemonic length in words into mnemonic in bytes
			let mnemonic_length = mnemonic_length + mnemonic_length / 3;

			{
				let data_path = PathBuf::from(config.wallet.data_file_dir.as_str());
				fs::create_dir_all(data_path).map_err(|e| {
					format!(
						"Unabel to create data directory {}, {}",
						config.wallet.data_file_dir, e
					)
				})?;
			}

			let node_client = create_node_client(&callback_name)?;
			let wallet = create_wallet_instance(context_id, node_client, &config.wallet)?;

			let mut w_lock = wallet.lock().expect("Mutex failure");
			let p = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;

			let mnemonic = p
				.create_wallet(
					None,
					None,
					mnemonic_length,
					password.into(),
					false,
					config.wallet.wallet_data_dir.as_ref().map(|s| s.as_str()),
					false,
				)
				.map_err(|e| format!("Unable to create wallet, {}", e))?;

			json!({
				"mnemonic" : mnemonic.to_string()
			})
		}
		"restore_new_wallet" => {
			let context_id = get_param(&params, "context_id")?;
			let callback_name: String = get_param(&params, "node_client_callback")?;
			let mnemonic: String = get_param(&params, "mnemonic")?;
			let password: String = get_param(&params, "password")?;
			let config: GlobalWalletConfigMembers = get_wallet_config(context_id)?;

			{
				let data_path = PathBuf::from(config.wallet.data_file_dir.as_str());
				fs::create_dir_all(data_path).map_err(|e| {
					format!(
						"Unable to create data directory {}, {}",
						config.wallet.data_file_dir, e
					)
				})?;
			}

			let node_client = create_node_client(&callback_name)?;
			let wallet = create_wallet_instance(context_id, node_client, &config.wallet)?;

			let mut w_lock = wallet.lock().expect("Mutex failure");
			let p = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;

			let _mnemonic = p
				.create_wallet(
					None,
					Some(mnemonic.into()),
					0,
					password.into(),
					false,
					config.wallet.wallet_data_dir.as_ref().map(|s| s.as_str()),
					false,
				)
				.map_err(|e| format!("Unable to create wallet, {}", e))?;

			json!({})
		}
		"open_wallet" => {
			let context_id = get_param(&params, "context_id")?;
			let callback_name: String = get_param(&params, "node_client_callback")?;
			let password: String = get_param(&params, "password")?;
			let config: GlobalWalletConfigMembers = get_wallet_config(context_id)?;

			let node_client = create_node_client(&callback_name)?;
			let wallet = create_wallet_instance(context_id, node_client, &config.wallet)?;

			let mut w_lock = wallet.lock().expect("Mutex failure");
			let p = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;

			let _empty_mask = p
				.open_wallet(
					None,
					password.into(),
					false,
					false,
					config.wallet.wallet_data_dir.as_ref().map(|s| s.as_ref()),
				)
				.map_err(|e| format!("Unable to open the wallet, {e}"))?;

			json!({})
		}
		"close_wallet" => {
			let context_id = get_param(&params, "context_id")?;

			let wallet = get_wallet_instance(context_id)?;
			let mut w_lock = wallet.lock().expect("Mutex failure");
			let lc = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;
			lc.close_wallet(None)
				.map_err(|e| format!("Unable to close wallet, {}", e))?;
			json!({})
		}
		"get_mnemonic" => {
			let context_id = get_param(&params, "context_id")?;
			let password: String = get_param(&params, "password")?;

			let config: GlobalWalletConfigMembers = get_wallet_config(context_id)?;
			let wallet = get_wallet_instance(context_id)?;

			let mut w_lock = wallet.lock().expect("Mutex failure");
			let lc = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;
			let mnemonic = lc
				.get_mnemonic(
					None,
					password.into(),
					Some(config.wallet.data_file_dir.as_str()),
				)
				.map_err(|e| format!("Unable to get mnemonic, {}", e))?;

			json!({
				"mnemonic" : mnemonic.to_string()
			})
		}
		"validate_password" => {
			let context_id = get_param(&params, "context_id")?;
			let password: String = get_param(&params, "password")?;
			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let data_file_dir = w.get_data_file_dir();
			let valid = WalletSeed::from_file(data_file_dir, password.into()).is_ok();
			json!({
				"valid" : valid,
			})
		}
		"change_password" => {
			let context_id = get_param(&params, "context_id")?;
			let old_password: String = get_param(&params, "old_password")?;
			let new_password: String = get_param(&params, "new_password")?;

			let config: GlobalWalletConfigMembers = get_wallet_config(context_id)?;
			let wallet = get_wallet_instance(context_id)?;

			let mut w_lock = wallet.lock().expect("Mutex failure");
			let lc = w_lock
				.lc_provider()
				.map_err(|e| format!("Wallet is invalid, {}", e))?;
			lc.change_password(
				None,
				old_password.into(),
				new_password.into(),
				Some(config.wallet.data_file_dir.as_str()),
			)
			.map_err(|e| format!("Unable to change a password, {}", e))?;
			json!({})
		}
		"start_tor_listener" => {
			let context_id = get_param(&params, "context_id")?;

			let wallet = get_wallet_instance(context_id)?;

			let tor_config = TorConfig::arti_tor_config();
			controller::foreign_listener(
				wallet,
				Arc::new(Mutex::new(None)),
				None,
				&tor_config,
				&None,
			)
			.map_err(|e| format!("Unable to start Tor listener, {}", e))?;

			json!({})
		}
		"get_tor_listener_status" => {
			let context_id = get_param(&params, "context_id")?;

			let is_running = is_foreign_api_running(context_id);
			let is_healthy = is_running && is_arti_healthy() && get_foreign_api_health(context_id);
			json!({
				"running" : is_running,
				"healthy" : is_healthy,
			})
		}
		"stop_tor_listener" => {
			let context_id = get_param(&params, "context_id")?;
			stop_foreign_api_running(context_id);
			json!({})
		}
		"start_mqs_listener" => {
			let context_id = get_param(&params, "context_id")?;

			let wallet = get_wallet_instance(context_id)?;

			controller::init_start_mwcmqs_listener(
				wallet,
				MQSConfig::default(),
				Arc::new(Mutex::new(None)),
				false,
			)
			.map_err(|e| format!("Unable to start MQS listener, {}", e))?;
			json!({})
		}
		"get_mqs_listener_status" => {
			let context_id = get_param(&params, "context_id")?;
			let (is_running, is_healthy) = match get_mwcmqs_brocker(context_id) {
				Some((_publisher, subscriber)) => {
					(subscriber.is_mqs_running(), subscriber.is_mqs_healthy())
				}
				None => (false, false),
			};
			json!({
				"running" : is_running,
				"healthy" : is_healthy,
			})
		}
		"stop_mqs_listener" => {
			let context_id = get_param(&params, "context_id")?;
			reset_mwcmqs_brocker(context_id);
			json!({})
		}
		// Update Tor/Slatepack/MQS address index. Expected that listeners are not running or at least will be restarted after
		"set_address_index" => {
			let context_id = get_param(&params, "context_id")?;
			let address_index: u32 = get_param(&params, "address_index")?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			{
				let mut batch = w
					.batch(None)
					.map_err(|e| format!("Batch access error, {}", e))?;
				batch
					.save_u64(U64_DATA_IDX_ADDRESS_INDEX, address_index as u64)
					.map_err(|e| format!("Db save error, {}", e))?;
				batch
					.commit()
					.map_err(|e| format!("Db commit error, {}", e))?;
			};
			json!({})
		}
		// Request Tor/Slatepack/MQS
		"get_address_index" => {
			let context_id = get_param(&params, "context_id")?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let address_index: u32 = {
				let mut batch = w
					.batch(None)
					.map_err(|e| format!("Batch access error, {}", e))?;
				let index = batch
					.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)
					.map_err(|e| format!("Db load error, {}", e))?;
				index as u32
			};
			json!({
				"address_index" : address_index,
			})
		}
		"rewind_hash" => {
			let context_id = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;
			let rewind_hash = owner::get_rewind_hash(wallet, None)
				.map_err(|e| format!("Rewind hash error, {}", e))?;
			json!({
				"rewind_hash" : rewind_hash,
			})
		}
		"scan_rewind_hash" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let rewind_hash: String = get_param(&params, "rewind_hash")?;
			let response_callback: String = get_param(&params, "response_callback")?;
			let response_id: String = get_param(&params, "response_id")?;

			let vew_res: ViewWallet =
				scan_rewind_hash(context_id, rewind_hash, response_callback, response_id)?;

			serde_json::to_value(&vew_res)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"generate_ownership_proof" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let message: String = get_param(&params, "message")?;
			let include_rewind_hash: Option<bool> =
				get_option_param(&params, "include_rewind_hash")?;
			let include_tor_address: Option<bool> =
				get_option_param(&params, "include_tor_address")?;
			let include_mqs_address: Option<bool> =
				get_option_param(&params, "include_mqs_address")?;

			let wallet = get_wallet_instance(context_id)?;
			let proof: OwnershipProof = owner::generate_ownership_proof(
				wallet,
				None,
				message,
				include_rewind_hash.unwrap_or(true),
				include_tor_address.unwrap_or(true),
				include_mqs_address.unwrap_or(true),
			)
			.map_err(|e| format!("Failed to generate ownership proof, {}", e))?;

			serde_json::to_value(&proof)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"validate_ownership_proof" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let proof: OwnershipProof = get_param(&params, "ownership_proof")?;

			let validation: OwnershipProofValidation =
				owner::validate_ownership_proof(context_id, proof)
					.map_err(|e| format!("Failed to validate ownership proof, {}", e))?;

			serde_json::to_value(&validation)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"create_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let account_name: String = get_param(&params, "account_name")?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let account_path = owner::create_account_path(&mut **w, None, &account_name)
				.map_err(|e| format!("Unable create account, {}", e))?;
			json!({
				"account_path" : account_path,
			})
		}
		"list_accounts" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let mut acc_res =
				keys::accounts(&mut **w).map_err(|e| format!("Accounts request failed, {}", e))?;

			acc_res.sort_by_key(|a| a.path.clone());

			let accounts = serde_json::to_value(&acc_res)
				.map_err(|e| format!("Unable convert result into json, {}", e))?;
			json!({
				"accounts" : accounts,
			})
		}
		"rename_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let account_path: Identifier = get_param(&params, "account_path")?;
			let account_name: String = get_param(&params, "account_name")?;

			let wallet = get_wallet_instance(context_id)?;

			wallet_lock!(wallet, w);

			let accounts =
				keys::accounts(&mut **w).map_err(|e| format!("Accounts request failed, {}", e))?;

			let old_acc_name = accounts
				.iter()
				.find(|a| a.path == account_path)
				.map(|a| a.label.clone())
				.ok_or("Not found account to rename")?;

			keys::rename_acct_path(&mut **w, None, accounts, &old_acc_name, &account_name)
				.map_err(|e| format!("Unable to rename account, {}", e))?;

			json!({})
		}
		// Get current account path
		"current_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let account_path = w.parent_key_id();
			json!({
				"account_path" : account_path,
			})
		}
		// Change current account
		"switch_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let account_id: Identifier = get_param(&params, "account_path")?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);

			w.set_parent_key_id(account_id);
			json!({})
		}
		// Get recieve funds account path
		"receive_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;

			let receive_path = foreign::get_receive_account(context_id);

			let receive_path = match receive_path {
				Some(path) => path,
				None => {
					let wallet = get_wallet_instance(context_id)?;
					wallet_lock!(wallet, w);
					w.parent_key_id()
				}
			};

			json!({
				"account_path" : receive_path,
			})
		}
		// Set recieve funds account path
		"switch_receive_account" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let account: Identifier = get_param(&params, "account_path")?;
			foreign::set_receive_account(context_id, account);
			json!({})
		}
		"send" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;

			let args: SendArgs = get_param(&params, "send_args")?;

			let mut owner =
				Owner::new(context_id, wallet, None, Some(TorConfig::arti_tor_config()));
			let res_tx_uuid = send(
				&mut owner,
				None,
				Some(TorConfig::arti_tor_config()),
				Some(MQSConfig::default()),
				args,
				true,
			)
			.map_err(|e| e.to_string())?;
			if res_tx_uuid.is_none() {
				return Err("Intenal error. Tx UUID wasn't generated".into());
			}
			json!({
				"tx_uuid" : res_tx_uuid.unwrap().to_string(),
			})
		}
		"encode_slatepack" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let slate: VersionedSlate = get_param(&params, "slate")?;
			let content: SlatePurpose = get_param(&params, "content")?;
			let recipient: Option<String> = get_option_param(&params, "recipient")?;
			let address_index: Option<u32> = get_option_param(&params, "address_index")?;

			let sp_str = encode_slatepack(context_id, slate, recipient, content, address_index)?;

			json!({
				"slatepack": sp_str
			})
		}
		"decode_slatepack" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;
			let slatepack: String = get_param(&params, "slatepack")?;
			let address_index: Option<u32> = get_option_param(&params, "address_index")?;

			wallet_lock!(wallet, w);
			let (slate, content, sender, recipient) = foreign::decrypt_slate(
				&mut **w,
				None,
				VersionedSlate::SP(slatepack),
				address_index,
			)
			.map_err(|e| format!("Slate decryption error, {}", e))?;

			let slate_version = slate.lowest_version();
			let vslate = VersionedSlate::into_version_plain(context_id, &slate, slate_version)
				.map_err(|e| format!("Unable to convert slate, {}", e))?;

			json!({
				"slate" : serde_json::to_value(&vslate)
						.map_err(|e| format!("Unable build slate json, {}", e))?,
				"content" : serde_json::to_value(content)
						.map_err(|e| format!("Unable build content json, {}", e))?,
				"sender" : sender.map(|pk| ProvableAddress::from_tor_pub_key(&pk).public_key),
				"recipient": recipient.map(|pk| ProvableAddress::from_tor_pub_key(&pk).public_key),
			})
		}
		"receive" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let slatepack: String = get_param(&params, "slatepack")?;
			let message: Option<String> = get_option_param(&params, "message")?;
			let account: Option<String> = get_option_param(&params, "account")?;

			let (response_slatepack_str, tx_uuid) =
				receive(context_id, slatepack, message, account)?;

			json!({
				"reply" : response_slatepack_str,
				"tx_uuid" : tx_uuid.to_string(),
			})
		}
		"has_finalized_data" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_id: String = get_param(&params, "tx_id")?;

			let finalized = get_finalized_transaction(context_id, tx_id).is_ok();
			json!({
				"finalized" : finalized,
			})
		}
		"finalize" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let slatepack: String = get_param(&params, "slatepack")?;
			let fluff: Option<bool> = get_option_param(&params, "fluff")?;
			let nopost: Option<bool> = get_option_param(&params, "nopost")?;

			finalize(context_id, slatepack, fluff, nopost)?;
			json!({})
		}
		"info" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let confirmations: u64 = get_param(&params, "confirmations")?;
			let account: Identifier = get_param(&params, "account_path")?;
			let manually_locked_outputs: Vec<String> =
				get_param(&params, "manually_locked_outputs")?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet, w);
			let wallet_info =
				updater::retrieve_info(&mut **w, &account, confirmations, manually_locked_outputs)
					.map_err(|e| format!("Inable to retrieve wallet summary, {}", e))?;

			serde_json::to_value(&wallet_info)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"outputs" => {
			// Here we don't support pagination or request for specific output because
			// it is caller expacted to manage it's data. Wallert is not a DB, calls are expensive
			let context_id: u32 = get_param(&params, "context_id")?;
			let include_spent: Option<bool> = get_option_param(&params, "include_spent")?;
			let account: Identifier = get_param(&params, "account_path")?;

			let wallet = get_wallet_instance(context_id)?;

			wallet_lock!(wallet, w);
			let outputs = updater::retrieve_outputs(
				&mut **w,
				None,
				include_spent.unwrap_or(false),
				None,
				&account,
				None,
				None,
			)
			.map_err(|e| format!("Unable retrieve outputs, {}", e))?;

			let height = w
				.last_confirmed_height()
				.map_err(|e| format!("Failed to get last confirmed height, {}", e))?;

			let outputs = serde_json::to_value(&outputs)
				.map_err(|e| format!("Unable convert result into json, {}", e))?;
			json!({
				"outputs" : outputs,
				"height": height,
			})
		}
		"transactions" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let account: Identifier = get_param(&params, "account_path")?;

			let wallet = get_wallet_instance(context_id)?;

			wallet_lock!(wallet, w);
			let txs = updater::retrieve_txs(
				&mut **w,
				None,
				None,
				None,
				None,
				Some(&account),
				false,
				None,
				None,
				Some(false),
			)
			.map_err(|e| format!("Unable retrieve outputs, {}", e))?;

			let txs: Vec<TxLogEntryAPI> = txs
				.iter()
				.map(|l| TxLogEntryAPI::from_txlogentry(l))
				.collect();

			let transactions = serde_json::to_value(&txs)
				.map_err(|e| format!("Unable convert result into json, {}", e))?;

			let height = w
				.last_confirmed_height()
				.map_err(|e| format!("Failed to get last confirmed height, {}", e))?;

			json!({
				"transactions" : transactions,
				"height": height,
			})
		}
		"transaction_by_uuid" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_uuid: String = get_param(&params, "tx_uuid")?;

			let tx_uuid =
				Uuid::from_str(&tx_uuid).map_err(|e| format!("Invalid UUID value, {}", e))?;

			let wallet = get_wallet_instance(context_id)?;

			wallet_lock!(wallet, w);
			let txs = updater::retrieve_txs(
				&mut **w,
				None,
				None,
				Some(tx_uuid),
				None,
				None,
				false,
				None,
				None,
				Some(false),
			)
			.map_err(|e| format!("Unable retrieve outputs, {}", e))?;

			if txs.is_empty() {
				json!({})
			} else {
				let tx = TxLogEntryAPI::from_txlogentry(&txs[0]);
				let tx = serde_json::to_value(&tx)
					.map_err(|e| format!("Unable convert result into json, {}", e))?;
				tx
			}
		}
		// Check if transaction has proof
		"tx_proof" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_id: String = get_param(&params, "tx_id")?;

			let wallet = get_wallet_instance(context_id)?;

			let data_file_dir = {
				wallet_lock!(wallet.clone(), w);
				w.get_data_file_dir().to_string()
			};

			let has_proof = TxProof::get_stored_tx_proof(&data_file_dir, &tx_id).is_ok();
			json!({
				"has_proof" : has_proof,
			})
		}
		// Post any transaction (used for cold wallet setup)
		"post" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let input_path: String = get_param(&params, "input_path")?;
			let fluff: Option<bool> = get_option_param(&params, "fluff")?;

			post(context_id, input_path, fluff)?;

			json!({})
		}
		// Poset existing finalized transaciton
		"repost" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_id: String = get_param(&params, "tx_id")?;
			let fluff: Option<bool> = get_option_param(&params, "fluff")?;

			repost(context_id, tx_id, fluff)?;

			json!({})
		}
		"cancel" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_id: String = get_param(&params, "tx_id")?;
			let tx_id = Uuid::from_str(tx_id.as_str())
				.map_err(|e| format!("tx_id has invalid UUID format, {}", e))?;

			let wallet = get_wallet_instance(context_id)?;
			wallet_lock!(wallet.clone(), w);
			tx::cancel_tx(&mut **w, None, None, None, Some(tx_id))
				.map_err(|e| format!("Unable to cancel transaction {}, {}", tx_id, e))?;
			json!({})
		}
		// Get proof as Json. This Json can be written in the file for export
		"get_proof" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let tx_id: String = get_param(&params, "tx_id")?;
			let tx_id = Uuid::from_str(tx_id.as_str())
				.map_err(|e| format!("tx_id has invalid UUID format, {}", e))?;

			let wallet = get_wallet_instance(context_id)?;
			let proof = owner::get_stored_tx_proof(wallet, None, Some(tx_id))
				.map_err(|e| format!("Unable to retrieve the proof for {}, {}", tx_id, e))?;

			serde_json::to_value(proof)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"verify_proof" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let proof: String = get_param(&params, "proof")?;

			let tx_pf: TxProof = serde_json::from_str(&proof)
				.map_err(|e| format!("Unable to deserialize proof data, {}", e))?;

			let secp = {
				let secp_inst = static_secp_instance();
				let secp = secp_inst.lock().expect("Mutex failure").clone();
				secp
			};

			let proof_result = mwc_wallet_libwallet::proof::tx_proof::verify_tx_proof_wrapper(
				context_id, &tx_pf, &secp,
			)
			.map_err(|e| format!("Proof not valid: {}", e))?;

			serde_json::to_value(proof_result)
				.map_err(|e| format!("Unable convert result into json, {}", e))?
		}
		"mqs_address" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;

			let mqs_pub_key = owner::get_mqs_address(wallet.clone(), None)
				.map_err(|e| format!("Unable to retrieve MQS address, {}", e))?;
			let mqs_addr = ProvableAddress::from_pub_key(context_id, &mqs_pub_key);

			json!({
				"mqs_addr": mqs_addr.to_string(),
			})
		}
		"tor_address" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet = get_wallet_instance(context_id)?;

			let tor_pub_key = owner::get_wallet_public_address(wallet, None)
				.map_err(|e| format!("Unable to retrieve Slatepack address, {}", e))?;
			let tor_addr = ProvableAddress::from_tor_pub_key(&tor_pub_key);
			json!({
				"tor_addr": tor_addr.to_string(),
			})
		}
		"scan" => {
			let context_id = get_param(&params, "context_id")?;
			let delete_unconfirmed: bool = get_param(&params, "delete_unconfirmed")?;
			let response_callback: String = get_param(&params, "response_callback")?;
			let response_id: String = get_param(&params, "response_id")?;

			let height = scan(
				context_id,
				delete_unconfirmed,
				response_callback,
				response_id,
			)?;
			json!({
				"height": height
			})
		}
		// Resync wallet to the current height
		"update_wallet_state" => {
			let context_id = get_param(&params, "context_id")?;
			let response_callback: String = get_param(&params, "response_callback")?;
			let response_id: String = get_param(&params, "response_id")?;

			let (validated, height) =
				update_wallet_state(context_id, response_callback, response_id)?;
			json!({
				"validated" : validated,
				"height": height,
			})
		}
		// Wallet Address for http based transaction
		"request_receiver_proof_address" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let wallet_url: String = get_param(&params, "url")?;
			let apisecret: Option<String> = get_option_param(&params, "apisecret")?;

			let http_sender =
				HttpDataSender::plain_http(context_id, &wallet_url, apisecret.clone())
					.map_err(|e| format!("Unable to build http client, {}", e))?;
			let proof_address = http_sender
				.check_receiver_proof_address(None)
				.map_err(|e| format!("Reciever address check is failed, {}", e))?;

			json!({
				"proof_address" : proof_address,
			})
		}
		// Utility method to zip the file
		"zip_file" => {
			let src_file: String = get_param(&params, "src_file")?;
			let dst_file: String = get_param(&params, "dst_file")?;
			let dst_file_name: String = get_param(&params, "dst_file_name")?;

			zip_file(&src_file, &dst_file, &dst_file_name)?;

			json!({})
		}
		"check_wallet_busy" => {
			let context_id: u32 = get_param(&params, "context_id")?;

			let wallet = get_wallet_instance(context_id)?;
			let accessible = wallet.try_lock().is_ok();
			json!({
				"busy" : !accessible,
			})
		}
		"faucet_request" => {
			let context_id: u32 = get_param(&params, "context_id")?;
			let amount: u64 = get_param(&params, "amount")?;

			let wallet = get_wallet_instance(context_id)?;
			let mut owner =
				Owner::new(context_id, wallet, None, Some(TorConfig::arti_tor_config()));

			command::fauset_request(&mut owner, None, amount, None)
				.map_err(|e| format!("Unable to request funds from faucet, {}", e))?;

			json!({})
		}
		_ => return Err(format!("Unknown method: {}", method)),
	};

	Ok(response)
}

fn get_param<T: DeserializeOwned>(params: &serde_json::Value, key: &str) -> Result<T, String> {
	let value = params
		.get(key)
		.cloned()
		.ok_or_else(|| format!("Not found expected parameter {}", key))?;

	serde_json::from_value::<T>(value)
		.map_err(|e| format!("Unable to parse expected parameter {}, {}", key, e))
}

fn get_option_param<T: DeserializeOwned>(
	params: &serde_json::Value,
	key: &str,
) -> Result<Option<T>, String> {
	match params.get(key) {
		Some(value) => {
			let res = serde_json::from_value::<T>(value.clone())
				.map_err(|e| format!("Unable to parse parameter {}, {}", key, e))?;
			Ok(Some(res))
		}
		None => Ok(None),
	}
}

pub(crate) fn call_mwc_wallet_request(input: String) -> String {
	let json_res = match process_request(input) {
		Ok(res) => {
			json!({
				"success": true,
				"result": res,
			})
		}
		Err(err) => {
			json!({
				"success": false,
				"error": err,
			})
		}
	};

	serde_json::to_string(&json_res).expect("Json internal failure")
}
