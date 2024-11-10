// Copyright 2020 The MWC Develope;
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

//! Generic implementation of owner API atomic swap functions

use crate::mwc_util::Mutex;
use crate::{mwc_util::secp::key::SecretKey, swap::ethereum::EthereumWallet};

use crate::internal::selection;
use crate::mwc_core::core::Committed;
use crate::mwc_core::{core, global};
use crate::mwc_keychain::ExtKeychainPath;
use crate::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::mwc_util::to_hex;
use crate::swap::error::Error;
use crate::swap::fsm::state::{Input, StateEtaInfo, StateId, StateProcessRespond};
use crate::swap::message::{Message, SecondaryUpdate, Update};
use crate::swap::swap::{Swap, SwapJournalRecord};
use crate::swap::types::{Action, Currency, Network, Role, SwapTransactionsConfirmations};
use crate::swap::{trades, BuyApi, Context, SwapApi};
use crate::types::NodeClient;
use crate::{get_receive_account, owner_eth};
use crate::{
	wallet_lock, OutputData, OutputStatus, Slate, SwapStartArgs, TxLogEntry, TxLogEntryType,
	WalletBackend, WalletInst, WalletLCProvider,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::sync::RwLock;
use uuid::Uuid;

lazy_static! {
	/// Offers that are online now. It is needed to answer correctly about offers status
	/// Key: offer Id,  Value: message uuid
	static ref ONLINE_OFFERS:   RwLock<HashMap<String,Uuid>>  = RwLock::new(HashMap::new());
}

/// Register marketplace offer that is publishing now. SO now income requests are expected.
pub fn add_published_offer(offer_id: String, message_uuid: Uuid) {
	ONLINE_OFFERS
		.write()
		.unwrap()
		.insert(offer_id, message_uuid);
}

/// Unregister marketplace offer. Any incoming requests about it are not expected.
pub fn remove_published_offer(message_uuid: &Uuid) {
	ONLINE_OFFERS
		.write()
		.unwrap()
		.retain(|_k, v| v != message_uuid);
}

fn get_swap_storage_key<K: Keychain>(keychain: &K) -> Result<SecretKey, Error> {
	Ok(keychain.derive_key(
		0,
		&ExtKeychainPath::new(3, 3, 2, 1, 0).to_identifier(),
		SwitchCommitmentType::None,
	)?)
}

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
pub fn swap_start<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	params: &SwapStartArgs,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Starting a swap trade.
	// This method only initialize and store the swap process. Nothing is done

	// First we need to define outputs that we can use.
	// Reading all output.
	let (_, outputs) = super::owner::retrieve_outputs(
		wallet_inst.clone(),
		keychain_mask,
		&None,
		false,
		false,
		None,
	)?;
	// Reading all swaps. We need to exclude

	let mut outs: HashMap<String, u64> = outputs
		.iter()
		.filter(|o| o.output.commit.is_some())
		.map(|o| (o.output.commit.clone().unwrap(), o.output.value))
		.collect();

	wallet_lock!(wallet_inst.clone(), w);
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let (height, _, _) = node_client.get_chain_tip()?;

	if height == 0 {
		return Err(Error::Generic(
			"MWC node is syncing and not ready yet".to_string(),
		));
	}

	let mut swap_reserved_amount = 0;
	let mut swap_reserved_gas_amount = 0.0;

	if params.outputs.is_some() {
		let outputs_to_use: HashSet<String> =
			params.outputs.clone().unwrap().iter().cloned().collect();
		outs.retain(|k, _| outputs_to_use.contains(k));
	} else {
		// Searching to swaps that are started, but not locked
		let swap_id = trades::list_swap_trades()?;
		for sw_id in &swap_id {
			let swap_lock = trades::get_swap_lock(sw_id);
			let _l = swap_lock.lock();
			let (_, swap) = trades::get_swap_trade(sw_id.as_str(), &skey, &*swap_lock)?;

			if swap.is_seller() && !swap.state.is_final_state() {
				// Check if funds are not locked yet
				if swap.posted_lock.is_none() {
					// So funds are not posted, transaction doesn't exist and outpuyts are not locked.
					// We have to exclude those outputs
					for inp in swap.lock_slate.tx_or_err()?.inputs_committed() {
						let in_commit = to_hex(&inp.0);
						if let Some(amount) = outs.remove(&in_commit) {
							swap_reserved_amount += amount;
						}
					}
				}

				//check if eth/erc-20 swap, for unconfirmed eth/erc-20 swap, we need to keep ether as gas to redeem funds.
				if !swap.secondary_currency.is_btc_family() {
					swap_reserved_gas_amount += swap
						.secondary_currency
						.get_default_fee(&Network::from_chain_type(global::get_chain_type())?);
				}
			}
		}
	}

	if swap_reserved_amount > 0 {
		let swap_reserved_amount_str =
			crate::mwc_core::core::amount_to_hr_string(swap_reserved_amount, true);
		info!("Running swaps reserved {} coins", swap_reserved_amount);
		println!("WARNING. This swap will need to reserve {} MWC. If you don't have enough funds, please cancel it.", swap_reserved_amount_str);
	}

	let outputs: Vec<String> = outs.keys().map(|k| k.clone()).collect();
	let secondary_currency = Currency::try_from(params.secondary_currency.as_str())?;
	let secondary_amount = secondary_currency.amount_from_hr_string(&params.secondary_amount)?;

	let mut swap_api = match secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				&secondary_currency,
				&params.electrum_node_uri1,
				&params.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(&secondary_currency, node_client, uri1, uri2)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&secondary_currency,
				&params.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&secondary_currency,
				&params.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&secondary_currency,
				&params.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				&secondary_currency,
				node_client,
				ethereum_wallet.clone(),
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	// Checking ElectrumX/Infura nodes...
	swap_api.test_client_connections()?;

	let parent_key_id = w.parent_key_id(); // account is current one
	let (outputs, total, amount, fee) = if !(params.dry_run && params.mwc_amount == 0) {
		crate::internal::selection::select_coins_and_fee(
			&mut **w,
			params.mwc_amount,
			false,
			&None,
			height,
			params.minimum_confirmations.unwrap_or(10),
			500,
			1,
			false,
			&parent_key_id,
			&Some(outputs), // outputs to include into the transaction
			1,              // Number of resulting outputs. Normally it is 1
			false,
			0,
		)?
	} else {
		// dry run with no amount. It is possible for Buy offer validation
		(vec![], 0, 0, 0)
	};

	let context = create_context(
		&mut **w,
		Some(&ethereum_wallet),
		keychain_mask,
		&mut swap_api,
		&keychain,
		secondary_currency,
		true,
		Some(
			outputs
				.iter()
				.map(|out| (out.key_id.clone(), out.mmr_index.clone(), out.value))
				.collect(),
		),
		total - amount - fee,
	)?;

	let mut swap = (*swap_api).create_swap_offer(
		&keychain,
		&context,
		params.mwc_amount, // mwc amount to sell
		secondary_amount,  // btc amount to buy
		secondary_currency,
		params.secondary_redeem_address.clone(),
		params.seller_lock_first,
		params.mwc_confirmations,
		params.secondary_confirmations,
		params.message_exchange_time_sec,
		params.redeem_time_sec,
		params.buyer_communication_method.clone(),
		params.buyer_communication_address.clone(),
		params.electrum_node_uri1.clone(),
		params.electrum_node_uri2.clone(),
		params.eth_swap_contract_address.clone(),
		params.erc20_swap_contract_address.clone(),
		params.eth_infura_project_id.clone(),
		params.eth_redirect_to_private_wallet.clone(),
		params.dry_run,
		params.tag.clone(),
	)?;

	// Store swap result into the file.
	let swap_id = swap.id.to_string();
	let secondary_fee = match params.secondary_fee {
		Some(fee) => fee,
		_ => {
			secondary_currency.get_default_fee(&Network::from_chain_type(global::get_chain_type())?)
		}
	};

	swap.secondary_fee = secondary_fee;
	if secondary_fee <= 0.0 {
		return Err(Error::Generic(
			"Invalid secondary transaction fee".to_string(),
		));
	}

	if !secondary_currency.is_btc_family() && !params.dry_run {
		swap_reserved_gas_amount += secondary_fee;
		let balance_gwei = owner_eth::get_eth_balance(ethereum_wallet.clone())?;

		if swap_reserved_gas_amount > balance_gwei as f32 {
			println!(
				"WARNING. {} gases should be keeped. Now {} ethers in your ethereum wallet!",
				swap_reserved_gas_amount, balance_gwei
			);
			return Err(Error::Generic(
				"No enough ether as gas for swap".to_string(),
			));
		}
	}

	let swap_lock = trades::get_swap_lock(&swap_id);
	let _l = swap_lock.lock();
	if trades::get_swap_trade(swap_id.as_str(), &skey, &*swap_lock).is_ok() {
		// Should be impossible, uuid suppose to be unique. But we don't want to overwrite anything
		return Err(Error::TradeIoError(
			swap_id.clone(),
			"This trade record already exist".to_string(),
		));
	}

	if params.dry_run {
		// In case of dry run we don't want to store or start anything. Just validate is enough.
		// Still we can return a new swap ID that is temporary, but still might be used for something
		return Ok(swap_id);
	}

	trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;

	Ok(swap_id)
}

/// Respond from swap_list API. Respond is very specific, that is why it has special structure
pub struct SwapListInfo {
	/// Swap id
	pub swap_id: String,
	/// Marketplace Tag for the trade.
	pub tag: Option<String>,
	/// flag if trade is seller
	pub is_seller: bool,
	/// MWC amount that was traded
	pub mwc_amount: String,
	/// Secondary currency amount that was traded
	pub secondary_amount: String,
	/// Secondary currency.
	pub secondary_currency: String,
	/// current state
	pub state: StateId,
	/// current action
	pub action: Option<Action>,
	/// expiration time for action
	pub expiration: Option<i64>,
	/// when this trade was created
	pub trade_start_time: i64,
	/// Secondary address. Caller need to know if ti is set
	pub secondary_address: String,
	/// Last error message if process was failed. Note, error will be very generic
	pub last_error: Option<String>,
}

/// List Swap trades. Returns SwapId + Status
/// Return: (<trades list>, <marketplace cancelled swaps>)
pub fn swap_list<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	do_check: bool,
) -> Result<(Vec<SwapListInfo>, Vec<Swap>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Need to lock first to check if the wallet is open
	wallet_lock!(wallet_inst, w);

	let swap_id = trades::list_swap_trades()?;
	let mut result: Vec<SwapListInfo> = Vec::new();

	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;

	let mut do_check = do_check;

	let mut cancelled_swaps: Vec<Swap> = vec![];

	for sw_id in &swap_id {
		let swap_lock = trades::get_swap_lock(sw_id);
		let _l = swap_lock.lock();
		let (context, mut swap) = trades::get_swap_trade(sw_id.as_str(), &skey, &*swap_lock)?;
		let trade_start_time = swap.started.timestamp();
		swap.wait_for_backup1 = true; // always waiting because moving forward it is not a swap list task

		if do_check && !swap.state.is_final_state() {
			let (state, action, expiration) = match update_swap_status_action_impl(
				&mut swap,
				&context,
				node_client.clone(),
				&keychain,
				ethereum_wallet.clone(),
			) {
				Ok((state, action, expiration, _state_eta, other_was_locked)) => {
					swap.last_check_error = None;
					trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
					if other_was_locked {
						let mut cncl_sw = cancel_trades_by_tag(&keychain, &swap)?;
						cancelled_swaps.append(&mut cncl_sw);
					}
					(state, action, expiration)
				}
				Err(e) => {
					do_check = false;
					swap.last_check_error = Some(format!("{}", e));
					swap.add_journal_message(format!("Processing error: {}", e));
					(swap.state.clone(), Action::None, None)
				}
			};

			result.push(SwapListInfo {
				swap_id: sw_id.clone(),
				tag: swap.tag.clone(),
				is_seller: swap.is_seller(),
				mwc_amount: core::amount_to_hr_string(swap.primary_amount, true),
				secondary_amount: swap
					.secondary_currency
					.amount_to_hr_string(swap.secondary_amount, true),
				secondary_currency: swap.secondary_currency.to_string(),
				state,
				action: Some(action),
				expiration,
				trade_start_time,
				secondary_address: swap.get_secondary_address(),
				last_error: swap.get_last_error(),
			});
		} else {
			result.push(SwapListInfo {
				swap_id: sw_id.clone(),
				tag: swap.tag.clone(),
				is_seller: swap.is_seller(),
				mwc_amount: core::amount_to_hr_string(swap.primary_amount, true),
				secondary_amount: swap
					.secondary_currency
					.amount_to_hr_string(swap.secondary_amount, true),
				secondary_currency: swap.secondary_currency.to_string(),
				state: swap.state.clone(),
				action: None,
				expiration: None,
				trade_start_time,
				secondary_address: swap.get_secondary_address(),
				last_error: swap.get_last_error(),
			});
		}
		trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
	}

	Ok((result, cancelled_swaps))
}

/// Delete Swap trade.
pub fn swap_delete<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;

	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();
	trades::delete_swap_trade(swap_id, &skey, &*swap_lock)?;
	Ok(())
}

/// Get a Swap kernel object.
pub fn swap_get<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<Swap, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();
	let (_, swap) = trades::get_swap_trade(swap_id, &skey, &*swap_lock)?;
	Ok(swap)
}

/// Update the state of Swap trade. Returns the new state
/// method & destination required for adjust_cmd='destination'
pub fn swap_adjust<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	adjust_cmd: &str,
	method: Option<String>,
	destination: Option<String>,
	secondary_address: Option<String>, // secondary address to adjust
	secondary_fee: Option<f32>,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_infura_project_id: Option<String>,
	tag: Option<String>,
) -> Result<(StateId, Action), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();

	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();
	let (context, mut swap) = trades::get_swap_trade(swap_id, &skey, &*swap_lock)?;

	match adjust_cmd {
		"electrumx_uri" => {
			match swap.secondary_currency.is_btc_family() {
				true => {
					// Let's test electrumX instances first.
					let mut electrum1 = electrum_node_uri1.clone();
					let mut electrum2 = electrum_node_uri2.clone();

					if electrum1.is_some() || electrum2.is_some() {
						if electrum1.is_none() {
							electrum1 = electrum2.clone();
						}
						if electrum2.is_none() {
							electrum2 = electrum1.clone();
						}

						let swap_api: Box<dyn SwapApi<K>> = crate::swap::api::create_btc_instance(
							&swap.secondary_currency,
							node_client.clone(),
							electrum1.unwrap(),
							electrum2.unwrap(),
						)?;
						swap_api.test_client_connections()?;
					}

					swap.electrum_node_uri1 = electrum_node_uri1;
					swap.electrum_node_uri2 = electrum_node_uri2;
					trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
					return Ok((swap.state.clone(), Action::None));
				}
				_ => {
					return Err(Error::Generic("Non BTC family coins".to_string()));
				}
			}
		}
		"eth_infura_project_id" => match swap.secondary_currency.is_btc_family() {
			true => {
				return Err(Error::Generic("Not Ethereum family coins".to_string()));
			}
			_ => {
				let eth_swap_contract_address = trades::get_eth_swap_contract_address(
					&swap.secondary_currency,
					&swap.eth_swap_contract_address,
				)?;

				let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
					&swap.secondary_currency,
					&swap.erc20_swap_contract_address,
				)?;

				if eth_infura_project_id.is_some() {
					let swap_api: Box<dyn SwapApi<K>> = crate::swap::api::create_eth_instance(
						&swap.secondary_currency,
						node_client.clone(),
						ethereum_wallet,
						eth_swap_contract_address,
						erc20_swap_contract_address,
						eth_infura_project_id.clone().unwrap(),
					)?;
					swap_api.test_client_connections()?;
				}

				swap.eth_infura_project_id = eth_infura_project_id;
				trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
				return Ok((swap.state.clone(), Action::None));
			}
		},
		"destination" => {
			if method.is_none() || destination.is_none() {
				return Err(Error::Generic(
					"Please define both '--method' and '--dest' values".to_string(),
				));
			}
			let method = method.unwrap();

			swap.communication_method = method;
			swap.communication_address = destination.unwrap();
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"secondary_address" => {
			if secondary_address.is_none() {
				return Err(Error::Generic(
					"Please define '--buyer_refund_address' or '--secondary_address' values"
						.to_string(),
				));
			}

			let secondary_address = secondary_address.unwrap();
			swap.secondary_currency
				.validate_address(&secondary_address)?;

			match &mut swap.role {
				Role::Buyer(address) => {
					address.replace(secondary_address);
				}
				Role::Seller(address, _) => {
					*address = secondary_address;
				}
			}

			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"secondary_fee" => {
			if secondary_fee.is_none() {
				return Err(Error::Generic(
					"Please define '--secondary_fee' values".to_string(),
				));
			}

			let secondary_fee = secondary_fee.unwrap();
			if secondary_fee <= 0.0 {
				return Err(Error::Generic(
					"Please define positive '--secondary_fee' value".to_string(),
				));
			}

			if !swap.secondary_currency.is_btc_family() {
				let balance_gwei = owner_eth::get_eth_balance(ethereum_wallet.clone())?;
				println!(
					"owner_swap.rs::swap_adjust ----- secondary_fee: {}, balance_gwei: {}",
					secondary_fee, balance_gwei
				);
				if secondary_fee > balance_gwei as f32 {
					return Err(Error::Generic(
						"No enough ether as gas for swap".to_string(),
					));
				}
			}

			swap.secondary_fee = secondary_fee;
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"tag" => {
			if tag.is_none() {
				return Err(Error::Generic("Please define '--tag' values".to_string()));
			}

			swap.tag = tag;
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		_ => (), // Nothing to do. Will continue with api construction
	}

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;

			crate::swap::api::create_btc_instance(
				&swap.secondary_currency,
				node_client.clone(),
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				&swap.secondary_currency,
				node_client.clone(),
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let mut fsm = swap_api.get_fsm(&keychain, &swap);

	let (height, _, _) = node_client.get_chain_tip()?;

	match adjust_cmd {
		"cancel" => {
			if !fsm.is_cancellable(&swap)? {
				return Err(Error::Generic(
					"Swap Trade is not cancellable at current stage".to_string(),
				));
			}

			// Cancelling the trade
			let tx_conf = swap_api.request_tx_confirmations(&keychain, &swap)?;
			let resp = fsm.process(
				Input::Cancel,
				&mut swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;

			return Ok((swap.state.clone(), resp.action.unwrap_or(Action::None)));
		}
		adjusted_state => {
			let state = StateId::from_cmd_str(adjusted_state)?;
			if !fsm.has_state(&state) {
				return Err(Error::Generic(format!(
					"State {} is invalid for this trade",
					adjusted_state
				)));
			}
			swap.add_journal_message(format!("State is manually adjusted to {}", adjusted_state));
			swap.state = state;

			swap.wait_for_backup1 = true; // Don't want to go forward

			let tx_conf = swap_api.request_tx_confirmations(&keychain, &swap)?;
			let resp = fsm.process(
				Input::Check,
				&mut swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;

			return Ok((swap.state.clone(), resp.action.unwrap_or(Action::None)));
		}
	}
}

/// Dump the swap file content
pub fn swap_dump<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();
	let dump_res = trades::dump_swap_trade(swap_id, &skey, &*swap_lock)?;
	Ok(dump_res)
}

/// Import swap trade from the file
/// Return: trade SwapId
pub fn swap_import_trade<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	trade_file_name: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&"export".to_string());
	let _l = swap_lock.lock();
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();

	// Checking if MWC node is available
	let mwc_tip = node_client.get_chain_tip()?.0;
	if mwc_tip == 0 {
		return Err(Error::Generic(
			"Unable contact healthy MWC node. The node probably in sync process".to_string(),
		));
	}

	let swap_id = trades::import_trade(trade_file_name, &skey, &*swap_lock)?;

	// It is not enough to restore the data. Now we need to update the state. Backup likely from the past, so something can happen.
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();
	let (context, mut swap) = trades::get_swap_trade(&swap_id, &skey, &*swap_lock)?;

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				&swap.secondary_currency,
				node_client.clone(),
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				&swap.secondary_currency,
				node_client.clone(),
				ethereum_wallet.clone(),
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	match swap.secondary_currency.is_btc_family() {
		true => {
			// let's calcutate the scrip hashes if needed and can
			if swap.is_seller() && swap.secondary_data.unwrap_btc()?.redeem_tx.is_none() {
				// try to calculate the hash if possible
				let _ =
					swap_api.publish_secondary_transaction(&keychain, &mut swap, &context, false);
			}
			if !swap.is_seller() && swap.secondary_data.unwrap_btc()?.refund_tx.is_none() {
				let refund_address = swap.unwrap_buyer()?;
				let _ = swap_api.post_secondary_refund_tx(
					&keychain,
					&context,
					&mut swap,
					refund_address,
					false,
				);
			}
		}
		_ => {
			// let's calcutate the scrip hashes if needed and can
			if swap.is_seller() && swap.secondary_data.unwrap_eth()?.redeem_tx.is_none() {
				// try to calculate the hash if possible
				let _ =
					swap_api.publish_secondary_transaction(&keychain, &mut swap, &context, false);
			}
			if !swap.is_seller() && swap.secondary_data.unwrap_eth()?.refund_tx.is_none() {
				let refund_address = swap.unwrap_buyer()?;
				let _ = swap_api.post_secondary_refund_tx(
					&keychain,
					&context,
					&mut swap,
					refund_address,
					false,
				);
			}
		}
	}

	let tx_conf = swap_api.request_tx_confirmations(&keychain, &swap)?;
	if tx_conf.mwc_tip == 0 {
		// here the swap trade is written, there is not much what we can do
		return Err(Error::Generic("Unable contact healthy MWC node. Please fix the problem and retry to restore this swap trade".to_string()));
	}
	if tx_conf.secondary_tip == 0 {
		// here the swap trade is written, there is not much what we can do
		return Err(Error::Generic(format!("Unable contact {} ElectrumX node. Please fix the problem and retry to restore this swap trade", swap.secondary_currency)));
	}

	if swap.is_seller() {
		if tx_conf.secondary_redeem_conf.is_some() {
			swap.state = StateId::SellerWaitingForRedeemConfirmations;
		} else if tx_conf.mwc_refund_conf.is_some() {
			swap.state = StateId::SellerWaitingForRefundConfirmations;
		} else if tx_conf.mwc_lock_conf.is_some() {
			swap.state = StateId::SellerWaitingForLockConfirmations;
		} else {
			swap.state = StateId::SellerCancelled;
		}
	} else {
		// Buyer case
		if tx_conf.mwc_redeem_conf.is_some() {
			swap.state = StateId::BuyerWaitForRedeemMwcConfirmations;
		} else if tx_conf.secondary_refund_conf.is_some() {
			swap.state = StateId::BuyerWaitingForRefundConfirmations;
		} else if tx_conf.secondary_lock_conf.is_some() {
			swap.state = StateId::BuyerWaitingForLockConfirmations;
		} else {
			swap.state = StateId::BuyerCancelled;
		}
	}

	swap.last_check_error = None;
	swap.last_process_error = None;

	trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;

	Ok(swap_id)
}

fn update_swap_status_action_impl<'a, C, K>(
	swap: &mut Swap,
	context: &Context,
	node_client: C,
	keychain: &K,
	ethereum_wallet: EthereumWallet,
) -> Result<(StateId, Action, Option<i64>, Vec<StateEtaInfo>, bool), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (height, _, _) = node_client.get_chain_tip()?;
	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let mut fsm = swap_api.get_fsm(keychain, swap);
	let tx_conf = swap_api.request_tx_confirmations(keychain, swap)?;
	let start_locked = swap.other_lock_first_done;
	let resp = fsm.process(
		Input::Check,
		swap,
		&context,
		height,
		&tx_conf,
		keychain.secp(),
	)?;

	let eta = fsm.get_swap_roadmap(swap, keychain.secp())?;

	Ok((
		resp.next_state_id,
		resp.action.unwrap_or(Action::None),
		resp.time_limit,
		eta,
		swap.tag.is_some() && start_locked != swap.other_lock_first_done,
	))
}

/// Refresh and get a status and current expected action for the swap.
/// return: <state>, <Action>, <time limit>
/// time limit shows when this action will be expired
pub fn cancel_trades_by_tag<'a, K>(keychain: &K, win_swap: &Swap) -> Result<Vec<Swap>, Error>
where
	K: Keychain + 'a,
{
	if win_swap.tag.is_none() {
		return Ok(vec![]);
	}

	println!(
		"Winning Trade with SwapId {} and tag {}",
		win_swap.id,
		win_swap.tag.clone().unwrap()
	);

	let swap_id = trades::list_swap_trades()?;
	let skey = get_swap_storage_key(keychain)?;

	// Note, it is not locked copies, we can't use much data from them
	let mut swaps_to_cancel: Vec<Swap> = vec![];

	{
		let exclude_swap_id = win_swap.id.to_string();
		for sw_id in &swap_id {
			if *sw_id == exclude_swap_id {
				continue;
			}

			let swap_lock = trades::get_swap_lock(sw_id);
			let _l = swap_lock.lock();

			let (context, mut swap) = trades::get_swap_trade(sw_id.as_str(), &skey, &*swap_lock)?;

			if swap.tag == win_swap.tag && swap.state.is_initial_state() {
				swaps_to_cancel.push(swap.clone());

				// Cancelling by changing the state. For initial it is safe.
				swap.add_journal_message("Cancelling, another marketplace trade win".to_string());
				swap.state = if swap.is_seller() {
					StateId::SellerCancelled
				} else {
					StateId::BuyerCancelled
				};
				trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
				trades::delete_swap_trade(&sw_id, &skey, &*swap_lock)?;
			}
		}
	}

	Ok(swaps_to_cancel)
}

/// Refresh and get a status and current expected action for the swap.
/// return: <state>, <Action>, <time limit>, ...., <marketplace cancelled swaps>
/// time limit shows when this action will be expired
pub fn update_swap_status_action<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_swap_contract_address: Option<String>,
	erc20_swap_contract_address: Option<String>,
	eth_infura_project_id: Option<String>,
	wait_for_backup1: bool,
) -> Result<
	(
		StateId,
		Action,
		Option<i64>,
		Vec<StateEtaInfo>,
		Vec<SwapJournalRecord>,
		Option<String>,
		Vec<Swap>,
	),
	Error,
>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();

	let (context, mut swap) = trades::get_swap_trade(swap_id, &skey, &*swap_lock)?;

	// Updating electrumX URI if they are defined. We can't reset them. For reset use Adjust
	if electrum_node_uri1.is_some() {
		swap.electrum_node_uri1 = electrum_node_uri1;
	}
	if electrum_node_uri2.is_some() {
		swap.electrum_node_uri2 = electrum_node_uri2;
	}

	// Updating ethereum contract address and project id if they are defined. We can't reset them. For reset use Adjust
	if eth_swap_contract_address.is_some() {
		swap.eth_swap_contract_address = eth_swap_contract_address;
	}
	if erc20_swap_contract_address.is_some() {
		swap.erc20_swap_contract_address = erc20_swap_contract_address;
	}
	if eth_infura_project_id.is_some() {
		swap.eth_infura_project_id = eth_infura_project_id;
	}

	swap.wait_for_backup1 = wait_for_backup1;

	match update_swap_status_action_impl(
		&mut swap,
		&context,
		node_client,
		&keychain,
		ethereum_wallet,
	) {
		Ok((next_state_id, action, time_limit, eta, cancel_mkt_place_trades)) => {
			swap.last_check_error = None;
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			let last_error = swap.get_last_error();

			let mut cancelled_swaps: Vec<Swap> = vec![];
			if cancel_mkt_place_trades {
				cancelled_swaps = cancel_trades_by_tag(&keychain, &swap)?;
			}

			Ok((
				next_state_id,
				action,
				time_limit,
				eta,
				swap.journal,
				last_error,
				cancelled_swaps,
			))
		}
		Err(e) => {
			swap.last_check_error = Some(format!("{}", e));
			swap.add_journal_message(format!("Processing error: {}", e));
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			Err(e)
		}
	}
}

/// Get a status of the transactions that involved into the swap.
pub fn get_swap_tx_tstatus<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_swap_contract_address: Option<String>,
	erc20_swap_contract_address: Option<String>,
	eth_infura_project_id: Option<String>,
) -> Result<SwapTransactionsConfirmations, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();

	let (_context, mut swap) = trades::get_swap_trade(swap_id, &skey, &*swap_lock)?;

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			// Note, electrum_node_uri updates will not be saved. Needed for the check with failed ElectrumX node
			if electrum_node_uri1.is_some() {
				swap.electrum_node_uri1 = electrum_node_uri1;
			}
			if electrum_node_uri2.is_some() {
				swap.electrum_node_uri2 = electrum_node_uri2;
			}
			let (uri1, uri2) = trades::get_electrumx_uri(
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		}
		_ => {
			// eth_infura_project_id is not saved in trade
			if eth_swap_contract_address.is_some() {
				swap.eth_swap_contract_address = eth_swap_contract_address;
			}
			if erc20_swap_contract_address.is_some() {
				swap.erc20_swap_contract_address = erc20_swap_contract_address;
			}
			if eth_infura_project_id.is_some() {
				swap.eth_infura_project_id = eth_infura_project_id;
			}

			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let res = swap_api.request_tx_confirmations(&keychain, &mut swap)?;

	Ok(res)
}

// return: <response, cancelled trades>
fn swap_process_impl<'a, L, C, K, F>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_lock: Arc<Mutex<()>>,
	swap: &mut Swap,
	context: &Context,
	node_client: C,
	keychain: K,
	message_sender: F,
	message_file_name: Option<String>,
	buyer_refund_address: Option<String>,
	secondary_fee: Option<f32>,
	secondary_address: Option<String>,
) -> Result<(StateProcessRespond, Vec<Swap>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	F: FnOnce(Message, String, String) -> Result<(bool, String), Error> + 'a,
{
	if let Some(secondary_fee) = secondary_fee {
		swap.secondary_fee = secondary_fee;
	}

	if swap.is_seller() {
		if let Some(secondary_address) = secondary_address {
			swap.secondary_currency
				.validate_address(&secondary_address)?;
			swap.update_secondary_address(secondary_address);
		}
	} else {
		if let Some(secondary_address) = buyer_refund_address {
			swap.secondary_currency
				.validate_address(&secondary_address)?;
			swap.update_secondary_address(secondary_address);
		}
	}

	let (height, _, _) = node_client.get_chain_tip()?;

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			wallet_lock!(wallet_inst.clone(), w);
			let ethereum_wallet = w.get_ethereum_wallet()?.clone();
			crate::swap::api::create_eth_instance(
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let tx_conf = swap_api.request_tx_confirmations(&keychain, swap)?;
	let mut fsm = swap_api.get_fsm(&keychain, swap);
	let other_lock_first_changed = swap.other_lock_first_done;
	let mut process_respond = fsm.process(
		Input::Check,
		swap,
		&context,
		height,
		&tx_conf,
		keychain.secp(),
	)?;

	let cancelled_swaps = if other_lock_first_changed != swap.other_lock_first_done {
		cancel_trades_by_tag(&keychain, &swap)?
	} else {
		vec![]
	};

	if process_respond.action.is_none() {
		return Ok((process_respond, cancelled_swaps));
	}

	match process_respond.action.clone().unwrap() {
		Action::SellerSendOfferMessage(message)
		| Action::BuyerSendAcceptOfferMessage(message)
		| Action::BuyerSendInitRedeemMessage(message)
		| Action::SellerSendRedeemMessage(message) => {
			let (has_ack, dest_str) = message_sender(
				message,
				swap.communication_method.clone(),
				swap.communication_address.clone(),
			)?;
			let process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
			swap.append_to_last_message(&format!(", {}", dest_str));
			if has_ack {
				match process_respond.action.clone().unwrap() {
					Action::SellerSendOfferMessage(_) | Action::BuyerSendAcceptOfferMessage(_) => {
						swap.ack_msg1()
					}
					_ => swap.ack_msg2(),
				}
			}
		}
		Action::SellerWaitingForOfferMessage
		| Action::SellerWaitingForInitRedeemMessage
		| Action::BuyerWaitingForRedeemMessage => {
			let message_fn = message_file_name.ok_or(Error::Generic("Wallet is waiting for the response from the Buyer. Make sure that your wallet is online and able to receive the messages. If you are using files for messages exchange, please specify income message file name with '--message_file_name' value".to_string()))?;

			let mut file = File::open(message_fn.clone()).map_err(|e| {
				Error::Generic(format!("Unable to open file {}, {}", message_fn, e))
			})?;
			let mut contents = String::new();
			file.read_to_string(&mut contents).map_err(|e| {
				Error::Generic(format!(
					"Unable to read a message from the file {}, {}",
					message_fn, e
				))
			})?;
			// processing the message with a regular API.

			let message = Message::from_json(&contents)?;
			if message.id != swap.id {
				return Err(Error::Generic(format!(
					"Message id {} doesn't match selected trade id",
					message.id
				)));
			}

			swap_income_message(
				wallet_inst.clone(),
				keychain_mask,
				&contents,
				Some(swap_lock.clone()),
			)?;
		}
		Action::BuyerDepositToContractAccount => {
			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
		}
		Action::SellerPublishMwcLockTx => {
			wallet_lock!(wallet_inst, w);
			// Checking if transaction is already created.
			let kernel = &swap.lock_slate.tx_or_err()?.body.kernels[0].excess;
			if w.tx_log_iter()
				.filter(|tx| tx.kernel_excess.filter(|c| c == kernel).is_some())
				.count() == 0
			{
				// Transaction doesn't exist, let's create it and lock the outputs.
				let seller_context = context.unwrap_seller()?;
				let slate_context = crate::types::Context::from_send_slate(
					&swap.lock_slate,
					context.lock_nonce.clone(),
					seller_context.inputs.clone(),
					vec![(
						seller_context.change_output.clone(),
						None,
						seller_context.change_amount,
					)],
					seller_context.parent_key_id.clone(),
					0,
				)?;
				selection::lock_tx_context(
					&mut **w,
					keychain_mask,
					&swap.lock_slate,
					tx_conf.mwc_tip,
					&slate_context,
					Some(format!("Swap {} Lock", swap.id)),
					None,
				)?;
			}

			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
		}
		Action::SellerPublishTxSecondaryRedeem {
			currency: _,
			address: _,
		} => {
			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
		}
		Action::BuyerPublishMwcRedeemTx => {
			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;

			wallet_lock!(wallet_inst, w);

			// Checking if this transaction already exist
			let kernel = &swap.redeem_slate.tx_or_err()?.body.kernels[0].excess;
			if w.tx_log_iter()
				.filter(|tx| tx.kernel_excess.filter(|c| c == kernel).is_some())
				.count() == 0
			{
				// Creating receive transaction from the slate
				let buyer_context = context.unwrap_buyer()?;
				create_receive_tx_record(
					&mut **w,
					keychain_mask,
					&swap.redeem_slate,
					format!("Swap {}", swap.id),
					&buyer_context.parent_key_id,
					&buyer_context.redeem,
				)?;
			}
		}
		Action::SellerPublishMwcRefundTx => {
			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;

			wallet_lock!(wallet_inst, w);

			let kernel = &swap.refund_slate.tx_or_err()?.body.kernels[0].excess;
			if w.tx_log_iter()
				.filter(|tx| tx.kernel_excess.filter(|c| c == kernel).is_some())
				.count() == 0
			{
				// For MWC transaction we can create a record in the wallet.
				let seller_context = context.unwrap_seller()?;
				create_receive_tx_record(
					&mut **w,
					keychain_mask,
					&swap.refund_slate,
					format!("Swap {} Refund", swap.id),
					&seller_context.parent_key_id,
					&seller_context.refund_output,
				)?;
			}
		}
		Action::BuyerPublishSecondaryRefundTx {
			currency: _,
			address: _,
		} => {
			//only btc family need to check refund address.
			if swap.secondary_currency.is_btc_family() && swap.unwrap_buyer()?.is_none() {
				return Err(Error::Generic(format!(
					"Please specify '--buyer_refund_address' {} address for your refund",
					swap.secondary_currency
				)));
			}

			process_respond = fsm.process(
				Input::Execute,
				swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
		}
		_ => (), // Nothing to do
	}

	Ok((process_respond, cancelled_swaps))
}

/// Process the action for the swap. Action has to match the expected one
/// message_sender - method that can send the message to another party. Caller defines how it can be done
/// Return: new State & Action
pub fn swap_process<'a, L, C, K, F>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	message_sender: F,
	message_file_name: Option<String>,
	buyer_refund_address: Option<String>,
	secondary_fee: Option<f32>,
	secondary_address: Option<String>,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_infura_project_id: Option<String>,
	wait_for_backup1: bool,
) -> Result<(StateProcessRespond, Vec<Swap>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	F: FnOnce(Message, String, String) -> Result<(bool, String), Error> + 'a,
{
	let (node_client, keychain) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let keychain = w.keychain(keychain_mask)?;
		(node_client, keychain)
	};

	let skey = get_swap_storage_key(&keychain)?;
	let swap_lock = trades::get_swap_lock(&swap_id.to_string());
	let _l = swap_lock.lock();

	let (context, mut swap) = trades::get_swap_trade(swap_id, &skey, &*swap_lock)?;

	// Updating electrumX URI if they are defined. We can't reset them. For reset use Adjust
	if electrum_node_uri1.is_some() {
		swap.electrum_node_uri1 = electrum_node_uri1;
	}
	if electrum_node_uri2.is_some() {
		swap.electrum_node_uri2 = electrum_node_uri2;
	}

	// upddate ethereum infura project id
	if eth_infura_project_id.is_some() {
		swap.eth_infura_project_id = eth_infura_project_id;
	}

	swap.wait_for_backup1 = wait_for_backup1;

	match swap_process_impl(
		wallet_inst,
		keychain_mask,
		swap_lock.clone(),
		&mut swap,
		&context,
		node_client,
		keychain,
		message_sender,
		message_file_name,
		buyer_refund_address,
		secondary_fee,
		secondary_address,
	) {
		Ok(mut respond) => {
			swap.last_process_error = None;
			respond.0.last_error = swap.get_last_error();
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			Ok(respond)
		}
		Err(e) => {
			swap.last_process_error = Some((swap.state.clone(), format!("{}", e)));
			swap.add_journal_message(format!("Processing error: {}", e));
			trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
			Err(e)
		}
	}
}

// Creating Transaction and output for expected recieve slate
fn create_receive_tx_record<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	tx_name: String,
	parent_key_id: &Identifier, // account id
	output_key_id: &Identifier, // output MUST match parent_key_id
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut batch = wallet.batch(keychain_mask)?;
	let log_id = batch.next_tx_log_id(parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);

	// Creating trnasaction
	t.tx_slate_id = Some(slate.id.clone());
	t.amount_credited = slate.amount;
	t.address = Some(tx_name);
	t.num_outputs = 1;
	t.output_commits = slate.tx_or_err()?.outputs_committed();
	t.messages = None;
	t.ttl_cutoff_height = None;
	// when invoicing, this will be invalid
	assert!(slate.tx_or_err()?.body.kernels.len() == 1);
	t.kernel_excess = Some(slate.tx_or_err()?.body.kernels[0].excess);
	t.kernel_lookup_min_height = Some(slate.height);
	batch.save_tx_log_entry(t, parent_key_id)?;

	assert!(slate.tx_or_err()?.body.outputs.len() == 1);

	// Creating output for that
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output_key_id.clone(),
		mmr_index: None,
		n_child: output_key_id.to_path().last_path_index(),
		commit: Some(to_hex(&slate.tx_or_err()?.outputs_committed()[0].0)),
		value: slate.amount,
		status: OutputStatus::Unconfirmed,
		height: slate.height,
		lock_height: slate.calc_lock_height(),
		is_coinbase: false,
		tx_log_entry: Some(log_id),
	})?;
	batch.commit()?;
	Ok(())
}

/// Create Swap record from income message
pub fn swap_create_from_offer<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	message_filename: String,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Updating wallet state first because we need to select outputs.
	let mut file = File::open(message_filename.clone())
		.map_err(|e| Error::Generic(format!("Unable to open file {}, {}", message_filename, e)))?;
	let mut contents = String::new();
	file.read_to_string(&mut contents).map_err(|e| {
		Error::Generic(format!(
			"Unable to read a message from the file {}, {}",
			message_filename, e
		))
	})?;

	// processing the message with a regular API.
	// but first let's check if the message type matching expected
	let message = Message::from_json(&contents)?;
	if !message.is_offer() {
		return Err(Error::Generic(
			"Expected offer message, get different one".to_string(),
		));
	}

	swap_income_message(wallet_inst, keychain_mask, &contents, None)?;
	Ok(message.id.to_string())
}

// read string value. Return empty if doesn't exist
fn json_get_str(json_msg: &serde_json::Value, key: &str) -> String {
	json_msg
		.get(key)
		.unwrap_or(&json!(""))
		.as_str()
		.unwrap_or(key)
		.to_string()
}

/// Get message for the marketplace.
pub fn marketplace_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	message: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let json_msg: serde_json::Value = serde_json::from_str(message)
		.map_err(|e| Error::Generic(format!("Unable to parse json request, {}", e)))?;

	// For response we need to enumerate all swaps. Let's start from that
	let swap_id = trades::list_swap_trades()?;
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();

	let mut swaps: Vec<Swap> = Vec::new();

	for sw_id in &swap_id {
		let swap_lock = trades::get_swap_lock(sw_id);
		let _l = swap_lock.lock();
		let (_context, swap) = trades::get_swap_trade(sw_id.as_str(), &skey, &*swap_lock)?;
		swaps.push(swap);
	}

	let command = json_get_str(&json_msg, "command");
	let response = if command == "accept_offer" || command == "check_offer" {
		let from = json_get_str(&json_msg, "from");
		let offer_id = json_get_str(&json_msg, "offer_id");
		if from.is_empty() || offer_id.is_empty() {
			return Err(Error::Generic(format!(
				"Incomplete marketplace message {}",
				message
			)));
		}

		if ONLINE_OFFERS.read().unwrap().contains_key(&offer_id) {
			if command == "accept_offer" {
				println!("Get accept_offer message from {} for {}", from, offer_id);
			}

			// Check if this offer is broadcasting and how many are running
			let tag = Some(offer_id.clone());
			let accepted_peers = swaps.iter().filter(|s| s.tag == tag).count();
			format!("{{\"running\":{}}}", accepted_peers)
		} else {
			"{\"running\":-1}".to_string() // Doesn't exist
		}
	} else if command == "fail_bidding" {
		let from = json_get_str(&json_msg, "from");
		let offer_id = json_get_str(&json_msg, "offer_id");
		if from.is_empty() || offer_id.is_empty() {
			return Err(Error::Generic(format!(
				"Incomplete marketplace message {}",
				message
			)));
		}
		println!("Get fail_bidding message from {} for {}", from, offer_id);
		// Let's cancel swap if we sell. For Buy we can't cancel automatically
		let swap_tag = Some(from + "_" + &offer_id);
		for swap in swaps.iter().filter(|s| s.tag == swap_tag) {
			if swap.is_seller() {
				// Lock and cancel...
				let swap_lock = trades::get_swap_lock(&swap.id.to_string());
				let _l = swap_lock.lock();
				let (context, mut swap) =
					trades::get_swap_trade(&swap.id.to_string(), &skey, &*swap_lock)?;

				let swap_api = match swap.secondary_currency.is_btc_family() {
					true => {
						let (uri1, uri2) = trades::get_electrumx_uri(
							&swap.secondary_currency,
							&swap.electrum_node_uri1,
							&swap.electrum_node_uri2,
						)?;
						crate::swap::api::create_btc_instance(
							&swap.secondary_currency,
							node_client.clone(),
							uri1,
							uri2,
						)?
					}
					_ => {
						let eth_swap_contract_address = trades::get_eth_swap_contract_address(
							&swap.secondary_currency,
							&swap.eth_swap_contract_address,
						)?;
						let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
							&swap.secondary_currency,
							&swap.erc20_swap_contract_address,
						)?;
						let eth_infura_project_id = trades::get_eth_infura_projectid(
							&swap.secondary_currency,
							&swap.eth_infura_project_id,
						)?;
						crate::swap::api::create_eth_instance(
							&swap.secondary_currency,
							node_client.clone(),
							ethereum_wallet.clone(),
							eth_swap_contract_address,
							erc20_swap_contract_address,
							eth_infura_project_id,
						)?
					}
				};
				let mut fsm = swap_api.get_fsm(&keychain, &swap);

				if fsm.is_cancellable(&swap)? {
					let (height, _, _) = node_client.get_chain_tip()?;
					let tx_conf = swap_api.request_tx_confirmations(&keychain, &swap)?;
					let _resp = fsm.process(
						Input::Cancel,
						&mut swap,
						&context,
						height,
						&tx_conf,
						keychain.secp(),
					)?;
					trades::store_swap_trade(&context, &swap, &skey, &*swap_lock)?;
				} else {
					warn!(
						"Get fail_bidding message for non cancellable swap trade {}, message: {}",
						swap.id, message
					);
				}
			} else {
				// Can't cancel automatically because user might post the funds to lock account. As a result
				// cancellation needs to be done manually.
				debug!("Get fail_bidding for Buyer swap trade. Nothing what we can do. Must be cancelled manually");
			}
		}
		"".to_string()
	} else {
		return Err(Error::Generic(format!(
			"marketplace message contains unknown command {}, message: {}",
			command, message
		)));
	};
	debug!("marketplace_message response: {}", response);
	Ok(response)
}

/// Processing swap income message. Note result of that can be a new offer of modification of the current one
/// We only notify user about that, no permission will be ask.
/// Reason: Nothing will be done with the funds until user will go forward manually
/// Return: option ack message
pub fn swap_income_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_message: &str,
	swap_lock: Option<Arc<Mutex<()>>>,
) -> Result<Option<Message>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let message = Message::from_json(swap_message)?;
	let swap_id = message.id.to_string();

	debug!("Get swap message {:?}", message);

	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let ethereum_wallet = w.get_ethereum_wallet()?.clone();
	let keychain = w.keychain(keychain_mask)?;
	let skey = get_swap_storage_key(&keychain)?;

	let (lock, need_to_lock) = match swap_lock {
		Some(lock) => (lock.clone(), false),
		None => (trades::get_swap_lock(&swap_id), true),
	};

	let _guard = if need_to_lock {
		Some(lock.lock())
	} else {
		None
	};

	let ack_msg = match &message.inner {
		Update::None => {
			return Err(Error::Generic(
				"Get empty message, nothing to process".to_string(),
			))
		}
		Update::Offer(offer_update) => {
			// We get an offer
			if trades::get_swap_trade(swap_id.as_str(), &skey, &*lock).is_ok() {
				return Err( Error::Generic(format!("trade with SwapID {} already exist. Probably you already processed this message", swap_id)));
			}

			let mut swap_api = match offer_update.secondary_currency.is_btc_family() {
				true => {
					let (uri1, uri2) =
						trades::get_electrumx_uri(&offer_update.secondary_currency, &None, &None)?;
					crate::swap::api::create_btc_instance(
						&offer_update.secondary_currency,
						node_client.clone(),
						uri1,
						uri2,
					)?
				}
				_ => {
					let eth_swap_contract_address = trades::get_eth_swap_contract_address(
						&offer_update.secondary_currency,
						&None,
					)?;
					let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
						&offer_update.secondary_currency,
						&None,
					)?;
					let eth_infura_project_id =
						trades::get_eth_infura_projectid(&offer_update.secondary_currency, &None)?;
					crate::swap::api::create_eth_instance(
						&offer_update.secondary_currency,
						node_client.clone(),
						ethereum_wallet.clone(),
						eth_swap_contract_address,
						erc20_swap_contract_address,
						eth_infura_project_id,
					)?
				}
			};

			// Creating Buyer context
			let context = create_context(
				&mut **w,
				Some(&ethereum_wallet.clone()),
				keychain_mask,
				&mut swap_api,
				&keychain,
				offer_update.secondary_currency,
				false,
				None,
				0,
			)?;

			let (id, offer, secondary_update) = message.unwrap_offer()?;
			let swap = BuyApi::accept_swap_offer(
				Some(ethereum_wallet),
				&keychain,
				&context,
				id,
				offer,
				secondary_update,
				&node_client.clone(),
			)?;

			trades::store_swap_trade(&context, &swap, &skey, &*lock)?;
			println!(
				"INFO: You get an offer to swap {} to MWC. SwapID is {}",
				swap.secondary_currency, swap.id
			);
			Some(Message::new(
				id,
				Update::MessageAcknowledge(1),
				SecondaryUpdate::Empty,
			))
		}
		Update::MessageAcknowledge(msg_id) => {
			let (context, mut swap) = trades::get_swap_trade(swap_id.as_str(), &skey, &*lock)?;
			match msg_id {
				1 => {
					if swap.is_seller() {
						swap.ack_msg1();
					}
				}
				2 => {
					if !swap.is_seller() {
						swap.ack_msg1();
					}
				}
				_ => {
					return Err(Error::Generic(format!(
						"Get unknown message group {} at 'MessageAcknowledge'",
						msg_id
					)))
				}
			}
			trades::store_swap_trade(&context, &swap, &skey, &*lock)?;
			None
		}
		_ => {
			let (context, mut swap) = trades::get_swap_trade(swap_id.as_str(), &skey, &*lock)?;
			let swap_api = match swap.secondary_currency.is_btc_family() {
				true => {
					let (uri1, uri2) = trades::get_electrumx_uri(
						&swap.secondary_currency,
						&swap.electrum_node_uri1,
						&swap.electrum_node_uri2,
					)?;
					crate::swap::api::create_btc_instance(
						&swap.secondary_currency,
						node_client.clone(),
						uri1,
						uri2,
					)?
				}
				_ => {
					let eth_swap_contract_address =
						trades::get_eth_swap_contract_address(&swap.secondary_currency, &None)?;
					let erc20_swap_contract_address =
						trades::get_erc20_swap_contract_address(&swap.secondary_currency, &None)?;
					let eth_infura_project_id =
						trades::get_eth_infura_projectid(&swap.secondary_currency, &None)?;
					crate::swap::api::create_eth_instance(
						&swap.secondary_currency,
						node_client.clone(),
						ethereum_wallet.clone(),
						eth_swap_contract_address,
						erc20_swap_contract_address,
						eth_infura_project_id,
					)?
				}
			};

			let tx_conf = swap_api.request_tx_confirmations(&keychain, &swap)?;
			let mut fsm = swap_api.get_fsm(&keychain, &swap);
			let msg_gr = match &&message.inner {
				Update::Offer(_) | Update::AcceptOffer(_) => 1,
				_ => 2,
			};
			swap.wait_for_backup1 = true; // Processing message pessimistic way. We don't want to trigger any action
			let (height, _, _) = node_client.get_chain_tip()?;
			fsm.process(
				Input::IncomeMessage(message),
				&mut swap,
				&context,
				height,
				&tx_conf,
				keychain.secp(),
			)?;
			trades::store_swap_trade(&context, &swap, &skey, &*lock)?;
			println!("INFO: Processed income message for SwapId {}", swap.id);

			Some(Message::new(
				swap.id.clone(),
				Update::MessageAcknowledge(msg_gr),
				SecondaryUpdate::Empty,
			))
		}
	};
	Ok(ack_msg)
}

// Local Helper method to create a context
fn create_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	ethereum_wallet: Option<&EthereumWallet>,
	keychain_mask: Option<&SecretKey>,
	swap_api: &mut Box<dyn SwapApi<K> + 'a>,
	keychain: &K,
	secondary_currency: Currency,
	is_seller: bool,
	inputs: Option<Vec<(Identifier, Option<u64>, u64)>>,
	change_amount: u64,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secondary_key_size =
		(**swap_api).context_key_count(keychain, secondary_currency, is_seller)?;
	let mut keys: Vec<Identifier> = Vec::new();

	let parent_key_id = if is_seller {
		wallet.parent_key_id()
	} else {
		// For Buyer it is receive account
		let dest_acct_name = get_receive_account();
		match dest_acct_name {
			Some(d) => {
				let pm = wallet.get_acct_path(d.to_owned())?;
				match pm {
					Some(p) => p.path,
					None => wallet.parent_key_id(),
				}
			}
			None => wallet.parent_key_id(),
		}
	};

	for _ in 0..secondary_key_size {
		keys.push(wallet.next_child(keychain_mask, Some(&parent_key_id), None)?);
	}

	let context = (**swap_api).create_context(
		keychain,
		ethereum_wallet,
		secondary_currency,
		is_seller,
		inputs,
		change_amount,
		keys,
		parent_key_id,
	)?;

	Ok(context)
}
