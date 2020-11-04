// Copyright 2019 The vault713 Developers
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

use super::client::BtcNodeClient;
use super::types::{BtcBuyerContext, BtcData, BtcSellerContext};
use crate::grin_util::secp::pedersen;
use crate::grin_util::Mutex;
use crate::swap::bitcoin::types::BtcTtansaction;
use crate::swap::bitcoin::Output;
use crate::swap::fsm::machine::StateMachine;
use crate::swap::fsm::{buyer_swap, seller_swap};
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::{
	BuyerContext, Context, Currency, RoleContext, SecondaryBuyerContext, SecondarySellerContext,
	SellerContext, SwapTransactionsConfirmations,
};
use crate::swap::{ErrorKind, SellApi, Swap, SwapApi};
use crate::{NodeClient, Slate};
use bitcoin::{Address, Script};
use bitcoin_hashes::sha256d;
use failure::_core::marker::PhantomData;
use grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp;
use grin_util::secp::aggsig::export_secnonce_single as generate_nonce;
use std::str::FromStr;
use std::sync::Arc;

/// SwapApi trait implementaiton for BTC
#[derive(Clone)]
pub struct BtcSwapApi<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Client for MWC node
	pub node_client: Arc<C>,
	/// Primary Client for BTC electrumx node
	pub btc_node_client1: Arc<Mutex<B>>,
	/// Secondary Client for BTC electrumx node
	pub btc_node_client2: Arc<Mutex<B>>,

	phantom: PhantomData<&'a C>,
}

impl<'a, C, B> BtcSwapApi<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create BTC Swap API instance
	pub fn new(
		node_client: Arc<C>,
		btc_node_client1: Arc<Mutex<B>>,
		btc_node_client2: Arc<Mutex<B>>,
	) -> Self {
		Self {
			node_client,
			btc_node_client1,
			btc_node_client2,
			phantom: PhantomData,
		}
	}

	/// For tests doesn't make sense to use any failover
	pub fn new_test(node_client: Arc<C>, btc_node_client: Arc<Mutex<B>>) -> Self {
		Self {
			node_client,
			btc_node_client1: btc_node_client.clone(),
			btc_node_client2: btc_node_client,
			phantom: PhantomData,
		}
	}

	/// Clone instance
	pub fn clone(&self) -> Self {
		Self {
			node_client: self.node_client.clone(),
			btc_node_client1: self.btc_node_client1.clone(),
			btc_node_client2: self.btc_node_client2.clone(),
			phantom: PhantomData,
		}
	}

	/// Update swap.secondary_data with a roll back script.
	pub(crate) fn script(&self, swap: &Swap) -> Result<Script, ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let sekp = secp::Secp256k1::new();
		Ok(btc_data.script(
			&sekp,
			swap.redeem_public
				.as_ref()
				.ok_or(ErrorKind::UnexpectedAction(
					"swap.redeem_public value is not defined. Method BtcSwapApi::script"
						.to_string(),
				))?,
			swap.get_time_btc_lock() as u64,
		)?)
	}

	/// Check BTC amount at the chain.
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	pub(crate) fn btc_balance(
		&self,
		swap: &Swap,
		input_script: &Script,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64, Vec<Output>), ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let address = btc_data.address(input_script, swap.network)?;
		let outputs = match self.btc_node_client1.lock().unspent(&address) {
			Ok(r) => r,
			Err(_) => self.btc_node_client2.lock().unspent(&address)?,
		};
		let height = match self.btc_node_client1.lock().height() {
			Ok(r) => r,
			Err(_) => self.btc_node_client2.lock().height()?,
		};
		let mut pending_amount = 0;
		let mut confirmed_amount = 0;
		let mut least_confirmations = None;

		let mut confirmed_outputs = Vec::new();

		for output in outputs {
			if output.height == 0 {
				// Output in mempool
				least_confirmations = Some(0);
				pending_amount += output.value;
			} else {
				let confirmations = height.saturating_sub(output.height) + 1;
				if confirmations >= confirmations_needed {
					// Enough confirmations
					confirmed_amount += output.value;
				} else {
					// Not yet enough confirmations
					if least_confirmations
						.map(|least| confirmations < least)
						.unwrap_or(true)
					{
						least_confirmations = Some(confirmations);
					}
					pending_amount += output.value;
				}
				confirmed_outputs.push(output);
			}
		}

		Ok((
			pending_amount,
			confirmed_amount,
			least_confirmations.unwrap_or(0),
			confirmed_outputs,
		))
	}

	/// Seller builds the transaction to redeem their Bitcoins, Status::Redeem
	/// Updating data:  swap.secondary_data.redeem_tx
	fn seller_build_redeem_tx<K: Keychain>(
		&self,
		keychain: &K,
		swap: &Swap,
		context: &Context,
		input_script: &Script,
	) -> Result<BtcTtansaction, ErrorKind> {
		let cosign_id = &context.unwrap_seller()?.unwrap_btc()?.cosign;

		let redeem_address_str = swap.unwrap_seller()?.0.clone();
		let redeem_address = Address::from_str(&redeem_address_str).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse BTC redeem address {}, {}",
				redeem_address_str, e
			))
		})?;

		let cosign_secret = keychain.derive_key(0, cosign_id, SwitchCommitmentType::None)?;
		let redeem_secret = SellApi::calculate_redeem_secret(keychain, swap)?;

		// This function should only be called once
		let btc_data = swap.secondary_data.unwrap_btc()?;

		let (pending_amount, confirmed_amount, _, mut conf_outputs) =
			self.btc_balance(swap, input_script, 0)?;
		if pending_amount + confirmed_amount == 0 {
			return Err(ErrorKind::Generic(
				"Not found outputs to redeem. Probably Buyer already refund it".to_string(),
			));
		}

		// Sort needed for transaction hash stabilization. We want all calls  return the same Hash
		conf_outputs.sort_by(|a, b| a.out_point.txid.cmp(&b.out_point.txid));

		let (btc_transaction, _, _, _) = btc_data.build_redeem_tx(
			keychain.secp(),
			&redeem_address,
			&input_script,
			swap.secondary_fee,
			&cosign_secret,
			&redeem_secret,
			&conf_outputs,
		)?;

		Ok(btc_transaction)
	}

	fn buyer_refund<K: Keychain>(
		&self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: &Address,
		input_script: &Script,
	) -> Result<(), ErrorKind> {
		let (pending_amount, confirmed_amount, _, conf_outputs) =
			self.btc_balance(swap, input_script, 0)?;

		if pending_amount + confirmed_amount == 0 {
			return Err(ErrorKind::Generic(
				"Not found outputs to refund. Probably Seller already redeem it".to_string(),
			));
		}

		let refund_key = keychain.derive_key(
			0,
			&context.unwrap_buyer()?.unwrap_btc()?.refund,
			SwitchCommitmentType::None,
		)?;

		let btc_lock_time = swap.get_time_btc_lock();
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let refund_tx = btc_data.refund_tx(
			keychain.secp(),
			refund_address,
			input_script,
			swap.secondary_fee,
			btc_lock_time,
			&refund_key,
			&conf_outputs,
		)?;

		let tx = refund_tx.tx.clone();
		if let Err(_) = self.btc_node_client1.lock().post_tx(tx.clone()) {
			self.btc_node_client2.lock().post_tx(tx)?;
		}
		btc_data.refund_tx = Some(refund_tx.txid);
		btc_data.tx_fee = Some(swap.secondary_fee);
		Ok(())
	}

	fn get_slate_confirmation_number(
		&self,
		mwc_tip: &u64,
		slate: &Slate,
		outputs_ok: bool,
	) -> Result<Option<u64>, ErrorKind> {
		let result: Option<u64> = if slate.tx.kernels().is_empty() {
			None
		} else {
			debug_assert!(slate.tx.kernels().len() == 1);

			let kernel = &slate.tx.kernels()[0].excess;
			if kernel.0.to_vec().iter().any(|v| *v != 0) {
				// kernel is non zero - we can check transaction by kernel
				match self
					.node_client
					.get_kernel(kernel, Some(slate.height), None)?
				{
					Some((_tx_kernel, height, _mmr_index)) => {
						Some(mwc_tip.saturating_sub(height) + 1)
					}
					None => None,
				}
			} else {
				if outputs_ok {
					// kernel is not valid, still can use outputs.
					let wallet_outputs: Vec<pedersen::Commitment> = slate
						.tx
						.outputs()
						.iter()
						.map(|o| o.commit.clone())
						.collect();
					let res = self.node_client.get_outputs_from_node(&wallet_outputs)?;
					let height = res.values().map(|v| v.1).max();
					match height {
						Some(h) => Some(mwc_tip.saturating_sub(h) + 1),
						None => None,
					}
				} else {
					None
				}
			}
		};
		Ok(result)
	}

	/// Retrieve confirmation number for BTC transaction.
	fn get_btc_confirmation_number(
		&self,
		btc_tip: &u64,
		tx_hash: Option<sha256d::Hash>,
	) -> Result<Option<u64>, ErrorKind> {
		let result: Option<u64> = match tx_hash {
			None => None,
			Some(tx_hash) => {
				let tx_resp = match self.btc_node_client1.lock().transaction(&tx_hash) {
					Ok(r) => r,
					Err(_) => self.btc_node_client2.lock().transaction(&tx_hash)?,
				};
				match tx_resp {
					None => None,
					Some((height, _tx)) => match height {
						None => Some(0),
						Some(h) => Some(btc_tip.saturating_sub(h) + 1),
					},
				}
			}
		};
		Ok(result)
	}
}

impl<'a, K, C, B> SwapApi<K> for BtcSwapApi<'a, C, B>
where
	K: Keychain + 'a,
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		_is_seller: bool,
	) -> Result<usize, ErrorKind> {
		if secondary_currency != Currency::Btc && secondary_currency != Currency::Bch {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		Ok(4)
	}

	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>,
		change_amount: u64,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind> {
		if secondary_currency != Currency::Btc && secondary_currency != Currency::Bch {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		let secp = keychain.secp();
		let mut keys = keys.into_iter();

		let role_context = if is_seller {
			RoleContext::Seller(SellerContext {
				inputs: inputs.ok_or(ErrorKind::UnexpectedRole(
					"Fn create_context() for seller not found inputs".to_string(),
				))?,
				change_output: keys.next().unwrap(),
				change_amount,
				refund_output: keys.next().unwrap(),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: keys.next().unwrap(),
				}),
			})
		} else {
			RoleContext::Buyer(BuyerContext {
				output: keys.next().unwrap(),
				redeem: keys.next().unwrap(),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: keys.next().unwrap(),
				}),
			})
		};

		Ok(Context {
			multisig_key: keys.next().unwrap(),
			multisig_nonce: generate_nonce(secp)?,
			lock_nonce: generate_nonce(secp)?,
			refund_nonce: generate_nonce(secp)?,
			redeem_nonce: generate_nonce(secp)?,
			role_context,
		})
	}

	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		seller_lock_first: bool,
		mwc_confirmations: u64,
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
		communication_method: String,
		buyer_destination_address: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
	) -> Result<Swap, ErrorKind> {
		// Checking if address is valid
		let _redeem_address = Address::from_str(&secondary_redeem_address).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse secondary currency redeem address {}, {}",
				secondary_redeem_address, e
			))
		})?;

		if secondary_currency != Currency::Btc && secondary_currency != Currency::Bch {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		let height = self.node_client.get_chain_tip()?.0;
		let mut swap = SellApi::create_swap_offer(
			keychain,
			context,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_redeem_address,
			height,
			seller_lock_first,
			mwc_confirmations,
			secondary_confirmations,
			message_exchange_time_sec,
			redeem_time_sec,
			communication_method,
			buyer_destination_address,
			electrum_node_uri1,
			electrum_node_uri2,
		)?;

		let btc_data = BtcData::new(keychain, context.unwrap_seller()?.unwrap_btc()?)?;
		swap.secondary_data = btc_data.wrap();

		Ok(swap)
	}

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate {
		let btc_data = swap
			.secondary_data
			.unwrap_btc()
			.expect("Secondary data of unexpected type");
		SecondaryUpdate::BTC(btc_data.offer_update())
	}

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate {
		let btc_data = swap
			.secondary_data
			.unwrap_btc()
			.expect("Secondary data of unexpected type");
		SecondaryUpdate::BTC(btc_data.accept_offer_update())
	}

	fn publish_secondary_transaction(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		assert!(swap.is_seller());

		let input_script = self.script(swap)?;

		let btc_tx = self.seller_build_redeem_tx(keychain, swap, context, &input_script)?;

		if let Err(_) = self.btc_node_client1.lock().post_tx(btc_tx.tx.clone()) {
			self.btc_node_client2.lock().post_tx(btc_tx.tx)?;
		}

		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.redeem_tx = Some(btc_tx.txid);
		btc_data.tx_fee = Some(swap.secondary_fee);
		Ok(())
	}

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&self,
		_keychain: &K, // keychain is kept for Type. Compiler need to understand all types
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind> {
		let mwc_tip = self.node_client.get_chain_tip()?.0;

		let is_seller = swap.is_seller();

		let mwc_lock_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.lock_slate, !is_seller)?;
		let mwc_redeem_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.redeem_slate, is_seller)?;
		let mwc_refund_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.refund_slate, !is_seller)?;

		let btc_tip = match self.btc_node_client1.lock().height() {
			Ok(r) => r,
			Err(_) => self.btc_node_client2.lock().height()?,
		};
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let secondary_redeem_conf =
			self.get_btc_confirmation_number(&btc_tip, btc_data.redeem_tx.clone())?;
		let secondary_refund_conf =
			self.get_btc_confirmation_number(&btc_tip, btc_data.refund_tx.clone())?;

		// BTC lock account...
		// Checking Amount, it can be too hight as well
		let mut secondary_lock_amount = 0;
		let mut least_confirmations = None;

		if let Ok(input_script) = self.script(swap) {
			if let Ok(address) = btc_data.address(&input_script, swap.network) {
				let outputs = match self.btc_node_client1.lock().unspent(&address) {
					Ok(r) => r,
					Err(_) => self.btc_node_client2.lock().unspent(&address)?,
				};
				for output in outputs {
					secondary_lock_amount += output.value;
					if output.height == 0 {
						// Output in mempool
						least_confirmations = Some(0);
					} else {
						let confirmations = btc_tip.saturating_sub(output.height) + 1;
						if confirmations < least_confirmations.unwrap_or(std::i32::MAX as u64) {
							least_confirmations = Some(confirmations);
						}
					}
				}
			}
		}

		Ok(SwapTransactionsConfirmations {
			mwc_tip,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
			secondary_tip: btc_tip,
			secondary_lock_conf: least_confirmations,
			secondary_lock_amount,
			secondary_redeem_conf,
			secondary_refund_conf,
		})
	}

	/// Check How much BTC coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64), ErrorKind> {
		let input_script = self.script(swap)?;

		let (pending_amount, confirmed_amount, least_confirmations, _outputs) =
			self.btc_balance(swap, &input_script, confirmations_needed)?;

		Ok((pending_amount, confirmed_amount, least_confirmations))
	}

	// Build state machine that match the swap data
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine {
		let kc = Arc::new(keychain.clone());
		let nc = self.node_client.clone();
		let b: Box<dyn SwapApi<K> + 'a> = Box::new((*self).clone());
		let swap_api = Arc::new(b);

		if swap.is_seller() {
			StateMachine::new(vec![
				Box::new(seller_swap::SellerOfferCreated::new()),
				Box::new(seller_swap::SellerSendingOffer::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForAcceptanceMessage::new(
					kc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerLock::new()),
				Box::new(seller_swap::SellerPostingLockMwcSlate::new(nc.clone())),
				Box::new(seller_swap::SellerWaitingForLockConfirmations::new(
					kc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForInitRedeemMessage::new(
					kc.clone(),
				)),
				Box::new(seller_swap::SellerSendingInitRedeemMessage::new()),
				Box::new(seller_swap::SellerWaitingForBuyerToRedeemMwc::new(
					nc.clone(),
				)),
				Box::new(seller_swap::SellerRedeemSecondaryCurrency::new(
					kc.clone(),
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForRedeemConfirmations::new(
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerSwapComplete::new()),
				Box::new(seller_swap::SellerWaitingForRefundHeight::new(nc.clone())),
				Box::new(seller_swap::SellerPostingRefundSlate::new(nc.clone())),
				Box::new(seller_swap::SellerWaitingForRefundConfirmations::new()),
				Box::new(seller_swap::SellerCancelledRefunded::new()),
				Box::new(seller_swap::SellerCancelled::new()),
			])
		} else {
			StateMachine::new(vec![
				Box::new(buyer_swap::BuyerOfferCreated::new()),
				Box::new(buyer_swap::BuyerSendingAcceptOfferMessage::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForSellerToLock::new()),
				Box::new(buyer_swap::BuyerPostingSecondaryToMultisigAccount::new(
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForLockConfirmations::new(
					kc.clone(),
				)),
				Box::new(buyer_swap::BuyerSendingInitRedeemMessage::new()),
				Box::new(buyer_swap::BuyerWaitingForRespondRedeemMessage::new(
					kc.clone(),
				)),
				Box::new(buyer_swap::BuyerRedeemMwc::new(nc.clone())),
				Box::new(buyer_swap::BuyerWaitForRedeemMwcConfirmations::new()),
				Box::new(buyer_swap::BuyerSwapComplete::new()),
				Box::new(buyer_swap::BuyerWaitingForRefundTime::new()),
				Box::new(buyer_swap::BuyerPostingRefundForSecondary::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForRefundConfirmations::new(
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerCancelledRefunded::new()),
				Box::new(buyer_swap::BuyerCancelled::new()),
			])
		}
	}

	/// Get a secondary address for the lock account
	fn get_secondary_lock_address(&self, swap: &Swap) -> Result<String, ErrorKind> {
		let input_script = self.script(swap)?;
		let adrress = swap
			.secondary_data
			.unwrap_btc()?
			.address(&input_script, swap.network)?;
		Ok(adrress.to_string())
	}

	/// Check if tx fee for the secondary is different from the posted
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, ErrorKind> {
		Ok(swap.secondary_data.unwrap_btc()?.tx_fee != Some(swap.secondary_fee))
	}

	/// Post BTC refund transaction
	fn post_secondary_refund_tx(
		&self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
	) -> Result<(), ErrorKind> {
		assert!(!swap.is_seller());

		let refund_address_str = refund_address.ok_or(ErrorKind::Generic(
			"Please define BTC refund address".to_string(),
		))?;

		let refund_address = Address::from_str(&refund_address_str).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse BTC address {}, {}",
				refund_address_str, e
			))
		})?;

		let input_script = self.script(swap)?;
		self.buyer_refund(keychain, context, swap, &refund_address, &input_script)?;
		Ok(())
	}
}
