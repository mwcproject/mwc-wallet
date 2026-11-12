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

use super::client::{secondary_confirmations_at_tip, BtcNodeClient};
use super::recovery::recover_confirmed_variant;
use super::refund::{self, BtcRefundBatch, BtcRefundPlan, BtcRefundProgress, MAX_REFUND_INPUTS};
use super::types::{minimum_output, BtcBuyerContext, BtcData, BtcSellerContext};
use crate::internal::chain_session::NodeReadSession;
use crate::swap::bitcoin::types::BtcTtansaction;
use crate::swap::bitcoin::Output;
use crate::swap::ethereum::*;
use crate::swap::fsm::machine::StateMachine;
use crate::swap::fsm::{buyer_swap, seller_swap};
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::{
	BuyerContext, Context, Currency, RoleContext, SecondaryBuyerContext, SecondarySellerContext,
	SellerContext, SellerInput, SwapTransactionsConfirmations,
};
use crate::swap::{Error, SellApi, Swap, SwapApi};
use crate::{NodeClient, SecondaryFeeUnits, Slate};
use bitcoin::{Script, Txid};
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::Message;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_wallet_util::Mutex;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;

struct BtcConfirmationSnapshot {
	tip: u64,
	lock_outputs: Vec<Output>,
	redeem_confirmations: Option<u64>,
	refund_confirmations: Option<u64>,
}

fn read_unspent_and_tip<B: BtcNodeClient>(
	client: &mut B,
	context_id: u32,
	currency: &Currency,
	address: &String,
) -> Result<(Vec<Output>, u64), Error> {
	// Read the tip last. Forward chain movement between the two reads can only
	// make the returned confirmation count conservative.
	let outputs = client.unspent(context_id, *currency, address)?;
	let tip = client.height()?;
	Ok((outputs, tip))
}

fn validate_coinbase_maturity<B: BtcNodeClient>(
	client: &mut B,
	currency: Currency,
	outputs: &[Output],
	tip: u64,
) -> Result<(), Error> {
	// These depths permit spending in the next block. BTC/BCH/LTC/Dash/ZEC
	// require 100 blocks; Dogecoin's current mainnet/testnet rules require 240
	// (src/chainparams.cpp, digishieldConsensus.nCoinbaseMaturity).
	let maturity = match currency {
		Currency::Btc | Currency::Bch | Currency::Ltc | Currency::Dash | Currency::ZCash => 100,
		Currency::Doge => 240,
		_ => return Err(Error::UnexpectedCoinType),
	};
	// The same transaction can fund multiple outputs. Reuse its immutable type
	// only within this read, so retries still recheck the current funding view.
	let mut checked_transactions = HashSet::new();
	for output in outputs {
		let confirmations = secondary_confirmations_at_tip(tip, output.height);
		if confirmations < maturity
			&& checked_transactions.insert(output.out_point.txid)
			&& client.transaction_is_coinbase(&output.out_point.txid)?
		{
			return Err(Error::Generic(format!(
				"Swap funding transaction {} is an immature coinbase: {confirmations} confirmations, {maturity} required",
				output.out_point.txid
			)));
		}
	}
	Ok(())
}

fn read_confirmation_snapshot<B: BtcNodeClient>(
	client: &mut B,
	context_id: u32,
	currency: &Currency,
	lock_address: Option<&String>,
	redeem_txs: &[Txid],
	redeem_attempts: &[BtcTtansaction],
	refund_tx: Option<&Txid>,
	prepared_refund_tx: Option<&Txid>,
) -> Result<BtcConfirmationSnapshot, Error> {
	let mut redeem_confirmations = Vec::with_capacity(redeem_txs.len());
	for tx_hash in redeem_txs {
		redeem_confirmations.push(client.transaction_confirmations(tx_hash)?);
	}
	// A legacy scriptSig variant may confirm under an unknown ID. Only a
	// confirmed spend matching a retained signed attempt counts as redemption.
	if redeem_confirmations.iter().all(|c| c.unwrap_or(0) == 0) {
		if let Some(found) =
			recover_confirmed_variant(client, redeem_attempts.iter(), "redemption")?
		{
			redeem_confirmations.push(Some(found.confirmations));
		}
	}
	let refund_confirmations = match refund_tx {
		Some(tx_hash) => client.transaction_confirmations(tx_hash)?,
		None => None,
	};
	// The prepared transaction may have been accepted even when its broadcast
	// response was lost. Continue checking the prior transaction as well, since
	// a rejected replacement must not hide a refund that has already confirmed.
	let prepared_refund_confirmations = match prepared_refund_tx {
		Some(tx_hash) if Some(tx_hash) != refund_tx => client.transaction_confirmations(tx_hash)?,
		_ => None,
	};
	let (lock_outputs, tip) = match lock_address {
		Some(address) => read_unspent_and_tip(client, context_id, currency, address)?,
		None => (Vec::new(), client.height()?),
	};
	let normalize_transaction_confirmations = |confirmations: Option<u64>| {
		confirmations.map(|confirmations| {
			if confirmations > tip {
				0
			} else {
				confirmations
			}
		})
	};

	Ok(BtcConfirmationSnapshot {
		tip,
		lock_outputs,
		redeem_confirmations: redeem_confirmations
			.into_iter()
			.filter_map(normalize_transaction_confirmations)
			.max(),
		refund_confirmations: normalize_transaction_confirmations(refund_confirmations).max(
			normalize_transaction_confirmations(prepared_refund_confirmations),
		),
	})
}

/// SwapApi trait implementation for BTC
#[derive(Clone)]
pub struct BtcSwapApi<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	context_id: u32,
	/// Currency. BTC - it is a BTC family. There are some tweaks for different coins.
	secondary_currency: Currency,
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
		context_id: u32,
		secondary_currency: Currency,
		node_client: Arc<C>,
		btc_node_client1: Arc<Mutex<B>>,
		btc_node_client2: Arc<Mutex<B>>,
	) -> Self {
		Self {
			context_id,
			secondary_currency,
			node_client,
			btc_node_client1,
			btc_node_client2,
			phantom: PhantomData,
		}
	}

	/// For tests doesn't make sense to use any failover
	pub fn new_test(node_client: Arc<C>, btc_node_client: Arc<Mutex<B>>) -> Self {
		Self {
			context_id: 0,
			secondary_currency: Currency::Btc,
			node_client,
			btc_node_client1: btc_node_client.clone(),
			btc_node_client2: btc_node_client,
			phantom: PhantomData,
		}
	}

	/// Clone instance
	pub fn clone(&self) -> Self {
		Self {
			context_id: self.context_id.clone(),
			secondary_currency: self.secondary_currency.clone(),
			node_client: self.node_client.clone(),
			btc_node_client1: self.btc_node_client1.clone(),
			btc_node_client2: self.btc_node_client2.clone(),
			phantom: PhantomData,
		}
	}

	/// Run a complete read against one backend. If the primary fails, repeat
	/// the whole operation against the secondary so fields from different chain
	/// views are never combined into one result.
	fn read_btc_with_fallback<T, F>(&self, mut read: F) -> Result<T, Error>
	where
		F: FnMut(&mut B) -> Result<T, Error>,
	{
		let primary_result = {
			let mut primary = self.btc_node_client1.lock();
			read(&mut *primary)
		};
		match primary_result {
			Ok(result) => Ok(result),
			Err(_) => {
				let mut secondary = self.btc_node_client2.lock();
				read(&mut *secondary)
			}
		}
	}

	/// Update swap.secondary_data with a roll back script.
	pub(crate) fn script(&self, swap: &Swap, secp: &Secp256k1) -> Result<Script, Error> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let lock_time = swap.get_time_secondary_lock_script()?;
		Ok(btc_data.script(
			swap.redeem_public.as_ref().ok_or(Error::UnexpectedAction(
				"swap.redeem_public value is not defined. Method BtcSwapApi::script".to_string(),
			))?,
			u64::try_from(lock_time).map_err(|e| {
				Error::DataOverflow(format!(
					"BtcSwapApi::script, secondary lock timestamp is before the Unix epoch or does not fit u64, lock_time={} error={}",
					lock_time, e
				))
			})?,
			secp,
		)?)
	}

	/// Check BTC amount at the chain.
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	pub(crate) fn btc_balance(
		&self,
		swap: &Swap,
		input_script: &Script,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64, Vec<Output>), Error> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let address = btc_data.address(self.secondary_currency, input_script, swap.network)?;
		let address = address.first().ok_or_else(|| {
			Error::Generic("BtcSwapApi::btc_balance, lock address is missing".to_string())
		})?;
		let (outputs, height) = self.read_btc_with_fallback(|client| {
			read_unspent_and_tip(client, self.context_id, &self.secondary_currency, address)
		})?;
		let mut pending_amount: u64 = 0;
		let mut confirmed_amount: u64 = 0;
		let mut least_confirmations = None;

		let mut confirmed_outputs = Vec::new();

		for output in outputs {
			if output.height == 0 || output.height > height {
				// A zero height is a mempool output. A height above this
				// backend's final tip is an in-flight/reorg inconsistency and is
				// handled just as conservatively until the next poll.
				least_confirmations = Some(0);
				pending_amount = pending_amount.checked_add(output.value).ok_or_else(|| {
					Error::DataOverflow(format!(
						"BtcSwapApi::btc_balance, pending secondary balance overflow, pending_amount={} output_value={}",
						pending_amount, output.value
					))
				})?;
			} else {
				let confirmations = secondary_confirmations_at_tip(height, output.height);
				if confirmations >= confirmations_needed {
					// Enough confirmations
					confirmed_amount =
						confirmed_amount.checked_add(output.value).ok_or_else(|| {
							Error::DataOverflow(format!(
								"BtcSwapApi::btc_balance, confirmed secondary balance overflow, confirmed_amount={} output_value={}",
								confirmed_amount, output.value
							))
						})?;
				} else {
					// Not yet enough confirmations
					if least_confirmations
						.map(|least| confirmations < least)
						.unwrap_or(true)
					{
						least_confirmations = Some(confirmations);
					}
					pending_amount = pending_amount.checked_add(output.value).ok_or_else(|| {
						Error::DataOverflow(format!(
							"BtcSwapApi::btc_balance, pending secondary balance overflow, pending_amount={} output_value={}",
							pending_amount, output.value
						))
					})?;
				}
				confirmed_outputs.push(output);
			}
		}
		confirmed_outputs.sort_by(|left, right| {
			left.out_point
				.txid
				.cmp(&right.out_point.txid)
				.then_with(|| left.out_point.vout.cmp(&right.out_point.vout))
		});

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
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
		input_script: &Script,
	) -> Result<BtcTtansaction, Error> {
		let cosign_id = &context.unwrap_seller()?.unwrap_btc()?.cosign;

		let redeem_address_str = swap.unwrap_seller()?.0.clone();

		self.secondary_currency
			.validate_address(self.context_id, &redeem_address_str)?;

		let cosign_secret = keychain.derive_key(secp, 0, cosign_id, SwitchCommitmentType::None)?;
		let redeem_secret = SellApi::calculate_redeem_secret(secp, swap)?;

		// Use the accepted set even if a mempool spend hides these outputs from
		// listunspent. Retries and fee replacements must spend the same inputs.
		let conf_outputs = swap
			.secondary_data
			.unwrap_btc()?
			.accepted_redeem_inputs(swap.secondary_amount)?;

		let secondary_currency = self.secondary_currency.clone();
		let redeem_script_sig = |msg: &Message| {
			BtcData::redeem_script_sig(
				&secondary_currency,
				input_script,
				&mut secp.sign(msg, &cosign_secret)?,
				&mut secp.sign(msg, &redeem_secret)?,
				&secp,
			)
		};

		let secondary_fee_units = swap.secondary_fee_units;
		let (btc_transaction, _, _, _) = BtcData::spend_lock_transaction(
			self.context_id,
			&self.secondary_currency,
			&redeem_address_str,
			&input_script,
			secondary_fee_units,
			0,
			conf_outputs,
			redeem_script_sig,
		)?;

		Ok(btc_transaction)
	}

	/// Prepare the next refund batch, or reuse/replace its saved attempt.
	/// The owner saves the mutated swap before `buyer_refund` broadcasts these
	/// exact bytes. Confirmation polling then requests this method again until
	/// every selected batch is confirmed; excluded deposits remain unrefunded.
	/// See `bitcoin::refund` for inventory, fee and parent/child recovery rules.
	fn buyer_build_refund_tx<K: Keychain>(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: &String,
		input_script: &Script,
	) -> Result<BtcTtansaction, Error> {
		let address = swap
			.secondary_data
			.unwrap_btc()?
			.address(self.secondary_currency, input_script, swap.network)?
			.into_iter()
			.next()
			.ok_or(Error::SecondaryDataIncomplete)?;
		let (observed_plan, mut observations, outputs, tip) =
			self.read_btc_with_fallback(|client| {
				let mut plan = swap.secondary_data.unwrap_btc()?.refund_plan.clone();
				let observations = match &mut plan {
					Some(plan) => plan.observe(client)?,
					None => Vec::new(),
				};
				let (outputs, tip) = read_unspent_and_tip(
					client,
					self.context_id,
					&self.secondary_currency,
					&address,
				)?;
				Ok((plan, observations, outputs, tip))
			})?;
		if swap.secondary_data.unwrap_btc()?.refund_plan.is_none() {
			let data = swap.secondary_data.unwrap_btc()?;
			if outputs.is_empty() && data.refund_transaction.is_none() {
				return Err(Error::Generic("No outputs available to refund".into()));
			}
			let mut plan = BtcRefundPlan::new(outputs.clone())?;
			if let Some(saved) = &data.refund_transaction {
				// Preserve an existing transaction even if listunspent hides its inputs.
				let assigned: std::collections::HashSet<_> =
					saved.inputs.iter().map(|o| o.out_point).collect();
				plan.pending.retain(|o| !assigned.contains(&o.out_point));
				plan.batches.push(BtcRefundBatch {
					spends_carry: false,
					attempts: vec![saved.clone()],
					legacy_txid: data
						.refund_tx
						.filter(|hash| *hash != saved.transaction.txid),
					last_broadcast_attempt: swap.posted_refund,
				});
			}
			// Keep the inventory even if fees or unconfirmed deposits prevent building.
			swap.secondary_data.unwrap_btc_mut()?.refund_plan = Some(plan);
			return self.buyer_build_refund_tx(
				secp,
				keychain,
				context,
				swap,
				refund_address,
				input_script,
			);
		}
		for observation in &mut observations {
			if observation.confirmations.unwrap_or(0) > tip {
				observation.confirmations = Some(0);
			}
		}
		let mut plan =
			observed_plan.ok_or_else(|| Error::Generic("Refund plan is missing".into()))?;
		if plan.skip_uneconomic(
			self.secondary_currency,
			swap.secondary_fee_units,
			input_script,
		)? > 0
		{
			swap.add_journal_message(format!(
				"{} refund: {} deposits totaling {} remain unrefunded because their value does not exceed their incremental fee. Outpoints and fee estimates are retained in the refund plan.",
				self.secondary_currency, plan.unrefunded.len(),
				self.secondary_currency.amount_to_hr_string(plan.unrefunded_amount()?, true),
			));
		}
		// Keep recovered confirmed variants and exclusions even if preparing the
		// next transaction fails. A child must retain its actual parent's bytes.
		swap.secondary_data.unwrap_btc_mut()?.refund_plan = Some(plan.clone());
		let progress = plan.progress(&observations, &outputs, tip, swap.secondary_confirmations)?;
		let refund_key = keychain.derive_key(
			secp,
			0,
			&context.unwrap_buyer()?.unwrap_btc()?.refund,
			SwitchCommitmentType::None,
		)?;
		let btc_lock_time = swap.get_time_secondary_lock_script()?;
		let carry_script = refund::carry_script(secp, &refund_key)?;
		let destination = self
			.secondary_currency
			.address_2_script_pubkey(self.context_id, refund_address)?;
		let (batch_index, selected, spends_carry, creates_carry, reuse) = match progress {
			BtcRefundProgress::NextBatch { .. } => {
				let carry = plan.carry(&observations)?;
				let available = plan.available(&outputs, tip)?;
				let available_count = available.len();
				let mut inputs = Vec::new();
				if let Some(output) = &carry {
					inputs.push(output.clone());
				}
				inputs.extend(available.into_iter().take(MAX_REFUND_INPUTS - inputs.len()));
				let count = inputs.len() - usize::from(carry.is_some());
				// Pay out when all currently confirmed deposits have been selected;
				// unconfirmed donations must not hold the buyer's balance in a carry.
				(
					plan.batches.len(),
					inputs,
					carry.is_some(),
					count < available_count,
					None,
				)
			}
			BtcRefundProgress::Pending {
				batch,
				confirmations,
				replacement_allowed,
				..
			} => {
				let saved = &plan.batches[batch];
				let pinned_hash = plan
					.batches
					.get(batch + 1)
					.filter(|child| child.spends_carry)
					.and_then(|child| child.attempts.first())
					.and_then(|attempt| attempt.inputs.first())
					.map(|input| {
						mwc_wallet_util::bitcoin_hashes::sha256d::Hash::from_byte_array(
							input.out_point.txid.to_byte_array(),
						)
					});
				let attempt = if let Some(hash) = pinned_hash {
					saved.attempts.iter().find(|a| a.transaction.txid == hash)
				} else if confirmations.unwrap_or(0) > 0 {
					saved
						.attempts
						.iter()
						.find(|a| Some(a.transaction.txid) == observations[batch].txid)
				} else {
					saved.attempts.last()
				}
				.ok_or_else(|| Error::Generic("Saved refund attempt is unavailable".into()))?;
				let reuse = !replacement_allowed
					|| confirmations.unwrap_or(0) > 0
					|| (attempt.fee_units == swap.secondary_fee_units
						&& attempt.address == *refund_address);
				(
					batch,
					attempt.inputs.clone(),
					saved.spends_carry,
					attempt.carry_output.is_some(),
					reuse.then(|| attempt.clone()),
				)
			}
			BtcRefundProgress::WaitingForFunding => {
				return Err(Error::Generic(
					"Waiting for recorded refund deposits to confirm".into(),
				))
			}
			BtcRefundProgress::Complete => return Err(Error::Generic(format!(
				"No further refund transaction is needed; {} uneconomic deposits remain unrefunded",
				plan.unrefunded.len()
			))),
		};
		let prepared = match reuse {
			Some(prepared) => prepared,
			None => {
				let carry = spends_carry.then(|| selected[0].clone());
				let original_inputs = &selected[usize::from(spends_carry)..];
				let assigned: std::collections::HashSet<_> =
					original_inputs.iter().map(|o| o.out_point).collect();
				let mut ordered = original_inputs.to_vec();
				// Only a carry output funds later batches. A direct payout's fee
				// replacement must not depend on newly confirmed deposits.
				if creates_carry {
					ordered.extend(
						plan.available(&outputs, tip)?
							.into_iter()
							.filter(|o| !assigned.contains(&o.out_point)),
					);
				}
				refund::check_remaining_fees(
					self.secondary_currency,
					&ordered,
					carry,
					original_inputs.len(),
					creates_carry,
					&destination,
					input_script,
					&carry_script,
					swap.secondary_fee_units,
					btc_lock_time,
				)?;
				let prepared = refund::build_batch(
					self.context_id,
					self.secondary_currency,
					refund_address,
					selected,
					spends_carry,
					creates_carry,
					input_script,
					&carry_script,
					swap.secondary_fee_units,
					btc_lock_time,
					&refund_key,
					secp,
				)?;
				if batch_index == plan.batches.len() {
					plan.pending.retain(|o| !assigned.contains(&o.out_point));
					plan.batches.push(BtcRefundBatch {
						spends_carry,
						attempts: Vec::new(),
						legacy_txid: None,
						last_broadcast_attempt: None,
					});
				}
				plan.batches[batch_index].attempts.push(prepared.clone());
				prepared
			}
		};
		plan.batches[batch_index].last_broadcast_attempt = Some(crate::swap::swap::get_cur_time());
		let transaction = prepared.transaction.clone();
		let data = swap.secondary_data.unwrap_btc_mut()?;
		data.refund_plan = Some(plan);
		data.refund_transaction = Some(prepared);
		Ok(transaction)
	}

	fn buyer_refund<K: Keychain>(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: &String,
		input_script: &Script,
		post_tx: bool,
	) -> Result<(), Error> {
		if !post_tx {
			self.buyer_build_refund_tx(
				secp,
				keychain,
				context,
				swap,
				refund_address,
				input_script,
			)?;
			return Ok(());
		}
		// Construction belongs to prepare_secondary_refund, followed by durable
		// storage in owner_swap. Never sign an unpersisted replacement while posting.
		let prepared = swap
			.secondary_data
			.unwrap_btc()?
			.refund_transaction
			.as_ref()
			.ok_or_else(|| {
				Error::Generic("Prepare and persist the refund before broadcasting".into())
			})?;
		let pinned = swap
			.secondary_data
			.unwrap_btc()?
			.refund_plan
			.as_ref()
			.is_some_and(|plan| {
				plan.batches
					.iter()
					.filter(|batch| batch.spends_carry)
					.any(|batch| {
						batch
							.attempts
							.first()
							.and_then(|attempt| attempt.inputs.first())
							.is_some_and(|input| {
								input.out_point.txid.to_byte_array()
									== prepared.transaction.txid.to_byte_array()
							})
					})
			});
		if !pinned
			&& (prepared.fee_units != swap.secondary_fee_units
				|| prepared.address != *refund_address)
		{
			return Err(Error::Generic(
				"Refund settings changed; prepare and persist the transaction before broadcasting"
					.into(),
			));
		}
		let refund_tx = prepared.transaction.clone();
		let fee_units = prepared.fee_units;
		let tx = refund_tx.tx.clone();
		// Release the first client guard before acquiring the fallback client;
		// an embedding caller may supply the same shared client for both slots.
		let primary_result = self.btc_node_client1.lock().post_tx(tx.clone());
		if let Err(primary_error) = primary_result {
			self.btc_node_client2.lock().post_tx(tx).map_err(|secondary_error| {
				Error::ElectrumNodeClient(format!(
					"Unable to post refund transaction through either node: primary error: {}; secondary error: {}",
					primary_error, secondary_error
				))
			})?;
		}

		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.refund_tx = Some(refund_tx.txid);
		btc_data.tx_fee_units = Some(fee_units);
		Ok(())
	}

	/// Find the confirmation height using the transaction's expected kernel.
	/// An all-zero excess is a valid placeholder in an unfinished local slate.
	/// For example, the buyer keeps its partially signed lock slate while the
	/// seller finalizes the kernel and broadcasts the transaction. The buyer's
	/// copy can therefore still have zero excess after the transaction confirms.
	/// Zero is not a valid finalized on-chain kernel excess. When `derive_kernel`
	/// is enabled, calculate the expected excess from the slate's inputs, outputs,
	/// fee, and offset regardless of the stored excess: the other party can supply
	/// a nonzero excess from an unrelated transaction. Derivation requires a
	/// non-compact slate so that the transaction body determines the excess.
	fn get_slate_confirmation_height(
		&self,
		secp: &Secp256k1,
		slate: &Slate,
		derive_kernel: bool,
		max_height: u64,
	) -> Result<Option<u64>, Error> {
		let tx = slate.tx_or_err()?;
		let Some(kernel) = tx.kernels().first() else {
			return Ok(None);
		};
		let excess = if derive_kernel {
			if tx.outputs().is_empty() {
				return Ok(None);
			}
			// calc_excess() uses participant public keys for compact slates,
			// which cannot establish that this transaction body was confirmed.
			if slate.compact_slate {
				return Err(Error::InvalidMessageData(
					"Swap confirmation requires a non-compact slate".to_string(),
				));
			}
			// The other party finalizes these slates, but their transaction bodies
			// already determine the expected kernel excess. An output match alone
			// could be seller change from a different transaction with no swap lock.
			slate.calc_excess(secp)?
		} else {
			if kernel.excess.0.iter().all(|byte| *byte == 0) {
				return Ok(None);
			}
			kernel.excess
		};
		match self
			.node_client
			.get_kernel(&excess, Some(slate.height), Some(max_height))?
		{
			Some((_tx_kernel, height, _mmr_index)) if height <= max_height => Ok(Some(height)),
			_ => Ok(None),
		}
	}

	fn confirmations_at_tip(
		tip_height: u64,
		output_height: Option<u64>,
	) -> Result<Option<u64>, Error> {
		output_height
			.map(|height| {
				tip_height
					.checked_sub(height)
					.and_then(|confirmations| confirmations.checked_add(1))
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"BtcSwapApi::confirmations_at_tip, confirmation count overflow, tip_height={} output_height={}",
							tip_height, height
						))
					})
			})
			.transpose()
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
	) -> Result<usize, Error> {
		match secondary_currency.is_btc_family() {
			true => Ok(4),
			_ => return Err(Error::UnexpectedCoinType),
		}
	}

	fn create_context(
		&mut self,
		secp: &mut Secp256k1,
		_keychain: &K,
		_ethereum_wallet: Option<&EthereumWallet>,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<SellerInput>>,
		change_amount: u64,
		keys: Vec<Identifier>,
		parent_key_id: Identifier,
	) -> Result<Context, Error> {
		match secondary_currency.is_btc_family() {
			true => (),
			_ => return Err(Error::UnexpectedCoinType),
		}

		let mut keys = keys.into_iter();

		let role_context = if is_seller {
			RoleContext::Seller(SellerContext {
				parent_key_id: parent_key_id,
				inputs: inputs.ok_or(Error::UnexpectedRole(
					"Fn create_context() for seller not found inputs".to_string(),
				))?,
				change_output: keys
					.next()
					.ok_or(Error::Generic("Not enough keys items".into()))?,
				change_amount,
				refund_output: keys
					.next()
					.ok_or(Error::Generic("Not enough keys items".into()))?,
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: keys
						.next()
						.ok_or(Error::Generic("Not enough keys items".into()))?,
				}),
			})
		} else {
			RoleContext::Buyer(BuyerContext {
				parent_key_id: parent_key_id,
				output: keys
					.next()
					.ok_or(Error::Generic("Not enough keys items".into()))?,
				redeem: keys
					.next()
					.ok_or(Error::Generic("Not enough keys items".into()))?,
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: keys
						.next()
						.ok_or(Error::Generic("Not enough keys items".into()))?,
				}),
			})
		};

		Ok(Context {
			multisig_key: keys
				.next()
				.ok_or(Error::Generic("Not enough keys items".into()))?,
			multisig_nonce: secp::aggsig::export_secnonce_single(secp)?, // generate_nonce operation
			lock_nonce: secp::aggsig::export_secnonce_single(secp)?,
			refund_nonce: secp::aggsig::export_secnonce_single(secp)?,
			redeem_nonce: secp::aggsig::export_secnonce_single(secp)?,
			role_context,
		})
	}

	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		secp: &mut Secp256k1,
		keychain: &K,
		context: &Context,
		mwc_anchor_height: u64,
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
		eth_swap_contract_address: Option<String>,
		erc20_swap_contract_address: Option<String>,
		eth_infura_project_id: Option<String>,
		_eth_redirect_out_wallet: Option<bool>,
		dry_run: bool,
		tag: Option<String>,
	) -> Result<Swap, Error> {
		// Checking if address is valid

		secondary_currency
			.validate_address(self.context_id, &secondary_redeem_address)
			.map_err(|e| {
				Error::Generic(format!(
					"Unable to parse secondary currency redeem address {}, {}",
					secondary_redeem_address, e
				))
			})?;

		match secondary_currency.is_btc_family() {
			true => (),
			_ => return Err(Error::UnexpectedCoinType),
		}

		let mut swap = SellApi::create_swap_offer(
			self.context_id,
			secp,
			keychain,
			context,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_redeem_address,
			mwc_anchor_height,
			seller_lock_first,
			mwc_confirmations,
			secondary_confirmations,
			message_exchange_time_sec,
			redeem_time_sec,
			communication_method,
			buyer_destination_address,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
			Some(false),
			dry_run,
			tag,
			self.node_client.as_ref(),
		)?;

		let btc_data = BtcData::new(secp, keychain, context.unwrap_seller()?.unwrap_btc()?)?;
		swap.secondary_data = btc_data.wrap();

		Ok(swap)
	}

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		Ok(SecondaryUpdate::BTC(btc_data.offer_update()))
	}

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		Ok(SecondaryUpdate::BTC(btc_data.accept_offer_update()?))
	}

	fn prepare_secondary_redeem(&self, swap: &mut Swap, secp: &Secp256k1) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"Only the seller accepts funding outputs".to_string(),
			));
		}
		let input_script = self.script(swap, secp)?;
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let addresses = btc_data.address(self.secondary_currency, &input_script, swap.network)?;
		let address = addresses.first().ok_or(Error::SecondaryDataIncomplete)?;
		let mut outputs = self.read_btc_with_fallback(|client| {
			let (mut outputs, tip) =
				read_unspent_and_tip(client, self.context_id, &self.secondary_currency, address)?;
			if let Some(accepted) = &btc_data.redeem_inputs {
				BtcData::validate_funding_outputs(accepted, swap.secondary_amount)?;
				// Revalidate the accepted outputs before resending the signature, but
				// never let unsolicited deposits change the input set or its limit.
				outputs.retain(|output| {
					accepted.iter().any(|input| {
						input.out_point == output.out_point && input.value == output.value
					})
				});
				if outputs.len() != accepted.len() {
					return Err(Error::Generic(
						"Accepted swap funding outputs are no longer available".to_string(),
					));
				}
			}
			BtcData::validate_funding_outputs(&outputs, swap.secondary_amount)?;
			if outputs.iter().any(|output| {
				secondary_confirmations_at_tip(tip, output.height)
					< swap.secondary_confirmations.max(1)
			}) {
				return Err(Error::Generic(
					"Swap funding outputs need more confirmations".to_string(),
				));
			}
			// listunspent includes immature mining rewards. Establish spendability
			// before authorizing MWC redemption, using the same backend throughout.
			validate_coinbase_maturity(client, self.secondary_currency, &outputs, tip)?;
			Ok(outputs)
		})?;
		// Before releasing the MWC redeem signature, ensure these exact inputs
		// can pay the configured redemption fee and leave a spendable output.
		// Recheck on retries too, since the seller can change the fee or address.
		let redeem_address = swap.unwrap_seller()?.0;
		let fee = BtcData::redeem_fee(
			self.context_id,
			&self.secondary_currency,
			&redeem_address,
			&input_script,
			swap.secondary_fee_units,
			&outputs,
		)?;
		let output_script = self
			.secondary_currency
			.address_2_script_pubkey(self.context_id, &redeem_address)?;
		BtcData::spend_lock_output_value(
			&self.secondary_currency,
			&output_script,
			swap.secondary_amount,
			fee,
		)?;
		outputs.sort_by(|left, right| {
			left.out_point
				.txid
				.cmp(&right.out_point.txid)
				.then_with(|| left.out_point.vout.cmp(&right.out_point.vout))
		});
		if btc_data.redeem_inputs.is_none() {
			swap.secondary_data.unwrap_btc_mut()?.redeem_inputs = Some(outputs);
		}
		Ok(())
	}

	fn publish_secondary_transaction(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		post_tx: bool,
	) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"publish_secondary_transaction called for buyer swap".to_string(),
			));
		}

		let input_script = self.script(swap, secp)?;

		let btc_tx = self.seller_build_redeem_tx(secp, keychain, swap, context, &input_script)?;

		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let had_attempts = !btc_data.redeem_attempts.is_empty();
		// Retain bytes before any RPC, including ambiguous broadcasts and import
		// reconstruction (post_tx=false). The owner saves them on success or error.
		if !btc_data
			.redeem_attempts
			.iter()
			.any(|attempt| attempt.txid == btc_tx.txid)
		{
			btc_data.redeem_attempts.push(btc_tx.clone());
		}
		if post_tx {
			let previously_recorded = btc_data.redeem_tx == Some(btc_tx.txid)
				|| btc_data.redeem_tx_candidates.contains(&btc_tx.txid);
			if !previously_recorded {
				// The owner persists the mutated swap on both success and error.
				// A failed response cannot establish that the node rejected the tx.
				btc_data.redeem_tx_candidates.push(btc_tx.txid);
			}
			let txid = Txid::from_byte_array(btc_tx.txid.to_byte_array());
			let already_known = previously_recorded
				&& self
					.read_btc_with_fallback(|client| client.transaction_confirmations(&txid))?
					.is_some();
			if !already_known {
				if had_attempts || previously_recorded {
					let recovered = self.read_btc_with_fallback(|client| {
						let found = recover_confirmed_variant(
							client,
							btc_data.redeem_attempts.iter(),
							"redemption",
						)?;
						let tip = client.height()?;
						Ok(found.is_some_and(|found| found.confirmations <= tip))
					})?;
					if recovered {
						// An earlier attempt may have paid a different fee. Do not
						// mark this unbroadcast replacement or its fee as successful.
						return Ok(());
					}
				}
				// Release the primary guard before taking the fallback guard; both
				// slots can refer to the same shared client.
				let primary_result = self.btc_node_client1.lock().post_tx(btc_tx.tx.clone());
				if let Err(primary_error) = primary_result {
					self.btc_node_client2
						.lock()
						.post_tx(btc_tx.tx)
						.map_err(|secondary_error| {
							Error::ElectrumNodeClient(format!(
								"Unable to post redeem transaction through either node: primary error: {}; secondary error: {}",
								primary_error, secondary_error
							))
						})?;
				}
			}
		}

		let secondary_fee_units = swap.secondary_fee_units;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if let Some(previous) = btc_data.redeem_tx.replace(btc_tx.txid) {
			if previous != btc_tx.txid && !btc_data.redeem_tx_candidates.contains(&previous) {
				btc_data.redeem_tx_candidates.push(previous);
			}
		}
		btc_data
			.redeem_tx_candidates
			.retain(|hash| *hash != btc_tx.txid);
		btc_data.tx_fee_units = Some(secondary_fee_units);
		Ok(())
	}

	/// Verify MWC confirmations independently of the secondary RPC service.
	fn request_mwc_tx_confirmations(
		&self,
		secp: &Secp256k1,
		_keychain: &K, // keychain is kept for Type. Compiler need to understand all types
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let session = NodeReadSession::start(&*self.node_client, "BTC swap confirmation poll")?;

		let is_seller = swap.is_seller();

		let mwc_lock_height = self.get_slate_confirmation_height(
			secp,
			&swap.lock_slate.slate,
			!is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "BTC swap lock confirmation")?;
		let mwc_redeem_height = self.get_slate_confirmation_height(
			secp,
			&swap.redeem_slate.slate,
			is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "BTC swap redeem confirmation")?;
		let mwc_refund_height = self.get_slate_confirmation_height(
			secp,
			&swap.refund_slate.slate,
			!is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "BTC swap refund confirmation")?;
		let final_tip = session.fresh_tip(&*self.node_client, "BTC swap confirmation poll")?;
		let mwc_lock_conf = Self::confirmations_at_tip(final_tip.height, mwc_lock_height)?;
		let mwc_redeem_conf = Self::confirmations_at_tip(final_tip.height, mwc_redeem_height)?;
		let mwc_refund_conf = Self::confirmations_at_tip(final_tip.height, mwc_refund_height)?;

		Ok(SwapTransactionsConfirmations::mwc_only(
			final_tip.height,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
		))
	}

	fn request_tx_confirmations(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let mwc = self.request_mwc_tx_confirmations(secp, keychain, swap)?;
		Ok(self
			.request_secondary_tx_confirmations(secp, keychain, swap)?
			.with_mwc(mwc))
	}

	fn request_secondary_tx_confirmations(
		&self,
		secp: &Secp256k1,
		_keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let is_seller = swap.is_seller();

		let btc_data = swap.secondary_data.unwrap_btc()?;
		let mut redeem_txs: Vec<_> = btc_data
			.redeem_tx
			.iter()
			.chain(btc_data.redeem_tx_candidates.iter())
			.chain(btc_data.redeem_attempts.iter().map(|attempt| &attempt.txid))
			.map(|hash| Txid::from_byte_array(hash.to_byte_array()))
			.collect();
		redeem_txs.sort_unstable();
		redeem_txs.dedup();
		let refund_tx = btc_data
			.refund_tx
			.as_ref()
			.map(|hash| Txid::from_byte_array(hash.to_byte_array()));
		let prepared_refund_tx = btc_data
			.refund_transaction
			.as_ref()
			.map(|refund| Txid::from_byte_array(refund.transaction.txid.to_byte_array()));

		// The lock address can only be derived once the buyer's redeem key is
		// known; before acceptance "no lock" is the correct observation. Any
		// other failure here (invalid timing, key, currency, or address data)
		// must propagate instead of reaching the state machine as an
		// unverified "not locked".
		let lock_address = if swap.redeem_public.is_some() {
			let input_script = self.script(swap, secp)?;
			let addresses =
				btc_data.address(swap.secondary_currency, &input_script, swap.network)?;
			Some(
				addresses
					.first()
					.ok_or(Error::SecondaryDataIncomplete)?
					.clone(),
			)
		} else {
			None
		};

		let (snapshot, refund_plan, mut refund_observations) =
			self.read_btc_with_fallback(|client| {
				let mut plan = btc_data.refund_plan.clone();
				let observations = match &mut plan {
					Some(plan) => plan.observe(client)?,
					None => Vec::new(),
				};
				let snapshot = read_confirmation_snapshot(
					client,
					self.context_id,
					&swap.secondary_currency,
					lock_address.as_ref(),
					&redeem_txs,
					&btc_data.redeem_attempts,
					refund_tx.as_ref(),
					prepared_refund_tx.as_ref(),
				)?;
				Ok((snapshot, plan, observations))
			})?;
		for observation in &mut refund_observations {
			if observation.confirmations.unwrap_or(0) > snapshot.tip {
				observation.confirmations = Some(0);
			}
		}
		let secondary_refund_progress = refund_plan
			.as_ref()
			.map(|plan| {
				plan.progress(
					&refund_observations,
					&snapshot.lock_outputs,
					snapshot.tip,
					swap.secondary_confirmations,
				)
			})
			.transpose()?;
		let BtcConfirmationSnapshot {
			tip: btc_tip,
			lock_outputs,
			redeem_confirmations: secondary_redeem_conf,
			refund_confirmations: mut secondary_refund_conf,
		} = snapshot;
		if let Some(progress) = &secondary_refund_progress {
			secondary_refund_conf = match progress {
				BtcRefundProgress::Pending { confirmations, .. } => *confirmations,
				BtcRefundProgress::Complete => refund_observations
					.iter()
					.filter_map(|o| o.confirmations)
					.min(),
				_ if !refund_observations.is_empty() => Some(0),
				_ => None,
			};
		}

		// BTC lock account...
		// Checking Amount, it can be too hight as well
		let mut secondary_lock_amount: u64 = 0;
		let mut least_confirmations = None;

		for output in lock_outputs {
			if is_seller {
				if let Some(accepted) = &btc_data.redeem_inputs {
					if !accepted.iter().any(|input| {
						input.out_point == output.out_point && input.value == output.value
					}) {
						continue;
					}
				}
			}
			secondary_lock_amount = secondary_lock_amount
				.checked_add(output.value)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"BtcSwapApi::request_tx_confirmations, secondary lock balance overflow, accumulated_amount={} output_value={}",
						secondary_lock_amount, output.value
					))
				})?;
			let confirmations = secondary_confirmations_at_tip(btc_tip, output.height);
			if least_confirmations
				.map(|least| confirmations < least)
				.unwrap_or(true)
			{
				least_confirmations = Some(confirmations);
			}
		}

		Ok(SwapTransactionsConfirmations {
			mwc_observed: false,
			secondary_observed: true,
			mwc_tip: 0,
			mwc_lock_conf: None,
			mwc_redeem_conf: None,
			mwc_refund_conf: None,
			secondary_tip: btc_tip,
			secondary_lock_conf: least_confirmations,
			secondary_lock_amount,
			secondary_redeem_conf,
			secondary_refund_conf,
			secondary_refund_progress,
		})
	}

	/// Check How much BTC coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		confirmations_needed: u64,
		secp: &Secp256k1,
	) -> Result<(u64, u64, u64), Error> {
		let input_script = self.script(swap, secp)?;

		let (pending_amount, confirmed_amount, least_confirmations, _outputs) =
			self.btc_balance(swap, &input_script, confirmations_needed)?;

		Ok((pending_amount, confirmed_amount, least_confirmations))
	}

	// Build state machine that match the swap data
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine<'_> {
		let kc = Arc::new(keychain.clone());
		let nc = self.node_client.clone();
		let b: Box<dyn SwapApi<K> + 'a> = Box::new((*self).clone());
		let swap_api = Arc::new(b);

		if swap.is_seller() {
			StateMachine::new(vec![
				Box::new(seller_swap::SellerOfferCreated::new()),
				Box::new(seller_swap::SellerSendingOffer::new(
					self.context_id,
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForAcceptanceMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerLock::new(
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerPostingLockMwcSlate::new(
					self.context_id,
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForLockConfirmations::new(
					self.context_id,
					kc.clone(),
					swap_api.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForInitRedeemMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerSendingInitRedeemMessage::new(
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerToRedeemMwc::new(
					nc.clone(),
				)),
				Box::new(seller_swap::SellerRedeemSecondaryCurrency::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForRedeemConfirmations::new(
					self.context_id,
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerSwapComplete::new()),
				Box::new(seller_swap::SellerWaitingForRefundHeight::new(nc.clone())),
				Box::new(seller_swap::SellerPostingRefundSlate::new(
					self.context_id,
					nc.clone(),
				)),
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
					self.context_id,
					kc.clone(),
					swap_api.clone(),
					nc.clone(),
				)),
				Box::new(buyer_swap::BuyerSendingInitRedeemMessage::new(
					self.context_id,
				)),
				Box::new(buyer_swap::BuyerWaitingForRespondRedeemMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(buyer_swap::BuyerRedeemMwc::new(self.context_id, nc.clone())),
				Box::new(buyer_swap::BuyerWaitForRedeemMwcConfirmations::new()),
				Box::new(buyer_swap::BuyerWaitingForMwcRefundConfirmations::new()),
				Box::new(buyer_swap::BuyerSwapComplete::new()),
				Box::new(buyer_swap::BuyerSwapFailed::new()),
				Box::new(buyer_swap::BuyerWaitingForRefundTime::new(swap_api.clone())),
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

	/// Get a secondary addresses for the lock account
	/// We can have several addresses because of different formats
	fn get_secondary_lock_address(
		&self,
		swap: &Swap,
		secp: &Secp256k1,
	) -> Result<Vec<String>, Error> {
		let input_script = self.script(swap, secp)?;
		let address = swap.secondary_data.unwrap_btc()?.address(
			swap.secondary_currency,
			&input_script,
			swap.network,
		)?;
		Ok(address)
	}

	/// Check if tx fee for the secondary is different from the posted
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, Error> {
		self.secondary_currency
			.validate_secondary_fee_units(swap.secondary_fee_units)?;
		Ok(swap.secondary_data.unwrap_btc()?.tx_fee_units != Some(swap.secondary_fee_units))
	}

	fn secondary_redeem_fee(
		&self,
		swap: &Swap,
		fee_units: SecondaryFeeUnits,
		secp: &Secp256k1,
	) -> Result<u64, Error> {
		let address = swap.unwrap_seller()?.0;
		let input_script = self.script(swap, secp)?;
		let inputs = swap
			.secondary_data
			.unwrap_btc()?
			.accepted_redeem_inputs(swap.secondary_amount)?;
		BtcData::redeem_fee(
			self.context_id,
			&self.secondary_currency,
			&address,
			&input_script,
			fee_units,
			inputs,
		)
	}

	fn secondary_redeem_minimum_output(&self, swap: &Swap) -> Result<u64, Error> {
		let address = swap.unwrap_seller()?.0;
		let output_script = self
			.secondary_currency
			.address_2_script_pubkey(self.context_id, &address)?;
		minimum_output(self.secondary_currency, &output_script)
	}

	fn prepare_secondary_refund(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
	) -> Result<(), Error> {
		let refund_address = swap
			.unwrap_buyer()?
			.ok_or(Error::Generic("Please define refund address".to_string()))?;
		swap.secondary_currency
			.validate_address(self.context_id, &refund_address)?;
		let input_script = self.script(swap, secp)?;
		self.buyer_build_refund_tx(
			secp,
			keychain,
			context,
			swap,
			&refund_address,
			&input_script,
		)?;
		Ok(())
	}

	/// Post BTC refund transaction
	fn post_secondary_refund_tx(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
		post_tx: bool,
	) -> Result<(), Error> {
		if swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"post_secondary_refund_tx called for seller swap".to_string(),
			));
		}

		let refund_address_str =
			refund_address.ok_or(Error::Generic("Please define refund address".to_string()))?;

		swap.secondary_currency
			.validate_address(self.context_id, &refund_address_str)?;

		let input_script = self.script(swap, secp)?;
		self.buyer_refund(
			secp,
			keychain,
			context,
			swap,
			&refund_address_str,
			&input_script,
			post_tx,
		)?;
		Ok(())
	}

	/// deposit secondary currecny to lock account.
	fn post_secondary_lock_tx(&self, _swap: &mut Swap) -> Result<(), Error> {
		Ok(())
	}

	/// transfer amount to dedicated address.
	fn transfer_scondary(&self, _swap: &mut Swap) -> Result<(), Error> {
		Ok(())
	}

	/// Validate clients. We want to be sure that the clients able to acceess the servers
	fn test_client_connections(&self) -> Result<(), Error> {
		{
			let mut c = self.btc_node_client1.lock();
			let name = c.name();
			let _ = c.height().map_err(|e| {
				Error::ElectrumNodeClient(format!(
					"Unable to contact the primary ElectrumX client {}, {}",
					name, e
				))
			})?;
		}
		{
			let mut c = self.btc_node_client2.lock();
			let name = c.name();
			let _ = c.height().map_err(|e| {
				Error::ElectrumNodeClient(format!(
					"Unable to contact the secondary ElectrumX client {}, {}",
					name, e
				))
			})?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::OutPoint;

	struct RecordingBtcClient {
		calls: Vec<&'static str>,
		tip: u64,
		outputs: Vec<Output>,
		coinbase: bool,
	}

	impl BtcNodeClient for RecordingBtcClient {
		fn name(&self) -> String {
			"recording-client".to_string()
		}

		fn height(&mut self) -> Result<u64, Error> {
			self.calls.push("height");
			Ok(self.tip)
		}

		fn unspent(
			&mut self,
			_context_id: u32,
			_currency: Currency,
			_address: &String,
		) -> Result<Vec<Output>, Error> {
			self.calls.push("unspent");
			Ok(self.outputs.clone())
		}

		fn post_tx(&mut self, _tx: Vec<u8>) -> Result<(), Error> {
			Ok(())
		}

		fn transaction(&mut self, _tx_hash: &Txid) -> Result<Option<u64>, Error> {
			panic!("the confirmation snapshot must use direct confirmation counts")
		}

		fn transaction_confirmations(&mut self, _tx_hash: &Txid) -> Result<Option<u64>, Error> {
			self.calls.push("transaction_confirmations");
			Ok(Some(101))
		}

		fn transaction_is_coinbase(&mut self, _tx_hash: &Txid) -> Result<bool, Error> {
			self.calls.push("coinbase");
			Ok(self.coinbase)
		}
	}

	#[test]
	fn secondary_snapshot_uses_one_client_and_reads_tip_last() {
		let lock_tx = Txid::from_byte_array([1; 32]);
		let redeem_tx = Txid::from_byte_array([2; 32]);
		let refund_tx = Txid::from_byte_array([3; 32]);
		let lock_address = "lock-address".to_string();
		let mut client = RecordingBtcClient {
			calls: Vec::new(),
			tip: 100,
			coinbase: false,
			outputs: vec![Output {
				out_point: OutPoint::new(lock_tx, 0),
				value: 5,
				height: 101,
			}],
		};

		let snapshot = read_confirmation_snapshot(
			&mut client,
			0,
			&Currency::Btc,
			Some(&lock_address),
			&[redeem_tx],
			&[],
			Some(&refund_tx),
			None,
		)
		.unwrap();

		assert_eq!(
			client.calls,
			vec![
				"transaction_confirmations",
				"transaction_confirmations",
				"unspent",
				"height"
			]
		);
		assert_eq!(snapshot.redeem_confirmations, Some(0));
		assert_eq!(snapshot.refund_confirmations, Some(0));
		assert_eq!(snapshot.lock_outputs.len(), 1);
		assert_eq!(
			secondary_confirmations_at_tip(snapshot.tip, snapshot.lock_outputs[0].height),
			0
		);
	}

	#[test]
	fn coinbase_maturity_uses_each_chain_boundary() {
		let outputs = vec![Output {
			out_point: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
			value: 100_000,
			height: 500_000,
		}];
		let mut client = RecordingBtcClient {
			calls: vec![],
			tip: 0,
			outputs: vec![],
			coinbase: true,
		};
		for (currency, maturity) in [
			(Currency::Btc, 100),
			(Currency::Bch, 100),
			(Currency::Ltc, 100),
			(Currency::Dash, 100),
			(Currency::ZCash, 100),
			(Currency::Doge, 240),
		] {
			for depth in [1, 6, maturity - 1, maturity, maturity + 1] {
				client.calls.clear();
				let result = validate_coinbase_maturity(
					&mut client,
					currency,
					&outputs,
					500_000 + depth - 1,
				);
				if depth < maturity {
					assert!(result
						.unwrap_err()
						.to_string()
						.contains("immature coinbase"));
					assert_eq!(client.calls, vec!["coinbase"]);
				} else {
					result.unwrap();
					assert!(client.calls.is_empty());
				}
			}
		}
	}
}
