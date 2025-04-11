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

//! Utilities to check the status of all the outputs we have stored in
//! the wallet storage and update them.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::error::Error;
use crate::internal::keys;
use crate::mwc_core::consensus::reward;
use crate::mwc_core::core::{Output, TxKernel};
use crate::mwc_core::global;
use crate::mwc_core::libtx::proof::ProofBuilder;
use crate::mwc_core::libtx::reward;
use crate::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::mwc_util as util;
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::secp::pedersen;
use crate::types::{
	NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend, WalletInfo,
};
use crate::{
	BlockFees, CbData, OutputCommitMapping, RetrieveTxQueryArgs, RetrieveTxQuerySortField,
	RetrieveTxQuerySortOrder,
};

use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
use num_bigint::BigInt;

/// Retrieve all of the outputs (doesn't attempt to update from node)
pub fn retrieve_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	show_spent: bool,
	tx: Option<&TxLogEntry>,
	parent_key_id: &Identifier,
	pagination_start: Option<u32>,
	pagination_len: Option<u32>,
) -> Result<Vec<OutputCommitMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// just read the wallet here, no need for a write lock
	let mut outputs = wallet
		.iter()
		.filter(|out| show_spent || out.status != OutputStatus::Spent)
		.collect::<Vec<_>>();

	let need_archived = match tx {
		Some(tx) => {
			let tip_height = wallet.w2n_client().get_chain_tip()?.0;
			let archive_height =
				Chain::height_2_archive_height(tip_height).saturating_sub(DAY_HEIGHT * 2);
			tx.output_height < archive_height
		}
		None => false,
	};

	if show_spent || need_archived {
		for out in wallet.archive_iter() {
			if out.status == OutputStatus::Spent {
				outputs.push(out);
			}
		}
	}

	// only include outputs with a given tx_id if provided
	if let Some(tx) = tx {
		let mut tx_commits: HashSet<String> = HashSet::new();

		tx_commits.extend(tx.input_commits.iter().map(|c| util::to_hex(&c.0)));
		tx_commits.extend(tx.output_commits.iter().map(|c| util::to_hex(&c.0)));

		outputs = outputs
			.into_iter()
			.filter(|out| {
				if tx_commits.is_empty() {
					out.tx_log_entry == Some(tx.id)
				} else {
					tx_commits.contains(&out.commit.clone().unwrap_or(String::from("?")))
				}
			})
			.collect::<Vec<_>>();
	}

	outputs = outputs
		.iter()
		.filter(|o| o.root_key_id == *parent_key_id)
		.cloned()
		.collect();

	outputs.sort_by_key(|out| out.n_child);
	let keychain = wallet.keychain(keychain_mask)?;

	// Key: tx_log id;  Value: true if active, false if cancelled
	let tx_log_is_active: HashMap<u32, bool> = wallet
		.tx_log_iter()
		.filter(|tx_log| tx_log.parent_key_id == *parent_key_id)
		.map(|tx_log| (tx_log.id, !tx_log.is_cancelled()))
		.collect();

	let mut res: Vec<OutputCommitMapping> = Vec::new();

	for out in outputs {
		// Filtering out Unconfirmed from cancelled (not active) transactions
		if (out.status == OutputStatus::Unconfirmed || out.status == OutputStatus::Reverted)
			&& !tx_log_is_active
				.get(&out.tx_log_entry.clone().unwrap_or(std::u32::MAX))
				.unwrap_or(&true)
		{
			continue;
		}

		let commit = match out.commit.clone() {
			Some(c) => pedersen::Commitment::from_vec(util::from_hex(&c).map_err(|e| {
				Error::GenericError(format!("Unable to parse HEX commit {}, {}", c, e))
			})?),
			None => keychain // TODO: proper support for different switch commitment schemes
				.commit(out.value, &out.key_id, SwitchCommitmentType::Regular)?,
		};
		res.push(OutputCommitMapping {
			output: out,
			commit,
		});
	}

	if pagination_len.is_some() || pagination_start.is_some() {
		let pag_len = pagination_len.unwrap_or(res.len() as u32);
		let pagination_start = pagination_start.unwrap_or(0);
		let mut pag_vec = Vec::new();

		let mut pre_count = 0;
		let mut count = 0;
		for n in res {
			if pre_count >= pagination_start {
				pag_vec.push(n);
				count = count + 1;
				if count == pag_len {
					break;
				}
			}
			pre_count = pre_count + 1;
		}
		Ok(pag_vec)
	} else {
		Ok(res)
	}
}

fn filter_tx_entry(tx_entry: &TxLogEntry, query_args: &RetrieveTxQueryArgs) -> bool {
	if query_args.exclude_cancelled.unwrap_or(false) {
		if tx_entry.tx_type == TxLogEntryType::TxReceivedCancelled
			|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
		{
			return false;
		}
	}

	if query_args.include_outstanding_only.unwrap_or(false) {
		if tx_entry.confirmed {
			return false;
		}
	}

	if query_args.include_confirmed_only.unwrap_or(false) {
		if !tx_entry.confirmed {
			return false;
		}
	}

	if query_args.include_sent_only.unwrap_or(false) {
		if !(tx_entry.tx_type == TxLogEntryType::TxSent
			|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled)
		{
			return false;
		}
	}

	if query_args.include_received_only.unwrap_or(false) {
		if !(tx_entry.tx_type == TxLogEntryType::TxReceived
			|| tx_entry.tx_type == TxLogEntryType::TxReceivedCancelled)
		{
			return false;
		}
	}

	if query_args.include_coinbase_only.unwrap_or(false) {
		if tx_entry.tx_type != TxLogEntryType::ConfirmedCoinbase {
			return false;
		}
	}

	if query_args.include_reverted_only.unwrap_or(false) {
		if tx_entry.tx_type != TxLogEntryType::TxReverted {
			return false;
		}
	}

	if tx_entry.id < query_args.min_id.unwrap_or(0) {
		return false;
	}
	if tx_entry.id > query_args.max_id.unwrap_or(u32::MAX) {
		return false;
	}

	if let Some(v) = query_args.min_amount {
		if tx_entry.tx_type == TxLogEntryType::TxSent
			|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
		{
			if BigInt::from(tx_entry.amount_debited) - BigInt::from(tx_entry.amount_credited)
				< BigInt::from(v)
			{
				return false;
			}
		} else {
			if BigInt::from(tx_entry.amount_credited) - BigInt::from(tx_entry.amount_debited)
				< BigInt::from(v)
			{
				return false;
			}
		}
	}

	if let Some(v) = query_args.max_amount {
		if tx_entry.tx_type == TxLogEntryType::TxSent
			|| tx_entry.tx_type == TxLogEntryType::TxSentCancelled
		{
			if BigInt::from(tx_entry.amount_debited) - BigInt::from(tx_entry.amount_credited)
				> BigInt::from(v)
			{
				return false;
			}
		} else {
			if BigInt::from(tx_entry.amount_credited) - BigInt::from(tx_entry.amount_debited)
				> BigInt::from(v)
			{
				return false;
			}
		}
	}

	if let Some(v) = query_args.min_creation_timestamp {
		if tx_entry.creation_ts < v {
			return false;
		}
	}

	if let Some(v) = query_args.max_creation_timestamp {
		if tx_entry.creation_ts > v {
			return false;
		}
	}

	if let Some(v) = query_args.min_confirmed_timestamp {
		if let Some(t) = tx_entry.confirmation_ts {
			if t < v {
				return false;
			}
		}
	}

	if let Some(v) = query_args.max_confirmed_timestamp {
		if let Some(t) = tx_entry.confirmation_ts {
			if t > v {
				return false;
			}
		}
	}

	true
}

/// Apply advanced filtering to resultset from retrieve_txs below
pub fn apply_advanced_tx_list_filtering<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	query_args: &RetrieveTxQueryArgs,
	height_limit: u64,
) -> Vec<TxLogEntry>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut return_txs: Vec<TxLogEntry> = Vec::new();
	// Apply simple bool, GTE or LTE fields
	for tx in wallet.tx_log_iter() {
		if filter_tx_entry(&tx, query_args) {
			return_txs.push(tx);
		}
	}

	if height_limit > 0 {
		for tx in wallet.tx_log_archive_iter() {
			if filter_tx_entry(&tx, query_args) {
				return_txs.push(tx);
			}
		}

		return_txs.retain(|tx| {
			tx.output_height >= height_limit || (!tx.confirmed && !tx.is_cancelled_reverted())
		});
	}

	// Now apply requested sorting
	if let Some(ref s) = query_args.sort_field {
		match s {
			RetrieveTxQuerySortField::Id => {
				return_txs.sort_by_key(|tx| tx.id);
			}
			RetrieveTxQuerySortField::CreationTimestamp => {
				return_txs.sort_by_key(|tx| tx.creation_ts);
			}
			RetrieveTxQuerySortField::ConfirmationTimestamp => {
				return_txs.sort_by_key(|tx| tx.confirmation_ts);
			}
			RetrieveTxQuerySortField::TotalAmount => {
				return_txs.sort_by_key(|tx| {
					if tx.tx_type == TxLogEntryType::TxSent
						|| tx.tx_type == TxLogEntryType::TxSentCancelled
					{
						BigInt::from(tx.amount_debited) - BigInt::from(tx.amount_credited)
					} else {
						BigInt::from(tx.amount_credited) - BigInt::from(tx.amount_debited)
					}
				});
			}
			RetrieveTxQuerySortField::AmountCredited => {
				return_txs.sort_by_key(|tx| tx.amount_credited);
			}
			RetrieveTxQuerySortField::AmountDebited => {
				return_txs.sort_by_key(|tx| tx.amount_debited);
			}
		}
	} else {
		return_txs.sort_by_key(|tx| tx.id);
	}

	if let Some(ref s) = query_args.sort_order {
		match s {
			RetrieveTxQuerySortOrder::Desc => return_txs.reverse(),
			_ => {}
		}
	}

	// Apply limit if requested
	if let Some(l) = query_args.limit {
		return_txs = return_txs.into_iter().take(l as usize).collect()
	}

	return_txs
}

fn filter_tx_entry2(
	tx_entry: &TxLogEntry,
	parent_key_id: Option<&Identifier>,
	tx_id: Option<u32>,
	tx_slate_id: &Option<Uuid>,
	outstanding_only: bool,
) -> bool {
	let f_pk = match parent_key_id {
		Some(k) => tx_entry.parent_key_id == *k,
		None => true,
	};
	let f_tx_id = match tx_id {
		Some(i) => tx_entry.id == i,
		None => true,
	};
	let f_txs = match tx_slate_id {
		Some(t) => tx_entry.tx_slate_id == Some(*t),
		None => true,
	};
	let f_outstanding = match outstanding_only {
		true => {
			!tx_entry.confirmed
				&& (tx_entry.tx_type == TxLogEntryType::TxReceived
					|| tx_entry.tx_type == TxLogEntryType::TxSent
					|| tx_entry.tx_type == TxLogEntryType::TxReverted)
		}
		false => true,
	};
	// Miners doesn't like the fact that CoinBase tx can be unconfirmed. That is we are hiding them for Rest API and for UI
	let non_confirmed_coinbase =
		!tx_entry.confirmed && (tx_entry.tx_type == TxLogEntryType::ConfirmedCoinbase);

	f_pk && f_tx_id && f_txs && f_outstanding && !non_confirmed_coinbase
}

/// Retrieve all of the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key
pub fn retrieve_txs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	_keychain_mask: Option<&SecretKey>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	query_args: Option<RetrieveTxQueryArgs>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
	pagination_start: Option<u32>,
	pagination_len: Option<u32>,
	show_last_four_days: Option<bool>,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut txs;

	let show_last_four_days = show_last_four_days.unwrap_or(false);
	let height_limit = if show_last_four_days {
		wallet
			.w2n_client()
			.get_chain_tip()?
			.0
			.saturating_sub(4 * DAY_HEIGHT)
	} else {
		0
	};

	// Adding in new transaction list query logic. If `tx_id` or `tx_slate_id`
	// is provided, then `query_args` is ignored and old logic is followed.
	if query_args.is_some() && tx_id.is_none() && tx_slate_id.is_none() {
		txs = apply_advanced_tx_list_filtering(wallet, &query_args.unwrap(), height_limit)
	} else {
		txs = wallet
			.tx_log_iter()
			.filter(|tx_entry| {
				filter_tx_entry2(
					tx_entry,
					parent_key_id,
					tx_id,
					&tx_slate_id,
					outstanding_only,
				)
			})
			.collect();

		if !(((tx_id.is_some() || tx_slate_id.is_some()) && !txs.is_empty()) || height_limit > 0) {
			for tx_entry in wallet.tx_log_archive_iter() {
				if filter_tx_entry2(
					&tx_entry,
					parent_key_id,
					tx_id,
					&tx_slate_id,
					outstanding_only,
				) {
					txs.push(tx_entry)
				}
			}
		}

		if height_limit > 0 {
			txs.retain(|tx| {
				tx.output_height >= height_limit || (!tx.confirmed && !tx.is_cancelled_reverted())
			})
		}

		txs.sort_by_key(|tx| tx.creation_ts);
	}

	if pagination_start.is_some() || pagination_len.is_some() {
		let pag_len = pagination_len.unwrap_or(txs.len() as u32);
		let mut pag_txs: Vec<TxLogEntry> = Vec::new();

		let mut pre_count = 0;
		let mut count = 0;

		let pagination_start = pagination_start.unwrap_or(0);

		for tx in txs {
			if pre_count >= pagination_start {
				pag_txs.push(tx);
				count = count + 1;
				if count == pag_len {
					break;
				}
			}
			pre_count = pre_count + 1;
		}
		Ok(pag_txs)
	} else {
		Ok(txs)
	}
}

/// Cancel transaction and associated outputs
pub fn cancel_tx_and_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	mut tx: TxLogEntry,
	outputs: Vec<OutputData>,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut batch = wallet.batch(keychain_mask)?;

	for mut o in outputs {
		// unlock locked outputs
		//if o.status == OutputStatus::Unconfirmed || o.status == OutputStatus::Reverted {   WMC don't delete outputs, we want to keep them mapped to cancelled trasactions
		//	batch.delete(&o.key_id, &o.mmr_index)?;
		//}
		if o.status == OutputStatus::Locked {
			o.status = OutputStatus::Unspent;
			batch.save(o)?;
		} else if o.status == OutputStatus::Reverted {
			o.status = OutputStatus::Unconfirmed;
			batch.save(o)?;
		}
	}
	match tx.tx_type {
		TxLogEntryType::TxSent => tx.tx_type = TxLogEntryType::TxSentCancelled,
		TxLogEntryType::TxReceived | TxLogEntryType::TxReverted => {
			tx.tx_type = TxLogEntryType::TxReceivedCancelled
		}
		_ => {}
	}

	if let Some(slate_id) = &tx.tx_slate_id {
		if let Err(e) = batch.delete_private_context(slate_id.as_bytes(), 0) {
			if !e.to_string().contains("MDB_NOTFOUND") {
				return Err(e);
			}
		}
		if let Err(e) = batch.delete_private_context(slate_id.as_bytes(), 1) {
			if !e.to_string().contains("MDB_NOTFOUND") {
				return Err(e);
			}
		}
	}

	batch.save_tx_log_entry(tx, parent_key_id)?;
	batch.commit()?;
	Ok(())
}

/// Retrieve summary info about the wallet
/// caller should refresh first if desired
pub fn retrieve_info<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: &Identifier,
	minimum_confirmations: u64,
) -> Result<WalletInfo, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let current_height = wallet.last_confirmed_height()?;
	println!("updater: the current_height is {}", current_height);
	let outputs = wallet
		.iter()
		.filter(|out| out.root_key_id == *parent_key_id);

	// Key: tx_log id;  Value: true if active, false if cancelled
	let tx_log_cancellation_status: HashMap<u32, bool> = wallet
		.tx_log_iter()
		.filter(|tx_log| tx_log.parent_key_id == *parent_key_id)
		.map(|tx_log| (tx_log.id, !tx_log.is_cancelled()))
		.collect();

	let mut unspent_total = 0;
	let mut immature_total = 0;
	let mut awaiting_finalization_total = 0;
	let mut unconfirmed_total = 0;
	let mut locked_total = 0;
	let mut reverted_total = 0;

	for out in outputs {
		match out.status {
			OutputStatus::Unspent => {
				if out.is_coinbase && out.lock_height > current_height {
					immature_total += out.value;
				} else if out.num_confirmations(current_height) < minimum_confirmations {
					// Treat anything less than minimum confirmations as "unconfirmed".
					unconfirmed_total += out.value;
				} else {
					unspent_total += out.value;
				}
			}
			OutputStatus::Unconfirmed => {
				// We ignore unconfirmed coinbase outputs completely.
				if let Some(tx_log_id) = out.tx_log_entry {
					if !tx_log_cancellation_status.get(&tx_log_id).unwrap_or(&true) {
						continue;
					}
				}

				if !out.is_coinbase {
					if minimum_confirmations == 0 {
						unconfirmed_total += out.value;
					} else {
						awaiting_finalization_total += out.value;
					}
				}
			}
			OutputStatus::Locked => {
				locked_total += out.value;
			}
			OutputStatus::Reverted => reverted_total += out.value,
			OutputStatus::Spent => {}
		}
	}

	Ok(WalletInfo {
		last_confirmed_height: current_height,
		minimum_confirmations,
		total: unspent_total + unconfirmed_total + immature_total,
		amount_awaiting_finalization: awaiting_finalization_total,
		amount_awaiting_confirmation: unconfirmed_total,
		amount_immature: immature_total,
		amount_locked: locked_total,
		amount_currently_spendable: unspent_total,
		amount_reverted: reverted_total,
	})
}

/// Build a coinbase output and insert into wallet
pub fn build_coinbase<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (out, kern, block_fees) = receive_coinbase(wallet, keychain_mask, block_fees, test_mode)?;

	Ok(CbData {
		output: out,
		kernel: kern,
		key_id: block_fees.key_id,
	})
}

//TODO: Split up the output creation and the wallet insertion
/// Build a coinbase output and the corresponding kernel
pub fn receive_coinbase<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<(Output, TxKernel, BlockFees), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let height = block_fees.height;
	let lock_height = height + global::coinbase_maturity();
	let key_id = block_fees.key_id();
	let parent_key_id = wallet.parent_key_id();

	let key_id = match key_id {
		Some(key_id) => match keys::retrieve_existing_key(wallet, key_id, None) {
			Ok(k) => k.0,
			Err(_) => keys::next_available_key(wallet, None)?,
		},
		None => keys::next_available_key(wallet, None)?,
	};

	{
		// Now acquire the wallet lock and write the new output.
		let amount = reward(block_fees.fees, height);
		let commit = wallet.calc_commit_for_cache(keychain_mask, amount, &key_id)?;
		let mut batch = wallet.batch(keychain_mask)?;
		batch.save(OutputData {
			root_key_id: parent_key_id,
			key_id: key_id.clone(),
			n_child: key_id.to_path().last_path_index(),
			mmr_index: None,
			commit: commit,
			value: amount,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: lock_height,
			is_coinbase: true,
			tx_log_entry: None,
		})?;
		batch.commit()?;
	}

	debug!(
		"receive_coinbase: built candidate output - {:?}, {}",
		key_id.clone(),
		key_id,
	);

	let mut block_fees = block_fees.clone();
	block_fees.key_id = Some(key_id.clone());

	debug!("receive_coinbase: {:?}", block_fees);

	let keychain = wallet.keychain(keychain_mask)?;
	let (out, kern) = reward::output(
		&keychain,
		&ProofBuilder::new(&keychain),
		&key_id,
		block_fees.fees,
		test_mode,
		height,
		keychain.secp(),
	)?;
	Ok((out, kern, block_fees))
}
