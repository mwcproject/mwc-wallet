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

use mwc_wallet_util::mwc_crates::uuid::Uuid;
use std::collections::{HashMap, HashSet};

use crate::error::Error;
use crate::internal::keys;
use crate::types::{
	NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend, WalletInfo,
	WalletOutputBatch,
};
use crate::{
	BlockFees, CbData, OutputCommitMapping, RetrieveTxQueryArgs, RetrieveTxQuerySortField,
	RetrieveTxQuerySortOrder,
};
use mwc_wallet_util::mwc_core::consensus::reward;
use mwc_wallet_util::mwc_core::core::hash::Hash;
use mwc_wallet_util::mwc_core::core::{Output, TxKernel};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::libtx::proof::ProofBuilder;
use mwc_wallet_util::mwc_core::libtx::reward;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::secp::s2c::Opening;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util;

use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
use mwc_wallet_util::mwc_crates::chrono::{DateTime, Duration, Utc};
use mwc_wallet_util::mwc_crates::log::{debug, warn};
use mwc_wallet_util::mwc_crates::num_bigint::BigInt;
use mwc_wallet_util::mwc_util::ToHex;

fn should_include_archived_output(
	status: &OutputStatus,
	show_spent: bool,
	need_archived: bool,
) -> bool {
	(show_spent && *status == OutputStatus::Spent)
		|| (need_archived && *status != OutputStatus::Spent)
}

fn validate_pagination_len(operation: &str, pagination_len: Option<u32>) -> Result<(), Error> {
	if pagination_len == Some(0) {
		return Err(Error::GenericError(format!(
			"{}, pagination_len must be greater than zero",
			operation
		)));
	}
	Ok(())
}

/// Retrieve all of the outputs (doesn't attempt to update from node).
/// A supplied pagination length must be greater than zero.
pub fn retrieve_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
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
	validate_pagination_len("updater::retrieve_outputs", pagination_len)?;

	// just read the wallet here, no need for a write lock
	let mut outputs = wallet
		.iter()?
		.filter(|out| show_spent || out.status != OutputStatus::Spent)
		.collect::<Vec<_>>();

	// Transaction history can refer to outputs already moved into the local
	// archive. The owner API permits retrieval with `refresh_from_node = false`,
	// so this lookup must remain local and work while the node is unavailable.
	// A live node tip is also not authoritative for records the wallet moved into
	// its archive during an earlier refresh; confirmation heights are supplied by
	// the caller's refresh anchor instead.
	let need_archived = tx.is_some();

	if show_spent || need_archived {
		for out in wallet.archive_iter()? {
			if should_include_archived_output(&out.status, show_spent, need_archived) {
				outputs.push(out);
			}
		}
	}

	let keychain = wallet.keychain(secp, keychain_mask)?;

	// only include outputs with a given tx_id if provided
	if let Some(tx) = tx {
		let mut tx_commits: HashSet<String> = HashSet::new();

		tx_commits.extend(tx.input_commits.iter().map(|c| mwc_util::to_hex(&c.0)));
		tx_commits.extend(tx.output_commits.iter().map(|c| mwc_util::to_hex(&c.0)));

		outputs = {
			let mut filtered = Vec::with_capacity(outputs.len());
			for out in outputs {
				// The tx_log_entry association is authoritative for outputs this
				// wallet created or locked for the transaction.
				if out.tx_log_entry == Some(tx.id) {
					filtered.push(out);
					continue;
				}
				if tx_commits.is_empty() {
					continue;
				}
				let commit_hex = match &out.commit {
					Some(c) => c.clone(),
					// Outputs persisted without a cached commit (legacy or
					// restored wallets) are matched by their derived commitment.
					None => mwc_util::to_hex(
						&keychain
							.commit(secp, out.value, &out.key_id, SwitchCommitmentType::Regular)?
							.0,
					),
				};
				if tx_commits.contains(&commit_hex) {
					filtered.push(out);
				}
			}
			filtered
		};
	}

	outputs = outputs
		.iter()
		.filter(|o| o.root_key_id == *parent_key_id)
		.cloned()
		.collect();

	outputs.sort_by_key(|out| out.n_child);

	// Key: tx_log id;  Value: true if active, false if cancelled
	let tx_log_is_active: HashMap<u32, bool> = wallet
		.tx_log_iter()?
		.filter(|tx_log| tx_log.parent_key_id == *parent_key_id)
		.map(|tx_log| (tx_log.id, !tx_log.is_cancelled()))
		.collect();

	let mut res: Vec<OutputCommitMapping> = Vec::new();

	for out in outputs {
		// Filtering out Unconfirmed from cancelled (not active) transactions
		if (out.status == OutputStatus::Unconfirmed || out.status == OutputStatus::Reverted)
			&& !tx_log_is_active
				.get(&out.tx_log_entry.clone().unwrap_or(u32::MAX))
				.unwrap_or(&true)
		{
			continue;
		}

		let commit = match out.commit.clone() {
			Some(c) => pedersen::Commitment::from_vec(mwc_util::from_hex(&c).map_err(|e| {
				Error::GenericError(format!("Unable to parse HEX commit {}, {}", c, e))
			})?)?,
			None => keychain // TODO: proper support for different switch commitment schemes
				.commit(secp, out.value, &out.key_id, SwitchCommitmentType::Regular)?,
		};
		res.push(OutputCommitMapping {
			output: out,
			commit,
		});
	}

	if pagination_len.is_some() || pagination_start.is_some() {
		let default_len = u32::try_from(res.len()).map_err(|_| {
			Error::DataOverflow(format!(
				"updater::retrieve_outputs, output result count exceeds u32 pagination limit, result_len={}",
				res.len()
			))
		})?;
		let pag_len = pagination_len.unwrap_or(default_len);
		let pagination_start = pagination_start.unwrap_or(0);
		let mut pag_vec = Vec::new();

		let mut pre_count: u32 = 0;
		let mut count: u32 = 0;
		for n in res {
			if pre_count >= pagination_start {
				pag_vec.push(n);
				// res.len() was proven to fit u32, so the counter cannot overflow.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the source Vec length was converted to u32 successfully"
				)]
				{
					count += 1;
				}
				if count == pag_len {
					break;
				}
			}
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the source Vec length was converted to u32 successfully"
			)]
			{
				pre_count += 1;
			}
		}
		Ok(pag_vec)
	} else {
		Ok(res)
	}
}

#[allow(
	clippy::arithmetic_side_effects,
	reason = "transaction amount differences use arbitrary-precision BigInt and cannot integer-overflow"
)]
fn filter_tx_entry(
	tx_entry: &TxLogEntry,
	query_args: &RetrieveTxQueryArgs,
	parent_key_id: Option<&Identifier>,
) -> bool {
	if let Some(parent_key_id) = parent_key_id {
		if tx_entry.parent_key_id != *parent_key_id {
			return false;
		}
	}

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

fn filter_recent_txs(
	txs: &mut Vec<TxLogEntry>,
	height_limit: u64,
	reference_time: DateTime<Utc>,
) -> Result<(), Error> {
	let creation_cutoff = reference_time
		.checked_sub_signed(Duration::days(4))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"updater::filter_recent_txs, creation cutoff overflow, reference_time={}",
				reference_time
			))
		})?;

	// Cancelled transactions usually have no confirmation height. Use their
	// creation time, while keeping outstanding transactions visible at any age.
	txs.retain(|tx| {
		tx.output_height >= height_limit
			|| (!tx.confirmed && !tx.is_cancelled_reverted())
			|| (tx.output_height == 0 && tx.creation_ts >= creation_cutoff)
	});
	Ok(())
}

/// Apply advanced filtering to resultset from retrieve_txs below
pub fn apply_advanced_tx_list_filtering<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	query_args: &RetrieveTxQueryArgs,
	height_limit: u64,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	apply_advanced_tx_list_filtering_for_parent(wallet, query_args, None, height_limit)
}

#[allow(
	clippy::arithmetic_side_effects,
	reason = "transaction amount sort keys use arbitrary-precision BigInt and cannot integer-overflow"
)]
fn apply_advanced_tx_list_filtering_for_parent<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	query_args: &RetrieveTxQueryArgs,
	parent_key_id: Option<&Identifier>,
	height_limit: u64,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut return_txs: Vec<TxLogEntry> = Vec::new();
	// Apply simple bool, GTE or LTE fields
	for tx in wallet.tx_log_iter()? {
		if filter_tx_entry(&tx, query_args, parent_key_id) {
			return_txs.push(tx);
		}
	}

	if height_limit == 0 {
		for tx in wallet.tx_log_archive_iter()? {
			if filter_tx_entry(&tx, query_args, parent_key_id) {
				return_txs.push(tx);
			}
		}
	} else {
		filter_recent_txs(&mut return_txs, height_limit, Utc::now())?;
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

	Ok(return_txs)
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

/// Retrieve matching entries from the active transaction-log namespace only.
/// Callers which also need historical records should use [`retrieve_txs`],
/// which can fall back to the archive when no active exact match exists.
pub(super) fn retrieve_txs_from_active_log<'a, T: ?Sized, C, K>(
	wallet: &T,
	tx_id: Option<u32>,
	tx_slate_id: &Option<Uuid>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	Ok(wallet
		.tx_log_iter()?
		.filter(|tx_entry| {
			filter_tx_entry2(
				tx_entry,
				parent_key_id,
				tx_id,
				tx_slate_id,
				outstanding_only,
			)
		})
		.collect())
}

/// Retrieve all of the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key.
///
/// `filter_tip_height` enables the "last four days" display filter when `Some`:
/// entries with a confirmation height below `filter_tip_height - 4 * DAY_HEIGHT`
/// are omitted, except outstanding transactions, which remain visible at any age.
/// Entries without a confirmation height, including cancelled/reverted entries,
/// are included when created within the last four days. This uses creation time,
/// not cancellation time. Such entries are only archived after five days, so the
/// recent listing can omit the archive. A chain younger than four days keeps all
/// entries, as does a disabled filter.
/// The filter is a coarse display convenience (listing recent transactions,
/// e.g. for backup review), not an exact time window, so the reference height
/// does not need to be exact or freshly validated:
/// - A reference height behind the real tip only moves the cutoff down, so the
///   listing over-includes old entries. That is harmless for a display filter.
/// - A reference height `D` blocks ahead hides confirmed transactions within
///   `D` blocks of the four-day boundary. A one-block extension only affects
///   an entry exactly at the boundary, which is immaterial here; hiding
///   transactions the view is meant to show requires `D` on the order of days.
/// Callers holding a validated chain anchor should pass it; an independent,
/// unvalidated tip sample is equally acceptable given the tolerance above.
/// A supplied pagination length must be greater than zero.
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
	filter_tip_height: Option<u64>,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_pagination_len("updater::retrieve_txs", pagination_len)?;

	let mut txs;

	let height_limit = match filter_tip_height {
		// A chain younger than four days intentionally clamps the display floor to genesis.
		Some(tip) => tip.saturating_sub(4 * DAY_HEIGHT),
		None => 0,
	};

	// Adding in new transaction list query logic. If `tx_id` or `tx_slate_id`
	// is provided, then `query_args` is ignored and old logic is followed.
	if let Some(query_args) = query_args
		.as_ref()
		.filter(|_| tx_id.is_none() && tx_slate_id.is_none())
	{
		txs = apply_advanced_tx_list_filtering_for_parent(
			wallet,
			query_args,
			parent_key_id,
			height_limit,
		)?
	} else {
		txs = retrieve_txs_from_active_log(
			wallet,
			tx_id,
			&tx_slate_id,
			parent_key_id,
			outstanding_only,
		)?;

		if !(((tx_id.is_some() || tx_slate_id.is_some()) && !txs.is_empty()) || height_limit > 0) {
			for tx_entry in wallet.tx_log_archive_iter()? {
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
			filter_recent_txs(&mut txs, height_limit, Utc::now())?;
		}

		txs.sort_by_key(|tx| tx.creation_ts);
	}

	if pagination_start.is_some() || pagination_len.is_some() {
		let default_len = u32::try_from(txs.len()).map_err(|_| {
			Error::DataOverflow(format!(
				"updater::retrieve_txs, transaction result count exceeds u32 pagination limit, result_len={}",
				txs.len()
			))
		})?;
		let pag_len = pagination_len.unwrap_or(default_len);
		let mut pag_txs: Vec<TxLogEntry> = Vec::new();

		let mut pre_count: u32 = 0;
		let mut count: u32 = 0;

		let pagination_start = pagination_start.unwrap_or(0);

		for tx in txs {
			if pre_count >= pagination_start {
				pag_txs.push(tx);
				// txs.len() was proven to fit u32, so the counter cannot overflow.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the source Vec length was converted to u32 successfully"
				)]
				{
					count += 1;
				}
				if count == pag_len {
					break;
				}
			}
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the source Vec length was converted to u32 successfully"
			)]
			{
				pre_count += 1;
			}
		}
		Ok(pag_txs)
	} else {
		Ok(txs)
	}
}

/// Stage a transaction cancellation and its associated output changes.
/// The caller owns the batch and commits after all related entries are staged.
pub fn cancel_tx_and_outputs<K>(
	batch: &mut dyn WalletOutputBatch<K>,
	mut tx: TxLogEntry,
	outputs: Vec<OutputData>,
	parent_key_id: &Identifier,
) -> Result<(), Error>
where
	K: Keychain,
{
	for mut o in outputs {
		// unlock locked outputs
		//if o.status == OutputStatus::Unconfirmed || o.status == OutputStatus::Reverted {   WMC don't delete outputs, we want to keep them mapped to cancelled trasactions
		//	batch.delete(&o.key_id, &o.mmr_index)?;
		//}
		let owned_by_cancelled_tx =
			o.root_key_id == *parent_key_id && o.tx_log_entry == Some(tx.id);
		if o.status == OutputStatus::Locked {
			// An output can match this transaction through historical commitment
			// metadata even after a newer transaction has taken ownership of its lock.
			// Only the transaction recorded as the current, account-scoped lock owner
			// may release it. When cancelling a slate group, the owning member will
			// process and unlock the output itself.
			if !owned_by_cancelled_tx {
				continue;
			}
			o.status = OutputStatus::Unspent;
			batch.save(o)?;
		} else if o.status == OutputStatus::Reverted {
			// Commitment history can also match a reverted output currently owned by
			// another transaction. Do not make that output appear unconfirmed for the
			// transaction being cancelled.
			if !owned_by_cancelled_tx {
				continue;
			}
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
		for participant_id in [0, 1] {
			match batch.delete_private_context(slate_id.as_bytes(), participant_id) {
				Ok(()) | Err(Error::PrivateContextNotFound(_)) => {}
				Err(e) => return Err(e),
			}
		}
	}

	batch.save_tx_log_entry(tx, parent_key_id)?;
	Ok(())
}

/// Check a caller-supplied manual lock, deriving legacy uncached commitments when needed.
fn is_output_manually_locked<F>(
	out: &OutputData,
	manually_locked_outputs: &HashSet<String>,
	derive_commit: F,
) -> Result<bool, Error>
where
	F: FnOnce(&OutputData) -> Result<String, Error>,
{
	if manually_locked_outputs.is_empty() {
		return Ok(false);
	}

	match &out.commit {
		Some(commit) => Ok(manually_locked_outputs.contains(commit)),
		// Legacy and restored outputs may not have a cached commitment. Derive it
		// instead of conflating the missing value with a caller-supplied empty string.
		None => Ok(manually_locked_outputs.contains(&derive_commit(out)?)),
	}
}

/// Retrieve summary info about the wallet
/// caller should refresh first if desired
pub fn retrieve_info<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	minimum_confirmations: u64,
	manually_locked_outputs: Vec<String>,
) -> Result<WalletInfo, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let current_height = wallet.last_confirmed_height()?;
	if mwc_wallet_util::mwc_util::is_console_output_enabled() {
		println!("updater: the current_height is {}", current_height);
	}
	let outputs = wallet
		.iter()?
		.filter(|out| out.root_key_id == *parent_key_id);

	// Key: tx_log id;  Value: true if active, false if cancelled
	let tx_log_cancellation_status: HashMap<u32, bool> = wallet
		.tx_log_iter()?
		.filter(|tx_log| tx_log.parent_key_id == *parent_key_id)
		.map(|tx_log| (tx_log.id, !tx_log.is_cancelled()))
		.collect();

	let mut unspent_total: u64 = 0;
	let mut immature_total: u64 = 0;
	let mut awaiting_finalization_total: u64 = 0;
	let mut unconfirmed_total: u64 = 0;
	let mut locked_total: u64 = 0;
	let mut reverted_total: u64 = 0;

	let manually_locked_outputs: HashSet<String> = manually_locked_outputs.into_iter().collect();

	for out in outputs {
		match out.status {
			OutputStatus::Unspent => {
				if out.is_coinbase && out.lock_height > current_height {
					immature_total = immature_total.checked_add(out.value).ok_or_else(|| {
						Error::DataOverflow(format!(
							"updater::retrieve_info, immature wallet balance overflow, immature_total={} output_value={}",
							immature_total, out.value
						))
					})?;
				} else if out.num_confirmations(current_height) < minimum_confirmations {
					// Treat anything less than minimum confirmations as "unconfirmed".
					unconfirmed_total =
						unconfirmed_total.checked_add(out.value).ok_or_else(|| {
							Error::DataOverflow(format!(
								"updater::retrieve_info, unconfirmed wallet balance overflow, unconfirmed_total={} output_value={}",
								unconfirmed_total, out.value
							))
						})?;
				} else {
					let manually_locked =
						is_output_manually_locked(&out, &manually_locked_outputs, |out| {
							Ok(wallet
								.calc_commit(secp, keychain_mask, out.value, &out.key_id)?
								.to_hex())
						})?;
					if manually_locked {
						locked_total = locked_total.checked_add(out.value).ok_or_else(|| {
							Error::DataOverflow(format!(
								"updater::retrieve_info, locked wallet balance overflow, locked_total={} output_value={}",
								locked_total, out.value
							))
						})?;
					} else {
						unspent_total = unspent_total.checked_add(out.value).ok_or_else(|| {
							Error::DataOverflow(format!(
								"updater::retrieve_info, unspent wallet balance overflow, unspent_total={} output_value={}",
								unspent_total, out.value
							))
						})?;
					}
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
						unconfirmed_total =
							unconfirmed_total.checked_add(out.value).ok_or_else(|| {
								Error::DataOverflow(format!(
									"updater::retrieve_info, unconfirmed wallet balance overflow, unconfirmed_total={} output_value={}",
									unconfirmed_total, out.value
								))
							})?;
					} else {
						awaiting_finalization_total = awaiting_finalization_total
							.checked_add(out.value)
							.ok_or_else(|| {
								Error::DataOverflow(format!(
									"updater::retrieve_info, awaiting-finalization wallet balance overflow, awaiting_finalization_total={} output_value={}",
									awaiting_finalization_total, out.value
								))
							})?;
					}
				}
			}
			OutputStatus::Locked => {
				locked_total = locked_total.checked_add(out.value).ok_or_else(|| {
					Error::DataOverflow(format!(
						"updater::retrieve_info, locked wallet balance overflow, locked_total={} output_value={}",
						locked_total, out.value
					))
				})?;
			}
			OutputStatus::Reverted => {
				reverted_total = reverted_total.checked_add(out.value).ok_or_else(|| {
					Error::DataOverflow(format!(
						"updater::retrieve_info, reverted wallet balance overflow, reverted_total={} output_value={}",
						reverted_total, out.value
					))
				})?;
			}
			OutputStatus::Spent => {}
		}
	}

	let total = unspent_total
		.checked_add(unconfirmed_total)
		.and_then(|a| a.checked_add(immature_total))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"updater::retrieve_info, available wallet balance overflow, unspent_total={} unconfirmed_total={} immature_total={}",
				unspent_total, unconfirmed_total, immature_total
			))
		})?;
	Ok(WalletInfo {
		last_confirmed_height: current_height,
		minimum_confirmations,
		total,
		amount_awaiting_finalization: awaiting_finalization_total,
		amount_awaiting_confirmation: unconfirmed_total,
		amount_immature: immature_total,
		amount_locked: locked_total,
		amount_currently_spendable: unspent_total,
		amount_reverted: reverted_total,
	})
}

/// Construct an S2C reward at any height. Changing D changes the kernel nonce
/// and signature while preserving ordinary rangeproof recovery metadata. The
/// mining node includes the opening in the block only after activation.
pub fn build_coinbase<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	request: &BlockFees,
) -> Result<CbData, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Reject invalid digests before allocating a key or saving an output.
	let binding_digest = Hash::from_hex(&request.binding_digest)
		.map_err(|e| Error::GenericError(format!("Invalid Coinbase binding digest: {}", e)))?;
	let (output, kernel, fees, coinbase_opening) =
		receive_coinbase_with_binding(wallet, secp, keychain_mask, request, binding_digest)?;
	Ok(CbData {
		output,
		kernel,
		key_id: fees.key_id,
		coinbase_opening,
	})
}

/// Validate that a caller-supplied key identifies a coinbase output that may
/// safely be replaced while rebuilding a mining candidate.
///
/// Miners return the `key_id` from an earlier `build_coinbase` response so the
/// wallet can reuse one derivation while transaction fees in the candidate
/// block change. The identifier is not, however, proof that the stored output
/// is a coinbase candidate. Pending receive and change outputs also have no MMR
/// index, and the backend key for an unindexed output is derived only from its
/// identifier. Saving a new coinbase output for that identifier is an upsert
/// and would replace an unrelated pending output, including its transaction-log
/// association.
///
/// Reuse is therefore limited to a disposable, unconfirmed coinbase candidate
/// with no transaction association. Both the stored account metadata and the
/// account derived from the key path must match the active account, and the
/// stored identifier, MMR state, and child index must be structurally
/// consistent. If the requested record is missing or fails validation,
/// `receive_coinbase_with_binding` leaves any existing record untouched, allocates a fresh
/// wallet key, and returns that new key to the miner. The value, commitment, and
/// height are intentionally not compared because they are rebuilt when the
/// candidate's fees or chain head change.
fn validate_reusable_coinbase_output(
	existing: &OutputData,
	requested_key_id: &Identifier,
	parent_key_id: &Identifier,
) -> Result<(), Error> {
	let derived_parent_key_id = keys::output_parent_key_id(&existing.key_id)?;
	let derived_child_index = keys::output_child_index(&existing.key_id)?;

	if existing.key_id != *requested_key_id
		|| existing.mmr_index.is_some()
		|| !existing.is_coinbase
		|| existing.status != OutputStatus::Unconfirmed
		|| existing.tx_log_entry.is_some()
		|| existing.root_key_id != *parent_key_id
		|| derived_parent_key_id != *parent_key_id
		|| existing.n_child != derived_child_index
	{
		return Err(Error::GenericError(format!(
			"Requested coinbase key_id={} is not a reusable unconfirmed coinbase output for the active account",
			requested_key_id
		)));
	}

	Ok(())
}

#[derive(Clone, Copy)]
enum CoinbaseKeyUse {
	Requested,
	Fresh,
}

enum CoinbaseAttemptError {
	KeyUnavailable(Error),
	Other(Error),
}

impl From<Error> for CoinbaseAttemptError {
	fn from(error: Error) -> Self {
		Self::Other(error)
	}
}

/// Check the property required for the intended use of a coinbase key.
///
/// A requested key must identify an eligible candidate that may be replaced.
/// A freshly allocated key must not already identify any live output. Although
/// `next_available_key` atomically advances the derivation index, it cannot
/// guarantee this when stored derivation metadata is stale.
fn validate_coinbase_key_candidate<I>(
	mut outputs: I,
	key_id: &Identifier,
	parent_key_id: &Identifier,
	key_use: CoinbaseKeyUse,
) -> Result<(), Error>
where
	I: Iterator<Item = OutputData>,
{
	match key_use {
		CoinbaseKeyUse::Requested => {
			let existing = outputs
				.find(|output| output.key_id == *key_id && output.mmr_index.is_none())
				.ok_or_else(|| {
					Error::GenericError(format!(
						"Requested coinbase key_id={} does not identify a live unindexed output",
						key_id
					))
				})?;
			validate_reusable_coinbase_output(&existing, key_id, parent_key_id)
		}
		CoinbaseKeyUse::Fresh => {
			if outputs.any(|output| output.key_id == *key_id) {
				return Err(Error::GenericError(format!(
					"Fresh coinbase key_id={} is already used by a live output",
					key_id
				)));
			}
			Ok(())
		}
	}
}

/// Build and store a coinbase output using a specific key.
///
/// The required key property is checked before construction and again in the
/// write batch, preventing the output set from changing between the initial
/// check and the upsert.
fn receive_coinbase_with_key<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	key_id: &Identifier,
	key_use: CoinbaseKeyUse,
	binding_digest: Hash,
) -> Result<(Output, TxKernel, Opening), CoinbaseAttemptError>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let height = block_fees.height;
	let context_id = wallet.get_context_id();
	let lock_height = height
		.checked_add(global::coinbase_maturity(context_id))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"updater::receive_coinbase, coinbase lock height overflow, height={} maturity={}",
				height,
				global::coinbase_maturity(context_id)
			))
		})?;
	let parent_key_id = wallet.parent_key_id();
	{
		let outputs = wallet.iter()?;
		validate_coinbase_key_candidate(outputs, key_id, &parent_key_id, key_use)
			.map_err(CoinbaseAttemptError::KeyUnavailable)?;
	}

	let amount = reward(context_id, block_fees.fees, height)
		.map_err(|e| Error::GenericError(format!("Unable to calculate coinbase reward, {}", e)))?;
	let keychain = wallet.keychain(secp, keychain_mask)?;
	let commit = wallet.calc_commit(secp, keychain_mask, amount, key_id)?;

	// Build the complete response before committing the wallet record. If
	// output or kernel construction fails, the node never learns this key and
	// the wallet must not retain a candidate that the call did not return.
	let proof_builder = ProofBuilder::new(secp, &keychain).map_err(Error::from)?;
	let (out, kern, opening) = reward::output_s2c(
		context_id,
		&keychain,
		&proof_builder,
		key_id,
		block_fees.fees,
		height,
		secp,
		binding_digest,
	)
	.map_err(Error::from)?;

	let mut batch = wallet.batch(secp, keychain_mask)?;
	{
		let outputs = batch.iter()?;
		validate_coinbase_key_candidate(outputs, key_id, &parent_key_id, key_use)
			.map_err(CoinbaseAttemptError::KeyUnavailable)?;
	}
	batch.save(OutputData {
		root_key_id: parent_key_id,
		key_id: key_id.clone(),
		n_child: keys::output_child_index(key_id)?,
		mmr_index: None,
		commit: Some(commit.to_hex()),
		value: amount,
		status: OutputStatus::Unconfirmed,
		height,
		lock_height,
		is_coinbase: true,
		tx_log_entry: None,
	})?;
	batch.commit()?;

	Ok((out, kern, opening))
}

/// Build a coinbase output and the corresponding kernel.
///
/// A caller-supplied key is tried first. If that key is ineligible, or a newly
/// allocated key collides with an existing output because the derivation index
/// is stale, the wallet advances to another key and retries. Non-key-related
/// errors are returned immediately.
fn receive_coinbase_with_binding<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	binding_digest: Hash,
) -> Result<(Output, TxKernel, BlockFees, Opening), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (mut key_id, mut key_use) = match block_fees.key_id() {
		Some(requested_key_id) => (requested_key_id, CoinbaseKeyUse::Requested),
		None => (
			keys::next_available_key(wallet, None)?,
			CoinbaseKeyUse::Fresh,
		),
	};

	let (key_id, out, kern, opening) = loop {
		match receive_coinbase_with_key(
			wallet,
			secp,
			keychain_mask,
			block_fees,
			&key_id,
			key_use,
			binding_digest,
		) {
			Ok((out, kern, opening)) => break (key_id, out, kern, opening),
			Err(CoinbaseAttemptError::KeyUnavailable(e)) => {
				warn!(
					"Unable to use coinbase key_id={}: {}. Retrying with the next key.",
					key_id, e
				);
				key_id = keys::next_available_key(wallet, None)?;
				key_use = CoinbaseKeyUse::Fresh;
			}
			Err(CoinbaseAttemptError::Other(e)) => return Err(e),
		}
	};

	debug!(
		"receive_coinbase: built candidate output - {:?}, {}",
		key_id.clone(),
		key_id,
	);

	let mut block_fees = block_fees.clone();
	block_fees.key_id = Some(key_id.clone());

	debug!("receive_coinbase: {:?}", block_fees);
	Ok((out, kern, block_fees, opening))
}

#[cfg(test)]
mod coinbase_tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::serde_json;

	#[test]
	fn bound_coinbase_request_requires_explicit_binding() {
		let legacy = serde_json::json!({"fees": "0", "height": "3632000", "key_id": null});
		assert!(serde_json::from_value::<BlockFees>(legacy.clone()).is_err());
		let mut bound = legacy;
		bound["binding_digest"] = serde_json::json!(Hash::from_vec(&[1u8; 32]).to_hex());
		let parsed = serde_json::from_value::<BlockFees>(bound.clone()).unwrap();
		assert_eq!(
			serde_json::to_value(parsed).unwrap()["binding_digest"],
			bound["binding_digest"]
		);
		for invalid in [
			serde_json::Value::Null,
			serde_json::json!(42),
			serde_json::json!(true),
			serde_json::json!(Hash::from_vec(&[1u8; 32])),
		] {
			let mut invalid_request = bound.clone();
			invalid_request["binding_digest"] = invalid;
			assert!(serde_json::from_value::<BlockFees>(invalid_request).is_err());
		}
		bound["unknown_binding"] = serde_json::json!(true);
		assert!(serde_json::from_value::<BlockFees>(bound).is_err());
	}
}

#[cfg(test)]
mod retrieve_tx_tests {
	use super::*;

	#[test]
	fn recent_terminal_transactions_include_the_four_day_boundary() {
		let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
		let cutoff = now - Duration::days(4);
		for tx_type in [
			TxLogEntryType::TxSentCancelled,
			TxLogEntryType::TxReceivedCancelled,
			TxLogEntryType::TxReverted,
		] {
			let mut txs = Vec::new();
			for (id, creation_ts) in [
				(0, cutoff - Duration::nanoseconds(1)),
				(1, cutoff),
				(2, cutoff + Duration::nanoseconds(1)),
			] {
				let mut tx = TxLogEntry::new(Identifier::zero(), tx_type.clone(), id);
				tx.creation_ts = creation_ts;
				txs.push(tx);
			}

			filter_recent_txs(&mut txs, 1, now).unwrap();
			assert_eq!(
				txs.iter().map(|tx| tx.id).collect::<Vec<_>>(),
				vec![1, 2],
				"four-day boundary for {tx_type:?}"
			);
		}
	}
}

#[cfg(test)]
mod retrieve_output_tests {
	use super::*;

	fn test_output(commit: Option<&str>) -> OutputData {
		OutputData {
			root_key_id: Identifier::zero(),
			key_id: Identifier::zero(),
			n_child: 0,
			commit: commit.map(str::to_owned),
			mmr_index: None,
			value: 10,
			status: OutputStatus::Unspent,
			height: 1,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: None,
		}
	}

	#[test]
	fn manual_lock_uses_cached_commitment_without_deriving() {
		let output = test_output(Some("cached-commit"));
		let locks = HashSet::from(["cached-commit".to_owned()]);

		let locked = is_output_manually_locked(&output, &locks, |_| {
			panic!("a cached commitment must not be derived")
		})
		.unwrap();

		assert!(locked);
	}

	#[test]
	fn manual_lock_derives_missing_commitment() {
		let output = test_output(None);
		let locks = HashSet::from(["derived-commit".to_owned()]);
		let mut derivations = 0;

		let locked = is_output_manually_locked(&output, &locks, |_| {
			derivations += 1;
			Ok("derived-commit".to_owned())
		})
		.unwrap();

		assert!(locked);
		assert_eq!(derivations, 1);
	}

	#[test]
	fn empty_manual_lock_does_not_match_missing_commitment() {
		let output = test_output(None);
		let locks = HashSet::from([String::new()]);

		let locked =
			is_output_manually_locked(&output, &locks, |_| Ok("derived-commit".to_owned()))
				.unwrap();

		assert!(!locked);
	}

	#[test]
	fn manual_lock_propagates_commitment_derivation_error() {
		let output = test_output(None);
		let locks = HashSet::from(["derived-commit".to_owned()]);

		let error = is_output_manually_locked(&output, &locks, |_| {
			Err(Error::GenericError("commit derivation failed".to_owned()))
		})
		.unwrap_err();

		assert!(matches!(
			error,
			Error::GenericError(message) if message == "commit derivation failed"
		));
	}

	#[test]
	fn archived_output_filter_respects_show_spent() {
		assert!(!should_include_archived_output(
			&OutputStatus::Spent,
			false,
			true
		));
		assert!(should_include_archived_output(
			&OutputStatus::Spent,
			true,
			false
		));
		assert!(!should_include_archived_output(
			&OutputStatus::Reverted,
			true,
			false
		));
		assert!(should_include_archived_output(
			&OutputStatus::Reverted,
			false,
			true
		));
		assert!(should_include_archived_output(
			&OutputStatus::Reverted,
			true,
			true
		));
	}

	#[test]
	fn zero_pagination_len_is_rejected() {
		assert!(validate_pagination_len("test", None).is_ok());
		assert!(validate_pagination_len("test", Some(1)).is_ok());

		let error = validate_pagination_len("test", Some(0)).unwrap_err();
		assert!(matches!(
			error,
			Error::GenericError(message)
				if message == "test, pagination_len must be greater than zero"
		));
	}
}
