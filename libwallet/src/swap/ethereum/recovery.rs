// Copyright 2026 The MWC Developers
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

//! Receipt reconciliation and process-local nonce reservations. The owner restores
//! swap reservations from encrypted trades before any Ethereum submission. Direct
//! transfers retain their signed recovery for this process's lifetime. Account
//! submission locks serialize allocation through signing and broadcasting.

use super::{EthNodeClient, EthTransactionRecovery};
use crate::swap::{Error, Swap, types::SecondaryData};
use mwc_wallet_util::{
	Mutex,
	mwc_web3::types::{Address, H256, TransactionReceipt, U256},
};
use std::{
	collections::{BTreeSet, HashMap, HashSet},
	sync::OnceLock,
};

#[derive(Default)]
struct ReservationState {
	nonces: HashMap<(u64, Address), BTreeSet<U256>>,
	direct_transfers: HashMap<(u64, Address, U256), EthTransactionRecovery>,
	// A redirect's cache entry must survive finality until every candidate hash
	// has been copied to durable swap storage. New replacements need a new save.
	redirect_transfers: HashMap<(u64, Address, U256), HashSet<H256>>,
}
static RESERVED_NONCES: OnceLock<Mutex<ReservationState>> = OnceLock::new();

fn reservations() -> &'static Mutex<ReservationState> {
	RESERVED_NONCES.get_or_init(|| Mutex::new(ReservationState::default()))
}

pub(super) fn reserve(recovery: &EthTransactionRecovery) {
	reservations()
		.lock()
		.nonces
		.entry((recovery.chain_id, recovery.sender))
		.or_default()
		.insert(recovery.nonce);
}

/// Reserve and retain a freshly signed direct transfer before broadcasting it.
/// The caller holds the account submission lock; no network I/O holds this mutex.
pub(super) fn retain_direct_transfer(record: EthTransactionRecovery) -> Result<(), Error> {
	let mut state = reservations().lock();
	let account = (record.chain_id, record.sender);
	let key = (record.chain_id, record.sender, record.nonce);
	if state.direct_transfers.contains_key(&key)
		|| state
			.nonces
			.get(&account)
			.is_some_and(|nonces| nonces.contains(&record.nonce))
	{
		return Err(Error::EthereumTransactionNonceReserved(record.nonce));
	}
	state
		.nonces
		.entry(account)
		.or_default()
		.insert(record.nonce);
	state.direct_transfers.insert(key, record);
	Ok(())
}

/// Any attempted hash identifies the same transfer, scoped to its signing account.
pub(super) fn direct_transfer(
	chain_id: u64,
	sender: Address,
	hash: H256,
) -> Result<EthTransactionRecovery, Error> {
	reservations()
		.lock()
		.direct_transfers
		.values()
		.find(|record| {
			record.chain_id == chain_id
				&& record.sender == sender
				&& record.attempted_hashes.contains(&hash)
		})
		.cloned()
		.ok_or(Error::EthereumTransactionRecoveryMissing(hash))
}

/// Follow a redirect by its exact signed transaction hash. Unlike retrying a
/// payment, this read does not require the account key or allocate a nonce.
pub(super) fn track_redirect(hash: H256) -> Vec<H256> {
	let mut state = reservations().lock();
	let found = state.direct_transfers.iter().find_map(|(key, record)| {
		record
			.attempted_hashes
			.contains(&hash)
			.then(|| (*key, record.attempted_hashes.clone()))
	});
	if let Some((key, hashes)) = found {
		state.redirect_transfers.entry(key).or_default();
		hashes
	} else {
		// Historical records and restarts can have only the saved hash(es).
		vec![hash]
	}
}

/// Keep known redirect replacements even when a later state check fails. These
/// hashes identify already signed payments, independently of staged FSM changes.
pub(crate) fn refresh_redirect_candidates(swap: &mut Swap) {
	if let SecondaryData::Eth(data) = &mut swap.secondary_data {
		if let Some(hash) = data.redirect_tx {
			for candidate in track_redirect(hash) {
				if !data.redirect_tx_candidates.contains(&candidate) {
					data.redirect_tx_candidates.push(candidate);
				}
			}
		}
	}
}

/// Keep replacements before broadcast, preserving the original transfer identity.
/// The caller holds the account submission lock throughout lookup and update.
pub(super) fn update_direct_transfer(record: EthTransactionRecovery) -> Result<(), Error> {
	let mut state = reservations().lock();
	let key = (record.chain_id, record.sender, record.nonce);
	let original_hash = record
		.attempted_hashes
		.first()
		.copied()
		.ok_or(Error::InvalidTxHash)?;
	let existing = state
		.direct_transfers
		.get_mut(&key)
		.ok_or(Error::EthereumTransactionRecoveryMissing(original_hash))?;
	if record.to != existing.to
		|| record.value != existing.value
		|| record.data != existing.data
		|| record.gas_limit != existing.gas_limit
		|| !record
			.attempted_hashes
			.starts_with(&existing.attempted_hashes)
	{
		return Err(Error::Generic(
			"Ethereum transfer recovery does not match its original payment".into(),
		));
	}
	*existing = record;
	Ok(())
}

pub(super) fn has_direct_transfers(chain_id: u64, sender: Address) -> bool {
	reservations()
		.lock()
		.direct_transfers
		.keys()
		.any(|(chain, account, _)| *chain == chain_id && *account == sender)
}

/// Finalized consumption retires recovery once any redirect's candidate hashes
/// have reached durable swap storage, even if a receipt was never requested.
pub(super) fn forget_finalized_direct_transfers(chain_id: u64, sender: Address, finalized: U256) {
	let mut state = reservations().lock();
	let ReservationState {
		direct_transfers,
		redirect_transfers,
		..
	} = &mut *state;
	direct_transfers.retain(|key @ (chain, account, nonce), record| {
		if *chain != chain_id || *account != sender || *nonce >= finalized {
			return true;
		}
		if redirect_transfers.get(key).is_some_and(|saved| {
			record
				.attempted_hashes
				.iter()
				.any(|hash| !saved.contains(hash))
		}) {
			return true;
		}
		redirect_transfers.remove(key);
		false
	});
}

/// Add restored reservations without removing other concurrent trades' entries.
pub(crate) fn record_swap(swap: &Swap) {
	if let SecondaryData::Eth(data) = &swap.secondary_data {
		for recovery in [
			&data.erc20_approval_recovery,
			&data.redeem_recovery,
			&data.refund_recovery,
			&data.lock_recovery,
			&data.lock_cancel_recovery,
		]
		.into_iter()
		.flatten()
		{
			reserve(recovery);
		}
		for approval in &data.erc20_approval_history {
			reserve(&approval.transaction);
		}
		if let Some(hash) = data.redirect_tx {
			let mut state = reservations().lock();
			let key = state
				.direct_transfers
				.iter()
				.find_map(|(key, record)| record.attempted_hashes.contains(&hash).then_some(*key));
			if let Some(key) = key {
				// record_swap is called after a successful save or when loading a
				// durable record, never from a staged status check that can roll back.
				let saved = state.redirect_transfers.entry(key).or_default();
				saved.insert(hash);
				saved.extend(data.redirect_tx_candidates.iter().copied());
			}
		}
	}
}

/// Caller holds the account submission lock until the selected nonce is signed
/// and any transaction reservation is installed. Only mined nonces may be forgotten;
/// the node's pending set can lose transactions after a restart or eviction.
pub(crate) fn next_nonce(
	chain_id: u64,
	sender: Address,
	confirmed: U256,
	pending: U256,
) -> Result<U256, Error> {
	let mut all = reservations().lock();
	// A mined direct transfer can become unmined in a reorg. Retained recovery
	// restores its reservation until finalized consumption permits forgetting it.
	let ReservationState {
		nonces,
		direct_transfers,
		..
	} = &mut *all;
	let reserved = nonces.entry((chain_id, sender)).or_default();
	reserved.retain(|nonce| *nonce >= confirmed);
	for (chain, account, nonce) in direct_transfers.keys() {
		if *chain == chain_id && *account == sender && *nonce >= confirmed {
			reserved.insert(*nonce);
		}
	}
	let next = confirmed.max(pending);
	if let Some(last) = reserved.last() {
		if *last >= next {
			// Skipping to last + 1 would create a nonce gap. Pending counts need
			// not include transactions queued beyond that gap, so a later send
			// could unknowingly replace another queued transfer at last + 1.
			return Err(Error::EthereumTransactionNonceReserved(*last));
		}
	}
	Ok(next)
}

pub(super) fn receipt_outcome(
	hash: H256,
	receipt: &TransactionReceipt,
) -> Result<Option<bool>, Error> {
	if receipt.transaction_hash != hash {
		return Err(Error::EthRetrieveTransReciptError);
	}
	if receipt.block_number.is_none() {
		return Ok(None);
	}
	match receipt.status {
		Some(status) if status == 1.into() => Ok(Some(true)),
		Some(status) if status == 0.into() => Ok(Some(false)),
		_ => Err(Error::EthRetrieveTransReciptError),
	}
}

/// The original can mine while a replacement is in flight. Inspect all hashes;
/// an unavailable receipt is not evidence that any of them was rejected.
pub(crate) fn transaction_status<C: EthNodeClient>(
	client: &C,
	tx_hash: Option<H256>,
	recovery: Option<&EthTransactionRecovery>,
) -> Result<(H256, bool), Error> {
	let receipt = transaction_receipt(client, tx_hash, recovery)?;
	Ok((receipt.transaction_hash, receipt.status == Some(1.into())))
}

/// Return the mined candidate itself so finality checks can validate its block hash.
pub(crate) fn transaction_receipt<C: EthNodeClient>(
	client: &C,
	tx_hash: Option<H256>,
	recovery: Option<&EthTransactionRecovery>,
) -> Result<TransactionReceipt, Error> {
	let mut hashes = recovery
		.map(|recovery| recovery.attempted_hashes.clone())
		.unwrap_or_default();
	if let Some(hash) = tx_hash {
		if !hashes.contains(&hash) {
			hashes.push(hash);
		}
	}
	transaction_receipt_for_hashes(client, &hashes)
}

/// Reconcile saved candidates without requiring signed transaction recovery.
pub(super) fn transaction_receipt_for_hashes<C: EthNodeClient>(
	client: &C,
	hashes: &[H256],
) -> Result<TransactionReceipt, Error> {
	if hashes.is_empty() {
		return Err(Error::InvalidTxHash);
	}
	let mut retrieval_error = None;
	for &hash in hashes {
		match client.retrieve_receipt(hash).and_then(|receipt| {
			receipt_outcome(hash, &receipt).map(|outcome| outcome.map(|_| receipt))
		}) {
			Ok(Some(receipt)) => return Ok(receipt),
			Ok(None) | Err(Error::EthTransactionInPending) => (),
			Err(error) => {
				// A failed query for one candidate must not hide another's mined
				// receipt. Preserve the error if no candidate can be reconciled.
				retrieval_error.get_or_insert(error);
			}
		}
	}
	Err(retrieval_error.unwrap_or(Error::EthTransactionInPending))
}

/// A cancellation's receipt must never be classified as successful funding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DepositOutcome {
	Deposited(H256),
	Reverted(H256),
	Cancelled(H256),
}

pub(crate) fn deposit_status<C: EthNodeClient>(
	client: &C,
	tx_hash: Option<H256>,
	deposit: Option<&EthTransactionRecovery>,
	cancellation: Option<&EthTransactionRecovery>,
) -> Result<DepositOutcome, Error> {
	let original_error = match transaction_status(client, tx_hash, deposit) {
		Ok((hash, success)) => {
			return Ok(if success {
				DepositOutcome::Deposited(hash)
			} else {
				DepositOutcome::Reverted(hash)
			});
		}
		Err(error) => error,
	};
	if let Some(cancellation) = cancellation {
		match transaction_status(client, None, Some(cancellation)) {
			// Even a reverted self-transfer consumes the nonce.
			Ok((hash, _)) => return Ok(DepositOutcome::Cancelled(hash)),
			Err(Error::EthTransactionInPending) => (),
			Err(error) => return Err(error),
		}
	}
	Err(original_error)
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn forget_for_test(chain_id: u64, sender: Address) {
	let mut state = reservations().lock();
	state.nonces.remove(&(chain_id, sender));
	state
		.direct_transfers
		.retain(|(chain, account, _), _| *chain != chain_id || *account != sender);
	state
		.redirect_transfers
		.retain(|(chain, account, _), _| *chain != chain_id || *account != sender);
}
