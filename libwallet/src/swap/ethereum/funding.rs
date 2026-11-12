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

//! Coordinate approval through deposit for an account/token/spender. The cache
//! mirrors encrypted trade records; the owner workflow restores those records
//! before funding after a restart. Keep the existing documented single-process
//! and post-submission persistence assumptions in doc/atomic_swaps.md.

use super::{
	recovery::{deposit_status, transaction_receipt, transaction_status, DepositOutcome},
	DepositRecoveryMode, Erc20AllowanceKey, Erc20ApprovalKind, Erc20ApprovalRecovery, Erc20Funding,
	Erc20FundingPhase, EthData, EthNodeClient, EthTransactionRecovery,
};
use crate::swap::{
	types::{Currency, SecondaryData},
	Error, Swap,
};
use mwc_wallet_util::{
	mwc_crates::uuid::Uuid,
	mwc_web3::types::{H256, U256},
	Mutex,
};
use std::{
	collections::HashMap,
	sync::{Arc, OnceLock},
};

#[derive(Clone)]
struct Reservation {
	funding: Erc20Funding,
	cancelled: bool,
	approval_recovery: Option<EthTransactionRecovery>,
	approval_history: Vec<Erc20ApprovalRecovery>,
	lock_tx: Option<H256>,
	lock_recovery: Option<EthTransactionRecovery>,
	lock_cancel_recovery: Option<EthTransactionRecovery>,
}

impl Reservation {
	fn from_data(data: &EthData, funding: Erc20Funding, cancelled: bool) -> Self {
		Self {
			funding,
			cancelled,
			approval_recovery: data.erc20_approval_recovery.clone(),
			approval_history: data.erc20_approval_history.clone(),
			lock_tx: data.lock_tx,
			lock_recovery: data.lock_recovery.clone(),
			lock_cancel_recovery: data.lock_cancel_recovery.clone(),
		}
	}
}

type Reservations = HashMap<Uuid, Reservation>;
type Allowances = HashMap<Erc20AllowanceKey, Arc<Mutex<Reservations>>>;
static ALLOWANCES: OnceLock<Mutex<Allowances>> = OnceLock::new();

fn reservations(key: Erc20AllowanceKey) -> Arc<Mutex<Reservations>> {
	ALLOWANCES
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.entry(key)
		.or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
		.clone()
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn forget_for_test(key: Erc20AllowanceKey) {
	reservations(key).lock().clear();
}

/// Called with this trade's lock held, after loading or successfully saving it.
/// Only the current trade is accessed: never acquire another trade lock while
/// holding an allowance lock. Completed deposits are also reconciled by waiting
/// trades, since the owner's FSM need not call the funding path again.
pub(crate) fn record_swap(swap: &Swap) {
	if swap.is_seller() {
		return;
	}
	let SecondaryData::Eth(data) = &swap.secondary_data else {
		return;
	};
	let Some(funding) = data.erc20_funding else {
		return;
	};
	let cancelled = swap.state.is_final_state();
	let entries = reservations(funding.key);
	let mut entries = entries.lock();
	if cancelled
		&& funding.phase == Erc20FundingPhase::CheckAllowance
		&& data.erc20_approval_history.is_empty()
	{
		entries.remove(&swap.id);
	} else {
		entries.insert(swap.id, Reservation::from_data(data, funding, cancelled));
	}
}

/// Convert wallet units to token atomic units without narrowing a remote value.
pub(crate) fn token_amount(currency: Currency, amount: u64) -> Result<U256, Error> {
	let scale = if currency.is_expo_shrinked18to9() {
		1_000_000_000u64
	} else {
		1
	};
	U256::from(amount)
		.checked_mul(U256::from(scale))
		.ok_or_else(|| Error::DataOverflow("ERC20 amount scaling overflow".into()))
}

/// Advance at most one transaction. Persist the mutated EthData even when this
/// returns an ambiguous submission error. The client lock is acquired before the
/// allowance lock; the deposit callback must use that same already-locked client.
pub(crate) fn advance<C: EthNodeClient>(
	client: &C,
	id: Uuid,
	currency: Currency,
	amount: u64,
	gas_gwei: u64,
	data: &mut EthData,
	deposit: impl FnOnce(&mut Option<EthTransactionRecovery>) -> Result<H256, Error>,
) -> Result<(), Error> {
	use Erc20FundingPhase::*;
	let key = client.erc20_allowance_key(currency)?;
	if data.erc20_funding.is_some_and(|funding| funding.key != key) {
		return Err(Error::Generic(
			"ERC20 funding account or contract changed".into(),
		));
	}
	client.validate_chain_and_contracts()?;
	let entries = reservations(key);
	let mut entries = entries.lock();
	let phase = data
		.erc20_funding
		.map(|funding| funding.phase)
		.unwrap_or_else(|| {
			// Retain existing hashes if an older record is explicitly resumed.
			data.lock_tx
				.map(DepositPending)
				.or_else(|| data.erc20_approve_tx.map(ApprovalPending))
				.unwrap_or(CheckAllowance)
		});
	// A cancelled owner may have left a transaction in flight. Never release its
	// allowance until that transaction has a mined success or failure receipt.
	// Reconcile/retry an existing deposit even if a later trade reserved the
	// allowance before a reorg. Only new funding must wait for other owners.
	let others: Vec<_> = entries
		.iter()
		.filter(|(owner, _)| **owner != id && !matches!(phase, Complete | DepositPending(_)))
		.map(|(owner, entry)| (*owner, entry.clone()))
		.collect();
	for (owner, entry) in others {
		for approval in &entry.approval_history {
			transaction_status(client, None, Some(&approval.transaction))?;
		}
		match entry.funding.phase {
			DepositPending(hash) => {
				deposit_status(
					client,
					Some(hash),
					entry.lock_recovery.as_ref(),
					entry.lock_cancel_recovery.as_ref(),
				)?;
			}
			Complete | DepositCancelled => {
				// Complete records are observations, not finality guarantees.
				deposit_status(
					client,
					entry.lock_tx,
					entry.lock_recovery.as_ref(),
					entry.lock_cancel_recovery.as_ref(),
				)?;
			}
			ResetPending(hash) | ApprovalPending(hash) if entry.cancelled => {
				transaction_status(client, Some(hash), entry.approval_recovery.as_ref())?;
			}
			CheckAllowance if entry.cancelled => (),
			_ => return Err(Error::Erc20FundingBusy(owner.to_string())),
		}
		entries.remove(&owner);
	}
	data.erc20_funding = Some(Erc20Funding { key, phase });
	let result = (|| {
		if !reconcile_approval_history(client, currency, gas_gwei, data)? {
			return Ok(());
		}
		step(client, currency, amount, gas_gwei, data, phase, deposit)
	})();
	if let Some(funding) = data.erc20_funding {
		entries.insert(id, Reservation::from_data(data, funding, false));
	}
	result
}

fn step<C: EthNodeClient>(
	client: &C,
	currency: Currency,
	amount: u64,
	gas_gwei: u64,
	data: &mut EthData,
	phase: Erc20FundingPhase,
	deposit: impl FnOnce(&mut Option<EthTransactionRecovery>) -> Result<H256, Error>,
) -> Result<(), Error> {
	use Erc20FundingPhase::*;
	if data.lock_cancel_recovery.is_some() {
		return Err(Error::UnexpectedAction(
			"Use explicit deposit recovery to reconcile its cancellation".into(),
		));
	}
	match phase {
		DepositCancelled => return Err(Error::UnexpectedAction("Deposit was cancelled".into())),
		Complete | DepositPending(_) => {
			let hash = match phase {
				DepositPending(hash) => Some(hash),
				_ => data.lock_tx,
			};
			match transaction_status(client, hash, data.lock_recovery.as_ref()) {
				Ok((hash, true)) => {
					data.lock_tx = Some(hash);
					set_phase(data, Complete);
					return Ok(());
				}
				Ok((_, false)) => {
					data.lock_tx = None;
					data.lock_recovery = None;
					set_phase(data, CheckAllowance);
					return Err(Error::Erc20FundingReverted(format!("{:?}", phase)));
				}
				Err(Error::EthTransactionInPending) => {
					let hash = hash.ok_or(Error::InvalidTxHash)?;
					set_phase(data, DepositPending(hash));
					if data.lock_recovery.is_none() {
						return Err(Error::EthereumTransactionRecoveryMissing(hash));
					}
					return submit_deposit(data, gas_gwei, deposit);
				}
				Err(error) => return Err(error),
			}
		}
		ResetPending(hash) | ApprovalPending(hash) => {
			if !advance_pending_approval(client, currency, amount, gas_gwei, data, phase, hash)? {
				return Ok(());
			}
		}
		CheckAllowance => (),
	}
	let required = token_amount(currency, amount)?;
	let allowance = client.erc20_allowance(currency)?;
	if (matches!(phase, ResetPending(_)) && !allowance.is_zero())
		|| (matches!(phase, ApprovalPending(_)) && allowance < required)
	{
		return Err(Error::EthERC20TokenApproveError);
	}
	if allowance >= required {
		return submit_deposit(data, gas_gwei, deposit);
	}
	submit_approval(
		client,
		currency,
		amount,
		gas_gwei,
		data,
		!allowance.is_zero(),
	)
}

/// Explicit recovery settles only the outstanding approval/reset. It can be
/// used for a cancelled trade without advancing into a new approval or deposit.
pub(crate) fn retry_approval<C: EthNodeClient>(
	client: &C,
	currency: Currency,
	amount: u64,
	gas_gwei: u64,
	data: &mut EthData,
) -> Result<(), Error> {
	let key = client.erc20_allowance_key(currency)?;
	if data.erc20_funding.is_some_and(|funding| funding.key != key) {
		return Err(Error::Generic(
			"ERC20 funding account or contract changed".into(),
		));
	}
	client.validate_chain_and_contracts()?;
	let entries = reservations(key);
	let _guard = entries.lock();
	let had_history = !data.erc20_approval_history.is_empty();
	if !reconcile_approval_history(client, currency, gas_gwei, data)? {
		return Ok(());
	}
	let phase = data
		.erc20_funding
		.map(|funding| funding.phase)
		.or_else(|| {
			data.erc20_approve_tx
				.map(Erc20FundingPhase::ApprovalPending)
		})
		.ok_or_else(|| Error::UnexpectedAction("No pending ERC20 approval".into()))?;
	let hash = match phase {
		Erc20FundingPhase::ResetPending(hash) | Erc20FundingPhase::ApprovalPending(hash) => hash,
		_ if had_history => return Ok(()),
		_ => return Err(Error::UnexpectedAction("No pending ERC20 approval".into())),
	};
	data.erc20_funding = Some(Erc20Funding { key, phase });
	advance_pending_approval(client, currency, amount, gas_gwei, data, phase, hash).map(|_| ())
}

/// True means the approval mined successfully and funding may inspect allowance.
/// A successful rebroadcast is still pending and must not advance the workflow.
fn advance_pending_approval<C: EthNodeClient>(
	client: &C,
	currency: Currency,
	amount: u64,
	gas_gwei: u64,
	data: &mut EthData,
	phase: Erc20FundingPhase,
	hash: H256,
) -> Result<bool, Error> {
	match transaction_status(client, Some(hash), data.erc20_approval_recovery.as_ref()) {
		Ok((mined_hash, success)) => {
			if let Some(transaction) = data.erc20_approval_recovery.take() {
				data.erc20_approval_history.push(Erc20ApprovalRecovery {
					kind: if matches!(phase, Erc20FundingPhase::ResetPending(_)) {
						Erc20ApprovalKind::Reset
					} else {
						Erc20ApprovalKind::Approve(amount)
					},
					transaction,
				});
			}
			data.erc20_approve_tx =
				if success && matches!(phase, Erc20FundingPhase::ApprovalPending(_)) {
					Some(mined_hash)
				} else {
					None
				};
			set_phase(data, Erc20FundingPhase::CheckAllowance);
			if !success {
				return Err(Error::Erc20FundingReverted(format!("{:?}", phase)));
			}
			Ok(true)
		}
		Err(Error::EthTransactionInPending) => {
			if data.erc20_approval_recovery.is_none() {
				return Err(Error::EthereumTransactionRecoveryMissing(hash));
			}
			submit_approval(
				client,
				currency,
				amount,
				gas_gwei,
				data,
				matches!(phase, Erc20FundingPhase::ResetPending(_)),
			)?;
			Ok(false)
		}
		Err(error) => Err(error),
	}
}

/// Resolve earlier account nonces before touching a later deposit. A mined
/// observation does not discard signed bytes; only canonical finality does.
fn reconcile_approval_history<C: EthNodeClient>(
	client: &C,
	currency: Currency,
	gas_gwei: u64,
	data: &mut EthData,
) -> Result<bool, Error> {
	data.erc20_approval_history
		.sort_by_key(|entry| entry.transaction.nonce);
	let mut index = 0;
	while index < data.erc20_approval_history.len() {
		let entry = &data.erc20_approval_history[index];
		match transaction_receipt(client, None, Some(&entry.transaction)) {
			Ok(receipt) => {
				if client.receipt_is_finalized(&receipt)? {
					data.erc20_approval_history.remove(index);
				} else {
					index += 1;
				}
			}
			Err(Error::EthTransactionInPending) => {
				let amount = match entry.kind {
					Erc20ApprovalKind::Reset => 0,
					Erc20ApprovalKind::Approve(amount) => amount,
				};
				let mut recovery = Some(entry.transaction.clone());
				let submission = client.erc20_approve(currency, amount, gas_gwei, &mut recovery);
				if let Some(record) = recovery {
					data.tx_fee_gwei = Some(record.gas_budget_gwei);
					data.erc20_approval_history[index].transaction = record;
				}
				submission?;
				return Ok(false);
			}
			Err(error) => return Err(error),
		}
	}
	Ok(true)
}

/// Recover only existing funding transactions. The client is already locked;
/// take the shared allowance lock before reconciling or signing a replacement.
pub(crate) fn recover_deposit<C: EthNodeClient>(
	client: &C,
	id: Uuid,
	currency: Currency,
	gas_gwei: u64,
	data: &mut EthData,
	mode: DepositRecoveryMode,
	cancelled: bool,
) -> Result<Option<DepositOutcome>, Error> {
	let key = client.erc20_allowance_key(currency)?;
	if data.erc20_funding.is_some_and(|funding| funding.key != key) {
		return Err(Error::Generic(
			"ERC20 funding account or contract changed".into(),
		));
	}
	client.validate_chain_and_contracts()?;
	// Retry must not undo a signed cancellation, even after a candidate has mined.
	if mode == DepositRecoveryMode::RetryOriginal && data.lock_cancel_recovery.is_some() {
		return Err(Error::UnexpectedAction(
			"Deposit cancellation already requested".into(),
		));
	}
	let hash = data
		.lock_tx
		.or_else(|| {
			data.lock_recovery
				.as_ref()
				.and_then(|record| record.attempted_hashes.last().copied())
		})
		.ok_or(Error::InvalidTxHash)?;
	let entries = reservations(key);
	let mut entries = entries.lock();
	data.erc20_funding.get_or_insert(Erc20Funding {
		key,
		phase: Erc20FundingPhase::DepositPending(hash),
	});
	let result = (|| {
		match deposit_status(
			client,
			Some(hash),
			data.lock_recovery.as_ref(),
			data.lock_cancel_recovery.as_ref(),
		) {
			Ok(outcome) => {
				match outcome {
					DepositOutcome::Deposited(hash) => {
						data.lock_tx = Some(hash);
						set_phase(data, Erc20FundingPhase::Complete);
					}
					DepositOutcome::Reverted(hash)
						if mode == DepositRecoveryMode::RetryOriginal =>
					{
						// Match normal funding's mined-revert handling. Recovery reports
						// the failure; a later funding step can use a fresh nonce.
						data.lock_tx = None;
						data.lock_recovery = None;
						set_phase(data, Erc20FundingPhase::CheckAllowance);
						return Err(Error::Erc20FundingReverted(format!(
							"{:?}",
							Erc20FundingPhase::DepositPending(hash)
						)));
					}
					DepositOutcome::Cancelled(_) | DepositOutcome::Reverted(_) => {
						// Retain both competitors in case this receipt is reorganized out.
						set_phase(data, Erc20FundingPhase::DepositCancelled);
					}
				}
				return Ok(Some(outcome));
			}
			Err(Error::EthTransactionInPending) => (),
			Err(error) => return Err(error),
		}
		if !reconcile_approval_history(client, currency, gas_gwei, data)? {
			return Ok(None);
		}
		set_phase(data, Erc20FundingPhase::DepositPending(hash));
		let original = data
			.lock_recovery
			.as_mut()
			.ok_or(Error::EthereumTransactionRecoveryMissing(hash))?;
		let submission = match mode {
			DepositRecoveryMode::RetryOriginal => {
				client.retry_deposit(currency, original, gas_gwei)
			}
			DepositRecoveryMode::Cancel => {
				client.cancel_deposit(currency, original, &mut data.lock_cancel_recovery, gas_gwei)
			}
		};
		if let Some(record) = data
			.lock_cancel_recovery
			.as_ref()
			.or(data.lock_recovery.as_ref())
		{
			data.tx_fee_gwei = Some(record.gas_budget_gwei);
		}
		if let Some(hash) = data
			.lock_recovery
			.as_ref()
			.and_then(|record| record.attempted_hashes.last().copied())
		{
			data.lock_tx = Some(hash);
			set_phase(data, Erc20FundingPhase::DepositPending(hash));
		}
		submission.map(|_| None)
	})();
	if let Some(funding) = data.erc20_funding {
		entries.insert(id, Reservation::from_data(data, funding, cancelled));
	}
	result
}

fn submit_approval<C: EthNodeClient>(
	client: &C,
	currency: Currency,
	amount: u64,
	gas_gwei: u64,
	data: &mut EthData,
	reset: bool,
) -> Result<(), Error> {
	use Erc20FundingPhase::*;
	let submission = client.erc20_approve(
		currency,
		if reset { 0 } else { amount },
		gas_gwei,
		&mut data.erc20_approval_recovery,
	);
	// Preserve the locally signed hash on both success and uncertain acceptance.
	let hash = match &submission {
		Ok(hash) => Some(*hash),
		Err(error) => error.ethereum_submission_hash(),
	}
	.or_else(|| {
		data.erc20_approval_recovery
			.as_ref()
			.and_then(|record| record.attempted_hashes.last().copied())
	});
	if let Some(hash) = hash {
		let phase = if reset {
			data.erc20_approve_tx = None;
			ResetPending(hash)
		} else {
			data.erc20_approve_tx = Some(hash);
			ApprovalPending(hash)
		};
		set_phase(data, phase);
		data.tx_fee_gwei = Some(
			data.erc20_approval_recovery
				.as_ref()
				.map_or(gas_gwei, |record| record.gas_budget_gwei),
		);
	}
	submission.map(|_| ())
}

/// Persist every deposit candidate, including a replacement whose submission failed.
fn submit_deposit(
	data: &mut EthData,
	gas_gwei: u64,
	deposit: impl FnOnce(&mut Option<EthTransactionRecovery>) -> Result<H256, Error>,
) -> Result<(), Error> {
	let submission = deposit(&mut data.lock_recovery);
	let submitted_hash = match &submission {
		Ok(hash) => Some(*hash),
		Err(error) => error.ethereum_submission_hash(),
	};
	let hash = submitted_hash.or_else(|| {
		data.lock_recovery
			.as_ref()
			.and_then(|record| record.attempted_hashes.last().copied())
	});
	if let Some(hash) = hash {
		data.lock_tx = Some(hash);
		set_phase(data, Erc20FundingPhase::DepositPending(hash));
		data.tx_fee_gwei = Some(
			data.lock_recovery
				.as_ref()
				.map_or(gas_gwei, |record| record.gas_budget_gwei),
		);
	}
	submission.map(|_| ())
}

fn set_phase(data: &mut EthData, phase: Erc20FundingPhase) {
	if let Some(funding) = data.erc20_funding.as_mut() {
		funding.phase = phase;
	}
}
