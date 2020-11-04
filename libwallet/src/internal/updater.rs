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

//! Utilities to check the status of all the outputs we have stored in
//! the wallet storage and update them.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::error::{Error, ErrorKind};
use crate::grin_core::consensus::reward;
use crate::grin_core::core::{Output, TxKernel};
use crate::grin_core::global;
use crate::grin_core::libtx::proof::ProofBuilder;
use crate::grin_core::libtx::reward;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util as util;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::internal::keys;
use crate::types::{
	NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend, WalletInfo,
};
use crate::{BlockFees, CbData, OutputCommitMapping};

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

	// only include outputs with a given tx_id if provided
	if let Some(tx) = tx {
		let mut tx_commits: HashSet<String> = HashSet::new();

		tx_commits.extend(tx.input_commits.iter().map(|c| util::to_hex(c.0.to_vec())));
		tx_commits.extend(tx.output_commits.iter().map(|c| util::to_hex(c.0.to_vec())));

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
		if out.status == OutputStatus::Unconfirmed
			&& !tx_log_is_active
				.get(&out.tx_log_entry.clone().unwrap_or(std::u32::MAX))
				.unwrap_or(&true)
		{
			continue;
		}

		let commit = match out.commit.clone() {
			Some(c) => pedersen::Commitment::from_vec(util::from_hex(&c).map_err(|e| {
				ErrorKind::GenericError(format!("Unable to parse HEX commit {}, {}", c, e))
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

/// Retrieve all of the transaction entries, or a particular entry
/// if `parent_key_id` is set, only return entries from that key
pub fn retrieve_txs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	_keychain_mask: Option<&SecretKey>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	parent_key_id: Option<&Identifier>,
	outstanding_only: bool,
	pagination_start: Option<u32>,
	pagination_len: Option<u32>,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut txs: Vec<TxLogEntry> = wallet
		.tx_log_iter()
		.filter(|tx_entry| {
			let f_pk = match parent_key_id {
				Some(k) => tx_entry.parent_key_id == *k,
				None => true,
			};
			let f_tx_id = match tx_id {
				Some(i) => tx_entry.id == i,
				None => true,
			};
			let f_txs = match tx_slate_id {
				Some(t) => tx_entry.tx_slate_id == Some(t),
				None => true,
			};
			let f_outstanding = match outstanding_only {
				true => {
					!tx_entry.confirmed
						&& (tx_entry.tx_type == TxLogEntryType::TxReceived
							|| tx_entry.tx_type == TxLogEntryType::TxSent)
				}
				false => true,
			};
			// Miners doesn't like the fact that CoinBase tx can be unconfirmed. That is we are hiding them fir Rest API and for UI
			let non_confirmed_coinbase =
				!tx_entry.confirmed && (tx_entry.tx_type == TxLogEntryType::ConfirmedCoinbase);

			f_pk && f_tx_id && f_txs && f_outstanding && !non_confirmed_coinbase
		})
		.collect();

	txs.sort_by_key(|tx| tx.creation_ts);

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
	tx: TxLogEntry,
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
		//if o.status == OutputStatus::Unconfirmed {   WMC don't delete outputs, we want to keep them mapped to cancelled trasactions
		//	batch.delete(&o.key_id, &o.mmr_index)?;
		//}
		if o.status == OutputStatus::Locked {
			o.status = OutputStatus::Unspent;
			batch.save(o)?;
		}
	}
	let mut tx = tx;
	if tx.tx_type == TxLogEntryType::TxSent {
		tx.tx_type = TxLogEntryType::TxSentCancelled;
	}
	if tx.tx_type == TxLogEntryType::TxReceived {
		tx.tx_type = TxLogEntryType::TxReceivedCancelled;
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
			Err(_) => keys::next_available_key(wallet, keychain_mask)?,
		},
		None => keys::next_available_key(wallet, keychain_mask)?,
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
	)?;
	Ok((out, kern, block_fees))
}
