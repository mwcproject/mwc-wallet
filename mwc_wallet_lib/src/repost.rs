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
use crate::wallet_lock;
use mwc_wallet_libwallet::internal::updater;
use mwc_wallet_libwallet::slate_versions::v3::sig_is_blank;
use mwc_wallet_libwallet::{owner, TxLogEntry, TxLogEntryType};
use mwc_wallet_util::mwc_core::core::Transaction;
use std::str::FromStr;
use uuid::Uuid;

pub fn get_finalized_transaction(
	context_id: u32,
	tx_id: String,
) -> Result<(Transaction, CallbackNodeClient), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let tx_id = Uuid::from_str(tx_id.as_str())
		.map_err(|e| format!("tx_id has invalid UUID format, {}", e))?;

	wallet_lock!(wallet, w);
	let mut txs = updater::retrieve_txs(
		&mut **w,
		None,
		None,
		Some(tx_id),
		None,
		None,
		false,
		None,
		None,
		Some(false),
	)
	.map_err(|e| format!("Unable retrieve outputs, {}", e))?;

	txs.retain(|tx| tx.tx_type == TxLogEntryType::TxSent);

	if txs.is_empty() {
		return Err(format!("Not sound any send transaction {}", tx_id));
	}

	let tx: &TxLogEntry = &txs[0];
	if tx.confirmed {
		return Err(format!("Transaction {} is already confirmed", tx_id));
	}

	let stored_tx = w
		.get_stored_tx(tx)
		.map_err(|e| format!("Unable to retrieve stored transaction, {}", e))?;

	let stored_tx = stored_tx.ok_or(format!(
		"Transaction with id {} does not have transaction data. Not reposting.",
		tx_id
	))?;

	if stored_tx.kernels().is_empty() || sig_is_blank(&stored_tx.kernels()[0].excess_sig) {
		return Err(format!("Transaction at {} has not been finalized.", tx_id));
	}

	Ok((stored_tx, w.w2n_client().clone()))
}

pub fn repost(context_id: u32, tx_id: String, fluff: Option<bool>) -> Result<(), String> {
	let (tx, client) = get_finalized_transaction(context_id, tx_id)?;

	owner::post_tx(&client, &tx, fluff.unwrap_or(false))
		.map_err(|e| format!("Unable to post transaction, {}", e))?;
	Ok(())
}
