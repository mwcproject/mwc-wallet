// Copyright 2019 The Grin Develope;
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

//! Generic implementation of owner API functions

use uuid::Uuid;

use crate::grin_core::core::hash::Hashed;
use crate::grin_core::core::Transaction;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_keychain::{Identifier, Keychain};
use crate::grin_util::secp::key::PublicKey;

use crate::internal::{keys, scan, selection, tx, updater};
use crate::slate::{PaymentInfo, Slate};
use crate::types::{AcctPathMapping, Context, NodeClient, TxLogEntry, WalletBackend, WalletInfo};
use crate::{
	wallet_lock, InitTxArgs, IssueInvoiceTxArgs, NodeHeightResult, OutputCommitMapping,
	PaymentProof, ScannedBlockInfo, TxLogEntryType, WalletInst, WalletLCProvider,
};
use crate::{Error, ErrorKind};

use crate::proof::tx_proof::{pop_proof_for_slate, TxProof};
use std::cmp;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::Arc;

const USER_MESSAGE_MAX_LEN: usize = 256;
use crate::proof::crypto;
use crate::proof::proofaddress;

/// List of accounts
pub fn accounts<'a, T: ?Sized, C, K>(w: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::accounts(&mut *w)
}

/// new account path
pub fn create_account_path<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::new_acct_path(&mut *w, keychain_mask, label)
}

/// set active account
pub fn set_active_account<'a, T: ?Sized, C, K>(w: &mut T, label: &str) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.set_parent_key_id_by_name(label)
}

/// Retrieve the payment proof address for the wallet
pub fn get_public_proof_address<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<PublicKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let k = w.keychain(keychain_mask)?;
	let pub_key = proofaddress::payment_proof_address_pubkey(&k)?;
	Ok(pub_key)
}

fn perform_refresh_from_node<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let validated = update_wallet_state(wallet_inst.clone(), keychain_mask, status_send_channel)?;

	Ok(validated)
}

/// retrieve outputs
pub fn retrieve_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	include_spent: bool,
	refresh_from_node: bool,
	tx_id: Option<u32>,
) -> Result<(bool, Vec<OutputCommitMapping>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated =
			perform_refresh_from_node(wallet_inst.clone(), keychain_mask, status_send_channel)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();

	let mut tx: Option<TxLogEntry> = None;
	if tx_id.is_some() {
		let mut txs = updater::retrieve_txs(
			&mut **w,
			keychain_mask,
			tx_id,
			None,
			Some(&parent_key_id),
			false,
			None,
			None,
		)?;

		if !txs.is_empty() {
			tx = Some(txs.remove(0));
		}
	}

	Ok((
		validated,
		updater::retrieve_outputs(
			&mut **w,
			keychain_mask,
			include_spent,
			tx.as_ref(),
			&parent_key_id,
			None,
			None,
		)?,
	))
}

/// Retrieve txs
pub fn retrieve_txs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(bool, Vec<TxLogEntry>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated =
			perform_refresh_from_node(wallet_inst.clone(), keychain_mask, status_send_channel)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let txs = updater::retrieve_txs(
		&mut **w,
		keychain_mask,
		tx_id,
		tx_slate_id,
		Some(&parent_key_id),
		false,
		None,
		None,
	)?;

	Ok((validated, txs))
}

/// Retrieve summary info
pub fn retrieve_summary_info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	minimum_confirmations: u64,
) -> Result<(bool, WalletInfo), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut validated = false;
	if refresh_from_node {
		validated =
			perform_refresh_from_node(wallet_inst.clone(), keychain_mask, status_send_channel)?;
	}

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let wallet_info = updater::retrieve_info(&mut **w, &parent_key_id, minimum_confirmations)?;
	Ok((validated, wallet_info))
}

/// Retrieve payment proof
pub fn retrieve_payment_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<PaymentProof, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if tx_id.is_none() && tx_slate_id.is_none() {
		return Err(ErrorKind::PaymentProofRetrieval(
			"Transaction ID or Slate UUID must be specified".into(),
		)
		.into());
	}
	if refresh_from_node {
		update_wallet_state(wallet_inst.clone(), keychain_mask, status_send_channel)?
	} else {
		false
	};
	let txs = retrieve_txs(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
		refresh_from_node,
		tx_id,
		tx_slate_id,
	)?;
	if txs.1.len() != 1 {
		return Err(ErrorKind::PaymentProofRetrieval("Transaction doesn't exist".into()).into());
	}
	// Pull out all needed fields, returning an error if they're not present
	let tx = txs.1[0].clone();
	let proof = match tx.payment_proof {
		Some(p) => p,
		None => {
			return Err(ErrorKind::PaymentProofRetrieval(
				"Transaction does not contain a payment proof".into(),
			)
			.into());
		}
	};
	let amount = if tx.amount_credited >= tx.amount_debited {
		tx.amount_credited - tx.amount_debited
	} else {
		let fee = match tx.fee {
			Some(f) => f,
			None => 0,
		};
		tx.amount_debited - tx.amount_credited - fee
	};
	let excess = match tx.kernel_excess {
		Some(e) => e,
		None => {
			return Err(ErrorKind::PaymentProofRetrieval(
				"Transaction does not contain kernel excess".into(),
			)
			.into());
		}
	};
	let r_sig = match proof.receiver_signature {
		Some(e) => e,
		None => {
			return Err(ErrorKind::PaymentProofRetrieval(
				"Proof does not contain receiver signature ".into(),
			)
			.into());
		}
	};
	let s_sig = match proof.sender_signature {
		Some(e) => e,
		None => {
			return Err(ErrorKind::PaymentProofRetrieval(
				"Proof does not contain sender signature ".into(),
			)
			.into());
		}
	};
	Ok(PaymentProof {
		amount: amount,
		excess: excess,
		recipient_address: proof.receiver_address,
		recipient_sig: r_sig,
		sender_address: proof.sender_address,
		sender_sig: s_sig,
	})
}
///get stored tx proof file.
pub fn get_stored_tx_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	id: Option<u32>,
) -> Result<TxProof, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if id.is_none() {
		return Err(
			ErrorKind::PaymentProofRetrieval("Transaction ID must be specified".into()).into(),
		);
	}
	let tx_id = id.unwrap();
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let txs: Vec<TxLogEntry> = updater::retrieve_txs(
		&mut **w,
		None,
		Some(tx_id),
		None,
		Some(&parent_key_id),
		false,
		None,
		None,
	)
	.map_err(|e| ErrorKind::StoredTransactionError(format!("{}", e)))?;
	if txs.len() != 1 {
		return Err(ErrorKind::GenericError(format!(
			"Unable to find tx, {}",
			tx_id
		)))?;
	}
	let uuid = txs[0].tx_slate_id.ok_or_else(|| {
		ErrorKind::GenericError(format!("Unable to find slateId for txId, {}", tx_id))
	})?;
	let proof = TxProof::get_stored_tx_proof(w.get_data_file_dir(), &uuid.to_string())
		.map_err(|e| ErrorKind::TransactionHasNoProof(format!("{}", e)))?;
	return Ok(proof);
}

/// Initiate tx as sender
/// Caller is responsible for wallet refresh
pub fn init_send_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: InitTxArgs,
	use_test_rng: bool,
	routputs: usize, // Number of resulting outputs. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let mut slate = tx::new_tx_slate(&mut *w, args.amount, 2, use_test_rng, args.ttl_blocks)?;

	// if we just want to estimate, don't save a context, just send the results
	// back
	if let Some(true) = args.estimate_only {
		let (total, fee) = tx::estimate_send_tx(
			&mut *w,
			args.amount,
			args.minimum_confirmations,
			args.max_outputs as usize,
			args.num_change_outputs as usize,
			args.selection_strategy_is_use_all,
			&parent_key_id,
			&args.outputs,
			routputs,
			args.exclude_change_outputs.unwrap_or(false),
			args.minimum_confirmations_change_outputs,
		)?;
		slate.amount = total;
		slate.fee = fee;
		return Ok(slate);
	}

	let mut context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		args.minimum_confirmations,
		args.max_outputs as usize,
		args.num_change_outputs as usize,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		0,
		message,
		true,
		use_test_rng,
		&args.outputs,
		routputs,
		args.exclude_change_outputs.unwrap_or(false),
		args.minimum_confirmations_change_outputs,
	)?;

	// Payment Proof, add addresses to slate and save address
	// TODO: Note we only use single derivation path for now,
	// probably want to allow sender to specify which one
	// sender_a has to in MQS format because we need Normal public key to sign, dalek will not work
	let k = w.keychain(keychain_mask)?;
	let sender_a = proofaddress::payment_proof_address(&k, proofaddress::ProofAddressType::MQS)?;

	if let Some(a) = args.address {
		if a.eq("file_proof") {
			debug!("doing file proof");
			//in file proof, we are putting the same address both both sender_address and receiver_address
			slate.payment_proof = Some(PaymentInfo {
				sender_address: sender_a.clone(),
				receiver_address: sender_a.clone(),
				receiver_signature: None,
			});

			context.payment_proof_derivation_index = Some(proofaddress::get_address_index());
		}
	}

	if let Some(a) = args.payment_proof_recipient_address {
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_a,
			receiver_address: a,
			receiver_signature: None,
		});

		context.payment_proof_derivation_index = Some(proofaddress::get_address_index());
	} else {
		debug!("There is no payment proof recipient address");
	}

	// mwc713 payment proof support.
	for input in slate.tx.inputs() {
		context.input_commits.push(input.commit.clone());
	}

	for output in slate.tx.outputs() {
		context.output_commits.push(output.commit.clone());
	}

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), 0, &context)?;
		batch.commit()?;
	}
	if let Some(v) = args.target_slate_version {
		slate.version_info.orig_version = v;
	}

	Ok(slate)
}

/// Initiate a transaction as the recipient (invoicing)
pub fn issue_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceTxArgs,
	use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match args.dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let mut slate = tx::new_tx_slate(&mut *w, args.amount, 2, use_test_rng, None)?;
	let context = tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		args.address.clone(),
		None,
		None,
		&parent_key_id,
		0, // Participant 0 for mwc713 compatibility
		message,
		true,
		use_test_rng,
		num_outputs,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		// Participant id is 0 for mwc713 compatibility
		batch.save_private_context(slate.id.as_bytes(), 0, &context)?;
		batch.commit()?;
	}

	if let Some(v) = args.target_slate_version {
		slate.version_info.orig_version = v;
	}

	Ok(slate)
}

/// Receive an invoice tx, essentially adding inputs to whatever
/// output was specified
/// Caller is responsible for wallet refresh
pub fn process_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	args: InitTxArgs,
	use_test_rng: bool,
	refresh_from_node: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut ret_slate = slate.clone();
	check_ttl(w, &ret_slate, refresh_from_node)?;
	let parent_key_id = match args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		&mut *w,
		keychain_mask,
		None,
		Some(ret_slate.id),
		Some(&parent_key_id),
		use_test_rng,
		None,
		None,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxSent {
			return Err(ErrorKind::TransactionAlreadyReceived(ret_slate.id.to_string()).into());
		}
	}

	let message = match args.message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	// update slate current height
	ret_slate.height = w.w2n_client().get_chain_tip()?.0;

	// update ttl if desired
	if let Some(b) = args.ttl_blocks {
		ret_slate.ttl_cutoff_height = Some(ret_slate.height + b);
	}

	let context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut ret_slate,
		args.minimum_confirmations,
		args.max_outputs as usize,
		args.num_change_outputs as usize,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		1, // Participant id 1 for mwc713 compatibility
		message,
		false,
		use_test_rng,
		&None,
		1,
		args.exclude_change_outputs.unwrap_or(false),
		args.minimum_confirmations_change_outputs,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		// Participant id 1 for mwc713 compatibility
		batch.save_private_context(slate.id.as_bytes(), 1, &context)?;
		batch.commit()?;
	}

	if let Some(v) = args.target_slate_version {
		ret_slate.version_info.orig_version = v;
	}

	Ok(ret_slate)
}

/// Lock sender outputs
pub fn tx_lock_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	address: Option<String>,
	participant_id: usize,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context = w.get_private_context(keychain_mask, slate.id.as_bytes(), participant_id)?;
	selection::lock_tx_context(&mut *w, keychain_mask, slate, &context, address)
}

/// Finalize slate
/// Context needed for mwc713 proof of sending funds through mwcmqs
pub fn finalize_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	refresh_from_node: bool,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	check_ttl(w, &sl, refresh_from_node)?;
	let context = w.get_private_context(keychain_mask, sl.id.as_bytes(), 0)?;
	tx::complete_tx(&mut *w, keychain_mask, &mut sl, 0, &context)?;
	tx::verify_slate_payment_proof(&mut *w, keychain_mask, &context, &sl)?;
	tx::update_stored_tx(&mut *w, keychain_mask, &context, &sl, false)?;
	tx::update_message(&mut *w, keychain_mask, &sl)?;
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.delete_private_context(sl.id.as_bytes(), 0)?;
		batch.commit()?;
	}

	// If Proof available, we can store it at that point
	if let Some(mut proof) = pop_proof_for_slate(&slate.id) {
		proof.amount = context.amount;
		proof.fee = context.fee;
		for input in &context.input_commits {
			proof.inputs.push(input.clone());
		}
		for output in &context.output_commits {
			proof.outputs.push(output.clone());
		}

		proof.store_tx_proof(w.get_data_file_dir(), &slate.id.to_string())?;
	};

	Ok((sl, context))
}

/// cancel tx
pub fn cancel_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !perform_refresh_from_node(wallet_inst.clone(), keychain_mask, status_send_channel)? {
		return Err(ErrorKind::TransactionCancellationError(
			"Can't contact running MWC node. Not Cancelling.",
		))?;
	}
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	tx::cancel_tx(&mut **w, keychain_mask, &parent_key_id, tx_id, tx_slate_id)
}

/// get stored tx
pub fn get_stored_tx<'a, T: ?Sized, C, K>(
	w: &T,
	entry: &TxLogEntry,
) -> Result<Option<Transaction>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.get_stored_tx(entry)
}

/// Loads a stored transaction from a file
pub fn load_stored_tx<'a, T: ?Sized, C, K>(w: &T, file: &String) -> Result<Transaction, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.load_stored_tx(file)
}

/// Posts a transaction to the chain
/// take a client impl instead of wallet so as not to have to lock the wallet
pub fn post_tx<'a, C>(client: &C, tx: &Transaction, fluff: bool) -> Result<(), Error>
where
	C: NodeClient + 'a,
{
	let res = client.post_tx(tx, fluff);
	if let Err(e) = res {
		error!("api: post_tx: failed with error: {}", e);
		Err(e)
	} else {
		debug!(
			"api: post_tx: successfully posted tx: {}, fluff? {}",
			tx.hash(),
			fluff
		);
		Ok(())
	}
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()
}

/// check repair
/// Accepts a wallet inst instead of a raw wallet so it can
/// lock as little as possible
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	start_height: Option<u64>,
	delete_unconfirmed: bool,
	status_send_channel: &Option<Sender<StatusMessage>>,
	do_full_outputs_refresh: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	{
		wallet_lock!(wallet_inst, w);
		w.w2n_client().reset_cache();
	}

	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) = get_last_detect_last_scanned_block(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
	)?;

	if tip_height == 0 {
		return Err(ErrorKind::NodeNotReady)?;
	}

	if has_reorg {
		info!(
			"Wallet update will do full outputs checking because since last update reorg happend"
		);
	}

	debug!(
		"Preparing to update the wallet from height {} to {}",
		last_scanned_block.height, tip_height
	);

	let start_height = match start_height {
		Some(h) => cmp::min(last_scanned_block.height, h),
		None => 1,
	};

	// First we need to get the hashes for heights... Reason, if block chain will be changed during scan, we will detect that naturally with next wallet_update.
	let mut blocks: Vec<ScannedBlockInfo> =
		vec![ScannedBlockInfo::new(tip_height, tip_hash.clone())];
	{
		wallet_lock!(wallet_inst, w);

		let mut step = 4;
		while blocks.last().unwrap().height.saturating_sub(step) > start_height {
			let h = blocks.last().unwrap().height.saturating_sub(step);
			let hdr = w.w2n_client().get_header_info(h)?;
			blocks.push(ScannedBlockInfo::new(h, hdr.hash));
			step *= 2;
		}
		// adding last_scanned_block.height not needed
	}

	scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		delete_unconfirmed,
		start_height,
		tip_height,
		status_send_channel,
		true,
		do_full_outputs_refresh,
	)?;

	wallet_lock!(wallet_inst, w);
	let mut batch = w.batch(keychain_mask)?;
	batch.save_last_scanned_blocks(start_height, &blocks)?;
	batch.commit()?;

	Ok(())
}

/// node height
pub fn node_height<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<NodeHeightResult, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let res = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()
	};
	match res {
		Ok(r) => Ok(NodeHeightResult {
			height: r.0,
			header_hash: r.1,
			updated_from_node: true,
		}),
		Err(_) => {
			let outputs = retrieve_outputs(wallet_inst, keychain_mask, &None, true, false, None)?;
			let height = match outputs.1.iter().map(|m| m.output.height).max() {
				Some(height) => height,
				None => 0,
			};
			Ok(NodeHeightResult {
				height,
				header_hash: "".to_owned(),
				updated_from_node: false,
			})
		}
	}
}

// write infor into the file or channel
fn write_info(
	message: String,
	file: Option<&mut File>,
	status_send_channel: &Sender<StatusMessage>,
) {
	match file {
		Some(file) => {
			let _ = write!(file, "{}\n", message);
		}
		None => {
			let _ = status_send_channel.send(StatusMessage::Info(message));
		}
	};
}

/// Print wallet status into send channel. This data suppose to be used for troubleshouting only
pub fn dump_wallet_data<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	status_send_channel: &Sender<StatusMessage>,
	file_name: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let fn_copy = file_name.clone();

	let mut file: Option<File> = match file_name {
		Some(file_name) => Some(File::create(file_name)?),
		None => None,
	};

	write_info(
		String::from("Wallet Outputs:"),
		file.as_mut(),
		status_send_channel,
	);
	for output in w.iter() {
		write_info(format!("{:?}", output), file.as_mut(), status_send_channel);
	}

	write_info(
		String::from("Wallet Transactions:"),
		file.as_mut(),
		status_send_channel,
	);
	for tx_log in w.tx_log_iter() {
		write_info(format!("{:?}", tx_log), file.as_mut(), status_send_channel);
		// Checking if Slate is available
		if let Some(uuid) = tx_log.tx_slate_id {
			let uuid_str = uuid.to_string();
			match w.get_stored_tx_by_uuid(&uuid_str) {
				Ok(t) => {
					write_info(
						format!("   Slate for {}: {:?}", uuid_str, t),
						file.as_mut(),
						status_send_channel,
					);
				}
				Err(_) => write_info(
					format!("   Slate for {} not found", uuid_str),
					file.as_mut(),
					status_send_channel,
				),
			}
		}
	}

	if let Some(f) = fn_copy {
		let _ = status_send_channel.send(StatusMessage::Info(format!(
			"Wallet dump is stored at  {}",
			f
		)));
	}

	Ok(())
}

// Checking if node head is fine and we can perform the scanning
// Result: (tip_height: u64, tip_hash:String, first_block_to_scan_from: ScannedBlockInfo, is_reorg: bool)
// is_reorg true if new need go back by the chain to perform scanning
// Note: In case of error return tip 0!!!
fn get_last_detect_last_scanned_block<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(u64, String, ScannedBlockInfo, bool), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	// Wallet update logic doesn't handle truncating of the blockchain. That happen when node in sync or in reorg-sync
	// In this case better to inform user and do nothing. Sync is useless in any case.

	// Checking if keychain mask correct. Issue that sometimes update_wallet_state doesn't need it and it is a security problem
	let _ = w.batch(keychain_mask)?;

	let (tip_height, tip_hash, _) = match w.w2n_client().get_chain_tip() {
		Ok(t) => t,
		Err(_) => {
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Warning(
					"Unable to contact mwc-node".to_owned(),
				));
			}
			return Ok((0, String::new(), ScannedBlockInfo::empty(), false));
		}
	};

	let blocks = w.last_scanned_blocks()?;

	// If the server height is less than our confirmed height, don't apply
	// these changes as the chain is syncing, incorrect or forking
	if tip_height == 0 || tip_height < blocks.first().map(|b| b.height).unwrap_or(0) {
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Warning(
				String::from("Wallet Update is skipped, please wait for sync on node to complete or fork to resolve.")
			));
		}
		return Ok((0, String::new(), ScannedBlockInfo::empty(), false));
	}

	let mut last_scanned_block = ScannedBlockInfo::empty();
	let head_height = blocks.first().map(|b| b.height).unwrap_or(0);
	for bl in blocks {
		// check if that block is not changed
		if let Ok(hdr_info) = w.w2n_client().get_header_info(bl.height) {
			if hdr_info.hash == bl.hash {
				last_scanned_block = bl;
				break;
			}
		}
	}

	let has_reorg = last_scanned_block.height != head_height;

	Ok((tip_height, tip_hash, last_scanned_block, has_reorg))
}

/// Experimental, wrap the entire definition of how a wallet's state is updated
pub fn update_wallet_state<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) = get_last_detect_last_scanned_block(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
	)?;

	if tip_height == 0 {
		return Ok(false);
	}

	if has_reorg {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().reset_cache(); // let's reset cach to be safe

		info!(
			"Wallet update will do full outputs checking because since last update reorg happend"
		);
	}

	debug!(
		"Preparing to update the wallet from height {} to {}",
		last_scanned_block.height, tip_height
	);

	if last_scanned_block.height == tip_height {
		debug!("update_wallet_state is skipped because data is already recently updated");
		return Ok(true);
	}

	let show_progress =
		tip_height < 1000 || tip_height.saturating_sub(last_scanned_block.height) > 20;

	if last_scanned_block.height == 0 {
		let msg = "This wallet has not been scanned against the current chain. Beginning full scan... (this first scan may take a while, but subsequent scans will be much quicker)".to_string();
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::FullScanWarn(msg));
		}
	}

	// First we need to get the hashes for heights... Reason, if block chain will be changed during scan, we will detect that naturally.
	let mut blocks: Vec<ScannedBlockInfo> =
		vec![ScannedBlockInfo::new(tip_height, tip_hash.clone())];
	{
		wallet_lock!(wallet_inst, w);

		let mut step = 4;

		while blocks.last().unwrap().height.saturating_sub(step) > last_scanned_block.height {
			let h = blocks.last().unwrap().height.saturating_sub(step);
			let hdr = w.w2n_client().get_header_info(h)?;
			blocks.push(ScannedBlockInfo::new(h, hdr.hash));
			step *= 2;
		}
		// adding last_scanned_block.height not needed
	}

	scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		false,
		last_scanned_block.height,
		tip_height,
		status_send_channel,
		show_progress,
		has_reorg,
	)?;

	// Checking if tip was changed. In this case we need to retry. Retry will be handles naturally optimal
	let mut tip_was_changed = false;
	{
		wallet_lock!(wallet_inst, w);

		if let Ok((after_tip_height, after_tip_hash, _)) = w.w2n_client().get_chain_tip() {
			// Since we are still online, we can save the scan status
			{
				let mut batch = w.batch(keychain_mask)?;
				batch.save_last_scanned_blocks(last_scanned_block.height, &blocks)?;
				batch.commit()?;
			}

			if after_tip_height == tip_height && after_tip_hash == tip_hash {
				return Ok(true);
			} else {
				tip_was_changed = true;
			}
		}
	}

	if tip_was_changed {
		// Since head was chaged, we need to update it
		return update_wallet_state(wallet_inst, keychain_mask, &status_send_channel);
	}

	// wasn't be able to confirm the tip. Scan is failed, scan height not updated.
	Ok(false)
}

/// Check TTL
pub fn check_ttl<'a, T: ?Sized, C, K>(
	w: &mut T,
	slate: &Slate,
	refresh_from_node: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Refuse if TTL is expired
	let last_confirmed_height = if refresh_from_node {
		w.w2n_client().get_chain_tip()?.0
	} else {
		w.last_confirmed_height()?
	};

	if let Some(e) = slate.ttl_cutoff_height {
		if last_confirmed_height >= e {
			return Err(ErrorKind::TransactionExpired.into());
		}
	}
	Ok(())
}

/// Verify/validate arbitrary payment proof
/// Returns (whether this wallet is the sender, whether this wallet is the recipient)
pub fn verify_payment_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	proof: &PaymentProof,
) -> Result<(bool, bool), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let sender_pubkey = proof.sender_address.clone().public_key;
	let msg = tx::payment_proof_message(proof.amount, &proof.excess, sender_pubkey)?;

	let (client, keychain) = {
		wallet_lock!(wallet_inst, w);
		(w.w2n_client().clone(), w.keychain(keychain_mask)?)
	};

	// Check kernel exists
	match client.get_kernel(&proof.excess, None, None) {
		Err(e) => {
			return Err(ErrorKind::PaymentProof(format!(
				"Error retrieving kernel from chain: {}",
				e
			))
			.into());
		}
		Ok(None) => {
			return Err(ErrorKind::PaymentProof(format!(
				"Transaction kernel with excess {:?} not found on chain",
				proof.excess
			))
			.into());
		}
		Ok(Some(_)) => {}
	};

	// Check Sigs
	let recipient_pubkey = proof.recipient_address.public_key()?;
	//	std::str::from_utf8(&msg).unwrap(),
	crypto::verify_signature(
		&msg,
		&crypto::signature_from_string(&proof.recipient_sig).unwrap(),
		&recipient_pubkey,
	)
	.map_err(|e| ErrorKind::TxProofVerifySignature(format!("{}", e)))?;

	let sender_pubkey = proof.sender_address.public_key()?;

	crypto::verify_signature(
		&msg,
		&crypto::signature_from_string(&proof.sender_sig).unwrap(),
		&sender_pubkey,
	)
	.map_err(|e| ErrorKind::TxProofVerifySignature(format!("{}", e)))?;

	let my_address_pubkey = proofaddress::payment_proof_address_pubkey(&keychain)?;
	let sender_mine = my_address_pubkey == sender_pubkey;
	let recipient_mine = my_address_pubkey == recipient_pubkey;

	Ok((sender_mine, recipient_mine))
}
