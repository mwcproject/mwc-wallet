// Copyright 2021 The Mwc Develope;
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

use crate::mwc_core::core::hash::Hashed;
use crate::mwc_core::core::{Output, OutputFeatures, Transaction};
use crate::mwc_core::libtx::proof;
use crate::mwc_keychain::ViewKey;
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::Mutex;
use crate::proof::crypto::Hex;

use crate::api_impl::owner_updater::StatusMessage;
use crate::mwc_keychain::{BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use crate::mwc_util::secp::key::PublicKey;
use crate::mwc_util::secp::Message;
use crate::mwc_util::secp::Secp256k1;
use crate::mwc_util::secp::Signature;

use crate::internal::{keys, scan, selection, tx, updater};
use crate::slate::{PaymentInfo, Slate};
use crate::types::{
	AcctPathMapping, Context, NodeClient, OutputData, TxLogEntry, WalletBackend, WalletInfo,
	FLAG_NEW_WALLET,
};
use crate::Error;
#[cfg(feature = "grin_proof")]
use crate::PaymentProof;
use crate::{
	wallet_lock, BuiltOutput, InitTxArgs, IssueInvoiceTxArgs, NodeHeightResult,
	OutputCommitMapping, OwnershipProof, OwnershipProofValidation, PubKeySignature,
	RetrieveTxQueryArgs, ScannedBlockInfo, TxLogEntryType, ViewWallet, WalletInst,
	WalletLCProvider,
};

use crate::proof::tx_proof::{pop_proof_for_slate, TxProof};
use digest::Digest;
use ed25519_dalek::Keypair as DalekKeypair;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::Signer;
use sha2::Sha256;
use signature::Verifier;
use std::cmp;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::Arc;

const USER_MESSAGE_MAX_LEN: usize = 1000; // We can keep messages as long as we need unless the slate will be too large to operate. 1000 symbols should be enough to keep everybody happy
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_util::from_hex;

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

/// Hash of the wallet root public key
pub fn get_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	use mwc_wallet_util::mwc_util::ToHex;

	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let root_public_key = keychain.public_root_key();
	let rewind_hash = ViewKey::rewind_hash(keychain.secp(), root_public_key).to_hex();
	Ok(rewind_hash)
}

/// Retrieve the MQS address for the wallet
pub fn get_mqs_address<'a, L, C, K>(
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

/// Retrieve TOR or public wallet address
pub fn get_wallet_public_address<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<DalekPublicKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let k = w.keychain(keychain_mask)?;
	let secret = proofaddress::payment_proof_address_secret(&k, None)?;
	let tor_pk = proofaddress::secret_2_tor_pub(&secret)?;
	Ok(tor_pk)
}

/// Refresh outputs/tx states of the wallet. Resync with a blockchain data
pub fn perform_refresh_from_node<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<bool, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let validated = update_wallet_state(wallet, keychain_mask, status_send_channel)?;

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
	wallet_lock!(wallet_inst, w);

	let mut validated = false;
	if refresh_from_node {
		validated = perform_refresh_from_node(&mut **w, keychain_mask, status_send_channel)?;
	}

	let parent_key_id = w.parent_key_id();

	let mut tx: Option<TxLogEntry> = None;
	if tx_id.is_some() {
		let mut txs = updater::retrieve_txs(
			&mut **w,
			keychain_mask,
			tx_id,
			None,
			None,
			Some(&parent_key_id),
			false,
			None,
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
	query_args: Option<RetrieveTxQueryArgs>,
	show_last_four_days: Option<bool>,
) -> Result<(bool, Vec<TxLogEntry>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let mut validated = false;
	if refresh_from_node {
		validated = perform_refresh_from_node(&mut **w, keychain_mask, status_send_channel)?;
	}

	let parent_key_id = w.parent_key_id();
	let txs = updater::retrieve_txs(
		&mut **w,
		keychain_mask,
		tx_id,
		tx_slate_id,
		query_args,
		Some(&parent_key_id),
		false,
		None,
		None,
		show_last_four_days,
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
	wallet_lock!(wallet_inst, w);

	let mut validated = false;
	if refresh_from_node {
		validated = perform_refresh_from_node(&mut **w, keychain_mask, status_send_channel)?;
	}

	let parent_key_id = w.parent_key_id();
	let wallet_info = updater::retrieve_info(&mut **w, &parent_key_id, minimum_confirmations)?;
	Ok((validated, wallet_info))
}

/// Retrieve payment proof
#[cfg(feature = "grin_proof")]
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
		return Err(Error::PaymentProofRetrieval(
			"Transaction ID or Slate UUID must be specified".to_owned(),
		));
	}
	let txs = retrieve_txs(
		wallet_inst,
		keychain_mask,
		status_send_channel,
		refresh_from_node,
		tx_id,
		tx_slate_id,
		None,
		None,
	)?;
	if txs.1.len() != 1 {
		return Err(Error::PaymentProofRetrieval(
			"Transaction doesn't exist".to_owned(),
		));
	}
	// Pull out all needed fields, returning an error if they're not present
	let tx = txs.1[0].clone();
	let proof = match tx.payment_proof {
		Some(p) => p,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Transaction does not contain a payment proof".to_owned(),
			));
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
			return Err(Error::PaymentProofRetrieval(
				"Transaction does not contain kernel excess".to_owned(),
			));
		}
	};
	let r_sig = match proof.receiver_signature {
		Some(e) => e,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Proof does not contain receiver signature ".to_owned(),
			));
		}
	};
	let s_sig = match proof.sender_signature {
		Some(e) => e,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Proof does not contain sender signature ".to_owned(),
			));
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
	tx_slate_id: Option<Uuid>,
) -> Result<TxProof, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if id.is_none() && tx_slate_id.is_none() {
		return Err(Error::PaymentProofRetrieval(
			"Transaction ID or Slate UUID must be specified".into(),
		));
	}
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let txs: Vec<TxLogEntry> = updater::retrieve_txs(
		&mut **w,
		None,
		id,
		tx_slate_id,
		None,
		Some(&parent_key_id),
		false,
		None,
		None,
		None,
	)
	.map_err(|e| Error::StoredTransactionError(format!("{}", e)))?;

	let tx_name = match id {
		Some(id) => id.to_string(),
		None => match tx_slate_id {
			Some(id) => format!("{}", id),
			None => "Unknown".into(),
		},
	};

	if txs.len() == 0 {
		return Err(Error::GenericError(format!(
			"Unable to find tx, {}",
			tx_name
		)))?;
	}
	// in case of many (self send) the first transaction is what we need
	let uuid = txs[0].tx_slate_id.ok_or_else(|| {
		Error::GenericError(format!("Unable to find slateId for txId, {}", tx_name))
	})?;
	let proof = TxProof::get_stored_tx_proof(w.get_data_file_dir(), &uuid.to_string())
		.map_err(|e| Error::TransactionHasNoProof(format!("{}", e)))?;
	return Ok(proof);
}

/// Initiate tx as sender
/// Caller is responsible for wallet refresh
pub fn init_send_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: &InitTxArgs,
	use_test_rng: bool,
	routputs: usize, // Number of resulting outputs. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match &args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.clone())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match &args.message {
		Some(m) => {
			let mut m = m.clone();
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let compact_slate =
		args.slatepack_recipient.is_some() || args.target_slate_version.clone().unwrap_or(0) >= 4;

	let mut slate = tx::new_tx_slate(
		&mut *w,
		args.amount,
		2,
		use_test_rng,
		args.ttl_blocks,
		compact_slate,
	)?;

	// if we just want to estimate, don't save a context, just send the results
	// back
	if let Some(true) = args.estimate_only {
		let (total, fee) = tx::estimate_send_tx(
			&mut *w,
			args.amount,
			args.amount_includes_fee.unwrap_or(false),
			&args.min_fee,
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

	// Updating height because it is lookup height for the kernel
	slate.height = w.w2n_client().get_chain_tip()?.0;
	let h = slate.height;
	let mut context = if args.late_lock.unwrap_or(false) {
		if !slate.compact_slate {
			return Err(Error::GenericError(
				"Lock later feature available only with a slatepack (compact slate) model"
					.to_string(),
			));
		}

		tx::create_late_lock_context(
			&mut *w,
			keychain_mask,
			&mut slate,
			h,
			&args,
			&parent_key_id,
			use_test_rng,
			0,
		)?
	} else {
		tx::add_inputs_to_slate(
			&mut *w,
			keychain_mask,
			&mut slate,
			&args.min_fee,
			None,
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
			args.amount_includes_fee.unwrap_or(false),
		)?
	};

	// Payment Proof, add addresses to slate and save address
	// TODO: Note we only use single derivation path for now,
	// probably want to allow sender to specify which one
	// sender_a has to in MQS format because we need Normal public key to sign, dalek will not work
	let k = w.keychain(keychain_mask)?;
	let sender_a = proofaddress::payment_proof_address(&k, proofaddress::ProofAddressType::MQS)?;

	if let Some(a) = &args.address {
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

	if let Some(a) = &args.payment_proof_recipient_address {
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_a,
			receiver_address: a.clone(),
			receiver_signature: None,
		});

		context.payment_proof_derivation_index = Some(proofaddress::get_address_index());
	} else {
		debug!("There is no payment proof recipient address");
	}

	// mwc713 payment proof support.
	context.input_commits = slate.tx_or_err()?.inputs_committed();

	for output in slate.tx_or_err()?.outputs() {
		context.output_commits.push(output.commitment());
	}

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;

		// We need to create transaction now, so user can cancel transaction and delete the context that we are saving below
		// If it is late lock - it is needed for sure.
		// If not late lock - still better to create because we don't want to have stale context in any case

		// Note, this transaction will be overwritten with more details at lock_tx_content.
		// This record for cancellation

		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, log_id);
		t.tx_slate_id = Some(slate.id);
		t.fee = Some(context.fee);
		t.ttl_cutoff_height = slate.ttl_cutoff_height.clone();
		if t.ttl_cutoff_height == Some(0) {
			t.ttl_cutoff_height = None;
		}
		t.address = args.address.clone();
		t.kernel_lookup_min_height = Some(slate.height);

		t.num_inputs = 0;
		t.input_commits = vec![];
		t.amount_debited = slate.amount;

		// write the output representing our change
		t.num_outputs = 0;
		t.output_commits = vec![];
		t.amount_credited = 0;
		batch.save_tx_log_entry(t, &parent_key_id)?;

		batch.save_private_context(slate.id.as_bytes(), 0, &context)?;
		batch.commit()?;
	}

	Ok(slate)
}

/// Initiate a transaction as the recipient (invoicing)
pub fn issue_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: &IssueInvoiceTxArgs,
	use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match &args.dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.clone())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match &args.message {
		Some(m) => {
			let mut m = m.clone();
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let compact_slate = args.slatepack_recipient.is_some();
	let mut slate = tx::new_tx_slate(&mut *w, args.amount, 2, use_test_rng, None, compact_slate)?;
	let chain_tip = slate.height; // it is fresh slate, height is a tip
	let context = tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		chain_tip,
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

	Ok(slate)
}

/// Generate Floonet fouset Invoce slate
pub fn generate_invoice_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if global::is_mainnet() {
		return Err(Error::FaucetRequestInvalidNetwork);
	}

	let parent_key_id = w.parent_key_id();

	let mut slate = tx::new_tx_slate(&mut *w, amount, 2, false, None, false)?;
	let chain_tip = slate.height; // it is fresh slate, height is a tip
	let context = tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		chain_tip,
		None,
		None,
		None,
		&parent_key_id,
		0,
		None,
		true,
		false,
		1,
	)?;

	Ok((slate, context))
}

/// Receive an invoice tx, essentially adding inputs to whatever
/// output was specified
/// Caller is responsible for wallet refresh
pub fn process_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	args: &InitTxArgs,
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
	let parent_key_id = match &args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.clone())?;
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
		None,
		Some(&parent_key_id),
		use_test_rng,
		None,
		None,
		None,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxSent {
			return Err(Error::TransactionAlreadyReceived(ret_slate.id.to_string()));
		}
		if t.tx_type == TxLogEntryType::TxSentCancelled {
			return Err(Error::TransactionWasCancelled(ret_slate.id.to_string()));
		}
	}

	let message = match &args.message {
		Some(m) => {
			let mut m = m.clone();
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	// update slate current height
	let (height, _, _) = w.w2n_client().get_chain_tip()?;
	ret_slate.height = height;

	// update ttl if desired
	if let Some(b) = &args.ttl_blocks {
		ret_slate.ttl_cutoff_height = Some(ret_slate.height + b);
	}

	// if self sending, make sure to store 'initiator' keys
	let context_res = w.get_private_context(keychain_mask, slate.id.as_bytes(), 0); // See issue_invoice_tx for sender (self)

	let mut context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut ret_slate,
		&args.min_fee,
		None,
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
		false,
	)?;

	if slate.compact_slate {
		let keychain = w.keychain(keychain_mask)?;

		// Add our contribution to the offset
		if context_res.is_ok() {
			// Self sending: don't correct for inputs and outputs
			// here, as we will do it during finalization.
			let mut tmp_context = context.clone();
			tmp_context.input_ids.clear();
			tmp_context.output_ids.clear();
			ret_slate.adjust_offset(&keychain, &mut tmp_context)?;
		} else {
			ret_slate.adjust_offset(&keychain, &mut context)?;
		}

		// needs to be stored as we're removing sig data for return trip. this needs to be present
		// when locking transaction context and updating tx log with excess later
		context.calculated_excess = Some(ret_slate.calc_excess(keychain.secp())?);

		// if self-sending, merge contexts
		if let Ok(c) = context_res {
			context.initial_sec_key = c.initial_sec_key;
			context.initial_sec_nonce = c.initial_sec_nonce;
			context.fee = c.fee;
			context.amount = c.amount;
			for o in c.output_ids.iter() {
				context.output_ids.push(o.clone());
			}
			for i in c.input_ids.iter() {
				context.input_ids.push(i.clone());
			}
		}

		selection::repopulate_tx(
			&mut *w,
			keychain_mask,
			&mut ret_slate,
			&context,
			false,
			use_test_rng,
		)?;
	}

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		// Participant id 1 for mwc713 compatibility
		batch.save_private_context(ret_slate.id.as_bytes(), 1, &context)?;
		batch.commit()?;
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
	use_test_rng: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context = w
		.get_private_context(keychain_mask, slate.id.as_bytes(), participant_id)
		.map_err(|_| Error::TransactionWasFinalizedOrCancelled(format!("{}", slate.id)))?;
	let mut excess_override = None;

	let mut sl = slate.clone();

	if slate.compact_slate {
		selection::repopulate_tx(
			&mut *w,
			keychain_mask,
			&mut sl,
			&context,
			true,
			use_test_rng,
		)?;

		if sl.participant_data.len() == 1 {
			// purely for invoice workflow, payer needs the excess back temporarily for storage
			excess_override = context.calculated_excess;
		}
	}

	let height = w.w2n_client().get_chain_tip()?.0;
	selection::lock_tx_context(
		&mut *w,
		keychain_mask,
		&sl,
		height,
		&context,
		address,
		excess_override,
	)
}

/// Finalize slate
/// Context needed for mwc713 proof of sending funds through mwcmqs
/// Note: do_proof will be used if proof data exist. It is needed to disable proof if it is not needed (MWCMQS case). Specify true if you don't know
pub fn finalize_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	refresh_from_node: bool,
	use_test_rng: bool,
	do_proof: bool,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	sl.height = w.w2n_client().get_chain_tip()?.0;
	check_ttl(w, &sl, refresh_from_node)?;
	let mut context = w
		.get_private_context(keychain_mask, sl.id.as_bytes(), 0)
		.map_err(|_| Error::TransactionWasFinalizedOrCancelled(format!("{}", sl.id)))?;
	let keychain = w.keychain(keychain_mask)?;
	let parent_key_id = context.parent_key_id.clone();

	if let Some(args) = context.late_lock_args.take() {
		// Transaction was late locked, select inputs+change now
		// and insert into original context

		let mut temp_sl = tx::new_tx_slate(
			&mut *w,
			context.amount,
			2,
			false,
			args.ttl_blocks,
			slate.compact_slate,
		)?;
		temp_sl.height = sl.height;
		let temp_context = selection::build_send_tx(
			w,
			&keychain,
			&mut temp_sl,
			&args.min_fee,
			Some(context.fee),
			args.minimum_confirmations,
			args.max_outputs as usize,
			args.num_change_outputs as usize,
			args.selection_strategy_is_use_all,
			parent_key_id.clone(),
			0,
			use_test_rng,
			true,
			&args.outputs,
			1,
			args.exclude_change_outputs.unwrap_or(false),
			args.minimum_confirmations_change_outputs,
			args.message,
			false,
		)?;

		// Add inputs and outputs to original context
		context.input_ids = temp_context.input_ids;
		context.output_ids = temp_context.output_ids;

		// Store the updated context
		{
			let mut batch = w.batch(keychain_mask)?;
			batch.save_private_context(sl.id.as_bytes(), 0, &context)?;
			batch.commit()?;
		}

		// Now do the actual locking
		tx_lock_outputs(w, keychain_mask, &sl, args.address, 0, use_test_rng)?;
	}

	if slate.compact_slate {
		// Add our contribution to the offset
		sl.adjust_offset(&keychain, &mut context)?;

		selection::repopulate_tx(
			&mut *w,
			keychain_mask,
			&mut sl,
			&context,
			true,
			use_test_rng,
		)?;
	}

	tx::complete_tx(&mut *w, keychain_mask, &mut sl, 0, &context)?;
	tx::verify_slate_payment_proof(&mut *w, keychain_mask, &context, &sl, use_test_rng)?;
	tx::update_stored_tx(
		&mut *w,
		keychain_mask,
		#[cfg(feature = "grin_proof")]
		&context,
		&sl,
		false,
	)?;
	tx::update_message(&mut *w, keychain_mask, &sl)?;
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.delete_private_context(sl.id.as_bytes(), 0)?;
		batch.commit()?;
	}

	// If Proof available, we can store it at that point
	if let Some(mut proof) = pop_proof_for_slate(&slate.id) {
		// Have special flag for proofs because of MQS. In MQS proof can be saved for any transaction. If we don't want the proof, we are not saving it
		if do_proof {
			proof.amount = context.amount;
			proof.fee = context.fee;
			for input in &context.input_commits {
				proof.inputs.push(input.clone());
			}
			for output in &context.output_commits {
				proof.outputs.push(output.clone());
			}

			proof.store_tx_proof(w.get_data_file_dir(), &slate.id.to_string())?;
		}
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
	wallet_lock!(wallet_inst, w);
	if !perform_refresh_from_node(&mut **w, keychain_mask, status_send_channel)? {
		return Err(Error::TransactionCancellationError(
			"Can't contact running MWC node. Not Cancelling.",
		))?;
	}
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

/// Scan outputs with the rewind hash of a third-party wallet.
/// Help to retrieve outputs information that belongs it
pub fn scan_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	rewind_hash: String,
	start_height: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let is_hex = rewind_hash.chars().all(|c| c.is_ascii_hexdigit());
	let rewind_hash = rewind_hash.to_lowercase();
	if !(is_hex && rewind_hash.len() == 64) {
		let msg = format!("Invalid Rewind Hash");
		return Err(Error::RewindHash(msg));
	}

	wallet_lock!(wallet_inst, w);

	let tip = w.w2n_client().get_chain_tip()?;

	let start_height = match start_height {
		Some(h) => h,
		None => 1,
	};

	let info = scan::scan_rewind_hash(
		&mut **w,
		rewind_hash,
		start_height,
		tip.0,
		status_send_channel,
	)?;
	Ok(info)
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
	wallet_lock!(wallet_inst, w);

	w.w2n_client().reset_cache();

	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) =
		get_last_detect_last_scanned_block(&mut **w, keychain_mask, status_send_channel)?;

	if tip_height == 0 {
		return Err(Error::NodeNotReady)?;
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
		&mut **w,
		keychain_mask,
		delete_unconfirmed,
		start_height,
		tip_height,
		status_send_channel,
		true,
		do_full_outputs_refresh,
	)?;

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
	for output in w.archive_iter() {
		write_info(
			format!("Archived  {:?}", output),
			file.as_mut(),
			status_send_channel,
		);
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
			match w.get_stored_tx_by_uuid(&uuid_str, false) {
				Ok(t) => {
					write_info(
						format!("tx for {}: {:?}   Transaction: {:?}", uuid_str, tx_log, t),
						file.as_mut(),
						status_send_channel,
					);
				}
				Err(_) => write_info(
					format!("tx for {}: {:?}    Slate not found", uuid_str, tx_log),
					file.as_mut(),
					status_send_channel,
				),
			}
		}
	}

	for tx_log in w.tx_log_archive_iter() {
		// Checking if Slate is available
		if let Some(uuid) = tx_log.tx_slate_id {
			let uuid_str = uuid.to_string();
			match w.get_stored_tx_by_uuid(&uuid_str, true) {
				Ok(t) => {
					write_info(
						format!(
							"Archived tx for {}: {:?}   Transaction: {:?}",
							uuid_str, tx_log, t
						),
						file.as_mut(),
						status_send_channel,
					);
				}
				Err(_) => write_info(
					format!(
						"Archived tx for {}: {:?}    Slate not found",
						uuid_str, tx_log
					),
					file.as_mut(),
					status_send_channel,
				),
			}
		} else {
			write_info(
				format!("Archived tx {:?}", tx_log),
				file.as_mut(),
				status_send_channel,
			);
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
fn get_last_detect_last_scanned_block<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(u64, String, ScannedBlockInfo, bool), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Wallet update logic doesn't handle truncating of the blockchain. That happen when node in sync or in reorg-sync
	// In this case better to inform user and do nothing. Sync is useless in any case.
	let (tip_height, tip_hash, _) = match wallet.w2n_client().get_chain_tip() {
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

	let mut neeed_init_last_scaned = false;
	{
		// Checking if keychain mask correct. Issue that sometimes update_wallet_state doesn't need it and it is a security problem
		let mut batch = wallet.batch(keychain_mask)?;
		if batch.load_flag(FLAG_NEW_WALLET, true)? {
			neeed_init_last_scaned = true;
		}
		batch.commit()?;
	}

	if neeed_init_last_scaned {
		// Let's still scan for last 100 blocks. That might be a mining wallet like tests has.
		if tip_height > 100 {
			// let's find commit's/txs min heights
			let mut max_height = tip_height - 100;
			for output in wallet.iter() {
				let h = output.height.saturating_sub(100);
				if h < max_height {
					max_height = h;
				}
			}

			let header = wallet.w2n_client().get_header_info(max_height)?;
			let blocks: Vec<ScannedBlockInfo> =
				vec![ScannedBlockInfo::new(header.height, header.hash)];

			let mut batch = wallet.batch(keychain_mask)?;
			batch.save_last_scanned_blocks(header.height, &blocks)?;
			batch.commit()?;
		}
	}

	let blocks = wallet.last_scanned_blocks()?;

	// If the server height is less than our confirmed height, don't apply
	// these changes as the chain is syncing, incorrect or forking
	if tip_height == 0
		|| tip_height < blocks.first().map(|b| b.height).unwrap_or(0)
			&& !(tip_height >= 694859 && tip_height < 707100)
	// This heights range is matching expected switch from one branch to another.
	{
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
		if bl.height > tip_height {
			continue; // Possible because of the parch (switch from branches)
		}
		if let Ok(hdr_info) = wallet.w2n_client().get_header_info(bl.height) {
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
pub fn update_wallet_state<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<bool, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) =
		get_last_detect_last_scanned_block(wallet, keychain_mask, status_send_channel)?;

	if tip_height == 0 {
		return Ok(false);
	}

	if has_reorg {
		wallet.w2n_client().reset_cache(); // let's reset cach to be safe

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
		let mut step = 4;

		while blocks.last().unwrap().height.saturating_sub(step) > last_scanned_block.height {
			let h = blocks.last().unwrap().height.saturating_sub(step);
			let hdr = wallet.w2n_client().get_header_info(h)?;
			blocks.push(ScannedBlockInfo::new(h, hdr.hash));
			step *= 2;
		}
		// adding last_scanned_block.height not needed
	}

	scan::scan(
		wallet,
		keychain_mask,
		false,
		last_scanned_block.height,
		tip_height,
		status_send_channel,
		show_progress,
		has_reorg,
	)?;

	// Note: retry logic, if tip was changed, is not needed, Problem that for busy wallet, like miner it could take a while.
	// Try to make optional, goes through the code and found that for all branches it is not critical.
	{
		// checking if node is online
		if wallet.w2n_client().get_chain_tip().is_ok() {
			// Since we are still online, we can save the scan status
			{
				let mut batch = wallet.batch(keychain_mask)?;
				batch.save_last_scanned_blocks(last_scanned_block.height, &blocks)?;
				batch.commit()?;
			}
			return Ok(true);
		}
	}

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
			return Err(Error::TransactionExpired);
		}
	}
	Ok(())
}

/// Verify/validate arbitrary payment proof
/// Returns (whether this wallet is the sender, whether this wallet is the recipient)
#[cfg(feature = "grin_proof")]
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
			return Err(Error::PaymentProof(format!(
				"Error retrieving kernel from chain: {}",
				e
			)));
		}
		Ok(None) => {
			return Err(Error::PaymentProof(format!(
				"Transaction kernel with excess {:?} not found on chain",
				proof.excess
			)));
		}
		Ok(Some(_)) => {}
	};

	// Check Sigs
	let recipient_pubkey = proof.recipient_address.public_key()?;
	//	std::str::from_utf8(&msg).unwrap(),
	crypto::verify_signature(
		&msg,
		&crypto::signature_from_string(&proof.recipient_sig, keychain.secp()).unwrap(),
		&recipient_pubkey,
		keychain.secp(),
	)
	.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;

	let sender_pubkey = proof.sender_address.public_key()?;

	crypto::verify_signature(
		&msg,
		&crypto::signature_from_string(&proof.sender_sig, keychain.secp()).unwrap(),
		&sender_pubkey,
		keychain.secp(),
	)
	.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;

	let my_address_pubkey = proofaddress::payment_proof_address_pubkey(&keychain)?;
	let sender_mine = my_address_pubkey == sender_pubkey;
	let recipient_mine = my_address_pubkey == recipient_pubkey;

	Ok((sender_mine, recipient_mine))
}

/// Generate signatures for root public keym tor address PK and MQS PK.
pub fn generate_ownership_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	message: String,
	include_public_root_key: bool,
	include_tor_address: bool,
	include_mqs_address: bool,
) -> Result<OwnershipProof, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if message.is_empty() {
		return Err(Error::GenericError(
			"Not defines message to sign".to_string(),
		));
	}

	if !include_public_root_key && !include_tor_address && !include_mqs_address {
		return Err(Error::GenericError(
			"No keys are selected to include into the ownership proof".to_string(),
		));
	}

	let network = if global::is_mainnet() {
		"mainnet"
	} else {
		"floonet"
	};
	let mut message2sign = String::new();
	message2sign.push_str(network);
	message2sign.push('|');
	message2sign.push_str(message.as_str());

	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let secp = keychain.secp();

	if include_public_root_key {
		let root_public_key = keychain.public_root_key();
		let root_public_key = root_public_key.to_hex();
		message2sign.push('|');
		message2sign.push_str(root_public_key.as_str());
	}

	if include_tor_address {
		let secret = proofaddress::payment_proof_address_secret(&keychain, None)?;
		let tor_pk = proofaddress::secret_2_tor_pub(&secret)?;
		let tor_pk = tor_pk.to_hex();
		message2sign.push('|');
		message2sign.push_str(tor_pk.as_str());
	}

	if include_mqs_address {
		let mqs_pub_key: PublicKey = proofaddress::payment_proof_address_pubkey(&keychain)?;
		let mqs_pub_key = mqs_pub_key.to_hex();
		message2sign.push('|');
		message2sign.push_str(mqs_pub_key.as_str());
	}

	// message to sign is ready. Now we can go forward and generate signatures for all public keys
	let mut hasher = Sha256::new();
	hasher.update(message2sign.as_bytes());
	let message_hash = hasher.finalize();

	// generating the signatures for message
	let wallet_root = if include_public_root_key {
		let secret = keychain.private_root_key();
		let signature = secp
			.sign(
				&Message::from_slice(message_hash.as_slice()).map_err(|e| {
					Error::GenericError(format!("Unable to build a message, {}", e))
				})?,
				&secret,
			)
			.map_err(|e| Error::from(e))?;
		Some(PubKeySignature {
			public_key: keychain.public_root_key().to_hex(),
			signature: signature.to_hex(),
		})
	} else {
		None
	};

	let tor_address = if include_tor_address {
		let secret = proofaddress::payment_proof_address_secret(&keychain, None)?;
		let secret = DalekSecretKey::from_bytes(&secret.0)
			.map_err(|e| Error::GenericError(format!("Unable build dalek public key, {}", e)))?;
		let public = DalekPublicKey::from(&secret);
		let keypair = DalekKeypair { secret, public };
		let signature = keypair
			.try_sign(message_hash.as_slice())
			.map_err(|e| Error::GenericError(format!("Unable build dalek signature, {}", e)))?;
		Some(PubKeySignature {
			public_key: public.to_hex(),
			signature: signature.to_hex(),
		})
	} else {
		None
	};

	let mqs_address = if include_mqs_address {
		let secret = proofaddress::payment_proof_address_secret(&keychain, None)?;
		let signature = secp
			.sign(
				&Message::from_slice(message_hash.as_slice()).map_err(|e| {
					Error::GenericError(format!("Unable to build a message, {}", e))
				})?,
				&secret,
			)
			.map_err(|e| Error::from(e))?;
		let mqs_pub_key = PublicKey::from_secret_key(&secp, &secret)?;
		Some(PubKeySignature {
			public_key: mqs_pub_key.to_hex(),
			signature: signature.to_hex(),
		})
	} else {
		None
	};

	Ok(OwnershipProof {
		network: network.to_string(),
		message,
		wallet_root,
		tor_address,
		mqs_address,
	})
}

/// Generate signatures for root public keym tor address PK and MQS PK.
pub fn validate_ownership_proof(proof: OwnershipProof) -> Result<OwnershipProofValidation, Error>
where
{
	if proof.message.is_empty() {
		return Err(Error::InvalidOwnershipProof(
			"message value is empty".to_string(),
		));
	}

	let mut result = OwnershipProofValidation::empty(proof.message.clone());

	let network = if global::is_mainnet() {
		"mainnet"
	} else {
		"floonet"
	};

	if proof.network != network {
		return Err(Error::InvalidOwnershipProof(format!(
			"This proof is generated for wrong network: {}",
			proof.network
		)));
	}

	result.network = network.to_string();

	let mut message2sign = String::new();
	message2sign.push_str(network);
	message2sign.push('|');
	message2sign.push_str(proof.message.as_str());

	let secp = Secp256k1::new();

	if let Some(wallet_root) = &proof.wallet_root {
		message2sign.push('|');
		message2sign.push_str(wallet_root.public_key.as_str());
	}
	if let Some(tor_address) = &proof.tor_address {
		message2sign.push('|');
		message2sign.push_str(tor_address.public_key.as_str());
	}
	if let Some(mqs_address) = &proof.mqs_address {
		message2sign.push('|');
		message2sign.push_str(mqs_address.public_key.as_str());
	}

	// message to sign is ready. Now we can go forward and generate signatures for all public keys
	let mut hasher = Sha256::new();
	hasher.update(message2sign.as_bytes());
	let message_hash = hasher.finalize();

	if let Some(wallet_root) = &proof.wallet_root {
		let public_key = PublicKey::from_hex(&wallet_root.public_key).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode wallet root public key, {}", e))
		})?;
		let signature = Signature::from_hex(&wallet_root.signature).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode wallet root signature, {}", e))
		})?;
		secp.verify(
			&Message::from_slice(message_hash.as_slice())
				.map_err(|e| Error::GenericError(format!("Unable to build a message, {}", e)))?,
			&signature,
			&public_key,
		)
		.map_err(|e| {
			Error::InvalidOwnershipProof(format!("wallet root signature is invalid, {}", e))
		})?;

		use mwc_wallet_util::mwc_util::ToHex;
		// we are good so far, reporting viewing key
		result.viewing_key = Some(ViewKey::rewind_hash(&secp, public_key).to_hex());
	}

	if let Some(mqs_address) = &proof.mqs_address {
		let public_key = PublicKey::from_hex(&mqs_address.public_key).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode mqs address public key, {}", e))
		})?;
		let signature = Signature::from_hex(&mqs_address.signature).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode mqs address signature, {}", e))
		})?;
		secp.verify(
			&Message::from_slice(message_hash.as_slice())
				.map_err(|e| Error::GenericError(format!("Unable to build a message, {}", e)))?,
			&signature,
			&public_key,
		)
		.map_err(|e| {
			Error::InvalidOwnershipProof(format!("mqs address signature is invalid, {}", e))
		})?;

		// we are good so far, reporting mwqs address
		let mqs_address = ProvableAddress::from_pub_key(&public_key);
		result.mqs_address = Some(mqs_address.public_key);
	}

	if let Some(tor_address) = &proof.tor_address {
		let public_key = from_hex(&tor_address.public_key).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address public key, {}", e))
		})?;

		let public_key = DalekPublicKey::from_bytes(&public_key).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address public key, {}", e))
		})?;

		let signature = from_hex(&tor_address.signature).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address signature, {}", e))
		})?;
		let signature = DalekSignature::from_bytes(&signature).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address signature, {}", e))
		})?;

		public_key
			.verify(message_hash.as_slice(), &signature)
			.map_err(|e| {
				Error::InvalidOwnershipProof(format!("tor address signature is invalid, {}", e))
			})?;

		// we are good so far, reporting tor address
		let tor_address = ProvableAddress::from_tor_pub_key(&public_key);
		result.tor_address = Some(tor_address.public_key);
	}

	return Ok(result);
}

///
pub fn self_spend_particular_output<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: OutputData,
	address: Option<String>,
	_current_height: u64,
	_minimum_confirmations: u64,
	_seperate_tx: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	scan::self_spend_particular_output(
		&mut **w,
		keychain_mask,
		output.value,
		output.commit.unwrap(),
		address,
		_current_height,
		_minimum_confirmations,
	)?;
	Ok(())
}

/// Builds an output for the wallet's next available key
pub fn build_output<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	features: OutputFeatures,
	amount: u64,
) -> Result<BuiltOutput, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let k = w.keychain(keychain_mask)?;

	let key_id = keys::next_available_key(&mut *w, None)?;

	let blind = k.derive_key(amount, &key_id, SwitchCommitmentType::Regular)?;
	let commit = k.secp().commit(amount, blind.clone())?;

	let proof_builder = proof::ProofBuilder::new(&k);
	let proof = proof::create(
		&k,
		&proof_builder,
		amount,
		&key_id,
		SwitchCommitmentType::Regular,
		commit,
		None,
	)?;

	let output = Output::new(features, commit, proof);

	Ok(BuiltOutput {
		blind: BlindingFactor::from_secret_key(blind),
		key_id: key_id,
		output: output,
	})
}
