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

use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::uuid::Uuid;

use crate::proof::crypto::Hex;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::{Output, OutputFeatures, Transaction};
use mwc_wallet_util::mwc_core::libtx::proof;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_keychain::ViewKey;
use mwc_wallet_util::mwc_util;

use mwc_wallet_util::mwc_crates::secp::EcdsaSignature;
use mwc_wallet_util::mwc_crates::secp::Message;
use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::{BlindingFactor, Identifier, Keychain, SwitchCommitmentType};

use crate::internal::chain_session::NodeReadSession;
use crate::internal::{keys, scan, selection, tx, updater};
use crate::slate::{PaymentInfo, Slate};
use crate::slatepack::validate_slatepack_size;
use crate::status::{send_status, StatusCallback, StatusMessage};
use crate::types::{
	AcctPathMapping, Context, NodeClient, StoredTxLocator, TxLogEntry, TxSession, WalletBackend,
	WalletInfo, WalletOutputBatch, FLAG_NEW_WALLET, U64_DATA_IDX_ADDRESS_INDEX,
};
use crate::Error;
use crate::SlateVersion;
use crate::{
	BuiltOutput, ChainTip, InitTxArgs, IssueInvoiceTxArgs, NodeHeightResult, OutputCommitMapping,
	OwnershipProof, OwnershipProofValidation, PubKeySignature, RetrieveTxQueryArgs,
	ScannedBlockInfo, TxLogEntryType, ViewWallet, WalletInst, WalletLCProvider, wallet_lock,
};

use crate::proof::tx_proof::{TxProof, pop_proof_for_slate, reserve_proof_for_slate};
use mwc_wallet_util::mwc_crates::digest::Digest;
use mwc_wallet_util::mwc_crates::ed25519_dalek::Signer;
use mwc_wallet_util::mwc_crates::sha2::Sha256;
use std::cmp;
use std::convert::TryInto;
use std::io::Write;
use std::sync::Arc;

const USER_MESSAGE_MAX_LEN: usize = 1000; // We can keep messages as long as we need unless the slate will be too large to operate. 1000 symbols should be enough to keep everybody happy
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::log::{debug, error, info};
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
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::new_acct_path(&mut *w, secp, keychain_mask, label)
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
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<Zeroizing<String>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	use mwc_wallet_util::mwc_util::ToHex;

	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(secp, keychain_mask)?;
	let root_public_key = keychain.public_root_key(secp)?;
	let rewind_hash = Zeroizing::new(ViewKey::rewind_hash(secp, root_public_key)?.to_hex());
	Ok(rewind_hash)
}

/// Retrieve the MQS address for the wallet
pub fn get_mqs_address<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<PublicKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let k = w.keychain(secp, keychain_mask)?;

	let address_index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"owner::get_mqs_address, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	let pub_key =
		proofaddress::payment_proof_address_pubkey(secp, w.get_context_id(), &k, address_index)?;
	Ok(pub_key)
}

/// Retrieve TOR or public wallet address
pub fn get_wallet_public_address<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<ed25519_dalek::VerifyingKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let k = w.keychain(secp, keychain_mask)?;

	let address_index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"owner::get_wallet_public_address, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	let secret =
		proofaddress::payment_proof_address_secret(secp, w.get_context_id(), &k, address_index)?;
	let tor_pk = proofaddress::secret_2_tor_pub(&secret)?;
	Ok(tor_pk)
}

/// retrieve outputs
///
/// Returns `(validated, refresh_anchor_height, outputs)`. When
/// `refresh_from_node` is set and the node update succeeds, `validated` is
/// true and `refresh_anchor_height` is the node tip the wallet state was
/// reconciled against; callers presenting heights or confirmation counts
/// must use that same snapshot rather than a second, possibly cached, tip
/// read. Otherwise both are left as `(false, 0)`.
pub fn retrieve_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	include_spent: bool,
	refresh_from_node: bool,
	tx_id: Option<u32>,
) -> Result<(bool, u64, Vec<OutputCommitMapping>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	// Authenticate before consulting transaction or output metadata. Otherwise a
	// missing tx_id returns TransactionDoesntExist before a masked wallet checks
	// the supplied mask, exposing transaction-id existence through error type.
	let _ = w.keychain(secp, keychain_mask)?;

	let mut validated = false;
	let mut refresh_anchor_height = 0;
	if refresh_from_node {
		let (v, h) = update_wallet_state(&mut **w, secp, keychain_mask, None)?;
		validated = v;
		refresh_anchor_height = h;
	}

	let parent_key_id = w.parent_key_id();

	let tx = if let Some(tx_id) = tx_id {
		let txs = updater::retrieve_txs(
			&mut **w,
			keychain_mask,
			Some(tx_id),
			None,
			None,
			Some(&parent_key_id),
			false,
			None,
			None,
			None,
		)?;

		Some(
			txs.into_iter()
				.next()
				.ok_or_else(|| Error::TransactionDoesntExist(tx_id.to_string()))?,
		)
	} else {
		None
	};

	Ok((
		validated,
		refresh_anchor_height,
		updater::retrieve_outputs(
			&mut **w,
			secp,
			keychain_mask,
			include_spent,
			tx.as_ref(),
			&parent_key_id,
			None,
			None,
		)?,
	))
}

/// Retrieve txs. Besides the `validated` flag, returns the chain tip height the
/// refreshed wallet state is anchored at. The anchor is `Some` only when the
/// refresh from the node succeeded; callers displaying confirmation counts must
/// use it instead of any independently sampled (and possibly stale) node height.
pub fn retrieve_txs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	query_args: Option<RetrieveTxQueryArgs>,
	show_last_four_days: Option<bool>,
) -> Result<(bool, Option<u64>, Vec<TxLogEntry>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	// Transaction-log reads do not otherwise need the keychain when a node
	// refresh is skipped. Authenticate masked-wallet callers before exposing any
	// stored transaction metadata.
	let _ = w.keychain(secp, keychain_mask)?;

	let mut validated = false;
	let mut refresh_anchor_height = None;
	if refresh_from_node {
		let (v, tip_height) = update_wallet_state(&mut **w, secp, keychain_mask, None)?;
		validated = v;
		if v {
			refresh_anchor_height = Some(tip_height);
		}
	}

	let parent_key_id = w.parent_key_id();

	// The four-day filter is a coarse display convenience (see the doc on
	// updater::retrieve_txs), so the validated refresh anchor is used as its
	// reference height: the listing is then filtered against the same height
	// the caller displays alongside `validated`. When the refresh was skipped
	// or failed validation there is no anchor; a single unvalidated tip sample
	// is acceptable because the cutoff is approximate by design, and
	// `validated` stays false, so the caller makes no consistency claim.
	let filter_tip_height = if show_last_four_days.unwrap_or(false) {
		match refresh_anchor_height {
			Some(anchor) => Some(anchor),
			None => Some(w.w2n_client().get_chain_tip()?.0),
		}
	} else {
		None
	};

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
		filter_tip_height,
	)?;

	Ok((validated, refresh_anchor_height, txs))
}

/// Retrieve summary info
pub fn retrieve_summary_info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	refresh_from_node: bool,
	minimum_confirmations: u64,
) -> Result<(bool, WalletInfo), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	// Summary reads do not otherwise need the keychain when a node refresh is
	// skipped. Authenticate masked-wallet callers before exposing balance data.
	let _ = w.keychain(secp, keychain_mask)?;

	let mut validated = false;
	if refresh_from_node {
		validated = update_wallet_state(&mut **w, secp, keychain_mask, None)?.0;
	}

	let parent_key_id = w.parent_key_id();
	let wallet_info = updater::retrieve_info(
		&mut **w,
		secp,
		keychain_mask,
		&parent_key_id,
		minimum_confirmations,
		vec![],
	)?;
	Ok((validated, wallet_info))
}

/// Retrieve a stored transaction proof after authenticating the wallet mask.
pub fn get_stored_tx_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
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
	// Stored proofs include message-decryption keys. Authenticate before looking
	// up any transaction metadata or reading the proof file.
	let _ = w.keychain(secp, keychain_mask)?;
	let parent_key_id = w.parent_key_id();
	let txs: Vec<TxLogEntry> = updater::retrieve_txs(
		&mut **w,
		keychain_mask,
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

	if txs.is_empty() {
		return Err(Error::GenericError(format!(
			"Unable to find tx, {}",
			tx_name
		)))?;
	}
	// in case of many (self send) the first transaction is what we need
	let uuid = txs.first().and_then(|tx| tx.tx_slate_id).ok_or_else(|| {
		Error::GenericError(format!("Unable to find slateId for txId, {}", tx_name))
	})?;
	TxProof::get_stored_tx_proof(w.get_data_file_dir(), &uuid.to_string())
}

/// Initiate tx as sender
/// Caller is responsible for wallet refresh
pub fn init_send_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	args: &InitTxArgs,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	routputs: usize, // Number of resulting outputs. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if args.late_lock.unwrap_or(false) && routputs != 1 {
		return Err(Error::GenericError(format!(
			"Late-lock transactions require exactly one recipient output, routputs={}",
			routputs
		)));
	}

	let parent_key_id = match &args.src_acct_name {
		Some(d) => {
			// An explicitly named source account must exist. Silently falling
			// back to the active account would select and lock outputs from an
			// account the caller did not name (e.g. a misspelled --from).
			match w.get_acct_path(d.clone())? {
				Some(p) => p.path,
				None => return Err(Error::UnknownAccountLabel(d.clone())),
			}
		}
		None => w.parent_key_id(),
	};

	let sanitized_message = match &args.message {
		Some(m) => {
			let mut m = m.clone();
			crate::types::truncate_to_char_boundary(&mut m, USER_MESSAGE_MAX_LEN);
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
		#[cfg(feature = "test-support")]
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
			args.max_outputs,
			args.num_change_outputs,
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
			secp,
			keychain_mask,
			&mut slate,
			h,
			&args,
			sanitized_message,
			&parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_rng,
			0,
		)?
	} else {
		tx::add_inputs_to_slate_round_1(
			&mut *w,
			secp,
			keychain_mask,
			&mut slate,
			&args.min_fee,
			None,
			args.minimum_confirmations,
			args.max_outputs,
			args.num_change_outputs,
			args.selection_strategy_is_use_all,
			&parent_key_id,
			0,
			sanitized_message,
			true,
			#[cfg(feature = "test-support")]
			use_test_rng,
			&args.outputs,
			routputs,
			args.exclude_change_outputs.unwrap_or(false),
			args.minimum_confirmations_change_outputs,
			args.amount_includes_fee.unwrap_or(false),
		)?
	};

	// Inputs and change are now known, but the recipient outputs are still
	// missing. Only a requested SP exchange needs this transport size budget.
	// Late locking budgets its provisional selection in create_late_lock_context.
	if args.slatepack_requested() && !args.late_lock.unwrap_or(false) {
		validate_slatepack_size(&slate, Some(&SlateVersion::SP), 0, routputs)?;
	}

	let address_index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"owner::init_send_tx, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	// Payment Proof, add addresses to slate and save address
	// TODO: Note we only use single derivation path for now,
	// probably want to allow sender to specify which one
	// sender_a has to in MQS format because we need Normal public key to sign, dalek will not work
	let k = w.keychain(secp, keychain_mask)?;
	let sender_a = proofaddress::payment_proof_address(
		secp,
		w.get_context_id(),
		&k,
		proofaddress::ProofAddressType::MQS,
		address_index,
	)?;

	if let Some(a) = &args.address {
		if a.eq("file_proof") {
			debug!("doing file proof");
			//in file proof, we are putting the same address both both sender_address and receiver_address
			slate.payment_proof = Some(PaymentInfo {
				sender_address: sender_a.clone(),
				receiver_address: sender_a.clone(),
				receiver_signature: None,
			});

			let mut batch = w.batch(secp, keychain_mask)?;
			let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
			context.payment_proof_derivation_index = Some(u32::try_from(index).map_err(|e| {
				Error::DataOverflow(format!(
					"owner::init_send_tx, wallet address index exceeds u32, index={} error={}",
					index, e
				))
			})?);
			// File proof: the sender's own address is the expected proof recipient
			context.payment_proof_recipient_address = Some(sender_a.public_key.clone());
		}
	}

	if let Some(a) = &args.payment_proof_recipient_address {
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_a,
			receiver_address: a.clone(),
			receiver_signature: None,
		});

		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		context.payment_proof_derivation_index = Some(u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"owner::init_send_tx, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?);
		// Remember the requested proof recipient so the returned slate can
		// be validated against it at finalize time
		context.payment_proof_recipient_address = Some(a.public_key.clone());
	} else {
		debug!("There is no payment proof recipient address");
	}

	// mwc713 payment proof support.
	context.input_commits = slate
		.tx_or_err()?
		.inputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	context.output_commits = slate
		.tx_or_err()?
		.outputs()
		.iter()
		.map(|o| o.commitment())
		.collect();

	// Reserve non-late sender inputs before returning from initialization, while
	// the wallet and global coin-selection locks are still held. The outputs
	// remain persistently Unspent during the remote exchange, so the TxSession
	// reservation is what prevents a concurrent send from selecting them.
	// In short: We need to reselect because of race conditions, somebody might already spent them.
	if !args.late_lock.unwrap_or(false) {
		if let Some(tx) = tx_session.as_deref_mut() {
			tx.set_input_commits(selection::input_commits_from_context(
				w,
				secp,
				keychain_mask,
				&context,
			)?)?;
		}
	}

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 0);
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
	t.update_messages(&slate.participant_messages());

	match tx_session {
		Some(tx_ses) => {
			tx_ses.set_context_participant(context, 0);
			tx_ses.set_tx_log_entry(t);
		}
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;

			// We need to create transaction now, so user can cancel transaction and delete the context that we are saving below
			// If it is late lock - it is needed for sure.
			// If not late lock - still better to create because we don't want to have stale context in any case

			// Note, this transaction will be overwritten with more details at lock_tx_content.
			// This record for cancellation

			let log_id = batch.next_tx_log_id(&parent_key_id)?;
			t.id = log_id;
			batch.save_tx_log_entry(t, &parent_key_id)?;

			batch.save_private_context(secp, slate.id.as_bytes(), 0, &context)?;
			batch.commit()?;
		}
	}

	Ok(slate)
}

/// Initiate a transaction as the recipient (invoicing)
pub fn issue_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	mut tx_session: Option<&mut TxSession>,
	args: &IssueInvoiceTxArgs,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match &args.dest_acct_name {
		Some(d) => {
			// An explicitly named destination account must exist. Silently
			// falling back to the active account would stage the invoice
			// output and transaction log under an unintended account.
			match w.get_acct_path(d.clone())? {
				Some(p) => p.path,
				None => return Err(Error::UnknownAccountLabel(d.clone())),
			}
		}
		None => w.parent_key_id(),
	};

	let message = match &args.message {
		Some(m) => {
			let mut m = m.clone();
			crate::types::truncate_to_char_boundary(&mut m, USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let compact_slate = args.slatepack_recipient.is_some();
	let mut slate = tx::new_tx_slate(
		&mut *w,
		args.amount,
		2,
		#[cfg(feature = "test-support")]
		use_test_rng,
		None,
		compact_slate,
	)?;
	let chain_tip = slate.height; // it is fresh slate, height is a tip
	if args.slatepack_recipient.is_some() {
		validate_slatepack_size(&slate, Some(&SlateVersion::SP), 0, num_outputs)?;
	}
	let context = tx::add_output_to_slate(
		&mut *w,
		secp,
		keychain_mask,
		&mut tx_session,
		&mut slate,
		chain_tip,
		args.address.clone(),
		None,
		&parent_key_id,
		0, // Participant 0 for mwc713 compatibility
		message,
		true,
		#[cfg(feature = "test-support")]
		use_test_rng,
		num_outputs,
	)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	match tx_session {
		Some(tx_ses) => {
			tx_ses.set_context_participant(context, 0);
		}
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;
			// Participant id is 0 for mwc713 compatibility
			batch.save_private_context(secp, slate.id.as_bytes(), 0, &context)?;
			batch.commit()?;
		}
	}

	Ok(slate)
}

/// Generate Floonet fouset Invoce slate
pub fn generate_invoice_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	mut tx_session: Option<&mut TxSession>,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if global::is_mainnet(w.get_context_id()) {
		return Err(Error::FaucetRequestInvalidNetwork);
	}

	let parent_key_id = w.parent_key_id();

	let mut slate = tx::new_tx_slate(
		&mut *w,
		amount,
		2,
		#[cfg(feature = "test-support")]
		false,
		None,
		false,
	)?;
	let chain_tip = slate.height; // it is fresh slate, height is a tip
	let context = tx::add_output_to_slate(
		&mut *w,
		secp,
		keychain_mask,
		&mut tx_session,
		&mut slate,
		chain_tip,
		None,
		None,
		&parent_key_id,
		0,
		None,
		true,
		#[cfg(feature = "test-support")]
		false,
		1,
	)?;

	Ok((slate, context))
}

fn private_context_if_present(
	context: Result<Context, Error>,
) -> Result<Option<Context>, Error> {
	match context {
		Ok(context) => Ok(Some(context)),
		Err(Error::PrivateContextNotFound(_)) => Ok(None),
		Err(error) => Err(error),
	}
}

fn map_tx_context_load_error(slate_id: &Uuid, error: Error) -> Error {
	match error {
		Error::PrivateContextNotFound(_) => {
			Error::TransactionWasFinalizedOrCancelled(slate_id.to_string())
		}
		error => error,
	}
}

/// Load a transaction context from an ephemeral session and bind it to the
/// operation which is about to consume it. A `TxSession` is intentionally not
/// keyed by UUID, so every consumer must enforce the participant and slate-id
/// invariants before using its signing secrets or staged wallet state.
fn context_from_tx_session(
	tx_session: &TxSession,
	slate_id: &Uuid,
	expected_participant_id: usize,
) -> Result<Context, Error> {
	let (context, participant_id) = tx_session
		.get_context_participant()
		.as_ref()
		.ok_or_else(|| Error::TransactionWasFinalizedOrCancelled(slate_id.to_string()))?;

	if *participant_id != expected_participant_id
		|| context.participant_id != expected_participant_id
	{
		return Err(Error::SlateValidation(format!(
			"transaction session participant mismatch, expected={} session={} context={}",
			expected_participant_id, participant_id, context.participant_id
		)));
	}

	let session_slate_id = tx_session
		.get_tx_log_entry()
		.as_ref()
		.and_then(|entry| entry.tx_slate_id.as_ref())
		.ok_or_else(|| {
			Error::SlateValidation("transaction session is missing its slate id".to_owned())
		})?;
	if session_slate_id != slate_id {
		return Err(Error::SlateValidation(format!(
			"response slate id does not match transaction session, expected={} actual={}",
			session_slate_id, slate_id
		)));
	}

	Ok(context.clone())
}

/// An empty session is the normal external-invoice case. A populated session
/// represents the issuer side of a self-invoice and must be bound to participant
/// zero and this exact Slate before it is used to validate the invoice.
fn invoice_initial_context_from_session(
	tx_session: &TxSession,
	slate_id: &Uuid,
) -> Result<Option<Context>, Error> {
	if tx_session.get_context_participant().is_none() {
		Ok(None)
	} else {
		context_from_tx_session(tx_session, slate_id, 0).map(Some)
	}
}

/// Bind the transaction elements of a locally issued invoice to the output
/// identifiers retained in its private issuer context. A normal invoice starts
/// with no inputs and exactly the issuer outputs. Compact transport may omit
/// those outputs, in which case `process_invoice_tx` reconstructs them from the
/// same context before signing.
fn validate_local_invoice_initial_transaction<'a, T: ?Sized, C, K>(
	w: &T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx = slate.tx_or_err()?;
	let initial_inputs = tx.inputs_committed()?.collect::<Result<Vec<_>, _>>()?;
	if !initial_inputs.is_empty() {
		return Err(Error::SlateValidation(
			"locally issued initial invoice contains unexpected inputs".to_owned(),
		));
	}

	let context_outputs = context.get_outputs();
	if context_outputs.is_empty() {
		return Err(Error::SlateValidation(
			"local invoice issuer context contains no outputs".to_owned(),
		));
	}
	let mut expected_output_commits = Vec::with_capacity(context_outputs.len());
	for (id, _, amount) in context_outputs {
		expected_output_commits.push(w.calc_commit(secp, keychain_mask, amount, &id)?);
	}

	// Compact slatepack transport is allowed to omit all transaction elements.
	// Any supplied output, however, must still be the one created by the issuer.
	if slate.compact_slate && tx.outputs().is_empty() {
		return Ok(());
	}
	if tx
		.outputs()
		.iter()
		.any(|output| output.features() != OutputFeatures::Plain)
	{
		return Err(Error::SlateValidation(
			"locally issued initial invoice altered issuer output features".to_owned(),
		));
	}

	let mut actual_output_commits: Vec<Commitment> =
		tx.outputs().iter().map(Output::commitment).collect();
	actual_output_commits.sort_unstable();
	expected_output_commits.sort_unstable();
	if actual_output_commits != expected_output_commits {
		return Err(Error::SlateValidation(
			"locally issued initial invoice altered issuer outputs".to_owned(),
		));
	}

	Ok(())
}

/// Reject unsupported invoice options before refreshing or changing wallet state.
pub fn validate_invoice_tx_args(args: &InitTxArgs) -> Result<(), Error> {
	if args.estimate_only == Some(true) {
		return Err(Error::GenericError(
			"estimate_only is not supported for invoice transactions; use init_send_tx with the invoice amount to estimate fees".to_owned(),
		));
	}
	if args.ttl_blocks.is_some() {
		return Err(Error::GenericError(
			"TTL is not supported for invoice transactions".to_owned(),
		));
	}
	if args.payment_proof_recipient_address.is_some() {
		return Err(Error::GenericError(
			"Payment proofs are not supported for invoice transactions".to_owned(),
		));
	}
	Ok(())
}

/// Receive an invoice tx, essentially adding inputs to whatever
/// output was specified
/// Caller is responsible for wallet refresh
pub fn process_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	args: &InitTxArgs,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	refresh_from_node: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_invoice_tx_args(args)?;

	let mut ret_slate = slate.clone();
	// The initial invoice slate is counterparty-controlled. Require the
	// two-party initial set this wallet implements before any key allocation
	// or signing: missing, duplicate, or extra participant records would enter
	// the aggregate nonce and blind sums used for the payer's partial
	// signature.
	ret_slate.validate_invoice_initial()?;
	// Participant messages are optional, but when present their signatures are
	// the only proof that the claimed issuer key authorized the text. Verify
	// them before selecting inputs or producing the payer partial signature.
	ret_slate.verify_messages(secp)?;
	let compact_invoice_output_omitted =
		ret_slate.compact_slate && ret_slate.tx_or_err()?.outputs().is_empty();
	check_ttl(w, &ret_slate, refresh_from_node)?;
	let parent_key_id = match &args.src_acct_name {
		Some(d) => {
			// An explicitly named source account must exist. Silently falling
			// back to the active account would fund the invoice payment from an
			// account the caller did not name.
			match w.get_acct_path(d.clone())? {
				Some(p) => p.path,
				None => return Err(Error::UnknownAccountLabel(d.clone())),
			}
		}
		None => w.parent_key_id(),
	};
	// Check the entire wallet history. retrieve_txs skips archived matches
	// when any active entry has this UUID, so an active receive could hide an
	// earlier invoice payment or cancellation from this replay check.
	let txs = w.tx_log_iter()?.chain(w.tx_log_archive_iter()?);
	for t in txs.filter(|t| t.tx_slate_id == Some(ret_slate.id)) {
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
			crate::types::truncate_to_char_boundary(&mut m, USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	// update slate current height
	let (height, _, _) = w.w2n_client().get_chain_tip()?;
	ret_slate.height = height;

	// Authenticate locally issued invoices against their issuer context. A
	// missing participant-0 context means no local issuer state is available;
	// every other load failure must be reported instead of mistaken for absence.
	let initial_context = match tx_session {
		Some(tx) => invoice_initial_context_from_session(tx, &ret_slate.id)?,
		None => private_context_if_present(w.get_private_context(
			secp,
			keychain_mask,
			slate.id.as_bytes(),
			0,
		))?,
	};
	if let Some(context) = initial_context.as_ref() {
		ret_slate.validate_invoice_initial_context(secp, context)?;
		validate_local_invoice_initial_transaction(&*w, secp, keychain_mask, &ret_slate, context)?;
	}
	let compact_invoice_output_remains_omitted =
		compact_invoice_output_omitted && initial_context.is_none();

	let mut context = tx::add_inputs_to_slate_round_1(
		&mut *w,
		secp,
		keychain_mask,
		&mut ret_slate,
		&args.min_fee,
		None,
		args.minimum_confirmations,
		args.max_outputs,
		args.num_change_outputs,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		1, // Participant id 1 for mwc713 compatibility
		message,
		false,
		#[cfg(feature = "test-support")]
		use_test_rng,
		&args.outputs,
		1,
		args.exclude_change_outputs.unwrap_or(false),
		args.minimum_confirmations_change_outputs,
		false,
	)?;

	let mut validation_slate = None;
	if slate.compact_slate {
		let keychain = w.keychain(secp, keychain_mask)?;

		// Apply the payer's complete contribution, including for self-invoices.
		// Finalization loads the separate participant-0 issuer context and adds
		// only that context's contribution. Keep its keys and outputs separate
		// so locking the payer cannot reassign the issuer output to payer change.
		ret_slate.adjust_offset(secp, &keychain, &context)?;

		// needs to be stored as we're removing sig data for return trip. this needs to be present
		// when locking transaction context and updating tx log with excess later
		context.calculated_excess = Some(ret_slate.calc_excess(secp)?);

		selection::repopulate_tx(
			&mut *w,
			secp,
			keychain_mask,
			tx_session,
			&mut ret_slate,
			&context,
			false,
			None,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;

		if let Some(issuer_context) = initial_context.as_ref() {
			// A local issuer's real output balances only after its offset has
			// been applied. Validate that completed transaction in a clone; the
			// response must retain only the payer offset so finalization adds
			// the issuer contribution exactly once.
			let mut complete_slate = ret_slate.clone();
			complete_slate.adjust_offset(secp, &keychain, issuer_context)?;
			selection::repopulate_tx(
				&mut *w,
				secp,
				keychain_mask,
				tx_session,
				&mut complete_slate,
				issuer_context,
				false,
				None,
				#[cfg(feature = "test-support")]
				use_test_rng,
			)?;
			validation_slate = Some(complete_slate);
		}
	}

	// The invoice body is counterparty-controlled. After compact-slate offset
	// adjustment/repopulation, validate its fee and every available transaction
	// element before producing the payer signature or publishing context and
	// reservation state. For an external compact invoice, reconstruct the omitted
	// issuer commitment for the kernel-sum check; its concrete output structure
	// and rangeproof are unavailable to the payer.
	tx::validate_invoice_slate(
		w.get_context_id(),
		secp,
		validation_slate.as_ref().unwrap_or(&ret_slate),
		1,
		compact_invoice_output_remains_omitted,
		&context,
	)?;
	if refresh_from_node {
		crate::transaction_preflight::check_slate(
			w.get_context_id(),
			w.w2n_client(),
			validation_slate.as_ref().unwrap_or(&ret_slate),
			secp,
			!compact_invoice_output_remains_omitted,
		)?;
	}
	// The validation clone changes only the deferred issuer offset and restores
	// its output. The participant keys, nonces and kernel message signed here
	// are the same ones whose balance and rangeproofs were checked above.
	ret_slate.fill_round_2(
		w.get_context_id(),
		secp,
		&context.sec_key,
		&context.sec_nonce,
		1,
	)?;

	// Updating context with inputs/outputs  Will need that for slate validation
	context.input_commits = ret_slate
		.tx_or_err()?
		.inputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	context.output_commits = ret_slate
		.tx_or_err()?
		.outputs()
		.iter()
		.map(|o| o.commitment())
		.collect();

	// Reserve selected inputs now, while the wallet lock that serializes coin
	// selection is still held. A TxSession owns its reservation directly; the
	// sessionless path binds the same commitments to the active SlateProcessGuard
	// returned by the public API. Until tx_lock_outputs, the database still marks
	// these outputs Unspent, so every supported path needs one of those owners.
	// In short: We need to reselect because of race conditions, somebody might already spent them.
	let selected_inputs = selection::input_commits_from_context(w, secp, keychain_mask, &context)?;
	match tx_session.as_deref_mut() {
		Some(tx) => tx.set_input_commits(selected_inputs)?,
		None => w.slate_process_tracker().reserve_inputs(
			ret_slate.id,
			selected_inputs
				.iter()
				.map(|(_id, _mmr, commit, _amount)| commit),
		)?,
	}

	// Save the aggsig context for when the finalized transaction returns.
	match tx_session {
		Some(tx) => {
			// Unlike an ordinary send, invoice payment historically deferred its
			// TxLogEntry until tx_lock_outputs. Bind the ephemeral context to the
			// invoice UUID now so a different response slate cannot consume it.
			if tx.get_tx_log_entry().is_none() {
				let mut log_entry =
					TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 0);
				log_entry.tx_slate_id = Some(ret_slate.id);
				log_entry.fee = Some(context.fee);
				log_entry.ttl_cutoff_height = ret_slate.ttl_cutoff_height;
				if log_entry.ttl_cutoff_height == Some(0) {
					log_entry.ttl_cutoff_height = None;
				}
				log_entry.address = args.address.clone();
				log_entry.kernel_lookup_min_height = Some(ret_slate.height);
				log_entry.amount_debited = ret_slate.amount;
				log_entry.update_messages(&ret_slate.participant_messages());
				tx.set_tx_log_entry(log_entry);
			}
			tx.set_context_participant(context, 1);
		}
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;
			// Participant id 1 for mwc713 compatibility.
			batch.save_private_context(secp, ret_slate.id.as_bytes(), 1, &context)?;
			batch.commit()?;
		}
	}

	Ok(ret_slate)
}

/// Lock sender outputs
pub fn tx_lock_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	address: Option<String>,
	participant_id: usize,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context = match tx_session {
		Some(tx) => context_from_tx_session(tx, &slate.id, participant_id)?,
		None => w
			.get_private_context(secp, keychain_mask, slate.id.as_bytes(), participant_id)
			.map_err(|error| map_tx_context_load_error(&slate.id, error))?,
	};
	lock_tx_outputs_with_context(
		w,
		secp,
		keychain_mask,
		tx_session,
		slate,
		address,
		&context,
		None,
		None,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)
}

/// Lock outputs using an already authenticated context. `context_update_participant`
/// requests that the supplied context be published atomically with the lock
/// state; ordinary pre-lock calls pass `None`, while late-lock finalization
/// passes the sender participant id after all response validation succeeds.
fn lock_tx_outputs_with_context<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	address: Option<String>,
	context: &Context,
	context_update_participant: Option<usize>,
	missing_output_height: Option<u64>,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	context.validate_slate(slate)?;

	let mut excess_override = None;

	let mut sl = slate.clone();

	if slate.compact_slate {
		// Ordinary compact locking is intentionally a two-stage rebuild. A
		// SendInitial Slatepack omits the sender's transaction elements, and the
		// sender's change is not written to the backend/session until
		// lock_tx_context below. Therefore this first, provisional slate may omit
		// that change when missing_output_height is None. Finalization calls
		// repopulate_tx again after the output record exists and replaces the
		// stored transaction with the complete one. Late-lock passes a height
		// because it must build and validate the complete transaction before any
		// wallet state is written.
		selection::repopulate_tx(
			&mut *w,
			secp,
			keychain_mask,
			tx_session,
			&mut sl,
			context,
			true,
			missing_output_height,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;

		// Purely for the invoice workflow: the payer needs the excess back
		// temporarily for storage. calculated_excess is set only when this
		// wallet paid a compact invoice (process_invoice_tx), which is exactly
		// when the override applies. The response participant count is not a
		// usable signal: Slate::validate_invoice_response merges the locally
		// retained payer record back into compact responses.
		if context.calculated_excess.is_some() {
			excess_override = context.calculated_excess;
		}
	}

	// Reject a peer-altered feature before publishing any input locks. Compact
	// slates are checked after their sender inputs have been reconstructed above.
	selection::validate_context_input_features(&*w, secp, keychain_mask, &sl, context)?;

	let height = w.w2n_client().get_chain_tip()?.0;
	selection::lock_tx_context(
		&mut *w,
		secp,
		keychain_mask,
		tx_session,
		&sl,
		height,
		context,
		address,
		excess_override,
		context_update_participant,
	)
}

/// Finalize slate
/// Context needed for mwc713 proof of sending funds through mwcmqs
/// Note: do_proof will be used if proof data exist. It is needed to disable proof if it is not needed (MWCMQS case). Specify true if you don't know
pub fn finalize_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	refresh_from_node: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	do_proof: bool,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	finalize_tx_with_output_version(
		w,
		secp,
		keychain_mask,
		tx_session,
		slate,
		refresh_from_node,
		#[cfg(feature = "test-support")]
		use_test_rng,
		do_proof,
		None,
	)
}

/// Finalize with a known response format. SP size validation runs on the
/// rebuilt transaction before committing late locks or consuming its context.
/// None leaves the output format to the caller of the unversioned API.
pub fn finalize_tx_with_output_version<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	refresh_from_node: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	do_proof: bool,
	output_version: Option<SlateVersion>,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	sl.height = if refresh_from_node {
		// Use one fresh tip for every chain-height-sensitive finalize decision.
		// In particular, late-lock input selection below must not reuse the
		// cached height sampled before TTL validation across a reorg.
		let height = w.w2n_client().get_chain_tip_fresh()?.0;
		check_ttl_with_height(sl.ttl_cutoff_height, || Ok(height))?;
		height
	} else {
		let height = w.w2n_client().get_chain_tip()?.0;
		check_ttl(w, &sl, false)?;
		height
	};
	let mut context = match tx_session {
		Some(tx) => context_from_tx_session(tx, &sl.id, 0)?,
		None => w
			.get_private_context(secp, keychain_mask, sl.id.as_bytes(), 0)
			.map_err(|error| map_tx_context_load_error(&sl.id, error))?,
	};

	context.validate_slate(slate)?;

	// Enforce the two-party participant invariants against the persisted
	// context before any locking or signing. Standalone finalize recovers only
	// the private context, so the original send slate is not available for
	// Slate::validate_send_response; the initiator record is checked against
	// context-derived public keys instead.
	slate.validate_send_response_context(secp, &context)?;

	let keychain = w.keychain(secp, keychain_mask)?;
	let parent_key_id = context.parent_key_id.clone();
	let mut preflight_checked = false;

	if let Some(args) = context.late_lock_args.clone() {
		// Build late-lock state on a private candidate. The original durable or
		// session context retains its retry instructions until the complete lock
		// plan has passed every peer-controlled validation.
		let mut candidate_context = context.clone();
		candidate_context.late_lock_args = None;

		let mut temp_sl = tx::new_tx_slate(
			&mut *w,
			context.amount,
			2,
			#[cfg(feature = "test-support")]
			false,
			args.ttl_blocks,
			slate.compact_slate,
		)?;
		temp_sl.height = sl.height;
		let temp_context = selection::build_send_tx(
			w,
			secp,
			&keychain,
			&mut temp_sl,
			&args.min_fee,
			Some(context.fee),
			args.minimum_confirmations,
			args.max_outputs,
			args.num_change_outputs,
			args.selection_strategy_is_use_all,
			parent_key_id.clone(),
			0,
			#[cfg(feature = "test-support")]
			use_test_rng,
			#[cfg(feature = "test-support")]
			true,
			&args.outputs,
			1,
			args.exclude_change_outputs.unwrap_or(false),
			args.minimum_confirmations_change_outputs,
			args.message,
			false,
		)?;

		candidate_context.input_ids = temp_context.input_ids;
		candidate_context.output_ids = temp_context.output_ids;
		candidate_context.output_build_heights = temp_context.output_build_heights;

		// Rebuild a complete candidate, including unpersisted change outputs,
		// and validate the peer signature, transaction balance, fees, kernel
		// policy and every rangeproof before any context or lock is published.
		let mut verify_slate = sl.clone();
		if verify_slate.compact_slate {
			verify_slate.adjust_offset(secp, &keychain, &candidate_context)?;
			selection::repopulate_tx(
				&mut *w,
				secp,
				keychain_mask,
				tx_session,
				&mut verify_slate,
				&candidate_context,
				true,
				Some(sl.height),
				#[cfg(feature = "test-support")]
				use_test_rng,
			)?;
		}
		// The candidate already contains all selected and received elements.
		validate_slatepack_size(&verify_slate, output_version.as_ref(), 0, 0)?;
		tx::validate_finalization_request(
			w.get_context_id(),
			secp,
			&verify_slate,
			0,
			&candidate_context,
		)?;
		tx::validate_slate_payment_proof(
			&mut *w,
			secp,
			keychain_mask,
			&candidate_context,
			&verify_slate,
		)?;
		if refresh_from_node {
			crate::transaction_preflight::check_slate(
				w.get_context_id(),
				w.w2n_client(),
				&verify_slate,
				secp,
				true,
			)?;
			preflight_checked = true;
		}

		// Publish the selected context in the same backend batch (or final
		// infallible session update) as its input locks, change outputs and log.
		lock_tx_outputs_with_context(
			w,
			secp,
			keychain_mask,
			tx_session,
			&sl,
			args.address,
			&candidate_context,
			Some(0),
			Some(sl.height),
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;
		context = candidate_context;
	}

	if slate.compact_slate {
		// Add our contribution to the offset
		sl.adjust_offset(secp, &keychain, &mut context)?;

		selection::repopulate_tx(
			&mut *w,
			secp,
			keychain_mask,
			tx_session,
			&mut sl,
			&context,
			true,
			None,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;
	}

	// V2/V3 JSON slates retain input features even though current core wire
	// transactions are commitment-only. Bind every feature-bearing sender input
	// to the canonical wallet output before producing the final signature.
	selection::validate_context_input_features(&*w, secp, keychain_mask, &sl, &context)?;
	// Recheck before signing: the peer may have added outputs, or the slate
	// may predate the initialization budget. V3 JSON has no SP size restriction.
	validate_slatepack_size(&sl, output_version.as_ref(), 0, 0)?;

	// The in-memory reservation prevents new local selection, but persistent
	// output status remains authoritative. Abort before producing our final
	// signature if a competing transaction committed while this exchange was
	// delayed.
	if let Some(tx) = tx_session.as_deref() {
		tx.validate_inputs(&*w, &sl.id)?;
	}

	if refresh_from_node && !preflight_checked {
		crate::transaction_preflight::check_slate(
			w.get_context_id(),
			w.w2n_client(),
			&sl,
			secp,
			true,
		)?;
	}

	tx::complete_tx(
		&mut *w,
		secp,
		keychain_mask,
		tx_session,
		&mut sl,
		0,
		&mut context,
	)?;
	let mut generated_proof = tx::verify_slate_payment_proof(
		&mut *w,
		secp,
		keychain_mask,
		&context,
		&sl,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)?;

	let proof_required = do_proof && context.payment_proof_recipient_address.is_some();
	let mut cached_proof_reservation = None;
	if do_proof {
		// MQS inserts its authenticated transport proof before invoking the slate
		// handler. Reserve that artifact until every fallible finalize step has
		// succeeded; the guard releases the reservation on storage/backend errors.
		cached_proof_reservation = reserve_proof_for_slate(w.get_context_id(), &slate.id)?;

		let proof_dir = w.get_data_file_dir().to_owned();
		let proof_id = slate.id.to_string();
		let store_proof = |proof: &mut TxProof| -> Result<(), Error> {
			proof.amount = context.amount;
			proof.fee = context.fee;
			proof.inputs = context.input_commits.clone();
			proof.outputs = context.output_commits.clone();

			// A requested proof must be durable before finalized wallet state can be
			// committed or its private context can be destroyed.
			proof.store_tx_proof(&proof_dir, &proof_id)
		};

		let proof_available = if sl.compact_slate {
			// MQS transport proofs are legacy, unversioned proofs. Although MQS can
			// carry a compact V3 slate, the payment-proof verifier deliberately
			// rejects that legacy proof format for compact slates. Prefer the
			// versioned proof generated from the finalized slate and keep the cache
			// reservation only so it is discarded after finalization succeeds.
			match generated_proof.as_mut() {
				Some(proof) => {
					store_proof(proof)?;
					true
				}
				None => false,
			}
		} else if let Some(reservation) = cached_proof_reservation.as_mut() {
			reservation.with_proof_mut(store_proof)?;
			true
		} else {
			match generated_proof.as_mut() {
				Some(proof) => {
					store_proof(proof)?;
					true
				}
				None => false,
			}
		};

		if !proof_available && proof_required {
			return Err(Error::TxProofUnavailable(format!(
				"proof data for transaction {} was not available",
				slate.id
			)));
		}
	} else {
		// Preserve the existing opt-out behavior: an explicitly unrequested
		// transport proof must not remain in the bounded cache indefinitely.
		let _ = pop_proof_for_slate(w.get_context_id(), &slate.id);
	}

	tx::update_stored_tx(&mut *w, secp, keychain_mask, tx_session, &sl, false)?;
	tx::update_message(&mut *w, secp, keychain_mask, tx_session, &sl)?;
	match tx_session {
		Some(tx) => tx.clear_context_participant(),
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;
			batch.delete_private_context(sl.id.as_bytes(), 0)?;
			batch.commit()?;
		}
	}
	if let Some(reservation) = cached_proof_reservation {
		reservation.commit();
	}

	Ok((sl, context))
}

/// cancel tx
pub fn cancel_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	if !update_wallet_state(&mut **w, secp, keychain_mask, None)?.0 {
		return Err(Error::TransactionCancellationError(
			"Can't contact running MWC node. Not Cancelling.",
		))?;
	}
	// The refresh above can perform TTL cancellation itself. The internal
	// cancellation operation is intentionally idempotent, so both that path and
	// an ordinary explicit cancellation report the same successful postcondition.
	let parent_key_id = w.parent_key_id();
	// Numeric transaction-log IDs are local to the active account, while a
	// slate UUID identifies the whole logical transaction and can have entries
	// under several parent keys (for example, a cross-account self-send).
	let parent_key_scope = match (tx_id.is_some(), tx_slate_id.is_some()) {
		(true, false) => Some(&parent_key_id),
		(false, true) => None,
		(false, false) => {
			return Err(Error::TransactionCancellationError(
				"Transaction is not defined. Please specify tx_id or tx_slate_id fields.",
			));
		}
		(true, true) => {
			return Err(Error::TransactionCancellationError(
				"Please specify only one of tx_id or tx_slate_id fields.",
			));
		}
	};
	tx::cancel_tx(
		&mut **w,
		secp,
		keychain_mask,
		parent_key_scope,
		tx_id,
		tx_slate_id,
	)
}

/// Resolve a stored transaction from an authoritative wallet transaction-log
/// entry. Numeric transaction IDs are scoped to the active account. An ID, a
/// Slate UUID, or a stored transaction filename is required; when multiple
/// locators are supplied, they must match the same entry. A supplied filename
/// is never opened directly.
pub fn get_stored_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	locator: &StoredTxLocator,
) -> Result<Option<Transaction>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if locator.id.is_none() && locator.tx_slate_id.is_none() && locator.stored_tx.is_none() {
		return Err(Error::StoredTransactionError(
			"transaction locator must include id, tx_slate_id, or stored_tx".to_owned(),
		));
	}

	let locator_description = format!(
		"id={:?}, tx_slate_id={:?}, stored_tx={:?}",
		locator.id, locator.tx_slate_id, locator.stored_tx
	);
	let parent_key_id = w.parent_key_id();
	let mut txs = updater::retrieve_txs(
		w,
		keychain_mask,
		locator.id,
		locator.tx_slate_id,
		None,
		Some(&parent_key_id),
		false,
		None,
		None,
		None,
	)?;
	if let Some(stored_tx) = locator.stored_tx.as_deref() {
		txs.retain(|entry| match entry.stored_tx.as_deref() {
			Some(authoritative_filename) => authoritative_filename == stored_tx,
			None => entry
				.tx_slate_id
				.map(|slate_id| format!("{}.mwctx", slate_id) == stored_tx)
				.unwrap_or(false),
		});
	}

	let entry = match txs.as_slice() {
		[entry] => entry,
		[] => return Err(Error::TransactionDoesntExist(locator_description)),
		_ => {
			return Err(Error::StoredTransactionError(format!(
				"multiple transaction-log entries found for {}",
				locator_description
			)));
		}
	};

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

/// Validate locally and preflight with the node, then publish the transaction.
/// Takes a client instead of the wallet so the wallet need not stay locked.
pub fn post_tx<'a, C>(
	context_id: u32,
	client: &C,
	tx: &Transaction,
	fluff: bool,
) -> Result<(), Error>
where
	C: NodeClient + 'a,
{
	let res = crate::transaction_preflight::prepare_transaction(context_id, client, tx)
		.and_then(|receipt| client.post_tx(tx, fluff, receipt));
	if let Err(e) = res {
		error!("api: post_tx: failed with error: {}", e);
		Err(e)
	} else {
		debug!("api: post_tx: successfully posted tx, fluff? {}", fluff);
		Ok(())
	}
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate, secp: &Secp256k1) -> Result<(), Error> {
	slate.verify_messages(secp)
}

fn validate_rewind_hash_format(rewind_hash: &str) -> Result<(), Error> {
	if rewind_hash.len() != 64 || !rewind_hash.chars().all(|c| c.is_ascii_hexdigit()) {
		return Err(Error::RewindHash("Invalid Rewind Hash".to_owned()));
	}
	Ok(())
}

/// Scan outputs with the rewind hash of a third-party wallet.
///
/// A successful rewind is a view-only match, not proof that the wallet knows
/// the output blinding factor. Anyone who knows the rewind hash can create an
/// unrelated valid output that also matches it. Consequently, returned outputs
/// and `total_balance` must not be used as an ownership or balance attestation.
/// If `tip` is provided it is used as the chain tip for the scan bound;
/// otherwise the tip is fetched from the node.
/// Progress is reported synchronously to `status_callback` when supplied.
pub fn scan_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	rewind_hash: Zeroizing<String>,
	start_height: Option<u64>,
	tip: Option<u64>,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_rewind_hash_format(rewind_hash.as_str())?;
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};
	client.reset_cache();
	let (current_height, current_hash, _) = client.get_chain_tip()?;
	let anchor = match tip {
		Some(height) if height > current_height => {
			return Err(Error::Node(format!(
				"Requested view-wallet scan tip {} is above the current node height {}",
				height, current_height
			)));
		}
		Some(height) if height < current_height => {
			let header = client.get_header_info(height)?;
			ChainTip {
				height,
				hash: header.hash,
			}
		}
		Some(height) => ChainTip {
			height,
			hash: current_hash,
		},
		None => ChainTip {
			height: current_height,
			hash: current_hash,
		},
	};
	scan_rewind_hash_with_anchor(
		wallet_inst,
		secp,
		rewind_hash,
		start_height,
		anchor,
		status_callback,
	)
}

/// Scan outputs with a rewind hash while binding every node request to a
/// specific chain header.
///
/// A successful rewind proves only that an output used the supplied rewind
/// credential. It does not prove spend ownership, and the returned total is a
/// view-only estimate rather than an authenticated wallet balance.
///
/// Known limitation — chain-snapshot consistency. The node API behind this
/// scan (`get_unspent_outputs`) bounds results by PMMR *insertion* position,
/// but evaluates spent/unspent against the node's *live* UTXO set — the set
/// at the current tip, not at the anchor. `NodeReadSession::verify_anchor`
/// therefore proves only header integrity (no reorg of the scanned prefix);
/// it cannot prove that the returned outputs form the UTXO snapshot at the
/// anchor. If the tip advances while the scan runs and a later block spends
/// a scanned output, the old output is omitted as spent while its
/// replacement sits above the anchored PMMR bound and is excluded too, so
/// the reported outputs and balance can miss funds that moved during the
/// scan. Different pages of one pass can also observe different live UTXO
/// states.
///
/// A single pass is deliberately considered sufficient here: the scan is an
/// on-demand report over a wallet whose pending transactions are known to
/// the operator, so a spend landing inside the scan window is expected and
/// the resulting inaccuracy is tolerable. Unlike the regular wallet scan —
/// which self-heals through the `update_wallet_state` refresh fixpoint (see
/// the comment there) — this report has no persistent scan state to converge
/// from; an exact up-to-date figure is obtained by simply re-running the
/// scan at the current tip.
/// Progress is reported synchronously to `status_callback` when supplied.
pub fn scan_rewind_hash_with_anchor<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	rewind_hash: Zeroizing<String>,
	start_height: Option<u64>,
	anchor: ChainTip,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_rewind_hash_format(rewind_hash.as_str())?;
	let rewind_hash = Zeroizing::new(rewind_hash.to_lowercase());

	let start_height = match start_height {
		Some(h) => h,
		None => 1,
	};

	let info = scan::scan_rewind_hash_with_anchor(
		wallet_inst,
		secp,
		rewind_hash,
		start_height,
		anchor,
		status_callback,
	)?;
	Ok(info)
}

/// check repair
/// Accepts a wallet inst instead of a raw wallet so it can
/// lock as little as possible
/// `backwards_from_tip` takes precedence over `start_height` and is resolved
/// against the scan's own freshly fetched anchor, not against any earlier tip
/// sample.
/// Progress is reported synchronously to `status_callback` when supplied.
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	start_height: Option<u64>,
	backwards_from_tip: Option<u64>,
	delete_unconfirmed: bool,
	do_full_outputs_refresh: bool,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<u64, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let session = NodeReadSession::start(w.w2n_client(), "Wallet repair scan")?;

	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) =
		get_last_detect_last_scanned_block(
			&mut **w,
			secp,
			keychain_mask,
			&session,
			status_callback,
		)?;

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

	// A relative lookback is resolved against this scan's own anchor: the tip
	// freshly fetched and verified when the node read session was started.
	// Resolving it against an earlier tip sample (cached or locally derived)
	// could move the requested start height forward and silently skip part of
	// the requested repair range. A lookback beyond genesis intentionally
	// starts the scan at genesis.
	let start_height = match backwards_from_tip {
		Some(b) => Some(tip_height.saturating_sub(b)),
		None => start_height,
	};

	let start_height = match start_height {
		Some(h) => cmp::min(last_scanned_block.height, h),
		None => 1,
	};

	// First we need to get the hashes for heights... Reason, if block chain will be changed during scan, we will detect that naturally with next wallet_update.
	let mut blocks: Vec<ScannedBlockInfo> =
		vec![ScannedBlockInfo::new(tip_height, tip_hash.clone())];
	{
		let mut step = 4;
		loop {
			match blocks.last() {
				Some(block) => {
					let block_height = block.height;
					if block_height > step {
						// block.height > step proves the subtraction cannot underflow.
						#[allow(
							clippy::arithmetic_side_effects,
							reason = "block.height is checked greater than step"
						)]
						let h = block_height - step;
						if h <= start_height {
							break;
						}
						let hdr = w.w2n_client().get_header_info(h)?;
						session.ensure_connection(
							w.w2n_client(),
							"Wallet repair scan header sampling",
						)?;
						blocks.push(ScannedBlockInfo::new(h, hdr.hash));
						step = step.checked_mul(2).ok_or_else(|| {
							Error::DataOverflow(format!(
								"owner::scan, wallet scan step overflow, step={} multiplier=2",
								step
							))
						})?;
					} else {
						break;
					}
				}
				None => {
					error!("Internal error at scan, blocks are empty");
					break;
				}
			}
		}
		// adding last_scanned_block.height not needed
	}

	let replay_rescan_height = scan::scan_with_session(
		&mut **w,
		secp,
		keychain_mask,
		delete_unconfirmed,
		start_height,
		tip_height,
		true,
		do_full_outputs_refresh,
		&session,
		status_callback,
	)?;
	apply_replay_rescan_height(w.w2n_client(), &session, &mut blocks, replay_rescan_height)?;

	let node_client = w.w2n_client().clone();
	session.verify_anchor(&node_client, "Wallet repair scan completion")?;
	let mut batch = w.batch(secp, keychain_mask)?;
	batch.save_last_scanned_blocks(start_height, &blocks)?;
	clear_new_wallet_flag(&mut *batch)?;
	batch.commit()?;

	Ok(tip_height)
}

/// node height
pub fn node_height<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
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
			let outputs = retrieve_outputs(wallet_inst, secp, keychain_mask, true, false, None)?;
			let height = match outputs.2.iter().map(|m| m.output.height).max() {
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

/// Dump wallet status into a file. This data is intended for troubleshooting only.
pub fn dump_wallet_data<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	file_name: String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	wallet_lock!(wallet_inst, w);
	// The dump only reads stored metadata, so it would otherwise bypass the
	// keychain operation that authenticates a masked wallet call.
	let _ = w.keychain(&secp, keychain_mask)?;

	let mut file = mwc_util::file::create_owner_only_file(file_name)?;

	writeln!(file, "Wallet Outputs:")?;
	for output in w.iter()? {
		writeln!(file, "{:?}", output)?;
	}
	for output in w.archive_iter()? {
		writeln!(file, "Archived  {:?}", output)?;
	}

	writeln!(file, "Wallet Transactions:")?;
	for tx_log in w.tx_log_iter()? {
		writeln!(file, "{:?}", tx_log)?;
		// Checking if Slate is available
		if let Some(uuid) = tx_log.tx_slate_id {
			let uuid_str = uuid.to_string();
			match w.get_stored_tx_by_uuid(&uuid_str, false) {
				Ok(t) => {
					writeln!(
						file,
						"tx for {}: {:?}   Transaction: {:?}",
						uuid_str, tx_log, t
					)?;
				}
				Err(Error::TransactionNotFound(_)) => {
					writeln!(
						file,
						"tx for {}: {:?}    Slate not found",
						uuid_str, tx_log
					)?;
				}
				Err(e) => return Err(e),
			}
		}
	}

	for tx_log in w.tx_log_archive_iter()? {
		// Checking if Slate is available
		if let Some(uuid) = tx_log.tx_slate_id {
			let uuid_str = uuid.to_string();
			match w.get_stored_tx_by_uuid(&uuid_str, true) {
				Ok(t) => {
					writeln!(
						file,
						"Archived tx for {}: {:?}   Transaction: {:?}",
						uuid_str, tx_log, t
					)?;
				}
				Err(Error::TransactionNotFound(_)) => {
					writeln!(
						file,
						"Archived tx for {}: {:?}    Slate not found",
						uuid_str, tx_log
					)?;
				}
				Err(e) => return Err(e),
			}
		} else {
			writeln!(file, "Archived tx {:?}", tx_log)?;
		}
	}

	Ok(())
}

// Remove the initialization marker in the batch that makes scan progress durable.
fn clear_new_wallet_flag<K>(batch: &mut dyn WalletOutputBatch<K>) -> Result<(), Error>
where
	K: Keychain,
{
	// Absence is already the desired state. Only a backend failure matters here.
	batch.load_flag(FLAG_NEW_WALLET, true)?;
	Ok(())
}

/// Keep the durable incremental-scan cursor before an unresolved replay
/// output. Only the pinned header is stored as the new head; older sparse
/// reorg anchors below the scan range remain in the backend.
fn apply_replay_rescan_height<C>(
	node_client: &C,
	session: &NodeReadSession,
	blocks: &mut Vec<ScannedBlockInfo>,
	replay_rescan_height: Option<u64>,
) -> Result<(), Error>
where
	C: NodeClient,
{
	let Some(replay_rescan_height) = replay_rescan_height else {
		return Ok(());
	};

	if replay_rescan_height >= session.anchor.height {
		return Err(Error::Node(format!(
			"Replay rescan height {} is not below the scan anchor {}",
			replay_rescan_height, session.anchor.height
		)));
	}

	let header = node_client.get_header_info(replay_rescan_height)?;
	session.ensure_connection(node_client, "Wallet replay rescan anchor")?;
	if header.height != replay_rescan_height {
		return Err(Error::Node(format!(
			"Replay rescan header request for height {} returned height {}",
			replay_rescan_height, header.height
		)));
	}

	info!(
		"Keeping wallet scan cursor at height {} until replay self-spend confirmation",
		replay_rescan_height
	);
	blocks.clear();
	blocks.push(ScannedBlockInfo::new(header.height, header.hash));
	Ok(())
}

// Checking if node head is fine and we can perform the scanning
// Result: (tip_height: u64, tip_hash:String, first_block_to_scan_from: ScannedBlockInfo, is_reorg: bool)
// is_reorg true if new need go back by the chain to perform scanning
// Note: In case of error return tip 0!!!
fn get_last_detect_last_scanned_block<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	session: &NodeReadSession,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<(u64, String, ScannedBlockInfo, bool), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tip_height = session.anchor.height;
	let tip_hash = session.anchor.hash.clone();

	let needs_init_last_scanned = {
		// Checking if keychain mask correct. Issue that sometimes update_wallet_state doesn't need it and it is a security problem
		let mut batch = wallet.batch(secp, keychain_mask)?;
		// Do not consume this one-shot marker until either the initial anchor or a
		// completed short-chain scan is made durable in the same write batch.
		let needs_init = batch.load_flag(FLAG_NEW_WALLET, false)?;
		batch.commit()?;
		needs_init
	};

	if needs_init_last_scanned {
		// Let's still scan for last 100 blocks. That might be a mining wallet like tests has.
		if tip_height > 100 {
			// let's find commit's/txs min heights
			// The surrounding guard proves this lookback subtraction is safe.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "tip_height is checked greater than the 100-block lookback"
			)]
			let mut max_height = tip_height - 100;
			for output in wallet.iter()? {
				// Outputs younger than the lookback intentionally clamp to genesis.
				let h = output.height.saturating_sub(100);
				if h < max_height {
					max_height = h;
				}
			}

			let header = wallet.w2n_client().get_header_info(max_height)?;
			session
				.ensure_connection(wallet.w2n_client(), "Wallet update initial anchor lookup")?;
			let blocks: Vec<ScannedBlockInfo> =
				vec![ScannedBlockInfo::new(header.height, header.hash)];

			let node_client = wallet.w2n_client().clone();
			let mut batch = wallet.batch(secp, keychain_mask)?;
			batch.save_last_scanned_blocks(header.height, &blocks)?;
			session.verify_anchor(&node_client, "Wallet update initialization")?;
			clear_new_wallet_flag(&mut *batch)?;
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
		send_status(
			status_callback,
			StatusMessage::Warning(
				"Wallet Update is skipped, please wait for sync on node to complete or fork to resolve."
					.to_owned(),
			),
		);
		return Ok((0, String::new(), ScannedBlockInfo::empty(), false));
	}

	let mut last_scanned_block = ScannedBlockInfo::empty();
	let head_height = blocks.first().map(|b| b.height).unwrap_or(0);
	for bl in blocks {
		// check if that block is not changed
		if bl.height > tip_height {
			continue; // Possible because of the parch (switch from branches)
		}
		// bl.height <= tip_height was checked above, so the header exists on
		// the serving node. A read failure here is a transport, RPC or parsing
		// problem, not a reorganization; treating it as a hash mismatch would
		// silently move the repair start point backwards.
		let hdr_info = wallet
			.w2n_client()
			.get_header_info(bl.height)
			.map_err(|e| {
				Error::Node(format!(
					"Wallet update reorg detection failed to read header at height {}: {}",
					bl.height, e
				))
			})?;
		session.ensure_connection(wallet.w2n_client(), "Wallet update reorg detection")?;
		if hdr_info.hash == bl.hash {
			last_scanned_block = bl;
			break;
		}
	}

	let has_reorg = last_scanned_block.height != head_height;

	Ok((tip_height, tip_hash, last_scanned_block, has_reorg))
}

/// Experimental, wrap the entire definition of how a wallet's state is updated
///
/// Chain-snapshot consistency: the paged output reads inside the scan bound
/// results by PMMR insertion position but evaluate spent/unspent against the
/// node's live UTXO set, so a round that races a tip advance can observe a
/// mix of snapshots (see `NodeReadSession::verify_anchor`). This workflow
/// absorbs that through a refresh fixpoint instead of retrying: the round
/// below anchors at the tip sampled at entry, and `last_scanned_blocks` is
/// saved no later than that anchor — never at the live tip. An unresolved
/// replay output deliberately holds it immediately before that output's block.
/// Anything that changed above the saved cursor is therefore re-scanned by the
/// next update pass. Passes repeat until one completes without the tip moving;
/// absent an unresolved replay output, the wallet state then matches a single,
/// consistent chain tip. The wallet's own pending transactions are known to
/// it, and no wallet actions are expected while a scan runs, so the transient
/// intermediate state of a racing pass is both explainable and self-healing.
/// Progress is reported synchronously to `status_callback` when supplied.
pub fn update_wallet_state<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<(bool, u64), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let session = NodeReadSession::start(wallet.w2n_client(), "Wallet state update")?;

	// Checking from what point we should start scanning
	let (tip_height, tip_hash, last_scanned_block, has_reorg) =
		get_last_detect_last_scanned_block(
			wallet,
			secp,
			keychain_mask,
			&session,
			status_callback,
		)?;

	if tip_height == 0 {
		return Ok((false, tip_height));
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

	if last_scanned_block.height == tip_height {
		debug!("update_wallet_state is skipped because data is already recently updated");
		return Ok((true, tip_height));
	}

	// During node synchronization a tip behind the wallet's saved height represents
	// zero forward progress and intentionally clamps to zero.
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "subtraction occurs only when tip_height >= last_scanned_block.height"
	)]
	let blocks_since_last_scan = if tip_height >= last_scanned_block.height {
		tip_height - last_scanned_block.height
	} else {
		0
	};
	let show_progress = tip_height < 1000 || blocks_since_last_scan > 20;

	if last_scanned_block.height == 0 {
		send_status(
			status_callback,
			StatusMessage::FullScanWarn(
				"This wallet has not been scanned against the current chain. Beginning full scan... (this first scan may take a while, but subsequent scans will be much quicker)".to_owned(),
			),
		);
	}

	// First we need to get the hashes for heights... Reason, if block chain will be changed during scan, we will detect that naturally.
	let mut blocks: Vec<ScannedBlockInfo> =
		vec![ScannedBlockInfo::new(tip_height, tip_hash.clone())];
	{
		let mut step = 4;

		loop {
			match blocks.last() {
				Some(block) => {
					let block_height = block.height;
					if block_height > step {
						// block.height > step proves the subtraction cannot underflow.
						#[allow(
							clippy::arithmetic_side_effects,
							reason = "block.height is checked greater than step"
						)]
						let h = block_height - step;
						if h <= last_scanned_block.height {
							break;
						}
						let hdr = wallet.w2n_client().get_header_info(h)?;
						session.ensure_connection(
							wallet.w2n_client(),
							"Wallet update header sampling",
						)?;
						blocks.push(ScannedBlockInfo::new(h, hdr.hash));
						step = step.checked_mul(2).ok_or_else(|| {
							Error::DataOverflow(format!(
								"owner::update_wallet_state, wallet update scan step overflow, step={} multiplier=2",
								step
							))
						})?;
					} else {
						break;
					}
				}
				None => {
					error!("Internal error at update_wallet_state, blocks are empty");
					break;
				}
			}
		}
		// adding last_scanned_block.height not needed
	}

	let replay_rescan_height = scan::scan_with_session(
		wallet,
		secp,
		keychain_mask,
		false,
		last_scanned_block.height,
		tip_height,
		show_progress,
		has_reorg,
		&session,
		status_callback,
	)?;
	apply_replay_rescan_height(
		wallet.w2n_client(),
		&session,
		&mut blocks,
		replay_rescan_height,
	)?;

	let node_client = wallet.w2n_client().clone();
	session.verify_anchor(&node_client, "Wallet state update completion")?;
	let mut batch = wallet.batch(secp, keychain_mask)?;
	batch.save_last_scanned_blocks(last_scanned_block.height, &blocks)?;
	clear_new_wallet_flag(&mut *batch)?;
	batch.commit()?;
	Ok((true, tip_height))
}

/// Resolve the chain height only when a cutoff actually needs enforcement.
fn check_ttl_with_height(
	ttl_cutoff_height: Option<u64>,
	get_height: impl FnOnce() -> Result<u64, Error>,
) -> Result<(), Error> {
	let Some(ttl_cutoff_height) = ttl_cutoff_height else {
		return Ok(());
	};

	if get_height()? >= ttl_cutoff_height {
		return Err(Error::TransactionExpired);
	}
	Ok(())
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
	// Refuse if TTL is expired. The tip must be fresh: a cached tip can accept
	// an expired slate or reject a valid one around the cutoff height.
	check_ttl_with_height(slate.ttl_cutoff_height, || {
		if refresh_from_node {
			Ok(w.w2n_client().get_chain_tip_fresh()?.0)
		} else {
			w.last_confirmed_height()
		}
	})
}

#[cfg(test)]
mod check_ttl_tests {
	use super::check_ttl_with_height;

	#[test]
	fn absent_cutoff_does_not_request_height() {
		let mut requested_height = false;
		check_ttl_with_height(None, || {
			requested_height = true;
			Ok(0)
		})
		.unwrap();

		assert!(!requested_height);
	}
}

/// Generate signatures for root public keym tor address PK and MQS PK.
pub fn generate_ownership_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
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

	// The message must not contain the field delimiter, otherwise the signed
	// transcript (network|message|key...) is ambiguous and fields can be
	// absorbed into the message.
	if message.contains('|') {
		return Err(Error::GenericError(
			"Message must not contain the '|' character".to_string(),
		));
	}

	if !include_public_root_key && !include_tor_address && !include_mqs_address {
		return Err(Error::GenericError(
			"No keys are selected to include into the ownership proof".to_string(),
		));
	}

	wallet_lock!(wallet_inst, w);

	let network = if global::is_mainnet(w.get_context_id()) {
		"mainnet"
	} else {
		"floonet"
	};
	// SECURITY/AUDIT NOTE:
	// Ownership proofs intentionally retain the legacy
	// `network|message|present_public_keys...` transcript. This encoding has no
	// explicit version, presence bitmap, or key-role tags, but its exact bytes
	// are expected by existing wallets and ownership-proof utilities. Changing
	// it would invalidate otherwise valid legacy proofs and break interoperability.
	// In particular, the legacy transcript does not cryptographically distinguish
	// a secp256k1 wallet-root attestation from an MQS attestation when the same
	// public-key/signature pair is moved between those single-attestation roles.
	// This known limitation is retained as a protocol-compatibility decision.
	// Do not change this format without a significant protocol-level reason and
	// a coordinated, explicitly versioned migration across all implementations.
	let mut message2sign = String::new();
	message2sign.push_str(network);
	message2sign.push('|');
	message2sign.push_str(message.as_str());

	let keychain = w.keychain(secp, keychain_mask)?;

	if include_public_root_key {
		let root_public_key = keychain.public_root_key(&secp)?;
		let root_public_key = root_public_key.to_hex(secp)?;
		message2sign.push('|');
		message2sign.push_str(root_public_key.as_str());
	}

	let address_index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"owner::generate_ownership_proof, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	if include_tor_address {
		let secret = proofaddress::payment_proof_address_secret(
			&secp,
			w.get_context_id(),
			&keychain,
			address_index,
		)?;
		let tor_pk = proofaddress::secret_2_tor_pub(&secret)?;
		let tor_pk = tor_pk.to_hex(secp)?;
		message2sign.push('|');
		message2sign.push_str(tor_pk.as_str());
	}

	if include_mqs_address {
		let mqs_pub_key: PublicKey = proofaddress::payment_proof_address_pubkey(
			&secp,
			w.get_context_id(),
			&keychain,
			address_index,
		)?;
		let mqs_pub_key = mqs_pub_key.to_hex(secp)?;
		message2sign.push('|');
		message2sign.push_str(mqs_pub_key.as_str());
	}

	// message to sign is ready. Now we can go forward and generate signatures for all public keys
	let mut hasher = Sha256::new();
	hasher.update(message2sign.as_bytes());
	let message_hash = hasher.finalize();

	// generating the signatures for message
	let wallet_root = if include_public_root_key {
		let secret = keychain.private_root_key()?;
		let signature = secp
			.sign(
				&Message::from_slice(message_hash.as_slice()).map_err(|e| {
					Error::GenericError(format!("Unable to build a message, {}", e))
				})?,
				&secret,
			)
			.map_err(|e| Error::from(e))?;
		Some(PubKeySignature {
			public_key: keychain.public_root_key(secp)?.to_hex(secp)?,
			signature: signature.to_hex(secp)?,
		})
	} else {
		None
	};

	let tor_address = if include_tor_address {
		let secret = proofaddress::payment_proof_address_secret(
			&secp,
			w.get_context_id(),
			&keychain,
			address_index,
		)?;
		let secret = ed25519_dalek::SigningKey::from_bytes(&secret.0);
		let public = secret.verifying_key();

		let signature = secret
			.try_sign(message_hash.as_slice())
			.map_err(|e| Error::GenericError(format!("Unable build dalek signature, {}", e)))?;

		Some(PubKeySignature {
			public_key: public.to_hex(secp)?,
			signature: signature.to_hex(secp)?,
		})
	} else {
		None
	};

	let mqs_address = if include_mqs_address {
		let secret = proofaddress::payment_proof_address_secret(
			&secp,
			w.get_context_id(),
			&keychain,
			address_index,
		)?;
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
			public_key: mqs_pub_key.to_hex(secp)?,
			signature: signature.to_hex(secp)?,
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
pub fn validate_ownership_proof(
	secp: &Secp256k1,
	context_id: u32,
	proof: OwnershipProof,
) -> Result<OwnershipProofValidation, Error>
where
{
	if proof.message.is_empty() {
		return Err(Error::InvalidOwnershipProof(
			"message value is empty".to_string(),
		));
	}

	// The legacy transcript uses `|` as its field delimiter. Reject it in the
	// user message so a field cannot be absorbed into that message.
	if proof.message.contains('|') {
		return Err(Error::InvalidOwnershipProof(
			"message value contains the '|' character".to_string(),
		));
	}

	// A proof without any signature attests nothing. The generator refuses to
	// create such proofs, so the verifier must reject them as well.
	if proof.wallet_root.is_none() && proof.tor_address.is_none() && proof.mqs_address.is_none() {
		return Err(Error::InvalidOwnershipProof(
			"Ownership proof contains no signatures".to_string(),
		));
	}

	let mut result = OwnershipProofValidation::empty(proof.message.clone());

	let network = if global::is_mainnet(context_id) {
		"mainnet"
	} else {
		"floonet"
	};

	if proof.network != network {
		return Err(Error::InvalidOwnershipProof(format!(
			"This proof was generated for a different network; expected {}",
			network
		)));
	}

	result.network = network.to_string();

	// Keep this reconstruction identical to generate_ownership_proof. See its
	// SECURITY/AUDIT NOTE before changing the legacy transcript format.
	let mut message2sign = String::new();
	message2sign.push_str(network);
	message2sign.push('|');
	message2sign.push_str(proof.message.as_str());

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
		let public_key = PublicKey::from_hex(secp, &wallet_root.public_key).map_err(|_| {
			Error::InvalidOwnershipProof("Unable to decode wallet root public key".to_string())
		})?;
		let signature = EcdsaSignature::from_hex(secp, &wallet_root.signature).map_err(|_| {
			Error::InvalidOwnershipProof("Unable to decode wallet root signature".to_string())
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
		result.viewing_key = Some(ViewKey::rewind_hash(&secp, public_key)?.to_hex());
	}

	if let Some(mqs_address) = &proof.mqs_address {
		let public_key = PublicKey::from_hex(secp, &mqs_address.public_key).map_err(|_| {
			Error::InvalidOwnershipProof("Unable to decode mqs address public key".to_string())
		})?;
		let signature = EcdsaSignature::from_hex(secp, &mqs_address.signature).map_err(|_| {
			Error::InvalidOwnershipProof("Unable to decode mqs address signature".to_string())
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
		let mqs_address = ProvableAddress::from_pub_key(secp, context_id, &public_key)?;
		result.mqs_address = Some(mqs_address.public_key);
	}

	if let Some(tor_address) = &proof.tor_address {
		let public_key = from_hex(&tor_address.public_key).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address public key, {}", e))
		})?;

		let public_key_bytes: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
			Error::InvalidOwnershipProof(format!(
				"Unable to decode tor address public key, wrong length {}",
				public_key.len()
			))
		})?;

		let public_key =
			ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).map_err(|e| {
				Error::InvalidOwnershipProof(format!(
					"Unable to decode tor address public key, {}",
					e
				))
			})?;

		let signature = from_hex(&tor_address.signature).map_err(|e| {
			Error::InvalidOwnershipProof(format!("Unable to decode tor address signature, {}", e))
		})?;
		let signature =
			ed25519_dalek::Signature::from_slice(signature.as_slice()).map_err(|e| {
				Error::InvalidOwnershipProof(format!(
					"Unable to decode tor address signature, {}",
					e
				))
			})?;

		// Strict verification rejects signatures with low-order R and weak
		// public keys, which the permissive `Verifier::verify` accepts. An
		// ownership proof is an attestation that third parties may validate
		// with strict semantics, so accept only what every validator accepts.
		public_key
			.verify_strict(message_hash.as_slice(), &signature)
			.map_err(|e| {
				Error::InvalidOwnershipProof(format!("tor address signature is invalid, {}", e))
			})?;

		// we are good so far, reporting tor address
		let tor_address = ProvableAddress::from_tor_pub_key(&public_key)?;
		result.tor_address = Some(tor_address.public_key);
	}

	return Ok(result);
}

/// Builds an output for the wallet's next available key
/// Plain outputs require a nonzero last confirmed height from wallet synchronization.
pub fn build_output<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	features: OutputFeatures,
	amount: u64,
) -> Result<BuiltOutput, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let k = w.keychain(secp, keychain_mask)?;

	// A zero height means no anti-replay tag to the scanner. Require a saved
	// sync height before reserving a key; this method does not sync the wallet.
	let build_height = if features.is_coinbase() {
		None
	} else {
		let height = w.last_confirmed_height()?;
		if height == 0 {
			return Err(Error::GenericError(
				"Cannot build a plain output without a confirmed height. Sync the wallet first."
					.to_owned(),
			));
		}
		Some(height)
	};

	let key_id = keys::next_available_key(&mut *w, None)?;

	let blind = k.derive_key(secp, amount, &key_id, SwitchCommitmentType::Regular)?;

	let proof_builder = proof::ProofBuilder::new(secp, &k)?;
	// Every wallet-generated output carries the anti-replay build height in
	// its rangeproof. Coinbase outputs are the only exception: they are
	// unique per block and cannot be replayed.
	let (commit, proof) = if let Some(height) = build_height {
		proof::height_tagged_rangeproof(secp, &k, &proof_builder, amount, &key_id, height)?
	} else {
		let commit = secp.commit(amount, blind.clone())?;
		let proof = proof::create(
			secp,
			&k,
			&proof_builder,
			amount,
			&key_id,
			SwitchCommitmentType::Regular,
			commit,
		)?;
		(commit, proof)
	};

	let output = Output::new(features, commit, proof);

	Ok(BuiltOutput {
		blind: BlindingFactor::from_secret_key(blind),
		key_id: key_id,
		output: output,
	})
}

#[cfg(test)]
mod private_context_if_present_tests {
	use super::{
		context_from_tx_session, invoice_initial_context_from_session, map_tx_context_load_error,
		private_context_if_present,
	};
	use crate::types::{Context, TxLogEntry, TxSession};
	use crate::{Error, TxLogEntryType};
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_crates::uuid::Uuid;
	use mwc_wallet_util::mwc_keychain::Identifier;

	fn transaction_session(
		slate_id: Uuid,
		context_participant_id: usize,
		session_participant_id: usize,
	) -> TxSession {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let context = Context::new(
			&secp,
			&Identifier::zero(),
			#[cfg(feature = "test-support")]
			false,
			#[cfg(feature = "test-support")]
			true,
			context_participant_id,
			1,
			1,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		let mut entry =
			TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxSent, 0);
		entry.tx_slate_id = Some(slate_id);

		let mut session = TxSession::new();
		session.set_context_participant(context, session_participant_id);
		session.set_tx_log_entry(entry);
		session
	}

	#[test]
	fn maps_only_not_found_to_absence() {
		let missing = private_context_if_present(Err(Error::PrivateContextNotFound(
			"missing".to_owned(),
		)))
			.unwrap();
		assert!(missing.is_none());

		let backend_failure =
			private_context_if_present(Err(Error::Backend("read failed".to_owned())));
		assert!(matches!(
			backend_failure,
			Err(Error::Backend(message)) if message == "read failed"
		));
	}

	#[test]
	fn tx_context_load_only_translates_not_found() {
		let slate_id = Uuid::new_v4();
		assert!(matches!(
			map_tx_context_load_error(
				&slate_id,
				Error::PrivateContextNotFound("missing".to_owned()),
			),
			Error::TransactionWasFinalizedOrCancelled(id) if id == slate_id.to_string()
		));
		assert!(matches!(
			map_tx_context_load_error(
				&slate_id,
				Error::Backend("database failure".to_owned()),
			),
			Error::Backend(message) if message == "database failure"
		));
	}

	#[test]
	fn session_context_is_bound_to_participant() {
		let slate_id = Uuid::new_v4();
		let session = transaction_session(slate_id, 0, 0);
		assert_eq!(
			context_from_tx_session(&session, &slate_id, 0)
				.unwrap()
				.participant_id,
			0
		);

		let error = context_from_tx_session(&session, &slate_id, 1).unwrap_err();
		assert!(matches!(error, Error::SlateValidation(message)
			if message.contains("participant mismatch")));

		let inconsistent_session = transaction_session(slate_id, 0, 1);
		let error =
			context_from_tx_session(&inconsistent_session, &slate_id, 0).unwrap_err();
		assert!(matches!(error, Error::SlateValidation(message)
			if message.contains("participant mismatch")));
	}

	#[test]
	fn session_context_is_bound_to_slate_id() {
		let session_slate_id = Uuid::new_v4();
		let response_slate_id = Uuid::new_v4();
		let session = transaction_session(session_slate_id, 0, 0);

		let error =
			context_from_tx_session(&session, &response_slate_id, 0).unwrap_err();
		assert!(matches!(error, Error::SlateValidation(message)
			if message.contains("does not match transaction session")));
	}

	#[test]
	fn invoice_session_is_empty_or_bound_to_issuer_and_slate() {
		let slate_id = Uuid::new_v4();
		assert!(
			invoice_initial_context_from_session(&TxSession::new(), &slate_id)
				.unwrap()
				.is_none()
		);

		let valid = transaction_session(slate_id, 0, 0);
		assert_eq!(
			invoice_initial_context_from_session(&valid, &slate_id)
				.unwrap()
				.unwrap()
				.participant_id,
			0
		);

		let wrong_participant = transaction_session(slate_id, 1, 1);
		assert!(matches!(
			invoice_initial_context_from_session(&wrong_participant, &slate_id),
			Err(Error::SlateValidation(message)) if message.contains("participant mismatch")
		));

		let other_slate_id = Uuid::new_v4();
		assert!(matches!(
			invoice_initial_context_from_session(&valid, &other_slate_id),
			Err(Error::SlateValidation(message))
				if message.contains("does not match transaction session")
		));
	}
}
