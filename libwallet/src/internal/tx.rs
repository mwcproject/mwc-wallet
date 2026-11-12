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

//! Transaction building functions

use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::ed25519_dalek::Signer;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_util;
#[cfg(feature = "test-support")]
use std::cell::Cell;
use std::collections::HashSet;

use crate::internal::{selection, updater};
use crate::proof::crypto;
use crate::proof::crypto::Hex;
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProvableAddress;
use crate::proof::tx_proof::TxProof;
use crate::slate::Slate;
use crate::slatepack::validate_slatepack_size;
use crate::types::{
	Context, NodeClient, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, TxSession,
	WalletBackend,
};
use crate::Error;
use crate::{InitTxArgs, LateLockArgs, SlateVersion};
use mwc_wallet_util::mwc_core::consensus::valid_header_version;
use mwc_wallet_util::mwc_core::core::HeaderVersion;
use mwc_wallet_util::mwc_crates::log::debug;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::{pedersen, EcdsaSignature};
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain};
use mwc_wallet_util::mwc_util::OnionV3Address;
use std::convert::TryInto;

#[cfg(feature = "test-support")]
thread_local! {
	// Test-only fixture IDs: production slate UUIDs come from Slate::blank's OS CSPRNG.
	// Keep deterministic sequencing isolated between concurrent tests; this bounded u8
	// sequence intentionally wraps after 256 IDs and is not a production uniqueness source.
	static SLATE_COUNTER: Cell<u8> = const { Cell::new(0) };
}

/// Creates a new slate for a transaction, can be called by anyone involved in
/// the transaction (sender(s), receiver(s))
pub fn new_tx_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	num_participants: usize,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	ttl_blocks: Option<u64>,
	compact_slate: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Anchor relative TTLs to the node's live tip. A cached height can make a
	// short-lived slate expire earlier than requested if the chain has advanced.
	let (current_height, _, _) = if ttl_blocks.is_some() {
		wallet.w2n_client().get_chain_tip_fresh()?
	} else {
		wallet.w2n_client().get_chain_tip()?
	};
	let mut slate = Slate::blank(num_participants, compact_slate)?;
	if let Some(b) = ttl_blocks {
		slate.ttl_cutoff_height = Some(current_height.checked_add(b).ok_or_else(|| {
			Error::DataOverflow(format!(
				"tx::new_tx_slate, slate TTL height overflow, current_height={} ttl_blocks={}",
				current_height, b
			))
		})?);
	}
	#[cfg(feature = "test-support")]
	if use_test_rng {
		let slate_counter = SLATE_COUNTER.with(Cell::get);
		let bytes = [
			4,
			54,
			67,
			12,
			43,
			2,
			98,
			76,
			32,
			50,
			87,
			5,
			1,
			33,
			43,
			slate_counter,
		];
		slate.id = Uuid::from_slice(&bytes).map_err(|e| {
			Error::GenericError(format!(
				"Unable to construct deterministic test slate ID: {}",
				e
			))
		})?;
		SLATE_COUNTER.with(|counter| counter.set(slate_counter.wrapping_add(1)));
	}
	slate.amount = amount;
	slate.height = current_height;

	let context_id = wallet.get_context_id();
	if valid_header_version(context_id, current_height, HeaderVersion(1)) {
		slate.version_info.block_header_version = 1;
	}

	if valid_header_version(context_id, current_height, HeaderVersion(2)) {
		slate.version_info.block_header_version = 2;
	}

	if valid_header_version(context_id, current_height, HeaderVersion(3)) {
		slate.version_info.block_header_version = 3;
	}

	// Set the lock_height explicitly to 0 here.
	// Set the features explicitly to 0 here.
	// This will generate a Plain kernel (rather than a HeightLocked kernel).
	slate.reset_lock_height();

	Ok(slate)
}

/// Estimates locked amount and fee for the transaction without creating one
/// Caller is responsible for data refresh!!!!
pub fn estimate_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	amount_includes_fee: bool,
	min_fee: &Option<u64>,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                   // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
) -> Result<
	(
		u64, // total
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Get lock height
	let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;
	// ensure outputs we're selecting are up to date

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let (_coins, total, _amount, fee) = selection::select_coins_and_fee(
		wallet,
		amount,
		amount_includes_fee,
		min_fee,
		None,
		current_height,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		parent_key_id,
		outputs,
		routputs,
		exclude_change_outputs,
		change_output_minimum_confirmations,
	)?;
	Ok((total, fee))
}

/// Add inputs and the local participant record to the slate (round 1).
/// Caller is responsible for wallet refresh and, for a non-initiator, must
/// validate the fully adjusted transaction before producing the round-2
/// partial signature.
pub(crate) fn add_inputs_to_slate_round_1<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	min_fee: &Option<u64>,
	fixed_fee: Option<u64>,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	participant_id: usize,
	message: Option<String>,
	_is_initiator: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                   // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
	amount_includes_fee: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(secp, keychain_mask)?;

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let mut context = selection::build_send_tx(
		wallet,
		secp,
		&keychain,
		slate,
		min_fee,
		fixed_fee,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		parent_key_id.clone(),
		participant_id,
		#[cfg(feature = "test-support")]
		use_test_rng,
		#[cfg(feature = "test-support")]
		_is_initiator,
		outputs,  // outputs to include into the transaction
		routputs, // Number of resulting outputs. Normally it is 1
		exclude_change_outputs,
		change_output_minimum_confirmations,
		message.clone(),
		amount_includes_fee,
	)?;

	// Generate a kernel offset and subtract from our context's secret key. Store
	// the offset in the slate's transaction kernel, and adds our public key
	// information to the slate
	slate.fill_round_1(
		secp,
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		message,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)?;

	context.initial_sec_key = context.sec_key.clone();

	Ok(context)
}

/// Validate the transaction elements available to the payer and its local
/// participant record before producing a partial signature. Invoice processing
/// supplies a completed validation slate when the local issuer context is known.
pub(crate) fn validate_invoice_slate(
	context_id: u32,
	secp: &mut Secp256k1,
	slate: &Slate,
	participant_id: usize,
	compact_invoice_output_omitted: bool,
	context: &Context,
) -> Result<(), Error> {
	let local_public_blind = PublicKey::from_secret_key(secp, &context.sec_key)?;
	let local_public_nonce = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
	slate.validate_invoice_before_signing(
		context_id,
		secp,
		participant_id,
		&local_public_blind,
		&local_public_nonce,
		compact_invoice_output_omitted,
	)
}

/// Add receiver output to the slate
pub fn add_output_to_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &mut Slate,
	current_height: u64,
	address: Option<String>,
	output_amounts: Option<Vec<u64>>,
	parent_key_id: &Identifier,
	participant_id: usize,
	message: Option<String>,
	is_initiator: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(secp, keychain_mask)?;

	// create an output using the amount in the slate
	let (_, mut context, mut tx) = selection::build_recipient_output(
		wallet,
		secp,
		keychain_mask,
		tx_session,
		slate,
		current_height,
		address,
		parent_key_id.clone(),
		participant_id,
		output_amounts,
		#[cfg(feature = "test-support")]
		use_test_rng,
		num_outputs, // Number of outputs for this transaction. Normally it is 1
		message.clone(),
	)?;

	// fill public keys
	slate.fill_round_1(
		secp,
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		message,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)?;

	context.initial_sec_key = context.sec_key.clone();

	if !is_initiator {
		// perform partial sig
		slate.fill_round_2(
			wallet.get_context_id(),
			secp,
			&context.sec_key,
			&context.sec_nonce,
			participant_id,
		)?;

		// update excess in stored transaction
		tx.kernel_excess = Some(slate.calc_excess(secp)?);

		match tx_session {
			Some(tx_ses) => {
				tx_ses.set_tx_log_entry(tx);
			}
			None => {
				let mut batch = wallet.batch(secp, keychain_mask)?;
				batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
				batch.commit()?;
			}
		}
	}

	Ok(context)
}

/// Create context, without adding inputs to slate
pub fn create_late_lock_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	init_tx_args: &InitTxArgs,
	sanitized_message: Option<String>,
	parent_key_id: &Identifier,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	participant_id: usize,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !slate.compact_slate {
		return Err(Error::SlateValidation(
			"tx::create_late_lock_context, operation requires a compact slate".to_string(),
		));
	}

	// we're just going to run a selection to get the potential fee,
	// but this won't be locked
	let (coins, total, amount, fee) = selection::select_coins_and_fee(
		wallet,
		init_tx_args.amount,
		init_tx_args.amount_includes_fee.unwrap_or(false),
		&init_tx_args.min_fee,
		None,
		current_height,
		init_tx_args.minimum_confirmations,
		init_tx_args.max_outputs,
		init_tx_args.num_change_outputs,
		init_tx_args.selection_strategy_is_use_all,
		&parent_key_id,
		&init_tx_args.outputs,
		1,
		init_tx_args.exclude_change_outputs.clone().unwrap_or(false),
		init_tx_args.minimum_confirmations_change_outputs,
	)?;
	if init_tx_args.slatepack_requested() {
		let change = total
			.checked_sub(amount)
			.and_then(|value| value.checked_sub(fee))
			.ok_or_else(|| {
				Error::DataOverflow(
					"tx::create_late_lock_context, selected inputs do not cover amount and fee"
						.to_owned(),
				)
			})?;
		let change_outputs =
			selection::change_output_count(change, init_tx_args.num_change_outputs)?;
		let outputs = change_outputs.checked_add(1).ok_or_else(|| {
			Error::SlatepackEncodeError("Slatepack output count overflow".to_owned())
		})?;
		validate_slatepack_size(slate, Some(&SlateVersion::SP), coins.len(), outputs)?;
	}

	// Store the fee-adjusted amount so a fee-inclusive send delivers
	// amount - fee to the receiver, matching the immediate-lock path.
	// Finalization selects amount + fixed_fee, i.e. the original total.
	slate.amount = amount;
	slate.fee = fee;

	let keychain = wallet.keychain(secp, keychain_mask)?;

	// Create our own private context
	let mut context = Context::new(
		secp,
		&parent_key_id,
		#[cfg(feature = "test-support")]
		use_test_rng,
		#[cfg(feature = "test-support")]
		true,
		participant_id,
		slate.amount,
		slate.fee,
		sanitized_message.clone(),
		0, // no lock_height, Plain Tx Kernel
		0_u8,
		slate.ttl_cutoff_height.clone(),
		true, // late lock works only for compact slate, so hardcoding as true
	)?;
	let mut late_lock_args = LateLockArgs::from(init_tx_args);
	late_lock_args.message = sanitized_message.clone();
	context.late_lock_args = Some(late_lock_args);

	// Generate a blinding factor for the tx and add
	//  public key info to the slate
	slate.fill_round_1(
		secp,
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		sanitized_message,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)?;

	Ok(context)
}

/// Select the exact private contribution used by the finalizer. Compact
/// self-invoice flows retain the issuer's original keys separately; all other
/// flows sign with the current context keys.
fn finalizer_signing_keys<'a>(
	slate: &Slate,
	context: &'a Context,
) -> (&'a SecretKey, &'a SecretKey) {
	if slate.compact_slate
		&& context.initial_sec_key != context.sec_key
		&& context.initial_sec_nonce != context.sec_nonce
	{
		(&context.initial_sec_key, &context.initial_sec_nonce)
	} else {
		(&context.sec_key, &context.sec_nonce)
	}
}

/// Calculate the persisted commitment for the exact aggregate signing
/// request that `complete_tx` will use.
pub(crate) fn finalizer_aggsig_challenge(
	context_id: u32,
	secp: &Secp256k1,
	slate: &Slate,
	participant_id: usize,
	context: &Context,
) -> Result<[u8; 32], Error> {
	let (sec_key, sec_nonce) = finalizer_signing_keys(slate, context);
	let local_public_blind = PublicKey::from_secret_key(secp, sec_key)?;
	let local_public_nonce = PublicKey::from_secret_key(secp, sec_nonce)?;
	slate.aggsig_challenge_hash(
		context_id,
		secp,
		participant_id,
		&local_public_blind,
		&local_public_nonce,
	)
}

/// Validate every peer-controlled part of a finalization request without
/// mutating wallet state or producing the local partial signature. Late-lock
/// finalization runs this against a fully rebuilt candidate before committing
/// input locks; `complete_tx` repeats it immediately before nonce binding.
pub(crate) fn validate_finalization_request(
	context_id: u32,
	secp: &mut Secp256k1,
	slate: &Slate,
	participant_id: usize,
	context: &Context,
) -> Result<(), Error> {
	// Reject a malformed peer share before pinning an otherwise unused nonce.
	slate.verify_part_sigs(context_id, secp)?;

	let (local_public_blind, local_public_nonce) = {
		let (sec_key, sec_nonce) = finalizer_signing_keys(slate, context);
		(
			PublicKey::from_secret_key(secp, sec_key)?,
			PublicKey::from_secret_key(secp, sec_nonce)?,
		)
	};
	slate.validate_before_signing(
		context_id,
		secp,
		participant_id,
		&local_public_blind,
		&local_public_nonce,
	)
}

/// Complete a transaction. Before calculating the local partial signature,
/// verify the peer signatures and durably bind the secret nonce to the exact
/// aggregate signing challenge. A later retry may reuse the nonce only for the
/// same challenge.
pub fn complete_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &mut Slate,
	participant_id: usize,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context_id = wallet.get_context_id();
	validate_finalization_request(context_id, secp, slate, participant_id, context)?;

	let challenge = finalizer_aggsig_challenge(
		context_id,
		secp,
		slate,
		participant_id,
		context,
	)?;
	context.bind_aggsig_challenge(challenge)?;

	// Persist on both first use and an identical retry. This makes the
	// persist-before-sign invariant independent of the caller's context source.
	match tx_session {
		Some(tx) => tx.set_context_participant(context.clone(), participant_id),
		None => {
			let mut batch = wallet.batch(secp, keychain_mask)?;
			batch.save_private_context(secp, slate.id.as_bytes(), participant_id, context)?;
			batch.commit()?;
		}
	}

	let (sec_key, sec_nonce) = finalizer_signing_keys(slate, context);

	slate.fill_round_2(
		context_id,
		secp,
		sec_key,
		sec_nonce,
		participant_id,
	)?;

	// Do not log the mutated slate here: it now contains the local partial
	// signature, which must not escape from a failed finalization attempt.
	debug!(
		"Finalizing slate {}, participant_id={}, participant_count={}",
		slate.id,
		participant_id,
		slate.participant_data.len()
	);
	slate.finalize(context_id, secp)?;
	Ok(())
}

/// Reject a cancellation group if one of its matching outputs is currently
/// locked by a transaction outside that group.
fn validate_cancellation_lock_owners(
	cancellations: &[(TxLogEntry, Vec<OutputData>, Identifier)],
	tx_id_string: &str,
) -> Result<(), Error> {
	let cancellation_ids: HashSet<(Identifier, u32)> = cancellations
		.iter()
		.map(|(tx, _, _)| (tx.parent_key_id.clone(), tx.id))
		.collect();

	for (_, outputs, _) in cancellations {
		for output in outputs
			.iter()
			.filter(|output| output.status == OutputStatus::Locked)
		{
			let lock_owner = output
				.tx_log_entry
				.map(|tx_id| (output.root_key_id.clone(), tx_id));
			if !lock_owner
				.as_ref()
				.map(|owner| cancellation_ids.contains(owner))
				.unwrap_or(false)
			{
				return Err(Error::TransactionNotCancellable(format!(
					"Transaction {} has an output locked by another transaction; cancel the dependent transaction first",
					tx_id_string
				)));
			}
		}
	}

	Ok(())
}

/// Rollback outputs associated with a transaction in the wallet.
///
/// Cancellation is idempotent: selecting only entries which are already
/// cancelled returns success. Owner cancellation refreshes wallet state first,
/// and that refresh can cancel TTL-expired entries before this function runs.
/// Treating the already-satisfied postcondition as success prevents callers from
/// receiving an error after their requested state change was durably committed.
pub fn cancel_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: Option<&Identifier>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx_id_string = if let Some(tx_id) = tx_id {
		tx_id.to_string()
	} else if let Some(tx_slate_id) = tx_slate_id {
		tx_slate_id.to_string()
	} else {
		return Err(Error::TransactionCancellationError(
			"Transaction is not defined. Please specify tx_id or tx_slate_id fields.",
		));
	};

	// Cancellation deliberately searches only the active transaction-log namespace.
	// Archive eligibility does not imply `confirmed`: an old unconfirmed/reverted
	// entry can be archived after it has no cancellable live output or nonterminal
	// input reservation left. At that point it is historical state; falling back to
	// the archive here cannot release funds and would re-create a cancelled copy
	// under the active prefix. Do not use `retrieve_txs`, whose history lookup falls
	// back to `tx_log_archive_iter` when no active exact match exists.
	let tx_vec = updater::retrieve_txs_from_active_log(
		wallet,
		tx_id,
		&tx_slate_id,
		parent_key_id,
		false,
	)?;
	if tx_vec.is_empty() {
		return Err(Error::TransactionDoesntExist(tx_id_string));
	}
	// There can be several transactions with the same slate ID (send file to self).
	// Validate and resolve all of them before changing wallet state so a failure in
	// a later entry cannot leave the earlier entries partially cancelled.
	let mut cancellations = Vec::with_capacity(tx_vec.len());
	for tx in tx_vec {
		// Ignore already-cancelled members. This makes retrying cancellation safe and
		// also repairs a slate group left partially cancelled by an older per-entry
		// cancellation loop: active members continue into the atomic batch below.
		if tx.is_cancelled() {
			continue;
		}
		match tx.tx_type {
			TxLogEntryType::TxSent | TxLogEntryType::TxReceived | TxLogEntryType::TxReverted => {}
			_ => return Err(Error::TransactionNotCancellable(tx_id_string)),
		}
		if tx.confirmed {
			return Err(Error::TransactionNotCancellable(tx_id_string));
		}
		// get outputs associated with tx (including spent, so that inputs of an
		// externally-posted transaction still resolve for the check below)
		let res = updater::retrieve_outputs(
			wallet,
			secp,
			keychain_mask,
			true,
			Some(&tx),
			&tx.parent_key_id,
			None,
			None,
		)?;
		// Every input commitment recorded in the tx log must resolve to a wallet
		// output; otherwise cancellation would commit while leaving unresolvable
		// inputs Locked (e.g. outputs persisted without a cached commitment).
		let resolved: Vec<String> = res.iter().map(|m| mwc_util::to_hex(&m.commit.0)).collect();
		if tx
			.input_commits
			.iter()
			.any(|c| !resolved.contains(&mwc_util::to_hex(&c.0)))
		{
			return Err(Error::TransactionNotCancellable(format!(
				"Unable to resolve all inputs of transaction {}. Refresh the wallet and retry; aborting to avoid leaving outputs locked.",
				tx_id_string
			)));
		}
		let outputs = res.into_iter().map(|m| m.output).collect();
		let parent_key_id = tx.parent_key_id.clone();
		cancellations.push((tx, outputs, parent_key_id));
	}
	validate_cancellation_lock_owners(&cancellations, &tx_id_string)?;
	if cancellations.is_empty() {
		// Every selected entry already has the requested durable state. This is a
		// successful idempotent retry, not a failed state transition.
		return Ok(());
	}

	// Apply every cancellation through one backend transaction. If staging any
	// entry fails, dropping the uncommitted batch rolls back all preceding writes.
	let mut batch = wallet.batch(secp, keychain_mask)?;
	for (tx, outputs, parent_key_id) in cancellations {
		updater::cancel_tx_and_outputs(&mut *batch, tx, outputs, &parent_key_id)?;
	}
	batch.commit()
}

/// Update the stored transaction (this update needs to happen when the TX is finalized)
pub fn update_stored_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	is_invoiced: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Reading saved TxLogEntry
	let mut tx = match tx_session {
		Some(tx_ses) => tx_ses
			.get_tx_log_entry()
			.clone()
			.ok_or(Error::TransactionDoesntExist(slate.id.to_string()))?,
		None => {
			let tx_vec = updater::retrieve_txs(
				wallet,
				keychain_mask,
				None,
				Some(slate.id),
				None,
				None,
				false,
				None,
				None,
				None,
			)?;
			let mut tx = None;
			// don't want to assume this is the right tx, in case of self-sending
			for t in tx_vec {
				if t.tx_type == TxLogEntryType::TxSent && !is_invoiced {
					tx = Some(t);
					break;
				}
				if t.tx_type == TxLogEntryType::TxReceived && is_invoiced {
					tx = Some(t);
					break;
				}
			}
			match tx {
				Some(t) => t,
				None => return Err(Error::TransactionDoesntExist(slate.id.to_string())),
			}
		}
	};

	if tx.tx_slate_id.is_none() {
		return Err(Error::GenericError(
			"Transaction doesn't have stored tx slate id".to_string(),
		));
	}

	if slate.compact_slate {
		tx.kernel_excess = Some(slate.calc_excess(secp)?);
	} else {
		tx.kernel_excess = Some(
			slate
				.tx_or_err()?
				.body
				.kernels
				.first()
				.ok_or_else(|| Error::GenericError("Finalized transaction has no kernel".into()))?
				.excess,
		);
	}
	tx.stored_tx = Some(format!("{}.mwctx", slate.id));

	match tx_session {
		Some(tx_ses) => {
			tx_ses.set_tx_log_entry(tx);
			tx_ses.set_transaction(slate.tx_or_err()?.clone());
		}
		None => {
			wallet.store_tx(&format!("{}", slate.id), slate.tx_or_err()?)?;
			let mut batch = wallet.batch(secp, keychain_mask)?;
			let parent_key = tx.parent_key_id.clone();
			batch.save_tx_log_entry(tx, &parent_key)?;
			batch.commit()?;
		}
	}

	Ok(())
}

/// Update the transaction participant messages
pub fn update_message<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	match tx_session {
		Some(tx_ses) => {
			tx_ses
				.get_mut_tx_log_entry()
				.as_mut()
				.ok_or(Error::TransactionDoesntExist(slate.id.to_string()))?
				.messages = Some(slate.participant_messages());
		}
		None => {
			let tx_vec = updater::retrieve_txs(
				wallet,
				keychain_mask,
				None,
				Some(slate.id),
				None,
				None,
				false,
				None,
				None,
				None,
			)?;
			if tx_vec.is_empty() {
				return Err(Error::TransactionDoesntExist(slate.id.to_string()));
			}
			let mut batch = wallet.batch(secp, keychain_mask)?;
			for mut tx in tx_vec.into_iter() {
				tx.update_messages(&slate.participant_messages());
				let parent_key = tx.parent_key_id.clone();
				batch.save_tx_log_entry(tx, &parent_key)?;
			}
			batch.commit()?;
		}
	}
	Ok(())
}

/// Generate the compatibility-sensitive payment-proof message used by mwc713.
///
/// This wire format is intentionally kept unchanged. Do not modify its field
/// order or encoding without a compelling protocol reason and a coordinated
/// compatibility plan. Signing and verification require the sender to be a
/// canonical, fixed-length MQS address; together with the fixed-size kernel
/// commitment, that makes the remaining decimal amount boundary unambiguous
/// and binds the proof to one particular transaction.
pub fn payment_proof_message(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address_publickey: String,
) -> Result<String, Error> {
	let mut message = String::new();
	debug!("the kernel excess is {:?}", kernel_commitment.0.to_vec());
	debug!("the sender public key is {}", &sender_address_publickey);
	message.push_str(&mwc_util::to_hex(&kernel_commitment.0));
	message.push_str(&sender_address_publickey);
	message.push_str(&amount.to_string());
	Ok(message)
}

/// decode proof message
//pub fn _decode_payment_proof_message(
//	msg: &[u8],
//) -> Result<(u64, pedersen::Commitment, ed25519_dalek::PublicKey), Error> {
//	let mut rdr = Cursor::new(msg);
//	let amount = rdr.read_u64::<BigEndian>()?;
//	let mut commit_bytes = [0u8; 33];
//	for i in 0..33 {
//		commit_bytes[i] = rdr.read_u8()?;
//	}
//	let mut sender_address_bytes = [0u8; 32];
//	for i in 0..32 {
//		sender_address_bytes[i] = rdr.read_u8()?;
//	}
//
//	Ok((
//		amount,
//		pedersen::Commitment::from_vec(commit_bytes.to_vec()),
//		ed25519_dalek::PublicKey::from_bytes(&sender_address_bytes)
//			.map_err(|e| Error::Signature(format!("Failed to build public key, {}", e)))?,
//	))
//}

/// Validate that a payment-proof receiver address is the canonical public
/// identity corresponding to the supplied signing key.
pub(crate) fn validate_payment_proof_receiver_binding(
	receiver_address: &ProvableAddress,
	sec_key: &SecretKey,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<(), Error> {
	// This is deliberately a key/address consistency check, not a wallet
	// ownership check. Anyone may verify a proof involving arbitrary addresses,
	// and callers may sign for any address when they supply its matching key.
	let expected_address = match receiver_address.public_key.len() {
		52 => {
			receiver_address
				.validate_mqs(secp, context_id)
				.map_err(|e| {
					Error::PaymentProof(format!("Invalid payment-proof receiver address, {}", e))
				})?;
			let public_key = crypto::public_key_from_secret_key(secp, sec_key).map_err(|e| {
				Error::PaymentProof(format!(
					"Unable to derive MQS payment-proof signing address, {}",
					e
				))
			})?;
			ProvableAddress::from_pub_key(secp, context_id, &public_key).map_err(|e| {
				Error::PaymentProof(format!(
					"Unable to derive MQS payment-proof signing address, {}",
					e
				))
			})?
		}
		56 => {
			ProvableAddress::from_str(secp, context_id, &receiver_address.public_key).map_err(
				|e| Error::PaymentProof(format!("Invalid payment-proof receiver address, {}", e)),
			)?;
			let signing_key = ed25519_dalek::SigningKey::from_bytes(&sec_key.0);
			ProvableAddress::from_tor_pub_key(&signing_key.verifying_key()).map_err(|e| {
				Error::PaymentProof(format!(
					"Unable to derive Onion payment-proof signing address, {}",
					e
				))
			})?
		}
		length => {
			return Err(Error::PaymentProof(format!(
				"Invalid payment-proof receiver address length {}, expected 52-character MQS or 56-character OnionV3",
				length
			)));
		}
	};

	if receiver_address.public_key != expected_address.public_key {
		return Err(Error::PaymentProof(
			"Payment-proof receiver address does not match the supplied signing key".to_owned(),
		));
	}

	Ok(())
}

/// Create a payment-proof signature using the established transport-specific
/// proof scheme.
///
/// This behavior is compatibility-sensitive and intentionally differs by
/// receiver address type:
///
/// * MQS receivers use the existing secp256k1 challenge-signature scheme.
/// * Tor/OnionV3 receivers use Ed25519 over the exact legacy proof-message
///   bytes.
///
/// These are distinct proof formats and must not be silently unified or
/// converted into one another. Changing either algorithm, encoding, or the
/// legacy message requires a compelling protocol reason and a coordinated
/// compatibility plan with existing mwc713 and mwc-wallet implementations.
pub fn create_payment_proof_signature(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address: ProvableAddress,
	receiver_address: ProvableAddress,
	sec_key: SecretKey,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<String, Error> {
	sender_address
		.validate_mqs(secp, context_id)
		.map_err(|e| Error::PaymentProof(format!("Invalid payment-proof sender address, {}", e)))?;
	validate_payment_proof_receiver_binding(&receiver_address, &sec_key, secp, context_id)?;
	let message_ser = payment_proof_message(amount, kernel_commitment, sender_address.public_key)?;
	if receiver_address.public_key.len() == 52 {
		//this is mqs address
		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, &sec_key, secp)?;
		let signature = signature.to_hex(secp)?;
		Ok(signature)
	} else if receiver_address.public_key.len() == 56 {
		//this is tor oninion address and the length should be 56
		let d_skey = ed25519_dalek::SigningKey::from_bytes(&sec_key.0);
		let signature = d_skey.sign(message_ser.as_bytes());
		let signature_vec = signature.to_bytes().to_vec();
		Ok(mwc_util::to_hex(&signature_vec))
	} else {
		Err(Error::PaymentProof(format!(
			"Invalid payment-proof receiver address length {}, expected 52-character MQS or 56-character OnionV3",
			receiver_address.public_key.len()
		)))
	}
}

// A valid secp256k1 DER signature is much shorter than this. Keep malformed,
// peer-controlled values bounded when returning them through user-visible errors.
const PAYMENT_PROOF_SIGNATURE_DISPLAY_LIMIT: usize = 256;

fn parse_mqs_payment_proof_signature(
	secp: &Secp256k1,
	signature: &str,
) -> Result<EcdsaSignature, Error> {
	let signature_ser = mwc_util::from_hex(signature).map_err(|e| {
		Error::PaymentProof(format!(
			"Unable to build signature from HEX {}, {}",
			crate::types::bounded_escape_for_display(
				signature,
				PAYMENT_PROOF_SIGNATURE_DISPLAY_LIMIT,
			),
			e
		))
	})?;
	EcdsaSignature::from_der(secp, &signature_ser)
		.map_err(|e| Error::PaymentProof(format!("Unable to build signature, {}", e)))
}

fn validate_payment_proof_request_state(
	derivation_index: Option<u32>,
	expected_recipient: Option<&str>,
	payment_proof_present: bool,
) -> Result<(), Error> {
	// Contexts persisted before payment_proof_recipient_address was introduced
	// still carry the derivation index that marks a requested proof. The original
	// recipient cannot be reconstructed from the returned, peer-controlled slate,
	// so fail closed instead of accepting a stripped or substituted proof.
	if derivation_index.is_some() && expected_recipient.is_none() {
		return Err(Error::PaymentProof(
			"Stored payment-proof recipient address is unavailable; restart the transaction"
				.to_owned(),
		));
	}

	if expected_recipient.is_some() && !payment_proof_present {
		return Err(Error::PaymentProof(
			"Expected Payment Proof for this Transaction is not present".to_owned(),
		));
	}

	Ok(())
}

fn parse_mqs_payment_proof_receiver_public_key(
	receiver_address: &ProvableAddress,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<PublicKey, Error> {
	let receiver_pubkey = receiver_address.public_key(secp, context_id).map_err(|_| {
		Error::PaymentProof(
			"Unable to get payment-proof receiver address: invalid encoding or network".to_owned(),
		)
	})?;

	// A successfully decoded MQS address contains only the Base58 alphabet and
	// is therefore safe to include in the debug log.
	debug!("the receiver pubkey is {}", receiver_address.public_key);
	Ok(receiver_pubkey)
}

struct VerifiedSlatePaymentProof {
	message: String,
	sender_secret: SecretKey,
	sender_address: ProvableAddress,
	onion_address: Option<String>,
}

/// Verify every peer-controlled payment-proof field without producing or
/// storing the sender's final proof artifact. Late-lock finalization calls this
/// before publishing input locks; final proof generation calls it again against
/// the completed slate and consumes the returned verified data.
fn verified_slate_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
) -> Result<Option<VerifiedSlatePaymentProof>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_payment_proof_request_state(
		context.payment_proof_derivation_index,
		context.payment_proof_recipient_address.as_deref(),
		slate.payment_proof.is_some(),
	)?;

	let context_id = wallet.get_context_id();

	if let Some(ref p) = slate.payment_proof {
		let keychain = wallet.keychain(secp, keychain_mask)?;
		let index = match context.payment_proof_derivation_index {
			Some(i) => i,
			None => {
				return Err(Error::PaymentProof(
					"Payment proof derivation index required".to_owned(),
				));
			}
		};
		// Normal public key is needed
		let orig_sender_a = proofaddress::payment_proof_address_from_index(
			secp,
			context_id,
			&keychain,
			index,
			proofaddress::ProofAddressType::MQS,
		)?;

		if p.sender_address.public_key != orig_sender_a.public_key {
			return Err(Error::PaymentProof(
				"Sender address on slate does not match original sender address".to_owned(),
			));
		}

		// The proof must be for the recipient that was originally requested,
		// not for an address substituted by the responding peer. The second
		// arm covers self-sends, where the sender is the requested recipient.
		if let Some(expected_recipient) = &context.payment_proof_recipient_address {
			if p.receiver_address.public_key != *expected_recipient
				&& p.sender_address.public_key != *expected_recipient
			{
				return Err(Error::PaymentProof(
					"Recipient address on slate does not match original recipient address"
						.to_owned(),
				));
			}
		}

		//build the message which was used to generated receiver signature.
		let msg = payment_proof_message(
			slate.amount,
			&slate.calc_excess(secp)?,
			orig_sender_a.public_key.clone(),
		)?;
		let sig = match p.clone().receiver_signature {
			Some(s) => s,
			None => {
				return Err(Error::PaymentProof(
					"Recipient did not provide requested proof signature".to_owned(),
				));
			}
		};
		// Match the transport-specific proof scheme used by
		// create_payment_proof_signature. MQS/secp256k1 and Tor/Ed25519 proofs
		// are intentionally distinct compatibility formats.
		if p.receiver_address.public_key.len() == 52 {
			let signature = parse_mqs_payment_proof_signature(secp, &sig)?;
			let receiver_pubkey =
				parse_mqs_payment_proof_receiver_public_key(&p.receiver_address, secp, context_id)?;
			crypto::verify_signature(&msg, &signature, &receiver_pubkey, secp)
				.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;
		} else {
			//the signature is generated using Dalek public key

			let dalek_sig_vec = mwc_util::from_hex(&sig).map_err(|e| {
				Error::PaymentProof(format!(
					"Unable to deserialize tor payment proof signature, {}",
					e
				))
			})?;

			let dalek_sig_bytes: [u8; 64] = dalek_sig_vec.as_slice().try_into().map_err(|_| {
				Error::PaymentProof(format!(
					"Unable to deserialize tor payment proof receiver signature, wrong length {}",
					dalek_sig_vec.len()
				))
			})?;

			let dalek_sig = ed25519_dalek::Signature::from_bytes(&dalek_sig_bytes);

			let receiver_dalek_pub_key = p.receiver_address.tor_public_key().map_err(|_| {
				Error::PaymentProof(
					"Unable to deserialize tor payment proof receiver address".to_owned(),
				)
			})?;
			// Strict verification only: payment proofs are generated by
			// this wallet with an honest signer, so permissive-only
			// signatures (low-order R, weak keys) are never legitimate.
			if let Err(e) = receiver_dalek_pub_key.verify_strict(&msg.as_bytes(), &dalek_sig) {
				return Err(Error::PaymentProof(format!(
					"Invalid proof signature, {}",
					e
				)))?;
			};
		}

		////add an extra step of generating and save proof.
		//generate the sender secret key
		let sender_address_secret_key =
			proofaddress::payment_proof_address_secret(secp, context_id, &keychain, index)?;
		let mut onion_address_str = None;
		if p.receiver_address.public_key.len() == 56 {
			//this should be a tor sending
			let onion_address = OnionV3Address::from_private(&sender_address_secret_key.0)
				.map_err(|e| {
					Error::PaymentProof(format!(
						"Unable to generate onion address for sender address, {}",
						e
					))
				})?;
			onion_address_str = Some(onion_address.to_ov3_str());
		}
		return Ok(Some(VerifiedSlatePaymentProof {
			message: msg,
			sender_secret: sender_address_secret_key,
			sender_address: orig_sender_a,
			onion_address: onion_address_str,
		}));
	}
	Ok(None)
}

/// Validate a returned payment proof before any late-lock wallet mutation.
pub(crate) fn validate_slate_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	verified_slate_payment_proof(wallet, secp, keychain_mask, context, slate).map(|_| ())
}

/// Verify all aspects of a completed payment proof on the current slate,
/// returning the verified proof artifact when one is present.
pub fn verify_slate_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<Option<TxProof>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context_id = wallet.get_context_id();
	let verified = verified_slate_payment_proof(wallet, secp, keychain_mask, context, slate)?;
	let Some(verified) = verified else {
		return Ok(None);
	};

	let tx_proof = TxProof::from_slate(
		context_id,
		verified.message,
		slate,
		&verified.sender_secret,
		&verified.sender_address,
		verified.onion_address,
		secp,
		#[cfg(feature = "test-support")]
		use_test_rng,
	)
	.map_err(|e| {
		Error::TxProofVerifySignature(format!("Cannot create tx_proof using slate, {}", e))
	})?;

	debug!("tx_proof = {:?}", tx_proof);
	Ok(Some(tx_proof))
}

#[cfg(test)]
mod test {
	use super::{
		create_payment_proof_signature, parse_mqs_payment_proof_receiver_public_key,
		parse_mqs_payment_proof_signature, payment_proof_message,
		validate_cancellation_lock_owners, validate_payment_proof_request_state,
	};
	use crate::{Error, OutputData, OutputStatus, TxLogEntry, TxLogEntryType};
	use crate::proof::proofaddress::ProvableAddress;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::core::{KernelFeatures, OutputFeatures};
	use mwc_wallet_util::mwc_core::global;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::libtx::{ProofBuilder, build};
	use mwc_wallet_util::mwc_crates::ed25519_dalek;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;
	use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
	use mwc_wallet_util::mwc_keychain::Identifier;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain};

	#[cfg(feature = "test-support")]
	#[test]
	fn slatepack_size_rejects_an_oversized_valid_transaction_before_finalization() {
		use crate::slatepack::SlatePurpose;
		use crate::{Context, Slate, SlateVersion, Slatepacker};
		use mwc_wallet_util::mwc_core::core::{FeeFields, Inputs, Transaction, TxKernel};
		use mwc_wallet_util::mwc_core::libtx::tx_fee;

		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_accept_fee_base(10_000).unwrap();
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[9; 32], false).unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let fee = tx_fee(0, 1, 101, 1).unwrap();
		let output_value = 100_000_000;
		let mut elements = vec![build::feature_input(
			output_value * 101 + fee,
			OutputFeatures::Plain,
			ExtKeychain::derive_key_id(3, 0, 0, 1, 0).unwrap(),
		)];
		for index in 2..103 {
			elements.push(build::height_tagged_output(
				output_value,
				ExtKeychain::derive_key_id(3, 0, 0, index, 0).unwrap(),
				0,
			));
		}
		let kernel = TxKernel::with_features(KernelFeatures::Plain {
			fee: FeeFields::new(fee).unwrap(),
		})
		.unwrap();
		let mut transaction = Transaction::empty().with_kernel(0, kernel).unwrap();
		transaction.body.inputs = Inputs::FeaturesAndCommit(vec![]);
		let (transaction, blind) = build::partial_transaction(
			0,
			&mut secp,
			transaction,
			&elements,
			&keychain,
			&builder,
		)
		.unwrap();
		let sender_key = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		let recipient_key = secp
			.blind_sum(
				vec![blind.secret_key(&secp).unwrap()],
				vec![sender_key.clone()],
			)
			.unwrap();
		let context = Context::with_excess(
			&secp,
			sender_key,
			&Identifier::zero(),
			true,
			0,
			output_value,
			fee,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		let recipient_nonce = SecretKey::from_slice(&secp, &[3; 32]).unwrap();
		let mut slate = Slate::blank(2, true).unwrap();
		slate.amount = output_value;
		slate.fee = fee;
		slate.tx = Some(transaction);
		slate
			.add_participant_info(
				&secp,
				&context.sec_key,
				&context.sec_nonce,
				0,
				None,
				None,
				false,
			)
			.unwrap();
		slate
			.add_participant_info(
				&secp,
				&recipient_key,
				&recipient_nonce,
				1,
				None,
				None,
				false,
			)
			.unwrap();
		slate
			.fill_round_2(0, &secp, &recipient_key, &recipient_nonce, 1)
			.unwrap();

		// The small response fits because SP omits sender inputs and change.
		let secret = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
		let mut response = slate.clone();
		response.tx_or_err_mut().unwrap().body.outputs.truncate(1);
		Slatepacker::encrypt_to_send(
			0,
			response,
			SlateVersion::SP,
			SlatePurpose::SendResponse,
			secret.verifying_key(),
			None,
			&secret,
			false,
			&secp,
		)
		.unwrap();
		// Shared signing validation is independent of the output format.
		super::validate_finalization_request(0, &mut secp, &slate, 0, &context).unwrap();
		crate::slatepack::validate_slatepack_size(&slate, Some(&SlateVersion::V3), 0, 0).unwrap();
		assert!(matches!(
			crate::slatepack::validate_slatepack_size(&slate, Some(&SlateVersion::SP), 0, 0),
			Err(Error::SlatepackEncodeError(_))
		));

		// The exact same transaction is valid under consensus but its FullSlate
		// cannot be encoded. The size guard must run before signing and storage.
		slate
			.fill_round_2(0, &secp, &context.sec_key, &context.sec_nonce, 0)
			.unwrap();
		slate.finalize(0, &mut secp).unwrap();
		let json = crate::VersionedSlate::into_version_plain(0, &slate, SlateVersion::V3).unwrap();
		assert!(json.into_slate_plain(0, false).unwrap().compact_slate);
		assert!(matches!(
			Slatepacker::encrypt_to_send(
				0,
				slate,
				SlateVersion::SP,
				SlatePurpose::FullSlate,
				secret.verifying_key(),
				None,
				&secret,
				false,
				&secp,
			),
			Err(Error::SlatepackEncodeError(_))
		));
	}

	fn locked_output(parent_key_id: &Identifier, lock_owner_id: Option<u32>) -> OutputData {
		OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: parent_key_id.clone(),
			n_child: 0,
			commit: None,
			mmr_index: None,
			value: 1,
			status: OutputStatus::Locked,
			height: 0,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: lock_owner_id,
		}
	}

	#[test]
	fn cancellation_rejects_output_locked_by_unselected_transaction() {
		let parent_key_id = Identifier::zero();
		let cancelled = TxLogEntry::new(
			parent_key_id.clone(),
			TxLogEntryType::TxReceived,
			1,
		);
		let cancellations = vec![(
			cancelled,
			vec![locked_output(&parent_key_id, Some(2))],
			parent_key_id,
		)];

		assert!(matches!(
			validate_cancellation_lock_owners(&cancellations, "1"),
			Err(Error::TransactionNotCancellable(message))
				if message.contains("locked by another transaction")
		));
	}

	#[test]
	fn cancellation_allows_output_locked_by_selected_group_member() {
		let parent_key_id = Identifier::zero();
		let first = TxLogEntry::new(
			parent_key_id.clone(),
			TxLogEntryType::TxReceived,
			1,
		);
		let lock_owner = TxLogEntry::new(
			parent_key_id.clone(),
			TxLogEntryType::TxSent,
			2,
		);
		let cancellations = vec![
			(
				first,
				vec![locked_output(&parent_key_id, Some(2))],
				parent_key_id.clone(),
			),
			(lock_owner, Vec::new(), parent_key_id),
		];

		assert!(validate_cancellation_lock_owners(&cancellations, "group").is_ok());
	}

	#[test]
	fn payment_proof_message_keeps_legacy_wire_format() {
		let kernel = Commitment([2_u8; 33]);
		let canonical_sender = "a".repeat(52);
		assert_eq!(
			payment_proof_message(23, &kernel, canonical_sender.clone()).unwrap(),
			format!("{}{}23", "02".repeat(33), canonical_sender)
		);
	}

	#[test]
	fn malformed_payment_proof_signature_is_safe_to_display() {
		let secp = Secp256k1::new().unwrap();
		let hostile_signature = format!("0z\n\u{1b}]52;c;payload\u{7}\u{202e}{}", "x".repeat(512));
		let error = parse_mqs_payment_proof_signature(&secp, &hostile_signature)
			.unwrap_err()
			.to_string();

		assert!(error.contains(r"\u000a"));
		assert!(error.contains(r"\u001b"));
		assert!(error.contains(r"\u0007"));
		assert!(error.contains(r"\u202e"));
		assert!(error.contains("...[truncated]"));
		assert!(!error.chars().any(char::is_control));
		assert!(!error.contains('\u{202e}'));
	}

	#[test]
	fn legacy_payment_proof_request_state_fails_closed() {
		for payment_proof_present in [false, true] {
			let error = validate_payment_proof_request_state(Some(7), None, payment_proof_present)
				.unwrap_err()
				.to_string();
			assert!(error.contains("recipient address is unavailable"));
		}

		assert!(validate_payment_proof_request_state(None, None, false).is_ok());
		assert!(validate_payment_proof_request_state(Some(7), Some("recipient"), true).is_ok());
	}

	#[test]
	fn malformed_payment_proof_receiver_is_safe_to_display() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::new().unwrap();
		let hostile_address = format!("\n\u{1b}{}", "x".repeat(50));
		assert_eq!(hostile_address.len(), 52);
		let mut receiver_address = ProvableAddress::blank();
		receiver_address.public_key = hostile_address.clone();

		let error = parse_mqs_payment_proof_receiver_public_key(&receiver_address, &secp, 0)
			.unwrap_err()
			.to_string();

		assert!(!error.contains(&hostile_address));
		assert!(!error.chars().any(char::is_control));
	}

	#[test]
	fn payment_proof_signing_requires_receiver_key_binding() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::new().unwrap();
		let signing_secret = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let other_secret = SecretKey::from_slice(&secp, &[2_u8; 32]).unwrap();
		let sender_secret = SecretKey::from_slice(&secp, &[3_u8; 32]).unwrap();

		let sender_public = PublicKey::from_secret_key(&secp, &sender_secret).unwrap();
		let sender_address = ProvableAddress::from_pub_key(&secp, 0, &sender_public).unwrap();
		let signing_public = PublicKey::from_secret_key(&secp, &signing_secret).unwrap();
		let signing_mqs = ProvableAddress::from_pub_key(&secp, 0, &signing_public).unwrap();
		let other_public = PublicKey::from_secret_key(&secp, &other_secret).unwrap();
		let other_mqs = ProvableAddress::from_pub_key(&secp, 0, &other_public).unwrap();
		let signing_onion = ProvableAddress::from_tor_pub_key(
			&ed25519_dalek::SigningKey::from_bytes(&signing_secret.0).verifying_key(),
		)
		.unwrap();
		let other_onion = ProvableAddress::from_tor_pub_key(
			&ed25519_dalek::SigningKey::from_bytes(&other_secret.0).verifying_key(),
		)
		.unwrap();
		let kernel = Commitment([2_u8; 33]);

		// Signing is wallet-agnostic: any address is accepted when the caller
		// supplies its corresponding private key.
		assert!(
			create_payment_proof_signature(
				23,
				&kernel,
				sender_address.clone(),
				signing_mqs,
				signing_secret.clone(),
				&secp,
				0,
			)
			.is_ok()
		);
		assert!(
			create_payment_proof_signature(
				23,
				&kernel,
				sender_address.clone(),
				signing_onion,
				signing_secret.clone(),
				&secp,
				0,
			)
			.is_ok()
		);

		assert!(matches!(
			create_payment_proof_signature(
				23,
				&kernel,
				sender_address.clone(),
				other_mqs,
				signing_secret.clone(),
				&secp,
				0,
			),
			Err(Error::PaymentProof(message))
				if message.contains("does not match the supplied signing key")
		));
		assert!(matches!(
			create_payment_proof_signature(
				23,
				&kernel,
				sender_address,
				other_onion,
				signing_secret,
				&secp,
				0,
			),
			Err(Error::PaymentProof(message))
				if message.contains("does not match the supplied signing key")
		));
	}

	#[cfg(feature = "test-support")]
	#[test]
	// demonstrate that input.commitment == referenced output.commitment
	// based on the public key and amount begin spent
	fn output_commitment_equals_input_commitment_on_spend() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[1u8; 32], false).unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id1 = ExtKeychainPath::new(3, 0, 0, 1, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx1 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 1u32.try_into().unwrap(),
			},
			&[build::height_tagged_output(105, key_id1.clone(), 0)],
			&keychain,
			&builder,
		)
		.unwrap();
		let tx2 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 1u32.try_into().unwrap(),
			},
			&[build::feature_input(105, OutputFeatures::Plain, key_id1)],
			&keychain,
			&builder,
		)
		.unwrap();

		let inputs = tx2.inputs().into_commit_wrappers(0).unwrap();
		assert_eq!(tx1.outputs()[0].commitment(), inputs[0].commitment());
	}
}
