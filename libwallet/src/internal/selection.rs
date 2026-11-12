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

//! Selection of inputs for building transactions

use crate::error::Error;
use crate::internal::{keys, output_proof};
use crate::slate::Slate;
use crate::types::*;
use mwc_wallet_util::mwc_core::core::{
	amount_to_hr_string, Committed, Inputs, OutputFeatures,
};
use mwc_wallet_util::mwc_core::consensus;
use mwc_wallet_util::mwc_core::libtx::{
	build,
	proof::{ProofBuild, ProofBuilder},
	tx_fee,
};
use mwc_wallet_util::mwc_core::libtx::{inputs_for_fee_points, inputs_for_minimal_fee};
use mwc_wallet_util::mwc_crates::log::{debug, warn};
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{
	BlindingFactor, Identifier, Keychain,
};
use mwc_wallet_util::mwc_util::{self, ToHex};
use std::collections::HashSet;
use std::convert::TryFrom;

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain: &K,
	slate: &mut Slate,
	min_fee: &Option<u64>,
	fixed_fee: Option<u64>, // Max fee to limit fee for late_lock case
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: Identifier,
	participant_id: usize,
	#[cfg(feature = "test-support")] use_test_nonce: bool,
	#[cfg(feature = "test-support")] is_initiator: bool,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                   // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
	message: Option<String>,
	amount_includes_fee: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// The Context below always records a Plain kernel policy (lock_height=0,
	// kernel_features=0), while the partial signature produced from this
	// slate commits to the slate's kernel. Refuse to build a signing context
	// for any other policy: Context::validate_slate would only flag the
	// mismatch in tx_lock_outputs, after the signed slate may already have
	// been sent to the counterparty (invoice HTTP flow).
	if slate.get_kernel_features() != 0 || slate.get_lock_height() != 0 {
		return Err(Error::InvalidKernelFeatures(format!(
			"selection::build_send_tx, slate kernel policy unsupported, kernel_features={} lock_height={} supported=Plain",
			slate.get_kernel_features(),
			slate.get_lock_height()
		)));
	}

	let (elems, inputs, change_amounts_derivations, fee) = select_send_tx(
		wallet,
		slate.amount,
		amount_includes_fee,
		min_fee,
		fixed_fee,
		slate.height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		outputs,
		routputs,
		exclude_change_outputs,
		change_output_minimum_confirmations,
		true, // Legacy value is true
	)?;
	if amount_includes_fee {
		slate.amount = slate.amount.checked_sub(fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::build_send_tx, transaction amount is too small to include fee, amount={} fee={}",
				slate.amount, fee
			))
		})?;
	};

	// Update the fee on the slate so we account for this when building the tx.
	slate.fee = fee;

	let proof_builder = ProofBuilder::new(secp, keychain)
		.map_err(|e| Error::GenericError(format!("Creating proof builder, {}", e)))?;
	let blinding = slate
		.add_transaction_elements(
			wallet.get_context_id(),
			secp,
			keychain,
			&proof_builder,
			elems,
		)
		.map_err(|e| Error::GenericError(format!("Building send transaction elements, {}", e)))?;

	// Create our own private context
	let mut context = if slate.compact_slate {
		Context::new(
			secp,
			//blinding.secret_key()?,
			&parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_nonce,
			#[cfg(feature = "test-support")]
			is_initiator,
			participant_id,
			slate.amount,
			slate.fee,
			message,
			0, // lock_height is none, Plain Tx Kernel
			0 as u8,
			slate.ttl_cutoff_height.clone(),
			slate.compact_slate,
		)
	} else {
		// Legacy part
		Context::with_excess(
			secp,
			blinding
				.secret_key(secp)
				.map_err(|e| Error::GenericError(format!("Extracting send blinding, {}", e)))?,
			&parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_nonce,
			participant_id,
			slate.amount,
			slate.fee,
			message,
			0, // lock_height is none, Plain Tx Kernel
			0 as u8,
			slate.ttl_cutoff_height.clone(),
			slate.compact_slate,
		)
	}
	.map_err(|e| Error::GenericError(format!("Creating send context, {}", e)))?;

	// Store our private identifiers for each input
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value);
	}

	// Store change output(s) and cached commits
	for (change_amount, id, mmr_index) in &change_amounts_derivations {
		context.add_output(&id, &mmr_index, *change_amount);
		context.output_build_heights.push((id.clone(), slate.height));
	}

	Ok(context)
}

/// Calculate the persistent identifiers and commitments for every input in a
/// transaction context. Sender and invoice initialization use the exact same
/// representation as the later lock step so their live-session reservations
/// cannot diverge.
pub(crate) fn input_commits_from_context<'a, T: ?Sized, C, K>(
	wallet: &T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
) -> Result<Vec<(Identifier, Option<u64>, Commitment, u64)>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut input_commits = Vec::new();
	for (id, mmr, amount) in context.get_inputs() {
		input_commits.push((
			id.clone(),
			mmr,
			wallet.calc_commit(secp, keychain_mask, amount, &id)?,
			amount,
		));
	}
	Ok(input_commits)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	current_height: u64,
	context: &Context,
	address: Option<String>,
	excess_override: Option<Commitment>,
	// When present, publish this context in the same state transition as the
	// input locks, change outputs and transaction log. This is used by late
	// locking so a failed lock cannot consume its retry instructions.
	context_update_participant: Option<usize>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut output_commits: Vec<(Identifier, Commitment, u64)> = Vec::new();
	// Store cached commits before locking wallet
	for (id, _, change_amount) in context.get_outputs() {
		output_commits.push((
			id.clone(),
			wallet.calc_commit(secp, keychain_mask, change_amount, &id)?,
			change_amount,
		));
	}

	let input_commits = input_commits_from_context(wallet, secp, keychain_mask, context)?;
	// A TxSession only stages locks in memory. Re-read the authoritative output
	// state before accepting a delayed response; the process-local weak
	// reservation may have expired after a competing session committed.
	if tx_session.is_some() {
		validate_deferred_inputs(wallet, &input_commits, &slate.id)?;
	}

	let _keychain = wallet.keychain(secp, keychain_mask)?;
	let messages = Some(slate.participant_messages());
	let slate_id = slate.id;
	let height = current_height;
	let parent_key_id = context.parent_key_id.clone();

	let found_tx = match tx_session {
		Some(tx) => tx.get_tx_log_entry().clone(),
		None => {
			let batch = wallet.batch(secp, keychain_mask)?;
			// Check if such transaction already exist. It is very possible for lock after case.
			batch
				.tx_log_iter()?
				.filter(|tx_entry| {
					if tx_entry.tx_type != TxLogEntryType::TxSent {
						return false;
					}
					match tx_entry.tx_slate_id {
						None => false,
						Some(uuid) => uuid == slate_id,
					}
				})
				.next()
		}
	};

	let (mut t, need_new_id) = match found_tx {
		Some(tx) => (tx, false),
		None => {
			// Creating a new record
			(
				TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 0),
				true,
			)
		}
	};

	t.tx_slate_id = Some(slate_id);
	let filename = format!("{}.mwctx", slate_id);
	t.stored_tx = Some(filename);
	t.fee = Some(context.fee);
	t.ttl_cutoff_height = context.ttl_cutoff_height;
	if t.ttl_cutoff_height == Some(0) {
		t.ttl_cutoff_height = None;
	}

	t.address = address;

	match excess_override {
		Some(e) => {
			if !slate.compact_slate {
				return Err(Error::SlateValidation(
					"selection::update_tx_log_entry, excess override requires a compact slate"
						.to_string(),
				));
			}
			t.kernel_excess = Some(e);
		}
		None => {
			t.kernel_excess = Some(slate.calc_excess(secp)?);
		}
	}
	t.kernel_lookup_min_height = Some(current_height);

	t.num_inputs = context.input_commits.len();
	t.input_commits = context.input_commits.clone();

	if context.late_lock_args.is_none() || !t.input_commits.is_empty() {
		t.num_inputs = input_commits.len();
		t.input_commits.clear();
		t.amount_debited = 0;
		for (_id, _mmr, commit, amount) in &input_commits {
			t.amount_debited = t.amount_debited.checked_add(*amount).ok_or_else(|| {
				Error::DataOverflow(format!(
					"selection::lock_tx_context, transaction debited amount overflow, amount_debited={} input_amount={}",
					t.amount_debited, amount
				))
			})?;
			t.input_commits.push(commit.clone());
		}
	} else {
		// It is lock later case. No inputs does exist yet.
		t.amount_debited = slate.amount;
	}

	t.messages = messages;

	// write the output representing our change
	t.num_outputs = 0;
	t.amount_credited = 0;
	t.output_commits.clear();
	let mut outputs = Vec::new();
	for (id, commit, change_amount) in output_commits {
		t.amount_credited = t.amount_credited
			.checked_add(change_amount)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"selection::lock_tx_context, transaction credited amount overflow, amount_credited={} change_amount={}",
					t.amount_credited, change_amount
				))
			})?;
		// The count is derived from the Vec length, whose allocation invariant guarantees it fits usize.
		t.num_outputs += 1;
		t.output_commits.push(commit.clone());
		outputs.push(OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: id.clone(),
			n_child: keys::output_child_index(&id)?,
			commit: Some(ToHex::to_hex(&commit)),
			mmr_index: None,
			value: change_amount,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(t.id),
		});
	}

	// Resolve the transaction before mutating either a session or a backend
	// batch. In the session branch every operation after the fallible input
	// reservation is deliberately infallible.
	let transaction = slate.tx_or_err()?.clone();

	match tx_session {
		Some(tx) => {
			tx.set_input_commits(input_commits)?;
			tx.set_tx_log_entry(t.clone());
			tx.set_outputs(outputs);
			tx.set_transaction(transaction);
			if let Some(participant_id) = context_update_participant {
				tx.set_context_participant(context.clone(), participant_id);
			}
		}
		None => {
			let mut batch = wallet.batch(secp, keychain_mask)?;

			if need_new_id {
				let log_id = batch.next_tx_log_id(&parent_key_id)?;
				t.id = log_id;
			}
			let locked_by_tx_log_id = if need_new_id { None } else { Some(t.id) };
			let mut inputs_to_lock = Vec::with_capacity(input_commits.len());
			for (id, mmr, commit, amount) in &input_commits {
				let mut coin = batch.get(id, mmr)?;
				validate_deferred_input(&coin, commit, *amount, &slate_id, locked_by_tx_log_id)?;
				coin.tx_log_entry = Some(t.id);
				inputs_to_lock.push(coin);
			}

			for mut out in outputs {
				// A new invoice-payment TxLogEntry receives its durable id only
				// after the change outputs were assembled above. Bind every output
				// to that final id before writing either record into the batch.
				out.tx_log_entry = Some(t.id);
				batch.save(out)?;
			}

			for mut coin in inputs_to_lock {
				batch.lock_output(&mut coin)?;
			}

			batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
			if let Some(participant_id) = context_update_participant {
				batch.save_private_context(
					secp,
					slate.id.as_bytes(),
					participant_id,
					context,
				)?;
			}

			// Write the transaction file before committing the log entry that
			// references it, mirroring TxSession::save_tx_data_into_batch: an
			// orphaned file on commit failure is harmless, while a committed
			// log entry without its file is not.
			batch.store_tx(&format!("{}", slate.id), &transaction)?;
			batch.commit()?;
		}
	}
	Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
pub fn build_recipient_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &mut Slate,
	current_height: u64,
	address: Option<String>,
	parent_key_id: Identifier,
	participant_id: usize,
	output_amounts: Option<Vec<u64>>,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
	message: Option<String>,
) -> Result<(Identifier, Context, TxLogEntry), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Supported two-party flows reserve participant 0 for the initiator and 1
	// for the receiver.
	let is_initiator = participant_id == 0;

	// Keeping keys with amounts because context want that ( <id>, <amount> )
	let mut key_vec_amounts = Vec::new();

	if let Some(output_amounts_unwrapped) = &output_amounts {
		// Just calculating the key...
		if num_outputs != output_amounts_unwrapped.len() {
			return Err(Error::GenericError(format!(
				"Expected {} output amounts, got {}",
				num_outputs,
				output_amounts_unwrapped.len()
			)));
		}
		let mut sum: u64 = 0;
		for oaui in output_amounts_unwrapped {
			sum = sum.checked_add(*oaui).ok_or_else(|| {
				Error::DataOverflow(format!(
					"selection::build_recipient_output, output amount sum overflow, sum={} output_amount={}",
					sum, oaui
				))
			})?;
			key_vec_amounts.push((
				keys::next_available_key(wallet, Some(&parent_key_id))?,
				*oaui,
			));
		}
		if sum != slate.amount {
			return Err(Error::AmountMismatch {
				amount: slate.amount,
				sum: sum,
			})?;
		}
	} else {
		// building transaction, always with a freshly allocated wallet key.
		let amount = slate.amount;
		let mut remaining_amount = amount;
		if num_outputs == 0 {
			return Err(Error::GenericError(
				"At least one recipient output is required".to_owned(),
			));
		}
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "num_outputs was rejected when zero, so subtracting one cannot underflow"
		)]
		let last_output = num_outputs - 1;
		for i in 0..num_outputs {
			let key_id = keys::next_available_key(wallet, Some(&parent_key_id))?;

			let output_amount: u64 = if i == last_output {
				remaining_amount
			} else {
				// num_outputs is nonzero above, and usize-to-u64 is supported by this project.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "num_outputs is nonzero and usize-to-u64 is lossless on supported targets"
				)]
				let av_amount = amount / num_outputs as u64;
				av_amount
			};
			if output_amount > 0 {
				key_vec_amounts.push((key_id.clone(), output_amount));
				remaining_amount =
					remaining_amount.checked_sub(output_amount).ok_or_else(|| {
						Error::DataOverflow(format!(
							"selection::build_recipient_output, output amount split underflow, remaining_amount={} output_amount={}",
							remaining_amount, output_amount
						))
					})?;
			}
		}
	}

	if slate.amount == 0 || num_outputs == 0 || key_vec_amounts.len() != num_outputs {
		return Err(Error::GenericError(format!(
			"Unable to build transaction for amount {} and outputs number {}",
			slate.amount, num_outputs
		)));
	}

	let keychain = wallet.keychain(secp, keychain_mask)?;
	let amount = slate.amount;
	let height = current_height;

	let slate_id = slate.id.clone();

	let mut out_vec = Vec::new();
	for kva in &key_vec_amounts {
		// The receiver output is the transaction element reused by a replay
		// attack: a malicious sender can choose new inputs and change while
		// retaining the receiver's original commitment and rangeproof.  Record
		// the build height in that rangeproof so a restored wallet, which has no
		// transaction history, can distinguish the old output from a new payment.
		out_vec.push(build::height_tagged_output(
			kva.1,
			kva.0.clone(),
			current_height,
		));
	}

	let proof_builder = ProofBuilder::new(secp, &keychain)
		.map_err(|e| Error::GenericError(format!("Creating proof builder, {}", e)))?;
	let context_id = wallet.get_context_id();
	let blinding = slate
		.add_transaction_elements(
			context_id,
			secp,
			&keychain,
			&proof_builder,
			out_vec,
		)
		.map_err(|e| Error::GenericError(format!("Building recipient output elements, {}", e)))?;

	if !is_initiator {
		// The incoming transaction may already be at the consensus transaction-weight
		// limit. Appending the recipient output increases its weight, so validate the
		// mutated transaction before staging wallet records or allowing the caller to
		// create participant data and a partial signature. Invoice initiation is
		// excluded because its zero-fee kernel is intentionally transitional.
		slate.validate_transaction_read(context_id)?;
	}

	// Add blinding sum to our context
	let mut context = if slate.compact_slate {
		Context::new(
			secp,
			&parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_rng,
			#[cfg(feature = "test-support")]
			is_initiator,
			participant_id,
			amount,
			slate.fee,
			message,
			slate.get_lock_height(),
			slate.get_kernel_features(),
			slate.ttl_cutoff_height.clone(),
			slate.compact_slate,
		)
	} else {
		// Legacy model
		Context::with_excess(
			secp,
			blinding.secret_key(secp).map_err(|e| {
				Error::GenericError(format!("Extracting recipient blinding, {}", e))
			})?,
			&parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_rng,
			participant_id,
			amount,
			slate.fee,
			message,
			slate.get_lock_height(),
			slate.get_kernel_features(),
			slate.ttl_cutoff_height.clone(),
			slate.compact_slate,
		)
	}
	.map_err(|e| Error::GenericError(format!("Creating recipient context, {}", e)))?;

	for kva in &key_vec_amounts {
		context.add_output(&kva.0, &None, kva.1);
		context
			.output_build_heights
			.push((kva.0.clone(), current_height));
	}

	let messages = Some(slate.participant_messages());

	let mut commit_vec = Vec::new();
	let mut commit_ped = Vec::new();
	for kva in &key_vec_amounts {
		let commit = wallet.calc_commit(secp, keychain_mask, kva.1, &kva.0)?;
		commit_ped.push(commit);
		commit_vec.push(Some(commit.to_hex()));
	}

	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, 0);
	t.tx_slate_id = Some(slate_id);
	t.amount_credited = amount;
	t.address = address;
	t.num_outputs = key_vec_amounts.len();
	t.output_commits = commit_ped;
	t.messages = messages;
	t.ttl_cutoff_height = slate.ttl_cutoff_height;
	//add the offset to the database tx record.
	let offset = slate.tx_or_err()?.offset.clone();
	if offset != BlindingFactor::zero() {
		let offset_skey = offset.secret_key(secp)?;
		let offset_pubkey = PublicKey::from_secret_key(secp, &offset_skey)?;
		let offset_commit = Commitment::from_pubkey(secp, &offset_pubkey)?;
		t.kernel_offset = Some(offset_commit);
	}

	if t.ttl_cutoff_height == Some(0) {
		t.ttl_cutoff_height = None;
	}

	// when invoicing, this will be invalid
	if let Ok(e) = slate.calc_excess(secp) {
		t.kernel_excess = Some(e)
	}
	t.kernel_lookup_min_height = Some(current_height);

	let mut outputs = Vec::new();
	if key_vec_amounts.len() != commit_vec.len() {
		return Err(Error::GenericError(
			"Output key and commitment counts differ".to_owned(),
		));
	}
	for (kva, commit) in key_vec_amounts.iter().zip(commit_vec.iter()) {
		outputs.push(OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: kva.0.clone(),
			mmr_index: None,
			n_child: keys::output_child_index(&kva.0)?,
			commit: commit.clone(),
			value: kva.1,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: None,
		});
	}

	match tx_session {
		Some(tx) => {
			tx.set_tx_log_entry(t.clone());
			tx.set_outputs(outputs);
		}
		None => {
			let mut batch = wallet.batch(secp, keychain_mask)?;
			let log_id = batch.next_tx_log_id(&parent_key_id)?;
			t.id = log_id;

			batch.save_tx_log_entry(t.clone(), &parent_key_id)?;

			for mut out in outputs {
				out.tx_log_entry = Some(log_id);
				batch.save(out)?;
			}
			batch.commit()?;
		}
	}

	// returning last key that was used in the chain.
	// That suppose to satisfy all caller needs
	Ok((
		key_vec_amounts
			.last()
			.ok_or(Error::GenericError(
				"build_recipient_output internal error,  is empty".into(),
			))?
			.0
			.clone(),
		context,
		t,
	))
}

fn calc_fees(
	context_id: u32,
	input_num: usize,
	output_num: usize,
	min_fee: &Option<u64>,
	fixed_fee: &Option<u64>, // Max fee to limit fee for late_lock case
) -> Result<u64, Error> {
	let mut fee = tx_fee(context_id, input_num, output_num, 1)?;
	if let Some(min_fee) = min_fee {
		fee = std::cmp::max(*min_fee, fee);
	}
	if let Some(fixed_fee) = fixed_fee {
		if fee > *fixed_fee {
			return Err(Error::Fee(format!(
				"Unable to finalize transaction with already locked fee {}. Please cancel transaction and retry, or use more outputs to reduce the fee.",
				fixed_fee
			)));
		}
		fee = *fixed_fee;
	}
	Ok(fee)
}

/// Builds a transaction to send to someone from the HD seed associated with the
/// wallet and the amount to send. Handles reading through the wallet data file,
/// selecting outputs to spend and building the change.
pub fn select_send_tx<'a, T: ?Sized, C, K, B>(
	wallet: &mut T,
	amount: u64,
	amount_includes_fee: bool,
	min_fee: &Option<u64>,
	fixed_fee: Option<u64>, // Max fee to limit fee for late_lock case
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                   // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
	include_inputs_in_sum: bool, // Legacy workflow value is true
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<OutputData>,
		Vec<(u64, Identifier, Option<u64>)>, // change amounts and derivations
		u64,                                 // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	B: ProofBuild,
{
	let (coins, _total, amount, fee) = select_coins_and_fee(
		wallet,
		amount,
		amount_includes_fee,
		min_fee,
		fixed_fee,
		current_height,
		minimum_confirmations,
		max_outputs,
		change_outputs,
		selection_strategy_is_use_all,
		&parent_key_id,
		outputs,  // outputs to include into the transaction
		routputs, // Number of resulting outputs. Normally it is 1
		exclude_change_outputs,
		change_output_minimum_confirmations,
	)?;

	// build transaction skeleton with inputs and change
	let (parts, change_amounts_derivations) = inputs_and_change(
		&coins,
		wallet,
		parent_key_id,
		amount,
		fee,
		change_outputs,
		include_inputs_in_sum,
		current_height,
	)?;

	Ok((parts, coins, change_amounts_derivations, fee))
}

// return:  (optimal_outputs_num, min_outputs_num)
fn calculate_optimal_min_optputs(
	context_id: u32,
	fixed_fee: &Option<u64>,
	outputs_num: usize,
) -> Result<(usize, Option<usize>), Error> {
	match fixed_fee {
		Some(fixed_fee) => {
			let need_inputs_min = inputs_for_fee_points(context_id, *fixed_fee, outputs_num, 1)?;
			Ok((need_inputs_min, Some(need_inputs_min)))
		}
		None => Ok((inputs_for_minimal_fee(outputs_num, 1)?, None)),
	}
}

fn sum_output_values(coins: &[OutputData]) -> Result<u64, Error> {
	coins.iter().try_fold(0u64, |sum, coin| {
		sum.checked_add(coin.value).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::sum_output_values, selected output value overflow, sum={} output_value={}",
				sum, coin.value
			))
		})
	})
}

/// Select outputs and calculating fee.
/// fee - can be larger that standard fee, but never smaller.
pub fn select_coins_and_fee<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	amount_includes_fee: bool,
	min_fee: &Option<u64>,
	fixed_fee: Option<u64>, // Max fee to limit fee for late_lock case
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                   // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
) -> Result<
	(
		Vec<OutputData>,
		u64, // total
		u64, // amount
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context_id = wallet.get_context_id();
	validate_max_outputs(max_outputs)?;
	if routputs > max_outputs {
		return Err(Error::TooLargeSlate(max_outputs));
	}
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "routputs was validated not to exceed max_outputs"
	)]
	let max_inputs = max_outputs - routputs;

	// First attempt to spend without change
	let (optimal_outputs_num, min_outputs_num) =
		calculate_optimal_min_optputs(context_id, &fixed_fee, routputs)?;

	// select some spendable coins from the wallet
	let mut coins = select_coins(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_inputs, // Exclude number of recipient outputs.
		selection_strategy_is_use_all,
		parent_key_id,
		outputs, // outputs to include into the transaction
		exclude_change_outputs,
		change_output_minimum_confirmations,
		optimal_outputs_num,
		min_outputs_num,
	)?;

	if coins
		.len()
		.checked_add(routputs)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::select_coins_and_fee, selected output count overflow, coins_len={} recipient_outputs={}",
				coins.len(), routputs
			))
		})?
		> max_outputs
	{
		return Err(Error::TooLargeSlate(max_outputs))?;
	}

	// First attempt to spend without change
	if routputs == 0 {
		return Err(Error::GenericError(
			"At least one recipient output is required".to_string(),
		));
	}

	let mut fee = calc_fees(context_id, coins.len(), routputs, min_fee, &fixed_fee)?;
	let mut total = sum_output_values(&coins)?;
	let mut amount_with_fee = match amount_includes_fee {
		true => amount,
		false => amount.checked_add(fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::select_coins_and_fee, amount plus fee overflow, amount={} fee={}",
				amount, fee
			))
		})?,
	};

	// If change required...
	if total != amount_with_fee {
		// reseting to trigger first retry cycle
		total = 0;

		let num_outputs = change_outputs
			.checked_add(routputs)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"selection::select_coins_and_fee, transaction output count overflow, change_outputs={} recipient_outputs={}",
					change_outputs, routputs
				))
			})?;
		if num_outputs >= max_outputs {
			return Err(Error::TooLargeSlate(max_outputs));
		}
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "num_outputs was validated not to exceed max_outputs"
		)]
		let max_inputs = max_outputs - num_outputs;

		// Here fixed fee ignored with purpose, it is not a case here, fixed can be broken
		amount_with_fee = match amount_includes_fee {
			true => amount,
			false => {
				let recalculated_fee =
					calc_fees(context_id, coins.len(), num_outputs, min_fee, &None)?;
				amount.checked_add(recalculated_fee).ok_or_else(|| {
					Error::DataOverflow(format!(
						"selection::select_coins_and_fee, amount plus fee overflow, amount={} fee={}",
						amount, recalculated_fee
					))
				})?
			}
		};

		let (optimal_outputs_num, min_outputs_num) =
			calculate_optimal_min_optputs(context_id, &fixed_fee, num_outputs)?;

		// Here check if we have enough outputs for the amount including fee otherwise
		// look for other outputs and check again
		while total < amount_with_fee {
			// End the loop if we have selected all the outputs and still not enough funds

			let coins_len = coins.len();

			// select some spendable coins from the wallet
			coins = select_coins(
				wallet,
				amount_with_fee,
				current_height,
				minimum_confirmations,
				max_inputs,
				selection_strategy_is_use_all,
				parent_key_id,
				outputs,
				exclude_change_outputs,
				change_output_minimum_confirmations,
				optimal_outputs_num,
				min_outputs_num,
			)?;

			if coins
				.len()
				.checked_add(num_outputs)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"selection::select_coins_and_fee, selected output count overflow, coins_len={} transaction_outputs={}",
						coins.len(), num_outputs
					))
				})?
				> max_outputs
			{
				return Err(Error::TooLargeSlate(max_outputs))?;
			}

			fee = calc_fees(context_id, coins.len(), num_outputs, min_fee, &fixed_fee)?;

			total = sum_output_values(&coins)?;
			let prev_amount_with_fee = amount_with_fee;
			amount_with_fee = match amount_includes_fee {
				true => amount,
				false => amount.checked_add(fee).ok_or_else(|| {
					Error::DataOverflow(format!(
						"selection::select_coins_and_fee, amount plus fee overflow, amount={} fee={}",
						amount, fee
					))
				})?,
			};

			// Checking if new solution is better (has more outputs)
			// Don't checking outputs limit because light overcounting is fine
			if coins.len() <= coins_len && prev_amount_with_fee >= amount_with_fee {
				break;
			}
		}

		if total < amount_with_fee {
			return Err(Error::NotEnoughFunds {
				available: total as u64,
				available_disp: amount_to_hr_string(total, true),
				needed: amount_with_fee as u64,
				needed_disp: amount_to_hr_string(amount_with_fee as u64, true),
			})?;
		}
	}
	// If original amount includes fee, the new amount should
	// be reduced, to accommodate the fee.
	let new_amount = match amount_includes_fee {
		true => amount.checked_sub(fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::select_coins_and_fee, transaction amount is too small to include fee, amount={} fee={}",
				amount, fee
			))
		})?,
		false => amount,
	};
	Ok((coins, total, new_amount, fee))
}

/// Number of change outputs actually built, including the small-change policy.
/// Late-lock initialization uses the same calculation to budget Slatepack size.
pub(crate) fn change_output_count(change: u64, requested: usize) -> Result<usize, Error> {
	if change == 0 {
		return Ok(0);
	}
	if requested == 0 {
		return Err(Error::GenericError(
			"At least one change output is required when change is nonzero".to_owned(),
		));
	}
	// Avoid splitting change into outputs smaller than 0.1 MWC.
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "requested is nonzero and usize-to-u64 is lossless on supported targets"
	)]
	let change_per_output = change / requested as u64;
	if requested > 1 && change_per_output < 100_000_000 {
		let count = std::cmp::max(
			usize::try_from(change / 100_000_000).map_err(|_| {
				Error::DataOverflow(format!(
					"selection::change_output_count, change output count exceeds usize, change={}",
					change
				))
			})?,
			1,
		);
		warn!(
			"Transaction requested has {} change outputs with change amount {}. We don't want create many small outputs, the number of change outputs is reduced to {}.",
			requested, change, count
		);
		Ok(count)
	} else {
		Ok(requested)
	}
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<'a, T: ?Sized, C, K, B>(
	coins: &[OutputData],
	wallet: &mut T,
	parent_key_id: &Identifier,
	amount: u64,
	fee: u64,
	num_change_outputs: usize,
	include_inputs_in_sum: bool,
	current_height: u64,
) -> Result<
	(
		Vec<Box<build::Append<K, B>>>,
		Vec<(u64, Identifier, Option<u64>)>,
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	B: ProofBuild,
{
	let mut parts = vec![];

	// calculate the total across all inputs, and how much is left
	let total = sum_output_values(coins)?;

	// if we are spending 10,000 coins to send 1,000 then our change will be 9,000
	// if the fee is 80 then the recipient will receive 1000 and our change will be
	// 8,920
	let required = amount.checked_add(fee).ok_or_else(|| {
		Error::DataOverflow(format!(
			"selection::inputs_and_change, transaction amount plus fee overflow, amount={} fee={}",
			amount, fee
		))
	})?;
	let change = total.checked_sub(required).ok_or_else(|| {
		Error::DataOverflow(format!(
			"selection::inputs_and_change, selected inputs do not cover amount and fee, total={} required={}",
			total, required
		))
	})?;

	// build inputs using the appropriate derived key_ids
	if include_inputs_in_sum {
		for coin in coins {
			if coin.is_coinbase {
				parts.push(build::feature_input(
					coin.value,
					OutputFeatures::Coinbase,
					coin.key_id.clone(),
				));
			} else {
				parts.push(build::feature_input(
					coin.value,
					OutputFeatures::Plain,
					coin.key_id.clone(),
				));
			}
		}
	}

	let mut change_amounts_derivations = vec![];

	if change == 0 {
		debug!("No change (sending exactly amount + fee), no change outputs to build");
	} else {
		let num_change_outputs = change_output_count(change, num_change_outputs)?;

		debug!(
			"Building change outputs: total change: {} ({} outputs)",
			change, num_change_outputs
		);

		// The branch above preserves num_change_outputs >= 1.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "num_change_outputs is nonzero and usize-to-u64 is lossless on supported targets"
		)]
		let part_change = change / num_change_outputs as u64;
		let remainder_change = change.checked_rem(part_change).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::inputs_and_change, calculated change output amount is zero, change={} part_change={}",
				change, part_change
			))
		})?;
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "num_change_outputs is nonzero, so subtracting one cannot underflow"
		)]
		let last_change_output = num_change_outputs - 1;

		for x in 0..num_change_outputs {
			// n-1 equal change_outputs and a final one accounting for any remainder
			let change_amount = if x == last_change_output {
				part_change.checked_add(remainder_change).ok_or_else(|| {
					Error::DataOverflow(format!(
						"selection::inputs_and_change, final change output amount overflow, part_change={} remainder_change={}",
						part_change, remainder_change
					))
				})?
			} else {
				part_change
			};

			let change_key = wallet.next_child(Some(parent_key_id))?;

			change_amounts_derivations.push((change_amount, change_key.clone(), None));
			parts.push(build::height_tagged_output(
				change_amount,
				change_key,
				current_height,
			));
		}
	}

	Ok((parts, change_amounts_derivations))
}

fn validate_max_outputs(max_outputs: usize) -> Result<(), Error> {
	// Every transaction element has weight of at least one, so a value above
	// the production maximum block weight cannot describe a valid transaction.
	// Use the production bound here rather than the artificially small test
	// chain limit, since the public API default must remain valid in tests.
	let maximum = usize::try_from(consensus::MAX_BLOCK_WEIGHT).map_err(|e| {
		Error::DataOverflow(format!(
			"selection::validate_max_outputs, maximum block weight does not fit usize, value={} error={}",
			consensus::MAX_BLOCK_WEIGHT,
			e
		))
	})?;
	if max_outputs > maximum {
		return Err(Error::TooLargeSlate(maximum));
	}
	Ok(())
}

fn bounded_optimal_outputs_num(optimal_outputs_num: usize, max_outputs: usize) -> usize {
	// The optimum is only a selection preference. Keeping it inside the hard
	// input limit prevents the sliding-window search from stopping on an
	// oversized candidate while a later bounded candidate may still exist.
	std::cmp::min(optimal_outputs_num, max_outputs)
}

fn output_is_eligible_for_selection(
	out: &OutputData,
	outputs: &Option<HashSet<String>>,
	change_outputs: &HashSet<String>,
	current_height: u64,
	minimum_confirmations: u64,
	change_output_minimum_confirmations: u64,
) -> bool {
	if let Some(outputs) = outputs {
		// Explicit selection only narrows the eligible set; it must not bypass
		// spendability, maturity, confirmation, or reservation checks.
		let selected = match out.commit.as_ref() {
			Some(commit) => outputs.contains(commit),
			None => false,
		};
		if !selected {
			return false;
		}
	}

	// Change outputs normally use a lower confirmation threshold than regular
	// outputs. If an output is misclassified as regular (for example, because
	// its optional cached commitment is absent), the usual effect is delayed
	// selection rather than a critical loss-of-funds condition.
	let is_change = out
		.commit
		.as_ref()
		.map(|commit| change_outputs.contains(commit))
		.unwrap_or(false);
	let confirmations = if is_change {
		change_output_minimum_confirmations
	} else {
		minimum_confirmations
	};
	out.eligible_to_spend(current_height, confirmations)
}

/// Select spendable coins from a wallet.
/// Default strategy is to spend the maximum number of outputs (up to
/// max_outputs). Alternative strategy is to spend smallest outputs first
/// but only as many as necessary. When we introduce additional strategies
/// we should pass something other than a bool in.
/// TODO: Possibly move this into another trait to be owned by a wallet?
pub fn select_coins<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	select_all: bool,
	parent_key_id: &Identifier,
	outputs: &Option<HashSet<String>>, // outputs to include into the transaction
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
	optimal_outputs_num: usize,
	min_outputs_num: Option<usize>, // Minimal number of outputs. Needs to keep fee below some threshold (fee can be already fixed, so need it to be lower)
) -> Result<Vec<OutputData>, Error>
//    max_outputs_available, Outputs
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	validate_max_outputs(max_outputs)?;
	let mut change_outputs: HashSet<String> = HashSet::new();
	if exclude_change_outputs {
		// A zero general confirmation threshold explicitly permits every otherwise-spendable
		// output to be used without confirmations, including unconfirmed change. The separate
		// change threshold is intended for the usual policy where confirmed change requires
		// fewer confirmations than other outputs, so only confirmed sent transactions are
		// classified as change here.
		let txs: Vec<TxLogEntry> = wallet
			.tx_log_iter()?
			.filter(|tx_entry| tx_entry.tx_type == TxLogEntryType::TxSent && tx_entry.confirmed)
			.collect();

		for tx in &txs {
			for o in &tx.output_commits {
				let commit = format!("{}", mwc_util::to_hex(&o.0));
				change_outputs.insert(commit);
			}
		}
	}
	debug!(
		"exclude_change_outputs = {}, change_output_minimum_confirmations = {}",
		exclude_change_outputs, change_output_minimum_confirmations
	);
	// first find all eligible outputs based on number of confirmations
	let mut eligible = wallet
		.iter()?
		.filter(|out| {
			if out.root_key_id != *parent_key_id {
				return false;
			}
			output_is_eligible_for_selection(
				out,
				outputs,
				&change_outputs,
				current_height,
				minimum_confirmations,
				change_output_minimum_confirmations,
			)
		})
		.collect::<Vec<OutputData>>();

	// sort eligible outputs by increasing value
	eligible.sort_by_key(|out| out.value);

	let total_eligible = eligible.len();

	let mut optimal_outputs_num = bounded_optimal_outputs_num(optimal_outputs_num, max_outputs);

	let mut min_outputs_num = min_outputs_num.unwrap_or(0);
	if select_all {
		optimal_outputs_num = max_outputs;
		min_outputs_num = std::cmp::min(total_eligible, max_outputs);
	}

	// Implemention of real sliding window algo, 1 pass, no overhead for max_outputs 500 outputs.
	let mut i1 = 0;
	let mut amount_sum: u64 = 0;

	while i1 < total_eligible {
		let output = eligible.get(i1).ok_or_else(|| {
			Error::GenericError("Selected output index exceeds eligible outputs".to_owned())
		})?;
		amount_sum = amount_sum.checked_add(output.value).ok_or_else(|| {
			Error::DataOverflow(format!(
				"selection::select_coins, selected output value overflow, amount_sum={} output_value={}",
				amount_sum, output.value
			))
		})?;
		// i1 < total_eligible and total_eligible is a Vec length, so i1 + 1 fits usize.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "i1 is strictly below the Vec length, so adding one cannot overflow"
		)]
		{
			i1 += 1;
		}
		if amount_sum >= amount && i1 >= min_outputs_num {
			break;
		}
	}

	let mut best_idx0 = 0;
	let mut best_len = i1;
	let mut best_amount: u64 = amount_sum;

	for i0 in 0..total_eligible {
		if amount_sum >= amount {
			// solution is found. checking if it is a best
			debug_assert!(i0 < i1);
			// The sliding-window invariant advances i1 no slower than the for-loop's i0.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the sliding-window invariant guarantees i1 >= i0"
			)]
			let outputs_num = i1 - i0;
			if outputs_num >= min_outputs_num {
				let choose_new_solution = if best_len > max_outputs {
					outputs_num < best_len
				} else {
					match (
						outputs_num >= optimal_outputs_num,
						best_len >= optimal_outputs_num,
					) {
						// Preserve the existing preference for reaching the target,
						// even when the below-target count is numerically closer.
						(true, false) => true,
						(false, true) => false,
						_ => {
							outputs_num.abs_diff(optimal_outputs_num)
								< best_len.abs_diff(optimal_outputs_num)
						}
					}
				};

				if choose_new_solution {
					best_idx0 = i0;
					best_len = outputs_num;
					best_amount = amount_sum;

					if outputs_num == optimal_outputs_num {
						break; // it is possible best solution
					}
				}
			}

			let first_output = eligible.get(i0).ok_or_else(|| {
				Error::GenericError("Selected output index exceeds eligible outputs".to_owned())
			})?;
			amount_sum = amount_sum.checked_sub(first_output.value).ok_or_else(|| {
				Error::DataOverflow(format!(
					"selection::select_coins, selected output value underflow, amount_sum={} output_value={}",
					amount_sum, first_output.value
				))
			})?;

			// The sliding-window invariant guarantees i1 >= i0.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the sliding-window invariant guarantees i1 >= i0"
			)]
			while i1 < total_eligible {
				// Re-evaluate the window after every i1 advance.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the sliding-window invariant guarantees i1 >= i0"
				)]
				let selected_len = i1 - i0;
				if amount_sum >= amount && selected_len >= min_outputs_num {
					break;
				}
				let output = eligible.get(i1).ok_or_else(|| {
					Error::GenericError("Selected output index exceeds eligible outputs".to_owned())
				})?;
				amount_sum = amount_sum.checked_add(output.value).ok_or_else(|| {
					Error::DataOverflow(format!(
						"selection::select_coins, selected output value overflow, amount_sum={} output_value={}",
						amount_sum, output.value
					))
				})?;
				// i1 < total_eligible, so i1 + 1 fits usize.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "i1 is strictly below the Vec length, so adding one cannot overflow"
				)]
				{
					i1 += 1;
				}
			}
		} else {
			if amount_sum > best_amount {
				best_idx0 = i0;
				// The sliding-window invariant guarantees i1 >= i0.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the sliding-window invariant guarantees i1 >= i0"
				)]
				{
					best_len = i1 - i0;
				}
				best_amount = amount_sum;
			}
			if i1 >= total_eligible {
				break;
			}
		}
	}

	// best_idx0 and best_len describe a window within eligible, so the sum is at most eligible.len().
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "the selected window is maintained within the eligible Vec"
	)]
	let best_end = best_idx0 + best_len;
	Ok(eligible
		.get(best_idx0..best_end)
		.ok_or_else(|| Error::GenericError("Selected output range is invalid".to_owned()))?
		.to_vec())
}

/// Validate feature-bearing inputs owned by this wallet against its canonical
/// output records.
///
/// Current core-protocol transactions may represent inputs by commitment only.
/// There is no peer-controlled feature to validate in that representation. V2
/// and V3 JSON slates, however, carry `OutputFeatures` alongside each input, so
/// a returned slate must not be allowed to change a sender input between
/// `Plain` and `Coinbase` while retaining the same commitment.
pub(crate) fn validate_context_input_features<'a, T: ?Sized, C, K>(
	wallet: &T,
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
	let inputs = match &slate.tx_or_err()?.body.inputs {
		Inputs::CommitOnly(_) => return Ok(()),
		Inputs::FeaturesAndCommit(inputs) => inputs,
	};

	for (id, mmr, amount) in context.get_inputs() {
		let output = wallet.get(&id, &mmr)?;
		if amount != output.value {
			return Err(Error::SlateValidation(format!(
				"selection::validate_context_input_features, wallet input value mismatch for key_id={} mmr_index={:?}, actual={} expected={}",
				id, mmr, output.value, amount
			)));
		}

		let commit = wallet.calc_commit(secp, keychain_mask, output.value, &output.key_id)?;
		let input = inputs
			.iter()
			.find(|input| input.commitment() == commit)
			.ok_or_else(|| {
				Error::SlateValidation(format!(
					"selection::validate_context_input_features, sender input is missing from the returned slate, commitment={}",
					commit.to_hex()
				))
			})?;
		let expected = if output.is_coinbase {
			OutputFeatures::Coinbase
		} else {
			OutputFeatures::Plain
		};
		if input.features != expected {
			return Err(Error::SlateValidation(format!(
				"selection::validate_context_input_features, sender input feature mismatch, commitment={} actual={:?} expected={:?}",
				commit.to_hex(),
				input.features,
				expected
			)));
		}
	}

	Ok(())
}

/// Repopulates output in the slate's transaction
/// with outputs from the stored context
/// change outputs and tx log entry
/// Remove the explicitly stored excess
/// Note, this method is expecting to use for compact slates only
pub fn repopulate_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &mut Slate,
	context: &Context,
	update_fee: bool,
	// When set, include context outputs which have not been persisted yet.
	// Late-lock finalization uses this to build a complete, validation-only
	// transaction before committing change outputs or input locks. Ordinary
	// locking deliberately passes None: its first rebuild may omit an
	// unpersisted sender-change output, lock_tx_context then creates that output
	// record, and finalization rebuilds and stores the complete transaction.
	// The supplied height never replaces the original proof height in context.
	missing_output_height: Option<u64>,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !slate.compact_slate {
		return Err(Error::SlateValidation(
			"selection::repopulate_tx, operation requires a compact slate".to_string(),
		));
	}

	// restore the original amount, fee
	slate.amount = context.amount;
	if update_fee {
		slate.fee = context.fee;
	}

	let keychain = wallet.keychain(secp, keychain_mask)?;

	// restore my signature data
	slate.add_participant_info(
		secp,
		&context.sec_key,
		&context.sec_nonce,
		context.participant_id,
		None,
		context.message.clone(),
		#[cfg(feature = "test-support")]
		use_test_rng,
	)?;

	let mut parts = vec![];
	let existing_input_commits = slate
		.tx_or_err()?
		.inputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	let existing_output_commits = slate
		.tx_or_err()?
		.outputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;

	for (id, mmr, amount) in context.get_inputs() {
		let out = wallet.get(&id, &mmr)?;
		if amount != out.value {
			return Err(Error::GenericError(format!(
				"Internal error. Output value {} doesn't match expected {} for {} {:?}",
				out.value, amount, id, mmr
			)));
		}
		let commit = wallet.calc_commit(secp, keychain_mask, out.value, &out.key_id)?;
		if existing_input_commits.contains(&commit) {
			continue;
		}
		if out.is_coinbase {
			parts.push(build::feature_input(
				out.value,
				OutputFeatures::Coinbase,
				out.key_id.clone(),
			));
		} else {
			parts.push(build::feature_input(
				out.value,
				OutputFeatures::Plain,
				out.key_id.clone(),
			));
		}
	}

	let mut saved_outputs = None;
	for (id, mmr, amount) in context.get_outputs() {
		let stored_value = match tx_session {
			Some(ts_ses) => {
				// Session outputs must not already be present in the wallet database.
				match wallet.get(&id, &mmr) {
					Ok(_) => {
						return Err(Error::GenericError(format!(
							"selection::repopulate_tx, session output already exists, key_id={} mmr_index={:?}",
							id, mmr
						)));
					}
					// Expected: the session output has not been persisted yet.
					Err(Error::OutputNotFound(_)) => {}
					// A real backend failure must not be mistaken for absence.
					Err(e) => return Err(e),
				}

				ts_ses
					.get_outputs()
					.iter()
					.find(|out| out.key_id == id)
					.map(|out| out.value)
			}
			None => match wallet.get(&id, &mmr) {
				Ok(out) => Some(out.value),
				// Expected: the context output has not been persisted to the
				// wallet store (e.g. a not-yet-created change output).
				Err(Error::OutputNotFound(_)) => None,
				// A real backend failure must not be mistaken for absence.
				Err(e) => return Err(e),
			},
		};
		if let Some(value) = stored_value {
			if amount != value {
				return Err(Error::GenericError(format!(
					"Internal error. Output value {} doesn't match expected {} for {} {:?}",
					value, amount, id, mmr
				)));
			}
		} else if missing_output_height.is_none() {
			continue;
		}
		let commit = wallet.calc_commit(secp, keychain_mask, amount, &id)?;
		if existing_output_commits.contains(&commit) {
			continue;
		}
		if let Some((_, height)) = context
			.output_build_heights
			.iter()
			.find(|(key, _)| key == &id)
		{
			// A compact rebuild reuses the output key and commitment. Its rewind
			// nonce therefore reuses alpha/rho and sL/sR. Changing the message's
			// height under those masks can expose the amount, even when tau1/tau2
			// use a height-bound private nonce. Reuse the original height so the
			// complete proof is identical; OutputData.height is mutable lock/chain
			// metadata and must not be used as the proof construction height.
			parts.push(build::height_tagged_output(
				amount,
				id.clone(),
				*height,
			));
		} else {
			// Older contexts did not persist the original height. Reuse their
			// saved proof verbatim; never guess a height and create another proof.
			if saved_outputs.is_none() {
				let transaction = match tx_session {
					Some(session) => session.get_transaction().clone(),
					None => match wallet.get_stored_tx_by_uuid(&slate.id.to_string(), false) {
						Ok(tx) => Some(tx),
						Err(Error::TransactionNotFound(_)) => None,
						Err(e) => return Err(e),
					},
				};
				saved_outputs = Some(
					transaction
						.map(|tx| tx.outputs().to_vec())
						.unwrap_or_default(),
				);
			}
			let original = saved_outputs
				.as_ref()
				.and_then(|outputs| outputs.iter().find(|out| out.commitment() == commit))
				.ok_or_else(|| Error::SlateValidation(format!(
					"Cannot rebuild output {}: its original proof and construction height are unavailable. Cancel and recreate the transaction.",
					id
				)))?;
			parts.push(output_proof::existing_output(amount, id, original.clone()));
		}
	}

	let proof_builder = ProofBuilder::new(secp, &keychain)
		.map_err(|e| Error::GenericError(format!("Creating proof builder, {}", e)))?;
	slate
		.add_transaction_elements(
			wallet.get_context_id(),
			secp,
			&keychain,
			&proof_builder,
			parts,
		)
		.map_err(|e| Error::GenericError(format!("Repopulating transaction elements, {}", e)))?;
	// restore the original offset
	slate.tx_or_err_mut()?.offset = slate.offset.clone();
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn slatepack_change_budget_matches_small_change_policy() {
		assert_eq!(change_output_count(0, 100).unwrap(), 0);
		assert_eq!(change_output_count(1, 100).unwrap(), 1);
		assert_eq!(change_output_count(200_000_001, 100).unwrap(), 2);
		assert_eq!(change_output_count(10_000_000_000, 100).unwrap(), 100);
		assert!(change_output_count(1, 0).is_err());
	}

	#[test]
	fn max_outputs_rejects_full_usize_range() {
		assert!(validate_max_outputs(usize::MAX).is_err());
	}

	#[test]
	fn optimal_output_target_does_not_exceed_max_outputs() {
		assert_eq!(bounded_optimal_outputs_num(4, 1), 1);
		assert_eq!(bounded_optimal_outputs_num(1, 4), 1);
	}

	#[test]
	fn explicitly_selected_change_uses_change_confirmation_threshold() {
		let output = OutputData {
			root_key_id: Identifier::zero(),
			key_id: Identifier::zero(),
			n_child: 0,
			commit: Some("selected-change".to_owned()),
			mmr_index: None,
			value: 1,
			status: OutputStatus::Unspent,
			height: 8,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: None,
		};
		let selected_outputs = Some(["selected-change".to_owned()].into_iter().collect());
		let change_outputs = ["selected-change".to_owned()].into_iter().collect();

		// At height 10 this output has three confirmations. It meets the normal
		// threshold of two, but not the configured change threshold of four.
		assert!(!output_is_eligible_for_selection(
			&output,
			&selected_outputs,
			&change_outputs,
			10,
			2,
			4,
		));
		assert!(output_is_eligible_for_selection(
			&output,
			&selected_outputs,
			&change_outputs,
			10,
			4,
			3,
		));
	}
}
