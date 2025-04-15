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
use crate::internal::keys;
use crate::mwc_core::core::amount_to_hr_string;
use crate::mwc_core::libtx::{
	build,
	proof::{ProofBuild, ProofBuilder},
	tx_fee,
};
use crate::mwc_keychain::{Identifier, Keychain};
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::secp::pedersen::Commitment;
use crate::proof::proofaddress;
use crate::slate::Slate;
use crate::types::*;
use mwc_wallet_util::mwc_core::libtx::{inputs_for_fee_points, inputs_for_minimal_fee};
use mwc_wallet_util::mwc_util as util;
use std::collections::{HashMap, HashSet};

/// Initialize a transaction on the sender side, returns a corresponding
/// libwallet transaction slate with the appropriate inputs selected,
/// and saves the private wallet identifiers of our selected outputs
/// into our transaction context

pub fn build_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain: &K,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	min_fee: &Option<u64>,
	fixed_fee: Option<u64>, // Max fee to limit fee for late_lock case
	minimum_confirmations: u64,
	max_outputs: usize,
	change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: Identifier,
	participant_id: usize,
	use_test_nonce: bool,
	is_initiator: bool,
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
		slate.amount = slate.amount.checked_sub(fee).ok_or(Error::GenericError(
			"Transaction amount is too small to include fee".into(),
		))?;
	};

	// Update the fee on the slate so we account for this when building the tx.
	slate.fee = fee;

	let blinding = slate.add_transaction_elements(keychain, &ProofBuilder::new(keychain), elems)?;

	// Create our own private context
	let mut context = if slate.compact_slate {
		Context::new(
			keychain.secp(),
			//blinding.secret_key()?,
			&parent_key_id,
			use_test_nonce,
			is_initiator,
			participant_id,
			slate.amount,
			slate.fee,
			message,
		)
	} else {
		// Legacy part
		Context::with_excess(
			keychain.secp(),
			blinding.secret_key(keychain.secp())?,
			&parent_key_id,
			use_test_nonce,
			participant_id,
			slate.amount,
			slate.fee,
			message,
		)
	};

	// Store our private identifiers for each input
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value);
	}

	let mut commits: HashMap<Identifier, Option<String>> = HashMap::new();

	// Store change output(s) and cached commits
	for (change_amount, id, mmr_index) in &change_amounts_derivations {
		context.add_output(&id, &mmr_index, *change_amount);
		commits.insert(
			id.clone(),
			wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
		);
	}

	Ok(context)
}

/// Locks all corresponding outputs in the context, creates
/// change outputs and tx log entry
pub fn lock_tx_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	current_height: u64,
	context: &Context,
	address: Option<String>,
	excess_override: Option<Commitment>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut output_commits: HashMap<Identifier, (Option<String>, u64)> = HashMap::new();
	// Store cached commits before locking wallet
	let mut total_change = 0;
	for (id, _, change_amount) in &context.get_outputs() {
		output_commits.insert(
			id.clone(),
			(
				wallet.calc_commit_for_cache(keychain_mask, *change_amount, &id)?,
				*change_amount,
			),
		);
		total_change += change_amount;
	}

	debug!("Change amount is: {}", total_change);

	let keychain = wallet.keychain(keychain_mask)?;

	let tx_entry = {
		let lock_inputs = context.get_inputs();
		let messages = Some(slate.participant_messages());
		let slate_id = slate.id;
		let height = current_height;
		let parent_key_id = context.parent_key_id.clone();
		let mut batch = wallet.batch(keychain_mask)?;

		// Check if such transaction already exist. It is very possible for lock after case.
		let found_tx = batch
			.tx_log_iter()
			.filter(|tx_entry| {
				if tx_entry.tx_type != TxLogEntryType::TxSent {
					return false;
				}
				match tx_entry.tx_slate_id {
					None => false,
					Some(uuid) => uuid == slate_id,
				}
			})
			.next();

		let mut t = match found_tx {
			Some(tx) => tx,
			None => {
				// Creating a new record
				let log_id = batch.next_tx_log_id(&parent_key_id)?;
				TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, log_id)
			}
		};

		t.tx_slate_id = Some(slate_id);
		let filename = format!("{}.mwctx", slate_id);
		t.stored_tx = Some(filename);
		t.fee = Some(context.fee);
		t.ttl_cutoff_height = slate.ttl_cutoff_height;
		if t.ttl_cutoff_height == Some(0) {
			t.ttl_cutoff_height = None;
		}

		t.address = address;

		if let Ok(e) = slate.calc_excess(keychain.secp(), Some(&keychain), current_height) {
			t.kernel_excess = Some(e)
		}
		if let Some(e) = excess_override {
			debug_assert!(slate.compact_slate);
			t.kernel_excess = Some(e)
		}
		t.kernel_lookup_min_height = Some(current_height);

		let mut amount_debited = 0;
		t.num_inputs = lock_inputs.len();
		t.input_commits = context.input_commits.clone();

		if context.late_lock_args.is_none() || !t.input_commits.is_empty() {
			for id in lock_inputs {
				let mut coin = batch.get(&id.0, &id.1)?;
				coin.tx_log_entry = Some(t.id);
				amount_debited += coin.value;
				batch.lock_output(&mut coin)?;
			}
			t.amount_debited = amount_debited;
		} else {
			// It is lock later case. No inputs does exist yet.
			t.amount_debited = slate.amount;
		}

		t.messages = messages;

		// store extra payment proof info, if required
		if let Some(ref p) = slate.payment_proof {
			let sender_address_path = match context.payment_proof_derivation_index {
				Some(p) => p,
				None => {
					return Err(Error::PaymentProof(
						"Payment proof derivation index required".to_owned(),
					));
				}
			};
			// MQS type because public key is requred
			let sender_a = proofaddress::payment_proof_address_from_index(
				&keychain,
				sender_address_path,
				proofaddress::ProofAddressType::MQS,
			)?;
			t.payment_proof = Some(StoredProofInfo {
				receiver_address: p.receiver_address.clone(),
				receiver_signature: p.receiver_signature.clone(),
				sender_address: sender_a,
				sender_address_path,
				sender_signature: None,
			});
		};

		// write the output representing our change
		t.num_outputs = context.output_commits.len();
		t.output_commits = context.output_commits.clone();
		for (id, _, _) in &context.get_outputs() {
			let (commit, change_amount) = output_commits.get(&id).unwrap().clone();
			t.amount_credited += change_amount;
			batch.save(OutputData {
				root_key_id: parent_key_id.clone(),
				key_id: id.clone(),
				n_child: id.to_path().last_path_index(),
				commit: commit,
				mmr_index: None,
				value: change_amount,
				status: OutputStatus::Unconfirmed,
				height: height,
				lock_height: 0,
				is_coinbase: false,
				tx_log_entry: Some(t.id),
			})?;
		}
		batch.save_tx_log_entry(t.clone(), &parent_key_id)?;
		batch.commit()?;
		t
	};
	wallet.store_tx(
		&format!("{}", tx_entry.tx_slate_id.unwrap()),
		slate.tx_or_err()?,
	)?;
	Ok(())
}

/// Creates a new output in the wallet for the recipient,
/// returning the key of the fresh output
/// Also creates a new transaction containing the output
/// Note: key_id & output_amounts needed for secure claims.
pub fn build_recipient_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	address: Option<String>,
	parent_key_id: Identifier,
	participant_id: usize,
	key_id_opt: Option<&str>,
	output_amounts: Option<Vec<u64>>,
	use_test_rng: bool,
	is_initiator: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
	message: Option<String>,
) -> Result<(Identifier, Context, TxLogEntry), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Keeping keys with amounts because context want that ( <id>, <amount> )
	let mut key_vec_amounts = Vec::new();

	if output_amounts.is_some() {
		// Just calculating the key...
		let mut i = 0;
		let output_amounts_unwrapped = output_amounts.clone().unwrap();
		assert!(num_outputs == output_amounts_unwrapped.len());
		let mut sum = 0;
		for oaui in output_amounts_unwrapped {
			sum = sum + oaui;
			key_vec_amounts.push((
				keys::next_available_key(wallet, Some(&parent_key_id))?,
				oaui,
			));
			i = i + 1;
		}
		if sum != slate.amount {
			println!("mismatch sum = {}, amount = {}", sum, slate.amount);
			return Err(Error::AmountMismatch {
				amount: slate.amount,
				sum: sum,
			})?;
		}
	} else {
		// building transaction, apply provided key.
		let amount = slate.amount;
		let mut remaining_amount = amount;
		assert!(num_outputs > 0);
		for i in 0..num_outputs {
			let key_id = if key_id_opt.is_some() {
				// Note! No need to handle so far, that is why we have one key_id_opt, so num_outputs can be only 1
				// If it is not true - likely use case was changed.
				assert!(num_outputs == 1);
				let key_str = key_id_opt.unwrap();
				Identifier::from_hex(key_str)?
			} else {
				keys::next_available_key(wallet, Some(&parent_key_id))?
			};

			let output_amount: u64 = if i == num_outputs - 1 {
				remaining_amount
			} else {
				amount / (num_outputs as u64)
			};
			if output_amount > 0 {
				key_vec_amounts.push((key_id.clone(), output_amount));
				remaining_amount -= output_amount;
			}
		}
	}

	// Note, it is not very critical, has to match for all normal case,
	// might fail for edge case if we send very smaller coins amount
	debug_assert!(key_vec_amounts.len() == num_outputs);

	if slate.amount == 0 || num_outputs == 0 || key_vec_amounts.len() != num_outputs {
		return Err(Error::GenericError(format!(
			"Unable to build transaction for amount {} and outputs number {}",
			slate.amount, num_outputs
		)));
	}

	let keychain = wallet.keychain(keychain_mask)?;
	let amount = slate.amount;
	let height = current_height;

	let slate_id = slate.id.clone();

	let mut out_vec = Vec::new();
	for kva in &key_vec_amounts {
		out_vec.push(build::output(kva.1, kva.0.clone()));
	}

	let blinding =
		slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), out_vec)?;

	// Add blinding sum to our context
	let mut context = if slate.compact_slate {
		Context::new(
			keychain.secp(),
			&parent_key_id,
			use_test_rng,
			is_initiator,
			participant_id,
			amount,
			slate.fee,
			message,
		)
	} else {
		// Legacy model
		Context::with_excess(
			keychain.secp(),
			blinding.secret_key(keychain.secp())?,
			&parent_key_id,
			use_test_rng,
			participant_id,
			amount,
			slate.fee,
			message,
		)
	};

	for kva in &key_vec_amounts {
		context.add_output(&kva.0, &None, kva.1);
	}

	let messages = Some(slate.participant_messages());

	let mut commit_vec = Vec::new();
	let mut commit_ped = Vec::new();
	for kva in &key_vec_amounts {
		let commit = wallet.calc_commit_for_cache(keychain_mask, kva.1, &kva.0)?;
		if let Some(cm) = commit.clone() {
			commit_ped.push(Commitment::from_vec(util::from_hex(&cm).map_err(|e| {
				Error::GenericError(format!("Output commit parse error, {}", e))
			})?));
		}
		commit_vec.push(commit);
	}

	let mut batch = wallet.batch(keychain_mask)?;
	let log_id = batch.next_tx_log_id(&parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);
	t.tx_slate_id = Some(slate_id);
	t.amount_credited = amount;
	t.address = address;
	t.num_outputs = key_vec_amounts.len();
	t.output_commits = commit_ped;
	t.messages = messages;
	t.ttl_cutoff_height = slate.ttl_cutoff_height;
	//add the offset to the database tx record.
	let offset_skey = slate.tx_or_err()?.offset.secret_key(keychain.secp())?;
	let offset_commit = keychain.secp().commit(0, offset_skey)?;
	t.kernel_offset = Some(offset_commit);

	if t.ttl_cutoff_height == Some(0) {
		t.ttl_cutoff_height = None;
	}

	// when invoicing, this will be invalid
	if let Ok(e) = slate.calc_excess(keychain.secp(), Some(&keychain), current_height) {
		t.kernel_excess = Some(e)
	}
	t.kernel_lookup_min_height = Some(current_height);
	batch.save_tx_log_entry(t.clone(), &parent_key_id)?;

	let mut i = 0;
	for kva in &key_vec_amounts {
		batch.save(OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: kva.0.clone(),
			mmr_index: None,
			n_child: kva.0.to_path().last_path_index(),
			commit: commit_vec[i].clone(),
			value: kva.1,
			status: OutputStatus::Unconfirmed,
			height: height,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(log_id),
		})?;
		i = i + 1;
	}
	batch.commit()?;

	// returning last key that was used in the chain.
	// That suppose to satisfy all caller needs
	Ok((key_vec_amounts.last().unwrap().0.clone(), context, t))
}

fn calc_fees(
	input_num: usize,
	output_num: usize,
	min_fee: &Option<u64>,
	fixed_fee: &Option<u64>, // Max fee to limit fee for late_lock case
) -> Result<u64, Error> {
	let mut fee = tx_fee(input_num, output_num, 1);
	if let Some(min_fee) = min_fee {
		fee = std::cmp::max(*min_fee, fee);
	}
	if let Some(fixed_fee) = fixed_fee {
		if fee > *fixed_fee {
			return Err(Error::Fee(format!("Unable to finalize transaction with already locked fee {}. Please cancel transaction and retry, or use more outputs to reduce the fee.", fixed_fee)));
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
	fixed_fee: &Option<u64>,
	outputs_num: usize,
) -> (usize, Option<usize>) {
	match fixed_fee {
		Some(fixed_fee) => {
			let need_inputs_min = inputs_for_fee_points(*fixed_fee, outputs_num, 1);
			(need_inputs_min, Some(need_inputs_min))
		}
		None => (inputs_for_minimal_fee(outputs_num, 1), None),
	}
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
	// First attempt to spend without change
	let (optimal_outputs_num, min_outputs_num) =
		calculate_optimal_min_optputs(&fixed_fee, routputs);

	// select some spendable coins from the wallet
	let mut coins = select_coins(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs.saturating_sub(routputs), // Exclude number sof outpus
		selection_strategy_is_use_all,
		parent_key_id,
		outputs, // outputs to include into the transaction
		exclude_change_outputs,
		change_output_minimum_confirmations,
		optimal_outputs_num,
		min_outputs_num,
	);

	if coins.len() + routputs > max_outputs {
		return Err(Error::TooLargeSlate(max_outputs))?;
	}

	// First attempt to spend without change
	assert!(routputs >= 1); // Normally it is 1

	let mut fee = calc_fees(coins.len(), routputs, min_fee, &fixed_fee)?;
	let mut total: u64 = coins.iter().map(|c| c.value).sum();
	let mut amount_with_fee = match amount_includes_fee {
		true => amount,
		false => amount + fee,
	};

	// If change required...
	if total != amount_with_fee {
		// reseting to trigger first retry cycle
		total = 0;

		let num_outputs = change_outputs + routputs;

		// Here fixed fee ignored with purpose, it is not a case here, fixed can be broken
		amount_with_fee = match amount_includes_fee {
			true => amount,
			false => amount + calc_fees(coins.len(), num_outputs, min_fee, &None)?,
		};

		let (optimal_outputs_num, min_outputs_num) =
			calculate_optimal_min_optputs(&fixed_fee, num_outputs);

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
				max_outputs.saturating_sub(num_outputs),
				selection_strategy_is_use_all,
				parent_key_id,
				outputs,
				exclude_change_outputs,
				change_output_minimum_confirmations,
				optimal_outputs_num,
				min_outputs_num,
			);

			if coins.len() + num_outputs > max_outputs {
				return Err(Error::TooLargeSlate(max_outputs))?;
			}

			fee = calc_fees(coins.len(), num_outputs, min_fee, &fixed_fee)?;

			total = coins.iter().map(|c| c.value).sum();
			let prev_amount_with_fee = amount_with_fee;
			amount_with_fee = match amount_includes_fee {
				true => amount,
				false => amount + fee,
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
		true => amount.checked_sub(fee).ok_or(Error::GenericError(
			"Transaction amount is too small to include fee".into(),
		))?,
		false => amount,
	};
	Ok((coins, total, new_amount, fee))
}

/// Selects inputs and change for a transaction
pub fn inputs_and_change<'a, T: ?Sized, C, K, B>(
	coins: &[OutputData],
	wallet: &mut T,
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
	let total: u64 = coins.iter().map(|c| c.value).sum();

	// if we are spending 10,000 coins to send 1,000 then our change will be 9,000
	// if the fee is 80 then the recipient will receive 1000 and our change will be
	// 8,920
	let change = total - amount - fee;

	// build inputs using the appropriate derived key_ids
	if include_inputs_in_sum {
		for coin in coins {
			if coin.is_coinbase {
				parts.push(build::coinbase_input(coin.value, coin.key_id.clone()));
			} else {
				parts.push(build::input(coin.value, coin.key_id.clone()));
			}
		}
	}

	let mut change_amounts_derivations = vec![];

	if change == 0 {
		debug!("No change (sending exactly amount + fee), no change outputs to build");
	} else {
		// we don't want part_change to be zero. Also we really don't want many small change outputs
		// If change less then 0.1 MWC, let's make it in one output.  1-in 2-out Tx fee will is: 4*2+1-1 = 0.008 MWC
		// We don't want many small outputs like that
		let num_change_outputs = if num_change_outputs > 1
			&& change / (num_change_outputs as u64) < 100_000_000
		{
			warn!("Transaction requested has {} change outputs with change amount {}. We don't want create many small outputs, the number of change outputs is reduced to 1", num_change_outputs, change);
			1
		} else {
			num_change_outputs
		};

		debug!(
			"Building change outputs: total change: {} ({} outputs)",
			change, num_change_outputs
		);

		let part_change = change / num_change_outputs as u64;
		let remainder_change = change % part_change;

		for x in 0..num_change_outputs {
			// n-1 equal change_outputs and a final one accounting for any remainder
			let change_amount = if x == (num_change_outputs - 1) {
				part_change + remainder_change
			} else {
				part_change
			};

			let change_key = wallet.next_child(None, Some(current_height))?;

			change_amounts_derivations.push((change_amount, change_key.clone(), None));
			parts.push(build::output(change_amount, change_key));
		}
	}

	Ok((parts, change_amounts_derivations))
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
) -> Vec<OutputData>
//    max_outputs_available, Outputs
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut change_outputs: HashSet<String> = HashSet::new();
	if exclude_change_outputs {
		let txs: Vec<TxLogEntry> = wallet
			.tx_log_iter()
			.filter(|tx_entry| tx_entry.tx_type == TxLogEntryType::TxSent && tx_entry.confirmed)
			.collect();

		for tx in &txs {
			for o in &tx.output_commits {
				let commit = format!("{}", util::to_hex(&o.0));
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
		.iter()
		.filter(|out| {
			if out.root_key_id != *parent_key_id {
				return false;
			}
			match outputs {
				Some(outputs) => {
					// selected outputs case
					if let Some(commit) = out.commit.as_ref() {
						return outputs.contains(commit);
					} else {
						return false;
					}
				}
				None => {
					// all outputs case exclude change
					let is_change = if let Some(commit) = out.commit.as_ref() {
						change_outputs.contains(commit)
					} else {
						false
					};

					let confirmations = if is_change {
						change_output_minimum_confirmations
					} else {
						minimum_confirmations
					};
					return out.eligible_to_spend(current_height, confirmations);
				}
			}
		})
		.collect::<Vec<OutputData>>();

	// sort eligible outputs by increasing value
	eligible.sort_by_key(|out| out.value);

	let total_eligible = eligible.len();

	let mut optimal_outputs_num: i32 = optimal_outputs_num as i32;

	let mut min_outputs_num = min_outputs_num.unwrap_or(0);
	if select_all {
		optimal_outputs_num = max_outputs as i32;
		min_outputs_num = std::cmp::min(total_eligible, max_outputs);
	}

	// Implemention of real sliding window algo, 1 pass, no overhead for max_outputs 500 outputs.
	let mut i1 = 0;
	let mut amount_sum: u64 = 0;

	while i1 < total_eligible {
		amount_sum += eligible[i1].value;
		i1 += 1;
		if amount_sum >= amount && i1 >= min_outputs_num {
			break;
		}
	}

	let mut best_idx0 = 0;
	let mut best_len = i1;
	let mut best_amount: u64 = amount_sum;

	for i0 in 0..total_eligible {
		if amount_sum >= amount {
			debug_assert!(i0 < i1);
			// solution is found. checking if it is a best
			let outputs_num: i32 = (i1 - i0) as i32;
			if outputs_num as usize >= min_outputs_num {
				let this_diff = outputs_num - optimal_outputs_num;
				let best_diff = best_len as i32 - optimal_outputs_num;

				let choose_new_solution = if best_len > max_outputs {
					outputs_num < best_len as i32
				} else if this_diff >= 0 {
					// For positive (extra inputs) prefer solution with smaller difference. 0 is ideal number
					this_diff < best_diff || best_diff < 0
				} else {
					// For negative, take existing positive, or bigger negative
					best_diff < 0 && this_diff > best_diff
				};

				if choose_new_solution {
					best_idx0 = i0;
					best_len = outputs_num as usize;
					best_amount = amount_sum;

					if this_diff == 0 {
						break; // it is possible best solution
					}
				}
			}

			amount_sum -= eligible[i0].value;

			while i1 < total_eligible && (amount_sum < amount || i1 - i0 < min_outputs_num as usize)
			{
				amount_sum += eligible[i1].value;
				i1 += 1;
			}
		} else {
			if amount_sum > best_amount {
				best_idx0 = i0;
				best_len = i1 - i0;
				best_amount = amount_sum;
			}
			if i1 >= total_eligible {
				break;
			}
		}
	}

	eligible[best_idx0..best_idx0 + best_len].to_vec()
}

/// Repopulates output in the slate's tranacstion
/// with outputs from the stored context
/// change outputs and tx log entry
/// Remove the explicitly stored excess
pub fn repopulate_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	update_fee: bool,
	use_test_rng: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Expected to be called at compact slate model only
	debug_assert!(slate.compact_slate);

	// restore the original amount, fee
	slate.amount = context.amount;
	if update_fee {
		slate.fee = context.fee;
	}

	let keychain = wallet.keychain(keychain_mask)?;

	// restore my signature data
	slate.add_participant_info(
		keychain.secp(),
		&context.sec_key,
		&context.sec_nonce,
		context.participant_id,
		None,
		context.message.clone(),
		use_test_rng,
	)?;

	let mut parts = vec![];

	for (id, mmr, amount) in context.get_inputs() {
		let out = wallet.get(&id, &mmr)?;
		if amount != out.value {
			return Err(Error::GenericError(format!(
				"Internal error. Output value {} doesn't match expected {} for {} {:?}",
				out.value, amount, id, mmr
			)));
		}
		if out.is_coinbase {
			parts.push(build::coinbase_input(out.value, out.key_id.clone()));
		} else {
			parts.push(build::input(out.value, out.key_id.clone()));
		}
	}

	for (id, mmr, amount) in context.get_outputs() {
		if let Ok(out) = wallet.get(&id, &mmr) {
			if amount != out.value {
				return Err(Error::GenericError(format!(
					"Internal error. Output value {} doesn't match expected {} for {} {:?}",
					out.value, amount, id, mmr
				)));
			}
			parts.push(build::output(out.value, out.key_id.clone()));
		}
	}

	slate.add_transaction_elements(&keychain, &ProofBuilder::new(&keychain), parts)?;
	// restore the original offset
	slate.tx_or_err_mut()?.offset = slate.offset.clone();
	Ok(())
}
