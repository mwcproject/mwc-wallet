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

#![cfg(feature = "test-support")]

extern crate mwc_wallet_util;

use mwc_wallet_impls::test_framework::LocalWalletClient;
use mwc_wallet_libwallet::{foreign, BlockFees, Error, OutputData, OutputStatus};
use mwc_wallet_util::mwc_core::core::{hash::Hash, Transaction};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain};
use mwc_wallet_util::mwc_util::{ToHex, ZeroingString};
use mwc_wallet_util::Mutex;
use std::sync::Arc;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn coinbase_key_reuse_test_impl(test_dir: &str) -> Result<(), Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool);

	create_wallet_and_add!(
		client,
		wallet,
		mask,
		test_dir,
		"wallet",
		None::<ZeroingString>,
		&mut wallet_proxy,
		false
	);

	let keychain_mask = (&mask).as_ref();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;

	// Exercise mandatory S2C mining below the fixed height-4 activation. The
	// backend test covers the same key reservation rules after activation.
	// A caller-supplied key must not turn an ordinary pending output into a
	// coinbase output or erase its transaction association.
	let pending_output = {
		wallet_inst!(wallet, w);
		let parent_key_id = w.parent_key_id();
		let key_id = w.next_child(None)?;
		let value = 42_000_000;
		let commit = w.calc_commit(&secp, keychain_mask, value, &key_id)?;
		let output = OutputData {
			root_key_id: parent_key_id,
			key_id: key_id.clone(),
			n_child: mwc_wallet_libwallet::internal::keys::output_child_index(&key_id)?,
			commit: Some(commit.to_hex()),
			mmr_index: None,
			value,
			status: OutputStatus::Unconfirmed,
			height: 0,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(7),
		};
		let mut batch = w.batch(&secp, keychain_mask)?;
		batch.save(output.clone())?;
		// Simulate stale derivation metadata. The first fresh allocation will
		// return this already occupied key, so receive_coinbase must advance
		// again instead of overwriting the pending output.
		batch.save_child_index(&output.root_key_id, 0)?;
		batch.commit()?;
		output
	};

	let pending_reuse = BlockFees {
		binding_digest: Hash::from_vec(&[1u8; 32]).to_hex(),
		fees: 0,
		height: 1,
		key_id: Some(pending_output.key_id.clone()),
	};
	let pending_fallback = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &pending_reuse)?
	};
	let pending_fallback_key = pending_fallback.key_id.ok_or_else(|| {
		Error::GenericError("Fallback coinbase response did not contain a key id".into())
	})?;
	assert_ne!(pending_fallback_key, pending_output.key_id);
	{
		wallet_inst!(wallet, w);
		assert_eq!(
			w.get(&pending_output.key_id, &pending_output.mmr_index)?,
			pending_output
		);
		assert!(w.get(&pending_fallback_key, &None)?.is_coinbase);
	}

	// An unconfirmed coinbase output belonging to another account is not an
	// eligible retry candidate for the active account.
	let cross_account_output = {
		let parent_key_id = ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?;
		let key_id = ExtKeychain::derive_key_id(3, 1, 0, 7, 0)?;
		wallet_inst!(wallet, w);
		let value = 60_000_000_000;
		let commit = w.calc_commit(&secp, keychain_mask, value, &key_id)?;
		let output = OutputData {
			root_key_id: parent_key_id,
			key_id: key_id.clone(),
			n_child: mwc_wallet_libwallet::internal::keys::output_child_index(&key_id)?,
			commit: Some(commit.to_hex()),
			mmr_index: None,
			value,
			status: OutputStatus::Unconfirmed,
			height: 2,
			lock_height: 2,
			is_coinbase: true,
			tx_log_entry: None,
		};
		let mut batch = w.batch(&secp, keychain_mask)?;
		batch.save(output.clone())?;
		batch.commit()?;
		output
	};

	let cross_account_reuse = BlockFees {
		binding_digest: Hash::from_vec(&[1u8; 32]).to_hex(),
		fees: 0,
		height: 2,
		key_id: Some(cross_account_output.key_id.clone()),
	};
	let cross_account_fallback = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(
			&mut **w,
			&mut secp,
			keychain_mask,
			&cross_account_reuse,
		)?
	};
	let cross_account_fallback_key = cross_account_fallback.key_id.ok_or_else(|| {
		Error::GenericError("Fallback coinbase response did not contain a key id".into())
	})?;
	assert_ne!(cross_account_fallback_key, cross_account_output.key_id);
	{
		wallet_inst!(wallet, w);
		assert_eq!(
			w.get(
				&cross_account_output.key_id,
				&cross_account_output.mmr_index
			)?,
			cross_account_output
		);
		assert!(w.get(&cross_account_fallback_key, &None)?.is_coinbase);
	}

	// A stale key may no longer have an unindexed record. Treat a missing
	// requested key like any other ineligible retry and return a fresh key.
	let missing_key_id = ExtKeychain::derive_key_id(3, 2, 0, 99, 0)?;
	let missing_reuse = BlockFees {
		binding_digest: Hash::from_vec(&[1u8; 32]).to_hex(),
		fees: 0,
		height: 2,
		key_id: Some(missing_key_id.clone()),
	};
	let missing_fallback = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &missing_reuse)?
	};
	let missing_fallback_key = missing_fallback.key_id.ok_or_else(|| {
		Error::GenericError("Fallback coinbase response did not contain a key id".into())
	})?;
	assert_ne!(missing_fallback_key, missing_key_id);
	{
		wallet_inst!(wallet, w);
		assert!(w.get(&missing_fallback_key, &None)?.is_coinbase);
	}

	// Preserve the miner retry behavior for a genuine unconfirmed coinbase
	// candidate in the active account.
	let initial_fees = BlockFees {
		binding_digest: Hash::from_vec(&[1u8; 32]).to_hex(),
		fees: 0,
		height: 3,
		key_id: None,
	};
	let initial_coinbase = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &initial_fees)?
	};
	let coinbase_key_id = initial_coinbase
		.key_id
		.ok_or_else(|| Error::GenericError("Coinbase response did not contain a key id".into()))?;

	let retry_fees = BlockFees {
		binding_digest: Hash::from_vec(&[1u8; 32]).to_hex(),
		fees: 1_000_000,
		height: 3,
		key_id: Some(coinbase_key_id.clone()),
	};
	let transaction_associated_candidate = {
		wallet_inst!(wallet, w);
		let mut stored = w.get(&coinbase_key_id, &None)?;
		stored.tx_log_entry = Some(99);
		let mut batch = w.batch(&secp, keychain_mask)?;
		batch.save(stored.clone())?;
		batch.commit()?;
		stored
	};
	let associated_fallback = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &retry_fees)?
	};
	let associated_fallback_key = associated_fallback.key_id.ok_or_else(|| {
		Error::GenericError("Fallback coinbase response did not contain a key id".into())
	})?;
	assert_ne!(associated_fallback_key, coinbase_key_id);
	{
		wallet_inst!(wallet, w);
		assert_eq!(
			w.get(&coinbase_key_id, &None)?,
			transaction_associated_candidate
		);
		assert!(w.get(&associated_fallback_key, &None)?.is_coinbase);
		let mut reusable = transaction_associated_candidate;
		reusable.tx_log_entry = None;
		let mut batch = w.batch(&secp, keychain_mask)?;
		batch.save(reusable)?;
		batch.commit()?;
	}

	let rebuilt_coinbase = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &retry_fees)?
	};
	assert_eq!(rebuilt_coinbase.key_id, Some(coinbase_key_id.clone()));
	{
		wallet_inst!(wallet, w);
		let stored = w.get(&coinbase_key_id, &None)?;
		assert!(stored.is_coinbase);
		assert_eq!(stored.status, OutputStatus::Unconfirmed);
		assert_eq!(stored.tx_log_entry, None);
		assert_eq!(stored.height, retry_fees.height);
	}

	Ok(())
}

#[test]
fn validates_caller_supplied_coinbase_key_reuse() {
	let test_dir = "test_output/coinbase_key_reuse";
	setup(test_dir);
	let result = coinbase_key_reuse_test_impl(test_dir);
	clean_output_dir(test_dir);
	if let Err(e) = result {
		panic!("Libwallet Error: {}", e);
	}
}

fn scan_older_coinbase_job(
	test_dir: &str,
	reuse_key: bool,
	replacement_height: u64,
	stale_indexed_record: Option<OutputStatus>,
) -> Result<(), Box<dyn std::error::Error>> {
	use mwc_wallet_controller::controller::owner_single_use;
	use mwc_wallet_impls::test_framework;
	use mwc_wallet_libwallet::{InitTxArgs, TxLogEntryType};
	use mwc_wallet_util::mwc_core::consensus;
	use mwc_wallet_util::mwc_core::core::Committed;

	let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	create_wallet_and_add!(
		client,
		wallet,
		mask,
		test_dir,
		"wallet",
		None::<ZeroingString>,
		&mut wallet_proxy,
		false
	);
	let keychain_mask = mask.as_ref();
	let proxy_handle = wallet_proxy.start();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(Error::from)?;
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		keychain_mask,
		3,
		false,
		&mut vec![],
	)?;

	// Build a real job A at the binding activation height without submitting
	// it. Then build B, either on a fresh key or by overwriting A as an older
	// miner can do. A's solved block and rangeproof remain available in both cases.
	let block_a = test_framework::create_block_for_wallet(
		&chain,
		chain.head_header()?,
		&[],
		wallet.clone(),
		keychain_mask,
	)?;
	let commit_a = block_a
		.outputs()
		.iter()
		.find(|out| out.is_coinbase())
		.unwrap()
		.commitment();
	let output_a = {
		wallet_inst!(wallet, w);
		w.iter()?
			.find(|out| out.commit.as_deref() == Some(commit_a.to_hex().as_str()))
			.unwrap()
	};
	let request_b = BlockFees {
		fees: 1_000_000,
		height: replacement_height,
		key_id: reuse_key.then(|| output_a.key_id.clone()),
		binding_digest: Hash::from_vec(&[2; 32]).to_hex(),
	};
	let coinbase_b = {
		wallet_inst!(wallet, w);
		foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &request_b)?
	};
	let key_b = coinbase_b.key_id.clone().unwrap();
	assert_eq!(key_b == output_a.key_id, reuse_key);
	assert_ne!(coinbase_b.output.commitment(), commit_a);
	{
		wallet_inst!(wallet, w);
		let count = w.iter()?.count();
		let repeated = foreign::build_coinbase(
			&mut **w,
			&mut secp,
			keychain_mask,
			&BlockFees {
				key_id: Some(key_b.clone()),
				..request_b.clone()
			},
		)?;
		assert_eq!(repeated.output, coinbase_b.output);
		assert_eq!(
			w.iter()?.count(),
			count,
			"same-fee rebuilds must not add outputs"
		);
	}

	// Scanning while the chain is still at H-1 must preserve every pending
	// candidate, regardless of database iteration order. If A was overwritten,
	// only B is stored at this point; scan must recover A later from its proof.
	owner_single_use(Some(wallet.clone()), keychain_mask, None, |api, m| {
		Ok(api.scan(m, Some(1), None, false)?)
	})?;
	{
		wallet_inst!(wallet, w);
		assert_eq!(
			w.get(&key_b, &None)?.commit,
			Some(coinbase_b.output.commitment().to_hex())
		);
		if !reuse_key {
			assert_eq!(w.get(&output_a.key_id, &None)?, output_a);
		}
	}
	test_framework::process_block(&chain, block_a)?;

	if let Some(status) = &stale_indexed_record {
		// Advance past B's height so an unchanged Reverted row is cleaned up,
		// while an Unspent row is updated and saved. Neither may undo recovery.
		test_framework::award_blocks_to_wallet(
			&chain,
			wallet.clone(),
			keychain_mask,
			1,
			false,
			&mut vec![],
		)?;
		// Model a stale indexed record whose key and MMR position belong to
		// A, but whose commitment and amount still describe fee variant B.
		// Restoring A must survive the rest of this same scan's writes.
		wallet_inst!(wallet, w);
		let mut stale = w.get(&key_b, &None)?;
		// Chain positions are zero-based; wallet/API MMR indices are one-based.
		stale.mmr_index = Some(chain.get_output_pos(&commit_a)? + 1);
		stale.status = status.clone();
		let mut batch = w.batch(&secp, keychain_mask)?;
		batch.delete(&key_b, &None)?;
		batch.save(stale)?;
		batch.commit()?;
	}

	// The older job wins. Scan twice to prove restoration is idempotent and
	// creates exactly one confirmed record and transaction for A's real value.
	for _ in 0..2 {
		owner_single_use(Some(wallet.clone()), keychain_mask, None, |api, m| {
			Ok(api.scan(m, Some(1), None, false)?)
		})?;
		wallet_inst!(wallet, w);
		let recovered: Vec<_> = w
			.iter()?
			.filter(|out| out.commit == output_a.commit)
			.collect();
		assert_eq!(recovered.len(), 1);
		let recovered = &recovered[0];
		assert_eq!(recovered.status, OutputStatus::Unspent);
		assert_eq!(recovered.key_id, output_a.key_id);
		assert_eq!(recovered.height, 4);
		assert_eq!(recovered.value, consensus::reward(0, 0, 4)?);
		assert!(recovered.mmr_index.is_some());
		let logs: Vec<_> = w
			.tx_log_iter()?
			.filter(|tx| tx.output_commits.contains(&commit_a))
			.collect();
		assert_eq!(logs.len(), 1);
		assert!(logs[0].confirmed);
		assert_eq!(logs[0].tx_type, TxLogEntryType::ConfirmedCoinbase);
		assert_eq!(logs[0].amount_credited, recovered.value);
		assert_eq!(logs[0].output_height, recovered.height);
		// A future-height candidate survives recovery even when it shares A's key.
		// An absent candidate at an already mined height is removed in this scan.
		if stale_indexed_record.is_none() && replacement_height > chain.head()?.height {
			assert_eq!(w.get(&key_b, &None)?.status, OutputStatus::Unconfirmed);
			// Explicit selection must not make the losing pending candidate
			// spendable, even with zero required confirmations.
			let parent = w.parent_key_id();
			let selected = mwc_wallet_libwallet::internal::selection::select_coins(
				&mut **w,
				1,
				chain.head()?.height,
				0,
				1,
				true,
				&parent,
				&Some(std::collections::HashSet::from([coinbase_b
					.output
					.commitment()
					.to_hex()])),
				false,
				0,
				1,
				None,
			)?;
			assert!(
				selected.is_empty(),
				"the losing fee variant cannot be spent"
			);
		} else {
			assert!(w.get(&key_b, &None).is_err());
		}
	}

	// Once the chain passes B's height, its unmatched pending record expires.
	// Deleting it must leave the confirmed, indexed A record intact.
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		keychain_mask,
		(replacement_height - 4 + 1) as usize,
		false,
		&mut vec![],
	)?;
	owner_single_use(Some(wallet.clone()), keychain_mask, None, |api, m| {
		Ok(api.scan(m, Some(1), None, false)?)
	})?;
	{
		wallet_inst!(wallet, w);
		assert!(w.get(&key_b, &None).is_err());
		let outputs: Vec<_> = w
			.iter()?
			.filter(|out| out.commit == output_a.commit)
			.collect();
		assert_eq!(outputs.len(), 1);
		assert_eq!(outputs[0].status, OutputStatus::Unspent);
	}
	// A recovered row is not enough: wait for maturity, select A by its real
	// commitment, finalize a self-send, and mine it through chain validation.
	let maturity = mwc_wallet_util::mwc_core::global::coinbase_maturity(0);
	let blocks_to_maturity = (4 + maturity).saturating_sub(chain.head()?.height);
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		keychain_mask,
		blocks_to_maturity as usize,
		false,
		&mut vec![],
	)?;
	let tx = owner_single_use(Some(wallet.clone()), keychain_mask, None, |api, m| {
		let args = InitTxArgs {
			amount: output_a.value,
			amount_includes_fee: Some(true),
			minimum_confirmations: 1,
			num_change_outputs: 0,
			selection_strategy_is_use_all: true,
			outputs: Some(std::collections::HashSet::from([commit_a.to_hex()])),
			..Default::default()
		};
		let slate = api.init_send_tx(m, None, &args, 1)?;
		let slate = client.send_tx_slate_direct("wallet", &slate)?;
		api.tx_lock_outputs(m, None, &slate, None, 0)?;
		let slate = api.finalize_tx(m, None, &slate, true)?;
		let tx = slate.tx_or_err()?.clone();
		api.post_tx(m, &tx, false)?;
		Ok(tx)
	})?;
	let inputs: Vec<_> = tx.inputs_committed()?.collect::<Result<_, _>>()?;
	assert_eq!(
		inputs,
		vec![commit_a],
		"the spend must use A, not fee variant B"
	);
	chain.validate_tx(&tx)?;
	let transactions = tx_pool.lock().clone();
	assert_eq!(transactions.len(), 1);
	test_framework::award_block_to_wallet(&chain, &transactions, wallet.clone(), keychain_mask)?;
	owner_single_use(Some(wallet.clone()), keychain_mask, None, |api, m| {
		Ok(api.scan(m, Some(1), None, false)?)
	})?;
	{
		wallet_inst!(wallet, w);
		let spent = w.iter()?.find(|out| out.commit == output_a.commit).unwrap();
		assert_eq!(spent.status, OutputStatus::Spent);
	}

	proxy_handle.stop()?;
	Ok(())
}

#[test]
fn scan_recovers_older_coinbase_jobs() {
	// Cover separate same-height candidates, a same-height overwrite, and an
	// overwrite with a later height. All must confirm the actual older job A.
	for (name, reuse_key, replacement_height) in [
		("separate", false, 4),
		("overwritten", true, 4),
		("later_height", true, 5),
	] {
		let test_dir = format!("test_output/coinbase_scan_{}", name);
		setup(&test_dir);
		let result = scan_older_coinbase_job(&test_dir, reuse_key, replacement_height, None);
		clean_output_dir(&test_dir);
		result.unwrap();
	}
}

#[test]
fn scan_replaces_stale_coinbase_at_recovered_position() {
	// Both the update path and the expired-candidate cleanup path must leave
	// the proof-recovered output intact at the colliding database position.
	for status in [OutputStatus::Unspent, OutputStatus::Reverted] {
		let test_dir = format!("test_output/coinbase_scan_stale_{:?}", status);
		setup(&test_dir);
		let result = scan_older_coinbase_job(&test_dir, true, 4, Some(status));
		clean_output_dir(&test_dir);
		result.unwrap();
	}
}
