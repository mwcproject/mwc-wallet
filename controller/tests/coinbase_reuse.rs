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
