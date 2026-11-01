// Copyright 2026 The Mwc Developers
// Licensed under the Apache License, Version 2.0.

//! Scan must repair fee variants and duplicate database keys in one pass.
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;

#[macro_use]
mod common;

use impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet as libwallet;
use mwc_wallet_util::{mwc_core as core, mwc_util as util};
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::thread;
use std::time::Duration;
use util::ToHex;

#[test]
fn scan_repairs_coinbase_records_in_one_pass() {
	let test_dir = "test_output/scan_coinbase_repair";
	common::setup(test_dir);
	core::global::set_local_chain_type(core::global::ChainTypes::AutomatedTesting);
	let tx_pool = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = proxy.chain.clone();
	let stopper = proxy.running.clone();
	create_wallet_and_add!(client, wallet1, mask_i, test_dir, "wallet1", None, &mut proxy, false);
	let mask = mask_i.as_ref();
	let proxy_thread = thread::spawn(move || {
		core::global::set_local_chain_type(core::global::ChainTypes::AutomatedTesting);
		proxy.run().unwrap();
	});
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask,
		20,
		false,
		&mut tx_pool.lock().unwrap(),
	)
	.unwrap();
	let originals =
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask, None, |api, m| {
			Ok(api
				.retrieve_outputs(m, false, true, None)?
				.1
				.into_iter()
				.map(|out| out.output)
				.collect::<Vec<_>>())
		})
		.unwrap();
	assert_eq!(originals.len(), 20);
	let mut originals = originals;
	originals.sort_by_key(|out| out.height);

	let mut stale = Vec::new();
	let pending;
	{
		wallet_inst_test!(wallet1, w);
		// A live indexed coinbase and a null-index copy must collapse to one record.
		let mut duplicate = originals[0].clone();
		duplicate.mmr_index = None;
		duplicate.status = libwallet::OutputStatus::Locked;
		let mut records = vec![duplicate];
		// An obsolete indexed copy belongs in the archive, outside wallet balances.
		let mut history = originals[8].clone();
		history.mmr_index = Some(10_000);
		records.push(history);
		// A confirmed output with only a null-index record must acquire its index.
		let mut missing_index = originals[1].clone();
		missing_index.mmr_index = None;
		records.push(missing_index);
		// Mined job A was overwritten locally by job B with a different fee.
		// Exercise each status users can have before scanning, including Locked.
		for (index, status) in [
			(2, libwallet::OutputStatus::Unconfirmed),
			(3, libwallet::OutputStatus::Unspent),
			(4, libwallet::OutputStatus::Locked),
			(5, libwallet::OutputStatus::Unspent),
			(6, libwallet::OutputStatus::Reverted),
			(19, libwallet::OutputStatus::Unconfirmed),
		] {
			let mut variant = originals[index].clone();
			variant.value += 1_000_000;
			variant.commit = Some(
				w.calc_commit(mask, variant.value, &variant.key_id)
					.unwrap()
					.to_hex(),
			);
			variant.tx_log_entry = None;
			variant.status = status;
			// Keep indexed collisions in two cases to cover the earlier recovery fix.
			if index == 5 || index == 6 {
				records.push(variant.clone());
			}
			variant.mmr_index = None;
			stale.push(variant.clone());
			records.push(variant);
		}
		// A candidate for the next height is still legitimate, even when the same
		// key already has a mined output at another position.
		let mut next = originals[7].clone();
		next.mmr_index = None;
		next.height = 21;
		next.value += 2_000_000;
		next.commit = Some(
			w.calc_commit(mask, next.value, &next.key_id)
				.unwrap()
				.to_hex(),
		);
		next.status = libwallet::OutputStatus::Unconfirmed;
		next.tx_log_entry = None;
		pending = next.clone();
		records.push(next);

		let mut batch = w.batch(mask).unwrap();
		// Preserve the active spending transaction when removing its null-index
		// duplicate. The surviving indexed output must remain Locked.
		let root = &originals[0].root_key_id;
		let id = batch.next_tx_log_id(root).unwrap();
		let mut spending =
			libwallet::TxLogEntry::new(root.clone(), libwallet::TxLogEntryType::TxSent, id);
		spending.input_commits = vec![util::secp::pedersen::Commitment::from_vec(
			util::from_hex(originals[0].commit.as_ref().unwrap()).unwrap(),
		)];
		spending.num_inputs = 1;
		spending.amount_debited = originals[0].value;
		batch.save_tx_log_entry(spending, root).unwrap();
		for index in [1, 2, 3, 4, 5, 6, 19] {
			batch
				.delete(&originals[index].key_id, &originals[index].mmr_index)
				.unwrap();
		}
		for record in records {
			batch.save(record).unwrap();
		}
		batch.commit().unwrap();
		drop(batch);
	}

	// Inspect the DB immediately: a subsequent refresh must not hide incomplete
	// cleanup. A second scan must produce exactly the same records.
	let mut previous = None;
	for _ in 0..2 {
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask, None, |api, m| {
			api.scan(m, None, false)?;
			Ok(())
		})
		.unwrap();
		wallet_inst_test!(wallet1, w);
		for original in &originals {
			let restored = w.get(&original.key_id, &original.mmr_index).unwrap();
			assert_eq!(restored.commit, original.commit);
			assert_eq!(restored.value, original.value);
			assert_eq!(
				restored.status,
				if original.key_id == originals[0].key_id {
					libwallet::OutputStatus::Locked
				} else {
					libwallet::OutputStatus::Unspent
				}
			);
		}
		for variant in &stale {
			assert!(w.get(&variant.key_id, &None).is_err());
		}
		assert!(w.get(&originals[0].key_id, &None).is_err());
		assert!(w.get(&originals[1].key_id, &None).is_err());
		assert_eq!(
			w.get(&pending.key_id, &None).unwrap().status,
			libwallet::OutputStatus::Unconfirmed
		);
		let records = w.iter().unwrap().collect::<Vec<_>>();
		assert_eq!(records.len(), originals.len() + 1);
		assert!(w.get(&originals[8].key_id, &Some(10_000)).is_err());
		assert!(records
			.iter()
			.all(|out| out.status != libwallet::OutputStatus::Reverted));
		let archived = w.archive_iter().unwrap().collect::<Vec<_>>();
		assert_eq!(archived.len(), 1);
		assert_eq!(archived[0].key_id, originals[8].key_id);
		assert_eq!(archived[0].commit, originals[8].commit);
		assert_eq!(archived[0].value, originals[8].value);
		assert_eq!(archived[0].mmr_index, Some(10_000));
		assert_eq!(archived[0].status, libwallet::OutputStatus::Reverted);
		let snapshot = serde_json::to_string(&(&records, &archived)).unwrap();
		if let Some(previous) = previous {
			assert_eq!(snapshot, previous);
		}
		previous = Some(snapshot);
	}

	// An output below the requested scan range is repaired by commitment lookup.
	// Its old (key, None) key must disappear when the lookup supplies an index.
	{
		wallet_inst_test!(wallet1, w);
		let mut record = originals[1].clone();
		record.mmr_index = None;
		let mut batch = w.batch(mask).unwrap();
		batch
			.delete(&originals[1].key_id, &originals[1].mmr_index)
			.unwrap();
		batch.save(record).unwrap();
		batch.commit().unwrap();
		drop(batch);
		libwallet::internal::scan::scan(&mut **w, mask, false, 15, 20, &None, false, true).unwrap();
		assert_eq!(
			w.get(&originals[1].key_id, &originals[1].mmr_index)
				.unwrap()
				.status,
			libwallet::OutputStatus::Unspent
		);
		assert!(w.get(&originals[1].key_id, &None).is_err());
	}

	// Cancelling a pending input must not invent a confirmation. Test both
	// ordinary zero-confirmation inputs and coinbase records corrupted by old code.
	for coinbase in [false, true] {
		wallet_inst_test!(wallet1, w);
		let mut input = pending.clone();
		input.is_coinbase = coinbase;
		input.status = libwallet::OutputStatus::Locked;
		let mut tx = w.tx_log_iter().unwrap().next().unwrap();
		tx.tx_type = libwallet::TxLogEntryType::TxSent;
		tx.confirmed = false;
		tx.tx_slate_id = None;
		let mut batch = w.batch(mask).unwrap();
		batch.save(input.clone()).unwrap();
		batch.commit().unwrap();
		drop(batch);
		libwallet::internal::updater::cancel_tx_and_outputs(
			&mut **w,
			mask,
			tx,
			vec![input],
			&pending.root_key_id,
		)
		.unwrap();
		assert_eq!(
			w.get(&pending.key_id, &None).unwrap().status,
			libwallet::OutputStatus::Unconfirmed
		);
	}

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	proxy_thread.join().unwrap();
	common::clean_output_dir(test_dir);
}
