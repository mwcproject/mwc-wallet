// Copyright 2026 The Mwc Developers
// Licensed under the Apache License, Version 2.0.

//! Reconcile a wallet history large enough to exhaust one LMDB transaction.
#![cfg(feature = "test-support")]

#[macro_use]
mod common;

use mwc_wallet_controller as wallet;
use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::{Error, TxLogEntry, TxLogEntryType};
use mwc_wallet_util::mwc_core as core;
use mwc_wallet_util::mwc_crates::{chrono, secp};
use mwc_wallet_util::{mwc_util as util, Mutex};
use std::sync::Arc;

#[test]
fn scan_archives_large_history_without_exhausting_lmdb() {
	let test_dir = "test_output/scan_large_history";
	common::setup(test_dir);
	core::global::set_local_chain_type(core::global::ChainTypes::AutomatedTesting);
	let tx_pool = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = proxy.chain.clone();
	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
	create_wallet_and_add!(
		client,
		wallet1,
		mask_i,
		test_dir,
		"wallet1",
		None::<util::ZeroingString>,
		&mut proxy,
		false
	);
	let mask = mask_i.as_ref();
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask,
		3,
		false,
		&mut tx_pool.lock(),
	)
	.unwrap();

	let history_count = 128;
	let address_len = 80_000;
	{
		wallet_inst_test!(wallet1, w);
		let parent = w.parent_key_id();
		for _ in 0..history_count {
			let mut batch = w.batch(&secp, mask).unwrap();
			let id = batch.next_tx_log_id(&parent).unwrap();
			let mut entry =
				TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceivedCancelled, id);
			entry.creation_ts = chrono::Utc::now() - chrono::Duration::days(10);
			entry.address = Some("x".repeat(address_len));
			batch.save_tx_log_entry(entry, &parent).unwrap();
			batch.commit().unwrap();
		}
		let entries: Vec<_> = w
			.tx_log_iter()
			.unwrap()
			.filter(|entry| entry.address.is_some())
			.collect();
		assert_eq!(entries.len(), history_count);
		// Reproduce the previous unbounded archive transaction, then ensure
		// its failure rolls back every move before the real scan retries.
		let result = (|| -> Result<(), Error> {
			let mut batch = w.batch(&secp, mask)?;
			for entry in &entries {
				batch.archive_transaction(entry)?;
			}
			batch.commit()
		})();
		assert!(matches!(result, Err(Error::DatabaseMapFull)), "{result:?}");
		assert_eq!(
			w.tx_log_iter()
				.unwrap()
				.filter(|entry| entry.address.is_some())
				.count(),
			history_count
		);
		assert_eq!(
			w.tx_log_archive_iter()
				.unwrap()
				.filter(|entry| entry.address.is_some())
				.count(),
			0
		);
	}

	for _ in 0..2 {
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask, None, |api, m| {
			api.scan(m, Some(1), None, false)?;
			Ok(())
		})
		.unwrap();
		wallet_inst_test!(wallet1, w);
		assert_eq!(
			w.tx_log_iter()
				.unwrap()
				.filter(|entry| entry.address.is_some())
				.count(),
			0
		);
		let archived: Vec<_> = w
			.tx_log_archive_iter()
			.unwrap()
			.filter(|entry| entry.address.is_some())
			.collect();
		assert_eq!(archived.len(), history_count);
		assert!(archived
			.iter()
			.all(|entry| entry.address.as_ref().unwrap().len() == address_len));
		assert_eq!(w.last_confirmed_height().unwrap(), 3);
	}
	drop(wallet1);
	proxy_handle.stop().unwrap();
	common::clean_output_dir(test_dir);
}
