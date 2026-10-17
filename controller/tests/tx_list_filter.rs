// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

//! tests of advanced TX filtering

#![cfg(feature = "test-support")]

use mwc_wallet_util::mwc_crates::log::debug;

use std::ops::DerefMut;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::{InitTxArgs, Slate};
use mwc_wallet_libwallet::{RetrieveTxQueryArgs, RetrieveTxQuerySortField};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mwc_wallet_impls::DefaultLCProvider;
use mwc_wallet_libwallet::WalletInst;
use mwc_wallet_util::mwc_core;
use mwc_wallet_util::mwc_keychain::ExtKeychain;

mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::core::Transaction;

fn test_wallet_tx_filtering(
	wallet: Arc<
		Mutex<
			Box<
				dyn WalletInst<
						'static,
						DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
						LocalWalletClient,
						ExtKeychain,
					>,
			>,
		>,
	>,
	mask: Option<&SecretKey>,
) -> Result<(), mwc_wallet_libwallet::Error> {
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, _m| {
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.min_id = Some(5);

			// Min ID
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results[0].id, 5);
			assert_eq!(tx_results[tx_results.len() - 1].id, 33);

			// Max ID
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.min_id = Some(5);
			tx_query_args.max_id = Some(20);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results[0].id, 5);
			assert_eq!(tx_results[tx_results.len() - 1].id, 20);

			// Exclude 1 cancelled
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.exclude_cancelled = Some(true);
			tx_query_args.min_id = Some(5);
			tx_query_args.max_id = Some(50);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 28);

			// Exclude 1 cancelled, show confirmed only
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.exclude_cancelled = Some(true);
			tx_query_args.include_confirmed_only = Some(true);
			tx_query_args.min_id = Some(5);
			tx_query_args.max_id = Some(50);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 14);

			// show outstanding only (including cancelled)
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.exclude_cancelled = Some(false);
			tx_query_args.include_outstanding_only = Some(true);
			tx_query_args.min_id = Some(5);
			tx_query_args.max_id = Some(50);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 15);

			// outstanding only and confirmed only should give empty set
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.exclude_cancelled = Some(false);
			tx_query_args.include_outstanding_only = Some(true);
			tx_query_args.include_confirmed_only = Some(true);
			tx_query_args.min_id = Some(5);
			tx_query_args.max_id = Some(50);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 0);

			// include sent only
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.include_sent_only = Some(true);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 15);

			// include received only (none in this set)
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.include_received_only = Some(true);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 0);

			// include reverted only (none in this set)
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.include_reverted_only = Some(true);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 0);

			// include coinbase only
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.include_coinbase_only = Some(true);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 19);

			// Amounts
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.min_amount = Some(14_000_000 + 8_000_000 / 100); // 8m are fees
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 19 + 8);

			// amount, should see as above with coinbases excluded
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.min_amount = Some(14_000_000 + 8_000_000 / 100);
			tx_query_args.max_amount = Some(2_380_952_380 - 1);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 8);

			// Amount - should only see coinbase (incoming)
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.min_amount = Some(2_380_952_380);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results.len(), 19);

			// sort order
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.sort_order = Some(mwc_wallet_libwallet::RetrieveTxQuerySortOrder::Desc);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;

			assert_eq!(tx_results[0].id, 33);
			assert_eq!(tx_results[tx_results.len() - 1].id, 0);

			// change sort field to amount desc, should have coinbases first
			let mut tx_query_args = RetrieveTxQueryArgs::default();
			tx_query_args.sort_order = Some(mwc_wallet_libwallet::RetrieveTxQuerySortOrder::Desc);
			tx_query_args.sort_field = Some(RetrieveTxQuerySortField::TotalAmount);
			let tx_results = api
				.retrieve_txs(mask, true, None, None, Some(tx_query_args), None)?
				.2;
			assert_eq!(tx_results[0].amount_credited, 2_380_952_380);

			/*for entry in tx_results.iter() {
				println!("{:?}", entry);
			}*/

			Ok(())
		},
	)
	.unwrap();
	Ok(())
}

/// Builds a wallet + chain with a few transactions, and return wallet for further testing
fn build_chain_for_tx_filtering(
	test_dir: &str,
	block_height: usize,
) -> Result<(), mwc_wallet_libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();
	debug!("Mask1: {:?}", mask1);
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false
	);
	let mask2 = (&mask2_i).as_ref();
	debug!("Mask2: {:?}", mask2);

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter
	let reward = mwc_core::consensus::calc_mwc_block_reward(0, 1);

	// Start off with a few blocks
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		3,
		false,
		tx_pool.lock().deref_mut(),
	);

	for i in 0..block_height {
		let mut wallet_1_has_funds = false;

		// Check wallet 1 contents
		mwc_wallet_controller::controller::owner_single_use(
			Some(wallet1.clone()),
			mask1,
			None,
			|api, m| {
				let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
				debug!(
					"Wallet 1 spendable - {}",
					wallet1_info.amount_currently_spendable
				);
				if wallet1_info.amount_currently_spendable > reward {
					wallet_1_has_funds = true;
				}
				Ok(())
			},
		)
		.unwrap();

		if !wallet_1_has_funds {
			let _ = test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				mask1,
				1,
				false,
				tx_pool.lock().deref_mut(),
			);
			continue;
		}

		// send a random tx
		let num_txs = 1;
		for _ in 0..num_txs {
			let amount: u64 = i as u64 * 1_000_000;
			let mut slate = Slate::blank(1, false)?;
			debug!("Creating TX for {}", amount);
			mwc_wallet_controller::controller::owner_single_use(
				Some(wallet1.clone()),
				mask1,
				None,
				|sender_api, m| {
					// note this will increment the block count as part of the transaction "Posting"
					let args = InitTxArgs {
						src_acct_name: None,
						amount: amount,
						minimum_confirmations: 1,
						max_outputs: 500,
						num_change_outputs: 1,
						selection_strategy_is_use_all: false,
						..Default::default()
					};
					let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
					slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
					sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;
					slate = sender_api.finalize_tx(m, None, &slate, true)?;
					Ok(())
				},
			)
			.unwrap();
		}
	}

	// Cancel a tx for filtering testing
	let amount: u64 = 1_000_000;
	let mut slate = Slate::blank(1, false)?;
	debug!("Creating TX for {}", amount);
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			// note this will increment the block count as part of the transaction "Posting"
			let args = InitTxArgs {
				src_acct_name: None,
				amount: amount,
				minimum_confirmations: 1,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;
			sender_api.cancel_tx(m, Some(33), None)?;
			Ok(())
		},
	)
	.unwrap();

	// Perform actual testing
	test_wallet_tx_filtering(wallet1, mask1)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_tx_filtering() {
	let test_dir = "test_output/advanced_tx_filtering";
	clean_output_dir(test_dir);
	setup(test_dir);
	if let Err(e) = build_chain_for_tx_filtering(test_dir, 30) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn last_four_days_includes_recent_cancelled_transactions() -> Result<(), mwc_wallet_libwallet::Error>
{
	use mwc_wallet_libwallet::internal::updater;
	use mwc_wallet_libwallet::{RetrieveTxQuerySortOrder, TxLogEntry, TxLogEntryType};
	use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
	use mwc_wallet_util::mwc_crates::chrono::{Duration as ChronoDuration, Utc};
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	use std::sync::mpsc::channel;

	const TIP_HEIGHT: u64 = 10_000;
	let height_limit = TIP_HEIGHT - 4 * DAY_HEIGHT;
	let dir = tempdir().unwrap();
	setup(dir.path().to_str().unwrap());
	let (requests, request_rx) = channel();
	let request_rx = Mutex::new(request_rx);
	let client = LocalWalletClient::new("four-day-filter", requests);
	let responses = client.get_send_instance();
	let (wallet, mask) =
		common::create_local_wallet(dir.path().to_str().unwrap(), "wallet", None, client, false);
	let owner = mwc_wallet_api::Owner::new(0, wallet.clone(), None)?;
	let other_account = owner.create_account_path(mask.as_ref(), "other")?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let now = Utc::now();
	{
		wallet_inst!(wallet, w);
		let parent = w.parent_key_id();
		let mut batch = w.batch(&secp, mask.as_ref())?;
		for (id, tx_type, age_days, output_height, confirmed) in [
			(0, TxLogEntryType::TxSentCancelled, 5, 0, false),
			(1, TxLogEntryType::TxSent, 1, 0, false),
			(2, TxLogEntryType::TxReceived, 2, 0, false),
			(3, TxLogEntryType::TxReceivedCancelled, 5, 0, false),
			(4, TxLogEntryType::TxSent, 10, 0, false),
			(5, TxLogEntryType::TxReceived, 10, height_limit, true),
			(6, TxLogEntryType::TxReceived, 0, height_limit - 1, true),
			(7, TxLogEntryType::TxReverted, 1, 0, false),
			(8, TxLogEntryType::TxReverted, 5, 0, false),
			(9, TxLogEntryType::TxReverted, 10, height_limit, false),
			(10, TxLogEntryType::TxReverted, 1, height_limit - 1, false),
			(11, TxLogEntryType::TxSentCancelled, 10, 0, false),
		] {
			let mut tx = TxLogEntry::new(parent.clone(), tx_type, id);
			tx.creation_ts = now - ChronoDuration::days(age_days);
			tx.output_height = output_height;
			tx.confirmed = confirmed;
			if id == 1 || id == 2 {
				// Exercise the real sent/received cancellation transition.
				updater::cancel_tx_and_outputs(&mut *batch, tx, vec![], &parent)?;
			} else {
				batch.save_tx_log_entry(tx.clone(), &parent)?;
				if id == 11 {
					batch.archive_transaction(&tx)?;
				}
			}
		}
		let other_tx = TxLogEntry::new(other_account.clone(), TxLogEntryType::TxSentCancelled, 99);
		batch.save_tx_log_entry(other_tx, &other_account)?;
		batch.commit()?;
	}

	// Supply only the tip needed by the display filter, without mining four days
	// of blocks or refreshing away the transaction states under test.
	let retrieve = |query, show_last_four_days: Option<bool>, tip| {
		let (_, _, txs) = thread::scope(|scope| {
			let responder = show_last_four_days.unwrap_or(false).then(|| {
				scope.spawn(|| {
					let mut request = request_rx
						.lock()
						.recv_timeout(Duration::from_secs(10))
						.unwrap();
					assert_eq!(request.method, "get_chain_tip");
					request.dest = request.sender_id;
					request.sender_id = "node".into();
					request.body = format!("{tip},{}", "00".repeat(32));
					responses.send(request).unwrap();
				})
			});
			let result =
				owner.retrieve_txs(mask.as_ref(), false, None, None, query, show_last_four_days);
			if let Some(responder) = responder {
				responder.join().unwrap();
			}
			result
		})?;
		assert!(request_rx.lock().try_recv().is_err());
		Ok::<_, mwc_wallet_libwallet::Error>(txs)
	};
	let ids = |txs: Vec<TxLogEntry>| txs.into_iter().map(|tx| tx.id).collect::<Vec<_>>();
	for query in [None, Some(RetrieveTxQueryArgs::default())] {
		let recent = retrieve(query.clone(), Some(true), TIP_HEIGHT)?;
		for id in [1, 2] {
			let cancelled = recent.iter().find(|tx| tx.id == id).unwrap();
			assert!(cancelled.is_cancelled());
			assert_eq!(cancelled.output_height, 0);
		}
		let mut recent_ids = ids(recent);
		recent_ids.sort_unstable();
		assert_eq!(recent_ids, vec![1, 2, 4, 5, 7, 9]);

		// Disabling the filter and clamping a young chain to genesis preserve the
		// existing full-history behavior, including old archived cancellations.
		for (show, tip) in [
			(None, TIP_HEIGHT),
			(Some(false), TIP_HEIGHT),
			(Some(true), DAY_HEIGHT),
		] {
			let mut all_ids = ids(retrieve(query.clone(), show, tip)?);
			all_ids.sort_unstable();
			assert_eq!(all_ids, (0..=11).collect::<Vec<_>>());
		}
	}

	let without_cancelled = RetrieveTxQueryArgs {
		exclude_cancelled: Some(true),
		..Default::default()
	};
	assert_eq!(
		ids(retrieve(Some(without_cancelled), Some(true), TIP_HEIGHT)?),
		vec![4, 5, 7, 9]
	);
	let limited = RetrieveTxQueryArgs {
		sort_order: Some(RetrieveTxQuerySortOrder::Desc),
		limit: Some(3),
		..Default::default()
	};
	assert_eq!(
		ids(retrieve(Some(limited), Some(true), TIP_HEIGHT)?),
		vec![9, 7, 5]
	);

	// Pagination applies after the ordinary path's date ordering and filtering.
	let ordered_ids = ids(retrieve(None, Some(true), TIP_HEIGHT)?);
	{
		wallet_inst!(wallet, w);
		let parent = w.parent_key_id();
		let page = updater::retrieve_txs(
			&mut **w,
			mask.as_ref(),
			None,
			None,
			None,
			Some(&parent),
			false,
			Some(2),
			Some(3),
			Some(TIP_HEIGHT),
		)?;
		assert_eq!(ids(page), ordered_ids[2..5]);
	}
	Ok(())
}
