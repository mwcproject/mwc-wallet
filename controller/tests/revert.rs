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

#![cfg(feature = "test-support")]

#[macro_use]
mod common;

use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_controller::Error;
use mwc_wallet_impls::test_framework::*;
use mwc_wallet_impls::{DefaultLCProvider, PathToSlatePutter, SlatePutter};
use mwc_wallet_libwallet::WalletInst;
use mwc_wallet_libwallet::api_impl::types::InitTxArgs;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_chain;
use mwc_wallet_util::mwc_core;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::pow;
use mwc_wallet_util::mwc_crates::chrono::{self, Timelike, Utc};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_keychain::ExtKeychain;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

type Wallet = Arc<
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
>;

fn revert(
	test_dir: &str,
	future_confirmation: bool,
) -> Result<
	(
		Arc<mwc_chain::Chain>,
		WalletProxyHandle,
		u64,
		u64,
		Transaction,
		Wallet,
		Option<SecretKey>,
		Wallet,
		Option<SecretKey>,
	),
	Error,
> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let test_dir2 = format!("{}/chain2", test_dir);
	let wallet_proxy2 = create_wallet_proxy(test_dir2, tx_pool.clone());
	let chain2 = wallet_proxy2.chain.clone();
	let secp = Secp256k1::new().unwrap();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false
	);
	let mask1 = mask1_i.as_ref();

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
	let mask2 = mask2_i.as_ref();

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "a")?;
			api.set_active_account(m, "a")?;
			Ok(())
		},
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.create_account_path(m, "b")?;
			api.set_active_account(m, "b")?;
			Ok(())
		},
	)?;

	let reward = mwc_core::consensus::reward(0, 0, 1).map_err(|e| {
		mwc_wallet_controller::Error::GenericError(format!("reward calculation failed: {}", e))
	})?;
	let cm = global::coinbase_maturity(0) as u64;
	let sent = reward * 2;

	// Mine some blocks
	let bh = 10u64;
	award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// Sanity check contents
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, bh * reward);
			assert_eq!(info.amount_currently_spendable, (bh - cm) * reward);
			assert_eq!(info.amount_reverted, 0);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let (c, _) = mwc_wallet_libwallet::TxLogEntry::sum_confirmed(&txs)?;
			assert_eq!(info.total, c);
			assert_eq!(txs.len(), bh as usize);
			Ok(())
		},
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, 0);
			assert_eq!(info.amount_currently_spendable, 0);
			assert_eq!(info.amount_reverted, 0);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 0);
			Ok(())
		},
	)?;

	// Send some funds
	let mut tx = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			// send to send
			let args = InitTxArgs {
				src_acct_name: None,
				amount: sent,
				minimum_confirmations: cm,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				..Default::default()
			};
			let slate = api.init_send_tx(m, None, &args, 1)?;
			// output tx file
			let send_file = format!("{}/part_tx_1.tx", test_dir);
			PathToSlatePutter::build_plain(0, Some(PathBuf::from(send_file)))
				.put_tx(
					&slate,
					None,
					#[cfg(feature = "test-support")]
					false,
					&secp,
				)?;
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			let slate = client1.send_tx_slate_direct("wallet2", &slate)?;
			let slate = api.finalize_tx(m, None, &slate, true)?;
			tx = slate.tx;

			Ok(())
		},
	)?;
	let tx = tx.expect("tx from slate");

	// Check funds have been received
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, 0);
			assert_eq!(info.amount_currently_spendable, 0);
			assert_eq!(info.amount_reverted, 0);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];
			assert_eq!(tx.tx_type, mwc_wallet_libwallet::TxLogEntryType::TxReceived);
			assert!(!tx.confirmed);
			Ok(())
		},
	)?;

	// Update parallel chain
	assert_eq!(chain2.head_header().unwrap().height, 0);
	for i in 0..bh {
		let header = chain.get_header_by_height(i + 1).unwrap();
		let block = chain.get_block_for_header(&header).unwrap();
		process_block(&chain2, block).map_err(|e| {
			mwc_wallet_controller::Error::GenericError(format!("process block failed: {}", e))
		})?;
	}
	assert_eq!(chain2.head_header().unwrap().height, bh);

	// Build 2 blocks at same height: 1 with the tx, 1 without
	let head = chain.head_header().unwrap();
	let mut block_with =
		create_block_for_wallet(&chain, head.clone(), &[tx.clone()], wallet1.clone(), mask1)?;
	if future_confirmation {
		// Valid block timestamps may be ahead of the wallet's clock. Re-mine
		// this block so the future confirmation comes from the actual chain.
		block_with.header.timestamp = (Utc::now() + chrono::Duration::minutes(10))
			.with_nanosecond(0)
			.unwrap();
		let difficulty = (block_with.header.total_difficulty() - head.total_difficulty())
			.expect("test block should increase total difficulty");
		pow::pow_size(
			0,
			&mut block_with.header,
			difficulty,
			global::proofsize(0),
			global::min_edge_bits(0),
		)
		.map_err(|e| Error::GenericError(format!("mining future-dated block failed: {}", e)))?;
	}
	let block_without = create_block_for_wallet(&chain, head, &[], wallet1.clone(), mask1)?;

	// Add block with tx to the chain
	process_block(&chain, block_with.clone()).map_err(|e| {
		mwc_wallet_controller::Error::GenericError(format!("process block failed: {}", e))
	})?;
	assert_eq!(chain.head_header().unwrap(), block_with.header);

	// Add block without tx to the parallel chain
	process_block(&chain2, block_without.clone()).map_err(|e| {
		mwc_wallet_controller::Error::GenericError(format!("process block failed: {}", e))
	})?;
	assert_eq!(chain2.head_header().unwrap(), block_without.header);

	let bh = bh + 1;

	// Check funds have been confirmed
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, sent);
			assert_eq!(info.amount_currently_spendable, sent);
			assert_eq!(info.amount_reverted, 0);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];
			assert_eq!(tx.tx_type, mwc_wallet_libwallet::TxLogEntryType::TxReceived);
			assert!(tx.confirmed);
			assert!(tx.kernel_excess.is_some());
			assert!(tx.reverted_after.is_none());
			if future_confirmation {
				assert_eq!(tx.confirmation_ts, Some(block_with.header.timestamp));
				assert!(tx.confirmation_ts.unwrap() > Utc::now());
			}
			Ok(())
		},
	)?;

	// Attach more blocks to the parallel chain, making it the longest one
	award_block_to_wallet(&chain2, &[], wallet1.clone(), mask1)?;
	assert_eq!(chain2.head_header().unwrap().height, bh + 1);
	let new_head = chain2
		.get_block_for_header(&chain2.head_header().unwrap())
		.unwrap();

	// Input blocks from parallel chain to original chain, updating it as well
	// and effectively reverting the transaction
	process_block(&chain, block_without.clone()).map_err(|e| {
		mwc_wallet_controller::Error::GenericError(format!("process block failed: {}", e))
	})?; // This shouldn't update the head
	assert_eq!(chain.head_header().unwrap(), block_with.header);
	process_block(&chain, new_head.clone()).map_err(|e| {
		mwc_wallet_controller::Error::GenericError(format!("process block failed: {}", e))
	})?; // But this should!
	assert_eq!(chain.head_header().unwrap(), new_head.header);

	let bh = bh + 1;

	// Check funds have been reverted
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.scan(m, None, None, false)?;
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, 0);
			assert_eq!(info.amount_currently_spendable, 0);
			assert_eq!(info.amount_reverted, sent);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];
			assert_eq!(tx.tx_type, mwc_wallet_libwallet::TxLogEntryType::TxReverted);
			assert!(!tx.confirmed);
			assert!(tx.reverted_after.is_some());
			if future_confirmation {
				assert!(tx.confirmation_ts.unwrap() > Utc::now());
				assert_eq!(tx.reverted_after, Some(Duration::ZERO));
			} else {
				assert!(tx.reverted_after.unwrap() > Duration::ZERO);
			}
			Ok(())
		},
	)?;

	Ok((
		chain, proxy_handle, sent, bh, tx, wallet1, mask1_i, wallet2, mask2_i,
	))
}

fn revert_reconfirm_impl(test_dir: &'static str) -> Result<(), Error> {
	let (chain, proxy_handle, sent, bh, tx, wallet1, mask1_i, wallet2, mask2_i) =
		revert(test_dir, false)?;
	let mask1 = mask1_i.as_ref();
	let mask2 = mask2_i.as_ref();

	// Include the tx into the chain again, the tx should no longer be reverted
	award_block_to_wallet(&chain, &[tx], wallet1.clone(), mask1)?;

	let bh = bh + 1;

	// Check funds have been confirmed again
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, sent);
			assert_eq!(info.amount_currently_spendable, sent);
			assert_eq!(info.amount_reverted, 0);
			// check tx log as well
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];
			assert_eq!(tx.tx_type, mwc_wallet_libwallet::TxLogEntryType::TxReceived);
			assert!(tx.confirmed);
			assert!(tx.reverted_after.is_none());
			Ok(())
		},
	)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

fn revert_cancel_impl(test_dir: &'static str) -> Result<(), Error> {
	let (chain, proxy_handle, sent, bh, _, _, _, wallet2, mask2_i) = revert(test_dir, false)?;
	let mask2 = mask2_i.as_ref();

	// Cancelling tx
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			// Sanity check
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, 0);
			assert_eq!(info.amount_currently_spendable, 0);
			assert_eq!(info.amount_reverted, sent);

			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];

			// Cancel
			api.cancel_tx(m, Some(tx.id), None)?;

			// Check updated summary info
			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, bh);
			assert_eq!(info.total, 0);
			assert_eq!(info.amount_currently_spendable, 0);
			assert_eq!(info.amount_reverted, 0);

			// Check updated tx log
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs.len(), 1);
			let tx = &txs[0];
			assert_eq!(
				tx.tx_type,
				mwc_wallet_libwallet::TxLogEntryType::TxReceivedCancelled
			);
			Ok(())
		},
	)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn tx_revert_reconfirm() {
	let test_dir = "test_output/revert_tx";
	setup(test_dir);
	if let Err(e) = revert_reconfirm_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn tx_revert_future_confirmation_clamps_duration_to_zero() {
	let test_dir = "test_output/revert_tx_future_confirmation";
	setup(test_dir);
	let (chain, proxy_handle, ..) =
		revert(test_dir, true).expect("future confirmation should revert");
	proxy_handle.stop().unwrap();
	drop(chain);
	clean_output_dir(test_dir);
}

#[test]
fn tx_revert_cancel() {
	let test_dir = "test_output/revert_tx_cancel";
	setup(test_dir);
	if let Err(e) = revert_cancel_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
