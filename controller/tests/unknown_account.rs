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

//! An explicitly named account that does not exist must be rejected with
//! UnknownAccountLabel. Falling back to the active account would silently
//! stage outputs, locks, and transaction log entries under an account the
//! caller did not name.

#![cfg(feature = "test-support")]

use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate};
use mwc_wallet_util::mwc_core::global;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::Mutex;

/// Unknown account labels across send, invoice issue, and invoice pay flows
fn unknown_account_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
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
		false
	);
	let mask1 = (&mask1_i).as_ref();

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

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter
	let reward = mwc_wallet_util::mwc_core::consensus::MWC_FIRST_GROUP_REWARD;

	// add a named account to wallet 1 and fund it
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			Ok(())
		},
	)?;
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	// init_send_tx with an unknown source account must fail and stage nothing
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs_before) = api.retrieve_txs(m, true, None, None, None, None)?;
			let args = InitTxArgs {
				src_acct_name: Some("nonexistent".to_owned()),
				amount: reward,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			assert!(matches!(
				api.init_send_tx(m, None, &args, 1),
				Err(mwc_wallet_libwallet::Error::UnknownAccountLabel(label)) if label == "nonexistent"
			));
			let (_, _, txs_after) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs_before.len(), txs_after.len());
			Ok(())
		},
	)?;

	// issue_invoice_tx with an unknown destination account must fail and
	// stage nothing
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs_before) = api.retrieve_txs(m, true, None, None, None, None)?;
			let args = IssueInvoiceTxArgs {
				dest_acct_name: Some("nonexistent".to_owned()),
				amount: reward,
				..Default::default()
			};
			assert!(matches!(
				api.issue_invoice_tx(m, None, &args),
				Err(mwc_wallet_libwallet::Error::UnknownAccountLabel(label)) if label == "nonexistent"
			));
			let (_, _, txs_after) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs_before.len(), txs_after.len());
			Ok(())
		},
	)?;

	// wallet 2 issues an invoice that wallet 1 will pay
	let mut invoice_slate = Slate::blank(2, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let args = IssueInvoiceTxArgs {
				amount: reward,
				..Default::default()
			};
			invoice_slate = api.issue_invoice_tx(m, None, &args)?;
			Ok(())
		},
	)?;

	// process_invoice_tx with an unknown source account must fail and leave
	// the slate free for a valid retry
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs_before) = api.retrieve_txs(m, true, None, None, None, None)?;
			let args = InitTxArgs {
				src_acct_name: Some("nonexistent".to_owned()),
				amount: invoice_slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let mut session = TxSession::new();
			assert!(matches!(
				api.process_invoice_tx(m, Some(&mut session), &invoice_slate, &args),
				Err(mwc_wallet_libwallet::Error::UnknownAccountLabel(label)) if label == "nonexistent"
			));
			let (_, _, txs_after) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs_before.len(), txs_after.len());
			Ok(())
		},
	)?;

	// Positive controls: existing account names still resolve in all three
	// flows.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount: reward,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			api.init_send_tx(m, None, &args, 1)?;

			let args = IssueInvoiceTxArgs {
				dest_acct_name: Some("mining".to_owned()),
				amount: reward,
				..Default::default()
			};
			api.issue_invoice_tx(m, None, &args)?;

			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount: invoice_slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let mut session = TxSession::new();
			let result =
				api.process_invoice_tx(m, Some(&mut session), &invoice_slate, &args)?;
			drop(result.processing_guard);
			Ok(())
		},
	)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn unknown_account() {
	let test_dir = "test_output/unknown_account";
	setup(test_dir);
	if let Err(e) = unknown_account_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
