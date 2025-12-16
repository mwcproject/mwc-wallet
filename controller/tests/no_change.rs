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

//! Test sender transaction with no change output
#[macro_use]
extern crate log;
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;

use mwc_wallet_util::mwc_core as core;
use mwc_wallet_util::mwc_core::global;
use std::ops::DerefMut;
use std::sync::Arc;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate};
use mwc_wallet_libwallet as libwallet;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::core::Transaction;
use std::sync::Mutex;

fn no_change_test_impl(test_dir: &str, inputs_num: usize) -> Result<(), wallet::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

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
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::reward(0, 0, 1);

	// Mine into wallet 1
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		4,
		false,
		tx_pool.lock().expect("Mutex failure").deref_mut(),
	);
	let fee = core::libtx::tx_fee(0, inputs_num, 1, 1);

	// send a single block's worth of transactions with minimal strategy
	let mut slate = Slate::blank(2, false);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = InitTxArgs {
			src_acct_name: None,
			amount: reward * inputs_num as u64 - fee,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		slate = api.init_send_tx(m, &None, &args, 1)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate)?;
		api.tx_lock_outputs(m, &None, &slate, None, 0)?;
		slate = api.finalize_tx(m, &None, &slate, true)?;
		assert!(slate.tx.clone().unwrap().body.inputs.len() == inputs_num);
		assert!(slate.tx.clone().unwrap().body.outputs.len() == 1); // only destination output is expected, no change outputs
		api.post_tx(m, slate.tx_or_err()?, false)?;
		Ok(())
	})?;

	// apply posted tx
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		1,
		false,
		tx_pool.lock().expect("Mutex failure").deref_mut(),
	);

	// Refresh and check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
		assert!(refreshed);
		assert!(txs.len() == 1);
		let tx = txs[0].clone();
		assert!(tx.num_inputs == inputs_num);
		assert!(tx.num_outputs == 0);
		println!("{:?}", tx);
		assert!(tx.confirmed);
		Ok(())
	})?;

	// ensure invoice TX works as well with no change
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Wallet 2 inititates an invoice transaction, requesting payment
		let args = IssueInvoiceTxArgs {
			amount: reward * inputs_num as u64 - fee,
			..Default::default()
		};
		slate = api.issue_invoice_tx(m, &None, &args)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Wallet 1 receives the invoice transaction
		let args = InitTxArgs {
			src_acct_name: None,
			amount: slate.amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		slate = api.process_invoice_tx(m, &None, &slate, &args)?;
		api.tx_lock_outputs(m, &None, &slate, None, 1)?;
		assert!(slate.tx.clone().unwrap().body.inputs.len() == inputs_num);
		assert!(slate.tx.clone().unwrap().body.outputs.len() == 1); // only destination output is expected, no change outputs
		Ok(())
	})?;

	// wallet 2 finalizes and posts
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		// Wallet 2 receives the invoice transaction
		slate = api.finalize_invoice_tx(&None, &slate)?;
		Ok(())
	})?;
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask1, None, |api, m| {
		api.post_tx(m, slate.tx_or_err()?, false)?;
		Ok(())
	})?;

	// apply posted tx
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		1,
		false,
		tx_pool.lock().expect("Mutex failure").deref_mut(),
	);

	// Refresh and check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
		assert!(refreshed);
		assert!(txs.len() == 1);
		let tx = txs[0].clone();
		assert!(tx.num_inputs == inputs_num);
		assert!(tx.num_outputs == 0);
		println!("{:?}", tx);
		assert!(tx.confirmed);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn no_change() {
	for inputs_num in 1..=3 {
		let test_dir = format!("test_output/no_change{}", inputs_num);
		setup(&test_dir);
		if let Err(e) = no_change_test_impl(&test_dir, 1) {
			panic!("Libwallet Error: {}", e);
		}
		clean_output_dir(&test_dir);
	}
}
