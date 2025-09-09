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
use mwc_wallet_util::mwc_util::Mutex;

fn broken_change_test_impl(
	test_dir: &str,
	put_into_change: u64,
	expected_outputs: usize,
	test_send: bool,
) -> Result<(), wallet::Error> {
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
	let reward = core::consensus::reward(0, 1);

	let inputs_num = 4;
	let output_num = 5;

	// Mine into wallet 1
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		4 + 3,
		false,
		tx_pool.lock().deref_mut(),
	);
	let fee = core::libtx::tx_fee(inputs_num, output_num + 1, 1);

	// send a single block's worth of transactions with minimal strategy
	let mut slate = Slate::blank(2, false);
	if test_send {
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: reward * inputs_num as u64 - fee - put_into_change,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: output_num as u32,
				selection_strategy_is_use_all: false,
				..Default::default()
			};
			slate = api.init_send_tx(m, &None, &args, 1)?;
			slate = client1.send_tx_slate_direct("wallet2", &slate)?;
			api.tx_lock_outputs(m, &None, &slate, None, 0)?;
			slate = api.finalize_tx(m, &None, &slate)?;
			assert!(slate.tx.clone().unwrap().body.inputs.len() == inputs_num);
			assert!(slate.tx.clone().unwrap().body.outputs.len() == expected_outputs);
			api.post_tx(m, slate.tx_or_err()?, false)?;
			Ok(())
		})?;
	} else {
		// testing invoice
		wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
			// Wallet 2 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * inputs_num as u64 - fee - put_into_change,
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
				num_change_outputs: output_num as u32,
				selection_strategy_is_use_all: false,
				..Default::default()
			};
			slate = api.process_invoice_tx(m, &None, &slate, &args)?;
			api.tx_lock_outputs(m, &None, &slate, None, 1)?;
			assert!(slate.tx.clone().unwrap().body.inputs.len() == inputs_num);
			assert!(slate.tx.clone().unwrap().body.outputs.len() == expected_outputs);
			Ok(())
		})?;
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

fn run_broken_change_test(
	test_dir: &str,
	put_into_change: u64,
	expected_outputs: usize,
	test_send: bool,
) {
	setup(test_dir);
	if let Err(e) = broken_change_test_impl(&test_dir, put_into_change, expected_outputs, test_send)
	{
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn broken_change() {
	run_broken_change_test("test_output/broken_change1", 0, 1, true);
	run_broken_change_test("test_output/broken_change2", 0, 1, false);
	run_broken_change_test("test_output/broken_change3", 7, 2, true);
	run_broken_change_test("test_output/broken_change4", 100, 2, false);
	run_broken_change_test("test_output/broken_change5", 500_000_000, 6, true); // 0.5 MWC for 1 outputs is good
	run_broken_change_test("test_output/broken_change6", 499_999_999, 5, false); // 0.4999999 MWC for 5 outputs is below the threshold, expected to use 4 output instead of 5.
}
