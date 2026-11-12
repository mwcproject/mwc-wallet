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

//! An invoice carrying a non-Plain kernel policy (HeightLocked or NRD) must be
//! rejected before any signing. The payer's Context is built with a Plain
//! policy (selection::build_send_tx), and the signed slate would otherwise be
//! sent to the issuer before tx_lock_outputs flags the mismatch, leaving the
//! payer with an error and no transaction record while the issuer can finalize
//! and broadcast.

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
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::Transaction;

/// Non-Plain kernel policies in process_invoice_tx
fn invoice_kernel_policy_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
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

	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	// wallet 2 issues an invoice that wallet 1 will be asked to pay
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

	// A HeightLocked invoice must be rejected before any signing or staging
	let mut locked_slate = invoice_slate.clone();
	locked_slate.set_lock_height_no_check(1000);
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs_before) = api.retrieve_txs(m, true, None, None, None, None)?;
			let args = InitTxArgs {
				amount: locked_slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let mut session = TxSession::new();
			assert!(matches!(
				api.process_invoice_tx(m, Some(&mut session), &locked_slate, &args),
				Err(mwc_wallet_libwallet::Error::InvalidKernelFeatures(_))
			));
			// The rejection happens before key allocation and signing, so the
			// session must hold no staged context, log entry, or transaction.
			assert!(session.is_empty());
			let (_, _, txs_after) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert_eq!(txs_before.len(), txs_after.len());
			Ok(())
		},
	)?;

	// Positive control: the original Plain invoice still processes normally
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				amount: invoice_slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let mut session = TxSession::new();
			let result = api.process_invoice_tx(m, Some(&mut session), &invoice_slate, &args)?;
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
fn invoice_kernel_policy() {
	let test_dir = "test_output/invoice_kernel_policy";
	setup(test_dir);
	if let Err(e) = invoice_kernel_policy_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
