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

//! tests differing accounts in the same wallet
#[macro_use]
extern crate log;
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;
extern crate mwc_wallet_util;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, Slate};
use mwc_wallet_libwallet as libwallet;
use std::ops::DerefMut;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_util::Mutex;

/// Various tests on accounts within the same wallet
fn payment_proofs_test_impl(test_dir: &str) -> Result<(), wallet::Error> {
	// Create a new proxy to simulate server and wallet responses
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

	// Do some mining
	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	let mut address = None;
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		address = Some(api.get_mqs_address(m)?);
		Ok(())
	})?;

	let address = ProvableAddress::from_pub_key(&address.unwrap());
	println!("Public address is: {:?}", address);
	let amount = 2_000_000_000; // mwc value: 60_000_000_000
	let mut slate = Slate::blank(1, false);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			payment_proof_recipient_address: Some(address.clone()),
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, &args, 1)?;

		assert_eq!(
			slate_i
				.payment_proof
				.as_ref()
				.unwrap()
				.receiver_address
				.public_key,
			address.public_key,
		);
		println!(
			"Sender addr: {:?}",
			slate_i.payment_proof.as_ref().unwrap().sender_address
		);

		// Check we are creating a tx with kernel features 0
		// We will check this produces a Plain kernel later.
		assert_eq!(0, slate.get_kernel_features());

		// Check we are creating a tx with the expected lock_height of 0.
		// We will check this produces a Plain kernel later.
		assert_eq!(0, slate_i.get_lock_height());

		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate, None, 0)?;

		// Ensure what's stored in TX log for payment proof is correct
		let (_, txs) = sender_api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
		assert!(txs[0].payment_proof.is_some());
		let pp = txs[0].clone().payment_proof.unwrap();
		assert_eq!(
			pp.receiver_address.public_key,
			slate
				.payment_proof
				.as_ref()
				.unwrap()
				.receiver_address
				.public_key
		);
		assert!(pp.receiver_signature.is_some());
		assert_eq!(pp.sender_address_path, 0);
		assert_eq!(pp.sender_signature, None);

		// check we should get an error at this point since proof is not complete
		let pp = sender_api.retrieve_payment_proof(m, true, None, Some(slate.id));
		assert!(pp.is_err());

		slate = sender_api.finalize_tx(m, &slate)?;
		sender_api.post_tx(m, slate.tx_or_err()?, true)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		2,
		false,
		tx_pool.lock().deref_mut(),
	);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// Check payment proof here
		let mut pp = sender_api.retrieve_payment_proof(m, true, None, Some(slate.id))?;

		println!("{:?}", pp);

		// verify, should be good
		let res = sender_api.verify_payment_proof(m, &pp)?;
		assert_eq!(res, (true, false));

		// Modify values, should not be good
		pp.amount = 20;
		let res = sender_api.verify_payment_proof(m, &pp);
		assert!(res.is_err());
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn payment_proofs() {
	let test_dir = "test_output/payment_proofs";
	setup(test_dir);
	if let Err(e) = payment_proofs_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
