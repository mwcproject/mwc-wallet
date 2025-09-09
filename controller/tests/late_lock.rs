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

//! Tests and experimentations with late locking
#[macro_use]
extern crate log;
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;
extern crate mwc_wallet_libwallet as libwallet;

use self::libwallet::{InitTxArgs, Slate};
use impls::test_framework::{self, LocalWalletClient};
use std::ops::DerefMut;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::consensus::calc_mwc_block_reward;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_util::Mutex;

/// self send impl
fn late_lock_test_impl(test_dir: &str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		client1,
		wallet_mining,
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
		wallet_acc1,
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
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet_mining.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		Ok(())
	})
	.unwrap();

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet_acc1.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account1")?;
		Ok(())
	})
	.unwrap();

	// Get some mining done
	{
		wallet_inst!(wallet_mining, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	{
		wallet_inst!(wallet_acc1, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	test_framework::award_blocks_to_wallet(
		&chain,
		wallet_mining.clone(),
		mask1,
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// update/test contents of both accounts
	wallet::controller::owner_single_use(Some(wallet_mining.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		// Reward from mining 11 blocks, minus the amount sent.
		// Note: We mined the block containing the tx, so fees are effectively refunded.
		let expected_amount = calc_mwc_block_reward(1) * (10 - 3);
		assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
		//reward is 2_380_952_380
		Ok(())
	})
	.unwrap();

	let mut slate = Slate::blank(2, false);
	let amount = 1_000_000_000;

	wallet::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				target_slate_version: Some(4),
				late_lock: Some(true),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, &None, &args, 1)?;
			println!("S1 SLATE: {:?}", slate_i);
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			println!("S2 SLATE: {:?}", slate);

			// Still all amount is spendable the same way
			wallet::controller::owner_single_use(
				Some(wallet_mining.clone()),
				mask1,
				None,
				|api, m| {
					let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
					assert!(wallet1_refreshed);
					// Reward from mining 11 blocks, minus the amount sent.
					// Note: We mined the block containing the tx, so fees are effectively refunded.
					let expected_amount = calc_mwc_block_reward(1) * (10 - 3);
					assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
					//reward is 2_380_952_380
					Ok(())
				},
			)
			.unwrap();

			// Note we don't call `tx_lock_outputs` on the sender side here,
			// as the outputs will only be locked during finalization

			slate = sender_api.finalize_tx(m, &None, &slate)?;
			println!("S3 SLATE: {:?}", slate);

			// Now one input should be locked
			wallet::controller::owner_single_use(
				Some(wallet_mining.clone()),
				mask1,
				None,
				|api, m| {
					let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
					assert!(wallet1_refreshed);
					// Reward from mining 11 blocks, minus the amount sent.
					// Note: We mined the block containing the tx, so fees are effectively refunded.
					let expected_amount = calc_mwc_block_reward(1) * (10 - 3 - 1);
					assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
					//reward is 2_380_952_380
					Ok(())
				},
			)
			.unwrap();

			// Now post tx to our node for inclusion in the next block.
			sender_api.post_tx(m, slate.tx_or_err().unwrap(), true)?;

			Ok(())
		},
	)
	.unwrap();

	test_framework::award_blocks_to_wallet(
		&chain,
		wallet_mining.clone(),
		mask1,
		4,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// update/test contents of both accounts
	wallet::controller::owner_single_use(Some(wallet_mining.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		// Reward from mining 11 blocks, minus the amount sent.
		// Note: We mined the block containing the tx, so fees are effectively refunded.
		let expected_amount = calc_mwc_block_reward(1) * (14 - 3) - amount; // fee should be mined back,
		assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
		// expected is 25190476180
		Ok(())
	})
	.unwrap();

	wallet::controller::owner_single_use(Some(wallet_acc1.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(amount, wallet_info.amount_currently_spendable);
		Ok(())
	})
	.unwrap();

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn late_lock() {
	let test_dir = "test_output/late_lock";
	setup(test_dir);
	if let Err(e) = late_lock_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
