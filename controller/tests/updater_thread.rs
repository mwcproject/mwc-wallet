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

//! Test a wallet repost command
#[macro_use]
extern crate log;
extern crate mwc_wallet_api as api;
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;
extern crate mwc_wallet_libwallet as libwallet;

// use crate::libwallet::api_impl::owner_updater::{start_updater_log_thread, StatusMessage};
// use mwc_wallet_util::mwc_core as core;

use impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_util::mwc_core::global;
use std::ops::DerefMut;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup, setup_global_chain_type};
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_util::Mutex;

/// updater thread test impl
fn updater_thread_test_impl(test_dir: &str) -> Result<(), wallet::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
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

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account1")?;
		api.create_account_path(m, "account2")?;
		Ok(())
	})?;

	// Get some mining done
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

	let owner_api = api::Owner::new(wallet1, None, None);
	owner_api.start_updater(mask1, Duration::from_secs(5))?;

	// let updater thread run a bit
	thread::sleep(Duration::from_secs(10));

	let messages = owner_api.get_updater_messages(Some(1000))?;
	assert!(messages.len() >= 15); // mwc has 32 lines, mwc has 25 lines.  We don't want ot validate content, it will change. Just checking that it alive.

	owner_api.stop_updater()?;
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_secs(2));
	Ok(())
}

#[test]
fn updater_thread() {
	// The "updater" kicks off a new thread so we need to ensure the global chain_type
	// is set for this to work correctly.
	setup_global_chain_type();

	let test_dir = "test_output/updater_thread";
	setup(test_dir);
	if let Err(e) = updater_thread_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
