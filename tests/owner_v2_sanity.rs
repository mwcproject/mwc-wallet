// Copyright 2019 The Mwc Developers
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

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate mwc_wallet;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use mwc_wallet_impls::DefaultLCProvider;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_keychain::ExtKeychain;

#[macro_use]
mod common;
use common::RetrieveSummaryInfoResp;
use common::{
	clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, send_request,
	setup,
};

#[test]
fn owner_v2_sanity() -> Result<(), mwc_wallet_controller::Error> {
	// For windows we can't run it because of the leaks. And we dont want to see bunch of warnings as well
	#[cfg(target_os = "windows")]
	if true {
		return Ok(());
	}

	let test_dir = "target/test_output/owner_v2_sanity";
	setup(test_dir);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	// Running update thread, we can't set local to it...
	global::init_global_chain_type(global::ChainTypes::AutomatedTesting);

	setup_proxy!(test_dir, chain, wallet1, client1, mask1, wallet2, client2, _mask2);

	// add some blocks manually
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);
	let client1_2 = client1.clone();

	// run the owner listener on wallet 1
	let arg_vec = vec!["mwc-wallet", "-p", "password", "owner_api"];
	// Set running
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let yml = load_yaml!("../src/bin/mwc-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).unwrap();
	});

	// run the foreign listener for wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password",
		"listen",
		"-l",
		"23415",
		"-n",
	];
	// Set owner listener running
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let yml = load_yaml!("../src/bin/mwc-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone()).unwrap();
	});

	thread::sleep(Duration::from_millis(1000));

	// 1) Send simple retrieve_info request to owner listener
	let req = include_str!("data/v2_reqs/retrieve_info.req.json");
	let res = send_request(1, "http://127.0.0.1:3420/v2/owner", req)?;
	assert!(res.is_ok());
	let value: RetrieveSummaryInfoResp = res.unwrap();
	assert_eq!(value.1.amount_currently_spendable, 16_666_666_660); // mwc: 420000000000
	println!("Response 1: {:?}", value);

	// 2) Send to wallet 2 foreign listener
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password",
		"send",
		"-d",
		"http://127.0.0.1:23415",
		"2", // mwc: 10    Only one block reward is spendable
	];
	let yml = load_yaml!("../src/bin/mwc-wallet.yml");
	let app = App::from_yaml(yml);
	let res = execute_command(&app, test_dir, "wallet1", &client1_2, arg_vec.clone());
	println!("Response 2: {:?}", res);
	assert!(res.is_ok());

	clean_output_dir(test_dir);
	Ok(())
}
