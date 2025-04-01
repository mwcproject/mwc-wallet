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

//! Test wallet command line works as expected
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
use mwc_wallet_util::mwc_keychain::ExtKeychain;

mod common;
use common::{clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, setup};
use mwc_wallet_controller::controller;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_core::consensus::calc_mwc_block_reward;

/// command line tests
fn command_line_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	setup(test_dir);
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	// load app yaml. If it don't exist, just say so and exit
	let yml = load_yaml!("../src/bin/mwc-wallet.yml");
	let app = App::from_yaml(yml);

	// wallet init
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "init", "-h"];
	// should create new wallet file
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

	// trying to init twice - should fail
	assert!(execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).is_err());
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());

	// add wallet to proxy
	//let wallet1 = test_framework::create_wallet(&format!("{}/wallet1", test_dir), client1.clone());
	let config1 = initial_setup_wallet(test_dir, "wallet1");
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1_i.clone(),
	);

	// Create wallet 2
	let arg_vec = vec!["mwc-wallet", "-p", "password2", "init", "-h"];
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	let config2 = initial_setup_wallet(test_dir, "wallet2");
	let wallet_config2 = config2.clone().members.unwrap().wallet;
	let (wallet2, mask2_i) = instantiate_wallet(
		wallet_config2.clone(),
		client2.clone(),
		"password2",
		"default",
	)?;
	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2_i.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Create some accounts in wallet 1
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "account", "-c", "mining"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"account",
		"-c",
		"account_1",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Create some accounts in wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"account",
		"-c",
		"account_1",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;
	// already exists
	assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"account",
		"-c",
		"account_2",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// let's see those accounts
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "account"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// let's see those accounts
	let arg_vec = vec!["mwc-wallet", "-p", "password2", "account"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Mine a bit into wallet 1 so we have something to send
	// (TODO: Be able to stop listeners so we can test this better)
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) =
		instantiate_wallet(wallet_config1, client1.clone(), "password1", "default")?;
	let mask1 = (&mask1_i).as_ref();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			Ok(())
		},
	)?;

	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let very_long_message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\
	                         This part should all be truncated";

	// Update info and check
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// try a file exchange
	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b00.send_init.slatepack",
		test_dir
	);

	let out_file_name = format!("{}/out_tx", test_dir);

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"-d",
		out_file_name.as_str(),
		"-g",
		very_long_message,
		"0.3", // mwc: "10"
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let arg_vec = vec!["mwc-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-f",
		&file_name,
		"-g",
		"Thanks, Yeast!",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	// shouldn't be allowed to receive twice
	assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b00.send_response.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	// Check our transaction log, should have 10 entries
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize);
			for t in txs {
				assert!(t.kernel_excess.is_some());
			}
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
	bh += 10;

	// update info for each
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["mwc-wallet", "-p", "password2", "-a", "account_1", "info"];
	execute_command(&app, test_dir, "wallet2", &client1, arg_vec)?;

	// check results in wallet 2
	let wallet_config2 = config2.clone().members.unwrap().wallet;
	let (wallet2, mask2_i) = instantiate_wallet(
		wallet_config2.clone(),
		client2.clone(),
		"password2",
		"default",
	)?;
	let mask2 = (&mask2_i).as_ref();

	// Extracting slatepack/tor addresses
	let mut tor_addr1 = String::new();
	controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Just address at derivation index 0 for now
		let tor_pub_key = api.get_wallet_public_address(m)?;
		tor_addr1 = ProvableAddress::from_tor_pub_key(&tor_pub_key).to_string();
		Ok(())
	})?;

	let mut tor_addr2 = String::new();
	controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Just address at derivation index 0 for now
		let tor_pub_key = api.get_wallet_public_address(m)?;
		tor_addr2 = ProvableAddress::from_tor_pub_key(&tor_pub_key).to_string();
		Ok(())
	})?;

	controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.set_active_account(m, "account_1")?;
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.amount_currently_spendable, 300_000_000); // mwc: 10_000_000_000,  mwc 0.3 to nano
		Ok(())
	})?;

	// Send to wallet 2 with --amount_includes_fee
	let mut old_balance = 0;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			old_balance = wallet1_info.amount_currently_spendable;
			Ok(())
		},
	)?;

	let file_name = format!("{}/tmp_tx.part_tx", test_dir);
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"-d",
		&file_name,
		"--amount_includes_fee",
		"0.25", // mwc: "10"
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	// let's check if backup is there
	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b01.send_init.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;
	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b01.send_response.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	// Mine some blocks to confirm the transaction
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
	bh += 10;

	// Now let's check a balance at wallet2
	controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.set_active_account(m, "account_1")?;
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			300_000_000 + 250_000_000 - 8_000_000
		); // mwc: 10_000_000_000,  mwc 0.3 to nano
		Ok(())
	})?;

	// Check the new balance of wallet 1 reduced by EXACTLY the tx amount (instead of amount + fee)
	// This confirms that the TX amount was correctly computed to allow for the fee
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			// make sure the new balance is exactly equal to the old balance - the tx amount + the amount mined since then
			let amt_mined = 10 * calc_mwc_block_reward(1);
			assert_eq!(
				wallet1_info.amount_currently_spendable + 250_000_000,
				old_balance + amt_mined
			);
			Ok(())
		},
	)?;

	// Send encrypted from wallet 1 to wallet 2
	// output wallet 2's address for test creation purposes,
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"address",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Send encrypted to wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"--slatepack_recipient",
		"fgmrkh7py6grrcv7ks72y5nv5ytbrvhmjaeg3pj7rv3uyqjgqqbpu6yd",
		"-d",
		out_file_name.as_str(),
		"1.1",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.send_init.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-f",
		&file_name,
	];
	if let Err(err) = execute_command(&app, test_dir, "wallet2", &client2, arg_vec) {
		assert_eq!( String::from("Impls Error, LibWallet Error, Unable to deserialize slatepack, Slatepack decode error, Unable to decrypt, ring::error::Unspecified"),
					err.to_string() );
	} else {
		panic!("Expected to fail because of another recipient")
	}

	// Now let's send to correct slatepack address
	// Send encrypted to wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"--slatepack_recipient",
		tor_addr2.as_str(),
		"-d",
		out_file_name.as_str(),
		"1.1",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b03.send_init.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b03.send_response.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	// Check our transaction log, should have bh entries
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize + 1);
			Ok(())
		},
	)?;

	// Send to self
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"self",
		"-o",
		"3",
		"-s",
		"smallest",
		"0.5", // mwc: "10"
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// MWC send to self include recieve and finalize. So no more steps are required

	bh += 1;

	// Check our transaction log, should have bh entries + 1 for self-seld
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize + 1);
			Ok(())
		},
	)?;

	// Another file exchange, don't send, but unlock with repair command
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"-d",
		out_file_name.as_str(),
		"1.2", // mwc 10
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["mwc-wallet", "-p", "password1", "scan", "-d"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Another file exchange, cancel this time
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"-d",
		out_file_name.as_str(),
		"1.5", // mwc was 10
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["mwc-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"cancel",
		"--txid",
		"0436430c-2b02-624c-2032-570501212b06",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// issue an invoice tx, wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"invoice",
		"--slatepack_recipient",
		"fgmrkh7py6grrcv7ks72y5nv5ytbrvhmjaeg3pj7rv3uyqjgqqbpu6yd",
		"-d",
		out_file_name.as_str(),
		"0.45", // 65 at mwc test
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b07.invoice_init.slatepack",
		test_dir
	);

	// now pay the invoice tx, wallet 1
	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"pay",
		"--file",
		&file_name,
		"--dest",
		out_file_name.as_str(),
	];
	if let Err(err) = execute_command(&app, test_dir, "wallet1", &client1, arg_vec) {
		assert_eq!( String::from("Invalid argument: Parsing IO error: Unable to read slate data from file target/test_output/command_line/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b07.invoice_init.slatepack, LibWallet Error, Unable to deserialize slatepack, Slatepack decode error, Unable to decrypt, ring::error::Unspecified"), err.to_string() );
	} else {
		panic!("Expected to fail because of another recipient")
	}

	// Retry invoice with correct slatepack address
	// issue an invoice tx, wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"invoice",
		"--slatepack_recipient",
		tor_addr1.as_str(),
		"-d",
		out_file_name.as_str(),
		"0.45", // 65 at mwc test
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b08.invoice_init.slatepack",
		test_dir
	);

	// now pay the invoice tx, wallet 1
	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"pay",
		"--file",
		&file_name,
		"--dest",
		out_file_name.as_str(),
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b08.invoice_response.slatepack",
		test_dir
	);

	// and finalize, wallet 2
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"finalize_invoice",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// bit more mining
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);
	//bh += 5;

	// txs and outputs (mostly spit out for a visual in test logs)
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "-a", "mining", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// message output (mostly spit out for a visual in test logs)
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"txs",
		"-i",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// txs and outputs (mostly spit out for a visual in test logs)
	let arg_vec = vec!["mwc-wallet", "-p", "password1", "-a", "mining", "outputs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["mwc-wallet", "-p", "password2", "-a", "account_1", "txs"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"outputs",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// get tx output via -tx parameter
	let mut tx_id = "".to_string();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.set_active_account(m, "account_1")?;
			let (_, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let some_tx_id = txs[0].tx_slate_id.clone();
			assert!(some_tx_id.is_some());
			tx_id = some_tx_id.unwrap().to_hyphenated().to_string().clone();
			Ok(())
		},
	)?;
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"txs",
		"-t",
		&tx_id[..],
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// bit of mining
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);

	// Now let's check a balance at wallet2
	controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.set_active_account(m, "account_1")?;
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			300_000_000 + 250_000_000 - 8_000_000 + 1_100_000_000 + 450_000_000
		); // mwc: 10_000_000_000,  mwc 0.3 to nano
		Ok(())
	})?;

	// Test wallet sweep
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-m",
		"slatepack",
		"-d",
		out_file_name.as_str(),
		"max",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b09.send_init.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;
	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b09.send_response.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"mwc-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-f",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Mine some blocks to confirm the transaction
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);

	// Check wallet 1 is now empty, except for immature coinbase outputs from recent mining),
	// and recently matured coinbase outputs, which were not mature at time of spending.
	// This confirms that the TX amount was correctly computed to allow for the fee
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 10)?;
			// Entire 'spendable' wallet balance should have been swept, except the coinbase outputs
			// which matured in the last batch of mining. Check that the new spendable balance is
			// exactly equal to those matured coins.
			let amt_mined = 10 * calc_mwc_block_reward(1);
			assert_eq!(wallet1_info.amount_currently_spendable, amt_mined);
			Ok(())
		},
	)?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_command_line() {
	// For windows we can't run it because of the leaks. And we dont want to see bunch of warnings as well
	#[cfg(target_os = "windows")]
	if true {
		return;
	}

	let test_dir = "target/test_output/command_line";
	if let Err(e) = command_line_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
}
