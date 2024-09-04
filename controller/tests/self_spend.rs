// Copyright 2019 The Grin Developers
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

//! Test a wallet spending some particular output
//! this is part of solution to mitigate replay attack.
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_core::global;

use self::libwallet::OutputStatus;
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn self_spend_impl(test_dir: &'static str) -> Result<(), wallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

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
		true
	);
	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::MWC_FIRST_GROUP_REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining1")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining1")?;
	}
	let mut bh = 4u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Check wallet 1 contents are as expected
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!(
			"Wallet 1 Info Pre-Transaction, after {} blocks: {:?}",
			wallet1_info.last_confirmed_height,
			wallet1_info //  assert_eq!(wallet1_info.total, 1);
		);
		assert_eq!(wallet1_info.total, bh * reward);

		Ok(())
	})?;

	//how to get the output in the wallet
	let (_, output_mappings) =
		libwallet::owner::retrieve_outputs(wallet1.clone(), mask1, &None, false, false, None)?;

	let mut output_list = Vec::new();
	for m in output_mappings.clone() {
		debug!("===========the outputs are {:?}", m);
		if m.output.status != OutputStatus::Unconfirmed && m.output.status != OutputStatus::Locked {
			output_list.push(m.output);
		}
	}

	debug!("===========the outputs list are {:?}", output_list);
	assert!(output_list.len() == 4);

	libwallet::owner::self_spend_particular_output(
		wallet1.clone(),
		mask1,
		output_list[0].clone(),
		Some("mining1".to_string()),
		1,
		1,
		true,
	)?;
	libwallet::owner::self_spend_particular_output(
		wallet1.clone(),
		mask1,
		output_list[1].clone(),
		Some("mining1".to_string()),
		1,
		1,
		true,
	)?;

	let _fee = core::libtx::tx_fee(1, 1, 1); //there is only one input and one output and one kernel

	//after the self spend, make sure the scan is done to update the status.
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!(
			"Wallet 1 Info Pre-Transaction, after {} blocks: {:?}",
			wallet1_info.last_confirmed_height, wallet1_info
		);
		bh += 2;
		assert_eq!(wallet1_info.total, bh * reward); //the way we build the testcode, the tx amount reward+fee will be mined and give it to the sender wallet.
		Ok(())
	})?;

	//how to get the output in the wallet
	let (_, output_mappings_after_spend) =
		libwallet::owner::retrieve_outputs(wallet1.clone(), mask1, &None, false, false, None)?;

	let mut output_list_after_spend = Vec::new();
	for m in output_mappings_after_spend.clone() {
		debug!("===========afterwards the outputs are {:?}", m);
		if m.output.status != OutputStatus::Unconfirmed && m.output.status != OutputStatus::Locked {
			output_list_after_spend.push(m.output);
		} else {
			println!("{:?}", m);
		}
	}
	//usize::from(bh)
	assert!(output_list_after_spend.len() == 6);

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_self_spend() {
	let test_dir = "test_output/self_spend";
	setup(test_dir);
	if let Err(e) = self_spend_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
