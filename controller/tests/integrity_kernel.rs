// Copyright 2021 The MWC Developers
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

//! Test an integrity output creation. Check if we can sing this commit.
//! At mwc-walllet there is a test for validation. It will use printed results form this test
//!
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_core::global;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use std::thread;
use std::time::Duration;

use grin_wallet_util::grin_util as util;
use libp2p::PeerId;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use grin_wallet_libwallet::internal::updater;
use grin_wallet_libwallet::{owner, TxLogEntryType};
use grin_wallet_util::grin_core::core::hash::Hash;
use grin_wallet_util::grin_core::core::{KernelFeatures, TxKernel};
use grin_wallet_util::grin_core::libtx::aggsig;
use grin_wallet_util::grin_p2p::libp2p_connection;
use grin_wallet_util::grin_util::secp;
use grin_wallet_util::grin_util::secp::pedersen::Commitment;
use grin_wallet_util::grin_util::secp::Message;
use libp2p::identity::Keypair;
use std::collections::HashMap;
use std::convert::TryInto;

/// self send impl
fn integrity_kernel_impl(test_dir: &'static str) -> Result<(), wallet::Error> {
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

	// 4 is a lock height for coinbase. We want 2 mining rewards to spend.
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);
	let _ = owner::perform_refresh_from_node(wallet1.clone(), mask1, &None)?;

	// Check wallet 1 contents are as expected
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!(
			"Wallet 1 Info Pre-Transaction, after {} blocks: {:?}",
			wallet1_info.last_confirmed_height,
			wallet1_info //  assert_eq!(wallet1_info.total, 1);
		);
		assert_eq!(wallet1_info.total, 5 * reward);

		Ok(())
	})?;

	// Nothing expected at the beginning
	let (account, outputs, _height, integral_balance) =
		libwallet::owner_libp2p::get_integral_balance(wallet1.clone(), mask1)?;
	assert!(account.is_none());
	assert!(outputs.is_empty());
	assert!(integral_balance.is_empty());

	// Creating the integral balance.
	let integral_balance = libwallet::owner_libp2p::create_integral_balance(
		wallet1.clone(),
		mask1,
		1_000_000_000,
		&vec![30_000_000],
		&Some("default".to_string()),
	)?;
	assert_eq!(integral_balance.len(), 1);
	assert_eq!(integral_balance[0].0.is_some(), true);
	assert_eq!(integral_balance[0].0.clone().unwrap().fee, 30_000_000);
	assert_eq!(integral_balance[0].1, false);
	assert_eq!(
		integral_balance[0].0.clone().unwrap().expiration_height,
		1445 + 3
	);

	let (account, outputs, _height, integral_balance) =
		libwallet::owner_libp2p::get_integral_balance(wallet1.clone(), mask1)?;
	assert!(account.is_some());
	assert_eq!(outputs.len(), 1);
	assert_eq!(integral_balance.len(), 1);
	assert_eq!(integral_balance[0].0.fee, 30_000_000);
	assert_eq!(integral_balance[0].1, false);
	assert_eq!(integral_balance[0].0.expiration_height, 1445 + 3);

	// Retry should do nothing because first transaction is not mined yet
	let integral_balance = libwallet::owner_libp2p::create_integral_balance(
		wallet1.clone(),
		mask1,
		1_000_000_000,
		&vec![30_000_000, 35_000_000],
		&Some("default".to_string()),
	)?;
	assert_eq!(integral_balance.len(), 2);
	assert_eq!(integral_balance[1].0.is_some(), true);
	assert_eq!(integral_balance[1].0.clone().unwrap().fee, 30_000_000);
	assert_eq!(integral_balance[1].1, false);
	assert_eq!(
		integral_balance[1].0.clone().unwrap().expiration_height,
		1445 + 3
	);
	assert_eq!(integral_balance[0].0.is_some(), false);
	assert_eq!(integral_balance[0].1, false);

	// Mine a block, the transaction should be confirmed
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 1, false);
	let _ = owner::perform_refresh_from_node(wallet1.clone(), mask1, &None)?;

	let (account, outputs, _height, integral_balance) =
		libwallet::owner_libp2p::get_integral_balance(wallet1.clone(), mask1)?;
	assert!(account.is_some());
	assert_eq!(outputs.len(), 1); // Should see available output
	assert_eq!(integral_balance.len(), 1);
	assert_eq!(integral_balance[0].0.fee, 30_000_000);
	assert_eq!(integral_balance[0].1, false); // Now should be confirmed...
	assert_eq!(integral_balance[0].0.expiration_height, 1446 + 3);

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 2, false);
	let _ = owner::perform_refresh_from_node(wallet1.clone(), mask1, &None)?;
	let (account, outputs, _height, integral_balance) =
		libwallet::owner_libp2p::get_integral_balance(wallet1.clone(), mask1)?;
	assert!(account.is_some());
	assert_eq!(outputs.len(), 1); // Should see available output
	assert_eq!(integral_balance.len(), 1);
	assert_eq!(integral_balance[0].0.fee, 30_000_000);
	assert_eq!(integral_balance[0].1, true); // Now should be confirmed...

	// Now create second one should succeed
	let integral_balance = libwallet::owner_libp2p::create_integral_balance(
		wallet1.clone(),
		mask1,
		1_000_000_000,
		&vec![30_000_000, 35_000_000],
		&Some("default".to_string()),
	)?;
	assert_eq!(integral_balance.len(), 2);
	assert_eq!(integral_balance[1].0.clone().unwrap().fee, 30_000_000);
	assert_eq!(integral_balance[1].1, true);
	assert_eq!(
		integral_balance[1].0.clone().unwrap().expiration_height,
		1446 + 3
	);
	assert_eq!(integral_balance[0].0.clone().unwrap().fee, 35_000_000);
	assert_eq!(integral_balance[0].1, false);
	assert_eq!(
		integral_balance[0].0.clone().unwrap().expiration_height,
		1449 + 3
	);

	// Mine a block, the second transaction should be confirmed
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	let _ = owner::perform_refresh_from_node(wallet1.clone(), mask1, &None)?;

	let (account, outputs, _height, integral_balance) =
		libwallet::owner_libp2p::get_integral_balance(wallet1.clone(), mask1)?;
	assert!(account.is_some());
	assert_eq!(outputs.len(), 1);
	assert_eq!(integral_balance.len(), 2);
	assert_eq!(integral_balance[0].0.fee, 30_000_000);
	assert_eq!(integral_balance[0].1, true);
	assert_eq!(integral_balance[0].0.expiration_height, 1446 + 3);
	assert_eq!(integral_balance[1].0.fee, 35_000_000);
	assert_eq!(integral_balance[1].1, true);
	assert_eq!(integral_balance[1].0.expiration_height, 1450 + 3); // +1 because post in test environment mining another block.

	// Let's verify if Integrity context match the Tx Kernels.
	let txs = {
		wallet_inst!(wallet1, w);
		let mut txs = updater::retrieve_txs(&mut **w, mask1, None, None, None, false, None, None)?;

		txs.retain(|t| t.tx_type == TxLogEntryType::TxSent);
		txs
	};

	assert_eq!(txs.len(), 2);
	assert!(txs[0].kernel_excess.is_some());
	assert!(txs[1].kernel_excess.is_some());

	assert_eq!(txs[0].fee, Some(30_000_000));
	assert_eq!(txs[1].fee, Some(35_000_000));

	let kernel1 = txs[0].kernel_excess.unwrap();
	let kernel2 = txs[1].kernel_excess.unwrap();

	let integrity_context1 = integral_balance[0].0.clone();
	let integrity_context2 = integral_balance[1].0.clone();

	// Let's check if excess values matching integrity_contexts
	let secp = secp::Secp256k1::new();

	// Let's check if all signaatures are unique. It is expected
	let mut signatures: Vec<secp::Signature> = Vec::new();

	let peer_keys = Keypair::generate_ed25519();

	let peer_id = PeerId::from_public_key(peer_keys.public());
	let peer_pk = peer_id.as_dalek_pubkey().unwrap();
	let peer_id_message =
		Message::from_slice(Hash::from_vec(peer_pk.as_bytes()).as_bytes()).unwrap();

	// Let't verify the we can generate multiple valid signatures for the commits
	for _i in 0..20 {
		let (excess1, signature1) = integrity_context1.calc_kernel_excess(&secp, &peer_pk)?;
		assert_eq!(excess1, kernel1);
		let pk1 = excess1.to_pubkey(&secp).unwrap();
		// Validating the message

		assert_eq!(signatures.contains(&signature1), false);
		signatures.push(signature1.clone());

		aggsig::verify_completed_sig(&secp, &signature1, &pk1, Some(&pk1), &peer_id_message)
			.expect("Signature1 validation is failed");

		let (excess2, signature2) = integrity_context2.calc_kernel_excess(&secp, &peer_pk)?;
		assert_eq!(excess2, kernel2);
		let pk2 = excess2.to_pubkey(&secp).unwrap();
		// Validating the message
		assert_eq!(signatures.contains(&signature2), false);
		signatures.push(signature2.clone());

		aggsig::verify_completed_sig(&secp, &signature2, &pk2, Some(&pk2), &peer_id_message)
			.expect("Signature2 validation is failed");
	}

	// Testing for libp2p routine
	println!("peer_id data: {}", util::to_hex(&peer_id.to_bytes()));

	let (kernel_excess, signature) = integrity_context1.calc_kernel_excess(&secp, &peer_pk)?;
	let message: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

	println!("kernel_excess: {}", util::to_hex(&kernel_excess.0));
	println!(
		"signature: {}",
		util::to_hex(&signature.serialize_compact(&secp))
	);

	// Build message for p2p network
	let libp2p_message = libp2p_connection::build_integrity_message(
		&kernel_excess,
		&peer_pk,
		&signature,
		&message,
		&secp,
	)
	.unwrap();

	let output_validation_fn = |_kernel: &Commitment| {
		Ok(Some(TxKernel::with_features(KernelFeatures::Plain {
			fee: (100_000_000 as u64).try_into().unwrap(),
		})))
	};
	let output_validation_fn = std::sync::Arc::new(output_validation_fn);

	let validate_ok = libp2p_connection::validate_integrity_message(
		&peer_id,
		&libp2p_message,
		output_validation_fn.clone(),
		&mut HashMap::new(),
		1_000_000,
		&secp,
	);
	// PeerId can be anyting. because of forward it can change
	let validate_ok2 = libp2p_connection::validate_integrity_message(
		&PeerId::random(),
		&libp2p_message,
		output_validation_fn.clone(),
		&mut HashMap::new(),
		1_000_000,
		&secp,
	);
	assert!(validate_ok.is_ok());
	assert_eq!(validate_ok.unwrap().0, 100_000_000);
	assert!(validate_ok2.is_ok());
	assert_eq!(validate_ok2.unwrap().0, 100_000_000);

	// add some accounts to check if lowest indexes will be used.
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let acc_id1 = api.create_account_path(m, "second")?;
		let acc_id2 = api.create_account_path(m, "third")?;
		assert_eq!(acc_id1.to_bip_32_string(), "m/1/0");
		assert_eq!(acc_id2.to_bip_32_string(), "m/2/0");
		Ok(())
	})?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_integrity_kernel() {
	let test_dir = "test_output/integrity_kernel";
	setup(test_dir);
	if let Err(e) = integrity_kernel_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
