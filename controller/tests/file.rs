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

//! Test a wallet file send/recieve

#![cfg(feature = "test-support")]

use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_impls::{PathToSlateGetter, PathToSlatePutter, SlateGetter, SlatePutter};
use std::thread;
use std::time::Duration;

use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{InitTxArgs, SlateVersion, VersionedSlate};
use mwc_wallet_libwallet::wallet_lock;

use mwc_wallet_util::mwc_core::global;

use mwc_wallet_util::mwc_crates::serde_json;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::{Input, OutputFeatures, Transaction};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};

/// self send impl
fn file_exchange_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

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
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter
	let reward = mwc_wallet_util::mwc_core::consensus::MWC_FIRST_GROUP_REWARD;

	// add some accounts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			api.create_account_path(m, "listener")?;
			Ok(())
		},
	)?;

	// add some accounts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.create_account_path(m, "account1")?;
			api.create_account_path(m, "account2")?;
			Ok(())
		},
	)?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	let send_file = format!("{}/part_tx_1.tx", test_dir);
	let receive_file = format!("{}/part_tx_2.tx", test_dir);

	// test optional message
	let message = "sender test message, sender test message";

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			// send to send
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount: reward * 2,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				message: Some(message.to_owned()),
				..Default::default()
			};
			let slate = api.init_send_tx(m, None, &args, 1)?;

			// output tx file
			PathToSlatePutter::build_plain(0, Some((&send_file).into()))
				.put_tx(
					&slate,
					None,
					#[cfg(feature = "test-support")]
					true,
					&secp,
				)?;
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			Ok(())
		},
	)?;

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let mut slate = PathToSlateGetter::build_form_path(0, (&send_file).into())
		.get_tx(None, &secp)?
		.to_slate()?
		.0;
	let mut naughty_slate = slate.clone();
	naughty_slate.participant_data[0].message = Some("I changed the message".to_owned());

	// verify messages on slate match
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.verify_slate_messages(m, &slate)?;
			assert!(api.verify_slate_messages(m, &naughty_slate).is_err());
			Ok(())
		},
	)?;

	let sender2_message = "And this is sender 2's message".to_owned();
	let initial_slate = slate.clone();
	let mut max_weight_slate = initial_slate.clone();
	{
		let mut tx = max_weight_slate.tx_or_err()?.clone();
		let current_weight = tx.body.weight_size()?;
		let filler_inputs = global::max_tx_weight(0)
			.checked_sub(current_weight)
			.expect("the initial test transaction must fit below the weight limit");
		assert!(filler_inputs > 0);
		for key_number in 1..=filler_inputs {
			let key_byte =
				u8::try_from(key_number).expect("the automated-test transaction limit fits in u8");
			let secret = SecretKey::from_slice(&secp, &[key_byte; 32]).unwrap();
			let commit = secp.commit(1, secret).unwrap();
			tx = tx
				.with_input(0, Input::new(OutputFeatures::Plain, commit))
				.unwrap();
		}
		*max_weight_slate.tx_or_err_mut()? = tx;
	}
	assert_eq!(
		max_weight_slate.tx_or_err()?.body.weight_size()?,
		global::max_tx_weight(0)
	);
	max_weight_slate.validate_transaction_read(0)?;

	// wallet 2 receives file, completes, sends file back
	mwc_wallet_controller::controller::foreign_single_use(
		wallet2.clone(),
		mask2_i.clone(),
		|api| {
			let mut rejected_session = TxSession::new();
			assert!(matches!(
				api.receive_tx(
					&mut rejected_session,
					&max_weight_slate,
					None,
					None,
					None,
					&None,
					None,
					true,
				),
				Err(mwc_wallet_libwallet::Error::Transaction(
					mwc_wallet_util::mwc_core::core::transaction::Error::TooHeavy
				))
			));
			assert!(rejected_session.is_empty());

			let sender =
				mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
					.verifying_key();
			let mut receive_session = TxSession::new();
			let receive_result = api.receive_tx(
				&mut receive_session,
				&slate,
				Some(ReplyBinding::file(&sender)),
				None,
				None,
				&None,
				Some(sender2_message.clone()),
				true,
			)?;
			slate = receive_result.slate;
			let processing_guard = receive_result.processing_guard;
			{
				wallet_lock!(api.wallet_inst, w);
				receive_session.save_tx_data(&secp, &mut **w, mask2, &slate.id)?;
			}
			if let Some(reservation) = receive_result.reply_reservation {
				reservation.complete(&slate);
			}
			if let Some(receive_data) = receive_result.receive_data {
				mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
			}
			drop(processing_guard);
			let mut retry_session = TxSession::new();
			let retry_result = api.receive_tx(
				&mut retry_session,
				&initial_slate,
				Some(ReplyBinding::file(&sender)),
				None,
				None,
				&None,
				Some(sender2_message.clone()),
				true,
			)?;
			let retried_slate = retry_result.slate;
			assert_eq!(
				VersionedSlate::into_version_plain(0, &slate, SlateVersion::V3)?.as_string()?,
				VersionedSlate::into_version_plain(0, &retried_slate, SlateVersion::V3)?
					.as_string()?
			);
			drop(retry_result.processing_guard);
			assert!(matches!(
				api.receive_tx(
					&mut TxSession::new(),
					&initial_slate,
					None,
					None,
					None,
					&None,
					Some(sender2_message.clone()),
					true,
				),
				Err(mwc_wallet_libwallet::Error::TransactionAlreadyReceived(_))
			));
			let mut changed_request = initial_slate.clone();
			changed_request.amount = changed_request.amount.saturating_add(1);
			assert!(matches!(
				api.receive_tx(
					&mut TxSession::new(),
					&changed_request,
					Some(ReplyBinding::file(&sender)),
					None,
					None,
					&None,
					Some(sender2_message.clone()),
					true,
				),
				Err(mwc_wallet_libwallet::Error::ReceiveResponseMismatch(_))
			));
			let other_sender =
				mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
					.verifying_key();
			assert!(matches!(
				api.receive_tx(
					&mut TxSession::new(),
					&initial_slate,
					Some(ReplyBinding::file(&other_sender)),
					None,
					None,
					&None,
					Some(sender2_message.clone()),
					true,
				),
				Err(mwc_wallet_libwallet::Error::ReceiveResponseMismatch(_))
			));
			assert!(
				!std::path::Path::new(&format!(
					"{}/wallet2/wallet_data/slatepack/{}.send_response.slate",
					test_dir, slate.id
				))
				.exists()
			);
			PathToSlatePutter::build_plain(0, Some((&receive_file).into()))
				.put_tx(
					&slate,
					None,
					#[cfg(feature = "test-support")]
					true,
					&secp,
				)?;
			Ok(())
		},
	)?;

	// wallet 1 finalises and posts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let mut slate = PathToSlateGetter::build_form_path(0, receive_file.into())
				.get_tx(None, &secp)?
				.to_slate()?
				.0;
			api.verify_slate_messages(m, &slate)?;
			slate = api.finalize_tx(m, None, &slate, true)?;
			api.post_tx(m, slate.tx_or_err()?, false)?;
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		3,
		false,
		tx_pool.lock().deref_mut(),
	);
	bh += 3;

	// Check total in mining account
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward - reward * 2);
			Ok(())
		},
	)?;

	// Check total in 'wallet 2' account
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet2_refreshed);
			assert_eq!(wallet2_info.last_confirmed_height, bh);
			assert_eq!(wallet2_info.total, 2 * reward);
			Ok(())
		},
	)?;

	// Check messages, all participants should have both
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, tx) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
			assert_eq!(
				tx[0].clone().messages.unwrap().messages[0].message,
				Some(message.to_owned())
			);
			assert_eq!(
				tx[0].clone().messages.unwrap().messages[1].message,
				Some(sender2_message.to_owned())
			);

			let msg_json = serde_json::to_string_pretty(&tx[0].clone().messages.unwrap()).unwrap();
			println!("{}", msg_json);
			Ok(())
		},
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (_, _, tx) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
			assert_eq!(
				tx[0].clone().messages.unwrap().messages[0].message,
				Some(message.to_owned())
			);
			assert_eq!(
				tx[0].clone().messages.unwrap().messages[1].message,
				Some(sender2_message)
			);
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
fn wallet_file_exchange() {
	let test_dir = "test_output/file_exchange";
	setup(test_dir);
	if let Err(e) = file_exchange_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
