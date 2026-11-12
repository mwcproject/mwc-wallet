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

#![cfg(feature = "test-support")]

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::{InitTxArgs, Slate};
use mwc_wallet_libwallet::wallet_lock;
use std::ops::DerefMut;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::consensus::calc_mwc_block_reward;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::libtx::aggsig;
use mwc_wallet_util::mwc_crates::blake2_rfc::blake2b::blake2b;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{self, ContextFlag, Secp256k1};
use mwc_wallet_util::Mutex;

/// self send impl
fn late_lock_test_impl(test_dir: &str) -> Result<(), mwc_wallet_libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

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
	let proxy_handle = wallet_proxy.start();

	// add some accounts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			Ok(())
		},
	)
	.unwrap();

	// add some accounts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|api, m| {
			api.create_account_path(m, "account1")?;
			Ok(())
		},
	)
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
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			// Reward from mining 11 blocks, minus the amount sent.
			// Note: We mined the block containing the tx, so fees are effectively refunded.
			let expected_amount = calc_mwc_block_reward(0, 1) * (10 - 3);
			assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
			//reward is 2_380_952_380
			Ok(())
		},
	)
	.unwrap();

	let mut slate = Slate::blank(2, false)?;
	let amount = 1_000_000_000;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|sender_api, m| {
			let oversized_message = "m".repeat(3_000);
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				message: Some(oversized_message),
				target_slate_version: Some(4),
				late_lock: Some(true),
				..Default::default()
			};
			for invalid_routputs in [0, 2] {
				let err = sender_api
					.init_send_tx(m, None, &args, invalid_routputs)
					.expect_err("late-lock must reject a receiver-output count other than one");
				let expected = format!(
					"Late-lock transactions require exactly one recipient output, routputs={}",
					invalid_routputs
				);
				assert!(
					matches!(
						&err,
						mwc_wallet_libwallet::Error::GenericError(message) if message == &expected
					),
					"unexpected error: {}",
					err
				);
			}
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			let sender_message = slate_i.participant_data[0]
				.message
				.as_deref()
				.expect("late-lock sender message must be present");
			assert_eq!(sender_message.len(), 1_000);
			assert!(sender_message.bytes().all(|byte| byte == b'm'));
			println!("S1 SLATE: {:?}", slate_i);
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			println!("S2 SLATE: {:?}", slate);

			// Still all amount is spendable the same way
			mwc_wallet_controller::controller::owner_single_use(
				Some(wallet_mining.clone()),
				mask1,
				None,
				|api, m| {
					let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
					assert!(wallet1_refreshed);
					// Reward from mining 11 blocks, minus the amount sent.
					// Note: We mined the block containing the tx, so fees are effectively refunded.
					let expected_amount = calc_mwc_block_reward(0, 1) * (10 - 3);
					assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
					//reward is 2_380_952_380
					Ok(())
				},
			)
			.unwrap();

			// Note we don't call `tx_lock_outputs` on the sender side here,
			// as the outputs will only be locked during finalization

			slate = sender_api.finalize_tx(m, None, &slate, true)?;
			println!("S3 SLATE: {:?}", slate);

			// Now one input should be locked
			mwc_wallet_controller::controller::owner_single_use(
				Some(wallet_mining.clone()),
				mask1,
				None,
				|api, m| {
					let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
					assert!(wallet1_refreshed);
					// Reward from mining 11 blocks, minus the amount sent.
					// Note: We mined the block containing the tx, so fees are effectively refunded.
					let expected_amount = calc_mwc_block_reward(0, 1) * (10 - 3 - 1);
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
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			// Reward from mining 11 blocks, minus the amount sent.
			// Note: We mined the block containing the tx, so fees are effectively refunded.
			let expected_amount = calc_mwc_block_reward(0, 1) * (14 - 3) - amount; // fee should be mined back,
			assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
			// expected is 25190476180
			Ok(())
		},
	)
	.unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|api, m| {
			let (wallet2_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet2_refreshed);
			assert_eq!(amount, wallet_info.amount_currently_spendable);
			Ok(())
		},
	)
	.unwrap();

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
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

/// Late lock with amount_includes_fee: the receiver must be credited
/// amount - fee and the sender must spend exactly amount. A max-spend
/// (strategy "all") late-lock send must be finalizable.
fn late_lock_includes_fee_test_impl(test_dir: &str) -> Result<(), mwc_wallet_libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

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

	let proxy_handle = wallet_proxy.start();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			Ok(())
		},
	)
	.unwrap();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|api, m| {
			api.create_account_path(m, "account1")?;
			Ok(())
		},
	)
	.unwrap();

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

	let mut slate = Slate::blank(2, false)?;
	let amount = 1_000_000_000;
	let mut fee1 = 0;

	// Part 1: fee-inclusive late-lock send wallet1 -> wallet2
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount,
				amount_includes_fee: Some(true),
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				target_slate_version: Some(4),
				late_lock: Some(true),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			fee1 = slate_i.fee;
			// The slate must carry the fee-adjusted amount so the receiver is
			// credited amount - fee and the sender spends exactly amount.
			assert_eq!(
				slate_i.amount,
				amount - fee1,
				"late-lock slate amount must be reduced by the fee"
			);
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			assert_eq!(slate.amount, amount - fee1);
			slate = sender_api.finalize_tx(m, None, &slate, true)?;
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

	// Sender is debited exactly amount: amount - fee goes to the receiver and
	// the fee is mined back, so the net outflow is amount - fee.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			let expected_amount = calc_mwc_block_reward(0, 1) * (14 - 3) - amount + fee1;
			assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
			Ok(())
		},
	)
	.unwrap();

	// Receiver is credited amount - fee.
	let spendable2 = mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|api, m| {
			let (wallet2_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet2_refreshed);
			assert_eq!(
				amount - fee1,
				wallet_info.amount_currently_spendable,
				"receiver must be credited amount - fee"
			);
			Ok(wallet_info.amount_currently_spendable)
		},
	)
	.unwrap();

	// Part 2: max-spend late-lock send wallet2 -> wallet1. Selection targets
	// the full balance; finalization must succeed rather than failing with
	// insufficient funds after the receiver already processed the slate.
	let mut fee2 = 0;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: Some("account1".to_owned()),
				amount: spendable2,
				amount_includes_fee: Some(true),
				minimum_confirmations: 1,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				target_slate_version: Some(4),
				late_lock: Some(true),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			fee2 = slate_i.fee;
			assert_eq!(slate_i.amount, spendable2 - fee2);
			slate = client2.send_tx_slate_direct("wallet1", &slate_i)?;
			slate = sender_api.finalize_tx(m, None, &slate, true)?;
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

	// wallet2 spent everything.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_acc1.clone()),
		mask2,
		None,
		|api, m| {
			let (wallet2_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet2_refreshed);
			assert_eq!(0, wallet_info.amount_currently_spendable);
			Ok(())
		},
	)
	.unwrap();

	// wallet1 received spendable2 - fee2, with fee2 mined back.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			let expected_amount =
				calc_mwc_block_reward(0, 1) * (18 - 3) - amount + fee1 + spendable2;
			assert_eq!(expected_amount, wallet_info.amount_currently_spendable);
			Ok(())
		},
	)
	.unwrap();

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn late_lock_amount_includes_fee() {
	let test_dir = "test_output/late_lock_includes_fee";
	setup(test_dir);
	if let Err(e) = late_lock_includes_fee_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[derive(Clone, Copy)]
enum LateLockCorruption {
	PartialSignature,
	RangeProof,
}

/// A crafted late-lock response must fail finalization before any durable
/// lock state is written, and the original late-lock context must remain
/// available for a valid retry.
fn late_lock_bad_response_impl(
	test_dir: &str,
	corruption: LateLockCorruption,
) -> Result<(), mwc_wallet_libwallet::Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

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
	let _ = mask2;

	let proxy_handle = wallet_proxy.start();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet_mining.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			Ok(())
		},
	)
	.unwrap();
	{
		wallet_inst!(wallet_mining, w);
		w.set_parent_key_id_by_name("mining")?;
	}

	test_framework::award_blocks_to_wallet(
		&chain,
		wallet_mining.clone(),
		mask1,
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	let amount = 1_000_000_000;
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
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
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			let valid_slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			let mut slate = valid_slate.clone();

			match corruption {
				LateLockCorruption::PartialSignature => {
					// Malicious receiver: a correctly encoded partial signature that
					// does not match the transaction transcript.
					let rogue_key = SecretKey::from_slice(&secp, &[7u8; 32]).unwrap();
					let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &[]);
					let msg = secp::Message::from_slice(&hashed.as_bytes()).unwrap();
					let rogue_pub = PublicKey::from_secret_key(&secp, &rogue_key).unwrap();
					let rogue_sig =
						aggsig::sign_single(&secp, &msg, &rogue_key, None, &rogue_pub).unwrap();
					let mut corrupted = 0;
					for p in slate.participant_data.iter_mut() {
						if p.id == 1 {
							p.part_sig = Some(rogue_sig.clone());
							corrupted += 1;
						}
					}
					assert_eq!(1, corrupted, "expected exactly one receiver record");
				}
				LateLockCorruption::RangeProof => {
					let output = slate
						.tx
						.as_mut()
						.and_then(|tx| tx.body.outputs.first_mut())
						.expect("receiver response must carry an output");
					assert!(output.proof.len()? > 0);
					output.proof.proof[0] ^= 1;
				}
			}

			let slate_id = slate.id;
			let res = sender_api.finalize_tx(m, None, &slate, true);
			assert!(res.is_err(), "finalize must reject the crafted response");

			// Wallet state must be untouched: everything is still spendable
			// and the init-time cancellation log entry was not updated with
			// inputs, change outputs, or commitments.
			let (refreshed, info) = sender_api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(
				calc_mwc_block_reward(0, 1) * (10 - 3),
				info.amount_currently_spendable,
				"no inputs may stay locked after the rejected finalize"
			);
			let (_, _, txs) = sender_api.retrieve_txs(m, false, None, None, None, None)?;
			let entry = txs
				.iter()
				.find(|t| t.tx_slate_id == Some(slate_id))
				.expect("the init-time cancellation log entry must exist");
			assert_eq!(
				0, entry.num_inputs,
				"rejected finalize must not record selected inputs"
			);
			assert!(
				entry.input_commits.is_empty() && entry.output_commits.is_empty(),
				"rejected finalize must not record input or change commitments"
			);
			{
				wallet_lock!(sender_api.wallet_inst, w);
				let context =
					w.get_private_context(&secp, m, slate_id.as_bytes(), 0)?;
				assert!(
					context.late_lock_args.is_some(),
					"rejected finalize must retain the late-lock retry context"
				);
			}

			let finalized = sender_api.finalize_tx(m, None, &valid_slate, true)?;
			assert_eq!(finalized.id, slate_id, "valid retry must succeed");
			Ok(())
		},
	)
	.unwrap();

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn late_lock_bad_response_sig() {
	let test_dir = "test_output/late_lock_bad_response_sig";
	setup(test_dir);
	if let Err(e) = late_lock_bad_response_impl(test_dir, LateLockCorruption::PartialSignature) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn late_lock_bad_rangeproof() {
	let test_dir = "test_output/late_lock_bad_rangeproof";
	setup(test_dir);
	if let Err(e) = late_lock_bad_response_impl(test_dir, LateLockCorruption::RangeProof) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
