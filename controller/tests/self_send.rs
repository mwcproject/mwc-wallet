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

//! Test a wallet sending to self

#![cfg(feature = "test-support")]

use mwc_wallet_util::mwc_core::{self, global};
use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::{InitTxArgs, OutputStatus, Slate, TxLogEntryType};
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::Transaction;

fn get_session(session: &mut TxSession, use_sessions: bool) -> Option<&mut TxSession> {
	if use_sessions { Some(session) } else { None }
}

/// self send impl
fn self_send_test_impl(
	test_dir: &str,
	use_sessions: bool,
) -> Result<(), mwc_wallet_controller::Error> {
	// Create a new proxy to simulate server and wallet responses
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
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
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter
	let reward = mwc_core::consensus::MWC_FIRST_GROUP_REWARD;

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

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
				mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
			)?;
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
				..Default::default()
			};

			let mut sender_session = TxSession::new();
			let mut receiver_session = TxSession::new();
			let mut duplicate_receiver_session = TxSession::new();
			let mut receive_data = None;
			let mut receive_processing_guard = None;

			let mut slate =
				api.init_send_tx(m, get_session(&mut sender_session, use_sessions), &args, 1)?;
			if use_sessions {
				// Non-late sends must reserve their inputs before the remote exchange,
				// not only when tx_lock_outputs is called afterward.
				assert!(!sender_session.get_input_commits().is_empty());
			}
			api.tx_lock_outputs(
				m,
				get_session(&mut sender_session, use_sessions),
				&slate,
				None,
				0,
			)?;
			let request_slate = slate.clone();
			// A nonexistent destination account must be rejected, not silently
			// rerouted to the configured receive account.
			mwc_wallet_controller::controller::foreign_single_use(
				wallet1.clone(),
				mask1_i.clone(),
				|api| {
					assert!(matches!(
						api.receive_tx(
							&mut TxSession::new(),
							&request_slate,
							None,
							None,
							None,
							&Some("no_such_account".to_string()),
							None,
							true,
						),
						Err(mwc_wallet_libwallet::Error::UnknownAccountLabel(name))
							if name == "no_such_account"
					));
					Ok(())
				},
			)?;
			// Send directly to self
			mwc_wallet_controller::controller::foreign_single_use(
				wallet1.clone(),
				mask1_i.clone(),
				|api| {
					let receive_result = api.receive_tx(
						&mut receiver_session,
						&request_slate,
						None,
						None,
						None,
						&Some("listener".to_string()),
						None,
						true,
					)?;
					assert!(receive_result.reply_reservation.is_none());
					slate = receive_result.slate;
					receive_processing_guard = Some(receive_result.processing_guard);
					receive_data = receive_result.receive_data;
					Ok(())
				},
			)?;
			if !use_sessions {
				{
					wallet_lock!(api.wallet_inst, w);
					receiver_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
				}
				if let Some(receive_data) = receive_data.take() {
					mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
				}
				drop(receive_processing_guard.take());
			}
			if use_sessions {
				// The same UUID cannot start another receive while the first
				// exchange still owns its process-local reservation.
				mwc_wallet_controller::controller::foreign_single_use(
					wallet1.clone(),
					mask1_i.clone(),
					|api| {
						assert!(matches!(
							api.receive_tx(
								&mut duplicate_receiver_session,
								&request_slate,
								None,
								None,
								None,
								&Some("default".to_string()),
								None,
								true,
							),
							Err(mwc_wallet_libwallet::Error::TransactionInProgress(id))
								if id == request_slate.id.to_string()
						));
						Ok(())
					},
				)?;
			}
			slate = api.finalize_tx(
				m,
				get_session(&mut sender_session, use_sessions),
				&slate,
				true,
			)?;
			api.post_tx(m, slate.tx_or_err()?, false)?; // mines a block

			if use_sessions {
				debug_assert!(sender_session.get_context_participant().is_none());
				debug_assert!(receiver_session.get_context_participant().is_none());

				let received_count = {
					wallet_lock!(api.wallet_inst, w);
					let mut batch = w.batch(&secp, m)?;
					sender_session.save_tx_data_into_batch(&mut *batch, &secp, &slate.id)?;
					receiver_session.save_tx_data_into_batch(&mut *batch, &secp, &slate.id)?;
					batch.commit()?;
					drop(batch);
					w
						.tx_log_iter()?
						.chain(w.tx_log_archive_iter()?)
						.filter(|tx| {
							tx.tx_type == mwc_wallet_libwallet::TxLogEntryType::TxReceived
								&& tx.tx_slate_id == Some(slate.id)
						})
						.count()
				};
				drop(receive_processing_guard.take());
				assert_eq!(received_count, 1);
				mwc_wallet_controller::controller::foreign_single_use(
					wallet1.clone(),
					mask1_i.clone(),
					|api| {
						assert!(matches!(
							api.receive_tx(
								&mut TxSession::new(),
								&request_slate,
								None,
								None,
								None,
								&Some("default".to_string()),
								None,
								true,
							),
							Err(mwc_wallet_libwallet::Error::TransactionAlreadyReceived(id))
								if id == request_slate.id.to_string()
						));
						Ok(())
					},
				)?;
				assert!(
					!std::path::Path::new(&format!(
						"{}/wallet1/wallet_data/slatepack/{}.send_response.slate",
						test_dir, slate.id
					))
					.exists()
				);
				if let Some(receive_data) = receive_data {
					mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
				}
			}
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

	// Check total in 'listener' account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, 2 * reward);
			Ok(())
		},
	)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

/// Numeric log IDs are account-local, but a slate UUID must repair every
/// matching entry across the wallet. Reproduce the dangerous legacy state in
/// which cancelling the receiver entry also removes both private contexts,
/// then ensure UUID cancellation still reaches and unlocks the sender entry.
fn cross_account_cancel_test_impl(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
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
		true
	);
	let mask1 = (&mask1_i).as_ref();
	let proxy_handle = wallet_proxy.start();

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
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		10,
		false,
		tx_pool.lock().deref_mut(),
	);

	let mut slate = Slate::blank(1, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
				mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
			)?;
			let args = InitTxArgs {
				src_acct_name: Some("mining".to_owned()),
				amount: mwc_core::consensus::MWC_FIRST_GROUP_REWARD * 2,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};

			slate = api.init_send_tx(m, None, &args, 1)?;
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			let request_slate = slate.clone();
			let mut receiver_session = TxSession::new();
			let mut receive_data = None;
			let mut receive_processing_guard = None;
			mwc_wallet_controller::controller::foreign_single_use(
				wallet1.clone(),
				mask1_i.clone(),
				|foreign_api| {
					let receive_result = foreign_api.receive_tx(
						&mut receiver_session,
						&request_slate,
						None,
						None,
						None,
						&Some("listener".to_owned()),
						None,
						true,
					)?;
					slate = receive_result.slate;
					receive_data = receive_result.receive_data;
					receive_processing_guard = Some(receive_result.processing_guard);
					Ok(())
				},
			)?;
			{
				wallet_lock!(api.wallet_inst, w);
				receiver_session.save_tx_data(&secp, &mut **w, m, &slate.id)?;
			}
			if let Some(receive_data) = receive_data.take() {
				mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
			}
			drop(receive_processing_guard.take());
			Ok(())
		},
	)?;

	let slate_id = slate.id;
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
				mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
			)?;
			let receiver_id = {
				wallet_lock!(api.wallet_inst, w);
				let group: Vec<_> = w
					.tx_log_iter()?
					.chain(w.tx_log_archive_iter()?)
					.filter(|tx| tx.tx_slate_id == Some(slate_id))
					.collect();
				assert_eq!(group.len(), 2);
				assert!([0, 1].into_iter().any(|participant_id| w
					.get_private_context(&secp, m, slate_id.as_bytes(), participant_id)
					.is_ok()));
				group
					.iter()
					.find(|tx| tx.tx_type == TxLogEntryType::TxReceived)
					.unwrap()
					.id
			};

			// Numeric cancellation is scoped to the active listener account.
			api.cancel_tx(m, Some(receiver_id), None)?;
			{
				wallet_lock!(api.wallet_inst, w);
				let group: Vec<_> = w
					.tx_log_iter()?
					.chain(w.tx_log_archive_iter()?)
					.filter(|tx| tx.tx_slate_id == Some(slate_id))
					.collect();
				assert!(group
					.iter()
					.any(|tx| tx.tx_type == TxLogEntryType::TxSent));
				assert!(group
					.iter()
					.any(|tx| tx.tx_type == TxLogEntryType::TxReceivedCancelled));
				assert!(w.iter()?.any(|output| output.status == OutputStatus::Locked));
				for participant_id in [0, 1] {
					assert!(w
						.get_private_context(&secp, m, slate_id.as_bytes(), participant_id)
						.is_err());
				}
			}

			// A repair scan must keep the input reserved while any account-local
			// member of this logical self-send remains active.
			api.scan(m, None, None, false)?;
			{
				wallet_lock!(api.wallet_inst, w);
				let group: Vec<_> = w
					.tx_log_iter()?
					.chain(w.tx_log_archive_iter()?)
					.filter(|tx| tx.tx_slate_id == Some(slate_id))
					.collect();
				assert!(group
					.iter()
					.any(|tx| tx.tx_type == TxLogEntryType::TxSent));
				assert!(group
					.iter()
					.any(|tx| tx.tx_type == TxLogEntryType::TxReceivedCancelled));
				assert!(w.iter()?.any(|output| output.status == OutputStatus::Locked));
			}

			// UUID cancellation is wallet-global and repairs the remaining sender
			// even though the listener account is active and contexts are gone.
			api.cancel_tx(m, None, Some(slate_id))?;
			{
				wallet_lock!(api.wallet_inst, w);
				let group: Vec<_> = w
					.tx_log_iter()?
					.chain(w.tx_log_archive_iter()?)
					.filter(|tx| tx.tx_slate_id == Some(slate_id))
					.collect();
				assert_eq!(group.len(), 2);
				assert!(group.iter().all(|tx| tx.is_cancelled()));
				assert!(!w.iter()?.any(|output| output.status == OutputStatus::Locked));
			}
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_self_send_no_sessions() {
	let test_dir = "test_output/self_send_nonses";
	setup(test_dir);
	if let Err(e) = self_send_test_impl(test_dir, false) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn wallet_self_send_with_sessions() {
	let test_dir = "test_output/self_send_ses";
	setup(test_dir);
	if let Err(e) = self_send_test_impl(test_dir, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn wallet_cross_account_cancel_scope() {
	let test_dir = "test_output/self_send_cancel_scope";
	setup(test_dir);
	if let Err(e) = cross_account_cancel_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
