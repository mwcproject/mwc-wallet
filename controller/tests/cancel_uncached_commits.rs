// Copyright 2024 The Mwc Developers
//
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

//! Regression tests for cancelling transactions whose wallet outputs have no
//! cached commitment (legacy or restored databases), and for the cancellation
//! guard against unresolvable locked inputs.

#![cfg(feature = "test-support")]

use std::ops::DerefMut;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_impls::DefaultLCProvider;
use mwc_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxyHandle};
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_libwallet::{
	InitTxArgs, OutputStatus, Slate, TxLogEntry, TxLogEntryType, WalletInst,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_chain;
use mwc_wallet_util::mwc_core::{self, global, ser};
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_crates::chrono::Duration as ChronoDuration;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::ContextFlag;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_keychain::ExtKeychain;

type Wallet = Arc<
	Mutex<
		Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>,
	>,
>;

/// Send wallet1 -> wallet2 without posting, leaving wallet1 with locked inputs
/// and an unconfirmed change output. Returns the proxy, chain, sender wallet
/// with its mask, and the finalized slate.
fn send_and_lock(
	test_dir: &str,
) -> Result<
	(
		WalletProxyHandle,
		Arc<mwc_chain::Chain>,
		Wallet,
		Option<SecretKey>,
		Slate,
	),
	mwc_wallet_controller::Error,
> {
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
	//let mask2 = (&mask2_i).as_ref();

	let proxy_handle = wallet_proxy.start();

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		5,
		false,
		tx_pool.lock().deref_mut(),
	);

	let amount = mwc_core::consensus::MWC_FIRST_GROUP_REWARD / 2;
	let mut slate = Slate::blank(1, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			// the transaction is finalized but never posted
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};

			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;
			slate = sender_api.finalize_tx(m, None, &slate, true)?;
			Ok(())
		},
	)?;

	Ok((proxy_handle, chain, wallet1, mask1_i, slate))
}

/// Outputs persisted without a cached commit must still be matched to the
/// transaction (by derived commitment or tx association), so cancellation
/// unlocks every locked input instead of silently leaving them locked.
fn cancel_with_uncached_commits(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let reward = mwc_core::consensus::MWC_FIRST_GROUP_REWARD;
	let cm = global::coinbase_maturity(0);

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let tx = txs
				.iter()
				.find(|t| t.tx_slate_id == Some(slate.id))
				.unwrap()
				.clone();
			assert!(!tx.input_commits.is_empty());

			let locked_before = api
				.retrieve_outputs(m, true, false, Some(tx.id))?
				.2
				.iter()
				.filter(|o| o.output.status == OutputStatus::Locked)
				.count();
			assert!(locked_before > 0);

			// Simulate a legacy/restored database: drop every cached commit.
			{
				wallet_lock!(api.wallet_inst, w);
				let outs: Vec<_> = w.iter()?.collect();
				assert!(outs.iter().all(|o| o.commit.is_some()));
				let mut batch = w.batch(&secp, m)?;
				for mut out in outs {
					out.commit = None;
					batch.save(out)?;
				}
				batch.commit()?;
			}

			// Cancellation must resolve and unlock all locked inputs even
			// though none of them carries a cached commitment anymore. Call the
			// internal cancel directly so the test does not depend on the owner
			// level's node refresh, which can rewrite the blanked commits.
			{
				wallet_lock!(api.wallet_inst, w);
				let parent_key_id = w.parent_key_id();
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&parent_key_id),
					Some(tx.id),
					None,
				)?;
			}

			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(
				!outputs
					.iter()
					.any(|o| o.output.status == OutputStatus::Locked),
				"cancellation left outputs locked"
			);

			let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(
				info.amount_currently_spendable,
				(info.last_confirmed_height - cm) * reward
			);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// If any input commitment recorded in the tx log cannot be resolved to a
/// wallet output, cancellation must fail instead of committing a partial
/// rollback that would leave the unresolvable inputs locked forever.
fn cancel_rejects_unresolvable_inputs(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let tx = txs
				.iter()
				.find(|t| t.tx_slate_id == Some(slate.id))
				.unwrap()
				.clone();
			assert!(!tx.input_commits.is_empty());

			let locked_before = api
				.retrieve_outputs(m, true, false, Some(tx.id))?
				.2
				.iter()
				.filter(|o| o.output.status == OutputStatus::Locked)
				.count();
			assert!(locked_before > 0);

			// Corrupt the tx log: add an input commitment that matches no
			// wallet output.
			let mut corrupted = tx.clone();
			corrupted.input_commits.push(Commitment([9u8; 33]));
			{
				wallet_lock!(api.wallet_inst, w);
				let mut batch = w.batch(&secp, m)?;
				batch.save_tx_log_entry(corrupted, &tx.parent_key_id)?;
				batch.commit()?;
			}

			// Cancellation must refuse to commit a partial rollback. Call the
			// internal cancel directly, bypassing the owner level's refresh.
			let res = {
				wallet_lock!(api.wallet_inst, w);
				let parent_key_id = w.parent_key_id();
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&parent_key_id),
					Some(tx.id),
					None,
				)
			};
			assert!(
				matches!(
					res,
					Err(mwc_wallet_libwallet::Error::TransactionNotCancellable(_))
				),
				"expected TransactionNotCancellable, got {:?}",
				res
			);

			// The transaction stays active and the inputs stay locked.
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let tx_after = txs
				.iter()
				.find(|t| t.tx_slate_id == Some(slate.id))
				.unwrap();
			assert!(!tx_after.is_cancelled());
			let locked_after = api
				.retrieve_outputs(m, true, false, Some(tx.id))?
				.2
				.iter()
				.filter(|o| o.output.status == OutputStatus::Locked)
				.count();
			assert_eq!(locked_before, locked_after);

			// With the log repaired, cancellation succeeds again.
			{
				wallet_lock!(api.wallet_inst, w);
				let mut batch = w.batch(&secp, m)?;
				batch.save_tx_log_entry(tx.clone(), &tx.parent_key_id)?;
				batch.commit()?;
			}
			{
				wallet_lock!(api.wallet_inst, w);
				let parent_key_id = w.parent_key_id();
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&parent_key_id),
					Some(tx.id),
					None,
				)?;
			}
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(
				!outputs
					.iter()
					.any(|o| o.output.status == OutputStatus::Locked),
				"cancellation left outputs locked"
			);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// A transaction can still match an output by its historical commitment after
/// another transaction has taken ownership of that output's lock. Cancelling
/// the historical transaction must not release the newer transaction's lock.
fn cancel_rejects_output_locked_by_another_transaction(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let lock_owner = txs
				.iter()
				.find(|tx| tx.tx_slate_id == Some(slate.id))
				.unwrap()
				.clone();
			assert!(!lock_owner.input_commits.is_empty());

			let locked_before = api
				.retrieve_outputs(m, true, false, Some(lock_owner.id))?
				.2
				.into_iter()
				.filter(|output| output.output.status == OutputStatus::Locked)
				.collect::<Vec<_>>();
			assert!(!locked_before.is_empty());
			assert!(
				locked_before
					.iter()
					.all(|output| output.output.tx_log_entry == Some(lock_owner.id))
			);

			// Model a separate transaction record which still references these
			// outputs by a historical commitment. The current lock remains owned by
			// `lock_owner`, just as it does after a dependent send takes the output.
			let historical_id = {
				wallet_lock!(api.wallet_inst, w);
				let mut batch = w.batch(&secp, m)?;
				let historical_id = batch.next_tx_log_id(&lock_owner.parent_key_id)?;
				let mut historical = TxLogEntry::new(
					lock_owner.parent_key_id.clone(),
					TxLogEntryType::TxReceived,
					historical_id,
				);
				historical.output_commits = lock_owner.input_commits.clone();
				batch.save_tx_log_entry(historical, &lock_owner.parent_key_id)?;
				batch.commit()?;
				historical_id
			};

			let res = {
				wallet_lock!(api.wallet_inst, w);
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&lock_owner.parent_key_id),
					Some(historical_id),
					None,
				)
			};
			assert!(
				matches!(
					&res,
					Err(mwc_wallet_libwallet::Error::TransactionNotCancellable(message))
						if message.contains("locked by another transaction")
				),
				"expected lock-ownership rejection, got {:?}",
				res
			);

			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			assert!(
				!txs.iter()
					.find(|tx| tx.id == historical_id)
					.unwrap()
					.is_cancelled()
			);
			assert!(
				!txs.iter()
					.find(|tx| tx.id == lock_owner.id)
					.unwrap()
					.is_cancelled()
			);

			let locked_after = api
				.retrieve_outputs(m, false, false, Some(lock_owner.id))?
				.2
				.into_iter()
				.filter(|output| output.output.status == OutputStatus::Locked)
				.collect::<Vec<_>>();
			assert_eq!(locked_before.len(), locked_after.len());
			assert!(
				locked_after
					.iter()
					.all(|output| output.output.tx_log_entry == Some(lock_owner.id))
			);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// Historical commitment metadata must not let cancellation rewrite a reverted
/// output whose account-scoped transaction association points to another entry.
fn cancel_preserves_reverted_output_owned_by_another_transaction(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let current_owner = txs
				.iter()
				.find(|tx| tx.tx_slate_id == Some(slate.id))
				.unwrap()
				.clone();
			let mut target = api
				.retrieve_outputs(m, true, false, Some(current_owner.id))?
				.2
				.into_iter()
				.find(|output| output.output.tx_log_entry == Some(current_owner.id))
				.unwrap();

			let historical_id = {
				wallet_lock!(api.wallet_inst, w);
				let mut batch = w.batch(&secp, m)?;
				let historical_id = batch.next_tx_log_id(&current_owner.parent_key_id)?;
				let mut historical = TxLogEntry::new(
					current_owner.parent_key_id.clone(),
					TxLogEntryType::TxReceived,
					historical_id,
				);
				historical.output_commits = vec![target.commit];

				target.output.status = OutputStatus::Reverted;
				batch.save(target.output.clone())?;
				batch.save_tx_log_entry(historical, &current_owner.parent_key_id)?;
				batch.commit()?;
				historical_id
			};

			{
				wallet_lock!(api.wallet_inst, w);
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&current_owner.parent_key_id),
					Some(historical_id),
					None,
				)?;

				let stored = w
					.iter()?
					.find(|output| {
						output.key_id == target.output.key_id
							&& output.mmr_index == target.output.mmr_index
					})
					.unwrap();
				assert_eq!(stored.status, OutputStatus::Reverted);
				assert_eq!(stored.tx_log_entry, Some(current_owner.id));
			}

			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			assert!(txs
				.iter()
				.find(|tx| tx.id == historical_id)
				.unwrap()
				.is_cancelled());
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// Cancelling every log entry for one slate must use a single backend batch.
/// Make the later entry writable in its active form but too large after its
/// transaction type changes to `TxReceivedCancelled`; the resulting staging
/// error must roll back the earlier entry and its output unlocks.
fn cancel_matching_entries_is_atomic_on_staging_error(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			let tx = txs
				.iter()
				.find(|t| t.tx_slate_id == Some(slate.id))
				.unwrap()
				.clone();

			let locked_before = api
				.retrieve_outputs(m, true, false, Some(tx.id))?
				.2
				.iter()
				.filter(|o| o.output.status == OutputStatus::Locked)
				.count();
			assert!(locked_before > 0);

			let duplicate_id;
			{
				wallet_lock!(api.wallet_inst, w);
				let mut duplicate = tx.clone();
				duplicate.tx_type = TxLogEntryType::TxReceived;
				duplicate.creation_ts += ChronoDuration::seconds(1);

				let mut batch = w.batch(&secp, m)?;
				duplicate.id = batch.next_tx_log_id(&duplicate.parent_key_id)?;
				duplicate_id = duplicate.id;

				// TxLogEntry storage is its JSON representation. Pad the active
				// entry to the exact accepted limit; the longer cancelled variant
				// will then fail while being staged by cancel_tx.
				duplicate.address = Some(String::new());
				let unpadded_len = serde_json::to_vec(&duplicate).unwrap().len();
				assert!(unpadded_len < ser::READ_CHUNK_LIMIT);
				duplicate.address = Some("x".repeat(ser::READ_CHUNK_LIMIT - unpadded_len));
				assert_eq!(
					serde_json::to_vec(&duplicate).unwrap().len(),
					ser::READ_CHUNK_LIMIT
				);

				let mut cancelled = duplicate.clone();
				cancelled.tx_type = TxLogEntryType::TxReceivedCancelled;
				assert!(serde_json::to_vec(&cancelled).unwrap().len() > ser::READ_CHUNK_LIMIT);

				batch.save_tx_log_entry(duplicate, &tx.parent_key_id)?;
				batch.commit()?;
			}

			let res = {
				wallet_lock!(api.wallet_inst, w);
				let parent_key_id = w.parent_key_id();
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&parent_key_id),
					None,
					Some(slate.id),
				)
			};
			assert!(
				matches!(
					&res,
					Err(mwc_wallet_libwallet::Error::Backend(message))
						if message.contains("Too large write")
				),
				"expected a staged tx-log size error, got {:?}",
				res
			);

			// The first entry was staged before the oversized second entry, but
			// neither its log nor its output locks may have reached the database.
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let tx_after = txs.iter().find(|t| t.id == tx.id).unwrap();
			let duplicate_after = txs.iter().find(|t| t.id == duplicate_id).unwrap();
			assert_eq!(tx_after.tx_type, tx.tx_type);
			assert_eq!(duplicate_after.tx_type, TxLogEntryType::TxReceived);

			let locked_after = api
				.retrieve_outputs(m, false, false, Some(tx.id))?
				.2
				.iter()
				.filter(|o| o.output.status == OutputStatus::Locked)
				.count();
			assert_eq!(locked_before, locked_after);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// A slate group left partially cancelled by an older wallet must be repairable:
/// already-cancelled members are left alone while the remaining members are
/// validated and committed through one batch. An entirely cancelled group is an
/// idempotent success.
fn cancel_partial_slate_group_repairs_remaining(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
			let tx = txs[0].clone();
			let duplicate_id;
			{
				wallet_lock!(api.wallet_inst, w);
				let mut duplicate = tx.clone();
				duplicate.tx_type = TxLogEntryType::TxReceived;
				duplicate.creation_ts += ChronoDuration::seconds(1);
				let mut batch = w.batch(&secp, m)?;
				duplicate.id = batch.next_tx_log_id(&duplicate.parent_key_id)?;
				duplicate_id = duplicate.id;
				batch.save_tx_log_entry(duplicate, &tx.parent_key_id)?;
				batch.commit()?;
			}

			// Reproduce the legacy partial state by cancelling only one numeric ID.
			{
				wallet_lock!(api.wallet_inst, w);
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&tx.parent_key_id),
					Some(tx.id),
					None,
				)?;
			}
			let (_, _, partial) = api.retrieve_txs(m, false, None, Some(slate.id), None, None)?;
			assert!(
				partial
					.iter()
					.find(|entry| entry.id == tx.id)
					.unwrap()
					.is_cancelled()
			);
			assert!(
				!partial
					.iter()
					.find(|entry| entry.id == duplicate_id)
					.unwrap()
					.is_cancelled()
			);

			// Slate-scoped cancellation skips the completed member and repairs the
			// remaining member atomically.
			{
				wallet_lock!(api.wallet_inst, w);
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&tx.parent_key_id),
					None,
					Some(slate.id),
				)?;
			}
			let (_, _, repaired) = api.retrieve_txs(m, false, None, Some(slate.id), None, None)?;
			assert!(repaired.iter().all(|entry| entry.is_cancelled()));

			{
				wallet_lock!(api.wallet_inst, w);
				mwc_wallet_libwallet::internal::tx::cancel_tx(
					&mut **w,
					&secp,
					m,
					Some(&tx.parent_key_id),
					None,
					Some(slate.id),
				)?;
			}
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// TTL cleanup must select all entries sharing a slate and use the aggregate
/// cancellation batch. The oversized later entry forces staging to fail; no
/// earlier entry or output unlock may survive that failed group cancellation.
fn ttl_cancel_matching_entries_is_atomic_on_staging_error(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	let (proxy_handle, chain, wallet1, mask1_i, slate) = send_and_lock(test_dir)?;
	let mask1 = (&mask1_i).as_ref();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let (tx_id, duplicate_id, locked_before) = mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			// Establish a scan baseline before advancing the chain below.
			let (_, _, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
			let mut tx = txs[0].clone();
			let locked_before = api
				.retrieve_outputs(m, false, false, Some(tx.id))?
				.2
				.iter()
				.filter(|output| output.output.status == OutputStatus::Locked)
				.count();
			assert!(locked_before > 0);

			let duplicate_id;
			{
				wallet_lock!(api.wallet_inst, w);
				tx.ttl_cutoff_height = Some(1);
				let mut duplicate = tx.clone();
				duplicate.tx_type = TxLogEntryType::TxReceived;
				duplicate.creation_ts += ChronoDuration::seconds(1);

				let mut batch = w.batch(&secp, m)?;
				duplicate.id = batch.next_tx_log_id(&duplicate.parent_key_id)?;
				duplicate_id = duplicate.id;
				duplicate.address = Some(String::new());
				let unpadded_len = serde_json::to_vec(&duplicate).unwrap().len();
				assert!(unpadded_len < ser::READ_CHUNK_LIMIT);
				duplicate.address = Some("x".repeat(ser::READ_CHUNK_LIMIT - unpadded_len));
				assert_eq!(
					serde_json::to_vec(&duplicate).unwrap().len(),
					ser::READ_CHUNK_LIMIT
				);

				let mut cancelled = duplicate.clone();
				cancelled.tx_type = TxLogEntryType::TxReceivedCancelled;
				assert!(serde_json::to_vec(&cancelled).unwrap().len() > ser::READ_CHUNK_LIMIT);
				batch.save_tx_log_entry(tx.clone(), &tx.parent_key_id)?;
				batch.save_tx_log_entry(duplicate, &tx.parent_key_id)?;
				batch.commit()?;
			}
			Ok((tx.id, duplicate_id, locked_before))
		},
	)?;

	// Force a scan at a new tip; both synthetic entries are already TTL-expired.
	test_framework::award_block_to_wallet(&chain, &[], wallet1.clone(), mask1)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None, None)?;
			let tx_after = txs.iter().find(|entry| entry.id == tx_id).unwrap();
			let duplicate_after = txs.iter().find(|entry| entry.id == duplicate_id).unwrap();
			assert_eq!(tx_after.tx_type, TxLogEntryType::TxSent);
			assert_eq!(duplicate_after.tx_type, TxLogEntryType::TxReceived);

			let locked_after = api
				.retrieve_outputs(m, false, false, Some(tx_id))?
				.2
				.iter()
				.filter(|output| output.output.status == OutputStatus::Locked)
				.count();
			assert_eq!(locked_before, locked_after);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn db_cancel_with_uncached_commits() {
	let test_dir = "test_output/cancel_with_uncached_commits";
	setup(test_dir);
	if let Err(e) = cancel_with_uncached_commits(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_cancel_rejects_unresolvable_inputs() {
	let test_dir = "test_output/cancel_rejects_unresolvable_inputs";
	setup(test_dir);
	if let Err(e) = cancel_rejects_unresolvable_inputs(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_cancel_rejects_output_locked_by_another_transaction() {
	let test_dir = "test_output/cancel_rejects_other_lock_owner";
	setup(test_dir);
	if let Err(e) = cancel_rejects_output_locked_by_another_transaction(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_cancel_preserves_reverted_output_owned_by_another_transaction() {
	let test_dir = "test_output/cancel_preserves_other_reverted_owner";
	setup(test_dir);
	if let Err(e) = cancel_preserves_reverted_output_owned_by_another_transaction(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_cancel_matching_entries_is_atomic_on_staging_error() {
	let test_dir = "test_output/cancel_matching_entries_atomic";
	setup(test_dir);
	if let Err(e) = cancel_matching_entries_is_atomic_on_staging_error(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_cancel_partial_slate_group_repairs_remaining() {
	let test_dir = "test_output/cancel_partial_slate_group_repair";
	setup(test_dir);
	if let Err(e) = cancel_partial_slate_group_repairs_remaining(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_ttl_cancel_matching_entries_is_atomic_on_staging_error() {
	let test_dir = "test_output/ttl_cancel_matching_entries_atomic";
	setup(test_dir);
	if let Err(e) = ttl_cancel_matching_entries_is_atomic_on_staging_error(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
