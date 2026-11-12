// Copyright 2026 The MWC Developers
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

//! Replay-attack mitigation scan tests.
//!
//! A malicious sender finalizes a compact late-lock slate twice: the second
//! finalization keeps the receiver's output (commitment and rangeproof) while
//! replacing the sender's inputs and change. Once the replayed transaction is
//! mined, the receiver's commitment is back in the UTXO set even though a
//! still-confirmed transaction already consumed it (see
//! `tests/common/replay.rs` for the full scenario).
//!
//! The scanned wallet retains its output and transaction history here, so the
//! scan must detect the replay purely from that history: a currently unspent
//! commitment that was already consumed by a still-confirmed transaction. The
//! replay is only a few blocks old, far below the two-day rangeproof-height
//! threshold, which is explicitly kept at its production value — if the
//! mitigation fires, history detection triggered it.
//!
//! The second test scans the same replayed chain with a wallet that has no
//! transaction history at all (a fresh seed restoration). It lowers the
//! test-only rangeproof-height gap so the independent build-height detection
//! path must fire, restore the replay candidate, and post the same defensive
//! self-spend.

#[cfg(feature = "test-support")]
#[macro_use]
mod common;
#[cfg(feature = "test-support")]
use common::replay::{assert_defensive_self_spend_lifecycle, build_replay, ReplayDetection};
#[cfg(feature = "test-support")]
use common::{clean_output_dir, setup};
#[cfg(feature = "test-support")]
use mwc_wallet_libwallet::{OutputStatus, ReplayMitigationConfig, TxLogEntryType};
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
#[cfg(feature = "test-support")]
use std::sync::Mutex;
#[cfg(feature = "test-support")]
use std::thread;
#[cfg(feature = "test-support")]
use std::time::Duration;

#[cfg(feature = "test-support")]
static REPLAY_ATTACK_SCAN_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(feature = "test-support")]
struct ReplayHeightGapReset;

#[cfg(feature = "test-support")]
impl Drop for ReplayHeightGapReset {
	fn drop(&mut self) {
		mwc_wallet_libwallet::set_replay_height_gap_for_tests(2 * DAY_HEIGHT);
	}
}

#[cfg(feature = "test-support")]
fn replay_attack_scan_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	// Build and mine the replay. The victim wallet keeps all of its records.
	let fixture = build_replay(test_dir, ReplayDetection::TransactionHistory)?;

	// Move both account-local halves of the confirmed transaction that consumed
	// the replayed commitment into the transaction archive. The stored
	// transaction is shared by the self-send entries, so archiving only one half
	// would leave the other active entry as replay evidence and would not exercise
	// the archive path.
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	{
		let mut w_lock = fixture.victim_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let active_transactions: Vec<_> = w.tx_log_iter()?.collect();
		let spending_uuid = active_transactions
			.iter()
			.find(|tx| {
				tx.tx_type == TxLogEntryType::TxSent
					&& tx.confirmed && tx.input_commits.contains(&fixture.replayed_commit)
			})
			.and_then(|tx| tx.tx_slate_id)
			.ok_or_else(|| {
				mwc_wallet_libwallet::Error::GenericError(
					"replay test spending transaction has no slate id".to_owned(),
				)
			})?;
		let transactions_to_archive: Vec<_> = active_transactions
			.into_iter()
			.filter(|tx| tx.tx_slate_id == Some(spending_uuid))
			.collect();
		assert!(
			!transactions_to_archive.is_empty(),
			"the spending transaction must have account-local log entries"
		);
		let mut batch = w.batch(&secp, (&fixture.victim_mask).as_ref())?;
		for tx in &transactions_to_archive {
			batch.archive_transaction(tx)?;
		}
		batch.commit()?;
	}

	// Make a different account active. The replayed output still belongs to the
	// default account, and mitigation must select it from that derived parent
	// rather than from this active-account cursor.
	mwc_wallet_controller::controller::owner_single_use(
		Some(fixture.victim_wallet.clone()),
		(&fixture.victim_mask).as_ref(),
		None,
		|api, m| {
			api.create_account_path(m, "unrelated_active")?;
			api.set_active_account(m, "unrelated_active")?;
			Ok(())
		},
	)?;

	// Keep this history-detection test on the production two-day threshold even
	// if the height-path test ran first in this process.
	mwc_wallet_libwallet::set_replay_height_gap_for_tests(2 * DAY_HEIGHT);
	mwc_wallet_libwallet::set_replay_config(
		0,
		ReplayMitigationConfig {
			replay_mitigation_flag: true,
			replay_mitigation_min_amount: 0,
			..Default::default()
		},
	);

	// Scan the original victim wallet. History detection must spot the
	// replayed commitment and post the defensive self-spend.
	mwc_wallet_controller::controller::owner_single_use(
		Some(fixture.victim_wallet.clone()),
		(&fixture.victim_mask).as_ref(),
		None,
		|api, m| {
			api.scan(m, None, None, true)?;
			Ok(())
		},
	)?;

	// The lifecycle assertions query account-local output and transaction data.
	// Return the cursor to the account that owns the replayed commitment only
	// after the mitigation scan has proved it can operate independently of that
	// cursor.
	mwc_wallet_controller::controller::owner_single_use(
		Some(fixture.victim_wallet.clone()),
		(&fixture.victim_mask).as_ref(),
		None,
		|api, m| {
			api.set_active_account(m, "default")?;
			Ok(())
		},
	)?;

	// Prove the defensive self-spend enters the pool with the replayed
	// commitment as input, is mined, is accepted after refresh, leaves the
	// replayed output Spent and the new output confirmed and Unspent, and has
	// a confirmed transaction record.
	assert_defensive_self_spend_lifecycle(
		&fixture,
		&fixture.victim_wallet,
		(&fixture.victim_mask).as_ref(),
	)?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	let chain = fixture.chain.clone();
	fixture.proxy_handle.stop()?;
	drop(chain);
	Ok(())
}

/// Height-detection test: the same replayed chain, but the scanned wallet is a
/// fresh seed restoration with no output or transaction records. With no
/// history to match, the lowered test gap makes the rangeproof build height
/// detect the replay and trigger the defensive self-spend.
#[cfg(feature = "test-support")]
fn replay_attack_scan_without_history_impl(
	test_dir: &str,
) -> Result<(), mwc_wallet_controller::Error> {
	// Build and mine the same replay, and create a second copy of the victim
	// wallet from the same seed. That copy is never refreshed, so it has no
	// output or transaction records.
	let fixture = build_replay(test_dir, ReplayDetection::SeedRestore)?;
	let restored_wallet = fixture
		.restored_wallet
		.clone()
		.expect("restored wallet must exist for the seed-restore scenario");
	let restored_mask = fixture.restored_mask.clone();

	// Prove the recreated wallet starts with no output or transaction history.
	mwc_wallet_controller::controller::owner_single_use(
		Some(restored_wallet.clone()),
		(&restored_mask).as_ref(),
		None,
		|api, m| {
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(
				outputs.is_empty(),
				"restored wallet must have no output records before the scan"
			);
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			assert!(
				txs.is_empty(),
				"restored wallet must have no transaction records before the scan"
			);
			Ok(())
		},
	)?;

	// Exercise the rangeproof build-height branch without mining a full day.
	// The replayed output was built several blocks before its second inclusion,
	// so a one-block test gap is sufficient to classify it as suspicious.
	mwc_wallet_libwallet::set_replay_height_gap_for_tests(1);
	mwc_wallet_libwallet::set_replay_config(
		0,
		ReplayMitigationConfig {
			replay_mitigation_flag: true,
			replay_mitigation_min_amount: 0,
			..Default::default()
		},
	);

	// Scan the restored wallet. History detection has nothing to match, so the
	// rangeproof build-height path must restore the replay candidate and post
	// its defensive self-spend.
	mwc_wallet_controller::controller::owner_single_use(
		Some(restored_wallet.clone()),
		(&restored_mask).as_ref(),
		None,
		|api, m| {
			api.scan(m, None, None, true)?;
			Ok(())
		},
	)?;

	// The scan must restore the replayed output before constructing the
	// defensive transaction, which immediately locks that restored record.
	mwc_wallet_controller::controller::owner_single_use(
		Some(restored_wallet.clone()),
		(&restored_mask).as_ref(),
		None,
		|api, m| {
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			let replayed = outputs
				.iter()
				.find(|mapping| mapping.commit == fixture.replayed_commit)
				.expect("replayed candidate must have been restored during the scan");
			assert_eq!(
				replayed.output.status,
				OutputStatus::Locked,
				"replayed candidate must be restored first and locked by the defensive self-spend"
			);
			Ok(())
		},
	)?;

	// Prove the defensive self-spend is posted, mined, confirmed, and replaces
	// the replayed commitment with a fresh unspent output.
	assert_defensive_self_spend_lifecycle(&fixture, &restored_wallet, (&restored_mask).as_ref())?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	let chain = fixture.chain.clone();
	fixture.proxy_handle.stop()?;
	drop(chain);
	Ok(())
}

#[test]
#[cfg(feature = "test-support")]
fn replay_attack_scan() {
	let _test_guard = REPLAY_ATTACK_SCAN_TEST_LOCK
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	let _height_gap_reset = ReplayHeightGapReset;
	let test_dir = "test_output/replay_attack_scan";
	setup(test_dir);
	if let Err(e) = replay_attack_scan_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
#[cfg(feature = "test-support")]
fn replay_attack_scan_without_history() {
	let _test_guard = REPLAY_ATTACK_SCAN_TEST_LOCK
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	let _height_gap_reset = ReplayHeightGapReset;
	let test_dir = "test_output/replay_attack_scan_without_history";
	setup(test_dir);
	if let Err(e) = replay_attack_scan_without_history_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
