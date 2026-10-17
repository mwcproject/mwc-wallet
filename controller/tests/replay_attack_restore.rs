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

//! Replay-attack mitigation after a seed restoration.
//!
//! The scenario is the same replay as in `replay_attack_scan.rs` (see
//! `tests/common/replay.rs`), but the mitigated wallet is recreated from the
//! victim's seed and therefore has no output or transaction records. History
//! cannot help here; the replay must be detected from the rangeproof build
//! height: the height tagged into the receiver output when it was built is far
//! below the height at which the replayed copy was included.
//!
//! Mining a real two-day gap is impractical, so the test overrides the
//! detection gap with `set_replay_height_gap_for_tests` — the replayed output
//! is genuinely a few blocks old, which exercises exactly the same delayed
//! replay branch production would trigger after two nominal days.
//!
//! The scan must first restore the candidate (its `OutputData` plus the
//! recovery transaction record) and only then construct the self-spend;
//! constructing it first is the insufficient-funds bug being fixed.

#[cfg(feature = "test-support")]
#[macro_use]
mod common;
#[cfg(feature = "test-support")]
use common::replay::{
	assert_cancelled_defensive_self_spend_is_recreated,
	assert_defensive_self_spend_is_created_once, build_replay, ReplayDetection,
};
#[cfg(feature = "test-support")]
use common::{clean_output_dir, setup};
#[cfg(feature = "test-support")]
use mwc_wallet_libwallet::{OutputStatus, ReplayMitigationConfig};
#[cfg(feature = "test-support")]
use std::thread;
#[cfg(feature = "test-support")]
use std::time::Duration;

#[cfg(feature = "test-support")]
fn replay_attack_restore_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	// Build and mine the replay, and create a second copy of the victim
	// wallet from the same seed. That copy is never refreshed, so it has no
	// output or transaction records.
	let fixture = build_replay(test_dir, ReplayDetection::SeedRestore)?;
	let restored_wallet = fixture
		.restored_wallet
		.clone()
		.expect("restored wallet must exist for the seed-restore scenario");
	let restored_mask = fixture.restored_mask.clone();

	// Prove the recreated wallet starts empty.
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

	// Exercise the rangeproof build-height branch without mining two days of
	// blocks: the replayed output's build height is genuinely several blocks
	// below its inclusion height.
	mwc_wallet_libwallet::set_replay_height_gap_for_tests(1);
	mwc_wallet_libwallet::set_replay_config(
		0,
		ReplayMitigationConfig {
			replay_mitigation_flag: true,
			replay_mitigation_min_amount: 0,
			..Default::default()
		},
	);

	// Scan the restored wallet. The scan succeeds only if the replay candidate
	// was restored (output plus recovery transaction) before the defensive
	// self-spend was constructed; the old order failed with insufficient funds.
	mwc_wallet_controller::controller::owner_single_use(
		Some(restored_wallet.clone()),
		(&restored_mask).as_ref(),
		None,
		|api, m| {
			api.scan(m, None, None, true)?;
			Ok(())
		},
	)?;

	// Right after the scan, before anything is mined: the replayed output must
	// have been restored and locked by the defensive self-spend. This proves
	// the restore happened before transaction construction.
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

	// A second scan while the normal transaction is pending must preserve its
	// input lock without reposting it or constructing a replacement.
	assert_defensive_self_spend_is_created_once(
		&fixture,
		&restored_wallet,
		(&restored_mask).as_ref(),
	)?;

	// A user cancellation must be recoverable through an ordinary incremental
	// refresh, even when the chain tip has not moved since the prior scan.
	assert_cancelled_defensive_self_spend_is_recreated(
		&fixture,
		&restored_wallet,
		(&restored_mask).as_ref(),
	)?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	let chain = fixture.chain.clone();
	fixture.proxy_handle.stop()?;
	drop(chain);
	Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn replay_attack_restore() {
	let test_dir = "test_output/replay_attack_restore";
	setup(test_dir);
	if let Err(e) = replay_attack_restore_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
