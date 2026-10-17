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

//! Shared constructor for the replay-attack mitigation integration tests.
//!
//! # The replay attack
//!
//! With compact (late-lock) slates a malicious sender can keep the receiver's
//! response slate and finalize it more than once. The receiver output — its
//! Pedersen commitment and its rangeproof — is fully determined by the
//! receiver's response, while late locking lets the sender select fresh inputs
//! and change at every finalization. Posting the second finalized transaction
//! therefore recreates the receiver's already-spent output on chain: the
//! commitment returns to the UTXO set even though a confirmed transaction has
//! consumed it. Without mitigation the wallet treats the resurrected output as
//! a new, never-spent payment.
//!
//! # The mitigation under test
//!
//! The wallet scan detects the resurrected output through two independent
//! paths and then defensively self-spends it, so the funds are consolidated
//! into a fresh output and the replayed commitment is destroyed:
//!
//! * Transaction history (`replay_attack_scan.rs`): a currently unspent chain
//!   output whose commitment already appears among the inputs of a wallet
//!   transaction that is still confirmed on chain is a replay. This path does
//!   not use the two-day rangeproof-height tolerance.
//! * Rangeproof build height (`replay_attack_restore.rs`): the receiver tags
//!   its rangeproof with the height at which the output was built. A wallet
//!   restored from the seed has no transaction history, so a large gap between
//!   the tagged build height and the on-chain inclusion height is the replay
//!   signal.
//!
//! # Node trust model
//!
//! The inclusion height is reported by the configured node rather than
//! authenticated by the output rangeproof. This is an intentional trust
//! boundary: an MWC wallet is expected to use its owner's trusted private node
//! as the authoritative view of the chain. Consequently, a suspicious height
//! gap is allowed to trigger a signed, fee-bearing defensive self-spend. Without
//! that rule, a seed-restored wallet has no transaction history and would not
//! react automatically to a replay. Connecting to an untrusted node can provoke
//! unnecessary self-spends and is outside this mitigation's threat model.
//!
//! The two bugs fixed by the production change were (1) compact-slate
//! reconstruction dropping the anti-replay height tag from the receiver
//! output, and (2) the mitigation trying to self-spend a candidate that a
//! seed-restored wallet had not yet persisted, which failed with insufficient
//! funds. The restored output and its recovery transaction are now committed
//! before the self-spend is constructed, and the self-spend transaction itself
//! is persisted/locked before it is broadcast.
//!
//! This module builds a real attack on the local test chain. The two test
//! files share it and differ only in which wallet is scanned and which
//! detection path must fire.

use mwc_wallet_impls::DefaultLCProvider;
use mwc_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxyHandle};
use mwc_wallet_libwallet::{
	Context, InitTxArgs, OutputData, OutputStatus, Slate, StoredTxLocator, TxLogEntryType,
	WalletInst,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core::core::hash::Hashed;
use mwc_wallet_util::mwc_core::core::{Committed, Transaction};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::ExtKeychain;
use mwc_wallet_util::mwc_util::ZeroingString;
use std::ops::DerefMut;
use std::sync::Arc;

/// Wallet instance handle used by the controller integration tests.
pub type WalletArc = Arc<
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

/// Fixed victim seed. The restoration wallet is created from the same
/// mnemonic, which is what makes the seed-restore replay scenario possible.
#[cfg(feature = "test-support")]
const VICTIM_MNEMONIC: &str = "affair pistol cancel crush garment candy ancient flag work \
                               market crush dry stand focus mutual weapon offer ceiling rival \
                               turn team spring where swift";

/// Which replay-detection path the constructed scenario must exercise.
/// Each variant is exercised by one of the two replay test binaries.
#[allow(dead_code)]
pub enum ReplayDetection {
	/// The scanned wallet keeps its output and transaction history; history
	/// alone must detect the replay (no rangeproof-height tolerance).
	TransactionHistory,
	/// The scanned wallet is recreated from the seed with no records; the
	/// rangeproof build height must detect the replay.
	SeedRestore,
}

/// Everything a replay-attack test needs after the attack has been mined.
/// The two replay test binaries each read a different subset of the fields.
#[allow(dead_code)]
pub struct ReplayFixture {
	/// Posted transactions waiting to be mined.
	pub tx_pool: Arc<Mutex<Vec<Transaction>>>,
	/// The local test chain.
	pub chain: Arc<Chain>,
	/// Handle of the wallet proxy thread; stop it at the end of the test.
	pub proxy_handle: WalletProxyHandle,
	/// Attacker wallet (sender of the original and the replayed transaction).
	pub sender_wallet: WalletArc,
	/// Attacker wallet mask.
	pub sender_mask: Option<SecretKey>,
	/// Victim wallet (receiver of the replayed output).
	pub victim_wallet: WalletArc,
	/// Victim wallet mask.
	pub victim_mask: Option<SecretKey>,
	/// Wallet recreated from the victim's seed with no records. Only created
	/// for [`ReplayDetection::SeedRestore`].
	pub restored_wallet: Option<WalletArc>,
	/// Restored wallet mask.
	pub restored_mask: Option<SecretKey>,
	/// Commitment of the replayed receiver output ("B").
	pub replayed_commit: Commitment,
}

/// Build a real replay attack on the local test chain.
///
/// After this function returns, the chain contains the replayed transaction:
/// the victim's receiver output `replayed_commit` was created by the original
/// transaction, legitimately spent by the victim, and then recreated by the
/// attacker. The mitigation has NOT run yet; that is what the test files do.
#[cfg(feature = "test-support")]
pub fn build_replay(
	test_dir: &str,
	detection: ReplayDetection,
) -> Result<ReplayFixture, mwc_wallet_controller::Error> {
	// The node-level replay protection (pipe::replay_attack_check) rejects
	// blocks that recreate a spent output once headers reach version 3. On
	// Mainnet/Floonet that version is not active yet, but the AutomatedTesting
	// chain used here reaches it at height 6, while coinbase maturity makes it
	// impossible to mine create -> spend -> recreate below that height. The
	// wallet-level mitigation is what these tests exercise, so the node check
	// is disabled on this thread (the thread that processes the test blocks);
	// production behavior is unchanged.
	mwc_wallet_util::mwc_core::global::set_local_replay_protection_enabled(false);

	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = super::create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let victim_mnemonic = Some(ZeroingString::from(VICTIM_MNEMONIC));

	// Attacker/sender wallet, funded by mining.
	let sender_client = LocalWalletClient::new("sender", wallet_proxy.tx.clone());
	let (sender_wallet, sender_mask) =
		super::create_local_wallet(test_dir, "sender", None, sender_client.clone(), false);
	wallet_proxy.add_wallet(
		"sender",
		sender_client.get_send_instance(),
		sender_wallet.clone(),
		sender_mask.clone(),
	);

	// Victim wallet with a fixed seed so it can later be recreated.
	let victim_client = LocalWalletClient::new("victim", wallet_proxy.tx.clone());
	let (victim_wallet, victim_mask) = super::create_local_wallet(
		test_dir,
		"victim",
		victim_mnemonic.clone(),
		victim_client.clone(),
		false,
	);
	wallet_proxy.add_wallet(
		"victim",
		victim_client.get_send_instance(),
		victim_wallet.clone(),
		victim_mask.clone(),
	);

	// For the seed-restore scenario, a second copy of the victim wallet is
	// created from the same seed. It is registered with the proxy but never
	// refreshed or scanned until the mitigation, so it keeps no output or
	// transaction records.
	let (restored_wallet, restored_mask) = match detection {
		ReplayDetection::SeedRestore => {
			let restored_client = LocalWalletClient::new("restored", wallet_proxy.tx.clone());
			let (wallet, mask) = super::create_local_wallet(
				test_dir,
				"restored",
				victim_mnemonic.clone(),
				restored_client.clone(),
				false,
			);
			wallet_proxy.add_wallet(
				"restored",
				restored_client.get_send_instance(),
				wallet.clone(),
				mask.clone(),
			);
			(Some(wallet), mask)
		}
		ReplayDetection::TransactionHistory => (None, None),
	};

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let amount = 1_000_000_000;

	// Fund the attacker.
	test_framework::award_blocks_to_wallet(
		&chain,
		sender_wallet.clone(),
		(&sender_mask).as_ref(),
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// Refresh the victim before it receives anything. The receiver output's
	// rangeproof is tagged with the wallet's last confirmed height when it is
	// built; it must be nonzero so the build height can later be compared with
	// the on-chain inclusion height.
	mwc_wallet_controller::controller::owner_single_use(
		Some(victim_wallet.clone()),
		(&victim_mask).as_ref(),
		None,
		|api, m| {
			let (victim_refreshed, victim_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(victim_refreshed);
			assert!(victim_info.last_confirmed_height > 0);
			Ok(())
		},
	)?;

	// The attacker creates a compact V4 slate with late locking. Late locking
	// defers input/change selection to finalization, which is exactly what
	// makes the replay possible: the receiver's response stays valid while the
	// sender side of the transaction is rebuilt.
	let args = InitTxArgs {
		src_acct_name: None,
		amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		target_slate_version: Some(4),
		late_lock: Some(true),
		..Default::default()
	};
	let slate_s1 = mwc_wallet_controller::controller::owner_single_use(
		Some(sender_wallet.clone()),
		(&sender_mask).as_ref(),
		None,
		|api, m| Ok(api.init_send_tx(m, None, &args, 1)?),
	)?;

	// The victim receives the slate, creating receiver output B. For a compact
	// slate the response carries exactly the receiver output and nothing else.
	let slate_s2 = sender_client.send_tx_slate_direct("victim", &slate_s1)?;
	let s2_outputs: Vec<Commitment> = slate_s2
		.tx_or_err()?
		.outputs()
		.iter()
		.map(|o| o.commitment())
		.collect();
	assert_eq!(s2_outputs.len(), 1);
	let replayed_commit = s2_outputs[0];

	// Clone the sender's private context BEFORE the first finalization. It
	// still carries the late-lock arguments and the sender's partial nonce and
	// excess, so re-saving it under a fresh slate id replays the finalization
	// with fresh inputs/change while keeping the receiver's partial signature
	// and output valid.
	let sender_context: Context = {
		let mut w_lock = sender_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		w.get_private_context(&secp, (&sender_mask).as_ref(), slate_s1.id.as_bytes(), 0)?
	};

	// Finalize, post and mine the honest transaction.
	let finalized1: Slate = mwc_wallet_controller::controller::owner_single_use(
		Some(sender_wallet.clone()),
		(&sender_mask).as_ref(),
		None,
		|api, m| {
			let slate = api.finalize_tx(m, None, &slate_s2, true)?;
			api.post_tx(m, slate.tx_or_err()?, true)?;
			Ok(slate)
		},
	)?;
	let tx1 = finalized1.tx_or_err()?.clone();

	test_framework::award_blocks_to_wallet(
		&chain,
		sender_wallet.clone(),
		(&sender_mask).as_ref(),
		2,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// Refresh the victim and locate B by its commitment.
	let output_b: OutputData = mwc_wallet_controller::controller::owner_single_use(
		Some(victim_wallet.clone()),
		(&victim_mask).as_ref(),
		None,
		|api, m| {
			let (victim_refreshed, _) = api.retrieve_summary_info(m, true, 1)?;
			assert!(victim_refreshed);
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			let output_b = outputs
				.iter()
				.find(|mapping| mapping.commit == replayed_commit)
				.map(|mapping| mapping.output.clone())
				.ok_or(mwc_wallet_libwallet::Error::GenericError(
					"replay test internal error, receiver output not found".into(),
				))?;
			assert_eq!(output_b.status, OutputStatus::Unspent);
			Ok(output_b)
		},
	)?;

	// The victim legitimately spends B. After this is mined and refreshed, the
	// victim's transaction history contains a confirmed transaction consuming
	// B, which is what the history-based detection relies on.
	let output_b_commit = output_b.commit.clone().ok_or_else(|| {
		mwc_wallet_libwallet::Error::GenericError(
			"replay test internal error, receiver output commitment is missing".into(),
		)
	})?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(victim_wallet.clone()),
		(&victim_mask).as_ref(),
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: output_b.value,
				amount_includes_fee: Some(true),
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 0,
				selection_strategy_is_use_all: true,
				outputs: Some(std::collections::HashSet::from([output_b_commit.clone()])),
				ttl_blocks: None,
				..Default::default()
			};
			let mut slate = api.init_send_tx(m, None, &args, 1)?;
			slate = victim_client.send_tx_slate_direct("victim", &slate)?;
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			slate = api.finalize_tx(m, None, &slate, true)?;
			api.post_tx(m, slate.tx_or_err()?, false)?;
			Ok(())
		},
	)?;

	test_framework::award_blocks_to_wallet(
		&chain,
		sender_wallet.clone(),
		(&sender_mask).as_ref(),
		2,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(victim_wallet.clone()),
		(&victim_mask).as_ref(),
		None,
		|api, m| {
			let (victim_refreshed, _) = api.retrieve_summary_info(m, true, 1)?;
			assert!(victim_refreshed);
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			assert!(
				txs.iter().any(|t| t.tx_type == TxLogEntryType::TxSent
					&& t.confirmed && t.input_commits.contains(&replayed_commit)),
				"victim history must record a confirmed transaction consuming the replayed output"
			);
			Ok(())
		},
	)?;

	// Now the attacker replays. Clone the original response slate, assign it a
	// fresh UUID (the slate UUID is not transaction-signature material, so the
	// receiver's partial signature stays valid) and save the cloned original
	// late-lock context under that UUID.
	let mut replay_slate = slate_s2.clone();
	replay_slate.id = Uuid::new_v4();
	{
		let mut w_lock = sender_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let mut batch = w.batch(&secp, (&sender_mask).as_ref())?;
		batch.save_private_context(&secp, replay_slate.id.as_bytes(), 0, &sender_context)?;
		batch.commit()?;
	}

	// The normal online wallet must reject the replay before committing late
	// locks or consuming the context. A malicious sender can bypass its own
	// wallet checks, so construct the attack through offline finalization after
	// proving that the normal path refuses it.
	let replay_rejected = mwc_wallet_controller::controller::owner_single_use(
		Some(sender_wallet.clone()),
		(&sender_mask).as_ref(),
		None,
		|api, m| Ok(api.finalize_tx(m, None, &replay_slate, true)?),
	)
	.expect_err("online finalization must reject a replayed output");
	assert!(
		replay_rejected
			.to_string()
			.contains("preflight rejected: transaction 0 replay:"),
		"unexpected replay finalization error: {replay_rejected}"
	);
	let finalized2 = {
		let mut w_lock = sender_wallet.lock();
		let lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let context = w.get_private_context(
			&secp,
			(&sender_mask).as_ref(),
			replay_slate.id.as_bytes(),
			0,
		)?;
		assert!(context.late_lock_args.is_some());
		assert!(w
			.tx_log_iter()?
			.all(|tx| tx.tx_slate_id != Some(replay_slate.id)));
		let (slate, _) = mwc_wallet_libwallet::api_impl::owner::finalize_tx(
			&mut **w,
			&mut secp,
			(&sender_mask).as_ref(),
			&mut None,
			&replay_slate,
			false,
			false,
			true,
		)?;
		slate
	};
	let tx2 = finalized2.tx_or_err()?.clone();

	// The replay must carry the very same receiver commitment and rangeproof
	// as the honest transaction. That is the essence of the attack.
	let b_original = tx1
		.outputs()
		.iter()
		.find(|o| o.commitment() == replayed_commit)
		.expect("original transaction must contain the receiver output");
	let b_replayed = tx2
		.outputs()
		.iter()
		.find(|o| o.commitment() == replayed_commit)
		.expect("replayed transaction must contain the identical receiver output");
	assert_eq!(b_original, b_replayed);
	// ... while the late locking selected fresh sender inputs, so the two
	// transactions spend different inputs. (The reused context keeps the same
	// sender partial nonce and excess, so the kernel itself is identical —
	// only the input/output set and the offset change.)
	let tx1_inputs: Vec<Commitment> = tx1
		.inputs_committed()
		.map_err(mwc_wallet_libwallet::Error::from)?
		.map(|c| c.map_err(mwc_wallet_libwallet::Error::from))
		.collect::<Result<Vec<_>, _>>()?;
	let tx2_inputs: Vec<Commitment> = tx2
		.inputs_committed()
		.map_err(mwc_wallet_libwallet::Error::from)?
		.map(|c| c.map_err(mwc_wallet_libwallet::Error::from))
		.collect::<Result<Vec<_>, _>>()?;
	assert!(
		!tx1_inputs.is_empty()
			&& !tx2_inputs.is_empty()
			&& !tx2_inputs.iter().any(|c| tx1_inputs.contains(c)),
		"the replay must spend fresh sender inputs"
	);

	// Posting also checks the unsigned transaction and refuses the replay.
	let post_rejected = mwc_wallet_controller::controller::owner_single_use(
		Some(sender_wallet.clone()),
		(&sender_mask).as_ref(),
		None,
		|api, m| {
			api.post_tx(m, &tx2, true)?;
			Ok(())
		},
	)
	.expect_err("posting must reject a replayed output");
	assert!(
		post_rejected
			.to_string()
			.contains("preflight rejected: transaction 0 replay:"),
		"unexpected replay publication error: {post_rejected}"
	);
	assert!(tx_pool.lock().is_empty());

	// Inject only into this test's mining queue. Block replay protection is
	// disabled above so scanning can still exercise recovery from a replay
	// already on chain, independent of the new wallet publication checks.
	tx_pool.lock().push(tx2);

	test_framework::award_blocks_to_wallet(
		&chain,
		sender_wallet.clone(),
		(&sender_mask).as_ref(),
		2,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	// Sanity: the replayed commitment is once again unspent on chain.
	assert!(
		chain
			.get_unspent(replayed_commit)
			.expect("chain get_unspent failed")
			.is_some(),
		"the replay must return the spent commitment to the UTXO set"
	);

	Ok(ReplayFixture {
		tx_pool,
		chain,
		proxy_handle,
		sender_wallet,
		sender_mask,
		victim_wallet,
		victim_mask,
		restored_wallet,
		restored_mask,
		replayed_commit,
	})
}

/// Verify that a second scan leaves the ordinary pending self-send alone.
/// The scan must not repost it, create a replacement transaction, or create
/// another transaction log while its replay input remains locked.
#[cfg(feature = "test-support")]
pub fn assert_defensive_self_spend_is_created_once(
	fixture: &ReplayFixture,
	wallet: &WalletArc,
	mask: Option<&SecretKey>,
) -> Result<(), mwc_wallet_controller::Error> {
	let first_transaction = {
		let pool = fixture.tx_pool.lock();
		assert_eq!(
			pool.len(),
			1,
			"the first mitigation scan must post one defensive transaction"
		);
		pool[0].clone()
	};
	let context_id = fixture.chain.get_context_id();
	let first_kernel_hash = first_transaction.kernels()[0]
		.hash(context_id)
		.expect("the posted defensive transaction kernel must hash");

	let (first_slate_id, first_log_id) = mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let defensive_senders: Vec<_> = txs
				.iter()
				.filter(|tx| {
					tx.tx_type == TxLogEntryType::TxSent
						&& tx.input_commits.contains(&fixture.replayed_commit)
				})
				.collect();
			assert_eq!(
				defensive_senders.len(),
				1,
				"the first scan must persist exactly one normal sender record for the replay input"
			);
			let sender = defensive_senders[0];
			assert_eq!(
				sender.ttl_cutoff_height, None,
				"defensive transactions must never carry a TTL"
			);
			let stored = api
				.get_stored_tx(m, &StoredTxLocator::from(sender))?
				.expect("the defensive transaction must be stored before posting");
			assert_eq!(
				stored.kernels()[0]
					.hash(context_id)
					.expect("the stored defensive transaction kernel must hash"),
				first_kernel_hash,
				"the normal transaction record must contain the transaction submitted to the node"
			);
			Ok((
				sender
					.tx_slate_id
					.expect("defensive transaction must have a slate id"),
				sender.id,
			))
		},
	)?;

	// Leave the transaction unmined and scan the same replay again, including
	// the ordinary bulk cleanup requested by restore scans.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			api.scan(m, None, None, true)?;
			Ok(())
		},
	)?;

	{
		let pool = fixture.tx_pool.lock();
		assert_eq!(
			pool.len(),
			1,
			"a repeated scan must neither repost nor replace the pending self-send"
		);
		assert_eq!(
			pool[0].kernels()[0]
				.hash(context_id)
				.expect("the pending defensive transaction kernel must hash"),
			first_kernel_hash,
			"the repeated scan must leave the original transaction in the pool"
		);
	}

	let replay_height = mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let defensive_senders: Vec<_> = txs
				.iter()
				.filter(|tx| {
					tx.tx_type == TxLogEntryType::TxSent
						&& tx.input_commits.contains(&fixture.replayed_commit)
				})
				.collect();
			assert_eq!(
				defensive_senders.len(),
				1,
				"a repeated scan must retain one defensive sender record"
			);
			let sender = defensive_senders[0];
			assert_eq!(sender.tx_slate_id, Some(first_slate_id));
			assert_eq!(sender.id, first_log_id);
			assert_eq!(sender.ttl_cutoff_height, None);
			let stored = api
				.get_stored_tx(m, &StoredTxLocator::from(sender))?
				.expect("the normal transaction must remain available for repost");
			assert_eq!(
				stored.kernels()[0]
					.hash(context_id)
					.expect("the stored defensive transaction kernel must hash"),
				first_kernel_hash
			);

			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;
			let replayed = outputs
				.iter()
				.find(|mapping| mapping.commit == fixture.replayed_commit)
				.expect("wallet must retain the replayed output");
			assert_eq!(replayed.output.status, OutputStatus::Locked);
			assert_eq!(replayed.output.tx_log_entry, Some(first_log_id));
			Ok(replayed.output.height)
		},
	)?;

	let saved_scan_height = {
		let mut wallet_lock = wallet.lock();
		let lc = wallet_lock.lc_provider()?;
		let wallet = lc.wallet_inst()?;
		wallet
			.last_scanned_blocks()?
			.first()
			.map(|block| block.height)
			.expect("a completed scan must save a scan cursor")
	};
	assert_eq!(
		saved_scan_height,
		replay_height.saturating_sub(1),
		"the scan cursor must remain immediately before the unresolved replay output"
	);

	Ok(())
}

/// Cancel the pending replay self-spend, then use an ordinary incremental
/// refresh at the unchanged chain tip. The pinned scan cursor must rediscover
/// the replayed commitment and create a new normal self-spend.
#[cfg(feature = "test-support")]
pub fn assert_cancelled_defensive_self_spend_is_recreated(
	fixture: &ReplayFixture,
	wallet: &WalletArc,
	mask: Option<&SecretKey>,
) -> Result<(), mwc_wallet_controller::Error> {
	let context_id = fixture.chain.get_context_id();
	let original_tx = {
		let pool = fixture.tx_pool.lock();
		assert_eq!(pool.len(), 1, "one defensive transaction must be pending");
		pool[0].clone()
	};
	let original_kernel_hash = original_tx.kernels()[0]
		.hash(context_id)
		.expect("the original defensive transaction kernel must hash");

	let original_slate_id = mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let sender = txs
				.iter()
				.find(|tx| {
					tx.tx_type == TxLogEntryType::TxSent
						&& !tx.confirmed && !tx.is_cancelled_reverted()
						&& tx.input_commits.contains(&fixture.replayed_commit)
				})
				.expect("the original defensive sender record must be active");
			Ok(sender
				.tx_slate_id
				.expect("the original defensive transaction must have a slate id"))
		},
	)?;

	// cancel_tx refreshes first. While the old transaction is still active that
	// refresh must preserve it; cancellation then releases its input lock.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			api.cancel_tx(m, None, Some(original_slate_id))?;
			Ok(())
		},
	)?;

	// The local test node uses this vector as its pending pool and has no mempool
	// cancellation API. Remove the cancelled submission before observing the
	// replacement that the wallet posts during the next ordinary refresh.
	fixture.tx_pool.lock().clear();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (refreshed, _) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			Ok(())
		},
	)?;

	let replacement_tx = {
		let pool = fixture.tx_pool.lock();
		assert_eq!(
			pool.len(),
			1,
			"an ordinary refresh must post one replacement after cancellation"
		);
		pool[0].clone()
	};
	let replacement_kernel_hash = replacement_tx.kernels()[0]
		.hash(context_id)
		.expect("the replacement defensive transaction kernel must hash");
	assert_ne!(
		replacement_kernel_hash, original_kernel_hash,
		"cancellation must result in a newly constructed transaction"
	);

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let original = txs
				.iter()
				.find(|tx| {
					tx.tx_slate_id == Some(original_slate_id)
						&& tx.input_commits.contains(&fixture.replayed_commit)
				})
				.expect("the cancelled defensive sender record must remain visible");
			assert!(original.is_cancelled_reverted());

			let active_senders: Vec<_> = txs
				.iter()
				.filter(|tx| {
					tx.tx_type == TxLogEntryType::TxSent
						&& !tx.confirmed && !tx.is_cancelled_reverted()
						&& tx.input_commits.contains(&fixture.replayed_commit)
				})
				.collect();
			assert_eq!(
				active_senders.len(),
				1,
				"exactly one replacement defensive sender must be active"
			);
			let replacement = active_senders[0];
			assert_ne!(replacement.tx_slate_id, Some(original_slate_id));
			let stored = api
				.get_stored_tx(m, &StoredTxLocator::from(replacement))?
				.expect("the replacement transaction must be saved before posting");
			assert_eq!(
				stored.kernels()[0]
					.hash(context_id)
					.expect("the stored replacement kernel must hash"),
				replacement_kernel_hash
			);

			let (_, _, outputs) = api.retrieve_outputs(m, false, false, None)?;
			let replayed = outputs
				.iter()
				.find(|mapping| mapping.commit == fixture.replayed_commit)
				.expect("the replayed output must remain in the wallet");
			assert_eq!(replayed.output.status, OutputStatus::Locked);
			assert_eq!(replayed.output.tx_log_entry, Some(replacement.id));
			Ok(())
		},
	)?;

	Ok(())
}

/// Verify the defensive self-spend that the mitigation scan must have posted.
///
/// This checks the full lifecycle required from the mitigation: the defensive
/// transaction enters the test transaction pool with the replayed commitment
/// as its input, is mined, is accepted by the wallet refresh, and leaves the
/// replayed output Spent, the new self-spend output confirmed and Unspent, and
/// a confirmed wallet transaction record.
#[cfg(feature = "test-support")]
pub fn assert_defensive_self_spend_lifecycle(
	fixture: &ReplayFixture,
	wallet: &WalletArc,
	mask: Option<&SecretKey>,
) -> Result<(), mwc_wallet_controller::Error> {
	// The mitigation scan must have posted exactly one defensive transaction,
	// and it must spend the replayed commitment.
	let defensive_tx: Transaction = {
		let pool = fixture.tx_pool.lock();
		assert_eq!(
			pool.len(),
			1,
			"the mitigation scan must post exactly one defensive self-spend transaction"
		);
		pool[0].clone()
	};
	let defensive_inputs: Vec<Commitment> = defensive_tx
		.inputs_committed()
		.map_err(mwc_wallet_libwallet::Error::from)?
		.map(|c| c.map_err(mwc_wallet_libwallet::Error::from))
		.collect::<Result<Vec<_>, _>>()?;
	assert!(
		defensive_inputs.contains(&fixture.replayed_commit),
		"the defensive self-spend must use the replayed commitment as an input"
	);
	assert_eq!(
		defensive_tx.outputs().len(),
		1,
		"the defensive self-spend must produce a single output (amount minus fee, no change)"
	);
	let defensive_output_commit = defensive_tx.outputs()[0].commitment();
	let defensive_kernel = defensive_tx.kernels()[0].excess;

	// Mine the defensive transaction.
	test_framework::award_blocks_to_wallet(
		&fixture.chain,
		fixture.sender_wallet.clone(),
		(&fixture.sender_mask).as_ref(),
		2,
		false,
		fixture.tx_pool.lock().deref_mut(),
	)?;

	// The wallet must accept it on refresh, the replayed commitment must be
	// gone from the UTXO set, and the new output must be confirmed.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (refreshed, _) = api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			Ok(())
		},
	)?;

	assert!(
		fixture
			.chain
			.get_unspent(fixture.replayed_commit)
			.expect("chain get_unspent failed")
			.is_none(),
		"the defensive self-spend must remove the replayed commitment from the UTXO set"
	);
	assert!(
		fixture
			.chain
			.get_unspent(defensive_output_commit)
			.expect("chain get_unspent failed")
			.is_some(),
		"the defensive self-spend output must be unspent on chain"
	);

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, None)?;

			// The replayed output is Spent in the wallet records.
			let replayed = outputs
				.iter()
				.find(|mapping| mapping.commit == fixture.replayed_commit)
				.expect("wallet must retain a record of the replayed output");
			assert_eq!(
				replayed.output.status,
				OutputStatus::Spent,
				"the replayed output must be Spent after the defensive self-spend"
			);

			// The new self-spend output is confirmed and Unspent.
			let defensive = outputs
				.iter()
				.find(|mapping| mapping.commit == defensive_output_commit)
				.expect("wallet must contain the defensive self-spend output");
			assert_eq!(
				defensive.output.status,
				OutputStatus::Unspent,
				"the defensive self-spend output must be confirmed and Unspent"
			);

			// A confirmed wallet transaction record exists for the defensive
			// self-spend, consuming the replayed commitment, with the kernel of
			// the transaction that was just mined.
			let (_, _, txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			assert!(
				txs.iter().any(|t| t.tx_type == TxLogEntryType::TxSent
					&& t.confirmed && t
					.input_commits
					.contains(&fixture.replayed_commit)
					&& t.kernel_excess == Some(defensive_kernel)),
				"a confirmed TxSent for the defensive self-spend must exist"
			);
			Ok(())
		},
	)?;

	let saved_scan_height = {
		let mut wallet_lock = wallet.lock();
		let lc = wallet_lock.lc_provider()?;
		let wallet = lc.wallet_inst()?;
		wallet
			.last_scanned_blocks()?
			.first()
			.map(|block| block.height)
			.expect("a confirmed refresh must save a scan cursor")
	};
	assert_eq!(
		saved_scan_height,
		fixture
			.chain
			.head()
			.expect("the test chain head must be available")
			.height,
		"the scan cursor must advance to the tip after the replay input is spent"
	);

	Ok(())
}
