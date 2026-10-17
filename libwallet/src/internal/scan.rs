// Copyright 2019 The Grin Developers
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
//! Functions to restore a wallet's outputs from just the master seed

use crate::api_impl::foreign;
use crate::api_impl::owner;
use crate::api_impl::types::InitTxArgs;
use crate::internal::chain_session::NodeReadSession;
use crate::internal::tx;
use crate::internal::{keys, output_proof, updater};
use crate::status::{send_status, StatusCallback, StatusMessage};
use crate::types::*;
use crate::wallet_lock;
use crate::Error;
use crate::ReplayMitigationConfig;
use mwc_wallet_util::mwc_api;
use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
use mwc_wallet_util::mwc_core::consensus::{valid_header_version, WEEK_HEIGHT};
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::core::HeaderVersion;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::libtx::proof;
use mwc_wallet_util::mwc_crates::chrono;
use mwc_wallet_util::mwc_crates::chrono::{Duration, Utc};
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::log::{debug, info, warn};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::secp::{self, Secp256k1};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::zeroizing_blake2b::zeroizing_blake2b;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util;
use mwc_wallet_util::{Mutex, RwLock};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
// Wallet - node sync up strategy. We can request blocks from the node and analyze them. 1 week of blocks can be requested in theory.
// Or we can validate tx kernels, outputs e.t.c

// for 10, using blocks strategy
const SYNC_BLOCKS_DEEPNESS: usize = 8;

// For every 100 outputs trade one additional block. It is make sense for the mining wallets with thousands of blocks.
const OUTPUT_TO_BLOCK: usize = 100;

// How many parallel requests to use for the blocks. We don't want to be very aggressive because
// of the node load. 4 is a reasonable number
const SYNC_BLOCKS_THREADS: usize = 4;

// Keep defensive replay self-spends small enough that one account with many
// replay candidates can always be processed through several valid transactions.
// Each transaction also contains one receiver output.
const REPLAY_SELF_SPEND_BATCH_SIZE: usize = 50;

// Maximum tolerated output build-to-inclusion gap before replay detection:
// two nominal days (2,880 blocks).
const REPLAY_HEIGHT_GAP: u64 = 2 * DAY_HEIGHT;

lazy_static! {
	static ref SCAN_INTERRUPT: RwLock<HashMap<u32, bool>> = RwLock::new(HashMap::new());
}

/// Clean up the scan interruption flag
pub fn release_interrupt_scan(context_id: u32) {
	SCAN_INTERRUPT.write().remove(&context_id);
}

/// Set interruption flag, so all scans will be interrupted, so no waiting will be introduced
pub fn interrupt_scan(context_id: u32) -> Result<(), Error> {
	// Keep the process-global interruption registry bounded to allocated wallet
	// contexts. In particular, do not retain arbitrary ids supplied through the
	// JSON/FFI stop-running-scan request.
	mwc_wallet_util::mwc_node_workflow::context::get_chain_type(context_id).map_err(|e| {
		Error::Lifecycle(format!(
			"Unable to interrupt scan for context {}: {}",
			context_id, e
		))
	})?;
	SCAN_INTERRUPT.write().insert(context_id, true);
	Ok(())
}

fn is_scan_interrupted(context_id: u32) -> bool {
	SCAN_INTERRUPT
		.read()
		.get(&context_id)
		.cloned()
		.unwrap_or(false)
}

/// Utility struct for return values from below
#[derive(Debug, Clone)]
pub struct OutputResult {
	///
	pub commit: pedersen::Commitment,
	///
	pub key_id: Identifier,
	///
	pub n_child: u32,
	///
	pub mmr_index: u64,
	///
	pub value: u64,
	///
	pub height: u64,
	///
	pub lock_height: u64,
	///
	pub is_coinbase: bool,
}

type NodeOutput = (pedersen::Commitment, pedersen::RangeProof, bool, u64, u64);

#[derive(Clone, Copy, Debug)]
enum PmmrEndExpectation {
	Unbounded,
	AtMost(u64),
	Exact(u64),
}

impl PmmrEndExpectation {
	fn requested_end(self) -> Option<u64> {
		match self {
			Self::Unbounded => None,
			Self::AtMost(end) | Self::Exact(end) => Some(end),
		}
	}
}

/// Validates the structural claims in paginated PMMR responses before any
/// output is rewound or persisted. The node supplies these fields, so page
/// progress alone is not sufficient to trust them.
#[derive(Default)]
struct PmmrPageValidator {
	highest_index: Option<u64>,
	seen_commitments: HashSet<[u8; 33]>,
	seen_mmr_indices: HashSet<u64>,
}

impl PmmrPageValidator {
	fn validate(
		&mut self,
		operation: &str,
		page_start: u64,
		end_expectation: PmmrEndExpectation,
		max_outputs: u64,
		highest_index: u64,
		last_retrieved_index: u64,
		outputs: &[NodeOutput],
	) -> Result<(), Error> {
		match end_expectation {
			PmmrEndExpectation::Unbounded => {}
			PmmrEndExpectation::AtMost(end) if highest_index > end => {
				return Err(Error::Node(format!(
					"{}, node returned highest PMMR index {} above requested end {}",
					operation, highest_index, end
				)));
			}
			PmmrEndExpectation::Exact(end) if highest_index != end => {
				return Err(Error::Node(format!(
					"{}, node returned highest PMMR index {}, expected exact anchored end {}",
					operation, highest_index, end
				)));
			}
			_ => {}
		}

		match self.highest_index {
			Some(expected) if highest_index != expected => {
				return Err(Error::Node(format!(
					"{}, node changed highest PMMR index between pages, expected {} got {}",
					operation, expected, highest_index
				)));
			}
			None => self.highest_index = Some(highest_index),
			_ => {}
		}

		if last_retrieved_index > highest_index {
			return Err(Error::Node(format!(
				"{}, node returned last PMMR index {} above highest index {}",
				operation, last_retrieved_index, highest_index
			)));
		}
		if last_retrieved_index < page_start {
			return Err(Error::Node(format!(
				"{}, node returned a non-advancing output page, last_retrieved_index={} start_index={}",
				operation, last_retrieved_index, page_start
			)));
		}

		let output_count = u64::try_from(outputs.len()).map_err(|e| {
			Error::DataOverflow(format!(
				"{}, output page length does not fit u64, output_count={} error={}",
				operation,
				outputs.len(),
				e
			))
		})?;
		if output_count > max_outputs {
			return Err(Error::Node(format!(
				"{}, node returned {} outputs, exceeding requested maximum {}",
				operation, output_count, max_outputs
			)));
		}

		let mut previous_index = None;
		for (commit, _, _, _, mmr_index) in outputs {
			if *mmr_index == 0 || *mmr_index < page_start || *mmr_index > last_retrieved_index {
				return Err(Error::Node(format!(
					"{}, node returned output {} at PMMR index {} outside current page {}-{}",
					operation,
					mwc_util::ToHex::to_hex(commit),
					mmr_index,
					page_start,
					last_retrieved_index
				)));
			}
			if !self.seen_mmr_indices.insert(*mmr_index) {
				return Err(Error::Node(format!(
					"{}, node returned PMMR index {} more than once",
					operation, mmr_index
				)));
			}
			if previous_index.is_some_and(|previous| previous >= *mmr_index) {
				return Err(Error::Node(format!(
					"{}, node returned outputs out of PMMR order at index {}",
					operation, mmr_index
				)));
			}
			previous_index = Some(*mmr_index);

			if !self.seen_commitments.insert(commit.0) {
				return Err(Error::Node(format!(
					"{}, node returned output {} more than once",
					operation,
					mwc_util::ToHex::to_hex(commit)
				)));
			}
		}

		Ok(())
	}
}

impl OutputResult {
	/// Compare parameters.
	pub fn params_equal_to(&self, output: &OutputData) -> bool {
		// Skipping commit because caller does selection by that
		self.key_id == output.key_id
			&& self.mmr_index == output.mmr_index.unwrap_or(0)
			&& self.n_child == output.n_child
			&& self.value == output.value
			&& self.height == output.height
			&& self.lock_height == output.lock_height
			&& self.is_coinbase == output.is_coinbase
	}

	/// Copy self params into output
	pub fn params_push_to(&self, output: &mut OutputData) {
		output.mmr_index = Some(self.mmr_index);
		output.key_id = self.key_id.clone();
		output.n_child = self.n_child;
		output.value = self.value;
		output.height = self.height;
		output.lock_height = self.lock_height;
		output.is_coinbase = self.is_coinbase;
	}
}

#[derive(Debug, Clone)]
/// Collect stats in case we want to just output a single tx log entry
/// for restored non-coinbase outputs
pub struct RestoredTxStats {
	///
	pub log_id: u32,
	///
	pub amount_credited: u64,
	///
	pub num_outputs: usize,
	/// Height of the output. Just want to know for transaction
	pub output_height: u64,
}

lazy_static! {
	/// Global config in memory storage.
	pub static ref REPLAY_MITIGATION_CONFIG: Mutex<HashMap<u32,ReplayMitigationConfig>> = Mutex::new(HashMap::new());
}

#[cfg(feature = "test-support")]
lazy_static! {
	/// Test-only build-to-inclusion threshold overrides, keyed by chain context.
	static ref REPLAY_HEIGHT_GAP_FOR_TESTS: Mutex<Option<u64>> = Mutex::new(None);
}

/// Clean up context
pub fn scan_clean_context(context_id: u32) {
	let _ = REPLAY_MITIGATION_CONFIG.lock().remove(&context_id);
}

/// Set address derivative index
pub fn set_replay_config(context_id: u32, config: ReplayMitigationConfig) {
	let mut lock = REPLAY_MITIGATION_CONFIG.lock();
	lock.insert(context_id, config);
}
/// Get address derivative index
pub fn get_replay_config(context_id: u32) -> ReplayMitigationConfig {
	REPLAY_MITIGATION_CONFIG
		.lock()
		.get(&context_id)
		.cloned()
		.unwrap_or(ReplayMitigationConfig::default())
}

/// Override the two-day replay detection gap for integration tests.
///
/// Production builds cannot change this threshold. The hook lets an
/// end-to-end test exercise a delayed replay without mining 2,880 blocks.
#[cfg(feature = "test-support")]
pub fn set_replay_height_gap_for_tests(height_gap: u64) {
	*REPLAY_HEIGHT_GAP_FOR_TESTS.lock() = Some(height_gap);
}

fn replay_height_gap() -> u64 {
	#[cfg(feature = "test-support")]
	if let Some(height_gap) = *REPLAY_HEIGHT_GAP_FOR_TESTS.lock() {
		return height_gap;
	}

	REPLAY_HEIGHT_GAP
}

fn identify_utxo_outputs<'a, K>(
	secp: &mut Secp256k1,
	context_id: u32,
	keychain: &K,
	outputs: Vec<NodeOutput>,
	end_height: Option<u64>,
	should_self_spend: bool,
	self_spend_amount: u64,
) -> Result<(Vec<OutputResult>, Vec<OutputResult>), Error>
where
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();
	let mut self_spend_outputs: Vec<OutputResult> = Vec::new();

	let legacy_builder = proof::LegacyProofBuilder::new(secp, keychain)?;
	let builder = proof::ProofBuilder::new(secp, keychain)?;
	let legacy_version = HeaderVersion(1);

	for output in outputs.iter() {
		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		let (commit, proof, is_coinbase, height, mmr_index) = output;
		// attempt to unwind message from the RP and get a value
		// will fail if it's not ours
		let (info, built_height) = {
			// Before HF+2wk, try legacy rewind first
			// Heights before the two-week lookback intentionally clamp to genesis.
			let info_legacy = if valid_header_version(
				context_id,
				height.saturating_sub(2 * WEEK_HEIGHT),
				legacy_version,
			) {
				proof::rewind(secp, &legacy_builder, *commit, None, *proof)?
			} else {
				None
			};

			// If legacy didn't work, try new rewind
			if let Some(info) = info_legacy {
				(Some(info), 0)
			} else {
				match output_proof::rewind_with_height(secp, keychain, &builder, *commit, *proof)? {
					Some((amount, key_id, switch, built_height)) => {
						(Some((amount, key_id, switch)), built_height)
					}
					None => (None, 0),
				}
			}
		};

		let (amount, key_id, switch) = match info {
			Some(i) => i,
			None => {
				continue;
			}
		};

		// OutputResult and the persisted wallet output format do not retain the
		// switch commitment type, while restoration and spending deliberately
		// reconstruct every wallet UTXO as Regular. Letting an owned None output
		// proceed would therefore discard cryptographic metadata and later derive a
		// different commitment. Scanning is best-effort, so skip only this unsupported
		// output instead of aborting recovery of the remaining regular outputs.
		if switch != SwitchCommitmentType::Regular {
			warn!(
				"Skipping owned output {:?} with unsupported switch commitment type {:?}",
				commit, switch
			);
			continue;
		}

		let lock_height = if *is_coinbase {
			height
				.checked_add(global::coinbase_maturity(context_id))
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"scan::identify_utxo_outputs, coinbase output lock height overflow, height={} coinbase_maturity={}",
						height,
						global::coinbase_maturity(context_id)
					))
				})?
		} else {
			*height
		};

		// Privacy tradeoff: the output and replay diagnostics below can reveal
		// wallet ownership, amounts, derivation identifiers, and timing metadata to
		// anyone with access to the logs. These details are intentionally retained
		// because they are needed to diagnose restore and replay-mitigation failures;
		// retaining or sharing wallet logs accepts this privacy exposure.
		debug!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			commit, amount, key_id, mmr_index
		);

		// Replay-mitigation trust model: the build height is authenticated by the
		// wallet-owned rangeproof, while the inclusion height comes from the
		// configured node. The wallet deliberately treats that node as its chain
		// source of truth; users are expected to connect to their own trusted
		// private node. Under that model a large height gap is sufficient to
		// authorize the automatic defensive self-spend. Using an untrusted node
		// can therefore cause unnecessary self-spends and fee expenditure.
		let on_the_chain_height = *height;
		let mut spent_candidate = false;
		if built_height != 0 {
			let built_height_64 = u64::from(built_height);
			let inclusion_gap = built_height_64.abs_diff(on_the_chain_height);
			let suspicious_replay = inclusion_gap > replay_height_gap();
			let stale_at_tip = end_height
				.map(|tip_height| tip_height.saturating_sub(built_height_64) > WEEK_HEIGHT)
				.unwrap_or(false);
			debug!(
				"Output build height {}, inclusion height {}, difference {}",
				built_height_64, on_the_chain_height, inclusion_gap
			);
			if suspicious_replay {
				warn!(
					"Possible replayed output detected: commitment {:?}, build height {}, inclusion height {}, difference {}",
					commit, built_height_64, on_the_chain_height, inclusion_gap
				);
			}
			if (suspicious_replay || stale_at_tip)
				&& should_self_spend
				&& amount > self_spend_amount
			{
				self_spend_outputs.push(OutputResult {
					commit: *commit,
					key_id: key_id.clone(),
					n_child: keys::output_child_index(&key_id)?,
					value: amount,
					height: *height,
					lock_height: lock_height,
					is_coinbase: *is_coinbase,
					mmr_index: *mmr_index,
				});
				spent_candidate = true;
			}
		}

		if !spent_candidate {
			wallet_outputs.push(OutputResult {
				commit: *commit,
				key_id: key_id.clone(),
				n_child: keys::output_child_index(&key_id)?,
				value: amount,
				height: *height,
				lock_height: lock_height,
				is_coinbase: *is_coinbase,
				mmr_index: *mmr_index,
			});
		}
	}

	Ok((wallet_outputs, self_spend_outputs))
}

fn collect_chain_outputs_rewind_hash<'a, C>(
	secp: &mut Secp256k1,
	context_id: u32,
	client: &C,
	session: &NodeReadSession,
	rewind_hash: Zeroizing<String>,
	start_index: u64,
	end_index: Option<u64>,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<ViewWallet, Error>
where
	C: NodeClient + 'a,
{
	let batch_size = 1000;
	// This collector is only used after resolving a height range against a
	// fixed scan anchor. A supplied end is therefore an exact terminal bound,
	// not merely a caller-provided cap.
	let end_expectation = match end_index {
		Some(end) => PmmrEndExpectation::Exact(end),
		None => PmmrEndExpectation::Unbounded,
	};
	let start_index_stat = start_index;
	let mut start_index = start_index;
	// The rewind hash is a viewing credential. Decode it once into a
	// zeroizing buffer instead of per output into plain heap memory.
	let rewind_hash_bytes = mwc_util::decode_secret_key_hex::<32>(rewind_hash.as_str())
		.map_err(|e| Error::RewindHash(format!("Unable to decode rewind hash: {}", e)))?;
	let mut vw = ViewWallet {
		rewind_hash,
		output_result: vec![],
		total_balance: 0,
		last_pmmr_index: 0,
	};
	let mut page_validator = PmmrPageValidator::default();
	loop {
		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;
		session.ensure_connection(client, "View-wallet scan output pagination")?;
		page_validator.validate(
			"scan::collect_chain_outputs_rewind_hash",
			start_index,
			end_expectation,
			batch_size,
			highest_index,
			last_retrieved_index,
			&outputs,
		)?;

		let range = highest_index.checked_sub(start_index_stat).ok_or_else(|| {
			Error::DataOverflow(format!(
				"scan::collect_chain_outputs_rewind_hash, output scan range underflow, highest_index={} start_index={}",
				highest_index, start_index_stat
			))
		})?;
		let progress = last_retrieved_index
			.checked_sub(start_index_stat)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs_rewind_hash, output scan progress underflow, last_retrieved_index={} start_index={}",
					last_retrieved_index, start_index_stat
				))
			})?;
		let percentage_complete = if range == 0 {
			0
		} else {
			let scaled_progress = progress.checked_mul(100).ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs_rewind_hash, output scan progress multiplication overflow, progress={} scale=100",
					progress
				))
			})?;
			// range is nonzero in this branch.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the zero range case is handled by the preceding branch"
			)]
			let bounded_percentage = (scaled_progress / range).min(99);
			u8::try_from(bounded_percentage).map_err(|e| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs_rewind_hash, bounded output scan progress does not fit u8, percentage={} error={}",
					bounded_percentage, e
				))
			})?
		};

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		info!("{} ({}% complete)", msg, percentage_complete);
		send_status(
			status_callback,
			StatusMessage::Scanning(true, msg, percentage_complete),
		);

		// Scanning outputs
		for output in outputs.iter() {
			let (commit, proof, is_coinbase, height, mmr_index) = output;

			// The node supplies both the proof and the pagination metadata.
			// Every output included in the chain carried a valid bulletproof,
			// so an invalid one means the node is serving corrupted data.
			// Verify before rewind: rewind is a decryption primitive that does
			// not validate proofs (it can succeed on a tampered proof), and its
			// InvalidRangeProof error below must mean "not owned by this hash",
			// never "the node tampered with the proof".
			secp.verify_bullet_proof(*commit, *proof, None).map_err(|e| {
				Error::GenericError(format!(
					"scan::collect_chain_outputs_rewind_hash, node served an output with an invalid bulletproof, commit={} error={}",
					mwc_util::ToHex::to_hex(&commit),
					e
				))
			})?;

			// SECURITY/SEMANTICS: a successful rewind proves only that this
			// rangeproof used the nonce derived from `rewind_hash` and `commit`.
			// It does not prove that the wallet behind the rewind hash knows the
			// output blinding factor. Anyone who knows the rewind hash can create
			// an unrelated valid output using the same rewind scheme, so that
			// output will be returned here and included in the reported total.
			// Treat this as a view-only match, not an ownership or balance proof.
			let rewind_nonce = zeroizing_blake2b(32, &commit.0, rewind_hash_bytes.as_slice());
			let nonce = SecretKey::from_slice(&secp, rewind_nonce.as_slice())
				.map_err(|e| Error::Nonce(format!("Unable to create nonce: {}", e)))?;
			let info = secp.rewind_bullet_proof(*commit, nonce.clone(), None, None, *proof);

			match info {
				Err(secp::Error::InvalidRangeProof) => continue,
				Err(e) => {
					return Err(mwc_wallet_util::mwc_core::libtx::Error::from(e).into());
				}
				Ok(info) => {
					vw.total_balance =
						vw.total_balance.checked_add(info.value).ok_or_else(|| {
							Error::DataOverflow(format!(
								"scan::collect_chain_outputs_rewind_hash, view-wallet balance overflow, total_balance={} output_value={}",
								vw.total_balance, info.value
							))
						})?;
					let lock_height = if *is_coinbase {
						height
							.checked_add(global::coinbase_maturity(context_id))
							.ok_or_else(|| {
								Error::DataOverflow(format!(
									"scan::collect_chain_outputs_rewind_hash, coinbase output lock height overflow, height={} coinbase_maturity={}",
									height,
									global::coinbase_maturity(context_id)
								))
							})?
					} else {
						*height
					};

					let output_info = ViewWalletOutputResult {
						commit: mwc_util::ToHex::to_hex(&commit),
						value: info.value,
						height: *height,
						mmr_index: *mmr_index,
						is_coinbase: *is_coinbase,
						lock_height: lock_height,
					};

					vw.output_result.push(output_info);
				}
			}
		}
		if highest_index <= last_retrieved_index {
			vw.last_pmmr_index = last_retrieved_index;
			break;
		}
		// The loop continues only when highest_index > last_retrieved_index, proving
		// last_retrieved_index is below u64::MAX.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "highest_index is greater than last_retrieved_index in this branch"
		)]
		{
			start_index = last_retrieved_index + 1;
		}
	}
	Ok(vw)
}

/// Scanning chain for the outputs. Shared with mwc713
pub fn collect_chain_outputs<'a, C, K>(
	secp: &mut Secp256k1,
	context_id: u32,
	keychain: &K,
	client: C,
	start_index: u64,
	end_index: Option<u64>,
	show_progress: bool,
	replay_config: Option<ReplayMitigationConfig>,
) -> Result<(Vec<OutputResult>, Vec<OutputResult>), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let expected_connection = client.get_node_connection_id();
	collect_chain_outputs_bound(
		secp,
		context_id,
		keychain,
		client,
		expected_connection,
		start_index,
		match end_index {
			Some(end) => PmmrEndExpectation::AtMost(end),
			None => PmmrEndExpectation::Unbounded,
		},
		show_progress,
		replay_config,
		None,
	)
}

fn collect_chain_outputs_bound<'a, C, K>(
	secp: &mut Secp256k1,
	context_id: u32,
	keychain: &K,
	client: C,
	expected_connection: NodeConnectionId,
	start_index: u64,
	end_expectation: PmmrEndExpectation,
	show_progress: bool,
	replay_config: Option<ReplayMitigationConfig>,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<(Vec<OutputResult>, Vec<OutputResult>), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut result_vec: Vec<OutputResult> = vec![];
	let mut self_spend_candidate_list: Vec<OutputResult> = vec![];
	let mut page_validator = PmmrPageValidator::default();
	let mut should_self_spent = false;
	let mut self_spent_amount = 0;
	if let Some(conf) = replay_config {
		if conf.replay_mitigation_flag {
			should_self_spent = true;
			self_spent_amount = conf.replay_mitigation_min_amount;
		}
	}
	loop {
		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		let (highest_index, last_retrieved_index, outputs) = client.get_outputs_by_pmmr_index(
			start_index,
			end_expectation.requested_end(),
			batch_size,
		)?;
		let actual_connection = client.get_node_connection_id();
		if actual_connection != expected_connection {
			return Err(Error::Node(format!(
				"Wallet scan changed node while retrieving output pages; expected {:?}, current {:?}. Partial results were discarded",
				expected_connection, actual_connection
			)));
		}
		page_validator.validate(
			"scan::collect_chain_outputs",
			start_index,
			end_expectation,
			batch_size,
			highest_index,
			last_retrieved_index,
			&outputs,
		)?;

		let range = highest_index.checked_sub(start_index_stat).ok_or_else(|| {
			Error::DataOverflow(format!(
				"scan::collect_chain_outputs, output scan range underflow, highest_index={} start_index={}",
				highest_index, start_index_stat
			))
		})?;
		let progress = last_retrieved_index
			.checked_sub(start_index_stat)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs, output scan progress underflow, last_retrieved_index={} start_index={}",
					last_retrieved_index, start_index_stat
				))
			})?;
		let perc_complete = if range == 0 {
			0
		} else {
			let scaled_progress = progress.checked_mul(100).ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs, output scan progress multiplication overflow, progress={} scale=100",
					progress
				))
			})?;
			// range is nonzero in this branch.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the zero range case is handled by the preceding branch"
			)]
			let bounded_percentage = (scaled_progress / range).min(99);
			u8::try_from(bounded_percentage).map_err(|e| {
				Error::DataOverflow(format!(
					"scan::collect_chain_outputs, bounded output scan progress does not fit u8, percentage={} error={}",
					bounded_percentage, e
				))
			})?
		};

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if show_progress {
			info!("{} ({}% complete)", msg, perc_complete);
		}
		send_status(
			status_callback,
			StatusMessage::Scanning(show_progress, msg, perc_complete),
		);
		let mut chain_outs_pair = identify_utxo_outputs(
			secp,
			context_id,
			keychain,
			outputs,
			None,
			should_self_spent,
			self_spent_amount,
		)?;
		result_vec.append(&mut chain_outs_pair.0);
		self_spend_candidate_list.append(&mut chain_outs_pair.1);

		if highest_index <= last_retrieved_index {
			break;
		}
		// The loop continues only when highest_index > last_retrieved_index, proving
		// last_retrieved_index is below u64::MAX.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "highest_index is greater than last_retrieved_index in this branch"
		)]
		{
			start_index = last_retrieved_index + 1;
		}
	}
	Ok((result_vec, self_spend_candidate_list))
}

/// Respore missing outputs. Shared with mwc713
fn restore_missing_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	output: OutputResult,
	output_creators: &OutputCreatorMap,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	found_parents: &mut HashMap<Identifier, u32>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let node_client = wallet.w2n_client().clone();
	let commit = wallet.calc_commit(secp, keychain_mask, output.value, &output.key_id)?;
	let parent_key_id = keys::output_parent_key_id(&output.key_id)?;
	let output_n_child = output.n_child;
	let commit_hex = mwc_util::ToHex::to_hex(&commit);

	// Transaction history is a recovery hint, not an integrity boundary: copied
	// or partially restored wallet data can contain dangling or duplicate log
	// records. Reuse a log id only when one trustworthy account-local creator
	// remains. Otherwise the recovery branch below creates a clean transaction
	// instead of aborting the scan or guessing which damaged record was intended.
	let (creator_log_id, candidate_count, valid_candidate_count) =
		select_output_creator_log_id(output_creators, transactions, &parent_key_id, &commit_hex);
	if candidate_count > 0 && creator_log_id.is_none() {
		warn!(
			"Restored output {} in account {} has {} recorded creator candidates, but {} trustworthy candidates; creating a recovery transaction",
			commit_hex, parent_key_id, candidate_count, valid_candidate_count
		);
	}
	let active_spender_log_id =
		select_active_output_spender_log_id(transactions, &parent_key_id, &commit_hex)?;
	let mut batch = wallet.batch(secp, keychain_mask)?;

	let creation_log_id = {
		if let Some(log_id) = creator_log_id {
			log_id
		} else {
			// Preserve questionable historical records for diagnostics, but create a
			// new, unambiguous account-local creation-history entry. If an active
			// transaction already spends this output, that spender remains the output's
			// current association below. The chain-proven output supplies the
			// confirmation data for the recovery entry.
			let log_id = batch.next_tx_log_id(&parent_key_id)?;
			let entry_type = match output.is_coinbase {
				true => TxLogEntryType::ConfirmedCoinbase,
				false => TxLogEntryType::TxReceived,
			};
			let mut t = TxLogEntry::new(parent_key_id.clone(), entry_type, log_id);
			t.confirmed = true;
			t.output_height = output.height;
			t.amount_credited = output.value;
			t.num_outputs = 1;
			t.output_commits = vec![output.commit.clone()];
			// The output was proven to be on chain by the scan, so this header
			// exists; a read failure is a node/transport problem and must not
			// leave a confirmed record without its confirmation data.
			let hdr_info = node_client.get_header_info(t.output_height).map_err(|e| {
				Error::Node(format!(
					"Wallet output restoration failed to read header at height {}: {}",
					t.output_height, e
				))
			})?;
			session.ensure_connection(&node_client, "Wallet output restoration")?;
			t.update_confirmation_ts(hdr_info.confirmed_time)?;
			batch.save_tx_log_entry(t, &parent_key_id)?;
			log_id
		}
	};
	if let Some(spender_log_id) = active_spender_log_id {
		info!(
			"Restored output {} in account {} remains locked by active transaction {}",
			commit_hex, parent_key_id, spender_log_id
		);
	}
	let (status, output_log_id) = match active_spender_log_id {
		Some(spender_log_id) => (OutputStatus::Locked, spender_log_id),
		None => (OutputStatus::Unspent, creation_log_id),
	};

	// WalletOutputBatch::save reserves this child key in the same transaction
	// as the recovered output and any new recovery log entry. A later scan error
	// therefore cannot leave a spendable output paired with a reusable key.
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		n_child: output_n_child,
		mmr_index: Some(output.mmr_index),
		commit: Some(commit_hex),
		value: output.value,
		status,
		height: output.height,
		lock_height: output.lock_height,
		is_coinbase: output.is_coinbase,
		tx_log_entry: Some(output_log_id),
	})?;

	session.verify_anchor(&node_client, "Wallet output restoration")?;
	batch.commit()?;

	// Keep the in-memory label restoration set aligned with committed outputs.
	let max_child_index = *found_parents.get(&parent_key_id).unwrap_or(&0);
	if output_n_child >= max_child_index {
		found_parents.insert(parent_key_id, output_n_child);
	}
	Ok(())
}

fn record_found_parent(
	found_parents: &mut HashMap<Identifier, u32>,
	output: &OutputResult,
) -> Result<Identifier, Error> {
	let parent_key_id = keys::output_parent_key_id(&output.key_id)?;
	let max_child_index = *found_parents.get(&parent_key_id).unwrap_or(&0);
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id.clone(), output.n_child);
	}
	Ok(parent_key_id)
}

/// Restore replay candidates which are absent from the wallet database,
/// reactivate candidates which were previously spent, and create ordinary
/// self-sends in bounded per-account batches. An active transaction which already
/// spends a candidate is sufficient protection and is left untouched.
///
/// A seed-restored wallet has the private key material needed to rewind and
/// spend the output, but normal transaction construction selects inputs from
/// persisted `OutputData`. The old implementation removed replay candidates
/// from the restore list and attempted the self-spend first, which failed with
/// insufficient funds. A history-detected replay has the same ordering
/// requirement: its existing wallet record is still `Spent` and points at the
/// original PMMR position. Persisting the current spendable record before
/// invoking the ordinary transaction path handles both cases.
fn restore_and_self_spend_replay_candidates<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	replay_candidates: Vec<OutputResult>,
	tip_height: u64,
	known_outputs: &HashMap<String, WalletOutputInfo>,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	found_parents: &mut HashMap<Identifier, u32>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let account_labels: HashMap<Identifier, String> = wallet
		.acct_path_iter()?
		.map(|mapping| (mapping.path, mapping.label))
		.collect();

	if replay_candidates.is_empty() {
		return Ok(());
	}

	// The defensive self-spend's receiver output carries the wallet's last
	// confirmed height as its anti-replay tag. On a fresh seed restoration that
	// height is still 0, which would leave the new output untagged and invisible
	// to future replay detection.
	// The scan has already reconciled and persisted all wallet data up to
	// the tip at this point, so it is safe and accurate to advance the
	// wallet-wide height now; the scan also saves it again at the end.
	// Every newly created output then always carries a meaningful tag.
	{
		let node_client = wallet.w2n_client().clone();
		let mut batch = wallet.batch(secp, keychain_mask)?;
		batch.save_last_confirmed_height(tip_height)?;
		session.verify_anchor(&node_client, "Wallet replay mitigation")?;
		batch.commit()?;
	}

	let output_creators = build_output_creator_map(transactions);
	let mut candidates_by_account: HashMap<String, Vec<OutputResult>> = HashMap::new();

	for replay_output in replay_candidates {
		let commit = mwc_util::ToHex::to_hex(&replay_output.commit);
		// Resolve and record the candidate's key-path metadata before grouping it.
		let parent_key_id = record_found_parent(found_parents, &replay_output)?;
		let account_label = account_labels.get(&parent_key_id).cloned();

		let active_spender_log_id =
			select_active_output_spender_log_id(transactions, &parent_key_id, &commit)?;
		let already_protected = active_spender_log_id.is_some();

		if let Some(known_output) = known_outputs.get(&commit) {
			// History detection deliberately removes the replay from the normal
			// reconciliation set, because its still-confirmed spending
			// transaction must not be reverted. Consequently the old output
			// record is still Spent here. Move that record to the replay's
			// current PMMR position. An ordinary active transaction keeps its normal
			// lock; otherwise make the output available to the exact-output selector.
			let mut spendable_output = known_output.output.clone();
			let old_key_id = spendable_output.key_id.clone();
			let old_mmr_index = spendable_output.mmr_index;
			replay_output.params_push_to(&mut spendable_output);
			reconcile_wallet_output_parent(
				&mut spendable_output,
				&parent_key_id,
				&commit,
				&output_creators,
				transactions,
			);
			spendable_output.status = match active_spender_log_id {
				Some(spender_log_id) => {
					spendable_output.tx_log_entry = Some(spender_log_id);
					OutputStatus::Locked
				}
				None => OutputStatus::Unspent,
			};

			let node_client = wallet.w2n_client().clone();
			let mut batch = wallet.batch(secp, keychain_mask)?;
			if old_key_id != spendable_output.key_id || old_mmr_index != spendable_output.mmr_index
			{
				batch.delete(&old_key_id, &old_mmr_index)?;
			}
			batch.save(spendable_output)?;
			session.verify_anchor(&node_client, "Wallet replay mitigation")?;
			batch.commit()?;
		} else {
			// restore_missing_output commits both OutputData and the matching
			// recovery transaction record. The grouped self-send can then select the
			// commitment through the regular wallet transaction path.
			restore_missing_output(
				wallet,
				secp,
				keychain_mask,
				replay_output.clone(),
				&output_creators,
				transactions,
				found_parents,
				session,
			)?;
		}

		if already_protected {
			info!(
				"Replay attack candidate {:?} is already locked by an active wallet transaction",
				replay_output.commit
			);
			continue;
		}

		let account_label = match account_label {
			Some(account_label) => account_label,
			None => {
				// Account mappings may be absent after a partial backup. Transaction
				// construction cannot select the correct account without its label.
				warn!(
					"Replay attack candidate {:?} belongs to account {} without a usable label; a later scan will retry",
					replay_output.commit, parent_key_id
				);
				continue;
			}
		};

		candidates_by_account
			.entry(account_label)
			.or_default()
			.push(replay_output);
	}

	for (account_label, candidates) in candidates_by_account {
		for candidates in candidates.chunks(REPLAY_SELF_SPEND_BATCH_SIZE) {
			let amount = candidates.iter().try_fold(0u64, |total, candidate| {
				total.checked_add(candidate.value).ok_or_else(|| {
					Error::DataOverflow(format!(
						"scan::restore_and_self_spend_replay_candidates, replay batch value sum overflow, total={} candidate_value={}",
						total, candidate.value
					))
				})
			});
			let amount = match amount {
				Ok(amount) => amount,
				Err(error) => {
					warn!(
						"Unable to total replay attack candidate batch for account {}: {}",
						account_label, error
					);
					return Err(error);
				}
			};
			let commits: HashSet<String> = candidates
				.iter()
				.map(|candidate| mwc_util::ToHex::to_hex(&candidate.commit))
				.collect();

			info!(
				"Self-spending {} replay attack output(s) in account {} after wallet restoration/reconciliation",
				candidates.len(), account_label
			);
			if let Err(error) = self_spend_selected_outputs(
				wallet,
				secp,
				keychain_mask,
				amount,
				commits,
				Some(account_label.clone()),
			) {
				warn!(
					"Unable to self-spend replay attack candidate batch for account {}: {}. Normal wallet state was retained; a later scan will retry candidates not reserved by an active transaction",
					account_label, error
				);
				continue;
			}
			session.verify_anchor(wallet.w2n_client(), "Wallet replay mitigation")?;
		}
	}

	Ok(())
}

#[derive(Debug)]
struct WalletOutputInfo {
	updated: bool,  // true if data was updated, we need push it into DB
	at_chain: bool, // true if this Output was founf at the Chain
	output: OutputData,
	commit: String,                      // commit as a string. output.output value
	tx_input_uuid: HashSet<TxUuidPlus>,  // transactions where this commit is input
	tx_output_uuid: HashSet<TxUuidPlus>, // transactions where this commit is output
}

impl WalletOutputInfo {
	pub fn new(output: OutputData) -> WalletOutputInfo {
		let commit = output.commit.clone().unwrap_or_else(|| String::new());
		WalletOutputInfo {
			updated: false,
			at_chain: false,
			output,
			commit,
			tx_input_uuid: HashSet::new(),
			tx_output_uuid: HashSet::new(),
		}
	}

	pub fn add_tx_input_uuid(&mut self, uuid: &TxUuidPlus) {
		self.tx_input_uuid.insert(uuid.clone());
	}

	pub fn add_tx_output_uuid(&mut self, uuid: &TxUuidPlus) {
		self.tx_output_uuid.insert(uuid.clone());
	}

	// Output that is not active and not mapped to any transaction.
	pub fn is_orphan_output(&self) -> bool {
		self.tx_input_uuid.len() == 0
			&& self.tx_output_uuid.len() == 0
			&& !self.output.is_spendable()
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TxUuidPlus {
	uuid_str: String,
	id: u32,
	parent_key_id: String,
}

impl TxUuidPlus {
	fn new(uuid_str: String, id: u32, parent_key_id: String) -> TxUuidPlus {
		TxUuidPlus {
			uuid_str,
			id,
			parent_key_id,
		}
	}

	fn tx_id(&self) -> String {
		format!("{}/{}", self.id, self.parent_key_id)
	}
}

#[derive(Debug)]
struct WalletTxInfo {
	updated: bool,       // true if data was updated, we need push it into DB
	tx_uuid: TxUuidPlus, // transaction uuid++. Format:  "{}/{}/{}", uuid_str, tx.id, tx.parent_key_id.to_hex()
	tx_log: TxLogEntry,
	// Complete stored-transaction commitments. Keep using these for legacy
	// reconciliation because damaged log entries may have lost their direct
	// commitment lists. They cannot safely choose a single creator for
	// tx_log_entry: self-send sender and receiver logs share the stored transaction.
	input_commit: HashSet<String>,
	output_commit: HashSet<String>,
	// Output commitments directly recorded by this account-local transaction log.
	owned_output_commit: HashSet<String>,
	kernel_validation: Option<bool>, // Kernel validation flag. None - mean not validated because of height
}

impl WalletTxInfo {
	pub fn new(tx_uuid: TxUuidPlus, tx_log: TxLogEntry) -> WalletTxInfo {
		let owned_output_commit: HashSet<String> = tx_log
			.output_commits
			.iter()
			.map(|c| mwc_util::to_hex(&c.0))
			.collect();
		WalletTxInfo {
			updated: false,
			tx_uuid,
			input_commit: tx_log
				.input_commits
				.iter()
				.map(|c| mwc_util::to_hex(&c.0))
				.collect(),
			output_commit: owned_output_commit.clone(),
			owned_output_commit,
			tx_log,
			kernel_validation: None,
		}
	}

	// read all commit from the transaction tx.
	pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
		for input in tx.inputs_committed()? {
			let input = input?;
			self.input_commit.insert(mwc_util::to_hex(&input.0));
		}

		for output in tx.outputs_committed()? {
			let output = output?;
			self.output_commit.insert(mwc_util::to_hex(&output.0));
		}

		// We have !tx_log.confirmed here because of Account to account transfer issue
		// By some reasons Send and receive getting different kernels. As a result Send TxLig has wrong kernel
		// We check is_cancelled because we want to minimize IOs.
		// As a result, if this issues happen, user cancel tx, it will not be uncancelled. We accept that because failure is not very
		// critical and user not expected to destroy it's own data.
		if self.tx_log.kernel_excess.is_none()
			|| (!self.tx_log.confirmed && !self.tx_log.is_cancelled_reverted())
		{
			if let Some(kernel) = tx.body.kernels.get(0) {
				if kernel.excess != pedersen::Commitment::from_vec(vec![0; 33])? {
					// We have a test case with zero (default value) kernel. Still need to handle
					self.tx_log.kernel_excess = Some(kernel.excess);
					self.updated = true;
				}
			}
		}
		Ok(())
	}
}

// Output transaction ids are account-local, so a commitment alone is not a
// sufficient lookup key. Keep all matches so damaged/duplicated history is
// reported explicitly instead of being resolved by HashMap iteration order.
type OutputCreatorKey = (String, String); // (parent key id, commitment)
type OutputCreatorMap = HashMap<OutputCreatorKey, Vec<TxUuidPlus>>;

fn output_creator_key(parent_key_id: &Identifier, commit: &str) -> OutputCreatorKey {
	(
		mwc_util::to_hex(&parent_key_id.to_bytes()),
		commit.to_owned(),
	)
}

fn build_output_creator_map(transactions: &HashMap<TxUuidPlus, WalletTxInfo>) -> OutputCreatorMap {
	let mut creators: OutputCreatorMap = HashMap::new();
	for tx in transactions.values() {
		for commit in &tx.owned_output_commit {
			creators
				.entry(output_creator_key(&tx.tx_log.parent_key_id, commit))
				.or_default()
				.push(tx.tx_uuid.clone());
		}
	}
	creators
}

/// Select an existing account-local creator only when the surviving wallet
/// metadata identifies exactly one trustworthy record. Backups and damaged
/// wallet databases can contain missing, duplicated, or internally inconsistent
/// transaction records; callers repair those cases with a new recovery entry.
fn select_output_creator_log_id(
	output_creators: &OutputCreatorMap,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	parent_key_id: &Identifier,
	commit: &str,
) -> (Option<u32>, usize, usize) {
	let candidates = match output_creators.get(&output_creator_key(parent_key_id, commit)) {
		Some(candidates) => candidates,
		None => return (None, 0, 0),
	};
	// Missing map targets and inconsistent fields are expected forms of damaged
	// backup data. Ignore them rather than turning restoration into a hard error.
	let valid_log_ids: Vec<u32> = candidates
		.iter()
		.filter_map(|uuid| transactions.get(uuid))
		.filter(|creator| {
			creator.tx_log.parent_key_id == *parent_key_id
				&& creator.owned_output_commit.contains(commit)
		})
		.map(|creator| creator.tx_log.id)
		.collect();
	// With multiple valid claims there is no reliable way to infer which
	// account-local numeric id the output originally referenced. A fresh recovery
	// entry is safer than an arbitrary but deterministic choice.
	let log_id = if valid_log_ids.len() == 1 {
		valid_log_ids.first().copied()
	} else {
		None
	};
	(log_id, candidates.len(), valid_log_ids.len())
}

/// Select the account-local pending transaction which currently reserves an
/// output as an input. Creator lookup and spender lookup are deliberately
/// separate: transaction output commitments preserve creation history, while a
/// pending sender's input commitments determine whether the output is spendable.
/// Multiple active claims are unsafe to resolve by iteration order, so fail
/// closed before the restored output is committed.
fn select_active_output_spender_log_id(
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	parent_key_id: &Identifier,
	commit: &str,
) -> Result<Option<u32>, Error> {
	let active_spenders: Vec<&WalletTxInfo> = transactions
		.values()
		.filter(|tx| {
			// Prefer the kernel result from this scan when available. In particular,
			// Some(false) turns a previously confirmed send back into a pending send
			// after a reorg, matching validate_transactions later in this pass.
			let effectively_confirmed = tx.kernel_validation.unwrap_or(tx.tx_log.confirmed);
			tx.tx_log.parent_key_id == *parent_key_id
				&& tx.tx_log.tx_type == TxLogEntryType::TxSent
				&& !tx.tx_log.is_cancelled_reverted()
				&& !effectively_confirmed
				&& tx.input_commit.contains(commit)
		})
		.collect();

	match active_spenders.as_slice() {
		[] => Ok(None),
		[spender] => Ok(Some(spender.tx_log.id)),
		spenders => Err(Error::GenericError(format!(
			"Restored output {} in account {} is reserved by {} active transactions",
			commit,
			parent_key_id,
			spenders.len()
		))),
	}
}

/// Choose the transaction-log association for a coinbase output whose missing
/// creation record is being rebuilt. A pending spender owns the output's single
/// association slot while it is locked; the new creator remains discoverable
/// through its recorded output commitment.
fn repaired_coinbase_output_log_id(
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	parent_key_id: &Identifier,
	commit: &str,
	coinbase_log_id: u32,
) -> Result<u32, Error> {
	Ok(
		select_active_output_spender_log_id(transactions, parent_key_id, commit)?
			.unwrap_or(coinbase_log_id),
	)
}

/// Keep the account-scoped fields of an output consistent with its recovered
/// key. Transaction log ids are local to an account, so an id retained from a
/// different parent must not follow the output into the recovered account.
fn reconcile_wallet_output_parent(
	output: &mut OutputData,
	recovered_parent: &Identifier,
	commit: &str,
	output_creators: &OutputCreatorMap,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
) -> bool {
	if output.root_key_id == *recovered_parent {
		return false;
	}

	let previous_parent = output.root_key_id.clone();
	let previous_log_id = output.tx_log_entry;
	let (creator_log_id, candidate_count, valid_candidate_count) =
		select_output_creator_log_id(output_creators, transactions, recovered_parent, commit);

	// A creator from the old account is never valid in the recovered account.
	// If history cannot identify one unambiguous account-local replacement, clear
	// the link instead of attaching the output to an unrelated transaction with
	// the same numeric id.
	output.root_key_id = recovered_parent.clone();
	output.tx_log_entry = creator_log_id;
	warn!(
		"Correcting output {} account from {} to {}; transaction log id {:?} -> {:?} ({} candidates, {} trustworthy)",
		commit,
		previous_parent,
		recovered_parent,
		previous_log_id,
		creator_log_id,
		candidate_count,
		valid_candidate_count
	);
	true
}

fn add_transaction_input_commits(
	commits: &mut HashSet<String>,
	transaction: Transaction,
) -> Result<(), Error> {
	for input in transaction.inputs_committed()? {
		let input = input?;
		commits.insert(mwc_util::to_hex(&input.0));
	}
	Ok(())
}

fn add_confirmed_tx_log_input_commits(commits: &mut HashSet<String>, tx_log: &TxLogEntry) -> bool {
	if !tx_log.confirmed || tx_log.is_cancelled_reverted() {
		return false;
	}
	commits.extend(
		tx_log
			.input_commits
			.iter()
			.map(|commit| mwc_util::to_hex(&commit.0)),
	);
	true
}

/// Collect immutable replay evidence without merging archived transactions into
/// the mutable scan map. Archived entries are only written after they cross the
/// chain archive horizon; their confirmed state is therefore the source of truth
/// in the same way as an active confirmed transaction below the scan boundary.
fn collect_transaction_history_spends<'a, T: ?Sized, C, K>(
	wallet: &T,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
) -> Result<HashSet<String>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut confirmed_spends = HashSet::new();

	for tx in transactions.values() {
		let confirmed = match tx.kernel_validation {
			// A current on-chain kernel is stronger evidence than a stale local
			// cancelled/reverted state. Transaction validation normalizes that state
			// later in the scan, after replay candidates have already been selected.
			Some(kernel_is_on_chain) => kernel_is_on_chain,
			None => tx.tx_log.confirmed && !tx.tx_log.is_cancelled_reverted(),
		};
		if confirmed {
			confirmed_spends.extend(tx.input_commit.iter().cloned());
		}
	}

	// A self-send can have multiple account-local log entries sharing one stored
	// transaction. Read each archived transaction file at most once.
	let mut loaded_stored_transactions = HashSet::new();
	// Failure to enumerate the archive remains fatal: silently dropping unknown
	// archived entries would make replay evidence incomplete and could restore a
	// previously spent output as ordinary spendable funds.
	for tx_log in wallet.tx_log_archive_iter()? {
		if !add_confirmed_tx_log_input_commits(&mut confirmed_spends, &tx_log) {
			continue;
		}

		if let Some(tx_slate_id) = tx_log.tx_slate_id {
			let uuid = tx_slate_id.to_string();
			if loaded_stored_transactions.insert(uuid.clone()) {
				match wallet.get_stored_tx_by_uuid(&uuid, true) {
					Ok(transaction) => {
						// A decoded transaction whose committed inputs cannot be read is
						// still incomplete replay evidence, so this also fails closed.
						add_transaction_input_commits(&mut confirmed_spends, transaction)?
					}
					// A stored transaction was not required by older log formats. The
					// account-local input commitments above remain valid evidence.
					Err(Error::TransactionNotFound(_)) => {}
					// A corrupt stored transaction can hide inputs that older log entries
					// did not record. Continuing here would fail open, so retain the error.
					Err(e) => return Err(e),
				}
			}
		}
	}

	Ok(confirmed_spends)
}

/// Remove outputs from the normal scan result when wallet transaction history
/// proves that the same commitment was already consumed by a transaction which
/// remains on the current chain.
///
/// This is the history-based half of replay-attack mitigation. It is independent
/// of the rangeproof build-height tolerance, so it detects a replay immediately
/// (including legacy outputs without a height tag). A transaction whose kernel
/// disappeared is deliberately not considered proof: its input may have
/// legitimately returned to the UTXO set after a reorg.
fn take_transaction_history_replay_candidates(
	chain_outs: &mut Vec<OutputResult>,
	confirmed_spends: &HashSet<String>,
	replay_config: &ReplayMitigationConfig,
) -> Vec<OutputResult> {
	if !replay_config.replay_mitigation_flag {
		return Vec::new();
	}

	let mut replay_candidates = Vec::new();
	chain_outs.retain(|chain_output| {
		if chain_output.value <= replay_config.replay_mitigation_min_amount {
			return true;
		}

		let commit = mwc_util::ToHex::to_hex(&chain_output.commit);
		if confirmed_spends.contains(&commit) {
			warn!(
				"Replay attack output detected from wallet transaction history: commitment {:?} is unspent again after its spending transaction was confirmed",
				chain_output.commit
			);
			replay_candidates.push(chain_output.clone());
			false
		} else {
			true
		}
	});

	replay_candidates
}

/// Ensure legacy or restored output records participate in commitment-keyed
/// scan reconciliation. Returning whether the cache was repaired lets the
/// caller persist the derived commitment even when no chain fields changed.
fn ensure_output_cached_commit<K: Keychain>(
	secp: &Secp256k1,
	keychain: &K,
	output: &mut OutputData,
) -> Result<(String, bool), Error> {
	if let Some(commit) = &output.commit {
		return Ok((commit.clone(), false));
	}

	let commit = mwc_util::to_hex(
		&keychain
			.commit(
				secp,
				output.value,
				&output.key_id,
				SwitchCommitmentType::Regular,
			)?
			.0,
	);
	output.commit = Some(commit.clone());
	Ok((commit, true))
}

// Getting: - transactions from wallet,
//          - outputs from wallet
//			- outputs from the chain
// Then build the transaction map that mapped to Outputs and
//     Outputs map that mapped to the transactions
//
// Consistency note: locking this workflow to one node URL would not freeze the
// node's state. A single node can advance, reorganize, or change its live UTXO
// set between requests, just as two trusted nodes can expose different current
// states. Consistency therefore comes from the caller-provided NodeReadSession,
// response validation, and final anchor verification; URL locking must not be
// used as a replacement for those checks.
fn get_wallet_and_chain_data<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	start_height: u64,
	end_height: u64,
	show_progress: bool,
	status_callback: Option<&StatusCallback<'_>>,
	do_full_outputs_refresh: bool, // true expected at the first and in case of reorgs
	replay_config: Option<ReplayMitigationConfig>,
	session: &NodeReadSession,
) -> Result<
	(
		HashMap<String, WalletOutputInfo>, // Outputs. Key: Commit
		Vec<OutputResult>,                 // Chain outputs
		HashMap<TxUuidPlus, WalletTxInfo>, // Slate based Transaction. Key: tx uuid
		String,                            // Commit of the last output in the sequence
		Vec<OutputResult>,                 // Outputs selected for replay-mitigation self-spend
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if start_height > end_height {
		return Err(Error::GenericError(
			"Wallet scan start height exceeds end height".to_owned(),
		));
	}
	let self_spend_candidate_list: Vec<OutputResult>;

	// Resulting wallet's outputs with extended info
	// Key: commit
	let mut outputs: HashMap<String, WalletOutputInfo> = HashMap::new();
	let mut spendable_outputs: usize = 0;

	let mut last_output = String::new();

	let context_id = wallet.get_context_id();

	// Wallet's transactions with extended info
	// Key: transaction uuid
	let mut transactions: HashMap<TxUuidPlus, WalletTxInfo> = HashMap::new();
	let chain_outs: Vec<OutputResult>;

	// The backend keys output records by key id and MMR index, not by
	// commitment, so distinct records can carry the same cached commitment
	// (e.g. after a fork switch or a replay restore). A plain map insert would
	// silently evict the earlier record from the scan; collect the full
	// duplicate sets instead and reconcile them explicitly below, once the
	// chain data is available.
	let mut duplicate_wallet_outputs: HashMap<String, Vec<OutputData>> = HashMap::new();
	{
		// First, reading data from the wallet
		{
			let keychain = wallet.keychain(secp, keychain_mask)?;
			for mut w_out in wallet.iter()? {
				let (commit, repaired_commit) =
					ensure_output_cached_commit(secp, &keychain, &mut w_out)?;
				last_output = commit.clone();
				let mut output_info = WalletOutputInfo::new(w_out.clone());
				output_info.updated = repaired_commit;
				if let Some(displaced) = outputs.insert(commit.clone(), output_info) {
					let duplicates = duplicate_wallet_outputs.entry(commit).or_default();
					if duplicates.is_empty() {
						duplicates.push(displaced.output);
					}
					duplicates.push(w_out.clone());
				}

				if w_out.is_spendable() {
					// This counter cannot exceed the number of outputs yielded by the
					// backing collection, whose length fits usize.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the counter is bounded by the backing collection length"
					)]
					{
						spendable_outputs += 1;
					}
				}
			}
		}

		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		// Key: id + tx.parent_key_id
		let mut transactions_id2uuid: HashMap<String, TxUuidPlus> = HashMap::new();
		let mut not_confirmed_txs: usize = 0;

		let mut non_uuid_tx_counter: u32 = 0;
		let temp_uuid_data = [0, 0, 0, 0, 0, 0, 0, 0]; // uuid expected 8 bytes

		// Collect what inputs/outputs trabsactions already has
		let mut input_commits: HashSet<String> = HashSet::new();
		let mut output_commits: HashSet<String> = HashSet::new();

		// Collecting Transactions from the wallet. UUID need to be known, otherwise
		// transaction is non complete and can be ignored.
		for tx in wallet.tx_log_iter()? {
			if !tx.confirmed {
				// This counter cannot exceed the number of transaction log entries,
				// whose backing collection length fits usize.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the counter is bounded by the backing collection length"
				)]
				{
					not_confirmed_txs += 1;
				}
			}

			// For transactions without uuid generating temp uuid just for mapping
			let tx_uuid_str = match tx.tx_slate_id {
				Some(tx_slate_id) => tx_slate_id.to_string(),
				None => {
					non_uuid_tx_counter = non_uuid_tx_counter.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"scan::get_wallet_and_chain_data, non-UUID transaction counter overflow, non_uuid_tx_counter={} increment=1",
							non_uuid_tx_counter
						))
					})?;
					Uuid::from_fields(non_uuid_tx_counter, 0, 0, &temp_uuid_data).to_string()
				}
			};

			// uuid must include tx uuid, id for transaction to handle self send with same account,
			//    parent_key_id  to handle senf send to different accounts
			let uuid_plus = TxUuidPlus::new(
				tx_uuid_str.clone(),
				tx.id,
				mwc_util::to_hex(&tx.parent_key_id.to_bytes()),
			);

			let mut wtx = WalletTxInfo::new(uuid_plus, tx.clone());

			// A missing stored transaction is normal (e.g. no slate was ever saved);
			// any other failure means the tx log and stored data disagree, so stop.
			match wallet.get_stored_tx_by_uuid(&tx_uuid_str, false) {
				Ok(transaction) => wtx.add_transaction(transaction)?,
				Err(Error::TransactionNotFound(_)) => {}
				Err(e) => return Err(e),
			}
			transactions_id2uuid.insert(wtx.tx_uuid.tx_id(), wtx.tx_uuid.clone());

			input_commits.extend(wtx.input_commit.iter().map(|s| s.clone()));
			output_commits.extend(wtx.output_commit.iter().map(|s| s.clone()));

			transactions.insert(wtx.tx_uuid.clone(), wtx);
		}

		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		// Propagate tx to output mapping to outputs
		for tx in transactions.values() {
			// updated output vs Transactions mapping
			for com in &tx.input_commit {
				if let Some(out) = outputs.get_mut(com) {
					out.add_tx_input_uuid(&tx.tx_uuid);
				}
			}
			for com in &tx.output_commit {
				if let Some(out) = outputs.get_mut(com) {
					out.add_tx_output_uuid(&tx.tx_uuid);
				}
			}
		}

		// Wallet - node sync up strategy. We can request blocks from the node and analyze them. 1 week of blocks can be requested in theory.
		// Or we can validate tx kernels, outputs e.t.c

		// Both divisors are nonzero constants.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the divisors are compile-time nonzero constants"
		)]
		let unconfirmed_depth = not_confirmed_txs / 2;
		let output_depth = spendable_outputs / OUTPUT_TO_BLOCK;
		let height_deep_limit = SYNC_BLOCKS_DEEPNESS
			.checked_add(unconfirmed_depth)
			.and_then(|limit| limit.checked_add(output_depth))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::get_wallet_and_chain_data, wallet scan depth overflow, base_depth={} unconfirmed_depth={} output_depth={}",
					SYNC_BLOCKS_DEEPNESS, unconfirmed_depth, output_depth
				))
			})?;
		let height_deep_limit = u64::try_from(height_deep_limit).map_err(|e| {
			Error::DataOverflow(format!(
				"scan::get_wallet_and_chain_data, wallet scan depth does not fit u64, height_deep_limit={} error={}",
				height_deep_limit, e
			))
		})?;

		if is_scan_interrupted(context_id) {
			return Err(Error::Interrupted);
		}

		// We need to choose a strategy. If there are few blocks, it is really make sense request those blocks
		// start_height <= end_height was validated at function entry.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "start_height is checked not to exceed end_height at function entry"
		)]
		let scan_height_span = end_height - start_height;
		if !do_full_outputs_refresh && (scan_height_span <= height_deep_limit) {
			debug!("get_wallet_and_chain_data using block base strategy");

			// Validate kernels from transaction. Kernel are a source of truth
			// Because of account transfer we might have 2 transactions with same kernel from the both sides.
			let mut txkernel_to_txuuid: HashMap<String, Vec<TxUuidPlus>> = HashMap::new();

			for (tx_uuid, tx) in &mut transactions {
				if tx.tx_log.kernel_excess.is_some() {
					// check if we need to reset tx confirmation first.
					if tx.tx_log.confirmed {
						if let Some(lookup_min_heihgt) = tx.tx_log.kernel_lookup_min_height {
							if lookup_min_heihgt >= start_height {
								tx.tx_log.confirmed = false;
								tx.updated = true;
							}
						}

						if tx.tx_log.output_height >= start_height {
							tx.tx_log.confirmed = false;
							tx.updated = true;
						}
					}

					if !tx.tx_log.confirmed {
						tx.kernel_validation = Some(false);
						let kernel = mwc_util::to_hex(&tx.tx_log.kernel_excess.clone().ok_or(Error::GenericError("get_wallet_and_chain_data internal error, tx.tx_log.kernel_excess is empty".into()))?.0);

						if let Some(v) = txkernel_to_txuuid.get_mut(&kernel) {
							v.push(tx_uuid.clone());
						} else {
							txkernel_to_txuuid.insert(kernel, vec![tx_uuid.clone()]);
						}
					}
				}
			}

			let client = wallet.w2n_client().clone();
			let keychain = wallet.keychain(secp, keychain_mask)?;

			let mut blocks: Vec<mwc_api::BlockPrintable> = Vec::new();

			let mut cur_height = start_height;
			while cur_height <= end_height {
				// next block to request the data
				// SYNC_BLOCKS_THREADS is the fixed value 4, so 4 * 4 - 1 is exactly 15.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "SYNC_BLOCKS_THREADS is the compile-time constant 4"
				)]
				let request_span = SYNC_BLOCKS_THREADS * SYNC_BLOCKS_THREADS - 1;
				let request_span = u64::try_from(request_span).map_err(|e| {
					Error::DataOverflow(format!(
						"scan::get_wallet_and_chain_data, block scan request span does not fit u64, request_span={} error={}",
						request_span, e
					))
				})?;
				// cur_height <= end_height is the loop condition. Limiting the increment
				// to the remaining range proves both operations stay within end_height.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the increment is bounded by end_height - cur_height"
				)]
				let next_h = cur_height + cmp::min(request_span, end_height - cur_height);

				if is_scan_interrupted(context_id) {
					return Err(Error::Interrupted);
				}

				// printing the progress
				if show_progress || status_callback.is_some() {
					// next_h is between cur_height and cur_height + request_span (15),
					// so this inclusive block count is in 1..=16.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "next_h is bounded to cur_height..=cur_height + 15"
					)]
					let block_count = next_h - cur_height + 1;
					let msg = format!(
						"Checking {} blocks, Height: {} - {}",
						block_count, cur_height, next_h,
					);
					// 10 - 90 %
					// let perc_complete = ((next_h + cur_height) / 2 - start_height) * 80
					//	/ (end_height - start_height + 1)
					//	+ 10;

					// next_h >= cur_height, and adding half their at-most-15-block
					// difference cannot exceed next_h.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the ordered heights differ by at most the 15-block request span"
					)]
					let midpoint = cur_height + (next_h - cur_height) / 2;
					let scan_range = scan_height_span.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"scan::get_wallet_and_chain_data, inclusive block scan range overflow, start_height={} end_height={}",
							start_height, end_height
						))
					})?;
					// midpoint is within the validated scan range, so this subtraction is safe.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "midpoint is bounded by start_height and end_height"
					)]
					let completed_span = midpoint - start_height;
					let scaled_progress = completed_span.checked_mul(80).ok_or_else(|| {
						Error::DataOverflow(format!(
							"scan::get_wallet_and_chain_data, block scan progress multiplication overflow, completed_span={} scale=80",
							completed_span
						))
					})?;
					// scan_range is an inclusive range and therefore nonzero. The quotient is
					// at most 80, so adding the ten-percent offset cannot overflow.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "scan_range is nonzero and the bounded quotient is at most 80"
					)]
					let perc_complete = scaled_progress / scan_range + 10;
					let perc_complete = u8::try_from(perc_complete).map_err(|e| {
						Error::DataOverflow(format!(
							"scan::get_wallet_and_chain_data, block scan progress does not fit u8, percentage={} error={}",
							perc_complete, e
						))
					})?;
					info!("{} ({}% complete)", msg, perc_complete);
					send_status(
						status_callback,
						StatusMessage::Scanning(show_progress, msg, perc_complete),
					);
				}

				let requested_blocks =
					client.get_blocks_by_height(cur_height, next_h, SYNC_BLOCKS_THREADS)?;
				session.ensure_connection(&client, "Wallet block scan")?;
				blocks.extend(requested_blocks);
				if next_h == end_height {
					break;
				}
				// next_h < end_height here, so next_h is below u64::MAX.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "next_h is strictly below end_height and therefore below u64::MAX"
				)]
				{
					cur_height = next_h + 1;
				}
			}
			// Checking blocks...
			// Let's check if all heights are there. Sorry, have issues, little paranoid, assuming node can be broken
			blocks.sort_by_key(|block| block.header.height);
			let block_heights: Vec<u64> = blocks.iter().map(|b| b.header.height).collect();
			let expected_blocks = scan_height_span.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::get_wallet_and_chain_data, expected block count overflow, start_height={} end_height={}",
					start_height, end_height
				))
			})?;
			let actual_blocks = u64::try_from(block_heights.len()).map_err(|e| {
				Error::DataOverflow(format!(
					"scan::get_wallet_and_chain_data, returned block count does not fit u64, block_count={} error={}",
					block_heights.len(), e
				))
			})?;
			if actual_blocks != expected_blocks {
				return Err(Error::Node("Unable to get all blocks data".to_string()))?;
			}
			if block_heights.first().copied() != Some(start_height)
				|| block_heights.last().copied() != Some(end_height)
			{
				return Err(Error::Node(
					"Get not expected blocks from the node".to_string(),
				))?;
			}
			if block_heights.len() > 1 {
				for i in 1..block_heights.len() {
					// The loop starts at one, so the preceding index cannot underflow.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the loop range starts at index one"
					)]
					let previous_index = i - 1;
					let previous = block_heights.get(previous_index).copied().ok_or_else(|| {
						Error::GenericError(format!(
							"scan::get_wallet_and_chain_data, missing previous sorted block height, previous_index={} block_count={}",
							previous_index,
							block_heights.len()
						))
					})?;
					let current = block_heights.get(i).copied();
					let expected_height = previous
						.checked_add(1)
						.ok_or_else(|| {
							Error::DataOverflow(format!(
								"scan::get_wallet_and_chain_data, consecutive block height overflow, previous_height={} increment=1",
								previous
							))
						})?;
					if Some(expected_height) != current {
						return Err(Error::Node(
							"Get duplicated blocks from the node".to_string(),
						))?;
					}
				}
			}
			for adjacent in blocks.windows(2) {
				let previous = &adjacent[0].header;
				let current = &adjacent[1].header;
				if current.previous != previous.hash {
					return Err(Error::Node(format!(
						"Wallet block scan returned a disconnected chain between heights {} and {}",
						previous.height, current.height
					)));
				}
			}
			if end_height == session.anchor.height
				&& blocks.last().map(|block| block.header.hash.as_str())
					!= Some(session.anchor.hash.as_str())
			{
				return Err(Error::Node(format!(
					"Wallet block scan tip does not match anchor at height {}",
					session.anchor.height
				)));
			}

			// commit, range_proof, is_coinbase, block_height, mmr_index,
			let mut node_outputs: Vec<(
				pedersen::Commitment,
				pedersen::RangeProof,
				bool,
				u64,
				u64,
			)> = Vec::new();
			// iputs - it is outputs that are gone
			let mut inputs: HashSet<String> = HashSet::new();

			for b in blocks {
				let height = b.header.height;

				inputs.extend(b.inputs);

				// Update transaction confirmation state, if kernel is found
				for tx_kernel in b.kernels {
					if let Some(tx_uuid_vec) = txkernel_to_txuuid.get(&tx_kernel.excess) {
						for tx_uuid in tx_uuid_vec {
							let tx = transactions.get_mut(tx_uuid).ok_or(Error::GenericError(
								format!(
									"get_wallet_and_chain_data internal error, not found expected transaction {:?}",
									tx_uuid
								),
							))?;
							tx.kernel_validation = Some(true);
							tx.tx_log.output_height = height; // Height must come from kernel and will match heights of outputs
							tx.updated = true;
						}
					}
				}

				for out in b.outputs {
					if !out.spent {
						node_outputs.push((
							out.commit,
							out.range_proof()?,
							match out.output_type {
								mwc_api::OutputType::Coinbase => true,
								mwc_api::OutputType::Transaction => false,
							},
							height,
							out.mmr_index,
						));
					}
				}
			}
			let mut should_self_spent = false;
			let mut self_spent_amount = 0;
			if let Some(conf) = replay_config {
				if conf.replay_mitigation_flag {
					should_self_spent = true;
					self_spent_amount = conf.replay_mitigation_min_amount;
				}
			}

			// Parse all node_outputs from the blocks and check ours the new ones...
			let output_pair = identify_utxo_outputs(
				secp,
				wallet.get_context_id(),
				&keychain,
				node_outputs,
				Some(end_height),
				should_self_spent,
				self_spent_amount,
			)?;

			chain_outs = output_pair.0;
			self_spend_candidate_list = output_pair.1;

			// Reporting user what outputs we found
			if show_progress || status_callback.is_some() {
				let mut msg = format!(
					"For height: {} - {} Identified {} wallet_outputs as belonging to this wallet [",
					start_height,
					end_height,
					chain_outs.len(),
				);
				let mut cnt: u8 = 8;
				for ch_out in &chain_outs {
					msg.push_str(&mwc_util::to_hex(&ch_out.commit.0));
					msg.push_str(",");
					// cnt starts at eight, and the loop breaks immediately when it reaches zero.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the loop breaks on zero before another subtraction"
					)]
					{
						cnt -= 1;
					}
					if cnt == 0 {
						break;
					}
				}
				if !chain_outs.is_empty() {
					msg.pop();
				}
				if cnt == 0 {
					msg.push_str("...");
				}
				msg.push_str("]");

				info!("{}", msg);
				send_status(
					status_callback,
					StatusMessage::Scanning(show_progress, msg, 99),
				);
			}

			// Apply inputs - outputs that are spent (they are inputs now)
			for out in outputs
				.values_mut()
				.filter(|out| inputs.contains(&out.commit))
			{
				// Commit is input now, so it is spent
				out.output.status = OutputStatus::Spent;
				out.updated = true;
			}
		} else {
			debug!("get_wallet_and_chain_data using check whatever needed strategy");
			// Full data update.
			let client = wallet.w2n_client().clone();
			let keychain = wallet.keychain(secp, keychain_mask)?;

			// Retrieve the actual PMMR index range we're looking for
			let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;
			session.ensure_connection(&client, "Wallet scan PMMR range")?;

			// Getting outputs that are published on the chain.
			let chain_outs_pair = collect_chain_outputs_bound(
				secp,
				wallet.get_context_id(),
				&keychain,
				client,
				session.connection,
				pmmr_range.0,
				PmmrEndExpectation::Exact(pmmr_range.1),
				show_progress,
				replay_config,
				status_callback,
			)?;
			chain_outs = chain_outs_pair.0;
			self_spend_candidate_list = chain_outs_pair.1;

			// Reporting user what outputs we found
			if show_progress || status_callback.is_some() {
				let mut msg = format!(
					"For height: {} - {} PMMRs: {} - {} Identified {} wallet_outputs as belonging to this wallet [",
					start_height,
					end_height,
					pmmr_range.0,
					pmmr_range.1,
					chain_outs.len(),
				);
				for ch_out in &chain_outs {
					msg.push_str(&mwc_util::to_hex(&ch_out.commit.0));
					msg.push_str(",");
				}
				if !chain_outs.is_empty() {
					msg.pop();
				}
				msg.push_str("]");

				info!("{}", msg);
				send_status(
					status_callback,
					StatusMessage::Scanning(show_progress, msg, 99),
				);
			}

			if is_scan_interrupted(context_id) {
				return Err(Error::Interrupted);
			}

			// Validate kernels from transaction. Kernel are a source of truth
			let client = wallet.w2n_client().clone();
			for tx in transactions.values_mut() {
				if !(tx.tx_log.confirmed || tx.tx_log.is_cancelled_reverted())
					|| tx.tx_log.output_height >= start_height
					|| start_height < 2
				{
					// Skipping old coinbase transaction that are not confirmed
					// A tip below 500 intentionally clamps this historical cutoff to genesis.
					if tx.tx_log.tx_type == TxLogEntryType::ConfirmedCoinbase
						&& tx.tx_log.output_height < end_height.saturating_sub(500)
					{
						continue;
					}

					if let Some(kernel) = &tx.tx_log.kernel_excess {
						// Note!!!! Test framework doesn't support None for params. So assuming that value must be provided
						let start_height = cmp::max(start_height, 1); // API to tests don't support 0 or smaller
						let res = client.get_kernel(
							&kernel,
							Some(cmp::min(
								start_height, // 1 is min supported value by API
								cmp::max(
									1,
									tx.tx_log.kernel_lookup_min_height.unwrap_or(start_height),
								),
							)),
							Some(end_height),
						)?;
						session.ensure_connection(&client, "Wallet scan kernel validation")?;

						match res {
							Some((txkernel, height, _mmr_index)) => {
								if txkernel.excess != *kernel {
									return Err(Error::Node(format!(
										"scan::validate_transactions, node returned a different kernel, requested_kernel={:?} returned_kernel={:?}",
										kernel, txkernel.excess
									)));
								}
								tx.kernel_validation = Some(true);
								tx.tx_log.output_height = height; // Height must come from kernel and will match heights of outputs
								tx.updated = true;
							}
							None => tx.kernel_validation = Some(false),
						}
					}
				}
			}

			// Validate all 'active output' - Unspend and Locked if they still on the chain
			// Spent and Unconfirmed news should come from the updates
			let mut wallet_outputs_to_check: Vec<pedersen::Commitment> = Vec::new();

			for out in outputs.values() {
				if out.output.is_spendable() && !out.commit.is_empty() {
					let commit = out.output.commit.as_ref().ok_or(Error::GenericError(
						"get_wallet_and_chain_data internal error, out.output.commit is empty"
							.into(),
					))?;
					// A malformed commitment means corrupted wallet state; it must not
					// be silently excluded from node validation.
					let hex = mwc_util::from_hex(commit).map_err(|e| {
						Error::GenericError(format!(
							"get_wallet_and_chain_data, unable to decode commitment of spendable output {}, {}",
							commit, e
						))
					})?;
					wallet_outputs_to_check.push(pedersen::Commitment::from_vec(hex)?);
				}
			}

			// Large output-detail queries take time. Chunk size is 200 ids.

			let mut commits: HashMap<pedersen::Commitment, NodeOutputDetails> = HashMap::new();

			if wallet_outputs_to_check.len() > 100 {
				let msg = format!(
					"You have {} active outputs, it is a large number, validation will take time. Please wait...",
					wallet_outputs_to_check.len()
				);
				warn!("{}", msg);
				send_status(status_callback, StatusMessage::Warning(msg));

				// processing them by groups becuase we want to shouw the progress
				let slices: Vec<&[pedersen::Commitment]> =
					wallet_outputs_to_check.chunks(100).collect();

				if is_scan_interrupted(context_id) {
					return Err(Error::Interrupted);
				}

				for (chunk_num, chunk) in slices.iter().enumerate() {
					if show_progress || status_callback.is_some() {
						let scaled_chunk = chunk_num.checked_mul(100).ok_or_else(|| {
							Error::DataOverflow(format!(
								"scan::get_wallet_and_chain_data, output validation progress multiplication overflow, chunk_num={} scale=100",
								chunk_num
							))
						})?;
						// slices is nonempty because this branch requires more than 100 outputs.
						#[allow(
							clippy::arithmetic_side_effects,
							reason = "the output list is nonempty before it is divided into slices"
						)]
						let progress = scaled_chunk / slices.len();
						let progress = u8::try_from(progress).map_err(|e| {
							Error::DataOverflow(format!(
								"scan::get_wallet_and_chain_data, output validation progress does not fit u8, progress={} error={}",
								progress, e
							))
						})?;
						info!("Validating outputs ({}% complete)", progress);
						send_status(
							status_callback,
							StatusMessage::Scanning(
								show_progress,
								"Validating outputs".to_owned(),
								progress,
							),
						);
					}

					commits.extend(client.get_outputs_from_node(&chunk.to_vec())?);
					session.ensure_connection(&client, "Wallet scan output validation")?;
				}

				if show_progress || status_callback.is_some() {
					info!("Finished outputs validation");
					send_status(
						status_callback,
						StatusMessage::ScanningComplete(
							show_progress,
							"Finish outputs validation".to_owned(),
						),
					);
				}
			} else {
				commits = client.get_outputs_from_node(&wallet_outputs_to_check)?;
				session.ensure_connection(&client, "Wallet scan output validation")?;
			}

			// Updating commits data with that
			// Key: commt, Value Heihgt
			let node_commits: HashMap<String, u64> = commits
				.values()
				.map(|details| (details.commit.clone(), details.height))
				.collect();

			for out in outputs
				.values_mut()
				.filter(|out| out.output.is_spendable() && out.output.commit.is_some())
			{
				if let Some(height) = node_commits.get(&out.commit) {
					// A positive lookup by commitment must not be overridden later by
					// omission from the independently paginated PMMR listing. Negative
					// state transitions are only safe when every consulted view agrees
					// that the output is absent.
					out.at_chain = true;
					if out.output.height != *height {
						out.output.height = *height;
						out.updated = true;
					}
				} else {
					// Commit is gone. Probably it is spent
					// Initial state 'Unspent' is possible if user playing with cancellations. So just ignore it
					// Next workflow will take case about the transaction state as well as Spent/Unconfirmed uncertainty
					out.output.status = match &out.output.status {
						OutputStatus::Locked => OutputStatus::Spent,
						OutputStatus::Unspent => OutputStatus::Reverted,
						a => a.clone(),
					};
					out.updated = true;
				}
			}
		}

		// Now let's process inputs from transaction that change it's status from confirmed to non confirmed
		// the issue that some Spent can be exist on the chain and they must be turn to Locked for now
		let mut commits: HashSet<String> = HashSet::new();

		for tx in transactions.values() {
			if let Some(kernel_validation) = tx.kernel_validation {
				if tx.tx_log.confirmed && kernel_validation == false {
					// All input commits need to reevaluate
					commits.extend(tx.input_commit.clone());
				}
			}
		}

		commits.retain(|c| outputs.contains_key(c));

		if !commits.is_empty() {
			let wallet_outputs_to_check: Vec<pedersen::Commitment> = commits
				.iter()
				.map(|out| {
					let hex = mwc_util::from_hex(out).map_err(|e| {
						Error::GenericError(format!("Unable to parse HEX commit {}, {}", out, e))
					})?;
					Ok(pedersen::Commitment::from_vec(hex)?)
				})
				.collect::<Result<Vec<_>, Error>>()?;

			let client = wallet.w2n_client().clone();

			// Node will return back only Commits that are exist now.
			let active_commits = client.get_outputs_from_node(&wallet_outputs_to_check)?;
			session.ensure_connection(&client, "Wallet scan locked-output validation")?;

			for details in active_commits.values() {
				let output = outputs.get_mut(&details.commit).ok_or(Error::GenericError(
					"Node return unknown commit value".to_string(),
				))?;
				if output.output.status != OutputStatus::Locked {
					output.output.status = OutputStatus::Locked;
					output.updated = true;
				}
			}
		}
	}

	// All duplicate-commitment records collected while loading the wallet are
	// reconciled explicitly now that the chain data is available.
	if !duplicate_wallet_outputs.is_empty() {
		reconcile_duplicate_wallet_outputs(
			wallet,
			secp,
			keychain_mask,
			&mut outputs,
			duplicate_wallet_outputs,
			&chain_outs,
			&self_spend_candidate_list,
			&transactions,
			session,
		)?;
	}

	// Do not self-spend while this function still owns a snapshot of the old
	// wallet state. The caller first reconciles and persists that snapshot, then
	// restores and groups missing replay candidates before creating ordinary
	// batched self-sends. This prevents stale scan data from overwriting their new
	// locks.
	Ok((
		outputs,
		chain_outs,
		transactions,
		last_output,
		self_spend_candidate_list,
	))
}

/// Prepare fail-closed status repairs for one duplicate-commitment set.
///
/// The canonical record may remain spendable only when the node confirms that
/// the commitment is live. A negative lookup repairs it along with every other
/// spendable copy and returns the repaired version for the in-memory scan map.
fn prepare_duplicate_output_repairs(
	commit: &str,
	records: &[OutputData],
	canonical_index: usize,
	live_output_exists: bool,
) -> Result<(OutputData, bool, Vec<OutputData>), Error> {
	let mut canonical = records.get(canonical_index).cloned().ok_or_else(|| {
		Error::GenericError(format!(
			"scan::reconcile_duplicate_wallet_outputs, canonical record {} is missing for commitment {}",
			canonical_index, commit
		))
	})?;
	let mut canonical_repaired = false;
	let mut repairs = Vec::new();

	for (index, record) in records.iter().enumerate() {
		// Only a positive node lookup proves that the canonical copy can remain
		// spendable. With a negative lookup, every spendable copy is stale.
		if !record.is_spendable() || (live_output_exists && index == canonical_index) {
			continue;
		}

		let mut repaired_record = record.clone();
		repaired_record.status = match &record.status {
			OutputStatus::Locked => OutputStatus::Spent,
			OutputStatus::Unspent => OutputStatus::Reverted,
			// is_spendable() restricts this branch to Unspent or Locked.
			other => other.clone(),
		};
		warn!(
			"scan::reconcile_duplicate_wallet_outputs, repairing stale duplicate record for commitment {} with key id {} from {:?} to {:?}",
			commit, record.key_id, record.status, repaired_record.status
		);

		if index == canonical_index {
			canonical = repaired_record.clone();
			canonical_repaired = true;
		}
		repairs.push(repaired_record);
	}

	Ok((canonical, canonical_repaired, repairs))
}

/// Reconcile wallet records that share the same cached commitment.
///
/// The scan map is keyed by commitment while the backend stores output records
/// by key id and MMR index, so loading the wallet into the map would otherwise
/// silently drop every duplicate but one from validation, repair and
/// persistence. The record at the live chain position (or, when the commitment
/// is not live in the scanned data, the record referenced by a transaction,
/// otherwise the first one seen) is canonical and keeps its place in the map. A
/// positive node lookup preserves that canonical record and repairs every other
/// spendable copy. A negative lookup repairs every spendable copy, including
/// the canonical record; otherwise replacing the already-validated map entry
/// with an older canonical record could resurrect an absent output as
/// spendable. Repairs use Unspent -> Reverted and Locked -> Spent, mirroring the
/// scan's gone-from-chain transition. Non-spendable duplicates are inert
/// history and are left untouched. No record is deleted.
fn reconcile_duplicate_wallet_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	duplicate_wallet_outputs: HashMap<String, Vec<OutputData>>,
	chain_outs: &[OutputResult],
	self_spend_candidates: &[OutputResult],
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let node_client = wallet.w2n_client().clone();
	let mut repairs: Vec<OutputData> = Vec::new();

	for (commit, records) in duplicate_wallet_outputs {
		// At most one of the records can be the live chain output for this
		// commitment. The scanned chain data identifies it directly; if the
		// commitment is not part of the scanned data, ask the node whether it
		// is live at all before deciding.
		let live_mmr_index = chain_outs
			.iter()
			.chain(self_spend_candidates.iter())
			.find(|chain_out| mwc_util::to_hex(&chain_out.commit.0) == commit)
			.map(|chain_out| chain_out.mmr_index);
		let live_mmr_index = match live_mmr_index {
			Some(mmr_index) => Some(mmr_index),
			None => {
				let commit_bytes = mwc_util::from_hex(&commit).map_err(|e| {
					Error::GenericError(format!(
						"scan::reconcile_duplicate_wallet_outputs, unable to decode commitment {}, {}",
						commit, e
					))
				})?;
				let live = node_client
					.get_outputs_from_node(&vec![pedersen::Commitment::from_vec(commit_bytes)?])?;
				session
					.ensure_connection(&node_client, "Wallet duplicate output reconciliation")?;
				live.values().next().map(|details| details.mmr_index)
			}
		};

		let canonical_index = match live_mmr_index {
			Some(mmr_index) => records
				.iter()
				.position(|record| record.mmr_index == Some(mmr_index))
				.unwrap_or_else(|| {
					records
						.iter()
						.position(|record| record.tx_log_entry.is_some())
						.unwrap_or(0)
				}),
			None => records
				.iter()
				.position(|record| record.tx_log_entry.is_some())
				.unwrap_or(0),
		};

		let (canonical, canonical_repaired, record_repairs) = prepare_duplicate_output_repairs(
			&commit,
			&records,
			canonical_index,
			live_mmr_index.is_some(),
		)?;
		repairs.extend(record_repairs);

		// The last record read won the map slot while loading the wallet, and
		// that is not necessarily the canonical one. A repaired canonical must
		// also replace itself so the map cannot retain its stale spendable state.
		let needs_replace = canonical_repaired
			|| match outputs.get(&commit) {
				Some(current) => {
					current.output.key_id != canonical.key_id
						|| current.output.mmr_index != canonical.mmr_index
				}
				None => true,
			};
		if needs_replace {
			let mut info = WalletOutputInfo::new(canonical);
			for tx in transactions.values() {
				if tx.input_commit.contains(&commit) {
					info.add_tx_input_uuid(&tx.tx_uuid);
				}
				if tx.output_commit.contains(&commit) {
					info.add_tx_output_uuid(&tx.tx_uuid);
				}
			}
			info.updated = true;
			outputs.insert(commit.clone(), info);
		}
	}

	if !repairs.is_empty() {
		let mut batch = wallet.batch(secp, keychain_mask)?;
		for repaired_record in repairs {
			batch.save(repaired_record)?;
		}
		session.verify_anchor(&node_client, "Wallet duplicate output reconciliation")?;
		batch.commit()?;
	}
	Ok(())
}

/// Scan outputs with a given rewind hash view wallet.
/// Retrieve all outputs information that belongs to it.
pub fn scan_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	rewind_hash: Zeroizing<String>,
	start_height: u64,
	end_height: u64,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};
	client.reset_cache();
	let header = client.get_header_info(end_height)?;
	let anchor = ChainTip {
		height: end_height,
		hash: header.hash,
	};
	scan_rewind_hash_with_anchor(wallet_inst, secp, rewind_hash, start_height, anchor, None)
}

pub(crate) fn scan_rewind_hash_with_anchor<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	rewind_hash: Zeroizing<String>,
	start_height: u64,
	anchor: ChainTip,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	info!("Starting UTXO scan");
	send_status(
		status_callback,
		StatusMessage::Scanning(true, "Starting UTXO scan".to_owned(), 0),
	);

	let (client, context_id) = {
		wallet_lock!(wallet_inst, w);
		let client = w.w2n_client().clone();
		(client, w.get_context_id())
	};
	let session = NodeReadSession::bind(&client, anchor.clone(), "View-wallet scan")?;

	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(anchor.height))?;
	session.ensure_connection(&client, "View-wallet scan PMMR range")?;

	let chain_outs = collect_chain_outputs_rewind_hash(
		secp,
		context_id,
		&client,
		&session,
		rewind_hash,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_callback,
	)?;
	// The live tip is allowed to advance while the scan runs. Re-read the header
	// at the original anchor height instead: an ordinary chain extension preserves
	// that hash, while a reorg affecting the scanned range changes it.
	// Note this proves header integrity only: the pages above read the node's
	// live unspent set, so an accepted extension can still have changed which
	// outputs this pass saw (a post-anchor spend removes the old output while
	// its replacement sits above the anchored PMMR bound). That single-pass
	// inaccuracy is accepted by design; see the comment on
	// owner::scan_rewind_hash_with_anchor.
	session.verify_anchor(&client, "View-wallet scan")?;

	let msg = format!(
		"Matched {} outputs with this rewind hash; matches are not proof of spend ownership",
		chain_outs.output_result.len(),
	);
	info!("{}", msg);
	send_status(status_callback, StatusMessage::Scanning(true, msg, 99));
	info!("Scanning complete");
	send_status(
		status_callback,
		StatusMessage::ScanningComplete(true, "Rewind-hash scan complete".to_owned()),
	);
	Ok(chain_outs)
}

pub(crate) fn scan_with_session<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	del_unconfirmed: bool,
	start_height: u64,
	tip_height: u64,
	show_progress: bool,
	do_full_outputs_refresh: bool,
	session: &NodeReadSession,
	status_callback: Option<&StatusCallback<'_>>,
) -> Result<Option<u64>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if session.anchor.height != tip_height {
		return Err(Error::Node(format!(
			"Wallet scan anchor height {} does not match requested tip height {}",
			session.anchor.height, tip_height
		)));
	}

	// First, get a definitive list of outputs we own from the chain.
	if show_progress {
		info!("Starting UTXO scan");
	}
	send_status(
		status_callback,
		StatusMessage::Scanning(show_progress, "Starting UTXO scan".to_owned(), 0),
	);

	// Collect the data form the chain and from the wallet
	let replay_config = get_replay_config(wallet.get_context_id());
	let (mut outputs, mut chain_outs, mut transactions, last_output, mut replay_candidates) =
		get_wallet_and_chain_data(
			wallet,
			secp,
			keychain_mask.clone(),
			start_height,
			tip_height,
			show_progress,
			status_callback,
			do_full_outputs_refresh,
			Some(replay_config.clone()),
			session,
		)?;
	session.verify_anchor(wallet.w2n_client(), "Wallet scan")?;

	// Height-based replay detection deliberately trusts the configured node's
	// inclusion height and may therefore authorize a defensive self-spend. This
	// is the wallet's explicit deployment model: users are expected to connect
	// to their own trusted private node. Wallets which still have transaction
	// history add a second, immediate signal: a currently unspent commitment was
	// already consumed by a transaction whose kernel remains on this chain.
	// This path deliberately does not use the two-day build-height tolerance.
	let confirmed_history_spends = if replay_config.replay_mitigation_flag {
		collect_transaction_history_spends(wallet, &transactions)?
	} else {
		HashSet::new()
	};
	replay_candidates.append(&mut take_transaction_history_replay_candidates(
		&mut chain_outs,
		&confirmed_history_spends,
		&replay_config,
	));
	let replay_candidate_commits: HashSet<String> = replay_candidates
		.iter()
		.map(|candidate| mwc_util::ToHex::to_hex(&candidate.commit))
		.collect();
	// A posted self-spend is not resolved until the replayed commitment is
	// removed from the chain UTXO set. Keep every unresolved candidate inside
	// subsequent incremental scan ranges by asking the owner workflow to retain
	// its cursor immediately before the earliest candidate block. This also
	// makes an explicit cancellation or a construction failure retryable on the
	// next ordinary wallet refresh without persistent transaction metadata. A
	// transaction saved before a failed post remains active for manual repost or
	// cancellation and therefore continues to hold this cursor.
	let replay_rescan_height = replay_candidates
		.iter()
		.map(|candidate| candidate.height.saturating_sub(1))
		.min();

	// Printing values for debug...
	/*	{
		println!("Chain range: Heights: {} to {}", start_height, tip_height );
		// Dump chain outputs...
		for ch_out in &chain_outs {
			println!("Chain output: {:?}", ch_out );
		}

		println!("outputs len is {}", outputs.len());
		for o in &outputs {
			println!("{}  =>  {:?}", o.0, o.1 );
		}

		println!("transactions len is {}", transactions.len());
		for t in &transactions {
			println!("{}  =>  {:?}", t.0, t.1 );
		}
	}*/

	// It is a safe height, we can't rollback there at node level. A young chain
	// intentionally clamps the additional two-day archive margin to genesis.
	let archive_height = Chain::height_2_archive_height(wallet.get_context_id(), tip_height)
		.saturating_sub(DAY_HEIGHT * 2);

	// Validated outputs states against the chain
	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();
	let outputs2del = validate_outputs(
		wallet,
		secp,
		keychain_mask.clone(),
		start_height,
		&chain_outs,
		&mut outputs,
		&transactions,
		&mut found_parents,
		session,
	)?;

	// Processing slate based transactions. Just need to update 'confirmed flag' and height
	// We don't want to cancel the transactions. Let's user do that.
	// We can uncancel transactions if it is confirmed
	validate_transactions(
		wallet,
		keychain_mask,
		&mut transactions,
		&outputs,
		&replay_candidate_commits,
		session,
	)?;

	// Checking for output to transaction mapping. We don't want to see active outputs without trsansaction or with cancelled transactions
	// we might unCancel transaction if output was found but all mapped transactions are cancelled (user just a cheater)
	let duplicated_coinbase_txs =
		validate_outputs_ownership(wallet, &mut outputs, &mut transactions, session)?;

	// A normal active sender which consumes a currently detected replay output
	// already protects that output. Preserve the whole logical self-send during
	// scan cleanup without adding persistent metadata.
	let active_receiver_uuids: HashSet<String> = transactions
		.values()
		.filter(|tx| {
			!tx.tx_log.confirmed
				&& !tx.tx_log.is_cancelled_reverted()
				&& tx.tx_log.tx_type == TxLogEntryType::TxReceived
		})
		.map(|tx| tx.tx_uuid.uuid_str.clone())
		.collect();
	let protected_replay_tx_uuids: HashSet<String> = transactions
		.values()
		.filter(|tx| {
			!tx.tx_log.confirmed
				&& !tx.tx_log.is_cancelled_reverted()
				&& tx.tx_log.tx_type == TxLogEntryType::TxSent
				&& active_receiver_uuids.contains(&tx.tx_uuid.uuid_str)
				&& tx
					.input_commit
					.iter()
					.any(|commit| replay_candidate_commits.contains(commit))
		})
		.map(|tx| tx.tx_uuid.uuid_str.clone())
		.collect();

	// Delete any unconfirmed outputs (requested by user), unlock any locked outputs and delete (cancel) associated transactions
	if del_unconfirmed {
		delete_unconfirmed(&mut outputs, &mut transactions, &protected_replay_tx_uuids)?;
	}

	// Let's check the consistency. Report is we found any discrepency, so users can do the check or restore.
	{
		validate_consistancy(&mut outputs, &transactions);
	}

	// Here we are done with all state changes of Outputs and transactions. Now we need to save them at the DB
	// Note, unknown new outputs are not here because we handle them in the beginning by 'restore'.

	// Apply last data updates and saving the data into DB.
	{
		store_transactions_outputs(
			wallet,
			secp,
			keychain_mask.clone(),
			&outputs2del,
			&mut outputs,
			tip_height,
			&last_output,
			&transactions,
			&duplicated_coinbase_txs,
			archive_height,
			session,
		)?;
	}

	// Replay construction must use the candidate output's account, not whichever
	// account happens to be active. Record all candidate paths up front and make
	// sure seed-restored paths have labels before account-directed transaction
	// construction begins.
	for replay_output in &replay_candidates {
		record_found_parent(&mut found_parents, replay_output)?;
	}
	{
		session.verify_anchor(wallet.w2n_client(), "Wallet label restoration")?;
		restore_labels(wallet, secp, keychain_mask.clone(), &found_parents)?;
	}

	// Reconcile and persist the ordinary scan snapshot before creating replay
	// mitigation transactions. Missing candidates are restored, then each
	// account's candidates are selected and locked by bounded self-send batches.
	restore_and_self_spend_replay_candidates(
		wallet,
		secp,
		keychain_mask,
		replay_candidates,
		tip_height,
		&outputs,
		&transactions,
		&mut found_parents,
		session,
	)?;

	// Update the wallet-global height at which this scan finished reconciling data.
	{
		let node_client = wallet.w2n_client().clone();
		let mut batch = wallet.batch(secp, keychain_mask)?;
		batch.save_last_confirmed_height(tip_height)?;
		session.verify_anchor(&node_client, "Wallet scan completion")?;
		batch.commit()?;
	}

	// Cancel any cancellable transactions with an expired TTL
	// We need to do that at the end when all scan data is updated and written. Otherwise data can be overwritten on updates
	{
		// The four-day filter only bounds which *confirmed* entries are loaded;
		// the TTL loop below skips those anyway, so the reference height cannot
		// affect cancellation outcomes (see the doc on updater::retrieve_txs).
		// The scan anchor is passed simply because it is already validated and
		// avoids a redundant node round-trip — and its failure mode — at the
		// end of an otherwise completed scan.
		let transactions = updater::retrieve_txs(
			wallet,
			keychain_mask,
			None,
			None,
			None,
			None,
			false,
			None,
			None,
			Some(session.anchor.height),
		)?;

		let mut seen_slate_ids = HashSet::new();
		let mut expired_slate_ids = Vec::new();
		let mut expired_without_slate = Vec::new();
		for tx_log in &transactions {
			if tx_log.confirmed || tx_log.is_cancelled_reverted() {
				continue;
			}

			if let Some(h) = tx_log.ttl_cutoff_height {
				if tip_height >= h {
					match tx_log.tx_slate_id {
						Some(slate_id) if seen_slate_ids.insert(slate_id) => {
							expired_slate_ids.push(slate_id)
						}
						Some(_) => {}
						None => {
							expired_without_slate.push((tx_log.parent_key_id.clone(), tx_log.id))
						}
					}
				}
			}
		}

		// A slate UUID is the logical transaction identity and can be shared by
		// several log entries (including entries in different accounts). Select the
		// whole group once so tx::cancel_tx stages it through one backend batch.
		// Legacy entries without a slate UUID remain independent ID-scoped groups.
		//
		// TTL cancellation is best-effort housekeeping, not part of scan success.
		// The reconciled scan state has already been committed above, so a failure
		// to cancel one expired transaction does not invalidate the scan. Log the
		// failure, report it through the optional status callback, and continue; a
		// later scan can retry the still-active expired transaction.
		for slate_id in expired_slate_ids {
			if let Err(e) = tx::cancel_tx(wallet, secp, keychain_mask, None, None, Some(slate_id)) {
				let msg = format!(
					"Unable to cancel TTL expired transaction {} because of error: {}",
					slate_id, e
				);
				warn!("{}", msg);
				send_status(status_callback, StatusMessage::Warning(msg));
			}
		}

		for (parent_key_id, tx_id) in expired_without_slate {
			if let Err(e) = tx::cancel_tx(
				wallet,
				secp,
				keychain_mask,
				Some(&parent_key_id),
				Some(tx_id),
				None,
			) {
				let msg = format!(
					"Unable to cancel TTL expired transaction {} because of error: {}",
					Uuid::nil(),
					e
				);
				warn!("{}", msg);
				send_status(status_callback, StatusMessage::Warning(msg));
			}
		}
	}

	/*	{
		// Dump chain outputs...
		for ch_out in &chain_outs {
			println!("End Chain output: {:?}", ch_out );
		}

		println!("End outputs len is {}", outputs.len());
		for o in &outputs {
			println!("{}  =>  {:?}", o.0, o.1 );
		}

		println!("End transactions len is {}", transactions.len());
		for t in &transactions {
			println!("{}  =>  {:?}", t.0, t.1 );
		}

		println!("------------------ scan END -----------------------------" );
	}*/

	if show_progress {
		info!("Scanning complete");
	}
	send_status(
		status_callback,
		StatusMessage::ScanningComplete(show_progress, "Scanning Complete".to_owned()),
	);

	Ok(replay_rescan_height)
}

// Validated outputs states against the chain
// Returns Output that need to be deleted. It is possible because
// We might find that Key Id is broken and Outputs are stored by this key_id.
// That is why we need to delete prev copy.
fn validate_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	start_height: u64,
	chain_outs: &Vec<OutputResult>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transaction: &HashMap<TxUuidPlus, WalletTxInfo>,
	found_parents: &mut HashMap<Identifier, u32>,
	session: &NodeReadSession,
) -> Result<Vec<OutputData>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// This is a final mutation-boundary check. PMMR collectors validate the
	// untrusted page metadata earlier, while this also protects block-based scans
	// and future callers from restoring one commitment or PMMR position twice.
	let mut seen_chain_commitments: HashSet<[u8; 33]> = HashSet::new();
	let mut seen_chain_mmr_indices: HashSet<u64> = HashSet::new();
	for chain_out in chain_outs {
		if !seen_chain_commitments.insert(chain_out.commit.0) {
			return Err(Error::Node(format!(
				"Wallet scan returned output {} more than once",
				mwc_util::ToHex::to_hex(&chain_out.commit)
			)));
		}
		if !seen_chain_mmr_indices.insert(chain_out.mmr_index) {
			return Err(Error::Node(format!(
				"Wallet scan returned PMMR index {} more than once",
				chain_out.mmr_index
			)));
		}
	}

	let output_creators = build_output_creator_map(transaction);

	let mut outputs2del: Vec<OutputData> = Vec::new();

	// Update wallet outputs with found at the chain outputs
	// Check how sync they are
	for ch_out in chain_outs {
		let commit = mwc_util::to_hex(&ch_out.commit.0);

		match outputs.get_mut(&commit) {
			Some(w_out) => {
				// w_out - is wallet outputs that match chain output ch_out.
				// It is mean that w_out does exist at the chain (confirmed) and doing well
				w_out.at_chain = true;

				// Sync up the data. ch_out is source of truth
				if !ch_out.params_equal_to(&w_out.output) {
					// Some parameters can be updated. ch_out is source if truth
					outputs2del.push(w_out.output.clone());
					ch_out.params_push_to(&mut w_out.output);
					w_out.updated = true;
				}

				// The rangeproof-authenticated key is also the source of truth for
				// account ownership. Keep root_key_id, the account-local transaction
				// link and the next-child counter in sync with it even when the other
				// cached output parameters already match.
				let recovered_parent = record_found_parent(found_parents, ch_out)?;
				if reconcile_wallet_output_parent(
					&mut w_out.output,
					&recovered_parent,
					&commit,
					&output_creators,
					transaction,
				) {
					w_out.updated = true;
				}

				// Validating status of the output.
				match w_out.output.status {
					OutputStatus::Spent => {
						// Spent output not supposed to exist at the chain. Seems like send transaction is not at the chain yet.
						// Reverting state to Locked
						match &w_out.output.commit {
							Some(commit) => {
								warn!("Changing status for output {} from Spent to Locked", commit)
							}
							None => warn!(
								"Changing status for coin base output at height {} from Spent to Locked",
								w_out.output.height
							),
						}
						w_out.updated = true;
						w_out.output.status = OutputStatus::Locked;
					}
					OutputStatus::Unconfirmed | OutputStatus::Reverted => {
						// Very expected event. Output is at the chain and we get a confirmation.
						match &w_out.output.commit {
							Some(commit) => info!(
								"Changing status for output {} from Unconfirmed/Reverted to Unspent",
								commit
							),
							None => info!(
								"Changing status for coin base output at height {} from Unconfirmed/Reverted to Unspent",
								w_out.output.height
							),
						}
						w_out.updated = true;
						w_out.output.status = OutputStatus::Unspent; // confirmed...
					}
					OutputStatus::Unspent => (), // Expected, Unspend is confirmed.
					OutputStatus::Locked => (),  // Expected, Locked is confirmed. Send still in progress
				};
			}
			None => {
				// Spotted unknown output. Probably another copy of wallet send it or it is a backup data?
				// In any case it is pretty nice output that we can spend.
				// Just create a new transaction for this output.
				warn!(
					"Confirmed output for {} with ID {} ({:?}, index {}) exists in UTXO set but not in wallet. Restoring.",
					ch_out.value, ch_out.key_id, ch_out.commit, ch_out.mmr_index
				);
				restore_missing_output(
					wallet,
					secp,
					keychain_mask,
					ch_out.clone(),
					&output_creators,
					transaction,
					found_parents,
					session,
				)?;
			}
		}
	}

	// Process not found at the chain but expected outputs.
	// It is a normal case when send transaction was finalized
	for w_out in outputs.values_mut() {
		if w_out.output.height >= start_height && !w_out.at_chain {
			match w_out.output.status {
				OutputStatus::Spent => (), // Spent not expected to be found at the chain
				OutputStatus::Unconfirmed | OutputStatus::Reverted => (), // Unconfirmed/Reverted are not expected as well
				OutputStatus::Unspent => {
					// Unspent not found - likely it is reorg and that is why the last transaction can't be confirmed now.
					warn!(
						"Changing status for output {} from Unspent to Unconfirmed",
						w_out.commit
					);
					w_out.updated = true;
					w_out.output.status = OutputStatus::Reverted;
				}
				OutputStatus::Locked => {
					// Locked is not on the chain is expected, It is mean that our send transaction was confirmed.
					info!(
						"Changing status for output {} from Locked to Spent",
						w_out.commit
					);
					w_out.updated = true;
					w_out.output.status = OutputStatus::Spent;
				}
			};
		}
	}

	Ok(outputs2del)
}

// Processing slate based transactions. Just need to update 'confirmed flag' and height
// We don't want to cancel the transactions. Let's user do that.
// We can uncancel transactions if it is confirmed
fn validate_transactions<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	_keychain_mask: Option<&SecretKey>,
	transactions: &mut HashMap<TxUuidPlus, WalletTxInfo>,
	outputs: &HashMap<String, WalletOutputInfo>,
	replay_candidate_commits: &HashSet<String>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for tx_info in transactions.values_mut() {
		// Checking the kernel - the source of truth for transactions
		if let Some(kernel_validation) = tx_info.kernel_validation {
			if kernel_validation {
				// transaction is valid
				let mut change_update_sent = false;
				if tx_info.tx_log.is_cancelled_reverted() {
					tx_info.tx_log.uncancel_unrevert();
					tx_info.updated = true;

					warn!(
						"Changing transaction {} from Canceled to active and confirmed",
						tx_info.tx_uuid.uuid_str
					);
					change_update_sent = true;
				}

				if !tx_info.tx_log.confirmed {
					tx_info.tx_log.confirmed = true;

					// The kernel was just proven to be on chain, so this header
					// exists; a read failure is a node/transport problem and must
					// not leave a confirmed record without its confirmation data.
					let hdr_info = wallet
						.w2n_client()
						.get_header_info(tx_info.tx_log.output_height)
						.map_err(|e| {
							Error::Node(format!(
								"Wallet transaction validation failed to read header at height {}: {}",
								tx_info.tx_log.output_height, e
							))
						})?;
					session
						.ensure_connection(wallet.w2n_client(), "Wallet transaction validation")?;
					tx_info
						.tx_log
						.update_confirmation_ts(hdr_info.confirmed_time)?;
					tx_info.updated = true;

					if !change_update_sent {
						info!(
							"Changing transaction {} state to confirmed",
							tx_info.tx_uuid.uuid_str
						);
					}
				}
			} else {
				if !tx_info.tx_log.is_cancelled_reverted() {
					if tx_info.tx_log.confirmed {
						tx_info.tx_log.confirmed = false;
						tx_info.updated = true;
						tx_info.tx_log.tx_type = match &tx_info.tx_log.tx_type {
							TxLogEntryType::TxReceived => {
								tx_info.tx_log.reverted_after = match tx_info
									.tx_log
									.confirmation_ts
									.as_ref()
								{
									Some(confirmed_at) => {
										let now = chrono::Utc::now();
										let seconds = now
												.timestamp()
												.checked_sub(confirmed_at.timestamp())
												.ok_or_else(|| {
													Error::DataOverflow(format!(
												"scan::validate_transactions, reverted duration subtraction overflow, now_timestamp={} confirmation_timestamp={}",
												now.timestamp(),
												confirmed_at.timestamp()
													))
												})?;
										// A valid block timestamp may be ahead of the wallet's
										// clock. Clamp this informational duration so it cannot
										// prevent the transaction from being marked reverted.
										let seconds = seconds.max(0);
										let seconds = u64::try_from(seconds).map_err(|e| {
											Error::DataOverflow(format!(
												"scan::validate_transactions, reverted duration does not fit u64, seconds={} error={}",
												seconds, e
											))
										})?;
										Some(std::time::Duration::from_secs(seconds))
									}
									None => None,
								};
								TxLogEntryType::TxReverted
							}
							t => t.clone(),
						};
						warn!(
							"Changing transaction {} state to reverted (unconfirmed)",
							tx_info.tx_uuid.uuid_str
						);
					}
				}
			}
		}

		update_non_kernel_transaction(wallet, tx_info, outputs, replay_candidate_commits, session)?;

		// Update confirmation flag fr the cancelled.
		if tx_info.tx_log.is_cancelled_reverted() {
			if tx_info.tx_log.confirmed {
				tx_info.tx_log.confirmed = false;
				tx_info.updated = true;
			}
		}
	}

	Ok(())
}

fn transaction_uuid_state_counts(
	tx_uuids: &HashSet<TxUuidPlus>,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
) -> (usize, usize) {
	// A slate UUID identifies one logical transaction, but self-sends can create
	// several account-local log entries for it. The logical transaction remains
	// active while any member is active. Missing map targets are also treated as
	// active: incomplete bookkeeping must not unlock a reserved wallet output.
	let mut active_uuids: HashSet<&str> = HashSet::new();
	let mut cancelled_uuids: HashSet<&str> = HashSet::new();
	for tx_uuid in tx_uuids {
		if transactions
			.get(tx_uuid)
			.map(|tx| tx.tx_log.is_cancelled_reverted())
			.unwrap_or(false)
		{
			cancelled_uuids.insert(tx_uuid.uuid_str.as_str());
		} else {
			active_uuids.insert(tx_uuid.uuid_str.as_str());
		}
	}

	let fully_cancelled = cancelled_uuids.difference(&active_uuids).count();
	(active_uuids.len(), fully_cancelled)
}

fn canonical_coinbase_transaction(
	output: &OutputData,
	candidates: &[TxUuidPlus],
) -> Option<TxUuidPlus> {
	let parent_key_id = mwc_util::to_hex(&output.root_key_id.to_bytes());
	if let Some(tx_log_entry) = output.tx_log_entry {
		if let Some(candidate) = candidates.iter().find(|candidate| {
			candidate.id == tx_log_entry && candidate.parent_key_id == parent_key_id
		}) {
			return Some(candidate.clone());
		}
	}

	// Every valid ConfirmedCoinbase candidate belongs to output.root_key_id;
	// coinbase transactions cannot be shared across accounts like self-sends.
	// A different parent_key_id here is malformed legacy metadata (older code
	// could store the output child key as the transaction parent), not evidence
	// that one transaction belongs to multiple accounts. Do not filter those
	// records out: this branch intentionally collapses broken legacy duplicates.
	// Keep the choice stable rather than depending on HashSet iteration order.
	candidates
		.iter()
		.min_by(|left, right| {
			left.parent_key_id
				.cmp(&right.parent_key_id)
				.then_with(|| left.id.cmp(&right.id))
				.then_with(|| left.uuid_str.cmp(&right.uuid_str))
		})
		.cloned()
}

// Checking for output to transaction mapping. We don't want to see active outputs without trsansaction or with cancelled transactions
// we might unCancel transaction if output was found but all mapped transactions are cancelled (user just a cheater)
fn validate_outputs_ownership<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &mut HashMap<TxUuidPlus, WalletTxInfo>,
	session: &NodeReadSession,
) -> Result<Vec<TxLogEntry>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut duplicated_coinbase_tx_ids: HashSet<TxUuidPlus> = HashSet::new();
	for w_out in outputs.values_mut() {
		// For every output checking to how many transaction it belong as Input and Output

		// Because of Account to account transactions (any type self transactions) we can have pairs.
		// Those pairs should be processed as a single transaction, overwise it will be guarantee
		// false collision reporting
		let (in_active, in_cancelled) =
			transaction_uuid_state_counts(&w_out.tx_input_uuid, transactions);
		let (out_active, out_cancelled) =
			transaction_uuid_state_counts(&w_out.tx_output_uuid, transactions);

		// Commit can belong to 1 transaction only. Other wise it is a transaction issue.
		// Fortunatelly transaction issue doesn't affect the balance of send logic.
		// So we can just report to user that he can't trust the transactions Data
		if out_active > 1 {
			// If it is mining transaction with a single output, we can fix that.

			let mut collided_coinbase_txs: Vec<TxUuidPlus> = Vec::new();
			for tx_uuid in &w_out.tx_output_uuid {
				if let Some(tx) = transactions.get(tx_uuid) {
					if tx.tx_log.tx_type == TxLogEntryType::ConfirmedCoinbase {
						collided_coinbase_txs.push(tx_uuid.clone());
					}
				}
			}

			if collided_coinbase_txs.len() > 1 {
				let canonical =
					canonical_coinbase_transaction(&w_out.output, &collided_coinbase_txs)
						.ok_or_else(|| {
							Error::GenericError(
								"Unable to select a canonical duplicate coinbase transaction"
									.to_owned(),
							)
						})?;
				if w_out.output.tx_log_entry != Some(canonical.id) {
					w_out.output.tx_log_entry = Some(canonical.id);
					w_out.updated = true;
				}
				for tx_uuid in collided_coinbase_txs {
					if tx_uuid != canonical {
						duplicated_coinbase_tx_ids.insert(tx_uuid);
					}
				}
			} else {
				report_transaction_collision(
					wallet.get_context_id(),
					&w_out.commit,
					&w_out.tx_output_uuid,
					&transactions,
					false,
				);
			}
		}

		if in_active > 1 {
			report_transaction_collision(
				wallet.get_context_id(),
				&w_out.commit,
				&w_out.tx_input_uuid,
				&transactions,
				true,
			);
		}

		match w_out.output.status {
			OutputStatus::Locked => {
				if in_active == 0 {
					// it is not Locked, it must be active output
					match &w_out.output.commit {
						Some(commit) => warn!(
							"Changing status for output {} from Locked to Unspent",
							commit
						),
						None => warn!(
							"Changing status for output at height {} from Locked to Unspent",
							w_out.output.height
						),
					}
					w_out.output.status = OutputStatus::Unspent;
					w_out.updated = true;
				}
				if out_active == 0 && out_cancelled > 0 {
					recover_first_cancelled(wallet, &w_out.tx_output_uuid, transactions, session)?;
				}
			}
			OutputStatus::Spent => {
				// output have to have some valid transation. User cancel all of them?
				if out_active == 0 && out_cancelled > 0 {
					recover_first_cancelled(wallet, &w_out.tx_output_uuid, transactions, session)?;
				}
				if in_active == 0 && in_cancelled > 0 {
					recover_first_cancelled(wallet, &w_out.tx_input_uuid, transactions, session)?;
				}
			}
			OutputStatus::Unconfirmed | OutputStatus::Reverted => {
				// Unconfirmed can be anything. We can delete that output
			}
			OutputStatus::Unspent => {
				// output have to have some valid transaction that created it. User cancel all of them?
				if in_active > 0 {
					// it is not Locked, it must be active output
					match &w_out.output.commit {
						Some(commit) => warn!(
							"Changing status for output {} from Unspent to Locked",
							commit
						),
						None => warn!(
							"Changing status for output at height {} from Unspent to Locked",
							w_out.output.height
						),
					}
					w_out.output.status = OutputStatus::Locked;
					w_out.updated = true;
				}
				if out_active == 0 && out_cancelled > 0 {
					recover_first_cancelled(wallet, &w_out.tx_output_uuid, transactions, session)?;
				}
			}
		}
	}

	// Keep the in-memory view consistent with the deletion set so the final
	// persistence pass cannot re-save a transaction that it just deleted.
	for w_out in outputs.values_mut() {
		w_out
			.tx_input_uuid
			.retain(|tx_uuid| !duplicated_coinbase_tx_ids.contains(tx_uuid));
		w_out
			.tx_output_uuid
			.retain(|tx_uuid| !duplicated_coinbase_tx_ids.contains(tx_uuid));
	}

	let mut duplicated_coinbase_txs = Vec::with_capacity(duplicated_coinbase_tx_ids.len());
	for tx_uuid in duplicated_coinbase_tx_ids {
		let tx_info = transactions.remove(&tx_uuid).ok_or_else(|| {
			Error::GenericError(format!(
				"Duplicate coinbase transaction disappeared before cleanup, id={} parent={}",
				tx_uuid.id, tx_uuid.parent_key_id
			))
		})?;
		duplicated_coinbase_txs.push(tx_info.tx_log);
	}
	duplicated_coinbase_txs.sort_by(|left, right| {
		left.parent_key_id
			.to_bytes()
			.cmp(&right.parent_key_id.to_bytes())
			.then_with(|| left.id.cmp(&right.id))
	});

	Ok(duplicated_coinbase_txs)
}

// Delete any unconfirmed outputs (requested by user), unlock any locked outputs and delete (cancel) associated transactions
fn delete_unconfirmed(
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &mut HashMap<TxUuidPlus, WalletTxInfo>,
	protected_tx_uuids: &HashSet<String>,
) -> Result<(), Error> {
	let mut transaction2cancel: HashSet<TxUuidPlus> = HashSet::new();
	// A scan may be asked to clean unrelated unconfirmed transactions. Do not
	// interpret that bulk cleanup as the user's explicit cancellation of a
	// normal transaction which is currently spending a detected replay output.
	// No marker is needed: the ordinary active sender and its input commitments
	// completely describe the reservation.
	for w_out in outputs.values_mut() {
		match w_out.output.status {
			OutputStatus::Locked => {
				if w_out
					.tx_input_uuid
					.iter()
					.any(|tx| protected_tx_uuids.contains(&tx.uuid_str))
				{
					continue;
				}
				match &w_out.output.commit {
					Some(commit) => warn!(
						"Changing status for output {} from Locked to Unspent",
						commit
					),
					None => warn!(
						"Changing status for coin base output at height {} from Locked to Unspent",
						w_out.output.height
					),
				}
				w_out.output.status = OutputStatus::Unspent;
				w_out.updated = true;
				for uuid in &w_out.tx_input_uuid {
					transaction2cancel.insert(uuid.clone());
				}
			}
			OutputStatus::Unconfirmed | OutputStatus::Reverted => {
				for uuid in &w_out.tx_output_uuid {
					transaction2cancel.insert(uuid.clone());
				}
			}
			OutputStatus::Unspent | OutputStatus::Spent => (),
		}
	}

	// Cancelling non confirmed transactions without outputs (possible for SP that was never finalized)
	for (uuid, tx) in transactions.iter() {
		if protected_tx_uuids.contains(&uuid.uuid_str) {
			continue;
		}
		if tx.tx_log.tx_type == TxLogEntryType::TxReverted
			|| (!tx.updated && !tx.tx_log.confirmed && !tx.tx_log.is_cancelled())
		{
			transaction2cancel.insert(uuid.clone());
		}
	}

	for tx_uuid in &transaction2cancel {
		if protected_tx_uuids.contains(&tx_uuid.uuid_str) {
			continue;
		}
		if let Some(tx) = transactions.get_mut(tx_uuid) {
			if !tx.tx_log.is_cancelled() {
				// let's cancell transaction
				match tx.tx_log.tx_type {
					TxLogEntryType::TxReverted => {
						tx.tx_log.tx_type = TxLogEntryType::TxReceivedCancelled;
					}
					TxLogEntryType::TxSent => {
						tx.tx_log.tx_type = TxLogEntryType::TxSentCancelled;
					}
					TxLogEntryType::TxReceived => {
						// Note, no reverted because it is a full scan with delete flag. Reverted is not a deleted
						tx.tx_log.tx_type = TxLogEntryType::TxReceivedCancelled;
					}
					TxLogEntryType::ConfirmedCoinbase => {
						// coinbased not confirmed are filtered out. That is why there no needs to change the status
						tx.tx_log.confirmed = false;
					}
					_ => {
						return Err(Error::GenericError(format!(
							"scan::delete_unconfirmed, transaction selected for cancellation has invalid type, tx_uuid={} tx_type={:?}",
							tx_uuid.uuid_str, tx.tx_log.tx_type
						)));
					}
				}
				tx.updated = true;
				warn!("Cancelling transaction {}", tx_uuid.uuid_str);
			}
		}
	}
	Ok(())
}

#[derive(Default)]
struct OutputConsistencyEvidence {
	has_confirmed_reference: bool,
	has_unconfirmed_output_reference: bool,
}

fn collect_output_consistency_evidence<'a>(
	transactions: impl IntoIterator<Item = &'a WalletTxInfo>,
) -> HashMap<&'a str, OutputConsistencyEvidence> {
	let mut evidence_by_commit: HashMap<&str, OutputConsistencyEvidence> = HashMap::new();

	for tx_info in transactions {
		if tx_info.tx_log.is_cancelled_reverted() {
			continue;
		}

		if tx_info.tx_log.confirmed {
			for commit in tx_info.input_commit.iter().chain(&tx_info.output_commit) {
				evidence_by_commit
					.entry(commit.as_str())
					.or_default()
					.has_confirmed_reference = true;
			}
		} else {
			for commit in &tx_info.output_commit {
				evidence_by_commit
					.entry(commit.as_str())
					.or_default()
					.has_unconfirmed_output_reference = true;
			}
		}
	}

	evidence_by_commit
}

// consistency checking. Report is we found any discrepancy, so users can do the check or restore.
// Here not much what we can do because full node scan or restore from the seed is required.
fn validate_consistancy(
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
) {
	// Self-send records can share the complete stored transaction while their
	// account-local kernel validation results differ. Reconcile each commitment
	// once so HashMap iteration order cannot decide its final state. A confirmed
	// reference is stronger evidence than an unconfirmed creator reference.
	for (commit, evidence) in collect_output_consistency_evidence(transactions.values()) {
		if let Some(out) = outputs.get_mut(commit) {
			if evidence.has_confirmed_reference
				&& (out.output.status == OutputStatus::Unconfirmed
					|| out.output.status == OutputStatus::Reverted)
			{
				out.output.status = OutputStatus::Spent;
				out.updated = true;
			} else if !evidence.has_confirmed_reference
				&& evidence.has_unconfirmed_output_reference
				&& out.output.status == OutputStatus::Spent
			{
				out.output.status = OutputStatus::Reverted;
				out.updated = true;
			}
		}
	}
}

fn can_archive_unchanged_transaction(
	tx: &WalletTxInfo,
	outputs: &HashMap<String, WalletOutputInfo>,
	tx_time_to_archive: &chrono::DateTime<Utc>,
	archive_height: u64,
) -> bool {
	let below_archive_horizon = if tx.tx_log.output_height == 0 {
		&tx.tx_log.creation_ts < tx_time_to_archive
	} else {
		tx.tx_log.output_height < archive_height
	};

	if !below_archive_horizon
		|| tx
			.output_commit
			.iter()
			.any(|commit| outputs.contains_key(commit))
	{
		return false;
	}

	// A cancelled/reverted transaction no longer reserves its former inputs.
	// Every other input relationship must disappear from the live namespace
	// before the transaction can move out of the mutable scan set.
	tx.tx_log.is_cancelled_reverted()
		|| tx
			.input_commit
			.iter()
			.all(|commit| !outputs.contains_key(commit))
}

// Apply last data updates and saving the data into DB.
fn store_transactions_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	outputs2del: &Vec<OutputData>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	tip_height: u64, // tip
	last_output: &String,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	duplicated_coinbase_txs: &[TxLogEntry],
	archive_height: u64,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let node_client = wallet.w2n_client().clone();
	let mut batch = wallet.batch(secp, keychain_mask)?;

	for transaction in duplicated_coinbase_txs {
		batch.delete_tx_log_entry(transaction.id, &transaction.parent_key_id)?;
	}

	// This time is secondary, used if TX output_height is not defined
	let archive_reference_time = Utc::now();
	let tx_time_to_archive = archive_reference_time
		.checked_sub_signed(Duration::days(5))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"scan::store_transactions_outputs, transaction archive time overflow, reference_time={} archive_age_days=5",
				archive_reference_time
			))
		})?;

	// Slate based Transacitons
	for tx in transactions.values() {
		if tx.updated {
			batch.save_tx_log_entry(tx.tx_log.clone(), &tx.tx_log.parent_key_id)?;
		} else if can_archive_unchanged_transaction(
			tx,
			outputs,
			&tx_time_to_archive,
			archive_height,
		) {
			// Archive only when no live wallet output remains and no nonterminal
			// input still reserves funds. Pending no-change sends have no wallet-owned
			// output, but their locked inputs must continue to reserve the funds.
			batch.archive_transaction(&tx.tx_log)?;
		}
	}

	// Need delete first and save after. Delete happens on data update, the DB key be the same
	for o2d in outputs2del {
		batch.delete(&o2d.key_id, &o2d.mmr_index)?;
	}

	// Save Slate Outputs to DB
	for output in outputs.values() {
		if output.updated {
			batch.save(output.output.clone())?;
		} else if (output.is_orphan_output() && !output.output.is_coinbase) ||
			// Delete expired mining outputs
			( output.output.is_coinbase && (output.output.status == OutputStatus::Unconfirmed || output.output.status == OutputStatus::Reverted) && ((output.output.height < tip_height) || (output.commit != *last_output)) )
		{
			// Unconfirmed without any transactions must be deleted as well
			warn!(
				"Deleting unconfirmed Output not mapped to any transaction. Commit: {}",
				output
					.output
					.commit
					.clone()
					.unwrap_or("UNKNOWN_COMMIT".to_string())
			);
			batch.delete(&output.output.key_id, &output.output.mmr_index)?;
		} else if !output.updated
			&& !output.output.is_spendable()
			&& output.output.height < archive_height
		{
			// Archiving very old spent output can go into archive
			// we can move only not updated outputs...
			match output.output.status {
				OutputStatus::Spent => {
					// Height needs to come from the transactions. That is the only source of truth
					let mut need_wait = false;
					for tx_id in &output.tx_input_uuid {
						if let Some(tx) = transactions.get(tx_id) {
							if tx.tx_log.output_height != 0
								&& tx.tx_log.output_height >= archive_height
							{
								need_wait = true;
								break;
							}
						}
					}
					if !need_wait {
						batch.archive_output(&output.output)?;
					}
				}
				OutputStatus::Reverted | OutputStatus::Unconfirmed => {
					// check if transactions are not confirmed and not concelled, then we can archive such output
					let mut need_wait = false;
					for tx_id in &output.tx_output_uuid {
						if let Some(tx) = transactions.get(tx_id) {
							if tx.tx_log.tx_type == TxLogEntryType::TxReceived
								|| tx.tx_log.tx_type == TxLogEntryType::TxSent
							{
								need_wait = true;
								break;
							}
						}
					}
					if !need_wait {
						batch.archive_output(&output.output)?;
					}
				}
				_ => {}
			}
		}
	}

	// It is very normal that Wallet has outputs without Transactions.
	// It is a coinbase transactions. Let's create coinbase transactions if they don't exist yet
	// See what updater::apply_api_outputs does
	for w_out in outputs.values_mut() {
		// coinbase non spendable MUST be ignored for mining case. For every coinbase call new commit is created.
		if w_out.output.is_coinbase
			&& w_out.output.is_spendable()
			&& w_out.tx_output_uuid.is_empty()
		{
			let parent_key_id = &w_out.output.root_key_id; // it is Account Key ID.

			let log_id = batch.next_tx_log_id(parent_key_id)?;
			let output_log_id = repaired_coinbase_output_log_id(
				transactions,
				parent_key_id,
				&w_out.commit,
				log_id,
			)?;
			let mut t = TxLogEntry::new(
				parent_key_id.clone(),
				TxLogEntryType::ConfirmedCoinbase,
				log_id,
			);
			t.confirmed = true;
			// output_height must be assigned before the header lookup:
			// TxLogEntry::new initializes it to zero, so looking the header up
			// first would stamp the transaction with the genesis block time.
			t.output_height = w_out.output.height;
			t.amount_credited = w_out.output.value;
			t.amount_debited = 0;
			t.num_outputs = 1;
			let hdr_info = node_client.get_header_info(t.output_height).map_err(|e| {
				Error::Node(format!(
					"Wallet output storage failed to read header at height {}: {}",
					t.output_height, e
				))
			})?;
			session.ensure_connection(&node_client, "Wallet output storage")?;
			t.update_confirmation_ts(hdr_info.confirmed_time)?;
			// calculate kernel excess for coinbase
			if let Some(commit) = &w_out.output.commit {
				let over_commit = secp.commit_value(w_out.output.value)?;
				let commit =
					pedersen::Commitment::from_vec(mwc_util::from_hex(commit).map_err(|e| {
						Error::GenericError(format!("Output commit parse error, {}", e))
					})?)?;
				t.output_commits = vec![commit.clone()];
				let excess = secp.commit_sum(vec![commit], vec![over_commit])?;
				t.kernel_excess = Some(excess);
				t.kernel_lookup_min_height = Some(w_out.output.height);
			}
			w_out.output.tx_log_entry = Some(output_log_id);

			batch.save_tx_log_entry(t, parent_key_id)?;
			batch.save(w_out.output.clone())?;
		}
	}

	session.verify_anchor(&node_client, "Wallet output storage")?;
	batch.commit()?;

	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NonKernelTransactionEvidence {
	Confirmed,
	Unconfirmed,
	Unknown,
}

fn non_kernel_transaction_evidence(
	tx_info: &WalletTxInfo,
	outputs: &HashMap<String, WalletOutputInfo>,
	replay_candidate_commits: &HashSet<String>,
) -> NonKernelTransactionEvidence {
	// A mapped input which is currently in the UTXO set proves that this
	// transaction is not its current spender. Known replay candidates are the
	// exception: their earlier spending transaction deliberately remains the
	// history proof used to create protection when no active spend exists.
	let has_live_non_replay_input = tx_info.input_commit.iter().any(|commit| {
		!replay_candidate_commits.contains(commit)
			&& outputs.get(commit).is_some_and(|output| output.at_chain)
	});
	if has_live_non_replay_input {
		return NonKernelTransactionEvidence::Unconfirmed;
	}

	// Only current-chain presence is positive confirmation evidence. In
	// particular, a stale Spent or Locked status must not newly confirm a legacy
	// transaction whose kernel is unavailable.
	let has_live_output = tx_info
		.output_commit
		.iter()
		.any(|commit| outputs.get(commit).is_some_and(|output| output.at_chain));
	if has_live_output {
		return NonKernelTransactionEvidence::Confirmed;
	}

	let has_unconfirmed_output = tx_info.output_commit.iter().any(|commit| {
		outputs.get(commit).is_some_and(|output| {
			matches!(
				output.output.status,
				OutputStatus::Unconfirmed | OutputStatus::Reverted
			)
		})
	});
	if has_unconfirmed_output {
		NonKernelTransactionEvidence::Unconfirmed
	} else {
		NonKernelTransactionEvidence::Unknown
	}
}

fn update_non_kernel_transaction<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	tx_info: &mut WalletTxInfo,
	outputs: &HashMap<String, WalletOutputInfo>,
	replay_candidate_commits: &HashSet<String>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Handle legacy broken data whose transaction kernel is unavailable.
	// Records old enough to lack this metadata are expected to be far below the
	// active scan horizon. This fallback reconciles their recorded state; it is
	// not expected to rediscover or replace their historical confirmation height.
	if tx_info.tx_log.kernel_excess.is_none() {
		match non_kernel_transaction_evidence(tx_info, outputs, replay_candidate_commits) {
			NonKernelTransactionEvidence::Confirmed => {
				if tx_info.tx_log.is_cancelled_reverted() {
					tx_info.tx_log.uncancel_unrevert();
					tx_info.updated = true;
				}
				if !tx_info.tx_log.confirmed {
					tx_info.tx_log.confirmed = true;
					// At least one output mapped to this transaction was proven to
					// be on chain, so this header exists; a read failure is a
					// node/transport problem and must not leave a confirmed
					// record without its confirmation data.
					let hdr_info = wallet
						.w2n_client()
						.get_header_info(tx_info.tx_log.output_height)
						.map_err(|e| {
							Error::Node(format!(
								"Wallet legacy transaction validation failed to read header at height {}: {}",
								tx_info.tx_log.output_height, e
							))
						})?;
					session.ensure_connection(
						wallet.w2n_client(),
						"Wallet legacy transaction validation",
					)?;
					tx_info
						.tx_log
						.update_confirmation_ts(hdr_info.confirmed_time)?;
					tx_info.updated = true;
				}
			}
			NonKernelTransactionEvidence::Unconfirmed => {
				if tx_info.tx_log.confirmed {
					tx_info.tx_log.confirmed = false;
					tx_info.updated = true;
				}
			}
			NonKernelTransactionEvidence::Unknown => {}
		}
	}
	Ok(())
}

// restore labels, account paths and child derivation indices
fn next_restore_account_label(
	existing_labels: &mut HashSet<String>,
	account_index: &mut usize,
) -> Result<String, Error> {
	loop {
		let label = format!("account_{}", account_index);
		*account_index = account_index.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"scan::next_restore_account_label, restored account index overflow, account_index={} increment=1",
				account_index
			))
		})?;
		if existing_labels.insert(label.clone()) {
			return Ok(label);
		}
	}
}

fn restore_labels<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	found_parents: &HashMap<Identifier, u32>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let accounts: Vec<AcctPathMapping> = wallet.acct_path_iter()?.collect();
	let account_paths: HashSet<Identifier> = accounts
		.iter()
		.map(|mapping| mapping.path.clone())
		.collect();
	let mut account_labels: HashSet<String> = accounts
		.iter()
		.map(|mapping| mapping.label.clone())
		.collect();
	let mut acct_index = accounts.len();
	for (path, max_child_index) in found_parents.iter() {
		// Only restore paths that don't exist
		if !account_paths.contains(path) {
			let label = next_restore_account_label(&mut account_labels, &mut acct_index)?;
			warn!("Setting account {} at path {}", label, path);
			keys::set_acct_path(wallet, secp, keychain_mask, &label, path)?;
		}
		let current_child_index = wallet.current_child_index(&path)?;
		if *max_child_index >= current_child_index {
			let mut batch = wallet.batch(secp, keychain_mask)?;
			let next_child_index = max_child_index.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"scan::restore_labels, restored child index overflow, max_child_index={} increment=1",
					max_child_index
				))
			})?;
			debug!("Next child for account {} is {}", path, next_child_index);
			batch.save_child_index(path, next_child_index)?;
			batch.commit()?;
		}
	}

	Ok(())
}

// Report to user about transactions that point to the same output.
fn report_transaction_collision(
	context_id: u32,
	commit: &String,
	tx_uuid: &HashSet<TxUuidPlus>,
	transactions: &HashMap<TxUuidPlus, WalletTxInfo>,
	inputs: bool,
) {
	// We don't want to report collision for old transactions. Migration could be a reason. Those messages
	// are aknowledged and users didn't recreate the wallet to get rid of them.
	// 4-5 month from now transaction should be valid. Expected that all users are migrated the wallet by that time
	let height_limit = if global::is_mainnet(context_id) {
		450_000
	} else {
		500_000
	};

	let countable_txs = tx_uuid
		.iter()
		.map(|tx_uuid| transactions.get(tx_uuid))
		.filter(|wtx| {
			wtx.map(|tx| tx.tx_log.output_height > height_limit)
				.unwrap_or(false)
		})
		.count();

	if countable_txs == 0 {
		// No report for legacy transactions.
		return;
	}

	let mut cancelled_tx = String::new();
	tx_uuid
		.iter()
		.filter_map(|tx_uuid| transactions.get(tx_uuid))
		.filter(|wtx| !wtx.tx_log.is_cancelled_reverted())
		.for_each(|wtx| {
			if !cancelled_tx.is_empty() {
				cancelled_tx.push_str(", ");
			}
			cancelled_tx.push_str(&format!("{}", wtx.tx_uuid.uuid_str));
		});

	let inputs = if inputs { "inputs" } else { "outputs" };

	// Do not emit this through the scan status callback. A persistent collision is
	// rediscovered on every scan update, so it would repeatedly show a noisy,
	// non-actionable warning to the user. A regular log warning is sufficient.
	warn!(
		"We detected transaction collision on {} {} for transactions with Id {}",
		inputs, commit, cancelled_tx
	);
}

// By some reasons output exist but all related transactions are cancelled. Let's activate one of them
// Note! There is no analisys what transaction to activate. As a result that can trigger the transaction collision.
// We don't want to implement complicated algorithm to handle that. User suppose to be sane and not cancell transactions without reason.
fn recover_first_cancelled<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	tx_uuid: &HashSet<TxUuidPlus>,
	transactions: &mut HashMap<TxUuidPlus, WalletTxInfo>,
	session: &NodeReadSession,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// let's revert first non cancelled
	for uuid in tx_uuid {
		if let Some(wtx) = transactions.get_mut(uuid) {
			if wtx.tx_log.is_cancelled_reverted() {
				let prev_tx_state = wtx.tx_log.tx_type.clone();
				wtx.tx_log.tx_type = match wtx.tx_log.tx_type {
					TxLogEntryType::TxReceivedCancelled | TxLogEntryType::TxReverted => {
						wtx.tx_log.reverted_after = None;
						TxLogEntryType::TxReceived
					}
					TxLogEntryType::TxSentCancelled => TxLogEntryType::TxSent,
					_ => {
						return Err(Error::GenericError(
							"Expected a cancelled transaction while recovering wallet state"
								.to_string(),
						));
					}
				};
				wtx.tx_log.confirmed = true;
				// The transaction is being recovered because its outputs were
				// found on chain, so this header exists; a read failure is a
				// node/transport problem and must not leave a recovered record
				// without its confirmation data.
				let hdr_info = wallet
					.w2n_client()
					.get_header_info(wtx.tx_log.output_height)
					.map_err(|e| {
						Error::Node(format!(
							"Wallet cancelled transaction recovery failed to read header at height {}: {}",
							wtx.tx_log.output_height, e
						))
					})?;
				session.ensure_connection(
					wallet.w2n_client(),
					"Wallet cancelled transaction recovery",
				)?;
				wtx.tx_log.update_confirmation_ts(hdr_info.confirmed_time)?;
				wtx.updated = true;
				warn!(
					"Changing transaction {} state from {:?} to {:?}",
					wtx.tx_uuid.uuid_str, prev_tx_state, wtx.tx_log.tx_type
				);

				break;
			}
		}
	}
	Ok(())
}

/// Create a normal self-send from an exact set of wallet outputs. The full
/// input amount includes the fee, so the transaction has one receiver output
/// and no change. Persist it before posting so a node error leaves a visible,
/// locked transaction that can be reposted or cancelled through normal APIs.
pub(crate) fn self_spend_selected_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	output_vec: HashSet<String>,
	address: Option<String>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if output_vec.is_empty() {
		return Err(Error::GenericError(
			"scan::self_spend_selected_outputs, at least one output is required".to_owned(),
		));
	}

	let context_id = wallet.get_context_id();
	let args = InitTxArgs {
		src_acct_name: address.clone(),
		amount,
		amount_includes_fee: Some(true),
		minimum_confirmations: 0,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		outputs: Some(output_vec),
		ttl_blocks: None,
		..Default::default()
	};

	let mut tx_session_send = TxSession::new();
	let mut tx_session_receive = TxSession::new();
	let mut slate;
	{
		//send
		slate = owner::init_send_tx(
			wallet,
			secp,
			keychain_mask,
			&mut Some(&mut tx_session_send),
			&args,
			#[cfg(feature = "test-support")]
			false,
			1,
		)?;
		//receiver
		let mut dest_account_name: Option<String> = None;
		if let Some(address) = &address {
			dest_account_name = Some(address.clone());
		}
		slate = foreign::receive_tx(
			wallet,
			secp,
			keychain_mask,
			&mut tx_session_receive,
			&slate,
			address.clone(),
			None,
			None,
			&dest_account_name,
			None,
			#[cfg(feature = "test-support")]
			false,
			false,
		)?
		.0;
		owner::tx_lock_outputs(
			wallet,
			secp,
			keychain_mask,
			&mut Some(&mut tx_session_send),
			&slate,
			address,
			0,
			#[cfg(feature = "test-support")]
			false,
		)?;
		slate = owner::finalize_tx(
			wallet,
			secp,
			keychain_mask,
			&mut Some(&mut tx_session_send),
			&slate,
			false,
			#[cfg(feature = "test-support")]
			false,
			false,
		)?
		.0;
	}
	let client = {
		// Test keychain mask, to keep API consistent
		let _ = wallet.keychain(secp, keychain_mask)?;
		wallet.w2n_client().clone()
	};

	if tx_session_send.get_context_participant().is_some()
		|| tx_session_receive.get_context_participant().is_some()
	{
		return Err(Error::GenericError(
			"scan::self_spend_selected_outputs, transaction session participant was already initialized"
				.to_string(),
		));
	}

	let transaction = slate.tx_or_err()?.clone();

	// The transaction is finalized and both private contexts were cleared. Save
	// the normal transaction and its locks before its first node submission.
	let mut batch = wallet.batch(secp, keychain_mask)?;
	tx_session_send.save_tx_data_into_batch(&mut *batch, secp, &slate.id)?;
	tx_session_receive.save_tx_data_into_batch(&mut *batch, secp, &slate.id)?;
	batch.commit()?;
	owner::post_tx(context_id, &client, &transaction, false)?;

	Ok(())
}

#[cfg(test)]
mod scan_consistency_tests {
	use super::*;
	use crate::NodeHeaderLink;
	use mwc_wallet_util::mwc_core::global::ChainTypes;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	use mwc_wallet_util::mwc_keychain::ExtKeychain;
	use mwc_wallet_util::mwc_node_workflow::context::{allocate_new_context, release_context};

	#[test]
	fn interrupt_scan_accepts_allocated_and_rejects_released_context() {
		let context_id = allocate_new_context(
			ChainTypes::AutomatedTesting,
			Some(global::DEFAULT_ACCEPT_FEE_BASE),
			Some(true),
		)
		.expect("a test context should be allocated");

		let interrupt_result = interrupt_scan(context_id);
		let was_interrupted = is_scan_interrupted(context_id);
		release_interrupt_scan(context_id);
		let release_result = release_context(context_id);
		let released_interrupt_result = interrupt_scan(context_id);
		let released_was_interrupted = is_scan_interrupted(context_id);

		assert!(
			interrupt_result.is_ok(),
			"an allocated context should be interruptible: {:?}",
			interrupt_result
		);
		assert!(was_interrupted);
		assert!(
			release_result.is_ok(),
			"the test context should be released: {:?}",
			release_result
		);
		assert!(released_interrupt_result.is_err());
		assert!(!released_was_interrupted);
	}

	#[test]
	fn interrupt_scan_rejects_out_of_range_context() {
		let context_id = u32::MAX;
		release_interrupt_scan(context_id);

		assert!(interrupt_scan(context_id).is_err());
		assert!(!is_scan_interrupted(context_id));
	}

	#[test]
	fn identify_utxo_outputs_skips_unsupported_switch_and_continues() -> Result<(), Error> {
		let context_id = allocate_new_context(
			ChainTypes::AutomatedTesting,
			Some(global::DEFAULT_ACCEPT_FEE_BASE),
			Some(true),
		)
		.expect("a test context should be allocated");

		// Build two valid, wallet-owned outputs. The first deliberately uses the
		// unsupported None switch type; the second proves that best-effort scanning
		// continues and still recovers a subsequent standard Regular output.
		let scan_result: Result<
			(Vec<OutputResult>, Vec<OutputResult>, pedersen::Commitment),
			Error,
		> = (|| {
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let keychain = ExtKeychain::from_seed(&secp, &[42_u8; 32], true)?;
			let builder = proof::ProofBuilder::new(&secp, &keychain)?;
			let height = 30_000;

			let unsupported_id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0)?;
			let unsupported_amount = 17;
			let unsupported_switch = SwitchCommitmentType::None;
			let unsupported_commit = keychain.commit(
				&secp,
				unsupported_amount,
				&unsupported_id,
				unsupported_switch,
			)?;
			let unsupported_proof = proof::create(
				&mut secp,
				&keychain,
				&builder,
				unsupported_amount,
				&unsupported_id,
				unsupported_switch,
				unsupported_commit,
			)?;

			let regular_id = ExtKeychain::derive_key_id(3, 4, 5, 6, 0)?;
			let regular_amount = 19;
			let regular_switch = SwitchCommitmentType::Regular;
			let regular_commit =
				keychain.commit(&secp, regular_amount, &regular_id, regular_switch)?;
			let regular_proof = proof::create(
				&mut secp,
				&keychain,
				&builder,
				regular_amount,
				&regular_id,
				regular_switch,
				regular_commit,
			)?;

			let (wallet_outputs, self_spend_outputs) = identify_utxo_outputs(
				&mut secp,
				context_id,
				&keychain,
				vec![
					(
						unsupported_commit,
						unsupported_proof,
						false,
						height,
						1,
					),
					(regular_commit, regular_proof, false, height, 2),
				],
				Some(height),
				false,
				0,
			)?;
			Ok((wallet_outputs, self_spend_outputs, regular_commit))
		})();

		let release_result = release_context(context_id);
		assert!(
			release_result.is_ok(),
			"the test context should be released: {:?}",
			release_result
		);

		let (wallet_outputs, self_spend_outputs, regular_commit) = scan_result?;
		assert_eq!(wallet_outputs.len(), 1);
		assert_eq!(wallet_outputs[0].commit, regular_commit);
		assert!(self_spend_outputs.is_empty());
		Ok(())
	}

	#[test]
	fn s2c_coinbase_scan_recovers_ordinary_account_key_without_digest() -> Result<(), Error> {
		use mwc_wallet_util::mwc_core::{consensus, core::hash::Hash, libtx::reward};
		let context = allocate_new_context(ChainTypes::Mainnet, None, None)
			.map_err(|e| Error::GenericError(e.to_string()))?;
		let result = (|| {
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let keychain = ExtKeychain::from_seed(&secp, &[88u8; 32], false)?;
			let restored = ExtKeychain::from_seed(&secp, &[88u8; 32], false)?;
			let builder = proof::ProofBuilder::new(&secp, &keychain)?;
			let height = 3_632_000;
			let key = ExtKeychain::derive_key_id(3, 1, 0, 7, 0)?;
			let (output, _, _) = reward::output_s2c(
				context,
				&keychain,
				&builder,
				&key,
				13,
				height,
				&mut secp,
				Hash::from_vec(&[9u8; 32]),
			)?;
			let (found, self_spends) = identify_utxo_outputs(
				&mut secp,
				context,
				&restored,
				vec![(output.commitment(), output.proof, true, height, 1)],
				None,
				false,
				0,
			)?;
			assert_eq!(found.len(), 1);
			assert_eq!(found[0].key_id, key);
			assert_eq!(
				found[0].value,
				consensus::reward(context, 13, height)
					.map_err(|e| Error::GenericError(e.to_string()))?
			);
			assert!(self_spends.is_empty());
			let mut parents = HashMap::new();
			let parent = record_found_parent(&mut parents, &found[0])?;
			assert_eq!(parent, ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?);
			assert_eq!(parents[&parent], 7);
			Ok(())
		})();
		release_context(context).map_err(|e| Error::GenericError(e.to_string()))?;
		result
	}

	#[test]
	fn restored_account_label_skips_an_existing_count_based_name() -> Result<(), Error> {
		let mut labels = HashSet::from(["default".to_owned(), "account_2".to_owned()]);
		let mut account_index = labels.len();

		let restored = next_restore_account_label(&mut labels, &mut account_index)?;

		assert_eq!(restored, "account_3");
		assert!(labels.contains("account_2"));
		assert!(labels.contains("account_3"));
		assert_eq!(account_index, 4);
		Ok(())
	}

	fn node_output(tag: u8, mmr_index: u64) -> NodeOutput {
		let mut commitment = [0_u8; 33];
		commitment[0] = 2;
		commitment[32] = tag;
		(
			pedersen::Commitment(commitment),
			pedersen::RangeProof::zero(),
			false,
			1,
			mmr_index,
		)
	}

	#[test]
	fn pmmr_page_validator_accepts_unique_sparse_pages() {
		let mut validator = PmmrPageValidator::default();
		validator
			.validate(
				"test scan",
				1,
				PmmrEndExpectation::Exact(20),
				1_000,
				20,
				10,
				&[node_output(1, 2), node_output(2, 9)],
			)
			.expect("a structurally valid sparse page should be accepted");
		validator
			.validate(
				"test scan",
				11,
				PmmrEndExpectation::Exact(20),
				1_000,
				20,
				20,
				&[node_output(3, 12), node_output(4, 18)],
			)
			.expect("a valid continuation page should be accepted");
	}

	#[test]
	fn pmmr_page_validator_rejects_commitment_replay_across_pages() {
		let mut validator = PmmrPageValidator::default();
		validator
			.validate(
				"test scan",
				1,
				PmmrEndExpectation::Exact(20),
				1_000,
				20,
				10,
				&[node_output(7, 2)],
			)
			.expect("the first copy should be accepted");

		let error = validator
			.validate(
				"test scan",
				11,
				PmmrEndExpectation::Exact(20),
				1_000,
				20,
				20,
				&[node_output(7, 12)],
			)
			.expect_err("the same commitment at a new index must be rejected");
		assert!(
			error.to_string().contains("output") && error.to_string().contains("more than once")
		);
	}

	#[test]
	fn pmmr_page_validator_rejects_index_replay_and_out_of_page_output() {
		let mut validator = PmmrPageValidator::default();
		let duplicate_index = validator
			.validate(
				"test scan",
				1,
				PmmrEndExpectation::Exact(10),
				1_000,
				10,
				10,
				&[node_output(1, 2), node_output(2, 2)],
			)
			.expect_err("one PMMR position cannot contain two outputs");
		assert!(duplicate_index
			.to_string()
			.contains("PMMR index 2 more than once"));

		let mut validator = PmmrPageValidator::default();
		let outside_page = validator
			.validate(
				"test scan",
				1,
				PmmrEndExpectation::Exact(10),
				1_000,
				10,
				5,
				&[node_output(3, 6)],
			)
			.expect_err("an output beyond the returned page must be rejected");
		assert!(outside_page
			.to_string()
			.contains("outside current page 1-5"));
	}

	#[test]
	fn pmmr_page_validator_requires_the_exact_anchored_end() {
		let mut validator = PmmrPageValidator::default();
		let error = validator
			.validate(
				"anchored scan",
				1,
				PmmrEndExpectation::Exact(20),
				1_000,
				10,
				10,
				&[node_output(1, 2)],
			)
			.expect_err("an anchored scan must not accept a forged lower terminal bound");
		assert!(error.to_string().contains("expected exact anchored end 20"));

		let mut capped_validator = PmmrPageValidator::default();
		capped_validator
			.validate(
				"capped scan",
				1,
				PmmrEndExpectation::AtMost(20),
				1_000,
				10,
				10,
				&[node_output(1, 2)],
			)
			.expect("a generic caller-provided cap may exceed the live PMMR end");
	}

	fn coinbase_output(tx_log_entry: Option<u32>) -> OutputData {
		OutputData {
			root_key_id: Identifier::zero(),
			key_id: Identifier::zero(),
			n_child: 0,
			commit: None,
			mmr_index: Some(1),
			value: 1,
			status: OutputStatus::Unspent,
			height: 1,
			lock_height: 1,
			is_coinbase: true,
			tx_log_entry,
		}
	}

	#[test]
	fn duplicate_repairs_only_preserve_canonical_after_positive_lookup() {
		let mut canonical = coinbase_output(Some(1));
		canonical.mmr_index = Some(10);
		let mut other_copy = coinbase_output(None);
		other_copy.mmr_index = Some(20);
		other_copy.status = OutputStatus::Locked;
		let records = vec![canonical, other_copy];

		let (absent_canonical, absent_canonical_repaired, absent_repairs) =
			prepare_duplicate_output_repairs("test-commitment", &records, 0, false)
				.expect("a valid duplicate set should be repairable");
		assert!(absent_canonical_repaired);
		assert_eq!(absent_canonical.status, OutputStatus::Reverted);
		assert_eq!(absent_repairs.len(), 2);
		assert_eq!(absent_repairs[0].status, OutputStatus::Reverted);
		assert_eq!(absent_repairs[1].status, OutputStatus::Spent);
		assert!(absent_repairs.iter().all(|record| !record.is_spendable()));

		let (live_canonical, live_canonical_repaired, live_repairs) =
			prepare_duplicate_output_repairs("test-commitment", &records, 0, true)
				.expect("a valid duplicate set should be repairable");
		assert!(!live_canonical_repaired);
		assert_eq!(live_canonical.status, OutputStatus::Unspent);
		assert_eq!(live_repairs.len(), 1);
		assert_eq!(live_repairs[0].mmr_index, Some(20));
		assert_eq!(live_repairs[0].status, OutputStatus::Spent);
	}

	#[test]
	fn uncached_output_commit_is_derived_for_scan() {
		let secp =
			Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context should initialize");
		let keychain = ExtKeychain::from_seed(&secp, &[1_u8; 32], true)
			.expect("test keychain should initialize");
		let key_id =
			ExtKeychain::derive_key_id(3, 0, 0, 7, 0).expect("test output path should derive");
		let mut output = coinbase_output(None);
		output.key_id = key_id.clone();
		output.value = 42;

		let expected = mwc_util::to_hex(
			&keychain
				.commit(&secp, output.value, &key_id, SwitchCommitmentType::Regular)
				.expect("test commitment should derive")
				.0,
		);
		let (commit, repaired) = ensure_output_cached_commit(&secp, &keychain, &mut output)
			.expect("scan should derive a missing commitment");

		assert!(repaired);
		assert_eq!(commit, expected);
		assert_eq!(output.commit.as_deref(), Some(expected.as_str()));

		let (cached_commit, repaired_again) =
			ensure_output_cached_commit(&secp, &keychain, &mut output)
				.expect("the cached commitment should remain usable");
		assert!(!repaired_again);
		assert_eq!(cached_commit, expected);
	}

	#[test]
	fn duplicate_coinbase_cleanup_keeps_referenced_transaction() {
		let parent = mwc_util::to_hex(&Identifier::zero().to_bytes());
		let candidates = vec![
			TxUuidPlus::new("second".to_owned(), 2, parent.clone()),
			TxUuidPlus::new("first".to_owned(), 1, parent),
		];
		let canonical = canonical_coinbase_transaction(&coinbase_output(Some(2)), &candidates)
			.expect("a canonical transaction should be selected");
		assert_eq!(canonical.id, 2);

		let canonical = canonical_coinbase_transaction(&coinbase_output(None), &candidates)
			.expect("the deterministic fallback should select a transaction");
		assert_eq!(canonical.id, 1);
	}

	fn test_commitment(tag: u8) -> pedersen::Commitment {
		node_output(tag, u64::from(tag)).0
	}

	fn test_wallet_tx(
		parent: &Identifier,
		id: u32,
		uuid: &str,
		tx_type: TxLogEntryType,
		owned_outputs: Vec<pedersen::Commitment>,
	) -> (TxUuidPlus, WalletTxInfo) {
		let mut tx_log = TxLogEntry::new(parent.clone(), tx_type, id);
		tx_log.output_commits = owned_outputs;
		let tx_uuid = TxUuidPlus::new(uuid.to_owned(), id, mwc_util::to_hex(&parent.to_bytes()));
		let tx_info = WalletTxInfo::new(tx_uuid.clone(), tx_log);
		(tx_uuid, tx_info)
	}

	#[test]
	fn partially_cancelled_self_send_uuid_remains_active() {
		let sender_parent =
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0).expect("sender account path should derive");
		let receiver_parent =
			ExtKeychain::derive_key_id(2, 1, 0, 0, 0).expect("receiver account path should derive");
		let (sender_uuid, sender) = test_wallet_tx(
			&sender_parent,
			7,
			"partial-self-send",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		let (receiver_uuid, receiver) = test_wallet_tx(
			&receiver_parent,
			8,
			"partial-self-send",
			TxLogEntryType::TxReceivedCancelled,
			Vec::new(),
		);
		let tx_uuids = HashSet::from([sender_uuid.clone(), receiver_uuid.clone()]);
		let mut transactions =
			HashMap::from([(sender_uuid.clone(), sender), (receiver_uuid, receiver)]);

		assert_eq!(
			transaction_uuid_state_counts(&tx_uuids, &transactions),
			(1, 0)
		);

		transactions
			.get_mut(&sender_uuid)
			.expect("sender transaction should exist")
			.tx_log
			.tx_type = TxLogEntryType::TxSentCancelled;
		assert_eq!(
			transaction_uuid_state_counts(&tx_uuids, &transactions),
			(0, 1)
		);
	}

	fn test_wallet_output_info(
		commit: &str,
		status: OutputStatus,
		at_chain: bool,
	) -> WalletOutputInfo {
		let mut output = coinbase_output(None);
		output.commit = Some(commit.to_owned());
		output.status = status;
		output.is_coinbase = false;
		let mut output_info = WalletOutputInfo::new(output);
		output_info.at_chain = at_chain;
		output_info
	}

	#[test]
	fn old_pending_no_change_transaction_keeps_locked_input_live() {
		let input_commit = "pending-no-change-input";
		let (_, mut transaction) = test_wallet_tx(
			&Identifier::zero(),
			1,
			"pending-no-change",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		let archive_reference_time = Utc::now();
		transaction.tx_log.creation_ts = archive_reference_time
			.checked_sub_signed(Duration::days(6))
			.expect("six days must fit in the supported timestamp range");
		let tx_time_to_archive = archive_reference_time
			.checked_sub_signed(Duration::days(5))
			.expect("five days must fit in the supported timestamp range");
		transaction.input_commit.insert(input_commit.to_owned());

		assert!(transaction.output_commit.is_empty());
		assert!(can_archive_unchanged_transaction(
			&transaction,
			&HashMap::new(),
			&tx_time_to_archive,
			100,
		));

		let live_outputs = HashMap::from([(
			input_commit.to_owned(),
			test_wallet_output_info(input_commit, OutputStatus::Locked, true),
		)]);
		assert!(!can_archive_unchanged_transaction(
			&transaction,
			&live_outputs,
			&tx_time_to_archive,
			100,
		));

		transaction.tx_log.tx_type = TxLogEntryType::TxSentCancelled;
		assert!(can_archive_unchanged_transaction(
			&transaction,
			&live_outputs,
			&tx_time_to_archive,
			100,
		));
	}

	#[test]
	fn consistency_prefers_confirmed_evidence_for_shared_outputs() {
		let parent = Identifier::zero();
		let (confirmed_uuid, mut confirmed_tx) = test_wallet_tx(
			&parent,
			1,
			"shared-transaction",
			TxLogEntryType::TxReceived,
			Vec::new(),
		);
		confirmed_tx.tx_log.confirmed = true;
		let (unconfirmed_uuid, mut unconfirmed_tx) = test_wallet_tx(
			&parent,
			2,
			"shared-transaction",
			TxLogEntryType::TxSent,
			Vec::new(),
		);

		let reverted_commit = "shared-reverted-output";
		let spent_commit = "shared-spent-output";
		for commit in [reverted_commit, spent_commit] {
			confirmed_tx.output_commit.insert(commit.to_owned());
			unconfirmed_tx.output_commit.insert(commit.to_owned());
		}

		// Evidence aggregation must produce the same precedence regardless of the
		// order in which the conflicting account-local records are observed.
		for ordered_transactions in [
			[&confirmed_tx, &unconfirmed_tx],
			[&unconfirmed_tx, &confirmed_tx],
		] {
			let evidence = collect_output_consistency_evidence(ordered_transactions);
			for commit in [reverted_commit, spent_commit] {
				let output_evidence = evidence
					.get(commit)
					.expect("the shared output should have consistency evidence");
				assert!(output_evidence.has_confirmed_reference);
				assert!(output_evidence.has_unconfirmed_output_reference);
			}
		}

		let transactions = HashMap::from([
			(confirmed_uuid, confirmed_tx),
			(unconfirmed_uuid, unconfirmed_tx),
		]);
		let mut outputs = HashMap::from([
			(
				reverted_commit.to_owned(),
				test_wallet_output_info(reverted_commit, OutputStatus::Reverted, false),
			),
			(
				spent_commit.to_owned(),
				test_wallet_output_info(spent_commit, OutputStatus::Spent, false),
			),
		]);

		validate_consistancy(&mut outputs, &transactions);

		let reverted_output = outputs
			.get(reverted_commit)
			.expect("the reverted shared output should remain present");
		assert_eq!(reverted_output.output.status, OutputStatus::Spent);
		assert!(reverted_output.updated);

		let spent_output = outputs
			.get(spent_commit)
			.expect("the spent shared output should remain present");
		assert_eq!(spent_output.output.status, OutputStatus::Spent);
		assert!(!spent_output.updated);
	}

	#[test]
	fn consistency_reverts_spent_output_with_only_unconfirmed_evidence() {
		let commit = "unconfirmed-output";
		let (tx_uuid, mut tx_info) = test_wallet_tx(
			&Identifier::zero(),
			1,
			"unconfirmed-transaction",
			TxLogEntryType::TxReceived,
			Vec::new(),
		);
		tx_info.output_commit.insert(commit.to_owned());
		let transactions = HashMap::from([(tx_uuid, tx_info)]);
		let mut outputs = HashMap::from([(
			commit.to_owned(),
			test_wallet_output_info(commit, OutputStatus::Spent, false),
		)]);

		validate_consistancy(&mut outputs, &transactions);

		let output = outputs
			.get(commit)
			.expect("the unconfirmed output should remain present");
		assert_eq!(output.output.status, OutputStatus::Reverted);
		assert!(output.updated);
	}

	fn test_non_kernel_sent_transaction() -> WalletTxInfo {
		let (_, mut tx_info) = test_wallet_tx(
			&Identifier::zero(),
			1,
			"legacy-sent",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		tx_info.input_commit.insert("input".to_owned());
		tx_info.output_commit.insert("change".to_owned());
		tx_info
	}

	#[test]
	fn live_non_replay_input_unconfirms_a_non_kernel_transaction() {
		let tx_info = test_non_kernel_sent_transaction();
		let outputs = HashMap::from([
			(
				"input".to_owned(),
				test_wallet_output_info("input", OutputStatus::Locked, true),
			),
			(
				"change".to_owned(),
				test_wallet_output_info("change", OutputStatus::Spent, false),
			),
		]);

		assert_eq!(
			non_kernel_transaction_evidence(&tx_info, &outputs, &HashSet::new()),
			NonKernelTransactionEvidence::Unconfirmed
		);
	}

	#[test]
	fn replay_candidate_input_preserves_non_kernel_transaction_history() {
		let tx_info = test_non_kernel_sent_transaction();
		let outputs = HashMap::from([
			(
				"input".to_owned(),
				test_wallet_output_info("input", OutputStatus::Locked, true),
			),
			(
				"change".to_owned(),
				test_wallet_output_info("change", OutputStatus::Spent, false),
			),
		]);
		let replay_candidates = HashSet::from(["input".to_owned()]);

		assert_eq!(
			non_kernel_transaction_evidence(&tx_info, &outputs, &replay_candidates),
			NonKernelTransactionEvidence::Unknown
		);
	}

	#[test]
	fn stale_spent_output_does_not_confirm_a_non_kernel_transaction() {
		let tx_info = test_non_kernel_sent_transaction();
		let outputs = HashMap::from([
			(
				"input".to_owned(),
				test_wallet_output_info("input", OutputStatus::Locked, false),
			),
			(
				"change".to_owned(),
				test_wallet_output_info("change", OutputStatus::Spent, false),
			),
		]);

		assert_eq!(
			non_kernel_transaction_evidence(&tx_info, &outputs, &HashSet::new()),
			NonKernelTransactionEvidence::Unknown
		);
	}

	#[test]
	fn live_output_confirms_a_non_kernel_transaction() {
		let tx_info = test_non_kernel_sent_transaction();
		let outputs = HashMap::from([
			(
				"input".to_owned(),
				test_wallet_output_info("input", OutputStatus::Spent, false),
			),
			(
				"change".to_owned(),
				test_wallet_output_info("change", OutputStatus::Unspent, true),
			),
		]);

		assert_eq!(
			non_kernel_transaction_evidence(&tx_info, &outputs, &HashSet::new()),
			NonKernelTransactionEvidence::Confirmed
		);
	}

	#[test]
	fn output_creator_map_uses_account_local_log_ownership() {
		let parent =
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0).expect("test account path should derive");
		let target = test_commitment(21);
		let change = test_commitment(22);
		let target_hex = mwc_util::to_hex(&target.0);
		let change_hex = mwc_util::to_hex(&change.0);

		let (sender_uuid, mut sender) = test_wallet_tx(
			&parent,
			7,
			"self-send",
			TxLogEntryType::TxSent,
			vec![change],
		);
		let (receiver_uuid, mut receiver) = test_wallet_tx(
			&parent,
			8,
			"self-send",
			TxLogEntryType::TxReceived,
			vec![target],
		);

		// Simulate add_transaction: both log entries see every output in the
		// shared stored transaction, but their owned sets remain account-local.
		sender.output_commit.insert(target_hex.clone());
		receiver.output_commit.insert(change_hex);

		let transactions =
			HashMap::from([(sender_uuid, sender), (receiver_uuid.clone(), receiver)]);
		let creators = build_output_creator_map(&transactions);
		assert_eq!(
			creators.get(&output_creator_key(&parent, &target_hex)),
			Some(&vec![receiver_uuid]),
			"the receiver log, not HashMap insertion order, owns the restored output"
		);
	}

	#[test]
	fn active_spender_is_selected_separately_from_creator() -> Result<(), Error> {
		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let target = test_commitment(27);
		let target_hex = mwc_util::to_hex(&target.0);
		let (creator_uuid, creator) = test_wallet_tx(
			&parent,
			7,
			"creator",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let (spender_uuid, mut spender) = test_wallet_tx(
			&parent,
			8,
			"pending-spender",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		spender.input_commit.insert(target_hex.clone());
		let transactions = HashMap::from([(creator_uuid, creator), (spender_uuid, spender)]);
		let creators = build_output_creator_map(&transactions);

		let (creator_log_id, _, _) =
			select_output_creator_log_id(&creators, &transactions, &parent, &target_hex);
		let active_spender_log_id =
			select_active_output_spender_log_id(&transactions, &parent, &target_hex)?;
		assert_eq!(creator_log_id, Some(7));
		assert_eq!(active_spender_log_id, Some(8));
		Ok(())
	}

	#[test]
	fn repaired_coinbase_keeps_pending_spender_association() -> Result<(), Error> {
		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let target = test_commitment(30);
		let target_hex = mwc_util::to_hex(&target.0);
		let (spender_uuid, mut spender) = test_wallet_tx(
			&parent,
			8,
			"pending-coinbase-spender",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		spender.input_commit.insert(target_hex.clone());

		let mut output = coinbase_output(Some(8));
		output.root_key_id = parent.clone();
		output.commit = Some(target_hex.clone());
		output.status = OutputStatus::Locked;
		let mut output = WalletOutputInfo::new(output);
		output.add_tx_input_uuid(&spender_uuid);
		let transactions = HashMap::from([(spender_uuid, spender)]);

		assert!(output.output.is_spendable());
		assert!(output.tx_output_uuid.is_empty());
		assert_eq!(
			repaired_coinbase_output_log_id(
				&transactions,
				&output.output.root_key_id,
				&output.commit,
				42,
			)?,
			8,
			"repairing creation history must not replace the pending lock owner"
		);
		assert_eq!(
			repaired_coinbase_output_log_id(
				&HashMap::new(),
				&output.output.root_key_id,
				&output.commit,
				42,
			)?,
			42,
			"without a pending spender the recovered creator owns the association"
		);
		Ok(())
	}

	#[test]
	fn active_spender_selection_uses_current_kernel_state() -> Result<(), Error> {
		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let target_hex = mwc_util::to_hex(&test_commitment(28).0);
		let (spender_uuid, mut spender) = test_wallet_tx(
			&parent,
			12,
			"reorged-spender",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		spender.tx_log.confirmed = true;
		spender.kernel_validation = Some(false);
		spender.input_commit.insert(target_hex.clone());
		let mut transactions = HashMap::from([(spender_uuid.clone(), spender)]);

		assert_eq!(
			select_active_output_spender_log_id(&transactions, &parent, &target_hex)?,
			Some(12),
			"a current negative kernel lookup makes a formerly confirmed send pending"
		);
		transactions
			.get_mut(&spender_uuid)
			.expect("spender should remain in the test transaction map")
			.kernel_validation = Some(true);
		assert_eq!(
			select_active_output_spender_log_id(&transactions, &parent, &target_hex)?,
			None,
			"a send whose kernel is currently confirmed must not reserve a live output"
		);
		Ok(())
	}

	#[test]
	fn active_spender_selection_rejects_ambiguous_reservations() -> Result<(), Error> {
		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let target_hex = mwc_util::to_hex(&test_commitment(29).0);
		let (first_uuid, mut first) = test_wallet_tx(
			&parent,
			13,
			"first-spender",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		let (second_uuid, mut second) = test_wallet_tx(
			&parent,
			14,
			"second-spender",
			TxLogEntryType::TxSent,
			Vec::new(),
		);
		first.input_commit.insert(target_hex.clone());
		second.input_commit.insert(target_hex.clone());
		let transactions = HashMap::from([(first_uuid, first), (second_uuid, second)]);

		let error = select_active_output_spender_log_id(&transactions, &parent, &target_hex)
			.expect_err("multiple active spenders must fail closed");
		assert!(
			error
				.to_string()
				.contains("reserved by 2 active transactions")
		);
		Ok(())
	}

	#[test]
	fn recovered_output_identity_updates_account_log_and_child_counter() -> Result<(), Error> {
		let stale_parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let recovered_parent = ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?;
		let recovered_key = ExtKeychain::derive_key_id(3, 1, 0, 12, 0)?;
		let target = test_commitment(26);
		let target_hex = mwc_util::to_hex(&target.0);
		let (creator_uuid, creator) = test_wallet_tx(
			&recovered_parent,
			9,
			"recovered-creator",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let transactions = HashMap::from([(creator_uuid, creator)]);
		let creators = build_output_creator_map(&transactions);

		let chain_output = OutputResult {
			commit: target,
			key_id: recovered_key.clone(),
			n_child: 12,
			mmr_index: 26,
			value: 42,
			height: 100,
			lock_height: 100,
			is_coinbase: false,
		};
		let mut found_parents = HashMap::new();
		let authenticated_parent = record_found_parent(&mut found_parents, &chain_output)?;
		assert_eq!(authenticated_parent, recovered_parent);

		let mut output = coinbase_output(Some(3));
		output.root_key_id = stale_parent;
		output.key_id = recovered_key;
		output.commit = Some(target_hex.clone());
		output.is_coinbase = false;

		assert!(reconcile_wallet_output_parent(
			&mut output,
			&authenticated_parent,
			&target_hex,
			&creators,
			&transactions,
		));
		assert_eq!(output.root_key_id, recovered_parent);
		assert_eq!(output.tx_log_entry, Some(9));
		assert_eq!(found_parents.get(&recovered_parent), Some(&12));
		Ok(())
	}

	#[test]
	fn recovered_output_identity_clears_a_foreign_transaction_link() -> Result<(), Error> {
		let stale_parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let recovered_parent = ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?;
		let mut output = coinbase_output(Some(7));
		output.root_key_id = stale_parent;

		assert!(reconcile_wallet_output_parent(
			&mut output,
			&recovered_parent,
			"test-commitment",
			&HashMap::new(),
			&HashMap::new(),
		));
		assert_eq!(output.root_key_id, recovered_parent);
		assert_eq!(output.tx_log_entry, None);
		Ok(())
	}

	#[test]
	fn output_creator_map_preserves_ambiguous_matches() {
		let parent =
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0).expect("test account path should derive");
		let target = test_commitment(23);
		let target_hex = mwc_util::to_hex(&target.0);
		let (first_uuid, first) = test_wallet_tx(
			&parent,
			1,
			"first",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let (second_uuid, second) = test_wallet_tx(
			&parent,
			2,
			"second",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let transactions = HashMap::from([(first_uuid, first), (second_uuid, second)]);
		let creators = build_output_creator_map(&transactions);
		assert_eq!(
			creators
				.get(&output_creator_key(&parent, &target_hex))
				.expect("both direct creators should be retained")
				.len(),
			2,
			"ambiguous history must not be silently resolved by last insertion"
		);
		assert_eq!(
			select_output_creator_log_id(&creators, &transactions, &parent, &target_hex),
			(None, 2, 2),
			"multiple trustworthy creators must use a fresh recovery transaction"
		);
	}

	#[test]
	fn output_creator_selection_tolerates_broken_transaction_records() {
		let parent =
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0).expect("test account path should derive");
		let target = test_commitment(25);
		let target_hex = mwc_util::to_hex(&target.0);
		let (valid_uuid, valid) = test_wallet_tx(
			&parent,
			7,
			"valid",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let missing_uuid = TxUuidPlus::new(
			"missing".to_owned(),
			8,
			mwc_util::to_hex(&parent.to_bytes()),
		);
		let transactions = HashMap::from([(valid_uuid.clone(), valid)]);
		let creators = HashMap::from([(
			output_creator_key(&parent, &target_hex),
			vec![missing_uuid, valid_uuid],
		)]);

		assert_eq!(
			select_output_creator_log_id(&creators, &transactions, &parent, &target_hex),
			(Some(7), 2, 1),
			"a missing transaction record must not hide the one trustworthy creator"
		);

		let other_parent =
			ExtKeychain::derive_key_id(2, 1, 0, 0, 0).expect("test account path should derive");
		let (foreign_uuid, foreign) = test_wallet_tx(
			&other_parent,
			9,
			"foreign",
			TxLogEntryType::TxReceived,
			vec![target],
		);
		let foreign_transactions = HashMap::from([(foreign_uuid.clone(), foreign)]);
		let inconsistent_creators =
			HashMap::from([(output_creator_key(&parent, &target_hex), vec![foreign_uuid])]);
		assert_eq!(
			select_output_creator_log_id(
				&inconsistent_creators,
				&foreign_transactions,
				&parent,
				&target_hex,
			),
			(None, 1, 0),
			"a creator from another account must fall back to recovery"
		);
	}

	#[test]
	fn confirmed_archived_log_inputs_are_replay_evidence() {
		let commitment = test_commitment(24);
		let commit_hex = mwc_util::to_hex(&commitment.0);
		let mut tx_log = TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxSent, 1);
		tx_log.confirmed = true;
		tx_log.input_commits = vec![commitment];
		let mut confirmed_spends = HashSet::new();
		assert!(add_confirmed_tx_log_input_commits(
			&mut confirmed_spends,
			&tx_log
		));
		assert!(confirmed_spends.contains(&commit_hex));

		let mut chain_outputs = vec![OutputResult {
			commit: commitment,
			key_id: Identifier::zero(),
			n_child: 0,
			mmr_index: 1,
			value: 10,
			height: 1,
			lock_height: 1,
			is_coinbase: false,
		}];
		let candidates = take_transaction_history_replay_candidates(
			&mut chain_outputs,
			&confirmed_spends,
			&ReplayMitigationConfig {
				replay_mitigation_flag: true,
				replay_mitigation_min_amount: 0,
				..Default::default()
			},
		);
		assert!(chain_outputs.is_empty());
		assert_eq!(candidates.len(), 1);

		tx_log.tx_type = TxLogEntryType::TxSentCancelled;
		let mut cancelled_spends = HashSet::new();
		assert!(!add_confirmed_tx_log_input_commits(
			&mut cancelled_spends,
			&tx_log
		));
		assert!(cancelled_spends.is_empty());
	}

	#[derive(Clone)]
	struct ScanConsistencyNodeClient {
		connection: Arc<Mutex<NodeConnectionId>>,
		tip_height: Arc<Mutex<u64>>,
		header_hash: Arc<Mutex<String>>,
		body_branch: Arc<Mutex<String>>,
		header_links: Arc<Mutex<HashMap<String, NodeHeaderLink>>>,
		refill_after_reset: Option<ChainTip>,
		cached_tip: Arc<Mutex<Option<ChainTip>>>,
		change_on_output_page: bool,
		change_on_next_header: Arc<Mutex<bool>>,
	}

	impl ScanConsistencyNodeClient {
		fn new(header_hash: &str, change_on_output_page: bool) -> Self {
			let client = Self {
				connection: Arc::new(Mutex::new(NodeConnectionId {
					node_index: 0,
					generation: 0,
				})),
				tip_height: Arc::new(Mutex::new(10)),
				header_hash: Arc::new(Mutex::new(header_hash.to_owned())),
				body_branch: Arc::new(Mutex::new(header_hash.to_owned())),
				header_links: Arc::new(Mutex::new(HashMap::new())),
				refill_after_reset: None,
				cached_tip: Arc::new(Mutex::new(None)),
				change_on_output_page,
				change_on_next_header: Arc::new(Mutex::new(false)),
			};
			client.set_body_tip(10, header_hash);
			client
		}

		fn hash_at_height(branch: &str, height: u64) -> String {
			match height {
				0 => "genesis".to_owned(),
				10 => branch.to_owned(),
				_ => format!("{}:{}", branch, height),
			}
		}

		fn set_body_tip(&self, tip_height: u64, branch: &str) {
			// Preserve immutable headers from both forks while selecting the body
			// tip independently of the header chain.
			let mut links = self.header_links.lock();
			for height in 1..=tip_height {
				let hash = Self::hash_at_height(branch, height);
				links.insert(
					hash.clone(),
					NodeHeaderLink {
						height,
						hash,
						previous: Self::hash_at_height(branch, height - 1),
					},
				);
			}
			*self.body_branch.lock() = branch.to_owned();
			*self.tip_height.lock() = tip_height;
		}

		fn set_tip_height(&self, tip_height: u64) {
			let branch = self.body_branch.lock().clone();
			self.set_body_tip(tip_height, &branch);
		}

		fn set_header_hash(&self, header_hash: &str) {
			*self.header_hash.lock() = header_hash.to_owned();
			let height = *self.tip_height.lock();
			self.set_body_tip(height, header_hash);
		}

		fn fail_over_on_next_header(&self) {
			*self.change_on_next_header.lock() = true;
		}

		fn maybe_fail_over(&self) {
			let mut change_on_next_header = self.change_on_next_header.lock();
			if *change_on_next_header {
				*self.connection.lock() = NodeConnectionId {
					node_index: 1,
					generation: 1,
				};
				*change_on_next_header = false;
			}
		}
	}

	impl NodeClient for ScanConsistencyNodeClient {
		fn set_node_index(&mut self, node_index: u8) {
			*self.connection.lock() = NodeConnectionId {
				node_index,
				generation: 1,
			};
		}

		fn get_node_index(&self) -> u8 {
			self.connection.lock().node_index
		}

		fn get_node_connection_id(&self) -> NodeConnectionId {
			*self.connection.lock()
		}

		fn reset_cache(&self) {
			// Model a delayed response repopulating the cache immediately after
			// it is cleared, without depending on thread scheduling in the test.
			*self.cached_tip.lock() = self.refill_after_reset.clone();
		}

		fn test_mempool_accept(
			&self,
			_request: &crate::transaction_preflight::MempoolAcceptRequest,
		) -> Result<crate::transaction_preflight::MempoolAcceptResponse, Error> {
			Err(Error::Node(
				"Node does not support testmempoolaccept".into(),
			))
		}

		fn post_tx(
			&self,
			_tx: &Transaction,
			_fluff: bool,
			_receipt: crate::transaction_preflight::PreflightReceipt,
		) -> Result<(), Error> {
			Err(Error::Node(
				"Node transport does not support preflighted publication".into(),
			))
		}

		fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
			None
		}

		fn get_chain_tip(&self) -> Result<(u64, String, u64), Error> {
			if let Some(tip) = self.cached_tip.lock().as_ref() {
				return Ok((tip.height, tip.hash.clone(), 100));
			}
			self.get_chain_tip_fresh()
		}

		fn get_chain_tip_fresh(&self) -> Result<(u64, String, u64), Error> {
			let height = *self.tip_height.lock();
			Ok((
				height,
				Self::hash_at_height(&self.body_branch.lock(), height),
				100,
			))
		}

		fn get_header_info(&self, height: u64) -> Result<HeaderInfo, Error> {
			if let Some(tip) = self.cached_tip.lock().as_ref() {
				if tip.height == height {
					return Ok(HeaderInfo {
						height,
						hash: tip.hash.clone(),
						confirmed_time: String::new(),
						version: 1,
						nonce: 0,
						total_difficulty: 100,
					});
				}
			}
			self.get_header_info_fresh(height)
		}

		fn get_header_info_fresh(&self, height: u64) -> Result<HeaderInfo, Error> {
			self.maybe_fail_over();
			Ok(HeaderInfo {
				height,
				hash: Self::hash_at_height(&self.header_hash.lock(), height),
				confirmed_time: String::new(),
				version: 1,
				nonce: 0,
				total_difficulty: 100,
			})
		}

		fn get_header_by_hash(&self, hash: &str) -> Result<NodeHeaderLink, Error> {
			self.maybe_fail_over();
			self.header_links
				.lock()
				.get(hash)
				.cloned()
				.ok_or_else(|| Error::Node(format!("Missing ancestry header {}", hash)))
		}

		fn get_connected_peer_info(
			&self,
		) -> Result<Vec<mwc_wallet_util::mwc_p2p::types::PeerInfoDisplayLegacy>, Error> {
			Ok(Vec::new())
		}

		fn get_kernel(
			&self,
			_excess: &pedersen::Commitment,
			_min_height: Option<u64>,
			_max_height: Option<u64>,
		) -> Result<Option<(mwc_wallet_util::mwc_core::core::TxKernel, u64, u64)>, Error> {
			Ok(None)
		}

		fn get_outputs_from_node(
			&self,
			_wallet_outputs: &Vec<pedersen::Commitment>,
		) -> Result<HashMap<pedersen::Commitment, NodeOutputDetails>, Error> {
			Ok(HashMap::new())
		}

		fn get_outputs_by_pmmr_index(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
			_max_outputs: u64,
		) -> Result<
			(
				u64,
				u64,
				Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
			),
			Error,
		> {
			if self.change_on_output_page {
				*self.connection.lock() = NodeConnectionId {
					node_index: 1,
					generation: 1,
				};
			}
			Ok((0, 0, Vec::new()))
		}

		fn height_range_to_pmmr_indices(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
		) -> Result<(u64, u64), Error> {
			Ok((0, 0))
		}

		fn get_blocks_by_height(
			&self,
			_start_height: u64,
			_end_height: u64,
			_threads_number: usize,
		) -> Result<Vec<mwc_api::BlockPrintable>, Error> {
			Ok(Vec::new())
		}
	}

	#[test]
	fn node_read_session_rejects_body_reorg_while_header_chain_keeps_anchor() {
		for height in [10, 11, 12] {
			let client = ScanConsistencyNodeClient::new("tip-a", false);
			let session = NodeReadSession::start(&client, "Session test").unwrap();
			client.set_body_tip(height, "tip-b");
			// Header-first sync can leave the header chain on A while the body
			// has switched to B. The old height-only check would accept this.
			assert_eq!(client.get_header_info_fresh(10).unwrap().hash, "tip-a");
			let error = session.verify_anchor(&client, "Session test").unwrap_err();
			assert!(
				error
					.to_string()
					.contains("body chain changed at height 10")
			);
			#[cfg(feature = "swaps")]
			assert!(session.fresh_tip(&client, "Session test").is_err());
			assert!(NodeReadSession::bind(&client, session.anchor, "Session test").is_err());
		}
	}

	#[test]
	fn node_read_session_accepts_body_extension_on_a_different_header_fork() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::start(&client, "Session test").unwrap();
		client.set_tip_height(12);
		*client.header_hash.lock() = "tip-b".to_owned();
		assert_eq!(client.get_header_info_fresh(10).unwrap().hash, "tip-b");

		session.verify_anchor(&client, "Session test").unwrap();
		#[cfg(feature = "swaps")]
		assert_eq!(
			session.fresh_tip(&client, "Session test").unwrap(),
			ChainTip {
				height: 12,
				hash: "tip-a:12".to_owned(),
			}
		);
		assert_eq!(
			NodeReadSession::start(&client, "Session test")
				.unwrap()
				.anchor
				.hash,
			"tip-a:12"
		);
	}

	#[test]
	fn node_read_session_rejects_inconsistent_ancestry_headers() {
		for wrong_hash in [true, false] {
			let client = ScanConsistencyNodeClient::new("tip-a", false);
			let session = NodeReadSession::start(&client, "Session test").unwrap();
			client.set_tip_height(12);
			// Corrupt the intermediate response, so validating only the tip's
			// header would miss it. Parent links must also match height and hash.
			{
				let mut links = client.header_links.lock();
				let header = links.get_mut("tip-a:11").unwrap();
				if wrong_hash {
					header.hash = "wrong-hash".to_owned();
				} else {
					header.height = 10;
				}
			}
			let error = session.verify_anchor(&client, "Session test").unwrap_err();
			assert!(error.to_string().contains("inconsistent ancestry header"));
			#[cfg(feature = "swaps")]
			assert!(session.fresh_tip(&client, "Session test").is_err());
		}
	}

	#[test]
	fn node_read_session_propagates_missing_ancestry_errors() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::start(&client, "Session test").unwrap();
		client.set_tip_height(12);
		client.header_links.lock().remove("tip-a:11");

		let error = session.verify_anchor(&client, "Session test").unwrap_err();
		assert!(
			error
				.to_string()
				.contains("Missing ancestry header tip-a:11")
		);
		#[cfg(feature = "swaps")]
		assert!(session.fresh_tip(&client, "Session test").is_err());
	}

	#[test]
	fn node_read_session_rejects_failover_during_ancestry_lookup() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::start(&client, "Session test").unwrap();
		client.set_tip_height(11);
		client.fail_over_on_next_header();

		let error = session.verify_anchor(&client, "Session test").unwrap_err();
		assert!(
			error
				.to_string()
				.contains("changed node while reading chain state")
		);
		#[cfg(feature = "swaps")]
		{
			*client.connection.lock() = session.connection;
			client.fail_over_on_next_header();
			let error = session.fresh_tip(&client, "Session test").unwrap_err();
			assert!(
				error
					.to_string()
					.contains("changed node while reading chain state")
			);
		}
	}

	#[test]
	fn node_read_session_handles_genesis_and_unchanged_tips_without_header_reads() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		for height in [0, 10] {
			client.set_tip_height(height);
			client.header_links.lock().clear();
			let session = NodeReadSession::start(&client, "Session test").unwrap();
			session.verify_anchor(&client, "Session test").unwrap();
			#[cfg(feature = "swaps")]
			assert_eq!(
				session.fresh_tip(&client, "Session test").unwrap(),
				session.anchor
			);
		}
	}

	#[test]
	fn node_read_session_uses_fresh_reads_after_cache_refill() {
		let mut client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::start(&client, "Session test").unwrap();
		client.refill_after_reset = Some(session.anchor.clone());
		client.set_tip_height(11);

		session.verify_anchor(&client, "Session test").unwrap();
		#[cfg(feature = "swaps")]
		assert_eq!(session.fresh_tip(&client, "Session test").unwrap().height, 11);

		client.set_header_hash("tip-b");
		let new_session = NodeReadSession::start(&client, "Session test").unwrap();
		assert_eq!(new_session.anchor.height, 11);
		assert_eq!(new_session.anchor.hash, "tip-b:11");
		NodeReadSession::bind(
			&client,
			ChainTip {
				height: 10,
				hash: "tip-b".to_owned(),
			},
			"Session test",
		)
		.expect("a stale cached header must not reject the current chain anchor");
	}

	#[test]
	fn node_read_session_rejects_reorg_and_rollback_despite_cache_refill() {
		let mut client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::start(&client, "Session test").unwrap();
		client.refill_after_reset = Some(session.anchor.clone());

		for (height, hash, expected_error) in [
			(9, "tip-a", "node tip moved behind"),
			(11, "tip-b", "chain changed at height"),
		] {
			client.set_tip_height(height);
			client.set_header_hash(hash);
			let error = session.verify_anchor(&client, "Session test").unwrap_err();
			assert!(error.to_string().contains(expected_error));
			#[cfg(feature = "swaps")]
			{
				let error = session.fresh_tip(&client, "Session test").unwrap_err();
				assert!(error.to_string().contains(expected_error));
			}
		}
	}

	#[test]
	fn scan_anchor_can_be_established_after_initial_header_failover() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		client.fail_over_on_next_header();

		let session = NodeReadSession::bind(
			&client,
			ChainTip {
				height: 10,
				hash: "tip-a".to_owned(),
			},
			"View-wallet scan",
		)
		.expect("initial failover to a node with the same anchor should be accepted");

		assert_eq!(session.connection.node_index, 1);
		assert_eq!(session.connection.generation, 1);
	}

	#[test]
	fn rewind_hash_scan_rejects_a_wrong_length_credential() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let session = NodeReadSession::bind(
			&client,
			ChainTip {
				height: 10,
				hash: "tip-a".to_owned(),
			},
			"View-wallet scan",
		)
		.expect("initial anchor should match");
		let mut secp =
			Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context should initialize");

		let error = collect_chain_outputs_rewind_hash(
			&mut secp,
			0,
			&client,
			&session,
			Zeroizing::new("00".repeat(31)),
			0,
			Some(0),
			None,
		)
		.err()
		.expect("a rewind hash must contain exactly 32 bytes");

		assert!(matches!(error, Error::RewindHash(_)));
	}

	#[test]
	fn rewind_hash_scan_rejects_a_node_change_before_processing_the_page() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let client = ScanConsistencyNodeClient::new("tip-a", true);
		let session = NodeReadSession::bind(
			&client,
			ChainTip {
				height: 10,
				hash: "tip-a".to_owned(),
			},
			"View-wallet scan",
		)
		.expect("initial anchor should match");
		let mut secp =
			Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context should initialize");

		let error = collect_chain_outputs_rewind_hash(
			&mut secp,
			0,
			&client,
			&session,
			Zeroizing::new("00".repeat(32)),
			0,
			Some(0),
			None,
		)
		.err()
		.expect("a page returned after failover must be rejected");

		assert!(error
			.to_string()
			.contains("changed node while reading chain state"));
	}

	#[test]
	fn ordinary_wallet_scan_rejects_a_node_change_before_processing_the_page() {
		let client = ScanConsistencyNodeClient::new("tip-a", true);
		let mut secp =
			Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context should initialize");
		let keychain = ExtKeychain::from_seed(&secp, &[1_u8; 32], true)
			.expect("test keychain should initialize");

		let error = collect_chain_outputs(&mut secp, 0, &keychain, client, 0, Some(0), false, None)
			.expect_err("an ordinary scan page returned after failover must be rejected");

		assert!(error
			.to_string()
			.contains("changed node while retrieving output pages"));
	}

	#[test]
	fn rewind_hash_scan_allows_the_tip_to_advance_past_the_anchor() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let anchor = ChainTip {
			height: 10,
			hash: "tip-a".to_owned(),
		};
		let session = NodeReadSession::bind(&client, anchor.clone(), "View-wallet scan")
			.expect("initial anchor should match");
		client.set_tip_height(11);

		session
			.verify_anchor(&client, "View-wallet scan")
			.expect("a chain extension that preserves the anchor must be accepted");
	}

	#[test]
	fn rewind_hash_scan_rejects_an_anchor_hash_change_after_scanning() {
		let client = ScanConsistencyNodeClient::new("tip-a", false);
		let anchor = ChainTip {
			height: 10,
			hash: "tip-a".to_owned(),
		};
		let session = NodeReadSession::bind(&client, anchor.clone(), "View-wallet scan")
			.expect("initial anchor should match");
		client.set_header_hash("tip-b");

		let error = session
			.verify_anchor(&client, "View-wallet scan")
			.expect_err("a changed anchor hash must invalidate the result");

		assert!(error.to_string().contains("chain changed at height 10"));
	}

	#[test]
	fn rewind_hash_scan_rejects_an_anchor_from_a_different_node_fork() {
		let client = ScanConsistencyNodeClient::new("tip-b", false);
		let anchor = ChainTip {
			height: 10,
			hash: "tip-a".to_owned(),
		};

		let error = NodeReadSession::bind(&client, anchor, "View-wallet scan")
			.expect_err("a different node fork must not satisfy the scan anchor");

		assert!(error
			.to_string()
			.contains("chain anchor changed at height 10"));
	}
}
