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
use crate::api_impl::owner_updater::StatusMessage;
use crate::api_impl::types::InitTxArgs;
use crate::internal::tx;
use crate::internal::{keys, updater};
use crate::mwc_core::consensus::{valid_header_version, WEEK_HEIGHT};
use crate::mwc_core::core::Committed;
use crate::mwc_core::core::HeaderVersion;
use crate::mwc_core::core::Transaction;
use crate::mwc_core::global;
use crate::mwc_core::libtx::{proof, tx_fee};
use crate::mwc_keychain::{ChildNumber, Identifier, Keychain, SwitchCommitmentType};
use crate::mwc_util as util;
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::secp::pedersen;
use crate::mwc_util::secp::{ContextFlag, Secp256k1};
use crate::mwc_util::Mutex;
use crate::mwc_util::{from_hex, ToHex};
use crate::types::*;
use crate::Error;
use crate::ReplayMitigationConfig;
use blake2_rfc::blake2b::blake2b;
use chrono::{Duration, Utc};
use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core::consensus::DAY_HEIGHT;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Sender;
use uuid::Uuid;
// Wallet - node sync up strategy. We can request blocks from the node and analyze them. 1 week of blocks can be requested in theory.
// Or we can validate tx kernels, outputs e.t.c

// for 10, using blocks strategy
const SYNC_BLOCKS_DEEPNESS: usize = 8;

// For every 100 outputs trade one additional block. It is make sense for the mining wallets with thousands of blocks.
const OUTPUT_TO_BLOCK: usize = 100;

// How many parallel requests to use for the blocks. We don't want to be very aggressive because
// of the node load. 4 is a reasonable number
const SYNC_BLOCKS_THREADS: usize = 4;

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

/// Utility struct for self spend
#[derive(Debug, Clone)]
pub struct OutputResultLight {
	/// key_id
	pub key_id: Identifier,
	///value
	pub value: u64,
	///commit
	pub commit: String,
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
	pub static ref REPLAY_MITIGATION_CONFIG: Mutex< ReplayMitigationConfig> = Mutex::new(ReplayMitigationConfig::default());
}
/// Set address derivative index
pub fn set_replay_config(config: ReplayMitigationConfig) {
	let mut lock = REPLAY_MITIGATION_CONFIG.lock();
	*lock = config;
}
/// Get address derivative index
pub fn get_replay_config() -> ReplayMitigationConfig {
	REPLAY_MITIGATION_CONFIG.lock().clone()
}

fn identify_utxo_outputs<'a, K>(
	keychain: &K,
	outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
	end_height: Option<u64>,
	should_self_spend: bool,
	self_spend_amount: u64,
) -> Result<(Vec<OutputResult>, Vec<OutputResult>), Error>
where
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();
	let mut self_spend_outputs: Vec<OutputResult> = Vec::new();

	let legacy_builder = proof::LegacyProofBuilder::new(keychain);
	let builder = proof::ProofBuilder::new(keychain);
	let legacy_version = HeaderVersion(1);

	for output in outputs.iter() {
		let (commit, proof, is_coinbase, height, mmr_index) = output;
		// attempt to unwind message from the RP and get a value
		// will fail if it's not ours
		let info = {
			// Before HF+2wk, try legacy rewind first
			let info_legacy =
				if valid_header_version(height.saturating_sub(2 * WEEK_HEIGHT), legacy_version) {
					proof::rewind(keychain.secp(), &legacy_builder, *commit, None, *proof)?
				} else {
					None
				};

			// If legacy didn't work, try new rewind
			if info_legacy.is_none() {
				proof::rewind(keychain.secp(), &builder, *commit, None, *proof)?
			} else {
				info_legacy
			}
		};

		let (amount, key_id, switch) = match info {
			Some(i) => i,
			None => {
				continue;
			}
		};

		let lock_height = if *is_coinbase {
			*height + global::coinbase_maturity()
		} else {
			*height
		};

		debug!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			commit, amount, key_id, mmr_index
		);

		if switch != SwitchCommitmentType::Regular {
			warn!("Unexpected switch commitment type {:?}", switch);
		}

		//adding an extra check of the height.
		//get the height used while building the key_id
		let path = key_id.to_path();
		let last_child_number = path.path[3];

		let mut built_height = 0;
		if let ChildNumber::Normal { index: ind } = last_child_number {
			built_height = ind;
		}
		let on_the_chain_height = *height;
		let mut spent_candidate = false;
		if built_height != 0 && on_the_chain_height <= u32::MAX as u64 {
			//if the built height if too far from the height, should be reject it?
			//if the build height or height is out of the horizon range, should we trigger the self-spend(based on the configuration)
			let built_height_64 = built_height as u64;

			debug!(
				"the build_height and chain height is {}, {}",
				built_height_64, on_the_chain_height
			);
			//compare the built_height_64 with the current tip height.
			if let Some(e_height) = end_height {
				if e_height > built_height_64
					&& e_height - built_height_64 > 1440 * 7
					&& should_self_spend
					&& amount > self_spend_amount
				{
					self_spend_outputs.push(OutputResult {
						commit: *commit,
						key_id: key_id.clone(),
						n_child: key_id.to_path().last_path_index(),
						value: amount,
						height: *height,
						lock_height: lock_height,
						is_coinbase: *is_coinbase,
						mmr_index: *mmr_index,
					});
					spent_candidate = true;
				}
			}
		}

		if !spent_candidate {
			wallet_outputs.push(OutputResult {
				commit: *commit,
				key_id: key_id.clone(),
				n_child: key_id.to_path().last_path_index(),
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
	client: C,
	rewind_hash: String,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	C: NodeClient + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut vw = ViewWallet {
		rewind_hash: rewind_hash,
		output_result: vec![],
		total_balance: 0,
		last_pmmr_index: 0,
	};
	let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);

	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let percentage_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(true, msg, percentage_complete));
		}

		// Scanning outputs
		for output in outputs.iter() {
			let (commit, proof, is_coinbase, height, mmr_index) = output;
			let rewind_hash = from_hex(vw.rewind_hash.as_str())
				.map_err(|e| Error::RewindHash(format!("Unable to decode rewind hash: {}", e)))?;
			let rewind_nonce = blake2b(32, &commit.0, &rewind_hash);
			let nonce = SecretKey::from_slice(&secp, rewind_nonce.as_bytes())
				.map_err(|e| Error::Nonce(format!("Unable to create nonce: {}", e)))?;
			let info = secp.rewind_bullet_proof(*commit, nonce.clone(), None, *proof);

			if info.is_err() {
				continue;
			}

			let info = info.unwrap();
			vw.total_balance += info.value;
			let lock_height = if *is_coinbase {
				*height + global::coinbase_maturity()
			} else {
				*height
			};

			let output_info = ViewWalletOutputResult {
				commit: commit.to_hex(),
				value: info.value,
				height: *height,
				mmr_index: *mmr_index,
				is_coinbase: *is_coinbase,
				lock_height: lock_height,
			};

			vw.output_result.push(output_info);
		}
		if highest_index <= last_retrieved_index {
			vw.last_pmmr_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok(vw)
}

/// Scanning chain for the outputs. Shared with mwc713
pub fn collect_chain_outputs<'a, C, K>(
	keychain: &K,
	client: C,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	show_progress: bool,
	replay_config: Option<ReplayMitigationConfig>,
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
	let mut should_self_spent = false;
	let mut self_spent_amount = 0;
	if let Some(conf) = replay_config {
		if conf.replay_mitigation_flag {
			should_self_spent = true;
			self_spent_amount = conf.replay_mitigation_min_amount;
		}
	}
	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let perc_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(show_progress, msg, perc_complete));
		}
		let mut chain_outs_pair = identify_utxo_outputs(
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
		start_index = last_retrieved_index + 1;
	}
	Ok((result_vec, self_spend_candidate_list))
}

/// Respore missing outputs. Shared with mwc713
fn restore_missing_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	output: OutputResult,
	commit2transactionuuid: &HashMap<String, String>,
	transaction: &HashMap<String, WalletTxInfo>,
	found_parents: &mut HashMap<Identifier, u32>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let node_client = wallet.w2n_client().clone();
	let commit = wallet.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)?;
	let mut batch = wallet.batch(keychain_mask)?;

	let parent_key_id = output.key_id.parent_path();
	let mut path = parent_key_id.to_path();
	// Resetting reply attack prevention block number to 0, so we could calculate parent correctly
	path.path[3] = ChildNumber::from(0);
	let parent_key_id = path.to_identifier();

	if !found_parents.contains_key(&parent_key_id) {
		found_parents.insert(parent_key_id.clone(), 0);
	}

	let log_id = {
		if let Some(uuid) =
			commit2transactionuuid.get(&commit.clone().unwrap_or("None".to_string()))
		{
			// Transaction already exist. using it...
			transaction.get(uuid).unwrap().tx_log.id
		} else {
			// Creating new transaction
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
			if let Ok(hdr_info) = node_client.get_header_info(t.output_height) {
				t.update_confirmation_ts(hdr_info.confirmed_time);
			}
			batch.save_tx_log_entry(t, &parent_key_id)?;
			log_id
		}
	};

	let _ = batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		n_child: output.n_child,
		mmr_index: Some(output.mmr_index),
		commit: commit,
		value: output.value,
		status: OutputStatus::Unspent,
		height: output.height,
		lock_height: output.lock_height,
		is_coinbase: output.is_coinbase,
		tx_log_entry: Some(log_id),
	});

	let max_child_index = *found_parents.get(&parent_key_id).unwrap_or(&0);
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id, output.n_child);
	}

	batch.commit()?;
	Ok(())
}

#[derive(Debug)]
struct WalletOutputInfo {
	updated: bool,  // true if data was updated, we need push it into DB
	at_chain: bool, // true if this Output was founf at the Chain
	output: OutputData,
	commit: String,                  // commit as a string. output.output value
	tx_input_uuid: HashSet<String>,  // transactions where this commit is input
	tx_output_uuid: HashSet<String>, // transactions where this commit is output
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

	pub fn add_tx_input_uuid(&mut self, uuid: &str) {
		self.tx_input_uuid.insert(String::from(uuid));
	}

	pub fn add_tx_output_uuid(&mut self, uuid: &str) {
		self.tx_output_uuid.insert(String::from(uuid));
	}

	// Output that is not active and not mapped to any transaction.
	pub fn is_orphan_output(&self) -> bool {
		self.tx_input_uuid.len() == 0
			&& self.tx_output_uuid.len() == 0
			&& !self.output.is_spendable()
	}
}

#[derive(Debug)]
struct WalletTxInfo {
	updated: bool,   // true if data was updated, we need push it into DB
	tx_uuid: String, // transaction uuid++. Foramt:  "{}/{}/{}", uuid_str, tx.id, tx.parent_key_id.to_hex()
	tx_log: TxLogEntry,
	input_commit: HashSet<String>,   // Commits from input (if found)
	output_commit: HashSet<String>,  // Commits from output (if found)
	kernel_validation: Option<bool>, // Kernel validation flag. None - mean not validated because of height
}

impl WalletTxInfo {
	pub fn new(tx_uuid: String, tx_log: TxLogEntry) -> WalletTxInfo {
		WalletTxInfo {
			updated: false,
			tx_uuid,
			input_commit: tx_log
				.input_commits
				.iter()
				.map(|c| util::to_hex(&c.0))
				.collect(),
			output_commit: tx_log
				.output_commits
				.iter()
				.map(|c| util::to_hex(&c.0))
				.collect(),
			tx_log,
			kernel_validation: None,
		}
	}

	// read all commit from the transaction tx.
	pub fn add_transaction(&mut self, tx: Transaction) {
		for input in &tx.inputs_committed() {
			self.input_commit.insert(util::to_hex(&input.0));
		}

		for output in tx.outputs_committed() {
			self.output_commit.insert(util::to_hex(&output.0));
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
				if kernel.excess != pedersen::Commitment::from_vec(vec![0; 33]) {
					// We have a test case with zero (default value) kernel. Still need to handle
					self.tx_log.kernel_excess = Some(kernel.excess);
					self.updated = true;
				}
			}
		}
	}
}

// Getting: - transactions from wallet,
//          - outputs from wallet
//			- outputs from the chain
// Then build the transaction map that mapped to Outputs and
//     Outputs map that mapped to the transactions
fn get_wallet_and_chain_data<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
	show_progress: bool,
	do_full_outputs_refresh: bool, // true expected at the first and in case of reorgs
	replay_config: Option<ReplayMitigationConfig>,
) -> Result<
	(
		HashMap<String, WalletOutputInfo>, // Outputs. Key: Commit
		Vec<OutputResult>,                 // Chain outputs
		HashMap<String, WalletTxInfo>,     // Slate based Transaction. Key: tx uuid
		String,                            // Commit of the last output in the sequence
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	assert!(start_height <= end_height);
	let self_spend_candidate_list: Vec<OutputResult>;
	let mut self_spend_candidate_light_list: Vec<OutputResultLight> = Vec::new();

	// Resulting wallet's outputs with extended info
	// Key: commit
	let mut outputs: HashMap<String, WalletOutputInfo> = HashMap::new();
	let mut spendable_outputs = 0;

	// Collecting Outputs with known commits only.
	// Really hard to say why Output can be without commit. Probably same non complete or failed data.
	// In any case we can't use it for recovering.
	let mut last_output = String::new();

	// Wallet's transactions with extended info
	// Key: transaction uuid
	let mut transactions: HashMap<String, WalletTxInfo> = HashMap::new();
	let chain_outs: Vec<OutputResult>;
	{
		// First, reading data from the wallet
		for w_out in wallet.iter().filter(|w| w.commit.is_some()) {
			outputs.insert(
				w_out.commit.clone().unwrap(),
				WalletOutputInfo::new(w_out.clone()),
			);
			last_output = w_out.commit.clone().unwrap();

			if w_out.is_spendable() {
				spendable_outputs += 1;
			}
		}

		// Key: id + tx.parent_key_id
		let mut transactions_id2uuid: HashMap<String, String> = HashMap::new();
		let mut not_confirmed_txs = 0;

		let mut non_uuid_tx_counter: u32 = 0;
		let temp_uuid_data = [0, 0, 0, 0, 0, 0, 0, 0]; // uuid expected 8 bytes

		// Collect what inputs/outputs trabsactions already has
		let mut input_commits: HashSet<String> = HashSet::new();
		let mut output_commits: HashSet<String> = HashSet::new();

		// Collecting Transactions from the wallet. UUID need to be known, otherwise
		// transaction is non complete and can be ignored.
		for tx in wallet.tx_log_iter() {
			if !tx.confirmed {
				not_confirmed_txs += 1;
			}

			// For transactions without uuid generating temp uuid just for mapping
			let tx_uuid_str = match tx.tx_slate_id {
				Some(tx_slate_id) => tx_slate_id.to_string(),
				None => {
					non_uuid_tx_counter += 1;
					Uuid::from_fields(non_uuid_tx_counter, 0, 0, &temp_uuid_data)
						.map_err(|e| Error::GenericError(format!("Unable to create UUID, {}", e)))?
						.to_string()
				}
			};

			// uuid must include tx uuid, id for transaction to handle self send with same account,
			//    parent_key_id  to handle senf send to different accounts
			let uuid_str = format!(
				"{}/{}/{}",
				tx_uuid_str,
				tx.id,
				util::to_hex(&tx.parent_key_id.to_bytes())
			);

			let mut wtx = WalletTxInfo::new(uuid_str, tx.clone());

			if let Ok(transaction) = wallet.get_stored_tx_by_uuid(&tx_uuid_str, false) {
				wtx.add_transaction(transaction);
			};
			transactions_id2uuid.insert(
				format!("{}/{}", tx.id, util::to_hex(&tx.parent_key_id.to_bytes())),
				wtx.tx_uuid.clone(),
			);

			input_commits.extend(wtx.input_commit.iter().map(|s| s.clone()));
			output_commits.extend(wtx.output_commit.iter().map(|s| s.clone()));

			transactions.insert(wtx.tx_uuid.clone(), wtx);
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

		let height_deep_limit =
			SYNC_BLOCKS_DEEPNESS + not_confirmed_txs / 2 + spendable_outputs / OUTPUT_TO_BLOCK;

		// We need to choose a strategy. If there are few blocks, it is really make sense request those blocks
		if !do_full_outputs_refresh && (end_height - start_height <= height_deep_limit as u64) {
			debug!("get_wallet_and_chain_data using block base strategy");

			// Validate kernels from transaction. Kernel are a source of truth
			// Because of account transfer we might have 2 transactions with same kernel from the both sides.
			let mut txkernel_to_txuuid: HashMap<String, Vec<String>> = HashMap::new();

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
						let kernel = util::to_hex(&tx.tx_log.kernel_excess.clone().unwrap().0);

						if let Some(v) = txkernel_to_txuuid.get_mut(&kernel) {
							v.push(tx_uuid.clone());
						} else {
							txkernel_to_txuuid.insert(kernel, vec![tx_uuid.clone()]);
						}
					}
				}
			}

			let client = wallet.w2n_client().clone();
			let keychain = wallet.keychain(keychain_mask)?;

			let mut blocks: Vec<crate::mwc_api::BlockPrintable> = Vec::new();

			let mut cur_height = start_height;
			while cur_height <= end_height {
				// next block to request the data
				let next_h = cmp::min(
					end_height,
					cur_height + (SYNC_BLOCKS_THREADS * SYNC_BLOCKS_THREADS - 1) as u64,
				);

				// printing the progress
				if let Some(ref s) = status_send_channel {
					let msg = format!(
						"Checking {} blocks, Height: {} - {}",
						next_h - cur_height + 1,
						cur_height,
						next_h,
					);
					// 10 - 90 %
					let perc_complete = ((next_h + cur_height) / 2 - start_height) * 80
						/ (end_height - start_height + 1)
						+ 10;
					let _ = s.send(StatusMessage::Scanning(
						show_progress,
						msg,
						perc_complete as u8,
					));
				}

				blocks.extend(client.get_blocks_by_height(
					cur_height,
					next_h,
					SYNC_BLOCKS_THREADS,
				)?);
				cur_height = next_h + 1;
			}
			// Checking blocks...
			// Let's check if all heights are there. Sorry, have issues, little paranoid, assuming node can be broken
			let mut block_heights: Vec<u64> = blocks.iter().map(|b| b.header.height).collect();
			block_heights.sort();
			if block_heights.len() as u64 != end_height - start_height + 1 {
				return Err(Error::Node("Unable to get all blocks data".to_string()))?;
			}
			if block_heights[0] != start_height
				|| block_heights[block_heights.len() - 1] != end_height
			{
				return Err(Error::Node(
					"Get not expected blocks from the node".to_string(),
				))?;
			}
			if block_heights.len() > 1 {
				for i in 1..block_heights.len() {
					if block_heights[i - 1] != block_heights[i] - 1 {
						return Err(Error::Node(
							"Get duplicated blocks from the node".to_string(),
						))?;
					}
				}
			}

			assert!(blocks.len() as u64 == end_height - start_height + 1);

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
							let tx = transactions.get_mut(tx_uuid).unwrap();
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
								crate::mwc_api::OutputType::Coinbase => true,
								crate::mwc_api::OutputType::Transaction => false,
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
				&keychain,
				node_outputs,
				Some(end_height),
				should_self_spent,
				self_spent_amount,
			)?;

			chain_outs = output_pair.0;
			self_spend_candidate_list = output_pair.1;

			// Reporting user what outputs we found
			if let Some(ref s) = status_send_channel {
				let mut msg = format!(
					"For height: {} - {} Identified {} wallet_outputs as belonging to this wallet [",
					start_height,
					end_height,
					chain_outs.len(),
				);
				let mut cnt = 8;
				for ch_out in &chain_outs {
					msg.push_str(&util::to_hex(&ch_out.commit.0));
					msg.push_str(",");
					cnt -= 1;
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

				let _ = s.send(StatusMessage::Scanning(show_progress, msg, 99));
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
			let keychain = wallet.keychain(keychain_mask)?;

			// Retrieve the actual PMMR index range we're looking for
			let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;

			// Getting outputs that are published on the chain.
			let chain_outs_pair = collect_chain_outputs(
				&keychain,
				client,
				pmmr_range.0,
				Some(pmmr_range.1),
				status_send_channel,
				show_progress,
				replay_config,
			)?;
			chain_outs = chain_outs_pair.0;
			self_spend_candidate_list = chain_outs_pair.1;

			// Reporting user what outputs we found
			if let Some(ref s) = status_send_channel {
				let mut msg = format!(
					"For height: {} - {} PMMRs: {} - {} Identified {} wallet_outputs as belonging to this wallet [",
					start_height, end_height, pmmr_range.0, pmmr_range.1,
					chain_outs.len(),
				);
				for ch_out in &chain_outs {
					msg.push_str(&util::to_hex(&ch_out.commit.0));
					msg.push_str(",");
				}
				if !chain_outs.is_empty() {
					msg.pop();
				}
				msg.push_str("]");

				let _ = s.send(StatusMessage::Scanning(show_progress, msg, 99));
			}

			// Validate kernels from transaction. Kernel are a source of truth
			let client = wallet.w2n_client().clone();
			for tx in transactions.values_mut() {
				if !(tx.tx_log.confirmed || tx.tx_log.is_cancelled_reverted())
					|| tx.tx_log.output_height >= start_height
					|| start_height < 2
				{
					// Skipping old coinbase transaction that are not confirmed
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

						match res {
							Some((txkernel, height, _mmr_index)) => {
								tx.kernel_validation = Some(true);
								assert!(txkernel.excess == *kernel);
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
			let wallet_outputs_to_check: Vec<pedersen::Commitment> = outputs
				.values()
				.filter(|out| out.output.is_spendable() && !out.commit.is_empty())
				// Parsing Commtment string into the binary, how API needed
				.map(|out| util::from_hex(&out.output.commit.as_ref().unwrap()))
				.filter(|out| out.is_ok())
				.map(|out| pedersen::Commitment::from_vec(out.unwrap()))
				.collect();

			// get_outputs_from_nodefor large number will take a time. Chunk size is 200 ids.

			let mut commits: HashMap<pedersen::Commitment, (String, u64, u64)> = HashMap::new();

			if wallet_outputs_to_check.len() > 100 {
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Warning(format!("You have {} active outputs, it is a large number, validation will take time. Please wait...", wallet_outputs_to_check.len())));
				}

				// processing them by groups becuase we want to shouw the progress
				let slices: Vec<&[pedersen::Commitment]> =
					wallet_outputs_to_check.chunks(100).collect();

				let mut chunk_num = 0;

				for chunk in &slices {
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Scanning(
							show_progress,
							"Validating outputs".to_string(),
							(chunk_num * 100 / slices.len()) as u8,
						));
					}
					chunk_num += 1;

					commits.extend(client.get_outputs_from_node(&chunk.to_vec())?);
				}

				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::ScanningComplete(
						show_progress,
						"Finish outputs validation".to_string(),
					));
				}
			} else {
				commits = client.get_outputs_from_node(&wallet_outputs_to_check)?;
			}

			// Updating commits data with that
			// Key: commt, Value Heihgt
			let node_commits: HashMap<String, u64> = commits
				.values()
				.map(|(commit, height, _mmr)| (commit.clone(), height.clone()))
				.collect();

			for out in outputs
				.values_mut()
				.filter(|out| out.output.is_spendable() && out.output.commit.is_some())
			{
				if let Some(height) = node_commits.get(&out.commit) {
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
						a => {
							debug_assert!(false);
							a.clone()
						}
					};
					out.updated = true;
				}
			}
		}

		// Now let's process inputs from transaction that change it's status from confirmed to non confirmed
		// the issue that some Spent can be exist on the chain and they must be turn to Locked for now
		let mut commits: HashSet<String> = HashSet::new();

		for tx in transactions.values() {
			if tx.kernel_validation.is_some() {
				if tx.tx_log.confirmed && tx.kernel_validation.clone().unwrap() == false {
					// All input commits need to reevaluate
					commits.extend(tx.input_commit.clone());
				}
			}
		}

		commits.retain(|c| outputs.contains_key(c));

		if !commits.is_empty() {
			let wallet_outputs_to_check: Vec<pedersen::Commitment> = commits
				.iter()
				.map(|out| util::from_hex(out))
				.filter(|out| out.is_ok())
				.map(|out| pedersen::Commitment::from_vec(out.unwrap()))
				.collect();

			let client = wallet.w2n_client().clone();

			// Node will return back only Commits that are exist now.
			let active_commits: HashMap<pedersen::Commitment, (String, u64, u64)> =
				client.get_outputs_from_node(&wallet_outputs_to_check)?;

			for (active_commit, _, _) in active_commits.values() {
				let output = outputs.get_mut(active_commit).ok_or(Error::GenericError(
					"Node return unknown commit value".to_string(),
				))?;
				if output.output.status != OutputStatus::Locked {
					output.output.status = OutputStatus::Locked;
					output.updated = true;
				}
			}
		}
		//convert the commitment to string in self_spend list

		for output in self_spend_candidate_list {
			let commit = wallet
				.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)
				.unwrap()
				.unwrap();
			self_spend_candidate_light_list.push(OutputResultLight {
				key_id: output.key_id,
				value: output.value.clone(),
				commit: commit,
			});
		}
	}

	// //do the self_spend
	debug!(
		"the self spent list is {:?}",
		self_spend_candidate_light_list
	);
	for output in self_spend_candidate_light_list {
		self_spend_particular_output(
			wallet,
			keychain_mask,
			output.value,
			output.commit,
			None,
			0,
			0,
		)?;
	}

	Ok((outputs, chain_outs, transactions, last_output))
}

/// Scan outputs with a given rewind hash view wallet.
/// Retrieve all outputs information that belongs to it.
pub fn scan_rewind_hash<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	rewind_hash: String,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(
			true,
			"Starting UTXO scan".to_owned(),
			0,
		));
	}
	let client = wallet.w2n_client().clone();

	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;

	let chain_outs = collect_chain_outputs_rewind_hash(
		client,
		rewind_hash,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_send_channel,
	)?;

	let msg = format!(
		"Identified {} wallet_outputs as belonging to this wallet",
		chain_outs.output_result.len(),
	);
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(true, msg, 99));
	}
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			true,
			"Scanning Complete".to_owned(),
		));
	}
	Ok(chain_outs)
}

/// Check / repair wallet contents by scanning against chain
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn scan<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	del_unconfirmed: bool,
	start_height: u64,
	tip_height: u64, // tip
	status_send_channel: &Option<Sender<StatusMessage>>,
	show_progress: bool,
	do_full_outputs_refresh: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(
			show_progress,
			"Starting UTXO scan".to_owned(),
			0,
		));
	}

	// Collect the data form the chain and from the wallet
	let replay_config = get_replay_config();
	let (mut outputs, chain_outs, mut transactions, last_output) = get_wallet_and_chain_data(
		wallet,
		keychain_mask.clone(),
		start_height,
		tip_height,
		status_send_channel,
		show_progress,
		do_full_outputs_refresh,
		Some(replay_config),
	)?;

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

	// It is a save heihgt, we can't rollback there at node level
	let archive_height = Chain::height_2_archive_height(tip_height).saturating_sub(DAY_HEIGHT * 2);

	// Validated outputs states against the chain
	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();
	let outputs2del = validate_outputs(
		wallet,
		keychain_mask.clone(),
		start_height,
		&chain_outs,
		&mut outputs,
		&transactions,
		status_send_channel,
		&mut found_parents,
	)?;

	// Processing slate based transactions. Just need to update 'confirmed flag' and height
	// We don't want to cancel the transactions. Let's user do that.
	// We can uncancel transactions if it is confirmed
	let _result = validate_transactions(
		wallet,
		keychain_mask,
		&mut transactions,
		&outputs,
		status_send_channel,
	);

	// Checking for output to transaction mapping. We don't want to see active outputs without trsansaction or with cancelled transactions
	// we might unCancel transaction if output was found but all mapped transactions are cancelled (user just a cheater)
	validate_outputs_ownership(
		wallet,
		keychain_mask,
		&mut outputs,
		&mut transactions,
		status_send_channel,
	);

	// Delete any unconfirmed outputs (requested by user), unlock any locked outputs and delete (cancel) associated transactions
	if del_unconfirmed {
		delete_unconfirmed(&mut outputs, &mut transactions, status_send_channel);
	}

	// Let's check the consistency. Report is we found any discrepency, so users can do the check or restore.
	{
		validate_consistancy(&mut outputs, &mut transactions);
	}

	// Here we are done with all state changes of Outputs and transactions. Now we need to save them at the DB
	// Note, unknown new outputs are not here because we handle them in the beginning by 'restore'.

	// Apply last data updates and saving the data into DB.
	{
		store_transactions_outputs(
			wallet,
			keychain_mask.clone(),
			&outputs2del,
			&mut outputs,
			tip_height,
			&last_output,
			&transactions,
			status_send_channel,
			archive_height,
		)?;
	}

	{
		restore_labels(
			wallet,
			keychain_mask.clone(),
			&found_parents,
			status_send_channel,
		)?;
	}

	// Updating confirmed height record. The height at what we finish updating the data
	// Updating 'done' job for all accounts that was involved. Update was done for all accounts- let's update that
	{
		let accounts: Vec<Identifier> = wallet.acct_path_iter().map(|m| m.path).collect();
		let mut batch = wallet.batch(keychain_mask)?;

		for par_id in &accounts {
			batch.save_last_confirmed_height(par_id, tip_height)?;
		}
		batch.commit()?;
	}

	// Cancel any cancellable transactions with an expired TTL
	// We need to do that at the end when all scan data is updated and written. Otherwise data can be overwritten on updates
	{
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
			Some(true),
		)?;

		for tx_log in &transactions {
			if tx_log.confirmed || tx_log.is_cancelled_reverted() {
				continue;
			}

			if let Some(h) = tx_log.ttl_cutoff_height {
				if tip_height >= h {
					match tx::cancel_tx(
						wallet,
						keychain_mask,
						&tx_log.parent_key_id,
						Some(tx_log.id),
						None,
					) {
						Err(e) => {
							if let Some(ref s) = status_send_channel {
								let _ = s.send(StatusMessage::Warning(format!(
									"Unable to cancel TTL expired transaction {} because of error: {}",
									tx_log.tx_slate_id.clone().unwrap_or(Uuid::nil()),
									e
								)));
							}
						}
						_ => (),
					}
				}
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
		// Dump the same from the DB.
		if let Some(ref s) = status_send_channel {
			let _ = crate::api_impl::owner::dump_wallet_data(wallet_inst.clone(), s, Some(String::from("/tmp/end.txt")) );
		}
	}*/

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			show_progress,
			"Scanning Complete".to_owned(),
		));
	}

	Ok(())
}

// Validated outputs states against the chain
// Returns Output that need to be deleted. It is possible because
// We might find that Key Id is broken and Outputs are stored by this key_id.
// That is why we need to delete prev copy.
fn validate_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	start_height: u64,
	chain_outs: &Vec<OutputResult>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transaction: &HashMap<String, WalletTxInfo>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	found_parents: &mut HashMap<Identifier, u32>,
) -> Result<Vec<OutputData>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut commit2transactionuuid: HashMap<String, String> = HashMap::new();
	for tx in transaction.values() {
		for out in &tx.output_commit {
			commit2transactionuuid.insert(out.clone(), tx.tx_uuid.clone());
		}
	}

	let mut outputs2del: Vec<OutputData> = Vec::new();

	// Update wallet outputs with found at the chain outputs
	// Check how sync they are
	for ch_out in chain_outs {
		let commit = util::to_hex(&ch_out.commit.0);

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

				// Validating status of the output.
				match w_out.output.status {
					OutputStatus::Spent => {
						// Spent output not supposed to exist at the chain. Seems like send transaction is not at the chain yet.
						// Reverting state to Locked
						if let Some(ref s) = status_send_channel {
							let _ = match &w_out.output.commit {
								Some(commit) => s.send(StatusMessage::Warning(format!("Changing status for output {} from Spent to Locked", commit))),
								None => s.send(StatusMessage::Warning(format!("Changing status for coin base output at height {} from Spent to Locked", w_out.output.height))),
							};
						}
						w_out.updated = true;
						w_out.output.status = OutputStatus::Locked;
					}
					OutputStatus::Unconfirmed | OutputStatus::Reverted => {
						// Very expected event. Output is at the chain and we get a confirmation.
						if let Some(ref s) = status_send_channel {
							let _ = match &w_out.output.commit {
								Some(commit) => s.send(StatusMessage::Info(format!("Changing status for output {} from Unconfirmed/Reverted to Unspent", commit))),
								None => s.send(StatusMessage::Info(format!("Changing status for coin base output at height {} from Unconfirmed/Reverted to Unspent", w_out.output.height))),
							};
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
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Warning(format!(
						"Confirmed output for {} with ID {} ({:?}, index {}) exists in UTXO set but not in wallet. Restoring.",
						ch_out.value, ch_out.key_id, ch_out.commit, ch_out.mmr_index
					)));
				}
				restore_missing_output(
					wallet,
					keychain_mask,
					ch_out.clone(),
					&commit2transactionuuid,
					transaction,
					found_parents,
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
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Warning(format!(
							"Changing status for output {} from Unspent to Unconfirmed",
							w_out.commit
						)));
					}
					w_out.updated = true;
					w_out.output.status = OutputStatus::Reverted;
				}
				OutputStatus::Locked => {
					// Locked is not on the chain is expected, It is mean that our send transaction was confirmed.
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Changing status for output {} from Locked to Spent",
							w_out.commit
						)));
					}
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
	transactions: &mut HashMap<String, WalletTxInfo>,
	outputs: &HashMap<String, WalletOutputInfo>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for tx_info in transactions.values_mut() {
		// Checking the kernel - the source of truth for transactions
		if tx_info.kernel_validation.is_some() {
			if tx_info.kernel_validation.clone().unwrap() {
				// transaction is valid
				if tx_info.tx_log.is_cancelled_reverted() {
					tx_info.tx_log.uncancel_unrevert();
					tx_info.updated = true;

					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Warning(format!(
							"Changing transaction {} from Canceled to active and confirmed",
							tx_info.tx_uuid.split('/').next().unwrap_or("????")
						)));
					}
				}

				if !tx_info.tx_log.confirmed {
					tx_info.tx_log.confirmed = true;

					if let Ok(hdr_info) = wallet
						.w2n_client()
						.get_header_info(tx_info.tx_log.output_height)
					{
						tx_info
							.tx_log
							.update_confirmation_ts(hdr_info.confirmed_time);
					}
					tx_info.updated = true;

					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Changing transaction {} state to confirmed",
							tx_info.tx_uuid.split('/').next().unwrap_or("????")
						)));
					}
				}
			} else {
				if !tx_info.tx_log.is_cancelled_reverted() {
					if tx_info.tx_log.confirmed {
						tx_info.tx_log.confirmed = false;
						tx_info.updated = true;
						tx_info.tx_log.tx_type = match &tx_info.tx_log.tx_type {
							TxLogEntryType::TxReceived => {
								tx_info.tx_log.reverted_after =
									tx_info.tx_log.confirmation_ts.clone().and_then(|t| {
										let now = chrono::Utc::now();
										(now - t).to_std().ok()
									});
								TxLogEntryType::TxReverted
							}
							t => t.clone(),
						};
						if let Some(ref s) = status_send_channel {
							let _ = s.send(StatusMessage::Info(format!(
								"Changing transaction {} state to NOT confirmed",
								tx_info.tx_uuid.split('/').next().unwrap_or("????")
							)));
						}
					}
				}
			}
		}

		let _update_result = update_non_kernel_transaction(wallet, tx_info, outputs);

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

fn delete_duplicated_coinbase_transactions<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	collided_coinbase_txs: &Vec<TxLogEntry>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// correcting the problem, deleting all tx except the firt one
	let mut batch = wallet.batch(keychain_mask)?;

	for i in 1..collided_coinbase_txs.len() {
		batch.delete_tx_log_entry(
			collided_coinbase_txs[i].id,
			&collided_coinbase_txs[i].parent_key_id,
		)?;
	}

	Ok(())
}

// Checking for output to transaction mapping. We don't want to see active outputs without trsansaction or with cancelled transactions
// we might unCancel transaction if output was found but all mapped transactions are cancelled (user just a cheater)
fn validate_outputs_ownership<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &mut HashMap<String, WalletTxInfo>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for w_out in outputs.values_mut() {
		// For every output checking to how many transaction it belong as Input and Output

		// Because of Account to account transactions (any type self transactions) we can have pairs.
		// Those pairs should be processed as a single transaction, overwise it will be guarantee
		// false collision reporting
		let in_cancelled_uuid: HashSet<String> = w_out
			.tx_input_uuid
			.iter()
			.filter(|tx_uuid| {
				transactions
					.get(*tx_uuid)
					.map(|tx| tx.tx_log.is_cancelled_reverted())
					.unwrap_or(false)
			})
			.map(|tx_uuid| format!("{}", tx_uuid.split('/').next().unwrap_or("????")))
			.collect();

		let in_all_uuid: HashSet<String> = w_out
			.tx_input_uuid
			.iter()
			.map(|tx_uuid| format!("{}", tx_uuid.split('/').next().unwrap_or("????")))
			.collect();

		let in_active = in_all_uuid.len() - in_cancelled_uuid.len();

		let out_cancelled_uuid: HashSet<String> = w_out
			.tx_output_uuid
			.iter()
			.filter(|tx_uuid| {
				transactions
					.get(*tx_uuid)
					.map(|tx| tx.tx_log.is_cancelled_reverted())
					.unwrap_or(false)
			})
			.map(|tx_uuid| format!("{}", tx_uuid.split('/').next().unwrap_or("????")))
			.collect();

		let out_all_uuid: HashSet<String> = w_out
			.tx_output_uuid
			.iter()
			.map(|tx_uuid| format!("{}", tx_uuid.split('/').next().unwrap_or("????")))
			.collect();

		let out_active = out_all_uuid.len() - out_cancelled_uuid.len();

		// Commit can belong to 1 transaction only. Other wise it is a transaction issue.
		// Fortunatelly transaction issue doesn't affect the balance of send logic.
		// So we can just report to user that he can't trust the transactions Data
		if out_active > 1 {
			// If it is mining transaction with a single output, we can fix that.

			let mut collided_coinbase_txs: Vec<TxLogEntry> = Vec::new();
			for tx_uuid in &w_out.tx_output_uuid {
				if let Some(tx) = transactions.get(tx_uuid) {
					if tx.tx_log.tx_type == TxLogEntryType::ConfirmedCoinbase {
						collided_coinbase_txs.push(tx.tx_log.clone());
					}
				}
			}

			if collided_coinbase_txs.len() > 1 {
				if let Err(e) = delete_duplicated_coinbase_transactions(
					wallet,
					keychain_mask,
					&collided_coinbase_txs,
				) {
					error!("Unable to delete duplicated coinbase transacitons, {}", e);
				}
			} else {
				report_transaction_collision(
					status_send_channel,
					&w_out.commit,
					&w_out.tx_output_uuid,
					&transactions,
					false,
				);
			}
		}

		if in_active > 1 {
			report_transaction_collision(
				status_send_channel,
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
					if let Some(ref s) = status_send_channel {
						let _ = match &w_out.output.commit {
							Some(commit) => s.send(StatusMessage::Warning(format!(
								"Changing status for output {} from Locked to Unspent",
								commit
							))),
							None => s.send(StatusMessage::Warning(format!(
								"Changing status for output at height {} from Locked to Unspent",
								w_out.output.height
							))),
						};
					}
					w_out.output.status = OutputStatus::Unspent;
					w_out.updated = true;
				}
				if out_active == 0 && out_cancelled_uuid.len() > 0 {
					let _result = recover_first_cancelled(
						wallet,
						status_send_channel,
						&w_out.tx_input_uuid,
						transactions,
					);
				}
			}
			OutputStatus::Spent => {
				// output have to have some valid transation. User cancel all of them?
				if out_active == 0 && out_cancelled_uuid.len() > 0 {
					let _result = recover_first_cancelled(
						wallet,
						status_send_channel,
						&w_out.tx_output_uuid,
						transactions,
					);
				}
				if in_active == 0 && in_cancelled_uuid.len() > 0 {
					let _result = recover_first_cancelled(
						wallet,
						status_send_channel,
						&w_out.tx_input_uuid,
						transactions,
					);
				}
			}
			OutputStatus::Unconfirmed | OutputStatus::Reverted => {
				// Unconfirmed can be anything. We can delete that output
			}
			OutputStatus::Unspent => {
				// output have to have some valid transaction that created it. User cancel all of them?
				if in_active > 0 {
					// it is not Locked, it must be active output
					if let Some(ref s) = status_send_channel {
						let _ = match &w_out.output.commit {
							Some(commit) => s.send(StatusMessage::Warning(format!(
								"Changing status for output {} from Unspent to Locked",
								commit
							))),
							None => s.send(StatusMessage::Warning(format!(
								"Changing status for output at height {} from Unspent to Locked",
								w_out.output.height
							))),
						};
					}
					w_out.output.status = OutputStatus::Locked;
					w_out.updated = true;
				}
				if out_active == 0 && out_cancelled_uuid.len() > 0 {
					let _result = recover_first_cancelled(
						wallet,
						status_send_channel,
						&w_out.tx_output_uuid,
						transactions,
					);
				}
			}
		}
	}
}

// Delete any unconfirmed outputs (requested by user), unlock any locked outputs and delete (cancel) associated transactions
fn delete_unconfirmed(
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &mut HashMap<String, WalletTxInfo>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) {
	let mut transaction2cancel: HashSet<String> = HashSet::new();

	for w_out in outputs.values_mut() {
		match w_out.output.status {
			OutputStatus::Locked => {
				if let Some(ref s) = status_send_channel {
					let _ = match &w_out.output.commit {
						Some(commit) => s.send(StatusMessage::Warning(format!("Changing status for output {} from Locked to Unspent", commit))),
						None => s.send(StatusMessage::Warning(format!("Changing status for coin base output at height {} from Locked to Unspent", w_out.output.height))),
					};
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

	for tx_uuid in &transaction2cancel {
		if let Some(tx) = transactions.get_mut(tx_uuid) {
			if !tx.tx_log.is_cancelled_reverted() {
				// let's cancell transaction
				match tx.tx_log.tx_type {
					TxLogEntryType::TxSent => {
						tx.tx_log.tx_type = TxLogEntryType::TxSentCancelled;
					}
					TxLogEntryType::TxReceived => {
						tx.tx_log.reverted_after =
							tx.tx_log.confirmation_ts.clone().and_then(|t| {
								let now = chrono::Utc::now();
								(now - t).to_std().ok()
							});
						tx.tx_log.tx_type = TxLogEntryType::TxReverted;
					}
					TxLogEntryType::ConfirmedCoinbase => {
						// coinbased not confirmed are filtered out. That is why there no needs to change the status
						tx.tx_log.confirmed = false;
					}
					_ => assert!(false), // Not expected, must be logical issue
				}
				tx.updated = true;
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Warning(format!(
						"Cancelling transaction {}",
						tx_uuid.split('/').next().unwrap_or("????")
					)));
				}
			}
		}
	}
}

// consistency checking. Report is we found any discrepancy, so users can do the check or restore.
// Here not much what we can do because full node scan or restore from the seed is required.
fn validate_consistancy(
	outputs: &mut HashMap<String, WalletOutputInfo>,
	transactions: &mut HashMap<String, WalletTxInfo>,
) {
	for tx_info in transactions.values_mut() {
		if tx_info.tx_log.is_cancelled_reverted() {
			continue;
		}

		if tx_info.tx_log.confirmed {
			// For confirmed inputs/outputs can't be Unconfirmed.
			// Inputs can't be spendable
			for out in &tx_info.input_commit {
				if let Some(out) = outputs.get_mut(out) {
					if out.output.status == OutputStatus::Unconfirmed
						|| out.output.status == OutputStatus::Reverted
					{
						out.output.status = OutputStatus::Spent;
						out.updated = true;
					}
				}
			}

			for out in &tx_info.output_commit {
				if let Some(out) = outputs.get_mut(out) {
					if out.output.status == OutputStatus::Unconfirmed
						|| out.output.status == OutputStatus::Reverted
					{
						out.output.status = OutputStatus::Spent;
						out.updated = true;
					}
				}
			}
		} else {
			// for non confirmed input can be anything
			// Output can't be valid.
			for out in &tx_info.output_commit {
				if let Some(out) = outputs.get_mut(out) {
					if out.output.status == OutputStatus::Spent {
						out.output.status = OutputStatus::Reverted;
						out.updated = true;
					}
				}
			}
		}
	}
}

// Apply last data updates and saving the data into DB.
fn store_transactions_outputs<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	outputs2del: &Vec<OutputData>,
	outputs: &mut HashMap<String, WalletOutputInfo>,
	tip_height: u64, // tip
	last_output: &String,
	transactions: &HashMap<String, WalletTxInfo>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	archive_height: u64,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let node_client = wallet.w2n_client().clone();
	let mut batch = wallet.batch(keychain_mask)?;

	// This time is secondary, used if TX output_height is not defined
	let tx_time_to_archive = Utc::now() - Duration::days(5);

	// Slate based Transacitons
	for tx in transactions.values() {
		if tx.updated {
			batch.save_tx_log_entry(tx.tx_log.clone(), &tx.tx_log.parent_key_id)?;
		}

		// checking if can archive the transaction
		// Can archive if there is no connections with non archived outputs AND it below horizon:
		let mut can_archive_tx = if tx.tx_log.output_height == 0 {
			tx.tx_log.creation_ts < tx_time_to_archive
		} else {
			tx.tx_log.output_height < archive_height
		};

		if can_archive_tx {
			// Checking if no not archived outputs are exist
			for outpt in &tx.output_commit {
				if outputs.contains_key(outpt) {
					can_archive_tx = false;
					break;
				}
			}
		}

		if can_archive_tx {
			// Archiving transactions into IMDB and mwctx files
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
		}

		// Unconfirmed without any transactions must be deleted as well
		if (output.is_orphan_output() && !output.output.is_coinbase) ||
			// Delete expired mining outputs
			( output.output.is_coinbase && (output.output.status == OutputStatus::Unconfirmed || output.output.status == OutputStatus::Reverted) && ((output.output.height < tip_height) || (output.commit != *last_output)) )
		{
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Warning(format!(
					"Deleting unconfirmed Output not mapped to any transaction. Commit: {}",
					output
						.output
						.commit
						.clone()
						.unwrap_or("UNKNOWN_COMMIT".to_string())
				)));
			}
			batch.delete(&output.output.key_id, &output.output.mmr_index)?;
		}

		// Archiving very old spent ouput can go into archive
		if output.output.height < archive_height {
			match output.output.status {
				OutputStatus::Spent => batch.archive_output(&output.output.key_id)?,
				OutputStatus::Reverted | OutputStatus::Unconfirmed => {
					// check if transactions are not confirmed and not concelled, then we can archive such transactions
					let mut need_wait = false;
					for tx_id in &output.tx_output_uuid {
						if let Some(tx) = transactions.get(tx_id) {
							if tx.tx_log.tx_type == TxLogEntryType::TxReceived
								|| tx.tx_log.tx_type == TxLogEntryType::TxSent
							{
								need_wait = true;
							}
						}
					}
					if !need_wait {
						batch.archive_output(&output.output.key_id)?;
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
			let mut t = TxLogEntry::new(
				parent_key_id.clone(),
				TxLogEntryType::ConfirmedCoinbase,
				log_id,
			);
			t.confirmed = true;
			if let Ok(hdr_info) = node_client.get_header_info(t.output_height) {
				t.update_confirmation_ts(hdr_info.confirmed_time);
			}
			t.output_height = w_out.output.height;
			t.amount_credited = w_out.output.value;
			t.amount_debited = 0;
			t.num_outputs = 1;
			// calculate kernel excess for coinbase
			if w_out.output.commit.is_some() {
				let secp = batch.keychain().secp();
				let over_commit = secp.commit_value(w_out.output.value)?;
				let commit = pedersen::Commitment::from_vec(
					util::from_hex(w_out.output.commit.as_ref().unwrap()).map_err(|e| {
						Error::GenericError(format!("Output commit parse error, {}", e))
					})?,
				);
				t.output_commits = vec![commit.clone()];
				let excess = secp.commit_sum(vec![commit], vec![over_commit])?;
				t.kernel_excess = Some(excess);
				t.kernel_lookup_min_height = Some(w_out.output.height);
			}
			w_out.output.tx_log_entry = Some(log_id);

			batch.save_tx_log_entry(t, parent_key_id)?;
			batch.save(w_out.output.clone())?;
		}
	}

	batch.commit()?;

	Ok(())
}

fn update_non_kernel_transaction<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	tx_info: &mut WalletTxInfo,
	outputs: &HashMap<String, WalletOutputInfo>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Handle legacy broken data case. Transaction might not have any kernel. Let's out outputs to upadte the state
	if tx_info.tx_log.kernel_excess.is_none() {
		// Rule is very simple. If outputs are exist, we will map them and update transaction status by that
		let mut outputs_state: HashSet<OutputStatus> = HashSet::new();
		for commit in &tx_info.output_commit {
			if let Some(out) = outputs.get(commit) {
				outputs_state.insert(out.output.status.clone());
			}
		}

		let mut input_state: HashSet<OutputStatus> = HashSet::new();
		for commit in &tx_info.input_commit {
			if let Some(out) = outputs.get(commit) {
				input_state.insert(out.output.status.clone());
			}
		}

		if !outputs_state.is_empty()
			&& !outputs_state.contains(&OutputStatus::Unconfirmed)
			&& !outputs_state.contains(&OutputStatus::Reverted)
		{
			if tx_info.tx_log.is_cancelled_reverted() {
				tx_info.tx_log.uncancel_unrevert();
				tx_info.updated = true;
			}
			if !tx_info.tx_log.confirmed {
				tx_info.tx_log.confirmed = true;
				{
					if let Ok(hdr_info) = wallet
						.w2n_client()
						.get_header_info(tx_info.tx_log.output_height)
					{
						tx_info
							.tx_log
							.update_confirmation_ts(hdr_info.confirmed_time);
					}
				}

				tx_info.updated = true;
			}
		} else if outputs_state.contains(&OutputStatus::Unconfirmed)
			|| outputs_state.contains(&OutputStatus::Reverted)
		{
			if tx_info.tx_log.confirmed {
				tx_info.tx_log.confirmed = false;
				tx_info.updated = true;
			}
		}
	}
	Ok(())
}

// restore labels, account paths and child derivation indices
fn restore_labels<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	found_parents: &HashMap<Identifier, u32>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label_base = "account";
	let accounts: Vec<Identifier> = wallet.acct_path_iter().map(|m| m.path).collect();
	let mut acct_index = accounts.len();
	for (path, max_child_index) in found_parents.iter() {
		// Only restore paths that don't exist
		if !accounts.contains(path) {
			let label = format!("{}_{}", label_base, acct_index);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Warning(format!(
					"Setting account {} at path {}",
					label, path
				)));
			}
			keys::set_acct_path(wallet, keychain_mask, &label, path)?;
			acct_index += 1;
		}
		let current_child_index = wallet.current_child_index(&path)?;
		if *max_child_index >= current_child_index {
			let mut batch = wallet.batch(keychain_mask)?;
			debug!("Next child for account {} is {}", path, max_child_index + 1);
			batch.save_child_index(path, max_child_index + 1)?;
			batch.commit()?;
		}
	}

	Ok(())
}

// Report to user about transactions that point to the same output.
fn report_transaction_collision(
	status_send_channel: &Option<Sender<StatusMessage>>,
	commit: &String,
	tx_uuid: &HashSet<String>,
	transactions: &HashMap<String, WalletTxInfo>,
	inputs: bool,
) {
	// We don't want to report collision for old transactions. Migration could be a reason. Those messages
	// are aknowledged and users didn't recreate the wallet to get rid of them.
	// 4-5 month from now transaction should be valid. Expected that all users are migrated the wallet by that time
	let height_limit = if global::is_mainnet() {
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

	if let Some(ref s) = status_send_channel {
		let mut cancelled_tx = String::new();
		tx_uuid
			.iter()
			.map(|tx_uuid| transactions.get(tx_uuid))
			.filter(|wtx| {
				wtx.map(|tx| !tx.tx_log.is_cancelled_reverted())
					.unwrap_or(false)
			})
			.for_each(|wtx| {
				if cancelled_tx.len() > 0 {
					cancelled_tx.push_str(", ");
				}
				let tx = wtx.unwrap();
				cancelled_tx.push_str(&format!(
					"{}",
					tx.tx_uuid.split('/').next().unwrap_or("????")
				));
			});

		let inputs = if inputs { "inputs" } else { "outputs" };

		let _ = s.send(StatusMessage::Warning(format!(
			"We detected transaction collision on {} {} for transactions with Id {}",
			inputs, commit, cancelled_tx
		)));
	}
}

// By some reasons output exist but all related transactions are cancelled. Let's activate one of them
// Note! There is no analisys what transaction to activate. As a result that can trigger the transaction collision.
// We don't want to implement complicated algorithm to handle that. User suppose to be sane and not cancell transactions without reason.
fn recover_first_cancelled<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_uuid: &HashSet<String>,
	transactions: &mut HashMap<String, WalletTxInfo>,
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
					_ => panic!(
						"Internal error. Expected cancelled transaction, but get different value"
					),
				};
				wtx.tx_log.confirmed = true;
				if let Ok(hdr_info) = wallet
					.w2n_client()
					.get_header_info(wtx.tx_log.output_height)
				{
					wtx.tx_log.update_confirmation_ts(hdr_info.confirmed_time);
				}
				wtx.updated = true;
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Warning(format!(
						"Changing transaction {} state from {:?} to {:?}",
						wtx.tx_uuid.split('/').next().unwrap_or("????"),
						prev_tx_state,
						wtx.tx_log.tx_type
					)));
				}

				break;
			}
		}
	}
	Ok(())
}

///this method is part of the solution to prevent replay attack
///Which is tracked in this discussion  https://forum.mwc.mw/t/replay-attacks-and-possible-mitigations/7415
/// and this github ticket: https://github.com/mwcproject/mwc-qt-wallet/issues/508

pub fn self_spend_particular_output<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	commit_string: String,
	address: Option<String>,
	_current_height: u64,
	_minimum_confirmations: u64,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	//spend this output to the account itself.
	let fee = tx_fee(1, 1, 1); //there is only one input and one output and one kernel
							//let amount = output.eligible_to_spend(current_height, minimum_confirmations);

	let mut output_vec = HashSet::new();
	output_vec.insert(commit_string);
	let args = InitTxArgs {
		src_acct_name: address.clone(),
		amount: amount - fee,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		outputs: Some(output_vec),
		ttl_blocks: Some(2),
		..Default::default()
	};

	let mut slate;
	{
		//send
		slate = owner::init_send_tx(wallet, keychain_mask, &args, false, 1)?;
		//receiver
		let mut dest_account_name: Option<String> = None;
		let address_string;
		if address.is_some() {
			address_string = address.clone().unwrap();
			dest_account_name = Some(address_string);
		}
		slate = foreign::receive_tx(
			wallet,
			keychain_mask,
			&slate,
			address.clone(),
			None,
			None,
			&dest_account_name,
			None,
			false,
			false,
		)?
		.0;
		owner::tx_lock_outputs(wallet, keychain_mask, &slate, address, 0, false)?;
		slate = owner::finalize_tx(wallet, keychain_mask, &slate, false, false)
			.unwrap()
			.0;
	}
	let client = {
		// Test keychain mask, to keep API consistent
		let _ = wallet.keychain(keychain_mask)?;
		wallet.w2n_client().clone()
	};
	owner::post_tx(&client, slate.tx_or_err()?, false)?;
	Ok(())
}
