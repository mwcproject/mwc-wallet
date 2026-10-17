// Copyright 2019 The vault713 Developers
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

/// Swap API trait
pub mod api;

/// Library that support bitcoin operations
pub mod bitcoin;

/// Library that support ethereum operations
pub mod ethereum;

/// Swap crate errors
pub mod error;

/// Messages that Buyer and Seller are exchanging during the swap process
pub mod message;

/// schnorr signature routine
pub mod multisig;

/// Finite State Machine that handle swap workflow
pub mod fsm;

/// Swap buyer API (selling MWC for BTC)
pub mod buyer;
/// Swap Seller API (selling BTC for MWC)
pub mod seller;
/// Swap state object that is used by both byer abd seller
pub mod swap;
/// Swap trade sessions catalog
pub mod trades;

/// Serialization adapters
pub mod ser;

/// Types used by swap library
pub mod types;

pub mod owner_eth;
pub mod owner_swap;

pub use self::error::Error;
pub use self::swap::Swap;
pub use self::types::Context;
#[cfg(all(test, feature = "test-support"))]
use mwc_wallet_util::mwc_crates::blake2_rfc;
#[cfg(all(test, feature = "test-support"))]
use mwc_wallet_util::mwc_crates::serde_json;
//pub use self::types::BtcSellerContext;

pub(crate) use self::api::SwapApi;
pub(crate) use self::buyer::BuyApi;
pub(crate) use self::seller::SellApi;

pub use mwc_wallet_util::mwc_keychain::Keychain;

#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
#[cfg(all(test, feature = "test-support"))]
use mwc_wallet_util::mwc_crates::serial_test;
#[cfg(all(test, feature = "test-support"))]
use mwc_wallet_util::mwc_crates::serial_test::serial;
#[cfg(feature = "test-support")]
use mwc_wallet_util::Mutex;
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "test-support")]
use std::sync::Arc;

const CURRENT_VERSION: u8 = 2;

#[cfg(feature = "test-support")]
use self::ethereum::*;

#[cfg(feature = "test-support")]
lazy_static! {
	/// Flag to set test mode
	static ref TEST_MODE: AtomicBool = AtomicBool::new(false);
	static ref ACTIVATE_TEST_RESPONSE: AtomicBool = AtomicBool::new(true);
	static ref ETH_RANDOM_WALLET: Arc<Mutex<Option<EthereumWallet>>> = Arc::new(Mutex::new(None));
}

/// Set the test mode
#[cfg(feature = "test-support")]
pub fn set_test_mode(mode: bool) {
	TEST_MODE.store(mode, Ordering::Relaxed);
}

/// Check if we are in test mode
#[cfg(feature = "test-support")]
pub fn is_test_mode() -> bool {
	TEST_MODE.load(Ordering::Relaxed)
}

/// Set the test mode
#[cfg(feature = "test-support")]
pub fn activate_test_response(mode: bool) {
	ACTIVATE_TEST_RESPONSE.store(mode, Ordering::Relaxed);
}

/// Check if we are in test mode
#[cfg(feature = "test-support")]
pub fn is_test_response() -> bool {
	ACTIVATE_TEST_RESPONSE.load(Ordering::Relaxed)
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
	mod coinbase_maturity;
	mod eth_finality;
	mod import;
	mod initial_redeem_fees;
	mod message_persistence;
	mod redeem_adaptor;
	mod redeem_cancellation;
	mod redeem_fees;
	mod redeem_recovery;
	mod roadmap;
	mod seller_recovery;

	use super::bitcoin::*;
	use super::message::Message;
	use super::types::*;
	use super::*;
	use crate::swap::fsm::machine::StateMachine;
	use crate::swap::fsm::state;
	use crate::swap::fsm::state::{Input, StateId, StateProcessRespond};
	use crate::swap::message::{SecondaryUpdate, Update};
	use crate::{
		NodeClient, NodeOutputDetails, SecondaryFeeUnits, Slate, SlateVersion, VersionedSlate,
	};
	use bitcoin_lib::secp256k1::ContextFlag;
	use bitcoin_lib::{Address, AddressType, Transaction as BitcoinTransaction, TxOut};
	use mwc_wallet_util::mwc_api;
	use mwc_wallet_util::mwc_bitcoin as bitcoin_lib;
	use mwc_wallet_util::mwc_core::consensus;
	use mwc_wallet_util::mwc_core::core::transaction::Weighting;
	use mwc_wallet_util::mwc_core::core::Committed;
	use mwc_wallet_util::mwc_core::core::OutputFeatures;
	use mwc_wallet_util::mwc_core::core::{Inputs, KernelFeatures, Transaction, TxKernel};
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_core::global::ChainTypes;
	use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;
	#[cfg(not(target_os = "windows"))]
	use mwc_wallet_util::mwc_crates::serde::{de::DeserializeOwned, Serialize};
	use mwc_wallet_util::mwc_crates::uuid::Uuid;
	#[cfg(not(target_os = "windows"))]
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	use mwc_wallet_util::mwc_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
	use mwc_wallet_util::mwc_p2p;
	use mwc_wallet_util::mwc_util::to_hex;
	use mwc_wallet_util::mwc_wagyu_ethereum::{wordlist::English, Ropsten};
	use mwc_wallet_util::Mutex;
	use std::collections::HashMap;
	use std::convert::TryInto;
	use std::fs::read_to_string;
	#[cfg(not(target_os = "windows"))]
	use std::fs::write;
	use std::mem;
	use std::sync::Arc;

	const MWC_UNIT: u64 = 1_000_000_000;

	#[cfg(not(target_os = "windows"))]
	fn assert_json_fixture<T>(path: &str, actual: &T)
	where
		T: DeserializeOwned + Serialize,
	{
		let fixture: T = serde_json::from_str(&read_to_string(path).unwrap()).unwrap();
		let fixture = serde_json::to_value(fixture).unwrap();
		let actual = serde_json::to_value(actual).unwrap();
		assert_eq!(fixture, actual);
	}

	fn keychain(secp: &Secp256k1, idx: u8) -> ExtKeychain {
		let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
		let seed_sell = blake2_rfc::blake2b::blake2b(32, &[], seed_sell.as_bytes());
		ExtKeychain::from_seed(secp, seed_sell.as_bytes(), false).unwrap()
	}

	fn context_sell(secp: &Secp256k1, kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(secp, kc, 1, 0),
			lock_nonce: key(secp, kc, 1, 1),
			refund_nonce: key(secp, kc, 1, 2),
			redeem_nonce: key(secp, kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				parent_key_id: key_id(0, 0),
				inputs: vec![
					SellerInput::new(key_id(0, 1), None, 60 * MWC_UNIT, false),
					SellerInput::new(key_id(0, 2), None, 60 * MWC_UNIT, false),
				],
				change_output: output_key_id(3),
				change_amount: 20 * MWC_UNIT, // selling 100 coins, so 20 will be left
				refund_output: output_key_id(4),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: key_id(0, 5),
				}),
			}),
		}
	}

	fn context_buy(secp: &Secp256k1, kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(secp, kc, 1, 0),
			lock_nonce: key(secp, kc, 1, 1),
			refund_nonce: key(secp, kc, 1, 2),
			redeem_nonce: key(secp, kc, 1, 3),
			role_context: RoleContext::Buyer(BuyerContext {
				parent_key_id: key_id(0, 0),
				output: output_key_id(1),
				redeem: key_id(0, 2),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: key_id(0, 3),
				}),
			}),
		}
	}

	fn key_id(d1: u32, d2: u32) -> Identifier {
		ExtKeychain::derive_key_id(2, d1, d2, 0, 0).unwrap()
	}

	fn output_key_id(child: u32) -> Identifier {
		ExtKeychain::derive_key_id(3, 0, 0, child, 0).unwrap()
	}

	fn key(secp: &Secp256k1, kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
		kc.derive_key(secp, 0, &key_id(d1, d2), SwitchCommitmentType::None)
			.unwrap()
	}

	// Method is used for testing. Normally we have multiple currencies, so the names must be different...
	fn btc_address(secp: &mut Secp256k1, kc: &ExtKeychain) -> String {
		let secret_key = key(secp, kc, 2, 0);
		let key = PublicKey::from_secret_key(secp, &secret_key).unwrap();
		let address = Address::new_btc()
			.p2pkh(
				secp,
				&bitcoin_lib::util::key::PublicKey {
					compressed: true,
					key,
				},
				bitcoin_lib::network::constants::Network::Testnet,
			)
			.unwrap();
		format!("{}", address)
	}

	fn context_eth_sell(secp: &Secp256k1, kc: &ExtKeychain) -> Context {
		let eth_sell_wallet = EthereumWallet::from_mnemonic::<Ropsten, English>(
			ETH_MNEMONIC,
			Some(ETH_PARTICIPANT_PASSWORD),
			ETH_ACCOUNT_PATH,
		)
		.unwrap();
		let redeem_address = to_eth_address(eth_sell_wallet.address.clone().unwrap());
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(secp, kc, 1, 0),
			lock_nonce: key(secp, kc, 1, 1),
			refund_nonce: key(secp, kc, 1, 2),
			redeem_nonce: key(secp, kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				parent_key_id: key_id(0, 0),
				inputs: vec![
					SellerInput::new(key_id(0, 1), None, 60 * MWC_UNIT, false),
					SellerInput::new(key_id(0, 2), None, 60 * MWC_UNIT, false),
				],
				change_output: output_key_id(3),
				change_amount: 20 * MWC_UNIT, // selling 100 coins, so 20 will be left
				refund_output: output_key_id(4),
				secondary_context: SecondarySellerContext::Eth(EthSellerContext {
					redeem_address: Some(redeem_address.unwrap()),
				}),
			}),
		}
	}

	fn context_eth_buy(secp: &Secp256k1, kc: &ExtKeychain) -> Context {
		let sec_key = key(secp, kc, 0, 2);
		let eth_rand_wallet =
			EthereumWallet::from_private_key(to_hex(&sec_key.0).as_str()).unwrap();
		let address_from_secret = to_eth_address(eth_rand_wallet.address.clone().unwrap());
		*ETH_RANDOM_WALLET.lock() = Some(eth_rand_wallet.clone());

		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(secp, kc, 1, 0),
			lock_nonce: key(secp, kc, 1, 1),
			refund_nonce: key(secp, kc, 1, 2),
			redeem_nonce: key(secp, kc, 1, 3),
			role_context: RoleContext::Buyer(BuyerContext {
				parent_key_id: key_id(0, 0),
				output: output_key_id(1),
				redeem: key_id(0, 2),
				secondary_context: SecondaryBuyerContext::Eth(EthBuyerContext {
					address_from_secret: address_from_secret.unwrap(),
				}),
			}),
		}
	}

	#[derive(Debug, Clone)]
	pub(super) struct TestNodeClientState {
		pub height: u64,
		pub chain_tip_error: Option<String>,
		pub pending: Vec<Transaction>,
		pub post_error_after_accept: bool,
		pub post_calls: usize,
		pub preflight_calls: usize,
		pub preflight_error: Option<String>,
		// Apply a chain-height change and optional spend before a numbered check.
		pub preflight_chain_updates: HashMap<usize, (u64, Option<Commitment>)>,
		// A test can cap lookups so a regressed FSM cycle fails instead of hanging.
		pub kernel_lookups: usize,
		pub kernel_lookup_limit: Option<usize>,
		pub outputs: HashMap<Commitment, u64>,
		pub kernels: HashMap<Commitment, (TxKernel, u64)>,
	}

	#[derive(Debug, Clone)]
	pub(super) struct TestNodeClient {
		pub state: Arc<Mutex<TestNodeClientState>>,
	}

	impl TestNodeClient {
		pub fn new(height: u64) -> Self {
			let state = TestNodeClientState {
				height,
				chain_tip_error: None,
				pending: Vec::new(),
				post_error_after_accept: false,
				post_calls: 0,
				preflight_calls: 0,
				preflight_error: None,
				preflight_chain_updates: HashMap::new(),
				kernel_lookups: 0,
				kernel_lookup_limit: None,
				outputs: HashMap::new(),
				kernels: HashMap::new(),
			};
			Self {
				state: Arc::new(Mutex::new(state)),
			}
		}

		pub fn push_output(&self, commit: Commitment) {
			let mut state = self.state.lock();
			let height = state.height;
			state.outputs.insert(commit, height);
		}

		fn add_seller_inputs(&self, secp: &Secp256k1, keychain: &ExtKeychain, context: &Context) {
			for input in &context.unwrap_seller().unwrap().inputs {
				self.push_output(
					keychain
						.commit(
							secp,
							input.amount,
							&input.key_id,
							SwitchCommitmentType::Regular,
						)
						.unwrap(),
				);
			}
		}

		pub fn mine_block(&self) {
			let mut state = self.state.lock();
			state.height += 1;
			let height = state.height;

			let pending = mem::replace(&mut state.pending, Vec::new());
			for tx in pending {
				for input in tx.inputs_committed().expect("test transaction inputs") {
					let input = input.expect("test input commitment");
					state.outputs.remove(&input);
				}
				for output in tx.outputs_committed().expect("test transaction outputs") {
					let output = output.expect("test output commitment");
					state.outputs.insert(output, height);
				}
				for kernel in tx.body.kernels {
					state
						.kernels
						.insert(kernel.excess.clone(), (kernel, height));
				}
			}
		}

		pub fn mine_blocks(&self, count: u64) {
			if count > 0 {
				self.mine_block();
				if count > 1 {
					let mut state = self.state.lock();
					state.height += count - 1;
				}
			}
		}

		/// Get a current state for the test chain
		pub fn get_state(&self) -> TestNodeClientState {
			self.state.lock().clone()
		}

		/// Set a state for the test chain
		pub fn set_state(&self, chain_state: &TestNodeClientState) {
			let mut state = self.state.lock();
			*state = chain_state.clone();
		}

		// Clean the data, not height. Reorg attack
		pub fn clean(&self) {
			let mut state = self.state.lock();
			state.pending.clear();
			state.outputs.clear();
			state.kernels.clear();
		}
	}

	impl NodeClient for TestNodeClient {
		fn set_node_index(&mut self, _node_index: u8) {
			unimplemented!()
		}
		fn get_node_index(&self) -> u8 {
			0
		}
		fn get_chain_tip(&self) -> Result<(u64, String, u64), crate::Error> {
			let state = self.state.lock();
			if let Some(error) = &state.chain_tip_error {
				return Err(crate::Error::Node(error.clone()));
			}
			let height = state.height;
			let res = (height, format!("testnodehash:{}", height), 123455);
			Ok(res)
		}
		fn get_header_info(&self, height: u64) -> Result<crate::HeaderInfo, crate::Error> {
			Ok(crate::HeaderInfo {
				height,
				hash: format!("testnodehash:{}", height),
				confirmed_time: String::new(),
				version: 1,
				nonce: 0,
				total_difficulty: 123455,
			})
		}
		fn get_header_by_hash(&self, hash: &str) -> Result<crate::NodeHeaderLink, crate::Error> {
			let height = hash
				.strip_prefix("testnodehash:")
				.and_then(|height| height.parse::<u64>().ok())
				.filter(|height| *height <= self.state.lock().height)
				.ok_or_else(|| crate::Error::Node(format!("Unknown test header {}", hash)))?;
			Ok(crate::NodeHeaderLink {
				height,
				hash: hash.to_owned(),
				previous: format!("testnodehash:{}", height.saturating_sub(1)),
			})
		}
		fn get_connected_peer_info(
			&self,
		) -> Result<Vec<mwc_p2p::types::PeerInfoDisplayLegacy>, crate::Error> {
			unimplemented!()
		}
		fn height_range_to_pmmr_indices(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
		) -> Result<(u64, u64), crate::Error> {
			unimplemented!()
		}
		fn get_blocks_by_height(
			&self,
			_start_height: u64,
			_end_height: u64,
			_threads_number: usize,
		) -> Result<Vec<mwc_api::BlockPrintable>, crate::Error> {
			unimplemented!()
		}

		fn reset_cache(&self) {}

		fn test_mempool_accept(
			&self,
			request: &crate::transaction_preflight::MempoolAcceptRequest,
		) -> Result<crate::transaction_preflight::MempoolAcceptResponse, crate::Error> {
			use crate::transaction_preflight::{MempoolAcceptResponse, PreflightTransaction};
			use mwc_wallet_util::mwc_core::core::transaction_preflight::PreflightDependencies;
			let mut state = self.state.lock();
			state.preflight_calls += 1;
			let call = state.preflight_calls;
			if let Some((height, spent)) = state.preflight_chain_updates.remove(&call) {
				state.height = height;
				if let Some(spent) = spent {
					state.outputs.remove(&spent);
				}
			}
			if let Some(error) = state
				.preflight_error
				.as_ref()
				.or(state.chain_tip_error.as_ref())
			{
				return Err(crate::Error::Node(error.clone()));
			}
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			request.validate_size().map_err(crate::Error::Node)?;
			let tip =
				mwc_wallet_util::mwc_core::core::hash::Hash::from_vec(&state.height.to_be_bytes());
			let mut response = MempoolAcceptResponse::new(request, tip, state.height);
			if let Some(expected) = request.expected_tip {
				let height = u64::from_be_bytes(expected.as_bytes()[..8].try_into().unwrap());
				let canonical =
					mwc_wallet_util::mwc_core::core::hash::Hash::from_vec(&height.to_be_bytes());
				if height > state.height || expected != canonical {
					response.reject("tip", "Anchor is not on the current body chain".into());
					return Ok(response);
				}
			}
			let pending = state
				.pending
				.iter()
				.map(|tx| PreflightTransaction::from_transaction(0, tx, true))
				.collect::<Result<Vec<_>, _>>()?;
			let mut dependencies = PreflightDependencies::default();
			for (request, result) in request.transactions.iter().zip(&mut response.transactions) {
				let tx = request
					.validation_transaction(0, &secp)
					.map_err(crate::Error::Node)?;
				request.check_balance(&tx, &secp, result);
				result.valid_from_height = tx.lock_height();
				let available = dependencies.check(request, result);
				if !request.allow_future_height && result.valid_from_height > state.height + 1 {
					result.reject("height", "Transaction is timelocked".into());
				}
				result.already_known =
					request.is_complete && pending.iter().any(|tx| request.same_transaction(tx));
				for input in &request.inputs {
					if !available
						.iter()
						.any(|output| output.commitment() == input.commitment)
						&& !state.outputs.contains_key(&input.commitment)
						&& !pending
							.iter()
							.any(|tx| tx.outputs.iter().any(|o| o.commitment == input.commitment))
					{
						result.reject("input_missing", "Input is not unspent".into());
					}
					if pending.iter().any(|tx| {
						!request.same_transaction(tx)
							&& tx.inputs.iter().any(|i| i.commitment == input.commitment)
					}) {
						result.reject("pool", "Input is already spent in the public pool".into());
					}
				}
				for output in &request.outputs {
					if state.outputs.contains_key(&output.commitment)
						|| pending.iter().any(|tx| {
							!request.same_transaction(tx)
								&& tx.outputs.iter().any(|o| o.commitment == output.commitment)
						}) {
						result.reject("outputs", "Output already exists".into());
					}
				}
				dependencies.remember(request, result);
			}
			Ok(response.finish())
		}

		fn post_tx(
			&self,
			tx: &Transaction,
			_fluff: bool,
			receipt: crate::transaction_preflight::PreflightReceipt,
		) -> Result<(), crate::Error> {
			receipt.check(self, tx)?;
			self.state.lock().post_calls += 1;
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
			tx.validate(0, Weighting::AsTransaction, &mut secp)
				.map_err(|e| crate::Error::Node(format!("Node failure, {}", e)))?;

			let mut state = self.state.lock();
			for input in tx
				.inputs_committed()
				.map_err(|e| crate::Error::Node(e.to_string()))?
			{
				let input = input.map_err(|e| crate::Error::Node(e.to_string()))?;
				// Output not unspent
				if !state.outputs.contains_key(&input) {
					return Err(crate::Error::Node("Node failure".to_string()));
				}

				// Double spend attempt
				for tx_pending in state.pending.iter() {
					for in_pending in tx_pending
						.inputs_committed()
						.map_err(|e| crate::Error::Node(e.to_string()))?
					{
						let in_pending =
							in_pending.map_err(|e| crate::Error::Node(e.to_string()))?;
						if in_pending == input {
							return Err(crate::Error::Node("Node failure".to_string()));
						}
					}
				}
			}
			// Check for duplicate output
			for output in tx
				.outputs_committed()
				.map_err(|e| crate::Error::Node(e.to_string()))?
			{
				let output = output.map_err(|e| crate::Error::Node(e.to_string()))?;
				if state.outputs.contains_key(&output) {
					return Err(crate::Error::Node("Node failure".to_string()));
				}

				for tx_pending in state.pending.iter() {
					for out_pending in tx_pending
						.outputs_committed()
						.map_err(|e| crate::Error::Node(e.to_string()))?
					{
						let out_pending =
							out_pending.map_err(|e| crate::Error::Node(e.to_string()))?;
						if out_pending == output {
							return Err(crate::Error::Node("Node failure".to_string()));
						}
					}
				}
			}
			// Check for duplicate kernel
			for kernel in tx.kernels() {
				// Duplicate kernel
				if state.kernels.contains_key(&kernel.excess) {
					return Err(crate::Error::Node("Node failure".to_string()));
				}

				for tx_pending in state.pending.iter() {
					for kernel_pending in tx_pending.kernels() {
						if kernel_pending.excess == kernel.excess {
							return Err(crate::Error::Node("Node failure".to_string()));
						}
					}
				}
			}
			state.pending.push(tx.clone());
			if state.post_error_after_accept {
				return Err(crate::Error::Node("Submission response lost".to_string()));
			}

			Ok(())
		}
		fn get_version_info(&mut self) -> Option<crate::NodeVersionInfo> {
			unimplemented!()
		}
		fn get_outputs_from_node(
			&self,
			wallet_outputs: &Vec<Commitment>,
		) -> Result<HashMap<Commitment, NodeOutputDetails>, crate::Error> {
			let mut map = HashMap::new();
			let state = self.state.lock();
			for output in wallet_outputs {
				if let Some(height) = state.outputs.get(&output) {
					map.insert(
						*output,
						NodeOutputDetails {
							commit: to_hex(&output.0),
							height: *height,
							mmr_index: 0,
						},
					);
				}
			}
			Ok(map)
		}
		fn get_outputs_by_pmmr_index(
			&self,
			_start_height: u64,
			_end_height: Option<u64>,
			_max_outputs: u64,
		) -> Result<(u64, u64, Vec<(Commitment, RangeProof, bool, u64, u64)>), crate::Error> {
			unimplemented!()
		}
		fn get_kernel(
			&self,
			excess: &Commitment,
			_min_height: Option<u64>,
			max_height: Option<u64>,
		) -> Result<Option<(TxKernel, u64, u64)>, crate::Error> {
			let mut state = self.state.lock();
			state.kernel_lookups += 1;
			if state
				.kernel_lookup_limit
				.is_some_and(|limit| state.kernel_lookups > limit)
			{
				return Err(crate::Error::Node("Test kernel lookup limit exceeded".into()));
			}
			let res = state
				.kernels
				.get(excess)
				.filter(|(_, height)| max_height.map_or(true, |maximum| *height <= maximum))
				.map(|(kernel, height)| (kernel.clone(), *height, 0));
			Ok(res)
		}
	}

	#[test]
	#[serial]
	fn btc_slate_confirmation_requires_kernel() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_buy(&secp, &kc);
		let mut buyer: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_buy_1.json").unwrap()).unwrap();
		let seller: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_2.json").unwrap()).unwrap();
		buyer.seller_lock_first = true;
		buyer.state = StateId::BuyerWaitingForSellerToLock;
		buyer.wait_for_backup1 = false;
		let nc = TestNodeClient::new(300_002);
		let api = BtcSwapApi::new_test(
			Arc::new(nc.clone()),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);

		// The buyer has a complete lock body but only a placeholder kernel.
		assert_eq!(
			buyer.lock_slate.slate.tx_or_err().unwrap().kernels()[0].excess.0,
			[0; 33]
		);
		let multisig = buyer.multisig.commit(&secp).unwrap();
		let change = buyer
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.outputs()
			.iter()
			.map(|output| output.commitment())
			.find(|commit| *commit != multisig)
			.unwrap();
		// Model a seller publishing its change in a different transaction,
		// without creating the multisig lock output.
		nc.push_output(change);
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_lock_conf, None);
		let mut fsm = api.get_fsm(&kc, &buyer);
		let response = fsm
			.process(Input::Check, &mut buyer, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerWaitingForSellerToLock);
		assert!(!buyer.other_lock_first_done);

		// On a fresh chain, the real finalized lock must still be detected from
		// the buyer's unfinished slate and allow secondary funding to proceed.
		nc.clean();
		let lock_tx = seller.lock_slate.slate.tx_or_err().unwrap();
		for input in lock_tx.inputs_committed().unwrap() {
			nc.push_output(input.unwrap());
		}
		crate::owner::post_tx(0, &nc, lock_tx, false).unwrap();
		nc.mine_block();
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_lock_conf, Some(1));
		let response = fsm
			.process(Input::Check, &mut buyer, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		assert!(buyer.other_lock_first_done);

		// The same derivation must find the refund kernel. Both confirmations
		// must remain available once all transaction outputs have been spent.
		let refund_height = seller.refund_slate.slate.get_lock_height_check().unwrap();
		nc.mine_blocks(refund_height - nc.get_state().height);
		crate::owner::post_tx(0, &nc, seller.refund_slate.slate.tx_or_err().unwrap(), false)
			.unwrap();
		nc.mine_block();
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_refund_conf, Some(1));
		nc.state.lock().outputs.clear();
		let spent = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(spent.mwc_lock_conf, confirmations.mwc_lock_conf);
		assert_eq!(spent.mwc_refund_conf, confirmations.mwc_refund_conf);
	}

	// Follow the buyer from accepting a forged offer to observing real chain
	// confirmations. An unrelated confirmed kernel must not count as either the
	// swap lock or refund, and must not prompt BTC funding. Once the actual swap
	// transactions confirm, polling must find them despite the forged excesses.
	#[test]
	#[serial]
	fn btc_slate_confirmation_ignores_peer_supplied_excess() {
		use mwc_wallet_util::mwc_core::libtx::{build, proof};

		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let message = Message::from_json(include_str!("../../swap_test/message_1.json")).unwrap();
		let (id, mut offer, secondary_update) = message.unwrap_offer().unwrap();
		let mut offered_lock = offer.lock_slate.into_slate_plain(0, true).unwrap();
		let mut offered_refund = offer.refund_slate.into_slate_plain(0, true).unwrap();
		let fee = offered_lock.fee;

		// The referenced kernel belongs to a valid transaction with no swap output.
		let unrelated_kc = keychain(&secp, 7);
		let builder = proof::ProofBuilder::new(&secp, &unrelated_kc).unwrap();
		let unrelated_tx = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: fee.try_into().unwrap(),
			},
			&[
				build::feature_input(200 * MWC_UNIT, OutputFeatures::Plain, key_id(9, 1)),
				build::height_tagged_output(
					200 * MWC_UNIT - fee,
					output_key_id(2),
					offered_lock.height,
				),
			],
			&unrelated_kc,
			&builder,
		)
		.unwrap();
		let unrelated_excess = unrelated_tx.kernels()[0].excess;
		// Change only the excess fields in the incoming offer. The lock and refund
		// bodies still describe the swap, but now claim the unrelated kernel's ID.
		offered_lock.tx_or_err_mut().unwrap().body.kernels[0].excess = unrelated_excess;
		offered_refund.tx_or_err_mut().unwrap().body.kernels[0].excess = unrelated_excess;
		offer.lock_slate =
			VersionedSlate::into_version_plain(0, &offered_lock, SlateVersion::V3).unwrap();
		offer.refund_slate =
			VersionedSlate::into_version_plain(0, &offered_refund, SlateVersion::V3).unwrap();
		offer.seller_lock_first = true;
		// Seed spendable inputs so normal offer validation can succeed, then mine
		// only the unrelated transaction. The swap's multisig output is absent.
		let nc = TestNodeClient::new(300_000);
		for input in offered_lock
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			nc.push_output(input.unwrap());
		}
		for input in unrelated_tx.inputs_committed().unwrap() {
			nc.push_output(input.unwrap());
		}
		crate::owner::post_tx(0, &nc, &unrelated_tx, false).unwrap();
		nc.mine_block();

		// Exercise normal offer acceptance, which retains the peer's kernel fields.
		let kc = keychain(&secp, 2);
		let context = context_buy(&secp, &kc);
		let mut buyer = BuyApi::accept_swap_offer(
			0,
			&mut secp,
			None,
			&kc,
			&context,
			id,
			offer,
			secondary_update,
			&nc,
		)
		.unwrap();
		for slate in [&buyer.lock_slate.slate, &buyer.refund_slate.slate] {
			assert_eq!(
				slate.tx_or_err().unwrap().kernels()[0].excess,
				unrelated_excess
			);
			assert_ne!(slate.calc_excess(&secp).unwrap(), unrelated_excess);
		}
		assert!(
			!nc.get_state()
				.outputs
				.contains_key(&buyer.multisig.commit(&secp).unwrap())
		);
		// Model a buyer that has sent its acceptance and completed the backup step.
		// This lets the state machine evaluate funding instead of retrying delivery.
		buyer.posted_msg1 = Some(swap::get_cur_time());
		buyer.state = StateId::BuyerWaitingForSellerToLock;
		buyer.wait_for_backup1 = false;
		let api = BtcSwapApi::new_test(
			Arc::new(nc.clone()),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);
		// Neither body-derived kernel is on-chain. Both confirmations must be
		// absent, and the buyer must keep waiting without authorizing BTC funding.
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_lock_conf, None);
		assert_eq!(confirmations.mwc_refund_conf, None);
		let mut fsm = api.get_fsm(&kc, &buyer);
		let response = fsm
			.process(
				Input::Check,
				&mut buyer,
				&context,
				&confirmations,
				&mut secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerWaitingForSellerToLock);
		assert!(!buyer.other_lock_first_done);

		// Mine the real lock while leaving the buyer's forged excess untouched.
		// Expect one lock confirmation, no refund confirmation, and permission for
		// the buyer to proceed to BTC funding only after this real lock exists.
		let seller: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_2.json")).unwrap();
		crate::owner::post_tx(0, &nc, seller.lock_slate.slate.tx_or_err().unwrap(), false)
			.unwrap();
		nc.mine_block();
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_lock_conf, Some(1));
		assert_eq!(confirmations.mwc_refund_conf, None);
		let response = fsm
			.process(
				Input::Check,
				&mut buyer,
				&context,
				&confirmations,
				&mut secp,
			)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		assert!(buyer.other_lock_first_done);

		// Advance to the refund lock height and mine the real refund. Its derived
		// kernel must yield one confirmation even though its stored excess is wrong.
		let refund_height = seller.refund_slate.slate.get_lock_height_check().unwrap();
		nc.mine_blocks(refund_height - nc.get_state().height);
		crate::owner::post_tx(0, &nc, seller.refund_slate.slate.tx_or_err().unwrap(), false)
			.unwrap();
		nc.mine_block();
		let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
		assert_eq!(confirmations.mwc_refund_conf, Some(1));
	}

	// Exercise the buyer's lock and refund derivation paths independently. A
	// nonzero stored excess must not hide an unsupported compact slate or an
	// invalid output commitment. An unfinished body with no outputs should instead
	// report no confirmation, allowing polling to continue during construction.
	#[test]
	#[serial]
	fn btc_slate_confirmation_rejects_invalid_derivation() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let buyer: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json")).unwrap();
		let api = BtcSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_002)),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);

		// A nonzero excess must not bypass validation of either derived slate.
		for refund in [false, true] {
			let mut invalid = buyer.clone();
			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.tx_or_err_mut().unwrap().body.kernels[0].excess =
				slate.calc_excess(&secp).unwrap();
			// Start with the correct nonzero excess, then mark the slate compact.
			// Polling must reject it: compact derivation uses participant keys and
			// cannot establish that this transaction body is the one confirmed.
			slate.compact_slate = true;
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &invalid),
				Err(Error::InvalidMessageData(message)) if message.contains("non-compact slate")
			));

			// Restore the supported format but make one output commitment invalid.
			// Expect the derivation error to propagate, without using the stored
			// excess as a fallback or treating the error as an absent transaction.
			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.compact_slate = false;
			slate.tx_or_err_mut().unwrap().body.outputs[0]
				.identifier
				.commit
				.0 = [0; 33];
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &invalid),
				Err(Error::LibWallet(_))
			));

			// Removing all outputs models an unfinished slate. This is a normal
			// pending state: polling succeeds and reports neither transaction confirmed.
			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.tx_or_err_mut().unwrap().body.outputs.clear();
			let confirmations = api.request_tx_confirmations(&secp, &kc, &invalid).unwrap();
			assert_eq!(confirmations.mwc_lock_conf, None);
			assert_eq!(confirmations.mwc_refund_conf, None);
		}
	}

	#[test]
	#[serial]
	fn test_btc_refund_tx_lock() {
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();
		swap::set_testing_cur_time(1567632152);

		let kc_sell = keychain(&secp, 1);
		let ctx_sell = context_sell(&secp, &kc_sell);
		let secondary_redeem_address = btc_address(&mut secp, &kc_sell);
		let node_height = 100_000;
		let mwc_anchor_height = node_height - 25;

		let seller_node = TestNodeClient::new(node_height);
		seller_node.add_seller_inputs(&secp, &kc_sell, &ctx_sell);
		let mut api_sell = BtcSwapApi::new_test(
			Arc::new(seller_node),
			Arc::new(Mutex::new(TestBtcNodeClient::new(1))),
		);
		let mut swap = api_sell
			.create_swap_offer(
				&mut secp,
				&kc_sell,
				&ctx_sell,
				mwc_anchor_height,
				100 * MWC_UNIT,
				3_000_000,
				Currency::Btc,
				secondary_redeem_address,
				true, // mwc should be publisher first
				30,
				3,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(false),
				false,
				None,
			)
			.unwrap();
		assert_eq!(swap.lock_slate.slate.height, mwc_anchor_height);
		assert_eq!(swap.refund_slate.slate.height, mwc_anchor_height);
		assert_eq!(swap.redeem_slate.slate.height, mwc_anchor_height);
		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap);
		let tx_state = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &mut swap)
			.unwrap();

		test_swap_ser(&swap);

		let message = match fsm_sell
			.process(Input::Check, &mut swap, &ctx_sell, &tx_state, &mut secp)
			.unwrap()
			.action
			.unwrap()
		{
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		// Simulate short refund lock time by passing height+4h
		let kc_buy = keychain(&secp, 2);
		let ctx_buy = context_buy(&secp, &kc_buy);
		let nc = TestNodeClient::new(node_height + 12 * 60);

		let (id, offer, secondary_update) = message.unwrap_offer().unwrap();
		let res = BuyApi::accept_swap_offer(
			0,
			&mut secp,
			None,
			&kc_buy,
			&ctx_buy,
			id,
			offer,
			secondary_update,
			&nc,
		);

		assert!(res.err().unwrap().to_string().contains("input_missing")); // Swap cannot be accepted
	}

	#[test]
	#[serial]
	fn seller_lock_slate_preserves_coinbase_input_features() {
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();
		swap::set_testing_cur_time(1567632152);

		let keychain = keychain(&secp, 1);
		let mut context = context_sell(&secp, &keychain);
		match &mut context.role_context {
			RoleContext::Seller(seller) => {
				seller.inputs[0].features = OutputFeatures::Coinbase;
			}
			RoleContext::Buyer(_) => panic!("seller test context changed role"),
		}
		let secondary_redeem_address = btc_address(&mut secp, &keychain);
		let seller_node = TestNodeClient::new(100_000);
		seller_node.add_seller_inputs(&secp, &keychain, &context);
		let mut api = BtcSwapApi::new_test(
			Arc::new(seller_node),
			Arc::new(Mutex::new(TestBtcNodeClient::new(1))),
		);
		let swap = api
			.create_swap_offer(
				&mut secp,
				&keychain,
				&context,
				100_000,
				100 * MWC_UNIT,
				3_000_000,
				Currency::Btc,
				secondary_redeem_address,
				true,
				30,
				3,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(false),
				false,
				None,
			)
			.unwrap();

		match &swap.lock_slate.slate.tx_or_err().unwrap().body.inputs {
			Inputs::FeaturesAndCommit(inputs) => {
				assert_eq!(inputs.len(), 2);
				assert_eq!(
					inputs
						.iter()
						.filter(|input| input.features == OutputFeatures::Coinbase)
						.count(),
					1
				);
				assert_eq!(
					inputs
						.iter()
						.filter(|input| input.features == OutputFeatures::Plain)
						.count(),
					1
				);
			}
			Inputs::CommitOnly(_) => panic!("lock slate discarded input features"),
		}
	}

	// Because of golden output new line symbol we skipping Windows.
	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn test_btc_swap() {
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		global::set_local_nrd_enabled(true);

		let write_json = false;

		let kc_sell = keychain(&secp, 1);
		let ctx_sell = context_sell(&secp, &kc_sell);
		let secondary_redeem_address = btc_address(&mut secp, &kc_sell);

		let nc = TestNodeClient::new(300_000);
		nc.add_seller_inputs(&secp, &kc_sell, &ctx_sell);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * MWC_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		// When test was stored:  Utc.ymd(2019, 9, 4).and_hms_micro(21, 22, 32, 581245)

		// Seller: create swap offer
		let mut api_sell =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let mut swap_sell = api_sell
			.create_swap_offer(
				&mut secp,
				&kc_sell,
				&ctx_sell,
				300_000,
				amount,
				btc_amount,
				Currency::Btc,
				secondary_redeem_address,
				true, // lock MWC first
				30,
				6,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(false),
				false,
				None,
			)
			.unwrap();

		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);
		let tx_conf = &api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();

		assert_eq!(swap_sell.state, StateId::SellerSendingOffer);
		let message_1: Message = match sell_resp.action.unwrap() {
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::Execute,
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitForOfferMessage"
		);
		assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);

		if write_json {
			write(
				"swap_test/swap_sell_1.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();

			write(
				"swap_test/message_1.json",
				serde_json::to_string_pretty(&message_1).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/context_sell.json",
				serde_json::to_string_pretty(&ctx_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_1.json", &swap_sell);
			assert_json_fixture("swap_test/message_1.json", &message_1);
			assert_json_fixture("swap_test/context_sell.json", &ctx_sell);
		}

		// Add inputs to utxo set
		nc.mine_blocks(2);
		for input in swap_sell
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			nc.push_output(input.unwrap());
		}

		let kc_buy = keychain(&secp, 2);
		let ctx_buy = context_buy(&secp, &kc_buy);

		// Buyer: accept swap offer
		let api_buy =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

		let (id, offer, secondary_update) = message_1.unwrap_offer().unwrap();
		let mut swap_buy = BuyApi::accept_swap_offer(
			0,
			&mut secp,
			None,
			&kc_buy,
			&ctx_buy,
			id,
			offer,
			secondary_update,
			&nc,
		)
		.unwrap();

		let mut fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();

		assert_eq!(swap_buy.state, StateId::BuyerSendingAcceptOfferMessage);
		let message_2 = match buy_resp.action.unwrap() {
			Action::BuyerSendAcceptOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForSellerToLock);

		// Expected to wait for the Seller to deposit MWC and wait for 1 block
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(required, 1);
				assert_eq!(actual, 0);
			}
			_ => panic!("Invalid action"),
		}

		// !!!!!!!!!!!!!!!!!!!!!!
		// Here we are changing lock order because we want to keep tests original. Waiting case is covered, can go normally
		swap_buy.seller_lock_first = false;
		swap_sell.seller_lock_first = true;
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();

		assert_eq!(
			swap_buy.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);

		// Buyer: should deposit bitcoin
		let address = match buy_resp.action.unwrap() {
			Action::DepositSecondary {
				currency: _,
				amount,
				address,
			} => {
				assert_eq!(amount, btc_amount);
				address
			}
			_ => panic!("Invalid action"),
		};
		let address = Address::new_btc().from_str(&address[0]).unwrap();

		// Buyer: first deposit
		let tx_1 = BitcoinTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: address.script_pubkey().unwrap(),
			}],
		};
		let txid_1 = tx_1.txid().unwrap();
		btc_nc.push_transaction(&tx_1).unwrap();
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(
			swap_buy.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		match buy_resp.action.unwrap() {
			Action::DepositSecondary {
				currency: _,
				amount,
				address: _,
			} => assert_eq!(amount, btc_amount_2),
			_ => panic!("Invalid action"),
		};

		// Buyer: second deposit
		btc_nc.mine_blocks(2);
		let tx_2 = BitcoinTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: address.script_pubkey().unwrap(),
			}],
		};
		let txid_2 = tx_2.txid().unwrap();
		btc_nc.push_transaction(&tx_2).unwrap();
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);

		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: _,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: actual,
			} => assert_eq!(actual, Some(1)),
			_ => panic!("Invalid action"),
		};
		btc_nc.mine_blocks(5);

		// Buyer: wait for Mwc confirmations
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: actual,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: _,
			} => assert_eq!(actual, 0),
			_ => panic!("Invalid action"),
		};

		// Check if buyer has correct confirmed outputs
		{
			let script = api_buy.script(&swap_buy, &mut secp).unwrap();
			let (pending_amount, confirmed_amount, _, conf_outputs) =
				api_buy.btc_balance(&swap_buy, &script, 1).unwrap();

			assert_eq!(pending_amount, 0);
			assert_eq!(confirmed_amount, btc_amount_1 + btc_amount_2);
			assert_eq!(conf_outputs.len(), 2);
			let mut match_1 = 0;
			let mut match_2 = 0;
			for output in &conf_outputs {
				if output.out_point.txid == txid_1 {
					match_1 += 1;
				}
				if output.out_point.txid == txid_2 {
					match_2 += 1;
				}
			}
			assert_eq!(match_1, 1);
			assert_eq!(match_2, 1);
		}

		if write_json {
			write(
				"swap_test/swap_buy_1.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_2.json",
				serde_json::to_string_pretty(&message_2).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/context_buy.json",
				serde_json::to_string_pretty(&ctx_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_buy_1.json", &swap_buy);
			assert_json_fixture("swap_test/message_2.json", &message_2);
			assert_json_fixture("swap_test/context_buy.json", &ctx_buy);
		}

		// Seller: receive accepted offer
		assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_2),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerPublishMwcLockTx"
		);
		assert_eq!(swap_sell.state, StateId::SellerPostingLockMwcSlate);

		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::Execute,
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: _,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 0)
			}
			_ => panic!("Invalid action"),
		}

		if write_json {
			write(
				"swap_test/swap_sell_2.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_2.json", &swap_sell);
		}

		// Seller: wait for Mwc confirmations
		nc.mine_blocks(10);
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: _,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 10)
			}
			_ => panic!("Invalid action"),
		}
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: _,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 10)
			}
			_ => panic!("Invalid action"),
		}

		// Undo a BTC block to test seller
		{
			let mut state = btc_nc.state.lock();
			state.height -= 1;
		}

		// Seller: wait BTC confirmations
		nc.mine_blocks(20);
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: _,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: required,
				sec_actual: actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, Some(5))
			}
			_ => panic!("Invalid action"),
		}
		btc_nc.mine_block();

		if write_json {
			write(
				"swap_test/swap_sell_3.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_3.json", &swap_sell);
		}

		// Checking if both seller & Buyer are moved to the redeem message exchange step
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();

		assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
		assert_eq!(swap_buy.state, StateId::BuyerSendingInitRedeemMessage);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);
		let message_3 = match buy_resp.action.unwrap() {
			Action::BuyerSendInitRedeemMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);

		if write_json {
			write(
				"swap_test/swap_buy_2.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_3.json",
				serde_json::to_string_pretty(&message_3).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_buy_2.json", &swap_buy);
			assert_json_fixture("swap_test/message_3.json", &message_3);
		}

		// Seller: sign redeem
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);

		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_3),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerSendingInitRedeemMessage);
		let message_4 = match sell_resp.action.unwrap() {
			Action::SellerSendRedeemMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::Execute,
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		// Seller: wait for buyer's on-chain redeem tx
		assert_eq!(swap_sell.state, StateId::SellerWaitingForBuyerToRedeemMwc);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitForBuyerRedeemPublish"
		);

		if write_json {
			write(
				"swap_test/swap_sell_4.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
			write(
				"swap_test/message_4.json",
				serde_json::to_string_pretty(&message_4).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_4.json", &swap_sell);
			assert_json_fixture("swap_test/message_4.json", &message_4);
		}

		// Buyer: redeem
		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerWaitingForRedeemMessage"
		);

		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(
				Input::IncomeMessage(message_4),
				&mut swap_buy,
				&ctx_buy,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerRedeemMwc);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerPublishMwcRedeemTx"
		);

		let tx_conf = &api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"WaitForMwcConfirmations"
		);

		// Buyer: almost done, just need to wait for confirmations
		nc.mine_block();

		let tx_conf = api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForMwcConfirmations {
				name: _,
				required,
				actual,
			} => {
				assert_eq!(actual, 1);
				assert_eq!(required, 30);
			}
			_ => panic!("Invalid action"),
		}

		// At this point, buyer would add Mwc to their outputs
		// Now seller can redeem BTC
		if write_json {
			write(
				"swap_test/swap_buy_3.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_buy_3.json", &swap_buy);
		}

		// Seller: publish BTC tx
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerRedeemSecondaryCurrency);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerPublishTxSecondaryRedeem"
		);

		if write_json {
			write(
				"swap_test/swap_sell_5.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_5.json", &swap_sell);
		}

		// Seller: publishing and wait for BTC confirmations
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::Execute,
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
				&mut secp,
			)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				expected_to_be_posted: _,
				currency: _,
				address: _,
				required,
				actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, 0)
			}
			_ => panic!("Invalid action"),
		}

		btc_nc.mine_block();
		// still waiting
		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				expected_to_be_posted: _,
				currency: _,
				address: _,
				required,
				actual,
			} => {
				assert_eq!(required, 6);
				assert_eq!(actual, 1)
			}
			_ => panic!("Invalid action"),
		}

		// Let's mine more blocks, so both Buyer and Seller will come to complete state
		nc.mine_blocks(30);
		btc_nc.mine_blocks(6);

		let tx_conf = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf, &mut secp)
			.unwrap();
		let tx_conf = &api_buy
			.request_tx_confirmations(&secp, &kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf, &mut secp)
			.unwrap();

		// Seller & Buyer: complete!
		assert_eq!(swap_sell.state, StateId::SellerSwapComplete);
		assert_eq!(swap_buy.state, StateId::BuyerSwapComplete);
		assert!(sell_resp.action.is_none());
		assert!(buy_resp.action.is_none());

		if write_json {
			write(
				"swap_test/swap_sell_6.json",
				serde_json::to_string_pretty(&swap_sell).unwrap(),
			)
			.unwrap();
		} else {
			assert_json_fixture("swap_test/swap_sell_6.json", &swap_sell);
		}

		assert!(!write_json, "json files written");
	}

	#[test]
	#[serial]
	fn buyer_finalized_redeem_resumes_after_lock_confirmations_recover() {
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let completed: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_buy_3.json").unwrap()).unwrap();
		let context: Context =
			serde_json::from_str(&read_to_string("swap_test/context_buy.json").unwrap()).unwrap();
		let kc = keychain(&secp, 2);
		let api = BtcSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);
		let message_deadline = completed.get_time_message_redeem().unwrap();
		assert!(message_deadline + 1 < completed.get_time_mwc_redeem().unwrap());
		assert!(completed
			.redeem_slate
			.slate
			.tx_or_err()
			.unwrap()
			.validate(0, Weighting::AsTransaction, &mut secp)
			.is_ok());
		assert!(completed
			.refund_slate
			.slate
			.tx_or_err()
			.unwrap()
			.validate(0, Weighting::AsTransaction, &mut secp)
			.is_err());

		for lose_mwc_confirmation in [true, false] {
			for recovery_time in [message_deadline - 1, message_deadline + 1] {
				let mut trade = completed.clone();
				trade.state = StateId::BuyerRedeemMwc;
				trade.posted_redeem = None;
				let mut confirmations = SwapTransactionsConfirmations {
					mwc_observed: true,
					secondary_observed: true,
					mwc_tip: 300_000,
					mwc_lock_conf: Some(trade.mwc_confirmations),
					mwc_redeem_conf: None,
					mwc_refund_conf: None,
					secondary_tip: 500_000,
					secondary_lock_conf: Some(trade.secondary_confirmations),
					secondary_lock_amount: trade.secondary_amount,
					secondary_redeem_conf: None,
					secondary_refund_conf: None,
					secondary_refund_progress: None,
				};
				let mut fsm = api.get_fsm(&kc, &trade);

				// Either chain can temporarily lose a required lock confirmation.
				swap::set_testing_cur_time(message_deadline - 60);
				if lose_mwc_confirmation {
					confirmations.mwc_lock_conf = Some(trade.mwc_confirmations - 1);
				} else {
					confirmations.secondary_lock_conf = Some(trade.secondary_confirmations - 1);
				}
				let waiting = fsm
					.process(
						Input::Check,
						&mut trade,
						&context,
						&confirmations,
						&mut secp,
					)
					.unwrap();
				assert_eq!(
					waiting.next_state_id,
					StateId::BuyerWaitingForLockConfirmations
				);

				// The response is already acknowledged and the redeem is finalized.
				// Recovery must resume publication even after the message deadline.
				confirmations.mwc_lock_conf = Some(trade.mwc_confirmations);
				confirmations.secondary_lock_conf = Some(trade.secondary_confirmations);
				swap::set_testing_cur_time(recovery_time);
				let recovered = fsm
					.process(
						Input::Check,
						&mut trade,
						&context,
						&confirmations,
						&mut secp,
					)
					.unwrap();
				assert_eq!(recovered.next_state_id, StateId::BuyerRedeemMwc);
				assert!(matches!(
					recovered.action,
					Some(Action::BuyerPublishMwcRedeemTx)
				));
			}
		}
		swap::reset_testing_cur_time();
	}

	// Use a completed MWC redeem fixture so the same accepted inputs can also be
	// exercised through the real Bitcoin signer and fee-replacement path.
	// Create only simulated nodes and funds: `count` outputs of 100,000 satoshis
	// exactly cover the agreed BTC amount and have enough confirmations. Tests
	// that exercise the earlier message gate reset the seller's state themselves.
	fn funding_limit_fixture(
		secp: &Secp256k1,
		count: usize,
	) -> (
		Swap,
		Context,
		ExtKeychain,
		TestNodeClient,
		TestBtcNodeClient,
	) {
		let mut swap: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_5.json").unwrap()).unwrap();
		let context: Context =
			serde_json::from_str(&read_to_string("swap_test/context_sell.json").unwrap()).unwrap();
		swap.secondary_amount = u64::try_from(count).unwrap() * 100_000;
		swap.secondary_data.unwrap_btc_mut().unwrap().redeem_inputs = None;
		let kc = keychain(secp, 1);
		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);
		let api = BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let address = (&api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&swap, secp)
			.unwrap();
		let script_pubkey = Currency::Btc
			.address_2_script_pubkey(0, &address[0])
			.unwrap();
		btc_nc
			.push_transaction(&BitcoinTransaction {
				version: 2,
				lock_time: 0,
				input: vec![],
				output: vec![
					TxOut {
						value: 100_000,
						script_pubkey
					};
					count
				],
			})
			.unwrap();
		btc_nc.mine_blocks(swap.secondary_confirmations);
		(swap, context, kc, nc, btc_nc)
	}

	// Exercise the last check before the seller exposes its MWC redeem signature.
	// Expect 32 fully funded inputs to permit the message; 33 and the reported
	// 400-input attack must enter the refund-wait state without exposing it.
	#[test]
	#[serial]
	fn seller_funding_limit_gates_redeem_message() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for count in [32, 33, 400] {
			let (mut swap, context, kc, nc, btc_nc) = funding_limit_fixture(&secp, count);
			// Rewind the completed fixture to the first attempt to send the message.
			// Existing delivery/redemption flags must not bypass the funding check.
			swap.state = StateId::SellerSendingInitRedeemMessage;
			swap.redeem_kernel_updated = false;
			swap.message2 = None;
			swap.posted_msg2 = None;
			let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc)));
			let mut confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
			// BTC is already confirmed by the fixture. Supply the MWC lock status
			// directly so the output count determines whether the message is allowed.
			confirmations.mwc_lock_conf = Some(swap.mwc_confirmations);
			let mut fsm = api.get_fsm(&kc, &swap);
			let response = fsm
				.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
				.unwrap();
			if count == 32 {
				// Accept the entire funding set and offer the outbound redeem action.
				assert!(matches!(
					response.action,
					Some(Action::SellerSendRedeemMessage(_))
				));
				assert_eq!(
					swap.secondary_data
						.unwrap_btc()
						.unwrap()
						.redeem_inputs
						.as_ref()
						.unwrap()
						.len(),
					32
				);
			} else {
				// Reject the swap instead of silently accepting only its first 32 outputs.
				// The message constructor must also refuse a swap with no accepted set.
				assert_eq!(swap.state, StateId::SellerWaitingForRefundHeight);
				assert!(!matches!(
					response.action,
					Some(Action::SellerSendRedeemMessage(_))
				));
				assert!(
					swap.secondary_data
						.unwrap_btc()
						.unwrap()
						.redeem_inputs
						.is_none()
				);
				assert!(SellApi::redeem_message(&swap).is_err());
			}
		}
	}

	// Accept 32 inputs, reload the saved swap, then add 400 unsolicited outputs.
	// Expect both pending and confirmed extra deposits to leave the accepted
	// balance and inputs unchanged. Redemption and its higher-fee replacement
	// must spend exactly those original 32 inputs and stay within the weight limit.
	#[test]
	#[serial]
	fn seller_funding_limit_preserves_inputs_across_deposits_restart_and_fee_bump() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = funding_limit_fixture(&secp, 32);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap, &secp)
			.unwrap();
		let inputs = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_inputs
			.clone()
			.unwrap();
		// Model a restart by serializing and reloading the recorded input set.
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		let address = (&api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&swap, &secp)
			.unwrap();
		let script_pubkey = Currency::Btc
			.address_2_script_pubkey(0, &address[0])
			.unwrap();
		btc_nc
			.post_transaction(&BitcoinTransaction {
				version: 2,
				lock_time: 0,
				input: vec![],
				output: vec![
					TxOut {
						value: 1_000,
						script_pubkey
					};
					400
				],
			})
			.unwrap();
		// Even unconfirmed unsolicited deposits must not prevent message retries.
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap, &secp)
			.unwrap();
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		assert_eq!(confirmations.secondary_lock_amount, swap.secondary_amount);
		assert!(confirmations.secondary_lock_conf.unwrap() >= swap.secondary_confirmations);
		// Confirm the extra deposits: they must still be excluded from acceptance.
		btc_nc.mine_blocks(swap.secondary_confirmations);
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap, &secp)
			.unwrap();
		// Publish once, then rebuild with a higher fee. Inspect both signed
		// transactions to ensure the added deposits never become redemption inputs.
		for fee in [10_000, 20_000] {
			swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(fee);
			api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
				.unwrap();
			let hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
			let state = btc_nc.get_state();
			let tx = state
				.pending
				.get(&bitcoin_lib::Txid::from_byte_array(hash.to_byte_array()))
				.unwrap();
			assert_eq!(tx.input.len(), 32);
			assert!(tx.get_weight().unwrap() <= 400_000);
			assert_eq!(
				tx.input
					.iter()
					.map(|input| input.previous_output)
					.collect::<Vec<_>>(),
				inputs
					.iter()
					.map(|input| input.out_point)
					.collect::<Vec<_>>()
			);
		}
	}

	/// Electrum-compatible UTXO visibility and controllable broadcast failures.
	#[derive(Clone)]
	struct RefundTestClient {
		inner: TestBtcNodeClient,
		unspent_error: bool,
		// 0 succeeds, 1 rejects, 2 accepts but loses the response.
		post_error: Arc<std::sync::atomic::AtomicU8>,
	}

	impl BtcNodeClient for RefundTestClient {
		fn name(&self) -> String {
			"refund-test".to_string()
		}
		fn height(&mut self) -> Result<u64, Error> {
			self.inner.height()
		}
		fn unspent(
			&mut self,
			context_id: u32,
			currency: Currency,
			address: &String,
		) -> Result<Vec<Output>, Error> {
			if self.unspent_error {
				return Err(Error::ElectrumNodeClient("injected unspent failure".into()));
			}
			let mut outputs = self.inner.unspent(context_id, currency, address)?;
			let state = self.inner.get_state();
			let spent: std::collections::HashSet<_> = state
				.txs
				.values()
				.chain(state.pending.values())
				.flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
				.collect();
			outputs.retain(|output| !spent.contains(&output.out_point));
			Ok(outputs)
		}
		fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
			let mode = self.post_error.load(std::sync::atomic::Ordering::SeqCst);
			if mode != 1 {
				self.inner.post_tx(tx)?;
			}
			if mode != 0 {
				return Err(Error::ElectrumNodeClient(
					"injected broadcast failure".into(),
				));
			}
			Ok(())
		}
		fn transaction(&mut self, hash: &bitcoin_lib::Txid) -> Result<Option<u64>, Error> {
			self.inner.transaction(hash)
		}
		fn transaction_is_coinbase(&mut self, hash: &bitcoin_lib::Txid) -> Result<bool, Error> {
			self.inner.transaction_is_coinbase(hash)
		}
		fn confirmed_spend(
			&mut self,
			outpoint: &bitcoin_lib::OutPoint,
			script_pubkey: &bitcoin_lib::Script,
		) -> Result<Option<(BitcoinTransaction, u64)>, Error> {
			self.inner.confirmed_spend(outpoint, script_pubkey)
		}
	}

	// Start with the buyer's MWC redemption complete and one confirmed BTC funding
	// output. Freeze that input through the real preparation path so each test
	// exercises real signing against simulated nodes, without network access.
	fn seller_redeem_fixture(
		secp: &Secp256k1,
	) -> (Swap, Context, ExtKeychain, TestNodeClient, RefundTestClient) {
		let (mut swap, context, kc, nc, inner) = funding_limit_fixture(secp, 1);
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(10_000);
		let btc_nc = RefundTestClient {
			inner,
			unspent_error: false,
			post_error: Arc::new(std::sync::atomic::AtomicU8::new(0)),
		};
		let api = BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap, secp)
			.unwrap();
		(swap, context, kc, nc, btc_nc)
	}

	// Lose both broadcast responses, save/reload the failed operation, and let
	// the transaction remain pending or confirm. Polling must find it, the FSM
	// must finish a confirmed swap, and a direct retry must avoid broadcasting.
	#[test]
	#[serial]
	fn seller_redeem_lost_response_survives_restart_and_retry() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for confirmed in [false, true] {
			let (mut swap, context, kc, nc, btc_nc) = seller_redeem_fixture(&secp);
			// A shared client also exercises releasing the primary lock on error.
			let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
			// Mode 2 accepts the transaction into the mempool but reports an error
			// for both attempts. Expect an uncertain candidate, with no acknowledged
			// transaction or fee recorded yet.
			btc_nc.post_error.store(2, Ordering::SeqCst);
			assert!(
				api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
					.is_err()
			);
			let btc_data = swap.secondary_data.unwrap_btc().unwrap();
			assert!(btc_data.redeem_tx.is_none());
			assert!(btc_data.tx_fee_units.is_none());
			assert_eq!(btc_data.redeem_tx_candidates.len(), 1);
			let attempted = btc_data.redeem_tx_candidates[0];
			// Model the owner's save after the error and a wallet restart. Polling
			// must recover the saved candidate in either the mempool or the chain.
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			if confirmed {
				btc_nc.inner.mine_blocks(swap.secondary_confirmations);
			}
			let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
			assert_eq!(
				confirmations.secondary_redeem_conf,
				Some(if confirmed {
					swap.secondary_confirmations
				} else {
					0
				})
			);
			if confirmed {
				// The normal state-machine check must complete the trade from the
				// candidate's confirmations, even though broadcasting returned errors.
				let mut completed = swap.clone();
				let mut fsm = api.get_fsm(&kc, &completed);
				fsm.process(
					Input::Check,
					&mut completed,
					&context,
					&confirmations,
					&mut secp,
				)
				.unwrap();
				assert_eq!(completed.state, StateId::SellerSwapComplete);
			}
			// Mode 1 rejects every broadcast. A direct retry can succeed only by
			// finding the existing transaction through its status query. It should
			// promote that candidate to the acknowledged hash and record its fee.
			btc_nc.post_error.store(1, Ordering::SeqCst);
			api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
				.unwrap();
			let btc_data = swap.secondary_data.unwrap_btc().unwrap();
			assert_eq!(btc_data.redeem_tx, Some(attempted));
			assert_eq!(btc_data.tx_fee_units, Some(swap.secondary_fee_units));
			assert!(btc_data.redeem_tx_candidates.is_empty());
		}
	}

	// A rejected transaction must remain retryable without growing duplicate
	// candidates. A successful fallback must still record the hash and fee.
	#[test]
	#[serial]
	fn seller_redeem_rejected_attempt_retries_with_fallback() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = seller_redeem_fixture(&secp);
		// Both clients see the same chain, but their failure controls are separate
		// so the fallback can recover while the primary keeps rejecting requests.
		let mut fallback = btc_nc.clone();
		fallback.post_error = Arc::new(std::sync::atomic::AtomicU8::new(1));
		let api = BtcSwapApi::new(
			0,
			Currency::Btc,
			Arc::new(nc),
			Arc::new(Mutex::new(btc_nc.clone())),
			Arc::new(Mutex::new(fallback.clone())),
		);
		btc_nc.post_error.store(1, Ordering::SeqCst);
		// Reject two identical submissions. Expect one saved candidate, no
		// acknowledged hash or fee, and None from polling because neither node
		// accepted the transaction. This must remain eligible for another attempt.
		for _ in 0..2 {
			assert!(
				api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
					.is_err()
			);
			let btc_data = swap.secondary_data.unwrap_btc().unwrap();
			assert!(btc_data.redeem_tx.is_none());
			assert!(btc_data.tx_fee_units.is_none());
			assert_eq!(btc_data.redeem_tx_candidates.len(), 1);
			assert_eq!(
				api.request_tx_confirmations(&secp, &kc, &swap)
					.unwrap()
					.secondary_redeem_conf,
				None
			);
		}
		let attempted = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_tx_candidates[0];
		// Restore only the fallback. The next attempt must broadcast successfully,
		// record the same hash and its fee, and remove the redundant candidate.
		fallback.post_error.store(0, Ordering::SeqCst);
		api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
			.unwrap();
		let btc_data = swap.secondary_data.unwrap_btc().unwrap();
		assert_eq!(btc_data.redeem_tx, Some(attempted));
		assert_eq!(btc_data.tx_fee_units, Some(swap.secondary_fee_units));
		assert!(btc_data.redeem_tx_candidates.is_empty());
	}

	// Track every fee-replacement candidate, including across successive lost
	// replies and a later successful replacement. Any predecessor can confirm.
	#[test]
	#[serial]
	fn seller_redeem_replacements_preserve_all_candidates() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		// Run once with replacements rejected (mode 1), and once with replacements
		// accepted but their replies lost (mode 2). Both outcomes look like errors
		// to the wallet, so both must preserve recovery data.
		for failure_mode in [1, 2] {
			let (mut swap, context, kc, nc, btc_nc) = seller_redeem_fixture(&secp);
			let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
			// First establish an acknowledged redemption, then attempt two distinct
			// fee increases. The original hash and fee must survive both failures;
			// retaining the old fee also keeps the replacement eligible for retry.
			api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
				.unwrap();
			let original = swap.secondary_data.unwrap_btc().unwrap().redeem_tx;
			let original_fee = swap.secondary_data.unwrap_btc().unwrap().tx_fee_units;
			btc_nc.post_error.store(failure_mode, Ordering::SeqCst);
			for fee in [20_000, 30_000] {
				swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(fee);
				assert!(
					api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
						.is_err()
				);
				let btc_data = swap.secondary_data.unwrap_btc().unwrap();
				assert_eq!(btc_data.redeem_tx, original);
				assert_eq!(btc_data.tx_fee_units, original_fee);
				assert!((&api as &dyn SwapApi<ExtKeychain>)
					.is_secondary_tx_fee_changed(&swap)
					.unwrap());
			}
			assert_eq!(
				swap.secondary_data
					.unwrap_btc()
					.unwrap()
					.redeem_tx_candidates
					.len(),
				2
			);
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			// Reconcile or successfully post the final candidate; neither outcome
			// may discard the original or the first ambiguous replacement.
			btc_nc.post_error.store(0, Ordering::SeqCst);
			api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
				.unwrap();
			assert_eq!(
				swap.secondary_data
					.unwrap_btc()
					.unwrap()
					.redeem_tx_candidates
					.len(),
				2
			);
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			// Model each possible chain outcome separately: mine exactly one of the
			// accepted transactions and discard its conflicting alternatives. Polling
			// after restart must report one confirmation for whichever hash wins,
			// including the original or an intermediate replacement.
			let pending = btc_nc.inner.get_state();
			for hash in pending.pending.keys() {
				let mut mined = pending.clone();
				mined.pending.retain(|txid, _| txid == hash);
				btc_nc.inner.set_state(&mined);
				btc_nc.inner.mine_block();
				assert_eq!(
					api.request_tx_confirmations(&secp, &kc, &swap)
						.unwrap()
						.secondary_redeem_conf,
					Some(1)
				);
			}
		}
	}

	fn refund_fixture(
		secp: &Secp256k1,
	) -> (Swap, Context, ExtKeychain, TestNodeClient, RefundTestClient) {
		let mut swap: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_buy_3.json").unwrap()).unwrap();
		let context =
			serde_json::from_str(&read_to_string("swap_test/context_buy.json").unwrap()).unwrap();
		swap.update_secondary_address("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string());
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(10_000);
		let kc = keychain(secp, 2);
		let nc = TestNodeClient::new(300_000);
		let btc_nc = RefundTestClient {
			inner: TestBtcNodeClient::new(500_000),
			unspent_error: false,
			post_error: Arc::new(std::sync::atomic::AtomicU8::new(0)),
		};
		let api = BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let addresses = (&api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&swap, secp)
			.unwrap();
		let script_pubkey = Currency::Btc
			.address_2_script_pubkey(0, &addresses[0])
			.unwrap();
		// A refund must also support partial funding, independent of the seller's accepted amount.
		btc_nc
			.inner
			.push_transaction(&BitcoinTransaction {
				version: 2,
				lock_time: 0,
				input: vec![],
				output: vec![
					TxOut {
						value: 100_000,
						script_pubkey
					};
					2
				],
			})
			.unwrap();
		(swap, context, kc, nc, btc_nc)
	}

	// Prepare and persist a partially funded refund, broadcast it, then hide its
	// spent inputs from listunspent as Electrum does. Reload the swap and retry:
	// expect identical transaction bytes. Raise the fee through the refund state
	// machine and expect the same inputs, destination and locktime, a larger fee,
	// and a return to waiting for confirmations.
	#[test]
	#[serial]
	fn buyer_refund_replacement_preserves_inputs_across_restart() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, mut btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let prepared = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_tx
				.is_none()
		);
		assert!(btc_nc.inner.get_state().pending.is_empty());
		assert_eq!(prepared.inputs.len(), 2);
		assert_eq!(
			prepared.inputs.iter().map(|input| input.value).sum::<u64>(),
			200_000
		);
		// Persisted preparation is sufficient even if the broadcast response is lost.
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		let first_hash = swap.secondary_data.unwrap_btc().unwrap().refund_tx.unwrap();
		assert_eq!(first_hash, prepared.transaction.txid);
		let addresses = (&api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&swap, &secp)
			.unwrap();
		assert!(
			btc_nc
				.unspent(0, Currency::Btc, &addresses[0])
				.unwrap()
				.is_empty()
		);
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			prepared.transaction.tx
		);
		assert_eq!(btc_nc.inner.get_state().pending.len(), 1);

		// Exercise the actual waiting -> posting -> waiting transition for a fee bump.
		swap.state = StateId::BuyerWaitingForRefundConfirmations;
		swap.posted_refund = Some(swap::get_cur_time());
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
		swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 3600);
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		assert_eq!(confirmations.secondary_refund_conf, Some(0));
		let mut fsm = api.get_fsm(&kc, &swap);
		let response = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::BuyerPostingRefundForSecondary
		);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		fsm.process(
			Input::Execute,
			&mut swap,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
		let replacement_hash = swap.secondary_data.unwrap_btc().unwrap().refund_tx.unwrap();
		assert_ne!(replacement_hash, first_hash);
		let state = btc_nc.inner.get_state();
		let first = &state.pending[&bitcoin_lib::Txid::from_byte_array(first_hash.to_byte_array())];
		let replacement =
			&state.pending[&bitcoin_lib::Txid::from_byte_array(replacement_hash.to_byte_array())];
		assert_eq!(
			replacement
				.input
				.iter()
				.map(|input| input.previous_output)
				.collect::<Vec<_>>(),
			prepared
				.inputs
				.iter()
				.map(|input| input.out_point)
				.collect::<Vec<_>>()
		);
		assert_eq!(replacement.lock_time, first.lock_time);
		assert_eq!(
			replacement.output[0].script_pubkey,
			first.output[0].script_pubkey
		);
		assert!(replacement.output[0].value < first.output[0].value);
		assert_eq!(swap.state, StateId::BuyerWaitingForRefundConfirmations);
	}

	// Broadcast a refund, then try a fee replacement with both backends either
	// rejecting it or accepting it while losing their responses. Expect the old
	// broadcast hash and fee to remain tracked and the candidate to remain saved.
	// Confirmation checks must recognize whichever transaction confirms; after
	// reloading, a retry must broadcast the exact saved candidate successfully.
	#[test]
	#[serial]
	fn buyer_refund_failed_replacement_preserves_recovery_data() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for failure_mode in [1, 2] {
			let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
			// Separate clients share a simulated chain, as the two Electrum backends do.
			let api = BtcSwapApi::new(
				0,
				Currency::Btc,
				Arc::new(nc),
				Arc::new(Mutex::new(btc_nc.clone())),
				Arc::new(Mutex::new(btc_nc.clone())),
			);
			let address = swap.unwrap_buyer().unwrap();
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
				.unwrap();
			let first_hash = swap.secondary_data.unwrap_btc().unwrap().refund_tx;
			let first_fee = swap.secondary_data.unwrap_btc().unwrap().tx_fee_units;
			swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			btc_nc
				.post_error
				.store(failure_mode, std::sync::atomic::Ordering::SeqCst);
			assert!(api
				.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
				.is_err());
			assert_eq!(
				swap.secondary_data.unwrap_btc().unwrap().refund_tx,
				first_hash
			);
			assert_eq!(
				swap.secondary_data.unwrap_btc().unwrap().tx_fee_units,
				first_fee
			);
			let candidate = swap
				.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.clone()
				.unwrap();
			// Either the rejected replacement's predecessor or the accepted
			// replacement can confirm before the wallet retries its broadcast.
			let pending = btc_nc.inner.get_state();
			let mut mined = pending.clone();
			let confirmed_hash = if failure_mode == 1 {
				first_hash.unwrap()
			} else {
				candidate.transaction.txid
			};
			mined.pending.retain(|hash, _| {
				*hash == bitcoin_lib::Txid::from_byte_array(confirmed_hash.to_byte_array())
			});
			btc_nc.inner.set_state(&mined);
			btc_nc.inner.mine_block();
			assert_eq!(
				api.request_tx_confirmations(&secp, &kc, &swap)
					.unwrap()
					.secondary_refund_conf,
				Some(1)
			);
			btc_nc.inner.set_state(&pending);
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			btc_nc
				.post_error
				.store(0, std::sync::atomic::Ordering::SeqCst);
			api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
				.unwrap();
			assert_eq!(
				swap.secondary_data.unwrap_btc().unwrap().refund_tx,
				Some(candidate.transaction.txid)
			);
			assert_eq!(
				swap.secondary_data
					.unwrap_btc()
					.unwrap()
					.refund_transaction
					.as_ref()
					.unwrap()
					.transaction
					.tx,
				candidate.transaction.tx
			);
		}
	}

	// Save the first refund before broadcasting, lose both broadcast responses,
	// then restart from that saved record and mine the refund. Even though no
	// successful-broadcast hash was saved, expect confirmation polling to find
	// the prepared transaction and the state machine to finish the refund.
	#[test]
	#[serial]
	fn buyer_refund_prepared_transaction_is_tracked_after_lost_response() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new(
			0,
			Currency::Btc,
			Arc::new(nc),
			Arc::new(Mutex::new(btc_nc.clone())),
			Arc::new(Mutex::new(btc_nc.clone())),
		);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let saved = serde_json::to_string(&swap).unwrap();
		btc_nc
			.post_error
			.store(2, std::sync::atomic::Ordering::SeqCst);
		let address = swap.unwrap_buyer().unwrap();
		assert!(
			api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
				.is_err()
		);
		// Restart from the checkpoint taken before broadcasting, then confirm it.
		swap = serde_json::from_str(&saved).unwrap();
		assert!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_tx
				.is_none()
		);
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		assert_eq!(
			confirmations.secondary_refund_conf,
			Some(swap.secondary_confirmations)
		);
		swap.state = StateId::BuyerWaitingForRefundConfirmations;
		let mut fsm = api.get_fsm(&kc, &swap);
		let response = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
	}

	fn refund_funding(
		btc_nc: &RefundTestClient,
		script: &bitcoin_lib::Script,
		amounts: &[u64],
		tag: u32,
	) -> bitcoin_lib::Txid {
		let funding = BitcoinTransaction {
			version: 2,
			lock_time: tag,
			input: vec![],
			output: amounts
				.iter()
				.map(|value| TxOut {
					value: *value,
					script_pubkey: script.to_p2sh(),
				})
				.collect(),
		};
		btc_nc.inner.push_transaction(&funding).unwrap();
		funding.txid().unwrap()
	}

	fn verify_refund_signatures(secp: &Secp256k1, swap: &Swap, transaction: &BitcoinTransaction) {
		use bitcoin_lib::blockdata::{opcodes, script::Instruction};
		use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Message as SecpMessage};
		let refund_key = swap.secondary_data.unwrap_btc().unwrap().refund.unwrap();
		for (index, input) in transaction.input.iter().enumerate() {
			let instructions = input
				.script_sig
				.instructions_minimal()
				.collect::<Result<Vec<_>, _>>()
				.unwrap();
			let signature = match instructions[0] {
				Instruction::PushBytes(bytes) => bytes,
				_ => panic!("missing signature"),
			};
			let script = match instructions.last().unwrap() {
				Instruction::PushBytes(bytes) => bitcoin_lib::Script::from(bytes.to_vec()),
				_ => panic!("missing redeem script"),
			};
			if instructions.len() == 3 {
				assert_eq!(instructions[1], Instruction::Op(opcodes::OP_TRUE));
			} else {
				assert_eq!(instructions.len(), 2);
			}
			assert_eq!(signature.last(), Some(&1));
			let signature =
				EcdsaSignature::from_der(secp, &signature[..signature.len() - 1]).unwrap();
			let msg = SecpMessage::from_slice(
				transaction
					.signature_hash(index, &script, 1)
					.unwrap()
					.as_ref(),
			)
			.unwrap();
			secp.verify(&msg, &signature, &refund_key).unwrap();
		}
	}

	// Change the refund branch selector from 1 to 2. Both are true in the
	// legacy script, so the refund still works with the same signatures but
	// gets a different transaction ID. This simulates a third-party mutation.
	fn malleate_refund_selector(
		transaction: &BitcoinTransaction,
		input: usize,
	) -> BitcoinTransaction {
		let mut changed = transaction.clone();
		let mut script_sig = changed.input[input].script_sig.to_bytes();
		// DER signatures use a one-byte push length. OP_2 is another minimally
		// encoded true value for the legacy OP_IF refund branch.
		let selector = 1 + usize::from(script_sig[0]);
		assert_eq!(script_sig[selector], 0x51);
		script_sig[selector] = 0x52;
		changed.input[input].script_sig = bitcoin_lib::Script::from(script_sig);
		changed.input[input]
			.script_sig
			.instructions_minimal()
			.collect::<Result<Vec<_>, _>>()
			.unwrap();
		assert_ne!(transaction.txid().unwrap(), changed.txid().unwrap());
		changed
	}

	// Workflow: refund 33 deposits in two batches, with the first batch's
	// selector changed before confirmation. Expect recovery of its actual txid
	// and a child spending that txid's carry output. After restart and a reorg,
	// retry the exact recovered parent and saved child. Finally, confirm a
	// selector-changed final payment and expect the whole refund to complete.
	#[test]
	#[serial]
	fn buyer_refund_recovers_malleated_parent_and_final_payment() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 1);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		// The 32-input limit leaves one deposit for a child batch; the first
		// batch must preserve its balance in a buyer-controlled carry output.
		refund_funding(&btc_nc, &script, &[100_000; 33], 0);
		let before_parent = btc_nc.inner.get_state();
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let first = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		let original: BitcoinTransaction =
			bitcoin_lib::consensus::deserialize(&first.transaction.tx).unwrap();
		verify_refund_signatures(&secp, &swap, &original);
		let changed = malleate_refund_selector(&original, 0);
		for i in 0..original.input.len() {
			// The original signatures are valid for the altered transaction too.
			assert_eq!(
				original.signature_hash(i, &script, 1).unwrap(),
				changed.signature_hash(i, &script, 1).unwrap()
			);
		}
		let changed_bytes = bitcoin_lib::consensus::serialize(&changed).unwrap();
		btc_nc.inner.post_transaction(&changed).unwrap();
		assert!(matches!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Pending {
				batch: 0,
				confirmations: None,
				..
			})
		));
		// A variant must actually confirm before it can be adopted.
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_plan
				.as_ref()
				.unwrap()
				.batches[0]
				.attempts
				.len(),
			1
		);
		// One confirmation is enough to recognize and save the variant, but
		// the child must wait for the swap's full required confirmation depth.
		btc_nc.inner.mine_block();
		assert!(swap.secondary_confirmations > 1);
		assert!(matches!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Pending {
				batch: 0,
				confirmations: Some(1),
				..
			})
		));
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			changed_bytes
		);
		btc_nc.inner.mine_blocks(swap.secondary_confirmations - 1);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::NextBatch {
				completed_batches: 1
			})
		);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let child = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert_eq!(
			child.inputs[0].out_point,
			bitcoin_lib::OutPoint::new(changed.txid().unwrap(), 0)
		);
		assert_eq!(child.inputs[0].value, changed.output[0].value);
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert_eq!(plan.batches[0].attempts.len(), 2);
		assert_eq!(
			plan.batches[0].attempts[0].transaction.tx,
			first.transaction.tx
		);
		assert_eq!(plan.batches[0].attempts[1].transaction.tx, changed_bytes);
		assert!(plan.pending.is_empty());
		// Restart and reorg: the signed child pins the recovered parent bytes,
		// even though the original attempt is also retained.
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		btc_nc.inner.set_state(&before_parent);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			changed_bytes
		);
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			child.transaction.tx
		);
		let final_payment: BitcoinTransaction =
			bitcoin_lib::consensus::deserialize(&child.transaction.tx).unwrap();
		verify_refund_signatures(&secp, &swap, &final_payment);
		// The final batch has a carry at input zero and a swap deposit at input
		// one. Changing the latter's selector must still be recognized as the
		// final payment to the intended address, allowing Complete progress.
		let changed_final = malleate_refund_selector(&final_payment, 1);
		btc_nc.inner.post_transaction(&changed_final).unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
		assert_eq!(
			changed_final.output[0].script_pubkey,
			Currency::Btc
				.address_2_script_pubkey(0, address.as_ref().unwrap())
				.unwrap()
		);
		// Reconciliation also persists when preparation reports that nothing
		// further needs signing (e.g. a final payment recovered after restart).
		assert!(api
			.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.is_err());
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_plan
				.as_ref()
				.unwrap()
				.batches[1]
				.attempts
				.len(),
			2
		);
	}

	// Workflow: save a refund, then have the mock node report confirmed spends
	// that change its signed fields or witness. The mock deliberately bypasses
	// consensus validation to exercise our response checks. Expect polling and
	// preparation to reject every mismatch and leave the saved swap unchanged.
	#[test]
	#[serial]
	fn buyer_refund_rejects_nonmatching_confirmed_spends() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let bytes = &swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.as_ref()
			.unwrap()
			.transaction
			.tx;
		let original: BitcoinTransaction = bitcoin_lib::consensus::deserialize(bytes).unwrap();
		let before_spend = btc_nc.inner.get_state();
		let saved_swap = serde_json::to_string(&swap).unwrap();
		let mutations: [(&str, fn(&mut BitcoinTransaction)); 8] = [
			("version", |tx| tx.version += 1),
			("locktime", |tx| tx.lock_time += 1),
			("amount", |tx| tx.output[0].value -= 1),
			("destination", |tx| {
				tx.output[0].script_pubkey = bitcoin_lib::Script::new()
			}),
			("input count", |tx| {
				tx.input.pop();
			}),
			("input outpoint", |tx| tx.input[1].previous_output.vout += 1),
			("sequence", |tx| tx.input[0].sequence += 1),
			("witness", |tx| tx.input[0].witness.push(vec![1])),
		];
		for (name, mutate) in mutations {
			btc_nc.inner.set_state(&before_spend);
			// Give every case an unknown txid so it reaches recovery, including
			// the witness case (witness alone does not change the txid).
			let mut changed = malleate_refund_selector(&original, 0);
			mutate(&mut changed);
			// Simulate a backend reporting a different confirmed spend. None of
			// these responses may be adopted as our refund, regardless of its ID.
			btc_nc.inner.push_transaction(&changed).unwrap();
			btc_nc.inner.mine_blocks(swap.secondary_confirmations);
			let error = api
				.request_tx_confirmations(&secp, &kc, &swap)
				.err()
				.unwrap();
			assert!(
				error
					.to_string()
					.contains("does not match any saved refund attempt"),
				"{name}: {error}"
			);
			assert!(
				api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
					.is_err(),
				"{name}"
			);
			assert_eq!(serde_json::to_string(&swap).unwrap(), saved_swap, "{name}");
		}
	}

	// Workflow: the primary node finds a variant but then fails; the fallback
	// only knows the unspent deposits. Expect no primary observations to be
	// saved. Next, confirm the original parent and sign a child, then reorg to
	// the variant. Expect an explicit conflict and unchanged saved transactions:
	// the signed child still requires its original parent's exact txid.
	#[test]
	#[serial]
	fn buyer_refund_malleated_recovery_preserves_pinned_children_and_failover() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		refund_funding(&btc_nc, &script, &[100_000; 33], 0);
		let before_parent = btc_nc.inner.get_state();
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let first = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		let original: BitcoinTransaction =
			bitcoin_lib::consensus::deserialize(&first.transaction.tx).unwrap();
		let changed = malleate_refund_selector(&original, 0);
		let mut primary = btc_nc.clone();
		primary.inner = TestBtcNodeClient::new(before_parent.height);
		primary.inner.set_state(&before_parent);
		primary.inner.push_transaction(&changed).unwrap();
		primary.inner.mine_blocks(swap.secondary_confirmations);
		primary.unspent_error = true;
		let failover_api = BtcSwapApi::new(
			0,
			Currency::Btc,
			Arc::new(nc),
			Arc::new(Mutex::new(primary)),
			Arc::new(Mutex::new(btc_nc.clone())),
		);
		// The primary discovers the variant, then fails its UTXO read. Only
		// the fallback's complete observation may influence the durable plan.
		assert!(matches!(
			failover_api
				.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Pending {
				batch: 0,
				confirmations: None,
				..
			})
		));
		failover_api
			.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			first.transaction.tx
		);
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_plan
				.as_ref()
				.unwrap()
				.batches[0]
				.attempts
				.len(),
			1
		);
		// Once a child is signed, its parent must never be silently switched
		// to a different txid, even if that parent is otherwise equivalent.
		btc_nc.inner.push_transaction(&original).unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let saved_swap = serde_json::to_string(&swap).unwrap();
		btc_nc.inner.set_state(&before_parent);
		btc_nc.inner.push_transaction(&changed).unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		let error = api
			.request_tx_confirmations(&secp, &kc, &swap)
			.err()
			.unwrap();
		assert!(error.to_string().contains("conflicts with a saved child"));
		assert!(api
			.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.is_err());
		assert_eq!(serde_json::to_string(&swap).unwrap(), saved_swap);
	}

	// More than 600 economical deposits previously exceeded BTC's standard
	// transaction weight. Recover all of them across restarts, never finishing
	// at an intermediate batch, and retain unsolicited dust as unrefunded.
	#[test]
	#[serial]
	fn buyer_refund_batches_all_economical_deposits_and_reports_skipped() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 1);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		let mut amounts = vec![100_000; 650];
		amounts.extend(vec![540; 600]);
		let funding = refund_funding(&btc_nc, &script, &amounts, 0);
		let address = swap.unwrap_buyer().unwrap();
		swap.state = StateId::BuyerPostingRefundForSecondary;
		let mut spent = std::collections::HashSet::new();
		let mut total_fee = 0;
		let mut previous_carry = None;
		for index in 0..21 {
			let before = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			let prepared = swap
				.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.clone()
				.unwrap();
			let transaction: BitcoinTransaction =
				bitcoin_lib::consensus::deserialize(&prepared.transaction.tx).unwrap();
			assert!(transaction.input.len() <= 32);
			assert!(transaction.get_weight().unwrap() <= 400_000);
			verify_refund_signatures(&secp, &swap, &transaction);
			let mut deposits = prepared.inputs.iter();
			if let Some(carry) = previous_carry {
				assert_eq!(deposits.next().unwrap().out_point, carry);
			}
			for input in deposits {
				assert_eq!(input.out_point.txid, funding);
				assert!(input.out_point.vout < 650);
				assert!(spent.insert(input.out_point));
			}
			let fee =
				prepared.inputs.iter().map(|o| o.value).sum::<u64>() - transaction.output[0].value;
			assert!(
				fee >= Currency::Btc
					.secondary_fee_amount(
						swap.secondary_fee_units,
						prepared.transaction.tx.len() as u64
					)
					.unwrap()
			);
			total_fee += fee;
			previous_carry = prepared.carry_output.as_ref().map(|o| o.out_point);
			// Restart from the durable pre-broadcast record and reprepare it.
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			assert_eq!(
				swap.secondary_data
					.unwrap_btc()
					.unwrap()
					.refund_transaction
					.as_ref()
					.unwrap()
					.transaction
					.tx,
				prepared.transaction.tx
			);
			let mut fsm = api.get_fsm(&kc, &swap);
			let response = fsm
				.process(Input::Execute, &mut swap, &context, &before, &mut secp)
				.unwrap();
			assert_eq!(
				response.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			btc_nc.inner.mine_blocks(swap.secondary_confirmations);
			let confirmed = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
			let response = fsm
				.process(Input::Check, &mut swap, &context, &confirmed, &mut secp)
				.unwrap();
			if index < 20 {
				assert_eq!(
					response.next_state_id,
					StateId::BuyerPostingRefundForSecondary
				);
				assert!(previous_carry.is_some());
			} else {
				assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
				assert!(previous_carry.is_none());
				assert_eq!(
					transaction.output[0].script_pubkey,
					Currency::Btc
						.address_2_script_pubkey(0, address.as_ref().unwrap())
						.unwrap()
				);
				assert_eq!(transaction.output[0].value + total_fee, 650 * 100_000);
			}
		}
		assert_eq!(spent.len(), 650);
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert!(plan.pending.is_empty());
		assert_eq!(plan.unrefunded.len(), 600);
		assert_eq!(plan.unrefunded_amount().unwrap(), 600 * 540);
		assert!(swap
			.journal
			.last()
			.unwrap()
			.message
			.contains("600 deposits"));
		assert!(swap
			.journal
			.last()
			.unwrap()
			.message
			.contains("remain unrefunded"));
	}

	#[test]
	#[serial]
	fn buyer_refund_retains_unconfirmed_inventory_and_ignores_late_deposits() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		let unconfirmed = refund_funding(&btc_nc, &script, &[100_000], 1);
		let mut chain = btc_nc.inner.get_state();
		chain.tx_heights.insert(unconfirmed, 0);
		btc_nc.inner.set_state(&chain);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert!(swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.as_ref()
			.unwrap()
			.carry_output
			.is_none());
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::WaitingForFunding)
		);
		let late = refund_funding(&btc_nc, &script, &[100_000], 2);
		let mut chain = btc_nc.inner.get_state();
		chain.tx_heights.insert(unconfirmed, chain.height);
		btc_nc.inner.set_state(&chain);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let saved = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.as_ref()
			.unwrap();
		assert_eq!(saved.inputs.len(), 1);
		assert!(saved.inputs.iter().any(|o| o.out_point.txid == unconfirmed));
		assert!(saved.inputs.iter().all(|o| o.out_point.txid != late));
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
	}

	#[test]
	#[serial]
	fn buyer_refund_reorg_allows_replacement_before_independent_batch() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 1);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		let unconfirmed = refund_funding(&btc_nc, &script, &[100_000], 1);
		let mut chain = btc_nc.inner.get_state();
		chain.tx_heights.insert(unconfirmed, 0);
		btc_nc.inner.set_state(&chain);

		// Pay the confirmed deposits directly, leaving the unconfirmed deposit
		// for a later batch that will not depend on this payout.
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let first = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert!(first.carry_output.is_none());
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		let mut chain = btc_nc.inner.get_state();
		chain.tx_heights.insert(unconfirmed, chain.height);
		btc_nc.inner.set_state(&chain);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let second = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert_eq!(second.inputs.len(), 1);
		assert_eq!(second.inputs[0].out_point.txid, unconfirmed);
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();

		// The alternative chain keeps the funding deposits but returns the first
		// payout to the mempool. The second payout remains independently valid.
		let first_txid = bitcoin_lib::Txid::from_byte_array(first.transaction.txid.to_byte_array());
		let mut chain = btc_nc.inner.get_state();
		let first_tx = chain.txs.remove(&first_txid).unwrap();
		chain.tx_heights.remove(&first_txid);
		chain.pending.insert(first_txid, first_tx.clone());
		btc_nc.inner.set_state(&chain);
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
		swap::set_testing_cur_time(swap::get_cur_time() + state::POST_SECONDARY_RETRY_PERIOD + 1);
		swap.state = StateId::BuyerWaitingForRefundConfirmations;
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		assert!(matches!(
			confirmations.secondary_refund_progress,
			Some(BtcRefundProgress::Pending {
				batch: 0,
				confirmations: Some(0),
				replacement_allowed: true,
				candidate_known: true,
				..
			})
		));
		let mut fsm = api.get_fsm(&kc, &swap);
		let response = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::BuyerPostingRefundForSecondary
		);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert_eq!(plan.batches.len(), 2);
		assert_eq!(plan.batches[0].attempts.len(), 2);
		assert_eq!(
			plan.batches[0].attempts[0].transaction.tx,
			first.transaction.tx
		);
		assert!(!plan.batches[1].spends_carry);
		assert_eq!(plan.batches[1].attempts.len(), 1);
		assert_eq!(
			plan.batches[1].attempts[0].transaction.tx,
			second.transaction.tx
		);
		let replacement = &plan.batches[0].attempts[1];
		assert_ne!(replacement.transaction.txid, first.transaction.txid);
		assert_eq!(replacement.fee_units, swap.secondary_fee_units);
		let replacement_tx: BitcoinTransaction =
			bitcoin_lib::consensus::deserialize(&replacement.transaction.tx).unwrap();
		assert_eq!(
			replacement_tx
				.input
				.iter()
				.map(|i| i.previous_output)
				.collect::<Vec<_>>(),
			first_tx
				.input
				.iter()
				.map(|i| i.previous_output)
				.collect::<Vec<_>>()
		);
		assert_eq!(replacement_tx.lock_time, first_tx.lock_time);
		assert_eq!(
			replacement_tx.output[0].script_pubkey,
			first_tx.output[0].script_pubkey
		);
		assert!(replacement_tx.output[0].value < first_tx.output[0].value);
		verify_refund_signatures(&secp, &swap, &replacement_tx);
		fsm.process(
			Input::Execute,
			&mut swap,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
		assert_eq!(swap.state, StateId::BuyerWaitingForRefundConfirmations);

		// The mock mempool retains conflicting attempts; mine the replacement
		// and the unchanged independent payout, then complete the refund plan.
		let mut chain = btc_nc.inner.get_state();
		chain.pending.remove(&first_txid);
		btc_nc.inner.set_state(&chain);
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
	}

	#[test]
	#[serial]
	fn buyer_refund_fee_replacements_ignore_newly_confirmed_deposits() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for spends_carry in [false, true] {
			let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
			let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
			let script = api.script(&swap, &secp).unwrap();
			btc_nc.inner.clean();
			let amounts = if spends_carry {
				let mut amounts = vec![100_000; 32];
				amounts.push(5_000);
				amounts
			} else {
				vec![100_000_000]
			};
			refund_funding(&btc_nc, &script, &amounts, 0);
			let donation_amount = if spends_carry { 100_000 } else { 2_700 };
			let donation = refund_funding(&btc_nc, &script, &[donation_amount], 1);
			let mut chain = btc_nc.inner.get_state();
			chain.tx_heights.insert(donation, 0);
			btc_nc.inner.set_state(&chain);
			let address = swap.unwrap_buyer().unwrap();
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			if spends_carry {
				// Confirm the parent, then exclude the remaining small deposit so
				// the next batch pays the carry directly to the refund address.
				api.post_secondary_refund_tx(
					&secp,
					&kc,
					&context,
					&mut swap,
					address.clone(),
					true,
				)
				.unwrap();
				btc_nc.inner.mine_blocks(swap.secondary_confirmations);
				swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(100_000);
				api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
					.unwrap();
			}
			let saved = swap
				.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.clone()
				.unwrap();
			assert_eq!(saved.inputs.len(), 1);
			assert!(saved.carry_output.is_none());
			api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
				.unwrap();

			// The recorded donation confirms while the saved payout is still in
			// the mempool. It must not prevent a fee bump of that payout.
			let mut chain = btc_nc.inner.get_state();
			chain.tx_heights.insert(donation, chain.height);
			btc_nc.inner.set_state(&chain);
			swap.secondary_fee_units =
				SecondaryFeeUnits::RatePerKvb(if spends_carry { 110_000 } else { 11_000 });
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.unwrap();
			let data = swap.secondary_data.unwrap_btc().unwrap();
			let replacement = data.refund_transaction.as_ref().unwrap();
			assert_eq!(replacement.inputs, saved.inputs);
			assert_eq!(replacement.address, saved.address);
			assert_eq!(replacement.fee_units, swap.secondary_fee_units);
			assert!(replacement.carry_output.is_none());
			assert_ne!(replacement.transaction.txid, saved.transaction.txid);
			let original: BitcoinTransaction =
				bitcoin_lib::consensus::deserialize(&saved.transaction.tx).unwrap();
			let transaction: BitcoinTransaction =
				bitcoin_lib::consensus::deserialize(&replacement.transaction.tx).unwrap();
			assert_eq!(transaction.lock_time, original.lock_time);
			assert_eq!(
				transaction.output[0].script_pubkey,
				original.output[0].script_pubkey
			);
			assert!(transaction.output[0].value < original.output[0].value);
			verify_refund_signatures(&secp, &swap, &transaction);
			let plan = data.refund_plan.as_ref().unwrap();
			assert_eq!(plan.pending.len(), 1);
			assert_eq!(plan.pending[0].out_point.txid, donation);
			assert_eq!(plan.pending[0].value, donation_amount);
			assert_eq!(
				plan.unrefunded_amount().unwrap(),
				if spends_carry { 5_000 } else { 0 }
			);
			let batch = plan.batches.last().unwrap();
			assert_eq!(batch.spends_carry, spends_carry);
			assert_eq!(batch.attempts.len(), 2);
			assert_eq!(batch.attempts[0].transaction.tx, saved.transaction.tx);
			api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
				.unwrap();
		}
	}

	#[test]
	#[serial]
	fn buyer_refund_fee_replacements_preserve_dependent_batch_checks() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		refund_funding(&btc_nc, &script, &[2_650; 33], 0);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let saved = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert_eq!(saved.inputs.len(), 32);
		assert!(saved.carry_output.is_some());
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(11_000);
		let error = api
			.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap_err();
		// The replacement itself can pay its fee and create a 1,970-satoshi
		// carry. The child has only 4,620 satoshis, insufficient at the new rate.
		assert!(
			matches!(error, Error::Generic(message) if message.starts_with(
				"Refund funds cannot cover fees and a spendable output: inputs=4620,"
			))
		);
		let data = swap.secondary_data.unwrap_btc().unwrap();
		assert_eq!(
			data.refund_transaction.as_ref().unwrap().transaction.tx,
			saved.transaction.tx
		);
		let plan = data.refund_plan.as_ref().unwrap();
		assert_eq!(plan.batches.len(), 1);
		assert_eq!(plan.batches[0].attempts.len(), 1);
		assert_eq!(plan.pending.len(), 1);
		assert_eq!(plan.pending[0].value, 2_650);
		assert!(plan.unrefunded.is_empty());
	}

	#[test]
	#[serial]
	fn buyer_refund_fee_increase_keeps_skipped_deposits_and_pays_final_carry() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		let mut amounts = vec![100_000; 32];
		amounts.push(5_000);
		refund_funding(&btc_nc, &script, &amounts, 0);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let address = swap.unwrap_buyer().unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(100_000);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert_eq!(plan.unrefunded_amount().unwrap(), 5_000);
		let final_tx = plan.batches.last().unwrap().attempts.last().unwrap();
		assert_eq!(final_tx.inputs.len(), 1);
		assert!(final_tx.carry_output.is_none());
		let transaction = bitcoin_lib::consensus::deserialize(&final_tx.transaction.tx).unwrap();
		verify_refund_signatures(&secp, &swap, &transaction);
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
	}

	#[test]
	#[serial]
	fn buyer_refund_all_skipped_and_insufficient_funds_preserve_inventory() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for amount in [540, 2_500] {
			let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
			let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
			let script = api.script(&swap, &secp).unwrap();
			btc_nc.inner.clean();
			refund_funding(&btc_nc, &script, &[amount], 0);
			assert!(api
				.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
				.is_err());
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			let plan = swap
				.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_plan
				.as_ref()
				.unwrap();
			assert!(plan.batches.is_empty());
			assert_eq!(
				plan.pending.iter().map(|o| o.value).sum::<u64>()
					+ plan.unrefunded_amount().unwrap(),
				amount
			);
			assert!(btc_nc.inner.get_state().pending.is_empty());
			if amount == 540 {
				let progress = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
				swap.state = StateId::BuyerWaitingForRefundConfirmations;
				let response = api
					.get_fsm(&kc, &swap)
					.process(Input::Check, &mut swap, &context, &progress, &mut secp)
					.unwrap();
				assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
				assert!(swap
					.journal
					.last()
					.unwrap()
					.message
					.contains("remain unrefunded"));
			} else {
				assert_eq!(plan.pending.len(), 1);
			}
		}
	}

	// An older fee attempt can win the race. A child must spend that winner,
	// and a later reorg must retry the same parent instead of invalidating it.
	#[test]
	#[serial]
	fn buyer_refund_tracks_parent_replacements_and_pins_signed_children() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 1);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let script = api.script(&swap, &secp).unwrap();
		btc_nc.inner.clean();
		refund_funding(&btc_nc, &script, &[100_000; 40], 0);
		let before_refund = btc_nc.inner.get_state();
		let address = swap.unwrap_buyer().unwrap();
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let first = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let replacement = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert_ne!(first.transaction.txid, replacement.transaction.txid);
		btc_nc
			.post_error
			.store(1, std::sync::atomic::Ordering::SeqCst);
		assert!(api
			.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.is_err());
		// The old attempt is known, but the prepared replacement is not. Retry
		// must remain possible even though the current fee matches that candidate.
		swap::set_testing_cur_time(swap::get_cur_time() + state::POST_SECONDARY_RETRY_PERIOD + 1);
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		swap.state = StateId::BuyerWaitingForRefundConfirmations;
		let response = api
			.get_fsm(&kc, &swap)
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::BuyerPostingRefundForSecondary
		);
		btc_nc
			.post_error
			.store(0, std::sync::atomic::Ordering::SeqCst);
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let child = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		assert_eq!(
			child.inputs[0].out_point,
			first.carry_output.as_ref().unwrap().out_point
		);
		// Reorg to before the parent's broadcast, then change the requested fee.
		btc_nc.inner.set_state(&before_refund);
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(30_000);
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			first.transaction.tx
		);
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.refund_transaction
				.as_ref()
				.unwrap()
				.transaction
				.tx,
			child.transaction.tx
		);
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert_eq!(plan.batches.len(), 2);
		assert_eq!(plan.batches[0].attempts.len(), 2);
	}

	#[test]
	#[serial]
	fn buyer_refund_migrates_legacy_cache_without_losing_spent_inputs() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, context, kc, nc, btc_nc) = refund_fixture(&secp);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let address = swap.unwrap_buyer().unwrap();
		// Posting must not implicitly build a transaction that was never saved.
		assert!(api
			.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address.clone(), true)
			.is_err());
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let legacy = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_transaction
			.clone()
			.unwrap();
		api.post_secondary_refund_tx(&secp, &kc, &context, &mut swap, address, true)
			.unwrap();
		swap.secondary_data.unwrap_btc_mut().unwrap().refund_plan = None;
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		api.prepare_secondary_refund(&secp, &kc, &context, &mut swap)
			.unwrap();
		let plan = swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.as_ref()
			.unwrap();
		assert!(plan.pending.is_empty());
		assert_eq!(plan.batches.len(), 1);
		assert_eq!(
			plan.batches[0].attempts[0].transaction.tx,
			legacy.transaction.tx
		);
		assert_eq!(plan.batches[0].attempts[0].inputs, legacy.inputs);
		btc_nc.inner.mine_blocks(swap.secondary_confirmations);
		assert_eq!(
			api.request_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_refund_progress,
			Some(BtcRefundProgress::Complete)
		);
	}

	// A permitted input count alone must not authorize the seller's signature.
	// Expect an amount mismatch or unconfirmed funding to fail acceptance. Once
	// accepted, missing outputs must fail revalidation while preserving the saved
	// set for recovery, rather than replacing it with whatever the node returns.
	#[test]
	#[serial]
	fn seller_funding_limit_requires_complete_confirmed_funding() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut swap, _context, _kc, nc, btc_nc) = funding_limit_fixture(&secp, 32);
		let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
		let api: &dyn SwapApi<ExtKeychain> = &api;
		// Make the confirmed funding one satoshi short of the agreed amount.
		swap.secondary_amount += 1;
		assert!(api.prepare_secondary_redeem(&mut swap, &secp).is_err());
		swap.secondary_amount -= 1;
		let original = btc_nc.get_state();
		let mut unconfirmed = original.clone();
		// Restore the amount, but mark every funding output as unconfirmed.
		for height in unconfirmed.tx_heights.values_mut() {
			*height = 0;
		}
		btc_nc.set_state(&unconfirmed);
		assert!(api.prepare_secondary_redeem(&mut swap, &secp).is_err());
		assert!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.redeem_inputs
				.is_none()
		);
		// Restore confirmed funding and accept it, then simulate its disappearance
		// from the backend. Revalidation must fail without forgetting the 32 inputs.
		btc_nc.set_state(&original);
		api.prepare_secondary_redeem(&mut swap, &secp).unwrap();
		btc_nc.clean();
		assert!(api.prepare_secondary_redeem(&mut swap, &secp).is_err());
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.redeem_inputs
				.as_ref()
				.unwrap()
				.len(),
			32
		);
	}

	// Because of gonden output new line symbol we skipping Windows.
	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn test_swap_serde() {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		// Seller context
		let ctx_sell_str = read_to_string("swap_test/context_sell.json").unwrap();
		let ctx_sell: Context = serde_json::from_str(&ctx_sell_str).unwrap();
		assert_eq!(
			serde_json::to_string_pretty(&ctx_sell).unwrap(),
			ctx_sell_str.trim_end()
		);

		// Buyer context
		let ctx_buy_str = read_to_string("swap_test/context_buy.json").unwrap();
		let ctx_buy: Context = serde_json::from_str(&ctx_buy_str).unwrap();
		assert_eq!(serde_json::to_string_pretty(&ctx_buy).unwrap(), ctx_buy_str);

		// Seller's swap state in different stages
		for i in 0..6 {
			println!("TRY SELL {}", i);
			let swap_str = read_to_string(format!("swap_test/swap_sell_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK SELL {}", i);
		}

		// Buyer's swap state in different stages
		for i in 0..3 {
			println!("TRY BUY {}", i);
			let swap_str = read_to_string(format!("swap_test/swap_buy_{}.json", i + 1)).unwrap();
			let swap: Swap = serde_json::from_str(&swap_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&swap).unwrap(), swap_str);
			println!("OK BUY {}", i);
		}

		// Messages
		for i in 0..4 {
			println!("TRY MSG {}", i);
			let message_str = read_to_string(format!("swap_test/message_{}.json", i + 1)).unwrap();
			let message: Message = serde_json::from_str(&message_str).unwrap();
			assert_eq!(serde_json::to_string_pretty(&message).unwrap(), message_str);
			println!("OK MSG {}", i);
		}
	}

	#[cfg(not(target_os = "windows"))]
	#[test]
	fn legacy_float_fee_swap_schema_is_rejected() {
		let mut legacy: serde_json::Value =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_1.json").unwrap()).unwrap();
		let object = legacy.as_object_mut().unwrap();
		object.remove("secondary_fee_units").unwrap();
		object.insert("secondary_fee".to_string(), serde_json::Value::from(1.4));
		object.insert("version".to_string(), serde_json::Value::from(1));

		assert!(serde_json::from_value::<Swap>(legacy).is_err());
	}

	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn trade_record_roundtrip_preserves_delimiter_in_tag() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().unwrap();
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();

		let context: Context =
			serde_json::from_str(&read_to_string("swap_test/context_sell.json").unwrap()).unwrap();
		let mut swap: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_1.json").unwrap()).unwrap();
		swap.tag = Some("offer<#>tag".to_string());

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let enc_key = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
		let lock = Mutex::new(());
		let _guard = lock.lock();
		trades::store_swap_trade(context_id, &context, &swap, &enc_key, &lock).unwrap();
		let (_, loaded) =
			trades::get_swap_trade(context_id, &swap.id.to_string(), &enc_key, &lock).unwrap();
		assert_eq!(loaded.tag.as_deref(), Some("offer<#>tag"));
		trades::trades_clean_context(context_id);
	}

	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn pending_marketplace_cancel_requires_explicit_discard_before_delete() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().unwrap();
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();

		let context: Context =
			serde_json::from_str(&read_to_string("swap_test/context_sell.json").unwrap()).unwrap();
		let mut swap: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_1.json").unwrap()).unwrap();
		swap.state = StateId::SellerCancelled;
		swap.pending_marketplace_cancel_notification = true;
		swap.marketplace_cancel_notification_nonce = Some(Uuid::new_v4());

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let enc_key = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
		let lock = Mutex::new(());
		let _guard = lock.lock();
		trades::store_swap_trade(context_id, &context, &swap, &enc_key, &lock).unwrap();

		let error = trades::delete_swap_trade(
			context_id,
			&swap.id.to_string(),
			&enc_key,
			&lock,
			false,
		)
		.unwrap_err();
		assert!(error.to_string().contains("pending marketplace cancellation"));

		trades::delete_swap_trade(
			context_id,
			&swap.id.to_string(),
			&enc_key,
			&lock,
			true,
		)
		.unwrap();
		assert!(matches!(
			trades::get_swap_trade(context_id, &swap.id.to_string(), &enc_key, &lock),
			Err(Error::TradeNotFound(_))
		));
		trades::trades_clean_context(context_id);
	}

	#[test]
	fn seller_remembers_marketplace_winner_lease_from_accept_offer() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = keychain(&secp, 1);
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_sell.json")).unwrap();
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_1.json")).unwrap();
		let message = Message::from_json(include_str!("../../swap_test/message_2.json")).unwrap();
		let (_, mut accept_offer, _) = message.unwrap_accept_offer().unwrap();
		let expires_at = 1_567_632_752;
		accept_offer.marketplace_winner_lease_expires_at = Some(expires_at);

		let nc = TestNodeClient::new(300_000);
		for input in swap
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			nc.push_output(input.unwrap());
		}

		SellApi::accepted_offer(
			0,
			&mut secp,
			&keychain,
			&mut swap,
			&context,
			accept_offer,
			&nc,
		)
		.unwrap();
		assert_eq!(swap.marketplace_winner_lease_expires_at, Some(expires_at));
	}

	#[test]
	fn swap_creation_locks_are_shared_per_context() {
		let context_id = u32::MAX - 17;
		let same_context = trades::get_swap_creation_lock(context_id);
		let same_context_again = trades::get_swap_creation_lock(context_id);
		let other_context = trades::get_swap_creation_lock(context_id + 1);

		assert!(Arc::ptr_eq(&same_context, &same_context_again));
		assert!(!Arc::ptr_eq(&same_context, &other_context));

		let _guard = same_context.lock();
		assert!(same_context_again.try_lock().is_none());
		assert!(other_context.try_lock().is_some());
	}

	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn malformed_existing_trade_is_not_reported_as_missing() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().unwrap();
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();

		let swap_id = "00000000-0000-0000-0000-000000000001";
		let trade_path = storage
			.path()
			.join(trades::SWAP_DEAL_SAVE_DIR)
			.join(format!("{}.swap", swap_id));
		let malformed_record = b"{malformed encrypted swap record";
		write(&trade_path, malformed_record).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let enc_key = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
		let lock = Mutex::new(());
		let _guard = lock.lock();
		let result = trades::get_swap_trade(context_id, swap_id, &enc_key, &lock);

		assert!(result.is_err());
		assert!(!matches!(&result, Err(Error::TradeNotFound(_))));
		assert_eq!(std::fs::read(&trade_path).unwrap(), malformed_record.to_vec());
		trades::trades_clean_context(context_id);
	}

	// test_swap_fsm timimg config. Constans will be used to validate the timing limits.
	const START_TIME: i64 = 1568000000;
	const MWC_CONFIRMATION: u64 = 30;
	const BTC_CONFIRMATION: u64 = 6;
	const MSG_EXCHANGE_TIME: i64 = 3600;
	const REDEEM_TIME: i64 = 3600;

	pub struct Trader<'a> {
		api: &'a BtcSwapApi<'a, TestNodeClient, TestBtcNodeClient>,
		pub swap: Swap,
		fsm: StateMachine<'a>,
		pub kc: ExtKeychain,
		ctx: Context,
		swap_stack: Vec<(Swap, TestNodeClientState, TestBtcNodeClientState)>,
	}

	impl<'a> Trader<'a> {
		pub fn process(
			&mut self,
			input: Input,
			secp: &mut Secp256k1,
		) -> Result<StateProcessRespond, Error> {
			if matches!(input, Input::Execute)
				&& self.swap.state == StateId::BuyerPostingRefundForSecondary
			{
				self.api
					.prepare_secondary_refund(secp, &self.kc, &self.ctx, &mut self.swap)?;
			}
			let tx_conf = self
				.api
				.request_tx_confirmations(secp, &self.kc, &self.swap)?;
			self.fsm
				.process(input, &mut self.swap, &self.ctx, &tx_conf, secp)
		}

		pub fn _get_tx_conf(
			&self,
			secp: &Secp256k1,
		) -> Result<SwapTransactionsConfirmations, Error> {
			self.api
				.request_tx_confirmations(secp, &self.kc, &self.swap)
		}

		pub fn is_cancellable(&self) -> bool {
			self.fsm.is_cancellable(&self.swap).unwrap()
		}

		pub fn pushs(&mut self) {
			self.swap_stack.push((
				self.swap.clone(),
				self.api.node_client.get_state(),
				self.api.btc_node_client1.lock().get_state(),
			));
		}
		pub fn pops(&mut self) {
			let (swap, nc_state, bnc_state) = self.swap_stack.pop().unwrap();
			self.swap = swap;
			self.api.node_client.set_state(&nc_state);
			self.api.btc_node_client1.lock().set_state(&bnc_state);
		}
	}

	// return time2pass, time2fail
	fn calc_time_to_test(
		timeout1: &Option<(i64, i64)>,
		timeout2: &Option<(i64, i64)>,
	) -> (Vec<i64>, Vec<i64>) {
		let (t, t2) = timeout1.clone().unwrap_or(timeout2.unwrap_or((-1, -1)));
		if t > 0 {
			assert!(swap::get_cur_time() < t);
			if t2 < 0 {
				(
					vec![swap::get_cur_time(), (swap::get_cur_time() + t) / 2, t - 1],
					vec![
						t + 1,
						t + MSG_EXCHANGE_TIME / 2,
						t + MSG_EXCHANGE_TIME,
						swap::get_cur_time() + 1000000000,
					],
				)
			} else {
				assert!(t < t2);
				(
					vec![swap::get_cur_time(), (swap::get_cur_time() + t) / 2, t - 1],
					vec![t + 1, (t + t2) / 2, t2 - 1],
				)
			}
		} else {
			if t2 < 0 {
				(
					vec![
						swap::get_cur_time(),
						swap::get_cur_time() + MSG_EXCHANGE_TIME,
						swap::get_cur_time() + 1000000000,
					],
					vec![],
				)
			} else {
				assert!(swap::get_cur_time() < t2);
				(vec![t2, t2 + MSG_EXCHANGE_TIME, t2 + 1000000000], vec![])
			}
		}
	}

	// Test all possible responds (covereage for all inputs and with timeouts )
	fn test_responds(
		trader: &mut Trader,
		expected_starting_state: StateId,
		timeout: Option<(i64, i64)>, // timeout if possible
		cancel_expected_state: Option<StateId>,
		check_before_expected_state: StateId, // Expected state before timeput
		check_after_expected_state: StateId,  // Expected state after timeout
		timeout_execute: Option<(i64, i64)>, // timeout for execute. Might be different becaus of switching to the next stage. If none, timeout will be used
		execute_before_expected_state: Option<StateId>, // Expected state before timeput
		execute_after_expected_state: Option<StateId>, // Expected state after timeout
		message: Option<Message>,            // Acceptable message
		message_before_expected_state: Option<StateId>,
		message_after_expected_state: Option<StateId>,
		secp: &mut Secp256k1,
	) {
		// Checking the timeout
		assert_eq!(trader.swap.state, expected_starting_state);

		if !is_test_response() {
			return;
		}

		let (time2pass, time2fail) = calc_time_to_test(&timeout, &None);

		let mut time_all = time2pass.clone();
		time_all.extend(time2fail.iter().copied());

		let start_time = swap::get_cur_time();

		// Checking what Cancel does
		for t in &time_all {
			trader.pushs();
			swap::set_testing_cur_time(*t);

			if cancel_expected_state.is_some() {
				let _sr = trader.process(Input::Cancel, secp).unwrap();
				assert_eq!(trader.swap.state, cancel_expected_state.clone().unwrap());
			} else {
				assert_eq!(trader.is_cancellable(), false);
				let sr = trader.process(Input::Cancel, secp);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}

		// Check Inputs
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check, secp).unwrap();
			assert_eq!(trader.swap.state, check_before_expected_state);
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check, secp).unwrap();
			assert_eq!(trader.swap.state, check_after_expected_state);
			trader.pops();
		}

		// Restore original time first
		swap::set_testing_cur_time(start_time);
		let (time2pass, time2fail) = calc_time_to_test(&timeout_execute, &timeout);

		// Execute
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			if execute_before_expected_state.is_some() {
				let _sr = trader.process(Input::Execute, secp).unwrap();
				assert_eq!(
					trader.swap.state,
					execute_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute, secp);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			if execute_after_expected_state.is_some() {
				let _sr = trader.process(Input::Execute, secp).unwrap();
				assert_eq!(
					trader.swap.state,
					execute_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute, secp);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}

		// IncomeMessage
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let message = Input::IncomeMessage(message.clone().unwrap_or(Message::new(
				trader.swap.id.clone(),
				Update::None,
				SecondaryUpdate::Empty,
			)));
			if message_before_expected_state.is_some() {
				let _sr = trader.process(message, secp).unwrap();
				assert_eq!(
					trader.swap.state,
					message_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message, secp);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let message = Input::IncomeMessage(message.clone().unwrap_or(Message::new(
				trader.swap.id.clone(),
				Update::None,
				SecondaryUpdate::Empty,
			)));
			if message_after_expected_state.is_some() {
				let _sr = trader.process(message, secp).unwrap();
				assert_eq!(
					trader.swap.state,
					message_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message, secp);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}

		// Restore original time
		swap::set_testing_cur_time(start_time);
	}

	#[test]
	#[serial]
	// The primary goal for this test is to cover all code path for edge cases
	fn test_swap_fsm() {
		activate_test_response(true);
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		swap::set_testing_cur_time(START_TIME);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * MWC_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount_plus = 10_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		let mut api_sell =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let kc_sell = keychain(&secp, 1);
		let ctx_sell = context_sell(&secp, &kc_sell);
		nc.add_seller_inputs(&secp, &kc_sell, &ctx_sell);

		let mut seller = {
			let secondary_redeem_address = btc_address(&mut secp, &kc_sell);
			let swap_sell = api_sell
				.create_swap_offer(
					&mut secp,
					&kc_sell,
					&ctx_sell,
					300_000,
					amount,
					btc_amount,
					Currency::Btc,
					secondary_redeem_address,
					true, // lock MWC first
					MWC_CONFIRMATION,
					BTC_CONFIRMATION,
					MSG_EXCHANGE_TIME as u64,
					REDEEM_TIME as u64,
					"file".to_string(),
					"/tmp/del.me".to_string(),
					None,
					None,
					None,
					None,
					None,
					Some(false),
					false,
					None,
				)
				.unwrap();
			let fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);

			// Seller: create swap offer
			Trader {
				api: &api_sell,
				swap: swap_sell,
				fsm: fsm_sell,
				kc: kc_sell.clone(),
				ctx: ctx_sell,
				swap_stack: Vec::new(),
			}
		};

		// Initial state test.
		test_responds(
			&mut seller,
			StateId::SellerOfferCreated,
			Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
			Some(StateId::SellerCancelled),
			StateId::SellerSendingOffer, // Expected state before timeput
			StateId::SellerCancelled,    // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		// Go to the next step
		swap::set_testing_cur_time(START_TIME + 20);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(seller.swap.state, StateId::SellerSendingOffer);
		assert_eq!(
			res.time_limit.clone().unwrap(),
			START_TIME + MSG_EXCHANGE_TIME
		);
		assert_eq!(res.next_state_id, seller.swap.state);
		let message1 = match res.action.unwrap() {
			Action::SellerSendOfferMessage(m) => m,
			_ => panic!("Unexpected action"),
		};

		// SellerSendingOffer
		test_responds(
			&mut seller,
			StateId::SellerSendingOffer,
			Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
			Some(StateId::SellerCancelled),
			StateId::SellerSendingOffer, // Expected state before timeput
			StateId::SellerCancelled,    // Expected state after timeout
			None,
			Some(StateId::SellerWaitingForAcceptanceMessage), // Expected state before timeput
			Some(StateId::SellerCancelled),                   // Expected state after timeout
			None,                                             // Acceptable message
			None,
			None,
			&mut secp,
		);
		// Seller send the message, so confirming to FSM with that
		let res = seller.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(
			seller.swap.state,
			StateId::SellerWaitingForAcceptanceMessage
		);
		assert_eq!(
			res.time_limit.clone().unwrap(),
			START_TIME + MSG_EXCHANGE_TIME
		);
		assert_eq!(res.next_state_id, seller.swap.state);
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"SellerWaitForOfferMessage"
		);

		// Let's test send retry logic
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);

		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSendingOffer);
		// simulate ack that we get from the network...
		seller.swap.ack_msg1();
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);

		// ----------------------------------------------------------------------------------------------------------
		// ----------------------------------------------------------------------------------------------------------
		// ----------------------------------------------------------------------------------------------------------

		// Creating buyer
		let kc_buy = keychain(&secp, 2);
		let ctx_buy = context_buy(&secp, &kc_buy);
		let api_buy =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

		////////////////////////////////////////////////////////////////////
		// Testing how Buyer can validate the data

		{
			// Try to create offer with no inputs on the chain
			nc.state.lock().outputs.clear();
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		// Add inputs to utxo set
		nc.mine_blocks(2);
		for input in seller
			.swap
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			nc.push_output(input.unwrap());
		}

		{
			// Should be good now...
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_ok(),
				true
			);
		}

		/////////////////////////////////////////////////////////////
		// -------------------- Testing cases when seller try to tweak some data

		{
			// Try to create offer with wrong times
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			swap::set_testing_cur_time(START_TIME - 30);
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		// Fixing the time. Assuming it took 100 seconds to deliver the message
		swap::set_testing_cur_time(START_TIME + 100);
		{
			// Offer with wrong network
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			offer.network = Network::Mainnet;
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		{
			// Offer lock slate has height (not important)...
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.set_lock_height_no_check(10);
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Offer lock slate has height (kernel value - attack)
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: lock_slate.fee.try_into().unwrap(),
					lock_height: 10,
				};
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Offer lock slate has height (kernel value - attack)
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.set_lock_height_no_check(10);
			lock_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: lock_slate.fee.try_into().unwrap(),
					lock_height: 10,
				};
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		// Trying to tweak the fees
		{
			// Offer lock slate has height
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.fee += 2;
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Offer lock slate has height
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.tx_or_err_mut().unwrap().body.kernels[0].features = KernelFeatures::Plain {
				fee: (lock_slate.fee + 1).try_into().unwrap(),
			};
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Offer lock slate has height
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.tx_or_err_mut().unwrap().body.kernels[0].features = KernelFeatures::Plain {
				fee: (lock_slate.fee - 1).try_into().unwrap(),
			};
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Offer lock slate has height
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.fee += 2;
			lock_slate.tx_or_err_mut().unwrap().body.kernels[0].features = KernelFeatures::Plain {
				fee: lock_slate.fee.try_into().unwrap(),
			};
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		{
			// No inputs at lock
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.tx_or_err_mut().unwrap().body.inputs = Inputs::CommitOnly(vec![]);
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Amounts at lock
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut lock_slate: Slate = offer.lock_slate.into_slate_plain(0, false).unwrap();
			lock_slate.amount += 1;
			offer.lock_slate =
				VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		{
			// Refund slate must have expected lock value
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.set_lock_height(u64::MAX - 3).unwrap();
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		{
			// Refund slate must have expected lock value
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.set_related_height(3200).unwrap();
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		{
			// Refund slate must have expected lock value
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.reset_lock_height();
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund slate must have expected lock value, tweaking kernel, adding one more plain one
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate
				.tx_or_err_mut()
				.unwrap()
				.body
				.kernels
				.push(TxKernel::empty().unwrap());
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund slate must have expected lock value, tweaking kernel to plain
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::Plain {
					fee: refund_slate.fee.try_into().unwrap(),
				};
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund slate must have expected lock value, tweaking kernel's height to plain
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: refund_slate.fee.try_into().unwrap(),
					lock_height: refund_slate.get_lock_height() - 1,
				};
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund slate must have expected lock value, tweaking kernel's height to plain
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: refund_slate.fee.try_into().unwrap(),
					lock_height: 0,
				};
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund slate must have expected lock value, tweaking kernel's height to plain
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: refund_slate.fee.try_into().unwrap(),
					lock_height: 1,
				};
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund fees
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.fee += 1;
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Refund fees
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.tx_or_err_mut().unwrap().body.kernels[0].features =
				KernelFeatures::HeightLocked {
					fee: (refund_slate.fee + 1).try_into().unwrap(),
					lock_height: refund_slate.get_lock_height(),
				};
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}
		{
			// Amounts at refund
			let (id, mut offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let mut refund_slate: Slate = offer.refund_slate.into_slate_plain(0, false).unwrap();
			refund_slate.amount -= 1;
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3).unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
					0,
					&mut secp,
					None,
					&kc_buy,
					&ctx_buy,
					id,
					offer.clone(),
					secondary_update.clone(),
					&nc
				)
				.is_err(),
				true
			);
		}

		// Secondary Data has only public key. Not much what we can tweak to steal the funds.

		// ----------------------------------------------------------------------------------------------
		// Finally going with buyer. Happy path
		let mut buyer = {
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let swap_buy = BuyApi::accept_swap_offer(
				0,
				&mut secp,
				None,
				&kc_buy,
				&ctx_buy,
				id,
				offer,
				secondary_update,
				&nc,
			)
			.unwrap();
			let fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);
			// Seller: create swap offer
			Trader {
				api: &api_buy,
				swap: swap_buy,
				fsm: fsm_buy,
				kc: kc_buy,
				ctx: ctx_buy,
				swap_stack: Vec::new(),
			}
		};

		// BTC address and let's prepare transactions. to be ready to deposit
		let input_script = buyer.api.script(&buyer.swap, &mut secp).unwrap();
		let btc_address_to_deposit = buyer
			.swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.address(Currency::Btc, &input_script, buyer.swap.network)
			.unwrap();
		let tx_1 = BitcoinTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: Currency::Btc
					.address_2_script_pubkey(0, &btc_address_to_deposit[0])
					.unwrap(),
			}],
		};
		let tx_2 = BitcoinTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: Currency::Btc
					.address_2_script_pubkey(0, &btc_address_to_deposit[0])
					.unwrap(),
			}],
		};
		let tx_plus = BitcoinTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_plus,
				script_pubkey: Currency::Btc
					.address_2_script_pubkey(0, &btc_address_to_deposit[0])
					.unwrap(),
			}],
		};

		// Initial buyer state test.
		test_responds(
			&mut buyer,
			StateId::BuyerOfferCreated,
			Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
			Some(StateId::BuyerCancelled),
			StateId::BuyerSendingAcceptOfferMessage, // Expected state before timeput
			StateId::BuyerCancelled,                 // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		swap::set_testing_cur_time(START_TIME + 120);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(buyer.swap.state, StateId::BuyerSendingAcceptOfferMessage);
		assert_eq!(
			res.time_limit.clone().unwrap(),
			START_TIME + MSG_EXCHANGE_TIME
		);
		assert_eq!(res.next_state_id, buyer.swap.state);
		let message2 = match res.action.unwrap() {
			Action::BuyerSendAcceptOfferMessage(m) => m,
			_ => panic!("Unexpected action"),
		};
		let lock_start_timelimit =
			START_TIME + MSG_EXCHANGE_TIME + BTC_CONFIRMATION as i64 * 10 * 60 * 11 / 10 / 20;
		let lock_second_message_round_timelimit = START_TIME
			+ MSG_EXCHANGE_TIME
			+ BTC_CONFIRMATION as i64 * 10 * 60 * 11 / 10
			+ MSG_EXCHANGE_TIME;
		let mwc_lock_time_limit = lock_second_message_round_timelimit
			+ MWC_CONFIRMATION as i64 * 60 * 11 / 10
			+ REDEEM_TIME;
		let btc_lock_time_limit = mwc_lock_time_limit
			+ REDEEM_TIME
			+ REDEEM_TIME
			+ MWC_CONFIRMATION as i64 * 60 * 11 / 10
			+ BTC_CONFIRMATION as i64 * 10 * 60 * 11 / 10;

		assert_eq!(
			seller.swap.get_time_start_lock().unwrap(),
			lock_start_timelimit
		);
		assert_eq!(
			seller.swap.get_time_message_redeem().unwrap(),
			lock_second_message_round_timelimit
		);
		assert_eq!(
			seller.swap.get_time_secondary_lock_script().unwrap(),
			btc_lock_time_limit
		);
		assert_eq!(
			seller.swap.get_time_mwc_lock().unwrap(),
			mwc_lock_time_limit
		);

		test_responds(
			&mut buyer,
			StateId::BuyerSendingAcceptOfferMessage,
			Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
			Some(StateId::BuyerCancelled),
			StateId::BuyerSendingAcceptOfferMessage, // Expected state before timeput
			StateId::BuyerCancelled,                 // Expected state after timeout
			Some((lock_start_timelimit, -1)),
			Some(StateId::BuyerWaitingForSellerToLock), // Expected state before timeput
			Some(StateId::BuyerCancelled),              // Expected state after timeout
			None,                                       // Acceptable message
			None,
			None,
			&mut secp,
		);
		swap::set_testing_cur_time(START_TIME + 130);
		// Reporting that message is sent...
		let res = buyer.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(buyer.swap.state, StateId::BuyerWaitingForSellerToLock);
		assert_eq!(res.next_state_id, buyer.swap.state);
		assert_eq!(res.time_limit.clone().unwrap(), lock_start_timelimit);
		assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");

		// Checking send message retry...
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerWaitingForSellerToLock);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerWaitingForSellerToLock);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
		// simulate ack
		buyer.swap.ack_msg1();
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerWaitingForSellerToLock);

		// Seller is waiting for the message form the buyer...
		assert_eq!(
			seller.swap.state,
			StateId::SellerWaitingForAcceptanceMessage
		);
		// Let's feed message to the seller.

		// Check if seller will wait for Buyer to deposit first.
		{
			// ------- It is a branch activity, will be rolled back soon
			seller.pushs();
			assert_eq!(seller.swap.seller_lock_first, true);
			seller.swap.seller_lock_first = false;
			test_responds(
				&mut seller,
				StateId::SellerWaitingForAcceptanceMessage,
				Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
				Some(StateId::SellerCancelled),
				StateId::SellerWaitingForAcceptanceMessage, // Expected state before timeput
				StateId::SellerCancelled,                   // Expected state after timeout
				Some((lock_start_timelimit, -1)),
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message2.clone()), // Acceptable message
				Some(StateId::SellerWaitingForBuyerLock),
				Some(StateId::SellerCancelled),
				&mut secp,
			);
			// try to process wrong message
			assert_eq!(
				seller
					.process(Input::IncomeMessage(message1.clone()), &mut secp)
					.is_err(),
				true
			);
			let res = seller
				.process(Input::IncomeMessage(message2.clone()), &mut secp)
				.unwrap();
			assert_eq!(seller.swap.state, StateId::SellerWaitingForBuyerLock);
			assert_eq!(res.next_state_id, seller.swap.state);
			assert_eq!(
				res.action.unwrap().get_id_str(),
				"WaitForSecondaryConfirmations"
			);

			// Double processing should be fine as well
			assert_eq!(seller.swap.state, StateId::SellerWaitingForBuyerLock);
			let res = seller
				.process(Input::IncomeMessage(message2.clone()), &mut secp)
				.unwrap();
			assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerLock);

			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerWaitingForBuyerLock, // Expected state before timeput
				StateId::SellerCancelled,           // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let state = btc_nc.get_state();

			btc_nc.post_transaction(&tx_1).unwrap();
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerWaitingForBuyerLock, // Expected state before timeput
				StateId::SellerCancelled,           // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			btc_nc.mine_blocks(1);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerWaitingForBuyerLock, // Expected state before timeput
				StateId::SellerCancelled,           // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			btc_nc.post_transaction(&tx_2).unwrap();
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerWaitingForBuyerLock, // Expected state before timeput
				StateId::SellerCancelled,           // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			btc_nc.mine_blocks(1);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerPostingLockMwcSlate, // Expected state before timeput
				StateId::SellerCancelled,           // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			btc_nc.post_transaction(&tx_plus).unwrap();
			// Expected to be cancelled because buyer posted too much funds...
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerLock,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerCancelled),
				StateId::SellerCancelled, // Expected state before timeput
				StateId::SellerCancelled, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			// Cleaning up after the branch
			btc_nc.set_state(&state);
			seller.pops();
			// Branch test is ended, evething is restored.
		}

		{
			// BRANCH - Checking simple cancel case
			buyer.pushs();
			seller.pushs();

			let res = buyer.process(Input::Cancel, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerCancelled);
			assert_eq!(res.action.is_some(), false);
			assert_eq!(res.time_limit.is_some(), false);

			let res = seller.process(Input::Cancel, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerCancelled);
			assert_eq!(res.action.is_some(), false);
			assert_eq!(res.time_limit.is_some(), false);

			test_responds(
				&mut seller,
				StateId::SellerCancelled,
				None,
				None,
				StateId::SellerCancelled, // Expected state before timeput
				StateId::SellerCancelled, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			test_responds(
				&mut buyer,
				StateId::BuyerCancelled,
				None,
				None,
				StateId::BuyerCancelled, // Expected state before timeput
				StateId::BuyerCancelled, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			seller.pops();
			buyer.pops();
			// End of branch
		}

		assert_eq!(
			seller.swap.state,
			StateId::SellerWaitingForAcceptanceMessage
		);
		assert_eq!(buyer.swap.state, StateId::BuyerWaitingForSellerToLock);

		test_responds(
			&mut seller,
			StateId::SellerWaitingForAcceptanceMessage,
			Some((START_TIME + MSG_EXCHANGE_TIME, -1)), // timeout if possible
			Some(StateId::SellerCancelled),
			StateId::SellerWaitingForAcceptanceMessage, // Expected state before timeput
			StateId::SellerCancelled,                   // Expected state after timeout
			Some((lock_start_timelimit, -1)),
			None,                   // Expected state before timeput
			None,                   // Expected state after timeout
			Some(message2.clone()), // Acceptable message
			Some(StateId::SellerPostingLockMwcSlate),
			Some(StateId::SellerCancelled),
			&mut secp,
		);
		// try to process wrong message
		assert_eq!(
			seller
				.process(Input::IncomeMessage(message1.clone()), &mut secp)
				.is_err(),
			true
		);
		let res = seller
			.process(Input::IncomeMessage(message2.clone()), &mut secp)
			.unwrap();
		assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
		assert_eq!(res.next_state_id, seller.swap.state);
		assert_eq!(res.time_limit.clone().unwrap(), lock_start_timelimit);
		assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcLockTx");

		// Double processing should be fine
		assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
		let res = seller
			.process(Input::IncomeMessage(message2.clone()), &mut secp)
			.unwrap();
		assert_eq!(res.next_state_id, StateId::SellerPostingLockMwcSlate);

		swap::set_testing_cur_time(START_TIME + 150);

		test_responds(
			&mut seller,
			StateId::SellerPostingLockMwcSlate,
			Some((lock_start_timelimit, -1)),
			Some(StateId::SellerCancelled),
			StateId::SellerPostingLockMwcSlate, // Expected state before timeput
			StateId::SellerCancelled,           // Expected state after timeout
			None,
			Some(StateId::SellerWaitingForLockConfirmations), // Expected state before timeput
			Some(StateId::SellerCancelled),                   // Expected state after timeout
			None,                                             // Acceptable message
			None,
			None,
			&mut secp,
		);

		// Seller posting MWC transaction, testing retry tx cases.
		let nc_nolock_state = nc.get_state();
		{
			// Let's check what happens if MWC is not published. Seller need to do a retry.
			let res = seller.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			assert_eq!(res.next_state_id, seller.swap.state);
			assert_eq!(
				res.time_limit.clone().unwrap(),
				lock_second_message_round_timelimit
			);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitForLockConfirmations");
			// check if record was created
			let first_post_time = swap::get_cur_time();
			assert_eq!(seller.swap.posted_lock.clone().unwrap(), first_post_time);

			//			let nc_lock_posted_state = nc.get_state();

			// Erasing the mwc post data...
			//			nc.set_state(&nc_nolock_state);

			swap::set_testing_cur_time(START_TIME + 150 + 60 * 5 + 1);
			// nothing was mined, should be not confirmed yet

			// Expecting that we will switch to the publish MWC lock state
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
			assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcLockTx");
			// SellerPostingLockMwcSlate expecting to fail because tx into the tx pool
			assert_eq!(seller.process(Input::Execute, &mut secp).is_err(), true);
			// Even a failed response records the latest submission attempt: the
			// wallet cannot assume that a node error means the lock was not accepted.
			let retry_post_time = swap::get_cur_time();
			assert_eq!(seller.swap.posted_lock.unwrap(), retry_post_time);
			// Let's check the cancel now is different.
			test_responds(
				&mut seller,
				StateId::SellerPostingLockMwcSlate,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerPostingLockMwcSlate, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				None,                                        // expected to fail.
				Some(StateId::SellerWaitingForRefundHeight), // Expected state after timeout
				None,                                        // Acceptable message
				None,
				None,
				&mut secp,
			);

			{
				// BRANCH - Check if cancel in far future is different.
				seller.pushs();
				nc.mine_blocks(600);
				let res = seller.process(Input::Cancel, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				seller.pops();
			}

			seller.pushs();
			// Let's mine block. Now SellerPostingLockMwcSlate should be able to detect that we are good nwo and not publish
			nc.mine_block();

			// block is mined, so it switched to SellerWaitingForLockConfirmations
			test_responds(
				&mut seller,
				StateId::SellerPostingLockMwcSlate,
				Some((lock_second_message_round_timelimit, -1)), // time from SellerWaitingForLockConfirmations
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				Some((lock_second_message_round_timelimit, -1)),
				Some(StateId::SellerWaitingForLockConfirmations), // Expected state before timeput
				Some(StateId::SellerWaitingForRefundHeight),      // Expected state after timeout
				None,                                             // Acceptable message
				None,
				None,
				&mut secp,
			);

			let _res = seller.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			// The lock is now confirmed, so Execute must not submit it again or
			// change the timestamp recorded for the earlier failed retry.
			assert_eq!(seller.swap.posted_lock.unwrap(), retry_post_time);
			seller.pops();

			// Resetting mwc chain as lock tx was never published and retry
			nc.set_state(&nc_nolock_state);

			test_responds(
				&mut seller,
				StateId::SellerPostingLockMwcSlate,
				Some((lock_start_timelimit, -1)),
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerPostingLockMwcSlate, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForLockConfirmations), // Expected state before timeput
				Some(StateId::SellerWaitingForRefundHeight),      // Expected state after timeout
				None,                                             // Acceptable message
				None,
				None,
				&mut secp,
			);

			let _res = seller.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			// post was made with retry. Check the timestamp
			assert_eq!(
				seller.swap.posted_lock.clone().unwrap(),
				swap::get_cur_time()
			);

			// Double processing should be fine
			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			let res = seller
				.process(Input::IncomeMessage(message2.clone()), &mut secp)
				.unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForLockConfirmations
			);

			nc.mine_blocks(2);

			// Let's test reorg case. We want to repost the transaciton
			//swap::set_testing_cur_time(START_TIME + 150 + 60 * 5 * 2 + 2);

			// waiting is fine
			seller.pushs();
			test_responds(
				&mut seller,
				StateId::SellerWaitingForLockConfirmations,
				Some((lock_second_message_round_timelimit, -1)),
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			// Let's roll back the chain
			nc.set_state(&nc_nolock_state);
			// Expecting switch to SellerPostingLockMwcSlate
			// not a time for retry
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForLockConfirmations
			);
			// let's trigger retry
			swap::set_testing_cur_time(START_TIME + 150 + 60 * 5 * 3 + 3);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingLockMwcSlate);
			seller.pops();
			// Last pop return us to a stage where seller already published MWC transaciton. So we can continue with Buyer
		}

		// Buyer should detect posted MWC and be able to switch to the next step
		test_responds(
			&mut buyer,
			StateId::BuyerWaitingForSellerToLock,
			Some((lock_start_timelimit, -1)), // timeout if possible
			Some(StateId::BuyerCancelled),
			StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
			StateId::BuyerCancelled,                         // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		{
			// BRANCH - checking that Sellr lock will set ack to the message
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);

			buyer.pops();
		}

		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			buyer.swap.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		assert_eq!(res.time_limit.unwrap(), lock_start_timelimit);
		match res.action.unwrap() {
			Action::DepositSecondary {
				currency,
				amount,
				address,
			} => {
				assert_eq!(currency, Currency::Btc);
				assert_eq!(amount, btc_amount);
				assert_eq!(address, btc_address_to_deposit);
			}
			_ => panic!("Invalid action"),
		}

		{
			// BRANCH - Checking retry messages
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);

			// Doing some tweaks, need to reset ack first
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);
			let st = nc.get_state();
			nc.set_state(&nc_nolock_state);
			buyer.swap.posted_msg1 = Some(swap::get_cur_time());

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);

			swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
			// simulate ack, so should return back to the current step
			nc.set_state(&st);
			buyer.swap.ack_msg1();
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);

			buyer.pops();
		}

		// Before nothing posted, Buyer still can cancel easily
		test_responds(
			&mut buyer,
			StateId::BuyerPostingSecondaryToMultisigAccount,
			Some((lock_start_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerCancelled),
			StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
			StateId::BuyerCancelled,                         // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		// Let's store BTC network without deposit
		let bnc_deposit_none = btc_nc.get_state();

		btc_nc.post_transaction(&tx_1).unwrap();
		// Posted, not mined. Buyer can't cancel easily
		test_responds(
			&mut buyer,
			StateId::BuyerPostingSecondaryToMultisigAccount,
			Some((lock_start_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,              // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			buyer.swap.state,
			StateId::BuyerPostingSecondaryToMultisigAccount
		);
		assert_eq!(res.time_limit.unwrap(), lock_start_timelimit);
		match res.action.unwrap() {
			Action::DepositSecondary {
				currency,
				amount,
				address,
			} => {
				assert_eq!(currency, Currency::Btc);
				assert_eq!(amount, btc_amount - btc_amount_1);
				assert_eq!(address, btc_address_to_deposit);
			}
			_ => panic!("Invalid action"),
		}

		{
			// BRANCH - Check Buyer cancel in far future is different
			buyer.pushs();
			let cur_ts = swap::get_cur_time();
			swap::set_testing_cur_time(btc_lock_time_limit + 1 + 600 * 5); // Will wait 5 blocks before refund
			let res = buyer.process(Input::Cancel, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);
			swap::set_testing_cur_time(cur_ts);
			buyer.pops();
		}

		// Let's store BTC network with part deposit
		let bnc_deposit_1 = btc_nc.get_state();

		btc_nc.post_transaction(&tx_2).unwrap();
		// Both deposits without confirmations is fine to more to the next step
		test_responds(
			&mut buyer,
			StateId::BuyerPostingSecondaryToMultisigAccount,
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		// Checking if mining blocks will change nothing
		btc_nc.mine_blocks(1);
		test_responds(
			&mut buyer,
			StateId::BuyerPostingSecondaryToMultisigAccount,
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		{
			// Branch -  Checking if posting too much will switch to cancellation
			buyer.pushs();
			btc_nc.post_transaction(&tx_plus).unwrap();
			test_responds(
				&mut buyer,
				StateId::BuyerPostingSecondaryToMultisigAccount,
				Some((lock_start_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForRefundTime, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			buyer.pops();
		}

		// Buyer is good to go to the waiting step
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(buyer.swap.state, StateId::BuyerWaitingForLockConfirmations);
		assert_eq!(res.time_limit.unwrap(), lock_second_message_round_timelimit);
		assert_eq!(res.action.unwrap().get_id_str(), "WaitForLockConfirmations");

		test_responds(
			&mut buyer,
			StateId::BuyerWaitingForLockConfirmations,
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		{
			// BRANCH - Checking retry messages
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);

			// Doing some tweaks, need to reset ack first
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);
			let st = nc.get_state();
			nc.set_state(&nc_nolock_state);
			buyer.swap.posted_msg1 = Some(swap::get_cur_time());

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);

			swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
			// simulate ack, so should return back to the current step
			buyer.swap.ack_msg1();
			nc.set_state(&st);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);

			buyer.pops();
		}

		{
			// BRANCH  - checking how buyer will switch back to deposit step if no funds will be found
			buyer.pushs();

			// With small amount - should switch back to BuyerPostingSecondaryToMultisigAccount
			btc_nc.set_state(&bnc_deposit_1);
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForLockConfirmations,
				Some((lock_start_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,              // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			// With no amount - should switch back to BuyerPostingSecondaryToMultisigAccount, cancel will be without refunds becuse the balance is empty
			btc_nc.set_state(&bnc_deposit_none);
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForLockConfirmations,
				Some((lock_start_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
				StateId::BuyerCancelled,                         // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				buyer.swap.state,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			assert_eq!(res.time_limit.unwrap(), lock_start_timelimit);
			match res.action.unwrap() {
				Action::DepositSecondary {
					currency,
					amount,
					address,
				} => {
					assert_eq!(currency, Currency::Btc);
					assert_eq!(amount, btc_amount);
					assert_eq!(address, btc_address_to_deposit);
				}
				_ => panic!("Invalid action"),
			}

			buyer.pops();
			// Branch is Over
		}

		// Updating Buyer refund address
		buyer
			.swap
			.update_secondary_address("mjdcskZm4Kimq7yzUGLtzwiEwMdBdTa3No".to_string());

		{
			// BRANCH - checking refund workflows.
			seller.pushs();
			buyer.pushs();

			let time_to_restore = swap::get_cur_time();

			let res = buyer.process(Input::Cancel, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForRefundTime);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitingForBtcRefund");
			assert_eq!(res.time_limit.unwrap(), btc_lock_time_limit + 600 * 5); // waiting for 5 extra blocks before refund

			let lock_height = seller
				.swap
				.refund_slate
				.slate
				.get_lock_height_check()
				.unwrap();
			let need_blocks = lock_height - nc.state.lock().height;

			let res = seller.process(Input::Cancel, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerWaitingForRefundHeight);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcRefundUnlock");
			assert_eq!(
				res.time_limit.unwrap(),
				swap::get_cur_time() + (need_blocks * 60) as i64
			);

			// Seller SellerWaitingForRefundHeight depend on height, not on time.
			test_responds(
				&mut seller,
				StateId::SellerWaitingForRefundHeight,
				None,
				None,
				StateId::SellerWaitingForRefundHeight, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			nc.mine_blocks(need_blocks + 1);
			// seller got needed height, now seller is ready to refund
			test_responds(
				&mut seller,
				StateId::SellerWaitingForRefundHeight,
				None,
				None,
				StateId::SellerPostingRefundSlate, // Expected state before timeput
				StateId::SellerPostingRefundSlate, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcRefundTx");
			assert_eq!(res.time_limit.is_none(), true);

			test_responds(
				&mut seller,
				StateId::SellerPostingRefundSlate,
				None,
				None,
				StateId::SellerPostingRefundSlate, // Expected state before timeput
				StateId::SellerPostingRefundSlate, // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForRefundConfirmations), // Expected state before timeput
				Some(StateId::SellerWaitingForRefundConfirmations), // Expected state after timeout
				None,                                               // Acceptable message
				None,
				None,
				&mut secp,
			);

			let nc_state_prepost = nc.get_state();

			let res = seller.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
			assert_eq!(res.time_limit.is_none(), true);
			// Checking post retry workflow. nc not mined, so not cofirmed until
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			//
			swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			// test network not supported repost
			assert_eq!(seller.process(Input::Execute, &mut secp).is_err(), true);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			nc.mine_block();
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);

			// reorg should trigger retry
			nc.set_state(&nc_state_prepost);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			let res = seller.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			nc.mine_block();
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);

			// Waiting and we shoudl done
			nc.mine_blocks(MWC_CONFIRMATION / 2);

			test_responds(
				&mut seller,
				StateId::SellerWaitingForRefundConfirmations,
				None,
				None,
				StateId::SellerWaitingForRefundConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundConfirmations, // Expected state after timeout
				None,
				None,
				None,
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			nc.mine_blocks(MWC_CONFIRMATION / 2);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForRefundConfirmations,
				None,
				None,
				StateId::SellerCancelledRefunded, // Expected state before timeput
				StateId::SellerCancelledRefunded, // Expected state after timeout
				None,
				None,
				None,
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerCancelledRefunded);
			assert_eq!(res.action.is_none(), true);
			assert_eq!(res.time_limit.is_none(), true);

			// Buyer turn to do a refund....
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRefundTime,
				Some((btc_lock_time_limit + 600 * 5, -1)),
				None,
				StateId::BuyerWaitingForRefundTime, // Expected state before timeput
				StateId::BuyerPostingRefundForSecondary, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			swap::set_testing_cur_time(btc_lock_time_limit + 1 + 600 * 5);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);
			assert_eq!(
				res.action.unwrap().get_id_str(),
				"BuyerPublishSecondaryRefundTx"
			);
			assert_eq!(res.time_limit.is_none(), true);

			test_responds(
				&mut buyer,
				StateId::BuyerPostingRefundForSecondary,
				None,
				None,
				StateId::BuyerPostingRefundForSecondary, // Expected state before timeput
				StateId::BuyerPostingRefundForSecondary, // Expected state after timeout
				None,
				Some(StateId::BuyerWaitingForRefundConfirmations),
				Some(StateId::BuyerWaitingForRefundConfirmations),
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let btc_state_prerefund = btc_nc.get_state();

			let res = buyer.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			assert_eq!(
				res.action.unwrap().get_id_str(),
				"WaitForSecondaryConfirmations"
			);
			assert_eq!(res.time_limit.is_none(), true);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);

			{
				// BRANCH - check if buyer can resubmit the Secondary refund transaction
				// Checking if resubmit works
				buyer.pushs();
				let cur_time = swap::get_cur_time();

				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);

				swap::set_testing_cur_time(cur_time * 61 * 5);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);
				// Changing fees, expecting to switch back to the posting
				buyer.swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(12_000);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);

				swap::set_testing_cur_time(cur_time);
				buyer.pops();
			}

			// checking retry scenarion
			let btc_state_refund_posted = btc_nc.get_state();
			btc_nc.set_state(&btc_state_prerefund);
			// no retry because of timeout
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);
			// Check be restored
			btc_nc.set_state(&btc_state_refund_posted);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			// Check that fees will not be rised
			let fee = buyer.swap.secondary_fee_units;
			btc_nc.mine_blocks_no_pending(9);
			swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			assert_eq!(fee, buyer.swap.secondary_fee_units);

			btc_nc.mine_blocks(1);
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRefundConfirmations,
				None,
				None,
				StateId::BuyerWaitingForRefundConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundConfirmations, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			{
				// BRANCH - check if buyer can't resubmit the refund transaction because it is already mined
				// Checking if resubmit works
				buyer.pushs();
				let cur_time = swap::get_cur_time();

				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);

				swap::set_testing_cur_time(cur_time * 61 * 5);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);
				// Changing fees, expecting to switch back to the posting
				buyer.swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(12_000);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);

				swap::set_testing_cur_time(cur_time);
				buyer.pops();
			}

			btc_nc.mine_blocks(BTC_CONFIRMATION);
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRefundConfirmations,
				None,
				None,
				StateId::BuyerCancelledRefunded, // Expected state before timeput
				StateId::BuyerCancelledRefunded, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerCancelledRefunded);
			assert_eq!(res.action.is_none(), true);
			assert_eq!(res.time_limit.is_none(), true);

			test_responds(
				&mut buyer,
				StateId::BuyerCancelledRefunded,
				None,
				None,
				StateId::BuyerCancelledRefunded, // Expected state before timeput
				StateId::BuyerCancelledRefunded, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerCancelledRefunded);
			assert_eq!(res.action.is_none(), true);
			assert_eq!(res.time_limit.is_none(), true);

			swap::set_testing_cur_time(time_to_restore);
			buyer.pops();
			seller.pops();
		}

		// Checking if Buyer and seller waiting for the confirmations.
		// They will wait for 30 MWC confirmations (2 are done) and 6 BTC (1 is done)
		for _btc_iter in 0..4 {
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForLockConfirmations,
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForLockConfirmations,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			nc.mine_blocks(10);
			btc_nc.mine_block();
		}

		// We are almost done here. But still waiting.
		test_responds(
			&mut buyer,
			StateId::BuyerWaitingForLockConfirmations,
			Some((
				lock_second_message_round_timelimit,
				btc_lock_time_limit + 600 * 5,
			)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		test_responds(
			&mut seller,
			StateId::SellerWaitingForLockConfirmations,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			Some(StateId::SellerWaitingForRefundHeight),
			StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
			StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		swap::set_testing_cur_time(START_TIME + 150 + 60 * 5 * 5);

		{
			// Branch - let's check of both buyer and seller will be able to switch back is chain will be cleared
			buyer.pushs();
			seller.pushs();

			nc.clean();
			btc_nc.clean();

			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForLockConfirmations,
				Some((lock_start_timelimit, btc_lock_time_limit + 600 * 5)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerPostingSecondaryToMultisigAccount, // Expected state before timeput
				StateId::BuyerCancelled,                         // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForLockConfirmations,
				Some((lock_start_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerPostingLockMwcSlate, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			seller.pops();
			buyer.pops();
			// End of the Branch
		}

		// Mine last needed blocks. That will trigger to
		nc.mine_blocks(20);
		btc_nc.mine_blocks(2);

		test_responds(
			&mut buyer,
			StateId::BuyerWaitingForLockConfirmations,
			Some((
				lock_second_message_round_timelimit,
				btc_lock_time_limit + 600 * 5,
			)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerSendingInitRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,     // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		test_responds(
			&mut seller,
			StateId::SellerWaitingForLockConfirmations,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			Some(StateId::SellerWaitingForRefundHeight),
			StateId::SellerWaitingForInitRedeemMessage, // Expected state before timeput
			StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSendingInitRedeemMessage);
		assert_eq!(res.time_limit.unwrap(), lock_second_message_round_timelimit);
		let message3 = match res.action.unwrap() {
			Action::BuyerSendInitRedeemMessage(message) => message,
			_ => panic!("Invalid action"),
		};

		{
			// BRANCH - checking thet message can be processing during confirmation step. It is fine
			seller.pushs();

			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			assert_eq!(
				seller
					.process(Input::IncomeMessage(message3.clone()), &mut secp)
					.is_ok(),
				true
			);

			seller.pops();
		}

		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForInitRedeemMessage
		);
		assert_eq!(res.time_limit.unwrap(), lock_second_message_round_timelimit);
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);

		swap::set_testing_cur_time(lock_second_message_round_timelimit - MSG_EXCHANGE_TIME);

		{
			// Branch.  At this point both Buyer and seller are still checking for locked transactions.
			// Loss any of them should switch to cancellation
			buyer.pushs();
			seller.pushs();

			// Testing mwc chain reset
			nc.clean();

			test_responds(
				&mut buyer,
				StateId::BuyerSendingInitRedeemMessage,
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)),
				Some(StateId::BuyerWaitingForLockConfirmations), // Expected state before timeput
				Some(StateId::BuyerWaitingForRefundTime),        // Expected state after timeout
				None,                                            // Acceptable message
				None,
				None,
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForRefundHeight, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message3.clone()), // Acceptable message
				None, // Reject the redeem slate while its lock input is absent.
				None,
				&mut secp,
			);
			seller.pops();
			buyer.pops();
			// ---------------------------
			buyer.pushs();
			seller.pushs();

			// Testing btc chain reset
			btc_nc.clean();

			test_responds(
				&mut buyer,
				StateId::BuyerSendingInitRedeemMessage,
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerCancelled, // Expected state before timeput
				StateId::BuyerCancelled, // Expected state after timeout
				None,
				Some(StateId::BuyerCancelled), // Expected state before timeput
				Some(StateId::BuyerCancelled), // Expected state after timeout
				None,                          // Acceptable message
				None,
				None,
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerWaitingForInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				None,
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message3.clone()), // Acceptable message
				Some(StateId::SellerWaitingForLockConfirmations),
				Some(StateId::SellerWaitingForRefundHeight),
				&mut secp,
			);
			seller.pops();
			buyer.pops();
		}

		// Normal case, message processing
		test_responds(
			&mut buyer,
			StateId::BuyerSendingInitRedeemMessage,
			Some((
				lock_second_message_round_timelimit,
				btc_lock_time_limit + 600 * 5,
			)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerSendingInitRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,     // Expected state after timeout
			None,
			Some(StateId::BuyerWaitingForRespondRedeemMessage), // Expected state before timeput
			Some(StateId::BuyerWaitingForRefundTime),           // Expected state after timeout
			None,                                               // Acceptable message
			None,
			None,
			&mut secp,
		);
		test_responds(
			&mut seller,
			StateId::SellerWaitingForInitRedeemMessage,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			Some(StateId::SellerWaitingForRefundHeight),
			StateId::SellerWaitingForInitRedeemMessage, // Expected state before timeout
			StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
			None,
			None,                   // Expected state before timeput
			None,                   // Expected state after timeout
			Some(message3.clone()), // Acceptable message
			Some(StateId::SellerSendingInitRedeemMessage),
			Some(StateId::SellerWaitingForBuyerToRedeemMwc),
			&mut secp,
		);

		// Message is already known from steps above, it is message3.
		// Finishing execution
		let res = buyer.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitingForRespondRedeemMessage
		);
		assert_eq!(res.time_limit.unwrap(), lock_second_message_round_timelimit);
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"BuyerWaitingForRedeemMessage"
		);

		// Checking send message retry
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitingForRespondRedeemMessage
		);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSendingInitRedeemMessage);
		buyer.swap.ack_msg2();
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitingForRespondRedeemMessage
		);

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		assert_eq!(
			seller
				.process(Input::IncomeMessage(message1.clone()), &mut secp)
				.is_err(),
			true
		);
		assert_eq!(
			seller
				.process(Input::IncomeMessage(message2.clone()), &mut secp)
				.is_err(),
			true
		);
		let res = seller
			.process(Input::IncomeMessage(message3.clone()), &mut secp)
			.unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);
		assert_eq!(res.time_limit.unwrap(), lock_second_message_round_timelimit);
		let message4 = match res.action.unwrap() {
			Action::SellerSendRedeemMessage(m) => m,
			_ => panic!("Invalid action"),
		};

		// Normal case, seller sends back message to buyers
		test_responds(
			&mut buyer,
			StateId::BuyerWaitingForRespondRedeemMessage,
			Some((
				lock_second_message_round_timelimit,
				btc_lock_time_limit + 600 * 5,
			)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForRespondRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,           // Expected state after timeout
			Some((
				lock_second_message_round_timelimit + REDEEM_TIME,
				btc_lock_time_limit + 600 * 5,
			)),
			None,                   // Expected state before timeput
			None,                   // Expected state after timeout
			Some(message4.clone()), // Acceptable message
			Some(StateId::BuyerRedeemMwc),
			Some(StateId::BuyerWaitingForRefundTime),
			&mut secp,
		);
		test_responds(
			&mut seller,
			StateId::SellerSendingInitRedeemMessage,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			None,
			StateId::SellerSendingInitRedeemMessage, // Expected state before timeput
			StateId::SellerWaitingForBuyerToRedeemMwc, // Expected state after timeout
			None,
			Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
			Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
			None,                                            // Acceptable message
			None,
			None,
			&mut secp,
		);

		{
			// BRANCH - what happens if chan will loose it's data
			// Checking if Buyer sneaky, reporting that message was never received. But instead it goes with redeem process.
			buyer.pushs();
			seller.pushs();

			// Testing mwc chain reset
			let nc_state = nc.get_state();

			assert_eq!(seller.swap.state, StateId::SellerSendingInitRedeemMessage);
			assert_eq!(seller.swap.message2.is_some(), false);
			assert_eq!(seller.swap.posted_msg2.is_none(), true);

			// Buyer is getting the messege but never respond back.
			let res = buyer
				.process(Input::IncomeMessage(message4.clone()), &mut secp)
				.unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
			// Still nothing happens, seller still sending the message
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);

			// Buyer posting MWC slate
			let res = buyer.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitForRedeemMwcConfirmations
			);
			// Still nothing happens, seller still sending the message
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);

			// The block is mined, so the secret can be revealed
			nc.mine_block();

			// Now seller should detect the fact that MWC are redeemed, the secret is revealed, so the message does delivered
			assert_eq!(seller.swap.posted_msg2.is_none(), true);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
			assert_eq!(seller.swap.posted_msg2.is_none(), false);

			nc.set_state(&nc_state);

			seller.pops();
			buyer.pops();
		}

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		{
			// BRANCH - what happens if chain will loose it's data
			// Loss any of them should switch to cancellation
			buyer.pushs();
			seller.pushs();

			// Testing mwc chain reset
			let nc_state = nc.get_state();
			nc.clean();

			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRespondRedeemMessage,
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				None,
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message4.clone()), // Acceptable message
				None, // Reject the completed redeem while its lock input is absent.
				None,
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerSendingInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				None,
				StateId::SellerWaitingForRefundHeight, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
				None,                                            // Acceptable message
				None,
				None,
				&mut secp,
			);

			let cur_time = swap::get_cur_time();
			swap::set_testing_cur_time(START_TIME + MSG_EXCHANGE_TIME);

			// Checking if glitch will be recoverable...
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingLockMwcSlate);

			nc.set_state(&nc_state);

			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRespondRedeemMessage
			);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);

			swap::set_testing_cur_time(cur_time);

			seller.pops();
			buyer.pops();
			// ---------------------------
			buyer.pushs();
			seller.pushs();

			// Testing btc chain reset
			let btc_state = btc_nc.get_state();
			btc_nc.clean();
			// Expected to fail because it is too late to deposit more
			let tlim = buyer.swap.get_time_mwc_redeem().unwrap();
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRespondRedeemMessage,
				Some((lock_second_message_round_timelimit, tlim)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerCancelled, // Expected state before timeput
				StateId::BuyerCancelled, // Expected state after timeout
				None,
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message4.clone()), // Acceptable message
				Some(StateId::BuyerCancelled),
				Some(StateId::BuyerCancelled),
				&mut secp,
			);

			btc_nc.set_state(&btc_state);
			btc_nc.state.lock().height -= 4;

			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRespondRedeemMessage,
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				Some((
					lock_second_message_round_timelimit,
					btc_lock_time_limit + 600 * 5,
				)),
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message4.clone()), // Acceptable message
				Some(StateId::BuyerWaitingForLockConfirmations),
				Some(StateId::BuyerWaitingForRefundTime),
				&mut secp,
			);
			test_responds(
				&mut seller,
				StateId::SellerSendingInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				None,
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
				None,                                            // Acceptable message
				None,
				None,
				&mut secp,
			);

			seller.pops();
			buyer.pops();
		}

		// processing message
		let res = seller.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);
		assert_eq!(
			res.time_limit.unwrap(),
			swap::get_cur_time()
				+ (seller
					.swap
					.refund_slate
					.slate
					.get_lock_height_check()
					.unwrap()
					.saturating_sub(nc.state.lock().height)
					* 60) as i64
		); // Time is related to refund, not to a real time...
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"SellerWaitForBuyerRedeemPublish"
		);

		// Check if send message retyr does work as expected
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);
		seller.swap.ack_msg2();
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);

		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message1.clone()), &mut secp)
				.is_err(),
			true
		);
		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message2.clone()), &mut secp)
				.is_err(),
			true
		);
		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message3.clone()), &mut secp)
				.is_err(),
			true
		);
		let res = buyer
			.process(Input::IncomeMessage(message4.clone()), &mut secp)
			.unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
		assert_eq!(
			res.time_limit.unwrap(),
			lock_second_message_round_timelimit + REDEEM_TIME
		);
		assert_eq!(res.action.unwrap().get_id_str(), "BuyerPublishMwcRedeemTx");

		// Double processing should be fine
		assert_eq!(buyer.swap.state, StateId::BuyerRedeemMwc);
		let res = buyer
			.process(Input::IncomeMessage(message4.clone()), &mut secp)
			.unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

		test_responds(
			&mut buyer,
			StateId::BuyerRedeemMwc,
			Some((
				lock_second_message_round_timelimit + REDEEM_TIME,
				btc_lock_time_limit + 600 * 5,
			)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerRedeemMwc,            // Expected state before timeput
			StateId::BuyerWaitingForRefundTime, // Expected state after timeout
			None,
			Some(StateId::BuyerWaitForRedeemMwcConfirmations), // Expected state before timeput
			Some(StateId::BuyerWaitingForRefundTime),          // Expected state after timeout
			None,
			None,
			None,
			&mut secp,
		);
		test_responds(
			&mut seller,
			StateId::SellerWaitingForBuyerToRedeemMwc,
			Some((lock_second_message_round_timelimit + REDEEM_TIME, -1)), // timeout if possible
			None,                                                          // Non cancellable
			StateId::SellerWaitingForBuyerToRedeemMwc,                     // Expected state before timeput
			StateId::SellerWaitingForBuyerToRedeemMwc,                     // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // NOT CANCELLABLE by time, will check about the height
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		{
			// Publish the buyer's redeem before the refund unlocks, then remove it
			// and explore competing redeem/refund branches near the refund height.
			// The buyer must pause for a mined refund and resume recovery if a reorg
			// removes it, while the seller continues its own recovery workflow.
			buyer.pushs();
			seller.pushs();
			let branch_time = swap::get_cur_time();
			let chain_before_redeem = nc.get_state();
			// Recovery near the refund height requires an earlier publication.
			// Publish within the safe window, then simulate losing that transaction.
			let res = buyer.process(Input::Execute, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitForRedeemMwcConfirmations);
			nc.set_state(&chain_before_redeem);
			swap::set_testing_cur_time(branch_time + 301);
			let res = buyer.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

			let lock_height = seller
				.swap
				.refund_slate
				.slate
				.get_lock_height_check()
				.unwrap();

			let need_blocks = lock_height - nc.state.lock().height - 1;
			nc.mine_blocks(need_blocks);

			seller.pushs();
			// Close to the lock, still waiting for buyer to publish
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerToRedeemMwc,
				Some((lock_second_message_round_timelimit + REDEEM_TIME, -1)), // timeout if possible
				None,                                                          // Non cancellable
				StateId::SellerWaitingForBuyerToRedeemMwc,                     // Expected state before timeput
				StateId::SellerWaitingForBuyerToRedeemMwc,                     // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // NOT CANCELLABLE by time, will check about the height
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			nc.mine_blocks(2);
			// can redeem, switching
			test_responds(
				&mut seller,
				StateId::SellerWaitingForBuyerToRedeemMwc,
				Some((lock_second_message_round_timelimit + REDEEM_TIME, -1)), // timeout if possible
				None,                                                          // Non cancellable
				StateId::SellerPostingRefundSlate,                             // Expected state before timeput
				StateId::SellerPostingRefundSlate,                             // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // NOT CANCELLABLE by time, will check about the height
				None, // Acceptable message
				None,
				None,
				&mut secp,
			);
			seller.pops();

			// Let's do many switches with reorgs. will see what happens
			nc.mine_blocks(2);

			let nc_state_ready = nc.get_state();
			let btc_state_ready = btc_nc.get_state();

			{
				buyer.pushs();
				// ----------------------------------------------------
				// Try scenario: Buyer does redeem. It rolled back, so it will retry.
				//    Seller does nothing
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

				let res = buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				// Check retry at the same block...
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				assert_eq!(buyer.process(Input::Execute, &mut secp).is_err(), true); // For test node, repost doesn't work by some reasons
																		 // We should be good now
				nc.mine_block();
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				let state_with_redeem = nc.get_state();

				// Do roll back
				nc.set_state(&nc_state_ready);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				// Switch to exist data
				nc.set_state(&state_with_redeem);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				// Do roll back & publish
				nc.set_state(&nc_state_ready);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				let res = buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				buyer.pops();
			}

			test_swap_ser(&seller.swap);
			test_swap_ser(&buyer.swap);

			{
				seller.pushs();
				// ----------------------------------------------------
				// Try scenario: Do Refund with reties. Buyer does nothing.
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcRefundTx");
				assert_eq!(res.time_limit.is_none(), true);
				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);
				assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
				assert_eq!(res.time_limit.is_none(), true);
				// Let's do retry cycle. for the post
				// Still waiting, no retry
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);
				match res.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, MWC_CONFIRMATION);
						assert_eq!(actual, 0);
					}
					_ => panic!("Invalid action"),
				};
				assert_eq!(res.time_limit.is_none(), true);
				// Retry should be triggered.
				swap::set_testing_cur_time(swap::get_cur_time() + 6 * 60);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				nc.mine_blocks(2);
				// Now transaction is visible, we don't need to repost any more. Let's check how we handle that.
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);
				match res.action.unwrap() {
					Action::WaitForMwcConfirmations {
						name: _,
						required,
						actual,
					} => {
						assert_eq!(required, MWC_CONFIRMATION);
						assert_eq!(actual, 2);
					}
					_ => panic!("Invalid action"),
				};
				//let nc_state_refund = nc.get_state();
				// Let's simulate the reog
				nc.set_state(&nc_state_ready);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				seller.pops();
			}

			// -----------------------------------
			// Scenario where Buyer posting redeem transaction.
			// Then rewind it.
			// Seller should try to get both BTC and MWC refund
			{
				buyer.pushs();
				seller.pushs();
				let res = buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
				assert_eq!(res.time_limit.is_none(), true);
				// Seller doesn't see the transaction yet
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				nc.mine_blocks(1);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);

				// Let's mwc chain to loos all data, it shoudn't affect anything at that stage
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				// Check if refund was posted...
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);

				// Clear and retry if posted
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);

				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);

				btc_nc.mine_blocks(BTC_CONFIRMATION + 1);
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);

				// At complete step - there is no more retry
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				seller.pops();
				buyer.pops();
			}

			test_swap_ser(&seller.swap);
			test_swap_ser(&buyer.swap);

			{
				// Scenario. Seller publishing Refund, rollback and Buyer publishing redeem.
				// Rollback and Seller publishing Refund and does redeem.
				// Rollback and Buyer publishing redeem.
				// Both party need to finish the deal as expected.
				buyer.pushs();
				seller.pushs();

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				nc.mine_block();
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerWaitingForMwcRefundConfirmations);
				// A mined refund suspends submission instead of attempting a double spend.
				let posts = nc.state.lock().post_calls;
				buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(nc.state.lock().post_calls, posts);

				// let's rollback. So buyer can publish...
				// Validate seller retry logic first...
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);

				// Interruption at SellerPostingRefundSlate
				{
					buyer.pushs();
					seller.pushs();

					let time = swap::get_cur_time();
					nc.set_state(&nc_state_ready);
					nc.mine_blocks(2);

					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);

					// The reorg removed the refund, so Check must release the buyer
					// from refund waiting and allow its exposed redeem to be retried.
					let res = buyer.process(Input::Check, &mut secp).unwrap();
					assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
					let res = buyer.process(Input::Execute, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::BuyerWaitForRedeemMwcConfirmations
					);

					nc.mine_block();

					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
					let res = seller.process(Input::Execute, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);

					// Checking seller retry logic for Secondary redeem
					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					// reset data
					let btc_state_posted = btc_nc.get_state();
					btc_nc.set_state(&btc_state_ready);
					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					// timeout is over, shold switch to post state
					swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
					// let's recover the network.
					btc_nc.set_state(&btc_state_posted);
					let res = seller.process(Input::Check, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					btc_nc.mine_block();
					let res = buyer.process(Input::Check, &mut secp).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::BuyerWaitForRedeemMwcConfirmations
					);

					swap::set_testing_cur_time(time);
					seller.pops();
					buyer.pops();
				}

				swap::set_testing_cur_time(swap::get_cur_time() - 60 * 6);

				nc.set_state(&nc_state_ready);
				nc.mine_blocks(2);

				// Interruption at SellerWaitingForRefundConfirmations and continue
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				// Restoring the branch before the refund must also restore the
				// buyer's ability to retry while the seller is waiting to retry.
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				let res = buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				nc.mine_block();

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				// Another rollback. Now Seller can redeem the BTC
				nc.set_state(&nc_state_ready);
				btc_nc.set_state(&btc_state_ready);
				nc.mine_blocks(2);

				// Checking if redeem timeout works
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);

				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				// Checking that seller can redeem both BTC and MWC
				nc.mine_blocks(1);
				assert_eq!(
					nc.get_kernel(
						&seller
							.swap
							.refund_slate
							.slate
							.tx_or_err()
							.unwrap()
							.body
							.kernels[0]
							.excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);
				// The secret is already exposed. Pause while the competing refund
				// confirms, retaining recovery if that refund is reorganized away.
				let buyer_before_retry = buyer.swap.clone();
				let btc_state_redeemed = btc_nc.get_state();
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerWaitingForMwcRefundConfirmations);
				assert!(!buyer.is_cancellable());
				assert!(buyer.process(Input::Cancel, &mut secp).is_err());
				let posts = nc.state.lock().post_calls;
				buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(nc.state.lock().post_calls, posts);

				// Restore the chains before both seller spends for another retry.
				buyer.swap = buyer_before_retry;
				nc.set_state(&nc_state_ready);
				btc_nc.set_state(&btc_state_ready);
				nc.mine_blocks(2);

				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				let res = buyer.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				// Rebroadcast the seller's BTC redemption on the restored chain.
				for tx in btc_state_redeemed.pending.values() {
					btc_nc.post_transaction(tx).unwrap();
				}
				nc.mine_block();
				btc_nc.mine_block();

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				let res = buyer.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				seller.pops();
				buyer.pops();
			}

			seller.pops();
			buyer.pops();
			swap::set_testing_cur_time(branch_time);
			// END of branch
		}

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		// Now let's finish with happy path
		// At this point Buyer Can reed, seller is waiting for this moment

		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);

		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

		// Let's buyer to redeem
		let res = buyer.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitForRedeemMwcConfirmations
		);
		assert_eq!(res.time_limit.is_none(), true);
		assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");

		// Double processing should be fine
		assert_eq!(
			buyer.swap.state,
			StateId::BuyerWaitForRedeemMwcConfirmations
		);
		let res = buyer
			.process(Input::IncomeMessage(message4.clone()), &mut secp)
			.unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitForRedeemMwcConfirmations
		);

		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);
		// Seller doesn't see the transaction yet
		// !!!! Here cancellation branch is not tested because it depend on chain height. That was test above
		test_responds(
			&mut seller,
			StateId::SellerWaitingForBuyerToRedeemMwc,
			None,                                      // timeout if possible
			None,                                      // Non cancellable
			StateId::SellerWaitingForBuyerToRedeemMwc, // Expected state before timeput
			StateId::SellerWaitingForBuyerToRedeemMwc, // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // NOT CANCELLABLE by time, will check about the height
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		nc.mine_block();

		test_responds(
			&mut buyer,
			StateId::BuyerWaitForRedeemMwcConfirmations,
			None, // timeout if possible
			None,
			StateId::BuyerWaitForRedeemMwcConfirmations, // Expected state before timeput
			StateId::BuyerWaitForRedeemMwcConfirmations, // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None,
			None,
			None,
			&mut secp,
		);
		// Seller does see the transaction from buyer
		test_responds(
			&mut seller,
			StateId::SellerWaitingForBuyerToRedeemMwc,
			None,                                   // timeout if possible
			None,                                   // Non cancellable
			StateId::SellerRedeemSecondaryCurrency, // Expected state before timeput
			StateId::SellerRedeemSecondaryCurrency, // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // NOT CANCELLABLE by time, will check about the height
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
		test_responds(
			&mut seller,
			StateId::SellerRedeemSecondaryCurrency,
			None,                                   // timeout if possible
			None,                                   // Non cancellable
			StateId::SellerRedeemSecondaryCurrency, // Expected state before timeput
			StateId::SellerRedeemSecondaryCurrency, // Expected state after timeout
			None,
			Some(StateId::SellerWaitingForRedeemConfirmations), // Expected state before timeput
			Some(StateId::SellerWaitingForRedeemConfirmations), // NOT CANCELLABLE by time, will check about the height
			None,                                               // Acceptable message
			None,
			None,
			&mut secp,
		);

		let res = seller.process(Input::Execute, &mut secp).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForRedeemConfirmations
		);
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"WaitForSecondaryConfirmations"
		);
		assert_eq!(res.time_limit.is_none(), true);

		{
			// BRANCH - check if seller can resubmit the Secondary transaction
			// Checking if resubmit works
			seller.pushs();
			let cur_time = swap::get_cur_time();

			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);

			swap::set_testing_cur_time(cur_time + 61 * 5);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);
			// Changing fees, expecting to switch back to the posting
			seller.swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(12_000);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);

			swap::set_testing_cur_time(cur_time);
			seller.pops();
		}

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		{
			// BRANCH - check if seller's fee will be updated if Tx in mem pool for 5+ blocks
			// Checking if resubmit works
			seller.pushs();

			let cur_time = swap::get_cur_time();

			for _i in 0..3 {
				let cur_time = swap::get_cur_time();
				let start_fee = seller.swap.secondary_fee_units;

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);

				btc_nc.mine_blocks_no_pending(3);
				swap::set_testing_cur_time(cur_time + 60 * 3);
				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				assert_eq!(
					start_fee,
					seller
						.swap
						.secondary_data
						.unwrap_btc()
						.unwrap()
						.tx_fee_units
						.unwrap()
				);

				// Exactly 5 - still ok
				btc_nc.mine_blocks_no_pending(2);
				swap::set_testing_cur_time(cur_time + 60 * 1);
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				assert_eq!(
					start_fee,
					seller
						.swap
						.secondary_data
						.unwrap_btc()
						.unwrap()
						.tx_fee_units
						.unwrap()
				);

				// 6 blocks - should trigger fees changes...
				btc_nc.mine_block_no_pending();

				let res = seller.process(Input::Check, &mut secp).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				let updated_fee = seller.swap.secondary_fee_units;
				assert_ne!(start_fee, updated_fee);
				let proportional_fee = seller
					.swap
					.secondary_currency
					.bump_secondary_fee(
						start_fee,
						state::SECONDARY_INCREASE_FEE_NUMERATOR,
						state::SECONDARY_INCREASE_FEE_DENOMINATOR,
					)
					.unwrap();
				assert_eq!(
					match (start_fee, proportional_fee) {
						(
							SecondaryFeeUnits::RatePerKvb(start),
							SecondaryFeeUnits::RatePerKvb(bumped),
						) => SecondaryFeeUnits::RatePerKvb(
							bumped.max(start + state::SECONDARY_MIN_FEE_INCREASE_PER_KVB),
						),
						_ => panic!("Expected BTC fee rates"),
					},
					updated_fee
				);

				let res = seller.process(Input::Execute, &mut secp).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				assert_eq!(
					seller.swap.secondary_fee_units,
					seller
						.swap
						.secondary_data
						.unwrap_btc()
						.unwrap()
						.tx_fee_units
						.unwrap()
				);
			}

			swap::set_testing_cur_time(cur_time);
			seller.pops();
		}

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		// Both party waiting for confirmations
		nc.mine_blocks(MWC_CONFIRMATION / 2);
		btc_nc.mine_blocks(BTC_CONFIRMATION / 2);
		test_responds(
			&mut buyer,
			StateId::BuyerWaitForRedeemMwcConfirmations,
			None, // timeout if possible
			None,
			StateId::BuyerWaitForRedeemMwcConfirmations, // Expected state before timeput
			StateId::BuyerWaitForRedeemMwcConfirmations, // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None,
			None,
			None,
			&mut secp,
		);

		test_responds(
			&mut seller,
			StateId::SellerWaitingForRedeemConfirmations,
			None,                                         // timeout if possible
			None,                                         // Non cancellable
			StateId::SellerWaitingForRedeemConfirmations, // Expected state before timeput
			StateId::SellerWaitingForRedeemConfirmations, // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // NOT CANCELLABLE by time, will check about the height
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		{
			// BRANCH - check if seller unable to resubmit the Secondary transaction. It is already mined
			// Checking if resubmit works
			seller.pushs();
			let cur_time = swap::get_cur_time();

			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);

			swap::set_testing_cur_time(cur_time * 61 * 5);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);
			// Changing fees, because Tx is already mined, nothing should happen
			seller.swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(12_000);
			let res = seller.process(Input::Check, &mut secp).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);

			swap::set_testing_cur_time(cur_time);
			seller.pops();
		}

		// Mine more, and all must be happy now
		nc.mine_blocks(MWC_CONFIRMATION / 2 + 1);
		btc_nc.mine_blocks(BTC_CONFIRMATION / 2 + 1);

		test_responds(
			&mut buyer,
			StateId::BuyerWaitForRedeemMwcConfirmations,
			None, // timeout if possible
			None,
			StateId::BuyerSwapComplete, // Expected state before timeput
			StateId::BuyerSwapComplete, // Expected state after timeout
			None,
			None,
			None,
			None,
			None,
			None,
			&mut secp,
		);

		test_responds(
			&mut seller,
			StateId::SellerWaitingForRedeemConfirmations,
			None,                        // timeout if possible
			None,                        // Non cancellable
			StateId::SellerSwapComplete, // Expected state before timeput
			StateId::SellerSwapComplete, // Expected state after timeout
			None,
			None,
			None,
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);

		// Final step
		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
		assert_eq!(res.action.is_none(), true);
		assert_eq!(res.time_limit.is_none(), true);

		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSwapComplete);
		assert_eq!(res.action.is_none(), true);
		assert_eq!(res.time_limit.is_none(), true);

		let res = seller.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
		let res = buyer.process(Input::Check, &mut secp).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSwapComplete);

		test_responds(
			&mut buyer,
			StateId::BuyerSwapComplete,
			None, // timeout if possible
			None,
			StateId::BuyerSwapComplete, // Expected state before timeput
			StateId::BuyerSwapComplete, // Expected state after timeout
			None,
			None,
			None,
			None,
			None,
			None,
			&mut secp,
		);

		test_responds(
			&mut seller,
			StateId::SellerSwapComplete,
			None,                        // timeout if possible
			None,                        // Non cancellable
			StateId::SellerSwapComplete, // Expected state before timeput
			StateId::SellerSwapComplete, // Expected state after timeout
			None,
			None,
			None,
			None, // Acceptable message
			None,
			None,
			&mut secp,
		);

		test_swap_ser(&seller.swap);
		test_swap_ser(&buyer.swap);
	}

	// Address parsing and generation adopted at bitcoin library. Here are the tests
	// Note!!! Add addresses are temprary, Dev team doesn't have any access to them.
	// If you send anything there, you will lost those funds.
	#[test]
	fn test_bitcoin_lib_address_parsing() {
		// BTC addresses

		// mainnet, segwit
		let address = Address::new_btc()
			.from_str("bc1q9p6etejnpzvwkkyt9qcl94hvd8tzwwq6afjyk3")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wpkh);
		assert_eq!(
			address.to_string(),
			"bc1q9p6etejnpzvwkkyt9qcl94hvd8tzwwq6afjyk3"
		);

		// mainnet, pk hash (Legacy address)
		let address = Address::new_btc()
			.from_str("1KN4Q4czMUro6vTJU7b4PBJECreWCEB6Uq")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "1KN4Q4czMUro6vTJU7b4PBJECreWCEB6Uq");

		// mainnet, multisig (Legacy)
		let address = Address::new_btc()
			.from_str("3N732nEbUkmYWGmHXcYE4GZnV9kDHydAWn")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "3N732nEbUkmYWGmHXcYE4GZnV9kDHydAWn");

		// mainnet, multisig (Segwit)
		let address = Address::new_btc()
			.from_str("bc1qpc59yxhkf46scr0jy690sv0xj3edvufgf356zxqrn6ltawf3x0kq0llant")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wsh);
		assert_eq!(
			address.to_string(),
			"bc1qpc59yxhkf46scr0jy690sv0xj3edvufgf356zxqrn6ltawf3x0kq0llant"
		);

		// testnet, segwit
		let address = Address::new_btc()
			.from_str("tb1q90vsej82xcy7cn9wexggvy6gtqees0w8ngj7z0")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wpkh);
		assert_eq!(
			address.to_string(),
			"tb1q90vsej82xcy7cn9wexggvy6gtqees0w8ngj7z0"
		);

		// testnet, pk hash (Legacy address)
		let address = Address::new_btc()
			.from_str("mowAPBbAdbkiNDzNDsYUPtYzTN2Zvz6JqT")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "mowAPBbAdbkiNDzNDsYUPtYzTN2Zvz6JqT");

		// testnet, multisig (Legacy)
		let address = Address::new_btc()
			.from_str("2N58JuGyrj1A9hKUKK6srqMUR3GFwtLoRem")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "2N58JuGyrj1A9hKUKK6srqMUR3GFwtLoRem");

		// testnet, multisig (Segwit)
		let address = Address::new_btc()
			.from_str("tb1qc3gjhdpnnc5lg5aqy2xqkpwnlqtsv98503957te787pwt36v6l4s6d3xua")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wsh);
		assert_eq!(
			address.to_string(),
			"tb1qc3gjhdpnnc5lg5aqy2xqkpwnlqtsv98503957te787pwt36v6l4s6d3xua"
		);

		// BCH - skipped, not coveted with bitcoin library. BCH are very different and there are another library to work with them

		// LTC

		// testnet, segwit
		let address = Address::new_ltc()
			.from_str("tltc1qvh2vseq03wyyk8e7fj245p49uw7lxph0yjq07x")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wpkh);
		assert_eq!(
			address.to_string(),
			"tltc1qvh2vseq03wyyk8e7fj245p49uw7lxph0yjq07x"
		);

		// testnet, pk hash (Legacy address)
		let address = Address::new_ltc()
			.from_str("mpQgPACKj4AVDa89xvwDrjRietyQG4Lzgg")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "mpQgPACKj4AVDa89xvwDrjRietyQG4Lzgg");

		// testnet, multisig (Legacy)
		let address = Address::new_ltc()
			.from_str("QUFqWUwTb7XsugzZkie6BQzaSRFVJWWXG7")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "QUFqWUwTb7XsugzZkie6BQzaSRFVJWWXG7");

		// testnet, multisig (Segwit)
		let address = Address::new_ltc()
			.from_str("tltc1q3ye4xgaqn0h6zttxne88fuv8zkzepst54udqr73jhmra8fsuxgfqgxfzsk")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wsh);
		assert_eq!(
			address.to_string(),
			"tltc1q3ye4xgaqn0h6zttxne88fuv8zkzepst54udqr73jhmra8fsuxgfqgxfzsk"
		);

		// mainnet, segwit
		let address = Address::new_ltc()
			.from_str("ltc1q9p6etejnpzvwkkyt9qcl94hvd8tzwwq6e4gqwp")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wpkh);
		assert_eq!(
			address.to_string(),
			"ltc1q9p6etejnpzvwkkyt9qcl94hvd8tzwwq6e4gqwp"
		);

		// mainnet, pk hash (Legacy address)
		let address = Address::new_ltc()
			.from_str("LPNrdDV83eDbEQGn34p16A6MiZk3uFj5Nw")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "LPNrdDV83eDbEQGn34p16A6MiZk3uFj5Nw");

		// mainnet, multisig (Legacy)
		let address = Address::new_ltc()
			.from_str("MNyckn2AK1uw2HLccnSbHPmZe92hAyTifB")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "MNyckn2AK1uw2HLccnSbHPmZe92hAyTifB");

		// mainnet, multisig (Segwit)
		let address = Address::new_ltc()
			.from_str("ltc1qh60u6pfxvxhllspvxcnx2894m69vgr262840m4zljdg9ww28aazs9rll7j")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2wsh);
		assert_eq!(
			address.to_string(),
			"ltc1qh60u6pfxvxhllspvxcnx2894m69vgr262840m4zljdg9ww28aazs9rll7j"
		);

		// DASH

		// Mainnet, pk (Legacy)
		let address = Address::new_dash()
			.from_str("XbgxFwr9UvsUSWhr9zMMvBChKw4aaFryeW")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "XbgxFwr9UvsUSWhr9zMMvBChKw4aaFryeW");

		// mainnet, multisig (Legacy)
		let address = Address::new_dash()
			.from_str("7iFKZHTR2R19ie6yn6CZvEqrhJA2HFutmK")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "7iFKZHTR2R19ie6yn6CZvEqrhJA2HFutmK");

		// Testnet, pk (Legacy)
		let address = Address::new_dash()
			.from_str("yY9X94xxyGbCocayg4QCxYrXgkLrQfpNkK")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "yY9X94xxyGbCocayg4QCxYrXgkLrQfpNkK");

		// testnet, multisig (Legacy)
		let address = Address::new_dash()
			.from_str("8kGdHo4UhmQ9dmayTBtZNJUf972z58SmEc")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "8kGdHo4UhmQ9dmayTBtZNJUf972z58SmEc");

		// ZCash
		// For ZCash we are supporting only transaparrent addresses. It shouldbe enough for swaps.

		// mainnnet, pk (Legacy)
		let address = Address::new_zec()
			.from_str("t1bU6mLTSoBTJ6LmM3SNwjnU211xqHNpfgk")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "t1bU6mLTSoBTJ6LmM3SNwjnU211xqHNpfgk");

		// mainnet, multisig (Legacy)
		let address = Address::new_zec()
			.from_str("t3XyYW8yBFRuMnfvm5KLGFbEVz25kckZXym")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "t3XyYW8yBFRuMnfvm5KLGFbEVz25kckZXym");

		// testnet, pk (Legacy)
		let address = Address::new_zec()
			.from_str("tmLaEMAHxJjNhFcZWNmdB8HWnyfkdVe2Pfd")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "tmLaEMAHxJjNhFcZWNmdB8HWnyfkdVe2Pfd");

		// Testnet, multisig (Legacy)
		let address = Address::new_zec()
			.from_str("t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v");

		// Dogecoin

		// mainnet, pk (Legacy)
		let address = Address::new_doge()
			.from_str("D5cvREcimMb1uRKVEUYoCzjdE5b2D8HsRP")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "D5cvREcimMb1uRKVEUYoCzjdE5b2D8HsRP");

		// mainnet, multisig (Legacy)
		let address = Address::new_doge()
			.from_str("9v7AhpobcssNGwBaJEgCm26KJgwi8yTsbo")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Bitcoin
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "9v7AhpobcssNGwBaJEgCm26KJgwi8yTsbo");

		// testnet, pk (Legacy)
		let address = Address::new_doge()
			.from_str("nnkguAAdJP1Aco6818knbvpCLtGgywXZdT")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "nnkguAAdJP1Aco6818knbvpCLtGgywXZdT");
		let address = Address::new_doge()
			.from_str("nYAVBkVii35TVtz7SxqSn6XpTGBbdDkhja")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2pkh);
		assert_eq!(address.to_string(), "nYAVBkVii35TVtz7SxqSn6XpTGBbdDkhja");

		// testnet, multisig (Legacy)
		let address = Address::new_doge()
			.from_str("2MsQug2PDbor2ndqYu9MxMij3MZFZ3EkGk9")
			.unwrap();
		assert_eq!(
			address.network,
			bitcoin_lib::network::constants::Network::Testnet
		);
		assert_eq!(address.address_type().unwrap(), AddressType::P2sh);
		assert_eq!(address.to_string(), "2MsQug2PDbor2ndqYu9MxMij3MZFZ3EkGk9");
	}

	// Manual test that is used to test if workflow from the secondary currencies works.
	// Since we need to support many combinations, it is easier to have the semiautomatic test.
	// Note: Test is expected to run against real ElectrumX & Nodes. The point of that test is to verify is
	//   everything works with real blockchain
	// The workflow ends at the BTC redeem/refund state. No needs to finish with MWC part of swap
	#[test]
	#[ignore]
	fn test_btc_chain_ops() {
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);

		let kc_sell = keychain(&secp, 1);
		let ctx_sell = context_sell(&secp, &kc_sell);
		// Currently that network operations you are tesitng and Redeem address on your tesntnet wallet.
		let currency = Currency::Btc;
		let secondary_redeem_address = "tb1qp6a3fc7fryx6s9tvhnsy96x57gmmu3j90a9hwe".to_string();
		// BTC amount in satoshi
		let btc_amount = 10_000;
		let mwc_amount = MWC_UNIT; // 1 mwc is fine

		let nc = TestNodeClient::new(300_000);
		nc.add_seller_inputs(&secp, &kc_sell, &ctx_sell);

		let mut secondary_currency_node_client1 = ElectrumNodeClient::new(
			"btc.test1.swap.mwc.mw:18339".to_string(),
			currency.get_block1_tx_hash(!global::is_mainnet(0)),
		);
		let secondary_currency_node_client2 = ElectrumNodeClient::new(
			"btc.test2.swap.mwc.mw:18339".to_string(),
			currency.get_block1_tx_hash(!global::is_mainnet(0)),
		);

		{
			// Check the client...
			let h = secondary_currency_node_client1.height().unwrap();
			println!("The blockchain height {}", h);
		}

		let electumx_client1 = Arc::new(Mutex::new(secondary_currency_node_client1));
		let electumx_client2 = Arc::new(Mutex::new(secondary_currency_node_client2));
		let mut swap_api = BtcSwapApi::new(
			0,
			currency.clone(),
			Arc::new(nc.clone()),
			electumx_client1,
			electumx_client2,
		);

		//let swap_api_sa : & SwapApi<ExtKeychain> = &swap_api as &SwapApi<ExtKeychain>;

		let mut swap_sell = swap_api
			.create_swap_offer(
				&mut secp,
				&kc_sell,
				&ctx_sell,
				300_000,
				mwc_amount,
				btc_amount,
				currency.clone(),
				secondary_redeem_address.clone(),
				true, // lock MWC first
				1,
				1,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(false),
				false,
				None,
			)
			.unwrap();

		nc.mine_blocks(2);
		for input in swap_sell
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			nc.push_output(input.unwrap());
		}

		let kc_buy = keychain(&secp, 2);
		let ctx_buy = context_buy(&secp, &kc_buy);

		let sec_update = swap_api
			.build_offer_message_secondary_update(&kc_sell, &mut swap_sell)
			.unwrap();
		let offer_message = SellApi::offer_message(0, &swap_sell, sec_update.clone()).unwrap();

		let (uuid, offer_update, secondary_update) = offer_message.unwrap_offer().unwrap();

		let mut swap_buy = BuyApi::accept_swap_offer(
			0,
			&mut secp,
			None,
			&kc_buy,
			&ctx_buy,
			uuid,
			offer_update,
			secondary_update,
			&nc,
		)
		.unwrap();

		let sec_update = swap_api
			.build_accept_offer_message_secondary_update(&kc_buy, &mut swap_buy)
			.unwrap();
		let accept_offer_message = BuyApi::accept_offer_message(&swap_buy, sec_update).unwrap();

		let (_uuid, accept_offer_update, secondary_update) =
			accept_offer_message.unwrap_accept_offer().unwrap();
		let btc_update = secondary_update
			.unwrap_btc()
			.unwrap()
			.unwrap_accept_offer()
			.unwrap();
		SellApi::accepted_offer(
			0,
			&mut secp,
			&kc_sell,
			&mut swap_sell,
			&ctx_sell,
			accept_offer_update,
			&nc,
		)
		.unwrap();
		let btc_data = swap_sell.secondary_data.unwrap_btc_mut().unwrap();
		btc_data.accepted_offer(btc_update).unwrap();

		// Locking MWC
		swap::publish_transaction(
			0,
			&mut secp,
			&nc,
			&swap_sell.lock_slate.slate.tx_or_err().unwrap(),
			false,
		)
		.unwrap();
		nc.mine_blocks(2);

		// Generatring lock address as get_secondary_lock_address does
		/*let input_script = swap_api.script(&swap_buy).unwrap();
		let adrress = swap_buy.secondary_data.unwrap_btc().unwrap().address(
			swap_sell.secondary_currency,
			&input_script,
			swap_sell.network,
		).unwrap();*/

		let lock_address = (&swap_api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&swap_buy, &secp)
			.unwrap();
		//let lock_address = swap_api.get_secondary_lock_address(&swap_buy).unwrap();
		println!(
			"Lock address: {}. please deposit {} {} and press Enter",
			lock_address[0],
			currency.amount_to_hr_string(btc_amount, true),
			currency
		);

		if true {
			// Here Byer can do a refund. In case of test, the refund time is already here
			swap_buy.update_secondary_address(secondary_redeem_address.clone());
			swap_api
				.prepare_secondary_refund(&secp, &kc_buy, &ctx_buy, &mut swap_buy)
				.unwrap();
			swap_api
				.post_secondary_refund_tx(
					&secp,
					&kc_buy,
					&ctx_buy,
					&mut swap_buy,
					Some(secondary_redeem_address.clone()),
					true,
				)
				.unwrap();
			return;
		}

		// going to redeem step...
		BuyApi::init_redeem(0, &mut secp, &kc_buy, &mut swap_buy, &ctx_buy, &nc).unwrap();
		let init_redeem_message = BuyApi::init_redeem_message(0, &swap_buy).unwrap();
		let (_uuid, init_redeem, _secondary_update) =
			init_redeem_message.unwrap_init_redeem().unwrap();
		SellApi::init_redeem(
			0,
			&mut secp,
			&kc_sell,
			&mut swap_sell,
			&ctx_sell,
			init_redeem,
			&nc,
		)
		.unwrap();

		(&swap_api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap_sell, &secp)
			.unwrap();
		let redeem_message = SellApi::redeem_message(&swap_sell).unwrap();
		let (_uuid, redeem, _secondary_update) = redeem_message.unwrap_redeem().unwrap();
		BuyApi::finalize_redeem_slate(
			0,
			&mut secp,
			&kc_buy,
			&mut swap_buy,
			&ctx_buy,
			redeem.redeem_participant,
			&nc,
		)
		.unwrap();

		swap::publish_transaction(
			0,
			&mut secp,
			&nc,
			&swap_buy.redeem_slate.slate.tx_or_err().unwrap(),
			false,
		)
		.unwrap();
		nc.mine_blocks(1);

		let found = crate::swap::fsm::seller_swap::check_mwc_redeem(&mut swap_sell, &nc).unwrap();
		assert!(found);

		// Seller does redeem
		swap_api
			.publish_secondary_transaction(&secp, &kc_sell, &mut swap_sell, &ctx_sell, true)
			.unwrap();
	}

	fn test_swap_ser(swap: &Swap) {
		let serialized = serde_json::to_vec(&swap).unwrap();
		let deserialized: Swap = serde_json::from_slice(&serialized).unwrap();

		let serialized2 = serde_json::to_vec(&deserialized).unwrap();

		assert_eq!(serialized, serialized2);
	}

	const ETH_MNEMONIC: &str = "square social wall upgrade owner flat razor across enable idea mirror autumn rescue pottery total seat confirm dizzy fabric couple reveal relief lucky session";
	const ETH_INITIATOR_PASSWORD: &str = "initiator";
	const ETH_PARTICIPANT_PASSWORD: &str = "participant";
	const ETH_ACCOUNT_PATH: &str = "m/44'/60'/0'/0";

	// Test ethereum wallet generate process
	#[test]
	fn test_eth_genwallet() {
		// initiator: for sender, 0xAB90ddDF7bdff0e4FCAB3c9bF608393a6C7e2390
		// participant: for receiver, 0x0a6d6D1f7D798cd1Ce033a3a9222b524B9d4bf0B
		let wallet = EthereumWallet::from_mnemonic::<Ropsten, English>(
			ETH_MNEMONIC,
			Some(ETH_PARTICIPANT_PASSWORD),
			ETH_ACCOUNT_PATH,
		)
		.unwrap();

		println!("test_eth_genwallet --- {}", wallet);
	}

	// Workflow: Query one hash with pending, timeout, and RPC errors, then query
	// without a hash, with an unmined receipt, and with mined status 0 and 1.
	// Expected: Client error kinds and messages survive unchanged; a missing
	// hash is rejected, an unmined receipt stays pending, and mined receipts
	// return the matching hash with false for a revert and true for success.
	#[test]
	#[serial]
	fn eth_receipt_status_preserves_client_errors_and_execution_status() {
		use super::ethereum::recovery::transaction_status;
		use mwc_wallet_util::mwc_web3::{
			self,
			types::{TransactionReceipt, H256},
		};
		let node = TestEthNodeClient::new(1);
		let hash = H256::repeat_byte(0x21);
		for error in [
			Error::EthTransactionInPending,
			Error::EthereumTimeout {
				operation: "eth_getTransactionReceipt",
				timeout_secs: 30,
			},
			Error::EthereumRpc {
				operation: "eth_getTransactionReceipt",
				source: Box::new(mwc_web3::Error::Unreachable),
			},
		] {
			let expected_kind = mem::discriminant(&error);
			let expected_message = error.to_string();
			node.receipt_results.lock().insert(hash, Err(error));
			let actual = transaction_status(&node, Some(hash), None).unwrap_err();
			assert_eq!(mem::discriminant(&actual), expected_kind);
			assert_eq!(actual.to_string(), expected_message);
		}
		assert!(matches!(
			transaction_status(&node, None, None),
			Err(Error::InvalidTxHash)
		));
		node.receipt_results.lock().insert(
			hash,
			Ok(TransactionReceipt {
				transaction_hash: hash,
				..Default::default()
			}),
		);
		assert!(matches!(
			transaction_status(&node, Some(hash), None),
			Err(Error::EthTransactionInPending)
		));
		for status in [0u64, 1] {
			node.receipt_results.lock().insert(
				hash,
				Ok(TransactionReceipt {
					transaction_hash: hash,
					block_number: Some(100.into()),
					status: Some(status.into()),
					..Default::default()
				}),
			);
			assert_eq!(
				transaction_status(&node, Some(hash), None).unwrap(),
				(hash, status == 1)
			);
		}
	}

	#[test]
	#[serial]
	fn eth_receipt_pending_allows_confirmation_polling_without_resubmission() {
		use mwc_wallet_util::mwc_web3::types::{TransactionReceipt, H256};
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 1);
		let node = TestEthNodeClient::new(1);
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(node.clone())),
		));
		let hash = H256::repeat_byte(0x21);
		for refund in [false, true] {
			let mut trade = erc20_funding_fixture(Currency::Ether, 100);
			let data = trade.secondary_data.unwrap_eth_mut().unwrap();
			if refund {
				data.refund_tx = Some(hash);
			} else {
				data.redeem_tx = Some(hash);
			}
			node.receipt_results
				.lock()
				.insert(hash, Err(Error::EthTransactionInPending));
			let confirmations = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
			assert_eq!(confirmations.secondary_redeem_conf, None);
			assert_eq!(confirmations.secondary_refund_conf, None);

			node.receipt_results.lock().insert(
				hash,
				Err(Error::EthereumTimeout {
					operation: "eth_getTransactionReceipt",
					timeout_secs: 30,
				}),
			);
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &trade),
				Err(Error::EthereumTimeout {
					operation: "eth_getTransactionReceipt",
					timeout_secs: 30
				})
			));
		}

		// Either same-nonce candidate can finalize. A missing or failed lookup for
		// the other candidate must not hide the receipt that completes the trade.
		let original = H256::repeat_byte(0x22);
		let replacement = H256::repeat_byte(0x23);
		for (refund, winner) in [
			(false, original),
			(false, replacement),
			(true, original),
			(true, replacement),
		] {
			node.finalized_receipts.lock().clear();
			node.finalized_receipts.lock().insert(winner);
			let mut trade = erc20_funding_fixture(Currency::Ether, 100);
			if !refund {
				trade.role = Role::Seller("unused".into(), 0);
			}
			let data = trade.secondary_data.unwrap_eth_mut().unwrap();
			let recovery = Some(eth_transaction_recovery_fixture(vec![
				original,
				replacement,
			]));
			if refund {
				data.refund_tx = Some(replacement);
				data.refund_recovery = recovery;
			} else {
				data.redeem_tx = Some(replacement);
				data.redeem_recovery = recovery;
			}
			for failed_lookup in [false, true] {
				for candidate in [original, replacement] {
					let receipt = if candidate == winner {
						Ok(TransactionReceipt {
							transaction_hash: candidate,
							block_number: Some(100.into()),
							status: Some(1.into()),
							..Default::default()
						})
					} else if failed_lookup {
						Err(Error::EthereumTimeout {
							operation: "eth_getTransactionReceipt",
							timeout_secs: 30,
						})
					} else {
						Err(Error::EthTransactionInPending)
					};
					node.receipt_results.lock().insert(candidate, receipt);
				}
				let confirmations = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
				assert_eq!(
					if refund {
						confirmations.secondary_refund_conf
					} else {
						confirmations.secondary_redeem_conf
					},
					Some(1)
				);
			}
			node.receipt_results
				.lock()
				.insert(original, Err(Error::EthTransactionInPending));
			node.receipt_results.lock().insert(
				replacement,
				Err(Error::EthereumTimeout {
					operation: "eth_getTransactionReceipt",
					timeout_secs: 30,
				}),
			);
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &trade),
				Err(Error::EthereumTimeout { .. })
			));
		}

		let mut trade = erc20_funding_fixture(Currency::Ether, 100);
		trade.secondary_data.unwrap_eth_mut().unwrap().lock_tx = Some(hash);
		node.receipt_results
			.lock()
			.insert(hash, Err(Error::EthTransactionInPending));
		assert!(matches!(
			api.post_secondary_lock_tx(&mut trade),
			Err(Error::EthereumTransactionRecoveryMissing(missing)) if missing == hash
		));
		assert_eq!(
			trade.secondary_data.unwrap_eth().unwrap().lock_tx,
			Some(hash)
		);
		assert!(node.tx_store.lock().is_empty());
	}

	#[test]
	#[serial]
	fn eth_failed_submission_keeps_recovery_and_retries_pending_transaction() {
		use mwc_wallet_util::mwc_web3::types::{TransactionReceipt, H256};
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		#[derive(Clone, Copy)]
		enum Operation {
			Redeem,
			Refund,
			Deposit,
		}
		use Operation::*;
		fn fields(
			data: &EthData,
			operation: Operation,
		) -> (Option<H256>, Option<&ethereum::EthTransactionRecovery>) {
			match operation {
				Redeem => (data.redeem_tx, data.redeem_recovery.as_ref()),
				Refund => (data.refund_tx, data.refund_recovery.as_ref()),
				Deposit => (data.lock_tx, data.lock_recovery.as_ref()),
			}
		}
		for (currency, operation) in [
			(Currency::Ether, Redeem),
			(Currency::Usdt, Redeem),
			(Currency::Ether, Refund),
			(Currency::Usdt, Refund),
			(Currency::Ether, Deposit),
			(Currency::Usdt, Deposit),
		] {
			// Reuse the signed MWC fixture with the buyer's redemption complete.
			let (mut trade, context, kc, nc, _) = seller_redeem_fixture(&secp);
			trade.secondary_currency = currency;
			if !matches!(operation, Redeem) {
				trade.role = Role::Buyer(None);
			}
			if matches!(operation, Deposit) {
				trade.state = StateId::BuyerPostingSecondaryToMultisigAccount;
			}
			trade.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(5_500_000);
			trade.secondary_data = erc20_funding_fixture(currency, 100).secondary_data;
			let node = TestEthNodeClient::new(1);
			node.erc20.lock().allowances.insert(
				currency,
				ethereum::funding::token_amount(currency, trade.secondary_amount).unwrap(),
			);
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
				0,
				currency,
				Arc::new(nc),
				Arc::new(Mutex::new(node.clone())),
			));
			let post = |trade: &mut Swap, post_tx| match operation {
				Refund => api.post_secondary_refund_tx(&secp, &kc, &context, trade, None, post_tx),
				Redeem => api.publish_secondary_transaction(&secp, &kc, trade, &context, post_tx),
				Deposit => api.post_secondary_lock_tx(trade),
			};
			let submission_result = match operation {
				Refund => &node.refund_result,
				Redeem => &node.redeem_result,
				Deposit => &node.initiate_result,
			};
			let original = H256::repeat_byte(0x31);
			let replacement = H256::repeat_byte(0x32);
			*submission_result.lock() = Some((
				eth_transaction_recovery_fixture(vec![original]),
				Err(Error::EthereumSubmissionTimeout {
					tx_hash: original,
					timeout_secs: 30,
				}),
			));
			if !matches!(operation, Deposit) {
				post(&mut trade, false).unwrap();
				assert!(submission_result.lock().is_some());
			}
			assert!(matches!(
				post(&mut trade, true),
				Err(Error::EthereumSubmissionTimeout { .. })
			));
			trade = serde_json::from_str(&serde_json::to_string(&trade).unwrap()).unwrap();
			let data = trade.secondary_data.unwrap_eth().unwrap();
			assert_eq!(fields(data, operation).0, Some(original));
			assert_eq!(
				fields(data, operation).1.unwrap().attempted_hashes,
				vec![original]
			);

			let before = serde_json::to_string(&trade).unwrap();
			node.receipt_results.lock().insert(
				original,
				Err(Error::EthereumTimeout {
					operation: "eth_getTransactionReceipt",
					timeout_secs: 30,
				}),
			);
			assert!(matches!(
				post(&mut trade, true),
				Err(Error::EthereumTimeout { .. })
			));
			assert_eq!(serde_json::to_string(&trade).unwrap(), before);

			// Missing receipt must reach the retry path instead of stopping forever.
			node.receipt_results
				.lock()
				.insert(original, Err(Error::EthTransactionInPending));
			let mut recovery = eth_transaction_recovery_fixture(vec![original, replacement]);
			recovery.gas_budget_gwei = 6_000_000;
			trade.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(recovery.gas_budget_gwei);
			// Even an error without a hash (e.g. worker failure) must preserve the
			// new candidate placed in recovery before submission started.
			*submission_result.lock() = Some((recovery, Err(Error::EthTransactionInPending)));
			assert!(matches!(
				post(&mut trade, true),
				Err(Error::EthTransactionInPending)
			));
			let data = trade.secondary_data.unwrap_eth().unwrap();
			assert_eq!(fields(data, operation).0, Some(replacement));
			assert_eq!(data.tx_fee_gwei, Some(6_000_000));
			assert_eq!(
				fields(data, operation).1.unwrap().attempted_hashes,
				vec![original, replacement]
			);

			let receipt = TransactionReceipt {
				transaction_hash: original,
				block_number: Some(100.into()),
				status: Some(1.into()),
				..Default::default()
			};
			node.receipt_results
				.lock()
				.insert(original, Ok(receipt.clone()));
			let mut waiting_trade = None;
			if matches!(operation, Deposit) && currency.is_erc20() {
				// Waiting trades must check all candidates too: the original can
				// succeed while the latest replacement never obtains a receipt.
				node.receipt_results
					.lock()
					.insert(replacement, Err(Error::EthTransactionInPending));
				node.erc20.lock().allowance_error = true;
				let mut sibling = erc20_funding_fixture(currency, 10);
				assert!(matches!(api.post_secondary_lock_tx(&mut sibling),
					Err(Error::Generic(message)) if message == "injected allowance RPC failure"));
				node.erc20.lock().allowance_error = false;
				waiting_trade = Some(sibling);
				node.receipt_results.lock().insert(original, Ok(receipt));
			}
			post(&mut trade, true).unwrap();
			assert_eq!(
				fields(trade.secondary_data.unwrap_eth().unwrap(), operation).0,
				Some(original)
			);
			assert!(node.tx_store.lock().is_empty());

			// Reorg after a successful receipt: keep recovery and retry even when
			// the ERC20 funding marker was already Complete and has been restored.
			trade = serde_json::from_str(&serde_json::to_string(&trade).unwrap()).unwrap();
			for hash in [original, replacement] {
				node.receipt_results
					.lock()
					.insert(hash, Err(Error::EthTransactionInPending));
			}
			let record = fields(trade.secondary_data.unwrap_eth().unwrap(), operation)
				.1
				.unwrap()
				.clone();
			*submission_result.lock() = Some((record, Err(Error::EthTransactionInPending)));
			assert!(matches!(
				post(&mut trade, true),
				Err(Error::EthTransactionInPending)
			));
			assert!(submission_result.lock().is_none());
			assert_eq!(
				fields(trade.secondary_data.unwrap_eth().unwrap(), operation).0,
				Some(replacement)
			);
			assert!(node.tx_store.lock().is_empty());
			// The existing deposit can recover while this later owner reserves
			// the allowance; release it before testing a fresh deposit below.
			if let Some(mut sibling) = waiting_trade {
				sibling.state = StateId::BuyerCancelled;
				ethereum::funding::record_swap(&sibling);
			}

			// A mined revert allows a fresh attempt; ambiguous/pending results do not.
			node.receipt_results.lock().insert(
				original,
				Ok(TransactionReceipt {
					transaction_hash: original,
					block_number: Some(100.into()),
					status: Some(0.into()),
					..Default::default()
				}),
			);
			if !matches!(operation, Deposit) {
				node.swap_store.lock().insert(
					trade
						.secondary_data
						.unwrap_eth()
						.unwrap()
						.address_from_secret
						.unwrap(),
					(1.into(), None, Default::default(), Default::default(), 100),
				);
			} else if currency.is_erc20() {
				assert!(matches!(
					post(&mut trade, true),
					Err(Error::Erc20FundingReverted(_))
				));
			}
			post(&mut trade, true).unwrap();
			assert_eq!(node.tx_store.lock().len(), 1);
			if matches!(operation, Deposit) && currency.is_erc20() {
				// New mock deposits now retain recovery just like production.
				// Explicitly construct the historical hash-only case below.
				let data = trade.secondary_data.unwrap_eth_mut().unwrap();
				let record = data.lock_recovery.take().unwrap();
				assert_eq!(record.attempted_hashes.last().copied(), data.lock_tx);
			}
			assert!(
				fields(trade.secondary_data.unwrap_eth().unwrap(), operation)
					.1
					.is_none()
			);
			let legacy_hash = fields(trade.secondary_data.unwrap_eth().unwrap(), operation)
				.0
				.unwrap();
			node.receipt_results
				.lock()
				.insert(legacy_hash, Err(Error::EthTransactionInPending));
			assert!(
				matches!(post(&mut trade, true), Err(Error::EthereumTransactionRecoveryMissing(hash)) if hash == legacy_hash)
			);
			assert_eq!(node.tx_store.lock().len(), 1);
		}
	}

	#[test]
	#[serial]
	fn eth_swap_api_uses_its_node_client_for_gas_balance() {
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(1)),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		));

		assert_eq!(
			api.ethereum_gas_balance().unwrap(),
			1_000_000_000_000_000_000
		);
	}

	fn assert_eth_slate_confirmation_requires_swap_kernel(forge_excess: bool) {
		use mwc_wallet_util::mwc_core::libtx::{build, proof};
		use mwc_wallet_util::mwc_web3::types::Address;

		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &kc);
		let seller: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_2.json")).unwrap();
		let eth_data = EthData::new(&EthSellerContext {
			redeem_address: Some(Address::repeat_byte(0x23)),
		})
		.unwrap();

		for currency in [Currency::Ether, Currency::Usdt] {
			let nc = TestNodeClient::new(300_000);
			let api = EthSwapApi::new(
				0,
				currency,
				Arc::new(nc.clone()),
				Arc::new(Mutex::new(TestEthNodeClient::new(1))),
			);
			let message = Message::from_json(include_str!("../../swap_test/message_1.json")).unwrap();
			let (id, mut offer, _) = message.unwrap_offer().unwrap();
			// Preserve the fixture's negotiated lock durations when changing currency.
			offer.secondary_confirmations *= 50; // 600-second BTC blocks / 12-second ETH slots.
			offer.secondary_currency = currency;
			offer.seller_lock_first = true;
			let mut lock = offer.lock_slate.into_slate_plain(0, true).unwrap();
			let mut refund = offer.refund_slate.into_slate_plain(0, true).unwrap();

			// Confirm a valid unrelated transaction that contains no swap output.
			let unrelated_kc = keychain(&secp, 7);
			let builder = proof::ProofBuilder::new(&secp, &unrelated_kc).unwrap();
			let unrelated = build::transaction(
				0,
				&mut secp,
				KernelFeatures::Plain {
					fee: lock.fee.try_into().unwrap(),
				},
				&[
					build::feature_input(200 * MWC_UNIT, OutputFeatures::Plain, key_id(9, 1)),
					build::height_tagged_output(
						200 * MWC_UNIT - lock.fee,
						output_key_id(2),
						lock.height,
					),
				],
				&unrelated_kc,
				&builder,
			)
			.unwrap();
			for input in unrelated.inputs_committed().unwrap() {
				nc.push_output(input.unwrap());
			}
			crate::owner::post_tx(0, &nc, &unrelated, false).unwrap();
			nc.mine_block();
			let supplied_excess = if forge_excess {
				unrelated.kernels()[0].excess
			} else {
				Commitment([0; 33])
			};
			lock.tx_or_err_mut().unwrap().body.kernels[0].excess = supplied_excess;
			refund.tx_or_err_mut().unwrap().body.kernels[0].excess = supplied_excess;
			offer.lock_slate = VersionedSlate::into_version_plain(0, &lock, SlateVersion::V3).unwrap();
			offer.refund_slate =
				VersionedSlate::into_version_plain(0, &refund, SlateVersion::V3).unwrap();
			for input in lock.tx_or_err().unwrap().inputs_committed().unwrap() {
				nc.push_output(input.unwrap());
			}

			// Run the real offer validation and signing, without a live gas-balance RPC.
			let validated = BuyApi::validate_offer_static(
				0,
				&secp,
				offer,
				SecondaryUpdate::ETH(eth_data.offer_update()),
			)
			.unwrap();
			let validated = BuyApi::validate_offer_node(0, validated, &nc).unwrap();
			let mut buyer = BuyApi::accept_validated_swap_offer(
				0, &mut secp, &kc, &context, id, validated, &nc,
			)
			.unwrap();
			for slate in [&buyer.lock_slate.slate, &buyer.refund_slate.slate] {
				assert_eq!(slate.tx_or_err().unwrap().kernels()[0].excess, supplied_excess);
				assert_ne!(slate.calc_excess(&secp).unwrap(), supplied_excess);
			}
			buyer.posted_msg1 = Some(swap::get_cur_time());
			buyer.state = StateId::BuyerWaitingForSellerToLock;
			buyer.wait_for_backup1 = false;

			// Only seller change exists; the shared lock has never been created.
			let multisig = buyer.multisig.commit(&secp).unwrap();
			let change = buyer
				.lock_slate
				.slate
				.tx_or_err()
				.unwrap()
				.outputs()
				.iter()
				.map(|output| output.commitment())
				.find(|commit| *commit != multisig)
				.unwrap();
			nc.push_output(change);
			assert!(!nc.get_state().outputs.contains_key(&multisig));
			let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
			assert_eq!(confirmations.mwc_lock_conf, None);
			assert_eq!(confirmations.mwc_refund_conf, None);
			let mut fsm = api.get_fsm(&kc, &buyer);
			let response = fsm
				.process(Input::Check, &mut buyer, &context, &confirmations, &mut secp)
				.unwrap();
			assert_eq!(response.next_state_id, StateId::BuyerWaitingForSellerToLock);
			assert!(!buyer.other_lock_first_done);

			// Real lock and refund kernels must be detected despite the stored excess.
			nc.clean();
			let lock_tx = seller.lock_slate.slate.tx_or_err().unwrap();
			for input in lock_tx.inputs_committed().unwrap() {
				nc.push_output(input.unwrap());
			}
			crate::owner::post_tx(0, &nc, lock_tx, false).unwrap();
			nc.mine_block();
			let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
			assert_eq!(confirmations.mwc_lock_conf, Some(1));
			assert_eq!(confirmations.mwc_refund_conf, None);
			let response = fsm
				.process(Input::Check, &mut buyer, &context, &confirmations, &mut secp)
				.unwrap();
			assert_eq!(
				response.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			assert!(buyer.other_lock_first_done);

			let refund_height = seller.refund_slate.slate.get_lock_height_check().unwrap();
			nc.mine_blocks(refund_height - nc.get_state().height);
			crate::owner::post_tx(0, &nc, seller.refund_slate.slate.tx_or_err().unwrap(), false)
				.unwrap();
			nc.mine_block();
			let confirmations = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
			assert_eq!(confirmations.mwc_refund_conf, Some(1));
			nc.state.lock().outputs.clear();
			let spent = api.request_tx_confirmations(&secp, &kc, &buyer).unwrap();
			assert_eq!(spent.mwc_lock_conf, confirmations.mwc_lock_conf);
			assert_eq!(spent.mwc_refund_conf, confirmations.mwc_refund_conf);
		}
	}

	#[test]
	#[serial]
	fn eth_slate_confirmation_requires_kernel() {
		assert_eth_slate_confirmation_requires_swap_kernel(false);
	}

	#[test]
	#[serial]
	fn eth_slate_confirmation_ignores_peer_supplied_excess() {
		assert_eth_slate_confirmation_requires_swap_kernel(true);
	}

	#[test]
	#[serial]
	fn eth_slate_confirmation_rejects_invalid_derivation() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let mut buyer: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json")).unwrap();
		buyer.secondary_currency = Currency::Ether;
		buyer.secondary_data = EthData::new(&EthSellerContext {
			redeem_address: None,
		})
		.unwrap()
		.wrap();
		let api = EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_002)),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		);

		for refund in [false, true] {
			let mut invalid = buyer.clone();
			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.tx_or_err_mut().unwrap().body.kernels[0].excess =
				slate.calc_excess(&secp).unwrap();
			// A nonzero excess cannot bypass body derivation or compact-slate rejection.
			slate.compact_slate = true;
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &invalid),
				Err(Error::InvalidMessageData(message)) if message.contains("non-compact slate")
			));

			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.compact_slate = false;
			slate.tx_or_err_mut().unwrap().body.outputs[0]
				.identifier
				.commit
				.0 = [0; 33];
			assert!(matches!(
				api.request_tx_confirmations(&secp, &kc, &invalid),
				Err(Error::LibWallet(_))
			));

			// An unfinished body remains pending; it is not a derivation failure.
			let slate = if refund {
				&mut invalid.refund_slate.slate
			} else {
				&mut invalid.lock_slate.slate
			};
			slate.tx_or_err_mut().unwrap().body.outputs.clear();
			let confirmations = api.request_tx_confirmations(&secp, &kc, &invalid).unwrap();
			assert_eq!(confirmations.mwc_lock_conf, None);
			assert_eq!(confirmations.mwc_refund_conf, None);
		}
	}

	#[test]
	#[serial]
	fn buyer_pending_eth_deposit_survives_cancellation_and_timeout() {
		use mwc_wallet_util::mwc_web3::types::{Address, H256, U256};
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &kc);
		for cancel in [false, true] {
			for ambiguous in [false, true] {
				for resend in [false, true] {
					let mut trade = erc20_funding_fixture(Currency::Ether, 100);
					let deadline = trade.get_time_start_lock().unwrap();
					swap::set_testing_cur_time(deadline - 1);
					trade.posted_msg1 = Some(deadline);
					let node = TestEthNodeClient::new(1);
					let hash = H256::repeat_byte(0x31);
					*node.initiate_result.lock() = Some((
						eth_transaction_recovery_fixture(vec![hash]),
						if ambiguous {
							Err(Error::EthereumSubmissionTimeout {
								tx_hash: hash,
								timeout_secs: 30,
							})
						} else {
							Ok(hash)
						},
					));
					let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
						Arc::new(TestNodeClient::new(300_000)),
						Arc::new(Mutex::new(node.clone())),
					));
					let snapshot = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
					assert_eq!(snapshot.secondary_lock_amount, 0);
					let mut fsm = api.get_fsm(&kc, &trade);
					let result =
						fsm.process(Input::Execute, &mut trade, &context, &snapshot, &mut secp);
					if ambiguous {
						assert!(matches!(
							result,
							Err(Error::EthereumSubmissionTimeout { .. })
						));
					} else {
						result.unwrap();
					}
					assert!(trade
						.secondary_data
						.unwrap_eth()
						.unwrap()
						.lock_recovery
						.is_some());
					if resend {
						// A pending deposit can fall back to message retransmission.
						trade.posted_msg1 = Some(0);
					}
					if !cancel {
						swap::set_testing_cur_time(deadline + 1);
					}
					node.receipt_results
						.lock()
						.insert(hash, Err(Error::EthTransactionInPending));
					let response = fsm
						.process(
							if cancel { Input::Cancel } else { Input::Check },
							&mut trade,
							&context,
							&snapshot,
							&mut secp,
						)
						.unwrap();
					assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
					assert!(matches!(
						response.action,
						Some(Action::WaitForSecondaryConfirmations { .. })
					));

					// Persist cancellation and restart while the deposit is still pending.
					trade = serde_json::from_str(&serde_json::to_string(&trade).unwrap()).unwrap();
					let mut fsm = api.get_fsm(&kc, &trade);
					let refund_time = trade.get_time_secondary_lock_publish().unwrap();
					swap::set_testing_cur_time(refund_time + 1);
					node.receipt_results
						.lock()
						.insert(hash, Err(Error::EthTransactionInPending));
					let response = fsm
						.process(Input::Check, &mut trade, &context, &snapshot, &mut secp)
						.unwrap();
					assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
					assert!(matches!(
						response.action,
						Some(Action::WaitForSecondaryConfirmations { .. })
					));
					assert!(node.tx_store.lock().is_empty());

					// Funding mines after both deadlines. A fresh poll must offer its refund.
					let data = trade.secondary_data.unwrap_eth().unwrap();
					node.swap_store.lock().insert(
						data.address_from_secret.unwrap(),
						(
							U256::from(1u64),
							None,
							Address::repeat_byte(0x44),
							data.redeem_address.unwrap(),
							trade.secondary_amount,
						),
					);
					let mined = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
					assert_eq!(mined.secondary_lock_amount, trade.secondary_amount);
					let response = fsm
						.process(Input::Check, &mut trade, &context, &mined, &mut secp)
						.unwrap();
					assert_eq!(
						response.next_state_id,
						StateId::BuyerPostingRefundForSecondary
					);
					assert!(matches!(
						response.action,
						Some(Action::BuyerPublishSecondaryRefundTx { .. })
					));
					fsm.process(Input::Execute, &mut trade, &context, &mined, &mut secp)
						.unwrap();
					let refund_hash = trade
						.secondary_data
						.unwrap_eth()
						.unwrap()
						.refund_tx
						.unwrap();
					node.finalized_receipts.lock().insert(refund_hash);
					let refunded = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
					let response = fsm
						.process(Input::Check, &mut trade, &context, &refunded, &mut secp)
						.unwrap();
					assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
					assert!(node.swap_store.lock().is_empty());
					assert_eq!(node.tx_store.lock().len(), 1);
				}
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_eth_refund_wait_requires_finalized_deposit_failure() {
		use mwc_wallet_util::mwc_web3::types::{TransactionReceipt, H256};
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &kc);
		for recovery_only in [false, true] {
			let mut trade = erc20_funding_fixture(Currency::Ether, 100);
			trade.state = if recovery_only {
				StateId::BuyerSendingAcceptOfferMessage
			} else {
				StateId::BuyerWaitingForSellerToLock
			};
			swap::set_testing_cur_time(trade.get_time_start_lock().unwrap() - 1);
			let node = TestEthNodeClient::new(1);
			let hash = H256::repeat_byte(0x51);
			let replacement = H256::repeat_byte(0x52);
			let data = trade.secondary_data.unwrap_eth_mut().unwrap();
			if recovery_only {
				data.lock_recovery =
					Some(eth_transaction_recovery_fixture(vec![hash, replacement]));
			} else {
				// Older trades may only retain the broadcast hash.
				data.lock_tx = Some(hash);
			}
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
				Arc::new(TestNodeClient::new(300_000)),
				Arc::new(Mutex::new(node.clone())),
			));
			let snapshot = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
			let mut fsm = api.get_fsm(&kc, &trade);
			for candidate in [hash, replacement] {
				node.receipt_results
					.lock()
					.insert(candidate, Err(Error::EthTransactionInPending));
			}
			fsm.process(Input::Cancel, &mut trade, &context, &snapshot, &mut secp)
				.unwrap();
			assert_eq!(trade.state, StateId::BuyerWaitingForRefundTime);

			// Endpoint errors are surfaced without declaring the trade finished.
			for candidate in [hash, replacement] {
				node.receipt_results
					.lock()
					.insert(candidate, Err(Error::EthRetrieveTransReciptError));
			}
			assert!(matches!(
				fsm.process(Input::Check, &mut trade, &context, &snapshot, &mut secp),
				Err(Error::EthRetrieveTransReciptError)
			));
			assert_eq!(trade.state, StateId::BuyerWaitingForRefundTime);

			for (success, finalized) in [(false, false), (true, true), (false, true)] {
				node.receipt_results.lock().insert(
					hash,
					Ok(TransactionReceipt {
						transaction_hash: hash,
						block_number: Some(1.into()),
						status: Some(u64::from(success).into()),
						..TransactionReceipt::default()
					}),
				);
				if finalized {
					node.finalized_receipts.lock().insert(hash);
				}
				let response = fsm
					.process(Input::Check, &mut trade, &context, &snapshot, &mut secp)
					.unwrap();
				let expected = if finalized && !success {
					StateId::BuyerCancelled
				} else {
					StateId::BuyerWaitingForRefundTime
				};
				assert_eq!(response.next_state_id, expected);
			}
			assert!(node.tx_store.lock().is_empty());
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_eth_without_deposit_cancels_immediately() {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &kc);
		for state in [
			StateId::BuyerPostingSecondaryToMultisigAccount,
			StateId::BuyerSendingAcceptOfferMessage,
			StateId::BuyerWaitingForSellerToLock,
		] {
			for cancel in [false, true] {
				let mut trade = erc20_funding_fixture(Currency::Ether, 100);
				trade.state = state.clone();
				let now = trade.get_time_start_lock().unwrap() + 1;
				swap::set_testing_cur_time(now);
				trade.posted_msg1 = Some(if state == StateId::BuyerSendingAcceptOfferMessage {
					0
				} else {
					now
				});
				let node = TestEthNodeClient::new(1);
				let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
					Arc::new(TestNodeClient::new(300_000)),
					Arc::new(Mutex::new(node.clone())),
				));
				let snapshot = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
				let response = api
					.get_fsm(&kc, &trade)
					.process(
						if cancel { Input::Cancel } else { Input::Check },
						&mut trade,
						&context,
						&snapshot,
						&mut secp,
					)
					.unwrap();
				assert_eq!(response.next_state_id, StateId::BuyerCancelled);
				assert!(response.action.is_none());
				assert!(node.tx_store.lock().is_empty());
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_posting_secondary_defers_until_balance_snapshot_matches() {
		use crate::swap::fsm::buyer_swap::BuyerPostingSecondaryToMultisigAccount;
		use crate::swap::fsm::state::State;

		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_buy(&secp, &kc);
		for expired in [false, true] {
			for partially_funded in [false, true] {
				for confirmed in [false, true] {
					let mut trade: Swap =
						serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))
							.unwrap();
					trade.state = StateId::BuyerPostingSecondaryToMultisigAccount;
					let deadline = trade.get_time_start_lock().unwrap();
					let now = if expired { deadline + 1 } else { deadline - 1 };
					swap::set_testing_cur_time(now);
					trade.posted_msg1 = Some(now);
					let btc_node = TestBtcNodeClient::new(500_000);
					let api = BtcSwapApi::new_test(
						Arc::new(TestNodeClient::new(300_000)),
						Arc::new(Mutex::new(btc_node.clone())),
					);
					let script_pubkey = api.script(&trade, &secp).unwrap().to_p2sh();
					let deposit = |value, tag| {
						btc_node
							.post_transaction(&BitcoinTransaction {
								version: 2,
								lock_time: tag,
								input: vec![],
								output: vec![TxOut {
									value,
									script_pubkey: script_pubkey.clone(),
								}],
							})
							.unwrap();
						if confirmed {
							btc_node.mine_blocks(trade.secondary_confirmations);
						}
					};
					let initial_amount = if partially_funded {
						trade.secondary_amount / 2
					} else {
						0
					};
					if initial_amount > 0 {
						deposit(initial_amount, 0);
					}
					let stale = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
					assert_eq!(stale.secondary_lock_amount, initial_amount);

					// Finish funding after the owner has already collected its snapshot.
					deposit(trade.secondary_amount - initial_amount, 1);
					let mut state = BuyerPostingSecondaryToMultisigAccount::new(Arc::new(
						Box::new(api.clone()) as Box<dyn SwapApi<ExtKeychain>>,
					));
					// Check the state directly first so a regression fails immediately
					// instead of hanging the test in the FSM's transition loop.
					let response = state
						.process(Input::Check, &mut trade, &context, &stale, &mut secp)
						.unwrap();
					assert_eq!(
						response.next_state_id,
						StateId::BuyerPostingSecondaryToMultisigAccount
					);
					assert!(response.action.is_none());

					let mut fsm = api.get_fsm(&kc, &trade);
					let response = fsm
						.process(Input::Check, &mut trade, &context, &stale, &mut secp)
						.unwrap();
					assert_eq!(
						response.next_state_id,
						StateId::BuyerPostingSecondaryToMultisigAccount
					);
					assert!(response.action.is_none());

					// The next owner poll refreshes the snapshot and allows progress.
					let fresh = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
					assert_eq!(fresh.secondary_lock_amount, trade.secondary_amount);
					let response = fsm
						.process(Input::Check, &mut trade, &context, &fresh, &mut secp)
						.unwrap();
					assert_eq!(
						response.next_state_id,
						StateId::BuyerWaitingForLockConfirmations
					);
					assert!(matches!(
						response.action,
						Some(Action::WaitForLockConfirmations { .. })
					));
				}
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_posting_secondary_timeout_preserves_either_balance_observation() {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_buy(&secp, &kc);
		for (snapshot_amount, chain_amount) in [
			(0, 1_000_000),
			(0, 4_000_000),
			(1_000_000, 0),
			(1_000_000, 1_000_000),
			(0, 0),
		] {
			let mut trade: Swap =
				serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json")).unwrap();
			trade.state = StateId::BuyerPostingSecondaryToMultisigAccount;
			let now = trade.get_time_start_lock().unwrap() + 1;
			swap::set_testing_cur_time(now);
			trade.posted_msg1 = Some(now);
			let btc_node = TestBtcNodeClient::new(500_000);
			let api = BtcSwapApi::new_test(
				Arc::new(TestNodeClient::new(300_000)),
				Arc::new(Mutex::new(btc_node.clone())),
			);
			let script_pubkey = api.script(&trade, &secp).unwrap().to_p2sh();
			let set_balance = |value| {
				btc_node.clean();
				if value > 0 {
					btc_node
						.post_transaction(&BitcoinTransaction {
							version: 2,
							lock_time: 0,
							input: vec![],
							output: vec![TxOut {
								value,
								script_pubkey: script_pubkey.clone(),
							}],
						})
						.unwrap();
				}
			};
			set_balance(snapshot_amount);
			let stale = api.request_tx_confirmations(&secp, &kc, &trade).unwrap();
			assert_eq!(stale.secondary_lock_amount, snapshot_amount);
			// Model propagation or disappearance between the two network reads.
			set_balance(chain_amount);
			let mut fsm = api.get_fsm(&kc, &trade);
			let response = fsm
				.process(Input::Check, &mut trade, &context, &stale, &mut secp)
				.unwrap();
			let expected = if snapshot_amount == 0 && chain_amount == 0 {
				StateId::BuyerCancelled
			} else {
				StateId::BuyerWaitingForRefundTime
			};
			assert_eq!(
				response.next_state_id, expected,
				"snapshot_amount={snapshot_amount}, chain_amount={chain_amount}"
			);
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_funding_eta_directs_ethereum_to_contract_deposit() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		for currency in [Currency::Ether, Currency::Usdt] {
			let trade = erc20_funding_fixture(currency, 100);
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
				0,
				currency,
				Arc::new(TestNodeClient::new(300_000)),
				Arc::new(Mutex::new(TestEthNodeClient::new(1))),
			));
			let trade_index = api.get_secondary_lock_address(&trade, &secp).unwrap();
			assert!(!trade_index[0].is_empty());
			let roadmap = api
				.get_fsm(&kc, &trade)
				.get_swap_roadmap(&trade, &secp)
				.unwrap();
			let eta = roadmap.iter().find(|eta| eta.active).unwrap();
			assert!(eta.name.contains("wallet"));
			assert!(eta.name.contains("swap contract"));
			assert!(eta.name.contains(&format!("swap --process -i {}", trade.id)));
			assert!(eta.name.contains(&format!("eth --info --currency {}", currency)));
			assert!(!eta.name.contains(&trade_index[0]));
			assert_eq!(eta.end_time, Some(trade.get_time_start_lock().unwrap()));
		}
	}

	#[test]
	#[serial]
	fn buyer_funding_eta_preserves_btc_addresses_and_reports_address_errors() {
		global::set_local_chain_type(ChainTypes::Floonet);
		swap::set_testing_cur_time(1567632152);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		for currency in [Currency::Btc, Currency::Bch] {
			let mut trade: Swap =
				serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json")).unwrap();
			trade.state = StateId::BuyerPostingSecondaryToMultisigAccount;
			trade.secondary_currency = currency;
			let btc_node = Arc::new(Mutex::new(TestBtcNodeClient::new(500_000)));
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(BtcSwapApi::new(
				0,
				currency,
				Arc::new(TestNodeClient::new(300_000)),
				btc_node.clone(),
				btc_node,
			));
			let addresses = api.get_secondary_lock_address(&trade, &secp).unwrap();
			let fsm = api.get_fsm(&kc, &trade);
			let roadmap = fsm.get_swap_roadmap(&trade, &secp).unwrap();
			let eta = roadmap.iter().find(|eta| eta.active).unwrap();
			assert_eq!(
				eta.name,
				format!(
					"Send {} to lock account {}",
					currency,
					addresses.join(" or ")
				)
			);
			assert_eq!(eta.end_time, Some(trade.get_time_start_lock().unwrap()));

			trade.secondary_data.unwrap_btc_mut().unwrap().refund = None;
			let error = api.get_secondary_lock_address(&trade, &secp).unwrap_err();
			let roadmap = fsm.get_swap_roadmap(&trade, &secp).unwrap();
			let eta = roadmap.iter().find(|eta| eta.active).unwrap();
			assert!(eta.name.contains("lock address"));
			assert!(eta.name.contains(&error.to_string()));
			assert!(!eta.name.starts_with("Send "));
			assert_eq!(eta.end_time, Some(trade.get_time_start_lock().unwrap()));
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn buyer_funding_eta_keeps_deadline_errors_visible() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let mut trade = erc20_funding_fixture(Currency::Ether, 100);
		trade.message_exchange_time_sec = u64::MAX;
		let error = trade.get_time_start_lock().unwrap_err();
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		));
		let roadmap = api
			.get_fsm(&kc, &trade)
			.get_swap_roadmap(&trade, &secp)
			.unwrap();
		let eta = roadmap.iter().find(|eta| eta.active).unwrap();
		assert!(eta.name.contains("funding deadline"));
		assert!(eta.name.contains(&error.to_string()));
		assert_eq!(eta.end_time, None);
	}

	#[test]
	#[serial]
	fn buyer_init_redeem_eta_preserves_active_step_and_reports_deadline_errors() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let mut trade = erc20_funding_fixture(Currency::Ether, 100);
		trade.state = StateId::BuyerSendingInitRedeemMessage;
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		));
		let active_eta = |trade: &Swap| {
			api.get_fsm(&kc, trade)
				.get_swap_roadmap(trade, &secp)
				.unwrap()
				.into_iter()
				.find(|eta| eta.active)
				.expect("the active init-redeem step must stay visible")
		};

		let eta = active_eta(&trade);
		assert_eq!(eta.name, "Send Init Redeem Message");
		assert_eq!(eta.end_time, Some(trade.get_time_message_redeem().unwrap()));

		let mut invalid_interval = trade.clone();
		invalid_interval.message_exchange_time_sec = u64::MAX;
		let mut invalid_mwc_confirmations = trade.clone();
		invalid_mwc_confirmations.mwc_confirmations = 1_u64 << 60;
		let mut invalid_secondary_confirmations = trade.clone();
		invalid_secondary_confirmations.secondary_confirmations = 1_u64 << 60;
		for invalid in [
			invalid_interval,
			invalid_mwc_confirmations,
			invalid_secondary_confirmations,
		] {
			let error = invalid.get_time_message_redeem().unwrap_err();
			assert!(matches!(&error, Error::DataOverflow(_)));
			let eta = active_eta(&invalid);
			assert!(eta
				.name
				.starts_with("Send Init Redeem Message: unable to determine deadline: "));
			assert!(eta.name.contains(&error.to_string()));
			assert_eq!(eta.end_time, None);
		}
	}

	#[test]
	#[serial]
	fn buyer_redeem_mwc_eta_preserves_active_step_and_reports_deadline_errors() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let mut trade = erc20_funding_fixture(Currency::Ether, 100);
		trade.state = StateId::BuyerRedeemMwc;
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		));
		let active_eta = |trade: &Swap| {
			api.get_fsm(&kc, trade)
				.get_swap_roadmap(trade, &secp)
				.unwrap()
				.into_iter()
				.find(|eta| eta.active)
				.expect("the active MWC redemption step must stay visible")
		};

		let eta = active_eta(&trade);
		assert_eq!(eta.name, "Redeem MWC");
		assert_eq!(eta.end_time, Some(trade.get_time_mwc_redeem().unwrap()));

		let mut invalid_redeem_interval = trade.clone();
		invalid_redeem_interval.redeem_time_sec = u64::MAX;
		let mut deadline_overflow = trade.clone();
		deadline_overflow.redeem_time_sec = u64::try_from(i64::MAX).unwrap();
		let mut invalid_message_interval = trade.clone();
		invalid_message_interval.message_exchange_time_sec = u64::MAX;
		for invalid in [
			invalid_redeem_interval,
			deadline_overflow,
			invalid_message_interval,
		] {
			let error = invalid.get_time_mwc_redeem().unwrap_err();
			assert!(matches!(&error, Error::DataOverflow(_)));
			let eta = active_eta(&invalid);
			assert!(eta
				.name
				.starts_with("Redeem MWC: unable to determine deadline: "));
			assert!(eta.name.contains(&error.to_string()));
			assert_eq!(eta.end_time, None);
		}
	}

	fn eth_transaction_recovery_fixture(
		hashes: Vec<mwc_wallet_util::mwc_web3::types::H256>,
	) -> ethereum::EthTransactionRecovery {
		use mwc_wallet_util::mwc_web3::types::{Address, Bytes};
		ethereum::EthTransactionRecovery {
			chain_id: 1,
			sender: Address::repeat_byte(0x61),
			nonce: 7.into(),
			to: Address::repeat_byte(0x62),
			value: 0.into(),
			data: Bytes(vec![0x63; 132]),
			gas_limit: 100_000.into(),
			gas_price: 15_000_000_000u64.into(),
			gas_budget_gwei: 5_500_000,
			raw_transaction: Bytes(vec![0x64; 256]),
			attempted_hashes: hashes,
			last_attempt_at: swap::get_cur_time(),
			rebroadcasted: false,
		}
	}

	fn erc20_funding_fixture(currency: Currency, amount: u64) -> Swap {
		use mwc_wallet_util::mwc_web3::types::Address;
		let mut swap: Swap =
			serde_json::from_str(&read_to_string("swap_test/swap_sell_1.json").unwrap()).unwrap();
		swap.id = Uuid::new_v4();
		swap.role = Role::Buyer(None);
		swap.state = StateId::BuyerPostingSecondaryToMultisigAccount;
		swap.secondary_currency = currency;
		swap.secondary_amount = amount;
		swap.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(5_500_000);
		let mut data = EthData::new(&EthSellerContext {
			redeem_address: Some(Address::repeat_byte(0x23)),
		})
		.unwrap();
		let mut secret_address = [0u8; 20];
		secret_address[..16].copy_from_slice(swap.id.as_bytes());
		data.address_from_secret = Some(Address::from(secret_address));
		swap.secondary_data = SecondaryData::Eth(data);
		swap
	}

	#[test]
	#[serial]
	fn eth_deposit_deadline_survives_validation_delay_and_slot_changes() {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let kc = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &kc);
		let secret = context
			.unwrap_buyer()
			.unwrap()
			.unwrap_eth()
			.unwrap()
			.address_from_secret;
		let public = PublicKey::from_secret_key(&secp, &key(&secp, &kc, 0, 2)).unwrap();
		let height = 25_000_000;
		for currency in [Currency::Ether, Currency::Usdt] {
			let mut expected_refund = None;
			for delay in [0, 5, 11, 24, 48] {
				let mut deposit = erc20_funding_fixture(currency, 100);
				deposit.redeem_public = Some(public.clone());
				deposit
					.secondary_data
					.unwrap_eth_mut()
					.unwrap()
					.address_from_secret = Some(secret);
				let block_time = deposit.get_time_start() + 1_800;
				swap::set_testing_cur_time(block_time);
				let node = TestEthNodeClient::new(height);
				if currency.is_erc20() {
					node.erc20.lock().allowances.insert(
						currency,
						ethereum::funding::token_amount(currency, deposit.secondary_amount)
							.unwrap(),
					);
				}
				let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
					0,
					currency,
					Arc::new(TestNodeClient::new(300_000)),
					Arc::new(Mutex::new(node.clone())),
				));
				// Validation returns the block it sampled before its RPC checks.
				// Advancing only the wall clock reproduces the latency that used
				// to shorten the funded lock, without sleeping or a live endpoint.
				swap::set_testing_cur_time(block_time + delay);
				api.post_secondary_lock_tx(&mut deposit).unwrap();
				if currency.is_erc20() {
					node.mine_erc20(erc20_pending_hash(&deposit), true);
					api.post_secondary_lock_tx(&mut deposit).unwrap();
				}
				let refund = u64::try_from(node.swap_store.lock().get(&secret).unwrap().0).unwrap();
				assert_eq!(*expected_refund.get_or_insert(refund), refund);
				let earliest_refund = block_time + i64::try_from(refund - height).unwrap() * 12;
				assert!(earliest_refund >= deposit.get_time_secondary_lock_script().unwrap());

				// Check every wall-clock position in a later slot, including a
				// chain that skipped two slots. All must accept the same deposit.
				for elapsed in [120, 144] {
					node.set_state(&TestEthNodeClientState {
						chain_tip_error: None,
						height: height + 10,
						timestamp: u64::try_from(block_time + elapsed).unwrap(),
					});
					for phase in 0..12 {
						swap::set_testing_cur_time(block_time + elapsed + phase);
						api.prepare_secondary_redeem(&mut deposit, &secp).unwrap();
					}
				}
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn eth_deposit_rejects_invalid_deadline_anchors_before_submission() {
		for case in 0..4 {
			let mut deposit = erc20_funding_fixture(Currency::Ether, 100);
			let now = deposit.get_time_start() + 1_800;
			swap::set_testing_cur_time(now);
			let node = TestEthNodeClient::new(25_000_000);
			match case {
				0 => node.state.lock().height = u64::MAX,
				1 => node.state.lock().timestamp = u64::MAX,
				2 => swap::set_testing_cur_time(-1),
				_ => swap::set_testing_cur_time(
					deposit.get_time_secondary_lock_script().unwrap() + 1,
				),
			}
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new_test(
				Arc::new(TestNodeClient::new(300_000)),
				Arc::new(Mutex::new(node.clone())),
			));
			assert!(api.post_secondary_lock_tx(&mut deposit).is_err());
			assert!(node.tx_store.lock().is_empty());
			assert!(node.swap_store.lock().is_empty());
		}
		swap::reset_testing_cur_time();
	}

	fn erc20_pending_hash(swap: &Swap) -> mwc_wallet_util::mwc_web3::types::H256 {
		use ethereum::Erc20FundingPhase::*;
		match swap
			.secondary_data
			.unwrap_eth()
			.unwrap()
			.erc20_funding
			.unwrap()
			.phase
		{
			ResetPending(hash) | ApprovalPending(hash) | DepositPending(hash) => hash,
			phase => panic!("expected pending transaction, got {:?}", phase),
		}
	}

	#[test]
	#[serial]
	fn erc20_funding_serializes_swaps_and_reuses_or_resets_allowance() {
		use ethereum::{funding, funding::token_amount, Erc20FundingPhase::*};
		use mwc_wallet_util::mwc_web3::types::{TransactionReceipt, U256};
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		for currency in [Currency::Usdt, Currency::Dai] {
			let node = TestEthNodeClient::new(1);
			node.erc20
				.lock()
				.allowances
				.insert(currency, token_amount(currency, 50).unwrap());
			// Independent API clients represent separate trades sharing one account.
			let make_api = || -> Box<dyn SwapApi<ExtKeychain>> {
				Box::new(EthSwapApi::new(
					0,
					currency,
					Arc::new(TestNodeClient::new(1)),
					Arc::new(Mutex::new(node.clone())),
				))
			};
			let a_api = make_api();
			let b_api = make_api();
			let exercise_approval_retry = |trade: &mut Swap| {
				let hash = erc20_pending_hash(trade);
				let before = serde_json::to_string(&trade.secondary_data).unwrap();
				node.receipt_results.lock().insert(
					hash,
					Err(Error::EthereumTimeout {
						operation: "approval receipt",
						timeout_secs: 30,
					}),
				);
				assert!(matches!(
					a_api.post_secondary_lock_tx(trade),
					Err(Error::EthereumTimeout { .. })
				));
				assert_eq!(
					serde_json::to_string(&trade.secondary_data).unwrap(),
					before
				);
				// Historical hashes remain readable but cannot invent a retry nonce.
				let record = trade
					.secondary_data
					.unwrap_eth_mut()
					.unwrap()
					.erc20_approval_recovery
					.take();
				assert!(matches!(a_api.post_secondary_lock_tx(trade),
					Err(Error::EthereumTransactionRecoveryMissing(missing)) if missing == hash));
				trade
					.secondary_data
					.unwrap_eth_mut()
					.unwrap()
					.erc20_approval_recovery = record;
				let now = swap::get_cur_time() + state::POST_SECONDARY_RETRY_PERIOD;
				swap::set_testing_cur_time(now);
				a_api.post_secondary_lock_tx(trade).unwrap();
				assert_eq!(
					trade
						.secondary_data
						.unwrap_eth()
						.unwrap()
						.erc20_approval_recovery
						.as_ref()
						.unwrap()
						.last_attempt_at,
					now
				);
				// Preserve replacement mutations even when the returned error has no hash.
				let mut replacement = trade
					.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_approval_recovery
					.clone()
					.unwrap();
				let replacement_hash = mwc_wallet_util::mwc_web3::types::H256::from_low_u64_be(
					u64::try_from(node.tx_store.lock().len()).unwrap() + 1000,
				);
				replacement.attempted_hashes.push(replacement_hash);
				replacement.gas_budget_gwei = 6_000_000;
				trade.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(7_000_000);
				*node.approve_result.lock() = Some((
					replacement.clone(),
					Err(Error::Generic("injected failure after signing".into())),
				));
				assert!(matches!(
					a_api.post_secondary_lock_tx(trade),
					Err(Error::Generic(_))
				));
				assert!(node.approve_result.lock().is_none());
				assert_eq!(erc20_pending_hash(trade), replacement_hash);
				let data = trade.secondary_data.unwrap_eth().unwrap();
				assert_eq!(data.tx_fee_gwei, Some(6_000_000));
				assert_eq!(
					serde_json::to_string(&data.erc20_approval_recovery).unwrap(),
					serde_json::to_string(&Some(replacement)).unwrap()
				);
				hash // The original can still mine after replacement submission failed.
			};
			let mut a = erc20_funding_fixture(currency, 100);
			let mut b = erc20_funding_fixture(currency, 200);
			a_api.post_secondary_lock_tx(&mut a).unwrap();
			assert!(matches!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				ResetPending(_)
			));
			assert!(matches!(
				b_api.post_secondary_lock_tx(&mut b),
				Err(Error::Erc20FundingBusy(_))
			));
			assert!(matches!(
				a_api.post_secondary_lock_tx(&mut a),
				Err(Error::EthTransactionInPending)
			));
			assert_eq!(node.tx_store.lock().len(), 1);
			let reset_hash = exercise_approval_retry(&mut a);
			node.mine_erc20(reset_hash, true);
			a_api.post_secondary_lock_tx(&mut a).unwrap();
			assert!(matches!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				ApprovalPending(_)
			));
			let approval_hash = exercise_approval_retry(&mut a);
			node.mine_erc20(approval_hash, true);
			assert!(b_api.post_secondary_lock_tx(&mut b).is_err());
			assert_eq!(
				node.erc20_allowance(currency).unwrap(),
				token_amount(currency, 100).unwrap()
			);
			a_api.post_secondary_lock_tx(&mut a).unwrap();
			assert!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_approval_recovery
					.is_none()
			);
			assert!(matches!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				DepositPending(_)
			));
			assert!(b_api.post_secondary_lock_tx(&mut b).is_err());
			assert_eq!(node.tx_store.lock().len(), 3);
			// Reset and approval remain independently recoverable after the deposit
			// is signed, persisted, and then removed along with them by a reorg.
			a = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
			let history = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.erc20_approval_history
				.clone();
			assert_eq!(history.len(), 2);
			assert!(matches!(
				history[0].kind,
				ethereum::Erc20ApprovalKind::Reset
			));
			assert!(matches!(
				history[1].kind,
				ethereum::Erc20ApprovalKind::Approve(100)
			));
			let deposit_before =
				serde_json::to_string(&a.secondary_data.unwrap_eth().unwrap().lock_recovery)
					.unwrap();
			let phase_before = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.erc20_funding
				.unwrap()
				.phase;
			let allowance_key = node.erc20_allowance_key(currency).unwrap();
			funding::forget_for_test(allowance_key);
			funding::record_swap(&a);
			for entry in &history {
				node.reorg_erc20(entry.transaction.attempted_hashes[0]);
			}
			node.erc20
				.lock()
				.allowances
				.insert(currency, token_amount(currency, 50).unwrap());
			for (index, entry) in history.iter().enumerate() {
				// A replacement with an ambiguous result is also absent after the reorg.
				for hash in &entry.transaction.attempted_hashes {
					node.receipt_results
						.lock()
						.insert(*hash, Err(Error::EthTransactionInPending));
				}
				assert!(b_api.post_secondary_lock_tx(&mut b).is_err());
				for hash in &entry.transaction.attempted_hashes {
					node.receipt_results
						.lock()
						.insert(*hash, Err(Error::EthTransactionInPending));
				}
				a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(8_000_000);
				node.erc20.lock().ambiguous = true;
				let result = if index == 0 {
					a_api.post_secondary_lock_tx(&mut a)
				} else {
					// Explicit approval recovery also works for a cancelled trade
					// whose funding phase has already advanced to its deposit.
					a.state = StateId::BuyerCancelled;
					a_api.retry_erc20_approval(&mut a)
				};
				assert!(matches!(
					result,
					Err(Error::EthereumSubmissionTimeout { .. })
				));
				let data = a.secondary_data.unwrap_eth().unwrap();
				let recovered = &data.erc20_approval_history[index].transaction;
				assert_eq!(recovered.nonce, entry.transaction.nonce);
				assert_eq!(recovered.data, entry.transaction.data);
				assert_eq!(recovered.gas_budget_gwei, 8_000_000);
				assert_eq!(data.erc20_funding.unwrap().phase, phase_before);
				assert_eq!(
					serde_json::to_string(&data.lock_recovery).unwrap(),
					deposit_before
				);
				assert_eq!(node.tx_store.lock().len(), 3);
				a = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
				node.receipt_results.lock().clear();
				node.erc20.lock().ambiguous = false;
				node.mine_erc20(entry.transaction.attempted_hashes[0], true);
			}
			a.state = StateId::BuyerPostingSecondaryToMultisigAccount;
			// Mere mining retained both records. Canonical finality prunes them
			// individually, without advancing the outstanding deposit.
			for remaining in (0..2).rev() {
				node.finalized_receipts
					.lock()
					.insert(history[1 - remaining].transaction.attempted_hashes[0]);
				a_api.retry_erc20_approval(&mut a).unwrap();
				assert_eq!(
					a.secondary_data
						.unwrap_eth()
						.unwrap()
						.erc20_approval_history
						.len(),
					remaining
				);
				assert_eq!(node.tx_store.lock().len(), 3);
			}
			node.mine_erc20(erc20_pending_hash(&a), true);
			// B reconciles A's deposit even if A never calls its funding path again.
			b_api.post_secondary_lock_tx(&mut b).unwrap();
			assert!(matches!(
				b.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				ApprovalPending(_)
			));
			node.mine_erc20(erc20_pending_hash(&b), true);
			b_api.post_secondary_lock_tx(&mut b).unwrap();
			node.mine_erc20(erc20_pending_hash(&b), true);
			b_api.post_secondary_lock_tx(&mut b).unwrap();
			assert_eq!(node.swap_store.lock().len(), 2);
			assert_eq!(node.tx_store.lock().len(), 5);
			assert_eq!(node.erc20_allowance(currency).unwrap(), U256::zero());
			// Reconcile A too, then exercise a full-width allowance that cannot fit u64.
			a_api.post_secondary_lock_tx(&mut a).unwrap();
			node.erc20.lock().allowances.insert(currency, U256::MAX);
			let mut c = erc20_funding_fixture(currency, 80);
			a_api.post_secondary_lock_tx(&mut c).unwrap();
			assert!(matches!(
				c.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				DepositPending(_)
			));
			assert_eq!(node.tx_store.lock().len(), 6);
			let hash = erc20_pending_hash(&c);
			let before_deposit = node.swap_store.lock().clone();
			node.mine_erc20(hash, true);
			a_api.post_secondary_lock_tx(&mut c).unwrap();
			assert_eq!(
				node.erc20_allowance(currency).unwrap(),
				U256::MAX
					.checked_sub(token_amount(currency, 80).unwrap())
					.unwrap()
			);
			// A completed deposit remains subject to reorgs after persistence.
			c = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
			let key = node.erc20_allowance_key(currency).unwrap();
			funding::forget_for_test(key);
			funding::record_swap(&c);
			// Another trade must reconcile the restored Complete marker even if
			// its owner never runs the funding step again.
			let mut d = erc20_funding_fixture(currency, 10);
			node.receipt_results
				.lock()
				.insert(hash, Err(Error::EthTransactionInPending));
			assert!(b_api.post_secondary_lock_tx(&mut d).is_err());
			assert_eq!(node.tx_store.lock().len(), 6);
			for error in [
				Error::EthereumTimeout {
					operation: "eth_getTransactionReceipt",
					timeout_secs: 30,
				},
				Error::EthTransactionInPending,
			] {
				node.receipt_results.lock().insert(hash, Err(error));
				assert!(a_api.post_secondary_lock_tx(&mut c).is_err());
				assert_eq!(c.secondary_data.unwrap_eth().unwrap().lock_tx, Some(hash));
				assert_eq!(node.tx_store.lock().len(), 6);
			}
			// A later mined revert permits funding again, with a fresh transaction.
			*node.swap_store.lock() = before_deposit;
			node.erc20.lock().allowances.insert(currency, U256::MAX);
			node.receipt_results.lock().insert(
				hash,
				Ok(TransactionReceipt {
					transaction_hash: hash,
					block_number: Some(2.into()),
					status: Some(0.into()),
					..Default::default()
				}),
			);
			assert!(matches!(
				a_api.post_secondary_lock_tx(&mut c),
				Err(Error::Erc20FundingReverted(_))
			));
			assert!(c.secondary_data.unwrap_eth().unwrap().lock_tx.is_none());
			a_api.post_secondary_lock_tx(&mut c).unwrap();
			assert_eq!(node.tx_store.lock().len(), 7);
			assert_ne!(erc20_pending_hash(&c), hash);
		}
	}

	#[test]
	#[serial]
	fn erc20_deposit_retry_recovers_mined_revert() {
		use ethereum::{funding, DepositRecoveryMode::RetryOriginal, Erc20FundingPhase::*};
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		for currency in [Currency::Usdt, Currency::Dai] {
			for previously_cancelled_phase in [false, true] {
				let node = TestEthNodeClient::new(1);
				let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
					0,
					currency,
					Arc::new(TestNodeClient::new(1)),
					Arc::new(Mutex::new(node.clone())),
				));
				let mut trade = erc20_funding_fixture(currency, 100);
				api.post_secondary_lock_tx(&mut trade).unwrap();
				node.mine_erc20(erc20_pending_hash(&trade), true);
				api.post_secondary_lock_tx(&mut trade).unwrap();
				let hash = erc20_pending_hash(&trade);
				let data = trade.secondary_data.unwrap_eth().unwrap();
				let original_nonce = data.lock_recovery.as_ref().unwrap().nonce;
				assert_eq!(data.erc20_approval_history.len(), 1);
				let approval_history = serde_json::to_string(&data.erc20_approval_history).unwrap();
				node.mine_erc20(hash, false);
				if previously_cancelled_phase {
					// Older retry recovery persisted this phase even without a cancellation.
					let data = trade.secondary_data.unwrap_eth_mut().unwrap();
					data.erc20_funding.as_mut().unwrap().phase = DepositCancelled;
				}
				assert!(matches!(
					api.recover_secondary_deposit(&mut trade, RetryOriginal),
					Err(Error::Erc20FundingReverted(_))
				));
				assert_eq!(trade.state, StateId::BuyerPostingSecondaryToMultisigAccount);
				let data = trade.secondary_data.unwrap_eth().unwrap();
				assert_eq!(data.erc20_funding.unwrap().phase, CheckAllowance);
				assert!(data.lock_tx.is_none());
				assert!(data.lock_recovery.is_none());
				assert!(data.lock_cancel_recovery.is_none());
				assert_eq!(
					serde_json::to_string(&data.erc20_approval_history).unwrap(),
					approval_history
				);
				assert_eq!(node.tx_store.lock().len(), 2);

				// The active trade retains its allowance, including after restoring
				// the mutations that the owner saves on an error return.
				let mut other = erc20_funding_fixture(currency, 200);
				assert!(matches!(
					api.post_secondary_lock_tx(&mut other),
					Err(Error::Erc20FundingBusy(_))
				));
				trade = serde_json::from_str(&serde_json::to_string(&trade).unwrap()).unwrap();
				let key = node.erc20_allowance_key(currency).unwrap();
				funding::forget_for_test(key);
				funding::record_swap(&trade);
				assert!(matches!(
					api.post_secondary_lock_tx(&mut other),
					Err(Error::Erc20FundingBusy(_))
				));
				api.post_secondary_lock_tx(&mut trade).unwrap();
				let fresh_hash = erc20_pending_hash(&trade);
				assert_ne!(fresh_hash, hash);
				let data = trade.secondary_data.unwrap_eth().unwrap();
				assert!(data.lock_recovery.as_ref().unwrap().nonce > original_nonce);
				assert_eq!(node.tx_store.lock().len(), 3);
				node.mine_erc20(fresh_hash, true);
				api.recover_secondary_deposit(&mut trade, RetryOriginal)
					.unwrap();
				let data = trade.secondary_data.unwrap_eth().unwrap();
				assert_eq!(data.erc20_funding.unwrap().phase, Complete);
				assert_eq!(node.swap_store.lock().len(), 1);
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	#[serial]
	fn erc20_deposit_retry_preserves_requested_cancellation() {
		use ethereum::{
			funding,
			DepositRecoveryMode::{Cancel, RetryOriginal},
		};
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		for cancellation_wins in [false, true] {
			let currency = Currency::Usdt;
			let node = TestEthNodeClient::new(1);
			node.erc20
				.lock()
				.allowances
				.insert(currency, funding::token_amount(currency, 100).unwrap());
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
				0,
				currency,
				Arc::new(TestNodeClient::new(1)),
				Arc::new(Mutex::new(node.clone())),
			));
			let mut trade = erc20_funding_fixture(currency, 100);
			api.post_secondary_lock_tx(&mut trade).unwrap();
			let hash = erc20_pending_hash(&trade);
			trade.state = StateId::BuyerWaitingForRefundTime;
			api.recover_secondary_deposit(&mut trade, Cancel).unwrap();
			let data = trade.secondary_data.unwrap_eth().unwrap();
			let cancel_hash = data.lock_cancel_recovery.as_ref().unwrap().attempted_hashes[0];
			node.mine_erc20(
				if cancellation_wins { cancel_hash } else { hash },
				cancellation_wins,
			);
			let before = serde_json::to_string(&trade.secondary_data).unwrap();
			assert!(matches!(
				api.recover_secondary_deposit(&mut trade, RetryOriginal),
				Err(Error::UnexpectedAction(_))
			));
			assert_eq!(
				serde_json::to_string(&trade.secondary_data).unwrap(),
				before
			);
			assert_eq!(node.tx_store.lock().len(), 2);
			api.recover_secondary_deposit(&mut trade, Cancel).unwrap();
			assert_eq!(trade.state, StateId::BuyerCancelled);
			let data = trade.secondary_data.unwrap_eth().unwrap();
			assert!(data.lock_recovery.is_some());
			assert!(data.lock_cancel_recovery.is_some());
		}
		swap::reset_testing_cur_time();
	}

	#[cfg(not(target_os = "windows"))]
	#[test]
	#[serial]
	fn erc20_funding_restores_cancelled_ambiguous_transactions_and_retries_reverts() {
		use ethereum::{funding, recovery, Erc20FundingPhase::*};
		use mwc_wallet_util::mwc_web3::types::{TransactionReceipt, H256};
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		swap::set_testing_cur_time(1567632152);
		let storage = tempdir().unwrap();
		trades::init_swap_trade_backend(
			0,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let enc_key = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
		let context: Context =
			serde_json::from_str(&read_to_string("swap_test/context_sell.json").unwrap()).unwrap();
		let save = |swap: &Swap| {
			let lock = trades::get_swap_lock(0, &swap.id.to_string()).unwrap();
			let _guard = lock.lock();
			trades::store_swap_trade(0, &context, swap, &enc_key, &lock).unwrap();
		};
		let record = eth_transaction_recovery_fixture(vec![H256::repeat_byte(0x65)]);
		let refund_sender = mwc_wallet_util::mwc_web3::types::Address::repeat_byte(0x66);
		let deposit_sender = mwc_wallet_util::mwc_web3::types::Address::repeat_byte(0x67);
		for state in [
			StateId::SellerRedeemSecondaryCurrency,
			StateId::BuyerPostingRefundForSecondary,
			StateId::BuyerPostingSecondaryToMultisigAccount,
		] {
			let mut record = record.clone();
			let mut pending_trade = erc20_funding_fixture(Currency::Ether, 100);
			match state {
				StateId::BuyerPostingRefundForSecondary => record.sender = refund_sender,
				StateId::BuyerPostingSecondaryToMultisigAccount => record.sender = deposit_sender,
				_ => pending_trade.role = Role::Seller("unused".into(), 0),
			}
			pending_trade.state = state.clone();
			let data = pending_trade.secondary_data.unwrap_eth_mut().unwrap();
			let (hash, recovery) = match state {
				StateId::BuyerPostingRefundForSecondary => {
					(&mut data.refund_tx, &mut data.refund_recovery)
				}
				StateId::BuyerPostingSecondaryToMultisigAccount => {
					(&mut data.lock_tx, &mut data.lock_recovery)
				}
				_ => (&mut data.redeem_tx, &mut data.redeem_recovery),
			};
			*hash = record.attempted_hashes.last().copied();
			*recovery = Some(record.clone());
			save(&pending_trade);
			// Direct transfers restore reservations without a target swap. A node
			// reporting nonce 7 must not let that transfer replace this transaction.
			recovery::forget_for_test(record.chain_id, record.sender);
			assert_eq!(
				recovery::next_nonce(record.chain_id, record.sender, 7.into(), 7.into()).unwrap(),
				7.into()
			);
			trades::restore_ethereum_resources(0, None, &enc_key).unwrap();
			assert!(matches!(
				recovery::next_nonce(record.chain_id, record.sender, 7.into(), 7.into()),
				Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == record.nonce
			));
			assert_eq!(
				recovery::next_nonce(record.chain_id, record.sender, 7.into(), 8.into()).unwrap(),
				8.into()
			);
			{
				let lock = trades::get_swap_lock(0, &pending_trade.id.to_string()).unwrap();
				let _guard = lock.lock();
				let (_, restored) =
					trades::get_swap_trade(0, &pending_trade.id.to_string(), &enc_key, &lock)
						.unwrap();
				let data = restored.secondary_data.unwrap_eth().unwrap();
				let restored = match state {
					StateId::BuyerPostingRefundForSecondary => &data.refund_recovery,
					StateId::BuyerPostingSecondaryToMultisigAccount => &data.lock_recovery,
					_ => &data.redeem_recovery,
				}
				.as_ref()
				.unwrap();
				assert_eq!(
					serde_json::to_string(restored).unwrap(),
					serde_json::to_string(&record).unwrap()
				);
			}
		}
		// Lose the response during reset, approval, and deposit respectively.
		for initial_allowance in [50, 0, 100] {
			let currency = Currency::Usdt;
			let node = TestEthNodeClient::new(1);
			node.erc20.lock().allowances.insert(
				currency,
				funding::token_amount(currency, initial_allowance).unwrap(),
			);
			node.erc20.lock().ambiguous = true;
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
				0,
				currency,
				Arc::new(TestNodeClient::new(1)),
				Arc::new(Mutex::new(node.clone())),
			));
			let mut a = erc20_funding_fixture(currency, 100);
			let mut b = erc20_funding_fixture(currency, 200);
			assert!(matches!(
				api.post_secondary_lock_tx(&mut a),
				Err(Error::EthereumSubmissionTimeout { .. })
			));
			let hash = erc20_pending_hash(&a);
			let approval_recovery = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.erc20_approval_recovery
				.clone();
			save(&a);
			save(&b);
			let key = node.erc20_allowance_key(currency).unwrap();
			funding::forget_for_test(key);
			if let Some(approval) = &approval_recovery {
				recovery::forget_for_test(approval.chain_id, approval.sender);
			}
			recovery::forget_for_test(record.chain_id, record.sender);
			trades::restore_ethereum_resources(0, Some(&b.id.to_string()), &enc_key).unwrap();
			if let Some(approval) = &approval_recovery {
				assert!(matches!(
					recovery::next_nonce(
						approval.chain_id,
						approval.sender,
						approval.nonce,
						approval.nonce
					),
					Err(Error::EthereumTransactionNonceReserved(_))
				));
			}
			assert!(matches!(
				recovery::next_nonce(record.chain_id, record.sender, 7.into(), 7.into()),
				Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == record.nonce
			));
			assert!(api.post_secondary_lock_tx(&mut b).is_err());
			assert_eq!(node.tx_store.lock().len(), 1);
			{
				let lock = trades::get_swap_lock(0, &a.id.to_string()).unwrap();
				let _guard = lock.lock();
				a = trades::get_swap_trade(0, &a.id.to_string(), &enc_key, &lock)
					.unwrap()
					.1;
			}
			assert_eq!(erc20_pending_hash(&a), hash);
			assert!(api.post_secondary_lock_tx(&mut a).is_err());
			assert_eq!(node.tx_store.lock().len(), 1);
			// Cancellation and deletion must not discard an unresolved transaction.
			a.state = StateId::BuyerCancelled;
			save(&a);
			{
				let lock = trades::get_swap_lock(0, &a.id.to_string()).unwrap();
				let _guard = lock.lock();
				trades::delete_swap_trade(0, &a.id.to_string(), &enc_key, &lock, false).unwrap();
			}
			funding::forget_for_test(key);
			trades::restore_ethereum_resources(0, Some(&b.id.to_string()), &enc_key).unwrap();
			assert!(api.post_secondary_lock_tx(&mut b).is_err());
			if let Some(mut approval) = approval_recovery {
				{
					let lock = trades::get_swap_lock(0, &a.id.to_string()).unwrap();
					let _guard = lock.lock();
					a = trades::get_swap_trade_for_ethereum_recovery(
						0,
						&a.id.to_string(),
						&enc_key,
						&lock,
					)
					.unwrap()
					.1;
				}
				assert_eq!(a.state, StateId::BuyerCancelled);
				assert!(matches!(
					api.post_secondary_lock_tx(&mut a),
					Err(Error::UnexpectedAction(_))
				));
				let replacement_hash = H256::repeat_byte(0x71);
				approval.attempted_hashes.push(replacement_hash);
				approval.gas_budget_gwei = 6_000_000;
				a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(6_000_000);
				*node.approve_result.lock() = Some((
					approval.clone(),
					Err(Error::EthereumSubmissionTimeout {
						tx_hash: replacement_hash,
						timeout_secs: 30,
					}),
				));
				assert!(matches!(
					api.retry_erc20_approval(&mut a),
					Err(Error::EthereumSubmissionTimeout { .. })
				));
				assert_eq!(erc20_pending_hash(&a), replacement_hash);
				save(&a); // Restored cancelled record supersedes its archived original.
				funding::forget_for_test(key);
				recovery::forget_for_test(approval.chain_id, approval.sender);
				trades::restore_ethereum_resources(0, Some(&b.id.to_string()), &enc_key).unwrap();
				assert!(matches!(
					recovery::next_nonce(
						approval.chain_id,
						approval.sender,
						approval.nonce,
						approval.nonce
					),
					Err(Error::EthereumTransactionNonceReserved(_))
				));
				node.receipt_results
					.lock()
					.insert(replacement_hash, Err(Error::EthTransactionInPending));
				assert!(matches!(
					api.post_secondary_lock_tx(&mut b),
					Err(Error::EthTransactionInPending)
				));
				assert_eq!(node.tx_store.lock().len(), 1);
				// Only the replacement mines. The original remains without a receipt.
				node.erc20.lock().allowances.insert(
					currency,
					funding::token_amount(currency, if initial_allowance == 50 { 0 } else { 100 })
						.unwrap(),
				);
				let receipt = TransactionReceipt {
					transaction_hash: replacement_hash,
					block_number: Some(2.into()),
					status: Some(1.into()),
					..Default::default()
				};
				node.receipt_results
					.lock()
					.insert(replacement_hash, Ok(receipt.clone()));
				// The other trade's cache must inspect all recorded candidate hashes.
				node.erc20.lock().ambiguous = false;
				api.post_secondary_lock_tx(&mut b).unwrap();
				node.receipt_results
					.lock()
					.insert(replacement_hash, Ok(receipt));
				api.retry_erc20_approval(&mut a).unwrap();
				assert_eq!(a.state, StateId::BuyerCancelled);
				assert!(
					a.secondary_data
						.unwrap_eth()
						.unwrap()
						.erc20_approval_recovery
						.is_none()
				);
				assert!(a.secondary_data.unwrap_eth().unwrap().lock_tx.is_none());
				assert_eq!(node.tx_store.lock().len(), 2);
				save(&a);
			} else {
				node.mine_erc20(hash, true);
				node.erc20.lock().ambiguous = false;
				api.post_secondary_lock_tx(&mut b).unwrap();
			}
			node.erc20.lock().ambiguous = false;
			let phase = b
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.erc20_funding
				.unwrap()
				.phase;
			assert!(matches!(
				(initial_allowance, phase),
				(0, ResetPending(_)) | (50 | 100, ApprovalPending(_))
			));
			// A mined failure must be surfaced once and leave a retryable state.
			node.mine_erc20(erc20_pending_hash(&b), false);
			assert!(matches!(
				api.post_secondary_lock_tx(&mut b),
				Err(Error::Erc20FundingReverted(_))
			));
			assert_eq!(node.tx_store.lock().len(), 2);
			node.erc20.lock().allowance_error = true;
			assert!(api.post_secondary_lock_tx(&mut b).is_err());
			assert_eq!(node.tx_store.lock().len(), 2);
			node.erc20.lock().allowance_error = false;
			api.post_secondary_lock_tx(&mut b).unwrap();
			assert_eq!(node.tx_store.lock().len(), 3);
		}
		// A dropped deposit remains recoverable after its deadline and after the
		// cancelled trade is archived. Exercise both winners of the same-nonce race.
		for winner in 0..4 {
			use ethereum::DepositRecoveryMode::{Cancel, RetryOriginal};
			swap::set_testing_cur_time(1567632152);
			let currency = Currency::Usdt;
			let node = TestEthNodeClient::new(1);
			node.erc20
				.lock()
				.allowances
				.insert(currency, funding::token_amount(currency, 100).unwrap());
			let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
				0,
				currency,
				Arc::new(TestNodeClient::new(1)),
				Arc::new(Mutex::new(node.clone())),
			));
			let mut a = erc20_funding_fixture(currency, 100);
			let mut b = erc20_funding_fixture(currency, 200);
			api.post_secondary_lock_tx(&mut a).unwrap();
			let hash = erc20_pending_hash(&a);
			let original = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.lock_recovery
				.clone()
				.unwrap();
			let deadline = a.get_time_secondary_lock_script().unwrap() + 1;
			swap::set_testing_cur_time(deadline);
			node.state.lock().timestamp = u64::try_from(deadline).unwrap();
			a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(6_000_000);
			api.post_secondary_lock_tx(&mut a).unwrap();
			assert_eq!(node.tx_store.lock().len(), 1);
			let retried = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.lock_recovery
				.as_ref()
				.unwrap();
			assert_eq!(retried.nonce, original.nonce);
			assert_eq!(retried.data, original.data);
			assert_eq!(retried.gas_budget_gwei, 6_000_000);
			a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(6_100_000);
			api.recover_secondary_deposit(&mut a, RetryOriginal)
				.unwrap();
			assert_eq!(node.tx_store.lock().len(), 1);
			assert_eq!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.lock_recovery
					.as_ref()
					.unwrap()
					.data,
				original.data
			);
			a.state = StateId::BuyerCancelled;
			save(&a);
			{
				let lock = trades::get_swap_lock(0, &a.id.to_string()).unwrap();
				let _guard = lock.lock();
				trades::delete_swap_trade(0, &a.id.to_string(), &enc_key, &lock, false).unwrap();
				a = trades::get_swap_trade_for_ethereum_recovery(
					0,
					&a.id.to_string(),
					&enc_key,
					&lock,
				)
				.unwrap()
				.1;
			}
			assert!(matches!(
				api.recover_secondary_deposit(&mut a, RetryOriginal),
				Err(Error::UnexpectedAction(_))
			));
			assert!(matches!(
				api.post_secondary_lock_tx(&mut a),
				Err(Error::UnexpectedAction(_))
			));
			let mut legacy = a.clone();
			legacy
				.secondary_data
				.unwrap_eth_mut()
				.unwrap()
				.lock_recovery = None;
			assert!(
				matches!(api.recover_secondary_deposit(&mut legacy, Cancel), Err(Error::EthereumTransactionRecoveryMissing(missing)) if missing == hash)
			);
			if winner == 0 {
				// Cancellation can also stop a trade still waiting for its lock.
				a.state = StateId::BuyerWaitingForLockConfirmations;
			}
			node.erc20.lock().ambiguous = true;
			assert!(matches!(
				api.recover_secondary_deposit(&mut a, Cancel),
				Err(Error::EthereumSubmissionTimeout { .. })
			));
			assert_eq!(a.state, StateId::BuyerCancelled);
			let cancellation = a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.lock_cancel_recovery
				.clone()
				.unwrap();
			let cancel_hash = cancellation.attempted_hashes[0];
			assert_ne!(cancel_hash, hash);
			assert_eq!(cancellation.nonce, original.nonce);
			assert_eq!(cancellation.to, original.sender);
			assert!(cancellation.data.0.is_empty());
			assert!(cancellation.value.is_zero());
			assert_eq!(a.secondary_data.unwrap_eth().unwrap().lock_tx, Some(hash));
			save(&a);
			let key = node.erc20_allowance_key(currency).unwrap();
			funding::forget_for_test(key);
			recovery::forget_for_test(key.chain_id, key.owner);
			trades::restore_ethereum_resources(0, None, &enc_key).unwrap();
			assert!(matches!(
				recovery::next_nonce(key.chain_id, key.owner, original.nonce, original.nonce),
				Err(Error::EthereumTransactionNonceReserved(_))
			));
			{
				let lock = trades::get_swap_lock(0, &a.id.to_string()).unwrap();
				let _guard = lock.lock();
				a = trades::get_swap_trade_for_ethereum_recovery(
					0,
					&a.id.to_string(),
					&enc_key,
					&lock,
				)
				.unwrap()
				.1;
			}
			assert_eq!(
				serde_json::to_string(&a.secondary_data.unwrap_eth().unwrap().lock_cancel_recovery)
					.unwrap(),
				serde_json::to_string(&Some(cancellation)).unwrap()
			);
			assert!(api.post_secondary_lock_tx(&mut b).is_err());
			assert_eq!(node.tx_store.lock().len(), 2);
			node.erc20.lock().ambiguous = false;
			a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(7_000_000);
			api.recover_secondary_deposit(&mut a, Cancel).unwrap();
			assert_eq!(node.tx_store.lock().len(), 2);
			let winning_hash = if winner < 2 { cancel_hash } else { hash };
			node.mine_erc20(winning_hash, winner % 2 == 0);
			api.recover_secondary_deposit(&mut a, Cancel).unwrap();
			assert_eq!(
				a.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				if winner == 2 {
					Complete
				} else {
					DepositCancelled
				}
			);
			assert_eq!(
				a.state,
				if winner == 2 {
					StateId::BuyerWaitingForRefundTime
				} else {
					StateId::BuyerCancelled
				}
			);
			assert_eq!(node.swap_store.lock().len(), usize::from(winner == 2));
			assert_eq!(a.secondary_data.unwrap_eth().unwrap().lock_tx, Some(hash));
			assert!(a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.lock_recovery
				.is_some());
			assert!(a
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.lock_cancel_recovery
				.is_some());
			// A reorg of either winning receipt reactivates the reservation. The
			// explicit action can still retry cancellation using the saved nonce.
			save(&a);
			funding::forget_for_test(key);
			trades::restore_ethereum_resources(0, None, &enc_key).unwrap();
			node.reorg_erc20(winning_hash);
			node.swap_store.lock().clear();
			node.erc20
				.lock()
				.allowances
				.insert(currency, funding::token_amount(currency, 100).unwrap());
			assert!(api.post_secondary_lock_tx(&mut b).is_err());
			a.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(8_000_000);
			api.recover_secondary_deposit(&mut a, Cancel).unwrap();
			assert_eq!(node.tx_store.lock().len(), 2);
			node.mine_erc20(cancel_hash, true);
			api.recover_secondary_deposit(&mut a, Cancel).unwrap();
			assert_eq!(a.state, StateId::BuyerCancelled);
			api.post_secondary_lock_tx(&mut b).unwrap();
			assert!(matches!(
				b.secondary_data
					.unwrap_eth()
					.unwrap()
					.erc20_funding
					.unwrap()
					.phase,
				ResetPending(_)
			));
			assert_eq!(node.tx_store.lock().len(), 3);
			// Completed swaps cannot be changed by a deposit cancellation action.
			a.state = StateId::BuyerSwapComplete;
			assert!(matches!(
				api.recover_secondary_deposit(&mut a, Cancel),
				Err(Error::UnexpectedAction(_))
			));
		}
		recovery::forget_for_test(record.chain_id, record.sender);
		recovery::forget_for_test(record.chain_id, refund_sender);
		recovery::forget_for_test(record.chain_id, deposit_sender);
		trades::trades_clean_context(0);
	}

	#[test]
	#[serial]
	fn eth_redirect_check_is_read_only_and_execute_is_idempotent() {
		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();
		swap::set_testing_cur_time(1617589405);

		let keychain = keychain(&secp, 1);
		let context = context_eth_sell(&secp, &keychain);
		let private_wallet = EthereumWallet::from_mnemonic::<Ropsten, English>(
			ETH_MNEMONIC,
			Some(ETH_INITIATOR_PASSWORD),
			ETH_ACCOUNT_PATH,
		)
		.unwrap();
		let redirect_address: String =
			private_wallet.address.clone().unwrap().drain(2..).collect();
		let eth_node = Arc::new(Mutex::new(TestEthNodeClient::new(1)));
		let seller_node = TestNodeClient::new(100_000);
		seller_node.add_seller_inputs(&secp, &keychain, &context);
		let mut api = EthSwapApi::new_test(Arc::new(seller_node), eth_node.clone());
		let mut swap = api
			.create_swap_offer(
				&mut secp,
				&keychain,
				&context,
				99_975,
				100 * MWC_UNIT,
				3_000_000,
				Currency::Ether,
				redirect_address.clone(),
				true,
				30,
				3,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(true),
				false,
				None,
			)
			.unwrap();

		// Import uses post_tx=false. It must not allocate a nonce, invoke redeem,
		// or manufacture a transaction hash.
		api.publish_secondary_transaction(&secp, &keychain, &mut swap, &context, false)
			.unwrap();
		assert_eq!(swap.secondary_data.unwrap_eth().unwrap().redeem_tx, None);
		assert!(eth_node.lock().tx_store.lock().is_empty());

		swap.state = StateId::SellerWaitingForRedeemConfirmations;
		let confirmations = SwapTransactionsConfirmations {
			mwc_observed: true,
			secondary_observed: true,
			mwc_tip: 0,
			mwc_lock_conf: None,
			mwc_redeem_conf: Some(1),
			mwc_refund_conf: None,
			secondary_tip: 1,
			secondary_lock_conf: Some(1),
			secondary_lock_amount: swap.secondary_amount,
			secondary_redeem_conf: Some(1),
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		};
		let mut fsm = api.get_fsm(&keychain, &swap);
		let check = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert!(matches!(
			check.action,
			Some(Action::SellerTransferSecondary { .. })
		));
		assert!(eth_node.lock().tx_store.lock().is_empty());

		let execute = fsm
			.process(Input::Execute, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			execute.next_state_id,
			StateId::SellerWaitingForRedeemConfirmations
		);
		let redirect_tx = swap.secondary_data.unwrap_eth().unwrap().redirect_tx;
		assert_eq!(
			redirect_tx,
			Some(mwc_wallet_util::mwc_web3::types::H256::from([4u8; 32]))
		);
		assert_eq!(eth_node.lock().tx_store.lock().len(), 1);

		// Re-execution sees the recorded hash and cannot transfer the amount again.
		<EthSwapApi<'_, TestNodeClient, TestEthNodeClient> as SwapApi<ExtKeychain>>::transfer_scondary(
			&api,
			&mut swap,
		)
		.unwrap();
		assert_eq!(eth_node.lock().tx_store.lock().len(), 1);
		let confirmed = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(confirmed.next_state_id, StateId::SellerSwapComplete);
	}

	#[test]
	#[serial]
	fn test_eth_refund_tx_lock() {
		use mwc_wallet_util::mwc_web3::types::{Address, U256};

		set_test_mode(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE).unwrap();
		swap::set_testing_cur_time(1617589405);

		let kc_sell = keychain(&secp, 1);
		let ctx_sell = context_eth_sell(&secp, &kc_sell);
		let eth_buy_wallet = EthereumWallet::from_mnemonic::<Ropsten, English>(
			ETH_MNEMONIC,
			Some(ETH_INITIATOR_PASSWORD),
			ETH_ACCOUNT_PATH,
		)
		.unwrap();
		let secondary_redeem_address = eth_buy_wallet.address.clone().unwrap().drain(2..).collect();
		let node_height = 100_000;
		let mwc_anchor_height = node_height - 25;

		let seller_node = TestNodeClient::new(node_height);
		seller_node.add_seller_inputs(&secp, &kc_sell, &ctx_sell);
		let mut api_sell = EthSwapApi::new_test(
			Arc::new(seller_node),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		);
		let mut swap = api_sell
			.create_swap_offer(
				&mut secp,
				&kc_sell,
				&ctx_sell,
				mwc_anchor_height,
				100 * MWC_UNIT,
				3_000_000,
				Currency::Ether,
				secondary_redeem_address,
				true, // mwc should be publisher first
				30,
				3,
				3600,
				3600,
				"file".to_string(),
				"/tmp/del.me".to_string(),
				None,
				None,
				None,
				None,
				None,
				Some(false),
				false,
				None,
			)
			.unwrap();
		assert_eq!(
			swap.secondary_confirmations,
			ethereum::ETH_FINALITY_PLANNING_SLOTS
		);
		assert_eq!(
			swap.get_timeinterval_secondary_lock().unwrap(),
			15 * 60 * 11 / 10
		);

		assert_eq!(swap.lock_slate.slate.height, mwc_anchor_height);
		assert_eq!(swap.refund_slate.slate.height, mwc_anchor_height);
		assert_eq!(swap.redeem_slate.slate.height, mwc_anchor_height);
		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap);
		let tx_state = api_sell
			.request_tx_confirmations(&secp, &kc_sell, &mut swap)
			.unwrap();

		let message = match fsm_sell
			.process(Input::Check, &mut swap, &ctx_sell, &tx_state, &mut secp)
			.unwrap()
			.action
			.unwrap()
		{
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		// Simulate short refund lock time by passing height+4h
		let kc_buy = keychain(&secp, 2);
		let ctx_buy = context_eth_buy(&secp, &kc_buy);
		let nc = TestNodeClient::new(node_height + 12 * 60);

		let (id, offer, secondary_update) = message.unwrap_offer().unwrap();
		let res = BuyApi::accept_swap_offer(
			0,
			&mut secp,
			None,
			&kc_buy,
			&ctx_buy,
			id,
			offer,
			secondary_update,
			&nc,
		);

		assert!(res.err().unwrap().to_string().contains("input_missing")); // Swap cannot be accepted

		// A long message window used to let ETH refund before MWC redemption
		// expired. Check the deposited height itself, including every fractional
		// slot offset and both funding paths. The next ETH block may arrive now.
		for currency in [Currency::Ether, Currency::Usdt] {
			for offset in 0..12 {
				let mut deposit = erc20_funding_fixture(currency, 100);
				deposit.redeem_public =
					Some(PublicKey::from_secret_key(&secp, &key(&secp, &kc_buy, 0, 2)).unwrap());
				deposit
					.secondary_data
					.unwrap_eth_mut()
					.unwrap()
					.address_from_secret = Some(
					ctx_buy
						.unwrap_buyer()
						.unwrap()
						.unwrap_eth()
						.unwrap()
						.address_from_secret,
				);
				deposit.mwc_confirmations = 30;
				deposit.secondary_confirmations = 3;
				deposit.message_exchange_time_sec = 21_600;
				deposit.redeem_time_sec = 600;
				let now = deposit.get_time_start() + 1_800 + offset;
				swap::set_testing_cur_time(now);
				let eth_height = 25_000_000;
				let eth_node = TestEthNodeClient::new(eth_height);
				if currency.is_erc20() {
					eth_node.erc20.lock().allowances.insert(
						currency,
						ethereum::funding::token_amount(currency, deposit.secondary_amount)
							.unwrap(),
					);
				}
				let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
					0,
					currency,
					Arc::new(TestNodeClient::new(node_height)),
					Arc::new(Mutex::new(eth_node.clone())),
				));
				api.post_secondary_lock_tx(&mut deposit).unwrap();
				if currency.is_erc20() {
					eth_node.mine_erc20(erc20_pending_hash(&deposit), true);
					api.post_secondary_lock_tx(&mut deposit).unwrap();
				}
				let secret = deposit
					.secondary_data
					.unwrap_eth()
					.unwrap()
					.address_from_secret
					.unwrap();
				let refund_height =
					u64::try_from(eth_node.swap_store.lock().get(&secret).unwrap().0).unwrap();
				let earliest_refund =
					now + i64::try_from(refund_height - eth_height - 1).unwrap() * 12;
				assert!(earliest_refund >= deposit.get_time_secondary_lock_script().unwrap());
				assert!(earliest_refund > deposit.get_time_mwc_lock().unwrap());

				let accepted = api
					.request_tx_confirmations(&secp, &kc_buy, &deposit)
					.unwrap();
				assert_eq!(accepted.secondary_lock_amount, deposit.secondary_amount);
				assert_eq!(accepted.secondary_lock_conf, Some(1));
				api.prepare_secondary_redeem(&mut deposit, &secp).unwrap();
				if offset != 0 {
					continue;
				}

				// A longer uint256 deadline remains redeemable; comparing its low
				// 64 bits would incorrectly reject the 2^64 case as already expired.
				for full_refund_height in [U256::from(u64::MAX) + U256::from(1), U256::MAX] {
					eth_node.swap_store.lock().get_mut(&secret).unwrap().0 = full_refund_height;
					let long_lock = api
						.request_tx_confirmations(&secp, &kc_buy, &deposit)
						.unwrap();
					assert_eq!(long_lock.secondary_lock_conf, Some(1));
					assert_eq!(long_lock.secondary_lock_amount, deposit.secondary_amount);
					api.prepare_secondary_redeem(&mut deposit, &secp).unwrap();
				}
				eth_node.swap_store.lock().get_mut(&secret).unwrap().0 = refund_height.into();

				// A counterparty can choose a shorter deadline on-chain. Neither a
				// one-block shortfall nor the old 101-block minimum may authorize MWC.
				let mut seller = deposit.clone();
				seller.role = swap.role.clone();
				seller.state = StateId::SellerSendingInitRedeemMessage;
				let mut stale_confirmations = accepted;
				stale_confirmations.mwc_lock_conf = Some(seller.mwc_confirmations);
				let mut seller_fsm = api.get_fsm(&kc_sell, &seller);
				for early_refund_height in [refund_height - 1, eth_height + 101] {
					eth_node.swap_store.lock().get_mut(&secret).unwrap().0 =
						early_refund_height.into();
					let rejected = api
						.request_tx_confirmations(&secp, &kc_sell, &seller)
						.unwrap();
					assert_eq!(rejected.secondary_lock_amount, deposit.secondary_amount);
					assert_eq!(rejected.secondary_lock_conf, None);
					let rejection = api.prepare_secondary_redeem(&mut seller, &secp).unwrap_err();
					// Even a previously successful poll cannot bypass the last check
					// before the seller sends its redeem response.
					let response = seller_fsm
						.process(
							Input::Check,
							&mut seller,
							&ctx_sell,
							&stale_confirmations,
							&mut secp
						)
						.unwrap_err();
					assert_eq!(response.to_string(), rejection.to_string());
					assert!(seller.message2.is_none());
				}
				eth_node.swap_store.lock().get_mut(&secret).unwrap().0 = refund_height.into();

				// Resume a funded buyer near expiry. Its deposit must remain visible
				// and cancellation must retain the refund workflow.
				eth_node.set_state(&TestEthNodeClientState {
					chain_tip_error: None,
					height: refund_height - 100,
					timestamp: u64::try_from(now).unwrap()
						+ (refund_height - eth_height - 100) * 12,
				});
				swap::set_testing_cur_time(
					now + i64::try_from(refund_height - eth_height - 100).unwrap() * 12,
				);
				let expiring = api
					.request_tx_confirmations(&secp, &kc_buy, &deposit)
					.unwrap();
				assert_eq!(expiring.secondary_lock_amount, deposit.secondary_amount);
				assert_eq!(expiring.secondary_lock_conf, None);
				assert_eq!(
					api.request_secondary_lock_balance(&deposit, 1, &secp)
						.unwrap()
						.1,
					deposit.secondary_amount,
				);
				let mut buyer_fsm = api.get_fsm(&kc_buy, &deposit);
				let cancelled = buyer_fsm
					.process(Input::Cancel, &mut deposit, &ctx_buy, &expiring, &mut secp)
					.unwrap();
				assert_eq!(cancelled.next_state_id, StateId::BuyerWaitingForRefundTime);

				eth_node.set_state(&TestEthNodeClientState {
					chain_tip_error: None,
					height: refund_height + 5,
					timestamp: u64::try_from(now).unwrap() + (refund_height + 5 - eth_height) * 12,
				});
				swap::set_testing_cur_time(deposit.get_time_secondary_lock_publish().unwrap() + 1);
				let expired = api
					.request_tx_confirmations(&secp, &kc_buy, &deposit)
					.unwrap();
				assert_eq!(expired.secondary_lock_amount, deposit.secondary_amount);
				assert_eq!(expired.secondary_lock_conf, None);
				let refund = buyer_fsm
					.process(Input::Check, &mut deposit, &ctx_buy, &expired, &mut secp)
					.unwrap();
				assert!(matches!(
					refund.action,
					Some(Action::BuyerPublishSecondaryRefundTx { .. })
				));
				buyer_fsm
					.process(Input::Execute, &mut deposit, &ctx_buy, &expired, &mut secp)
					.unwrap();
				let refund_hash = deposit
					.secondary_data
					.unwrap_eth()
					.unwrap()
					.refund_tx
					.unwrap();
				eth_node.finalized_receipts.lock().insert(refund_hash);
				let refunded = api
					.request_tx_confirmations(&secp, &kc_buy, &deposit)
					.unwrap();
				assert_eq!(refunded.secondary_lock_amount, 0);
				let completed = buyer_fsm
					.process(Input::Check, &mut deposit, &ctx_buy, &refunded, &mut secp)
					.unwrap();
				assert_eq!(completed.next_state_id, StateId::BuyerCancelledRefunded);
			}
		}

		// After MWC is locked, a buyer can initiate a zero-value lock or use an
		// unrelated token with an arbitrary uint256 amount and deadline. Both
		// cancellation and timeout must still reach the seller's MWC refund
		// without requiring that record to clear.
		let malicious_token = Some(Address::repeat_byte(0x25));
		for (currency, token, amount) in [
			(Currency::Ether, None, U256::zero()),
			(
				Currency::Usdt,
				Some(Currency::Usdt.erc20_token_address().unwrap()),
				U256::zero(),
			),
			(
				Currency::Usdt,
				malicious_token,
				U256::from(u64::MAX).checked_add(U256::one()).unwrap(),
			),
			(Currency::Dai, malicious_token, U256::MAX),
		] {
			for refund_block in [U256::from(u64::MAX) + U256::from(1), U256::MAX] {
				let mut seller: Swap =
					serde_json::from_str(include_str!("../../swap_test/swap_sell_2.json")).unwrap();
				seller.secondary_currency = currency;
				seller.state = StateId::SellerWaitingForLockConfirmations;
				let participant = Address::repeat_byte(0x23);
				let secret = ctx_buy
					.unwrap_buyer()
					.unwrap()
					.unwrap_eth()
					.unwrap()
					.address_from_secret;
				let mut data = EthData::new(&EthSellerContext {
					redeem_address: Some(participant),
				})
				.unwrap();
				data.address_from_secret = Some(secret);
				seller.secondary_data = SecondaryData::Eth(data);
				swap::set_testing_cur_time(seller.get_time_locking().unwrap());
				let nc = TestNodeClient::new(seller.lock_slate.slate.height);
				let lock_tx = seller.lock_slate.slate.tx_or_err().unwrap();
				for input in lock_tx.inputs_committed().unwrap() {
					nc.push_output(input.unwrap());
				}
				crate::owner::post_tx(0, &nc, lock_tx, false).unwrap();
				nc.mine_block();
				let eth_node = TestEthNodeClient::new(25_000_000);
				eth_node.raw_swap_store.lock().insert(
					secret,
					(
						refund_block,
						token,
						Address::repeat_byte(0x24),
						participant,
						amount,
					),
				);
				let api = EthSwapApi::new(
					0,
					currency,
					Arc::new(nc.clone()),
					Arc::new(Mutex::new(eth_node)),
				);
				let locked = api
					.request_tx_confirmations(&secp, &kc_sell, &seller)
					.unwrap();
				assert_eq!(locked.mwc_lock_conf, Some(1));
				assert_eq!(locked.secondary_lock_amount, 0);
				assert_eq!(locked.secondary_lock_conf, None);
				let mut fsm = api.get_fsm(&kc_sell, &seller);
				let input = if refund_block == U256::MAX {
					swap::set_testing_cur_time(seller.get_time_message_redeem().unwrap() + 1);
					Input::Check
				} else {
					Input::Cancel
				};
				let cancelled = fsm
					.process(input, &mut seller, &ctx_sell, &locked, &mut secp)
					.unwrap();
				assert_eq!(
					cancelled.next_state_id,
					StateId::SellerWaitingForRefundHeight
				);
				let refund_height = seller.refund_slate.slate.get_lock_height_check().unwrap();
				nc.mine_blocks(refund_height + 1 - nc.get_state().height);
				let unlocked = api
					.request_tx_confirmations(&secp, &kc_sell, &seller)
					.unwrap();
				let refund = fsm
					.process(Input::Check, &mut seller, &ctx_sell, &unlocked, &mut secp)
					.unwrap();
				assert!(matches!(
					refund.action,
					Some(Action::SellerPublishMwcRefundTx)
				));
				fsm.process(Input::Execute, &mut seller, &ctx_sell, &unlocked, &mut secp)
					.unwrap();
				nc.mine_blocks(seller.mwc_confirmations + 1);
				let refunded = api
					.request_tx_confirmations(&secp, &kc_sell, &seller)
					.unwrap();
				assert_eq!(refunded.mwc_refund_conf, Some(seller.mwc_confirmations + 1));
				assert_eq!(refunded.secondary_lock_amount, 0);
				assert_eq!(refunded.secondary_lock_conf, None);
				let completed = fsm
					.process(Input::Check, &mut seller, &ctx_sell, &refunded, &mut secp)
					.unwrap();
				assert_eq!(completed.next_state_id, StateId::SellerCancelledRefunded);
			}
		}
		swap::reset_testing_cur_time();
	}

	#[test]
	fn test_eth_wallet() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).expect("test secp context");
		let kc = keychain(&secp, 1);
		let sec_key = key(&secp, &kc, 0, 0);
		let eth_pri_wallet = EthereumWallet::from_private_key(to_hex(&sec_key.0).as_str()).unwrap();
		println!("eth_pri_wallet  ---- {:?}", eth_pri_wallet);

		let pub_key = PublicKey::from_secret_key(&secp, &sec_key).unwrap();
		println!("pub_key  ---- {:?}", pub_key);

		let pub_key_vec = pub_key.serialize_vec(&secp, false).unwrap();

		let eth_pub_wallet =
			EthereumWallet::from_public_key(to_hex(&pub_key_vec[1..]).as_str()).unwrap();
		println!("eth_pub_wallet  ---- {:?}", eth_pub_wallet);
	}
}

#[cfg(all(test, not(feature = "test-support")))]
#[test]
fn deterministic_swap_tests_require_test_support() {
	panic!("test-support feature is required to run the tests");
}
