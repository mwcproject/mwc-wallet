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

pub use self::error::ErrorKind;
pub use self::swap::Swap;
pub use self::types::Context;
//pub use self::types::BtcSellerContext;

pub(crate) use self::api::SwapApi;
pub(crate) use self::buyer::BuyApi;
pub(crate) use self::seller::SellApi;

pub use grin_keychain::Keychain;

#[cfg(test)]
use serial_test::serial;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

const CURRENT_VERSION: u8 = 1;

#[cfg(test)]
lazy_static! {
	/// Flag to set test mode
	static ref TEST_MODE: AtomicBool = AtomicBool::new(false);
	static ref ACTIVATE_TEST_RESPONSE: AtomicBool = AtomicBool::new(true);
}

#[cfg(test)]
/// Set the test mode
pub fn set_test_mode(mode: bool) {
	TEST_MODE.store(mode, Ordering::Relaxed);
}

#[cfg(test)]
/// Check if we are in test mode
pub fn is_test_mode() -> bool {
	TEST_MODE.load(Ordering::Relaxed)
}

#[cfg(test)]
/// Set the test mode
pub fn activate_test_response(mode: bool) {
	ACTIVATE_TEST_RESPONSE.store(mode, Ordering::Relaxed);
}

#[cfg(test)]
/// Check if we are in test mode
pub fn is_test_response() -> bool {
	ACTIVATE_TEST_RESPONSE.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
	use crate::grin_util::{Mutex, RwLock};
	use crate::{NodeClient, Slate, SlateVersion, VersionedSlate};
	use bitcoin_lib::network::constants::Network as BtcNetwork;
	use bitcoin_lib::util::key::PublicKey as BtcPublicKey;
	use bitcoin_lib::{Address, Transaction as BtcTransaction, TxOut};
	use grin_core::core::transaction::Weighting;
	use grin_core::core::verifier_cache::LruVerifierCache;
	use grin_core::core::{KernelFeatures, Transaction, TxKernel};
	use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
	use grin_util::secp::key::{PublicKey, SecretKey};
	use grin_util::secp::pedersen::{Commitment, RangeProof};
	use grin_util::to_hex;
	use std::collections::HashMap;
	use std::fs::{read_to_string, write};
	use std::mem;
	use std::str::FromStr;
	use std::sync::Arc;

	use super::bitcoin::*;
	use super::message::Message;
	use super::types::*;
	use super::*;
	use crate::swap::fsm::machine::StateMachine;
	use crate::swap::fsm::state::{Input, StateId, StateProcessRespond};
	use crate::swap::message::{SecondaryUpdate, Update};
	use grin_core::global;
	use grin_core::global::ChainTypes;

	const GRIN_UNIT: u64 = 1_000_000_000;

	fn keychain(idx: u8) -> ExtKeychain {
		let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
		let seed_sell = crate::blake2::blake2b::blake2b(32, &[], seed_sell.as_bytes());
		ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
	}

	fn context_sell(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Seller(SellerContext {
				inputs: vec![
					(key_id(0, 1), None, 60 * GRIN_UNIT),
					(key_id(0, 2), None, 60 * GRIN_UNIT),
				],
				change_output: key_id(0, 3),
				change_amount: 20 * GRIN_UNIT, // selling 100 coins, so 20 will be left
				refund_output: key_id(0, 4),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: key_id(0, 5),
				}),
			}),
		}
	}

	fn context_buy(kc: &ExtKeychain) -> Context {
		Context {
			multisig_key: key_id(0, 0),
			multisig_nonce: key(kc, 1, 0),
			lock_nonce: key(kc, 1, 1),
			refund_nonce: key(kc, 1, 2),
			redeem_nonce: key(kc, 1, 3),
			role_context: RoleContext::Buyer(BuyerContext {
				output: key_id(0, 1),
				redeem: key_id(0, 2),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: key_id(0, 3),
				}),
			}),
		}
	}

	fn key_id(d1: u32, d2: u32) -> Identifier {
		ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
	}

	fn key(kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
		kc.derive_key(0, &key_id(d1, d2), SwitchCommitmentType::None)
			.unwrap()
	}

	fn btc_address(kc: &ExtKeychain) -> String {
		let key = PublicKey::from_secret_key(kc.secp(), &key(kc, 2, 0)).unwrap();
		let address = Address::p2pkh(
			&BtcPublicKey {
				compressed: true,
				key,
			},
			BtcNetwork::Testnet,
		);
		format!("{}", address)
	}

	#[derive(Debug, Clone)]
	struct TestNodeClientState {
		pub height: u64,
		pub pending: Vec<Transaction>,
		pub outputs: HashMap<Commitment, u64>,
		pub kernels: HashMap<Commitment, (TxKernel, u64)>,
	}

	#[derive(Debug, Clone)]
	struct TestNodeClient {
		pub state: Arc<Mutex<TestNodeClientState>>,
	}

	impl TestNodeClient {
		pub fn new(height: u64) -> Self {
			let state = TestNodeClientState {
				height,
				pending: Vec::new(),
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

		pub fn mine_block(&self) {
			let mut state = self.state.lock();
			state.height += 1;
			let height = state.height;

			let pending = mem::replace(&mut state.pending, Vec::new());
			for tx in pending {
				for input in tx.body.inputs {
					state.outputs.remove(&input.commit);
				}
				for output in tx.body.outputs {
					state.outputs.insert(output.commit, height);
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
		fn node_url(&self) -> &str {
			"test_node_url"
		}
		fn set_node_url(&mut self, _node_url: &str) {
			unimplemented!()
		}
		fn node_api_secret(&self) -> Option<String> {
			unimplemented!()
		}
		fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {
			unimplemented!()
		}
		fn get_chain_tip(&self) -> Result<(u64, String, u64), crate::Error> {
			let res = (self.state.lock().height, "testnodehash".to_string(), 123455);
			Ok(res)
		}
		fn get_header_info(&self, _height: u64) -> Result<crate::HeaderInfo, crate::Error> {
			unimplemented!()
		}
		fn get_connected_peer_info(
			&self,
		) -> Result<Vec<grin_p2p::types::PeerInfoDisplayLegacy>, crate::Error> {
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
		) -> Result<Vec<grin_api::BlockPrintable>, crate::Error> {
			unimplemented!()
		}
		fn reset_cache(&self) {
			unimplemented!()
		}
		fn post_tx(&self, tx: &Transaction, _fluff: bool) -> Result<(), crate::Error> {
			tx.validate(
				Weighting::AsTransaction,
				Arc::new(RwLock::new(LruVerifierCache::new())),
			)
			.map_err(|e| crate::ErrorKind::Node(format!("Node failure, {}", e)))?;

			let mut state = self.state.lock();
			for input in tx.inputs() {
				// Output not unspent
				if !state.outputs.contains_key(&input.commit) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				// Double spend attempt
				for tx_pending in state.pending.iter() {
					for in_pending in tx_pending.inputs() {
						if in_pending.commit == input.commit {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			// Check for duplicate output
			for output in tx.outputs() {
				if state.outputs.contains_key(&output.commit) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				for tx_pending in state.pending.iter() {
					for out_pending in tx_pending.outputs() {
						if out_pending.commit == output.commit {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			// Check for duplicate kernel
			for kernel in tx.kernels() {
				// Duplicate kernel
				if state.kernels.contains_key(&kernel.excess) {
					return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
				}

				for tx_pending in state.pending.iter() {
					for kernel_pending in tx_pending.kernels() {
						if kernel_pending.excess == kernel.excess {
							return Err(crate::ErrorKind::Node("Node failure".to_string()).into());
						}
					}
				}
			}
			state.pending.push(tx.clone());

			Ok(())
		}
		fn get_version_info(&mut self) -> Option<crate::NodeVersionInfo> {
			unimplemented!()
		}
		fn get_outputs_from_node(
			&self,
			wallet_outputs: &Vec<Commitment>,
		) -> Result<HashMap<Commitment, (String, u64, u64)>, crate::Error> {
			let mut map = HashMap::new();
			let state = self.state.lock();
			for output in wallet_outputs {
				if let Some(height) = state.outputs.get(&output) {
					map.insert(output.clone(), (to_hex(output.0.to_vec()), *height, 0));
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
			_max_height: Option<u64>,
		) -> Result<Option<(TxKernel, u64, u64)>, crate::Error> {
			let state = self.state.lock();
			let res = state
				.kernels
				.get(excess)
				.map(|(kernel, height)| (kernel.clone(), *height, 0));
			Ok(res)
		}
	}

	#[test]
	#[serial]
	fn test_refund_tx_lock() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);

		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);
		let height = 100_000;

		let mut api_sell = BtcSwapApi::new_test(
			Arc::new(TestNodeClient::new(height)),
			Arc::new(Mutex::new(TestBtcNodeClient::new(1))),
		);
		let mut swap = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				100 * GRIN_UNIT,
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
			)
			.unwrap();
		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap);
		let tx_state = api_sell
			.request_tx_confirmations(&kc_sell, &mut swap)
			.unwrap();

		let message = match fsm_sell
			.process(Input::Check, &mut swap, &ctx_sell, &tx_state)
			.unwrap()
			.action
			.unwrap()
		{
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		// Simulate short refund lock time by passing height+4h
		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);
		let nc = TestNodeClient::new(height + 12 * 60);

		let (id, offer, secondary_update) = message.unwrap_offer().unwrap();
		let res = BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc);

		assert_eq!(
			res.err().unwrap(),
			ErrorKind::InvalidMessageData(
				"Lock Slate inputs are not found at the chain".to_string()
			)
		); // Swap cannot be accepted
	}

	#[test]
	#[serial]
	fn test_btc_swap() {
		set_test_mode(true);
		swap::set_testing_cur_time(1567632152);
		global::set_mining_mode(ChainTypes::Floonet);
		let write_json = false;

		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);
		let secondary_redeem_address = btc_address(&kc_sell);

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * GRIN_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		// When test was stored:  Utc.ymd(2019, 9, 4).and_hms_micro(21, 22, 32, 581245)

		// Seller: create swap offer
		let mut api_sell =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let mut swap_sell = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
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
			)
			.unwrap();

		let mut fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);
		let tx_conf = &api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, tx_conf)
			.unwrap();

		assert_eq!(swap_sell.state, StateId::SellerSendingOffer);
		let message_1: Message = match sell_resp.action.unwrap() {
			Action::SellerSendOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Execute, &mut swap_sell, &ctx_sell, &tx_conf)
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_1.json").unwrap(),
				serde_json::to_string_pretty(&message_1).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/context_sell.json").unwrap(),
				serde_json::to_string_pretty(&ctx_sell).unwrap()
			);
		}

		// Add inputs to utxo set
		nc.mine_blocks(2);
		for input in swap_sell.lock_slate.tx.inputs() {
			nc.push_output(input.commit.clone());
		}

		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);

		// Buyer: accept swap offer
		let api_buy =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

		let (id, offer, secondary_update) = message_1.unwrap_offer().unwrap();
		let mut swap_buy =
			BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc).unwrap();

		let mut fsm_buy = api_buy.get_fsm(&kc_buy, &swap_buy);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();

		assert_eq!(swap_buy.state, StateId::BuyerSendingAcceptOfferMessage);
		let message_2 = match buy_resp.action.unwrap() {
			Action::BuyerSendAcceptOfferMessage(message) => message,
			_ => panic!("Unexpected action"),
		};
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf)
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
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
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
		let address = Address::from_str(&address).unwrap();

		// Buyer: first deposit
		let tx_1 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_1 = tx_1.txid();
		btc_nc.push_transaction(&tx_1);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
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
		let tx_2 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: address.script_pubkey(),
			}],
		};
		let txid_2 = tx_2.txid();
		btc_nc.push_transaction(&tx_2);
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);

		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: _,
				currency: _,
				sec_required: _,
				sec_actual: actual,
			} => assert_eq!(actual, Some(1)),
			_ => panic!("Invalid action"),
		};
		btc_nc.mine_blocks(5);

		// Buyer: wait for Grin confirmations
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: actual,
				currency: _,
				sec_required: _,
				sec_actual: _,
			} => assert_eq!(actual, 0),
			_ => panic!("Invalid action"),
		};

		// Check if buyer has correct confirmed outputs
		{
			let script = api_buy.script(&swap_buy).unwrap();
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
			assert_eq!(
				read_to_string("swap_test/swap_buy_1.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_2.json").unwrap(),
				serde_json::to_string_pretty(&message_2).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/context_buy.json").unwrap(),
				serde_json::to_string_pretty(&ctx_buy).unwrap()
			);
		}

		// Seller: receive accepted offer
		assert_eq!(swap_sell.state, StateId::SellerWaitingForAcceptanceMessage);
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_2),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerPublishMwcLockTx"
		);
		assert_eq!(swap_sell.state, StateId::SellerPostingLockMwcSlate);

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Execute, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: wait for Grin confirmations
		nc.mine_blocks(10);
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
				sec_required: _,
				sec_actual: _,
			} => {
				assert_eq!(required, 30);
				assert_eq!(actual, 10)
			}
			_ => panic!("Invalid action"),
		}
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForLockConfirmations);
		match buy_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: required,
				mwc_actual: actual,
				currency: _,
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
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForLockConfirmations);
		match sell_resp.action.unwrap() {
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: _,
				currency: _,
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Checking if both seller & Buyer are moved to the redeem message exchange step
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
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
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf)
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
			assert_eq!(
				read_to_string("swap_test/swap_buy_2.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_3.json").unwrap(),
				serde_json::to_string_pretty(&message_3).unwrap()
			);
		}

		// Seller: sign redeem
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerWaitingForInitRedeemMessage);
		assert_eq!(
			sell_resp.action.unwrap().get_id_str(),
			"SellerWaitingForInitRedeemMessage"
		);

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(
				Input::IncomeMessage(message_3),
				&mut swap_sell,
				&ctx_sell,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(swap_sell.state, StateId::SellerSendingInitRedeemMessage);
		let message_4 = match sell_resp.action.unwrap() {
			Action::SellerSendRedeemMessage(message) => message,
			_ => panic!("Unexpected action"),
		};

		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Execute, &mut swap_sell, &ctx_sell, &tx_conf)
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_4.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
			assert_eq!(
				read_to_string("swap_test/message_4.json").unwrap(),
				serde_json::to_string_pretty(&message_4).unwrap()
			);
		}

		// Buyer: redeem
		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitingForRespondRedeemMessage);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerWaitingForRedeemMessage"
		);

		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(
				Input::IncomeMessage(message_4),
				&mut swap_buy,
				&ctx_buy,
				&tx_conf,
			)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerRedeemMwc);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"BuyerPublishMwcRedeemTx"
		);

		let tx_conf = &api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Execute, &mut swap_buy, &ctx_buy, &tx_conf)
			.unwrap();
		assert_eq!(swap_buy.state, StateId::BuyerWaitForRedeemMwcConfirmations);
		assert_eq!(
			buy_resp.action.unwrap().get_id_str(),
			"WaitForMwcConfirmations"
		);

		// Buyer: almost done, just need to wait for confirmations
		nc.mine_block();

		let tx_conf = api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
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

		// At this point, buyer would add Grin to their outputs
		// Now seller can redeem BTC
		if write_json {
			write(
				"swap_test/swap_buy_3.json",
				serde_json::to_string_pretty(&swap_buy).unwrap(),
			)
			.unwrap();
		} else {
			assert_eq!(
				read_to_string("swap_test/swap_buy_3.json").unwrap(),
				serde_json::to_string_pretty(&swap_buy).unwrap()
			);
		}

		// Seller: publish BTC tx
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_5.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		// Seller: publishing and wait for BTC confirmations
		let tx_conf = api_sell
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Execute, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
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
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		assert_eq!(
			swap_sell.state,
			StateId::SellerWaitingForRedeemConfirmations
		);
		match sell_resp.action.unwrap() {
			Action::WaitForSecondaryConfirmations {
				name: _,
				currency: _,
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
			.request_tx_confirmations(&kc_sell, &swap_sell)
			.unwrap();
		let sell_resp = fsm_sell
			.process(Input::Check, &mut swap_sell, &ctx_sell, &tx_conf)
			.unwrap();
		let tx_conf = &api_buy
			.request_tx_confirmations(&kc_buy, &swap_buy)
			.unwrap();
		let buy_resp = fsm_buy
			.process(Input::Check, &mut swap_buy, &ctx_buy, &tx_conf)
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
			assert_eq!(
				read_to_string("swap_test/swap_sell_6.json").unwrap(),
				serde_json::to_string_pretty(&swap_sell).unwrap()
			);
		}

		assert!(!write_json, "json files written");
	}

	#[test]
	#[serial]
	fn test_swap_serde() {
		// Seller context
		let ctx_sell_str = read_to_string("swap_test/context_sell.json").unwrap();
		let ctx_sell: Context = serde_json::from_str(&ctx_sell_str).unwrap();
		assert_eq!(
			serde_json::to_string_pretty(&ctx_sell).unwrap(),
			ctx_sell_str
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
		pub fn process(&mut self, input: Input) -> Result<StateProcessRespond, ErrorKind> {
			let tx_conf = self.api.request_tx_confirmations(&self.kc, &self.swap)?;
			self.fsm.process(input, &mut self.swap, &self.ctx, &tx_conf)
		}

		pub fn _get_tx_conf(&self) -> Result<SwapTransactionsConfirmations, ErrorKind> {
			self.api.request_tx_confirmations(&self.kc, &self.swap)
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
				let _sr = trader.process(Input::Cancel).unwrap();
				assert_eq!(trader.swap.state, cancel_expected_state.clone().unwrap());
			} else {
				assert_eq!(trader.is_cancellable(), false);
				let sr = trader.process(Input::Cancel);
				assert!(sr.is_err(), true);
			}
			trader.pops();
		}

		// Check Inputs
		for t in &time2pass {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check).unwrap();
			assert_eq!(trader.swap.state, check_before_expected_state);
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			let _sr = trader.process(Input::Check).unwrap();
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
				let _sr = trader.process(Input::Execute).unwrap();
				assert_eq!(
					trader.swap.state,
					execute_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute);
				assert_eq!(sr.is_err(), true);
			}
			trader.pops();
		}
		for t in &time2fail {
			trader.pushs();
			swap::set_testing_cur_time(*t);
			if execute_after_expected_state.is_some() {
				let _sr = trader.process(Input::Execute).unwrap();
				assert_eq!(
					trader.swap.state,
					execute_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(Input::Execute);
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
				let _sr = trader.process(message).unwrap();
				assert_eq!(
					trader.swap.state,
					message_before_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message);
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
				let _sr = trader.process(message).unwrap();
				assert_eq!(
					trader.swap.state,
					message_after_expected_state.clone().unwrap()
				);
			} else {
				let sr = trader.process(message);
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
		swap::set_testing_cur_time(START_TIME);
		global::set_mining_mode(ChainTypes::Floonet);

		let nc = TestNodeClient::new(300_000);
		let btc_nc = TestBtcNodeClient::new(500_000);

		let amount = 100 * GRIN_UNIT;
		let btc_amount_1 = 2_000_000;
		let btc_amount_2 = 1_000_000;
		let btc_amount_plus = 10_000;
		let btc_amount = btc_amount_1 + btc_amount_2;

		let mut api_sell =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));
		let kc_sell = keychain(1);
		let ctx_sell = context_sell(&kc_sell);

		let mut seller = {
			let secondary_redeem_address = btc_address(&kc_sell);
			let swap_sell = api_sell
				.create_swap_offer(
					&kc_sell,
					&ctx_sell,
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
				)
				.unwrap();
			let fsm_sell = api_sell.get_fsm(&kc_sell, &swap_sell);

			// Seller: create swap offer
			Trader {
				api: &api_sell,
				swap: swap_sell,
				fsm: fsm_sell,
				kc: kc_sell,
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
		);

		// Go to the next step
		swap::set_testing_cur_time(START_TIME + 20);
		let res = seller.process(Input::Check).unwrap();
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
		);
		// Seller send the message, so confirming to FSM with that
		let res = seller.process(Input::Execute).unwrap();
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
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);

		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSendingOffer);
		// simulate ack that we get from the network...
		seller.swap.ack_msg1();
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::SellerWaitingForAcceptanceMessage
		);

		// ----------------------------------------------------------------------------------------------------------
		// ----------------------------------------------------------------------------------------------------------
		// ----------------------------------------------------------------------------------------------------------

		// Creating buyer
		let kc_buy = keychain(2);
		let ctx_buy = context_buy(&kc_buy);
		let api_buy =
			BtcSwapApi::new_test(Arc::new(nc.clone()), Arc::new(Mutex::new(btc_nc.clone())));

		////////////////////////////////////////////////////////////////////
		// Testing how Buyer can validate the data

		{
			// Try to create offer with no inputs on the chain
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
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
		for input in seller.swap.lock_slate.tx.inputs() {
			nc.push_output(input.commit.clone());
		}

		{
			// Should be good now...
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.lock_height = 10;
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: lock_slate.fee,
				lock_height: 10,
			};
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.lock_height = 10;
			lock_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: lock_slate.fee,
				lock_height: 10,
			};
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.fee += 2;
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.tx.body.kernels[0].features = KernelFeatures::Plain {
				fee: lock_slate.fee + 1,
			};
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.tx.body.kernels[0].features = KernelFeatures::Plain {
				fee: lock_slate.fee - 1,
			};
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.fee += 2;
			lock_slate.tx.body.kernels[0].features = KernelFeatures::Plain {
				fee: lock_slate.fee,
			};
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.tx.body.inputs.clear();
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut lock_slate: Slate = offer.lock_slate.into();
			lock_slate.amount += 1;
			offer.lock_slate = VersionedSlate::into_version(lock_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.lock_height -= 1;
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.lock_height = 0;
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels.push(TxKernel::empty());
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels[0].features = KernelFeatures::Plain {
				fee: refund_slate.fee,
			};
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: refund_slate.fee,
				lock_height: refund_slate.lock_height - 1,
			};
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: refund_slate.fee,
				lock_height: 0,
			};
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: refund_slate.fee,
				lock_height: 1,
			};
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.fee += 1;
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.tx.body.kernels[0].features = KernelFeatures::HeightLocked {
				fee: refund_slate.fee + 1,
				lock_height: refund_slate.lock_height,
			};
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
			let mut refund_slate: Slate = offer.refund_slate.into();
			refund_slate.amount -= 1;
			offer.refund_slate = VersionedSlate::into_version(refund_slate, SlateVersion::V3);
			assert_eq!(
				BuyApi::accept_swap_offer(
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
		// Finaly going with buyer. Happy path
		let mut buyer = {
			let (id, offer, secondary_update) = message1.clone().unwrap_offer().unwrap();
			let swap_buy =
				BuyApi::accept_swap_offer(&kc_buy, &ctx_buy, id, offer, secondary_update, &nc)
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
		let input_script = buyer.api.script(&buyer.swap).unwrap();
		let btc_address_to_deposit = buyer
			.swap
			.secondary_data
			.unwrap_btc()
			.unwrap()
			.address(&input_script, buyer.swap.network)
			.unwrap();
		let tx_1 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_1,
				script_pubkey: btc_address_to_deposit.script_pubkey(),
			}],
		};
		let _txid_1 = tx_1.txid();
		let tx_2 = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_2,
				script_pubkey: btc_address_to_deposit.script_pubkey(),
			}],
		};
		let _txid_2 = tx_2.txid();
		let tx_plus = BtcTransaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![TxOut {
				value: btc_amount_plus,
				script_pubkey: btc_address_to_deposit.script_pubkey(),
			}],
		};
		let _txid_plus = tx_plus.txid();

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
		);

		swap::set_testing_cur_time(START_TIME + 120);
		let res = buyer.process(Input::Check).unwrap();
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

		assert_eq!(seller.swap.get_time_start_lock(), lock_start_timelimit);
		assert_eq!(
			seller.swap.get_time_message_redeem(),
			lock_second_message_round_timelimit
		);
		assert_eq!(seller.swap.get_time_btc_lock(), btc_lock_time_limit);
		assert_eq!(seller.swap.get_time_mwc_lock(), mwc_lock_time_limit);

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
		);
		swap::set_testing_cur_time(START_TIME + 130);
		// Reporting that message is sent...
		let res = buyer.process(Input::Execute).unwrap();
		assert_eq!(buyer.swap.state, StateId::BuyerWaitingForSellerToLock);
		assert_eq!(res.next_state_id, buyer.swap.state);
		assert_eq!(res.time_limit.clone().unwrap(), lock_start_timelimit);
		assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");

		// Checking send message retry...
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerWaitingForSellerToLock);
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerWaitingForSellerToLock);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
		// simulate ack
		buyer.swap.ack_msg1();
		let res = buyer.process(Input::Check).unwrap();
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
			);
			// try to process wrong message
			assert_eq!(
				seller
					.process(Input::IncomeMessage(message1.clone()))
					.is_err(),
				true
			);
			let res = seller
				.process(Input::IncomeMessage(message2.clone()))
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
				.process(Input::IncomeMessage(message2.clone()))
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
			);

			let state = btc_nc.get_state();

			btc_nc.post_transaction(&tx_1);
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
			);
			btc_nc.post_transaction(&tx_2);
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
			);
			btc_nc.post_transaction(&tx_plus);
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

			let res = buyer.process(Input::Cancel).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerCancelled);
			assert_eq!(res.action.is_some(), false);
			assert_eq!(res.time_limit.is_some(), false);

			let res = seller.process(Input::Cancel).unwrap();
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
		);
		// try to process wrong message
		assert_eq!(
			seller
				.process(Input::IncomeMessage(message1.clone()))
				.is_err(),
			true
		);
		let res = seller
			.process(Input::IncomeMessage(message2.clone()))
			.unwrap();
		assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
		assert_eq!(res.next_state_id, seller.swap.state);
		assert_eq!(res.time_limit.clone().unwrap(), lock_start_timelimit);
		assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcLockTx");

		// Double processing should be fine
		assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
		let res = seller
			.process(Input::IncomeMessage(message2.clone()))
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
		);

		// Seller posting MWC transaction, testing retry tx cases.
		let nc_nolock_state = nc.get_state();
		{
			// Let's check what happens if MWC is not published. Seller need to do a retry.
			let res = seller.process(Input::Execute).unwrap();
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
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(seller.swap.state, StateId::SellerPostingLockMwcSlate);
			assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcLockTx");
			// SellerPostingLockMwcSlate expecting to fail because tx into the tx pool
			assert_eq!(seller.process(Input::Execute).is_err(), true);
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
			);

			{
				// BRANCH - Check if cancel in far future is different.
				seller.pushs();
				nc.mine_blocks(600);
				let res = seller.process(Input::Cancel).unwrap();
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
			);

			let _res = seller.process(Input::Execute).unwrap();
			assert_eq!(
				seller.swap.state,
				StateId::SellerWaitingForLockConfirmations
			);
			// post wasn't made.
			assert_eq!(seller.swap.posted_lock.clone().unwrap(), first_post_time);
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
			);

			let _res = seller.process(Input::Execute).unwrap();
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
				.process(Input::IncomeMessage(message2.clone()))
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
			);
			// Let's roll back the chain
			nc.set_state(&nc_nolock_state);
			// Expecting switch to SellerPostingLockMwcSlate
			// not a time for retry
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForLockConfirmations
			);
			// let's trigger retry
			swap::set_testing_cur_time(START_TIME + 150 + 60 * 5 * 3 + 3);
			let res = seller.process(Input::Check).unwrap();
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
		);

		{
			// BRANCH - checking that Sellr lock will set ack to the message
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);

			buyer.pops();
		}

		let res = buyer.process(Input::Check).unwrap();
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
				assert_eq!(address, btc_address_to_deposit.to_string());
			}
			_ => panic!("Invalid action"),
		}

		{
			// BRANCH - Checking retry messages
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check).unwrap();
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

			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerPostingSecondaryToMultisigAccount
			);

			swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);

			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
			// simulate ack, so should return back to the current step
			nc.set_state(&st);
			buyer.swap.ack_msg1();
			let res = buyer.process(Input::Check).unwrap();
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
		);

		// Let's store BTC network without deposit
		let bnc_deposit_none = btc_nc.get_state();

		btc_nc.post_transaction(&tx_1);
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
		);
		let res = buyer.process(Input::Check).unwrap();
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
				assert_eq!(address, btc_address_to_deposit.to_string());
			}
			_ => panic!("Invalid action"),
		}

		{
			// BRANCH - Check Buyer cancel in far future is different
			buyer.pushs();
			let cur_ts = swap::get_cur_time();
			swap::set_testing_cur_time(btc_lock_time_limit + 1);
			let res = buyer.process(Input::Cancel).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);
			swap::set_testing_cur_time(cur_ts);
			buyer.pops();
		}

		// Let's store BTC network with part deposit
		let bnc_deposit_1 = btc_nc.get_state();

		btc_nc.post_transaction(&tx_2);
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
		);
		{
			// Branch -  Checking if posting too much will switch to cancellation
			buyer.pushs();
			btc_nc.post_transaction(&tx_plus);
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
			);
			buyer.pops();
		}

		// Buyer is good to go to the waiting step
		let res = buyer.process(Input::Check).unwrap();
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
		);

		{
			// BRANCH - Checking retry messages
			buyer.pushs();

			// No retry if MWC are posted...
			buyer.swap.posted_msg1 = Some(swap::get_cur_time() - 60 * 10);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);

			// Doing some tweaks, need to reset ack first
			assert_eq!(buyer.swap.posted_msg1.unwrap(), u32::MAX as i64);
			let st = nc.get_state();
			nc.set_state(&nc_nolock_state);
			buyer.swap.posted_msg1 = Some(swap::get_cur_time());

			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);

			swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);

			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerSendingAcceptOfferMessage);
			// simulate ack, so should return back to the current step
			buyer.swap.ack_msg1();
			nc.set_state(&st);
			let res = buyer.process(Input::Check).unwrap();
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
			);
			let res = buyer.process(Input::Check).unwrap();
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
					assert_eq!(address, btc_address_to_deposit.to_string());
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

			let res = buyer.process(Input::Cancel).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForRefundTime);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitingForBtcRefund");
			assert_eq!(res.time_limit.unwrap(), btc_lock_time_limit);

			let lock_height = seller.swap.refund_slate.lock_height;
			let need_blocks = lock_height - nc.state.lock().height;

			let res = seller.process(Input::Cancel).unwrap();
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
			);

			let res = seller.process(Input::Check).unwrap();
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
			);

			let nc_state_prepost = nc.get_state();

			let res = seller.process(Input::Execute).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
			assert_eq!(res.time_limit.is_none(), true);
			// Checking post retry workflow. nc not mined, so not cofirmed until
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			//
			swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			// test network not supported repost
			assert_eq!(seller.process(Input::Execute).is_err(), true);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			nc.mine_block();
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);

			// reorg should trigger retry
			nc.set_state(&nc_state_prepost);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
			let res = seller.process(Input::Execute).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRefundConfirmations
			);
			nc.mine_block();
			let res = seller.process(Input::Check).unwrap();
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
			);

			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerCancelledRefunded);
			assert_eq!(res.action.is_none(), true);
			assert_eq!(res.time_limit.is_none(), true);

			// Buyer turn to do a refund....
			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRefundTime,
				Some((btc_lock_time_limit, -1)),
				None,
				StateId::BuyerWaitingForRefundTime, // Expected state before timeput
				StateId::BuyerPostingRefundForSecondary, // Expected state after timeout
				None,
				None, // Expected state before timeput
				None, // Expected state after timeout
				None, // Acceptable message
				None,
				None,
			);

			swap::set_testing_cur_time(btc_lock_time_limit + 1);

			let res = buyer.process(Input::Check).unwrap();
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
			);

			let btc_state_prerefund = btc_nc.get_state();

			let res = buyer.process(Input::Execute).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			assert_eq!(
				res.action.unwrap().get_id_str(),
				"WaitForSecondaryConfirmations"
			);
			assert_eq!(res.time_limit.is_none(), true);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);

			{
				// BRANCH - check if buyer can resubmit the Secondary refund transaction
				// Checking if resubmit works
				buyer.pushs();
				let cur_time = swap::get_cur_time();

				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);

				swap::set_testing_cur_time(cur_time * 61 * 5);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);
				// Changing fees, expecting to switch back to the posting
				buyer.swap.secondary_fee = 12.0;
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);

				swap::set_testing_cur_time(cur_time);
				buyer.pops();
			}

			// checking retry scenarion
			let btc_state_refund_posted = btc_nc.get_state();
			btc_nc.set_state(&btc_state_prerefund);
			// no retry because of timeout
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);
			swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerPostingRefundForSecondary);
			// Check be restored
			btc_nc.set_state(&btc_state_refund_posted);
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRefundConfirmations
			);

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
			);

			{
				// BRANCH - check if buyer can't resubmit the refund transaction because it is already mined
				// Checking if resubmit works
				buyer.pushs();
				let cur_time = swap::get_cur_time();

				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);

				swap::set_testing_cur_time(cur_time * 61 * 5);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitingForRefundConfirmations
				);
				// Changing fees, expecting to switch back to the posting
				buyer.swap.secondary_fee = 12.0;
				let res = buyer.process(Input::Check).unwrap();
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
			);

			let res = buyer.process(Input::Check).unwrap();
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
			);

			let res = buyer.process(Input::Check).unwrap();
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
			);
			nc.mine_blocks(10);
			btc_nc.mine_block();
		}

		// We are almost done here. But still waiting.
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
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerSendingInitRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,     // Expected state after timeout
			None,
			None, // Expected state before timeput
			None, // Expected state after timeout
			None, // Acceptable message
			None,
			None,
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
		);

		let res = buyer.process(Input::Check).unwrap();
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
					.process(Input::IncomeMessage(message3.clone()))
					.is_ok(),
				true
			);

			seller.pops();
		}

		let res = seller.process(Input::Check).unwrap();
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
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)),
				Some(StateId::BuyerWaitingForLockConfirmations), // Expected state before timeput
				Some(StateId::BuyerWaitingForRefundTime),        // Expected state after timeout
				None,                                            // Acceptable message
				None,
				None,
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
				Some(StateId::SellerWaitingForRefundHeight),
				Some(StateId::SellerWaitingForRefundHeight),
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
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerCancelled, // Expected state before timeput
				StateId::BuyerCancelled, // Expected state after timeout
				None,
				Some(StateId::BuyerCancelled), // Expected state before timeput
				Some(StateId::BuyerCancelled), // Expected state after timeout
				None,                          // Acceptable message
				None,
				None,
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
			);
			seller.pops();
			buyer.pops();
		}

		// Normal case, message processing
		test_responds(
			&mut buyer,
			StateId::BuyerSendingInitRedeemMessage,
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerSendingInitRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,     // Expected state after timeout
			None,
			Some(StateId::BuyerWaitingForRespondRedeemMessage), // Expected state before timeput
			Some(StateId::BuyerWaitingForRefundTime),           // Expected state after timeout
			None,                                               // Acceptable message
			None,
			None,
		);
		test_responds(
			&mut seller,
			StateId::SellerWaitingForInitRedeemMessage,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			Some(StateId::SellerWaitingForRefundHeight),
			StateId::SellerWaitingForInitRedeemMessage, // Expected state before timeput
			StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
			None,
			None,                   // Expected state before timeput
			None,                   // Expected state after timeout
			Some(message3.clone()), // Acceptable message
			Some(StateId::SellerSendingInitRedeemMessage),
			Some(StateId::SellerWaitingForRefundHeight),
		);

		// Message is already known from steps above, it is message3.
		// Finishing execution
		let res = buyer.process(Input::Execute).unwrap();
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
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitingForRespondRedeemMessage
		);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSendingInitRedeemMessage);
		buyer.swap.ack_msg2();
		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitingForRespondRedeemMessage
		);

		assert_eq!(
			seller
				.process(Input::IncomeMessage(message1.clone()))
				.is_err(),
			true
		);
		assert_eq!(
			seller
				.process(Input::IncomeMessage(message2.clone()))
				.is_err(),
			true
		);
		let res = seller
			.process(Input::IncomeMessage(message3.clone()))
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
			Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
			Some(StateId::BuyerWaitingForRefundTime),
			StateId::BuyerWaitingForRespondRedeemMessage, // Expected state before timeput
			StateId::BuyerWaitingForRefundTime,           // Expected state after timeout
			Some((
				lock_second_message_round_timelimit + REDEEM_TIME,
				btc_lock_time_limit,
			)),
			None,                   // Expected state before timeput
			None,                   // Expected state after timeout
			Some(message4.clone()), // Acceptable message
			Some(StateId::BuyerRedeemMwc),
			Some(StateId::BuyerWaitingForRefundTime),
		);
		test_responds(
			&mut seller,
			StateId::SellerSendingInitRedeemMessage,
			Some((lock_second_message_round_timelimit, -1)), // timeout if possible
			Some(StateId::SellerWaitingForRefundHeight),
			StateId::SellerSendingInitRedeemMessage, // Expected state before timeput
			StateId::SellerWaitingForRefundHeight,   // Expected state after timeout
			None,
			Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
			Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
			None,                                            // Acceptable message
			None,
			None,
		);

		{
			// BRANCH - what happens if chan will loose it's data
			// Loss any of them should switch to cancellation
			buyer.pushs();
			seller.pushs();

			// Testing mwc chain reset
			let nc_state = nc.get_state();
			nc.clean();

			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRespondRedeemMessage,
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				None,
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message4.clone()), // Acceptable message
				Some(StateId::BuyerWaitingForLockConfirmations),
				Some(StateId::BuyerWaitingForRefundTime),
			);
			test_responds(
				&mut seller,
				StateId::SellerSendingInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForRefundHeight, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight, // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
				None,                                            // Acceptable message
				None,
				None,
			);

			let cur_time = swap::get_cur_time();
			swap::set_testing_cur_time(START_TIME + MSG_EXCHANGE_TIME);

			// Checking if glitch will be recoverable...
			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::BuyerWaitingForLockConfirmations);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerPostingLockMwcSlate);

			nc.set_state(&nc_state);

			let res = buyer.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::BuyerWaitingForRespondRedeemMessage
			);
			let res = seller.process(Input::Check).unwrap();
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
			let tlim = buyer.swap.get_time_mwc_redeem();
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
			);

			btc_nc.set_state(&btc_state);
			btc_nc.state.lock().height -= 4;

			test_responds(
				&mut buyer,
				StateId::BuyerWaitingForRespondRedeemMessage,
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)), // timeout if possible
				Some(StateId::BuyerWaitingForRefundTime),
				StateId::BuyerWaitingForLockConfirmations, // Expected state before timeput
				StateId::BuyerWaitingForRefundTime,        // Expected state after timeout
				Some((lock_second_message_round_timelimit, btc_lock_time_limit)),
				None,                   // Expected state before timeput
				None,                   // Expected state after timeout
				Some(message4.clone()), // Acceptable message
				Some(StateId::BuyerWaitingForLockConfirmations),
				Some(StateId::BuyerWaitingForRefundTime),
			);
			test_responds(
				&mut seller,
				StateId::SellerSendingInitRedeemMessage,
				Some((lock_second_message_round_timelimit, -1)), // timeout if possible
				Some(StateId::SellerWaitingForRefundHeight),
				StateId::SellerWaitingForLockConfirmations, // Expected state before timeput
				StateId::SellerWaitingForRefundHeight,      // Expected state after timeout
				None,
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // Expected state before timeput
				Some(StateId::SellerWaitingForBuyerToRedeemMwc), // NOT CANCELLABLE by time, will check about the height
				None,                                            // Acceptable message
				None,
				None,
			);

			seller.pops();
			buyer.pops();
		}

		// processing message
		let res = seller.process(Input::Execute).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);
		assert_eq!(
			res.time_limit.unwrap(),
			swap::get_cur_time()
				+ (seller
					.swap
					.refund_slate
					.lock_height
					.saturating_sub(nc.state.lock().height)
					* 60) as i64
		); // Time is related to refund, not to a real time...
		assert_eq!(
			res.action.unwrap().get_id_str(),
			"SellerWaitForBuyerRedeemPublish"
		);

		// Check if send message retyr does work as expected
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);
		swap::set_testing_cur_time(swap::get_cur_time() + 61 * 5);
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSendingInitRedeemMessage);
		seller.swap.ack_msg2();
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);

		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message1.clone()))
				.is_err(),
			true
		);
		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message2.clone()))
				.is_err(),
			true
		);
		assert_eq!(
			buyer
				.process(Input::IncomeMessage(message3.clone()))
				.is_err(),
			true
		);
		let res = buyer
			.process(Input::IncomeMessage(message4.clone()))
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
			.process(Input::IncomeMessage(message4.clone()))
			.unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

		test_responds(
			&mut buyer,
			StateId::BuyerRedeemMwc,
			Some((
				lock_second_message_round_timelimit + REDEEM_TIME,
				btc_lock_time_limit,
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
		);

		{
			// BRANCH - testing how seller can defend an attack. In worst case Buyer can manipulate with
			// seller  refund and buyer redeem transaction. Only one of them can be active, so we are chekcing if byer can switch from one to another
			buyer.pushs();
			seller.pushs();

			let lock_height = seller.swap.refund_slate.lock_height;

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
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

				let res = buyer.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				// Check retry at the same block...
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				assert_eq!(buyer.process(Input::Execute).is_err(), true); // For test node, repost doesn't work by some reasons
														  // We should be good now
				nc.mine_block();
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				let state_with_redeem = nc.get_state();

				// Do roll back
				nc.set_state(&nc_state_ready);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				// Switch to exist data
				nc.set_state(&state_with_redeem);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				// Do roll back & publish
				nc.set_state(&nc_state_ready);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				let res = buyer.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				buyer.pops();
			}

			{
				seller.pushs();
				// ----------------------------------------------------
				// Try scenario: Do Refund with reties. Buyer does nothing.
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				assert_eq!(res.action.unwrap().get_id_str(), "SellerPublishMwcRefundTx");
				assert_eq!(res.time_limit.is_none(), true);
				let res = seller.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);
				assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
				assert_eq!(res.time_limit.is_none(), true);
				// Let's do retry cycle. for the post
				// Still waiting, no retry
				let res = seller.process(Input::Check).unwrap();
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
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				nc.mine_blocks(2);
				// Now transaction is visible, we don't need to repost any more. Let's check how we handle that.
				let res = seller.process(Input::Check).unwrap();
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
				let res = seller.process(Input::Check).unwrap();
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
				let res = buyer.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				assert_eq!(res.action.unwrap().get_id_str(), "WaitForMwcConfirmations");
				assert_eq!(res.time_limit.is_none(), true);
				// Seller doesn't see the transaction yet
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				nc.mine_blocks(1);
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);

				// Let's mwc chain to loos all data, it shoudn't affect anything at that stage
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				// Check if refund was posted...
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
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
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
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
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
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
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);

				// At complete step - there is no more retrys
				nc.set_state(&nc_state_ready);
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
				nc.mine_block();
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
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

			{
				// Scenario. Seller publishing Refund, rollback and Buyer publishing redeem.
				// Rollback and Seller publishing Refund and does redeem.
				// Rollback and Buyer publishing redeem.
				// Both party need to finish the deal as expected.
				buyer.pushs();
				seller.pushs();

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);
				let res = seller.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				nc.mine_block();
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				// Check if Buyer can't publish tx
				assert_eq!(buyer.process(Input::Execute).is_err(), true);

				// let's rollback. So buyer can publish...
				// Validate seller retry logic first...
				let res = seller.process(Input::Check).unwrap();
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

					let res = seller.process(Input::Check).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerPostingRefundSlate);

					let res = buyer.process(Input::Execute).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::BuyerWaitForRedeemMwcConfirmations
					);

					nc.mine_block();

					let res = seller.process(Input::Check).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
					let res = seller.process(Input::Execute).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);

					// Checking seller retry logic for Secondary redeem
					let res = seller.process(Input::Check).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					// reset data
					let btc_state_posted = btc_nc.get_state();
					btc_nc.set_state(&btc_state_ready);
					let res = seller.process(Input::Check).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					// timeout is over, shold switch to post state
					swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
					let res = seller.process(Input::Check).unwrap();
					assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
					// let's recover the network.
					btc_nc.set_state(&btc_state_posted);
					let res = seller.process(Input::Check).unwrap();
					assert_eq!(
						res.next_state_id,
						StateId::SellerWaitingForRedeemConfirmations
					);
					btc_nc.mine_block();
					let res = buyer.process(Input::Check).unwrap();
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
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRefundConfirmations
				);

				let res = buyer.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				nc.mine_block();

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				let res = seller.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				let res = buyer.process(Input::Check).unwrap();
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
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);

				swap::set_testing_cur_time(swap::get_cur_time() + 60 * 6);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					false
				);
				let res = seller.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);
				let res = seller.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				// Checking that seller can redeem both BTC and MWC
				nc.mine_blocks(1);
				assert_eq!(
					nc.get_kernel(
						&seller.swap.refund_slate.tx.body.kernels[0].excess,
						None,
						None
					)
					.unwrap()
					.is_some(),
					true
				);
				// Attacker Buyer lost everything. His fault, seller was able to protect himself.
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				assert_eq!(buyer.process(Input::Execute).is_err(), true);

				// Another rollback. Now Buyer redeem MWC, seller continue to redeem BTC.
				nc.set_state(&nc_state_ready);
				nc.mine_blocks(2);

				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);
				let res = buyer.process(Input::Execute).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);
				nc.mine_block();
				btc_nc.mine_block();

				let res = seller.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				let res = buyer.process(Input::Check).unwrap();
				assert_eq!(
					res.next_state_id,
					StateId::BuyerWaitForRedeemMwcConfirmations
				);

				seller.pops();
				buyer.pops();
			}

			seller.pops();
			buyer.pops();
			// END of branch
		}

		// Now let's finish with happy path
		// At this point Buyer Can reed, seller is waiting for this moment

		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerWaitingForBuyerToRedeemMwc);

		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerRedeemMwc);

		// Let's buyer to redeem
		let res = buyer.process(Input::Execute).unwrap();
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
			.process(Input::IncomeMessage(message4.clone()))
			.unwrap();
		assert_eq!(
			res.next_state_id,
			StateId::BuyerWaitForRedeemMwcConfirmations
		);

		let res = seller.process(Input::Check).unwrap();
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
		);
		let res = seller.process(Input::Check).unwrap();
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
		);

		let res = seller.process(Input::Execute).unwrap();
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

			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);

			swap::set_testing_cur_time(cur_time * 61 * 5);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);
			// Changing fees, expecting to switch back to the posting
			seller.swap.secondary_fee = 12.0;
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(res.next_state_id, StateId::SellerRedeemSecondaryCurrency);

			swap::set_testing_cur_time(cur_time);
			seller.pops();
		}

		// Bith party waiting for confirmations
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
		);

		{
			// BRANCH - check if seller unable to resubmit the Secondary transaction. It is already mined
			// Checking if resubmit works
			seller.pushs();
			let cur_time = swap::get_cur_time();

			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);

			swap::set_testing_cur_time(cur_time * 61 * 5);
			let res = seller.process(Input::Check).unwrap();
			assert_eq!(
				res.next_state_id,
				StateId::SellerWaitingForRedeemConfirmations
			);
			// Changing fees, because Tx is already mined, nothing should happen
			seller.swap.secondary_fee = 12.0;
			let res = seller.process(Input::Check).unwrap();
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
		);

		// Final step
		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
		assert_eq!(res.action.is_none(), true);
		assert_eq!(res.time_limit.is_none(), true);

		let res = buyer.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::BuyerSwapComplete);
		assert_eq!(res.action.is_none(), true);
		assert_eq!(res.time_limit.is_none(), true);

		let res = seller.process(Input::Check).unwrap();
		assert_eq!(res.next_state_id, StateId::SellerSwapComplete);
		let res = buyer.process(Input::Check).unwrap();
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
		);
	}
}
