// Copyright 2021 The MWC Developers
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

use crate::grin_util::Mutex;
use crate::swap::types::Currency;
use crate::swap::ErrorKind;
use secp256k1::SecretKey;
use std::sync::Arc;
use std::{collections::HashMap, u64};
use web3::types::{Address, TransactionReceipt, H256};

use super::to_eth_address;

/// Ethereum node client
pub trait EthNodeClient: Sync + Send + 'static {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String;
	/// Get node height
	fn height(&self) -> Result<u64, ErrorKind>;
	/// Get balance for the address
	fn balance(&self, currency: Currency) -> Result<(String, u64), ErrorKind>;
	/// Retrieve receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, ErrorKind>;
	/// Send coins to destination account
	fn transfer(&self, to: Address, value: u64) -> Result<H256, ErrorKind>;
	/// initiate swap
	fn initiate(
		&self,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
	) -> Result<H256, ErrorKind>;
	/// redeem ether
	fn redeem(
		&self,
		address_from_secret: Address,
		secret_key: SecretKey,
	) -> Result<H256, ErrorKind>;
	/// refund ether
	fn refund(&self, address_from_secret: Address) -> Result<H256, ErrorKind>;
	/// get swap info
	fn get_swap_details(
		&self,
		address_from_secret: Address,
	) -> Result<(u64, Address, Address, u64), ErrorKind>;
}

/// Mock Eth node for the testing
#[derive(Debug, Clone)]
pub struct TestEthNodeClientState {
	/// current height
	pub height: u64,
}

/// Mock ETH node client
#[derive(Debug, Clone)]
pub struct TestEthNodeClient {
	/// mock node state
	pub state: Arc<Mutex<TestEthNodeClientState>>,
	/// swap HashMap
	pub swap_store: Arc<Mutex<HashMap<Address, (u64, Address, Address, u64)>>>,
	/// txs HashMap
	pub tx_store: Arc<Mutex<HashMap<H256, String>>>,
}

impl TestEthNodeClient {
	/// Create an instance at height
	pub fn new(height: u64) -> Self {
		Self {
			state: Arc::new(Mutex::new(TestEthNodeClientState { height })),
			swap_store: Arc::new(Mutex::new(HashMap::with_capacity(10))),
			tx_store: Arc::new(Mutex::new(HashMap::with_capacity(10))),
		}
	}

	/// Get a current state for the test chain
	pub fn get_state(&self) -> TestEthNodeClientState {
		self.state.lock().clone()
	}

	/// Set a state for the test chain
	pub fn set_state(&self, chain_state: &TestEthNodeClientState) {
		let mut state = self.state.lock();
		*state = chain_state.clone();
	}

	/// Clean the data, not height. Reorg attack
	pub fn clean(&self) {
		// let mut state = self.state.lock();
	}
}

impl EthNodeClient for TestEthNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		String::from("ETH test client")
	}

	/// Fetch the current chain height
	fn height(&self) -> Result<u64, ErrorKind> {
		Ok(self.state.lock().height)
	}

	/// get wallet balance
	fn balance(&self, _currency: Currency) -> Result<(String, u64), ErrorKind> {
		Ok(("1.00".to_string(), 1_000_000_000_000_000_000u64))
	}

	/// Retrieve receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, ErrorKind> {
		let receipt_str = r#"{
			"blockHash": "0x83eaba432089a0bfe99e9fc9022d1cfcb78f95f407821be81737c84ae0b439c5",
			"blockNumber": "0x38",
			"contractAddress": "0x03d8c4566478a6e1bf75650248accce16a98509f",
			"cumulativeGasUsed": "0x927c0",
			"gasUsed": "0x927c0",
			"logs": [],
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"root": null,
			"transactionHash": "0x422fb0d5953c0c48cbb42fb58e1c30f5e150441c68374d70ca7d4f191fd56f26",
			"transactionIndex": "0x0",
			"status": "0x1"
		}"#;

		let mut receipt: TransactionReceipt = serde_json::from_str(receipt_str).unwrap();
		receipt.transaction_hash = tx_hash;
		Ok(receipt)
	}

	/// Send coins
	fn transfer(&self, _to: Address, _value: u64) -> Result<H256, ErrorKind> {
		unimplemented!()
	}

	/// initiate swap offer
	fn initiate(
		&self,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
	) -> Result<H256, ErrorKind> {
		//todo need to check balance
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			return Err(ErrorKind::InvalidEthSwapTradeIndex);
		}
		store.insert(
			address_from_secret,
			(
				refund_time,
				to_eth_address("0xAB90ddDF7bdff0e4FCAB3c9bF608393a6C7e2390".to_string()).unwrap(),
				participant,
				value,
			),
		);
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([1u8; 32]), "initiate".to_string());
			Ok(H256::from([1u8; 32]))
		} else {
			Ok(H256::zero())
		}
	}

	/// ether buyer redeem
	fn redeem(
		&self,
		address_from_secret: Address,
		_secret_key: SecretKey,
	) -> Result<H256, ErrorKind> {
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([2u8; 32]), "redeem".to_string());
			store.remove(&address_from_secret);
			Ok(H256::from([2u8; 32]))
		} else {
			Ok(H256::zero())
		}
	}

	/// refund ether
	fn refund(&self, address_from_secret: Address) -> Result<H256, ErrorKind> {
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([3u8; 32]), "refund".to_string());
			store.remove(&address_from_secret);
			Ok(H256::from([3u8; 32]))
		} else {
			Ok(H256::zero())
		}
	}

	/// get swap info
	fn get_swap_details(
		&self,
		address_from_secret: Address,
	) -> Result<(u64, Address, Address, u64), ErrorKind> {
		let store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			Ok(store[&address_from_secret])
		} else {
			Err(ErrorKind::InvalidEthSwapTradeIndex)
		}
	}
}
