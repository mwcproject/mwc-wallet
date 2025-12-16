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

use crate::swap::types::Currency;
use crate::swap::Error;
use bitcoin::consensus::Decodable;
use bitcoin::{OutPoint, Transaction, Txid};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::mem;
use std::sync::Arc;
use std::sync::Mutex;

/// Single BTC output
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub struct Output {
	/// A reference to a bitcoin transaction output
	#[serde(with = "OutPointRef")]
	pub out_point: OutPoint,
	/// BTC Output value
	pub value: u64,
	/// BTC Output  height
	pub height: u64,
}

/// Serialization for bitcoin::OutPoint. Helper
#[derive(Serialize, Deserialize, Debug)]
#[serde(remote = "OutPoint")]
struct OutPointRef {
	pub txid: Txid,
	pub vout: u32,
}

impl PartialEq for Output {
	fn eq(&self, other: &Output) -> bool {
		self.out_point == other.out_point
	}
}

impl Hash for Output {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.out_point.hash(state);
	}
}

/// Bitcoin node client
pub trait BtcNodeClient: Sync + Send + 'static {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String;
	/// Get node height
	fn height(&mut self) -> Result<u64, Error>;
	/// Get unspent outputs for the address
	fn unspent(
		&mut self,
		context_id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error>;
	/// Post BTC tranaction,
	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error>;
	/// Get BTC transaction info.
	/// Return (height)
	/// Note: we can't return transaction because it is not Only BTC now, so we don't have parser
	/// to handle all possible coins. ZCash Tx is not parcable by BTC
	fn transaction(
		&mut self,
		tx_hash: &Txid, // tx hash
	) -> Result<Option<u64>, Error>;
}

/// Mock BTC node for the testing
#[derive(Debug, Clone)]
pub struct TestBtcNodeClientState {
	/// current height
	pub height: u64,
	/// Transactions to heights
	pub tx_heights: HashMap<Txid, u64>,
	/// Mined transactions
	pub txs: HashMap<Txid, Transaction>,
	/// Pending transactions
	pub pending: HashMap<Txid, Transaction>,
}

/// Mock BTC node client
#[derive(Debug, Clone)]
pub struct TestBtcNodeClient {
	/// mock node state
	pub state: Arc<Mutex<TestBtcNodeClientState>>,
}

impl TestBtcNodeClient {
	/// Create an instance at height
	pub fn new(height: u64) -> Self {
		Self {
			state: Arc::new(Mutex::new(TestBtcNodeClientState {
				height,
				tx_heights: HashMap::new(),
				txs: HashMap::new(),
				pending: HashMap::new(),
			})),
		}
	}

	/// Add 'mined' transaction
	pub fn push_transaction(&self, transaction: &Transaction) {
		let mut state = self.state.lock().expect("Mutex failure");
		let height = state.height;

		let txid = transaction.txid();
		state.tx_heights.insert(txid.clone(), height);
		state.txs.insert(txid, transaction.clone());
	}

	/// Add tx into the mem pool transaction
	pub fn post_transaction(&self, transaction: &Transaction) {
		let mut state = self.state.lock().expect("Mutex failure");
		let txid = transaction.txid();
		state.pending.insert(txid.clone(), transaction.clone());
	}

	/// Mine a new block. All oending transacitons will be included
	pub fn mine_block(&self) {
		self.mine_block_impl(true);
	}

	/// Mine block and not include any pending transactions
	pub fn mine_block_no_pending(&self) {
		self.mine_block_impl(false);
	}

	fn mine_block_impl(&self, include_pending: bool) {
		let mut state = self.state.lock().expect("Mutex failure");
		state.height += 1;
		let height = state.height;

		if include_pending {
			let pending = mem::replace(&mut state.pending, HashMap::new());
			for (txid, tx) in pending {
				state.tx_heights.insert(txid.clone(), height);
				state.txs.insert(txid, tx);
			}
		}
	}

	/// Mine several blocks
	pub fn mine_blocks(&self, count: u64) {
		if count > 0 {
			self.mine_block();
			if count > 1 {
				let mut state = self.state.lock().expect("Mutex failure");
				state.height += count - 1;
			}
		}
	}

	/// Mine several blocks but not include any pending transactions.
	pub fn mine_blocks_no_pending(&self, count: u64) {
		if count > 0 {
			self.mine_block_no_pending();
			if count > 1 {
				let mut state = self.state.lock().expect("Mutex failure");
				state.height += count - 1;
			}
		}
	}

	/// Get a current state for the test chain
	pub fn get_state(&self) -> TestBtcNodeClientState {
		self.state.lock().expect("Mutex failure").clone()
	}

	/// Set a state for the test chain
	pub fn set_state(&self, chain_state: &TestBtcNodeClientState) {
		let mut state = self.state.lock().expect("Mutex failure");
		*state = chain_state.clone();
	}

	/// Clean the data, not height. Reorg attack
	pub fn clean(&self) {
		let mut state = self.state.lock().expect("Mutex failure");
		state.pending.clear();
		state.tx_heights.clear();
		state.txs.clear();
	}
}

impl BtcNodeClient for TestBtcNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		String::from("BTC test client")
	}

	fn height(&mut self) -> Result<u64, Error> {
		Ok(self.state.lock().expect("Mutex failure").height)
	}

	fn unspent(
		&mut self,
		context_id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error> {
		let state = self.state.lock().expect("Mutex failure");
		let script_pubkey = currency.address_2_script_pubkey(context_id, address)?;

		let mut outputs = Vec::new();
		for (txid, tx) in &state.txs {
			let height = *state.tx_heights.get(txid).unwrap();
			for idx in 0..tx.output.len() {
				let o = &tx.output[idx];
				if o.script_pubkey == script_pubkey {
					outputs.push(Output {
						out_point: OutPoint {
							txid: txid.clone(),
							vout: idx as u32,
						},
						value: o.value,
						height,
					});
				}
			}
		}

		for (txid, tx) in &state.pending {
			for idx in 0..tx.output.len() {
				let o = &tx.output[idx];
				if o.script_pubkey == script_pubkey {
					outputs.push(Output {
						out_point: OutPoint {
							txid: txid.clone(),
							vout: idx as u32,
						},
						value: o.value,
						height: 0,
					});
				}
			}
		}

		Ok(outputs)
	}

	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		let mut state = self.state.lock().expect("Mutex failure");

		let cursor = Cursor::new(tx);
		let tx = Transaction::consensus_decode(cursor).map_err(|e| {
			Error::ElectrumNodeClient(format!("Unable to parse transaction, {}", e))
		})?;

		let txid = tx.txid();
		/* It is expected, transaction repost does work, especially if fees are different...
		if state.pending.contains_key(&txid) {
			return Err(Error::ElectrumNodeClient("Already in mempool".into()));
		}*/
		if state.txs.contains_key(&txid) {
			return Err(Error::ElectrumNodeClient("Already in chain".into()));
		}

		let verify_fn = |out_point: &OutPoint| match state.txs.get(&out_point.txid) {
			Some(tx) => match tx.output.get(out_point.vout as usize) {
				Some(out) => Some(out.clone()),
				None => None,
			},
			None => None,
		};

		tx.verify(verify_fn)
			.map_err(|e| Error::ElectrumNodeClient(format!("{}", e)))?;
		state.pending.insert(txid, tx.clone());

		Ok(())
	}

	fn transaction(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let state = self.state.lock().expect("Mutex failure");

		if state.pending.contains_key(tx_hash) {
			return Ok(Some(0));
		}

		let res = match state.txs.get(tx_hash) {
			Some(_tx) => state.tx_heights.get(tx_hash).map(|h| *h),
			None => None,
		};
		Ok(res)
	}
}
