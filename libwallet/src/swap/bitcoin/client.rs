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
use bitcoin::{OutPoint, Script, Transaction, Txid};
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::Mutex;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::mem;
use std::sync::Arc;

/// Single BTC output
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
#[serde(crate = "serde")]
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
#[serde(crate = "serde")]
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

/// Convert a secondary-chain output height into confirmations at `tip`.
///
/// A zero height denotes a mempool transaction. A height above the observed
/// tip can occur when separate Electrum reads straddle a new block or a reorg;
/// treating that observation as unconfirmed is conservative and lets the next
/// poll reconcile it instead of turning the race into an arithmetic error.
pub(crate) fn secondary_confirmations_at_tip(tip: u64, height: u64) -> u64 {
	if height == 0 {
		return 0;
	}

	tip.checked_sub(height)
		.and_then(|blocks_before_tip| blocks_before_tip.checked_add(1))
		.unwrap_or(0)
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

	/// Identify mining rewards before accepting funding that may still be immature.
	/// Missing transactions or unavailable metadata must return an error, not false.
	fn transaction_is_coinbase(&mut self, _tx_hash: &Txid) -> Result<bool, Error> {
		Err(Error::ElectrumNodeClient(
			"Coinbase lookup is not supported by this backend".into(),
		))
	}

	/// Return the number of confirmations for a known transaction. `Some(0)`
	/// means that the transaction is known but unconfirmed, while `None` means
	/// that the backend does not know it.
	///
	/// Implementations whose RPC exposes confirmations directly should override
	/// this method. The default preserves compatibility with height-based
	/// clients and reads the tip after the transaction height so forward chain
	/// movement can only make the result conservative.
	fn transaction_confirmations(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let height = match self.transaction(tx_hash)? {
			Some(height) => height,
			None => return Ok(None),
		};
		if height == 0 {
			return Ok(Some(0));
		}

		let tip = self.height()?;
		Ok(Some(secondary_confirmations_at_tip(tip, height)))
	}

	/// Find the confirmed transaction spending an output, using its script's
	/// history, and return its bytes decoded as a BTC-family transaction together
	/// with its confirmation count. Recovery must validate it against a saved
	/// attempt before treating it as a refund or redemption. Unsupported backends
	/// fail explicitly instead of silently missing a confirmed, malleated spend.
	fn confirmed_spend(
		&mut self,
		_outpoint: &OutPoint,
		_script_pubkey: &Script,
	) -> Result<Option<(Transaction, u64)>, Error> {
		Err(Error::ElectrumNodeClient(
			"Confirmed spend lookup is not supported by this backend".into(),
		))
	}
}

/// Mock BTC node for the testing
#[derive(Debug, Clone)]
pub struct TestBtcNodeClientState {
	/// current height
	pub height: u64,
	/// Inject an unavailable secondary RPC service.
	pub height_error: Option<String>,
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
				height_error: None,
				tx_heights: HashMap::new(),
				txs: HashMap::new(),
				pending: HashMap::new(),
			})),
		}
	}

	/// Add 'mined' transaction
	pub fn push_transaction(&self, transaction: &Transaction) -> Result<(), Error> {
		let mut state = self.state.lock();
		let height = state.height;

		let txid = transaction.txid()?;
		state.tx_heights.insert(txid.clone(), height);
		state.txs.insert(txid, transaction.clone());
		Ok(())
	}

	/// Add tx into the mem pool transaction
	pub fn post_transaction(&self, transaction: &Transaction) -> Result<(), Error> {
		let mut state = self.state.lock();
		let txid = transaction.txid()?;
		state.pending.insert(txid.clone(), transaction.clone());
		Ok(())
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
		let mut state = self.state.lock();
		// The in-memory test chain intentionally clamps at the maximum synthetic height.
		state.height = state.height.saturating_add(1);
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
				let mut state = self.state.lock();
				// The in-memory test chain intentionally clamps oversized synthetic advances.
				state.height = state.height.saturating_add(count - 1);
			}
		}
	}

	/// Mine several blocks but not include any pending transactions.
	pub fn mine_blocks_no_pending(&self, count: u64) {
		if count > 0 {
			self.mine_block_no_pending();
			if count > 1 {
				let mut state = self.state.lock();
				// The in-memory test chain intentionally clamps oversized synthetic advances.
				state.height = state.height.saturating_add(count - 1);
			}
		}
	}

	/// Get a current state for the test chain
	pub fn get_state(&self) -> TestBtcNodeClientState {
		self.state.lock().clone()
	}

	/// Set a state for the test chain
	pub fn set_state(&self, chain_state: &TestBtcNodeClientState) {
		let mut state = self.state.lock();
		*state = chain_state.clone();
	}

	/// Clean the data, not height. Reorg attack
	pub fn clean(&self) {
		let mut state = self.state.lock();
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
		let state = self.state.lock();
		if let Some(error) = &state.height_error {
			return Err(Error::Generic(error.clone()));
		}
		Ok(state.height)
	}

	fn unspent(
		&mut self,
		context_id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error> {
		let state = self.state.lock();
		let script_pubkey = currency.address_2_script_pubkey(context_id, address)?;

		let mut outputs = Vec::new();
		for (txid, tx) in &state.txs {
			let height = *state.tx_heights.get(txid).ok_or(Error::Generic(format!(
				"Not found expected data for {txid} at tx_heights"
			)))?;
			for (idx, o) in tx.output.iter().enumerate() {
				if o.script_pubkey == script_pubkey {
					let vout = u32::try_from(idx).map_err(|e| {
						Error::DataOverflow(format!(
							"TestBtcNodeClient::unspent, bitcoin transaction output index exceeds u32, output_index={} error={}",
							idx, e
						))
					})?;
					outputs.push(Output {
						out_point: OutPoint {
							txid: txid.clone(),
							vout,
						},
						value: o.value,
						height,
					});
				}
			}
		}

		for (txid, tx) in &state.pending {
			for (idx, o) in tx.output.iter().enumerate() {
				if o.script_pubkey == script_pubkey {
					let vout = u32::try_from(idx).map_err(|e| {
						Error::DataOverflow(format!(
							"TestBtcNodeClient::unspent, pending bitcoin transaction output index exceeds u32, output_index={} error={}",
							idx, e
						))
					})?;
					outputs.push(Output {
						out_point: OutPoint {
							txid: txid.clone(),
							vout,
						},
						value: o.value,
						height: 0,
					});
				}
			}
		}

		// Exclude outputs spent by confirmed or pending transactions.
		let spent: HashSet<OutPoint> = state
			.txs
			.values()
			.chain(state.pending.values())
			.flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
			.collect();
		outputs.retain(|output| !spent.contains(&output.out_point));

		Ok(outputs)
	}

	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		let mut state = self.state.lock();

		let cursor = Cursor::new(tx);
		let tx = Transaction::consensus_decode(cursor).map_err(|e| {
			Error::ElectrumNodeClient(format!("Unable to parse transaction, {}", e))
		})?;

		let txid = tx.txid()?;
		/* It is expected, transaction repost does work, especially if fees are different...
		if state.pending.contains_key(&txid) {
			return Err(Error::ElectrumNodeClient("Already in mempool".into()));
		}*/
		if state.txs.contains_key(&txid) {
			return Err(Error::ElectrumNodeClient("Already in chain".into()));
		}

		let spent_output = |out_point: &OutPoint| match state.txs.get(&out_point.txid) {
			// u32-to-usize is lossless on every supported target (minimum 32-bit usize).
			#[allow(
				clippy::cast_possible_truncation,
				reason = "the project supports only targets with usize at least 32 bits"
			)]
			Some(tx) => match tx.output.get(out_point.vout as usize) {
				Some(out) => Some(out.clone()),
				None => None,
			},
			None => None,
		};

		let mut input_value = 0_u64;
		for input in &tx.input {
			let output = spent_output(&input.previous_output).ok_or_else(|| {
				Error::ElectrumNodeClient(format!("Unknown spent output {}", input.previous_output))
			})?;
			input_value = input_value.checked_add(output.value).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TestBtcNodeClient::post_tx, transaction input value overflow, accumulated_input_value={} output_value={}",
					input_value, output.value
				))
			})?;
		}
		let output_value = tx.output.iter().try_fold(0_u64, |total, output| {
			total.checked_add(output.value).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TestBtcNodeClient::post_tx, transaction output value overflow, accumulated_output_value={} output_value={}",
					total, output.value
				))
			})
		})?;
		if output_value > input_value {
			return Err(Error::ElectrumNodeClient(
				"Transaction outputs exceed inputs".to_owned(),
			));
		}
		state.pending.insert(txid, tx.clone());

		Ok(())
	}

	fn transaction(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let state = self.state.lock();

		if state.pending.contains_key(tx_hash) {
			return Ok(Some(0));
		}

		let res = match state.txs.get(tx_hash) {
			Some(_tx) => state.tx_heights.get(tx_hash).map(|h| *h),
			None => None,
		};
		Ok(res)
	}

	fn transaction_is_coinbase(&mut self, tx_hash: &Txid) -> Result<bool, Error> {
		let state = self.state.lock();
		let tx = state
			.txs
			.get(tx_hash)
			.or_else(|| state.pending.get(tx_hash))
			.ok_or_else(|| {
				Error::ElectrumNodeClient(format!("Funding transaction {tx_hash} is missing"))
			})?;
		Ok(tx.is_coin_base())
	}

	fn transaction_confirmations(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let state = self.state.lock();

		if state.pending.contains_key(tx_hash) {
			return Ok(Some(0));
		}

		Ok(match state.txs.get(tx_hash) {
			Some(_) => state
				.tx_heights
				.get(tx_hash)
				.map(|height| secondary_confirmations_at_tip(state.height, *height)),
			None => None,
		})
	}

	fn confirmed_spend(
		&mut self,
		outpoint: &OutPoint,
		_script_pubkey: &Script,
	) -> Result<Option<(Transaction, u64)>, Error> {
		let state = self.state.lock();
		for (txid, tx) in &state.txs {
			if tx
				.input
				.iter()
				.any(|input| input.previous_output == *outpoint)
			{
				let height = state.tx_heights.get(txid).ok_or_else(|| {
					Error::Generic(format!("Missing height for confirmed spend {txid}"))
				})?;
				let confirmations = secondary_confirmations_at_tip(state.height, *height);
				if confirmations > 0 {
					return Ok(Some((tx.clone(), confirmations)));
				}
			}
		}
		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use super::secondary_confirmations_at_tip;
	use super::{BtcNodeClient, Currency, OutPoint, Script, TestBtcNodeClient, Transaction};
	use mwc_wallet_util::mwc_bitcoin::{consensus::serialize, TxIn, TxOut};

	#[test]
	fn unspent_excludes_pending_and_confirmed_spends() {
		let mut client = TestBtcNodeClient::new(500_000);
		let address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string();
		let funding = Transaction {
			version: 2,
			lock_time: 0,
			input: vec![],
			output: vec![
				TxOut {
					value: 100_000,
					script_pubkey: Currency::Btc.address_2_script_pubkey(0, &address).unwrap(),
				};
				2
			],
		};
		client.push_transaction(&funding).unwrap();
		assert_eq!(client.unspent(0, Currency::Btc, &address).unwrap().len(), 2);

		let funding_txid = funding.txid().unwrap();
		let spending = Transaction {
			version: 2,
			lock_time: 0,
			input: vec![TxIn {
				previous_output: OutPoint::new(funding_txid, 0),
				script_sig: Script::new(),
				sequence: u32::MAX,
				witness: vec![],
			}],
			output: vec![TxOut {
				value: 90_000,
				script_pubkey: Script::new(),
			}],
		};
		client.post_tx(serialize(&spending).unwrap()).unwrap();

		// The untouched output remains available both before and after mining.
		for confirmed in [false, true] {
			if confirmed {
				client.mine_block();
			}
			let outputs = client.unspent(0, Currency::Btc, &address).unwrap();
			assert_eq!(outputs.len(), 1, "confirmed={confirmed}");
			assert_eq!(outputs[0].out_point, OutPoint::new(funding_txid, 1));
		}
	}

	#[test]
	fn secondary_confirmation_count_is_conservative_for_ahead_heights() {
		assert_eq!(secondary_confirmations_at_tip(100, 0), 0);
		assert_eq!(secondary_confirmations_at_tip(100, 101), 0);
		assert_eq!(secondary_confirmations_at_tip(100, 100), 1);
		assert_eq!(secondary_confirmations_at_tip(100, 99), 2);
	}
}
