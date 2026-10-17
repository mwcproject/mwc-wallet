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

use super::client::*;
use super::rpc::*;
use crate::swap::Error;
use crate::swap::types::Currency;
use bitcoin::{OutPoint, Script, Transaction, Txid};
use mwc_wallet_util::bitcoin_hashes::sha256d::Hash;
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_crates::log::debug;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::sha2::{Digest, Sha256};
use mwc_wallet_util::mwc_util::{from_hex, to_hex};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::mem::replace;
use std::str::FromStr;
use std::time::{Duration, Instant};

struct ElectrumRpcClient {
	inner: RpcClient,
	id: u32,
}

enum ElectrumError {
	Response(ElectrumResponseError),
	Other(Error),
}

impl From<Error> for ElectrumError {
	fn from(error: Error) -> ElectrumError {
		ElectrumError::Other(error)
	}
}

impl From<ElectrumResponseError> for ElectrumError {
	fn from(error: ElectrumResponseError) -> ElectrumError {
		ElectrumError::Response(error)
	}
}

impl From<ElectrumError> for Error {
	fn from(error: ElectrumError) -> Error {
		match error {
			ElectrumError::Response(e) => {
				Error::ElectrumNodeClient(format!("ElectrumX error response: {}", e.message))
			}
			ElectrumError::Other(e) => e,
		}
	}
}

impl ElectrumRpcClient {
	pub fn new(address: String) -> Result<Self, Error> {
		let mut client = Self {
			inner: RpcClient::new(address)?,
			id: 0,
		};
		client.version()?;

		Ok(client)
	}

	pub fn is_connected(&self) -> bool {
		self.inner.is_connected()
	}

	fn wait<T: for<'de> Deserialize<'de>>(&mut self, id: String) -> Result<T, ElectrumError> {
		let res = self.inner.read()?;
		match res {
			RpcResponse::ResponseErr(e) => {
				if e.id.map(|res_id| res_id == id).unwrap_or(true) {
					let err: ElectrumResponseError =
						serde_json::from_value(e.error).map_err(|e| {
							Error::ElectrumNodeClient(format!("ElectrumX error response, {}", e))
						})?;
					return Err(err.into());
				}
			}
			RpcResponse::ResponseOk(o) => {
				debug!("Get a response back: {:?}", o);
				if o.id.map(|res_id| res_id == id).unwrap_or(false) {
					let res_copy = o.result.clone();
					let obj: T = serde_json::from_value(o.result).map_err(|e| {
						Error::ElectrumNodeClient(format!(
							"Unable to decode response '{}', {}",
							res_copy, e
						))
					})?;
					return Ok(obj);
				}
			}
		};
		Err(Error::ElectrumNodeClient(format!("No response received")).into())
	}

	fn next_id(&mut self) -> u32 {
		self.id = self.id.wrapping_add(1);
		self.id
	}

	fn version(&mut self) -> Result<Vec<String>, Error> {
		let params = VersionRequestParams::new("Electrum 3.3.8".into(), "1.4".into());
		let request = RpcRequest::new(self.next_id(), "server.version", params)?;
		self.write(&request)?;
		let version: Vec<String> = self.wait(request.id)?;
		Ok(version)
	}

	fn write(&mut self, request: &RpcRequest) -> Result<(), Error> {
		self.inner.write(request)
	}

	pub fn unspent(&mut self, script_pubkey: &Script) -> Result<Vec<Utxo>, Error> {
		let params = ScriptHashParams::new(script_pubkey);
		let request = RpcRequest::new(self.next_id(), "blockchain.scripthash.listunspent", params)?;
		self.write(&request)?;
		let utxos: Vec<Utxo> = self.wait(request.id)?;

		Ok(utxos)
	}

	fn history(&mut self, script_pubkey: &Script) -> Result<Vec<HistoryEntry>, Error> {
		let params = ScriptHashParams::new(script_pubkey);
		let request = RpcRequest::new(self.next_id(), "blockchain.scripthash.get_history", params)?;
		self.write(&request)?;
		Ok(self.wait(request.id)?)
	}

	pub fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		let params = BroadcastParams::new(tx);
		let request = RpcRequest::new(self.next_id(), "blockchain.transaction.broadcast", params)?;
		self.write(&request)?;
		let hash: String = self.wait(request.id)?;
		let hash = from_hex(hash.as_str()).map_err(|e| {
			Error::ElectrumNodeClient(format!(
				"Unable to post tx, wrong hash value {}, {}",
				hash, e
			))
		})?;

		if hash.len() != 32 {
			return Err(Error::ElectrumNodeClient(format!(
				"Unable to post tx, wrong hash {:?}",
				hash
			)));
		}

		Ok(())
	}

	pub fn transaction(&mut self, tx_hash: String) -> Result<Option<ElectrumTransaction>, Error> {
		let params = TransactionParams::new(tx_hash);
		let request = RpcRequest::new(self.next_id(), "blockchain.transaction.get", params)?;
		self.write(&request)?;
		let tx: Result<ElectrumTransaction, ElectrumError> = self.wait(request.id);
		match tx {
			Ok(t) => Ok(Some(t)),
			Err(ElectrumError::Response(e)) => {
				if e.code == 2
					&& e.message
						.contains("No such mempool or blockchain transaction")
				{
					Ok(None)
				} else {
					Err(ElectrumError::Response(e).into())
				}
			}
			Err(ElectrumError::Other(e)) => Err(e),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct VersionRequestParams {
	client_name: String,
	protocol_version: String,
}

impl VersionRequestParams {
	pub fn new(client_name: String, protocol_version: String) -> Self {
		Self {
			client_name,
			protocol_version,
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct ScriptHashParams {
	scripthash: String,
}

impl ScriptHashParams {
	pub fn new(script_pubkey: &Script) -> Self {
		let mut hash = Sha256::digest(script_pubkey.as_bytes())[..].to_vec();
		hash.reverse();
		Self {
			scripthash: to_hex(&hash),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct TransactionParams {
	tx_hash: String,
	verbose: bool,
}

impl TransactionParams {
	pub fn new(tx_hash: String) -> Self {
		Self {
			tx_hash,
			verbose: true,
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct BroadcastParams {
	raw_tx: String,
}

impl BroadcastParams {
	pub fn new(tx: Vec<u8>) -> Self {
		Self {
			raw_tx: to_hex(&tx),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct Utxo {
	pub tx_hash: String,
	pub tx_pos: u32,
	pub value: u64,
	pub height: u64,
}

fn outputs_from_utxos(utxos: Vec<Utxo>) -> Result<Vec<Output>, Error> {
	let mut outputs: HashMap<OutPoint, Output> = HashMap::with_capacity(utxos.len());
	for utxo in utxos {
		let hash = Hash::from_str(&utxo.tx_hash).map_err(|e| {
			Error::ElectrumNodeClient(format!(
				"ElectrumX returned an invalid transaction hash: {}",
				e
			))
		})?;
		let out_point = OutPoint::new(Txid::from_byte_array(hash.to_byte_array()), utxo.tx_pos);
		let output = Output {
			out_point,
			value: utxo.value,
			height: utxo.height,
		};

		match outputs.entry(out_point) {
			Entry::Vacant(entry) => {
				entry.insert(output);
			}
			Entry::Occupied(entry) => {
				let previous = entry.get();
				if previous.value != output.value || previous.height != output.height {
					return Err(Error::ElectrumNodeClient(format!(
						"ElectrumX returned conflicting data for output {}: first value={} height={}, duplicate value={} height={}",
						previous.out_point,
						previous.value,
						previous.height,
						output.value,
						output.height
					)));
				}
			}
		}
	}

	let mut outputs: Vec<Output> = outputs.into_values().collect();
	outputs.sort_by(|left, right| {
		left.out_point
			.txid
			.cmp(&right.out_point.txid)
			.then_with(|| left.out_point.vout.cmp(&right.out_point.vout))
	});
	Ok(outputs)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct ElectrumTransaction {
	#[serde(default)]
	pub blockhash: Option<String>,
	#[serde(default)]
	pub blocktime: Option<u64>,
	#[serde(default)]
	pub confirmations: Option<u64>,
	pub hex: String,
	pub locktime: u64,
	pub size: u64,
	#[serde(default)]
	pub time: u64,
	pub version: u64,
	/// Spend discovery and coinbase classification require inputs. Height queries
	/// also work with backends that omit this part of the verbose response.
	#[serde(default)]
	pub vin: Option<Vec<ElectrumInput>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct ElectrumInput {
	// Coinbase inputs have neither field.
	pub txid: Option<Txid>,
	pub vout: Option<u32>,
	/// Mining reward input script from the verbose transaction response.
	pub coinbase: Option<String>,
}

impl ElectrumTransaction {
	fn is_coinbase(&self) -> Result<bool, Error> {
		let inputs = self.vin.as_ref().ok_or_else(|| {
			Error::ElectrumNodeClient("Transaction response is missing its inputs".into())
		})?;
		if let [input] = inputs.as_slice() {
			if input.coinbase.is_some() && input.txid.is_none() && input.vout.is_none() {
				return Ok(true);
			}
		}
		if !inputs.is_empty()
			&& inputs.iter().all(|input| {
				input.coinbase.is_none()
					&& matches!((input.txid, input.vout),
				(Some(txid), Some(vout)) if !OutPoint::new(txid, vout).is_null())
			}) {
			return Ok(false);
		}
		Err(Error::ElectrumNodeClient(
			"Transaction response has invalid inputs for coinbase classification".into(),
		))
	}
}

#[derive(Deserialize)]
#[serde(crate = "serde")]
struct HistoryEntry {
	tx_hash: Txid,
	// Electrum uses 0 and -1 for unconfirmed history entries.
	height: i64,
}

/// Electrum Bitcoin node client
/// Warning: this client doesn't perform any of the SPV checks,
/// it assumes the provided information is truthful
pub struct ElectrumNodeClient {
	/// ElectrumX URI (host:port)
	pub address: String,
	/// transaction at block 1. The number of confirmations must be equal to the height
	pub check_tx_hash: String,
	/// ElectrumX client
	client: Option<(ElectrumRpcClient, Instant)>,
}

impl ElectrumNodeClient {
	/// Create a new instance.
	/// address - it is URI for electrumX host    host:port
	pub fn new(address: String, check_tx_hash: String) -> Self {
		Self {
			address,
			check_tx_hash,
			client: None,
		}
	}
	/// Connect to the ElectrumX node
	pub fn connect(&mut self) -> Result<(), Error> {
		self.client()?;
		Ok(())
	}

	fn client(&mut self) -> Result<&mut ElectrumRpcClient, Error> {
		// Reset connection if it disconnected or if we haven't used it for a while
		if self
			.client
			.as_ref()
			.map(|(c, t)| !c.is_connected() || t.elapsed() >= Duration::from_secs(30))
			.unwrap_or(false)
		{
			self.client = None;
		}

		if self.client.is_none() {
			self.client = Some((
				ElectrumRpcClient::new(self.address.clone())?,
				Instant::now(),
			));
		}

		let (c, t) = self.client.as_mut().ok_or(Error::Generic(
			"Electrum client internal error, client is not initialized".into(),
		))?;
		let _previous_connection_time = replace(t, Instant::now());
		Ok(c)
	}
}

impl BtcNodeClient for ElectrumNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		self.address.clone()
	}

	/// Fetch the current chain height
	fn height(&mut self) -> Result<u64, Error> {
		// The proper way to do this is to download all the block headers
		// and validate them. Since we assume the server can be trusted,
		// instead we simply ask for the number of confirmations on the
		// coinbase output at height 1
		/*		let tx_hash = if self.testnet {
			"f0315ffc38709d70ad5647e22048358dd3745f3ce3874223c80a7c92fab0c8ba"
		} else {
			"0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
		}
		.to_owned();*/
		let hash = self.check_tx_hash.clone();
		let client = self.client()?;
		let tx = client.transaction(hash)?.ok_or(Error::ElectrumNodeClient(
			"Unable to determine height".into(),
		))?;
		tx.confirmations.ok_or(Error::ElectrumNodeClient(
			"Unable to determine height".into(),
		))
	}

	/// Fetch a list of unspent outputs belonging to this address
	fn unspent(
		&mut self,
		context_id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error> {
		// A full SPV client should validate the Merkle proofs of the transactions
		// that created these outputs
		let client = self.client()?;
		let script = if address.starts_with("bitcoin-script:") {
			// Converting back from the script... Address is a hex
			let prefix_len = "bitcoin-script:".len();
			// The fixed prefix length plus the four-character network marker is tiny.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "prefix_len is the fixed length of the bitcoin-script literal"
			)]
			let payload_start = prefix_len + 4;
			let payload_end = address
				.len()
				.checked_sub(8)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"ElectrumNodeClient::unspent, bitcoin-script address is too short, address_len={} checksum_len=8",
						address.len()
					))
				})?;
			if payload_end < payload_start {
				return Err(
					Error::Generic("bitcoin-script address is too short".to_owned()).into(),
				);
			}
			// https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki
			// The boundary check above proves payload_end >= payload_start.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "payload_end is checked not to precede payload_start"
			)]
			let payload_len = payload_end - payload_start;
			let script_hex: String = address
				.chars()
				.skip(payload_start)
				.take(payload_len)
				.collect();
			let script_bin = from_hex(&script_hex).map_err(|e| {
				Error::Generic(format!(
					"Unable to convert bitcoin-script address '{}' into Script hex, {}",
					address, e
				))
			})?;
			Script::from(script_bin)
		} else {
			currency.address_2_script_pubkey(context_id, address)?
		};

		let utxos = client.unspent(&script)?;

		// ElectrumX can return duplicate entries. Deduplicate only exact
		// OutPoints: one transaction may legitimately pay the swap script at
		// several different output indices.
		outputs_from_utxos(utxos)
	}
	/// Post BTC transaction
	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		let client = self.client()?;
		client.post_tx(tx)
	}
	/// Request a transaction from the node
	fn transaction(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let client = self.client()?;
		let tx = match client.transaction(format!("{}", tx_hash))? {
			Some(t) => t,
			None => return Ok(None),
		};

		let height = match tx.confirmations {
			Some(c) if c > 0 => {
				// Read the tip after the transaction. If a block arrives between
				// these calls, the derived height is conservative rather than being
				// placed ahead of the observed tip.
				let head_height = self.height()?;
				// The match guard proves the confirmation count is nonzero.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the match guard checks confirmations > 0"
				)]
				let blocks_before_tip = c - 1;
				Some(head_height.checked_sub(blocks_before_tip).ok_or_else(|| {
					Error::ElectrumNodeClient(format!(
						"Inconsistent ElectrumX transaction view: confirmation count exceeds chain height, head_height={} blocks_before_tip={}",
						head_height, blocks_before_tip
					))
				})?)
			}
			_ => Some(0),
		};
		Ok(height)
	}

	fn transaction_is_coinbase(&mut self, tx_hash: &Txid) -> Result<bool, Error> {
		self.client()?
			.transaction(tx_hash.to_string())?
			.ok_or_else(|| {
				Error::ElectrumNodeClient(format!("Funding transaction {tx_hash} is missing"))
			})?
			.is_coinbase()
	}

	fn transaction_confirmations(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let client = self.client()?;
		Ok(client
			.transaction(format!("{}", tx_hash))?
			.map(|tx| tx.confirmations.unwrap_or(0)))
	}

	fn confirmed_spend(
		&mut self,
		outpoint: &OutPoint,
		script_pubkey: &Script,
	) -> Result<Option<(Transaction, u64)>, Error> {
		let client = self.client()?;
		// A prepared transaction may not have been broadcast yet. Avoid walking
		// the entire history when its first input is still available.
		if outputs_from_utxos(client.unspent(script_pubkey)?)?
			.iter()
			.any(|output| output.out_point == *outpoint)
		{
			return Ok(None);
		}
		for entry in client.history(script_pubkey)? {
			if entry.height <= 0 || entry.tx_hash == outpoint.txid {
				continue;
			}
			let Some(tx) = client.transaction(entry.tx_hash.to_string())? else {
				// A reorg can remove a transaction after the history read.
				continue;
			};
			let confirmations = tx.confirmations.unwrap_or(0);
			if confirmations == 0 {
				continue;
			}
			let inputs = tx.vin.as_ref().ok_or_else(|| {
				Error::ElectrumNodeClient("Transaction response is missing its inputs".into())
			})?;
			if !inputs
				.iter()
				.any(|input| input.txid == Some(outpoint.txid) && input.vout == Some(outpoint.vout))
			{
				continue;
			}
			// Use verbose inputs only to locate the spend. Verify the raw bytes
			// and hash before returning it. Unrelated history can include special
			// coin-specific transactions that the BTC decoder does not support.
			let bytes = from_hex(&tx.hex).map_err(|error| {
				Error::ElectrumNodeClient(format!("Invalid confirmed spend bytes: {error}"))
			})?;
			let transaction: Transaction = bitcoin::consensus::deserialize(&bytes)?;
			if transaction.txid()? != entry.tx_hash
				|| !transaction
					.input
					.iter()
					.any(|input| input.previous_output == *outpoint)
			{
				return Err(Error::ElectrumNodeClient(
					"Confirmed spend does not match the requested transaction or input".into(),
				));
			}
			return Ok(Some((transaction, confirmations)));
		}
		Ok(None)
	}
}

/// ElectrumX client error response.
#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct ElectrumResponseError {
	code: i64,
	pub message: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	// Exercise the real JSON-RPC encoding and decoding over a local connection.
	// Each request must match the expected method before receiving its canned
	// response; an unexpected extra request makes the test fail.
	fn scripted_client(
		responses: Vec<(&'static str, serde_json::Value)>,
	) -> (ElectrumNodeClient, std::thread::JoinHandle<()>) {
		use std::io::{BufRead, BufReader, Write};
		use std::net::{TcpListener, TcpStream};
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
		let server = std::thread::spawn(move || {
			let (peer, _) = listener.accept().unwrap();
			peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
			let mut reader = BufReader::new(peer);
			for (method, result) in responses {
				let mut line = String::new();
				reader.read_line(&mut line).unwrap();
				let request: serde_json::Value = serde_json::from_str(&line).unwrap();
				assert_eq!(request["method"], method);
				let response = serde_json::json!({"id": request["id"], "result": result});
				writeln!(reader.get_mut(), "{response}").unwrap();
				reader.get_mut().flush().unwrap();
			}
		});
		let node = ElectrumNodeClient {
			address: "unused:0".into(),
			check_tx_hash: String::new(),
			client: Some((
				ElectrumRpcClient {
					inner: RpcClient::from_plain_stream(stream),
					id: 0,
				},
				Instant::now(),
			)),
		};
		(node, server)
	}

	#[test]
	fn coinbase_lookup_requires_unambiguous_transaction_inputs() {
		let txid = Txid::from_byte_array([1; 32]);
		let ordinary = serde_json::json!({"txid": txid, "vout": 0});
		for (inputs, expected) in [
			(
				Some(serde_json::json!([{"coinbase": "03010203"}])),
				Some(true),
			),
			(Some(serde_json::json!([ordinary.clone()])), Some(false)),
			(
				Some(serde_json::json!([ordinary.clone(), ordinary.clone()])),
				Some(false),
			),
			(None, None),
			(Some(serde_json::Value::Null), None),
			(Some(serde_json::json!([])), None),
			(Some(serde_json::json!([{}])), None),
			(Some(serde_json::json!([{"txid": txid}])), None),
			(Some(serde_json::json!([{"vout": 0}])), None),
			(
				Some(serde_json::json!([{"txid": txid, "vout": 0, "coinbase": "00"}])),
				None,
			),
			(
				Some(serde_json::json!([{"coinbase": "00"}, ordinary])),
				None,
			),
			(Some(serde_json::json!([{"coinbase": 1}])), None),
			(
				Some(
					serde_json::json!([{"txid": Txid::from_byte_array([0; 32]), "vout": u32::MAX}]),
				),
				None,
			),
		] {
			let mut verbose = serde_json::json!({
				"confirmations": 6, "hex": "", "locktime": 0, "size": 0, "version": 2
			});
			if let Some(inputs) = inputs {
				verbose["vin"] = inputs;
			}
			let (mut node, server) = scripted_client(vec![("blockchain.transaction.get", verbose)]);
			let result = node.transaction_is_coinbase(&txid);
			match expected {
				Some(expected) => assert_eq!(result.unwrap(), expected),
				None => assert!(result.is_err()),
			}
			drop(node);
			server.join().unwrap();
		}
	}

	// Workflow: an input has disappeared from the UTXO list, so search history
	// containing mempool entries, its funding transaction, an unrelated spend,
	// and its confirmed spender. Expect only the spender and its confirmation
	// count to be returned. Then corrupt each relevant response field: malformed
	// or inconsistent data must return an error, and an unconfirmed spender
	// must return None rather than being adopted for refund recovery.
	#[test]
	fn confirmed_spend_discovers_history_and_validates_raw_transaction() {
		let outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 2);
		let transaction = Transaction {
			version: 2,
			lock_time: 0,
			input: vec![bitcoin::TxIn {
				previous_output: outpoint,
				script_sig: Script::from(vec![0x51]),
				sequence: 0,
				witness: Vec::new(),
			}],
			output: vec![bitcoin::TxOut {
				value: 1_000,
				script_pubkey: Script::new(),
			}],
		};
		let txid = transaction.txid().unwrap();
		let bytes = bitcoin::consensus::serialize(&transaction).unwrap();
		let verbose = serde_json::json!({
			"confirmations": 4, "hex": to_hex(&bytes), "locktime": 0,
			"size": bytes.len(), "version": 2,
			"vin": [{"txid": outpoint.txid, "vout": outpoint.vout}]
		});
		let unrelated = Txid::from_byte_array([2; 32]);
		let mut unrelated_verbose = verbose.clone();
		unrelated_verbose["vin"] = serde_json::json!([{"coinbase": "00"}]);
		// Unrelated history may use another coin-specific encoding; do not
		// feed it to the Bitcoin decoder just to discover refund spends.
		unrelated_verbose["hex"] = serde_json::json!("not-a-btc-transaction");
		let responses = vec![
			("blockchain.scripthash.listunspent", serde_json::json!([])),
			(
				"blockchain.scripthash.get_history",
				serde_json::json!([
					{"height": -1, "tx_hash": unrelated},
					{"height": 0, "tx_hash": unrelated},
					{"height": 1, "tx_hash": outpoint.txid},
					{"height": 2, "tx_hash": unrelated},
					{"height": 3, "tx_hash": txid}
				]),
			),
			("blockchain.transaction.get", unrelated_verbose),
			("blockchain.transaction.get", verbose.clone()),
		];
		let (mut node, server) = scripted_client(responses);
		assert_eq!(
			node.confirmed_spend(&outpoint, &Script::new()).unwrap(),
			Some((transaction.clone(), 4))
		);
		drop(node);
		server.join().unwrap();

		// Neither a mismatched hash nor misleading verbose inputs may bypass
		// validation of the actual bytes returned by the node.
		for mismatch in ["hash", "input", "encoding", "missing inputs", "unconfirmed"] {
			let mut response = verbose.clone();
			let mut hash = txid;
			match mismatch {
				"hash" => hash = unrelated,
				"input" => {
					let mut wrong = transaction.clone();
					wrong.input[0].previous_output.vout += 1;
					hash = wrong.txid().unwrap();
					response["hex"] =
						serde_json::json!(to_hex(&bitcoin::consensus::serialize(&wrong).unwrap()));
				}
				"encoding" => response["hex"] = serde_json::json!("not-hex"),
				"missing inputs" => {
					response.as_object_mut().unwrap().remove("vin");
				}
				"unconfirmed" => response["confirmations"] = serde_json::json!(0),
				_ => unreachable!(),
			}
			let (mut node, server) = scripted_client(vec![
				("blockchain.scripthash.listunspent", serde_json::json!([])),
				(
					"blockchain.scripthash.get_history",
					serde_json::json!([{"height": 3, "tx_hash": hash}]),
				),
				("blockchain.transaction.get", response),
			]);
			let result = node.confirmed_spend(&outpoint, &Script::new());
			if mismatch == "unconfirmed" {
				assert!(result.unwrap().is_none());
			} else {
				assert!(result.is_err(), "{mismatch}");
			}
			drop(node);
			server.join().unwrap();
		}
	}

	// Workflow: first report the input as unspent and expect None without any
	// history request. Then report it spent but return malformed history.
	// Expect that decoding error to reach the caller, which can try its fallback
	// node, instead of silently treating the failed lookup as no confirmed spend.
	#[test]
	fn confirmed_spend_skips_history_for_unspent_input_and_propagates_errors() {
		let outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
		let (mut node, server) = scripted_client(vec![(
			"blockchain.scripthash.listunspent",
			serde_json::json!([
				{"tx_hash": outpoint.txid, "tx_pos": 0, "height": 1, "value": 1_000}
			]),
		)]);
		assert!(node
			.confirmed_spend(&outpoint, &Script::new())
			.unwrap()
			.is_none());
		drop(node);
		server.join().unwrap();
		let (mut node, server) = scripted_client(vec![
			("blockchain.scripthash.listunspent", serde_json::json!([])),
			(
				"blockchain.scripthash.get_history",
				serde_json::json!("invalid history response"),
			),
		]);
		assert!(node.confirmed_spend(&outpoint, &Script::new()).is_err());
		drop(node);
		server.join().unwrap();
	}

	// Fail a request on a freshly cached socket, then immediately request the
	// client again. Expect the failed connection to be discarded without waiting
	// 30 seconds. The deliberately invalid reconnect address proves that a new
	// connection was attempted instead of returning the old cached client.
	#[test]
	fn failed_write_invalidates_cached_client_before_idle_timeout() {
		use std::net::{Shutdown, TcpListener, TcpStream};
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
		let (_peer, _) = listener.accept().unwrap();
		stream.shutdown(Shutdown::Write).unwrap();
		let mut node = ElectrumNodeClient {
			// Reconnection must fail immediately with a malformed address. An
			// Ok result would mean the broken cached client was returned again.
			address: "missing-port".into(),
			check_tx_hash: String::new(),
			client: Some((
				ElectrumRpcClient {
					inner: RpcClient::from_plain_stream(stream),
					id: 0,
				},
				Instant::now(),
			)),
		};
		assert!(node.post_tx(vec![1]).is_err());
		let (client, used_at) = node.client.as_ref().unwrap();
		assert!(used_at.elapsed() < Duration::from_secs(30));
		assert!(!client.is_connected());
		assert!(node.client().is_err());
		assert!(node.client.is_none());
	}

	#[test]
	fn unspent_deduplicates_by_complete_outpoint() {
		let tx_hash = "11".repeat(32);
		let outputs = outputs_from_utxos(vec![
			Utxo {
				tx_hash: tx_hash.clone(),
				tx_pos: 1,
				value: 7,
				height: 90,
			},
			Utxo {
				tx_hash: tx_hash.clone(),
				tx_pos: 0,
				value: 5,
				height: 90,
			},
			// An exact duplicate from ElectrumX must not be counted twice.
			Utxo {
				tx_hash,
				tx_pos: 0,
				value: 5,
				height: 90,
			},
		])
		.unwrap();

		assert_eq!(outputs.len(), 2);
		assert_eq!(outputs[0].out_point.vout, 0);
		assert_eq!(outputs[0].value, 5);
		assert_eq!(outputs[1].out_point.vout, 1);
		assert_eq!(outputs[1].value, 7);
		assert_eq!(outputs.iter().map(|output| output.value).sum::<u64>(), 12);
	}

	#[test]
	fn unspent_rejects_conflicting_duplicate_outpoint_data() {
		let tx_hash = "22".repeat(32);
		let error = outputs_from_utxos(vec![
			Utxo {
				tx_hash: tx_hash.clone(),
				tx_pos: 0,
				value: 5,
				height: 90,
			},
			Utxo {
				tx_hash,
				tx_pos: 0,
				value: 6,
				height: 90,
			},
		])
		.unwrap_err();

		assert!(matches!(error, Error::ElectrumNodeClient(_)));
	}

	/*	use super::*;
	use crate::swap::bitcoin::BtcData;
	use crate::swap::types::Network;
	use mwc_wallet_util::bitcoin_hashes::hex::FromHex;
	use mwc_wallet_util::mwc_crates::bitcoin_hashes::sha256d::Hash;
	use mwc_wallet_util::mwc_util::from_hex;
	use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_crates::rand::{thread_rng, Rng};

	#[test]
	fn test_electrum() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let addresses = vec![
			"btc-testnet.theblains.org:50007",
			"testnet.hsmiths.com:53011",
			"bitcoin-test.networkingfanatic.com:50003",
			"tn.not.fyi:55001",
		];

		let mut client = None;
		for _ in 0..addresses.len() {
			let mut c = ElectrumNodeClient::new(
				String::from(*thread_rng().choose(&addresses).unwrap()),
				true,
			);
			if c.connect().is_ok() {
				client = Some(c);
				break;
			}
		}
		let mut client = client.expect("Unable to connect to any of the testnet Electrum servers");

		let mut data = BtcData {
			lock_time: 1541355814,
			cosign: PublicKey::from_slice(
				&secp,
				&from_hex(
					"02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef".into(),
				)
				.unwrap(),
			)
			.unwrap(),
			refund: Some(
				PublicKey::from_slice(
					&secp,
					&from_hex(
						"022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2".into(),
					)
					.unwrap(),
				)
				.unwrap(),
			),
			confirmed_outputs: Vec::new(),
			locked: false,
			redeem_tx: None,
			redeem_confirmations: None,
			script: None,
		};
		data.script(
			&secp,
			&PublicKey::from_slice(
				&secp,
				&from_hex(
					"03cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c".into(),
				)
				.unwrap(),
			)
			.unwrap(),
		)
		.unwrap();

		let address = data.address(Network::Floonet).unwrap();
		let tx_hash =
			Hash::from_hex("b34aab44804c827306d23023c0e07ee6aad0b291b80c5f04d12fd9ff36708347")
				.unwrap();

		let unspent = client.unspent(&address).unwrap();
		assert!(unspent.len() > 0);
		assert_eq!(unspent[0].out_point.txid, tx_hash);

		let (height, _) = client.transaction(&tx_hash).unwrap().unwrap();
		assert_eq!(height, Some(1_575_077));

		let tx_hash =
			Hash::from_hex("b44aab44804c827306d23023c0e07ee6aad0b291b80c5f04d12fd9ff36708347")
				.unwrap();
		let tx = client.transaction(&tx_hash).unwrap();
		assert!(tx.is_none());
	}*/
}
