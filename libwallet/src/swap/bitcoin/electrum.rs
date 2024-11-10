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
use crate::mwc_util::{from_hex, to_hex};
use crate::swap::types::Currency;
use crate::swap::Error;
use bitcoin::{OutPoint, Script, Txid};
use bitcoin_hashes::sha256d::Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
		self.id += 1;
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
pub struct Utxo {
	pub tx_hash: String,
	pub tx_pos: u32,
	pub value: u64,
	pub height: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

		let (c, t) = self.client.as_mut().unwrap();
		let _ = replace(t, Instant::now());
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
	fn unspent(&mut self, currency: Currency, address: &String) -> Result<Vec<Output>, Error> {
		// A full SPV client should validate the Merkle proofs of the transactions
		// that created these outputs
		let client = self.client()?;
		let script = if address.starts_with("bitcoin-script:") {
			// Converting back from the script... Address is a hex
			let prefix_len = "bitcoin-script:".len();
			// https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki
			let script_hex: String = address
				.chars()
				.skip(prefix_len + 4)
				.take(address.len() - prefix_len - 4 - 8)
				.collect();
			let script_bin = from_hex(&script_hex).map_err(|e| {
				Error::Generic(format!(
					"Unable to convert bitcoin-script address '{}' into Script hex, {}",
					address, e
				))
			})?;
			Script::from(script_bin)
		} else {
			currency.address_2_script_pubkey(address)?
		};

		let utxos = client.unspent(&script)?;

		// Outputs can have duplicates. I saw that at BCH few times. User will see that like
		// was posted twice as needed. In a moment that will be fixed by ElectrumX.
		// Because of that we are using hash map for dedups...
		let outputs: HashMap<bitcoin::Txid, Output> = utxos
			.into_iter()
			.filter_map(|u| {
				Hash::from_str(&u.tx_hash).ok().map(|h| {
					let out_point = OutPoint::new(h.into(), u.tx_pos);
					Output {
						out_point,
						value: u.value,
						height: u.height,
					}
				})
			})
			.map(|output| (output.out_point.txid.clone(), output))
			.collect();

		let outputs: Vec<Output> = outputs.values().cloned().collect();
		Ok(outputs)
	}
	/// Post BTC transaction
	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		let client = self.client()?;
		client.post_tx(tx)
	}
	/// Request a transaction from the node
	fn transaction(&mut self, tx_hash: &Txid) -> Result<Option<u64>, Error> {
		let head_height = self.height()?;

		let client = self.client()?;
		let tx = match client.transaction(format!("{}", tx_hash))? {
			Some(t) => t,
			None => return Ok(None),
		};

		let height = match tx.confirmations {
			Some(c) if c > 0 => Some(head_height.saturating_sub(c - 1)),
			_ => None,
		};
		Ok(height)
	}
}

/// ElectrumX client error response.
#[derive(Serialize, Deserialize, Debug)]
struct ElectrumResponseError {
	code: i64,
	pub message: String,
}

#[cfg(test)]
mod tests {
	/*	use super::*;
	use crate::swap::bitcoin::BtcData;
	use crate::swap::types::Network;
	use bitcoin_hashes::hex::FromHex;
	use bitcoin_hashes::sha256d::Hash;
	use mwc_util::from_hex;
	use mwc_util::secp::key::PublicKey;
	use mwc_util::secp::{ContextFlag, Secp256k1};
	use rand::{thread_rng, Rng};

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
