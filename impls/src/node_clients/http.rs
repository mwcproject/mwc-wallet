// Copyright 2019 The Grin Developers
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

//! Client functions, implementations of the NodeClient trait

use crate::api::{self, LocatedTxKernel, OutputListing, OutputPrintable};
use crate::core::core::{Transaction, TxKernel};
use crate::libwallet::HeaderInfo;
use crate::libwallet::{NodeClient, NodeVersionInfo};
use crossbeam_utils::thread::scope;
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::{env, thread};
use tokio::runtime::Builder;

use crate::client_utils::Client;
use crate::libwallet;
use crate::util::secp::pedersen;
use crate::util::{self, to_hex};

use super::resp_types::*;
use crate::client_utils::json_rpc::*;
use std::time::{Duration, Instant};
use std::sync::{Arc, RwLock};

const ENDPOINT: &str = "/v2/foreign";
const CACHE_VALID_TIME_MS: u128 = 5000; // 2 seconds for cache should be enough for our purpose

const NODE_CALL_RETRY: i32 = 3;
lazy_static! {
	static ref NODE_CALL_DELAY: Vec<u64> = vec![5000, 3000, 1000];
}

// cashed values are stored by the key K
#[derive(Clone)]
struct CachedValue<K, T> {
	data: Arc<RwLock<HashMap<K, (T,Instant)>>>,
}

impl<K,T> CachedValue<K,T>
	where K: std::cmp::Eq + std::hash::Hash,
		  T: Clone
{
	fn new() -> Self {
		CachedValue {
			data: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	// Return none is cached value not set of epired
	fn get_value(&self, key: &K) -> Option<T> {
		match self.data.write().unwrap().get(key) {
			Some( (data, time) ) => {
				if time.elapsed().as_millis() > CACHE_VALID_TIME_MS {
					return None;
				}
				Some( (*data).clone())
			},
			None => None
		}
	}

	fn set_value(&self, key: K, value: T) {
		self.data.write().unwrap().insert(key, (value, Instant::now()) );
	}

	fn clean(&self) {
		self.data.write().unwrap().clear();
	}
}

#[derive(Clone)]
pub struct HTTPNodeClient {
	node_url: String,
	node_api_secret: Option<String>,
	node_version_info: Option<NodeVersionInfo>,
	client: Client,

	// cache for the data
	chain_tip:   CachedValue<u8,(u64, String, u64)>,
	header_info: CachedValue<u64, HeaderInfo>,
	block_info:  CachedValue<u64, api::BlockPrintable>,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given grin node
	pub fn new(node_url: &str, node_api_secret: Option<String>) -> Result<HTTPNodeClient, Error> {
		let client = Client::new(false, None)
			.map_err(|e| Error::GenericError(format!("Unable to create a client, {}", e)))?;

		Ok(HTTPNodeClient {
			node_url: node_url.to_owned(),
			node_api_secret: node_api_secret,
			node_version_info: None,
			client,
			chain_tip: 	 CachedValue::new(),
			header_info: CachedValue::new(),
			block_info:  CachedValue::new(),
		})
	}

	/// Allow returning the chain height without needing a wallet instantiated
	pub fn chain_height(&self) -> Result<(u64, String, u64), libwallet::Error> {
		self.get_chain_tip()
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
		counter: i32
	) -> Result<D, libwallet::Error> {
		let url = format!("{}{}", self.node_url(), ENDPOINT);
		let req = build_request(method, params);
		let res = self.client.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				if counter>0 {
					debug!("Retrying to call Node API method {}: {}", method, e);
					thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
					return self.send_json_request(method, params, counter-1);
				}
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(inner) => match inner.clone().into_result() {
				Ok(r) => Ok(r),
				Err(e) => {
					if counter>0 {
						debug!("Retrying to call Node API method {}: {}", method, e);
						thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
						return self.send_json_request(method, params, counter-1);
					}
					error!("{:?}", inner);
					// error message is likely what user want to see...
					let report = format!("{}", e);
					error!("{}", report);
					Err(libwallet::ErrorKind::ClientCallback(report).into())
				}
			},
		}
	}

	/// Return Connected peers
	fn get_connected_peer_info_impls(&self, counter: i32) -> Result<Vec<grin_p2p::types::PeerInfoDisplayLegacy>, libwallet::Error> {
		// There is no v2 API with connected peers. Keep using v1 for that
		let addr = self.node_url();
		let url = format!("{}/v1/peers/connected", addr);

		let res = self.client
			.get::<Vec<grin_p2p::types::PeerInfoDisplayLegacy>>(url.as_str(), self.node_api_secret());
		match res {
			Err(e) => {
				// Do retry
				if counter>0 {
					debug!("Retry to call connected peers API {}, {}", url, e);
					thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
					return self.get_connected_peer_info_impls(counter-1);
				}
				let report = format!("Get connected peers error {}, {}", url, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(peer) => Ok(peer),
		}
	}

	/// Get kernel implementation
	fn get_kernel_impl(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
		counter: i32,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
		let method = "get_kernel";
		let params = json!([to_hex(excess.0.to_vec()), min_height, max_height]);
		// have to handle this manually since the error needs to be parsed
		let url = format!("{}{}", self.node_url(), ENDPOINT);
		let req = build_request(method, &params);
		let res = self.client.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				if counter>0 {
					debug!("Retry to call API get_kernel, {}", e);
					thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
					return self.get_kernel_impl(excess, min_height, max_height, counter-1);
				}
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(inner) => match inner.clone().into_result::<LocatedTxKernel>() {
				Ok(r) => Ok(Some((r.tx_kernel, r.height, r.mmr_index))),
				Err(e) => {
					let contents = format!("{:?}", inner);
					if contents.contains("NotFound") {
						Ok(None)
					} else {
						let report = format!("Unable to parse response for {}: {}", method, e);
						error!("{}", report);
						Err(libwallet::ErrorKind::ClientCallback(report).into())
					}
				}
			},
		}
	}

	/// Retrieve outputs from node
	/// Result value: Commit, Height, MMR
	fn get_outputs_from_node_impl(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
		counter: i32,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, libwallet::Error> {
		// build a map of api outputs by commit so we can look them up efficiently
		let mut api_outputs: HashMap<pedersen::Commitment, (String, u64, u64)> = HashMap::new();

		if wallet_outputs.is_empty() {
			return Ok(api_outputs);
		}

		// build vec of commits for inclusion in query
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| format!("{}", util::to_hex(commit.as_ref().to_vec())))
			.collect();

		// going to leave this here even though we're moving
		// to the json RPC api to keep the functionality of
		// parallelizing larger requests.
		let chunk_default = 200;
		let chunk_size = match env::var("GRIN_OUTPUT_QUERY_SIZE") {
			Ok(s) => match s.parse::<usize>() {
				Ok(c) => c,
				Err(e) => {
					error!(
						"Unable to parse GRIN_OUTPUT_QUERY_SIZE, defaulting to {}",
						chunk_default
					);
					error!("Reason: {}", e);
					chunk_default
				}
			},
			Err(_) => chunk_default,
		};

		trace!("Output query chunk size is: {}", chunk_size);

		let url = format!("{}{}", self.node_url(), ENDPOINT);

		let task = async move {
			let params: Vec<_> = query_params
				.chunks(chunk_size)
				.map(|c| json!([c, null, null, false, false]))
				.collect();

			let mut reqs = Vec::with_capacity(params.len());
			for p in &params {
				reqs.push(build_request("get_outputs", p));
			}

			let mut tasks = Vec::with_capacity(params.len());
			for req in &reqs {
				tasks.push(self.client.post_async::<Request, Response>(
					url.as_str(),
					self.node_api_secret(),
					req,
				));
			}

			let task: FuturesUnordered<_> = tasks.into_iter().collect();
			task.try_collect().await
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res: Result<Vec<Response>, _> = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		})
		.unwrap();

		let results: Vec<OutputPrintable> = match res {
			Ok(resps) => {
				let mut results = vec![];
				for r in resps {
					match r.into_result::<Vec<OutputPrintable>>() {
						Ok(mut r) => results.append(&mut r),
						Err(e) => {
							if counter>0 {
								debug!("Retry to call API get_outputs, {}", e);
								thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
								return self.get_outputs_from_node_impl(wallet_outputs,counter-1);
							}

							let report = format!("Unable to parse response for get_outputs: {}", e);
							error!("{}", report);
							return Err(libwallet::ErrorKind::ClientCallback(report).into());
						}
					};
				}
				results
			}
			Err(e) => {
				if counter>0 {
					debug!("Retry to call API get_outputs, {}", e);
					thread::sleep(Duration::from_millis(NODE_CALL_DELAY[(counter-1) as usize]));
					return self.get_outputs_from_node_impl(wallet_outputs,counter-1);
				}
				let report = format!("Outputs by id failed: {}", e);
				error!("{}", report);
				return Err(libwallet::ErrorKind::ClientCallback(report).into());
			}
		};

		for out in results.iter() {
			if out.spent {
				continue; // we don't expect any spent, let's skip it
			}
			let height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!("Missing block height for output {:?}", out.commit);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			api_outputs.insert(
				out.commit,
				(util::to_hex(out.commit.0.to_vec()), height, out.mmr_index),
			);
		}
		Ok(api_outputs)
	}
}

impl NodeClient for HTTPNodeClient {
	fn node_url(&self) -> &str {
		&self.node_url
	}
	fn node_api_secret(&self) -> Option<String> {
		self.node_api_secret.clone()
	}

	fn set_node_url(&mut self, node_url: &str) {
		self.node_url = node_url.to_owned();
	}

	fn set_node_api_secret(&mut self, node_api_secret: Option<String>) {
		self.node_api_secret = node_api_secret;
	}

	fn reset_cache(&self) {
		self.chain_tip.clean();
		self.header_info.clean();
		self.block_info.clean();
	}

	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		if let Some(v) = self.node_version_info.as_ref() {
			return Some(v.clone());
		}
		let retval = match self
			.send_json_request::<GetVersionResp>("get_version", &serde_json::Value::Null, 2)
		{
			Ok(n) => NodeVersionInfo {
				node_version: n.node_version,
				block_header_version: n.block_header_version,
				verified: Some(true),
			},
			Err(e) => {
				// If node isn't available, allow offline functions
				// unfortunately have to parse string due to error structure
				let err_string = format!("{}", e);
				if err_string.contains("404") {
					return Some(NodeVersionInfo {
						node_version: "1.0.0".into(),
						block_header_version: 1,
						verified: Some(false),
					});
				} else {
					error!(
						"Unable to contact Node to get version info: {}, {}",
						self.node_url, e
					);
					return None;
				}
			}
		};
		self.node_version_info = Some(retval.clone());
		Some(retval)
	}


	/// Posts a transaction to a grin node
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), libwallet::Error> {
		let params = json!([tx, fluff]);
		self.send_json_request::<serde_json::Value>("push_transaction", &params, NODE_CALL_RETRY)?;
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String, u64), libwallet::Error> {
		if let Some(tip) = self.chain_tip.get_value(&0) {
			return Ok(tip);
		}

		let result = self.send_json_request::<GetTipResp>("get_tip", &serde_json::Value::Null, 1)?;
		let res = (
			result.height,
			result.last_block_pushed,
			result.total_difficulty,
		);
		self.chain_tip.set_value(0, res.clone());
		Ok(res)
	}

	/// Return header info from given height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, libwallet::Error> {
		if let Some(h) = self.header_info.get_value(&height) {
			return Ok(h);
		}

		let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
		let r = self.send_json_request::<api::BlockHeaderPrintable>("get_header", &params, NODE_CALL_RETRY)?;

		assert!(r.height == height);
		let hdr = HeaderInfo {
			height: r.height,
			hash: r.hash,
			confirmed_time: r.timestamp,
			version: r.version as i32,
			nonce: r.nonce,
			total_difficulty: r.total_difficulty,
		};
		self.header_info.set_value(height, hdr.clone());
		Ok(hdr)
	}

	/// Return Connected peers
	fn get_connected_peer_info(
		&self,
	) -> Result<Vec<grin_p2p::types::PeerInfoDisplayLegacy>, libwallet::Error> {
		self.get_connected_peer_info_impls(1)
	}

	/// Get kernel implementation
	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {

		self.get_kernel_impl(excess, min_height, max_height, NODE_CALL_RETRY)
	}

	/// Retrieve outputs from node
	/// Result value: Commit, Height, MMR
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, libwallet::Error> {
		self.get_outputs_from_node_impl(wallet_outputs, NODE_CALL_RETRY)
	}

	// Expected respond from non full node, that can return reliable only non spent outputs.
	fn get_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		libwallet::Error,
	> {
		let mut api_outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)> =
			Vec::new();

		let params = json!([start_index, end_index, max_outputs, Some(true)]);
		let res = self.send_json_request::<OutputListing>("get_unspent_outputs", &params, NODE_CALL_RETRY)?;
		for out in res.outputs {
			if out.spent {
				continue;
			}

			let is_coinbase = match out.output_type {
				api::OutputType::Coinbase => true,
				api::OutputType::Transaction => false,
			};
			let range_proof = match out.range_proof() {
				Ok(r) => r,
				Err(e) => {
					let msg = format!(
						"Unexpected error in returned output (missing range proof): {:?}. {:?}, {}",
						out.commit, out, e
					);
					error!("{}", msg);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			let block_height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!(
						"Unexpected error in returned output (missing block height): {:?}. {:?}",
						out.commit, out
					);
					error!("{}", msg);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			api_outputs.push((
				out.commit,
				range_proof,
				is_coinbase,
				block_height,
				out.mmr_index,
			));
		}
		Ok((res.highest_index, res.last_retrieved_index, api_outputs))
	}

	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), libwallet::Error> {
		let params = json!([start_height, end_height]);
		let res = self.send_json_request::<OutputListing>("get_pmmr_indices", &params, NODE_CALL_RETRY)?;

		Ok((res.last_retrieved_index, res.highest_index))
	}

	/// Get blocks for height range. end_height is included.
	/// Note, single block required singe request. Don't abuse it much because mwc713 wallets using the same node
	/// threads_number - how many requests to do in parallel
	/// Result of blocks not ordered
	fn get_blocks_by_height(
		&self,
		start_height: u64,
		end_height: u64,
		threads_number: usize,
	) -> Result<Vec<api::BlockPrintable>, libwallet::Error> {
		debug!(
			"Requesting blocks from heights {}-{}",
			start_height, end_height
		);
		assert!(threads_number>0 && threads_number<20, "Please use a sane positive number for the wallet that can be connected to the shareable node");
		assert!(start_height <= end_height);

		let mut result_blocks: Vec<api::BlockPrintable> = Vec::new();
		let mut rt = Builder::new()
			.basic_scheduler()
			.enable_all()
			.build()
			.unwrap();
		let mut height = start_height;

		while height <= end_height {
			let mut tasks = Vec::new();
			while tasks.len() < threads_number && height <= end_height {
				if let Some(b) = self.block_info.get_value(&height) {
					result_blocks.push(b); // using cache
				}
				else {
					let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
					tasks.push(async move {
						self.send_json_request::<api::BlockPrintable>("get_block", &params, NODE_CALL_RETRY)
					});
				}
				height += 1;
			}

			if !tasks.is_empty() {
				let task = async {
					let task: FuturesUnordered<_> = tasks.into_iter().collect();
					task.try_collect().await
				};
				let res: Result<Vec<api::BlockPrintable>, _> = rt.block_on(task);
				match res {
					Ok(blocks) => {
						for b in &blocks {
							self.block_info.set_value(b.header.height, b.clone());
						}
						result_blocks.extend(blocks)
					},
					Err(e) => {
						let report = format!(
							"get_blocks_by_height: error calling api 'get_block' at {}. Error: {}",
							self.node_url, e
						);
						error!("{}", report);
						return Err(libwallet::ErrorKind::ClientCallback(report).into());
					}
				}
			}
		}

		rt.shutdown_timeout(Duration::from_secs(5));

		Ok(result_blocks)
	}
}
