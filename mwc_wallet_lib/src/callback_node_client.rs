// Copyright 2025 The MWC Developers
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

// It is a callback node client. All requests with json string body are translated to the
// callback function. Response is expected in a string json format as well

use log::{debug, error, info};
use mwc_wallet_impls::json_rpc::Response;
use mwc_wallet_impls::node_clients::resp_types::{GetTipResp, GetVersionResp};
use mwc_wallet_libwallet as libwallet;
use mwc_wallet_libwallet::{Error, HeaderInfo, NodeClient, NodeVersionInfo};
use mwc_wallet_util::mwc_api::{
	json_rpc, BlockHeaderPrintable, BlockPrintable, Libp2pMessages, Libp2pPeers, LocatedTxKernel,
	OutputListing, OutputPrintable, OutputType,
};
use mwc_wallet_util::mwc_core::core::{Transaction, TxKernel};
use mwc_wallet_util::mwc_node_lib::ffi::CallbackFn;
use mwc_wallet_util::mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_wallet_util::mwc_util::secp::pedersen;
use mwc_wallet_util::mwc_util::ToHex;
use serde_json::json;
use std::collections::HashMap;
use std::ffi::{CStr, CString};

#[derive(Clone)]
pub struct CallbackNodeClient {
	// C++ Callback function that will be called for every request
	callback: CallbackFn,
	callback_context: usize,
}

impl CallbackNodeClient {
	pub fn new(callback: CallbackFn, callback_context: usize) -> Self {
		CallbackNodeClient {
			callback,
			callback_context,
		}
	}

	fn process_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, Error> {
		let str_response = match self.build_request(method, params) {
			Ok(req) => {
				let c_req = CString::new(req).map_err(|e| {
					Error::IO(format!("Unable convert string into C format, {}", e))
				})?;
				let c_compatible_ref: *const libc::c_char = c_req.as_c_str().as_ptr();

				let callback = self.callback;
				let response = callback(
					self.callback_context as *mut std::ffi::c_void,
					c_compatible_ref,
				);

				if response.is_null() {
					return Err(Error::ClientCallback("Null response".to_string()));
				}

				let c_resp: &CStr = unsafe { CStr::from_ptr(response) };
				match c_resp.to_str() {
					Ok(resp) => String::from(resp),
					Err(e) => {
						return Err(Error::ClientCallback(format!(
							"Invalid response from callback, {}",
							e
						)))
					}
				}
			}
			Err(e) => return Err(Error::ClientCallback(e)),
		};

		let node_resp: Response = serde_json::from_str(str_response.as_str()).map_err(|e| {
			Error::ClientCallback(format!(
				"Unable to parse node response: {}, {}",
				str_response, e
			))
		})?;

		match node_resp.into_result() {
			Ok(r) => Ok(r),
			Err(e) => {
				// error message is likely what user want to see...
				let report = format!("{}", e);
				info!(
					"Get node client error responce for {}. Error: {}",
					method, e
				);
				Err(Error::ClientCallback(report))
			}
		}
	}

	fn build_request(&self, method: &str, params: &serde_json::Value) -> Result<String, String> {
		let req = json_rpc::build_request(method, params);
		let req_json: serde_json::Value = serde_json::to_value(&req)
			.map_err(|e| format!("Unable convert {} request into json, {}", method, e))?;

		let req_json_string = serde_json::to_string(&req_json)
			.map_err(|e| format!("Unable convert {} request into json string, {}", method, e))?;
		Ok(req_json_string)
	}
}

impl NodeClient for CallbackNodeClient {
	fn set_node_index(&mut self, _index: u8) {}

	fn get_node_index(&self) -> u8 {
		0
	}

	fn reset_cache(&self) {}

	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		let retval =
			match self.process_request::<GetVersionResp>("get_version", &serde_json::Value::Null) {
				Ok(n) => NodeVersionInfo {
					node_version: n.node_version,
					block_header_version: n.block_header_version,
					verified: Some(true),
				},
				Err(e) => {
					// If node isn't available, allow offline functions
					// unfortunately have to parse string due to error structure
					error!("Unable to contact Node to get version info: {}", e);
					return None;
				}
			};
		Some(retval)
	}

	/// Posts a transaction to a mwc node
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), Error> {
		let params = json!([tx, fluff]);
		self.process_request::<serde_json::Value>("push_transaction", &params)?;
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String, u64), libwallet::Error> {
		let result = self.process_request::<GetTipResp>("get_tip", &serde_json::Value::Null)?;
		let res = (
			result.height,
			result.last_block_pushed,
			result.total_difficulty,
		);
		Ok(res)
	}

	/// Return header info from given height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, libwallet::Error> {
		let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
		let r = self.process_request::<BlockHeaderPrintable>("get_header", &params)?;

		assert!(r.height == height);
		let hdr = HeaderInfo {
			height: r.height,
			hash: r.hash,
			confirmed_time: r.timestamp,
			version: r.version as i32,
			nonce: r.nonce,
			total_difficulty: r.total_difficulty,
		};
		Ok(hdr)
	}

	/// Return Connected peers
	fn get_connected_peer_info(&self) -> Result<Vec<PeerInfoDisplayLegacy>, Error> {
		let res = self.process_request::<Vec<PeerInfoDisplayLegacy>>(
			"get_connected_peers",
			&serde_json::Value::Null,
		)?;
		Ok(res)
	}

	/// Get kernel implementation
	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
		let params = json!([excess.0.as_ref().to_hex(), min_height, max_height]);

		match self.process_request::<LocatedTxKernel>("get_kernel", &params) {
			Ok(res) => Ok(Some((res.tx_kernel, res.height, res.mmr_index))),
			Err(e) => {
				let err_str = format!("{}", e);
				if err_str.contains("NotFound") {
					Ok(None)
				} else {
					let report = format!("Unable to parse response for get_kernel: {}", e);
					error!("{}", report);
					Err(Error::ClientCallback(report))
				}
			}
		}
	}

	/// Retrieve outputs from node
	/// Result value: Commit, Height, MMR
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, Error> {
		// build a map of api outputs by commit so we can look them up efficiently
		let mut api_outputs: HashMap<pedersen::Commitment, (String, u64, u64)> = HashMap::new();

		if wallet_outputs.is_empty() {
			return Ok(api_outputs);
		}

		// build vec of commits for inclusion in query
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| format!("{}", commit.as_ref().to_hex()))
			.collect();

		let commits: Vec<serde_json::Value> = query_params
			.chunks(200)
			.map(|c| json!([c, null, null, false, false]))
			.collect();

		for c in &commits {
			let res = self.process_request::<Vec<OutputPrintable>>("get_outputs", &c)?;

			for out in res {
				if out.spent {
					continue; // we don't expect any spent, let's skip it
				}
				let height = match out.block_height {
					Some(h) => h,
					None => {
						let msg = format!("Missing block height for output {:?}", out.commit);
						return Err(libwallet::Error::ClientCallback(msg));
					}
				};
				api_outputs.insert(
					out.commit,
					(out.commit.as_ref().to_hex(), height, out.mmr_index),
				);
			}
		}
		Ok(api_outputs)
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
		let res = self.process_request::<OutputListing>("get_unspent_outputs", &params)?;

		// We asked for unspent outputs via the api but defensively filter out spent outputs just in case.
		for out in res.outputs.into_iter().filter(|out| out.spent == false) {
			let is_coinbase = match out.output_type {
				OutputType::Coinbase => true,
				OutputType::Transaction => false,
			};
			let range_proof = match out.range_proof() {
				Ok(r) => r,
				Err(e) => {
					let msg = format!(
						"Unexpected error in returned output (missing range proof): {:?}. {:?}, {}",
						out.commit, out, e
					);
					error!("{}", msg);
					return Err(libwallet::Error::ClientCallback(msg));
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
					return Err(libwallet::Error::ClientCallback(msg));
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
		let res = self.process_request::<OutputListing>("get_pmmr_indices", &params)?;
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
		_threads_number: usize,
	) -> Result<Vec<BlockPrintable>, libwallet::Error> {
		debug!(
			"Requesting blocks from heights {}-{}",
			start_height, end_height
		);
		assert!(start_height <= end_height);

		let mut result_blocks: Vec<BlockPrintable> = Vec::new();

		for height in start_height..=end_height {
			let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);

			let block = self.process_request::<BlockPrintable>("get_block", &params)?;
			result_blocks.push(block);
		}
		Ok(result_blocks)
	}

	/// Get Node Tor address
	fn get_libp2p_peers(&self) -> Result<Libp2pPeers, libwallet::Error> {
		debug!("Requesting libp2p peer connections from mwc-node");
		let params = json!([]);
		let res = self.process_request::<Libp2pPeers>("get_libp2p_peers", &params)?;
		Ok(res)
	}

	fn get_libp2p_messages(&self) -> Result<Libp2pMessages, libwallet::Error> {
		debug!("Requesting libp2p received messages from mwc-node");
		let params = json!([]);
		let res = self.process_request::<Libp2pMessages>("get_libp2p_messages", &params)?;
		Ok(res)
	}
}
