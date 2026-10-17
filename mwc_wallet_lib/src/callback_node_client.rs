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

use mwc_wallet_impls::json_rpc::Response;
use mwc_wallet_impls::node_clients::resp_types::{GetTipResp, GetVersionResp};
use mwc_wallet_impls::node_clients::{is_kernel_not_found_error, validate_located_kernel_response};
use mwc_wallet_libwallet::slate_versions::v3::transaction_to_legacy_json;
use mwc_wallet_libwallet::{
	Error, HeaderInfo, NodeClient, NodeHeaderLink, NodeOutputDetails, NodeVersionInfo,
};
use mwc_wallet_util::mwc_api::{
	BlockHeaderPrintable, BlockPrintable, LocatedTxKernel, OutputListing, OutputPrintable,
	OutputType, json_rpc,
};
use mwc_wallet_util::mwc_core::core::{Transaction, TxKernel};
use mwc_wallet_util::mwc_crates::libc;
use mwc_wallet_util::mwc_crates::log::{debug, error, info};
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::serde;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::serde_json::json;
use mwc_wallet_util::mwc_node_lib::ffi::LIB_CALLBACKS;
use mwc_wallet_util::mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_wallet_util::mwc_util::ToHex;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

fn deserialize_output_printables_with_context(
	context_id: u32,
	value: serde_json::Value,
) -> Result<Vec<OutputPrintable>, Error> {
	let values: Vec<serde_json::Value> = serde_json::from_value(value).map_err(|error| {
		Error::ClientCallback(format!("Unable to decode node output response: {}", error))
	})?;
	values
		.into_iter()
		.map(|value| {
			OutputPrintable::deserialize_with_context(context_id, value).map_err(|error| {
				Error::ClientCallback(format!("Unable to decode node output response: {}", error))
			})
		})
		.collect()
}

fn deserialize_output_listing_with_context(
	context_id: u32,
	value: serde_json::Value,
) -> Result<OutputListing, Error> {
	#[derive(serde::Deserialize)]
	#[serde(crate = "serde")]
	struct RawOutputListing {
		highest_index: u64,
		last_retrieved_index: u64,
		outputs: serde_json::Value,
	}

	let raw: RawOutputListing = serde_json::from_value(value).map_err(|error| {
		Error::ClientCallback(format!("Unable to decode node output response: {}", error))
	})?;
	let outputs = deserialize_output_printables_with_context(context_id, raw.outputs)?;
	Ok(OutputListing {
		highest_index: raw.highest_index,
		last_retrieved_index: raw.last_retrieved_index,
		outputs,
	})
}

fn deserialize_block_printable_with_context(
	context_id: u32,
	value: serde_json::Value,
) -> Result<BlockPrintable, Error> {
	#[derive(serde::Deserialize)]
	#[serde(crate = "serde")]
	struct RawBlockPrintable {
		header: BlockHeaderPrintable,
		inputs: Vec<String>,
		outputs: serde_json::Value,
		kernels: Vec<mwc_wallet_util::mwc_api::TxKernelPrintable>,
	}

	let raw: RawBlockPrintable = serde_json::from_value(value).map_err(|error| {
		Error::ClientCallback(format!("Unable to decode node output response: {}", error))
	})?;
	let outputs = deserialize_output_printables_with_context(context_id, raw.outputs)?;
	Ok(BlockPrintable {
		header: raw.header,
		inputs: raw.inputs,
		outputs,
		kernels: raw.kernels,
	})
}

#[derive(Clone)]
pub struct CallbackNodeClient {
	context_id: u32,
	// Registered C++ callback that will be resolved for every request.
	callback_name: String,
	n: Arc<AtomicU32>,
}

impl CallbackNodeClient {
	pub fn new(context_id: u32, callback_name: String) -> Self {
		CallbackNodeClient {
			context_id,
			callback_name,
			n: Arc::new(AtomicU32::new(0)),
		}
	}

	fn process_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, Error> {
		let (node_resp, request_id) = self.process_request_raw(method, params)?;

		match node_resp.into_result(&request_id) {
			Ok(r) => Ok(r),
			Err(e) => {
				// error message is likely what user want to see...
				let report = format!("{}", e);
				info!(
					"Get node client error response for {}. Error: {}",
					method, e
				);
				Err(Error::ClientCallback(report))
			}
		}
	}

	/// Dispatch a request and preserve its structured JSON-RPC response so callers
	/// with method-specific error semantics can classify it without parsing text.
	fn process_request_raw(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<(Response, serde_json::Value), Error> {
		let (req, request_id) = self
			.build_request(method, params)
			.map_err(Error::ClientCallback)?;
		let c_req = CString::new(req)
			.map_err(|e| Error::IO(format!("Unable convert string into C format, {}", e)))?;
		let c_compatible_ref: *const libc::c_char = c_req.as_c_str().as_ptr();

		let str_response = {
			// Keep the registry read lock until the callback response has been copied.
			// This makes unregister_lib_callback wait before the caller-owned context
			// or response storage can be freed or reused by the host application.
			let callbacks = LIB_CALLBACKS.read_recursive();
			let (callback, callback_context) =
				callbacks.get(&self.callback_name).ok_or_else(|| {
					Error::ClientCallback(format!(
						"Callback {} is not registered",
						self.callback_name
					))
				})?;
			let response = callback(*callback_context as *mut std::ffi::c_void, c_compatible_ref);

			if response.is_null() {
				return Err(Error::ClientCallback("Null response".to_string()));
			}

			unsafe { CStr::from_ptr(response) }
				.to_str()
				.map_err(|e| {
					Error::ClientCallback(format!("Invalid response from callback, {}", e))
				})?
				.to_string()
		};

		let node_resp = serde_json::from_str(str_response.as_str()).map_err(|e| {
			Error::ClientCallback(format!(
				"Unable to parse node response: {}, {}",
				str_response, e
			))
		})?;

		Ok((node_resp, request_id))
	}

	fn build_request(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<(String, serde_json::Value), String> {
		let request_id = self.n.fetch_add(1, Ordering::Relaxed);
		let req = json_rpc::build_request(request_id, method, params);
		let req_json: serde_json::Value = serde_json::to_value(&req)
			.map_err(|e| format!("Unable convert {} request into json, {}", method, e))?;

		let req_json_string = serde_json::to_string(&req_json)
			.map_err(|e| format!("Unable convert {} request into json string, {}", method, e))?;
		Ok((req_json_string, serde_json::Value::from(request_id)))
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

	fn test_mempool_accept(
		&self,
		request: &mwc_wallet_libwallet::transaction_preflight::MempoolAcceptRequest,
	) -> Result<mwc_wallet_libwallet::transaction_preflight::MempoolAcceptResponse, Error> {
		let params = serde_json::to_value([request]).map_err(|e| Error::Format(e.to_string()))?;
		self.process_request("testmempoolaccept", &params)
	}

	fn post_tx(
		&self,
		tx: &Transaction,
		fluff: bool,
		receipt: mwc_wallet_libwallet::transaction_preflight::PreflightReceipt,
	) -> Result<(), Error> {
		receipt.check(self, tx)?;
		let params = json!([transaction_to_legacy_json(tx)?, fluff]);
		self.process_request::<()>("push_transaction", &params)?;
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String, u64), Error> {
		let result = self.process_request::<GetTipResp>("get_tip", &serde_json::Value::Null)?;
		let res = (
			result.height,
			result.last_block_pushed,
			result.total_difficulty,
		);
		Ok(res)
	}

	/// Return header info from given height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, Error> {
		let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
		let r = self.process_request::<BlockHeaderPrintable>("get_header", &params)?;

		if r.height != height {
			return Err(Error::Node(format!(
				"CallbackNodeClient::get_header_info, node returned a header for the wrong height, requested_height={} returned_height={}",
				height, r.height
			)));
		}
		let hdr = HeaderInfo {
			height: r.height,
			hash: r.hash,
			confirmed_time: r.timestamp,
			version: i32::from(r.version),
			nonce: r.nonce,
			total_difficulty: r.total_difficulty,
		};
		Ok(hdr)
	}

	fn get_header_by_hash(&self, hash: &str) -> Result<NodeHeaderLink, Error> {
		let params = json!([null, hash, null]);
		let header = self.process_request::<BlockHeaderPrintable>("get_header", &params)?;
		if header.hash != hash {
			return Err(Error::Node(format!(
				"CallbackNodeClient::get_header_by_hash, requested hash {}, received {}",
				hash, header.hash
			)));
		}
		Ok(NodeHeaderLink {
			height: header.height,
			hash: header.hash,
			previous: header.previous,
		})
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
	) -> Result<Option<(TxKernel, u64, u64)>, Error> {
		let params = json!([excess.0.as_ref().to_hex(), min_height, max_height]);

		let (response, request_id) = self.process_request_raw("get_kernel", &params)?;
		match response.into_result::<LocatedTxKernel>(&request_id) {
			Ok(response) => {
				validate_located_kernel_response(excess, min_height, max_height, response).map(Some)
			}
			Err(e) if is_kernel_not_found_error(&e, &params) => Ok(None),
			Err(e) => {
				let report = format!("Unable to parse response for get_kernel: {}", e);
				error!("{}", report);
				Err(Error::ClientCallback(report))
			}
		}
	}

	/// Retrieve output details from node.
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, NodeOutputDetails>, Error> {
		let mut api_outputs = HashMap::new();
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| commit.as_ref().to_hex())
			.collect();

		for commits in query_params.chunks(200) {
			let params = json!([commits, null, null, false, false]);
			let response = self.process_request::<serde_json::Value>("get_outputs", &params)?;
			for out in deserialize_output_printables_with_context(self.context_id, response)? {
				if out.spent {
					continue;
				}
				let height = out.block_height.ok_or_else(|| {
					Error::ClientCallback(format!(
						"Missing block height for output {:?}",
						out.commit
					))
				})?;
				api_outputs.insert(
					out.commit,
					NodeOutputDetails {
						commit: out.commit.as_ref().to_hex(),
						height,
						mmr_index: out.mmr_index,
					},
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
		Error,
	> {
		let mut api_outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)> =
			Vec::new();

		let params = json!([start_index, end_index, max_outputs, Some(true)]);
		let response = self.process_request::<serde_json::Value>("get_unspent_outputs", &params)?;
		let res = deserialize_output_listing_with_context(self.context_id, response)?;

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
					return Err(Error::ClientCallback(msg));
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
					return Err(Error::ClientCallback(msg));
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
	) -> Result<(u64, u64), Error> {
		let params = json!([start_height, end_height]);
		let response = self.process_request::<serde_json::Value>("get_pmmr_indices", &params)?;
		let res = deserialize_output_listing_with_context(self.context_id, response)?;
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
	) -> Result<Vec<BlockPrintable>, Error> {
		debug!(
			"Requesting blocks from heights {}-{}",
			start_height, end_height
		);
		if start_height > end_height {
			return Err(Error::Node(format!(
				"CallbackNodeClient::get_blocks_by_height, invalid height range, start_height={} end_height={}",
				start_height, end_height
			)));
		}

		let mut result_blocks: Vec<BlockPrintable> = Vec::new();

		for height in start_height..=end_height {
			let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);

			let response = self.process_request::<serde_json::Value>("get_block", &params)?;
			let block = deserialize_block_printable_with_context(self.context_id, response)?;
			result_blocks.push(block);
		}
		Ok(result_blocks)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Barrier, OnceLock};
	use std::thread;

	static CALLBACK_BARRIERS: OnceLock<(Barrier, Barrier)> = OnceLock::new();
	static CALLBACK_RESPONSE: &[u8] =
		b"{\"result\":{\"Ok\":null},\"error\":null,\"id\":0,\"jsonrpc\":\"2.0\"}\0";
	static OUTPUT_LISTING_RESPONSE: &[u8] = b"{\"result\":{\"Ok\":{\"highest_index\":20,\"last_retrieved_index\":9,\"outputs\":[{\"output_type\":\"Coinbase\",\"commit\":\"083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f\",\"spent\":false,\"proof\":\"00\",\"proof_hash\":\"ed6ba96009b86173bade6a9227ed60422916593fa32dd6d78b25b7a4eeef4946\",\"block_height\":42,\"merkle_proof\":null,\"mmr_index\":9}]}},\"error\":null,\"id\":0,\"jsonrpc\":\"2.0\"}\0";
	const VALID_KERNEL_EXCESS: &str =
		"08761e9cb1eea5bfcf771d1218b5ec802798d6eecaf75faae50ba3a1997aaef009";
	const VALID_KERNEL_SIGNATURE: &str = "971317046c533d21dff3e449cc9380c2be10b0274f70e009aa2453f755239e3299883c09a1785b15a141d89d563cdd59395886c7d63aba9c2b6438575555e2c4";

	extern "C" fn blocking_callback(
		_context: *mut std::ffi::c_void,
		_message: *const libc::c_char,
	) -> *const libc::c_char {
		let barriers = CALLBACK_BARRIERS.get().expect("test barriers initialized");
		barriers.0.wait();
		barriers.1.wait();
		CALLBACK_RESPONSE.as_ptr().cast()
	}

	extern "C" fn output_listing_callback(
		_context: *mut std::ffi::c_void,
		_message: *const libc::c_char,
	) -> *const libc::c_char {
		OUTPUT_LISTING_RESPONSE.as_ptr().cast()
	}

	extern "C" fn context_response_callback(
		context: *mut std::ffi::c_void,
		_message: *const libc::c_char,
	) -> *const libc::c_char {
		context.cast::<libc::c_char>().cast_const()
	}

	fn get_kernel_with_callback_response(
		callback_name: &str,
		response: serde_json::Value,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error> {
		let response = CString::new(response.to_string()).unwrap();
		assert!(
			LIB_CALLBACKS
				.write()
				.insert(
					callback_name.to_string(),
					(context_response_callback, response.as_ptr().addr()),
				)
				.is_none()
		);
		let client = CallbackNodeClient::new(0, callback_name.to_string());

		let result = client.get_kernel(excess, min_height, max_height);
		assert!(LIB_CALLBACKS.write().remove(callback_name).is_some());
		result
	}

	fn valid_kernel_excess() -> pedersen::Commitment {
		pedersen::Commitment::from_vec(
			mwc_wallet_util::mwc_util::from_hex(VALID_KERNEL_EXCESS).unwrap(),
		)
		.unwrap()
	}

	fn located_kernel_response(height: u64) -> serde_json::Value {
		json!({
			"result": {
				"Ok": {
					"tx_kernel": {
						"features": "Coinbase",
						"excess": VALID_KERNEL_EXCESS,
						"excess_sig": VALID_KERNEL_SIGNATURE,
					},
					"height": height,
					"mmr_index": 7,
				}
			},
			"error": null,
			"id": 0,
			"jsonrpc": "2.0",
		})
	}

	#[test]
	fn callback_preflight_serialization_failure_returns_error() {
		use mwc_wallet_libwallet::transaction_preflight::{
			MempoolAcceptRequest, PreflightKernel, PreflightTransaction, check_request,
		};
		use mwc_wallet_util::mwc_core::core::{FeeFields, KernelFeatures};

		let client = CallbackNodeClient::new(0, "unregistered_preflight_callback".to_owned());
		let request = MempoolAcceptRequest::single(PreflightTransaction {
			is_complete: false,
			inputs: vec![],
			outputs: vec![],
			kernels: vec![PreflightKernel {
				features: KernelFeatures::Plain {
					fee: FeeFields::zero(),
				},
				excess: None,
				kernel_hash: None,
			}],
			offset: None,
			allow_future_height: false,
		});

		let error = check_request(&client, &request).unwrap_err();
		assert!(matches!(error, Error::Format(message) if message.contains("fee is zero")));
	}

	#[test]
	fn callback_header_by_hash_returns_parent_and_rejects_wrong_hash() {
		let callback_name = "wallet_callback_header_by_hash_test";
		for returned_hash in ["body-header", "wrong-header"] {
			let response = CString::new(
				json!({
					"jsonrpc": "2.0", "id": 0,
					"result": { "Ok": {
						"hash": returned_hash, "height": 10, "previous": "body-parent",
						"version": 1, "prev_root": "previous-root",
						"timestamp": "2026-09-25T00:00:00Z",
						"output_root": "output-root", "output_mmr_size": 0,
						"range_proof_root": "range-proof-root",
						"kernel_root": "kernel-root", "kernel_mmr_size": 0,
						"nonce": 0, "edge_bits": 29, "cuckoo_solution": [],
						"total_difficulty": 100, "secondary_scaling": 1,
						"total_kernel_offset": "kernel-offset"
					}}
				})
				.to_string(),
			)
			.unwrap();
			assert!(
				LIB_CALLBACKS
					.write()
					.insert(
						callback_name.to_owned(),
						(context_response_callback, response.as_ptr().addr()),
					)
					.is_none()
			);
			let client = CallbackNodeClient::new(0, callback_name.to_owned());

			let result = client.get_header_by_hash("body-header");
			assert!(LIB_CALLBACKS.write().remove(callback_name).is_some());
			if returned_hash == "body-header" {
				assert_eq!(
					result.unwrap(),
					NodeHeaderLink {
						height: 10,
						hash: "body-header".to_owned(),
						previous: "body-parent".to_owned(),
					}
				);
			} else {
				assert!(matches!(result, Err(Error::Node(message))
					if message.contains("requested hash body-header, received wrong-header")));
			}
		}
	}

	#[test]
	fn callback_kernel_not_found_classification_is_exact() {
		let excess = valid_kernel_excess();
		let not_found = json!({
			"result": {"Err": "API NotFound: kernel value for requested excess"},
			"error": null,
			"id": 0,
			"jsonrpc": "2.0",
		});
		assert!(
			get_kernel_with_callback_response(
				"wallet_callback_kernel_not_found_test",
				not_found,
				&excess,
				Some(10),
				Some(20),
			)
			.unwrap()
			.is_none()
		);

		let method_not_found = json!({
			"result": null,
			"error": {
				"code": -32601,
				"message": "Method NotFound",
				"data": null,
			},
			"id": 0,
			"jsonrpc": "2.0",
		});
		assert!(matches!(
			get_kernel_with_callback_response(
				"wallet_callback_kernel_method_not_found_test",
				method_not_found,
				&excess,
				Some(10),
				Some(20),
			),
			Err(Error::ClientCallback(message)) if message.contains("Method NotFound")
		));
	}

	#[test]
	fn callback_kernel_response_must_be_within_requested_heights() {
		let excess = valid_kernel_excess();
		assert!(matches!(
			get_kernel_with_callback_response(
				"wallet_callback_kernel_out_of_range_test",
				located_kernel_response(21),
				&excess,
				Some(10),
				Some(20),
			),
			Err(Error::Node(message))
				if message.contains("outside the requested height range")
		));

		let result = get_kernel_with_callback_response(
			"wallet_callback_kernel_valid_height_test",
			located_kernel_response(15),
			&excess,
			Some(10),
			Some(20),
		)
		.unwrap()
		.expect("kernel within the requested heights should be returned");
		assert_eq!(result.0.excess, excess);
		assert_eq!(result.1, 15);
		assert_eq!(result.2, 7);
	}

	#[test]
	fn callback_decodes_nonempty_output_listing_with_context() {
		let callback_name = "wallet_callback_output_listing_test";
		assert!(
			LIB_CALLBACKS
				.write()
				.insert(callback_name.to_string(), (output_listing_callback, 0))
				.is_none()
		);
		let client = CallbackNodeClient::new(7, callback_name.to_string());

		let result = client.get_outputs_by_pmmr_index(1, None, 100);
		assert!(LIB_CALLBACKS.write().remove(callback_name).is_some());
		let (highest_index, last_retrieved_index, outputs) =
			result.expect("a nonempty output listing should use context-aware decoding");

		assert_eq!(highest_index, 20);
		assert_eq!(last_retrieved_index, 9);
		assert_eq!(outputs.len(), 1);
		assert!(outputs[0].2);
		assert_eq!(outputs[0].3, 42);
		assert_eq!(outputs[0].4, 9);
		assert_eq!(outputs[0].1.len().unwrap(), 1);
	}

	#[test]
	fn callback_dispatch_holds_registration_until_response_is_copied() {
		let callback_name = "wallet_callback_node_client_registration_test";
		CALLBACK_BARRIERS
			.set((Barrier::new(2), Barrier::new(2)))
			.expect("test barriers initialized once");
		assert!(
			LIB_CALLBACKS
				.write()
				.insert(callback_name.to_string(), (blocking_callback, 0))
				.is_none()
		);

		let client = CallbackNodeClient::new(0, callback_name.to_string());
		let request_client = client.clone();
		let request = thread::spawn(move || {
			request_client.process_request::<()>("push_transaction", &serde_json::Value::Null)
		});

		let barriers = CALLBACK_BARRIERS.get().expect("test barriers initialized");
		barriers.0.wait();
		let registration_is_locked = LIB_CALLBACKS.try_write().is_none();
		barriers.1.wait();
		request.join().expect("request thread completed").unwrap();
		assert!(registration_is_locked);

		assert!(LIB_CALLBACKS.write().remove(callback_name).is_some());
		let error = client
			.process_request::<()>("push_transaction", &serde_json::Value::Null)
			.unwrap_err();
		assert!(matches!(
			error,
			Error::ClientCallback(message) if message.contains("is not registered")
		));
	}
}
