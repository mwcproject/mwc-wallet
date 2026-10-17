// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

use mwc_wallet_libwallet::slate_versions::v3::transaction_to_legacy_json;
use mwc_wallet_libwallet::{HeaderInfo, NodeHeaderLink};
use mwc_wallet_libwallet::{NodeClient, NodeConnectionId, NodeOutputDetails, NodeVersionInfo};
use mwc_wallet_util::mwc_api::{self, LocatedTxKernel, OutputListing, OutputPrintable};
use mwc_wallet_util::mwc_core::core::{Transaction, TxKernel};
use mwc_wallet_util::mwc_crates::futures::TryStreamExt;
use mwc_wallet_util::mwc_crates::futures::stream::FuturesUnordered;
use mwc_wallet_util::mwc_crates::lru::LruCache;
use mwc_wallet_util::mwc_crates::reqwest::StatusCode;
use mwc_wallet_util::mwc_crates::serde;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::types::PeerInfoDisplayLegacy;
use std::collections::HashMap;
use std::env;

use mwc_wallet_libwallet;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::serde_json::json;
use mwc_wallet_util::mwc_util;
use mwc_wallet_util::mwc_util::ToHex;

#[cfg(test)]
use super::KERNEL_NOT_FOUND_ERROR;
use super::resp_types::*;
use super::{is_kernel_not_found_error, validate_located_kernel_response};
use crate::client_utils::json_rpc::*;
use crate::client_utils::{Client, safe_node_error, safe_node_text, url_with_appended_path};
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_crates::log::{debug, error, trace};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CACHE_VALID_TIME: Duration = Duration::from_millis(5000);
const NODE_METADATA_CACHE_MAX_ENTRIES: usize = 1;
const HEADER_CACHE_MAX_ENTRIES: usize = 256;
const BLOCK_CACHE_MAX_ENTRIES: usize = 32;

const NODE_CALL_RETRY: i32 = 2; // it is total 3 attempts  to get the data
const NODE_VERSION_CALL_RETRY: i32 = 7; // it is total 3 attempts  to get the data

#[derive(Debug)]
struct JsonRequestError {
	error: mwc_wallet_libwallet::Error,
	http_status: Option<StatusCode>,
}

impl JsonRequestError {
	fn without_http_status(error: mwc_wallet_libwallet::Error) -> Self {
		JsonRequestError {
			error,
			http_status: None,
		}
	}

	fn is_http_status(&self, status: StatusCode) -> bool {
		self.http_status == Some(status)
	}

	fn into_wallet_error(self) -> mwc_wallet_libwallet::Error {
		self.error
	}
}

impl std::fmt::Display for JsonRequestError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.error.fmt(formatter)
	}
}

impl From<JsonRequestError> for mwc_wallet_libwallet::Error {
	fn from(error: JsonRequestError) -> Self {
		error.into_wallet_error()
	}
}

fn node_api_url(
	node_url: &str,
	path_segments: &[&str],
) -> Result<String, mwc_wallet_libwallet::Error> {
	// Embedded URL credentials are deliberately supported because node URLs are
	// unrestricted operator-supplied configuration. Diagnostics preserve the
	// configured URL, so any username or password in its userinfo may appear in
	// logs and returned errors. Operators choosing such URLs explicitly accept
	// that disclosure risk; do not reject or redact URL userinfo here.
	let url = url_with_appended_path(node_url, path_segments).map_err(|e| {
		mwc_wallet_libwallet::Error::ClientCallback(format!(
			"Invalid node URL {}: {}",
			safe_node_text(node_url),
			e
		))
	})?;
	if !matches!(url.scheme(), "http" | "https") {
		return Err(mwc_wallet_libwallet::Error::ClientCallback(format!(
			"Invalid node URL {}: unsupported scheme {}; expected http or https",
			safe_node_text(node_url),
			url.scheme()
		)));
	}
	Ok(url.to_string())
}

fn validate_node_url_list(node_url_list: &[String]) -> Result<(), Error> {
	if node_url_list.len() > usize::from(u8::MAX) + 1 {
		return Err(Error::GenericError(
			"At most 256 node URLs are supported".to_string(),
		));
	}

	for node_url in node_url_list {
		node_api_url(node_url, &["v2", "foreign"]).map_err(|e| {
			Error::GenericError(format!(
				"Unable to configure node URL: {}",
				safe_node_error(&e)
			))
		})?;
	}
	Ok(())
}

fn deserialize_output_printables_with_context(
	context_id: u32,
	value: serde_json::Value,
) -> Result<Vec<OutputPrintable>, Error> {
	let values: Vec<serde_json::Value> = serde_json::from_value(value)?;
	values
		.into_iter()
		.map(|value| {
			OutputPrintable::deserialize_with_context(context_id, value).map_err(Error::from)
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

	let raw: RawOutputListing = serde_json::from_value(value)?;
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
) -> Result<mwc_api::BlockPrintable, Error> {
	#[derive(serde::Deserialize)]
	#[serde(crate = "serde")]
	struct RawBlockPrintable {
		header: mwc_api::BlockHeaderPrintable,
		inputs: Vec<String>,
		outputs: serde_json::Value,
		kernels: Vec<mwc_api::TxKernelPrintable>,
	}

	let raw: RawBlockPrintable = serde_json::from_value(value)?;
	let outputs = deserialize_output_printables_with_context(context_id, raw.outputs)?;
	Ok(mwc_api::BlockPrintable {
		header: raw.header,
		inputs: raw.inputs,
		outputs,
		kernels: raw.kernels,
	})
}

// Cached values are stored by key K and evicted by recency once the configured
// capacity is reached.
struct CachedValue<K, T> {
	data: RwLock<LruCache<K, (T, Instant)>>,
}

impl<K, T> Clone for CachedValue<K, T>
where
	K: Clone + std::cmp::Eq + std::hash::Hash,
	T: Clone,
{
	fn clone(&self) -> Self {
		CachedValue {
			data: RwLock::new(self.data.read_recursive().clone()),
		}
	}
}

impl<K, T> CachedValue<K, T>
where
	K: std::cmp::Eq + std::hash::Hash,
	T: Clone,
{
	fn new(max_entries: usize) -> Self {
		let capacity =
			NonZeroUsize::new(max_entries).expect("CachedValue capacity must be greater than zero");
		CachedValue {
			data: RwLock::new(LruCache::new(capacity)),
		}
	}

	// Return None if the cached value is not set or has expired. Expired values
	// are removed immediately rather than occupying capacity until LRU eviction.
	fn get_value(&self, key: &K) -> Option<T> {
		let mut cache = self.data.write();
		let expired = cache
			.peek(key)
			.is_some_and(|(_, cached_at)| cached_at.elapsed() > CACHE_VALID_TIME);
		if expired {
			let _ = cache.pop(key);
			return None;
		}
		cache.get(key).map(|(data, _)| data.clone())
	}

	fn set_value(&self, key: K, value: T) {
		let _ = self.data.write().put(key, (value, Instant::now()));
	}

	fn clean(&self) {
		self.data.write().clear();
	}
}

/// Ordinary clones keep independent configuration, connection state and caches.
/// `NodeClient::clone_for_request` shares state for requests outside the wallet lock.
pub struct HTTPNodeClient {
	state: Arc<HTTPNodeClientState>,
}

// A request handle shares this state. URL and credential changes install a new
// state so in-flight requests can only update caches for their own configuration.
struct HTTPNodeClientState {
	node_url_list: Vec<String>,
	node_api_secret: Option<Zeroizing<String>>, //share the same secret for all the nodes.
	// The selected node is this counter modulo the number of configured nodes.
	// Keeping selection and generation in one atomic prevents torn connection IDs.
	node_connection_counter: AtomicU64,
	client: Client,

	// cache for the data
	node_version_info: CachedValue<NodeConnectionId, NodeVersionInfo>,
	chain_tip: CachedValue<NodeConnectionId, (u64, String, u64)>,
	header_info: CachedValue<(NodeConnectionId, u64), HeaderInfo>,
	block_info: CachedValue<(NodeConnectionId, u64), mwc_api::BlockPrintable>,
}

impl Clone for HTTPNodeClient {
	fn clone(&self) -> Self {
		HTTPNodeClient {
			state: Arc::new(self.state.as_ref().clone()),
		}
	}
}

impl Clone for HTTPNodeClientState {
	fn clone(&self) -> Self {
		HTTPNodeClientState {
			node_url_list: self.node_url_list.clone(),
			node_api_secret: self.node_api_secret.clone(),
			node_connection_counter: AtomicU64::new(
				self.node_connection_counter.load(Ordering::SeqCst),
			),
			client: self.client.clone(),
			node_version_info: self.node_version_info.clone(),
			chain_tip: self.chain_tip.clone(),
			header_info: self.header_info.clone(),
			block_info: self.block_info.clone(),
		}
	}
}

impl HTTPNodeClientState {
	fn new(
		node_url_list: Vec<String>,
		node_api_secret: Option<Zeroizing<String>>,
		client: Client,
		connection_counter: u64,
	) -> Self {
		Self {
			node_url_list,
			node_api_secret,
			node_connection_counter: AtomicU64::new(connection_counter),
			client,
			node_version_info: CachedValue::new(NODE_METADATA_CACHE_MAX_ENTRIES),
			chain_tip: CachedValue::new(NODE_METADATA_CACHE_MAX_ENTRIES),
			header_info: CachedValue::new(HEADER_CACHE_MAX_ENTRIES),
			block_info: CachedValue::new(BLOCK_CACHE_MAX_ENTRIES),
		}
	}
}

impl HTTPNodeClient {
	/// Create a node client without copying an API secret out of zeroizing
	/// storage.
	pub fn new(
		context_id: u32,
		node_url_list: Vec<String>,
		node_api_secret: Option<Zeroizing<String>>,
	) -> Result<HTTPNodeClient, Error> {
		validate_node_url_list(&node_url_list)?;
		let client = match Client::new(context_id) {
			Ok(client) => client,
			Err(e) => {
				return Err(Error::GenericError(format!(
					"Unable to create a client, {}",
					e
				)));
			}
		};

		Ok(HTTPNodeClient {
			state: Arc::new(HTTPNodeClientState::new(
				node_url_list,
				node_api_secret,
				client,
				0,
			)),
		})
	}

	/// Allow returning the chain height without needing a wallet instantiated.
	///
	/// Trust model: configured nodes are trusted, authoritative sources for chain
	/// state. This client validates transport and JSON-RPC errors, but does not
	/// independently authenticate the reported height, hashes, or difficulty.
	/// Dishonest or malicious responses from a configured node are outside this
	/// client's threat model.
	pub fn chain_height(&self) -> Result<(u64, String, u64), mwc_wallet_libwallet::Error> {
		self.get_chain_tip()
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
		counter: i32,
	) -> Result<(D, NodeConnectionId), JsonRequestError> {
		self.send_json_request_with_decoder(method, params, counter, |value| {
			serde_json::from_value(value).map_err(Error::from)
		})
	}

	fn send_json_request_with_decoder<D, F>(
		&self,
		method: &str,
		params: &serde_json::Value,
		counter: i32,
		decode: F,
	) -> Result<(D, NodeConnectionId), JsonRequestError>
	where
		F: Fn(serde_json::Value) -> Result<D, Error>,
	{
		mwc_util::run_global_async_block(
			self.send_json_request_async_with_decoder(method, params, counter, decode),
		)
		.map_err(|e| {
			JsonRequestError::without_http_status(mwc_wallet_libwallet::Error::ClientCallback(
				format!(
					"send_json_request: async runtime error: {}",
					safe_node_error(&e)
				),
			))
		})?
	}

	async fn send_json_request_async_with_decoder<D, F>(
		&self,
		method: &str,
		params: &serde_json::Value,
		mut retries_remaining: i32,
		decode: F,
	) -> Result<(D, NodeConnectionId), JsonRequestError>
	where
		F: Fn(serde_json::Value) -> Result<D, Error>,
	{
		// Retry diagnostics deliberately include the complete JSON-RPC parameters.
		// For methods such as `push_transaction`, this can reveal transaction linkage
		// and other wallet-private metadata to anyone who can read the debug logs.
		// Enabling or sharing debug logs accepts that privacy tradeoff in exchange for
		// request-level information that is useful when diagnosing node failures.
		loop {
			let (node_url, connection_id) = self
				.node_url_with_connection()
				.map_err(JsonRequestError::without_http_status)?;
			let url = node_api_url(&node_url, &["v2", "foreign"])
				.map_err(JsonRequestError::without_http_status)?;
			let req = build_request(method, params);
			let res = self
				.state
				.client
				.post_async::<Request, Response>(url.as_str(), self.node_api_secret(), &req)
				.await;

			match res {
				Err(e) => {
					let http_status = e.http_status();
					let safe_error = safe_node_error(&e);
					if retries_remaining > 0 {
						debug!(
							"Retrying to call Node API {} method {} with {}: {}",
							url, method, params, safe_error
						);
						self.increase_index_if_current(connection_id);
						retries_remaining = retries_remaining.saturating_sub(1);
						continue;
					}
					let report = format!("Error calling {}: {}", method, safe_error);
					error!("{}", report);
					return Err(JsonRequestError {
						error: mwc_wallet_libwallet::Error::ClientCallback(report),
						http_status,
					});
				}
				Ok(inner) => match inner
					.into_result::<serde_json::Value>(&req.id)
					.and_then(&decode)
				{
					Ok(result) => return Ok((result, connection_id)),
					Err(e) => {
						let safe_error = safe_node_error(&e);
						if retries_remaining > 0 {
							debug!(
								"Retrying to call Node API {} method {} with {}: {}",
								url, method, params, safe_error
							);
							self.increase_index_if_current(connection_id);
							retries_remaining = retries_remaining.saturating_sub(1);
							continue;
						}
						error!("{}", safe_error);
						return Err(JsonRequestError::without_http_status(
							mwc_wallet_libwallet::Error::ClientCallback(safe_error),
						));
					}
				},
			}
		}
	}

	/// Return Connected peers
	fn get_connected_peer_info_impls(
		&self,
		counter: i32,
	) -> Result<Vec<PeerInfoDisplayLegacy>, mwc_wallet_libwallet::Error> {
		// There is no v2 API with connected peers. Keep using v1 for that
		let (addr, connection_id) = self.node_url_with_connection()?;
		let url = node_api_url(&addr, &["v1", "peers", "connected"])?;

		let res = self
			.state
			.client
			.get::<Vec<PeerInfoDisplayLegacy>>(url.as_str(), self.node_api_secret());
		match res {
			Err(e) => {
				let safe_error = safe_node_error(&e);
				// Do retry
				if counter > 0 {
					debug!(
						"Retry to call connected peers API {}, {}",
						safe_node_text(&url),
						safe_error
					);
					self.increase_index_if_current(connection_id);
					// The retry branch requires a positive counter.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the retry counter is checked greater than zero"
					)]
					return self.get_connected_peer_info_impls(counter - 1);
				}
				let report = format!(
					"Get connected peers error {}, {}",
					safe_node_text(&url),
					safe_error
				);
				error!("{}", report);
				Err(mwc_wallet_libwallet::Error::ClientCallback(report))
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
	) -> Result<Option<(TxKernel, u64, u64)>, mwc_wallet_libwallet::Error> {
		let method = "get_kernel";
		let params = json!([excess.0.as_ref().to_hex(), min_height, max_height]);
		// have to handle this manually since the error needs to be parsed
		let (node_url, connection_id) = self.node_url_with_connection()?;
		let url = node_api_url(&node_url, &["v2", "foreign"])?;
		let req = build_request(method, &params);
		let res =
			self.state
				.client
				.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				let safe_error = safe_node_error(&e);
				if counter > 0 {
					debug!("Retry to call API get_kernel, {}", safe_error);
					self.increase_index_if_current(connection_id);
					// The retry branch requires a positive counter.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "the retry counter is checked greater than zero"
					)]
					return self.get_kernel_impl(excess, min_height, max_height, counter - 1);
				}
				let report = format!("Error calling {}: {}", method, safe_error);
				error!("{}", report);
				Err(mwc_wallet_libwallet::Error::ClientCallback(report))
			}
			Ok(inner) => match inner.into_result::<LocatedTxKernel>(&req.id) {
				Ok(r) => {
					validate_located_kernel_response(excess, min_height, max_height, r).map(Some)
				}
				Err(e) if is_kernel_not_found_error(&e, &params) => Ok(None),
				Err(e) => {
					let report = format!(
						"Unable to parse response for {}: {}",
						method,
						safe_node_error(&e)
					);
					error!("{}", report);
					Err(mwc_wallet_libwallet::Error::ClientCallback(report))
				}
			},
		}
	}

	fn clean_caches(&self) {
		self.state.node_version_info.clean();
		self.state.chain_tip.clean();
		self.state.header_info.clean();
		self.state.block_info.clean();
	}

	fn advance_connection_counter(&self) {
		// `try_update` returns `Err` only when the closure returns `None`.
		// This closure always proposes a value, including wrapping MAX to zero.
		self.state
			.node_connection_counter
			.try_update(Ordering::SeqCst, Ordering::SeqCst, |counter| {
				Some(counter.checked_add(1).unwrap_or(0))
			})
			.expect("connection counter update closure always returns Some");
		self.clean_caches();
	}

	/// Advance only if this is still the connection that failed. Concurrent
	/// failures from an already abandoned node must not skip additional nodes.
	fn increase_index_if_current(&self, failed_connection: NodeConnectionId) {
		if self.state.node_url_list.len() > 1 {
			let next_counter = failed_connection.generation.checked_add(1).unwrap_or(0);
			if self
				.state
				.node_connection_counter
				.compare_exchange(
					failed_connection.generation,
					next_counter,
					Ordering::SeqCst,
					Ordering::SeqCst,
				)
				.is_ok()
			{
				self.clean_caches();
			}
		}
	}

	pub fn increase_index(&self) {
		if self.state.node_url_list.len() > 1 {
			self.advance_connection_counter();
		}
	}

	/// Select a requested node while keeping the node index encoded in the
	/// single connection counter.
	///
	/// The counter is advanced to the next value for which
	/// `counter % node_count == node_index % node_count`. When `force_change`
	/// is false, selecting the already-active index leaves the counter
	/// unchanged. When it is true, the counter advances by a full node-list
	/// cycle so the index stays the same but the connection identity changes.
	/// The latter is required after replacing the URL list, because the same
	/// numeric index may now identify a different node.
	///
	/// Any successful counter change invalidates all node-specific caches.
	fn select_node_index_with_change(&self, node_index: u8, force_change: bool) {
		let node_count = self.state.node_url_list.len() as u64;
		if node_count == 0 {
			return;
		}
		let target_index = u64::from(node_index) % node_count;
		let update = self.state.node_connection_counter.try_update(
			Ordering::SeqCst,
			Ordering::SeqCst,
			|counter| {
				let current_index = counter % node_count;
				if current_index == target_index {
					if force_change {
						return Some(counter.checked_add(node_count).unwrap_or(target_index));
					}
					return None;
				}
				let distance = if target_index > current_index {
					target_index.checked_sub(current_index)?
				} else {
					node_count
						.checked_sub(current_index)?
						.checked_add(target_index)?
				};
				Some(counter.checked_add(distance).unwrap_or(target_index))
			},
		);
		if update.is_ok() {
			self.clean_caches();
		}
	}

	fn node_url_with_connection(
		&self,
	) -> Result<(String, NodeConnectionId), mwc_wallet_libwallet::Error> {
		if self.state.node_url_list.is_empty() {
			return Err(mwc_wallet_libwallet::Error::NodeUrlIsEmpty);
		}
		let connection_id = self.get_node_connection_id();
		let index = usize::from(connection_id.node_index);
		self.state
			.node_url_list
			.get(index)
			.cloned()
			.map(|url| (url, connection_id))
			.ok_or(mwc_wallet_libwallet::Error::NodeUrlIsEmpty)
	}

	pub fn node_url(&self) -> Result<String, mwc_wallet_libwallet::Error> {
		self.node_url_with_connection().map(|(url, _)| url)
	}

	/// Return the configured node API secret without making a plaintext copy.
	///
	/// Trust model: code with access to `HTTPNodeClient` is trusted with this
	/// credential. This public accessor intentionally exposes a plaintext-readable
	/// reference; `Zeroizing` clears owned storage on drop but cannot prevent a
	/// caller from copying or logging the value. Retaining that exposure is an
	/// accepted API risk.
	pub fn node_api_secret(&self) -> &Option<Zeroizing<String>> {
		&self.state.node_api_secret
	}

	pub fn set_node_url(&mut self, node_url_list: Vec<String>) -> Result<(), Error> {
		validate_node_url_list(&node_url_list)?;
		self.replace_configuration(node_url_list, self.state.node_api_secret.clone());
		Ok(())
	}

	fn replace_configuration(
		&mut self,
		node_url_list: Vec<String>,
		node_api_secret: Option<Zeroizing<String>>,
	) {
		let connection = self.get_node_connection_id();
		self.state = Arc::new(HTTPNodeClientState::new(
			node_url_list,
			node_api_secret,
			self.state.client.clone(),
			connection.generation,
		));
		if self.state.node_url_list.is_empty() {
			self.advance_connection_counter();
		} else {
			// Changing configuration changes the connection identity. Move to
			// another counter value that still selects the same logical index.
			self.select_node_index_with_change(connection.node_index, true);
		}
	}

	/// Replace the node API secret without copying it out of zeroizing storage.
	pub fn set_node_api_secret(&mut self, node_api_secret: Option<Zeroizing<String>>) {
		self.replace_configuration(self.state.node_url_list.clone(), node_api_secret);
	}
}

impl NodeClient for HTTPNodeClient {
	fn clone_for_request(&self) -> Self {
		Self {
			state: Arc::clone(&self.state),
		}
	}

	fn set_node_index(&mut self, node_index: u8) {
		self.select_node_index_with_change(node_index, false);
	}
	fn get_node_index(&self) -> u8 {
		self.get_node_connection_id().node_index
	}

	fn get_node_connection_id(&self) -> NodeConnectionId {
		let counter = self.state.node_connection_counter.load(Ordering::SeqCst);
		let node_index = if self.state.node_url_list.is_empty() {
			0
		} else {
			u8::try_from(counter % (self.state.node_url_list.len() as u64)).unwrap_or(0)
		};
		NodeConnectionId {
			node_index,
			generation: counter,
		}
	}

	fn reset_cache(&self) {
		self.clean_caches();
	}

	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		let connection_id = self.get_node_connection_id();
		if let Some(version) = self.state.node_version_info.get_value(&connection_id) {
			return Some(version);
		}
		let retval = match self
			.send_json_request::<GetVersionResp>("get_version", &serde_json::Value::Null, NODE_VERSION_CALL_RETRY) //mainnet has 6 nodes.
		{
			Ok((n, connection_id)) => (
				NodeVersionInfo {
					node_version: n.node_version,
					block_header_version: n.block_header_version,
					verified: Some(true),
				},
				connection_id,
			),
			Err(e) if e.is_http_status(StatusCode::NOT_FOUND) => {
				// If node isn't available, allow offline functions
				return Some(NodeVersionInfo {
					node_version: "1.0.0".into(),
					block_header_version: 1,
					verified: Some(false),
				});
			}
			Err(e) => {
				let error = e.into_wallet_error();
				let safe_error = safe_node_error(&error);
				error!(
					"Unable to contact Node to get version info: {:?}, {}",
					self.node_url().map(|url| safe_node_text(&url)),
					safe_error
				);
				return None;
			}
		};
		self.state
			.node_version_info
			.set_value(retval.1, retval.0.clone());
		Some(retval.0)
	}

	fn test_mempool_accept(
		&self,
		request: &mwc_wallet_libwallet::transaction_preflight::MempoolAcceptRequest,
	) -> Result<
		mwc_wallet_libwallet::transaction_preflight::MempoolAcceptResponse,
		mwc_wallet_libwallet::Error,
	> {
		// A preflight and its publication must refer to the same selected node.
		// A retry starts a new preflight instead of silently disclosing to a fallback.
		let connection = self.get_node_connection_id();
		let params = serde_json::to_value([request])
			.map_err(|e| mwc_wallet_libwallet::Error::Format(e.to_string()))?;
		let (response, actual) = self.send_json_request("testmempoolaccept", &params, 0)?;
		if connection != actual || actual != self.get_node_connection_id() {
			return Err(mwc_wallet_libwallet::Error::Node(
				"Node changed during preflight".into(),
			));
		}
		Ok(response)
	}

	fn post_tx(
		&self,
		tx: &Transaction,
		fluff: bool,
		receipt: mwc_wallet_libwallet::transaction_preflight::PreflightReceipt,
	) -> Result<(), mwc_wallet_libwallet::Error> {
		let (address, connection) = self.node_url_with_connection()?;
		receipt.check(self, tx)?;
		if connection != self.get_node_connection_id() {
			return Err(mwc_wallet_libwallet::Error::Node(
				"Node changed before publication".into(),
			));
		}
		// Pin the validated endpoint. Do not use the generic failover loop here.
		let url = node_api_url(&address, &["v2", "foreign"])?;
		let params = json!([transaction_to_legacy_json(tx)?, fluff]);
		let request = build_request("push_transaction", &params);
		let response = self
			.state
			.client
			.post::<Request, Response>(url.as_str(), self.node_api_secret(), &request)
			.map_err(|e| mwc_wallet_libwallet::Error::ClientCallback(safe_node_error(&e)))?;
		response
			.into_result::<()>(&request.id)
			.map_err(|e| mwc_wallet_libwallet::Error::ClientCallback(safe_node_error(&e)))
	}

	/// Return the chain tip from a given trusted node.
	///
	/// The cached value retains the same trust as the node response; caching only
	/// reduces requests and is not an independent chain-validation mechanism.
	fn get_chain_tip(&self) -> Result<(u64, String, u64), mwc_wallet_libwallet::Error> {
		let connection_id = self.get_node_connection_id();
		if let Some(tip) = self.state.chain_tip.get_value(&connection_id) {
			return Ok(tip);
		}

		self.get_chain_tip_fresh()
	}

	fn get_chain_tip_fresh(&self) -> Result<(u64, String, u64), mwc_wallet_libwallet::Error> {
		let (result, connection_id) =
			self.send_json_request::<GetTipResp>("get_tip", &serde_json::Value::Null, 1)?;
		let res = (
			result.height,
			result.last_block_pushed,
			result.total_difficulty,
		);
		self.state.chain_tip.set_value(connection_id, res.clone());
		Ok(res)
	}

	/// Return header info from given height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, mwc_wallet_libwallet::Error> {
		let connection_id = self.get_node_connection_id();
		if let Some(h) = self.state.header_info.get_value(&(connection_id, height)) {
			return Ok(h);
		}

		self.get_header_info_fresh(height)
	}

	fn get_header_info_fresh(
		&self,
		height: u64,
	) -> Result<HeaderInfo, mwc_wallet_libwallet::Error> {
		let params = json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
		let (r, connection_id) = self.send_json_request::<mwc_api::BlockHeaderPrintable>(
			"get_header",
			&params,
			NODE_CALL_RETRY,
		)?;

		if r.height != height {
			return Err(mwc_wallet_libwallet::Error::Node(format!(
				"HTTPNodeClient::get_header_info, node returned a header for the wrong height, requested_height={} returned_height={}",
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
		self.state
			.header_info
			.set_value((connection_id, height), hdr.clone());
		Ok(hdr)
	}

	fn get_header_by_hash(
		&self,
		hash: &str,
	) -> Result<NodeHeaderLink, mwc_wallet_libwallet::Error> {
		let params = json!([null, hash, null]);
		let (header, _) = self.send_json_request::<mwc_api::BlockHeaderPrintable>(
			"get_header",
			&params,
			NODE_CALL_RETRY,
		)?;
		if header.hash != hash {
			return Err(mwc_wallet_libwallet::Error::Node(format!(
				"HTTPNodeClient::get_header_by_hash, requested hash {}, received {}",
				hash, header.hash
			)));
		}
		// A hash lookup can return a fork outside the selected header chain, so
		// neither read nor populate the height-keyed header cache here.
		Ok(NodeHeaderLink {
			height: header.height,
			hash: header.hash,
			previous: header.previous,
		})
	}

	/// Return Connected peers
	fn get_connected_peer_info(
		&self,
	) -> Result<Vec<PeerInfoDisplayLegacy>, mwc_wallet_libwallet::Error> {
		self.get_connected_peer_info_impls(1)
	}

	/// Get kernel implementation
	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, mwc_wallet_libwallet::Error> {
		self.get_kernel_impl(excess, min_height, max_height, NODE_CALL_RETRY)
	}

	/// Retrieve output details from node.
	///
	/// Trust model: the configured node is authoritative and trusted to honor the
	/// `get_outputs` contract by returning only outputs for the requested
	/// commitments, with consistent metadata for any duplicate entries. This
	/// method therefore validates transport, JSON-RPC, and field decoding errors,
	/// but deliberately does not revalidate response membership or conflicting
	/// duplicates. A node violating that RPC contract is outside the threat model.
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, NodeOutputDetails>, mwc_wallet_libwallet::Error> {
		if wallet_outputs.is_empty() {
			return Ok(HashMap::new());
		}

		// Parallelize larger JSON-RPC requests while keeping each request within
		// the node's configured output-query limit.
		let chunk_default = 200;
		let chunk_size = match env::var("MWC_OUTPUT_QUERY_SIZE") {
			Ok(s) => match s.parse::<usize>() {
				Ok(c) if c > 0 => c,
				Ok(_) => {
					error!(
						"MWC_OUTPUT_QUERY_SIZE must be greater than zero, defaulting to {}",
						chunk_default
					);
					chunk_default
				}
				Err(e) => {
					error!(
						"Unable to parse MWC_OUTPUT_QUERY_SIZE, defaulting to {}",
						chunk_default
					);
					error!("Reason: {}", e);
					chunk_default
				}
			},
			Err(_) => chunk_default,
		};
		trace!("Output query chunk size is: {}", chunk_size);

		let mut retries_remaining = NODE_CALL_RETRY;
		'retry: loop {
			let query_params: Vec<String> = wallet_outputs
				.iter()
				.map(|commit| commit.as_ref().to_hex())
				.collect();
			let (node_url, connection_id) = self.node_url_with_connection()?;
			let url = node_api_url(&node_url, &["v2", "foreign"])?;
			let api_secret = self.node_api_secret();
			let context_id = self.state.client.context_id();
			let cl = self.state.client.clone();
			let task = async move {
				let params: Vec<_> = query_params
					.chunks(chunk_size)
					.map(|commits| json!([commits, null, null, false, false]))
					.collect();

				let mut requests = Vec::with_capacity(params.len());
				for params in &params {
					requests.push(build_request("get_outputs", params));
				}

				let mut tasks = Vec::with_capacity(requests.len());
				let cl = &cl;
				let url = url.as_str();
				for request in &requests {
					let request_id = request.id.clone();
					tasks.push(async move {
						cl.post_async::<Request, Response>(url, api_secret, request)
							.await
							.map(|response| (response, request_id))
					});
				}

				let tasks: FuturesUnordered<_> = tasks.into_iter().collect();
				tasks.try_collect().await
			};

			let response: Result<Vec<_>, _> =
				mwc_util::run_global_async_block(task).map_err(|e| {
					mwc_wallet_libwallet::Error::ClientCallback(format!(
						"Async runtime error, {}",
						e
					))
				})?;

			let results: Vec<OutputPrintable> = match response {
				Ok(responses) => {
					let mut results = vec![];
					for (response, request_id) in responses {
						match response
							.into_result::<serde_json::Value>(&request_id)
							.and_then(|value| {
								deserialize_output_printables_with_context(context_id, value)
							}) {
							Ok(mut outputs) => results.append(&mut outputs),
							Err(e) if retries_remaining > 0 => {
								debug!("Retry to call API get_outputs, {}", safe_node_error(&e));
								self.increase_index_if_current(connection_id);
								retries_remaining = retries_remaining.saturating_sub(1);
								continue 'retry;
							}
							Err(e) => {
								let report = format!(
									"Unable to parse response for get_outputs: {}",
									safe_node_error(&e)
								);
								error!("{}", report);
								return Err(mwc_wallet_libwallet::Error::ClientCallback(report));
							}
						}
					}
					results
				}
				Err(e) if retries_remaining > 0 => {
					debug!("Retry to call API get_outputs, {}", safe_node_error(&e));
					self.increase_index_if_current(connection_id);
					retries_remaining = retries_remaining.saturating_sub(1);
					continue 'retry;
				}
				Err(e) => {
					let report = format!("Outputs by id failed: {}", safe_node_error(&e));
					error!("{}", report);
					return Err(mwc_wallet_libwallet::Error::ClientCallback(report));
				}
			};

			let mut output_details = HashMap::new();
			for output in results {
				if output.spent {
					continue;
				}
				let height = output.block_height.ok_or_else(|| {
					mwc_wallet_libwallet::Error::ClientCallback(format!(
						"Missing block height for output {:?}",
						output.commit
					))
				})?;
				output_details.insert(
					output.commit,
					NodeOutputDetails {
						commit: output.commit.as_ref().to_hex(),
						height,
						mmr_index: output.mmr_index,
					},
				);
			}
			return Ok(output_details);
		}
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
		mwc_wallet_libwallet::Error,
	> {
		let mut api_outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)> =
			Vec::new();

		let params = json!([start_index, end_index, max_outputs, Some(true)]);
		let context_id = self.state.client.context_id();
		let (res, _) = self.send_json_request_with_decoder(
			"get_unspent_outputs",
			&params,
			NODE_CALL_RETRY,
			|value| deserialize_output_listing_with_context(context_id, value),
		)?;
		// We asked for unspent outputs via the api but defensively filter out spent outputs just in case.
		for out in res.outputs.into_iter().filter(|out| out.spent == false) {
			let is_coinbase = match out.output_type {
				mwc_api::OutputType::Coinbase => true,
				mwc_api::OutputType::Transaction => false,
			};
			let range_proof = match out.range_proof() {
				Ok(r) => r,
				Err(e) => {
					let msg = format!(
						"Unexpected error in returned output (missing range proof) for commitment {:?}: {}",
						out.commit,
						safe_node_error(&e)
					);
					error!("{}", msg);
					return Err(mwc_wallet_libwallet::Error::ClientCallback(msg));
				}
			};
			let block_height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!(
						"Unexpected error in returned output (missing block height) for commitment {:?}",
						out.commit
					);
					error!("{}", msg);
					return Err(mwc_wallet_libwallet::Error::ClientCallback(msg));
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
	) -> Result<(u64, u64), mwc_wallet_libwallet::Error> {
		let params = json!([start_height, end_height]);
		let (res, _) =
			self.send_json_request::<OutputListing>("get_pmmr_indices", &params, NODE_CALL_RETRY)?;

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
	) -> Result<Vec<mwc_api::BlockPrintable>, mwc_wallet_libwallet::Error> {
		debug!(
			"Requesting blocks from heights {}-{}",
			start_height, end_height
		);
		if threads_number == 0 || threads_number > 20 {
			return Err(mwc_wallet_libwallet::Error::ClientCallback(
				"Block request thread count must be between 1 and 20".to_owned(),
			));
		}
		if start_height > end_height {
			return Err(mwc_wallet_libwallet::Error::ClientCallback(
				"Block request start height exceeds end height".to_owned(),
			));
		}

		let mut result_blocks: Vec<mwc_api::BlockPrintable> = Vec::new();
		let mut height = start_height;
		let mut done = false;
		let expected_connection = self.get_node_connection_id();
		let context_id = self.state.client.context_id();

		while !done && height <= end_height {
			let mut tasks = Vec::new();
			while tasks.len() < threads_number && height <= end_height && !done {
				if let Some(b) = self
					.state
					.block_info
					.get_value(&(expected_connection, height))
				{
					result_blocks.push(b); // using cache
				} else {
					let params =
						json!([Some(height), None::<Option<String>>, None::<Option<String>>]);
					tasks.push(async move {
						self.send_json_request_async_with_decoder(
							"get_block",
							&params,
							NODE_CALL_RETRY,
							|value| deserialize_block_printable_with_context(context_id, value),
						)
						.await
					});
				}
				if height == end_height {
					done = true;
				} else {
					// height <= end_height is a loop condition and this branch excludes
					// equality, so height is strictly below u64::MAX.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "height is strictly less than end_height in this branch"
					)]
					{
						height += 1;
					}
				}
			}

			if !tasks.is_empty() {
				let task = async {
					let task: FuturesUnordered<_> = tasks.into_iter().collect();
					task.try_collect().await
				};
				let res: Result<Vec<(mwc_api::BlockPrintable, NodeConnectionId)>, _> =
					mwc_util::run_global_async_block(task).map_err(|e| {
						mwc_wallet_libwallet::Error::ClientCallback(format!(
							"get_blocks_by_height: async runtime error: {}",
							safe_node_error(&e)
						))
					})?;
				match res {
					Ok(blocks) => {
						for (block, connection_id) in blocks {
							if connection_id != expected_connection {
								return Err(mwc_wallet_libwallet::Error::Node(format!(
									"get_blocks_by_height changed node while fetching a block range; expected {:?}, received {:?}. Partial results were discarded",
									expected_connection, connection_id
								)));
							}
							self.state
								.block_info
								.set_value((connection_id, block.header.height), block.clone());
							result_blocks.push(block);
						}
					}
					Err(e) => {
						let report = format!(
							"get_blocks_by_height: error calling api 'get_block' at {:?}. Error: {}",
							self.node_url().map(|url| safe_node_text(&url)),
							safe_node_error(&e)
						);
						error!("{}", report);
						return Err(mwc_wallet_libwallet::Error::ClientCallback(report));
					}
				}
			}
			let current_connection = self.get_node_connection_id();
			if current_connection != expected_connection {
				return Err(mwc_wallet_libwallet::Error::Node(format!(
					"get_blocks_by_height changed node while fetching a block range; expected {:?}, current {:?}. Partial results were discarded",
					expected_connection, current_connection
				)));
			}
		}

		Ok(result_blocks)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::HTTPNodeClient;
	use mwc_wallet_libwallet;
	use mwc_wallet_libwallet::NodeClient;
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
	use mwc_wallet_util::mwc_util;
	use std::io::{ErrorKind, Read, Write};
	use std::net::TcpListener;
	use std::thread;
	use std::thread::JoinHandle;
	use std::time::{Duration, Instant};

	fn preflight_test_transaction(context_id: u32) -> Transaction {
		use mwc_wallet_util::mwc_core::{
			core::{FeeFields, KernelFeatures},
			libtx::{build, ProofBuilder},
		};
		use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
		use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain};
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keys = ExtKeychain::from_seed(&secp, &[19; 32], false).unwrap();
		let input = ExtKeychain::derive_key_id(3, 1, 0, 0, 0).unwrap();
		let output = ExtKeychain::derive_key_id(3, 2, 0, 0, 0).unwrap();
		let proof = ProofBuilder::new(&secp, &keys).unwrap();
		build::transaction(
			context_id,
			&mut secp,
			KernelFeatures::Plain {
				fee: FeeFields::new(2).unwrap(),
			},
			&[
				build::feature_input(
					10,
					mwc_wallet_util::mwc_core::core::OutputFeatures::Plain,
					input,
				),
				build::height_tagged_output(8, output, 1),
			],
			&keys,
			&proof,
		)
		.unwrap()
	}

	fn serve_preflight(
		accept: bool,
		unsupported: bool,
	) -> (String, JoinHandle<Vec<serde_json::Value>>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let url = format!("http://{}", listener.local_addr().unwrap());
		let server = thread::spawn(move || {
			let mut requests = Vec::new();
			let deadline = Instant::now() + Duration::from_secs(5);
			let expected = if accept { 2 } else { 1 };
			while requests.len() < expected {
				assert!(
					Instant::now() < deadline,
					"missing preflight/publication request"
				);
				let (mut stream, _) = match listener.accept() {
					Ok(stream) => stream,
					Err(e) if e.kind() == ErrorKind::WouldBlock => {
						thread::sleep(Duration::from_millis(5));
						continue;
					}
					Err(e) => panic!("{}", e),
				};
				stream.set_nonblocking(false).unwrap();
				stream
					.set_read_timeout(Some(Duration::from_secs(2)))
					.unwrap();
				let mut wire = Vec::new();
				let request = loop {
					let mut buffer = [0; 4096];
					let count = stream.read(&mut buffer).unwrap();
					assert!(count > 0);
					wire.extend_from_slice(&buffer[..count]);
					if let Some(end) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
						let headers = String::from_utf8_lossy(&wire[..end]);
						let size = headers
							.lines()
							.find_map(|line| {
								let (name, value) = line.split_once(':')?;
								if name.eq_ignore_ascii_case("content-length") {
									value.trim().parse::<usize>().ok()
								} else {
									None
								}
							})
							.unwrap();
						if wire.len() >= end + 4 + size {
							break serde_json::from_slice::<serde_json::Value>(
								&wire[end + 4..end + 4 + size],
							)
							.unwrap();
						}
					}
				};
				let reply = if requests.is_empty() {
					assert_eq!(request["method"], "testmempoolaccept");
					let unsigned = &request["params"][0];
					assert!(unsigned["transactions"][0]["is_complete"].as_bool().unwrap());
					assert!(unsigned["transactions"][0]["outputs"][0].get("proof").is_none());
					assert!(unsigned["transactions"][0]["kernels"][0].get("excess_sig").is_none());
					assert!(unsigned.get("participant_data").is_none());
					if unsupported {
						json!({"jsonrpc":"2.0", "id":request["id"], "error":{"code":-32601,"message":"Method not found"}})
					} else {
						use mwc_wallet_libwallet::transaction_preflight::{
							MempoolAcceptRequest, MempoolAcceptResponse,
						};
						let description =
							serde_json::from_value::<MempoolAcceptRequest>(unsigned.clone())
								.unwrap();
						let mut response = MempoolAcceptResponse::new(
							&description,
							mwc_wallet_util::mwc_core::core::hash::Hash::default(),
							10,
						);
						response.transactions[0].balance_checked = true;
						if !accept {
							response.reject("input_missing", "already spent".into());
						}
						json!({"jsonrpc":"2.0","id":request["id"],"result":{"Ok":response}})
					}
				} else {
					assert_eq!(request["method"], "push_transaction");
					json!({"jsonrpc":"2.0","id":request["id"],"result":{"Ok":null}})
				};
				requests.push(request);
				let body = reply.to_string();
				write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
			}
			// A rejected/unsupported check must never be followed by a signed push.
			let until = Instant::now() + Duration::from_millis(200);
			while Instant::now() < until {
				assert!(
					listener.accept().is_err(),
					"unexpected extra RPC after preflight"
				);
				thread::sleep(Duration::from_millis(5));
			}
			requests
		});
		(url, server)
	}

	#[test]
	fn preflight_http_serialization_failure_returns_error() {
		use mwc_wallet_libwallet::transaction_preflight::{
			MempoolAcceptRequest, PreflightKernel, PreflightTransaction,
		};
		use mwc_wallet_util::mwc_core::core::{FeeFields, KernelFeatures};

		let client = HTTPNodeClient::new(0, vec![], None).unwrap();
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

		let error = client.test_mempool_accept(&request).unwrap_err();
		assert!(matches!(
			error,
			mwc_wallet_libwallet::Error::Format(message) if message.contains("fee is zero")
		));
	}

	#[test]
	fn preflight_http_rejection_and_unsupported_node_never_receive_signed_transaction() {
		mwc_util::init_global_runtime().unwrap();
		let tx = preflight_test_transaction(0);
		for unsupported in [false, true] {
			let (url, server) = serve_preflight(false, unsupported);
			let client = HTTPNodeClient::new(0, vec![url], None).unwrap();
			assert!(mwc_wallet_libwallet::owner::post_tx(0, &client, &tx, false).is_err());
			assert_eq!(server.join().unwrap().len(), 1);
		}
	}

	#[test]
	fn preflight_http_success_validates_once_before_publication() {
		mwc_util::init_global_runtime().unwrap();
		let context_id = 7;
		let tx = preflight_test_transaction(context_id);
		let (url, server) = serve_preflight(true, false);
		let client = HTTPNodeClient::new(context_id, vec![url], None).unwrap();
		mwc_wallet_libwallet::owner::post_tx(context_id, &client, &tx, false).unwrap();
		assert_eq!(server.join().unwrap().len(), 2);
	}

	fn serve_version_response(status: &str, body: &str) -> (String, JoinHandle<()>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let node_url = format!("http://{}", listener.local_addr().unwrap());
		let response = format!(
			"HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
			status,
			body.len(),
			body
		);
		let server = thread::spawn(move || {
			for _ in 0..=NODE_VERSION_CALL_RETRY {
				let (mut stream, _) = listener.accept().unwrap();
				stream
					.set_read_timeout(Some(Duration::from_secs(2)))
					.unwrap();
				let mut request = [0u8; 4096];
				let bytes_read = stream.read(&mut request).unwrap();
				assert!(bytes_read > 0);
				stream.write_all(response.as_bytes()).unwrap();
			}
		});
		(node_url, server)
	}

	fn serve_single_rpc_response(
		expected_method: &'static str,
		body: serde_json::Value,
	) -> (String, JoinHandle<()>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let node_url = format!("http://{}", listener.local_addr().unwrap());
		let body = body.to_string();
		let response = format!(
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
			body.len(),
			body
		);
		let server = thread::spawn(move || {
			let started = Instant::now();
			loop {
				match listener.accept() {
					Ok((mut stream, _)) => {
						stream.set_nonblocking(false).unwrap();
						stream
							.set_read_timeout(Some(Duration::from_secs(2)))
							.unwrap();
						let mut request = [0u8; 4096];
						let bytes_read = stream.read(&mut request).unwrap();
						let request = String::from_utf8_lossy(&request[..bytes_read]);
						assert!(request.contains(expected_method));
						stream.write_all(response.as_bytes()).unwrap();
						break;
					}
					Err(error) if error.kind() == ErrorKind::WouldBlock => {
						assert!(
							started.elapsed() < Duration::from_secs(5),
							"client did not make the expected RPC request"
						);
						thread::yield_now();
					}
					Err(error) => panic!("unable to accept RPC request: {}", error),
				}
			}
		});
		(node_url, server)
	}

	fn serve_block_response(height: u64) -> (String, JoinHandle<()>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let node_url = format!("http://{}", listener.local_addr().unwrap());
		let body = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"result": {
				"Ok": {
					"header": {
						"hash": "block-hash",
						"version": 1,
						"height": height,
						"previous": "previous-hash",
						"prev_root": "previous-root",
						"timestamp": "2026-08-28T00:00:00Z",
						"output_root": "output-root",
						"output_mmr_size": 0,
						"range_proof_root": "range-proof-root",
						"kernel_root": "kernel-root",
						"kernel_mmr_size": 0,
						"nonce": 0,
						"edge_bits": 29,
						"cuckoo_solution": [],
						"total_difficulty": 1,
						"secondary_scaling": 1,
						"total_kernel_offset": "kernel-offset"
					},
					"inputs": [],
					"outputs": [{
						"output_type": "Coinbase",
						"commit": "083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f",
						"spent": false,
						"proof": null,
						"proof_hash": "ed6ba96009b86173bade6a9227ed60422916593fa32dd6d78b25b7a4eeef4946",
						"block_height": height,
						"merkle_proof": null,
						"mmr_index": 9
					}],
					"kernels": []
				}
			}
		})
		.to_string();
		let response = format!(
			"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
			body.len(),
			body
		);
		let server = thread::spawn(move || {
			let started = Instant::now();
			loop {
				match listener.accept() {
					Ok((mut stream, _)) => {
						stream.set_nonblocking(false).unwrap();
						stream
							.set_read_timeout(Some(Duration::from_secs(2)))
							.unwrap();
						let mut request = [0u8; 4096];
						let bytes_read = stream.read(&mut request).unwrap();
						let request = String::from_utf8_lossy(&request[..bytes_read]);
						assert!(request.contains("POST /v2/foreign"));
						stream.write_all(response.as_bytes()).unwrap();
						break;
					}
					Err(error) if error.kind() == ErrorKind::WouldBlock => {
						assert!(
							started.elapsed() < Duration::from_secs(5),
							"client did not make the block request"
						);
						thread::yield_now();
					}
					Err(error) => panic!("unable to accept block request: {}", error),
				}
			}
		});
		(node_url, server)
	}

	#[test]
	fn node_endpoint_urls_use_structured_paths() {
		assert_eq!(
			node_api_url("https://node.example/proxy/", &["v2", "foreign"]).unwrap(),
			"https://node.example/proxy/v2/foreign"
		);
		assert!(node_api_url("https://node.example?token=secret", &["v2", "foreign"]).is_err());
		assert!(node_api_url("https://node.example#api", &["v2", "foreign"]).is_err());
		assert!(node_api_url("ftp://node.example", &["v2", "foreign"]).is_err());
	}

	#[test]
	fn uncached_blocks_use_the_async_http_path() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let height = 42;
		let (node_url, server) = serve_block_response(height);
		let client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();

		let blocks = client.get_blocks_by_height(height, height, 1).unwrap();
		server.join().unwrap();

		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0].header.height, height);
		assert_eq!(blocks[0].outputs.len(), 1);
		assert_eq!(blocks[0].outputs[0].block_height, Some(height));
		assert_eq!(blocks[0].outputs[0].context_id, 0);
	}

	#[test]
	fn nonempty_output_response_uses_context_aware_deserialization() {
		let response: Response = serde_json::from_value(serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"result": {
				"Ok": [{
					"output_type": "Coinbase",
					"commit": "083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f",
					"spent": false,
					"proof": null,
					"proof_hash": "ed6ba96009b86173bade6a9227ed60422916593fa32dd6d78b25b7a4eeef4946",
					"block_height": 42,
					"merkle_proof": null,
					"mmr_index": 9
				}]
			}
		}))
		.unwrap();
		let value = response
			.into_result::<serde_json::Value>(&serde_json::json!(1))
			.unwrap();

		let outputs = deserialize_output_printables_with_context(7, value).unwrap();

		assert_eq!(outputs.len(), 1);
		assert_eq!(outputs[0].block_height, Some(42));
		assert_eq!(outputs[0].mmr_index, 9);
		assert_eq!(outputs[0].context_id, 7);
	}

	#[test]
	fn get_outputs_by_pmmr_index_decodes_nonempty_output_listing_with_context() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (node_url, server) = serve_single_rpc_response(
			"get_unspent_outputs",
			serde_json::json!({
				"jsonrpc": "2.0",
				"id": 1,
				"result": {
					"Ok": {
						"highest_index": 20,
						"last_retrieved_index": 9,
						"outputs": [{
							"output_type": "Coinbase",
							"commit": "083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f",
							"spent": false,
							"proof": "00",
							"proof_hash": "ed6ba96009b86173bade6a9227ed60422916593fa32dd6d78b25b7a4eeef4946",
							"block_height": 42,
							"merkle_proof": null,
							"mmr_index": 9
						}]
					}
				}
			}),
		);
		let client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();

		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(1, None, 100).unwrap();
		server.join().unwrap();

		assert_eq!(highest_index, 20);
		assert_eq!(last_retrieved_index, 9);
		assert_eq!(outputs.len(), 1);
		assert!(outputs[0].2);
		assert_eq!(outputs[0].3, 42);
		assert_eq!(outputs[0].4, 9);
		assert_eq!(outputs[0].1.len().unwrap(), 1);
	}

	#[test]
	fn version_fallback_requires_exact_http_not_found_status() {
		let text_only_404 =
			JsonRequestError::without_http_status(mwc_wallet_libwallet::Error::ClientCallback(
				"Cannot parse JSON response at column 404".to_owned(),
			));
		assert!(!text_only_404.is_http_status(StatusCode::NOT_FOUND));

		let not_found = JsonRequestError {
			error: mwc_wallet_libwallet::Error::ClientCallback("not found".to_owned()),
			http_status: Some(StatusCode::NOT_FOUND),
		};
		assert!(not_found.is_http_status(StatusCode::NOT_FOUND));
		assert!(!not_found.is_http_status(StatusCode::INTERNAL_SERVER_ERROR));
	}

	#[test]
	fn version_fallback_does_not_accept_404_in_json_rpc_error_text() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let body = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"error": {
				"code": -32000,
				"message": "unrelated error containing 404",
				"data": null
			}
		})
		.to_string();
		let (node_url, server) = serve_version_response("200 OK", &body);
		let mut client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();

		let version = client.get_version_info();
		server.join().unwrap();

		assert!(version.is_none());
	}

	#[test]
	fn version_fallback_accepts_actual_http_not_found() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (node_url, server) = serve_version_response("404 Not Found", "");
		let mut client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();

		let version = client.get_version_info().unwrap();
		server.join().unwrap();

		assert_eq!(version.node_version, "1.0.0");
		assert_eq!(version.block_header_version, 1);
		assert_eq!(version.verified, Some(false));
	}

	#[test]
	fn request_handles_preserve_version_cache_and_failover() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (failed_url, failed_server) = serve_single_rpc_response(
			"get_version",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 1,
				"error": { "code": -32000, "message": "node unavailable" }
			}),
		);
		let (working_url, working_server) = serve_single_rpc_response(
			"get_version",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 1,
				"result": { "Ok": { "node_version": "7.0.0", "block_header_version": 3 } }
			}),
		);
		let mut client = HTTPNodeClient::new(0, vec![failed_url, working_url], None).unwrap();
		let initial_connection = client.get_node_connection_id();
		let mut request = client.clone_for_request();
		assert_eq!(request.get_version_info().unwrap().node_version, "7.0.0");
		failed_server.join().unwrap();
		working_server.join().unwrap();
		let working_connection = request.get_node_connection_id();
		assert_eq!(working_connection.node_index, 1);
		assert_ne!(working_connection, initial_connection);
		drop(request);

		// Both servers have stopped: these calls must reuse the successful lookup.
		assert_eq!(client.get_node_connection_id(), working_connection);
		assert_eq!(
			client
				.clone_for_request()
				.get_version_info()
				.unwrap()
				.node_version,
			"7.0.0"
		);
		assert_eq!(client.get_version_info().unwrap().node_version, "7.0.0");
	}

	#[test]
	fn request_handles_keep_old_responses_out_of_reconfigured_caches() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (old_url, old_server) = serve_single_rpc_response(
			"get_version",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 1,
				"result": { "Ok": { "node_version": "old-node", "block_header_version": 2 } }
			}),
		);
		let (new_url, new_server) = serve_single_rpc_response(
			"get_version",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 1,
				"result": { "Ok": { "node_version": "new-node", "block_header_version": 3 } }
			}),
		);
		let mut client = HTTPNodeClient::new(0, vec![old_url.clone()], None).unwrap();
		let mut old_request = client.clone_for_request();
		let old_connection = old_request.get_node_connection_id();
		client.set_node_url(vec![new_url.clone()]).unwrap();
		assert_ne!(client.get_node_connection_id(), old_connection);
		assert_eq!(old_request.node_url().unwrap(), old_url);

		// A request acquired before the configuration change completes afterward.
		assert_eq!(
			old_request.get_version_info().unwrap().node_version,
			"old-node"
		);
		old_server.join().unwrap();
		assert_eq!(client.get_version_info().unwrap().node_version, "new-node");
		new_server.join().unwrap();
		old_request.reset_cache();
		assert_eq!(client.node_url().unwrap(), new_url);
		assert_eq!(client.get_version_info().unwrap().node_version, "new-node");
	}

	#[test]
	fn request_handles_keep_old_credentials_and_caches_after_secret_change() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (url, server) = serve_single_rpc_response(
			"get_version",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 1,
				"result": { "Ok": { "node_version": "old-credentials", "block_header_version": 3 } }
			}),
		);
		let mut client =
			HTTPNodeClient::new(0, vec![url], Some(Zeroizing::new("old-secret".to_owned())))
				.unwrap();
		let mut old_request = client.clone_for_request();
		let old_connection = old_request.get_node_connection_id();
		client.set_node_api_secret(Some(Zeroizing::new("new-secret".to_owned())));
		let new_connection = client.get_node_connection_id();
		assert_ne!(new_connection, old_connection);
		assert_eq!(new_connection.node_index, old_connection.node_index);
		assert_eq!(
			old_request.node_api_secret().as_ref().unwrap().as_str(),
			"old-secret"
		);
		assert_eq!(
			client.node_api_secret().as_ref().unwrap().as_str(),
			"new-secret"
		);
		assert_eq!(
			old_request.get_version_info().unwrap().node_version,
			"old-credentials"
		);
		server.join().unwrap();
		assert!(
			client
				.state
				.node_version_info
				.get_value(&new_connection)
				.is_none()
		);
		assert!(
			client
				.state
				.node_version_info
				.get_value(&old_connection)
				.is_none()
		);
	}

	#[test]
	fn kernel_not_found_classification_does_not_hide_protocol_errors() {
		let params = serde_json::json!(["kernel-excess", 10, 20]);
		let method_error = |message: &str| {
			Error::GenericError(
				serde_json::to_string(message).expect("test error message must serialize"),
			)
		};

		assert!(is_kernel_not_found_error(
			&method_error(KERNEL_NOT_FOUND_ERROR),
			&params
		));
		assert!(is_kernel_not_found_error(
			&method_error(&format!(
				"get_kernel({}): {}",
				serde_json::to_string(&params).unwrap(),
				KERNEL_NOT_FOUND_ERROR
			)),
			&params
		));
		assert!(!is_kernel_not_found_error(&Error::IdMismatch, &params));
		assert!(!is_kernel_not_found_error(&Error::VersionMismatch, &params));
		assert!(!is_kernel_not_found_error(
			&Error::MalformedResponse("NotFound".to_owned()),
			&params
		));
		assert!(!is_kernel_not_found_error(
			&method_error("API Internal error: database NotFound while reading kernel index"),
			&params
		));
		assert!(!is_kernel_not_found_error(
			&Error::GenericError(serde_json::json!({"message": "NotFound"}).to_string()),
			&params
		));
		assert!(!is_kernel_not_found_error(
			&method_error(&format!(
				"get_kernel([\"another-kernel\",10,20]): {}",
				KERNEL_NOT_FOUND_ERROR
			)),
			&params
		));
	}

	fn located_kernel(excess: Commitment, height: u64) -> LocatedTxKernel {
		let mut tx_kernel = TxKernel::empty().expect("empty test kernel must build");
		tx_kernel.excess = excess;
		LocatedTxKernel {
			tx_kernel,
			height,
			mmr_index: 7,
		}
	}

	#[test]
	fn located_kernel_response_must_match_the_request() {
		let requested = Commitment::from_vec(vec![0; 33]).unwrap();
		let different = Commitment::from_vec(vec![1; 33]).unwrap();

		let valid = validate_located_kernel_response(
			&requested,
			Some(10),
			Some(20),
			located_kernel(requested, 15),
		)
		.unwrap();
		assert_eq!(valid.0.excess, requested);
		assert_eq!(valid.1, 15);
		assert_eq!(valid.2, 7);

		assert!(matches!(
			validate_located_kernel_response(
				&requested,
				Some(10),
				Some(20),
				located_kernel(different, 15)
			),
			Err(mwc_wallet_libwallet::Error::Node(message))
				if message.contains("different kernel")
		));
		for height in [9, 21] {
			assert!(matches!(
				validate_located_kernel_response(
					&requested,
					Some(10),
					Some(20),
					located_kernel(requested, height)
				),
				Err(mwc_wallet_libwallet::Error::Node(message))
					if message.contains("outside the requested height range")
			));
		}
	}

	#[test]
	fn fresh_tip_bypasses_a_refilled_cache() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let (node_url, server) = serve_single_rpc_response(
			"get_tip",
			json!({
				"jsonrpc": "2.0",
				"id": 1,
				"result": { "Ok": {
					"height": 11,
					"last_block_pushed": "new-tip",
					"prev_block_to_last": "previous-hash",
					"total_difficulty": 110
				}}
			}),
		);
		let client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();
		client.reset_cache();
		// A response from a request started before reset_cache can arrive now.
		client.state.chain_tip.set_value(
			client.get_node_connection_id(),
			(10, "old-tip".to_owned(), 100),
		);
		assert_eq!(client.get_chain_tip().unwrap().0, 10);

		let tip = client.get_chain_tip_fresh().unwrap();
		server.join().unwrap();
		assert_eq!(tip, (11, "new-tip".to_owned(), 110));
		assert_eq!(client.get_chain_tip().unwrap(), tip);
	}

	#[test]
	fn fresh_header_bypasses_a_refilled_cache_and_validates_height() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for returned_height in [10, 11] {
			let (node_url, server) = serve_single_rpc_response(
				"get_header",
				json!({
					"jsonrpc": "2.0",
					"id": 1,
					"result": { "Ok": {
						"hash": "new-header",
						"version": 1,
						"height": returned_height,
						"previous": "previous-hash",
						"prev_root": "previous-root",
						"timestamp": "2026-09-25T00:00:00Z",
						"output_root": "output-root",
						"output_mmr_size": 0,
						"range_proof_root": "range-proof-root",
						"kernel_root": "kernel-root",
						"kernel_mmr_size": 0,
						"nonce": 0,
						"edge_bits": 29,
						"cuckoo_solution": [],
						"total_difficulty": 100,
						"secondary_scaling": 1,
						"total_kernel_offset": "kernel-offset"
					}}
				}),
			);
			let client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();
			client.reset_cache();
			// Model an old in-flight response repopulating the header cache.
			client.state.header_info.set_value(
				(client.get_node_connection_id(), 10),
				HeaderInfo {
					height: 10,
					hash: "old-header".to_owned(),
					confirmed_time: String::new(),
					version: 1,
					nonce: 0,
					total_difficulty: 100,
				},
			);
			assert_eq!(client.get_header_info(10).unwrap().hash, "old-header");

			let header = client.get_header_info_fresh(10);
			server.join().unwrap();
			if returned_height == 10 {
				assert_eq!(header.unwrap().hash, "new-header");
				assert_eq!(client.get_header_info(10).unwrap().hash, "new-header");
			} else {
				let error = header
					.err()
					.expect("a header for the wrong height must fail");
				assert!(error.to_string().contains("wrong height"));
				assert_eq!(client.get_header_info(10).unwrap().hash, "old-header");
			}
		}
	}

	#[test]
	fn header_by_hash_bypasses_height_cache_and_validates_hash() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for returned_hash in ["body-header", "wrong-header"] {
			let (node_url, server) = serve_single_rpc_response(
				"\"params\":[null,\"body-header\",null]",
				json!({
					"jsonrpc": "2.0", "id": 1,
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
				}),
			);
			let client = HTTPNodeClient::new(0, vec![node_url], None).unwrap();
			client.state.header_info.set_value(
				(client.get_node_connection_id(), 10),
				HeaderInfo {
					height: 10,
					hash: "header-fork".to_owned(),
					confirmed_time: String::new(),
					version: 1,
					nonce: 0,
					total_difficulty: 100,
				},
			);

			let result = client.get_header_by_hash("body-header");
			server.join().unwrap();
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
				assert!(
					matches!(result, Err(mwc_wallet_libwallet::Error::Node(message))
					if message.contains("requested hash body-header, received wrong-header"))
				);
			}
			// A by-hash response must not poison a height lookup on another fork.
			assert_eq!(client.get_header_info(10).unwrap().hash, "header-fork");
		}
	}

	#[test]
	fn cached_value_evicts_the_least_recently_used_entry() {
		let cache = CachedValue::<u8, u8>::new(2);
		cache.set_value(1, 10);
		cache.set_value(2, 20);

		assert_eq!(cache.get_value(&1), Some(10));
		cache.set_value(3, 30);

		assert_eq!(cache.get_value(&1), Some(10));
		assert_eq!(cache.get_value(&2), None);
		assert_eq!(cache.get_value(&3), Some(30));
		assert_eq!(cache.data.read_recursive().len(), 2);
	}

	#[test]
	fn cached_value_removes_expired_entries() {
		let cache = CachedValue::<u8, u8>::new(2);
		let expired_age = CACHE_VALID_TIME
			.checked_add(Duration::from_millis(1))
			.expect("test cache age is representable");
		let cached_at = Instant::now()
			.checked_sub(expired_age)
			.expect("monotonic clock has advanced past the cache lifetime");
		let _ = cache.data.write().put(1, (10, cached_at));

		assert_eq!(cache.get_value(&1), None);
		assert!(!cache.data.read_recursive().contains(&1));
	}

	#[test]
	fn rejects_more_node_urls_than_stored_index_can_address() {
		let urls = vec!["http://127.0.0.1:13413".to_owned(); 257];
		assert!(HTTPNodeClient::new(0, urls, None).is_err());
	}

	#[test]
	fn node_urls_are_validated_before_configuration_changes() {
		for invalid_url in [
			"node-without-a-scheme",
			"ftp://node.example",
			"https://node.example?token=secret",
			"https://node.example#foreign",
		] {
			assert!(
				HTTPNodeClient::new(
					0,
					vec![
						"https://valid-node.example".to_owned(),
						invalid_url.to_owned()
					],
					None,
				)
				.is_err(),
				"accepted invalid node URL {invalid_url}"
			);
		}

		let original_url = "https://original-node.example".to_owned();
		let mut client = HTTPNodeClient::new(0, vec![original_url.clone()], None).unwrap();
		let original_connection = client.get_node_connection_id();
		assert!(
			client
				.set_node_url(vec![
					"https://valid-node.example".to_owned(),
					"not-a-url".to_owned(),
				])
				.is_err()
		);
		assert_eq!(client.node_url().unwrap(), original_url);
		assert_eq!(client.get_node_connection_id(), original_connection);
	}

	#[test]
	fn cloned_clients_do_not_share_configuration_or_caches() -> Result<(), String> {
		let original = HTTPNodeClient::new(0, vec!["http://node-0.invalid".to_owned()], None)
			.map_err(|e| e.to_string())?;
		let original_connection = original.get_node_connection_id();
		let original_tip = (10, "node-0-tip".to_owned(), 100);
		original
			.state
			.chain_tip
			.set_value(original_connection, original_tip.clone());

		let mut cloned = original.clone();
		assert_eq!(
			cloned.state.chain_tip.get_value(&original_connection),
			Some(original_tip.clone())
		);

		cloned
			.state
			.chain_tip
			.set_value(original_connection, (20, "changed-tip".to_owned(), 200));
		cloned
			.set_node_url(vec!["http://new-node-0.invalid".to_owned()])
			.map_err(|e| e.to_string())?;

		assert_eq!(
			original.node_url().map_err(|e| e.to_string())?,
			"http://node-0.invalid"
		);
		assert_eq!(original.get_node_connection_id(), original_connection);
		assert_eq!(
			original.state.chain_tip.get_value(&original_connection),
			Some(original_tip)
		);
		assert_eq!(
			cloned.node_url().map_err(|e| e.to_string())?,
			"http://new-node-0.invalid"
		);
		assert_ne!(cloned.get_node_connection_id(), original_connection);
		assert!(
			cloned
				.state
				.chain_tip
				.get_value(&original_connection)
				.is_none()
		);
		Ok(())
	}

	#[test]
	fn failover_invalidates_chain_caches_and_advances_connection_counter() -> Result<(), String> {
		let client = HTTPNodeClient::new(
			0,
			vec![
				"http://node-0.invalid".to_owned(),
				"http://node-1.invalid".to_owned(),
			],
			None,
		)
		.map_err(|e| e.to_string())?;
		let node_0 = client.get_node_connection_id();
		client
			.state
			.chain_tip
			.set_value(node_0, (10, "node-0-tip".to_owned(), 100));
		client.state.node_version_info.set_value(
			node_0,
			NodeVersionInfo {
				node_version: "node-0-version".to_owned(),
				block_header_version: 1,
				verified: Some(true),
			},
		);
		client.state.header_info.set_value(
			(node_0, 10),
			HeaderInfo {
				height: 10,
				hash: "node-0-tip".to_owned(),
				confirmed_time: String::new(),
				version: 1,
				nonce: 0,
				total_difficulty: 100,
			},
		);

		client.clone_for_request().increase_index();
		let node_1 = client.get_node_connection_id();
		assert_eq!(node_1.node_index, 1);
		assert_ne!(node_1, node_0);
		assert!(client.state.node_version_info.get_value(&node_0).is_none());
		assert!(client.state.chain_tip.get_value(&node_0).is_none());
		assert!(client.state.header_info.get_value(&(node_0, 10)).is_none());

		client.increase_index();
		let node_0_again = client.get_node_connection_id();
		assert_eq!(node_0_again.node_index, 0);
		assert_ne!(node_0_again, node_0);

		client
			.state
			.node_connection_counter
			.store(u64::MAX, Ordering::SeqCst);
		client.increase_index();
		let wrapped = client.get_node_connection_id();
		assert_eq!(wrapped.generation, 0);
		assert_eq!(wrapped.node_index, 0);
		Ok(())
	}

	#[test]
	fn stale_failure_does_not_advance_the_connection_again() -> Result<(), String> {
		let client = HTTPNodeClient::new(
			0,
			vec![
				"http://node-0.invalid".to_owned(),
				"http://node-1.invalid".to_owned(),
				"http://node-2.invalid".to_owned(),
			],
			None,
		)
		.map_err(|e| e.to_string())?;
		let failed_connection = client.get_node_connection_id();
		client.increase_index_if_current(failed_connection);
		let node_1 = client.get_node_connection_id();
		assert_eq!(node_1.node_index, 1);

		client
			.clone_for_request()
			.increase_index_if_current(failed_connection);
		assert_eq!(client.get_node_connection_id(), node_1);
		Ok(())
	}

	#[test]
	fn explicit_node_and_url_updates_keep_counter_and_index_consistent() -> Result<(), String> {
		let mut client = HTTPNodeClient::new(
			0,
			vec![
				"http://node-0.invalid".to_owned(),
				"http://node-1.invalid".to_owned(),
				"http://node-2.invalid".to_owned(),
			],
			None,
		)
		.map_err(|e| e.to_string())?;

		client.set_node_index(2);
		let selected = client.get_node_connection_id();
		assert_eq!(selected.node_index, 2);
		assert_eq!(u64::from(selected.node_index), selected.generation % 3);

		client
			.set_node_url(vec![
				"http://new-node-0.invalid".to_owned(),
				"http://new-node-1.invalid".to_owned(),
				"http://new-node-2.invalid".to_owned(),
			])
			.map_err(|e| e.to_string())?;
		let replaced = client.get_node_connection_id();
		assert_eq!(replaced.node_index, 2);
		assert_ne!(replaced, selected);
		assert_eq!(u64::from(replaced.node_index), replaced.generation % 3);
		Ok(())
	}

	#[test]
	fn node_index_updates_are_atomic_across_threads() -> Result<(), String> {
		let client = HTTPNodeClient::new(
			0,
			vec![
				"http://node-0.invalid".to_owned(),
				"http://node-1.invalid".to_owned(),
			],
			None,
		)
		.map_err(|e| e.to_string())?;
		let mut threads = Vec::new();
		for _ in 0..8 {
			let client = client.clone_for_request();
			threads.push(thread::spawn(move || {
				for _ in 0..1_000 {
					client.increase_index();
					let connection = client.get_node_connection_id();
					assert_eq!(u64::from(connection.node_index), connection.generation % 2);
				}
			}));
		}
		for thread in threads {
			thread
				.join()
				.map_err(|_| "Node index test thread terminated unexpectedly".to_owned())?;
		}
		assert_eq!(client.get_node_connection_id().generation, 8_000);
		assert_eq!(
			client.node_url().map_err(|e| e.to_string())?,
			"http://node-0.invalid"
		);
		Ok(())
	}

	// Let's do a stress test for the Node.
	// Normally test is ignoring because the point of that test to run it manually and review the results.
	#[test]
	#[ignore]
	fn run_node_stress_test() -> Result<(), mwc_wallet_libwallet::Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		let threads_number = 40;
		let iterations_per_thread = 5;
		let print_call_latency = false;
		let print_stat = true;

		//let node_url = "http://127.0.0.1:13413";
		let node_url = "https://mwc713.floonet.mwc.mw".to_owned();
		let mut node_list = Vec::new();
		node_list.push(node_url);
		let api_secret = "11ne3EAUtOXVKwhxm84U";

		//let node_url = "http://52.47.109.152:13413";
		//let api_secret = "xgSQOfZLDkoYOVWTmjps";

		let mut joins: Vec<JoinHandle<Result<(), mwc_wallet_libwallet::Error>>> = Vec::new();

		for thr_idx in 0..threads_number {
			let thr_idx = thr_idx;

			let kernel_exist = Commitment::from_vec(
				mwc_util::from_hex(
					"0974e00703b771aaed85d3ff0c2050018a0b648078b3793fabb19dd9ce97b07efb",
				)
				.unwrap(),
			)
			.unwrap();
			let kernel_not_exist = Commitment::from_vec(
				mwc_util::from_hex(
					"0974e00703b771aaed85d3ff0c2050018a0b648078b3793fabb19dd9ce97b07efa",
				)
				.unwrap(),
			)
			.unwrap();

			let outputs_exist: Vec<Commitment> = vec![
				Commitment::from_vec(
					mwc_util::from_hex(
						"08a30bc4893f169098cab8291d699741853553f897f202fcdea2ca3d9c187551ab",
					)
					.unwrap(),
				)
				.unwrap(),
				Commitment::from_vec(
					mwc_util::from_hex(
						"09118e17c6a39d50336344cb490c94f96503d1fa45a7014ac037c89778839639c4",
					)
					.unwrap(),
				)
				.unwrap(),
			];

			let outputs_not_exist: Vec<Commitment> = vec![
				Commitment::from_vec(
					mwc_util::from_hex(
						"08a30bc4893f169098cab8291d699741853553f897f202fcdea2ca3d9c187551ac",
					)
					.unwrap(),
				)
				.unwrap(),
				Commitment::from_vec(
					mwc_util::from_hex(
						"09118e17c6a39d50336344cb490c94f96503d1fa45a7014ac037c89778839639c5",
					)
					.unwrap(),
				)
				.unwrap(),
			];

			let node_list_clone = node_list.clone();
			joins.push(thread::spawn(move || {
				let client = HTTPNodeClient::new(
					0,
					node_list_clone,
					Some(Zeroizing::new(api_secret.into())),
				)
				.map_err(|e| mwc_wallet_libwallet::Error::ClientCallback(format!("{}", e)))?;

				let total_time = Instant::now();

				for _ in 0..iterations_per_thread {
					let now = Instant::now();
					let (h, _, _) = client.get_chain_tip()?;
					if print_call_latency {
						println!(
							"get_tip height {}, latency {} ms",
							h,
							now.elapsed().as_millis()
						);
					}

					let now = Instant::now();
					let _ = client.get_header_info(h - 2)?;
					if print_call_latency {
						println!("get_header_info latency {} ms", now.elapsed().as_millis());
					}

					let now = Instant::now();
					let _ = client.get_connected_peer_info()?;
					if print_call_latency {
						println!(
							"get_connected_peer_info latency {} ms",
							now.elapsed().as_millis()
						);
					}

					let now = Instant::now();
					let _ = client.get_kernel(&kernel_exist, None, None)?;
					if print_call_latency {
						println!("get_kernel exist latency {} ms", now.elapsed().as_millis());
					}
					let now = Instant::now();
					let _ = client.get_kernel(&kernel_not_exist, None, None)?;
					if print_call_latency {
						println!(
							"get_kernel not exist latency {} ms",
							now.elapsed().as_millis()
						);
					}

					let now = Instant::now();
					let _ = client.get_outputs_from_node(&outputs_exist)?;
					if print_call_latency {
						println!(
							"get_output_details_from_node exist latency {} ms",
							now.elapsed().as_millis()
						);
					}
					let now = Instant::now();
					let _ = client.get_outputs_from_node(&outputs_not_exist)?;
					if print_call_latency {
						println!(
							"get_output_details_from_node not exist latency {} ms",
							now.elapsed().as_millis()
						);
					}

					let now = Instant::now();
					let _ = client.get_outputs_by_pmmr_index(1342000, None, 100)?;
					if print_call_latency {
						println!(
							"get_outputs_by_pmmr_index latency {} ms",
							now.elapsed().as_millis()
						);
					}

					let now = Instant::now();
					let _ = client.height_range_to_pmmr_indices(h - 10, None)?;
					if print_call_latency {
						println!(
							"height_range_to_pmmr_indices latency {} ms",
							now.elapsed().as_millis()
						);
					}

					/*let now = Instant::now();
					let blocks = client.get_blocks_by_height(h-3000, h, 5)?;
					if print_call_latency {
						println!("get_blocks_by_height {}, latency {} ms", blocks.len(), now.elapsed().as_millis() );
					}*/
				}

				if print_stat {
					println!(
						"Thread {} is done, latency per iteratoin {} ms",
						thr_idx,
						total_time.elapsed().as_millis() / iterations_per_thread
					);
				}

				Ok(())
			}));
		}

		for j in joins {
			if let Err(e) = j.join().unwrap() {
				println!("Thread failed with error: {}", e);
			}
		}

		Ok(())
	}
}
