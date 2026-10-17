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

use crate::SlateSender;
#[cfg(feature = "swaps")]
use crate::SwapMessageSender;
use crate::adapters::MarketplaceMessageSender;
use crate::client_utils::{safe_http_error, safe_http_text, url_with_appended_path};
/// HTTP Wallet 'plugin' implementation
use crate::error::Error;
use mwc_wallet_libwallet::Slate;
use mwc_wallet_libwallet::address;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::slate_versions::{SlateVersion, VersionedSlate};
use mwc_wallet_libwallet::slatepack::{SlatePurpose, Slatepacker};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::Message;
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::log::{debug, error, info, trace, warn};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde::Serialize;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::serde_json::{Value, json};
use mwc_wallet_util::mwc_crates::tokio;
use mwc_wallet_util::mwc_crates::tokio::net::TcpStream;
use mwc_wallet_util::mwc_crates::url::Url;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_p2p::tor::arti;
use mwc_wallet_util::mwc_p2p::tor::arti::arti_async_block;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_util::run_global_async_block;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

type ReconnectHandler = Arc<dyn Fn() -> Result<TcpDataStream, Error> + Send + Sync>;

fn is_http_not_found(error: &Error) -> bool {
	matches!(error, Error::HttpStatus(404))
}

/// Parse the easy-jsonrpc `Result<T, E>` envelope used by the foreign wallet API.
/// A transport-level HTTP success is not a delivery acknowledgement unless the
/// response has the expected JSON-RPC version/id and an explicit `result.Ok`.
fn parse_foreign_rpc_ok(
	response_body: &str,
	expected_id: u64,
	operation: &str,
) -> Result<Value, Error> {
	let response: Value = serde_json::from_str(response_body).map_err(|e| {
		Error::ClientCallback(format!(
			"{} returned invalid JSON: {}; response: {}",
			operation,
			safe_http_error(&e),
			safe_http_text(response_body)
		))
	})?;
	let object = response.as_object().ok_or_else(|| {
		Error::ClientCallback(format!(
			"{} returned a non-object JSON-RPC response: {}",
			operation,
			safe_http_text(&response.to_string())
		))
	})?;

	if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
		return Err(Error::ClientCallback(format!(
			"{} returned an invalid JSON-RPC version",
			operation
		)));
	}
	if object.get("id").and_then(Value::as_u64) != Some(expected_id) {
		return Err(Error::ClientCallback(format!(
			"{} returned a mismatched JSON-RPC response id",
			operation
		)));
	}

	if let Some(rpc_error) = object.get("error").filter(|value| !value.is_null()) {
		return Err(Error::ClientCallback(format!(
			"{} failed with JSON-RPC error: {}",
			operation,
			safe_http_text(&rpc_error.to_string())
		)));
	}

	let result = object
		.get("result")
		.and_then(Value::as_object)
		.ok_or_else(|| {
			Error::ClientCallback(format!(
				"{} returned a malformed result envelope",
				operation
			))
		})?;
	if let Some(remote_error) = result.get("Err").filter(|value| !value.is_null()) {
		return Err(Error::ClientCallback(format!(
			"{} was rejected by the remote wallet: {}",
			operation,
			safe_http_text(&remote_error.to_string())
		)));
	}
	result.get("Ok").cloned().ok_or_else(|| {
		Error::ClientCallback(format!(
			"{} returned a result without an explicit Ok value",
			operation
		))
	})
}

fn validate_receiver_proof_address(context_id: u32, proof_address: &str) -> Result<String, Error> {
	if proof_address.len() != 56 {
		return Err(Error::ClientCallback(format!(
			"Receiver wallet returned a proof address with invalid length {}, expected a 56-byte OnionV3 address",
			proof_address.len()
		)));
	}

	// Reuse the canonical payment-proof parser rather than accepting an address
	// based on length alone. The secp context is unused for OnionV3 addresses but
	// is required by the shared parser because it also supports legacy MQS keys.
	let secp = Secp256k1::with_caps(ContextFlag::None)?;
	let address = ProvableAddress::from_str(&secp, context_id, proof_address).map_err(|e| {
		Error::ClientCallback(format!(
			"Receiver wallet returned an invalid proof address: {}",
			safe_http_error(&e)
		))
	})?;
	Ok(address.public_key)
}

/// Parse the string payload returned by the marketplace foreign API. Command-specific
/// acknowledgement semantics are validated by the controller, but an empty payload is
/// never a valid marketplace response.
fn parse_marketplace_rpc_ok(response_body: &str) -> Result<String, Error> {
	let result_value = parse_foreign_rpc_ok(response_body, 1, "Sending marketplace message")?;
	let result = result_value.as_str().ok_or_else(|| {
		Error::ClientCallback(
			"Marketplace endpoint returned a malformed success response".to_string(),
		)
	})?;
	if result.trim().is_empty() {
		return Err(Error::ClientCallback(
			"Marketplace endpoint returned an empty acknowledgement".to_string(),
		));
	}
	Ok(result.to_string())
}

#[derive(Clone)]
struct SlatepackResponsePolicy {
	expected_sender: ed25519_dalek::VerifyingKey,
	expected_recipient: ed25519_dalek::VerifyingKey,
	expected_content: SlatePurpose,
}

fn expected_slatepack_response_content(request: &SlatePurpose) -> Result<SlatePurpose, Error> {
	match request {
		SlatePurpose::SendInitial => Ok(SlatePurpose::SendResponse),
		SlatePurpose::InvoiceResponse => Ok(SlatePurpose::FullSlate),
		other => Err(Error::ClientCallback(format!(
			"Encrypted HTTP Slatepack request has unsupported content purpose {:?}",
			other
		))),
	}
}

fn validate_slatepack_response(
	slatepack: &Slatepacker,
	policy: &SlatepackResponsePolicy,
) -> Result<(), Error> {
	if slatepack.get_sender() != Some(policy.expected_sender) {
		return Err(Error::ClientCallback(
			"Encrypted HTTP Slatepack response sender does not match the request recipient"
				.to_string(),
		));
	}
	if slatepack.get_recipient() != Some(policy.expected_recipient) {
		return Err(Error::ClientCallback(
			"Encrypted HTTP Slatepack response is not addressed to this wallet".to_string(),
		));
	}
	if slatepack.get_content() != policy.expected_content {
		return Err(Error::ClientCallback(format!(
			"Encrypted HTTP Slatepack response has unexpected content purpose {:?}, expected {:?}",
			slatepack.get_content(),
			policy.expected_content
		)));
	}
	Ok(())
}

fn decode_http_slate_response(
	context_id: u32,
	slate_value: &Value,
	slatepack_secret: &ed25519_dalek::SigningKey,
	response_policy: Option<&SlatepackResponsePolicy>,
	secp: &Secp256k1,
) -> Result<Slate, Error> {
	let slate_str = serde_json::to_string(slate_value).map_err(|e| {
		Error::GenericError(format!(
			"Unable to build slate from values, {}",
			safe_http_error(&e)
		))
	})?;

	if Slate::deserialize_is_plain(&slate_str) {
		if response_policy.is_some() {
			return Err(Error::ClientCallback(
				"Encrypted HTTP Slatepack request received a plaintext slate response".to_string(),
			));
		}
		return Slate::deserialize_upgrade_plain(context_id, &slate_str).map_err(|e| {
			Error::GenericError(format!(
				"Unable to build slate from response: {}",
				safe_http_error(&e)
			))
		});
	}

	let slatepack_str: String = serde_json::from_str(&slate_str).map_err(|e| {
		Error::GenericError(format!(
			"Invalid other wallet response, unable to decode the Slatepack, {}",
			safe_http_error(&e)
		))
	})?;
	let slatepack =
		Slate::deserialize_upgrade_slatepack(context_id, &slatepack_str, slatepack_secret, secp)
			.map_err(|e| {
				Error::LibWallet(format!("Unable to process slate, {}", safe_http_error(&e)))
			})?;
	if let Some(policy) = response_policy {
		validate_slatepack_response(&slatepack, policy)?;
	}
	Ok(slatepack.to_result_slate())
}

#[derive(Clone)]
pub struct HttpDataSender {
	context_id: u32,
	// Sender clones serialize access to the same cached connection and reconnect it as needed.
	connection_cache: Arc<RwLock<Option<TcpDataStream>>>,
	// We need to be able to reconnect
	reconnect_function: ReconnectHandler,
	// Shared ownership avoids plaintext clones of the secret; zeroized when the last
	// reference is dropped.
	apisecret: Option<Arc<Zeroizing<String>>>,
	base_url: String,
}

impl HttpDataSender {
	/// Create, return Err if scheme is not "http"
	pub fn plain_http(
		context_id: u32,
		base_url: &str,
		apisecret: Option<Arc<Zeroizing<String>>>,
	) -> Result<HttpDataSender, Error> {
		let url = url_with_appended_path(base_url, &["v2", "foreign"]).map_err(|e| {
			Error::ArgumentError(format!(
				"Invalid base url {}, {}",
				safe_http_text(base_url),
				e
			))
		})?;

		// Only plain http is supported: this sender connects with a raw
		// TcpStream and speaks cleartext HTTP/1.1, so an https URL would get no
		// TLS handshake and no certificate validation. Reject it instead of
		// silently downgrading; use Tor for an encrypted transport.
		if url.scheme() != "http" {
			return Err(Error::ArgumentError(format!(
				"Invalid http url: {}. Only http:// URLs are supported by the plain HTTP sender; use Tor for encrypted transport",
				safe_http_text(base_url)
			)));
		}

		let host = url
			.host_str()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the host",
				safe_http_text(base_url)
			)))?
			.to_string();
		let port = url
			.port_or_known_default()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the port",
				safe_http_text(base_url)
			)))?;

		let base_url2 = safe_http_text(base_url);
		let reconnect_fn = move || {
			let host = host.clone();
			let port = port;
			let base_url2 = base_url2.to_string();
			let stream = run_global_async_block(async {
				let stream =
					tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
						.await
						.map_err(|_| {
							Error::ConnectionError(format!(
								"Unable connect to {} by direct connection",
								base_url2
							))
						})?
						.map_err(|e| {
							Error::ConnectionError(format!(
								"Unable connect to {} by direct connection, {}",
								base_url2, e
							))
						})?;
				Ok::<TcpDataStream, Error>(TcpDataStream::from_tcp(stream))
			})
			.map_err(|e| Error::ConnectionError(format!("Async runtime error, {}", e)))??;
			Ok(stream)
		};

		let stream = reconnect_fn()?;

		Ok(HttpDataSender {
			context_id,
			connection_cache: Arc::new(RwLock::new(Some(stream))),
			reconnect_function: Arc::new(reconnect_fn),
			apisecret,
			base_url: base_url.to_string(),
		})
	}

	/// Connect to a caller-validated Onion v3 service through Arti.
	///
	/// `base_url` must first be normalized and validated with
	/// `validate_tor_address`; every in-tree caller does so. A clearnet hostname
	/// is outside this constructor's contract because this adapter does not add a
	/// TLS layer.
	///
	/// The wallet intentionally sends HTTP/1.1 as the application protocol inside
	/// the Arti `DataStream`. Onion-service circuits encrypt the stream end to end,
	/// authenticate the service through its v3 onion address, and have no exit
	/// node, so the HTTP request is not exposed in transit. The URL scheme is used
	/// for URL and default-port handling here; it does not negotiate TLS.
	pub fn tor_connection(
		context_id: u32,
		base_url: &str,
		apisecret: Option<Arc<Zeroizing<String>>>,
		tor_config: &TorConfig,
		base_dir: &Path,
	) -> Result<HttpDataSender, Error> {
		if !tor_config.tor_enabled.unwrap_or(true) {
			return Err(Error::TorConfig("Tor disabled by the wallet config".into()));
		}

		let url = url_with_appended_path(base_url, &["v2", "foreign"]).map_err(|e| {
			Error::ArgumentError(format!(
				"Invalid base url {}, {}",
				safe_http_text(base_url),
				e
			))
		})?;

		let onion_address = url
			.host_str()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the host",
				safe_http_text(base_url)
			)))?
			.to_string();
		let port = url
			.port_or_known_default()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the port",
				safe_http_text(base_url)
			)))?;

		if !arti::is_arti_started() {
			// Arti is process-global: the first Tor sender starts it, and individual
			// senders only own their streams. Arti remains running for the process lifetime.
			arti::start_arti(&tor_config, base_dir, false, false)
				.map_err(|e| Error::Arti(format!("Unable to start Tor (Arti), {}", e)))?;
		}

		let base_url2 = safe_http_text(base_url);
		let reconnect_fn = move || {
			// Use Arti for connection.
			if !arti::is_arti_healthy() {
				return Err(Error::Arti(" Tor (Arti) is not able connect to the network, please check your network connection".into()));
			}
			let onion_address = onion_address.clone();
			let onion_for_connect = onion_address.clone();
			let stream = arti::access_arti(|arti| {
				arti_async_block(
					async move { arti.connect((onion_for_connect.as_str(), port)).await },
				)
			})
				.map_err(|e| {
					Error::ConnectionError(format!("Unable connect to {}:{}, {}", base_url2, port, e))
				})?
				.map_err(|e| {
					Error::ConnectionError(format!("Unable connect to {}:{}, {}", base_url2, port, e))
				})?;
			// The wallet transaction flow is serialized and intentionally permits only one
			// live outbound Tor connection to a destination. Use the onion address as the
			// Arti active-object name so an accidental parallel send to the same wallet is
			// rejected. The sender is transaction-scoped; while its cached stream is alive,
			// Arti restart deliberately waits for the transaction to finish and drop it.
			let stream = TcpDataStream::from_data(stream, onion_address).map_err(|e| {
				Error::ConnectionError(format!("Unable connect to {}:{}, {}", base_url2, port, e))
			})?;
			Ok(stream)
		};

		let stream = reconnect_fn()?;

		Ok(HttpDataSender {
			context_id,
			connection_cache: Arc::new(RwLock::new(Some(stream))),
			reconnect_function: Arc::new(reconnect_fn),
			apisecret,
			base_url: base_url.to_string(),
		})
	}

	/// Check version of the listening wallet
	pub fn check_other_version(
		&self,
		timeout: Option<u128>,
		destination_address: &String,
		show_error: bool,
	) -> Result<(SlateVersion, Option<String>), Error> {
		trace!("starting now check version");

		let req = json!({
				"jsonrpc": "2.0",
				"method": "check_version",
				"id": 1,
				"params": []
		});

		let requested_timeout = timeout.unwrap_or(30_000);
		let timeout_ms = u64::try_from(requested_timeout).map_err(|e| {
			Error::DataOverflow(format!(
				"HttpSlateSender::check_other_version, HTTP timeout exceeds u64 milliseconds, timeout_ms={} error={}",
				requested_timeout, e
			))
		})?;
		let (res_str, close) = match self.post(true, &Duration::from_millis(timeout_ms), req) {
			Ok((r, c)) => (r, c),
			Err(e) => {
				let mut report = format!(
					"Performing version check (is recipient listening?): {}",
					safe_http_error(&e)
				);
				if is_http_not_found(&e) {
					// Report that the other version of the wallet is out of date
					report = "Other wallet is incompatible and requires an upgrade. \
				          	Please urge the other wallet owner to upgrade and try the transaction again."
						.to_string();
				}
				if show_error {
					error!("{}", report);
				} else {
					debug!("{}", report);
				}
				return Err(Error::ClientCallback(report));
			}
		};
		if close {
			warn!("Unexpected connection close request at check_version response");
		}

		let resp_value = parse_foreign_rpc_ok(&res_str, 1, "Checking version")?;
		trace!(
			"Response value: {}",
			safe_http_text(&resp_value.to_string())
		);
		let foreign_api_version: u16 =
			serde_json::from_value(resp_value["foreign_api_version"].clone()).map_err(|e| {
				Error::GenericError(format!(
					"Unable to read response foreign_api_version value: {}; response: {}",
					safe_http_error(&e),
					safe_http_text(&res_str)
				))
			})?;
		let supported_slate_versions: Vec<String> = serde_json::from_value(
			resp_value["supported_slate_versions"].clone(),
		)
		.map_err(|e| {
			Error::GenericError(format!(
				"Unable to read response supported_slate_versions value: {}; response: {}",
				safe_http_error(&e),
				safe_http_text(&res_str)
			))
		})?;

		// trivial tests for now, but will be expanded later
		if foreign_api_version < 2 {
			let report = "Other wallet reports unrecognized API format.".to_string();
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let slatepack_address: Option<String> =
			if supported_slate_versions.contains(&"SP".to_owned()) {
				match address::pubkey_from_onion_v3(destination_address) {
					Ok(pk) => Some(address::onion_v3_from_pubkey(&pk)),
					Err(_) => {
						// Destination is not tor address, so making foreign API request for get an address
						Some(self.check_receiver_proof_address(timeout.clone())?)
					}
				}
			} else {
				None
			};

		if supported_slate_versions.contains(&"SP".to_owned()) {
			return Ok((SlateVersion::SP, slatepack_address));
		} else if supported_slate_versions.contains(&"V3B".to_owned()) {
			return Ok((SlateVersion::V3B, slatepack_address));
		} else if supported_slate_versions.contains(&"V3".to_owned()) {
			return Ok((SlateVersion::V3, slatepack_address));
		} else if supported_slate_versions.contains(&"V2".to_owned()) {
			return Ok((SlateVersion::V2, slatepack_address));
		}

		let report = "Unable to negotiate slate format with other wallet.".to_string();
		error!("{}", report);
		Err(Error::ClientCallback(report))
	}

	/// Check proof address of the listening wallet
	pub fn check_receiver_proof_address(&self, timeout: Option<u128>) -> Result<String, Error> {
		trace!("starting now check proof address of listening wallet");

		let req = json!({
				"jsonrpc": "2.0",
				"method": "get_proof_address",
				"id": 1,
				"params": []
		});

		let requested_timeout = timeout.unwrap_or(30_000);
		let timeout = u64::try_from(requested_timeout).map_err(|e| {
			Error::DataOverflow(format!(
				"HttpSlateSender::check_receiver_proof_address, HTTP timeout exceeds u64 milliseconds, timeout_ms={} error={}",
				requested_timeout, e
			))
		})?;
		let (res_str, close) = match self.post(true, &Duration::from_millis(timeout), req) {
			Ok((r, c)) => (r, c),
			Err(e) => {
				let mut report = format!(
					"Performing receiver proof address check (is recipient listening?): {}",
					safe_http_error(&e)
				);
				if is_http_not_found(&e) {
					// Report that the other version of the wallet is out of date
					report = "Other wallet is incompatible and requires an upgrade. \
				          	Please urge the other wallet owner to upgrade and try the transaction again."
						.to_string();
				}
				error!("{}", report);
				return Err(Error::ClientCallback(report));
			}
		};
		if close {
			warn!("Unexpected connection close request at receiver proof address response");
		}

		let resp_value =
			parse_foreign_rpc_ok(&res_str, 1, "Checking receiver wallet proof address")?;
		trace!(
			"Response value: {}",
			safe_http_text(&resp_value.to_string())
		);
		let receiver_proof_address = resp_value.as_str().ok_or_else(|| {
			Error::ClientCallback(
				"Receiver wallet returned a non-string proof address".to_string(),
			)
		})?;
		validate_receiver_proof_address(self.context_id, receiver_proof_address)
	}

	fn post<IN>(
		&self,
		keep_alive: bool,
		timeout: &Duration,
		input: IN,
	) -> Result<(String, bool), Error>
	where
		IN: Serialize,
	{
		let url = Self::build_foreign_api_url(&self.base_url)?;

		let mut stream = self.connection_cache.write();

		let strm = stream.take();

		let strm = match strm {
			Some(mut strm) => {
				if !strm.is_alive() {
					None
				} else {
					Some(strm)
				}
			}
			None => None,
		};

		let mut strm = match strm {
			Some(s) => s,
			None => (*self.reconnect_function)()?,
		};

		let (result, close) = crate::http_parser::post::post_auth_with_timeout(
			self.context_id,
			url,
			self.apisecret.as_deref(),
			&mut strm,
			keep_alive,
			*timeout,
			input,
		)?;

		if close {
			// `strm` was removed from the cache above, so shut down that local
			// stream rather than trying to take the now-empty cache again.
			if let Err(e) = strm.shutdown() {
				info!("Connection shutdown error: {}", e);
			}
		} else {
			// keeping connection open
			let _stored_stream = stream.insert(strm);
		}
		Ok((result, close))
	}

	fn build_foreign_api_url(base_url: &str) -> Result<Url, Error> {
		url_with_appended_path(base_url, &["v2", "foreign"]).map_err(|e| {
			Error::ConnectionError(format!(
				"Invalid base url {}, {}",
				safe_http_text(base_url),
				e
			))
		})
	}
}

impl SlateSender for HttpDataSender {
	fn check_other_wallet_version(
		&self,
		destination_address: &String,
		show_error: bool,
	) -> Result<Option<(SlateVersion, Option<String>)>, Error> {
		// we need to keep _tor in scope so that the process is not killed by drop.
		Ok(Some(self.check_other_version(
			None,
			destination_address,
			show_error,
		)?))
	}

	fn send_tx(
		&self,
		send_tx: bool, // false if invoice, true if send operation
		slate: &Slate,
		slate_content: SlatePurpose,
		slatepack_secret: &ed25519_dalek::SigningKey,
		recipient: Option<ed25519_dalek::VerifyingKey>,
		other_wallet_version: Option<(SlateVersion, Option<String>)>,
		secp: &Secp256k1,
	) -> Result<Slate, Error> {
		let (mut slate_version, slatepack_address) =
			other_wallet_version.ok_or(Error::GenericError(
				"Internal error, http based send_tx get empty value for other_wallet_version"
					.to_string(),
			))?;
		let request_content = slate_content.clone();
		let mut encrypted_request_recipient = None;

		if recipient.is_some() {
			if slate_version != SlateVersion::SP || !slate.compact_slate {
				return Err(Error::ClientCallback(format!(
					"An explicit Slatepack recipient requires a compact Slatepack exchange; \
					 refusing plaintext fallback (peer version {:?}, compact slate {})",
					slate_version, slate.compact_slate
				)));
			}
		} else if slate_version == SlateVersion::SP && !slate.compact_slate {
			// Preserve the legacy compatibility fallback only when the caller did
			// not explicitly require encryption to a particular recipient.
			slate_version = SlateVersion::V3B;
		}

		let slate_send = match slate_version {
			SlateVersion::SP => {
				// Preferring recipient from params because http request can be interrupted. So encryption will help in this case
				let mut recipient = recipient;
				if recipient.is_none() {
					if let Some(slatepack_address) = slatepack_address {
						recipient = Some(
							ProvableAddress::from_str(secp, self.context_id, &slatepack_address)
								.map_err(|e| {
									Error::LibWallet(format!(
										"Unable to parse slatepack address {}, {}",
										safe_http_text(&slatepack_address),
										safe_http_error(&e)
									))
								})?
								.tor_public_key()
								.map_err(|e| {
									Error::LibWallet(format!(
										"Unable to convert slatepack address {} into public key, {}",
										safe_http_text(&slatepack_address),
										safe_http_error(&e)
									))
								})?,
						);
					}
				}

				let recipient = recipient.ok_or_else(|| {
					Error::GenericError(
						"Not provided expected recipient address for Slate Pack".to_string(),
					)
				})?;
				encrypted_request_recipient = Some(recipient);
				let tor_pk = ed25519_dalek::VerifyingKey::from(slatepack_secret);

				VersionedSlate::into_version(
					self.context_id,
					slate.clone(),
					SlateVersion::SP,
					slate_content,
					tor_pk,
					Some(recipient),
					slatepack_secret,
					#[cfg(feature = "test-support")]
					false,
					secp,
				)
				.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?
			}
			SlateVersion::V3B => {
				if slate.compact_slate {
					return Err(Error::ClientCallback(
						"Other wallet doesn't support slatepack compact model".into(),
					));
				}
				VersionedSlate::into_version_plain(self.context_id, slate, SlateVersion::V3B)
					.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?
			}
			SlateVersion::V2 | SlateVersion::V3 => {
				let mut slate = slate.clone();
				if slate.compact_slate {
					return Err(Error::ClientCallback(
						"Other wallet doesn't support slatepack compact model".into(),
					));
				}
				if slate.payment_proof.is_some() {
					return Err(Error::ClientCallback("Payment proof requested, but other wallet does not support payment proofs or tor payment proof. Please urge other user to upgrade, or re-send tx without a payment proof".into()));
				}
				if slate.ttl_cutoff_height.is_some() {
					warn!("Slate TTL value will be ignored and removed by other wallet, as other wallet does not support this feature. Please urge other user to upgrade");
				}
				slate.version_info.version = 2;
				VersionedSlate::into_version_plain(self.context_id, &slate, SlateVersion::V2)
					.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?
			}
		};
		let response_policy = encrypted_request_recipient
			.map(|expected_sender| {
				Ok::<_, Error>(SlatepackResponsePolicy {
					expected_sender,
					expected_recipient: slatepack_secret.verifying_key(),
					expected_content: expected_slatepack_response_content(&request_content)?,
				})
			})
			.transpose()?;

		// //get the proof address of the other wallet
		// let receiver_proof_address = self.check_receiver_proof_address(&url_str, None)?;

		// Note: not using easy-jsonrpc as don't want the dependencies in this crate

		let req = if send_tx {
			json!({
			"jsonrpc": "2.0",
			"method": "receive_tx",
			"id": 1,
			"params": [
						slate_send,
						null,
						null
					]
			})
		} else {
			json!({
			"jsonrpc": "2.0",
			"method": "finalize_invoice_tx",
			"id": 1,
			"params": [
						slate_send
					]
			})
		};
		trace!(
			"Sending request: {}",
			safe_http_text(&req.to_string())
		);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting transaction slate (is recipient listening?): {}",
					safe_http_error(&e)
				))
			})?;
		if close {
			info!("Get connection close request at receive_tx response");
		}

		let mut slate_value = parse_foreign_rpc_ok(&res_str, 1, "Posting transaction slate")?;
		trace!(
			"slate_value: {}",
			safe_http_text(&slate_value.to_string())
		);
		if slate_value.is_null() {
			let report = format!(
				"Unable to parse receiver wallet response {}",
				safe_http_text(&res_str)
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		if slate_value["version_info"]["version"] == json!(3)
			&& slate_value["ttl_cutoff_height"] == json!(null)
		{
			slate_value["ttl_cutoff_height"] = json!(u64::MAX);
		}

		let res_slate = decode_http_slate_response(
			self.context_id,
			&slate_value,
			slatepack_secret,
			response_policy.as_ref(),
			secp,
		)?;

		Ok(res_slate)
	}
}

#[cfg(feature = "swaps")]
impl SwapMessageSender for HttpDataSender {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and processed)
	fn send_swap_message(&self, swap_message: &Message, _secp: &Secp256k1) -> Result<bool, Error> {
		// we need to keep _tor in scope so that the process is not killed by drop.
		let message_ser = &serde_json::to_string(&swap_message).map_err(|e| {
			Error::SwapMessageGenericError(format!(
				"Failed to convert swap message to json in preparation for Tor request, {}",
				e
			))
		})?;

		let req = json!({
			"jsonrpc": "2.0",
			"method": "receive_swap_message",
			"id": 1,
			"params": [
						message_ser,
					]
		});
		// Swap fields can originate at the peer, so bound and escape the trace payload.
		trace!(
			"Sending receive_swap_message request: {}",
			safe_http_text(&req.to_string())
		);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting swap message (is recipient listening?): {}",
					safe_http_error(&e)
				))
			})?;
		if close {
			info!("Unexpected connection close request at swap message response");
		}

		let acknowledgement = parse_foreign_rpc_ok(&res_str, 1, "Sending swap message")?;
		if !acknowledgement.is_null() {
			return Err(Error::ClientCallback(
				"Swap endpoint returned a malformed acknowledgement".to_string(),
			));
		}

		// The synchronous endpoint returned an explicit Result::Ok acknowledgement.
		Ok(true)
	}
}

impl MarketplaceMessageSender for HttpDataSender {
	fn send_swap_marketplace_message(&self, json_str: &String) -> Result<String, Error> {
		let req = json!({
			"jsonrpc": "2.0",
			"method": "marketplace_message",
			"id": 1,
			"params": [
						json_str,
					]
		});
		trace!(
			"Sending marketplace_message request: {}",
			safe_http_text(&req.to_string())
		);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting marketplace message (is recipient listening?): {}",
					safe_http_error(&e)
				))
			})?;
		if close {
			info!("Unexpected connection close request at marketplace message response");
		}

		parse_marketplace_rpc_ok(&res_str)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_core::global;

	#[test]
	fn only_structured_404_is_treated_as_not_found() {
		assert!(is_http_not_found(&Error::HttpStatus(404)));
		assert!(!is_http_not_found(&Error::HttpStatus(500)));
		assert!(!is_http_not_found(&Error::ConnectionError(
			"Unable to connect to http://127.0.0.1:4040".to_string()
		)));
	}

	#[test]
	fn foreign_api_url_uses_path_segments_and_rejects_other_components() {
		assert_eq!(
			HttpDataSender::build_foreign_api_url("http://wallet.example/proxy/")
				.unwrap()
				.as_str(),
			"http://wallet.example/proxy/v2/foreign"
		);
		assert!(
			HttpDataSender::build_foreign_api_url("http://wallet.example/proxy?tenant=1").is_err()
		);
		assert!(
			HttpDataSender::build_foreign_api_url("http://wallet.example/proxy#foreign").is_err()
		);

		let error = match HttpDataSender::plain_http(0, "http://127.0.0.1:1/proxy?tenant=1", None) {
			Ok(_) => panic!("query-bearing base URL was accepted"),
			Err(error) => error,
		};
		assert!(error.to_string().contains("must not contain a query"));
	}

	#[test]
	fn receiver_proof_address_requires_canonical_onion_v3() {
		let valid = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		assert_eq!(validate_receiver_proof_address(0, valid).unwrap(), valid);

		let malformed = "💣".repeat(14);
		assert_eq!(malformed.len(), 56);
		assert!(validate_receiver_proof_address(0, &malformed).is_err());
		let invalid_checksum = format!("{}a", &valid[..55]);
		assert!(validate_receiver_proof_address(0, &invalid_checksum).is_err());
		assert!(validate_receiver_proof_address(0, &valid.to_uppercase()).is_err());
		assert!(validate_receiver_proof_address(0, &valid[..55]).is_err());
	}

	#[test]
	fn foreign_rpc_response_requires_matching_success_envelope() {
		let ok = r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":null}}"#;
		assert!(parse_foreign_rpc_ok(ok, 1, "test").unwrap().is_null());

		for rejected in [
			r#"{"jsonrpc":"2.0","id":2,"result":{"Ok":null}}"#,
			r#"{"jsonrpc":"1.0","id":1,"result":{"Ok":null}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":{"Err":"rejected"}}"#,
			r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"failed"}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
			"not json",
		] {
			assert!(parse_foreign_rpc_ok(rejected, 1, "test").is_err());
		}
	}

	#[test]
	fn marketplace_rpc_response_requires_nonempty_string_payload() {
		let ok = r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":"{\"cancelled\":true}"}}"#;
		assert_eq!(
			parse_marketplace_rpc_ok(ok).unwrap(),
			r#"{"cancelled":true}"#
		);

		for rejected in [
			r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":""}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":"   "}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":null}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":{}}}"#,
		] {
			assert!(parse_marketplace_rpc_ok(rejected).is_err());
		}
	}

	#[test]
	fn foreign_rpc_errors_escape_and_bound_remote_text() {
		let body = format!(
			r#"{{"jsonrpc":"2.0","id":1,"result":{{"Err":"before\n\u001b]52;c;payload\u0007\u202e{}"}}}}"#,
			"x".repeat(crate::client_utils::MAX_HTTP_DIAGNOSTIC_BYTES * 2)
		);
		let error = parse_foreign_rpc_ok(&body, 1, "test").unwrap_err();
		let display = error.to_string();
		assert!(display.contains(r"\n\u001b]52;c;payload\u0007\u202e"));
		assert!(display.ends_with("...[truncated]"));
		assert!(!display.chars().any(char::is_control));
		assert!(!display.contains('\u{202e}'));
		assert!(display.len() < crate::client_utils::MAX_HTTP_DIAGNOSTIC_BYTES + 512);
	}

	fn assert_explicit_recipient_policy_error(version: SlateVersion, compact_slate: bool) {
		let sender = HttpDataSender {
			context_id: 0,
			connection_cache: Arc::new(RwLock::new(None)),
			reconnect_function: Arc::new(|| {
				Err(Error::ConnectionError(
					"unexpected HTTP reconnect".to_string(),
				))
			}),
			apisecret: None,
			base_url: "http://127.0.0.1".to_string(),
		};
		let slate = Slate::blank(2, compact_slate).unwrap();
		let slatepack_secret = ed25519_dalek::SigningKey::from_bytes(&[1_u8; 32]);
		let recipient_secret = ed25519_dalek::SigningKey::from_bytes(&[2_u8; 32]);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let error = sender
			.send_tx(
				true,
				&slate,
				SlatePurpose::SendInitial,
				&slatepack_secret,
				Some(recipient_secret.verifying_key()),
				Some((version, None)),
				&secp,
			)
			.unwrap_err();
		match error {
			Error::ClientCallback(message) => {
				assert!(message.contains("refusing plaintext fallback"));
			}
			other => panic!("unexpected error: {other}"),
		}
	}

	#[test]
	fn explicit_slatepack_recipient_rejects_plaintext_versions() {
		for version in [SlateVersion::V2, SlateVersion::V3, SlateVersion::V3B] {
			assert_explicit_recipient_policy_error(version, true);
		}
	}

	#[test]
	fn explicit_slatepack_recipient_requires_compact_slate() {
		assert_explicit_recipient_policy_error(SlateVersion::SP, false);
	}

	fn response_policy(
		sender: ed25519_dalek::VerifyingKey,
		recipient: ed25519_dalek::VerifyingKey,
		content: SlatePurpose,
	) -> SlatepackResponsePolicy {
		SlatepackResponsePolicy {
			expected_sender: sender,
			expected_recipient: recipient,
			expected_content: content,
		}
	}

	#[test]
	fn encrypted_response_policy_checks_encryption_direction_and_purpose() {
		let local = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]).verifying_key();
		let remote = ed25519_dalek::SigningKey::from_bytes(&[12_u8; 32]).verifying_key();
		let other = ed25519_dalek::SigningKey::from_bytes(&[13_u8; 32]).verifying_key();
		let policy = response_policy(remote, local, SlatePurpose::SendResponse);
		let slate = Slate::blank(2, true).unwrap();

		let valid = Slatepacker {
			sender: Some(remote),
			recipient: Some(local),
			content: SlatePurpose::SendResponse,
			slate: slate.clone(),
		};
		assert!(validate_slatepack_response(&valid, &policy).is_ok());

		let unencrypted = Slatepacker::wrap_slate(slate.clone());
		assert!(validate_slatepack_response(&unencrypted, &policy).is_err());

		let wrong_sender = Slatepacker {
			sender: Some(other),
			..valid.clone()
		};
		assert!(validate_slatepack_response(&wrong_sender, &policy).is_err());

		let wrong_recipient = Slatepacker {
			recipient: Some(other),
			..valid.clone()
		};
		assert!(validate_slatepack_response(&wrong_recipient, &policy).is_err());

		let wrong_purpose = Slatepacker {
			content: SlatePurpose::FullSlate,
			..valid
		};
		assert!(validate_slatepack_response(&wrong_purpose, &policy).is_err());
	}

	#[test]
	fn encrypted_request_rejects_plain_response_while_legacy_accepts_it() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let local_secret = ed25519_dalek::SigningKey::from_bytes(&[21_u8; 32]);
		let remote = ed25519_dalek::SigningKey::from_bytes(&[22_u8; 32]).verifying_key();
		let policy = response_policy(
			remote,
			local_secret.verifying_key(),
			SlatePurpose::SendResponse,
		);
		let slate = Slate::blank(2, false).unwrap();
		let plain = VersionedSlate::into_version_plain(0, &slate, SlateVersion::V3B).unwrap();
		let plain_value = serde_json::to_value(plain).unwrap();

		let error =
			decode_http_slate_response(0, &plain_value, &local_secret, Some(&policy), &secp)
				.unwrap_err();
		assert!(error.to_string().contains("plaintext slate response"));

		assert!(decode_http_slate_response(0, &plain_value, &local_secret, None, &secp).is_ok());
	}
}
