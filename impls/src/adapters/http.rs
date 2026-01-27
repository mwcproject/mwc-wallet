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

use crate::adapters::MarketplaceMessageSender;
/// HTTP Wallet 'plugin' implementation
use crate::error::Error;
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::swap::message::Message;
use crate::libwallet::Slate;
use crate::{SlateSender, SwapMessageSender};
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use mwc_wallet_libwallet::address;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_util::mwc_p2p::tor::arti;
use mwc_wallet_util::mwc_p2p::tor::arti::arti_async_block;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_p2p::{DataStream, TorConfig};
use mwc_wallet_util::mwc_util;
use mwc_wallet_util::mwc_util::run_global_async_block;
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use mwc_wallet_util::mwc_util::tokio_socks::tcp::Socks5Stream;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use url::Url;

type ReconnectHandler = Arc<dyn Fn() -> Result<TcpDataStream, Error> + Send + Sync>;

#[derive(Clone)]
pub struct HttpDataSender {
	context_id: u32,
	// Connection can be broken or closed. In this case 'reconnect_function' is needed to reconnect
	connection_cache: Arc<RwLock<Option<TcpDataStream>>>,
	// We need to be able to reconnect
	reconnect_function: ReconnectHandler,
	apisecret: Option<String>,
	base_url: String,
	need_stop_arti: bool,
}

impl Drop for HttpDataSender {
	fn drop(&mut self) {
		if self.need_stop_arti {
			arti::stop_arti();
		}
	}
}

impl HttpDataSender {
	/// Create, return Err if scheme is not "http"
	pub fn plain_http(
		context_id: u32,
		base_url: &str,
		apisecret: Option<String>,
	) -> Result<HttpDataSender, Error> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			return Err(Error::GenericError(format!(
				"Invalid http url: {}",
				base_url
			)));
		}

		let url = Url::parse(base_url)
			.map_err(|e| Error::ArgumentError(format!("Invalid base url {}, {}", base_url, e)))?;

		let host = url
			.host_str()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the host",
				base_url
			)))?
			.to_string();
		let port = url
			.port_or_known_default()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the port",
				base_url
			)))?;

		let base_url2 = base_url.to_string();
		let reconnect_fn = move || {
			let host = host.clone();
			let port = port;
			let base_url2 = base_url2.to_string();
			let stream = run_global_async_block(async {
				let stream = mwc_util::tokio::time::timeout(
					Duration::from_secs(10),
					TcpStream::connect((host, port)),
				)
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
			need_stop_arti: false,
		})
	}

	/// Switch to using socks proxy
	pub fn tor_connection(
		context_id: u32,
		base_url: &str,
		apisecret: Option<String>,
		tor_config: &TorConfig,
		base_dir: &Path,
	) -> Result<HttpDataSender, Error> {
		if !tor_config.tor_enabled.unwrap_or(true) {
			return Err(Error::TorConfig("Tor disabled by the wallet config".into()));
		}

		let url = Url::parse(base_url)
			.map_err(|e| Error::ArgumentError(format!("Invalid base url {}, {}", base_url, e)))?;

		let onion_address = url
			.host_str()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the host",
				base_url
			)))?
			.to_string();
		let port = url
			.port_or_known_default()
			.ok_or(Error::ArgumentError(format!(
				"Invalid base url {}, not able extract the port",
				base_url
			)))?;

		let mut need_stop_arti = false;
		if tor_config.is_tor_internal_arti() {
			if !arti::is_arti_started() {
				// Starting tor service. Start once and never stop after. We have a single tor core, let's keep it running
				arti::start_arti(&tor_config, base_dir, false)
					.map_err(|e| Error::Arti(format!("Unable to start Tor (Arti), {}", e)))?;
				need_stop_arti = true;
			}
		}

		let tor_config = tor_config.clone();
		let base_url2 = base_url.to_string();
		let reconnect_fn = move || {
			let stream = if tor_config.tor_external.unwrap_or(false) {
				// If external tor, we can use the proxy connection
				let socks_port = tor_config.socks_port.ok_or(Error::TorConfig(
					"socks_port is not defined at Tor config".into(),
				))?;
				let onion_address = onion_address.clone();
				let stream = run_global_async_block(async {
					let proxy_address = format!("127.0.0.1:{}", socks_port);
					let stream = Socks5Stream::connect(proxy_address.as_str(), (onion_address, 80))
						.await
						.map_err(|e| {
							mwc_wallet_util::mwc_p2p::Error::TorConnect(format!(
								"Unable connect to External Tor as 127.0.0.1:{}, {}",
								socks_port, e
							))
						});
					let stream = stream?;
					Ok(TcpDataStream::from_tcp(stream.into_inner()))
				})
				.map_err(|e: mwc_wallet_util::mwc_p2p::Error| {
					Error::ConnectionError(format!(
						"Unable connect to {} through socks proxy, {}",
						base_url2, e
					))
				})?;
				stream
			} else {
				// Use Arti for connection...
				if !arti::is_arti_healthy() {
					return Err(Error::Arti(" Tor (Arti) is not able connect to the network, please check your network connection".into()));
				}
				let onion_address = onion_address.clone();
				let stream = arti::access_arti(|arti| {
					arti_async_block(async {
						// For Tor using port 80 for p2p connections. No configs for that
						let stream =
							arti.connect((onion_address.as_str(), port))
								.await
								.map_err(|e| {
									mwc_wallet_util::mwc_p2p::Error::TorConnect(format!(
										"Unable connect to {}:{}, {}",
										onion_address, 80, e
									))
								})?;
						Ok::<DataStream, mwc_wallet_util::mwc_p2p::Error>(stream)
					})?
				})
				.map_err(|e| {
					Error::ConnectionError(format!(
						"Unable connect to {}:{}, {}",
						onion_address, 80, e
					))
				})?;
				TcpDataStream::from_data(stream, onion_address)
			};
			Ok(stream)
		};

		let stream = reconnect_fn()?;

		Ok(HttpDataSender {
			context_id,
			connection_cache: Arc::new(RwLock::new(Some(stream))),
			reconnect_function: Arc::new(reconnect_fn),
			apisecret,
			base_url: base_url.to_string(),
			need_stop_arti,
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

		let (res_str, close) = match self.post(
			true,
			&Duration::from_millis(timeout.unwrap_or(30_000) as u64),
			req,
		) {
			Ok((r, c)) => (r, c),
			Err(e) => {
				let mut report =
					format!("Performing version check (is recipient listening?): {}", e);
				let err_string = format!("{}", e);
				if err_string.contains("404") {
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

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			Error::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Checking version: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let resp_value = res["result"]["Ok"].clone();
		trace!("resp_value: {}", resp_value.clone());
		let foreign_api_version: u16 =
			serde_json::from_value(resp_value["foreign_api_version"].clone()).map_err(|e| {
				Error::GenericError(format!(
					"Unable to read respond foreign_api_version value {}, {}",
					res_str, e
				))
			})?;
		let supported_slate_versions: Vec<String> = serde_json::from_value(
			resp_value["supported_slate_versions"].clone(),
		)
		.map_err(|e| {
			Error::GenericError(format!(
				"Unable to read respond supported_slate_versions value {}, {}",
				res_str, e
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
					Ok(pk) => Some(address::onion_v3_from_pubkey(&pk).map_err(|e| {
						Error::LibWallet(format!(
							"Unable to build onion address from public key, {}",
							e
						))
					})?),
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

		let (res_str, close) = match self.post(
			true,
			&Duration::from_millis(timeout.unwrap_or(30_000) as u64),
			req,
		) {
			Ok((r, c)) => (r, c),
			Err(e) => {
				let mut report = format!(
					"Performing receiver proof address check (is recipient listening?): {}",
					e
				);
				let err_string = format!("{}", e);
				if err_string.contains("404") {
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

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			Error::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Checking receiver wallet proof address: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let resp_value = res["result"]["Ok"].clone();
		trace!("resp_value: {}", resp_value.clone());
		let mut receiver_proof_address: String = resp_value.to_string();

		if receiver_proof_address.contains("\"") {
			receiver_proof_address = receiver_proof_address.replace("\"", "");
		}
		if receiver_proof_address.len() == 56 {
			return Ok(receiver_proof_address);
		}
		let report = "Unable to check proof address with other wallet.".to_string();
		error!("{}", report);
		Err(Error::ClientCallback(report))
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
		let url = Url::parse(&Self::build_url_str(&self.base_url)).map_err(|e| {
			Error::ConnectionError(format!("Invalid base url {}, {}", self.base_url, e))
		})?;

		let mut stream = self
			.connection_cache
			.write()
			.unwrap_or_else(|e| e.into_inner());

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

		strm.set_write_timeout(timeout.clone());
		strm.set_read_timeout(timeout.clone());
		let (result, close) = crate::http_parser::post::post_auth(
			self.context_id,
			url,
			&self.apisecret,
			&mut strm,
			keep_alive,
			input,
		)?;

		if close {
			if let Some(strm) = stream.take() {
				if let Err(e) = strm.shutdown() {
					info!("Connection shutdown error: {}", e);
				}
			}
		} else {
			// keeping connection open
			let _ = stream.insert(strm);
		}
		Ok((result, close))
	}

	fn build_url_str(base_url: &str) -> String {
		let trailing = match base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		format!("{}{}v2/foreign", base_url, trailing)
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
		slatepack_secret: &DalekSecretKey,
		recipient: Option<DalekPublicKey>,
		other_wallet_version: Option<(SlateVersion, Option<String>)>,
		secp: &Secp256k1,
	) -> Result<Slate, Error> {
		let (mut slate_version, slatepack_address) =
			other_wallet_version.ok_or(Error::GenericError(
				"Internal error, http based send_tx get empty value for other_wallet_version"
					.to_string(),
			))?;

		// Slate can't be slatepack if it is not a compact. Let's handle that here.
		if slate_version == SlateVersion::SP && !slate.compact_slate {
			slate_version = SlateVersion::V3B;
		}

		let slate_send = match slate_version {
			SlateVersion::SP => {
				// Preferring recipient from params because http request can be interrupted. So encryption will help in this case
				let mut recipient = recipient;
				if recipient.is_none() {
					if let Some(slatepack_address) = slatepack_address {
						recipient =
							Some(ProvableAddress::from_str(self.context_id, &slatepack_address)
								.map_err(|e| Error::LibWallet(format!("Unable to parse slatepack address {}, {}", slatepack_address, e)))?
								.tor_public_key()
								.map_err(|e| Error::LibWallet(format!("Unable to convert slatepack address {} into public key, {}", slatepack_address, e)))?);
					}
				}

				if recipient.is_none() {
					return Err(Error::GenericError(
						"Not provided expected recipient address for Slate Pack".to_string(),
					));
				}
				let tor_pk = DalekPublicKey::from(slatepack_secret);

				VersionedSlate::into_version(
					self.context_id,
					slate.clone(),
					SlateVersion::SP,
					slate_content,
					tor_pk,
					recipient,
					slatepack_secret,
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
		trace!("Sending request: {}", req);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting transaction slate (is recipient listening?): {}",
					e
				))
			})?;
		if close {
			info!("Get connection close request at receive_tx response");
		}

		let mut res: Value = serde_json::from_str(&res_str).map_err(|e| {
			Error::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}
		if res["result"]["Err"] != json!(null) {
			let report = format!("Posting transaction slate: Error: {}", res["result"]["Err"]);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let slate_value = res["result"]["Ok"].clone();
		trace!("slate_value: {}", slate_value);
		if slate_value.is_null() {
			let report = format!("Unable to parse receiver wallet response {}", res_str);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		if res["result"]["Ok"]["version_info"]["version"] == json!(3)
			&& res["result"]["Ok"]["ttl_cutoff_height"] == json!(null)
		{
			res["result"]["Ok"]["ttl_cutoff_height"] = json!(u64::MAX);
		}

		let slate_str = serde_json::to_string(&slate_value).map_err(|e| {
			Error::GenericError(format!("Unable to build slate from values, {}", e))
		})?;

		let res_slate = if Slate::deserialize_is_plain(&slate_str) {
			Slate::deserialize_upgrade_plain(self.context_id, &slate_str).map_err(|e| {
				Error::GenericError(format!(
					"Unable to build slate from response {}, {}",
					res_str, e
				))
			})?
		} else {
			let slatepack_str: String = serde_json::from_str(&slate_str).map_err(|e| {
				Error::GenericError(format!(
					"Invalid other wallet response, unable to decode the slate {}, {}",
					slate_str, e
				))
			})?;
			let sp = Slate::deserialize_upgrade_slatepack(
				self.context_id,
				&slatepack_str,
				&slatepack_secret,
				secp,
			)
			.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?;
			sp.to_result_slate()
		};

		Ok(res_slate)
	}
}

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
		trace!("Sending receive_swap_message request: {}", req);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting swap message (is recipient listening?): {}",
					e
				))
			})?;
		if close {
			info!("Unexpected connection close request at swap message response");
		}

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			Error::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;

		if res["error"] != json!(null) {
			let report = format!(
				"Sending swap message: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		// http call is synchronouse, so message was delivered and processes. Ack cn be granted.
		Ok(true)
	}
}

impl MarketplaceMessageSender for HttpDataSender {
	fn send_swap_marketplace_message(&self, json_str: &String) -> Result<String, Error> {
		// we need to keep _tor in scope so that the process is not killed by drop.

		let req = json!({
			"jsonrpc": "2.0",
			"method": "marketplace_message",
			"id": 1,
			"params": [
						json_str,
					]
		});
		trace!("Sending marketplace_message request: {}", req);

		let (res_str, close) = self
			.post(true, &Duration::from_millis(30_000), req)
			.map_err(|e| {
				Error::ClientCallback(format!(
					"Posting marketplace message (is recipient listening?): {}",
					e
				))
			})?;
		if close {
			info!("Unexpected connection close request at marketplace message response");
		}

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			Error::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;

		if res["error"] != json!(null) {
			let report = format!(
				"Sending marketplace_message: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		// http call is synchronouse, so message was delivered and processes. Ack cn be granted.
		let result = res["result"]["Ok"].as_str().unwrap_or("").to_string();
		Ok(result)
	}
}
