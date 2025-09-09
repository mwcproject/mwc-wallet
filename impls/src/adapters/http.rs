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

/// HTTP Wallet 'plugin' implementation
use crate::client_utils::{Client, ClientError};
use crate::error::Error;
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::swap::message::Message;
use crate::libwallet::Slate;
use crate::tor::bridge::TorBridge;
use crate::tor::proxy::TorProxy;
use crate::{SlateSender, SwapMessageSender};
use mwc_wallet_config::types::{TorBridgeConfig, TorProxyConfig};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::path::MAIN_SEPARATOR;
use std::rc::Rc;

use crate::adapters::MarketplaceMessageSender;
use crate::tor;
use crate::tor::config as tor_config;
use crate::tor::process as tor_process;
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use mwc_wallet_libwallet::address;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_util::mwc_util::secp::Secp256k1;

const TOR_CONFIG_PATH: &str = "tor/sender";

#[derive(Clone)]
pub struct HttpDataSender {
	base_url: String,
	apisecret: Option<String>,
	pub use_socks: bool,
	socks_proxy_addr: Option<SocketAddr>,
	// tor_process instance is needed. The process is alive until this instance is not dropped.
	tor_process: Rc<Option<tor_process::TorProcess>>,
}

impl Drop for HttpDataSender {
	fn drop(&mut self) {
		if self.tor_process.is_some() {
			tor::status::set_tor_sender_running(false);
		}
	}
}

impl HttpDataSender {
	/// Create, return Err if scheme is not "http"
	pub fn plain_http(base_url: &str, apisecret: Option<String>) -> Result<HttpDataSender, Error> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			Err(Error::GenericError(format!(
				"Invalid http url: {}",
				base_url
			)))
		} else {
			Ok(HttpDataSender {
				base_url: Self::build_url_str(base_url),
				apisecret,
				use_socks: false,
				socks_proxy_addr: None,
				tor_process: Rc::new(None),
			})
		}
	}

	/// Switch to using socks proxy
	pub fn tor_through_socks_proxy(
		base_url: &str,
		apisecret: Option<String>,
		proxy_addr: &str,
		tor_config_dir: Option<String>,
		socks_running: bool,
		tor_log_file: &Option<String>,
		tor_bridge: &TorBridgeConfig,
		tor_proxy: &TorProxyConfig,
	) -> Result<HttpDataSender, Error> {
		let addr = proxy_addr.parse().map_err(|e| {
			Error::GenericError(format!("Unable to parse address {}, {}", proxy_addr, e))
		})?;
		let socks_proxy_addr = SocketAddr::V4(addr);
		let tor_config_dir = tor_config_dir.unwrap_or(String::from(""));

		let (base_url, tor_process) = Self::set_up_tor_sender_process(
			base_url,
			&tor_config_dir,
			socks_running,
			&socks_proxy_addr,
			&tor_bridge,
			&tor_proxy,
			&tor_log_file,
		)?;

		Ok(HttpDataSender {
			base_url,
			apisecret,
			use_socks: true,
			socks_proxy_addr: Some(socks_proxy_addr),
			tor_process: Rc::new(Some(tor_process)),
		})
	}

	/// Check version of the listening wallet
	pub fn check_other_version(
		&self,
		timeout: Option<u128>,
		destination_address: &String,
		show_error: bool,
	) -> Result<(SlateVersion, Option<String>), Error> {
		let res_str: String;
		let start_time = std::time::Instant::now();
		trace!("starting now check version");

		loop {
			let req = json!({
				"jsonrpc": "2.0",
				"method": "check_version",
				"id": 1,
				"params": []
			});

			let res = self.post(req);

			let diff_time = start_time.elapsed().as_millis();
			trace!("elapsed time check version = {}", diff_time);
			// we try until it's taken more than 30 seconds.

			let is_http_err = match &res {
				Ok(_) => false,
				Err(e) => {
					let err_string = format!("{}", e);
					err_string.contains("HTTP error")
				}
			};

			if res.is_err() && !is_http_err && diff_time <= timeout.unwrap_or(30_000) {
				let res_err_str = format!("{:?}", res);
				trace!(
					"Got error (version_check), but continuing: {}, time elapsed = {}ms",
					res_err_str,
					diff_time
				);
				// the api seems to have "GeneralFailures"
				// on some platforms. retry is fast and can be
				// done again.
				// keep trying for 30 seconds.
				continue;
			} else if !res.is_err() {
				res_str = res.unwrap();
				break;
			}

			res.map_err(|e| {
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
				Error::ClientCallback(report)
			})?;
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
		let res_str: String;
		let start_time = std::time::Instant::now();
		trace!("starting now check proof address of listening wallet");

		loop {
			let req = json!({
				"jsonrpc": "2.0",
				"method": "get_proof_address",
				"id": 1,
				"params": []
			});

			let res = self.post(req);

			let diff_time = start_time.elapsed().as_millis();
			trace!("elapsed time check proof address = {}", diff_time);
			// we try until it's taken more than 30 seconds.
			if res.is_err() && diff_time <= timeout.unwrap_or(30_000) {
				let res_err_str = format!("{:?}", res);
				trace!(
					"Got error (receiver_proof_address), but continuing: {}, time elapsed = {}ms",
					res_err_str,
					diff_time
				);
				// the api seems to have "GeneralFailures"
				// on some platforms. retry is fast and can be
				// done again.
				// keep trying for 30 seconds.
				continue;
			} else if !res.is_err() {
				res_str = res.unwrap();
				break;
			}

			res.map_err(|e| {
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
				Error::ClientCallback(report)
			})?;
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

	fn post<IN>(&self, input: IN) -> Result<String, ClientError>
	where
		IN: Serialize,
	{
		// For state sender we want send and disconnect
		let client = if !self.use_socks {
			Client::new()
		} else {
			Client::with_socks_proxy(
				self.socks_proxy_addr
					.ok_or_else(|| ClientError::Internal("No socks proxy address set".into()))?,
			)
		}
		.map_err(|err| ClientError::Internal(format!("Unable to create http client, {}", err)))?;

		let req = client.create_post_request(
			&self.base_url,
			Some("mwc".to_string()),
			&self.apisecret,
			&input,
		)?;
		let res = client.send_request(req)?;
		Ok(res)
	}

	fn build_url_str(base_url: &str) -> String {
		let trailing = match base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		format!("{}{}v2/foreign", base_url, trailing)
	}

	fn set_up_tor_sender_process(
		base_url: &str,
		tor_config_dir: &String,
		socks_running: bool,
		socks_proxy_addr: &SocketAddr,
		bridge: &TorBridgeConfig,
		proxy: &TorProxyConfig,
		tor_log_file: &Option<String>,
	) -> Result<(String, tor_process::TorProcess), Error> {
		let url_str = Self::build_url_str(base_url);

		// set up tor send process if needed
		let mut tor = tor_process::TorProcess::new();
		// We are checking the tor address because we are using the same Socks port. If listener is running,
		// we don't need the sender.
		if !socks_running
			&& tor::status::get_tor_address().is_none()
			&& !tor::status::get_tor_sender_running()
		{
			let tor_dir = format!("{}{}{}", &tor_config_dir, MAIN_SEPARATOR, TOR_CONFIG_PATH);
			warn!("Starting TOR Process for send at {}", socks_proxy_addr);

			let mut hm_tor_bridge: HashMap<String, String> = HashMap::new();
			if bridge.bridge_line.is_some() {
				let bridge_struct = TorBridge::try_from(bridge.clone())
					.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
				hm_tor_bridge = bridge_struct
					.to_hashmap()
					.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			}

			let mut hm_tor_proxy: HashMap<String, String> = HashMap::new();
			if proxy.transport.is_some() || proxy.allowed_port.is_some() {
				let proxy = TorProxy::try_from(proxy.clone())
					.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
				hm_tor_proxy = proxy
					.to_hashmap()
					.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			}

			tor_config::output_tor_sender_config(
				&tor_dir,
				socks_proxy_addr.to_string().as_str(),
				tor_log_file,
				hm_tor_bridge,
				hm_tor_proxy,
			)
			.map_err(|e| Error::TorConfig(format!("Failed to config Tor, {}", e)))?;
			// Start TOR process
			let tor_cmd = format!("{}/torrc", &tor_dir);
			tor.torrc_path(&tor_cmd)
				.working_dir(&tor_dir)
				.timeout(20)
				.completion_percent(100)
				.launch()
				.map_err(|e| {
					Error::TorProcess(format!("Unable to start Tor process. If error persist, please run from the console 'tor -f {}' to see the error details, {:?}", tor_cmd, e))
				})?;
			tor::status::set_tor_sender_running(true);
		}
		Ok((url_str, tor))
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
		if other_wallet_version.is_none() {
			return Err(Error::GenericError(
				"Internal error, http based send_tx get empty value for other_wallet_version"
					.to_string(),
			));
		}

		let (mut slate_version, slatepack_address) = other_wallet_version.unwrap();

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
							Some(ProvableAddress::from_str(&slatepack_address)
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
				VersionedSlate::into_version_plain(slate.clone(), SlateVersion::V3B)
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
				VersionedSlate::into_version_plain(slate.clone(), SlateVersion::V2)
					.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?
			}
		};

		// //get the proof address of the other wallet
		// let receiver_proof_address = self.check_receiver_proof_address(&url_str, None)?;

		let res_str: String;
		let start_time = std::time::Instant::now();
		loop {
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

			let res = self.post(req);

			let diff_time = start_time.elapsed().as_millis();
			trace!("diff time slate send = {}", diff_time);
			// we try until it's taken more than 30 seconds.
			if res.is_err() && diff_time <= 30_000 {
				let res_err_str = format!("{:?}", res);
				trace!(
					"Got error (send_slate), but continuing: {}, time elapsed = {}ms",
					res_err_str,
					diff_time
				);

				// the api seems to have "GeneralFailures"
				// on some platforms. retry is fast and can be
				// done again.
				// we continue to try for up to 30 seconds
				continue;
			} else if !res.is_err() {
				res_str = res.unwrap();
				break;
			}

			res.map_err(|e| {
				let report = format!("Posting transaction slate (is recipient listening?): {}", e);
				error!("{}", report);
				Error::ClientCallback(report)
			})?;
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
			Slate::deserialize_upgrade_plain(&slate_str).map_err(|e| {
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
			let sp = Slate::deserialize_upgrade_slatepack(&slatepack_str, &slatepack_secret, secp)
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
		let res_str: String;
		let start_time = std::time::Instant::now();

		loop {
			let req = json!({
				"jsonrpc": "2.0",
				"method": "receive_swap_message",
				"id": 1,
				"params": [
							message_ser,
						]
			});
			trace!("Sending receive_swap_message request: {}", req);

			let res = self.post(req);

			let diff_time = start_time.elapsed().as_millis();
			if !res.is_err() {
				res_str = res.unwrap();
				break;
			} else if diff_time <= 30_000 {
				continue;
			}

			res.map_err(|e| {
				let report = format!("Posting swap message (is recipient listening?): {}", e);
				error!("{}", report);
				Error::ClientCallback(report)
			})?;
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
		let res_str: String;
		let start_time = std::time::Instant::now();

		loop {
			let req = json!({
				"jsonrpc": "2.0",
				"method": "marketplace_message",
				"id": 1,
				"params": [
							json_str,
						]
			});
			trace!("Sending marketplace_message request: {}", req);

			let res = self.post(req);

			let diff_time = start_time.elapsed().as_millis();
			if !res.is_err() {
				res_str = res.unwrap();
				break;
			} else if diff_time <= 30_000 {
				continue;
			}

			res.map_err(|e| {
				let report = format!("Posting swap message (is recipient listening?): {}", e);
				error!("{}", report);
				Error::ClientCallback(report)
			})?;
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
