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

/// HTTP Wallet 'plugin' implementation
use crate::client_utils::{Client, ClientError};
use crate::error::{Error, ErrorKind};
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::swap::message::Message;
use crate::libwallet::Slate;
use crate::{SlateSender, SwapMessageSender};
use serde::Serialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::MAIN_SEPARATOR;

use crate::tor::config as tor_config;
use crate::tor::process as tor_process;

const TOR_CONFIG_PATH: &str = "tor/sender";

#[derive(Clone)]
pub struct HttpDataSender {
	base_url: String,
	apisecret: Option<String>,
	pub use_socks: bool,
	socks_proxy_addr: Option<SocketAddr>,
	tor_config_dir: String,
	socks_running: bool,
}

impl HttpDataSender {
	/// Create, return Err if scheme is not "http"
	pub fn new(
		base_url: &str,
		apisecret: Option<String>,
		tor_config_dir: Option<String>,
		socks_running: bool,
	) -> Result<HttpDataSender, Error> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			Err(ErrorKind::GenericError(format!("Invalid http url: {}", base_url)).into())
		} else {
			Ok(HttpDataSender {
				base_url: base_url.to_owned(),
				apisecret,
				use_socks: false,
				socks_proxy_addr: None,
				tor_config_dir: tor_config_dir.unwrap_or(String::from("")),
				socks_running: socks_running,
			})
		}
	}

	/// Switch to using socks proxy
	pub fn with_socks_proxy(
		base_url: &str,
		apisecret: Option<String>,
		proxy_addr: &str,
		tor_config_dir: Option<String>,
		socks_running: bool,
	) -> Result<HttpDataSender, Error> {
		let mut ret = Self::new(base_url, apisecret, tor_config_dir.clone(), socks_running)?;
		ret.use_socks = true;
		let addr = proxy_addr.parse().map_err(|e| {
			ErrorKind::GenericError(format!("Anable to parse address {}, {}", proxy_addr, e))
		})?;
		ret.socks_proxy_addr = Some(SocketAddr::V4(addr));
		ret.tor_config_dir = tor_config_dir.unwrap_or(String::from(""));
		Ok(ret)
	}

	/// Check version of the listening wallet
	pub fn check_other_version(
		&self,
		url: &str,
		timeout: Option<u128>,
	) -> Result<SlateVersion, Error> {
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

			let res = self.post(url, self.apisecret.clone(), req);

			let diff_time = start_time.elapsed().as_millis();
			trace!("elapsed time check version = {}", diff_time);
			// we try until it's taken more than 30 seconds.
			if res.is_err() && diff_time <= timeout.unwrap_or(30_000) {
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
				error!("{}", report);
				ErrorKind::ClientCallback(report)
			})?;
		}

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Checking version: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let resp_value = res["result"]["Ok"].clone();
		trace!("resp_value: {}", resp_value.clone());
		let foreign_api_version: u16 =
			serde_json::from_value(resp_value["foreign_api_version"].clone()).map_err(|e| {
				ErrorKind::GenericError(format!(
					"Unable to read respond foreign_api_version value {}, {}",
					res_str, e
				))
			})?;
		let supported_slate_versions: Vec<String> = serde_json::from_value(
			resp_value["supported_slate_versions"].clone(),
		)
		.map_err(|e| {
			ErrorKind::GenericError(format!(
				"Unable to read respond supported_slate_versions value {}, {}",
				res_str, e
			))
		})?;

		// trivial tests for now, but will be expanded later
		if foreign_api_version < 2 {
			let report = "Other wallet reports unrecognized API format.".to_string();
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		if supported_slate_versions.contains(&"V3B".to_owned()) {
			return Ok(SlateVersion::V3B);
		}

		if supported_slate_versions.contains(&"V3".to_owned()) {
			return Ok(SlateVersion::V3);
		}
		if supported_slate_versions.contains(&"V2".to_owned()) {
			return Ok(SlateVersion::V2);
		}

		let report = "Unable to negotiate slate format with other wallet.".to_string();
		error!("{}", report);
		Err(ErrorKind::ClientCallback(report).into())
	}

	/// Check proof address of the listening wallet
	pub fn check_receiver_proof_address(
		&self,
		url: &str,
		timeout: Option<u128>,
	) -> Result<String, Error> {
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

			let res = self.post(url, self.apisecret.clone(), req);

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
				ErrorKind::ClientCallback(report)
			})?;
		}

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Checking receiver wallet proof address: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
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
		Err(ErrorKind::ClientCallback(report).into())
	}

	fn post<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: IN,
	) -> Result<String, ClientError>
	where
		IN: Serialize,
	{
		// For state sender we want send and disconnect
		let client = Client::new(self.use_socks, self.socks_proxy_addr)?;
		let req = client.create_post_request(url, Some("mwc".to_string()), api_secret, &input)?;
		let res = client.send_request(req)?;
		Ok(res)
	}

	pub fn start_socks(&mut self, proxy_addr: &str) -> Result<tor_process::TorProcess, Error> {
		self.socks_running = true;

		let addr = proxy_addr.parse().map_err(|e| {
			ErrorKind::GenericError(format!("Anable to parse address {}, {}", proxy_addr, e))
		})?;
		self.socks_proxy_addr = Some(SocketAddr::V4(addr));

		let mut tor = tor_process::TorProcess::new();
		let tor_dir = format!(
			"{}{}{}",
			&self.tor_config_dir, MAIN_SEPARATOR, TOR_CONFIG_PATH
		);
		warn!(
			"Starting Tor Process for send at {:?}",
			self.socks_proxy_addr
		);
		tor_config::output_tor_sender_config(
			&tor_dir,
			&self
				.socks_proxy_addr
				.ok_or(ErrorKind::GenericError(
					"Not found socks_proxy_addr value".to_string(),
				))?
				.to_string(),
		)
		.map_err(|e| ErrorKind::TorConfig(format!("Failed to config Tor, {}", e)))?;
		// Start TOR process
		let tor_cmd = format!("{}/torrc", &tor_dir);
		tor.torrc_path(&tor_cmd)
			.working_dir(&tor_dir)
			.timeout(200)
			.completion_percent(100)
			.launch()
			.map_err(|e| {
				ErrorKind::TorProcess(format!("Unable to start Tor process {}, {:?}", tor_cmd, e))
			})?;

		Ok(tor)
	}

	fn set_up_tor_send_process(&self) -> Result<(String, tor_process::TorProcess), Error> {
		let trailing = match self.base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		let url_str = format!("{}{}v2/foreign", self.base_url, trailing);

		// set up tor send process if needed
		let mut tor = tor_process::TorProcess::new();
		if self.use_socks && !self.socks_running {
			let tor_dir = format!(
				"{}{}{}",
				&self.tor_config_dir, MAIN_SEPARATOR, TOR_CONFIG_PATH
			);
			warn!(
				"Starting TOR Process for send at {:?}",
				self.socks_proxy_addr
			);
			tor_config::output_tor_sender_config(
				&tor_dir,
				&self
					.socks_proxy_addr
					.ok_or(ErrorKind::GenericError(
						"Not found socks_proxy_addr value".to_string(),
					))?
					.to_string(),
			)
			.map_err(|e| ErrorKind::TorConfig(format!("Failed to config Tor, {}", e)))?;
			// Start TOR process
			let tor_cmd = format!("{}/torrc", &tor_dir);
			tor.torrc_path(&tor_cmd)
				.working_dir(&tor_dir)
				.timeout(20)
				.completion_percent(100)
				.launch()
				.map_err(|e| {
					ErrorKind::TorProcess(format!(
						"Unable to start Tor process {}, {:?}",
						tor_cmd, e
					))
				})?;
		}
		Ok((url_str, tor))
	}
}

impl SlateSender for HttpDataSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		// we need to keep _tor in scope so that the process is not killed by drop.
		let (url_str, _tor) = self.set_up_tor_send_process()?;

		let slate_send = match self.check_other_version(&url_str, None)? {
			SlateVersion::V3B => VersionedSlate::into_version(slate.clone(), SlateVersion::V3),
			SlateVersion::V2 | SlateVersion::V3 => {
				let mut slate = slate.clone();
				if slate.payment_proof.is_some() {
					return Err(ErrorKind::ClientCallback("Payment proof requested, but other wallet does not support payment proofs or tor payment proof. Please urge other user to upgrade, or re-send tx without a payment proof".into()).into());
				}
				if slate.ttl_cutoff_height.is_some() {
					warn!("Slate TTL value will be ignored and removed by other wallet, as other wallet does not support this feature. Please urge other user to upgrade");
				}
				slate.version_info.version = 2;
				slate.version_info.orig_version = 2;
				VersionedSlate::into_version(slate, SlateVersion::V2)
			}
		};

		// //get the proof address of the other wallet
		// let receiver_proof_address = self.check_receiver_proof_address(&url_str, None)?;

		let res_str: String;
		let start_time = std::time::Instant::now();
		loop {
			// Note: not using easy-jsonrpc as don't want the dependencies in this crate
			let req = json!({
				"jsonrpc": "2.0",
				"method": "receive_tx",
				"id": 1,
				"params": [
							slate_send,
							null,
							null
						]
			});
			trace!("Sending receive_tx request: {}", req);

			let res = self.post(&url_str, self.apisecret.clone(), req);

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
				ErrorKind::ClientCallback(report)
			})?;
		}

		let mut res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}
		if res["result"]["Err"] != json!(null) {
			let report = format!("Posting transaction slate: Error: {}", res["result"]["Err"]);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let slate_value = res["result"]["Ok"].clone();
		trace!("slate_value: {}", slate_value);
		if slate_value.is_null() {
			let report = format!("Unable to parse receiver wallet response {}", res_str);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		if res["result"]["Ok"]["version_info"]["version"] == json!(3)
			&& res["result"]["Ok"]["ttl_cutoff_height"] == json!(null)
		{
			res["result"]["Ok"]["ttl_cutoff_height"] = json!(u64::MAX);
		}
		let slate =
			Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).map_err(|e| {
				ErrorKind::GenericError(format!("Unable to build slate from values, {}", e))
			})?)
			.map_err(|e| {
				ErrorKind::GenericError(format!("Unable to build slate from response {}, {}", res_str, e))
			})?;

		// //compare the listening wallet proof address retrieved earlier to the returned slate. If they don't match, return error
		// if let Some(ref p) = slate.payment_proof {
		// 	let receiver_a = p.clone().receiver_address;
		// 	if receiver_a.public_key != receiver_proof_address {
		// 		return Err(ErrorKind::ProofAddressMismatch(
		// 			receiver_a.public_key,
		// 			receiver_proof_address,
		// 		)
		// 		.into());
		// 	}
		// }

		Ok(slate)
	}
}

impl SwapMessageSender for HttpDataSender {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and procesed)
	fn send_swap_message(&self, swap_message: &Message) -> Result<bool, Error> {
		// we need to keep _tor in scope so that the process is not killed by drop.
		let (url_str, _tor) = self.set_up_tor_send_process()?;
		let message_ser = &serde_json::to_string(&swap_message).map_err(|e| {
			ErrorKind::SwapMessageGenericError(format!(
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

			let res = self.post(&url_str, self.apisecret.clone(), req);

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
				ErrorKind::ClientCallback(report)
			})?;
		}

		let res: Value = serde_json::from_str(&res_str).map_err(|e| {
			ErrorKind::GenericError(format!("Unable to parse respond {}, {}", res_str, e))
		})?;

		if res["error"] != json!(null) {
			let report = format!(
				"Sending swap message: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		// http call is synchronouse, so message was delivered and processes. Ack cn be granted.
		Ok(true)
	}
}
