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

//! High level JSON/HTTP client API

use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::reqwest;
use mwc_wallet_util::mwc_crates::reqwest::header::{
	ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT,
};
use mwc_wallet_util::mwc_crates::reqwest::{ClientBuilder, Method, Proxy, RequestBuilder};
use mwc_wallet_util::mwc_crates::serde::{Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_util::{run_global_async_block, to_base64};
use std::net::SocketAddr;
use std::time::Duration;

use super::safe_node_error;

#[derive(Clone, Eq, thiserror::Error, PartialEq, Debug)]
pub enum Error {
	#[error("Internal error: {0}")]
	Internal(String),
	#[error("Request error: {0}")]
	RequestError(String),
	#[error("Request error: Get error response, HTTP error code: {0}")]
	HttpStatus(reqwest::StatusCode),
	#[error("ResponseError error: {0}")]
	ResponseError(String),
}

impl Error {
	pub(crate) fn http_status(&self) -> Option<reqwest::StatusCode> {
		match self {
			Error::HttpStatus(status) => Some(*status),
			_ => None,
		}
	}
}

#[derive(Clone)]
pub struct Client {
	context_id: u32,
	client: reqwest::Client,
}

impl Client {
	/// New client
	pub fn new(context_id: u32) -> Result<Self, Error> {
		Self::build(context_id, None)
	}

	pub(crate) fn context_id(&self) -> u32 {
		self.context_id
	}

	fn build(context_id: u32, socks_proxy_addr: Option<SocketAddr>) -> Result<Self, Error> {
		let mut headers = HeaderMap::new();
		headers.insert(USER_AGENT, HeaderValue::from_static("mwc-client"));
		headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
		headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

		headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

		let timeout;
		let connect_timeout;

		if socks_proxy_addr.is_none() {
			#[cfg(not(target_os = "android"))]
			{
				connect_timeout = 15;
				timeout = 40;
			}

			#[cfg(target_os = "android")]
			{
				// For android timeouts need to be longer because we already experiencing some connection issues.
				connect_timeout = 30;
				timeout = 50;
			}
		} else {
			connect_timeout = 60;
			timeout = 180;
		}

		let mut builder = ClientBuilder::new()
			.connect_timeout(Duration::from_secs(connect_timeout))
			.timeout(Duration::from_secs(timeout))
			// Only use a proxy when one is explicitly supplied below. In particular,
			// do not expose node RPC credentials or request data to an environment or
			// operating-system configured proxy.
			.no_proxy()
			// Node RPC requests can contain wallet-related data. Do not allow a node
			// to forward them to another origin or an internal service.
			.redirect(reqwest::redirect::Policy::none())
			.use_rustls_tls()
			.default_headers(headers);

		if let Some(s) = socks_proxy_addr {
			let proxy = Proxy::all(&format!("socks5h://{}:{}", s.ip(), s.port()))
				.map_err(|e| Error::Internal(format!("Unable to create proxy: {}", e)))?;
			builder = builder.proxy(proxy);
		}

		let client = builder
			.build()
			.map_err(|e| Error::Internal(format!("Unable to build client: {}", e)))?;

		Ok(Client { context_id, client })
	}

	/// Helper function to easily issue a HTTP GET request against a given URL that
	/// returns a JSON object. Handles request building, JSON deserialization and
	/// response code checking.
	pub fn get<'a, T>(
		&self,
		url: &'a str,
		api_secret: &Option<Zeroizing<String>>,
	) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		self.handle_request(self.build_request(url, Method::GET, None, api_secret, None)?)
	}

	/// Helper function to easily issue an async HTTP GET request against a given
	/// URL that returns a future. Handles request building, JSON deserialization
	/// and response code checking.
	pub async fn _get_async<'a, T>(
		&self,
		url: &'a str,
		api_secret: &Option<Zeroizing<String>>,
	) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		self.handle_request_async(self.build_request(url, Method::GET, None, api_secret, None)?)
			.await
	}

	/// Helper function to easily issue a HTTP GET request
	/// on a given URL that returns nothing. Handles request
	/// building and response code checking.
	pub fn _get_no_ret(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
	) -> Result<(), Error> {
		let req = self.build_request(url, Method::GET, None, api_secret, None)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns a JSON object. Handles request
	/// building, JSON serialization and deserialization, and response code
	/// checking.
	pub fn post<IN, OUT>(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
		input: &IN,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		for<'de> OUT: Deserialize<'de>,
	{
		let req = self.create_post_request(url, None, api_secret, input)?;
		self.handle_request(req)
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub async fn post_async<IN, OUT>(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
		input: &IN,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		OUT: Send + 'static,
		for<'de> OUT: Deserialize<'de>,
	{
		self.handle_request_async(self.create_post_request(url, None, api_secret, input)?)
			.await
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns nothing. Handles request
	/// building, JSON serialization, and response code
	/// checking.
	pub fn _post_no_ret<IN>(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		let req = self.create_post_request(url, None, api_secret, input)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub async fn _post_no_ret_async<IN>(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		self.send_request_async(self.create_post_request(url, None, api_secret, input)?)
			.await?;
		Ok(())
	}

	fn build_request(
		&self,
		url: &str,
		method: Method,
		basic_auth_key: Option<String>, // In Node will be generated. Specify None if talk to the Node. Another wallet wants 'mwc'
		api_secret: &Option<Zeroizing<String>>,
		body: Option<String>,
	) -> Result<RequestBuilder, Error> {
		let basic_auth_key = basic_auth_key.unwrap_or(if global::is_mainnet(self.context_id) {
			"mwcmain".to_string()
		} else if global::is_floonet(self.context_id) {
			"mwcfloo".to_string()
		} else {
			"mwc".to_string()
		});

		self.build_request_ex(
			url,
			method,
			api_secret,
			Some(basic_auth_key.to_string()),
			body,
		)
	}

	fn build_request_ex(
		&self,
		url: &str,
		method: Method,
		api_secret: &Option<Zeroizing<String>>,
		basic_auth_key: Option<String>,
		body: Option<String>,
	) -> Result<RequestBuilder, Error> {
		// Both HTTP and HTTPS are deliberately supported. The node RPC traffic is
		// not treated as confidential, and this client does not dictate deployment
		// topology by enforcing HTTPS. HTTP Basic authentication provides no
		// confidentiality on its own: deployments that need to protect the node API
		// secret must use an appropriately secured network or terminate HTTPS at a
		// gateway, as public MWC nodes do.
		let mut builder = self.client.request(method, url);

		if let (Some(basic_auth_key), Some(api_secret)) = (basic_auth_key, api_secret.as_ref()) {
			let mut credentials = Zeroizing::new(String::with_capacity(
				basic_auth_key.len() + 1 + api_secret.len(),
			));
			credentials.push_str(&basic_auth_key);
			credentials.push(':');
			credentials.push_str(api_secret.as_str());

			let base64_key = Zeroizing::new(to_base64(credentials.as_str()));
			let mut basic_auth =
				Zeroizing::new(String::with_capacity("Basic ".len() + base64_key.len()));
			basic_auth.push_str("Basic ");
			basic_auth.push_str(base64_key.as_str());
			let mut authorization = HeaderValue::from_str(basic_auth.as_str()).map_err(|e| {
				Error::Internal(format!("Unable to build authorization header: {}", e))
			})?;
			authorization.set_sensitive(true);
			builder = builder.header(AUTHORIZATION, authorization);
		}

		if let Some(body) = body {
			builder = builder.body(body);
		}
		Ok(builder)
	}

	pub fn create_post_request<IN>(
		&self,
		url: &str,
		basic_auth_key: Option<String>, // Specify None if talk to the Node. Another wallet wants 'mwc'
		api_secret: &Option<Zeroizing<String>>,
		input: &IN,
	) -> Result<RequestBuilder, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input)
			.map_err(|e| Error::Internal(format!("Could not serialize data to JSON, {}", e)))?;
		self.build_request(url, Method::POST, basic_auth_key, api_secret, Some(json))
	}

	pub fn _create_post_request_ex<IN>(
		&self,
		url: &str,
		api_secret: &Option<Zeroizing<String>>,
		basic_auth_key: Option<String>,
		input: &IN,
	) -> Result<RequestBuilder, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input)
			.map_err(|e| Error::Internal(format!("Could not serialize data to JSON, {}", e)))?;
		self.build_request_ex(url, Method::POST, api_secret, basic_auth_key, Some(json))
	}

	fn handle_request<T>(&self, req: RequestBuilder) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		let data = self.send_request(req)?;
		parse_response(&data)
	}

	async fn handle_request_async<T>(&self, req: RequestBuilder) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		let data = self.send_request_async(req).await?;
		parse_response(&data)
	}

	async fn send_request_async(&self, req: RequestBuilder) -> Result<String, Error> {
		let resp = req
			.send()
			.await
			.map_err(|e| Error::RequestError(format!("Cannot make request: {}", e)))?;
		if !resp.status().is_success() {
			return Err(Error::HttpStatus(resp.status()));
		}
		let bytes = resp
			.bytes()
			.await
			.map_err(|e| Error::ResponseError(format!("Cannot get response: {}", e)))?;
		std::str::from_utf8(&bytes)
			.map(str::to_owned)
			.map_err(|e| Error::ResponseError(format!("Response is not valid UTF-8: {}", e)))
	}

	pub fn send_request(&self, req: RequestBuilder) -> Result<String, Error> {
		// This client is currently used both outside and inside of a tokio runtime
		// context. In the latter case we are not allowed to do a blocking call to
		// our global runtime, which unfortunately means we have to spawn a new thread
		run_global_async_block(self.send_request_async(req))
			.map_err(|e| Error::Internal(format!("Async runtime error, {}", e)))?
	}
}

fn parse_response<T>(data: &str) -> Result<T, Error>
where
	for<'de> T: Deserialize<'de>,
{
	if data.is_empty() {
		return Err(Error::ResponseError(
			"Access denied, foreign_api_secret is invalid or not set".to_owned(),
		));
	}
	serde_json::from_str(data).map_err(|e| {
		Error::ResponseError(format!(
			"Cannot parse JSON response ({} bytes): {}",
			data.len(),
			safe_node_error(&e)
		))
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_util::init_global_runtime;
	use std::io::{ErrorKind, Read, Write};
	use std::net::TcpListener;
	use std::sync::mpsc;
	use std::thread;
	use std::time::Instant;

	#[test]
	fn authorization_header_is_sensitive() {
		let client = Client::new(0).unwrap();
		let api_secret = Some(Zeroizing::new("secret".to_owned()));
		let request = client
			.build_request_ex(
				"http://127.0.0.1/",
				Method::GET,
				&api_secret,
				Some("mwc".to_owned()),
				None,
			)
			.unwrap()
			.build()
			.unwrap();

		assert!(request.headers()[AUTHORIZATION].is_sensitive());
	}

	#[test]
	fn client_does_not_forward_post_body_on_redirect() {
		init_global_runtime().unwrap();

		let target = TcpListener::bind("127.0.0.1:0").unwrap();
		target.set_nonblocking(true).unwrap();
		let target_url = format!("http://{}/internal", target.local_addr().unwrap());
		let (stop_target_sender, stop_target_receiver) = mpsc::channel();
		let (target_contacted_sender, target_contacted_receiver) = mpsc::channel();
		let target_thread = thread::spawn(move || {
			loop {
				match target.accept() {
					Ok((mut stream, _)) => {
						stream.set_nonblocking(false).unwrap();
						target_contacted_sender.send(()).unwrap();
						let mut request = [0u8; 4096];
						let _ = stream.read(&mut request);
						let _ = stream.write_all(
							b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
						);
						break;
					}
					Err(error) if error.kind() == ErrorKind::WouldBlock => {
						if stop_target_receiver.try_recv().is_ok() {
							break;
						}
						thread::yield_now();
					}
					Err(error) => panic!("unable to accept redirect target connection: {}", error),
				}
			}
		});

		let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
		redirector.set_nonblocking(true).unwrap();
		let redirector_url = format!("http://{}/rpc", redirector.local_addr().unwrap());
		let redirect_thread = thread::spawn(move || {
			let started = Instant::now();
			loop {
				match redirector.accept() {
					Ok((mut stream, _)) => {
						stream.set_nonblocking(false).unwrap();
						stream
							.set_read_timeout(Some(Duration::from_secs(2)))
							.unwrap();
						let mut request = [0u8; 4096];
						stream.read(&mut request).unwrap();
						let response = format!(
							"HTTP/1.1 307 Temporary Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
							target_url
						);
						stream.write_all(response.as_bytes()).unwrap();
						break;
					}
					Err(error) if error.kind() == ErrorKind::WouldBlock => {
						assert!(
							started.elapsed() < Duration::from_secs(5),
							"client did not connect to redirect test server"
						);
						thread::yield_now();
					}
					Err(error) => panic!("unable to accept client connection: {}", error),
				}
			}
		});

		let client = Client::new(0).unwrap();
		let request = client
			._create_post_request_ex(
				&redirector_url,
				&None,
				None,
				&serde_json::json!({ "wallet": "request-body" }),
			)
			.unwrap();
		let result = client.send_request(request);

		redirect_thread.join().unwrap();
		let _ = stop_target_sender.send(());
		target_thread.join().unwrap();

		assert!(matches!(
			result,
			Err(Error::HttpStatus(reqwest::StatusCode::TEMPORARY_REDIRECT))
		));
		assert!(target_contacted_receiver.try_recv().is_err());
	}

	#[test]
	fn parse_error_does_not_retain_hostile_response_body() {
		let body = "not-json\n\u{1b}]52;c;copied\u{7}\u{202e}spoofed";
		let error = parse_response::<serde_json::Value>(body)
			.expect_err("the hostile body is not valid JSON")
			.to_string();

		assert!(error.contains(&format!("{} bytes", body.len())));
		assert!(!error.contains("not-json"));
		assert!(!error.contains('\n'));
		assert!(!error.contains('\u{1b}'));
		assert!(!error.contains('\u{7}'));
		assert!(!error.contains('\u{202e}'));
	}
}
