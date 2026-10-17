// Copyright 2025 The Mwc Developers
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

use crate::Error;
use crate::http_parser::parse_utils;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::serde::Serialize;
use mwc_wallet_util::mwc_crates::url::{Position, Url};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_util::to_base64;
use mwc_wallet_util::sensitive;
use std::io::Write;
use std::time::{Duration, Instant};

const DEFAULT_HTTP_POST_TIMEOUT: Duration = Duration::from_secs(30);
const BASIC_AUTH_HEADER_PREFIX: &str = "Authorization: Basic ";

fn checked_string_capacity(parts: &[usize], description: &str) -> Result<usize, Error> {
	parts
		.iter()
		.try_fold(0usize, |total, part| total.checked_add(*part))
		.ok_or_else(|| Error::DataOverflow(format!("{} length overflow", description)))
}

fn build_basic_auth_header(
	basic_auth_key: &str,
	api_secret: &str,
) -> Result<Zeroizing<String>, Error> {
	let auth_key_capacity = checked_string_capacity(
		&[basic_auth_key.len(), ":".len(), api_secret.len()],
		"Basic authentication key",
	)?;
	let mut auth_key = Zeroizing::new(String::with_capacity(auth_key_capacity));
	let auth_key_allocation = auth_key.as_ptr();
	auth_key.push_str(basic_auth_key);
	auth_key.push(':');
	auth_key.push_str(api_secret);
	debug_assert_eq!(auth_key.len(), auth_key_capacity);
	debug_assert_eq!(auth_key.as_ptr(), auth_key_allocation);

	let base64_key = Zeroizing::new(to_base64(auth_key.as_str()));
	let header_capacity = checked_string_capacity(
		&[BASIC_AUTH_HEADER_PREFIX.len(), base64_key.len()],
		"Basic Authorization header",
	)?;
	let mut header = Zeroizing::new(String::with_capacity(header_capacity));
	let header_allocation = header.as_ptr();
	header.push_str(BASIC_AUTH_HEADER_PREFIX);
	header.push_str(base64_key.as_str());
	debug_assert_eq!(header.len(), header_capacity);
	debug_assert_eq!(header.as_ptr(), header_allocation);
	Ok(header)
}

fn build_post_request(
	path: &str,
	host: &str,
	auth_header: Option<&str>,
	connection_header: &str,
	body: &str,
) -> Result<Zeroizing<String>, Error> {
	let content_length = body.len().to_string();
	let auth_line_ending_len = auth_header.map_or(0, |_| "\r\n".len());
	let req_capacity = checked_string_capacity(
		&[
			"POST ".len(),
			path.len(),
			" HTTP/1.1\r\nHost: ".len(),
			host.len(),
			"\r\nContent-Type: application/json\r\n".len(),
			auth_header.map_or(0, str::len),
			auth_line_ending_len,
			"Content-Length: ".len(),
			content_length.len(),
			"\r\n".len(),
			connection_header.len(),
			"\r\n\r\n".len(),
			body.len(),
		],
		"HTTP POST request",
	)?;
	let mut req = Zeroizing::new(String::with_capacity(req_capacity));
	let req_allocation = req.as_ptr();
	req.push_str("POST ");
	req.push_str(path);
	req.push_str(" HTTP/1.1\r\nHost: ");
	req.push_str(host);
	req.push_str("\r\nContent-Type: application/json\r\n");
	if let Some(header) = auth_header {
		req.push_str(header);
		req.push_str("\r\n");
	}
	req.push_str("Content-Length: ");
	req.push_str(&content_length);
	req.push_str("\r\n");
	req.push_str(connection_header);
	req.push_str("\r\n\r\n");
	req.push_str(body);
	debug_assert_eq!(req.len(), req_capacity);
	debug_assert_eq!(req.as_ptr(), req_allocation);
	Ok(req)
}

/// Post with authentication using one timeout budget for the complete HTTP
/// request and response exchange.
pub fn post_auth_with_timeout<OUT>(
	context_id: u32,
	url: Url,
	apisecret: Option<&Zeroizing<String>>,
	stream: &mut TcpDataStream,
	keep_alive: bool,
	timeout: Duration,
	body: OUT,
) -> Result<(String, bool), Error>
where
	OUT: Serialize,
{
	let started = Instant::now();
	let auth_header = match apisecret {
		Some(api_secret) => {
			let basic_auth_key = if global::is_mainnet(context_id) {
				"mwcmain"
			} else if global::is_floonet(context_id) {
				"mwcfloo"
			} else {
				"mwc"
			};
			// Allocate credential buffers at their complete sizes before copying the
			// secret. This ensures every allocation containing credentials remains
			// owned by a Zeroizing wrapper until it is wiped on drop.
			Some(build_basic_auth_header(
				basic_auth_key,
				api_secret.as_str(),
			)?)
		}
		None => None,
	};

	post_impl(url, auth_header, stream, keep_alive, started, timeout, body)
}

/// response with error AND close connection request flag
pub fn post<OUT>(
	url: Url,
	stream: &mut TcpDataStream,
	keep_alive: bool,
	body: OUT,
) -> Result<(String, bool), Error>
where
	OUT: Serialize,
{
	post_impl(
		url,
		None,
		stream,
		keep_alive,
		Instant::now(),
		DEFAULT_HTTP_POST_TIMEOUT,
		body,
	)
}

fn post_impl<OUT>(
	url: Url,
	auth_header: Option<Zeroizing<String>>,
	stream: &mut TcpDataStream,
	keep_alive: bool,
	started: Instant,
	timeout: Duration,
	body: OUT,
) -> Result<(String, bool), Error>
where
	OUT: Serialize,
{
	let path = url.path();
	url.host_str().ok_or(Error::ConnectionError(format!(
		"Unable to extract host from {}",
		url
	)))?;
	// Preserve the authority's port and IPv6 brackets without including userinfo.
	let host = &url[Position::BeforeHost..Position::AfterPort];
	let body_bytes = sensitive::serialize_json(&body)
		.map_err(|e| Error::ConnectionError(format!("Could not serialize data to JSON, {}", e)))?;
	let body = std::str::from_utf8(&body_bytes).map_err(|e| {
		Error::ConnectionError(format!("Serialized JSON is not valid UTF-8, {}", e))
	})?;

	let connection_header = if keep_alive {
		"Connection: keep-alive"
	} else {
		"Connection: close"
	};

	// The sender constructors define the security of the underlying stream. The
	// direct constructor accepts only HTTP URLs. The Tor constructor's contract
	// requires a validated Onion v3 destination; in that case these HTTP/1.1 bytes
	// are application data inside Arti's end-to-end encrypted and authenticated
	// onion-service stream. There is no Tor exit node and no separate TLS record
	// layer is needed to keep the request confidential in transit.
	//
	// The request buffer contains the Authorization header. Allocate its complete
	// size before copying credentials so String growth cannot leave an unwiped old
	// allocation, then zeroize the final allocation on drop.
	let req = build_post_request(
		path,
		host,
		auth_header.as_ref().map(|header| header.as_str()),
		connection_header,
		body,
	)?;

	stream.set_write_timeout(remaining_post_timeout(
		started,
		timeout,
		"sending HTTP request",
	)?);
	stream
		.write_all(req.as_bytes())
		.map_err(|e| Error::ConnectionError(format!("Unable to send the request, {}", e)))?;
	stream.set_write_timeout(remaining_post_timeout(
		started,
		timeout,
		"flushing HTTP request",
	)?);
	stream
		.flush()
		.map_err(|e| Error::ConnectionError(format!("Unable to send the request, {}", e)))?;

	// Reading the response:
	let mut buf: Vec<u8> = Vec::new();
	let remaining = remaining_post_timeout(started, timeout, "reading HTTP response headers")?;
	let header_text = parse_utils::read_headers_with_limits(
		stream,
		&mut buf,
		parse_utils::MAX_HTTP_HEADER_BYTES,
		parse_utils::HTTP_READ_POLL_INTERVAL,
		remaining,
		&|| false,
	)?;
	let headers = parse_utils::parse_status_and_headers(&header_text)?;

	// 3. ---------- read exact body ----------
	let body_len = required_response_content_length(&headers)?;

	let remaining = remaining_post_timeout(started, timeout, "reading HTTP response body")?;
	let body = parse_utils::read_exact_bytes_with_deadline(
		stream,
		&mut buf,
		body_len,
		parse_utils::HTTP_READ_POLL_INTERVAL,
		remaining,
		&|| false,
	)?;

	// 4. ---------- keep-alive check ----------
	let close = !keep_alive
		|| headers
			.iter()
			.any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
	// `Content-Length` completely frames the response body. `Connection: close`
	// only makes the connection non-reusable; reading beyond the framed body
	// would let an untrusted peer stream unbounded data while this call waits.

	let body_str = String::from_utf8(body)
		.map_err(|e| Error::ConnectionError(format!("Response is not a string, {}", e)))?;
	remaining_post_timeout(started, timeout, "processing HTTP response")?;

	Ok((body_str, close))
}

fn required_response_content_length(headers: &[(String, String)]) -> Result<usize, Error> {
	let body_len = parse_utils::content_length(headers)?;
	// A successful response without explicit framing is close-delimited. This
	// client deliberately rejects that form so a connection can never be reused
	// with unread response bytes.
	if !headers
		.iter()
		.any(|(key, _)| key.eq_ignore_ascii_case("content-length"))
	{
		return Err(Error::ConnectionError(
			"Successful HTTP response is missing a Content-Length header".to_string(),
		));
	}
	Ok(body_len)
}

fn remaining_post_timeout(
	started: Instant,
	timeout: Duration,
	operation: &str,
) -> Result<Duration, Error> {
	timeout
		.checked_sub(started.elapsed())
		.filter(|remaining| !remaining.is_zero())
		.ok_or_else(|| {
			Error::HttpReadTimeout(format!("POST deadline exceeded while {}", operation))
		})
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::serde_json;
	use mwc_wallet_util::mwc_crates::tokio::net::TcpStream;
	use mwc_wallet_util::mwc_util::{init_global_runtime, run_global_async_block};
	use std::io::{BufRead, BufReader, Read, Write};
	use std::net::TcpListener;
	use std::sync::mpsc;
	use std::thread;
	use std::time::{Duration, Instant};

	#[test]
	fn authenticated_request_uses_preallocated_credential_buffers() {
		let auth_header = build_basic_auth_header("mwc", "test-secret").unwrap();
		assert_eq!(
			auth_header.as_str(),
			"Authorization: Basic bXdjOnRlc3Qtc2VjcmV0"
		);

		// Make the body large enough that the previous format!-based request
		// construction had to grow after copying the Authorization header.
		let body = format!("{{\"payload\":\"{}\"}}", "x".repeat(4096));
		let request = build_post_request(
			"/v2/foreign",
			"wallet.example",
			Some(auth_header.as_str()),
			"Connection: keep-alive",
			&body,
		)
		.unwrap();
		let expected = format!(
			"POST /v2/foreign HTTP/1.1\r\n\
             Host: wallet.example\r\n\
             Content-Type: application/json\r\n\
             Authorization: Basic bXdjOnRlc3Qtc2VjcmV0\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n{}",
			body.len(),
			body
		);
		assert_eq!(request.as_str(), expected);
	}

	#[test]
	fn post_host_header_preserves_authority_without_userinfo() {
		init_global_runtime().unwrap();
		for (target, expected_host) in [
			(
				"http://wallet.example:3415/v2/foreign",
				"wallet.example:3415",
			),
			("http://127.0.0.1:3415/v2/foreign", "127.0.0.1:3415"),
			("http://[::1]:3415/v2/foreign", "[::1]:3415"),
			("http://wallet.example/v2/foreign", "wallet.example"),
			("http://wallet.example:80/v2/foreign", "wallet.example"),
			("http://[::1]/v2/foreign", "[::1]"),
			(
				"http://user:password@wallet.example:3415/v2/foreign",
				"wallet.example:3415",
			),
			("http://user:password@[::1]:3415/v2/foreign", "[::1]:3415"),
		] {
			// Use a local stream to inspect the request for each URL authority.
			let listener = TcpListener::bind("127.0.0.1:0").unwrap();
			let address = listener.local_addr().unwrap();
			let server = thread::spawn(move || {
				let (socket, _) = listener.accept().unwrap();
				socket
					.set_read_timeout(Some(Duration::from_secs(2)))
					.unwrap();
				let mut socket = BufReader::new(socket);
				let mut headers = String::new();
				loop {
					let mut line = String::new();
					assert!(socket.read_line(&mut line).unwrap() > 0);
					if line == "\r\n" {
						break;
					}
					headers.push_str(&line);
				}
				let mut body = [0u8; 2];
				socket.read_exact(&mut body).unwrap();
				assert_eq!(&body, b"{}");
				socket
					.get_mut()
					.write_all(
						b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
					)
					.unwrap();
				headers
			});

			let tcp_stream = run_global_async_block(TcpStream::connect(address))
				.unwrap()
				.unwrap();
			let mut stream = TcpDataStream::from_tcp(tcp_stream);
			let result = post(
				Url::parse(target).unwrap(),
				&mut stream,
				false,
				serde_json::json!({}),
			);
			let headers = server.join().unwrap();
			assert_eq!(result.unwrap(), ("{}".to_string(), true));
			let hosts: Vec<_> = headers
				.lines()
				.filter_map(|line| line.strip_prefix("Host: "))
				.collect();
			assert_eq!(hosts, [expected_host], "incorrect Host header for {target}");
		}
	}

	#[test]
	fn successful_response_without_content_length_is_rejected() {
		init_global_runtime().unwrap();
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut socket, _) = listener.accept().unwrap();
			let mut request = [0u8; 4096];
			socket.read(&mut request).unwrap();
			socket
				.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}")
				.unwrap();
		});

		let tcp_stream = run_global_async_block(TcpStream::connect(address))
			.unwrap()
			.unwrap();
		let mut stream = TcpDataStream::from_tcp(tcp_stream);
		let url = Url::parse(&format!("http://{}/", address)).unwrap();
		let result = post(
			url,
			&mut stream,
			true,
			serde_json::json!({ "request": true }),
		);
		server.join().unwrap();

		assert!(matches!(
			result,
			Err(Error::ConnectionError(message))
				if message == "Successful HTTP response is missing a Content-Length header"
		));
	}

	#[test]
	fn framed_close_response_does_not_drain_unbounded_trailing_bytes() {
		init_global_runtime().unwrap();
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let (stop_sender, stop_receiver) = mpsc::channel();
		let server = thread::spawn(move || {
			let (mut socket, _) = listener.accept().unwrap();
			let mut request = [0u8; 4096];
			socket.read(&mut request).unwrap();
			socket
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
				.unwrap();
			loop {
				if stop_receiver.try_recv().is_ok() || socket.write_all(b"x").is_err() {
					break;
				}
				thread::sleep(Duration::from_millis(20));
			}
		});

		let tcp_stream = run_global_async_block(TcpStream::connect(address))
			.unwrap()
			.unwrap();
		let mut stream = TcpDataStream::from_tcp(tcp_stream);
		let url = Url::parse(&format!("http://{}/", address)).unwrap();
		let (result_sender, result_receiver) = mpsc::channel();
		let client = thread::spawn(move || {
			let result = post(
				url,
				&mut stream,
				true,
				serde_json::json!({ "request": true }),
			)
			.map_err(|e| e.to_string());
			result_sender.send(result).unwrap();
		});

		let timely_result = result_receiver.recv_timeout(Duration::from_secs(1));
		let _ = stop_sender.send(());
		server.join().unwrap();
		client.join().unwrap();
		let (body, close) = timely_result
			.expect("framed response waited for bytes beyond Content-Length")
			.unwrap();
		assert_eq!(body, "{}");
		assert!(close);
	}

	#[test]
	fn post_timeout_is_shared_by_headers_and_body() {
		init_global_runtime().unwrap();
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = thread::spawn(move || {
			let (mut socket, _) = listener.accept().unwrap();
			let mut request = [0u8; 4096];
			socket.read(&mut request).unwrap();

			thread::sleep(Duration::from_millis(80));
			socket
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
				.unwrap();
			socket.flush().unwrap();
			thread::sleep(Duration::from_millis(100));
			let _ = socket.write_all(b"{}");
		});

		let tcp_stream = run_global_async_block(TcpStream::connect(address))
			.unwrap()
			.unwrap();
		let mut stream = TcpDataStream::from_tcp(tcp_stream);
		let url = Url::parse(&format!("http://{}/", address)).unwrap();
		let started = Instant::now();
		let result = post_impl(
			url,
			None,
			&mut stream,
			true,
			started,
			Duration::from_millis(150),
			serde_json::json!({ "request": true }),
		);
		let elapsed = started.elapsed();

		server.join().unwrap();
		assert!(matches!(result, Err(Error::HttpReadTimeout(_))));
		assert!(
			elapsed < Duration::from_millis(300),
			"POST exceeded its shared timeout budget: {:?}",
			elapsed
		);
	}
}
