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

use crate::http_parser::parse_utils;
use crate::Error;
use hyper::body::to_bytes;
use hyper::http;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use std::io::Write;
use std::time::Duration;

/// Read response from the stream. Response with the body and closed connection flag.
pub fn read_http_request(
	buf: &mut Vec<u8>,
	stream: &mut TcpDataStream,
	try_read_timeout: &Duration,
	data_wait_timeout: &Duration,
) -> Result<(http::Request<hyper::Body>, bool), Error> {
	// Reading the response:
	stream.set_read_timeout(try_read_timeout.clone());

	let header_text = parse_utils::read_headers(stream, buf)?;
	let (method, path, version, headers) = parse_utils::parse_method_and_headers(&header_text)?;

	// 3. ---------- read exact body ----------
	let body_len = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.parse::<usize>().ok())
		.unwrap_or(0);

	stream.set_read_timeout(data_wait_timeout.clone());

	// Not printing timeout into the error
	let body = parse_utils::read_exact_bytes(stream, buf, body_len)
		.map_err(|_e| Error::ConnectionError(format!("Unable to read the request")))?;
	let body = hyper::Body::from(body);

	let mut builder = http::Request::builder()
		.method(method)
		.uri(path)
		.version(version);
	let mut close_connection = false;
	for (k, v) in headers {
		if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close") {
			close_connection = true;
		}
		builder = builder.header(k, v);
	}

	let request = builder
		.body(body)
		.map_err(|e| Error::ConnectionError(format!("Unable to build a request, {}", e)))?;

	Ok((request, close_connection))
}

pub fn send_http_response(
	stream: &mut TcpDataStream,
	response: http::Response<hyper::Body>,
	close_connection: bool,
) -> Result<(), Error> {
	// 1. status line
	let status = response.status();
	let version = match response.version() {
		http::Version::HTTP_10 => "HTTP/1.0",
		http::Version::HTTP_11 => "HTTP/1.1",
		_ => "HTTP/1.1",
	};
	let reason = status.canonical_reason().unwrap_or("");
	let mut header = String::with_capacity(1024);
	header.push_str(version);
	header.push(' ');
	header.push_str(&status.as_u16().to_string());
	header.push(' ');
	header.push_str(reason);
	header.push_str("\r\n");

	// 2. headers
	for (k, v) in response.headers() {
		header.push_str(k.as_str());
		header.push_str(": ");
		header.push_str(
			v.to_str().map_err(|e| {
				Error::ConnectionError(format!("Invalid response header data, {}", e))
			})?,
		);
		header.push_str("\r\n");
	}

	// 3. content-length + keep-alive
	let body_bytes = body_to_bytes(response.into_body())?;
	header.push_str("Content-Length: ");
	header.push_str(&body_bytes.len().to_string());
	header.push_str("\r\nConnection: ");
	if close_connection {
		header.push_str("close");
	} else {
		header.push_str("keep-alive");
	}
	header.push_str("\r\n\r\n");

	// 4. send headers + body
	stream
		.write_all(header.as_bytes())
		.map_err(|e| Error::ConnectionError(format!("Response write error, {}", e)))?;
	stream
		.write_all(&body_bytes)
		.map_err(|e| Error::ConnectionError(format!("Response write error, {}", e)))?;
	stream
		.flush()
		.map_err(|e| Error::ConnectionError(format!("Response flush error, {}", e)))?;
	Ok(())
}

fn body_to_bytes(body: hyper::body::Body) -> Result<Vec<u8>, Error> {
	futures::executor::block_on(to_bytes(body))
		.map(|b| b.to_vec())
		.map_err(|e| Error::ConnectionError(format!("Broken body data, {}", e)))
}
