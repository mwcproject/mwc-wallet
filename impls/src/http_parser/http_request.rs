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
use mwc_wallet_util::mwc_crates::bytes::Bytes;
use mwc_wallet_util::mwc_crates::futures;
use mwc_wallet_util::mwc_crates::http;
use mwc_wallet_util::mwc_crates::http_body_util::{BodyExt, Full};
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use std::io::Write;
use std::time::Duration;

/// Read one HTTP request while allowing server shutdown to interrupt the
/// absolute header/body deadlines at the normal poll interval.
pub fn read_http_request(
	buf: &mut Vec<u8>,
	stream: &mut TcpDataStream,
	try_read_timeout: &Duration,
	data_wait_timeout: &Duration,
	cancelled: &dyn Fn() -> bool,
) -> Result<(http::Request<Bytes>, bool), Error> {
	// Reading the response:
	stream.set_read_timeout(*try_read_timeout);

	let header_text = parse_utils::read_headers_with_limits(
		stream,
		buf,
		parse_utils::MAX_HTTP_HEADER_BYTES,
		*try_read_timeout,
		parse_utils::HTTP_HEADER_READ_DEADLINE,
		cancelled,
	)?;
	let (method, path, version, headers) = parse_utils::parse_method_and_headers(&header_text)?;

	// 3. ---------- read exact body ----------
	let body_len = parse_utils::content_length(&headers)?;

	stream.set_read_timeout(*data_wait_timeout);

	// Not printing timeout into the error
	let body = parse_utils::read_exact_bytes_with_deadline(
		stream,
		buf,
		body_len,
		*try_read_timeout,
		*data_wait_timeout,
		cancelled,
	)?;
	let body = Bytes::from(body);

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
	response: http::Response<Full<Bytes>>,
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
	append_response_headers(&mut header, response.headers())?;

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

fn append_response_headers(
	header: &mut String,
	headers: &http::HeaderMap<http::HeaderValue>,
) -> Result<(), Error> {
	for (k, v) in headers {
		// Framing is owned by send_http_response. Forwarding these values before
		// adding the computed fields below could create duplicate Content-Length
		// headers or an ambiguous Transfer-Encoding/Content-Length response.
		if k == http::header::CONTENT_LENGTH
			|| k == http::header::TRANSFER_ENCODING
			|| k == http::header::CONNECTION
		{
			continue;
		}

		header.push_str(k.as_str());
		header.push_str(": ");
		header.push_str(
			v.to_str().map_err(|e| {
				Error::ConnectionError(format!("Invalid response header data, {}", e))
			})?,
		);
		header.push_str("\r\n");
	}
	Ok(())
}

fn body_to_bytes(body: Full<Bytes>) -> Result<Vec<u8>, Error> {
	let collected = futures::executor::block_on(body.collect())
		.map_err(|e| Error::ConnectionError(format!("Broken body data, {}", e)))?;
	Ok(collected.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn managed_response_headers_are_not_forwarded() {
		let response = http::Response::builder()
			.header(http::header::CONTENT_LENGTH, "999")
			.header(http::header::TRANSFER_ENCODING, "chunked")
			.header(http::header::CONNECTION, "close")
			.header("x-test-header", "preserved")
			.body(Full::new(Bytes::from_static(b"body")))
			.unwrap();
		let mut header = String::new();

		append_response_headers(&mut header, response.headers()).unwrap();

		assert_eq!(header, "x-test-header: preserved\r\n");
	}
}
