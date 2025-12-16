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
use hyper::http;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use std::io::Read;

/// Read until double CRLF; return header block as String.
pub(crate) fn read_headers(stream: &mut TcpDataStream, buf: &mut Vec<u8>) -> Result<String, Error> {
	loop {
		if let Some(idx) = find_double_crlf(buf) {
			let raw = buf.drain(..idx).collect::<Vec<_>>();
			return String::from_utf8(raw)
				.map_err(|_| Error::ConnectionError("Invalid response, non-utf8 header".into()));
		}
		// need more
		let mut tmp = [0u8; 2048];
		let n = stream
			.read(&mut tmp)
			.map_err(|e| Error::ConnectionError(format!("Reading response error, {}", e)))?;
		if n == 0 {
			return Err(Error::ConnectionError("eof while reading headers".into()));
		}
		buf.extend_from_slice(&tmp[..n]);
	}
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
	buf.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.or_else(|| buf.windows(2).position(|w| w == b"\n\n"))
		.map(|p| p + if buf[p..].starts_with(b"\r\n") { 4 } else { 2 })
}

/// Minimal status/headers parser.
pub(crate) fn parse_status_and_headers(head_block: &str) -> Result<Vec<(String, String)>, Error> {
	let mut lines = head_block.lines();

	let status_line = lines.next().ok_or_else(|| {
		Error::ConnectionError("Get response with no data. Connection is closed".into())
	})?;
	let status = parse_status_line(status_line)?;
	if status != 200 && status != 201 {
		return Err(Error::ConnectionError(format!("HTTP error {}", status)));
	}

	let mut headers = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_owned(), v.trim().to_owned()));
		}
	}
	Ok(headers)
}

// return (method, path, version, headers)
pub(crate) fn parse_method_and_headers(
	head_block: &str,
) -> Result<
	(
		http::Method,
		http::Uri,
		http::Version,
		Vec<(String, String)>,
	),
	Error,
> {
	let mut lines = head_block.lines();

	let request_line = lines.next().ok_or_else(|| {
		Error::ConnectionError("Get response with no data. Connection is closed".into())
	})?;

	let mut parts = request_line.splitn(3, ' ');
	let method = parts.next().ok_or(Error::ConnectionError(format!(
		"missing method at request line: {}",
		request_line
	)))?;
	let uri = parts.next().ok_or(Error::ConnectionError(format!(
		"missing uri at request line: {}",
		request_line
	)))?;
	let version = parts.next().ok_or(Error::ConnectionError(format!(
		"missing version at request line: {}",
		request_line
	)))?;

	let method = http::Method::from_bytes(method.as_bytes()).map_err(|e| {
		Error::ConnectionError(format!("HTTP request get invalid method {}, {}", method, e))
	})?;
	let uri = uri.parse::<http::Uri>().map_err(|e| {
		Error::ConnectionError(format!("HTTP request get invalid Uri {}, {}", uri, e))
	})?;
	let version = match version {
		"HTTP/1.0" => http::Version::HTTP_10,
		"HTTP/1.1" => http::Version::HTTP_11,
		"HTTP/2.0" | "HTTP/2" => http::Version::HTTP_2,
		_ => {
			return Err(Error::ConnectionError(format!(
				"HTTP request get invalid protocol version {}",
				version
			)))
		}
	};

	let mut headers = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_owned(), v.trim().to_owned()));
		}
	}
	Ok((method, uri, version, headers))
}

/// Read *exactly* `n` bytes (draining leftover buffer first).
pub(crate) fn read_exact_bytes(
	stream: &mut TcpDataStream,
	buf: &mut Vec<u8>,
	n: usize,
) -> Result<Vec<u8>, Error> {
	let mut out = vec![0u8; n];
	let from_buf = buf.len().min(n);
	out[..from_buf].copy_from_slice(&buf[..from_buf]);
	buf.drain(..from_buf);
	stream
		.read_exact(&mut out[from_buf..])
		.map_err(|e| Error::ConnectionError(format!("Response reading error, {}", e)))?;
	Ok(out)
}

fn parse_status_line(line: &str) -> Result<u16, Error> {
	// "HTTP/1.1 200 OK"
	let code = line
		.split_whitespace()
		.nth(1)
		.ok_or_else(|| {
			Error::ConnectionError(format!("malformed status line at response: {}", line))
		})?
		.parse::<u16>()
		.map_err(|_| {
			Error::ConnectionError(format!("Invalid status code at response: {}", line))
		})?;

	Ok(code)
}
