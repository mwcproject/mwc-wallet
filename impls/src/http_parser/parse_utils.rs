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
use crate::client_utils::safe_http_text;
use mwc_wallet_util::mwc_crates::http;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use std::io::Read;
use std::time::{Duration, Instant};

pub(crate) const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const HTTP_HEADER_READ_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const HTTP_READ_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Read until double CRLF with application-level size and time bounds.
pub(crate) fn read_headers_with_limits(
	stream: &mut TcpDataStream,
	buf: &mut Vec<u8>,
	max_header_bytes: usize,
	poll_interval: Duration,
	deadline: Duration,
	cancelled: &dyn Fn() -> bool,
) -> Result<String, Error> {
	let started = Instant::now();
	let mut scan_from = 0;

	loop {
		if cancelled() {
			return Err(Error::ClosedListener("HTTP request".to_string()));
		}
		if let Some(idx) = find_header_end(buf, scan_from) {
			if idx > max_header_bytes {
				return Err(Error::HttpMessageTooLarge(format!(
					"HTTP headers exceed {} bytes",
					max_header_bytes
				)));
			}
			let raw = buf.drain(..idx).collect::<Vec<_>>();
			return String::from_utf8(raw)
				.map_err(|_| Error::ConnectionError("Invalid response, non-utf8 header".into()));
		}

		if buf.len() >= max_header_bytes {
			return Err(Error::HttpMessageTooLarge(format!(
				"HTTP headers exceed {} bytes",
				max_header_bytes
			)));
		}

		let remaining = deadline.checked_sub(started.elapsed()).ok_or_else(|| {
			Error::HttpReadTimeout("deadline exceeded while reading HTTP headers".into())
		})?;
		if remaining.is_zero() {
			return Err(Error::HttpReadTimeout(
				"deadline exceeded while reading HTTP headers".into(),
			));
		}
		stream.set_read_timeout(poll_interval.min(remaining));

		let mut tmp = [0u8; 2048];
		let read_limit = tmp.len().min(max_header_bytes.saturating_sub(buf.len()));
		let previous_len = buf.len();
		let n = match stream.read(&mut tmp[..read_limit]) {
			Ok(n) => n,
			Err(e) if is_read_timeout(&e) => continue,
			Err(e) => {
				return Err(Error::ConnectionError(format!(
					"Reading response error, {}",
					e
				)));
			}
		};
		if n == 0 {
			return Err(Error::ConnectionError("eof while reading headers".into()));
		}
		buf.extend_from_slice(&tmp[..n]);
		// A delimiter beginning before this boundary was checked already. Retain
		// three bytes of overlap for a CRLFCRLF split across reads.
		scan_from = previous_len.saturating_sub(3);
	}
}

fn find_header_end(buf: &[u8], scan_from: usize) -> Option<usize> {
	let start = scan_from.min(buf.len());
	for idx in start..buf.len() {
		let remaining = buf.get(idx..)?;
		if remaining.starts_with(b"\r\n\r\n") {
			return idx.checked_add(4);
		}
		if remaining.starts_with(b"\n\n") {
			return idx.checked_add(2);
		}
	}
	None
}

/// Minimal status/headers parser.
pub(crate) fn parse_status_and_headers(head_block: &str) -> Result<Vec<(String, String)>, Error> {
	let mut lines = head_block.lines();

	let status_line = lines.next().ok_or_else(|| {
		Error::ConnectionError("Get response with no data. Connection is closed".into())
	})?;
	let status = parse_status_line(status_line)?;
	if status != 200 && status != 201 {
		return Err(Error::HttpStatus(status));
	}

	let mut headers = Vec::new();
	for line in lines {
		if line.trim().is_empty() {
			continue;
		}
		let (key, value) = line.split_once(':').ok_or_else(|| {
			Error::ConnectionError(format!(
				"Malformed HTTP response header: {}",
				safe_http_text(line)
			))
		})?;
		let key = key.trim();
		if key.is_empty() {
			return Err(Error::ConnectionError(
				"Malformed HTTP response header with an empty name".to_string(),
			));
		}
		headers.push((key.to_owned(), value.trim().to_owned()));
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
		safe_http_text(request_line)
	)))?;
	let uri = parts.next().ok_or(Error::ConnectionError(format!(
		"missing uri at request line: {}",
		safe_http_text(request_line)
	)))?;
	let version = parts.next().ok_or(Error::ConnectionError(format!(
		"missing version at request line: {}",
		safe_http_text(request_line)
	)))?;

	let method = http::Method::from_bytes(method.as_bytes()).map_err(|e| {
		Error::ConnectionError(format!(
			"HTTP request get invalid method {}, {}",
			safe_http_text(method),
			e
		))
	})?;
	let uri = uri.parse::<http::Uri>().map_err(|e| {
		Error::ConnectionError(format!(
			"HTTP request get invalid Uri {}, {}",
			safe_http_text(uri),
			e
		))
	})?;
	let version = match version {
		"HTTP/1.0" => http::Version::HTTP_10,
		"HTTP/1.1" => http::Version::HTTP_11,
		"HTTP/2.0" | "HTTP/2" => http::Version::HTTP_2,
		_ => {
			return Err(Error::ConnectionError(format!(
				"HTTP request get invalid protocol version {}",
				safe_http_text(version)
			)));
		}
	};

	let mut headers = Vec::new();
	for line in lines {
		if line.trim().is_empty() {
			continue;
		}
		let (key, value) = line.split_once(':').ok_or_else(|| {
			Error::ConnectionError(format!(
				"Malformed HTTP request header: {}",
				safe_http_text(line)
			))
		})?;
		// Trimming the field name is intentional compatibility behavior for legacy
		// clients that put whitespace before `:` or send a colon-containing folded
		// line. The wallet has one framing parser and one peer-derived access policy
		// per TCP connection; it does not multiplex different clients on a shared
		// connection. Consequently this leniency can only affect the sending peer's
		// own request stream, so there is no parser differential inside the wallet.
		// A reverse proxy that pools a backend connection across clients introduces
		// a second framing authority and must reject or normalize ambiguous syntax
		// before forwarding it; raw ambiguous HTTP forwarding is not a supported
		// wallet security boundary.
		let key = key.trim();
		if key.is_empty() {
			return Err(Error::ConnectionError(
				"Malformed HTTP request header with an empty name".to_string(),
			));
		}
		headers.push((key.to_owned(), value.trim().to_owned()));
	}
	Ok((method, uri, version, headers))
}

/// Parse HTTP body framing without silently accepting ambiguous or unsupported input.
pub(crate) fn content_length(headers: &[(String, String)]) -> Result<usize, Error> {
	if headers
		.iter()
		.any(|(key, _)| key.eq_ignore_ascii_case("transfer-encoding"))
	{
		return Err(Error::ConnectionError(
			"Transfer-Encoding is not supported by this HTTP parser".to_string(),
		));
	}

	let mut values = headers
		.iter()
		.filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
		.map(|(_, value)| value);
	let Some(value) = values.next() else {
		return Ok(0);
	};
	if values.next().is_some() {
		return Err(Error::ConnectionError(
			"Multiple Content-Length headers are not allowed".to_string(),
		));
	}

	// `usize::from_str` also accepts a leading `+` (for example, `+5`). This is
	// retained for compatibility with direct legacy clients. As above, the wallet
	// has no second parser or cross-client connection multiplexing with which this
	// interpretation could disagree. Deployments adding a pooling reverse proxy
	// must enforce canonical Content-Length syntax at that external boundary. The
	// limit below still bounds allocation and rejects integer overflow.
	let content_length = value
		.parse::<usize>()
		.map_err(|e| Error::ConnectionError(format!("Invalid Content-Length header: {}", e)))?;
	if content_length > MAX_HTTP_BODY_BYTES {
		return Err(Error::HttpMessageTooLarge(format!(
			"HTTP body length {} exceeds {} bytes",
			content_length, MAX_HTTP_BODY_BYTES
		)));
	}
	Ok(content_length)
}

/// Read exactly `n` bytes, draining buffered bytes first and enforcing the
/// supplied total deadline.
pub(crate) fn read_exact_bytes_with_deadline(
	stream: &mut TcpDataStream,
	buf: &mut Vec<u8>,
	n: usize,
	poll_interval: Duration,
	deadline: Duration,
	cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, Error> {
	if n > MAX_HTTP_BODY_BYTES {
		return Err(Error::HttpMessageTooLarge(format!(
			"HTTP body length {} exceeds {} bytes",
			n, MAX_HTTP_BODY_BYTES
		)));
	}

	let mut out = Vec::new();
	out.try_reserve_exact(n).map_err(|e| {
		Error::HttpMessageTooLarge(format!(
			"unable to allocate HTTP body of {} bytes: {}",
			n, e
		))
	})?;
	out.resize(n, 0);
	let from_buf = buf.len().min(n);
	out[..from_buf].copy_from_slice(&buf[..from_buf]);
	buf.drain(..from_buf);

	let started = Instant::now();
	let mut offset = from_buf;
	while offset < n {
		if cancelled() {
			return Err(Error::ClosedListener("HTTP request".to_string()));
		}
		let remaining = deadline.checked_sub(started.elapsed()).ok_or_else(|| {
			Error::HttpReadTimeout("deadline exceeded while reading HTTP body".into())
		})?;
		if remaining.is_zero() {
			return Err(Error::HttpReadTimeout(
				"deadline exceeded while reading HTTP body".into(),
			));
		}
		stream.set_read_timeout(poll_interval.min(remaining));

		match stream.read(&mut out[offset..]) {
			Ok(0) => {
				return Err(Error::ConnectionError("eof while reading HTTP body".into()));
			}
			Ok(read) => {
				offset = offset
					.checked_add(read)
					.ok_or_else(|| Error::DataOverflow("HTTP body read offset overflow".into()))?;
			}
			Err(e) if is_read_timeout(&e) => continue,
			Err(e) => {
				return Err(Error::ConnectionError(format!(
					"Response reading error, {}",
					e
				)));
			}
		}
	}
	Ok(out)
}

fn is_read_timeout(error: &std::io::Error) -> bool {
	matches!(
		error.kind(),
		std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
	)
}

fn parse_status_line(line: &str) -> Result<u16, Error> {
	// "HTTP/1.1 200 OK"
	let mut parts = line.split_ascii_whitespace();
	let version = parts.next().ok_or_else(|| {
		Error::ConnectionError(format!(
			"malformed status line at response: {}",
			safe_http_text(line)
		))
	})?;
	if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
		return Err(Error::ConnectionError(format!(
			"Invalid protocol version at response: {}",
			safe_http_text(line)
		)));
	}

	let code_text = parts.next().ok_or_else(|| {
		Error::ConnectionError(format!(
			"malformed status line at response: {}",
			safe_http_text(line)
		))
	})?;
	if code_text.len() != 3 || !code_text.bytes().all(|byte| byte.is_ascii_digit()) {
		return Err(Error::ConnectionError(format!(
			"Invalid status code at response: {}",
			safe_http_text(line)
		)));
	}

	let code = code_text.parse::<u16>().map_err(|_| {
		Error::ConnectionError(format!(
			"Invalid status code at response: {}",
			safe_http_text(line)
		))
	})?;

	Ok(code)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn content_length_rejects_invalid_values() {
		let headers = vec![("Content-Length".to_string(), "invalid".to_string())];
		assert!(content_length(&headers).is_err());
	}

	#[test]
	fn content_length_rejects_duplicates() {
		let headers = vec![
			("Content-Length".to_string(), "1".to_string()),
			("content-length".to_string(), "1".to_string()),
		];
		assert!(content_length(&headers).is_err());
	}

	#[test]
	fn content_length_rejects_unsupported_transfer_encoding() {
		let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
		assert!(content_length(&headers).is_err());
	}

	#[test]
	fn content_length_rejects_oversized_body() {
		let headers = vec![(
			"Content-Length".to_string(),
			(MAX_HTTP_BODY_BYTES + 1).to_string(),
		)];
		assert!(matches!(
			content_length(&headers),
			Err(Error::HttpMessageTooLarge(_))
		));
	}

	#[test]
	fn non_success_status_is_preserved_as_structured_error() {
		let error = parse_status_and_headers("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			.unwrap_err();
		assert!(matches!(error, Error::HttpStatus(404)));
	}

	#[test]
	fn status_line_rejects_invalid_version_and_noncanonical_code() {
		for line in [
			"garbage 200 OK",
			"HTTP/2 200 OK",
			"HTTP/1.1 +200 OK",
			"HTTP/1.1 0200 OK",
			"HTTP/1.1 20 OK",
			"HTTP/1.1\u{a0}200 OK",
		] {
			assert!(parse_status_line(line).is_err(), "accepted {line:?}");
		}

		assert_eq!(parse_status_line("HTTP/1.0 200 OK").unwrap(), 200);
		assert_eq!(parse_status_line("HTTP/1.1 201 Created").unwrap(), 201);
	}

	#[test]
	fn malformed_response_diagnostics_are_bounded_and_terminal_safe() {
		let mut hostile = "bad\r\u{1b}]52;c;payload\u{7}\u{202e}".to_owned();
		hostile.push_str(&"x".repeat(crate::client_utils::MAX_HTTP_DIAGNOSTIC_BYTES * 2));

		for error in [
			parse_status_line(&hostile).unwrap_err(),
			parse_status_and_headers(&format!("HTTP/1.1 200 OK\r\n{}\r\n\r\n", hostile))
				.unwrap_err(),
		] {
			let rendered = error.to_string();
			assert!(rendered.contains("\\u000d"));
			assert!(rendered.contains("\\u001b"));
			assert!(rendered.contains("\\u0007"));
			assert!(rendered.contains("\\u202e"));
			assert!(rendered.ends_with("...[truncated]"));
			assert!(!rendered.chars().any(char::is_control));
			assert!(!rendered.contains('\u{202e}'));
		}
	}

	#[test]
	fn incremental_header_scan_finds_split_delimiters() {
		let mut header = b"POST /v2/foreign HTTP/1.1\r\nHost: localhost\r\n".to_vec();
		let previous_len = header.len();
		header.extend_from_slice(b"\r\nbody");
		assert_eq!(
			find_header_end(&header, previous_len.saturating_sub(3)),
			Some(previous_len + 2)
		);
	}

	#[test]
	fn header_scan_uses_the_first_supported_delimiter() {
		let header = b"GET / HTTP/1.1\n\nignored\r\n\r\n";
		assert_eq!(find_header_end(header, 0), Some(16));
	}
}
