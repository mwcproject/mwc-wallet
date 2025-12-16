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
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_util::to_base64;
use serde::Serialize;
use std::io::{Read, Write};
use url::Url;

/// response with error AND close connection request flag
pub fn post_auth<OUT>(
	context_id: u32,
	url: Url,
	apisecret: &Option<String>,
	stream: &mut TcpDataStream,
	keep_alive: bool,
	body: OUT,
) -> Result<(String, bool), Error>
where
	OUT: Serialize,
{
	let auth_header = match apisecret {
		Some(api_secret) => {
			let basic_auth_key = if global::is_mainnet(context_id) {
				"mwcmain".to_string()
			} else if global::is_floonet(context_id) {
				"mwcfloo".to_string()
			} else {
				"mwc".to_string()
			};
			let auth_key = format!("{}:{}", basic_auth_key, api_secret);
			let base64_key = to_base64(&auth_key);
			Some(format!("Authorization: Basic {}", base64_key))
		}
		None => None,
	};

	post_impl(url, auth_header, stream, keep_alive, body)
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
	post_impl(url, None, stream, keep_alive, body)
}

fn post_impl<OUT>(
	url: Url,
	auth_header: Option<String>,
	stream: &mut TcpDataStream,
	keep_alive: bool,
	body: OUT,
) -> Result<(String, bool), Error>
where
	OUT: Serialize,
{
	let path = url.path();
	let host = url.host_str().ok_or(Error::ConnectionError(format!(
		"Unable to extract host from {}",
		url
	)))?;
	let body = serde_json::to_string(&body)
		.map_err(|e| Error::ConnectionError(format!("Could not serialize data to JSON, {}", e)))?;

	let connection_header = if keep_alive {
		"Connection: keep-alive"
	} else {
		"Connection: close"
	};

	let req = format!(
		"POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
			 {}\
             Content-Length: {}\r\n\
             {}\r\n\
             \r\n{}",
		path,
		host,
		auth_header.map(|h| h + "\r\n").unwrap_or("".into()),
		body.len(),
		connection_header,
		body
	);

	stream
		.write_all(req.as_bytes())
		.map_err(|e| Error::ConnectionError(format!("Unable to send the request, {}", e)))?;
	stream
		.flush()
		.map_err(|e| Error::ConnectionError(format!("Unable to send the request, {}", e)))?;

	// Reading the response:
	let mut buf: Vec<u8> = Vec::new();
	let header_text = parse_utils::read_headers(stream, &mut buf)?;
	let headers = parse_utils::parse_status_and_headers(&header_text)?;

	// 3. ---------- read exact body ----------
	let body_len = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.parse::<usize>().ok())
		.unwrap_or(0);

	let body = parse_utils::read_exact_bytes(stream, &mut buf, body_len)
		.map_err(|e| Error::ConnectionError(format!("Unable to read the response, {}", e)))?;

	// 4. ---------- keep-alive check ----------
	let close = !keep_alive
		|| headers
			.iter()
			.any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
	if close {
		// consume rest of stream so drop() does not panic on unread data
		let _ = stream.read_to_end(&mut Vec::new());
	}

	let body_str = String::from_utf8(body)
		.map_err(|e| Error::ConnectionError(format!("Response is not a string, {}", e)))?;

	Ok((body_str, close))
}
