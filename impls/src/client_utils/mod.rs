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

mod client;
pub mod json_rpc;

pub use client::Client;

use mwc_wallet_libwallet::types::bounded_escape_for_display;
use mwc_wallet_util::mwc_crates::url::Url;
use std::fmt::Display;

const MAX_NODE_ERROR_BYTES: usize = 2_048;
pub(crate) const MAX_HTTP_DIAGNOSTIC_BYTES: usize = 4_096;

/// Append fixed endpoint segments to a parsed hierarchical URL. Query and
/// fragment components are rejected because appending text after either one
/// does not extend the URL path and can route a request to the wrong handler.
pub(crate) fn url_with_appended_path(
	base_url: &str,
	path_segments: &[&str],
) -> Result<Url, String> {
	let mut url = Url::parse(base_url).map_err(|e| format!("unable to parse URL: {}", e))?;
	if url.query().is_some() {
		return Err("base URL must not contain a query".to_string());
	}
	if url.fragment().is_some() {
		return Err("base URL must not contain a fragment".to_string());
	}

	{
		let mut segments = url
			.path_segments_mut()
			.map_err(|_| "base URL cannot be used as a hierarchical URL".to_string())?;
		segments.pop_if_empty();
		segments.extend(path_segments.iter().copied());
	}

	Ok(url)
}

/// Produce a bounded, single-line representation of node-controlled text for
/// logs and user-facing callback errors.
pub(crate) fn safe_node_text(text: &str) -> String {
	bounded_escape_for_display(text, MAX_NODE_ERROR_BYTES)
}

pub(crate) fn safe_node_error(error: &impl Display) -> String {
	safe_node_text(&error.to_string())
}

/// Produce a bounded, single-line representation of recipient-controlled HTTP
/// status lines, headers, bodies and errors.
pub(crate) fn safe_http_text(text: &str) -> String {
	bounded_escape_for_display(text, MAX_HTTP_DIAGNOSTIC_BYTES)
}

pub(crate) fn safe_http_error(error: &impl Display) -> String {
	safe_http_text(&error.to_string())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn endpoint_segments_are_appended_to_the_parsed_url_path() {
		for (base_url, expected) in [
			("http://wallet.example", "http://wallet.example/v2/foreign"),
			("http://wallet.example/", "http://wallet.example/v2/foreign"),
			(
				"http://wallet.example/proxy/",
				"http://wallet.example/proxy/v2/foreign",
			),
		] {
			let url = url_with_appended_path(base_url, &["v2", "foreign"]).unwrap();
			assert_eq!(url.as_str(), expected);
		}
	}

	#[test]
	fn endpoint_builder_rejects_query_fragment_and_nonhierarchical_bases() {
		for base_url in [
			"http://wallet.example/proxy?tenant=1",
			"http://wallet.example/proxy#foreign",
			"mailto:wallet@example.com",
		] {
			assert!(url_with_appended_path(base_url, &["v2", "foreign"]).is_err());
		}
	}

	#[test]
	fn node_error_text_is_bounded_and_escapes_terminal_controls() {
		let mut hostile = "before\n\u{1b}]52;c;payload\u{7}\u{202e}".to_owned();
		hostile.push_str(&"x".repeat(MAX_NODE_ERROR_BYTES * 2));
		let safe = safe_node_text(&hostile);

		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
	}

	#[test]
	fn http_error_text_is_bounded_and_terminal_safe() {
		let mut hostile = "before\r\n\u{1b}]52;c;payload\u{7}\u{2066}".to_owned();
		hostile.push_str(&"x".repeat(MAX_HTTP_DIAGNOSTIC_BYTES * 2));
		let safe = safe_http_text(&hostile);

		assert!(safe.contains("\\u000d\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u2066"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{2066}'));
	}
}
