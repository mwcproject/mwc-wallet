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

//! Tor Configuration + Onion (Hidden) Service operations
use crate::Error;
use crate::client_utils::safe_http_text;
use mwc_wallet_util::mwc_crates::url::Url;
use mwc_wallet_util::mwc_util::OnionV3Address;
use std::convert::TryFrom;

const ONION_V3_IDENTITY_LEN: usize = 56;

pub(crate) enum TorAddressClassification {
	Valid(String),
	InvalidOnion(Error),
	NotOnion,
}

/// Classify a destination without collapsing malformed Onion addresses and
/// ordinary HTTP addresses into the same error case.
pub(crate) fn classify_tor_address(input: &str) -> TorAddressClassification {
	match complete_tor_address(input) {
		Ok(destination) => TorAddressClassification::Valid(destination),
		Err(error) if looks_like_onion_host(input) => TorAddressClassification::InvalidOnion(error),
		Err(_) => TorAddressClassification::NotOnion,
	}
}

fn looks_like_onion_host(input: &str) -> bool {
	let input = input.trim();
	let parsed = Url::parse(input).or_else(|_| Url::parse(&format!("http://{}", input)));
	let Ok(url) = parsed else {
		return false;
	};

	// Deliberately recognize only unambiguous Onion forms: an `.onion` suffix,
	// an exact-length Base32 Onion v3 identity, a legacy hexadecimal identity, or
	// extra Base32 data appended to a valid Onion identity. Hexadecimal identities
	// and overlong identities are rejected by `parse_tor_address`; recognizing them
	// here prevents malformed Onion destinations from falling through to direct
	// DNS/HTTP. A near-length bare hostname (for example, 55 Base32 characters) is
	// also a syntactically valid DNS name, so treating it as a presumed mistyped
	// Onion address would reject legitimate HTTP destinations based on guessed
	// user intent and still could not cover every possible typo. Callers requiring
	// fail-closed Tor validation must select the `tor` method or supply `.onion`.
	url.host_str()
		.map(|host| host.trim_end_matches('.'))
		.is_some_and(|host| {
			let bytes = host.as_bytes();
			let looks_like_base32_identity = is_base32_onion_identity(host);
			let looks_like_hex_identity =
				bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit);

			host.eq_ignore_ascii_case("onion")
				|| host
					.get(host.len().saturating_sub(".onion".len())..)
					.is_some_and(|suffix| suffix.eq_ignore_ascii_case(".onion"))
				|| looks_like_base32_identity
				|| looks_like_hex_identity
				|| starts_with_valid_onion_identity(host)
		})
}

fn is_base32_onion_identity(value: &str) -> bool {
	let bytes = value.as_bytes();
	bytes.len() == ONION_V3_IDENTITY_LEN
		&& bytes
			.iter()
			.all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
}

fn starts_with_valid_onion_identity(host: &str) -> bool {
	let bytes = host.as_bytes();
	if bytes.len() <= ONION_V3_IDENTITY_LEN
		|| !bytes
			.iter()
			.all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
	{
		return false;
	}

	let Some(identity) = host.get(..ONION_V3_IDENTITY_LEN) else {
		return false;
	};
	let onion_host = format!("{}.onion", identity);
	OnionV3Address::try_from(onion_host.as_str())
		.map(|address| address.to_ov3_str().eq_ignore_ascii_case(identity))
		.unwrap_or(false)
}

/// Validate if it is a tor address
pub fn is_tor_address(input: &str) -> Result<(), Error> {
	parse_tor_address(input).map(|_| ())
}

/// Make sure that this address is a completer tor address
pub fn complete_tor_address(input: &str) -> Result<String, Error> {
	let (scheme, address) = parse_tor_address(input)?;
	Ok(format!("{}://{}.onion", scheme, address.to_ov3_str()))
}

fn parse_tor_address(input: &str) -> Result<(&'static str, OnionV3Address), Error> {
	let trimmed = input.trim();
	let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
	let (scheme, address) = if trimmed
		.get(..8)
		.is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
	{
		("https", &trimmed[8..])
	} else if trimmed
		.get(..7)
		.is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
	{
		("http", &trimmed[7..])
	} else {
		("http", trimmed)
	};

	// Only an Onion identity belongs here. Accepting other URL components would
	// validate one string while returning or connecting to a different endpoint.
	if address.is_empty()
		|| !address
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
	{
		return Err(Error::NotOnion(format!(
			"{}, Tor address must not contain URL components other than the scheme and Onion host",
			safe_http_text(input)
		)));
	}

	let identity = address
		.len()
		.checked_sub(".onion".len())
		.and_then(|suffix_start| {
			address
				.get(suffix_start..)
				.filter(|suffix| suffix.eq_ignore_ascii_case(".onion"))
				.and_then(|_| address.get(..suffix_start))
		})
		.unwrap_or(address);

	// The shared OnionV3Address parser also accepts a 64-character raw public
	// key and can ignore trailing Base32 data. Wallet destinations intentionally
	// support only the canonical 56-character Onion v3 identity.
	if !is_base32_onion_identity(identity) {
		return Err(Error::NotOnion(format!(
			"{}, Tor address must be a 56-character Base32 Onion v3 identity, optionally followed by .onion",
			safe_http_text(input)
		)));
	}

	// Include the suffix to prevent an all-hexadecimal Base32 identity from being
	// interpreted as the shared parser's legacy raw-key format.
	let onion_host = format!("{}.onion", identity);
	let onion_address = OnionV3Address::try_from(onion_host.as_str())
		.map_err(|e| Error::NotOnion(format!("{}, {}", safe_http_text(input), e)))?;
	if !onion_address.to_ov3_str().eq_ignore_ascii_case(identity) {
		return Err(Error::NotOnion(format!(
			"{}, Tor address is not canonical",
			safe_http_text(input)
		)));
	}

	Ok((scheme, onion_address))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_is_tor_address() -> Result<(), Error> {
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok());
		assert!(is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_ok());
		assert!(
			is_tor_address("http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_ok()
		);
		assert!(
			is_tor_address(
				"https://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
			)
			.is_ok()
		);
		assert!(
			is_tor_address("http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid")
				.is_ok()
		);
		assert!(
			is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_ok()
		);
		// address too short
		assert!(
			is_tor_address("http://kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_err()
		);
		assert!(is_tor_address("kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_err());
		Ok(())
	}

	#[test]
	fn test_complete_tor_address() -> Result<(), Error> {
		let onion = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let raw_key = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address(onion).unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion")
				.unwrap()
		);
		assert!(
			complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi")
				.is_err()
		);
		assert_eq!(
			format!("https://{}.onion", onion),
			complete_tor_address(&format!("HTTPS://{}.ONION/", onion)).unwrap()
		);
		assert!(complete_tor_address(raw_key).is_err());
		assert!(is_tor_address(raw_key).is_err());
		for invalid in [
			format!("http://{}.onion/CaseSensitive", onion),
			format!("http://{}.onion?query", onion),
			format!("http://{}.onion#fragment", onion),
			format!("http://user@{}.onion", onion),
			format!("http://{}.onion:80", onion),
			format!("http://{}aaaaaaaa", onion),
			format!("http://{}aaaaaaaa.onion", onion),
		] {
			assert!(complete_tor_address(&invalid).is_err(), "{invalid}");
			assert!(is_tor_address(&invalid).is_err(), "{invalid}");
		}
		Ok(())
	}

	#[test]
	fn tor_address_errors_escape_untrusted_input() {
		let error = is_tor_address("invalid\n\u{1b}]52;c;payload\u{7}")
			.unwrap_err()
			.to_string();

		assert!(error.contains("\\u000a"));
		assert!(error.contains("\\u001b"));
		assert!(error.contains("\\u0007"));
		assert!(!error.chars().any(char::is_control));
	}

	#[test]
	fn tor_address_classification_distinguishes_invalid_onion_from_http() {
		let onion = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let invalid_onion = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyia";
		let raw_key = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";

		assert!(matches!(
			classify_tor_address(onion),
			TorAddressClassification::Valid(destination)
				if destination == format!("http://{}.onion", onion)
		));
		for invalid in [
			format!("http://{}.onion", invalid_onion),
			format!("http://{}/RejectedPath", invalid_onion),
			format!("http://{}.onion/RejectedPath", onion),
			format!("http://{}aaaaaaaa", onion),
			format!("http://{}aaaaaaaa.onion", onion),
			raw_key.to_string(),
		] {
			assert!(matches!(
				classify_tor_address(&invalid),
				TorAddressClassification::InvalidOnion(_)
			));
		}
		for http in [
			"http://wallet.example/path.onion".to_string(),
			"http://wallet.example".to_string(),
			format!("http://{}", &onion[..ONION_V3_IDENTITY_LEN - 1]),
		] {
			assert!(matches!(
				classify_tor_address(&http),
				TorAddressClassification::NotOnion
			));
		}
	}
}
