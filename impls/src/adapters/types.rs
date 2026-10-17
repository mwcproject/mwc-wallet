// Copyright 2026 The Mwc Developers
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

use crate::error::Error;
use mwc_wallet_libwallet::Slate;
use mwc_wallet_libwallet::proof::tx_proof::TxProof;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::Message;
use mwc_wallet_libwallet::types::{bounded_escape_for_display, escape_for_display};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::url::Url;
use mwc_wallet_util::mwc_crates::uuid;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender; //only for the Address::parse

use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_util::mwc_crates::regex::Regex;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use std::fmt::{self, Debug, Display};

const DEFAULT_MWCMQS_DOMAIN: &str = "mqs.mwc.mw";
pub const DEFAULT_MWCMQS_PORT: u16 = 443;

const ADDRESS_REGEX: &str = r"^((?P<address_type>mwcmq|mwcmqs|https|http)://).+$";
const MAX_ADDRESS_ERROR_BYTES: usize = 4_096;

pub enum CloseReason {
	Normal,
	Abnormal(Error),
}

/// Outcome of one MQS message-processing attempt.
///
/// `Processed` permits an immediate broker acknowledgement. `Rejected` records
/// a failed attempt, but does not by itself acknowledge the message: the MWCMQS
/// broker applies the same bounded retry policy to `Rejected` and `Err` so the
/// transport does not depend on an incomplete error-variant classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MqsMessageDisposition {
	Processed,
	Rejected,
}

/// Details for an MQS message-processing failure.
///
/// This remains a distinct type rather than a `String` so callers preserve the
/// failure reason across the subscription boundary. It is not an unbounded
/// retry classification: the broker gives both this error and `Rejected` the
/// same finite retry budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MqsRetryableError {
	message: String,
}

impl MqsRetryableError {
	pub fn new(message: impl Into<String>) -> Self {
		Self {
			message: message.into(),
		}
	}
}

impl Display for MqsRetryableError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for MqsRetryableError {}

pub type MqsMessageResult = Result<MqsMessageDisposition, MqsRetryableError>;

static NEXT_MQS_RESPONSE_WAITER_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Identity of one exact MQS response-waiter registration.
///
/// Slate UUIDs are reusable across retries, so cleanup must carry this token
/// and may remove only the registration that originally issued it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MqsResponseWaiterToken(u64);

impl MqsResponseWaiterToken {
	pub fn try_new() -> Result<Self, Error> {
		NEXT_MQS_RESPONSE_WAITER_TOKEN
			.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				current.checked_add(1)
			})
			.map(Self)
			.map_err(|_| {
				Error::MqsGenericError("MQS response waiter token space is exhausted".to_string())
			})
	}
}

pub trait Publisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address, secp: &Secp256k1) -> Result<(), Error>;
	fn encrypt_slate(
		&self,
		slate: &Slate,
		to: &dyn Address,
		secp: &Secp256k1,
	) -> Result<String, Error>;
	fn decrypt_slate(
		&self,
		from: String,
		mapmessage: String,
		signature: String,
		source_address: &ProvableAddress,
		secp: &Secp256k1,
	) -> Result<String, Error>;

	#[cfg(feature = "swaps")]
	fn post_take(&self, message: &Message, to: &dyn Address, secp: &Secp256k1)
	-> Result<(), Error>;
	// Address of this publisher (from address)
	fn get_publisher_address(&self) -> Result<Box<dyn Address>, Error>;
}

pub trait Subscriber {
	fn start(&mut self) -> Result<(), Error>;
	fn stop(&mut self, call_reset_mwcmqs_brocker: bool) -> Result<(), Error>;
	fn is_running(&self) -> bool;

	fn set_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		original_slate: Slate,
		expected_peer_public_key: String,
		expected_response: SlatePurpose,
		slate_send_channel: Sender<Slate>,
	) -> Result<MqsResponseWaiterToken, Error>;
	fn reset_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		waiter_token: &MqsResponseWaiterToken,
	);
}

pub trait SubscriptionHandler: Send + Sync {
	fn on_open(&self);
	fn on_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		tx_proof: TxProof,
	) -> MqsMessageResult;
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
	// Process a swap message and return the message to respond. `from` is the
	// sender identity authenticated while decrypting the MWCMQS envelope.
	// Ok(None) acknowledges the message without a response (deterministic
	// rejection or nothing to send); an Err leaves the message unacknowledged
	// so the broker redelivers it under its bounded retry budget. Implementors
	// must map only transient local failures to Err.
	#[cfg(feature = "swaps")]
	fn on_swap_message(
		&self,
		from: &dyn Address,
		swap: Message,
	) -> Result<Option<Message>, MqsRetryableError>;

	fn set_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		original_slate: Slate,
		expected_peer_public_key: String,
		expected_response: SlatePurpose,
		slate_send_channel: Sender<Slate>,
	) -> Result<MqsResponseWaiterToken, Error>;
	fn reset_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		waiter_token: &MqsResponseWaiterToken,
	);
}

//The following is support mqs usage in mwc713

pub trait Address: Debug + Display {
	fn from_str(secp: &Secp256k1, context_id: u32, s: &str) -> Result<Self, Error>
	where
		Self: Sized;
	fn address_type(&self) -> AddressType;
	fn get_stripped(&self) -> String;
	fn get_full_name(&self) -> String;
	/// Cryptographic public key identifying this transport peer, when the
	/// address type has one. Callers must only treat this as authenticated
	/// after the transport has verified the corresponding message.
	fn get_public_key(&self) -> Option<&str> {
		None
	}
}

#[derive(Debug, PartialEq)]
pub enum AddressType {
	MWCMQS,
	Https,
}

#[derive(Clone, Debug)]
pub struct MWCMQSAddress {
	pub address: ProvableAddress,
	pub domain: String,
	pub port: u16,
}

const MWCMQ_ADDRESS_REGEX: &str = r"^(mwcmqs://)?(?P<public_key>[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{52})(@(?P<domain>[a-zA-Z0-9\.]+)(:(?P<port>[0-9]*))?)?$";

impl MWCMQSAddress {
	pub fn new(address: ProvableAddress, domain: Option<String>, port: Option<u16>) -> Self {
		Self {
			address,
			domain: domain.unwrap_or(DEFAULT_MWCMQS_DOMAIN.to_string()),
			port: port.unwrap_or(DEFAULT_MWCMQS_PORT),
		}
	}
}

impl Display for MWCMQSAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "mwcmqs://{}", self.address.public_key)?;
		if self.domain != DEFAULT_MWCMQS_DOMAIN || self.port != DEFAULT_MWCMQS_PORT {
			write!(f, "@{}", self.domain)?;
			if self.port != DEFAULT_MWCMQS_PORT {
				write!(f, ":{}", self.port)?;
			}
		}
		Ok(())
	}
}

impl Address for MWCMQSAddress {
	/// Extract the address plus additional data
	fn from_str(secp: &Secp256k1, context_id: u32, s: &str) -> Result<Self, Error> {
		let re = Regex::new(MWCMQ_ADDRESS_REGEX).map_err(|e| {
			Error::MqsGenericError(format!("Unable to construct MQS address parser: {}", e))
		})?;
		let captures = re.captures(s).ok_or(Error::MqsGenericError(format!(
			"Unable to parse MWC address {}",
			escape_for_display(s)
		)))?;

		let public_key = captures
			.name("public_key")
			.ok_or(Error::MqsGenericError(format!(
				"Unable to parse MWC MQS address {}, public key part is not found",
				escape_for_display(s)
			)))?
			.as_str()
			.to_string();

		let domain = captures.name("domain").map(|m| m.as_str().to_string());
		let port = match captures.name("port") {
			Some(m) => Some(u16::from_str_radix(m.as_str(), 10).map_err(|_| {
				Error::MqsGenericError(format!("Unable to parse MWC MQS port value"))
			})?),
			None => None,
		};

		Ok(MWCMQSAddress::new(
			ProvableAddress::from_str(secp, context_id, &public_key).map_err(|e| {
				Error::MqsGenericError(format!(
					"Invalid MQS address {}, {}",
					escape_for_display(s),
					e
				))
			})?,
			domain,
			port,
		))
	}

	fn get_stripped(&self) -> String {
		format!("{}", self)[9..].to_string()
	}

	fn get_full_name(&self) -> String {
		"mwcmqs://".to_string() + &self.get_stripped()
	}

	fn get_public_key(&self) -> Option<&str> {
		Some(&self.address.public_key)
	}

	fn address_type(&self) -> AddressType {
		AddressType::MWCMQS
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct HttpsAddress {
	pub uri: String,
}

impl Address for HttpsAddress {
	fn from_str(_secp: &Secp256k1, _context_id: u32, s: &str) -> Result<Self, Error> {
		let syntax_violation = std::cell::Cell::new(false);
		let record_syntax_violation = |_| syntax_violation.set(true);
		let url = Url::options()
			.syntax_violation_callback(Some(&record_syntax_violation))
			.parse(s)
			.map_err(|_| {
				Error::HttpsAddressParsingError(bounded_escape_for_display(
					s,
					MAX_ADDRESS_ERROR_BYTES,
				))
			})?;

		if syntax_violation.get()
			|| !matches!(url.scheme(), "http" | "https")
			|| url.host_str().is_none()
			|| !url.username().is_empty()
			|| url.password().is_some()
		{
			return Err(Error::HttpsAddressParsingError(bounded_escape_for_display(
				s,
				MAX_ADDRESS_ERROR_BYTES,
			)));
		}

		Ok(Self { uri: url.into() })
	}

	fn address_type(&self) -> AddressType {
		AddressType::Https
	}

	fn get_stripped(&self) -> String {
		self.uri.clone()
	}

	fn get_full_name(&self) -> String {
		self.get_stripped()
	}
}

impl Display for HttpsAddress {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.uri)?;
		Ok(())
	}
}

impl dyn Address {
	pub fn parse(
		secp: &Secp256k1,
		context_id: u32,
		address: &str,
	) -> Result<Box<dyn Address>, Error> {
		let re = Regex::new(ADDRESS_REGEX).map_err(|e| {
			Error::AddressGenericError(format!("Unable to construct address parser, {}", e))
		})?;
		match re.captures(address) {
			None => Ok(Box::new(MWCMQSAddress::from_str(
				secp, context_id, address,
			)?)),
			Some(captures) => {
				let address_type = captures
					.name("address_type")
					.ok_or_else(|| {
						Error::AddressGenericError("Address type capture is missing".to_string())
					})?
					.as_str()
					.to_string();
				let address: Box<dyn Address> = match address_type.as_ref() {
					"mwcmqs" => Box::new(MWCMQSAddress::from_str(secp, context_id, address)?),
					"https" => Box::new(HttpsAddress::from_str(secp, context_id, address)?),
					"http" => Box::new(HttpsAddress::from_str(secp, context_id, address)?),
					x => Err(Error::UnknownAddressType(x.to_string()))?,
				};
				Ok(address)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn https_address_accepts_http_and_https_and_stores_the_canonical_url() {
		let secp = Secp256k1::new().unwrap();

		let https = HttpsAddress::from_str(&secp, 0, "HTTPS://Wallet.Example").unwrap();
		assert_eq!(https.uri, "https://wallet.example/");

		let http = HttpsAddress::from_str(&secp, 0, "http://wallet.example/path").unwrap();
		assert_eq!(http.uri, "http://wallet.example/path");
	}

	#[test]
	fn https_address_rejects_unsupported_or_ambiguous_urls() {
		let secp = Secp256k1::new().unwrap();

		for invalid in [
			"mailto:wallet@example.com",
			"file:///etc/passwd",
			"https://user:password@wallet.example",
			"https://wallet.example/pa\tth",
			"https:////wallet.example",
			"https://wallet.example/%1",
		] {
			assert!(
				HttpsAddress::from_str(&secp, 0, invalid).is_err(),
				"accepted invalid HTTP address {invalid:?}"
			);
		}
	}

	#[test]
	fn https_address_parse_errors_escape_and_bound_untrusted_input() {
		let secp = Secp256k1::new().unwrap();
		let hostile = format!(
			"not-a-url\u{1b}\n{}",
			"x".repeat(MAX_ADDRESS_ERROR_BYTES * 2)
		);

		let error = HttpsAddress::from_str(&secp, 0, &hostile)
			.unwrap_err()
			.to_string();
		assert!(error.contains("\\u001b"));
		assert!(error.contains("\\u000a"));
		assert!(error.contains("...[truncated]"));
		assert!(!error.contains('\u{1b}'));
		assert!(!error.contains('\n'));
	}
}
