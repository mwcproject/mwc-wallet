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

mod file;
pub mod http;

mod mwcmq;
mod types;

pub use self::file::{PathToSlateGetter, PathToSlatePutter};
pub use self::http::HttpDataSender;
use std::path::Path;
use std::sync::Arc;

use crate::client_utils::{safe_http_error, safe_http_text};
use crate::error::Error;
use crate::tor::config::{TorAddressClassification, classify_tor_address, complete_tor_address};
use mwc_wallet_config::WalletConfig;
use mwc_wallet_libwallet::Slate;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::Message;
use mwc_wallet_libwallet::{SlateVersion, Slatepacker};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::ZeroingString;
pub use mwcmq::{
	MWCMQPublisher, MWCMQSubscriber, MqsLifecycleGuard, MqsListenerWait, MqsTermination,
	MwcMqsChannel, get_mwcmqs_brocker, get_mwcmqs_listener_termination, init_mwcmqs_access_data,
	lock_mwcmqs_lifecycle, reset_mwcmqs_brocker, reset_mwcmqs_brocker_if_current,
	stop_mwcmqs_brocker_if_current,
};
pub use types::{
	Address, AddressType, CloseReason, HttpsAddress, MWCMQSAddress, MqsMessageDisposition,
	MqsMessageResult, MqsResponseWaiterToken, MqsRetryableError, Publisher, Subscriber,
	SubscriptionHandler,
};

/// Sends transactions to a corresponding SlateReceiver
pub trait SlateSender {
	/// Check other wallet version and address. Return None if it is impossible to make such a request
	/// and sending will use least possible features.
	fn check_other_wallet_version(
		&self,
		destination_address: &String,
		show_error: bool,
	) -> Result<Option<(SlateVersion, Option<String>)>, Error>;

	/// Send a transaction slate to another listening wallet and return result
	/// TODO: Probably need a slate wrapper type
	fn send_tx(
		&self,
		send_tx: bool, // false if invoice, true if send operation
		slate: &Slate,
		slate_content: SlatePurpose,
		slatepack_secret: &ed25519_dalek::SigningKey,
		recipient: Option<ed25519_dalek::VerifyingKey>,
		other_wallet_version: Option<(SlateVersion, Option<String>)>,
		secp: &Secp256k1,
	) -> Result<Slate, Error>;
}

pub trait SlateReceiver {
	/// Start a listener, passing received messages to the wallet api directly
	/// Takes a wallet config for now to avoid needing all sorts of awkward
	/// type parameters on this trait
	fn listen(
		&self,
		config: WalletConfig,
		passphrase: ZeroingString,
		account: &str,
		node_api_secret: Option<String>,
	) -> Result<(), Error>;
}

/// Posts slates to be read later by a corresponding getter
pub trait SlatePutter {
	/// Send a transaction synchronously. Return content that was stored/sent
	fn put_tx(
		&self,
		slate: &Slate,
		slatepack_secret: Option<&ed25519_dalek::SigningKey>,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<String, Error>;
}

/// SlateGetter, get_tx response
pub enum SlateGetData {
	/// Plain slate, V2 or V3
	PlainSlate(Slate),
	/// Encoded Slatepack
	Slatepack(Slatepacker),
}

/// Checks for a transaction from a corresponding SlatePutter, returns the transaction if it exists
pub trait SlateGetter {
	/// Receive a transaction sync. Just read it from wherever and return the slate.
	fn get_tx(
		&self,
		slatepack_secret: Option<&ed25519_dalek::SigningKey>,
		secp: &Secp256k1,
	) -> Result<SlateGetData, Error>;
}

/// Swap Message Sender
#[cfg(feature = "swaps")]
pub trait SwapMessageSender {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and procesed)
	fn send_swap_message(&self, swap_message: &Message, secp: &Secp256k1) -> Result<bool, Error>;
}

/// Swap Message Sender
pub trait MarketplaceMessageSender {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and procesed)
	fn send_swap_marketplace_message(&self, json_str: &String) -> Result<String, Error>;
}

impl SlateGetData {
	/// Convert to the slate
	/// Return: Slate, sender and recipient
	pub fn to_slate(
		self,
	) -> Result<
		(
			Slate,
			Option<ed25519_dalek::VerifyingKey>,
			Option<ed25519_dalek::VerifyingKey>,
			SlatePurpose,
			bool,
		),
		Error,
	> {
		let res = match self {
			SlateGetData::PlainSlate(slate) => (slate, None, None, SlatePurpose::FullSlate, false),
			SlateGetData::Slatepack(slatepacker) => {
				let sender = slatepacker.get_sender();
				let recipient = slatepacker.get_recipient();
				let content = slatepacker.get_content();
				(
					slatepacker.to_result_slate(),
					sender,
					recipient,
					content,
					true,
				)
			}
		};
		Ok(res)
	}
}

/// select a SlateSender based on method and dest fields from, e.g., SendArgs
pub fn create_sender(
	context_id: u32,
	method: &str,
	dest: &str,
	apisecret: &Option<Arc<Zeroizing<String>>>,
	tor_config: Option<&TorConfig>,
	base_dir: &Path,
) -> Result<Box<dyn SlateSender>, Error> {
	let invalid = |e: Error| {
		Error::WalletComms(format!(
			"Invalid wallet comm type and destination. method: {}, dest: {}, error: {}",
			safe_http_text(method),
			safe_http_text(dest),
			safe_http_error(&e)
		))
	};

	let auto_tor_destination = if method == "http" {
		// A valid Onion destination is automatically routed through Tor. If the
		// host is Onion-like but validation fails, return that error instead of
		// leaking the destination to DNS through the direct HTTP sender.
		match classify_tor_address(dest) {
			TorAddressClassification::Valid(destination) => Some(destination),
			TorAddressClassification::InvalidOnion(error) => return Err(invalid(error)),
			TorAddressClassification::NotOnion => None,
		}
	} else {
		None
	};
	let method = if auto_tor_destination.is_some() {
		"tor"
	} else {
		method
	};

	Ok(match method {
		"http" => Box::new(
			HttpDataSender::plain_http(context_id, &dest, apisecret.clone())
				.map_err(|e| invalid(e))?,
		),
		"tor" => match tor_config {
			None => {
				return Err(Error::WalletComms("Tor Configuration required".to_string()));
			}
			Some(tc) => {
				let dest = match auto_tor_destination {
					Some(destination) => destination,
					None => validate_tor_address(dest)?,
				};
				Box::new(HttpDataSender::tor_connection(
					context_id,
					&dest,
					apisecret.clone(),
					tc,
					base_dir,
				)?)
			}
		},
		"mwcmqs" => Box::new(MwcMqsChannel::new(context_id, dest.to_string())),
		_ => {
			return Err(handle_unsupported_types(method));
		}
	})
}

/// create a Swap Message Sender
/// apisecret is shared by reference counted pointer, so no plaintext copies of the
/// secret are made for each sender; it is zeroized when the last sender is dropped.
#[cfg(feature = "swaps")]
pub fn create_swap_message_sender(
	context_id: u32,
	method: &str,
	dest: &str,
	apisecret: &Option<Arc<Zeroizing<String>>>,
	tor_config: &TorConfig,
	base_dir: &Path,
) -> Result<Box<dyn SwapMessageSender>, Error> {
	Ok(match method {
		"tor" => {
			let dest = validate_tor_address(dest)?;
			Box::new(HttpDataSender::tor_connection(
				context_id,
				&dest,
				apisecret.clone(),
				tor_config,
				base_dir,
			)?)
		}
		"mwcmqs" => Box::new(MwcMqsChannel::new(context_id, dest.to_string())),
		_ => {
			return Err(handle_unsupported_types(method));
		}
	})
}

/// Validate and complete TOR address.
pub fn validate_tor_address(dest: &str) -> Result<String, Error> {
	// will test if this is a tor address and fill out
	// the http://[].onion if missing
	let dest = complete_tor_address(dest)?;
	Ok(dest)
}

/// create sender not-supported types
pub fn handle_unsupported_types(method: &str) -> Error {
	match method {
		"file" => {
			return Error::WalletComms(
				"File based transactions must be performed asynchronously.".to_string(),
			);
		}
		"self" => {
			return Error::WalletComms("No sender implementation for \"self\".".to_string());
		}
		_ => {
			return Error::WalletComms(format!(
				"Wallet communication method \"{}\" does not exist.",
				safe_http_text(method)
			));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn invalid_onion_http_destination_is_not_downgraded() {
		let onion = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let invalid_destinations = [
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyia.onion".to_string(),
			"d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb".to_string(),
			format!("http://{}aaaaaaaa", onion),
			format!("http://{}aaaaaaaa.onion", onion),
		];

		for invalid_destination in invalid_destinations {
			assert!(validate_tor_address(&invalid_destination).is_err());
			let result =
				create_sender(0, "http", &invalid_destination, &None, None, Path::new("."));
			assert!(
				matches!(result, Err(Error::WalletComms(_))),
				"{invalid_destination}"
			);
		}
	}

	fn assert_terminal_safe(message: &str) {
		assert!(message.contains("\\u000a"));
		assert!(message.contains("\\u001b"));
		assert!(message.contains("\\u0007"));
		assert!(message.contains("\\u202e"));
		assert!(!message.chars().any(char::is_control));
		assert!(!message.contains('\u{202e}'));
	}

	#[test]
	fn invalid_sender_error_escapes_destination_controls() {
		let onion = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let invalid_onion = format!(
			"http://{}.onion/rejected\n\u{1b}]52;c;payload\u{7}\u{202e}",
			onion
		);
		let error = create_sender(0, "http", &invalid_onion, &None, None, Path::new("."))
			.err()
			.expect("invalid Onion destination must be rejected")
			.to_string();

		assert_terminal_safe(&error);
	}

	#[test]
	fn unsupported_method_error_escapes_and_bounds_input() {
		let method = format!(
			"unsupported\n\u{1b}]52;c;payload\u{7}\u{202e}{}",
			"x".repeat(crate::client_utils::MAX_HTTP_DIAGNOSTIC_BYTES * 2)
		);
		let error = handle_unsupported_types(&method).to_string();

		assert_terminal_safe(&error);
		assert!(error.contains("...[truncated]"));
		assert!(error.len() < crate::client_utils::MAX_HTTP_DIAGNOSTIC_BYTES + 128);
	}
}
