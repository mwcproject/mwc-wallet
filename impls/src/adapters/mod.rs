// Copyright 2021 The Grin Developers
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
pub mod libp2p_messaging;
mod mwcmq;
mod types;

pub use self::file::{PathToSlateGetter, PathToSlatePutter};
pub use self::http::HttpDataSender;

use crate::config::{TorConfig, WalletConfig};
use crate::error::{Error, ErrorKind};
use crate::libwallet::swap::message::Message;
use crate::libwallet::Slate;
use crate::tor::config::complete_tor_address;
use crate::util::ZeroingString;
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use grin_wallet_libwallet::slatepack::SlatePurpose;
use grin_wallet_libwallet::{SlateVersion, Slatepacker};
use grin_wallet_util::grin_util::secp::Secp256k1;
pub use mwcmq::{
	get_mwcmqs_brocker, init_mwcmqs_access_data, MWCMQPublisher, MWCMQSubscriber, MwcMqsChannel,
};
pub use types::{
	Address, AddressType, CloseReason, HttpsAddress, MWCMQSAddress, Publisher, Subscriber,
	SubscriptionHandler,
};

/// Sends transactions to a corresponding SlateReceiver
pub trait SlateSender {
	/// Check other wallet version and address. Return None if it is impossible to make such a request
	/// and sending will use least possible features.
	fn check_other_wallet_version(
		&self,
		destination_address: &String,
	) -> Result<Option<(SlateVersion, Option<String>)>, Error>;

	/// Send a transaction slate to another listening wallet and return result
	/// TODO: Probably need a slate wrapper type
	fn send_tx(
		&self,
		slate: &Slate,
		slate_content: SlatePurpose,
		slatepack_secret: &DalekSecretKey,
		recipient: Option<DalekPublicKey>,
		other_wallet_version: Option<(SlateVersion, Option<String>)>,
		height: u64,
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
		slatepack_secret: Option<&DalekSecretKey>,
		use_test_rng: bool,
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
		slatepack_secret: Option<&DalekSecretKey>,
		height: u64,
		secp: &Secp256k1,
	) -> Result<SlateGetData, Error>;
}

/// Swap Message Sender
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
	/// Check if the slate is encrypted
	pub fn is_encrypted(&self) -> bool {
		match &self {
			SlateGetData::PlainSlate(_) => false,
			SlateGetData::Slatepack(_) => true,
		}
	}

	/// Convert to the slate
	/// Return: Slate, sender and recipient
	pub fn to_slate(
		self,
	) -> Result<
		(
			Slate,
			Option<DalekPublicKey>,
			Option<DalekPublicKey>,
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
	method: &str,
	dest: &str,
	apisecret: &Option<String>,
	tor_config: Option<TorConfig>,
) -> Result<Box<dyn SlateSender>, Error> {
	let invalid = |e| {
		ErrorKind::WalletComms(format!(
			"Invalid wallet comm type and destination. method: {}, dest: {}, error: {}",
			method, dest, e
		))
	};

	let method = if method == "http" {
		// Url might be onion. In this case we can update method to tor
		if validate_tor_address(dest).is_ok() {
			"tor"
		} else {
			method
		}
	} else {
		method
	};

	Ok(match method {
		"http" => Box::new(
			HttpDataSender::new(&dest, apisecret.clone(), None, false, None)
				.map_err(|e| invalid(e))?,
		),
		"tor" => match tor_config {
			None => {
				return Err(
					ErrorKind::WalletComms("Tor Configuration required".to_string()).into(),
				);
			}
			Some(tc) => {
				let dest = validate_tor_address(dest)?;
				Box::new(
					HttpDataSender::with_socks_proxy(
						&dest,
						apisecret.clone(),
						&tc.socks_proxy_addr,
						Some(tc.send_config_dir),
						tc.socks_running,
						tc.tor_log_file,
						tc.bridge,
						tc.proxy,
					)
					.map_err(|e| invalid(e))?,
				)
			}
		},
		"mwcmqs" => Box::new(MwcMqsChannel::new(dest.to_string())),
		_ => {
			return Err(handle_unsupported_types(method));
		}
	})
}

/// create a Swap Message Sender
pub fn create_swap_message_sender(
	method: &str,
	dest: &str,
	apisecret: &Option<String>,
	tor_config: &TorConfig,
) -> Result<Box<dyn SwapMessageSender>, Error> {
	let invalid = |e| {
		ErrorKind::WalletComms(format!(
			"Invalid wallet comm type and destination. method: {}, dest: {}, error: {}",
			method, dest, e
		))
	};

	Ok(match method {
		"tor" => {
			let dest = validate_tor_address(dest)?;
			Box::new(
				HttpDataSender::with_socks_proxy(
					&dest,
					apisecret.clone(),
					&tor_config.socks_proxy_addr,
					Some(tor_config.send_config_dir.clone()),
					tor_config.socks_running,
					tor_config.tor_log_file.clone(),
					tor_config.bridge.clone(),
					tor_config.proxy.clone(),
				)
				.map_err(|e| invalid(e))?,
			)
		}
		"mwcmqs" => Box::new(MwcMqsChannel::new(dest.to_string())),
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
			return ErrorKind::WalletComms(
				"File based transactions must be performed asynchronously.".to_string(),
			)
			.into();
		}
		"self" => {
			return ErrorKind::WalletComms("No sender implementation for \"self\".".to_string())
				.into();
		}
		_ => {
			return ErrorKind::WalletComms(format!(
				"Wallet comm method \"{}\" does not exist.",
				method
			))
			.into();
		}
	}
}
