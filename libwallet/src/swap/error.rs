// Copyright 2019 The vault713 Developers
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

use super::multisig;
use failure::Fail;
use grin_core::core::committed;
use grin_util::secp;
use std::error::Error as StdError;
use std::io;

/// Swap crate errors
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// ElectrumX connection URI is not setup
	#[fail(
		display = "ElectrumX {} URI is not defined. Please specify it at wallet config or with swap arguments",
		_0
	)]
	UndefinedElectrumXURI(String),
	/// Unexpected state or status. Business logic is broken
	#[fail(display = "Swap Unexpected action, {}", _0)]
	UnexpectedAction(String),
	/// Unexpected network
	#[fail(display = "Swap Unexpected network {}", _0)]
	UnexpectedNetwork(String),
	/// Unexpected role. Business logic is broken
	#[fail(display = "Swap Unexpected role, {}", _0)]
	UnexpectedRole(String),
	/// Not enough MWC to start swap
	#[fail(display = "Insufficient funds. Required: {}, available: {}", _0, _1)]
	InsufficientFunds(u64, u64),
	/// Message type is wrong. Business logic is broken or another party messing up with us.
	#[fail(display = "Swap Unexpected message type, {}", _0)]
	UnexpectedMessageType(String),
	/// Likely BTC data is not initialized. Or workflow for your new currenly is not defined
	#[fail(display = "Swap Unexpected secondary coin type")]
	UnexpectedCoinType,
	/// Yours swap version is different from other party. Somebody need to make an upgrade
	#[fail(
		display = "Swap engines version are different. Other party has version {}, you has {}. To make a deal, you need to have the same versions.",
		_0, _1
	)]
	IncompatibleVersion(u8, u8),
	/// Message from different swap. Probably other party messing up with us.
	#[fail(display = "Mismatch between swap and message IDs")]
	MismatchedId,
	/// Unable to parse the amount string
	#[fail(display = "Invalid amount string, {}", _0)]
	InvalidAmountString(String),
	/// Wrong currency name
	#[fail(display = "Swap Invalid currency: {}", _0)]
	InvalidCurrency(String),
	/// Lock slate can't be locked
	#[fail(display = "Invalid lock height for Swap lock tx")]
	InvalidLockHeightLockTx,
	/// Schnorr signature is invalid
	#[fail(display = "Swap Invalid adaptor signature (Schnorr signature)")]
	InvalidAdaptorSignature,
	/// swap.refund is not defined
	#[fail(display = "Swap secondary currency data not complete")]
	SecondaryDataIncomplete,
	/// Expected singe call for that
	#[fail(display = "Swap function should only be called once, {}", _0)]
	OneShot(String),
	/// Swap is already finalized
	#[fail(display = "Swap is not active (finalized or cancelled)")]
	NotActive,
	/// Multisig error
	#[fail(display = "Swap Multisig error: {}", _0)]
	Multisig(multisig::ErrorKind),
	/// Keychain failed
	#[fail(display = "Swap Keychain error: {}", _0)]
	Keychain(grin_keychain::Error),
	/// LibWallet error
	#[fail(display = "Swap LibWaller error: {}", _0)]
	LibWallet(crate::ErrorKind),
	/// Secp issue
	#[fail(display = "Swap Secp error: {}", _0)]
	Secp(String),
	/// IO error
	#[fail(display = "Swap I/O: {}", _0)]
	IO(String),
	/// Serde error
	#[fail(display = "Swap Serde error: {}", _0)]
	Serde(String),
	/// Rps error
	#[fail(display = "Swap Rpc error: {}", _0)]
	Rpc(String),
	/// Electrum Node client error
	#[fail(display = "Electrum Node error, {}", _0)]
	ElectrumNodeClient(String),
	/// Requested swap trade not found
	#[fail(display = "Swap trade {} not found", _0)]
	TradeNotFound(String),
	/// swap trade IO error
	#[fail(display = "Swap trade {} IO error, {}", _0, _1)]
	TradeIoError(String, String),
	/// swap trade encryption/decryption error
	#[fail(display = "Swap trade {} encryption/decryption error", _0)]
	TradeEncDecError(String),
	/// Message validation error. Likely somebody trying to cheat with as
	#[fail(display = "Invalid Message data, {}", _0)]
	InvalidMessageData(String),
	/// Invalid Swap state input
	#[fail(display = "Invalid Swap state input, {}", _0)]
	InvalidSwapStateInput(String),
	/// Invalid Swap state input
	#[fail(display = "Swap state machine error, {}", _0)]
	SwapStateMachineError(String),
	/// Generic error
	#[fail(display = "Swap generic error, {}", _0)]
	Generic(String),
}

impl ErrorKind {
	/// Check if this error network related
	pub fn is_network_error(&self) -> bool {
		use ErrorKind::*;
		format!("");
		match self {
			Rpc(_) | ElectrumNodeClient(_) | LibWallet(crate::ErrorKind::Node(_)) => true,
			_ => false,
		}
	}
}

impl From<grin_keychain::Error> for ErrorKind {
	fn from(error: grin_keychain::Error) -> ErrorKind {
		ErrorKind::Keychain(error)
	}
}

impl From<multisig::ErrorKind> for ErrorKind {
	fn from(error: multisig::ErrorKind) -> ErrorKind {
		ErrorKind::Multisig(error)
	}
}

impl From<crate::Error> for ErrorKind {
	fn from(error: crate::Error) -> ErrorKind {
		ErrorKind::LibWallet(error.kind())
	}
}

// we have to use e.description  because of the bug at rust-secp256k1-zkp
#[allow(deprecated)]

impl From<secp::Error> for ErrorKind {
	fn from(error: secp::Error) -> ErrorKind {
		// secp::Error to_string is broken, in past biilds.
		ErrorKind::Secp(format!("{}", error.description()))
	}
}

#[warn(deprecated)]

impl From<io::Error> for ErrorKind {
	fn from(error: io::Error) -> ErrorKind {
		ErrorKind::IO(format!("{}", error))
	}
}

impl From<serde_json::Error> for ErrorKind {
	fn from(error: serde_json::Error) -> ErrorKind {
		ErrorKind::Serde(format!("{}", error))
	}
}

impl From<committed::Error> for ErrorKind {
	fn from(error: committed::Error) -> ErrorKind {
		match error {
			committed::Error::Keychain(e) => e.into(),
			committed::Error::Secp(e) => e.into(),
			e => ErrorKind::Generic(format!("{}", e)),
		}
	}
}

/// Return generic error with formatted arguments
#[macro_export]
macro_rules! generic {
    ($($arg:tt)*) => ($crate::ErrorKind::Generic(format!($($arg)*)))
}

/// Return network error with formatted arguments
#[macro_export]
macro_rules! network {
    ($($arg:tt)*) => ($crate::ErrorKind::ElectrumNodeClient(format!($($arg)*)))
}
