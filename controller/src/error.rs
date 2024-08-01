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

//! Implementation specific error types
use crate::api;
use crate::core::core::transaction;
use crate::core::libtx;
use crate::impls;
use crate::keychain;
use crate::libwallet;
use failure::{Backtrace, Context, Fail};
use std::env;
use std::fmt::{self, Display};

/// Error definition
#[derive(Debug)]
pub struct Error {
	pub inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// LibTX Error
	#[fail(display = "LibTx Error, {}", _0)]
	LibTX(libtx::Error),

	/// Impls error
	#[fail(display = "Impls Error, {}", _0)]
	Impls(impls::ErrorKind),

	/// LibWallet Error
	#[fail(display = "LibWallet Error, {}", _0)]
	LibWallet(String),

	/// Keychain error
	#[fail(display = "Keychain error, {}", _0)]
	Keychain(keychain::Error),

	/// Transaction Error
	#[fail(display = "Transaction error, {}", _0)]
	Transaction(transaction::Error),

	/// Secp Error
	#[fail(display = "Secp error, {}", _0)]
	Secp(String),

	/// Filewallet error
	#[fail(display = "Wallet data error: {}", _0)]
	FileWallet(&'static str),

	/// Error when formatting json
	#[fail(display = "Controller IO error, {}", _0)]
	IO(String),

	/// Error when formatting json
	#[fail(display = "Serde JSON error, {}", _0)]
	Format(String),

	/// Error when contacting a node through its API
	#[fail(display = "Node API error, {}", _0)]
	Node(api::Error),

	/// Error originating from hyper.
	#[fail(display = "Hyper error, {}", _0)]
	Hyper(String),

	/// Error originating from hyper uri parsing.
	#[fail(display = "Uri parsing error")]
	Uri,

	/// Attempt to use duplicate transaction id in separate transactions
	#[fail(display = "Duplicate transaction ID error, {}", _0)]
	DuplicateTransactionId(String),

	/// Wallet seed already exists
	#[fail(display = "Wallet seed file exists: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Enc/Decryption Error
	#[fail(display = "Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[fail(display = "BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[fail(display = "Invalid argument: {}", _0)]
	ArgumentError(String),

	/// Other
	#[fail(display = "Generic error: {}", _0)]
	GenericError(String),

	/// Listener error
	#[fail(display = "Listener Startup Error")]
	ListenerError,

	/// Tor Configuration Error
	#[fail(display = "Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Tor Process error
	#[fail(display = "Tor Process Error: {}", _0)]
	TorProcess(String),

	/// MQS Configuration Error
	#[fail(display = "MQS Config Error: {}", _0)]
	MQSConfig(String),

	///rejecting invoice as auto invoice acceptance is turned off
	#[fail(display = "rejecting invoice as auto invoice acceptance is turned off!")]
	DoesNotAcceptInvoices,

	///when invoice amount is too big(added with mqs feature)
	#[fail(display = "error: rejecting invoice as amount '{}' is too big!", _0)]
	InvoiceAmountTooBig(u64),

	/// Verify slate messages call failure
	#[fail(display = "failed verifying slate messages, {}", _0)]
	VerifySlateMessagesError(String),

	/// Processing swap message failure
	#[fail(display = "failed processing swap messages, {}", _0)]
	ProcessSwapMessageError(String),
}

impl Fail for Error {
	fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => {
				if r == "1" {
					true
				} else {
					false
				}
			}
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\nBacktrace: {}", backtrace);
		let mut output = inner_output.clone();
		if show_bt {
			output.push_str(&backtrace_output);
		}
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<api::Error> for Error {
	fn from(error: api::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Node(error)),
		}
	}
}

impl From<keychain::Error> for Error {
	fn from(error: keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(error)),
		}
	}
}

impl From<transaction::Error> for Error {
	fn from(error: transaction::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Transaction(error)),
		}
	}
}

impl From<libwallet::Error> for Error {
	fn from(error: libwallet::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibWallet(format!("{}", error))),
		}
	}
}

impl From<libtx::Error> for Error {
	fn from(error: libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibTX(error)),
		}
	}
}

impl From<impls::Error> for Error {
	fn from(error: impls::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Impls(error.kind())),
		}
	}
}
