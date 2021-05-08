// Copyright 2019 The Grin Developers
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

//! Error types for libwallet

use crate::grin_core::core::{committed, transaction};
use crate::grin_core::libtx;
use crate::grin_keychain;
use crate::grin_store;
use crate::grin_util::secp;
use crate::swap::error::ErrorKind as SwapErrorKind;
use crate::util;
use failure::{Backtrace, Context, Fail};
use std::env;
use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::io;

/// Error definition
#[derive(Debug, Fail)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail, Serialize, Deserialize)]
pub enum ErrorKind {
	/// Not enough funds
	#[fail(
		display = "Not enough funds. Required: {}, Available: {}",
		needed_disp, available_disp
	)]
	NotEnoughFunds {
		/// available funds
		available: u64,
		/// Display friendly
		available_disp: String,
		/// Needed funds
		needed: u64,
		/// Display friendly
		needed_disp: String,
	},

	/// Too large slate
	#[fail(
		display = "Slate inputs and outputs number is more then {}. Please reduce number of outputs or reduce sending amount",
		_0
	)]
	TooLargeSlate(usize),

	/// Fee error
	#[fail(display = "Fee Error: {}", _0)]
	Fee(String),

	/// LibTX Error
	#[fail(display = "LibTx Error, {}", _0)]
	LibTX(crate::grin_core::libtx::ErrorKind),

	/// Keychain error
	#[fail(display = "Keychain error, {}", _0)]
	Keychain(grin_keychain::Error),

	/// Transaction Error
	#[fail(display = "Transaction error, {}", _0)]
	Transaction(transaction::Error),

	/// API Error
	#[fail(display = "Client Callback Error, {}", _0)]
	ClientCallback(String),

	/// Secp Error
	#[fail(display = "Secp error, {}", _0)]
	Secp(String),

	/// Onion V3 Address Error
	#[fail(display = "Onion V3 Address Error, {}", _0)]
	OnionV3Address(util::OnionV3AddressError),

	/// Callback implementation error conversion
	#[fail(display = "Trait Implementation error, {}", _0)]
	CallbackImpl(String),

	/// Wallet backend error
	#[fail(display = "Wallet store error, {}", _0)]
	Backend(String),

	/// Callback implementation error conversion
	#[fail(display = "Restore Error")]
	Restore,

	/// An error in the format of the JSON structures exchanged by the wallet
	#[fail(display = "JSON format error, {}", _0)]
	Format(String),

	/// Other serialization errors
	#[fail(display = "Ser/Deserialization error, {}", _0)]
	Deser(crate::grin_core::ser::Error),

	/// IO Error
	#[fail(display = "I/O error, {}", _0)]
	IO(String),

	/// Error when contacting a node through its API
	#[fail(display = "Node API error: {}", _0)]
	Node(String),

	/// Error when not found ready to process sync data node
	#[fail(display = "Node not ready or not available")]
	NodeNotReady,

	/// Error originating from hyper.
	#[fail(display = "Hyper error, {}", _0)]
	Hyper(String),

	/// Error originating from hyper uri parsing.
	#[fail(display = "Uri parsing error")]
	Uri,

	/// Signature error
	#[fail(display = "Signature error: {}", _0)]
	Signature(String),

	/// OwnerAPIEncryption
	#[fail(display = "API encryption error, {}", _0)]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[fail(display = "Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[fail(display = "Wallet seed exists error: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[fail(display = "Transaction {} doesn't exist", _0)]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[fail(display = "Transaction {} cannot be cancelled", _0)]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[fail(display = "Cancellation Error: {}", _0)]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[fail(display = "Tx dump Error: {}", _0)]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[fail(display = "Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[fail(display = "Transaction {} has already been received", _0)]
	TransactionAlreadyReceived(String),

	/// Transaction with same offset has already been received
	#[fail(
		display = "Transaction  with offset hex string {} has already been received",
		_0
	)]
	TransactionWithSameOffsetAlreadyReceived(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[fail(display = "Transaction building not completed: {}", _0)]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[fail(display = "Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[fail(display = "Account Label '{}' already exists", _0)]
	AccountLabelAlreadyExists(String),

	/// Try to rename/delete unknown account
	#[fail(display = "error: Account label {} doesn't exist!", _0)]
	AccountLabelNotExists(String),

	/// Account with can't be renamed
	#[fail(display = "error: default account cannot be renamed!")]
	AccountDefaultCannotBeRenamed,

	/// Reference unknown account label
	#[fail(display = "Unknown Account Label '{}'", _0)]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[fail(display = "Committed Error, {}", _0)]
	Committed(committed::Error),

	/// Can't parse slate version
	#[fail(display = "Can't parse slate version, {}", _0)]
	SlateVersionParse(String),

	/// Can't serialize slate
	#[fail(display = "Can't Serialize slate, {}", _0)]
	SlateSer(String),

	/// Can't deserialize slate
	#[fail(display = "Can't Deserialize slate, {}", _0)]
	SlateDeser(String),

	/// Unknown slate version
	#[fail(display = "Unknown Slate Version: {}", _0)]
	SlateVersion(u16),

	/// Slate Validation error
	#[fail(display = "Unable to validate slate, {}", _0)]
	SlateValidation(String),

	/// Compatibility error between incoming slate versions and what's expected
	#[fail(display = "Compatibility Error: {}", _0)]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[fail(display = "Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[fail(display = "Lifecycle Error: {}", _0)]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[fail(display = "Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Generating ED25519 Public Key
	#[fail(display = "Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Generating Payment Proof
	#[fail(display = "Payment Proof generation error: {}", _0)]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[fail(display = "Payment Proof retrieval error: {}", _0)]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[fail(display = "Payment Proof parsing error: {}", _0)]
	PaymentProofParsing(String),

	/// Can't convert payment proof message
	#[fail(display = "Can't convert payment proof message, {}", _0)]
	PaymentProofMessageSer(String),

	/// Payment Proof address
	#[fail(display = "Payment Proof address error: {}", _0)]
	PaymentProofAddress(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[fail(display = "Proof Address decoding: {}", _0)]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[fail(display = "Transaction Expired")]
	TransactionExpired,

	/// Stored Transaction issues
	#[fail(display = "Stored transaction error, {}", _0)]
	StoredTransactionError(String),

	/// Claim prepare call with wrong amount value
	#[fail(
		display = "error: Amount specified does not match slate! slate = {} / sum = {}",
		amount, sum
	)]
	AmountMismatch {
		/// Amount that pass as a prameter
		amount: u64,
		/// Sum of amounts that slate has
		sum: u64,
	},

	/// Other
	#[fail(display = "Generic error, {}", _0)]
	GenericError(String),

	/// Fail to parse any type of proofable address
	#[fail(display = "Unable to parse address {}", _0)]
	ProofableAddressParsingError(String),

	/// Tx Proof error
	#[fail(display = "Tx Proof error, {}", _0)]
	TxProofGenericError(String),

	/// Unable to verify signature for the proof
	#[fail(display = "Tx Proof unable to verify signature, {}", _0)]
	TxProofVerifySignature(String),

	/// Expected destinatin address doesn't match expected value
	#[fail(
		display = "Tx Proof unable to verify destination address. Expected {}, found {}",
		_0, _1
	)]
	TxProofVerifyDestination(String, String),

	/// Expected sender address doesn't match expected value
	#[fail(
		display = "Tx Proof unable to verify sender address. Expected {}, found {}",
		_0, _1
	)]
	TxProofVerifySender(String, String),

	/// Not found Tx Proof file
	#[fail(display = "transaction doesn't have a proof, file {} not found", _0)]
	TransactionHasNoProof(String),

	/// Base58 generic error
	#[fail(display = "Base58 error, {}", _0)]
	Base58Error(String),

	/// Hex conversion error
	#[fail(display = "Hex conversion error, {}", _0)]
	HexError(String),

	/// Derive key error
	#[fail(display = "Derive key error, {}", _0)]
	DeriveKeyError(String),

	/// Swap error
	#[fail(display = "Swap Error , {}", _0)]
	SwapError(String),

	/// Slatepack Decoding Error
	#[fail(display = "Slatepack decode error, {}", _0)]
	SlatepackDecodeError(String),

	/// Slatepack Encoding Error
	#[fail(display = "Slatepack encode error, {}", _0)]
	SlatepackEncodeError(String),

	/// Ethereum Wallet Error
	#[fail(display = "Ethereum wallet error, {}", _0)]
	EthereumWalletError(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => r == "1",
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\n Backtrace: {}", backtrace);
		let mut output = inner_output;
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

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IO(format!("{}", error))),
		}
	}
}

impl From<grin_keychain::Error> for Error {
	fn from(error: grin_keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(error)),
		}
	}
}

impl From<libtx::Error> for Error {
	fn from(error: crate::grin_core::libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibTX(error.kind())),
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

impl From<crate::grin_core::ser::Error> for Error {
	fn from(error: crate::grin_core::ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Deser(error)),
		}
	}
}

// we have to use e.description  because of the bug at rust-secp256k1-zkp
#[allow(deprecated)]

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error {
			// secp::Error to_string is broken, in past biilds.
			inner: Context::new(ErrorKind::Secp(format!("{}", error.description()))),
		}
	}
}

#[warn(deprecated)]

impl From<committed::Error> for Error {
	fn from(error: committed::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Committed(error)),
		}
	}
}

impl From<grin_store::Error> for Error {
	fn from(error: grin_store::Error) -> Error {
		Error::from(ErrorKind::Backend(format!("{}", error)))
	}
}

impl From<util::OnionV3AddressError> for Error {
	fn from(error: util::OnionV3AddressError) -> Error {
		Error::from(ErrorKind::OnionV3Address(error))
	}
}

impl From<SwapErrorKind> for Error {
	fn from(error: SwapErrorKind) -> Error {
		Error::from(ErrorKind::SwapError(format!("{}", error)))
	}
}
