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

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error, {0}")]
	LibTX(#[from] libtx::Error),

	/// Impls error
	#[error("Impls Error, {0}")]
	Impls(#[from] impls::Error),

	/// LibWallet Error
	#[error("LibWallet Error, {0}")]
	LibWallet(String),

	/// Swap Error
	#[error("Swap error, {0}")]
	SwapError(String),

	/// Keychain error
	#[error("Keychain error, {0}")]
	Keychain(#[from] keychain::Error),

	/// Transaction Error
	#[error("Transaction error, {0}")]
	Transaction(#[from] transaction::Error),

	/// Secp Error
	#[error("Secp error, {0}")]
	Secp(String),

	/// Filewallet error
	#[error("Wallet data error: {0}")]
	FileWallet(&'static str),

	/// Error when formatting json
	#[error("Controller IO error, {0}")]
	IO(String),

	/// Error when formatting json
	#[error("Serde JSON error, {0}")]
	Format(String),

	/// Error when contacting a node through its API
	#[error("Node API error, {0}")]
	Node(#[from] api::Error),

	/// Error originating from hyper.
	#[error("Hyper error, {0}")]
	Hyper(String),

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error, {0}")]
	DuplicateTransactionId(String),

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("Invalid argument: {0}")]
	ArgumentError(String),

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),

	/// Listener error
	#[error("Listener Startup Error")]
	ListenerError,

	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),

	/// MQS Configuration Error
	#[error("MQS Config Error: {0}")]
	MQSConfig(String),

	///rejecting invoice as auto invoice acceptance is turned off
	#[error("Rejecting invoice as auto invoice acceptance is turned off!")]
	DoesNotAcceptInvoices,

	///when invoice amount is too big(added with mqs feature)
	#[error("Rejecting invoice as amount '{0}' is too big!")]
	InvoiceAmountTooBig(u64),

	/// Verify slate messages call failure
	#[error("Failed verifying slate messages, {0}")]
	VerifySlateMessagesError(String),

	/// Processing swap message failure
	#[error("Failed processing swap messages, {0}")]
	ProcessSwapMessageError(String),
}

impl From<grin_wallet_libwallet::Error> for Error {
	fn from(error: grin_wallet_libwallet::Error) -> Error {
		Error::LibWallet(format!("{}", error))
	}
}

impl From<grin_wallet_libwallet::swap::Error> for Error {
	fn from(error: grin_wallet_libwallet::swap::Error) -> Error {
		Error::SwapError(format!("{}", error))
	}
}
