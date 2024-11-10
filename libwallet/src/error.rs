// Copyright 2021 The Mwc Developers
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

use crate::mwc_core::core::{committed, transaction};
use crate::mwc_core::libtx;
use crate::mwc_keychain;
use crate::mwc_util::secp;
use crate::util::{self, mwc_store};
use std::io;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
	/// Not enough funds
	#[error("Not enough funds. Required: {needed_disp:?}, Available: {available_disp:?}")]
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
	#[error("Slate inputs and outputs number is more then {0}. Please reduce number of outputs or reduce sending amount")]
	TooLargeSlate(usize),

	/// Fee error
	#[error("Fee Error: {0}")]
	Fee(String),

	/// LibTX Error
	#[error("LibTx Error, {0}")]
	LibTX(#[from] libtx::Error),

	/// Keychain error
	#[error("Keychain error, {0}")]
	Keychain(#[from] mwc_keychain::Error),

	/// Transaction Error
	#[error("Transaction error, {0}")]
	Transaction(#[from] transaction::Error),

	/// API Error
	#[error("Client Callback Error, {0}")]
	ClientCallback(String),

	/// Secp Error
	#[error("Secp error, {0}")]
	Secp(String),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error, {0}")]
	OnionV3Address(#[from] util::OnionV3AddressError),

	/// Callback implementation error conversion
	#[error("Trait Implementation error, {0}")]
	CallbackImpl(String),

	/// Wallet backend error
	#[error("Wallet store error, {0}")]
	Backend(String),

	/// Callback implementation error conversion
	#[error("Restore Error")]
	Restore,

	/// An error in the format of the JSON structures exchanged by the wallet
	#[error("JSON format error, {0}")]
	Format(String),

	/// Other serialization errors
	#[error("Ser/Deserialization error, {0}")]
	Deser(#[from] crate::mwc_core::ser::Error),

	/// IO Error
	#[error("I/O error, {0}")]
	IO(String),

	/// Error when contacting a node through its API
	#[error("Node API error: {0}")]
	Node(String),

	/// Error when not found ready to process sync data node
	#[error("Node not ready or not available")]
	NodeNotReady,

	/// Node api url is not set.
	#[error("node_url is empty. Please update your config.")]
	NodeUrlIsEmpty,

	/// Error originating from hyper.
	#[error("Hyper error, {0}")]
	Hyper(String),

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Signature error
	#[error("Signature error: {0}")]
	Signature(String),

	/// OwnerAPIEncryption
	#[error("API encryption error, {0}")]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed exists error: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[error("Transaction {0} doesn't exist")]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[error("Transaction {0} cannot be cancelled")]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[error("Cancellation Error: {0}")]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[error("Tx dump Error: {0}")]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[error("Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[error("Transaction {0} has already been received")]
	TransactionAlreadyReceived(String),

	/// Transaction with same offset has already been received
	#[error("Transaction  with offset hex string {0} has already been received")]
	TransactionWithSameOffsetAlreadyReceived(String),

	/// Transaction has been cancelled
	#[error("Transaction {0} has been cancelled")]
	TransactionWasCancelled(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[error("Transaction building not completed: {0}")]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[error("Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[error("Account Label '{0}' already exists")]
	AccountLabelAlreadyExists(String),

	/// Try to rename/delete unknown account
	#[error("error: Account label {0} doesn't exist!")]
	AccountLabelNotExists(String),

	/// Account with can't be renamed
	#[error("error: default account cannot be renamed!")]
	AccountDefaultCannotBeRenamed,

	/// Reference unknown account label
	#[error("Unknown Account Label '{0}'")]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[error("Committed Error, {0}")]
	Committed(#[from] committed::Error),

	/// Can't parse slate version
	#[error("Can't parse slate version, {0}")]
	SlateVersionParse(String),

	/// Unknown Kernel Feature
	#[error("Unknown Kernel Feature: {0}")]
	UnknownKernelFeatures(u8),

	/// Invalid Kernel Feature
	#[error("Invalid Kernel Feature: {0}")]
	InvalidKernelFeatures(String),

	/// Can't serialize slate
	#[error("Can't Serialize slate, {0}")]
	SlateSer(String),

	/// Can't deserialize slate
	#[error("Can't Deserialize slate, {0}")]
	SlateDeser(String),

	/// Unknown slate version
	#[error("Unknown Slate Version: {0}")]
	SlateVersion(u16),

	/// Slate Validation error
	#[error("Unable to validate slate, {0}")]
	SlateValidation(String),

	/// Attempt to use slate transaction data that doesn't exists
	#[error("Get empty slate, Slate transaction required in this context")]
	SlateTransactionRequired,

	/// Attempt to downgrade slate that can't be downgraded
	#[error("Can't downgrade slate: {0}")]
	SlateInvalidDowngrade(String),

	/// Compatibility error between incoming slate versions and what's expected
	#[error("Compatibility Error: {0}")]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[error("Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[error("Lifecycle Error: {0}")]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[error("Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Generating Payment Proof
	#[error("Payment Proof generation error: {0}")]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof retrieval error: {0}")]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof parsing error: {0}")]
	PaymentProofParsing(String),

	/// Can't convert payment proof message
	#[error("Can't convert payment proof message, {0}")]
	PaymentProofMessageSer(String),

	/// Payment Proof address
	#[error("Payment Proof address error: {0}")]
	PaymentProofAddress(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[error("Proof Address decoding: {0}")]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[error("Transaction Expired")]
	TransactionExpired,

	/// Stored Transaction issues
	#[error("Stored transaction error, {0}")]
	StoredTransactionError(String),

	/// Claim prepare call with wrong amount value
	#[error("error: Amount specified does not match slate! slate = {amount} / sum = {sum}")]
	AmountMismatch {
		/// Amount that pass as a prameter
		amount: u64,
		/// Sum of amounts that slate has
		sum: u64,
	},

	/// Other
	#[error("Generic error, {0}")]
	GenericError(String),

	/// Fail to parse any type of proofable address
	#[error("Unable to parse address {0}")]
	ProofableAddressParsingError(String),

	/// Tx Proof error
	#[error("Tx Proof error, {0}")]
	TxProofGenericError(String),

	/// Unable to verify signature for the proof
	#[error("Tx Proof unable to verify signature, {0}")]
	TxProofVerifySignature(String),

	/// Expected destinatin address doesn't match expected value
	#[error("Tx Proof unable to verify destination address. Expected {0}, found {1}")]
	TxProofVerifyDestination(String, String),

	/// Expected sender address doesn't match expected value
	#[error("Tx Proof unable to verify sender address. Expected {0}, found {1}")]
	TxProofVerifySender(String, String),

	/// Not found Tx Proof file
	#[error("transaction doesn't have a proof, file {0} not found")]
	TransactionHasNoProof(String),

	/// Base58 generic error
	#[error("Base58 error, {0}")]
	Base58Error(String),

	/// Hex conversion error
	#[error("Hex conversion error, {0}")]
	HexError(String),

	/// Derive key error
	#[error("Derive key error, {0}")]
	DeriveKeyError(String),

	/// Swap error
	#[error("Swap Error, {0}")]
	SwapError(String),

	/// Slatepack Decoding Error
	#[error("Slatepack decode error, {0}")]
	SlatepackDecodeError(String),

	/// Slatepack Encoding Error
	#[error("Slatepack encode error, {0}")]
	SlatepackEncodeError(String),

	/// Ethereum Wallet Error
	#[error("Ethereum wallet error, {0}")]
	EthereumWalletError(String),

	/// Rewind Hash parsing error
	#[error("Rewind Hash error: {0}")]
	RewindHash(String),

	/// Nonce creation error
	#[error("Nonce error: {0}")]
	Nonce(String),

	/// Invalid ownership proof
	#[error("Invalid ownership proof: {0}")]
	InvalidOwnershipProof(String),
}

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Error {
		Error::IO(format!("{}", error))
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(format!("{}", error))
	}
}

impl From<mwc_store::Error> for Error {
	fn from(error: mwc_store::Error) -> Error {
		Error::Backend(format!("{}", error))
	}
}

impl From<crate::swap::error::Error> for Error {
	fn from(error: crate::swap::error::Error) -> Error {
		Error::Backend(format!("{}", error))
	}
}
