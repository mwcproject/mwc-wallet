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

//! Implementation specific error types
use mwc_wallet_util::mwc_core::core::transaction;
use mwc_wallet_util::mwc_core::libtx;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use std::fmt;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Integer conversion or arithmetic overflow/underflow.
	#[error("Wallet controller data overflow error, {0}")]
	DataOverflow(String),

	/// LibTX Error
	#[error("LibTx Error, {0}")]
	LibTX(#[from] libtx::Error),

	/// Impls error
	#[error("Impls Error, {0}")]
	Impls(#[from] mwc_wallet_impls::Error),

	/// LibWallet Error
	#[error("LibWallet Error, {0}")]
	LibWallet(String),

	/// Swap Error
	#[error("Swap error, {0}")]
	SwapError(String),

	/// The remote marketplace returned an acknowledgement that does not match
	/// the command-specific response contract.
	#[cfg(feature = "swaps")]
	#[error("Invalid marketplace acknowledgement: {0}")]
	MarketplaceResponse(String),

	/// An `accept_offer` request reached the remote wallet, but that wallet no
	/// longer has the selected offer available.
	#[cfg(feature = "swaps")]
	#[error("Marketplace offer is unavailable: {0}")]
	MarketplaceOfferUnavailable(String),

	/// Structured swap error
	#[cfg(feature = "swaps")]
	#[error(transparent)]
	Swap(#[from] mwc_wallet_libwallet::swap::Error),

	/// Keychain error
	#[error("Keychain error, {0}")]
	Keychain(#[from] mwc_wallet_util::mwc_keychain::Error),

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

	/// Slate storage failed after wallet state was persisted, and the
	/// compensating cancellation failed.
	#[error(
		"{storage_error}. Automatic cancellation of transaction {slate_id} also failed: \
		 {cancellation_error}. The transaction remains pending and its inputs may be locked. \
		 Restore node connectivity and run `cancel --txid {slate_id}`."
	)]
	SlateStorageRollbackFailed {
		/// UUID of the persisted transaction requiring recovery.
		slate_id: Uuid,
		/// Original slate storage error.
		storage_error: String,
		/// Error returned by the compensating cancellation.
		cancellation_error: String,
	},

	/// Displaying or backing up the slatepack failed after the transaction
	/// state was persisted. The transaction remains pending with locked
	/// inputs; the caller is expected to cancel it explicitly rather than
	/// retry the send, which would create a second payable slate.
	#[error(
		"Unable to display or back up the slatepack for transaction {slate_id}: {display_error}. \
		 Publication status: {publication_status}. The transaction is pending and its inputs \
		 may be locked. Run `cancel --txid {slate_id}` to release them before retrying."
	)]
	SlatepackBackupFailed {
		/// UUID of the persisted transaction requiring recovery.
		slate_id: Uuid,
		/// Whether the initial slate was already published to the destination.
		publication_status: SlatePublicationStatus,
		/// Original slatepack display/backup error.
		display_error: String,
	},

	/// Error when formatting json
	#[error("Serde JSON error, {0}")]
	Format(String),

	/// Error when contacting a node through its API
	#[error("Node API error, {0}")]
	Node(#[from] mwc_wallet_util::mwc_api::Error),

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
	#[error("Listener Startup Error: {0}")]
	ListenerError(String),

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

	/// Swap message processing failed on a transient local condition (node,
	/// storage, keychain, entropy). The message may succeed on redelivery, so
	/// the transport must leave it unacknowledged instead of dropping it.
	#[cfg(feature = "swaps")]
	#[error("Transient swap message processing failure, {0}")]
	TransientSwapMessageError(String),
}

impl From<mwc_wallet_libwallet::Error> for Error {
	fn from(error: mwc_wallet_libwallet::Error) -> Error {
		Error::LibWallet(format!("{}", error))
	}
}

/// Whether the initial slate had been published to its destination before a
/// subsequent failure. Used to report the durable state of a transaction when
/// a post-publication step fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlatePublicationStatus {
	/// A destination was set and the slate was written to it before the
	/// failure; the recipient may already have access to the slate.
	PublishedToDest,
	/// No destination was set; the slate was never released anywhere.
	NotPublished,
}

impl fmt::Display for SlatePublicationStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			SlatePublicationStatus::PublishedToDest => write!(
				f,
				"published to the destination (the recipient may already have the slate)"
			),
			SlatePublicationStatus::NotPublished => {
				write!(f, "not published (no destination was set)")
			}
		}
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(format!("{}", error))
	}
}

#[cfg(all(test, feature = "swaps"))]
mod tests {
	use super::Error;

	#[test]
	fn swap_error_conversion_preserves_structured_cause() {
		let error: Error = mwc_wallet_libwallet::swap::Error::EthereumChainMismatch {
			expected: 1,
			actual: "3".to_string(),
		}
		.into();

		assert!(matches!(
			error,
			Error::Swap(mwc_wallet_libwallet::swap::Error::EthereumChainMismatch {
				expected: 1,
				ref actual,
			}) if actual == "3"
		));
	}
}
