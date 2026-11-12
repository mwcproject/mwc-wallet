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
use mwc_wallet_util::mwc_core::core::committed;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_web3;
use mwc_wallet_util::mwc_web3::types::{H256, U256};
use std::io;

/// Swap crate errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Funding must fit the seller's single-transaction redemption policy.
	#[error("Swap funding has {actual} outputs; maximum allowed is {maximum}")]
	TooManySecondaryOutputs {
		/// Number of funding outputs found.
		actual: usize,
		/// Maximum accepted funding outputs.
		maximum: usize,
	},
	/// The completed Bitcoin transaction exceeds standard relay policy.
	#[error("Secondary transaction weight {actual} exceeds the standard limit {maximum}")]
	SecondaryTransactionTooHeavy {
		/// Fully signed transaction weight.
		actual: usize,
		/// Maximum standard transaction weight.
		maximum: usize,
	},
	/// Integer conversion or arithmetic overflow/underflow.
	#[error("Swap data overflow error, {0}")]
	DataOverflow(String),
	/// ElectrumX connection URI is not setup
	#[error(
		"ElectrumX {0} URI is not defined. Please specify it at wallet config or with swap arguments"
	)]
	UndefinedElectrumXURI(String),
	/// Unexpected state or status. Business logic is broken
	#[error("Swap Unexpected action, {0}")]
	UnexpectedAction(String),
	/// Unexpected network
	#[error("Swap Unexpected network {0}")]
	UnexpectedNetwork(String),
	/// Unexpected role. Business logic is broken
	#[error("Swap Unexpected role, {0}")]
	UnexpectedRole(String),
	/// Not enough MWC to start swap
	#[error("Insufficient funds. Required: {0}, available: {1}")]
	InsufficientFunds(u64, u64),
	/// Message type is wrong. Business logic is broken or another party messing up with us.
	#[error("Swap Unexpected message type, {0}")]
	UnexpectedMessageType(String),
	/// Likely BTC data is not initialized. Or workflow for your new currenly is not defined
	#[error("Swap Unexpected secondary coin type")]
	UnexpectedCoinType,
	/// Yours swap version is different from other party. Somebody need to make an upgrade
	#[error(
		"Swap engines version are different. Other party has version {0}, you has {1}. To make a deal, you need to have the same versions."
	)]
	IncompatibleVersion(u8, u8),
	/// Message from different swap. Probably other party messing up with us.
	#[error("Mismatch between swap and message IDs")]
	MismatchedId,
	/// Unable to parse the amount string
	#[error("Invalid amount string, {0}")]
	InvalidAmountString(String),
	/// Wrong currency name
	#[error("Swap Invalid currency: {0}")]
	InvalidCurrency(String),
	/// Lock slate can't be locked
	#[error("Invalid lock height for Swap lock tx")]
	InvalidLockHeightLockTx,
	/// Schnorr signature is invalid
	#[error("Swap Invalid adaptor signature (Schnorr signature)")]
	InvalidAdaptorSignature,
	/// swap.refund is not defined
	#[error("Swap secondary currency data not complete")]
	SecondaryDataIncomplete,
	/// Expected singe call for that
	#[error("Swap function should only be called once, {0}")]
	OneShot(String),
	/// Swap is already finalized
	#[error("Swap is not active (finalized or cancelled)")]
	NotActive,
	/// Multisig error
	#[error("Swap Multisig error: {0}")]
	Multisig(#[from] multisig::Error),
	/// Keychain failed
	#[error("Swap Keychain error: {0}")]
	Keychain(#[from] mwc_wallet_util::mwc_keychain::Error),
	/// LibWallet error
	#[error("Swap LibWallet error: {0}")]
	LibWallet(String),
	/// Secp issue
	#[error("Swap Secp error: {0}")]
	Secp(secp::Error),
	/// IO error
	#[error("Swap I/O: {0}")]
	IO(String),
	/// Serde error
	#[error("Swap Serde error: {0}")]
	Serde(String),
	/// Rps error
	#[error("Swap Rpc error: {0}")]
	Rpc(String),
	/// Electrum Node client error
	#[error("Electrum Node error, {0}")]
	ElectrumNodeClient(String),
	/// Requested swap trade not found
	#[error("Swap trade {0} not found")]
	TradeNotFound(String),
	/// swap trade IO error
	#[error("Swap trade {0} IO error, {1}")]
	TradeIoError(String, String),
	/// swap trade encryption/decryption error
	#[error("Swap trade {0} encryption/decryption error")]
	TradeEncDecError(String),
	/// Failure of the operating-system entropy source; always a local, retryable
	/// condition, never a property of the peer's message
	#[error("Unable to obtain randomness from the OS: {0}")]
	EntropyError(String),
	/// Message validation error. Likely somebody trying to cheat with as
	#[error("Invalid Message data, {0}")]
	InvalidMessageData(String),
	/// Invalid Swap state input
	#[error("Invalid Swap state input, {0}")]
	InvalidSwapStateInput(String),
	/// Invalid Swap state input
	#[error("Swap state machine error, {0}")]
	SwapStateMachineError(String),
	/// Generic error
	#[error("Swap generic error, {0}")]
	Generic(String),

	/// Message sending issues
	#[error("Message sending error, {0}")]
	MessageSender(String),

	/// BCH tweks related error
	#[error("BCH error, {0}")]
	BchError(String),

	/// Deals path is not set
	#[error(
		"Trade deals path not defined. Please specify it at wallet config or with swap arguments"
	)]
	UndefinedTradeDealsPath,
	/// Infura Node client error
	#[error(
		"Infura Project Id not defined. Please specify it at wallet config or with swap arguments"
	)]
	UndefinedInfuraProjectId,
	/// Eth SWap Contract Address error
	#[error(
		"Eth Swap Contract Address is not defined. Please specify it at wallet config or with swap arguments"
	)]
	UndefinedEthSwapContractAddress,
	/// ERC20 Swap Contract Address error
	#[error(
		"ERC20 Swap Contract Address is not defined. Please specify it at wallet config or with swap arguments"
	)]
	UndefinedERC20SwapContractAddress,
	/// A caller tried to redirect an existing trade to another Ethereum swap contract.
	#[error(
		"Ethereum swap contract address does not match the address pinned to this trade; contract addresses cannot be changed after trade creation"
	)]
	EthSwapContractAddressMismatch,
	/// A caller tried to redirect an existing trade to another ERC20 swap contract.
	#[error(
		"ERC20 swap contract address does not match the address pinned to this trade; contract addresses cannot be changed after trade creation"
	)]
	ERC20SwapContractAddressMismatch,
	/// Infura Node error
	#[error("Infura Node error, {0}")]
	InfuraNodeClient(String),
	/// Invalid Swap Trade Index
	#[error("Ethereum Swap Trade Index error")]
	InvalidEthSwapTradeIndex,
	/// Invalid Eth Address
	#[error("Ethereum Address error")]
	InvalidEthAddress,
	/// A direct Ethereum transfer targeted the zero account, which would
	/// irreversibly destroy native funds.
	#[error("Ethereum transfer destination must not be the zero address")]
	ZeroEthTransferAddress,
	/// A swap contract address resolved to the zero account.
	#[error("Ethereum {kind} swap contract address must not be the zero address")]
	ZeroEthSwapContractAddress {
		/// Contract role (`native` or `ERC20`).
		kind: &'static str,
	},
	/// No runtime bytecode exists at a configured swap contract address.
	#[error("Ethereum {kind} swap contract {address} has no deployed code on chain id {chain_id}")]
	MissingEthSwapContractCode {
		/// Contract role (`native` or `ERC20`).
		kind: &'static str,
		/// Canonical contract address.
		address: String,
		/// EIP-155 chain identifier returned by the endpoint.
		chain_id: u64,
	},
	/// Runtime bytecode is not one of the wallet's supported custody contracts.
	#[error(
		"Ethereum {kind} swap contract {address} has unsupported deployed code on chain id {chain_id}, SHA-256 {actual_hash}"
	)]
	UnsupportedEthSwapContractCode {
		/// Contract role (`native` or `ERC20`).
		kind: &'static str,
		/// Canonical contract address.
		address: String,
		/// EIP-155 chain identifier returned by the endpoint.
		chain_id: u64,
		/// SHA-256 of the raw runtime bytecode returned by `eth_getCode`.
		actual_hash: String,
	},
	/// Eth balance is not enough
	#[error("Eth Wallet Balance is not enough")]
	EthBalanceNotEnough,
	/// ERC20 Token balance is not enough
	#[error("ERC20 Token {0} Balance is not enough")]
	ERC20TokenBalanceNotEnough(String),
	/// Invalid Tx Hash
	#[error("Invalid Eth Transaction Hash")]
	InvalidTxHash,
	/// Finalized state is unavailable or does not yet contain the required lock.
	#[error("Ethereum finality is unavailable: {0}")]
	EthereumFinalityUnavailable(String),
	/// Contract error
	#[error("Call Swap Contract error: {0}")]
	EthContractCallError(String),
	/// Ethereum JSON-RPC or transport failure before transaction submission.
	#[error("Ethereum operation {operation} failed: {source}")]
	EthereumRpc {
		/// Operation that failed.
		operation: &'static str,
		/// Original Web3 error.
		#[source]
		source: Box<mwc_web3::Error>,
	},
	/// Ethereum contract ABI or query failure.
	#[error("Ethereum contract operation {operation} failed: {source}")]
	EthereumContract {
		/// Operation that failed.
		operation: &'static str,
		/// Original contract error.
		#[source]
		source: Box<mwc_web3::contract::Error>,
	},
	/// Ethereum private-key parsing or transaction-signing failure.
	#[error("Ethereum signing operation {operation} failed: {source}")]
	EthereumSigning {
		/// Operation that failed.
		operation: &'static str,
		/// Original Web3 signing or decoding error.
		#[source]
		source: Box<mwc_web3::Error>,
	},
	/// Worker thread creation failure for a synchronous Ethereum operation.
	#[error("Ethereum worker creation for {operation} failed: {source}")]
	EthereumWorkerSpawn {
		/// Operation that could not be started.
		operation: &'static str,
		/// Original thread creation error.
		#[source]
		source: io::Error,
	},
	/// Tokio runtime construction failure for a synchronous Ethereum operation.
	#[error("Ethereum runtime creation for {operation} failed: {source}")]
	EthereumRuntime {
		/// Operation that could not be started.
		operation: &'static str,
		/// Original runtime construction error.
		#[source]
		source: io::Error,
	},
	/// Ethereum operation exceeded its application-level deadline.
	#[error("Ethereum operation {operation} timed out after {timeout_secs} seconds")]
	EthereumTimeout {
		/// Operation that timed out.
		operation: &'static str,
		/// Configured timeout in seconds.
		timeout_secs: u64,
	},
	/// Scoped Ethereum worker panicked.
	#[error("Ethereum worker for {operation} panicked: {message}")]
	EthereumWorkerPanic {
		/// Operation whose worker panicked.
		operation: &'static str,
		/// Panic payload when it contained a string.
		message: String,
	},
	/// The connected endpoint reports a chain other than the configured chain.
	#[error("Ethereum endpoint chain mismatch, expected chain id {expected}, found {actual}")]
	EthereumChainMismatch {
		/// Locally configured EIP-155 chain id.
		expected: u64,
		/// Chain id returned by the endpoint.
		actual: String,
	},
	/// The estimated gas required by a transaction exceeds the caller's maximum
	/// fee budget at the selected gas price.
	#[error(
		"Ethereum operation {operation} requires a gas fee of {required_wei} wei, exceeding the configured budget of {available_wei} wei"
	)]
	EthereumGasBudgetExceeded {
		/// Operation that cannot be funded by the configured budget.
		operation: &'static str,
		/// Estimated maximum transaction fee in wei.
		required_wei: U256,
		/// Configured maximum transaction fee in wei.
		available_wei: U256,
	},
	/// The gas estimate with its safety margin exceeds the network's gas limit.
	#[error(
		"Ethereum operation {operation} requires {required_gas} gas, exceeding the permitted limit of {maximum_gas}"
	)]
	EthereumGasLimitExceeded {
		/// Operation that cannot fit within the network's gas limit.
		operation: &'static str,
		/// Gas estimate including the safety margin.
		required_gas: U256,
		/// Smaller of the block limit and the applicable transaction cap.
		maximum_gas: U256,
	},
	/// Submission failed after the signed transaction may have reached the endpoint.
	#[error(
		"Ethereum transaction submission outcome is unknown for {tx_hash:?}: {source}; reconcile by hash before retrying"
	)]
	EthereumSubmissionUnknown {
		/// Locally computed transaction hash.
		tx_hash: H256,
		/// Original submission error.
		#[source]
		source: Box<mwc_web3::Error>,
	},
	/// Submission timed out after the signed transaction may have reached the endpoint.
	#[error(
		"Ethereum transaction submission timed out after {timeout_secs} seconds for {tx_hash:?}; reconcile by hash before retrying"
	)]
	EthereumSubmissionTimeout {
		/// Locally computed transaction hash.
		tx_hash: H256,
		/// Configured timeout in seconds.
		timeout_secs: u64,
	},
	/// Retrieve TransactionRecipt error
	#[error("Retrieve Eth TransactionReceipt error")]
	EthRetrieveTransReciptError,
	/// Unsupported ERC-20 Token
	#[error("Unsupported ERC20 Token: {0}")]
	EthUnsupportedERC20TokenError(String),
	/// ERC-20 Token Approve Failed
	#[error("ERC20 Token Approve Failed!")]
	EthERC20TokenApproveError,
	/// Another swap still owns this account/token/spender allowance.
	#[error("ERC20 funding is waiting for swap {0} to finish its deposit or cancellation")]
	Erc20FundingBusy(String),
	/// A mined reset, approval, or deposit reverted; the next attempt can retry.
	#[error("ERC20 funding transaction reverted: {0}")]
	Erc20FundingReverted(String),
	/// Refund Time Not Arrived
	#[error("Refund Time Not Arrived")]
	EthRefundTimeNotArrived,
	/// Transaction in Pending status
	#[error("Transaction Not Confirmed")]
	EthTransactionInPending,
	/// A direct transfer was mined without successfully executing its payment.
	#[error("Ethereum transfer reverted: {0:?}; its nonce has been consumed")]
	EthereumTransferReverted(H256),
	/// A historical hash cannot safely be replaced without its account nonce.
	#[error("Ethereum recovery data is missing for transaction {0:?}")]
	EthereumTransactionRecoveryMissing(H256),
	/// Other submissions must wait while a reserved transaction is missing from the pool.
	#[error("Ethereum account is waiting for nonce {0} to be accepted or confirmed")]
	EthereumTransactionNonceReserved(U256),
	/// The account consumed this nonce; reconcile receipts before another transaction.
	#[error("Ethereum nonce {nonce} has been consumed; reconcile transaction {tx_hash:?}")]
	EthereumTransactionNonceConsumed {
		/// Reserved account nonce.
		nonce: U256,
		/// Latest attempted transaction hash.
		tx_hash: H256,
	},
	/// Lib Tx error
	#[error("Lib Tx error: {0}")]
	LibTx(#[from] mwc_wallet_util::mwc_core::libtx::Error),
}

impl Error {
	/// Return the locally computed hash carried by an ambiguous Ethereum
	/// submission error. The signed payload is deliberately not propagated in
	/// errors; callers persist this hash and reconcile it before retrying.
	pub(crate) fn ethereum_submission_hash(&self) -> Option<H256> {
		match self {
			Self::EthereumSubmissionUnknown { tx_hash, .. }
			| Self::EthereumSubmissionTimeout { tx_hash, .. } => Some(*tx_hash),
			_ => None,
		}
	}

	/// Whether the failure reflects a local condition that can change —
	/// infrastructure, configuration, balances, entropy, or in-flight chain
	/// state — rather than the content of the peer's message. Transient
	/// failures are worth redelivering; peer-data validation failures are not.
	/// Ambiguous variants (Generic, LibWallet) are biased toward transient: a
	/// wrong transient classification costs a bounded number of retries, while
	/// a wrong deterministic classification silently drops a valid message.
	pub fn is_transient(&self) -> bool {
		match self {
			Self::Multisig(error) => error.is_transient(),
			// Most secp failures are deterministic validation results for peer
			// keys/signatures. Retrying those poison messages cannot change the
			// result; only local entropy/allocation failures may recover.
			Self::Secp(error) => matches!(
				error,
				secp::Error::SysRngFailure | secp::Error::AllocationError
			),
			Self::Keychain(_)
			| Self::IO(_)
			| Self::Rpc(_)
			| Self::ElectrumNodeClient(_)
			| Self::InfuraNodeClient(_)
			| Self::TradeIoError(..)
			| Self::EntropyError(_)
			| Self::LibWallet(_)
			| Self::Generic(_)
			| Self::MessageSender(_)
			| Self::UndefinedElectrumXURI(_)
			| Self::UndefinedInfuraProjectId
			| Self::UndefinedEthSwapContractAddress
			| Self::UndefinedERC20SwapContractAddress
			| Self::UndefinedTradeDealsPath
			| Self::ZeroEthSwapContractAddress { .. }
			| Self::MissingEthSwapContractCode { .. }
			| Self::EthBalanceNotEnough
			| Self::ERC20TokenBalanceNotEnough(_)
			| Self::InsufficientFunds(..)
			| Self::EthRetrieveTransReciptError
			| Self::EthContractCallError(_)
			| Self::EthERC20TokenApproveError
			| Self::Erc20FundingBusy(_)
			| Self::Erc20FundingReverted(_)
			| Self::EthRefundTimeNotArrived
			| Self::EthereumTransactionNonceConsumed { .. }
			| Self::EthereumTransactionNonceReserved(_)
			| Self::EthTransactionInPending
			| Self::EthereumFinalityUnavailable(_)
			| Self::EthereumRpc { .. }
			| Self::EthereumContract { .. }
			| Self::EthereumSigning { .. }
			| Self::EthereumWorkerSpawn { .. }
			| Self::EthereumRuntime { .. }
			| Self::EthereumTimeout { .. }
			| Self::EthereumWorkerPanic { .. }
			| Self::EthereumChainMismatch { .. }
			| Self::EthereumGasBudgetExceeded { .. }
			| Self::EthereumGasLimitExceeded { .. }
			| Self::EthereumSubmissionUnknown { .. }
			| Self::EthereumSubmissionTimeout { .. } => true,
			_ => false,
		}
	}
}

#[warn(deprecated)]

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Error {
		// Swap I/O errors are intentionally reduced to diagnostic messages; retry
		// classification treats every `Error::IO` as transient. Code that needs a
		// specific `io::ErrorKind` must inspect it before this conversion boundary.
		Error::IO(format!("{}", error))
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(error)
	}
}

impl From<mwc_wallet_util::mwc_bitcoin::blockdata::script::Error> for Error {
	fn from(error: mwc_wallet_util::mwc_bitcoin::blockdata::script::Error) -> Error {
		Error::Generic(format!("Bitcoin script error: {}", error))
	}
}

impl From<mwc_wallet_util::mwc_bitcoin::util::address::Error> for Error {
	fn from(error: mwc_wallet_util::mwc_bitcoin::util::address::Error) -> Error {
		Error::Generic(format!("Bitcoin address error: {}", error))
	}
}

impl From<mwc_wallet_util::mwc_core::ser::Error> for Error {
	fn from(error: mwc_wallet_util::mwc_core::ser::Error) -> Error {
		Error::Generic(format!("MWC serialization error: {}", error))
	}
}

impl From<mwc_wallet_util::mwc_bitcoin::consensus::encode::Error> for Error {
	fn from(error: mwc_wallet_util::mwc_bitcoin::consensus::encode::Error) -> Error {
		Error::Generic(format!("Bitcoin encoding error: {}", error))
	}
}

impl From<serde_json::Error> for Error {
	fn from(error: serde_json::Error) -> Error {
		Error::Serde(format!("{}", error))
	}
}

impl From<committed::Error> for Error {
	fn from(error: committed::Error) -> Error {
		match error {
			committed::Error::Keychain(e) => e.into(),
			committed::Error::Secp(e) => e.into(),
			e => Error::Generic(format!("{}", e)),
		}
	}
}

impl From<crate::Error> for Error {
	fn from(error: crate::Error) -> Error {
		Error::LibWallet(format!("{}", error))
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn transient_classification_separates_local_failures_from_peer_data() {
		// Local infrastructure, configuration, and in-flight chain state
		assert!(Error::Rpc("node down".to_string()).is_transient());
		assert!(Error::IO("disk".to_string()).is_transient());
		assert!(Error::Generic("ambiguous".to_string()).is_transient());
		assert!(Error::EthTransactionInPending.is_transient());
		assert!(Error::EthRetrieveTransReciptError.is_transient());
		assert!(Error::UndefinedInfuraProjectId.is_transient());
		assert!(Error::InsufficientFunds(10, 5).is_transient());
		let spawn_error = Error::EthereumWorkerSpawn {
			operation: "test worker startup",
			source: io::Error::from(io::ErrorKind::WouldBlock),
		};
		assert!(spawn_error.is_transient());
		assert!(
			Error::EthereumGasBudgetExceeded {
				operation: "test transfer",
				required_wei: U256::from(2u8),
				available_wei: U256::from(1u8),
			}
			.is_transient()
		);
		assert!(Error::EntropyError("getentropy failed".to_string()).is_transient());
		assert!(Error::Multisig(multisig::Error::Secp(secp::Error::SysRngFailure)).is_transient());
		assert!(Error::Secp(secp::Error::SysRngFailure).is_transient());
		assert!(Error::Secp(secp::Error::AllocationError).is_transient());
		// Peer-controlled message content and deterministic local logic
		assert!(!Error::InvalidMessageData("bad offer".to_string()).is_transient());
		assert!(!Error::ZeroEthTransferAddress.is_transient());
		assert!(!Error::TradeEncDecError("bad ciphertext".to_string()).is_transient());
		assert!(!Error::Multisig(multisig::Error::Secp(secp::Error::InvalidCommit)).is_transient());
		assert!(!Error::Secp(secp::Error::InvalidPublicKey).is_transient());
		assert!(!Error::Secp(secp::Error::InvalidSignature).is_transient());
		assert!(!Error::Secp(secp::Error::InvalidCommit).is_transient());
		assert!(!Error::Secp(secp::Error::InvalidParameters).is_transient());
		assert!(!Error::IncompatibleVersion(1, 2).is_transient());
		assert!(!Error::InvalidSwapStateInput("bad input".to_string()).is_transient());
		assert!(!Error::SecondaryDataIncomplete.is_transient());
		assert!(!Error::InvalidAdaptorSignature.is_transient());
	}

	#[test]
	fn secp_transience_is_preserved_at_the_libwallet_boundary() {
		let deterministic: crate::Error = Error::Secp(secp::Error::InvalidPublicKey).into();
		assert!(matches!(deterministic, crate::Error::Backend(_)));

		let retryable: crate::Error = Error::Secp(secp::Error::SysRngFailure).into();
		assert!(matches!(retryable, crate::Error::SwapTransient(_)));
	}

	#[test]
	fn submission_errors_expose_only_reconciliation_data() {
		let tx_hash = H256::from_low_u64_be(7);
		let unknown = Error::EthereumSubmissionUnknown {
			tx_hash,
			source: Box::new(mwc_web3::Error::InvalidResponse(
				"submission connection closed".to_string(),
			)),
		};
		let message = unknown.to_string();
		assert!(message.contains("submission connection closed"));
		assert!(message.contains("reconcile by hash before retrying"));
		assert_eq!(unknown.ethereum_submission_hash(), Some(tx_hash));

		// Intentionally list every field so adding a signed payload back to either
		// propagated error breaks this regression test at compile time.
		match unknown {
			Error::EthereumSubmissionUnknown {
				tx_hash: actual,
				source,
			} => {
				assert_eq!(actual, tx_hash);
				assert!(source.to_string().contains("submission connection closed"));
			}
			other => panic!("unexpected result: {:?}", other),
		}

		let timed_out = Error::EthereumSubmissionTimeout {
			tx_hash,
			timeout_secs: 30,
		};
		assert_eq!(timed_out.ethereum_submission_hash(), Some(tx_hash));
		match timed_out {
			Error::EthereumSubmissionTimeout {
				tx_hash: actual,
				timeout_secs,
			} => {
				assert_eq!(actual, tx_hash);
				assert_eq!(timeout_secs, 30);
			}
			other => panic!("unexpected result: {:?}", other),
		}
	}
}
