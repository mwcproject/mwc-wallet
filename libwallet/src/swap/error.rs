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
use crate::mwc_core::core::committed;
use crate::mwc_util::secp;
use std::io;

/// Swap crate errors
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// ElectrumX connection URI is not setup
	#[error("ElectrumX {0} URI is not defined. Please specify it at wallet config or with swap arguments")]
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
	#[error("Swap engines version are different. Other party has version {0}, you has {1}. To make a deal, you need to have the same versions.")]
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
	Keychain(#[from] crate::mwc_keychain::Error),
	/// LibWallet error
	#[error("Swap LibWallet error: {0}")]
	LibWallet(String),
	/// Secp issue
	#[error("Swap Secp error: {0}")]
	Secp(#[from] secp::Error),
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
	#[error("Eth Swap Contract Address is not defined. Please specify it at wallet config or with swap arguments")]
	UndefinedEthSwapContractAddress,
	/// ERC20 Swap Contract Address error
	#[error("ERC20 Swap Contract Address is not defined. Please specify it at wallet config or with swap arguments")]
	UndefinedERC20SwapContractAddress,
	/// Infura Node error
	#[error("Infura Node error, {0}")]
	InfuraNodeClient(String),
	/// Invalid Swap Trade Index
	#[error("Ethereum Swap Trade Index error")]
	InvalidEthSwapTradeIndex,
	/// Invalid Eth Address
	#[error("Ethereum Address error")]
	InvalidEthAddress,
	/// Eth balance is not enough
	#[error("Eth Wallet Balance is not enough")]
	EthBalanceNotEnough,
	/// ERC20 Token balance is not enough
	#[error("ERC20 Token {0} Balance is not enough")]
	ERC20TokenBalanceNotEnough(String),
	/// Invalid Tx Hash
	#[error("Invalid Eth Transaction Hash")]
	InvalidTxHash,
	/// Contract error
	#[error("Call Swap Contract error: {0}")]
	EthContractCallError(String),
	/// Retrieve TransactionRecipt error
	#[error("Retrieve Eth TransactionReceipt error")]
	EthRetrieveTransReciptError,
	/// Unsupported ERC-20 Token
	#[error("Unsupported ERC20 Token: {0}")]
	EthUnsupportedERC20TokenError(String),
	/// ERC-20 Token Approve Failed
	#[error("ERC20 Token Approve Failed!")]
	EthERC20TokenApproveError,
	/// Refund Time Not Arrived
	#[error("Refund Time Not Arrived")]
	EthRefundTimeNotArrived,
	/// Transaction in Pending status
	#[error("Transaction Not Confirmed")]
	EthTransactionInPending,
}

#[warn(deprecated)]

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Error {
		Error::IO(format!("{}", error))
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
