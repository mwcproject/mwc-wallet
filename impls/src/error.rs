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
use crate::core::libtx;
use crate::keychain;
use mwc_wallet_util::OnionV3AddressError;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, thiserror::Error, Eq, PartialEq, Debug)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error, {0}")]
	LibTX(#[from] libtx::Error),

	/// LibWallet Error
	#[error("LibWallet Error, {0}")]
	LibWallet(String),

	/// Keychain error
	#[error("Keychain error, {0}")]
	Keychain(#[from] keychain::Error),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error, {0}")]
	OnionV3Address(#[from] OnionV3AddressError),

	/// Error when obfs4proxy is not in the user path if TOR brigde is enabled
	#[error("Unable to find obfs4proxy binary in your path; {0}")]
	Obfs4proxyBin(String),

	/// Error the bridge input is in bad format
	#[error("Bridge line is in bad format; {0}")]
	BridgeLine(String),

	/// Error when formatting json
	#[error("IO error, {0}")]
	IO(String),

	/// Secp Error
	#[error("Secp error, {0}")]
	Secp(String),

	/// Error when formatting json
	#[error("Serde JSON error, {0}")]
	Format(String),

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet doesn't exist at {0}. {1}")]
	WalletDoesntExist(String, String),

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?), {0}")]
	Encryption(String),

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error, {0}")]
	Mnemonic(String),

	/// Command line argument error
	#[error("{0}")]
	ArgumentError(String),

	/// Tor Bridge error
	#[error("Tor Bridge Error, {0}")]
	TorBridge(String),

	/// Tor Proxy error
	#[error("Tor Proxy Error, {0}")]
	TorProxy(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {0}")]
	NotOnion(String),

	/// API Error
	#[error("Adapter Callback Error, {0}")]
	ClientCallback(String),

	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Tor Process error
	#[error("Tor (Arti) Error: {0}")]
	Arti(String),

	/// Error contacting wallet API
	#[error("Wallet Communication Error: {0}")]
	WalletComms(String),

	/// Listener is closed issue
	#[error("{0} listener is closed! consider using `listen` first.")]
	ClosedListener(String),

	/// MQS generic error
	#[error("MQS error: {0}")]
	MqsGenericError(String),

	/// Address generic error
	#[error("Address error: {0}")]
	AddressGenericError(String),

	/// Get MQS invalid response
	#[error("{0} Sender returned invalid response.")]
	MqsInvalidRespose(String),

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),

	/// Other
	#[error("Connection error: {0}")]
	ConnectionError(String),

	#[error("unknown address!, {0}")]
	UnknownAddressType(String),

	#[error("could not parse `{0}` to a https address!")]
	HttpsAddressParsingError(String),

	#[error("Swap message error, {0}")]
	SwapMessageGenericError(String),

	#[error("Swap deal not found error, {0}")]
	SwapDealGenericError(String),

	#[error("Error in getting swap nodes info, {0}")]
	SwapNodesObtainError(String),

	#[error("proof address mismatch {0}, {1}!")]
	ProofAddressMismatch(String, String),
}
