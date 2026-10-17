// Copyright 2021 The MWC Developers
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

use crate::Error;
use mwc_wallet_util::mwc_crates::colored::*;
use mwc_wallet_util::mwc_crates::hex;
use mwc_wallet_util::mwc_crates::rand::TryCryptoRng;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::{Zeroize, ZeroizeOnDrop};
use std::{fmt, fmt::Display, fmt::Write, str::FromStr};

use mwc_wallet_util::mwc_wagyu_ethereum::{
	wordlist::*, EthereumAddress, EthereumDerivationPath, EthereumExtendedPrivateKey,
	EthereumExtendedPublicKey, EthereumFormat, EthereumMnemonic, EthereumNetwork,
	EthereumPrivateKey, EthereumPublicKey, Mainnet, Ropsten,
};
use mwc_wallet_util::mwc_wagyu_model::{
	AddressError, AmountError, DerivationPathError, ExtendedPrivateKey, ExtendedPrivateKeyError,
	ExtendedPublicKey, ExtendedPublicKeyError, Mnemonic, MnemonicCount, MnemonicError,
	MnemonicExtended, PrivateKey, PrivateKeyError, PublicKey, PublicKeyError, TransactionError,
};

/// Ethereum Error
#[derive(Debug, thiserror::Error)]
pub enum EthError {
	/// Address error
	#[error("{0}")]
	AddressError(AddressError),
	/// Amount error
	#[error("#[from] {0}")]
	AmountError(AmountError),
	/// Crate error
	#[error("{0}: {1}")]
	Crate(&'static str, String),
	/// Derivation Path Error
	#[error("{0}")]
	DerivationPathError(DerivationPathError),
	/// ExtendedPrivateKey Error
	#[error("{0}")]
	ExtendedPrivateKeyError(ExtendedPrivateKeyError),
	/// ExtendedPublicKey Error
	#[error("{0}")]
	ExtendedPublicKeyError(ExtendedPublicKeyError),
	/// InvalidMnemonicForPrivateSpendKey
	#[error("invalid derived mnemonic for a given private spend key")]
	InvalidMnemonicForPrivateSpendKey,
	/// PrivateKeyError
	#[error("{0}")]
	PrivateKeyError(PrivateKeyError),
	/// PublicKeyError
	#[error("{0}")]
	PublicKeyError(PublicKeyError),
	/// MnemonicError
	#[error("{0}")]
	MnemonicError(MnemonicError),
	/// TransactionError
	#[error("{0}")]
	TransactionError(TransactionError),
	/// Unsupported Mnemonic Language
	#[error("unsupported mnemonic language")]
	UnsupportedLanguage,
}

impl From<AddressError> for EthError {
	fn from(error: AddressError) -> Self {
		EthError::AddressError(error)
	}
}

impl From<core::num::ParseIntError> for EthError {
	fn from(error: core::num::ParseIntError) -> Self {
		EthError::Crate("parse_int", format!("{:?}", error))
	}
}

impl From<DerivationPathError> for EthError {
	fn from(error: DerivationPathError) -> Self {
		EthError::DerivationPathError(error)
	}
}

impl From<ExtendedPrivateKeyError> for EthError {
	fn from(error: ExtendedPrivateKeyError) -> Self {
		EthError::ExtendedPrivateKeyError(error)
	}
}

impl From<ExtendedPublicKeyError> for EthError {
	fn from(error: ExtendedPublicKeyError) -> Self {
		EthError::ExtendedPublicKeyError(error)
	}
}

impl From<hex::FromHexError> for EthError {
	fn from(error: hex::FromHexError) -> Self {
		EthError::Crate("hex", format!("{:?}", error))
	}
}

impl From<MnemonicError> for EthError {
	fn from(error: MnemonicError) -> Self {
		EthError::MnemonicError(error)
	}
}

impl From<PrivateKeyError> for EthError {
	fn from(error: PrivateKeyError) -> Self {
		EthError::PrivateKeyError(error)
	}
}

impl From<PublicKeyError> for EthError {
	fn from(error: PublicKeyError) -> Self {
		EthError::PublicKeyError(error)
	}
}

impl From<serde_json::error::Error> for EthError {
	fn from(error: serde_json::error::Error) -> Self {
		EthError::Crate("serde_json", format!("{:?}", error))
	}
}

impl From<TransactionError> for EthError {
	fn from(error: TransactionError) -> Self {
		EthError::TransactionError(error)
	}
}

/// Represents parameters for an Ethereum transaction input
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "serde")]
pub struct EthereumInput {
	/// destination address
	pub to: String,
	/// how much coins send to
	pub value: String,
	/// gas fee for chain
	pub gas: String,
	/// gas price for chain
	#[serde(rename(deserialize = "gasPrice"))]
	pub gas_price: String,
	/// nonce
	pub nonce: u64,
	/// data for contract
	pub data: Option<String>,
}
/// Represents a generic wallet to output
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(crate = "serde")]
pub struct EthereumWallet {
	///hd wallet path
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<String>,
	///wallet password
	#[serde(skip_serializing_if = "Option::is_none")]
	pub password: Option<String>,
	///wallet mnemonic phrase
	#[serde(skip_serializing_if = "Option::is_none")]
	pub mnemonic: Option<String>,
	///wallet externded private key
	#[serde(skip_serializing_if = "Option::is_none")]
	pub extended_private_key: Option<String>,
	///wallet externded public key
	#[serde(skip_serializing_if = "Option::is_none")]
	pub extended_public_key: Option<String>,
	///wallet private key
	#[serde(skip_serializing_if = "Option::is_none")]
	pub private_key: Option<String>,
	///wallet public key
	#[serde(skip_serializing_if = "Option::is_none")]
	pub public_key: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	///wallet address
	pub address: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	///wallet transaction id
	pub transaction_id: Option<String>,
	///wallet network (mainnet , ropsten ...)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub network: Option<String>,
	///wallet transaction hash
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transaction_hex: Option<String>,
}

impl Zeroize for EthereumWallet {
	fn zeroize(&mut self) {
		self.path.zeroize();
		self.password.zeroize();
		self.mnemonic.zeroize();
		self.extended_private_key.zeroize();
		self.extended_public_key.zeroize();
		self.private_key.zeroize();
		self.public_key.zeroize();
		self.address.zeroize();
		self.transaction_id.zeroize();
		self.network.zeroize();
		self.transaction_hex.zeroize();
	}
}

impl Drop for EthereumWallet {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl ZeroizeOnDrop for EthereumWallet {}

impl fmt::Debug for EthereumWallet {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("EthereumWallet")
			.field("path", &self.path)
			.field("password", &self.password.as_ref().map(|_| "<redacted>"))
			.field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
			.field(
				"extended_private_key",
				&self.extended_private_key.as_ref().map(|_| "<redacted>"),
			)
			.field("extended_public_key", &self.extended_public_key)
			.field(
				"private_key",
				&self.private_key.as_ref().map(|_| "<redacted>"),
			)
			.field("public_key", &self.public_key)
			.field("address", &self.address)
			.field("transaction_id", &self.transaction_id)
			.field("network", &self.network)
			.field("transaction_hex", &self.transaction_hex)
			.finish()
	}
}

impl EthereumWallet {
	/// Remove recovery material that is not needed for runtime Ethereum signing.
	/// The derived private key remains available for transactions.
	pub fn discard_recovery_material(&mut self) {
		self.password.zeroize();
		self.mnemonic.zeroize();
		self.extended_private_key.zeroize();
	}

	///new eth wallet from random
	pub fn new<R: TryCryptoRng>(rng: &mut R) -> Result<Self, EthError> {
		let private_key = EthereumPrivateKey::new(rng)?;
		let public_key = private_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		// Reserve the full hex encoding so reallocations cannot leave secret fragments.
		// Store the buffer in the wallet before writing so errors also trigger zeroization.
		let private_key_hex = wallet.private_key.insert(String::with_capacity(64));
		write!(private_key_hex, "{}", private_key)
			.map_err(|error| EthError::Crate("fmt", error.to_string()))?;
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth hd wallet
	pub fn new_hd<N: EthereumNetwork, W: EthereumWordlist, R: TryCryptoRng>(
		rng: &mut R,
		word_count: u8,
		password: Option<&str>,
		path: &str,
	) -> Result<Self, EthError> {
		let mnemonic = EthereumMnemonic::<N, W>::new_with_count(rng, word_count)?;
		let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
		let derivation_path = EthereumDerivationPath::from_str(path)?;
		let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
		let extended_public_key = extended_private_key.to_extended_public_key();
		let private_key = extended_private_key.to_private_key();
		let public_key = extended_public_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		wallet.path = Some(path.to_string());
		wallet.password = password.map(String::from);
		wallet.mnemonic = Some(mnemonic.to_string());
		wallet.extended_private_key = Some(extended_private_key.to_string());
		wallet.extended_public_key = Some(extended_public_key.to_string());
		wallet.private_key = Some(private_key.to_string());
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from mnemonic
	pub fn from_mnemonic<N: EthereumNetwork, W: EthereumWordlist>(
		mnemonic: &str,
		password: Option<&str>,
		path: &str,
	) -> Result<Self, EthError> {
		let mnemonic = EthereumMnemonic::<N, W>::from_phrase(&mnemonic)?;
		let master_extended_private_key = mnemonic.to_extended_private_key(password)?;
		let derivation_path = EthereumDerivationPath::from_str(path)?;
		let extended_private_key = master_extended_private_key.derive(&derivation_path)?;
		let extended_public_key = extended_private_key.to_extended_public_key();
		let private_key = extended_private_key.to_private_key();
		let public_key = extended_public_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		wallet.path = Some(path.to_string());
		wallet.password = password.map(String::from);
		wallet.mnemonic = Some(mnemonic.to_string());
		wallet.extended_private_key = Some(extended_private_key.to_string());
		wallet.extended_public_key = Some(extended_public_key.to_string());
		// Reserve the full hex encoding so reallocations cannot leave secret fragments.
		// Store the buffer in the wallet before writing so errors also trigger zeroization.
		let private_key_hex = wallet.private_key.insert(String::with_capacity(64));
		write!(private_key_hex, "{}", private_key)
			.map_err(|error| EthError::Crate("fmt", error.to_string()))?;
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from specified extened private key
	pub fn from_extended_private_key<N: EthereumNetwork>(
		extended_private_key: &str,
		path: &Option<String>,
	) -> Result<Self, EthError> {
		let mut extended_private_key =
			EthereumExtendedPrivateKey::<N>::from_str(extended_private_key)?;
		if let Some(derivation_path) = path {
			let derivation_path = EthereumDerivationPath::from_str(&derivation_path)?;
			extended_private_key = extended_private_key.derive(&derivation_path)?;
		}
		let extended_public_key = extended_private_key.to_extended_public_key();
		let private_key = extended_private_key.to_private_key();
		let public_key = extended_public_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		wallet.path = path.clone();
		wallet.extended_private_key = Some(extended_private_key.to_string());
		wallet.extended_public_key = Some(extended_public_key.to_string());
		wallet.private_key = Some(private_key.to_string());
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from specified extened public key
	pub fn from_extended_public_key<N: EthereumNetwork>(
		extended_public_key: &str,
		path: &Option<String>,
	) -> Result<Self, EthError> {
		let mut extended_public_key =
			EthereumExtendedPublicKey::<N>::from_str(extended_public_key)?;
		if let Some(derivation_path) = path {
			let derivation_path = EthereumDerivationPath::from_str(&derivation_path)?;
			extended_public_key = extended_public_key.derive(&derivation_path)?;
		}
		let public_key = extended_public_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		wallet.path = path.clone();
		wallet.extended_public_key = Some(extended_public_key.to_string());
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from private key
	pub fn from_private_key(private_key: &str) -> Result<Self, EthError> {
		let private_key = EthereumPrivateKey::from_str(private_key)?;
		let public_key = private_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		// Reserve the full hex encoding so reallocations cannot leave secret fragments.
		// Store the buffer in the wallet before writing so errors also trigger zeroization.
		let private_key_hex = wallet.private_key.insert(String::with_capacity(64));
		write!(private_key_hex, "{}", private_key)
			.map_err(|error| EthError::Crate("fmt", error.to_string()))?;
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from public key
	pub fn from_public_key(public_key: &str) -> Result<Self, EthError> {
		let public_key = EthereumPublicKey::from_str(public_key)?;
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		let mut wallet = Self::default();
		wallet.public_key = Some(public_key.to_string());
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}

	///new eth wallet from eth key
	pub fn from_address(address: &str) -> Result<Self, EthError> {
		let address = EthereumAddress::from_str(address)?;
		let mut wallet = Self::default();
		wallet.address = Some(address.to_string());
		Ok(wallet)
	}
}

impl Display for EthereumWallet {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// Borrow field values so formatting does not leave temporary copies of secrets.
		for (label, padding, value) in [
			("Path", "                 ", &self.path),
			("Password", "             ", &self.password),
			("Mnemonic", "             ", &self.mnemonic),
			("Extended Private Key", " ", &self.extended_private_key),
			("Extended Public Key", "  ", &self.extended_public_key),
			("Private Key", "          ", &self.private_key),
			("Public Key", "           ", &self.public_key),
			("Address", "              ", &self.address),
			("Transaction Id", "       ", &self.transaction_id),
			("Network", "              ", &self.network),
			("Transaction Hex", "      ", &self.transaction_hex),
		] {
			if let Some(value) = value {
				// Prefix each line to avoid trimming a trailing newline or failing on an empty wallet.
				write!(f, "\n      {}{}{}", label.cyan().bold(), padding, value)?;
			}
		}
		Ok(())
	}
}

/// Generate an Ethereum wallet from a mnemonic without a BIP39 passphrase.
/// The mutable wallet-file encryption password must not affect Ethereum keys.
pub fn generate_ethereum_wallet(
	network: &str,
	mnemonic: &str,
	path: &str,
) -> Result<EthereumWallet, Error> {
	let ethereum_wallet = match network {
		"mainnet" => EthereumWallet::from_mnemonic::<Mainnet, English>(mnemonic, None, path),
		_ => EthereumWallet::from_mnemonic::<Ropsten, English>(mnemonic, None, path),
	};

	match ethereum_wallet {
		Ok(w) => Ok(w),
		Err(e) => {
			Err(Error::EthereumWalletError(format!("create ethereum wallet failed!, {}", e)).into())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ethereum_wallet_display_handles_empty_wallet() {
		let wallet = EthereumWallet::default();
		assert_eq!(wallet.to_string(), "");
		assert_eq!(format!("{}", wallet), "");
	}

	#[test]
	fn ethereum_wallet_display_preserves_layout_and_values() {
		let mut wallet = EthereumWallet {
			path: Some("test-path".into()),
			password: Some("test-password".into()),
			mnemonic: Some("test-mnemonic".into()),
			extended_private_key: Some("test-extended-private-key".into()),
			extended_public_key: Some("test-extended-public-key".into()),
			private_key: Some("test-private-key".into()),
			public_key: Some("test-public-key".into()),
			address: Some("test-address".into()),
			transaction_id: Some("test-transaction-id".into()),
			network: Some("test-network".into()),
			transaction_hex: Some("test-transaction-hex".into()),
		};
		assert_eq!(
			wallet.to_string(),
			format!(
				concat!(
					"\n      {}                 test-path",
					"\n      {}             test-password",
					"\n      {}             test-mnemonic",
					"\n      {} test-extended-private-key",
					"\n      {}  test-extended-public-key",
					"\n      {}          test-private-key",
					"\n      {}           test-public-key",
					"\n      {}              test-address",
					"\n      {}       test-transaction-id",
					"\n      {}              test-network",
					"\n      {}      test-transaction-hex",
				),
				"Path".cyan().bold(),
				"Password".cyan().bold(),
				"Mnemonic".cyan().bold(),
				"Extended Private Key".cyan().bold(),
				"Extended Public Key".cyan().bold(),
				"Private Key".cyan().bold(),
				"Public Key".cyan().bold(),
				"Address".cyan().bold(),
				"Transaction Id".cyan().bold(),
				"Network".cyan().bold(),
				"Transaction Hex".cyan().bold(),
			)
		);

		wallet.zeroize();
		assert_eq!(wallet.to_string(), "");
		wallet.password = Some(String::new());
		wallet.address = Some("unicode-é-🔑\n".into());
		assert_eq!(
			wallet.to_string(),
			format!(
				"\n      {}             \n      {}              unicode-é-🔑\n",
				"Password".cyan().bold(),
				"Address".cyan().bold(),
			)
		);
	}

	#[test]
	fn ethereum_wallet_display_borrows_secret_values() {
		struct SecretWriter<'a> {
			secrets: [&'a str; 4],
			seen: [bool; 4],
		}

		impl fmt::Write for SecretWriter<'_> {
			fn write_str(&mut self, s: &str) -> fmt::Result {
				for (index, secret) in self.secrets.iter().enumerate() {
					if s.contains(*secret) {
						// The writer must receive the original field, not a temporary copy.
						assert_eq!(s.as_ptr(), secret.as_ptr());
						assert_eq!(s.len(), secret.len());
						self.seen[index] = true;
					}
				}
				Ok(())
			}
		}

		let mut wallet = EthereumWallet::default();
		wallet.password = Some("test-password".into());
		wallet.mnemonic = Some("test-mnemonic".into());
		wallet.extended_private_key = Some("test-extended-private-key".into());
		wallet.private_key = Some("test-private-key".into());
		let mut writer = SecretWriter {
			secrets: [
				wallet.password.as_deref().unwrap(),
				wallet.mnemonic.as_deref().unwrap(),
				wallet.extended_private_key.as_deref().unwrap(),
				wallet.private_key.as_deref().unwrap(),
			],
			seen: [false; 4],
		};
		write!(&mut writer, "{}", wallet).unwrap();
		assert_eq!(writer.seen, [true; 4]);
	}

	#[test]
	fn ethereum_wallet_display_propagates_writer_errors() {
		struct FailAfter {
			remaining: usize,
			failed: bool,
		}

		impl fmt::Write for FailAfter {
			fn write_str(&mut self, s: &str) -> fmt::Result {
				assert!(!self.failed, "writing continued after an error");
				if let Some(remaining) = self.remaining.checked_sub(s.len()) {
					self.remaining = remaining;
					Ok(())
				} else {
					self.failed = true;
					Err(fmt::Error)
				}
			}
		}

		let mut wallet = EthereumWallet::default();
		wallet.private_key = Some("test-private-key".into());
		wallet.address = Some("test-address".into());
		for remaining in 0..wallet.to_string().len() {
			let mut writer = FailAfter {
				remaining,
				failed: false,
			};
			assert!(write!(&mut writer, "{}", wallet).is_err());
			assert!(writer.failed);
		}
	}

	#[test]
	fn generated_ethereum_wallet_does_not_use_a_bip39_passphrase() {
		const MNEMONIC: &str =
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		const PATH: &str = "m/44'/0'/0'/0";

		let generated = generate_ethereum_wallet("mainnet", MNEMONIC, PATH).unwrap();
		let without_passphrase =
			EthereumWallet::from_mnemonic::<Mainnet, English>(MNEMONIC, None, PATH).unwrap();
		let with_wallet_password = EthereumWallet::from_mnemonic::<Mainnet, English>(
			MNEMONIC,
			Some("wallet-password"),
			PATH,
		)
		.unwrap();

		assert_eq!(generated.address, without_passphrase.address);
		assert_ne!(generated.address, with_wallet_password.address);
		assert!(generated.password.is_none());
	}

	#[test]
	fn ethereum_wallet_zeroizes_on_drop_and_redacts_debug_secrets() {
		fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

		assert_zeroize_on_drop::<EthereumWallet>();
		let mut wallet = EthereumWallet::default();
		wallet.password = Some("wallet-password".to_string());
		wallet.mnemonic = Some("secret mnemonic".to_string());
		wallet.private_key = Some("secret-private-key".to_string());
		let debug = format!("{:?}", wallet);
		assert!(!debug.contains("wallet-password"));
		assert!(!debug.contains("secret mnemonic"));
		assert!(!debug.contains("secret-private-key"));
	}

	#[test]
	fn discarding_recovery_material_preserves_runtime_signing_key() {
		let mut wallet = EthereumWallet::default();
		wallet.password = Some("wallet-password".to_string());
		wallet.mnemonic = Some("secret mnemonic".to_string());
		wallet.extended_private_key = Some("secret-extended-private-key".to_string());
		wallet.private_key = Some("runtime-private-key".to_string());

		wallet.discard_recovery_material();

		assert!(wallet.password.is_none());
		assert!(wallet.mnemonic.is_none());
		assert!(wallet.extended_private_key.is_none());
		assert_eq!(wallet.private_key.as_deref(), Some("runtime-private-key"));
	}
}
