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

use crate::ErrorKind;
use colored::*;
use failure::Fail;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Display, str::FromStr};

use wagyu_ethereum::{
	wordlist::*, EthereumAddress, EthereumDerivationPath, EthereumExtendedPrivateKey,
	EthereumExtendedPublicKey, EthereumFormat, EthereumMnemonic, EthereumNetwork,
	EthereumPrivateKey, EthereumPublicKey, Mainnet, Ropsten,
};
use wagyu_model::{
	AddressError, AmountError, DerivationPathError, ExtendedPrivateKey, ExtendedPrivateKeyError,
	ExtendedPublicKey, ExtendedPublicKeyError, Mnemonic, MnemonicCount, MnemonicError,
	MnemonicExtended, PrivateKey, PrivateKeyError, PublicKey, PublicKeyError, TransactionError,
};

/// Ethereum Error
#[derive(Debug, Fail)]
pub enum EthError {
	/// Address error
	#[fail(display = "{}", _0)]
	AddressError(AddressError),
	/// Amount error
	#[fail(display = "{}", _0)]
	AmountError(AmountError),
	/// Crate error
	#[fail(display = "{}: {}", _0, _1)]
	Crate(&'static str, String),
	/// Derivation Path Error
	#[fail(display = "{}", _0)]
	DerivationPathError(DerivationPathError),
	/// ExtendedPrivateKey Error
	#[fail(display = "{}", _0)]
	ExtendedPrivateKeyError(ExtendedPrivateKeyError),
	/// ExtendedPublicKey Error
	#[fail(display = "{}", _0)]
	ExtendedPublicKeyError(ExtendedPublicKeyError),
	/// InvalidMnemonicForPrivateSpendKey
	#[fail(display = "invalid derived mnemonic for a given private spend key")]
	InvalidMnemonicForPrivateSpendKey,
	/// PrivateKeyError
	#[fail(display = "{}", _0)]
	PrivateKeyError(PrivateKeyError),
	/// PublicKeyError
	#[fail(display = "{}", _0)]
	PublicKeyError(PublicKeyError),
	/// MnemonicError
	#[fail(display = "{}", _0)]
	MnemonicError(MnemonicError),
	/// TransactionError
	#[fail(display = "{}", _0)]
	TransactionError(TransactionError),
	/// Unsupported Mnemonic Language
	#[fail(display = "unsupported mnemonic language")]
	UnsupportedLanguage,
}

impl From<AddressError> for EthError {
	fn from(error: AddressError) -> Self {
		EthError::AddressError(error)
	}
}

impl From<AmountError> for EthError {
	fn from(error: AmountError) -> Self {
		EthError::AmountError(error)
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
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
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

impl EthereumWallet {
	///new eth wallet from random
	pub fn new<R: Rng>(rng: &mut R) -> Result<Self, EthError> {
		let private_key = EthereumPrivateKey::new(rng)?;
		let public_key = private_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		Ok(Self {
			private_key: Some(private_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
	}

	///new eth hd wallet
	pub fn new_hd<N: EthereumNetwork, W: EthereumWordlist, R: Rng>(
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
		Ok(Self {
			path: Some(path.to_string()),
			password: password.map(String::from),
			mnemonic: Some(mnemonic.to_string()),
			extended_private_key: Some(extended_private_key.to_string()),
			extended_public_key: Some(extended_public_key.to_string()),
			private_key: Some(private_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
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
		Ok(Self {
			path: Some(path.to_string()),
			password: password.map(String::from),
			mnemonic: Some(mnemonic.to_string()),
			extended_private_key: Some(extended_private_key.to_string()),
			extended_public_key: Some(extended_public_key.to_string()),
			private_key: Some(private_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
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
		Ok(Self {
			path: path.clone(),
			extended_private_key: Some(extended_private_key.to_string()),
			extended_public_key: Some(extended_public_key.to_string()),
			private_key: Some(private_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
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
		Ok(Self {
			path: path.clone(),
			extended_public_key: Some(extended_public_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
	}

	///new eth wallet from private key
	pub fn from_private_key(private_key: &str) -> Result<Self, EthError> {
		let private_key = EthereumPrivateKey::from_str(private_key)?;
		let public_key = private_key.to_public_key();
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		Ok(Self {
			private_key: Some(private_key.to_string()),
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
	}

	///new eth wallet from public key
	pub fn from_public_key(public_key: &str) -> Result<Self, EthError> {
		let public_key = EthereumPublicKey::from_str(public_key)?;
		let address = public_key.to_address(&EthereumFormat::Standard)?;
		Ok(Self {
			public_key: Some(public_key.to_string()),
			address: Some(address.to_string()),
			..Default::default()
		})
	}

	///new eth wallet from eth key
	pub fn from_address(address: &str) -> Result<Self, EthError> {
		let address = EthereumAddress::from_str(address)?;
		Ok(Self {
			address: Some(address.to_string()),
			..Default::default()
		})
	}
}

impl Display for EthereumWallet {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let output = [
			match &self.path {
				Some(path) => format!("      {}                 {}\n", "Path".cyan().bold(), path),
				_ => "".to_owned(),
			},
			match &self.password {
				Some(password) => format!(
					"      {}             {}\n",
					"Password".cyan().bold(),
					password
				),
				_ => "".to_owned(),
			},
			match &self.mnemonic {
				Some(mnemonic) => format!(
					"      {}             {}\n",
					"Mnemonic".cyan().bold(),
					mnemonic
				),
				_ => "".to_owned(),
			},
			match &self.extended_private_key {
				Some(extended_private_key) => format!(
					"      {} {}\n",
					"Extended Private Key".cyan().bold(),
					extended_private_key
				),
				_ => "".to_owned(),
			},
			match &self.extended_public_key {
				Some(extended_public_key) => format!(
					"      {}  {}\n",
					"Extended Public Key".cyan().bold(),
					extended_public_key
				),
				_ => "".to_owned(),
			},
			match &self.private_key {
				Some(private_key) => format!(
					"      {}          {}\n",
					"Private Key".cyan().bold(),
					private_key
				),
				_ => "".to_owned(),
			},
			match &self.public_key {
				Some(public_key) => format!(
					"      {}           {}\n",
					"Public Key".cyan().bold(),
					public_key
				),
				_ => "".to_owned(),
			},
			match &self.address {
				Some(address) => format!(
					"      {}              {}\n",
					"Address".cyan().bold(),
					address
				),
				_ => "".to_owned(),
			},
			match &self.transaction_id {
				Some(transaction_id) => format!(
					"      {}       {}\n",
					"Transaction Id".cyan().bold(),
					transaction_id
				),
				_ => "".to_owned(),
			},
			match &self.network {
				Some(network) => format!(
					"      {}              {}\n",
					"Network".cyan().bold(),
					network
				),
				_ => "".to_owned(),
			},
			match &self.transaction_hex {
				Some(transaction_hex) => {
					format!(
						"      {}      {}\n",
						"Transaction Hex".cyan().bold(),
						transaction_hex
					)
				}
				_ => "".to_owned(),
			},
		]
		.concat();

		// Removes final new line character
		let output = output[..output.len() - 1].to_owned();
		write!(f, "\n{}", output)
	}
}

///genereate ethereum_wallet by
pub fn generate_ethereum_wallet(
	network: &str,
	mnemonic: &str,
	password: &str,
	path: &str,
) -> Result<EthereumWallet, ErrorKind> {
	let ethereum_wallet = match network {
		"mainnet" => {
			EthereumWallet::from_mnemonic::<Mainnet, English>(mnemonic, Some(password), path)
		}
		_ => EthereumWallet::from_mnemonic::<Ropsten, English>(mnemonic, Some(password), path),
	};

	match ethereum_wallet {
		Ok(w) => Ok(w),
		Err(e) => Err(ErrorKind::EthereumWalletError(format!(
			"create ethereum wallet failed!, {}",
			e
		))
		.into()),
	}
}
