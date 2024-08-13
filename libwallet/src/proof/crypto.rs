// Copyright 2020 The MWC Developers
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

use grin_wallet_util::grin_util::secp::key::{PublicKey, SecretKey};
use grin_wallet_util::grin_util::secp::pedersen::Commitment;
use grin_wallet_util::grin_util::secp::{ContextFlag, Message, Secp256k1, Signature};

use super::base58;
use crate::error::Error;
use crate::grin_util as util;
use sha2::{Digest, Sha256};

/// Build a public key for the given private key
pub fn public_key_from_secret_key(
	secp: &Secp256k1,
	secret_key: &SecretKey,
) -> Result<PublicKey, Error> {
	PublicKey::from_secret_key(&secp, secret_key).map_err(|e| Error::from(e))
}

/// Verify signature, usual way
pub fn verify_signature(
	challenge: &str,
	signature: &Signature,
	public_key: &PublicKey,
	secp: &Secp256k1,
) -> Result<(), Error> {
	let mut hasher = Sha256::new();
	hasher.update(challenge.as_bytes());
	let message = Message::from_slice(hasher.finalize().as_slice())?;
	secp.verify(&message, signature, public_key)
		.map_err(|e| Error::from(e))?;
	Ok(())
}

/// Sing the challenge with a private key.
pub fn sign_challenge(
	challenge: &str,
	secret_key: &SecretKey,
	secp: &Secp256k1,
) -> Result<Signature, Error> {
	let mut hasher = Sha256::new();
	hasher.update(challenge.as_bytes());
	let message = Message::from_slice(hasher.finalize().as_slice())?;
	secp.sign(&message, secret_key).map_err(|e| Error::from(e))
}

/// convert to a signature from string
pub fn signature_from_string(sig_str: &str, secp: &Secp256k1) -> Result<Signature, Error> {
	let signature_ser = util::from_hex(sig_str).map_err(|e| {
		Error::TxProofGenericError(format!(
			"Unable to build signature from HEX {}, {}",
			sig_str, e
		))
	})?;
	let signature = Signature::from_der(secp, &signature_ser)
		.map_err(|e| Error::TxProofGenericError(format!("Unable to build signature, {}", e)))?;
	Ok(signature)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/// to and from Hex conversion
pub trait Hex<T> {
	/// HEX to object conversion
	fn from_hex(str: &str) -> Result<T, Error>;
	/// Object to HEX conversion
	fn to_hex(&self) -> String;
}

impl Hex<PublicKey> for PublicKey {
	fn from_hex(str: &str) -> Result<PublicKey, Error> {
		let hex = util::from_hex(str)
			.map_err(|e| Error::HexError(format!("Unable convert Publi Key HEX {}, {}", str, e)))?;
		let secp = Secp256k1::with_caps(ContextFlag::None);
		PublicKey::from_slice(&secp, &hex).map_err(|e| {
			Error::HexError(format!(
				"Unable to build public key from HEX {}, {}",
				str, e
			))
		})
	}

	fn to_hex(&self) -> String {
		let secp = Secp256k1::with_caps(ContextFlag::None);
		util::to_hex(&base58::serialize_public_key(&secp, self))
	}
}

impl Hex<Signature> for Signature {
	fn from_hex(str: &str) -> Result<Signature, Error> {
		let hex = util::from_hex(str)
			.map_err(|e| Error::HexError(format!("Unable convert Signature HEX {}, {}", str, e)))?;
		let secp = Secp256k1::with_caps(ContextFlag::None);
		Signature::from_der(&secp, &hex).map_err(|e| {
			Error::HexError(format!("Unable to build Signature from HEX {}, {}", str, e))
		})
	}

	fn to_hex(&self) -> String {
		let secp = Secp256k1::with_caps(ContextFlag::None);
		let signature = self.serialize_der(&secp);
		util::to_hex(&signature)
	}
}

impl Hex<SecretKey> for SecretKey {
	fn from_hex(str: &str) -> Result<SecretKey, Error> {
		let data = util::from_hex(str)
			.map_err(|e| Error::HexError(format!("Unable convert key HEX, {}", e)))?;
		let secp = Secp256k1::with_caps(ContextFlag::None);
		SecretKey::from_slice(&secp, &data)
			.map_err(|e| Error::HexError(format!("Unable to build Key from HEX, {}", e)))
	}

	fn to_hex(&self) -> String {
		util::to_hex(&self.0)
	}
}

impl Hex<Commitment> for Commitment {
	fn from_hex(str: &str) -> Result<Commitment, Error> {
		let data = util::from_hex(str).map_err(|e| {
			Error::HexError(format!("Unable convert Commitment HEX {}, {}", str, e))
		})?;
		Ok(Commitment::from_vec(data))
	}

	fn to_hex(&self) -> String {
		util::to_hex(&self.0)
	}
}
