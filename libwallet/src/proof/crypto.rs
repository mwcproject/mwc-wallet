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

use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Message, Secp256k1};
use mwc_wallet_util::mwc_util;
use std::convert::TryInto;

use super::base58;
use crate::error::Error;
use mwc_wallet_util::mwc_crates::sha2::{Digest, Sha256};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;

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
	signature: &EcdsaSignature,
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
) -> Result<EcdsaSignature, Error> {
	let mut hasher = Sha256::new();
	hasher.update(challenge.as_bytes());
	let message = Message::from_slice(hasher.finalize().as_slice())?;
	secp.sign(&message, secret_key).map_err(|e| Error::from(e))
}

/// convert to a signature from string
pub fn signature_from_string(sig_str: &str, secp: &Secp256k1) -> Result<EcdsaSignature, Error> {
	let signature_ser = mwc_util::from_hex(sig_str)
		.map_err(|_| Error::TxProofVerify("Unable to decode signature HEX".to_string()))?;
	let signature = EcdsaSignature::from_der(secp, &signature_ser)
		.map_err(|e| Error::TxProofVerify(format!("Unable to build signature, {}", e)))?;
	Ok(signature)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/// to and from Hex conversion
pub trait Hex<T, Output = String> {
	/// HEX to object conversion
	fn from_hex(secp: &Secp256k1, str: &str) -> Result<T, Error>;
	/// Object to HEX conversion
	fn to_hex(&self, secp: &Secp256k1) -> Result<Output, Error>;
}

impl Hex<PublicKey> for PublicKey {
	fn from_hex(secp: &Secp256k1, str: &str) -> Result<PublicKey, Error> {
		let hex = mwc_util::from_hex(str)
			.map_err(|_| Error::HexError("Unable to decode public key HEX".to_string()))?;
		PublicKey::from_slice(secp, &hex).map_err(|e| {
			Error::HexError(format!(
				"Unable to build public key from decoded bytes, {}",
				e
			))
		})
	}

	fn to_hex(&self, secp: &Secp256k1) -> Result<String, Error> {
		Ok(mwc_util::to_hex(&base58::serialize_public_key(secp, self)?))
	}
}

impl Hex<EcdsaSignature> for EcdsaSignature {
	fn from_hex(secp: &Secp256k1, str: &str) -> Result<EcdsaSignature, Error> {
		let hex = mwc_util::from_hex(str)
			.map_err(|_| Error::HexError("Unable to decode signature HEX".to_string()))?;
		EcdsaSignature::from_der(secp, &hex).map_err(|e| {
			Error::HexError(format!(
				"Unable to build signature from decoded bytes, {}",
				e
			))
		})
	}

	fn to_hex(&self, secp: &Secp256k1) -> Result<String, Error> {
		let signature = self.serialize_der(secp)?;
		Ok(mwc_util::to_hex(&signature))
	}
}

impl Hex<ed25519_dalek::VerifyingKey> for ed25519_dalek::VerifyingKey {
	fn from_hex(_secp: &Secp256k1, str: &str) -> Result<ed25519_dalek::VerifyingKey, Error> {
		let hex = mwc_util::from_hex(str)
			.map_err(|_| Error::HexError("Unable to decode public key HEX".to_string()))?;

		let bytes: [u8; 32] = hex.as_slice().try_into().map_err(|_| {
			Error::HexError(format!(
				"Unable to build public key from decoded bytes, wrong length {}",
				hex.len()
			))
		})?;

		let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|e| {
			Error::HexError(format!(
				"Unable to build public key from decoded bytes, {}",
				e
			))
		})?;

		if key.is_weak() {
			return Err(Error::HexError(
				"Unable to build public key from decoded bytes, key has small order".to_string(),
			));
		}

		Ok(key)
	}

	fn to_hex(&self, _secp: &Secp256k1) -> Result<String, Error> {
		Ok(mwc_util::to_hex(self.as_bytes()))
	}
}

impl Hex<ed25519_dalek::Signature> for ed25519_dalek::Signature {
	fn from_hex(_secp: &Secp256k1, str: &str) -> Result<ed25519_dalek::Signature, Error> {
		let hex = mwc_util::from_hex(str)
			.map_err(|_| Error::HexError("Unable to decode signature HEX".to_string()))?;

		let bytes: [u8; 64] = hex.as_slice().try_into().map_err(|_| {
			Error::HexError(format!(
				"Unable to build signature from decoded bytes, wrong length {}",
				hex.len()
			))
		})?;

		Ok(ed25519_dalek::Signature::from_bytes(&bytes))
	}

	fn to_hex(&self, _secp: &Secp256k1) -> Result<String, Error> {
		Ok(mwc_util::to_hex(&self.clone().to_bytes()))
	}
}

impl Hex<SecretKey, Zeroizing<String>> for SecretKey {
	fn from_hex(secp: &Secp256k1, str: &str) -> Result<SecretKey, Error> {
		let data = mwc_util::decode_secret_key_hex::<32>(str)
			.map_err(|e| Error::HexError(format!("Unable convert key HEX, {}", e)))?;
		SecretKey::from_slice(secp, data.as_ref())
			.map_err(|e| Error::HexError(format!("Unable to build Key from HEX, {}", e)))
	}

	fn to_hex(&self, _secp: &Secp256k1) -> Result<Zeroizing<String>, Error> {
		Ok(Zeroizing::new(mwc_util::to_hex(&self.0)))
	}
}

impl Hex<Commitment> for Commitment {
	fn from_hex(secp: &Secp256k1, str: &str) -> Result<Commitment, Error> {
		let data = mwc_util::from_hex(str)
			.map_err(|_| Error::HexError("Unable to decode commitment HEX".to_string()))?;
		let commitment = Commitment::from_vec(data)?;
		secp.validate_commitment(&commitment)?;
		Ok(commitment)
	}

	fn to_hex(&self, _secp: &Secp256k1) -> Result<String, Error> {
		Ok(mwc_util::to_hex(&self.0))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse_error<T>(result: Result<T, Error>) -> Error {
		result.err().expect("malicious input must fail to parse")
	}

	fn assert_terminal_safe(error: Error, untrusted: &str) {
		let message = error.to_string();
		assert!(
			!message.contains(untrusted),
			"error contains attacker-controlled input: {:?}",
			message
		);
		assert!(
			!message.chars().any(char::is_control),
			"error contains terminal control characters: {:?}",
			message
		);
	}

	#[test]
	fn parse_errors_do_not_echo_untrusted_input() {
		let secp = Secp256k1::new().unwrap();
		let terminal_payload = "\u{1b}]52;c;dGVzdA==\u{7}\rspoof";
		let errors = [
			parse_error(signature_from_string(terminal_payload, &secp)),
			parse_error(PublicKey::from_hex(&secp, terminal_payload)),
			parse_error(EcdsaSignature::from_hex(&secp, terminal_payload)),
			parse_error(ed25519_dalek::VerifyingKey::from_hex(
				&secp,
				terminal_payload,
			)),
			parse_error(ed25519_dalek::Signature::from_hex(&secp, terminal_payload)),
			parse_error(SecretKey::from_hex(&secp, terminal_payload)),
			parse_error(Commitment::from_hex(&secp, terminal_payload)),
		];

		for error in errors {
			assert_terminal_safe(error, terminal_payload);
		}
	}

	#[test]
	fn verifying_key_from_hex_rejects_small_order_key() {
		let secp = Secp256k1::new().unwrap();
		let mut identity = [0u8; 32];
		identity[0] = 1;

		let error = ed25519_dalek::VerifyingKey::from_hex(&secp, &mwc_util::to_hex(&identity))
			.expect_err("small-order public key must be rejected");

		assert!(matches!(
			error,
			Error::HexError(message) if message.contains("small order")
		));
	}

	#[test]
	fn secret_key_to_hex_returns_zeroizing_string() {
		let secp = Secp256k1::new().unwrap();
		let mut bytes = [0u8; 32];
		bytes[31] = 1;
		let secret_key = SecretKey::from_slice(&secp, &bytes).unwrap();

		let encoded: Zeroizing<String> = secret_key.to_hex(&secp).unwrap();

		assert_eq!(
			encoded.as_str(),
			"0000000000000000000000000000000000000000000000000000000000000001"
		);
	}

	#[test]
	fn commitment_from_hex_rejects_invalid_commitment() {
		let secp = Secp256k1::new().unwrap();
		let invalid_commitment = mwc_util::to_hex(&[0u8; 33]);

		assert!(Commitment::from_hex(&secp, &invalid_commitment).is_err());
	}
}
