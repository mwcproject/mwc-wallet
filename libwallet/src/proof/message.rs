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

#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::rand::RngExt;
use mwc_wallet_util::mwc_crates::rand::{TryRng, rngs::SysRng};
use mwc_wallet_util::mwc_crates::ring;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_util;

use super::proofaddress;
use crate::error::Error;

#[cfg(feature = "test-support")]
use crate::step_rng::StepRng;
use mwc_wallet_util::mwc_crates::ring::aead;
use mwc_wallet_util::mwc_crates::ring::pbkdf2;
use std::mem::MaybeUninit;
use std::num::NonZeroU32;

const MAX_ENCRYPTED_MESSAGE_ERROR_DISPLAY_LEN: usize = 256;
const MAX_NONCE_ERROR_DISPLAY_LEN: usize = 64;

/// Encrypted message, used for Tx Proofs
#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct EncryptedMessage {
	/// Destination dddress for that massage
	pub destination: proofaddress::ProvableAddress,
	/// Encrypted message (normally it is a slate)
	encrypted_message: String,
	/// salt value
	salt: String,
	/// Nonce value
	nonce: String,
}

// See comments at  mwc-wallet/impls/src/seed.rs
// Seed is encrypted exactly the same way ...

fn secure_salt_and_nonce() -> Result<([u8; 8], [u8; 12]), Error> {
	let mut salt = [0u8; 8];
	let mut nonce = [0u8; 12];
	SysRng
		.try_fill_bytes(&mut salt)
		.map_err(|e| Error::PaymentProof(format!("Unable to generate message salt, {}", e)))?;
	SysRng
		.try_fill_bytes(&mut nonce)
		.map_err(|e| Error::PaymentProof(format!("Unable to generate message nonce, {}", e)))?;
	Ok((salt, nonce))
}

/// Derive the legacy message key from the raw x-coordinate of the ECDH point.
///
/// `PublicKey::mul_assign` mutates a public-key value into sensitive shared-point
/// material, but `PublicKey` itself is `Copy` and has no zeroizing destructor.
/// Keeping it inside `Zeroizing<MaybeUninit<_>>` lets zeroize overwrite its full
/// backing storage on every return path without requiring an invalid zero
/// `PublicKey` value.
///
/// Despite its name, `PublicKey::serialize_vec` returns a fixed-capacity
/// `ArrayVec`, not a heap-backed `Vec`. Its backing bytes are stored inline, so
/// zeroizing the enclosing `MaybeUninit<ArrayVec<...>>` erases the serialized
/// shared point itself and cannot orphan a heap allocation. Keep the serialized
/// point in this guard unless its return type changes to a zeroizing type.
///
/// SECURITY/AUDIT NOTE: This legacy wire-compatible derivation uses
/// `PublicKey::mul_assign` and public-key serialization on secret-derived data.
/// Those operations are not constant-time, so we accept a timing side-channel
/// risk here. Replacing them with the available constant-time ECDH helper would
/// change the derived key and break compatibility with existing MQS messages;
/// removing this risk requires a versioned MQS key-derivation migration.
fn derive_message_key(
	public_key: &PublicKey,
	secret_key: &SecretKey,
	secp: &Secp256k1,
	salt: &[u8],
	operation: &str,
	multiplication_error: &str,
) -> Result<Zeroizing<[u8; 32]>, Error> {
	let mut common_secret_guard = Zeroizing::new(MaybeUninit::uninit());
	let common_secret = (&mut *common_secret_guard).write(*public_key);
	common_secret
		.mul_assign(secp, secret_key)
		.map_err(|e| Error::PaymentProof(format!("{}, {}", multiplication_error, e)))?;
	let mut common_secret_ser_guard = Zeroizing::new(MaybeUninit::uninit());
	let common_secret_ser =
		(&mut *common_secret_ser_guard).write(common_secret.serialize_vec(secp, true)?);
	let common_secret_slice = common_secret_ser.get(1..33).ok_or_else(|| {
		Error::PaymentProof(format!(
			"{}, serialized shared secret has invalid length, serialized_len={} required_len=33",
			operation,
			common_secret_ser.len()
		))
	})?;

	let mut key = Zeroizing::new([0; 32]);
	pbkdf2::derive(
		ring::pbkdf2::PBKDF2_HMAC_SHA512,
		NonZeroU32::new(100).ok_or_else(|| {
			Error::PaymentProof("PBKDF2 iteration count must be non-zero".to_string())
		})?,
		salt,
		common_secret_slice,
		&mut *key,
	);
	Ok(key)
}

impl EncryptedMessage {
	/// Construct new instance
	pub fn new(
		message: String,
		destination: &proofaddress::ProvableAddress,
		receiver_public_key: &PublicKey,
		secret_key: &SecretKey,
		secp: &Secp256k1,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<EncryptedMessage, Error> {
		// This payload is intentionally shared with the peer, so it is less sensitive
		// than a long-lived wallet key. It can still contain short-lived secret
		// scalars, so erase the local plaintext allocation on every return path.
		let message = Zeroizing::new(message);

		#[cfg(feature = "test-support")]
		let (salt, nonce) = if use_test_rng {
			let mut test_rng = StepRng::new(1_234_567_891_u64, 1);
			(test_rng.random(), test_rng.random())
		} else {
			secure_salt_and_nonce()?
		};
		#[cfg(not(feature = "test-support"))]
		let (salt, nonce) = secure_salt_and_nonce()?;

		let key = derive_message_key(
			receiver_public_key,
			secret_key,
			secp,
			&salt,
			"EncryptedMessage::new",
			"Unable to encrypt message",
		)?;
		let mut enc_bytes = Zeroizing::new(message.as_bytes().to_vec());
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &*key)
			.map_err(|e| Error::PaymentProof(format!("Unable to build a key, {}", e)))?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut *enc_bytes,
			)
			.map_err(|e| Error::PaymentProof(format!("Unable to encrypt, {}", e)))?;

		Ok(EncryptedMessage {
			destination: destination.clone(),
			encrypted_message: mwc_util::to_hex(&enc_bytes),
			salt: mwc_util::to_hex(&salt),
			nonce: mwc_util::to_hex(&nonce),
		})
	}

	/// Build a zeroizing key that is expected to match this message.
	pub fn key(
		&self,
		sender_public_key: &PublicKey,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> Result<Zeroizing<[u8; 32]>, Error> {
		let salt = mwc_util::from_hex(&self.salt).map_err(|e| {
			Error::PaymentProof(format!(
				"Unable to decode salt from HEX {}, {}",
				// A proof supplied by a remote peer controls this field. Keep the
				// diagnostic useful, but do not allow it to inject log lines or
				// terminal control sequences. Valid salts are only 16 hex characters.
				crate::types::bounded_escape_for_display(&self.salt, 64),
				e
			))
		})?;

		derive_message_key(
			sender_public_key,
			secret_key,
			secp,
			&salt,
			"EncryptedMessage::key",
			"Key manipulation error",
		)
	}

	/// Decrypt/verify a message, keeping its plaintext zeroized on drop.
	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<Zeroizing<String>, Error> {
		// encrypted_message and nonce are peer-controlled (they come from a
		// proof supplied by a remote party). Bound and escape them before embedding
		// them in errors because callers may send those errors directly to output.
		let mut encrypted_message =
			Zeroizing::new(mwc_util::from_hex(&self.encrypted_message).map_err(|e| {
				Error::PaymentProof(format!(
					"Unable decode message from HEX {}, {}",
					crate::types::bounded_escape_for_display(
						&self.encrypted_message,
						MAX_ENCRYPTED_MESSAGE_ERROR_DISPLAY_LEN,
					),
					e
				))
			})?);
		let nonce = mwc_util::from_hex(&self.nonce).map_err(|e| {
			Error::PaymentProof(format!(
				"Unable decode nonce from HEX {}, {}",
				crate::types::bounded_escape_for_display(&self.nonce, MAX_NONCE_ERROR_DISPLAY_LEN,),
				e
			))
		})?;
		let nonce: [u8; 12] = nonce.try_into().map_err(|nonce: Vec<u8>| {
			Error::PaymentProof(format!(
				"EncryptedMessage::decrypt_with_key, invalid nonce length, nonce_len={} required_len=12",
				nonce.len()
			))
		})?;

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
			.map_err(|e| Error::PaymentProof(format!("Unable to build a key, {}", e)))?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let decrypted_data = opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut *encrypted_message,
			)
			.map_err(|e| Error::PaymentProof(format!("Unable to decrypt the message, {}", e)))?;

		// Validate UTF-8 while the bytes remain in zeroizing storage. A failed
		// String::from_utf8 conversion would otherwise own an unguarded copy.
		let res_msg = std::str::from_utf8(decrypted_data)
			.map_err(|e| Error::PaymentProof(format!("Decrypted message is corrupted, {}", e)))?;
		Ok(Zeroizing::new(res_msg.to_owned()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;

	#[test]
	fn ecdh_message_key_is_zeroizing_and_wire_compatible() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let sender_secret = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
		let receiver_secret = SecretKey::from_slice(&secp, &[2u8; 32]).unwrap();
		let sender_public = PublicKey::from_secret_key(&secp, &sender_secret).unwrap();
		let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret).unwrap();

		let message = EncryptedMessage::new(
			"payment proof".to_string(),
			&proofaddress::ProvableAddress::blank(),
			&receiver_public,
			&sender_secret,
			&secp,
			#[cfg(feature = "test-support")]
			true,
		)
		.unwrap();
		let key: Zeroizing<[u8; 32]> = message
			.key(&sender_public, &receiver_secret, &secp)
			.unwrap();

		let plaintext: Zeroizing<String> = message.decrypt_with_key(&key).unwrap();
		assert_eq!(plaintext.as_str(), "payment proof");

		let legacy_fixture = EncryptedMessage {
			destination: proofaddress::ProvableAddress::blank(),
			encrypted_message: String::new(),
			salt: "0000000000000000".to_string(),
			nonce: String::new(),
		};
		let fixture_key = legacy_fixture
			.key(&sender_public, &receiver_secret, &secp)
			.unwrap();
		assert_eq!(
			mwc_util::to_hex(&*fixture_key),
			"2867ecf368a67d9daf5079ce2eb02c968cb34985fc441e6f5f2ca7cd997abc2c"
		);
	}

	#[test]
	fn payment_proof_nonce_has_one_exact_encoding() {
		let key = [7u8; 32];
		let nonce = [0u8; 12];
		let mut encrypted_message = b"payment proof".to_vec();
		let sealing_key =
			aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::empty(),
				&mut encrypted_message,
			)
			.unwrap();
		let mut message = EncryptedMessage {
			destination: proofaddress::ProvableAddress::blank(),
			encrypted_message: mwc_util::to_hex(&encrypted_message),
			salt: String::new(),
			nonce: mwc_util::to_hex(&nonce),
		};

		assert_eq!(
			message.decrypt_with_key(&key).unwrap().as_str(),
			"payment proof"
		);

		for invalid_nonce in ["0000000000000000000000", "00000000000000000000000000"] {
			message.nonce = invalid_nonce.to_string();
			assert!(matches!(
				message.decrypt_with_key(&key),
				Err(Error::PaymentProof(error)) if error.contains("invalid nonce length")
			));
		}
	}

	#[test]
	fn authenticated_non_utf8_plaintext_is_rejected() {
		let key = [7u8; 32];
		let nonce = [1u8; 12];
		let mut bytes = b"secret-scalar-\xff".to_vec();
		let sealing_key =
			aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aead::Aad::empty(),
				&mut bytes,
			)
			.unwrap();
		let message = EncryptedMessage {
			destination: proofaddress::ProvableAddress::blank(),
			encrypted_message: mwc_util::to_hex(&bytes),
			salt: String::new(),
			nonce: mwc_util::to_hex(&nonce),
		};
		let error = message.decrypt_with_key(&key).unwrap_err().to_string();
		assert!(error.contains("Decrypted message is corrupted"));
		assert!(!error.contains("secret-scalar"));
	}

	#[test]
	fn malformed_message_error_values_are_bounded() {
		let key = [7u8; 32];
		let oversized_invalid_hex = "g".repeat(1_024);
		let mut message = EncryptedMessage {
			destination: proofaddress::ProvableAddress::blank(),
			encrypted_message: oversized_invalid_hex.clone(),
			salt: String::new(),
			nonce: String::new(),
		};

		let ciphertext_error = message.decrypt_with_key(&key).unwrap_err().to_string();
		assert!(ciphertext_error.contains("...[truncated]"));
		assert!(!ciphertext_error.contains(&oversized_invalid_hex));

		message.encrypted_message.clear();
		message.nonce = oversized_invalid_hex.clone();
		let nonce_error = message.decrypt_with_key(&key).unwrap_err().to_string();
		assert!(nonce_error.contains("...[truncated]"));
		assert!(!nonce_error.contains(&oversized_invalid_hex));
	}
}
