// Copyright 2026 The MWC Developers
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

//! Compatibility helpers for wallet output rangeproofs.

use crate::Error;
use crate::internal::keys;
use mwc_wallet_util::mwc_core::core::Output;
use mwc_wallet_util::mwc_core::libtx::{build, proof};
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use std::convert::TryFrom;

const PROOF_MESSAGE_SIZE: usize = 20;
const PROOF_MESSAGE_IDENTIFIER_START: usize = 3;

/// Reuse an existing proof when an older context has no saved construction
/// height. Guessing from OutputData.height could create a second message under
/// the same alpha/rho masks; copying the original proof avoids that reuse.
pub(crate) fn existing_output<K, B>(
	value: u64,
	key_id: Identifier,
	output: Output,
) -> Box<build::Append<K, B>>
where
	K: Keychain,
	B: proof::ProofBuild,
{
	Box::new(move |build, acc| {
		let (tx, sum) = acc?;
		let expected = build.keychain.commit(
			build.secp,
			value,
			&key_id,
			SwitchCommitmentType::Regular,
		)?;
		if output.is_coinbase() || output.commitment() != expected {
			return Err(mwc_wallet_util::mwc_core::libtx::Error::RangeProof(
				"Saved output does not match the transaction context".into(),
			));
		}
		proof::verify(build.secp, expected, output.proof, None)?;
		Ok((
			tx.with_output(build.context_id, output.clone())?,
			sum.add_key_id(key_id.to_value_path(value)?),
		))
	})
}

/// Rewind a current output proof, accepting the historical depth-3 proof
/// message whose unused fourth path component contains an anti-replay height.
/// The returned identifier is always canonical and safe for key derivation.
pub(crate) fn rewind_with_height<K, B>(
	secp: &mut Secp256k1,
	keychain: &K,
	builder: &B,
	commit: Commitment,
	proof: RangeProof,
) -> Result<Option<(u64, Identifier, SwitchCommitmentType, u32)>, Error>
where
	K: Keychain,
	B: proof::ProofBuild,
{
	proof::verify(secp, commit, proof, None)
		.map_err(mwc_wallet_util::mwc_core::libtx::Error::from)?;
	let nonce = builder.rewind_nonce(secp, &commit).map_err(|e| {
		mwc_wallet_util::mwc_core::libtx::Error::RangeProof(format!(
			"Unable rewind for commit {:?}, {}",
			commit, e
		))
	})?;
	let info = match secp.rewind_bullet_proof(commit, nonce, None, None, proof) {
		Ok(info) => info,
		Err(secp::Error::InvalidRangeProof) => return Ok(None),
		Err(e) => return Err(mwc_wallet_util::mwc_core::libtx::Error::from(e).into()),
	};

	// The rewind nonce is a shareable viewing credential, so a successful
	// rewind alone does not establish wallet ownership. Treat all decoded
	// metadata failures as an unowned output rather than aborting the scan.
	let message = info.message;
	if message.len() != PROOF_MESSAGE_SIZE {
		return Ok(None);
	}
	let message = message.as_bytes();
	if message[..2] != [0, 0] {
		return Ok(None);
	}
	let switch = match SwitchCommitmentType::try_from(message[2]) {
		Ok(switch) => switch,
		Err(_) => return Ok(None),
	};
	let depth = message[PROOF_MESSAGE_IDENTIFIER_START];
	if depth > 4 {
		return Ok(None);
	}

	let encoded_key_id = match Identifier::from_bytes(&message[PROOF_MESSAGE_IDENTIFIER_START..]) {
		Ok(key_id) => key_id,
		Err(_) => return Ok(None),
	};
	let (key_id, built_height) = if depth == 3 {
		let (canonical, legacy_height) = match keys::canonicalize_stored_identifier(&encoded_key_id)
		{
			Ok(metadata) => metadata,
			Err(_) => return Ok(None),
		};
		(canonical, legacy_height.unwrap_or(0))
	} else {
		// Only the historical depth-three format may carry data below its
		// declared path. All other proof identifiers must already be canonical.
		if encoded_key_id.to_path().is_err() {
			return Ok(None);
		}
		(encoded_key_id, 0)
	};
	// Matching the decoded metadata back to the commitment is the ownership
	// check. A mismatch is an ordinary unowned output, not a wallet failure.
	let expected_commit = keychain.commit(secp, info.value, &key_id, switch)?;
	if commit != expected_commit {
		return Ok(None);
	}

	Ok(Some((info.value, key_id, switch, built_height)))
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "swaps")]
	use mwc_wallet_util::mwc_core::core::OutputFeatures;
	use mwc_wallet_util::mwc_core::libtx::proof::ProofBuild;
	use mwc_wallet_util::mwc_crates::secp::pedersen::ProofMessage;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	use mwc_wallet_util::mwc_keychain::ExtKeychain;

	#[test]
	fn height_tagged_proofs_rewind_with_height_bound_private_nonces() -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[2u8; 32], true)?;
		let builder = proof::ProofBuilder::new(&secp, &keychain)?;
		let key_id = ExtKeychain::derive_key_id(3, 4, 5, 6, 0)?;
		let switch = SwitchCommitmentType::Regular;
		let amount = 42;
		let expected_commit = keychain.commit(&secp, amount, &key_id, switch)?;
		let secret_key = keychain.derive_key(&secp, amount, &key_id, switch)?;
		let mut previous_nonce = None;

		for height in [0u32, 1, 456_789, u32::MAX] {
			let (commit, rangeproof) = proof::height_tagged_rangeproof(
				&mut secp,
				&keychain,
				&builder,
				amount,
				&key_id,
				u64::from(height),
			)?;
			assert_eq!(commit, expected_commit);
			proof::verify(&mut secp, commit, rangeproof, None)?;

			// Independently encode the historical height-tagged identifier. Passing
			// its private nonce to rewind checks the masks used by the actual proof,
			// rather than only checking that two derived nonces differ.
			let mut nonce_id_bytes = key_id.to_bytes();
			nonce_id_bytes[13..17].copy_from_slice(&height.to_be_bytes());
			let nonce_id = Identifier::from_bytes(&nonce_id_bytes)?;
			let private_nonce = builder.private_nonce(&secp, &commit, &nonce_id)?;
			let rewind_nonce = builder.rewind_nonce(&secp, &commit)?;
			let info = secp.rewind_bullet_proof(
				commit,
				rewind_nonce.clone(),
				Some(private_nonce.clone()),
				None,
				rangeproof,
			)?;
			assert_eq!(info.value, amount);
			assert_eq!(info.blinding, secret_key);
			assert_eq!(
				info.message.as_bytes(),
				builder.proof_message(&secp, &nonce_id, switch)?.as_bytes(),
			);
			assert_eq!(
				rewind_with_height(&mut secp, &keychain, &builder, commit, rangeproof)?,
				Some((amount, key_id.clone(), switch, height)),
			);
			if let Some(previous_nonce) = previous_nonce {
				assert_ne!(private_nonce, previous_nonce);
				assert!(
					secp.rewind_bullet_proof(
						commit,
						rewind_nonce,
						Some(previous_nonce),
						None,
						rangeproof
					)
					.is_err()
				);
			}
			previous_nonce = Some(private_nonce);
		}
		Ok(())
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn swap_output_builder_requires_depth_three_and_preserves_recovery() -> Result<(), Error> {
		use mwc_wallet_util::mwc_core::core::Transaction;

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[8u8; 32], true)?;
		let builder = proof::ProofBuilder::new(&secp, &keychain)?;
		let switch = SwitchCommitmentType::Regular;
		let amount = 42;
		let height = 456_789u32;

		let key_id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0)?;
		let output_builder = build::height_tagged_output(amount, key_id.clone(), u64::from(height));
		let (tx, _) = build::partial_transaction(
			0,
			&mut secp,
			Transaction::empty(),
			&[output_builder],
			&keychain,
			&builder,
		)?;
		assert_eq!(tx.outputs().len(), 1);
		let output = &tx.outputs()[0];
		assert_eq!(output.features(), OutputFeatures::Plain);
		assert_eq!(
			output.commitment(),
			keychain.commit(&secp, amount, &key_id, switch)?,
		);
		proof::verify(&mut secp, output.commitment(), output.proof(), None)?;
		assert_eq!(
			rewind_with_height(
				&mut secp,
				&keychain,
				&builder,
				output.commitment(),
				output.proof(),
			)?,
			Some((amount, key_id, switch, height)),
		);

		// Swap construction must reject unsupported paths instead of creating
		// an untagged output. Existing proofs remain recoverable below.
		for key_id in [
			ExtKeychain::derive_key_id(0, 0, 0, 0, 0)?,
			ExtKeychain::derive_key_id(1, 1, 0, 0, 0)?,
			ExtKeychain::derive_key_id(2, 1, 2, 0, 0)?,
			ExtKeychain::derive_key_id(4, 1, 2, 3, 123_456)?,
		] {
			let output_builder = build::height_tagged_output(amount, key_id, u64::from(height));
			let error = build::partial_transaction(
				0,
				&mut secp,
				Transaction::empty(),
				&[output_builder],
				&keychain,
				&builder,
			)
			.unwrap_err();
			assert!(matches!(
				error,
				mwc_wallet_util::mwc_core::libtx::Error::RangeProof(message)
					if message.contains("Height-tagged output key must have derivation depth 3")
			));
		}
		Ok(())
	}

	#[test]
	fn depth_four_identifier_is_not_interpreted_as_a_height() -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[3u8; 32], true)?;
		let builder = proof::ProofBuilder::new(&secp, &keychain)?;
		let key_id = ExtKeychain::derive_key_id(4, 7, 8, 9, 123_456)?;
		let switch = SwitchCommitmentType::Regular;
		let amount = 24;
		let commit = keychain.commit(&secp, amount, &key_id, switch)?;
		let rangeproof = proof::create(
			&mut secp, &keychain, &builder, amount, &key_id, switch, commit,
		)?;

		let rewound = rewind_with_height(&mut secp, &keychain, &builder, commit, rangeproof)?;

		assert_eq!(rewound, Some((amount, key_id, switch, 0)));
		Ok(())
	}

	#[test]
	fn foreign_proof_using_wallet_rewind_nonce_is_not_owned() -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let wallet_keychain = ExtKeychain::from_seed(&secp, &[4u8; 32], true)?;
		let wallet_builder = proof::ProofBuilder::new(&secp, &wallet_keychain)?;
		let foreign_keychain = ExtKeychain::from_seed(&secp, &[5u8; 32], true)?;
		let foreign_builder = proof::ProofBuilder::new(&secp, &foreign_keychain)?;
		let foreign_key_id = ExtKeychain::derive_key_id(3, 10, 11, 12, 0)?;
		let switch = SwitchCommitmentType::Regular;
		let amount = 17;
		let commit = foreign_keychain.commit(&secp, amount, &foreign_key_id, switch)?;
		let secret_key = foreign_keychain.derive_key(&secp, amount, &foreign_key_id, switch)?;
		let rewind_nonce = wallet_builder.rewind_nonce(&secp, &commit)?;
		let mut message_id_bytes = foreign_key_id.to_bytes();
		message_id_bytes[13..17].copy_from_slice(&456_789u32.to_be_bytes());
		let message_id = Identifier::from_bytes(&message_id_bytes)?;
		let message = foreign_builder.proof_message(&secp, &message_id, switch)?;
		let nonce_id =
			Identifier::from_bytes(&message.as_bytes()[PROOF_MESSAGE_IDENTIFIER_START..])?;
		let private_nonce = foreign_builder.private_nonce(&secp, &commit, &nonce_id)?;
		let rangeproof = secp.bullet_proof(
			amount,
			secret_key,
			rewind_nonce,
			private_nonce,
			None,
			Some(message),
		)?;

		let rewound = rewind_with_height(
			&mut secp,
			&wallet_keychain,
			&wallet_builder,
			commit,
			rangeproof,
		)?;

		assert_eq!(rewound, None);
		Ok(())
	}

	#[test]
	fn malformed_message_using_wallet_rewind_nonce_is_not_owned() -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let wallet_keychain = ExtKeychain::from_seed(&secp, &[6u8; 32], true)?;
		let wallet_builder = proof::ProofBuilder::new(&secp, &wallet_keychain)?;
		let foreign_keychain = ExtKeychain::from_seed(&secp, &[7u8; 32], true)?;
		let foreign_builder = proof::ProofBuilder::new(&secp, &foreign_keychain)?;
		let foreign_key_id = ExtKeychain::derive_key_id(3, 13, 14, 15, 0)?;
		let switch = SwitchCommitmentType::Regular;
		let amount = 19;
		let commit = foreign_keychain.commit(&secp, amount, &foreign_key_id, switch)?;
		let secret_key = foreign_keychain.derive_key(&secp, amount, &foreign_key_id, switch)?;
		let rewind_nonce = wallet_builder.rewind_nonce(&secp, &commit)?;
		let mut message_id_bytes = foreign_key_id.to_bytes();
		message_id_bytes[13..17].copy_from_slice(&456_789u32.to_be_bytes());
		let message_id = Identifier::from_bytes(&message_id_bytes)?;
		let mut message_bytes = foreign_builder
			.proof_message(&secp, &message_id, switch)?
			.as_bytes()
			.to_vec();
		message_bytes[0] = 1;
		let message = ProofMessage::from_bytes(&message_bytes)?;
		let nonce_id =
			Identifier::from_bytes(&message.as_bytes()[PROOF_MESSAGE_IDENTIFIER_START..])?;
		let private_nonce = foreign_builder.private_nonce(&secp, &commit, &nonce_id)?;
		let rangeproof = secp.bullet_proof(
			amount,
			secret_key,
			rewind_nonce,
			private_nonce,
			None,
			Some(message),
		)?;

		let rewound = rewind_with_height(
			&mut secp,
			&wallet_keychain,
			&wallet_builder,
			commit,
			rangeproof,
		)?;

		assert_eq!(rewound, None);
		Ok(())
	}
}
