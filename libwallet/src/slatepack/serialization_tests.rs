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
use super::*;
use mwc_wallet_util::mwc_core::libtx::{aggsig, proof};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, SecretKey};
use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};

fn keys() -> (ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
	(
		ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
		ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
	)
}

// Serialization fixture with real commitments, proofs and a signature. It is
// an intermediate response, not a balanced or finalized transaction.
fn response() -> (Secp256k1, Slate) {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = ExtKeychain::from_seed(&secp, &[9; 32], true).unwrap();
	let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
	let mut slate = Slate::blank(2, true).unwrap();
	slate.id = Uuid::from_bytes([1; 16]);
	slate.amount = 1;
	slate.fee = 2;
	slate.height = 32;
	for child in 1..=2 {
		let id = ExtKeychain::derive_key_id(1, child, 0, 0, 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, 5, &id, switch).unwrap();
		let proof = proof::create(&mut secp, &keychain, &builder, 5, &id, switch, commit).unwrap();
		slate
			.tx_or_err_mut()
			.unwrap()
			.body
			.outputs
			.push(Output::new(OutputFeatures::Plain, commit, proof));
	}
	slate.tx_or_err_mut().unwrap().body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(
		secp.commit_value(slate.amount + slate.fee).unwrap(),
	)]);
	let kernel = TxKernel::with_features(KernelFeatures::Plain {
		fee: FeeFields::try_from(slate.fee).unwrap(),
	})
	.unwrap();
	let secret = SecretKey::from_slice(&secp, &[3; 32]).unwrap();
	let nonce = SecretKey::from_slice(&secp, &[4; 32]).unwrap();
	let public = PublicKey::from_secret_key(&secp, &secret).unwrap();
	let public_nonce = PublicKey::from_secret_key(&secp, &nonce).unwrap();
	let signature = aggsig::sign_single(
		&secp,
		&kernel.msg_to_sign(0).unwrap(),
		&secret,
		Some(&nonce),
		&public,
	)
	.unwrap();
	slate.tx_or_err_mut().unwrap().body.kernels.push(kernel);
	slate.participant_data.push(ParticipantData {
		id: 1,
		public_blind_excess: public,
		public_nonce,
		part_sig: Some(signature),
		message: None,
		message_sig: None,
	});
	(secp, slate)
}

fn encode(
	slate: &Slate,
	purpose: SlatePurpose,
	encrypted: bool,
	secp: &Secp256k1,
) -> Result<Vec<u8>, Error> {
	let (sender, recipient) = keys();
	let pack = Slatepack {
		sender: Some(sender.verifying_key()),
		recipient: encrypted.then(|| recipient.verifying_key()),
		content: purpose,
		slate: slate.clone(),
	};
	let (data, actual_encrypted) = pack.to_binary(
		0,
		SlateVersion::SP,
		&sender,
		#[cfg(feature = "test-support")]
		true,
		secp,
	)?;
	assert_eq!(actual_encrypted, encrypted);
	Ok(data)
}

// Wrap arbitrary, possibly malformed payloads with valid transport framing so
// decoder tests cannot pass merely because of an invalid checksum or AEAD tag.
fn envelope(mut payload: Vec<u8>, encrypted: bool) -> Vec<u8> {
	let mut data = vec![0]; // Version 0.
	if encrypted {
		let (sender, recipient) = keys();
		data.extend_from_slice(sender.verifying_key().as_bytes());
		data.extend_from_slice(recipient.verifying_key().as_bytes());
		let mut digest = CRC32.digest();
		digest.update(&data);
		digest.update(&payload);
		payload.extend_from_slice(&digest.finalize().to_be_bytes());
		let (ciphertext, nonce) = Slatepack::encrypt_payload(
			payload,
			&sender,
			&recipient.verifying_key(),
			#[cfg(feature = "test-support")]
			true,
		)
		.unwrap();
		data.extend_from_slice(&nonce);
		payload = ciphertext;
	}
	data.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
	data.extend_from_slice(&payload);
	data
}

// Enable each empty list separately, covering both input representations.
// Version 0 cannot encode these lists: the writer must return a section-specific
// encoding error before writing any slate fields, even partially buffered bits.
#[test]
fn enabled_empty_lists_are_rejected_before_writing_slate_fields() {
	let secp = Secp256k1::new().unwrap();
	let mut slate = Slate::blank(2, true).unwrap();
	for inputs in [
		Inputs::CommitOnly(vec![]),
		Inputs::FeaturesAndCommit(vec![]),
	] {
		slate.tx_or_err_mut().unwrap().body.inputs = inputs;
		for (inputs, outputs, kernels, section) in [
			(true, false, false, "input"),
			(false, true, false, "output"),
			(false, false, true, "kernel"),
		] {
			let mut data = Vec::new();
			let mut writer = BitWriter::endian(&mut data, BigEndian);
			let error = Slatepack::write_slate_data(
				0,
				&slate,
				false,
				false,
				false,
				inputs,
				outputs,
				kernels,
				false,
				false,
				false,
				false,
				&mut writer,
				&secp,
			)
			.unwrap_err();
			assert!(matches!(error, Error::SlatepackEncodeError(ref message)
				if message.contains(&format!("empty {} list", section))));
			writer.byte_align().unwrap();
			assert!(data.is_empty());
		}
	}
}

// A compact invoice omits the issuer's output. When payment requires no change,
// its response therefore has zero outputs and must fail encoding. One and two
// outputs exercise the supported stop/continuation framing and must round-trip
// without changing the checked fields, in both plain and encrypted messages.
#[test]
fn invoice_response_requires_outputs_in_both_transport_modes() {
	let (secp, slate) = response();
	let (_, recipient) = keys();
	for encrypted in [false, true] {
		for count in 0..=2 {
			let mut response = slate.clone();
			response
				.tx_or_err_mut()
				.unwrap()
				.body
				.outputs
				.truncate(count);
			let encoded = encode(&response, SlatePurpose::InvoiceResponse, encrypted, &secp);
			if count == 0 {
				assert!(
					matches!(encoded.unwrap_err(), Error::SlatepackEncodeError(ref message)
					if message.contains("empty output list"))
				);
				continue;
			}
			let decoded =
				Slatepack::from_binary(0, &encoded.unwrap(), encrypted, &recipient, &secp)
					.unwrap()
					.slate;
			assert_eq!(decoded.id, response.id);
			assert_eq!(decoded.amount, response.amount);
			assert_eq!(decoded.fee, response.fee);
			assert_eq!(
				decoded.tx_or_err().unwrap().body.outputs,
				response.tx_or_err().unwrap().body.outputs
			);
			match (
				&decoded.tx_or_err().unwrap().body.inputs,
				&response.tx_or_err().unwrap().body.inputs,
			) {
				(Inputs::CommitOnly(actual), Inputs::CommitOnly(expected)) => {
					assert_eq!(actual.len(), expected.len());
					for (actual, expected) in actual.iter().zip(expected) {
						assert_eq!(actual.commitment(), expected.commitment());
					}
				}
				_ => panic!("input encoding changed"),
			}
			assert_eq!(
				decoded.participant_data[0].part_sig,
				response.participant_data[0].part_sig
			);
		}
	}
}

// Initial send/invoice messages intentionally omit transaction-body sections.
// Empty lists in those omitted sections must not trigger the new writer guards;
// both message purposes must still round-trip in plain and encrypted form.
#[test]
fn initial_messages_allow_omitted_empty_sections() {
	let (secp, mut slate) = response();
	let (_, recipient) = keys();
	slate.tx = Slate::blank(2, true).unwrap().tx;
	slate.participant_data[0].id = 0;
	slate.participant_data[0].part_sig = None;
	for purpose in [SlatePurpose::InvoiceInitial, SlatePurpose::SendInitial] {
		for encrypted in [false, true] {
			let encoded = encode(&slate, purpose.clone(), encrypted, &secp).unwrap();
			let decoded =
				Slatepack::from_binary(0, &encoded, encrypted, &recipient, &secp).unwrap();
			assert_eq!(decoded.content, purpose);
			assert!(decoded.slate.tx_or_err().unwrap().body.outputs.is_empty());
			assert!(decoded.slate.tx_or_err().unwrap().body.inputs.is_empty());
		}
	}
}

// Corrupt one output in an otherwise encodable response. Both transport modes
// must reject an invalid commitment and an empty proof. Oversized proofs cannot
// be constructed through RangeProof's public API; the reader tests cover
// oversized lengths supplied over the wire.
#[test]
fn writer_rejects_invalid_output_commitments_and_proof_lengths() {
	let (secp, slate) = response();
	for encrypted in [false, true] {
		let mut invalid = slate.clone();
		invalid.tx_or_err_mut().unwrap().body.outputs[0]
			.identifier
			.commit = Commitment([0; PEDERSEN_COMMITMENT_SIZE]);
		assert!(
			matches!(encode(&invalid, SlatePurpose::InvoiceResponse, encrypted, &secp).unwrap_err(),
			Error::SlatepackEncodeError(ref message) if message.contains("Invalid output commitment"))
		);
		let mut invalid = slate.clone();
		invalid.tx_or_err_mut().unwrap().body.outputs[0].proof = RangeProof::zero();
		assert!(
			matches!(encode(&invalid, SlatePurpose::InvoiceResponse, encrypted, &secp).unwrap_err(),
			Error::SlatepackEncodeError(ref message) if message.contains("range proof length"))
		);
	}
}

// Construct malformed output sections directly, bypassing the writer's guards.
// Valid transport framing ensures each failure comes from parsing the slate.
// Invalid commitments/lengths must produce SlatepackDecodeError first; valid
// declarations followed by incomplete bytes must instead produce Error::IO.
#[test]
fn reader_rejects_invalid_or_truncated_outputs() {
	let (secp, slate) = response();
	let (_, recipient) = keys();
	let output = slate.tx_or_err().unwrap().body.outputs[0];
	for case in 0..6 {
		let mut payload = Vec::new();
		let mut writer = BitWriter::endian(&mut payload, BigEndian);
		writer
			.write(3, SlatePurpose::SendResponse.to_int())
			.unwrap();
		// SendResponse header, stopping immediately before its output section.
		Slatepack::write_slate_data(
			0,
			&slate,
			false,
			false,
			true,
			false,
			false,
			false,
			false,
			false,
			false,
			false,
			&mut writer,
			&secp,
		)
		.unwrap();
		let expected = match case {
			0 => {
				// A complete but invalid commitment must fail before reading its proof length.
				writer.write_bytes(&[0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
				Some("Invalid output commitment")
			}
			1 | 2 => {
				// Case 1 declares an empty proof; case 2 exceeds the destination buffer.
				writer.write_bytes(&output.identifier.commit.0).unwrap();
				let length = if case == 1 {
					0
				} else {
					u32::try_from(MAX_PROOF_SIZE + 1).unwrap()
				};
				writer.write(10, length).unwrap();
				// Deliberately omit proof bytes: length validation must win over EOF.
				Some(if case == 1 {
					"Empty output range proof"
				} else {
					"exceeds maximum"
				})
			}
			3 => {
				// Only 10 of the required 33 commitment bytes are present: expect EOF.
				writer
					.write_bytes(&output.identifier.commit.0[..10])
					.unwrap();
				None
			}
			4 | 5 => {
				writer.write_bytes(&output.identifier.commit.0).unwrap();
				writer
					.write(10, u32::try_from(output.proof.len().unwrap()).unwrap())
					.unwrap();
				if case == 4 {
					// The proof length is valid, but only 10 proof bytes follow: expect EOF.
					writer
						.write_bytes(&output.proof.bytes().unwrap()[..10])
						.unwrap();
				} else {
					// The first output is complete; reading the promised next one must hit EOF.
					writer.write_bytes(output.proof.bytes().unwrap()).unwrap();
					writer.write(1, 1u8).unwrap(); // Another output promised, but missing.
				}
				None
			}
			_ => unreachable!(),
		};
		writer.byte_align().unwrap();
		for encrypted in [false, true] {
			let error = Slatepack::from_binary(
				0,
				&envelope(payload.clone(), encrypted),
				encrypted,
				&recipient,
				&secp,
			)
			.unwrap_err();
			if let Some(expected) = expected {
				assert!(
					matches!(error, Error::SlatepackDecodeError(ref message) if message.contains(expected)),
					"case {}: {}",
					case,
					error
				);
			} else {
				assert!(matches!(error, Error::IO(_)), "case {}: {}", case, error);
			}
		}
	}
}

// A correctly encrypted, checksum-valid message can still contain a truncated
// slate. Arrange for checksum bits to resemble the missing participant flags,
// demonstrate that those bits could complete parsing if exposed as slate data,
// then require the encrypted reader to stop at the payload boundary with EOF.
#[test]
fn encrypted_reader_cannot_use_checksum_as_missing_participant_flags() {
	let (secp, mut slate) = response();
	let (sender, recipient) = keys();
	slate.participant_data[0].id = 0;
	slate.participant_data[0].part_sig = None;
	// With amount=1 and height=32, the two absent participant-data flags
	// occupy their own final byte. Removing it leaves both flags missing.
	let encoded = encode(&slate, SlatePurpose::InvoiceInitial, false, &secp).unwrap();
	let mut payload = encoded[3..].to_vec();
	assert_eq!(payload.len(), 89);
	assert_eq!(payload.pop(), Some(0));

	// Choose a UUID whose checksum starts with two zero bits. The old reader
	// treated those bits as the absent signature/message flags and succeeded.
	let mut header = vec![0];
	header.extend_from_slice(sender.verifying_key().as_bytes());
	header.extend_from_slice(recipient.verifying_key().as_bytes());
	let mut found = false;
	for value in 0..=255 {
		payload[1] = value; // Wholly inside the UUID, following the 3-bit purpose.
		let mut digest = CRC32.digest();
		digest.update(&header);
		digest.update(&payload);
		let checksum = digest.finalize().to_be_bytes();
		if checksum[0] & 0xc0 == 0 {
			let mut borrowed = payload.clone();
			borrowed.extend_from_slice(&checksum);
			// Demonstrate that this checksum can actually complete the slate.
			assert!(Slatepack::from_binary(
				0,
				&envelope(borrowed, false),
				false,
				&recipient,
				&secp
			)
			.is_ok());
			found = true;
			break;
		}
	}
	assert!(found);
	let error =
		Slatepack::from_binary(0, &envelope(payload, true), true, &recipient, &secp).unwrap_err();
	assert!(matches!(error, Error::IO(_)), "{}", error);
}
