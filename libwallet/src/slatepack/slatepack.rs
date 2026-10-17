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

/// Slatepack Types + Serialization implementation
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

use mwc_wallet_util::mwc_crates::secp::key::PublicKey;

use crate::{Error, ParticipantData, Slate, SlateVersion};

use crate::proof::proofaddress::ProvableAddress;
use std::io;

use crate::proof::proofaddress;
use crate::slate::{PaymentInfo, MAX_PARTICIPANT_MESSAGE_LEN};
use mwc_wallet_util::mwc_core::consensus::WEEK_HEIGHT;
use mwc_wallet_util::mwc_core::core::CommitWrapper;
use mwc_wallet_util::mwc_core::core::{
	FeeFields, Input, Inputs, KernelFeatures, Output, OutputFeatures, OutputIdentifier, TxKernel,
};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::bitstream_io::{
	BigEndian, BitRead2, BitReader, BitWrite2, BitWriter, Endianness,
};
use mwc_wallet_util::mwc_crates::crc::{Crc, CRC_32_ISO_HDLC};
use mwc_wallet_util::mwc_crates::ed25519_dalek::PUBLIC_KEY_LENGTH;
use mwc_wallet_util::mwc_crates::rand::{rngs::SysRng, TryRng};
use mwc_wallet_util::mwc_crates::ring::aead;
use mwc_wallet_util::mwc_crates::secp::constants::{
	MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE, SECRET_KEY_SIZE, SINGLE_BULLET_PROOF_SIZE,
};
use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_wallet_util::mwc_crates::secp::AggSigSignature;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::BlindingFactor;
use mwc_wallet_util::mwc_util::{from_hex, ToHex};

fn secure_payload_nonce() -> Result<[u8; 12], Error> {
	let mut nonce = [0u8; 12];
	SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
		Error::SlatepackEncodeError(format!("Unable to generate slatepack nonce, {}", e))
	})?;
	Ok(nonce)
}

/// Basic Slatepack definition
#[derive(Debug, Clone)]
pub struct Slatepack {
	// Optional Fields
	/// Sender address, non if slate wasn'r encrypted
	pub sender: Option<ed25519_dalek::VerifyingKey>,
	/// Recipient addresses, enrypted id defined
	pub recipient: Option<ed25519_dalek::VerifyingKey>,
	/// The content purpose. It customize serializer/deserializer for us.
	pub content: SlatePurpose,

	/// Slate data.
	pub slate: Slate,
}

/// Slate state definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum SlatePurpose {
	/// Standard flow, freshly init
	SendInitial,
	/// Standard flow, return journey
	SendResponse,
	///Invoice flow, init
	InvoiceInitial,
	///Invoice flow, return journey
	InvoiceResponse,
	/// Just a full slate. Might me stored, or sent for posting.
	FullSlate,
}

impl SlatePurpose {
	/// Create from integer value
	pub fn from_int(i: u8) -> Result<Self, Error> {
		let res: Self = match i {
			0 => SlatePurpose::SendInitial,
			1 => SlatePurpose::SendResponse,
			2 => SlatePurpose::InvoiceInitial,
			3 => SlatePurpose::InvoiceResponse,
			4 => SlatePurpose::FullSlate,
			_ => {
				return Err(Error::SlatepackDecodeError(format!(
					"SlatePackPurpose wrong value {}",
					i
				)));
			}
		};
		Ok(res)
	}

	/// Convert to integer value
	pub fn to_int(&self) -> u8 {
		match self {
			SlatePurpose::SendInitial => 0,
			SlatePurpose::SendResponse => 1,
			SlatePurpose::InvoiceInitial => 2,
			SlatePurpose::InvoiceResponse => 3,
			SlatePurpose::FullSlate => 4,
		}
	}

	/// Show slatepack purpose as string
	pub fn to_str(&self) -> &str {
		match self {
			SlatePurpose::SendInitial => "send_init",
			SlatePurpose::SendResponse => "send_response",
			SlatePurpose::InvoiceInitial => "invoice_init",
			SlatePurpose::InvoiceResponse => "invoice_response",
			SlatePurpose::FullSlate => "full",
		}
	}
}

const SLATE_PACK_PLAIN_DATA_SIZE: usize = 1 + 32 + 32;
const MAX_SLATEPACK_PAYLOAD_SIZE: usize = 65_534;
const MAX_SLATEPACK_COMPRESSED_MESSAGE_LEN: usize = 30_000;
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Reserve enough space for an encrypted FullSlate when SP output is requested.
/// Initial/response Slatepacks omit transaction elements, so their
/// encoded size cannot tell us whether the completed transaction will fit.
/// Additional counts include locally selected elements and expected peer outputs.
/// A compact slate may also be sent as V3 JSON; compactness does not select SP.
pub(crate) fn validate_slatepack_size(
	slate: &Slate,
	output_version: Option<&SlateVersion>,
	additional_inputs: usize,
	additional_outputs: usize,
) -> Result<(), Error> {
	if output_version != Some(&SlateVersion::SP) {
		return Ok(());
	}
	let body = &slate.tx_or_err()?.body;
	let too_large = || {
		Error::SlatepackEncodeError(format!(
			"Transaction is too large for Slatepack's {}-byte payload limit, including space reserved for signatures, messages and payment proof; reduce the number of inputs or outputs",
			MAX_SLATEPACK_PAYLOAD_SIZE
		))
	};
	let inputs = body
		.inputs
		.len()
		.checked_add(additional_inputs)
		.ok_or_else(too_large)?;
	let outputs = body
		.outputs
		.len()
		.checked_add(additional_outputs)
		.ok_or_else(too_large)?;

	// Upper bounds in bits, matching write_slate_data. Reserve maximum-width
	// integers, TTL, both signed participant records and payment proof. Smaz
	// emits at most two bytes per input byte. Wallet validation bounds each
	// participant message to MAX_PARTICIPANT_MESSAGE_LEN before signing.
	const HEADER_BITS: usize = 3 + 128 + 1 + 2 * 73 + 3 * 70 + 1 + 256 + 1;
	const PARTICIPANT_BITS: usize =
		2 * (7 + 33 * 8) + 1 + 64 * 8 + 1 + 16 + 2 * MAX_PARTICIPANT_MESSAGE_LEN * 8 + 64 * 8;
	const PAYMENT_PROOF_BITS: usize = 1 + 2 * (1 + 7 + 33 * 8) + 1 + 4 + 79 * 8;
	const INPUT_BITS: usize = PEDERSEN_COMMITMENT_SIZE * 8 + 2;
	const OUTPUT_BITS: usize = PEDERSEN_COMMITMENT_SIZE * 8 + 10 + SINGLE_BULLET_PROOF_SIZE * 8 + 1;
	const KERNEL_BITS: usize = 73 + PEDERSEN_COMMITMENT_SIZE * 8 + 64 * 8 + 1;
	const FIXED_BITS: usize = HEADER_BITS + 2 * PARTICIPANT_BITS + PAYMENT_PROOF_BITS;

	// Every completed transaction has at least one input, output and kernel.
	// Check all arithmetic, including untrusted requested output counts.
	let bits = inputs
		.max(1)
		.checked_mul(INPUT_BITS)
		.and_then(|size| outputs.max(1).checked_mul(OUTPUT_BITS)?.checked_add(size))
		.and_then(|size| {
			body.kernels
				.len()
				.max(1)
				.checked_mul(KERNEL_BITS)?
				.checked_add(size)
		})
		.and_then(|size| size.checked_add(FIXED_BITS))
		.ok_or_else(too_large)?;
	let bytes = bits
		.checked_add(7)
		.map(|size| size / 8)
		.and_then(|size| size.checked_add(4 + 16)) // CRC32 and AEAD tag
		.ok_or_else(too_large)?;
	if bytes > MAX_SLATEPACK_PAYLOAD_SIZE {
		return Err(too_large());
	}
	Ok(())
}

/// Smaz compression codebook, taken verbatim from the reference
/// implementation (antirez/smaz, as mirrored by the `smaz` crate). This
/// table is part of the Slatepack wire format and must never change: any
/// deviation breaks participant-message decoding for other wallets.
const SMAZ_CODEBOOK: [&str; 254] = [
	" ", "the", "e", "t", "a", "of", "o", "and", "i", "n", "s", "e ", "r", " th", " t", "in", "he",
	"th", "h", "he ", "to", "\r\n", "l", "s ", "d", " a", "an", "er", "c", " o", "d ", "on", " of",
	"re", "of ", "t ", ", ", "is", "u", "at", "   ", "n ", "or", "which", "f", "m", "as", "it",
	"that", "\n", "was", "en", "  ", " w", "es", " an", " i", "\r", "f ", "g", "p", "nd", " s",
	"nd ", "ed ", "w", "ed", "http://", "for", "te", "ing", "y ", "The", " c", "ti", "r ", "his",
	"st", " in", "ar", "nt", ",", " to", "y", "ng", " h", "with", "le", "al", "to ", "b", "ou",
	"be", "were", " b", "se", "o ", "ent", "ha", "ng ", "their", "\"", "hi", "from", " f", "in ",
	"de", "ion", "me", "v", ".", "ve", "all", "re ", "ri", "ro", "is ", "co", "f t", "are", "ea",
	". ", "her", " m", "er ", " p", "es ", "by", "they", "di", "ra", "ic", "not", "s, ", "d t",
	"at ", "ce", "la", "h ", "ne", "as ", "tio", "on ", "n t", "io", "we", " a ", "om", ", a",
	"s o", "ur", "li", "ll", "ch", "had", "this", "e t", "g ", "e\r\n", " wh", "ere", " co", "e o",
	"a ", "us", " d", "ss", "\n\r\n", "\r\n\r", "=\"", " be", " e", "s a", "ma", "one", "t t",
	"or ", "but", "el", "so", "l ", "e s", "s,", "no", "ter", " wa", "iv", "ho", "e a", " r",
	"hat", "s t", "ns", "ch ", "wh", "tr", "ut", "/", "have", "ly ", "ta", " ha", " on", "tha",
	"-", " l", "ati", "en ", "pe", " re", "there", "ass", "si", " fo", "wa", "ec", "our", "who",
	"its", "z", "fo", "rs", ">", "ot", "un", "<", "im", "th ", "nc", "ate", "><", "ver", "ad",
	" we", "ly", "ee", " n", "id", " cl", "ac", "il", "</", "rt", " wi", "div", "e, ", " it",
	"whi", " ma", "ge", "x", "e c", "men", ".com",
];

lazy_static! {
	/// Reverse lookup for [`SMAZ_CODEBOOK`]: smaz string fragment -> code.
	static ref SMAZ_CODEBOOK_MAP: HashMap<&'static [u8], u8> = {
		let mut map = HashMap::new();
		for (i, code) in SMAZ_CODEBOOK.iter().enumerate() {
			map.insert(code.as_bytes(), i as u8);
		}
		map
	};
}

impl Slatepack {
	/// Decode and decrypt the Slatepack
	/// Note:  from_binary & to_binary - are NOT serializers, minimum amount of the data is transported.
	/// from_binary & to_binary are symmetrical
	pub fn from_binary(
		context_id: u32,
		data: &Vec<u8>,
		encrypted: bool,
		secret: &ed25519_dalek::SigningKey,
		secp: &Secp256k1,
	) -> Result<Self, Error> {
		if encrypted && data.len() < SLATE_PACK_PLAIN_DATA_SIZE {
			return Err(Error::SlatepackDecodeError(
				"Slatapack data is too short".to_string(),
			));
		}
		let mut digest = CRC32.digest();

		if encrypted {
			digest.update(&data[..SLATE_PACK_PLAIN_DATA_SIZE]);
		}

		let mut r = BitReader::endian(data.as_slice(), BigEndian);
		let version: u8 = r.read(8)?;
		if version != 0 {
			return Err(Error::SlatepackDecodeError(
				"Wrong slatepack version".to_string(),
			));
		}

		let (payload, sender, recipient) = if encrypted {
			// Sender address, so other party can open the message
			debug_assert!(PUBLIC_KEY_LENGTH == 32);
			let mut data: [u8; 32] = [0; 32];
			r.read_bytes(&mut data)?;
			let sender = ed25519_dalek::VerifyingKey::from_bytes(&data).map_err(|e| {
				Error::SlatepackDecodeError(format!("Unable to read a sender public key, {}", e))
			})?;
			if sender.is_weak() {
				return Err(Error::SlatepackDecodeError(
					"Slatepack sender public key has small order".to_owned(),
				));
			}
			// Receiver address, so this wallet open the message if it is in the archive
			let mut data: [u8; 32] = [0; 32];
			r.read_bytes(&mut data)?;
			let recipient = ed25519_dalek::VerifyingKey::from_bytes(&data).map_err(|e| {
				Error::SlatepackDecodeError(format!("Unable to read a recipient public key, {}", e))
			})?;
			if recipient.is_weak() {
				return Err(Error::SlatepackDecodeError(
					"Slatepack recipient public key has small order".to_owned(),
				));
			}

			// Incoming Slatepacks derive their key from our secret and the
			// declared sender. Outgoing archives derive it from our secret and
			// the declared recipient. Select the peer only after binding the
			// supplied secret to the corresponding local header role; otherwise
			// successful decryption with one header key could authenticate an
			// unrelated identity in the other header field.
			let own_public = secret.verifying_key();
			let peer_public = if recipient == own_public {
				&sender
			} else if sender == own_public {
				&recipient
			} else {
				return Err(Error::SlatepackDecodeError(
					"Slatepack is neither addressed to nor sent by the supplied wallet key"
						.to_owned(),
				));
			};

			let mut nonce: [u8; 12] = [0; 12];
			r.read_bytes(&mut nonce)?;

			let enc_len: u32 = r.read(16)?;
			let enc_len = usize::try_from(enc_len).map_err(|e| {
				Error::DataOverflow(format!(
					"Slatepack::from_binary, encrypted payload length does not fit usize, enc_len={} error={}",
					enc_len, e
				))
			})?;
			let mut data_to_decrypt: Vec<u8> = vec![0; enc_len];
			r.read_bytes(&mut data_to_decrypt)?;
			let mut payload = Self::decrypt_payload(data_to_decrypt, nonce, secret, peer_public)?;

			// Let's check the payload CRC first (crc32 is last 4 bytes.)
			{
				let crc_start = payload.len().checked_sub(4).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Slatepack::from_binary, slatepack payload is missing its checksum, payload_len={} checksum_len=4",
						payload.len()
					))
				})?;
				let data = payload.get(..crc_start).ok_or_else(|| {
					Error::SlatepackDecodeError("Invalid Slatepack checksum boundary".to_owned())
				})?;
				let checksum = payload.get(crc_start..).ok_or_else(|| {
					Error::SlatepackDecodeError("Invalid Slatepack checksum boundary".to_owned())
				})?;
				digest.update(data);
				let mut crc_reader = BitReader::endian(checksum, BigEndian);
				let read_crc32: u32 = crc_reader.read(32)?;
				let data_crc32 = digest.finalize();
				if read_crc32 != data_crc32 {
					return Err(Error::SlatepackDecodeError(
						"Slatepack content is not consistent".to_string(),
					));
				}
				// The checksum is framing, not slate data. A truncated slate must
				// not consume checksum bytes to complete its last field.
				payload.truncate(crc_start);
			}

			(payload, Some(sender), Some(recipient))
		} else {
			let enc_len: u32 = r.read(16)?;
			let enc_len = usize::try_from(enc_len).map_err(|e| {
				Error::DataOverflow(format!(
					"Slatepack::from_binary, plaintext payload length does not fit usize, enc_len={} error={}",
					enc_len, e
				))
			})?;
			let mut payload: Vec<u8> = vec![0; enc_len];
			r.read_bytes(&mut payload)?;
			(payload, None, None)
		};

		let mut r = BitReader::endian(payload.as_slice(), BigEndian);
		let content = SlatePurpose::from_int(r.read(3)?)?;

		let mut slate = match content {
			SlatePurpose::InvoiceInitial => Self::read_slate_data(
				context_id, true, false, false, false, false, false, true, false, false, false,
				&mut r, secp,
			)?,
			SlatePurpose::InvoiceResponse => Self::read_slate_data(
				context_id, true, true, true, true, true, true, false, true, false, false, &mut r,
				secp,
			)?,
			SlatePurpose::FullSlate => Self::read_slate_data(
				context_id, true, true, true, true, true, true, true, true, true, true, &mut r,
				secp,
			)?,
			SlatePurpose::SendInitial => Self::read_slate_data(
				context_id, true, true, false, false, false, false, true, false, true, false,
				&mut r, secp,
			)?,
			SlatePurpose::SendResponse => Self::read_slate_data(
				context_id, false, false, true, false, true, true, false, true, true, true, &mut r,
				secp,
			)?,
		};

		Self::update_tx_from_slate(context_id, &mut slate, secp)?;

		Ok(Slatepack {
			sender,
			recipient,
			content,
			slate,
		})
	}

	/// Encode this slatepack into the binary format, version and recipients will be truncated and not encoded,
	/// The rest will be encrypted, there is no reason to know who isi the sender.
	/// Note:  from_binary & to_binary - are NOT serializers, minimum amount of the data is transported
	/// from_binary & to_binary are symmetrical
	/// Return: binary data, encrypted flag
	pub fn to_binary(
		&self,
		context_id: u32,
		slate_version: SlateVersion,
		secret: &ed25519_dalek::SigningKey,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<(Vec<u8>, bool), Error> {
		if !self.slate.compact_slate {
			return Err(Error::SlatepackEncodeError(
				"Slatepack expecting only compact model".to_string(),
			));
		}

		// Here we can calculate the version of the slatepack that it needed. Currently there is no choices, just a single version.
		match slate_version {
			SlateVersion::SP => (),
			_ => return Err(Error::SlatepackEncodeError("Slate is plain".to_string())),
		}

		if self.recipient.is_some() {
			let sender = self.sender.as_ref().ok_or(Error::SlatepackEncodeError(
				"Not found expected sender value".to_string(),
			))?;
			if sender != &secret.verifying_key() {
				return Err(Error::SlatepackEncodeError(
					"Slatepack sender public key does not match the supplied encryption key"
						.to_owned(),
				));
			}
		}

		let mut encrypted_data = Vec::new();

		let mut w = BitWriter::endian(&mut encrypted_data, BigEndian);
		w.write(3, self.content.to_int())?;

		match self.content {
			SlatePurpose::InvoiceInitial => {
				Self::write_slate_data(
					context_id,
					&self.slate,
					true,
					false,
					false,
					false,
					false,
					false,
					true,
					false,
					false,
					false,
					&mut w,
					secp,
				)?;
			}
			SlatePurpose::InvoiceResponse => {
				Self::write_slate_data(
					context_id,
					&self.slate,
					true,
					true,
					true,
					true,
					true,
					true,
					false,
					true,
					false,
					false,
					&mut w,
					secp,
				)?;
			}
			SlatePurpose::FullSlate => {
				Self::write_slate_data(
					context_id,
					&self.slate,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					true,
					&mut w,
					secp,
				)?;
			}
			SlatePurpose::SendInitial => {
				Self::write_slate_data(
					context_id,
					&self.slate,
					true,
					true,
					false,
					false,
					false,
					false,
					true,
					false,
					true,
					false,
					&mut w,
					secp,
				)?;
			}
			SlatePurpose::SendResponse => {
				Self::write_slate_data(
					context_id,
					&self.slate,
					false,
					false,
					true,
					false,
					true,
					true,
					false,
					true,
					true,
					true,
					&mut w,
					secp,
				)?;
			}
		}

		// Here is a binary that we will use
		let mut pack_binary = Vec::new();
		// w_pack must be limited because we want tread form the pack_binary pretty soon
		let mut w_pack = BitWriter::endian(&mut pack_binary, BigEndian);

		// Writing the version 0. The version is global for all slatepack.
		w_pack.write(8, 0u8)?;

		if let Some(recipient) = &self.recipient {
			// recipient is define, so we can do encryption

			let sender = self.sender.clone().ok_or(Error::SlatepackEncodeError(
				"Not found expected sender value".to_string(),
			))?;
			// Sender address, so other party can open the message
			w_pack.write_bytes(sender.as_bytes())?;
			// Receiver address, so this wallet open the message if it is in the archive
			w_pack.write_bytes(recipient.as_bytes())?; // 32 bytes unencrypted - recipient. Primary reason - we want to be able to read what we write.
											  // expected to be aligned

			// Do CRC and encryption. CRC we want to be encrypted
			{
				let mut digest = CRC32.digest();
				if pack_binary.len() != SLATE_PACK_PLAIN_DATA_SIZE {
					return Err(Error::SlatepackEncodeError(format!(
						"Slatepack::to_binary, plaintext header has invalid length, header_len={} expected_len={}",
						pack_binary.len(),
						SLATE_PACK_PLAIN_DATA_SIZE
					)));
				}
				digest.update(&pack_binary);
				w.byte_align()?;

				digest.update(&encrypted_data);

				// We have to destroy prev instance of w in order to read from the encrypted_data for crc32.
				let mut w = BitWriter::endian(&mut encrypted_data, BigEndian);
				let crc32: u32 = digest.finalize();
				w.write(32, crc32)?;
			}
			let (encrypted_data, nonce) = Self::encrypt_payload(
				encrypted_data,
				secret,
				&recipient,
				#[cfg(feature = "test-support")]
				use_test_rng,
			)?;

			// We have to destroy prev instance of w_pack in order to read from the pack_binary for crc32.
			let mut w_pack = BitWriter::endian(&mut pack_binary, BigEndian);

			w_pack.write_bytes(&nonce)?;

			let enc_len = encrypted_data.len();
			if enc_len > MAX_SLATEPACK_PAYLOAD_SIZE {
				return Err(Error::SlatepackEncodeError(
					"Slate too large for encoding".to_string(),
				));
			}
			let enc_len = u32::try_from(enc_len).map_err(|e| {
				Error::DataOverflow(format!(
					"Slatepack::to_binary, slate length does not fit u32, enc_len={} error={}",
					enc_len, e
				))
			})?;
			w_pack.write(16, enc_len)?; // Need to keep byte aligned
			w_pack.write_bytes(&encrypted_data)?;
			// expected to be aligned

			Ok((pack_binary, true))
		} else {
			// Non encrypted data. Just a plain binary format, not CRC any other control.
			w.byte_align()?;

			let enc_len = encrypted_data.len();
			if enc_len > MAX_SLATEPACK_PAYLOAD_SIZE {
				return Err(Error::SlatepackEncodeError(
					"Slate too large for encoding".to_string(),
				));
			}
			let enc_len = u32::try_from(enc_len).map_err(|e| {
				Error::DataOverflow(format!(
					"Slatepack::to_binary, slate length does not fit u32, enc_len={} error={}",
					enc_len, e
				))
			})?;
			w_pack.write(16, enc_len)?; // Need to keep byte aligned
			w_pack.write_bytes(&encrypted_data)?;

			Ok((pack_binary, false))
		}
	}

	fn write_u64<W: io::Write, E: Endianness>(
		amount: u64,
		has_hundreds: bool,
		writer: &mut BitWriter<W, E>,
	) -> Result<(), Error> {
		// amount normally has many zeroes and not much digits as decimal. Let's use this fact
		let mut hundreds: u8 = 0;
		let mut amount = amount;
		if has_hundreds {
			while amount % 100 == 0 && hundreds < 7 {
				amount /= 100;
				// The loop condition bounds hundreds to at most seven.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "the loop condition checks hundreds < 7"
				)]
				{
					hundreds += 1;
				}
			}
		}
		// now calculating the used digits
		let mut d: u64 = 1;
		let mut dn: u32 = 1;
		while dn < 64 && d < amount {
			// dn starts at one and is incremented only while below 64. At dn == 63,
			// d is 2^62, so shifting it once produces 2^63 without overflowing u64.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "dn < 64 bounds the counter and d to at most 2^62 before the shift"
			)]
			{
				dn += 1;
				d <<= 1;
			}
		}
		if has_hundreds {
			writer.write(3, hundreds)?; // 8 max value
		}
		// dn starts at one and is never decreased.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "dn is initialized to one and only incremented"
		)]
		writer.write(6, dn - 1)?; // 64 max value, 1 min
		writer.write(dn, amount)?;

		Ok(())
	}

	fn write_participant_data<W: io::Write, E: Endianness>(
		part_data: &ParticipantData,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		Self::write_publick_key(&part_data.public_blind_excess, w, secp)?;
		Self::write_publick_key(&part_data.public_nonce, w, secp)?;

		match part_data.part_sig {
			Some(sig) => {
				w.write(1, 1u8)?;
				let sig_dt = sig.serialize_compact(secp)?;
				w.write_bytes(&sig_dt)?;
			}
			None => {
				w.write(1, 0u8)?;
			}
		}

		match &part_data.message {
			Some(message) => {
				w.write(1, 1u8)?;
				let msg_enc = Self::encode_participant_message(message)?;
				let message_len = u16::try_from(msg_enc.len()).map_err(|e| {
					Error::DataOverflow(format!(
						"Slatepack::write_participant_data, participant message is too large, compressed_len={} error={}",
						msg_enc.len(), e
					))
				})?;
				w.write(16, message_len)?;
				w.write_bytes(&msg_enc)?;

				// Writing signature as a proof of the message, so other party will not be able to change it as well
				if let Some(sig) = part_data.message_sig {
					let sig_dt = sig.serialize_compact(secp)?;
					w.write_bytes(&sig_dt)?;
				} else {
					return Err(Error::GenericError(
						"Not found message signature at participant data".to_string(),
					));
				}
			}
			None => w.write::<u8>(1, 0)?,
		}
		Ok(())
	}

	fn encode_participant_message(message: &str) -> Result<Vec<u8>, Error> {
		let encoded = Self::smaz_compress(message.as_bytes());
		if encoded.len() > MAX_SLATEPACK_COMPRESSED_MESSAGE_LEN {
			return Err(Error::SlatepackEncodeError(format!(
				"Participant message is too large for Slatepack encoding, compressed_len={} maximum={}",
				encoded.len(),
				MAX_SLATEPACK_COMPRESSED_MESSAGE_LEN
			)));
		}
		Ok(encoded)
	}

	fn write_publick_key<W: io::Write, E: Endianness>(
		pk: &PublicKey,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let xs = pk.serialize_vec(secp, true)?;
		let xs_len: u32 = xs.len().try_into().map_err(|e| {
			Error::DataOverflow(format!(
				"Slatepack::write_publick_key, public key length is too large, xs_len={} error={}",
				xs.len(),
				e
			))
		})?;
		if xs_len > 127 {
			return Err(Error::SlatepackEncodeError(format!(
				"Public key length {} is too large",
				xs_len
			)));
		}
		w.write(7, xs_len)?;
		w.write_bytes(&xs)?;
		Ok(())
	}

	// Write this address 'efficeint' way. The problem that it can be PublicKey aka MQS address
	// or ed25519_dalek::PublicKey aka Tor Address.
	// We will need to save a a binary
	fn write_provable_address<W: io::Write, E: Endianness>(
		context_id: u32,
		address: &ProvableAddress,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		match address.public_key(secp, context_id) {
			Ok(pk) => {
				//
				w.write(1, 1u8)?;
				Self::write_publick_key(&pk, w, secp)?;
			}
			Err(_) => {
				// it must be tor address.
				w.write(1, 0u8)?;
				// len is 32 bytes
				w.write_bytes(address.tor_public_key()?.as_bytes())?;
			}
		}
		Ok(())
	}

	fn write_slate_data<W: io::Write, E: Endianness>(
		context_id: u32,
		slate: &Slate,
		write_amount: bool,
		write_fee: bool,
		write_offset: bool,
		write_inputs: bool,
		write_outputs: bool,
		write_kernels: bool,
		write_participan_data_0: bool,
		write_participan_data_1: bool,
		write_proof_addresses: bool,
		write_proof_signature: bool,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		// Version 0 puts a continuation bit after each list element, so an
		// enabled section must contain at least one element. Omitted sections
		// (for example, the outputs in an initial invoice) may still be empty.
		if write_inputs || write_outputs || write_kernels {
			let body = &slate.tx_or_err()?.body;
			for (enabled, empty, section) in [
				(write_inputs, body.inputs.is_empty(), "input"),
				(write_outputs, body.outputs.is_empty(), "output"),
				(write_kernels, body.kernels.is_empty(), "kernel"),
			] {
				if enabled && empty {
					return Err(Error::SlatepackEncodeError(format!(
						"Current Slatepack format cannot encode an empty {} list",
						section
					)));
				}
			}
		}

		// Transaction ID is included in every payload.
		// 16 bytes
		w.write_bytes(slate.id.as_bytes())?;
		// Add network Info. 1 for mainnet, 0 for for the rest...
		if global::is_mainnet(context_id) {
			w.write(1, 1u8)?;
		} else {
			w.write(1, 0u8)?;
		}

		if write_amount {
			Self::write_u64(slate.amount, true, w)?;
		}
		if write_fee {
			Self::write_u64(slate.fee, true, w)?;
		}

		Self::write_u64(slate.height, false, w)?;
		Self::write_u64(slate.get_lock_height(), false, w)?;

		// Note, kernel features are never written, they are calculated from lock_height

		match slate.ttl_cutoff_height {
			Some(h) => {
				w.write(1, 1u8)?;
				Self::write_u64(h, false, w)?;
			}
			None => {
				w.write(1, 0u8)?;
			}
		}

		if write_offset {
			// size: SECRET_KEY_SIZE
			let offset = slate.offset.as_ref();
			w.write_bytes(offset)?;
		}

		if write_inputs {
			match &slate.tx_or_err()?.body.inputs {
				Inputs::CommitOnly(commit_wrapper) => {
					w.write(1, 0u8)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for commit in commit_wrapper {
						if has_data {
							w.write(1, 1u8)?; // go bit
						}
						// Len: constants::PEDERSEN_COMMITMENT_SIZE
						w.write_bytes(&commit.commitment().0)?;
						has_data = true;
					}
					w.write(1, 0u8)?; // stop bit
				}
				Inputs::FeaturesAndCommit(inputs) => {
					w.write(1, 1u8)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for inp in inputs {
						if has_data {
							w.write(1, 1u8)?; // go bit
						}
						w.write(1, inp.features as u8)?;
						w.write_bytes(&inp.commit.0)?;
						has_data = true;
					}
					w.write(1, 0u8)?; // stop bit
				}
			}
		}

		if write_outputs {
			// Using a stop bit because normally we have few outputs.
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for out in &slate.tx_or_err()?.body.outputs {
				secp.validate_commitment(&out.identifier.commit)
					.map_err(|_| {
						Error::SlatepackEncodeError("Invalid output commitment".to_owned())
					})?;
				let proof_bytes = out.proof.bytes()?;
				let proof_len = proof_bytes.len();
				let maximum_proof_len = MAX_PROOF_SIZE.min(1023);
				if proof_len == 0 || proof_len > maximum_proof_len {
					return Err(Error::SlatepackEncodeError(format!(
						"Output range proof length {} is outside 1..={}",
						proof_len, maximum_proof_len
					)));
				}
				if has_data {
					w.write(1, 1u8)?; // go bit
				}
				// Feature can be only plain
				// Len: constants::PEDERSEN_COMMITMENT_SIZE
				w.write_bytes(&out.identifier.commit.0)?;
				let proof_len: u32 = proof_len.try_into().map_err(|e| {
					Error::DataOverflow(format!(
						"Slatepack::write_slate_data, range proof length is too large, proof_len={} error={}",
						proof_len, e
					))
				})?;
				w.write(10, proof_len)?; // max 675 - should fit 10 bits
				w.write_bytes(proof_bytes)?;
				has_data = true;
			}
			w.write(1, 0u8)?; // stop bit
		}

		if write_kernels {
			// Using stop bit because normally there is only one kernel
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for kernel in &slate.tx_or_err()?.body.kernels {
				if has_data {
					w.write(1, 1u8)?; // go bit
				}
				// Expecting only Plain kernels. It is about wallet basic operations, so nothing extra
				match kernel.features {
					KernelFeatures::Plain { fee } => {
						Self::write_u64(fee.into(), true, w)?;
					}
					_ => {
						return Err(Error::SlatepackEncodeError(
							"Slatepack expecting only Plain Kernels".to_string(),
						));
					}
				}
				let is_response = write_participan_data_1 && !write_participan_data_0;
				if secp.validate_commitment(&kernel.excess).is_err()
					&& !(is_response && kernel.excess.0.iter().all(|byte| *byte == 0))
				{
					return Err(Error::SlatepackEncodeError(
						"Invalid kernel excess".to_string(),
					));
				}
				w.write_bytes(&kernel.excess.0)?;
				let sig_dt = if kernel.excess_sig.is_valid(secp) {
					kernel.excess_sig.serialize_compact(secp)?
				} else if is_response && kernel.excess_sig == AggSigSignature::blank() {
					// A response is not final yet. Preserve the protocol's explicit blank
					// kernel placeholder; finalization replaces it with a verified signature.
					[0; 64]
				} else {
					return Err(Error::SlatepackEncodeError(
						"Not found valid kernel signature".to_string(),
					));
				};
				w.write_bytes(&sig_dt)?;
				has_data = true;
			}
			w.write(1, 0u8)?; // stop bit
		}

		if write_participan_data_0 {
			let part_data = slate
				.participant_with_id(0)
				.ok_or(Error::SlatepackEncodeError(
					"Not found slate participant data".to_string(),
				))?;
			Self::write_participant_data(&part_data, w, secp)?;
		}
		if write_participan_data_1 {
			let part_data = slate
				.participant_with_id(1)
				.ok_or(Error::SlatepackEncodeError(
					"Not found slate participant data".to_string(),
				))?;
			Self::write_participant_data(&part_data, w, secp)?;
		}

		if write_proof_addresses {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1u8)?;
					// len is 32 bytes
					Self::write_provable_address(context_id, &pp.sender_address, w, secp)?;
					Self::write_provable_address(context_id, &pp.receiver_address, w, secp)?;
					// signature is None
				}
				None => w.write(1, 0u8)?,
			}
		}

		if write_proof_signature {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1u8)?;
					let sign_str =
						pp.receiver_signature
							.clone()
							.ok_or(Error::SlatepackEncodeError(
								"Not found expected payment proof signature".to_string(),
							))?;
					let sign_v = from_hex(&sign_str).map_err(|e| {
						Error::SlatepackEncodeError(format!("Wrong signature at slate data, {}", e))
					})?;
					// Signature length can be different (so far it is 64 bytes or 70) because the PK might be from different families.
					// That is why let's save the size
					let sign_len = sign_v.len();
					if sign_len < 64 || sign_len >= 64 + 16 {
						return Err(Error::SlatepackEncodeError(
							"Invalid Signature length".to_string(),
						));
					}
					// The validation above proves sign_len >= 64.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "signature length is checked to be in 64..80"
					)]
					let encoded_sign_len = sign_len - 64;
					let sign_len = u32::try_from(encoded_sign_len).map_err(|e| {
						Error::DataOverflow(format!(
							"Slatepack::write_slate_data, signature length does not fit u32, encoded_len={} error={}",
							encoded_sign_len, e
						))
					})?;
					w.write(4, sign_len)?;
					w.write_bytes(&sign_v)?;
				}
				None => w.write(1, 0u8)?,
			}
		}

		Ok(())
	}

	// see write_amount for details
	fn read_u64<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		has_hundreds: bool,
	) -> Result<u64, Error> {
		let hundreds: u16 = if has_hundreds { r.read(3)? } else { 0 };

		let digits: u32 = r.read(6)?;
		// A six-bit value is at most 63, so adding one fits u32.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "digits is read from exactly six bits and is at most 63"
		)]
		let mut amount: u64 = r.read(digits + 1)?;

		for _ in 0..hundreds {
			amount = amount.checked_mul(100).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Slatepack::read_u64, slatepack amount overflow, amount={} multiplier=100",
					amount
				))
			})?;
		}
		Ok(amount)
	}

	fn read_participant_data<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		id: u64,
		secp: &Secp256k1,
	) -> Result<ParticipantData, Error> {
		let blind_excess = Self::read_publick_key(r, secp)?;
		let nonce = Self::read_publick_key(r, secp)?;

		let signature = if r.read::<u8>(1)? == 1 {
			let mut sig_dt: [u8; 64] = [0; 64];
			r.read_bytes(&mut sig_dt)?;
			Some(AggSigSignature::from_compact(secp, &sig_dt)?)
		} else {
			None
		};

		let (message, message_sig) = if r.read::<u8>(1)? == 1 {
			let sz: u32 = r.read(16)?;
			let sz = usize::try_from(sz).map_err(|e| {
				Error::DataOverflow(format!(
					"Slatepack::read_participant_data, participant message length does not fit usize, message_len={} error={}",
					sz, e
				))
			})?;
			let mut msg: Vec<u8> = vec![0; sz];
			r.read_bytes(&mut msg)?;
			// Peer-controlled bytes: use the local non-panicking decoder, not
			// smaz 0.1.0 which panics on a truncated verbatim marker.
			let msg = Self::smaz_decompress(&msg)?;
			let mut sig_dt: [u8; 64] = [0; 64];
			r.read_bytes(&mut sig_dt)?;
			(
				Some(String::from_utf8(msg).map_err(|e| {
					Error::SlatepackDecodeError(format!("Unable to decode message, {}", e))
				})?),
				Some(AggSigSignature::from_compact(secp, &sig_dt)?),
			)
		} else {
			(None, None)
		};

		Ok(ParticipantData {
			id,
			public_blind_excess: blind_excess,
			public_nonce: nonce,
			part_sig: signature,
			message,
			message_sig,
		})
	}

	/// Local replacement for `smaz::compress` now that the smaz crate is no
	/// longer a dependency. Implements the reference algorithm (longest
	/// codebook match, verbatim bytes emitted as 0xfe/0xff markers) and
	/// produces byte-for-byte the same output, so Slatepacks stay
	/// wire-compatible with other wallets.
	fn smaz_compress(input: &[u8]) -> Vec<u8> {
		let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2);
		let mut verbatim: Vec<u8> = Vec::new();
		let mut i: usize = 0;
		while i < input.len() {
			let max_len = std::cmp::min(7, input.len() - i);
			let mut matched = false;
			for len in (1..=max_len).rev() {
				if let Some(&code) = SMAZ_CODEBOOK_MAP.get(&input[i..i + len]) {
					if !verbatim.is_empty() {
						Self::smaz_flush_verbatim(&mut out, &mut verbatim);
					}
					out.push(code);
					i += len;
					matched = true;
					break;
				}
			}
			if !matched {
				verbatim.push(input[i]);
				i += 1;
				if verbatim.len() == 256 {
					Self::smaz_flush_verbatim(&mut out, &mut verbatim);
				}
			}
		}
		if !verbatim.is_empty() {
			Self::smaz_flush_verbatim(&mut out, &mut verbatim);
		}
		out
	}

	/// Emit pending verbatim bytes: a single byte follows a 0xfe marker,
	/// longer runs a 0xff marker plus a `len - 1` count byte.
	fn smaz_flush_verbatim(out: &mut Vec<u8>, verbatim: &mut Vec<u8>) {
		if verbatim.len() > 1 {
			out.push(255);
			out.push((verbatim.len() - 1) as u8);
		} else {
			out.push(254);
		}
		out.append(verbatim);
	}

	/// Non-panicking stand-in for `smaz::decompress`. smaz 0.1.0 (the only
	/// published version) indexes out of bounds on a truncated verbatim
	/// marker — a trailing 0xfe or 0xff — and these message bytes are
	/// peer-controlled in unencrypted Slatepacks, so a well-formed Slatepack
	/// could otherwise crash the wallet instead of returning an Error.
	/// Output and acceptance behavior are byte-for-byte identical to
	/// `smaz::decompress` for every input on which smaz does not panic, so
	/// this stays wire-compatible with other wallets.
	fn smaz_decompress(input: &[u8]) -> Result<Vec<u8>, Error> {
		let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3);
		let mut i: usize = 0;
		while i < input.len() {
			match input[i] {
				254 => {
					// Single verbatim byte follows the marker.
					let b = *input.get(i + 1).ok_or_else(|| {
						Error::SlatepackDecodeError(
							"Unable to decode message, truncated smaz verbatim byte".to_string(),
						)
					})?;
					out.push(b);
					i += 2;
				}
				255 => {
					// Verbatim run: length byte `len`, then `len + 1` literal bytes.
					let len = *input.get(i + 1).ok_or_else(|| {
						Error::SlatepackDecodeError(
							"Unable to decode message, truncated smaz verbatim run".to_string(),
						)
					})? as usize;
					let run = input.get(i + 2..i + 3 + len).ok_or_else(|| {
						Error::SlatepackDecodeError(
							"Unable to decode message, truncated smaz verbatim run".to_string(),
						)
					})?;
					out.extend_from_slice(run);
					i += 3 + len;
				}
				code => {
					out.extend_from_slice(SMAZ_CODEBOOK[code as usize].as_bytes());
					i += 1;
				}
			}
		}
		Ok(out)
	}

	fn read_publick_key<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		secp: &Secp256k1,
	) -> Result<PublicKey, Error> {
		let xs_len: u32 = r.read(7)?;
		let xs_len = usize::try_from(xs_len).map_err(|e| {
			Error::DataOverflow(format!(
				"Slatepack::read_publick_key, public key length does not fit usize, xs_len={} error={}",
				xs_len, e
			))
		})?;
		let mut xs: Vec<u8> = vec![0; xs_len];
		r.read_bytes(&mut xs)?;
		let pk = PublicKey::from_slice(secp, &xs)?;
		Ok(pk)
	}

	fn read_provable_address<R: io::Read, E: Endianness>(
		context_id: u32,
		r: &mut BitReader<R, E>,
		secp: &Secp256k1,
	) -> Result<ProvableAddress, Error> {
		let pa = if r.read::<u8>(1)? == 1 {
			// PublicKey (MQS)
			let pk = Self::read_publick_key(r, secp)?;
			ProvableAddress::from_pub_key(secp, context_id, &pk)?
		} else {
			let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
			r.read_bytes(&mut pk)?;
			let dalek_pk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| {
				Error::SlatepackDecodeError(format!("Unable decode Public Key data, {}", e))
			})?;

			ProvableAddress::from_tor_pub_key(&dalek_pk)?
		};

		Ok(pa)
	}

	fn read_slate_data<R: io::Read, E: Endianness>(
		context_id: u32,
		read_amount: bool,
		read_fee: bool,
		read_offset: bool,
		read_inputs: bool,
		read_outputs: bool,
		read_kernels: bool,
		read_participan_data_0: bool,
		read_participan_data_1: bool,
		read_proof_addresses: bool,
		read_proof_signature: bool,
		r: &mut BitReader<R, E>,
		secp: &Secp256k1,
	) -> Result<Slate, Error> {
		let mut slate = Slate::blank(2, true)?;
		let mut slate_id: [u8; 16] = [0; 16];
		r.read_bytes(&mut slate_id)?;
		slate.id = Uuid::from_slice(&slate_id).map_err(|e| {
			Error::SlatepackDecodeError(format!("Unable to encode UUID data, {}", e))
		})?;

		let network: u8 = r.read(1)?;

		if (network == 1) ^ global::is_mainnet(context_id) {
			return Err(Error::SlatepackDecodeError("Slate from wrong network".to_string()).into());
		}

		if read_amount {
			slate.amount = Self::read_u64(r, true)?;
		}
		if read_fee {
			slate.fee = Self::read_u64(r, true)?;
		}

		slate.height = Self::read_u64(r, false)?;
		let lock_height = Self::read_u64(r, false)?;

		// Note, so far kernel_features is not stored, it can be calculated from the lock_height
		// We want to eliminate storing because that will break backward compatibility

		slate.reset_lock_height();
		if lock_height != 0 {
			if lock_height < WEEK_HEIGHT {
				slate.set_related_height(lock_height)?;
			} else {
				slate.set_lock_height(lock_height)?;
			}
		}

		if r.read::<u8>(1)? == 1 {
			slate.ttl_cutoff_height = Some(Self::read_u64(r, false)?);
		} else {
			slate.ttl_cutoff_height = None;
		}

		if read_offset {
			let mut offset: [u8; SECRET_KEY_SIZE] = [0; SECRET_KEY_SIZE];
			r.read_bytes(&mut offset)?;
			slate.offset = BlindingFactor::from_slice(&offset)?;
		}

		if read_inputs {
			if r.read::<u8>(1)? == 0 {
				// Inputs::CommitOnly  type
				let mut input_commit: Vec<CommitWrapper> = vec![];
				loop {
					let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
					r.read_bytes(&mut commit)?;
					input_commit.push(CommitWrapper::from(Commitment(commit)));
					if r.read::<u8>(1)? == 0 {
						break;
					}
				}
				slate.tx_or_err_mut()?.body.inputs = Inputs::CommitOnly(input_commit);
			} else {
				// Inputs::FeaturesAndCommit(Vec<Input>) type
				let mut inputs: Vec<Input> = vec![];
				loop {
					let of: OutputFeatures = if r.read::<u8>(1)? == 0 {
						OutputFeatures::Plain
					} else {
						OutputFeatures::Coinbase
					};
					let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
					r.read_bytes(&mut commit)?;
					inputs.push(Input::new(of, Commitment(commit)));
					if r.read::<u8>(1)? == 0 {
						break;
					}
				}
				slate.tx_or_err_mut()?.body.inputs = Inputs::FeaturesAndCommit(inputs);
			}
		}

		if read_outputs {
			loop {
				let mut commit: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
				r.read_bytes(&mut commit)?;
				let commit = Commitment(commit);
				secp.validate_commitment(&commit).map_err(|_| {
					Error::SlatepackDecodeError("Invalid output commitment".to_owned())
				})?;

				let proof_len: u32 = r.read(10)?;
				let proof_len = usize::try_from(proof_len).map_err(|e| {
					Error::DataOverflow(format!(
						"Slatepack::read_slate_data, range proof length does not fit usize, proof_len={} error={}",
						proof_len, e
					))
				})?;
				let mut proof_bytes = [0u8; MAX_PROOF_SIZE];
				if proof_len == 0 {
					return Err(Error::SlatepackDecodeError(
						"Empty output range proof".to_owned(),
					));
				}
				let proof_destination = proof_bytes.get_mut(..proof_len).ok_or_else(|| {
					Error::SlatepackDecodeError(format!(
						"Range proof length {} exceeds maximum {}",
						proof_len, MAX_PROOF_SIZE
					))
				})?;
				r.read_bytes(proof_destination)?;
				let proof = RangeProof::from_bytes(proof_destination)?;

				slate.tx_or_err_mut()?.body.outputs.push(Output {
					identifier: OutputIdentifier {
						features: OutputFeatures::Plain,
						commit,
					},
					proof,
				});

				if r.read::<u8>(1)? == 0 {
					break;
				}
			}
		}

		if read_kernels {
			loop {
				let fee = Self::read_u64(r, true)?;

				let mut excess: [u8; PEDERSEN_COMMITMENT_SIZE] = [0; PEDERSEN_COMMITMENT_SIZE];
				r.read_bytes(&mut excess)?;

				let mut signature: [u8; 64] = [0; 64];
				r.read_bytes(&mut signature)?;

				let excess_sig = if signature.iter().all(|byte| *byte == 0) {
					// Intermediate response Slatepacks historically encode a blank kernel
					// signature. Keep it as a typed placeholder; completed slates are
					// finalized and verified in update_tx_from_slate below.
					AggSigSignature::blank()
				} else {
					AggSigSignature::from_compact(secp, &signature)?
				};

				slate.tx_or_err_mut()?.body.kernels.push(TxKernel {
					features: KernelFeatures::Plain {
						fee: FeeFields::try_from(fee).map_err(|e| {
							Error::DataOverflow(format!(
								"Slatepack::read_slate_data, fee does not fit FeeFields, fee={} error={}",
								fee, e
							))
						})?,
					},
					excess: Commitment(excess),
					excess_sig,
				});

				if r.read::<u8>(1)? == 0 {
					break;
				}
			}
		}

		if read_participan_data_0 {
			slate
				.participant_data
				.push(Self::read_participant_data(r, 0, secp)?);
		}

		if read_participan_data_1 {
			slate
				.participant_data
				.push(Self::read_participant_data(r, 1, secp)?);
		}

		if read_proof_addresses {
			if r.read::<u8>(1)? == 1 {
				let sender_address = Self::read_provable_address(context_id, r, secp)?;
				let receiver_address = Self::read_provable_address(context_id, r, secp)?;

				match &mut slate.payment_proof {
					Some(proof) => {
						proof.sender_address = sender_address;
						proof.receiver_address = receiver_address;
					}
					None => {
						slate.payment_proof = Some(PaymentInfo {
							sender_address,
							receiver_address,
							receiver_signature: None,
						});
					}
				}
			}
		}

		if read_proof_signature {
			if r.read::<u8>(1)? == 1 {
				let encoded_sign_len = r.read::<u32>(4)?;
				// A four-bit encoded length is at most 15, so adding 64 fits u32.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "encoded_sign_len is read from exactly four bits and is at most 15"
				)]
				let sign_len = encoded_sign_len + 64;
				let sign_len = usize::try_from(sign_len).map_err(|e| {
					Error::DataOverflow(format!(
						"Slatepack::read_slate_data, signature length does not fit usize, signature_len={} error={}",
						sign_len, e
					))
				})?;
				let mut signature: Vec<u8> = vec![0; sign_len];
				r.read_bytes(&mut signature)?;

				match &mut slate.payment_proof {
					Some(proof) => {
						proof.receiver_signature = Some(signature.to_hex());
					}
					None => {
						slate.payment_proof = Some(PaymentInfo {
							sender_address: ProvableAddress::blank(),
							receiver_address: ProvableAddress::blank(),
							receiver_signature: Some(signature.to_hex()),
						});
					}
				}
			}
		}

		Ok(slate)
	}

	/// Encrypt the payload. For encryption we are using  Diffie-Hellman key exchange for secret exchange
	/// Then everything will be encrypted with EAED.
	fn encrypt_payload(
		payload: Vec<u8>,
		secret: &ed25519_dalek::SigningKey,
		recipient: &ed25519_dalek::VerifyingKey,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<(Vec<u8>, [u8; 12]), Error> {
		// https://github.com/dalek-cryptography/x25519-dalek
		// convert to xDalek PK & Secret
		let recipient = proofaddress::tor_pub_2_slatepack_pub(&recipient).map_err(|e| {
			Error::SlatepackEncodeError(format!("Invalid recipient public key, {}", e))
		})?;
		let secret = proofaddress::tor_secret_2_slatepack_secret(&secret);
		let shared_secret = secret.diffie_hellman(&recipient);
		if !shared_secret.was_contributory() {
			return Err(Error::SlatepackEncodeError(
				"Recipient public key produced a non-contributory key exchange".to_owned(),
			));
		}

		#[cfg(feature = "test-support")]
		let nonce = if use_test_rng {
			[1; 12]
		} else {
			secure_payload_nonce()?
		};
		#[cfg(not(feature = "test-support"))]
		let nonce = secure_payload_nonce()?;

		let mut enc_bytes = payload;

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, shared_secret.as_bytes())
			.map_err(|e| Error::SlatepackEncodeError(format!("Unable to build a key, {}", e)))?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut enc_bytes,
			)
			.map_err(|e| Error::SlatepackEncodeError(format!("Unable to encrypt, {}", e)))?;

		Ok((enc_bytes, nonce))
	}

	/// As above, decrypt if needed
	/// dec_key - is a secret that is used for all types of weallet addresses.
	fn decrypt_payload(
		payload: Vec<u8>,
		nonce: [u8; 12],
		secret: &ed25519_dalek::SigningKey,
		sender: &ed25519_dalek::VerifyingKey,
	) -> Result<Vec<u8>, Error> {
		// https://github.com/dalek-cryptography/x25519-dalek
		// convert to xDalek PK & Secret
		let sender = proofaddress::tor_pub_2_slatepack_pub(&sender).map_err(|e| {
			Error::SlatepackDecodeError(format!("Invalid sender public key, {}", e))
		})?;
		let secret = proofaddress::tor_secret_2_slatepack_secret(&secret);
		let shared_secret = secret.diffie_hellman(&sender);
		if !shared_secret.was_contributory() {
			return Err(Error::SlatepackDecodeError(
				"Sender public key produced a non-contributory key exchange".to_owned(),
			));
		}

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, shared_secret.as_bytes())
			.map_err(|e| Error::SlatepackDecodeError(format!("Unable to build a key, {}", e)))?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);

		let mut encrypted_message = payload;

		let decrypted_data = opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut encrypted_message,
			)
			.map_err(|e| Error::SlatepackDecodeError(format!("Unable to decrypt, {}", e)))?;

		Ok(decrypted_data.to_vec())
	}

	// Update a transaction form the slate data.
	fn update_tx_from_slate(
		context_id: u32,
		slate: &mut Slate,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		if !slate.compact_slate {
			return Err(Error::SlatepackDecodeError(
				"Slatepack::update_tx_from_slate, operation requires a compact slate".to_string(),
			));
		}
		let participants_complete = slate.participant_data.len() == slate.num_participants
			&& slate.participant_data.iter().all(|p| p.is_complete());
		if !participants_complete {
			if slate.tx_or_err()?.body.kernels.is_empty() {
				let mut kernel = TxKernel::with_features(slate.kernel_features()?)?;
				kernel.excess = slate.calc_excess(secp)?;
				// Initial compact Slatepacks omit their kernel from the payload. Rebuild
				// its known excess, but keep the all-zero signature as "none" because
				// the other participant has not signed the partial transaction yet.
				slate.tx_or_err_mut()?.body.kernels.push(kernel);
			}
			return Ok(());
		}

		let excess = slate.calc_excess(secp)?;
		let mut kernel = TxKernel::with_features(slate.kernel_features()?)?;
		kernel.excess = excess;
		kernel.excess_sig = slate.finalize_signature(context_id, secp)?;

		// Updating tx kernel and offset with what slate has
		let offset = slate.offset.clone();
		let tx = slate.tx_or_err_mut()?;
		match tx.body.kernels.first_mut() {
			Some(existing_kernel) => *existing_kernel = kernel,
			None => tx.body.kernels.push(kernel),
		}
		tx.offset = offset;

		Ok(())
	}
}

#[test]
fn smaz_test() {
	// Let's check if smaz compressor really effective
	let message = "test string to check the compress";
	// let's limit message with 32 k
	let msg_enc = Slatepack::smaz_compress(message.as_bytes());
	// see 33 to 17 compression.
	assert_eq!(message.len(), 33);
	assert_eq!(msg_enc.len(), 17);
	assert!(msg_enc.len() < message.len());

	let msg = Slatepack::smaz_decompress(&msg_enc).unwrap();
	let dec_msg = String::from_utf8(msg).unwrap();
	assert_eq!(message, dec_msg);
}

#[test]
fn slatepack_size_budget_accounts_for_inputs_outputs_and_overflow() {
	let slate = Slate::blank(2, true).unwrap();
	let version = Some(&SlateVersion::SP);
	assert!(validate_slatepack_size(&slate, version, 1, 2).is_ok());
	assert!(validate_slatepack_size(&slate, version, 1, 79).is_ok());
	assert!(validate_slatepack_size(&slate, version, 1, 80).is_err());
	assert!(validate_slatepack_size(&slate, version, 2_000, 2).is_err());
	assert!(validate_slatepack_size(&slate, version, usize::MAX, 1).is_err());
	assert!(validate_slatepack_size(&slate, version, 1, usize::MAX).is_err());

	// Compact construction alone must not impose SP transport limits.
	for compact in [false, true] {
		let slate = Slate::blank(2, compact).unwrap();
		for version in [None, Some(&SlateVersion::V3), Some(&SlateVersion::V3B)] {
			assert!(validate_slatepack_size(&slate, version, 2_000, 100).is_ok());
		}
	}
}

#[test]
fn oversized_participant_message_is_rejected_instead_of_truncated() {
	let message = "9".repeat(MAX_SLATEPACK_COMPRESSED_MESSAGE_LEN + 1);
	let error = Slatepack::encode_participant_message(&message).unwrap_err();
	assert!(matches!(error, Error::SlatepackEncodeError(_)));
}

#[test]
fn smaz_decompress_rejects_truncated_markers() {
	// smaz 0.1.0 panics on all of these; the local decoder must return Err.
	assert!(Slatepack::smaz_decompress(&[254]).is_err());
	assert!(Slatepack::smaz_decompress(&[255]).is_err());
	assert!(Slatepack::smaz_decompress(&[0, 254]).is_err());
	assert!(Slatepack::smaz_decompress(&[0, 255]).is_err());
	assert!(Slatepack::smaz_decompress(&[255, 5, 1, 2]).is_err());
	assert!(Slatepack::smaz_decompress(&[255, 1, 7]).is_err());
}

#[test]
fn smaz_compress_decompress_full_cycle() {
	// compress -> decompress must be the identity for any input. Covers the
	// reference smaz test strings, multi-byte UTF-8, long incompressible
	// input (forces the 256-byte verbatim-run flush) and every possible byte
	// value, so 0xfe/0xff also appear as *data*, not only as markers.
	let mut messages: Vec<Vec<u8>> = [
		"",
		"This is a small string",
		"foobar",
		"the end",
		"not-a-g00d-Exampl333",
		"Smaz is a simple compression library",
		"Nothing is more difficult, and therefore more precious, than to be able to decide",
		"this is an example of what works very well with smaz",
		"1000 numbers 2000 will 10 20 30 compress very little",
		"and now a few italian sentences:",
		"Nel mezzo del cammin di nostra vita, mi ritrovai in una selva oscura",
		"Mi illumino di immenso",
		"L'autore di questa libreria vive in Sicilia",
		"try it against urls",
		"http://google.com",
		"http://programming.reddit.com",
		"\u{a5} \u{20ac} unicode \u{1f600}",
	]
	.iter()
	.map(|s| s.as_bytes().to_vec())
	.collect();
	// Incompressible: '9' has no codebook entry.
	messages.push(vec![b'9'; 700]);
	// Long but highly compressible.
	messages.push(
		"the end of the road, the beginning of the path, "
			.repeat(40)
			.into_bytes(),
	);
	// Every byte value, including the 0xfe/0xff marker bytes themselves.
	messages.push((0u8..=255).collect());

	for message in messages {
		let compressed = Slatepack::smaz_compress(&message);
		let cycled = Slatepack::smaz_decompress(&compressed).unwrap_or_else(|e| {
			panic!(
				"decompress failed for input of len {}: {}",
				message.len(),
				e
			)
		});
		assert_eq!(
			cycled,
			message,
			"full cycle mismatch for input of len {} starting {:?}",
			message.len(),
			&message[..message.len().min(16)]
		);
	}
}

#[test]
fn smaz_wire_format_matches_reference_vectors() {
	// Compressed bytes produced by the reference smaz 0.1.0 implementation.
	// They lock wire compatibility with other wallets now that the smaz
	// crate is no longer a dependency. The vectors cover codebook hits,
	// single verbatim bytes (0xfe), verbatim runs (0xff), multi-byte UTF-8
	// and the empty message.
	let vectors: [(&str, &[u8]); 8] = [
		("", &[]),
		("a", &[4]),
		("z", &[219]),
		(
			"test string to check the compress",
			&[
				69, 77, 62, 195, 70, 82, 73, 16, 28, 254, 107, 13, 251, 147, 60, 33, 166,
			],
		),
		(
			"not-a-g00d-Exampl333",
			&[
				132, 204, 4, 204, 59, 255, 1, 48, 48, 24, 204, 254, 69, 250, 4, 45, 60, 22, 255, 2,
				51, 51, 51,
			],
		),
		("http://google.com", &[67, 59, 6, 6, 59, 87, 253]),
		(
			"\u{a5} \u{20ac} unicode \u{1f600}",
			&[
				255, 1, 194, 165, 0, 255, 2, 226, 130, 172, 0, 224, 131, 6, 106, 0, 255, 3, 240,
				159, 152, 128,
			],
		),
		(
			"Nothing is more difficult, and therefore more precious, than to be able to decide",
			&[
				254, 78, 223, 102, 99, 116, 45, 42, 11, 129, 44, 44, 131, 38, 22, 3, 148, 63, 210,
				68, 11, 45, 42, 11, 60, 33, 28, 144, 164, 36, 203, 143, 96, 92, 25, 90, 87, 82,
				165, 215, 237, 2,
			],
		),
	];
	for (message, reference) in vectors {
		assert_eq!(
			&Slatepack::smaz_compress(message.as_bytes())[..],
			reference,
			"compress mismatch for {:?}",
			message
		);
		assert_eq!(
			&Slatepack::smaz_decompress(reference).unwrap()[..],
			message.as_bytes(),
			"decompress mismatch for {:?}",
			message
		);
	}
}

#[cfg(test)]
#[path = "serialization_tests.rs"]
mod serialization_tests;

#[cfg(test)]
mod key_validation_tests {
	use super::*;

	fn weak_key() -> ed25519_dalek::VerifyingKey {
		let mut identity = [0u8; 32];
		identity[0] = 1;
		let key = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
		assert!(key.is_weak());
		key
	}

	fn encrypted_header(
		sender: &ed25519_dalek::VerifyingKey,
		recipient: &ed25519_dalek::VerifyingKey,
	) -> Vec<u8> {
		let mut data = Vec::with_capacity(SLATE_PACK_PLAIN_DATA_SIZE);
		data.push(0);
		data.extend_from_slice(sender.as_bytes());
		data.extend_from_slice(recipient.as_bytes());
		data
	}

	#[test]
	fn encrypted_slatepack_rejects_weak_header_keys() {
		let secp = Secp256k1::new().unwrap();
		let secret = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let valid = secret.verifying_key();
		let weak = weak_key();

		let sender_error =
			Slatepack::from_binary(0, &encrypted_header(&weak, &valid), true, &secret, &secp)
				.unwrap_err();
		assert!(sender_error.to_string().contains("sender public key"));

		let recipient_error =
			Slatepack::from_binary(0, &encrypted_header(&valid, &weak), true, &secret, &secp)
				.unwrap_err();
		assert!(recipient_error.to_string().contains("recipient public key"));
	}

	#[test]
	fn encrypted_slatepack_rejects_headers_unbound_to_wallet_key() {
		let secp = Secp256k1::new().unwrap();
		let wallet_secret = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let claimed_sender = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).verifying_key();
		let claimed_recipient = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();

		let error = Slatepack::from_binary(
			0,
			&encrypted_header(&claimed_sender, &claimed_recipient),
			true,
			&wallet_secret,
			&secp,
		)
		.unwrap_err();

		assert!(error
			.to_string()
			.contains("neither addressed to nor sent by"));
	}

	#[test]
	fn encrypted_slatepack_rejects_sender_key_mismatch_during_encoding() {
		let secp = Secp256k1::new().unwrap();
		let encryption_secret = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let claimed_sender = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).verifying_key();
		let recipient = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
		let slatepack = Slatepack {
			sender: Some(claimed_sender),
			recipient: Some(recipient),
			content: SlatePurpose::FullSlate,
			slate: Slate::blank(2, true).unwrap(),
		};

		let error = slatepack
			.to_binary(
				0,
				SlateVersion::SP,
				&encryption_secret,
				#[cfg(feature = "test-support")]
				false,
				&secp,
			)
			.unwrap_err();

		assert!(error.to_string().contains("does not match"));
	}

	#[test]
	fn payload_crypto_rejects_weak_peer_keys() {
		let secret = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let weak = weak_key();

		let encrypt_error = Slatepack::encrypt_payload(
			vec![1, 2, 3],
			&secret,
			&weak,
			#[cfg(feature = "test-support")]
			false,
		)
		.unwrap_err();
		assert!(matches!(encrypt_error, Error::SlatepackEncodeError(_)));

		let decrypt_error =
			Slatepack::decrypt_payload(vec![0; 16], [0; 12], &secret, &weak).unwrap_err();
		assert!(matches!(decrypt_error, Error::SlatepackDecodeError(_)));
	}
}
