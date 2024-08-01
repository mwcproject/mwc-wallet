// Copyright 2021 The Grin Developers
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
use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey, PUBLIC_KEY_LENGTH};
use std::convert::TryInto;

use crate::grin_util::secp::key::PublicKey;

use crate::{Error, ErrorKind};
use crate::{ParticipantData, Slate, SlateVersion};

use crate::proof::proofaddress::ProvableAddress;
use std::io;

use crate::grin_core::core::CommitWrapper;
use crate::grin_core::core::{
	Input, Inputs, KernelFeatures, Output, OutputFeatures, OutputIdentifier, TxKernel,
};
use crate::grin_core::global;
use crate::grin_keychain::{BlindingFactor, ExtKeychain};
use crate::grin_util::secp::constants::{PEDERSEN_COMMITMENT_SIZE, SECRET_KEY_SIZE};
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::grin_util::{from_hex, ToHex};
use crate::proof::proofaddress;
use crate::slate::PaymentInfo;
use bitstream_io::{BigEndian, BitReader, BitWriter, Endianness};
use crc::{crc32, Hasher32};
use grin_wallet_util::grin_core::consensus::WEEK_HEIGHT;
use grin_wallet_util::grin_util::secp::Secp256k1;
use rand::{thread_rng, Rng};
use ring::aead;
use smaz;
use uuid::Uuid;

/// Basic Slatepack definition
#[derive(Debug, Clone)]
pub struct Slatepack {
	// Optional Fields
	/// Sender address, non if slate wasn'r encrypted
	pub sender: Option<DalekPublicKey>,
	/// Recipient addresses, enrypted id defined
	pub recipient: Option<DalekPublicKey>,
	/// The content purpose. It customize serializer/deserializer for us.
	pub content: SlatePurpose,

	/// Slate data.
	pub slate: Slate,
}

/// Slate state definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
				return Err(ErrorKind::SlatepackDecodeError(format!(
					"SlatePackPurpose wrong value {}",
					i
				))
				.into())
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
}

const SLATE_PACK_PLAIN_DATA_SIZE: usize = 1 + 32 + 32;

impl Slatepack {
	/// Decode and decrypt the Slatepack
	/// Note:  from_binary & to_binary - are NOT serializers, minimum amount of the data is transported.
	/// from_binary & to_binary are symmetrical
	pub fn from_binary(
		data: &Vec<u8>,
		encrypted: bool,
		secret: &DalekSecretKey,
		height: u64,
		secp: &Secp256k1,
	) -> Result<Self, Error> {
		if encrypted && data.len() < SLATE_PACK_PLAIN_DATA_SIZE {
			return Err(
				ErrorKind::SlatepackDecodeError("Slatapack data is too short".to_string()).into(),
			);
		}
		let mut digest = crc32::Digest::new(crc32::IEEE);

		if encrypted {
			digest.write(&data[..SLATE_PACK_PLAIN_DATA_SIZE]);
		}

		let mut r = BitReader::endian(data.as_slice(), BigEndian);
		let version: u8 = r.read(8)?;
		if version != 0 {
			return Err(
				ErrorKind::SlatepackDecodeError("Wrong slatepack version".to_string()).into(),
			);
		}

		let (payload, sender, recipient) = if encrypted {
			// Sender address, so other party can open the message
			debug_assert!(PUBLIC_KEY_LENGTH == 32);
			let mut data: [u8; 32] = [0; 32];
			r.read_bytes(&mut data)?;
			let sender = DalekPublicKey::from_bytes(&data).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!(
					"Unable to read a sender public key, {}",
					e
				))
			})?;
			// Receiver address, so this wallet open the message if it is in the archive
			let mut data: [u8; 32] = [0; 32];
			r.read_bytes(&mut data)?;
			let recipient = DalekPublicKey::from_bytes(&data).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!(
					"Unable to read a sender public key, {}",
					e
				))
			})?;

			let mut nonce: [u8; 12] = [0; 12];
			r.read_bytes(&mut nonce)?;

			let enc_len: u32 = r.read(16)?;
			let mut data_to_decrypt: Vec<u8> = vec![0; enc_len as usize];
			r.read_bytes(&mut data_to_decrypt)?;
			let payload = match Self::decrypt_payload(
				data_to_decrypt.clone(),
				nonce.clone(),
				secret,
				&sender,
			) {
				Ok(payload) => payload,
				Err(e) => {
					// Try recipient PK.  May be we are open what was stored before.
					let res = Self::decrypt_payload(data_to_decrypt, nonce, secret, &recipient);
					if res.is_err() {
						// in case of error we want to return the parent error.
						return Err(e);
					}
					res.unwrap()
				}
			};

			// Let's check the payload CRC first (crc32 is last 4 bytes.)
			{
				digest.write(&payload[..(payload.len() - 4)]);
				let mut crc_reader = BitReader::endian(&payload[(payload.len() - 4)..], BigEndian);
				let read_crc32: u32 = crc_reader.read(32)?;
				let data_crc32 = digest.sum32();
				if read_crc32 != data_crc32 {
					return Err(ErrorKind::SlatepackDecodeError(
						"Slatepack content is not consistent".to_string(),
					)
					.into());
				}
			}

			(payload, Some(sender), Some(recipient))
		} else {
			let enc_len: u32 = r.read(16)?;
			let mut payload: Vec<u8> = vec![0; enc_len as usize];
			r.read_bytes(&mut payload)?;
			(payload, None, None)
		};

		let mut r = BitReader::endian(payload.as_slice(), BigEndian);
		let content = SlatePurpose::from_int(r.read(3)?)?;

		let mut slate = match content {
			SlatePurpose::InvoiceInitial => Self::read_slate_data(
				true, false, false, false, false, false, true, false, false, false, &mut r, secp,
			)?,
			SlatePurpose::InvoiceResponse => Self::read_slate_data(
				true, true, true, true, true, true, false, true, false, false, &mut r, secp,
			)?,
			SlatePurpose::FullSlate => Self::read_slate_data(
				true, true, true, true, true, true, true, true, true, true, &mut r, secp,
			)?,
			SlatePurpose::SendInitial => Self::read_slate_data(
				true, true, false, false, false, false, true, false, true, false, &mut r, secp,
			)?,
			SlatePurpose::SendResponse => Self::read_slate_data(
				false, false, true, false, true, true, false, true, true, true, &mut r, secp,
			)?,
		};

		Self::update_tx_from_slate(&mut slate, height, secp)?;

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
		slate_version: SlateVersion,
		secret: &DalekSecretKey,
		use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<(Vec<u8>, bool), Error> {
		if !self.slate.compact_slate {
			return Err(ErrorKind::SlatepackEncodeError(
				"Slatepack expecting only compact model".to_string(),
			)
			.into());
		}

		// Here we can calculate the version of the slatepack that it needed. Currently there is no choices, just a single version.
		match slate_version {
			SlateVersion::SP => (),
			_ => return Err(ErrorKind::SlatepackEncodeError("Slate is plain".to_string()).into()),
		}

		let mut encrypted_data = Vec::new();

		let mut w = BitWriter::endian(&mut encrypted_data, BigEndian);
		w.write(3, self.content.to_int())?;

		match self.content {
			SlatePurpose::InvoiceInitial => {
				Self::write_slate_data(
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
		w_pack.write(8, 0)?;

		if let Some(recipient) = &self.recipient {
			// recipient is define, so we can do encryption

			if self.sender.is_none() {
				return Err(ErrorKind::SlatepackEncodeError(
					"Not found expected sender value".to_string(),
				)
				.into());
			}
			let sender = self.sender.clone().unwrap();
			// Sender address, so other party can open the message
			debug_assert!(sender.as_bytes().len() == 32);
			w_pack.write_bytes(sender.as_bytes())?;
			// Receiver address, so this wallet open the message if it is in the archive
			debug_assert!(recipient.as_bytes().len() == 32);
			w_pack.write_bytes(recipient.as_bytes())?; // 32 bytes unencrypted - recipient. Primary reason - we want to be able to read what we write.
										   // expected to be aligned

			// Do CRC and encryption. CRC we want to be encrypted
			{
				let mut digest = crc32::Digest::new(crc32::IEEE);
				debug_assert!(pack_binary.len() == SLATE_PACK_PLAIN_DATA_SIZE);
				digest.write(&pack_binary);
				w.byte_align()?;

				digest.write(&encrypted_data);

				// We have to destroy prev instance of w in order to read from the encrypted_data for crc32.
				let mut w = BitWriter::endian(&mut encrypted_data, BigEndian);
				let crc32: u32 = digest.sum32();
				w.write(32, crc32)?;
			}
			let (encrypted_data, nonce) =
				Self::encrypt_payload(encrypted_data, secret, &recipient, use_test_rng)?;

			// We have to destroy prev instance of w_pack in order to read from the pack_binary for crc32.
			let mut w_pack = BitWriter::endian(&mut pack_binary, BigEndian);

			w_pack.write_bytes(&nonce)?;

			let enc_len = encrypted_data.len();
			if enc_len > 65534 {
				return Err(ErrorKind::SlatepackEncodeError(
					"Slate too large for encoding".to_string(),
				)
				.into());
			}
			w_pack.write(16, enc_len as u32)?; // Need to keep byte aligned
			w_pack.write_bytes(&encrypted_data)?;
			// expected to be aligned

			Ok((pack_binary, true))
		} else {
			// Non encrypted data. Just a plain binary format, not CRC any other control.
			w.byte_align()?;

			let enc_len = encrypted_data.len();
			if enc_len > 65534 {
				return Err(ErrorKind::SlatepackEncodeError(
					"Slate too large for encoding".to_string(),
				)
				.into());
			}
			w_pack.write(16, enc_len as u32)?; // Need to keep byte aligned
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
				hundreds += 1;
			}
		}
		// now calculating the used digits
		let mut d: u64 = 1;
		let mut dn = 1;
		while dn < 64 && d < amount {
			dn += 1;
			d <<= 1;
		}
		if has_hundreds {
			writer.write(3, hundreds)?; // 8 max value
		}
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
				w.write(1, 1)?;
				let sig_dt = sig.serialize_compact(secp);
				w.write_bytes(&sig_dt)?;
			}
			None => {
				w.write(1, 0)?;
			}
		}

		match &part_data.message {
			Some(message) => {
				w.write(1, 1)?;
				let mut message = message.clone();
				// let's limit message with 32 k
				let mut msg_enc = smaz::compress(message.as_bytes());
				while msg_enc.len() > 30000 {
					message.truncate(message.len() / 2);
					msg_enc = smaz::compress(message.as_bytes());
				}
				w.write(16, msg_enc.len() as u16)?;
				w.write_bytes(&msg_enc)?;

				// Writing signature as a proof of the message, so other party will not be able to change it as well
				if let Some(sig) = part_data.message_sig {
					let sig_dt = sig.serialize_compact(secp);
					w.write_bytes(&sig_dt)?;
				} else {
					return Err(ErrorKind::GenericError(
						"Not found message signature at participant data".to_string(),
					)
					.into());
				}
			}
			None => w.write::<u8>(1, 0)?,
		}
		Ok(())
	}

	fn write_publick_key<W: io::Write, E: Endianness>(
		pk: &PublicKey,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let xs = pk.serialize_vec(secp, true);
		w.write(7, xs.len() as u32)?;
		w.write_bytes(&xs)?;
		Ok(())
	}

	// Write this address 'efficeint' way. The problem that it can be PublicKey aka MQS address
	// or DalekPublicKey aka Tor Address.
	// We will need to save a a binary
	fn write_provable_address<W: io::Write, E: Endianness>(
		address: &ProvableAddress,
		w: &mut BitWriter<W, E>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		match address.public_key() {
			Ok(pk) => {
				//
				w.write(1, 1)?;
				Self::write_publick_key(&pk, w, secp)?;
			}
			Err(_) => {
				// it must be tor address.
				w.write(1, 0)?;
				// len is 32 bytes
				w.write_bytes(address.tor_public_key()?.as_bytes())?;
			}
		}
		Ok(())
	}

	fn write_slate_data<W: io::Write, E: Endianness>(
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
		// stransaction Id is included in every paylod
		// 16 bytes
		w.write_bytes(slate.id.as_bytes())?;
		// Add network Info. 1 for mainnet, 0 for for the rest...
		if global::is_mainnet() {
			w.write(1, 1)?;
		} else {
			w.write(1, 0)?;
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
				w.write(1, 1)?;
				Self::write_u64(h, false, w)?;
			}
			None => {
				w.write(1, 0)?;
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
					w.write(1, 0)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for commit in commit_wrapper {
						if has_data {
							w.write(1, 1)?; // go bit
						}
						// Len: constants::PEDERSEN_COMMITMENT_SIZE
						w.write_bytes(&commit.commitment().0)?;
						has_data = true;
					}
					w.write(1, 0)?; // stop bit
				}
				Inputs::FeaturesAndCommit(inputs) => {
					w.write(1, 1)?;
					// Using stop bit because normally we have few inputs...
					let mut has_data = false;
					for inp in inputs {
						if has_data {
							w.write(1, 1)?; // go bit
						}
						w.write(1, inp.features as u8)?;
						w.write_bytes(&inp.commit.0)?;
						has_data = true;
					}
					w.write(1, 0)?; // stop bit
				}
			}
		}

		if write_outputs {
			// Using stop bit because normally we have few inputs...
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for out in &slate.tx_or_err()?.body.outputs {
				if has_data {
					w.write(1, 1)?; // go bit
				}
				// Feature can be only plain
				// Len: constants::PEDERSEN_COMMITMENT_SIZE
				w.write_bytes(&out.identifier.commit.0)?;
				w.write(10, out.proof.plen as u32)?; // max 675 - should fit 10 bits
				w.write_bytes(out.proof.bytes())?;
				has_data = true;
			}
			w.write(1, 0)?; // stop bit
		}

		if write_kernels {
			// Using stop bit because normally there is only one kernel
			let mut has_data = false;
			// Because usually expecting 1 output, it is better to use a stop symbol instead on length
			for kernel in &slate.tx_or_err()?.body.kernels {
				if has_data {
					w.write(1, 1)?; // go bit
				}
				// Expecting only Plain kernels. It is about wallet basic operations, so nothing extra
				match kernel.features {
					KernelFeatures::Plain { fee } => {
						Self::write_u64(fee.into(), true, w)?;
					}
					_ => {
						return Err(ErrorKind::SlatepackEncodeError(
							"Slatepack expecting only Plain Kernels".to_string(),
						)
						.into())
					}
				}
				w.write_bytes(&kernel.excess.0)?;
				w.write_bytes(&kernel.excess_sig.serialize_compact(secp))?;
				has_data = true;
			}
			w.write(1, 0)?; // stop bit
		}

		if write_participan_data_0 {
			let part_data = slate
				.participant_with_id(0)
				.ok_or(ErrorKind::SlatepackEncodeError(
					"Not found slate participant data".to_string(),
				))?;
			Self::write_participant_data(&part_data, w, secp)?;
		}
		if write_participan_data_1 {
			let part_data = slate
				.participant_with_id(1)
				.ok_or(ErrorKind::SlatepackEncodeError(
					"Not found slate participant data".to_string(),
				))?;
			Self::write_participant_data(&part_data, w, secp)?;
		}

		if write_proof_addresses {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1)?;
					// len is 32 bytes
					Self::write_provable_address(&pp.sender_address, w, secp)?;
					Self::write_provable_address(&pp.receiver_address, w, secp)?;
					// signature is None
				}
				None => w.write(1, 0)?,
			}
		}

		if write_proof_signature {
			match &slate.payment_proof {
				Some(pp) => {
					w.write(1, 1)?;
					let sign_str =
						pp.receiver_signature
							.clone()
							.ok_or(ErrorKind::SlatepackEncodeError(
								"Not found expected payment proof signature".to_string(),
							))?;
					let sign_v = from_hex(&sign_str).map_err(|e| {
						ErrorKind::SlatepackEncodeError(format!(
							"Wrong signature at slate data, {}",
							e
						))
					})?;
					// Signature length can be different (so far it is 64 bytes or 70) because the PK might be from different families.
					// That is why let's save the size
					let sign_len = sign_v.len();
					if sign_len < 64 || sign_len >= 64 + 16 {
						return Err(ErrorKind::SlatepackEncodeError(
							"Invalid Signature length".to_string(),
						)
						.into());
					}
					let sign_len: u32 = sign_len as u32 - 64;
					w.write(4, sign_len)?;
					w.write_bytes(&sign_v)?;
				}
				None => w.write(1, 0)?,
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
		let mut amount: u64 = r.read(digits + 1)?;

		for _i in 0..hundreds {
			amount *= 100;
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
			Some(Signature::from_compact(secp, &sig_dt)?)
		} else {
			None
		};

		let (message, message_sig) = if r.read::<u8>(1)? == 1 {
			let sz: u32 = r.read(16)?;
			let mut msg: Vec<u8> = vec![0; sz as usize];
			r.read_bytes(&mut msg)?;
			let msg = smaz::decompress(&msg).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable to decode message, {}", e))
			})?;
			let mut sig_dt: [u8; 64] = [0; 64];
			r.read_bytes(&mut sig_dt)?;
			(
				Some(String::from_utf8(msg).map_err(|e| {
					ErrorKind::SlatepackDecodeError(format!("Unable to decode message, {}", e))
				})?),
				Some(Signature::from_compact(secp, &sig_dt)?),
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

	fn read_publick_key<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		secp: &Secp256k1,
	) -> Result<PublicKey, Error> {
		let xs_len: u32 = r.read(7)?;
		let mut xs: Vec<u8> = vec![0; xs_len as usize];
		r.read_bytes(&mut xs)?;
		let pk = PublicKey::from_slice(secp, &xs)?;
		Ok(pk)
	}

	fn read_provable_address<R: io::Read, E: Endianness>(
		r: &mut BitReader<R, E>,
		secp: &Secp256k1,
	) -> Result<ProvableAddress, Error> {
		let pa = if r.read::<u8>(1)? == 1 {
			// PublicKey (MQS)
			let pk = Self::read_publick_key(r, secp)?;
			ProvableAddress::from_pub_key(&pk)
		} else {
			let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
			r.read_bytes(&mut pk)?;
			let dalek_pk = DalekPublicKey::from_bytes(&pk).map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable decode Public Key data, {}", e))
			})?;

			ProvableAddress::from_tor_pub_key(&dalek_pk)
		};

		Ok(pa)
	}

	fn read_slate_data<R: io::Read, E: Endianness>(
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
		let mut slate = Slate::blank(2, true);
		let mut slate_id: [u8; 16] = [0; 16];
		r.read_bytes(&mut slate_id)?;
		slate.id = Uuid::from_slice(&slate_id).map_err(|e| {
			ErrorKind::SlatepackDecodeError(format!("Unable to encode UUID data, {}", e))
		})?;

		let network: u8 = r.read(1)?;

		if (network == 1) ^ global::is_mainnet() {
			return Err(
				ErrorKind::SlatepackDecodeError("Slate from wrong network".to_string()).into(),
			);
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
			slate.offset = BlindingFactor::from_slice(&offset);
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

				let proof_len: u32 = r.read(10)?;
				let mut proof_data: Vec<u8> = vec![0; proof_len as usize];
				r.read_bytes(&mut proof_data)?;

				let mut proof = RangeProof::zero();
				proof.plen = proof_len as usize;
				for i in 0..proof_len {
					proof.proof[i as usize] = proof_data[i as usize];
				}

				slate.tx_or_err_mut()?.body.outputs.push(Output {
					identifier: OutputIdentifier {
						features: OutputFeatures::Plain,
						commit: Commitment(commit),
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

				slate.tx_or_err_mut()?.body.kernels.push(TxKernel {
					features: KernelFeatures::Plain {
						fee: fee.try_into()?,
					},
					excess: Commitment(excess),
					excess_sig: Signature::from_compact(secp, &signature)?,
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
				let sender_address = Self::read_provable_address(r, secp)?;
				let receiver_address = Self::read_provable_address(r, secp)?;

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
				let sign_len = r.read::<u32>(4)? + 64;
				let mut signature: Vec<u8> = vec![0; sign_len as usize];
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
		secret: &DalekSecretKey,
		recipient: &DalekPublicKey,
		use_test_rng: bool,
	) -> Result<(Vec<u8>, [u8; 12]), Error> {
		// https://github.com/dalek-cryptography/x25519-dalek
		// convert to xDalek PK & Secret
		let recipient = proofaddress::tor_pub_2_slatepack_pub(&recipient)?;
		let secret = proofaddress::tor_secret_2_slatepack_secret(&secret);
		let shared_secret = secret.diffie_hellman(&recipient);

		let nonce: [u8; 12] = if use_test_rng {
			[1; 12]
		} else {
			thread_rng().gen()
		};

		let mut enc_bytes = payload;

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, shared_secret.as_bytes())
			.map_err(|e| {
				ErrorKind::SlatepackEncodeError(format!("Unable to build a key, {}", e))
			})?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut enc_bytes,
			)
			.map_err(|e| ErrorKind::SlatepackEncodeError(format!("Unable to encrypt, {}", e)))?;

		Ok((enc_bytes, nonce))
	}

	/// As above, decrypt if needed
	/// dec_key - is a secret that is used for all types of weallet addresses.
	fn decrypt_payload(
		payload: Vec<u8>,
		nonce: [u8; 12],
		secret: &DalekSecretKey,
		sender: &DalekPublicKey,
	) -> Result<Vec<u8>, Error> {
		// https://github.com/dalek-cryptography/x25519-dalek
		// convert to xDalek PK & Secret
		let sender = proofaddress::tor_pub_2_slatepack_pub(&sender)?;
		let secret = proofaddress::tor_secret_2_slatepack_secret(&secret);
		let shared_secret = secret.diffie_hellman(&sender);

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, shared_secret.as_bytes())
			.map_err(|e| {
				ErrorKind::SlatepackDecodeError(format!("Unable to build a key, {}", e))
			})?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);

		let mut encrypted_message = payload;

		let decrypted_data = opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut encrypted_message,
			)
			.map_err(|e| ErrorKind::SlatepackDecodeError(format!("Unable to decrypt, {}", e)))?;

		Ok(decrypted_data.to_vec())
	}

	// Update a transaction form the slate data.
	fn update_tx_from_slate(slate: &mut Slate, height: u64, secp: &Secp256k1) -> Result<(), Error> {
		debug_assert!(slate.compact_slate);
		// Passing None to calc_excess because it is not needed for compact_slate.
		let excess = match slate.calc_excess::<ExtKeychain>(secp, None, height) {
			Ok(e) => e,
			Err(_) => Commitment::from_vec(vec![0]),
		};
		let excess_sig = match slate.finalize_signature(secp) {
			Ok(s) => s,
			Err(_) => Signature::from_raw_data(&[0; 64])?,
		};
		let kernel = TxKernel {
			features: slate.kernel_features()?,
			excess,
			excess_sig,
		};

		// Updating tx kernel and offset with what slate has
		let offset = slate.offset.clone();
		let tx = slate.tx_or_err_mut()?;
		if tx.body.kernels.is_empty() {
			tx.body.kernels.push(kernel);
		} else {
			tx.body.kernels[0] = kernel;
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
	let msg_enc = smaz::compress(message.as_bytes());
	// see 33 to 17 compression.
	assert_eq!(message.len(), 33);
	assert_eq!(msg_enc.len(), 17);
	assert!(msg_enc.len() < message.len());

	let msg = smaz::decompress(&msg_enc).unwrap();
	let dec_msg = String::from_utf8(msg).unwrap();
	assert_eq!(message, dec_msg);
}
