// Copyright 2020 The Grin Developers
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
use crate::{Slate, SlateVersion, Slatepack, SlatepackArmor};

use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use grin_wallet_util::grin_util::secp::Secp256k1;

use crate::slatepack::slatepack::SlatePurpose;

#[derive(Clone, Debug)]
/// Arguments, mostly for encrypting decrypting a slatepack
pub struct Slatepacker {
	/// Sender address, None for wrapped
	pub sender: Option<DalekPublicKey>,
	/// Recipient addresses, None for wrapped
	pub recipient: Option<DalekPublicKey>,
	/// The content purpose. It customize serializer/deserializer for us.
	pub content: SlatePurpose,
	/// Slate data.
	pub slate: Slate,
}

impl Slatepacker {
	/// Swap a slate with the packer. Slate is expecte to be full
	pub fn wrap_slate(slate: Slate) -> Self {
		Self {
			sender: None,
			recipient: None,
			content: SlatePurpose::FullSlate,
			slate,
		}
	}

	/// Pack everything into the armored slatepack
	pub fn encrypt_to_send(
		slate: Slate,
		slate_version: SlateVersion,
		content: SlatePurpose,
		sender: DalekPublicKey,
		recipient: Option<DalekPublicKey>, // Encrypted only if recipient is some
		secret: &DalekSecretKey,
		use_test_rng: bool,
		secp: &Secp256k1,
	) -> Result<String, Error> {
		let pack = Slatepack {
			sender: Some(sender),
			recipient: recipient,
			content,
			slate: slate,
		};

		let (slate_bin, encrypted) = pack.to_binary(slate_version, secret, use_test_rng, secp)?;

		SlatepackArmor::encode(&slate_bin, encrypted)
	}

	/// return slatepack
	pub fn decrypt_slatepack(
		data: &[u8],
		dec_key: &DalekSecretKey,
		height: u64,
		secp: &Secp256k1,
	) -> Result<Self, Error> {
		let (slate_bytes, encrypted) = SlatepackArmor::decode(data)?;

		let slatepack = Slatepack::from_binary(&slate_bytes, encrypted, dec_key, height, secp)?;

		let Slatepack {
			sender,
			recipient,
			content,
			slate,
		} = slatepack;

		Ok(Self {
			sender,
			recipient,
			content,
			slate,
		})
	}

	/// Get Transaction ID related into form this slatepack
	pub fn get_content(&self) -> SlatePurpose {
		self.content.clone()
	}

	/// Get Sender info. It is needed to send the response back
	pub fn get_sender(&self) -> Option<DalekPublicKey> {
		self.sender.clone()
	}

	/// Get Sender info. It is needed to send the response back
	pub fn get_recipient(&self) -> Option<DalekPublicKey> {
		self.recipient.clone()
	}

	/// Convert this slate back to the resulting slate. Since the slate pack contain only the change set,
	/// to recover the data it is required original slate to merge with.
	pub fn to_result_slate(self) -> Slate {
		self.slate
	}
}

#[test]
fn slatepack_io_test() {
	use crate::grin_core::core::KernelFeatures;
	use crate::grin_core::core::{Input, Output, OutputFeatures, Transaction, TxKernel};
	use crate::grin_core::global;
	use crate::grin_keychain::BlindingFactor;
	use crate::grin_keychain::ExtKeychain;
	use crate::grin_util as util;
	use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
	use crate::grin_util::secp::Signature;
	use crate::grin_util::secp::{PublicKey, SecretKey};
	use crate::proof::proofaddress;
	use crate::proof::proofaddress::ProvableAddress;
	use crate::slate::{PaymentInfo, VersionCompatInfo};
	use crate::ParticipantData;
	use grin_wallet_util::grin_util::secp::Secp256k1;
	use uuid::Uuid;
	use x25519_dalek::PublicKey as xDalekPublicKey;

	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	let bytes_16: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
	let bytes_32: [u8; 32] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32,
	];
	let bytes_32_2: [u8; 32] = [
		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31, 32, 33,
	];
	let bytes_33: [u8; 33] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32, 33,
	];
	let bytes_64: [u8; 64] = [
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
		26, 27, 28, 29, 30, 31, 32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
		19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	];

	let secp = Secp256k1::new();
	let sk = SecretKey::from_slice(&secp, &bytes_32).unwrap();

	let dalek_sk = DalekSecretKey::from_bytes(&bytes_32).unwrap();
	let dalek_pk = DalekPublicKey::from(&dalek_sk);

	let dalek_sk2 = DalekSecretKey::from_bytes(&bytes_32_2).unwrap();
	let dalek_pk2 = DalekPublicKey::from(&dalek_sk2);

	// Let's test out Dalec 2 xDalec algebra.
	let dalek_xpk = proofaddress::tor_pub_2_slatepack_pub(&dalek_pk).unwrap();
	let dalek_xpk2 = proofaddress::tor_pub_2_slatepack_pub(&dalek_pk2).unwrap();
	let dalek_xsk = proofaddress::tor_secret_2_slatepack_secret(&dalek_sk);
	let dalek_xsk2 = proofaddress::tor_secret_2_slatepack_secret(&dalek_sk2);

	let builded_xpk = xDalekPublicKey::from(&dalek_xsk);
	let builded_xpk2 = xDalekPublicKey::from(&dalek_xsk2);

	assert_eq!(dalek_xpk.as_bytes(), builded_xpk.as_bytes());
	assert_eq!(dalek_xpk2.as_bytes(), builded_xpk2.as_bytes());

	// check if Diffie Hoffman works...
	let shared_secret1 = dalek_xsk.diffie_hellman(&dalek_xpk2);
	let shared_secret2 = dalek_xsk2.diffie_hellman(&dalek_xpk);

	assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());

	// Note, Slate Data is fake. Just some randome numbers, it will not pass validation of any type
	let mut slate_enc = Slate::new(
		true,
		VersionCompatInfo {
			version: 3,
			block_header_version: 1,
		},
		2,
		Uuid::from_bytes(bytes_16),
		Some(Transaction::empty()
			.with_offset(BlindingFactor::from_slice(&bytes_32) )
			.with_input( Input::new( OutputFeatures::Plain, Commitment(bytes_33)) )
			.with_output( Output::new(OutputFeatures::Plain, Commitment(bytes_33), RangeProof::zero()))
			.with_kernel( TxKernel::with_features(KernelFeatures::Plain { fee: 321.into() }) )),
		30000000000000000,
		321,
		67,
		0,
		0,
		Some(54),
		vec![
			ParticipantData {
				id: 0,
				public_blind_excess: PublicKey::from_secret_key( &secp, &sk).unwrap(),
				public_nonce:  PublicKey::from_secret_key( &secp, &sk).unwrap(),
				part_sig: None,
				message: Some("message 1 to send".to_string()),
				message_sig: Some(Signature::from_compact(&secp, &util::from_hex("89cc3c1480fea655f29d300fcf68d0cfbf53f96a1d6b1219486b64385ed7ed89acf96f1532b31ac8309e611583b1ecf37090e79700fae3683cf682c0043b3029").unwrap()).unwrap()),
			},
			ParticipantData {
				id: 1,
				public_blind_excess: PublicKey::from_secret_key( &secp, &sk).unwrap(),
				public_nonce:  PublicKey::from_secret_key( &secp, &sk).unwrap(),
				part_sig: Some(Signature::from_compact(&secp, &util::from_hex("89cc3c1480fea655f29d300fcf68d0cfbf53f96a1d6b1219486b64385ed7ed89acf96f1532b31ac8309e611583b1ecf37090e79700fae3683cf682c0043b3029").unwrap()).unwrap()),
				message: Some("message 2 to send".to_string()),
				message_sig: Some(Signature::from_compact(&secp, &util::from_hex("89cc3c1480fea655f29d300fcf68d0cfbf53f96a1d6b1219486b64385ed7ed89acf96f1532b31ac8309e611583b1ecf37090e79700fae3683cf682c0043b3029").unwrap()).unwrap()),
			}
		],
		Some(PaymentInfo {
			sender_address: ProvableAddress::from_str("a5ib4b2l5snzdgxzpdzouwxwvn4c3setpp5t5j2tr37n3uy3665qwnqd").unwrap(),
			receiver_address: ProvableAddress::from_str("a5ib4b2l5snzdgxzpdzouwxwvn4c3setpp5t5j2tr37n3uy3665qwnqd").unwrap(),
			receiver_signature: Some( util::to_hex(&bytes_64) ),
		}),
		BlindingFactor::from_slice(&bytes_32)).unwrap();

	let height = 67;

	// updating kernel excess
	slate_enc.tx_or_err_mut().unwrap().body.kernels[0].excess = slate_enc
		.calc_excess::<ExtKeychain>(&secp, None, height)
		.unwrap();

	let slate_enc_str = format!("{:?}", slate_enc);
	println!("start encrypted slate = {}", slate_enc_str);

	// Not encoded, just want to review the data...
	let slatepack_string_encrypted = Slatepacker::encrypt_to_send(
		slate_enc.clone(),
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		dalek_pk.clone(),
		Some(dalek_pk2.clone()), // sending to self, should be fine...
		&dalek_sk,
		true,
		&secp,
	)
	.unwrap();
	println!("slatepack encrypted = {}", slatepack_string_encrypted);

	// Not encoded, just want to review the data...
	let slatepack_string_binary = Slatepacker::encrypt_to_send(
		slate_enc.clone(),
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		dalek_pk.clone(),
		None, // No recipient, should trigger non encrypted mode.
		&dalek_sk,
		true,
		&secp,
	)
	.unwrap();
	println!("slatepack binary = {}", slatepack_string_binary);

	assert!(slatepack_string_encrypted.len() > slatepack_string_binary.len());

	// Testing if can open from a backup
	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_encrypted.as_bytes(),
		&dalek_sk,
		height,
		&secp,
	)
	.unwrap();
	let res_slate = slatepack.to_result_slate();
	let slate2_str = format!("{:?}", res_slate);
	println!("res_slate = {:?}", slate2_str);

	assert_eq!(slate_enc_str, slate2_str);

	// Testing if another party can open it
	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_encrypted.as_bytes(),
		&dalek_sk2,
		height,
		&secp,
	)
	.unwrap();
	let res_slate = slatepack.to_result_slate();
	let slate2_str = format!("{:?}", res_slate);
	println!("res_slate2 = {:?}", slate2_str);

	assert_eq!(slate_enc_str, slate2_str);

	// Testing if can decode form the binary
	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_binary.as_bytes(),
		&DalekSecretKey::from_bytes(&[1; 32]).unwrap(),
		height,
		&secp,
	)
	.unwrap();
	let res_slate = slatepack.to_result_slate();
	let slate3_str = format!("{:?}", res_slate);
	println!("slate3_str = {:?}", slate3_str);

	assert_eq!(slate_enc_str, slate3_str);

	// Now let's validate if kernel features processed correctly
	// Build kernel features based on variant and associated data.
	// 0: plain
	// 1: coinbase (invalid)
	// 2: height_locked (with associated lock_height)
	// 3: NRD (with associated relative_height)

	slate_enc.reset_lock_height();
	slate_enc.height = 1234567;

	let slatepack_string_encrypted = Slatepacker::encrypt_to_send(
		slate_enc.clone(),
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		dalek_pk.clone(),
		Some(dalek_pk2.clone()), // sending to self, should be fine...
		&dalek_sk,
		true,
		&secp,
	)
	.unwrap();

	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_encrypted.as_bytes(),
		&dalek_sk,
		height,
		&secp,
	)
	.unwrap();

	assert_eq!(
		slate_enc.get_lock_height(),
		slatepack.slate.get_lock_height()
	);
	assert_eq!(slate_enc.height, slatepack.slate.height);
	assert_eq!(
		slate_enc.get_kernel_features(),
		slatepack.slate.get_kernel_features()
	);

	slate_enc.set_lock_height(1234567 + 123).unwrap();
	slate_enc.height = 1234567;

	assert!(slate_enc.set_lock_height(1234567 - 123).is_err());

	let slatepack_string_encrypted = Slatepacker::encrypt_to_send(
		slate_enc.clone(),
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		dalek_pk.clone(),
		Some(dalek_pk2.clone()), // sending to self, should be fine...
		&dalek_sk,
		true,
		&secp,
	)
	.unwrap();

	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_encrypted.as_bytes(),
		&dalek_sk,
		height,
		&secp,
	)
	.unwrap();

	assert_eq!(
		slate_enc.get_lock_height(),
		slatepack.slate.get_lock_height()
	);
	assert_eq!(slate_enc.height, slatepack.slate.height);
	assert_eq!(
		slate_enc.get_kernel_features(),
		slatepack.slate.get_kernel_features()
	);

	assert!(slate_enc.set_related_height(123999).is_err());

	slate_enc.set_related_height(123).unwrap();
	slate_enc.height = 1234567;

	let slatepack_string_encrypted = Slatepacker::encrypt_to_send(
		slate_enc.clone(),
		SlateVersion::SP,
		SlatePurpose::FullSlate,
		dalek_pk.clone(),
		Some(dalek_pk2.clone()), // sending to self, should be fine...
		&dalek_sk,
		true,
		&secp,
	)
	.unwrap();

	let slatepack = Slatepacker::decrypt_slatepack(
		slatepack_string_encrypted.as_bytes(),
		&dalek_sk,
		height,
		&secp,
	)
	.unwrap();

	assert_eq!(
		slate_enc.get_lock_height(),
		slatepack.slate.get_lock_height()
	);
	assert_eq!(slate_enc.height, slatepack.slate.height);
	assert_eq!(
		slate_enc.get_kernel_features(),
		slatepack.slate.get_kernel_features()
	);
}
