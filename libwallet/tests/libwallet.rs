// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

//! core::libtx specific tests
use mwc_wallet_libwallet::proof::crypto::Hex;
use mwc_wallet_libwallet::Context;
use mwc_wallet_util::mwc_core::core::{transaction, FeeFields};
use mwc_wallet_util::mwc_core::libtx::{aggsig, proof};
use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::{
	BlindSum, BlindingFactor, ChildNumber, ExtKeychain, ExtKeychainPath, Keychain,
	SwitchCommitmentType,
};

fn kernel_sig_msg() -> secp::Message {
	transaction::KernelFeatures::Plain {
		fee: FeeFields::new(1).unwrap(),
	}
	.kernel_sig_msg(0)
	.unwrap()
}

#[test]
fn aggsig_sender_receiver_interaction() {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let parent = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let switch = SwitchCommitmentType::Regular;
	let sender_keychain = ExtKeychain::from_seed(&secp, &[1u8; 32], true).unwrap();
	let receiver_keychain = ExtKeychain::from_seed(&secp, &[2u8; 32], true).unwrap();

	// Calculate the kernel excess here for convenience.
	// Normally this would happen during transaction building.
	let kernel_excess = {
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let skey1 = sender_keychain.derive_key(&secp, 0, &id1, switch).unwrap();
		let skey2 = receiver_keychain
			.derive_key(&secp, 0, &id1, switch)
			.unwrap();

		let blinding_factor = sender_keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.add_blinding_factor(BlindingFactor::from_secret_key(skey2)),
			)
			.unwrap();

		secp.commit(0, blinding_factor.secret_key(&secp).unwrap())
			.unwrap()
	};

	let s_cx;
	let mut rx_cx;
	// sender starts the tx interaction
	let (sender_pub_excess, sender_pub_nonce) = {
		let keychain = sender_keychain.clone();
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let skey = keychain.derive_key(&secp, 0, &id1, switch).unwrap();

		// dealing with an input here so we need to negate the blinding_factor
		// rather than use it as is
		let bs = BlindSum::new();
		let blinding_factor = keychain
			.blind_sum(
				&secp,
				&bs.sub_blinding_factor(BlindingFactor::from_secret_key(skey)),
			)
			.unwrap();

		let blind = blinding_factor.secret_key(&secp).unwrap();

		s_cx = Context::with_excess(
			&secp,
			blind,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			0,
			0,
			0,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		s_cx.get_public_keys(&secp).unwrap()
	};

	let pub_nonce_sum;
	let pub_key_sum;
	// receiver receives partial tx
	let (receiver_pub_excess, receiver_pub_nonce, rx_sig_part) = {
		let keychain = receiver_keychain.clone();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

		// let blind = blind_sum.secret_key(&secp)?;
		let blind = keychain.derive_key(&secp, 0, &key_id, switch).unwrap();

		rx_cx = Context::with_excess(
			&secp,
			blind,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			1,
			0,
			0,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		let (pub_excess, pub_nonce) = rx_cx.get_public_keys(&secp).unwrap();
		rx_cx.add_output(&key_id, &None, 0);

		pub_nonce_sum = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().1,
				&rx_cx.get_public_keys(&secp).unwrap().1,
			],
		)
		.unwrap();

		pub_key_sum = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().0,
				&rx_cx.get_public_keys(&secp).unwrap().0,
			],
		)
		.unwrap();

		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&secp,
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();
		(pub_excess, pub_nonce, sig_part)
	};

	// check the sender can verify the partial signature
	// received in the response back from the receiver
	{
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&secp,
			&rx_sig_part,
			&pub_nonce_sum,
			&receiver_pub_nonce,
			&receiver_pub_excess,
			&pub_key_sum,
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// now sender signs with their key
	let sender_sig_part = {
		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&secp,
			&s_cx.sec_key,
			&s_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();
		sig_part
	};

	// check the receiver can verify the partial signature
	// received by the sender
	{
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&secp,
			&sender_sig_part,
			&pub_nonce_sum,
			&sender_pub_nonce,
			&sender_pub_excess,
			&pub_key_sum,
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Receiver now builds final signature from sender and receiver parts
	let (final_sig, final_pubkey) = {
		let msg = kernel_sig_msg();
		let our_sig_part = aggsig::calculate_partial_sig(
			&secp,
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();

		// Receiver now generates final signature from the two parts
		let final_sig =
			aggsig::add_signatures(&secp, vec![&sender_sig_part, &our_sig_part], &pub_nonce_sum)
				.unwrap();

		// Receiver calculates the final public key (to verify sig later)
		let final_pubkey = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().0,
				&rx_cx.get_public_keys(&secp).unwrap().0,
			],
		)
		.unwrap();

		(final_sig, final_pubkey)
	};

	// Receiver checks the final signature verifies
	{
		let msg = kernel_sig_msg();

		// Receiver check the final signature verifies
		let sig_verifies =
			aggsig::verify_completed_sig(&secp, &final_sig, &final_pubkey, &final_pubkey, &msg);
		assert!(!sig_verifies.is_err());
	}

	// Check we can verify the sig using the kernel excess
	{
		let msg = kernel_sig_msg();
		let sig_verifies =
			aggsig::verify_single_from_commit(&secp, &final_sig, &msg, &kernel_excess);

		assert!(!sig_verifies.is_err());
	}
}

#[test]
fn aggsig_sender_receiver_interaction_offset() {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let parent = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let switch = SwitchCommitmentType::Regular;
	let sender_keychain = ExtKeychain::from_seed(&secp, &[1u8; 32], true).unwrap();
	let receiver_keychain = ExtKeychain::from_seed(&secp, &[2u8; 32], true).unwrap();

	// This is the kernel offset that we use to split the key
	// Summing these at the block level prevents the
	// kernels from being used to reconstruct (or identify) individual transactions
	let kernel_offset = SecretKey::new(&secp, &mut SysRng).unwrap();

	// Calculate the kernel excess here for convenience.
	// Normally this would happen during transaction building.
	let kernel_excess = {
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let skey1 = sender_keychain.derive_key(&secp, 0, &id1, switch).unwrap();
		let skey2 = receiver_keychain
			.derive_key(&secp, 0, &id1, switch)
			.unwrap();

		let blinding_factor = sender_keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.add_blinding_factor(BlindingFactor::from_secret_key(skey2))
					// subtract the kernel offset here like as would when
					// verifying a kernel signature
					.sub_blinding_factor(BlindingFactor::from_secret_key(kernel_offset.clone())),
			)
			.unwrap();

		secp.commit(0, blinding_factor.secret_key(&secp).unwrap())
			.unwrap()
	};

	let s_cx;
	let mut rx_cx;
	// sender starts the tx interaction
	let (sender_pub_excess, sender_pub_nonce) = {
		let keychain = sender_keychain.clone();
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let skey = keychain.derive_key(&secp, 0, &id1, switch).unwrap();

		// dealing with an input here so we need to negate the blinding_factor
		// rather than use it as is
		let blinding_factor = keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey))
					// subtract the kernel offset to create an aggsig context
					// with our "split" key
					.sub_blinding_factor(BlindingFactor::from_secret_key(kernel_offset)),
			)
			.unwrap();

		let blind = blinding_factor.secret_key(&secp).unwrap();

		s_cx = Context::with_excess(
			&secp,
			blind,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			0,
			0,
			0,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		s_cx.get_public_keys(&secp).unwrap()
	};

	// receiver receives partial tx
	let pub_nonce_sum;
	let pub_key_sum;
	let (receiver_pub_excess, receiver_pub_nonce, sig_part) = {
		let keychain = receiver_keychain.clone();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

		let blind = keychain.derive_key(&secp, 0, &key_id, switch).unwrap();

		rx_cx = Context::with_excess(
			&secp,
			blind,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			1,
			0,
			0,
			None,
			0,
			0,
			None,
			true,
		)
		.unwrap();
		let (pub_excess, pub_nonce) = rx_cx.get_public_keys(&secp).unwrap();
		rx_cx.add_output(&key_id, &None, 0);

		pub_nonce_sum = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().1,
				&rx_cx.get_public_keys(&secp).unwrap().1,
			],
		)
		.unwrap();

		pub_key_sum = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().0,
				&rx_cx.get_public_keys(&secp).unwrap().0,
			],
		)
		.unwrap();

		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&secp,
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();
		(pub_excess, pub_nonce, sig_part)
	};

	// check the sender can verify the partial signature
	// received in the response back from the receiver
	{
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&secp,
			&sig_part,
			&pub_nonce_sum,
			&receiver_pub_nonce,
			&receiver_pub_excess,
			&pub_key_sum,
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// now sender signs with their key
	let sender_sig_part = {
		let msg = kernel_sig_msg();
		let sig_part = aggsig::calculate_partial_sig(
			&secp,
			&s_cx.sec_key,
			&s_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();
		sig_part
	};

	// check the receiver can verify the partial signature
	// received by the sender
	{
		let msg = kernel_sig_msg();
		let sig_verifies = aggsig::verify_partial_sig(
			&secp,
			&sender_sig_part,
			&pub_nonce_sum,
			&sender_pub_nonce,
			&sender_pub_excess,
			&pub_key_sum,
			&msg,
		);
		assert!(!sig_verifies.is_err());
	}

	// Receiver now builds final signature from sender and receiver parts
	let (final_sig, final_pubkey) = {
		let msg = kernel_sig_msg();
		let our_sig_part = aggsig::calculate_partial_sig(
			&secp,
			&rx_cx.sec_key,
			&rx_cx.sec_nonce,
			&pub_nonce_sum,
			&pub_key_sum,
			&msg,
		)
		.unwrap();

		// Receiver now generates final signature from the two parts
		let final_sig =
			aggsig::add_signatures(&secp, vec![&sender_sig_part, &our_sig_part], &pub_nonce_sum)
				.unwrap();

		// Receiver calculates the final public key (to verify sig later)
		let final_pubkey = PublicKey::from_combination(
			&secp,
			vec![
				&s_cx.get_public_keys(&secp).unwrap().0,
				&rx_cx.get_public_keys(&secp).unwrap().0,
			],
		)
		.unwrap();

		(final_sig, final_pubkey)
	};

	// Receiver checks the final signature verifies
	{
		let msg = kernel_sig_msg();

		// Receiver check the final signature verifies
		let sig_verifies =
			aggsig::verify_completed_sig(&secp, &final_sig, &final_pubkey, &final_pubkey, &msg);
		assert!(!sig_verifies.is_err());
	}

	// Check we can verify the sig using the kernel excess
	{
		let msg = kernel_sig_msg();
		let sig_verifies =
			aggsig::verify_single_from_commit(&secp, &final_sig, &msg, &kernel_excess);

		assert!(!sig_verifies.is_err());
	}
}

#[test]
fn test_rewind_range_proof() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = ExtKeychain::from_seed(&secp, &[1u8; 32], true).unwrap();
	let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let switch = SwitchCommitmentType::Regular;
	let commit = keychain.commit(&secp, 5, &key_id, switch).unwrap();

	let proof = proof::create(
		&mut secp,
		&keychain,
		&builder,
		5,
		&key_id,
		switch,
		commit,
	)
	.unwrap();
	let proof_info = proof::rewind(
		&mut secp,
		&builder,
		commit,
		None,
		proof,
	)
	.unwrap();

	assert!(proof_info.is_some());
	let (r_amount, r_key_id, r_switch) = proof_info.unwrap();
	assert_eq!(r_amount, 5);
	assert_eq!(r_key_id, key_id);
	assert_eq!(r_switch, switch);

	// cannot rewind with a different commit
	let commit2 = keychain.commit(&secp, 5, &key_id2, switch).unwrap();
	assert!(matches!(
		proof::rewind(
			&mut secp,
			&builder,
			commit2,
			None,
			proof,
		),
		Err(mwc_wallet_util::mwc_core::libtx::Error::Secp(
			secp::Error::InvalidRangeProof
		))
	));

	// cannot rewind with a commitment to a different value
	let commit3 = keychain.commit(&secp, 4, &key_id, switch).unwrap();
	assert!(matches!(
		proof::rewind(
			&mut secp,
			&builder,
			commit3,
			None,
			proof,
		),
		Err(mwc_wallet_util::mwc_core::libtx::Error::Secp(
			secp::Error::InvalidRangeProof
		))
	));

	// cannot rewind with wrong extra committed data
	let wrong_extra_data = [98u8; 64];
	assert!(matches!(
		proof::rewind(
			&mut secp,
			&builder,
			commit,
			Some(wrong_extra_data.to_vec().clone()),
			proof,
		),
		Err(mwc_wallet_util::mwc_core::libtx::Error::Secp(
			secp::Error::InvalidRangeProof
		))
	));

	let key_id4 = ExtKeychain::derive_key_id(4, 2, 0, 0, 5).unwrap(); //simulate a height of 5.
	let commit4 = keychain.commit(&secp, 5, &key_id4, switch).unwrap();
	let _key_id5 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap(); //simulate a height of 5.
	let _commit5 = keychain.commit(&secp, 5, &key_id4, switch).unwrap();
	let proof4 = proof::create(
		&mut secp, &keychain, &builder, 5, &key_id4, switch, commit4,
	)
	.unwrap();

	let proof_info4 = proof::rewind(&mut secp, &builder, commit4, None, proof4).unwrap();

	assert!(proof_info4.is_some());
	let (r_amount, r_key_id, r_switch) = proof_info4.unwrap();
	assert_eq!(r_amount, 5);
	assert_eq!(r_key_id, key_id4);
	assert_eq!(r_switch, switch);
	let path = key_id4.to_path().unwrap();
	let last_child_number = path.path[3];

	let mut built_height = 0;
	if let ChildNumber::Normal { index: ind } = last_child_number {
		built_height = ind;
	}
	assert_eq!(built_height, 5);
}

#[test]
fn blind_factor() {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	// This is the kernel offset that we use to split the key
	// Summing these at the block level prevents the
	// kernels from being used to reconstruct (or identify) individual transactions
	let _kernel_offset = SecretKey::new(&secp, &mut SysRng).unwrap();

	let bytes_32: [u8; 32] = [
		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31, 32, 33,
	];

	let kernel_offset = BlindingFactor::from_slice(&bytes_32).unwrap();
	let offset_skey = kernel_offset.secret_key(&secp).unwrap();
	let offset_commit = secp.commit(0, offset_skey).unwrap();
	//the hex string of the offset commit should remains the same.
	let mut i = 0;

	while i < 5 {
		assert_eq!(
			offset_commit.to_hex(&secp).unwrap(),
			"08460a7b966efffb36946f6dc3c17ff73ad789fc1c2df43c1258039ca2f9a1e3e6"
		);
		i = i + 1;
	}
}
