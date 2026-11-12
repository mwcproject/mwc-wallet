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

//! tests differing accounts in the same wallet

#![cfg(feature = "test-support")]

use mwc_wallet_util::mwc_util::ToHex;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{InitTxArgs, Slate, SlateVersion};
use std::ops::DerefMut;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::proof::tx_proof::{
	ProofInsertResult, TxProof, next_proof_cache_generation, push_proof_for_slate,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};

/// Verify stored payment proofs for either participant order.
fn payment_proofs_test_impl(
	test_dir: &str,
	reverse_participants: bool,
) -> Result<(), mwc_wallet_controller::Error> {
	// Create a new proxy to simulate server and wallet responses
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false
	);

	let mask1 = (&mask1_i).as_ref();

	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false
	);

	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter

	// Do some mining
	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	let mut address = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			address = Some(api.get_mqs_address(m)?);
			Ok(())
		},
	)?;

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let address = ProvableAddress::from_pub_key(&secp, 0, &address.unwrap())?;
	println!("Public address is: {:?}", address);
	let amount = 2_000_000_000; // mwc value: 60_000_000_000
	let mut slate = Slate::blank(1, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			// note this will increment the block count as part of the transaction "Posting"
			let args = InitTxArgs {
				src_acct_name: None,
				amount: amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				payment_proof_recipient_address: Some(address.clone()),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;

			assert_eq!(
				slate_i
					.payment_proof
					.as_ref()
					.unwrap()
					.receiver_address
					.public_key,
				address.public_key,
			);
			println!(
				"Sender addr: {:?}",
				slate_i.payment_proof.as_ref().unwrap().sender_address
			);

			// Check we are creating a tx with kernel features 0
			// We will check this produces a Plain kernel later.
			assert_eq!(0, slate.get_kernel_features());

			// Check we are creating a tx with the expected lock_height of 0.
			// We will check this produces a Plain kernel later.
			assert_eq!(0, slate_i.get_lock_height());

			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;

			slate = if reverse_participants {
				// Participant IDs define the roles even when the receiver is
				// the first entry in the returned noncompact slate.
				assert!(!slate.compact_slate);
				slate.participant_data.reverse();
				assert_eq!(
					slate
						.participant_data
						.iter()
						.map(|p| p.id)
						.collect::<Vec<_>>(),
					vec![1, 0]
				);
				sender_api.finalize_tx_with_output_version(
					m,
					None,
					&slate,
					true,
					Some(SlateVersion::V3),
				)?
			} else {
				sender_api.finalize_tx(m, None, &slate, true)?
			};
			sender_api.post_tx(m, slate.tx_or_err()?, true)?;
			Ok(())
		},
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, _m| {
			let tx_proof = sender_api
				.get_stored_tx_proof(None, None, Some(slate.id))
				.unwrap();
			let proof_verify = sender_api.verify_tx_proof(&tx_proof).unwrap();

			assert_eq!(
				tx_proof.address.public_key,
				slate
					.payment_proof
					.as_ref()
					.unwrap()
					.receiver_address
					.public_key
			);
			assert_eq!(tx_proof.amount, slate.amount);

			assert_eq!(proof_verify.amount, slate.amount);
			assert_eq!(
				proof_verify.sender_address,
				slate
					.payment_proof
					.as_ref()
					.unwrap()
					.sender_address
					.public_key
			);
			assert_eq!(
				proof_verify.reciever_address,
				slate
					.payment_proof
					.as_ref()
					.unwrap()
					.receiver_address
					.public_key
			);

			assert_eq!(
				proof_verify.outputs.len(),
				slate.tx.as_ref().unwrap().body.outputs.len() - 1
			);
			let sz = proof_verify.outputs.len();
			for i in 0..sz {
				let mut found = false;
				for j in 0..sz + 1 {
					if proof_verify.outputs[i]
						== slate.tx.as_ref().unwrap().body.outputs[j]
							.identifier
							.commit
							.to_hex()
					{
						found = true;
						break;
					}
				}
				assert!(found);
			}
			assert_eq!(
				proof_verify.kernel,
				slate.tx.as_ref().unwrap().body.kernels[0].excess.to_hex()
			);
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		2,
		false,
		tx_pool.lock().deref_mut(),
	);

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, _m| {
			// Check payment proof here
			let mut tx_proof = sender_api
				.get_stored_tx_proof(None, None, Some(slate.id))
				.unwrap();

			println!("{:?}", tx_proof);

			// verify, should be good
			let _proof_verify = sender_api.verify_tx_proof(&tx_proof).unwrap();

			// Modify values, should not be good
			tx_proof.amount = 20;
			let res = sender_api.verify_tx_proof(&tx_proof);
			assert!(res.is_err());
			Ok(())
		},
	)?;

	// MQS can transport compact slates, but its cached transport proof uses the
	// legacy unversioned format that the payment-proof verifier rejects for a
	// compact slate. A cached MQS proof must therefore not replace the versioned
	// proof generated from the finalized slate.
	let mut compact_slate = Slate::blank(1, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				target_slate_version: Some(4),
				payment_proof_recipient_address: Some(address.clone()),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			assert!(slate_i.compact_slate);
			compact_slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &compact_slate, None, 0)?;

			let cached_legacy_proof = TxProof {
				address: address.clone(),
				message: "cached legacy MQS transport proof".to_owned(),
				challenge: String::new(),
				signature: None,
				key: [7; 32],
				amount: 0,
				fee: 0,
				inputs: vec![],
				outputs: vec![],
				version: None,
				slate_message: None,
				tor_proof_signature: None,
				tor_sender_address: None,
				tor_sender_signature: None,
			};
			assert_eq!(
				push_proof_for_slate(
					0,
					next_proof_cache_generation()?,
					&compact_slate.id,
					cached_legacy_proof,
				),
				ProofInsertResult::Inserted
			);

			compact_slate = sender_api.finalize_tx(m, None, &compact_slate, true)?;
			let stored_proof =
				sender_api.get_stored_tx_proof(None, None, Some(compact_slate.id))?;
			assert_eq!(stored_proof.version.as_deref(), Some("version2"));
			let verified = sender_api.verify_tx_proof(&stored_proof)?;
			assert_eq!(verified.amount, compact_slate.amount);
			Ok(())
		},
	)?;

	// let logging finish
	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn payment_proofs() {
	let test_dir = "test_output/payment_proofs";
	setup(test_dir);
	if let Err(e) = payment_proofs_test_impl(test_dir, false) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn payment_proofs_reordered_participants() {
	let test_dir = "test_output/payment_proofs_reordered_participants";
	setup(test_dir);
	if let Err(e) = payment_proofs_test_impl(test_dir, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

/// Tor payment proofs: the receiver signs with its ed25519 (onion) key and
/// the proof stores the sender's onion address as display-only data.
/// Verification must succeed against the authenticated MQS sender.
fn payment_proofs_tor_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false
	);

	let mask1 = (&mask1_i).as_ref();

	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false
	);

	let proxy_handle = wallet_proxy.start();

	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	// The receiver's onion proof address is what a Tor sender pays to.
	let mut receiver_onion = None;
	mwc_wallet_controller::controller::foreign_single_use(
		wallet2.clone(),
		mask2_i.clone(),
		|api| {
			receiver_onion = Some(api.get_proof_address()?);
			Ok(())
		},
	)?;
	let receiver_onion = receiver_onion.unwrap();
	assert_eq!(receiver_onion.len(), 56);

	let mut sender_onion = None;
	mwc_wallet_controller::controller::foreign_single_use(
		wallet1.clone(),
		mask1_i.clone(),
		|api| {
			sender_onion = Some(api.get_proof_address()?);
			Ok(())
		},
	)?;
	let sender_onion = sender_onion.unwrap();

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let address = ProvableAddress::from_str(&secp, 0, &receiver_onion)?;
	let amount = 2_000_000_000;
	let mut slate = Slate::blank(1, false)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				payment_proof_recipient_address: Some(address.clone()),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;
			slate = sender_api.finalize_tx(m, None, &slate, true)?;
			sender_api.post_tx(m, slate.tx_or_err()?, true)?;
			Ok(())
		},
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, _m| {
			let tx_proof = sender_api
				.get_stored_tx_proof(None, None, Some(slate.id))
				.unwrap();
			assert_eq!(tx_proof.version, Some("tor".to_string()));
			assert_eq!(tx_proof.tor_sender_address, Some(sender_onion.clone()));

			// The regression this guards: an authentic Tor proof generated by
			// this wallet must verify (previously rejected when the onion
			// display address was fed to the MQS sender validation).
			let proof_verify = sender_api.verify_tx_proof(&tx_proof).unwrap();
			assert_eq!(proof_verify.sender_address, sender_onion);
			assert_eq!(proof_verify.reciever_address, receiver_onion);
			assert_eq!(proof_verify.amount, slate.amount);
			assert_eq!(
				proof_verify.kernel,
				slate.tx.as_ref().unwrap().body.kernels[0].excess.to_hex()
			);

			// A legacy Tor proof (no sender attestation) must still verify,
			// but it reports the authenticated MQS sender, not the onion.
			let mut legacy_proof = sender_api
				.get_stored_tx_proof(None, None, Some(slate.id))
				.unwrap();
			legacy_proof.tor_sender_signature = None;
			let legacy_verify = sender_api.verify_tx_proof(&legacy_proof).unwrap();
			// The authenticated sender is the MQS address embedded in the
			// receiver-signed message (kernel hex is 66 chars, MQS is 52).
			let expected_mqs = legacy_proof
				.message
				.get(66..118)
				.expect("proof message must embed the MQS sender");
			assert_eq!(legacy_verify.sender_address, expected_mqs);
			assert_ne!(legacy_verify.sender_address, sender_onion);
			assert_eq!(legacy_verify.amount, slate.amount);
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn payment_proofs_tor() {
	let test_dir = "test_output/payment_proofs_tor";
	setup(test_dir);
	if let Err(e) = payment_proofs_tor_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

/// A payment proof requested at init time must still be present on the
/// returned slate and must name the originally requested recipient. A peer
/// that strips the proof or substitutes a recipient address it controls
/// must not be finalized.
fn payment_proof_enforced_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false
	);
	let mask1 = (&mask1_i).as_ref();

	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false
	);
	let mask2 = (&mask2_i).as_ref();

	// A third wallet, standing in for a third-party address that neither the
	// sender nor the receiving wallet controls
	create_wallet_and_add!(
		client3,
		wallet3,
		mask3_i,
		test_dir,
		"wallet3",
		None,
		&mut wallet_proxy,
		false
	);
	let mask3 = (&mask3_i).as_ref();

	let proxy_handle = wallet_proxy.start();

	let bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;

	// The receiving wallet's address: the requested proof recipient
	let mut address2 = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			address2 = Some(api.get_mqs_address(m)?);
			Ok(())
		},
	)?;
	let address2 = ProvableAddress::from_pub_key(&secp, 0, &address2.unwrap())?;

	// The third wallet's address, used as the requested proof recipient that
	// the receiving wallet does not control
	let mut address1 = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet3.clone()),
		mask3,
		None,
		|api, m| {
			address1 = Some(api.get_mqs_address(m)?);
			Ok(())
		},
	)?;
	let address1 = ProvableAddress::from_pub_key(&secp, 0, &address1.unwrap())?;

	let amount = 2_000_000_000;

	// Case 1: the peer strips the requested payment proof from the response
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				payment_proof_recipient_address: Some(address2.clone()),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			let mut slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;

			// Malicious peer: remove the requested proof altogether
			slate.payment_proof = None;
			let res = sender_api.finalize_tx(m, None, &slate, true);
			assert!(res.is_err());
			assert!(
				format!("{}", res.unwrap_err()).contains("Expected Payment Proof"),
				"unexpected error for stripped payment proof"
			);

			sender_api.cancel_tx(m, None, Some(slate.id))?;
			Ok(())
		},
	)?;

	// Case 2: the peer substitutes a recipient address it controls and signs
	// the proof for it instead of for the requested recipient
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				// Request a proof for an address the receiver does not control
				payment_proof_recipient_address: Some(address1.clone()),
				..Default::default()
			};
			let mut slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			let sender_key = sender_api.get_mqs_address(m)?;

			// A valid address for a different key must be rejected before the
			// receiver stages an output or advances its child-key allocator.
			let child_index_before = {
				wallet_inst!(wallet2, w);
				let parent_key_id = w.parent_key_id();
				w.current_child_index(&parent_key_id)?
			};
			mwc_wallet_controller::controller::foreign_single_use(
				wallet2.clone(),
				mask2_i.clone(),
				|receiver_api| {
					let mut receive_session = TxSession::new();
					let receive_result = receiver_api.receive_tx(
						&mut receive_session,
						&slate_i,
						None,
						None,
						Some(sender_key),
						&None,
						None,
						true,
					);
					assert!(matches!(
						receive_result,
						Err(mwc_wallet_libwallet::Error::PaymentProof(message))
							if message.contains("does not match the supplied signing key")
					));
					assert!(receive_session.is_empty());
					Ok(())
				},
			)?;
			let child_index_after = {
				wallet_inst!(wallet2, w);
				let parent_key_id = w.parent_key_id();
				w.current_child_index(&parent_key_id)?
			};
			assert_eq!(child_index_after, child_index_before);

			// Malicious peer: replace the proof recipient with its own
			// address before signing, so the signature stays valid
			if let Some(ref mut p) = slate_i.payment_proof {
				p.receiver_address = address2.clone();
			}
			let slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
			sender_api.tx_lock_outputs(m, None, &slate, None, 0)?;

			let res = sender_api.finalize_tx(m, None, &slate, true);
			assert!(res.is_err());
			assert!(
				format!("{}", res.unwrap_err())
					.contains("does not match original recipient address"),
				"unexpected error for substituted proof recipient"
			);

			sender_api.cancel_tx(m, None, Some(slate.id))?;
			Ok(())
		},
	)?;

	// Case 3: transports without an authenticated sender can still produce a
	// payment proof. When a transport does authenticate the sender, the slate's
	// claimed sender must match that identity.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				payment_proof_recipient_address: Some(address2.clone()),
				..Default::default()
			};
			let slate_i = sender_api.init_send_tx(m, None, &args, 1)?;
			let sender_key = sender_api.get_mqs_address(m)?;
			// An authenticated identity that is not the slate's sender address
			let wrong_key = address1.public_key(&secp, 0)?;

			mwc_wallet_controller::controller::foreign_single_use(
				wallet2.clone(),
				mask2_i.clone(),
				|receiver_api| {
					// Plain JSON-RPC and file transports have no authenticated peer
					// identity. They may still stage a response and sign the requested
					// proof after the operator has reviewed the slate details.
					{
						let mut receive_session = TxSession::new();
						let receive_result = receiver_api.receive_tx(
							&mut receive_session,
							&slate_i,
							None,
							None,
							None,
							&None,
							None,
							true,
						)?;
						assert!(!receive_session.is_empty());
						assert!(
							receive_result
								.slate
								.payment_proof
								.as_ref()
								.and_then(|proof| proof.receiver_signature.as_ref())
								.is_some()
						);
					}

					let mut receive_session = TxSession::new();
					let receive_result = receiver_api.receive_tx(
						&mut receive_session,
						&slate_i,
						None,
						None,
						Some(wrong_key),
						&None,
						None,
						true,
					);
					assert!(matches!(
						receive_result,
						Err(mwc_wallet_libwallet::Error::PaymentProof(message))
							if message.contains("does not match the authenticated sender")
					));
					assert!(receive_session.is_empty());

					// The matching authenticated identity passes the binding check
					let mut receive_session = TxSession::new();
					receiver_api.receive_tx(
						&mut receive_session,
						&slate_i,
						None,
						None,
						Some(sender_key),
						&None,
						None,
						true,
					)?;
					Ok(())
				},
			)?;

			sender_api.cancel_tx(m, None, Some(slate_i.id))?;
			Ok(())
		},
	)?;

	proxy_handle.stop()?;
	drop(chain);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn payment_proof_enforced_on_returned_slate() {
	let test_dir = "test_output/payment_proof_enforced";
	setup(test_dir);
	if let Err(e) = payment_proof_enforced_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
