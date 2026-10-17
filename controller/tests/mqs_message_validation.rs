// Copyright 2026 The Mwc Developers
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

#![cfg(feature = "test-support")]

use mwc_wallet_controller::controller::{Controller, owner_single_use};
use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_impls::{
	Address, MWCMQSAddress, MqsMessageDisposition, Publisher, SubscriptionHandler,
};
use mwc_wallet_libwallet::proof::crypto::Hex;
use mwc_wallet_libwallet::proof::{
	crypto, message::EncryptedMessage, proofaddress::ProvableAddress, tx_proof::TxProof,
};
use mwc_wallet_libwallet::{InitTxArgs, Slate, SlateVersion, VersionedSlate};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::{consensus, core::Transaction};
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::{serde_json, uuid::Uuid};
use std::sync::Arc;

#[macro_use]
mod common;

#[derive(Default)]
struct RecordingPublisher(Mutex<Option<Slate>>);

impl Publisher for RecordingPublisher {
	fn post_slate(
		&self,
		slate: &Slate,
		_: &dyn Address,
		_: &Secp256k1,
	) -> Result<(), mwc_wallet_impls::Error> {
		*self.0.lock() = Some(slate.clone());
		Ok(())
	}

	fn encrypt_slate(
		&self,
		_: &Slate,
		_: &dyn Address,
		_: &Secp256k1,
	) -> Result<String, mwc_wallet_impls::Error> {
		unreachable!()
	}

	fn decrypt_slate(
		&self,
		_: String,
		_: String,
		_: String,
		_: &ProvableAddress,
		_: &Secp256k1,
	) -> Result<String, mwc_wallet_impls::Error> {
		unreachable!()
	}

	#[cfg(feature = "swaps")]
	fn post_take(
		&self,
		_: &mwc_wallet_libwallet::swap::message::Message,
		_: &dyn Address,
		_: &Secp256k1,
	) -> Result<(), mwc_wallet_impls::Error> {
		unreachable!()
	}

	fn get_publisher_address(&self) -> Result<Box<dyn Address>, mwc_wallet_impls::Error> {
		unreachable!()
	}
}

#[test]
fn authenticated_mqs_receive_validates_participant_messages()
-> Result<(), Box<dyn std::error::Error>> {
	let test_dir = std::env::temp_dir()
		.join(format!("mwc-mqs-message-validation-{}", Uuid::new_v4()))
		.to_str()
		.unwrap()
		.to_owned();
	common::setup(&test_dir);
	let pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = common::create_wallet_proxy(test_dir.clone(), pool.clone());
	let chain = proxy.chain.clone();
	create_wallet_and_add!(
		client1, wallet1, mask1, &test_dir, "sender", None, &mut proxy, false
	);
	create_wallet_and_add!(
		client2, wallet2, mask2, &test_dir, "receiver", None, &mut proxy, false
	);
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1.as_ref(),
		10,
		false,
		&mut *pool.lock(),
	)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let initial = owner_single_use(Some(wallet1.clone()), mask1.as_ref(), None, |api, mask| {
		api.init_send_tx(
			mask,
			None,
			&InitTxArgs {
				amount: consensus::MWC_FIRST_GROUP_REWARD,
				minimum_confirmations: 2,
				message: Some("original signed message".into()),
				..Default::default()
			},
			1,
		)
		.map_err(Into::into)
	})?;
	initial.verify_messages(&secp)?;

	let sender_secret = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
	let receiver_secret = SecretKey::from_slice(&secp, &[8; 32]).unwrap();
	let sender_address = ProvableAddress::from_pub_key(
		&secp,
		0,
		&PublicKey::from_secret_key(&secp, &sender_secret).unwrap(),
	)?;
	let receiver_public = PublicKey::from_secret_key(&secp, &receiver_secret).unwrap();
	let receiver_address = ProvableAddress::from_pub_key(&secp, 0, &receiver_public)?;
	// Authenticate every slate through the real MQS envelope verifier. A valid
	// transport signature must not bypass participant message authentication.
	let authenticate = |slate: &Slate| -> Result<(Slate, TxProof), Box<dyn std::error::Error>> {
		let wire = VersionedSlate::into_version_plain(0, slate, SlateVersion::V3)?.as_string()?;
		let envelope = EncryptedMessage::new(
			wire,
			&receiver_address,
			&receiver_public,
			&sender_secret,
			&secp,
			false,
		)?;
		let message = serde_json::to_string(&envelope)?;
		let signature = crypto::sign_challenge(&message, &sender_secret, &secp)?.to_hex(&secp)?;
		Ok(TxProof::from_response(
			0,
			&sender_address,
			message,
			String::new(),
			signature,
			&receiver_secret,
			&receiver_address,
			&secp,
		)?)
	};
	let from = MWCMQSAddress::new(sender_address.clone(), None, None);
	let controller = Controller::new(
		"message-validation",
		wallet2.clone(),
		Arc::new(Mutex::new(mask2)),
		None,
		true,
	)?;
	let publisher = Arc::new(RecordingPublisher::default());
	controller.set_publisher(publisher.clone());
	let child_index_before = {
		wallet_inst!(wallet2, w);
		w.current_child_index(&w.parent_key_id())?
	};

	let mut altered_message = initial.clone();
	altered_message.participant_data[0].message =
		Some("altered message with stale signature".into());
	let mut missing_signature = initial.clone();
	missing_signature.participant_data[0].message_sig = None;
	let mut missing_message = initial.clone();
	missing_message.participant_data[0].message = None;
	for invalid in [altered_message, missing_signature, missing_message] {
		let expected_error = invalid.verify_messages(&secp).unwrap_err().to_string();
		let (mut received, proof) = authenticate(&invalid)?;
		let error = controller
			.on_slate(&from, &mut received, proof)
			.unwrap_err();
		assert!(error.to_string().contains(&expected_error), "{error}");
		assert!(publisher.0.lock().is_none());
		assert_eq!(received.participant_data.len(), 1);
		wallet_inst!(wallet2, w);
		assert_eq!(
			w.current_child_index(&w.parent_key_id())?,
			child_index_before
		);
		assert!(w.iter()?.next().is_none());
		assert!(w.tx_log_iter()?.next().is_none());
	}

	// A corrected retry with the same UUID must succeed: rejected requests
	// must release the processing guard and reply-cache reservation.
	let (mut received, proof) = authenticate(&initial)?;
	assert_eq!(
		controller.on_slate(&from, &mut received, proof)?,
		MqsMessageDisposition::Processed
	);
	let reply = publisher.0.lock().take().unwrap();
	assert_eq!(reply.participant_data.len(), 2);
	reply.verify_messages(&secp)?;
	{
		wallet_inst!(wallet2, w);
		let entry = w
			.tx_log_iter()?
			.find(|tx| tx.tx_slate_id == Some(initial.id))
			.unwrap();
		assert_eq!(
			entry.messages.unwrap().messages[0].message.as_deref(),
			Some("original signed message")
		);
		assert_eq!(w.iter()?.count(), 1);
	}
	proxy_handle.stop()?;
	drop(controller);
	drop(wallet1);
	drop(wallet2);
	drop(chain);
	common::clean_output_dir(&test_dir);
	Ok(())
}
