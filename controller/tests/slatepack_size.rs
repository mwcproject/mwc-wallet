// Copyright 2026 The MWC Developers
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

//! Reject oversized Slatepack sends before persisting or staging a transaction.

#![cfg(feature = "test-support")]

use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{Error, InitTxArgs};
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::Mutex;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn slatepack_size_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = proxy.chain.clone();
	create_wallet_and_add!(client, wallet, mask, test_dir, "wallet", None, &mut proxy, false);
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		mask.as_ref(),
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask.as_ref(),
		None,
		|api, m| {
			let (_, _, before_outputs) = api.retrieve_outputs(m, true, true, None)?;
			let before_outputs = format!("{:?}", before_outputs);
			let (_, _, before_txs) = api.retrieve_txs(m, false, None, None, None, None)?;
			let mut args = InitTxArgs {
				amount: 1_000_000_000,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 100,
				selection_strategy_is_use_all: true,
				target_slate_version: Some(4),
				slatepack_recipient: Some(
					mwc_wallet_libwallet::proof::proofaddress::ProvableAddress::from_tor_pub_key(
						&mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(
							&[7; 32],
						)
						.verifying_key(),
					)?,
				),
				..Default::default()
			};

			// Large change sets fail in both ordinary and late-lock initialization.
			// A large expected recipient contribution must also be budgeted even
			// though it is absent from SendInitial.
			for (late_lock, change_outputs, recipient_outputs) in
				[(false, 100, 1), (true, 100, 1), (false, 1, 100)]
			{
				args.late_lock = Some(late_lock);
				args.num_change_outputs = change_outputs;
				for staged in [false, true] {
					let mut session = TxSession::new();
					let error = api
						.init_send_tx(
							m,
							if staged { Some(&mut session) } else { None },
							&args,
							recipient_outputs,
						)
						.unwrap_err();
					assert!(
						matches!(&error, Error::SlatepackEncodeError(message)
						if message.contains("65534-byte payload limit")),
						"{}",
						error
					);
					assert!(session.is_empty());
					let (_, _, after_txs) = api.retrieve_txs(m, false, None, None, None, None)?;
					assert_eq!(before_txs.len(), after_txs.len());
					let (_, _, after_outputs) = api.retrieve_outputs(m, true, false, None)?;
					assert_eq!(before_outputs, format!("{:?}", after_outputs));
				}
			}

			// Rejected requests leave the funds usable for a normal-sized send.
			args.num_change_outputs = 1;
			for late_lock in [false, true] {
				args.late_lock = Some(late_lock);
				let mut session = TxSession::new();
				api.init_send_tx(m, Some(&mut session), &args, 1)?;
				assert!(!session.is_empty());
			}
			// V3 sends use the same builder but do not inherit the SP limit.
			args.late_lock = Some(false);
			args.target_slate_version = Some(3);
			args.slatepack_recipient = None;
			let mut session = TxSession::new();
			let plain = api.init_send_tx(m, Some(&mut session), &args, 100)?;
			assert!(!plain.compact_slate);
			Ok(())
		},
	)?;
	proxy_handle.stop()?;
	Ok(())
}

#[test]
fn slatepack_size_is_rejected_during_initialization() {
	let test_dir = "test_output/slatepack_size";
	setup(test_dir);
	slatepack_size_test_impl(test_dir).unwrap();
	clean_output_dir(test_dir);
}

#[cfg(feature = "test-support")]
fn compact_json_finalize_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	use mwc_wallet_api::{Owner, OwnerRpcV3, Token};
	use mwc_wallet_libwallet::api_impl::owner;
	use mwc_wallet_libwallet::wallet_lock;
	use mwc_wallet_libwallet::{InitTxSendArgs, SlatePurpose, SlateVersion, VersionedSlate};
	use mwc_wallet_util::mwc_core::consensus::MAX_BLOCK_WEIGHT;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};

	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	// Both wallet construction and node preflight use production weight limits.
	let mut proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone())
		.with_max_block_weight(MAX_BLOCK_WEIGHT);
	let chain = proxy.chain.clone();
	create_wallet_and_add!(client, wallet, mask, test_dir, "sender", None, &mut proxy, false);
	create_wallet_and_add!(
		receiver_client,
		receiver_wallet,
		receiver_mask,
		test_dir,
		"receiver",
		None,
		&mut proxy,
		false
	);
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		mask.as_ref(),
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;
	let api = Owner::new(0, wallet.clone(), None)?;
	api.retrieve_outputs(mask.as_ref(), true, true, None)?;

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let mut args = InitTxArgs {
		amount: 1_000_000_000,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 100,
		selection_strategy_is_use_all: true,
		target_slate_version: Some(4), // Compact construction does not select the wire format.
		late_lock: Some(true),
		..Default::default()
	};
	// Compact JSON construction remains unrestricted for both raw API callers
	// and MQS. Use a session so this preliminary selection is never persisted.
	args.late_lock = Some(false);
	{
		let mut session = TxSession::new();
		let compact = api.init_send_tx(mask.as_ref(), Some(&mut session), &args, 1)?;
		assert!(compact.compact_slate);
		assert_eq!(compact.tx_or_err()?.body.outputs.len(), 100);
		VersionedSlate::into_version_plain(0, &compact, SlateVersion::V3)?;
		// Choosing unencrypted SP at the actual encoding boundary enforces the
		// early budget even though no recipient was supplied at initialization.
		let error = api
			.encrypt_slate(
				mask.as_ref(),
				&compact,
				Some(SlateVersion::SP),
				SlatePurpose::SendInitial,
				None,
				None,
				false,
			)
			.unwrap_err();
		assert!(
			matches!(&error, Error::SlatepackEncodeError(message)
			if message.contains("65534-byte payload limit")),
			"{}",
			error
		);
	}
	args.late_lock = Some(true);
	args.send_args = Some(InitTxSendArgs {
		method: "mwcmqs".to_owned(),
		dest: "unused".to_owned(),
		apisecret: None,
		finalize: false,
		post_tx: false,
		fluff: false,
	});
	args.slatepack_recipient = Some(
		mwc_wallet_libwallet::proof::proofaddress::ProvableAddress::from_tor_pub_key(
			&mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&[7; 32])
				.verifying_key(),
		)?,
	);
	{
		wallet_lock!(wallet, w);
		// The lower-level API does not contact a broker.
		owner::init_send_tx(
			&mut **w,
			&mut secp,
			mask.as_ref(),
			&mut Some(&mut TxSession::new()),
			&args,
			false,
			1,
		)?;
	}
	args.send_args = None;
	args.slatepack_recipient = None;
	let initial = api.init_send_tx(mask.as_ref(), None, &args, 1)?;
	assert!(initial.compact_slate);
	let response = {
		wallet_lock!(receiver_wallet, w);
		mwc_wallet_libwallet::foreign::receive_tx(
			&mut **w,
			&mut secp,
			receiver_mask.as_ref(),
			&mut TxSession::new(),
			&initial,
			None,
			None,
			None,
			&None,
			None,
			false,
			false,
		)?
		.0
	};
	let packed = api.encrypt_slate(
		mask.as_ref(),
		&response,
		Some(SlateVersion::SP),
		SlatePurpose::SendResponse,
		None,
		None,
		false,
	)?;
	let token = || Token {
		keychain_mask: mask.clone(),
	};
	let error = OwnerRpcV3::finalize_tx(&api, token(), packed).unwrap_err();
	assert!(
		matches!(&error, Error::SlatepackEncodeError(message)
		if message.contains("65534-byte payload limit")),
		"{}",
		error
	);
	{
		wallet_lock!(wallet, w);
		let context = w.get_private_context(&secp, mask.as_ref(), initial.id.as_bytes(), 0)?;
		assert!(context.late_lock_args.is_some());
		assert!(context.aggsig_challenge.is_none());
		assert!(context.input_ids.is_empty());
		assert!(w
			.iter()?
			.all(|output| output.status != mwc_wallet_libwallet::OutputStatus::Locked));
	}

	// The same returned compact slate can still finalize as V3 JSON. The SP
	// failure must not consume its context or lock the provisional selection.
	let json = VersionedSlate::into_version_plain(0, &response, SlateVersion::V3)?;
	let finalized = OwnerRpcV3::finalize_tx(&api, token(), json)?;
	assert_eq!(finalized.version(), SlateVersion::V3);
	let finalized = finalized.into_slate_plain(0, false)?;
	assert!(finalized.compact_slate);
	assert_eq!(finalized.tx_or_err()?.body.outputs.len(), 101);
	finalized.tx_or_err()?.validate(
		0,
		mwc_wallet_util::mwc_core::core::transaction::Weighting::AsTransaction,
		&mut secp,
	)?;
	proxy_handle.stop()?;
	Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn compact_json_rpc_finalization_bypasses_slatepack_limit() {
	let test_dir = "test_output/slatepack_compact_json_size";
	setup(test_dir);
	compact_json_finalize_test_impl(test_dir).unwrap();
	clean_output_dir(test_dir);
}
