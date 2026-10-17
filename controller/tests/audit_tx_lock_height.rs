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

//! Compact rebuilds must preserve each commitment's original proof height.
//! Changing that message would reuse its deterministic amount masks.

#![cfg(feature = "test-support")]

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::InitTxArgs;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::libtx::proof::{ProofBuild, ProofBuilder};
use mwc_wallet_util::mwc_core::{self, core::Transaction, global};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use std::ops::DerefMut;
use std::sync::Arc;
#[macro_use]
mod common;

#[test]
fn repeated_compact_lock_preserves_original_proof() -> Result<(), Box<dyn std::error::Error>> {
	let directory = mwc_wallet_util::mwc_crates::tempfile::tempdir()?;
	let test_dir = directory.path().to_str().unwrap();
	common::setup(test_dir);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone());
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
	let mask1 = mask1_i.as_ref();
	let mask2 = mask2_i.as_ref();
	let proxy_handle = wallet_proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;
	let mut slate = None;
	let mut original_output = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let mut initial = api.init_send_tx(
				m,
				None,
				&InitTxArgs {
					amount: mwc_core::consensus::MWC_FIRST_GROUP_REWARD,
					minimum_confirmations: 2,
					max_outputs: 500,
					num_change_outputs: 1,
					selection_strategy_is_use_all: true,
					target_slate_version: Some(4),
					..Default::default()
				},
				1,
			)?;
			assert!(initial.compact_slate);
			original_output = Some(initial.tx_or_err()?.outputs()[0].clone());
			// Compact transport omits the sender's change, which locking rebuilds.
			initial.tx_or_err_mut()?.body.outputs.clear();
			slate = Some(initial);
			Ok(())
		},
	)?;
	let slate = slate.unwrap();
	let original_output = original_output.unwrap();
	// Delay even the first lock: its current tip must not replace the height
	// used to construct the change output during init_send_tx.
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet2.clone(),
		mask2,
		1,
		false,
		tx_pool.lock().deref_mut(),
	)?;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			Ok(())
		},
	)?;
	// An older context may have neither the height nor a saved change proof:
	// the first compact lock above stores only a provisional transaction.
	// Refuse to manufacture a new proof from its mutable output record.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let original_context = {
				wallet_inst!(wallet1, w);
				let context = w.get_private_context(&secp, m, slate.id.as_bytes(), 0)?;
				let mut legacy_context = context.clone();
				legacy_context.output_build_heights.clear();
				let mut batch = w.batch(&secp, m)?;
				batch.save_private_context(&secp, slate.id.as_bytes(), 0, &legacy_context)?;
				batch.commit()?;
				context
			};
			let error = api.tx_lock_outputs(m, None, &slate, None, 0).unwrap_err();
			assert!(
				matches!(error, mwc_wallet_libwallet::Error::SlateValidation(message)
				if message.contains("original proof and construction height are unavailable"))
			);
			wallet_inst!(wallet1, w);
			let (id, mmr, _) = original_context.get_outputs().remove(0);
			assert_eq!(w.get(&id, &mmr)?.height, 11);
			let mut batch = w.batch(&secp, m)?;
			batch.save_private_context(&secp, slate.id.as_bytes(), 0, &original_context)?;
			batch.commit()?;
			Ok(())
		},
	)?;
	let mut proofs = Vec::new();
	let mut nonces = Vec::new();
	let mut proof_heights = Vec::new();
	let mut commitments = Vec::new();
	for step in 0..3 {
		test_framework::award_blocks_to_wallet(
			&chain,
			wallet2.clone(),
			mask2,
			1,
			false,
			tx_pool.lock().deref_mut(),
		)?;
		mwc_wallet_controller::controller::owner_single_use(
			Some(wallet1.clone()),
			mask1,
			None,
			|api, m| {
				api.tx_lock_outputs(m, None, &slate, None, 0)?;
				let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
				wallet_inst!(wallet1, w);
				let context = w.get_private_context(&secp, m, slate.id.as_bytes(), 0)?;
				let (id, mmr, _) = context.get_outputs().remove(0);
				assert_eq!(context.output_build_heights, vec![(id.clone(), 10)]);
				let stored_output = w.get(&id, &mmr)?;
				let tx = w.get_stored_tx_by_uuid(&slate.id.to_string(), false)?;
				let output = &tx.outputs()[0];
				assert_eq!(output.commitment(), original_output.commitment());
				assert_eq!(output.proof, original_output.proof);
				let keychain = w.keychain(&secp, m)?;
				let builder = ProofBuilder::new(&secp, &keychain)?;
				let rewind_nonce = builder.rewind_nonce(&secp, &output.commitment())?;
				secp.verify_bullet_proof(output.commitment(), output.proof, None)?;
				let info = secp.rewind_bullet_proof(
					output.commitment(),
					rewind_nonce.clone(),
					None,
					None,
					output.proof,
				)?;
				let height =
					u32::from_be_bytes(info.message.as_bytes()[16..20].try_into().unwrap());
				let nonce_id = Identifier::from_bytes(&info.message.as_bytes()[3..])?;
				let private_nonce =
					builder.private_nonce(&secp, &output.commitment(), &nonce_id)?;
				// Supplying the private nonce makes rewind check the recovered
				// blinding factor against the commitment. This fails if production
				// still builds proofs using the untagged canonical identifier.
				let checked_info = secp.rewind_bullet_proof(
					output.commitment(),
					rewind_nonce,
					Some(private_nonce.clone()),
					None,
					output.proof,
				)?;
				let expected_key = keychain.derive_key(
					&secp,
					stored_output.value,
					&id,
					SwitchCommitmentType::Regular,
				)?;
				assert_eq!(checked_info.value, stored_output.value);
				assert_eq!(checked_info.blinding, expected_key);
				nonces.push(private_nonce);
				proof_heights.push(height);
				proofs.push(output.proof);
				commitments.push(output.commitment());
				assert_eq!(stored_output.height, 12 + step);
				assert_eq!(height, 10);
				Ok(())
			},
		)?;
	}
	assert_eq!(commitments[0], commitments[1]);
	assert_eq!(commitments[1], commitments[2]);
	assert_eq!(proof_heights, [10, 10, 10]);
	assert_eq!(nonces[0], nonces[1]);
	assert_eq!(nonces[1], nonces[2]);
	assert_eq!(proofs[0], proofs[1]);
	assert_eq!(proofs[1], proofs[2]);
	// Simulate a context written before construction heights were recorded.
	// Its saved proof remains usable even though OutputData.height has advanced.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			{
				wallet_inst!(wallet1, w);
				let mut context = w.get_private_context(&secp, m, slate.id.as_bytes(), 0)?;
				context.output_build_heights.clear();
				let mut batch = w.batch(&secp, m)?;
				batch.save_private_context(&secp, slate.id.as_bytes(), 0, &context)?;
				batch.commit()?;
			}
			api.tx_lock_outputs(m, None, &slate, None, 0)?;
			wallet_inst!(wallet1, w);
			let tx = w.get_stored_tx_by_uuid(&slate.id.to_string(), false)?;
			assert_eq!(tx.outputs()[0].proof, original_output.proof);
			Ok(())
		},
	)?;
	proxy_handle.stop()?;
	Ok(())
}
