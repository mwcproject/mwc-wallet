// Copyright 2026 The Mwc Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction, output, summary, and proof retrieval must authenticate masked-wallet
//! callers, and advanced transaction queries must stay scoped to the active account.

#![cfg(feature = "test-support")]

use mwc_wallet_api::{OwnerRpcV3, Token};
use mwc_wallet_impls::test_framework::LocalWalletClient;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::{Error, RetrieveTxQueryArgs, TxLogEntry, TxLogEntryType, TxProof};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::tempfile::tempdir;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::Error as KeychainError;
use std::sync::Arc;
use std::sync::mpsc::channel;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn retrieve_txs_security_test_impl(test_dir: &str) -> Result<(), Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool);

	create_wallet_and_add!(
		_client,
		wallet,
		mask,
		test_dir,
		"wallet",
		None,
		&mut wallet_proxy,
		true
	);

	let correct_mask = mask
		.as_ref()
		.expect("the test wallet must be opened with a keychain mask");
	let owner_api = mwc_wallet_api::Owner::new(0, wallet.clone(), None)?;
	let account_a = owner_api.create_account_path(Some(correct_mask), "account_a")?;
	let account_b = owner_api.create_account_path(Some(correct_mask), "account_b")?;

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	{
		wallet_inst!(wallet, w);
		let mut batch = w.batch(&secp, Some(correct_mask))?;

		let mut tx_a = TxLogEntry::new(account_a.clone(), TxLogEntryType::TxReceived, 0);
		tx_a.confirmed = true;
		tx_a.amount_credited = 1;
		batch.save_tx_log_entry(tx_a, &account_a)?;

		let mut tx_b = TxLogEntry::new(account_b.clone(), TxLogEntryType::TxReceived, 0);
		tx_b.confirmed = true;
		tx_b.amount_credited = 2;
		batch.save_tx_log_entry(tx_b, &account_b)?;

		let mut archived_tx_b = TxLogEntry::new(account_b.clone(), TxLogEntryType::TxReceived, 1);
		archived_tx_b.confirmed = true;
		archived_tx_b.amount_credited = 3;
		batch.save_tx_log_entry(archived_tx_b.clone(), &account_b)?;
		batch.archive_transaction(&archived_tx_b)?;
		batch.commit()?;
	}

	owner_api.set_active_account(Some(correct_mask), "account_a")?;
	let (_, _, txs) = owner_api.retrieve_txs(
		Some(correct_mask),
		false,
		None,
		None,
		Some(RetrieveTxQueryArgs::default()),
		None,
	)?;
	assert_eq!(txs.len(), 1);
	assert_eq!(txs[0].parent_key_id, account_a);
	assert_eq!(txs[0].amount_credited, 1);

	let wrong_mask = SecretKey::from_slice(&secp, &[42; 32])?;
	let missing_mask_error = owner_api
		.retrieve_txs(
			None,
			false,
			None,
			None,
			Some(RetrieveTxQueryArgs::default()),
			None,
		)
		.expect_err("a masked wallet transaction query must reject a missing mask");
	assert!(
		matches!(
			missing_mask_error,
			Error::Keychain(KeychainError::KeychainMasked)
		),
		"unexpected missing-mask error: {missing_mask_error:?}"
	);

	let wrong_mask_error = owner_api
		.retrieve_txs(
			Some(&wrong_mask),
			false,
			None,
			None,
			Some(RetrieveTxQueryArgs::default()),
			None,
		)
		.expect_err("a masked wallet transaction query must reject an incorrect mask");
	assert!(
		matches!(
			wrong_mask_error,
			Error::InvalidKeychainMask | Error::Keychain(KeychainError::InvalidMasterKeyMask)
		),
		"unexpected wrong-mask error: {wrong_mask_error:?}"
	);

	owner_api.retrieve_summary_info(Some(correct_mask), false, 1)?;

	let missing_summary_mask_error = owner_api
		.retrieve_summary_info(None, false, 1)
		.expect_err("a masked wallet summary query must reject a missing mask");
	assert!(
		matches!(
			missing_summary_mask_error,
			Error::Keychain(KeychainError::KeychainMasked)
		),
		"unexpected missing-mask summary error: {missing_summary_mask_error:?}"
	);

	let wrong_summary_mask_error = owner_api
		.retrieve_summary_info(Some(&wrong_mask), false, 1)
		.expect_err("a masked wallet summary query must reject an incorrect mask");
	assert!(
		matches!(
			wrong_summary_mask_error,
			Error::InvalidKeychainMask | Error::Keychain(KeychainError::InvalidMasterKeyMask)
		),
		"unexpected wrong-mask summary error: {wrong_summary_mask_error:?}"
	);

	let missing_tx_id = u32::MAX;
	let missing_tx_error = owner_api
		.retrieve_outputs(Some(correct_mask), false, false, Some(missing_tx_id))
		.expect_err("an authenticated query for a missing transaction must report it missing");
	assert!(
		matches!(
			missing_tx_error,
			Error::TransactionDoesntExist(ref id) if id == &missing_tx_id.to_string()
		),
		"unexpected missing-transaction error: {missing_tx_error:?}"
	);

	let missing_output_mask_error = owner_api
		.retrieve_outputs(None, false, false, Some(missing_tx_id))
		.expect_err("output retrieval must authenticate before looking up a transaction id");
	assert!(
		matches!(
			missing_output_mask_error,
			Error::Keychain(KeychainError::KeychainMasked)
		),
		"unexpected missing-mask output error: {missing_output_mask_error:?}"
	);

	let wrong_output_mask_error = owner_api
		.retrieve_outputs(Some(&wrong_mask), false, false, Some(missing_tx_id))
		.expect_err("output retrieval must reject an incorrect mask before transaction lookup");
	assert!(
		matches!(
			wrong_output_mask_error,
			Error::InvalidKeychainMask | Error::Keychain(KeychainError::InvalidMasterKeyMask)
		),
		"unexpected wrong-mask output error: {wrong_output_mask_error:?}"
	);

	Ok(())
}

#[test]
fn retrieve_txs_authenticates_mask_and_scopes_advanced_queries() {
	let test_dir = "test_output/retrieve_txs_security";
	setup(test_dir);
	if let Err(e) = retrieve_txs_security_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn stored_tx_proof_authenticates_mask_before_lookup() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let dir = tempdir().unwrap();
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let wrong_mask = SecretKey::from_slice(&secp, &[42; 32])?;
	let proof = TxProof {
		address: ProvableAddress::blank(),
		message: "stored proof fixture".to_owned(),
		challenge: String::new(),
		signature: None,
		key: [7; 32],
		amount: 1,
		fee: 0,
		inputs: vec![],
		outputs: vec![],
		version: None,
		slate_message: None,
		tor_proof_signature: None,
		tor_sender_address: None,
		tor_sender_signature: None,
	};

	for create_mask in [true, false] {
		let name = if create_mask { "masked" } else { "unmasked" };
		let (sender, _receiver) = channel();
		let client = LocalWalletClient::new(name, sender);
		let (wallet, mask) = common::create_local_wallet(
			dir.path().to_str().unwrap(),
			name,
			None,
			client,
			create_mask,
		);
		assert_eq!(mask.is_some(), create_mask);
		let slate_id = Uuid::new_v4();
		let tx = {
			wallet_inst!(wallet, w);
			let parent_key_id = w.parent_key_id();
			let mut tx = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 0);
			tx.tx_slate_id = Some(slate_id);
			tx.confirmed = true;
			let mut batch = w.batch(&secp, mask.as_ref())?;
			batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
			batch.commit()?;
			drop(batch);
			proof.store_tx_proof(w.get_data_file_dir(), &slate_id.to_string())?;
			tx
		};
		let owner_api = mwc_wallet_api::Owner::new(0, wallet.clone(), None)?;

		for archived in [false, true] {
			if archived {
				wallet_inst!(wallet, w);
				let mut batch = w.batch(&secp, mask.as_ref())?;
				batch.archive_transaction(&tx)?;
				batch.commit()?;
			}
			for (tx_id, tx_slate_id) in [(Some(tx.id), None), (None, Some(slate_id))] {
				let loaded = owner_api.get_stored_tx_proof(mask.as_ref(), tx_id, tx_slate_id)?;
				assert_eq!(loaded.key, proof.key);
				let loaded = OwnerRpcV3::retrieve_payment_proof(
					&owner_api,
					Token {
						keychain_mask: mask.clone(),
					},
					tx_id,
					tx_slate_id,
				)?;
				assert_eq!(loaded.key, proof.key);
			}

			if create_mask {
				// Authentication must precede both successful and missing transaction lookups.
				for (tx_id, tx_slate_id) in [
					(Some(tx.id), None),
					(None, Some(slate_id)),
					(Some(u32::MAX), None),
					(None, Some(Uuid::new_v4())),
				] {
					for bad_mask in [None, Some(&wrong_mask)] {
						let api_error = owner_api
							.get_stored_tx_proof(bad_mask, tx_id, tx_slate_id)
							.expect_err("proof retrieval must reject a missing or incorrect mask");
						let rpc_error = OwnerRpcV3::retrieve_payment_proof(
							&owner_api,
							Token {
								keychain_mask: bad_mask.cloned(),
							},
							tx_id,
							tx_slate_id,
						)
						.expect_err("RPC proof retrieval must reject a missing or incorrect token");
						for error in [api_error, rpc_error] {
							assert!(
								matches!(
									error,
									Error::Keychain(KeychainError::KeychainMasked)
										| Error::Keychain(KeychainError::InvalidMasterKeyMask)
										| Error::InvalidKeychainMask
								),
								"unexpected proof retrieval error: {error:?}"
							);
						}
					}
				}
			}
		}
	}
	Ok(())
}
