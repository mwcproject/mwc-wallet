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

//! Active receives must not hide archived invoice payments or cancellations.

#![cfg(feature = "test-support")]

use mwc_wallet_impls::test_framework::LocalWalletClient;
use mwc_wallet_impls::LMDBBackend;
use mwc_wallet_libwallet::api_impl::owner;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{Error, InitTxArgs, Slate, TxLogEntry, TxLogEntryType, WalletBackend};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::libtx::{build, proof::ProofBuilder};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::tempfile::tempdir;
use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain};
use std::sync::mpsc::channel;

fn check_archived_invoice_replay(tx_type: TxLogEntryType) -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let directory = tempdir()?;
	let (sender, receiver) = channel();
	// Replay rejection must happen before any node request. A disconnected
	// proxy makes an unexpected request fail immediately rather than hang.
	drop(receiver);
	let node = LocalWalletClient::new("invoice_replay", sender);
	let mut wallet =
		LMDBBackend::<_, ExtKeychain>::new(0, directory.path().to_str().unwrap(), node)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let keychain = ExtKeychain::from_seed(&secp, &[42; 32], true)?;
	wallet.set_keychain(&secp, Box::new(keychain), false, false)?;
	let parent_key_id = wallet.parent_key_id();

	// Build a valid external invoice with its issuer output and participant.
	let issuer_keychain = ExtKeychain::from_seed(&secp, &[43; 32], true)?;
	let proof_builder = ProofBuilder::new(&secp, &issuer_keychain)?;
	let output_id = ExtKeychain::derive_key_id(3, 0, 0, 0, 0)?;
	let mut invoice = Slate::blank(2, false)?;
	invoice.amount = 1_000_000_000;
	let blind = invoice.add_transaction_elements(
		0,
		&mut secp,
		&issuer_keychain,
		&proof_builder,
		vec![build::height_tagged_output(
			invoice.amount,
			output_id,
			invoice.height,
		)],
	)?;
	invoice.fill_round_1(
		&secp,
		&issuer_keychain,
		&mut blind.secret_key(&secp)?,
		&SecretKey::from_slice(&secp, &[44; 32])?,
		0,
		None,
		false,
	)?;

	{
		let mut batch = wallet.batch_no_mask()?;
		let mut previous = TxLogEntry::new(
			parent_key_id.clone(),
			tx_type.clone(),
			batch.next_tx_log_id(&parent_key_id)?,
		);
		previous.tx_slate_id = Some(invoice.id);
		previous.confirmed = tx_type == TxLogEntryType::TxSent;
		batch.save_tx_log_entry(previous.clone(), &parent_key_id)?;
		batch.archive_transaction(&previous)?;

		// Receive processing permits a new incoming transaction with the UUID
		// of an older sent transaction. Its active log must not mask the archive.
		let mut received = TxLogEntry::new(
			parent_key_id.clone(),
			TxLogEntryType::TxReceived,
			batch.next_tx_log_id(&parent_key_id)?,
		);
		received.tx_slate_id = Some(invoice.id);
		batch.save_tx_log_entry(received, &parent_key_id)?;
		batch.commit()?;
	}
	let child_index = wallet.current_child_index(&parent_key_id)?;
	let args = InitTxArgs::default();
	for with_session in [false, true] {
		let mut session = TxSession::new();
		let mut tx_session = with_session.then_some(&mut session);
		let error = owner::process_invoice_tx(
			&mut wallet,
			&mut secp,
			None,
			&mut tx_session,
			&invoice,
			&args,
			false,
			false,
		)
		.expect_err("archived invoice history must reject another payment");
		match tx_type {
			TxLogEntryType::TxSent => assert!(
				matches!(&error, Error::TransactionAlreadyReceived(id) if id == &invoice.id.to_string()),
				"unexpected replay error: {error:?}"
			),
			TxLogEntryType::TxSentCancelled => assert!(
				matches!(&error, Error::TransactionWasCancelled(id) if id == &invoice.id.to_string()),
				"unexpected cancellation error: {error:?}"
			),
			_ => unreachable!(),
		}
		assert!(session.is_empty());
		assert!(session.get_input_commits().is_empty());
		assert_eq!(wallet.current_child_index(&parent_key_id)?, child_index);
	}
	Ok(())
}

#[test]
fn archived_paid_invoice_rejected_with_active_receive() -> Result<(), Error> {
	check_archived_invoice_replay(TxLogEntryType::TxSent)
}

#[test]
fn archived_cancelled_invoice_rejected_with_active_receive() -> Result<(), Error> {
	check_archived_invoice_replay(TxLogEntryType::TxSentCancelled)
}
