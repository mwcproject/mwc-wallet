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

//! Test a wallet sending to self

#![cfg(feature = "test-support")]

use mwc_wallet_util::mwc_core::global;
use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::types::{input_is_free, TxSession};
use mwc_wallet_libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate, SlateVersion, VersionedSlate};
use mwc_wallet_util::mwc_core;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_util::mwc_core::core::{Committed, Transaction};
use mwc_wallet_util::mwc_util::ToHex;
use mwc_wallet_util::Mutex;

/// self send impl
fn invoice_tx_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	// Create a new proxy to simulate server and wallet responses
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
		true
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
		true
	);
	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	// few values to keep things shorter
	let reward = mwc_core::consensus::MWC_FIRST_GROUP_REWARD;

	// add some accounts
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.create_account_path(m, "mining")?;
			api.create_account_path(m, "listener")?;
			Ok(())
		},
	)?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		bh as usize,
		false,
		tx_pool.lock().deref_mut(),
	);

	// Sanity check wallet 1 contents
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			Ok(())
		},
	)?;

	let mut slate = Slate::blank(2, false)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			// Wallet 2 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * 2,
				message: Some("invoice terms".to_owned()),
				..Default::default()
			};
			slate = api.issue_invoice_tx(m, None, &args)?;
			Ok(())
		},
	)?;

	let invoice_request = slate.clone();
	let mut payer_session = TxSession::new();
	let mut payer_processing_guard = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};

			// The payer must authenticate an invoice participant message before
			// selecting coins or publishing a signing context.
			let mut altered_message_invoice = invoice_request.clone();
			altered_message_invoice.participant_data[0].message =
				Some("altered invoice terms".to_owned());
			let mut altered_message_session = TxSession::new();
			assert!(matches!(
				api.process_invoice_tx(
					m,
					Some(&mut altered_message_session),
					&altered_message_invoice,
					&args,
				),
				Err(mwc_wallet_libwallet::Error::Signature(message))
					if message.contains("does not match")
			));
			assert!(altered_message_session.is_empty());

			// A peer-controlled invalid rangeproof must be rejected before the
			// payer partial signature or transaction-session state is published.
			let mut malformed_invoice = invoice_request.clone();
			let malformed_output = malformed_invoice
				.tx
				.as_mut()
				.and_then(|tx| tx.body.outputs.first_mut())
				.expect("invoice must contain the issuer output");
			assert!(malformed_output.proof.len()? > 0);
			malformed_output.proof.proof[0] ^= 1;
			let mut malformed_session = TxSession::new();
			assert!(api
				.process_invoice_tx(m, Some(&mut malformed_session), &malformed_invoice, &args,)
				.is_err());
			assert!(malformed_session.is_empty());

			let mut unsupported_ttl_args = args.clone();
			unsupported_ttl_args.ttl_blocks = Some(2);
			assert!(matches!(
				api.process_invoice_tx(
					m,
					Some(&mut payer_session),
					&invoice_request,
					&unsupported_ttl_args,
				),
				Err(mwc_wallet_libwallet::Error::GenericError(message))
					if message == "TTL is not supported for invoice transactions"
			));

			// Wallet 1 receives the invoice transaction
			let result =
				api.process_invoice_tx(m, Some(&mut payer_session), &invoice_request, &args)?;
			slate = result.slate;
			payer_processing_guard = Some(result.processing_guard);
			Ok(())
		},
	)?;

	// A second request with the same externally supplied UUID cannot start
	// while the first invoice exchange is still in progress.
	let mut competing_session = TxSession::new();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: invoice_request.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			assert!(matches!(
				api.process_invoice_tx(
					m,
					Some(&mut competing_session),
					&invoice_request,
					&args,
				),
				Err(mwc_wallet_libwallet::Error::TransactionInProgress(id))
					if id == invoice_request.id.to_string()
			));
			Ok(())
		},
	)?;
	drop(competing_session);

	let invoice_response = slate.clone();
	let wallet2_context_id = {
		wallet_inst!(wallet2, w);
		w.get_context_id()
	};

	// wallet 2 finalizes and posts
	mwc_wallet_controller::controller::foreign_single_use(
		wallet2.clone(),
		mask2_i.clone(),
		|api| {
			// A payer can produce a valid partial signature for arbitrary participant
			// keys without making those keys balance the supplied transaction. This
			// malformed response must fail before the issuer's nonce challenge is
			// persisted, so the original payer response remains finalizable.
			let mut poisoned_response = invoice_response.clone();
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let attacker_key = SecretKey::from_slice(&secp, &[21_u8; 32])?;
			let attacker_nonce = SecretKey::from_slice(&secp, &[22_u8; 32])?;
			let payer = poisoned_response
				.participant_data
				.iter_mut()
				.find(|participant| participant.id == 1)
				.expect("invoice response must contain payer participant 1");
			payer.public_blind_excess = PublicKey::from_secret_key(&secp, &attacker_key)?;
			payer.public_nonce = PublicKey::from_secret_key(&secp, &attacker_nonce)?;
			payer.part_sig = None;
			payer.message = None;
			payer.message_sig = None;
			poisoned_response.fill_round_2(
				wallet2_context_id,
				&secp,
				&attacker_key,
				&attacker_nonce,
				1,
			)?;
			let error = api
				.finalize_invoice_tx(None, &poisoned_response, None)
				.err()
				.expect("An unbalanced invoice response must be rejected before signing");
			assert!(
				matches!(&error, mwc_wallet_libwallet::Error::Node(message)
					if message.contains("transaction 0 balance:")),
				"Unexpected invoice rejection: {:?}",
				error
			);

			let sender =
				mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&[11u8; 32])
					.verifying_key();
			let finalize_result =
				api.finalize_invoice_tx(None, &slate, Some(ReplyBinding::file(&sender)))?;
			slate = finalize_result.slate;
			drop(finalize_result.processing_guard);
			let retry_result = api
				.finalize_invoice_tx(
					None,
					&invoice_response,
					Some(ReplyBinding::file(&sender)),
				)?;
			assert_eq!(
				VersionedSlate::into_version_plain(0, &slate, SlateVersion::V3)?.as_string()?,
				VersionedSlate::into_version_plain(0, &retry_result.slate, SlateVersion::V3)?
					.as_string()?
			);
			drop(retry_result.processing_guard);
			let other_sender =
				mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&[12u8; 32])
					.verifying_key();
			assert!(matches!(
				api.finalize_invoice_tx(
					None,
					&invoice_response,
					Some(ReplyBinding::file(&other_sender)),
				),
				Err(mwc_wallet_libwallet::Error::ReceiveResponseMismatch(_))
			));
			assert!(
				!std::path::Path::new(&format!(
					"{}/wallet2/wallet_data/slatepack/{}.full.slate",
					test_dir, slate.id
				))
					.exists()
			);
			Ok(())
		},
	)?;

	// The complete response is now known. Stage its locks and final transaction,
	// post it, and only then persist the payer session.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.tx_lock_outputs(m, Some(&mut payer_session), &slate, None, 1)?;
			let (_, _, staged_txs) =
				api.retrieve_txs(m, false, None, Some(slate.id), None, None)?;
			assert!(
				staged_txs.is_empty(),
				"tx_lock_outputs persisted a transaction before the session save"
			);
			api.post_tx(m, slate.tx_or_err()?, false)?;
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			wallet_inst!(wallet1, w);
			payer_session.save_tx_data(&secp, &mut **w, mask1, &slate.id)?;
			Ok(())
		},
	)?;
	drop(payer_processing_guard);
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: invoice_request.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			assert!(matches!(
				api.process_invoice_tx(m, None, &invoice_request, &args),
				Err(mwc_wallet_libwallet::Error::TransactionAlreadyReceived(id))
					if id == invoice_request.id.to_string()
			));
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		3,
		false,
		tx_pool.lock().deref_mut(),
	);
	bh += 3;

	// Check transaction log for wallet 2
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (_, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
			let (refreshed, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert!(refreshed);
			assert!(txs.len() == 1);
			println!(
				"last confirmed height: {}, bh: {}",
				wallet2_info.last_confirmed_height, bh
			);
			assert!(refreshed);
			assert_eq!(wallet2_info.amount_currently_spendable, slate.amount);
			Ok(())
		},
	)?;

	// Check transaction log for wallet 1, ensure only 1 entry
	// exists
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			let (refreshed, _, txs) = api.retrieve_txs(m, true, None, None, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len() as u64, bh + 1);
			println!(
				"Wallet 1: last confirmed height: {}, bh: {}",
				wallet1_info.last_confirmed_height, bh
			);
			Ok(())
		},
	)?;

	// Test self-sending
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			// Wallet 1 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * 2,
				..Default::default()
			};
			slate = api.issue_invoice_tx(m, None, &args)?;
			// Wallet 1 receives the invoice transaction
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};

			// A self-invoice is recognized by its saved participant-0 context.
			// Do not let a request with the same UUID replace the issuer nonce.
			let mut altered_nonce_invoice = slate.clone();
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let rogue_nonce = SecretKey::from_slice(&secp, &[23_u8; 32])?;
			altered_nonce_invoice.participant_data[0].public_nonce =
				PublicKey::from_secret_key(&secp, &rogue_nonce)?;
			assert!(matches!(
				api.process_invoice_tx(m, None, &altered_nonce_invoice, &args),
				Err(mwc_wallet_libwallet::Error::SlateValidation(message))
					if message.contains("issuer participant")
			));

			// Likewise, a different valid issuer output must not be substituted
			// into the locally issued invoice before the payer signs it.
			let replacement_output = *invoice_request
				.tx_or_err()?
				.outputs()
				.first()
				.expect("external invoice must contain an issuer output");
			let mut altered_output_invoice = slate.clone();
			*altered_output_invoice
				.tx
				.as_mut()
				.and_then(|tx| tx.body.outputs.first_mut())
				.expect("self-invoice must contain an issuer output") = replacement_output;
			assert!(matches!(
				api.process_invoice_tx(m, None, &altered_output_invoice, &args),
				Err(mwc_wallet_libwallet::Error::SlateValidation(message))
					if message.contains("altered issuer outputs")
			));

			let process_result = api.process_invoice_tx(m, None, &slate, &args)?;
			slate = process_result.slate;
			let selected_inputs = slate
				.tx_or_err()?
				.inputs_committed()
				.expect("processed invoice inputs must be readable")
				.collect::<Result<Vec<_>, _>>()
				.expect("processed invoice input commitments must be valid");
			assert!(!selected_inputs.is_empty());
			assert!(selected_inputs
				.iter()
				.all(|commit| !input_is_free(&commit.to_hex())));
			api.tx_lock_outputs(m, None, &slate, None, 1)?;
			drop(process_result.processing_guard);
			Ok(())
		},
	)?;

	// wallet 1 finalizes and posts
	mwc_wallet_controller::controller::foreign_single_use(
		wallet1.clone(),
		mask1_i.clone(),
		|api| {
			// Wallet 2 receives the invoice transaction
			let result = api.finalize_invoice_tx(None, &slate, None)?;
			slate = result.slate;
			Ok(())
		},
	)?;

	// test that payee can only cancel once
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		3,
		false,
		tx_pool.lock().deref_mut(),
	);
	//bh += 3;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			// Wallet 2 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * 2,
				..Default::default()
			};
			slate = api.issue_invoice_tx(m, None, &args)?;
			Ok(())
		},
	)?;

	let orig_slate = slate.clone();

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			// Wallet 1 receives the invoice transaction
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let process_result = api.process_invoice_tx(m, None, &slate, &args)?;
			slate = process_result.slate;
			api.tx_lock_outputs(m, None, &slate, None, 1)?;

			// Persistent invoice payments allocate their TxSent id while locking.
			// Every change output must be rebound from the placeholder id to that
			// final durable id before the lock batch is committed.
			let (_, _, txs) = api.retrieve_txs(m, false, None, Some(slate.id), None, None)?;
			let sent_tx = txs
				.iter()
				.find(|tx| tx.tx_type == mwc_wallet_libwallet::TxLogEntryType::TxSent)
				.expect("invoice payment must create a TxSent entry");
			assert_ne!(sent_tx.id, 0, "test must exercise a non-placeholder id");
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, Some(sent_tx.id))?;
			let change_outputs: Vec<_> = outputs
				.iter()
				.filter(|output| sent_tx.output_commits.contains(&output.commit))
				.collect();
			assert_eq!(change_outputs.len(), sent_tx.num_outputs);
			assert!(!change_outputs.is_empty());
			assert!(change_outputs
				.iter()
				.all(|output| output.output.tx_log_entry == Some(sent_tx.id)));

			// Wallet 1 cancels the invoice transaction
			api.cancel_tx(m, None, Some(slate.id))?;
			drop(process_result.processing_guard);

			// Wallet 1 attempts to repay again
			let res = api.process_invoice_tx(m, None, &orig_slate, &args);
			assert!(res.is_err());

			Ok(())
		},
	)?;

	// Faucet invoices create and finalize their TxReceived entry in one
	// uncommitted session. That entry must receive a fresh durable ID rather
	// than overwrite the existing transaction whose ID matches its placeholder.
	let mut staged_invoice_session = TxSession::new();
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let args = IssueInvoiceTxArgs {
				amount: reward,
				..Default::default()
			};
			slate = api.issue_invoice_tx(m, Some(&mut staged_invoice_session), &args)?;
			Ok(())
		},
	)?;
	let staged_placeholder_id = staged_invoice_session
		.get_tx_log_entry()
		.as_ref()
		.unwrap()
		.id;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let process_result = api.process_invoice_tx(m, None, &slate, &args)?;
			slate = process_result.slate;
			api.tx_lock_outputs(m, None, &slate, None, 1)?;
			Ok(())
		},
	)?;

	let mut finalize_processing_guard = None;
	mwc_wallet_controller::controller::foreign_single_use(
		wallet2.clone(),
		mask2_i.clone(),
		|api| {
			let invoice_context = staged_invoice_session
				.get_context_participant()
				.as_ref()
				.expect("invoice session must contain its signing context")
				.0
				.clone();
			staged_invoice_session.set_context_participant(invoice_context.clone(), 1);
			assert!(matches!(
				api.finalize_invoice_tx(Some(&mut staged_invoice_session), &slate, None),
				Err(mwc_wallet_libwallet::Error::SlateValidation(message))
					if message.contains("participant mismatch")
			));
			staged_invoice_session.set_context_participant(invoice_context, 0);

			let mut relabeled_slate = slate.clone();
			relabeled_slate.id = Uuid::new_v4();
			assert!(matches!(
				api.finalize_invoice_tx(
					Some(&mut staged_invoice_session),
					&relabeled_slate,
					None,
				),
				Err(mwc_wallet_libwallet::Error::SlateValidation(message))
					if message.contains("does not match transaction session")
			));

			let result =
				api.finalize_invoice_tx(Some(&mut staged_invoice_session), &slate, None)?;
			slate = result.slate;
			finalize_processing_guard = Some(result.processing_guard);
			Ok(())
		},
	)?;

	{
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_inst!(wallet2, w);
		staged_invoice_session.save_tx_data(&secp, &mut **w, mask2, &slate.id)?;
	}
	drop(finalize_processing_guard);
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let (_, _, txs) = api.retrieve_txs(m, false, None, Some(slate.id), None, None)?;
			assert_eq!(txs.len(), 1);
			assert_ne!(txs[0].id, staged_placeholder_id);
			assert!(txs[0].stored_tx.is_some());
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
fn wallet_invoice_tx() -> Result<(), mwc_wallet_controller::Error> {
	let test_dir = "test_output/invoice_tx";
	setup(test_dir);
	invoice_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
