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

//! Reject oversized invoice replies before consuming their signing context.
#![cfg(feature = "test-support")]

use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_api::{Foreign, ForeignRpc, Owner};
use mwc_wallet_controller::command::{finalize, FinalizeArgs};
use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{
	Error, InitTxArgs, IssueInvoiceTxArgs, SlatePurpose, SlateVersion, VersionedSlate,
};
use mwc_wallet_util::mwc_core::consensus::MAX_BLOCK_WEIGHT;
use mwc_wallet_util::mwc_core::core::{transaction::Weighting, Transaction};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::Mutex;

#[macro_use]
mod common;

fn assert_size_error(error: Error) {
	assert!(
		matches!(&error, Error::SlatepackEncodeError(message)
			if message.contains("65534-byte payload limit")),
		"{}",
		error
	);
}

fn invoice_slatepack_size_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	// Exercise the Slatepack boundary with production weight limits on both
	// the wallet and node threads, while retaining automated mining parameters.
	let mut proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone())
		.with_max_block_weight(MAX_BLOCK_WEIGHT);
	let chain = proxy.chain.clone();
	create_wallet_and_add!(
		payer_client,
		payer_wallet,
		payer_mask,
		test_dir,
		"payer",
		None,
		&mut proxy,
		false
	);
	create_wallet_and_add!(
		issuer_client,
		issuer_wallet,
		issuer_mask,
		test_dir,
		"issuer",
		None,
		&mut proxy,
		false
	);
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		payer_wallet.clone(),
		payer_mask.as_ref(),
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;
	let payer = Owner::new(0, payer_wallet.clone(), None)?;
	let mut issuer = Owner::new(0, issuer_wallet.clone(), None)?;
	let foreign = Foreign::new(issuer_wallet.clone(), issuer_mask.clone(), None);
	payer.retrieve_outputs(payer_mask.as_ref(), true, true, None)?;

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let payer_address = payer.get_wallet_public_address(payer_mask.as_ref())?;
	let issuer_address = issuer.get_wallet_public_address(issuer_mask.as_ref())?;
	let mut session = TxSession::new();
	let initial = issuer.issue_invoice_tx(
		issuer_mask.as_ref(),
		Some(&mut session),
		&IssueInvoiceTxArgs {
			amount: 1_000_000_000,
			slatepack_recipient: Some(ProvableAddress::from_tor_pub_key(&payer_address)?),
			..Default::default()
		},
	)?;
	let packed_initial = issuer.encrypt_slate(
		issuer_mask.as_ref(),
		&initial,
		Some(SlateVersion::SP),
		SlatePurpose::InvoiceInitial,
		Some(payer_address),
		None,
		false,
	)?;
	let (incoming, _, _, _) = payer.decrypt_slatepack(payer_mask.as_ref(), packed_initial, None)?;
	let response = payer.process_invoice_tx(
		payer_mask.as_ref(),
		None,
		&incoming,
		&InitTxArgs {
			amount: incoming.amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 91,
			selection_strategy_is_use_all: true,
			..Default::default()
		},
	)?;
	// InvoiceResponse fits the wire limit because it omits the issuer output.
	let packed = payer.encrypt_slate(
		payer_mask.as_ref(),
		&response.slate,
		Some(SlateVersion::SP),
		SlatePurpose::InvoiceResponse,
		None,
		None,
		false,
	)?;
	let (wire_response, _, _, _) = issuer.decrypt_slatepack(issuer_mask.as_ref(), packed, None)?;
	assert_eq!(wire_response.tx_or_err()?.body.outputs.len(), 91);

	// Rejection must also leave an uncommitted session intact and unsigned.
	let staged_log = format!("{:?}", session.get_tx_log_entry());
	let staged_outputs = session.get_outputs().clone();
	let error = foreign
		.finalize_invoice_tx_with_output_version(
			Some(&mut session),
			&wire_response,
			None,
			Some(SlateVersion::SP),
		)
		.err()
		.expect("oversized staged invoice should fail");
	assert_size_error(error);
	assert!(session
		.get_context_participant()
		.as_ref()
		.unwrap()
		.0
		.aggsig_challenge
		.is_none());
	assert!(session.get_transaction().is_none());
	assert_eq!(staged_log, format!("{:?}", session.get_tx_log_entry()));
	assert_eq!(&staged_outputs, session.get_outputs());
	{
		wallet_inst!(issuer_wallet, w);
		assert_eq!(w.tx_log_iter()?.count(), 0);
		assert_eq!(w.iter()?.count(), 0);
		// Persist the still-pending invoice to exercise the command and RPC paths.
		session.save_tx_data(&secp, &mut **w, issuer_mask.as_ref(), &initial.id)?;
	}
	drop(session);

	let pending_state = || -> Result<String, Error> {
		wallet_inst!(issuer_wallet, w);
		let context =
			w.get_private_context(&secp, issuer_mask.as_ref(), initial.id.as_bytes(), 0)?;
		assert!(context.aggsig_challenge.is_none());
		assert!(matches!(
			w.get_stored_tx_by_uuid(&initial.id.to_string(), false),
			Err(Error::TransactionNotFound(_))
		));
		assert!(tx_pool.lock().is_empty());
		Ok(format!(
			"{:?} {:?}",
			w.tx_log_iter()?.collect::<Vec<_>>(),
			w.iter()?.collect::<Vec<_>>()
		))
	};
	let before = pending_state()?;
	for encrypted in [false, true] {
		let packed = payer.encrypt_slate(
			payer_mask.as_ref(),
			&response.slate,
			Some(SlateVersion::SP),
			SlatePurpose::InvoiceResponse,
			if encrypted {
				Some(issuer_address)
			} else {
				None
			},
			None,
			false,
		)?;
		let error = finalize(
			&mut issuer,
			issuer_mask.as_ref(),
			FinalizeArgs {
				input_file: None,
				input_slatepack_message: Some(packed.as_string()?),
				fluff: false,
				nopost: false,
				dest: None,
			},
			true,
		)
		.unwrap_err();
		assert!(
			error.to_string().contains("65534-byte payload limit"),
			"{}",
			error
		);
		assert_eq!(before, pending_state()?);
		// Repeated authenticated requests must release their reply reservation.
		for _ in 0..2 {
			assert_size_error(
				ForeignRpc::finalize_invoice_tx(&foreign, packed.clone()).unwrap_err(),
			);
			assert_eq!(before, pending_state()?);
		}
	}

	// The very same invoice still finalizes as compact V3 JSON, which has no
	// Slatepack payload limit. This proves rejection has not consumed its nonce.
	let json = VersionedSlate::into_version_plain(0, &wire_response, SlateVersion::V3)?;
	let finalized = ForeignRpc::finalize_invoice_tx(&foreign, json)?;
	assert_eq!(finalized.version(), SlateVersion::V3);
	let finalized = finalized.into_slate_plain(0, false)?;
	assert_eq!(finalized.tx_or_err()?.body.outputs.len(), 92);
	finalized
		.tx_or_err()?
		.validate(0, Weighting::AsTransaction, &mut secp)?;
	{
		wallet_inst!(issuer_wallet, w);
		assert!(matches!(
			w.get_private_context(&secp, issuer_mask.as_ref(), initial.id.as_bytes(), 0),
			Err(Error::PrivateContextNotFound(_))
		));
		w.get_stored_tx_by_uuid(&initial.id.to_string(), false)?
			.validate(0, Weighting::AsTransaction, &mut secp)?;
	}
	proxy_handle.stop()?;
	Ok(())
}

#[test]
fn oversized_invoice_slatepack_preserves_context() {
	let test_dir = "test_output/invoice_slatepack_size";
	common::setup(test_dir);
	invoice_slatepack_size_impl(test_dir).unwrap();
	common::clean_output_dir(test_dir);
}
