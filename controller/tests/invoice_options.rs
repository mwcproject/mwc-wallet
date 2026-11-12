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

//! Invoice payments must reject unsupported options and respect explicit coin selection.

#![cfg(feature = "test-support")]

use std::collections::HashSet;
use std::ops::DerefMut;
use std::sync::Arc;

use mwc_wallet_api::{Owner, OwnerRpcV3, Token};
use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::api_impl::owner;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{
	Error, InitTxArgs, IssueInvoiceTxArgs, OutputStatus, SlatePurpose, SlateVersion, VersionedSlate,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::consensus::MWC_FIRST_GROUP_REWARD;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_util::ToHex;

#[macro_use]
mod common;

fn assert_option_rejected(error: Error, reason: &str) {
	assert!(
		matches!(&error, Error::GenericError(message) if message.contains(reason)),
		"unexpected invoice option error: {error:?}"
	);
}

fn invoice_options_test_impl(test_dir: &str) -> Result<(), mwc_wallet_controller::Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	create_wallet_and_add!(
		payer_client,
		payer_wallet,
		payer_mask,
		test_dir,
		"payer",
		None,
		&mut wallet_proxy,
		true
	);
	create_wallet_and_add!(
		issuer_client,
		issuer_wallet,
		issuer_mask,
		test_dir,
		"issuer",
		None,
		&mut wallet_proxy,
		true
	);
	let proxy_handle = wallet_proxy.start();
	let payer = Owner::new(0, payer_wallet.clone(), None)?;
	let issuer = Owner::new(0, issuer_wallet, None)?;
	let mask = payer_mask.as_ref();
	let payer_public_key = payer.get_wallet_public_address(mask)?;
	let payer_address = ProvableAddress::from_tor_pub_key(&payer_public_key)?;
	let issuer_public_key = issuer.get_wallet_public_address(issuer_mask.as_ref())?;
	let issuer_address = ProvableAddress::from_tor_pub_key(&issuer_public_key)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	test_framework::award_blocks_to_wallet(
		&chain,
		payer_wallet.clone(),
		mask,
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;

	for compact in [false, true] {
		let invoice = issuer.issue_invoice_tx(
			issuer_mask.as_ref(),
			None,
			&IssueInvoiceTxArgs {
				amount: MWC_FIRST_GROUP_REWARD,
				slatepack_recipient: compact.then_some(payer_address.clone()),
				..Default::default()
			},
		)?;
		assert_eq!(invoice.compact_slate, compact);
		let versioned = if compact {
			issuer.encrypt_slate(
				issuer_mask.as_ref(),
				&invoice,
				Some(SlateVersion::SP),
				SlatePurpose::InvoiceInitial,
				Some(payer_public_key),
				None,
				false,
			)?
		} else {
			VersionedSlate::into_version_plain(0, &invoice, SlateVersion::V3)?
		};
		let rpc_process = |args| {
			OwnerRpcV3::process_invoice_tx(
				&payer,
				Token {
					keychain_mask: payer_mask.clone(),
				},
				versioned.clone(),
				args,
			)
		};
		let (updated, height, outputs_before) = payer.retrieve_outputs(mask, false, true, None)?;
		assert!(updated);
		let eligible: Vec<_> = outputs_before
			.iter()
			.filter(|o| o.output.eligible_to_spend(height, 2))
			.collect();
		// One reward covers the invoice amount but not its fee. Two suffice,
		// and other eligible coins exist to catch an unrestricted fallback.
		assert!(eligible.len() > 2);
		assert!(eligible.iter().all(|o| o.output.value == invoice.amount));
		let selected: HashSet<_> = eligible.iter().take(2).map(|o| o.commit.to_hex()).collect();
		let mut args = InitTxArgs {
			amount: invoice.amount,
			minimum_confirmations: 2,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let snapshot = || -> Result<_, Error> {
			wallet_inst!(payer_wallet, w);
			let parent = w.parent_key_id();
			Ok((
				w.current_child_index(&parent)?,
				w.iter()?.collect::<Vec<_>>(),
				w.tx_log_iter()?.count(),
			))
		};
		let before = snapshot()?;

		for (estimate_only, proof_recipient, reason) in [
			(Some(true), None, "estimate_only is not supported"),
			(
				None,
				Some(issuer_address.clone()),
				"Payment proofs are not supported for invoice transactions",
			),
		] {
			args.estimate_only = estimate_only;
			args.payment_proof_recipient_address = proof_recipient;
			assert_option_rejected(rpc_process(args.clone()).unwrap_err(), reason);
			assert_eq!(snapshot()?, before);
			// Public and direct libwallet callers must reject unsupported options,
			// with or without a session, before allocating change or signing.
			for with_session in [false, true] {
				let mut session = TxSession::new();
				let error = payer
					.process_invoice_tx(mask, with_session.then_some(&mut session), &invoice, &args)
					.err()
					.expect("unsupported invoice option must be rejected");
				assert_option_rejected(error, reason);
				assert!(session.is_empty());
				assert!(session.get_input_commits().is_empty());
				assert!(session.get_outputs().is_empty());
				assert_eq!(snapshot()?, before);
				{
					wallet_inst!(payer_wallet, w);
					let error = owner::process_invoice_tx(
						&mut **w,
						&mut secp,
						mask,
						&mut with_session.then_some(&mut session),
						&invoice,
						&args,
						false,
						false,
					)
					.unwrap_err();
					assert_option_rejected(error, reason);
				}
				assert!(session.is_empty());
				assert!(session.get_input_commits().is_empty());
				assert!(session.get_outputs().is_empty());
				assert_eq!(snapshot()?, before);
			}
			{
				wallet_inst!(payer_wallet, w);
				assert!(matches!(
					w.get_private_context(&secp, mask, invoice.id.as_bytes(), 1),
					Err(Error::PrivateContextNotFound(_))
				));
			}
		}

		// Both explicit false and the omitted option allow a real payment.
		args.estimate_only = if compact { None } else { Some(false) };
		args.payment_proof_recipient_address = None;
		for allowed in [HashSet::new(), HashSet::from([eligible[0].commit.to_hex()])] {
			args.outputs = Some(allowed);
			let error = rpc_process(args.clone()).unwrap_err();
			assert!(
				matches!(error, Error::NotEnoughFunds { .. }),
				"selection must not fall back to unselected outputs: {error:?}"
			);
			assert_eq!(snapshot()?, before);
		}
		{
			wallet_inst!(payer_wallet, w);
			assert!(matches!(
				w.get_private_context(&secp, mask, invoice.id.as_bytes(), 1),
				Err(Error::PrivateContextNotFound(_))
			));
		}

		args.outputs = Some(selected.clone());
		let (paid, _, _) =
			issuer.decrypt_versioned_slate(issuer_mask.as_ref(), rpc_process(args)?)?;
		let actual: HashSet<_> = paid
			.tx_or_err()?
			.inputs()
			.to_commit_wrappers(0)
			.map_err(Error::from)?
			.iter()
			.map(|input| input.commitment().to_hex())
			.collect();
		assert_eq!(actual, selected);
		assert!(
			paid.participant_data
				.iter()
				.any(|p| p.id == 1 && p.part_sig.is_some())
		);
		let (_, _, outputs_after) = payer.retrieve_outputs(mask, false, false, None)?;
		for previous in outputs_before {
			let current = outputs_after
				.iter()
				.find(|o| o.commit == previous.commit)
				.expect("existing output must remain tracked");
			let expected = if selected.contains(&previous.commit.to_hex()) {
				OutputStatus::Locked
			} else {
				previous.output.status
			};
			assert_eq!(current.output.status, expected);
		}
	}
	proxy_handle.stop()?;
	Ok(())
}

#[test]
fn invoice_options() {
	let test_dir = "test_output/invoice_options";
	common::setup(test_dir);
	invoice_options_test_impl(test_dir).unwrap();
	common::clean_output_dir(test_dir);
}
