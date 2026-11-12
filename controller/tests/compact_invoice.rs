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

//! Compact self-invoices must remain balanced through processing and finalization.

#![cfg(feature = "test-support")]

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_libwallet::{
	Error, InitTxArgs, IssueInvoiceTxArgs, Slate, SlateVersion, Slatepacker, TxLogEntryType,
};
use mwc_wallet_util::mwc_core::core::{transaction::Weighting, Transaction};
use mwc_wallet_util::mwc_core::{self, global};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::{key::SecretKey, ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::BlindingFactor;
use mwc_wallet_util::Mutex;
use std::{ops::DerefMut, sync::Arc};

#[macro_use]
mod common;

fn slatepack_round_trip(
	slate: Slate,
	purpose: SlatePurpose,
	secret: &ed25519_dalek::SigningKey,
	secp: &Secp256k1,
) -> Result<Slate, Error> {
	let public = ed25519_dalek::VerifyingKey::from(secret);
	let packed = Slatepacker::encrypt_to_send(
		0,
		slate,
		SlateVersion::SP,
		purpose,
		public,
		Some(public),
		secret,
		false,
		secp,
	)?;
	Ok(Slatepacker::decrypt_slatepack(0, packed.as_bytes(), secret, secp)?.to_result_slate())
}

fn compact_self_invoice(
	test_dir: &str,
	use_slatepack: bool,
) -> Result<(), mwc_wallet_controller::Error> {
	common::setup(test_dir);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = common::create_wallet_proxy(test_dir.into(), pool.clone());
	let chain = proxy.chain.clone();
	create_wallet_and_add!(client, wallet, mask_i, test_dir, "wallet", None, &mut proxy, true);
	let mask = mask_i.as_ref();
	let handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		wallet.clone(),
		mask,
		10,
		false,
		pool.lock().deref_mut(),
	)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let secret = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
	let public = ed25519_dalek::VerifyingKey::from(&secret);
	let mut response = Slate::blank(2, true)?;
	let mut original_output = None;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet.clone()),
		mask,
		None,
		|api, m| {
			let invoice = api.issue_invoice_tx(
				m,
				None,
				&IssueInvoiceTxArgs {
					amount: mwc_core::consensus::MWC_FIRST_GROUP_REWARD * 2,
					slatepack_recipient: Some(ProvableAddress::from_tor_pub_key(&public)?),
					message: Some("compact invoice issuer".to_owned()),
					..Default::default()
				},
			)?;
			original_output = invoice.tx_or_err()?.outputs().first().copied();
			let invoice = if use_slatepack {
				let decoded =
					slatepack_round_trip(invoice, SlatePurpose::InvoiceInitial, &secret, &secp)?;
				assert!(decoded.tx_or_err()?.outputs().is_empty());
				decoded
			} else {
				invoice
			};
			assert!(invoice.compact_slate);
			let args = InitTxArgs {
				amount: invoice.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				message: Some("compact invoice payer".to_owned()),
				..Default::default()
			};

			// Completing the local issuer offset for validation must still detect
			// an altered incoming offset, before saving a payer signing context.
			let mut altered_invoice = invoice.clone();
			altered_invoice.offset =
				BlindingFactor::from_secret_key(SecretKey::from_slice(&secp, &[23u8; 32])?);
			altered_invoice.tx_or_err_mut()?.offset = altered_invoice.offset.clone();
			assert!(matches!(
				api.process_invoice_tx(m, None, &altered_invoice, &args),
				Err(Error::Committed(_))
			));
			{
				let mut wallet_lock = api.wallet_inst.lock();
				let w = wallet_lock.lc_provider()?.wallet_inst()?;
				assert!(matches!(
					w.get_private_context(&secp, m, invoice.id.as_bytes(), 1),
					Err(Error::PrivateContextNotFound(_))
				));
			}

			let result = api.process_invoice_tx(m, None, &invoice, &args)?;
			response = result.slate;
			api.tx_lock_outputs(m, None, &response, None, 1)?;
			drop(result.processing_guard);

			// Locking the payer must not turn the issuer's output into change or
			// replace its original transaction-log association.
			let (_, _, txs) = api.retrieve_txs(m, false, None, Some(response.id), None, None)?;
			let received = txs
				.iter()
				.find(|tx| tx.tx_type == TxLogEntryType::TxReceived)
				.unwrap();
			let sent = txs
				.iter()
				.find(|tx| tx.tx_type == TxLogEntryType::TxSent)
				.unwrap();
			let issuer_commit = original_output.unwrap().commitment();
			assert!(received.output_commits.contains(&issuer_commit));
			assert!(!sent.output_commits.contains(&issuer_commit));
			let (_, _, outputs) = api.retrieve_outputs(m, true, false, Some(received.id))?;
			assert!(outputs.iter().any(|output| output.commit == issuer_commit));
			Ok(())
		},
	)?;
	if use_slatepack {
		response = slatepack_round_trip(response, SlatePurpose::InvoiceResponse, &secret, &secp)?;
	}
	mwc_wallet_controller::controller::foreign_single_use(wallet.clone(), mask_i.clone(), |api| {
		let finalized = api.finalize_invoice_tx(None, &response, None)?.slate;
		finalized
			.tx_or_err()?
			.validate(0, Weighting::AsTransaction, &mut secp)?;
		assert!(finalized
			.tx_or_err()?
			.outputs()
			.contains(&original_output.unwrap()));
		assert_eq!(finalized.fee, response.fee);
		Ok(())
	})?;
	handle.stop()?;
	common::clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn compact_self_invoice_slatepack() -> Result<(), mwc_wallet_controller::Error> {
	compact_self_invoice("test_output/compact_self_invoice_slatepack", true)
}

#[test]
fn compact_self_invoice_direct() -> Result<(), mwc_wallet_controller::Error> {
	compact_self_invoice("test_output/compact_self_invoice_direct", false)
}
