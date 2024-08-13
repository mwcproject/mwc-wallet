// Copyright 2021 The Grin Developers
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

//! Test a wallet file send/recieve
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;

use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlateGetter, PathToSlatePutter, SlateGetter, SlatePutter};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use grin_wallet_libwallet::{InitTxArgs, IssueInvoiceTxArgs, NodeClient, Slate, Slatepacker};

use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
use libwallet::proof::proofaddress;

#[macro_use]
mod common;
use self::core::global;
use common::{clean_output_dir, create_wallet_proxy, setup};
use grin_wallet_libwallet::slatepack::SlatePurpose;
use grin_wallet_util::grin_util::secp::Secp256k1;
use impls::adapters::SlateGetData;

fn output_slatepack(
	slate: &Slate,
	content: SlatePurpose,
	file_name: &str,
	sender: DalekPublicKey,
	recipients: Option<DalekPublicKey>,
	sender_secret: &DalekSecretKey,
	secp: &Secp256k1,
) -> Result<(), libwallet::Error> {
	PathToSlatePutter::build_encrypted(Some(file_name.into()), content, sender, recipients, true)
		.put_tx(&slate, Some(&sender_secret), true, secp)
		.map_err(|e| libwallet::Error::GenericError(format!("Unable to store the slate, {}", e)))?;
	Ok(())
}

fn slate_from_packed(
	file: &str,
	dec_key: &DalekSecretKey,
	height: u64,
	secp: &Secp256k1,
) -> Result<Slatepacker, libwallet::Error> {
	match PathToSlateGetter::build_form_path(file.into())
		.get_tx(Some(dec_key), height, secp)
		.map_err(|e| libwallet::Error::GenericError(format!("Unable to read the slate, {}", e)))?
	{
		// Plain slate, V2 or V3
		SlateGetData::PlainSlate(_) => {
			return Err(libwallet::Error::GenericError(
				"Not found expected encrypted slatepack, found in plain format only".to_string(),
			)
			.into())
		}
		SlateGetData::Slatepack(sp) => Ok(sp),
	}
}

/// self send impl
fn slatepack_exchange_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();
	let secp = Secp256k1::new();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
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
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::MWC_FIRST_GROUP_REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining").unwrap();
		api.create_account_path(m, "listener").unwrap();
		Ok(())
	})
	.unwrap();

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account1").unwrap();
		api.create_account_path(m, "account2").unwrap();
		Ok(())
	})
	.unwrap();

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let (_address1, recipients_1, secret_1, sender_1) = {
		let mut pub_key = DalekPublicKey::from_bytes(&[0; 32]).unwrap();
		let mut sec_key = DalekSecretKey::from_bytes(&[0u8; 32]).unwrap();
		let mut address = proofaddress::ProvableAddress::blank();
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
			let mut w_lock = api.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			let k = w.keychain(m)?;
			sec_key = proofaddress::payment_proof_address_dalek_secret(&k, None)?;
			pub_key = DalekPublicKey::from(&sec_key);
			address = proofaddress::ProvableAddress::from_tor_pub_key(&pub_key);
			Ok(())
		})
		.unwrap();
		(address, Some(pub_key.clone()), sec_key, pub_key)
	};

	let (address2, recipients_2, secret_2, sender_2) = {
		let mut pub_key = DalekPublicKey::from_bytes(&[0; 32]).unwrap();
		let mut sec_key = DalekSecretKey::from_bytes(&[0u8; 32]).unwrap();
		let mut address = proofaddress::ProvableAddress::blank();
		wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
			let mut w_lock = api.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			let k = w.keychain(m)?;
			sec_key = proofaddress::payment_proof_address_dalek_secret(&k, None)?;
			pub_key = DalekPublicKey::from(&sec_key);
			address = proofaddress::ProvableAddress::from_tor_pub_key(&pub_key);
			Ok(())
		})
		.unwrap();
		(address, Some(pub_key.clone()), sec_key, pub_key)
	};

	let (send_file, receive_file, final_file) = (
		format!("{}/standard_S1.slatepack", test_dir),
		format!("{}/standard_S2.slatepack", test_dir),
		format!("{}/standard_S3.slatepack", test_dir),
	);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		// send to send
		let args = InitTxArgs {
			src_acct_name: Some("mining".to_owned()),
			amount: reward * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			slatepack_recipient: Some(address2.clone()),
			..Default::default()
		};
		let slate = api.init_send_tx(m, &args, 1).unwrap();

		println!("init_send_tx write slate: {:?}", slate);

		// output tx file
		output_slatepack(
			&slate,
			SlatePurpose::SendInitial,
			&send_file,
			sender_1.clone(),
			recipients_2.clone(),
			&secret_1,
			&secp,
		)?;
		api.tx_lock_outputs(m, &slate, None, 0).unwrap();
		Ok(())
	})
	.unwrap();

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let height = {
		wallet_inst!(wallet2, w);
		let (height, _, _) = w.w2n_client().get_chain_tip().unwrap();
		height
	};

	let receive_sp = slate_from_packed(&send_file, &secret_2, height, &secp)?;

	let receive_sender = receive_sp.get_sender();
	let receive_slate = receive_sp.to_result_slate();
	assert!(receive_sender.is_some());

	println!("init_send_tx read slate: {:?}", receive_slate);

	// wallet 2 receives file, completes, sends file back
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		let slate = api.receive_tx(&receive_slate, None, None, None)?;
		println!("receive_tx write slate: {:?}", slate);
		output_slatepack(
			&slate,
			SlatePurpose::SendResponse,
			&receive_file,
			// re-encrypt for sender!
			sender_2.clone(),
			receive_sender,
			&secret_2,
			&secp,
		)?;
		Ok(())
	})
	.unwrap();

	// wallet 1 finalises and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let mut slate = slate_from_packed(&receive_file, &secret_1, height, &secp)
			.unwrap()
			.to_result_slate();

		println!("receive_tx read slate: {:?}", slate);

		slate = api.finalize_tx(m, &slate)?;

		println!("finalize_tx write slate: {:?}", slate);

		// Output final file for reference, SlatePurpose value is fake, will be stored as a plain slate
		output_slatepack(
			&slate,
			SlatePurpose::FullSlate,
			&final_file,
			sender_1.clone(),
			None,
			&secret_1,
			&secp,
		)?;
		api.post_tx(m, slate.tx_or_err()?, false)?;
		bh += 1;
		println!("finalize_tx read slate: {:?}", slate);

		Ok(())
	})
	.unwrap();

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})
	.unwrap();

	// Check total in 'wallet 2' account
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * reward);
		Ok(())
	})
	.unwrap();

	// Now other types of exchange, for reference
	// Invoice transaction
	let (send_file, receive_file, final_file) = {
		(
			format!("{}/invoice_I1.slatepack", test_dir),
			format!("{}/invoice_I2.slatepack", test_dir),
			format!("{}/invoice_I3.slatepack", test_dir),
		)
	};

	//    let mut tmp_slate2 = Slate::blank(2);
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let args = IssueInvoiceTxArgs {
			amount: 1000000000,
			slatepack_recipient: Some(address2.clone()),
			..Default::default()
		};
		let slate = api.issue_invoice_tx(m, &args)?;

		println!("issue_invoice_tx write slate: {:?}", slate);
		//tmp_slate2 = slate.clone();
		output_slatepack(
			&slate,
			SlatePurpose::InvoiceInitial,
			&send_file,
			sender_2.clone(),
			recipients_1.clone(),
			&secret_2,
			&secp,
		)?;
		Ok(())
	})
	.unwrap();

	//    let mut tmp_slate = Slate::blank(2);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let res = slate_from_packed(&send_file, &secret_1, height, &secp)?;
		let invoice_sender = res.get_sender();
		assert!(invoice_sender.is_some());
		let invoice_slate = res.to_result_slate();

		println!("issue_invoice_tx read1 slate: {:?}", invoice_slate);
		//        let invoice_slate = tmp_slate2.clone();
		//        println!("issue_invoice_tx read2 slate: {:?}", invoice_slate);

		let args = InitTxArgs {
			src_acct_name: None,
			amount: invoice_slate.amount, // Whatever number, should be ignored
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};

		let invoice_slate = api.process_invoice_tx(m, &invoice_slate, &args)?;
		api.tx_lock_outputs(m, &invoice_slate, None, 1)?; // because of mwc compability, Invoice processer using participant_id 1

		println!("process_invoice_tx write slate: {:?}", invoice_slate);
		//tmp_slate = invoice_slate.clone();
		output_slatepack(
			&invoice_slate,
			SlatePurpose::InvoiceResponse,
			&receive_file,
			sender_1.clone(),
			invoice_sender,
			&secret_1,
			&secp,
		)?;
		Ok(())
	})
	.unwrap();
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		// Wallet 2 receives the invoice transaction
		let slate = slate_from_packed(&receive_file, &secret_2, height, &secp)?.to_result_slate();

		println!("process_invoice_tx read slate: {:?}", slate);
		//let slate = tmp_slate.clone();
		let slate = api.finalize_invoice_tx(&slate)?; // Slate will be finalized and posted automatically
		output_slatepack(
			&slate,
			SlatePurpose::FullSlate,
			&final_file,
			sender_2.clone(),
			None,
			&secret_2,
			&secp,
		)?;
		Ok(())
	})
	.unwrap();

	// Standard, with payment proof
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	let (send_file, receive_file, final_file) = (
		format!("{}/standard_pp_S1.slatepack", test_dir),
		format!("{}/standard_pp_S2.slatepack", test_dir),
		format!("{}/standard_pp_S3.slatepack", test_dir),
	);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// send to send
		let args = InitTxArgs {
			src_acct_name: Some("mining".to_owned()),
			amount: reward,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			payment_proof_recipient_address: Some(address2.clone()),
			slatepack_recipient: Some(address2.clone()),
			..Default::default()
		};
		let slate = api.init_send_tx(m, &args, 1)?;
		output_slatepack(
			&slate,
			SlatePurpose::SendInitial,
			&send_file,
			sender_1.clone(),
			recipients_2.clone(),
			&secret_1,
			&secp,
		)?;
		api.tx_lock_outputs(m, &slate, None, 0)?;
		Ok(())
	})
	.unwrap();

	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		let res = slate_from_packed(&send_file, &secret_2, height, &secp)?;
		let sender = res.get_sender();
		assert!(sender.is_some());
		let slate = res.to_result_slate();
		let slate = api.receive_tx(&slate, None, None, None)?;
		output_slatepack(
			&slate,
			SlatePurpose::SendResponse,
			&receive_file,
			sender_2.clone(),
			sender,
			&secret_2,
			&secp,
		)?;
		Ok(())
	})
	.unwrap();

	// wallet 1 finalises and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let res = slate_from_packed(&receive_file, &secret_1, height, &secp)?;
		let sender = res.get_sender();
		assert!(sender.is_some());
		let slate = res.to_result_slate();
		let slate = api.finalize_tx(m, &slate)?;
		// Output final file for reference
		output_slatepack(
			&slate,
			SlatePurpose::FullSlate,
			&final_file,
			sender_1,
			None,
			&secret_1,
			&secp,
		)?;
		api.post_tx(m, slate.tx_or_err()?, false)?;
		bh += 1;
		Ok(())
	})
	.unwrap();

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn slatepack_exchange() {
	let test_dir = "test_output/slatepack_exchange";
	setup(test_dir);
	// Json output
	if let Err(e) = slatepack_exchange_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
