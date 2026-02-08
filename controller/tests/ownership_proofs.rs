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
#[macro_use]
extern crate log;
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;

use mwc_wallet_util::mwc_core::global;
use std::ops::DerefMut;
use std::sync::Arc;

use impls::test_framework::{self, LocalWalletClient};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use mwc_wallet_libwallet::PubKeySignature;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_util::ZeroingString;
use std::sync::Mutex;

/// self send impl
fn ownership_proof_impl(test_dir: &str) -> Result<(), wallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		Some(ZeroingString::from(
			"room plastic there over junior comfort drip envelope hope divide cake trophy"
		)),
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		10 as usize,
		false,
		tx_pool
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.deref_mut(),
	);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert!(wallet1_info.last_confirmed_height > 0);
		assert!(wallet1_info.total > 0);

		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), true, true, true)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_some());
		assert!(proof.tor_address.is_some());
		assert!(proof.mqs_address.is_some());

		assert_eq!(format!("{:?}", proof), "OwnershipProof { network: \"floonet\", message: \"my message to sign\", wallet_root: Some(PubKeySignature { public_key: \"022e4a08245fc03ca5da9c717c1b29c589413fac96150a400500eff613d05dd34d\", signature: \"3045022100e12d078b67446cc83ab46918b5a641a61b4a02bcdfac03b8978865ca6740def302202f463ec8dea18921942e20452d15ddd2fbcf590aa36b0c414d45078a83d38b92\" }), tor_address: Some(PubKeySignature { public_key: \"fa30d0726b505d6304d93a4ed6c4a428d467b1da13a7826cfdd4131046ca27a4\", signature: \"1cb237ca781f0868752dcc0e503eb70904fd208c7b64c3d23ed6830c808663cae723ac909709f1c16495b2162ec9028a225f7074863172246930eaaee3853706\" }), mqs_address: Some(PubKeySignature { public_key: \"0214f727d0503231f7dd4797509b3e7cde3f7cfdf8c32a3b562c8bd3f650bb2509\", signature: \"30440220035e56caa572ade99ebbffdc2d166c943fe433418269cb156d21f4a0e02557520220628e9e530e662ca1632774106f37a1404873f6bc482bc603a8cfee6c3e92f2f6\" }) }");

		let validate_res = api.validate_ownership_proof(proof.clone());
		assert!(validate_res.is_ok());
		let validate_res = validate_res.unwrap();

		assert_eq!(proof.message, validate_res.message);
		assert_eq!(proof.network, validate_res.network);
		assert_eq!(format!("{:?}", validate_res), "OwnershipProofValidation { network: \"floonet\", message: \"my message to sign\", viewing_key: Some(\"60a98a5d7d1823743b9c3993a31bec49fc7114d3cdbe6bf9e81f53a7f7e02727\"), tor_address: Some(\"7iyna4tlkbowgbgzhjhnnrfefdkgpmo2cotye3h52qjrarwke6saswid\"), mqs_address: Some(\"xmfmGjJU6hLUtndfwDSQmxtYckgDQEquMwXxxCW8D2zUN1uvdrkN\") }");

		// Now let's try to adjust something and validate that it will fail
		let mut invalid_proof = proof.clone();
		invalid_proof.network = "mainnet".to_string();
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.message = "another message".to_string();
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.tor_address = None;
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.wallet_root = None;
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.mqs_address = None;
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.wallet_root = Some(PubKeySignature{
            public_key: "022e4a08245fc03ca5da9c717c1b29c589413fac96150a400500eff613d15dd34d".to_string(), // PK is changed
            signature: "3045022100e12d078b67446cc83ab46918b5a641a61b4a02bcdfac03b8978865ca6740def302202f463ec8dea18921942e20452d15ddd2fbcf590aa36b0c414d45078a83d38b92".to_string(),
        });
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		let mut invalid_proof = proof.clone();
		invalid_proof.wallet_root = Some(PubKeySignature{
            public_key: "022e4a08245fc03ca5da9c717c1b29c589413fac96150a400500eff613d05dd34d".to_string(),
            signature: "3045022100e12d078b67446cc83ab46918b5a641a61b4a02bcdfac03b8978865ca6740def302202f453ec8dea18921942e20452d15ddd2fbcf590aa36b0c414d45078a83d38b92".to_string(), // signature is changed
        });
		let validate_res = api.validate_ownership_proof(invalid_proof);
		assert!(validate_res.is_err());

		// Now let try not full proofs
		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), true, false, false)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_some());
		assert!(proof.tor_address.is_none());
		assert!(proof.mqs_address.is_none());

		let validate_res = api.validate_ownership_proof(proof).unwrap();
		assert_eq!("my message to sign", validate_res.message);
		assert_eq!("floonet", validate_res.network);
		assert!(validate_res.viewing_key.is_some());
		assert!(validate_res.tor_address.is_none());
		assert!(validate_res.mqs_address.is_none());

		// Now let try not full proofs
		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), false, true, false)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_none());
		assert!(proof.tor_address.is_some());
		assert!(proof.mqs_address.is_none());

		let validate_res = api.validate_ownership_proof(proof).unwrap();
		assert_eq!("my message to sign", validate_res.message);
		assert_eq!("floonet", validate_res.network);
		assert!(validate_res.viewing_key.is_none());
		assert!(validate_res.tor_address.is_some());
		assert!(validate_res.mqs_address.is_none());

		// Now let try not full proofs
		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), false, false, true)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_none());
		assert!(proof.tor_address.is_none());
		assert!(proof.mqs_address.is_some());

		let validate_res = api.validate_ownership_proof(proof).unwrap();
		assert_eq!("my message to sign", validate_res.message);
		assert_eq!("floonet", validate_res.network);
		assert!(validate_res.viewing_key.is_none());
		assert!(validate_res.tor_address.is_none());
		assert!(validate_res.mqs_address.is_some());

		// Now let try not full proofs
		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), true, false, true)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_some());
		assert!(proof.tor_address.is_none());
		assert!(proof.mqs_address.is_some());

		let validate_res = api.validate_ownership_proof(proof).unwrap();
		assert_eq!("my message to sign", validate_res.message);
		assert_eq!("floonet", validate_res.network);
		assert!(validate_res.viewing_key.is_some());
		assert!(validate_res.tor_address.is_none());
		assert!(validate_res.mqs_address.is_some());

		// Now let try not full proofs
		let proof =
			api.retrieve_ownership_proof(m, "my message to sign".to_string(), true, true, false)?;

		assert_eq!(proof.message, "my message to sign");
		assert_eq!(proof.network, "floonet");
		assert!(proof.wallet_root.is_some());
		assert!(proof.tor_address.is_some());
		assert!(proof.mqs_address.is_none());

		let validate_res = api.validate_ownership_proof(proof).unwrap();
		assert_eq!("my message to sign", validate_res.message);
		assert_eq!("floonet", validate_res.network);
		assert!(validate_res.viewing_key.is_some());
		assert!(validate_res.tor_address.is_some());
		assert!(validate_res.mqs_address.is_none());

		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn wallet_ownership_proof() {
	let test_dir = "test_output/ownership_proof";
	setup(test_dir);
	if let Err(e) = ownership_proof_impl(test_dir) {
		panic!("ownership_proof_impl Error: {}", e);
	}
	clean_output_dir(test_dir);
}
