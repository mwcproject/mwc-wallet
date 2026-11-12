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

#![cfg(feature = "test-support")]

extern crate mwc_wallet_util;

use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::core::{OutputFeatures, Transaction};
use mwc_wallet_util::mwc_core::libtx::proof::{ProofBuild, ProofBuilder};
use mwc_wallet_util::mwc_crates::rand::{TryRng, rngs::SysRng};
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_keychain::{
	BlindingFactor, ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType, mnemonic,
};
use mwc_wallet_util::mwc_util::ZeroingString;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn build_output_test_impl(test_dir: &str) -> Result<(), mwc_wallet_libwallet::Error> {
	// Generate seed so we can verify the blinding factor is derived correctly
	let mut seed = [0u8; 32];
	SysRng.try_fill_bytes(&mut seed).unwrap();
	let mut secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
	let keychain = ExtKeychain::from_seed(&secp, &seed, false).unwrap();
	let mnemonic = mnemonic::from_entropy(&seed).unwrap();

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
		Some(ZeroingString::from(mnemonic.to_string())),
		&mut wallet_proxy,
		false
	);

	let mask1 = (&mask1_i).as_ref();

	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"miner",
		None,
		&mut wallet_proxy,
		false
	);
	let mask2 = mask2_i.as_ref();

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	let features = OutputFeatures::Plain;
	let amount = 60_000_000_000;
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			let error = api.build_output(m, features, amount).unwrap_err();
			assert!(matches!(
				error,
				mwc_wallet_libwallet::Error::GenericError(ref message)
					if message == "Cannot build a plain output without a confirmed height. Sync the wallet first."
			));
			Ok(())
		},
	)
	.unwrap();

	// Coinbase outputs can still be built before synchronization.
	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let built = api.build_output(m, OutputFeatures::Coinbase, amount)?;
			assert!(built.output.is_coinbase());
			built.output.verify_proof(&mut secp)?;
			Ok(())
		},
	)
	.unwrap();
	test_framework::award_block_to_wallet(&chain, &[], wallet2.clone(), mask2)?;

	mwc_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|sender_api, m| {
			// A nonzero node tip alone does not replace the wallet's saved sync height.
			assert!(sender_api.build_output(m, features, amount).is_err());
			let (refreshed, info) = sender_api.retrieve_summary_info(m, true, 1)?;
			assert!(refreshed);
			assert_eq!(info.last_confirmed_height, 1);
			let built_output = sender_api.build_output(m, features, amount)?;

			let key_id = built_output.key_id;
			// Rejected requests must not reserve derivation indices.
			assert_eq!(
				key_id.to_path().unwrap(),
				ExtKeychainPath::new(3, 0, 0, 0, 0).unwrap()
			);

			let blind = built_output.blind;
			let key = keychain.derive_key(&secp, amount, &key_id, SwitchCommitmentType::Regular)?;
			assert_eq!(blind, BlindingFactor::from_secret_key(key.clone()));

			let output = built_output.output;
			assert_eq!(output.features(), features);
			assert_eq!(output.commitment(), secp.commit(amount, key).unwrap());
			output.verify_proof(&mut secp)?;

			let builder = ProofBuilder::new(&secp, &keychain)?;
			let nonce = builder.rewind_nonce(&secp, &output.commitment())?;
			let proof_info =
				secp.rewind_bullet_proof(output.commitment(), nonce, None, None, output.proof)?;
			assert_eq!(proof_info.value, amount);
			assert_eq!(&proof_info.message.as_bytes()[16..20], &1u32.to_be_bytes());

			Ok(())
		},
	)
	.unwrap();

	// let logging finish
	proxy_handle.stop()?;
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn build_output() {
	let test_dir = "test_output/build_output";
	setup(test_dir);
	if let Err(e) = build_output_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
