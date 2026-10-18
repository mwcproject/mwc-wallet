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

//! Wallet data dumps must authenticate masked-wallet callers before producing
//! output or touching the requested destination file.

#![cfg(feature = "test-support")]

use mwc_wallet_impls::test_framework::LocalWalletClient;
use mwc_wallet_libwallet::Error;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_util::file;
use mwc_wallet_util::Mutex;
use std::fs;
use std::sync::Arc;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn dump_wallet_data_mask_test_impl(test_dir: &str) -> Result<(), Error> {
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy = create_wallet_proxy(test_dir.into(), tx_pool);

	create_wallet_and_add!(
		client,
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
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let wrong_mask = SecretKey::from_slice(&secp, &[42; 32])?;
	let dump_path = format!("{}/wallet-dump.txt", test_dir);
	let new_dump_path = format!("{}/new-wallet-dump.txt", test_dir);
	let sentinel = b"existing file contents";
	// The authenticated dump requires a private destination regardless of umask.
	file::write_new_owner_only_file(&dump_path, sentinel)?;

	let mut owner_api = mwc_wallet_api::Owner::new(0, wallet, None)?;

	owner_api
		.dump_wallet_data(None, new_dump_path.clone())
		.expect_err("a masked wallet dump must reject a missing mask");
	assert!(!std::path::Path::new(&new_dump_path).exists());

	owner_api
		.dump_wallet_data(Some(&wrong_mask), dump_path.clone())
		.expect_err("a masked wallet dump must reject an incorrect mask");
	assert_eq!(fs::read(&dump_path)?, sentinel);

	mwc_wallet_controller::command::dump_wallet_data(
		&mut owner_api,
		Some(correct_mask),
		dump_path.clone(),
	)
	.expect("the command must forward the correct mask to the Owner API");
	let dump = fs::read_to_string(&dump_path)?;
	assert!(dump.contains("Wallet Outputs:"));
	assert!(dump.contains("Wallet Transactions:"));

	Ok(())
}

#[test]
fn dump_wallet_data_requires_mask_before_touching_destination() {
	let test_dir = "test_output/dump_wallet_data_mask";
	setup(test_dir);
	if let Err(e) = dump_wallet_data_mask_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
