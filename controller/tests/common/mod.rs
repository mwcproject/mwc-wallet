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

//! common functions for tests (instantiating wallet and proxy, mostly)
extern crate mwc_wallet_controller as wallet;
extern crate mwc_wallet_impls as impls;
extern crate mwc_wallet_libwallet as libwallet;

use mwc_wallet_util::mwc_core as core;
use mwc_wallet_util::mwc_keychain as keychain;
use mwc_wallet_util::mwc_util as util;

use self::core::global;
use self::keychain::ExtKeychain;
use self::libwallet::WalletInst;
use impls::test_framework::{LocalWalletClient, WalletProxy};
use impls::{DefaultLCProvider, DefaultWalletImpl};
use mwc_wallet_util::mwc_core::consensus;
use mwc_wallet_util::mwc_core::core::Transaction;
use std::sync::Arc;
use std::sync::Mutex;
use util::secp::key::SecretKey;
use util::ZeroingString;

#[macro_export]
macro_rules! wallet_inst {
	($wallet:ident, $w: ident) => {
		let mut w_lock = $wallet.lock().unwrap_or_else(|e| e.into_inner());
		let lc = w_lock.lc_provider()?;
		let $w = lc.wallet_inst()?;
	};
}

#[macro_export]
macro_rules! wallet_inst_test {
	($wallet:ident, $w: ident) => {
		let mut w_lock = $wallet.lock().unwrap_or_else(|e| e.into_inner());
		let lc = w_lock.lc_provider().unwrap();
		let $w = lc.wallet_inst().unwrap();
	};
}

#[macro_export]
macro_rules! create_wallet_and_add {
	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $seed_phrase: expr, $proxy: expr, $create_mask: expr) => {
		let $client = LocalWalletClient::new($name, $proxy.tx.clone());
		let ($wallet, $mask) = common::create_local_wallet(
			$test_dir,
			$name,
			$seed_phrase.clone(),
			$client.clone(),
			$create_mask,
		);
		$proxy.add_wallet(
			$name,
			$client.get_send_instance(),
			$wallet.clone(),
			$mask.clone(),
		);
	};
}

#[macro_export]
macro_rules! open_wallet_and_add {
	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $proxy: expr, $create_mask: expr) => {
		let $client = LocalWalletClient::new($name, $proxy.tx.clone());
		let ($wallet, $mask) =
			common::open_local_wallet($test_dir, $name, $client.clone(), $create_mask);
		$proxy.add_wallet(
			$name,
			$client.get_send_instance(),
			$wallet.clone(),
			$mask.clone(),
		);
	};
}
#[allow(dead_code)]
pub fn clean_output_dir(test_dir: &str) {
	let path = std::path::Path::new(test_dir);
	if path.is_dir() {
		#[cfg(target_os = "windows")]
		{
			let _ = remove_dir_all::remove_dir_all(test_dir);
		}
		#[cfg(not(target_os = "windows"))]
		{
			remove_dir_all::remove_dir_all(test_dir).unwrap();
		}
	}
}

#[allow(dead_code)]
pub fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(consensus::MILLI_MWC / 100);
	global::set_local_nrd_enabled(true);
}

/// Some tests require the global chain_type to be configured due to threads being spawned internally.
/// It is recommended to avoid relying on this if at all possible as global chain_type
/// leaks across multiple tests and will likely have unintended consequences.
#[allow(dead_code)]
pub fn setup_global_chain_type() {
	global::init_global_chain_type(0, global::ChainTypes::AutomatedTesting);
	global::init_global_nrd_enabled(0, true);
	global::init_global_accept_fee_base(0, global::DEFAULT_ACCEPT_FEE_BASE);
}

#[allow(dead_code)]
pub fn create_wallet_proxy(
	test_dir: String,
	tx_pool: Arc<Mutex<Vec<Transaction>>>,
) -> WalletProxy<
	'static,
	DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
	LocalWalletClient,
	ExtKeychain,
> {
	WalletProxy::new(test_dir, tx_pool)
}

#[allow(dead_code)]
pub fn create_local_wallet(
	test_dir: &str,
	name: &str,
	mnemonic: Option<ZeroingString>,
	client: LocalWalletClient,
	create_mask: bool,
) -> (
	Arc<
		Mutex<
			Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>,
		>,
	>,
	Option<SecretKey>,
) {
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(0, client))
		as Box<
			dyn WalletInst<
				DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/{}", test_dir, name));
	lc.create_wallet(
		None,
		mnemonic,
		32,
		ZeroingString::from(""),
		false,
		None,
		true,
	)
	.unwrap();
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), create_mask, false, None)
		.unwrap();
	(Arc::new(Mutex::new(wallet)), mask)
}

#[allow(dead_code)]
pub fn open_local_wallet(
	test_dir: &str,
	name: &str,
	client: LocalWalletClient,
	create_mask: bool,
) -> (
	Arc<
		Mutex<
			Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>,
		>,
	>,
	Option<SecretKey>,
) {
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(0, client))
		as Box<
			dyn WalletInst<
				DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/{}", test_dir, name));
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), create_mask, false, None)
		.unwrap();
	(Arc::new(Mutex::new(wallet)), mask)
}
