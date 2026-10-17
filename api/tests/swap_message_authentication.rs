// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

#![cfg(all(feature = "swaps", feature = "test-support"))]

use mwc_wallet_api::{Foreign, ForeignRpc};
use mwc_wallet_impls::test_framework::LocalWalletClient;
use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use mwc_wallet_libwallet::WalletInst;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::swap::message::{Message, Update};
use mwc_wallet_libwallet::swap::{Context, Swap, owner_swap, swap, trades};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::{consensus, global};
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::serial_test;
use mwc_wallet_util::mwc_crates::serial_test::serial;
use mwc_wallet_util::mwc_crates::sha2::{Digest, Sha256};
use mwc_wallet_util::mwc_crates::tempfile::{TempDir, tempdir};
use mwc_wallet_util::mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util::{ZeroingString, to_hex};
use std::sync::{Arc, mpsc};

type TestWallet = Arc<
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
>;

struct TestEnvironment {
	wallet: TestWallet,
	storage_key: SecretKey,
	directory: TempDir,
}

impl TestEnvironment {
	fn new(secp: &Secp256k1) -> Self {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let directory = tempdir().unwrap();
		// No node is running: authentication and exact replay must finish before
		// any chain query. Unexpected queries fail instead of waiting for a reply.
		let (tx, rx) = mpsc::channel();
		drop(rx);
		let client = LocalWalletClient::new("swap-authentication", tx);
		let wallet: TestWallet = Arc::new(Mutex::new(Box::new(DefaultWalletImpl::new(0, client))));
		let storage_key = {
			let mut wallet = wallet.lock();
			let lc = wallet.lc_provider().unwrap();
			lc.set_top_level_directory(directory.path().to_str().unwrap())
				.unwrap();
			lc.create_wallet(None, None, 32, ZeroingString::from(""), false, None, false)
				.unwrap();
			lc.open_wallet(secp, None, ZeroingString::from(""), false, false, None)
				.unwrap();
			let keychain = lc.wallet_inst().unwrap().keychain(secp, None).unwrap();
			let path = ExtKeychainPath::new(3, 3, 2, 1, 0)
				.unwrap()
				.to_identifier()
				.unwrap();
			keychain
				.derive_key(secp, 0, &path, SwitchCommitmentType::None)
				.unwrap()
		};
		trades::init_swap_trade_backend(
			0,
			directory.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();
		Self {
			wallet,
			storage_key,
			directory,
		}
	}

	fn store(&self, context: &Context, swap: &Swap) {
		let lock = trades::get_swap_lock(0, &swap.id.to_string()).unwrap();
		let _guard = lock.lock();
		trades::store_swap_trade(0, context, swap, &self.storage_key, &lock).unwrap();
	}

	fn load(&self, id: &str) -> Swap {
		let lock = trades::get_swap_lock(0, id).unwrap();
		let _guard = lock.lock();
		trades::get_swap_trade(0, id, &self.storage_key, &lock)
			.unwrap()
			.1
	}

	fn set_destination(&self, secp: &mut Secp256k1, id: &str, method: &str, peer: &str) {
		owner_swap::swap_adjust(
			self.wallet.clone(),
			secp,
			None,
			id,
			"destination",
			Some(method.to_string()),
			Some(peer.to_string()),
			None,
			None,
			None,
			None,
			None,
			None,
		)
		.unwrap();
	}
}

impl Drop for TestEnvironment {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
		trades::trades_clean_context(0);
	}
}

fn peer(secp: &Secp256k1, seed: u8) -> ProvableAddress {
	let secret = SecretKey::from_slice(secp, &[seed; 32]).unwrap();
	ProvableAddress::from_pub_key(secp, 0, &PublicKey::from_secret_key(secp, &secret).unwrap())
		.unwrap()
}

#[test]
#[serial]
fn foreign_swap_message_cannot_bypass_changed_mqs_peer() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let env = TestEnvironment::new(&secp);
	let context: Context =
		serde_json::from_str(include_str!("../../libwallet/swap_test/context_sell.json")).unwrap();
	let swap: Swap =
		serde_json::from_str(include_str!("../../libwallet/swap_test/swap_sell_1.json")).unwrap();
	let id = swap.id.to_string();
	env.store(&context, &swap);
	let previous = peer(&secp, 41);
	let current = peer(&secp, 42);
	env.set_destination(&mut secp, &id, "mwcmqs", &previous.to_string());
	env.set_destination(&mut secp, &id, "mwcmqs", &current.to_string());
	let before = serde_json::to_value(env.load(&id)).unwrap();
	let api = Foreign::new(env.wallet.clone(), None, None);

	// A valid acceptance for the original offer must fail at the sender check,
	// even though its UUID and protocol signatures still belong to this trade.
	let message = include_str!("../../libwallet/swap_test/message_2.json").to_string();
	let error = owner_swap::swap_income_message(
		env.wallet.clone(),
		&mut secp,
		None,
		&message,
		Some(&previous.public_key),
	)
	.unwrap_err();
	assert!(error.to_string().contains("current trade peer"));
	let error = ForeignRpc::receive_swap_message(&api, message).unwrap_err();
	assert!(
		error
			.to_string()
			.contains("require an authenticated sender"),
		"unexpected error: {error}"
	);
	assert_eq!(serde_json::to_value(env.load(&id)).unwrap(), before);
}

#[test]
#[serial]
fn mqs_offer_replay_requires_network_authentication_but_allows_owner_file_import() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let env = TestEnvironment::new(&secp);
	let current = peer(&secp, 43);
	let context: Context =
		serde_json::from_str(include_str!("../../libwallet/swap_test/context_buy.json")).unwrap();
	let mut swap: Swap =
		serde_json::from_str(include_str!("../../libwallet/swap_test/swap_buy_1.json")).unwrap();
	let mut message =
		Message::from_json(include_str!("../../libwallet/swap_test/message_1.json")).unwrap();
	let Update::Offer(offer) = &mut message.inner else {
		panic!("expected offer fixture")
	};
	offer.communication_method = "mwcmqs".to_string();
	offer.from_address = current.to_string();
	swap::set_testing_cur_time(offer.start_time.timestamp());
	let wire_message = message.to_json().unwrap();
	// Reconstruct the durable receipt of an already accepted offer. Authentication
	// must run before this exact-replay shortcut returns an acknowledgement.
	let mut fingerprint = Sha256::new();
	fingerprint.update(b"mwc-wallet/swap-message-fingerprint/v1\0");
	fingerprint.update(u64::try_from(wire_message.len()).unwrap().to_be_bytes());
	fingerprint.update(wire_message.as_bytes());
	swap.received_offer_fingerprint = Some(to_hex(&fingerprint.finalize()));
	let id = swap.id.to_string();
	env.store(&context, &swap);
	env.set_destination(&mut secp, &id, "mwcmqs", &current.to_string());
	let before = serde_json::to_value(env.load(&id)).unwrap();
	let api = Foreign::new(env.wallet.clone(), None, None);
	let error = ForeignRpc::receive_swap_message(&api, wire_message.clone()).unwrap_err();
	assert!(
		error
			.to_string()
			.contains("require an authenticated sender"),
		"unexpected error: {error}"
	);
	let acknowledgement = owner_swap::swap_income_message(
		env.wallet.clone(),
		&mut secp,
		None,
		&wire_message,
		Some(&current.public_key),
	)
	.unwrap()
	.unwrap();
	assert!(matches!(
		acknowledgement.inner,
		Update::MessageAcknowledge(1)
	));
	let message_file = env.directory.path().join("offer.json");
	std::fs::write(&message_file, &wire_message).unwrap();
	assert_eq!(
		owner_swap::swap_create_from_offer(
			env.wallet.clone(),
			&mut secp,
			None,
			message_file.to_str().unwrap().to_string(),
		)
		.unwrap(),
		id
	);
	assert_eq!(serde_json::to_value(env.load(&id)).unwrap(), before);

	// An owner-selected Tor transport continues to accept unauthenticated delivery.
	env.set_destination(&mut secp, &id, "tor", "current-peer.onion");
	ForeignRpc::receive_swap_message(&api, wire_message).unwrap();
}
