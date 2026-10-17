//! Exercise swap cancellation against real committed wallet reservations.

use super::{
	LMDBBackend,
	tests::{TestWalletDir, test_wallet},
};
use crate::node_clients::HTTPNodeClient;
use crate::test_framework::LocalWalletClient;
use mwc_wallet_libwallet::swap::fsm::{
	seller_swap::SellerPostingLockMwcSlate,
	state::{Input, State, StateId},
};
use mwc_wallet_libwallet::swap::owner_swap::process_seller_lock_for_test;
use mwc_wallet_libwallet::swap::types::SwapTransactionsConfirmations;
use mwc_wallet_libwallet::swap::{Context, Error, Swap, swap};
use mwc_wallet_libwallet::transaction_preflight::{MempoolAcceptRequest, MempoolAcceptResponse};
use mwc_wallet_libwallet::{OutputData, OutputStatus, TxLogEntryType, WalletBackend};
use mwc_wallet_util::mwc_core::{consensus, global};
use mwc_wallet_util::mwc_crates::{
	blake2_rfc::blake2b,
	secp::{ContextFlag, Secp256k1},
	serde_json,
	serial_test::{self, serial},
};
use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain};
use mwc_wallet_util::mwc_util::ToHex;
use std::sync::{Arc, mpsc};
use std::thread;

struct Fixture {
	wallet: LMDBBackend<'static, HTTPNodeClient, ExtKeychain>,
	_directory: TestWalletDir,
	secp: Secp256k1,
	swap: Swap,
	context: Context,
	confirmations: SwapTransactionsConfirmations,
}

impl Fixture {
	fn new() -> Self {
		let directory = TestWalletDir::new().unwrap();
		let mut wallet = test_wallet(&directory).unwrap();
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let seed = blake2b::blake2b(32, &[], b"fixed0rng0for0testing0purposes01");
		let keychain = ExtKeychain::from_seed(&secp, seed.as_bytes(), false).unwrap();
		wallet
			.set_keychain(&secp, Box::new(keychain), false, false)
			.unwrap();
		let context: Context = serde_json::from_str(include_str!(
			"../../../libwallet/swap_test/context_sell.json"
		))
		.unwrap();
		let mut swap: Swap = serde_json::from_str(include_str!(
			"../../../libwallet/swap_test/swap_sell_2.json"
		))
		.unwrap();
		swap.state = StateId::SellerPostingLockMwcSlate;
		swap.posted_lock = None;
		swap::set_testing_cur_time(swap.get_time_start_lock().unwrap() - 1);
		let seller = context.unwrap_seller().unwrap();
		for input in &seller.inputs {
			let commit = wallet
				.calc_commit(&secp, None, input.amount, &input.key_id)
				.unwrap();
			let mut batch = wallet.batch(&secp, None).unwrap();
			batch
				.save(OutputData {
					root_key_id: seller.parent_key_id.clone(),
					key_id: input.key_id.clone(),
					n_child: mwc_wallet_libwallet::internal::keys::output_child_index(
						&input.key_id,
					)
					.unwrap(),
					commit: Some(commit.to_hex()),
					mmr_index: input.mmr_index,
					value: input.amount,
					status: OutputStatus::Unspent,
					height: 299_000,
					lock_height: 0,
					is_coinbase: false,
					tx_log_entry: None,
				})
				.unwrap();
			batch.commit().unwrap();
		}
		Self {
			wallet,
			_directory: directory,
			secp,
			swap,
			context,
			confirmations: SwapTransactionsConfirmations {
				mwc_observed: true,
				secondary_observed: true,
				mwc_tip: 300_000,
				mwc_lock_conf: None,
				mwc_redeem_conf: None,
				mwc_refund_conf: None,
				secondary_tip: 500_000,
				secondary_lock_conf: None,
				secondary_lock_amount: 0,
				secondary_redeem_conf: None,
				secondary_refund_conf: None,
				secondary_refund_progress: None,
			},
		}
	}

	fn assert_inputs(&self, status: OutputStatus) {
		for input in &self.context.unwrap_seller().unwrap().inputs {
			assert_eq!(
				self.wallet
					.get(&input.key_id, &input.mmr_index)
					.unwrap()
					.status,
				status
			);
		}
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
	}
}

#[test]
#[serial]
fn swap_lock_deadline_after_reservation_releases_wallet_inputs() {
	let mut f = Fixture::new();
	let mut state = SellerPostingLockMwcSlate::new(0, Arc::new(f.wallet.w2n_client().clone()));
	let response = state
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert!(response.action.is_some());
	let result = process_seller_lock_for_test(
		&mut f.wallet,
		&mut f.secp,
		None,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		|swap, secp| {
			// Expire between the owner's Check and the state's Execute, after
			// the real backend has durably reserved the transaction inputs.
			swap::set_testing_cur_time(swap.get_time_start_lock().unwrap() + 1);
			let response = state.process_with_persist(
				Input::Execute,
				swap,
				&f.context,
				&f.confirmations,
				secp,
				&|_| panic!("expired lock must not reach publication"),
			)?;
			swap.state = response.next_state_id.clone();
			Ok(response)
		},
	)
	.unwrap();
	assert_eq!(result.next_state_id, StateId::SellerCancelled);
	f.assert_inputs(OutputStatus::Unspent);
	let logs: Vec<_> = f.wallet.tx_log_iter().unwrap().collect();
	assert_eq!(logs.len(), 1);
	assert_eq!(logs[0].tx_type, TxLogEntryType::TxSentCancelled);
	let change = &f.context.unwrap_seller().unwrap().change_output;
	assert_eq!(
		f.wallet.get(change, &None).unwrap().tx_log_entry,
		Some(logs[0].id)
	);
}

#[test]
#[serial]
fn swap_lock_persistence_failure_releases_inputs_and_allows_retry() {
	let mut f = Fixture::new();
	// Let node validation succeed so each attempt reaches the injected save
	// failure. The backend fixture's HTTP client has no running node.
	let (requests_tx, requests_rx) = mpsc::channel();
	let client = LocalWalletClient::new("swap-lock", requests_tx);
	let responses = client.get_send_instance();
	let height = f.confirmations.mwc_tip;
	let node = thread::spawn(move || {
		let mut calls = Vec::new();
		for mut message in requests_rx {
			let body = if message.method == "testmempoolaccept" {
				let request: MempoolAcceptRequest = serde_json::from_str(&message.body).unwrap();
				let mut response = MempoolAcceptResponse::new(&request, Default::default(), height);
				for result in &mut response.transactions {
					result.balance_checked = result.is_complete;
				}
				serde_json::to_string(&response).unwrap()
			} else {
				serde_json::to_string("unexpected publication after persistence failure").unwrap()
			};
			calls.push(message.method.clone());
			message.dest = message.sender_id;
			message.sender_id = "node".into();
			message.body = body;
			responses.send(message).unwrap();
		}
		calls
	});
	let mut state = SellerPostingLockMwcSlate::new(0, Arc::new(client));
	for attempt in 1..=2 {
		let result = process_seller_lock_for_test(
			&mut f.wallet,
			&mut f.secp,
			None,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			|swap, secp| {
				state.process_with_persist(
					Input::Execute,
					swap,
					&f.context,
					&f.confirmations,
					secp,
					&|_| Err(Error::Generic("injected persistence failure".into())),
				)
			},
		);
		let error = result.unwrap_err();
		assert!(
			error.to_string().contains("injected persistence failure"),
			"unexpected lock error: {error}"
		);
		assert!(f.swap.posted_lock.is_none());
		f.assert_inputs(OutputStatus::Unspent);
		let logs: Vec<_> = f.wallet.tx_log_iter().unwrap().collect();
		assert_eq!(logs.len(), attempt);
		assert!(
			logs.iter()
				.all(|entry| entry.tx_type == TxLogEntryType::TxSentCancelled)
		);
	}
	drop(state);
	assert_eq!(node.join().unwrap(), vec!["testmempoolaccept"; 2]);
}

#[test]
#[serial]
fn swap_lock_exposure_retains_wallet_inputs_on_failure() {
	for observed in [false, true] {
		let mut f = Fixture::new();
		if observed {
			f.confirmations.mwc_lock_conf = Some(1);
		} else {
			f.swap.posted_lock = Some(swap::get_cur_time());
		}
		let result = process_seller_lock_for_test(
			&mut f.wallet,
			&mut f.secp,
			None,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			|_, _| Err(Error::Generic("submission outcome unresolved".into())),
		);
		assert!(result.is_err());
		f.assert_inputs(OutputStatus::Locked);
		assert!(
			f.wallet
				.tx_log_iter()
				.unwrap()
				.all(|entry| entry.tx_type == TxLogEntryType::TxSent)
		);
	}
}
