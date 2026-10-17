//! Regression tests for bounded state transitions and durable seller lock publication.

use super::import::rejected_import_leaves_live_record;
use super::*;
use crate::swap::owner_swap::recover_imported_trade_state;
use mwc_wallet_util::mwc_crates::secp::AggSigSignature;
use std::cell::RefCell;

struct Fixture {
	secp: Secp256k1,
	swap: Swap,
	keychain: ExtKeychain,
	context: Context,
	node: TestNodeClient,
	confirmations: SwapTransactionsConfirmations,
}

impl Fixture {
	fn new() -> Self {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = keychain(&secp, 1);
		let context = context_sell(&secp, &keychain);
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_sell_2.json")).unwrap();
		// Start with a fully signed lock transaction before its first submission.
		swap.state = StateId::SellerPostingLockMwcSlate;
		swap.posted_lock = None;
		swap::set_testing_cur_time(swap.started.timestamp());
		let node = TestNodeClient::new(300_000);
		for input in swap
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
		{
			node.push_output(input.unwrap());
		}
		let confirmations = SwapTransactionsConfirmations {
			mwc_observed: true,
			secondary_observed: true,
			mwc_tip: 300_000,
			mwc_lock_conf: None,
			mwc_redeem_conf: None,
			mwc_refund_conf: None,
			secondary_tip: 500_000,
			secondary_lock_conf: Some(swap.secondary_confirmations),
			secondary_lock_amount: swap.secondary_amount,
			secondary_redeem_conf: None,
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		};
		Self {
			secp,
			swap,
			keychain,
			context,
			node,
			confirmations,
		}
	}

	fn api(&self) -> BtcSwapApi<'static, TestNodeClient, TestBtcNodeClient> {
		BtcSwapApi::new_test(
			Arc::new(self.node.clone()),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		)
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
	}
}

fn unavailable_secondary_api(f: &mut Fixture, currency: Currency) -> Box<dyn SwapApi<ExtKeychain>> {
	if currency == Currency::Btc {
		let secondary = TestBtcNodeClient::new(500_000);
		secondary.state.lock().height_error = Some("secondary RPC unavailable".into());
		Box::new(BtcSwapApi::new(
			0,
			currency,
			Arc::new(f.node.clone()),
			Arc::new(Mutex::new(secondary.clone())),
			Arc::new(Mutex::new(secondary)),
		))
	} else {
		use crate::swap::ethereum::{EthData, EthSwapApi, TestEthNodeClient};
		f.swap.secondary_currency = currency;
		f.swap.secondary_data = SecondaryData::Eth(
			serde_json::from_value::<EthData>(serde_json::json!({
				"redeem_address": null, "address_from_secret": null,
				"erc20_approve_tx": null, "lock_tx": null, "refund_tx": null,
				"redeem_tx": null, "tx_fee_gwei": null
			}))
			.unwrap(),
		);
		let secondary = TestEthNodeClient::new(500_000);
		secondary.state.lock().chain_tip_error = Some("secondary RPC unavailable".into());
		Box::new(EthSwapApi::new(
			0,
			currency,
			Arc::new(f.node.clone()),
			Arc::new(Mutex::new(secondary)),
		))
	}
}

// Both secondary services fail their normal confirmation query. Verified MWC
// observations must still carry a seller from the refund wait through an actual
// transaction submission and sufficient confirmations, without fabricating a
// secondary balance or weakening any MWC lookup failure.
#[test]
#[serial]
fn seller_refund_completes_with_secondary_rpc_unavailable() {
	for currency in [Currency::Btc, Currency::Ether] {
		let mut f = Fixture::new();
		f.node
			.state
			.lock()
			.pending
			.push(f.swap.lock_slate.slate.tx_or_err().unwrap().clone());
		f.node.mine_block();
		f.node.state.lock().height = f.swap.refund_slate.slate.get_lock_height_check().unwrap() + 1;
		f.swap.state = StateId::SellerWaitingForRefundHeight;
		f.swap.posted_lock = Some(swap::get_cur_time());
		let api = unavailable_secondary_api(&mut f, currency);
		assert!(
			api.request_tx_confirmations(&f.secp, &f.keychain, &f.swap)
				.err()
				.unwrap()
				.to_string()
				.contains("secondary RPC unavailable")
		);
		let confirmations = api
			.request_tx_confirmations_for_state(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert!(!confirmations.secondary_observed);
		assert!(confirmations.mwc_lock_conf.is_some());
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert!(matches!(
			response.action,
			Some(Action::SellerPublishMwcRefundTx)
		));
		fsm.process(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&confirmations,
			&mut f.secp,
		)
		.unwrap();
		assert_eq!(f.node.state.lock().post_calls, 1);
		assert_eq!(f.swap.state, StateId::SellerWaitingForRefundConfirmations);
		f.node.mine_blocks(f.swap.mwc_confirmations + 1);
		let confirmations = api
			.request_tx_confirmations_for_state(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		fsm.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&confirmations,
			&mut f.secp,
		)
		.unwrap();
		assert_eq!(f.swap.state, StateId::SellerCancelledRefunded);

		f.node.state.lock().chain_tip_error = Some("MWC RPC unavailable".into());
		assert!(
			api.request_tx_confirmations_for_state(&f.secp, &f.keychain, &f.swap)
				.is_err()
		);
	}
}

// A partial snapshot cannot flow into lock validation or secondary redemption.
// A newly observed buyer redemption leaves the refund branch, then requires a
// fresh full snapshot before the next action can be selected.
#[test]
#[serial]
fn seller_refund_snapshot_stops_before_secondary_dependent_states() {
	for currency in [Currency::Btc, Currency::Ether] {
		let mut f = Fixture::new();
		f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
		f.swap.state = StateId::SellerWaitingForRefundHeight;
		let buyer: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_buy_3.json")).unwrap();
		f.node
			.state
			.lock()
			.pending
			.push(buyer.redeem_slate.slate.tx_or_err().unwrap().clone());
		f.node.mine_block();
		let api = unavailable_secondary_api(&mut f, currency);
		let confirmations = api
			.request_tx_confirmations_for_state(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert!(confirmations.mwc_redeem_conf.is_some());
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(f.swap.state, StateId::SellerWaitingForBuyerToRedeemMwc);
		assert!(response.action.is_none());
		assert!(
			fsm.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&confirmations,
				&mut f.secp
			)
			.is_err()
		);
		assert!(
			api.request_tx_confirmations_for_state(&f.secp, &f.keychain, &f.swap)
				.is_err()
		);
		assert_eq!(f.node.state.lock().post_calls, 0);
	}
}

#[test]
#[serial]
fn buyer_btc_refund_completes_with_mwc_rpc_unavailable() {
	let _clock = Fixture::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, keychain, mwc, btc) = refund_fixture(&secp);
	// A prepared buyer redemption was never submitted; the funded trade timed out.
	swap.posted_redeem = None;
	swap.state = StateId::BuyerWaitingForRefundTime;
	swap::set_testing_cur_time(swap.get_time_secondary_lock_publish().unwrap() + 1);
	mwc.state.lock().chain_tip_error = Some("MWC RPC unavailable".into());
	let api = BtcSwapApi::new_test(Arc::new(mwc.clone()), Arc::new(Mutex::new(btc.clone())));
	assert!(
		api.request_tx_confirmations(&secp, &keychain, &swap)
			.is_err()
	);
	let confirmations = api
		.request_tx_confirmations_for_state(&secp, &keychain, &swap)
		.unwrap();
	assert!(!confirmations.mwc_observed);
	assert!(confirmations.secondary_observed);
	let mut fsm = api.get_fsm(&keychain, &swap);
	let response = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishSecondaryRefundTx { .. })
	));
	api.prepare_secondary_refund(&secp, &keychain, &context, &mut swap)
		.unwrap();
	// Exercise the same save-before-publication boundary as the owner.
	swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
	fsm.process(
		Input::Execute,
		&mut swap,
		&context,
		&confirmations,
		&mut secp,
	)
	.unwrap();
	assert_eq!(swap.state, StateId::BuyerWaitingForRefundConfirmations);
	assert!(!btc.inner.get_state().pending.is_empty());
	btc.inner.mine_blocks(swap.secondary_confirmations);
	let confirmations = api
		.request_tx_confirmations_for_state(&secp, &keychain, &swap)
		.unwrap();
	fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	assert_eq!(swap.state, StateId::BuyerCancelledRefunded);
	assert_eq!(mwc.state.lock().post_calls, 0);
	btc.inner.state.lock().height_error = Some("BTC RPC unavailable".into());
	assert!(
		api.request_tx_confirmations_for_state(&secp, &keychain, &swap)
			.is_err()
	);
}

#[test]
#[serial]
fn seller_btc_redemption_completes_with_mwc_rpc_unavailable() {
	let _clock = Fixture::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, keychain, mwc, btc) = seller_redeem_fixture(&secp);
	assert!(swap.redeem_kernel_updated);
	let api = BtcSwapApi::new_test(Arc::new(mwc.clone()), Arc::new(Mutex::new(btc.clone())));
	assert!(
		api.request_tx_confirmations_for_state(&secp, &keychain, &swap)
			.unwrap()
			.mwc_observed
	);
	mwc.state.lock().chain_tip_error = Some("MWC RPC unavailable".into());
	assert!(
		api.request_tx_confirmations(&secp, &keychain, &swap)
			.is_err()
	);
	let confirmations = api
		.request_tx_confirmations_for_state(&secp, &keychain, &swap)
		.unwrap();
	assert!(!confirmations.mwc_observed);
	let mut fsm = api.get_fsm(&keychain, &swap);
	let response = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::SellerPublishTxSecondaryRedeem { .. })
	));
	fsm.process(
		Input::Execute,
		&mut swap,
		&context,
		&confirmations,
		&mut secp,
	)
	.unwrap();
	assert_eq!(swap.state, StateId::SellerWaitingForRedeemConfirmations);
	assert!(!btc.inner.get_state().pending.is_empty());
	btc.inner.mine_blocks(swap.secondary_confirmations);
	let confirmations = api
		.request_tx_confirmations_for_state(&secp, &keychain, &swap)
		.unwrap();
	fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	assert_eq!(swap.state, StateId::SellerSwapComplete);
	assert_eq!(mwc.state.lock().post_calls, 0);
}

#[test]
#[serial]
fn secondary_snapshot_cannot_bypass_mwc_redeem_or_refund_resolution() {
	let _clock = Fixture::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, keychain, mwc, btc) = seller_redeem_fixture(&secp);
	swap.redeem_kernel_updated = false;
	mwc.state.lock().chain_tip_error = Some("MWC RPC unavailable".into());
	let api = BtcSwapApi::new_test(Arc::new(mwc), Arc::new(Mutex::new(btc)));
	let confirmations = api
		.request_secondary_tx_confirmations(&secp, &keychain, &swap)
		.unwrap();
	let mut fsm = api.get_fsm(&keychain, &swap);
	assert!(
		fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.is_err()
	);
	assert!(
		api.request_tx_confirmations_for_state(&secp, &keychain, &swap)
			.is_err()
	);

	let (mut swap, context, keychain, mwc, btc) = refund_fixture(&secp);
	mwc.state.lock().chain_tip_error = Some("MWC RPC unavailable".into());
	let api = BtcSwapApi::new_test(Arc::new(mwc), Arc::new(Mutex::new(btc)));
	let confirmations = api
		.request_secondary_tx_confirmations(&secp, &keychain, &swap)
		.unwrap();
	for state in [
		StateId::BuyerWaitForRedeemMwcConfirmations,
		StateId::BuyerWaitingForMwcRefundConfirmations,
	] {
		swap.state = state;
		let mut fsm = api.get_fsm(&keychain, &swap);
		assert!(
			fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
				.is_err()
		);
		assert!(
			api.request_tx_confirmations_for_state(&secp, &keychain, &swap)
				.is_err()
		);
	}
}

// A lost acknowledgement must stop causing retries at the message deadline.
// Check through a staged trade and reload it after success, as the owner does,
// then verify that the seller can still advance to its refund when it unlocks.
#[test]
#[serial]
fn expired_redeem_message_retry_waits_and_remains_refundable() {
	let mut f = Fixture::new();
	let original: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
	let deadline = original.get_time_message_redeem().unwrap();
	let refund_height = original.refund_slate.slate.get_lock_height_check().unwrap();
	f.confirmations.mwc_lock_conf = Some(original.mwc_confirmations);
	let api = f.api();
	for initial_state in [
		StateId::SellerWaitingForBuyerToRedeemMwc,
		StateId::SellerSendingInitRedeemMessage,
	] {
		for now in [deadline, deadline + 1] {
			f.swap = original.clone();
			f.swap.state = initial_state.clone();
			f.swap.redeem_kernel_updated = false;
			f.swap.posted_msg2 = Some(deadline - 600);
			f.confirmations.mwc_tip = refund_height - 1;
			swap::set_testing_cur_time(now);
			for _ in 0..2 {
				let mut staged = f.swap.clone();
				let mut fsm = api.get_fsm(&f.keychain, &staged);
				let response = fsm
					.process(
						Input::Check,
						&mut staged,
						&f.context,
						&f.confirmations,
						&mut f.secp,
					)
					.unwrap();
				assert_eq!(
					response.next_state_id,
					StateId::SellerWaitingForBuyerToRedeemMwc
				);
				assert!(matches!(
					response.action,
					Some(Action::SellerWaitForBuyerRedeemPublish { .. })
				));
				assert_eq!(staged.posted_msg2, Some(i64::from(u32::MAX)));
				f.swap = serde_json::from_str(&serde_json::to_string(&staged).unwrap()).unwrap();
			}

			f.confirmations.mwc_tip = refund_height + 1;
			let mut fsm = api.get_fsm(&f.keychain, &f.swap);
			let response = fsm
				.process(
					Input::Check,
					&mut f.swap,
					&f.context,
					&f.confirmations,
					&mut f.secp,
				)
				.unwrap();
			assert_eq!(response.next_state_id, StateId::SellerPostingRefundSlate);
			assert!(matches!(
				response.action,
				Some(Action::SellerPublishMwcRefundTx)
			));
		}
	}
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// An unacknowledged redeem message can be retried after a secondary-chain
// reorg reduces the lock confirmations. Let the resulting wait time out, then
// mine the buyer's redemption before the refund unlocks. The seller must
// recover the signed kernel and offer secondary redemption in the same check.
#[test]
#[serial]
fn refund_wait_recovers_redemption_after_lock_reorg_and_timeout() {
	let mut f = Fixture::new();
	f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
	assert_eq!(f.swap.state, StateId::SellerWaitingForBuyerToRedeemMwc);
	assert!(f.swap.message2.is_some());
	let deadline = f.swap.get_time_message_redeem().unwrap();
	let refund_height = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
	f.node.state.lock().height = refund_height - 100;
	f.confirmations.mwc_tip = refund_height - 100;
	f.confirmations.mwc_lock_conf = Some(f.swap.mwc_confirmations);
	f.confirmations.secondary_lock_conf = Some(f.swap.secondary_confirmations - 1);
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	for (now, expected_state) in [
		(deadline - 60, StateId::SellerWaitingForLockConfirmations),
		(deadline + 1, StateId::SellerWaitingForRefundHeight),
	] {
		swap::set_testing_cur_time(now);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, expected_state);
	}

	let buyer: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_buy_3.json")).unwrap();
	let redeem_tx = buyer.redeem_slate.slate.tx_or_err().unwrap().clone();
	let redeem_kernel = redeem_tx.kernels()[0].clone();
	f.node.state.lock().pending.push(redeem_tx);
	f.node.mine_block();
	f.confirmations.mwc_tip = f.node.state.lock().height;
	f.confirmations.mwc_redeem_conf = Some(1);
	f.confirmations.secondary_lock_conf = Some(f.swap.secondary_confirmations);
	assert!(f.confirmations.mwc_tip < refund_height);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerRedeemSecondaryCurrency
	);
	assert!(matches!(
		response.action,
		Some(Action::SellerPublishTxSecondaryRedeem { .. })
	));
	assert!(f.swap.redeem_kernel_updated);
	assert_eq!(
		serde_json::to_value(&f.swap.redeem_slate.slate.tx_or_err().unwrap().kernels()[0]).unwrap(),
		serde_json::to_value(&redeem_kernel).unwrap()
	);
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// A previously recovered kernel still supplies the redemption secret when
// a later snapshot no longer sees the transaction. Resume without a lookup.
#[test]
#[serial]
fn refund_wait_uses_recovered_kernel_without_confirmation() {
	let mut f = Fixture::new();
	f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_5.json")).unwrap();
	f.swap.state = StateId::SellerWaitingForRefundHeight;
	assert!(f.swap.redeem_kernel_updated);
	assert!(f.confirmations.mwc_redeem_conf.is_none());
	f.confirmations.mwc_tip = f.swap.refund_slate.slate.get_lock_height_check().unwrap() - 1;
	f.node.state.lock().kernel_lookup_limit = Some(0);
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerRedeemSecondaryCurrency
	);
	assert!(matches!(
		response.action,
		Some(Action::SellerPublishTxSecondaryRedeem { .. })
	));
	assert_eq!(f.node.state.lock().kernel_lookups, 0);
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// A confirmation snapshot alone cannot supply the redemption secret. A node
// error must propagate, and a kernel removed by a reorg must leave us waiting
// or return the bounded cycle error if the refund height has already passed.
#[test]
#[serial]
fn refund_wait_requires_kernel_and_propagates_lookup_errors() {
	for (unlocked, lookup_fails) in [(false, true), (false, false), (true, false)] {
		let mut f = Fixture::new();
		f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
		f.swap.state = StateId::SellerWaitingForRefundHeight;
		let refund_height = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
		f.confirmations.mwc_tip = if unlocked {
			refund_height + 1
		} else {
			refund_height - 1
		};
		f.confirmations.mwc_redeem_conf = Some(1);
		f.node.state.lock().kernel_lookup_limit = Some(if lookup_fails { 0 } else { 4 });
		swap::set_testing_cur_time(f.swap.get_time_message_redeem().unwrap() + 1);
		let api = f.api();
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let result = fsm.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		);
		if lookup_fails {
			assert!(
				result
					.unwrap_err()
					.to_string()
					.contains("Test kernel lookup limit exceeded")
			);
		} else if unlocked {
			assert!(
				matches!(result, Err(Error::SwapStateMachineError(message)) if message.contains("cycle"))
			);
		} else {
			let response = result.unwrap();
			assert_eq!(
				response.next_state_id,
				StateId::SellerWaitingForBuyerToRedeemMwc
			);
			assert!(matches!(
				response.action,
				Some(Action::SellerWaitForBuyerRedeemPublish { .. })
			));
		}
		assert!(!f.swap.redeem_kernel_updated);
		assert_eq!(f.node.state.lock().kernel_lookups, 1);
		assert_eq!(f.node.state.lock().post_calls, 0);
	}
}

// The confirmation snapshot sees a redeem, but a reorg removes its kernel
// before the FSM's fresh lookup. The first check must return a cycle error
// without broadcasting or ending the swap. A subsequent poll with fresh
// confirmations must offer the refund.
#[test]
#[serial]
fn reorg_cycle_returns_error_and_fresh_poll_resumes_refund() {
	let mut f = Fixture::new();
	f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
	f.confirmations.mwc_tip = f.swap.refund_slate.slate.get_lock_height_check().unwrap() + 1;
	f.confirmations.mwc_lock_conf = Some(f.swap.mwc_confirmations);
	f.confirmations.mwc_redeem_conf = Some(1);
	// Bound even the broken implementation so a regression fails instead of hanging.
	f.node.state.lock().kernel_lookup_limit = Some(4);
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let result = fsm.process_with_persist(
		Input::Check,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|_| panic!("A check must not prepare a new lock transaction"),
	);
	assert!(
		matches!(result, Err(Error::SwapStateMachineError(message)) if message.contains("cycle"))
	);
	assert_eq!(f.node.state.lock().kernel_lookups, 1);
	assert_eq!(f.node.state.lock().post_calls, 0);
	assert!(!f.swap.state.is_final_state());

	f.confirmations.mwc_redeem_conf = None;
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::SellerPostingRefundSlate);
	assert!(matches!(
		response.action,
		Some(Action::SellerPublishMwcRefundTx)
	));
}

// Accept an InitRedeem while lock confirmations are still insufficient. The
// automatic checks can legitimately return to the original state once, since
// that state initially processed a message rather than the same Check input.
// Expect the adaptor signature to be saved and the swap to wait for more
// confirmations, without reporting a cycle.
#[test]
#[serial]
fn incoming_message_can_return_to_its_initial_state_for_a_check() {
	let mut f = Fixture::new();
	f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_3.json")).unwrap();
	f.node.push_output(f.swap.multisig.commit(&f.secp).unwrap());
	f.confirmations.mwc_lock_conf = Some(1);
	let message = serde_json::from_str(include_str!("../../../swap_test/message_3.json")).unwrap();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let response = fsm
		.process(
			Input::IncomeMessage(message),
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerWaitingForLockConfirmations
	);
	assert!(matches!(
		response.action,
		Some(Action::WaitForLockConfirmations { .. })
	));
	assert!(f.swap.adaptor_signature.is_some());
}

// Submit a valid lock and capture the saved trade before the node is called.
// Reload that record and verify it contains the publication marker and the
// exact transaction sent to the node. Successful submission must then leave
// the running swap waiting for lock confirmations.
#[test]
#[serial]
fn successful_lock_is_persisted_before_submission() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let saved = RefCell::new(None);
	let response = fsm
		.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|swap| {
				assert_eq!(f.node.state.lock().post_calls, 0);
				assert!(swap.posted_lock.is_some());
				*saved.borrow_mut() = Some(serde_json::to_string(swap).unwrap());
				Ok(())
			},
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerWaitingForLockConfirmations
	);
	assert_eq!(f.node.state.lock().pending.len(), 1);
	let restored: Swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
	assert_eq!(restored.state, StateId::SellerPostingLockMwcSlate);
	assert_eq!(restored.posted_lock, f.swap.posted_lock);
	assert_eq!(
		serde_json::to_value(restored.lock_slate.slate.tx_or_err().unwrap()).unwrap(),
		serde_json::to_value(&f.node.state.lock().pending[0]).unwrap()
	);
}

// Import the record saved before broadcasting, while its lock is still in the
// mempool. Both a successful submission and a lost acknowledgement must keep
// recovery active until that lock can be refunded. An earlier backup without
// the publication marker must be rejected without replacing the saved record.
#[test]
#[serial]
fn import_pending_seller_lock_remains_refundable() {
	for lost_response in [false, true] {
		let mut f = Fixture::new();
		f.swap
			.record_processed_incoming_message(1, "accepted-offer-before-backup".to_string())
			.unwrap();
		let stale_backup = f.swap.clone();
		let api = f.api();
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let saved = RefCell::new(None);
		f.node.state.lock().post_error_after_accept = lost_response;
		let result = fsm.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|swap| {
				*saved.borrow_mut() = Some(serde_json::to_string(swap).unwrap());
				Ok(())
			},
		);
		if lost_response {
			assert!(result
				.unwrap_err()
				.to_string()
				.contains("Submission response lost"));
		} else {
			result.unwrap();
		}
		assert_eq!(f.node.state.lock().pending.len(), 1);
		f.swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
		let posted_lock = f.swap.posted_lock;
		assert!(posted_lock.is_some());
		let confirmations = api
			.request_tx_confirmations(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert_eq!(confirmations.mwc_lock_conf, None);
		f.swap = rejected_import_leaves_live_record(
			&f.secp,
			&f.context,
			&f.swap,
			stale_backup,
			"lock exposure",
		);
		trades::trades_clean_context(0);

		// Import and reload twice to exercise the durable state used after restart.
		for _ in 0..2 {
			recover_imported_trade_state(&f.secp, &f.keychain, &f.context, &mut f.swap, &api)
				.unwrap();
			f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
			assert_eq!(f.swap.state, StateId::SellerWaitingForRefundHeight);
			assert_eq!(f.swap.posted_lock, posted_lock);
			assert!(!f.swap.state.is_final_state());
		}
		assert_eq!(f.node.state.lock().post_calls, 1);

		// The previously pending lock confirms after import. At the refund height,
		// the recovered state must publish and confirm the actual refund transaction.
		f.node.state.lock().post_error_after_accept = false;
		let refund_height = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
		let current_height = f.node.state.lock().height;
		f.node.mine_blocks(refund_height + 1 - current_height);
		let confirmations = api
			.request_tx_confirmations(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert!(confirmations.mwc_lock_conf.is_some());
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert!(matches!(
			response.action,
			Some(Action::SellerPublishMwcRefundTx)
		));
		fsm.process(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&confirmations,
			&mut f.secp,
		)
		.unwrap();
		f.node.mine_blocks(f.swap.mwc_confirmations + 1);
		let confirmations = api
			.request_tx_confirmations(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert!(confirmations.mwc_refund_conf.unwrap() >= f.swap.mwc_confirmations);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::SellerCancelledRefunded);
	}
}

#[test]
#[serial]
fn import_signed_seller_lock_without_publication_evidence_is_rejected() {
	let mut f = Fixture::new();
	let api = f.api();
	let error = recover_imported_trade_state(&f.secp, &f.keychain, &f.context, &mut f.swap, &api)
		.unwrap_err();
	assert!(error.to_string().contains("publication is unknown"));
	assert_eq!(f.swap.state, StateId::SellerPostingLockMwcSlate);
	assert!(f.swap.posted_lock.is_none());
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// The node accepts the lock but loses its response. Reload only the record
// saved before submission to simulate a restart. Cancellation and timeout
// must both wait for a refund rather than ending the swap. After mining the
// lock and reaching its refund height, publish and confirm the refund; expect
// SellerCancelledRefunded even though the original lock submission errored.
#[test]
#[serial]
fn lost_lock_response_remains_refundable_after_restart() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let saved = RefCell::new(None);
	f.node.state.lock().post_error_after_accept = true;
	let result = fsm.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|swap| {
			assert_eq!(f.node.state.lock().post_calls, 0);
			assert!(swap.posted_lock.is_some());
			*saved.borrow_mut() = Some(serde_json::to_string(swap).unwrap());
			Ok(())
		},
	);
	assert!(
		result
			.unwrap_err()
			.to_string()
			.contains("Submission response lost")
	);
	assert_eq!(f.node.state.lock().pending.len(), 1);
	assert!(f.swap.posted_lock.is_some());
	f.swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
	fsm = api.get_fsm(&f.keychain, &f.swap);
	let response = fsm
		.process(
			Input::Cancel,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerWaitingForRefundHeight
	);

	// Timeout must also preserve the refund path while the lock is still pending.
	swap::set_testing_cur_time(f.swap.get_time_start_lock().unwrap() + 1);
	for input in [Input::Check, Input::Execute] {
		let mut restored: Swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
		let mut restored_fsm = api.get_fsm(&f.keychain, &restored);
		let response = restored_fsm
			.process(
				input,
				&mut restored,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::SellerWaitingForRefundHeight
		);
	}
	assert_eq!(f.node.state.lock().post_calls, 1);

	f.node.mine_block();
	f.node.state.lock().height = f.swap.refund_slate.slate.get_lock_height_check().unwrap() + 1;
	f.node.state.lock().post_error_after_accept = false;
	f.confirmations.mwc_tip = f.node.state.lock().height;
	f.confirmations.mwc_lock_conf = Some(f.swap.mwc_confirmations);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::SellerPublishMwcRefundTx)
	));
	fsm.process(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
	)
	.unwrap();
	f.node.mine_blocks(f.swap.mwc_confirmations + 1);
	f.confirmations.mwc_tip = f.node.state.lock().height;
	f.confirmations.mwc_refund_conf = Some(f.swap.mwc_confirmations + 1);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::SellerCancelledRefunded);
}

// Start with no local publication marker, but a confirmation snapshot that
// already sees the lock. Cancelling must remember that exposure and wait for
// the refund height without submitting another transaction.
#[test]
#[serial]
fn observed_lock_without_local_submission_marker_requires_refund() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	f.confirmations.mwc_lock_conf = Some(1);
	let response = fsm
		.process(
			Input::Cancel,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::SellerWaitingForRefundHeight
	);
	assert!(f.swap.posted_lock.is_some());
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// Start each branch with a lock that was neither submitted nor observed.
// Cancel explicitly, or let its deadline expire before Check or Execute.
// Every branch must finish as SellerCancelled without saving a publication
// marker or broadcasting, since no locked funds need recovery.
#[test]
#[serial]
fn unpublished_lock_can_cancel_or_expire_without_refund() {
	let mut f = Fixture::new();
	let api = f.api();
	for input in [Input::Cancel, Input::Check, Input::Execute] {
		let mut swap = f.swap.clone();
		let mut fsm = api.get_fsm(&f.keychain, &swap);
		if !matches!(input, Input::Cancel) {
			swap::set_testing_cur_time(swap.get_time_start_lock().unwrap() + 1);
		}
		let response = fsm
			.process_with_persist(
				input,
				&mut swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
				&|_| panic!("An unpublished cancellation must not reach persistence"),
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::SellerCancelled);
		assert!(swap.posted_lock.is_none());
	}
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// Fail saving the trade during both a first submission and a retry of an
// earlier submission. The save error must reach the caller and prevent all
// node submissions. Restore the previous marker so the first attempt creates
// no exposure, while a retry retains the earlier attempt's refund protection.
#[test]
#[serial]
fn lock_persistence_failure_prevents_broadcast_and_preserves_prior_marker() {
	let mut f = Fixture::new();
	let api = f.api();
	for previous in [None, Some(swap::get_cur_time() - 1)] {
		f.swap.posted_lock = previous;
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let result = fsm.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|swap| {
				assert!(swap.posted_lock.is_some());
				Err(Error::Generic("Persistence failed".into()))
			},
		);
		assert!(matches!(result, Err(Error::Generic(message)) if message == "Persistence failed"));
		assert_eq!(f.swap.posted_lock, previous);
		assert_eq!(f.node.state.lock().post_calls, 0);
		assert!(f.node.state.lock().pending.is_empty());
	}
}

// Replace the lock's kernel signature with an invalid one, then try to
// execute it. Validation must return an error before saving or submitting
// anything, leaving the publication marker unset.
#[test]
#[serial]
fn invalid_lock_does_not_record_publication() {
	let mut f = Fixture::new();
	f.swap
		.lock_slate
		.slate
		.tx_or_err_mut()
		.unwrap()
		.body
		.kernels[0]
		.excess_sig = AggSigSignature::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let result = fsm.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|_| panic!("An invalid lock must not reach persistence"),
	);
	assert!(result.is_err());
	assert!(f.swap.posted_lock.is_none());
	assert_eq!(f.node.state.lock().post_calls, 0);
}

#[test]
#[serial]
fn refund_preflight_requires_the_negotiated_parent() {
	let mut f = Fixture::new();
	f.swap
		.validate_lock_and_refund_slates(0, &f.node, &f.secp)
		.unwrap();
	let foreign_parent = f.secp.commit_value(123).unwrap();
	f.swap
		.refund_slate
		.slate
		.tx_or_err_mut()
		.unwrap()
		.body
		.inputs = mwc_wallet_util::mwc_core::core::Inputs::CommitOnly(vec![foreign_parent.into()]);
	let calls = f.node.state.lock().preflight_calls;
	assert!(f
		.swap
		.validate_lock_and_refund_slates(0, &f.node, &f.secp)
		.is_err());
	assert_eq!(f.node.state.lock().preflight_calls, calls);
}

#[test]
#[serial]
fn preflight_accepts_an_ancestor_and_rejects_a_removed_anchor() {
	let f = Fixture::new();
	let transaction = f
		.swap
		.lock_slate
		.slate
		.node_preflight_transaction(0, &f.secp, true)
		.unwrap();
	let mut request = crate::transaction_preflight::MempoolAcceptRequest::single(transaction);
	let checked = crate::transaction_preflight::check_request(&f.node, &request).unwrap();
	request.expected_tip = Some(checked.checked_tip);
	f.node.mine_block();
	let refreshed = crate::transaction_preflight::check_request(&f.node, &request).unwrap();
	assert_eq!(refreshed.checked_height, checked.checked_height + 1);
	assert_ne!(refreshed.checked_tip, checked.checked_tip);
	f.node.state.lock().height = checked.checked_height - 1;
	let error = crate::transaction_preflight::check_request(&f.node, &request).unwrap_err();
	assert!(error.to_string().contains("tip"));
}

#[test]
#[serial]
fn related_preflight_returns_positive_results_in_one_snapshot() {
	let f = Fixture::new();
	f.node
		.state
		.lock()
		.preflight_chain_updates
		.insert(1, (300_001, None));
	let lock = f
		.swap
		.lock_slate
		.slate
		.node_preflight_transaction(0, &f.secp, true)
		.unwrap();
	let refund = f.swap.refund_preflight_transaction(0, &f.secp).unwrap();
	let request = crate::transaction_preflight::MempoolAcceptRequest {
		transactions: vec![lock, refund],
		expected_tip: None,
	};
	let checked = crate::transaction_preflight::check_request(&f.node, &request).unwrap();
	assert!(checked.checks_passed);
	assert_eq!(checked.transactions.len(), 2);
	assert!(checked
		.transactions
		.iter()
		.all(|r| r.checks_passed && r.balance_checked && r.failures.is_empty()));
	assert_eq!(checked.checked_height, 300_001);
	assert_eq!(
		checked.transactions[1].valid_from_height,
		f.swap.refund_slate.slate.get_lock_height_check().unwrap()
	);
	assert_eq!(f.node.state.lock().preflight_calls, 1);
	assert_eq!(f.node.state.lock().post_calls, 0);

	// Future-height permission never permits a failed verdict from the node.
	for check in ["height", "input_missing"] {
		let mut rejected = checked.clone();
		rejected.transactions[1].reject(check, "rejected child".into());
		let rejected = rejected.finish();
		assert!(crate::transaction_preflight::require_preflight(&request, &rejected).is_err());
	}
	let mut missing_child = checked.clone();
	missing_child.transactions.pop();
	assert!(crate::transaction_preflight::require_preflight(&request, &missing_child).is_err());
}

#[test]
#[serial]
fn lock_publication_checks_both_transactions_before_exposure_in_one_call() {
	let mut f = Fixture::new();
	f.node
		.state
		.lock()
		.preflight_chain_updates
		.insert(1, (300_010, None));
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	fsm.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|swap| {
			assert!(swap.posted_lock.is_some());
			assert_eq!(f.node.state.lock().preflight_calls, 1);
			assert_eq!(f.node.state.lock().post_calls, 0);
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(f.node.state.lock().preflight_calls, 1);
	assert_eq!(f.node.state.lock().post_calls, 1);
}

#[test]
#[serial]
fn related_preflight_rechecks_funding_after_a_chain_change_before_publication() {
	for height in [300_001, 299_999] {
		let mut f = Fixture::new();
		let input = f
			.swap
			.lock_slate
			.slate
			.tx_or_err()
			.unwrap()
			.inputs_committed()
			.unwrap()
			.next()
			.unwrap()
			.unwrap();
		f.node
			.state
			.lock()
			.preflight_chain_updates
			.insert(1, (height, Some(input)));
		let api = f.api();
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		let result = fsm.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|_| panic!("Failed related checks must not reach persistence"),
		);
		let error = result.unwrap_err().to_string();
		assert!(error.contains("input_missing"), "{}", error);
		assert!(f.swap.posted_lock.is_none());
		assert_eq!(f.node.state.lock().post_calls, 0);
		assert_eq!(f.node.state.lock().preflight_calls, 1);
	}
}
#[test]
#[serial]
fn accepted_offer_rejects_invalid_node_state_before_accepting_slates() {
	for failure in ["input_missing", "outputs", "node unavailable"] {
		let mut f = Fixture::new();
		f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_1.json")).unwrap();
		let message =
			Message::from_json(include_str!("../../../swap_test/message_2.json")).unwrap();
		let (_, update, _) = message.unwrap_accept_offer().unwrap();
		let before = serde_json::to_value(&f.swap).unwrap();
		let outputs = f.node.state.lock().outputs.clone();
		match failure {
			"input_missing" => f.node.state.lock().outputs.clear(),
			"outputs" => f.node.push_output(
				f.swap.refund_slate.slate.tx_or_err().unwrap().outputs()[0].commitment(),
			),
			_ => f.node.state.lock().preflight_error = Some(failure.into()),
		}
		let error = SellApi::accepted_offer(
			0,
			&mut f.secp,
			&f.keychain,
			&mut f.swap,
			&f.context,
			update.clone(),
			&f.node,
		)
		.unwrap_err();
		assert!(error.to_string().contains(failure), "{error}");
		assert_eq!(serde_json::to_value(&f.swap).unwrap(), before);
		assert_eq!(f.node.state.lock().post_calls, 0);

		f.node.state.lock().outputs = outputs;
		f.node.state.lock().preflight_error = None;
		SellApi::accepted_offer(
			0,
			&mut f.secp,
			&f.keychain,
			&mut f.swap,
			&f.context,
			update,
			&f.node,
		)
		.unwrap();
		assert!(f.swap.redeem_public.is_some());
	}
}

#[test]
#[serial]
fn incoming_redeem_rejects_invalid_node_state_before_accepting_signature() {
	for failure in ["input_missing", "outputs", "node unavailable"] {
		let mut f = Fixture::new();
		f.swap = serde_json::from_str(include_str!("../../../swap_test/swap_sell_3.json")).unwrap();
		f.node.push_output(f.swap.multisig.commit(&f.secp).unwrap());
		let message =
			Message::from_json(include_str!("../../../swap_test/message_3.json")).unwrap();
		let (_, update, _) = message.unwrap_init_redeem().unwrap();
		let before = serde_json::to_value(&f.swap).unwrap();
		let outputs = f.node.state.lock().outputs.clone();
		match failure {
			"input_missing" => f.node.state.lock().outputs.clear(),
			"outputs" => {
				let slate = update
					.redeem_slate
					.clone()
					.into_slate_plain(0, true)
					.unwrap();
				f.node
					.push_output(slate.tx_or_err().unwrap().outputs()[0].commitment());
			}
			_ => f.node.state.lock().preflight_error = Some(failure.into()),
		}
		let error = SellApi::init_redeem(
			0,
			&mut f.secp,
			&f.keychain,
			&mut f.swap,
			&f.context,
			update.clone(),
			&f.node,
		)
		.unwrap_err();
		assert!(error.to_string().contains(failure), "{error}");
		assert_eq!(serde_json::to_value(&f.swap).unwrap(), before);
		assert_eq!(f.node.state.lock().post_calls, 0);

		f.node.state.lock().outputs = outputs;
		f.node.state.lock().preflight_error = None;
		SellApi::init_redeem(
			0,
			&mut f.secp,
			&f.keychain,
			&mut f.swap,
			&f.context,
			update,
			&f.node,
		)
		.unwrap();
		assert!(f.swap.adaptor_signature.is_some());
	}
}

#[test]
#[serial]
fn conflicting_refund_output_prevents_lock_exposure_and_submission() {
	let mut f = Fixture::new();
	let conflict = f.swap.refund_slate.slate.tx_or_err().unwrap().outputs()[0].commitment();
	f.node.push_output(conflict);
	let api = f.api();
	let mut machine = api.get_fsm(&f.keychain, &f.swap);
	let result = machine.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|_| panic!("Unsafe refund must prevent lock exposure"),
	);
	assert!(result.is_err());
	assert!(f.swap.posted_lock.is_none());
	assert_eq!(f.node.state.lock().post_calls, 0);
}
