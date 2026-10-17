//! Regression tests for publishing and recovering the buyer's MWC redemption.
//! Tests control time, mock node state, and confirmation observations separately.
//! JSON round trips simulate restoring the saved trade after a restart.

use super::*;
use crate::swap::fsm::buyer_swap::{prepare_mwc_redeem, BuyerRedeemMwc};
use crate::swap::fsm::state::{State, POST_MWC_RETRY_PERIOD};
use std::cell::{Cell, RefCell};

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
		let keychain = keychain(&secp, 2);
		let context = context_buy(&secp, &keychain);
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_buy_3.json")).unwrap();
		// Reuse the fully signed transaction at the point before its first post.
		swap.state = StateId::BuyerRedeemMwc;
		swap.posted_redeem = None;
		swap::set_testing_cur_time(swap.started.timestamp());
		let node = TestNodeClient::new(300_000);
		for input in swap
			.redeem_slate
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
			mwc_lock_conf: Some(swap.mwc_confirmations),
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

// Start with a signed redeem that has never been submitted. Cancel one copy,
// then let another reach its deadline and try both Check and Execute. Each path
// must wait for a secondary refund without recording exposure or sending MWC.
#[test]
#[serial]
fn cancellation_and_timeout_remain_available_before_redeem_exposure() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	assert!(fsm.is_cancellable(&f.swap).unwrap());
	let mut cancelled = f.swap.clone();
	let response = fsm
		.process(
			Input::Cancel,
			&mut cancelled,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
	assert!(cancelled.posted_redeem.is_none());

	swap::set_testing_cur_time(f.swap.get_time_mwc_redeem().unwrap() + 1);
	let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
	for input in [Input::Check, Input::Execute] {
		let response = state
			.process(
				input,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
		assert!(f.swap.posted_redeem.is_none());
	}
	assert!(f.node.state.lock().pending.is_empty());
}

// Publish and mine the redeem, then rewind the node and restore the saved trade.
// Advance past the deadline and report that the secondary lock has been spent.
// Cancellation must remain blocked; retrying MWC must still be possible and
// complete the swap once the redeem reaches the required confirmations.
#[test]
#[serial]
fn cancellation_stays_blocked_after_redeem_reorg_and_reload() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let chain_before_redeem = f.node.get_state();
	fsm.process(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
	)
	.unwrap();
	assert_eq!(f.node.state.lock().pending.len(), 1);
	assert!(!fsm.is_cancellable(&f.swap).unwrap());
	f.node.mine_block();
	f.confirmations.mwc_redeem_conf = Some(1);
	fsm.process(
		Input::Check,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
	)
	.unwrap();

	// Reorg away the redemption, then restart from the persisted trade. The
	// seller can retain the secret even when its secondary lock is now spent.
	f.node.set_state(&chain_before_redeem);
	f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
	fsm = api.get_fsm(&f.keychain, &f.swap);
	f.confirmations.mwc_redeem_conf = None;
	f.confirmations.mwc_lock_conf = Some(0);
	f.confirmations.secondary_lock_conf = None;
	f.confirmations.secondary_lock_amount = 0;
	f.confirmations.secondary_redeem_conf = Some(1);
	swap::set_testing_cur_time(f.swap.get_time_mwc_redeem().unwrap() + 1);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerRedeemMwc);
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishMwcRedeemTx)
	));
	assert_eq!(response.time_limit, None);
	assert!(!fsm.is_cancellable(&f.swap).unwrap());
	let before_cancel = serde_json::to_value(&f.swap).unwrap();
	assert!(fsm
		.process(
			Input::Cancel,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp
		)
		.is_err());
	let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
	assert!(!state.is_cancellable(&f.swap));
	assert!(state
		.process(
			Input::Cancel,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp
		)
		.is_err());
	assert_eq!(serde_json::to_value(&f.swap).unwrap(), before_cancel);
	assert_eq!(state.get_eta(&f.swap, &f.secp).unwrap().end_time, None);

	// The original deadline and missing lock confirmations must not prevent
	// recovery of an already exposed transaction.
	fsm.process(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
	)
	.unwrap();
	assert_eq!(f.node.state.lock().pending.len(), 1);
	f.node.mine_blocks(f.swap.mwc_confirmations);
	f.confirmations.mwc_redeem_conf = Some(f.swap.mwc_confirmations);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerSwapComplete);
}

// Let the node accept the redeem but return an error, then restore the record
// saved before that network call. Cancellation must remain blocked, and retry
// throttling must prevent another immediate submission. After the transaction
// disappears, recovery must persist once and resend the same signed transaction.
#[test]
#[serial]
fn lost_redeem_submission_response_does_not_enable_cancellation() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let chain_before_post = f.node.get_state();
	let saved = RefCell::new(None);
	f.node.state.lock().post_error_after_accept = true;
	assert!(fsm
		.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|swap| {
				assert_eq!(f.node.state.lock().post_calls, 0);
				assert!(swap.posted_redeem.is_some());
				*saved.borrow_mut() = Some(serde_json::to_string(swap).unwrap());
				Ok(())
			}
		)
		.is_err());
	assert_eq!(f.node.state.lock().pending.len(), 1);
	assert_eq!(f.swap.state, StateId::BuyerRedeemMwc);
	assert!(f.swap.posted_redeem.is_some());
	let submitted = f.node.state.lock().pending[0].clone();
	// Reload exactly the record saved before the lost RPC response.
	f.swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
	assert!(!fsm.is_cancellable(&f.swap).unwrap());
	assert!(fsm
		.process(
			Input::Cancel,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp
		)
		.is_err());
	// At the retry-period boundary, Execute must still wait without contacting
	// the node again or moving the timestamp forward and delaying later recovery.
	let posted_at = f.swap.posted_redeem.unwrap();
	swap::set_testing_cur_time(posted_at + POST_MWC_RETRY_PERIOD);
	let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
	let response = state
		.process(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::BuyerWaitForRedeemMwcConfirmations
	);
	assert_eq!(f.node.state.lock().post_calls, 1);
	assert_eq!(f.swap.posted_redeem, Some(posted_at));

	// The transaction disappears, but its revealed signature must be recovered
	// even after the deadline and after the secondary lock has been spent.
	f.node.set_state(&chain_before_post);
	f.confirmations.secondary_lock_amount = 0;
	f.confirmations.secondary_lock_conf = None;
	swap::set_testing_cur_time(f.swap.get_time_mwc_redeem().unwrap() + 1);
	let persistence_calls = Cell::new(0);
	fsm.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|_| {
			persistence_calls.set(persistence_calls.get() + 1);
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(persistence_calls.get(), 1);
	assert_eq!(f.node.state.lock().post_calls, 1);
	let node_state = f.node.state.lock();
	assert_eq!(node_state.pending.len(), 1);
	assert_eq!(
		serde_json::to_value(&node_state.pending[0]).unwrap(),
		serde_json::to_value(&submitted).unwrap(),
	);
}

// Prepare the redeem and capture the saved trade before any broadcast occurs.
// Restoring that record must conservatively treat the signature as exposed and
// forbid cancellation. A later preparation that cannot be saved must return its
// persistence error without submitting a transaction.
#[test]
#[serial]
fn redeem_exposure_is_saved_before_broadcast_and_survives_restart() {
	let mut f = Fixture::new();
	let mut saved = None;
	let (response, _receipt) = prepare_mwc_redeem(
		0,
		&f.node,
		&mut f.swap,
		&f.confirmations,
		&mut f.secp,
		|swap| {
			assert!(swap.posted_redeem.is_some());
			assert!(f.node.state.lock().pending.is_empty());
			saved = Some(serde_json::to_string(swap).unwrap());
			Ok(())
		},
	)
	.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishMwcRedeemTx)
	));
	// Simulate restarting before any post-broadcast state update was saved.
	f.swap = serde_json::from_str(&saved.unwrap()).unwrap();
	let api = f.api();
	let fsm = api.get_fsm(&f.keychain, &f.swap);
	assert!(!fsm.is_cancellable(&f.swap).unwrap());

	// Pass the retry delay so the next attempt actually reaches persistence.
	swap::set_testing_cur_time(swap::get_cur_time() + 301);
	let result = prepare_mwc_redeem(0, &f.node, &mut f.swap, &f.confirmations, &mut f.secp, |_| {
		Err(Error::Generic("Persistence failed".to_string()))
	});
	assert!(matches!(result, Err(Error::Generic(message)) if message == "Persistence failed"));
	assert!(f.node.state.lock().pending.is_empty());
}

// Remove the transaction from the redeem slate before preparation. Validation
// must fail before invoking persistence, recording exposure, or sending to MWC.
#[test]
#[serial]
fn invalid_redeem_transaction_does_not_record_exposure() {
	let mut f = Fixture::new();
	f.swap.redeem_slate.slate.tx = None;
	assert!(
		prepare_mwc_redeem(0, &f.node, &mut f.swap, &f.confirmations, &mut f.secp, |_| {
			panic!("Invalid transaction must not reach persistence")
		})
		.is_err()
	);
	assert!(f.swap.posted_redeem.is_none());
	assert!(f.node.state.lock().pending.is_empty());
}

// Leave the local submission timestamp unset but report a known redeem, first
// unconfirmed and then mined. Either observation must reject Cancel; a later
// Check must also record exposure so cancellation stays blocked locally.
#[test]
#[serial]
fn observed_redeem_blocks_cancellation_without_a_local_post_timestamp() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	for conf in [0, 1] {
		f.confirmations.mwc_redeem_conf = Some(conf);
		assert!(fsm
			.process(
				Input::Cancel,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp
			)
			.is_err());
	}
	fsm.process(
		Input::Check,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
	)
	.unwrap();
	assert!(f.swap.posted_redeem.is_some());
	assert!(!fsm.is_cancellable(&f.swap).unwrap());
}

// Keep the deadline and lock confirmations valid while moving the MWC tip to a
// safe height, the exact confirmation-window cutoff, and the refund unlock height.
// Only the safe case may save exposure and broadcast once. At either boundary,
// both Check and Execute must select the secondary refund path without exposure.
#[test]
#[serial]
fn first_redeem_reserves_confirmation_blocks_before_refund_unlock() {
	for remaining_margin in [1, 0, -1] {
		let mut f = Fixture::new();
		let refund_height = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
		f.confirmations.mwc_tip = match remaining_margin {
			1 => refund_height - f.swap.mwc_confirmations - 1,
			0 => refund_height - f.swap.mwc_confirmations,
			_ => refund_height,
		};
		let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
		let expected = if remaining_margin > 0 {
			StateId::BuyerRedeemMwc
		} else {
			StateId::BuyerWaitingForRefundTime
		};
		let response = state
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, expected);
		let persisted = Cell::new(false);
		state
			.process_with_persist(
				Input::Execute,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
				&|_| {
					persisted.set(true);
					Ok(())
				},
			)
			.unwrap();
		assert_eq!(persisted.get(), remaining_margin > 0);
		assert_eq!(f.swap.posted_redeem.is_some(), remaining_margin > 0);
		assert_eq!(
			f.node.state.lock().post_calls,
			usize::from(remaining_margin > 0)
		);
	}
}

// Check initially offers publication, then Execute receives a newer tip at the
// refund height. Execute must withdraw that action before persistence or sending.
// Also supply a tip whose confirmation-window addition overflows: both inputs
// must return DataOverflow and leave the signature unexposed.
#[test]
#[serial]
fn first_redeem_rechecks_height_at_execution_and_rejects_overflow() {
	let mut f = Fixture::new();
	let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
	let response = state
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
		Some(Action::BuyerPublishMwcRedeemTx)
	));
	f.confirmations.mwc_tip = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
	let response = state
		.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|_| panic!("An unsafe first publication must not reach persistence"),
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
	f.confirmations.mwc_tip = u64::MAX;
	for input in [Input::Check, Input::Execute] {
		assert!(matches!(
			state.process(
				input,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			),
			Err(Error::DataOverflow(_))
		));
	}
	assert!(f.swap.posted_redeem.is_none());
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// Fail the persistence callback during the first publication attempt. The FSM
// must propagate the error, make zero node submissions, and restore the unset
// exposure marker. Advancing to the refund height must then block the next
// attempt under the first-publication rules.
#[test]
#[serial]
fn persistence_failure_prevents_redeem_broadcast() {
	let mut f = Fixture::new();
	let api = f.api();
	let mut fsm = api.get_fsm(&f.keychain, &f.swap);
	let response = fsm.process_with_persist(
		Input::Execute,
		&mut f.swap,
		&f.context,
		&f.confirmations,
		&mut f.secp,
		&|swap| {
			assert!(swap.posted_redeem.is_some());
			Err(Error::Generic("Persistence failed".to_string()))
		},
	);
	assert!(matches!(response, Err(Error::Generic(message)) if message == "Persistence failed"));
	assert_eq!(f.node.state.lock().post_calls, 0);
	assert!(f.swap.posted_redeem.is_none());
	// A known failure before sending must not bypass the first-publication
	// height check on the next attempt.
	f.confirmations.mwc_tip = f.swap.refund_slate.slate.get_lock_height_check().unwrap();
	let response = fsm
		.process_with_persist(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
			&|_| panic!("First-publication safety checks must still apply"),
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// From each redeem state, report prior exposure and a competing MWC refund one
// confirmation short of the required count. The buyer must pause broadcasts and
// reject cancellation. Restore the trade, remove the refund observation as in a
// reorg, and expect redemption to resume despite the expired deadline and empty
// secondary lock; success requires the full MWC confirmation count.
#[test]
#[serial]
fn pending_mwc_refund_suspends_redeem_and_reorg_resumes_recovery() {
	for initial_state in [
		StateId::BuyerRedeemMwc,
		StateId::BuyerWaitForRedeemMwcConfirmations,
	] {
		let mut f = Fixture::new();
		f.swap.state = initial_state;
		f.swap.posted_redeem = Some(swap::get_cur_time());
		swap::set_testing_cur_time(f.swap.get_time_mwc_redeem().unwrap() + 1);
		f.confirmations.mwc_refund_conf = Some(f.swap.mwc_confirmations - 1);
		f.confirmations.secondary_lock_conf = None;
		f.confirmations.secondary_lock_amount = 0;
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
			StateId::BuyerWaitingForMwcRefundConfirmations
		);
		assert!(!fsm.is_cancellable(&f.swap).unwrap());
		assert!(!fsm.get_swap_roadmap(&f.swap, &f.secp).unwrap().is_empty());
		fsm.process(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
		assert_eq!(f.node.state.lock().post_calls, 0);

		// The saved waiting state must retain exposure. Once the competing refund
		// disappears, the next Check should offer recovery of the MWC redeem.
		f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
		f.confirmations.mwc_refund_conf = None;
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
			Some(Action::BuyerPublishMwcRedeemTx)
		));
		fsm.process(
			Input::Execute,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
		assert_eq!(f.node.state.lock().post_calls, 1);
		// One confirmation below the target still waits; reaching it completes.
		f.confirmations.mwc_redeem_conf = Some(f.swap.mwc_confirmations - 1);
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
			StateId::BuyerWaitForRedeemMwcConfirmations
		);
		f.confirmations.mwc_redeem_conf = Some(f.swap.mwc_confirmations);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerSwapComplete);
	}
}

// Confirm the seller's MWC refund after exposure and report an empty secondary
// lock. Unknown, unconfirmed, or insufficiently confirmed secondary redemption
// must leave the outcome unresolved across reloads, with zero MWC broadcasts.
// Only a sufficiently confirmed seller redemption establishes the failed swap.
#[test]
#[serial]
fn confirmed_mwc_refund_stops_redeem_without_assuming_missing_funds_are_stolen() {
	for initial_state in [
		StateId::BuyerRedeemMwc,
		StateId::BuyerWaitForRedeemMwcConfirmations,
	] {
		let mut f = Fixture::new();
		f.swap.state = initial_state;
		f.swap.posted_redeem = Some(swap::get_cur_time());
		swap::set_testing_cur_time(f.swap.get_time_secondary_lock_publish().unwrap() + 1);
		f.confirmations.mwc_refund_conf = Some(f.swap.mwc_confirmations);
		f.confirmations.secondary_lock_conf = None;
		f.confirmations.secondary_lock_amount = 0;
		let api = f.api();
		let mut fsm = api.get_fsm(&f.keychain, &f.swap);
		for secondary_conf in [None, Some(0), Some(f.swap.secondary_confirmations - 1)] {
			f.confirmations.secondary_redeem_conf = secondary_conf;
			let response = fsm
				.process(
					Input::Check,
					&mut f.swap,
					&f.context,
					&f.confirmations,
					&mut f.secp,
				)
				.unwrap();
			assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
			assert!(matches!(response.action,
				Some(Action::WaitForSecondaryConfirmations { name, .. }) if name.contains("unresolved")));
			assert!(!f.swap.state.is_final_state());
			assert_eq!(f.node.state.lock().post_calls, 0);
			f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
		}
		f.confirmations.secondary_redeem_conf = Some(f.swap.secondary_confirmations);
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerSwapFailed);
		assert!(f.swap.state.is_final_state());
		assert!(!f.swap.state.is_cancelled_no_refund());
		assert_eq!(
			StateId::from_cmd_str(&f.swap.state.to_cmd_str()).unwrap(),
			f.swap.state
		);
		assert!(fsm
			.process(
				Input::Execute,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp
			)
			.is_err());
		assert_eq!(f.node.state.lock().post_calls, 0);
	}
}

// Confirm the MWC refund while secondary funds remain: wait for their unlock,
// then offer a secondary refund. If that balance disappears during any refund
// state, return to monitoring its unresolved outcome. A subsequently observed,
// sufficiently confirmed buyer refund must finish as BuyerCancelledRefunded,
// without any further MWC submission.
#[test]
#[serial]
fn confirmed_mwc_refund_preserves_secondary_refund_and_checks_later_spending() {
	let mut f = Fixture::new();
	f.swap.posted_redeem = Some(swap::get_cur_time());
	f.confirmations.mwc_refund_conf = Some(f.swap.mwc_confirmations);
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
	assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
	assert!(matches!(
		response.action,
		Some(Action::WaitingForBtcRefund { .. })
	));
	swap::set_testing_cur_time(f.swap.get_time_secondary_lock_publish().unwrap() + 1);
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
		StateId::BuyerPostingRefundForSecondary
	);
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishSecondaryRefundTx { .. })
	));
	let refunding = f.swap.clone();
	f.confirmations.secondary_lock_amount = 0;
	for initial_state in [
		StateId::BuyerWaitingForRefundTime,
		StateId::BuyerPostingRefundForSecondary,
		StateId::BuyerWaitingForRefundConfirmations,
	] {
		f.swap = refunding.clone();
		f.swap.state = initial_state;
		let response = fsm
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&f.confirmations,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
	}
	// A known buyer refund still completes normally, without a false loss report.
	f.confirmations.secondary_refund_conf = Some(f.swap.secondary_confirmations);
	let response = fsm
		.process(
			Input::Check,
			&mut f.swap,
			&f.context,
			&f.confirmations,
			&mut f.secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
	assert_eq!(f.node.state.lock().post_calls, 0);
}

// Before the first redeem, report a competing refund as unconfirmed and then
// mined, while the supplied tip still passes the height guard. Both Check and
// Execute must wait for the refund's outcome, with no exposure or node submission.
#[test]
#[serial]
fn observed_refund_prevents_first_redeem_even_before_height_guard() {
	let mut f = Fixture::new();
	let mut state = BuyerRedeemMwc::new(0, Arc::new(f.node.clone()));
	for conf in [0, 1] {
		f.confirmations.mwc_refund_conf = Some(conf);
		for input in [Input::Check, Input::Execute] {
			let response = state
				.process(
					input,
					&mut f.swap,
					&f.context,
					&f.confirmations,
					&mut f.secp,
				)
				.unwrap();
			assert_eq!(
				response.next_state_id,
				StateId::BuyerWaitingForMwcRefundConfirmations
			);
			assert!(f.swap.posted_redeem.is_none());
		}
	}
	assert_eq!(f.node.state.lock().post_calls, 0);
}

#[test]
#[serial]
fn rejected_node_preflight_does_not_mark_redeem_exposed() {
	let mut f = Fixture::new();
	f.node.state.lock().outputs.clear();
	let result = prepare_mwc_redeem(0, &f.node, &mut f.swap, &f.confirmations, &mut f.secp, |_| {
		panic!("A rejected redeem must not reach exposure persistence")
	});
	assert!(result.is_err());
	assert!(f.swap.posted_redeem.is_none());
	assert_eq!(f.node.state.lock().preflight_calls, 1);
	assert_eq!(f.node.state.lock().post_calls, 0);
}

#[test]
#[serial]
fn post_uses_one_preflight_and_receipt_binds_transaction() {
	let f = Fixture::new();
	let tx = f.swap.redeem_slate.slate.tx_or_err().unwrap();
	let receipt = crate::transaction_preflight::prepare_transaction(0, &f.node, tx).unwrap();
	let mut changed = tx.clone();
	changed.offset = mwc_wallet_util::mwc_keychain::BlindingFactor::zero();
	assert!(f.node.post_tx(&changed, false, receipt).is_err());
	assert_eq!(f.node.state.lock().post_calls, 0);
	let receipt = crate::transaction_preflight::prepare_transaction(0, &f.node, tx).unwrap();
	let cloned = f.node.clone();
	cloned.post_tx(tx, false, receipt).unwrap();
	assert_eq!(f.node.state.lock().preflight_calls, 2);
	assert_eq!(f.node.state.lock().post_calls, 1);

	let f = Fixture::new();
	let tx = f.swap.redeem_slate.slate.tx_or_err().unwrap();
	crate::owner::post_tx(0, &f.node, tx, false).unwrap();
	assert_eq!(f.node.state.lock().preflight_calls, 1);
	assert_eq!(f.node.state.lock().post_calls, 1);
}
