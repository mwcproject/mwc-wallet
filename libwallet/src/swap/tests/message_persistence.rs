//! Preserve the buyer's signing transcript across failed delivery and restart.

use super::*;
use crate::swap::owner_swap::{commit_swap_on_success, send_swap_message};
use std::cell::{Cell, RefCell};

struct Fixture {
	node: TestNodeClient,
	secp: Secp256k1,
	swap: Swap,
	keychain: ExtKeychain,
	context: Context,
	confirmations: SwapTransactionsConfirmations,
}

impl Fixture {
	fn new() -> Self {
		// Use production randomness so rebuilding the slate would change its offset.
		set_test_mode(false);
		global::set_local_chain_type(ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = keychain(&secp, 2);
		let context = context_buy(&secp, &keychain);
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_buy_1.json")).unwrap();
		swap.set_swap_trade_transport("file".into(), "buyer-init-redeem.json".into())
			.unwrap();
		swap::set_testing_cur_time(swap.started.timestamp());
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
		let node = TestNodeClient::new(300_000);
		node.push_output(swap.multisig.commit(&secp).unwrap());
		Self {
			node,
			secp,
			swap,
			keychain,
			context,
			confirmations,
		}
	}

	fn try_check(&mut self) -> Result<Action, Error> {
		let api = BtcSwapApi::new_test(
			Arc::new(self.node.clone()),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);
		let mut fsm = api.get_fsm(&self.keychain, &self.swap);
		let response = commit_swap_on_success(&mut self.swap, |swap| {
			fsm.process(
				Input::Check,
				swap,
				&self.context,
				&self.confirmations,
				&mut self.secp,
			)
		})?;
		let action = response.action.unwrap();
		assert!(matches!(action, Action::BuyerSendInitRedeemMessage(_)));
		Ok(action)
	}

	fn check(&mut self) -> Action {
		self.try_check().unwrap()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
		set_test_mode(true);
	}
}

#[test]
#[serial]
fn buyer_init_redeem_reuses_persisted_message_after_delivery_error_and_restart() {
	let mut f = Fixture::new();
	assert!(f.swap.adaptor_signature.is_none());
	let action = f.check();
	let expected = serde_json::to_value(BuyApi::init_redeem_message(0, &f.swap).unwrap()).unwrap();
	let saved = RefCell::new(None::<String>);
	let result = send_swap_message(
		&f.swap,
		&action,
		&f.secp,
		|message, method, destination, _| {
			assert_eq!(method, "file");
			assert_eq!(destination, "buyer-init-redeem.json");
			// Delivery can succeed before an acknowledgement is lost. Its exact
			// signing transcript must already be recoverable at this boundary.
			let restored: Swap =
				serde_json::from_str(saved.borrow().as_ref().expect("save before send")).unwrap();
			assert_eq!(serde_json::to_value(&message).unwrap(), expected);
			assert_eq!(
				serde_json::to_value(BuyApi::init_redeem_message(0, &restored).unwrap()).unwrap(),
				expected
			);
			Err(Error::Generic("Acknowledgement lost".into()))
		},
		&|swap| {
			*saved.borrow_mut() = Some(serde_json::to_string(swap).unwrap());
			Ok(())
		},
	);
	assert!(matches!(result, Err(Error::Generic(message)) if message == "Acknowledgement lost"));

	// Lose all subsequent in-memory changes, as if the process stopped before
	// Execute or the final save. A fresh FSM must resend the original transcript.
	f.swap = serde_json::from_str(saved.borrow().as_ref().unwrap()).unwrap();
	assert_eq!(f.swap.state, StateId::BuyerSendingInitRedeemMessage);
	assert!(f.swap.message2.is_none());
	assert!(f.swap.posted_msg2.is_none());
	let checks = f.node.state.lock().preflight_calls;
	let retry = f.check();
	assert_eq!(f.node.state.lock().preflight_calls, checks);
	let result = send_swap_message(
		&f.swap,
		&retry,
		&f.secp,
		|message, _, destination, _| {
			assert_eq!(serde_json::to_value(message).unwrap(), expected);
			Ok((true, destination))
		},
		&|_| Ok(()),
	)
	.unwrap();
	assert!(result.0);
}

#[test]
#[serial]
fn buyer_init_redeem_persistence_failure_prevents_delivery() {
	let mut f = Fixture::new();
	let action = f.check();
	let sent = Cell::new(false);
	let result = send_swap_message(
		&f.swap,
		&action,
		&f.secp,
		|_, _, destination, _| {
			sent.set(true);
			Ok((true, destination))
		},
		&|swap| {
			assert!(swap.adaptor_signature.is_some());
			assert_eq!(swap.redeem_slate.slate.participant_data.len(), 2);
			Err(Error::Generic("Persistence failed".into()))
		},
	);
	assert!(matches!(result, Err(Error::Generic(message)) if message == "Persistence failed"));
	assert!(!sent.get());
	assert!(f.swap.posted_msg2.is_none());
}

#[test]
#[serial]
fn rejected_redeem_is_not_accepted_or_returned_as_a_message() {
	let mut f = Fixture::new();
	let before = serde_json::to_value(&f.swap).unwrap();
	f.node.state.lock().outputs.clear();
	let result = f.try_check();
	assert!(result.unwrap_err().to_string().contains("input_missing"));
	assert_eq!(serde_json::to_value(&f.swap).unwrap(), before);
	assert_eq!(f.node.state.lock().preflight_calls, 1);
	assert_eq!(f.node.state.lock().post_calls, 0);
}
