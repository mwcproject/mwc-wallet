//! Bind adaptor signatures to the declared buyer nonce, including its sign.

use super::*;
use crate::swap::fsm::seller_swap::{
	SellerWaitingForInitRedeemMessage, SellerWaitingForLockConfirmations,
};
use crate::swap::fsm::state::State;
use mwc_wallet_util::mwc_crates::secp::aggsig;

fn assert_rejects_adaptor_nonce(negate_nonce: bool) {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	global::set_local_nrd_enabled(true);
	global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let seller_keychain = Arc::new(keychain(&secp, 1));
	let buyer_keychain = keychain(&secp, 2);
	let node = Arc::new(TestNodeClient::new(300_000));
	let api: Arc<Box<dyn SwapApi<ExtKeychain>>> = Arc::new(Box::new(BtcSwapApi::new_test(
		node.clone(),
		Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
	)));

	// Negating both declared nonces flips the aggregate point, exercising both
	// branches of aggsig's Jacobi normalization without changing the transaction.
	for negate_transcript in [false, true] {
		let mut seller_context = context_sell(&secp, &seller_keychain);
		let mut buyer_context = context_buy(&secp, &buyer_keychain);
		if negate_transcript {
			seller_context.redeem_nonce.neg_assign(&secp).unwrap();
			buyer_context.redeem_nonce.neg_assign(&secp).unwrap();
		}
		let mut original: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_sell_3.json")).unwrap();
		let mut buyer: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_buy_2.json")).unwrap();
		node.push_output(original.multisig.commit(&secp).unwrap());
		let seller_nonce = PublicKey::from_secret_key(&secp, &seller_context.redeem_nonce).unwrap();
		let buyer_nonce = PublicKey::from_secret_key(&secp, &buyer_context.redeem_nonce).unwrap();
		for slate in [
			&mut original.redeem_slate.slate,
			&mut buyer.redeem_slate.slate,
		] {
			for participant in &mut slate.participant_data {
				participant.public_nonce = if participant.id == 0 {
					seller_nonce.clone()
				} else {
					buyer_nonce.clone()
				};
			}
		}
		let fields = original
			.redeem_tx_fields(0, &buyer.redeem_slate.slate, &secp)
			.unwrap();
		let buyer_key =
			BuyApi::redeem_tx_secret(&secp, &buyer_keychain, &buyer, &buyer_context).unwrap();
		let redeem_secret = BuyApi::redeem_secret(&secp, &buyer_keychain, &buyer_context).unwrap();
		let sign_adaptor = |nonce: &SecretKey| {
			aggsig::sign_single(
				&secp,
				&fields.message,
				&buyer_key,
				Some(nonce),
				Some(&redeem_secret),
				Some(&fields.pub_nonce_sum),
				&fields.pub_blind_sum,
				Some(&fields.pub_nonce_sum),
			)
			.unwrap()
		};
		buyer.adaptor_signature = Some(sign_adaptor(&buyer_context.redeem_nonce));
		let honest_message = BuyApi::init_redeem_message(0, &buyer).unwrap();
		let mut wrong_nonce = buyer_context.redeem_nonce.clone();
		if negate_nonce {
			wrong_nonce.neg_assign(&secp).unwrap();
		} else {
			wrong_nonce = SecretKey::from_slice(&secp, &[42; 32]).unwrap();
		}
		let wrong_adaptor = sign_adaptor(&wrong_nonce);
		// Both attacks pass the old check with the exact same aggregate challenge.
		assert!(
			aggsig::verify_single(
				&secp,
				&wrong_adaptor,
				&fields.message,
				Some(&fields.pub_nonce_sum),
				&PublicKey::from_secret_key(&secp, &buyer_key).unwrap(),
				&fields.pub_blind_sum,
				original.redeem_public.as_ref(),
				true,
			)
			.unwrap()
		);
		// An x-coordinate comparison alone cannot reject the negation attack.
		assert_eq!(
			wrong_adaptor.as_ref()[..32] == buyer_nonce.serialize_vec(&secp, true).unwrap()[1..33],
			negate_nonce
		);
		let mut malicious_message = honest_message.clone();
		match &mut malicious_message.inner {
			Update::InitRedeem(update) => update.adaptor_signature = wrong_adaptor,
			_ => panic!("expected InitRedeem"),
		}
		let confirmations = SwapTransactionsConfirmations {
			mwc_observed: true,
			secondary_observed: true,
			mwc_tip: 300_000,
			mwc_lock_conf: Some(original.mwc_confirmations),
			mwc_redeem_conf: None,
			mwc_refund_conf: None,
			secondary_tip: 500_000,
			secondary_lock_conf: Some(original.secondary_confirmations),
			secondary_lock_amount: original.secondary_amount,
			secondary_redeem_conf: None,
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		};
		let states: Vec<Box<dyn State>> = vec![
			Box::new(SellerWaitingForInitRedeemMessage::new(
				0,
				seller_keychain.clone(),
				node.clone(),
			)),
			Box::new(SellerWaitingForLockConfirmations::new(
				0,
				seller_keychain.clone(),
				api.clone(),
				node.clone(),
			)),
		];
		for mut state in states {
			let mut seller = original.clone();
			seller.state = state.get_state_id();
			let before = serde_json::to_value(&seller).unwrap();
			let error = state
				.process(
					Input::IncomeMessage(malicious_message.clone()),
					&mut seller,
					&seller_context,
					&confirmations,
					&mut secp,
				)
				.unwrap_err();
			assert!(matches!(error, Error::InvalidAdaptorSignature), "{error}");
			assert_eq!(serde_json::to_value(&seller).unwrap(), before);

			// Retry the same swap with the honest adaptor and complete the exchange.
			let response = state
				.process(
					Input::IncomeMessage(honest_message.clone()),
					&mut seller,
					&seller_context,
					&confirmations,
					&mut secp,
				)
				.unwrap();
			assert_eq!(
				response.next_state_id,
				StateId::SellerSendingInitRedeemMessage
			);
			assert_eq!(seller.adaptor_signature, buyer.adaptor_signature);
			let seller_participant = seller.redeem_slate.slate.participant_with_id(0).unwrap();
			assert!(seller_participant.part_sig.is_some());
			let mut completed_buyer = buyer.clone();
			BuyApi::finalize_redeem_slate(
				0,
				&mut secp,
				&buyer_keychain,
				&mut completed_buyer,
				&buyer_context,
				seller_participant,
				node.as_ref(),
			)
			.unwrap();
			// Simulate observing the buyer's completed kernel on chain.
			seller
				.redeem_slate
				.slate
				.tx_or_err_mut()
				.unwrap()
				.body
				.kernels[0] = completed_buyer
				.redeem_slate
				.slate
				.tx_or_err()
				.unwrap()
				.body
				.kernels[0]
				.clone();
			assert_eq!(
				SellApi::calculate_redeem_secret(&secp, &seller).unwrap(),
				redeem_secret
			);
		}
	}
}

#[test]
#[serial]
fn seller_rejects_adaptor_with_different_nonce_without_mutation() {
	assert_rejects_adaptor_nonce(false);
}

#[test]
#[serial]
fn seller_rejects_adaptor_with_negated_nonce_without_mutation() {
	assert_rejects_adaptor_nonce(true);
}
