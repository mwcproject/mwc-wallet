//! Redemption fees must be affordable before the seller releases its MWC signature.

use super::*;

fn before_redeem_message(swap: &mut Swap) {
	swap.state = StateId::SellerSendingInitRedeemMessage;
	swap.redeem_kernel_updated = false;
	swap.message2 = None;
	swap.posted_msg2 = None;
}

#[test]
#[serial]
fn initial_redeem_fee_rejects_fragmented_funding_and_allows_retry() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, keychain, node, btc_node) = funding_limit_fixture(&secp, 32);
	swap::set_testing_cur_time(swap.started.timestamp());
	before_redeem_message(&mut swap);
	// The permitted 32 inputs total 3,200,000 satoshis. At 400 sat/vB their
	// redemption costs 3,998,400, so the buyer must not receive our signature.
	swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(400_000);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc_node.clone())));
	let mut confirmations = api
		.request_tx_confirmations(&secp, &keychain, &swap)
		.unwrap();
	confirmations.mwc_lock_conf = Some(swap.mwc_confirmations);
	let mut fsm = api.get_fsm(&keychain, &swap);
	let before = serde_json::to_value(&swap).unwrap();
	let error = fsm
		.process_with_persist(
			Input::Check,
			&mut swap,
			&context,
			&confirmations,
			&mut secp,
			&|_| Ok(()),
		)
		.unwrap_err();
	assert!(
		matches!(error, Error::DataOverflow(ref message)
		if message.contains("fee exceeds input amount")),
		"{error}"
	);
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);
	assert!(SellApi::redeem_message(&swap).is_err());
	assert!(btc_node.get_state().pending.is_empty());

	// Adjusting the fee permits a retry through the same state machine.
	swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(10_000);
	let response = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	let message = match response.action {
		Some(Action::SellerSendRedeemMessage(message)) => message,
		other => panic!("Expected redeem message, got {other:?}"),
	};
	let accepted = swap
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_inputs
		.clone()
		.unwrap();
	assert_eq!(accepted.len(), 32);

	// A cached message must not bypass the check if the fee changes. Preserve
	// the accepted inputs on failure, including after saving and reloading.
	swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(400_000);
	let before = serde_json::to_value(&swap).unwrap();
	assert!(matches!(
		fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp),
		Err(Error::DataOverflow(_))
	));
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);
	swap.message2 = Some(message);
	swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
	let mut fsm = api.get_fsm(&keychain, &swap);
	let before = serde_json::to_value(&swap).unwrap();
	assert!(matches!(
		fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp),
		Err(Error::DataOverflow(_))
	));
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);
	swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(10_000);
	assert!(matches!(
		fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap()
			.action,
		Some(Action::SellerSendRedeemMessage(_))
	));
	assert_eq!(
		swap.secondary_data.unwrap_btc().unwrap().redeem_inputs,
		Some(accepted)
	);
	swap::reset_testing_cur_time();
}

#[test]
#[serial]
fn initial_redeem_fee_checks_destination_dust_before_authorizing() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let destinations = [
		(
			bitcoin_lib::Script::new_p2pkh(&bitcoin_lib::PubkeyHash::from_byte_array([4; 20])),
			546,
		),
		(
			bitcoin_lib::blockdata::script::Builder::new()
				.push_int(0)
				.unwrap()
				.push_slice(&[4; 20])
				.unwrap()
				.into_script(),
			294,
		),
	];
	for (destination, minimum) in destinations {
		let (mut original, context, keychain, node, btc_node) = funding_limit_fixture(&secp, 1);
		swap::set_testing_cur_time(original.started.timestamp());
		before_redeem_message(&mut original);
		let address = Address::new_btc()
			.from_script(&destination, bitcoin_lib::Network::Testnet)
			.unwrap()
			.to_string();
		original.role = Role::Seller(address, original.unwrap_seller().unwrap().1);
		let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc_node.clone())));
		let mut confirmations = api
			.request_tx_confirmations(&secp, &keychain, &original)
			.unwrap();
		confirmations.mwc_lock_conf = Some(original.mwc_confirmations);

		// At one sat/vB the fee equals the conservative signed transaction size.
		// Size a clone so each case still tests the first acceptance of the funds.
		let mut sizing = original.clone();
		sizing.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(1_000);
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut sizing, &secp)
			.unwrap();
		let vbytes = (&api as &dyn SwapApi<ExtKeychain>)
			.secondary_redeem_fee(&sizing, sizing.secondary_fee_units, &secp)
			.unwrap();
		assert!(vbytes < 1_000);
		let funded_chain = btc_node.get_state();

		for remainder in [0, 1, minimum - 1, minimum, minimum + 1] {
			btc_node.set_state(&funded_chain);
			let mut swap = original.clone();
			let expected_fee = swap.secondary_amount - remainder;
			swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(expected_fee * 1_000 / vbytes);
			let mut fsm = api.get_fsm(&keychain, &swap);
			let before = serde_json::to_value(&swap).unwrap();
			let response =
				fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp);
			if remainder < minimum {
				let error = response.unwrap_err();
				assert!(
					matches!(error, Error::Generic(ref message)
					if message.contains("below the dust threshold")
						&& message.contains(&format!("minimum_output={minimum}"))),
					"{error}"
				);
				assert_eq!(serde_json::to_value(&swap).unwrap(), before);
				assert!(SellApi::redeem_message(&swap).is_err());
			} else {
				assert!(matches!(
					response.unwrap().action,
					Some(Action::SellerSendRedeemMessage(_))
				));
				// Restore the fixture's completed MWC redemption and verify that
				// the real Bitcoin signer leaves exactly the preflighted output.
				swap.redeem_kernel_updated = true;
				api.publish_secondary_transaction(&secp, &keychain, &mut swap, &context, true)
					.unwrap();
				let hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
				let chain = btc_node.get_state();
				let tx = chain
					.pending
					.get(&bitcoin_lib::Txid::from_byte_array(hash.to_byte_array()))
					.unwrap();
				assert_eq!(tx.output[0].value, remainder);
				assert_eq!(tx.output[0].script_pubkey, destination);
			}
		}
	}
	swap::reset_testing_cur_time();
}
