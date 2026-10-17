//! Automatic redemption fees must cover all inputs and recover from relay rejection.

use super::*;

#[derive(Clone)]
struct RbfRelayClient {
	inner: TestBtcNodeClient,
	incremental_rate_per_kvb: u64,
}

impl BtcNodeClient for RbfRelayClient {
	fn name(&self) -> String {
		"BTC relay with incremental replacement fees".into()
	}

	fn height(&mut self) -> Result<u64, Error> {
		self.inner.height()
	}

	fn unspent(
		&mut self,
		id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error> {
		self.inner.unspent(id, currency, address)
	}

	fn transaction(&mut self, txid: &bitcoin_lib::Txid) -> Result<Option<u64>, Error> {
		self.inner.transaction(txid)
	}

	fn transaction_is_coinbase(&mut self, txid: &bitcoin_lib::Txid) -> Result<bool, Error> {
		self.inner.transaction_is_coinbase(txid)
	}

	fn confirmed_spend(
		&mut self,
		outpoint: &bitcoin_lib::OutPoint,
		script_pubkey: &bitcoin_lib::Script,
	) -> Result<Option<(BitcoinTransaction, u64)>, Error> {
		self.inner.confirmed_spend(outpoint, script_pubkey)
	}

	fn post_tx(&mut self, raw: Vec<u8>) -> Result<(), Error> {
		let tx: BitcoinTransaction = bitcoin_lib::consensus::deserialize(&raw).unwrap();
		let state = self.inner.get_state();
		let fee = |tx: &BitcoinTransaction| {
			let inputs: u64 = tx
				.input
				.iter()
				.map(|input| {
					state.txs[&input.previous_output.txid].output
						[usize::try_from(input.previous_output.vout).unwrap()]
					.value
				})
				.sum();
			inputs - tx.output.iter().map(|output| output.value).sum::<u64>()
		};
		let conflicts: Vec<_> = state
			.pending
			.iter()
			.filter(|(_, old)| {
				tx.input.iter().any(|input| {
					old.input
						.iter()
						.any(|old_input| input.previous_output == old_input.previous_output)
				})
			})
			.collect();
		if !conflicts.is_empty() {
			// These are legacy P2SH transactions, so serialized bytes equal vbytes.
			// Enforce Bitcoin Core's absolute additional fee rule, independently of
			// the wallet's chosen rate or percentage increase.
			assert!(tx.input.iter().all(|input| input.witness.is_empty()));
			let old_fee: u64 = conflicts.iter().map(|(_, old)| fee(old)).sum();
			let required =
				(u64::try_from(raw.len()).unwrap() * self.incremental_rate_per_kvb / 1_000).max(1);
			if fee(&tx) < old_fee + required {
				return Err(Error::ElectrumNodeClient(
					"not enough additional fees to relay".into(),
				));
			}
		}
		self.inner.post_tx(raw)?;
		let mut mempool = self.inner.state.lock();
		for (txid, _) in conflicts {
			mempool.pending.remove(txid);
		}
		Ok(())
	}
}

fn check_automatic_fee_bump(input_count: usize, initial_rate: u64, allow_bump: bool) {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, keychain, node, btc_node) = funding_limit_fixture(&secp, input_count);
	swap::set_testing_cur_time(swap.started.timestamp());
	swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(initial_rate);
	let api = BtcSwapApi::new_test(
		Arc::new(node),
		Arc::new(Mutex::new(RbfRelayClient {
			inner: btc_node.clone(),
			incremental_rate_per_kvb: 1_000,
		})),
	);
	(&api as &dyn SwapApi<ExtKeychain>)
		.prepare_secondary_redeem(&mut swap, &secp)
		.unwrap();
	api.publish_secondary_transaction(&secp, &keychain, &mut swap, &context, true)
		.unwrap();
	let initial_hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
	let initial_tx = btc_node
		.get_state()
		.pending
		.get(&bitcoin_lib::Txid::from_byte_array(
			initial_hash.to_byte_array(),
		))
		.unwrap()
		.clone();
	let initial_fee = swap.secondary_amount - initial_tx.output[0].value;
	assert!(initial_fee * 2 < swap.secondary_amount);

	swap.state = StateId::SellerWaitingForRedeemConfirmations;
	swap.posted_secondary_height = Some(500_000);
	swap.posted_redeem = Some(swap::get_cur_time() - state::POST_SECONDARY_RETRY_PERIOD - 1);
	let before = serde_json::to_value(&swap).unwrap();
	let confirmations = SwapTransactionsConfirmations {
		mwc_observed: true,
		secondary_observed: true,
		mwc_tip: 300_000,
		mwc_lock_conf: Some(swap.mwc_confirmations),
		mwc_redeem_conf: Some(1),
		mwc_refund_conf: None,
		secondary_tip: 500_000 + state::SECONDARY_HEIGHT_TO_INCREASE_FEE + 1,
		secondary_lock_conf: None,
		secondary_lock_amount: 0,
		secondary_redeem_conf: Some(0),
		secondary_refund_conf: None,
		secondary_refund_progress: None,
	};
	let mut fsm = api.get_fsm(&keychain, &swap);
	let response = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	if allow_bump {
		assert_eq!(
			response.next_state_id,
			StateId::SellerRedeemSecondaryCurrency
		);
		assert_eq!(
			swap.secondary_fee_units,
			SecondaryFeeUnits::RatePerKvb((initial_rate * 6 / 5).max(initial_rate + 1_000))
		);
		fsm.process(
			Input::Execute,
			&mut swap,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
		let hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
		assert_ne!(hash, initial_hash);
		let btc_state = btc_node.get_state();
		let replacement = btc_state
			.pending
			.get(&bitcoin_lib::Txid::from_byte_array(hash.to_byte_array()))
			.unwrap();
		let replacement_fee = swap.secondary_amount - replacement.output[0].value;
		assert!(replacement_fee > initial_fee);
		assert!(replacement_fee * 2 < swap.secondary_amount);
		assert_eq!(
			replacement
				.input
				.iter()
				.map(|i| i.previous_output)
				.collect::<Vec<_>>(),
			initial_tx
				.input
				.iter()
				.map(|i| i.previous_output)
				.collect::<Vec<_>>()
		);
	} else {
		assert_eq!(
			response.next_state_id,
			StateId::SellerWaitingForRedeemConfirmations
		);
		assert!(matches!(
			response.action,
			Some(Action::WaitForSecondaryConfirmations { .. })
		));
		// Rejecting an automatic increase must preserve the pending transaction,
		// its fee setting and its retry timestamps.
		assert_eq!(serde_json::to_value(&swap).unwrap(), before);
		assert_eq!(btc_node.get_state().pending.len(), 1);

		// The same cap must hold while retrying a replacement at a changed fee.
		swap.state = StateId::SellerRedeemSecondaryCurrency;
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(initial_rate + 1);
		let before_retry = serde_json::to_value(&swap).unwrap();
		let response = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::SellerRedeemSecondaryCurrency
		);
		assert_eq!(serde_json::to_value(&swap).unwrap(), before_retry);
		assert_eq!(btc_node.get_state().pending.len(), 1);
	}
	swap::reset_testing_cur_time();
}

// 32 accepted inputs totaling 3,200,000 satoshis cost 1,499,400 satoshis
// at 150 sat/vB. The proposed 180 sat/vB replacement costs 1,799,280,
// which must be rejected because it exceeds half the trade amount.
#[test]
#[serial]
fn automatic_btc_fee_bump_rejects_multi_input_fee_above_half_the_trade() {
	check_automatic_fee_bump(32, 150_000, false);
}

// Low-fee replacements must still be signed and published, spending the same
// accepted inputs, whether the funding consists of one, two or 32 outputs.
#[test]
#[serial]
fn automatic_btc_fee_bump_publishes_affordable_replacements() {
	for inputs in [1, 2, 32] {
		check_automatic_fee_bump(inputs, 10_000, true);
	}
}

#[test]
#[serial]
fn automatic_btc_fee_bump_covers_incremental_relay_fee_at_low_rates() {
	for inputs in [1, 2, 32] {
		check_automatic_fee_bump(inputs, 100, true);
	}
}

#[test]
#[serial]
fn automatic_btc_fee_bump_preserves_spendable_destination_outputs() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	// The legacy replacement costs 391 satoshis: cover the reported 900-satoshi
	// trade and both sides of its 546-satoshi dust boundary. The same small trade
	// remains eligible with a SegWit destination, whose minimum is only 294.
	for (segwit, amount, allow_bump) in [
		(false, 900, false),
		(false, 936, false),
		(false, 937, true),
		(true, 900, true),
	] {
		let (mut original, context, keychain, node, _) = funding_limit_fixture(&secp, 1);
		swap::set_testing_cur_time(original.started.timestamp());
		original.secondary_amount = amount;
		original.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(100);
		if segwit {
			let destination = bitcoin_lib::blockdata::script::Builder::new()
				.push_int(0)
				.unwrap()
				.push_slice(&[4; 20])
				.unwrap()
				.into_script();
			let address = Address::new_btc()
				.from_script(&destination, bitcoin_lib::Network::Testnet)
				.unwrap()
				.to_string();
			original.role = Role::Seller(address, original.unwrap_seller().unwrap().1);
		}
		let btc_node = TestBtcNodeClient::new(500_000);
		let api = BtcSwapApi::new_test(
			Arc::new(node),
			Arc::new(Mutex::new(RbfRelayClient {
				inner: btc_node.clone(),
				incremental_rate_per_kvb: 1_000,
			})),
		);
		let addresses = (&api as &dyn SwapApi<ExtKeychain>)
			.get_secondary_lock_address(&original, &secp)
			.unwrap();
		btc_node
			.push_transaction(&BitcoinTransaction {
				version: 2,
				lock_time: 0,
				input: vec![],
				output: vec![TxOut {
					value: amount,
					script_pubkey: Currency::Btc
						.address_2_script_pubkey(0, &addresses[0])
						.unwrap(),
				}],
			})
			.unwrap();
		btc_node.mine_blocks(original.secondary_confirmations);
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut original, &secp)
			.unwrap();
		api.publish_secondary_transaction(&secp, &keychain, &mut original, &context, true)
			.unwrap();
		let initial_hash = original.secondary_data.unwrap_btc().unwrap().redeem_tx;
		let initial_chain = btc_node.get_state();
		let proposed_fee = (&api as &dyn SwapApi<ExtKeychain>)
			.secondary_redeem_fee(&original, SecondaryFeeUnits::RatePerKvb(1_100), &secp)
			.unwrap();
		assert!(proposed_fee * 2 < amount);
		let minimum = if segwit { 294 } else { 546 };
		assert_eq!(amount - proposed_fee >= minimum, allow_bump);

		for (initial_state, redeem_conf) in [
			(StateId::SellerWaitingForRedeemConfirmations, Some(0)),
			(StateId::SellerRedeemSecondaryCurrency, None),
		] {
			btc_node.set_state(&initial_chain);
			let mut swap = original.clone();
			swap.state = initial_state;
			swap.posted_secondary_height = Some(500_000);
			swap.posted_redeem =
				Some(swap::get_cur_time() - state::POST_SECONDARY_RETRY_PERIOD - 1);
			let before = serde_json::to_value(&swap).unwrap();
			let confirmations = SwapTransactionsConfirmations {
				mwc_observed: true,
				secondary_observed: true,
				mwc_tip: 300_000,
				mwc_lock_conf: Some(swap.mwc_confirmations),
				mwc_redeem_conf: Some(1),
				mwc_refund_conf: None,
				secondary_tip: 500_006,
				secondary_lock_conf: None,
				secondary_lock_amount: 0,
				secondary_redeem_conf: redeem_conf,
				secondary_refund_conf: None,
				secondary_refund_progress: None,
			};
			let mut fsm = api.get_fsm(&keychain, &swap);
			for _ in 0..2 {
				fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
					.unwrap();
				if allow_bump {
					assert_eq!(
						swap.secondary_fee_units,
						SecondaryFeeUnits::RatePerKvb(1_100)
					);
					assert_eq!(swap.posted_secondary_height, None);
				} else {
					// Include the journal, recorded transaction and retry timestamps.
					assert!(
						serde_json::to_value(&swap).unwrap() == before,
						"A dust-producing bump must leave the trade unchanged"
					);
				}
			}
			if swap.state == StateId::SellerRedeemSecondaryCurrency {
				fsm.process(
					Input::Execute,
					&mut swap,
					&context,
					&confirmations,
					&mut secp,
				)
				.unwrap();
				let hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
				let chain = btc_node.get_state();
				let tx = &chain.pending[&bitcoin_lib::Txid::from_byte_array(hash.to_byte_array())];
				assert!(tx.output[0].value >= minimum);
				if allow_bump {
					assert_eq!(tx.output[0].value, amount - proposed_fee);
					assert_ne!(Some(hash), initial_hash);
				} else {
					// A skipped bump must still allow retrying the original transaction.
					assert_eq!(Some(hash), initial_hash);
				}
			}
			assert_eq!(btc_node.get_state().pending.len(), 1);
		}
	}
	swap::reset_testing_cur_time();
}

#[test]
#[serial]
fn rejected_btc_replacements_remain_eligible_for_later_fee_bumps() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	for redeem_conf in [Some(0), None] {
		let (mut swap, context, keychain, node, btc_node) = funding_limit_fixture(&secp, 1);
		swap::set_testing_cur_time(swap.started.timestamp());
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(100);
		let api = BtcSwapApi::new_test(
			Arc::new(node),
			Arc::new(Mutex::new(RbfRelayClient {
				inner: btc_node.clone(),
				// Stricter than the normal policy: the first two bumps must fail.
				incremental_rate_per_kvb: 3_000,
			})),
		);
		(&api as &dyn SwapApi<ExtKeychain>)
			.prepare_secondary_redeem(&mut swap, &secp)
			.unwrap();
		api.publish_secondary_transaction(&secp, &keychain, &mut swap, &context, true)
			.unwrap();
		let initial_hash = swap.secondary_data.unwrap_btc().unwrap().redeem_tx.unwrap();
		swap.state = StateId::SellerWaitingForRedeemConfirmations;
		swap.posted_secondary_height = Some(500_000);
		swap.posted_redeem = Some(swap::get_cur_time() - state::POST_SECONDARY_RETRY_PERIOD - 1);
		let mut confirmations = SwapTransactionsConfirmations {
			mwc_observed: true,
			secondary_observed: true,
			mwc_tip: 300_000,
			mwc_lock_conf: Some(swap.mwc_confirmations),
			mwc_redeem_conf: Some(1),
			mwc_refund_conf: None,
			secondary_tip: 500_006,
			secondary_lock_conf: None,
			secondary_lock_amount: 0,
			secondary_redeem_conf: redeem_conf,
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		};
		let mut fsm = api.get_fsm(&keychain, &swap);
		for expected_rate in [1_100, 2_100, 3_100] {
			// Repeated checks alone must not compound an unsubmitted fee increase.
			for _ in 0..3 {
				let response = fsm
					.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
					.unwrap();
				assert_eq!(
					response.next_state_id,
					StateId::SellerRedeemSecondaryCurrency
				);
				assert_eq!(
					swap.secondary_fee_units,
					SecondaryFeeUnits::RatePerKvb(expected_rate)
				);
				assert_eq!(swap.posted_secondary_height, None);
			}
			if expected_rate == 3_100 {
				let response = fsm
					.process(
						Input::Execute,
						&mut swap,
						&context,
						&confirmations,
						&mut secp,
					)
					.unwrap();
				assert_eq!(
					response.next_state_id,
					StateId::SellerWaitingForRedeemConfirmations
				);
				assert_eq!(
					swap.posted_secondary_height,
					Some(confirmations.secondary_tip)
				);
				assert_eq!(
					swap.secondary_data.unwrap_btc().unwrap().tx_fee_units,
					Some(SecondaryFeeUnits::RatePerKvb(3_100))
				);
				assert_ne!(
					swap.secondary_data.unwrap_btc().unwrap().redeem_tx,
					Some(initial_hash)
				);
				assert_eq!(btc_node.get_state().pending.len(), 1);
				break;
			}

			let attempted_height = confirmations.secondary_tip;
			// Frequent rejected submissions must not restart the block delay.
			for blocks in 0..=5 {
				confirmations.secondary_tip = attempted_height + blocks;
				fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
					.unwrap();
				assert_eq!(
					swap.secondary_fee_units,
					SecondaryFeeUnits::RatePerKvb(expected_rate)
				);
				let error = fsm
					.process(
						Input::Execute,
						&mut swap,
						&context,
						&confirmations,
						&mut secp,
					)
					.unwrap_err();
				assert!(
					error.to_string().contains("not enough additional fees"),
					"{error}"
				);
				assert_eq!(swap.state, StateId::SellerRedeemSecondaryCurrency);
				assert_eq!(swap.posted_secondary_height, Some(attempted_height));
				assert_eq!(
					swap.secondary_data.unwrap_btc().unwrap().redeem_tx,
					Some(initial_hash)
				);
				assert_eq!(
					swap.secondary_data.unwrap_btc().unwrap().tx_fee_units,
					Some(SecondaryFeeUnits::RatePerKvb(100))
				);
			}
			confirmations.secondary_tip = attempted_height + 6;

			// A restart after a failed submission must retain the retry deadline.
			swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
			fsm = api.get_fsm(&keychain, &swap);

			// If an earlier transaction confirms instead, finish without another bump.
			let mut confirmed_swap = swap.clone();
			confirmations.secondary_redeem_conf = Some(swap.secondary_confirmations);
			let response = fsm
				.process(
					Input::Check,
					&mut confirmed_swap,
					&context,
					&confirmations,
					&mut secp,
				)
				.unwrap();
			assert_eq!(response.next_state_id, StateId::SellerSwapComplete);
			assert_eq!(confirmed_swap.secondary_fee_units, swap.secondary_fee_units);
			confirmations.secondary_redeem_conf = redeem_conf;
		}
	}
	swap::reset_testing_cur_time();
}
