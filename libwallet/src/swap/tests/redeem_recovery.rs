//! Redemptions must remain observable when their legacy scriptSig changes the txid.

use super::*;
use bitcoin_lib::blockdata::script::Instruction;
use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Message as SecpMessage};

fn setup() -> Secp256k1 {
	set_test_mode(true);
	swap::set_testing_cur_time(1567632152);
	global::set_local_chain_type(ChainTypes::Floonet);
	Secp256k1::with_caps(ContextFlag::Commit).unwrap()
}

// Negative zero selects the same legacy OP_IF branch as OP_0, using a minimal
// data push. Both signatures stay unchanged and the transaction gets a new ID.
fn malleate_redeem(transaction: &BitcoinTransaction) -> BitcoinTransaction {
	let mut changed = transaction.clone();
	let mut bytes = changed.input[0].script_sig.to_bytes();
	let second_signature = 2 + usize::from(bytes[1]);
	let selector = second_signature + 1 + usize::from(bytes[second_signature]);
	assert_eq!(bytes[selector], 0);
	bytes.splice(selector..selector + 1, [1, 0x80]);
	changed.input[0].script_sig = bitcoin_lib::Script::from(bytes);
	let instructions = changed.input[0]
		.script_sig
		.instructions_minimal()
		.collect::<Result<Vec<_>, _>>()
		.unwrap();
	assert!(matches!(instructions[3], Instruction::PushBytes([0x80])));
	assert_ne!(transaction.txid().unwrap(), changed.txid().unwrap());
	changed
}

fn verify_signatures(secp: &Secp256k1, swap: &Swap, transaction: &BitcoinTransaction) {
	let keys = [
		swap.secondary_data.unwrap_btc().unwrap().cosign,
		swap.redeem_public.unwrap(),
	];
	for (index, input) in transaction.input.iter().enumerate() {
		let instructions = input
			.script_sig
			.instructions_minimal()
			.collect::<Result<Vec<_>, _>>()
			.unwrap();
		let Instruction::PushBytes(script) = instructions[4] else {
			panic!("missing redeem script")
		};
		let message = SecpMessage::from_slice(
			transaction
				.signature_hash(index, &bitcoin_lib::Script::from(script.to_vec()), 1)
				.unwrap()
				.as_ref(),
		)
		.unwrap();
		for (index, key) in keys.iter().enumerate() {
			let Instruction::PushBytes(bytes) = instructions[index + 1] else {
				panic!("missing signature")
			};
			let signature = EcdsaSignature::from_der(secp, &bytes[..bytes.len() - 1]).unwrap();
			secp.verify(&message, &signature, key).unwrap();
		}
	}
}

// Exercise real signing, persistence, confirmation polling and FSM completion
// for successful and ambiguous broadcasts. Recovery is refreshed after a reorg.
#[test]
#[serial]
fn seller_redeem_recovers_malleated_transaction_after_restart() {
	let mut secp = setup();
	for broadcast_mode in [0, 2] {
		let (mut swap, context, kc, node, btc) = seller_redeem_fixture(&secp);
		let before_spend = btc.inner.get_state();
		let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
		btc.post_error.store(broadcast_mode, Ordering::SeqCst);
		let result = api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true);
		assert_eq!(result.is_ok(), broadcast_mode == 0);
		let attempts = &swap.secondary_data.unwrap_btc().unwrap().redeem_attempts;
		assert_eq!(attempts.len(), 1);
		let original: BitcoinTransaction =
			bitcoin_lib::consensus::deserialize(&attempts[0].tx).unwrap();
		let changed = malleate_redeem(&original);
		verify_signatures(&secp, &swap, &changed);
		swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
		let saved = serde_json::to_value(&swap).unwrap();
		btc.inner.set_state(&before_spend);
		btc.inner.post_transaction(&changed).unwrap();
		// Discovery requires confirmation, not merely an unknown mempool spend.
		assert_eq!(
			api.request_secondary_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_redeem_conf,
			None
		);
		btc.inner.mine_block();
		assert_eq!(
			api.request_secondary_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_redeem_conf,
			Some(1)
		);
		btc.inner.mine_blocks(swap.secondary_confirmations - 1);
		let confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
		assert_eq!(
			confirmations.secondary_redeem_conf,
			Some(swap.secondary_confirmations)
		);
		assert_eq!(confirmations.secondary_lock_amount, 0);
		assert_eq!(serde_json::to_value(&swap).unwrap(), saved);
		let mut completed = swap.clone();
		api.get_fsm(&kc, &completed)
			.process(
				Input::Check,
				&mut completed,
				&context,
				&confirmations,
				&mut secp,
			)
			.unwrap();
		assert_eq!(completed.state, StateId::SellerSwapComplete);
		// A direct retry must recognize the confirmed variant without broadcasting.
		btc.post_error.store(1, Ordering::SeqCst);
		api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
			.unwrap();
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.redeem_attempts
				.len(),
			1
		);
		assert!(btc.inner.get_state().pending.is_empty());
		btc.inner.set_state(&before_spend);
		assert_eq!(
			api.request_secondary_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_redeem_conf,
			None
		);
		btc.post_error.store(0, Ordering::SeqCst);
		api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
			.unwrap();
		assert_eq!(
			btc.inner.get_state().pending[&original.txid().unwrap()],
			original
		);
	}
}

// Older attempts can confirm after a later fee replacement or lost response.
#[test]
#[serial]
fn seller_redeem_recovers_every_saved_replacement() {
	let secp = setup();
	let (mut swap, context, kc, node, btc) = seller_redeem_fixture(&secp);
	let before_spend = btc.inner.get_state();
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
		.unwrap();
	btc.post_error.store(2, Ordering::SeqCst);
	for fee in [20_000, 30_000] {
		swap.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(fee);
		assert!(api
			.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
			.is_err());
	}
	let original_fee = swap.secondary_data.unwrap_btc().unwrap().tx_fee_units;
	swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
	let attempts = swap
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_attempts
		.clone();
	assert_eq!(attempts.len(), 3);
	for attempt in attempts {
		let transaction = bitcoin_lib::consensus::deserialize(&attempt.tx).unwrap();
		let changed = malleate_redeem(&transaction);
		verify_signatures(&secp, &swap, &changed);
		btc.inner.set_state(&before_spend);
		btc.inner.push_transaction(&changed).unwrap();
		assert_eq!(
			api.request_secondary_tx_confirmations(&secp, &kc, &swap)
				.unwrap()
				.secondary_redeem_conf,
			Some(1)
		);
		btc.post_error.store(1, Ordering::SeqCst);
		api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
			.unwrap();
		assert_eq!(
			swap.secondary_data.unwrap_btc().unwrap().tx_fee_units,
			original_fee
		);
		assert_eq!(
			swap.secondary_data
				.unwrap_btc()
				.unwrap()
				.redeem_attempts
				.len(),
			3
		);
	}
}

// Backend responses that change the payment must fail, even though they spend
// the expected funding. Consensus-invalid mock transactions exercise validation.
#[test]
#[serial]
fn seller_redeem_rejects_changed_payment() {
	let secp = setup();
	let (mut swap, context, kc, node, btc) = seller_redeem_fixture(&secp);
	let before_spend = btc.inner.get_state();
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
		.unwrap();
	let original: BitcoinTransaction = bitcoin_lib::consensus::deserialize(
		&swap.secondary_data.unwrap_btc().unwrap().redeem_attempts[0].tx,
	)
	.unwrap();
	let saved = serde_json::to_value(&swap).unwrap();
	for change_destination in [false, true] {
		let mut changed = malleate_redeem(&original);
		if change_destination {
			changed.output[0].script_pubkey = bitcoin_lib::Script::new();
		} else {
			changed.output[0].value -= 1;
		}
		btc.inner.set_state(&before_spend);
		btc.inner.push_transaction(&changed).unwrap();
		let error = api
			.request_secondary_tx_confirmations(&secp, &kc, &swap)
			.err()
			.unwrap();
		assert!(error
			.to_string()
			.contains("does not match any saved redemption attempt"));
		assert_eq!(serde_json::to_value(&swap).unwrap(), saved);
	}
}

// Discard an entire primary observation if a later read fails. Recovered
// confirmations must not survive into a fallback that sees unspent funding.
#[test]
#[serial]
fn seller_redeem_recovery_preserves_complete_backend_failover() {
	let secp = setup();
	let (mut swap, context, kc, node, btc) = seller_redeem_fixture(&secp);
	let before_spend = btc.inner.get_state();
	let api = BtcSwapApi::new_test(Arc::new(node.clone()), Arc::new(Mutex::new(btc.clone())));
	api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
		.unwrap();
	let original = bitcoin_lib::consensus::deserialize(
		&swap.secondary_data.unwrap_btc().unwrap().redeem_attempts[0].tx,
	)
	.unwrap();
	let changed = malleate_redeem(&original);
	btc.inner.set_state(&before_spend);
	let mut primary = btc.clone();
	primary.inner = TestBtcNodeClient::new(before_spend.height);
	primary.inner.set_state(&before_spend);
	primary.inner.push_transaction(&changed).unwrap();
	primary.unspent_error = true;
	let primary = Arc::new(Mutex::new(primary));
	let fallback = Arc::new(Mutex::new(btc.clone()));
	let api = BtcSwapApi::new(0, Currency::Btc, Arc::new(node), primary, fallback.clone());
	let saved = serde_json::to_value(&swap).unwrap();
	let result = api
		.request_secondary_tx_confirmations(&secp, &kc, &swap)
		.unwrap();
	assert_eq!(result.secondary_redeem_conf, None);
	assert_eq!(result.secondary_lock_amount, swap.secondary_amount);
	fallback.lock().unspent_error = true;
	assert!(api
		.request_secondary_tx_confirmations(&secp, &kc, &swap)
		.is_err());
	assert_eq!(serde_json::to_value(&swap).unwrap(), saved);
}

// Old backups remain readable. Re-signing an unchanged legacy attempt can
// retain its bytes safely; merely observing spent inputs must not mark it paid.
#[test]
#[serial]
fn seller_redeem_legacy_hashes_remain_readable_and_retry_retains_bytes() {
	let secp = setup();
	let (mut swap, context, kc, node, btc) = seller_redeem_fixture(&secp);
	let before_spend = btc.inner.get_state();
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
		.unwrap();
	let original = bitcoin_lib::consensus::deserialize(
		&swap.secondary_data.unwrap_btc().unwrap().redeem_attempts[0].tx,
	)
	.unwrap();
	let mut legacy = serde_json::to_value(&swap).unwrap();
	legacy["secondary_data"]["Btc"]
		.as_object_mut()
		.unwrap()
		.remove("redeem_attempts");
	swap = serde_json::from_value(legacy).unwrap();
	assert!(swap
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_attempts
		.is_empty());
	assert_eq!(
		api.request_secondary_tx_confirmations(&secp, &kc, &swap)
			.unwrap()
			.secondary_redeem_conf,
		Some(0)
	);
	btc.inner.set_state(&before_spend);
	btc.inner
		.push_transaction(&malleate_redeem(&original))
		.unwrap();
	assert_eq!(
		api.request_secondary_tx_confirmations(&secp, &kc, &swap)
			.unwrap()
			.secondary_redeem_conf,
		None
	);
	btc.post_error.store(1, Ordering::SeqCst);
	api.publish_secondary_transaction(&secp, &kc, &mut swap, &context, true)
		.unwrap();
	assert_eq!(
		swap.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_attempts
			.len(),
		1
	);
	assert_eq!(
		api.request_secondary_tx_confirmations(&secp, &kc, &swap)
			.unwrap()
			.secondary_redeem_conf,
		Some(1)
	);
}
