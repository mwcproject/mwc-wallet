//! Finalized locks gate new commitments, and finalized payments gate completion.

use super::*;
use mwc_wallet_util::mwc_web3::types::{Address, H256, TransactionReceipt, U256};
use std::collections::HashMap;

struct Fixture {
	secp: Secp256k1,
	keychain: ExtKeychain,
	context: Context,
	swap: Swap,
	node: TestEthNodeClient,
	mwc: TestNodeClient,
	api: Box<dyn SwapApi<ExtKeychain>>,
}

impl Fixture {
	fn new(currency: Currency) -> Self {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = keychain(&secp, 2);
		let context = context_eth_buy(&secp, &keychain);
		let secret = context
			.unwrap_buyer()
			.unwrap()
			.unwrap_eth()
			.unwrap()
			.address_from_secret;
		let mut swap = erc20_funding_fixture(currency, 100);
		swap.redeem_public =
			Some(PublicKey::from_secret_key(&secp, &key(&secp, &keychain, 0, 2)).unwrap());
		swap.secondary_data
			.unwrap_eth_mut()
			.unwrap()
			.address_from_secret = Some(secret);
		swap::set_testing_cur_time(swap.get_time_start() + 1_800);
		let node = TestEthNodeClient::new(25_000_000);
		node.swap_store.lock().insert(
			secret,
			(
				U256::MAX,
				if currency.is_erc20() {
					Some(currency.erc20_token_address().unwrap())
				} else {
					None
				},
				Address::repeat_byte(0x24),
				swap.secondary_data
					.unwrap_eth()
					.unwrap()
					.redeem_address
					.unwrap(),
				swap.secondary_amount,
			),
		);
		*node.finalized_swap_store.lock() = Some(HashMap::new());
		let mwc = TestNodeClient::new(300_000);
		let api = Box::new(EthSwapApi::new(
			0,
			currency,
			Arc::new(mwc.clone()),
			Arc::new(Mutex::new(node.clone())),
		));
		Self {
			secp,
			keychain,
			context,
			swap,
			node,
			mwc,
			api,
		}
	}

	fn snapshot(&self) -> Result<SwapTransactionsConfirmations, Error> {
		self.api
			.request_tx_confirmations(&self.secp, &self.keychain, &self.swap)
	}

	fn finalize(&self) {
		*self.node.finalized_swap_store.lock() = Some(self.node.swap_store.lock().clone());
	}
}

#[test]
#[serial]
fn eth_finality_outage_does_not_hide_observed_mwc_redemption_or_refund() {
	for currency in [Currency::Ether, Currency::Usdt] {
		for refund in [false, true] {
			let mut f = Fixture::new(currency);
			let completed: Swap =
				serde_json::from_str(include_str!("../../../swap_test/swap_sell_5.json")).unwrap();
			f.swap.redeem_slate = completed.redeem_slate;
			f.swap.refund_slate = completed.refund_slate;
			assert!(!f.swap.redeem_kernel_updated);
			assert!(f.swap.posted_redeem.is_none());
			*f.node.finality_error.lock() = Some("finalized RPC unavailable".into());
			assert!(f.snapshot().is_err());
			let tx = if refund {
				&f.swap.refund_slate
			} else {
				&f.swap.redeem_slate
			}
			.slate
			.tx_or_err()
			.unwrap()
			.clone();
			f.mwc.state.lock().pending.push(tx);
			f.mwc.mine_block();
			let observed = f.snapshot().unwrap();
			assert_eq!(
				if refund {
					observed.mwc_refund_conf
				} else {
					observed.mwc_redeem_conf
				},
				Some(1)
			);
			assert_eq!(observed.secondary_lock_amount, f.swap.secondary_amount);
			assert_eq!(observed.secondary_lock_conf, Some(0));
		}
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
	}
}

fn payment_fixture(currency: Currency, refund: bool) -> (Fixture, H256, H256) {
	let mut f = Fixture::new(currency);
	let original = H256::repeat_byte(0x31);
	let replacement = H256::repeat_byte(0x32);
	// The successful payment consumed the lock; recovery skips lock acceptance.
	f.node.swap_store.lock().clear();
	swap::set_testing_cur_time(f.swap.get_time_secondary_lock_publish().unwrap() + 1);
	let data = f.swap.secondary_data.unwrap_eth_mut().unwrap();
	data.tx_fee_gwei = Some(5_500_000);
	let recovery = Some(eth_transaction_recovery_fixture(vec![
		original,
		replacement,
	]));
	if refund {
		data.refund_tx = Some(replacement);
		data.refund_recovery = recovery;
		f.swap.state = StateId::BuyerWaitingForRefundConfirmations;
		f.swap.posted_refund = Some(swap::get_cur_time());
	} else {
		data.redeem_tx = Some(replacement);
		data.redeem_recovery = recovery;
		f.swap.role = Role::Seller("private-address".into(), 0);
		f.swap.state = StateId::SellerWaitingForRedeemConfirmations;
		f.swap.posted_redeem = Some(swap::get_cur_time());
		f.swap.redeem_kernel_updated = true;
		f.swap.eth_redirect_to_private_wallet = Some(false);
		f.context = context_eth_sell(&f.secp, &f.keychain);
	}
	assert!(!f.swap.needs_secondary_lock_finality().unwrap());
	(f, original, replacement)
}

fn payment_receipt(hash: H256) -> TransactionReceipt {
	TransactionReceipt {
		transaction_hash: hash,
		block_number: Some(25_000_000.into()),
		block_hash: Some(H256::repeat_byte(0x33)),
		status: Some(1.into()),
		..Default::default()
	}
}

#[test]
#[serial]
fn eth_finality_keeps_payment_recovery_active_through_reorg_and_restart() {
	for currency in [Currency::Ether, Currency::Usdt] {
		for refund in [false, true] {
			let (mut f, original, replacement) = payment_fixture(currency, refund);
			let waiting_state = f.swap.state.clone();
			let saved_recovery = f.swap.secondary_data.unwrap_eth().unwrap().clone();
			let observe = |f: &Fixture| {
				f.api
					.request_secondary_tx_confirmations(&f.secp, &f.keychain, &f.swap)
					.unwrap()
			};
			let confirmations = |observed: &SwapTransactionsConfirmations| {
				if refund {
					observed.secondary_refund_conf
				} else {
					observed.secondary_redeem_conf
				}
			};
			f.node
				.receipt_results
				.lock()
				.insert(original, Ok(payment_receipt(original)));
			let mined = observe(&f);
			assert_eq!(confirmations(&mined), Some(0));
			f.api
				.get_fsm(&f.keychain, &f.swap)
				.process(Input::Check, &mut f.swap, &f.context, &mined, &mut f.secp)
				.unwrap();
			assert_eq!(f.swap.state, waiting_state);

			// Reload the waiting trade, then remove the unfinalized receipt.
			f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
			swap::set_testing_cur_time(
				swap::get_cur_time() + fsm::state::POST_SECONDARY_RETRY_PERIOD + 1,
			);
			for hash in [original, replacement] {
				f.node
					.receipt_results
					.lock()
					.insert(hash, Err(Error::EthTransactionInPending));
			}
			let reorged = observe(&f);
			assert_eq!(confirmations(&reorged), None);
			let response = f
				.api
				.get_fsm(&f.keychain, &f.swap)
				.process(Input::Check, &mut f.swap, &f.context, &reorged, &mut f.secp)
				.unwrap();
			if refund {
				assert_eq!(f.swap.state, StateId::BuyerPostingRefundForSecondary);
				assert!(matches!(
					response.action,
					Some(Action::BuyerPublishSecondaryRefundTx { .. })
				));
			} else {
				assert_eq!(f.swap.state, StateId::SellerRedeemSecondaryCurrency);
				assert!(matches!(
					response.action,
					Some(Action::SellerPublishTxSecondaryRedeem { .. })
				));
			}
			let data = f.swap.secondary_data.unwrap_eth().unwrap();
			assert_eq!(data.redeem_recovery, saved_recovery.redeem_recovery);
			assert_eq!(data.refund_recovery, saved_recovery.refund_recovery);
			assert_eq!(data.redeem_tx, saved_recovery.redeem_tx);
			assert_eq!(data.refund_tx, saved_recovery.refund_tx);

			// A replacement in a finalized block may finally complete the trade.
			f.node
				.receipt_results
				.lock()
				.insert(original, Err(Error::EthTransactionInPending));
			f.node
				.receipt_results
				.lock()
				.insert(replacement, Ok(payment_receipt(replacement)));
			f.node.finalized_receipts.lock().insert(replacement);
			let finalized = observe(&f);
			assert_eq!(confirmations(&finalized), Some(1));
			f.api
				.get_fsm(&f.keychain, &f.swap)
				.process(
					Input::Check,
					&mut f.swap,
					&f.context,
					&finalized,
					&mut f.secp,
				)
				.unwrap();
			assert_eq!(
				f.swap.state,
				if refund {
					StateId::BuyerCancelledRefunded
				} else {
					StateId::SellerSwapComplete
				}
			);
			assert!(f.node.tx_store.lock().is_empty());
		}
	}
}

#[test]
#[serial]
fn eth_finality_payment_errors_propagate_without_disabling_reverted_recovery() {
	for currency in [Currency::Ether, Currency::Usdt] {
		for refund in [false, true] {
			let (f, original, _) = payment_fixture(currency, refund);
			*f.node.finality_error.lock() = Some("payment finality unavailable".into());
			f.node
				.receipt_results
				.lock()
				.insert(original, Ok(payment_receipt(original)));
			assert!(matches!(
				f.api.request_secondary_tx_confirmations(&f.secp, &f.keychain, &f.swap),
				Err(Error::EthereumFinalityUnavailable(message)) if message == "payment finality unavailable"
			));
			assert!(!f.swap.state.is_final_state());

			// A reverted transaction must still be retried, even during a finality outage.
			let mut reverted = payment_receipt(original);
			reverted.status = Some(0.into());
			f.node.receipt_results.lock().insert(original, Ok(reverted));
			let observed = f
				.api
				.request_secondary_tx_confirmations(&f.secp, &f.keychain, &f.swap)
				.unwrap();
			assert_eq!(observed.secondary_redeem_conf, None);
			assert_eq!(observed.secondary_refund_conf, None);
			assert!(f.node.tx_store.lock().is_empty());
		}
	}
}

#[test]
#[serial]
fn eth_finality_requires_matching_contract_state_even_after_fifteen_minutes() {
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut f = Fixture::new(currency);
		let original_deadline = f.swap.get_time_secondary_lock_script().unwrap();
		let expected = f.swap.secondary_amount;
		let pending = f.snapshot().unwrap();
		assert_eq!(pending.secondary_lock_amount, expected);
		assert_eq!(pending.secondary_lock_conf, Some(0));
		assert!(!check_txs_confirmed(
			currency,
			pending.secondary_lock_conf,
			f.swap.secondary_confirmations
		));
		assert!(
			f.api
				.prepare_secondary_redeem(&mut f.swap, &f.secp)
				.is_err()
		);
		swap::set_testing_cur_time(swap::get_cur_time() + 901);
		assert_eq!(f.snapshot().unwrap().secondary_lock_conf, Some(0));
		// Restart/import preserves deadlines and must query finality again.
		f.swap = serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
		assert_eq!(
			f.swap.get_time_secondary_lock_script().unwrap(),
			original_deadline
		);
		assert_eq!(f.snapshot().unwrap().secondary_lock_conf, Some(0));
		f.finalize();
		assert_eq!(f.snapshot().unwrap().secondary_lock_conf, Some(1));
		f.api
			.prepare_secondary_redeem(&mut f.swap, &f.secp)
			.unwrap();
		let secret = f
			.swap
			.secondary_data
			.unwrap_eth()
			.unwrap()
			.address_from_secret
			.unwrap();
		let valid = *f.node.swap_store.lock().get(&secret).unwrap();
		for mismatch in [
			(valid.0, valid.1, valid.2, valid.3, expected + 1),
			(
				valid.0,
				valid.1,
				valid.2,
				Address::repeat_byte(0x55),
				expected,
			),
			(U256::from(25_000_001), valid.1, valid.2, valid.3, expected),
		] {
			f.node
				.finalized_swap_store
				.lock()
				.as_mut()
				.unwrap()
				.insert(secret, mismatch);
			assert_eq!(f.snapshot().unwrap().secondary_lock_conf, Some(0));
		}
		// A deposit removed from latest state must not be accepted using old finalized data.
		f.finalize();
		f.node.swap_store.lock().remove(&secret);
		assert_eq!(f.snapshot().unwrap().secondary_lock_conf, None);
		assert!(
			f.api
				.prepare_secondary_redeem(&mut f.swap, &f.secp)
				.is_err()
		);
	}
}

#[test]
#[serial]
fn eth_finality_gates_buyer_publication_and_stale_seller_authorization() {
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut f = Fixture::new(currency);
		f.swap.state = StateId::BuyerRedeemMwc;
		let mut pending = f.snapshot().unwrap();
		pending.mwc_lock_conf = Some(f.swap.mwc_confirmations);
		pending.mwc_tip = 0;
		let result =
			fsm::buyer_swap::prepare_mwc_redeem(0, &f.mwc, &mut f.swap, &pending, &mut f.secp, |_| {
				panic!("must not persist a new signature exposure")
			})
			.unwrap();
		assert_eq!(
			result.0.next_state_id,
			StateId::BuyerWaitingForLockConfirmations
		);
		assert!(f.swap.posted_redeem.is_none());
		f.finalize();
		let mut accepted = f.snapshot().unwrap();
		accepted.mwc_lock_conf = Some(f.swap.mwc_confirmations);
		f.swap.role = Role::Seller("private-address".into(), 0);
		f.swap.state = StateId::SellerSendingInitRedeemMessage;
		*f.node.finalized_swap_store.lock() = Some(HashMap::new());
		let mut machine = f.api.get_fsm(&f.keychain, &f.swap);
		assert!(matches!(
			machine.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&accepted,
				&mut f.secp
			),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		assert!(f.swap.message2.is_none());
	}
}

#[test]
#[serial]
fn eth_finality_outage_preserves_cancellation_refunds_and_exposed_recovery() {
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut f = Fixture::new(currency);
		*f.node.finality_error.lock() = Some("finalized RPC unavailable".into());
		assert!(matches!(
			f.snapshot(),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		assert_eq!(
			f.api
				.request_secondary_lock_balance(&f.swap, 1, &f.secp)
				.unwrap()
				.1,
			f.swap.secondary_amount
		);
		let cancel = f
			.api
			.request_tx_confirmations_for_cancel(&f.secp, &f.keychain, &f.swap)
			.unwrap();
		assert_eq!(cancel.secondary_lock_conf, Some(0));
		let mut machine = f.api.get_fsm(&f.keychain, &f.swap);
		machine
			.process(Input::Cancel, &mut f.swap, &f.context, &cancel, &mut f.secp)
			.unwrap();
		assert_eq!(f.swap.state, StateId::BuyerWaitingForRefundTime);
		assert_eq!(
			f.snapshot().unwrap().secondary_lock_amount,
			f.swap.secondary_amount
		);
		f.swap.state = StateId::BuyerRedeemMwc;
		f.swap.posted_redeem = Some(swap::get_cur_time());
		assert_eq!(
			f.snapshot().unwrap().secondary_lock_amount,
			f.swap.secondary_amount
		);
		f.swap.posted_redeem = None;
		swap::set_testing_cur_time(f.swap.get_time_secondary_lock_publish().unwrap() + 1);
		let expired = f.snapshot().unwrap();
		assert_eq!(expired.secondary_lock_amount, f.swap.secondary_amount);
		assert_eq!(expired.secondary_lock_conf, None);
		f.swap.state = StateId::BuyerWaitingForRefundTime;
		let secret = f
			.swap
			.secondary_data
			.unwrap_eth()
			.unwrap()
			.address_from_secret
			.unwrap();
		f.node.swap_store.lock().get_mut(&secret).unwrap().0 = U256::one();
		let refundable = f.snapshot().unwrap();
		machine
			.process(
				Input::Check,
				&mut f.swap,
				&f.context,
				&refundable,
				&mut f.secp,
			)
			.unwrap();
		assert_eq!(f.swap.state, StateId::BuyerPostingRefundForSecondary);
		machine
			.process(
				Input::Execute,
				&mut f.swap,
				&f.context,
				&refundable,
				&mut f.secp,
			)
			.unwrap();
		assert!(
			f.swap
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.refund_tx
				.is_some()
		);
		assert!(f.node.swap_store.lock().is_empty());
	}
}

#[test]
#[serial]
fn eth_finality_unavailable_rejects_new_buyer_context_and_deposit() {
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut f = Fixture::new(currency);
		*f.node.finality_error.lock() = Some("finalized RPC unsupported".into());
		assert!(matches!(
			f.api.create_context(
				&mut f.secp,
				&f.keychain,
				None,
				currency,
				false,
				None,
				0,
				vec![],
				Identifier::zero()
			),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		if currency == Currency::Ether {
			f.node.swap_store.lock().clear();
			assert!(matches!(
				f.api.post_secondary_lock_tx(&mut f.swap),
				Err(Error::EthereumFinalityUnavailable(_))
			));
			assert!(
				f.swap
					.secondary_data
					.unwrap_eth()
					.unwrap()
					.lock_tx
					.is_none()
			);
			assert!(f.node.tx_store.lock().is_empty());
		}
	}
}
