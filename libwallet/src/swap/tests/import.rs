//! Import recovery uses real swap APIs with simulated chains and encrypted storage.

use super::*;
use crate::swap::owner_swap::{recover_imported_trade_state, store_imported_trade};
use mwc_wallet_util::mwc_crates::tempfile::tempdir;
use mwc_wallet_util::mwc_web3::types::{Address as EthAddress, H256, U256};

struct TestEnvironment;

impl TestEnvironment {
	fn new() -> Self {
		set_test_mode(true);
		global::set_local_chain_type(ChainTypes::Floonet);
		swap::set_testing_cur_time(1567632152);
		Self
	}
}

impl Drop for TestEnvironment {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
		trades::trades_clean_context(0);
	}
}

// Exercise the same read/validate/write boundary as the owner import API, and
// return the live record reloaded after the rejected replacement.
pub(super) fn rejected_import_leaves_live_record(
	secp: &Secp256k1,
	context: &Context,
	live: &Swap,
	mut backup: Swap,
	message: &str,
) -> Swap {
	let storage = tempdir().unwrap();
	trades::init_swap_trade_backend(
		0,
		storage.path().to_str().unwrap(),
		&None,
		&None,
		&None,
		&None,
	)
	.unwrap();
	let key = SecretKey::from_slice(secp, &[73; 32]).unwrap();
	let creation_lock = trades::get_swap_creation_lock(0);
	let _creation_guard = creation_lock.lock();
	let lock = trades::get_swap_lock(0, &live.id.to_string()).unwrap();
	let _guard = lock.lock();
	trades::store_swap_trade(0, context, live, &key, &lock).unwrap();
	let path = storage
		.path()
		.join(trades::SWAP_DEAL_SAVE_DIR)
		.join(format!("{}.swap", live.id));
	let before = std::fs::read(&path).unwrap();
	let backup_before = serde_json::to_value(&backup).unwrap();
	let error = store_imported_trade(0, context, &mut backup, &key, &lock, |_| {
		panic!("conflicting backups must be rejected before recovery")
	})
	.unwrap_err();
	assert!(
		matches!(error, Error::InvalidMessageData(ref detail) if detail.contains(message)),
		"{error}"
	);
	assert_eq!(std::fs::read(&path).unwrap(), before);
	assert_eq!(serde_json::to_value(&backup).unwrap(), backup_before);
	let (_, retained) = trades::get_swap_trade(0, &live.id.to_string(), &key, &lock).unwrap();
	assert_eq!(
		serde_json::to_value(&retained).unwrap(),
		serde_json::to_value(live).unwrap()
	);
	retained
}

#[test]
#[serial]
fn import_pending_transactions_without_submission_records_is_atomic() {
	let _environment = TestEnvironment::new();
	global::set_local_nrd_enabled(true);
	global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	for (seller, existing_record) in [(true, false), (false, false), (true, true), (false, true)] {
		let mut backup: Swap = serde_json::from_str(if seller {
			include_str!("../../../swap_test/swap_sell_2.json")
		} else {
			include_str!("../../../swap_test/swap_buy_3.json")
		})
		.unwrap();
		backup.state = if seller {
			StateId::SellerPostingLockMwcSlate
		} else {
			StateId::BuyerRedeemMwc
		};
		backup.posted_lock = None;
		backup.posted_redeem = None;
		let keychain = keychain(&secp, if seller { 1 } else { 2 });
		let context = if seller {
			context_sell(&secp, &keychain)
		} else {
			context_buy(&secp, &keychain)
		};
		let node = TestNodeClient::new(300_000);
		let tx = if seller {
			&backup.lock_slate.slate
		} else {
			&backup.redeem_slate.slate
		}
		.tx_or_err()
		.unwrap();
		for input in tx.inputs_committed().unwrap() {
			node.push_output(input.unwrap());
		}
		// Publication occurred after this backup. The kernel remains pending.
		crate::owner::post_tx(0, &node, tx, false).unwrap();
		let api = BtcSwapApi::new_test(
			Arc::new(node.clone()),
			Arc::new(Mutex::new(TestBtcNodeClient::new(500_000))),
		);
		let storage = tempdir().unwrap();
		trades::init_swap_trade_backend(
			0,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();
		let key = SecretKey::from_slice(&secp, &[73; 32]).unwrap();
		let creation_lock = trades::get_swap_creation_lock(0);
		let _creation_guard = creation_lock.lock();
		let lock = trades::get_swap_lock(0, &backup.id.to_string()).unwrap();
		let _guard = lock.lock();
		let path = storage
			.path()
			.join(trades::SWAP_DEAL_SAVE_DIR)
			.join(format!("{}.swap", backup.id));
		let original_file = if existing_record {
			trades::store_swap_trade(0, &context, &backup, &key, &lock).unwrap();
			Some(std::fs::read(&path).unwrap())
		} else {
			None
		};
		let original_backup = serde_json::to_value(&backup).unwrap();
		for failed_poll in [true, false] {
			node.state.lock().chain_tip_error = if failed_poll {
				Some("injected import poll failure".into())
			} else {
				None
			};
			let error = store_imported_trade(0, &context, &mut backup, &key, &lock, |staged| {
				recover_imported_trade_state(&secp, &keychain, &context, staged, &api)
			})
			.unwrap_err();
			assert!(error.to_string().contains(if failed_poll {
				"injected import poll failure"
			} else {
				"publication is unknown"
			}));
			if let Some(bytes) = &original_file {
				assert_eq!(&std::fs::read(&path).unwrap(), bytes);
			} else {
				assert!(!path.exists());
			}
			assert_eq!(serde_json::to_value(&backup).unwrap(), original_backup);
		}
		// Retrying the same backup succeeds once the original transaction is mined.
		node.mine_block();
		store_imported_trade(0, &context, &mut backup, &key, &lock, |staged| {
			recover_imported_trade_state(&secp, &keychain, &context, staged, &api)
		})
		.unwrap();
		let (_, restored) = trades::get_swap_trade(0, &backup.id.to_string(), &key, &lock).unwrap();
		assert_eq!(
			restored.state,
			if seller {
				StateId::SellerWaitingForLockConfirmations
			} else {
				StateId::BuyerWaitForRedeemMwcConfirmations
			}
		);
		assert!(if seller {
			restored.posted_lock.is_some()
		} else {
			restored.buyer_redeem_is_exposed()
		});
		assert_eq!(node.state.lock().post_calls, 1);
	}
}

#[test]
#[serial]
fn import_healthy_btc_trade_does_not_prepare_a_refund() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut trade, context, keychain, node, btc) = refund_fixture(&secp);
	trade.state = StateId::BuyerWaitingForLockConfirmations;
	trade.posted_redeem = None;
	let early_trade: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_buy_1.json")).unwrap();
	trade.redeem_slate = early_trade.redeem_slate;
	trade.secondary_amount = 200_000;
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	let original_data = serde_json::to_value(&trade.secondary_data).unwrap();
	for _ in 0..2 {
		recover_imported_trade_state(&secp, &keychain, &context, &mut trade, &api).unwrap();
		assert_eq!(trade.state, StateId::BuyerWaitingForLockConfirmations);
		assert_eq!(
			serde_json::to_value(&trade.secondary_data).unwrap(),
			original_data
		);
		assert!(btc.inner.get_state().pending.is_empty());
	}
}

#[test]
#[serial]
fn import_exposed_mwc_redeem_keeps_retrying_after_secondary_funds_disappear() {
	let _environment = TestEnvironment::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut trade, context, keychain, node, btc) = refund_fixture(&secp);
	btc.inner.clean();
	swap::set_testing_cur_time(trade.get_time_mwc_redeem().unwrap() + 1);
	trade.posted_redeem = Some(swap::get_cur_time() - state::POST_MWC_RETRY_PERIOD - 1);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc)));
	let mut confirmations = api
		.request_tx_confirmations(&secp, &keychain, &trade)
		.unwrap();
	assert_eq!(confirmations.mwc_redeem_conf, None);
	assert_eq!(confirmations.secondary_lock_amount, 0);
	recover_imported_trade_state(&secp, &keychain, &context, &mut trade, &api).unwrap();
	assert_eq!(trade.state, StateId::BuyerWaitForRedeemMwcConfirmations);
	let mut fsm = api.get_fsm(&keychain, &trade);
	let response = fsm
		.process(
			Input::Check,
			&mut trade,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishMwcRedeemTx)
	));
	assert!(!fsm.is_cancellable(&trade).unwrap());

	// A mined competing refund suspends retries; losing it to a reorg resumes them.
	confirmations.mwc_refund_conf = Some(1);
	let response = fsm
		.process(
			Input::Check,
			&mut trade,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
	assert_eq!(
		response.next_state_id,
		StateId::BuyerWaitingForMwcRefundConfirmations
	);
	confirmations.mwc_refund_conf = None;
	let response = fsm
		.process(
			Input::Check,
			&mut trade,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishMwcRedeemTx)
	));
}

#[test]
#[serial]
fn import_legacy_redeem_exposure_is_retained_after_successful_poll() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (original, context, keychain, node, btc) = refund_fixture(&secp);
	let api = BtcSwapApi::new_test(Arc::new(node.clone()), Arc::new(Mutex::new(btc.clone())));
	btc.inner.clean();
	for state in [
		StateId::BuyerWaitForRedeemMwcConfirmations,
		StateId::BuyerSwapComplete,
	] {
		let storage = tempdir().unwrap();
		trades::init_swap_trade_backend(
			0,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();
		let key = SecretKey::from_slice(&secp, &[73; 32]).unwrap();
		let creation_lock = trades::get_swap_creation_lock(0);
		let _creation_guard = creation_lock.lock();
		let lock = trades::get_swap_lock(0, &original.id.to_string()).unwrap();
		let _guard = lock.lock();
		let mut trade = original.clone();
		trade.state = state;
		trade.posted_redeem = None;
		node.state.lock().chain_tip_error = Some("injected import poll failure".into());
		assert!(
			store_imported_trade(0, &context, &mut trade, &key, &lock, |staged| {
				recover_imported_trade_state(&secp, &keychain, &context, staged, &api)
			})
			.is_err()
		);
		assert!(
			trades::get_swap_trades_for_import(0, &trade.id.to_string(), &key, &lock)
				.unwrap()
				.is_empty()
		);
		assert!(trade.posted_redeem.is_none());
		node.state.lock().chain_tip_error = None;
		store_imported_trade(0, &context, &mut trade, &key, &lock, |staged| {
			recover_imported_trade_state(&secp, &keychain, &context, staged, &api)
		})
		.unwrap();
		let (_, restored) = trades::get_swap_trade(0, &trade.id.to_string(), &key, &lock).unwrap();
		assert!(restored.buyer_redeem_is_exposed());
		assert_eq!(restored.state, StateId::BuyerWaitForRedeemMwcConfirmations);
	}
}

#[test]
#[serial]
fn import_rejects_missing_exposure_and_replaced_mwc_transaction_before_writing() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (live, context, _, _, _) = refund_fixture(&secp);
	let mut before_publication = live.clone();
	before_publication.state = StateId::BuyerRedeemMwc;
	before_publication.posted_redeem = None;
	for posted_redeem in [live.posted_redeem, None] {
		let mut existing = live.clone();
		existing.posted_redeem = posted_redeem;
		rejected_import_leaves_live_record(
			&secp,
			&context,
			&existing,
			before_publication.clone(),
			"redeem exposure",
		);
	}
	let mut conflicting = live.clone();
	conflicting
		.redeem_slate
		.slate
		.tx_or_err_mut()
		.unwrap()
		.body
		.outputs
		.clear();
	rejected_import_leaves_live_record(
		&secp,
		&context,
		&live,
		conflicting,
		"exposed MWC redeem transaction",
	);
}

#[test]
#[serial]
fn import_rejects_lost_seller_signing_data_without_message_receipts() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let context = context_eth_sell(&secp, &keychain(&secp, 1));
	let before_init: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_sell_3.json")).unwrap();
	let after_init: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
	let observed: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_sell_5.json")).unwrap();
	let expected_secret = SellApi::calculate_redeem_secret(&secp, &observed).unwrap();
	let node = TestNodeClient::new(300_000);
	node.state
		.lock()
		.pending
		.push(observed.redeem_slate.slate.tx_or_err().unwrap().clone());
	node.mine_block();

	for currency in [Currency::Ether, Currency::Usdt] {
		let mut live = after_init.clone();
		let mut stale = before_init.clone();
		let funding = erc20_funding_fixture(currency, live.secondary_amount);
		for trade in [&mut live, &mut stale] {
			trade.secondary_currency = currency;
			trade.secondary_data = funding.secondary_data.clone();
			trade.secondary_fee_units = funding.secondary_fee_units;
			trade
				.set_swap_trade_transport("file".to_string(), "swap-message.json".to_string())
				.unwrap();
			assert!(trade.processed_incoming_ack1.is_none());
			assert!(trade.processed_incoming_ack2.is_none());
		}
		// File delivery can expose the seller's Redeem message without recording
		// an incoming receipt. This backup predates InitRedeem, but retains the
		// lock exposure and all Ethereum transaction recovery records.
		assert!(live.adaptor_signature.is_some());
		assert!(stale.adaptor_signature.is_none());
		assert!(!live.redeem_kernel_updated);
		let mut missing_adaptor = live.clone();
		missing_adaptor.adaptor_signature = None;
		let mut changed_adaptor = live.clone();
		changed_adaptor.adaptor_signature =
			live.redeem_slate.slate.participant_data[0].part_sig;
		let mut missing_partial_signature = live.clone();
		missing_partial_signature.redeem_slate.slate.participant_data[0].part_sig = None;
		let mut missing_participants = live.clone();
		missing_participants.redeem_slate.slate.participant_data.clear();
		let mut changed_participant_id = live.clone();
		changed_participant_id.participant_id = 1;
		let mut missing_redeem_public = live.clone();
		missing_redeem_public.redeem_public = None;

		for backup in [
			stale,
			missing_adaptor,
			changed_adaptor,
			missing_partial_signature,
			missing_participants,
			changed_participant_id,
			missing_redeem_public,
		] {
			let mut retained = rejected_import_leaves_live_record(
				&secp,
				&context,
				&live,
				backup,
				"seller's redeem signing data",
			);
			// The rejected import preserves the data needed to extract the secret
			// when the seller subsequently observes the buyer's MWC redemption.
			assert!(crate::swap::fsm::seller_swap::check_mwc_redeem(&mut retained, &node).unwrap());
			assert_eq!(
				SellApi::calculate_redeem_secret(&secp, &retained).unwrap(),
				expected_secret
			);
		}
	}
}

#[test]
#[serial]
fn import_rejects_lost_seller_redeem_kernel() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, _, node, _) = seller_redeem_fixture(&secp);
	let signed_redeem = live.redeem_slate.slate.tx_or_err().unwrap().clone();
	let before_observation: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_sell_4.json")).unwrap();
	live.redeem_slate
		.slate
		.tx_or_err_mut()
		.unwrap()
		.body
		.kernels = before_observation
		.redeem_slate
		.slate
		.tx_or_err()
		.unwrap()
		.body
		.kernels
		.clone();
	live.redeem_kernel_updated = false;
	live.state = StateId::SellerWaitingForBuyerToRedeemMwc;
	let stale = live.clone();
	assert!(SellApi::calculate_redeem_secret(&secp, &stale).is_err());

	node.state.lock().pending.push(signed_redeem);
	node.mine_block();
	assert!(crate::swap::fsm::seller_swap::check_mwc_redeem(&mut live, &node).unwrap());
	assert!(live.redeem_kernel_updated);
	assert!(live
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_tx
		.is_none());
	assert!(live
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_tx_candidates
		.is_empty());
	let redeem_secret = SellApi::calculate_redeem_secret(&secp, &live).unwrap();

	// A reorg removes the observed kernel before the first secondary redemption.
	// The live record must retain the secret even when chain recovery cannot help.
	node.clean();
	assert!(live.find_redeem_kernel(&node).unwrap().is_none());
	let mut missing_marker = live.clone();
	missing_marker.redeem_kernel_updated = false;
	let mut changed_kernel = live.clone();
	changed_kernel
		.redeem_slate
		.slate
		.tx_or_err_mut()
		.unwrap()
		.body
		.kernels[0] = live.lock_slate.slate.tx_or_err().unwrap().kernels()[0];
	for backup in [stale, missing_marker, changed_kernel] {
		let retained = rejected_import_leaves_live_record(
			&secp,
			&context,
			&live,
			backup,
			"seller's observed MWC redeem",
		);
		assert_eq!(
			SellApi::calculate_redeem_secret(&secp, &retained).unwrap(),
			redeem_secret
		);
	}
}

#[test]
#[serial]
fn import_expired_ethereum_deposit_reaches_the_refund_workflow() {
	let _environment = TestEnvironment::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain(&secp, 2);
	let context = context_eth_buy(&secp, &keychain);
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut trade = erc20_funding_fixture(currency, 100);
		swap::set_testing_cur_time(trade.get_time_secondary_lock_publish().unwrap() + 1);
		let eth = TestEthNodeClient::new(500_000);
		let data = trade.secondary_data.unwrap_eth().unwrap();
		eth.swap_store.lock().insert(
			data.address_from_secret.unwrap(),
			(
				U256::from(499_999),
				if currency.is_erc20() {
					Some(currency.erc20_token_address().unwrap())
				} else {
					None
				},
				EthAddress::repeat_byte(3),
				data.redeem_address.unwrap(),
				100,
			),
		);
		let api = EthSwapApi::new_test(
			Arc::new(TestNodeClient::new(300_000)),
			Arc::new(Mutex::new(eth)),
		);
		let confirmations = (&api as &dyn SwapApi<ExtKeychain>)
			.request_tx_confirmations(&secp, &keychain, &trade)
			.unwrap();
		assert_eq!(confirmations.secondary_lock_conf, None);
		assert_eq!(confirmations.secondary_lock_amount, 100);
		recover_imported_trade_state(&secp, &keychain, &context, &mut trade, &api).unwrap();
		assert_eq!(trade.state, StateId::BuyerWaitingForRefundTime);
		let mut fsm = api.get_fsm(&keychain, &trade);
		let response = fsm
			.process(
				Input::Check,
				&mut trade,
				&context,
				&confirmations,
				&mut secp,
			)
			.unwrap();
		assert!(matches!(
			response.action,
			Some(Action::BuyerPublishSecondaryRefundTx { .. })
		));
	}
}

#[test]
#[serial]
fn import_pending_ethereum_deposit_remains_monitored() {
	let _environment = TestEnvironment::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain(&secp, 2);
	let context = context_eth_buy(&secp, &keychain);
	for currency in [Currency::Ether, Currency::Usdt] {
		for signed_recovery_only in [false, true] {
			let mut trade = erc20_funding_fixture(currency, 100);
			swap::set_testing_cur_time(trade.get_time_secondary_lock_publish().unwrap() + 1);
			let hash = H256::repeat_byte(4);
			let data = trade.secondary_data.unwrap_eth_mut().unwrap();
			if signed_recovery_only {
				data.lock_recovery = Some(eth_transaction_recovery_fixture(vec![hash]));
			} else {
				data.lock_tx = Some(hash);
			}
			let api = EthSwapApi::new_test(
				Arc::new(TestNodeClient::new(300_000)),
				Arc::new(Mutex::new(TestEthNodeClient::new(500_000))),
			);
			recover_imported_trade_state(&secp, &keychain, &context, &mut trade, &api).unwrap();
			assert_eq!(trade.state, StateId::BuyerWaitingForRefundTime);
			let confirmations = api
				.request_tx_confirmations(&secp, &keychain, &trade)
				.unwrap();
			let mut fsm = api.get_fsm(&keychain, &trade);
			let response = fsm
				.process(
					Input::Check,
					&mut trade,
					&context,
					&confirmations,
					&mut secp,
				)
				.unwrap();
			assert_eq!(response.next_state_id, StateId::BuyerWaitingForRefundTime);
			assert!(matches!(
				response.action,
				Some(Action::WaitForSecondaryConfirmations { .. })
			));
		}
	}
}

#[test]
#[serial]
fn import_unfunded_ethereum_trade_can_still_cancel() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain(&secp, 2);
	let context = context_eth_buy(&secp, &keychain);
	let mut trade = erc20_funding_fixture(Currency::Ether, 100);
	let api = EthSwapApi::new_test(
		Arc::new(TestNodeClient::new(300_000)),
		Arc::new(Mutex::new(TestEthNodeClient::new(500_000))),
	);
	recover_imported_trade_state(&secp, &keychain, &context, &mut trade, &api).unwrap();
	assert_eq!(trade.state, StateId::BuyerCancelled);
}

#[test]
#[serial]
fn import_deleted_ethereum_trade_uses_selected_backup() {
	use crate::swap::ethereum::{funding, recovery};

	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain(&secp, 2);
	let context = context_eth_buy(&secp, &keychain);
	let key = SecretKey::from_slice(&secp, &[73; 32]).unwrap();
	// Deleted copies do not constrain the selected backup, including when both
	// archive directories contain different snapshots of the same trade.
	for (marketplace, older_archive) in [(false, false), (true, false), (true, true)] {
		let storage = tempdir().unwrap();
		trades::init_swap_trade_backend(
			0,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)
		.unwrap();
		let creation_lock = trades::get_swap_creation_lock(0);
		let _creation_guard = creation_lock.lock();
		let archive = |trade: &Swap| {
			let lock = trades::get_swap_lock(0, &trade.id.to_string()).unwrap();
			let _guard = lock.lock();
			trades::store_swap_trade(0, &context, trade, &key, &lock).unwrap();
			trades::delete_swap_trade(0, &trade.id.to_string(), &key, &lock, false).unwrap();
		};
		let node = TestEthNodeClient::new(1);
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
			0,
			Currency::Usdt,
			Arc::new(TestNodeClient::new(1)),
			Arc::new(Mutex::new(node.clone())),
		));
		let mut live = erc20_funding_fixture(Currency::Usdt, 100);
		if older_archive {
			let mut previous = live.clone();
			previous.state = StateId::BuyerCancelled;
			archive(&previous);
		}
		if marketplace {
			live.tag = Some("archived-approval-offer".to_string());
		}
		let mut stale = live.clone();
		api.post_secondary_lock_tx(&mut live).unwrap();
		let approval = live
			.secondary_data
			.unwrap_eth()
			.unwrap()
			.erc20_approval_recovery
			.clone()
			.unwrap();
		let allowance_key = node.erc20_allowance_key(Currency::Usdt).unwrap();
		live.state = crate::swap::fsm::buyer_swap::buyer_cancellation_state(&live, 0).unwrap();
		assert_eq!(live.state, StateId::BuyerCancelled);
		archive(&live);

		let root = storage.path().join(trades::SWAP_DEAL_SAVE_DIR);
		let active_path = root.join(format!("{}.swap", live.id));
		let archives: Vec<_> = [
			trades::SWAP_DEAL_DELETED_DIR,
			trades::SWAP_DEAL_MKT_DELETED_DIR,
		]
		.into_iter()
		.map(|dir| root.join(dir).join(format!("{}.swap.del", live.id)))
		.filter(|path| path.exists())
		.map(|path| {
			let bytes = std::fs::read(&path).unwrap();
			(path, bytes)
		})
		.collect();
		assert_eq!(archives.len(), if older_archive { 2 } else { 1 });
		let stale_before = serde_json::to_value(&stale).unwrap();
		assert!(!active_path.exists());

		let assert_restored_reservations = || {
			funding::forget_for_test(allowance_key);
			recovery::forget_for_test(approval.chain_id, approval.sender);
			trades::restore_ethereum_resources(0, None, &key).unwrap();
			assert!(matches!(
				recovery::next_nonce(
					approval.chain_id,
					approval.sender,
					approval.nonce,
					approval.nonce
				),
				Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == approval.nonce
			));
			let mut competing = erc20_funding_fixture(Currency::Usdt, 200);
			assert!(matches!(
				api.post_secondary_lock_tx(&mut competing),
				Err(Error::EthTransactionInPending)
			));
			assert_eq!(node.tx_store.lock().len(), 1);
		};
		assert_restored_reservations();

		// Import accepts the user's older backup and leaves the archives intact.
		{
			let lock = trades::get_swap_lock(0, &live.id.to_string()).unwrap();
			let _guard = lock.lock();
			store_imported_trade(0, &context, &mut stale, &key, &lock, |_| Ok(())).unwrap();
			let (_, restored) =
				trades::get_swap_trade(0, &live.id.to_string(), &key, &lock).unwrap();
			assert_eq!(serde_json::to_value(&restored).unwrap(), stale_before);
		}
		assert!(active_path.exists());
		for (path, bytes) in &archives {
			assert_eq!(&std::fs::read(path).unwrap(), bytes);
		}
		// On restart, the imported active record supersedes the newer archives.
		funding::forget_for_test(allowance_key);
		recovery::forget_for_test(approval.chain_id, approval.sender);
		trades::restore_ethereum_resources(0, None, &key).unwrap();
		assert_eq!(
			recovery::next_nonce(
				approval.chain_id,
				approval.sender,
				approval.nonce,
				approval.nonce
			)
			.unwrap(),
			approval.nonce
		);

		// Choosing a backup with the approval restores both reservations.
		{
			let lock = trades::get_swap_lock(0, &live.id.to_string()).unwrap();
			let _guard = lock.lock();
			let mut matching = live.clone();
			store_imported_trade(0, &context, &mut matching, &key, &lock, |_| Ok(())).unwrap();
			let (_, restored) =
				trades::get_swap_trade(0, &live.id.to_string(), &key, &lock).unwrap();
			assert_eq!(
				serde_json::to_value(&restored).unwrap(),
				serde_json::to_value(&live).unwrap()
			);
		}
		assert_restored_reservations();
		// Recovery data in an active trade remains protected against stale imports.
		{
			let lock = trades::get_swap_lock(0, &live.id.to_string()).unwrap();
			let _guard = lock.lock();
			let error =
				store_imported_trade(0, &context, &mut stale, &key, &lock, |_| Ok(())).unwrap_err();
			assert!(
				matches!(error, Error::InvalidMessageData(ref message) if message.contains("Ethereum transaction recovery")),
				"{error}"
			);
		}
		funding::forget_for_test(allowance_key);
		recovery::forget_for_test(approval.chain_id, approval.sender);
	}
}

#[test]
#[serial]
fn import_deleted_btc_trade_uses_selected_backup() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = refund_fixture(&secp);
	let mut backup = live.clone();
	let backup_data = serde_json::to_value(&backup.secondary_data).unwrap();
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc)));
	api.prepare_secondary_refund(&secp, &keychain, &context, &mut live)
		.unwrap();
	assert!(
		live.secondary_data
			.unwrap_btc()
			.unwrap()
			.refund_plan
			.is_some()
	);
	live.state = StateId::BuyerCancelledRefunded;

	let storage = tempdir().unwrap();
	trades::init_swap_trade_backend(
		0,
		storage.path().to_str().unwrap(),
		&None,
		&None,
		&None,
		&None,
	)
	.unwrap();
	let key = SecretKey::from_slice(&secp, &[73; 32]).unwrap();
	let creation_lock = trades::get_swap_creation_lock(0);
	let _creation_guard = creation_lock.lock();
	let lock = trades::get_swap_lock(0, &live.id.to_string()).unwrap();
	let _guard = lock.lock();
	trades::store_swap_trade(0, &context, &live, &key, &lock).unwrap();
	trades::delete_swap_trade(0, &live.id.to_string(), &key, &lock, false).unwrap();
	let archive_path = storage
		.path()
		.join(trades::SWAP_DEAL_SAVE_DIR)
		.join(trades::SWAP_DEAL_DELETED_DIR)
		.join(format!("{}.swap.del", live.id));
	let archived_bytes = std::fs::read(&archive_path).unwrap();

	store_imported_trade(0, &context, &mut backup, &key, &lock, |_| Ok(())).unwrap();
	let (_, restored) = trades::get_swap_trade(0, &live.id.to_string(), &key, &lock).unwrap();
	assert_eq!(
		serde_json::to_value(&restored.secondary_data).unwrap(),
		backup_data
	);
	assert_eq!(std::fs::read(&archive_path).unwrap(), archived_bytes);
}

#[test]
#[serial]
fn import_btc_redeem_rejects_missing_or_changed_inputs() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = funding_limit_fixture(&secp, 2);
	let stale = live.clone();
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc)));
	(&api as &dyn SwapApi<ExtKeychain>)
		.prepare_secondary_redeem(&mut live, &secp)
		.unwrap();
	let mut retained = rejected_import_leaves_live_record(
		&secp,
		&context,
		&live,
		stale,
		"BTC redemption recovery",
	);
	// The rejected import leaves the seller able to sign and collect the BTC.
	api.publish_secondary_transaction(&secp, &keychain, &mut retained, &context, true)
		.unwrap();

	let inputs = live
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.redeem_inputs
		.clone()
		.unwrap();
	let mut changed_amounts = inputs.clone();
	changed_amounts[0].value += 1;
	changed_amounts[1].value -= 1;
	let mut changed_height = inputs.clone();
	changed_height[0].height += 1;
	let mut changed_outpoint = inputs;
	changed_outpoint[0].out_point.vout += 2;
	// Even unchanged outpoints and an unchanged total must not hide modified
	// amounts or heights behind Output's outpoint-only PartialEq.
	for inputs in [
		Vec::new(),
		changed_amounts,
		changed_height,
		changed_outpoint,
	] {
		let mut backup = live.clone();
		backup
			.secondary_data
			.unwrap_btc_mut()
			.unwrap()
			.redeem_inputs = Some(inputs);
		rejected_import_leaves_live_record(
			&secp,
			&context,
			&live,
			backup,
			"BTC redemption recovery",
		);
	}
}

#[test]
#[serial]
fn import_btc_redeem_rejects_lost_broadcast_and_replacement_hashes() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = seller_redeem_fixture(&secp);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	let before_broadcast = live.clone();
	btc.post_error.store(2, Ordering::SeqCst);
	assert!(
		api.publish_secondary_transaction(&secp, &keychain, &mut live, &context, true)
			.is_err()
	);
	assert!(
		live.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_tx
			.is_none()
	);
	assert_eq!(
		live.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_tx_candidates
			.len(),
		1
	);
	rejected_import_leaves_live_record(
		&secp,
		&context,
		&live,
		before_broadcast,
		"BTC redemption recovery",
	);

	btc.post_error.store(0, Ordering::SeqCst);
	api.publish_secondary_transaction(&secp, &keychain, &mut live, &context, true)
		.unwrap();
	let before_replacement = live.clone();
	live.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
	api.publish_secondary_transaction(&secp, &keychain, &mut live, &context, true)
		.unwrap();
	let mut missing_current = live.clone();
	missing_current
		.secondary_data
		.unwrap_btc_mut()
		.unwrap()
		.redeem_tx = None;
	let mut missing_predecessor = live.clone();
	missing_predecessor
		.secondary_data
		.unwrap_btc_mut()
		.unwrap()
		.redeem_tx_candidates
		.clear();
	for backup in [before_replacement, missing_current, missing_predecessor] {
		rejected_import_leaves_live_record(
			&secp,
			&context,
			&live,
			backup,
			"BTC redemption recovery",
		);
	}
}

#[test]
#[serial]
fn import_btc_redeem_retains_signed_attempts() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = seller_redeem_fixture(&secp);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	api.publish_secondary_transaction(&secp, &keychain, &mut live, &context, true)
		.unwrap();
	btc.post_error.store(2, Ordering::SeqCst);
	live.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
	assert!(
		api.publish_secondary_transaction(&secp, &keychain, &mut live, &context, true)
			.is_err()
	);
	assert_eq!(
		live.secondary_data.unwrap_btc().unwrap().redeem_attempts.len(),
		2
	);
	// Keeping every hash is insufficient if a backup loses or changes the
	// original bytes used to validate a confirmed scriptSig variant.
	for mutation in 0..3 {
		let mut backup = live.clone();
		let attempts = &mut backup
			.secondary_data
			.unwrap_btc_mut()
			.unwrap()
			.redeem_attempts;
		match mutation {
			0 => attempts.clear(),
			1 => {
				attempts.remove(0);
			}
			_ => attempts[0].tx[0] ^= 1,
		}
		rejected_import_leaves_live_record(
			&secp,
			&context,
			&live,
			backup,
			"BTC redemption recovery",
		);
	}
}

#[test]
#[serial]
fn import_btc_redeem_allows_newer_and_matching_recovery() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut trade, context, keychain, node, btc) = seller_redeem_fixture(&secp);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	let mut before_preparation = trade.clone();
	before_preparation
		.secondary_data
		.unwrap_btc_mut()
		.unwrap()
		.redeem_inputs = None;
	let mut snapshots = vec![before_preparation, trade.clone()];
	btc.post_error.store(2, Ordering::SeqCst);
	assert!(
		api.publish_secondary_transaction(&secp, &keychain, &mut trade, &context, true)
			.is_err()
	);
	snapshots.push(trade.clone());
	btc.post_error.store(0, Ordering::SeqCst);
	api.publish_secondary_transaction(&secp, &keychain, &mut trade, &context, true)
		.unwrap();
	snapshots.push(trade.clone());
	trade.secondary_fee_units = SecondaryFeeUnits::RatePerKvb(20_000);
	api.publish_secondary_transaction(&secp, &keychain, &mut trade, &context, true)
		.unwrap();
	snapshots.push(trade);

	let storage = tempdir().unwrap();
	trades::init_swap_trade_backend(
		0,
		storage.path().to_str().unwrap(),
		&None,
		&None,
		&None,
		&None,
	)
	.unwrap();
	let key = SecretKey::from_slice(&secp, &[73; 32]).unwrap();
	let creation_lock = trades::get_swap_creation_lock(0);
	let _creation_guard = creation_lock.lock();
	let lock = trades::get_swap_lock(0, &snapshots[0].id.to_string()).unwrap();
	let _guard = lock.lock();
	trades::store_swap_trade(0, &context, &snapshots[0], &key, &lock).unwrap();
	// Preparation adds inputs, a successful retry promotes a candidate to the
	// current hash, and replacement moves that hash back into the history.
	for mut backup in snapshots {
		let expected = serde_json::to_value(&backup.secondary_data).unwrap();
		for _ in 0..2 {
			store_imported_trade(0, &context, &mut backup, &key, &lock, |_| Ok(())).unwrap();
			let (_, restored) =
				trades::get_swap_trade(0, &backup.id.to_string(), &key, &lock).unwrap();
			assert_eq!(
				serde_json::to_value(&restored.secondary_data).unwrap(),
				expected
			);
		}
	}
}

#[test]
#[serial]
fn import_rejects_missing_or_conflicting_btc_refund_records() {
	let _environment = TestEnvironment::new();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = refund_fixture(&secp);
	live.state = StateId::BuyerWaitingForRefundTime;
	live.posted_redeem = None;
	swap::set_testing_cur_time(live.get_time_secondary_lock_publish().unwrap() + 1);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc)));
	api.prepare_secondary_refund(&secp, &keychain, &context, &mut live)
		.unwrap();
	let address = live.unwrap_buyer().unwrap();
	api.post_secondary_refund_tx(&secp, &keychain, &context, &mut live, address, true)
		.unwrap();
	for field in ["refund_plan", "refund_transaction", "refund_tx"] {
		let mut backup = live.clone();
		let mut data = serde_json::to_value(&backup.secondary_data).unwrap();
		data["Btc"][field] = serde_json::Value::Null;
		backup.secondary_data = serde_json::from_value(data).unwrap();
		rejected_import_leaves_live_record(&secp, &context, &live, backup, "BTC refund recovery");
	}
	// The same outpoint with a changed value is not the same recovery record.
	// Output's outpoint-only equality must not hide either difference.
	let mut backup = live.clone();
	backup
		.secondary_data
		.unwrap_btc_mut()
		.unwrap()
		.refund_transaction
		.as_mut()
		.unwrap()
		.inputs[0]
		.value += 1;
	rejected_import_leaves_live_record(&secp, &context, &live, backup, "BTC refund recovery");
	let mut backup = live.clone();
	backup
		.secondary_data
		.unwrap_btc_mut()
		.unwrap()
		.refund_plan
		.as_mut()
		.unwrap()
		.batches[0]
		.attempts[0]
		.inputs[0]
		.value += 1;
	rejected_import_leaves_live_record(&secp, &context, &live, backup, "BTC refund recovery");
}

#[test]
#[serial]
fn import_stale_backup_cannot_erase_a_confirmed_btc_refund_carry() {
	let _environment = TestEnvironment::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut live, context, keychain, node, btc) = refund_fixture(&secp);
	live.state = StateId::BuyerWaitingForRefundTime;
	live.posted_redeem = None;
	// This partially funded trade never reached MWC redeem signing.
	let early_trade: Swap =
		serde_json::from_str(include_str!("../../../swap_test/swap_buy_1.json")).unwrap();
	live.redeem_slate = early_trade.redeem_slate;
	let backup = live.clone();
	swap::set_testing_cur_time(live.get_time_secondary_lock_publish().unwrap() + 1);
	let api = BtcSwapApi::new_test(Arc::new(node), Arc::new(Mutex::new(btc.clone())));
	let script = api.script(&live, &secp).unwrap();
	btc.inner.clean();
	refund_funding(&btc, &script, &[100_000; 33], 0);
	api.prepare_secondary_refund(&secp, &keychain, &context, &mut live)
		.unwrap();
	let carry = live
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.refund_transaction
		.as_ref()
		.unwrap()
		.carry_output
		.clone()
		.unwrap();
	let address = live.unwrap_buyer().unwrap();
	api.post_secondary_refund_tx(&secp, &keychain, &context, &mut live, address, true)
		.unwrap();
	btc.inner.mine_blocks(live.secondary_confirmations);
	let mut retained =
		rejected_import_leaves_live_record(&secp, &context, &live, backup, "BTC refund recovery");
	recover_imported_trade_state(&secp, &keychain, &context, &mut retained, &api).unwrap();
	assert_eq!(retained.state, StateId::BuyerWaitingForRefundConfirmations);
	let confirmations = api
		.request_tx_confirmations(&secp, &keychain, &retained)
		.unwrap();
	let mut fsm = api.get_fsm(&keychain, &retained);
	let response = fsm
		.process(
			Input::Check,
			&mut retained,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
	assert!(matches!(
		response.action,
		Some(Action::BuyerPublishSecondaryRefundTx { .. })
	));
	api.prepare_secondary_refund(&secp, &keychain, &context, &mut retained)
		.unwrap();
	let next = retained
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.refund_transaction
		.as_ref()
		.unwrap();
	assert!(
		next.inputs
			.iter()
			.any(|input| input.out_point == carry.out_point)
	);
	let address = retained.unwrap_buyer().unwrap();
	api.post_secondary_refund_tx(&secp, &keychain, &context, &mut retained, address, true)
		.unwrap();
	btc.inner.mine_blocks(retained.secondary_confirmations);
	let confirmations = api
		.request_tx_confirmations(&secp, &keychain, &retained)
		.unwrap();
	let response = fsm
		.process(
			Input::Check,
			&mut retained,
			&context,
			&confirmations,
			&mut secp,
		)
		.unwrap();
	assert_eq!(response.next_state_id, StateId::BuyerCancelledRefunded);
}
