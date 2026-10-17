//! Regression tests for seller funding instructions and unavailable roadmap timing.

use super::*;
use crate::swap::fsm::state::StateEtaInfo;

struct Fixture {
	secp: Secp256k1,
	keychain: ExtKeychain,
	trade: Swap,
	node: Arc<TestNodeClient>,
}

impl Fixture {
	fn new() -> Self {
		global::set_local_chain_type(ChainTypes::Floonet);
		swap::set_testing_cur_time(1567632152);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = keychain(&secp, 1);
		let mut trade: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_sell_2.json")).unwrap();
		trade.seller_lock_first = false;
		Self {
			secp,
			keychain,
			trade,
			node: Arc::new(TestNodeClient::new(300_000)),
		}
	}

	fn btc_api(&self) -> BtcSwapApi<'static, TestNodeClient, TestBtcNodeClient> {
		let btc_node = Arc::new(Mutex::new(TestBtcNodeClient::new(500_000)));
		BtcSwapApi::new(
			0,
			self.trade.secondary_currency,
			self.node.clone(),
			btc_node.clone(),
			btc_node,
		)
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
	}
}

fn active_eta(fsm: &StateMachine<'_>, trade: &Swap, secp: &Secp256k1) -> StateEtaInfo {
	let mut active = fsm
		.get_swap_roadmap(trade, secp)
		.unwrap()
		.into_iter()
		.filter(|eta| eta.active);
	let eta = active
		.next()
		.expect("The current roadmap step must remain visible");
	assert!(active.next().is_none());
	eta
}

#[test]
#[serial]
fn seller_ethereum_funding_uses_contract_instructions() {
	for currency in [Currency::Ether, Currency::Usdt] {
		let mut f = Fixture::new();
		f.trade.secondary_currency = currency;
		f.trade.secondary_data = erc20_funding_fixture(currency, 100).secondary_data;
		let api: Box<dyn SwapApi<ExtKeychain>> = Box::new(EthSwapApi::new(
			0,
			currency,
			f.node.clone(),
			Arc::new(Mutex::new(TestEthNodeClient::new(1))),
		));
		let trade_index = api.get_secondary_lock_address(&f.trade, &f.secp).unwrap();
		assert!(!trade_index[0].is_empty());
		for state in [
			StateId::SellerWaitingForBuyerLock,
			StateId::SellerWaitingForLockConfirmations,
		] {
			f.trade.state = state;
			let fsm = api.get_fsm(&f.keychain, &f.trade);
			let eta = active_eta(&fsm, &f.trade, &f.secp);
			assert!(eta.name.contains("swap contract"));
			assert!(eta.name.contains(&currency.to_string()));
			assert!(
				fsm.get_swap_roadmap(&f.trade, &f.secp)
					.unwrap()
					.iter()
					.all(|eta| !eta.name.contains(&trade_index[0]))
			);
			let deadline = match f.trade.state {
				StateId::SellerWaitingForBuyerLock => {
					assert!(eta.name.contains("Buyer"));
					assert!(eta.name.contains("wallet"));
					f.trade.get_time_start_lock().unwrap()
				}
				_ => f.trade.get_time_message_redeem().unwrap(),
			};
			assert_eq!(eta.end_time, Some(deadline));
		}
	}
}

#[test]
#[serial]
fn seller_btc_funding_preserves_all_lock_addresses() {
	for currency in [Currency::Btc, Currency::Bch] {
		let mut f = Fixture::new();
		f.trade.secondary_currency = currency;
		let api = f.btc_api();
		let addresses =
			<_ as SwapApi<ExtKeychain>>::get_secondary_lock_address(&api, &f.trade, &f.secp)
				.unwrap();
		assert_eq!(
			addresses.len(),
			if currency == Currency::Bch { 2 } else { 1 }
		);
		for state in [
			StateId::SellerWaitingForBuyerLock,
			StateId::SellerWaitingForLockConfirmations,
		] {
			f.trade.state = state;
			let fsm = api.get_fsm(&f.keychain, &f.trade);
			let eta = active_eta(&fsm, &f.trade, &f.secp);
			assert!(addresses.iter().all(|address| eta.name.contains(address)));
			assert!(!eta.name.contains("swap contract"));
			let deadline = match f.trade.state {
				StateId::SellerWaitingForBuyerLock => f.trade.get_time_start_lock().unwrap(),
				_ => f.trade.get_time_message_redeem().unwrap(),
			};
			assert_eq!(eta.end_time, Some(deadline));
		}
	}
}

#[test]
#[serial]
fn seller_buyer_lock_address_errors_remain_visible_and_recover() {
	let mut f = Fixture::new();
	f.trade.state = StateId::SellerWaitingForBuyerLock;
	let api = f.btc_api();
	let fsm = api.get_fsm(&f.keychain, &f.trade);
	let refund = f.trade.secondary_data.unwrap_btc().unwrap().refund;
	let deadline = f.trade.get_time_start_lock().unwrap();
	for unavailable in [false, true, false] {
		f.trade.secondary_data.unwrap_btc_mut().unwrap().refund =
			if unavailable { None } else { refund };
		let eta = active_eta(&fsm, &f.trade, &f.secp);
		assert!(eta.name.starts_with("Waiting For Buyer to send"));
		assert_eq!(eta.end_time, Some(deadline));
		if unavailable {
			assert!(eta.name.contains("unable to determine lock address"));
			assert!(eta
				.name
				.contains(&Error::SecondaryDataIncomplete.to_string()));
		} else {
			let addresses =
				<_ as SwapApi<ExtKeychain>>::get_secondary_lock_address(&api, &f.trade, &f.secp)
					.unwrap();
			assert!(addresses.iter().all(|address| eta.name.contains(address)));
			assert!(!eta.name.contains("unable to determine"));
		}
	}
}

#[test]
#[serial]
fn seller_buyer_lock_address_is_pending_only_before_acceptance() {
	let mut f = Fixture::new();
	f.trade.redeem_public = None;
	f.trade.secondary_data.unwrap_btc_mut().unwrap().refund = None;
	let api = f.btc_api();
	let fsm = api.get_fsm(&f.keychain, &f.trade);
	let deadline = f.trade.get_time_start_lock().unwrap();
	for state in [
		StateId::SellerOfferCreated,
		StateId::SellerSendingOffer,
		StateId::SellerWaitingForAcceptanceMessage,
	] {
		f.trade.state = state;
		let roadmap = fsm.get_swap_roadmap(&f.trade, &f.secp).unwrap();
		let eta = roadmap
			.iter()
			.find(|eta| eta.name.starts_with("Waiting For Buyer to send"))
			.expect("The future buyer funding step must remain visible");
		assert!(!eta.active);
		assert!(eta
			.name
			.contains("lock address available after offer acceptance"));
		assert!(!eta.name.contains("unable to determine"));
		assert_eq!(eta.end_time, Some(deadline));
	}
	f.trade.state = StateId::SellerWaitingForBuyerLock;
	let eta = active_eta(&fsm, &f.trade, &f.secp);
	let error = <_ as SwapApi<ExtKeychain>>::get_secondary_lock_address(&api, &f.trade, &f.secp)
		.unwrap_err();
	assert!(eta.name.contains("unable to determine lock address"));
	assert!(eta.name.contains(&error.to_string()));
	assert_eq!(eta.end_time, Some(deadline));
}

#[test]
#[serial]
fn seller_buyer_lock_timing_errors_keep_active_step_and_recover() {
	for currency in [Currency::Btc, Currency::Ether] {
		let mut f = Fixture::new();
		f.trade.secondary_currency = currency;
		f.trade.state = StateId::SellerWaitingForBuyerLock;
		let api: Box<dyn SwapApi<ExtKeychain>> = if currency.is_btc_family() {
			Box::new(f.btc_api())
		} else {
			f.trade.secondary_data = erc20_funding_fixture(currency, 100).secondary_data;
			Box::new(EthSwapApi::new(
				0,
				currency,
				f.node.clone(),
				Arc::new(Mutex::new(TestEthNodeClient::new(1))),
			))
		};
		let fsm = api.get_fsm(&f.keychain, &f.trade);
		let interval = f.trade.message_exchange_time_sec;
		let deadline = f.trade.get_time_start_lock().unwrap();
		for unavailable in [false, true, false] {
			f.trade.message_exchange_time_sec = if unavailable { u64::MAX } else { interval };
			let eta = active_eta(&fsm, &f.trade, &f.secp);
			assert_eq!(eta.start_time, None);
			if unavailable {
				let error = f.trade.get_time_start_lock().unwrap_err();
				assert!(eta.name.contains("unable to determine deadline"));
				assert!(eta.name.contains(&error.to_string()));
				assert_eq!(eta.end_time, None);
				if currency.is_btc_family() {
					assert!(eta.name.contains("unable to determine lock address"));
				}
			} else {
				assert!(!eta.name.contains("unable to determine"));
				assert_eq!(eta.end_time, Some(deadline));
			}
		}
		f.trade.seller_lock_first = true;
		assert!(!fsm
			.get_swap_roadmap(&f.trade, &f.secp)
			.unwrap()
			.iter()
			.any(|eta| eta.active));
	}
}

#[test]
#[serial]
fn seller_lock_confirmations_address_errors_remain_visible_and_recover() {
	let mut f = Fixture::new();
	f.trade.state = StateId::SellerWaitingForLockConfirmations;
	let api = f.btc_api();
	let fsm = api.get_fsm(&f.keychain, &f.trade);
	let refund = f.trade.secondary_data.unwrap_btc().unwrap().refund;
	let deadline = f.trade.get_time_message_redeem().unwrap();
	for unavailable in [false, true, false] {
		f.trade.secondary_data.unwrap_btc_mut().unwrap().refund =
			if unavailable { None } else { refund };
		let eta = active_eta(&fsm, &f.trade, &f.secp);
		assert!(eta
			.name
			.starts_with("Waiting for Lock funds confirmations."));
		assert_eq!(eta.end_time, Some(deadline));
		if unavailable {
			assert!(eta.name.contains("unable to determine lock address"));
			assert!(eta
				.name
				.contains(&Error::SecondaryDataIncomplete.to_string()));
		} else {
			let addresses =
				<_ as SwapApi<ExtKeychain>>::get_secondary_lock_address(&api, &f.trade, &f.secp)
					.unwrap();
			assert!(addresses.iter().all(|address| eta.name.contains(address)));
			assert!(!eta.name.contains("unable to determine"));
		}
	}
}

#[test]
#[serial]
fn seller_lock_confirmations_address_is_pending_only_before_acceptance() {
	let mut f = Fixture::new();
	f.trade.redeem_public = None;
	f.trade.secondary_data.unwrap_btc_mut().unwrap().refund = None;
	let api = f.btc_api();
	let fsm = api.get_fsm(&f.keychain, &f.trade);
	let deadline = f.trade.get_time_message_redeem().unwrap();
	for state in [
		StateId::SellerOfferCreated,
		StateId::SellerSendingOffer,
		StateId::SellerWaitingForAcceptanceMessage,
	] {
		f.trade.state = state;
		let roadmap = fsm.get_swap_roadmap(&f.trade, &f.secp).unwrap();
		let eta = roadmap
			.iter()
			.find(|eta| {
				eta.name
					.starts_with("Waiting for Lock funds confirmations.")
			})
			.expect("The future lock confirmation step must remain visible");
		assert!(!eta.active);
		assert!(eta
			.name
			.contains("lock address available after offer acceptance"));
		assert!(!eta.name.contains("unable to determine"));
		assert_eq!(eta.end_time, Some(deadline));
	}
	f.trade.state = StateId::SellerWaitingForLockConfirmations;
	let eta = active_eta(&fsm, &f.trade, &f.secp);
	let error = <_ as SwapApi<ExtKeychain>>::get_secondary_lock_address(&api, &f.trade, &f.secp)
		.unwrap_err();
	assert!(eta.name.contains("unable to determine lock address"));
	assert!(eta.name.contains(&error.to_string()));
	assert!(!eta
		.name
		.contains("lock address available after offer acceptance"));
	assert_eq!(eta.end_time, Some(deadline));
}

#[test]
#[serial]
fn seller_lock_confirmations_timing_errors_keep_active_step_and_recover() {
	for currency in [Currency::Btc, Currency::Ether] {
		let mut f = Fixture::new();
		f.trade.secondary_currency = currency;
		f.trade.state = StateId::SellerWaitingForLockConfirmations;
		let api: Box<dyn SwapApi<ExtKeychain>> = if currency.is_btc_family() {
			Box::new(f.btc_api())
		} else {
			f.trade.secondary_data = erc20_funding_fixture(currency, 100).secondary_data;
			Box::new(EthSwapApi::new(
				0,
				currency,
				f.node.clone(),
				Arc::new(Mutex::new(TestEthNodeClient::new(1))),
			))
		};
		let fsm = api.get_fsm(&f.keychain, &f.trade);
		let interval = f.trade.message_exchange_time_sec;
		let deadline = f.trade.get_time_message_redeem().unwrap();
		for unavailable in [false, true, false] {
			f.trade.message_exchange_time_sec = if unavailable { u64::MAX } else { interval };
			let eta = active_eta(&fsm, &f.trade, &f.secp);
			assert_eq!(eta.start_time, None);
			if unavailable {
				let error = f.trade.get_time_message_redeem().unwrap_err();
				assert!(eta.name.contains("unable to determine deadline"));
				assert!(eta.name.contains(&error.to_string()));
				assert_eq!(eta.end_time, None);
				if currency.is_btc_family() {
					assert!(eta.name.contains("unable to determine lock address"));
				}
			} else {
				assert!(!eta.name.contains("unable to determine"));
				assert_eq!(eta.end_time, Some(deadline));
			}
		}
	}
}

#[test]
#[serial]
fn seller_node_failure_keeps_active_step_and_recovery_restores_timing() {
	let mut f = Fixture::new();
	let api = f.btc_api();
	let lock_height = f.trade.refund_slate.slate.calc_lock_height().unwrap();
	f.node.state.lock().height = lock_height - 10;
	let unlock_time = swap::get_cur_time() + 600;
	for (state, name) in [
		(
			StateId::SellerWaitingForBuyerToRedeemMwc,
			"Wait For Buyer to redeem MWC",
		),
		(
			StateId::SellerWaitingForRefundHeight,
			"Wait for MWC refund to unlock",
		),
		(StateId::SellerPostingRefundSlate, "Post MWC Refund Slate"),
	] {
		f.trade.state = state;
		let fsm = api.get_fsm(&f.keychain, &f.trade);
		for unavailable in [false, true, false] {
			f.node.state.lock().chain_tip_error = unavailable.then(|| "node unavailable".into());
			let eta = active_eta(&fsm, &f.trade, &f.secp);
			assert!(eta.name.starts_with(name));
			if unavailable {
				assert!(eta.name.contains("unable to determine"));
				assert!(eta.name.contains("node unavailable"));
				assert_eq!(eta.start_time, None);
				assert_eq!(eta.end_time, None);
			} else {
				assert_eq!(eta.name, name);
				if f.trade.state == StateId::SellerPostingRefundSlate {
					assert_eq!(eta.start_time, Some(unlock_time));
					assert_eq!(
						eta.end_time,
						Some(unlock_time + i64::try_from(f.trade.redeem_time_sec).unwrap())
					);
				} else {
					assert_eq!(eta.start_time, None);
					assert_eq!(eta.end_time, Some(unlock_time));
				}
			}
		}
	}
}

#[test]
#[serial]
fn seller_timing_errors_do_not_hide_active_step() {
	let mut f = Fixture::new();
	let api = f.btc_api();
	f.trade
		.refund_slate
		.slate
		.set_lock_height_no_check(u64::MAX);
	for state in [
		StateId::SellerWaitingForBuyerToRedeemMwc,
		StateId::SellerWaitingForRefundHeight,
		StateId::SellerPostingRefundSlate,
	] {
		f.trade.state = state;
		let fsm = api.get_fsm(&f.keychain, &f.trade);
		let eta = active_eta(&fsm, &f.trade, &f.secp);
		assert!(eta.name.contains("unable to determine"));
		assert!(eta.name.contains("overflow"));
		assert_eq!(eta.start_time, None);
		assert_eq!(eta.end_time, None);
	}
	f.trade.refund_slate.slate.set_lock_height_no_check(300_000);
	for interval in [u64::MAX, u64::try_from(i64::MAX).unwrap()] {
		f.trade.redeem_time_sec = interval;
		let fsm = api.get_fsm(&f.keychain, &f.trade);
		let eta = active_eta(&fsm, &f.trade, &f.secp);
		assert!(eta.name.contains("unable to determine refund timing"));
		assert_eq!(eta.start_time, None);
		assert_eq!(eta.end_time, None);
	}
}
