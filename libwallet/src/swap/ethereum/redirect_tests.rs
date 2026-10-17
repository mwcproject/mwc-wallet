// Copyright 2026 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Redirect confirmation must follow the same-nonce replacements retained by transfers.

use super::{EthData, EthSwapApi, EthTransactionRecovery, TestEthNodeClient, recovery};
use crate::SecondaryFeeUnits;
use crate::swap::fsm::{
	seller_swap::SellerWaitingForRedeemConfirmations,
	state::{Input, State, StateId},
};
use crate::swap::tests::TestNodeClient;
use crate::swap::types::{
	Action, Context, Currency, Role, SecondaryData, SwapTransactionsConfirmations,
};
use crate::swap::{Error, Swap, SwapApi};
use mwc_wallet_util::{
	Mutex,
	mwc_crates::{
		secp::{ContextFlag, Secp256k1},
		serde_json,
		serial_test::{self, serial},
	},
	mwc_keychain::ExtKeychain,
	mwc_web3::types::{Address, H256, TransactionReceipt},
};
use std::sync::Arc;

// Start with a confirmed secondary redemption, then execute one private-wallet
// redirect through the real seller state using a mock Ethereum node. The fixture
// seeds direct-transfer recovery and acknowledges the initial hash as saved;
// replacement signing, network broadcasts, and disk writes are simulated.
struct Fixture {
	swap: Swap,
	context: Context,
	secp: Secp256k1,
	state: SellerWaitingForRedeemConfirmations<'static, TestNodeClient, ExtKeychain>,
	node: Arc<Mutex<TestEthNodeClient>>,
	record: EthTransactionRecovery,
	confirmations: SwapTransactionsConfirmations,
}

impl Fixture {
	fn new(currency: Currency) -> Self {
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../../swap_test/swap_sell_5.json")).unwrap();
		let data: EthData = serde_json::from_value(serde_json::json!({
			"redeem_address": null, "address_from_secret": null,
			"erc20_approve_tx": null, "lock_tx": null, "refund_tx": null,
			"redeem_tx": null, "tx_fee_gwei": null
		}))
		.unwrap();
		let original = H256::repeat_byte(4); // TestEthNodeClient's submitted transfer hash.
		let record = EthTransactionRecovery {
			chain_id: 1,
			sender: Address::repeat_byte(0xa7),
			nonce: 7.into(),
			to: Address::repeat_byte(0xa8),
			value: 42.into(),
			data: Default::default(),
			gas_limit: 21_000.into(),
			gas_price: 100.into(),
			gas_budget_gwei: 5_500_000,
			raw_transaction: vec![4].into(),
			attempted_hashes: vec![original],
			last_attempt_at: 0,
			rebroadcasted: false,
		};
		recovery::retain_direct_transfer(record.clone()).unwrap();
		swap.secondary_currency = currency;
		swap.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(record.gas_budget_gwei);
		swap.secondary_data = SecondaryData::Eth(data);
		swap.role = Role::Seller(format!("{:#x}", record.to), 0);
		swap.eth_redirect_to_private_wallet = Some(true);
		swap.state = StateId::SellerWaitingForRedeemConfirmations;
		let context =
			serde_json::from_str(include_str!("../../../swap_test/context_sell.json")).unwrap();
		let node = Arc::new(Mutex::new(TestEthNodeClient::new(1)));
		let mwc = Arc::new(TestNodeClient::new(300_000));
		let api: Arc<Box<dyn SwapApi<ExtKeychain>>> =
			Arc::new(Box::new(EthSwapApi::new_test(mwc.clone(), node.clone())));
		let state = SellerWaitingForRedeemConfirmations::new(0, mwc, api);
		let mut fixture = Self {
			swap,
			context,
			state,
			node,
			record,
			secp: Secp256k1::with_caps(ContextFlag::Commit).unwrap(),
			confirmations: SwapTransactionsConfirmations {
				mwc_observed: true,
				secondary_observed: true,
				mwc_tip: 0,
				mwc_lock_conf: None,
				mwc_redeem_conf: Some(1),
				mwc_refund_conf: None,
				secondary_tip: 100,
				secondary_lock_conf: Some(1),
				secondary_lock_amount: 0,
				secondary_redeem_conf: Some(1),
				secondary_refund_conf: None,
				secondary_refund_progress: None,
			},
		};
		fixture.process(Input::Execute).unwrap();
		assert_eq!(fixture.node.lock().tx_store.lock().len(), 1);
		assert_eq!(
			fixture
				.swap
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.redirect_tx,
			Some(original)
		);
		// This is the same acknowledgement that store_swap_trade performs after fsync.
		recovery::record_swap(&fixture.swap);
		fixture
	}

	fn process(
		&mut self,
		input: Input,
	) -> Result<crate::swap::fsm::state::StateProcessRespond, Error> {
		if matches!(input, Input::Check) {
			// Exercise the owner's rollback boundary as well as the real FSM state.
			return crate::swap::owner_swap::commit_swap_on_success(&mut self.swap, |swap| {
				self.state.process(
					input,
					swap,
					&self.context,
					&self.confirmations,
					&mut self.secp,
				)
			});
		}
		self.state.process(
			input,
			&mut self.swap,
			&self.context,
			&self.confirmations,
			&mut self.secp,
		)
	}

	fn replace(&mut self) -> H256 {
		let replacement = H256::repeat_byte(5);
		self.record.gas_price = 120.into();
		self.record.attempted_hashes.push(replacement);
		self.record.raw_transaction = vec![5].into();
		// Production retries update recovery before broadcasting their new bytes.
		recovery::update_direct_transfer(self.record.clone()).unwrap();
		replacement
	}

	fn receipt(&self, hash: H256, result: Result<TransactionReceipt, Error>) {
		self.node.lock().receipt_results.lock().insert(hash, result);
	}

	fn mined(&self, hash: H256, success: bool) {
		self.receipt(
			hash,
			Ok(TransactionReceipt {
				transaction_hash: hash,
				block_number: Some(100.into()),
				status: Some(u64::from(success).into()),
				..Default::default()
			}),
		);
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		recovery::forget_for_test(self.record.chain_id, self.record.sender);
	}
}

// Workflow: For ETH and USDT, submit a redirect and register a fee replacement
// at the same nonce. Let either transaction mine successfully or revert while
// the other receipt lookup fails. Poll through the owner's rollback boundary,
// serialize/reload the swap, acknowledge the simulated save, retire finalized
// recovery, and poll again using only the saved hashes.
// Expected: Success completes the swap; a revert reports EthContractCallError.
// Both hashes survive errors and reloads, the original marker stays unchanged,
// and finality cannot erase recovery before the hashes are acknowledged as saved.
// Executing again after either outcome must not create another payment.
#[test]
#[serial]
fn redirect_replacements_resolve_success_and_revert_after_reload() {
	for currency in [Currency::Ether, Currency::Usdt] {
		for success in [false, true] {
			for original_wins in [false, true] {
				let mut f = Fixture::new(currency);
				let original = f.record.attempted_hashes[0];
				let replacement = f.replace();
				// Finality must not erase a replacement before the swap copies it.
				recovery::forget_finalized_direct_transfers(1, f.record.sender, 8.into());
				assert!(recovery::direct_transfer(1, f.record.sender, original).is_ok());
				let winner = if original_wins { original } else { replacement };
				let loser = if original_wins { replacement } else { original };
				for restored in [false, true] {
					f.receipt(
						loser,
						Err(Error::EthereumTimeout {
							operation: "test receipt",
							timeout_secs: 30,
						}),
					);
					f.mined(winner, success);
					let response = f.process(Input::Check);
					if success {
						assert_eq!(response.unwrap().next_state_id, StateId::SellerSwapComplete);
					} else {
						assert!(matches!(response, Err(Error::EthContractCallError(_))));
					}
					let data = f.swap.secondary_data.unwrap_eth().unwrap();
					assert_eq!(data.redirect_tx, Some(original));
					assert_eq!(data.redirect_tx_candidates, vec![original, replacement]);
					if !restored {
						// Polling status alone does not acknowledge durability.
						recovery::forget_finalized_direct_transfers(1, f.record.sender, 8.into());
						assert!(recovery::direct_transfer(1, f.record.sender, original).is_ok());
						f.swap =
							serde_json::from_str(&serde_json::to_string(&f.swap).unwrap()).unwrap();
						recovery::record_swap(&f.swap);
						recovery::forget_finalized_direct_transfers(1, f.record.sender, 8.into());
						assert!(!recovery::has_direct_transfers(1, f.record.sender));
					}
				}
				// Executing again must not create a second payment after either outcome.
				f.node.lock().tx_store.lock().clear();
				f.process(Input::Execute).unwrap();
				assert!(f.node.lock().tx_store.lock().is_empty());
			}
		}
	}
}

// Workflow: Submit a redirect and register its replacement. Keep the original
// pending, then return a missing, unmined, status-less, or wrong-hash receipt for
// the replacement on successive status checks.
// Expected: Every check keeps SellerWaitingForRedeemConfirmations and its wait
// action, retaining both candidate hashes. None of these receipts establishes
// that the payment succeeded or reverted.
#[test]
#[serial]
fn redirect_keeps_waiting_for_missing_or_invalid_candidate_receipts() {
	let mut f = Fixture::new(Currency::Ether);
	let original = f.record.attempted_hashes[0];
	let replacement = f.replace();
	for receipt in [
		Err(Error::EthTransactionInPending),
		Ok(TransactionReceipt {
			transaction_hash: replacement,
			..Default::default()
		}),
		Ok(TransactionReceipt {
			transaction_hash: replacement,
			block_number: Some(100.into()),
			..Default::default()
		}),
		Ok(TransactionReceipt {
			transaction_hash: H256::repeat_byte(6),
			block_number: Some(100.into()),
			status: Some(1.into()),
			..Default::default()
		}),
	] {
		f.receipt(original, Err(Error::EthTransactionInPending));
		f.receipt(replacement, receipt);
		let response = f.process(Input::Check).unwrap();
		assert_eq!(
			response.next_state_id,
			StateId::SellerWaitingForRedeemConfirmations
		);
		assert!(matches!(
			response.action,
			Some(Action::SellerWaitForSecondaryTransferConfirmations { .. })
		));
		assert_eq!(
			f.swap
				.secondary_data
				.unwrap_eth()
				.unwrap()
				.redirect_tx_candidates,
			vec![original, replacement]
		);
	}
}
