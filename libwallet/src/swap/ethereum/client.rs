// Copyright 2021 The MWC Developers
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

use super::{Erc20AllowanceKey, EthTransactionRecovery};
use crate::swap::types::Currency;
use crate::swap::Error;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_web3;
#[cfg(feature = "test-support")]
use mwc_wallet_util::Mutex;
use mwc_web3::types::{Address, BlockId, TransactionReceipt, H256, U256};
#[cfg(feature = "test-support")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "test-support")]
use std::sync::Arc;

#[cfg(feature = "test-support")]
use super::to_eth_address;

/// Height and timestamp read from the same mined Ethereum block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthChainTip {
	/// Mined block height.
	pub height: u64,
	/// Block timestamp in seconds since the Unix epoch.
	pub timestamp: u64,
}

/// Contract lock terms in the currency's canonical integer units.
pub type EthSwapDetails = (U256, Option<Address>, Address, Address, u64);

/// Ethereum node client
pub trait EthNodeClient: Sync + Send + 'static {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String;
	/// Get node height
	fn height(&self) -> Result<u64, Error>;
	/// Read the latest mined block's height and timestamp together.
	fn chain_tip(&self) -> Result<EthChainTip, Error>;
	/// Hash of a mined block explicitly reported as finalized by this chain.
	/// Missing support must never fall back to the latest block.
	fn finalized_block(&self) -> Result<H256, Error>;
	/// Verify the endpoint chain and both configured swap custody contracts.
	/// Returns the height and timestamp of the block used for validation.
	fn validate_chain_and_contracts(&self) -> Result<EthChainTip, Error>;
	/// Get balance for the address
	fn balance(&self, currency: Currency) -> Result<(String, u64), Error>;
	/// Retrieve a receipt, returning EthTransactionInPending if none is available.
	/// Transport and RPC failures propagate separately from pending transactions.
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, Error>;
	/// Only true when the receipt is in a canonical finalized block. Networks
	/// without finality support retain recovery history.
	fn receipt_is_finalized(&self, _receipt: &TransactionReceipt) -> Result<bool, Error> {
		Ok(false)
	}
	/// Retry an existing deposit without rebuilding its deadline or allocating a nonce.
	fn retry_deposit(
		&self,
		currency: Currency,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error>;
	/// Cancel at the original deposit nonce, preserving both competing transactions.
	fn cancel_deposit(
		&self,
		currency: Currency,
		original: &EthTransactionRecovery,
		cancellation: &mut Option<EthTransactionRecovery>,
		gas_gwei: u64,
	) -> Result<H256, Error>;
	/// Send coins to destination account
	fn transfer(&self, currency: Currency, to: Address, value: u64) -> Result<H256, Error>;
	/// Submit or retry an ERC20 approval, retaining recovery on success and error.
	fn erc20_approve(
		&self,
		currency: Currency,
		value: u64,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error>;
	/// Identify the account/token/spender allowance used for funding swaps.
	fn erc20_allowance_key(&self, currency: Currency) -> Result<Erc20AllowanceKey, Error>;
	/// Read the allowance in full token atomic units, without decimal truncation.
	fn erc20_allowance(&self, currency: Currency) -> Result<U256, Error>;
	/// Initiate a swap, retaining recovery mutations on success and error as for redeem.
	fn initiate(
		&self,
		currency: Currency,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error>;
	/// Redeem ether, borrowing the key so its owner retains erasing storage.
	/// Retain signed transaction recovery before broadcasting. The caller must
	/// persist mutations to recovery on both successful and error returns.
	fn redeem(
		&self,
		currency: Currency,
		address_from_secret: Address,
		secret_key: &mwc_web3::signing::SecretKey,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error>;
	/// Refund ether, retaining recovery mutations on success and error as for redeem.
	fn refund(
		&self,
		currency: Currency,
		address_from_secret: Address,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error>;
	/// Get swap info, preserving the contract's full-width refund block.
	fn get_swap_details(
		&self,
		currency: Currency,
		address_from_secret: Address,
	) -> Result<(U256, Option<Address>, Address, Address, u64), Error>;
	/// Read the lock at an explicit block, including a finalized block hash.
	fn get_swap_details_at(
		&self,
		currency: Currency,
		address_from_secret: Address,
		block: BlockId,
	) -> Result<EthSwapDetails, Error>;
}

/// Mock Eth node for the testing
#[cfg(feature = "test-support")]
#[derive(Debug, Clone)]
pub struct TestEthNodeClientState {
	/// current height
	pub height: u64,
	/// Inject an unavailable secondary RPC service.
	pub chain_tip_error: Option<String>,
	/// Timestamp of the current mock block, independent of the test wall clock.
	pub timestamp: u64,
}

/// Mock ETH node client
#[cfg(feature = "test-support")]
#[derive(Debug, Clone)]
pub struct TestEthNodeClient {
	/// mock node state
	pub state: Arc<Mutex<TestEthNodeClientState>>,
	/// swap HashMap
	pub swap_store: Arc<Mutex<HashMap<Address, (U256, Option<Address>, Address, Address, u64)>>>,
	/// Raw contract responses overriding swap_store, normalized on every lookup.
	pub raw_swap_store:
		Arc<Mutex<HashMap<Address, (U256, Option<Address>, Address, Address, U256)>>>,
	/// txs HashMap
	pub tx_store: Arc<Mutex<HashMap<H256, String>>>,
	/// One-shot receipt lookup responses, keyed by transaction hash.
	pub receipt_results: Arc<Mutex<HashMap<H256, Result<TransactionReceipt, Error>>>>,
	/// Receipts whose blocks have reached canonical finality.
	pub finalized_receipts: Arc<Mutex<HashSet<H256>>>,
	/// Override finalized contract state; None gives existing fixtures instant finality.
	pub finalized_swap_store: Arc<Mutex<Option<HashMap<Address, EthSwapDetails>>>>,
	/// Simulate unavailable finality without disabling balance/refund RPCs.
	pub finality_error: Arc<Mutex<Option<String>>>,
	/// One-shot mutation and result returned by a redeem submission.
	pub redeem_result: Arc<Mutex<Option<(EthTransactionRecovery, Result<H256, Error>)>>>,
	/// One-shot mutation and result returned by a refund submission.
	pub refund_result: Arc<Mutex<Option<(EthTransactionRecovery, Result<H256, Error>)>>>,
	/// One-shot mutation and result returned by a deposit submission.
	pub initiate_result: Arc<Mutex<Option<(EthTransactionRecovery, Result<H256, Error>)>>>,
	/// One-shot mutation and result returned by an approval submission or retry.
	pub approve_result: Arc<Mutex<Option<(EthTransactionRecovery, Result<H256, Error>)>>>,
	/// Controllable ERC20 allowance and mining state, shared by cloned clients.
	pub erc20: Arc<Mutex<TestErc20State>>,
}

/// Simulated ERC20 chain state for the real funding workflow tests.
#[cfg(feature = "test-support")]
#[derive(Debug)]
pub struct TestErc20State {
	/// Distinct account per mock node; clones share its allowances.
	pub owner: Address,
	/// Confirmed allowances in full token atomic units.
	pub allowances: HashMap<Currency, U256>,
	/// Lose the response after accepting an ERC20 transaction.
	pub ambiguous: bool,
	/// Inject a failed allowance RPC.
	pub allowance_error: bool,
	txs: Vec<(H256, Currency, TestErc20Call, Option<bool>)>,
}

#[cfg(feature = "test-support")]
#[derive(Debug, Clone, Copy)]
enum TestErc20Call {
	Approve(u64),
	Cancel,
	Deposit {
		amount: u64,
		refund_time: u64,
		secret: Address,
		participant: Address,
	},
}

#[cfg(feature = "test-support")]
impl TestEthNodeClient {
	/// Create an instance at height
	pub fn new(height: u64) -> Self {
		let id = mwc_wallet_util::mwc_crates::uuid::Uuid::new_v4();
		let mut owner = [0u8; 20];
		owner[..16].copy_from_slice(id.as_bytes());
		Self {
			state: Arc::new(Mutex::new(TestEthNodeClientState {
				height,
				chain_tip_error: None,
				timestamp: u64::try_from(crate::swap::swap::get_cur_time())
					.expect("mock Ethereum block timestamp is nonnegative"),
			})),
			swap_store: Arc::new(Mutex::new(HashMap::with_capacity(10))),
			raw_swap_store: Arc::new(Mutex::new(HashMap::new())),
			tx_store: Arc::new(Mutex::new(HashMap::with_capacity(10))),
			receipt_results: Arc::new(Mutex::new(HashMap::new())),
			finalized_receipts: Arc::new(Mutex::new(HashSet::new())),
			finalized_swap_store: Arc::new(Mutex::new(None)),
			finality_error: Arc::new(Mutex::new(None)),
			redeem_result: Arc::new(Mutex::new(None)),
			refund_result: Arc::new(Mutex::new(None)),
			initiate_result: Arc::new(Mutex::new(None)),
			approve_result: Arc::new(Mutex::new(None)),
			erc20: Arc::new(Mutex::new(TestErc20State {
				owner: Address::from(owner),
				allowances: HashMap::new(),
				ambiguous: false,
				allowance_error: false,
				txs: Vec::new(),
			})),
		}
	}

	fn post_erc20(
		&self,
		currency: Currency,
		call: TestErc20Call,
		gas_gwei: u64,
		nonce: Option<U256>,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let mut state = self.erc20.lock();
		let index = u64::try_from(state.txs.len()).map_err(|e| Error::Generic(e.to_string()))?;
		let hash = H256::from_low_u64_be(
			index
				.checked_add(100)
				.ok_or_else(|| Error::DataOverflow("mock tx index".into()))?,
		);
		state.txs.push((hash, currency, call, None));
		self.tx_store.lock().insert(hash, format!("{:?}", call));
		let ambiguous = state.ambiguous;
		drop(state);
		let key = self.erc20_allowance_key(currency)?;
		let (to, data) = match call {
			TestErc20Call::Approve(value) => (key.token, value.to_be_bytes().to_vec()),
			TestErc20Call::Deposit {
				amount,
				refund_time,
				..
			} => (
				key.spender,
				[amount.to_be_bytes(), refund_time.to_be_bytes()].concat(),
			),
			TestErc20Call::Cancel => (key.owner, Vec::new()),
		};
		let record = EthTransactionRecovery {
			chain_id: key.chain_id,
			sender: key.owner,
			nonce: nonce.unwrap_or(U256::from(index) + U256::one()),
			to,
			value: U256::zero(),
			data: data.into(),
			gas_limit: 100_000.into(),
			gas_price: 1.into(),
			gas_budget_gwei: gas_gwei,
			raw_transaction: hash.as_bytes().to_vec().into(),
			attempted_hashes: vec![hash],
			last_attempt_at: crate::swap::swap::get_cur_time(),
			rebroadcasted: false,
		};
		super::recovery::reserve(&record);
		*recovery = Some(record);
		if ambiguous {
			Err(Error::EthereumSubmissionTimeout {
				tx_hash: hash,
				timeout_secs: 30,
			})
		} else {
			Ok(hash)
		}
	}

	fn retry_record(
		&self,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		let now = crate::swap::swap::get_cur_time();
		if gas_gwei == record.gas_budget_gwei
			&& now.saturating_sub(record.last_attempt_at)
				< crate::swap::fsm::state::POST_SECONDARY_RETRY_PERIOD
		{
			return Err(Error::EthTransactionInPending);
		}
		record.last_attempt_at = now;
		record.gas_budget_gwei = gas_gwei;
		let hash = record
			.attempted_hashes
			.last()
			.copied()
			.ok_or(Error::InvalidTxHash)?;
		if self.erc20.lock().ambiguous {
			Err(Error::EthereumSubmissionTimeout {
				tx_hash: hash,
				timeout_secs: 30,
			})
		} else {
			Ok(hash)
		}
	}

	/// Remove a mined receipt. Tests restore affected allowance/contract state separately.
	pub fn reorg_erc20(&self, hash: H256) {
		let mut state = self.erc20.lock();
		state
			.txs
			.iter_mut()
			.find(|tx| tx.0 == hash)
			.expect("known mock transaction")
			.3 = None;
		self.finalized_receipts.lock().remove(&hash);
	}

	/// Mine a pending mock ERC20 transaction, enforcing USDT approval semantics
	/// and consuming the shared allowance only for successful deposits.
	pub fn mine_erc20(&self, hash: H256, success: bool) {
		let mut state = self.erc20.lock();
		let index = state
			.txs
			.iter()
			.position(|tx| tx.0 == hash)
			.expect("known mock transaction");
		let (_, currency, call, mined) = state.txs[index];
		assert!(mined.is_none(), "transaction already mined");
		let allowance = state.allowances.get(&currency).copied().unwrap_or_default();
		let mut success = success;
		if success {
			match call {
				TestErc20Call::Cancel => (),
				TestErc20Call::Approve(value) => {
					if currency == Currency::Usdt && value != 0 && !allowance.is_zero() {
						success = false;
					} else {
						state.allowances.insert(
							currency,
							super::funding::token_amount(currency, value).unwrap(),
						);
					}
				}
				TestErc20Call::Deposit {
					amount,
					refund_time,
					secret,
					participant,
				} => {
					let amount_atomic = super::funding::token_amount(currency, amount).unwrap();
					if let Some(remaining) = allowance.checked_sub(amount_atomic) {
						let mut swaps = self.swap_store.lock();
						if swaps.contains_key(&secret) {
							success = false;
						} else {
							state.allowances.insert(currency, remaining);
							swaps.insert(
								secret,
								(
									U256::from(refund_time),
									Some(currency.erc20_token_address().unwrap()),
									state.owner,
									participant,
									amount,
								),
							);
						}
					} else {
						success = false;
					}
				}
			}
		}
		state.txs[index].3 = Some(success);
	}

	/// Get a current state for the test chain
	pub fn get_state(&self) -> TestEthNodeClientState {
		self.state.lock().clone()
	}

	/// Set a state for the test chain
	pub fn set_state(&self, chain_state: &TestEthNodeClientState) {
		let mut state = self.state.lock();
		*state = chain_state.clone();
	}

	/// Clean the data, not height. Reorg attack
	pub fn clean(&self) {
		// let mut state = self.state.lock();
	}
}

#[cfg(feature = "test-support")]
impl EthNodeClient for TestEthNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		String::from("ETH test client")
	}

	/// Fetch the current chain height
	fn height(&self) -> Result<u64, Error> {
		Ok(self.state.lock().height)
	}

	fn chain_tip(&self) -> Result<EthChainTip, Error> {
		let state = self.state.lock();
		if let Some(error) = &state.chain_tip_error {
			return Err(Error::Generic(error.clone()));
		}
		Ok(EthChainTip {
			height: state.height,
			timestamp: state.timestamp,
		})
	}

	fn finalized_block(&self) -> Result<H256, Error> {
		if let Some(error) = self.finality_error.lock().as_ref() {
			return Err(Error::EthereumFinalityUnavailable(error.clone()));
		}
		Ok(H256::repeat_byte(0xf1))
	}

	fn validate_chain_and_contracts(&self) -> Result<EthChainTip, Error> {
		self.chain_tip()
	}

	/// get wallet balance
	fn balance(&self, _currency: Currency) -> Result<(String, u64), Error> {
		Ok(("1.00".to_string(), 1_000_000_000_000_000_000u64))
	}

	/// Retrieve receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, Error> {
		if let Some(result) = self.receipt_results.lock().remove(&tx_hash) {
			return result;
		}
		if let Some((_, _, _, success)) = self.erc20.lock().txs.iter().find(|tx| tx.0 == tx_hash) {
			return Ok(TransactionReceipt {
				transaction_hash: tx_hash,
				block_number: success.map(|_| 1.into()),
				status: success.map(|success| u64::from(success).into()),
				..TransactionReceipt::default()
			});
		}
		let receipt_str = r#"{
			"blockHash": "0x83eaba432089a0bfe99e9fc9022d1cfcb78f95f407821be81737c84ae0b439c5",
			"blockNumber": "0x38",
			"contractAddress": "0x03d8c4566478a6e1bf75650248accce16a98509f",
			"cumulativeGasUsed": "0x927c0",
			"gasUsed": "0x927c0",
			"logs": [],
			"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"root": null,
			"transactionHash": "0x422fb0d5953c0c48cbb42fb58e1c30f5e150441c68374d70ca7d4f191fd56f26",
			"transactionIndex": "0x0",
			"status": "0x1"
		}"#;

		let mut receipt: TransactionReceipt = serde_json::from_str(receipt_str)
			.map_err(|e| Error::Generic(format!("Invalid mock transaction receipt: {}", e)))?;
		receipt.transaction_hash = tx_hash;
		Ok(receipt)
	}

	/// Send coins
	fn transfer(&self, _currency: Currency, _to: Address, _value: u64) -> Result<H256, Error> {
		let tx_hash = H256::from([4u8; 32]);
		self.tx_store.lock().insert(tx_hash, "transfer".to_string());
		Ok(tx_hash)
	}

	fn erc20_approve(
		&self,
		currency: Currency,
		value: u64,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		if let Some((record, result)) = self.approve_result.lock().take() {
			super::recovery::reserve(&record);
			*recovery = Some(record);
			return result;
		}
		if let Some(record) = recovery.as_mut() {
			return self.retry_record(record, gas_gwei);
		}
		self.post_erc20(
			currency,
			TestErc20Call::Approve(value),
			gas_gwei,
			None,
			recovery,
		)
	}

	fn receipt_is_finalized(&self, receipt: &TransactionReceipt) -> Result<bool, Error> {
		if let Some(error) = self.finality_error.lock().as_ref() {
			return Err(Error::EthereumFinalityUnavailable(error.clone()));
		}
		Ok(self
			.finalized_receipts
			.lock()
			.contains(&receipt.transaction_hash))
	}

	fn retry_deposit(
		&self,
		_currency: Currency,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		if let Some((replacement, result)) = self.initiate_result.lock().take() {
			super::recovery::reserve(&replacement);
			*record = replacement;
			return result;
		}
		self.retry_record(record, gas_gwei)
	}

	fn cancel_deposit(
		&self,
		currency: Currency,
		original: &EthTransactionRecovery,
		cancellation: &mut Option<EthTransactionRecovery>,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		if let Some(record) = cancellation.as_mut() {
			assert_eq!(record.nonce, original.nonce);
			return self.retry_record(record, gas_gwei);
		}
		self.post_erc20(
			currency,
			TestErc20Call::Cancel,
			gas_gwei,
			Some(original.nonce),
			cancellation,
		)
	}

	fn erc20_allowance_key(&self, currency: Currency) -> Result<Erc20AllowanceKey, Error> {
		Ok(Erc20AllowanceKey {
			chain_id: 3,
			owner: self.erc20.lock().owner,
			token: currency.erc20_token_address()?,
			spender: Address::repeat_byte(0x42),
		})
	}

	fn erc20_allowance(&self, currency: Currency) -> Result<U256, Error> {
		let state = self.erc20.lock();
		if state.allowance_error {
			return Err(Error::Generic("injected allowance RPC failure".into()));
		}
		Ok(state.allowances.get(&currency).copied().unwrap_or_default())
	}

	/// initiate swap offer
	fn initiate(
		&self,
		currency: Currency,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		if let Some((record, result)) = self.initiate_result.lock().take() {
			*recovery = Some(record);
			return result;
		}
		if currency.is_erc20() {
			return self.post_erc20(
				currency,
				TestErc20Call::Deposit {
					amount: value,
					refund_time,
					secret: address_from_secret,
					participant,
				},
				gas_gwei,
				None,
				recovery,
			);
		}
		//todo need to check balance
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			return Err(Error::InvalidEthSwapTradeIndex);
		}
		store.insert(
			address_from_secret,
			(
				U256::from(refund_time),
				None,
				to_eth_address("0xAB90ddDF7bdff0e4FCAB3c9bF608393a6C7e2390".to_string())?,
				participant,
				value,
			),
		);
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([1u8; 32]), "initiate".to_string());
			Ok(H256::from([1u8; 32]))
		} else {
			Ok(H256::zero())
		}
	}

	/// ether buyer redeem
	fn redeem(
		&self,
		_currency: Currency,
		address_from_secret: Address,
		_secret_key: &mwc_web3::signing::SecretKey,
		_gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		if let Some((record, result)) = self.redeem_result.lock().take() {
			*recovery = Some(record);
			return result;
		}
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([2u8; 32]), "redeem".to_string());
			store.remove(&address_from_secret);
			Ok(H256::from([2u8; 32]))
		} else {
			Err(Error::InvalidEthSwapTradeIndex)
		}
	}

	/// refund ether
	fn refund(
		&self,
		_currency: Currency,
		address_from_secret: Address,
		_gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		if let Some((record, result)) = self.refund_result.lock().take() {
			*recovery = Some(record);
			return result;
		}
		let mut store = self.swap_store.lock();
		if store.contains_key(&address_from_secret) {
			let mut txs = self.tx_store.lock();
			txs.insert(H256::from([3u8; 32]), "refund".to_string());
			store.remove(&address_from_secret);
			Ok(H256::from([3u8; 32]))
		} else {
			Err(Error::InvalidEthSwapTradeIndex)
		}
	}

	/// get swap info
	fn get_swap_details(
		&self,
		currency: Currency,
		address_from_secret: Address,
	) -> Result<(U256, Option<Address>, Address, Address, u64), Error> {
		if let Some(details) = self
			.raw_swap_store
			.lock()
			.get(&address_from_secret)
			.copied()
		{
			return super::infura::normalized_swap_details(currency, details);
		}
		let store = self.swap_store.lock();
		store
			.get(&address_from_secret)
			.copied()
			.ok_or(Error::InvalidEthSwapTradeIndex)
	}

	fn get_swap_details_at(
		&self,
		currency: Currency,
		address_from_secret: Address,
		block: BlockId,
	) -> Result<EthSwapDetails, Error> {
		if matches!(block, BlockId::Hash(_)) {
			if let Some(store) = self.finalized_swap_store.lock().as_ref() {
				return store
					.get(&address_from_secret)
					.copied()
					.ok_or(Error::InvalidEthSwapTradeIndex);
			}
		}
		self.get_swap_details(currency, address_from_secret)
	}
}
