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

use super::client::*;
use super::secret_key::SecretKeyGuard;
use super::*;
use crate::swap::Error;
#[cfg(feature = "test-support")]
use crate::swap::is_test_mode;
#[cfg(all(test, feature = "test-support"))]
use crate::swap::set_test_mode;
use crate::swap::types::Currency;
#[cfg(feature = "test-support")]
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_crates::crossbeam_utils::thread::scope;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
#[cfg(all(test, feature = "test-support"))]
use mwc_wallet_util::mwc_crates::rand;
use mwc_wallet_util::mwc_crates::ring::digest;
use mwc_wallet_util::mwc_crates::tokio::runtime::Builder;
use mwc_wallet_util::mwc_crates::tokio::time::timeout;
use mwc_wallet_util::mwc_util::decode_secret_key_hex;
use mwc_wallet_util::mwc_util::to_hex;
use mwc_wallet_util::mwc_web3;
use mwc_web3::{
	api::{Accounts, Namespace},
	contract::{Contract, Options, tokens::Tokenize},
	signing,
	signing::{Key, SecretKeyRef},
	types::{
		Address, BlockId, BlockNumber, Bytes, CallRequest, H256, TransactionParameters, TransactionReceipt,
		U256,
	},
};
use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

const DEFAULT_TRANSFER_GAS_BUDGET_GWEI: u64 = 5_500_000u64;
// EIP-7825 caps the declared gas limit of mainnet transactions, not just gas used.
const ETH_MAINNET_TRANSACTION_GAS_LIMIT: u64 = 16_777_216;
const ETH_RPC_TIMEOUT_SECS: u64 = 30;
const ETH_RPC_TIMEOUT: Duration = Duration::from_secs(ETH_RPC_TIMEOUT_SECS);
const GAS_ESTIMATE_MARGIN_NUMERATOR: u64 = 120;
const GAS_ESTIMATE_MARGIN_DENOMINATOR: u64 = 100;
// SHA-256 of the raw bytes returned by eth_getCode for the checked-in,
// explorer-verified runtime bytecode snapshots. Calculate each value from its
// `deployed-bytecode.hex` file as:
//
//     SHA256(hex_decode(trim(file).strip_prefix("0x")))
//
// One way to reproduce that calculation is:
//
//     tr -d '\r\n' < deployed-bytecode.hex | sed 's/^0x//' | xxd -r -p | shasum -a 256
//
// The `manifest.json` values intentionally differ: they hash the trimmed ASCII
// `0x...` representation, whereas eth_getCode and validation below operate on
// the decoded EVM bytecode bytes.
const NATIVE_SWAP_RUNTIME_SHA256: &str =
	"f9c8388ea99836f6bc0bf844737cc04599939a1f01415451127ad526bc823d75";
const ERC20_SWAP_RUNTIME_SHA256: &str =
	"7f7d8506d7902644c0eade5002ea879cd73033647e600b47ae2599f59cfd5e5a";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwapContractKind {
	Native,
	Erc20,
}

impl SwapContractKind {
	fn label(self) -> &'static str {
		match self {
			Self::Native => "native",
			Self::Erc20 => "ERC20",
		}
	}

	fn supported_runtime_hash(self, chain_id: u64) -> Result<&'static str, Error> {
		// Both supported networks use deployments of the same audited runtime
		// artifacts.  Keeping the chain id in this match makes adding a network or
		// approving a different build an explicit release decision.
		match (chain_id, self) {
			(1 | 3, Self::Native) => Ok(NATIVE_SWAP_RUNTIME_SHA256),
			(1 | 3, Self::Erc20) => Ok(ERC20_SWAP_RUNTIME_SHA256),
			_ => Err(Error::UnexpectedNetwork(format!(
				"Ethereum chain id {}",
				chain_id
			))),
		}
	}
}

fn parse_swap_contract_address(kind: SwapContractKind, address: String) -> Result<Address, Error> {
	let address = to_eth_address(address)?;
	if address == Address::zero() {
		return Err(Error::ZeroEthSwapContractAddress { kind: kind.label() });
	}
	Ok(address)
}

fn validate_swap_contract_runtime(
	chain_id: u64,
	kind: SwapContractKind,
	address: Address,
	code: &[u8],
) -> Result<(), Error> {
	let address = eth_address(address);
	if code.is_empty() {
		return Err(Error::MissingEthSwapContractCode {
			kind: kind.label(),
			address,
			chain_id,
		});
	}

	let actual_hash = to_hex(digest::digest(&digest::SHA256, code).as_ref());
	if actual_hash != kind.supported_runtime_hash(chain_id)? {
		return Err(Error::UnsupportedEthSwapContractCode {
			kind: kind.label(),
			address,
			chain_id,
			actual_hash,
		});
	}
	Ok(())
}

fn secret_key_from_hex(private_key: &str) -> Result<SecretKeyGuard, mwc_web3::Error> {
	let decoded = decode_secret_key_hex::<32>(private_key).map_err(|e| {
		mwc_web3::Error::Decoder(format!("Invalid Ethereum private key hex: {}", e))
	})?;
	SecretKeyGuard::from_bytes(&decoded)
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
	if let Some(message) = payload.downcast_ref::<String>() {
		message.clone()
	} else if let Some(message) = payload.downcast_ref::<&'static str>() {
		(*message).to_string()
	} else {
		"non-string panic payload".to_string()
	}
}

fn run_async<T, F>(operation: &'static str, task: F) -> Result<T, Error>
where
	T: Send,
	F: Future<Output = Result<T, Error>> + Send,
{
	scope(|scope| {
		let handle = scope
			.builder()
			.spawn(move |_| {
				let runtime = Builder::new_current_thread()
					.enable_all()
					.build()
					.map_err(|source| Error::EthereumRuntime { operation, source })?;
				// Catch the unwind before it drops the runtime, whose default shutdown
				// would wait for any blocking DNS lookup still in progress.
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					runtime.block_on(task)
				}));
				// Stop async work without waiting for already-running blocking work.
				// Such work cannot be cancelled and may finish in the background.
				runtime.shutdown_background();
				match result {
					Ok(result) => result,
					Err(payload) => std::panic::resume_unwind(payload),
				}
			})
			.map_err(|source| Error::EthereumWorkerSpawn { operation, source })?;
		handle
			.join()
			.map_err(|payload| Error::EthereumWorkerPanic {
				operation,
				message: panic_payload_message(payload.as_ref()),
			})?
	})
	.map_err(|payload| Error::EthereumWorkerPanic {
		operation,
		message: panic_payload_message(payload.as_ref()),
	})?
}

async fn web3_call<T, F>(operation: &'static str, call: F) -> Result<T, Error>
where
	F: Future<Output = Result<T, mwc_web3::Error>>,
{
	match timeout(ETH_RPC_TIMEOUT, call).await {
		Ok(result) => result.map_err(|source| Error::EthereumRpc {
			operation,
			source: Box::new(source),
		}),
		Err(_) => Err(Error::EthereumTimeout {
			operation,
			timeout_secs: ETH_RPC_TIMEOUT_SECS,
		}),
	}
}

async fn contract_call<T, F>(operation: &'static str, call: F) -> Result<T, Error>
where
	F: Future<Output = Result<T, mwc_web3::contract::Error>>,
{
	match timeout(ETH_RPC_TIMEOUT, call).await {
		Ok(result) => result.map_err(|source| Error::EthereumContract {
			operation,
			source: Box::new(source),
		}),
		Err(_) => Err(Error::EthereumTimeout {
			operation,
			timeout_secs: ETH_RPC_TIMEOUT_SECS,
		}),
	}
}

async fn query_erc20_allowance<T: mwc_web3::Transport>(
	eth: mwc_web3::api::Eth<T>,
	key: Erc20AllowanceKey,
) -> Result<U256, Error> {
	verify_chain_id(&eth, key.chain_id).await?;
	let contract =
		Contract::from_json(eth, key.token, ERC20_TOKEN_CONTRACT.as_bytes()).map_err(|source| {
			Error::EthereumContract {
				operation: "construct ERC20 allowance query",
				source: Box::new(mwc_web3::contract::Error::Abi(source)),
			}
		})?;
	contract_call(
		"ERC20 allowance",
		contract.query(
			"allowance",
			(key.owner, key.spender),
			None,
			Options::default(),
			None,
		),
	)
	.await
}

async fn signing_call<T, F>(operation: &'static str, call: F) -> Result<T, Error>
where
	F: Future<Output = Result<T, mwc_web3::Error>>,
{
	match timeout(ETH_RPC_TIMEOUT, call).await {
		Ok(result) => result.map_err(|source| Error::EthereumSigning {
			operation,
			source: Box::new(source),
		}),
		Err(_) => Err(Error::EthereumTimeout {
			operation,
			timeout_secs: ETH_RPC_TIMEOUT_SECS,
		}),
	}
}

fn expected_chain_id(chain: &str) -> Result<u64, Error> {
	match chain {
		"mainnet" => Ok(1),
		"ropsten" => Ok(3),
		_ => Err(Error::UnexpectedNetwork(chain.to_string())),
	}
}

async fn verify_chain_id<T>(eth: &mwc_web3::api::Eth<T>, expected: u64) -> Result<(), Error>
where
	T: mwc_web3::Transport,
{
	let actual = web3_call("eth_chainId", eth.chain_id()).await?;
	if actual != U256::from(expected) {
		return Err(Error::EthereumChainMismatch {
			expected,
			actual: actual.to_string(),
		});
	}
	Ok(())
}

/// Fetch both time and height from one mined block response. A missing or
/// pending block cannot supply an anchor for a refund deadline.
async fn query_chain_tip<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
) -> Result<EthChainTip, Error> {
	let operation = "eth_getBlockByNumber for Ethereum chain tip";
	let block = web3_call(operation, eth.block(BlockNumber::Latest.into()))
		.await?
		.ok_or_else(|| Error::EthereumRpc {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(
				"node returned no latest Ethereum block".into(),
			)),
		})?;
	let number = block.number.ok_or_else(|| Error::EthereumRpc {
		operation,
		source: Box::new(mwc_web3::Error::InvalidResponse(
			"latest Ethereum block has no mined block number".into(),
		)),
	})?;
	Ok(EthChainTip {
		height: number.as_u64(),
		timestamp: checked_u256_to_u64(block.timestamp, "block timestamp")?,
	})
}

/// Resolve finality once and pin subsequent contract queries to its block hash.
async fn query_finalized_block<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
) -> Result<H256, Error> {
	let block = web3_call(
		"Ethereum finalized block",
		eth.block(BlockNumber::Finalized.into()),
	)
	.await?
	.ok_or_else(|| Error::EthereumFinalityUnavailable("node returned no finalized block".into()))?;
	match (block.number, block.hash) {
		(Some(_), Some(hash)) => Ok(hash),
		_ => Err(Error::EthereumFinalityUnavailable(
			"finalized block has no mined height or hash".into(),
		)),
	}
}

/// Finality applies to the receipt's canonical block, not just its height.
async fn receipt_is_finalized<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	receipt: &TransactionReceipt,
) -> Result<bool, Error> {
	if super::recovery::receipt_outcome(receipt.transaction_hash, receipt)?.is_none() {
		return Ok(false);
	}
	let number = receipt
		.block_number
		.ok_or(Error::EthRetrieveTransReciptError)?;
	let hash = receipt
		.block_hash
		.ok_or(Error::EthRetrieveTransReciptError)?;
	let finalized = web3_call(
		"Ethereum finalized block",
		eth.block(BlockNumber::Finalized.into()),
	)
	.await?
	.ok_or(Error::EthRetrieveTransReciptError)?;
	let finalized_number = finalized.number.ok_or(Error::EthRetrieveTransReciptError)?;
	if number > finalized_number {
		return Ok(false);
	}
	let canonical = web3_call(
		"Ethereum receipt canonical block",
		eth.block(BlockNumber::Number(number).into()),
	)
	.await?
	.ok_or(Error::EthRetrieveTransReciptError)?;
	Ok(canonical.number == Some(number) && canonical.hash == Some(hash))
}

type SubmissionLockKey = (u64, Address);
type SubmissionLockMap = HashMap<SubmissionLockKey, Arc<StdMutex<()>>>;

static SUBMISSION_LOCKS: OnceLock<StdMutex<SubmissionLockMap>> = OnceLock::new();

/// Return the process-wide lock for one Ethereum account.
///
/// Accepted operating assumptions: only one wallet process controls an account,
/// and that process remains alive long enough for the caller to persist the
/// returned or ambiguous transaction. Reservations keep an unmined nonce
/// unavailable to other operations even if the node drops it from its pending set.
/// This is not a cross-process lock. A crash/storage failure after node
/// acceptance and before swap persistence remains a tolerated risk; see
/// `doc/atomic_swaps.md`.
fn submission_lock(chain_id: u64, address: Address) -> Arc<StdMutex<()>> {
	let mut locks = SUBMISSION_LOCKS
		.get_or_init(|| StdMutex::new(HashMap::new()))
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner());
	locks
		.entry((chain_id, address))
		.or_insert_with(|| Arc::new(StdMutex::new(())))
		.clone()
}

async fn submit_signed_transaction<T>(
	eth: &mwc_web3::api::Eth<T>,
	tx_hash: H256,
	raw_transaction: Bytes,
) -> Result<H256, Error>
where
	T: mwc_web3::Transport,
{
	let submission = eth.send_raw_transaction(raw_transaction);
	match timeout(ETH_RPC_TIMEOUT, submission).await {
		Ok(Ok(remote_hash)) if remote_hash == tx_hash => Ok(tx_hash),
		Ok(Ok(remote_hash)) => Err(Error::EthereumSubmissionUnknown {
			tx_hash,
			source: Box::new(mwc_web3::Error::InvalidResponse(format!(
				"eth_sendRawTransaction returned hash {:?}, expected {:?}",
				remote_hash, tx_hash
			))),
		}),
		Ok(Err(source)) => Err(Error::EthereumSubmissionUnknown {
			tx_hash,
			source: Box::new(source),
		}),
		Err(_) => Err(Error::EthereumSubmissionTimeout {
			tx_hash,
			timeout_secs: ETH_RPC_TIMEOUT_SECS,
		}),
	}
}

fn gas_limit_from_gwei(gas_gwei: u64) -> Result<U256, Error> {
	U256::from(gas_gwei)
		.checked_mul(U256::from(1_000_000_000u64))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Ethereum gas budget cannot be converted from gwei to wei, gwei={}",
				gas_gwei
			))
		})
}

fn checked_u256_to_u64(value: U256, field: &str) -> Result<u64, Error> {
	if value > U256::from(u64::MAX) {
		return Err(Error::DataOverflow(format!(
			"Ethereum {} value {} exceeds u64::MAX",
			field, value
		)));
	}
	Ok(value.low_u64())
}

/// Normalize the requested currency's balance while preserving the contract's
/// token, parties, and uint256 refund block. Unrelated tokens contribute no balance.
pub(super) fn normalized_swap_details(
	currency: Currency,
	details: (U256, Option<Address>, Address, Address, U256),
) -> Result<(U256, Option<Address>, Address, Address, u64), Error> {
	if currency.is_erc20() && details.1 != Some(currency.erc20_token_address()?) {
		// Anyone can initiate a lock using an unrelated token and an arbitrary
		// uint256 amount. Do not let conversion of that amount block MWC refunds.
		return Ok((details.0, details.1, details.2, details.3, 0));
	}
	let balance = if currency.is_expo_shrinked18to9() {
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "U256::exp10(9) is a fixed nonzero divisor"
		)]
		let balance = details.4 / U256::exp10(9);
		balance
	} else {
		details.4
	};
	Ok((
		details.0,
		details.1,
		details.2,
		details.3,
		checked_u256_to_u64(balance, "swap balance")?,
	))
}

async fn query_swap_details_at<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	currency: Currency,
	contract_address: Address,
	address_from_secret: Address,
	block: BlockId,
) -> Result<EthSwapDetails, Error> {
	let contract_abi = if currency.is_erc20() {
		ERC20_SWAP_CONTRACT
	} else {
		ETH_SWAP_CONTRACT
	};
	let contract = Contract::from_json(eth.clone(), contract_address, contract_abi.as_bytes())
		.map_err(|source| Error::EthereumContract {
			operation: "load swap details ABI",
			source: Box::new(mwc_web3::contract::Error::Abi(source)),
		})?;

	//0: refundBlock, 1: contractAddress<Option>, 2: initiator, 3: participant, 4: value
	let raw = if !currency.is_erc20() {
		let res: (U256, Address, Address, U256) = contract_call(
			"native getSwapDetails",
			contract.query(
				"getSwapDetails",
				address_from_secret,
				None,
				Options::default(),
				Some(block),
			),
		)
		.await?;
		(res.0, None, res.1, res.2, res.3)
	} else {
		let res: (U256, Address, Address, Address, U256) = contract_call(
			"ERC20 getSwapDetails",
			contract.query(
				"getSwapDetails",
				address_from_secret,
				None,
				Options::default(),
				Some(block),
			),
		)
		.await?;
		(res.0, Some(res.1), res.2, res.3, res.4)
	};
	normalized_swap_details(currency, raw)
}

fn normalized_ether_balance(balance_wei: U256) -> Result<(String, u64), Error> {
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "U256::exp10(9) is a fixed nonzero divisor"
	)]
	let balance_gwei = balance_wei / U256::exp10(9);
	let balance_gwei = checked_u256_to_u64(balance_gwei, "balance in gwei")?;
	Ok((
		Currency::Ether.amount_to_hr_string(balance_gwei, true),
		balance_gwei,
	))
}

fn pending_nonce_block() -> Option<BlockNumber> {
	Some(BlockNumber::Pending)
}

/// All account submissions respect swap and direct-transfer nonce reservations.
/// The caller holds submission_lock through allocation and broadcast.
async fn next_account_nonce<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	chain_id: u64,
	from: Address,
) -> Result<U256, Error> {
	let confirmed = web3_call(
		"eth_getTransactionCount(latest)",
		eth.transaction_count(from, Some(BlockNumber::Latest)),
	)
	.await?;
	let pending = web3_call(
		"eth_getTransactionCount(pending)",
		eth.transaction_count(from, pending_nonce_block()),
	)
	.await?;
	if chain_id == 1 && super::recovery::has_direct_transfers(chain_id, from) {
		let finalized = web3_call(
			"eth_getTransactionCount(finalized) for direct transfer recovery",
			eth.transaction_count(from, Some(BlockNumber::Finalized)),
		)
		.await?;
		super::recovery::forget_finalized_direct_transfers(
			chain_id,
			from,
			finalized.min(confirmed),
		);
	}
	super::recovery::next_nonce(chain_id, from, confirmed, pending)
}

enum RecoveryTarget<'a> {
	Swap(&'a mut Option<EthTransactionRecovery>),
	DirectTransfer,
}

/// Retain the signed transaction before entering the ambiguous submission interval.
async fn submit_prepared_transaction<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	from: Address,
	tx: TransactionParameters,
	private_key: &str,
	gas_budget: U256,
	recovery_target: RecoveryTarget<'_>,
	operation: &'static str,
) -> Result<H256, Error> {
	let key = secret_key_from_hex(private_key).map_err(|source| Error::EthereumSigning {
		operation,
		source: Box::new(source),
	})?;
	if SecretKeyRef::new(&key).address() != from {
		return Err(Error::Generic(
			"Ethereum signing account does not match its private key".into(),
		));
	}
	let accounts = Accounts::new(eth.transport().clone());
	let signed = signing_call(
		operation,
		accounts.sign_transaction(tx.clone(), SecretKeyRef::new(&key)),
	)
	.await?;
	let record = EthTransactionRecovery {
		chain_id: tx
			.chain_id
			.ok_or_else(|| Error::Generic("Missing transaction chain id".into()))?,
		sender: from,
		nonce: tx
			.nonce
			.ok_or_else(|| Error::Generic("Missing transaction nonce".into()))?,
		to: tx
			.to
			.ok_or_else(|| Error::Generic("Missing transaction contract".into()))?,
		value: tx.value,
		data: tx.data,
		gas_limit: tx.gas,
		gas_price: tx
			.gas_price
			.ok_or_else(|| Error::Generic("Missing transaction gas price".into()))?,
		gas_budget_gwei: checked_u256_to_u64(
			gas_budget
				.checked_div(U256::from(1_000_000_000u64))
				.ok_or_else(|| Error::DataOverflow("Ethereum gas budget division".into()))?,
			"transaction gas budget",
		)?,
		raw_transaction: signed.raw_transaction.clone(),
		attempted_hashes: vec![signed.transaction_hash],
		last_attempt_at: crate::swap::swap::get_cur_time(),
		rebroadcasted: false,
	};
	match recovery_target {
		RecoveryTarget::Swap(recovery) => {
			super::recovery::reserve(&record);
			*recovery = Some(record);
		}
		RecoveryTarget::DirectTransfer => super::recovery::retain_direct_transfer(record)?,
	}
	submit_signed_transaction(eth, signed.transaction_hash, signed.raw_transaction).await
}

fn replacement_gas_price(previous: U256, suggested: U256) -> Result<U256, Error> {
	let bumped = previous
		.checked_mul(U256::from(120u64))
		.and_then(|v| v.checked_add(U256::from(99u64)))
		.and_then(|v| v.checked_div(U256::from(100u64)))
		.ok_or_else(|| Error::DataOverflow("Ethereum replacement gas price overflow".into()))?;
	let minimum = previous
		.checked_add(U256::one())
		.ok_or_else(|| Error::DataOverflow("Ethereum replacement gas price overflow".into()))?;
	Ok(suggested.max(bumped).max(minimum))
}

/// Cancellation competes at the original nonce, with separate signed recovery.
async fn cancel_signed_deposit<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	original: &EthTransactionRecovery,
	cancellation: &mut Option<EthTransactionRecovery>,
	gas_gwei: u64,
	private_key: &str,
) -> Result<H256, Error> {
	let operation = "cancel Ethereum deposit";
	verify_chain_id(eth, original.chain_id).await?;
	let hash = original
		.attempted_hashes
		.last()
		.copied()
		.ok_or(Error::InvalidTxHash)?;
	let confirmed = web3_call(
		operation,
		eth.transaction_count(original.sender, Some(BlockNumber::Latest)),
	)
	.await?;
	if confirmed > original.nonce {
		return Err(Error::EthereumTransactionNonceConsumed {
			nonce: original.nonce,
			tx_hash: hash,
		});
	}
	let budget = gas_limit_from_gwei(gas_gwei)?;
	// Pending state may already charge the deposit and later transactions.
	// Estimate against confirmed state because this call replaces the deposit.
	let (suggested, gas) = estimate_contract_gas(
		eth,
		operation,
		CallRequest {
			from: Some(original.sender),
			to: Some(original.sender),
			value: Some(U256::zero()),
			data: Some(Bytes::default()),
			..CallRequest::default()
		},
		original.chain_id,
		budget,
		BlockNumber::Latest,
	)
	.await?;
	let gas_price = replacement_gas_price(original.gas_price, suggested)?;
	ensure_gas_budget(operation, gas, gas_price, budget)?;
	let tx = legacy_transaction(
		original.nonce,
		original.sender,
		gas,
		gas_price,
		U256::zero(),
		Bytes::default(),
		original.chain_id,
	);
	submit_prepared_transaction(
		eth,
		original.sender,
		tx,
		private_key,
		budget,
		RecoveryTarget::Swap(cancellation),
		operation,
	)
	.await
}

/// Retry an unmined transaction without allocating a nonce or re-estimating against
/// pending state, which may already include the original contract execution.
async fn retry_signed_transaction<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	record: &mut EthTransactionRecovery,
	gas_gwei: u64,
	private_key: &str,
	now: i64,
) -> Result<H256, Error> {
	let hash = prepare_transaction_retry(eth, record, gas_gwei, private_key, now).await?;
	submit_signed_transaction(eth, hash, record.raw_transaction.clone()).await
}

/// Prepare a retry so direct transfers can retain updated recovery before sending.
async fn prepare_transaction_retry<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	record: &mut EthTransactionRecovery,
	gas_gwei: u64,
	private_key: &str,
	now: i64,
) -> Result<H256, Error> {
	let operation = "retry Ethereum transaction";
	let current_hash = record
		.attempted_hashes
		.last()
		.copied()
		.ok_or(Error::InvalidTxHash)?;
	let budget_changed = gas_gwei != record.gas_budget_gwei;
	if !budget_changed
		&& now.saturating_sub(record.last_attempt_at)
			< crate::swap::fsm::state::POST_SECONDARY_RETRY_PERIOD
	{
		return Err(Error::EthTransactionInPending);
	}
	verify_chain_id(eth, record.chain_id).await?;
	let confirmed = web3_call(
		"eth_getTransactionCount(latest) for transaction recovery",
		eth.transaction_count(record.sender, Some(BlockNumber::Latest)),
	)
	.await?;
	if confirmed > record.nonce {
		return Err(Error::EthereumTransactionNonceConsumed {
			nonce: record.nonce,
			tx_hash: current_hash,
		});
	}
	super::recovery::reserve(record);
	let gas_budget = gas_limit_from_gwei(gas_gwei)?;
	let suggested = adjusted_gas_price(
		operation,
		web3_call("eth_gasPrice for transaction recovery", eth.gas_price()).await?,
	)?;
	if budget_changed || record.rebroadcasted || suggested > record.gas_price {
		let gas_price = replacement_gas_price(record.gas_price, suggested)?;
		ensure_gas_budget(operation, record.gas_limit, gas_price, gas_budget)?;
		let key = secret_key_from_hex(private_key).map_err(|source| Error::EthereumSigning {
			operation,
			source: Box::new(source),
		})?;
		if SecretKeyRef::new(&key).address() != record.sender {
			return Err(Error::Generic(
				"Ethereum transaction recovery belongs to a different account".into(),
			));
		}
		let tx = legacy_transaction(
			record.nonce,
			record.to,
			record.gas_limit,
			gas_price,
			record.value,
			record.data.clone(),
			record.chain_id,
		);
		let accounts = Accounts::new(eth.transport().clone());
		let signed = signing_call(
			operation,
			accounts.sign_transaction(tx, SecretKeyRef::new(&key)),
		)
		.await?;
		record.gas_price = gas_price;
		record.gas_budget_gwei = gas_gwei;
		record.raw_transaction = signed.raw_transaction;
		record.attempted_hashes.push(signed.transaction_hash);
		record.rebroadcasted = false;
	} else {
		ensure_gas_budget(operation, record.gas_limit, record.gas_price, gas_budget)?;
		record.rebroadcasted = true;
	}
	record.last_attempt_at = now;
	let hash = record
		.attempted_hashes
		.last()
		.copied()
		.ok_or(Error::InvalidTxHash)?;
	Ok(hash)
}

/// The caller holds the account submission lock from cache lookup to broadcast.
async fn retry_direct_transfer<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	mut record: EthTransactionRecovery,
	gas_gwei: u64,
	private_key: &str,
	now: i64,
) -> Result<H256, Error> {
	verify_chain_id(eth, record.chain_id).await?;
	let mut retrieval_error = None;
	for hash in &record.attempted_hashes {
		let result = web3_call(
			"eth_getTransactionReceipt for direct transfer recovery",
			eth.transaction_receipt(*hash),
		)
		.await;
		match result.and_then(|receipt| {
			receipt
				.map(|receipt| super::recovery::receipt_outcome(*hash, &receipt))
				.transpose()
		}) {
			Ok(Some(Some(true))) => return Ok(*hash),
			Ok(Some(Some(false))) => return Err(Error::EthereumTransferReverted(*hash)),
			Ok(_) => (),
			Err(error) => {
				retrieval_error.get_or_insert(error);
			}
		}
	}
	if let Some(error) = retrieval_error {
		return Err(error);
	}
	let hash = prepare_transaction_retry(eth, &mut record, gas_gwei, private_key, now).await?;
	let raw = record.raw_transaction.clone();
	super::recovery::update_direct_transfer(record)?;
	submit_signed_transaction(eth, hash, raw).await
}

fn legacy_transaction(
	nonce: U256,
	to: Address,
	gas: U256,
	gas_price: U256,
	value: U256,
	data: Bytes,
	chain_id: u64,
) -> TransactionParameters {
	TransactionParameters {
		nonce: Some(nonce),
		to: Some(to),
		gas,
		gas_price: Some(gas_price),
		value,
		data,
		chain_id: Some(chain_id),
		transaction_type: None,
		access_list: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	}
}

fn erc20_transfer_data(to: Address, value: U256) -> Result<Bytes, Error> {
	erc20_call_data("transfer", to, value)
}

fn erc20_call_data(function: &'static str, to: Address, value: U256) -> Result<Bytes, Error> {
	let contract =
		mwc_web3::ethabi::Contract::load(ERC20_TOKEN_CONTRACT.as_bytes()).map_err(|source| {
			Error::EthereumContract {
				operation: "load ERC20 ABI",
				source: Box::new(mwc_web3::contract::Error::Abi(source)),
			}
		})?;
	let data = contract
		.function(function)
		.and_then(|function| function.encode_input(&(to, value).into_tokens()))
		.map_err(|source| Error::EthereumContract {
			operation: "encode ERC20 call",
			source: Box::new(mwc_web3::contract::Error::Abi(source)),
		})?;
	Ok(Bytes(data))
}

fn contract_call_data<T, P>(
	contract: &Contract<T>,
	operation: &'static str,
	function: &str,
	params: P,
) -> Result<Bytes, Error>
where
	T: mwc_web3::Transport,
	P: Tokenize,
{
	let data = contract
		.abi()
		.function(function)
		.and_then(|function| function.encode_input(&params.into_tokens()))
		.map_err(|source| Error::EthereumContract {
			operation,
			source: Box::new(mwc_web3::contract::Error::Abi(source)),
		})?;
	Ok(Bytes(data))
}

async fn estimate_contract_gas<T>(
	eth: &mwc_web3::api::Eth<T>,
	operation: &'static str,
	mut request: CallRequest,
	chain_id: u64,
	gas_budget: U256,
	block_number: BlockNumber,
) -> Result<(U256, U256), Error>
where
	T: mwc_web3::Transport,
{
	let node_gas_price = web3_call(operation, eth.gas_price()).await?;
	let gas_price = adjusted_gas_price(operation, node_gas_price)?;
	let block = web3_call(operation, eth.block(block_number.into()))
		.await?
		.ok_or_else(|| Error::EthereumRpc {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(format!(
				"node returned no {:?} block for {}",
				block_number, operation
			))),
		})?;
	let maximum_gas = if chain_id == 1 {
		block
			.gas_limit
			.min(U256::from(ETH_MAINNET_TRANSACTION_GAS_LIMIT))
	} else {
		block.gas_limit
	};
	request.gas = Some(maximum_gas);
	request.gas_price = Some(gas_price);
	let estimated_gas = web3_call(operation, eth.estimate_gas(request, Some(block_number))).await?;
	let gas = gas_estimate_with_margin(operation, estimated_gas)?;
	if gas > maximum_gas {
		return Err(Error::EthereumGasLimitExceeded {
			operation,
			required_gas: gas,
			maximum_gas,
		});
	}
	// The budget limits the fee; it must never reduce the gas needed to execute.
	ensure_gas_budget(operation, gas, gas_price, gas_budget)?;
	Ok((gas_price, gas))
}

fn adjusted_gas_price(operation: &'static str, node_gas_price: U256) -> Result<U256, Error> {
	#[allow(
		clippy::arithmetic_side_effects,
		reason = "the gas-price divisor is the fixed nonzero value two"
	)]
	let half_gas_price = node_gas_price / U256::from(2);
	let gas_price =
		node_gas_price
			.checked_add(half_gas_price)
			.ok_or_else(|| Error::EthereumSigning {
				operation,
				source: Box::new(mwc_web3::Error::InvalidResponse(format!(
					"adjusted gas price overflow, gas_price={} half_gas_price={}",
					node_gas_price, half_gas_price
				))),
			})?;
	if gas_price.is_zero() {
		return Err(Error::EthereumSigning {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(
				"node returned a zero gas price".to_string(),
			)),
		});
	}
	Ok(gas_price)
}

fn gas_estimate_with_margin(operation: &'static str, estimated_gas: U256) -> Result<U256, Error> {
	if estimated_gas.is_zero() {
		return Err(Error::EthereumSigning {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(
				"eth_estimateGas returned zero".to_string(),
			)),
		});
	}

	let numerator = U256::from(GAS_ESTIMATE_MARGIN_NUMERATOR);
	let denominator = U256::from(GAS_ESTIMATE_MARGIN_DENOMINATOR);
	let rounding = denominator.checked_sub(U256::from(1u8)).ok_or_else(|| {
		Error::DataOverflow("Ethereum gas estimate rounding underflow".to_string())
	})?;
	estimated_gas
		.checked_mul(numerator)
		.and_then(|scaled| scaled.checked_add(rounding))
		.and_then(|scaled| scaled.checked_div(denominator))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Ethereum gas estimate margin overflow, operation={} estimated_gas={}",
				operation, estimated_gas
			))
		})
}

fn ensure_gas_budget(
	operation: &'static str,
	gas: U256,
	gas_price: U256,
	gas_budget: U256,
) -> Result<(), Error> {
	let required_wei = gas.checked_mul(gas_price).ok_or_else(|| {
		Error::DataOverflow(format!(
			"Ethereum maximum fee overflow, operation={} gas={} gas_price={}",
			operation, gas, gas_price
		))
	})?;
	if required_wei > gas_budget {
		return Err(Error::EthereumGasBudgetExceeded {
			operation,
			required_wei,
			available_wei: gas_budget,
		});
	}
	Ok(())
}

/// Estimate and validate a native transfer before signing or broadcasting it.
/// The caller holds the account's submission lock through this entire operation.
async fn submit_ether_transfer<T>(
	eth: &mwc_web3::api::Eth<T>,
	from: Address,
	to: Address,
	value: U256,
	gas_budget: U256,
	chain_id: u64,
	private_key: &str,
) -> Result<H256, Error>
where
	T: mwc_web3::Transport,
{
	let operation = "construct Ether transfer";
	verify_chain_id(eth, chain_id).await?;
	let gas_price = web3_call("eth_gasPrice for Ether transfer", eth.gas_price()).await?;
	if gas_price.is_zero() {
		return Err(Error::EthereumSigning {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(
				"node returned a zero gas price".to_string(),
			)),
		});
	}
	let block = web3_call(
		"eth_getBlockByNumber(pending) for Ether transfer",
		eth.block(BlockNumber::Pending.into()),
	)
	.await?
	.ok_or_else(|| Error::EthereumRpc {
		operation: "eth_getBlockByNumber(pending) for Ether transfer",
		source: Box::new(mwc_web3::Error::InvalidResponse(
			"node returned no pending block".to_string(),
		)),
	})?;
	let maximum_gas = if chain_id == 1 {
		block
			.gas_limit
			.min(U256::from(ETH_MAINNET_TRANSACTION_GAS_LIMIT))
	} else {
		block.gas_limit
	};
	let estimate_request = CallRequest {
		from: Some(from),
		to: Some(to),
		gas: Some(maximum_gas),
		gas_price: Some(gas_price),
		value: Some(value),
		data: Some(Bytes::default()),
		..CallRequest::default()
	};
	let estimated_gas = web3_call(
		"eth_estimateGas for Ether transfer",
		eth.estimate_gas(estimate_request, Some(BlockNumber::Pending)),
	)
	.await?;
	// Size the transaction from its estimated work; the fee budget is only a ceiling.
	let gas = gas_estimate_with_margin(operation, estimated_gas)?;
	if gas > maximum_gas {
		return Err(Error::EthereumGasLimitExceeded {
			operation,
			required_gas: gas,
			maximum_gas,
		});
	}
	ensure_gas_budget(operation, gas, gas_price, gas_budget)?;
	let nonce = next_account_nonce(eth, chain_id, from).await?;
	let tx = legacy_transaction(nonce, to, gas, gas_price, value, Bytes::default(), chain_id);
	submit_prepared_transaction(
		eth,
		from,
		tx,
		private_key,
		gas_budget,
		RecoveryTarget::DirectTransfer,
		"sign Ether transfer",
	)
	.await
}

/// The caller holds the account submission lock through allocation and broadcast.
async fn submit_erc20_transfer<T: mwc_web3::Transport>(
	eth: &mwc_web3::api::Eth<T>,
	from: Address,
	token_address: Address,
	to: Address,
	value: U256,
	gas_budget: U256,
	chain_id: u64,
	private_key: &str,
) -> Result<H256, Error> {
	verify_chain_id(eth, chain_id).await?;
	let data = erc20_transfer_data(to, value)?;
	let node_gas_price = web3_call("eth_gasPrice for ERC20 transfer", eth.gas_price()).await?;
	let gas_price = adjusted_gas_price("construct ERC20 transfer", node_gas_price)?;
	let estimate_request = CallRequest {
		from: Some(from),
		to: Some(token_address),
		gas: None,
		gas_price: Some(gas_price),
		value: Some(U256::zero()),
		data: Some(data.clone()),
		..CallRequest::default()
	};
	let estimated_gas = web3_call(
		"eth_estimateGas for ERC20 transfer",
		eth.estimate_gas(estimate_request, Some(BlockNumber::Pending)),
	)
	.await?;
	let gas = gas_estimate_with_margin("construct ERC20 transfer", estimated_gas)?;
	ensure_gas_budget("construct ERC20 transfer", gas, gas_price, gas_budget)?;
	let nonce = next_account_nonce(eth, chain_id, from).await?;
	let tx = legacy_transaction(
		nonce,
		token_address,
		gas,
		gas_price,
		U256::from(0u8),
		data,
		chain_id,
	);
	submit_prepared_transaction(
		eth,
		from,
		tx,
		private_key,
		gas_budget,
		RecoveryTarget::DirectTransfer,
		"sign ERC20 transfer",
	)
	.await
}

fn sign_redeem_authorization(
	secret_key: &mwc_web3::signing::SecretKey,
	message: &[u8],
	operation: &'static str,
) -> Result<(H256, H256, u8), Error> {
	// Preserve the contract's existing authorization scheme exactly: hash the
	// packed swap fields first, then apply the EIP-191 personal-sign envelope to
	// that 32-byte digest. Applying EIP-191 directly to `message` would produce a
	// different signature and make every redeem revert.
	let packed_hash = signing::keccak256(message);
	let message_hash = signing::hash_message(packed_hash);
	let signature = SecretKeyRef::new(secret_key)
		.sign(message_hash.as_bytes(), None)
		.map_err(|source| Error::EthereumSigning {
			operation,
			source: Box::new(mwc_web3::Error::Signing(source)),
		})?;
	let v = u8::try_from(signature.v).map_err(|_| Error::EthereumSigning {
		operation,
		source: Box::new(mwc_web3::Error::InvalidResponse(format!(
			"redeem authorization recovery id {} does not fit u8",
			signature.v
		))),
	})?;
	if !matches!(v, 27 | 28) {
		return Err(Error::EthereumSigning {
			operation,
			source: Box::new(mwc_web3::Error::InvalidResponse(format!(
				"redeem authorization recovery id {} is not in Electrum notation",
				v
			))),
		});
	}
	Ok((signature.r, signature.s, v))
}

#[cfg(feature = "test-support")]
lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref REDEEM_WALLET:   RwLock<Option<EthereumWallet>>  = RwLock::new(None);
}

// macro_rules! mwc_web3_handle {
// 	($chain: expr, $projectid: expr) => {{
// 		let url = format!("wss://{}.infura.io/ws/v3/{}", $chain, $projectid);
// 		let transport = mwc_web3::transports::WebSocket::new(url.as_str())
// 			.await
// 			.unwrap();
// 		mwc_web3::Web3::new(transport)
// 		}};
// }

struct SwapContracts {
	native: Address,
	erc20: Address,
}

/// Infura Ethereum node client
pub struct InfuraNodeClient {
	/// Infura URI
	pub project_id: String,
	/// Chain
	pub chain: String,
	/// Wallet Inst
	pub wallet: EthereumWallet,
	/// Validated custody contracts for swap-capable clients.
	swap_contracts: Option<SwapContracts>,
}

impl InfuraNodeClient {
	/// Create a swap-capable instance with both custody contracts configured.
	pub fn new(
		project_id: String,
		chain: String,
		wallet: EthereumWallet,
		contract_addr: String,
		erc20_contract_addr: String,
	) -> Result<Self, Error> {
		expected_chain_id(&chain)?;
		let contract_addr = parse_swap_contract_address(SwapContractKind::Native, contract_addr)?;
		let erc20_contract_addr =
			parse_swap_contract_address(SwapContractKind::Erc20, erc20_contract_addr)?;
		Ok(Self {
			project_id,
			chain,
			wallet,
			swap_contracts: Some(SwapContracts {
				native: contract_addr,
				erc20: erc20_contract_addr,
			}),
		})
	}

	/// Create an account-only instance for balance queries and direct transfers.
	/// Swap operations fail closed unless the caller uses [`Self::new`].
	pub fn new_account(
		project_id: String,
		chain: String,
		wallet: EthereumWallet,
	) -> Result<Self, Error> {
		expected_chain_id(&chain)?;
		Ok(Self {
			project_id,
			chain,
			wallet,
			swap_contracts: None,
		})
	}

	fn native_swap_contract_address(&self) -> Result<Address, Error> {
		self.swap_contracts
			.as_ref()
			.map(|contracts| contracts.native)
			.ok_or(Error::UndefinedEthSwapContractAddress)
	}

	fn erc20_swap_contract_address(&self) -> Result<Address, Error> {
		self.swap_contracts
			.as_ref()
			.map(|contracts| contracts.erc20)
			.ok_or(Error::UndefinedERC20SwapContractAddress)
	}

	fn wallet_address(&self) -> Result<Address, Error> {
		to_eth_address(
			self.wallet
				.address
				.clone()
				.ok_or_else(|| Error::Generic("Ethereum wallet address is missing".to_string()))?,
		)
	}

	/// Locally encode and sign a contract mutation, then submit the exact signed
	/// bytes through the common ambiguous-outcome classifier. The caller receives
	/// a stable hash on success or in `EthereumSubmission*` errors.
	fn submit_contract_call<P>(
		&self,
		signing_wallet: &EthereumWallet,
		contract_address: Address,
		contract_abi: &'static str,
		function: &'static str,
		params: P,
		value: U256,
		gas_budget: U256,
		operation: &'static str,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error>
	where
		P: Tokenize + Send,
	{
		let chain_id = expected_chain_id(&self.chain)?;
		let from =
			to_eth_address(signing_wallet.address.clone().ok_or_else(|| {
				Error::Generic("Ethereum wallet address is missing".to_string())
			})?)?;
		let private_key = signing_wallet
			.private_key
			.as_deref()
			.ok_or_else(|| Error::Generic("Ethereum wallet private key is missing".to_string()))?;
		let account_lock = submission_lock(chain_id, from);
		let _submission_guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				operation,
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let eth = web3.eth();
			verify_chain_id(&eth, chain_id).await?;
			let contract =
				Contract::from_json(eth.clone(), contract_address, contract_abi.as_bytes())
					.map_err(|source| Error::EthereumContract {
						operation,
						source: Box::new(mwc_web3::contract::Error::Abi(source)),
					})?;
			let data = contract_call_data(&contract, operation, function, params)?;
			let (gas_price, gas) = estimate_contract_gas(
				&eth,
				operation,
				CallRequest {
					from: Some(from),
					to: Some(contract_address),
					value: Some(value),
					data: Some(data.clone()),
					..CallRequest::default()
				},
				chain_id,
				gas_budget,
				BlockNumber::Pending,
			)
			.await?;
			let nonce = next_account_nonce(&eth, chain_id, from).await?;
			let tx = legacy_transaction(
				nonce,
				contract_address,
				gas,
				gas_price,
				value,
				data,
				chain_id,
			);
			submit_prepared_transaction(
				&eth,
				from,
				tx,
				private_key,
				gas_budget,
				RecoveryTarget::Swap(recovery),
				operation,
			)
			.await
		};

		run_async(operation, task)
	}

	/// Retry a recorded swap transaction without allocating another account nonce.
	fn retry_contract_call(
		&self,
		signing_wallet: &EthereumWallet,
		currency: Currency,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		let contract = if currency.is_erc20() {
			self.erc20_swap_contract_address()?
		} else {
			self.native_swap_contract_address()?
		};
		self.retry_contract_call_to(signing_wallet, contract, record, gas_gwei)
	}

	/// The operation selects its expected destination: approval calls target the
	/// token, while deposits, redeems and refunds target the custody contract.
	fn retry_contract_call_to(
		&self,
		signing_wallet: &EthereumWallet,
		contract: Address,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		let chain_id = expected_chain_id(&self.chain)?;
		let from = to_eth_address(
			signing_wallet
				.address
				.clone()
				.ok_or_else(|| Error::Generic("Ethereum wallet address is missing".into()))?,
		)?;
		if record.chain_id != chain_id || record.sender != from || record.to != contract {
			return Err(Error::Generic(
				"Ethereum transaction recovery account, chain, or contract mismatch".into(),
			));
		}
		let account_lock = submission_lock(chain_id, from);
		let _guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let private_key = signing_wallet
			.private_key
			.as_deref()
			.ok_or_else(|| Error::Generic("Ethereum wallet private key is missing".into()))?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("retry Ethereum swap transaction", async move {
			let transport = web3_call(
				"connect for transaction recovery",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			retry_signed_transaction(
				&eth,
				record,
				gas_gwei,
				private_key,
				crate::swap::swap::get_cur_time(),
			)
			.await
		})
	}

	/// Retry a direct ETH/ERC20 transfer retained by this wallet process. Any
	/// attempted hash identifies the original payment; the nonce and payment
	/// remain fixed. None preserves the recorded maximum fee budget (in gwei).
	/// A mined revert is reported separately from a successful receipt.
	pub fn retry_transfer(
		&self,
		tx_hash: H256,
		gas_budget_gwei: Option<u64>,
	) -> Result<H256, Error> {
		let chain_id = expected_chain_id(&self.chain)?;
		let from = self.wallet_address()?;
		let account_lock = submission_lock(chain_id, from);
		let _guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let record = super::recovery::direct_transfer(chain_id, from, tx_hash)?;
		let gas_gwei = gas_budget_gwei.unwrap_or(record.gas_budget_gwei);
		let private_key = self
			.wallet
			.private_key
			.as_deref()
			.ok_or_else(|| Error::Generic("Ethereum wallet private key is missing".into()))?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("retry direct Ethereum transfer", async move {
			let transport = web3_call(
				"connect for direct transfer recovery",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			retry_direct_transfer(
				&eth,
				record,
				gas_gwei,
				private_key,
				crate::swap::swap::get_cur_time(),
			)
			.await
		})
	}

	/// get ether balance
	pub fn ether_balance(&self) -> Result<(String, u64), Error> {
		let account = self.wallet_address()?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for eth_getBalance",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let balance = web3_call("eth_getBalance", web3.eth().balance(account, None)).await?;
			normalized_ether_balance(balance)
		};

		run_async("eth_getBalance", task)
	}

	/// get erc20 token balance
	pub fn erc20_balance(&self, currency: Currency) -> Result<(String, u64), Error> {
		if !currency.is_erc20() {
			return Err(Error::UnexpectedCoinType);
		}
		let token_address = currency.erc20_token_address()?;
		let account = self.wallet_address()?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for ERC20 balanceOf",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let contract =
				Contract::from_json(web3.eth(), token_address, ERC20_TOKEN_CONTRACT.as_bytes())
					.map_err(|source| Error::EthereumContract {
						operation: "construct ERC20 contract",
						source: Box::new(mwc_web3::contract::Error::Abi(source)),
					})?;

			let balance: U256 = contract_call(
				"ERC20 balanceOf",
				contract.query("balanceOf", account, None, Options::default(), None),
			)
			.await?;
			let balance = if currency.is_expo_shrinked18to9() {
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "U256::exp10(9) is a fixed nonzero divisor"
				)]
				{
					balance / U256::exp10(9)
				}
			} else {
				balance
			};
			let balance_units = checked_u256_to_u64(balance, "ERC20 balance")?;
			Ok((
				currency.amount_to_hr_string(balance_units, true),
				balance_units,
			))
		};

		run_async("ERC20 balanceOf", task)
	}

	/// ether transfer
	fn ether_transfer(&self, to: Address, value: U256, gas_budget: U256) -> Result<H256, Error> {
		let from = self.wallet_address()?;
		let chain_id = expected_chain_id(&self.chain)?;
		let account_lock = submission_lock(chain_id, from);
		let _submission_guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let private_key =
			self.wallet.private_key.as_deref().ok_or_else(|| {
				Error::Generic("Ethereum wallet private key is missing".to_string())
			})?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for Ether transfer",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			submit_ether_transfer(
				&web3.eth(),
				from,
				to,
				value,
				gas_budget,
				chain_id,
				private_key,
			)
			.await
		};

		run_async("Ether transfer", task)
	}

	/// erc20 transfer
	fn erc20_transfer(
		&self,
		currency: Currency,
		to: Address,
		value: U256,
		gas_budget: U256,
	) -> Result<H256, Error> {
		if !currency.is_erc20() {
			return Err(Error::UnexpectedCoinType);
		}
		let token_address = currency.erc20_token_address()?;
		let from = self.wallet_address()?;
		let chain_id = expected_chain_id(&self.chain)?;
		let account_lock = submission_lock(chain_id, from);
		let _submission_guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let private_key =
			self.wallet.private_key.as_deref().ok_or_else(|| {
				Error::Generic("Ethereum wallet private key is missing".to_string())
			})?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for ERC20 transfer",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let eth = web3.eth();
			submit_erc20_transfer(
				&eth,
				from,
				token_address,
				to,
				value,
				gas_budget,
				chain_id,
				private_key,
			)
			.await
		};

		run_async("ERC20 transfer", task)
	}

	/// ether initiate swap offer
	fn ether_initiate(
		&self,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: U256,
		gas_limit: U256,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let contract_address = self.native_swap_contract_address()?;
		self.submit_contract_call(
			&self.wallet,
			contract_address,
			ETH_SWAP_CONTRACT,
			"initiate",
			(refund_time, address_from_secret, participant),
			value,
			gas_limit,
			"submit Ether swap initiate",
			recovery,
		)
	}

	/// erc20 initiate swap offer
	fn erc20_initiate(
		&self,
		currency: Currency,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: U256,
		gas_limit: U256,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let token_address = currency.erc20_token_address()?;
		let contract_address = self.erc20_swap_contract_address()?;
		self.submit_contract_call(
			&self.wallet,
			contract_address,
			ERC20_SWAP_CONTRACT,
			"initiate",
			(
				refund_time,
				address_from_secret,
				participant,
				token_address,
				value,
			),
			U256::zero(),
			gas_limit,
			"submit ERC20 swap initiate",
			recovery,
		)
	}

	/// ether buyer redeem
	fn ether_redeem(
		&self,
		signing_wallet: &EthereumWallet,
		address_from_secret: Address,
		secret_key: &mwc_web3::signing::SecretKey,
		gas_limit: U256,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let (refund_time, _, initiator, participant, _) =
			self.get_swap_details(Currency::Ether, address_from_secret)?;
		let refund_blocks = refund_time.to_big_endian();
		let authorization_message = [
			address_from_secret.as_bytes(),
			participant.as_bytes(),
			initiator.as_bytes(),
			refund_blocks.as_ref(),
		]
		.concat();
		let (r, s, v) = sign_redeem_authorization(
			secret_key,
			&authorization_message,
			"sign Ether redeem authorization",
		)?;

		let contract_address = self.native_swap_contract_address()?;
		self.submit_contract_call(
			signing_wallet,
			contract_address,
			ETH_SWAP_CONTRACT,
			"redeem",
			(address_from_secret, r, s, v),
			U256::zero(),
			gas_limit,
			"submit Ether swap redeem",
			recovery,
		)
	}

	/// erc20 buyer redeem
	fn erc20_redeem(
		&self,
		signing_wallet: &EthereumWallet,
		currency: Currency,
		address_from_secret: Address,
		secret_key: &mwc_web3::signing::SecretKey,
		gas_limit: U256,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let (refund_time, token_address, initiator, participant, _) =
			self.get_swap_details(currency, address_from_secret)?;
		let token_address = token_address.ok_or(Error::UnexpectedCoinType)?;
		let refund_blocks = refund_time.to_big_endian();
		let authorization_message = [
			address_from_secret.as_bytes(),
			participant.as_bytes(),
			initiator.as_bytes(),
			refund_blocks.as_ref(),
			token_address.as_bytes(),
		]
		.concat();
		let (r, s, v) = sign_redeem_authorization(
			secret_key,
			&authorization_message,
			"sign ERC20 redeem authorization",
		)?;

		let contract_address = self.erc20_swap_contract_address()?;
		self.submit_contract_call(
			signing_wallet,
			contract_address,
			ERC20_SWAP_CONTRACT,
			"redeem",
			(address_from_secret, r, s, v),
			U256::zero(),
			gas_limit,
			"submit ERC20 swap redeem",
			recovery,
		)
	}
}

impl EthNodeClient for InfuraNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		"Infura Node".to_string()
	}

	/// Fetch the current chain height
	fn height(&self) -> Result<u64, Error> {
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for eth_blockNumber",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let block_number = web3_call("eth_blockNumber", web3.eth().block_number()).await?;
			Ok(block_number.as_u64())
		};

		run_async("eth_blockNumber", task)
	}

	fn chain_tip(&self) -> Result<EthChainTip, Error> {
		let chain_id = expected_chain_id(&self.chain)?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for Ethereum chain tip",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			verify_chain_id(&eth, chain_id).await?;
			query_chain_tip(&eth).await
		};
		run_async("Ethereum chain tip", task)
	}

	fn finalized_block(&self) -> Result<H256, Error> {
		let chain_id = expected_chain_id(&self.chain)?;
		if chain_id != 1 {
			return Err(Error::EthereumFinalityUnavailable(format!(
				"chain {} does not support finalized Ethereum swaps",
				chain_id
			)));
		}
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("Ethereum finalized block", async move {
			let transport = web3_call(
				"connect for Ethereum finality",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			verify_chain_id(&eth, chain_id).await?;
			query_finalized_block(&eth).await
		})
	}

	fn validate_chain_and_contracts(&self) -> Result<EthChainTip, Error> {
		let expected_chain_id = expected_chain_id(&self.chain)?;
		let native_address = self.native_swap_contract_address()?;
		let erc20_address = self.erc20_swap_contract_address()?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		let task = async move {
			let transport = web3_call(
				"connect for Ethereum swap contract validation",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			let eth = web3.eth();
			verify_chain_id(&eth, expected_chain_id).await?;
			let tip = query_chain_tip(&eth).await?;
			let block = Some(BlockNumber::Number(tip.height.into()));
			let native_code = web3_call(
				"eth_getCode for native swap contract",
				eth.code(native_address, block),
			)
			.await?;
			let erc20_code = web3_call(
				"eth_getCode for ERC20 swap contract",
				eth.code(erc20_address, block),
			)
			.await?;

			validate_swap_contract_runtime(
				expected_chain_id,
				SwapContractKind::Native,
				native_address,
				&native_code.0,
			)?;
			validate_swap_contract_runtime(
				expected_chain_id,
				SwapContractKind::Erc20,
				erc20_address,
				&erc20_code.0,
			)?;
			Ok(tip)
		};

		run_async("validate Ethereum swap contracts", task)
	}

	/// get wallet balance
	fn balance(&self, currency: Currency) -> Result<(String, u64), Error> {
		match currency {
			Currency::Ether => self.ether_balance(),
			currency if currency.is_erc20() => self.erc20_balance(currency),
			_ => Err(Error::UnexpectedCoinType),
		}
	}

	/// Retrieve transaction receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = web3_call(
				"connect for eth_getTransactionReceipt",
				mwc_web3::transports::WebSocket::new(url.as_str()),
			)
			.await?;
			let web3 = mwc_web3::Web3::new(transport);
			web3_call(
				"eth_getTransactionReceipt",
				web3.eth().transaction_receipt(tx_hash),
			)
			.await
		};

		// A successful null response means no mined receipt is available yet. Retain
		// the transaction hash even if it has not propagated to this endpoint.
		run_async("eth_getTransactionReceipt", task)?.ok_or(Error::EthTransactionInPending)
	}

	/// Send coins
	fn transfer(&self, currency: Currency, to: Address, value: u64) -> Result<H256, Error> {
		if !currency.is_ethereum_family() {
			return Err(Error::UnexpectedCoinType);
		}
		if to == Address::zero() {
			return Err(Error::ZeroEthTransferAddress);
		}
		let gas_budget = gas_limit_from_gwei(DEFAULT_TRANSFER_GAS_BUDGET_GWEI)?;
		let balance_ether = self.balance(Currency::Ether)?;
		// Scaling any u64 gwei amount by 10^9 is below 2^94 and fits U256.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "a u64 value multiplied by 10^9 fits within U256"
		)]
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if currency == Currency::Ether {
			// Both operands originate from u64 values scaled by 10^9; their sum is
			// below 2^95 and fits U256.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "scaled u64 value and fixed gas budget sum to less than 2^95"
			)]
			let value = U256::from(value) * U256::exp10(9);
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "scaled u64 value and fixed gas budget sum to less than 2^95"
			)]
			let required = gas_budget + value;
			if balance_ether < required {
				return Err(Error::EthBalanceNotEnough);
			}
			self.ether_transfer(to, value, gas_budget)
		} else {
			if balance_ether < gas_budget {
				return Err(Error::EthBalanceNotEnough);
			}

			let balance_token = self.balance(currency)?;
			let balance_token = U256::from(balance_token.1);
			let balance_token = match currency.is_expo_shrinked18to9() {
				// balance_token came from u64, so this scaling fits U256.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "a u64 token balance multiplied by 10^9 fits within U256"
				)]
				true => balance_token * U256::exp10(9),
				false => balance_token,
			};
			let value = match currency.is_expo_shrinked18to9() {
				// value is u64, so this scaling fits U256.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "a u64 token amount multiplied by 10^9 fits within U256"
				)]
				true => U256::from(value) * U256::exp10(9),
				false => U256::from(value),
			};

			if balance_token < value {
				return Err(Error::ERC20TokenBalanceNotEnough(format!("{}", currency)));
			}

			self.erc20_transfer(currency, to, value, gas_budget)
		}
	}

	/// Retain signed recovery until the receipt's block is finalized and canonical.
	fn receipt_is_finalized(&self, receipt: &TransactionReceipt) -> Result<bool, Error> {
		let chain_id = expected_chain_id(&self.chain)?;
		if chain_id != 1 {
			// Legacy proof-of-work networks have no finalized block tag.
			return Ok(false);
		}
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("check Ethereum receipt finality", async move {
			let transport = web3_call(
				"connect for Ethereum finality",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			verify_chain_id(&eth, chain_id).await?;
			receipt_is_finalized(&eth, receipt).await
		})
	}

	fn retry_deposit(
		&self,
		currency: Currency,
		record: &mut EthTransactionRecovery,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		self.retry_contract_call(&self.wallet, currency, record, gas_gwei)
	}

	fn cancel_deposit(
		&self,
		currency: Currency,
		original: &EthTransactionRecovery,
		cancellation: &mut Option<EthTransactionRecovery>,
		gas_gwei: u64,
	) -> Result<H256, Error> {
		let key = self.erc20_allowance_key(currency)?;
		if original.chain_id != key.chain_id
			|| original.sender != key.owner
			|| original.to != key.spender
		{
			return Err(Error::Generic(
				"Deposit recovery account, chain, or contract mismatch".into(),
			));
		}
		if let Some(record) = cancellation.as_mut() {
			if record.nonce != original.nonce
				|| !record.value.is_zero()
				|| !record.data.0.is_empty()
			{
				return Err(Error::Generic(
					"Deposit cancellation recovery call mismatch".into(),
				));
			}
			return self.retry_contract_call_to(&self.wallet, key.owner, record, gas_gwei);
		}
		let account_lock = submission_lock(key.chain_id, key.owner);
		let _guard = account_lock
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let private_key = self
			.wallet
			.private_key
			.as_deref()
			.ok_or_else(|| Error::Generic("Ethereum wallet private key is missing".into()))?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("cancel Ethereum deposit", async move {
			let transport = web3_call(
				"connect for deposit cancellation",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			cancel_signed_deposit(&eth, original, cancellation, gas_gwei, private_key).await
		})
	}

	/// Account/token/spender identity for the shared allowance.
	fn erc20_allowance_key(&self, currency: Currency) -> Result<Erc20AllowanceKey, Error> {
		if !currency.is_erc20() {
			return Err(Error::UnexpectedCoinType);
		}
		Ok(Erc20AllowanceKey {
			chain_id: expected_chain_id(&self.chain)?,
			owner: self.wallet_address()?,
			token: currency.erc20_token_address()?,
			spender: self.erc20_swap_contract_address()?,
		})
	}

	fn erc20_allowance(&self, currency: Currency) -> Result<U256, Error> {
		let key = self.erc20_allowance_key(currency)?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("ERC20 allowance", async move {
			let transport = web3_call(
				"connect for ERC20 allowance",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			query_erc20_allowance(eth, key).await
		})
	}

	/// Submit one approval; the funding workflow handles allowance reuse and resets.
	fn erc20_approve(
		&self,
		currency: Currency,
		value: u64,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let token_address = currency.erc20_token_address()?;
		let swap_contract_address = self.erc20_swap_contract_address()?;
		let value = super::funding::token_amount(currency, value)?;
		if let Some(record) = recovery.as_mut() {
			if !record.value.is_zero()
				|| record.data != erc20_call_data("approve", swap_contract_address, value)?
			{
				return Err(Error::Generic(
					"ERC20 approval recovery call mismatch".into(),
				));
			}
			return self.retry_contract_call_to(&self.wallet, token_address, record, gas_gwei);
		}
		let gas_limit = gas_limit_from_gwei(gas_gwei)?;
		let balance_ether = self.balance(Currency::Ether)?;
		// Scaling any u64 gwei balance by 10^9 fits U256.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "a u64 value multiplied by 10^9 fits within U256"
		)]
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		let balance_token = self.balance(currency)?;
		let balance_token = U256::from(balance_token.1);
		let balance_token = match currency.is_expo_shrinked18to9() {
			// balance_token came from u64, so this scaling fits U256.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "a u64 token balance multiplied by 10^9 fits within U256"
			)]
			true => balance_token * U256::exp10(9),
			false => balance_token,
		};

		if balance_token < value {
			return Err(Error::ERC20TokenBalanceNotEnough(format!("{}", currency)));
		}

		self.submit_contract_call(
			&self.wallet,
			token_address,
			ERC20_TOKEN_CONTRACT,
			"approve",
			(swap_contract_address, value),
			U256::zero(),
			gas_limit,
			"submit ERC20 approve",
			recovery,
		)
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
		if let Some(record) = recovery.as_mut() {
			return self.retry_contract_call(&self.wallet, currency, record, gas_gwei);
		}
		let gas_limit = gas_limit_from_gwei(gas_gwei)?;
		let balance_ether = self.balance(Currency::Ether)?;
		// Scaling any u64 gwei balance by 10^9 fits U256.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "a u64 value multiplied by 10^9 fits within U256"
		)]
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if !currency.is_erc20() {
			// Both operands originate from u64 values scaled by 10^9; their sum fits U256.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "scaled u64 value and gas limit sum to less than 2^95"
			)]
			let value = U256::from(value) * U256::exp10(9);
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "scaled u64 value and gas limit sum to less than 2^95"
			)]
			let required = gas_limit + value;
			if balance_ether < required {
				return Err(Error::EthBalanceNotEnough);
			}

			self.ether_initiate(
				refund_time,
				address_from_secret,
				participant,
				value,
				gas_limit,
				recovery,
			)
		} else {
			// one gas_limit for approve, the other one for initiate
			if balance_ether < gas_limit {
				return Err(Error::EthBalanceNotEnough);
			}

			let value = match currency.is_expo_shrinked18to9() {
				// value is u64, so this scaling fits U256.
				#[allow(
					clippy::arithmetic_side_effects,
					reason = "a u64 token amount multiplied by 10^9 fits within U256"
				)]
				true => U256::from(value) * U256::exp10(9),
				_ => U256::from(value),
			};

			self.erc20_initiate(
				currency,
				refund_time,
				address_from_secret,
				participant,
				U256::from(value),
				gas_limit,
				recovery,
			)
		}
	}

	/// buyer redeem
	fn redeem(
		&self,
		currency: Currency,
		address_from_secret: Address,
		secret_key: &mwc_web3::signing::SecretKey,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		#[cfg(feature = "test-support")]
		let test_redeem_wallet = if is_test_mode() {
			REDEEM_WALLET.read().clone()
		} else {
			None
		};
		#[cfg(feature = "test-support")]
		let signing_wallet = test_redeem_wallet.as_ref().unwrap_or(&self.wallet);
		#[cfg(not(feature = "test-support"))]
		let signing_wallet = &self.wallet;

		if let Some(record) = recovery.as_mut() {
			return self.retry_contract_call(signing_wallet, currency, record, gas_gwei);
		}
		let gas_limit = gas_limit_from_gwei(gas_gwei)?;
		let balance_ether = self.balance(Currency::Ether)?;
		// Scaling any u64 gwei balance by 10^9 fits U256.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "a u64 value multiplied by 10^9 fits within U256"
		)]
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);
		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		if !currency.is_erc20() {
			self.ether_redeem(
				signing_wallet,
				address_from_secret,
				secret_key,
				gas_limit,
				recovery,
			)
		} else {
			self.erc20_redeem(
				signing_wallet,
				currency,
				address_from_secret,
				secret_key,
				gas_limit,
				recovery,
			)
		}
	}

	/// refund ether
	fn refund(
		&self,
		currency: Currency,
		address_from_secret: Address,
		gas_gwei: u64,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		if let Some(record) = recovery.as_mut() {
			return self.retry_contract_call(&self.wallet, currency, record, gas_gwei);
		}
		let gas_limit = gas_limit_from_gwei(gas_gwei)?;
		let balance_ether = self.balance(Currency::Ether)?;
		// Scaling any u64 gwei balance by 10^9 fits U256.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "a u64 value multiplied by 10^9 fits within U256"
		)]
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);
		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		let height = self.height()?;
		let swap_details = self.get_swap_details(currency, address_from_secret)?;
		let refund_time_blocks = swap_details.0;
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"refund: hegiht = {}, refund_time_blocks = {}",
				height, refund_time_blocks
			);
		}
		if U256::from(height) < refund_time_blocks {
			return Err(Error::EthRefundTimeNotArrived);
		}

		let (contract_address, contract_abi) = if currency.is_erc20() {
			(self.erc20_swap_contract_address()?, ERC20_SWAP_CONTRACT)
		} else {
			(self.native_swap_contract_address()?, ETH_SWAP_CONTRACT)
		};
		self.submit_contract_call(
			&self.wallet,
			contract_address,
			contract_abi,
			"refund",
			address_from_secret,
			U256::zero(),
			gas_limit,
			"submit swap refund",
			recovery,
		)
	}

	/// get swap info
	fn get_swap_details(
		&self,
		currency: Currency,
		address_from_secret: Address,
	) -> Result<EthSwapDetails, Error> {
		self.get_swap_details_at(currency, address_from_secret, BlockNumber::Latest.into())
	}

	fn get_swap_details_at(
		&self,
		currency: Currency,
		address_from_secret: Address,
		block: BlockId,
	) -> Result<EthSwapDetails, Error> {
		let contract_address = if currency.is_erc20() {
			self.erc20_swap_contract_address()?
		} else {
			self.native_swap_contract_address()?
		};
		let chain_id = expected_chain_id(&self.chain)?;
		let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
		run_async("getSwapDetails", async move {
			let transport = web3_call(
				"connect for getSwapDetails",
				mwc_web3::transports::WebSocket::new(&url),
			)
			.await?;
			let eth = mwc_web3::Web3::new(transport).eth();
			verify_chain_id(&eth, chain_id).await?;
			query_swap_details_at(&eth, currency, contract_address, address_from_secret, block).await
		})
	}
}

/// Infura client error response.
/*#[derive(Serialize, Deserialize, Debug)]
struct InfuraResponseError {
	code: i64,
	pub message: String,
}*/

#[cfg(all(test, feature = "test-support"))]
mod tests {
	use super::*;
	use jsonrpc_core::{Call as RpcCall, Value as RpcValue};
	use mwc_wallet_util::mwc_crates::serde_json::{self, json};
	use std::future::{Ready, ready};
	use std::{thread, time};
	const MNMENOIC: &str = "square social wall upgrade owner flat razor across enable idea mirror autumn rescue pottery total seat confirm dizzy fabric couple reveal relief lucky session";
	const REDEEM_MNMENOIC: &str = "chef bunker radar park canal run manage regular clarify drop display retreat wool brisk olympic recall cash sample slender fruit tell lunar young unusual";
	const WALLET_PATH: &str = "m/44'/0'/0'/0";
	const PROJECT_ID: &str = "d00e825c599c45a19b18dc4003626bee";
	const CHAIN: &str = "ropsten";
	const CONTRACT_ADDR: &str = "A21b2c034dF046a3DB790dd20b0C5C0040a74c67";
	const ERC20_CONTRACT_ADDR: &str = "8955539Ea48A5d9196cdB2f8a7F67eB0dC7d15df";

	#[derive(Clone, Debug)]
	struct ChainTipTransport(mwc_web3::Result<RpcValue>);

	impl mwc_web3::Transport for ChainTipTransport {
		type Out = Ready<mwc_web3::Result<RpcValue>>;

		fn prepare(&self, method: &str, params: Vec<RpcValue>) -> (mwc_web3::RequestId, RpcCall) {
			assert_eq!(method, "eth_getBlockByNumber");
			assert_eq!(params, vec![json!("latest"), json!(false)]);
			(1, mwc_web3::helpers::build_request(1, method, params))
		}

		fn send(&self, _id: mwc_web3::RequestId, _request: RpcCall) -> Self::Out {
			ready(self.0.clone())
		}
	}

	#[test]
	fn chain_tip_reads_one_mined_block_and_rejects_invalid_responses() {
		let query = |response| {
			let eth = mwc_web3::api::Eth::new(ChainTipTransport(response));
			run_async("test Ethereum chain tip", query_chain_tip(&eth))
		};
		let mut block = mwc_web3::types::Block::<H256> {
			number: Some(25_000_000.into()),
			timestamp: 1_800_000_000u64.into(),
			..Default::default()
		};
		assert_eq!(
			query(Ok(json!(block))).unwrap(),
			EthChainTip {
				height: 25_000_000,
				timestamp: 1_800_000_000,
			}
		);
		assert!(matches!(
			query(Ok(json!(null))),
			Err(Error::EthereumRpc { .. })
		));
		block.number = None;
		assert!(matches!(
			query(Ok(json!(block))),
			Err(Error::EthereumRpc { .. })
		));
		block.number = Some(25_000_000.into());
		block.timestamp = U256::from(u64::MAX) + U256::from(1u8);
		assert!(matches!(
			query(Ok(json!(block))),
			Err(Error::DataOverflow(_))
		));
		assert!(matches!(
			query(Err(mwc_web3::Error::Unreachable)),
			Err(Error::EthereumRpc { .. })
		));
	}

	/// Script the RPC responses while retaining the actual signed transaction.
	#[derive(Clone, Debug)]
	struct EtherTransferTransport {
		gas_price: U256,
		block_gas_limit: U256,
		estimate: mwc_web3::Result<U256>,
		pending_estimate: Option<mwc_web3::Result<U256>>,
		nonce: U256,
		pending_nonce: Option<U256>,
		finalized_nonce: U256,
		check_direct_sender: Option<Address>,
		receipt_results:
			Arc<StdMutex<std::collections::VecDeque<mwc_web3::Result<Option<TransactionReceipt>>>>>,
		block_results: Arc<StdMutex<std::collections::VecDeque<mwc_web3::Result<RpcValue>>>>,
		call_results: Arc<StdMutex<std::collections::VecDeque<mwc_web3::Result<RpcValue>>>>,
		submission_errors: Arc<StdMutex<std::collections::VecDeque<mwc_web3::Error>>>,
		requests: Arc<StdMutex<Vec<(String, Vec<RpcValue>)>>>,
	}

	impl EtherTransferTransport {
		fn new(gas_price: u64, block_gas_limit: u64, estimate: mwc_web3::Result<U256>) -> Self {
			Self {
				gas_price: U256::from(gas_price),
				block_gas_limit: U256::from(block_gas_limit),
				estimate,
				pending_estimate: None,
				nonce: U256::from(7u64),
				pending_nonce: None,
				finalized_nonce: U256::zero(),
				check_direct_sender: None,
				receipt_results: Arc::new(StdMutex::new(std::collections::VecDeque::new())),
				block_results: Arc::new(StdMutex::new(std::collections::VecDeque::new())),
				call_results: Arc::new(StdMutex::new(std::collections::VecDeque::new())),
				submission_errors: Arc::new(StdMutex::new(std::collections::VecDeque::new())),
				requests: Arc::new(StdMutex::new(Vec::new())),
			}
		}
	}

	impl mwc_web3::Transport for EtherTransferTransport {
		type Out = Ready<mwc_web3::Result<RpcValue>>;

		fn prepare(&self, method: &str, params: Vec<RpcValue>) -> (mwc_web3::RequestId, RpcCall) {
			let mut requests = self.requests.lock().unwrap();
			requests.push((method.to_string(), params.clone()));
			let id = requests.len();
			(id, mwc_web3::helpers::build_request(id, method, params))
		}

		fn send(&self, _id: mwc_web3::RequestId, request: RpcCall) -> Self::Out {
			let RpcCall::MethodCall(call) = request else {
				panic!("unexpected RPC request: {request:?}");
			};
			ready(match call.method.as_str() {
				"eth_chainId" => Ok(json!(U256::from(1u64))),
				"eth_call" => self
					.call_results
					.lock()
					.unwrap()
					.pop_front()
					.unwrap_or_else(|| Ok(json!(Bytes(U256::MAX.to_big_endian().to_vec())))),
				"eth_gasPrice" => Ok(json!(self.gas_price)),
				"eth_getTransactionReceipt" => self
					.receipt_results
					.lock()
					.unwrap()
					.pop_front()
					.unwrap_or(Ok(None))
					.map(|receipt| json!(receipt)),
				"eth_getBlockByNumber" => self
					.block_results
					.lock()
					.unwrap()
					.pop_front()
					.unwrap_or_else(|| {
						Ok(json!(mwc_web3::types::Block::<H256> {
							gas_limit: self.block_gas_limit,
							..Default::default()
						}))
					}),
				"eth_estimateGas" => {
					let jsonrpc_core::Params::Array(params) = call.params else {
						panic!("expected positional gas estimation parameters");
					};
					let estimate = if params.get(1) == Some(&json!("pending")) {
						self.pending_estimate.as_ref().unwrap_or(&self.estimate)
					} else {
						&self.estimate
					};
					estimate.clone().map(|gas| json!(gas))
				}
				"eth_getTransactionCount" => {
					let jsonrpc_core::Params::Array(params) = call.params else {
						panic!("expected positional nonce parameters");
					};
					Ok(json!(if params[1] == json!("pending") {
						self.pending_nonce.unwrap_or(self.nonce)
					} else if params[1] == json!("finalized") {
						self.finalized_nonce
					} else {
						self.nonce
					}))
				}
				"eth_sendRawTransaction" => {
					let jsonrpc_core::Params::Array(params) = call.params else {
						panic!("expected positional transaction parameters");
					};
					let raw: Bytes = serde_json::from_value(params[0].clone()).unwrap();
					let hash = H256::from(signing::keccak256(&raw.0));
					if let Some(sender) = self.check_direct_sender {
						// Assert recovery exists before the RPC can accept or fail this send.
						let saved =
							super::super::recovery::direct_transfer(1, sender, hash).unwrap();
						assert_eq!(saved.raw_transaction, raw);
						assert_eq!(
							saved.nonce,
							rlp::Rlp::new(&raw.0).val_at::<U256>(0).unwrap()
						);
					}
					if let Some(error) = self.submission_errors.lock().unwrap().pop_front() {
						return ready(Err(error));
					}
					Ok(json!(hash))
				}
				_ => panic!("unexpected RPC method: {}", call.method),
			})
		}
	}

	fn run_ether_transfer(transport: EtherTransferTransport) -> Result<H256, Error> {
		let private_key = "01".repeat(32);
		let key = secret_key_from_hex(&private_key).unwrap();
		let from = SecretKeyRef::new(&key).address();
		let eth = mwc_web3::api::Eth::new(transport);
		let account_lock = submission_lock(1, from);
		let _guard = account_lock.lock().unwrap();
		super::super::recovery::forget_for_test(1, from);
		let result = Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap()
			.block_on(submit_ether_transfer(
				&eth,
				from,
				Address::repeat_byte(0x42),
				U256::from(1_000_000_000_000_000_000u64),
				gas_limit_from_gwei(DEFAULT_TRANSFER_GAS_BUDGET_GWEI).unwrap(),
				1,
				&private_key,
			));
		super::super::recovery::forget_for_test(1, from);
		result
	}

	#[test]
	fn swap_submission_failure_survives_restart_and_replaces_at_the_same_nonce() {
		let operation = "test swap transaction recovery";
		let private_key = "24".repeat(32);
		let key = secret_key_from_hex(&private_key).unwrap();
		let from = SecretKeyRef::new(&key).address();
		let budget_gwei = 30_000;
		let gas = U256::from(100_000u64);
		let gas_price = U256::from(150_000_000u64);
		let period = crate::swap::fsm::state::POST_SECONDARY_RETRY_PERIOD;
		for (currency, function, approval_amount) in [
			(Currency::Ether, "redeem", 0),
			(Currency::Usdt, "redeem", 0),
			(Currency::Ether, "refund", 0),
			(Currency::Usdt, "refund", 0),
			(Currency::Ether, "initiate", 0),
			(Currency::Usdt, "initiate", 0),
			(Currency::Usdt, "approve", 0),
			(Currency::Usdt, "approve", 100),
			(Currency::Dai, "approve", 0),
			(Currency::Dai, "approve", 100),
		] {
			// Each case starts from the same simulated chain state. Direct transfers
			// now retain nonce 8 as well, so reset both kinds of recovery between cases.
			super::super::recovery::forget_for_test(1, from);
			let abi = if function == "approve" {
				ERC20_TOKEN_CONTRACT
			} else if currency.is_erc20() {
				ERC20_SWAP_CONTRACT
			} else {
				ETH_SWAP_CONTRACT
			};
			let mut transport = EtherTransferTransport::new(100_000_000, 30_000_000, Ok(gas));
			let eth = mwc_web3::api::Eth::new(transport.clone());
			let contract_address = if function == "approve" {
				currency.erc20_token_address().unwrap()
			} else {
				Address::repeat_byte(0x42)
			};
			let contract =
				Contract::from_json(eth.clone(), contract_address, abi.as_bytes()).unwrap();
			let data = if function == "approve" {
				erc20_call_data(
					"approve",
					Address::repeat_byte(0x42),
					super::super::funding::token_amount(currency, approval_amount).unwrap(),
				)
			} else if function == "initiate" {
				let params = (
					1234u64,
					Address::repeat_byte(0x43),
					Address::repeat_byte(0x44),
				);
				if currency.is_erc20() {
					contract_call_data(
						&contract,
						operation,
						function,
						(
							params.0,
							params.1,
							params.2,
							currency.erc20_token_address().unwrap(),
							U256::from(100),
						),
					)
				} else {
					contract_call_data(&contract, operation, function, params)
				}
			} else if function == "refund" {
				contract_call_data(&contract, operation, function, Address::repeat_byte(0x43))
			} else {
				let (r, s, v) =
					sign_redeem_authorization(&key, b"swap authorization", operation).unwrap();
				contract_call_data(
					&contract,
					operation,
					function,
					(Address::repeat_byte(0x43), r, s, v),
				)
			}
			.unwrap();
			let value = if function == "initiate" && !currency.is_erc20() {
				U256::from(100)
			} else {
				U256::zero()
			};
			let tx = legacy_transaction(
				7.into(),
				contract_address,
				gas,
				gas_price,
				value,
				data.clone(),
				1,
			);
			transport
				.submission_errors
				.lock()
				.unwrap()
				.push_back(mwc_web3::Error::Unreachable);
			let mut recovery = None;
			let result = run_async(
				operation,
				submit_prepared_transaction(
					&eth,
					from,
					tx,
					&private_key,
					gas_limit_from_gwei(budget_gwei).unwrap(),
					RecoveryTarget::Swap(&mut recovery),
					operation,
				),
			);
			let original_hash = recovery.as_ref().unwrap().attempted_hashes[0];
			assert!(
				matches!(result, Err(Error::EthereumSubmissionUnknown { tx_hash, .. })
				if tx_hash == original_hash)
			);

			// Restore exactly what is persisted after the failed submission.
			let mut restored: EthTransactionRecovery =
				serde_json::from_str(&serde_json::to_string(&recovery.unwrap()).unwrap()).unwrap();
			let original_raw = restored.raw_transaction.clone();
			let start = restored.last_attempt_at;
			if function == "approve" {
				let client = InfuraNodeClient::new(
					"unused".into(),
					"mainnet".into(),
					EthereumWallet::from_private_key(&private_key).unwrap(),
					eth_address(Address::repeat_byte(0x42)),
					eth_address(Address::repeat_byte(0x42)),
				)
				.unwrap();
				// Approval recovery must reject another chain/account/token/spender,
				// changed value or amount, before attempting any network access.
				for mismatch in 0..6 {
					let mut invalid = restored.clone();
					match mismatch {
						0 => invalid.chain_id = 3,
						1 => invalid.sender = Address::zero(),
						2 => invalid.to = Address::repeat_byte(0x42),
						3 => invalid.value = U256::one(),
						4 => {
							invalid.data = erc20_call_data(
								"approve",
								Address::repeat_byte(0x43),
								super::super::funding::token_amount(currency, approval_amount)
									.unwrap(),
							)
							.unwrap()
						}
						_ => {
							invalid.data = erc20_call_data(
								"approve",
								Address::repeat_byte(0x42),
								super::super::funding::token_amount(currency, approval_amount + 1)
									.unwrap(),
							)
							.unwrap()
						}
					}
					let mut recovery = Some(invalid);
					let before = serde_json::to_string(&recovery).unwrap();
					assert!(matches!(
						client.erc20_approve(currency, approval_amount, budget_gwei, &mut recovery),
						Err(Error::Generic(_))
					));
					assert_eq!(serde_json::to_string(&recovery).unwrap(), before);
				}
			}
			assert!(matches!(
				run_async(
					operation,
					retry_signed_transaction(
						&eth,
						&mut restored,
						budget_gwei,
						&private_key,
						start + period - 1
					)
				),
				Err(Error::EthTransactionInPending)
			));

			// An already-known response is still ambiguous until a receipt exists.
			transport
				.submission_errors
				.lock()
				.unwrap()
				.push_back(mwc_web3::Error::Rpc(jsonrpc_core::Error {
					code: jsonrpc_core::ErrorCode::ServerError(-32000),
					message: "already known".into(),
					data: None,
				}));
			assert!(
				matches!(run_async(operation, retry_signed_transaction(&eth, &mut restored,
				budget_gwei, &private_key, start + period)),
				Err(Error::EthereumSubmissionUnknown { tx_hash, .. }) if tx_hash == original_hash)
			);
			assert_eq!(restored.raw_transaction, original_raw);
			assert_eq!(restored.attempted_hashes, vec![original_hash]);

			// The next timed retry raises the price even if the node's suggestion
			// has not moved; no new nonce or pending-state gas estimate is needed.
			let replacement = run_async(
				operation,
				retry_signed_transaction(
					&eth,
					&mut restored,
					budget_gwei,
					&private_key,
					start + 2 * period,
				),
			)
			.unwrap();
			assert_ne!(replacement, original_hash);
			assert_eq!(restored.attempted_hashes, vec![original_hash, replacement]);
			assert_eq!(restored.gas_price, U256::from(180_000_000u64));

			// A changed budget permits an immediate replacement, but only within
			// its cap. A rejected budget must leave the current recovery intact.
			let before = serde_json::to_string(&restored).unwrap();
			assert!(matches!(
				run_async(
					operation,
					retry_signed_transaction(
						&eth,
						&mut restored,
						1,
						&private_key,
						start + 2 * period
					)
				),
				Err(Error::EthereumGasBudgetExceeded { .. })
			));
			assert_eq!(serde_json::to_string(&restored).unwrap(), before);
			transport
				.submission_errors
				.lock()
				.unwrap()
				.push_back(mwc_web3::Error::Rpc(jsonrpc_core::Error {
					code: jsonrpc_core::ErrorCode::ServerError(-32000),
					message: "nonce too low".into(),
					data: None,
				}));
			let result = run_async(
				operation,
				retry_signed_transaction(
					&eth,
					&mut restored,
					40_000,
					&private_key,
					start + 2 * period,
				),
			);
			assert!(
				matches!(result, Err(Error::EthereumSubmissionUnknown { tx_hash, .. })
				if Some(&tx_hash) == restored.attempted_hashes.last())
			);
			assert_eq!(restored.gas_budget_gwei, 40_000);
			assert_eq!(restored.attempted_hashes.len(), 3);

			transport.nonce = U256::from(8u64);
			let consumed = mwc_web3::api::Eth::new(transport.clone());
			assert!(matches!(
				run_async(
					operation,
					retry_signed_transaction(
						&consumed,
						&mut restored,
						40_000,
						&private_key,
						start + 3 * period
					)
				),
				Err(Error::EthereumTransactionNonceConsumed { .. })
			));

			let requests = transport.requests.lock().unwrap();
			assert!(
				!requests
					.iter()
					.any(|(method, _)| method == "eth_estimateGas")
			);
			let raws: Vec<Bytes> = requests
				.iter()
				.filter(|(method, _)| method == "eth_sendRawTransaction")
				.map(|(_, params)| serde_json::from_value(params[0].clone()).unwrap())
				.collect();
			assert_eq!(raws.len(), 4);
			assert_eq!(raws[0], raws[1]);
			for (raw, expected_price) in
				raws.iter()
					.zip([150_000_000u64, 150_000_000, 180_000_000, 216_000_000])
			{
				let signed = rlp::Rlp::new(&raw.0);
				assert_eq!(signed.val_at::<U256>(0).unwrap(), U256::from(7u64));
				assert_eq!(
					signed.val_at::<U256>(1).unwrap(),
					U256::from(expected_price)
				);
				assert_eq!(signed.val_at::<U256>(2).unwrap(), gas);
				assert_eq!(signed.val_at::<Address>(3).unwrap(), contract_address);
				assert_eq!(signed.val_at::<U256>(4).unwrap(), value);
				assert_eq!(signed.val_at::<Vec<u8>>(5).unwrap(), data.0);
				assert!(matches!(signed.val_at::<u64>(6).unwrap(), 37 | 38)); // EIP-155, chain 1.
			}
			drop(requests);

			// A normal transfer must wait if the node drops this transaction. Merely
			// skipping nonce 7 would queue nonce 8 behind a gap, which a later
			// pending-count query could offer for reuse by another transfer.
			assert!(matches!(run_async(operation, submit_ether_transfer(
				&eth, from, Address::repeat_byte(0x44), 1.into(),
				gas_limit_from_gwei(budget_gwei).unwrap(), 1, &private_key,
			)), Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == 7.into()));
			assert_eq!(
				transport
					.requests
					.lock()
					.unwrap()
					.iter()
					.filter(|(method, _)| method == "eth_sendRawTransaction")
					.count(),
				4
			);

			// Once the transaction is in the contiguous pending sequence, ordinary
			// transfers can continue at the following nonce before it is mined.
			transport.nonce = 7.into();
			transport.pending_nonce = Some(8.into());
			let accepted = mwc_web3::api::Eth::new(transport.clone());
			run_async(
				operation,
				submit_ether_transfer(
					&accepted,
					from,
					Address::repeat_byte(0x44),
					1.into(),
					gas_limit_from_gwei(budget_gwei).unwrap(),
					1,
					&private_key,
				),
			)
			.unwrap();
			let requests = transport.requests.lock().unwrap();
			let (_, params) = requests
				.iter()
				.rev()
				.find(|(method, _)| method == "eth_sendRawTransaction")
				.unwrap();
			let raw: Bytes = serde_json::from_value(params[0].clone()).unwrap();
			assert_eq!(
				rlp::Rlp::new(&raw.0).val_at::<U256>(0).unwrap(),
				U256::from(8u64)
			);
			drop(requests);
			if function == "initiate" && currency.is_erc20() {
				// Cancellation is a separate signed zero-value self-transfer at
				// nonce 7, even when nonce 8 is already pending. A failed broadcast
				// retains it without changing the original deposit recovery.
				let mut cancellation_transport =
					EtherTransferTransport::new(100_000_000, 30_000_000, Ok(21_000.into()));
				cancellation_transport.pending_nonce = Some(8.into());
				// Pending execution of the deposit and later transfers can deplete
				// the balance even though replacing the deposit is affordable.
				// Cancellation must still reach budget validation and broadcast.
				cancellation_transport.pending_estimate =
					Some(Err(mwc_web3::Error::Rpc(jsonrpc_core::Error {
						code: jsonrpc_core::ErrorCode::ServerError(-32000),
						message: "insufficient funds for gas * price + value".into(),
						data: None,
					})));
				let cancel_eth = mwc_web3::api::Eth::new(cancellation_transport.clone());
				let original = serde_json::to_string(&restored).unwrap();
				let mut cancellation = None;
				assert!(matches!(
					run_async(
						operation,
						cancel_signed_deposit(
							&cancel_eth,
							&restored,
							&mut cancellation,
							1,
							&private_key
						)
					),
					Err(Error::EthereumGasBudgetExceeded { .. })
				));
				assert!(cancellation.is_none());
				cancellation_transport
					.submission_errors
					.lock()
					.unwrap()
					.push_back(mwc_web3::Error::Unreachable);
				assert!(matches!(
					run_async(
						operation,
						cancel_signed_deposit(
							&cancel_eth,
							&restored,
							&mut cancellation,
							40_000,
							&private_key
						)
					),
					Err(Error::EthereumSubmissionUnknown { .. })
				));
				assert_eq!(serde_json::to_string(&restored).unwrap(), original);
				let mut cancellation: EthTransactionRecovery =
					serde_json::from_str(&serde_json::to_string(&cancellation.unwrap()).unwrap())
						.unwrap();
				let signed = rlp::Rlp::new(&cancellation.raw_transaction.0);
				assert_eq!(signed.val_at::<U256>(0).unwrap(), restored.nonce);
				assert_eq!(
					signed.val_at::<U256>(1).unwrap(),
					U256::from(259_200_000u64)
				);
				assert_eq!(signed.val_at::<Address>(3).unwrap(), from);
				assert!(signed.val_at::<U256>(4).unwrap().is_zero());
				assert!(signed.val_at::<Vec<u8>>(5).unwrap().is_empty());
				assert!(
					!restored
						.attempted_hashes
						.contains(&cancellation.attempted_hashes[0])
				);
				let retry_time = cancellation.last_attempt_at;
				run_async(
					operation,
					retry_signed_transaction(
						&cancel_eth,
						&mut cancellation,
						50_000,
						&private_key,
						retry_time,
					),
				)
				.unwrap();
				assert_eq!(cancellation.nonce, restored.nonce);
				assert_eq!(cancellation.to, from);
				assert!(cancellation.value.is_zero());
				assert!(cancellation.data.0.is_empty());
				assert_eq!(cancellation.attempted_hashes.len(), 2);
				let before = serde_json::to_string(&cancellation).unwrap();
				assert!(matches!(
					run_async(
						operation,
						cancel_signed_deposit(
							&consumed,
							&restored,
							&mut None,
							40_000,
							&private_key
						)
					),
					Err(Error::EthereumTransactionNonceConsumed { .. })
				));
				assert_eq!(serde_json::to_string(&cancellation).unwrap(), before);
			}
		}
		super::super::recovery::forget_for_test(1, from);
	}

	#[test]
	fn eth_finality_block_query_requires_explicit_mined_finalized_response() {
		let query = |response| {
			let transport = EtherTransferTransport::new(1, 1, Ok(1.into()));
			transport.block_results.lock().unwrap().push_back(response);
			let eth = mwc_web3::api::Eth::new(transport.clone());
			let result = run_async("test finalized block", query_finalized_block(&eth));
			assert_eq!(
				*transport.requests.lock().unwrap(),
				vec![(
					"eth_getBlockByNumber".into(),
					vec![json!("finalized"), json!(false)]
				)]
			);
			result
		};
		let hash = H256::repeat_byte(0x42);
		let mut block = mwc_web3::types::Block::<H256> {
			number: Some(100.into()),
			hash: Some(hash),
			..Default::default()
		};
		assert_eq!(query(Ok(json!(block))).unwrap(), hash);
		assert!(matches!(
			query(Ok(json!(null))),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		block.number = None;
		assert!(matches!(
			query(Ok(json!(block))),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		block.number = Some(100.into());
		block.hash = None;
		assert!(matches!(
			query(Ok(json!(block))),
			Err(Error::EthereumFinalityUnavailable(_))
		));
		assert!(matches!(
			query(Err(mwc_web3::Error::Unreachable)),
			Err(Error::EthereumRpc { .. })
		));
		assert!(matches!(
			query(Ok(json!({"hash": "malformed"}))),
			Err(Error::EthereumRpc { .. })
		));
	}

	#[test]
	fn eth_finality_lock_queries_pin_contract_state_to_finalized_hash() {
		use mwc_web3::ethabi::{Token, encode};
		for currency in [Currency::Ether, Currency::Usdt] {
			let transport = EtherTransferTransport::new(1, 1, Ok(1.into()));
			let eth = mwc_web3::api::Eth::new(transport.clone());
			let hash = H256::repeat_byte(0x42);
			let contract = Address::repeat_byte(0x43);
			let secret = Address::repeat_byte(0x44);
			let initiator = Address::repeat_byte(0x45);
			let participant = Address::repeat_byte(0x46);
			let mut tokens = vec![Token::Uint(200.into())];
			let token_address = if currency.is_erc20() {
				let token = currency.erc20_token_address().unwrap();
				tokens.push(Token::Address(token.0.into()));
				Some(token)
			} else {
				None
			};
			tokens.extend([
				Token::Address(initiator.0.into()),
				Token::Address(participant.0.into()),
				Token::Uint(if currency.is_erc20() {
					100.into()
				} else {
					100_000_000_000u64.into()
				}),
			]);
			let query = || {
				run_async(
					"test finalized lock",
					query_swap_details_at(&eth, currency, contract, secret, hash.into()),
				)
			};
			transport
				.call_results
				.lock()
				.unwrap()
				.push_back(Ok(json!(Bytes(encode(&tokens)))));
			assert_eq!(
				query().unwrap(),
				(200.into(), token_address, initiator, participant, 100)
			);
			// An absent finalized lock is an empty contract result, not a fallback to latest.
			let empty = vec![0; tokens.len() * 32];
			transport
				.call_results
				.lock()
				.unwrap()
				.push_back(Ok(json!(Bytes(empty))));
			assert_eq!(query().unwrap().4, 0);
			transport
				.call_results
				.lock()
				.unwrap()
				.push_back(Err(mwc_web3::Error::Unreachable));
			assert!(matches!(query(), Err(Error::EthereumContract { .. })));
			let requests = transport.requests.lock().unwrap();
			assert_eq!(requests.len(), 3);
			for (method, params) in requests.iter() {
				assert_eq!(method, "eth_call");
				assert_eq!(params[0]["to"], json!(contract));
				assert_eq!(params[1], json!({"blockHash": hash}));
			}
		}
	}

	#[test]
	fn receipt_finality_requires_matching_canonical_block() {
		let receipt = TransactionReceipt {
			transaction_hash: H256::repeat_byte(0x41),
			block_number: Some(100.into()),
			block_hash: Some(H256::repeat_byte(0x42)),
			status: Some(1.into()),
			..Default::default()
		};
		let block = |height, hash| {
			json!(mwc_web3::types::Block::<H256> {
				number: Some(height),
				hash: Some(hash),
				..Default::default()
			})
		};
		let finalized = block(120.into(), H256::repeat_byte(0x43));
		let query = |responses: Vec<mwc_web3::Result<RpcValue>>| {
			let transport = EtherTransferTransport::new(1, 1, Ok(1.into()));
			transport.block_results.lock().unwrap().extend(responses);
			let eth = mwc_web3::api::Eth::new(transport.clone());
			let result = run_async(
				"test receipt finality",
				receipt_is_finalized(&eth, &receipt),
			);
			let requests = transport.requests.lock().unwrap();
			assert_eq!(
				requests[0],
				(
					"eth_getBlockByNumber".into(),
					vec![json!("finalized"), json!(false)]
				)
			);
			if requests.len() == 2 {
				assert_eq!(
					requests[1],
					(
						"eth_getBlockByNumber".into(),
						vec![json!("0x64"), json!(false)]
					)
				);
			}
			result
		};
		assert!(
			query(vec![
				Ok(finalized.clone()),
				Ok(block(100.into(), receipt.block_hash.unwrap()))
			])
			.unwrap()
		);
		// A receipt from an orphaned block must survive even below finalized height.
		assert!(
			!query(vec![
				Ok(finalized.clone()),
				Ok(block(100.into(), H256::repeat_byte(0x44)))
			])
			.unwrap()
		);
		assert!(!query(vec![Ok(block(99.into(), H256::repeat_byte(0x45)))]).unwrap());
		assert!(query(vec![Ok(finalized), Ok(json!(null))]).is_err());
		assert!(matches!(
			query(vec![Err(mwc_web3::Error::Unreachable)]),
			Err(Error::EthereumRpc { .. })
		));
	}

	#[test]
	fn ether_transfer_uses_estimated_gas_at_low_prices() {
		// Cover a simple recipient and a contract that needs more execution gas.
		for (estimate, expected_gas) in [(21_000u64, 25_200u64), (65_000, 78_000)] {
			let transport = EtherTransferTransport::new(
				100_000_000, // 0.1 gwei: the old budget / price calculation gave 55M gas.
				30_000_000,
				Ok(U256::from(estimate)),
			);
			let tx_hash = run_ether_transfer(transport.clone()).unwrap();
			let requests = transport.requests.lock().unwrap();
			let (_, estimate_params) = requests
				.iter()
				.find(|(method, _)| method == "eth_estimateGas")
				.unwrap();
			let private_key = secret_key_from_hex(&"01".repeat(32)).unwrap();
			let from = SecretKeyRef::new(&private_key).address();
			assert_eq!(
				estimate_params,
				&vec![
					json!({
						"from": from,
						"to": Address::repeat_byte(0x42),
						"gas": U256::from(16_777_216u64),
						"gasPrice": U256::from(100_000_000u64),
						"value": U256::from(1_000_000_000_000_000_000u64),
						"data": "0x"
					}),
					json!("pending")
				]
			);
			let broadcasts: Vec<_> = requests
				.iter()
				.filter(|(method, _)| method == "eth_sendRawTransaction")
				.collect();
			assert_eq!(broadcasts.len(), 1);
			let raw: Bytes = serde_json::from_value(broadcasts[0].1[0].clone()).unwrap();
			// Decode the submitted bytes so this checks what is actually signed and sent.
			let tx = rlp::Rlp::new(&raw.0);
			assert_eq!(tx.val_at::<U256>(2).unwrap(), U256::from(expected_gas));
			assert_eq!(tx.val_at::<Address>(3).unwrap(), Address::repeat_byte(0x42));
			assert_eq!(
				tx.val_at::<U256>(4).unwrap(),
				U256::from(1_000_000_000_000_000_000u64)
			);
			assert_eq!(tx_hash, H256::from(signing::keccak256(&raw.0)));
		}
	}

	#[test]
	fn ether_transfer_rejects_invalid_gas_before_submission() {
		struct Case {
			name: &'static str,
			transport: EtherTransferTransport,
			expected_error: fn(&Error) -> bool,
		}
		let cases = [
			Case {
				name: "transaction cap exceeded by safety margin",
				transport: EtherTransferTransport::new(
					100_000_000,
					30_000_000,
					Ok(U256::from(14_000_000u64)),
				),
				expected_error: |error| {
					matches!(error, Error::EthereumGasLimitExceeded {
					required_gas, maximum_gas, ..
				} if *required_gas == U256::from(16_800_000u64)
					&& *maximum_gas == U256::from(16_777_216u64))
				},
			},
			Case {
				name: "smaller block gas limit exceeded",
				transport: EtherTransferTransport::new(
					100_000_000,
					100_000,
					Ok(U256::from(90_000u64)),
				),
				expected_error: |error| {
					matches!(error, Error::EthereumGasLimitExceeded {
					required_gas, maximum_gas, ..
				} if *required_gas == U256::from(108_000u64)
					&& *maximum_gas == U256::from(100_000u64))
				},
			},
			Case {
				name: "fee budget exceeded",
				transport: EtherTransferTransport::new(
					300_000_000_000,
					30_000_000,
					Ok(U256::from(21_000u64)),
				),
				expected_error: |error| matches!(error, Error::EthereumGasBudgetExceeded { .. }),
			},
			Case {
				name: "estimation reverted",
				transport: EtherTransferTransport::new(
					100_000_000,
					30_000_000,
					Err(mwc_web3::Error::Rpc(jsonrpc_core::Error {
						code: jsonrpc_core::ErrorCode::ServerError(3),
						message: "execution reverted".to_string(),
						data: None,
					})),
				),
				expected_error: |error| {
					matches!(error, Error::EthereumRpc {
					operation: "eth_estimateGas for Ether transfer", source,
				} if matches!(source.as_ref(), mwc_web3::Error::Rpc(_)))
				},
			},
			Case {
				name: "zero gas price",
				transport: EtherTransferTransport::new(0, 30_000_000, Ok(U256::from(21_000u64))),
				expected_error: |error| matches!(error, Error::EthereumSigning { .. }),
			},
		];
		for case in cases {
			let error = run_ether_transfer(case.transport.clone()).unwrap_err();
			assert!((case.expected_error)(&error), "{}: {error:?}", case.name);
			assert!(error.is_transient(), "{}: {error:?}", case.name);
			assert!(error.ethereum_submission_hash().is_none(), "{}", case.name);
			let requests = case.transport.requests.lock().unwrap();
			assert!(
				requests
					.iter()
					.all(|(method, _)| method != "eth_sendRawTransaction"),
				"{}: {requests:?}",
				case.name
			);
		}
	}

	#[test]
	fn unexpected_erc20_tokens_do_not_contribute_to_swap_balance() {
		let refund_block = U256::MAX;
		let initiator = Address::repeat_byte(0x21);
		let participant = Address::repeat_byte(0x22);
		let oversized = U256::from(u64::MAX).checked_add(U256::one()).unwrap();
		for currency in [Currency::Usdt, Currency::Dai, Currency::Wbtc] {
			for token in [
				None,
				Some(Address::zero()),
				Some(Address::repeat_byte(0x23)),
			] {
				for amount in [U256::zero(), U256::from(100), oversized, U256::MAX] {
					assert_eq!(
						normalized_swap_details(
							currency,
							(refund_block, token, initiator, participant, amount),
						)
						.unwrap(),
						(refund_block, token, initiator, participant, 0),
					);
				}
			}
		}
	}

	#[test]
	fn u256_to_u64_conversion_rejects_remote_overflow() {
		assert_eq!(
			checked_u256_to_u64(U256::from(u64::MAX), "test value").unwrap(),
			u64::MAX
		);
		let oversized = U256::from(u64::MAX).checked_add(U256::from(1u8)).unwrap();
		assert!(matches!(
			checked_u256_to_u64(oversized, "test value"),
			Err(Error::DataOverflow(_))
		));

		// Refund blocks are contract-controlled uint256 values. Preserve them
		// even for a zero-value lock, while still checking wallet-sized balances.
		for currency in [
			Currency::Ether,
			Currency::Usdt,
			Currency::Dai,
			Currency::Wbtc,
		] {
			let scale = if currency.is_expo_shrinked18to9() {
				U256::exp10(9)
			} else {
				U256::from(1)
			};
			let token = currency
				.is_erc20()
				.then(|| currency.erc20_token_address().unwrap());
			let initiator = Address::repeat_byte(0x21);
			let participant = Address::repeat_byte(0x22);
			for refund_block in [U256::from(u64::MAX), oversized, U256::MAX] {
				for amount in [0, 100, u64::MAX] {
					let raw_amount = U256::from(amount).checked_mul(scale).unwrap();
					let details = (refund_block, token, initiator, participant, raw_amount);
					assert_eq!(
						normalized_swap_details(currency, details).unwrap(),
						(refund_block, token, initiator, participant, amount),
					);
				}
			}
			let oversized_balance = oversized.checked_mul(scale).unwrap();
			assert!(matches!(
				normalized_swap_details(
					currency,
					(oversized, token, initiator, participant, oversized_balance),
				),
				Err(Error::DataOverflow(_))
			));
		}
	}

	#[test]
	fn integer_gwei_converts_exactly_to_wei() {
		assert_eq!(
			gas_limit_from_gwei(5_500_000).unwrap(),
			U256::from(5_500_000_000_000_000u64)
		);
	}

	#[test]
	fn constructors_distinguish_account_and_swap_clients() {
		let account_client = InfuraNodeClient::new_account(
			"unused".to_string(),
			"mainnet".to_string(),
			EthereumWallet::default(),
		)
		.unwrap();
		assert!(account_client.swap_contracts.is_none());
		assert!(matches!(
			account_client.native_swap_contract_address(),
			Err(Error::UndefinedEthSwapContractAddress)
		));
		assert!(matches!(
			account_client.erc20_swap_contract_address(),
			Err(Error::UndefinedERC20SwapContractAddress)
		));

		let swap_client = InfuraNodeClient::new(
			"unused".to_string(),
			"mainnet".to_string(),
			EthereumWallet::default(),
			"0x0000000000000000000000000000000000000001".to_string(),
			"0x0000000000000000000000000000000000000002".to_string(),
		)
		.unwrap();
		assert!(swap_client.swap_contracts.is_some());
		assert_eq!(
			swap_client.native_swap_contract_address().unwrap(),
			Address::from_low_u64_be(1)
		);
		assert_eq!(
			swap_client.erc20_swap_contract_address().unwrap(),
			Address::from_low_u64_be(2)
		);
	}

	#[test]
	fn erc20_gas_estimate_is_margin_adjusted_and_budget_limited() {
		let operation = "construct test ERC20 transfer";
		assert_eq!(
			adjusted_gas_price(operation, U256::from(100u64)).unwrap(),
			U256::from(150u64)
		);
		assert_eq!(
			gas_estimate_with_margin(operation, U256::from(50_001u64)).unwrap(),
			U256::from(60_002u64)
		);

		let gas = U256::from(60_000u64);
		let gas_price = U256::from(100u64);
		let exact_budget = U256::from(6_000_000u64);
		assert!(ensure_gas_budget(operation, gas, gas_price, exact_budget).is_ok());
		assert!(matches!(
			ensure_gas_budget(
				operation,
				gas,
				gas_price,
				U256::from(5_999_999u64)
			),
			Err(Error::EthereumGasBudgetExceeded {
				required_wei,
				available_wei,
				..
			}) if required_wei == exact_budget && available_wei == U256::from(5_999_999u64)
		));
		assert!(gas_estimate_with_margin(operation, U256::zero()).is_err());
		assert!(gas_estimate_with_margin(operation, U256::MAX).is_err());

		// Exercise the deposit estimator with the actual native and ERC20 calldata.
		// A higher gas price must reject an inadequate budget, not shrink the gas
		// limit until a transaction that cannot execute gets signed.
		let from = Address::repeat_byte(0x11);
		let to = Address::repeat_byte(0x22);
		let secret = Address::repeat_byte(0x33);
		let participant = Address::repeat_byte(0x44);
		let budget = gas_limit_from_gwei(DEFAULT_TRANSFER_GAS_BUDGET_GWEI).unwrap();
		for currency in [Currency::Ether, Currency::Usdt] {
			for node_price in [100_000_000u64, 50_000_000_000] {
				let transport =
					EtherTransferTransport::new(node_price, 30_000_000, Ok(U256::from(110_000u64)));
				let eth = mwc_web3::api::Eth::new(transport.clone());
				let abi = if currency.is_erc20() {
					ERC20_SWAP_CONTRACT
				} else {
					ETH_SWAP_CONTRACT
				};
				let contract = Contract::from_json(eth.clone(), to, abi.as_bytes()).unwrap();
				let (data, value) = if currency.is_erc20() {
					(
						contract_call_data(
							&contract,
							operation,
							"initiate",
							(
								25_000_100u64,
								secret,
								participant,
								currency.erc20_token_address().unwrap(),
								U256::from(100u64),
							),
						)
						.unwrap(),
						U256::zero(),
					)
				} else {
					(
						contract_call_data(
							&contract,
							operation,
							"initiate",
							(25_000_100u64, secret, participant),
						)
						.unwrap(),
						U256::exp10(18),
					)
				};
				let result = run_async(
					operation,
					estimate_contract_gas(
						&eth,
						operation,
						CallRequest {
							from: Some(from),
							to: Some(to),
							value: Some(value),
							data: Some(data.clone()),
							..CallRequest::default()
						},
						1,
						budget,
						BlockNumber::Pending,
					),
				);
				if node_price == 100_000_000 {
					assert_eq!(
						result.unwrap(),
						(U256::from(150_000_000u64), U256::from(132_000u64))
					);
				} else {
					assert!(matches!(result, Err(Error::EthereumGasBudgetExceeded {
						required_wei, available_wei, ..
					}) if required_wei == U256::from(9_900_000_000_000_000u64) && available_wei == budget));
				}
				let requests = transport.requests.lock().unwrap();
				let (_, params) = requests
					.iter()
					.find(|(method, _)| method == "eth_estimateGas")
					.unwrap();
				let call: CallRequest = serde_json::from_value(params[0].clone()).unwrap();
				assert_eq!(call.from, Some(from));
				assert_eq!(call.to, Some(to));
				assert_eq!(call.value, Some(value));
				assert_eq!(call.data, Some(data));
				assert_eq!(
					call.gas,
					Some(U256::from(ETH_MAINNET_TRANSACTION_GAS_LIMIT))
				);
				assert_eq!(
					call.gas_price,
					Some(U256::from(node_price + node_price / 2))
				);
				assert_eq!(params[1], json!("pending"));
			}
		}
	}

	#[test]
	fn ether_balance_display_preserves_all_normalized_gwei_digits() {
		let balance_wei = U256::from(999u64) * U256::exp10(9);
		assert_eq!(
			normalized_ether_balance(balance_wei).unwrap(),
			("0.000000999".to_string(), 999)
		);
	}

	#[test]
	fn transfer_transactions_use_pending_nonce_and_local_chain_id() {
		assert_eq!(pending_nonce_block(), Some(BlockNumber::Pending));

		let to = Address::from_low_u64_be(7);
		let tx = legacy_transaction(
			U256::from(11u8),
			to,
			U256::from(21_000u64),
			U256::from(3u8),
			U256::from(5u8),
			Bytes::default(),
			1,
		);
		assert_eq!(tx.nonce, Some(U256::from(11u8)));
		assert_eq!(tx.to, Some(to));
		assert_eq!(tx.chain_id, Some(1));

		// Exercise the production transfer paths with the existing RPC harness.
		// Each case owns a distinct account from the other tests in this module.
		let private_key = "35".repeat(32);
		let key = secret_key_from_hex(&private_key).unwrap();
		let from = SecretKeyRef::new(&key).address();
		let account_lock = submission_lock(1, from);
		let _guard = account_lock.lock().unwrap();
		let budget_gwei = DEFAULT_TRANSFER_GAS_BUDGET_GWEI;
		let budget = gas_limit_from_gwei(budget_gwei).unwrap();
		let period = crate::swap::fsm::state::POST_SECONDARY_RETRY_PERIOD;
		let broadcasts = |transport: &EtherTransferTransport| {
			transport
				.requests
				.lock()
				.unwrap()
				.iter()
				.filter(|(method, _)| method == "eth_sendRawTransaction")
				.count()
		};
		let send =
			|transport: &EtherTransferTransport, currency: Currency, to: Address, value: u64| {
				let eth = mwc_web3::api::Eth::new(transport.clone());
				run_async("test direct transfer", async {
					if currency == Currency::Ether {
						submit_ether_transfer(&eth, from, to, value.into(), budget, 1, &private_key)
							.await
					} else {
						submit_erc20_transfer(
							&eth,
							from,
							currency.erc20_token_address()?,
							to,
							value.into(),
							budget,
							1,
							&private_key,
						)
						.await
					}
				})
			};
		let retry = |transport: &EtherTransferTransport,
		             record: EthTransactionRecovery,
		             gas_gwei: u64,
		             now: i64| {
			let eth = mwc_web3::api::Eth::new(transport.clone());
			run_async(
				"test direct transfer retry",
				retry_direct_transfer(&eth, record, gas_gwei, &private_key, now),
			)
		};
		for currency in [Currency::Ether, Currency::Usdt, Currency::Link] {
			for ambiguous in [false, true] {
				super::super::recovery::forget_for_test(1, from);
				let mut transport =
					EtherTransferTransport::new(100_000_000, 30_000_000, Ok(60_000.into()));
				transport.check_direct_sender = Some(from);
				let eth = mwc_web3::api::Eth::new(transport.clone());

				// Invalid or mismatched keys must leave the account usable, with no send.
				for invalid_key in ["not hex".to_string(), "36".repeat(32)] {
					assert!(
						run_async(
							"test failed signing",
							submit_prepared_transaction(
								&eth,
								from,
								tx.clone(),
								&invalid_key,
								budget,
								RecoveryTarget::DirectTransfer,
								"test failed signing",
							)
						)
						.is_err()
					);
				}
				assert!(!super::super::recovery::has_direct_transfers(1, from));
				assert_eq!(
					run_async("test nonce", next_account_nonce(&eth, 1, from)).unwrap(),
					7.into()
				);
				assert_eq!(broadcasts(&transport), 0);
				if ambiguous {
					transport
						.submission_errors
						.lock()
						.unwrap()
						.push_back(mwc_web3::Error::Unreachable);
				}
				let result = send(&transport, currency, to, 42);
				let hash = match result {
					Ok(hash) => {
						assert!(!ambiguous);
						hash
					}
					Err(Error::EthereumSubmissionUnknown { tx_hash, .. }) => {
						assert!(ambiguous);
						tx_hash
					}
					other => panic!("unexpected transfer result: {other:?}"),
				};
				let original = super::super::recovery::direct_transfer(1, from, hash).unwrap();
				assert_eq!(original.nonce, 7.into());
				assert_eq!(broadcasts(&transport), 1);
				assert!(matches!(
					super::super::recovery::retain_direct_transfer(original.clone()),
					Err(Error::EthereumTransactionNonceReserved(_))
				));
				assert!(super::super::recovery::direct_transfer(3, from, hash).is_err());
				assert!(super::super::recovery::direct_transfer(1, Address::zero(), hash).is_err());

				// The node still offers 7. Different payments and other currencies wait.
				for other in [Currency::Ether, Currency::Usdt, Currency::Link] {
					assert!(
						matches!(send(&transport, other, Address::repeat_byte(0x44), 9),
						Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == 7.into())
					);
				}
				assert_eq!(broadcasts(&transport), 1);
				let start = original.last_attempt_at;
				assert!(matches!(
					retry(&transport, original.clone(), budget_gwei, start),
					Err(Error::EthTransactionInPending)
				));
				transport
					.receipt_results
					.lock()
					.unwrap()
					.push_back(Err(mwc_web3::Error::Unreachable));
				assert!(matches!(
					retry(&transport, original.clone(), budget_gwei, start + period),
					Err(Error::EthereumRpc { .. })
				));
				assert_eq!(broadcasts(&transport), 1);

				// A first retry can rebroadcast the exact signed bytes. A later retry
				// bumps only the fee, retaining the replacement before an ambiguous send.
				transport.gas_price = 1.into();
				assert_eq!(
					retry(&transport, original.clone(), budget_gwei, start + period).unwrap(),
					hash
				);
				let rebroadcast = super::super::recovery::direct_transfer(1, from, hash).unwrap();
				assert!(rebroadcast.rebroadcasted);
				assert_eq!(rebroadcast.raw_transaction, original.raw_transaction);
				let before = serde_json::to_string(&rebroadcast).unwrap();
				assert!(matches!(
					retry(&transport, rebroadcast.clone(), 1, start + 2 * period),
					Err(Error::EthereumGasBudgetExceeded { .. })
				));
				assert_eq!(
					serde_json::to_string(
						&super::super::recovery::direct_transfer(1, from, hash).unwrap()
					)
					.unwrap(),
					before
				);
				transport
					.submission_errors
					.lock()
					.unwrap()
					.push_back(mwc_web3::Error::Unreachable);
				let result = retry(&transport, rebroadcast, budget_gwei, start + 2 * period);
				let replacement = super::super::recovery::direct_transfer(1, from, hash).unwrap();
				let replacement_hash = *replacement.attempted_hashes.last().unwrap();
				assert_ne!(replacement_hash, hash);
				assert!(
					matches!(result, Err(Error::EthereumSubmissionUnknown { tx_hash, .. }) if tx_hash == replacement_hash)
				);
				assert_eq!(
					super::super::recovery::direct_transfer(1, from, replacement_hash)
						.unwrap()
						.attempted_hashes,
					replacement.attempted_hashes
				);
				assert_eq!(broadcasts(&transport), 3);
				let requests = transport.requests.lock().unwrap();
				let raws: Vec<Bytes> = requests
					.iter()
					.filter(|(method, _)| method == "eth_sendRawTransaction")
					.map(|(_, params)| serde_json::from_value(params[0].clone()).unwrap())
					.collect();
				assert_eq!(raws[0], raws[1]);
				for raw in &raws {
					let signed = rlp::Rlp::new(&raw.0);
					assert_eq!(signed.val_at::<U256>(0).unwrap(), original.nonce);
					assert_eq!(signed.val_at::<Address>(3).unwrap(), original.to);
					assert_eq!(signed.val_at::<U256>(4).unwrap(), original.value);
					assert_eq!(signed.val_at::<Vec<u8>>(5).unwrap(), original.data.0);
					assert!(matches!(signed.val_at::<u64>(6).unwrap(), 37 | 38));
				}
				drop(requests);

				// While 7 is pending, 8 is available. Falling behind either reservation
				// cannot reuse a nonce, including after a mined-but-unfinalized reorg.
				transport.pending_nonce = Some(8.into());
				let next_hash = send(&transport, currency, Address::repeat_byte(0x44), 9).unwrap();
				assert_eq!(
					super::super::recovery::direct_transfer(1, from, next_hash)
						.unwrap()
						.nonce,
					8.into()
				);
				transport.pending_nonce = Some(7.into());
				assert!(
					matches!(send(&transport, currency, to, 3), Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == 8.into())
				);
				transport.nonce = 9.into();
				transport.pending_nonce = Some(9.into());
				let mined = mwc_web3::api::Eth::new(transport.clone());
				assert_eq!(
					run_async("test mined nonce", next_account_nonce(&mined, 1, from)).unwrap(),
					9.into()
				);
				assert!(super::super::recovery::direct_transfer(1, from, hash).is_ok());
				assert!(matches!(
					retry(
						&transport,
						replacement.clone(),
						budget_gwei,
						start + 3 * period
					),
					Err(Error::EthereumTransactionNonceConsumed { .. })
				));
				transport.nonce = 7.into();
				transport.pending_nonce = Some(7.into());
				assert!(
					matches!(send(&transport, currency, to, 3), Err(Error::EthereumTransactionNonceReserved(nonce)) if nonce == 8.into())
				);
				assert_eq!(broadcasts(&transport), 4);

				// The older attempt may mine; successful and reverted receipts must
				// resolve without another broadcast, even when the retry interval is short.
				for success in [false, true] {
					transport.receipt_results.lock().unwrap().push_back(Ok(Some(
						TransactionReceipt {
							transaction_hash: hash,
							block_number: Some(100.into()),
							status: Some(u64::from(success).into()),
							..Default::default()
						},
					)));
					let result = retry(&transport, replacement.clone(), budget_gwei, start);
					if success {
						assert_eq!(result.unwrap(), hash);
					} else {
						assert!(
							matches!(result, Err(Error::EthereumTransferReverted(tx_hash)) if tx_hash == hash)
						);
					}
				}
				assert_eq!(broadcasts(&transport), 4);
				transport.nonce = 9.into();
				transport.pending_nonce = Some(9.into());
				transport.finalized_nonce = 9.into();
				let finalized = mwc_web3::api::Eth::new(transport.clone());
				assert_eq!(
					run_async(
						"test finalized nonce",
						next_account_nonce(&finalized, 1, from)
					)
					.unwrap(),
					9.into()
				);
				assert!(!super::super::recovery::has_direct_transfers(1, from));
			}
		}
		super::super::recovery::forget_for_test(1, from);
	}

	#[test]
	fn submission_lock_is_shared_by_chain_and_account() {
		let account = Address::from_low_u64_be(7);
		let same_key_a = submission_lock(1, account);
		let same_key_b = submission_lock(1, account);
		let other_chain = submission_lock(3, account);
		let other_account = submission_lock(1, Address::from_low_u64_be(8));

		assert!(Arc::ptr_eq(&same_key_a, &same_key_b));
		assert!(!Arc::ptr_eq(&same_key_a, &other_chain));
		assert!(!Arc::ptr_eq(&same_key_a, &other_account));
	}

	#[test]
	fn redeem_authorization_preserves_the_existing_double_hash_scheme() {
		let key = SecretKeyGuard::from_bytes(&[1u8; 32]).unwrap();
		let packed_fields = b"packed swap authorization fields";
		let (r, s, v) =
			sign_redeem_authorization(&key, packed_fields, "test redeem authorization").unwrap();

		// The historical contract protocol signs personal_sign(keccak256(fields)),
		// not personal_sign(fields). Keep this explicit so a cleanup cannot silently
		// produce authorizations that the deployed contracts reject.
		let packed_hash = signing::keccak256(packed_fields);
		let signed_hash = signing::hash_message(packed_hash);
		let expected = SecretKeyRef::new(&key)
			.sign(signed_hash.as_bytes(), None)
			.unwrap();
		assert_eq!((r, s, u64::from(v)), (expected.r, expected.s, expected.v));
		assert_ne!(signed_hash, signing::hash_message(packed_fields));
	}

	#[test]
	fn configured_network_has_a_fixed_expected_chain_id() {
		assert_eq!(expected_chain_id("mainnet").unwrap(), 1);
		assert_eq!(expected_chain_id("ropsten").unwrap(), 3);
		assert!(matches!(
			expected_chain_id("unknown"),
			Err(Error::UnexpectedNetwork(_))
		));
	}

	#[test]
	fn swap_contract_addresses_are_parsed_and_nonzero() {
		let native = parse_swap_contract_address(
			SwapContractKind::Native,
			"0x0000000000000000000000000000000000000001".to_string(),
		)
		.unwrap();
		assert_eq!(native, Address::from_low_u64_be(1));
		assert!(matches!(
			parse_swap_contract_address(
				SwapContractKind::Erc20,
				"0x0000000000000000000000000000000000000000".to_string(),
			),
			Err(Error::ZeroEthSwapContractAddress { kind: "ERC20" })
		));
		assert!(
			parse_swap_contract_address(SwapContractKind::Native, "not-an-address".to_string(),)
				.is_err()
		);
	}

	#[test]
	fn only_supported_swap_contract_runtime_code_is_accepted() {
		fn decode_runtime(snapshot: &str) -> Vec<u8> {
			let snapshot = snapshot.trim();
			mwc_wallet_util::mwc_crates::hex::decode(
				snapshot.strip_prefix("0x").unwrap_or(snapshot),
			)
			.unwrap()
		}

		let native_runtime = decode_runtime(include_str!(
			"../../../../doc/swap/ethereum-contracts/0x2FA243fC8f9EAF014f8d6E909157B6A48cEE0bdC/deployed-bytecode.hex"
		));
		let erc20_runtime = decode_runtime(include_str!(
			"../../../../doc/swap/ethereum-contracts/0xDd62a95626453F54E686cF0531bCbf6766150794/deployed-bytecode.hex"
		));
		let native_address = Address::from_low_u64_be(1);
		let erc20_address = Address::from_low_u64_be(2);

		validate_swap_contract_runtime(
			1,
			SwapContractKind::Native,
			native_address,
			&native_runtime,
		)
		.unwrap();
		validate_swap_contract_runtime(3, SwapContractKind::Erc20, erc20_address, &erc20_runtime)
			.unwrap();
		assert!(matches!(
			validate_swap_contract_runtime(
				1,
				SwapContractKind::Native,
				native_address,
				&erc20_runtime,
			),
			Err(Error::UnsupportedEthSwapContractCode { .. })
		));
		assert!(matches!(
			validate_swap_contract_runtime(1, SwapContractKind::Erc20, erc20_address, &[],),
			Err(Error::MissingEthSwapContractCode { .. })
		));
	}

	#[test]
	fn erc20_transfer_is_abi_encoded_locally() {
		let data = erc20_transfer_data(Address::from_low_u64_be(7), U256::from(42u8)).unwrap();
		assert_eq!(data.0.len(), 68);
		assert_eq!(&data.0[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
		// Reuse the RPC harness to verify the actual allowance query and decoding,
		// including a return value that would overflow the wallet's u64 amounts.
		let transport = EtherTransferTransport::new(1, 1, Ok(U256::one()));
		let key = Erc20AllowanceKey {
			chain_id: 1,
			owner: Address::repeat_byte(0x11),
			token: Address::repeat_byte(0x22),
			spender: Address::repeat_byte(0x33),
		};
		let eth = mwc_web3::api::Eth::new(transport.clone());
		assert_eq!(
			run_async("test allowance", query_erc20_allowance(eth, key)).unwrap(),
			U256::MAX
		);
		let requests = transport.requests.lock().unwrap();
		assert_eq!(requests.len(), 2);
		assert_eq!(requests[0].0, "eth_chainId");
		assert_eq!(requests[1].0, "eth_call");
		let query: CallRequest = serde_json::from_value(requests[1].1[0].clone()).unwrap();
		assert_eq!(query.to, Some(key.token));
		let data = query.data.unwrap().0;
		assert_eq!(data.len(), 68);
		assert_eq!(&data[..4], &[0xdd, 0x62, 0xed, 0x3e]);
		assert_eq!(&data[16..36], key.owner.as_bytes());
		assert_eq!(&data[48..68], key.spender.as_bytes());
	}

	#[test]
	fn web3_errors_retain_the_operation_and_source() {
		let result = run_async("test worker", async {
			web3_call("test RPC", async {
				Err::<(), _>(mwc_web3::Error::InvalidResponse(
					"specific transport cause".to_string(),
				))
			})
			.await
		});

		match result {
			Err(Error::EthereumRpc { operation, source }) => {
				assert_eq!(operation, "test RPC");
				assert!(source.to_string().contains("specific transport cause"));
			}
			other => panic!("unexpected result: {:?}", other),
		}
	}

	#[test]
	fn worker_panic_payload_message_is_preserved() {
		for (kind, expected) in [
			(0, "specific worker failure"),
			(1, "owned worker failure"),
			(2, "non-string panic payload"),
		] {
			let result = run_async::<(), _>("test worker panic", async move {
				match kind {
					0 => panic!("specific worker failure"),
					1 => std::panic::panic_any("owned worker failure".to_string()),
					_ => std::panic::panic_any(42u32),
				}
			});
			match result {
				Err(Error::EthereumWorkerPanic { operation, message }) => {
					assert_eq!(operation, "test worker panic");
					assert_eq!(message, expected);
				}
				other => panic!("unexpected result: {:?}", other),
			}
		}
	}

	fn worker_result_with_pending_blocking_task(panic_in_task: bool) -> Result<(), Error> {
		use mwc_wallet_util::mwc_crates::tokio;
		use std::sync::mpsc;

		let (release_tx, release_rx) = mpsc::channel();
		let (finished_tx, finished_rx) = mpsc::channel();
		let (result_tx, result_rx) = mpsc::channel();
		let worker = thread::spawn(move || {
			let result = run_async("test worker shutdown", async move {
				let (started_tx, started_rx) = tokio::sync::oneshot::channel();
				let blocking = tokio::task::spawn_blocking(move || {
					started_tx.send(()).unwrap();
					release_rx.recv().unwrap();
					finished_tx.send(()).unwrap();
				});
				// Running blocking tasks cannot be cancelled during runtime shutdown.
				started_rx.await.unwrap();
				if panic_in_task {
					panic!("worker panic with pending blocking task");
				}
				match timeout(Duration::from_secs(1), blocking).await {
					Err(_) => Err(Error::EthereumTimeout {
						operation: "test blocking task",
						timeout_secs: 1,
					}),
					Ok(_) => panic!("blocking task completed before it was released"),
				}
			});
			result_tx.send(result).unwrap();
		});

		// The result must arrive while the blocking task is still waiting.
		let result = result_rx.recv_timeout(Duration::from_secs(5));
		// Release and join before asserting, so a regression does not hang the test.
		let released = release_tx.send(());
		let finished = finished_rx.recv_timeout(Duration::from_secs(5));
		worker.join().unwrap();
		released.unwrap();
		finished.unwrap();
		result.expect("worker waited for blocking work after its task finished")
	}

	#[test]
	fn worker_timeout_does_not_wait_for_blocking_tasks() {
		assert!(matches!(
			worker_result_with_pending_blocking_task(false),
			Err(Error::EthereumTimeout {
				operation: "test blocking task",
				timeout_secs: 1,
			})
		));
	}

	#[test]
	fn worker_panic_does_not_wait_for_blocking_tasks() {
		match worker_result_with_pending_blocking_task(true) {
			Err(Error::EthereumWorkerPanic { operation, message }) => {
				assert_eq!(operation, "test worker shutdown");
				assert_eq!(message, "worker panic with pending blocking task");
			}
			other => panic!("unexpected result: {:?}", other),
		}
	}

	#[test]
	fn transfer_rejects_zero_destination_before_wallet_or_network_access() {
		let client = InfuraNodeClient::new_account(
			"unused".to_string(),
			"mainnet".to_string(),
			EthereumWallet::default(),
		)
		.unwrap();
		for address in [
			"0x0000000000000000000000000000000000000000",
			"0X0000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000",
		] {
			let to = to_eth_address(address.to_string()).unwrap();
			// Cover native ETH and tokens with both supported amount representations.
			for currency in [Currency::Ether, Currency::Usdt, Currency::Link] {
				assert!(matches!(
					client.transfer(currency, to, 1),
					Err(Error::ZeroEthTransferAddress)
				));
			}
		}
	}

	#[test]
	fn ethereum_dispatch_rejects_btc_family_without_network_access() {
		let client = InfuraNodeClient::new(
			"unused".to_string(),
			"mainnet".to_string(),
			EthereumWallet::default(),
			"0x0000000000000000000000000000000000000001".to_string(),
			"0x0000000000000000000000000000000000000002".to_string(),
		)
		.unwrap();
		for currency in [
			Currency::Btc,
			Currency::Bch,
			Currency::Ltc,
			Currency::Dash,
			Currency::ZCash,
			Currency::Doge,
		] {
			assert!(matches!(
				client.balance(currency),
				Err(Error::UnexpectedCoinType)
			));
			assert!(matches!(
				client.erc20_allowance(currency),
				Err(Error::UnexpectedCoinType)
			));
			assert!(matches!(
				client.transfer(currency, Address::from_low_u64_be(1), 1),
				Err(Error::UnexpectedCoinType)
			));
		}
	}

	#[test]
	fn private_key_decoder_enforces_fixed_length_valid_secret_hex() {
		assert!(secret_key_from_hex(&"01".repeat(32)).is_ok());
		assert!(secret_key_from_hex(&"01".repeat(31)).is_err());
		assert!(secret_key_from_hex(&"00".repeat(32)).is_err());
		assert!(secret_key_from_hex("not hex").is_err());
	}

	macro_rules! get_infura_client {
		($project_id: expr, $chain: expr, $mnmenoic: expr, $path: expr, $contract_addr: expr, $erc20_contract_addr: expr) => {{
			let wallet = generate_ethereum_wallet($chain, $mnmenoic, $path).unwrap();
			InfuraNodeClient::new(
				$project_id.to_string(),
				$chain.to_string(),
				wallet,
				$contract_addr.to_string(),
				$erc20_contract_addr.to_string(),
			)
			.unwrap()
		}};
	}

	#[test]
	#[ignore]
	fn test_infura() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		println!("wallet address: {}", nc.wallet.address.clone().unwrap());

		let balance = nc.balance(Currency::Ether).unwrap();
		println!("balance: {}", balance.0);

		let height = nc.height().unwrap();
		println!("height: {}", height);
	}

	#[test]
	#[ignore]
	fn test_transfer_funds() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let res = c.transfer(
			Currency::Ether,
			to_eth_address("0xAa7937998d2f417EaC0524ad6E15c9C5e40efBA9".to_string()).unwrap(),
			1000u64,
		);
		println!("transfer result: {:?}", res);
	}

	#[test]
	#[ignore]
	fn test_retrieve_trans_receipt() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let res = c.retrieve_receipt(
			to_eth_tx_hash(
				"0x193342ec1fc85fb075d8c09006b954c5dc8b015606c72e57e8759f43b7191ea6".to_string(),
			)
			.unwrap(),
		);
		println!("test_retrieve_trans_receipt result: {:?}", res.unwrap());
	}

	#[test]
	#[ignore]
	fn test_initiate_swap() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let mut rng = rand::rngs::SysRng;
		let wallet_rand = EthereumWallet::new(&mut rng).unwrap();
		let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();
		let height = nc.height().unwrap();
		let res = nc.initiate(
			Currency::Tst,
			height + 2700,
			address_from_secret,
			to_eth_address("aa7937998d2f417eac0524ad6e15c9c5e40efba8".to_string()).unwrap(),
			10,
			5_500_000,
			&mut None,
		);
		println!("initiate_swap result: {:?}", res);
	}

	// wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("4651f24db5971c714d854df5ea5a68f2fccce96a24b8c41c619f4c9d49cd96e2"), public_key: Some("6673c66071c3fed37fc29b22bc55b723dc183f746c5170f432de35326cb7e2e07d9aa0096943d901d753af0a0f314712eae7c759a1ae3b3e0dea3054d3ae65ba"), address: Some("0x3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692"), transaction_id: None, network: None, transaction_hex: None }
	#[test]
	#[ignore]
	fn test_get_swap_details() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		let address_from_secret =
			to_eth_address("3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692".to_string()).unwrap();
		let res = c.get_swap_details(Currency::Ether, address_from_secret);
		println!("test_get_swap_details result: {:?}", res);
	}

	// // wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("64b0699526f9ed457cafb6cd27dbffe7ea8196a602b23354e0303521d0c1e265"), public_key: Some("cff6fc214ee02f9fb2def6908b605e84e2e2aaa5b0b484426d3997cb123dbba037c1b9d86fb76477c5c0df9750f7ba222adc80549e164affe68c6d2b75008942"), address: Some("0xDed1df8d3ea680C314bF9D7B9D0577c8F2eE980C"), transaction_id: None, network: None, transaction_hex: None }
	#[test]
	#[ignore]
	fn test_redeem() {
		set_test_mode(true);
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		//generate rand address for swap index
		let mut rng = rand::rngs::SysRng;
		let wallet_rand = EthereumWallet::new(&mut rng).unwrap();
		let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();

		//generate participant wallet
		let redeem_wallet = generate_ethereum_wallet(CHAIN, REDEEM_MNMENOIC, WALLET_PATH).unwrap();
		REDEEM_WALLET.write().replace(redeem_wallet.clone());

		//initiate swap offer
		let res = nc.initiate(
			Currency::Tst,
			720,
			address_from_secret,
			to_eth_address(redeem_wallet.address.clone().unwrap()).unwrap(),
			10,
			5_500_000,
			&mut None,
		);
		println!("initiate_swap result: {:?}", res.unwrap());

		// delay 300s , then redeem
		let secs = time::Duration::from_secs(3 * 10);
		thread::sleep(secs);

		// redeem now
		//call redeem function
		let key = secret_key_from_hex(wallet_rand.private_key.as_deref().unwrap()).unwrap();
		let res = nc.redeem(
			Currency::Tst,
			address_from_secret,
			&key,
			5_500_000,
			&mut None,
		);
		println!("test_redeem result: {:?}", res.unwrap());
	}

	#[test]
	#[ignore]
	fn test_refund() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		let res = nc.refund(
			Currency::Tst,
			to_eth_address("1d8d33f1e9b5a2d3af9c46957b8b21d7e15b4d0e".to_string()).unwrap(),
			5_500_000,
			&mut None,
		);
		println!("test_refund result: {:?}", res);
	}
}
