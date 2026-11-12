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

use super::ethereum::*;
use super::secret_key::SecretKeyGuard;
use super::types::{
	to_eth_address, EthBuyerContext, EthData, EthSellerContext, EthTransactionRecovery,
};
use super::{
	client::{EthChainTip, EthNodeClient},
	eth_address,
};
use crate::internal::chain_session::NodeReadSession;
use crate::swap::fsm::machine::StateMachine;
use crate::swap::fsm::{buyer_swap, seller_swap};
use crate::swap::message::SecondaryUpdate;
use crate::swap::swap;
use crate::swap::types::{
	BuyerContext, Context, Currency, RoleContext, SecondaryBuyerContext, SecondarySellerContext,
	SecondaryTransferStatus, SellerContext, SellerInput, SwapTransactionsConfirmations,
};
use crate::swap::{Error, SellApi, Swap, SwapApi};
use crate::{NodeClient, Slate};
use mwc_wallet_util::mwc_crates::secp::aggsig::export_secnonce_single as generate_nonce;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util::to_hex;
use mwc_wallet_util::mwc_web3;
use mwc_wallet_util::Mutex;
use mwc_web3::types::{Address, H256, U256};
use std::marker::PhantomData;
use std::sync::Arc;

/// A locally signed Ethereum transaction has a stable hash even when the RPC
/// response cannot say whether the node accepted it. Record that hash before
/// propagating the error so a live wallet can reconcile instead of constructing
/// another transaction.
fn submitted_or_ambiguous_hash(result: &Result<H256, Error>) -> Option<H256> {
	match result {
		Ok(tx_hash) => Some(*tx_hash),
		Err(error) => error.ethereum_submission_hash(),
	}
}

/// Observed funds remain refundable even when the lock cannot advance the trade.
#[derive(Default)]
struct EthLockStatus {
	amount: u64,
	acceptable: bool,
	finalized: bool,
}

/// SwapApi trait implementaiton for ETH
#[derive(Clone)]
pub struct EthSwapApi<'a, C, B>
where
	C: NodeClient + 'a,
	B: EthNodeClient + 'a,
{
	context_id: u32,
	/// Currency. ETH - it is a ERC20 family. There are some tweaks for different coins.
	secondary_currency: Currency,
	/// Client for MWC node
	pub node_client: Arc<C>,
	/// Client for ETH node
	pub eth_node_client: Arc<Mutex<B>>,

	phantom: PhantomData<&'a C>,
}

impl<'a, C, E> EthSwapApi<'a, C, E>
where
	C: NodeClient + 'a,
	E: EthNodeClient + 'a,
{
	fn secondary_fee_gwei(&self, swap: &Swap) -> Result<u64, Error> {
		self.secondary_currency
			.secondary_fee_gwei(swap.secondary_fee_units)
	}

	/// Create Eth Swap API instance
	pub fn new(
		context_id: u32,
		secondary_currency: Currency,
		node_client: Arc<C>,
		eth_node_client: Arc<Mutex<E>>,
	) -> Self {
		Self {
			context_id,
			secondary_currency,
			node_client,
			eth_node_client,
			phantom: PhantomData,
		}
	}

	/// For tests doesn't make sense to use any failover
	pub fn new_test(node_client: Arc<C>, eth_node_client: Arc<Mutex<E>>) -> Self {
		Self {
			context_id: 0,
			secondary_currency: Currency::Ether,
			node_client,
			eth_node_client,
			phantom: PhantomData,
		}
	}

	/// Clone instance
	pub fn clone(&self) -> Self {
		Self {
			context_id: self.context_id.clone(),
			secondary_currency: self.secondary_currency.clone(),
			node_client: self.node_client.clone(),
			eth_node_client: self.eth_node_client.clone(),
			phantom: PhantomData,
		}
	}

	/// Read the height and timestamp of the same mined Ethereum block.
	fn eth_tip(&self) -> Result<EthChainTip, Error> {
		let c = self.eth_node_client.lock();
		c.chain_tip()
	}

	/// Check ETH amount at the chain.
	///
	/// A missing `address_from_secret` means the trade has not derived its lock
	/// address yet (expected before initiation) and maps to
	/// InvalidEthSwapTradeIndex. Query failures propagate unchanged so callers
	/// can tell an endpoint outage apart from an absent lock.
	pub(crate) fn eth_swap_details(
		&self,
		swap: &Swap,
		address_from_secret: Option<Address>,
	) -> Result<(U256, Option<Address>, Address, Address, u64), Error> {
		let address_from_secret = address_from_secret.ok_or(Error::InvalidEthSwapTradeIndex)?;

		let c = self.eth_node_client.lock();
		c.get_swap_details(swap.secondary_currency, address_from_secret)
	}

	/// Seller call contract function to redeem their Ethers, Status::Redeem
	fn seller_post_redeem_tx<K: Keychain>(
		&self,
		secp: &Secp256k1,
		_keychain: &K,
		swap: &Swap,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let c = self.eth_node_client.lock();
		c.validate_chain_and_contracts()?;
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let redeem_secret = SellApi::calculate_redeem_secret(secp, swap)?;
		let secret_key = SecretKeyGuard::from_bytes(&redeem_secret.0)
			.map_err(|e| Error::Generic(format!("Building mwc_web3 secret error, {}", e)))?;
		c.redeem(
			swap.secondary_currency,
			eth_data
				.address_from_secret
				.clone()
				.ok_or(Error::Generic("address_from_secret is not set".into()))?,
			&secret_key,
			self.secondary_fee_gwei(swap)?,
			recovery,
		)
	}

	/// Seller transfer eth from internal wallet to users' wallet
	fn seller_transfer_secondary(&self, swap: &Swap) -> Result<H256, Error> {
		let c = self.eth_node_client.lock();
		let address = swap.unwrap_seller()?.0;
		c.transfer(
			swap.secondary_currency,
			to_eth_address(address)?,
			swap.secondary_amount,
		)
	}

	/// buyer call contract function to refund their Ethers
	fn buyer_refund<K: Keychain>(
		&self,
		_keychain: &K,
		_context: &Context,
		swap: &Swap,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let c = self.eth_node_client.lock();
		c.validate_chain_and_contracts()?;
		let eth_data = swap.secondary_data.unwrap_eth()?;
		c.refund(
			swap.secondary_currency,
			eth_data
				.address_from_secret
				.clone()
				.ok_or(Error::Generic("address_from_secret is not set".into()))?,
			self.secondary_fee_gwei(swap)?,
			recovery,
		)
	}

	/// Advance ERC20 reset/approval/deposit while reserving the shared allowance.
	fn advance_erc20_funding(&self, swap: &mut Swap) -> Result<(), Error> {
		if swap.state.is_final_state() {
			return Err(Error::UnexpectedAction(
				"Cannot fund a finished swap".into(),
			));
		}
		let gas_gwei = self.secondary_fee_gwei(swap)?;
		let mut data = swap.secondary_data.unwrap_eth()?.clone();
		let nc = self.eth_node_client.lock();
		let result = super::funding::advance(
			&*nc,
			swap.id,
			swap.secondary_currency,
			swap.secondary_amount,
			gas_gwei,
			&mut data,
			|recovery| self.buyer_deposit_with_client(swap, &*nc, recovery),
		);
		// The owner persists swap changes even on errors, including ambiguous hashes.
		*swap.secondary_data.unwrap_eth_mut()? = data;
		result
	}

	/// buyer deposit eth to contract address
	fn buyer_deposit(
		&self,
		swap: &Swap,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let nc = self.eth_node_client.lock();
		self.buyer_deposit_with_client(swap, &*nc, recovery)
	}

	/// Anchor funding and acceptance to a block timestamp, so RPC latency and
	/// the position within a slot cannot shorten or shift the negotiated lock.
	fn eth_refund_height(
		swap: &Swap,
		current_timestamp: i64,
		tip: EthChainTip,
	) -> Result<u64, Error> {
		let lock_time = swap.get_time_secondary_lock_script()?;
		let current_time = u64::try_from(current_timestamp).map_err(|e| {
			Error::DataOverflow(format!(
				"EthSwapApi::eth_refund_height, current wall-clock time is before the Unix epoch or does not fit u64, current_time={} error={}",
				current_timestamp, e
			))
		})?;
		let eth_lock_time = u64::from(swap::validate_secondary_lock_time(
			lock_time,
			current_timestamp,
		)?);
		if eth_lock_time < current_time {
			return Err(Error::InvalidMessageData(
				"Ethereum lock deadline has already passed".into(),
			));
		}

		let block_period_seconds = swap.secondary_currency.block_time_period_sec();
		let block_period = u64::try_from(block_period_seconds).map_err(|e| {
			Error::DataOverflow(format!(
				"EthSwapApi::eth_refund_height, secondary currency block period is negative or does not fit u64, block_period_seconds={} error={}",
				block_period_seconds, e
			))
		})?;
		let lock_seconds = eth_lock_time.checked_sub(tip.timestamp).ok_or_else(|| {
			Error::DataOverflow(format!(
				"EthSwapApi::eth_refund_height, ETH lock timestamp precedes the chain tip, eth_lock_time={} block_timestamp={}",
				eth_lock_time, tip.timestamp
			))
		})?;
		// Block periods are fixed positive constants. Round up so a fractional
		// block never shortens the negotiated lock duration.
		let refund_blocks = lock_seconds.div_ceil(block_period);

		// Retain one extra block of safety. With consecutive 12-second slots this
		// cutoff stays constant as the tip advances; skipped slots can only lower
		// the later acceptance requirement, leaving an existing deposit safe.
		tip.height
			.checked_add(refund_blocks)
			.and_then(|height| height.checked_add(1))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"EthSwapApi::eth_refund_height, ETH refund height overflow, current_height={} refund_blocks={} safety_blocks=1",
					tip.height, refund_blocks
				))
			})
	}

	fn buyer_deposit_with_client(
		&self,
		swap: &Swap,
		nc: &E,
		recovery: &mut Option<EthTransactionRecovery>,
	) -> Result<H256, Error> {
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let tip = nc.validate_chain_and_contracts()?;
		if let Some(record) = recovery.as_mut() {
			return nc.retry_deposit(
				swap.secondary_currency,
				record,
				self.secondary_fee_gwei(swap)?,
			);
		}
		nc.finalized_block()?;
		let refund_time = Self::eth_refund_height(swap, swap::get_cur_time(), tip)?;
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!("height: {}, refund_time: {}", tip.height, refund_time);
		}
		let address_from_secret = eth_data
			.address_from_secret
			.clone()
			.ok_or(Error::Generic("address_from_secret is not set".into()))?;
		let participant = eth_data
			.redeem_address
			.clone()
			.ok_or(Error::Generic("redeem_address is not set".into()))?;
		let value = swap.secondary_amount;

		nc.initiate(
			swap.secondary_currency,
			refund_time,
			address_from_secret,
			participant,
			value,
			self.secondary_fee_gwei(swap)?,
			recovery,
		)
	}

	/// Confirm the expected transaction kernel. For slates finalized by the other
	/// party, derive the excess from the complete transaction body even if the
	/// stored excess is nonzero: it may identify an unrelated transaction. A
	/// matching change output alone does not prove that the swap lock exists.
	fn get_slate_confirmation_height(
		&self,
		secp: &Secp256k1,
		slate: &Slate,
		derive_kernel: bool,
		max_height: u64,
	) -> Result<Option<u64>, Error> {
		let tx = slate.tx_or_err()?;
		let Some(kernel) = tx.kernels().first() else {
			return Ok(None);
		};
		let excess = if derive_kernel {
			if tx.outputs().is_empty() {
				return Ok(None);
			}
			// Compact slates derive excess from participant keys, not the body.
			if slate.compact_slate {
				return Err(Error::InvalidMessageData(
					"Swap confirmation requires a non-compact slate".to_string(),
				));
			}
			slate.calc_excess(secp)?
		} else {
			// Locally unfinished transactions have no on-chain kernel yet.
			if kernel.excess.0.iter().all(|byte| *byte == 0) {
				return Ok(None);
			}
			kernel.excess
		};
		match self
			.node_client
			.get_kernel(&excess, Some(slate.height), Some(max_height))?
		{
			Some((_tx_kernel, height, _mmr_index)) if height <= max_height => Ok(Some(height)),
			_ => Ok(None),
		}
	}

	fn confirmations_at_tip(
		tip_height: u64,
		output_height: Option<u64>,
	) -> Result<Option<u64>, Error> {
		output_height
			.map(|height| {
				tip_height
					.checked_sub(height)
					.and_then(|confirmations| confirmations.checked_add(1))
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"EthSwapApi::confirmations_at_tip, confirmation count overflow, tip_height={} output_height={}",
							tip_height, height
						))
					})
			})
			.transpose()
	}

	/// Keep a mined payment in the waiting state until its canonical block is final.
	fn finalized_tx_confirmation(
		&self,
		tx_hash: Option<H256>,
		recovery: Option<&EthTransactionRecovery>,
	) -> Result<Option<u64>, Error> {
		let client = self.eth_node_client.lock();
		match super::recovery::transaction_receipt(&*client, tx_hash, recovery) {
			Ok(receipt) if receipt.status == Some(1.into()) => {
				Ok(Some(u64::from(client.receipt_is_finalized(&receipt)?)))
			}
			// Missing, pending, or reverted transactions remain eligible for recovery.
			Ok(_) | Err(Error::InvalidTxHash) | Err(Error::EthTransactionInPending) => Ok(None),
			Err(error) => Err(error),
		}
	}

	/// Recovery polls retain current funds without requiring finalized lock acceptance.
	fn secondary_tx_confirmations(
		&self,
		secp: &Secp256k1,
		swap: &Swap,
		check_finality: bool,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let secondary_tip = self.eth_tip()?;
		let lock_status = self.get_eth_initiate_tx_status(secp, swap, secondary_tip, check_finality)?;
		let secondary_lock_amount = lock_status.amount;
		// A skipped finality query must never produce permission to advance.
		let secondary_lock_conf = lock_status
			.acceptable
			.then_some(u64::from(lock_status.finalized));

		let eth_data = swap.secondary_data.unwrap_eth()?;
		// Payment finality is required even when recovery skips lock acceptance:
		// a positive marker lets the state machine stop monitoring the swap.
		let secondary_redeem_conf =
			self.finalized_tx_confirmation(eth_data.redeem_tx, eth_data.redeem_recovery.as_ref())?;
		let secondary_refund_conf =
			self.finalized_tx_confirmation(eth_data.refund_tx, eth_data.refund_recovery.as_ref())?;

		Ok(SwapTransactionsConfirmations {
			mwc_observed: false,
			secondary_observed: true,
			mwc_tip: 0,
			mwc_lock_conf: None,
			mwc_redeem_conf: None,
			mwc_refund_conf: None,
			secondary_tip: secondary_tip.height,
			secondary_lock_conf,
			secondary_lock_amount,
			secondary_redeem_conf,
			secondary_refund_conf,
			secondary_refund_progress: None,
		})
	}

	/// Read the deposited amount independently of whether its terms are acceptable.
	fn get_eth_initiate_tx_status(
		&self,
		secp: &Secp256k1,
		swap: &Swap,
		eth_tip: EthChainTip,
		check_finality: bool,
	) -> Result<EthLockStatus, Error> {
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let details = match self.eth_swap_details(swap, eth_data.address_from_secret) {
			Ok(details) => details,
			// Missing lock address: expected before initiation, nothing is locked.
			Err(Error::InvalidEthSwapTradeIndex) => return Ok(EthLockStatus::default()),
			// A failed contract query is not proof that no funds are locked.
			// Propagating keeps the state machine off cancel/timeout paths that
			// an unverified absence would trigger.
			Err(e) => return Err(e),
		};
		let (refund_time, erc20_token_addr, _, participant, value) = details;
		let mut status = EthLockStatus {
			amount: value,
			..Default::default()
		};
		if value == 0 || value != swap.secondary_amount {
			return Ok(status);
		}
		if swap.secondary_currency.is_erc20()
			&& erc20_token_addr != Some(swap.secondary_currency.erc20_token_address()?)
		{
			return Ok(status);
		}
		if eth_data.redeem_address != Some(participant) {
			return Ok(status);
		}
		let current_time = swap::get_cur_time();
		if current_time >= swap.get_time_secondary_lock_script()? {
			return Ok(status);
		}
		let required_refund_height = Self::eth_refund_height(swap, current_time, eth_tip)?;
		let safe_redeem_height = eth_tip.height.checked_add(100).ok_or_else(|| {
			Error::DataOverflow(format!(
				"EthSwapApi::get_eth_initiate_tx_status, ETH redeem safety height overflow, eth_tip={} safety_blocks=100",
				eth_tip.height
			))
		})?;
		// The negotiated deadline protects the seller while the buyer can still
		// redeem MWC. Also retain the 100-block margin for immediate ETH redemption.
		if refund_time < U256::from(required_refund_height)
			|| refund_time <= U256::from(safe_redeem_height)
		{
			return Ok(status);
		}
		let public_key = match swap.redeem_public.as_ref() {
			Some(public_key) => public_key,
			None => return Ok(status),
		};
		// Convert the MWC public key to Ethereum public key format.
		let serialized = public_key.serialize_vec(secp, false)?;
		let pub_key_vec = serialized
			.get(1..)
			.ok_or_else(|| Error::Generic("Unable to serialize redeem public key".to_string()))?;
		let wallet = EthereumWallet::from_public_key(to_hex(pub_key_vec).as_str())
			.map_err(|e| Error::Generic(format!("Eth wallet build public key error, {}", e)))?;
		let address = to_eth_address(
			wallet
				.address
				.clone()
				.ok_or(Error::Generic("Eth wallet address is empty".into()))?,
		)?;
		status.acceptable = eth_data.address_from_secret == Some(address);
		if status.acceptable && check_finality {
			let client = self.eth_node_client.lock();
			let finalized = client.finalized_block()?;
			status.finalized =
				match client.get_swap_details_at(swap.secondary_currency, address, finalized.into()) {
					Ok(finalized_details) => finalized_details == details,
					Err(Error::InvalidEthSwapTradeIndex) => false,
					Err(error) => return Err(error),
				};
		}
		Ok(status)
	}
}

impl<'a, K, C, E> SwapApi<K> for EthSwapApi<'a, C, E>
where
	K: Keychain + 'a,
	C: NodeClient + 'a,
	E: EthNodeClient + 'a,
{
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		_is_seller: bool,
	) -> Result<usize, Error> {
		match secondary_currency {
			Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Wbtc
			| Currency::Usdt
			| Currency::Usdc
			| Currency::Trx
			| Currency::Tst => Ok(3),
			_ => return Err(Error::UnexpectedCoinType),
		}
	}

	fn create_context(
		&mut self,
		secp: &mut Secp256k1,
		keychain: &K,
		ethereum_wallet: Option<&EthereumWallet>,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<SellerInput>>,
		change_amount: u64,
		keys: Vec<Identifier>,
		parent_key_id: Identifier,
	) -> Result<Context, Error> {
		match secondary_currency {
			Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Wbtc
			| Currency::Usdt
			| Currency::Usdc
			| Currency::Trx
			| Currency::Tst => (),
			_ => return Err(Error::UnexpectedCoinType),
		}

		// Buyer admission happens here; seller admission is checked when creating its offer.
		if !is_seller {
			self.eth_node_client.lock().finalized_block()?;
		}

		let mut keys = keys.into_iter();
		let role_context = if is_seller {
			let ethereum_wallet = ethereum_wallet.ok_or(Error::Generic(
				"create_context param ethereum_wallet is empty".into(),
			))?;
			let eth_address = to_eth_address(
				ethereum_wallet
					.address
					.clone()
					.ok_or(Error::Generic("Eth wallet address is empty".into()))?,
			)?;
			RoleContext::Seller(SellerContext {
				parent_key_id: parent_key_id,
				inputs: inputs.ok_or(Error::UnexpectedRole(
					"Fn create_context() for seller not found inputs".to_string(),
				))?,
				change_output: keys.next().ok_or(Error::Generic(
					"create_context keys param is too short".into(),
				))?,
				change_amount,
				refund_output: keys.next().ok_or(Error::Generic(
					"create_context keys param is too short".into(),
				))?,
				secondary_context: SecondarySellerContext::Eth(EthSellerContext {
					redeem_address: Some(eth_address),
				}),
			})
		} else {
			let output = keys.next().ok_or(Error::Generic(
				"create_context keys param is too short".into(),
			))?;
			let redeem = keys.next().ok_or(Error::Generic(
				"create_context keys param is too short".into(),
			))?;
			let sec_key = keychain
				.derive_key(secp, 0, &redeem, SwitchCommitmentType::None)
				.map_err(|e| Error::Generic(format!("Unbale to build redeem key, {}", e)))?;
			let eth_rand_wallet = {
				let private_key_hex = Zeroizing::new(to_hex(&sec_key.0));
				EthereumWallet::from_private_key(private_key_hex.as_str()).map_err(|e| {
					Error::Generic(format!(
						"Unable to build Eth wallet from private key, {}",
						e
					))
				})?
			};
			let eth_address = to_eth_address(eth_rand_wallet.address.clone().ok_or(
				Error::Generic("create_context Eth wallet address is emoty".into()),
			)?)?;
			RoleContext::Buyer(BuyerContext {
				parent_key_id: parent_key_id,
				output,
				redeem,
				secondary_context: SecondaryBuyerContext::Eth(EthBuyerContext {
					address_from_secret: eth_address,
				}),
			})
		};

		Ok(Context {
			multisig_key: keys.next().ok_or(Error::Generic(
				"create_context keys param is too short".into(),
			))?,
			multisig_nonce: generate_nonce(secp)?,
			lock_nonce: generate_nonce(secp)?,
			refund_nonce: generate_nonce(secp)?,
			redeem_nonce: generate_nonce(secp)?,
			role_context,
		})
	}

	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		secp: &mut Secp256k1,
		keychain: &K,
		context: &Context,
		mwc_anchor_height: u64,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		seller_lock_first: bool,
		mwc_confirmations: u64,
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
		communication_method: String,
		buyer_destination_address: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_swap_contract_address: Option<String>,
		erc20_swap_contract_address: Option<String>,
		eth_infura_project_id: Option<String>,
		eth_redirect_out_wallet: Option<bool>,
		dry_run: bool,
		tag: Option<String>,
	) -> Result<Swap, Error> {
		match secondary_currency {
			Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Wbtc
			| Currency::Usdt
			| Currency::Usdc
			| Currency::Trx
			| Currency::Tst => (),
			_ => return Err(Error::UnexpectedCoinType),
		}

		self.eth_node_client.lock().finalized_block()?;

		let mut swap = SellApi::create_swap_offer(
			self.context_id,
			secp,
			keychain,
			context,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_redeem_address,
			mwc_anchor_height,
			seller_lock_first,
			mwc_confirmations,
			secondary_confirmations,
			message_exchange_time_sec,
			redeem_time_sec,
			communication_method,
			buyer_destination_address,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
			eth_redirect_out_wallet,
			dry_run,
			tag,
			self.node_client.as_ref(),
		)?;

		let eth_data = EthData::new(context.unwrap_seller()?.unwrap_eth()?)?;
		swap.secondary_data = eth_data.wrap();

		Ok(swap)
	}

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error> {
		let eth_data = swap.secondary_data.unwrap_eth()?;
		Ok(SecondaryUpdate::ETH(eth_data.offer_update()))
	}

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error> {
		let eth_data = swap.secondary_data.unwrap_eth()?;
		Ok(SecondaryUpdate::ETH(eth_data.accept_offer_update()))
	}

	fn publish_secondary_transaction(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		_context: &Context,
		post_tx: bool,
	) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"EthSwapApi::publish_secondary_transaction, swap role is not seller".to_string(),
			));
		}
		// Ethereum cannot prepare a historical transaction hash without assigning a
		// fresh live-account nonce. In particular, trade import passes false and must
		// remain a read-only recovery operation.
		if !post_tx {
			return Ok(());
		}
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let status = super::recovery::transaction_status(
			&*self.eth_node_client.lock(),
			eth_data.redeem_tx,
			eth_data.redeem_recovery.as_ref(),
		);
		match status {
			Ok((hash, true)) => {
				swap.secondary_data.unwrap_eth_mut()?.redeem_tx = Some(hash);
				return Ok(());
			}
			Ok((_, false)) => {
				// A reverted mined transaction consumed its nonce. Only this evidence
				// permits constructing a fresh redeem with a different nonce.
				let data = swap.secondary_data.unwrap_eth_mut()?;
				data.redeem_tx = None;
				data.redeem_recovery = None;
			}
			Err(Error::InvalidTxHash) => (),
			Err(Error::EthTransactionInPending) => {
				if eth_data.redeem_recovery.is_none() {
					return Err(Error::EthereumTransactionRecoveryMissing(
						eth_data.redeem_tx.ok_or(Error::InvalidTxHash)?,
					));
				}
			}
			Err(error) => return Err(error),
		}

		let secondary_fee_gwei = self.secondary_fee_gwei(swap)?;
		let mut recovery = swap.secondary_data.unwrap_eth()?.redeem_recovery.clone();
		let submission = self.seller_post_redeem_tx(secp, keychain, swap, &mut recovery);
		// Preserve signed bytes even when sending failed or a worker panicked.
		// The owner persists the mutated trade on both successful and error returns.
		let eth_data = swap.secondary_data.unwrap_eth_mut()?;
		if let Some(record) = &recovery {
			eth_data.redeem_tx = record.attempted_hashes.last().copied();
			eth_data.tx_fee_gwei = Some(record.gas_budget_gwei);
		}
		eth_data.redeem_recovery = recovery;
		if let Some(eth_tx) = submitted_or_ambiguous_hash(&submission) {
			eth_data.redeem_tx = Some(eth_tx);
			if eth_data.redeem_recovery.is_none() {
				eth_data.tx_fee_gwei = Some(secondary_fee_gwei);
			}
		}
		submission.map(|_| ())
	}

	/// Verify MWC confirmations independently of the secondary RPC service.
	fn request_mwc_tx_confirmations(
		&self,
		secp: &Secp256k1,
		_keychain: &K, // keychain is kept for Type. Compiler need to understand all types
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let session =
			NodeReadSession::start(&*self.node_client, "Ethereum swap confirmation poll")?;

		let is_seller = swap.is_seller();

		let mwc_lock_height = self.get_slate_confirmation_height(
			secp,
			&swap.lock_slate.slate,
			!is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "Ethereum swap lock confirmation")?;
		let mwc_redeem_height = self.get_slate_confirmation_height(
			secp,
			&swap.redeem_slate.slate,
			is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "Ethereum swap redeem confirmation")?;
		let mwc_refund_height = self.get_slate_confirmation_height(
			secp,
			&swap.refund_slate.slate,
			!is_seller,
			session.anchor.height,
		)?;
		session.ensure_connection(&*self.node_client, "Ethereum swap refund confirmation")?;
		let final_tip = session.fresh_tip(&*self.node_client, "Ethereum swap confirmation poll")?;
		let mwc_lock_conf = Self::confirmations_at_tip(final_tip.height, mwc_lock_height)?;
		let mwc_redeem_conf = Self::confirmations_at_tip(final_tip.height, mwc_redeem_height)?;
		let mwc_refund_conf = Self::confirmations_at_tip(final_tip.height, mwc_refund_height)?;

		Ok(SwapTransactionsConfirmations::mwc_only(
			final_tip.height,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
		))
	}

	fn request_tx_confirmations(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let mwc = self.request_mwc_tx_confirmations(secp, keychain, swap)?;
		// An observed redeem/refund already requires recovery, even before its
		// exposure or recovered kernel has been persisted in the trade.
		let check_finality = mwc.mwc_redeem_conf.is_none()
			&& mwc.mwc_refund_conf.is_none()
			&& swap.needs_secondary_lock_finality()?;
		Ok(self
			.secondary_tx_confirmations(secp, swap, check_finality)?
			.with_mwc(mwc))
	}

	fn request_secondary_tx_confirmations(
		&self,
		secp: &Secp256k1,
		_keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		self.secondary_tx_confirmations(secp, swap, swap.needs_secondary_lock_finality()?)
	}

	fn request_tx_confirmations_for_cancel(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		let mwc = self.request_mwc_tx_confirmations(secp, keychain, swap)?;
		Ok(self
			.secondary_tx_confirmations(secp, swap, false)?
			.with_mwc(mwc))
	}

	/// Check How much ETH coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		_confirmations_needed: u64,
		secp: &Secp256k1,
	) -> Result<(u64, u64, u64), Error> {
		let eth_tip = self.eth_tip()?;
		let status = self.get_eth_initiate_tx_status(secp, swap, eth_tip, false)?;
		Ok((0, status.amount, 0))
	}

	fn prepare_secondary_redeem(&self, swap: &mut Swap, secp: &Secp256k1) -> Result<(), Error> {
		let eth_tip = self.eth_tip()?;
		let status = self.get_eth_initiate_tx_status(secp, swap, eth_tip, true)?;
		if !status.acceptable {
			return Err(Error::Generic(
				"Ethereum deposit does not satisfy the negotiated swap terms and redeem safety margin"
					.into(),
			));
		}
		if !status.finalized {
			return Err(Error::EthereumFinalityUnavailable(
				"waiting for the valid swap lock to finalize".into(),
			));
		}
		Ok(())
	}

	// Build state machine that match the swap data
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine<'_> {
		let kc = Arc::new(keychain.clone());
		let nc = self.node_client.clone();
		let b: Box<dyn SwapApi<K> + 'a> = Box::new((*self).clone());
		let swap_api = Arc::new(b);

		if swap.is_seller() {
			StateMachine::new(vec![
				Box::new(seller_swap::SellerOfferCreated::new()),
				Box::new(seller_swap::SellerSendingOffer::new(
					self.context_id,
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForAcceptanceMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerLock::new(
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerPostingLockMwcSlate::new(
					self.context_id,
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForLockConfirmations::new(
					self.context_id,
					kc.clone(),
					swap_api.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForInitRedeemMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(seller_swap::SellerSendingInitRedeemMessage::new(
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerToRedeemMwc::new(
					nc.clone(),
				)),
				Box::new(seller_swap::SellerRedeemSecondaryCurrency::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForRedeemConfirmations::new(
					self.context_id,
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerSwapComplete::new()),
				Box::new(seller_swap::SellerWaitingForRefundHeight::new(nc.clone())),
				Box::new(seller_swap::SellerPostingRefundSlate::new(
					self.context_id,
					nc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForRefundConfirmations::new()),
				Box::new(seller_swap::SellerCancelledRefunded::new()),
				Box::new(seller_swap::SellerCancelled::new()),
			])
		} else {
			StateMachine::new(vec![
				Box::new(buyer_swap::BuyerOfferCreated::new()),
				Box::new(buyer_swap::BuyerSendingAcceptOfferMessage::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForSellerToLock::new()),
				Box::new(buyer_swap::BuyerPostingSecondaryToMultisigAccount::new(
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForLockConfirmations::new(
					self.context_id,
					kc.clone(),
					swap_api.clone(),
					nc.clone(),
				)),
				Box::new(buyer_swap::BuyerSendingInitRedeemMessage::new(
					self.context_id,
				)),
				Box::new(buyer_swap::BuyerWaitingForRespondRedeemMessage::new(
					self.context_id,
					kc.clone(),
					nc.clone(),
				)),
				Box::new(buyer_swap::BuyerRedeemMwc::new(self.context_id, nc.clone())),
				Box::new(buyer_swap::BuyerWaitForRedeemMwcConfirmations::new()),
				Box::new(buyer_swap::BuyerWaitingForMwcRefundConfirmations::new()),
				Box::new(buyer_swap::BuyerSwapComplete::new()),
				Box::new(buyer_swap::BuyerSwapFailed::new()),
				Box::new(buyer_swap::BuyerWaitingForRefundTime::new(swap_api.clone())),
				Box::new(buyer_swap::BuyerPostingRefundForSecondary::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerWaitingForRefundConfirmations::new(
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerCancelledRefunded::new()),
				Box::new(buyer_swap::BuyerCancelled::new()),
			])
		}
	}

	/// Get a secondary address for the lock account
	fn get_secondary_lock_address(
		&self,
		swap: &Swap,
		_secp: &Secp256k1,
	) -> Result<Vec<String>, Error> {
		let eth_data = swap.secondary_data.unwrap_eth()?;

		match eth_data.address_from_secret {
			Some(address) => Ok(vec![eth_address(address)]),
			_ => Ok(vec!["".to_string()]),
		}
	}

	/// Check if tx fee for the secondary is different from the posted
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, Error> {
		Ok(swap.secondary_data.unwrap_eth()?.tx_fee_gwei != Some(self.secondary_fee_gwei(swap)?))
	}

	/// Post ETH refund transaction
	fn post_secondary_refund_tx(
		&self,
		_secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		_refund_address: Option<String>,
		post_tx: bool,
	) -> Result<(), Error> {
		if swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"EthSwapApi::post_secondary_refund_tx, swap role is not buyer".to_string(),
			));
		}
		if !post_tx {
			return Ok(());
		}
		let eth_data = swap.secondary_data.unwrap_eth()?;

		let status = super::recovery::transaction_status(
			&*self.eth_node_client.lock(),
			eth_data.refund_tx,
			eth_data.refund_recovery.as_ref(),
		);
		match status {
			Ok((hash, true)) => {
				swap.secondary_data.unwrap_eth_mut()?.refund_tx = Some(hash);
				return Ok(());
			}
			Ok((_, false)) => {
				// A mined revert consumed the nonce, permitting a fresh refund.
				let data = swap.secondary_data.unwrap_eth_mut()?;
				data.refund_tx = None;
				data.refund_recovery = None;
			}
			Err(Error::InvalidTxHash) => (),
			Err(Error::EthTransactionInPending) => {
				if eth_data.refund_recovery.is_none() {
					return Err(Error::EthereumTransactionRecoveryMissing(
						eth_data.refund_tx.ok_or(Error::InvalidTxHash)?,
					));
				}
			}
			Err(error) => return Err(error),
		}

		let secondary_fee_gwei = self.secondary_fee_gwei(swap)?;
		let mut recovery = swap.secondary_data.unwrap_eth()?.refund_recovery.clone();
		let submission = self.buyer_refund(keychain, context, swap, &mut recovery);
		// The owner persists the signed refund and every replacement even on errors.
		let eth_data = swap.secondary_data.unwrap_eth_mut()?;
		if let Some(record) = &recovery {
			eth_data.refund_tx = record.attempted_hashes.last().copied();
			eth_data.tx_fee_gwei = Some(record.gas_budget_gwei);
		}
		eth_data.refund_recovery = recovery;
		if let Some(eth_tx) = submitted_or_ambiguous_hash(&submission) {
			eth_data.refund_tx = Some(eth_tx);
			if eth_data.refund_recovery.is_none() {
				eth_data.tx_fee_gwei = Some(secondary_fee_gwei);
			}
		}

		submission.map(|_| ())
	}

	/// Recover only the pending approval, including for a finished buyer trade.
	fn retry_erc20_approval(&self, swap: &mut Swap) -> Result<(), Error> {
		if swap.is_seller() || !swap.secondary_currency.is_erc20() {
			return Err(Error::UnexpectedAction(
				"ERC20 approval recovery requires a buyer trade".into(),
			));
		}
		let gas_gwei = self.secondary_fee_gwei(swap)?;
		let nc = self.eth_node_client.lock();
		let result = super::funding::retry_approval(
			&*nc,
			swap.secondary_currency,
			swap.secondary_amount,
			gas_gwei,
			swap.secondary_data.unwrap_eth_mut()?,
		);
		super::funding::record_swap(swap);
		result
	}

	fn recover_secondary_deposit(
		&self,
		swap: &mut Swap,
		mode: super::DepositRecoveryMode,
	) -> Result<(), Error> {
		use super::{recovery::DepositOutcome, DepositRecoveryMode};
		use crate::swap::fsm::state::StateId;
		if swap.is_seller() || !swap.secondary_currency.is_erc20() {
			return Err(Error::UnexpectedAction(
				"Deposit recovery requires an ERC20 buyer trade".into(),
			));
		}
		if mode == DepositRecoveryMode::RetryOriginal && swap.state.is_final_state() {
			return Err(Error::UnexpectedAction(
				"Use cancel_erc20_deposit for a finished trade".into(),
			));
		}
		if mode == DepositRecoveryMode::Cancel
			&& !matches!(
				swap.state,
				StateId::BuyerPostingSecondaryToMultisigAccount
					| StateId::BuyerWaitingForLockConfirmations
					| StateId::BuyerWaitingForRefundTime
					| StateId::BuyerCancelled
			) {
			return Err(Error::UnexpectedAction("Deposit cancellation requires a funding or cancelled trade before redemption or refund submission".into()));
		}
		let gas_gwei = self.secondary_fee_gwei(swap)?;
		let mut data = swap.secondary_data.unwrap_eth()?.clone();
		let nc = self.eth_node_client.lock();
		let recovery = super::funding::recover_deposit(
			&*nc,
			swap.id,
			swap.secondary_currency,
			gas_gwei,
			&mut data,
			mode,
			swap.state.is_final_state(),
		);
		// Once cancellation is signed, automated funding must not continue while
		// its outcome is uncertain. Explicit recovery reconciles either winner.
		if mode == DepositRecoveryMode::Cancel
			&& data.lock_cancel_recovery.is_some()
			&& matches!(
				swap.state,
				StateId::BuyerPostingSecondaryToMultisigAccount
					| StateId::BuyerWaitingForLockConfirmations
			) {
			swap.state = StateId::BuyerCancelled;
		}
		*swap.secondary_data.unwrap_eth_mut()? = data;
		let result = (|| {
			let outcome = recovery?;
			if mode == DepositRecoveryMode::Cancel {
				match outcome {
					Some(DepositOutcome::Deposited(_)) => {
						let address = swap
							.secondary_data
							.unwrap_eth()?
							.address_from_secret
							.ok_or(Error::InvalidEthSwapTradeIndex)?;
						let key = nc.erc20_allowance_key(swap.secondary_currency)?;
						let (_, token, initiator, _, value) =
							nc.get_swap_details(swap.secondary_currency, address)?;
						if value > 0 && token == Some(key.token) && initiator == key.owner {
							swap.state = StateId::BuyerWaitingForRefundTime;
						}
					}
					Some(DepositOutcome::Cancelled(_) | DepositOutcome::Reverted(_)) => {
						swap.state = StateId::BuyerCancelled;
					}
					None => (),
				}
			}
			Ok(())
		})();
		super::funding::record_swap(swap);
		result
	}

	/// deposit secondary currecny to lock account.
	fn post_secondary_lock_tx(&self, swap: &mut Swap) -> Result<(), Error> {
		if swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"EthSwapApi::post_secondary_lock_tx, swap role is not buyer".to_string(),
			));
		}
		if swap.secondary_currency.is_erc20() {
			return self.advance_erc20_funding(swap);
		}
		let eth_data = swap.secondary_data.unwrap_eth()?;

		let status = super::recovery::transaction_status(
			&*self.eth_node_client.lock(),
			eth_data.lock_tx,
			eth_data.lock_recovery.as_ref(),
		);
		match status {
			Ok((hash, true)) => {
				swap.secondary_data.unwrap_eth_mut()?.lock_tx = Some(hash);
				return Ok(());
			}
			Ok((_, false)) => {
				// A mined revert consumed the nonce, permitting a fresh deposit.
				let data = swap.secondary_data.unwrap_eth_mut()?;
				data.lock_tx = None;
				data.lock_recovery = None;
			}
			Err(Error::InvalidTxHash) => (),
			Err(Error::EthTransactionInPending) => {
				if eth_data.lock_recovery.is_none() {
					return Err(Error::EthereumTransactionRecoveryMissing(
						eth_data.lock_tx.ok_or(Error::InvalidTxHash)?,
					));
				}
			}
			Err(error) => return Err(error),
		}

		let secondary_fee_gwei = self.secondary_fee_gwei(swap)?;
		let mut recovery = swap.secondary_data.unwrap_eth()?.lock_recovery.clone();
		let submission = self.buyer_deposit(swap, &mut recovery);
		// Keep signed bytes and replacement hashes on errors, as for refunds.
		let eth_data = swap.secondary_data.unwrap_eth_mut()?;
		if let Some(record) = &recovery {
			eth_data.lock_tx = record.attempted_hashes.last().copied();
			eth_data.tx_fee_gwei = Some(record.gas_budget_gwei);
		}
		eth_data.lock_recovery = recovery;
		if let Some(eth_tx) = submitted_or_ambiguous_hash(&submission) {
			eth_data.lock_tx = Some(eth_tx);
			if eth_data.lock_recovery.is_none() {
				eth_data.tx_fee_gwei = Some(secondary_fee_gwei);
			}
		}

		submission.map(|_| ())
	}

	fn secondary_lock_tx_failed(&self, swap: &Swap) -> Result<bool, Error> {
		let data = swap.secondary_data.unwrap_eth()?;
		let client = self.eth_node_client.lock();
		let receipt = match super::recovery::transaction_receipt(
			&*client,
			data.lock_tx,
			data.lock_recovery.as_ref(),
		) {
			Ok(receipt) => receipt,
			Err(Error::EthTransactionInPending) => return Ok(false),
			Err(error) => return Err(error),
		};
		if receipt.status != Some(0.into()) {
			return Ok(false);
		}
		// A reorganization can remove a reverted receipt and allow the deposit
		// to succeed later. Do not stop monitoring until that failure is final.
		client.receipt_is_finalized(&receipt)
	}

	/// transfer amount to dedicated address.
	fn transfer_scondary(&self, swap: &mut Swap) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"EthSwapApi::transfer_scondary, swap role is not seller".to_string(),
			));
		}

		if swap.secondary_data.unwrap_eth()?.redirect_tx.is_some() {
			// The recorded hash is authoritative until its receipt is reconciled.
			return Ok(());
		}

		let submission = self.seller_transfer_secondary(swap);
		if let Some(eth_tx) = submitted_or_ambiguous_hash(&submission) {
			let data = swap.secondary_data.unwrap_eth_mut()?;
			data.redirect_tx = Some(eth_tx);
			data.redirect_tx_candidates = super::recovery::track_redirect(eth_tx);
		}
		submission.map(|_| ())
	}

	fn transfer_secondary_status(&self, swap: &mut Swap) -> Result<SecondaryTransferStatus, Error> {
		// A fee retry preserves the payment but changes its hash. Save all known
		// candidates so later checks also work after cache cleanup or a restart.
		super::recovery::refresh_redirect_candidates(swap);
		let data = swap.secondary_data.unwrap_eth()?;
		if data.redirect_tx.is_none() {
			return Ok(SecondaryTransferStatus::NotPosted);
		}
		match super::recovery::transaction_receipt_for_hashes(
			&*self.eth_node_client.lock(),
			&data.redirect_tx_candidates,
		) {
			Ok(receipt) if receipt.status == Some(1.into()) => {
				Ok(SecondaryTransferStatus::Confirmed)
			}
			Ok(_) => Ok(SecondaryTransferStatus::Failed),
			// Pending transactions and lookup failures both require retaining the hash
			// and refusing to create another transfer until its receipt is reconciled.
			Err(_) => Ok(SecondaryTransferStatus::Pending),
		}
	}

	fn ethereum_gas_balance(&self) -> Result<u64, Error> {
		Ok(self.eth_node_client.lock().balance(Currency::Ether)?.1)
	}

	fn test_client_connections(&self) -> Result<(), Error> {
		{
			let c = self.eth_node_client.lock();
			let name = c.name();
			let _ = c.validate_chain_and_contracts().map_err(|e| {
				Error::InfuraNodeClient(format!(
					"Unable to validate Ethereum client and swap contracts {}, {}",
					name, e
				))
			})?;
		}
		Ok(())
	}
}
