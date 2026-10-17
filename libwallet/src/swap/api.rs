// Copyright 2019 The vault713 Developers
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

use super::error::Error;
use super::swap::Swap;
use super::types::{Context, Currency, SecondaryTransferStatus, SellerInput};
use super::Keychain;
use crate::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};
use crate::swap::ethereum::{EthSwapApi, EthereumWallet, InfuraNodeClient};
use crate::swap::fsm::machine::StateMachine;
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::SwapTransactionsConfirmations;
use crate::{NodeClient, SecondaryFeeUnits};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::Identifier;
use mwc_wallet_util::Mutex;
use std::sync::Arc;

/// Swap API trait that is used by both Buyer and Seller.
/// Every currency that Swap want to support, need to implement
/// this trait. Current we have only implementaiton: api::BtcSwapApi
pub trait SwapApi<K: Keychain>: Sync + Send {
	/// Number of the keys at the create_context, keys (For BTC it is 4)
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
	) -> Result<usize, Error>;

	/// Creating buyer/seller context. Keys are used to generate this session secrets.
	/// Number of them defined by context_key_count
	fn create_context(
		&mut self,
		secp: &mut Secp256k1,
		keychain: &K,
		ethereum_wallet: Option<&EthereumWallet>,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<SellerInput>>, // inputs with amounts and features that seller agrees to use.
		change_amount: u64,
		keys: Vec<Identifier>,
		parent_key_id: Identifier,
	) -> Result<Context, Error>;

	/// Seller creates a swap offer and creates the core Swap Object.
	/// It is a starting point for Seller swap workflow
	fn create_swap_offer(
		&mut self,
		secp: &mut Secp256k1,
		keychain: &K,
		context: &Context,
		mwc_anchor_height: u64, // validated wallet-refresh height
		primary_amount: u64,    // mwc amount to sell
		secondary_amount: u64,  // btc amount to buy
		secondary_currency: Currency,
		secondary_redeem_address: String, // redeed address for BTC
		seller_lock_first: bool,
		mwc_confirmations: u64, // Needed conformation numbers for mwc & btc
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
	) -> Result<Swap, Error>;

	/// get state machine fro this trade.
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine<'_>;

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&self,
		secp: &Secp256k1,
		_keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error>;

	/// Query MWC independently so an unrelated RPC outage cannot block its refund.
	/// Implementations without a separate query retain the full-snapshot behavior.
	fn request_mwc_tx_confirmations(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		self.request_tx_confirmations(secp, keychain, swap)
	}

	/// Query secondary recovery independently of the MWC RPC service.
	fn request_secondary_tx_confirmations(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		self.request_tx_confirmations(secp, keychain, swap)
	}

	/// Recovery can use its own chain without treating unavailable observations
	/// as an absent transaction. Import and other callers requiring both chains
	/// continue to use request_tx_confirmations.
	fn request_tx_confirmations_for_state(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		if swap.can_use_secondary_confirmations() {
			let secondary = self.request_secondary_tx_confirmations(secp, keychain, swap)?;
			// Preserve MWC observations and opportunistic refunds when available,
			// but their RPC failure must not prevent secondary recovery. The FSM
			// explicitly restricts transitions when these observations are missing.
			Ok(
				match self.request_mwc_tx_confirmations(secp, keychain, swap) {
					Ok(mwc) => secondary.with_mwc(mwc),
					Err(_) => secondary,
				},
			)
		} else if swap.is_seller() && swap.state.is_seller_refund() {
			self.request_mwc_tx_confirmations(secp, keychain, swap)
		} else {
			self.request_tx_confirmations(secp, keychain, swap)
		}
	}

	/// Cancellation observes funds for recovery without authorizing new commitments.
	fn request_tx_confirmations_for_cancel(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, Error> {
		self.request_tx_confirmations(secp, keychain, swap)
	}

	/// Check How much BTC coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		confirmations_needed: u64,
		secp: &Secp256k1,
	) -> Result<(u64, u64, u64), Error>;

	/// Validate and freeze the seller's secondary funding before exposing its
	/// MWC redeem signature, including redemption fee affordability and dust.
	/// Account-based currencies do not select UTXOs.
	fn prepare_secondary_redeem(&self, _swap: &mut Swap, _secp: &Secp256k1) -> Result<(), Error> {
		Ok(())
	}

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error>;

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> Result<SecondaryUpdate, Error>;

	/// Publishing Secinadary (BTC) transactions
	/// Seller: redeep BTC transaction at State RedeemSecondary
	fn publish_secondary_transaction(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		post_tx: bool,
	) -> Result<(), Error>;

	/// Get a secondary addresses for the lock account
	/// We can have several addresses because of different formats
	fn get_secondary_lock_address(
		&self,
		swap: &Swap,
		secp: &Secp256k1,
	) -> Result<Vec<String>, Error>;

	/// Check if the unit-bearing secondary fee differs from the posted fee.
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, Error>;

	/// Calculate the seller's redemption fee without signing or changing the trade.
	/// Used to limit automatic BTC fee increases before accepting a new rate.
	fn secondary_redeem_fee(
		&self,
		_swap: &Swap,
		_fee_units: SecondaryFeeUnits,
		_secp: &Secp256k1,
	) -> Result<u64, Error> {
		Err(Error::UnexpectedCoinType)
	}

	/// Minimum spendable output for the seller's redemption destination, using
	/// the same dust policy as the signer. Used before accepting automatic fees.
	fn secondary_redeem_minimum_output(&self, _swap: &Swap) -> Result<u64, Error> {
		Err(Error::UnexpectedCoinType)
	}

	/// Prepare the buyer refund for durable storage before broadcasting it.
	fn prepare_secondary_refund(
		&self,
		_secp: &Secp256k1,
		_keychain: &K,
		_context: &Context,
		_swap: &mut Swap,
	) -> Result<(), Error> {
		Ok(())
	}

	/// Post Refund transaction.
	fn post_secondary_refund_tx(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
		post_tx: bool,
	) -> Result<(), Error>;

	/// deposit secondary currecny to lock account.
	fn post_secondary_lock_tx(&self, swap: &mut Swap) -> Result<(), Error>;

	/// True only when a recorded deposit reverted in a canonical finalized block.
	/// Pending deposits and successful deposits still require refund monitoring;
	/// lookup failures must propagate rather than establish that funding failed.
	fn secondary_lock_tx_failed(&self, _swap: &Swap) -> Result<bool, Error> {
		Ok(false)
	}

	/// Explicitly recover an existing ERC20 approval/reset, including after
	/// cancellation. Does not start another approval or deposit. Persist mutations
	/// on errors as well as success, as for secondary transaction submissions.
	fn retry_erc20_approval(&self, _swap: &mut Swap) -> Result<(), Error> {
		Err(Error::UnexpectedCoinType)
	}

	/// Resolve an already signed ERC20 deposit, including after cancellation.
	/// Persist mutations even when submission returns an error.
	fn recover_secondary_deposit(
		&self,
		_swap: &mut Swap,
		_mode: super::ethereum::DepositRecoveryMode,
	) -> Result<(), Error> {
		Err(Error::UnexpectedCoinType)
	}

	/// transfer amount to dedicated address.
	fn transfer_scondary(&self, swap: &mut Swap) -> Result<(), Error>;

	/// Reconcile the seller's Ethereum private-wallet redirect transaction.
	/// BTC-family implementations never require this operation.
	fn transfer_secondary_status(&self, _swap: &mut Swap) -> Result<SecondaryTransferStatus, Error> {
		Ok(SecondaryTransferStatus::NotPosted)
	}

	/// Return the wallet's Ether balance in gwei for Ethereum transaction fees.
	fn ethereum_gas_balance(&self) -> Result<u64, Error> {
		Err(Error::UnexpectedCoinType)
	}

	/// Validate clients. We want to be sure that the clients able to acceess the servers
	fn test_client_connections(&self) -> Result<(), Error>;
}

/// Create an appropriate instance for the Currency
/// electrumx_uri - mandatory for BTC
/// Note: Result lifetime is equal of arguments lifetime!
pub fn create_btc_instance<'a, C, K>(
	context_id: u32,
	currency: &Currency,
	node_client: C,
	electrum_node_uri1: String,
	electrum_node_uri2: String,
) -> Result<Box<dyn SwapApi<K> + 'a>, Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	//todo change to check btc family
	match currency {
		Currency::Btc
		| Currency::Bch
		| Currency::Ltc
		| Currency::Dash
		| Currency::ZCash
		| Currency::Doge => {
			let secondary_currency_node_client1 = ElectrumNodeClient::new(
				electrum_node_uri1,
				currency.get_block1_tx_hash(!global::is_mainnet(context_id)),
			);
			let secondary_currency_node_client2 = ElectrumNodeClient::new(
				electrum_node_uri2,
				currency.get_block1_tx_hash(!global::is_mainnet(context_id)),
			);
			Ok(Box::new(BtcSwapApi::new(
				context_id,
				currency.clone(),
				Arc::new(node_client),
				Arc::new(Mutex::new(secondary_currency_node_client1)),
				Arc::new(Mutex::new(secondary_currency_node_client2)),
			)))
		}
		_ => Err(Error::InvalidCurrency(
			"unknow btc family coins".to_string(),
		)),
	}
}

/// Create an appropriate instance for the Currency
/// ethereum - mandatory for ETH
/// Note: Result lifetime is equal of arguments lifetime!
pub fn create_eth_instance<'a, C, K>(
	context_id: u32,
	currency: &Currency,
	node_client: C,
	ethereum_wallet: EthereumWallet,
	eth_swap_contract_addr: String,
	erc20_swap_contract_addr: String,
	eth_infura_project_id: String,
) -> Result<Box<dyn SwapApi<K> + 'a>, Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	match currency {
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
		| Currency::Tst => {
			let chain = if global::is_mainnet(context_id) {
				"mainnet".to_string()
			} else {
				"ropsten".to_string()
			};
			let secondary_currency_node_client = InfuraNodeClient::new(
				eth_infura_project_id,
				chain,
				ethereum_wallet,
				eth_swap_contract_addr,
				erc20_swap_contract_addr,
			)?;

			Ok(Box::new(EthSwapApi::new(
				context_id,
				currency.clone(),
				Arc::new(node_client),
				Arc::new(Mutex::new(secondary_currency_node_client)),
			)))
		}
		_ => Err(Error::InvalidCurrency(
			"unknow ethereum family coins".to_string(),
		)),
	}
}
