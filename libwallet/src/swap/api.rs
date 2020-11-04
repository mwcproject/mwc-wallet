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

use super::error::ErrorKind;
use super::swap::Swap;
use super::types::{Context, Currency};
use super::Keychain;
use crate::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};
use crate::swap::fsm::machine::StateMachine;
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::SwapTransactionsConfirmations;
use crate::NodeClient;
use grin_core::global;
use grin_keychain::Identifier;
use grin_util::Mutex;
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
	) -> Result<usize, ErrorKind>;

	/// Creating buyer/seller context. Keys are used to generate this session secrets.
	/// Number of them defined by context_key_count
	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>, // inputs with amounts that sellect is agree to use.
		change_amount: u64,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind>;

	/// Seller creates a swap offer and creates the core Swap Object.
	/// It is a starting point for Seller swap workflow
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		primary_amount: u64,   // mwc amount to sell
		secondary_amount: u64, // btc amount to buy
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
	) -> Result<Swap, ErrorKind>;

	/// get state machine fro this trade.
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine;

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&self,
		_keychain: &K,
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind>;

	/// Check How much BTC coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64), ErrorKind>;

	/// Build secondary update part of the offer message
	fn build_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate;

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate;

	/// Publishing Secinadary (BTC) transactions
	/// Seller: redeep BTC transaction at State RedeemSecondary
	fn publish_secondary_transaction(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind>;

	/// Get a secondary address for the lock account
	fn get_secondary_lock_address(&self, swap: &Swap) -> Result<String, ErrorKind>;

	/// Check if tx fee for the secondary is different from the posted. compare swap.secondary_fee with
	/// posted BTC secondary_fee
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, ErrorKind>;

	/// Post Refund transaction.
	fn post_secondary_refund_tx(
		&self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
	) -> Result<(), ErrorKind>;
}

/// Create an appropriate instance for the Currency
/// electrumx_uri - mandatory for BTC
/// Note: Result lifetime is equal of arguments lifetime!
pub fn create_instance<'a, C, K>(
	currency: &Currency,
	node_client: C,
	electrum_node_uri1: String,
	electrum_node_uri2: String,
) -> Result<Box<dyn SwapApi<K> + 'a>, ErrorKind>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secondary_currency_node_client1 = ElectrumNodeClient::new(
		electrum_node_uri1,
		currency.get_block1_tx_hash(!global::is_mainnet()),
	);
	let secondary_currency_node_client2 = ElectrumNodeClient::new(
		electrum_node_uri2,
		currency.get_block1_tx_hash(!global::is_mainnet()),
	);
	Ok(Box::new(BtcSwapApi::new(
		Arc::new(node_client),
		Arc::new(Mutex::new(secondary_currency_node_client1)),
		Arc::new(Mutex::new(secondary_currency_node_client2)),
	)))
}
