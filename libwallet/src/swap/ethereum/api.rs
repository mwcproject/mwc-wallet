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
use super::types::{to_eth_address, EthBuyerContext, EthData, EthSellerContext};
use super::{client::EthNodeClient, eth_address};
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::{
	secp::aggsig::export_secnonce_single as generate_nonce, secp::pedersen, to_hex, Mutex,
};
use crate::swap::fsm::machine::StateMachine;
use crate::swap::fsm::{buyer_swap, seller_swap};
use crate::swap::message::SecondaryUpdate;
use crate::swap::swap;
use crate::swap::types::{
	BuyerContext, Context, Currency, RoleContext, SecondaryBuyerContext, SecondarySellerContext,
	SellerContext, SwapTransactionsConfirmations,
};
use crate::swap::{ErrorKind, SellApi, Swap, SwapApi};
use crate::{NodeClient, Slate};
use failure::_core::marker::PhantomData;
use grin_wallet_util::grin_core::core::Committed;
use std::sync::Arc;
use web3::types::{Address, H256};
use grin_wallet_util::grin_util::secp::Secp256k1;

/// SwapApi trait implementaiton for ETH
#[derive(Clone)]
pub struct EthSwapApi<'a, C, B>
where
	C: NodeClient + 'a,
	B: EthNodeClient + 'a,
{
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
	/// Create Eth Swap API instance
	pub fn new(
		secondary_currency: Currency,
		node_client: Arc<C>,
		eth_node_client: Arc<Mutex<E>>,
	) -> Self {
		Self {
			secondary_currency,
			node_client,
			eth_node_client,
			phantom: PhantomData,
		}
	}

	/// For tests doesn't make sense to use any failover
	pub fn new_test(node_client: Arc<C>, eth_node_client: Arc<Mutex<E>>) -> Self {
		Self {
			secondary_currency: Currency::Ether,
			node_client,
			eth_node_client,
			phantom: PhantomData,
		}
	}

	/// Clone instance
	pub fn clone(&self) -> Self {
		Self {
			secondary_currency: self.secondary_currency.clone(),
			node_client: self.node_client.clone(),
			eth_node_client: self.eth_node_client.clone(),
			phantom: PhantomData,
		}
	}

	/// Get Eth Chain Height.
	pub(crate) fn eth_height(&self) -> Result<u64, ErrorKind> {
		let c = self.eth_node_client.lock();
		c.height()
	}

	/// Check ETH amount at the chain.
	pub(crate) fn eth_swap_details(
		&self,
		swap: &Swap,
		address_from_secret: Option<Address>,
	) -> Result<(u64, Option<Address>, Address, Address, u64), ErrorKind> {
		if address_from_secret.is_none() {
			return Err(ErrorKind::InvalidEthSwapTradeIndex);
		}

		let c = self.eth_node_client.lock();
		let res = c.get_swap_details(swap.secondary_currency, address_from_secret.unwrap());
		match res {
			Ok((_refund_time, _contract_address, _initiator, _participant, _value)) => res,
			_ => Err(ErrorKind::InvalidEthSwapTradeIndex),
		}
	}

	/// Seller call contract function to redeem their Ethers, Status::Redeem
	fn seller_post_redeem_tx<K: Keychain>(
		&self,
		keychain: &K,
		swap: &Swap,
	) -> Result<H256, ErrorKind> {
		let c = self.eth_node_client.lock();
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let redeem_secret = SellApi::calculate_redeem_secret(keychain, swap)?;
		let secret_key: secp256k1::SecretKey =
			secp256k1::SecretKey::from_slice(&redeem_secret.0).unwrap();
		c.redeem(
			swap.secondary_currency,
			eth_data.address_from_secret.clone().unwrap(),
			secret_key,
			swap.secondary_fee,
		)
	}

	/// Seller transfer eth from internal wallet to users' wallet
	fn seller_transfer_secondary(&self, swap: &Swap) -> Result<H256, ErrorKind> {
		let c = self.eth_node_client.lock();
		let address = swap.unwrap_seller().unwrap().0;
		c.transfer(
			swap.secondary_currency,
			to_eth_address(address).unwrap(),
			swap.secondary_amount,
		)
	}

	/// buyer call contract function to refund their Ethers
	fn buyer_refund<K: Keychain>(
		&self,
		_keychain: &K,
		_context: &Context,
		swap: &mut Swap,
		_post_tx: bool,
	) -> Result<H256, ErrorKind> {
		let c = self.eth_node_client.lock();
		let eth_data = swap.secondary_data.unwrap_eth()?;
		c.refund(
			swap.secondary_currency,
			eth_data.address_from_secret.clone().unwrap(),
			swap.secondary_fee,
		)
	}

	/// buyer deposit eth to contract address
	fn erc20_approve(&self, swap: &mut Swap) -> Result<H256, ErrorKind> {
		let nc = self.eth_node_client.lock();
		nc.erc20_approve(
			swap.secondary_currency,
			swap.secondary_amount,
			swap.secondary_fee,
		)
	}

	/// buyer deposit eth to contract address
	fn buyer_deposit(&self, swap: &mut Swap) -> Result<H256, ErrorKind> {
		let eth_lock_time = swap.get_time_secondary_lock_script() as u64;
		// Don't lock for more than 4 weeks. 4 weeks + 2 day, because max locking is expecting 2 weeks and 1 day to do the swap and 1 extra day for Buyer
		if eth_lock_time > (swap::get_cur_time() + 3600 * 24 * (7 * 4 + 2)) as u64 {
			return Err(ErrorKind::Generic(
				"ETH locking time interval is larger than 4 weeks. Rejecting, looks like a scam."
					.to_string(),
			));
		}

		if eth_lock_time >= u32::MAX as u64 {
			return Err(ErrorKind::Generic(
				"ETH locking time is out of range. Rejecting, looks like a scam.".to_string(),
			));
		}

		let refund_blocks = (eth_lock_time - swap::get_cur_time() as u64)
			/ swap.secondary_currency.block_time_period_sec() as u64;
		println!(
			"eth_lock_time: {},  current_time: {}, refund_blocks: {}",
			eth_lock_time,
			swap::get_cur_time(),
			refund_blocks
		);
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let height = self.eth_height()?;
		let refund_time = height + refund_blocks;
		println!("height: {}, refund_time: {}", height, refund_time);
		let address_from_secret = eth_data.address_from_secret.clone().unwrap();
		let participant = eth_data.redeem_address.clone().unwrap();
		let value = swap.secondary_amount;

		let nc = self.eth_node_client.lock();
		nc.initiate(
			swap.secondary_currency,
			refund_time,
			address_from_secret,
			participant,
			value,
			swap.secondary_fee,
		)
	}

	fn get_slate_confirmation_number(
		&self,
		mwc_tip: &u64,
		slate: &Slate,
		outputs_ok: bool,
	) -> Result<Option<u64>, ErrorKind> {
		let result: Option<u64> = if slate.tx_or_err()?.kernels().is_empty() {
			None
		} else {
			debug_assert!(slate.tx_or_err()?.kernels().len() == 1);

			let kernel = &slate.tx_or_err()?.kernels()[0].excess;
			if kernel.0.to_vec().iter().any(|v| *v != 0) {
				// kernel is non zero - we can check transaction by kernel
				match self
					.node_client
					.get_kernel(kernel, Some(slate.height), None)?
				{
					Some((_tx_kernel, height, _mmr_index)) => {
						Some(mwc_tip.saturating_sub(height) + 1)
					}
					None => None,
				}
			} else {
				if outputs_ok {
					// kernel is not valid, still can use outputs.
					let wallet_outputs: Vec<pedersen::Commitment> =
						slate.tx_or_err()?.outputs_committed();
					let res = self.node_client.get_outputs_from_node(&wallet_outputs)?;
					let height = res.values().map(|v| v.1).max();
					match height {
						Some(h) => Some(mwc_tip.saturating_sub(h) + 1),
						None => None,
					}
				} else {
					None
				}
			}
		};
		Ok(result)
	}

	/// Check transaction confirm status
	pub(crate) fn check_eth_transaction_status(
		&self,
		tx_id: Option<H256>,
	) -> Result<u64, ErrorKind> {
		if tx_id.is_none() {
			return Err(ErrorKind::InvalidTxHash);
		}

		let c = self.eth_node_client.lock();
		let res = c.retrieve_receipt(tx_id.unwrap());
		match res {
			Ok(receipt) => match receipt.block_number {
				Some(_block_number) => match receipt.status {
					Some(status) => {
						if status == 1.into() {
							Ok(1)
						} else {
							Ok(0)
						}
					}
					_ => Ok(0),
				},
				_ => Err(ErrorKind::EthTransactionInPending),
			},
			_ => Err(ErrorKind::EthRetrieveTransReciptError),
		}
	}

	/// check deposit transaction status
	fn get_eth_initiate_tx_status(&self, swap: &Swap) -> Result<u64, ErrorKind> {
		let eth_data = swap.secondary_data.unwrap_eth()?;
		let eth_tip = self.eth_height()?;
		match self.eth_swap_details(swap, eth_data.address_from_secret.clone()) {
			Ok((refund_time, erc20_token_addr, _, participant, value)) => {
				if swap.secondary_currency.is_erc20() {
					if erc20_token_addr.is_none() {
						return Ok(0);
					} else {
						if swap.secondary_currency.erc20_token_address()?
							!= erc20_token_addr.unwrap()
						{
							return Ok(0);
						}
					}
				}

				if (eth_data.redeem_address.clone().unwrap() == participant)
				&& (refund_time > eth_tip + 100u64) //100 about 25 minutes, make sure we have enough time to redeem ether
				&& value == swap.secondary_amount
				&& swap.redeem_public.is_some()
				{
					let public_key = swap.redeem_public.clone().unwrap();
					// convert mwc public key to ethereum public key format
					let pub_key_array = public_key.0 .0;
					let first_part: Vec<u8> = pub_key_array[..pub_key_array.len() / 2]
						.to_owned()
						.iter()
						.rev()
						.cloned()
						.collect();
					let second_part: Vec<u8> = pub_key_array[pub_key_array.len() / 2..]
						.to_owned()
						.iter()
						.rev()
						.cloned()
						.collect();
					let pub_key_vec: Vec<u8> = first_part
						.into_iter()
						.chain(second_part.into_iter())
						.collect();
					let wallet =
						EthereumWallet::from_public_key(to_hex(&pub_key_vec).as_str()).unwrap();
					let address = to_eth_address(wallet.address.clone().unwrap()).unwrap();
					if eth_data.address_from_secret.unwrap() == address {
						Ok(value)
					} else {
						Ok(0)
					}
				} else {
					Ok(0)
				}
			}
			_ => Ok(0),
		}
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
	) -> Result<usize, ErrorKind> {
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
			_ => return Err(ErrorKind::UnexpectedCoinType),
		}
	}

	fn create_context(
		&mut self,
		keychain: &K,
		ethereum_wallet: Option<&EthereumWallet>,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>,
		change_amount: u64,
		keys: Vec<Identifier>,
		parent_key_id: Identifier,
	) -> Result<Context, ErrorKind> {
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
			_ => return Err(ErrorKind::UnexpectedCoinType),
		}

		let secp = keychain.secp();
		let mut keys = keys.into_iter();
		let role_context = if is_seller {
			let eth_address = to_eth_address(ethereum_wallet.unwrap().address.clone().unwrap())?;
			RoleContext::Seller(SellerContext {
				parent_key_id: parent_key_id,
				inputs: inputs.ok_or(ErrorKind::UnexpectedRole(
					"Fn create_context() for seller not found inputs".to_string(),
				))?,
				change_output: keys.next().unwrap(),
				change_amount,
				refund_output: keys.next().unwrap(),
				secondary_context: SecondarySellerContext::Eth(EthSellerContext {
					redeem_address: Some(eth_address),
				}),
			})
		} else {
			let output = keys.next().unwrap();
			let redeem = keys.next().unwrap();
			let sec_key = keychain
				.derive_key(0, &redeem, SwitchCommitmentType::None)
				.unwrap();
			let eth_rand_wallet =
				EthereumWallet::from_private_key(to_hex(&sec_key.0).as_str()).unwrap();
			let eth_address = to_eth_address(eth_rand_wallet.address.clone().unwrap())?;
			RoleContext::Buyer(BuyerContext {
				parent_key_id: parent_key_id,
				output,
				redeem,
				secondary_context: SecondaryBuyerContext::Eth(EthBuyerContext {
					address_from_secret: Some(eth_address),
				}),
			})
		};

		Ok(Context {
			multisig_key: keys.next().unwrap(),
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
		keychain: &K,
		context: &Context,
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
	) -> Result<Swap, ErrorKind> {
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
			_ => return Err(ErrorKind::UnexpectedCoinType),
		}

		let height = self.node_client.get_chain_tip()?.0;
		let mut swap = SellApi::create_swap_offer(
			keychain,
			context,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_redeem_address,
			height,
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
	) -> SecondaryUpdate {
		let eth_data = swap
			.secondary_data
			.unwrap_eth()
			.expect("Secondary data of unexpected type");
		SecondaryUpdate::ETH(eth_data.offer_update())
	}

	/// Build secondary update part of the accept offer message
	fn build_accept_offer_message_secondary_update(
		&self,
		_keychain: &K, // To make compiler happy
		swap: &mut Swap,
	) -> SecondaryUpdate {
		let eth_data = swap
			.secondary_data
			.unwrap_eth()
			.expect("Secondary data of unexpected type");
		SecondaryUpdate::ETH(eth_data.accept_offer_update())
	}

	fn publish_secondary_transaction(
		&self,
		keychain: &K,
		swap: &mut Swap,
		_context: &Context,
		_post_tx: bool,
	) -> Result<(), ErrorKind> {
		assert!(swap.is_seller());
		let eth_data = swap.secondary_data.unwrap_eth()?;
		if eth_data.redeem_tx.is_some() {
			let status = self.check_eth_transaction_status(eth_data.redeem_tx)?;
			if status == 1 {
				return Ok(());
			}
		}

		let eth_tx = self.seller_post_redeem_tx(keychain, swap)?;
		let eth_data = swap.secondary_data.unwrap_eth_mut()?;
		eth_data.redeem_tx = Some(eth_tx);
		eth_data.tx_fee = Some(swap.secondary_fee);
		Ok(())
	}

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&self,
		_keychain: &K, // keychain is kept for Type. Compiler need to understand all types
		swap: &Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind> {
		let mwc_tip = self.node_client.get_chain_tip()?.0;

		let is_seller = swap.is_seller();

		let mwc_lock_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.lock_slate, !is_seller)?;
		let mwc_redeem_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.redeem_slate, is_seller)?;
		let mwc_refund_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.refund_slate, !is_seller)?;

		let secondary_tip = self.eth_height()?;
		// check eth transaction status
		let secondary_lock_amount = self.get_eth_initiate_tx_status(swap)?;
		let secondary_lock_conf = match secondary_lock_amount > 0 {
			true => Some(1),
			_ => None,
		};

		let eth_data = swap.secondary_data.unwrap_eth()?;
		let secondary_redeem_conf = match self.check_eth_transaction_status(eth_data.redeem_tx) {
			Ok(status) => {
				if status == 0 {
					None
				} else {
					Some(1)
				}
			}
			_ => None,
		};
		let secondary_refund_conf = match self.check_eth_transaction_status(eth_data.refund_tx) {
			Ok(status) => {
				if status == 0 {
					None
				} else {
					Some(1)
				}
			}
			_ => None,
		};

		Ok(SwapTransactionsConfirmations {
			mwc_tip,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
			secondary_tip,
			secondary_lock_conf,
			secondary_lock_amount,
			secondary_redeem_conf,
			secondary_refund_conf,
		})
	}

	/// Check How much ETH coins are locked on the chain
	/// Return output with at least 1 confirmations because it is needed for refunds or redeems. Both party want to take everything
	/// Return: (<pending_amount>, <confirmed_amount>, <least_confirmations>)
	fn request_secondary_lock_balance(
		&self,
		swap: &Swap,
		_confirmations_needed: u64,
		_secp: &Secp256k1,
	) -> Result<(u64, u64, u64), ErrorKind> {
		// check eth transaction status
		let amount = self.get_eth_initiate_tx_status(swap)?;
		Ok((0, amount, 0))
	}

	// Build state machine that match the swap data
	fn get_fsm(&self, keychain: &K, swap: &Swap) -> StateMachine {
		let kc = Arc::new(keychain.clone());
		let nc = self.node_client.clone();
		let b: Box<dyn SwapApi<K> + 'a> = Box::new((*self).clone());
		let swap_api = Arc::new(b);

		if swap.is_seller() {
			StateMachine::new(vec![
				Box::new(seller_swap::SellerOfferCreated::new()),
				Box::new(seller_swap::SellerSendingOffer::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForAcceptanceMessage::new(
					kc.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForBuyerLock::new(
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerPostingLockMwcSlate::new(nc.clone())),
				Box::new(seller_swap::SellerWaitingForLockConfirmations::new(
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForInitRedeemMessage::new(
					kc.clone(),
				)),
				Box::new(seller_swap::SellerSendingInitRedeemMessage::new(nc.clone())),
				Box::new(seller_swap::SellerWaitingForBuyerToRedeemMwc::new(
					nc.clone(),
				)),
				Box::new(seller_swap::SellerRedeemSecondaryCurrency::new(
					kc.clone(),
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerWaitingForRedeemConfirmations::new(
					nc.clone(),
					swap_api.clone(),
				)),
				Box::new(seller_swap::SellerSwapComplete::new()),
				Box::new(seller_swap::SellerWaitingForRefundHeight::new(nc.clone())),
				Box::new(seller_swap::SellerPostingRefundSlate::new(nc.clone())),
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
					kc.clone(),
					swap_api.clone(),
				)),
				Box::new(buyer_swap::BuyerSendingInitRedeemMessage::new()),
				Box::new(buyer_swap::BuyerWaitingForRespondRedeemMessage::new(
					kc.clone(),
				)),
				Box::new(buyer_swap::BuyerRedeemMwc::new(nc.clone())),
				Box::new(buyer_swap::BuyerWaitForRedeemMwcConfirmations::new()),
				Box::new(buyer_swap::BuyerSwapComplete::new()),
				Box::new(buyer_swap::BuyerWaitingForRefundTime::new()),
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
	fn get_secondary_lock_address(&self, swap: &Swap, _secp: &Secp256k1) -> Result<Vec<String>, ErrorKind> {
		let eth_data = swap.secondary_data.unwrap_eth()?;

		match eth_data.address_from_secret {
			Some(address) => Ok(vec![eth_address(address)]),
			_ => Ok(vec!["".to_string()]),
		}
	}

	/// Check if tx fee for the secondary is different from the posted
	fn is_secondary_tx_fee_changed(&self, swap: &Swap) -> Result<bool, ErrorKind> {
		Ok(swap.secondary_data.unwrap_eth()?.tx_fee != Some(swap.secondary_fee))
	}

	/// Post ETH refund transaction
	fn post_secondary_refund_tx(
		&self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		_refund_address: Option<String>,
		post_tx: bool,
	) -> Result<(), ErrorKind> {
		assert!(!swap.is_seller());
		let eth_data = swap.secondary_data.unwrap_eth()?;

		if eth_data.refund_tx.is_some() {
			let status = self.check_eth_transaction_status(eth_data.refund_tx)?;
			if status == 1 {
				return Ok(());
			}
		}

		let eth_tx = self.buyer_refund(keychain, context, swap, post_tx)?;
		let eth_data = swap.secondary_data.unwrap_eth_mut()?;
		eth_data.refund_tx = Some(eth_tx);
		eth_data.tx_fee = Some(swap.secondary_fee);

		Ok(())
	}

	/// deposit secondary currecny to lock account.
	fn post_secondary_lock_tx(&self, swap: &mut Swap) -> Result<(), ErrorKind> {
		assert!(!swap.is_seller());
		let eth_data = swap.secondary_data.unwrap_eth()?;

		if eth_data.lock_tx.is_some() {
			let status = self.check_eth_transaction_status(eth_data.lock_tx)?;
			if status == 1 {
				return Ok(());
			}
		}

		if swap.secondary_currency.is_erc20() {
			if eth_data.erc20_approve_tx.is_some() {
				let approve_status =
					self.check_eth_transaction_status(eth_data.erc20_approve_tx)?;
				if approve_status == 1 {
					let eth_tx = self.buyer_deposit(swap)?;
					let eth_data = swap.secondary_data.unwrap_eth_mut()?;
					eth_data.lock_tx = Some(eth_tx);
				} else {
					return Err(ErrorKind::EthERC20TokenApproveError);
				}
			} else {
				let erc20_approve_tx = self.erc20_approve(swap)?;
				let eth_data = swap.secondary_data.unwrap_eth_mut()?;
				eth_data.erc20_approve_tx = Some(erc20_approve_tx);
			}
		} else {
			let eth_tx = self.buyer_deposit(swap)?;
			let eth_data = swap.secondary_data.unwrap_eth_mut()?;
			eth_data.lock_tx = Some(eth_tx);
		}

		Ok(())
	}

	/// transfer amount to dedicated address.
	fn transfer_scondary(&self, swap: &mut Swap) -> Result<(), ErrorKind> {
		assert!(swap.is_seller());

		self.seller_transfer_secondary(swap)?;
		Ok(())
	}

	fn test_client_connections(&self) -> Result<(), ErrorKind> {
		{
			let c = self.eth_node_client.lock();
			let name = c.name();
			let _ = c.height().map_err(|e| {
				ErrorKind::InfuraNodeClient(format!(
					"Unable to contact Ethereum client {}, {}",
					name, e
				))
			})?;
		}
		Ok(())
	}
}
