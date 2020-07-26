// Copyright 2020 The MWC Developers
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

// Sell swap happy path states

use crate::swap::bitcoin::{BtcNodeClient, BtcSwapApi};
use crate::swap::fsm::state::{Input, State, StateId, StateProcessRespond};
use crate::swap::message::Message;
use crate::swap::types::{Action, SwapTransactionsConfirmations};
use crate::swap::{swap, Context, ErrorKind, SellApi, Swap, SwapApi};
use crate::NodeClient;
use failure::_core::marker::PhantomData;
use grin_keychain::Keychain;
use std::sync::Arc;

/*
// Print how much time left from the time limit
fn left_from_time_limit(time_limit: u64) -> String {
	let left_sec = time_limit as i64 - Utc::now().timestamp();
	if left_sec <= 0 {
		"time is over".to_string()
	}
	else {
		if left_sec > 3600 {
			format!("{} hours {} minutes left", left_sec/3600, (left_sec%3600)/60)
		}
		else if left_sec>60 {
			format!("{} minutes left", left_sec/60)
		}
		else {
			format!("{} seconds left", left_sec)
		}
	}
}*/

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerOfferCreated
pub struct SellerOfferCreated {}
impl SellerOfferCreated {
	/// create a new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for SellerOfferCreated {
	fn get_state_id(&self) -> StateId {
		StateId::SellerOfferCreated
	}
	fn get_name(&self) -> String {
		"Offer Created".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerSendingOffer)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerOfferCreated get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerSendingOffer)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerSendingOffer
pub struct SellerSendingOffer<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	message: Option<Message>,
	phantom: PhantomData<&'a C>,
}
impl<'a, C, B, K> SellerSendingOffer<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create new instance
	pub fn new(keychain: Arc<K>, swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			keychain,
			swap_api,
			phantom: PhantomData,
			message: None,
		}
	}
}
impl<'a, C, B, K> State for SellerSendingOffer<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerSendingOffer
	}
	fn get_name(&self) -> String {
		"Sending Offer".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			Input::Check => {
				if swap.message1.is_none() {
					let time_limit = swap.get_time_message_offers();
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							let sec_update = self
								.swap_api
								.build_offer_message_secondary_update(&*self.keychain, swap);
							self.message = Some(SellApi::offer_message(swap, sec_update)?);
						}
						Ok(StateProcessRespond::new(StateId::SellerSendingOffer)
							.action(Action::SellerSendOfferMessage(
								self.message.clone().unwrap(),
							))
							.time_limit(time_limit))
					} else {
						Ok(StateProcessRespond::new(StateId::SellerCancelled))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForAcceptanceMessage,
					))
				}
			}
			Input::Execute {
				refund_address: _,
				fee_satoshi_per_byte: _,
			} => {
				debug_assert!(swap.message1.is_none());
				debug_assert!(self.message.is_some()); // Check expected to be called first
				swap.message1 = Some(self.message.clone().unwrap());

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForAcceptanceMessage,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerSendingOffer get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerOfferCreated)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForAcceptanceMessage)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerWaitingForAcceptanceMessage
pub struct SellerWaitingForAcceptanceMessage<K: Keychain> {
	keychain: Arc<K>,
}
impl<K: Keychain> SellerWaitingForAcceptanceMessage<K> {
	/// Create new instance
	pub fn new(keychain: Arc<K>) -> Self {
		Self { keychain }
	}
}
impl<K: Keychain> State for SellerWaitingForAcceptanceMessage<K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForAcceptanceMessage
	}
	fn get_name(&self) -> String {
		"Waiting For Buyer to accept the offer".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			Input::Check => {
				if swap.redeem_public.is_none() {
					let time_limit = swap.get_time_message_offers();
					if swap::get_cur_time() < time_limit {
						Ok(
							StateProcessRespond::new(StateId::SellerWaitingForAcceptanceMessage)
								.action(Action::SellerWaitingForOfferMessage)
								.time_limit(time_limit),
						)
					} else {
						// cancelling
						Ok(StateProcessRespond::new(StateId::SellerCancelled))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock))
				}
			}
			Input::IncomeMessage(message) => {
				debug_assert!(swap.redeem_public.is_none());
				let (_, accept_offer, secondary_update) = message.unwrap_accept_offer()?;
				let btc_update = secondary_update.unwrap_btc()?.unwrap_accept_offer()?;

				SellApi::accepted_offer(&*self.keychain, swap, context, accept_offer)?;
				let btc_data = swap.secondary_data.unwrap_btc_mut()?;
				btc_data.accepted_offer(btc_update)?;
				debug_assert!(swap.redeem_public.is_some());
				Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForAcceptanceMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerSendingOffer)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForBuyerLock)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// SellerWaitingForBuyerLock state
pub struct SellerWaitingForBuyerLock {}
impl SellerWaitingForBuyerLock {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for SellerWaitingForBuyerLock {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForBuyerLock
	}
	fn get_name(&self) -> String {
		"Waiting For Buyer to start Locking coins".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			Input::Check => {
				// Check the deadline for locking
				let time_limit = swap.get_time_start_lock();
				if swap::get_cur_time() > time_limit {
					// cancelling
					return Ok(StateProcessRespond::new(StateId::SellerCancelled));
				}

				if swap.seller_lock_first {
					// Skipping this step. Buyer waiting for us to start locking
					Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
				} else {
					let conf = tx_conf.secondary_lock_conf.unwrap_or(0);

					if conf < 1 {
						Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock)
							.action(Action::WaitForSecondaryConfirmations {
								name: "Buyer to lock funds".to_string(),
								currency: swap.secondary_currency,
								required: 1,
								actual: conf,
							})
							.time_limit(time_limit))
					} else {
						Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
					}
				}
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForBuyerLock get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForAcceptanceMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerPostingLockMwcSlate)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerPostingLockMwcSlate
pub struct SellerPostingLockMwcSlate<'a, C, B>
where
	C: NodeClient,
	B: BtcNodeClient,
{
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C, B> SellerPostingLockMwcSlate<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create an instance
	pub fn new(swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B> State for SellerPostingLockMwcSlate<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerPostingLockMwcSlate
	}
	fn get_name(&self) -> String {
		"Posting MWC Lock Slate".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		let time_limit = swap.get_time_start_lock();
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(StateId::SellerCancelled)), // Locking is not done yet, we can cancel easy way
			Input::Check => {
				// Check if mwc lock is already done
				if tx_conf.mwc_lock_conf.is_some() {
					// Going to the next step... MWC lock is already published.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					));
				}

				// Check the deadline for locking
				if swap::get_cur_time() > time_limit {
					// cancelling because of timeout
					return Ok(StateProcessRespond::new(StateId::SellerCancelled));
				}

				Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate)
					.action(Action::SellerPublishMwcLockTx)
					.time_limit(time_limit))
			}
			Input::Execute {
				refund_address: _,
				fee_satoshi_per_byte: _,
			} => {
				// Executing the MWC lock transaction
				if swap::get_cur_time() > time_limit {
					// cancelling because of timeout. The last Chance to cancel easy way.
					return Ok(StateProcessRespond::new(StateId::SellerCancelled));
				}
				// Posting the transaction
				swap::publish_transaction(&*self.swap_api.node_client, &swap.lock_slate.tx, false)?;
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForLockConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerPostingLockMwcSlate get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForBuyerLock)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForLockConfirmations)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerWaitingForLockConfirmations
pub struct SellerWaitingForLockConfirmations {}
impl SellerWaitingForLockConfirmations {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for SellerWaitingForLockConfirmations {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForLockConfirmations
	}
	fn get_name(&self) -> String {
		"Waiting for Locking funds confirmations".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(
				StateId::SellerWaitingForRefundHeight,
			)), // Long cancellation path
			Input::Check => {
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);

				let time_limit = swap.get_time_message_redeem();

				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					// Checking for a deadline. Note time_message_redeem is fine, we can borrow time from that operation and still be safe
					if swap::get_cur_time() > time_limit {
						// cancelling because of timeout
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRefundHeight,
						));
					}
				}

				// Waiting for own funds first. For seller it is MWC
				if mwc_lock < swap.mwc_confirmations {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					)
					.action(Action::WaitForMwcConfirmations {
						name: "MWC Lock transaction".to_string(),
						required: swap.mwc_confirmations,
						actual: mwc_lock,
					})
					.time_limit(time_limit));
				}

				if secondary_lock < swap.secondary_confirmations {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					)
					.action(Action::WaitForSecondaryConfirmations {
						name: format!("{} Locking Account", swap.secondary_currency),
						currency: swap.secondary_currency,
						required: swap.secondary_confirmations,
						actual: secondary_lock,
					})
					.time_limit(time_limit));
				}

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForInitRedeemMessage,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForLockConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerPostingLockMwcSlate)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForInitRedeemMessage)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

/// SellerWaitingForInitRedeemMessage
pub struct SellerWaitingForInitRedeemMessage<K: Keychain> {
	keychain: Arc<K>,
}
impl<K: Keychain> SellerWaitingForInitRedeemMessage<K> {
	/// Create an instance
	pub fn new(keychain: Arc<K>) -> Self {
		Self { keychain }
	}
}
impl<K: Keychain> State for SellerWaitingForInitRedeemMessage<K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForInitRedeemMessage
	}
	fn get_name(&self) -> String {
		"Waiting For Init Redeem message from the Buyer".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(
				StateId::SellerWaitingForRefundHeight,
			)),
			Input::Check => {
				if swap.adaptor_signature.is_some() {
					// Was already processed. Can go to the next step
					return Ok(StateProcessRespond::new(
						StateId::SellerSendingInitRedeemMessage,
					));
				}

				let time_limit = swap.get_time_message_redeem();
				if swap::get_cur_time() < time_limit {
					Ok(
						StateProcessRespond::new(StateId::SellerWaitingForInitRedeemMessage)
							.action(Action::SellerWaitingForInitRedeemMessage)
							.time_limit(time_limit),
					)
				} else {
					// cancelling
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					))
				}
			}
			Input::IncomeMessage(message) => {
				debug_assert!(swap.adaptor_signature.is_none());
				let (_, init_redeem, _) = message.unwrap_init_redeem()?;
				SellApi::init_redeem(&*self.keychain, swap, context, init_redeem)?;
				debug_assert!(swap.adaptor_signature.is_some());
				Ok(StateProcessRespond::new(
					StateId::SellerSendingInitRedeemMessage,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForInitRedeemMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForLockConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerSendingInitRedeemMessage)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerSendingInitRedeemMessage
pub struct SellerSendingInitRedeemMessage {
	message: Option<Message>,
}
impl SellerSendingInitRedeemMessage {
	/// Create in instance
	pub fn new() -> Self {
		Self { message: None }
	}
}
impl State for SellerSendingInitRedeemMessage {
	fn get_state_id(&self) -> StateId {
		StateId::SellerSendingInitRedeemMessage
	}
	fn get_name(&self) -> String {
		"Sending Redeem Message".to_string()
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => Ok(StateProcessRespond::new(
				StateId::SellerWaitingForRefundHeight,
			)), // Last chance to quit
			Input::Check => {
				if swap.message2.is_none() {
					let time_limit = swap.get_time_message_redeem();
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = Some(SellApi::redeem_message(swap)?);
						}
						Ok(
							StateProcessRespond::new(StateId::SellerSendingInitRedeemMessage)
								.action(Action::SellerSendRedeemMessage(
									self.message.clone().unwrap(),
								))
								.time_limit(time_limit),
						)
					} else {
						Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRefundHeight,
						))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForAcceptanceMessage,
					))
				}
			}
			Input::Execute {
				refund_address: _,
				fee_satoshi_per_byte: _,
			} => {
				debug_assert!(swap.message2.is_none());
				debug_assert!(self.message.is_some()); // Check expected to be called first
				swap.message2 = Some(self.message.clone().unwrap());

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForBuyerToRedeemMwc,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerSendingInitRedeemMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForInitRedeemMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForBuyerToRedeemMwc)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Return true if mwc redeemed by Buyer. So we are good to claim BTC
fn check_mwc_redeem<C: NodeClient>(swap: &mut Swap, node_client: &C) -> Result<bool, ErrorKind> {
	// Trying to find redeem
	if let Some((kernel, _h)) = swap.find_redeem_kernel(node_client)? {
		// Replace kernel
		let _ = std::mem::replace(
			swap.redeem_slate
				.tx
				.kernels_mut()
				.get_mut(0)
				.ok_or(ErrorKind::UnexpectedAction(
					"Seller Fn required_action() redeem slate not initialized, kernels are empty"
						.to_string(),
				))?,
			kernel,
		);
		return Ok(true);
	}
	Ok(false)
}

/// State SellerWaitingForBuyerToRedeemMwc
pub struct SellerWaitingForBuyerToRedeemMwc<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C, B> SellerWaitingForBuyerToRedeemMwc<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create a new instance
	pub fn new(swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B> State for SellerWaitingForBuyerToRedeemMwc<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForBuyerToRedeemMwc
	}
	fn get_name(&self) -> String {
		"Waiting For Buyer redeem MWC".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Check the deadline for locking
				//
				let (height, _, _) = self.swap_api.node_client.get_chain_tip()?;
				if height > swap.refund_slate.lock_height {
					info!("Waiting too long for the Buyer to redeem, time to get refund.");
					// Time to to get my MWC back with a refund.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					));
				}

				if check_mwc_redeem(swap, &*self.swap_api.node_client)? {
					// Buyer did a redeem, we can continue processing and redeem BTC
					return Ok(StateProcessRespond::new(
						StateId::SellerRedeemSecondaryCurrency,
					));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForBuyerToRedeemMwc)
						.action(Action::SellerWaitForBuyerRedeemPublish {
							mwc_tip: height,
							lock_height: swap.lock_slate.lock_height,
						})
						.time_limit(
							swap::get_cur_time()
								+ (swap.lock_slate.lock_height.saturating_sub(height) * 60) as i64,
						),
				)
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForBuyerToRedeemMwc get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerSendingInitRedeemMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerRedeemSecondaryCurrency)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Greedy approach, check the deadline for locking
// It is fair because that code will work only of Buyer delay a lot the redeeming on MWC transaction.
// One of the reasons to delay is attack.
fn post_refund_if_possible<'a, C: NodeClient + 'a, B: BtcNodeClient + 'a>(
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	swap: &Swap,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<(), ErrorKind> {
	let (height, _, _) = swap_api.node_client.get_chain_tip()?;
	if height > swap.refund_slate.lock_height && tx_conf.mwc_refund_conf.is_none() {
		let res = swap::publish_transaction(&*swap_api.node_client, &swap.refund_slate.tx, false);
		if let Err(e) = res {
			info!("MWC refund can be issued even likely it will fail. Trying to post it. get an error {}", e);
		} else {
			info!("MWC refund can be was issued, even it was expected to fail");
		}
	}
	Ok(())
}

/// State SellerRedeemSecondaryCurrency
pub struct SellerRedeemSecondaryCurrency<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C, B, K> SellerRedeemSecondaryCurrency<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new instance
	pub fn new(keychain: Arc<K>, swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			keychain,
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B, K> State for SellerRedeemSecondaryCurrency<'a, C, B, K>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerRedeemSecondaryCurrency
	}
	fn get_name(&self) -> String {
		"Posting Secondary Redeem Transaction".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Be greedy, check the deadline for locking
				post_refund_if_possible(self.swap_api.clone(), swap, tx_conf)?;

				if !check_mwc_redeem(swap, &*self.swap_api.node_client)? {
					debug_assert!(false); // That shouldn't happen
					  // Some strange bugs, let's go back to the waiting
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				// Ready to redeem BTC.
				Ok(
					StateProcessRespond::new(StateId::SellerRedeemSecondaryCurrency)
						.action(Action::SellerPublishTxSecondaryRedeem(
							swap.secondary_currency,
						))
						.time_limit(swap.get_time_btc_lock() - swap.get_timeinterval_btc_lock()),
				)
			}
			Input::Execute {
				refund_address: _,
				fee_satoshi_per_byte,
			} => {
				self.swap_api.publish_secondary_transaction(
					&*self.keychain,
					swap,
					context,
					fee_satoshi_per_byte.clone(),
					false,
				)?;
				debug_assert!(swap.secondary_data.unwrap_btc()?.redeem_tx.is_some());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRedeemConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerRedeemSecondaryCurrency get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForBuyerToRedeemMwc)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRedeemConfirmations)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerWaitingForRedeemConfirmations
pub struct SellerWaitingForRedeemConfirmations<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C, B> SellerWaitingForRedeemConfirmations<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create a new instance
	pub fn new(swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B> State for SellerWaitingForRedeemConfirmations<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForRedeemConfirmations
	}
	fn get_name(&self) -> String {
		"Waiting For Redeem Tx Confirmations".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Be greedy, check the deadline for locking
				post_refund_if_possible(self.swap_api.clone(), swap, tx_conf)?;

				// Just waiting
				if let Some(conf) = tx_conf.secondary_redeem_conf {
					if conf >= swap.secondary_confirmations {
						// We are done
						return Ok(StateProcessRespond::new(StateId::SellerSwapComplete));
					}
				}

				return Ok(
					StateProcessRespond::new(StateId::SellerWaitingForRedeemConfirmations).action(
						Action::WaitForSecondaryConfirmations {
							name: "Redeem Transaction".to_string(),
							currency: swap.secondary_currency,
							required: swap.secondary_confirmations,
							actual: tx_conf.secondary_redeem_conf.unwrap_or(0),
						},
					),
				);
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForRedeemConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerRedeemSecondaryCurrency)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerSwapComplete)
	}
}

/////////////////////////////////////////////////////////////////////////////////

/// State SellerSwapComplete
pub struct SellerSwapComplete {}
impl SellerSwapComplete {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for SellerSwapComplete {
	fn get_state_id(&self) -> StateId {
		StateId::SellerSwapComplete
	}
	fn get_name(&self) -> String {
		"Swap is completed sucessufully".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerSwapComplete)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerSwapComplete get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRedeemConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		None
	}
}

///////////////////////////////////////////////////////////////////

/// State SellerCancelled
pub struct SellerCancelled {}
impl SellerCancelled {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for SellerCancelled {
	fn get_state_id(&self) -> StateId {
		StateId::SellerCancelled
	}
	fn get_name(&self) -> String {
		"Swap is cancelled, no funds was locked, no refund needed".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerCancelled get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		None
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
//     Refund workflow
////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerWaitingForRefundHeight
pub struct SellerWaitingForRefundHeight<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C, B> SellerWaitingForRefundHeight<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create a new instance
	pub fn new(swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B> State for SellerWaitingForRefundHeight<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForRefundHeight
	}
	fn get_name(&self) -> String {
		"Waiting for MWC refund to unlock".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => {
				debug_assert!(false);
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundHeight,
				))
			}
			Input::Check => {
				// Check the deadline for locking
				//
				let (height, _, _) = self.swap_api.node_client.get_chain_tip()?;
				if height > swap.lock_slate.lock_height {
					return Ok(StateProcessRespond::new(StateId::SellerPostingRefundSlate));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForBuyerToRedeemMwc).action(
						Action::WaitForMwcRefundUnlock {
							mwc_tip: height,
							lock_height: swap.lock_slate.lock_height,
						},
					),
				)
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForRefundHeight get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerPostingRefundSlate)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerPostingRefundSlate
pub struct SellerPostingRefundSlate<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	swap_api: Arc<BtcSwapApi<'a, C, B>>,
	phantom: PhantomData<&'a C>,
}
impl<'a, C, B> SellerPostingRefundSlate<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	/// Create a new instance
	pub fn new(swap_api: Arc<BtcSwapApi<'a, C, B>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, B> State for SellerPostingRefundSlate<'a, C, B>
where
	C: NodeClient + 'a,
	B: BtcNodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerPostingRefundSlate
	}
	fn get_name(&self) -> String {
		"Posting MWC Refund Slate".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Check if mwc lock is already done
				if tx_conf.mwc_refund_conf.is_some() {
					// already published.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundConfirmations,
					));
				}

				Ok(StateProcessRespond::new(StateId::SellerPostingRefundSlate)
					.action(Action::SellerPublishMwcRefundTx))
			}
			Input::Execute {
				refund_address: _,
				fee_satoshi_per_byte: _,
			} => {
				// Executing the MWC lock transaction
				// Posting the transaction
				debug_assert!(tx_conf.mwc_refund_conf.is_none());
				swap::publish_transaction(
					&*self.swap_api.node_client,
					&swap.refund_slate.tx,
					false,
				)?;
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerPostingRefundSlate get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRefundHeight)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRefundConfirmations)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerWaitingForRefundConfirmations
pub struct SellerWaitingForRefundConfirmations {}
impl SellerWaitingForRefundConfirmations {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for SellerWaitingForRefundConfirmations {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForRefundConfirmations
	}
	fn get_name(&self) -> String {
		"Waiting for MWC Refund confirmations".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Check if mwc lock is already done
				let refund_conf = tx_conf.mwc_refund_conf.unwrap_or(0);
				if refund_conf > swap.mwc_confirmations {
					// already published.
					return Ok(StateProcessRespond::new(StateId::SellerCancelledRefunded));
				}

				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForRefundConfirmations).action(
						Action::WaitForMwcConfirmations {
							name: "MWC Refund".to_string(),
							required: swap.mwc_confirmations,
							actual: refund_conf,
						},
					),
				)
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerWaitingForRefundConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRefundConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerCancelledRefunded)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

/// State SellerCancelledRefunded
pub struct SellerCancelledRefunded {}
impl SellerCancelledRefunded {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for SellerCancelledRefunded {
	fn get_state_id(&self) -> StateId {
		StateId::SellerCancelledRefunded
	}
	fn get_name(&self) -> String {
		"Swap is cancelled, MWC refund is redeemed".to_string()
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerCancelledRefunded)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"SellerCancelled get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::SellerWaitingForRefundConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		None
	}
}