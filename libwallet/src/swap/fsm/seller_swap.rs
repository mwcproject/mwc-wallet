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

use super::state::{
	JOURNAL_CANCELLED_BYER_LOCK_TOO_MUCH_FUNDS, JOURNAL_CANCELLED_BY_TIMEOUT,
	JOURNAL_CANCELLED_BY_USER, JOURNAL_NOT_LOCKED,
};
use crate::swap::fsm::state::{Input, State, StateEtaInfo, StateId, StateProcessRespond};
use crate::swap::message::Message;
use crate::swap::types::{Action, SwapTransactionsConfirmations};
use crate::swap::{swap, Context, ErrorKind, SellApi, Swap, SwapApi};
use crate::NodeClient;
use chrono::{Local, TimeZone};
use failure::_core::marker::PhantomData;
use grin_keychain::Keychain;
use std::sync::Arc;

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
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		let dt = Local.timestamp(swap.started.timestamp(), 0);
		let time_str = dt.format("%B %e %H:%M:%S").to_string();
		Some(StateEtaInfo::new(&format!("Offer Created at {}", time_str)))
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
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
pub struct SellerSendingOffer<'a, K>
where
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	message: Option<Message>,
	phantom: PhantomData<&'a K>,
}
impl<'a, K> SellerSendingOffer<'a, K>
where
	K: Keychain + 'a,
{
	/// Create new instance
	pub fn new(keychain: Arc<K>, swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			keychain,
			swap_api,
			phantom: PhantomData,
			message: None,
		}
	}
}
impl<'a, K> State for SellerSendingOffer<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerSendingOffer
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Sending Offer to Buyer").end_time(swap.get_time_message_offers()))
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					let time_limit = swap.get_time_message_offers();
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = swap.message1.clone();
						}
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
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						Ok(StateProcessRespond::new(StateId::SellerCancelled))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForAcceptanceMessage,
					))
				}
			}
			Input::Execute => {
				debug_assert!(self.message.is_some()); // Check expected to be called first
				if swap.message1.is_none() {
					swap.message1 = Some(self.message.clone().unwrap());
				}
				swap.posted_msg1 = Some(swap::get_cur_time());

				swap.add_journal_message("Offer message was sent".to_string());
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
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Waiting For Buyer to accept the offer")
				.end_time(swap.get_time_message_offers()),
		)
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				if swap.redeem_public.is_none() {
					let time_limit = swap.get_time_message_offers();
					if swap::get_cur_time() < time_limit {
						// Check if we need to retry to send the message
						if swap.posted_msg1.unwrap_or(0)
							< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
						{
							return Ok(StateProcessRespond::new(StateId::SellerSendingOffer));
						}
						Ok(
							StateProcessRespond::new(StateId::SellerWaitingForAcceptanceMessage)
								.action(Action::SellerWaitingForOfferMessage)
								.time_limit(time_limit),
						)
					} else {
						// cancelling
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						Ok(StateProcessRespond::new(StateId::SellerCancelled))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock))
				}
			}
			Input::IncomeMessage(message) => {
				// Double processing should be fine
				if swap.redeem_public.is_none() {
					let (_, accept_offer, secondary_update) = message.unwrap_accept_offer()?;
					let btc_update = secondary_update.unwrap_btc()?.unwrap_accept_offer()?;

					SellApi::accepted_offer(&*self.keychain, swap, context, accept_offer)?;
					let btc_data = swap.secondary_data.unwrap_btc_mut()?;
					btc_data.accepted_offer(btc_update)?;

					swap.add_journal_message("Processed Offer Accept message".to_string());
					swap.ack_msg1(); // Just in case duplicate ack, because we get a respond, so the message was delivered
				}
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
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		if swap.seller_lock_first {
			None
		} else {
			Some(
				StateEtaInfo::new("Waiting For Buyer to start Locking coins")
					.end_time(swap.get_time_start_lock()),
			)
		}
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				// Check the deadline for locking
				let time_limit = swap.get_time_start_lock();
				if swap::get_cur_time() > time_limit {
					// cancelling
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return Ok(StateProcessRespond::new(StateId::SellerCancelled));
				}

				if swap.seller_lock_first {
					// Skipping this step. Buyer waiting for us to start locking
					Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
				} else {
					let mut conf = tx_conf.secondary_lock_conf.unwrap_or(0);
					if tx_conf.secondary_lock_amount < swap.secondary_amount {
						conf = 0;
					}

					if tx_conf.secondary_lock_amount > swap.secondary_amount {
						// Posted too much, byer probably will cancel the deal, we are not going to lock the MWCs
						swap.add_journal_message(format!(
							"Cancelled because buyer locked too much {} funds",
							swap.secondary_currency
						));
						return Ok(StateProcessRespond::new(StateId::SellerCancelled));
					}

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
						swap.add_journal_message("Buyer start locking the funds".to_string());
						Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
					}
				}
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_accept_offer()?;
				Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock))
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
pub struct SellerPostingLockMwcSlate<'a, C>
where
	C: NodeClient + 'a,
{
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> SellerPostingLockMwcSlate<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create an instance
	pub fn new(node_client: Arc<C>) -> Self {
		Self {
			node_client,
			phantom: PhantomData,
		}
	}

	fn generate_cancel_respond(swap: &Swap) -> Result<StateProcessRespond, ErrorKind> {
		if swap.posted_lock.is_none() {
			Ok(StateProcessRespond::new(StateId::SellerCancelled))
		} else {
			// Better to wait for some time. Since it was posted, it can be pablished later by anybody.
			// Let's be ready to refund. We better stuck there.
			Ok(StateProcessRespond::new(
				StateId::SellerWaitingForRefundHeight,
			))
		}
	}
}

impl<'a, C> State for SellerPostingLockMwcSlate<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerPostingLockMwcSlate
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Locking MWC funds").end_time(swap.get_time_start_lock()))
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Self::generate_cancel_respond(swap)
			} // Locking is not done yet, we can cancel easy way
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
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return Self::generate_cancel_respond(swap);
				}

				Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate)
					.action(Action::SellerPublishMwcLockTx)
					.time_limit(time_limit))
			}
			Input::Execute => {
				if tx_conf.mwc_lock_conf.is_some() {
					// Going to the next step... MWC lock is already published.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					));
				}
				// Executing the MWC lock transaction
				if swap::get_cur_time() > time_limit {
					// cancelling because of timeout. The last Chance to cancel easy way.
					return Self::generate_cancel_respond(swap);
				}
				// Posting the transaction
				swap::publish_transaction(&*self.node_client, &swap.lock_slate.tx, false)?;
				swap.posted_lock = Some(swap::get_cur_time());
				swap.add_journal_message("MWC lock slate is posted".to_string());

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForLockConfirmations,
				))
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_accept_offer()?;
				Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
			} /*_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				  "SellerPostingLockMwcSlate get {:?}",
				  input
			  ))),*/
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
pub struct SellerWaitingForLockConfirmations<K: Keychain> {
	keychain: Arc<K>,
}
impl<K: Keychain> SellerWaitingForLockConfirmations<K> {
	/// Create a new instance
	pub fn new(keychain: Arc<K>) -> Self {
		Self { keychain }
	}
}

impl<K: Keychain> State for SellerWaitingForLockConfirmations<K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForLockConfirmations
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Waiting for Lock funds confirmations")
				.end_time(swap.get_time_message_redeem()),
		)
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
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundHeight,
				)) // Long cancellation path
			}
			Input::Check => {
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let mut secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);

				if tx_conf.secondary_lock_amount < swap.secondary_amount {
					secondary_lock = 0;
				}

				if tx_conf.secondary_lock_amount > swap.secondary_amount {
					// Posted too much, bayer probably will cancel the deal, let's be in sync
					swap.add_journal_message(format!(
						"{}. Expected {} {}, but get {} {}",
						JOURNAL_CANCELLED_BYER_LOCK_TOO_MUCH_FUNDS,
						swap.secondary_currency
							.amount_to_hr_string(swap.secondary_amount, true),
						swap.secondary_currency,
						swap.secondary_currency
							.amount_to_hr_string(tx_conf.secondary_lock_amount, true),
						swap.secondary_currency
					));
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					));
				}

				let time_limit = swap.get_time_message_redeem();

				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					// Checking for a deadline. Note time_message_redeem is fine, we can borrow time from that operation and still be safe
					if swap::get_cur_time() > time_limit {
						// cancelling because of timeout
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRefundHeight,
						));
					}

					if mwc_lock == 0
						&& swap.posted_lock.clone().unwrap_or(0)
							< swap::get_cur_time() - super::state::POST_MWC_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate));
					}

					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					)
					.action(Action::WaitForLockConfirmations {
						mwc_required: swap.mwc_confirmations,
						mwc_actual: mwc_lock,
						currency: swap.secondary_currency,
						sec_required: swap.secondary_confirmations,
						sec_actual: tx_conf.secondary_lock_conf,
					})
					.time_limit(time_limit));
				}

				// Waiting for own funds first. For seller it is MWC
				if mwc_lock < swap.mwc_confirmations {
					if mwc_lock == 0
						&& swap.posted_lock.clone().unwrap_or(0)
							< swap::get_cur_time() - super::state::POST_MWC_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate));
					}

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

				swap.add_journal_message(format!(
					"MWC and {} funds are Locked",
					swap.secondary_currency
				));
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForInitRedeemMessage,
				))
			}
			Input::IncomeMessage(message) => {
				// That can be late Accept offer message
				if message.clone().unwrap_accept_offer().is_ok() {
					return Ok(StateProcessRespond::new(
						StateId::SellerSendingInitRedeemMessage,
					));
				}

				// We can accept message durinf the wait. Byers can already get a confirmation and sending a message
				if swap.adaptor_signature.is_none() {
					let (_, init_redeem, _) = message.unwrap_init_redeem()?;
					SellApi::init_redeem(&*self.keychain, swap, context, init_redeem)?;
				}
				debug_assert!(swap.adaptor_signature.is_some());
				swap.add_journal_message("Init Redeem message is accepted".to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerSendingInitRedeemMessage,
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
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Waiting For Init Redeem message")
				.end_time(swap.get_time_message_redeem()),
		)
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
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundHeight,
				))
			}
			Input::Check => {
				if swap.adaptor_signature.is_some() {
					// Was already processed. Can go to the next step
					return Ok(StateProcessRespond::new(
						StateId::SellerSendingInitRedeemMessage,
					));
				}

				// Check if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
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
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					))
				}
			}
			Input::IncomeMessage(message) => {
				if swap.adaptor_signature.is_none() {
					let (_, init_redeem, _) = message.unwrap_init_redeem()?;
					SellApi::init_redeem(&*self.keychain, swap, context, init_redeem)?;
				}
				debug_assert!(swap.adaptor_signature.is_some());
				swap.add_journal_message("Init Redeem message is accepted".to_string());
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
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Sending back Redeem Message")
				.end_time(swap.get_time_message_redeem()),
		)
	}
	fn is_cancellable(&self) -> bool {
		true
	}

	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				if swap.posted_msg2.is_none() {
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					))
				} else {
					// we can't cancel, we must continue to wait
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					))
				}
			} // Last chance to quit
			Input::Check => {
				// Redeem is published, so we are good
				if swap.redeem_kernel_updated {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				if swap.posted_msg2.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					// Check if everything is still locked...
					let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
					let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
					if mwc_lock < swap.mwc_confirmations
						|| secondary_lock < swap.secondary_confirmations
					{
						swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForLockConfirmations,
						));
					}

					let time_limit = swap.get_time_message_redeem();
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = swap.message2.clone();
						}
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
						if swap.posted_msg2.is_none() {
							swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
							Ok(StateProcessRespond::new(
								StateId::SellerWaitingForRefundHeight,
							))
						} else {
							// we can't cancel, we must continue to wait
							// because it is cancellation, let's do ack for this send.
							// Sending really doesn't needed any more
							swap.ack_msg2();
							Ok(StateProcessRespond::new(
								StateId::SellerWaitingForBuyerToRedeemMwc,
							))
						}
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					))
				}
			}
			Input::Execute => {
				debug_assert!(self.message.is_some()); // Check expected to be called first
				if swap.message2.is_none() {
					swap.message2 = Some(self.message.clone().unwrap());
				}
				swap.posted_msg2 = Some(swap::get_cur_time());
				swap.add_journal_message("Send response to Redeem message".to_string());

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
		swap.redeem_kernel_updated = true;
		return Ok(true);
	}
	Ok(false)
}

/// State SellerWaitingForBuyerToRedeemMwc
pub struct SellerWaitingForBuyerToRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> SellerWaitingForBuyerToRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create a new instance
	pub fn new(node_client: Arc<C>) -> Self {
		Self {
			node_client,
			phantom: PhantomData,
		}
	}
}

fn calc_mwc_unlock_time(swap: &Swap, tip: &u64) -> i64 {
	swap::get_cur_time() + (swap.refund_slate.lock_height.saturating_sub(*tip) * 60) as i64
}

impl<'a, C> State for SellerWaitingForBuyerToRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForBuyerToRedeemMwc
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		// Time limit is defined by the chain height
		if let Ok((height, _, _)) = self.node_client.get_chain_tip() {
			Some(
				StateEtaInfo::new("Wait For Buyer to redeem MWC")
					.end_time(calc_mwc_unlock_time(swap, &height)),
			)
		} else {
			Some(StateEtaInfo::new("Wait For Buyer to redeem MWC"))
		}
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
				// Redeem slate is already found, it's kernel updated, we can go forward
				if swap.redeem_kernel_updated {
					return Ok(StateProcessRespond::new(
						StateId::SellerRedeemSecondaryCurrency,
					));
				}

				// Checking if can redeem first because redeem can be made when we can do refund.
				// Then we want to do redeem and refund from redeem branch.
				if !swap.redeem_slate.tx.kernels().is_empty() {
					if check_mwc_redeem(swap, &*self.node_client)? {
						swap.add_journal_message(
							"Buyer redeemed MWC, transaction published on the blockchain"
								.to_string(),
						);
						swap.ack_msg2();
						// Buyer did a redeem, we can continue processing and redeem BTC
						return Ok(StateProcessRespond::new(
							StateId::SellerRedeemSecondaryCurrency,
						));
					}
				}

				// Check the deadline for locking
				//
				let (height, _, _) = self.node_client.get_chain_tip()?;
				if height > swap.refund_slate.lock_height {
					swap.add_journal_message(
						"Buyer didn't redeem, time to get a refund".to_string(),
					);
					// Time to to get my MWC back with a refund.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					));
				}

				// Check if we need to retry to send the message
				if swap.posted_msg2.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					return Ok(StateProcessRespond::new(
						StateId::SellerSendingInitRedeemMessage,
					));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForBuyerToRedeemMwc)
						.action(Action::SellerWaitForBuyerRedeemPublish {
							mwc_tip: height,
							lock_height: swap.lock_slate.lock_height,
						})
						.time_limit(calc_mwc_unlock_time(swap, &height)),
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
fn post_refund_if_possible<C: NodeClient>(
	node_client: Arc<C>,
	swap: &Swap,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<(), ErrorKind> {
	let (height, _, _) = node_client.get_chain_tip()?;
	if height > swap.refund_slate.lock_height
		&& tx_conf.mwc_redeem_conf.is_none()
		&& tx_conf.mwc_refund_conf.is_none()
	{
		let res = swap::publish_transaction(&*node_client, &swap.refund_slate.tx, false);
		if let Err(e) = res {
			info!("MWC refund can be issued even likely it will fail. Trying to post it. get an error {}", e);
		} else {
			info!("MWC refund can be was issued, even it was expected to fail");
		}
	}
	Ok(())
}

/// State SellerRedeemSecondaryCurrency
pub struct SellerRedeemSecondaryCurrency<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	node_client: Arc<C>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}

impl<'a, C, K> SellerRedeemSecondaryCurrency<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new instance
	pub fn new(
		keychain: Arc<K>,
		node_client: Arc<C>,
		swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	) -> Self {
		Self {
			keychain,
			node_client,
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, K> State for SellerRedeemSecondaryCurrency<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerRedeemSecondaryCurrency
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Post Secondary Redeem Transaction")
				.end_time(swap.get_time_btc_lock() - swap.get_timeinterval_btc_lock()),
		)
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
				post_refund_if_possible(self.node_client.clone(), swap, tx_conf)?;

				if !swap.redeem_kernel_updated {
					debug_assert!(false); // That shouldn't happen
					  // let's go back to the waiting since the data is not ready
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				// Check if already processed
				if tx_conf.secondary_redeem_conf.is_some()
					&& (tx_conf.secondary_redeem_conf.unwrap() > 0
						|| !self.swap_api.is_secondary_tx_fee_changed(swap)?)
				{
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRedeemConfirmations,
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
			Input::Execute => {
				self.swap_api
					.publish_secondary_transaction(&*self.keychain, swap, context)?;
				debug_assert!(swap.secondary_data.unwrap_btc()?.redeem_tx.is_some());
				swap.posted_redeem = Some(swap::get_cur_time());
				swap.add_journal_message(format!(
					"{} redeem transaction is posted",
					swap.secondary_currency
				));
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
pub struct SellerWaitingForRedeemConfirmations<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	node_client: Arc<C>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}

impl<'a, C, K> SellerWaitingForRedeemConfirmations<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new instance
	pub fn new(node_client: Arc<C>, swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			node_client,
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, C, K> State for SellerWaitingForRedeemConfirmations<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForRedeemConfirmations
	}
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Wait For Redeem Tx Confirmations"))
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
				post_refund_if_possible(self.node_client.clone(), swap, tx_conf)?;

				// Just waiting
				if let Some(conf) = tx_conf.secondary_redeem_conf {
					if conf >= swap.secondary_confirmations {
						// We are done
						swap.add_journal_message(format!(
							"{} redeem transaction get enough confirmations. Trade is complete",
							swap.secondary_currency
						));
						return Ok(StateProcessRespond::new(StateId::SellerSwapComplete));
					}

					// If transaction in the memory pool fo a long time and fee is different  now, we should do a retry
					if conf == 0
						&& self.swap_api.is_secondary_tx_fee_changed(swap)?
						&& swap.posted_redeem.unwrap_or(0)
							< swap::get_cur_time() - super::state::POST_SECONDARY_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(
							StateId::SellerRedeemSecondaryCurrency,
						));
					}
				} else {
					// might need to retry
					if swap.posted_redeem.unwrap_or(0)
						< swap::get_cur_time() - super::state::POST_SECONDARY_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(
							StateId::SellerRedeemSecondaryCurrency,
						));
					}
				}

				return Ok(
					StateProcessRespond::new(StateId::SellerWaitingForRedeemConfirmations).action(
						Action::WaitForSecondaryConfirmations {
							name: "Redeeming funds".to_string(),
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
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap completed"))
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
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Swap is cancelled, no funds was locked, no refund needed",
		))
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
pub struct SellerWaitingForRefundHeight<'a, C>
where
	C: NodeClient + 'a,
{
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> SellerWaitingForRefundHeight<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create a new instance
	pub fn new(node_client: Arc<C>) -> Self {
		Self {
			node_client,
			phantom: PhantomData,
		}
	}
}

impl<'a, C> State for SellerWaitingForRefundHeight<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForRefundHeight
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		if let Ok((height, _, _)) = self.node_client.get_chain_tip() {
			Some(
				StateEtaInfo::new("Wait for MWC refund to unlock")
					.end_time(calc_mwc_unlock_time(swap, &height)),
			)
		} else {
			Some(StateEtaInfo::new("Wait for MWC refund to unlock"))
		}
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
				let (height, _, _) = self.node_client.get_chain_tip()?;
				if height > swap.refund_slate.lock_height {
					swap.add_journal_message("MWC funds are unlocked".to_string());
					return Ok(StateProcessRespond::new(StateId::SellerPostingRefundSlate));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForRefundHeight)
						.action(Action::WaitForMwcRefundUnlock {
							mwc_tip: height,
							lock_height: swap.refund_slate.lock_height,
						})
						.time_limit(calc_mwc_unlock_time(swap, &height)),
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
pub struct SellerPostingRefundSlate<'a, C>
where
	C: NodeClient + 'a,
{
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}
impl<'a, C> SellerPostingRefundSlate<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create a new instance
	pub fn new(node_client: Arc<C>) -> Self {
		Self {
			node_client,
			phantom: PhantomData,
		}
	}
}

impl<'a, C> State for SellerPostingRefundSlate<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerPostingRefundSlate
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		if let Ok((height, _, _)) = self.node_client.get_chain_tip() {
			let start_time_limit = calc_mwc_unlock_time(swap, &height);
			Some(
				StateEtaInfo::new("Post MWC Refund Slate")
					.start_time(start_time_limit)
					.end_time(start_time_limit + swap.redeem_time_sec as i64),
			)
		} else {
			Some(StateEtaInfo::new("Post MWC Refund Slate"))
		}
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

				if tx_conf.mwc_redeem_conf.is_some() {
					// Buyer published the slate, we can to redeem BTCs now
					swap.add_journal_message("Buyer published redeem transaction".to_string());
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				Ok(StateProcessRespond::new(StateId::SellerPostingRefundSlate)
					.action(Action::SellerPublishMwcRefundTx))
			}
			Input::Execute => {
				// Executing the MWC lock transaction
				// Posting the transaction
				debug_assert!(tx_conf.mwc_refund_conf.is_none());
				swap::publish_transaction(&*self.node_client, &swap.refund_slate.tx, false)?;
				swap.posted_refund = Some(swap::get_cur_time());
				swap.add_journal_message("MWC refund slate is posted".to_string());
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
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Wait for MWC Refund confirmations"))
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
				if tx_conf.mwc_refund_conf.is_none() {
					if tx_conf.mwc_redeem_conf.is_some() {
						// Found that Buyer redeem, let's switch to that branch
						swap.add_journal_message("Buyer published redeem transaction".to_string());
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForBuyerToRedeemMwc,
						));
					}

					if swap.posted_refund.unwrap_or(0)
						< swap::get_cur_time() - super::state::POST_MWC_RETRY_PERIOD
					{
						// We can retry to post
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRefundHeight,
						));
					}
				}

				let refund_conf = tx_conf.mwc_refund_conf.unwrap_or(0);
				if refund_conf > swap.mwc_confirmations {
					// already published.
					swap.add_journal_message("MWC refund transaction get enough confirmation. Trade is cancelled and refunded".to_string());
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
		Some(StateId::SellerPostingRefundSlate)
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
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap is cancelled, MWC are refunded"))
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
