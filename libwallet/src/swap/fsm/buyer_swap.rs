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
use crate::swap::swap;
use crate::swap::types::{Action, SwapTransactionsConfirmations};
use crate::swap::{BuyApi, Context, ErrorKind, Swap, SwapApi};
use crate::NodeClient;
use chrono::{Local, TimeZone};
use failure::_core::marker::PhantomData;
use grin_core::core::verifier_cache::LruVerifierCache;
use grin_core::core::Weighting;
use grin_keychain::Keychain;
use grin_util::RwLock;
use std::sync::Arc;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerOfferCreated
pub struct BuyerOfferCreated {}
impl BuyerOfferCreated {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for BuyerOfferCreated {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerOfferCreated
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		let dt = Local.timestamp(swap.started.timestamp(), 0);
		let time_str = dt.format("%B %e %H:%M:%S").to_string();
		Some(StateEtaInfo::new(&format!("Get an Offer at {}", time_str)))
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
				Ok(StateProcessRespond::new(StateId::BuyerCancelled))
			}
			Input::Check => Ok(StateProcessRespond::new(
				StateId::BuyerSendingAcceptOfferMessage,
			)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerOfferCreated get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerSendingAcceptOfferMessage)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerSendingAcceptOfferMessage
pub struct BuyerSendingAcceptOfferMessage<'a, K>
where
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	message: Option<Message>,
	phantom: PhantomData<&'a K>,
}
impl<'a, K> BuyerSendingAcceptOfferMessage<'a, K>
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
impl<'a, K> State for BuyerSendingAcceptOfferMessage<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerSendingAcceptOfferMessage
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Send Accept Offer Message").end_time(swap.get_time_message_offers()),
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
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				if tx_conf.secondary_lock_amount == 0 {
					Ok(StateProcessRespond::new(StateId::BuyerCancelled))
				} else {
					Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
				}
			}
			Input::Check => {
				let time_limit = swap.get_time_message_offers();
				if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					if swap::get_cur_time() < time_limit {
						self.message = swap.message1.clone();
						if self.message.is_none() {
							let sec_update = self
								.swap_api
								.build_accept_offer_message_secondary_update(&*self.keychain, swap);
							self.message = Some(BuyApi::accept_offer_message(swap, sec_update)?);
						}
						Ok(
							StateProcessRespond::new(StateId::BuyerSendingAcceptOfferMessage)
								.action(Action::BuyerSendAcceptOfferMessage(
									self.message.clone().unwrap(),
								))
								.time_limit(time_limit),
						)
					} else {
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						if tx_conf.secondary_lock_amount == 0 {
							Ok(StateProcessRespond::new(StateId::BuyerCancelled))
						} else {
							Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
						}
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForSellerToLock,
					))
				}
			}
			Input::Execute => {
				debug_assert!(self.message.is_some()); // Check expected to be called first
				if swap.message1.is_none() {
					swap.message1 = Some(self.message.clone().unwrap());
				}
				swap.posted_msg1 = Some(swap::get_cur_time());
				swap.add_journal_message("Response to offer message was sent back".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForSellerToLock,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerSendingAcceptOfferMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerOfferCreated)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForSellerToLock)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerWaitingForSellerToLock
pub struct BuyerWaitingForSellerToLock {}
impl BuyerWaitingForSellerToLock {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for BuyerWaitingForSellerToLock {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForSellerToLock
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		if swap.seller_lock_first {
			Some(
				StateEtaInfo::new("Wait for seller to start locking MWC")
					.end_time(swap.get_time_start_lock()),
			)
		} else {
			None
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
				if tx_conf.secondary_lock_amount == 0 {
					Ok(StateProcessRespond::new(StateId::BuyerCancelled))
				} else {
					Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
				}
			}
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				let time_limit = swap.get_time_start_lock();
				// Check the deadline for locking
				if swap::get_cur_time() > time_limit {
					// cancelling
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return if tx_conf.secondary_lock_amount == 0 {
						Ok(StateProcessRespond::new(StateId::BuyerCancelled))
					} else {
						Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
					};
				}

				if !swap.seller_lock_first {
					// Skipping this step. Seller waiting for us to start locking
					Ok(StateProcessRespond::new(
						StateId::BuyerPostingSecondaryToMultisigAccount,
					))
				} else {
					let conf = tx_conf.mwc_lock_conf.unwrap_or(0);

					if conf < 1 {
						Ok(
							StateProcessRespond::new(StateId::BuyerWaitingForSellerToLock)
								.action(Action::WaitForMwcConfirmations {
									name: "Seller locking funds".to_string(),
									required: 1,
									actual: conf,
								})
								.time_limit(time_limit),
						)
					} else {
						swap.add_journal_message("Seller start locking MWC funds".to_string());
						Ok(StateProcessRespond::new(
							StateId::BuyerPostingSecondaryToMultisigAccount,
						))
					}
				}
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitingForSellerToLock get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerSendingAcceptOfferMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerPostingSecondaryToMultisigAccount)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerPostingSecondaryToMultisigAccount
pub struct BuyerPostingSecondaryToMultisigAccount<'a, K>
where
	K: Keychain + 'a,
{
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}
impl<'a, K> BuyerPostingSecondaryToMultisigAccount<'a, K>
where
	K: Keychain + 'a,
{
	/// Create new instance
	pub fn new(swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, K> State for BuyerPostingSecondaryToMultisigAccount<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerPostingSecondaryToMultisigAccount
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Post BTC to lock account").end_time(swap.get_time_start_lock()))
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
				if tx_conf.secondary_lock_amount == 0 {
					Ok(StateProcessRespond::new(StateId::BuyerCancelled))
				} else {
					Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
				}
			} // We can't just cancel. Funds might be posted, it is a manual process.
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				// Check if mwc lock is already done
				let (pending_amount, confirmed_amount, _least_confirmations) = self
					.swap_api
					.request_secondary_lock_balance(swap, swap.secondary_confirmations)?;

				let chain_amount = pending_amount + confirmed_amount;
				let time_limit = swap.get_time_start_lock();

				// Check the deadline for locking
				if chain_amount != swap.secondary_amount {
					if swap::get_cur_time() > time_limit {
						// cancelling because of timeout
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						return if tx_conf.secondary_lock_amount == 0 {
							Ok(StateProcessRespond::new(StateId::BuyerCancelled))
						} else {
							Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
						};
					}
				}

				if chain_amount < swap.secondary_amount {
					// At this point, user needs to deposit (more) Bitcoin
					return Ok(StateProcessRespond::new(
						StateId::BuyerPostingSecondaryToMultisigAccount,
					)
					.action(Action::DepositSecondary {
						currency: swap.secondary_currency,
						amount: swap.secondary_amount - chain_amount,
						address: format!("{}", self.swap_api.get_secondary_lock_address(swap)?),
					})
					.time_limit(time_limit));
				}

				// Posted more then expected. We are not going forward. Deal is broken, probably it is a mistake. We are cancelling the trade because of that.
				if chain_amount > swap.secondary_amount {
					swap.add_journal_message(format!(
						"{}. Expected {} {}, but get {} {}",
						JOURNAL_CANCELLED_BYER_LOCK_TOO_MUCH_FUNDS,
						swap.secondary_currency
							.amount_to_hr_string(swap.secondary_amount, true),
						swap.secondary_currency,
						swap.secondary_currency
							.amount_to_hr_string(chain_amount, true),
						swap.secondary_currency
					));
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}

				debug_assert!(chain_amount == swap.secondary_amount);

				swap.add_journal_message("Funds are posted to Lock account".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForLockConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerPostingSecondaryToMultisigAccount get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForSellerToLock)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForLockConfirmations)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerWaitingForLockConfirmations
pub struct BuyerWaitingForLockConfirmations<K>
where
	K: Keychain,
{
	keychain: Arc<K>,
}
impl<K> BuyerWaitingForLockConfirmations<K>
where
	K: Keychain,
{
	/// Create new instance
	pub fn new(keychain: Arc<K>) -> Self {
		Self { keychain }
	}
}

impl<K> State for BuyerWaitingForLockConfirmations<K>
where
	K: Keychain,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForLockConfirmations
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Wait for Locking funds confirmations")
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
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime)) // Long cancellation path
			}
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);

				if tx_conf.secondary_lock_amount < swap.secondary_amount {
					swap.add_journal_message(
						"Found that Secondary lock acocunt need more funds".to_string(),
					);
					// Need to deposit more. Something happens? Likely will be cancelled because of timeout.
					return Ok(StateProcessRespond::new(
						StateId::BuyerPostingSecondaryToMultisigAccount,
					));
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
						return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
					}

					return Ok(
						StateProcessRespond::new(StateId::BuyerWaitingForLockConfirmations)
							.action(Action::WaitForLockConfirmations {
								mwc_required: swap.mwc_confirmations,
								mwc_actual: mwc_lock,
								currency: swap.secondary_currency,
								sec_required: swap.secondary_confirmations,
								sec_actual: tx_conf.secondary_lock_conf,
							})
							.time_limit(time_limit),
					);
				}

				// If we got here, funds have been locked on both chains with sufficient confirmations
				// On the first run - let's update the swap data
				if swap.redeem_slate.participant_data.len() <= 1 || swap.adaptor_signature.is_none()
				{
					BuyApi::init_redeem(&*self.keychain, swap, context)?;
				}

				swap.add_journal_message(format!(
					"MWC and {} funds are Locked",
					swap.secondary_currency
				));
				Ok(StateProcessRespond::new(
					StateId::BuyerSendingInitRedeemMessage,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitingForLockConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerPostingSecondaryToMultisigAccount)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerSendingInitRedeemMessage)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerSendingInitRedeemMessage
pub struct BuyerSendingInitRedeemMessage {
	message: Option<Message>,
}
impl BuyerSendingInitRedeemMessage {
	/// Create new instance
	pub fn new() -> Self {
		Self { message: None }
	}
}
impl State for BuyerSendingInitRedeemMessage {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerSendingInitRedeemMessage
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Send Init Redeem Message").end_time(swap.get_time_message_redeem()))
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
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			} // Last chance to quit
			Input::Check => {
				// Check first if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}

				let time_limit = swap.get_time_message_redeem();

				if swap.posted_msg2.unwrap_or(0)
					< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
				{
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = swap.message2.clone();
						}
						if self.message.is_none() {
							self.message = Some(BuyApi::init_redeem_message(swap)?);
						}
						Ok(
							StateProcessRespond::new(StateId::BuyerSendingInitRedeemMessage)
								.action(Action::BuyerSendInitRedeemMessage(
									self.message.clone().unwrap(),
								))
								.time_limit(time_limit),
						)
					} else {
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
					}
				} else {
					// Probably it is a rerun because of some reset. We should tolerate that
					Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForRespondRedeemMessage,
					))
				}
			}
			Input::Execute => {
				debug_assert!(self.message.is_some()); // Check expected to be called first
				if swap.message2.is_none() {
					swap.message2 = Some(self.message.clone().unwrap());
				}
				swap.posted_msg2 = Some(swap::get_cur_time());
				swap.add_journal_message("Sent init redeem message".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForRespondRedeemMessage,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerSendingInitRedeemMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForLockConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRespondRedeemMessage)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerWaitingForRespondRedeemMessage
pub struct BuyerWaitingForRespondRedeemMessage<K: Keychain> {
	keychain: Arc<K>,
}
impl<K: Keychain> BuyerWaitingForRespondRedeemMessage<K> {
	/// Create new instance
	pub fn new(keychain: Arc<K>) -> Self {
		Self { keychain }
	}
}
impl<K: Keychain> State for BuyerWaitingForRespondRedeemMessage<K> {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForRespondRedeemMessage
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Wait For Redeem response message")
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
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			}
			Input::Check => {
				// Check first if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}

				if swap
					.refund_slate
					.tx
					.validate(
						Weighting::AsTransaction,
						Arc::new(RwLock::new(LruVerifierCache::new())),
					)
					.is_ok()
				{
					// Was already processed. Can go to the next step
					return Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc));
				}

				let time_limit = swap.get_time_message_redeem();
				if swap::get_cur_time() < time_limit {
					if swap.posted_msg2.unwrap_or(0)
						< swap::get_cur_time() - super::state::SEND_MESSAGE_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(
							StateId::BuyerSendingInitRedeemMessage,
						));
					}

					Ok(
						StateProcessRespond::new(StateId::BuyerWaitingForRespondRedeemMessage)
							.action(Action::BuyerWaitingForRedeemMessage)
							.time_limit(time_limit),
					)
				} else {
					// cancelling
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
				}
			}
			Input::IncomeMessage(message) => {
				if swap
					.redeem_slate
					.tx
					.validate(
						Weighting::AsTransaction,
						Arc::new(RwLock::new(LruVerifierCache::new())),
					)
					.is_err()
				{
					let (_, redeem, _) = message.unwrap_redeem()?;
					BuyApi::finalize_redeem_slate(
						&*self.keychain,
						swap,
						context,
						redeem.redeem_participant,
					)?;
					swap.ack_msg2();
					swap.add_journal_message("Process Redeem response message".to_string());
				}
				debug_assert!(swap
					.redeem_slate
					.tx
					.validate(
						Weighting::AsTransaction,
						Arc::new(RwLock::new(LruVerifierCache::new()))
					)
					.is_ok());
				Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitingForRespondRedeemMessage get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerSendingInitRedeemMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerRedeemMwc)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerRedeemMwc
pub struct BuyerRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> BuyerRedeemMwc<'a, C>
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

impl<'a, C> State for BuyerRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerRedeemMwc
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Redeem MWC").end_time(swap.get_time_mwc_redeem()))
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
		let time_limit = swap.get_time_mwc_redeem();
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			}
			Input::Check => {
				// Redeem slate is already published, can go forward
				if tx_conf.mwc_redeem_conf.unwrap_or(0) > 0 {
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitForRedeemMwcConfirmations,
					));
				}

				// Sorry, too late to redeem, risk is higher then expected
				if swap::get_cur_time() > time_limit {
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}

				// Check if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}

				// Still waiting...
				Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc)
					.action(Action::BuyerPublishMwcRedeemTx)
					.time_limit(time_limit))
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_redeem()?;
				Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc))
			}
			Input::Execute => {
				if swap::get_cur_time() > time_limit {
					// too late, exiting
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}

				// Check if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_lock = tx_conf.secondary_lock_conf.unwrap_or(0);
				if mwc_lock < swap.mwc_confirmations
					|| secondary_lock < swap.secondary_confirmations
				{
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}

				swap::publish_transaction(&*self.node_client, &swap.redeem_slate.tx, false)?;
				swap.posted_redeem = Some(swap::get_cur_time());
				swap.add_journal_message("MWC Redeem slate is posted".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitForRedeemMwcConfirmations,
				))
			} /*_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				  "BuyerRedeemMwc get {:?}",
				  input
			  ))),*/
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRespondRedeemMessage)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitForRedeemMwcConfirmations)
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerWaitForRedeemMwcConfirmations
pub struct BuyerWaitForRedeemMwcConfirmations {}
impl BuyerWaitForRedeemMwcConfirmations {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for BuyerWaitForRedeemMwcConfirmations {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitForRedeemMwcConfirmations
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
				// Check the deadline for locking
				// TODO   Check if need to do a retry.

				let conf = tx_conf.mwc_redeem_conf.unwrap_or(0);
				if conf >= swap.mwc_confirmations {
					// We are done
					swap.add_journal_message(
						"Redeem transacton get enough confirnation. The Swap trade is finished"
							.to_string(),
					);
					return Ok(StateProcessRespond::new(StateId::BuyerSwapComplete));
				}

				if tx_conf.mwc_redeem_conf.is_none()
					&& swap.posted_redeem.unwrap_or(0)
						< swap::get_cur_time() - super::state::POST_MWC_RETRY_PERIOD
				{
					// We can retry to post
					return Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc));
				}

				return Ok(
					StateProcessRespond::new(StateId::BuyerWaitForRedeemMwcConfirmations).action(
						Action::WaitForMwcConfirmations {
							name: "Redeeming funds".to_string(),
							required: swap.mwc_confirmations,
							actual: conf,
						},
					),
				);
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_redeem()?;
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitForRedeemMwcConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitForRedeemMwcConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerRedeemMwc)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerSwapComplete)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////

/// State BuyerSwapComplete
pub struct BuyerSwapComplete {}
impl BuyerSwapComplete {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for BuyerSwapComplete {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerSwapComplete
	}
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap is completed"))
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
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerSwapComplete)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerSwapComplete get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitForRedeemMwcConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		None
	}
}

///////////////////////////////////////////////////////////////////

/// State BuyerCancelled
pub struct BuyerCancelled {}
impl BuyerCancelled {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for BuyerCancelled {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerCancelled
	}
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Swap is cancelled, no funds was locked, no refund was needed",
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
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerCancelled)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerCancelled get {:?}",
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

/// State BuyerWaitingForRefundTime
pub struct BuyerWaitingForRefundTime {}

impl BuyerWaitingForRefundTime {
	/// Create a new instance
	pub fn new() -> Self {
		Self {}
	}
}

impl State for BuyerWaitingForRefundTime {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForRefundTime
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Waiting for Secondary to unlock")
				.start_time(swap.get_time_btc_lock()),
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
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => {
				// Just chilling. MWC redeem was never posted, so Seller can't get BTC. But still checking for what if

				// Should be impossible scenarion. But somehow the slate was posted. In any case we
				// have nothing loose, that slate is ours in any case.
				debug_assert!(tx_conf.mwc_redeem_conf.is_none());

				let cur_time = swap::get_cur_time();
				let time_limit = swap.get_time_btc_lock();
				if cur_time > time_limit {
					swap.add_journal_message(format!(
						"{} funds are unlocked, ready for refund",
						swap.secondary_currency
					));
					return Ok(StateProcessRespond::new(
						StateId::BuyerPostingRefundForSecondary,
					));
				}

				// Still waiting...
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime)
					.action(Action::WaitingForBtcRefund {
						currency: swap.secondary_currency,
						required: time_limit as u64,
						current: cur_time as u64,
					})
					.time_limit(time_limit))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitingForRefundTime get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerPostingRefundForSecondary)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerPostingRefundForSecondary
pub struct BuyerPostingRefundForSecondary<'a, K>
where
	K: Keychain + 'a,
{
	keychain: Arc<K>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}
impl<'a, K> BuyerPostingRefundForSecondary<'a, K>
where
	K: Keychain + 'a,
{
	/// Create new instance
	pub fn new(keychain: Arc<K>, swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			keychain,
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, K> State for BuyerPostingRefundForSecondary<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerPostingRefundForSecondary
	}
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Post Refund for Secondary").start_time(swap.get_time_btc_lock()))
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
				let cur_time = swap::get_cur_time();
				let time_limit = swap.get_time_btc_lock();
				if cur_time < time_limit {
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}

				// Check if refund is already issued
				if tx_conf.secondary_refund_conf.is_some()
					&& (tx_conf.secondary_refund_conf.unwrap() > 0
						|| !self.swap_api.is_secondary_tx_fee_changed(swap)?)
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForRefundConfirmations,
					));
				}

				Ok(
					StateProcessRespond::new(StateId::BuyerPostingRefundForSecondary).action(
						Action::BuyerPublishSecondaryRefundTx(swap.secondary_currency),
					),
				)
			}
			Input::Execute => {
				let refund_address = swap.unwrap_buyer()?;
				self.swap_api.post_secondary_refund_tx(
					&*self.keychain,
					context,
					swap,
					refund_address,
				)?;
				swap.posted_refund = Some(swap::get_cur_time());
				swap.add_journal_message(format!("{} refund is posted", swap.secondary_currency));
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForRefundConfirmations,
				))
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerPostingRefundForSecondary get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRefundTime)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRefundConfirmations)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerWaitingForRefundConfirmations
pub struct BuyerWaitingForRefundConfirmations<'a, K>
where
	K: Keychain + 'a,
{
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}
impl<'a, K> BuyerWaitingForRefundConfirmations<'a, K>
where
	K: Keychain + 'a,
{
	/// Create new instance
	pub fn new(swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			swap_api,
			phantom: PhantomData,
		}
	}
}

impl<'a, K> State for BuyerWaitingForRefundConfirmations<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForRefundConfirmations
	}
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Wait for Refund confirmations"))
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
				if let Some(conf) = tx_conf.secondary_refund_conf {
					if conf >= swap.secondary_confirmations {
						// We are done
						swap.add_journal_message(format!("{} refund transaction has enough confirmations. The trade is completed, refund is redeemed.", swap.secondary_currency));
						return Ok(StateProcessRespond::new(StateId::BuyerCancelledRefunded));
					}

					if conf == 0
						&& self.swap_api.is_secondary_tx_fee_changed(swap)?
						&& swap.posted_refund.unwrap_or(0)
							< swap::get_cur_time() - super::state::POST_SECONDARY_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(
							StateId::BuyerPostingRefundForSecondary,
						));
					}
				} else {
					// might need to retry
					if swap.posted_refund.unwrap_or(0)
						< swap::get_cur_time() - super::state::POST_SECONDARY_RETRY_PERIOD
					{
						return Ok(StateProcessRespond::new(
							StateId::BuyerPostingRefundForSecondary,
						));
					}
				}

				Ok(
					StateProcessRespond::new(StateId::BuyerWaitingForRefundConfirmations).action(
						Action::WaitForSecondaryConfirmations {
							name: format!("{} Refund", swap.secondary_currency),
							currency: swap.secondary_currency,
							required: swap.secondary_confirmations,
							actual: tx_conf.secondary_refund_conf.unwrap_or(0),
						},
					),
				)
			}
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerWaitingForRefundConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerPostingRefundForSecondary)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerCancelledRefunded)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

/// State BuyerCancelledRefunded
pub struct BuyerCancelledRefunded {}
impl BuyerCancelledRefunded {
	/// Create new instance
	pub fn new() -> Self {
		Self {}
	}
}
impl State for BuyerCancelledRefunded {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerCancelledRefunded
	}
	fn get_eta(&self, _swap: &Swap) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap is cancelled, refund is redeemed"))
	}
	fn is_cancellable(&self) -> bool {
		false
	}

	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerCancelledRefunded)),
			_ => Err(ErrorKind::InvalidSwapStateInput(format!(
				"BuyerCancelledRefunded get {:?}",
				input
			))),
		}
	}

	fn get_prev_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRefundConfirmations)
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		None
	}
}
