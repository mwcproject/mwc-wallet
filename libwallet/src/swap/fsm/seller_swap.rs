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
use crate::swap::fsm::state;
use crate::swap::fsm::state::{Input, State, StateEtaInfo, StateId, StateProcessRespond};
use crate::swap::message::Message;
use crate::swap::types::{
	check_txs_confirmed, Action, Currency, SecondaryTransferStatus, SwapTransactionsConfirmations,
};
use crate::swap::{swap, Context, Error, SellApi, Swap, SwapApi};
use crate::{NodeClient, SecondaryFeeUnits};
use mwc_wallet_util::mwc_crates::chrono::Local;
use mwc_wallet_util::mwc_crates::log::info;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::Keychain;
use std::marker::PhantomData;
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let dt = swap.started.with_timezone(&Local);
		let time_str = dt.format("%B %e %H:%M:%S").to_string();
		Some(StateEtaInfo::new(&format!("Offer Created at {}", time_str)))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerSendingOffer)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
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
	pub fn new(context_id: u32, keychain: Arc<K>, swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			context_id,
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let info = match swap.get_time_message_offers() {
			Ok(deadline) => StateEtaInfo::new("Sending Offer to Buyer").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Sending Offer to Buyer: unable to determine deadline: {}",
				error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					let time_limit = swap.get_time_message_offers()?;
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = swap.message1.clone();
						}
						if self.message.is_none() {
							let sec_update = self
								.swap_api
								.build_offer_message_secondary_update(&*self.keychain, swap)?;
							self.message =
								Some(SellApi::offer_message(self.context_id, swap, sec_update)?);
						}
						Ok(StateProcessRespond::new(StateId::SellerSendingOffer)
							.action(Action::SellerSendOfferMessage(self.message.clone().ok_or(
								Error::Generic("Internal error, message is empty".into()),
							)?))
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
					swap.message1 = Some(
						self.message
							.clone()
							.ok_or(Error::Generic("Internal error, message is empty".into()))?,
					);
				}
				swap.posted_msg1 = Some(swap::get_cur_time());

				swap.add_journal_message("Offer message was sent".to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForAcceptanceMessage,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct SellerWaitingForAcceptanceMessage<C: NodeClient, K: Keychain> {
	context_id: u32,
	keychain: Arc<K>,
	node_client: Arc<C>,
}
impl<C: NodeClient, K: Keychain> SellerWaitingForAcceptanceMessage<C, K> {
	/// Create new instance
	pub fn new(context_id: u32, keychain: Arc<K>, node_client: Arc<C>) -> Self {
		Self {
			context_id,
			keychain,
			node_client,
		}
	}
}
impl<C: NodeClient, K: Keychain> State for SellerWaitingForAcceptanceMessage<C, K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForAcceptanceMessage
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Waiting For Buyer to accept the offer")
				.end_time(swap.get_time_message_offers().ok()?),
		)
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				if swap.redeem_public.is_none() {
					let time_limit = swap.get_time_message_offers()?;
					if swap::get_cur_time() < time_limit {
						// Check if we need to retry to send the message
						if swap.posted_msg1.unwrap_or(0)
							< swap::get_cur_time()
								.saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
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
					match swap.secondary_currency.is_btc_family() {
						true => {
							let btc_update =
								secondary_update.unwrap_btc()?.unwrap_accept_offer()?;
							SellApi::accepted_offer(
								self.context_id,
								secp,
								&*self.keychain,
								swap,
								context,
								accept_offer,
								self.node_client.as_ref(),
							)?;
							let btc_data = swap.secondary_data.unwrap_btc_mut()?;
							btc_data.accepted_offer(btc_update)?;
						}
						_ => {
							let eth_update =
								secondary_update.unwrap_eth()?.unwrap_accept_offer()?;
							SellApi::accepted_offer(
								self.context_id,
								secp,
								&*self.keychain,
								swap,
								context,
								accept_offer,
								self.node_client.as_ref(),
							)?;
							let eth_data = swap.secondary_data.unwrap_eth_mut()?;
							eth_data.accepted_offer(eth_update)?;
						}
					}
					swap.add_journal_message("Processed Offer Accept message".to_string());
					swap.ack_msg1(); // Just in case duplicate ack, because we get a respond, so the message was delivered
				}
				if swap.redeem_public.is_none() {
					return Err(Error::UnexpectedAction(
						"SellerWaitingForAcceptanceMessage::process, redeem public key is missing"
							.to_string(),
					));
				}
				Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct SellerWaitingForBuyerLock<'a, K>
where
	K: Keychain + 'a,
{
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a K>,
}

impl<'a, K> SellerWaitingForBuyerLock<'a, K>
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

impl<'a, K> State for SellerWaitingForBuyerLock<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForBuyerLock
	}
	fn get_eta(&self, swap: &Swap, secp: &Secp256k1) -> Option<StateEtaInfo> {
		if swap.seller_lock_first {
			None
		} else {
			// Ethereum's secondary address identifies the trade; funding must go
			// through the buyer wallet's swap contract deposit.
			let name = if !swap.secondary_currency.is_btc_family() {
				format!(
					"Waiting for Buyer to deposit {} from their wallet into the swap contract",
					swap.secondary_currency
				)
			} else if swap.redeem_public.is_none()
				&& matches!(
					swap.state,
					StateId::SellerOfferCreated
						| StateId::SellerSendingOffer
						| StateId::SellerWaitingForAcceptanceMessage
				) {
				// The roadmap includes this future step before the buyer supplies
				// the public keys needed to construct its lock address.
				format!(
						"Waiting For Buyer to send {} coins (lock address available after offer acceptance)",
						swap.secondary_currency
					)
			} else {
				match self.swap_api.get_secondary_lock_address(swap, secp) {
					Ok(address) => {
						if address.len() > 1 {
							format!(
								"Waiting For Buyer to send {} coins to any of those addresses: {}",
								swap.secondary_currency,
								address.join(", ")
							)
						} else if let Some(address) = address.first() {
							format!(
								"Waiting For Buyer to send {} coins to {}",
								swap.secondary_currency, address
							)
						} else {
							format!(
									"Waiting For Buyer to send {} coins: unable to determine lock address: no address returned",
									swap.secondary_currency
								)
						}
					}
					Err(error) => format!(
						"Waiting For Buyer to send {} coins: unable to determine lock address: {}",
						swap.secondary_currency, error
					),
				}
			};

			Some(match swap.get_time_start_lock() {
				Ok(deadline) => StateEtaInfo::new(&name).end_time(deadline),
				Err(error) => StateEtaInfo::new(&format!(
					"{}: unable to determine deadline: {}",
					name, error
				)),
			})
		}
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::SellerCancelled))
			}
			Input::Check => {
				// Check the deadline for locking
				let time_limit = swap.get_time_start_lock()?;
				if swap::get_cur_time() > time_limit {
					// cancelling
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return Ok(StateProcessRespond::new(StateId::SellerCancelled));
				}

				if swap.wait_for_backup1 {
					return Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock)
						.action(Action::WaitingForTradeBackup)
						.time_limit(time_limit));
				}

				if swap.seller_lock_first {
					// Skipping this step. Buyer waiting for us to start locking
					Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
				} else {
					let mut conf = tx_conf.secondary_lock_conf.unwrap_or(0);
					if tx_conf.secondary_lock_amount < swap.secondary_amount {
						conf = 0;
					}

					let lock_addresses = self.swap_api.get_secondary_lock_address(swap, secp)?;
					debug_assert!(lock_addresses.len() > 0);
					debug_assert!(lock_addresses.len() <= 2);

					if tx_conf.secondary_lock_amount > swap.secondary_amount {
						// Posted too much, byer probably will cancel the deal, we are not going to lock the MWCs
						swap.add_journal_message(format!(
							"Cancelled because buyer sent funds greater than the agreed upon {} amount to the lock address {}",
							swap.secondary_currency,
							lock_addresses.join(" or "),
						));
						return Ok(StateProcessRespond::new(StateId::SellerCancelled));
					}

					// Memory pool does count
					if tx_conf.secondary_lock_amount == swap.secondary_amount {
						swap.other_lock_first_done = true;
					}

					if conf < 1 {
						Ok(StateProcessRespond::new(StateId::SellerWaitingForBuyerLock)
							.action(Action::WaitForSecondaryConfirmations {
								name: format!("Buyer to lock {}", swap.secondary_currency),
								expected_to_be_posted: swap
									.secondary_amount
									.saturating_sub(tx_conf.secondary_lock_amount),
								currency: swap.secondary_currency,
								address: self
									.swap_api
									.get_secondary_lock_address(swap, secp)
									.unwrap_or(vec!["XXXXX".to_string()]),
								required: 1,
								actual: conf,
							})
							.time_limit(time_limit))
					} else {
						swap.add_journal_message(format!(
							"Buyer sent the funds to lock address {}",
							lock_addresses.join(" or ")
						));
						swap.other_lock_first_done = true;
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
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> SellerPostingLockMwcSlate<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create an instance
	pub fn new(context_id: u32, node_client: Arc<C>) -> Self {
		Self {
			context_id,
			node_client,
			phantom: PhantomData,
		}
	}

	fn generate_cancel_respond(
		swap: &Swap,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, Error> {
		if swap.posted_lock.is_none() && tx_conf.mwc_lock_conf.is_none() {
			Ok(StateProcessRespond::new(StateId::SellerCancelled))
		} else {
			// A submitted or observed lock can confirm even after cancellation.
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(match swap.get_time_start_lock() {
			Ok(deadline) => StateEtaInfo::new("Locking MWC funds").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Locking MWC funds: unable to determine deadline: {}",
				error
			)),
		})
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		self.process_with_persist(input, swap, context, tx_conf, secp, &|_| Ok(()))
	}

	fn process_with_persist(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
		persist: &dyn Fn(&Swap) -> Result<(), Error>,
	) -> Result<StateProcessRespond, Error> {
		let time_limit = swap.get_time_start_lock()?;
		if tx_conf.mwc_lock_conf.is_some() {
			// Remember an observed lock even if a later reorg removes it.
			swap.posted_lock.get_or_insert_with(swap::get_cur_time);
		}
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Self::generate_cancel_respond(swap, tx_conf)
			}
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
					return Self::generate_cancel_respond(swap, tx_conf);
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
					return Self::generate_cancel_respond(swap, tx_conf);
				}
				let refund = swap.refund_preflight_transaction(self.context_id, secp)?;
				let receipt = crate::transaction_preflight::prepare_transaction_with_related(
					self.context_id,
					self.node_client.as_ref(),
					swap.lock_slate.slate.tx_or_err()?,
					&[refund],
				)?;
				let previous_post = swap.posted_lock;
				swap.posted_lock = Some(swap::get_cur_time());
				if let Err(error) = persist(swap) {
					// No signatures or proofs were sent. Preserve earlier exposure, but
					// do not strand a first attempt that failed before broadcasting.
					swap.posted_lock = previous_post;
					return Err(error);
				}
				// A submission error is ambiguous. Keep the saved marker even if
				// the node accepted the lock but its response was lost.
				self.node_client.post_tx(
					swap.lock_slate.slate.tx_or_err()?,
					false,
					receipt,
				)?;
				swap.add_journal_message("MWC lock slate posted".to_string());

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForLockConfirmations,
				))
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_accept_offer()?;
				Ok(StateProcessRespond::new(StateId::SellerPostingLockMwcSlate))
			} /*_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct SellerWaitingForLockConfirmations<'a, C: NodeClient, K: Keychain> {
	context_id: u32,
	keychain: Arc<K>,
	node_client: Arc<C>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
}
impl<'a, C: NodeClient, K: Keychain> SellerWaitingForLockConfirmations<'a, C, K> {
	/// Create a new instance
	pub fn new(
		context_id: u32,
		keychain: Arc<K>,
		swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
		node_client: Arc<C>,
	) -> Self {
		Self {
			context_id,
			keychain,
			node_client,
			swap_api,
		}
	}
}

impl<'a, C: NodeClient, K: Keychain> State for SellerWaitingForLockConfirmations<'a, C, K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForLockConfirmations
	}
	fn get_eta(&self, swap: &Swap, secp: &Secp256k1) -> Option<StateEtaInfo> {
		let name = if !swap.secondary_currency.is_btc_family() {
			format!(
				"Waiting for MWC lock and {} swap contract deposit confirmations",
				swap.secondary_currency
			)
		} else if swap.redeem_public.is_none()
			&& matches!(
				swap.state,
				StateId::SellerOfferCreated
					| StateId::SellerSendingOffer
					| StateId::SellerWaitingForAcceptanceMessage
			) {
			// The roadmap includes this future step before the buyer supplies
			// the public keys needed to construct its lock address.
			"Waiting for Lock funds confirmations. (lock address available after offer acceptance)"
				.to_string()
		} else {
			let address_info = match self.swap_api.get_secondary_lock_address(swap, secp) {
				Ok(address) => {
					debug_assert!(address.len() > 0);
					debug_assert!(address.len() <= 2);
					format!(
						" {} lock address {}",
						swap.secondary_currency,
						address.join(" or ")
					)
				}
				Err(error) => format!(" unable to determine lock address: {}", error),
			};
			format!("Waiting for Lock funds confirmations.{}", address_info)
		};
		Some(match swap.get_time_message_redeem() {
			Ok(deadline) => StateEtaInfo::new(&name).end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"{}: unable to determine deadline: {}",
				name, error
			)),
		})
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundHeight,
				)) // Long cancellation path
			}
			Input::Check => {
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let mut secondary_lock_conf = tx_conf.secondary_lock_conf;

				if tx_conf.secondary_lock_amount < swap.secondary_amount {
					secondary_lock_conf = Some(0);
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

				let time_limit = swap.get_time_message_redeem()?;
				let secondary_confirmed = check_txs_confirmed(
					swap.secondary_currency,
					secondary_lock_conf,
					swap.secondary_confirmations,
				);
				if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
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
							< swap::get_cur_time()
								.saturating_sub(super::state::POST_MWC_RETRY_PERIOD)
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
						address: self.swap_api.get_secondary_lock_address(swap, secp)?,
						sec_expected_to_be_posted: swap
							.secondary_amount
							.saturating_sub(tx_conf.secondary_lock_amount),
						sec_required: swap.secondary_confirmations,
						sec_actual: tx_conf.secondary_lock_conf,
					})
					.time_limit(time_limit));
				}

				// Waiting for own funds first. For seller it is MWC
				if mwc_lock < swap.mwc_confirmations {
					if mwc_lock == 0
						&& swap.posted_lock.clone().unwrap_or(0)
							< swap::get_cur_time()
								.saturating_sub(super::state::POST_MWC_RETRY_PERIOD)
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

				if !secondary_confirmed {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					)
					.action(Action::WaitForSecondaryConfirmations {
						name: format!("{} Locking Account", swap.secondary_currency),
						expected_to_be_posted: swap
							.secondary_amount
							.saturating_sub(tx_conf.secondary_lock_amount),
						currency: swap.secondary_currency,
						address: self.swap_api.get_secondary_lock_address(swap, secp)?,
						required: swap.secondary_confirmations,
						actual: secondary_lock_conf.unwrap_or(0),
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
				// That can be a late or replayed Accept offer message. The offer
				// was already accepted to reach this state, so the message carries
				// no new information. Ignore it like the adjacent states do:
				// advancing to SellerSendingInitRedeemMessage here would skip the
				// InitRedeem/adaptor-signature processing below and strand the
				// trade, since that state rejects income messages.
				if message.clone().unwrap_accept_offer().is_ok() {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					));
				}

				// We can accept message durinf the wait. Byers can already get a confirmation and sending a message
				if swap.adaptor_signature.is_none() {
					let (_, init_redeem, _) = message.unwrap_init_redeem()?;
					SellApi::init_redeem(
						self.context_id,
						secp,
						&*self.keychain,
						swap,
						context,
						init_redeem,
						self.node_client.as_ref(),
					)?;
				}
				if swap.adaptor_signature.is_none() {
					return Err(Error::UnexpectedAction(
						"SellerWaitingForLockConfirmations::process, adaptor signature is missing"
							.to_string(),
					));
				}
				swap.add_journal_message("Init Redeem message is accepted".to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerSendingInitRedeemMessage,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct SellerWaitingForInitRedeemMessage<C: NodeClient, K: Keychain> {
	context_id: u32,
	keychain: Arc<K>,
	node_client: Arc<C>,
}
impl<C: NodeClient, K: Keychain> SellerWaitingForInitRedeemMessage<C, K> {
	/// Create an instance
	pub fn new(context_id: u32, keychain: Arc<K>, node_client: Arc<C>) -> Self {
		Self {
			context_id,
			keychain,
			node_client,
		}
	}
}
impl<C: NodeClient, K: Keychain> State for SellerWaitingForInitRedeemMessage<C, K> {
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForInitRedeemMessage
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let info = match swap.get_time_message_redeem() {
			Ok(deadline) => StateEtaInfo::new("Waiting For Init Redeem message").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Waiting For Init Redeem message: unable to determine deadline: {}",
				error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		true
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
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
				let secondary_confirmed = check_txs_confirmed(
					swap.secondary_currency,
					tx_conf.secondary_lock_conf,
					swap.secondary_confirmations,
				);
				if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForLockConfirmations,
					));
				}

				let time_limit = swap.get_time_message_redeem()?;
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
					SellApi::init_redeem(
						self.context_id,
						secp,
						&*self.keychain,
						swap,
						context,
						init_redeem,
						self.node_client.as_ref(),
					)?;
				}
				if swap.adaptor_signature.is_none() {
					return Err(Error::UnexpectedAction(
						"SellerWaitingForInitRedeemMessage::process, adaptor signature is missing"
							.to_string(),
					));
				}
				swap.add_journal_message("Init Redeem message is accepted".to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerSendingInitRedeemMessage,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct SellerSendingInitRedeemMessage<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain,
{
	node_client: Arc<C>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	phantom: PhantomData<&'a C>,
	message: Option<Message>,
}

impl<'a, C, K> SellerSendingInitRedeemMessage<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain,
{
	/// Create in instance
	pub fn new(node_client: Arc<C>, swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self {
			node_client,
			swap_api,
			phantom: PhantomData,
			message: None,
		}
	}
}
impl<'a, C, K> State for SellerSendingInitRedeemMessage<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerSendingInitRedeemMessage
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let info = match swap.get_time_message_redeem() {
			Ok(deadline) => StateEtaInfo::new("Sending back Redeem Message").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Sending back Redeem Message: unable to determine deadline: {}",
				error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => {
				// Checking if can redeem. The Buyer can be sneaky and try to fool us. We should assume that
				// message was delivered and buyer can do the redeem.
				if !swap.redeem_slate.slate.tx_or_err()?.kernels().is_empty() {
					if check_mwc_redeem(swap, &*self.node_client)? {
						// Buyer did a redeem, we can continue processing and redeem BTC
						swap.posted_msg2 = Some(u32::MAX as i64);
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForBuyerToRedeemMwc,
						));
					}
				}

				// Redeem is published, so we are good
				if swap.redeem_kernel_updated {
					swap.posted_msg2 = Some(u32::MAX as i64);
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				if swap.posted_msg2.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					// Check if everything is still locked...
					let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
					let secondary_confirmed = check_txs_confirmed(
						swap.secondary_currency,
						tx_conf.secondary_lock_conf,
						swap.secondary_confirmations,
					);
					if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
						swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForLockConfirmations,
						));
					}

					let time_limit = swap.get_time_message_redeem()?;
					if swap::get_cur_time() < time_limit {
						// Gate every outgoing redeem message, including early InitRedeem
						// messages that bypassed the lock-confirmation waiting state.
						if let Err(error) = self.swap_api.prepare_secondary_redeem(swap, secp) {
							if matches!(error, Error::TooManySecondaryOutputs { .. })
								&& swap.message2.is_none()
								&& swap.posted_msg2.is_none()
							{
								swap.add_journal_message(format!("Swap funding rejected: {error}"));
								return Ok(StateProcessRespond::new(
									StateId::SellerWaitingForRefundHeight,
								));
							}
							return Err(error);
						}
						if self.message.is_none() {
							self.message = swap.message2.clone();
						}
						if self.message.is_none() {
							self.message = Some(SellApi::redeem_message(swap)?);
						}
						Ok(
							StateProcessRespond::new(StateId::SellerSendingInitRedeemMessage)
								.action(Action::SellerSendRedeemMessage(
									self.message.clone().ok_or(Error::Generic(
										"Internal error, message is empty".into(),
									))?,
								))
								.time_limit(time_limit),
						)
					} else {
						// we can't cancel, we must continue to wait
						// because it is cancellation, let's do ack for this send.
						// Sending really doesn't needed any more
						swap.posted_msg2 = Some(u32::MAX as i64);
						Ok(StateProcessRespond::new(
							StateId::SellerWaitingForBuyerToRedeemMwc,
						))
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
					swap.message2 = Some(
						self.message
							.clone()
							.ok_or(Error::Generic("Internal error, message is empty".into()))?,
					);
				}
				swap.posted_msg2 = Some(swap::get_cur_time());
				swap.add_journal_message("Send response to Redeem message".to_string());

				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForBuyerToRedeemMwc,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub(crate) fn check_mwc_redeem<C: NodeClient>(
	swap: &mut Swap,
	node_client: &C,
) -> Result<bool, Error> {
	// Trying to find redeem
	if let Some((kernel, _h)) = swap.find_redeem_kernel(node_client)? {
		// Replace kernel
		let _previous_kernel = std::mem::replace(
			swap.redeem_slate
				.slate
				.tx_or_err_mut()?
				.body
				.kernels
				.get_mut(0)
				.ok_or(Error::UnexpectedAction(
					"Seller Fn required_action() redeem slate not initialized, kernels are empty"
						.to_string(),
				))?,
			kernel,
		);
		swap.redeem_kernel_updated = true;

		swap.add_journal_message(
			"Buyer redeemed MWC, transaction published on the blockchain".to_string(),
		);
		swap.ack_msg2();

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

fn calc_mwc_unlock_time(swap: &Swap, tip: &u64) -> Result<i64, Error> {
	let lock_height = swap.refund_slate.slate.calc_lock_height()?;
	// A tip beyond the lock height means the transaction is already unlocked.
	let blocks = lock_height.saturating_sub(*tip);
	let seconds_u64 = blocks.checked_mul(60).ok_or_else(|| {
		Error::DataOverflow(format!(
			"seller_swap::calc_mwc_unlock_time, MWC unlock interval overflow, blocks={} seconds_per_block=60",
			blocks
		))
	})?;
	let seconds = i64::try_from(seconds_u64).map_err(|e| {
		Error::DataOverflow(format!(
			"seller_swap::calc_mwc_unlock_time, MWC unlock interval does not fit i64, seconds={} error={}",
			seconds_u64, e
		))
	})?;
	let current_time = swap::get_cur_time();
	current_time.checked_add(seconds).ok_or_else(|| {
		Error::DataOverflow(format!(
			"seller_swap::calc_mwc_unlock_time, MWC unlock timestamp overflow, current_time={} seconds={}",
			current_time, seconds
		))
	})
}

impl<'a, C> State for SellerWaitingForBuyerToRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::SellerWaitingForBuyerToRedeemMwc
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		// Time limit is defined by the chain height
		let deadline = self
			.node_client
			.get_chain_tip()
			.map_err(Error::from)
			.and_then(|(height, _, _)| calc_mwc_unlock_time(swap, &height));
		Some(match deadline {
			Ok(deadline) => StateEtaInfo::new("Wait For Buyer to redeem MWC").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Wait For Buyer to redeem MWC: unable to determine deadline: {}",
				error
			)),
		})
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
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
				if !swap.redeem_slate.slate.tx_or_err()?.kernels().is_empty() {
					if check_mwc_redeem(swap, &*self.node_client)? {
						// Buyer did a redeem, we can continue processing and redeem BTC
						return Ok(StateProcessRespond::new(
							StateId::SellerRedeemSecondaryCurrency,
						));
					}
				}

				// Check the deadline for locking
				//
				let height = tx_conf.mwc_tip;
				if height > swap.refund_slate.slate.get_lock_height_check()? {
					swap.add_journal_message(
						"Buyer didn't redeem, time to get a refund".to_string(),
					);
					// Time to to get my MWC back with a refund.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForRefundHeight,
					));
				}

				// Check if we need to retry to send the message
				let now = swap::get_cur_time();
				if swap.posted_msg2.unwrap_or(0)
					< now.saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					if now < swap.get_time_message_redeem()? {
						return Ok(StateProcessRespond::new(
							StateId::SellerSendingInitRedeemMessage,
						));
					}
					// Stop expired retries here. Visiting the sending state just to
					// return here would trigger the state machine's cycle guard.
					// The buyer may already have the message, so keep waiting for
					// redemption or the refund height.
					swap.posted_msg2 = Some(i64::from(u32::MAX));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForBuyerToRedeemMwc)
						.action(Action::SellerWaitForBuyerRedeemPublish {
							mwc_tip: height,
							lock_height: swap.refund_slate.slate.get_lock_height_check()?,
						})
						.time_limit(calc_mwc_unlock_time(swap, &height)?),
				)
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
	secp: &mut Secp256k1,
	node_client: Arc<C>,
	swap: &Swap,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<(), Error> {
	if !tx_conf.mwc_observed {
		// Secondary redemption can proceed with its already recovered secret,
		// but unavailable MWC data cannot authorize an opportunistic refund.
		return Ok(());
	}
	let height = tx_conf.mwc_tip;
	// intentionally no checking at refund step, no failure here
	if height > swap.refund_slate.slate.get_lock_height()
		&& tx_conf.mwc_redeem_conf.is_none()
		&& tx_conf.mwc_refund_conf.is_none()
	{
		let res = swap::publish_transaction(
			context_id,
			secp,
			&*node_client,
			swap.refund_slate.slate.tx_or_err()?,
			false,
		);
		if let Err(e) = res {
			info!("MWC refund can be issued even likely it will fail. Trying to post it. get an error {}", e);
		} else {
			info!("MWC refund can be was issued, even it was expected to fail");
		}
	}
	Ok(())
}

fn bump_btc_redeem_fee<K: Keychain>(
	swap_api: &dyn SwapApi<K>,
	swap: &mut Swap,
	tx_conf: &SwapTransactionsConfirmations,
	secp: &Secp256k1,
) -> Result<(), Error> {
	if swap.secondary_currency != Currency::Btc || tx_conf.secondary_redeem_conf.unwrap_or(0) > 0 {
		return Ok(());
	}
	let attempted_height = match swap.posted_secondary_height {
		Some(height) => height,
		None => return Ok(()),
	};
	if tx_conf.secondary_tip.saturating_sub(attempted_height)
		<= state::SECONDARY_HEIGHT_TO_INCREASE_FEE
	{
		return Ok(());
	}
	let posted_fee = swap
		.secondary_data
		.unwrap_btc()?
		.tx_fee_units
		.unwrap_or(swap.secondary_fee_units);
	let rate = match (swap.secondary_fee_units, posted_fee) {
		(SecondaryFeeUnits::RatePerKvb(current), SecondaryFeeUnits::RatePerKvb(posted)) => {
			current.max(posted)
		}
		_ => return Err(Error::UnexpectedCoinType),
	};
	let proportional_fee = swap.secondary_currency.bump_secondary_fee(
		SecondaryFeeUnits::RatePerKvb(rate),
		state::SECONDARY_INCREASE_FEE_NUMERATOR,
		state::SECONDARY_INCREASE_FEE_DENOMINATOR,
	)?;
	let proportional_rate = match proportional_fee {
		SecondaryFeeUnits::RatePerKvb(rate) => rate,
		_ => return Err(Error::UnexpectedCoinType),
	};
	// A percentage-only bump can fail Bitcoin's incremental relay fee rule at
	// low rates. Add at least 1 sat/vB to cover the replacement's entire size;
	// stricter node policies can still reject it, so later attempts must be able
	// to increase the fee again in SellerRedeemSecondaryCurrency as well.
	let minimum_rate = rate
		.checked_add(state::SECONDARY_MIN_FEE_INCREASE_PER_KVB)
		.ok_or_else(|| Error::DataOverflow("BTC redeem fee rate overflow".to_string()))?;
	let increased_fee_units = SecondaryFeeUnits::RatePerKvb(proportional_rate.max(minimum_rate));
	// Keep automatic fees below half the trade amount, using the signer's size
	// calculation for all accepted inputs.
	let increased_fee = swap_api.secondary_redeem_fee(swap, increased_fee_units, secp)?;
	let doubled_fee = increased_fee
		.checked_mul(2)
		.ok_or_else(|| Error::DataOverflow("BTC redeem fee overflow".to_string()))?;
	if doubled_fee < swap.secondary_amount {
		let output_value = swap
			.secondary_amount
			.checked_sub(increased_fee)
			.ok_or_else(|| Error::DataOverflow("BTC redeem output amount underflow".to_string()))?;
		// The half-amount cap alone can still leave dust in a small trade. Keep
		// the current fee and retry settings if the signer would reject the output.
		if output_value < swap_api.secondary_redeem_minimum_output(swap)? {
			return Ok(());
		}
		swap.secondary_fee_units = increased_fee_units;
		// Start the next block delay when this fee is actually attempted. Repeated
		// checks must not keep increasing a fee that has not been submitted yet.
		swap.posted_secondary_height = None;
		swap.posted_redeem = None;
		swap.add_journal_message(format!(
			"Fee for {} redeem transaction is increased. New fee is {} {}",
			swap.secondary_currency,
			swap.secondary_fee_units,
			swap.secondary_currency.get_fee_units().0
		));
	}
	Ok(())
}

/// State SellerRedeemSecondaryCurrency
pub struct SellerRedeemSecondaryCurrency<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	context_id: u32,
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
		context_id: u32,
		keychain: Arc<K>,
		node_client: Arc<C>,
		swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	) -> Self {
		Self {
			context_id,
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let name = format!(
			"Post {} Redeem Transaction, address {}",
			swap.secondary_currency,
			swap.unwrap_seller().unwrap_or(("XXXXXX".to_string(), 0)).0
		);
		// Using script lock time as more pessimistic
		let info = match swap.get_time_btc_redeem_limit() {
			Ok(deadline) => StateEtaInfo::new(&name).end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"{}: unable to determine deadline: {}",
				name, error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => {
				// Be greedy, check the deadline for locking
				post_refund_if_possible(
					self.context_id,
					secp,
					self.node_client.clone(),
					swap,
					tx_conf,
				)?;

				if !swap.redeem_kernel_updated {
					// The data is not ready yet, so return to the waiting state.
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				bump_btc_redeem_fee(&**self.swap_api, swap, tx_conf, secp)?;

				// Check if already processed
				if let Some(secondary_redeem_conf) = tx_conf.secondary_redeem_conf {
					if secondary_redeem_conf > 0
						|| !self.swap_api.is_secondary_tx_fee_changed(swap)?
					{
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRedeemConfirmations,
						));
					}
				}

				// Ready to redeem BTC.
				Ok(
					// Using script lock time for ETA as more pessimistic
					StateProcessRespond::new(StateId::SellerRedeemSecondaryCurrency)
						.action(Action::SellerPublishTxSecondaryRedeem {
							currency: swap.secondary_currency,
							address: swap.unwrap_seller()?.0,
						})
						.time_limit(swap.get_time_btc_redeem_limit()?),
				)
			}
			Input::Execute => {
				let submission = self.swap_api.publish_secondary_transaction(
					secp,
					&*self.keychain,
					swap,
					context,
					true,
				);
				if swap.secondary_currency == Currency::Btc {
					// A rejected replacement leaves us in this state. Retain its first
					// attempt height even on error so fees can rise after the block delay;
					// resetting it on every retry would keep postponing that increase.
					swap.posted_secondary_height
						.get_or_insert(tx_conf.secondary_tip);
				}
				submission?;
				let redeem_was_recorded = match swap.secondary_currency.is_btc_family() {
					true => swap.secondary_data.unwrap_btc()?.redeem_tx.is_some(),
					false => swap.secondary_data.unwrap_eth()?.redeem_tx.is_some(),
				};
				if !redeem_was_recorded {
					return Err(Error::UnexpectedAction(
						"SellerRedeemSecondaryCurrency::process, published redeem transaction was not recorded"
							.to_string(),
					));
				}
				swap.posted_redeem = Some(swap::get_cur_time());
				swap.posted_secondary_height = Some(tx_conf.secondary_tip);
				swap.add_journal_message(format!(
					"{} redeem transaction is sent, address {}",
					swap.secondary_currency,
					swap.unwrap_seller()?.0,
				));
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRedeemConfirmations,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
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
	pub fn new(
		context_id: u32,
		node_client: Arc<C>,
		swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
	) -> Self {
		Self {
			context_id,
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(&format!(
			"Wait For {} Redeem Tx Confirmations",
			swap.secondary_currency
		)))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		if let Input::Check = input {
			// Be greedy, check the deadline for locking
			post_refund_if_possible(
				self.context_id,
				secp,
				self.node_client.clone(),
				swap,
				tx_conf,
			)?;

			bump_btc_redeem_fee(&**self.swap_api, swap, tx_conf, secp)?;

			// Just waiting
			if let Some(conf) = tx_conf.secondary_redeem_conf {
				let secondary_redeem_conf = check_txs_confirmed(
					swap.secondary_currency,
					tx_conf.secondary_redeem_conf,
					swap.secondary_confirmations,
				);
				if secondary_redeem_conf {
					let redirect_to_private_wallet = if swap.secondary_currency.is_btc_family() {
						false
					} else {
						swap.eth_redirect_to_private_wallet.ok_or_else(|| {
							Error::Generic(
								"Internal error, eth_redirect_to_private_wallet is empty".into(),
							)
						})?
					};

					if redirect_to_private_wallet {
						let address = swap.unwrap_seller()?.0;
						match self.swap_api.transfer_secondary_status(swap)? {
							SecondaryTransferStatus::NotPosted => {
								// Check and status/list operations must not move funds. Autoswap
								// or an explicit Process call executes this action.
								return Ok(StateProcessRespond::new(
									StateId::SellerWaitingForRedeemConfirmations,
								)
								.action(Action::SellerTransferSecondary {
									currency: swap.secondary_currency,
									address,
									amount: swap.secondary_amount,
								}));
							}
							SecondaryTransferStatus::Pending => {
								return Ok(StateProcessRespond::new(
									StateId::SellerWaitingForRedeemConfirmations,
								)
								.action(
									Action::SellerWaitForSecondaryTransferConfirmations {
										currency: swap.secondary_currency,
										address,
									},
								));
							}
							SecondaryTransferStatus::Failed => {
								return Err(Error::EthContractCallError(
									"Seller private-wallet redirect transaction failed; its recorded hash must be resolved before another transfer is allowed"
										.to_string(),
								));
							}
							SecondaryTransferStatus::Confirmed => {}
						}
					}
					// We are done
					swap.add_journal_message(format!(
						"{} redeem transaction has enough confirmations. Trade is complete",
						swap.secondary_currency
					));
					return Ok(StateProcessRespond::new(StateId::SellerSwapComplete));
				}

				// If transaction in the memory pool for a long time or fee is different now, we should do a retry
				if conf == 0
					&& (self.swap_api.is_secondary_tx_fee_changed(swap)?
						&& swap.posted_redeem.unwrap_or(0)
							< swap::get_cur_time()
								.saturating_sub(super::state::POST_SECONDARY_RETRY_PERIOD))
				{
					return Ok(StateProcessRespond::new(
						StateId::SellerRedeemSecondaryCurrency,
					));
				}
			} else {
				// might need to retry
				if swap.posted_redeem.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::POST_SECONDARY_RETRY_PERIOD)
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
						expected_to_be_posted: 0,
						currency: swap.secondary_currency,
						address: vec![swap.unwrap_seller()?.0],
						required: swap.secondary_confirmations,
						actual: tx_conf.secondary_redeem_conf.unwrap_or(0),
					},
				),
			);
		} else if let Input::Execute = input {
			if swap.secondary_currency.is_btc_family()
				|| !swap.eth_redirect_to_private_wallet.unwrap_or(false)
			{
				return Err(Error::InvalidSwapStateInput(
					"Seller private-wallet transfer requested for a swap that does not require it"
						.to_string(),
				));
			}

			// Accepted durability model: transfer_scondary records a successful or
			// ambiguous hash in memory and the owner persists it immediately after this
			// call. We intentionally do not persist a signed transaction before sending;
			// a crash or storage failure in that narrow window can still lose the hash.
			self.swap_api.transfer_scondary(swap)?;
			let address = swap.unwrap_seller()?.0;
			swap.add_journal_message(format!(
				"{} transfer from the internal Ethereum wallet to {} was submitted",
				swap.secondary_currency, address
			));
			Ok(StateProcessRespond::new(
				StateId::SellerWaitingForRedeemConfirmations,
			))
		} else {
			Err(Error::InvalidSwapStateInput(format!(
				"SellerWaitingForRedeemConfirmations get {:?}",
				input
			)))
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap completed"))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerSwapComplete)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Swap is cancelled, no funds was locked, no refund needed",
		))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerCancelled)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let deadline = self
			.node_client
			.get_chain_tip()
			.map_err(Error::from)
			.and_then(|(height, _, _)| calc_mwc_unlock_time(swap, &height));
		Some(match deadline {
			Ok(deadline) => StateEtaInfo::new("Wait for MWC refund to unlock").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Wait for MWC refund to unlock: unable to determine deadline: {}",
				error
			)),
		})
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => {
				// The buyer may redeem while we are waiting for a refund.
				// Resume kernel recovery and secondary-currency redemption
				// immediately when redemption has been observed.
				if swap.redeem_kernel_updated || tx_conf.mwc_redeem_conf.is_some() {
					return Ok(StateProcessRespond::new(
						StateId::SellerWaitingForBuyerToRedeemMwc,
					));
				}

				// Check the deadline for locking
				//
				let height = tx_conf.mwc_tip;
				if height > swap.refund_slate.slate.get_lock_height() {
					swap.add_journal_message("MWC funds are unlocked".to_string());
					return Ok(StateProcessRespond::new(StateId::SellerPostingRefundSlate));
				}

				// Still waiting...
				Ok(
					StateProcessRespond::new(StateId::SellerWaitingForRefundHeight)
						.action(Action::WaitForMwcRefundUnlock {
							mwc_tip: height,
							lock_height: swap.refund_slate.slate.get_lock_height(),
						})
						.time_limit(calc_mwc_unlock_time(swap, &height)?),
				)
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}
impl<'a, C> SellerPostingRefundSlate<'a, C>
where
	C: NodeClient + 'a,
{
	/// Create a new instance
	pub fn new(context_id: u32, node_client: Arc<C>) -> Self {
		Self {
			context_id,
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let times = (|| -> Result<(i64, i64), Error> {
			let (height, _, _) = self.node_client.get_chain_tip()?;
			let start = calc_mwc_unlock_time(swap, &height)?;
			let redeem_time = i64::try_from(swap.redeem_time_sec).map_err(|error| {
				Error::DataOverflow(format!("MWC refund interval does not fit i64: {}", error))
			})?;
			let end = start
				.checked_add(redeem_time)
				.ok_or_else(|| Error::DataOverflow("MWC refund deadline overflow".to_string()))?;
			Ok((start, end))
		})();
		Some(match times {
			Ok((start, end)) => StateEtaInfo::new("Post MWC Refund Slate")
				.start_time(start)
				.end_time(end),
			Err(error) => StateEtaInfo::new(&format!(
				"Post MWC Refund Slate: unable to determine refund timing: {}",
				error
			)),
		})
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
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
				if tx_conf.mwc_refund_conf.is_some() {
					return Err(Error::UnexpectedAction(
						"SellerPostingRefundSlate::process, refund transaction is already confirmed"
							.to_string(),
					));
				}
				swap::publish_transaction(
					self.context_id,
					secp,
					&*self.node_client,
					swap.refund_slate.slate.tx_or_err()?,
					false,
				)?;
				swap.posted_refund = Some(swap::get_cur_time());
				swap.add_journal_message("MWC refund slate is posted".to_string());
				Ok(StateProcessRespond::new(
					StateId::SellerWaitingForRefundConfirmations,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Wait for MWC Refund confirmations"))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
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
						< swap::get_cur_time().saturating_sub(super::state::POST_MWC_RETRY_PERIOD)
					{
						// We can retry to post
						return Ok(StateProcessRespond::new(
							StateId::SellerWaitingForRefundHeight,
						));
					}
				}

				let refund_conf = tx_conf.mwc_refund_conf.unwrap_or(0);
				if swap.mwc_confirmations > 0
					&& tx_conf
						.mwc_refund_conf
						.map(|actual| actual > swap.mwc_confirmations)
						.unwrap_or(false)
				{
					// already published.
					swap.add_journal_message("MWC refund transaction has enough confirmation. Trade is cancelled and refunded".to_string());
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
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap is cancelled, MWC are refunded"))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::SellerCancelledRefunded)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
