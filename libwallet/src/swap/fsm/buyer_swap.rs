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
use crate::swap::bitcoin::BtcRefundProgress;
use crate::swap::fsm::state::{Input, State, StateEtaInfo, StateId, StateProcessRespond};
use crate::swap::message::Message;
use crate::swap::swap;
use crate::swap::types::{check_txs_confirmed, Action, SwapTransactionsConfirmations};
use crate::swap::{BuyApi, Context, Error, Swap, SwapApi};
use crate::NodeClient;
use mwc_wallet_util::mwc_core::core::Weighting;
use mwc_wallet_util::mwc_crates::chrono::Local;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::Keychain;
use std::marker::PhantomData;
use std::sync::Arc;

// An account-based deposit can still mine after cancellation or timeout, even
// when the contract balance is zero. Keep its signed recovery on the refund path.
fn has_secondary_lock_transaction(swap: &Swap) -> Result<bool, Error> {
	if swap.secondary_currency.is_btc_family() {
		return Ok(false);
	}
	let data = swap.secondary_data.unwrap_eth()?;
	Ok(data.lock_tx.is_some() || data.lock_recovery.is_some())
}

pub(crate) fn buyer_cancellation_state(
	swap: &Swap,
	observed_lock_amount: u64,
) -> Result<StateId, Error> {
	if observed_lock_amount > 0 || has_secondary_lock_transaction(swap)? {
		Ok(StateId::BuyerWaitingForRefundTime)
	} else {
		Ok(StateId::BuyerCancelled)
	}
}

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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let dt = swap.started.with_timezone(&Local);
		let time_str = dt.format("%B %e %H:%M:%S").to_string();
		Some(StateEtaInfo::new(&format!("Get an Offer at {}", time_str)))
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
				Ok(StateProcessRespond::new(StateId::BuyerCancelled))
			}
			Input::Check => Ok(StateProcessRespond::new(
				StateId::BuyerSendingAcceptOfferMessage,
			)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Send Accept Offer Message")
				.end_time(swap.get_time_message_offers().ok()?),
		)
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(buyer_cancellation_state(
					swap,
					tx_conf.secondary_lock_amount,
				)?))
			}
			Input::Check => {
				let time_limit = swap.get_time_message_offers()?;
				if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					if swap::get_cur_time() < time_limit {
						self.message = swap.message1.clone();
						if self.message.is_none() {
							let sec_update =
								self.swap_api.build_accept_offer_message_secondary_update(
									&*self.keychain,
									swap,
								)?;
							self.message = Some(BuyApi::accept_offer_message(swap, sec_update)?);
						}
						Ok(
							StateProcessRespond::new(StateId::BuyerSendingAcceptOfferMessage)
								.action(Action::BuyerSendAcceptOfferMessage(
									self.message.clone().ok_or(Error::Generic(
										"Internal error, empty message value".into(),
									))?,
								))
								.time_limit(time_limit),
						)
					} else {
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						Ok(StateProcessRespond::new(buyer_cancellation_state(
							swap,
							tx_conf.secondary_lock_amount,
						)?))
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
					swap.message1 = Some(
						self.message
							.clone()
							.ok_or(Error::Generic("Internal error, empty message value".into()))?,
					);
				}
				swap.posted_msg1 = Some(swap::get_cur_time());
				swap.add_journal_message("Response to offer message was sent back".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForSellerToLock,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		if swap.seller_lock_first {
			Some(
				StateEtaInfo::new("Wait for seller to start locking MWC")
					.end_time(swap.get_time_start_lock().ok()?),
			)
		} else {
			None
		}
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(buyer_cancellation_state(
					swap,
					tx_conf.secondary_lock_amount,
				)?))
			}
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				let time_limit = swap.get_time_start_lock()?;
				// Check the deadline for locking
				if swap::get_cur_time() > time_limit {
					// cancelling
					swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
					return Ok(StateProcessRespond::new(buyer_cancellation_state(
						swap,
						tx_conf.secondary_lock_amount,
					)?));
				}

				if swap.wait_for_backup1 {
					return Ok(
						StateProcessRespond::new(StateId::BuyerWaitingForSellerToLock)
							.action(Action::WaitingForTradeBackup)
							.time_limit(time_limit),
					);
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
						swap.add_journal_message(
							"Seller has started locking MWC funds".to_string(),
						);
						swap.other_lock_first_done = true;
						Ok(StateProcessRespond::new(
							StateId::BuyerPostingSecondaryToMultisigAccount,
						))
					}
				}
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, secp: &Secp256k1) -> Option<StateEtaInfo> {
		let time_limit = match swap.get_time_start_lock() {
			Ok(time_limit) => time_limit,
			Err(error) => {
				// A missing ETA denotes a skipped state, so keep failures visible.
				return Some(StateEtaInfo::new(&format!(
					"Unable to determine {} funding deadline: {}",
					swap.secondary_currency, error
				)));
			}
		};
		let name = if swap.secondary_currency.is_btc_family() {
			match self.swap_api.get_secondary_lock_address(swap, secp) {
				Ok(address) => {
					debug_assert!(address.len() > 0);
					debug_assert!(address.len() <= 2);
					format!(
						"Send {} to lock account {}",
						swap.secondary_currency,
						address.join(" or ")
					)
				}
				Err(error) => format!(
					"Unable to determine {} lock address: {}",
					swap.secondary_currency, error
				),
			}
		} else {
			// Ethereum's secondary lock address is a trade identifier derived from
			// the redeem secret. Funding requires the wallet's contract call.
			format!(
				"Run 'swap --process -i {}' to deposit {} from your wallet into the swap contract. View your wallet's funding address with 'eth --info --currency {}'.",
				swap.id, swap.secondary_currency, swap.secondary_currency
			)
		};
		Some(StateEtaInfo::new(&name).end_time(time_limit))
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
				Ok(StateProcessRespond::new(buyer_cancellation_state(
					swap,
					tx_conf.secondary_lock_amount,
				)?))
			} // We can't just cancel. Funds might be posted, it is a manual process.
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				// Check if btc/eth lock is already done
				let (pending_amount, confirmed_amount, _least_confirmations) = self
					.swap_api
					.request_secondary_lock_balance(swap, swap.secondary_confirmations, secp)?;
				let chain_amount =
					pending_amount
						.checked_add(confirmed_amount)
						.ok_or_else(|| {
							Error::DataOverflow(format!(
								"BuyerWaitingForLockConfirmations::process, total secondary lock amount overflow, pending_amount={} confirmed_amount={}",
								pending_amount, confirmed_amount
							))
						})?;
				let time_limit = swap.get_time_start_lock()?;

				if chain_amount != swap.secondary_amount {
					if swap::get_cur_time() > time_limit {
						// cancelling because of timeout
						swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
						// Either observation can establish that a refund is needed.
						return Ok(StateProcessRespond::new(buyer_cancellation_state(
							swap,
							chain_amount.max(tx_conf.secondary_lock_amount),
						)?));
					}
				}

				if chain_amount < swap.secondary_amount {
					// At this point, user needs to deposit (more) Bitcoin
					// For eth, coins are locked in contract address in automatic mode,
					// so it will face this situation
					if swap.secondary_currency.is_btc_family() {
						// The enclosing branch proves chain_amount is below secondary_amount.
						#[allow(
							clippy::arithmetic_side_effects,
							reason = "chain_amount < secondary_amount proves subtraction cannot underflow"
						)]
						let amount_to_deposit = swap.secondary_amount - chain_amount;
						return Ok(StateProcessRespond::new(
							StateId::BuyerPostingSecondaryToMultisigAccount,
						)
						.action(Action::DepositSecondary {
							currency: swap.secondary_currency,
							amount: amount_to_deposit,
							address: self.swap_api.get_secondary_lock_address(swap, secp)?,
						})
						.time_limit(time_limit));
					} else {
						return Ok(StateProcessRespond::new(
							StateId::BuyerPostingSecondaryToMultisigAccount,
						)
						.action(Action::BuyerDepositToContractAccount)
						.time_limit(time_limit));
					}
				}

				let lock_address = self.swap_api.get_secondary_lock_address(swap, secp)?;
				debug_assert!(lock_address.len() > 0);
				debug_assert!(lock_address.len() <= 2);

				// Posted more then expected. We are not going forward. Deal is broken, probably it is a mistake. We are cancelling the trade because of that.
				if chain_amount > swap.secondary_amount {
					swap.add_journal_message(format!(
						"{} {}. Expected {} {}, but get {} {}",
						JOURNAL_CANCELLED_BYER_LOCK_TOO_MUCH_FUNDS,
						lock_address.join(" or "),
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

				// The next state uses tx_conf, which remains fixed for this FSM call.
				// A deposit may have arrived after that snapshot. Yield until the next
				// poll instead of cycling back here or requesting another deposit.
				if tx_conf.secondary_lock_amount != chain_amount {
					return Ok(StateProcessRespond::new(
						StateId::BuyerPostingSecondaryToMultisigAccount,
					));
				}

				swap.add_journal_message(format!(
					"{} have been posted to lock account {}",
					swap.secondary_currency,
					lock_address.join(" or ")
				));
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForLockConfirmations,
				))
			}
			Input::Execute => {
				// for btc family, buyer should deposit secondary currency manually.
				if swap.secondary_currency.is_btc_family() {
					return Err(Error::InvalidSwapStateInput(format!(
						"BuyerPostingSecondaryToMultisigAccount get {:?}",
						input
					)));
				}
				self.swap_api.post_secondary_lock_tx(swap)?;
				Ok(StateProcessRespond::new(
					StateId::BuyerPostingSecondaryToMultisigAccount,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct BuyerWaitingForLockConfirmations<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	context_id: u32,
	keychain: Arc<K>,
	node_client: Arc<C>,
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
}
impl<'a, C, K> BuyerWaitingForLockConfirmations<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	/// Create new instance
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

impl<'a, C, K> State for BuyerWaitingForLockConfirmations<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForLockConfirmations
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Wait for Locking funds confirmations")
				.end_time(swap.get_time_message_redeem().ok()?),
		)
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime)) // Long cancellation path
			}
			Input::Check => {
				// Checking if need to retry to send a message
				if tx_conf.mwc_lock_conf.is_some() {
					swap.ack_msg1();
				} else if swap.posted_msg1.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					return Ok(StateProcessRespond::new(
						StateId::BuyerSendingAcceptOfferMessage,
					));
				}

				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);

				if tx_conf.secondary_lock_amount < swap.secondary_amount {
					// The branch proves the observed amount is below the required amount.
					#[allow(
						clippy::arithmetic_side_effects,
						reason = "secondary_lock_amount < secondary_amount proves subtraction cannot underflow"
					)]
					let missing_amount = swap.secondary_amount - tx_conf.secondary_lock_amount;
					let lock_address = self.swap_api.get_secondary_lock_address(swap, secp)?;
					debug_assert!(lock_address.len() > 0);
					debug_assert!(lock_address.len() <= 2);
					swap.add_journal_message(format!(
						"Waiting for posting {} {} to lock account {}",
						swap.secondary_currency
							.amount_to_hr_string(missing_amount, true),
						swap.secondary_currency,
						lock_address.join(" or ")
					));
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
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}

				let time_limit = swap.get_time_message_redeem()?;
				let secondary_confirmed = check_txs_confirmed(
					swap.secondary_currency,
					tx_conf.secondary_lock_conf,
					swap.secondary_confirmations,
				);
				if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
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
								address: self.swap_api.get_secondary_lock_address(swap, secp)?,
								sec_expected_to_be_posted: 0,
								sec_required: swap.secondary_confirmations,
								sec_actual: tx_conf.secondary_lock_conf,
							})
							.time_limit(time_limit),
					);
				}

				// If we got here, funds have been locked on both chains with sufficient confirmations
				// On the first run - let's update the swap data
				if swap.redeem_slate.slate.participant_data.len() <= 1
					|| swap.adaptor_signature.is_none()
				{
					BuyApi::init_redeem(
						self.context_id,
						secp,
						&*self.keychain,
						swap,
						context,
						self.node_client.as_ref(),
					)?;
				}

				swap.add_journal_message(format!(
					"MWC and {} funds are Locked",
					swap.secondary_currency
				));
				Ok(StateProcessRespond::new(
					StateId::BuyerSendingInitRedeemMessage,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	context_id: u32,
	message: Option<Message>,
}
impl BuyerSendingInitRedeemMessage {
	/// Create new instance
	pub fn new(context_id: u32) -> Self {
		Self {
			context_id,
			message: None,
		}
	}
}
impl State for BuyerSendingInitRedeemMessage {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerSendingInitRedeemMessage
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let info = match swap.get_time_message_redeem() {
			Ok(deadline) => StateEtaInfo::new("Send Init Redeem Message").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Send Init Redeem Message: unable to determine deadline: {}",
				error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
	}

	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		_context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Cancel => {
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			} // Last chance to quit
			Input::Check => {
				// Check first if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_confirmed = check_txs_confirmed(
					swap.secondary_currency,
					tx_conf.secondary_lock_conf,
					swap.secondary_confirmations,
				);
				if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}
				let time_limit = swap.get_time_message_redeem()?;

				if swap.posted_msg2.unwrap_or(0)
					< swap::get_cur_time().saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
				{
					if swap::get_cur_time() < time_limit {
						if self.message.is_none() {
							self.message = swap.message2.clone();
						}
						if self.message.is_none() {
							self.message =
								Some(BuyApi::init_redeem_message(self.context_id, swap)?);
						}
						Ok(
							StateProcessRespond::new(StateId::BuyerSendingInitRedeemMessage)
								.action(Action::BuyerSendInitRedeemMessage(
									self.message.clone().ok_or(Error::Generic(
										"Internal error, empty message value".into(),
									))?,
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
					swap.message2 = Some(
						self.message
							.clone()
							.ok_or(Error::Generic("Internal error, empty message value".into()))?,
					);
				}
				swap.posted_msg2 = Some(swap::get_cur_time());
				swap.add_journal_message("Sent init redeem message".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForRespondRedeemMessage,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
pub struct BuyerWaitingForRespondRedeemMessage<C: NodeClient, K: Keychain> {
	context_id: u32,
	keychain: Arc<K>,
	node_client: Arc<C>,
}
impl<C: NodeClient, K: Keychain> BuyerWaitingForRespondRedeemMessage<C, K> {
	/// Create new instance
	pub fn new(context_id: u32, keychain: Arc<K>, node_client: Arc<C>) -> Self {
		Self {
			context_id,
			keychain,
			node_client,
		}
	}
}
impl<C: NodeClient, K: Keychain> State for BuyerWaitingForRespondRedeemMessage<C, K> {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForRespondRedeemMessage
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new("Wait For Redeem response message")
				.end_time(swap.get_time_message_redeem().ok()?),
		)
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			}
			Input::Check => {
				// Check first if everything is still locked...
				let mwc_lock = tx_conf.mwc_lock_conf.unwrap_or(0);
				let secondary_confirmed = check_txs_confirmed(
					swap.secondary_currency,
					tx_conf.secondary_lock_conf,
					swap.secondary_confirmations,
				);
				if mwc_lock < swap.mwc_confirmations || !secondary_confirmed {
					swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
					return Ok(StateProcessRespond::new(
						StateId::BuyerWaitingForLockConfirmations,
					));
				}

				if swap
					.redeem_slate
					.slate
					.tx_or_err()?
					.validate(self.context_id, Weighting::AsTransaction, secp)
					.is_ok()
				{
					// Was already processed. Can go to the next step
					return Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc));
				}

				let time_limit = swap.get_time_message_redeem()?;
				if swap::get_cur_time() < time_limit {
					if swap.posted_msg2.unwrap_or(0)
						< swap::get_cur_time()
							.saturating_sub(super::state::SEND_MESSAGE_RETRY_PERIOD)
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
					.slate
					.tx_or_err()?
					.validate(self.context_id, Weighting::AsTransaction, secp)
					.is_err()
				{
					let (_, redeem, _) = message.unwrap_redeem()?;
					BuyApi::finalize_redeem_slate(
						self.context_id,
						secp,
						&*self.keychain,
						swap,
						context,
						redeem.redeem_participant,
						self.node_client.as_ref(),
					)?;
					swap.ack_msg2();
					swap.add_journal_message("Process Redeem response message".to_string());
				}
				swap.redeem_slate
					.slate
					.tx_or_err()?
					.validate(self.context_id, Weighting::AsTransaction, secp)
					.map_err(|e| {
						Error::InvalidMessageData(format!(
							"BuyerWaitingForRespondRedeemMessage::process, finalized redeem transaction is invalid, error={}",
							e
						))
					})?;
				Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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

fn wait_for_mwc_redeem(swap: &Swap, actual: u64) -> StateProcessRespond {
	StateProcessRespond::new(StateId::BuyerWaitForRedeemMwcConfirmations).action(
		Action::WaitForMwcConfirmations {
			name: "Redeeming funds".to_string(),
			required: swap.mwc_confirmations,
			actual,
		},
	)
}

// Once the signature has been exposed, a timeout or a missing secondary lock
// must not end MWC recovery. A mined competing refund suspends retries; once
// sufficiently confirmed, it ends redemption and we resolve secondary funds.
fn check_mwc_redeem(
	swap: &mut Swap,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<StateProcessRespond, Error> {
	if tx_conf.mwc_redeem_conf.is_some() {
		swap.posted_redeem.get_or_insert_with(swap::get_cur_time);
	}
	let redeem_conf = tx_conf.mwc_redeem_conf.unwrap_or(0);
	if swap.mwc_confirmations > 0 && redeem_conf >= swap.mwc_confirmations {
		swap.add_journal_message(
			"MWC redeem transaction has enough confirmation. The Swap trade is finished"
				.to_string(),
		);
		return Ok(StateProcessRespond::new(StateId::BuyerSwapComplete));
	}
	if redeem_conf > 0 {
		return Ok(wait_for_mwc_redeem(swap, redeem_conf));
	}

	let refund_conf = tx_conf.mwc_refund_conf.unwrap_or(0);
	if refund_conf > 0 || (!swap.buyer_redeem_is_exposed() && tx_conf.mwc_refund_conf.is_some()) {
		if swap.mwc_confirmations > 0 && refund_conf >= swap.mwc_confirmations {
			swap.add_journal_message(
				"Seller's MWC refund is confirmed; stopping MWC redemption and resolving secondary funds".to_string(),
			);
			return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
		}
		return Ok(
			StateProcessRespond::new(StateId::BuyerWaitingForMwcRefundConfirmations).action(
				Action::WaitForMwcConfirmations {
					name: "Seller's MWC refund".to_string(),
					required: swap.mwc_confirmations,
					actual: refund_conf,
				},
			),
		);
	}

	let response =
		StateProcessRespond::new(StateId::BuyerRedeemMwc).action(Action::BuyerPublishMwcRedeemTx);
	if swap.buyer_redeem_is_exposed() {
		if tx_conf.mwc_redeem_conf.is_some()
			|| swap.posted_redeem.unwrap_or(0)
				>= swap::get_cur_time().saturating_sub(super::state::POST_MWC_RETRY_PERIOD)
		{
			return Ok(wait_for_mwc_redeem(swap, redeem_conf));
		}
		return Ok(response);
	}

	let time_limit = swap.get_time_mwc_redeem()?;
	if swap::get_cur_time() > time_limit {
		swap.add_journal_message(JOURNAL_CANCELLED_BY_TIMEOUT.to_string());
		return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
	}

	// Wall-clock estimates cannot ensure the refund is still height-locked.
	// Reserve the agreed confirmation window before revealing the signature.
	let confirmation_height = tx_conf
		.mwc_tip
		.checked_add(swap.mwc_confirmations)
		.ok_or_else(|| {
			Error::DataOverflow("MWC redeem confirmation height overflow".to_string())
		})?;
	if confirmation_height >= swap.refund_slate.slate.get_lock_height_check()? {
		swap.add_journal_message(
			"Not enough MWC blocks remain before refund unlock to safely publish the first redeem"
				.to_string(),
		);
		return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
	}

	let secondary_confirmed = check_txs_confirmed(
		swap.secondary_currency,
		tx_conf.secondary_lock_conf,
		swap.secondary_confirmations,
	);
	if tx_conf.mwc_lock_conf.unwrap_or(0) < swap.mwc_confirmations || !secondary_confirmed {
		swap.add_journal_message(JOURNAL_NOT_LOCKED.to_string());
		return Ok(StateProcessRespond::new(
			StateId::BuyerWaitingForLockConfirmations,
		));
	}

	Ok(response.time_limit(time_limit))
}

/// Preflight without signatures, then record exposure before signed submission.
/// The owner API supplies durable persistence; direct FSM execution also uses
/// this helper so a submission error cannot erase exposure from the live trade.
pub(crate) fn prepare_mwc_redeem<C: NodeClient>(
	context_id: u32,
	node_client: &C,
	swap: &mut Swap,
	tx_conf: &SwapTransactionsConfirmations,
	_secp: &mut Secp256k1,
	persist: impl FnOnce(&Swap) -> Result<(), Error>,
) -> Result<
	(
		StateProcessRespond,
		Option<crate::transaction_preflight::PreflightReceipt>,
	),
	Error,
> {
	let response = check_mwc_redeem(swap, tx_conf)?;
	if matches!(response.action, Some(Action::BuyerPublishMwcRedeemTx)) {
		let receipt = crate::transaction_preflight::prepare_transaction(
			context_id,
			node_client,
			swap.redeem_slate.slate.tx_or_err()?,
		)?;
		let previous_post = swap.posted_redeem;
		swap.posted_redeem = Some(swap::get_cur_time());
		if let Err(error) = persist(swap) {
			// No signing material has been disclosed. Preserve earlier exposure, but
			// a failed first preparation must still obey first-publication guards.
			swap.posted_redeem = previous_post;
			return Err(error);
		}
		return Ok((response, Some(receipt)));
	}
	Ok((response, None))
}

/// State BuyerRedeemMwc
pub struct BuyerRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	context_id: u32,
	node_client: Arc<C>,
	phantom: PhantomData<&'a C>,
}

impl<'a, C> BuyerRedeemMwc<'a, C>
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

impl<'a, C> State for BuyerRedeemMwc<'a, C>
where
	C: NodeClient + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerRedeemMwc
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		if swap.buyer_redeem_is_exposed() {
			return Some(StateEtaInfo::new("Redeem MWC"));
		}
		let info = match swap.get_time_mwc_redeem() {
			Ok(deadline) => StateEtaInfo::new("Redeem MWC").end_time(deadline),
			Err(error) => StateEtaInfo::new(&format!(
				"Redeem MWC: unable to determine deadline: {}",
				error
			)),
		};
		Some(info)
	}
	fn is_cancellable(&self, swap: &Swap) -> bool {
		!swap.buyer_redeem_is_exposed()
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
		match input {
			Input::Cancel => {
				if !self.is_cancellable(swap) || tx_conf.mwc_redeem_conf.is_some() {
					return Err(Error::InvalidSwapStateInput(
						"Cannot cancel after the MWC redeem signature may have been exposed"
							.to_string(),
					));
				}
				swap.add_journal_message(JOURNAL_CANCELLED_BY_USER.to_string());
				Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime))
			}
			Input::Check => check_mwc_redeem(swap, tx_conf),
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_redeem()?;
				Ok(StateProcessRespond::new(StateId::BuyerRedeemMwc))
			}
			Input::Execute => {
				let (response, receipt) = prepare_mwc_redeem(
					self.context_id,
					self.node_client.as_ref(),
					swap,
					tx_conf,
					secp,
					persist,
				)?;
				if !matches!(response.action, Some(Action::BuyerPublishMwcRedeemTx)) {
					return Ok(response);
				}

				// Already validated by prepare_mwc_redeem. Retain posted_redeem even
				// if the node accepted the transaction but its response was lost.
				self.node_client.post_tx(
					swap.redeem_slate.slate.tx_or_err()?,
					false,
					receipt.ok_or_else(|| {
						Error::UnexpectedAction("Missing redeem preflight".into())
					})?,
				)?;
				swap.add_journal_message("MWC Redeem slate is posted".to_string());
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitForRedeemMwcConfirmations,
				))
			}
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Wait For MWC Redeem Tx Confirmations"))
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
				// Entering this state also proves a prior broadcast for legacy trades.
				swap.posted_redeem.get_or_insert_with(swap::get_cur_time);
				check_mwc_redeem(swap, tx_conf)
			}
			Input::IncomeMessage(message) => {
				// Message must be ignored. Late delivery sometimes is possible
				// Still checking the type of the message
				let _ = message.unwrap_redeem()?;
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitForRedeemMwcConfirmations,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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

/// Suspend redemption while the competing MWC refund is being confirmed.
pub struct BuyerWaitingForMwcRefundConfirmations {}

impl BuyerWaitingForMwcRefundConfirmations {
	/// Create a new instance.
	pub fn new() -> Self {
		Self {}
	}
}

impl State for BuyerWaitingForMwcRefundConfirmations {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForMwcRefundConfirmations
	}
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Wait for seller's MWC refund confirmations",
		))
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
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			// A reorg removing the refund allows recovery of an exposed redeem.
			Input::Check | Input::Execute => check_mwc_redeem(swap, tx_conf),
			Input::IncomeMessage(message) => {
				let _ = message.unwrap_redeem()?;
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForMwcRefundConfirmations,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
				"BuyerWaitingForMwcRefundConfirmations get {:?}",
				input
			))),
		}
	}
	fn get_prev_swap_state(&self) -> Option<StateId> {
		None
	}
	fn get_next_swap_state(&self) -> Option<StateId> {
		Some(StateId::BuyerWaitingForRefundTime)
	}
}

/// Final failure, established by confirmed spending on both chains.
pub struct BuyerSwapFailed {}

impl BuyerSwapFailed {
	/// Create a new instance.
	pub fn new() -> Self {
		Self {}
	}
}

impl State for BuyerSwapFailed {
	fn get_state_id(&self) -> StateId {
		StateId::BuyerSwapFailed
	}
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Swap failed: seller refunded MWC and redeemed secondary funds",
		))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}
	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerSwapFailed)),
			_ => Err(Error::InvalidSwapStateInput(format!(
				"BuyerSwapFailed get {:?}",
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new("Swap is completed"))
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
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerSwapComplete)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, _swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(StateEtaInfo::new(
			"Swap is cancelled, no funds was locked, no refund was needed",
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
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerCancelled)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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

// An exposed redeem reaches the secondary refund path only after the competing
// MWC refund is sufficiently confirmed. Missing funds alone do not prove that
// the seller redeemed them. Avoid refunding an empty lock or reporting success
// until its outcome is known; any remaining balance still follows normal refund.
fn check_secondary_after_mwc_refund(
	swap: &mut Swap,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<Option<StateProcessRespond>, Error> {
	if !swap.buyer_redeem_is_exposed()
		|| tx_conf.secondary_lock_amount > 0
		|| tx_conf.secondary_refund_conf.is_some()
		|| tx_conf.secondary_refund_progress.is_some()
	{
		return Ok(None);
	}
	if check_txs_confirmed(
		swap.secondary_currency,
		tx_conf.secondary_redeem_conf,
		swap.secondary_confirmations,
	) {
		swap.add_journal_message(
			"Swap failed: seller's MWC refund and secondary redemption are confirmed".to_string(),
		);
		return Ok(Some(StateProcessRespond::new(StateId::BuyerSwapFailed)));
	}
	Ok(Some(
		StateProcessRespond::new(StateId::BuyerWaitingForRefundTime).action(
			Action::WaitForSecondaryConfirmations {
				name: format!(
					"{} outcome unresolved after MWC refund",
					swap.secondary_currency
				),
				expected_to_be_posted: 0,
				currency: swap.secondary_currency,
				address: vec![swap.unwrap_buyer()?.unwrap_or("XXXXX".to_string())],
				required: swap.secondary_confirmations,
				actual: tx_conf.secondary_redeem_conf.unwrap_or(0),
			},
		),
	))
}

/// State BuyerWaitingForRefundTime
pub struct BuyerWaitingForRefundTime<'a, K>
where
	K: Keychain + 'a,
{
	swap_api: Arc<Box<dyn SwapApi<K> + 'a>>,
}

impl<'a, K> BuyerWaitingForRefundTime<'a, K>
where
	K: Keychain + 'a,
{
	/// Create a new instance
	pub fn new(swap_api: Arc<Box<dyn SwapApi<K> + 'a>>) -> Self {
		Self { swap_api }
	}
}

impl<'a, K> State for BuyerWaitingForRefundTime<'a, K>
where
	K: Keychain + 'a,
{
	fn get_state_id(&self) -> StateId {
		StateId::BuyerWaitingForRefundTime
	}
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		Some(
			StateEtaInfo::new(&format!(
				"Waiting for {} to unlock",
				swap.secondary_currency
			))
			.start_time(swap.get_time_secondary_lock_publish().ok()?),
		)
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
				if let Some(response) = check_secondary_after_mwc_refund(swap, tx_conf)? {
					return Ok(response);
				}

				let cur_time = swap::get_cur_time();
				let time_limit = swap.get_time_secondary_lock_publish()?;
				if tx_conf.secondary_lock_amount == 0 && has_secondary_lock_transaction(swap)? {
					if self.swap_api.secondary_lock_tx_failed(swap)? {
						swap.add_journal_message(
							"Secondary deposit failed and is finalized; no refund is needed".into(),
						);
						return Ok(StateProcessRespond::new(StateId::BuyerCancelled));
					}
					// A pending deposit may outlive both deadlines. Keep polling it,
					// without starting another deposit or refunding an empty contract.
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime)
						.action(Action::WaitForSecondaryConfirmations {
							name: format!("{} deposit before refund", swap.secondary_currency),
							expected_to_be_posted: swap.secondary_amount,
							currency: swap.secondary_currency,
							address: self.swap_api.get_secondary_lock_address(swap, secp)?,
							required: 1,
							actual: 0,
						}));
				}
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
						address: swap.unwrap_buyer()?.unwrap_or("XXXXX".to_string()),
						required: u64::try_from(time_limit).map_err(|e| {
							Error::DataOverflow(format!(
								"BuyerWaitingForRefundTime::process, refund deadline is before the Unix epoch or does not fit u64, time_limit={} error={}",
								time_limit, e
							))
						})?,
						current: u64::try_from(cur_time).map_err(|e| {
							Error::DataOverflow(format!(
								"BuyerWaitingForRefundTime::process, current wall-clock time is before the Unix epoch or does not fit u64, current_time={} error={}",
								cur_time, e
							))
						})?,
					})
					.time_limit(time_limit))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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

/// Choose the next refund action from the complete persisted batch plan.
fn refund_plan_response(
	swap: &mut Swap,
	progress: &BtcRefundProgress,
) -> Result<StateProcessRespond, Error> {
	let plan = swap
		.secondary_data
		.unwrap_btc()?
		.refund_plan
		.as_ref()
		.ok_or_else(|| Error::Generic("Refund progress has no saved plan".into()))?;
	let mut actual = 0;
	let mut post = false;
	let mut name = format!("{} Refund", swap.secondary_currency);
	match progress {
		BtcRefundProgress::Complete => {
			let message = refund_completion_message(swap)?;
			swap.add_journal_message(message);
			return Ok(StateProcessRespond::new(StateId::BuyerCancelledRefunded));
		}
		BtcRefundProgress::NextBatch { completed_batches } => {
			// Execute is followed by Check with the pre-broadcast snapshot.
			// Do not request another batch using that stale observation.
			post = plan.batches.len() == *completed_batches;
		}
		BtcRefundProgress::WaitingForFunding => {
			name = format!("{} recorded refund deposits", swap.secondary_currency);
		}
		BtcRefundProgress::Pending {
			batch,
			confirmations,
			replacement_allowed,
			candidate_known,
			..
		} => {
			actual = confirmations.unwrap_or(0);
			let batch = plan
				.batches
				.get(*batch)
				.ok_or_else(|| Error::Generic("Refund batch is missing".into()))?;
			let attempt = batch
				.attempts
				.last()
				.ok_or_else(|| Error::Generic("Refund attempt is missing".into()))?;
			let changed = attempt.fee_units != swap.secondary_fee_units
				|| Some(attempt.address.clone()) != swap.unwrap_buyer()?;
			let retry_due = batch.last_broadcast_attempt.unwrap_or(0)
				< swap::get_cur_time().saturating_sub(super::state::POST_SECONDARY_RETRY_PERIOD);
			post =
				retry_due && actual == 0 && (!candidate_known || (*replacement_allowed && changed));
		}
	}
	if post {
		return Ok(
			StateProcessRespond::new(StateId::BuyerPostingRefundForSecondary).action(
				Action::BuyerPublishSecondaryRefundTx {
					currency: swap.secondary_currency,
					address: swap.unwrap_buyer()?.unwrap_or("XXXXXX".to_string()),
				},
			),
		);
	}
	Ok(
		StateProcessRespond::new(StateId::BuyerWaitingForRefundConfirmations).action(
			Action::WaitForSecondaryConfirmations {
				name,
				expected_to_be_posted: 0,
				currency: swap.secondary_currency,
				address: vec![swap.unwrap_buyer()?.unwrap_or("XXXXX".to_string())],
				required: swap.secondary_confirmations,
				actual,
			},
		),
	)
}

fn refund_completion_message(swap: &Swap) -> Result<String, Error> {
	let plan = swap
		.secondary_data
		.unwrap_btc()?
		.refund_plan
		.as_ref()
		.ok_or_else(|| Error::Generic("Refund plan is missing".into()))?;
	if plan.unrefunded.is_empty() {
		Ok(format!(
			"All {} refund batches have enough confirmations. The refund is redeemed.",
			swap.secondary_currency
		))
	} else {
		Ok(format!("{} refund processing finished; {} deposits totaling {} remain unrefunded because their value does not exceed their incremental fee. Their outpoints are retained in the refund plan.",
			swap.secondary_currency, plan.unrefunded.len(),
			swap.secondary_currency.amount_to_hr_string(plan.unrefunded_amount()?, true)))
	}
}

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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let address = swap
			.unwrap_buyer()
			.map(|b| b.unwrap_or("XXXXXXX".to_string()))
			.unwrap_or("XXXXXXX".to_string());
		Some(
			StateEtaInfo::new(&format!(
				"Post {} Refund to address {}",
				swap.secondary_currency, address
			))
			.start_time(swap.get_time_secondary_lock_publish().ok()?),
		)
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
				if let Some(response) = check_secondary_after_mwc_refund(swap, tx_conf)? {
					return Ok(response);
				}
				let cur_time = swap::get_cur_time();
				let time_limit = swap.get_time_secondary_lock_publish()?;
				if cur_time < time_limit {
					return Ok(StateProcessRespond::new(StateId::BuyerWaitingForRefundTime));
				}
				if let Some(progress) = &tx_conf.secondary_refund_progress {
					return refund_plan_response(swap, progress);
				}

				// Check if refund is already issued
				if let Some(secondary_refund_conf) = tx_conf.secondary_refund_conf {
					if secondary_refund_conf > 0
						|| !self.swap_api.is_secondary_tx_fee_changed(swap)?
					{
						return Ok(StateProcessRespond::new(
							StateId::BuyerWaitingForRefundConfirmations,
						));
					}
				}

				Ok(
					StateProcessRespond::new(StateId::BuyerPostingRefundForSecondary).action(
						Action::BuyerPublishSecondaryRefundTx {
							currency: swap.secondary_currency,
							address: swap.unwrap_buyer()?.unwrap_or("XXXXXX".to_string()),
						},
					),
				)
			}
			Input::Execute => {
				if let Some(response) = check_secondary_after_mwc_refund(swap, tx_conf)? {
					return Ok(response);
				}
				let refund_address = swap.unwrap_buyer()?;
				self.swap_api.post_secondary_refund_tx(
					secp,
					&*self.keychain,
					context,
					swap,
					refund_address,
					true,
				)?;
				swap.posted_refund = Some(swap::get_cur_time());
				swap.add_journal_message(format!(
					"{} refund transaction is posted (final destination: {})",
					swap.secondary_currency,
					swap.unwrap_buyer()?.unwrap_or("XXXXXX".to_string())
				));
				Ok(StateProcessRespond::new(
					StateId::BuyerWaitingForRefundConfirmations,
				))
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		let address = swap
			.unwrap_buyer()
			.map(|b| b.unwrap_or("XXXXXXX".to_string()))
			.unwrap_or("XXXXXXX".to_string());
		Some(StateEtaInfo::new(&format!(
			"Wait for {} Refund confirmations, address {}",
			swap.secondary_currency, address,
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
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => {
				if let Some(response) = check_secondary_after_mwc_refund(swap, tx_conf)? {
					return Ok(response);
				}
				if let Some(progress) = &tx_conf.secondary_refund_progress {
					return refund_plan_response(swap, progress);
				}
				if let Some(conf) = tx_conf.secondary_refund_conf {
					if check_txs_confirmed(
						swap.secondary_currency,
						tx_conf.secondary_refund_conf,
						swap.secondary_confirmations,
					) {
						// We are done
						swap.add_journal_message(format!("{} refund transaction has enough confirmations. The trade is completed, refund is redeemed.", swap.secondary_currency));
						return Ok(StateProcessRespond::new(StateId::BuyerCancelledRefunded));
					}

					if conf == 0
						&& self.swap_api.is_secondary_tx_fee_changed(swap)?
						&& swap.posted_refund.unwrap_or(0)
							< swap::get_cur_time()
								.saturating_sub(super::state::POST_SECONDARY_RETRY_PERIOD)
					{
						return Ok(StateProcessRespond::new(
							StateId::BuyerPostingRefundForSecondary,
						));
					}
				} else {
					// might need to retry
					if swap.posted_refund.unwrap_or(0)
						< swap::get_cur_time()
							.saturating_sub(super::state::POST_SECONDARY_RETRY_PERIOD)
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
							expected_to_be_posted: 0,
							currency: swap.secondary_currency,
							address: vec![swap.unwrap_buyer()?.unwrap_or("XXXXX".to_string())],
							required: swap.secondary_confirmations,
							actual: tx_conf.secondary_refund_conf.unwrap_or(0),
						},
					),
				)
			}
			_ => Err(Error::InvalidSwapStateInput(format!(
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
	fn get_eta(&self, swap: &Swap, _secp: &Secp256k1) -> Option<StateEtaInfo> {
		if swap.secondary_currency.is_btc_family()
			&& swap
				.secondary_data
				.unwrap_btc()
				.ok()?
				.refund_plan
				.as_ref()
				.is_some_and(|plan| !plan.unrefunded.is_empty())
		{
			return Some(StateEtaInfo::new(&refund_completion_message(swap).ok()?));
		}
		let address = swap
			.unwrap_buyer()
			.map(|b| b.unwrap_or("XXXXXXX".to_string()))
			.unwrap_or("XXXXXXX".to_string());
		Some(StateEtaInfo::new(&format!(
			"Swap is cancelled, {} refund is redeemed to address {}",
			swap.secondary_currency, address,
		)))
	}
	fn is_cancellable(&self, _swap: &Swap) -> bool {
		false
	}

	fn process(
		&mut self,
		input: Input,
		_swap: &mut Swap,
		_context: &Context,
		_tx_conf: &SwapTransactionsConfirmations,
		_secp: &mut Secp256k1,
	) -> Result<StateProcessRespond, Error> {
		match input {
			Input::Check => Ok(StateProcessRespond::new(StateId::BuyerCancelledRefunded)),
			_ => Err(Error::InvalidSwapStateInput(format!(
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
