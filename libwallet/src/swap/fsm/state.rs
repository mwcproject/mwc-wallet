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

use crate::swap::message::Message;
use crate::swap::swap::SwapJournalRecord;
use crate::swap::types::{Action, SwapTransactionsConfirmations};
use crate::swap::{Context, ErrorKind, Swap};
use std::fmt;

/// We need to reprty post transaction we we don't see it on the blockchain
pub const POST_MWC_RETRY_PERIOD: i64 = 300;
/// For BTC - let's use same period. BTC is visible into the mem pool quickly, so it is expected to be delivered after 5 minutes...
pub const POST_SECONDARY_RETRY_PERIOD: i64 = 300;
/// Retry period for the messages, including files
pub const SEND_MESSAGE_RETRY_PERIOD: i64 = 300;

/// Journal messages that are repeatable for State
pub const JOURNAL_CANCELLED_BY_USER: &str = "Cancelled by user";
/// Journal messages that are repeatable for State
pub const JOURNAL_CANCELLED_BY_TIMEOUT: &str = "Cancelled as expired";
/// Journal messages that are repeatable for State
pub const JOURNAL_CANCELLED_BYER_LOCK_TOO_MUCH_FUNDS: &str =
	"Cancelled because buyer posted too much funds to the Lock account";
/// Journal messages that are repeatable for State
pub const JOURNAL_NOT_LOCKED: &str = "Funds are not locking any more, switching back to waiting";

/// StateId of the swap finite state machine.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateId {
	// ---------------- Seller Happy path -----------------
	/// Seller created Offer (Initial state for Seller)
	SellerOfferCreated,
	/// Seller want to send the offer message
	SellerSendingOffer,
	/// Seller waiting for the message to be accepted
	SellerWaitingForAcceptanceMessage,
	/// Seller wait for the Buyer to start locking the funds (optional, depend on swap offer)
	SellerWaitingForBuyerLock,
	/// Seller need to post MWC lock slate
	SellerPostingLockMwcSlate,
	/// Seller waiting for Locks
	SellerWaitingForLockConfirmations,
	/// Seller waiting for InitRedeem message from the Buyer
	SellerWaitingForInitRedeemMessage,
	/// Seller responds Back to Buyer with Init redeem message
	SellerSendingInitRedeemMessage,
	/// Seller waiting when Buyer will redeem MWC
	SellerWaitingForBuyerToRedeemMwc,
	/// Seller knows the secret and now it can redeem BTC
	SellerRedeemSecondaryCurrency,
	/// Seller waiting for confirmations on BTC
	SellerWaitingForRedeemConfirmations,
	/// Seller complete the swap process
	SellerSwapComplete,

	// ------------- Seller calcellation with refund path (secondary happy path, redeem wasn't made yet) -----------------
	/// Seller waiting when Refunds can be issued.
	SellerWaitingForRefundHeight,
	/// Seller posting refund Slate
	SellerPostingRefundSlate,
	/// Seller waiting for refund confirmations
	SellerWaitingForRefundConfirmations,
	/// Seller cancelled and get a refund.
	SellerCancelledRefunded,

	/// Simple cancelled State for the seller (never was locked, refunded)
	SellerCancelled,

	// -------------- Buyer happy path ----------------
	/// Buyer offer is created (initial state for the Buyer)
	BuyerOfferCreated,
	/// Buyer sending accept offer message
	BuyerSendingAcceptOfferMessage,
	/// If Seller lock first, let's wait for that
	BuyerWaitingForSellerToLock,
	/// Buyer waiting until enough BTC will be posted to the account.
	BuyerPostingSecondaryToMultisigAccount,
	/// Wating to needed number of cinfirmations for both locks
	BuyerWaitingForLockConfirmations,
	/// Buyer sending InitRedeem message to Seller
	BuyerSendingInitRedeemMessage,
	/// Buyer waiting for a seller to respond with data to finalize Redeem slate
	BuyerWaitingForRespondRedeemMessage,
	/// Buyer post MWC redeem slate
	BuyerRedeemMwc,
	/// Buyer waiting for confirmation of the redeem.
	BuyerWaitForRedeemMwcConfirmations,
	/// Buyer is done with a swap sucessfully
	BuyerSwapComplete,

	// ------------- Buyer calcellation with refund path -----------------
	/// Waiting until BTC lock time will be expired
	BuyerWaitingForRefundTime,
	/// Posting refund BTC transaction
	BuyerPostingRefundForSecondary,
	/// Buyer waiting until BTC transaction will be confirmed
	BuyerWaitingForRefundConfirmations,
	/// Trade is cancelled and already refunded
	BuyerCancelledRefunded,

	/// SImple cencelled stated for the Buyer, nothing was locked, no refunds needed
	BuyerCancelled,
}

impl fmt::Display for StateId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let disp = match &self {
			StateId::SellerOfferCreated => "Offer is created",
			StateId::SellerSendingOffer => "Send offer message to Buyer",
			StateId::SellerWaitingForAcceptanceMessage => "Waiting for Buyer to accept an offer",
			StateId::SellerWaitingForBuyerLock => "Waiting for Buyer to start locking",
			StateId::SellerPostingLockMwcSlate => "Posting Lock MWC slate",
			StateId::SellerWaitingForLockConfirmations => "Waiting for funds to be locked",
			StateId::SellerWaitingForInitRedeemMessage => "Waiting for Buyer to init redeem",
			StateId::SellerSendingInitRedeemMessage => "Send init redeem response to Buyer",
			StateId::SellerWaitingForBuyerToRedeemMwc => "Waiting for Buyer to redeem MWC",
			StateId::SellerRedeemSecondaryCurrency => "Redeem Secondary Currency",
			StateId::SellerWaitingForRedeemConfirmations => {
				"Waiting for confirmations of Redeem transaction"
			}
			StateId::SellerSwapComplete => "Seller Swap trade is successfully complete",

			StateId::SellerWaitingForRefundHeight => "Waiting when refund Slate can be posted",
			StateId::SellerPostingRefundSlate => "Post MWC refund slate",
			StateId::SellerWaitingForRefundConfirmations => {
				"Waiting for Refund transaction confirmations"
			}
			StateId::SellerCancelledRefunded => "Seller swap was cancelled, refund was processed",
			StateId::SellerCancelled => {
				"Seller swap was cancelled, nothing was locked, no need to refund"
			}

			StateId::BuyerOfferCreated => "Offer is ready to Accept",
			StateId::BuyerSendingAcceptOfferMessage => "Send offer message to Seller",
			StateId::BuyerWaitingForSellerToLock => "Waiting for Seller to start locking",
			StateId::BuyerPostingSecondaryToMultisigAccount => {
				"Buyer posting Coins to Lock account"
			}
			StateId::BuyerWaitingForLockConfirmations => "Waiting for funds to be locked",
			StateId::BuyerSendingInitRedeemMessage => "Send Init redeem message to Seller",
			StateId::BuyerWaitingForRespondRedeemMessage => {
				"Waiting for Redeem response form Seller"
			}
			StateId::BuyerRedeemMwc => "Redeem MWC",
			StateId::BuyerWaitForRedeemMwcConfirmations => {
				"Waiting for confirmations of Redeem transaction"
			}
			StateId::BuyerSwapComplete => "Buyer Swap trade is successfully complete",

			StateId::BuyerWaitingForRefundTime => "Waiting when refund Transaction can be posted",
			StateId::BuyerPostingRefundForSecondary => "Post Refund Transaction",
			StateId::BuyerWaitingForRefundConfirmations => {
				"Waiting for Refund transaction confirmations"
			}
			StateId::BuyerCancelledRefunded => "Buyer swap cancelled, refund was processed",
			StateId::BuyerCancelled => {
				"Buyer swap was cancelled, nothing was locked, no need to refund"
			}
		};
		write!(f, "{}", disp)
	}
}

impl StateId {
	/// return true if this state is final and swap trade is done
	pub fn is_final_state(&self) -> bool {
		match self {
			StateId::SellerSwapComplete
			| StateId::BuyerSwapComplete
			| StateId::SellerCancelled
			| StateId::BuyerCancelled
			| StateId::SellerCancelledRefunded
			| StateId::BuyerCancelledRefunded => true,
			_ => false,
		}
	}

	/// Convert string name to State instance
	pub fn from_cmd_str(str: &str) -> Result<Self, ErrorKind> {
		match str {
			"SellerOfferCreated" => Ok(StateId::SellerOfferCreated),
			"SellerSendingOffer" => Ok(StateId::SellerSendingOffer),
			"SellerWaitingForAcceptanceMessage" => Ok(StateId::SellerWaitingForAcceptanceMessage),
			"SellerWaitingForBuyerLock" => Ok(StateId::SellerWaitingForBuyerLock),
			"SellerPostingLockMwcSlate" => Ok(StateId::SellerPostingLockMwcSlate),
			"SellerWaitingForLockConfirmations" => Ok(StateId::SellerWaitingForLockConfirmations),
			"SellerWaitingForInitRedeemMessage" => Ok(StateId::SellerWaitingForInitRedeemMessage),
			"SellerSendingInitRedeemMessage" => Ok(StateId::SellerSendingInitRedeemMessage),
			"SellerWaitingForBuyerToRedeemMwc" => Ok(StateId::SellerWaitingForBuyerToRedeemMwc),
			"SellerRedeemSecondaryCurrency" => Ok(StateId::SellerRedeemSecondaryCurrency),
			"SellerWaitingForRedeemConfirmations" => {
				Ok(StateId::SellerWaitingForRedeemConfirmations)
			}
			"SellerSwapComplete" => Ok(StateId::SellerSwapComplete),
			"SellerWaitingForRefundHeight" => Ok(StateId::SellerWaitingForRefundHeight),
			"SellerPostingRefundSlate" => Ok(StateId::SellerPostingRefundSlate),
			"SellerWaitingForRefundConfirmations" => {
				Ok(StateId::SellerWaitingForRefundConfirmations)
			}
			"SellerCancelledRefunded" => Ok(StateId::SellerCancelledRefunded),
			"SellerCancelled" => Ok(StateId::SellerCancelled),
			"BuyerOfferCreated" => Ok(StateId::BuyerOfferCreated),
			"BuyerSendingAcceptOfferMessage" => Ok(StateId::BuyerSendingAcceptOfferMessage),
			"BuyerWaitingForSellerToLock" => Ok(StateId::BuyerWaitingForSellerToLock),
			"BuyerPostingSecondaryToMultisigAccount" => {
				Ok(StateId::BuyerPostingSecondaryToMultisigAccount)
			}
			"BuyerWaitingForLockConfirmations" => Ok(StateId::BuyerWaitingForLockConfirmations),
			"BuyerSendingInitRedeemMessage" => Ok(StateId::BuyerSendingInitRedeemMessage),
			"BuyerWaitingForRespondRedeemMessage" => {
				Ok(StateId::BuyerWaitingForRespondRedeemMessage)
			}
			"BuyerRedeemMwc" => Ok(StateId::BuyerRedeemMwc),
			"BuyerWaitForRedeemMwcConfirmations" => Ok(StateId::BuyerWaitForRedeemMwcConfirmations),
			"BuyerSwapComplete" => Ok(StateId::BuyerSwapComplete),
			"BuyerWaitingForRefundTime" => Ok(StateId::BuyerWaitingForRefundTime),
			"BuyerPostingRefundForSecondary" => Ok(StateId::BuyerPostingRefundForSecondary),
			"BuyerWaitingForRefundConfirmations" => Ok(StateId::BuyerWaitingForRefundConfirmations),
			"BuyerCancelledRefunded" => Ok(StateId::BuyerCancelledRefunded),
			"BuyerCancelled" => Ok(StateId::BuyerCancelled),
			_ => Err(ErrorKind::Generic(format!("Unknown state value {}", str))),
		}
	}
}

/// State input
#[derive(Debug)]
pub enum Input {
	/// user request to cancel the trade.
	Cancel,

	/// Checking current Actions
	Check,

	/// Executing current action
	Execute,

	/// Process Income message
	IncomeMessage(Message),
}

/// Respond result
#[derive(Debug)]
pub struct StateProcessRespond {
	/// next state (new current state)
	pub next_state_id: StateId,
	/// next action that is expected from the user
	pub action: Option<Action>,
	/// time limit (seconds timestamp) for this action
	pub time_limit: Option<i64>,
	/// New swap journal records
	pub journal: Vec<SwapJournalRecord>,
}

impl StateProcessRespond {
	/// build reult foor state only, no action
	pub fn new(next_state_id: StateId) -> Self {
		StateProcessRespond {
			next_state_id,
			action: None,
			time_limit: None,
			journal: Vec::new(),
		}
	}

	/// Specify action for respond
	pub fn action(self, action: Action) -> Self {
		StateProcessRespond {
			next_state_id: self.next_state_id,
			action: Some(action),
			time_limit: self.time_limit,
			journal: self.journal,
		}
	}

	/// Specify time limit for respond
	pub fn time_limit(self, tl: i64) -> Self {
		StateProcessRespond {
			next_state_id: self.next_state_id,
			action: self.action,
			time_limit: Some(tl),
			journal: self.journal,
		}
	}
}

/// ETA or roadmap info the the state.
#[derive(Serialize, Deserialize)]
pub struct StateEtaInfo {
	/// True if this is current active state
	pub active: bool,
	/// Name of the state to show for user
	pub name: String,
	/// Starting time
	pub start_time: Option<i64>,
	/// Expiration time
	pub end_time: Option<i64>,
}

impl StateEtaInfo {
	/// Create a new instance for the ETA state
	pub fn new(name: &str) -> Self {
		StateEtaInfo {
			active: false,
			name: name.to_string(),
			start_time: None,
			end_time: None,
		}
	}
	/// Define ETA start time
	pub fn start_time(self, time: i64) -> Self {
		StateEtaInfo {
			active: self.active,
			name: self.name,
			start_time: Some(time),
			end_time: self.end_time,
		}
	}
	/// Define ETA end time
	pub fn end_time(self, time: i64) -> Self {
		StateEtaInfo {
			active: self.active,
			name: self.name,
			start_time: self.start_time,
			end_time: Some(time),
		}
	}
	/// Mark it as active
	pub fn active(self) -> Self {
		StateEtaInfo {
			active: true,
			name: self.name,
			start_time: self.start_time,
			end_time: self.end_time,
		}
	}
}

/// State that is describe a finite state machine
pub trait State {
	/// This state Id
	fn get_state_id(&self) -> StateId;

	/// Get a state eta. Return None for states that are never executed
	fn get_eta(&self, swap: &Swap) -> Option<StateEtaInfo>;

	/// Check if it is cancellable
	fn is_cancellable(&self) -> bool;

	/// Process the state. Result will be the next state
	fn process(
		&mut self,
		input: Input,
		swap: &mut Swap,
		context: &Context,
		tx_conf: &SwapTransactionsConfirmations,
	) -> Result<StateProcessRespond, ErrorKind>;

	/// Get the prev happy path State.
	fn get_prev_swap_state(&self) -> Option<StateId>;
	/// Get the next happy path State.
	fn get_next_swap_state(&self) -> Option<StateId>;
}
