// Copyright 2020 The MWC Develope;
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

//! Generic implementation of owner API atomic swap functions

use super::bitcoin::BtcData;
use super::error::Error;
use super::ethereum::{eth_address, to_eth_address, EthData, EthereumWallet};
use super::fsm::state::{Input, StateEtaInfo, StateId, StateProcessRespond};
use super::message::{MarketplaceMessage, Message, SecondaryUpdate, Update};
use super::owner_eth;
pub use super::swap::MarketplaceCancelNotification;
use super::swap::{IncomingMessageReceipt, Swap, SwapJournalRecord};
use super::types::{Action, Currency, Network, Role, SellerInput, SwapTransactionsConfirmations};
use super::{trades, BuyApi, Context, SwapApi};
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::ring::digest;
use mwc_wallet_util::mwc_crates::secp::{key::SecretKey, AggSigSignature, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::Mutex;

use crate::get_receive_account;
use crate::internal::selection;
use crate::proof::proofaddress::{self, ProvableAddress};
use crate::types::{bounded_escape_for_display, NodeClient, U64_DATA_IDX_ADDRESS_INDEX};
use crate::{
	wallet_lock, OutputData, OutputStatus, Slate, SwapStartArgs, TxLogEntry,
	TxLogEntryType, WalletBackend, WalletInst, WalletLCProvider,
};
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::{self, core, global};
use mwc_wallet_util::mwc_crates::chrono::Utc;
use mwc_wallet_util::mwc_crates::log::{debug, info, warn};
use mwc_wallet_util::mwc_crates::rand::{rngs::SysRng, TryRng};
use mwc_wallet_util::mwc_crates::serde_json::json;
use mwc_wallet_util::mwc_crates::uuid::{Builder as UuidBuilder, Uuid};
use mwc_wallet_util::mwc_keychain::ExtKeychainPath;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util::to_hex;
use mwc_wallet_util::mwc_web3::types::Address;
use mwc_wallet_util::RwLock;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;

lazy_static! {
	/// Offers that are online now. It is needed to answer correctly about offers status
	/// Key: offer Id,  Value: message uuid
	static ref ONLINE_OFFERS:   RwLock<HashMap<u32, HashMap<String,Uuid>>>  = RwLock::new(HashMap::new());
}

const MAX_MARKETPLACE_DISPLAY_BYTES: usize = 1024;
/// Default duration of a newly selected marketplace candidate's exclusive lease.
/// Expiry only permits checking whether the existing winner can be replaced;
/// it does not itself release the slot. A visible lock keeps the existing winner.
/// Legacy acknowledged trades without a saved lease preserve a longer hold; see
/// `probe_or_claim_marketplace_lease` and doc/atomic_swaps.md.
pub const MARKETPLACE_WINNER_LEASE_SECS: i64 = 10 * 60;
const SWAP_MESSAGE_FINGERPRINT_DOMAIN: &[u8] = b"mwc-wallet/swap-message-fingerprint/v1\0";
const SWAP_OFFER_CONTENT_FINGERPRINT_DOMAIN: &[u8] =
	b"mwc-wallet/swap-offer-content-fingerprint/v1\0";

fn mwcmqs_public_key_from_address(
	secp: &Secp256k1,
	context_id: u32,
	address: &str,
) -> Result<String, Error> {
	let address = address.strip_prefix("mwcmqs://").unwrap_or(address);
	if address.contains("://") {
		return Err(Error::InvalidMessageData(
			"Swap peer contains an invalid MWCMQS address scheme".to_string(),
		));
	}

	let mut address_parts = address.split('@');
	let public_key = address_parts.next().unwrap_or_default();
	let route = address_parts.next();
	if address_parts.next().is_some() {
		return Err(Error::InvalidMessageData(
			"Swap peer contains an invalid MWCMQS address".to_string(),
		));
	}

	// Match the MWCMQS transport grammar: the generic payment-proof parser
	// also accepts OnionV3 addresses, which cannot be used as MQS keys.
	if public_key.len() != 52 {
		return Err(Error::InvalidMessageData(
			"Swap peer contains an invalid MWCMQS public key".to_string(),
		));
	}

	if let Some(route) = route {
		let mut route_parts = route.split(':');
		let domain = route_parts.next().unwrap_or_default();
		let port = route_parts.next();
		if domain.is_empty()
			|| !domain
				.chars()
				.all(|character| character.is_ascii_alphanumeric() || character == '.')
			|| route_parts.next().is_some()
		{
			return Err(Error::InvalidMessageData(
				"Swap peer contains an invalid MWCMQS route".to_string(),
			));
		}
		if let Some(port) = port {
			// Integer parsing accepts a leading '+', but the transport requires digits only.
			if port.is_empty()
				|| !port.bytes().all(|character| character.is_ascii_digit())
				|| port.parse::<u16>().is_err()
			{
				return Err(Error::InvalidMessageData(
					"Swap peer contains an invalid MWCMQS port".to_string(),
				));
			}
		}
	}

	let address = ProvableAddress::from_str(secp, context_id, public_key).map_err(|_| {
		Error::InvalidMessageData("Swap peer contains an invalid MWCMQS public key".to_string())
	})?;
	Ok(address.public_key)
}

fn validate_mwcmqs_binding(
	secp: &Secp256k1,
	context_id: u32,
	communication_method: &str,
	communication_address: &str,
	authenticated_sender: &str,
) -> Result<(), Error> {
	if communication_method != "mwcmqs" {
		return Err(Error::InvalidMessageData(
			"Incoming MWCMQS message does not match the swap transport".to_string(),
		));
	}
	let authenticated_sender = ProvableAddress::from_str(secp, context_id, authenticated_sender)
		.map_err(|_| {
			Error::InvalidMessageData(
				"MWCMQS transport supplied an invalid authenticated sender key".to_string(),
			)
		})?;
	let expected_sender = mwcmqs_public_key_from_address(secp, context_id, communication_address)?;
	if expected_sender != authenticated_sender.public_key {
		return Err(Error::InvalidMessageData(
			"Incoming swap message sender does not match the current trade peer".to_string(),
		));
	}
	Ok(())
}

fn validate_authenticated_offer_sender(
	secp: &Secp256k1,
	context_id: u32,
	offer: &super::message::OfferUpdate,
	authenticated_sender: Option<&str>,
) -> Result<(), Error> {
	match authenticated_sender {
		Some(authenticated_sender) => validate_mwcmqs_binding(
			secp,
			context_id,
			&offer.communication_method,
			&offer.from_address,
			authenticated_sender,
		),
		None if offer.communication_method == "mwcmqs" => {
			// Tor/file delivery does not authenticate this return address, but it
			// must still be parseable before it becomes durable trade metadata.
			mwcmqs_public_key_from_address(secp, context_id, &offer.from_address).map(|_| ())
		}
		None => Ok(()),
	}
}

// Only owner-selected file imports may bypass an existing trade's MQS identity.
// Keep that provenance separate from a network message with no authenticated sender.
#[derive(Clone, Copy)]
enum SwapMessageSource<'a> {
	AuthenticatedMqs(&'a str),
	UnauthenticatedNetwork,
	OwnerFile,
}

impl<'a> SwapMessageSource<'a> {
	fn authenticated_sender(self) -> Option<&'a str> {
		match self {
			Self::AuthenticatedMqs(sender) => Some(sender),
			Self::UnauthenticatedNetwork | Self::OwnerFile => None,
		}
	}
}

fn validate_authenticated_trade_sender(
	secp: &Secp256k1,
	context_id: u32,
	swap: &Swap,
	source: SwapMessageSource<'_>,
) -> Result<(), Error> {
	match source {
		SwapMessageSource::AuthenticatedMqs(authenticated_sender) => validate_mwcmqs_binding(
			secp,
			context_id,
			&swap.communication_method,
			&swap.communication_address,
			authenticated_sender,
		),
		SwapMessageSource::UnauthenticatedNetwork if swap.communication_method == "mwcmqs" => {
			Err(Error::InvalidMessageData(
				"Incoming network messages for an MWCMQS trade require an authenticated sender"
					.to_string(),
			))
		}
		SwapMessageSource::UnauthenticatedNetwork | SwapMessageSource::OwnerFile => Ok(()),
	}
}

/// Clean up context
pub fn owner_swap_clean_context(context_id: u32) {
	let _ = ONLINE_OFFERS.write().remove(&context_id);
}

/// Register marketplace offer that is publishing now. SO now income requests are expected.
pub fn add_published_offer(context_id: u32, offer_id: String, message_uuid: Uuid) {
	let mut offers = ONLINE_OFFERS.write();

	offers
		.entry(context_id)
		.or_insert_with(|| HashMap::new())
		.insert(offer_id, message_uuid);
}

/// Unregister marketplace offer. Any incoming requests about it are not expected.
pub fn remove_published_offer(context_id: u32, message_uuid: &Uuid) {
	ONLINE_OFFERS
		.write()
		.get_mut(&context_id)
		.map(|offers| offers.retain(|_k, v| v != message_uuid));
}

pub(crate) fn get_swap_storage_key<K: Keychain>(
	secp: &Secp256k1,
	keychain: &K,
) -> Result<SecretKey, Error> {
	let path = ExtKeychainPath::new(3, 3, 2, 1, 0)?.to_identifier()?;
	Ok(keychain.derive_key(secp, 0, &path, SwitchCommitmentType::None)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EffectiveEthContracts {
	eth: String,
	erc20: String,
}

// Contract addresses identify the on-chain protocol instance that will hold the
// funds. Resolve defaults once at trade creation; unlike an Infura endpoint,
// these values must become immutable trade data rather than remain references to
// mutable wallet configuration.
fn resolve_effective_eth_contracts(
	context_id: u32,
	currency: &Currency,
	eth_override: &Option<String>,
	erc20_override: &Option<String>,
) -> Result<EffectiveEthContracts, Error> {
	let (eth, erc20) = trades::get_eth_swap_contract_addresses(
		context_id,
		currency,
		eth_override,
		erc20_override,
	)?;
	let eth = to_eth_address(eth)?;
	if eth == Address::zero() {
		return Err(Error::ZeroEthSwapContractAddress { kind: "native" });
	}
	let erc20 = to_eth_address(erc20)?;
	if erc20 == Address::zero() {
		return Err(Error::ZeroEthSwapContractAddress { kind: "ERC20" });
	}
	Ok(EffectiveEthContracts {
		eth: eth_address(eth),
		erc20: eth_address(erc20),
	})
}

fn validate_pinned_contract_address(
	pinned: &Option<String>,
	requested: &Option<String>,
	kind: &'static str,
	mismatch_error: Error,
) -> Result<(), Error> {
	let Some(requested) = requested else {
		return Ok(());
	};
	let requested = to_eth_address(requested.clone())?;
	if requested == Address::zero() {
		return Err(Error::ZeroEthSwapContractAddress { kind });
	}
	if let Some(pinned) = pinned {
		// Ethereum addresses are case-insensitive byte values, and the `0x`
		// prefix is optional. Compare parsed addresses so an equivalent spelling
		// is accepted while a different on-chain contract is rejected.
		if to_eth_address(pinned.clone())? != requested {
			return Err(mismatch_error);
		}
	}
	Ok(())
}

/// Treat contract-address arguments on an existing trade as assertions, not
/// mutable overrides.
///
/// New Ethereum-family trades always have both fields pinned at creation. The
/// `None` cases below exist only so a legacy trade can pin its first explicit
/// valid, nonzero address; after that, every supplied value must identify the
/// same contract.
fn pin_or_validate_eth_contracts(
	pinned_eth: &mut Option<String>,
	pinned_erc20: &mut Option<String>,
	requested_eth: Option<String>,
	requested_erc20: Option<String>,
) -> Result<(), Error> {
	// Validate both fields before mutating either one, so invalid input or a
	// mismatch cannot leave a partially updated pair even if a caller handles
	// the error.
	validate_pinned_contract_address(
		pinned_eth,
		&requested_eth,
		"native",
		Error::EthSwapContractAddressMismatch,
	)?;
	validate_pinned_contract_address(
		pinned_erc20,
		&requested_erc20,
		"ERC20",
		Error::ERC20SwapContractAddressMismatch,
	)?;

	if pinned_eth.is_none() {
		*pinned_eth = requested_eth;
	}
	if pinned_erc20.is_none() {
		*pinned_erc20 = requested_erc20;
	}
	Ok(())
}

fn new_marketplace_nonce_with_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Uuid, Error> {
	let mut bytes = [0u8; 16];
	rng.try_fill_bytes(&mut bytes).map_err(|e| {
		Error::Generic(format!(
			"Unable to generate marketplace nonce from the operating-system CSPRNG, {}",
			e
		))
	})?;
	Ok(UuidBuilder::from_random_bytes(bytes).into_uuid())
}

fn new_marketplace_nonce() -> Result<Uuid, Error> {
	new_marketplace_nonce_with_rng(&mut SysRng)
}

fn typed_swap_message_fingerprint(domain: &[u8], message: &Message) -> Result<String, Error> {
	let canonical_message = message.to_json()?;
	let message_len = u64::try_from(canonical_message.len()).map_err(|e| {
		Error::DataOverflow(format!("Swap message is too long to fingerprint, {}", e))
	})?;
	let mut material = Vec::with_capacity(
		domain
			.len()
			.saturating_add(std::mem::size_of::<u64>())
			.saturating_add(canonical_message.len()),
	);
	material.extend_from_slice(domain);
	material.extend_from_slice(&message_len.to_be_bytes());
	material.extend_from_slice(canonical_message.as_bytes());
	Ok(to_hex(digest::digest(&digest::SHA256, &material).as_ref()))
}

/// Fingerprint a typed message after parsing so insignificant JSON formatting
/// differences do not affect replay detection.
fn swap_message_fingerprint(message: &Message) -> Result<String, Error> {
	typed_swap_message_fingerprint(SWAP_MESSAGE_FINGERPRINT_DOMAIN, message)
}

fn incoming_protocol_message_group(update: &Update) -> Option<u32> {
	match update {
		Update::Offer(_) | Update::AcceptOffer(_) => Some(1),
		Update::InitRedeem(_) | Update::Redeem(_) => Some(2),
		Update::None | Update::MessageAcknowledge(_) => None,
	}
}

/// Fingerprint the complete typed offer payload without its peer-selected swap
/// UUID. Changing only `Message::id` must not turn one offer into a new offer.
fn swap_offer_content_fingerprint(message: &Message) -> Result<String, Error> {
	if !message.is_offer() {
		return Err(Error::UnexpectedMessageType(
			"Offer content fingerprint requires an offer message".to_string(),
		));
	}
	let mut content = message.clone();
	content.id = Uuid::nil();
	typed_swap_message_fingerprint(SWAP_OFFER_CONTENT_FINGERPRINT_DOMAIN, &content)
}

fn is_exact_offer_replay(swap: &Swap, incoming_fingerprint: &str) -> bool {
	!swap.is_seller() && swap.received_offer_fingerprint.as_deref() == Some(incoming_fingerprint)
}

/// Maximum number of unreviewed incoming offers (trades still in
/// BuyerOfferCreated) the wallet may hold open, regardless of transport or
/// authenticated identity. Every pending offer owns durable HD child indices
/// and, for Ethereum-family trades, a gas obligation, so remote peers must not
/// be able to create an unbounded number of them by rotating identities.
const MAX_PENDING_OFFERS_PER_WALLET: usize = 50;

/// Additional per-authenticated-sender limit for unreviewed incoming offers.
const MAX_PENDING_OFFERS_PER_SENDER: usize = 10;

/// Full admission check for an incoming offer, run under the wallet-context
/// creation lock before any durable key allocation. Rejects offers that
/// duplicate a stored trade by typed content, reuse MWC lock inputs of an
/// active trade (only one lock transaction can ever confirm, so every sibling
/// is a zombie trade that still burns key indices), or exceed either the
/// wallet-wide or sender-specific pending-offer allowance. The caller must hold
/// the creation lock and no per-trade lock; this routine acquires at most one
/// trade lock at a time.
#[allow(clippy::too_many_arguments)]
fn check_offer_admission(
	context_id: u32,
	secp: &Secp256k1,
	incoming_swap_id: &str,
	incoming_content_fingerprint: &str,
	incoming_lock_inputs: Option<&HashSet<String>>,
	authenticated_sender: Option<&str>,
	skey: &SecretKey,
) -> Result<(), Error> {
	let mut pending_offers_in_wallet = 0usize;
	let mut pending_offers_from_sender = 0usize;
	for existing_swap_id in trades::list_swap_trades(context_id)? {
		if existing_swap_id == incoming_swap_id {
			continue;
		}

		let existing_lock = trades::get_swap_lock(context_id, &existing_swap_id)?;
		let _existing_guard = existing_lock.lock();
		let existing_swap =
			match trades::get_swap_trade(context_id, &existing_swap_id, skey, &*existing_lock) {
				Ok((_context, swap)) => swap,
				// Explicit trade deletion does not take the creation lock. A record
				// may therefore disappear after list_swap_trades returned it.
				Err(Error::TradeNotFound(_)) => continue,
				Err(e) => return Err(e),
			};

		if existing_swap.received_offer_content_fingerprint.as_deref()
			== Some(incoming_content_fingerprint)
		{
			return Err(Error::InvalidMessageData(format!(
				"Swap offer {} duplicates existing trade {} with the same offer content",
				incoming_swap_id, existing_swap_id
			)));
		}

		if existing_swap.state.is_final_state() {
			continue;
		}

		if let Some(incoming_lock_inputs) = incoming_lock_inputs {
			for input in existing_swap
				.lock_slate
				.slate
				.tx_or_err()?
				.inputs_committed()?
			{
				let existing_commit = to_hex(&input?.0);
				if incoming_lock_inputs.contains(&existing_commit) {
					return Err(Error::InvalidMessageData(format!(
						"Swap offer {} reuses MWC lock input of active trade {}",
						incoming_swap_id, existing_swap_id
					)));
				}
			}
		}

		let is_pending_incoming_offer = !existing_swap.is_seller()
			&& existing_swap.state == StateId::BuyerOfferCreated;
		if is_pending_incoming_offer {
			pending_offers_in_wallet += 1;
		}

		if let Some(sender) = authenticated_sender {
			// Only MWCMQS trades carry a sender key here. Older offers received
			// over Tor/file may contain malformed MWCMQS return addresses. They
			// still count toward the wallet limit and undergo the duplicate/input
			// checks above, but cannot be attributed to this sender.
			if is_pending_incoming_offer
				&& existing_swap.communication_method == "mwcmqs"
				&& mwcmqs_public_key_from_address(
					secp,
					context_id,
					&existing_swap.communication_address,
				)
				.is_ok_and(|existing_sender| existing_sender == sender)
			{
				pending_offers_from_sender += 1;
			}
		}
	}

	// The sender count only advances when an authenticated sender was supplied;
	// the wallet-wide count covers every transport and identity.
	if pending_offers_from_sender >= MAX_PENDING_OFFERS_PER_SENDER {
		return Err(Error::InvalidMessageData(format!(
			"Sender already has {} pending swap offers; review or cancel them before accepting more",
			pending_offers_from_sender
		)));
	}
	if pending_offers_in_wallet >= MAX_PENDING_OFFERS_PER_WALLET {
		return Err(Error::InvalidMessageData(format!(
			"Wallet already has {} pending swap offers; review or cancel them before accepting more",
			pending_offers_in_wallet
		)));
	}
	Ok(())
}

/// Apply a fallible mutation to a clone and replace the live trade only after the
/// entire operation succeeds. Callers may therefore persist diagnostics on an
/// error without also persisting a partially mutated state-machine check.
/// Previously signed redirect hashes are refreshed independently on error so a
/// reverted payment cannot prevent its replacement IDs from reaching storage.
pub(super) fn commit_swap_on_success<T, F>(swap: &mut Swap, operation: F) -> Result<T, Error>
where
	F: FnOnce(&mut Swap) -> Result<T, Error>,
{
	let mut staged_swap = swap.clone();
	let result = match operation(&mut staged_swap) {
		Ok(result) => result,
		Err(error) => {
			super::ethereum::recovery::refresh_redirect_candidates(swap);
			return Err(error);
		}
	};
	*swap = staged_swap;
	Ok(result)
}

fn install_marketplace_cancel_notification(
	swap: &mut Swap,
	notification: MarketplaceCancelNotification,
) {
	swap.marketplace_cancel_notification_nonce = Some(notification.nonce);
	swap.pending_marketplace_cancel_notification = true;
	swap.marketplace_cancel_notification = Some(notification);
}

/// Return the immutable outbox record, migrating a legacy Boolean/nonce record
/// while the caller holds the trade lock.
fn materialize_marketplace_cancel_notification(
	swap: &mut Swap,
) -> Result<Option<MarketplaceCancelNotification>, Error> {
	if let Some(notification) = swap.marketplace_cancel_notification.clone() {
		if notification.swap_id != swap.id {
			return Err(Error::InvalidMessageData(format!(
				"Marketplace cancellation record belongs to swap {}, not {}",
				notification.swap_id, swap.id
			)));
		}
		install_marketplace_cancel_notification(swap, notification.clone());
		return Ok(Some(notification));
	}

	if !swap.pending_marketplace_cancel_notification {
		return Ok(None);
	}

	let offer_id = swap.tag.clone().ok_or_else(|| {
		Error::InvalidMessageData(format!(
			"Pending marketplace cancellation for swap {} has no marketplace offer id",
			swap.id
		))
	})?;
	let nonce = match swap.marketplace_cancel_notification_nonce {
		Some(nonce) => nonce,
		None => new_marketplace_nonce()?,
	};
	let notification = MarketplaceCancelNotification {
		swap_id: swap.id,
		offer_id,
		peer_address: swap.communication_address.clone(),
		nonce,
		signing_address_index: swap.marketplace_signing_address_index,
	};
	install_marketplace_cancel_notification(swap, notification.clone());
	Ok(Some(notification))
}

fn marketplace_lock_seen(confirmations: &SwapTransactionsConfirmations) -> bool {
	confirmations.mwc_lock_conf.is_some()
		|| confirmations.secondary_lock_conf.is_some()
		|| confirmations.secondary_lock_amount > 0
}

fn marketplace_trade_can_own_lease(swap: &Swap) -> bool {
	// Refund workflows retain their acceptance and lease metadata for recovery,
	// but no longer compete to complete the marketplace purchase.
	!swap.is_seller()
		&& swap.tag.is_some()
		&& !swap.state.is_final_state()
		&& !matches!(
			swap.state,
			StateId::BuyerWaitingForRefundTime
				| StateId::BuyerPostingRefundForSecondary
				| StateId::BuyerWaitingForRefundConfirmations
		)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarketplaceWinnerDecision {
	Wait,
	RejectNew,
	Replace,
}

/// Evaluate a saved lease and the observed chain state. `Replace` is a local
/// selection decision; it does not prove that the old peer cannot broadcast later.
fn marketplace_winner_decision(
	lock_seen: bool,
	lease_expires_at: i64,
	now: i64,
) -> MarketplaceWinnerDecision {
	if now < lease_expires_at {
		MarketplaceWinnerDecision::Wait
	} else if lock_seen {
		MarketplaceWinnerDecision::RejectNew
	} else {
		MarketplaceWinnerDecision::Replace
	}
}

/// Persist the first lease without renewing or shortening an existing selection.
fn store_marketplace_lease(
	context_id: u32,
	swap_id: &str,
	expires_at: i64,
	skey: &SecretKey,
) -> Result<(), Error> {
	let swap_lock = trades::get_swap_lock(context_id, swap_id)?;
	let Some(_guard) = swap_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace trade {} is busy; winner selection will be retried",
			swap_id
		)));
	};
	let (context, mut swap) =
		trades::get_swap_trade(context_id, swap_id, skey, &*swap_lock)?;
	if swap.marketplace_winner_lease_expires_at.is_none() {
		swap.marketplace_winner_lease_expires_at = Some(expires_at);
		swap.add_journal_message(format!(
			"Marketplace winner selected until {}",
			expires_at
		));
		trades::store_swap_trade(context_id, &context, &swap, skey, &*swap_lock)?;
	}
	Ok(())
}

/// Find or reserve the one local buyer candidate for a marketplace tag. Selecting
/// one peer before sending AcceptOffer avoids inviting several peers to lock funds
/// for a purchase that will use only one of them. Creation/import/tag changes share
/// the outer lock; an expired lease still identifies a winner until the caller
/// checks chain state and persists the replacement decision.
///
/// Compatibility policy for a legacy trade without a saved lease:
///
/// - an ordinary `posted_msg1` value gives the send time plus the default lease;
/// - `Swap::ack_msg1` replaces that time with `i64::from(u32::MAX)`. Adding the
///   lease to this marker preserves a far-future hold (4294967895, in 2106).
///   Retaining that hold is deliberate: the acknowledged peer may still lock
///   funds, and migration must not invite another peer by inventing a fresh
///   ten-minute deadline. Normal completion/cancellation can make the old record
///   final and release it before that date. This is a finite compatibility marker,
///   not the actual send time or an on-chain lock deadline.
///
/// Existing explicit leases remain authoritative, including after acknowledgement.
///
/// `Some` identifies a competing winner and its saved expiry. `None` means no
/// competing winner needs handling (the target owns a lease or is ineligible).
/// This probe does not contact either chain or cancel a selected trade.
fn probe_or_claim_marketplace_lease(
	context_id: u32,
	target_id: Uuid,
	now: i64,
	skey: &SecretKey,
) -> Result<Option<(Uuid, i64)>, Error> {
	let creation_lock = trades::get_swap_creation_lock(context_id);
	let Some(_creation_guard) = creation_lock.try_lock() else {
		return Err(Error::Generic(
			"Marketplace winner selection is busy; retry this swap shortly".to_string(),
		));
	};

	probe_or_claim_marketplace_lease_locked(context_id, target_id, now, skey)
}

/// Caller holds the context's creation lock and no trade lock. Reuse the same
/// group scan before committing a chain observation taken outside that lock.
fn probe_or_claim_marketplace_lease_locked(
	context_id: u32,
	target_id: Uuid,
	now: i64,
	skey: &SecretKey,
) -> Result<Option<(Uuid, i64)>, Error> {
	let target_id_string = target_id.to_string();
	let target_lock = trades::get_swap_lock(context_id, &target_id_string)?;
	let Some(_target_guard) = target_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace trade {} is busy; retry it shortly",
			target_id
		)));
	};
	let (_target_context, target) =
		trades::get_swap_trade(context_id, &target_id_string, skey, &*target_lock)?;
	if !marketplace_trade_can_own_lease(&target) {
		return Ok(None);
	}
	if target.marketplace_winner_lease_expires_at.is_some() {
		return Ok(None);
	}
	let target_tag = target.tag.clone().ok_or_else(|| {
		Error::Generic("Internal error: marketplace candidate has no tag".to_string())
	})?;
	let target_posted_msg1 = target.posted_msg1;
	drop(_target_guard);

	// A legacy candidate that already sent AcceptOffer is the existing winner.
	// Preserve both real send times and the acknowledgement hold described above.
	if let Some(posted_at) = target_posted_msg1 {
		let expires_at = posted_at
			.checked_add(MARKETPLACE_WINNER_LEASE_SECS)
			.ok_or_else(|| Error::DataOverflow("Marketplace lease overflow".to_string()))?;
		store_marketplace_lease(context_id, &target_id_string, expires_at, skey)?;
		return Ok(None);
	}

	let mut winner = None;
	for swap_id in trades::list_swap_trades(context_id)? {
		if swap_id == target_id_string {
			continue;
		}
		let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
		let Some(_guard) = swap_lock.try_lock() else {
			return Err(Error::Generic(format!(
				"Marketplace trade {} is busy; winner selection will be retried",
				swap_id
			)));
		};
		let (context, mut swap) =
			trades::get_swap_trade(context_id, &swap_id, skey, &*swap_lock)?;
		if !marketplace_trade_can_own_lease(&swap)
			|| swap.tag.as_deref() != Some(target_tag.as_str())
		{
			continue;
		}
		let expires_at = match (
			swap.marketplace_winner_lease_expires_at,
			swap.posted_msg1,
		) {
			(Some(expires_at), _) => expires_at,
			(None, Some(posted_at)) => {
				// Apply the same legacy policy to a competing winner. In particular,
				// do not clamp the acknowledgement marker to `now` or expire it.
				let expires_at = posted_at
					.checked_add(MARKETPLACE_WINNER_LEASE_SECS)
					.ok_or_else(|| Error::DataOverflow("Marketplace lease overflow".to_string()))?;
				swap.marketplace_winner_lease_expires_at = Some(expires_at);
				trades::store_swap_trade(context_id, &context, &swap, skey, &*swap_lock)?;
				expires_at
			}
			(None, None) => continue,
		};
		if winner.replace((swap.id, expires_at)).is_some() {
			return Err(Error::Generic(format!(
				"Marketplace offer {} has more than one selected trade",
				target_tag
			)));
		}
	}

	match winner {
		Some(winner) => Ok(Some(winner)),
		None => {
			let expires_at = now
				.checked_add(MARKETPLACE_WINNER_LEASE_SECS)
				.ok_or_else(|| Error::DataOverflow("Marketplace lease overflow".to_string()))?;
			store_marketplace_lease(context_id, &target_id_string, expires_at, skey)?;
			Ok(None)
		}
	}
}

/// Save local cancellation and its durable notification. Delivery/acknowledgement
/// happens separately; this write alone does not stop the peer from locking funds.
fn cancel_marketplace_trade_locked(
	context_id: u32,
	context: &Context,
	swap: &mut Swap,
	reason: &str,
	skey: &SecretKey,
	swap_lock: &Mutex<()>,
) -> Result<Option<MarketplaceCancelNotification>, Error> {
	let cancellation_state = if swap.is_seller() {
		StateId::SellerCancelled
	} else {
		// No visible lock does not rule out a submitted deposit that mines later.
		super::fsm::buyer_swap::buyer_cancellation_state(swap, 0)?
	};
	swap.add_journal_message(reason.to_string());
	swap.state = cancellation_state;
	swap.pending_marketplace_cancel_notification = true;
	let notification = match materialize_marketplace_cancel_notification(swap) {
		Ok(notification) => notification,
		Err(e) => {
			warn!(
				"Marketplace trade {} was cancelled, but its rejection will be materialized later: {}",
				swap.id, e
			);
			None
		}
	};
	trades::store_swap_trade(context_id, context, swap, skey, swap_lock)?;
	Ok(notification)
}

fn marketplace_tx_confirmations<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	context_id: u32,
	skey: &SecretKey,
	swap_id: Uuid,
) -> Result<SwapTransactionsConfirmations, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (node_client, ethereum_wallet, keychain, current_context_id) = {
		wallet_lock!(wallet_inst, w);
		(
			w.w2n_client().clone(),
			w.get_ethereum_wallet(keychain_mask)?,
			w.keychain(secp, keychain_mask)?,
			w.get_context_id(),
		)
	};
	if current_context_id != context_id {
		return Err(Error::Generic(
			"Wallet context changed while checking the marketplace winner".to_string(),
		));
	}

	let swap_id = swap_id.to_string();
	let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
	let Some(guard) = swap_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace winner {} is busy; retry the new offer later",
			swap_id
		)));
	};
	let (_context, mut swap) =
		trades::get_swap_trade(context_id, &swap_id, skey, &*swap_lock)?;
	drop(guard);

	request_swap_tx_confirmations(
		context_id,
		secp,
		node_client,
		ethereum_wallet,
		&keychain,
		&mut swap,
	)
}

/// Apply the existing winner policy before processing a new candidate. An
/// unexpired selection blocks it; after expiry, lookup errors defer selection
/// and an observed lock rejects the newcomer. With no visible lock, the current
/// workflow cancels the old record locally before selecting the replacement.
/// Cancellation delivery is asynchronous, so this is local exclusivity rather
/// than a protocol guarantee against late locks by a previously accepted peer.
fn prepare_marketplace_winner_lease<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	target_id: Uuid,
) -> Result<Vec<MarketplaceCancelNotification>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context_id, skey) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		(w.get_context_id(), get_swap_storage_key(secp, &keychain)?)
	};
	let target_id_string = target_id.to_string();
	let target_lock = trades::get_swap_lock(context_id, &target_id_string)?;
	let Some(_target_guard) = target_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace trade {} is busy; retry it shortly",
			target_id
		)));
	};
	let (_context, target) =
		trades::get_swap_trade(context_id, &target_id_string, &skey, &*target_lock)?;
	let needs_selection = !target.is_seller()
		&& target.tag.is_some()
		&& !target.state.is_final_state()
		&& target.marketplace_winner_lease_expires_at.is_none()
		&& target.posted_msg1.is_none()
		&& matches!(
			target.state,
			StateId::BuyerOfferCreated | StateId::BuyerSendingAcceptOfferMessage
		);
	drop(_target_guard);
	if !needs_selection {
		return Ok(Vec::new());
	}
	let now = super::swap::get_cur_time();
	let Some((winner_id, expected_expiration)) = probe_or_claim_marketplace_lease(
		context_id,
		target_id,
		now,
		&skey,
	)? else {
		return Ok(Vec::new());
	};

	// While the saved selection is unexpired, do not contact either chain or
	// answer the new candidate. This includes the legacy acknowledgement hold;
	// it is not necessarily ten minutes. The selected trade's own workflow can
	// still progress or cancel it, and the new candidate can retry later.
	if marketplace_winner_decision(
		false,
		expected_expiration,
		super::swap::get_cur_time(),
	) == MarketplaceWinnerDecision::Wait
	{
		return Err(Error::Generic(format!(
			"Marketplace trade {} is selected until {}; retry trade {} later",
			winner_id, expected_expiration, target_id
		)));
	}

	// Once the saved lease expires, a lookup failure is not evidence that the
	// old winner failed to lock. Leave both records unchanged and retry later.
	// A successful lookup is only a snapshot of visible funds; it cannot revoke
	// the acceptance already sent or rule out a later broadcast by that peer.
	let confirmations = marketplace_tx_confirmations(
		wallet_inst,
		secp,
		keychain_mask,
		context_id,
		&skey,
		winner_id,
	)?;
	apply_marketplace_winner_observation(
		context_id,
		target_id,
		(winner_id, expected_expiration),
		&confirmations,
		&skey,
	)
}

/// Revalidate group ownership and persist the decision after the chain lookup.
fn apply_marketplace_winner_observation(
	context_id: u32,
	target_id: Uuid,
	expected_winner: (Uuid, i64),
	confirmations: &SwapTransactionsConfirmations,
	skey: &SecretKey,
) -> Result<Vec<MarketplaceCancelNotification>, Error> {
	let (winner_id, expected_expiration) = expected_winner;
	let lock_seen = marketplace_lock_seen(confirmations);
	let winner_decision =
		marketplace_winner_decision(lock_seen, expected_expiration, super::swap::get_cur_time());
	if winner_decision == MarketplaceWinnerDecision::Wait {
		return Err(Error::Generic(
			"Marketplace winner lease has not expired; retry shortly".to_string(),
		));
	}

	let creation_lock = trades::get_swap_creation_lock(context_id);
	let Some(_creation_guard) = creation_lock.try_lock() else {
		return Err(Error::Generic(
			"Marketplace winner selection changed while checking the chain; retry shortly"
				.to_string(),
		));
	};

	// Another candidate may have replaced the observed winner during the lookup.
	// Inspect the entire group while holding the same lock used to grant leases;
	// seeing only that the old winner is cancelled does not prove the slot is free.
	match probe_or_claim_marketplace_lease_locked(
		context_id,
		target_id,
		super::swap::get_cur_time(),
		skey,
	)? {
		None => return Ok(Vec::new()),
		Some(current_winner) if current_winner == expected_winner => {}
		Some(_) => {
			return Err(Error::Generic(
				"Marketplace winner changed while checking the chain; retry shortly".to_string(),
			));
		}
	}

	let target_id_string = target_id.to_string();
	let target_lock = trades::get_swap_lock(context_id, &target_id_string)?;
	let Some(_target_guard) = target_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace trade {} is busy; retry it shortly",
			target_id
		)));
	};
	let (_target_context, target) =
		trades::get_swap_trade(context_id, &target_id_string, skey, &*target_lock)?;
	if target.marketplace_winner_lease_expires_at.is_some()
		|| !marketplace_trade_can_own_lease(&target)
	{
		return Ok(Vec::new());
	}
	let target_tag = target.tag.clone().ok_or_else(|| {
		Error::Generic("Internal error: marketplace candidate has no tag".to_string())
	})?;
	drop(_target_guard);

	let winner_id_string = winner_id.to_string();
	let winner_lock = trades::get_swap_lock(context_id, &winner_id_string)?;
	let Some(_winner_guard) = winner_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Marketplace winner {} is busy; retry the new offer shortly",
			winner_id
		)));
	};
	let winner_record = trades::get_swap_trade(context_id, &winner_id_string, skey, &*winner_lock);
	let mut notification = None;
	match winner_record {
		Ok((winner_context, mut winner)) => {
			if !marketplace_trade_can_own_lease(&winner)
				|| winner.tag.as_deref() != Some(target_tag.as_str())
			{
				// The old slot was released while its chain state was being checked.
			} else if winner.marketplace_winner_lease_expires_at != Some(expected_expiration) {
				return Err(Error::Generic(
					"Marketplace winner changed while checking the chain; retry shortly"
						.to_string(),
				));
			} else if winner_decision == MarketplaceWinnerDecision::RejectNew {
				drop(_winner_guard);
				let target_lock = trades::get_swap_lock(context_id, &target_id_string)?;
				let Some(_target_guard) = target_lock.try_lock() else {
					return Err(Error::Generic(format!(
						"Marketplace trade {} is busy; retry it shortly",
						target_id
					)));
				};
				let (target_context, mut target) =
					trades::get_swap_trade(context_id, &target_id_string, skey, &*target_lock)?;
				cancel_marketplace_trade_locked(
					context_id,
					&target_context,
					&mut target,
					"Rejected because another marketplace trade has started locking funds",
					skey,
					&*target_lock,
				)?;
				return Err(Error::Generic(format!(
					"Marketplace trade {} has started locking funds; offer {} was rejected",
					winner_id, target_id
				)));
			} else {
				notification = cancel_marketplace_trade_locked(
					context_id,
					&winner_context,
					&mut winner,
					"Cancelled after its 10-minute marketplace winner lease expired without a visible lock transaction",
					skey,
					&*winner_lock,
				)?;
			}
		}
		Err(Error::TradeNotFound(_)) => {}
		Err(e) => return Err(e),
	}
	drop(_winner_guard);

	let expires_at = super::swap::get_cur_time()
		.checked_add(MARKETPLACE_WINNER_LEASE_SECS)
		.ok_or_else(|| Error::DataOverflow("Marketplace lease overflow".to_string()))?;
	store_marketplace_lease(context_id, &target_id_string, expires_at, skey)?;
	Ok(notification.into_iter().collect())
}

fn validate_imported_incoming_receipt(
	existing: &Option<IncomingMessageReceipt>,
	imported: &Option<IncomingMessageReceipt>,
	message_group: u32,
) -> Result<(), Error> {
	match (existing.as_ref(), imported.as_ref()) {
		(Some(existing_receipt), Some(imported_receipt))
			if existing_receipt != imported_receipt =>
		{
			return Err(Error::InvalidMessageData(format!(
				"Imported trade conflicts with the live processed-message receipt for group {}",
				message_group
			)));
		}
		(Some(_), None) => {
			// The receipt and the message's effects (for example, the adaptor
			// signature from InitRedeem) were committed together. Copying only the
			// receipt would acknowledge redelivery without restoring those effects.
			return Err(Error::InvalidMessageData(format!(
				"Imported trade predates the processed incoming message for group {}; retain the live trade or use a newer backup",
				message_group
			)));
		}
		_ => {}
	}
	Ok(())
}

fn validate_imported_eth_recovery(existing: &EthData, imported: &EthData) -> Result<(), Error> {
	let hashes_retained = [
		(existing.erc20_approve_tx, imported.erc20_approve_tx),
		(existing.lock_tx, imported.lock_tx),
		(existing.refund_tx, imported.refund_tx),
		(existing.redeem_tx, imported.redeem_tx),
	]
	.into_iter()
	.all(|(existing, imported)| existing.is_none_or(|hash| imported == Some(hash)));
	let recovery_retained = [
		(
			&existing.erc20_approval_recovery,
			&imported.erc20_approval_recovery,
		),
		(&existing.lock_recovery, &imported.lock_recovery),
		(&existing.lock_cancel_recovery, &imported.lock_cancel_recovery),
		(&existing.refund_recovery, &imported.refund_recovery),
		(&existing.redeem_recovery, &imported.redeem_recovery),
	]
	.into_iter()
	.all(|(existing, imported)| {
		existing
			.as_ref()
			.is_none_or(|record| imported.as_ref() == Some(record))
	});
	let funding_retained = existing
		.erc20_funding
		.is_none_or(|funding| imported.erc20_funding == Some(funding));
	let history_retained = existing
		.erc20_approval_history
		.iter()
		.all(|record| imported.erc20_approval_history.contains(record));
	if !hashes_retained || !recovery_retained || !funding_retained || !history_retained {
		// These records rebuild nonce/allowance reservations after a restart.
		// Chain polling cannot recover missing signed bytes or unmined replacements,
		// and merging independent funding phases could revive a cancelled deposit.
		return Err(Error::InvalidMessageData(
			"Imported trade would discard or replace live Ethereum transaction recovery; retain the live trade or use a backup with matching recovery records"
				.to_string(),
		));
	}
	Ok(())
}

fn validate_imported_btc_recovery(existing: &BtcData, imported: &BtcData) -> Result<(), Error> {
	// Compare complete records, including output values and heights: Output's
	// PartialEq compares only outpoints. A plan also retains signed replacements
	// and carry outputs that cannot be rediscovered at the original lock address.
	if existing
		.refund_tx
		.is_some_and(|hash| imported.refund_tx != Some(hash))
		|| (existing.refund_transaction.is_some()
			&& serde_json::to_value(&existing.refund_transaction)?
				!= serde_json::to_value(&imported.refund_transaction)?)
		|| (existing.refund_plan.is_some()
			&& serde_json::to_value(&existing.refund_plan)?
				!= serde_json::to_value(&imported.refund_plan)?)
	{
		return Err(Error::InvalidMessageData(
			"Imported trade would discard or replace live BTC refund recovery; retain the live trade or use a backup with matching recovery records"
				.to_string(),
		));
	}
	// The seller freezes these inputs before exposing its MWC redeem signature;
	// a later spend can hide them from listunspent. Compare their complete records
	// too, and retain every redemption hash even when retries or fee replacements
	// move it between the current transaction and candidate history.
	let imported_hashes: HashSet<_> = imported
		.redeem_tx
		.iter()
		.chain(&imported.redeem_tx_candidates)
		.copied()
		.collect();
	let hashes_retained = existing
		.redeem_tx
		.iter()
		.chain(&existing.redeem_tx_candidates)
		.all(|hash| imported_hashes.contains(hash));
	// Hashes alone cannot recover scriptSig variants. A backup must also keep
	// the signed bytes for every attempt, even after later fee replacements.
	let attempts_retained = existing.redeem_attempts.iter().all(|attempt| {
		imported
			.redeem_attempts
			.iter()
			.any(|other| other.txid == attempt.txid && other.tx == attempt.tx)
	});
	if !hashes_retained
		|| !attempts_retained
		|| (existing.redeem_inputs.is_some()
			&& serde_json::to_value(&existing.redeem_inputs)?
				!= serde_json::to_value(&imported.redeem_inputs)?)
	{
		return Err(Error::InvalidMessageData(
			"Imported trade would discard or replace live BTC redemption recovery; retain the live trade or use a backup with matching inputs, all known redemption hashes and signed attempts"
				.to_string(),
		));
	}
	Ok(())
}

fn buyer_redeem_exposure_recorded(swap: &Swap) -> bool {
	// Legacy records may lack the timestamp even though their state proves that
	// the signed redeem was published. Retain this evidence before changing state.
	swap.buyer_redeem_is_exposed()
		|| (!swap.is_seller()
			&& matches!(
				swap.state,
				StateId::BuyerWaitForRedeemMwcConfirmations | StateId::BuyerSwapComplete
			))
}

/// Keep replay/outbox state from the live record authoritative when importing
/// a backup over the same UUID. Reject backups that discard seller lock exposure,
/// seller redeem signing data, buyer redeem exposure, observed seller redeem
/// kernels, accepted cancellations, processed messages or transaction recovery
/// before changing either record.
/// Compatible protocol state may be restored, but a stale backup must not replace
/// a pending notification or resurrect one that the live record already completed.
fn reconcile_imported_replay_state(existing: &mut Swap, imported: &mut Swap) -> Result<(), Error> {
	if existing.id != imported.id
		|| existing.is_seller() != imported.is_seller()
		|| existing.secondary_currency != imported.secondary_currency
	{
		return Err(Error::InvalidMessageData(
			"Imported trade does not match the live trade's UUID, role or currency".to_string(),
		));
	}
	// A submitted lock may still confirm even when the node cannot see it.
	// Losing this marker would let import cancel the trade without a refund.
	if existing.is_seller() && existing.posted_lock.is_some() && imported.posted_lock.is_none() {
		return Err(Error::InvalidMessageData(
			"Imported trade predates the seller's MWC lock exposure; \
			 retain the live trade or use a newer backup"
				.to_string(),
		));
	}
	// File delivery and legacy records may have no incoming-message receipt.
	// Once InitRedeem is processed, retain the adaptor signature and participant
	// signing data needed to extract the secret when the buyer redeems MWC. A
	// newer backup may add the observed kernel without changing this data.
	if existing.is_seller()
		&& existing.adaptor_signature.is_some()
		&& (existing.adaptor_signature != imported.adaptor_signature
			|| existing.redeem_public != imported.redeem_public
			|| existing.participant_id != imported.participant_id
			|| existing.redeem_slate.slate.participant_data
				!= imported.redeem_slate.slate.participant_data)
	{
		return Err(Error::InvalidMessageData(
			"Imported trade would discard or replace the seller's redeem signing data; retain the live trade or use a backup with matching adaptor signature and participant data"
				.to_string(),
		));
	}
	// An observed redeem kernel supplies the seller's secondary redemption secret.
	// A reorg can hide it from the node, so a backup must retain that evidence.
	if existing.is_seller()
		&& existing.redeem_kernel_updated
		&& (!imported.redeem_kernel_updated
			|| serde_json::to_value(existing.redeem_slate.slate.tx_or_err()?)?
				!= serde_json::to_value(imported.redeem_slate.slate.tx_or_err()?)?)
	{
		return Err(Error::InvalidMessageData(
			"Imported trade would discard or replace the seller's observed MWC redeem transaction; retain the live trade or use a backup with the same observed transaction"
				.to_string(),
		));
	}
	// A broadcast may have revealed the buyer's redeem secret even when
	// the transaction is no longer visible to the node.
	if buyer_redeem_exposure_recorded(existing) {
		if !buyer_redeem_exposure_recorded(imported) {
			return Err(Error::InvalidMessageData(
				"Imported trade predates the buyer's MWC redeem exposure; \
				 retain the live trade or use a newer backup"
					.to_string(),
			));
		}
		if serde_json::to_value(existing.redeem_slate.slate.tx_or_err()?)?
			!= serde_json::to_value(imported.redeem_slate.slate.tx_or_err()?)?
		{
			return Err(Error::InvalidMessageData(
				"Imported trade would replace the buyer's exposed MWC redeem transaction; retain the live trade or use a backup with the same signed transaction"
					.to_string(),
			));
		}
	}

	// The cancellation receipt and its state transition belong together.
	// Require the backup to retain the same accepted cancellation.
	if let Some(existing_nonce) = existing.marketplace_received_cancel_nonce {
		if imported.marketplace_received_cancel_nonce != Some(existing_nonce) {
			return Err(Error::InvalidMessageData(
				"Imported trade would discard or replace the accepted \
				 marketplace cancellation; retain the live trade or use \
				 a backup with the same cancellation receipt"
					.to_string(),
			));
		}
	}

	validate_imported_incoming_receipt(
		&existing.processed_incoming_ack1,
		&imported.processed_incoming_ack1,
		1,
	)?;
	validate_imported_incoming_receipt(
		&existing.processed_incoming_ack2,
		&imported.processed_incoming_ack2,
		2,
	)?;
	if existing.secondary_currency.is_btc_family() {
		validate_imported_btc_recovery(
			existing.secondary_data.unwrap_btc()?,
			imported.secondary_data.unwrap_btc()?,
		)?;
	} else {
		validate_imported_eth_recovery(
			existing.secondary_data.unwrap_eth()?,
			imported.secondary_data.unwrap_eth()?,
		)?;
	}

	// A stale backup must not change which candidate currently owns the local
	// marketplace lease or move that lease into a different offer group.
	imported.marketplace_winner_lease_expires_at =
		existing.marketplace_winner_lease_expires_at;
	if existing.marketplace_winner_lease_expires_at.is_some() {
		imported.tag = existing.tag.clone();
	}

	if existing.marketplace_cancel_notification.is_some() {
		let existing_notification = materialize_marketplace_cancel_notification(existing)?
			.ok_or_else(|| {
				Error::Generic(
					"Internal error: live marketplace cancellation disappeared during import"
						.to_string(),
				)
			})?;
		// A legacy backup may carry only the old Boolean marker. The full live
		// record is authoritative, so only a conflicting full record is rejected.
		if imported.marketplace_cancel_notification.is_some() {
			let imported_notification = materialize_marketplace_cancel_notification(imported)?
				.ok_or_else(|| {
					Error::Generic(
						"Internal error: imported marketplace cancellation disappeared"
							.to_string(),
					)
				})?;
			if imported_notification != existing_notification {
				return Err(Error::InvalidMessageData(
					"Imported trade contains a different pending marketplace cancellation"
						.to_string(),
				));
			}
		}
		install_marketplace_cancel_notification(imported, existing_notification);
	} else {
		// A backup may be the only remaining copy of a legacy pending record's
		// tag/address. Reuse the live nonce before materializing that backup so
		// restoration does not accidentally create a different outbox event.
		if imported.marketplace_cancel_notification.is_none() {
			if existing.pending_marketplace_cancel_notification {
				imported.pending_marketplace_cancel_notification = true;
			}
			if imported.pending_marketplace_cancel_notification
				&& imported.marketplace_cancel_notification_nonce.is_none()
			{
				imported.marketplace_cancel_notification_nonce =
					existing.marketplace_cancel_notification_nonce;
			}
		}
		let imported_notification = materialize_marketplace_cancel_notification(imported)?;
		if existing.pending_marketplace_cancel_notification
			&& existing.marketplace_cancel_notification_nonce.is_none()
		{
			// A Boolean-only live record must share the backup's migration nonce.
			// Generating one independently would falsely conflict with the same event.
			existing.marketplace_cancel_notification_nonce = imported_notification
				.as_ref()
				.map(|notification| notification.nonce);
		}
		let existing_notification =
			match materialize_marketplace_cancel_notification(existing) {
				Ok(notification) => notification,
				Err(existing_error) if existing.pending_marketplace_cancel_notification => {
					match imported_notification.clone() {
						Some(imported_notification)
							if existing
								.marketplace_cancel_notification_nonce
								.is_none_or(|nonce| nonce == imported_notification.nonce) =>
						{
							install_marketplace_cancel_notification(
								existing,
								imported_notification.clone(),
							);
							Some(imported_notification)
						}
						_ => return Err(existing_error),
					}
				}
				Err(e) => return Err(e),
			};

		match existing_notification {
			Some(existing_notification) => {
				if imported_notification
					.as_ref()
					.is_some_and(|notification| notification != &existing_notification)
				{
					return Err(Error::InvalidMessageData(
						"Imported trade contains a different pending marketplace cancellation"
							.to_string(),
					));
				}
				install_marketplace_cancel_notification(imported, existing_notification);
			}
			None if existing.marketplace_cancel_notification_nonce.is_some() => {
				if imported_notification.as_ref().is_some_and(|notification| {
					Some(notification.nonce) != existing.marketplace_cancel_notification_nonce
				}) {
					return Err(Error::InvalidMessageData(
						"Imported trade contains a marketplace cancellation that conflicts with the completed live record"
							.to_string(),
					));
				}
				imported.marketplace_cancel_notification = None;
				imported.pending_marketplace_cancel_notification = false;
				imported.marketplace_cancel_notification_nonce =
					existing.marketplace_cancel_notification_nonce;
			}
			None => {}
		}
	}

	match (
		existing.received_offer_fingerprint.as_ref(),
		imported.received_offer_fingerprint.as_ref(),
	) {
		(Some(existing_fingerprint), Some(imported_fingerprint))
			if existing_fingerprint != imported_fingerprint =>
		{
			return Err(Error::InvalidMessageData(
				"Imported trade does not match the offer accepted by the live record".to_string(),
			));
		}
		(Some(existing_fingerprint), None) => {
			imported.received_offer_fingerprint = Some(existing_fingerprint.clone());
		}
		_ => {}
	}

	match (
		existing.received_offer_content_fingerprint.as_ref(),
		imported.received_offer_content_fingerprint.as_ref(),
	) {
		(Some(existing_fingerprint), Some(imported_fingerprint))
			if existing_fingerprint != imported_fingerprint =>
		{
			return Err(Error::InvalidMessageData(
				"Imported trade does not match the content of the offer accepted by the live record"
					.to_string(),
			));
		}
		(Some(existing_fingerprint), None) => {
			imported.received_offer_content_fingerprint = Some(existing_fingerprint.clone());
		}
		_ => {}
	}

	if !existing.secondary_currency.is_btc_family() {
		let existing_redirect_tx = existing.secondary_data.unwrap_eth()?.redirect_tx;
		let imported_redirect_tx = imported.secondary_data.unwrap_eth()?.redirect_tx;
		match (existing_redirect_tx, imported_redirect_tx) {
			(Some(existing_hash), Some(imported_hash)) if existing_hash != imported_hash => {
				return Err(Error::InvalidMessageData(
					"Imported trade contains a different Ethereum private-wallet redirect transaction"
						.to_string(),
				));
			}
			(Some(existing_hash), None) => {
				// A stale backup must not erase the only structured reconciliation
				// handle that prevents another full-value redirect transfer.
				imported.secondary_data.unwrap_eth_mut()?.redirect_tx = Some(existing_hash);
			}
			_ => {}
		}
		let imported_data = imported.secondary_data.unwrap_eth_mut()?;
		for hash in &existing.secondary_data.unwrap_eth()?.redirect_tx_candidates {
			if !imported_data.redirect_tx_candidates.contains(hash) {
				imported_data.redirect_tx_candidates.push(*hash);
			}
		}
	}

	Ok(())
}

fn canonical_marketplace_peer_address(
	secp: &Secp256k1,
	context_id: u32,
	address: &str,
) -> Result<String, Error> {
	let public_key = crate::address::pubkey_from_onion_v3(address)?;
	let address = ProvableAddress::from_tor_pub_key(&public_key)?;
	ProvableAddress::from_str(secp, context_id, &address.to_string())?;
	Ok(address.to_string())
}

fn marketplace_signing_address_index_key(
	offer_id: &str,
	peer_address: &str,
) -> Result<[u8; 32], Error> {
	let mut material = b"mwc-wallet/marketplace-signing-index/v1\0".to_vec();
	for field in [offer_id.as_bytes(), peer_address.as_bytes()] {
		let length = u32::try_from(field.len()).map_err(|e| {
			Error::DataOverflow(format!(
				"Marketplace signing-index field is too long, {}",
				e
			))
		})?;
		material.extend_from_slice(&length.to_be_bytes());
		material.extend_from_slice(field);
	}
	let hash = digest::digest(&digest::SHA256, &material);
	let mut key = [0u8; 32];
	key.copy_from_slice(hash.as_ref());
	Ok(key)
}

/// Select the signing address index once for an offer and peer, then reuse it
/// regardless of later changes to the wallet's current address index.
///
/// `accept_offer` is signed before its remote protocol offer creates a local
/// Swap Deal, so there is no `swap_id` or Swap record yet. The small pre-Swap
/// `(offer, peer) -> address_index` binding is therefore stored transactionally
/// in the existing wallet LMDB. Once the Swap is tagged, the index is copied
/// into `Swap::marketplace_signing_address_index`, which becomes authoritative.
pub fn get_or_create_marketplace_signing_address_index<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	offer_id: &str,
	peer_address: &str,
) -> Result<u32, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let address_index = {
		wallet_lock!(wallet_inst, w);
		let context_id = w.get_context_id();
		let peer_address =
			canonical_marketplace_peer_address(secp, context_id, peer_address)?;
		let binding_key = marketplace_signing_address_index_key(offer_id, &peer_address)?;
		let keychain = w.keychain(secp, keychain_mask)?;
		let mut batch = w.batch(secp, keychain_mask)?;
		match batch.load_marketplace_signing_address_index(&binding_key)? {
			Some(address_index) => {
				proofaddress::payment_proof_address_dalek_secret(
					secp,
					context_id,
					&keychain,
					address_index,
				)?;
				address_index
			}
			None => {
				let address_index = u32::try_from(
					batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?,
				)
				.map_err(|e| {
					Error::DataOverflow(format!(
						"Wallet address index exceeds u32 while binding marketplace signing index, {}",
						e
					))
				})?;
				proofaddress::payment_proof_address_dalek_secret(
					secp,
					context_id,
					&keychain,
					address_index,
				)?;
				batch.save_marketplace_signing_address_index(&binding_key, address_index)?;
				batch.commit()?;
				address_index
			}
		}
	};
	Ok(address_index)
}

/// Load the signing address index bound to a buyer swap, repairing the Swap
/// from the durable pre-trade LMDB binding when necessary.
pub fn marketplace_signing_address_index_for_swap<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: Uuid,
	offer_id: &str,
	peer_address: &str,
) -> Result<u32, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context_id, keychain, skey) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(w.get_context_id(), keychain, skey)
	};
	let peer_address = canonical_marketplace_peer_address(secp, context_id, peer_address)?;
	let binding_key = marketplace_signing_address_index_key(offer_id, &peer_address)?;
	let swap_id_string = swap_id.to_string();
	let swap_lock = trades::get_swap_lock(context_id, &swap_id_string)?;
	let _guard = swap_lock.lock();
	let (context, mut swap) =
		trades::get_swap_trade(context_id, &swap_id_string, &skey, &*swap_lock)?;
	if swap.is_seller() || swap.tag.as_deref() != Some(offer_id) {
		return Err(Error::InvalidMessageData(
			"Marketplace cancellation does not match the selected buyer trade".to_string(),
		));
	}
	let stored_peer = canonical_marketplace_peer_address(
		secp,
		context_id,
		&swap.communication_address,
	)?;
	if stored_peer != peer_address {
		return Err(Error::InvalidMessageData(
			"Marketplace cancellation peer does not match the selected trade".to_string(),
		));
	}

	if let Some(address_index) = swap.marketplace_signing_address_index {
		proofaddress::payment_proof_address_dalek_secret(
			secp,
			context_id,
			&keychain,
			address_index,
		)?;
		return Ok(address_index);
	}

	// The swap -> wallet lock order is permitted by the swap locking contract.
	let address_index = {
		wallet_lock!(wallet_inst, w);
		if w.get_context_id() != context_id {
			return Err(Error::Generic(
				"Wallet context changed while loading marketplace signing index".to_string(),
			));
		}
		let mut batch = w.batch(secp, keychain_mask)?;
		batch.load_marketplace_signing_address_index(&binding_key)?
	}
	.ok_or_else(|| {
		Error::InvalidMessageData(format!(
			"Swap {} does not contain its originating marketplace signing address index; set the original address index and re-apply the marketplace tag before retrying",
			swap_id
		))
	})?;
	proofaddress::payment_proof_address_dalek_secret(
		secp,
		context_id,
		&keychain,
		address_index,
	)?;
	swap.marketplace_signing_address_index = Some(address_index);
	trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
	Ok(address_index)
}

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
pub fn swap_start<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	params: &SwapStartArgs,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Starting a swap trade.
	// This method only initialize and store the swap process. Nothing is done
	// First we need to define outputs that we can use.
	let secondary_currency = Currency::try_from(params.secondary_currency.as_str())?;
	let context_id = {
		wallet_lock!(wallet_inst, w);
		w.get_context_id()
	};

	// This is the outermost swap lock. It makes reservation discovery, selection,
	// gas validation and durable persistence one atomic creation operation for the
	// wallet context. It is deliberately acquired without holding the wallet mutex.
	let creation_lock = trades::get_swap_creation_lock(context_id);
	let _creation_guard = creation_lock.lock();

	// Refresh and read outputs as one operation. A successful RPC call can still
	// report that the serving node is behind the wallet's saved scan state, so
	// coin selection must be gated on the explicit validation result and use its
	// anchor height rather than a second cached tip read.
	let (validated, height, outputs) = crate::owner::retrieve_outputs(
		wallet_inst.clone(),
		secp,
		keychain_mask,
		false,
		true,
		None,
	)?;
	if !validated || height == 0 {
		return Err(Error::Generic(
			"Wallet state could not be validated against the serving MWC chain; the node may be syncing or on a fork"
				.to_string(),
		));
	}
	// Reading all swaps. We need to exclude

	let mut outs: HashMap<String, u64> = outputs
		.iter()
		.map(|o| match &o.output.commit {
			Some(commit) => Some((commit.clone(), o.output.value)),
			None => None,
		})
		.flatten()
		.collect();

	// Release the wallet mutex before acquiring any swap trade lock.
	let (node_client, ethereum_wallet, keychain, skey) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = if secondary_currency.is_btc_family() {
			None
		} else {
			Some(w.get_ethereum_wallet(keychain_mask)?)
		};
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		if w.get_context_id() != context_id {
			return Err(Error::Generic(
				"Wallet context changed while starting swap".to_string(),
			));
		}
		(node_client, ethereum_wallet, keychain, skey)
	};

	let mut swap_reserved_amount = 0u64;
	let mut swap_reserved_gas_amount = 0u64;

	let explicitly_selected_outputs = params
		.outputs
		.as_ref()
		.map(|outputs| outputs.iter().cloned().collect::<HashSet<_>>());
	if let Some(outputs_to_use) = &explicitly_selected_outputs {
		outs.retain(|k, _| outputs_to_use.contains(k));
	}

	// This exclusion is intentionally local to swap creation: it prevents two
	// active swaps from selecting the same MWC inputs, but does not reserve those
	// inputs against ordinary wallet transactions. Making every wallet selection
	// path depend on swap trade storage and locking would add substantial coupling
	// to an already complex protocol, while normal wallet usage does not spend an
	// offer's inputs concurrently. If a collision does occur, consensus permits
	// only one spend and the affected swap follows its cancellation/reversion (and,
	// when necessary, refund) path. This recoverable edge case is an accepted
	// tradeoff rather than a wallet-wide swap reservation.
	//
	// Explicit output selection narrows the eligible MWC inputs but cannot
	// override this swap-local exclusion. Ethereum obligations are always
	// enumerated as well, so explicit MWC selection cannot bypass gas reservation.
	let swap_ids = trades::list_swap_trades(context_id)?;
	for sw_id in &swap_ids {
		let swap_lock = trades::get_swap_lock(context_id, sw_id)?;
		let _l = swap_lock.lock();
		let (_, swap) = trades::get_swap_trade(context_id, sw_id.as_str(), &skey, &*swap_lock)?;

		if !swap.state.is_final_state() {
			if swap.is_seller() {
				for inp in swap.lock_slate.slate.tx_or_err()?.inputs_committed()? {
					let in_commit = to_hex(&inp?.0);
					if explicitly_selected_outputs
						.as_ref()
						.is_some_and(|outputs| outputs.contains(&in_commit))
					{
						return Err(Error::Generic(format!(
							"Requested MWC output {} is already reserved by active swap {}",
							in_commit, sw_id
						)));
					}
					if let Some(amount) = outs.remove(&in_commit) {
						swap_reserved_amount =
							swap_reserved_amount.checked_add(amount).ok_or_else(|| {
								Error::DataOverflow(format!(
									"owner_swap::swap_start, reserved swap amount overflow, reserved_amount={} output_amount={}",
									swap_reserved_amount, amount
								))
							})?;
					}
				}
			}

			// Every active Ethereum-family trade has at least one remaining
			// participant transaction (redeem, refund, or initiate) that may need
			// this wallet's gas. Reserve the persisted per-trade budget regardless
			// of role or explicit MWC output selection. Pre-acceptance incoming
			// offers (BuyerOfferCreated) are excluded: the owner has not agreed to
			// anything yet, so counting them would let a peer inflate the
			// reservation with unsolicited offers and block legitimate swap
			// creation.
			let pending_incoming_offer =
				!swap.is_seller() && swap.state == StateId::BuyerOfferCreated;
			if !swap.secondary_currency.is_btc_family() && !pending_incoming_offer {
				let fee_gwei = swap
					.secondary_currency
					.secondary_fee_gwei(swap.secondary_fee_units)?;
				swap_reserved_gas_amount = swap_reserved_gas_amount
					.checked_add(fee_gwei)
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"owner_swap::swap_start, reserved Ethereum gas overflow, reserved_gwei={} fee_gwei={}",
							swap_reserved_gas_amount, fee_gwei
						))
					})?;
			}
		}
	}

	if swap_reserved_amount > 0 {
		let swap_reserved_amount_str =
			mwc_core::core::amount_to_hr_string(swap_reserved_amount, true);
		info!("Running swaps reserved {} coins", swap_reserved_amount);
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"WARNING. This swap will need to reserve {} MWC. If you don't have enough funds, please cancel it.",
				swap_reserved_amount_str
			);
		}
	}

	let outputs: HashSet<String> = outs.keys().map(|k| k.clone()).collect();
	let secondary_amount = secondary_currency.amount_from_hr_string(&params.secondary_amount)?;

	let (mut swap_api, effective_eth_contracts) = match secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&secondary_currency,
				&params.electrum_node_uri1,
				&params.electrum_node_uri2,
			)?;
			(
				crate::swap::api::create_btc_instance(
					context_id,
					&secondary_currency,
					node_client,
					uri1,
					uri2,
				)?,
				None,
			)
		}
		_ => {
			let ethereum_wallet_for_api = ethereum_wallet
				.clone()
				.ok_or_else(|| Error::Generic("Ethereum wallet is not available".to_string()))?;
			let contracts = resolve_effective_eth_contracts(
				context_id,
				&secondary_currency,
				&params.eth_swap_contract_address,
				&params.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				context_id,
				&secondary_currency,
				&params.eth_infura_project_id,
			)?;
			(
				crate::swap::api::create_eth_instance(
					context_id,
					&secondary_currency,
					node_client,
					ethereum_wallet_for_api,
					contracts.eth.clone(),
					contracts.erc20.clone(),
					eth_infura_project_id,
				)?,
				Some(contracts),
			)
		}
	};

	// Checking ElectrumX/Infura nodes...
	swap_api.test_client_connections()?;

	let context = {
		// The wallet mutex is re-acquired here while no swap trade lock is held.
		wallet_lock!(wallet_inst, w);
		let parent_key_id = w.parent_key_id(); // account is current one
		let (outputs, total, amount, fee) = if !(params.dry_run && params.mwc_amount == 0) {
			crate::internal::selection::select_coins_and_fee(
				&mut **w,
				params.mwc_amount,
				false,
				&None,
				None,
				height,
				params.minimum_confirmations.unwrap_or(10),
				500,
				1,
				false,
				&parent_key_id,
				&Some(outputs), // outputs to include into the transaction
				1,              // Number of resulting outputs. Normally it is 1
				false,
				0,
			)?
		} else {
			// dry run with no amount. It is possible for Buy offer validation
			(vec![], 0, 0, 0)
		};

		// change_amount = total - amount - fee
		let change_amount = total.checked_sub(amount)
			.and_then(|a| a.checked_sub(fee))
			.ok_or_else(|| {
			Error::DataOverflow(format!(
				"owner_swap::swap_start, selected swap inputs do not cover amount, selected_total={} amount={} fee={}",
				total, amount, fee
			))
		})?;
		let context = create_context(
			&mut **w,
			secp,
			ethereum_wallet.as_ref(),
			&mut swap_api,
			&keychain,
			secondary_currency,
			true,
			Some(
				outputs
					.iter()
					.map(|out| {
						SellerInput::new(
							out.key_id.clone(),
							out.mmr_index,
							out.value,
							out.is_coinbase,
						)
					})
					.collect(),
			),
			change_amount,
		)?;
		context
	};

	// Persist the exact contract pair used to construct the initial client. If
	// the caller omitted overrides, storing the resolved defaults (rather than
	// `None`) prevents a restart or configuration edit from moving this trade to
	// another on-chain contract after funds have been committed.
	let persisted_eth_swap_contract_address = effective_eth_contracts
		.as_ref()
		.map(|contracts| contracts.eth.clone())
		.or_else(|| params.eth_swap_contract_address.clone());
	let persisted_erc20_swap_contract_address = effective_eth_contracts
		.as_ref()
		.map(|contracts| contracts.erc20.clone())
		.or_else(|| params.erc20_swap_contract_address.clone());
	let mut swap = (*swap_api).create_swap_offer(
		secp,
		&keychain,
		&context,
		height,
		params.mwc_amount, // mwc amount to sell
		secondary_amount,  // btc amount to buy
		secondary_currency,
		params.secondary_redeem_address.clone(),
		params.seller_lock_first,
		params.mwc_confirmations,
		params.secondary_confirmations,
		params.message_exchange_time_sec,
		params.redeem_time_sec,
		params.buyer_communication_method.clone(),
		params.buyer_communication_address.clone(),
		params.electrum_node_uri1.clone(),
		params.electrum_node_uri2.clone(),
		persisted_eth_swap_contract_address,
		persisted_erc20_swap_contract_address,
		params.eth_infura_project_id.clone(),
		params.eth_redirect_to_private_wallet.clone(),
		params.dry_run,
		params.tag.clone(),
	)?;

	// Store swap result into the file.
	let swap_id = swap.id.to_string();
	let secondary_fee_units = match params.secondary_fee.as_deref() {
		Some(fee) => secondary_currency.normalize_secondary_fee(fee)?,
		None => secondary_currency.get_default_fee(&Network::from_chain_type(
			global::get_chain_type(context_id),
		)?),
	};
	swap.secondary_fee_units = secondary_fee_units;

	if !secondary_currency.is_btc_family() && !params.dry_run {
		let fee_gwei = secondary_currency.secondary_fee_gwei(secondary_fee_units)?;
		swap_reserved_gas_amount = swap_reserved_gas_amount
			.checked_add(fee_gwei)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"owner_swap::swap_start, total Ethereum gas reservation overflow, reserved_gwei={} fee_gwei={}",
					swap_reserved_gas_amount, fee_gwei
				))
			})?;
		let balance_gwei = swap_api.ethereum_gas_balance()?;

		if swap_reserved_gas_amount > balance_gwei {
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"WARNING. {} gases should be keeped. Now {} ethers in your ethereum wallet!",
					swap_reserved_gas_amount, balance_gwei
				);
			} else {
				info!(
					"WARNING. {} gases should be keeped. Now {} ethers in your ethereum wallet!",
					swap_reserved_gas_amount, balance_gwei
				);
			}
			return Err(Error::Generic(
				"No enough ether as gas for swap".to_string(),
			));
		}
	}

	let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
	let _l = swap_lock.lock();
	match trades::get_swap_trade(context_id, swap_id.as_str(), &skey, &*swap_lock) {
		Ok(_) => {
			// Should be impossible, uuid suppose to be unique. But we don't want to overwrite anything
			return Err(Error::TradeIoError(
				swap_id.clone(),
				"This trade record already exist".to_string(),
			));
		}
		// Only a missing record proves the generated ID is unused. I/O, decryption,
		// parsing and network-validation errors must not be treated as absence.
		Err(Error::TradeNotFound(_)) => (),
		Err(e) => return Err(e),
	}

	if params.dry_run {
		// In case of dry run we don't want to store or start anything. Just validate is enough.
		// Still we can return a new swap ID that is temporary, but still might be used for something
		return Ok(swap_id);
	}

	trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;

	Ok(swap_id)
}

/// Respond from swap_list API. Respond is very specific, that is why it has special structure
pub struct SwapListInfo {
	/// Swap id
	pub swap_id: String,
	/// Marketplace Tag for the trade.
	pub tag: Option<String>,
	/// flag if trade is seller
	pub is_seller: bool,
	/// MWC amount that was traded
	pub mwc_amount: String,
	/// Secondary currency amount that was traded
	pub secondary_amount: String,
	/// Secondary currency.
	pub secondary_currency: String,
	/// current state
	pub state: StateId,
	/// current action
	pub action: Option<Action>,
	/// expiration time for action
	pub expiration: Option<i64>,
	/// when this trade was created
	pub trade_start_time: i64,
	/// Secondary address. Caller need to know if ti is set
	pub secondary_address: String,
	/// Last error message if process was failed. Note, error will be very generic
	pub last_error: Option<String>,
}

/// Coherent swap status derived from one locked trade and confirmation snapshot.
pub struct SwapStatusSnapshot {
	/// Stored trade after the status check.
	pub swap: Swap,
	/// Current FSM state.
	pub state: StateId,
	/// Current expected action.
	pub action: Action,
	/// Expiration of the current action.
	pub time_limit: Option<i64>,
	/// State roadmap derived by the FSM.
	pub roadmap: Vec<StateEtaInfo>,
	/// Transaction confirmations used by the FSM check.
	pub confirmations: SwapTransactionsConfirmations,
}

/// List Swap trades. Returns SwapId + Status
/// Return: (<trades list>, <marketplace cancellation notifications>)
pub fn swap_list<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	do_check: bool,
) -> Result<(Vec<SwapListInfo>, Vec<MarketplaceCancelNotification>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Release the wallet mutex before acquiring any swap trade lock.
	// Need to lock first to check if the wallet is open
	let (context_id, node_client, ethereum_wallet, keychain, skey) = {
		wallet_lock!(wallet_inst, w);
		let context_id = w.get_context_id();
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(context_id, node_client, ethereum_wallet, keychain, skey)
	};
	let swap_id = trades::list_swap_trades(context_id)?;
	let mut result: Vec<SwapListInfo> = Vec::new();
	let mut pending_notifications = Vec::new();

	for sw_id in &swap_id {
		let swap_lock = trades::get_swap_lock(context_id, sw_id)?;
		let _l = swap_lock.lock();
		let (context, mut swap) =
			trades::get_swap_trade(context_id, sw_id.as_str(), &skey, &*swap_lock)?;
		let trade_start_time = swap.started.timestamp();
		swap.wait_for_backup1 = true; // always waiting because moving forward it is not a swap list task

		if do_check && !swap.state.is_final_state() {
			let (state, action, expiration) = match update_swap_status_action_impl(
				context_id,
				secp,
				&mut swap,
				&context,
				node_client.clone(),
				&keychain,
				ethereum_wallet.clone(),
			) {
				Ok((state, action, expiration, _state_eta, _confirmations)) => {
					swap.last_check_error = None;
					(state, action, expiration)
				}
				Err(e) => {
					swap.last_check_error = Some(format!("{}", e));
					swap.add_journal_message(format!("Processing error: {}", e));
					(swap.state.clone(), Action::None, None)
				}
			};

			result.push(SwapListInfo {
				swap_id: sw_id.clone(),
				tag: swap.tag.clone(),
				is_seller: swap.is_seller(),
				mwc_amount: core::amount_to_hr_string(swap.primary_amount, true),
				secondary_amount: swap
					.secondary_currency
					.amount_to_hr_string(swap.secondary_amount, true),
				secondary_currency: swap.secondary_currency.to_string(),
				state,
				action: Some(action),
				expiration,
				trade_start_time,
				secondary_address: swap.get_secondary_address(),
				last_error: swap.get_last_error(),
			});
		} else {
			result.push(SwapListInfo {
				swap_id: sw_id.clone(),
				tag: swap.tag.clone(),
				is_seller: swap.is_seller(),
				mwc_amount: core::amount_to_hr_string(swap.primary_amount, true),
				secondary_amount: swap
					.secondary_currency
					.amount_to_hr_string(swap.secondary_amount, true),
				secondary_currency: swap.secondary_currency.to_string(),
				state: swap.state.clone(),
				action: None,
				expiration: None,
				trade_start_time,
				secondary_address: swap.get_secondary_address(),
				last_error: swap.get_last_error(),
			});
		}
		if let Some(notification) = materialize_marketplace_cancel_notification(&mut swap)? {
			pending_notifications.push(notification);
		}
		trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
	}

	Ok((result, pending_notifications))
}

/// Delete Swap trade.
pub fn swap_delete<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(skey, w.get_context_id())
	};

	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();
	trades::delete_swap_trade(context_id, swap_id, &skey, &*swap_lock, false)?;
	Ok(())
}

/// Delete a swap while explicitly discarding any pending marketplace
/// cancellation notification.
pub fn swap_delete_discarding_pending_marketplace_cancel<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(skey, w.get_context_id())
	};

	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _guard = swap_lock.lock();
	trades::delete_swap_trade(
		context_id,
		swap_id,
		&skey,
		&*swap_lock,
		true,
	)
}

/// Get a Swap kernel object.
pub fn swap_get<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<Swap, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(skey, w.get_context_id())
	};
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();
	let (_, swap) = trades::get_swap_trade(context_id, swap_id, &skey, &*swap_lock)?;
	Ok(swap)
}

/// Update the state of Swap trade. Returns the new state
/// method & destination required for adjust_cmd='destination'
pub fn swap_adjust<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	adjust_cmd: &str,
	method: Option<String>,
	destination: Option<String>,
	secondary_address: Option<String>, // secondary address to adjust
	secondary_fee: Option<String>,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_infura_project_id: Option<String>,
	tag: Option<String>,
) -> Result<(StateId, Action), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (keychain, skey, node_client, ethereum_wallet, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let context_id = w.get_context_id();
		(keychain, skey, node_client, ethereum_wallet, context_id)
	};

	let ethereum_recovery = matches!(
		adjust_cmd,
		"retry_erc20_approval" | "retry_erc20_deposit" | "cancel_erc20_deposit"
	);

	// Marketplace group membership must not change while a winner is scanning
	// that group. Use the same outer lock as creation/import, and acquire it before
	// the per-trade lock to preserve the global lock order.
	let tag_membership_lock = if adjust_cmd == "tag" {
		Some(trades::get_swap_creation_lock(context_id))
	} else {
		None
	};
	let _tag_membership_guard = tag_membership_lock.as_ref().map(|lock| lock.lock());
	if ethereum_recovery {
		// Restore active and archived nonce reservations before taking a trade lock.
		trades::restore_ethereum_resources(context_id, None, &skey)?;
	}

	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();
	let (context, mut swap) = if ethereum_recovery {
		trades::get_swap_trade_for_ethereum_recovery(context_id, swap_id, &skey, &swap_lock)?
	} else {
		trades::get_swap_trade(context_id, swap_id, &skey, &*swap_lock)?
	};
	if ethereum_recovery {
		if let Some(fee) = secondary_fee.as_deref() {
			swap.secondary_fee_units = swap.secondary_currency.normalize_secondary_fee(fee)?;
		}
		if let Some(project_id) = eth_infura_project_id.as_ref() {
			swap.eth_infura_project_id = Some(project_id.clone());
		}
	}

	match adjust_cmd {
		"electrumx_uri" => {
			match swap.secondary_currency.is_btc_family() {
				true => {
					// Let's test electrumX instances first.
					let mut electrum1 = electrum_node_uri1.clone();
					let mut electrum2 = electrum_node_uri2.clone();

					if electrum1.is_some() || electrum2.is_some() {
						if electrum1.is_none() {
							electrum1 = electrum2.clone();
						}
						if electrum2.is_none() {
							electrum2 = electrum1.clone();
						}

						let uri1 = electrum1.ok_or_else(|| {
							Error::Generic("First ElectrumX URI is missing".to_string())
						})?;
						let uri2 = electrum2.ok_or_else(|| {
							Error::Generic("Second ElectrumX URI is missing".to_string())
						})?;
						let swap_api: Box<dyn SwapApi<K>> = crate::swap::api::create_btc_instance(
							context_id,
							&swap.secondary_currency,
							node_client.clone(),
							uri1,
							uri2,
						)?;
						swap_api.test_client_connections()?;
					}

					swap.electrum_node_uri1 = electrum_node_uri1;
					swap.electrum_node_uri2 = electrum_node_uri2;
					trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
					return Ok((swap.state.clone(), Action::None));
				}
				_ => {
					return Err(Error::Generic("Non BTC family coins".to_string()));
				}
			}
		}
		"eth_infura_project_id" => match swap.secondary_currency.is_btc_family() {
			true => {
				return Err(Error::Generic("Not Ethereum family coins".to_string()));
			}
			_ => {
				let eth_swap_contract_address = trades::get_eth_swap_contract_address(
					context_id,
					&swap.secondary_currency,
					&swap.eth_swap_contract_address,
				)?;

				let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
					context_id,
					&swap.secondary_currency,
					&swap.erc20_swap_contract_address,
				)?;

				if let Some(eth_infura_project_id) = &eth_infura_project_id {
					let swap_api: Box<dyn SwapApi<K>> = crate::swap::api::create_eth_instance(
						context_id,
						&swap.secondary_currency,
						node_client.clone(),
						ethereum_wallet,
						eth_swap_contract_address,
						erc20_swap_contract_address,
						eth_infura_project_id.clone(),
					)?;
					swap_api.test_client_connections()?;
				}

				swap.eth_infura_project_id = eth_infura_project_id;
				trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
				return Ok((swap.state.clone(), Action::None));
			}
		},
		"destination" => {
			let method =
				method.ok_or(Error::Generic("Please define '--method' value".to_string()))?;
			let destination =
				destination.ok_or(Error::Generic("Please define '--dest' value".to_string()))?;

			// swap_adjust is an authenticated owner operation, so its values have
			// owner provenance. Peer offer fields never pass through this path.
			swap.set_swap_trade_transport(method, destination)?;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"secondary_address" => {
			let secondary_address = secondary_address.ok_or(Error::Generic(
				"Please define '--buyer_refund_address' or '--secondary_address' values".into(),
			))?;
			swap.secondary_currency
				.validate_address(context_id, &secondary_address)?;

			match &mut swap.role {
				Role::Buyer(address) => {
					address.replace(secondary_address);
				}
				Role::Seller(address, _) => {
					*address = secondary_address;
				}
			}

			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"secondary_fee" => {
			let secondary_fee = secondary_fee.ok_or(Error::Generic(
				"Please define '--secondary_fee' values".to_string(),
			))?;
			let secondary_fee_units = swap
				.secondary_currency
				.normalize_secondary_fee(&secondary_fee)?;

			if !swap.secondary_currency.is_btc_family() {
				let balance_gwei = owner_eth::get_eth_balance(context_id, ethereum_wallet.clone())?;
				let required_gwei = swap
					.secondary_currency
					.secondary_fee_gwei(secondary_fee_units)?;
				if mwc_wallet_util::mwc_util::is_console_output_enabled() {
					println!(
						"owner_swap.rs::swap_adjust ----- secondary_fee: {}, balance_gwei: {}",
						secondary_fee_units, balance_gwei
					);
				} else {
					info!(
						"owner_swap.rs::swap_adjust ----- secondary_fee: {}, balance_gwei: {}",
						secondary_fee_units, balance_gwei
					);
				}
				if required_gwei > balance_gwei {
					return Err(Error::Generic(
						"No enough ether as gas for swap".to_string(),
					));
				}
			}

			swap.secondary_fee_units = secondary_fee_units;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		"tag" => {
			let tag = tag.ok_or_else(|| {
				Error::Generic("Please define '--tag' values".to_string())
			})?;
			if !swap.is_seller()
				&& swap.marketplace_winner_lease_expires_at.is_some()
				&& swap.tag.as_deref().is_some_and(|current_tag| current_tag != tag)
				&& !swap.state.is_final_state()
			{
				return Err(Error::Generic(
					"The marketplace tag cannot be changed while this trade owns the winner lease"
						.to_string(),
				));
			}
			if !swap.is_seller() && swap.marketplace_signing_address_index.is_none() {
				let address_index = get_or_create_marketplace_signing_address_index(
					wallet_inst.clone(),
					secp,
					keychain_mask,
					&tag,
					&swap.communication_address,
				)?;
				swap.marketplace_signing_address_index = Some(address_index);
			}

			swap.tag = Some(tag);
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			return Ok((swap.state.clone(), Action::None));
		}
		_ => (), // Nothing to do. Will continue with api construction
	}

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;

			crate::swap::api::create_btc_instance(
				context_id,
				&swap.secondary_currency,
				node_client.clone(),
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				context_id,
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				context_id,
				&swap.secondary_currency,
				node_client.clone(),
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	if ethereum_recovery {
		let result = match adjust_cmd {
			"retry_erc20_approval" => swap_api.retry_erc20_approval(&mut swap),
			"retry_erc20_deposit" => swap_api.recover_secondary_deposit(
				&mut swap,
				super::ethereum::DepositRecoveryMode::RetryOriginal,
			),
			_ => swap_api
				.recover_secondary_deposit(&mut swap, super::ethereum::DepositRecoveryMode::Cancel),
		};
		// A failed submission may have created another signed replacement.
		trades::store_swap_trade(context_id, &context, &swap, &skey, &swap_lock)?;
		result?;
		return Ok((swap.state.clone(), Action::None));
	}
	let mut fsm = swap_api.get_fsm(&keychain, &swap);

	match adjust_cmd {
		"cancel" => {
			if !fsm.is_cancellable(&swap)? {
				return Err(Error::Generic(
					"Swap Trade is not cancellable at current stage".to_string(),
				));
			}

			// Cancelling the trade
			let tx_conf = swap_api.request_tx_confirmations_for_cancel(secp, &keychain, &swap)?;
			let resp = fsm.process(Input::Cancel, &mut swap, &context, &tx_conf, secp)?;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;

			return Ok((swap.state.clone(), resp.action.unwrap_or(Action::None)));
		}
		adjusted_state => {
			let state = StateId::from_cmd_str(adjusted_state)?;
			if !fsm.has_state(&state) {
				return Err(Error::Generic(format!(
					"State {} is invalid for this trade",
					adjusted_state
				)));
			}
			swap.add_journal_message(format!("State is manually adjusted to {}", adjusted_state));
			swap.state = state;

			swap.wait_for_backup1 = true; // Don't want to go forward

			let tx_conf = swap_api.request_tx_confirmations(secp, &keychain, &swap)?;
			let resp = fsm.process(Input::Check, &mut swap, &context, &tx_conf, secp)?;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;

			return Ok((swap.state.clone(), resp.action.unwrap_or(Action::None)));
		}
	}
}

/// Dump the swap file content
pub fn swap_dump<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(skey, w.get_context_id())
	};
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();
	let dump_res = trades::dump_swap_trade(context_id, swap_id, &skey, &*swap_lock)?;
	Ok(dump_res)
}

/// Validate against live records and recover chain state before saving an import.
/// The caller holds the wallet-wide creation lock and this trade's canonical lock.
pub(super) fn store_imported_trade(
	context_id: u32,
	context: &Context,
	swap: &mut Swap,
	skey: &SecretKey,
	swap_lock: &Mutex<()>,
	recover: impl FnOnce(&mut Swap) -> Result<(), Error>,
) -> Result<(), Error> {
	let existing_trades =
		trades::get_swap_trades_for_import(context_id, &swap.id.to_string(), skey, swap_lock)?;
	// Reconciliation can migrate outbox metadata. Stage those changes so a
	// validation or recovery failure leaves the caller's backup unchanged too.
	let mut imported = swap.clone();
	if existing_trades.is_empty() {
		// A newly imported record keeps any durable replay/outbox state
		// carried by the backup itself.
		let _ = materialize_marketplace_cancel_notification(&mut imported)?;
	} else {
		for mut existing in existing_trades {
			reconcile_imported_replay_state(&mut existing, &mut imported)?;
		}
	}
	if buyer_redeem_exposure_recorded(&imported) {
		imported
			.posted_redeem
			.get_or_insert_with(super::swap::get_cur_time);
		// Retain legacy exposure evidence before recovering chain state.
		imported.state = StateId::BuyerWaitForRedeemMwcConfirmations;
	}
	// A failed or ambiguous recovery must leave the stored trade and backup intact.
	recover(&mut imported)?;
	trades::store_swap_trade(context_id, context, &imported, skey, swap_lock)?;
	*swap = imported;
	Ok(())
}

/// Import swap trade from the file
/// Return: trade SwapId
pub fn swap_import_trade<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	trade_file_name: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (keychain, skey, node_client, ethereum_wallet, context_id) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let context_id = w.get_context_id();
		(keychain, skey, node_client, ethereum_wallet, context_id)
	};

	// Checking if MWC node is available
	let mwc_tip = node_client.get_chain_tip()?.0;
	if mwc_tip == 0 {
		return Err(Error::Generic(
			"Unable contact healthy MWC node. The node probably in sync process".to_string(),
		));
	}

	// Decrypt and validate first so the embedded UUID can select the one lock
	// that protects every read and write of the imported target record.
	let (context, mut swap) =
		trades::read_imported_trade(context_id, trade_file_name, &skey)?;
	let swap_id = swap.id.to_string();

	// Importing an active trade can introduce the same MWC/gas obligations as a
	// newly created one, so it participates in the wallet-wide creation order.
	let creation_lock = trades::get_swap_creation_lock(context_id);
	let _creation_guard = creation_lock.lock();
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();

	// The backup may be stale. Resolve chain state before writing it, while
	// retaining the canonical target lock through validation and storage.

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				context_id,
				&swap.secondary_currency,
				node_client.clone(),
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				context_id,
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				context_id,
				&swap.secondary_currency,
				node_client.clone(),
				ethereum_wallet.clone(),
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	store_imported_trade(
		context_id,
		&context,
		&mut swap,
		&skey,
		&*swap_lock,
		|staged| recover_imported_trade_state(secp, &keychain, &context, staged, &*swap_api),
	)?;

	Ok(swap_id)
}

/// Reconcile an imported trade with both chains without starting a buyer refund.
pub(super) fn recover_imported_trade_state<K: Keychain>(
	secp: &Secp256k1,
	keychain: &K,
	context: &Context,
	swap: &mut Swap,
	swap_api: &dyn SwapApi<K>,
) -> Result<(), Error> {
	match swap.secondary_currency.is_btc_family() {
		true => {
			// Recover a missing seller redemption hash when its inputs are available.
			if swap.is_seller() && swap.secondary_data.unwrap_btc()?.redeem_tx.is_none() {
				// try to calculate the hash if possible
				if let Err(e) =
					swap_api.publish_secondary_transaction(secp, keychain, swap, context, false)
				{
					warn!("Unable to prepare the secondary redeem transaction: {}", e);
				}
			}
			// Preparing a buyer refund creates a durable plan even without a
			// broadcast. Only the refund workflow may start that plan; import polls
			// the recorded hashes and signed transactions exactly as restored.
		}
		_ => {
			// Ethereum-family hashes require a freshly allocated account nonce.
			// Import is recovery, not transaction preparation, so it restores
			// authenticated hashes without invoking a mutating contract method.
		}
	}

	let tx_conf = swap_api.request_tx_confirmations(secp, keychain, swap)?;
	if tx_conf.mwc_tip == 0 {
		return Err(Error::Generic("Unable contact healthy MWC node. Please fix the problem and retry to restore this swap trade".to_string()));
	}
	if tx_conf.secondary_tip == 0 {
		return Err(Error::Generic(format!(
			"Unable contact {} ElectrumX node. Please fix the problem and retry to restore this swap trade",
			swap.secondary_currency
		)));
	}

	// A signed backup may predate publication. Missing kernels cannot prove
	// that it was never sent; refuse the import rather than infer cancellation.
	let (slate, publication_unknown) = if swap.is_seller() {
		(
			&swap.lock_slate.slate,
			swap.posted_lock.is_none()
				&& tx_conf.mwc_lock_conf.is_none()
				&& tx_conf.mwc_refund_conf.is_none()
				&& tx_conf.secondary_redeem_conf.is_none(),
		)
	} else {
		(
			&swap.redeem_slate.slate,
			!buyer_redeem_exposure_recorded(swap)
			&& tx_conf.mwc_redeem_conf.is_none()
			// A sufficiently confirmed competing refund also resolves the MWC spend.
			&& tx_conf.mwc_refund_conf.unwrap_or(0) < swap.mwc_confirmations.max(1),
		)
	};
	if publication_unknown
		&& slate
			.tx_or_err()?
			.kernels()
			.iter()
			.any(|kernel| kernel.excess_sig != AggSigSignature::blank())
	{
		return Err(Error::InvalidMessageData(
			"Cannot safely import this signed trade: MWC transaction publication is unknown. \
			 Retry after the transaction confirms or use a newer backup"
				.to_string(),
		));
	}

	if swap.is_seller() {
		if tx_conf.secondary_redeem_conf.is_some() {
			swap.state = StateId::SellerWaitingForRedeemConfirmations;
		} else if tx_conf.mwc_refund_conf.is_some() {
			swap.state = StateId::SellerWaitingForRefundConfirmations;
		} else if tx_conf.mwc_lock_conf.is_some() {
			swap.posted_lock
				.get_or_insert_with(super::swap::get_cur_time);
			swap.state = StateId::SellerWaitingForLockConfirmations;
		} else if swap.posted_lock.is_some() {
			// A submitted lock can still confirm while its kernel is absent.
			// Keep refund recovery active for pending or reorganized locks.
			swap.state = StateId::SellerWaitingForRefundHeight;
		} else {
			swap.state = StateId::SellerCancelled;
		}
	} else {
		// Buyer case
		if buyer_redeem_exposure_recorded(swap) || tx_conf.mwc_redeem_conf.is_some() {
			swap.posted_redeem.get_or_insert_with(super::swap::get_cur_time);
			// The normal redeem state machine retries exposed transactions and
			// resolves a competing MWC refund at the agreed confirmation depth.
			swap.state = StateId::BuyerWaitForRedeemMwcConfirmations;
		} else if tx_conf.secondary_refund_conf.is_some()
			|| tx_conf.secondary_refund_progress.is_some()
		{
			swap.state = StateId::BuyerWaitingForRefundConfirmations;
		} else if tx_conf.secondary_lock_conf.is_some() {
			swap.state = StateId::BuyerWaitingForLockConfirmations;
		} else {
			swap.state = super::fsm::buyer_swap::buyer_cancellation_state(
				swap,
				tx_conf.secondary_lock_amount,
			)?;
		}
	}

	swap.last_check_error = None;
	swap.last_process_error = None;

	Ok(())
}

fn update_swap_status_action_impl<'a, C, K>(
	context_id: u32,
	secp: &mut Secp256k1,
	swap: &mut Swap,
	context: &Context,
	node_client: C,
	keychain: &K,
	ethereum_wallet: EthereumWallet,
) -> Result<
	(
		StateId,
		Action,
		Option<i64>,
		Vec<StateEtaInfo>,
		SwapTransactionsConfirmations,
	),
	Error,
>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				context_id,
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			crate::swap::api::create_eth_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let tx_conf = swap_api.request_tx_confirmations_for_state(secp, keychain, swap)?;
	let (resp, eta) = commit_swap_on_success(swap, |staged_swap| {
		let mut fsm = swap_api.get_fsm(keychain, staged_swap);
		let resp = fsm.process(Input::Check, staged_swap, &context, &tx_conf, secp)?;
		let eta = fsm.get_swap_roadmap(staged_swap, secp)?;
		Ok((resp, eta))
	})?;

	Ok((
		resp.next_state_id,
		resp.action.unwrap_or(Action::None),
		resp.time_limit,
		eta,
		tx_conf,
	))
}

/// One record that could not be inspected while scanning the durable
/// marketplace cancellation outbox.
#[derive(Debug, Clone)]
pub struct PendingMarketplaceCancelScanFailure {
	/// Canonical swap identifier from the active trade directory.
	pub swap_id: String,
	/// Read, authentication, validation, or repair failure.
	pub error: String,
}

/// Partial result of scanning the durable marketplace cancellation outbox.
#[derive(Debug, Clone)]
pub struct PendingMarketplaceCancelScan {
	/// Successfully decoded pending notifications.
	pub pending: Vec<MarketplaceCancelNotification>,
	/// Records whose pending state could not be determined.
	pub failures: Vec<PendingMarketplaceCancelScanFailure>,
}

fn try_inspect_pending_marketplace_cancel_record(
	context_id: u32,
	swap_id: &str,
	skey: &SecretKey,
) -> Result<Option<MarketplaceCancelNotification>, Error> {
	let swap_lock = trades::get_swap_lock(context_id, swap_id)?;
	let Some(_guard) = swap_lock.try_lock() else {
		return Err(Error::Generic(format!(
			"Swap {} is busy; durable marketplace outbox inspection was deferred",
			swap_id
		)));
	};
	let (context, mut swap) =
		trades::get_swap_trade(context_id, swap_id, skey, &*swap_lock)?;
	let original_notification = swap.marketplace_cancel_notification.clone();
	let original_pending = swap.pending_marketplace_cancel_notification;
	let original_nonce = swap.marketplace_cancel_notification_nonce;
	let notification = materialize_marketplace_cancel_notification(&mut swap)?;
	let migrated = original_notification != swap.marketplace_cancel_notification
		|| original_pending != swap.pending_marketplace_cancel_notification
		|| original_nonce != swap.marketplace_cancel_notification_nonce;
	if migrated {
		trades::store_swap_trade(context_id, &context, &swap, skey, &*swap_lock)?;
	}
	Ok(notification)
}

/// Return durable cancellation notifications that survived a failed send or
/// process exit together with every record that could not be inspected.
pub fn pending_marketplace_cancel_notifications<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<PendingMarketplaceCancelScan, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context_id, skey) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(w.get_context_id(), skey)
	};

	let mut pending = Vec::new();
	let mut failures = Vec::new();
	for swap_id in trades::list_swap_trades(context_id)? {
		match try_inspect_pending_marketplace_cancel_record(context_id, &swap_id, &skey) {
			Ok(Some(notification)) => pending.push(notification),
			Ok(None) => {}
			Err(e) => failures.push(PendingMarketplaceCancelScanFailure {
				swap_id,
				error: e.to_string(),
			}),
		}
	}
	Ok(PendingMarketplaceCancelScan { pending, failures })
}

/// Complete a durable cancellation notification after the remote wallet acknowledges it.
pub fn complete_marketplace_cancel_notification<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	notification: &MarketplaceCancelNotification,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context_id, skey) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		(w.get_context_id(), get_swap_storage_key(secp, &keychain)?)
	};
	let swap_id_string = notification.swap_id.to_string();
	let swap_lock = trades::get_swap_lock(context_id, &swap_id_string)?;
	let _guard = swap_lock.lock();
	let (context, mut swap) =
		trades::get_swap_trade(context_id, &swap_id_string, &skey, &*swap_lock)?;
	let pending_notification = materialize_marketplace_cancel_notification(&mut swap)?;
	if pending_notification.as_ref() != Some(notification) {
		return Err(Error::InvalidMessageData(
			"Marketplace cancellation acknowledgement does not match the pending record"
				.to_string(),
		));
	}

	// Commit logical outbox completion while the record still has its active,
	// discoverable name. If this write fails, a later scan can inspect the same
	// active path and either retry the stable nonce or observe the completed
	// marker. Archival must not be the commit point: rename can succeed before a
	// subsequent directory sync reports an error.
	swap.marketplace_cancel_notification = None;
	swap.pending_marketplace_cancel_notification = false;
	trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;

	// The acknowledged cancellation is durable now. Archival is best-effort
	// housekeeping: on failure the record is either still active and explicitly
	// non-pending, or it has already moved to the deleted directory. Neither case
	// should be reported as a pending notification.
	if let Err(e) = trades::delete_swap_trade(
		context_id,
		&swap_id_string,
		&skey,
		&*swap_lock,
		false,
	) {
		warn!(
			"Marketplace cancellation for swap {} was completed, but archival needs cleanup: {}",
			notification.swap_id, e
		);
	}
	Ok(())
}

/// Refresh a swap and return every report field from one locked confirmation snapshot.
pub fn update_swap_status_snapshot<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_swap_contract_address: Option<String>,
	erc20_swap_contract_address: Option<String>,
	eth_infura_project_id: Option<String>,
	wait_for_backup1: bool,
) -> Result<(SwapStatusSnapshot, Vec<MarketplaceCancelNotification>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Release the wallet mutex before acquiring any swap trade lock.
	let (node_client, ethereum_wallet, keychain, skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		let context_id = w.get_context_id();
		(node_client, ethereum_wallet, keychain, skey, context_id)
	};
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();

	let (context, mut swap) = trades::get_swap_trade(context_id, swap_id, &skey, &*swap_lock)?;

	// Updating electrumX URI if they are defined. We can't reset them. For reset use Adjust
	if electrum_node_uri1.is_some() {
		swap.electrum_node_uri1 = electrum_node_uri1;
	}
	if electrum_node_uri2.is_some() {
		swap.electrum_node_uri2 = electrum_node_uri2;
	}

	// Contract addresses are immutable trade identity. Supplying one here asserts
	// the pinned value; a different value is an error rather than an override that
	// could redirect an in-flight trade. Legacy records with `None` are pinned on
	// their first explicit value.
	if !swap.secondary_currency.is_btc_family() {
		pin_or_validate_eth_contracts(
			&mut swap.eth_swap_contract_address,
			&mut swap.erc20_swap_contract_address,
			eth_swap_contract_address,
			erc20_swap_contract_address,
		)?;
	}
	// The Infura project identifies an RPC endpoint, not the contract holding the
	// funds, so it remains an operational override.
	if eth_infura_project_id.is_some() {
		swap.eth_infura_project_id = eth_infura_project_id;
	}

	swap.wait_for_backup1 = wait_for_backup1;

	let previous_state = swap.state.clone();
	match update_swap_status_action_impl(
		context_id,
		secp,
		&mut swap,
		&context,
		node_client,
		&keychain,
		ethereum_wallet,
	) {
		Ok((next_state_id, action, time_limit, roadmap, confirmations)) => {
			if swap.state == StateId::SellerCancelled {
				wallet_lock!(wallet_inst, w);
				if let Err(error) = cancel_unpublished_swap_lock(
					&mut **w,
					secp,
					keychain_mask,
					&swap,
					&context,
					&confirmations,
				) {
					swap.state = previous_state;
					swap.last_check_error = Some(error.to_string());
					trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
					return Err(error);
				}
			}
			swap.last_check_error = None;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			Ok((
				SwapStatusSnapshot {
					swap,
					state: next_state_id,
					action,
					time_limit,
					roadmap,
					confirmations,
				},
				Vec::new(),
			))
		}
		Err(e) => {
			swap.last_check_error = Some(format!("{}", e));
			swap.add_journal_message(format!("Processing error: {}", e));
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			Err(e)
		}
	}
}

/// Refresh and get the legacy tuple-shaped swap status response.
pub fn update_swap_status_action<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_swap_contract_address: Option<String>,
	erc20_swap_contract_address: Option<String>,
	eth_infura_project_id: Option<String>,
	wait_for_backup1: bool,
) -> Result<
	(
		StateId,
		Action,
		Option<i64>,
		Vec<StateEtaInfo>,
		Vec<SwapJournalRecord>,
		Option<String>,
		Vec<MarketplaceCancelNotification>,
	),
	Error,
>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (snapshot, cancelled_notifications) = update_swap_status_snapshot(
		wallet_inst,
		secp,
		keychain_mask,
		swap_id,
		electrum_node_uri1,
		electrum_node_uri2,
		eth_swap_contract_address,
		erc20_swap_contract_address,
		eth_infura_project_id,
		wait_for_backup1,
	)?;
	let last_error = snapshot.swap.get_last_error();
	Ok((
		snapshot.state,
		snapshot.action,
		snapshot.time_limit,
		snapshot.roadmap,
		snapshot.swap.journal,
		last_error,
		cancelled_notifications,
	))
}

fn request_swap_tx_confirmations<C, K>(
	context_id: u32,
	secp: &Secp256k1,
	node_client: C,
	ethereum_wallet: EthereumWallet,
	keychain: &K,
	swap: &mut Swap,
) -> Result<SwapTransactionsConfirmations, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let swap_api = if swap.secondary_currency.is_btc_family() {
		let (uri1, uri2) = trades::get_electrumx_uri(
			context_id,
			&swap.secondary_currency,
			&swap.electrum_node_uri1,
			&swap.electrum_node_uri2,
		)?;
		crate::swap::api::create_btc_instance(
			context_id,
			&swap.secondary_currency,
			node_client,
			uri1,
			uri2,
		)?
	} else {
		let eth_swap_contract_address = trades::get_eth_swap_contract_address(
			context_id,
			&swap.secondary_currency,
			&swap.eth_swap_contract_address,
		)?;
		let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
			context_id,
			&swap.secondary_currency,
			&swap.erc20_swap_contract_address,
		)?;
		let eth_infura_project_id = trades::get_eth_infura_projectid(
			context_id,
			&swap.secondary_currency,
			&swap.eth_infura_project_id,
		)?;
		crate::swap::api::create_eth_instance(
			context_id,
			&swap.secondary_currency,
			node_client,
			ethereum_wallet,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
		)?
	};

	swap_api.request_tx_confirmations(secp, keychain, swap)
}

/// Get a status of the transactions that involved into the swap.
pub fn get_swap_tx_tstatus<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_swap_contract_address: Option<String>,
	erc20_swap_contract_address: Option<String>,
	eth_infura_project_id: Option<String>,
) -> Result<SwapTransactionsConfirmations, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Release the wallet mutex before acquiring any swap trade lock.
	let (node_client, ethereum_wallet, keychain, skey, context_id) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		let context_id = w.get_context_id();
		(node_client, ethereum_wallet, keychain, skey, context_id)
	};
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();

	let (_context, mut swap) = trades::get_swap_trade(context_id, swap_id, &skey, &*swap_lock)?;

	// These overrides apply only to this snapshot and are never persisted.
	if swap.secondary_currency.is_btc_family() {
		if electrum_node_uri1.is_some() {
			swap.electrum_node_uri1 = electrum_node_uri1;
		}
		if electrum_node_uri2.is_some() {
			swap.electrum_node_uri2 = electrum_node_uri2;
		}
	} else {
		// Contract arguments are assertions against the durable trade identity;
		// they must never select a different contract for one status query.
		pin_or_validate_eth_contracts(
			&mut swap.eth_swap_contract_address,
			&mut swap.erc20_swap_contract_address,
			eth_swap_contract_address,
			erc20_swap_contract_address,
		)?;
		if eth_infura_project_id.is_some() {
			swap.eth_infura_project_id = eth_infura_project_id;
		}
	}
	drop(_l);

	request_swap_tx_confirmations(
		context_id,
		secp,
		node_client,
		ethereum_wallet,
		&keychain,
		&mut swap,
	)
}

/// Persist signing state that must survive a retry before exposing its message.
pub(super) fn send_swap_message<F>(
	swap: &Swap,
	action: &Action,
	secp: &Secp256k1,
	message_sender: F,
	persist_transaction: &dyn Fn(&Swap) -> Result<(), Error>,
) -> Result<(bool, String), Error>
where
	F: FnOnce(Message, String, String, &Secp256k1) -> Result<(bool, String), Error>,
{
	let message = match action {
		Action::SellerSendOfferMessage(message)
		| Action::BuyerSendAcceptOfferMessage(message)
		| Action::BuyerSendInitRedeemMessage(message)
		| Action::SellerSendRedeemMessage(message) => message,
		_ => {
			return Err(Error::UnexpectedAction(
				"Expected a send-message action".into(),
			));
		}
	};
	// Resolve at the sink boundary. In particular, a buyer trade created
	// from an offer cannot turn the offer's `from_address` into a filesystem
	// write without an owner-selected SwapTradeTransport.
	let (communication_method, communication_address) = swap.outbound_transport()?;
	if matches!(action, Action::BuyerSendInitRedeemMessage(_)) {
		// A restart must reuse the exact redeem slate and adaptor signature. A
		// rebuild would change the offset while reusing the context's signing nonce.
		persist_transaction(swap)?;
	} else if matches!(action, Action::SellerSendRedeemMessage(_))
		&& swap.secondary_currency.is_btc_family()
	{
		// Delivery may succeed even if its acknowledgement is lost or the
		// process crashes. Save the exact redemption inputs before exposure.
		swap.secondary_data
			.unwrap_btc()?
			.accepted_redeem_inputs(swap.secondary_amount)?;
		persist_transaction(swap)?;
	}
	message_sender(
		message.clone(),
		communication_method,
		communication_address,
		secp,
	)
}

// A missing kernel alone is not evidence that a submission never happened.
fn seller_lock_unpublished(swap: &Swap, tx_conf: &SwapTransactionsConfirmations) -> bool {
	swap.is_seller()
		&& tx_conf.mwc_observed
		&& swap.posted_lock.is_none()
		&& tx_conf.mwc_lock_conf.is_none()
		&& tx_conf.mwc_redeem_conf.is_none()
		&& tx_conf.mwc_refund_conf.is_none()
}

// Cancel only this swap's wallet transaction. The ordinary cancellation path
// atomically updates its log and releases only its account-scoped input locks.
fn cancel_unpublished_swap_lock<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap: &Swap,
	context: &Context,
	tx_conf: &SwapTransactionsConfirmations,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !seller_lock_unpublished(swap, tx_conf) {
		return Ok(());
	}
	let parent = &context.unwrap_seller()?.parent_key_id;
	let slate = &swap.lock_slate.slate;
	let entry = wallet.tx_log_iter()?.find(|tx| {
		tx.parent_key_id == *parent && tx.tx_slate_id == Some(slate.id) && !tx.is_cancelled()
	});
	if let Some(entry) = entry {
		let kernel = slate
			.tx_or_err()?
			.kernels()
			.first()
			.ok_or_else(|| Error::Generic("Swap lock transaction has no kernel".into()))?;
		if entry.kernel_excess != Some(kernel.excess) {
			return Err(Error::Generic(
				"Swap lock wallet record has a different kernel".into(),
			));
		}
		crate::internal::tx::cancel_tx(
			wallet,
			secp,
			keychain_mask,
			Some(parent),
			Some(entry.id),
			None,
		)?;
	}
	Ok(())
}

fn process_seller_lock<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap: &mut Swap,
	context: &Context,
	tx_conf: &SwapTransactionsConfirmations,
	execute: impl FnOnce(&mut Swap, &mut Secp256k1) -> Result<StateProcessRespond, Error>,
) -> Result<StateProcessRespond, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Checking if transaction is already created.
	let kernel = &swap
		.lock_slate
		.slate
		.tx_or_err()?
		.body
		.kernels
		.first()
		.ok_or_else(|| Error::Generic("Swap lock transaction has no kernel".to_string()))?
		.excess;
	let seller_context = context.unwrap_seller()?;
	if !wallet.tx_log_iter()?.any(|tx| {
		!tx.is_cancelled()
			&& tx.parent_key_id == seller_context.parent_key_id
			&& tx.tx_slate_id == Some(swap.lock_slate.slate.id)
			&& tx.kernel_excess.as_ref() == Some(kernel)
	}) {
		// Transaction doesn't exist, let's create it and lock the outputs.
		let slate_context = crate::types::Context::from_send_slate(
			&swap.lock_slate.slate,
			context.lock_nonce.clone(),
			seller_context
				.inputs
				.iter()
				.map(|input| (input.key_id.clone(), input.mmr_index, input.amount))
				.collect(),
			vec![(
				seller_context.change_output.clone(),
				None,
				seller_context.change_amount,
			)],
			seller_context.parent_key_id.clone(),
			0,
		)?;
		selection::lock_tx_context(
			wallet,
			secp,
			keychain_mask,
			&mut None,
			&swap.lock_slate.slate,
			tx_conf.mwc_tip,
			&slate_context,
			Some(format!("Swap {} Lock", swap.id)),
			None,
			None,
		)?;
	}

	let previous_state = swap.state.clone();
	let result = execute(swap, secp);
	if (result.is_err() || swap.state == StateId::SellerCancelled)
		&& seller_lock_unpublished(swap, tx_conf)
	{
		if let Err(cleanup_error) =
			cancel_unpublished_swap_lock(wallet, secp, keychain_mask, swap, context, tx_conf)
		{
			// Keep cancellation retryable if the wallet batch could not commit.
			// There was no publication, so restoring this state cannot hide exposure.
			swap.state = previous_state;
			return Err(match result {
				Err(error) => Error::Generic(format!(
					"{}; unable to release unpublished swap inputs: {}",
					error, cleanup_error
				)),
				Ok(_) => cleanup_error,
			});
		}
	}
	result
}

/// Exercise the owner lock-publication boundary with a concrete wallet backend.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn process_seller_lock_for_test<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap: &mut Swap,
	context: &Context,
	tx_conf: &SwapTransactionsConfirmations,
	execute: impl FnOnce(&mut Swap, &mut Secp256k1) -> Result<StateProcessRespond, Error>,
) -> Result<StateProcessRespond, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	process_seller_lock(wallet, secp, keychain_mask, swap, context, tx_conf, execute)
}

fn swap_process_impl<'a, L, C, K, F>(
	context_id: u32,
	secp: &mut Secp256k1,
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap: &mut Swap,
	context: &Context,
	node_client: C,
	keychain: &K,
	message_sender: F,
	persist_transaction: impl Fn(&Swap) -> Result<(), Error>,
	message_file_name: Option<String>,
	buyer_refund_address: Option<String>,
	secondary_fee: Option<String>,
	secondary_address: Option<String>,
) -> Result<StateProcessRespond, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	F: FnOnce(Message, String, String, &Secp256k1) -> Result<(bool, String), Error> + 'a,
{
	if let Some(secondary_fee) = secondary_fee {
		swap.secondary_fee_units = swap
			.secondary_currency
			.normalize_secondary_fee(&secondary_fee)?;
	}

	if swap.is_seller() {
		if let Some(secondary_address) = secondary_address {
			swap.secondary_currency
				.validate_address(context_id, &secondary_address)?;
			swap.update_secondary_address(secondary_address);
		}
	} else {
		if let Some(secondary_address) = buyer_refund_address {
			swap.secondary_currency
				.validate_address(context_id, &secondary_address)?;
			swap.update_secondary_address(secondary_address);
		}
	}

	let swap_api = match swap.secondary_currency.is_btc_family() {
		true => {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		}
		_ => {
			let eth_swap_contract_address = trades::get_eth_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.eth_swap_contract_address,
			)?;
			let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
				context_id,
				&swap.secondary_currency,
				&swap.erc20_swap_contract_address,
			)?;
			let eth_infura_project_id = trades::get_eth_infura_projectid(
				context_id,
				&swap.secondary_currency,
				&swap.eth_infura_project_id,
			)?;
			wallet_lock!(wallet_inst.clone(), w);
			let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
			crate::swap::api::create_eth_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				eth_swap_contract_address,
				erc20_swap_contract_address,
				eth_infura_project_id,
			)?
		}
	};

	let tx_conf = swap_api.request_tx_confirmations_for_state(secp, keychain, swap)?;
	let mut fsm = swap_api.get_fsm(keychain, swap);
	let mut process_respond = commit_swap_on_success(swap, |staged_swap| {
		let respond = fsm.process(Input::Check, staged_swap, &context, &tx_conf, secp)?;
		if staged_swap.state == StateId::SellerCancelled {
			wallet_lock!(wallet_inst, w);
			cancel_unpublished_swap_lock(
				&mut **w,
				secp,
				keychain_mask,
				staged_swap,
				context,
				&tx_conf,
			)?;
		}
		Ok(respond)
	})?;

	let action = match &process_respond.action {
		None => return Ok(process_respond),
		Some(action) => action.clone(),
	};
	match &action {
		Action::SellerSendOfferMessage(_)
		| Action::BuyerSendAcceptOfferMessage(_)
		| Action::BuyerSendInitRedeemMessage(_)
		| Action::SellerSendRedeemMessage(_) => {
			let (has_ack, dest_str) = send_swap_message(
				swap,
				&action,
				secp,
				message_sender,
				&persist_transaction,
			)?;
			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
			swap.append_to_last_message(&format!(", {}", dest_str));
			if has_ack {
				match &action {
					Action::SellerSendOfferMessage(_) | Action::BuyerSendAcceptOfferMessage(_) => {
						swap.ack_msg1()
					}
					Action::BuyerSendInitRedeemMessage(_) | Action::SellerSendRedeemMessage(_) => {
						swap.ack_msg2()
					}
					_ => unreachable!("send-message arm only accepts message actions"),
				}
			}
		}
		Action::SellerWaitingForOfferMessage
		| Action::SellerWaitingForInitRedeemMessage
		| Action::BuyerWaitingForRedeemMessage => {
			let message_fn = message_file_name.ok_or(Error::Generic("Wallet is waiting for the response from the Buyer. Make sure that your wallet is online and able to receive the messages. If you are using files for messages exchange, please specify income message file name with '--message_file_name' value".to_string()))?;

			let mut file = File::open(message_fn.clone()).map_err(|e| {
				Error::Generic(format!("Unable to open file {}, {}", message_fn, e))
			})?;
			let mut contents = String::new();
			file.read_to_string(&mut contents).map_err(|e| {
				Error::Generic(format!(
					"Unable to read a message from the file {}, {}",
					message_fn, e
				))
			})?;
			let message = Message::from_json(&contents)?;
			if message.id != swap.id {
				return Err(Error::Generic(format!(
					"Message id {} doesn't match selected trade id",
					message.id
				)));
			}

			// Stage all peer-controlled mutations and commit them only after the complete
			// state-machine operation succeeds. The caller still persists diagnostics on
			// the original trade when processing fails, without persisting partial
			// multisig, slate, or adaptor-signature state.
			let mut staged_swap = swap.clone();
			staged_swap.wait_for_backup1 = true;
			let staged_respond = fsm.process(
				Input::IncomeMessage(message),
				&mut staged_swap,
				&context,
				&tx_conf,
				secp,
			)?;
			*swap = staged_swap;
			process_respond = staged_respond;
		}
		Action::BuyerDepositToContractAccount => {
			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
		}
		Action::SellerPublishMwcLockTx => {
			wallet_lock!(wallet_inst, w);
			process_respond = process_seller_lock(
				&mut **w,
				secp,
				keychain_mask,
				swap,
				context,
				&tx_conf,
				|swap, secp| {
					// Save exposure before submission, including ambiguous responses.
					fsm.process_with_persist(
						Input::Execute,
						swap,
						context,
						&tx_conf,
						secp,
						&persist_transaction,
					)
				},
			)?;
		}
		Action::SellerPublishTxSecondaryRedeem {
			currency: _,
			address: _,
		} => {
			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
		}
		Action::SellerTransferSecondary { .. } => {
			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
		}
		Action::BuyerPublishMwcRedeemTx => {
			{
				wallet_lock!(wallet_inst, w);
				let buyer_context = context.unwrap_buyer()?;
				ensure_swap_receive_tx_record(
					&mut **w,
					secp,
					keychain_mask,
					&swap.redeem_slate.slate,
					format!("Swap {}", swap.id),
					&buyer_context.parent_key_id,
					&buyer_context.output,
				)?;
			}

			// Persist exposure before the network side effect, including the case
			// where the node accepts the transaction but we lose its response.
			process_respond = fsm.process_with_persist(
				Input::Execute,
				swap,
				&context,
				&tx_conf,
				secp,
				&persist_transaction,
			)?;
		}
		Action::SellerPublishMwcRefundTx => {
			{
				wallet_lock!(wallet_inst, w);
				let seller_context = context.unwrap_seller()?;
				ensure_swap_receive_tx_record(
					&mut **w,
					secp,
					keychain_mask,
					&swap.refund_slate.slate,
					format!("Swap {} Refund", swap.id),
					&seller_context.parent_key_id,
					&seller_context.refund_output,
				)?;
			}

			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
		}
		Action::BuyerPublishSecondaryRefundTx {
			currency: _,
			address: _,
		} => {
			//only btc family need to check refund address.
			if swap.secondary_currency.is_btc_family() && swap.unwrap_buyer()?.is_none() {
				return Err(Error::Generic(format!(
					"Please specify '--buyer_refund_address' {} address for your refund",
					swap.secondary_currency
				)));
			}

			if swap.secondary_currency.is_btc_family() {
				swap_api.prepare_secondary_refund(secp, keychain, context, swap)?;
				// Save before the network side effect: even a lost response or a
				// crash must leave the original inputs available for recovery.
				persist_transaction(swap)?;
			}
			process_respond = fsm.process(Input::Execute, swap, &context, &tx_conf, secp)?;
		}
		_ => (), // Nothing to do
	}

	Ok(process_respond)
}

/// Process the action for the swap. Action has to match the expected one
/// message_sender - method that can send the message to another party. Caller defines how it can be done
/// Return: new State & Action
pub fn swap_process<'a, L, C, K, F>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	message_sender: F,
	message_file_name: Option<String>,
	buyer_refund_address: Option<String>,
	secondary_fee: Option<String>,
	secondary_address: Option<String>,
	electrum_node_uri1: Option<String>,
	electrum_node_uri2: Option<String>,
	eth_infura_project_id: Option<String>,
	wait_for_backup1: bool,
) -> Result<(StateProcessRespond, Vec<MarketplaceCancelNotification>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
	F: FnOnce(Message, String, String, &Secp256k1) -> Result<(bool, String), Error> + 'a,
{
	let target_id = Uuid::parse_str(swap_id)
		.map_err(|_| Error::InvalidMessageData("Swap id must be a valid UUID".to_string()))?;
	let lease_notifications = prepare_marketplace_winner_lease(
		wallet_inst.clone(),
		secp,
		keychain_mask,
		target_id,
	)?;
	let (node_client, keychain, context_id) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let keychain = w.keychain(secp, keychain_mask)?;
		(node_client, keychain, w.get_context_id())
	};

	let skey = get_swap_storage_key(secp, &keychain)?;
	trades::restore_ethereum_resources(context_id, Some(swap_id), &skey)?;
	let swap_lock = trades::get_swap_lock(context_id, &swap_id.to_string())?;
	let _l = swap_lock.lock();

	let (context, mut swap) = trades::get_swap_trade(context_id, swap_id, &skey, &*swap_lock)?;

	// Updating electrumX URI if they are defined. We can't reset them. For reset use Adjust
	if electrum_node_uri1.is_some() {
		swap.electrum_node_uri1 = electrum_node_uri1;
	}
	if electrum_node_uri2.is_some() {
		swap.electrum_node_uri2 = electrum_node_uri2;
	}

	// upddate ethereum infura project id
	if eth_infura_project_id.is_some() {
		swap.eth_infura_project_id = eth_infura_project_id;
	}

	swap.wait_for_backup1 = wait_for_backup1;

	match swap_process_impl(
		context_id,
		secp,
		wallet_inst,
		keychain_mask,
		&mut swap,
		&context,
		node_client,
		&keychain,
		message_sender,
		|swap| trades::store_swap_trade(context_id, &context, swap, &skey, &*swap_lock),
		message_file_name,
		buyer_refund_address,
		secondary_fee,
		secondary_address,
	) {
		Ok(mut respond) => {
			swap.last_process_error = None;
			respond.last_error = swap.get_last_error();
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			Ok((respond, lease_notifications))
		}
		Err(e) => {
			swap.last_process_error = Some((swap.state.clone(), format!("{}", e)));
			swap.add_journal_message(format!("Processing error: {}", e));
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
			Err(e)
		}
	}
}

// Upgrade reconciliation is intentionally omitted. Swaps have been disabled
// for a long time, so no pending swap deals are expected at deployment.

/// Ensure wallet accounting exists for a swap receive transaction before it is
/// broadcast. This operation is idempotent by kernel excess.
fn ensure_swap_receive_tx_record<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	tx_name: String,
	parent_key_id: &Identifier,
	output_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let kernel = &slate
		.tx_or_err()?
		.body
		.kernels
		.first()
		.ok_or_else(|| Error::Generic("Swap receive transaction has no kernel".to_string()))?
		.excess;
	if wallet
		.tx_log_iter()?
		.any(|tx| tx.kernel_excess.map(|commit| commit == *kernel).unwrap_or(false))
	{
		return Ok(());
	}
	create_swap_receive_tx_record(
		wallet,
		secp,
		keychain_mask,
		slate,
		tx_name,
		parent_key_id,
		output_key_id,
	)
}

// Creating Transaction and output for expected recieve slate
fn create_swap_receive_tx_record<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	tx_name: String,
	parent_key_id: &Identifier, // account id
	output_key_id: &Identifier, // output MUST match parent_key_id
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let transaction = slate.tx_or_err()?;
	if transaction.body.kernels.len() != 1 {
		return Err(Error::Generic(format!(
			"Swap receive transaction must have exactly one kernel, found {}",
			transaction.body.kernels.len()
		)));
	}
	if transaction.body.outputs.len() != 1 {
		return Err(Error::Generic(format!(
			"Swap receive transaction must have exactly one output, found {}",
			transaction.body.outputs.len()
		)));
	}
	let output_commits = transaction
		.outputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	let output_commit = output_commits.first().ok_or_else(|| {
		Error::Generic("Swap receive transaction output commitment is missing".to_string())
	})?;
	let output_commit_hex = to_hex(&output_commit.0);
	let kernel_excess = transaction
		.body
		.kernels
		.first()
		.ok_or_else(|| Error::Generic("Swap receive transaction kernel is missing".to_string()))?
		.excess;
	let child_index = output_key_id.to_path()?.last_path_index()?;

	let mut batch = wallet.batch(secp, keychain_mask)?;
	let log_id = batch.next_tx_log_id(parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);

	// Creating trnasaction
	t.tx_slate_id = Some(slate.id.clone());
	t.amount_credited = slate.amount;
	t.address = Some(tx_name);
	t.num_outputs = 1;
	t.output_commits = output_commits;
	t.messages = None;
	t.ttl_cutoff_height = None;
	t.kernel_excess = Some(kernel_excess);
	t.kernel_lookup_min_height = Some(slate.height);
	batch.save_tx_log_entry(t, parent_key_id)?;

	// Creating output for that
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output_key_id.clone(),
		mmr_index: None,
		n_child: child_index,
		commit: Some(output_commit_hex),
		value: slate.amount,
		status: OutputStatus::Unconfirmed,
		height: slate.height,
		lock_height: slate.calc_lock_height()?,
		is_coinbase: false,
		tx_log_entry: Some(log_id),
	})?;
	batch.commit()?;
	Ok(())
}

/// Create Swap record from income message
pub fn swap_create_from_offer<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	message_filename: String,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Updating wallet state first because we need to select outputs.
	let mut file = File::open(message_filename.clone())
		.map_err(|e| Error::Generic(format!("Unable to open file {}, {}", message_filename, e)))?;
	let mut contents = String::new();
	file.read_to_string(&mut contents).map_err(|e| {
		Error::Generic(format!(
			"Unable to read a message from the file {}, {}",
			message_filename, e
		))
	})?;

	// processing the message with a regular API.
	// but first let's check if the message type matching expected
	let message = Message::from_json(&contents)?;
	if !message.is_offer() {
		return Err(Error::Generic(
			"Expected offer message, get different one".to_string(),
		));
	}

	swap_income_message_from_source(
		wallet_inst,
		secp,
		keychain_mask,
		&contents,
		SwapMessageSource::OwnerFile,
	)?;
	Ok(message.id.to_string())
}

/// Build a short-lived marketplace command signed by a pinned or current OnionV3 key.
pub fn create_marketplace_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	command: String,
	recipient: String,
	offer_id: String,
	swap_id: Option<Uuid>,
	nonce: Option<Uuid>,
	signing_address_index: Option<u32>,
) -> Result<MarketplaceMessage, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if command == "fail_bidding" && signing_address_index.is_none() {
		return Err(Error::InvalidMessageData(
			"Marketplace cancellation is missing its originating signing address index"
				.to_string(),
		));
	}
	let (context_id, signing_key) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let address_index = match signing_address_index {
			Some(address_index) => address_index,
			None => {
				let mut batch = w.batch(secp, keychain_mask)?;
				u32::try_from(batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?).map_err(
					|e| {
						Error::DataOverflow(format!(
							"Wallet address index exceeds u32 while signing marketplace message, {}",
							e
						))
					},
				)?
			}
		};
		let context_id = w.get_context_id();
		let signing_key = proofaddress::payment_proof_address_dalek_secret(
			secp,
			context_id,
			&keychain,
			address_index,
		)?;
		(context_id, signing_key)
	};
	let recipient = ProvableAddress::from_str(secp, context_id, &recipient)?;
	if recipient.public_key.len() != 56 {
		return Err(Error::InvalidMessageData(
			"Marketplace recipient must be an OnionV3 address".to_string(),
		));
	}
	let nonce = match nonce {
		Some(nonce) => nonce,
		None => new_marketplace_nonce()?,
	};
	MarketplaceMessage::signed(
		command,
		recipient.to_string(),
		offer_id,
		swap_id,
		nonce,
		Utc::now().timestamp(),
		Network::current_network(context_id)?,
		&signing_key,
	)
}

/// Get message for the marketplace.
pub fn marketplace_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	message: &str,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let json_msg: serde_json::Value = serde_json::from_str(message)
		.map_err(|e| Error::Generic(format!("Unable to parse json request, {}", e)))?;
	let command = json_msg
		.get("command")
		.and_then(serde_json::Value::as_str)
		.ok_or_else(|| Error::InvalidMessageData("Marketplace command is missing".to_string()))?;
	if command.len() > 32 {
		return Err(Error::InvalidMessageData(
			"Marketplace command is too long".to_string(),
		));
	}

	// Release the wallet mutex before acquiring any swap trade lock.
	let (keychain, skey, node_client, ethereum_wallet, context_id, wallet_address) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let context_id = w.get_context_id();
		let address_index = {
			let mut batch = w.batch(secp, keychain_mask)?;
			u32::try_from(batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?).map_err(|e| {
				Error::DataOverflow(format!(
					"Wallet address index exceeds u32 while verifying marketplace message, {}",
					e
				))
			})?
		};
		let signing_key = proofaddress::payment_proof_address_dalek_secret(
			secp,
			context_id,
			&keychain,
			address_index,
		)?;
		(
			keychain,
			skey,
			node_client,
			ethereum_wallet,
			context_id,
			ProvableAddress::from_tor_pub_key(&signing_key.verifying_key())?.to_string(),
		)
	};

	let response = if command == "accept_offer" || command == "check_offer" {
		let from = json_msg
			.get("from")
			.and_then(serde_json::Value::as_str)
			.ok_or_else(|| {
				Error::InvalidMessageData("Marketplace sender is missing".to_string())
			})?;
		let offer_id = json_msg
			.get("offer_id")
			.and_then(serde_json::Value::as_str)
			.ok_or_else(|| {
				Error::InvalidMessageData("Marketplace offer id is missing".to_string())
			})?;
		if offer_id.is_empty() || offer_id.len() > 256 {
			return Err(Error::InvalidMessageData(
				"Marketplace offer id has an invalid length".to_string(),
			));
		}

		// DoS policy: this unauthenticated Foreign API does not promise
		// per-method resistance to sustained request floods. Other valid foreign
		// calls, notably `receive_tx`, can also consume wallet work and create
		// pending state, so special throttling or caching only for this branch
		// would not establish a meaningful security boundary. Resource admission
		// belongs to the listener-wide connection, body, request and lifetime
		// limits; this active-trade scan is accepted as bounded application work.
		let mut swaps = Vec::new();
		for swap_id in trades::list_swap_trades(context_id)? {
			let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
			let _guard = swap_lock.lock();
			let (_context, swap) =
				trades::get_swap_trade(context_id, &swap_id, &skey, &*swap_lock)?;
			swaps.push(swap);
		}

		if ONLINE_OFFERS
			.read()
			.get(&context_id)
			.map(|offers| offers.contains_key(offer_id))
			.unwrap_or(false)
		{
			if command == "accept_offer" {
				if mwc_wallet_util::mwc_util::is_console_output_enabled() {
					println!(
						"Get accept_offer message from {} for {}",
						bounded_escape_for_display(from, MAX_MARKETPLACE_DISPLAY_BYTES),
						bounded_escape_for_display(offer_id, MAX_MARKETPLACE_DISPLAY_BYTES)
					);
				} else {
					info!(
						"Get accept_offer message from {} for {}",
						bounded_escape_for_display(from, MAX_MARKETPLACE_DISPLAY_BYTES),
						bounded_escape_for_display(offer_id, MAX_MARKETPLACE_DISPLAY_BYTES)
					);
				}
			}

			// Check if this offer is broadcasting and how many are running
			let tag = Some(offer_id.to_string());
			let accepted_peers = swaps.iter().filter(|s| s.tag == tag).count();
			format!("{{\"running\":{}}}", accepted_peers)
		} else {
			"{\"running\":-1}".to_string() // Doesn't exist
		}
	} else if command == "fail_bidding" {
		let signed_message: MarketplaceMessage = serde_json::from_value(json_msg)?;
		signed_message.verify(
			secp,
			context_id,
			&wallet_address,
			Network::current_network(context_id)?,
			Utc::now().timestamp(),
		)?;
		let swap_id = signed_message.swap_id.ok_or_else(|| {
			Error::InvalidMessageData(
				"Authenticated fail_bidding command is missing its swap id".to_string(),
			)
		})?;
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"Get fail_bidding message from {} for {}",
				bounded_escape_for_display(&signed_message.from, MAX_MARKETPLACE_DISPLAY_BYTES),
				bounded_escape_for_display(&signed_message.offer_id, MAX_MARKETPLACE_DISPLAY_BYTES)
			);
		} else {
			info!(
				"Get fail_bidding message from {} for {}",
				bounded_escape_for_display(&signed_message.from, MAX_MARKETPLACE_DISPLAY_BYTES),
				bounded_escape_for_display(&signed_message.offer_id, MAX_MARKETPLACE_DISPLAY_BYTES)
			);
		}
		let swap_id_string = swap_id.to_string();
		let swap_lock = trades::get_swap_lock(context_id, &swap_id_string)?;
		let _guard = swap_lock.lock();
		let (context, mut swap) =
			trades::get_swap_trade(context_id, &swap_id_string, &skey, &*swap_lock)?;
		if !swap.is_seller()
			|| swap.tag
				!= Some(format!(
					"{}_{}",
					signed_message.from, signed_message.offer_id
				)) {
			return Err(Error::InvalidMessageData(
				"Marketplace cancellation does not match the selected seller trade".to_string(),
			));
		}
		if swap.marketplace_received_cancel_nonce == Some(signed_message.nonce) {
			return Ok(json!({ "cancelled": true }).to_string());
		}
		if swap.marketplace_received_cancel_nonce.is_some() {
			return Err(Error::InvalidMessageData(
				"Swap already accepted a different marketplace cancellation".to_string(),
			));
		}

		let swap_api = if swap.secondary_currency.is_btc_family() {
			let (uri1, uri2) = trades::get_electrumx_uri(
				context_id,
				&swap.secondary_currency,
				&swap.electrum_node_uri1,
				&swap.electrum_node_uri2,
			)?;
			crate::swap::api::create_btc_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				uri1,
				uri2,
			)?
		} else {
			crate::swap::api::create_eth_instance(
				context_id,
				&swap.secondary_currency,
				node_client,
				ethereum_wallet,
				trades::get_eth_swap_contract_address(
					context_id,
					&swap.secondary_currency,
					&swap.eth_swap_contract_address,
				)?,
				trades::get_erc20_swap_contract_address(
					context_id,
					&swap.secondary_currency,
					&swap.erc20_swap_contract_address,
				)?,
				trades::get_eth_infura_projectid(
					context_id,
					&swap.secondary_currency,
					&swap.eth_infura_project_id,
				)?,
			)?
		};
		let mut fsm = swap_api.get_fsm(&keychain, &swap);
		if !fsm.is_cancellable(&swap)? {
			return Err(Error::InvalidMessageData(format!(
				"Swap {} is no longer cancellable",
				swap.id
			)));
		}
		let tx_conf = swap_api.request_tx_confirmations_for_cancel(secp, &keychain, &swap)?;
		fsm.process(Input::Cancel, &mut swap, &context, &tx_conf, secp)?;
		swap.marketplace_received_cancel_nonce = Some(signed_message.nonce);
		trades::store_swap_trade(context_id, &context, &swap, &skey, &*swap_lock)?;
		json!({ "cancelled": true }).to_string()
	} else {
		return Err(Error::InvalidMessageData(format!(
			"Marketplace message contains unknown command {}",
			bounded_escape_for_display(command, MAX_MARKETPLACE_DISPLAY_BYTES)
		)));
	};
	debug!(
		"marketplace_message response: {}",
		bounded_escape_for_display(&response, MAX_MARKETPLACE_DISPLAY_BYTES)
	);
	Ok(response)
}

/// Processing swap income message. Note result of that can be a new offer of modification of the current one
/// We only notify user about that, no permission will be ask.
/// Reason: Nothing will be done with the funds until user will go forward manually
/// Return: option ack message
/// `authenticated_sender` must come from the verified MQS transport. `None`
/// denotes unauthenticated network delivery and cannot update an existing MQS trade.
pub fn swap_income_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_message: &str,
	authenticated_sender: Option<&str>,
) -> Result<Option<Message>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let source = match authenticated_sender {
		Some(sender) => SwapMessageSource::AuthenticatedMqs(sender),
		None => SwapMessageSource::UnauthenticatedNetwork,
	};
	swap_income_message_from_source(wallet_inst, secp, keychain_mask, swap_message, source)
}

fn swap_income_message_from_source<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	swap_message: &str,
	source: SwapMessageSource<'_>,
) -> Result<Option<Message>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let authenticated_sender = source.authenticated_sender();
	let message = Message::from_json(swap_message)?;
	let swap_id = message.id.to_string();
	let incoming_message_group = incoming_protocol_message_group(&message.inner);
	let incoming_message_fingerprint = match incoming_message_group {
		Some(_) => Some(swap_message_fingerprint(&message)?),
		None => None,
	};
	let offer_fingerprint = match &message.inner {
		Update::Offer(_) => incoming_message_fingerprint.clone(),
		_ => None,
	};
	let offer_content_fingerprint = match &message.inner {
		Update::Offer(_) => Some(swap_offer_content_fingerprint(&message)?),
		_ => None,
	};

	debug!(
		"Get swap message {}",
		bounded_escape_for_display(&format!("{:?}", message), 4096)
	);

	// Reading the immutable wallet context id is the only wallet access needed
	// before context-free validation. In particular, malformed offers never ask
	// for the keychain or Ethereum wallet.
	let context_id = {
		wallet_lock!(wallet_inst, w);
		w.get_context_id()
	};
	if let Update::Offer(offer_update) = &message.inner {
		validate_authenticated_offer_sender(
			secp,
			context_id,
			offer_update,
			authenticated_sender,
		)?;
	}

	// Validate every context-free property of an incoming offer before
	// acquiring the creation lock, making endpoint RPC calls, or allocating
	// durable HD child indices. Otherwise a stream of unique invalid offers
	// can monopolize swap creation and burn derivation indices without ever
	// creating a trade.
	let mut statically_validated_offer = match &message.inner {
		Update::Offer(_) => {
			let (_, offer, secondary_update) = message.clone().unwrap_offer()?;
			Some(BuyApi::validate_offer_static(
				context_id,
				secp,
				offer,
				secondary_update,
			)?)
		}
		_ => None,
	};

	// Hex-encoded MWC lock input commitments of an incoming offer. The
	// creation-lock admission check uses them to reject offers that reuse
	// inputs of an active trade under a fresh UUID.
	let offer_lock_inputs = match &statically_validated_offer {
		Some(validated) => Some(validated.lock_input_commitments()?),
		None => None,
	};

	// Release the wallet mutex before acquiring any swap trade lock.
	let (node_client, ethereum_wallet, keychain, skey) = {
		wallet_lock!(wallet_inst, w);
		let node_client = w.w2n_client().clone();
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let keychain = w.keychain(secp, keychain_mask)?;
		let skey = get_swap_storage_key(secp, &keychain)?;
		(node_client, ethereum_wallet, keychain, skey)
	};

	// Probe for an existing UUID before remote validation. Exact retries must
	// bypass chain-input checks because an accepted offer's lock inputs may
	// already be spent. The probe lock is released before any node, contract, or
	// balance RPC; the record is checked again under the final creation/trade
	// locks before keys are allocated.
	let mut prepared_offer = match &message.inner {
		Update::Offer(offer_update) => {
			let incoming_fingerprint = offer_fingerprint.as_deref().ok_or_else(|| {
				Error::Generic("Internal error: offer fingerprint is missing".to_string())
			})?;
			let incoming_content_fingerprint =
				offer_content_fingerprint.as_deref().ok_or_else(|| {
					Error::Generic(
						"Internal error: offer content fingerprint is missing".to_string(),
					)
				})?;
			{
				let probe_lock = trades::get_swap_lock(context_id, &swap_id)?;
				let _probe_guard = probe_lock.lock();
				match trades::get_swap_trade(
					context_id,
					swap_id.as_str(),
					&skey,
					&*probe_lock,
				) {
					Ok((_context, existing_swap)) => {
						validate_authenticated_trade_sender(
							secp,
							context_id,
							&existing_swap,
							source,
						)?;
						if is_exact_offer_replay(&existing_swap, incoming_fingerprint) {
							debug!(
								"Acknowledging exact replay of swap offer {} without processing it again",
								swap_id
							);
							return Ok(Some(Message::new(
								message.id,
								Update::MessageAcknowledge(1),
								SecondaryUpdate::Empty,
							)));
						}
						return Err(Error::InvalidMessageData(format!(
							"Swap offer {} conflicts with an existing trade using the same UUID",
							swap_id
						)));
					}
					Err(Error::TradeNotFound(_)) => (),
					Err(e) => return Err(e),
				}
			}

			// The UUID is peer-controlled and is not an offer identity. Run the full
			// local admission check — typed content duplicates, reused MWC lock
			// inputs of active trades, and the wallet-wide and per-sender
			// pending-offer limits —
			// before spending remote RPC work on node, endpoint, and gas-balance
			// validation. This is a preflight; the same check is repeated under the
			// final creation lock to close races between concurrent UUIDs.
			{
				let creation_lock = trades::get_swap_creation_lock(context_id);
				let _creation_guard = creation_lock.lock();
				check_offer_admission(
					context_id,
					secp,
					&swap_id,
					incoming_content_fingerprint,
					offer_lock_inputs.as_ref(),
					authenticated_sender,
					&skey,
				)?;
			}

			let validated_offer = BuyApi::validate_offer_node(
				context_id,
				statically_validated_offer.take().ok_or_else(|| {
					Error::Generic(
						"Internal error: statically validated offer is missing".to_string(),
					)
				})?,
				&node_client.clone(),
			)?;

			let (swap_api, effective_eth_contracts) =
				match offer_update.secondary_currency.is_btc_family() {
					true => {
						let (uri1, uri2) = trades::get_electrumx_uri(
							context_id,
							&offer_update.secondary_currency,
							&None,
							&None,
						)?;
						(
							crate::swap::api::create_btc_instance(
								context_id,
								&offer_update.secondary_currency,
								node_client.clone(),
								uri1,
								uri2,
							)?,
							None,
						)
					}
					_ => {
						let contracts = resolve_effective_eth_contracts(
							context_id,
							&offer_update.secondary_currency,
							&None,
							&None,
						)?;
						let eth_infura_project_id = trades::get_eth_infura_projectid(
							context_id,
							&offer_update.secondary_currency,
							&None,
						)?;
						(
							crate::swap::api::create_eth_instance(
								context_id,
								&offer_update.secondary_currency,
								node_client.clone(),
								ethereum_wallet.clone(),
								contracts.eth.clone(),
								contracts.erc20.clone(),
								eth_infura_project_id,
							)?,
							Some(contracts),
						)
					}
				};
			if !offer_update.secondary_currency.is_btc_family() {
				// Buyer-created trades pin the same configured contract pair as
				// seller starts. Validate the endpoint and deployed runtime code
				// before deriving context keys or making the first durable write.
				swap_api.test_client_connections()?;
			}
			BuyApi::validate_offer_gas(
				context_id,
				validated_offer.offer(),
				Some(&ethereum_wallet),
			)?;
			Some((validated_offer, swap_api, effective_eth_contracts))
		}
		_ => None,
	};

	// An incoming offer creates a resource-bearing trade. Acquire the creation
	// lock before its UUID lock so a concurrent seller start cannot take a
	// reservation snapshot while this trade is being allocated and stored.
	let creation_lock = match &message.inner {
		Update::Offer(_) => Some(trades::get_swap_creation_lock(context_id)),
		_ => None,
	};
	let _creation_guard = creation_lock.as_ref().map(|lock| lock.lock());
	if let Some(incoming_content_fingerprint) = offer_content_fingerprint.as_deref() {
		// Creation and import use this same outer lock. Rechecking here ensures
		// that concurrent copies with different UUIDs cannot both allocate keys
		// and become durable after passing the preflight check together. The
		// admission check also rejects reused MWC lock inputs and a wallet or
		// sender holding too many unreviewed offers.
		check_offer_admission(
			context_id,
			secp,
			&swap_id,
			incoming_content_fingerprint,
			offer_lock_inputs.as_ref(),
			authenticated_sender,
			&skey,
		)?;
	}

	let lock = trades::get_swap_lock(context_id, &swap_id)?;
	let _guard = lock.lock();

	let ack_msg = match &message.inner {
		Update::None => {
			return Err(Error::Generic(
				"Get empty message, nothing to process".to_string(),
			));
		}
		Update::Offer(offer_update) => {
			// We get an offer
			let incoming_fingerprint = offer_fingerprint.as_deref().ok_or_else(|| {
				Error::Generic("Internal error: offer fingerprint is missing".to_string())
			})?;
			let incoming_content_fingerprint =
				offer_content_fingerprint.as_deref().ok_or_else(|| {
					Error::Generic(
						"Internal error: offer content fingerprint is missing".to_string(),
					)
				})?;
			match trades::get_swap_trade(context_id, swap_id.as_str(), &skey, &*lock) {
				Ok((_context, existing_swap)) => {
					validate_authenticated_trade_sender(secp, context_id, &existing_swap, source)?;
					if is_exact_offer_replay(&existing_swap, incoming_fingerprint) {
						debug!(
							"Acknowledging exact replay of swap offer {} without processing it again",
							swap_id
						);
						return Ok(Some(Message::new(
							message.id,
							Update::MessageAcknowledge(1),
							SecondaryUpdate::Empty,
						)));
					}
					return Err(Error::InvalidMessageData(format!(
						"Swap offer {} conflicts with an existing trade using the same UUID",
						swap_id
					)));
				}
				// Only a missing record permits creation. An unreadable or invalid
				// record still owns this ID and must never be overwritten.
				Err(Error::TradeNotFound(_)) => (),
				Err(e) => return Err(e),
			}

			let (validated_offer, mut swap_api, effective_eth_contracts) =
				prepared_offer.take().ok_or_else(|| {
					Error::Generic("Internal error: prepared offer is missing".to_string())
				})?;
			validated_offer.ensure_not_expired()?;

			// Creating Buyer context. Lock ordering: acquiring the wallet mutex while
			// holding a swap trade lock is allowed (swap -> wallet).
			let context = {
				wallet_lock!(wallet_inst, w);
				create_context(
					&mut **w,
					secp,
					Some(&ethereum_wallet),
					&mut swap_api,
					&keychain,
					offer_update.secondary_currency,
					false,
					None,
					0,
				)?
			};

			let id = message.id;
			let mut swap = BuyApi::accept_validated_swap_offer(
				context_id,
				secp,
				&keychain,
				&context,
				id,
				validated_offer,
				&node_client,
			)?;
			if let Some(contracts) = effective_eth_contracts {
				// Buyer construction historically left these fields empty. Pin the
				// contract pair used to validate the incoming offer before its first
				// durable write, for the same reason as seller-created trades.
				swap.eth_swap_contract_address = Some(contracts.eth);
				swap.erc20_swap_contract_address = Some(contracts.erc20);
			}
			swap.received_offer_fingerprint = Some(incoming_fingerprint.to_string());
			swap.received_offer_content_fingerprint =
				Some(incoming_content_fingerprint.to_string());
			let acknowledgement =
				swap.record_processed_incoming_message(1, incoming_fingerprint.to_string())?;

			trades::store_swap_trade(context_id, &context, &swap, &skey, &*lock)?;
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"INFO: You get an offer to swap {} to MWC. SwapID is {}",
					swap.secondary_currency, swap.id
				);
			} else {
				info!(
					"INFO: You get an offer to swap {} to MWC. SwapID is {}",
					swap.secondary_currency, swap.id
				);
			}
			Some(acknowledgement)
		}
		Update::MessageAcknowledge(msg_id) => {
			let (context, mut swap) =
				trades::get_swap_trade(context_id, swap_id.as_str(), &skey, &*lock)?;
			validate_authenticated_trade_sender(secp, context_id, &swap, source)?;
			// Both roles send one message in each group. The group number selects the
			// posted-message slot; the presence of that slot proves this trade sent it.
			match msg_id {
				1 if swap.posted_msg1.is_some() => swap.ack_msg1(),
				2 if swap.posted_msg2.is_some() => swap.ack_msg2(),
				1 | 2 => {
					return Err(Error::Generic(format!(
						"Received acknowledge for unsent message group {}",
						msg_id
					)));
				}
				_ => {
					return Err(Error::Generic(format!(
						"Get unknown message group {} at 'MessageAcknowledge'",
						msg_id
					)));
				}
			}
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*lock)?;
			None
		}
		_ => {
			let (context, mut swap) =
				trades::get_swap_trade(context_id, swap_id.as_str(), &skey, &*lock)?;
			validate_authenticated_trade_sender(secp, context_id, &swap, source)?;
			let msg_gr = incoming_message_group.ok_or_else(|| {
				Error::Generic("Internal error: incoming swap message group is missing".to_string())
			})?;
			let incoming_fingerprint =
				incoming_message_fingerprint.as_deref().ok_or_else(|| {
					Error::Generic(
						"Internal error: incoming swap message fingerprint is missing".to_string(),
					)
				})?;
			if let Some(acknowledgement) =
				swap.replay_processed_incoming_message(msg_gr, incoming_fingerprint)?
			{
				debug!(
					"Acknowledging exact replay of swap message group {} for {} without processing it again",
					msg_gr, swap.id
				);
				return Ok(Some(acknowledgement));
			}

			let swap_api = match swap.secondary_currency.is_btc_family() {
				true => {
					let (uri1, uri2) = trades::get_electrumx_uri(
						context_id,
						&swap.secondary_currency,
						&swap.electrum_node_uri1,
						&swap.electrum_node_uri2,
					)?;
					crate::swap::api::create_btc_instance(
						context_id,
						&swap.secondary_currency,
						node_client.clone(),
						uri1,
						uri2,
					)?
				}
				_ => {
					let eth_swap_contract_address = trades::get_eth_swap_contract_address(
						context_id,
						&swap.secondary_currency,
						&swap.eth_swap_contract_address,
					)?;
					let erc20_swap_contract_address = trades::get_erc20_swap_contract_address(
						context_id,
						&swap.secondary_currency,
						&swap.erc20_swap_contract_address,
					)?;
					let eth_infura_project_id = trades::get_eth_infura_projectid(
						context_id,
						&swap.secondary_currency,
						&swap.eth_infura_project_id,
					)?;
					crate::swap::api::create_eth_instance(
						context_id,
						&swap.secondary_currency,
						node_client.clone(),
						ethereum_wallet.clone(),
						eth_swap_contract_address,
						erc20_swap_contract_address,
						eth_infura_project_id,
					)?
				}
			};

			let tx_conf = swap_api.request_tx_confirmations(secp, &keychain, &swap)?;
			let mut fsm = swap_api.get_fsm(&keychain, &swap);
			swap.wait_for_backup1 = true; // Processing message pessimistic way. We don't want to trigger any action
			fsm.process(
				Input::IncomeMessage(message),
				&mut swap,
				&context,
				&tx_conf,
				secp,
			)?;
			let acknowledgement =
				swap.record_processed_incoming_message(msg_gr, incoming_fingerprint.to_string())?;
			trades::store_swap_trade(context_id, &context, &swap, &skey, &*lock)?;

			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!("INFO: Processed income message for SwapId {}", swap.id);
			} else {
				info!("INFO: Processed income message for SwapId {}", swap.id);
			}

			Some(acknowledgement)
		}
	};
	Ok(ack_msg)
}

// Local Helper method to create a context
fn create_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &mut Secp256k1,
	ethereum_wallet: Option<&EthereumWallet>,
	swap_api: &mut Box<dyn SwapApi<K> + 'a>,
	keychain: &K,
	secondary_currency: Currency,
	is_seller: bool,
	inputs: Option<Vec<SellerInput>>,
	change_amount: u64,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secondary_key_size =
		(**swap_api).context_key_count(keychain, secondary_currency, is_seller)?;
	let mut keys: Vec<Identifier> = Vec::new();
	let parent_key_id = if is_seller {
		wallet.parent_key_id()
	} else {
		// For Buyer it is receive account
		get_receive_account(wallet.get_context_id()).unwrap_or(wallet.parent_key_id())
	};

	for _ in 0..secondary_key_size {
		keys.push(wallet.next_child(Some(&parent_key_id))?);
	}

	let context = (**swap_api).create_context(
		secp,
		keychain,
		ethereum_wallet,
		secondary_currency,
		is_seller,
		inputs,
		change_amount,
		keys,
		parent_key_id,
	)?;

	Ok(context)
}

#[cfg(test)]
mod marketplace_tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::rand::TryRng;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test::serial;
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	use mwc_wallet_util::mwc_crates::uuid::{Variant, Version};
	use mwc_wallet_util::mwc_keychain::ExtKeychain;
	use std::convert::Infallible;
	use std::io;

	struct FixedRng;

	impl TryRng for FixedRng {
		type Error = Infallible;

		fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
			Ok(0x5a5a_5a5a)
		}

		fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
			Ok(0x5a5a_5a5a_5a5a_5a5a)
		}

		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
			dest.fill(0x5a);
			Ok(())
		}
	}

	struct FailingRng;

	impl TryRng for FailingRng {
		type Error = io::Error;

		fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
			Err(io::Error::other("entropy unavailable"))
		}

		fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
			Err(io::Error::other("entropy unavailable"))
		}

		fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
			Err(io::Error::other("entropy unavailable"))
		}
	}

	#[cfg(feature = "test-support")]
	fn store_marketplace_test_swap(
		context_id: u32,
		context: &Context,
		swap: &Swap,
		skey: &SecretKey,
	) -> Result<(), Error> {
		let swap_id = swap.id.to_string();
		let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
		let _guard = swap_lock.lock();
		trades::store_swap_trade(context_id, context, swap, skey, &*swap_lock)
	}

	#[cfg(feature = "test-support")]
	fn load_marketplace_test_swap(
		context_id: u32,
		swap_id: Uuid,
		skey: &SecretKey,
	) -> Result<Swap, Error> {
		let swap_id = swap_id.to_string();
		let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
		let _guard = swap_lock.lock();
		Ok(trades::get_swap_trade(context_id, &swap_id, skey, &*swap_lock)?.1)
	}

	#[test]
	fn marketplace_cancel_nonce_is_rfc_v4() -> Result<(), Error> {
		let nonce = new_marketplace_nonce_with_rng(&mut FixedRng)?;
		assert_eq!(nonce.get_version(), Some(Version::Random));
		assert_eq!(nonce.get_variant(), Variant::RFC4122);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn mwcmqs_binding_rejects_a_sender_after_the_peer_changes() -> Result<(), Error> {
		use mwc_wallet_util::mwc_crates::secp::key::PublicKey;

		global::set_local_chain_type(global::ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let current_secret = SecretKey::from_slice(&secp, &[41u8; 32])?;
		let stale_secret = SecretKey::from_slice(&secp, &[42u8; 32])?;
		let current = ProvableAddress::from_pub_key(
			&secp,
			0,
			&PublicKey::from_secret_key(&secp, &current_secret)?,
		)?;
		let stale = ProvableAddress::from_pub_key(
			&secp,
			0,
			&PublicKey::from_secret_key(&secp, &stale_secret)?,
		)?;
		let routed_current = format!("mwcmqs://{}@example.com:443", current);

		validate_mwcmqs_binding(&secp, 0, "mwcmqs", &routed_current, &current.public_key)?;
		let error = validate_mwcmqs_binding(&secp, 0, "mwcmqs", &routed_current, &stale.public_key)
			.unwrap_err();
		assert!(error.to_string().contains("current trade peer"));
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn trade_sender_validation_distinguishes_network_delivery_from_owner_files() -> Result<(), Error>
	{
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_1.json"))?;
		for method in ["mwcmqs", "tor", "file"] {
			swap.set_swap_trade_transport(method.to_string(), "owner-selected-peer".to_string())?;
			let network_result = validate_authenticated_trade_sender(
				&secp,
				0,
				&swap,
				SwapMessageSource::UnauthenticatedNetwork,
			);
			if method == "mwcmqs" {
				assert!(matches!(network_result, Err(Error::InvalidMessageData(_))));
			} else {
				network_result?;
			}
			validate_authenticated_trade_sender(&secp, 0, &swap, SwapMessageSource::OwnerFile)?;
		}
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn mwcmqs_offer_return_address_is_validated_without_authenticated_sender() -> Result<(), Error> {
		use mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey;
		use mwc_wallet_util::mwc_crates::secp::key::PublicKey;

		global::set_local_chain_type(global::ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let sender_secret = SecretKey::from_slice(&secp, &[84; 32])?;
		let sender = ProvableAddress::from_pub_key(
			&secp,
			0,
			&PublicKey::from_secret_key(&secp, &sender_secret)?,
		)?;
		let onion =
			ProvableAddress::from_tor_pub_key(&SigningKey::from_bytes(&[85; 32]).verifying_key())?;
		let (_, mut offer, _) =
			Message::from_json(include_str!("../../swap_test/message_1.json"))?.unwrap_offer()?;
		offer.communication_method = "mwcmqs".to_string();
		for address in [
			"not-a-key".to_string(),
			format!("mwcmqs://{}@", sender),
			format!("mwcmqs://{}@example.com:", sender),
			format!("mwcmqs://{}@example.com:65536", sender),
			format!("mwcmqs://{}@example.com:+443", sender),
			format!("mwcmqs://{}@example.com:-443", sender),
			onion.to_string(),
			format!("mwcmqs://{}", onion),
			format!("mwcmqs://{}@example.com:443", onion),
			format!("http://{}", sender),
		] {
			offer.from_address = address;
			for authenticated_sender in [None, Some(sender.public_key.as_str())] {
				assert!(
					matches!(
						validate_authenticated_offer_sender(&secp, 0, &offer, authenticated_sender),
						Err(Error::InvalidMessageData(_))
					),
					"accepted invalid MWCMQS return address {:?} with sender {:?}",
					offer.from_address,
					authenticated_sender,
				);
			}
		}

		for address in [
			sender.to_string(),
			format!("mwcmqs://{}", sender),
			format!("{}@example.com", sender),
			format!("mwcmqs://{}@example.com:443", sender),
			format!("mwcmqs://{}@example.com:00443", sender),
			format!("mwcmqs://{}@example.com:0", sender),
			format!("mwcmqs://{}@example.com:65535", sender),
		] {
			offer.from_address = address;
			validate_authenticated_offer_sender(&secp, 0, &offer, None)?;
			validate_authenticated_offer_sender(&secp, 0, &offer, Some(&sender.public_key))?;
		}
		for (method, address) in [("file", ""), ("tor", "peer.onion")] {
			offer.communication_method = method.to_string();
			offer.from_address = address.to_string();
			validate_authenticated_offer_sender(&secp, 0, &offer, None)?;
			assert!(validate_authenticated_offer_sender(
				&secp,
				0,
				&offer,
				Some(&sender.public_key),
			)
			.is_err());
		}
		Ok(())
	}

	#[test]
	fn marketplace_cancel_nonce_propagates_rng_failure() {
		let error = new_marketplace_nonce_with_rng(&mut FailingRng).unwrap_err();
		assert!(error.to_string().contains("entropy unavailable"));
	}

	#[test]
	fn pinned_index_remains_derivable_after_selecting_another_index() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[29; 32], false)?;
		let pinned =
			proofaddress::payment_proof_address_dalek_secret(&secp, 0, &keychain, 11)?;
		let current_after_rotation =
			proofaddress::payment_proof_address_dalek_secret(&secp, 0, &keychain, 12)?;
		let retry =
			proofaddress::payment_proof_address_dalek_secret(&secp, 0, &keychain, 11)?;

		assert_ne!(pinned.verifying_key(), current_after_rotation.verifying_key());
		assert_eq!(pinned.verifying_key(), retry.verifying_key());
		Ok(())
	}

	#[test]
	fn marketplace_signing_index_key_encodes_field_boundaries() -> Result<(), Error> {
		assert_ne!(
			marketplace_signing_address_index_key("ab", "c")?,
			marketplace_signing_address_index_key("a", "bc")?
		);
		assert_eq!(
			marketplace_signing_address_index_key("offer", "peer")?,
			marketplace_signing_address_index_key("offer", "peer")?
		);
		Ok(())
	}

	#[test]
	fn exact_offer_replay_uses_the_typed_wire_message_fingerprint() -> Result<(), Error> {
		let message = Message::from_json(include_str!("../../swap_test/message_1.json"))?;
		assert!(matches!(message.inner, Update::Offer(_)));
		let fingerprint = swap_message_fingerprint(&message)?;
		let content_fingerprint = swap_offer_content_fingerprint(&message)?;

		let reparsed = Message::from_json(&message.to_json()?)?;
		assert_eq!(fingerprint, swap_message_fingerprint(&reparsed)?);
		assert_eq!(
			content_fingerprint,
			swap_offer_content_fingerprint(&reparsed)?
		);

		let mut changed_uuid = message.clone();
		changed_uuid.id =
			Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid UUID");
		assert_ne!(fingerprint, swap_message_fingerprint(&changed_uuid)?);
		assert_eq!(
			content_fingerprint,
			swap_offer_content_fingerprint(&changed_uuid)?
		);

		let mut buyer_swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		buyer_swap.received_offer_fingerprint = Some(fingerprint.clone());
		assert!(is_exact_offer_replay(&buyer_swap, &fingerprint));

		let mut conflicting_message = message.clone();
		match &mut conflicting_message.inner {
			Update::Offer(offer) => offer.from_address.push_str("-different"),
			_ => unreachable!("fixture message must be an offer"),
		}
		let conflicting_fingerprint = swap_message_fingerprint(&conflicting_message)?;
		assert_ne!(fingerprint, conflicting_fingerprint);
		assert_ne!(
			content_fingerprint,
			swap_offer_content_fingerprint(&conflicting_message)?
		);
		assert!(!is_exact_offer_replay(
			&buyer_swap,
			&conflicting_fingerprint
		));
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn offer_content_duplicate_is_found_across_swap_uuids() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[79; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let message = Message::from_json(include_str!("../../swap_test/message_1.json"))?;
		let content_fingerprint = swap_offer_content_fingerprint(&message)?;
		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		existing.id = Uuid::parse_str("00000000-0000-0000-0000-000000000301").expect("valid UUID");
		existing.received_offer_content_fingerprint = Some(content_fingerprint.clone());
		store_marketplace_test_swap(context_id, &context, &existing, &skey)?;

		let incoming_id = "00000000-0000-0000-0000-000000000302";
		let creation_lock = trades::get_swap_creation_lock(context_id);
		let creation_guard = creation_lock.lock();
		// The same typed offer content under a different UUID is a duplicate.
		let duplicate_error = check_offer_admission(
			context_id,
			&secp,
			incoming_id,
			&content_fingerprint,
			None,
			None,
			&skey,
		)
		.unwrap_err();
		assert!(duplicate_error.to_string().contains(&existing.id.to_string()));
		// Different offer content is admitted.
		assert!(
			check_offer_admission(context_id, &secp, incoming_id, "different", None, None, &skey)
				.is_ok()
		);
		// A stored trade is not a duplicate of itself.
		assert!(check_offer_admission(
			context_id,
			&secp,
			&existing.id.to_string(),
			&content_fingerprint,
			None,
			None,
			&skey,
		)
		.is_ok());
		drop(creation_guard);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn sender_pending_offer_count_ignores_non_mwcmqs_transports() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[80; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		// A pending buy offer received over the file transport carries no
		// parseable MWCMQS sender key; it must not break admission of an
		// unrelated MWCMQS offer.
		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		existing.id = Uuid::parse_str("00000000-0000-0000-0000-000000000401").expect("valid UUID");
		existing.state = StateId::BuyerOfferCreated;
		existing.received_offer_content_fingerprint = Some("file-offer".to_string());
		store_marketplace_test_swap(context_id, &context, &existing, &skey)?;

		let creation_lock = trades::get_swap_creation_lock(context_id);
		let creation_guard = creation_lock.lock();
		assert!(check_offer_admission(
			context_id,
			&secp,
			"00000000-0000-0000-0000-000000000402",
			"incoming-offer",
			None,
			Some("mwcmqs-authenticated-sender"),
			&skey,
		)
		.is_ok());
		drop(creation_guard);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn malformed_stored_mwcmqs_sender_does_not_block_offer_admission() -> Result<(), Error> {
		use mwc_wallet_util::mwc_crates::secp::key::PublicKey;

		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[85; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		existing.id = Uuid::parse_str("00000000-0000-0000-0003-000000000001").expect("valid UUID");
		existing.state = StateId::BuyerOfferCreated;
		existing.communication_method = "mwcmqs".to_string();
		// Older offers received over Tor/file could persist this unchecked address.
		existing.communication_address = "not-a-key".to_string();
		existing.received_offer_content_fingerprint = Some("stored-offer".to_string());
		let stored_inputs = existing
			.lock_slate
			.slate
			.tx_or_err()?
			.inputs_committed()?
			.map(|input| input.map(|commit| to_hex(&commit.0)))
			.collect::<Result<HashSet<_>, _>>()?;
		assert!(!stored_inputs.is_empty());
		let fresh_inputs = HashSet::from([to_hex(&secp.commit_value(1)?.0)]);
		assert!(fresh_inputs.is_disjoint(&stored_inputs));
		let sender_secret = SecretKey::from_slice(&secp, &[86; 32])?;
		let sender = ProvableAddress::from_pub_key(
			&secp,
			context_id,
			&PublicKey::from_secret_key(&secp, &sender_secret)?,
		)?;
		let creation_lock = trades::get_swap_creation_lock(context_id);
		let creation_guard = creation_lock.lock();
		store_marketplace_test_swap(context_id, &context, &existing, &skey)?;
		let check_admission = |fingerprint: &str, inputs: &HashSet<String>| {
			check_offer_admission(
				context_id,
				&secp,
				"00000000-0000-0000-0003-ffffffffffff",
				fingerprint,
				Some(inputs),
				Some(&sender.public_key),
				&skey,
			)
		};

		check_admission("incoming-offer", &fresh_inputs)?;
		// A malformed sender does not exempt the record from the other checks.
		let duplicate_error = check_admission("stored-offer", &fresh_inputs).unwrap_err();
		assert!(duplicate_error.to_string().contains("duplicates existing trade"));
		let reused_input_error = check_admission("incoming-offer", &stored_inputs).unwrap_err();
		assert!(reused_input_error.to_string().contains("reuses MWC lock input"));
		for offer_number in 2..=MAX_PENDING_OFFERS_PER_WALLET {
			existing.id = Uuid::parse_str(&format!(
				"00000000-0000-0000-0003-{offer_number:012x}"
			))
			.expect("valid UUID");
			existing.received_offer_content_fingerprint = Some(format!("stored-offer-{offer_number}"));
			store_marketplace_test_swap(context_id, &context, &existing, &skey)?;
			if offer_number == MAX_PENDING_OFFERS_PER_WALLET - 1 {
				check_admission("incoming-offer", &fresh_inputs)?;
			}
		}
		let limit_error = check_admission("incoming-offer", &fresh_inputs).unwrap_err();
		assert!(limit_error.to_string().contains(&format!(
			"Wallet already has {} pending",
			MAX_PENDING_OFFERS_PER_WALLET
		)));
		drop(creation_guard);
		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn pending_offer_limits_reject_sender_and_wallet_saturation() -> Result<(), Error> {
		use mwc_wallet_util::mwc_crates::secp::key::PublicKey;

		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[81; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let repeated_secret = SecretKey::from_slice(&secp, &[83; 32])?;
		let repeated_sender = ProvableAddress::from_pub_key(
			&secp,
			context_id,
			&PublicKey::from_secret_key(&secp, &repeated_secret)?,
		)?;

		for offer_number in 1..=MAX_PENDING_OFFERS_PER_WALLET {
			let communication_address = if offer_number <= MAX_PENDING_OFFERS_PER_SENDER {
				repeated_sender.to_string()
			} else {
				let sender_byte = u8::try_from(offer_number).expect("offer limit fits in u8");
				let sender_secret = SecretKey::from_slice(&secp, &[sender_byte; 32])?;
				ProvableAddress::from_pub_key(
					&secp,
					context_id,
					&PublicKey::from_secret_key(&secp, &sender_secret)?,
				)?
				.to_string()
			};
			let mut existing: Swap =
				serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
			existing.id = Uuid::parse_str(&format!(
				"00000000-0000-0000-0002-{offer_number:012x}"
			))
			.expect("valid UUID");
			existing.state = StateId::BuyerOfferCreated;
			existing.communication_method = "mwcmqs".to_string();
			existing.communication_address = communication_address;
			existing.received_offer_content_fingerprint =
				Some(format!("rotated-sender-offer-{offer_number}"));
			store_marketplace_test_swap(context_id, &context, &existing, &skey)?;
		}

		let incoming_secret = SecretKey::from_slice(&secp, &[82; 32])?;
		let incoming_sender = ProvableAddress::from_pub_key(
			&secp,
			context_id,
			&PublicKey::from_secret_key(&secp, &incoming_secret)?,
		)?;
		let creation_lock = trades::get_swap_creation_lock(context_id);
		let creation_guard = creation_lock.lock();
		let sender_error = check_offer_admission(
			context_id,
			&secp,
			"00000000-0000-0000-0002-eeeeeeeeeeee",
			"same-sender-incoming-offer",
			None,
			Some(&repeated_sender.public_key),
			&skey,
		)
		.unwrap_err();
		let expected_sender_error = format!(
			"Sender already has {} pending",
			MAX_PENDING_OFFERS_PER_SENDER
		);
		assert!(sender_error.to_string().contains(&expected_sender_error));

		for authenticated_sender in [Some(incoming_sender.public_key.as_str()), None] {
			let error = check_offer_admission(
				context_id,
				&secp,
				"00000000-0000-0000-0002-ffffffffffff",
				"rotated-sender-incoming-offer",
				None,
				authenticated_sender,
				&skey,
			)
			.unwrap_err();
			let expected = format!(
				"Wallet already has {} pending",
				MAX_PENDING_OFFERS_PER_WALLET
			);
			assert!(error.to_string().contains(&expected));
		}
		drop(creation_guard);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn processed_incoming_message_receipt_survives_reload() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[81; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_sell.json"))?;
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_4.json"))?;
		let message = Message::from_json(include_str!("../../swap_test/message_3.json"))?;
		assert_eq!(swap.id, message.id);

		let fingerprint = swap_message_fingerprint(&message)?;
		assert!(
			swap.replay_processed_incoming_message(2, &fingerprint)?
				.is_none()
		);
		let expected_acknowledgement =
			swap.record_processed_incoming_message(2, fingerprint.clone())?;
		let stored_state = swap.state.clone();
		let stored_journal_len = swap.journal.len();
		store_marketplace_test_swap(context_id, &context, &swap, &skey)?;

		let reloaded = load_marketplace_test_swap(context_id, swap.id, &skey)?;
		let replayed_acknowledgement = reloaded
			.replay_processed_incoming_message(2, &fingerprint)?
			.expect("the durable receipt must acknowledge an exact replay");
		assert_eq!(
			replayed_acknowledgement.to_json()?,
			expected_acknowledgement.to_json()?
		);
		assert_eq!(reloaded.state, stored_state);
		assert_eq!(reloaded.journal.len(), stored_journal_len);

		// A backup from before InitRedeem lacks the adaptor signature. It must
		// not acquire a receipt that would suppress the message needed to restore it.
		let mut before_redeem: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_3.json"))?;
		assert!(before_redeem.adaptor_signature.is_none());
		assert!(reloaded.adaptor_signature.is_some());
		let mut live = reloaded.clone();
		assert!(matches!(
			reconcile_imported_replay_state(&mut live, &mut before_redeem),
			Err(Error::InvalidMessageData(_))
		));
		assert!(before_redeem.processed_incoming_ack2.is_none());
		assert_eq!(live.adaptor_signature, reloaded.adaptor_signature);
		let mut matching_backup = reloaded.clone();
		reconcile_imported_replay_state(&mut live, &mut matching_backup)?;
		assert_eq!(
			matching_backup
				.replay_processed_incoming_message(2, &fingerprint)?
				.expect("matching backup must retain its receipt")
				.to_json()?,
			expected_acknowledgement.to_json()?
		);

		let conflicting = Message::from_json(include_str!("../../swap_test/message_4.json"))?;
		let conflicting_fingerprint = swap_message_fingerprint(&conflicting)?;
		assert!(matches!(
			reloaded.replay_processed_incoming_message(2, &conflicting_fingerprint),
			Err(Error::InvalidMessageData(_))
		));

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[test]
	fn failed_staged_swap_check_leaves_the_live_trade_unchanged() -> Result<(), Error> {
		let mut swap: Swap = serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		let original = serde_json::to_value(&swap)?;

		let result: Result<(), Error> = commit_swap_on_success(&mut swap, |staged_swap| {
			staged_swap.other_lock_first_done = true;
			staged_swap.redeem_slate.slate.fee = 42;
			staged_swap.add_journal_message("partial check mutation".to_string());
			Err(Error::Generic("injected check failure".to_string()))
		});

		assert!(result.is_err());
		assert_eq!(serde_json::to_value(&swap)?, original);
		Ok(())
	}

	fn empty_marketplace_confirmations() -> SwapTransactionsConfirmations {
		SwapTransactionsConfirmations {
			mwc_observed: true,
			secondary_observed: true,
			mwc_tip: 0,
			mwc_lock_conf: None,
			mwc_redeem_conf: None,
			mwc_refund_conf: None,
			secondary_tip: 0,
			secondary_lock_conf: None,
			secondary_lock_amount: 0,
			secondary_redeem_conf: None,
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		}
	}

	#[test]
	fn marketplace_mempool_lock_counts_as_progress() {
		let mut confirmations = empty_marketplace_confirmations();
		assert!(!marketplace_lock_seen(&confirmations));

		confirmations.mwc_lock_conf = Some(0);
		assert!(marketplace_lock_seen(&confirmations));
		confirmations.mwc_lock_conf = None;
		confirmations.secondary_lock_amount = 1;
		assert!(marketplace_lock_seen(&confirmations));
	}

	#[test]
	fn marketplace_winner_decision_uses_the_ten_minute_lease() {
		let expires_at = 1_600;
		assert_eq!(
			marketplace_winner_decision(false, expires_at, 1_599),
			MarketplaceWinnerDecision::Wait
		);
		assert_eq!(
			marketplace_winner_decision(true, expires_at, 1_599),
			MarketplaceWinnerDecision::Wait
		);
		assert_eq!(
			marketplace_winner_decision(false, expires_at, expires_at),
			MarketplaceWinnerDecision::Replace
		);
		assert_eq!(
			marketplace_winner_decision(true, expires_at, 2_000),
			MarketplaceWinnerDecision::RejectNew
		);
	}

	#[cfg(feature = "test-support")]
	fn with_marketplace_lease_trades(
		test: impl FnOnce(u32, &Context, &SecretKey, [Swap; 3]) -> Result<(), Error>,
	) -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[87; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let base: Swap = serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		let candidates = [0x871, 0x872, 0x873].map(|id| {
			let mut swap = base.clone();
			swap.id = Uuid::from_u128(id);
			swap.state = StateId::BuyerOfferCreated;
			swap.tag = Some("marketplace-lease-regression".to_string());
			swap.posted_msg1 = None;
			swap.marketplace_winner_lease_expires_at = None;
			swap
		});
		for candidate in &candidates {
			store_marketplace_test_swap(context_id, &context, candidate, &skey)?;
		}
		let result = test(context_id, &context, &skey, candidates);
		trades::trades_clean_context(context_id);
		result
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn marketplace_overlapping_replacements_keep_one_winner() -> Result<(), Error> {
		with_marketplace_lease_trades(|context_id, _, skey, [old, first, second]| {
			probe_or_claim_marketplace_lease(context_id, old.id, 1_000, skey)?;
			// Both requests finish discovery before either chain lookup returns.
			let first_observation =
				probe_or_claim_marketplace_lease(context_id, first.id, 1_700, skey)?
					.expect("old winner");
			let second_observation =
				probe_or_claim_marketplace_lease(context_id, second.id, 1_700, skey)?
					.expect("same old winner");
			assert_eq!(first_observation, second_observation);
			let confirmations = empty_marketplace_confirmations();
			let notifications = apply_marketplace_winner_observation(
				context_id,
				first.id,
				first_observation,
				&confirmations,
				skey,
			)?;
			assert_eq!(notifications.len(), 1);
			assert_eq!(notifications[0].swap_id, old.id);
			let first_lease = load_marketplace_test_swap(context_id, first.id, skey)?
				.marketplace_winner_lease_expires_at
				.expect("first replacement owns the lease");

			// The second lookup still refers to the now-cancelled old winner.
			let error = apply_marketplace_winner_observation(
				context_id,
				second.id,
				second_observation,
				&confirmations,
				skey,
			)
			.unwrap_err();
			assert!(matches!(error, Error::Generic(message) if message.contains("winner changed")));
			let second = load_marketplace_test_swap(context_id, second.id, skey)?;
			assert_eq!(second.state, StateId::BuyerOfferCreated);
			assert!(second.marketplace_winner_lease_expires_at.is_none());
			assert!(!second.pending_marketplace_cancel_notification);
			assert_eq!(
				probe_or_claim_marketplace_lease(context_id, second.id, 1_700, skey)?,
				Some((first.id, first_lease))
			);
			assert_eq!(
				load_marketplace_test_swap(context_id, old.id, skey)?.state,
				StateId::BuyerCancelled
			);
			Ok(())
		})
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn marketplace_replacement_preserves_pending_deposit_recovery() -> Result<(), Error> {
		use crate::SecondaryFeeUnits;
		use crate::swap::ethereum::EthTransactionRecovery;
		use crate::swap::types::SecondaryData;
		use mwc_wallet_util::mwc_web3::types::{Bytes, H256, U256};

		for currency in [Currency::Ether, Currency::Usdt] {
			for recovery_only in [false, true] {
				with_marketplace_lease_trades(
					|context_id, context, skey, [mut old, first, second]| {
						old.secondary_currency = currency;
						old.secondary_fee_units = SecondaryFeeUnits::EthereumGwei(10);
						old.state = StateId::BuyerPostingSecondaryToMultisigAccount;
						old.seller_lock_first = false;
						old.posted_msg1 = Some(1_000);
						old.secondary_data = SecondaryData::Eth(serde_json::from_value(json!({
							"redeem_address": null, "address_from_secret": null,
							"erc20_approve_tx": null, "lock_tx": null, "refund_tx": null,
							"redeem_tx": null, "tx_fee_gwei": null
						}))?);
						let hash = H256::from_low_u64_be(87);
						let data = old.secondary_data.unwrap_eth_mut()?;
						if recovery_only {
							data.lock_recovery = Some(EthTransactionRecovery {
								chain_id: 3,
								sender: Address::from_low_u64_be(827401),
								nonce: U256::from(1),
								to: Address::from_low_u64_be(827402),
								value: U256::from(1),
								data: Bytes(vec![1, 2, 3]),
								gas_limit: U256::from(21_000),
								gas_price: U256::from(1),
								gas_budget_gwei: 10,
								raw_transaction: Bytes(vec![4, 5, 6]),
								attempted_hashes: vec![hash],
								last_attempt_at: 1_100,
								rebroadcasted: false,
							});
						} else {
							data.lock_tx = Some(hash);
						}
						let saved_deposit = serde_json::to_value(&old.secondary_data)?;
						store_marketplace_test_swap(context_id, context, &old, skey)?;
						probe_or_claim_marketplace_lease(context_id, old.id, 1_000, skey)?;
						let expected =
							probe_or_claim_marketplace_lease(context_id, first.id, 1_700, skey)?
								.expect("old winner");
						let notifications = apply_marketplace_winner_observation(
							context_id,
							first.id,
							expected,
							&empty_marketplace_confirmations(),
							skey,
						)?;
						assert_eq!(notifications.len(), 1);
						assert_eq!(notifications[0].swap_id, old.id);
						// Reload encrypted storage as after a restart, not just the staged swap.
						let mut cancelled = load_marketplace_test_swap(context_id, old.id, skey)?;
						assert_eq!(cancelled.state, StateId::BuyerWaitingForRefundTime);
						assert_eq!(
							serde_json::to_value(&cancelled.secondary_data)?,
							saved_deposit
						);
						assert!(cancelled.pending_marketplace_cancel_notification);
						assert_eq!(
							cancelled.marketplace_cancel_notification.as_ref(),
							notifications.first()
						);
						let first_lease = load_marketplace_test_swap(context_id, first.id, skey)?
							.marketplace_winner_lease_expires_at
							.expect("replacement lease");
						// Advancing refund recovery must not resurrect the old reservation.
						for state in [
							StateId::BuyerWaitingForRefundTime,
							StateId::BuyerPostingRefundForSecondary,
							StateId::BuyerWaitingForRefundConfirmations,
						] {
							cancelled.state = state;
							store_marketplace_test_swap(context_id, context, &cancelled, skey)?;
							assert_eq!(
								probe_or_claim_marketplace_lease(
									context_id, second.id, 1_700, skey
								)?,
								Some((first.id, first_lease))
							);
						}
						Ok(())
					},
				)?;
			}
		}
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn marketplace_visible_lock_rejects_replacement() -> Result<(), Error> {
		with_marketplace_lease_trades(|context_id, _, skey, [old, first, _]| {
			probe_or_claim_marketplace_lease(context_id, old.id, 1_000, skey)?;
			let expected = probe_or_claim_marketplace_lease(context_id, first.id, 1_700, skey)?
				.expect("old winner");
			let mut confirmations = empty_marketplace_confirmations();
			confirmations.secondary_lock_conf = Some(0);
			assert!(
				apply_marketplace_winner_observation(
					context_id,
					first.id,
					expected,
					&confirmations,
					skey,
				)
				.is_err()
			);
			let rejected = load_marketplace_test_swap(context_id, first.id, skey)?;
			assert_eq!(rejected.state, StateId::BuyerCancelled);
			assert!(rejected.marketplace_winner_lease_expires_at.is_none());
			assert!(rejected.pending_marketplace_cancel_notification);
			let winner = load_marketplace_test_swap(context_id, old.id, skey)?;
			assert_eq!(winner.state, old.state);
			assert_eq!(winner.marketplace_winner_lease_expires_at, Some(expected.1));
			assert!(!winner.pending_marketplace_cancel_notification);
			Ok(())
		})
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn marketplace_candidates_share_one_ten_minute_lease() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[72; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let base: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;

		let mut first = base.clone();
		first.id = Uuid::parse_str("00000000-0000-0000-0000-000000000071")
			.expect("valid test UUID");
		first.state = StateId::BuyerOfferCreated;
		first.tag = Some("marketplace-offer".to_string());
		first.posted_msg1 = None;

		let mut second = base;
		second.id = Uuid::parse_str("00000000-0000-0000-0000-000000000072")
			.expect("valid test UUID");
		second.state = StateId::BuyerOfferCreated;
		second.tag = first.tag.clone();
		second.posted_msg1 = None;

		store_marketplace_test_swap(context_id, &context, &first, &skey)?;
		store_marketplace_test_swap(context_id, &context, &second, &skey)?;

		assert_eq!(
			probe_or_claim_marketplace_lease(context_id, first.id, 1_000, &skey)?,
			None
		);
		assert_eq!(
			load_marketplace_test_swap(context_id, first.id, &skey)?
				.marketplace_winner_lease_expires_at,
			Some(1_000 + MARKETPLACE_WINNER_LEASE_SECS)
		);
		assert_eq!(
			probe_or_claim_marketplace_lease(context_id, second.id, 1_001, &skey)?,
			Some((first.id, 1_000 + MARKETPLACE_WINNER_LEASE_SECS))
		);
		assert_eq!(
			probe_or_claim_marketplace_lease(
				context_id,
				second.id,
				1_000 + MARKETPLACE_WINNER_LEASE_SECS,
				&skey,
			)?,
			Some((first.id, 1_000 + MARKETPLACE_WINNER_LEASE_SECS))
		);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn marketplace_outbox_scan_defers_a_busy_trade() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 0;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[73; 32], false)?;
		let skey = get_swap_storage_key(&secp, &keychain)?;
		let context: Context =
			serde_json::from_str(include_str!("../../swap_test/context_buy.json"))?;
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		swap.tag = Some("marketplace-offer".to_string());
		swap.pending_marketplace_cancel_notification = true;
		store_marketplace_test_swap(context_id, &context, &swap, &skey)?;

		let swap_id = swap.id.to_string();
		let swap_lock = trades::get_swap_lock(context_id, &swap_id)?;
		let guard = swap_lock.lock();
		assert!(matches!(
			try_inspect_pending_marketplace_cancel_record(context_id, &swap_id, &skey),
			Err(Error::Generic(message)) if message.contains("deferred")
		));
		drop(guard);

		let notification =
			try_inspect_pending_marketplace_cancel_record(context_id, &swap_id, &skey)?
				.expect("the pending notification must be collected after the lock is released");
		assert_eq!(notification.swap_id, swap.id);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[test]
	fn cancellation_outbox_identity_survives_trade_field_changes() -> Result<(), Error> {
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		swap.tag = Some("marketplace-offer".to_string());
		swap.communication_address = "original-peer".to_string();
		swap.marketplace_signing_address_index = Some(17);
		swap.pending_marketplace_cancel_notification = true;
		swap.marketplace_cancel_notification_nonce = Some(Uuid::new_v4());

		let original = materialize_marketplace_cancel_notification(&mut swap)?
			.expect("pending cancellation must materialize");
		swap.tag = Some("adjusted-offer".to_string());
		swap.communication_address = "adjusted-peer".to_string();
		swap.marketplace_signing_address_index = Some(18);

		assert_eq!(
			materialize_marketplace_cancel_notification(&mut swap)?,
			Some(original.clone())
		);
		assert_eq!(original.offer_id, "marketplace-offer");
		assert_eq!(original.peer_address, "original-peer");
		assert_eq!(original.signing_address_index, Some(17));
		Ok(())
	}

	// Workflow: Reconcile stale backups without replacement history, with and
	// without the original redirect marker, against a live trade holding both
	// hashes. Repeat each import, then try a conflicting original marker.
	// Expected: Imports preserve the live marker and both hashes without adding
	// duplicates. A conflicting marker returns InvalidMessageData, preserving
	// the identity that prevents another full-value redirect payment.
	#[test]
	fn import_preserves_redirect_replacement_history() -> Result<(), Error> {
		use super::super::ethereum::{
			Erc20AllowanceKey, Erc20ApprovalKind, Erc20ApprovalRecovery, Erc20Funding,
			Erc20FundingPhase, EthTransactionRecovery,
		};
		use mwc_wallet_util::mwc_web3::types::{Address, H256};

		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_5.json"))?;
		let original = H256::from_low_u64_be(42);
		let replacement = H256::from_low_u64_be(43);
		existing.secondary_currency = Currency::Ether;
		existing.secondary_data = crate::swap::types::SecondaryData::Eth(serde_json::from_value(
			serde_json::json!({
				"redeem_address": null, "address_from_secret": null,
				"erc20_approve_tx": null, "lock_tx": null, "refund_tx": null,
				"redeem_tx": null, "tx_fee_gwei": null,
				"redirect_tx": original,
				"redirect_tx_candidates": [original, replacement]
			}),
		)?);

		for old_hash in [None, Some(original)] {
			let mut imported = existing.clone();
			let data = imported.secondary_data.unwrap_eth_mut()?;
			data.redirect_tx = old_hash;
			data.redirect_tx_candidates.clear();
			reconcile_imported_replay_state(&mut existing, &mut imported)?;
			// Repeated imports must not duplicate candidates.
			reconcile_imported_replay_state(&mut existing, &mut imported)?;
			let data = imported.secondary_data.unwrap_eth()?;
			assert_eq!(data.redirect_tx, Some(original));
			assert_eq!(data.redirect_tx_candidates, vec![original, replacement]);
		}

		let mut conflicting = existing.clone();
		conflicting.secondary_data.unwrap_eth_mut()?.redirect_tx = Some(replacement);
		assert!(matches!(
			reconcile_imported_replay_state(&mut existing, &mut conflicting),
			Err(Error::InvalidMessageData(_))
		));

		// Redirect reconciliation must not authorize erasing another transaction's
		// durable hash, signed recovery, replacement history or allowance reservation.
		let recovery = EthTransactionRecovery {
			chain_id: 1,
			sender: Address::repeat_byte(1),
			nonce: 7.into(),
			to: Address::repeat_byte(2),
			value: 42.into(),
			data: Default::default(),
			gas_limit: 21_000.into(),
			gas_price: 100.into(),
			gas_budget_gwei: 5_500_000,
			raw_transaction: vec![4].into(),
			attempted_hashes: vec![original, replacement],
			last_attempt_at: 1_000,
			rebroadcasted: false,
		};
		let funding = Erc20Funding {
			key: Erc20AllowanceKey {
				chain_id: recovery.chain_id,
				owner: recovery.sender,
				token: Address::repeat_byte(3),
				spender: recovery.to,
			},
			phase: Erc20FundingPhase::DepositPending(replacement),
		};
		let history = vec![Erc20ApprovalRecovery {
			kind: Erc20ApprovalKind::Approve(42),
			transaction: recovery.clone(),
		}];
		for (field, value) in [
			("erc20_approve_tx", json!(original)),
			("lock_tx", json!(original)),
			("refund_tx", json!(original)),
			("redeem_tx", json!(original)),
			("erc20_approval_recovery", json!(recovery)),
			("lock_recovery", json!(recovery)),
			("lock_cancel_recovery", json!(recovery)),
			("refund_recovery", json!(recovery)),
			("redeem_recovery", json!(recovery)),
			("erc20_funding", json!(funding)),
			("erc20_approval_history", json!(history)),
		] {
			let mut live = existing.clone();
			let mut data = serde_json::to_value(live.secondary_data.unwrap_eth()?)?;
			data[field] = value;
			live.secondary_data =
				crate::swap::types::SecondaryData::Eth(serde_json::from_value(data)?);
			let mut stale = existing.clone();
			assert!(
				matches!(
					reconcile_imported_replay_state(&mut live, &mut stale),
					Err(Error::InvalidMessageData(_))
				),
				"import must not discard {field}"
			);
			let mut matching = live.clone();
			reconcile_imported_replay_state(&mut live, &mut matching)?;
		}

		let mut live = existing.clone();
		live.secondary_data.unwrap_eth_mut()?.lock_recovery = Some(recovery.clone());
		let mut stale = live.clone();
		stale
			.secondary_data
			.unwrap_eth_mut()?
			.lock_recovery
			.as_mut()
			.unwrap()
			.attempted_hashes
			.pop();
		assert!(matches!(
			reconcile_imported_replay_state(&mut live, &mut stale),
			Err(Error::InvalidMessageData(_))
		));
		Ok(())
	}

	// AcceptOffer processing finishes before publication, so a pre-broadcast
	// backup has the same receipts. Neither a pending lock nor a lost broadcast
	// response may let that backup erase the marker that keeps refunds active.
	#[test]
	fn import_rejects_lost_seller_lock_exposure() -> Result<(), Error> {
		let mut backup: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_3.json"))?;
		backup.state = StateId::SellerPostingLockMwcSlate;
		backup.posted_lock = None;
		let message = Message::from_json(include_str!("../../swap_test/message_2.json"))?;
		backup.record_processed_incoming_message(1, swap_message_fingerprint(&message)?)?;

		for state in [
			StateId::SellerPostingLockMwcSlate,
			StateId::SellerWaitingForLockConfirmations,
			StateId::SellerWaitingForRefundHeight,
		] {
			let mut existing = backup.clone();
			existing.state = state;
			existing.posted_lock = Some(123_456);
			existing.marketplace_winner_lease_expires_at = Some(123_456);
			let mut imported = backup.clone();
			let existing_before = serde_json::to_value(&existing)?;
			let imported_before = serde_json::to_value(&imported)?;

			assert!(matches!(
				reconcile_imported_replay_state(&mut existing, &mut imported),
				Err(Error::InvalidMessageData(message)) if message.contains("lock exposure")
			));
			assert_eq!(serde_json::to_value(&existing)?, existing_before);
			assert_eq!(serde_json::to_value(&imported)?, imported_before);
		}
		Ok(())
	}

	// A retry can change the timestamp while retaining exposure. Newer backups,
	// unpublished seller trades and buyer records must remain importable.
	#[test]
	fn import_allows_compatible_lock_exposure() -> Result<(), Error> {
		let seller_fixture = include_str!("../../swap_test/swap_sell_3.json");
		let buyer_fixture = include_str!("../../swap_test/swap_buy_1.json");
		for (fixture, live_posted, backup_posted) in [
			(seller_fixture, None, None),
			(seller_fixture, None, Some(123_456)),
			(seller_fixture, Some(123_456), Some(123_456)),
			(seller_fixture, Some(123_456), Some(123_455)),
			(seller_fixture, Some(123_456), Some(123_457)),
			(buyer_fixture, Some(123_456), None),
		] {
			let mut existing: Swap = serde_json::from_str(fixture)?;
			existing.posted_lock = live_posted;
			let mut imported = existing.clone();
			imported.posted_lock = backup_posted;

			reconcile_imported_replay_state(&mut existing, &mut imported)?;
			assert_eq!(existing.posted_lock, live_posted);
			assert_eq!(imported.posted_lock, backup_posted);
		}
		Ok(())
	}

	#[test]
	fn import_allows_matching_and_newer_seller_redeem_state() -> Result<(), Error> {
		let before_init = include_str!("../../swap_test/swap_sell_3.json");
		let before = include_str!("../../swap_test/swap_sell_4.json");
		let observed = include_str!("../../swap_test/swap_sell_5.json");
		for (live, backup) in [
			(before_init, before_init),
			(before_init, before),
			(before_init, observed),
			(before, before),
			(before, observed),
			(observed, observed),
		] {
			let mut existing: Swap = serde_json::from_str(live)?;
			let mut imported: Swap = serde_json::from_str(backup)?;
			let expected = serde_json::to_value(&imported.redeem_slate)?;
			let expected_marker = imported.redeem_kernel_updated;
			reconcile_imported_replay_state(&mut existing, &mut imported)?;
			assert_eq!(serde_json::to_value(&imported.redeem_slate)?, expected);
			assert_eq!(imported.redeem_kernel_updated, expected_marker);
		}
		Ok(())
	}

	// A backup after processing Redeem but before its first broadcast has the
	// same message receipts. It must not erase the later exposure marker or
	// partially reconcile any other live state when rejected.
	#[test]
	fn import_rejects_lost_buyer_redeem_exposure() -> Result<(), Error> {
		let mut imported: Swap = serde_json::from_str(include_str!("../../swap_test/swap_buy_3.json"))?;
		imported.state = StateId::BuyerRedeemMwc;
		imported.posted_redeem = None;
		for (group, json) in [
			(1, include_str!("../../swap_test/message_1.json")),
			(2, include_str!("../../swap_test/message_4.json")),
		] {
			let message = Message::from_json(json)?;
			imported.record_processed_incoming_message(group, swap_message_fingerprint(&message)?)?;
		}
		let mut existing = imported.clone();
		existing.posted_redeem = Some(123_456);
		existing.state = StateId::BuyerWaitForRedeemMwcConfirmations;
		existing.marketplace_winner_lease_expires_at = Some(123_456);
		let existing_before = serde_json::to_value(&existing)?;
		let imported_before = serde_json::to_value(&imported)?;

		assert!(matches!(
			reconcile_imported_replay_state(&mut existing, &mut imported),
			Err(Error::InvalidMessageData(message)) if message.contains("redeem exposure")
		));
		assert_eq!(serde_json::to_value(&existing)?, existing_before);
		assert_eq!(serde_json::to_value(&imported)?, imported_before);
		Ok(())
	}

	// Rebroadcasts change timestamps without undoing exposure. Backups from
	// before either record submitted a redeem, newer backups, and seller-side
	// secondary redemption timestamps must remain compatible with this guard.
	#[test]
	fn import_allows_compatible_redeem_exposure() -> Result<(), Error> {
		let buyer_fixture = include_str!("../../swap_test/swap_buy_3.json");
		let seller_fixture = include_str!("../../swap_test/swap_sell_5.json");
		for (fixture, live_posted, backup_posted) in [
			(buyer_fixture, None, None),
			(buyer_fixture, None, Some(123_456)),
			(buyer_fixture, Some(123_456), Some(123_456)),
			(buyer_fixture, Some(123_456), Some(123_455)),
			(seller_fixture, Some(123_456), None),
		] {
			let mut existing: Swap = serde_json::from_str(fixture)?;
			existing.posted_redeem = live_posted;
			let mut imported = existing.clone();
			imported.posted_redeem = backup_posted;

			reconcile_imported_replay_state(&mut existing, &mut imported)?;
			assert_eq!(existing.posted_redeem, live_posted);
			assert_eq!(imported.posted_redeem, backup_posted);
		}
		Ok(())
	}

	// Losing an accepted fail_bidding nonce would prevent acknowledgement of
	// redelivery after cancellation. Reject missing or conflicting receipts
	// before changing either record, while allowing matching and newer backups.
	#[test]
	fn import_rejects_lost_or_conflicting_received_cancellation() -> Result<(), Error> {
		let mut backup: Swap = serde_json::from_str(include_str!("../../swap_test/swap_sell_3.json"))?;
		backup.state = StateId::SellerPostingLockMwcSlate;
		backup.posted_lock = None;
		let message = Message::from_json(include_str!("../../swap_test/message_2.json"))?;
		backup.record_processed_incoming_message(1, swap_message_fingerprint(&message)?)?;
		let accepted_nonce = Uuid::from_u128(42);
		let mut existing = backup.clone();
		existing.marketplace_received_cancel_nonce = Some(accepted_nonce);
		existing.state = StateId::SellerCancelled;
		let existing_before = serde_json::to_value(&existing)?;

		for imported_nonce in [None, Some(Uuid::from_u128(43))] {
			let mut imported = backup.clone();
			imported.marketplace_received_cancel_nonce = imported_nonce;
			let imported_before = serde_json::to_value(&imported)?;
			assert!(matches!(
				reconcile_imported_replay_state(&mut existing, &mut imported),
				Err(Error::InvalidMessageData(message))
					if message.contains("accepted marketplace cancellation")
			));
			assert_eq!(serde_json::to_value(&existing)?, existing_before);
			assert_eq!(serde_json::to_value(&imported)?, imported_before);
		}

		let mut matching = existing.clone();
		reconcile_imported_replay_state(&mut existing, &mut matching)?;
		assert_eq!(
			matching.marketplace_received_cancel_nonce,
			Some(accepted_nonce)
		);
		assert_eq!(matching.state, StateId::SellerCancelled);

		// A backup may contain a cancellation absent from the live record.
		reconcile_imported_replay_state(&mut backup, &mut matching)?;
		assert_eq!(
			matching.marketplace_received_cancel_nonce,
			Some(accepted_nonce)
		);
		assert_eq!(matching.state, StateId::SellerCancelled);
		Ok(())
	}

	#[test]
	fn import_preserves_live_pending_cancellation_identity() -> Result<(), Error> {
		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		existing.tag = Some("marketplace-offer".to_string());
		existing.communication_address = "original-peer".to_string();
		existing.marketplace_signing_address_index = Some(17);
		existing.pending_marketplace_cancel_notification = true;
		existing.marketplace_cancel_notification_nonce = Some(Uuid::new_v4());
		existing.marketplace_winner_lease_expires_at = Some(123_456);
		let expected = materialize_marketplace_cancel_notification(&mut existing)?
			.expect("pending cancellation must materialize");

		let mut imported = existing.clone();
		imported.marketplace_cancel_notification = None;
		imported.pending_marketplace_cancel_notification = true;
		imported.marketplace_cancel_notification_nonce = None;
		imported.marketplace_winner_lease_expires_at = None;
		imported.tag = Some("stale-backup-offer".to_string());
		imported.communication_address = "stale-backup-peer".to_string();

		reconcile_imported_replay_state(&mut existing, &mut imported)?;
		assert_eq!(
			imported.marketplace_cancel_notification,
			Some(expected.clone())
		);
		assert!(imported.pending_marketplace_cancel_notification);
		assert_eq!(
			imported.marketplace_cancel_notification_nonce,
			Some(expected.nonce)
		);
		assert_eq!(imported.marketplace_winner_lease_expires_at, Some(123_456));
		assert_eq!(imported.tag.as_deref(), Some("marketplace-offer"));

		// Boolean-only legacy records must share one migration nonce, including
		// when neither the live record nor its backup has ever been materialized.
		for nonce in [None, Some(Uuid::new_v4())] {
			let mut legacy = existing.clone();
			legacy.marketplace_cancel_notification = None;
			legacy.marketplace_cancel_notification_nonce = nonce;
			let mut backup = legacy.clone();
			backup.marketplace_cancel_notification_nonce = None;
			let stale_backup = backup.clone();
			reconcile_imported_replay_state(&mut legacy, &mut backup)?;
			assert_eq!(
				legacy.marketplace_cancel_notification,
				backup.marketplace_cancel_notification
			);
			let shared_nonce = backup.marketplace_cancel_notification_nonce;
			assert!(shared_nonce.is_some());
			if let Some(nonce) = nonce {
				assert_eq!(shared_nonce, Some(nonce));
			}
			reconcile_imported_replay_state(&mut legacy, &mut backup)?;
			assert_eq!(backup.marketplace_cancel_notification_nonce, shared_nonce);

			// Restoring that old backup after completion must keep the event completed.
			legacy.marketplace_cancel_notification = None;
			legacy.pending_marketplace_cancel_notification = false;
			let mut backup = stale_backup;
			reconcile_imported_replay_state(&mut legacy, &mut backup)?;
			assert!(backup.marketplace_cancel_notification.is_none());
			assert!(!backup.pending_marketplace_cancel_notification);
			assert_eq!(backup.marketplace_cancel_notification_nonce, shared_nonce);
		}
		Ok(())
	}

	#[test]
	fn import_can_restore_missing_legacy_cancellation_identity() -> Result<(), Error> {
		let mut existing: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		existing.tag = None;
		existing.pending_marketplace_cancel_notification = true;
		existing.marketplace_cancel_notification_nonce = Some(Uuid::new_v4());

		let mut imported = existing.clone();
		imported.tag = Some("restored-marketplace-offer".to_string());
		imported.communication_address = "restored-peer".to_string();
		imported.marketplace_signing_address_index = Some(23);
		imported.pending_marketplace_cancel_notification = false;
		imported.marketplace_cancel_notification_nonce = None;

		reconcile_imported_replay_state(&mut existing, &mut imported)?;
		let restored = imported
			.marketplace_cancel_notification
			.expect("backup identity must repair the legacy pending marker");
		assert_eq!(restored.offer_id, "restored-marketplace-offer");
		assert_eq!(restored.peer_address, "restored-peer");
		assert_eq!(restored.signing_address_index, Some(23));
		assert_eq!(
			Some(restored.nonce),
			existing.marketplace_cancel_notification_nonce
		);
		Ok(())
	}

	#[test]
	fn stale_cancellation_ack_does_not_match_a_different_outbox_record() -> Result<(), Error> {
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		swap.tag = Some("marketplace-offer".to_string());
		swap.communication_address = "original-peer".to_string();
		swap.pending_marketplace_cancel_notification = true;
		swap.marketplace_cancel_notification_nonce = Some(Uuid::new_v4());
		let stale_ack = materialize_marketplace_cancel_notification(&mut swap)?
			.expect("pending cancellation must materialize");

		let mut current = stale_ack.clone();
		current.peer_address = "different-peer".to_string();
		install_marketplace_cancel_notification(&mut swap, current.clone());
		let pending = materialize_marketplace_cancel_notification(&mut swap)?;

		assert_eq!(pending.as_ref(), Some(&current));
		assert_ne!(pending.as_ref(), Some(&stale_ack));
		Ok(())
	}

	#[test]
	fn effective_eth_contracts_are_captured_before_configuration_changes() -> Result<(), Error> {
		let context_id = u32::MAX - 102;
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let old_eth = "0x1111111111111111111111111111111111111111".to_string();
		let old_erc20 = "0x2222222222222222222222222222222222222222".to_string();
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&Some(old_eth.clone()),
			&Some(old_erc20.clone()),
			&None,
		)?;

		let pinned = resolve_effective_eth_contracts(context_id, &Currency::Ether, &None, &None)?;
		trades::init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&Some("0x3333333333333333333333333333333333333333".to_string()),
			&Some("0x4444444444444444444444444444444444444444".to_string()),
			&None,
		)?;

		assert_eq!(pinned.eth, old_eth);
		assert_eq!(pinned.erc20, old_erc20);
		assert_ne!(
			pinned,
			resolve_effective_eth_contracts(context_id, &Currency::Ether, &None, &None)?
		);

		trades::trades_clean_context(context_id);
		Ok(())
	}

	#[test]
	fn existing_trade_rejects_contract_address_changes() -> Result<(), Error> {
		let original_eth = "0x1111111111111111111111111111111111111111".to_string();
		let original_erc20 = "0x2222222222222222222222222222222222222222".to_string();
		let mut pinned_eth = Some(original_eth.clone());
		let mut pinned_erc20 = Some(original_erc20.clone());

		let error = pin_or_validate_eth_contracts(
			&mut pinned_eth,
			&mut pinned_erc20,
			Some("0x3333333333333333333333333333333333333333".to_string()),
			Some(original_erc20.clone()),
		)
		.unwrap_err();

		assert!(matches!(error, Error::EthSwapContractAddressMismatch));
		assert_eq!(pinned_eth.as_ref(), Some(&original_eth));
		assert_eq!(pinned_erc20.as_ref(), Some(&original_erc20));

		let error = pin_or_validate_eth_contracts(
			&mut pinned_eth,
			&mut pinned_erc20,
			Some(original_eth.clone()),
			Some("0x4444444444444444444444444444444444444444".to_string()),
		)
		.unwrap_err();

		assert!(matches!(error, Error::ERC20SwapContractAddressMismatch));
		assert_eq!(pinned_eth, Some(original_eth));
		assert_eq!(pinned_erc20, Some(original_erc20));
		Ok(())
	}

	#[test]
	fn existing_trade_accepts_equivalent_contract_address_spelling() -> Result<(), Error> {
		let mut pinned_eth =
			Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
		let mut pinned_erc20 =
			Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());

		pin_or_validate_eth_contracts(
			&mut pinned_eth,
			&mut pinned_erc20,
			Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
			Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()),
		)?;
		Ok(())
	}

	#[test]
	fn legacy_trade_pins_first_explicit_contract_pair() -> Result<(), Error> {
		let eth = "0x1111111111111111111111111111111111111111".to_string();
		let erc20 = "0x2222222222222222222222222222222222222222".to_string();
		let mut pinned_eth = None;
		let mut pinned_erc20 = None;

		pin_or_validate_eth_contracts(
			&mut pinned_eth,
			&mut pinned_erc20,
			Some(eth.clone()),
			Some(erc20.clone()),
		)?;

		assert_eq!(pinned_eth, Some(eth));
		assert_eq!(pinned_erc20, Some(erc20));
		Ok(())
	}

	#[test]
	fn legacy_trade_rejects_invalid_contract_addresses_without_pinning() -> Result<(), Error> {
		let eth = "0x1111111111111111111111111111111111111111".to_string();
		let erc20 = "0x2222222222222222222222222222222222222222".to_string();
		let zero = "0x0000000000000000000000000000000000000000";

		for invalid in [
			"",
			"not-an-address",
			"0xgggggggggggggggggggggggggggggggggggggggg",
			"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
			zero,
		] {
			for invalid_native in [true, false] {
				for other_is_pinned in [false, true] {
					let mut pinned_eth = (other_is_pinned && !invalid_native).then(|| eth.clone());
					let mut pinned_erc20 =
						(other_is_pinned && invalid_native).then(|| erc20.clone());
					let original = (pinned_eth.clone(), pinned_erc20.clone());
					let requested_eth = if invalid_native { invalid } else { &eth };
					let requested_erc20 = if invalid_native { &erc20 } else { invalid };
					let result = pin_or_validate_eth_contracts(
						&mut pinned_eth,
						&mut pinned_erc20,
						Some(requested_eth.to_string()),
						Some(requested_erc20.to_string()),
					);
					assert!(
						result.is_err(),
						"accepted {invalid:?}, native={invalid_native}, other_is_pinned={other_is_pinned}"
					);
					if invalid == zero {
						let expected_kind = if invalid_native { "native" } else { "ERC20" };
						assert!(matches!(
							result,
							Err(Error::ZeroEthSwapContractAddress { kind }) if kind == expected_kind
						));
					}
					assert_eq!((&pinned_eth, &pinned_erc20), (&original.0, &original.1));

					// A rejected first value must leave the trade able to accept a correction.
					pin_or_validate_eth_contracts(
						&mut pinned_eth,
						&mut pinned_erc20,
						Some(eth.clone()),
						Some(erc20.clone()),
					)?;
					assert_eq!(pinned_eth.as_ref(), Some(&eth));
					assert_eq!(pinned_erc20.as_ref(), Some(&erc20));
				}
			}
		}
		Ok(())
	}
}
