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

use super::message::*;
use super::multisig::{self, Hashed};
use super::ser::*;
use super::types::*;
use super::{Error, Keychain};
use crate::swap::fsm::state::StateId;
use crate::{NodeClient, SecondaryFeeUnits, Slate};
use mwc_wallet_util::mwc_core::core::{
	transaction as tx, CommitWrapper, Inputs, KernelFeatures, OutputIdentifier, TxKernel, Weighting,
};
use mwc_wallet_util::mwc_core::libtx::secp_ser;
use mwc_wallet_util::mwc_core::ser as core_ser;
use mwc_wallet_util::mwc_crates::chrono::{DateTime, Utc};
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_wallet_util::mwc_crates::secp::{AggSigSignature, Secp256k1};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::SwitchCommitmentType;

use crate::slate::SlateCtx;
use mwc_wallet_util::mwc_core::global;
#[cfg(feature = "test-support")]
use mwc_wallet_util::RwLock;

/// The protocol never intentionally locks either chain for more than 30 days.
/// Keep the ingress and chain-specific builders on one limit so an accepted
/// offer cannot later fail only when its secondary lock is constructed.
pub(crate) const MAX_SWAP_LOCK_INTERVAL_SECONDS: i64 = 30 * 24 * 60 * 60;
/// MWC targets one block per minute, so this is the block-height equivalent of
/// [`MAX_SWAP_LOCK_INTERVAL_SECONDS`].
pub(crate) const MAX_MWC_REFUND_LOCK_BLOCKS: u64 = 30 * 24 * 60;

/// Validate the absolute secondary-chain lock timestamp against the common
/// protocol policy and the 32-bit locktime representation used downstream.
pub(crate) fn validate_secondary_lock_time(
	lock_time: i64,
	current_time: i64,
) -> Result<u32, Error> {
	let maximum_lock_time = current_time
		.checked_add(MAX_SWAP_LOCK_INTERVAL_SECONDS)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"maximum secondary lock timestamp overflow, current_time={} maximum_interval={}",
				current_time, MAX_SWAP_LOCK_INTERVAL_SECONDS
			))
		})?;
	if lock_time > maximum_lock_time {
		return Err(Error::InvalidMessageData(format!(
			"Secondary locking time exceeds 30 days, lock_time={} maximum_lock_time={}",
			lock_time, maximum_lock_time
		)));
	}
	if lock_time < 0 || lock_time >= i64::from(u32::MAX) {
		return Err(Error::InvalidMessageData(format!(
			"Secondary locking time is outside the supported u32 range, lock_time={}",
			lock_time
		)));
	}
	u32::try_from(lock_time).map_err(|error| {
		Error::DataOverflow(format!(
			"secondary lock timestamp does not fit u32, lock_time={} error={}",
			lock_time, error
		))
	})
}

/// Validate one participant received in a swap protocol message. Transaction
/// partial signatures do not commit to the participant id or optional message,
/// so those fields must be checked before the record enters a slate.
pub(super) fn validate_swap_participant(
	secp: &Secp256k1,
	participant: &crate::ParticipantData,
	expected_id: u64,
	expected_complete: bool,
	stage: &str,
) -> Result<(), Error> {
	if participant.id != expected_id {
		return Err(Error::InvalidMessageData(format!(
			"{} contains participant id {}, expected {}",
			stage, participant.id, expected_id
		)));
	}
	if participant.is_complete() != expected_complete {
		return Err(Error::InvalidMessageData(format!(
			"{} participant {} has an unexpected partial-signature state",
			stage, participant.id
		)));
	}
	participant.verify_message(secp).map_err(|error| {
		Error::InvalidMessageData(format!(
			"{} participant {} message is invalid: {}",
			stage, participant.id, error
		))
	})
}

/// Validate the exact participant set expected at a swap protocol stage.
/// Bounds and ids are checked before any per-record signature verification so
/// an attacker cannot expand cryptographic work with an oversized vector.
pub(super) fn validate_swap_slate_participants(
	secp: &Secp256k1,
	slate: &Slate,
	expected: &[(u64, bool)],
	stage: &str,
) -> Result<(), Error> {
	if slate.num_participants != crate::slate::MAX_SEND_PARTICIPANTS {
		return Err(Error::InvalidMessageData(format!(
			"{} must declare exactly two participants, declared={}",
			stage, slate.num_participants
		)));
	}
	if slate.participant_data.len() != expected.len()
		|| expected.len() > crate::slate::MAX_SEND_PARTICIPANTS
	{
		return Err(Error::InvalidMessageData(format!(
			"{} has an unexpected participant record count, actual={} expected={}",
			stage,
			slate.participant_data.len(),
			expected.len()
		)));
	}
	slate.check_unique_participant_ids().map_err(|error| {
		Error::InvalidMessageData(format!("{} participant ids are invalid: {}", stage, error))
	})?;

	for (expected_id, expected_complete) in expected {
		let participant = slate
			.participant_data
			.iter()
			.find(|participant| participant.id == *expected_id)
			.ok_or_else(|| {
				Error::InvalidMessageData(format!(
					"{} is missing participant {}",
					stage, expected_id
				))
			})?;
		validate_swap_participant(secp, participant, *expected_id, *expected_complete, stage)?;
	}

	Ok(())
}

/// Bind a returned participant to the round-one values previously stored for
/// it. Only `part_sig` is allowed to appear in a later protocol message.
pub(super) fn validate_swap_participant_binding(
	expected: &crate::ParticipantData,
	returned: &crate::ParticipantData,
	stage: &str,
) -> Result<(), Error> {
	if expected.id != returned.id
		|| expected.public_blind_excess != returned.public_blind_excess
		|| expected.public_nonce != returned.public_nonce
		|| expected.message != returned.message
		|| expected.message_sig != returned.message_sig
	{
		return Err(Error::InvalidMessageData(format!(
			"{} changed participant {} round-one data",
			stage, expected.id
		)));
	}
	Ok(())
}

/// Dummy wrapper for the hex-encoded serialized transaction.
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct TxWrapper {
	/// hex representation of transaction
	pub tx_hex: String,
}

/// Swap event
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct SwapJournalRecord {
	/// Unix timestamp, when event happens
	pub time: i64,
	/// Description with what happens at that time.
	pub message: String,
}

/// An outbound transport selected by the wallet owner.
///
/// This is deliberately separate from the communication hint carried by a
/// peer's offer. In particular, a peer-provided `file` address must never
/// become an authorized local filesystem path.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(
	crate = "serde",
	tag = "method",
	content = "destination",
	rename_all = "lowercase"
)]
pub enum SwapTradeTransport {
	/// MWC MQS destination.
	Mwcmqs(String),
	/// Tor destination.
	Tor(String),
	/// Output file selected by the wallet operator.
	File(String),
}

/// Immutable durable-outbox identity for one marketplace cancellation.
///
/// This is stored inside the swap before delivery. Retry scans must return this
/// exact value instead of rebuilding an address or signing identity from fields
/// that an owner adjustment or trade import may later change.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "serde")]
pub struct MarketplaceCancelNotification {
	/// Swap whose cancellation is being reported.
	pub swap_id: Uuid,
	/// Marketplace offer identifier shared by the related trades.
	pub offer_id: String,
	/// Peer wallet address that receives the cancellation.
	pub peer_address: String,
	/// Stable idempotency nonce persisted before delivery.
	pub nonce: Uuid,
	/// HD address index whose derived key signs the cancellation.
	pub signing_address_index: Option<u32>,
}

/// Durable receipt for one successfully processed incoming protocol message.
///
/// The containing `Swap` supplies the swap UUID. Persisting the message
/// fingerprint and acknowledgement group with the state transition lets a
/// redelivery return the same acknowledgement without executing the FSM again.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "serde")]
pub(crate) struct IncomingMessageReceipt {
	fingerprint: String,
	acknowledgement_group: u32,
}

impl IncomingMessageReceipt {
	fn new(fingerprint: String, acknowledgement_group: u32) -> Result<Self, Error> {
		if !matches!(acknowledgement_group, 1 | 2) {
			return Err(Error::Generic(format!(
				"Invalid incoming swap acknowledgement group {}",
				acknowledgement_group
			)));
		}
		Ok(Self {
			fingerprint,
			acknowledgement_group,
		})
	}

	fn validate_for_group(&self, expected_group: u32) -> Result<(), Error> {
		if self.acknowledgement_group != expected_group {
			return Err(Error::InvalidMessageData(format!(
				"Stored incoming swap receipt has acknowledgement group {}, expected {}",
				self.acknowledgement_group, expected_group
			)));
		}
		Ok(())
	}

	fn acknowledgement(&self, swap_id: Uuid, expected_group: u32) -> Result<Message, Error> {
		self.validate_for_group(expected_group)?;
		Ok(Message::new(
			swap_id,
			Update::MessageAcknowledge(self.acknowledgement_group),
			SecondaryUpdate::Empty,
		))
	}
}

impl SwapTradeTransport {
	pub(crate) fn from_selection(method: &str, destination: String) -> Result<Self, Error> {
		if destination.is_empty() {
			return Err(Error::InvalidMessageData(
				"Communication destination must not be empty".to_string(),
			));
		}

		match method {
			"mwcmqs" => Ok(Self::Mwcmqs(destination)),
			"tor" => Ok(Self::Tor(destination)),
			"file" => Ok(Self::File(destination)),
			_ => Err(Error::InvalidMessageData(format!(
				"Unsupported communication method '{}'",
				method
			))),
		}
	}

	fn parts(&self) -> (&'static str, &str) {
		match self {
			Self::Mwcmqs(destination) => ("mwcmqs", destination),
			Self::Tor(destination) => ("tor", destination),
			Self::File(destination) => ("file", destination),
		}
	}
}

/// Primary SWAP state. Both Seller and Buyer are using it.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct Swap {
	/// Swap session uuid
	pub id: Uuid,
	/// Swap engine version. Both party are expected to have the same version
	pub version: u8,
	/// Network for the swap session (mainnet/floonet)
	pub network: Network,
	/// Role of the party (Byer or Seller)
	pub role: Role,
	/// Method how we are sending message to other party
	pub communication_method: String,
	/// destination address of the other party
	pub communication_address: String,
	/// Outbound transport explicitly selected by the wallet owner. Incoming offers
	/// never populate this field. It is required before a buyer may write a
	/// protocol message to a file.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub swap_trade_transport: Option<SwapTradeTransport>,
	/// Flag that specify the Locking fund order (Will wait for the fact that transaction is publishing, not for all confirmations).
	///    true: Seller lock MWC first, then Buyer BTC.
	///    false: Buyer lock BTC first, then Seller does lock.
	pub seller_lock_first: bool,
	/// Time when we started swap session
	pub started: DateTime<Utc>,
	/// Current state for this swap session
	pub state: StateId,
	/// MWC amount that Seller offer
	#[serde(with = "secp_ser::string_or_u64")]
	pub primary_amount: u64,
	/// BTC amount that Buyer pay
	#[serde(with = "secp_ser::string_or_u64")]
	pub secondary_amount: u64,
	/// units for BTC
	pub secondary_currency: Currency,
	/// Data associated with BTC deal
	pub secondary_data: SecondaryData,
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	/// Buyer Redeem slate public key
	pub(super) redeem_public: Option<PublicKey>,
	/// Schnorr multisig this party participant id
	pub(super) participant_id: usize,
	/// Schnorr multisig builder and holder
	pub(super) multisig: multisig::Builder,
	/// MWC Lock Slate
	pub lock_slate: SlateCtx,
	/// MWC Refund Slate
	pub refund_slate: SlateCtx,
	/// MWC redeem slate
	pub redeem_slate: SlateCtx,
	/// Redeem slate was updated. Seller spot it on the blockchain and get the kernel updated.
	pub redeem_kernel_updated: bool,
	/// Signature that is done with multisig
	#[serde(
		serialize_with = "option_sig_to_hex",
		deserialize_with = "option_sig_from_hex"
	)]
	/// Multisig signature
	pub(super) adaptor_signature: Option<AggSigSignature>,
	/// Required confirmations for MWC Locking
	pub mwc_confirmations: u64,
	/// Required confirmations for BTC Locking
	pub secondary_confirmations: u64,
	/// Time interval for message exchange session.
	pub message_exchange_time_sec: u64,
	/// Time interval needed to redeem or execute a refund transaction.
	pub redeem_time_sec: u64,
	/// First message that was sent, keep for retry operations
	pub message1: Option<Message>,
	/// Second message that was sent, keep for retry operations
	pub message2: Option<Message>,
	/// Last send timestamp for message one, or `i64::from(u32::MAX)` after
	/// acknowledgement to suppress retries. `None` means no recorded send.
	/// The acknowledgement marker is also preserved as a conservative hold when
	/// migrating a legacy marketplace winner that has no saved lease.
	pub posted_msg1: Option<i64>,
	/// Last send timestamp for message two, or `i64::from(u32::MAX)` after
	/// acknowledgement to suppress retries. `None` means no recorded send.
	pub posted_msg2: Option<i64>,
	/// Timestamp of the last MWC lock submission or first chain observation.
	/// Saved before broadcasting, since a failed response may still mean the
	/// funds were locked. Retain it to keep cancellation on the refund path.
	pub posted_lock: Option<i64>,
	/// Timestamp of the last redeem submission. For a buyer this is saved before
	/// broadcasting MWC, since even a failed response may have revealed the
	/// redeem secret. Once set for a buyer, it must never be cleared.
	pub posted_redeem: Option<i64>,
	/// timestamp when refund transaction was posted
	pub posted_refund: Option<i64>,
	/// Height of the secondary redeem submission. BTC also retains the first failed
	/// attempt height so rejected replacements remain eligible for a later fee bump.
	/// Cleared when proposing a new automatic fee; secondary refunds do not use it.
	pub posted_secondary_height: Option<u64>,
	/// Last error message if --check was failed. Note, error will be very generic
	pub last_check_error: Option<String>,
	/// Last error message if --process was failed. Note, error will be very generic
	pub last_process_error: Option<(StateId, String)>,
	/// Event log for this swap trade.
	pub journal: Vec<SwapJournalRecord>,
	/// Canonical secondary fee with explicit integer units.
	///
	/// This field intentionally has no alias for the former `secondary_fee`
	/// field, so swap records written with the float-based schema are rejected.
	pub secondary_fee_units: SecondaryFeeUnits,
	/// ElectrumX URI1
	pub electrum_node_uri1: Option<String>,
	/// ElectrumX failover URI2
	pub electrum_node_uri2: Option<String>,
	/// Ethereum swap contract address. New Ethereum-family trades persist the
	/// effective address used by their first client, even when it came from wallet
	/// defaults, so later configuration changes cannot redirect the trade.
	/// `None` is retained only for non-Ethereum or legacy records.
	pub eth_swap_contract_address: Option<String>,
	/// ERC20 swap contract address, pinned together with
	/// `eth_swap_contract_address` at trade creation.
	pub erc20_swap_contract_address: Option<String>,
	/// Ethereum Infura Project Id
	pub eth_infura_project_id: Option<String>,
	/// Ethereum transfer to users' wallet directly
	pub eth_redirect_to_private_wallet: Option<bool>,

	// --------------------------------
	// Additional non stored params for the trade. They good for a single call, not for all sessions
	/// For the step 1 backup. The QT wallet will take care about the backup. Here we should wait until
	/// it is done by user
	#[serde(skip)]
	#[serde(default = "default_false")]
	pub wait_for_backup1: bool,
	/// Tag for the swap. Using for swap marketplace automation process.
	pub tag: Option<String>,
	/// Flag that other party locking is confirmed. Utility flag for swap marketplace
	#[serde(default = "default_false")]
	pub other_lock_first_done: bool,
	/// Saved marketplace selection expiry in Unix seconds. A newly selected tagged
	/// buyer sets a ten-minute lease before sending AcceptOffer. Expiry permits a
	/// chain-state check; it does not itself release the winner or cancel the peer.
	/// Legacy migration may derive a far-future hold from the `posted_msg1`
	/// acknowledgement marker. Acknowledgement does not alter an existing lease.
	/// Sellers retain the value received in AcceptOffer as marketplace metadata.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_winner_lease_expires_at: Option<i64>,
	/// Fingerprint of the exact offer from which a buyer trade was created.
	/// Exact replays with the same UUID can be acknowledged without processing the
	/// offer twice; a different payload using that UUID remains an error.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub received_offer_fingerprint: Option<String>,
	/// Fingerprint of the typed offer payload excluding its outer swap UUID.
	/// Used to reject the same offer when a peer resends it under another UUID.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub received_offer_content_fingerprint: Option<String>,
	/// Durable receipt for the incoming group-one message (`Offer` for a buyer or
	/// `AcceptOffer` for a seller).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) processed_incoming_ack1: Option<IncomingMessageReceipt>,
	/// Durable receipt for the incoming group-two message (`InitRedeem` for a
	/// seller or `Redeem` for a buyer).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) processed_incoming_ack2: Option<IncomingMessageReceipt>,
	/// Immutable cancellation notification still awaiting acknowledged delivery.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_cancel_notification: Option<MarketplaceCancelNotification>,
	/// Legacy pending marker retained for backwards-compatible deserialization.
	/// New writes keep it synchronized with `marketplace_cancel_notification`.
	#[serde(default = "default_false", skip_serializing_if = "is_false")]
	pub pending_marketplace_cancel_notification: bool,
	/// Legacy/compatibility copy of the durable notification nonce.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_cancel_notification_nonce: Option<Uuid>,
	/// HD address index used to sign the marketplace bid and every later
	/// cancellation. Before this Swap exists, the index is staged in the wallet
	/// database by offer and peer; once attached here, this field is authoritative
	/// for the active deal. The secret key and derived address are never persisted.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_signing_address_index: Option<u32>,
	/// Last authenticated cancellation nonce accepted for this trade.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_received_cancel_nonce: Option<Uuid>,
}

/// Every value that enters the redeem adaptor and partial-signature challenge,
/// after the participant transcript has been bound to the transaction body and
/// its single Plain kernel.
pub(super) struct RedeemTxFields {
	pub(super) pub_nonce_sum: PublicKey,
	pub(super) pub_blind_sum: PublicKey,
	pub(super) tx_excess: Commitment,
	pub(super) message: secp::Message,
}

fn default_false() -> bool {
	false
}

fn is_false(value: &bool) -> bool {
	!*value
}

fn invalidate_stale_cached_offer(
	message1: &mut Option<Message>,
	posted_msg1: &mut Option<i64>,
	method: &str,
) {
	let stale_offer = matches!(
		message1.as_ref(),
		Some(message) if matches!(
			&message.inner,
			Update::Offer(offer) if offer.communication_method.as_str() != method
		)
	);
	if stale_offer {
		*message1 = None;
		*posted_msg1 = None;
	}
}

impl Swap {
	/// Return the persisted acknowledgement for an exact replay. A different
	/// message occupying the same protocol group is a deterministic conflict.
	pub(crate) fn replay_processed_incoming_message(
		&self,
		message_group: u32,
		incoming_fingerprint: &str,
	) -> Result<Option<Message>, Error> {
		let receipt = match message_group {
			1 => self.processed_incoming_ack1.as_ref(),
			2 => self.processed_incoming_ack2.as_ref(),
			_ => {
				return Err(Error::Generic(format!(
					"Invalid incoming swap message group {}",
					message_group
				)));
			}
		};
		let receipt = match receipt {
			Some(receipt) => receipt,
			None => return Ok(None),
		};
		receipt.validate_for_group(message_group)?;
		if receipt.fingerprint != incoming_fingerprint {
			return Err(Error::InvalidMessageData(format!(
				"Incoming swap message conflicts with the message already processed for group {}",
				message_group
			)));
		}
		Ok(Some(receipt.acknowledgement(self.id, message_group)?))
	}

	/// Record successful processing before the updated swap is durably stored.
	/// Repeating the call with the same fingerprint is itself idempotent.
	pub(crate) fn record_processed_incoming_message(
		&mut self,
		message_group: u32,
		incoming_fingerprint: String,
	) -> Result<Message, Error> {
		if let Some(acknowledgement) =
			self.replay_processed_incoming_message(message_group, &incoming_fingerprint)?
		{
			return Ok(acknowledgement);
		}

		let receipt = IncomingMessageReceipt::new(incoming_fingerprint, message_group)?;
		let acknowledgement = receipt.acknowledgement(self.id, message_group)?;
		match message_group {
			1 => self.processed_incoming_ack1 = Some(receipt),
			2 => self.processed_incoming_ack2 = Some(receipt),
			_ => {
				return Err(Error::Generic(format!(
					"Invalid incoming swap message group {}",
					message_group
				)));
			}
		}
		Ok(acknowledgement)
	}

	/// Validate durable receipt invariants after reading or before writing a swap
	/// record.
	pub(crate) fn validate_processed_incoming_messages(&self) -> Result<(), Error> {
		if let Some(receipt) = self.processed_incoming_ack1.as_ref() {
			receipt.validate_for_group(1)?;
		}
		if let Some(receipt) = self.processed_incoming_ack2.as_ref() {
			receipt.validate_for_group(2)?;
		}
		Ok(())
	}

	/// Store a communication method and destination selected through the wallet
	/// owner interface.
	pub(crate) fn set_swap_trade_transport(
		&mut self,
		method: String,
		destination: String,
	) -> Result<(), Error> {
		let swap_trade_transport =
			SwapTradeTransport::from_selection(&method, destination.clone())?;
		// Offers embed the communication method. Do not let a retry reuse an
		// offer built for a transport that the owner has since replaced.
		invalidate_stale_cached_offer(&mut self.message1, &mut self.posted_msg1, &method);
		self.communication_method = method;
		self.communication_address = destination;
		self.swap_trade_transport = Some(swap_trade_transport);
		Ok(())
	}

	/// Resolve the transport that may be used for an outbound protocol message.
	///
	/// Network addresses from an offer remain usable because they do not name a
	/// local filesystem object. File paths require local provenance. The seller
	/// fallback keeps pre-provenance trade records compatible: seller transport
	/// settings originated from local swap creation, whereas a buyer's settings
	/// originated in the peer's offer.
	pub(crate) fn outbound_transport(&self) -> Result<(String, String), Error> {
		resolve_outbound_transport(
			&self.communication_method,
			&self.communication_address,
			self.swap_trade_transport.as_ref(),
			self.is_seller(),
		)
	}

	/// Validate the unit-bearing secondary fee after deserialization.
	pub(crate) fn validate_secondary_fee_units(&self) -> Result<(), Error> {
		self.secondary_currency
			.validate_secondary_fee_units(self.secondary_fee_units)
	}

	/// Validate the confirmation thresholds negotiated in the offer.
	pub(crate) fn validate_confirmation_requirements(&self) -> Result<(), Error> {
		validate_confirmation_requirements(self.mwc_confirmations, self.secondary_confirmations)
	}

	/// Validate complete lock/refund slates against the same body-chain tip.
	pub(crate) fn validate_lock_and_refund_slates<C: NodeClient>(
		&self,
		context_id: u32,
		node_client: &C,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let lock = self.lock_slate.slate.node_preflight_transaction(
			context_id,
			secp,
			true,
		)?;
		let refund = self.refund_preflight_transaction(context_id, secp)?;
		crate::transaction_preflight::check_request(
			node_client,
			&crate::transaction_preflight::MempoolAcceptRequest {
				transactions: vec![lock, refund],
				expected_tip: None,
			},
		)?;
		Ok(())
	}

	/// Describe a complete future refund and bind it to its negotiated lock output.
	/// The node validates its parent dependency in the same request.
	pub(crate) fn refund_preflight_transaction(
		&self,
		context_id: u32,
		secp: &Secp256k1,
	) -> Result<crate::transaction_preflight::PreflightTransaction, Error> {
		let mut request = self
			.refund_slate
			.slate
			.node_preflight_transaction(context_id, secp, true)?;
		let parent = self.multisig.commit(secp)?;
		if request.inputs.len() != 1
			|| request.inputs[0].commitment != parent
			|| request.inputs[0]
				.features
				.is_some_and(|f| f != tx::OutputFeatures::Plain)
			|| !self
				.lock_slate
				.slate
				.tx_or_err()?
				.outputs()
				.iter()
				.any(|o| o.commitment() == parent && !o.is_coinbase())
		{
			return Err(Error::InvalidMessageData(
				"Refund must spend only its negotiated lock output".into(),
			));
		}
		request.allow_future_height = true;
		Ok(request)
	}

	/// Return true for Seller
	pub fn is_seller(&self) -> bool {
		match self.role {
			Role::Seller(_, _) => true,
			Role::Buyer(_) => false,
		}
	}

	/// Whether the buyer's MWC redeem signature may already be public.
	pub(crate) fn buyer_redeem_is_exposed(&self) -> bool {
		!self.is_seller() && self.posted_redeem.is_some()
	}

	/// These recovery states no longer need an MWC observation to spend the
	/// secondary funds. Buyer redemption and competing-MWC-refund resolution
	/// remain outside this set; a seller must already hold the recovered kernel.
	pub(crate) fn can_use_secondary_confirmations(&self) -> bool {
		if self.is_seller() {
			self.redeem_kernel_updated
				&& matches!(
					self.state,
					StateId::SellerWaitingForBuyerToRedeemMwc
						| StateId::SellerRedeemSecondaryCurrency
						| StateId::SellerWaitingForRedeemConfirmations
						| StateId::SellerSwapComplete
						| StateId::SellerWaitingForRefundHeight
				)
		} else {
			matches!(
				self.state,
				StateId::BuyerWaitingForRefundTime
					| StateId::BuyerPostingRefundForSecondary
					| StateId::BuyerWaitingForRefundConfirmations
					| StateId::BuyerCancelledRefunded
					| StateId::BuyerSwapFailed
					| StateId::BuyerCancelled
			)
		}
	}

	/// Only fresh cross-chain commitments require an Ethereum lock-finality query.
	/// Refunds, expired trades, and recovery after signature exposure still need
	/// current balances even if the node cannot provide finalized state.
	pub(crate) fn needs_secondary_lock_finality(&self) -> Result<bool, Error> {
		if self.can_use_secondary_confirmations()
			|| self.buyer_redeem_is_exposed()
			|| self.redeem_kernel_updated
			|| (self.is_seller() && self.state.is_seller_refund())
		{
			return Ok(false);
		}
		let deadline = if self.is_seller() {
			self.get_time_message_redeem()?
		} else {
			self.get_time_mwc_redeem()?
		};
		Ok(get_cur_time() <= deadline)
	}

	/// Return Seller specific data
	pub fn unwrap_seller(&self) -> Result<(String, u64), Error> {
		match &self.role {
			Role::Seller(address, change) => {
				match address == "0x0000000000000000000000000000000000000000" {
					true => Ok(("Internal Ethereum Wallet".to_string(), *change)),
					_ => Ok((address.clone(), *change)),
				}
			}
			_ => Err(Error::UnexpectedRole("Swap call unwrap_seller".to_string())),
		}
	}

	/// Return buyer specific data
	pub fn unwrap_buyer(&self) -> Result<Option<String>, Error> {
		match &self.role {
			Role::Buyer(address) => match address {
				Some(address) => match address == "0x0000000000000000000000000000000000000000" {
					true => Ok(Some("Internal Ethereum Wallet".to_string())),
					_ => Ok(Some(address.clone())),
				},
				_ => Ok(address.clone()),
			},
			_ => Err(Error::UnexpectedRole("Swap call unwrap_buyer".to_string())),
		}
	}

	/// Update secondary address. Depend on role, updates redeem or refund secondary currency address
	/// Preserve the address, including the Ethereum zero-address sentinel; format labels for display only.
	pub fn update_secondary_address(&mut self, secondary_address: String) {
		match &mut self.role {
			Role::Buyer(address) => {
				address.replace(secondary_address);
			}
			Role::Seller(address, _) => {
				*address = secondary_address;
			}
		};
	}

	/// Get secondary address. Depend on role, returns redeem or refund secondary currency address
	pub fn get_secondary_address(&self) -> String {
		match &self.role {
			Role::Buyer(address) => address.clone().unwrap_or(String::new()),
			Role::Seller(address, _) => address.clone(),
		}
	}

	pub(super) fn message(
		&self,
		inner: Update,
		inner_secondary: SecondaryUpdate,
	) -> Result<Message, Error> {
		Ok(Message::new(self.id.clone(), inner, inner_secondary))
	}

	pub(super) fn multisig_secret<K: Keychain>(
		&self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let sec_key = keychain.derive_key(
			secp,
			self.primary_amount,
			&context.multisig_key,
			SwitchCommitmentType::None,
		)?;

		Ok(sec_key)
	}

	pub(super) fn refund_amount(&self) -> Result<u64, Error> {
		self.primary_amount
			.checked_sub(self.refund_slate.slate.fee)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::refund_amount, primary amount is smaller than refund fee, primary_amount={} refund_fee={}",
					self.primary_amount, self.refund_slate.slate.fee
				))
			})
	}

	pub(super) fn redeem_tx_fields(
		&self,
		context_id: u32,
		redeem_slate: &Slate,
		secp: &Secp256k1,
	) -> Result<RedeemTxFields, Error> {
		// Swap redeem messages carry the complete transaction body. In particular,
		// calc_excess() uses the participant aggregate instead of the body for a
		// compact slate, which would make the body/participant binding below
		// tautological.
		if redeem_slate.compact_slate {
			return Err(Error::InvalidMessageData(
				"Redeem slate must not be compact".to_string(),
			));
		}

		let redeem_tx = redeem_slate.tx_or_err().map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate transaction is missing or invalid: {}",
				error
			))
		})?;
		if redeem_tx.body.inputs.len() != 1
			|| redeem_tx.body.outputs.len() != 1
			|| redeem_tx.body.kernels.len() != 1
		{
			return Err(Error::InvalidMessageData(format!(
				"Redeem slate transaction must contain exactly one input, one output, and one kernel; found inputs={} outputs={} kernels={}",
				redeem_tx.body.inputs.len(),
				redeem_tx.body.outputs.len(),
				redeem_tx.body.kernels.len()
			)));
		}
		redeem_slate
			.validate_transaction_read(context_id)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Redeem slate transaction failed lightweight validation: {}",
					error
				))
			})?;

		if redeem_slate.get_kernel_features() != 0 || redeem_slate.get_lock_height() != 0 {
			return Err(Error::InvalidMessageData(format!(
				"Redeem slate must use a Plain kernel with zero lock height; feature={} lock_height={}",
				redeem_slate.get_kernel_features(),
				redeem_slate.get_lock_height()
			)));
		}
		let slate_features = redeem_slate.kernel_features().map_err(|error| {
			Error::InvalidMessageData(format!("Redeem slate has invalid kernel fields: {}", error))
		})?;
		if !matches!(slate_features, KernelFeatures::Plain { .. }) {
			return Err(Error::InvalidMessageData(
				"Redeem slate kernel feature is not Plain".to_string(),
			));
		}
		let kernel = redeem_tx.body.kernels.first().ok_or_else(|| {
			Error::InvalidMessageData("Redeem slate transaction kernel is missing".to_string())
		})?;
		if kernel.features != slate_features {
			return Err(Error::InvalidMessageData(format!(
				"Redeem slate fields do not match its transaction kernel: slate={:?} transaction={:?}",
				slate_features, kernel.features
			)));
		}
		let message = kernel
			.features
			.kernel_sig_msg(context_id)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Redeem slate kernel message is invalid: {}",
					error
				))
			})?;
		let slate_message = redeem_slate.msg_to_sign(context_id).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate signing message is invalid: {}",
				error
			))
		})?;
		if slate_message != message {
			return Err(Error::InvalidMessageData(
				"Redeem slate and transaction kernel produce different signing messages"
					.to_string(),
			));
		}

		// Both callers use this while constructing the adaptor signature, before
		// either partial transaction signature exists. Validate the bounded,
		// two-party transcript before aggregating peer-controlled public keys.
		validate_swap_slate_participants(
			secp,
			redeem_slate,
			&[(0, false), (1, false)],
			"Redeem slate",
		)?;
		let local_id = self.participant_id as u64;
		let expected_local = self
			.redeem_slate
			.slate
			.participant_data
			.iter()
			.find(|participant| participant.id == local_id)
			.ok_or_else(|| {
				Error::InvalidMessageData(format!(
					"Stored redeem slate is missing local participant {}",
					local_id
				))
			})?;
		validate_swap_participant(secp, expected_local, local_id, false, "Stored redeem slate")?;
		let returned_local = redeem_slate
			.participant_data
			.iter()
			.find(|participant| participant.id == local_id)
			.ok_or_else(|| {
				Error::InvalidMessageData(format!(
					"Redeem slate is missing local participant {}",
					local_id
				))
			})?;
		validate_swap_participant_binding(expected_local, returned_local, "Redeem slate")?;

		let pub_nonces = redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		let pub_nonce_sum = PublicKey::from_combination(secp, pub_nonces).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate has an invalid aggregate public nonce: {}",
				error
			))
		})?;
		let pub_blinds = redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		let pub_blind_sum = PublicKey::from_combination(secp, pub_blinds).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate has an invalid aggregate public excess: {}",
				error
			))
		})?;

		let tx_excess = redeem_slate.calc_excess(secp).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate transaction excess cannot be calculated: {}",
				error
			))
		})?;
		let tx_excess_public = tx_excess.to_pubkey(secp).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem slate transaction excess is invalid: {}",
				error
			))
		})?;
		if tx_excess_public != pub_blind_sum {
			return Err(Error::InvalidMessageData(
				"Redeem slate transaction excess does not match the participant aggregate"
					.to_string(),
			));
		}

		Ok(RedeemTxFields {
			pub_nonce_sum,
			pub_blind_sum,
			tx_excess,
			message,
		})
	}

	pub(super) fn find_redeem_kernel<C: NodeClient>(
		&self,
		node_client: &C,
	) -> Result<Option<(TxKernel, u64)>, Error> {
		let excess = &self
			.redeem_slate
			.slate
			.tx_or_err()?
			.kernels()
			.get(0)
			.ok_or(Error::UnexpectedAction(
				"Swap Fn find_redeem_kernel() redeem slate is not initialized, not found kernel"
					.to_string(),
			))?
			.excess;

		let res = node_client
			.get_kernel(excess, None, None)?
			.map(|(kernel, height, _)| (kernel, height));

		Ok(res)
	}

	pub(super) fn other_participant_id(&self) -> usize {
		usize::from(self.participant_id == 0)
	}

	/// Common nonce for the BulletProof is sum_i H(C_i) where C_i is the commitment of participant i
	pub(super) fn common_nonce(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		let hashed_nonces: Vec<SecretKey> = self
			.multisig
			.participants
			.iter()
			.filter_map(|participant| participant.partial_commitment.as_ref())
			.map(|commitment| -> Result<SecretKey, super::multisig::Error> {
				let hash = commitment.hash()?;
				Ok(hash.to_secret_key(secp)?)
			})
			.collect::<Result<_, _>>()?;
		if hashed_nonces.len() != 2 {
			return Err(super::multisig::Error::MultiSigIncomplete.into());
		}
		let sec_key = secp.blind_sum(hashed_nonces, Vec::new())?;

		Ok(sec_key)
	}

	/// Mark message one acknowledged by replacing its send time with the legacy
	/// retry-suppression marker. This intentionally discards the original timestamp.
	/// Marketplace migration preserves the marker for an acknowledged trade without
	/// a saved lease; an existing explicit lease is unchanged. See
	/// `owner_swap::probe_or_claim_marketplace_lease` for the exclusivity policy.
	pub fn ack_msg1(&mut self) {
		if self.posted_msg1.is_some() {
			self.posted_msg1 = Some(i64::from(u32::MAX));
		}
	}
	/// Mark message two acknowledged using the same retry-suppression marker.
	/// This field does not participate in marketplace winner selection.
	pub fn ack_msg2(&mut self) {
		if self.posted_msg2.is_some() {
			self.posted_msg2 = Some(i64::from(u32::MAX));
		}
	}

	/// Add a journal message for this swap trade
	pub fn add_journal_message(&mut self, msg: String) {
		self.journal.push(SwapJournalRecord {
			time: get_cur_time(),
			message: msg,
		});
		// We want to limit journal to 1000 items because of the performance.
		while self.journal.len() > 1000 {
			self.journal.remove(0);
		}
	}

	/// Append to the last message.
	pub fn append_to_last_message(&mut self, msg: &String) {
		if let Some(last) = self.journal.last_mut() {
			last.message.push_str(msg.as_str());
		}
	}

	// Time management functions

	/// Trade starting time
	pub fn get_time_start(&self) -> i64 {
		self.started.timestamp()
	}

	/// Offer message exchange session time limit
	pub fn get_time_message_offers(&self) -> Result<i64, Error> {
		let interval = i64::try_from(self.message_exchange_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_time_message_offers, message exchange interval exceeds i64 seconds, message_exchange_time_sec={} error={}",
				self.message_exchange_time_sec, e
			))
		})?;
		let start_time = self.get_time_start();
		start_time.checked_add(interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_message_offers, offer message deadline overflow, start_time={} interval={}",
				start_time, interval
			))
		})
	}

	/// When locking need to be started
	pub fn get_time_start_lock(&self) -> Result<i64, Error> {
		// We can get 5% from the total lock time. We have to post fast
		let interval = std::cmp::max(
			self.get_timeinterval_mwc_lock()?,
			self.get_timeinterval_secondary_lock()?,
		) / 20;
		let offers_deadline = self.get_time_message_offers()?;
		offers_deadline.checked_add(interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_start_lock, swap lock start deadline overflow, offers_deadline={} interval={}",
				offers_deadline, interval
			))
		})
	}

	/// When locking time will be expired
	pub fn get_time_locking(&self) -> Result<i64, Error> {
		// for confirmation adding 10% for possible network slow down.
		let interval = std::cmp::max(
			self.get_timeinterval_mwc_lock()?,
			self.get_timeinterval_secondary_lock()?,
		);
		let offers_deadline = self.get_time_message_offers()?;
		offers_deadline.checked_add(interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_locking, swap locking deadline overflow, offers_deadline={} interval={}",
				offers_deadline, interval
			))
		})
	}

	/// Second period of the message exchange
	pub fn get_time_message_redeem(&self) -> Result<i64, Error> {
		let interval = i64::try_from(self.message_exchange_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_time_message_redeem, message exchange interval exceeds i64 seconds, message_exchange_time_sec={} error={}",
				self.message_exchange_time_sec, e
			))
		})?;
		let locking_deadline = self.get_time_locking()?;
		locking_deadline
			.checked_add(interval)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::get_time_message_redeem, redeem message deadline overflow, locking_deadline={} interval={}",
					locking_deadline, interval
				))
			})
	}

	/// MWC redeem time
	pub fn get_time_mwc_redeem(&self) -> Result<i64, Error> {
		let interval = i64::try_from(self.redeem_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_time_mwc_redeem, redeem interval exceeds i64 seconds, redeem_time_sec={} error={}",
				self.redeem_time_sec, e
			))
		})?;
		let redeem_message_deadline = self.get_time_message_redeem()?;
		redeem_message_deadline
			.checked_add(interval)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::get_time_mwc_redeem, MWC redeem deadline overflow, redeem_message_deadline={} interval={}",
					redeem_message_deadline, interval
				))
			})
	}

	/// MWC locking time
	pub fn get_time_mwc_lock(&self) -> Result<i64, Error> {
		// Add 10% for network instability
		let redeem_deadline = self.get_time_mwc_redeem()?;
		let lock_interval = self.get_timeinterval_mwc_lock()?;
		redeem_deadline.checked_add(lock_interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_mwc_lock, MWC lock deadline overflow, redeem_deadline={} lock_interval={}",
				redeem_deadline, lock_interval
			))
		})
	}

	/// mwc refund time
	pub fn get_time_mwc_refund(&self) -> Result<i64, Error> {
		// Add 10% for network instability
		let interval = i64::try_from(self.redeem_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_time_mwc_refund, redeem interval exceeds i64 seconds, redeem_time_sec={} error={}",
				self.redeem_time_sec, e
			))
		})?;
		let lock_deadline = self.get_time_mwc_lock()?;
		lock_deadline.checked_add(interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_mwc_refund, MWC refund deadline overflow, lock_deadline={} interval={}",
				lock_deadline, interval
			))
		})
	}

	/// BTC/ETH lock time for script
	pub fn get_time_secondary_lock_script(&self) -> Result<i64, Error> {
		let redeem_interval = i64::try_from(self.redeem_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_time_secondary_lock_script, redeem interval exceeds i64 seconds, redeem_time_sec={} error={}",
				self.redeem_time_sec, e
			))
		})?;
		let mwc_interval = self.get_timeinterval_mwc_lock()?;
		let secondary_interval = self.get_timeinterval_secondary_lock()?;
		let refund_deadline = self.get_time_mwc_refund()?;
		refund_deadline.checked_add(redeem_interval)
			.and_then(|time| time.checked_add(mwc_interval))
			.and_then(|time| time.checked_add(secondary_interval))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::get_time_secondary_lock_script, secondary lock script deadline overflow, refund_deadline={} redeem_interval={} mwc_interval={} secondary_interval={}",
					refund_deadline, redeem_interval, mwc_interval, secondary_interval
				))
			})
	}

	/// BTC/ETH lock time publish
	pub fn get_time_secondary_lock_publish(&self) -> Result<i64, Error> {
		// Here is what BTC node said:
		// Only accept nLockTime-using transactions that can be mined in the next
		// block; we don't want our mempool filled up with transactions that can't
		// be mined yet.
		//
		// As a result we have to wait guarantee 1 block. To be safe, we will wait time for 5 blocks before we try to publish
		// 5 is a large number, but accordign the testnet, it is needed.
		let safety_interval = self
			.secondary_currency
			.block_time_period_sec()
			.checked_mul(5)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::get_time_secondary_lock_publish, secondary publish safety interval overflow, block_time_period_sec={} multiplier=5",
					self.secondary_currency.block_time_period_sec()
				))
			})?;
		let script_deadline = self.get_time_secondary_lock_script()?;
		script_deadline
			.checked_add(safety_interval)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Swap::get_time_secondary_lock_publish, secondary lock publish time overflow, script_deadline={} safety_interval={}",
					script_deadline, safety_interval
				))
			})
	}

	/// btc redeem time limit
	pub fn get_time_btc_redeem_limit(&self) -> Result<i64, Error> {
		// Using script time as lowest possible value
		let script_deadline = self.get_time_secondary_lock_script()?;
		let secondary_interval = self.get_timeinterval_secondary_lock()?;
		script_deadline.checked_sub(secondary_interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_time_btc_redeem_limit, BTC redeem deadline underflow, script_deadline={} secondary_interval={}",
				script_deadline, secondary_interval
			))
		})
	}

	////////////////////////////////////////////////////////////
	// Time periof functions

	/// MWC locking time interval
	pub fn get_timeinterval_mwc_lock(&self) -> Result<i64, Error> {
		// adding extra 10% for chain instability
		let confirmations = i64::try_from(self.mwc_confirmations).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_timeinterval_mwc_lock, MWC confirmation count exceeds i64, confirmations={} error={}",
				self.mwc_confirmations, e
			))
		})?;
		let padded_seconds = confirmations.checked_mul(60 * 11).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_timeinterval_mwc_lock, MWC confirmation interval overflow, confirmations={}",
				confirmations
			))
		})?;
		Ok(padded_seconds / 10)
	}

	/// BTC/ETH locking time interval
	pub fn get_timeinterval_secondary_lock(&self) -> Result<i64, Error> {
		// adding extra 10% for chain instability
		let confirmations = i64::try_from(self.secondary_confirmations).map_err(|e| {
			Error::DataOverflow(format!(
				"Swap::get_timeinterval_secondary_lock, secondary confirmation count exceeds i64, confirmations={} error={}",
				self.secondary_confirmations, e
			))
		})?;
		let block_period = self.secondary_currency.block_time_period_sec();
		let seconds = confirmations.checked_mul(block_period).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_timeinterval_secondary_lock, secondary confirmation interval overflow, confirmations={} block_time_period_sec={}",
				confirmations, block_period
			))
		})?;
		let padded_seconds = seconds.checked_mul(11).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Swap::get_timeinterval_secondary_lock, secondary confirmation safety interval overflow, seconds={} multiplier=11",
				seconds
			))
		})?;
		Ok(padded_seconds / 10)
	}

	/// Latest error message. Check has higher priority because it is normally done first
	pub fn get_last_error(&self) -> Option<String> {
		if self.last_check_error.is_some() {
			self.last_check_error.clone()
		} else {
			if let Some((state, err)) = self.last_process_error.clone() {
				// Error is reportable only if it happend for the current state. If state was changed,
				// th error is not applicable any more.
				if state == self.state {
					Some(err)
				} else {
					None
				}
			} else {
				None
			}
		}
	}

	/// Validate the network. Expected to be done after deserialization
	/// Unfortunatelly we can't pass context_id into deserializer
	pub(crate) fn validate_network(&self, context_id: u32) -> Result<(), Error> {
		let network_name = global::get_network_name(context_id);
		if *self
			.lock_slate
			.network_name
			.as_ref()
			.ok_or(Error::UnexpectedNetwork(
				"lock_slate network_name is not defined".into(),
			))? != network_name
		{
			return Err(Error::UnexpectedNetwork(format!(
				"lock_slate has invalid network: {:?}  Expected: {}",
				self.lock_slate.network_name, network_name
			)));
		}

		if *self
			.refund_slate
			.network_name
			.as_ref()
			.ok_or(Error::UnexpectedNetwork(
				"refund_slate network_name is not defined".into(),
			))? != network_name
		{
			return Err(Error::UnexpectedNetwork(format!(
				"refund_slate has invalid network: {:?}  Expected: {}",
				self.refund_slate.network_name, network_name
			)));
		}

		if *self
			.redeem_slate
			.network_name
			.as_ref()
			.ok_or(Error::UnexpectedNetwork(
				"redeem_slate network_name is not defined".into(),
			))? != network_name
		{
			return Err(Error::UnexpectedNetwork(format!(
				"redeem_slate has invalid network: {:?}  Expected: {}",
				self.redeem_slate.network_name, network_name
			)));
		}

		Ok(())
	}
}

fn resolve_outbound_transport(
	communication_method: &str,
	communication_address: &str,
	swap_trade_transport: Option<&SwapTradeTransport>,
	allow_legacy_file_destination: bool,
) -> Result<(String, String), Error> {
	if let Some(swap_trade_transport) = swap_trade_transport {
		let (transport_method, transport_destination) = swap_trade_transport.parts();
		if transport_method != communication_method {
			return Err(Error::InvalidMessageData(
				"Stored swap trade transport does not match the swap communication method"
					.to_string(),
			));
		}
		if transport_destination.is_empty() {
			return Err(Error::InvalidMessageData(
				"Stored swap trade transport destination is empty".to_string(),
			));
		}
		return Ok((
			transport_method.to_string(),
			transport_destination.to_string(),
		));
	}

	if communication_method == "file" {
		if allow_legacy_file_destination && !communication_address.is_empty() {
			return Ok((
				communication_method.to_string(),
				communication_address.to_string(),
			));
		}
		return Err(Error::InvalidMessageData(
			"The file destination in this swap was supplied by the peer or is missing. Select an output path with `swap --swap_id <id> --adjust destination --method file --dest <path>` or provide `--method file --dest <path>` with `swap --process`"
				.to_string(),
		));
	}

	Ok((
		communication_method.to_string(),
		communication_address.to_string(),
	))
}

#[cfg(test)]
mod swap_trade_transport_tests {
	use super::*;

	#[test]
	fn transport_change_invalidates_a_stale_cached_offer() {
		let cached_offer = Message::from_json(include_str!("../../swap_test/message_1.json"))
			.expect("offer fixture must be valid");
		let original_method = match &cached_offer.inner {
			Update::Offer(offer) => offer.communication_method.as_str(),
			_ => panic!("fixture message must be an offer"),
		};
		let replacement_method = if original_method == "tor" {
			"mwcmqs"
		} else {
			"tor"
		};

		let mut message1 = Some(cached_offer.clone());
		let mut posted_msg1 = Some(123);
		invalidate_stale_cached_offer(&mut message1, &mut posted_msg1, original_method);
		assert!(message1.is_some());
		assert_eq!(posted_msg1, Some(123));

		invalidate_stale_cached_offer(&mut message1, &mut posted_msg1, replacement_method);
		assert!(message1.is_none());
		assert!(posted_msg1.is_none());
	}

	#[test]
	fn buyer_cannot_resolve_peer_provided_file_destination() {
		let peer_destination = "/tmp/peer-selected-target";
		let error = resolve_outbound_transport("file", peer_destination, None, false)
			.expect_err("peer-provided file path must be rejected");

		assert!(matches!(error, Error::InvalidMessageData(_)));
		assert!(!error.to_string().contains(peer_destination));
	}

	#[test]
	fn swap_trade_file_destination_is_authorized() {
		let swap_trade_transport =
			SwapTradeTransport::from_selection("file", "/tmp/owner-selected-output".to_string())
				.unwrap();

		assert_eq!(
			resolve_outbound_transport(
				"file",
				"/tmp/peer-selected-target",
				Some(&swap_trade_transport),
				false,
			)
			.unwrap(),
			("file".to_string(), "/tmp/owner-selected-output".to_string())
		);
	}

	#[test]
	fn legacy_seller_file_destination_remains_usable() {
		assert_eq!(
			resolve_outbound_transport("file", "/tmp/legacy-seller-output", None, true).unwrap(),
			("file".to_string(), "/tmp/legacy-seller-output".to_string())
		);
	}

	#[test]
	fn inconsistent_swap_trade_transport_is_rejected() {
		let swap_trade_transport =
			SwapTradeTransport::from_selection("tor", "counterparty.onion".to_string()).unwrap();

		assert!(matches!(
			resolve_outbound_transport(
				"file",
				"/tmp/peer-selected-target",
				Some(&swap_trade_transport),
				false,
			),
			Err(Error::InvalidMessageData(_))
		));
	}
}

/*impl ser::Writeable for Swap {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("OutputData to json conversion failed, {}", e))
		})?)
	}
}

impl ser::Readable for Swap {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Swap, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("Json to outputData conversion failed, {}", e))
		})
	}
}*/

/// Add an input to a tx at the appropriate position
pub fn tx_add_input(context_id: u32, slate: &mut Slate, commit: Commitment) -> Result<(), Error> {
	match &mut slate.tx_or_err_mut()?.body.inputs {
		Inputs::FeaturesAndCommit(inputs) => {
			let input = tx::Input {
				features: tx::OutputFeatures::Plain,
				commit,
			};
			inputs.push(input);
			core_ser::sort_by_hash(context_id, inputs)?;
		}
		Inputs::CommitOnly(commits) => {
			let cmt = CommitWrapper::from(commit);
			commits.push(cmt);
			core_ser::sort_by_hash(context_id, commits)?;
		}
	}
	Ok(())
}

/// Add an output to a tx at the appropriate position
pub fn tx_add_output(
	context_id: u32,
	slate: &mut Slate,
	commit: Commitment,
	proof: RangeProof,
) -> Result<(), Error> {
	let output = tx::Output {
		identifier: OutputIdentifier {
			features: tx::OutputFeatures::Plain,
			commit,
		},
		proof,
	};
	let outputs = &mut slate.tx_or_err_mut()?.body.outputs;
	outputs.push(output);
	core_ser::sort_by_hash(context_id, outputs)?;
	Ok(())
}

/// Interpret the final 32 bytes of the signature as a secret key
pub fn signature_as_secret(
	secp: &Secp256k1,
	signature: &AggSigSignature,
) -> Result<SecretKey, Error> {
	let key_bytes = signature.as_ref().get(32..).ok_or_else(|| {
		Error::Generic("Aggregate signature is shorter than 64 bytes".to_string())
	})?;
	let key = SecretKey::from_slice(secp, key_bytes)?;
	Ok(key)
}

/// Serialize a transaction and submit it to the network
pub fn publish_transaction<C: NodeClient>(
	context_id: u32,
	secp: &mut Secp256k1,
	node_client: &C,
	tx: &tx::Transaction,
	fluff: bool,
) -> Result<(), Error> {
	tx.validate(context_id, Weighting::AsTransaction, secp)
		.map_err(|e| Error::UnexpectedAction(format!("slate is not valid, {}", e)))?;

	crate::owner::post_tx(context_id, node_client, tx, fluff)?;
	Ok(())
}

#[cfg(feature = "test-support")]
lazy_static! {
	static ref CURRENT_TEST_TIME: RwLock<Option<i64>> = RwLock::new(None);
}

/// Override the current timestamp for deterministic tests.
#[cfg(feature = "test-support")]
pub fn set_testing_cur_time(cur_time: i64) {
	CURRENT_TEST_TIME.write().replace(cur_time);
}

/// Remove test timer control for swaps. Will use current system time instead
#[cfg(feature = "test-support")]
pub fn reset_testing_cur_time() {
	CURRENT_TEST_TIME.write().take();
}

/// Return the test-controlled time when test support is active, or the system time otherwise.
pub fn get_cur_time() -> i64 {
	#[cfg(feature = "test-support")]
	{
		match *CURRENT_TEST_TIME.read() {
			Some(time) => time,
			None => Utc::now().timestamp(),
		}
	}
	#[cfg(not(feature = "test-support"))]
	{
		Utc::now().timestamp()
	}
}

/// Print how much time left from the time limit
pub fn left_from_time_limit(time_limit: &Option<i64>) -> String {
	match time_limit {
		Some(time_limit) => {
			// This display-only countdown intentionally clamps extreme/expired timestamps
			// instead of changing the fallible swap APIs used for state decisions.
			let left_sec = time_limit.saturating_sub(get_cur_time());
			if left_sec <= 0 {
				"expired".to_string()
			} else {
				if left_sec > 3600 {
					format!(
						"expired in {} hours {} minutes",
						left_sec / 3600,
						(left_sec % 3600) / 60
					)
				} else if left_sec > 60 {
					format!("expired in {} minutes", left_sec / 60)
				} else {
					format!("expired in {} seconds", left_sec)
				}
			}
		}
		None => "".to_string(),
	}
}

#[cfg(test)]
mod swap_ingress_validation_tests {
	use super::*;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::core::OutputFeatures;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serde_json;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test::serial;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_keychain::BlindingFactor;

	fn participant(secp: &Secp256k1, id: u64, seed: u8) -> crate::ParticipantData {
		let blind = SecretKey::from_slice(secp, &[seed; 32]).unwrap();
		let nonce = SecretKey::from_slice(secp, &[seed.saturating_add(1); 32]).unwrap();
		crate::ParticipantData {
			id,
			public_blind_excess: PublicKey::from_secret_key(secp, &blind).unwrap(),
			public_nonce: PublicKey::from_secret_key(secp, &nonce).unwrap(),
			part_sig: None,
			message: None,
			message_sig: None,
		}
	}

	#[test]
	fn swap_participant_validation_uses_ids_not_vector_positions() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let mut slate = Slate::blank(2, false).unwrap();
		// Reversed order is valid because the protocol identity is the id field,
		// not an attacker-controlled vector position.
		slate.participant_data.push(participant(&secp, 1, 3));
		slate.participant_data.push(participant(&secp, 0, 1));
		assert!(validate_swap_slate_participants(
			&secp,
			&slate,
			&[(0, false), (1, false)],
			"test redeem slate"
		)
		.is_ok());

		let mut duplicate = slate.clone();
		duplicate.participant_data[0].id = 0;
		assert!(validate_swap_slate_participants(
			&secp,
			&duplicate,
			&[(0, false), (1, false)],
			"test redeem slate"
		)
		.is_err());

		let mut oversized = slate.clone();
		oversized.participant_data.push(participant(&secp, 2, 5));
		assert!(validate_swap_slate_participants(
			&secp,
			&oversized,
			&[(0, false), (1, false)],
			"test redeem slate"
		)
		.is_err());
	}

	#[test]
	fn swap_participant_binding_rejects_changed_round_one_data() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let expected = participant(&secp, 0, 1);
		let mut returned = expected.clone();
		returned.public_nonce = participant(&secp, 0, 7).public_nonce;
		assert!(matches!(
			validate_swap_participant_binding(&expected, &returned, "test response"),
			Err(Error::InvalidMessageData(_))
		));
	}

	#[cfg(feature = "test-support")]
	fn redeem_fixture() -> (Swap, Slate, Secp256k1) {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_sell_3.json")).unwrap();
		let message = Message::from_json(include_str!("../../swap_test/message_3.json")).unwrap();
		let (_, init_redeem, _) = message.unwrap_init_redeem().unwrap();
		let slate = init_redeem.redeem_slate.into_slate_plain(0, true).unwrap();
		(swap, slate, secp)
	}

	#[cfg(feature = "test-support")]
	fn assert_invalid_redeem(result: Result<RedeemTxFields, Error>) {
		let error = match result {
			Ok(_) => panic!("malformed redeem slate must be rejected"),
			Err(error) => error,
		};
		assert!(matches!(error, Error::InvalidMessageData(_)));
		assert!(!error.is_transient());
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn redeem_fields_accept_the_bound_plain_fixture() {
		let (swap, slate, secp) = redeem_fixture();
		let fields = swap.redeem_tx_fields(0, &slate, &secp).unwrap();
		assert_eq!(
			fields.tx_excess.to_pubkey(&secp).unwrap(),
			fields.pub_blind_sum
		);
		assert_eq!(fields.message, slate.msg_to_sign(0).unwrap());
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn redeem_fields_reject_body_excess_not_bound_to_participants() {
		let (swap, mut slate, secp) = redeem_fixture();
		let replacement_offset =
			SecretKey::from_slice(&secp, &[42; 32]).expect("test offset must be valid");
		slate.tx_or_err_mut().unwrap().offset = BlindingFactor::from_secret_key(replacement_offset);

		assert_invalid_redeem(swap.redeem_tx_fields(0, &slate, &secp));
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn redeem_fields_reject_height_locked_kernel_message() {
		let (swap, mut slate, secp) = redeem_fixture();
		let lock_height = slate.height + 1;
		let fee = match slate.tx_or_err().unwrap().body.kernels[0].features {
			KernelFeatures::Plain { fee } => fee,
			_ => panic!("fixture redeem kernel must be Plain"),
		};
		slate.set_lock_height(lock_height).unwrap();
		slate.tx_or_err_mut().unwrap().body.kernels[0].features =
			KernelFeatures::HeightLocked { fee, lock_height };

		assert_invalid_redeem(swap.redeem_tx_fields(0, &slate, &secp));
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn redeem_fields_reject_invalid_body_shape_and_compact_mode() {
		let (swap, slate, secp) = redeem_fixture();

		let mut coinbase_output = slate.clone();
		coinbase_output.tx_or_err_mut().unwrap().body.outputs[0]
			.identifier
			.features = OutputFeatures::Coinbase;
		assert_invalid_redeem(swap.redeem_tx_fields(0, &coinbase_output, &secp));

		let mut missing_output = slate.clone();
		missing_output.tx_or_err_mut().unwrap().body.outputs.clear();
		assert_invalid_redeem(swap.redeem_tx_fields(0, &missing_output, &secp));

		let mut compact = slate;
		compact.compact_slate = true;
		assert_invalid_redeem(swap.redeem_tx_fields(0, &compact, &secp));
	}

	#[test]
	fn secondary_lock_policy_has_a_shared_thirty_day_boundary() {
		let current_time = 1_000_000;
		let maximum = current_time + MAX_SWAP_LOCK_INTERVAL_SECONDS;
		assert_eq!(
			validate_secondary_lock_time(maximum, current_time).unwrap(),
			u32::try_from(maximum).unwrap()
		);
		assert!(matches!(
			validate_secondary_lock_time(maximum + 1, current_time),
			Err(Error::InvalidMessageData(_))
		));

		let near_u32_limit = i64::from(u32::MAX) - MAX_SWAP_LOCK_INTERVAL_SECONDS;
		assert!(matches!(
			validate_secondary_lock_time(i64::from(u32::MAX), near_u32_limit),
			Err(Error::InvalidMessageData(_))
		));
	}
}
