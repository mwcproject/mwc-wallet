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

use super::Error;
use super::bitcoin::BtcUpdate;
use super::ethereum::EthUpdate;
use super::multisig;
use super::ser::*;
use super::types::{Currency, Network};
use crate::VersionedSlate;
use crate::proof::crypto;
use crate::proof::message::EncryptedMessage;
use crate::proof::proofaddress::ProvableAddress;
use crate::types::bounded_escape_for_display;
use mwc_wallet_util::mwc_core::libtx::secp_ser;
use mwc_wallet_util::mwc_crates::chrono::{DateTime, Utc};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::ed25519_dalek::Signer;
use mwc_wallet_util::mwc_crates::secp::AggSigSignature;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_util::{from_hex, to_hex};
use std::convert::TryInto;

const MARKETPLACE_MESSAGE_DOMAIN: &[u8] = b"mwc-wallet/marketplace-message/v1\0";
/// Maximum lifetime of a signed marketplace command.
pub const MARKETPLACE_MESSAGE_TTL_SEC: i64 = 5 * 60;
const MARKETPLACE_MESSAGE_FUTURE_SKEW_SEC: i64 = 60;
const MAX_MARKETPLACE_COMMAND_BYTES: usize = 32;
const MAX_MARKETPLACE_OFFER_ID_BYTES: usize = 256;
const MAX_SWAP_MESSAGE_ERROR_DISPLAY_LEN: usize = 256;

/// Authenticated marketplace command sent to a wallet's public foreign API.
///
/// The signature binds the command to both OnionV3 peers, the offer and swap,
/// the active network, a unique nonce, and a short validity window.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct MarketplaceMessage {
	/// Envelope version.
	pub version: u8,
	/// Marketplace command.
	pub command: String,
	/// Canonical OnionV3 address of the sender.
	pub from: String,
	/// Canonical OnionV3 address of the intended recipient.
	pub to: String,
	/// Marketplace offer identifier.
	pub offer_id: String,
	/// Swap identifier. Destructive commands require this value.
	pub swap_id: Option<Uuid>,
	/// Unique id used for replay protection and idempotent retries.
	pub nonce: Uuid,
	/// UTC Unix timestamp at which this command was issued.
	pub issued_at: i64,
	/// UTC Unix timestamp after which this command must be rejected.
	pub expires_at: i64,
	/// Swap network on which the command is valid.
	pub network: Network,
	/// Ed25519 signature encoded as lowercase hexadecimal.
	pub signature: String,
}

impl MarketplaceMessage {
	/// Construct and sign a marketplace command with an OnionV3 wallet key.
	pub fn signed(
		command: String,
		to: String,
		offer_id: String,
		swap_id: Option<Uuid>,
		nonce: Uuid,
		issued_at: i64,
		network: Network,
		signing_key: &ed25519_dalek::SigningKey,
	) -> Result<Self, Error> {
		let expires_at = issued_at
			.checked_add(MARKETPLACE_MESSAGE_TTL_SEC)
			.ok_or_else(|| {
				Error::DataOverflow("Marketplace message expiry overflow".to_string())
			})?;
		let from = ProvableAddress::from_tor_pub_key(&signing_key.verifying_key())?.to_string();
		let mut message = Self {
			version: 1,
			command,
			from,
			to,
			offer_id,
			swap_id,
			nonce,
			issued_at,
			expires_at,
			network,
			signature: String::new(),
		};
		message.validate_fields()?;
		message.signature = to_hex(&signing_key.sign(&message.transcript()?).to_bytes());
		Ok(message)
	}

	/// Verify addressing, freshness, network binding, and the strict Ed25519 signature.
	pub fn verify(
		&self,
		secp: &Secp256k1,
		context_id: u32,
		expected_recipient: &str,
		expected_network: Network,
		now: i64,
	) -> Result<(), Error> {
		self.validate_fields()?;
		if self.to != expected_recipient {
			return Err(Error::InvalidMessageData(
				"Marketplace message is addressed to another wallet".to_string(),
			));
		}
		if self.network != expected_network {
			return Err(Error::InvalidMessageData(
				"Marketplace message is for another network".to_string(),
			));
		}
		if !matches!(
			self.expires_at.checked_sub(self.issued_at),
			Some(validity) if validity > 0 && validity <= MARKETPLACE_MESSAGE_TTL_SEC
		) || self.expires_at <= now
			|| self.issued_at > now.saturating_add(MARKETPLACE_MESSAGE_FUTURE_SKEW_SEC)
		{
			return Err(Error::InvalidMessageData(
				"Marketplace message validity window is invalid or expired".to_string(),
			));
		}

		let sender = ProvableAddress::from_str(secp, context_id, &self.from)?;
		let signature_bytes = from_hex(&self.signature).map_err(|_| {
			Error::InvalidMessageData("Marketplace signature is not valid hex".to_string())
		})?;
		let signature_bytes: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| {
			Error::InvalidMessageData("Marketplace signature has an invalid length".to_string())
		})?;
		let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
		sender
			.tor_public_key()?
			.verify_strict(&self.transcript()?, &signature)
			.map_err(|_| {
				Error::InvalidMessageData("Marketplace signature verification failed".to_string())
			})
	}

	fn validate_fields(&self) -> Result<(), Error> {
		if self.version != 1 {
			return Err(Error::InvalidMessageData(format!(
				"Unsupported marketplace message version {}",
				self.version
			)));
		}
		if self.command.is_empty() || self.command.len() > MAX_MARKETPLACE_COMMAND_BYTES {
			return Err(Error::InvalidMessageData(
				"Marketplace command has an invalid length".to_string(),
			));
		}
		if self.offer_id.is_empty() || self.offer_id.len() > MAX_MARKETPLACE_OFFER_ID_BYTES {
			return Err(Error::InvalidMessageData(
				"Marketplace offer id has an invalid length".to_string(),
			));
		}
		if self.from.len() != 56 || self.to.len() != 56 {
			return Err(Error::InvalidMessageData(
				"Marketplace peers must be canonical OnionV3 addresses".to_string(),
			));
		}
		if self.nonce.is_nil() || self.swap_id.is_some_and(|swap_id| swap_id.is_nil()) {
			return Err(Error::InvalidMessageData(
				"Marketplace message contains a nil identifier".to_string(),
			));
		}
		Ok(())
	}

	fn transcript(&self) -> Result<Vec<u8>, Error> {
		let network = match self.network {
			Network::Floonet => "floonet",
			Network::Mainnet => "mainnet",
		};
		let swap_id = self.swap_id.map(|id| id.to_string()).unwrap_or_default();
		let version = self.version.to_string();
		let nonce = self.nonce.to_string();
		let issued_at = self.issued_at.to_string();
		let expires_at = self.expires_at.to_string();
		let fields = [
			version.as_bytes(),
			self.command.as_bytes(),
			self.from.as_bytes(),
			self.to.as_bytes(),
			self.offer_id.as_bytes(),
			swap_id.as_bytes(),
			nonce.as_bytes(),
			issued_at.as_bytes(),
			expires_at.as_bytes(),
			network.as_bytes(),
		];
		let mut transcript = MARKETPLACE_MESSAGE_DOMAIN.to_vec();
		for field in fields {
			let length = u32::try_from(field.len()).map_err(|e| {
				Error::DataOverflow(format!("Marketplace transcript field is too long, {}", e))
			})?;
			transcript.extend_from_slice(&length.to_be_bytes());
			transcript.extend_from_slice(field);
		}
		Ok(transcript)
	}
}

/// Swap message that is used for Seller/Buyer interaction
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct Message {
	/// Swap session UUID
	pub id: Uuid,
	/// Swap core data
	pub inner: Update,
	/// Secondary currency (BTC/ETH) related data
	inner_secondary: SecondaryUpdate,
}

impl Message {
	/// Create message form it's components
	pub fn new(id: Uuid, inner: Update, inner_secondary: SecondaryUpdate) -> Self {
		Self {
			id,
			inner,
			inner_secondary,
		}
	}

	/// Init BTC related messgae
	pub fn set_inner_secondary(&mut self, inner_secondary: SecondaryUpdate) {
		self.inner_secondary = inner_secondary;
	}

	/// Unwrap message as Offer
	pub fn unwrap_offer(self) -> Result<(Uuid, OfferUpdate, SecondaryUpdate), Error> {
		match self.inner {
			Update::Offer(u) => Ok((self.id, u, self.inner_secondary)),
			unexpected => Err(unexpected_update_type("Offer", &unexpected)),
		}
	}

	/// Return true is it is Offer message
	pub fn is_offer(&self) -> bool {
		match &self.inner {
			Update::Offer(_u) => true,
			_ => false,
		}
	}

	/// Unwrap message as Accepted Offer
	pub fn unwrap_accept_offer(self) -> Result<(Uuid, AcceptOfferUpdate, SecondaryUpdate), Error> {
		match self.inner {
			Update::AcceptOffer(u) => Ok((self.id, u, self.inner_secondary)),
			unexpected => Err(unexpected_update_type("AcceptOffer", &unexpected)),
		}
	}

	/// Unwrap message as Init Redeem
	pub fn unwrap_init_redeem(self) -> Result<(Uuid, InitRedeemUpdate, SecondaryUpdate), Error> {
		match self.inner {
			Update::InitRedeem(u) => Ok((self.id, u, self.inner_secondary)),
			unexpected => Err(unexpected_update_type("InitRedeem", &unexpected)),
		}
	}

	/// Unwrap message as Redeem
	pub fn unwrap_redeem(self) -> Result<(Uuid, RedeemUpdate, SecondaryUpdate), Error> {
		match self.inner {
			Update::Redeem(u) => Ok((self.id, u, self.inner_secondary)),
			unexpected => Err(unexpected_update_type("Redeem", &unexpected)),
		}
	}

	/// Message to Json String
	pub fn to_json(&self) -> Result<String, Error> {
		let str = serde_json::to_string(&self)
			.map_err(|e| Error::Serde(format!("Unable to serialize a message, {}", e)))?;
		Ok(str)
	}

	/// Build message from Json
	pub fn from_json(s: &str) -> Result<Message, Error> {
		Ok(serde_json::from_str(s)
			.map_err(|e| Error::Serde(format!("Unable to parse Swap Message, {}", e)))?)
	}
}

/// Swap core data of the Seller/Buyer message
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum Update {
	/// Empty data placeholder
	None,
	/// Seller to Buyer, Seller creates initial offer
	Offer(OfferUpdate),
	/// Buyer sending back accepted offer
	AcceptOffer(AcceptOfferUpdate),
	/// Buyer to Seller, start working on Reedem slate
	InitRedeem(InitRedeemUpdate),
	/// Seller to Buyer, working on Reedem slate
	Redeem(RedeemUpdate),
	/// Message Acknowledge, can be used for AcceptOffer & Redeem messages only.
	/// Value is 1 for msg1 (session 1) or 2 for msg2 (session 2)
	MessageAcknowledge(u32),
}

impl Update {
	fn variant_name(&self) -> &'static str {
		match self {
			Self::None => "None",
			Self::Offer(_) => "Offer",
			Self::AcceptOffer(_) => "AcceptOffer",
			Self::InitRedeem(_) => "InitRedeem",
			Self::Redeem(_) => "Redeem",
			Self::MessageAcknowledge(_) => "MessageAcknowledge",
		}
	}
}

fn unexpected_update_type(expected: &'static str, actual: &Update) -> Error {
	Error::UnexpectedMessageType(format!(
		"expected Update::{}, got Update::{}",
		expected,
		actual.variant_name()
	))
}

/// Seller, Status::Created  Seller creates initial offer
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct OfferUpdate {
	/// Swap starting time.
	pub start_time: DateTime<Utc>,
	/// Version of the swap engine. Both party must match
	pub version: u8,
	/// The type of the network. Floonet or mainnet
	pub network: Network,
	/// Method how we are sending message, should match to what we are using
	pub communication_method: String,
	/// from destination address
	pub from_address: String,
	/// Flag that specify the Locking fund order (Will wait for the fact that transaction is publishing, not for all confirmations).
	///    true: Seller lock MWC first, then Buyer BTC/ETH.
	///    false: Buyer lock BTC/ETH first, then Seller does lock.
	pub seller_lock_first: bool,
	/// Number of MWC to offer
	#[serde(with = "secp_ser::string_or_u64")]
	pub primary_amount: u64,
	/// Number of BTC to get
	#[serde(with = "secp_ser::string_or_u64")]
	pub secondary_amount: u64,
	/// BTC/ETH
	pub secondary_currency: Currency,
	/// Seller part of multisig
	pub multisig: multisig::ParticipantData,
	/// Lock V2 Slate that Buyer need to continue to build
	pub lock_slate: VersionedSlate,
	/// Refund V2 slate that byer need to sign.
	pub refund_slate: VersionedSlate,
	/// Needed info to build step 1 on redeem state (that saving some interaction)
	pub redeem_participant: crate::ParticipantData,
	/// Required confirmations for MWC Locking
	pub mwc_confirmations: u64,
	/// Required confirmations for BTC/ETH Locking
	pub secondary_confirmations: u64,
	/// Time interval for message exchange session.
	pub message_exchange_time_sec: u64,
	/// Time interval needed to redeem or execute a refund transaction.
	pub redeem_time_sec: u64,
}

/// Buyer, Status::Offered  Buyer responded for offer
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct AcceptOfferUpdate {
	/// Buyer's saved marketplace selection expiry in Unix seconds. Direct swaps
	/// omit it. This metadata does not itself cancel the trade, revoke an accepted
	/// offer, or replace the swap's transaction-locking deadlines. See the winner
	/// selection policy in doc/atomic_swaps.md, including legacy acknowledgement holds.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub marketplace_winner_lease_expires_at: Option<i64>,
	/// Buyer part of multisig
	pub multisig: multisig::ParticipantData,
	/// Public key for Redeem Slate
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub redeem_public: PublicKey,
	/// Buyer part needed to build lock slate
	pub lock_participant: crate::ParticipantData,
	/// Buyer part needed to build refund slate
	pub refund_participant: crate::ParticipantData,
}

/// Buyer, Status::Locked   Buyer building the redeem slate
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct InitRedeemUpdate {
	/// redeem slate, construction in the progress
	pub redeem_slate: VersionedSlate,
	/// signature for redeem_slate, see calculate_adaptor_signature  how we build it
	#[serde(serialize_with = "sig_to_hex", deserialize_with = "sig_from_hex")]
	pub adaptor_signature: AggSigSignature,
}

/// Seller, Status::InitRedeem.  Sending it's part needed for redeem transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct RedeemUpdate {
	/// Needed data to build redeem transaction
	pub redeem_participant: crate::ParticipantData,
}

/// Update message about Secondary Currency (BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum SecondaryUpdate {
	/// None, empty value
	Empty,
	/// BTC upadte
	BTC(BtcUpdate),
	/// ETH update
	ETH(EthUpdate),
}

impl SecondaryUpdate {
	/// Helper to extract BtcUpdate with type validation
	pub fn unwrap_btc(self) -> Result<BtcUpdate, Error> {
		match self {
			SecondaryUpdate::BTC(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}

	/// Helper to extract EthUpdate with type validation
	pub fn unwrap_eth(self) -> Result<EthUpdate, Error> {
		match self {
			SecondaryUpdate::ETH(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
}

/// encryption/decryption of swap message
#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct SwapMessage {
	/// key to decrypt the message
	pub key: [u8; 32],
}

impl SwapMessage {
	/// Authenticate the sender and recipient, then decrypt a received MQS message.
	pub fn from_received(
		context_id: u32,
		from: &ProvableAddress,
		message: String,
		_challenge: String,
		signature: String,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> Result<Message, Error> {
		let public_key = from.public_key(secp, context_id).map_err(|e| {
			Error::TradeEncDecError(format!(
				"Unable to build public key for address {}, {}",
				bounded_escape_for_display(&from.public_key, MAX_SWAP_MESSAGE_ERROR_DISPLAY_LEN),
				e
			))
		})?;

		// MQS post_take signs the serialized envelope itself; the legacy challenge
		// argument is unused. ECDH decryption alone cannot authenticate the sender:
		// both directions share a key, so an outgoing message can be reflected back.
		let signature = crypto::signature_from_string(&signature, secp).map_err(|e| {
			Error::TradeEncDecError(format!("Invalid swap message signature, {}", e))
		})?;
		crypto::verify_signature(&message, &signature, &public_key, secp).map_err(|e| {
			Error::TradeEncDecError(format!("Invalid swap message signature, {}", e))
		})?;

		let encrypted_message: EncryptedMessage = serde_json::from_str(&message).map_err(|e| {
			Error::TradeEncDecError(format!(
				"Failed to extract the encrypted swap message, {}",
				bounded_escape_for_display(&e.to_string(), MAX_SWAP_MESSAGE_ERROR_DISPLAY_LEN)
			))
		})?;

		let recipient_public_key = crypto::public_key_from_secret_key(secp, secret_key)?;
		let recipient = ProvableAddress::from_pub_key(secp, context_id, &recipient_public_key)?;
		if encrypted_message.destination.public_key != recipient.public_key {
			return Err(Error::TradeEncDecError(
				"Swap message is addressed to another wallet".to_string(),
			));
		}

		let key = encrypted_message
			.key(&public_key, secret_key, secp)
			.map_err(|e| {
				Error::TradeEncDecError(format!("Unable to derive the swap message key, {}", e))
			})?;

		let decrypted_message = encrypted_message.decrypt_with_key(&key).map_err(|e| {
			Error::TradeEncDecError(format!("Unable to decrypt the swap message, {}", e))
		})?;

		let swap = serde_json::from_str(&decrypted_message).map_err(|e| {
			Error::TradeEncDecError(format!(
				"Unable to build the swap message from the received message, {}",
				bounded_escape_for_display(&e.to_string(), MAX_SWAP_MESSAGE_ERROR_DISPLAY_LEN)
			))
		})?;

		Ok(swap)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::proof::crypto::Hex;
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};

	struct MqsPeers {
		secp: Secp256k1,
		sender_key: SecretKey,
		sender: ProvableAddress,
		recipient_key: SecretKey,
		recipient: ProvableAddress,
	}

	impl MqsPeers {
		fn new() -> Self {
			global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let sender_key = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
			let recipient_key = SecretKey::from_slice(&secp, &[2u8; 32]).unwrap();
			let sender = ProvableAddress::from_pub_key(
				&secp,
				0,
				&PublicKey::from_secret_key(&secp, &sender_key).unwrap(),
			)
			.unwrap();
			let recipient = ProvableAddress::from_pub_key(
				&secp,
				0,
				&PublicKey::from_secret_key(&secp, &recipient_key).unwrap(),
			)
			.unwrap();
			Self {
				secp,
				sender_key,
				sender,
				recipient_key,
				recipient,
			}
		}

		fn sign(&self, message: &str) -> String {
			crypto::sign_challenge(message, &self.sender_key, &self.secp)
				.unwrap()
				.to_hex(&self.secp)
				.unwrap()
		}

		fn envelope(&self, plaintext: String) -> (String, String) {
			let encrypted = EncryptedMessage::new(
				plaintext,
				&self.recipient,
				&self.recipient.public_key(&self.secp, 0).unwrap(),
				&self.sender_key,
				&self.secp,
				#[cfg(feature = "test-support")]
				true,
			)
			.unwrap();
			let message = serde_json::to_string(&encrypted).unwrap();
			let signature = self.sign(&message);
			(message, signature)
		}

		fn receive(&self, message: String, signature: String) -> Result<Message, Error> {
			SwapMessage::from_received(
				0,
				&self.sender,
				message,
				String::new(),
				signature,
				&self.recipient_key,
				&self.secp,
			)
		}
	}

	#[test]
	fn received_swap_requires_a_valid_sender_signature() {
		let peers = MqsPeers::new();
		let id = Uuid::new_v4();
		let message = Message::new(id, Update::MessageAcknowledge(1), SecondaryUpdate::Empty);
		let (envelope, signature) = peers.envelope(message.to_json().unwrap());
		let received = peers.receive(envelope.clone(), signature).unwrap();
		assert_eq!(received.id, id);
		assert!(matches!(received.inner, Update::MessageAcknowledge(1)));

		for signature in ["", "not-hex", "00"] {
			let error = peers
				.receive(envelope.clone(), signature.to_string())
				.unwrap_err();
			assert!(error.to_string().contains("Invalid swap message signature"));
		}
		let wrong_signature = crypto::sign_challenge(&envelope, &peers.recipient_key, &peers.secp)
			.unwrap()
			.to_hex(&peers.secp)
			.unwrap();
		assert!(peers.receive(envelope, wrong_signature).is_err());
	}

	#[test]
	fn received_swap_rejects_reflection_and_wrong_destination() {
		let peers = MqsPeers::new();
		let message = Message::new(
			Uuid::new_v4(),
			Update::MessageAcknowledge(1),
			SecondaryUpdate::Empty,
		);
		let (envelope, signature) = peers.envelope(message.to_json().unwrap());
		let reflected = SwapMessage::from_received(
			0,
			&peers.recipient,
			envelope.clone(),
			String::new(),
			signature.clone(),
			&peers.sender_key,
			&peers.secp,
		)
		.unwrap_err();
		assert!(
			reflected
				.to_string()
				.contains("Invalid swap message signature")
		);

		let mut tampered: serde_json::Value = serde_json::from_str(&envelope).unwrap();
		tampered["destination"]["public_key"] = peers.sender.public_key.clone().into();
		let tampered = tampered.to_string();
		let error = peers.receive(tampered.clone(), signature).unwrap_err();
		assert!(error.to_string().contains("Invalid swap message signature"));

		// Even a correctly signed envelope must name this wallet as recipient.
		let error = peers
			.receive(tampered.clone(), peers.sign(&tampered))
			.unwrap_err();
		assert!(error.to_string().contains("addressed to another wallet"));
	}

	#[test]
	fn received_swap_parse_errors_are_bounded_and_escaped() {
		let peers = MqsPeers::new();
		let hostile = "g\n\u{001b}[2J\u{202e}".repeat(1_024);
		let updates = [
			serde_json::json!({"AcceptOffer": {"multisig": {}, "redeem_public": hostile}}),
			// This field uses a dependency's custom deserializer, so sanitizing
			// only the swap HEX helpers would leave its error exposed.
			serde_json::json!({"Redeem": {"redeem_participant": {"id": hostile}}}),
		];
		for update in updates {
			let payload = serde_json::json!({
				"id": Uuid::new_v4(), "inner": update, "inner_secondary": "Empty"
			});
			let (envelope, signature) = peers.envelope(payload.to_string());
			let error = peers.receive(envelope, signature).unwrap_err().to_string();
			assert!(error.contains("Unable to build the swap message"));
			assert!(!error.chars().any(char::is_control));
			assert!(!error.contains('\u{202e}'));
			assert!(!error.contains(&hostile));
			assert!(error.len() < 2_048);
		}
	}

	#[test]
	fn unexpected_update_error_omits_the_message_payload() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[7u8; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let marker = "peer-controlled-payload-marker";
		let message = Message::new(
			Uuid::new_v4(),
			Update::Redeem(RedeemUpdate {
				redeem_participant: crate::ParticipantData {
					id: 0,
					public_blind_excess: public_key,
					public_nonce: public_key,
					part_sig: None,
					message: Some(marker.repeat(4_096)),
					message_sig: None,
				},
			}),
			SecondaryUpdate::Empty,
		);

		let error = message.unwrap_offer().unwrap_err().to_string();
		assert!(error.contains("expected Update::Offer, got Update::Redeem"));
		assert!(!error.contains(marker));
		assert!(error.len() < 128);
	}

	#[test]
	fn marketplace_signature_binds_payload_recipient_network_and_time() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let sender = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let recipient = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
		let recipient_address =
			ProvableAddress::from_tor_pub_key(&recipient.verifying_key()).unwrap();
		let issued_at = 1_700_000_000;
		let message = MarketplaceMessage::signed(
			"fail_bidding".to_string(),
			recipient_address.to_string(),
			"offer-1".to_string(),
			Some(Uuid::new_v4()),
			Uuid::new_v4(),
			issued_at,
			Network::Floonet,
			&sender,
		)
		.unwrap();

		message
			.verify(
				&secp,
				0,
				&recipient_address.to_string(),
				Network::Floonet,
				issued_at,
			)
			.unwrap();

		let mut tampered = message.clone();
		tampered.offer_id = "offer-2".to_string();
		assert!(
			tampered
				.verify(
					&secp,
					0,
					&recipient_address.to_string(),
					Network::Floonet,
					issued_at,
				)
				.is_err()
		);
		assert!(
			message
				.verify(
					&secp,
					0,
					&recipient_address.to_string(),
					Network::Mainnet,
					issued_at,
				)
				.is_err()
		);
		assert!(
			message
				.verify(
					&secp,
					0,
					&ProvableAddress::from_tor_pub_key(
						&ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]).verifying_key(),
					)
					.unwrap()
					.to_string(),
					Network::Floonet,
					issued_at,
				)
				.is_err()
		);
		assert!(
			message
				.verify(
					&secp,
					0,
					&recipient_address.to_string(),
					Network::Floonet,
					issued_at + MARKETPLACE_MESSAGE_TTL_SEC + 1,
				)
				.is_err()
		);
	}
}
