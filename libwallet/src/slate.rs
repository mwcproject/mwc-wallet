// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

//! Functions for building partial transactions to be passed
//! around during an interactive wallet exchange

use crate::error::Error;
use crate::{Context, VersionedSlate};
use mwc_wallet_util::mwc_core::core::amount_to_hr_string;
use mwc_wallet_util::mwc_core::core::committed::Committed;
use mwc_wallet_util::mwc_core::core::transaction::{
	Input, KernelFeatures, Output, OutputFeatures, Transaction, TransactionBody, TxKernel,
	Weighting,
};
use mwc_wallet_util::mwc_core::libtx::{aggsig, build, proof::ProofBuild, secp_ser, tx_fee};
use mwc_wallet_util::mwc_core::map_vec;
use mwc_wallet_util::mwc_crates::blake2_rfc::blake2b::blake2b;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_wallet_util::mwc_crates::secp::AggSigSignature;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid::{Builder as UuidBuilder, Uuid};
use mwc_wallet_util::mwc_keychain::{BlindSum, BlindingFactor, Keychain, SwitchCommitmentType};
use mwc_wallet_util::mwc_util::ToHex;
use std::convert::TryFrom;
use std::fmt;

use crate::slate_versions::v2::SlateV2;
use crate::slate_versions::v2::SlateV2ParseTTL;

use crate::slate_versions::v3::{
	option_aggsig_serde, InputV3, OutputV3, ParticipantDataV3, PaymentInfoV3, SlateV3,
	TransactionBodyV3, TransactionV3, TxKernelV3, VersionCompatInfoV3,
};
use mwc_wallet_util::mwc_core::consensus::WEEK_HEIGHT;

// use crate::slate_versions::{CURRENT_SLATE_VERSION, MWC_BLOCK_HEADER_VERSION};
use crate::proof::proofaddress::ProvableAddress;
#[cfg(feature = "test-support")]
use crate::step_rng::StepRng;
use crate::{SlateVersion, Slatepacker, CURRENT_SLATE_VERSION};
use mwc_wallet_util::mwc_core::core::FeeFields;
use mwc_wallet_util::mwc_core::core::{Inputs, NRDRelativeHeight, OutputIdentifier};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::log::{debug, error, info};
use mwc_wallet_util::mwc_crates::rand::{rngs::SysRng, TryRng};
use mwc_wallet_util::mwc_crates::secp::ContextFlag;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;

/// Maximum number of parties in an invoice exchange: the issuer and the
/// payer. A response slate with more participant records than this is
/// rejected before any signature verification takes place.
pub const MAX_INVOICE_PARTICIPANTS: usize = 2;
/// The interactive send protocol currently supports one sender and one
/// receiver. Response validation must stay bounded even when a peer declares
/// a larger participant count.
pub const MAX_SEND_PARTICIPANTS: usize = 2;
/// Maximum UTF-8 byte length of a participant message accepted from a slate.
pub const MAX_PARTICIPANT_MESSAGE_LEN: usize = 2_048;
/// Blake2b key used to domain-separate persisted aggregate-signature
/// challenge commitments from every other wallet hash.
const AGGSIG_CHALLENGE_HASH_KEY: &[u8] = b"mwc-wallet/aggsig-challenge/v1";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct PaymentInfo {
	#[serde(serialize_with = "ProvableAddress::serialize_as_string")]
	pub sender_address: ProvableAddress,
	#[serde(serialize_with = "ProvableAddress::serialize_as_string")]
	pub receiver_address: ProvableAddress,
	pub receiver_signature: Option<String>,
}

/// Public data for each participant in the slate
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(crate = "serde")]
pub struct ParticipantData {
	/// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_nonce: PublicKey,
	/// Public partial signature
	#[serde(default, with = "option_aggsig_serde")]
	pub part_sig: Option<AggSigSignature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	#[serde(default, with = "option_aggsig_serde")]
	pub message_sig: Option<AggSigSignature>,
}

impl ParticipantData {
	/// A helper to return whether this participant
	/// has completed round 1 and round 2;
	/// Round 1 has to be completed before instantiation of this struct
	/// anyhow, and for each participant consists of:
	/// -Inputs added to transaction
	/// -Outputs added to transaction
	/// -Public signature nonce chosen and added
	/// -Public contribution to blinding factor chosen and added
	/// Round 2 can only be completed after all participants have
	/// performed round 1, and adds:
	/// -Part sig is filled out
	pub fn is_complete(&self) -> bool {
		self.part_sig.is_some()
	}

	/// Verify the participant message/signature pair. Both fields are optional,
	/// but they must either both be absent or both be present: accepting an
	/// orphaned signature would let a peer erase a signed message while leaving
	/// a superficially signed participant record behind.
	pub(crate) fn verify_message(&self, secp: &Secp256k1) -> Result<(), Error> {
		// Keep the size invariant in the per-participant verifier as well as the
		// slate verifier. Swap messages sometimes carry ParticipantData directly,
		// so relying only on Slate::verify_messages would allow those callers to
		// hash, serialize and persist an attacker-sized signed message.
		if let Some(message) = &self.message {
			if message.len() > MAX_PARTICIPANT_MESSAGE_LEN {
				return Err(Error::SlateValidation(format!(
					"participant {} message is too large, actual={} maximum={}",
					self.id,
					message.len(),
					MAX_PARTICIPANT_MESSAGE_LEN
				)));
			}
		}

		let (message, signature) = match (&self.message, &self.message_sig) {
			(None, None) => return Ok(()),
			(None, Some(_)) => {
				error!(
					"verify_messages - participant message signature has no message, participant_id={}",
					self.id
				);
				return Err(Error::Signature(
					"Participant message signature is present without a message".to_owned(),
				));
			}
			(Some(message), None) => {
				error!(
					"verify_messages - participant message doesn't have signature. Message: \"{}\"",
					crate::types::escape_for_display(message)
				);
				return Err(Error::Signature(
					"Optional participant message doesn't have a signature".to_owned(),
				));
			}
			(Some(message), Some(signature)) => (message, signature),
		};

		let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &message.as_bytes()[..]);
		let message_hash = secp::Message::from_slice(hashed.as_bytes())?;
		if !aggsig::verify_single(
			secp,
			signature,
			&message_hash,
			None,
			&self.public_blind_excess,
			&self.public_blind_excess,
			false,
		)? {
			error!(
				"verify_messages - participant message doesn't match signature. Message: \"{}\"",
				crate::types::escape_for_display(message)
			);
			return Err(Error::Signature(
				"Optional participant message does not match its signature".to_owned(),
			));
		}

		info!(
			"verify_messages - signature verified ok. Participant message: \"{}\"",
			crate::types::escape_for_display(message)
		);
		Ok(())
	}
}

/// Public message data (for serialising and storage)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct ParticipantMessageData {
	/// id of the particpant in the tx
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_key: PublicKey,
	/// Message,
	pub message: Option<String>,
	/// Signature
	#[serde(default, with = "option_aggsig_serde")]
	pub message_sig: Option<AggSigSignature>,
}

impl ParticipantMessageData {
	/// extract relevant message data from participant data
	pub fn from_participant_data(p: &ParticipantData) -> ParticipantMessageData {
		ParticipantMessageData {
			id: p.id,
			public_key: p.public_blind_excess,
			message: p.message.clone(),
			message_sig: p.message_sig,
		}
	}
}

impl fmt::Display for ParticipantMessageData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f)?;
		write!(f, "Participant ID {} ", self.id)?;
		if self.id == 0 {
			writeln!(f, "(Sender)")?;
		} else {
			writeln!(f, "(Recipient)")?;
		}
		writeln!(f, "---------------------")?;
		let secp = Secp256k1::with_caps(ContextFlag::None).map_err(|_| fmt::Error)?;
		writeln!(
			f,
			"Public Key: {}",
			&self
				.public_key
				.serialize_vec(&secp, true)
				.map_err(|_| fmt::Error)?
				.to_hex()
		)?;
		let message = match &self.message {
			None => "None".to_owned(),
			Some(m) => crate::types::escape_for_display(m),
		};
		writeln!(f, "Message: {}", message)?;
		let message_sig = match self.message_sig {
			None => "None".to_owned(),
			// This human-readable output historically uses the legacy compact
			// encoding, and users expect signatures here in that format.
			Some(m) => m
				.serialize_compact(&secp)
				.map_err(|_| fmt::Error)?
				.as_ref()
				.to_hex(),
		};
		writeln!(f, "Message Signature: {}", message_sig)
	}
}

/// A 'Slate' is passed around to all parties to build up all of the public
/// transaction data needed to create a finalized transaction. Callers can pass
/// the slate around by whatever means they choose, (but we can provide some
/// binary or JSON serialization helpers here).

#[derive(Debug, Clone)]
pub struct Slate {
	/// True is created from slatepack data.
	pub compact_slate: bool,
	/// Versioning info
	pub version_info: VersionCompatInfo,
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	/// Optional as of V4(aka V3) to allow for a compact
	/// transaction initiation
	pub tx: Option<Transaction>,
	/// base amount (excluding fee)
	pub amount: u64,
	/// fee amount
	pub fee: u64,
	/// Block height for the transaction
	pub height: u64,
	/// Lock height (private because it is related to kernel_features)
	lock_height: u64,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	pub ttl_cutoff_height: Option<u64>,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantData>,
	/// Payment Proof
	pub payment_proof: Option<PaymentInfo>,
	/// Offset, needed when posting of transaction is deferred.
	pub offset: BlindingFactor,
	/// Kernel Features flag -
	/// 	0: plain
	/// 	1: coinbase (invalid)
	/// 	2: height_locked
	/// 	3: NRD
	kernel_features: u8,
}

/// Slate with a network from the context
#[derive(Debug, Clone)]
pub struct SlateCtx {
	/// Slate
	pub slate: Slate,
	/// Network name form the context
	pub network_name: Option<String>,
}

/// Versioning and compatibility info about this slate
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct VersionCompatInfo {
	/// The current version of the slate format
	pub version: u16,
	/// The mwc block header version this slate is intended for
	pub block_header_version: u16,
}

/// Helper just to facilitate serialization
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct ParticipantMessages {
	/// included messages
	pub messages: Vec<ParticipantMessageData>,
}

impl Slate {
	/// Create new instance. Data will be validated
	pub fn new(
		compact_slate: bool,
		version_info: VersionCompatInfo,
		num_participants: usize,
		id: Uuid,
		tx: Option<Transaction>,
		amount: u64,
		fee: u64,
		height: u64,
		lock_height: u64,
		kernel_features: u8,
		ttl_cutoff_height: Option<u64>,
		participant_data: Vec<ParticipantData>,
		payment_proof: Option<PaymentInfo>,
		offset: BlindingFactor,
	) -> Result<Self, Error> {
		let res = Slate {
			compact_slate,
			version_info,
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			payment_proof,
			offset,
			kernel_features,
		};
		// let's validate the kernal params first
		let _ = res.kernel_features()?;
		Ok(res)
	}

	/// Return the transaction, throwing an error if it doesn't exist
	/// to be used at points in the code where the existence of a transaction
	/// is assumed
	pub fn tx_or_err(&self) -> Result<&Transaction, Error> {
		match &self.tx {
			Some(t) => Ok(t),
			None => Err(Error::SlateTransactionRequired),
		}
	}

	/// Perform lightweight consensus validation on the transaction carried by
	/// this slate. This bounds its weight and checks ordering, uniqueness,
	/// cut-through, and transaction features without requiring the partial
	/// transaction's range proofs, kernel signatures, or kernel sums to verify.
	pub fn validate_transaction_read(&self, context_id: u32) -> Result<(), Error> {
		self.tx_or_err()?.validate_read(context_id)?;
		Ok(())
	}

	/// As above, but return mutable reference
	pub fn tx_or_err_mut(&mut self) -> Result<&mut Transaction, Error> {
		match &mut self.tx {
			Some(t) => Ok(t),
			None => Err(Error::SlateTransactionRequired),
		}
	}

	/// Get kernel feature code
	pub fn get_kernel_features(&self) -> u8 {
		self.kernel_features
	}

	/// Get lock height pure value, caller must take care about kernel_features as well
	pub fn get_lock_height(&self) -> u64 {
		self.lock_height
	}

	/// Get lock height for current kernel feature. Note, for NRD it might be not accurate value
	pub fn calc_lock_height(&self) -> Result<u64, Error> {
		match self.kernel_features {
			3 => self.height.checked_add(self.lock_height).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Slate::calc_lock_height, NRD lock height overflow, height={} relative_lock_height={}",
					self.height, self.lock_height
				))
			}),
			_ => Ok(self.lock_height), // others must have height in sync
		}
	}

	/// Locking height value with kernel feature consistency checking
	pub fn get_lock_height_check(&self) -> Result<u64, Error> {
		match self.kernel_features {
			2 => Ok(self.lock_height),
			_ => Err(Error::InvalidKernelFeatures(format!(
				"Expected legit Lock kernel, but get kernel {} and lock_height {}",
				self.kernel_features, self.lock_height
			))),
		}
	}

	/// Reset to plain kernel
	pub fn reset_lock_height(&mut self) {
		self.lock_height = 0;
		self.kernel_features = 0;
	}

	/// For debug only!!!
	pub fn set_lock_height_no_check(&mut self, lock_height: u64) {
		self.lock_height = lock_height;
		self.kernel_features = 2;
	}

	/// Set lock height and LockHeight Kernel type
	pub fn set_lock_height(&mut self, lock_height: u64) -> Result<(), Error> {
		if lock_height == 0 {
			return Err(Error::InvalidKernelFeatures(format!(
				"Setting zero lock height"
			)));
		}
		if lock_height <= self.height {
			return Err(Error::InvalidKernelFeatures(format!(
				"Lock height {} is lower then slate height {}",
				lock_height, self.height
			)));
		}
		self.lock_height = lock_height;
		self.kernel_features = 2;
		Ok(())
	}

	/// Set NRD LockHeight Kernel type
	/// Note, currently NRD is not active, so node will reject it until the hardfork
	/// Currently nobody expectign to call it
	pub fn set_related_height(&mut self, lock_height: u64) -> Result<(), Error> {
		if lock_height == 0 || lock_height >= WEEK_HEIGHT {
			return Err(Error::InvalidKernelFeatures(format!(
				"Setting wrong related height {}",
				lock_height
			)));
		}
		self.lock_height = lock_height;
		self.kernel_features = 3;
		Ok(())
	}

	/// Attempt to find slate version
	pub fn parse_slate_version(slate_json: &str) -> Result<u16, Error> {
		let probe: SlateVersionProbe = serde_json::from_str(slate_json).map_err(|e| {
			Error::SlateVersionParse(format!("Unable to find slate version, {}",e))
		})?;
		Ok(probe.version())
	}

	/// Check if this text slate is plain
	pub fn deserialize_is_plain(slate_str: &str) -> bool {
		slate_str.as_bytes().starts_with(b"{")
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade_slatepack(
		context_id: u32,
		slate_str: &str,
		dec_key: &ed25519_dalek::SigningKey,
		secp: &Secp256k1,
	) -> Result<Slatepacker, Error> {
		let sp = Slatepacker::decrypt_slatepack(context_id, slate_str.as_bytes(), dec_key, secp)?;
		Ok(sp)
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade_plain(context_id: u32, slate_json: &str) -> Result<Slate, Error> {
		let version = Slate::parse_slate_version(slate_json)?;

		//I don't think we need to do this for coin_type and network_type, the slate containing these two
		//fields has to be version 3. If receiver wallet doesn't supported them, they will be filtered out.
		let ttl_cutoff_height = if version == 2 {
			serde_json::from_str::<SlateV2ParseTTL>(slate_json)
				.map_err(|e| {
					Error::SlateDeser(format!(
						"Unable to parse SlateV2 TTL metadata: {:?} JSON error at line {}, column {}",
						e.classify(),
						e.line(),
						e.column()
					))
				})?
				.ttl_cutoff_height
		} else {
			None
		};

		let v3: SlateV3 = match version {
			3 => serde_json::from_str(slate_json).map_err(|e| {
				Error::SlateDeser(format!(
					"Json to SlateV3 conversion failed: {:?} JSON error at line {}, column {}",
					e.classify(),
					e.line(),
					e.column()
				))
			})?,
			2 => {
				let v2: SlateV2 = serde_json::from_str(slate_json).map_err(|e| {
					Error::SlateDeser(format!(
						"Json to SlateV2 conversion failed: {:?} JSON error at line {}, column {}",
						e.classify(),
						e.line(),
						e.column()
					))
				})?;
				let mut ret = SlateV3::from(v2);
				ret.ttl_cutoff_height = ttl_cutoff_height;
				ret
			}
			_ => return Err(Error::SlateVersion(version)),
		};
		Ok(v3.to_slate(Some(global::get_network_name(context_id)), true)?)
	}

	/// Create a new slate
	/// slatepack also mean 'compact slate'. Please note the slates are build different way, so for the compact
	/// slates we have different method of building it.
	pub fn blank(num_participants: usize, compact_slate: bool) -> Result<Slate, Error> {
		let np = match num_participants {
			0 => 2,
			n => n,
		};
		// Slates carry input features in the V2/V3 exchange formats. Keep an empty
		// feature-preserving input collection so later transaction building does not
		// silently downgrade coinbase inputs to commitments without metadata.
		let mut tx = Transaction::empty();
		tx.body.inputs = Inputs::FeaturesAndCommit(vec![]);
		let mut uuid_bytes = [0_u8; 16];
		SysRng.try_fill_bytes(&mut uuid_bytes).map_err(|e| {
			Error::GenericError(format!(
				"Slate::blank, unable to generate slate UUID from the operating-system CSPRNG, num_participants={} compact_slate={} error={}",
				np, compact_slate, e
			))
		})?;
		let slate = Slate {
			compact_slate,
			num_participants: np, // assume 2 if not present
			id: UuidBuilder::from_random_bytes(uuid_bytes).into_uuid(),
			tx: Some(tx),
			amount: 0,
			fee: 0,
			height: 0,
			lock_height: 0,
			ttl_cutoff_height: None,
			participant_data: vec![],
			version_info: VersionCompatInfo {
				version: CURRENT_SLATE_VERSION,
				block_header_version: 1, // MWC_BLOCK_HEADER_VERSION,
			},
			payment_proof: None,
			offset: BlindingFactor::zero(),
			kernel_features: 0,
		};
		Ok(slate)
	}

	/// Validate a receiver's response against the locally-created initial send
	/// slate before doing message or partial-signature work.
	pub fn validate_send_response(&self, response: &Self) -> Result<(), Error> {
		if response.id != self.id {
			return Err(Error::SlateValidation(
				"send response UUID mismatch".to_string(),
			));
		}
		if response.compact_slate != self.compact_slate {
			return Err(Error::SlateValidation(
				"send response compact_slate flag mismatch".to_string(),
			));
		}
		if self.num_participants != MAX_SEND_PARTICIPANTS
			|| response.num_participants != self.num_participants
		{
			return Err(Error::SlateValidation(format!(
				"send response participant declaration mismatch, original={} response={} supported={}",
				self.num_participants, response.num_participants, MAX_SEND_PARTICIPANTS
			)));
		}
		if self.participant_data.len() != 1 || self.participant_data[0].id != 0 {
			return Err(Error::SlateValidation(
				"initial send slate must contain exactly participant 0".to_string(),
			));
		}
		if response.participant_data.len() > MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"send response has too many participant records, actual={} maximum={}",
				response.participant_data.len(),
				MAX_SEND_PARTICIPANTS
			)));
		}

		response.check_unique_participant_ids()?;
		if response
			.participant_data
			.iter()
			.any(|participant| participant.id > 1)
		{
			return Err(Error::SlateValidation(
				"send response contains an unexpected participant id".to_string(),
			));
		}

		let returned_initiator = response
			.participant_data
			.iter()
			.find(|participant| participant.id == 0);
		match returned_initiator {
			Some(participant) if participant == &self.participant_data[0] => {}
			Some(_) => {
				return Err(Error::SlateValidation(
					"send response altered the initiator participant".to_string(),
				));
			}
			None if self.compact_slate => {}
			None => {
				return Err(Error::SlateValidation(
					"send response omitted the initiator participant".to_string(),
				));
			}
		}

		let responder = response
			.participant_data
			.iter()
			.find(|participant| participant.id == 1)
			.ok_or_else(|| {
				Error::SlateValidation(
					"send response is missing receiver participant 1".to_string(),
				)
			})?;
		if !responder.is_complete() {
			return Err(Error::SlateValidation(
				"send response receiver participant is incomplete".to_string(),
			));
		}
		response.check_participant_message_lengths()?;

		Ok(())
	}

	/// Validate an issuer-finalized invoice response received over HTTP against
	/// the response slate this wallet sent. The transaction signature does not
	/// commit the slate UUID or the participant transcript, so the returned
	/// values must be bound to the sent ones before the payer locks outputs,
	/// posts the transaction, or records the payment: a swapped UUID would be
	/// stored as the payment id, defeating the duplicate-payment check keyed on
	/// the original invoice id.
	///
	/// The issuer record must match the sent one in every field except the
	/// completed partial signature, and a noncompact response must carry our
	/// payer record unchanged. For a compact response the return-trip encoding
	/// legitimately omits the payer record; the locally retained record is
	/// merged back into `response` so the persisted transcript is complete.
	pub fn validate_invoice_response(&self, response: &mut Self) -> Result<(), Error> {
		if response.id != self.id {
			return Err(Error::SlateValidation(
				"invoice response UUID mismatch".to_string(),
			));
		}
		if response.compact_slate != self.compact_slate {
			return Err(Error::SlateValidation(
				"invoice response compact_slate flag mismatch".to_string(),
			));
		}
		if self.num_participants != MAX_INVOICE_PARTICIPANTS
			|| response.num_participants != self.num_participants
		{
			return Err(Error::SlateValidation(format!(
				"invoice response participant declaration mismatch, sent={} response={} supported={}",
				self.num_participants, response.num_participants, MAX_INVOICE_PARTICIPANTS
			)));
		}
		if response.participant_data.len() > MAX_INVOICE_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"invoice response has too many participant records, actual={} maximum={}",
				response.participant_data.len(),
				MAX_INVOICE_PARTICIPANTS
			)));
		}
		response.check_unique_participant_ids()?;
		if response.participant_data.iter().any(|p| p.id > 1) {
			return Err(Error::SlateValidation(
				"invoice response contains an unexpected participant id".to_string(),
			));
		}
		// Our own payer record (id 1) must come back unchanged. Noncompact
		// responses carry the full transcript, so its absence is an
		// alteration; compact return-trip encoding legitimately omits it, and
		// the locally retained record is merged back below.
		match response.participant_data.iter().find(|p| p.id == 1) {
			Some(returned_payer) => match self.participant_data.iter().find(|p| p.id == 1) {
				Some(sent_payer) if returned_payer == sent_payer => {}
				_ => {
					return Err(Error::SlateValidation(
						"invoice response altered the payer participant".to_string(),
					));
				}
			},
			None if self.compact_slate => {}
			None => {
				return Err(Error::SlateValidation(
					"invoice response is missing payer participant 1".to_string(),
				));
			}
		}
		// The issuer record (id 0) must be present and carry its completed
		// partial signature. Everything the issuer asserted at issuance is
		// otherwise immutable: the transaction signature does not commit
		// participant_data and verify_messages skips absent messages, so the
		// returned nonce, blind, message and message signature must be bound
		// to the sent slate explicitly. Only the part_sig completion may
		// differ.
		let issuer = response
			.participant_data
			.iter()
			.find(|p| p.id == 0)
			.ok_or_else(|| {
				Error::SlateValidation(
					"invoice response is missing issuer participant 0".to_string(),
				)
			})?;
		if !issuer.is_complete() {
			return Err(Error::SlateValidation(
				"invoice response issuer participant is incomplete".to_string(),
			));
		}
		match self.participant_data.iter().find(|p| p.id == 0) {
			Some(sent_issuer)
				if ParticipantData {
					part_sig: None,
					..issuer.clone()
				} == ParticipantData {
					part_sig: None,
					..sent_issuer.clone()
				} => {}
			_ => {
				return Err(Error::SlateValidation(
					"invoice response altered the issuer participant".to_string(),
				));
			}
		}
		// A compact return trip legitimately omits the payer record. Reattach
		// the locally retained one so the transcript persisted by
		// lock_tx_context (participant messages) is complete.
		if self.compact_slate && !response.participant_data.iter().any(|p| p.id == 1) {
			if let Some(sent_payer) = self.participant_data.iter().find(|p| p.id == 1) {
				response.participant_data.push(sent_payer.clone());
			}
		}
		response.check_participant_message_lengths()?;

		Ok(())
	}

	/// Validate a counterparty's initial send slate before message
	/// verification, key allocation, or signing. Only the two-party flow is
	/// implemented, so the slate must declare two participants and carry
	/// exactly the sender record (id 0) at this stage. Excess or duplicate
	/// records would still enter the aggregate nonce and blind sums used for
	/// the receiver's partial signature, making the wallet sign a participant
	/// transcript that does not match the implemented protocol.
	pub fn validate_send_initial(&self) -> Result<(), Error> {
		if self.num_participants != MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"initial send slate participant declaration unsupported, num_participants={} supported={}",
				self.num_participants, MAX_SEND_PARTICIPANTS
			)));
		}
		if self.participant_data.len() != 1 || self.participant_data[0].id != 0 {
			return Err(Error::SlateValidation(format!(
				"initial send slate must contain exactly participant 0, participant_count={}",
				self.participant_data.len()
			)));
		}
		Ok(())
	}

	/// Validate a counterparty's initial invoice slate before message
	/// verification, key allocation, or signing. Only the two-party flow is
	/// implemented, so the invoice must declare two participants and carry
	/// exactly the issuer record (id 0) at this stage. Missing, duplicate, or
	/// extra records would still enter the aggregate nonce and blind sums used
	/// for the payer's partial signature, making the wallet sign a participant
	/// transcript that does not match the implemented protocol.
	pub fn validate_invoice_initial(&self) -> Result<(), Error> {
		if self.num_participants != MAX_INVOICE_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"initial invoice slate participant declaration unsupported, num_participants={} supported={}",
				self.num_participants, MAX_INVOICE_PARTICIPANTS
			)));
		}
		if self.participant_data.len() != 1 || self.participant_data[0].id != 0 {
			return Err(Error::SlateValidation(format!(
				"initial invoice slate must contain exactly participant 0, participant_count={}",
				self.participant_data.len()
			)));
		}
		// Only Plain kernels are implemented for invoice payment. The payer's
		// Context is always built with lock_height=0/kernel_features=0
		// (selection::build_send_tx), and the policy match against that Context
		// is verified only after the signed slate has been sent back to the
		// issuer (Context::validate_slate in tx_lock_outputs). The partial
		// signature commits to the slate's kernel, so any other policy must be
		// rejected here, before key allocation and signing.
		if self.kernel_features != 0 || self.lock_height != 0 {
			return Err(Error::InvalidKernelFeatures(format!(
				"initial invoice slate kernel policy unsupported, kernel_features={} lock_height={} supported=Plain",
				self.kernel_features, self.lock_height
			)));
		}
		self.check_unique_participant_ids()?;
		self.check_participant_message_lengths()?;
		Ok(())
	}

	/// Bind a locally issued invoice request to the private issuer context that
	/// created it. This is used when the same wallet pays its own invoice: the
	/// UUID alone is not authentication, so the public signing keys, participant
	/// message and immutable invoice metadata must still match before the payer
	/// selects coins or signs. The caller verifies the participant message
	/// signature separately so this helper does not repeat that expensive work.
	pub(crate) fn validate_invoice_initial_context(
		&self,
		secp: &Secp256k1,
		context: &Context,
	) -> Result<(), Error> {
		self.validate_invoice_initial()?;
		if context.participant_id != 0 {
			return Err(Error::SlateValidation(format!(
				"invoice issuer context participant mismatch, expected=0 actual={}",
				context.participant_id
			)));
		}

		if self.compact_slate != context.compact_slate {
			return Err(Error::SlateValidation(
				"initial invoice compact_slate flag does not match issuer context".to_owned(),
			));
		}
		if self.amount != context.amount {
			return Err(Error::SlateValidation(
				"initial invoice amount does not match issuer context".to_owned(),
			));
		}
		if self.fee != context.fee {
			return Err(Error::SlateValidation(
				"initial invoice fee does not match issuer context".to_owned(),
			));
		}
		if self.get_kernel_features() != context.kernel_features
			|| self.get_lock_height() != context.lock_height
		{
			return Err(Error::SlateValidation(
				"initial invoice kernel policy does not match issuer context".to_owned(),
			));
		}
		if self.ttl_cutoff_height != context.ttl_cutoff_height {
			return Err(Error::SlateValidation(
				"initial invoice TTL does not match issuer context".to_owned(),
			));
		}

		let issuer = self.participant_data.first().ok_or_else(|| {
			Error::SlateValidation("initial invoice is missing issuer participant 0".to_owned())
		})?;
		let expected_nonce = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
		let expected_blind = PublicKey::from_secret_key(secp, &context.sec_key)?;
		if issuer.public_nonce != expected_nonce || issuer.public_blind_excess != expected_blind {
			return Err(Error::SlateValidation(
				"initial invoice issuer participant does not match issuer context".to_owned(),
			));
		}
		if issuer.message.as_ref() != context.message.as_ref() {
			return Err(Error::SlateValidation(
				"initial invoice issuer message does not match issuer context".to_owned(),
			));
		}

		Ok(())
	}

	/// Validate a send response slate against the persisted private context.
	/// Standalone finalize flows (file, slatepack, RPC, C API) recover only the
	/// context, so [`Slate::validate_send_response`] cannot be used: the
	/// original send slate is gone. The same participant invariants are
	/// enforced here — the two-party declaration, unique in-range ids, a
	/// complete responder record and bounded messages — and the initiator
	/// record is required for a noncompact response and checked against the
	/// public values and participant message persisted in the context. A
	/// compact response may omit it because repopulation restores the local
	/// record from that same context.
	/// Must run before locking or signing: unchecked records would enter the
	/// aggregate nonce and blind sums, making the wallet sign a participant
	/// transcript outside the implemented two-party protocol. Message
	/// signatures are verified as part of this validation.
	pub fn validate_send_response_context(
		&self,
		secp: &Secp256k1,
		context: &Context,
	) -> Result<(), Error> {
		if self.num_participants != MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"send response participant declaration unsupported, num_participants={} supported={}",
				self.num_participants, MAX_SEND_PARTICIPANTS
			)));
		}
		if self.participant_data.len() > MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"send response has too many participant records, actual={} maximum={}",
				self.participant_data.len(),
				MAX_SEND_PARTICIPANTS
			)));
		}
		self.check_unique_participant_ids()?;
		if self.participant_data.iter().any(|p| p.id > 1) {
			return Err(Error::SlateValidation(
				"send response contains an unexpected participant id".to_string(),
			));
		}
		match self.participant_data.iter().find(|p| p.id == 0) {
			Some(initiator) => {
				let expected_nonce = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
				let expected_blind = PublicKey::from_secret_key(secp, &context.sec_key)?;
				if initiator.public_nonce != expected_nonce
					|| initiator.public_blind_excess != expected_blind
				{
					return Err(Error::SlateValidation(
						"send response altered the initiator participant".to_string(),
					));
				}
				if initiator.message.as_ref() != context.message.as_ref() {
					return Err(Error::SlateValidation(
						"send response altered the initiator participant message".to_string(),
					));
				}
			}
			None if context.compact_slate => {}
			None => {
				return Err(Error::SlateValidation(
					"send response omitted the initiator participant".to_string(),
				));
			}
		}
		let responder = self
			.participant_data
			.iter()
			.find(|p| p.id == 1)
			.ok_or_else(|| {
				Error::SlateValidation(
					"send response is missing receiver participant 1".to_string(),
				)
			})?;
		if !responder.is_complete() {
			return Err(Error::SlateValidation(
				"send response receiver participant is incomplete".to_string(),
			));
		}
		self.check_participant_message_lengths()?;
		self.verify_messages(secp)?;

		Ok(())
	}

	/// Validate the context-free structure of a two-party response slate (a
	/// send response or an invoice response) before participant message
	/// verification or any wallet operation. Only the two-party flow is
	/// implemented, so the slate must declare two participants, carry at most
	/// two unique records with ids 0 and 1, and the counterparty record
	/// (id 1) must be complete. Participant ids and num_participants are not
	/// covered by partial signatures, so these checks keep a relabeled or
	/// oversized transcript out of the signing and storage paths; running
	/// them before message verification also keeps attacker-supplied records
	/// out of the per-record signature verification loop.
	pub fn validate_response_participants(&self) -> Result<(), Error> {
		if self.num_participants != MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"response participant declaration unsupported, num_participants={} supported={}",
				self.num_participants, MAX_SEND_PARTICIPANTS
			)));
		}
		if self.participant_data.len() > MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"response has too many participant records, actual={} maximum={}",
				self.participant_data.len(),
				MAX_SEND_PARTICIPANTS
			)));
		}
		self.check_unique_participant_ids()?;
		if self.participant_data.iter().any(|p| p.id > 1) {
			return Err(Error::SlateValidation(
				"response contains an unexpected participant id".to_string(),
			));
		}
		let counterparty = self
			.participant_data
			.iter()
			.find(|p| p.id == 1)
			.ok_or_else(|| {
				Error::SlateValidation(
					"response is missing counterparty participant 1".to_string(),
				)
			})?;
		if !counterparty.is_complete() {
			return Err(Error::SlateValidation(
				"response counterparty participant is incomplete".to_string(),
			));
		}
		self.check_participant_message_lengths()?;

		Ok(())
	}

	/// Validate an invoice response slate against the persisted issuer
	/// context. Standalone issuer finalize flows (file, slatepack, C API)
	/// recover only the private context, so [`Slate::validate_invoice_response`]
	/// cannot be used: the slate sent back by the payer is all that remains.
	/// The two-party invariants come from
	/// [`Slate::validate_response_participants`]; the issuer record (id 0) is
	/// required for a noncompact response and bound to the public values and
	/// participant message persisted in the context. A compact response may
	/// omit it because repopulation restores the local record from the context.
	/// Must run before key allocation or signing: participant ids are not
	/// covered by partial signatures, so an unchecked relabeled record would
	/// make the wallet sign and store a transcript outside the implemented
	/// two-party protocol. Message signatures are verified as part of this
	/// validation.
	pub fn validate_invoice_response_context(
		&self,
		secp: &Secp256k1,
		context: &Context,
	) -> Result<(), Error> {
		self.validate_response_participants()?;
		match self.participant_data.iter().find(|p| p.id == 0) {
			Some(issuer) => {
				let expected_nonce = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
				let expected_blind = PublicKey::from_secret_key(secp, &context.sec_key)?;
				if issuer.public_nonce != expected_nonce
					|| issuer.public_blind_excess != expected_blind
				{
					return Err(Error::SlateValidation(
						"invoice response altered the issuer participant".to_string(),
					));
				}
				if issuer.message.as_ref() != context.message.as_ref() {
					return Err(Error::SlateValidation(
						"invoice response altered the issuer participant message".to_string(),
					));
				}
			}
			None if context.compact_slate => {}
			None => {
				return Err(Error::SlateValidation(
					"invoice response omitted the issuer participant".to_string(),
				));
			}
		}
		self.verify_messages(secp)?;
		Ok(())
	}

	/// Compare two slates for invoice: sended and responded. Just want to check if sender didn't mess with slate
	pub fn compare_slates_invoice(invoice_slate: &Self, respond_slate: &Self) -> Result<(), Error> {
		if invoice_slate.id != respond_slate.id {
			return Err(Error::SlateValidation("uuid mismatch".to_string()));
		}
		if invoice_slate.amount != respond_slate.amount {
			return Err(Error::SlateValidation("amount mismatch".to_string()));
		}
		if invoice_slate.height != respond_slate.height {
			return Err(Error::SlateValidation("height mismatch".to_string()));
		}
		if invoice_slate.ttl_cutoff_height != respond_slate.ttl_cutoff_height {
			return Err(Error::SlateValidation("ttl_cutoff mismatch".to_string()));
		}
		// The exchange metadata below is fixed when the invoice is issued. The
		// responder must not alter the kernel policy we are asked to sign under.
		if invoice_slate.compact_slate != respond_slate.compact_slate {
			return Err(Error::SlateValidation(
				"compact_slate flag mismatch".to_string(),
			));
		}
		if invoice_slate.num_participants != respond_slate.num_participants {
			return Err(Error::SlateValidation(
				"num_participants mismatch".to_string(),
			));
		}
		if invoice_slate.get_kernel_features() != respond_slate.get_kernel_features() {
			return Err(Error::SlateValidation(
				"kernel_features mismatch".to_string(),
			));
		}
		if invoice_slate.get_lock_height() != respond_slate.get_lock_height() {
			return Err(Error::SlateValidation("lock_height mismatch".to_string()));
		}
		if !invoice_slate.tx_or_err()?.body.inputs.is_empty() {
			return Err(Error::SlateValidation(
				"Slate::compare_slates_invoice, invoice slate unexpectedly contains inputs"
					.to_string(),
			));
		}
		// Respond outputs must include original ones. Expected that some was added
		for output in &invoice_slate.tx_or_err()?.body.outputs {
			if !respond_slate.tx_or_err()?.body.outputs.contains(&output) {
				return Err(Error::SlateValidation("outputs mismatch".to_string()));
			}
		}
		// Checking if participant data match each other
		for pat_data in &invoice_slate.participant_data {
			if !respond_slate.participant_data.contains(&pat_data) {
				return Err(Error::SlateValidation(
					"participant data mismatch".to_string(),
				));
			}
		}
		// The responder may only append their own record. The participant set
		// must stay bounded and unique before any message or partial-signature
		// verification: excess completed records make verification quadratic
		// and can later exceed the transaction log serialization limit.
		if respond_slate.participant_data.len() > MAX_INVOICE_PARTICIPANTS
			|| respond_slate.participant_data.len()
				> invoice_slate.participant_data.len().saturating_add(1)
		{
			return Err(Error::SlateValidation(
				"unexpected number of participants".to_string(),
			));
		}
		respond_slate.check_unique_participant_ids()?;
		respond_slate.check_participant_message_lengths()?;

		Ok(())
	}

	/// Verify that participant ids are unique. Duplicate records would make the
	/// aggregate nonce/blind sums and partial-signature verification ambiguous.
	pub fn check_unique_participant_ids(&self) -> Result<(), Error> {
		let mut seen = std::collections::HashSet::with_capacity(self.participant_data.len());
		for p in &self.participant_data {
			if !seen.insert(p.id) {
				return Err(Error::SlateValidation(
					"duplicate participant id".to_string(),
				));
			}
		}
		Ok(())
	}

	/// Reject oversized signed messages instead of truncating them. Truncation
	/// would change the signed value, while accepting them permits avoidable
	/// hashing, logging and transaction-log storage amplification.
	pub fn check_participant_message_lengths(&self) -> Result<(), Error> {
		for participant in &self.participant_data {
			if let Some(message) = &participant.message {
				if message.len() > MAX_PARTICIPANT_MESSAGE_LEN {
					return Err(Error::SlateValidation(format!(
						"participant {} message is too large, actual={} maximum={}",
						participant.id,
						message.len(),
						MAX_PARTICIPANT_MESSAGE_LEN
					)));
				}
			}
		}
		Ok(())
	}

	/// Calculate the lowest plain Slate version that can represent this Slate
	/// without losing data or failing conversion. Prefer V2 for compatibility,
	/// but only when all V3-to-V2 downgrade preconditions are satisfied.
	pub fn lowest_version(&self) -> SlateVersion {
		if self.payment_proof.is_none()
			&& self.ttl_cutoff_height.is_none()
			&& !self.compact_slate
			&& matches!(self.kernel_features, 0 | 2)
			&& self.tx.is_some()
		{
			SlateVersion::V2
		} else {
			SlateVersion::V3
		}
	}

	/// Adds selected inputs and outputs to the slate's transaction
	/// Returns blinding factor
	pub fn add_transaction_elements<K, B>(
		&mut self,
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		builder: &B,
		elems: Vec<Box<build::Append<K, B>>>,
	) -> Result<BlindingFactor, Error>
	where
		K: Keychain,
		B: ProofBuild,
	{
		self.update_kernel()?;
		if elems.is_empty() {
			return Ok(BlindingFactor::zero());
		}
		let (tx, blind) = build::partial_transaction(
			context_id,
			secp,
			self.tx_or_err()?.clone(),
			&elems,
			keychain,
			builder,
		)
		.map_err(|e| Error::GenericError(format!("Adding transaction elements, {}", e)))?;
		self.tx = Some(tx);
		Ok(blind)
	}

	/// Update the tx kernel based on kernel features derived from the current slate.
	/// The fee may change as we build a transaction and we need to
	/// update the tx kernel to reflect this during the tx building process.
	pub fn update_kernel(&mut self) -> Result<(), Error> {
		self.tx = Some(
			self.tx_or_err()?
				.clone()
				.replace_kernel(TxKernel::with_features(self.kernel_features()?)?),
		);
		Ok(())
	}

	/// Completes callers part of round 1, adding public key info
	/// to the slate
	pub fn fill_round_1<K>(
		&mut self,
		secp: &Secp256k1,
		keychain: &K,
		sec_key: &mut SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
		message: Option<String>,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		if !self.compact_slate {
			// Generating offset for backward compability. Offset ONLY for the TX, the slate copy is kept the same.
			if self.tx_or_err()?.offset == BlindingFactor::zero() {
				self.generate_legacy_offset(
					secp,
					keychain,
					sec_key,
					#[cfg(feature = "test-support")]
					use_test_rng,
				)
				.map_err(|e| Error::GenericError(format!("Generating legacy offset, {}", e)))?;
			}
		}

		self.add_participant_info(
			secp,
			&sec_key,
			&sec_nonce,
			participant_id,
			None,
			message,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)
		.map_err(|e| Error::GenericError(format!("Adding participant info, {}", e)))?;
		Ok(())
	}

	/// Build kernel features based on variant and associated data.
	/// kernel_features values:
	/// 0: plain
	/// 1: coinbase (invalid)
	/// 2: height_locked (with associated lock_height)
	/// 3: NRD (with associated relative_height)
	/// Any other value is invalid.
	pub fn kernel_features(&self) -> Result<KernelFeatures, Error> {
		match self.kernel_features {
			0 => {
				if self.lock_height != 0 {
					return Err(Error::SlateValidation(format!(
						"Invalid lock_height for Plain kernel feature. lock_height expected to be zero, but has {}",
						self.lock_height
					)));
				}
				Ok(KernelFeatures::Plain {
					fee: self.build_fee()?,
				})
			}
			1 => Err(Error::InvalidKernelFeatures(
				"Coinbase feature is not expected at Slate".into(),
			)),
			2 => Ok(KernelFeatures::HeightLocked {
				fee: self.build_fee()?,
				lock_height: if self.lock_height > self.height && self.height > 0 {
					self.lock_height
				} else {
					return Err(Error::SlateValidation(format!(
						"Invalid lock_height, height value is {}, but lock_height is {}",
						self.height, self.lock_height
					)));
				},
			}),
			3 => Ok(KernelFeatures::NoRecentDuplicate {
				fee: self.build_fee()?,
				relative_height: if self.lock_height < WEEK_HEIGHT {
					NRDRelativeHeight::new(self.lock_height)?
				} else {
					return Err(Error::SlateValidation(format!(
						"Invalid NRD relative_height, height value is {}, limit is {}",
						self.lock_height, WEEK_HEIGHT
					)));
				},
			}),
			n => Err(Error::UnknownKernelFeatures(n)),
		}
	}

	// u64 try_into for FeeFields is build for VALID values, so 0 is not accepted.
	// That is why we need this method
	fn build_fee(&self) -> Result<FeeFields, Error> {
		if self.fee == 0 {
			Ok(FeeFields::zero())
		} else {
			FeeFields::try_from(self.fee).map_err(|e| {
				Error::DataOverflow(format!(
					"Slate::build_fee, fee does not fit FeeFields, fee={} error={}",
					self.fee, e
				))
			})
		}
	}

	/// This is the msg that we will sign as part of the tx kernel.
	/// If lock_height is 0 then build a plain kernel, otherwise build a height locked kernel.
	pub fn msg_to_sign(&self, context_id: u32) -> Result<secp::Message, Error> {
		let msg = self.kernel_features()?.kernel_sig_msg(context_id)?;
		Ok(msg)
	}

	/// Fingerprint every input that controls this participant's Schnorr
	/// equation. The fingerprint is persisted before signing so the same secret
	/// nonce may only ever be used for this exact aggregate challenge. The slate
	/// and participant identifiers are included as additional domain binding,
	/// even though the Schnorr challenge itself is defined by the aggregate
	/// nonce, aggregate public key and kernel message.
	pub(crate) fn aggsig_challenge_hash(
		&self,
		context_id: u32,
		secp: &Secp256k1,
		participant_id: usize,
		local_public_blind: &PublicKey,
		local_public_nonce: &PublicKey,
	) -> Result<[u8; 32], Error> {
		let participant_id = u64::try_from(participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"Slate::aggsig_challenge_hash, participant id does not fit u64, participant_id={} error={}",
				participant_id, e
			))
		})?;
		let aggregate_nonce = self.pub_nonce_sum(secp)?;
		let aggregate_blind = self.pub_blind_sum(secp)?;
		let kernel_message = self.msg_to_sign(context_id)?;

		let mut preimage = Vec::with_capacity(16 + 4 + 8 + 33 * 4 + 32);
		preimage.extend_from_slice(self.id.as_bytes());
		preimage.extend_from_slice(&context_id.to_le_bytes());
		preimage.extend_from_slice(&participant_id.to_le_bytes());
		for public_key in [
			local_public_blind,
			local_public_nonce,
			&aggregate_blind,
			&aggregate_nonce,
		] {
			preimage.extend_from_slice(&public_key.serialize_vec(secp, true)?);
		}
		preimage.extend_from_slice(kernel_message.as_ref());

		let digest = blake2b(32, AGGSIG_CHALLENGE_HASH_KEY, &preimage);
		let mut challenge = [0u8; 32];
		challenge.copy_from_slice(digest.as_bytes());
		Ok(challenge)
	}

	/// Completes caller's part of round 2, completing signatures
	pub fn fill_round_2(
		&mut self,
		context_id: u32,
		secp: &Secp256k1,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
	) -> Result<(), Error> {
		// TODO: Note we're unable to verify fees in this instance because of the slatepacks
		// Inputs are not transferred.
		// Also with lock later feature, fees and inputs can be adjusted before finalizing by the send init party
		// self.check_fees()?;

		// usize-to-u64 is lossless on every target architecture supported by this project.
		let participant_id = participant_id as u64;
		let participant_count = self.participant_data.len();
		let participant_index = self
			.participant_data
			.iter()
			.position(|participant| participant.id == participant_id)
			.ok_or_else(|| {
				Error::SlateValidation(format!(
					"Slate::fill_round_2, participant is missing, participant_id={} participant_count={}",
					participant_id, participant_count
				))
			})?;

		self.verify_part_sigs(context_id, secp)?;
		let sig_part = aggsig::calculate_partial_sig(
			secp,
			sec_key,
			sec_nonce,
			&self.pub_nonce_sum(secp)?,
			&self.pub_blind_sum(secp)?,
			&self.msg_to_sign(context_id)?,
		)?;
		self.participant_data[participant_index].part_sig = Some(sig_part);
		Ok(())
	}

	/// Creates the final signature, callable by either the sender or recipient
	/// (after phase 3: sender confirmation)
	pub fn finalize(&mut self, context_id: u32, secp: &mut Secp256k1) -> Result<(), Error> {
		let final_sig = self.finalize_signature(context_id, secp)?;
		self.finalize_transaction(context_id, secp, &final_sig)
	}

	/// Return the participant with the given id
	pub fn participant_with_id(&self, id: usize) -> Option<ParticipantData> {
		// usize-to-u64 is lossless on every target architecture supported by this project.
		let id = id as u64;
		for p in self.participant_data.iter() {
			if p.id == id {
				return Some(p.clone());
			}
		}
		None
	}

	/// Return the sum of public nonces
	pub fn pub_nonce_sum(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let pub_nonces: Vec<&PublicKey> = self
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		if pub_nonces.len() == 0 {
			return Err(Error::GenericError(format!(
				"Participant nonces cannot be empty"
			)));
		}
		match PublicKey::from_combination(&secp, pub_nonces) {
			Ok(k) => Ok(k),
			Err(e) => Err(Error::from(e)),
		}
	}

	/// Describe the available body without disclosing proofs or signing material.
	/// For a complete body, bind balance to the participant aggregate, never to
	/// an excess reconstructed from the same body being checked.
	pub(crate) fn node_preflight_transaction(
		&self,
		context_id: u32,
		secp: &Secp256k1,
		is_complete: bool,
	) -> Result<crate::transaction_preflight::PreflightTransaction, Error> {
		let mut request = crate::transaction_preflight::PreflightTransaction::from_transaction(
			context_id,
			self.tx_or_err()?,
			is_complete,
		)?;
		if is_complete {
			self.check_unique_participant_ids()?;
			if self.participant_data.len() != self.num_participants || request.kernels.len() != 1 {
				return Err(Error::SlateValidation(
					"Complete preflight requires all participants and one kernel".into(),
				));
			}
			let excess = Commitment::from_pubkey(secp, &self.pub_blind_sum(secp)?)?;
			if request.kernels[0].excess != Some(excess) {
				// An unfinished peer kernel is only a placeholder. Its stored excess
				// and signature hash do not identify the negotiated transaction.
				request.kernels[0].kernel_hash = None;
			}
			request.kernels[0].excess = Some(excess);
		}
		Ok(request)
	}

	/// Return the sum of public blinding factors
	fn pub_blind_sum(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let pub_blinds: Vec<&PublicKey> = self
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		if pub_blinds.len() == 0 {
			return Err(Error::GenericError(format!(
				"Participant Blind sums cannot be empty"
			)));
		}
		match PublicKey::from_combination(secp, pub_blinds) {
			Ok(k) => Ok(k),
			Err(e) => Err(Error::from(e)),
		}
	}

	/// Return every declared participant's partial signature.
	fn part_sigs(&self) -> Result<Vec<AggSigSignature>, Error> {
		if self.num_participants == 0 || self.participant_data.len() != self.num_participants {
			return Err(Error::SlateValidation(format!(
				"Slate::part_sigs, participant count does not match declaration, actual={} declared={}",
				self.participant_data.len(),
				self.num_participants
			)));
		}

		self.participant_data
			.iter()
			.map(|participant| {
				participant.part_sig.ok_or_else(|| {
					Error::SlateValidation(format!(
						"Slate::part_sigs, participant signature is missing, participant_id={}",
						participant.id
					))
				})
			})
			.collect()
	}

	/// Adds participants public keys to the slate data
	/// and saves participant's transaction context
	/// sec_key can be overridden to replace the blinding
	/// factor (by whoever split the offset)
	pub fn add_participant_info(
		&mut self,
		secp: &secp::Secp256k1,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		id: usize,
		part_sig: Option<AggSigSignature>,
		message: Option<String>,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<(), Error> {
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(secp, &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(secp, &sec_nonce)?;

		#[cfg(feature = "test-support")]
		let test_message_nonce = SecretKey::from_slice(secp, &[1; 32])?;
		#[cfg(feature = "test-support")]
		let message_nonce = match use_test_rng {
			false => None,
			true => Some(&test_message_nonce),
		};
		#[cfg(not(feature = "test-support"))]
		let message_nonce = None;

		// Sign the provided message
		let message_sig = {
			if let Some(m) = message.clone() {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &m.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let res = aggsig::sign_single(secp, &m, sec_key, message_nonce, &pub_key)?;
				Some(res)
			} else {
				None
			}
		};

		// The record might exist. In this case we should update it
		match self
			.participant_data
			.iter_mut()
			.find(|ref p| p.id == id as u64)
		{
			Some(pp) => {
				if pp.public_blind_excess == pub_key && pp.public_nonce == pub_nonce {
					if part_sig.is_some() {
						pp.part_sig = part_sig;
					}

					if pp.message == message {
						if message_sig.is_some() {
							pp.message_sig = message_sig;
						}
					} else {
						pp.message_sig = message_sig;
					}
				} else {
					pp.part_sig = part_sig;
					pp.message_sig = message_sig;
				}
				pp.public_blind_excess = pub_key;
				pp.public_nonce = pub_nonce;
				pp.message = message;
			}
			None => {
				self.participant_data.push(ParticipantData {
					id: id as u64,
					public_blind_excess: pub_key,
					public_nonce: pub_nonce,
					part_sig: part_sig,
					message: message,
					message_sig: message_sig,
				});
			}
		}
		Ok(())
	}

	/// helper to return all participant messages
	pub fn participant_messages(&self) -> ParticipantMessages {
		let mut ret = ParticipantMessages { messages: vec![] };
		for ref m in self.participant_data.iter() {
			ret.messages
				.push(ParticipantMessageData::from_participant_data(m));
		}
		ret
	}

	/// NOTE: Non compact workflow supporting. This code does generate the offset for NON slatepack case
	/// Slateppacks will override that!!!!
	/// Somebody involved needs to generate an offset with their private key
	/// For now, we'll have the transaction initiator be responsible for it
	/// Return offset private key for the participant to use later in the
	/// transaction
	fn generate_legacy_offset<K: Keychain>(
		&mut self,
		secp: &Secp256k1,
		keychain: &K,
		sec_key: &mut SecretKey,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<(), Error> {
		// Generate a random kernel offset here
		// and subtract it from the blind_sum so we create
		// the aggsig context with the "split" key
		#[cfg(feature = "test-support")]
		let offset = if use_test_rng {
			// allow for consistent test results
			let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
			let mut bytes = [0u8; secp::constants::SECRET_KEY_SIZE];
			test_rng.try_fill_bytes(&mut bytes).map_err(|e| {
				Error::GenericError(format!("Unable to generate test secret key, {}", e))
			})?;
			BlindingFactor::from_secret_key(SecretKey::from_slice(secp, &bytes)?)
		} else {
			BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?)
		};
		#[cfg(not(feature = "test-support"))]
		let offset = BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?);
		self.tx_or_err_mut()?.offset = offset;

		let blind_offset = keychain.blind_sum(
			secp,
			&BlindSum::new()
				.add_blinding_factor(BlindingFactor::from_secret_key(sec_key.clone()))
				.sub_blinding_factor(self.tx_or_err()?.offset.clone()),
		)?;
		*sec_key = blind_offset.secret_key(secp)?;
		Ok(())
	}

	/// Add our contribution to the offset based on the excess, inputs and outputs
	pub fn adjust_offset<K: Keychain>(
		&mut self,
		secp: &Secp256k1,
		keychain: &K,
		context: &Context,
	) -> Result<(), Error> {
		if !self.compact_slate {
			return Err(Error::SlateValidation(
				"Slate::adjust_offset, operation requires a compact slate".to_string(),
			));
		}

		let mut sum = BlindSum::new()
			.add_blinding_factor(self.offset.clone())
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				context.initial_sec_key.clone(),
			));
		for (id, _, amount) in &context.input_ids {
			sum = sum.sub_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				secp,
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}
		for (id, _, amount) in &context.output_ids {
			sum = sum.add_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				secp,
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}

		self.offset = keychain.blind_sum(secp, &sum)?;

		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self, context_id: u32) -> Result<(), Error> {
		let tx = self.tx_or_err()?;
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(
			context_id,
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
		)?;
		let tx_fee = tx.fee()?;

		if fee > tx_fee {
			return Err(Error::Fee(format!(
				"Fee Dispute Error: {}, {}",
				tx_fee, fee,
			)));
		}

		let received_with_fee = self.amount.checked_add(self.fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Slate::compare_slates_send, slate amount and fee overflow, amount={} fee={}",
				self.amount, self.fee
			))
		})?;
		if fee > received_with_fee {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(received_with_fee, false)
			);
			info!("{}", reason);
			return Err(Error::Fee(reason));
		}

		Ok(())
	}

	/// Validate every peer-controlled property that can make finalization fail
	/// before the local signing nonce is durably bound to this request. Kernel
	/// signature verification is intentionally excluded: the local partial
	/// signature does not exist yet. Its public key, the transaction balance,
	/// and all range proofs can still be checked without using the nonce.
	pub(crate) fn validate_before_signing(
		&self,
		context_id: u32,
		secp: &mut Secp256k1,
		participant_id: usize,
		local_public_blind: &PublicKey,
		local_public_nonce: &PublicKey,
	) -> Result<(), Error> {
		self.validate_before_signing_inner(
			context_id,
			secp,
			participant_id,
			local_public_blind,
			local_public_nonce,
			false,
		)
	}

	/// Invoice responses require the same pre-sign validation. Compact transport
	/// intentionally omits the issuer output and rangeproof, but its aggregate
	/// commitment can be reconstructed from the invoiced amount and issuer public
	/// blind for the kernel-sum check. The concrete output structure and proofs
	/// remain unavailable to the payer; the issuer restores and validates them at
	/// finalization.
	pub(crate) fn validate_invoice_before_signing(
		&self,
		context_id: u32,
		secp: &mut Secp256k1,
		participant_id: usize,
		local_public_blind: &PublicKey,
		local_public_nonce: &PublicKey,
		compact_invoice_output_omitted: bool,
	) -> Result<(), Error> {
		self.validate_before_signing_inner(
			context_id,
			secp,
			participant_id,
			local_public_blind,
			local_public_nonce,
			compact_invoice_output_omitted,
		)
	}

	fn validate_before_signing_inner(
		&self,
		context_id: u32,
		secp: &mut Secp256k1,
		participant_id: usize,
		local_public_blind: &PublicKey,
		local_public_nonce: &PublicKey,
		compact_invoice_output_omitted: bool,
	) -> Result<(), Error> {
		self.check_unique_participant_ids()?;
		let participant_id = u64::try_from(participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"Slate::validate_before_signing, participant id does not fit u64, participant_id={} error={}",
				participant_id, e
			))
		})?;
		let local_participant = self
			.participant_data
			.iter()
			.find(|participant| participant.id == participant_id)
			.ok_or_else(|| {
				Error::SlateValidation(format!(
					"Slate::validate_before_signing, local participant is missing, participant_id={}",
					participant_id
				))
			})?;
		if local_participant.public_blind_excess != *local_public_blind
			|| local_participant.public_nonce != *local_public_nonce
		{
			return Err(Error::SlateValidation(
				"Slate::validate_before_signing, local participant does not match signing keys"
					.to_string(),
			));
		}

		self.validate_transaction_read(context_id)?;
		self.check_fees(context_id)?;
		let tx = self.tx_or_err()?;
		if tx.kernels().len() != 1 {
			return Err(Error::SlateValidation(format!(
				"Slate::validate_before_signing, expected exactly one transaction kernel, kernel_count={}",
				tx.kernels().len()
			)));
		}
		let kernel = *tx.kernels().first().ok_or_else(|| {
			Error::SlateValidation(
				"Slate::validate_before_signing, transaction kernel is missing".to_string(),
			)
		})?;
		let expected_kernel_features = self.kernel_features()?;
		if kernel.features != expected_kernel_features {
			return Err(Error::SlateValidation(format!(
				"Slate::validate_before_signing, transaction kernel features do not match slate, actual={:?} expected={:?}",
				kernel.features, expected_kernel_features
			)));
		}

		// The aggregate participant key must be the actual transaction excess.
		// Check this through the consensus kernel-sum equation before signing.
		let mut preflight_kernel = kernel;
		preflight_kernel.excess = Commitment::from_pubkey(secp, &self.pub_blind_sum(secp)?)?;
		let mut preflight_tx = tx.clone().replace_kernel(preflight_kernel);
		if compact_invoice_output_omitted {
			let issuer = self
				.participant_data
				.iter()
				.find(|participant| participant.id == 0)
				.ok_or_else(|| {
					Error::SlateValidation(
						"Slate::validate_before_signing, compact invoice issuer is missing"
							.to_owned(),
					)
				})?;
			let issuer_blind = Commitment::from_pubkey(secp, &issuer.public_blind_excess)?;
			let issuer_value = secp.commit_value(self.amount)?;
			let issuer_output_sum =
				secp.commit_sum(vec![issuer_blind, issuer_value], Vec::new())?;
			// This synthetic output exists only in the preflight clone. Its zero
			// proof is never verified or returned; the real compact proof is absent.
			preflight_tx = preflight_tx.with_output(
				context_id,
				Output::new(OutputFeatures::Plain, issuer_output_sum, RangeProof::zero()),
			)?;
			// Include the reconstructed aggregate output in the weight and minimum
			// fee checks as well as the balance equation.
			preflight_tx.validate_read(context_id)?;
			let mut preflight_slate = self.clone();
			preflight_slate.tx = Some(preflight_tx.clone());
			preflight_slate.check_fees(context_id)?;
		}
		preflight_tx.verify_kernel_sums(
			preflight_tx.overage()?,
			preflight_tx.offset.clone(),
			secp,
		)?;

		// Full transaction validation after signing performs the same expensive
		// proof check. Doing it here prevents an invalid proof from pinning the
		// nonce to an otherwise valid aggregate signing challenge.
		if !tx.outputs().is_empty() {
			let commits = tx
				.outputs()
				.iter()
				.map(Output::commitment)
				.collect::<Vec<_>>();
			let proofs = tx.outputs().iter().map(Output::proof).collect::<Vec<_>>();
			Output::batch_verify_proofs(&commits, &proofs, secp)?;
		}

		Ok(())
	}

	/// Verifies all of the partial signatures in the Slate are valid
	pub(crate) fn verify_part_sigs(&self, context_id: u32, secp: &Secp256k1) -> Result<(), Error> {
		if !self.participant_data.iter().any(|p| p.is_complete()) {
			return Ok(());
		}
		// The aggregate nonce, blind sum and message are the same for every
		// participant; compute them once instead of per partial signature.
		let pub_nonce_sum = self.pub_nonce_sum(secp)?;
		let pub_blind_sum = self.pub_blind_sum(secp)?;
		let msg = self.msg_to_sign(context_id)?;
		// collect public nonces
		for p in self.participant_data.iter() {
			if p.is_complete() {
				aggsig::verify_partial_sig(
					secp,
					p.part_sig.as_ref().ok_or(Error::GenericError(
						"at complete slate the part_sig is empty".into(),
					))?,
					&pub_nonce_sum,
					&p.public_nonce,
					&p.public_blind_excess,
					&pub_blind_sum,
					&msg,
				)?;
			}
		}
		Ok(())
	}

	/// Verifies any messages in the slate's participant data match their signatures
	pub fn verify_messages(&self, secp: &Secp256k1) -> Result<(), Error> {
		self.check_participant_message_lengths()?;
		// Only the two-party flow is implemented, so no valid slate carries
		// more participant records. Reject them before the verification loop:
		// every record can carry a valid attacker-generated signature, which
		// would make the loop cost proportional to the attacker-controlled
		// record count.
		if self.participant_data.len() > MAX_SEND_PARTICIPANTS {
			return Err(Error::SlateValidation(format!(
				"too many participant records, actual={} maximum={}",
				self.participant_data.len(),
				MAX_SEND_PARTICIPANTS
			)));
		}
		for p in self.participant_data.iter() {
			p.verify_message(secp)?;
		}
		Ok(())
	}

	/// This should be callable by either the sender or receiver
	/// once phase 3 is done
	///
	/// Receive Part 3 of interactive transactions from sender, Sender
	/// Confirmation Return Ok/Error
	/// -Receiver receives sS
	/// -Receiver verifies sender's sig, by verifying that
	/// kS * G + e *xS * G = sS* G
	/// -Receiver calculates final sig as s=(sS+sR, kS * G+kR * G)
	/// -Receiver puts into TX kernel:
	///
	/// Signature S
	/// pubkey xR * G+xS * G
	/// fee (= M)PaymentInfoV3
	///
	/// Returns completed transaction ready for posting to the chain

	pub fn finalize_signature(
		&mut self,
		context_id: u32,
		secp: &Secp256k1,
	) -> Result<AggSigSignature, Error> {
		// Finalization must fail closed if any declared participant has not
		// completed round 2. In particular, do not silently omit absent shares:
		// malformed public-key and nonce contributions can cancel in the sums.
		let part_sigs = self.part_sigs()?;
		self.verify_part_sigs(context_id, secp)?;

		let pub_nonce_sum = self.pub_nonce_sum(secp)?;
		let final_pubkey = self.pub_blind_sum(secp)?;
		// get the final signature
		let final_sig = aggsig::add_signatures(secp, part_sigs.iter().collect(), &pub_nonce_sum)?;

		// Calculate the final public key (for our own sanity check)

		// Check our final sig verifies
		aggsig::verify_completed_sig(
			secp,
			&final_sig,
			&final_pubkey,
			&final_pubkey,
			&self.msg_to_sign(context_id)?,
		)?;

		Ok(final_sig)
	}

	/// return the final excess
	pub fn calc_excess(&self, secp: &Secp256k1) -> Result<Commitment, Error> {
		if self.compact_slate {
			let sum = self.pub_blind_sum(secp)?;
			Ok(Commitment::from_pubkey(secp, &sum)?)
		} else {
			// Legacy method
			let tx = self.tx_or_err()?.clone();
			let kernel_offset = tx.offset.clone();
			let mut output_commits = tx.outputs_committed()?.collect::<Result<Vec<_>, _>>()?;
			output_commits.push(secp.commit_value(tx.fee()?)?);
			let input_commits = tx.inputs_committed()?.collect::<Result<Vec<_>, _>>()?;
			let tx_excess = secp.commit_sum(output_commits, input_commits)?;

			// subtract the kernel_excess (built from kernel_offset)
			if kernel_offset == BlindingFactor::zero() {
				Ok(tx_excess)
			} else {
				let offset_skey = kernel_offset.secret_key(secp)?;
				let offset_pubkey = PublicKey::from_secret_key(secp, &offset_skey)?;
				let offset_excess = Commitment::from_pubkey(secp, &offset_pubkey)?;
				Ok(secp.commit_sum(vec![tx_excess], vec![offset_excess])?)
			}
		}
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_transaction(
		&mut self,
		context_id: u32,
		secp: &mut Secp256k1,
		final_sig: &secp::AggSigSignature,
	) -> Result<(), Error> {
		self.check_fees(context_id)?;
		// build the final excess based on final tx and offset
		let final_excess = self.calc_excess(secp)?;

		debug!("Final Tx excess: {:?}", final_excess);

		let final_tx = self.tx_or_err()?;

		// update the tx kernel to reflect the offset excess and sig
		if final_tx.kernels().len() != 1 {
			return Err(Error::SlateValidation(format!(
				"Slate::finalize_transaction, expected exactly one transaction kernel, kernel_count={}",
				final_tx.kernels().len()
			)));
		}
		let mut kernel = *final_tx.kernels().first().ok_or_else(|| {
			Error::SlateValidation(
				"Slate::finalize_transaction, transaction kernel is missing".to_string(),
			)
		})?;
		kernel.excess = final_excess;
		kernel.excess_sig = final_sig.clone();

		let final_tx = final_tx.clone().replace_kernel(kernel);

		// confirm the kernel verifies successfully before proceeding
		debug!(
			"Validating final transaction. Inputs: {}  Outputs: {}",
			final_tx.body.inputs.len(),
			final_tx.body.outputs.len()
		);
		final_tx.kernels()[0].verify(context_id, secp)?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		final_tx.validate(context_id, Weighting::AsTransaction, secp)?;

		// replace our slate tx with the new one with updated kernel
		self.tx = Some(final_tx);

		Ok(())
	}
}

impl Serialize for SlateCtx {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

		let v3 = SlateV3::from(self);
		match self.slate.version_info.version {
			3 => v3.serialize(serializer),
			// left as a reminder
			2 => {
				let v2 = match SlateV2::try_from(&v3) {
					Ok(s) => s,
					Err(e) => return Err(S::Error::custom(format!("{}", e))),
				};
				v2.serialize(serializer)
			}
			v => Err(S::Error::custom(format!("Unknown slate version {}", v))),
		}
	}
}

impl<'de> Deserialize<'de> for SlateCtx {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = VersionedSlate::deserialize(deserializer)?;
		// Swaps are not using the slatepacks.

		match s {
			VersionedSlate::SP(_) => {
				return Err(serde::de::Error::custom("Slate is encrypted".to_string()));
			}
			VersionedSlate::V3(s) => Ok(SlateCtx {
				network_name: s.network_type.clone(),
				slate: s
					.clone()
					.to_slate(None, true)
					.map_err(|e| serde::de::Error::custom(format!("Slate parsing error, {}", e)))?,
			}),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s.clone());

				Ok(SlateCtx {
					network_name: s.network_type.clone(),
					slate: s.to_slate(None, false).map_err(|e| {
						serde::de::Error::custom(format!("Slate parsing error, {}", e))
					})?,
				})
			}
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct SlateVersionProbe {
	#[serde(default)]
	version: Option<u64>,
	#[serde(default)]
	version_info: Option<VersionCompatInfo>,
}

impl SlateVersionProbe {
	pub fn version(&self) -> u16 {
		match &self.version_info {
			Some(v) => v.version,
			None => match self.version {
				Some(_) => 1,
				None => 0,
			},
		}
	}
}

// Current slate version to versioned conversions
impl From<&SlateCtx> for SlateV3 {
	fn from(slate_with_ctx: &SlateCtx) -> SlateV3 {
		let Slate {
			compact_slate,
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
			offset: tx_offset,
			kernel_features,
		} = &slate_with_ctx.slate;
		let num_participants = *num_participants;
		let id = *id;
		let amount = *amount;
		let fee = *fee;
		let height = *height;
		let lock_height = *lock_height;
		let ttl_cutoff_height = *ttl_cutoff_height;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(p)),
			None => None,
		};
		let tx = match tx {
			Some(t) => {
				let mut t = TransactionV3::from(t);
				if *compact_slate {
					// for compact the Slate offset is dominate
					t.offset = tx_offset.clone();
				}
				Some(t)
			}
			None => None,
		};

		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			coin_type: Some("mwc".to_string()),
			network_type: slate_with_ctx.network_name.clone(),
			participant_data,
			version_info,
			payment_proof,
			compact_slate: if *compact_slate { Some(true) } else { None },
			kernel_features: *kernel_features,
		}
	}
}

impl From<&ParticipantData> for ParticipantDataV3 {
	fn from(data: &ParticipantData) -> ParticipantDataV3 {
		let ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfo> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfo) -> VersionCompatInfoV3 {
		let VersionCompatInfo {
			version,
			block_header_version,
		} = data;
		let version = *version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version: version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfo> for PaymentInfoV3 {
	fn from(data: &PaymentInfo) -> PaymentInfoV3 {
		let PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		} = data;
		let sender_address = sender_address.clone();
		let receiver_address = receiver_address.clone();
		let receiver_signature = receiver_signature.clone();
		PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

impl From<Transaction> for TransactionV3 {
	fn from(tx: Transaction) -> TransactionV3 {
		let Transaction { offset, body } = tx;
		let body = TransactionBodyV3::from(&body);
		TransactionV3 { offset, body }
	}
}

impl From<&Transaction> for TransactionV3 {
	fn from(tx: &Transaction) -> TransactionV3 {
		let Transaction { offset, body } = tx;
		let offset = offset.clone();
		let body = TransactionBodyV3::from(body);
		TransactionV3 { offset, body }
	}
}

impl From<&TransactionBody> for TransactionBodyV3 {
	fn from(body: &TransactionBody) -> TransactionBodyV3 {
		let TransactionBody {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = match inputs {
			Inputs::CommitOnly(commits) => {
				// TransactionV3 requires a feature for every input, but older stored
				// transactions and compact slates can legitimately retain commitments
				// only. The original feature cannot be recovered reliably: these inputs
				// are normally already spent and therefore absent from the node's UTXO
				// response, while wallet history is not authoritative consensus data.
				// Rejecting every such conversion would break otherwise usable legacy
				// records, and a node lookup would make conversion state-dependent without
				// making it reliable. Plain is therefore the deterministic best-effort
				// placeholder; it is not recovered input metadata. Direct reposting uses
				// the original core Transaction and bypasses this conversion.
				map_vec!(commits, |commit| InputV3 {
					features: OutputFeatures::Plain,
					commit: commit.commitment(),
				})
			}
			Inputs::FeaturesAndCommit(inputs) => map_vec!(inputs, |inp| InputV3 {
				features: inp.features,
				commit: inp.commit,
			}),
		};

		let outputs = map_vec!(outputs, |out| OutputV3::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV3::from(kern));
		TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&Input> for InputV3 {
	fn from(input: &Input) -> InputV3 {
		let Input { features, commit } = *input;
		InputV3 { features, commit }
	}
}

impl From<&Output> for OutputV3 {
	fn from(output: &Output) -> OutputV3 {
		let Output {
			identifier: OutputIdentifier { features, commit },
			proof,
		} = *output;
		OutputV3 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernel> for TxKernelV3 {
	fn from(kernel: &TxKernel) -> TxKernelV3 {
		let (features, fee, lock_height) = match kernel.features {
			KernelFeatures::Plain { fee } => (CompatKernelFeatures::Plain, fee, 0),
			KernelFeatures::Coinbase => (CompatKernelFeatures::Coinbase, FeeFields::zero(), 0),
			KernelFeatures::HeightLocked { fee, lock_height } => {
				(CompatKernelFeatures::HeightLocked, fee, lock_height)
			}
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => (
				CompatKernelFeatures::NoRecentDuplicate,
				fee,
				relative_height.into(),
			),
		};
		TxKernelV3 {
			features,
			fee: fee.into(),
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

impl From<&ParticipantDataV3> for ParticipantData {
	fn from(data: &ParticipantDataV3) -> ParticipantData {
		let ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfo {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfo {
		let VersionCompatInfoV3 {
			version,
			orig_version: _,
			block_header_version,
		} = data;
		let version = *version;
		let block_header_version = *block_header_version;
		VersionCompatInfo {
			version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfoV3> for PaymentInfo {
	fn from(data: &PaymentInfoV3) -> PaymentInfo {
		let PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		} = data;
		let sender_address = sender_address.clone();
		let receiver_address = receiver_address.clone();
		let receiver_signature = receiver_signature.clone();
		PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

impl TryFrom<TransactionV3> for Transaction {
	type Error = Error;
	fn try_from(tx: TransactionV3) -> Result<Transaction, Error> {
		let TransactionV3 { offset, body } = tx;
		let body = TransactionBody::try_from(&body)?;
		Ok(Transaction { offset, body })
	}
}

impl TryFrom<&TransactionBodyV3> for TransactionBody {
	type Error = Error;
	fn try_from(body: &TransactionBodyV3) -> Result<TransactionBody, Error> {
		let TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = Inputs::FeaturesAndCommit(map_vec!(inputs, |inp| Input::from(inp)));
		let outputs = map_vec!(outputs, |out| Output::from(out));
		let mut kernels_tx: Vec<TxKernel> = Vec::new();
		for kern in kernels {
			kernels_tx.push(TxKernel::try_from(kern)?);
		}
		Ok(TransactionBody {
			inputs,
			outputs,
			kernels: kernels_tx,
		})
	}
}

impl From<&InputV3> for Input {
	fn from(input: &InputV3) -> Input {
		let InputV3 { features, commit } = *input;
		Input { features, commit }
	}
}

impl From<&OutputV3> for Output {
	fn from(output: &OutputV3) -> Output {
		let OutputV3 {
			features,
			commit,
			proof,
		} = *output;
		Output {
			identifier: OutputIdentifier { features, commit },
			proof,
		}
	}
}

impl TryFrom<&TxKernelV3> for TxKernel {
	type Error = Error;

	fn try_from(kernel: &TxKernelV3) -> Result<TxKernel, Error> {
		let (fee, lock_height) = (kernel.fee, kernel.lock_height);
		let fee = if fee == 0 {
			FeeFields::zero()
		} else {
			FeeFields::try_from(fee).map_err(|e| {
				Error::DataOverflow(format!(
					"TxKernel::try_from, fee does not fit FeeFields, fee={} error={}",
					fee, e
				))
			})?
		};

		let features = match kernel.features {
			CompatKernelFeatures::Plain => KernelFeatures::Plain { fee },
			CompatKernelFeatures::Coinbase => KernelFeatures::Coinbase,
			CompatKernelFeatures::HeightLocked => KernelFeatures::HeightLocked { fee, lock_height },
			CompatKernelFeatures::NoRecentDuplicate => KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height: NRDRelativeHeight::new(lock_height)?,
			},
		};
		Ok(TxKernel {
			features,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		})
	}
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum CompatKernelFeatures {
	Plain,
	Coinbase,
	HeightLocked,
	NoRecentDuplicate,
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_core::core::transaction::CommitWrapper;
	use mwc_wallet_util::mwc_core::core::transaction::OutputFeatures;
	use mwc_wallet_util::mwc_keychain::Identifier;

	fn test_secp() -> Secp256k1 {
		Secp256k1::with_caps(ContextFlag::Commit).unwrap()
	}

	#[test]
	fn participant_message_display_escapes_terminal_controls() {
		let secp = test_secp();
		let secret_key = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
		let participant = ParticipantMessageData {
			id: 0,
			public_key: PublicKey::from_secret_key(&secp, &secret_key).unwrap(),
			message: Some("before\n\u{1b}]52;c;payload\u{7}after".to_owned()),
			message_sig: None,
		};

		let rendered = participant.to_string();
		assert!(rendered.contains("Message: before\\u000a\\u001b]52;c;payload\\u0007after"));
		assert!(!rendered.contains('\u{1b}'));
		assert!(!rendered.contains('\u{7}'));
	}

	fn test_context(secp: &Secp256k1, compact_slate: bool) -> Context {
		let sec_key = SecretKey::from_slice(secp, &[1u8; 32]).unwrap();
		let sec_nonce = SecretKey::from_slice(secp, &[2u8; 32]).unwrap();
		Context {
			parent_key_id: Identifier::zero(),
			sec_key: sec_key.clone(),
			sec_nonce: sec_nonce.clone(),
			initial_sec_key: sec_key,
			initial_sec_nonce: sec_nonce,
			output_ids: vec![],
			output_build_heights: vec![],
			input_ids: vec![],
			amount: 100_000_000,
			fee: 1_000_000,
			participant_id: 0,
			payment_proof_derivation_index: None,
			payment_proof_recipient_address: None,
			output_commits: vec![],
			input_commits: vec![],
			late_lock_args: None,
			calculated_excess: None,
			message: None,
			lock_height: 0,
			kernel_features: 0,
			ttl_cutoff_height: None,
			compact_slate,
			aggsig_challenge: None,
			context_version: crate::types::CURRENT_CONTEXT_VERSION,
		}
	}

	#[test]
	fn lowest_version_never_selects_an_invalid_v2_downgrade() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut slate = Slate::blank(2, false).unwrap();
		assert_eq!(slate.lowest_version(), SlateVersion::V2);
		assert!(matches!(
			VersionedSlate::into_version_plain(0, &slate, slate.lowest_version()).unwrap(),
			VersionedSlate::V2(_)
		));

		// Height-locked kernels are representable in V2.
		slate.kernel_features = 2;
		assert_eq!(slate.lowest_version(), SlateVersion::V2);
		assert!(matches!(
			VersionedSlate::into_version_plain(0, &slate, slate.lowest_version()).unwrap(),
			VersionedSlate::V2(_)
		));

		// NRD is V3-only. Selecting V2 here used to make MQS response
		// publication fail deterministically after receive processing.
		slate.kernel_features = 3;
		assert_eq!(slate.lowest_version(), SlateVersion::V3);
		assert!(matches!(
			VersionedSlate::into_version_plain(0, &slate, slate.lowest_version()).unwrap(),
			VersionedSlate::V3(_)
		));

		// A Slate without the full transaction also cannot be represented in V2.
		slate.kernel_features = 0;
		slate.tx = None;
		assert_eq!(slate.lowest_version(), SlateVersion::V3);
	}

	fn initiator_from_context(secp: &Secp256k1, context: &Context) -> ParticipantData {
		let public_blind_excess = PublicKey::from_secret_key(secp, &context.sec_key).unwrap();
		let message_sig = context.message.as_ref().map(|message| {
			let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], message.as_bytes());
			let message_hash = secp::Message::from_slice(hashed.as_bytes()).unwrap();
			aggsig::sign_single(
				secp,
				&message_hash,
				&context.sec_key,
				None,
				&public_blind_excess,
			)
			.unwrap()
		});
		ParticipantData {
			id: 0,
			public_blind_excess,
			public_nonce: PublicKey::from_secret_key(secp, &context.sec_nonce).unwrap(),
			part_sig: None,
			message: context.message.clone(),
			message_sig,
		}
	}

	fn responder(secp: &Secp256k1, complete: bool) -> ParticipantData {
		let sec_key = SecretKey::from_slice(secp, &[3u8; 32]).unwrap();
		let sec_nonce = SecretKey::from_slice(secp, &[4u8; 32]).unwrap();
		let part_sig = if complete {
			let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &[]);
			let msg = secp::Message::from_slice(&hashed.as_bytes()).unwrap();
			let pub_key = PublicKey::from_secret_key(secp, &sec_key).unwrap();
			Some(aggsig::sign_single(secp, &msg, &sec_key, None, &pub_key).unwrap())
		} else {
			None
		};
		ParticipantData {
			id: 1,
			public_blind_excess: PublicKey::from_secret_key(secp, &sec_key).unwrap(),
			public_nonce: PublicKey::from_secret_key(secp, &sec_nonce).unwrap(),
			part_sig,
			message: None,
			message_sig: None,
		}
	}

	fn response_slate(secp: &Secp256k1, context: &Context, compact_slate: bool) -> Slate {
		let mut slate = Slate::blank(2, compact_slate).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(secp, context));
		slate.participant_data.push(responder(secp, true));
		slate
	}

	fn participant_from_secrets(
		secp: &Secp256k1,
		id: u64,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
	) -> ParticipantData {
		ParticipantData {
			id,
			public_blind_excess: PublicKey::from_secret_key(secp, sec_key).unwrap(),
			public_nonce: PublicKey::from_secret_key(secp, sec_nonce).unwrap(),
			part_sig: None,
			message: None,
			message_sig: None,
		}
	}

	#[test]
	fn finalize_signature_rejects_fewer_records_than_declared() {
		let secp = test_secp();
		let sec_key = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
		let sec_nonce = SecretKey::from_slice(&secp, &[2u8; 32]).unwrap();
		let mut slate = Slate::blank(2, false).unwrap();
		slate.fee = 1;
		slate
			.participant_data
			.push(participant_from_secrets(&secp, 0, &sec_key, &sec_nonce));

		let pub_nonce_sum = slate.pub_nonce_sum(&secp).unwrap();
		let pub_blind_sum = slate.pub_blind_sum(&secp).unwrap();
		let msg = slate.msg_to_sign(0).unwrap();
		slate.participant_data[0].part_sig = Some(
			aggsig::calculate_partial_sig(
				&secp,
				&sec_key,
				&sec_nonce,
				&pub_nonce_sum,
				&pub_blind_sum,
				&msg,
			)
			.unwrap(),
		);

		assert!(matches!(
			slate.finalize_signature(0, &secp),
			Err(Error::SlateValidation(message))
				if message.contains("participant count does not match declaration")
		));
	}

	#[test]
	fn finalize_signature_rejects_missing_canceling_shares() {
		let secp = test_secp();
		let signer_key = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
		let signer_nonce = SecretKey::from_slice(&secp, &[2u8; 32]).unwrap();
		let canceling_key = SecretKey::from_slice(&secp, &[3u8; 32]).unwrap();
		let canceling_nonce = SecretKey::from_slice(&secp, &[4u8; 32]).unwrap();
		let mut inverse_key = canceling_key.clone();
		inverse_key.neg_assign(&secp).unwrap();
		let mut inverse_nonce = canceling_nonce.clone();
		inverse_nonce.neg_assign(&secp).unwrap();

		let mut slate = Slate::blank(3, false).unwrap();
		slate.fee = 1;
		slate.participant_data = vec![
			participant_from_secrets(&secp, 0, &signer_key, &signer_nonce),
			participant_from_secrets(&secp, 1, &canceling_key, &canceling_nonce),
			participant_from_secrets(&secp, 2, &inverse_key, &inverse_nonce),
		];

		let pub_nonce_sum = slate.pub_nonce_sum(&secp).unwrap();
		let pub_blind_sum = slate.pub_blind_sum(&secp).unwrap();
		let msg = slate.msg_to_sign(0).unwrap();
		slate.participant_data[0].part_sig = Some(
			aggsig::calculate_partial_sig(
				&secp,
				&signer_key,
				&signer_nonce,
				&pub_nonce_sum,
				&pub_blind_sum,
				&msg,
			)
			.unwrap(),
		);

		assert!(matches!(
			slate.finalize_signature(0, &secp),
			Err(Error::SlateValidation(message))
				if message.contains("participant signature is missing")
		));
	}

	#[test]
	fn validate_send_response_context_accepts_valid_response() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let slate = response_slate(&secp, &context, false);
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_ok());
	}

	#[test]
	fn validate_send_response_context_rejects_stripped_initiator_message() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.message = Some("sender terms".to_owned());
		let mut slate = response_slate(&secp, &context, false);
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_ok());

		// Deleting both fields bypassed verify_messages before the context
		// message was explicitly bound to the returned participant record.
		slate.participant_data[0].message = None;
		slate.participant_data[0].message_sig = None;
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_accepts_compact_without_initiator() {
		let secp = test_secp();
		let context = test_context(&secp, true);
		let mut slate = Slate::blank(2, true).unwrap();
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_ok());
	}

	#[test]
	fn validate_send_response_context_rejects_wrong_declaration() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		slate.num_participants = 3;
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_excess_records() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		let mut extra = responder(&secp, true);
		extra.id = 2;
		slate.participant_data.push(extra);
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_duplicate_ids() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate.participant_data.push(responder(&secp, true));
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_unexpected_id() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		let mut unexpected = responder(&secp, true);
		unexpected.id = 5;
		slate.participant_data.push(unexpected);
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_missing_responder() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(&secp, &context));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_missing_noncompact_initiator() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_incomplete_responder() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(&secp, &context));
		slate.participant_data.push(responder(&secp, false));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_altered_initiator() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		let rogue_key = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		slate.participant_data[0].public_nonce =
			PublicKey::from_secret_key(&secp, &rogue_key).unwrap();
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_send_response_context_rejects_oversized_message() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		slate.participant_data[1].message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1));
		assert!(slate
			.validate_send_response_context(&secp, &context)
			.is_err());
	}

	fn initial_invoice_slate_from_context(secp: &Secp256k1, context: &Context) -> Slate {
		let mut slate = Slate::blank(2, context.compact_slate).unwrap();
		slate.amount = context.amount;
		slate.fee = context.fee;
		slate.ttl_cutoff_height = context.ttl_cutoff_height;
		slate
			.participant_data
			.push(initiator_from_context(secp, context));
		slate
	}

	fn initial_invoice_slate(secp: &Secp256k1) -> Slate {
		initial_invoice_slate_from_context(secp, &test_context(secp, false))
	}

	/// The payer's response slate and the issuer-finalized response for it:
	/// the same slate with the issuer record (id 0) completed by its partial
	/// signature.
	fn invoice_exchange_slates(secp: &Secp256k1) -> (Slate, Slate) {
		let mut sent = Slate::blank(2, false).unwrap();
		let mut issuer = responder(secp, false);
		issuer.id = 0;
		sent.participant_data.push(issuer);
		sent.participant_data.push(responder(secp, true));
		let mut returned = sent.clone();
		let mut signed_issuer = responder(secp, true);
		signed_issuer.id = 0;
		returned.participant_data[0] = signed_issuer;
		(sent, returned)
	}

	#[test]
	fn validate_invoice_initial_accepts_valid_invoice() {
		let secp = test_secp();
		assert!(initial_invoice_slate(&secp)
			.validate_invoice_initial()
			.is_ok());
	}

	#[test]
	fn validate_invoice_initial_context_accepts_original_invoice() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let slate = initial_invoice_slate_from_context(&secp, &context);
		assert!(slate
			.validate_invoice_initial_context(&secp, &context)
			.is_ok());
	}

	#[test]
	fn validate_invoice_initial_context_rejects_altered_issuer_nonce() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = initial_invoice_slate_from_context(&secp, &context);
		let rogue_nonce = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		slate.participant_data[0].public_nonce =
			PublicKey::from_secret_key(&secp, &rogue_nonce).unwrap();
		assert!(slate
			.validate_invoice_initial_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_initial_context_rejects_removed_issuer_message() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.message = Some("invoice terms".to_owned());
		let mut slate = initial_invoice_slate_from_context(&secp, &context);
		// Removing both fields still passes standalone message verification, so
		// the saved context must bind the original text as well.
		slate.participant_data[0].message = None;
		slate.participant_data[0].message_sig = None;
		assert!(slate.verify_messages(&secp).is_ok());
		assert!(slate
			.validate_invoice_initial_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_initial_context_rejects_altered_metadata() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = initial_invoice_slate_from_context(&secp, &context);
		slate.amount += 1;
		assert!(slate
			.validate_invoice_initial_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_wrong_declaration() {
		let secp = test_secp();
		let mut slate = initial_invoice_slate(&secp);
		slate.num_participants = 3;
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_missing_issuer() {
		let slate = Slate::blank(2, false).unwrap();
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_non_issuer_record() {
		let secp = test_secp();
		let mut slate = Slate::blank(2, false).unwrap();
		slate.participant_data.push(responder(&secp, true));
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_extra_participant() {
		let secp = test_secp();
		let mut slate = initial_invoice_slate(&secp);
		slate.participant_data.push(responder(&secp, true));
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_oversized_message() {
		let secp = test_secp();
		let mut slate = initial_invoice_slate(&secp);
		slate.participant_data[0].message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1));
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_initial_rejects_non_plain_kernel_policy() {
		let secp = test_secp();
		// HeightLocked kernel: the payer's partial signature would commit to a
		// policy its Context does not record, and the mismatch would only be
		// detected after the signed slate was sent to the issuer.
		let mut slate = initial_invoice_slate(&secp);
		slate.set_lock_height_no_check(100);
		assert!(slate.validate_invoice_initial().is_err());
		// NRD kernel policy.
		let mut slate = initial_invoice_slate(&secp);
		slate.kernel_features = 3;
		slate.lock_height = 1440;
		assert!(slate.validate_invoice_initial().is_err());
	}

	#[test]
	fn validate_invoice_response_accepts_valid_response() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		assert!(sent.validate_invoice_response(&mut returned).is_ok());
	}

	#[test]
	fn validate_invoice_response_accepts_compact_without_payer_record() {
		let secp = test_secp();
		let (mut sent, mut returned) = invoice_exchange_slates(&secp);
		sent.compact_slate = true;
		returned.compact_slate = true;
		returned.participant_data.remove(1);
		assert!(sent.validate_invoice_response(&mut returned).is_ok());
	}

	#[test]
	fn validate_invoice_response_rejects_uuid_mismatch() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.id = Slate::blank(2, false).unwrap().id;
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_compact_flag_mismatch() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.compact_slate = !sent.compact_slate;
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_wrong_declaration() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.num_participants = 3;
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_excess_records() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		let mut extra = responder(&secp, true);
		extra.id = 2;
		returned.participant_data.push(extra);
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_duplicate_ids() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data[1] = returned.participant_data[0].clone();
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_unexpected_id() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data[1].id = 5;
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_altered_payer() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		let rogue_key = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		returned.participant_data[1].public_nonce =
			PublicKey::from_secret_key(&secp, &rogue_key).unwrap();
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_missing_issuer() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data.remove(0);
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_incomplete_issuer() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data[0].part_sig = None;
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_oversized_message() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data[0].message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1));
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_missing_payer_noncompact() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		returned.participant_data.remove(1);
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_altered_issuer_message() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		// The transaction signature does not commit participant messages and
		// verify_messages skips absent ones, so an injected or erased issuer
		// message must be caught by the sent-slate comparison.
		returned.participant_data[0].message = Some("rewritten invoice terms".to_string());
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_rejects_altered_issuer_nonce() {
		let secp = test_secp();
		let (sent, mut returned) = invoice_exchange_slates(&secp);
		let rogue_key = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		returned.participant_data[0].public_nonce =
			PublicKey::from_secret_key(&secp, &rogue_key).unwrap();
		assert!(sent.validate_invoice_response(&mut returned).is_err());
	}

	#[test]
	fn validate_invoice_response_merges_payer_record_for_compact() {
		let secp = test_secp();
		let (mut sent, mut returned) = invoice_exchange_slates(&secp);
		sent.compact_slate = true;
		returned.compact_slate = true;
		let sent_payer = sent.participant_data[1].clone();
		returned.participant_data.remove(1);
		assert!(sent.validate_invoice_response(&mut returned).is_ok());
		// The locally retained payer record is reattached so the persisted
		// transcript (tx log participant messages) is complete.
		assert_eq!(returned.participant_data.len(), 2);
		assert_eq!(returned.participant_data[1], sent_payer);
	}

	/// An invoice response as the issuer finalizes it: the issuer record
	/// (id 0) bound to the issuer context plus the payer's completed record
	/// (id 1).
	fn invoice_response_slate(secp: &Secp256k1, context: &Context) -> Slate {
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(secp, context));
		slate.participant_data.push(responder(secp, true));
		slate
	}

	#[test]
	fn validate_response_participants_accepts_valid_response() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		assert!(response_slate(&secp, &context, false)
			.validate_response_participants()
			.is_ok());
	}

	#[test]
	fn validate_response_participants_rejects_missing_counterparty() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(&secp, &context));
		assert!(slate.validate_response_participants().is_err());
	}

	#[test]
	fn validate_invoice_response_context_accepts_valid_response() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let slate = invoice_response_slate(&secp, &context);
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_ok());
	}

	#[test]
	fn validate_invoice_response_context_rejects_stripped_issuer_message() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.message = Some("invoice terms".to_owned());
		let mut slate = invoice_response_slate(&secp, &context);
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_ok());

		slate.participant_data[0].message = None;
		slate.participant_data[0].message_sig = None;
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_accepts_compact_without_issuer() {
		let secp = test_secp();
		let context = test_context(&secp, true);
		let mut slate = Slate::blank(2, true).unwrap();
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_ok());
	}

	#[test]
	fn validate_invoice_response_context_rejects_wrong_declaration() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = invoice_response_slate(&secp, &context);
		slate.num_participants = 3;
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_excess_records() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = invoice_response_slate(&secp, &context);
		let mut extra = responder(&secp, true);
		extra.id = 2;
		slate.participant_data.push(extra);
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_duplicate_ids() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate.participant_data.push(responder(&secp, true));
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	/// The payer's validly-signed record relabeled to id 2: the partial
	/// signature still verifies, so the structural check must reject it.
	#[test]
	fn validate_invoice_response_context_rejects_relabeled_payer() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = invoice_response_slate(&secp, &context);
		slate.participant_data.remove(0);
		slate.participant_data[0].id = 2;
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_missing_payer() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(&secp, &context));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_missing_noncompact_issuer() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate.participant_data.push(responder(&secp, true));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_incomplete_payer() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = Slate::blank(2, false).unwrap();
		slate
			.participant_data
			.push(initiator_from_context(&secp, &context));
		slate.participant_data.push(responder(&secp, false));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_altered_issuer() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = invoice_response_slate(&secp, &context);
		let rogue_key = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		slate.participant_data[0].public_nonce =
			PublicKey::from_secret_key(&secp, &rogue_key).unwrap();
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	#[test]
	fn validate_invoice_response_context_rejects_oversized_message() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = invoice_response_slate(&secp, &context);
		slate.participant_data[1].message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1));
		assert!(slate
			.validate_invoice_response_context(&secp, &context)
			.is_err());
	}

	/// No valid flow carries more than two participant records, so message
	/// verification must reject larger sets instead of verifying each one.
	#[test]
	fn verify_messages_rejects_excess_participant_records() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		let mut extra = responder(&secp, true);
		extra.id = 2;
		slate.participant_data.push(extra);
		assert!(slate.verify_messages(&secp).is_err());
	}

	#[test]
	fn verify_messages_rejects_signature_without_message() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.message = Some("signed message".to_owned());
		let mut slate = response_slate(&secp, &context, false);
		slate.participant_data[0].message = None;
		assert!(slate.participant_data[0].message_sig.is_some());
		assert!(slate.verify_messages(&secp).is_err());
	}

	#[test]
	fn standalone_participant_verification_rejects_oversized_message() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN));
		assert!(initiator_from_context(&secp, &context)
			.verify_message(&secp)
			.is_ok());

		context.message = Some("x".repeat(MAX_PARTICIPANT_MESSAGE_LEN + 1));
		let participant = initiator_from_context(&secp, &context);
		assert!(matches!(
			participant.verify_message(&secp),
			Err(Error::SlateValidation(_))
		));
	}

	#[test]
	fn context_nonce_binding_allows_only_the_same_aggregate_challenge() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		let mut slate = response_slate(&secp, &context, false);
		slate.fee = context.fee;
		let first =
			crate::internal::tx::finalizer_aggsig_challenge(0, &secp, &slate, 0, &context).unwrap();
		context.bind_aggsig_challenge(first).unwrap();
		context.bind_aggsig_challenge(first).unwrap();
		assert_eq!(context.aggsig_challenge, Some(first));
		assert_eq!(
			context.context_version,
			crate::types::CURRENT_CONTEXT_VERSION
		);

		let different_nonce = SecretKey::from_slice(&secp, &[9u8; 32]).unwrap();
		slate.participant_data[1].public_nonce =
			PublicKey::from_secret_key(&secp, &different_nonce).unwrap();
		let second =
			crate::internal::tx::finalizer_aggsig_challenge(0, &secp, &slate, 0, &context).unwrap();
		assert_ne!(first, second);
		assert!(context.bind_aggsig_challenge(second).is_err());
	}

	#[test]
	fn context_nonce_binding_rejects_contexts_with_unknown_legacy_nonce_usage() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut value = serde_json::to_value(&context).unwrap();
		value.as_object_mut().unwrap().remove("aggsig_challenge");
		value
			.as_object_mut()
			.unwrap()
			.remove("context_version");
		let mut restored: Context = serde_json::from_value(value).unwrap();
		assert_eq!(restored.aggsig_challenge, None);
		assert_eq!(restored.context_version, 0);

		let challenge = [17u8; 32];
		assert!(matches!(
			restored.bind_aggsig_challenge(challenge),
			Err(Error::SlateValidation(message)) if message.contains("unknown legacy usage")
		));
	}

	#[test]
	fn context_nonce_binding_preserves_fresh_state_across_serialization() {
		let secp = test_secp();
		let context = test_context(&secp, false);
		let mut restored: Context =
			serde_json::from_value(serde_json::to_value(&context).unwrap()).unwrap();
		assert_eq!(
			restored.context_version,
			crate::types::CURRENT_CONTEXT_VERSION
		);

		let challenge = [23u8; 32];
		restored.bind_aggsig_challenge(challenge).unwrap();
		assert_eq!(restored.aggsig_challenge, Some(challenge));
		assert_eq!(
			restored.context_version,
			crate::types::CURRENT_CONTEXT_VERSION
		);
	}

	#[test]
	fn context_nonce_binding_accepts_same_challenge_from_previous_schema() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		let challenge = [31u8; 32];
		context.bind_aggsig_challenge(challenge).unwrap();

		let mut value = serde_json::to_value(&context).unwrap();
		value
			.as_object_mut()
			.unwrap()
			.remove("context_version");
		let mut restored: Context = serde_json::from_value(value).unwrap();
		assert_eq!(restored.context_version, 0);
		restored.bind_aggsig_challenge(challenge).unwrap();
		assert_eq!(restored.aggsig_challenge, Some(challenge));
		assert_eq!(
			restored.context_version,
			crate::types::CURRENT_CONTEXT_VERSION
		);
	}

	#[test]
	fn context_nonce_binding_rejects_unknown_future_context_versions() {
		let secp = test_secp();
		let mut context = test_context(&secp, false);
		context.context_version = crate::types::CURRENT_CONTEXT_VERSION + 1;

		assert!(matches!(
			context.bind_aggsig_challenge([37u8; 32]),
			Err(Error::SlateValidation(message)) if message.contains("newer than supported")
		));
	}

	fn test_commitment(secp: &Secp256k1, key_byte: u8, value: u64) -> Commitment {
		secp.commit(value, SecretKey::from_slice(secp, &[key_byte; 32]).unwrap())
			.unwrap()
	}

	#[test]
	fn transaction_read_validation_rejects_overweight_slate() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = test_secp();
		let mut slate = Slate::blank(2, false).unwrap();
		let input = CommitWrapper::from(test_commitment(&secp, 10, 41));
		let input_count = usize::try_from(global::max_tx_weight(0) + 1).unwrap();
		slate.tx_or_err_mut().unwrap().body.inputs =
			Inputs::CommitOnly(vec![input; input_count]);

		assert!(matches!(
			slate.validate_transaction_read(0),
			Err(Error::Transaction(
				mwc_wallet_util::mwc_core::core::transaction::Error::TooHeavy
			))
		));
	}

	#[test]
	fn transaction_read_validation_rejects_cut_through() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = test_secp();
		let mut slate = Slate::blank(2, false).unwrap();
		let commit = test_commitment(&secp, 10, 41);
		let tx = slate.tx_or_err_mut().unwrap();
		tx.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(commit)]);
		tx.body.outputs.push(Output {
			identifier: OutputIdentifier {
				features: OutputFeatures::Plain,
				commit,
			},
			proof: mwc_wallet_util::mwc_crates::secp::pedersen::RangeProof::zero(),
		});

		assert!(matches!(
			slate.validate_transaction_read(0),
			Err(Error::Transaction(
				mwc_wallet_util::mwc_core::core::transaction::Error::CutThrough
			))
		));
	}

	#[test]
	fn v3_conversion_uses_plain_for_commitment_only_inputs() {
		let secp = test_secp();
		let commit = test_commitment(&secp, 11, 42);
		let mut tx = Transaction::empty();
		tx.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(commit)]);

		let versioned = TransactionV3::from(&tx);
		assert_eq!(versioned.body.inputs.len(), 1);
		assert_eq!(versioned.body.inputs[0].features, OutputFeatures::Plain);
		assert_eq!(versioned.body.inputs[0].commit, commit);
	}

	#[test]
	fn v3_round_trip_preserves_full_input_features() {
		let secp = test_secp();
		let commit = test_commitment(&secp, 12, 43);
		let mut tx = Transaction::empty();
		tx.body.inputs = Inputs::FeaturesAndCommit(vec![Input {
			features: OutputFeatures::Coinbase,
			commit,
		}]);

		let encoded = serde_json::to_value(TransactionV3::from(&tx)).unwrap();
		assert!(encoded["body"]["inputs"][0].is_object());

		let versioned: TransactionV3 = serde_json::from_value(encoded).unwrap();
		let restored = Transaction::try_from(versioned).unwrap();
		match restored.body.inputs {
			Inputs::FeaturesAndCommit(inputs) => {
				assert_eq!(inputs.len(), 1);
				assert_eq!(inputs[0].features, OutputFeatures::Coinbase);
				assert_eq!(inputs[0].commit, commit);
			}
			Inputs::CommitOnly(_) => panic!("full input lost its output features"),
		}
	}

	#[test]
	fn v3_round_trip_preserves_nrd_relative_height() {
		let relative_height = NRDRelativeHeight::new(1_440).unwrap();
		let mut kernel = TxKernel::empty().unwrap();
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: FeeFields::new(2).unwrap(),
			relative_height,
		};

		let versioned = TxKernelV3::from(&kernel);
		assert_eq!(versioned.lock_height, 1_440);
		let restored = TxKernel::try_from(&versioned).unwrap();
		match restored.features {
			KernelFeatures::NoRecentDuplicate {
				relative_height: restored_height,
				..
			} => assert_eq!(u64::from(restored_height), 1_440),
			other => panic!("expected NRD kernel, got {:?}", other),
		}
	}
}
