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

use crate::blake2::blake2b::blake2b;
use crate::error::Error;
use crate::mwc_core::core::amount_to_hr_string;
use crate::mwc_core::core::committed::Committed;
use crate::mwc_core::core::transaction::{
	Input, KernelFeatures, Output, OutputFeatures, Transaction, TransactionBody, TxKernel,
	Weighting,
};
use crate::mwc_core::global;
use crate::mwc_core::libtx::{aggsig, build, proof::ProofBuild, secp_ser, tx_fee};
use crate::mwc_core::map_vec;
use crate::mwc_keychain::{BlindSum, BlindingFactor, Keychain, SwitchCommitmentType};
use crate::mwc_util::secp;
use crate::mwc_util::secp::key::{PublicKey, SecretKey};
use crate::mwc_util::secp::pedersen::Commitment;
use crate::mwc_util::secp::Signature;
use crate::mwc_util::ToHex;
use crate::Context;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use uuid::Uuid;

use crate::slate_versions::v2::SlateV2;
use crate::slate_versions::v2::SlateV2ParseTTL;

use crate::mwc_core::consensus::WEEK_HEIGHT;
use crate::slate_versions::v3::{
	CoinbaseV3, InputV3, OutputV3, ParticipantDataV3, PaymentInfoV3, SlateV3, TransactionBodyV3,
	TransactionV3, TxKernelV3, VersionCompatInfoV3,
};

// use crate::slate_versions::{CURRENT_SLATE_VERSION, MWC_BLOCK_HEADER_VERSION};
use crate::mwc_core::core::{Inputs, NRDRelativeHeight, OutputIdentifier};
use crate::proof::proofaddress::ProvableAddress;
use crate::types::CbData;
use crate::{SlateVersion, Slatepacker, CURRENT_SLATE_VERSION};
use ed25519_dalek::SecretKey as DalekSecretKey;
use mwc_wallet_util::mwc_core::core::FeeFields;
use mwc_wallet_util::mwc_util::secp::ContextFlag;
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use rand::rngs::mock::StepRng;
use rand::thread_rng;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentInfo {
	#[serde(serialize_with = "ProvableAddress::serialize_as_string")]
	pub sender_address: ProvableAddress,
	#[serde(serialize_with = "ProvableAddress::serialize_as_string")]
	pub receiver_address: ProvableAddress,
	pub receiver_signature: Option<String>,
}

/// Public data for each participant in the slate
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
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
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part_sig: Option<Signature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
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
}

/// Public message data (for serialising and storage)
#[derive(Serialize, Deserialize, Debug, Clone)]
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
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
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
		let secp = Secp256k1::with_caps(ContextFlag::None);
		writeln!(
			f,
			"Public Key: {}",
			&self.public_key.serialize_vec(&secp, true).to_hex()
		)?;
		let message = match self.message.clone() {
			None => "None".to_owned(),
			Some(m) => m,
		};
		writeln!(f, "Message: {}", message)?;
		let message_sig = match self.message_sig {
			None => "None".to_owned(),
			Some(m) => m.to_raw_data().as_ref().to_hex(),
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

/// Versioning and compatibility info about this slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfo {
	/// The current version of the slate format
	pub version: u16,
	/// The mwc block header version this slate is intended for
	pub block_header_version: u16,
}

/// Helper just to facilitate serialization
#[derive(Serialize, Deserialize, Debug, Clone)]
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
	pub fn calc_lock_height(&self) -> u64 {
		match self.kernel_features {
			3 => self.height + self.lock_height, // nrd
			_ => self.lock_height,               // others must have height in sync
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
			Error::SlateVersionParse(format!(
				"Unable to find slate version at {}, {}",
				slate_json, e
			))
		})?;
		Ok(probe.version())
	}

	/// Check if this text slate is plain
	pub fn deserialize_is_plain(slate_str: &str) -> bool {
		slate_str.len() > 0 && slate_str.as_bytes()[0] == '{' as u8
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade_slatepack(
		slate_str: &str,
		dec_key: &DalekSecretKey,
		height: u64,
		secp: &Secp256k1,
	) -> Result<Slatepacker, Error> {
		let sp = Slatepacker::decrypt_slatepack(slate_str.as_bytes(), dec_key, height, secp)?;
		Ok(sp)
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade_plain(slate_json: &str) -> Result<Slate, Error> {
		let version = Slate::parse_slate_version(slate_json)?;

		//I don't think we need to do this for coin_type and network_type, the slate containing these two
		//fields has to be version 3. If receiver wallet doesn't supported them, they will be filtered out.
		let ttl_cutoff_height = if version == 2 {
			let parse_slate: Result<SlateV2ParseTTL, serde_json::error::Error> =
				serde_json::from_str(slate_json);
			if parse_slate.is_ok() {
				parse_slate.unwrap().ttl_cutoff_height
			} else {
				None
			}
		} else {
			None
		};

		let v3: SlateV3 = match version {
			3 => serde_json::from_str(slate_json).map_err(|e| {
				Error::SlateDeser(format!(
					"Json to SlateV3 conversion failed for {}, {}",
					slate_json, e
				))
			})?,
			2 => {
				let v2: SlateV2 = serde_json::from_str(slate_json).map_err(|e| {
					Error::SlateDeser(format!(
						"Json to SlateV2 conversion failed for {}, {}",
						slate_json, e
					))
				})?;
				let mut ret = SlateV3::from(v2);
				ret.ttl_cutoff_height = ttl_cutoff_height;
				ret
			}
			_ => return Err(Error::SlateVersion(version)),
		};
		Ok(v3.to_slate(true)?)
	}

	/// Create a new slate
	/// slatepack also mean 'compact slate'. Please note the slates are build different way, so for the compact
	/// slates we have different method of building it.
	pub fn blank(num_participants: usize, compact_slate: bool) -> Slate {
		let np = match num_participants {
			0 => 2,
			n => n,
		};
		// The transaction inputs type need to be Commit and feature. So let's fix that now while it is empty.
		let mut tx = Transaction::empty();
		tx.body.inputs = Inputs::FeaturesAndCommit(vec![]);
		let slate = Slate {
			compact_slate,
			num_participants: np, // assume 2 if not present
			id: Uuid::new_v4(),
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
		slate
	}

	/// Compare two slates for send: sended and responded. Just want to check if sender didn't mess with slate
	pub fn compare_slates_send(send_slate: &Self, respond_slate: &Self) -> Result<(), Error> {
		if send_slate.id != respond_slate.id {
			return Err(Error::SlateValidation("uuid mismatch".to_string()));
		}
		if !send_slate.compact_slate {
			if send_slate.amount != respond_slate.amount {
				return Err(Error::SlateValidation("amount mismatch".to_string()));
			}
			if send_slate.fee != respond_slate.fee {
				return Err(Error::SlateValidation("fee mismatch".to_string()));
			}
			// Checking transaction...
			// Inputs must match exactly
			if send_slate.tx_or_err()?.body.inputs != respond_slate.tx_or_err()?.body.inputs {
				return Err(Error::SlateValidation("inputs mismatch".to_string()));
			}

			// Checking if participant data match each other
			for pat_data in &send_slate.participant_data {
				if !respond_slate.participant_data.contains(&pat_data) {
					return Err(Error::SlateValidation(
						"participant data mismatch".to_string(),
					));
				}
			}

			// Respond outputs must include send_slate's. Expected that some was added
			for output in &send_slate.tx_or_err()?.body.outputs {
				if !respond_slate.tx_or_err()?.body.outputs.contains(&output) {
					return Err(Error::SlateValidation("outputs mismatch".to_string()));
				}
			}

			// Kernels must match exactly
			if send_slate.tx_or_err()?.body.kernels != respond_slate.tx_or_err()?.body.kernels {
				return Err(Error::SlateValidation("kernels mismatch".to_string()));
			}
		}
		if send_slate.kernel_features != respond_slate.kernel_features {
			return Err(Error::SlateValidation(
				"kernel_features mismatch".to_string(),
			));
		}
		if send_slate.lock_height != respond_slate.lock_height {
			return Err(Error::SlateValidation("lock_height mismatch".to_string()));
		}
		if send_slate.height != respond_slate.height {
			return Err(Error::SlateValidation("height mismatch".to_string()));
		}
		if send_slate.ttl_cutoff_height != respond_slate.ttl_cutoff_height {
			return Err(Error::SlateValidation("ttl_cutoff mismatch".to_string()));
		}

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
		assert!(invoice_slate.tx_or_err()?.body.inputs.is_empty());
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

		Ok(())
	}

	/// Calculate minimal plain Slate version. For exchange we want to keep the varsion as low as possible
	/// because there are might be many non upgraded wallets and we want ot be friendly to them.
	pub fn lowest_version(&self) -> SlateVersion {
		if self.payment_proof.is_some() || self.ttl_cutoff_height.is_some() || self.compact_slate {
			SlateVersion::V3
		} else {
			SlateVersion::V2
		}
	}

	/// Adds selected inputs and outputs to the slate's transaction
	/// Returns blinding factor
	pub fn add_transaction_elements<K, B>(
		&mut self,
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
		let (tx, blind) =
			build::partial_transaction(self.tx_or_err()?.clone(), &elems, keychain, builder)?;
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
				.replace_kernel(TxKernel::with_features(self.kernel_features()?)),
		);
		Ok(())
	}

	/// Completes callers part of round 1, adding public key info
	/// to the slate
	pub fn fill_round_1<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		if !self.compact_slate {
			// Generating offset for backward compability. Offset ONLY for the TX, the slate copy is kept the same.
			if self.tx_or_err()?.offset == BlindingFactor::zero() {
				self.generate_legacy_offset(keychain, sec_key, use_test_rng)?;
			}
		}

		self.add_participant_info(
			keychain.secp(),
			&sec_key,
			&sec_nonce,
			participant_id,
			None,
			message,
			use_test_rng,
		)?;
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
					return Err(Error::SlateValidation(format!("Invalid lock_height for Plain kernel feature. lock_height expected to be zero, but has {}", self.lock_height)));
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
			Ok(self.fee.try_into()?)
		}
	}

	/// This is the msg that we will sign as part of the tx kernel.
	/// If lock_height is 0 then build a plain kernel, otherwise build a height locked kernel.
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.kernel_features()?.kernel_sig_msg()?;
		Ok(msg)
	}

	/// Completes caller's part of round 2, completing signatures
	pub fn fill_round_2(
		&mut self,
		secp: &Secp256k1,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
	) -> Result<(), Error> {
		// TODO: Note we're unable to verify fees in this instance because of the slatepacks
		// Inputs are not transferred.
		// Also with lock later feature, fees and inputs can be adjusted before finalizing by the send init party
		// self.check_fees()?;

		self.verify_part_sigs(secp)?;
		let sig_part = aggsig::calculate_partial_sig(
			secp,
			sec_key,
			sec_nonce,
			&self.pub_nonce_sum(secp)?,
			Some(&self.pub_blind_sum(secp)?),
			&self.msg_to_sign()?,
		)?;
		for i in 0..self.num_participants {
			if self.participant_data[i].id == participant_id as u64 {
				self.participant_data[i].part_sig = Some(sig_part);
				break;
			}
		}
		Ok(())
	}

	/// Creates the final signature, callable by either the sender or recipient
	/// (after phase 3: sender confirmation)
	pub fn finalize<K>(&mut self, keychain: &K, height: u64) -> Result<(), Error>
	where
		K: Keychain,
	{
		let final_sig = self.finalize_signature(keychain.secp())?;
		self.finalize_transaction(keychain, &final_sig, height)
	}

	/// Return the participant with the given id
	pub fn participant_with_id(&self, id: usize) -> Option<ParticipantData> {
		for p in self.participant_data.iter() {
			if p.id as usize == id {
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

	/// Return vector of all partial sigs
	fn part_sigs(&self) -> Vec<&Signature> {
		self.participant_data
			.iter()
			.filter(|p| p.part_sig.is_some())
			.map(|p| p.part_sig.as_ref().unwrap())
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
		part_sig: Option<Signature>,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error> {
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(secp, &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(secp, &sec_nonce)?;

		let test_message_nonce = SecretKey::from_slice(secp, &[1; 32])?;
		let message_nonce = match use_test_rng {
			false => None,
			true => Some(&test_message_nonce),
		};

		// Sign the provided message
		let message_sig = {
			if let Some(m) = message.clone() {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &m.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let res = aggsig::sign_single(secp, &m, &sec_key, message_nonce, Some(&pub_key))?;
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
		keychain: &K,
		sec_key: &mut SecretKey,
		use_test_rng: bool,
	) -> Result<(), Error> {
		// Generate a random kernel offset here
		// and subtract it from the blind_sum so we create
		// the aggsig context with the "split" key
		self.tx_or_err_mut()?.offset = match use_test_rng {
			false => {
				BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()))
			}
			true => {
				// allow for consistent test results
				let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
				BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut test_rng))
			}
		};

		let blind_offset = keychain.blind_sum(
			&BlindSum::new()
				.add_blinding_factor(BlindingFactor::from_secret_key(sec_key.clone()))
				.sub_blinding_factor(self.tx_or_err()?.offset.clone()),
		)?;
		*sec_key = blind_offset.secret_key(keychain.secp())?;
		Ok(())
	}

	/// Add our contribution to the offset based on the excess, inputs and outputs
	pub fn adjust_offset<K: Keychain>(
		&mut self,
		keychain: &K,
		context: &Context,
	) -> Result<(), Error> {
		// Only compact slate flow.
		debug_assert!(self.compact_slate);

		let mut sum = BlindSum::new()
			.add_blinding_factor(self.offset.clone())
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				context.initial_sec_key.clone(),
			));
		for (id, _, amount) in &context.input_ids {
			sum = sum.sub_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}
		for (id, _, amount) in &context.output_ids {
			sum = sum.add_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}

		self.offset = keychain.blind_sum(&sum)?;

		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self, height: u64) -> Result<(), Error> {
		let tx = self.tx_or_err()?;
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(tx.inputs().len(), tx.outputs().len(), tx.kernels().len());

		if fee > tx.fee(height) {
			return Err(Error::Fee(format!(
				"Fee Dispute Error: {}, {}",
				tx.fee(height),
				fee,
			)));
		}

		if fee > self.amount + self.fee {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(self.amount + self.fee, false)
			);
			info!("{}", reason);
			return Err(Error::Fee(reason));
		}

		Ok(())
	}

	/// Verifies all of the partial signatures in the Slate are valid
	fn verify_part_sigs(&self, secp: &Secp256k1) -> Result<(), Error> {
		// collect public nonces
		for p in self.participant_data.iter() {
			if p.is_complete() {
				debug_assert!(p.part_sig.is_some());
				aggsig::verify_partial_sig(
					secp,
					p.part_sig.as_ref().unwrap(),
					&self.pub_nonce_sum(secp)?,
					&p.public_blind_excess,
					Some(&self.pub_blind_sum(secp)?),
					&self.msg_to_sign()?,
				)?;
			}
		}
		Ok(())
	}

	/// Verifies any messages in the slate's participant data match their signatures
	pub fn verify_messages(&self) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);
		for p in self.participant_data.iter() {
			if let Some(msg) = &p.message {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &msg.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let signature = match p.message_sig {
					None => {
						error!("verify_messages - participant message doesn't have signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
						return Err(Error::Signature(
							"Optional participant messages doesn't have signature".to_owned(),
						));
					}
					Some(s) => s,
				};
				if !aggsig::verify_single(
					&secp,
					&signature,
					&m,
					None,
					&p.public_blind_excess,
					Some(&p.public_blind_excess),
					false,
				) {
					error!("verify_messages - participant message doesn't match signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
					return Err(Error::Signature(
						"Optional participant messages do not match signatures".to_owned(),
					));
				} else {
					info!(
						"verify_messages - signature verified ok. Participant message: \"{}\"",
						String::from_utf8_lossy(&msg.as_bytes()[..])
					);
				}
			}
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

	pub fn finalize_signature(&mut self, secp: &Secp256k1) -> Result<Signature, Error> {
		self.verify_part_sigs(secp)?;

		let part_sigs = self.part_sigs();
		let pub_nonce_sum = self.pub_nonce_sum(secp)?;
		let final_pubkey = self.pub_blind_sum(secp)?;
		// get the final signature
		let final_sig = aggsig::add_signatures(secp, part_sigs, &pub_nonce_sum)?;

		// Calculate the final public key (for our own sanity check)

		// Check our final sig verifies
		aggsig::verify_completed_sig(
			secp,
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&self.msg_to_sign()?,
		)?;

		Ok(final_sig)
	}

	/// return the final excess
	pub fn calc_excess(&self, secp: &Secp256k1, height: u64) -> Result<Commitment, Error> {
		if self.compact_slate {
			let sum = self.pub_blind_sum(secp)?;
			Ok(Commitment::from_pubkey(secp, &sum)?)
		} else {
			// Legacy method
			let tx = self.tx_or_err()?.clone();
			let kernel_offset = tx.offset.clone();
			let overage = tx.fee(height) as i64;
			let tx_excess = tx.sum_commitments(overage, secp)?;

			// subtract the kernel_excess (built from kernel_offset)
			let offset_excess = secp.commit(0, kernel_offset.secret_key(secp)?)?;
			Ok(secp.commit_sum(vec![tx_excess], vec![offset_excess])?)
		}
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_transaction<K>(
		&mut self,
		keychain: &K,
		final_sig: &secp::Signature,
		height: u64,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.check_fees(height)?;
		// build the final excess based on final tx and offset
		let secp = keychain.secp();
		let final_excess = self.calc_excess(secp, height)?;

		debug!("Final Tx excess: {:?}", final_excess);

		let final_tx = self.tx_or_err()?;

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.kernels().len(), 1);

		let mut kernel = final_tx.kernels()[0];
		kernel.excess = final_excess;
		kernel.excess_sig = final_sig.clone();

		let final_tx = final_tx.clone().replace_kernel(kernel);

		// confirm the kernel verifies successfully before proceeding
		debug!(
			"Validating final transaction. Inputs: {}  Outputs: {}",
			final_tx.body.inputs.len(),
			final_tx.body.outputs.len()
		);
		trace!(
			"Final tx: {}",
			serde_json::to_string_pretty(&final_tx).unwrap()
		);
		final_tx.kernels()[0].verify(secp)?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		final_tx.validate(Weighting::AsTransaction, height, secp)?;

		// replace our slate tx with the new one with updated kernel
		self.tx = Some(final_tx);

		Ok(())
	}
}

impl Serialize for Slate {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

		let v3 = SlateV3::from(self);
		match self.version_info.version {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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

// Coinbase data to versioned.
impl From<CbData> for CoinbaseV3 {
	fn from(cb: CbData) -> CoinbaseV3 {
		CoinbaseV3 {
			output: OutputV3::from(&cb.output),
			kernel: TxKernelV3::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

// Current slate version to versioned conversions

// Slate to versioned
impl From<Slate> for SlateV3 {
	fn from(slate: Slate) -> SlateV3 {
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
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(&version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(&p)),
			None => None,
		};
		let tx = match tx {
			Some(t) => {
				let mut t = TransactionV3::from(t);
				if compact_slate {
					// for compact the Slate offset is dominate
					t.offset = tx_offset;
				}
				Some(t)
			}
			None => None,
		};
		SlateV3 {
			num_participants,
			id,
			tx: tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			coin_type: Some("mwc".to_string()),
			network_type: Some(global::get_network_name()),
			participant_data,
			version_info,
			payment_proof,
			compact_slate: if compact_slate { Some(true) } else { None },
			kernel_features,
		}
	}
}

impl From<&Slate> for SlateV3 {
	fn from(slate: &Slate) -> SlateV3 {
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
		} = slate;
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
			network_type: Some(global::get_network_name()),
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
				error!("Transaction Body has type Inputs::CommitOnly, some data is lost");
				map_vec!(commits, |c| InputV3 {
					features: OutputFeatures::Plain,
					commit: c.commitment(),
				})
			}
			Inputs::FeaturesAndCommit(inputs) => {
				map_vec!(inputs, |inp| InputV3 {
					features: inp.features,
					commit: inp.commit,
				})
			}
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
				relative_height: _,
			} => {
				error!("NRD kernel not supported well. Wrong height. Fix me");
				(CompatKernelFeatures::NoRecentDuplicate, fee, 0)
			}
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

		let inputs = map_vec!(inputs, |inp| Input::from(inp));
		let outputs = map_vec!(outputs, |out| Output::from(out));
		let mut kernels_tx: Vec<TxKernel> = Vec::new();
		for kern in kernels {
			kernels_tx.push(TxKernel::try_from(kern)?);
		}
		Ok(TransactionBody {
			inputs: Inputs::FeaturesAndCommit(inputs),
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
			fee.try_into()?
		};

		let features = match kernel.features {
			CompatKernelFeatures::Plain => KernelFeatures::Plain { fee },
			CompatKernelFeatures::Coinbase => KernelFeatures::Coinbase,
			CompatKernelFeatures::HeightLocked => KernelFeatures::HeightLocked { fee, lock_height },
			CompatKernelFeatures::NoRecentDuplicate => KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height: NRDRelativeHeight::new(lock_height).unwrap(),
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
pub enum CompatKernelFeatures {
	Plain,
	Coinbase,
	HeightLocked,
	NoRecentDuplicate,
}
