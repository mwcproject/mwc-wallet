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

use super::error::Error;
use crate::blake2::blake2b::blake2b;
use crate::mwc_core::core::{
	Input as TxInput, Output as TxOutput, OutputFeatures, OutputIdentifier,
};
use crate::mwc_core::libtx::secp_ser;
use crate::mwc_util::secp::constants::SECRET_KEY_SIZE;
use crate::mwc_util::secp::key::{PublicKey, SecretKey};
use crate::mwc_util::secp::pedersen::{Commitment, RangeProof};
use crate::mwc_util::secp::Secp256k1;
use crate::swap::ser::*;
use hex::FromHex;
use rand::thread_rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Multisig builder
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Builder {
	/// Number of participant. For swap it is 2
	num_participants: usize,
	#[serde(with = "secp_ser::string_or_u64")]
	/// MWC amount that are used for swap
	pub amount: u64,
	/// False: use comitment Hash
	/// True:  use comitment data
	commit_reveal: bool,
	/// Multisig participants data
	pub participants: Vec<ParticipantData>,
	/// This party participant Id
	participant_id: usize,
	/// This party secret
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	nonce: SecretKey,
	#[serde(
		serialize_with = "option_seckey_to_hex",
		deserialize_with = "option_seckey_from_hex",
		skip_serializing_if = "Option::is_none",
		default
	)]
	/// Sharable nonce
	pub common_nonce: Option<SecretKey>,
}

impl Builder {
	/// Create a builder
	pub fn new(
		num_participants: usize,
		amount: u64,
		commit_reveal: bool,
		participant_id: usize,
		nonce: SecretKey,
		common_nonce: Option<SecretKey>,
	) -> Self {
		Self {
			num_participants,
			amount,
			commit_reveal,
			participants: vec![],
			participant_id,
			nonce,
			common_nonce,
		}
	}

	/// Create this party participant part
	pub fn create_participant(
		&mut self,
		secp: &Secp256k1,
		secret_key: &SecretKey,
	) -> Result<(), Error> {
		let id = self.participants.len();
		if id != self.participant_id {
			return Err(Error::ParticipantOrdering);
		}
		let partial_commitment = secp.commit(0, secret_key.clone())?;
		self.participants.push(if self.commit_reveal {
			ParticipantData::new_commit(partial_commitment)?
		} else {
			ParticipantData::new_revealed(partial_commitment)
		});
		Ok(())
	}

	/// Import participant data from the other party
	pub fn import_participant(
		&mut self,
		id: usize,
		participant: &ParticipantData,
	) -> Result<(), Error> {
		if self.participants.len() > id {
			return Err(Error::ParticipantExists);
		}

		if self.participants.len() != id || self.participants.len() >= self.num_participants {
			return Err(Error::ParticipantOrdering);
		}

		self.participants.push(if self.commit_reveal {
			participant.new_foreign_commit()?
		} else {
			participant.new_foreign_reveal()?
		});

		Ok(())
	}

	/// Checking revealed data
	pub fn reveal_participant(
		&mut self,
		id: usize,
		participant: &ParticipantData,
	) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(Error::ParticipantDoesntExist);
		}

		if self.commit_reveal && self.participants.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		match participant.partial_commitment.as_ref() {
			Some(p) => self.participants[id].reveal(p),
			None => Err(Error::Reveal),
		}
	}

	/// Round 1 of building multisig
	pub fn round_1_participant(
		&mut self,
		id: usize,
		participant: &ParticipantData,
	) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(Error::ParticipantDoesntExist);
		}

		if self.participants.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		if participant.t_1.is_none() || participant.t_2.is_none() {
			return Err(Error::Round1Missing);
		}

		self.participants[id].t_1 = participant.t_1.clone();
		self.participants[id].t_2 = participant.t_2.clone();
		Ok(())
	}

	/// Round 2 of building multisig
	pub fn round_2_participant(
		&mut self,
		id: usize,
		participant: &ParticipantData,
	) -> Result<(), Error> {
		if self.participants.len() <= id {
			return Err(Error::ParticipantDoesntExist);
		}

		if self.participants.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		if participant.tau_x.is_none() {
			return Err(Error::Round2Missing);
		}

		self.participants[id].tau_x = participant.tau_x.clone();
		Ok(())
	}

	/// Export this party participant data
	pub fn export(&self) -> Result<ParticipantData, Error> {
		if self.participants.len() <= self.participant_id {
			return Err(Error::ParticipantDoesntExist);
		}

		Ok(self.participants[self.participant_id].clone())
	}

	/// Checking revealed data
	pub fn reveal(&mut self, secp: &Secp256k1, secret_key: &SecretKey) -> Result<(), Error> {
		if self.participants.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		let partial_commitment = secp.commit(0, secret_key.clone())?;
		self.participants[self.participant_id].reveal(&partial_commitment)?;
		Ok(())
	}

	/// Mulisig buiding round 1
	pub fn round_1(&mut self, secp: &Secp256k1, blind: &SecretKey) -> Result<(), Error> {
		let mut t_1 = PublicKey::new();
		let mut t_2 = PublicKey::new();
		// Round 1 doesnt require knowledge of total commit or common nonce, we should allow NULL argument in libsecp
		let commit = secp.commit(0, SecretKey::new(secp, &mut thread_rng()))?;
		let common_nonce = self
			.common_nonce
			.clone()
			.unwrap_or(SecretKey::new(secp, &mut thread_rng()));
		secp.bullet_proof_multisig(
			self.amount,
			blind.clone(),
			common_nonce,
			None,
			None,
			None,
			Some(&mut t_1),
			Some(&mut t_2),
			vec![commit],
			Some(&self.nonce),
			1,
		);
		self.participants[self.participant_id].t_1 = Some(t_1);
		self.participants[self.participant_id].t_2 = Some(t_2);
		Ok(())
	}

	/// Mulisig buiding round 2
	pub fn round_2(&mut self, secp: &Secp256k1, blind: &SecretKey) -> Result<(), Error> {
		let mut t_1 = self.sum_t_1(secp)?;
		let mut t_2 = self.sum_t_2(secp)?;
		let mut tau_x = SecretKey([0; SECRET_KEY_SIZE]);
		let commit = self.commit(secp)?;
		secp.bullet_proof_multisig(
			self.amount,
			blind.clone(),
			self.common_nonce()?,
			None,
			None,
			Some(&mut tau_x),
			Some(&mut t_1),
			Some(&mut t_2),
			vec![commit],
			Some(&self.nonce),
			2,
		);
		self.participants[self.participant_id].tau_x = Some(tau_x);
		Ok(())
	}

	/// Finalize building multisig
	pub fn finalize(&self, secp: &Secp256k1, blind: &SecretKey) -> Result<RangeProof, Error> {
		let mut t_1 = self.sum_t_1(secp)?;
		let mut t_2 = self.sum_t_2(secp)?;
		let mut tau_x = self.sum_tau_x(secp)?;
		let commit = self.commit(secp)?;
		let proof = secp
			.bullet_proof_multisig(
				self.amount,
				blind.clone(),
				self.common_nonce()?,
				None,
				None,
				Some(&mut tau_x),
				Some(&mut t_1),
				Some(&mut t_2),
				vec![commit],
				Some(&self.nonce),
				0,
			)
			.ok_or(Error::MultiSigIncomplete)?;
		secp.verify_bullet_proof(commit, proof, None)?;
		Ok(proof)
	}

	/// Multisig as commit
	pub fn as_input(&self, secp: &Secp256k1) -> Result<TxInput, Error> {
		Ok(TxInput {
			features: OutputFeatures::Plain,
			commit: self.commit(secp)?,
		})
	}

	/// Multisig as output
	pub fn as_output(&self, secp: &Secp256k1, blind: &SecretKey) -> Result<TxOutput, Error> {
		Ok(TxOutput {
			identifier: OutputIdentifier {
				features: OutputFeatures::Plain,
				commit: self.commit(secp)?,
			},
			proof: self.finalize(secp, blind)?,
		})
	}

	/// Build a commitment with initialized multisig
	pub fn commit(&self, secp: &Secp256k1) -> Result<Commitment, Error> {
		let mut partial_commitments: Vec<Commitment> = self
			.participants
			.iter()
			.filter_map(|p| p.partial_commitment.clone())
			.collect();

		if partial_commitments.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		let commitment_value = secp.commit_value(self.amount)?;
		partial_commitments.push(commitment_value);
		let commitment = secp.commit_sum(partial_commitments, vec![])?;
		Ok(commitment)
	}

	fn common_nonce(&self) -> Result<SecretKey, Error> {
		self.common_nonce.clone().ok_or(Error::CommonNonceMissing)
	}

	fn sum_t_1(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let t_1s: Vec<&PublicKey> = self
			.participants
			.iter()
			.filter_map(|p| p.t_1.as_ref())
			.collect();

		if t_1s.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		let t_1 = PublicKey::from_combination(secp, t_1s)?;
		Ok(t_1)
	}

	fn sum_t_2(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let t_2s: Vec<&PublicKey> = self
			.participants
			.iter()
			.filter_map(|p| p.t_2.as_ref())
			.collect();

		if t_2s.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		let t_2 = PublicKey::from_combination(secp, t_2s)?;
		Ok(t_2)
	}

	fn sum_tau_x(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		let mut sum_tau_x = SecretKey([0; SECRET_KEY_SIZE]);
		let tau_xs: Vec<&SecretKey> = self
			.participants
			.iter()
			.filter_map(|p| p.tau_x.as_ref())
			.collect();

		if tau_xs.len() != self.num_participants {
			return Err(Error::MultiSigIncomplete);
		}

		for x in tau_xs {
			sum_tau_x.add_assign(secp, x)?;
		}
		Ok(sum_tau_x)
	}
}

/// Multisig participant data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantData {
	/// Hash for commit (not revealed data)
	#[serde(skip_serializing_if = "Option::is_none", default)]
	partial_commitment_hash: Option<Hash>,
	#[serde(
		serialize_with = "option_commit_to_hex",
		deserialize_with = "option_commit_from_hex",
		skip_serializing_if = "Option::is_none",
		default
	)]
	/// Commit (revealed case)
	pub partial_commitment: Option<Commitment>,
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex",
		skip_serializing_if = "Option::is_none",
		default
	)]
	/// Public key
	t_1: Option<PublicKey>,
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex",
		skip_serializing_if = "Option::is_none",
		default
	)]
	/// Public key
	t_2: Option<PublicKey>,
	#[serde(
		serialize_with = "option_seckey_to_hex",
		deserialize_with = "option_seckey_from_hex",
		skip_serializing_if = "Option::is_none",
		default
	)]
	/// Secret
	tau_x: Option<SecretKey>,
}

impl ParticipantData {
	/// Build from commitment as not revealed
	pub fn new_commit(partial_commitment: Commitment) -> Result<Self, Error> {
		Ok(ParticipantData {
			partial_commitment_hash: Some(partial_commitment.hash()?),
			partial_commitment: None,
			t_1: None,
			t_2: None,
			tau_x: None,
		})
	}

	/// Build from commitment as revealed
	pub fn new_revealed(partial_commitment: Commitment) -> Self {
		ParticipantData {
			partial_commitment_hash: None,
			partial_commitment: Some(partial_commitment),
			t_1: None,
			t_2: None,
			tau_x: None,
		}
	}

	/// Convert this to not revealed
	pub fn new_foreign_commit(&self) -> Result<Self, Error> {
		let hash = self
			.partial_commitment_hash
			.clone()
			.ok_or(Error::ParticipantInvalid)?;
		Ok(ParticipantData {
			partial_commitment_hash: Some(hash),
			partial_commitment: None,
			t_1: None,
			t_2: None,
			tau_x: None,
		})
	}

	/// Convert this to revealed
	pub fn new_foreign_reveal(&self) -> Result<Self, Error> {
		let commit = self
			.partial_commitment
			.clone()
			.ok_or(Error::ParticipantInvalid)?;
		Ok(ParticipantData {
			partial_commitment_hash: None,
			partial_commitment: Some(commit),
			t_1: None,
			t_2: None,
			tau_x: None,
		})
	}

	/// Check if partial_commitment match the hash
	fn reveal(&mut self, partial_commitment: &Commitment) -> Result<(), Error> {
		let hash = self.partial_commitment_hash.as_ref().ok_or(Error::Reveal)?;
		if &partial_commitment.hash()? == hash {
			Ok(())
		} else {
			Err(Error::Reveal)
		}
	}
}

/// Hash value
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Hash {
	inner: Vec<u8>,
}

impl Hash {
	/// Create a new hash instance
	pub fn new(inner: Vec<u8>) -> Result<Self, Error> {
		if inner.len() != 32 {
			return Err(Error::HashLength);
		}

		Ok(Self { inner })
	}

	/// Init secret from the hash
	pub fn to_secret_key(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		let key = SecretKey::from_slice(secp, &self.inner)?;
		Ok(key)
	}
}

impl Serialize for Hash {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&hex::encode(&self.inner))
	}
}

impl<'de> Deserialize<'de> for Hash {
	fn deserialize<D>(deserializer: D) -> Result<Hash, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;
		let s = String::deserialize(deserializer)?;

		let v = Vec::from_hex(&s).map_err(D::Error::custom)?;

		Hash::new(v).map_err(D::Error::custom)
	}
}

/// Trait that make Hashable
pub trait Hashed {
	/// Calculate hash value
	fn hash(&self) -> Result<Hash, Error>;
}
/// Define Hash for Pedersen Commitment
impl Hashed for Commitment {
	fn hash(&self) -> Result<Hash, Error> {
		Hash::new(blake2b(32, &[], &self.0).as_bytes().to_vec())
	}
}

/// Define hash for vector
impl Hashed for Vec<u8> {
	fn hash(&self) -> Result<Hash, Error> {
		Hash::new(blake2b(32, &[], &self).as_bytes().to_vec())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mwc_util::secp::ContextFlag;
	use rand::thread_rng;

	/*
	/// Test proof for 2-of-2 multisig with a commit & reveal phase
	// TODO: fix this test
	#[test]
	fn test_builder() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		//// Set up phase: parties agree on the participants (and an ordering), amount and a common nonce ////
		let num_participants: usize = 2;
		let amount: u64 = 713_000_000;
		let (common_nonce, _) = secp.generate_keypair(&mut thread_rng()).unwrap();

		//// Commit phase: parties all send their hashed partial commitment to each other (inside the ParticipantData) ////
		// A
		let id_a = 0;
		let (secret_a, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let (nonce_a, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let mut builder_a = Builder::new(num_participants, amount, true, id_a, nonce_a, Some(common_nonce.clone()));
		assert!(builder_a.create_participant(&secp, &secret_a).is_ok());
		// A cannot reveal yet
		assert!(builder_a.reveal(&secp, &secret_a).is_err());
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		let id_b = 1;
		let (secret_b, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let (nonce_b, _) = secp.generate_keypair(&mut thread_rng()).unwrap();
		let mut builder_b = Builder::new(num_participants, amount, true, id_b, nonce_b, Some(common_nonce.clone()));
		// Participant cannot be created before previous ones are imported
		assert!(builder_b.create_participant(&secp, &secret_b).is_err());
		assert!(builder_b.import_participant(id_a, &part_a).is_ok());
		assert!(builder_b.create_participant(&secp, &secret_b).is_ok());

		//// Reveal phase ////
		// B
		// Revealing with the wrong secret will fail
		assert!(builder_b.reveal(&secp, &secret_a).is_err());
		assert!(builder_b.reveal(&secp, &secret_b).is_ok());
		// A hasn't revealed yet, we don't know the total commitment
		assert!(builder_b.commit(&secp).is_err());
		let part_b = builder_b.export().unwrap(); // B -> all

		// A
		// (import+reveal of B at the same time to save on communication, not required)
		assert!(builder_a.import_participant(id_b, &part_b).is_ok());
		assert!(builder_a.reveal_participant(id_b, &part_b).is_ok());
		assert!(builder_a.reveal(&secp, &secret_a).is_ok());
		assert!(builder_a.commit(&secp).is_ok());

		//// Build phase round 1: T_1 and T_2 ////
		// A
		assert!(builder_a.round_1(&secp, &secret_a).is_ok());
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		// (reveal+round 1 of A at the same time to save on communication, not required)
		// Revealing with the wrong commitment will fail
		assert!(builder_b.reveal_participant(id_a, &part_b).is_err());
		assert!(builder_b.reveal_participant(id_a, &part_a).is_ok());
		// All parties agree on the total commitment
		assert_eq!(builder_a.commit(&secp).unwrap(), builder_b.commit(&secp).unwrap());
		assert!(builder_b.round_1(&secp, &secret_b).is_ok());
		assert!(builder_b.round_1_participant(id_a, &part_a).is_ok());

		//// Build phase round 2: tau_x ////
		// B
		assert!(builder_b.round_2(&secp, &secret_b).is_ok());
		let part_b = builder_b.export().unwrap(); // B -> all

		// A
		// (round 1+round 2 of B at the same time to save on communication, not required)
		// Round 2 cannot be done without all round 1 information
		assert!(builder_a.round_2(&secp, &secret_a).is_err());
		assert!(builder_a.round_1_participant(id_b, &part_b).is_ok());
		// All parties agree on the total T_1 and T_2
		assert_eq!(builder_a.sum_t_1(&secp).unwrap(), builder_b.sum_t_1(&secp).unwrap());
		assert_eq!(builder_a.sum_t_2(&secp).unwrap(), builder_b.sum_t_2(&secp).unwrap());
		assert!(builder_a.round_2(&secp, &secret_a).is_ok());

		//// Finalization phase ////
		// A
		// Finalization cannot be done without all round 2 information
		assert!(builder_a.finalize(&secp, &secret_a).is_err());
		assert!(builder_a.round_2_participant(id_b, &part_b).is_ok());
		assert!(builder_a.finalize(&secp, &secret_a).is_ok());
		// Explicitly verify proof
		let commit_a = builder_a.commit(&secp).unwrap();
		let proof_a = builder_a.proof().unwrap();
		assert!(secp.verify_bullet_proof(commit_a, proof_a, None).is_ok());
		// For completeness, do same on B
		let part_a = builder_a.export().unwrap(); // A -> all

		// B
		assert!(builder_b.round_2_participant(id_a, &part_a).is_ok());
		// All parties agree on the total tau_x
		assert_eq!(builder_a.sum_tau_x(&secp).unwrap(), builder_b.sum_tau_x(&secp).unwrap());
		assert!(builder_b.finalize(&secp, &secret_b).is_ok());
		// Explicitly verify proof
		let commit_b = builder_b.commit(&secp).unwrap();
		let proof_b = builder_b.proof().unwrap();
		assert!(secp.verify_bullet_proof(commit_b, proof_b, None).is_ok());
		// Generated proof is the same
		assert_eq!(proof_a, proof_b);
	}*/

	/// Test proof for 2-of-2 multisig in a single round trip
	#[test]
	fn test_builder_single() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit);

		//// Set up phase: parties agree on the participants (and an ordering), amount and a common nonce
		let num_participants: usize = 2;
		let amount: u64 = 42_000_000;
		let common_nonce = SecretKey::new(&secp, &mut thread_rng());

		// A: round 1
		let id_a = 0;
		let secret_a = SecretKey::new(&secp, &mut thread_rng());
		let nonce_a = SecretKey::new(&secp, &mut thread_rng());
		let mut builder_a = Builder::new(
			num_participants,
			amount,
			false,
			id_a,
			nonce_a,
			Some(common_nonce.clone()),
		);
		assert!(builder_a.create_participant(&secp, &secret_a).is_ok());
		assert!(builder_a.round_1(&secp, &secret_a).is_ok());
		let part_a = builder_a.export().unwrap(); // A -> B

		// B: round 1 + round 2
		let id_b = 1;
		let secret_b = SecretKey::new(&secp, &mut thread_rng());
		let nonce_b = SecretKey::new(&secp, &mut thread_rng());
		let mut builder_b = Builder::new(
			num_participants,
			amount,
			false,
			id_b,
			nonce_b,
			Some(common_nonce.clone()),
		);
		assert!(builder_b.import_participant(id_a, &part_a).is_ok());
		assert!(builder_b.create_participant(&secp, &secret_b).is_ok());
		assert!(builder_b.round_1_participant(id_a, &part_a).is_ok());
		assert!(builder_b.round_1(&secp, &secret_b).is_ok());
		assert!(builder_b.round_2(&secp, &secret_b).is_ok());
		let part_b = builder_b.export().unwrap(); // B -> A

		// A: round 2 + finalize
		assert!(builder_a.import_participant(id_b, &part_b).is_ok());
		assert!(builder_a.round_1_participant(id_b, &part_b).is_ok());
		assert!(builder_a.round_2_participant(id_b, &part_b).is_ok());
		assert!(builder_a.round_2(&secp, &secret_a).is_ok());
		let proof = builder_a.finalize(&secp, &secret_a).unwrap();

		// Explicitly verify proof
		let commit = builder_a.commit(&secp).unwrap();
		assert!(secp.verify_bullet_proof(commit, proof, None).is_ok());
	}
}
