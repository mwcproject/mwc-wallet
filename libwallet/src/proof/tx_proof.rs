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

use crate::proof::crypto::Hex;
use mwc_wallet_util::file::replace_owner_only_file_with;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Secp256k1, pedersen};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid;

use super::crypto;
use super::message::EncryptedMessage;
use super::proofaddress::ProvableAddress;
use crate::Slate;
use crate::error::Error;
use crate::internal::tx;
use crate::slate_versions::VersionedSlate;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_keychain::BlindingFactor;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path;

use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::core::amount_to_hr_string;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::colored::*;
use mwc_wallet_util::mwc_crates::log::warn;
use mwc_wallet_util::mwc_crates::zeroize::{Zeroize, Zeroizing};
use mwc_wallet_util::mwc_util;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Dir name with proof files
pub const TX_PROOF_SAVE_DIR: &'static str = "saved_proofs";

/// Maximum number of proofs kept in the in-memory storage
const SLATE_PROOFS_MAX_ENTRIES: usize = 10240;
/// Proofs older than this are destroyed; they belong to abandoned or rejected flows.
const SLATE_PROOFS_TTL: Duration = Duration::from_secs(3600);
/// Maximum number of bytes from an unauthenticated response field included in an error.
const MAX_RESPONSE_ERROR_DISPLAY_LEN: usize = 256;
/// Maximum number of bytes from an unauthenticated slate field included in an error.
const MAX_FROM_SLATE_ERROR_DISPLAY_LEN: usize = 256;
/// Canonical OnionV3 addresses contain exactly 56 lower-case base32 characters.
const ONION_V3_ADDRESS_LEN: usize = 56;

/// Parse a Tor payment-proof receiver without accepting the more permissive
/// URL, raw-key, case-normalizing, or path forms supported by the general Tor
/// address parser. A transferable proof reports the original address string,
/// so verification must authenticate one canonical representation of the key.
fn canonical_tor_receiver_public_key(
	address: &ProvableAddress,
	context_id: u32,
	secp: &Secp256k1,
) -> Result<ed25519_dalek::VerifyingKey, Error> {
	if address.public_key.len() != ONION_V3_ADDRESS_LEN {
		return Err(Error::TxProofVerify(format!(
			"Tor payment-proof receiver address has invalid length {}, expected {}",
			address.public_key.len(),
			ONION_V3_ADDRESS_LEN
		)));
	}

	ProvableAddress::from_str(secp, context_id, &address.public_key).map_err(|_| {
		Error::TxProofVerify(
			"Tor payment-proof receiver address is not a canonical OnionV3 address".to_owned(),
		)
	})?;
	address.tor_public_key().map_err(|_| {
		Error::TxProofVerify(
			"Unable to build public key from canonical Tor payment-proof receiver address"
				.to_owned(),
		)
	})
}

type ProofCacheKey = (u32, uuid::Uuid);

struct CachedProof {
	/// The proof stays in this stable allocation while it is reserved so moving
	/// the reservation cannot leave copies of its decryption key behind.
	proof: Arc<Mutex<Option<TxProof>>>,
	/// A finalizer has exclusive use of `proof`. Keeping the entry in the map
	/// prevents a concurrent listener from replacing it before commit or rollback.
	reserved: bool,
	expires_at: Instant,
	/// Listener generation that inserted this entry. Teardown of one listener
	/// generation must only remove its own entries: a stale generation's last
	/// reference can outlive the startup of a replacement listener for the same
	/// wallet context, and must not delete proofs the replacement inserted.
	generation: u64,
}

static PROOF_CACHE_GENERATION: AtomicU64 = AtomicU64::new(1);

fn allocate_proof_cache_generation(counter: &AtomicU64) -> Result<u64, Error> {
	counter
		.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			current.checked_add(1)
		})
		.map_err(|_| {
			Error::DataOverflow("Proof cache generation identifier space exhausted".to_string())
		})
}

/// Allocate a fresh listener-generation tag for the proof cache. Every MQS
/// listener instance gets its own tag so its teardown can clear exactly the
/// entries it inserted and nothing else. Once the identifier space is
/// exhausted, fail instead of wrapping and reusing a live generation.
pub fn next_proof_cache_generation() -> Result<u64, Error> {
	allocate_proof_cache_generation(&PROOF_CACHE_GENERATION)
}

lazy_static! {
	/// Global proof storage keyed by wallet context plus slate UUID. Cache
	/// operations prune it directly, and the MQS listener invokes periodic
	/// maintenance while it is capable of creating entries.
	static ref SLATE_PROOFS: Mutex<HashMap<ProofCacheKey, CachedProof>> =
		Mutex::new(HashMap::new());
}

/// Outcome of push_proof_for_slate. Callers must use this to tell whether the
/// proof was actually stored before removing or relying on the entry.
#[must_use = "proof insertion can fail when the bounded cache is full"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofInsertResult {
	/// The proof was stored under (context_id, uuid)
	Inserted,
	/// An entry for (context_id, uuid) already exists; the new proof was dropped
	Duplicate,
	/// The storage is full; the proof was dropped
	Full,
}

/// Drop expired entries from memory. Removing a `CachedProof` drops its
/// `TxProof`, whose `Drop` implementation zeroizes the decryption key.
fn prune_expired_proofs_locked(map: &mut HashMap<ProofCacheKey, CachedProof>, now: Instant) {
	// Never prune an actively reserved slot. Its guard will either remove it on
	// commit or release it on drop, after which normal TTL pruning resumes.
	map.retain(|_, cached| cached.expires_at > now || cached.reserved);
}

/// Perform periodic cache maintenance from an existing wallet service loop.
///
/// MQS is the only production source of cached transport proofs. Its listener
/// calls this function on every long-poll iteration, so abandoned proofs expire
/// even when no later proof-cache API operation occurs and no dedicated cache
/// thread is required.
pub fn prune_expired_proofs() {
	prune_expired_proofs_locked(&mut SLATE_PROOFS.lock(), Instant::now());
}

/// Add a txProof into the mem storage. Returns whether the proof was actually
/// inserted; on Duplicate or Full the proof is dropped and the pre-existing
/// state is left untouched. `generation` identifies the listener instance that
/// owns the entry, so teardown of one listener cannot clear entries inserted
/// by its replacement (see clear_proofs_for_context_generation).
pub fn push_proof_for_slate(
	context_id: u32,
	generation: u64,
	uuid: &uuid::Uuid,
	proof: TxProof,
) -> ProofInsertResult {
	push_proof_for_slate_with_ttl(context_id, generation, uuid, proof, SLATE_PROOFS_TTL)
}

fn push_proof_for_slate_with_ttl(
	context_id: u32,
	generation: u64,
	uuid: &uuid::Uuid,
	proof: TxProof,
	ttl: Duration,
) -> ProofInsertResult {
	let now = Instant::now();
	let mut map = SLATE_PROOFS.lock();
	prune_expired_proofs_locked(&mut map, now);
	let key = (context_id, uuid.clone());
	if map.contains_key(&key) {
		warn!(
			"push_proof_for_slate: proof for slate {} already exists, keeping the existing one",
			uuid
		);
		return ProofInsertResult::Duplicate;
	}
	if map.len() >= SLATE_PROOFS_MAX_ENTRIES {
		warn!(
			"push_proof_for_slate: proof storage is full ({} entries), dropping proof for slate {}",
			map.len(),
			uuid
		);
		return ProofInsertResult::Full;
	}
	map.insert(
		key,
		CachedProof {
			proof: Arc::new(Mutex::new(Some(proof))),
			reserved: false,
			expires_at: now + ttl,
			generation,
		},
	);
	ProofInsertResult::Inserted
}

/// Exclusive, rollback-safe access to one cached transport proof.
///
/// Dropping this value before [`ProofCacheReservation::commit`] makes the proof
/// available in the same cache slot again. The proof itself never leaves that
/// stable allocation, making fallible persistence transactional without holding
/// the global cache mutex during file I/O or copying its decryption key.
pub struct ProofCacheReservation {
	key: ProofCacheKey,
	slot: Arc<Mutex<Option<TxProof>>>,
	committed: bool,
}

impl ProofCacheReservation {
	/// Run a fallible operation with mutable access to the reserved proof.
	///
	/// Only the per-proof slot is locked while `operation` runs; the global cache
	/// mutex remains available to listener maintenance and context teardown.
	pub fn with_proof_mut<R>(
		&mut self,
		operation: impl FnOnce(&mut TxProof) -> Result<R, Error>,
	) -> Result<R, Error> {
		let mut slot = self.slot.lock();
		let proof = slot.as_mut().ok_or_else(|| {
			Error::Lifecycle("Reserved transaction proof is missing from its cache slot".to_owned())
		})?;
		operation(proof)
	}

	/// Permanently remove the proof after the operation using it has committed.
	pub fn commit(mut self) {
		let mut map = SLATE_PROOFS.lock();
		let is_same_slot = map
			.get(&self.key)
			.is_some_and(|cached| Arc::ptr_eq(&cached.proof, &self.slot));
		if is_same_slot {
			map.remove(&self.key);
		}
		self.committed = true;
		drop(map);
	}
}

impl Drop for ProofCacheReservation {
	fn drop(&mut self) {
		if self.committed {
			return;
		}

		let mut map = SLATE_PROOFS.lock();
		let Some(cached) = map.get_mut(&self.key) else {
			// Explicit context/listener teardown removed the slot while it was
			// reserved, so the proof must not be resurrected.
			return;
		};
		if !Arc::ptr_eq(&cached.proof, &self.slot) {
			return;
		}

		cached.reserved = false;
		// Time spent in durable storage must not consume the retry window.
		cached.expires_at = Instant::now() + SLATE_PROOFS_TTL;
	}
}

/// Reserve a cached proof for a fallible finalize operation.
///
/// The returned guard releases its reservation on every error/unwind path. A
/// second concurrent reservation for the same slate is rejected rather than
/// falling through to a proof-less finalize.
pub fn reserve_proof_for_slate(
	context_id: u32,
	uuid: &uuid::Uuid,
) -> Result<Option<ProofCacheReservation>, Error> {
	let key = (context_id, uuid.clone());
	let mut map = SLATE_PROOFS.lock();
	prune_expired_proofs_locked(&mut map, Instant::now());
	let Some(cached) = map.get_mut(&key) else {
		return Ok(None);
	};
	if cached.reserved {
		return Err(Error::Lifecycle(format!(
			"Transaction proof for slate {} is already reserved",
			uuid
		)));
	}
	if cached.proof.lock().is_none() {
		return Err(Error::Lifecycle(format!(
			"Transaction proof for slate {} is missing from its cache slot",
			uuid
		)));
	}
	cached.reserved = true;
	let slot = cached.proof.clone();
	Ok(Some(ProofCacheReservation {
		key,
		slot,
		committed: false,
	}))
}

/// Get txProof form the mem storage. At step we suppose to Finalize
pub fn pop_proof_for_slate(context_id: u32, uuid: &uuid::Uuid) -> Option<TxProof> {
	let mut map = SLATE_PROOFS.lock();
	prune_expired_proofs_locked(&mut map, Instant::now());
	let key = (context_id, uuid.clone());
	let proof = {
		let cached = map.get(&key)?;
		if cached.reserved {
			return None;
		}
		cached.proof.lock().take()
	};
	if proof.is_some() {
		map.remove(&key);
	}
	proof
}

/// Remove a txProof from the mem storage, e.g. when slate processing failed
pub fn remove_proof_for_slate(context_id: u32, uuid: &uuid::Uuid) {
	SLATE_PROOFS.lock().remove(&(context_id, uuid.clone()));
}

/// Remove every transport proof owned by a wallet context.
///
/// Callers that are releasing a context must first stop and join its message
/// handlers so no in-flight request can insert another proof after this clear.
pub fn clear_proofs_for_context(context_id: u32) {
	SLATE_PROOFS
		.lock()
		.retain(|(entry_context_id, _), _| *entry_context_id != context_id);
}

/// Remove only the transport proofs that one listener generation inserted into
/// a wallet context.
///
/// Listener teardown uses this instead of the context-wide clear: a stale
/// listener's last shared reference can be dropped after a replacement
/// listener for the same context has already started, and the replacement's
/// proofs must survive that late teardown.
pub fn clear_proofs_for_context_generation(context_id: u32, generation: u64) {
	SLATE_PROOFS.lock().retain(|(entry_context_id, _), cached| {
		*entry_context_id != context_id || cached.generation != generation
	});
}

/// Tx Proof - the mwc713 based proof that can be made for any address that is a public key.
/// we would like to generalize mwc713 proof implementation to be used in mwc-wallet proof framework with changing
/// of the message to generate signature in receiver wallet.
/// in mwc713 proof signature is generated using json string of  slate; and after upgrade
/// it is generated using three factors: amount,sender address and commitment sum.
///
/// # Proof workflows
///
/// MQS proofs (`version: "version2"`): the receiver signs the message
/// `hex(kernel_commitment) || sender_MQS_address || decimal(amount)` with its
/// secp256k1 payment-proof key (ECDSA, stored in `signature`). The slate is
/// encrypted for the sender's MQS (secp256k1) address into `slate_message`;
/// `key` is the AEAD key, embedded so that anyone can decrypt the slate.
///
/// Tor proofs (`version: "tor"`): the receiver signs the same message bytes
/// with its ed25519 (onion) key (`tor_proof_signature`). The signed message
/// still names the sender's MQS address: the proof framework is built on
/// secp256k1 primitives (the slate encryption ECDH-targets the sender's
/// secp256k1 key), so the sender's onion address cannot occupy that slot.
/// Instead it is carried alongside: appended to the encrypted slate as a
/// `<onion>tor` suffix and stored in `tor_sender_address`.
///
/// # The problem with the Tor sender address
///
/// The receiver's signature authenticates only the kernel, the amount and
/// the sender's MQS address. The onion sender is covered by nothing: `key`
/// is embedded in the proof, so any holder can decrypt the slate, rewrite
/// the `<onion>tor` suffix and `tor_sender_address` consistently, and
/// re-encrypt. Verification used to report that value as the sender, so a
/// proof holder could make a valid proof claim any sender onion address.
///
/// # How proofs are reported
///
/// New Tor proofs carry `tor_sender_signature`: the sender's secp256k1
/// signature over its onion address, made with the payment-proof key whose
/// public key the receiver signed into the message. Verification checks the
/// attestation against that receiver-anchored key, so the onion sender
/// becomes as trustworthy as the MQS identity and is reported as the sender.
///
/// Legacy Tor proofs (created before the attestation existed) have no
/// `tor_sender_signature`. They still verify normally, but only
/// authenticated identities are reported: the sender is shown as the MQS
/// address from the receiver-signed message, clearly labeled as an MQS
/// address even though the payment was sent over Tor. This fallback is
/// downgrade-safe on purpose: stripping an attestation can only degrade the
/// display from onion to MQS, it can never substitute an attacker-chosen
/// address.
// Memory-erasure policy: `Drop` below zeroizes the decryption key of every
// successfully constructed `TxProof`. A derived Serde deserializer can hold a
// plain field temporary and then reject a different malformed or missing field;
// that failure-only copy is intentionally out of scope. It contains only
// rejected caller-supplied bytes, and recovering it requires an independent
// process-memory disclosure. This is the project-wide rule for API/RPC DTOs, so
// do not replace the derive solely to scrub partially constructed values after a
// deserialization error. The exception does not apply to successfully accepted
// values, wallet-derived secrets, or ignored errors.
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct TxProof {
	/// Reciever address.
	#[serde(serialize_with = "ProvableAddress::serialize_as_string")]
	pub address: ProvableAddress,
	/// Message that contain slate data
	pub message: String,
	/// Challenge
	pub challenge: String,
	/// Message & Challenge signature
	pub signature: Option<EcdsaSignature>,
	/// Private key to decrypt the message
	pub key: [u8; 32],
	/// Placeholder
	pub amount: u64,
	/// Placeholder
	pub fee: u64,
	/// Placeholder
	pub inputs: Vec<Commitment>,
	/// Placeholder
	pub outputs: Vec<Commitment>,
	/// added to support the new proof implementation but be backward compatible
	pub version: Option<String>,
	/// this is the encrypted slate message, contains sender address
	pub slate_message: Option<String>,
	/// Tor (Dalek ed25519) signature
	pub tor_proof_signature: Option<String>,
	/// Tor Sender address
	pub tor_sender_address: Option<String>,
	/// Sender signature over the Tor sender address, made with the secp256k1
	/// payment-proof key. It binds the onion address to the MQS address that
	/// the receiver signs into the proof message, so the onion sender can be
	/// trusted as much as the receiver-signed sender identity.
	pub tor_sender_signature: Option<String>,
}

// Debug is implemented manually so the message decryption key is never disclosed
impl fmt::Debug for TxProof {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("TxProof")
			.field("address", &self.address)
			.field("message", &self.message)
			.field("challenge", &self.challenge)
			.field("signature", &self.signature)
			.field("key", &"[redacted]")
			.field("amount", &self.amount)
			.field("fee", &self.fee)
			.field("inputs", &self.inputs)
			.field("outputs", &self.outputs)
			.field("version", &self.version)
			.field("slate_message", &self.slate_message)
			.field("tor_proof_signature", &self.tor_proof_signature)
			.field("tor_sender_address", &self.tor_sender_address)
			.field("tor_sender_signature", &self.tor_sender_signature)
			.finish()
	}
}

// The key field holds the message decryption key and must not linger in memory
impl Drop for TxProof {
	fn drop(&mut self) {
		self.key.zeroize();
	}
}

/// Vefiry proof resulting data
#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct VerifyProofResult {
	/// Sender address
	pub sender_address: String,
	/// Reciever address
	pub reciever_address: String,
	/// Transaction amount
	pub amount: u64,
	/// Outputs, not necessary all of them belong to the reciever, change outputs can be included
	pub outputs: Vec<String>,
	/// Tx kernel
	pub kernel: String,
	/// Slate as a string. Exactly how it was stored in the proof
	pub slate: String,
}

impl TxProof {
	/// Verify this Proof. Note, message needs checking by caller.
	/// Return: authenticated sender address (the MQS destination from the
	/// encrypted message), Slate, and the decrypted slate string. For Tor
	/// proofs the onion sender is only trustworthy when the sender's
	/// attestation is present (verified here against the MQS destination);
	/// legacy proofs without it must be presented with the MQS sender.
	pub fn verify_extract(
		&self,
		context_id: u32,
		secp: &Secp256k1,
		expected_destination: Option<&ProvableAddress>,
	) -> Result<(ProvableAddress, Slate, String), Error> {
		// Versioned proofs are generated by signing exactly the payment proof
		// message with an empty challenge (TxProof::from_slate,
		// tx::create_payment_proof_signature). The signature below covers
		// message||challenge while every semantic check afterwards reads only
		// self.message, so a non-empty challenge would let a proof holder shift
		// signed bytes (e.g. amount digits) out of the authenticated message
		// without invalidating the receiver signature. Legacy mwc713 proofs (no
		// version) sign message||challenge and keep that behavior.
		if self.version.is_some() && !self.challenge.is_empty() {
			return Err(Error::TxProofVerify(
				"versioned proof must have an empty challenge".into(),
			));
		}

		let mut challenge = String::new();
		challenge.push_str(self.message.as_str());
		challenge.push_str(self.challenge.as_str());

		let mut tor_proof = false;
		if let Some(version) = &self.version {
			if version.eq("tor") {
				tor_proof = true;
			}
		}
		// Tor sender metadata is only ever present on Tor proofs generated by
		// this wallet; on any other proof its presence indicates tampering.
		if !tor_proof && (self.tor_sender_address.is_some() || self.tor_sender_signature.is_some())
		{
			return Err(Error::TxProofVerify(
				"tor sender metadata is only valid for tor proofs".into(),
			));
		}
		if tor_proof {
			if let Some(signature) = &self.tor_proof_signature {
				let dalek_sig_vec = mwc_util::from_hex(&signature).map_err(|e| {
					Error::TxProofVerify(format!(
						"Unable to deserialize tor payment proof signature, {}",
						e
					))
				})?;

				let dalek_sig_bytes: [u8; 64] =
					dalek_sig_vec.as_slice().try_into().map_err(|_| {
						Error::TxProofVerify(format!(
							"Unable to deserialize tor payment proof receiver signature, wrong length {}",
							dalek_sig_vec.len()
						))
					})?;

				let dalek_sig = ed25519_dalek::Signature::from_bytes(&dalek_sig_bytes);

				let receiver_dalek_pub_key =
					canonical_tor_receiver_public_key(&self.address, context_id, secp)?;
				// Strict verification only: payment proofs are generated by
				// this wallet with an honest signer, so permissive-only
				// signatures (low-order R, weak keys) are never legitimate.
				if let Err(e) =
					receiver_dalek_pub_key.verify_strict(&challenge.as_bytes(), &dalek_sig)
				{
					return Err(Error::PaymentProof(format!(
						"Invalid proof signature, {}",
						e
					)))?;
				};
			} else {
				// A missing Tor signature must fail exactly like a missing secp
				// signature below. The proof supplies its own AEAD key and
				// encrypted slate, so without a verified receiver signature
				// everything after this point is attacker-controlled.
				return Err(Error::TxProofVerifySignature(
					"empty tor proof signature!".into(),
				));
			}
		} else {
			let public_key = self.address.public_key(secp, context_id).map_err(|e| {
				Error::TxProofVerify(format!(
					"Unable to build public key from address {}, {}",
					crate::types::escape_for_display(&self.address.public_key),
					e
				))
			})?;
			if let Some(signature) = &self.signature {
				crypto::verify_signature(&challenge, &signature, &public_key, secp)
					.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;
			} else {
				return Err(Error::TxProofVerifySignature(format!(
					"empty proof signature!"
				)));
			}
		}

		let encrypted_message: EncryptedMessage;
		if let Some(_version) = &self.version {
			//this is the newer version tx_proof
			// self.message is attacker-controlled; escape it before embedding it
			// in errors because callers may send those errors directly to output.
			encrypted_message = serde_json::from_str(
				&self
					.slate_message
					.clone()
					.ok_or(Error::PaymentProof("slate_message is empty".into()))?,
			)
			.map_err(|e| {
				Error::TxProofVerify(format!(
					"Fail to convert Json to EncryptedMessage {}, {}",
					crate::types::escape_for_display(&self.message),
					e
				))
			})?;
		} else {
			encrypted_message = serde_json::from_str(&self.message.clone()).map_err(|e| {
				Error::TxProofVerify(format!(
					"Fail to convert proof message Json to EncryptedMessage {}, {}",
					crate::types::escape_for_display(&self.message),
					e
				))
			})?;
		}

		// TODO: at some point, make this check required
		let destination = &encrypted_message.destination; //sender address

		if let Some(expected_destination) = expected_destination {
			if destination.public_key != expected_destination.public_key {
				return Err(Error::TxProofVerifyDestination(
					crate::types::escape_for_display(&expected_destination.public_key),
					crate::types::escape_for_display(&destination.public_key),
				));
			}
		}

		let mut decrypted_message = encrypted_message
			.decrypt_with_key(&self.key)
			.map_err(|e| Error::TxProofVerify(format!("Unable to decrypt message, {}", e)))?;
		//the decrypted_message cloud have been appended with the _<torkey>tor
		let mut tor_key = "tor".to_string();
		if decrypted_message.ends_with("tor") {
			let leng = decrypted_message.len();
			if leng <= 59 {
				return Err(Error::TxProofVerify(format!(
					"Unable to build Slate form proof message"
				)));
			}
			// The preceding length check proves the 59-byte Tor suffix fits.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the message length is checked greater than the 59-byte suffix"
			)]
			let tor_key_start = leng - 59;
			tor_key = decrypted_message
				.get(tor_key_start..)
				.ok_or_else(|| Error::TxProofVerify("Invalid Tor suffix boundary".to_owned()))?
				.to_owned();
			// truncate() panics if byte 56 splits a multibyte character, and
			// the decrypted message is attacker-controlled.
			tor_key = tor_key
				.get(..56)
				.ok_or_else(|| Error::TxProofVerify("Invalid Tor key boundary".to_owned()))?
				.to_owned();
			decrypted_message.truncate(tor_key_start); //remove the "tor" and tor_key from the elnd
		}

		let slate =
			Slate::deserialize_upgrade_plain(context_id, &decrypted_message).map_err(|e| {
				Error::TxProofVerify(format!("Unable to build Slate form proof message, {}", e))
			})?;
		if tor_proof {
			// The onion address is sender-provided data. Legacy tor proofs carry
			// it without any authentication, so it is consistency-checked here
			// but must not be reported as the sender (callers report the
			// authenticated MQS destination instead).
			if let Some(onion_addr) = self.tor_sender_address.clone() {
				if tor_key != "tor" && tor_key != onion_addr {
					return Err(Error::TxProofVerifySender(
						crate::types::escape_for_display(&tor_key),
						crate::types::escape_for_display(&onion_addr),
					));
				}
				ProvableAddress::from_str(secp, context_id, &onion_addr).map_err(|e| {
					Error::TxProofVerify(format!("Unable to create sender onion address, {}", e))
				})?;
			}
			// Newer proofs authenticate the onion address through the sender's
			// own attestation: the sender signs the onion address with the
			// secp256k1 key behind the MQS destination from the encrypted
			// message. verify_tx_proof anchors that MQS address to the
			// receiver-signed proof message, which makes the onion sender as
			// trustworthy as the receiver-signed sender identity. Proofs
			// without the attestation are legacy and fall back to the MQS
			// sender at presentation time.
			if let Some(attestation) = self.tor_sender_signature.as_ref() {
				let onion_addr = self.tor_sender_address.clone().ok_or_else(|| {
					Error::TxProofVerify(
						"tor sender address signature without the sender address".into(),
					)
				})?;
				let attestation = crypto::signature_from_string(attestation, secp)?;
				let sender_public_key = destination.public_key(secp, context_id).map_err(|e| {
					Error::TxProofVerify(format!("Unable to build proof sender public key, {}", e))
				})?;
				crypto::verify_signature(&onion_addr, &attestation, &sender_public_key, secp)
					.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;
			}
		}
		// This public proof API exports an owned slate string. Keep the plaintext
		// guarded until verification succeeds and ownership passes to its caller.
		Ok((
			destination.clone(),
			slate,
			std::mem::take(&mut *decrypted_message),
		))
	}

	/// Build proof data. message suppose to be slate.
	pub fn from_response(
		context_id: u32,
		from: &ProvableAddress,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: &ProvableAddress,
		secp: &Secp256k1,
	) -> Result<(Slate, TxProof), Error> {
		let address = from;

		// MQS input has not been authenticated yet. Escape fields before embedding
		// them in errors because callers may send those errors directly to output.
		let signature = mwc_util::from_hex(&signature).map_err(|e| {
			Error::TxProofVerify(format!(
				"Unable to build signature from HEX {}, {}",
				crate::types::bounded_escape_for_display(
					&signature,
					MAX_RESPONSE_ERROR_DISPLAY_LEN,
				),
				e
			))
		})?;
		let signature = EcdsaSignature::from_der(secp, &signature)
			.map_err(|e| Error::TxProofVerify(format!("Unable to build signature, {}", e)))?;

		let public_key = address.public_key(secp, context_id).map_err(|e| {
			Error::TxProofVerify(format!(
				"Unable to build public key for address {}, {}",
				address, e
			))
		})?;

		let encrypted_message: EncryptedMessage = serde_json::from_str(&message).map_err(|e| {
			Error::TxProofVerify(format!(
				"Unable to build message fom HEX {}, {}",
				crate::types::bounded_escape_for_display(&message, MAX_RESPONSE_ERROR_DISPLAY_LEN,),
				e
			))
		})?;
		let key = encrypted_message
			.key(&public_key, secret_key, secp)
			.map_err(|e| Error::TxProofVerify(format!("Unable to build a signature, {}", e)))?;

		let proof = TxProof {
			address: address.clone(),
			message,
			challenge,
			signature: Some(signature),
			key: *key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: None,
			slate_message: None,
			tor_proof_signature: None,
			tor_sender_address: None,
			tor_sender_signature: None,
		};

		let (_, slate, _) = proof.verify_extract(context_id, secp, Some(expected_destination))?;

		Ok((slate, proof))
	}

	/// Build proof data from slate
	pub fn from_slate(
		context_id: u32,
		message: String,
		slate: &Slate,
		secret_key: &SecretKey,
		expected_destination: &ProvableAddress, //sender address
		tor_destination: Option<String>,        //tor onion address
		secp: &Secp256k1,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<TxProof, Error> {
		if let Some(p) = slate.payment_proof.clone() {
			if let Some(signature) = p.receiver_signature {
				//build the signature from signature string:
				if p.receiver_address.public_key.len() == ONION_V3_ADDRESS_LEN {
					let address = p.receiver_address;

					let _public_key =
						canonical_tor_receiver_public_key(&address, context_id, secp)?;

					//build the encrypted message from the slate
					//and generate the key.

					let version = slate.lowest_version();
					let slate = VersionedSlate::into_version_plain(context_id, slate, version)
						.map_err(|e| {
							Error::TxProofVerify(format!("Slate serialization error, {}", e))
						})?;

					let mut slate_json_with_tor = serde_json::to_string(&slate).map_err(|e| {
						Error::TxProofVerify(format!("Unable to serialize slate, {}", e))
					})?;
					if let Some(tor_des) = tor_destination.clone() {
						slate_json_with_tor = slate_json_with_tor + &tor_des + "tor";
					}
					let sender_public_key = expected_destination
						.public_key(secp, context_id)
						.map_err(|e| {
							Error::TxProofVerify(format!(
								"Unable to build sender public key, {}",
								e
							))
						})?;

					let encrypted_message = EncryptedMessage::new(
						slate_json_with_tor,
						expected_destination, //this is the sender address
						&sender_public_key,
						&secret_key,
						secp,
						#[cfg(feature = "test-support")]
						use_test_rng,
					)
					.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

					let message_ser = &serde_json::to_string(&encrypted_message).map_err(|e| {
						Error::TxProofVerify(format!("Unable to serialize encrypted slate, {}", e))
					})?;
					let key = encrypted_message
						.key(&sender_public_key, secret_key, secp)
						.map_err(|e| {
							Error::TxProofVerify(format!("Unable to build a signature, {}", e))
						})?;

					//create the tor address for the sender wallet.

					// Authenticate the sender onion address: sign it with the
					// payment-proof secret key. The receiver signature anchors
					// the matching MQS address into the proof message, so this
					// attestation makes the onion sender as trustworthy as the
					// receiver-signed sender identity.
					let tor_sender_signature = match &tor_destination {
						Some(tor_des) => Some(
							crypto::sign_challenge(tor_des, secret_key, secp)
								.map_err(|e| {
									Error::TxProofVerify(format!(
										"Unable to sign tor sender address, {}",
										e
									))
								})?
								.to_hex(secp)
								.map_err(|e| {
									Error::TxProofVerify(format!(
										"Unable to serialize tor sender address signature, {}",
										e
									))
								})?,
						),
						None => None,
					};

					let proof = TxProof {
						address: address.clone(),
						message,
						challenge: "".to_string(),
						signature: None,
						key: *key,
						amount: 0,
						fee: 0,
						inputs: vec![],
						outputs: vec![],
						version: Some("tor".to_string()),
						slate_message: Some(message_ser.to_string()),
						tor_proof_signature: Some(signature),
						tor_sender_address: tor_destination,
						tor_sender_signature,
					};
					proof.verify_extract(context_id, secp, Some(expected_destination))?;
					Ok(proof)
				} else {
					let address = p.receiver_address;
					let signature = mwc_util::from_hex(&signature).map_err(|e| {
						Error::TxProofVerify(format!(
							"Unable to build signature from HEX {}, {}",
							crate::types::bounded_escape_for_display(
								&signature,
								MAX_FROM_SLATE_ERROR_DISPLAY_LEN,
							),
							e
						))
					})?;
					let signature = EcdsaSignature::from_der(secp, &signature).map_err(|e| {
						Error::TxProofVerify(format!("Unable to build signature, {}", e))
					})?;

					let _public_key = address.public_key(secp, context_id).map_err(|e| {
						Error::TxProofVerify(format!(
							"Unable to build payment-proof receiver public key, {}",
							e
						))
					})?;

					//build the encrypted message from the slate
					//and generate the key.

					let version = slate.lowest_version();
					let slate = VersionedSlate::into_version_plain(context_id, slate, version)
						.map_err(|e| {
							Error::TxProofVerify(format!("Slate serialization error, {}", e))
						})?;

					let slate_json = serde_json::to_string(&slate).map_err(|e| {
						Error::TxProofVerify(format!("Unable to serialize slate, {}", e))
					})?;
					let sender_public_key = expected_destination
						.public_key(secp, context_id)
						.map_err(|e| {
							Error::TxProofVerify(format!(
								"Unable to build sender public key, {}",
								e
							))
						})?;
					let encrypted_message = EncryptedMessage::new(
						slate_json,
						expected_destination, //this is the sender address when receiver wallet sends the slate back
						&sender_public_key,
						&secret_key,
						secp,
						#[cfg(feature = "test-support")]
						use_test_rng,
					)
					.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

					let message_ser = &serde_json::to_string(&encrypted_message).map_err(|e| {
						Error::TxProofVerify(format!("Unable to serialize encrypted slate, {}", e))
					})?;
					let key = encrypted_message
						.key(&sender_public_key, secret_key, secp)
						.map_err(|e| {
							Error::TxProofVerify(format!("Unable to build a signature, {}", e))
						})?;

					let proof = TxProof {
						address: address.clone(),
						message,
						challenge: "".to_string(),
						signature: Some(signature),
						key: *key,
						amount: 0,
						fee: 0,
						inputs: vec![],
						outputs: vec![],
						version: Some("version2".to_string()),
						slate_message: Some(message_ser.to_string()),
						tor_proof_signature: None,
						tor_sender_address: None,
						tor_sender_signature: None,
					};
					proof.verify_extract(context_id, secp, Some(expected_destination))?;
					Ok(proof)
				}
			} else {
				return Err(Error::TxProofVerify(
					"No receiver signature in payment proof in slate".to_string(),
				));
			}
		} else {
			return Err(Error::TxProofVerify(
				"No pyament proof in slate".to_string(),
			));
		}
	}

	/// Init proff files storage
	pub fn init_proof_backend(data_file_dir: &str) -> Result<(), Error> {
		let stored_tx_proof_path = path::Path::new(data_file_dir).join(TX_PROOF_SAVE_DIR);
		mwc_util::file::ensure_owner_only_dir_all(&stored_tx_proof_path).map_err(|e| {
			Error::Backend(format!(
				"Couldn't create wallet backend tx proof storage directory {}, {}",
				stored_tx_proof_path.to_string_lossy(),
				e
			))
		})?;
		Ok(())
	}

	fn stored_tx_proof_filename(uuid: &str) -> Result<String, Error> {
		let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
			Error::PaymentProofParsing(
				"Transaction proof identifier must be a valid UUID".to_owned(),
			)
		})?;
		Ok(format!("{}.proof", uuid))
	}

	fn read_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<Zeroizing<String>, Error> {
		let filename = Self::stored_tx_proof_filename(uuid)?;
		let tx_proof_file = path::Path::new(data_file_dir)
			.join(TX_PROOF_SAVE_DIR)
			.join(filename);
		let mut tx_proof_f = match File::open(&tx_proof_file) {
			Ok(file) => file,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
				return Err(Error::TransactionHasNoProof(
					tx_proof_file.display().to_string(),
				));
			}
			Err(e) => {
				return Err(Error::IO(format!(
					"Unable to open transaction proof at {}, {}",
					tx_proof_file.display(),
					e
				)));
			}
		};

		let file_size = tx_proof_f.metadata()?.len();
		let capacity: usize = file_size.try_into().map_err(|e| {
			Error::DataOverflow(format!(
				"Stored transaction proof size does not fit usize, size={} error={}",
				file_size, e
			))
		})?;
		let mut content = Zeroizing::new(String::with_capacity(capacity));
		tx_proof_f.read_to_string(&mut *content).map_err(|e| {
			Error::IO(format!(
				"Unable to read transaction proof at {}, {}",
				tx_proof_file.display(),
				e
			))
		})?;
		Ok(content)
	}

	/// Return whether a proof accepted by the canonical legacy `TxProof`
	/// deserializer is stored. Only a missing file is false; invalid identifiers,
	/// permission, I/O, UTF-8, and JSON errors are propagated.
	pub fn has_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<bool, Error> {
		match Self::get_stored_tx_proof(data_file_dir, uuid) {
			Ok(_) => Ok(true),
			Err(Error::TransactionHasNoProof(_)) => Ok(false),
			Err(e) => Err(e),
		}
	}

	/// Read stored proof file. data_file_dir
	pub fn get_stored_tx_proof(data_file_dir: &str, uuid: &str) -> Result<TxProof, Error> {
		let content = Self::read_stored_tx_proof(data_file_dir, uuid)?;
		serde_json::from_str(content.as_str())
			.map_err(|e| Error::TxProofVerify(format!("Unable to build TxProof from JSON, {}", e)))
	}

	/// Store tx proof at the file.
	pub fn store_tx_proof(&self, data_file_dir: &str, uuid: &str) -> Result<(), Error> {
		let filename = Self::stored_tx_proof_filename(uuid)?;
		let proof_dir = path::Path::new(data_file_dir).join(TX_PROOF_SAVE_DIR);
		mwc_util::file::ensure_owner_only_dir_all(&proof_dir).map_err(|e| {
			Error::IO(format!(
				"Unable to create transaction proof directory {}, {}",
				proof_dir.display(),
				e
			))
		})?;
		let proof_path = proof_dir.join(filename);
		replace_owner_only_file_with(&proof_path, |replacement| {
			serde_json::to_writer(replacement, self).map_err(Into::into)
		})
		.map_err(|e| {
			Error::IO(format!(
				"Unable to serialize or store transaction proof at {}, {}",
				proof_path.display(),
				e
			))
		})?;
		Ok(())
	}
}

///support mwc713 payment proof message
pub fn proof_ok(context_id: u32, proof_result: &VerifyProofResult) {
	// Proof fields are peer-controlled (a proof holder can re-encrypt a
	// doctored slate with the key embedded in the proof). Escape control
	// characters before printing so a crafted proof cannot inject terminal
	// escape sequences or forge log layout.
	let sender_address = crate::types::escape_for_display(&proof_result.sender_address);
	let reciever_address = crate::types::escape_for_display(&proof_result.reciever_address);

	// Format each party by its own address type. The sender is an onion
	// address only for Tor proofs whose attestation bound it to the
	// receiver-signed MQS identity; otherwise it is the authenticated MQS
	// address and must not be rendered as an onion URL.
	let sender_message = if proof_result.sender_address.len() == 56 {
		format!(
			" from [{}{}{}]",
			"http://".bright_green(),
			sender_address.bright_green(),
			".onion".bright_green()
		)
	} else {
		format!(" from [{}]", sender_address.bright_green())
	};

	if proof_result.reciever_address.len() == 56 {
		println!(
			"this file proves that [{}] MWCs was sent to [{}]{}",
			amount_to_hr_string(proof_result.amount, false).bright_green(),
			format!(
				"{}{}{}",
				"http://".bright_green(),
				reciever_address.bright_green(),
				".onion".bright_green()
			),
			sender_message
		);
	} else {
		println!(
			"this file proves that [{}] MWCs was sent to [{}]{}",
			amount_to_hr_string(proof_result.amount, false).bright_green(),
			reciever_address.bright_green(),
			sender_message
		);
	}

	// Legacy Tor proofs predate the sender attestation: the payment was sent
	// over Tor, but the proof authenticates only the sender's MQS address, so
	// say so explicitly instead of letting it read as the Tor sender.
	if proof_result.reciever_address.len() == 56 && proof_result.sender_address.len() != 56 {
		println!(
			"{}: the sender address above is an MQS address, not the Tor address used for the transaction. This legacy Tor proof does not authenticate the sender's Tor (onion) address.",
			"NOTE".bright_yellow()
		);
	}

	println!("\noutputs:");
	if global::is_mainnet(context_id) {
		for output in &proof_result.outputs {
			println!(
				"   {}: https://explorer.mwc.mw/#o{}",
				output.bright_magenta(),
				output
			);
		}
		println!("kernel:");
		println!(
			"   {}: https://explorer.mwc.mw/#k{}",
			proof_result.kernel.bright_magenta(),
			proof_result.kernel
		);
	} else {
		for output in &proof_result.outputs {
			println!(
				"   {}: https://explorer.floonet.mwc.mw/#o{}",
				output.bright_magenta(),
				output
			);
		}
		println!("kernel:");
		println!(
			"   {}: https://explorer.floonet.mwc.mw/#k{}",
			proof_result.kernel.bright_magenta(),
			proof_result.kernel
		);
	}

	println!(
		"slate: {}",
		crate::types::escape_for_display(&proof_result.slate)
	);

	println!(
		"\n{}: this proof should only be considered valid if the kernel is actually on-chain with sufficient confirmations",
		"WARNING".bright_yellow()
	);
	println!("please use a mwc block explorer to verify this is the case.");
}

/// Verify a payment proof using the legacy mwc713-compatible format.
///
/// This format intentionally authenticates the transaction kernel, sender
/// address, and amount. Those fields are sufficient for the payment-proof
/// claim once the kernel is confirmed on-chain; the carried slate and output
/// list are auxiliary compatibility data rather than additional signed claims.
pub fn verify_tx_proof(
	context_id: u32,
	tx_proof: &TxProof,
	secp: &Secp256k1,
) -> Result<
	(
		ProvableAddress,           // from address
		ProvableAddress,           // to address
		u64,                       // amount
		Vec<pedersen::Commitment>, // outputs
		pedersen::Commitment,      // transaction kernel that was signed
		String,                    // slate as a string
	),
	Error,
> {
	let (sender_address, slate, slate_str) = tx_proof
		.verify_extract(context_id, secp, None)
		.map_err(|e| {
			Error::TxProofVerify(format!("Unable to extract destination and slate, {}", e))
		})?;

	if slate.fee != tx_proof.fee {
		return Err(Error::TxProofVerify("fee value doesn't match slate".into()));
	}

	if slate.amount != tx_proof.amount {
		return Err(Error::TxProofVerify(
			"amount value doesn't match slate".into(),
		));
	}

	// Validating amount & address against signed message.
	let versioned_proof = tx_proof.version.is_some();
	let mut kernel: Option<Commitment> = None;
	if versioned_proof {
		sender_address
			.validate_mqs(secp, context_id)
			.map_err(|_| Error::TxProofVerify("Invalid proof sender address".into()))?;
		let tx = slate
			.tx
			.as_ref()
			.ok_or_else(|| Error::TxProofVerify("Slate doesn't contain transaction".into()))?;
		let tx_kernel = match tx.body.kernels.as_slice() {
			[tx_kernel] => tx_kernel,
			kernels => {
				return Err(Error::TxProofVerify(format!(
					"Versioned proof slate must contain exactly one transaction kernel, kernel_count={}",
					kernels.len()
				)));
			}
		};
		let expected_message = tx::payment_proof_message(
			tx_proof.amount,
			&tx_kernel.excess,
			sender_address.public_key.clone(),
		)?;
		if tx_proof.message != expected_message {
			return Err(Error::TxProofVerify(
				"Invalid message, amount, slate".into(),
			));
		}
		kernel = Some(tx_kernel.excess.clone());
	}

	let inputs_ex = tx_proof.inputs.iter().collect::<HashSet<_>>();

	let tx_input_commits = slate
		.tx_or_err()?
		.inputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	let mut inputs: Vec<pedersen::Commitment> = tx_input_commits
		.into_iter()
		.filter(|c| !inputs_ex.contains(c))
		.collect();

	let outputs_ex = tx_proof.outputs.iter().collect::<HashSet<_>>();

	let tx_output_commits = slate
		.tx_or_err()?
		.outputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	let tx_output_set: HashSet<_> = tx_output_commits.iter().cloned().collect();
	let mut outputs: Vec<pedersen::Commitment> = tx_output_commits
		.into_iter()
		.filter(|c| !outputs_ex.contains(c))
		.collect();

	let excess_parts: Vec<&PublicKey> = slate
		.participant_data
		.iter()
		.map(|p| &p.public_blind_excess)
		.collect();
	let excess_sum = PublicKey::from_combination(secp, excess_parts)
		.map_err(|e| Error::TxProofVerify(format!("Unable to combine public keys, {}", e)))?;

	// Validating if amount is correct
	let commit_amount = secp.commit_value(tx_proof.amount)?;
	inputs.push(commit_amount);

	let mut input_com: Vec<pedersen::Commitment> = slate
		.tx_or_err()?
		.inputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;
	let mut output_com: Vec<pedersen::Commitment> = slate
		.tx_or_err()?
		.outputs_committed()?
		.collect::<Result<Vec<_>, _>>()?;

	let slate_offset = slate.tx_or_err()?.offset.clone();
	if slate_offset != BlindingFactor::zero() {
		let offset_skey = slate_offset.secret_key(secp)?;
		let offset_pubkey = PublicKey::from_secret_key(secp, &offset_skey)?;
		input_com.push(Commitment::from_pubkey(secp, &offset_pubkey)?);
	}

	output_com.push(secp.commit_value(slate.fee)?);

	let excess_sum_com = Secp256k1::commit_sum(secp, output_com, input_com)?;

	// A proof holder has the slate-encryption key and can re-encrypt modified
	// contents. Bind the recomputed body excess to the kernel authenticated by
	// the receiver's signature instead of trusting internal slate consistency.
	if versioned_proof && kernel.as_ref() != Some(&excess_sum_com) {
		return Err(Error::TxProofVerify(
			"Slate transaction excess does not match receiver-authenticated kernel".into(),
		));
	}

	if excess_sum_com.to_pubkey(secp)? != excess_sum {
		return Err(Error::TxProofVerify("Invalid slate".into()));
	}

	if slate.compact_slate {
		for o in &tx_proof.outputs {
			// tx_proof.outputs is unsigned proof data. Only commitments that
			// are actually part of the transaction may be presented as its
			// outputs; anything else is an injected forgery.
			if !tx_output_set.contains(o) {
				return Err(Error::TxProofVerify(
					"proof output is not part of the slate transaction".into(),
				));
			}
			outputs.push(o.clone());
		}
	} else {
		// Participant order is not fixed; ID 1 identifies the receiver.
		let excess = &slate
			.participant_data
			.iter()
			.find(|participant| participant.id == 1)
			.ok_or_else(|| {
				Error::TxProofVerify(format!(
					"TxProof::verify_extract, receiver participant is missing, participant_count={}",
					slate.participant_data.len()
				))
			})?
			.public_blind_excess;
		let commit_excess = secp.commit_sum(outputs.clone(), inputs)?;
		let pubkey_excess = commit_excess.to_pubkey(secp)?;

		if *excess != pubkey_excess {
			return Err(Error::TxProofVerify("Invalid amount".into()));
		}
	}

	if !versioned_proof {
		if slate.compact_slate {
			return Err(Error::TxProofVerify(
				"Legacy proof with invalid compact slate".into(),
			));
		}

		kernel = Some(excess_sum_com);
	}

	Ok((
		sender_address,
		tx_proof.address.clone(), // reciever address
		tx_proof.amount,
		outputs,
		kernel.ok_or(Error::PaymentProof("Unable to extract kernel".into()))?,
		slate_str,
	))
}

///to support mwc713 payment proof verification
pub fn verify_tx_proof_wrapper(
	context_id: u32,
	tx_proof: &TxProof,
	secp: &Secp256k1,
) -> Result<VerifyProofResult, Error> {
	let (sender, receiver, amount, outputs, excess_sum, slate_str) =
		verify_tx_proof(context_id, tx_proof, secp)?;

	let outputs = outputs.iter().map(|o| mwc_util::to_hex(&o.0)).collect();

	// The verified sender is the MQS address the receiver signed into the
	// proof message. For Tor proofs that carry the sender's attestation,
	// verify_extract has cryptographically bound the onion address to that
	// same MQS identity, so the onion address can be shown instead (mwc713
	// display convention). Legacy Tor proofs have no attestation: report the
	// authenticated MQS sender, never their unauthenticated onion metadata.
	let sender_address = match &tx_proof.tor_sender_signature {
		Some(_) => match &tx_proof.tor_sender_address {
			Some(onion_address) => onion_address.clone(),
			None => sender.public_key,
		},
		None => sender.public_key,
	};

	Ok(VerifyProofResult {
		sender_address,
		reciever_address: receiver.public_key,
		amount,
		outputs,
		kernel: excess_sum.to_hex(secp)?,
		slate: slate_str,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::ed25519_dalek::{Signer, Verifier};
	use mwc_wallet_util::mwc_crates::hex;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	use std::fs;
	use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

	static NEXT_PROOF_CACHE_TEST_CONTEXT: AtomicU32 = AtomicU32::new(u32::MAX - 500_000);

	fn proof_cache_test_context() -> u32 {
		NEXT_PROOF_CACHE_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed)
	}

	fn assert_terminal_safe_error(error: Error) -> String {
		let message = error.to_string();
		assert!(
			!message.chars().any(char::is_control),
			"error contains terminal control characters: {:?}",
			message
		);
		message
	}

	fn build_tor_tx_proof(
		address_key: &ed25519_dalek::VerifyingKey,
		signature_hex: String,
	) -> TxProof {
		TxProof {
			address: ProvableAddress::from_tor_pub_key(address_key).unwrap(),
			message: "payment".to_string(),
			challenge: String::new(),
			signature: None,
			key: [0u8; 32],
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: Some("tor".to_string()),
			slate_message: None,
			tor_proof_signature: Some(signature_hex),
			tor_sender_address: None,
			tor_sender_signature: None,
		}
	}

	fn proof_cache_test_proof(key: u8) -> TxProof {
		let signing_key = ed25519_dalek::SigningKey::from_bytes(&[key; 32]);
		let mut proof = build_tor_tx_proof(&signing_key.verifying_key(), "00".repeat(64));
		proof.key = [key; 32];
		proof
	}

	fn proof_is_cached(context_id: u32, slate_id: &uuid::Uuid) -> bool {
		SLATE_PROOFS
			.lock()
			.contains_key(&(context_id, slate_id.clone()))
	}

	fn cached_proof_key_address(context_id: u32, slate_id: &uuid::Uuid) -> usize {
		let map = SLATE_PROOFS.lock();
		let cached = map
			.get(&(context_id, slate_id.clone()))
			.expect("proof must be cached");
		let slot = cached.proof.lock();
		slot.as_ref()
			.expect("cached proof slot must be populated")
			.key
			.as_ptr() as usize
	}

	#[test]
	fn proof_cache_generation_exhaustion_does_not_wrap() {
		let counter = AtomicU64::new(u64::MAX - 1);
		assert_eq!(
			allocate_proof_cache_generation(&counter).unwrap(),
			u64::MAX - 1
		);
		assert!(matches!(
			allocate_proof_cache_generation(&counter),
			Err(Error::DataOverflow(_))
		));
		assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
	}

	#[test]
	fn proof_cache_reservation_releases_proof_after_storage_error() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate(context_id, generation, &slate_id, proof_cache_test_proof(9)),
			ProofInsertResult::Inserted
		);

		{
			let mut reservation = reserve_proof_for_slate(context_id, &slate_id)
				.unwrap()
				.expect("cached proof must be reservable");
			// The entry remains present while reserved, so a concurrent
			// listener cannot replace the proof being finalized.
			assert_eq!(
				push_proof_for_slate(
					context_id,
					generation,
					&slate_id,
					proof_cache_test_proof(10)
				),
				ProofInsertResult::Duplicate
			);
			assert!(matches!(
				reserve_proof_for_slate(context_id, &slate_id),
				Err(Error::Lifecycle(_))
			));
			assert!(pop_proof_for_slate(context_id, &slate_id).is_none());

			let dir = tempdir().unwrap();
			let not_a_directory = dir.path().join("not-a-directory");
			fs::write(&not_a_directory, b"file blocks proof directory creation").unwrap();
			assert!(
				reservation
					.with_proof_mut(|proof| {
						proof.store_tx_proof(
							not_a_directory.to_str().unwrap(),
							&slate_id.to_string(),
						)
					})
					.is_err()
			);
		}

		let released = pop_proof_for_slate(context_id, &slate_id)
			.expect("failed persistence must release the cached proof");
		assert_eq!(released.key, [9; 32]);
	}

	#[test]
	fn proof_cache_reservation_commit_removes_proof() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		assert_eq!(
			push_proof_for_slate(
				context_id,
				generation,
				&slate_id,
				proof_cache_test_proof(11)
			),
			ProofInsertResult::Inserted
		);

		reserve_proof_for_slate(context_id, &slate_id)
			.unwrap()
			.expect("cached proof must be reservable")
			.commit();

		assert!(!proof_is_cached(context_id, &slate_id));
		assert!(pop_proof_for_slate(context_id, &slate_id).is_none());
	}

	#[test]
	fn proof_cache_reservation_keeps_key_in_stable_slot() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate(
				context_id,
				generation,
				&slate_id,
				proof_cache_test_proof(12)
			),
			ProofInsertResult::Inserted
		);

		let before_reservation = cached_proof_key_address(context_id, &slate_id);
		let mut reservation = reserve_proof_for_slate(context_id, &slate_id)
			.unwrap()
			.expect("cached proof must be reservable");
		let while_reserved = reservation
			.with_proof_mut(|proof| Ok(proof.key.as_ptr() as usize))
			.unwrap();
		assert_eq!(while_reserved, before_reservation);

		drop(reservation);
		assert_eq!(
			cached_proof_key_address(context_id, &slate_id),
			before_reservation
		);
		remove_proof_for_slate(context_id, &slate_id);
	}

	#[test]
	fn proof_cache_reservation_prevents_ttl_pruning_until_release() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate_with_ttl(
				context_id,
				generation,
				&slate_id,
				proof_cache_test_proof(13),
				Duration::from_millis(25),
			),
			ProofInsertResult::Inserted
		);

		let reservation = reserve_proof_for_slate(context_id, &slate_id)
			.unwrap()
			.expect("cached proof must be reservable");
		std::thread::sleep(Duration::from_millis(50));
		prune_expired_proofs();
		assert!(proof_is_cached(context_id, &slate_id));

		drop(reservation);
		let proof = pop_proof_for_slate(context_id, &slate_id)
			.expect("released reservation must refresh the proof TTL");
		assert_eq!(proof.key, [13; 32]);
	}

	#[test]
	fn stale_reservation_cannot_release_replacement_slot() {
		let context_id = proof_cache_test_context();
		let old_generation = next_proof_cache_generation().unwrap();
		let new_generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate(
				context_id,
				old_generation,
				&slate_id,
				proof_cache_test_proof(14)
			),
			ProofInsertResult::Inserted
		);
		let stale_reservation = reserve_proof_for_slate(context_id, &slate_id)
			.unwrap()
			.expect("old proof must be reservable");

		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate(
				context_id,
				new_generation,
				&slate_id,
				proof_cache_test_proof(15)
			),
			ProofInsertResult::Inserted
		);
		let replacement_reservation = reserve_proof_for_slate(context_id, &slate_id)
			.unwrap()
			.expect("replacement proof must be reservable");

		drop(stale_reservation);
		assert!(matches!(
			reserve_proof_for_slate(context_id, &slate_id),
			Err(Error::Lifecycle(_))
		));

		drop(replacement_reservation);
		let proof = pop_proof_for_slate(context_id, &slate_id)
			.expect("replacement reservation must remain intact");
		assert_eq!(proof.key, [15; 32]);
	}

	#[test]
	fn proof_cache_prunes_expired_entries_on_insert() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let expired_slate = uuid::Uuid::new_v4();
		let new_slate = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate_with_ttl(
				context_id,
				generation,
				&expired_slate,
				proof_cache_test_proof(1),
				Duration::from_millis(25),
			),
			ProofInsertResult::Inserted
		);
		assert!(proof_is_cached(context_id, &expired_slate));
		std::thread::sleep(Duration::from_millis(50));

		assert_eq!(
			push_proof_for_slate(
				context_id,
				generation,
				&new_slate,
				proof_cache_test_proof(2)
			),
			ProofInsertResult::Inserted
		);
		assert!(!proof_is_cached(context_id, &expired_slate));
		assert!(proof_is_cached(context_id, &new_slate));
		remove_proof_for_slate(context_id, &new_slate);
	}

	#[test]
	fn periodic_proof_cache_maintenance_expires_idle_entry() {
		let context_id = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let slate_id = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate_with_ttl(
				context_id,
				generation,
				&slate_id,
				proof_cache_test_proof(3),
				Duration::from_millis(25),
			),
			ProofInsertResult::Inserted
		);
		std::thread::sleep(Duration::from_millis(50));

		prune_expired_proofs();

		assert!(!proof_is_cached(context_id, &slate_id));
	}

	#[test]
	fn clearing_a_proof_context_does_not_touch_other_contexts() {
		let cleared_context = proof_cache_test_context();
		let retained_context = proof_cache_test_context();
		let generation = next_proof_cache_generation().unwrap();
		let cleared_slate = uuid::Uuid::new_v4();
		let retained_slate = uuid::Uuid::new_v4();
		assert_eq!(
			push_proof_for_slate(
				cleared_context,
				generation,
				&cleared_slate,
				proof_cache_test_proof(2)
			),
			ProofInsertResult::Inserted
		);
		assert_eq!(
			push_proof_for_slate(
				retained_context,
				generation,
				&retained_slate,
				proof_cache_test_proof(3)
			),
			ProofInsertResult::Inserted
		);

		clear_proofs_for_context(cleared_context);

		assert!(!proof_is_cached(cleared_context, &cleared_slate));
		assert!(proof_is_cached(retained_context, &retained_slate));
		assert_eq!(
			pop_proof_for_slate(retained_context, &retained_slate)
				.expect("other context's proof must remain")
				.key,
			[3; 32]
		);
	}

	#[test]
	fn stale_generation_clear_preserves_replacement_listener_proofs() {
		let context_id = proof_cache_test_context();
		let old_generation = next_proof_cache_generation().unwrap();
		let new_generation = next_proof_cache_generation().unwrap();
		let old_slate = uuid::Uuid::new_v4();
		let new_slate = uuid::Uuid::new_v4();
		clear_proofs_for_context(context_id);
		assert_eq!(
			push_proof_for_slate(
				context_id,
				old_generation,
				&old_slate,
				proof_cache_test_proof(4)
			),
			ProofInsertResult::Inserted
		);
		// The replacement listener starts while the stale generation is still
		// alive and inserts its own proofs into the same context.
		assert_eq!(
			push_proof_for_slate(
				context_id,
				new_generation,
				&new_slate,
				proof_cache_test_proof(5)
			),
			ProofInsertResult::Inserted
		);

		// The stale generation's last reference is dropped only now.
		clear_proofs_for_context_generation(context_id, old_generation);

		assert!(!proof_is_cached(context_id, &old_slate));
		assert!(proof_is_cached(context_id, &new_slate));

		// Synchronized wallet-context release still clears everything.
		clear_proofs_for_context(context_id);
		assert!(!proof_is_cached(context_id, &new_slate));
	}

	#[test]
	fn stored_proof_paths_require_uuid_and_only_missing_is_false() {
		let dir = tempdir().unwrap();
		let data_file_dir = dir.path().to_str().unwrap();
		let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let mut proof = build_tor_tx_proof(&signing_key.verifying_key(), "00".repeat(64));
		proof.key = [42u8; 32];
		let valid_id = uuid::Uuid::new_v4().to_string();
		let missing_id = uuid::Uuid::new_v4().to_string();
		let invalid_json_id = uuid::Uuid::new_v4().to_string();
		let invalid_utf8_id = uuid::Uuid::new_v4().to_string();

		proof.store_tx_proof(data_file_dir, &valid_id).unwrap();
		assert!(TxProof::has_stored_tx_proof(data_file_dir, &valid_id).unwrap());
		assert_eq!(
			TxProof::get_stored_tx_proof(data_file_dir, &valid_id)
				.unwrap()
				.key,
			[42u8; 32]
		);
		assert!(!TxProof::has_stored_tx_proof(data_file_dir, &missing_id).unwrap());
		assert!(matches!(
			TxProof::get_stored_tx_proof(data_file_dir, &missing_id),
			Err(Error::TransactionHasNoProof(_))
		));

		let proof_dir = dir.path().join(TX_PROOF_SAVE_DIR);
		fs::write(proof_dir.join(format!("{}.proof", invalid_json_id)), b"{").unwrap();
		assert!(matches!(
			TxProof::has_stored_tx_proof(data_file_dir, &invalid_json_id),
			Err(Error::TxProofVerify(_))
		));

		fs::write(proof_dir.join(format!("{}.proof", invalid_utf8_id)), [0xff]).unwrap();
		assert!(matches!(
			TxProof::has_stored_tx_proof(data_file_dir, &invalid_utf8_id),
			Err(Error::IO(_))
		));

		for invalid_id in ["../outside", "/tmp/outside", "not-a-uuid"] {
			assert!(matches!(
				TxProof::has_stored_tx_proof(data_file_dir, invalid_id),
				Err(Error::PaymentProofParsing(_))
			));
		}
		assert!(matches!(
			proof.store_tx_proof(data_file_dir, "../outside"),
			Err(Error::PaymentProofParsing(_))
		));
	}

	// The tor payment proof signature must pass strict ed25519 verification.
	// With a canonical, non-weak key a signer can still craft a signature
	// with a low-order R (here the identity point): choosing s = k·a makes
	// the permissive equation -[k]A + [s]B = identity = R hold. Permissive
	// verification accepts it, strict verification rejects the low-order R,
	// and so must the tx proof.
	#[test]
	fn tor_payment_proof_requires_strict_signature() {
		use mwc_wallet_util::mwc_crates::digest::Digest;
		use mwc_wallet_util::mwc_crates::num_bigint::BigUint;
		use mwc_wallet_util::mwc_crates::sha2::Sha512;

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let message = b"payment"; // self.message; the challenge must be empty

		let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let vk = sk.verifying_key();
		assert!(!vk.is_weak());

		// ed25519 group order L
		let l = BigUint::from_bytes_le(&[
			0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
			0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x10,
		]);

		// secret scalar a = clamp(SHA512(seed)[..32])
		let mut a_bytes = [0u8; 32];
		let mut h = Sha512::new();
		h.update([7u8; 32]);
		a_bytes.copy_from_slice(&h.finalize()[..32]);
		a_bytes[0] &= 248;
		a_bytes[31] &= 63;
		a_bytes[31] |= 64;
		let a = BigUint::from_bytes_le(&a_bytes);

		// R = identity, k = SHA512(R || A || M) mod L, s = k·a mod L
		let mut r_bytes = [0u8; 32];
		r_bytes[0] = 1;
		let mut h = Sha512::new();
		h.update(r_bytes);
		h.update(vk.as_bytes());
		h.update(message);
		let k = BigUint::from_bytes_le(&h.finalize()) % &l;
		let s = (k * a) % &l;
		let mut s_bytes = s.to_bytes_le();
		s_bytes.resize(32, 0);

		let mut sig_bytes = [0u8; 64];
		sig_bytes[..32].copy_from_slice(&r_bytes);
		sig_bytes[32..].copy_from_slice(&s_bytes);
		let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

		// The permissive verifier accepts this signature...
		assert!(vk.verify(message, &sig).is_ok());
		// ...while strict verification rejects it.
		assert!(vk.verify_strict(message, &sig).is_err());

		// The tx proof must side with the strict verifier.
		let proof = build_tor_tx_proof(&vk, hex::encode(sig_bytes));
		let err = proof
			.verify_extract(0, &secp, None)
			.err()
			.expect("a low-order-R signature must be rejected");
		assert!(
			format!("{}", err).contains("Invalid proof signature"),
			"unexpected error: {}",
			err
		);

		// An honestly generated signature must keep verifying. The proof fails
		// later (its slate message is a placeholder), but not at the signature
		// check.
		let honest_sig = sk.sign(message);
		assert!(vk.verify_strict(message, &honest_sig).is_ok());

		let proof = build_tor_tx_proof(&vk, hex::encode(honest_sig.to_bytes()));
		if let Err(e) = proof.verify_extract(0, &secp, None) {
			assert!(
				!format!("{}", e).contains("Invalid proof signature"),
				"honest signature was rejected: {}",
				e
			);
		}
	}

	#[test]
	fn from_response_escapes_untrusted_fields_in_parse_errors() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let address = ProvableAddress::from_pub_key(&secp, 0, &public_key).unwrap();
		let terminal_payload = "\n\u{1b}]52;c;payload\u{7}\rspoof\u{202e}bidi\u{202c}\u{2028}line";
		let escaped_payload =
			r"\u000a\u001b]52;c;payload\u0007\u000dspoof\u202ebidi\u202c\u2028line";

		let signature_error = TxProof::from_response(
			0,
			&address,
			"{}".to_string(),
			"".to_string(),
			format!("00{}", terminal_payload),
			&secret_key,
			&address,
			&secp,
		)
		.err()
		.expect("the malformed signature must fail to parse");
		assert!(assert_terminal_safe_error(signature_error).contains(escaped_payload));

		let signature = crypto::sign_challenge("", &secret_key, &secp)
			.unwrap()
			.to_hex(&secp)
			.unwrap();
		let message_error = TxProof::from_response(
			0,
			&address,
			format!("not-json{}", terminal_payload),
			"".to_string(),
			signature,
			&secret_key,
			&address,
			&secp,
		)
		.err()
		.expect("the malformed message must fail to parse");
		assert!(assert_terminal_safe_error(message_error).contains(escaped_payload));

		// A syntactically valid encrypted-message envelope reaches key derivation
		// before verify_extract authenticates the outer signature. Its nested salt
		// must therefore be escaped at the point where the decode error is built.
		let salt_message = serde_json::json!({
			"destination": &address,
			"encrypted_message": "",
			"salt": format!("00{}", terminal_payload),
			"nonce": "",
		})
		.to_string();
		let salt_signature = crypto::sign_challenge(&salt_message, &secret_key, &secp)
			.unwrap()
			.to_hex(&secp)
			.unwrap();
		let salt_error = TxProof::from_response(
			0,
			&address,
			salt_message,
			"".to_string(),
			salt_signature,
			&secret_key,
			&address,
			&secp,
		)
		.err()
		.expect("the malformed salt must fail to decode");
		assert!(assert_terminal_safe_error(salt_error).contains(escaped_payload));
	}

	#[test]
	fn from_response_bounds_untrusted_fields_in_parse_errors() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let address = ProvableAddress::from_pub_key(&secp, 0, &public_key).unwrap();
		let omitted_tail = "OMITTED_UNTRUSTED_TAIL";

		let oversized_signature = format!(
			"zz{}{}",
			"a".repeat(MAX_RESPONSE_ERROR_DISPLAY_LEN + 32),
			omitted_tail
		);
		let signature_error = TxProof::from_response(
			0,
			&address,
			"{}".to_string(),
			String::new(),
			oversized_signature,
			&secret_key,
			&address,
			&secp,
		)
		.err()
		.expect("the malformed signature must fail to parse");
		let signature_error = assert_terminal_safe_error(signature_error);
		assert!(signature_error.contains("...[truncated]"));
		assert!(!signature_error.contains(omitted_tail));

		let parseable_signature = crypto::sign_challenge("", &secret_key, &secp)
			.unwrap()
			.to_hex(&secp)
			.unwrap();
		let oversized_message = format!(
			"not-json{}{}",
			"a".repeat(MAX_RESPONSE_ERROR_DISPLAY_LEN + 32),
			omitted_tail
		);
		let message_error = TxProof::from_response(
			0,
			&address,
			oversized_message,
			String::new(),
			parseable_signature,
			&secret_key,
			&address,
			&secp,
		)
		.err()
		.expect("the malformed message must fail to parse");
		let message_error = assert_terminal_safe_error(message_error);
		assert!(message_error.contains("...[truncated]"));
		assert!(!message_error.contains(omitted_tail));
	}

	#[test]
	fn from_slate_errors_do_not_echo_untrusted_payment_proof_fields() {
		use crate::slate::PaymentInfo;

		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let sender_address = ProvableAddress::from_pub_key(&secp, 0, &public_key).unwrap();
		let terminal_payload = "\n\u{1b}]52;c;payload\u{7}\rspoof\u{202e}bidi\u{202c}\u{2028}line";
		let omitted_tail = "OMITTED_UNTRUSTED_TAIL";

		let mut slate = Slate::blank(2, false).unwrap();
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_address.clone(),
			receiver_address: sender_address.clone(),
			receiver_signature: Some(format!(
				"zz{}{}{}",
				terminal_payload,
				"a".repeat(MAX_FROM_SLATE_ERROR_DISPLAY_LEN + 32),
				omitted_tail
			)),
		});
		let signature_error = TxProof::from_slate(
			0,
			String::new(),
			&slate,
			&secret_key,
			&sender_address,
			None,
			&secp,
			#[cfg(feature = "test-support")]
			true,
		)
		.err()
		.expect("the malformed receiver signature must fail");
		let signature_error = assert_terminal_safe_error(signature_error);
		assert!(signature_error.contains("...[truncated]"));
		assert!(!signature_error.contains(omitted_tail));

		let oversized_address = format!(
			"{}{}{}",
			terminal_payload,
			"a".repeat(MAX_FROM_SLATE_ERROR_DISPLAY_LEN + 32),
			omitted_tail
		);
		let parseable_signature = crypto::sign_challenge("", &secret_key, &secp)
			.unwrap()
			.to_hex(&secp)
			.unwrap();
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_address.clone(),
			receiver_address: ProvableAddress {
				public_key: oversized_address.clone(),
				domain: String::new(),
				port: None,
			},
			receiver_signature: Some(parseable_signature),
		});
		let address_error = TxProof::from_slate(
			0,
			String::new(),
			&slate,
			&secret_key,
			&sender_address,
			None,
			&secp,
			#[cfg(feature = "test-support")]
			true,
		)
		.err()
		.expect("the malformed receiver address must fail");
		let address_error = assert_terminal_safe_error(address_error);
		assert!(!address_error.contains(&oversized_address));
		assert!(!address_error.contains(omitted_tail));
	}

	#[test]
	fn tor_proof_rejects_noncanonical_receiver_representations() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let verifying_key = signing_key.verifying_key();
		let canonical = ProvableAddress::from_tor_pub_key(&verifying_key).unwrap();
		let signature = hex::encode(signing_key.sign(b"payment").to_bytes());
		let alternatives = [
			mwc_util::to_hex(verifying_key.as_bytes()),
			canonical.public_key.to_uppercase(),
			format!("http://{}.onion/path", canonical.public_key),
		];

		for alternative in alternatives {
			let alternative_address = ProvableAddress {
				public_key: alternative,
				domain: String::new(),
				port: None,
			};
			assert_eq!(
				alternative_address.tor_public_key().unwrap(),
				verifying_key,
				"the general Tor parser must demonstrate the alternate representation"
			);

			let mut proof = build_tor_tx_proof(&verifying_key, signature.clone());
			proof.address = alternative_address;
			let error = proof
				.verify_extract(0, &secp, None)
				.err()
				.expect("a noncanonical Tor receiver address must be rejected");
			assert!(
				error.to_string().contains("receiver address"),
				"unexpected error: {}",
				error
			);
		}
	}

	// A Tor proof without a signature must fail like a secp proof without one:
	// the proof carries its own decryption key, so skipping the signature
	// check makes every later verification step attacker-controlled.
	#[test]
	fn tor_proof_requires_signature() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let mut proof = build_tor_tx_proof(&signing_key.verifying_key(), "00".repeat(64));
		proof.tor_proof_signature = None;
		let err = proof
			.verify_extract(0, &secp, None)
			.err()
			.expect("a tor proof without a signature must be rejected");
		assert!(
			format!("{}", err).contains("empty tor proof signature"),
			"unexpected error: {}",
			err
		);
	}

	// verify_extract embeds attacker-controlled proof fields in errors; they
	// must be escaped so verification errors are safe to print and log.
	#[test]
	fn verify_extract_escapes_untrusted_fields_in_errors() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[9; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let address = ProvableAddress::from_pub_key(&secp, 0, &public_key).unwrap();
		let terminal_payload = "\n\u{1b}]52;c;payload\u{7}\rspoof";
		let escaped_payload = r"\u000a\u001b]52;c;payload\u0007\u000dspoof";

		// The proof message is echoed in slate_message parse errors.
		let message = format!("proof{}", terminal_payload);
		let signature = crypto::sign_challenge(&message, &secret_key, &secp).unwrap();
		let message_error = TxProof {
			address: address.clone(),
			message,
			challenge: String::new(),
			signature: Some(signature),
			key: [0u8; 32],
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: Some("version2".to_string()),
			slate_message: Some("not-json".to_string()),
			tor_proof_signature: None,
			tor_sender_address: None,
			tor_sender_signature: None,
		}
		.verify_extract(0, &secp, None)
		.err()
		.expect("the malformed slate message must fail to parse");
		assert!(assert_terminal_safe_error(message_error).contains(escaped_payload));

		// So is the encrypted message when it fails to decode from hex.
		let slate_message = format!(
			r#"{{"destination":"{}","encrypted_message":"0z\u000a\u001bz","salt":"","nonce":""}}"#,
			address.public_key
		);
		let hex_error = TxProof {
			address,
			message: "payment".to_string(),
			challenge: String::new(),
			signature: Some(crypto::sign_challenge("payment", &secret_key, &secp).unwrap()),
			key: [0u8; 32],
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			version: Some("version2".to_string()),
			slate_message: Some(slate_message),
			tor_proof_signature: None,
			tor_sender_address: None,
			tor_sender_signature: None,
		}
		.verify_extract(0, &secp, None)
		.err()
		.expect("the non-hex encrypted message must fail to decode");
		assert!(assert_terminal_safe_error(hex_error).contains(r"0z\u000a\u001bz"));
	}

	// Builds an honest Tor payment proof for a compact slate exactly the way
	// the sender wallet does in verify_slate_payment_proof, over a fully
	// balanced synthetic transaction. Also returns the sender key material so
	// tests can rewrite the proof the way a malicious holder would.
	fn build_compact_tor_proof(
		secp: &Secp256k1,
	) -> (
		TxProof,
		String,
		String,
		Commitment,
		Commitment,
		u64,
		ProvableAddress,
		SecretKey,
	) {
		use crate::slate::{ParticipantData, PaymentInfo};
		use mwc_wallet_util::mwc_core::core::transaction::{
			CommitWrapper, Inputs, Output, OutputFeatures, OutputIdentifier, Transaction, TxKernel,
		};
		use mwc_wallet_util::mwc_crates::secp::pedersen::RangeProof;

		let sender_secret = SecretKey::from_slice(secp, &[11u8; 32]).unwrap();
		let sender_mqs = ProvableAddress::from_pub_key(
			secp,
			0,
			&PublicKey::from_secret_key(secp, &sender_secret).unwrap(),
		)
		.unwrap();
		let sender_onion = mwc_util::OnionV3Address::from_private(&sender_secret.0)
			.unwrap()
			.to_ov3_str();

		let receiver_dalek = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
		let receiver_onion =
			ProvableAddress::from_tor_pub_key(&receiver_dalek.verifying_key()).unwrap();

		let amount = 5_000_000_000u64;
		let fee = 1_000_000u64;

		let input_commit = secp
			.commit(
				amount + fee,
				SecretKey::from_slice(secp, &[5u8; 32]).unwrap(),
			)
			.unwrap();
		let output_commit = secp
			.commit(amount, SecretKey::from_slice(secp, &[7u8; 32]).unwrap())
			.unwrap();
		// outputs + fee - inputs = (ro - ri) * G: the excess the participant
		// blind excesses must combine to for the commitment-sum check.
		let excess_commit = Secp256k1::commit_sum(
			secp,
			vec![output_commit.clone(), secp.commit_value(fee).unwrap()],
			vec![input_commit.clone()],
		)
		.unwrap();
		let excess_pubkey = excess_commit.to_pubkey(secp).unwrap();

		let mut transaction = Transaction::empty();
		transaction.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(input_commit)]);
		transaction.body.outputs.push(Output {
			identifier: OutputIdentifier {
				features: OutputFeatures::Plain,
				commit: output_commit.clone(),
			},
			proof: RangeProof::zero(),
		});
		let mut kernel = TxKernel::empty().unwrap();
		kernel.excess = excess_commit.clone();
		transaction.body.kernels.push(kernel);

		let mut slate = Slate::blank(2, true).unwrap();
		slate.amount = amount;
		slate.fee = fee;
		slate.tx = Some(transaction);
		slate.participant_data.push(ParticipantData {
			id: 0,
			public_blind_excess: excess_pubkey,
			public_nonce: PublicKey::from_secret_key(
				secp,
				&SecretKey::from_slice(secp, &[8u8; 32]).unwrap(),
			)
			.unwrap(),
			part_sig: None,
			message: None,
			message_sig: None,
		});

		// Generation signs the message containing the 52-character MQS sender
		// and stores the 56-character onion address as display-only data.
		let message =
			tx::payment_proof_message(amount, &excess_commit, sender_mqs.public_key.clone())
				.unwrap();
		let signature = receiver_dalek.sign(message.as_bytes());
		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_mqs.clone(),
			receiver_address: receiver_onion.clone(),
			receiver_signature: Some(hex::encode(signature.to_bytes())),
		});

		let mut proof = TxProof::from_slate(
			0,
			message,
			&slate,
			&sender_secret,
			&sender_mqs,
			Some(sender_onion.clone()),
			&secp,
			#[cfg(feature = "test-support")]
			true,
		)
		.expect("an honest tor proof must build");
		// from_slate leaves the placeholders zeroed; the sender wallet fills
		// them from its context before storing (api_impl/owner.rs).
		proof.amount = amount;
		proof.fee = fee;
		(
			proof,
			sender_onion,
			receiver_onion.public_key,
			output_commit,
			excess_commit,
			amount,
			sender_mqs,
			sender_secret,
		)
	}

	// End-to-end Tor payment proof: the sender's attestation binds the onion
	// address to the receiver-signed MQS identity, so the onion address is
	// reported as the sender.
	#[test]
	fn compact_tor_proof_verifies_end_to_end() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (proof, sender_onion, receiver_onion, output_commit, excess_commit, amount, _, _) =
			build_compact_tor_proof(&secp);

		assert!(proof.tor_sender_signature.is_some());
		let result = verify_tx_proof_wrapper(0, &proof, &secp)
			.expect("an honest tor payment proof must verify");
		assert_eq!(result.sender_address, sender_onion);
		assert_eq!(result.reciever_address, receiver_onion);
		assert_eq!(result.amount, amount);
		assert_eq!(result.outputs, vec![mwc_util::to_hex(&output_commit.0)]);
		assert_eq!(result.kernel, mwc_util::to_hex(&excess_commit.0));
	}

	// tx_proof.outputs is unsigned proof data: for compact slates every entry
	// must be a commitment that is actually part of the slate transaction.
	#[test]
	fn compact_proof_rejects_outputs_not_in_slate() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		// An unrelated but otherwise valid commitment must be rejected even
		// though it does not disturb any signature or commitment-sum check.
		let (mut proof, _, _, _, _, _, _, _) = build_compact_tor_proof(&secp);
		let junk = secp
			.commit(42, SecretKey::from_slice(&secp, &[42u8; 32]).unwrap())
			.unwrap();
		proof.outputs = vec![junk];
		let err = verify_tx_proof(0, &proof, &secp)
			.err()
			.expect("an output that is not part of the transaction must be rejected");
		assert!(
			format!("{}", err).contains("not part of the slate transaction"),
			"unexpected error: {}",
			err
		);

		// The sender's real change output stays acceptable: it is in the slate.
		let (mut proof, _, _, output_commit, _, _, _, _) = build_compact_tor_proof(&secp);
		proof.outputs = vec![output_commit.clone()];
		let (_, _, _, outputs, _, _) = verify_tx_proof(0, &proof, &secp)
			.expect("a change output that is part of the transaction must verify");
		assert_eq!(outputs, vec![output_commit]);
	}

	// Re-encrypts the proof's slate message after applying `mutate` to the
	// plaintext (slate JSON plus the `<onion>tor` suffix), exactly the way a
	// proof holder would: the AEAD key is embedded in the proof, so the
	// encrypted slate is holder-mutable.
	fn rewrite_encrypted_slate(
		secp: &Secp256k1,
		proof: &mut TxProof,
		sender_mqs: &ProvableAddress,
		sender_secret: &SecretKey,
		mutate: impl FnOnce(&mut String),
	) {
		let em: EncryptedMessage =
			serde_json::from_str(proof.slate_message.as_ref().unwrap()).unwrap();
		let mut plain = em.decrypt_with_key(&proof.key).unwrap();
		mutate(&mut plain);
		let sender_pub = sender_mqs.public_key(secp, 0).unwrap();
		let em = EncryptedMessage::new(
			std::mem::take(&mut *plain),
			sender_mqs,
			&sender_pub,
			sender_secret,
			secp,
			#[cfg(feature = "test-support")]
			true,
		)
		.unwrap();
		proof.slate_message = Some(serde_json::to_string(&em).unwrap());
		proof.key = *em.key(&sender_pub, sender_secret, secp).unwrap();
	}

	// The receiver signature authenticates the transaction kernel in the
	// payment-proof message. A holder must not be able to replace the slate's
	// body excess and participant aggregate while retaining that signed kernel.
	#[test]
	fn versioned_proof_rejects_body_excess_not_bound_to_signed_kernel() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut proof, _, _, _, _, _, sender_mqs, sender_secret) = build_compact_tor_proof(&secp);

		// The honest synthetic slate has body excess 2*G. Replacing its zero
		// transaction offset with 1 makes the body excess 1*G; replacing the
		// participant aggregate with 1*G kept the old checks internally
		// consistent even though the receiver signed the unchanged 2*G kernel.
		let mut one_bytes = [0u8; 32];
		one_bytes[31] = 1;
		let one_secret = SecretKey::from_slice(&secp, &one_bytes).unwrap();
		let one_public = PublicKey::from_secret_key(&secp, &one_secret).unwrap();
		let offset_hex = mwc_util::to_hex(&one_bytes);
		let public_hex = mwc_util::to_hex(&one_public.serialize_vec(&secp, true).unwrap());
		rewrite_encrypted_slate(
			&secp,
			&mut proof,
			&sender_mqs,
			&sender_secret,
			move |plain| {
				let suffix = plain.split_off(plain.len() - 59);
				let mut json: serde_json::Value = serde_json::from_str(plain).unwrap();
				json["tx"]["offset"] = serde_json::json!(offset_hex);
				json["participant_data"][0]["public_blind_excess"] = serde_json::json!(public_hex);
				*plain = format!("{}{}", json, suffix);
			},
		);

		let err = verify_tx_proof(0, &proof, &secp)
			.err()
			.expect("a body excess different from the signed kernel must be rejected");
		assert!(
			format!("{}", err).contains("receiver-authenticated kernel"),
			"unexpected error: {}",
			err
		);
	}

	// A versioned payment proof has one receiver-authenticated transaction
	// kernel. Extra unsigned kernels would make the selected kernel ambiguous.
	#[test]
	fn versioned_proof_rejects_multiple_transaction_kernels() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut proof, _, _, _, _, _, sender_mqs, sender_secret) = build_compact_tor_proof(&secp);

		rewrite_encrypted_slate(&secp, &mut proof, &sender_mqs, &sender_secret, |plain| {
			let suffix = plain.split_off(plain.len() - 59);
			let mut json: serde_json::Value = serde_json::from_str(plain).unwrap();
			let first_kernel = json["tx"]["body"]["kernels"][0].clone();
			json["tx"]["body"]["kernels"]
				.as_array_mut()
				.unwrap()
				.push(first_kernel);
			*plain = format!("{}{}", json, suffix);
		});

		let err = verify_tx_proof(0, &proof, &secp)
			.err()
			.expect("a versioned proof with multiple kernels must be rejected");
		assert!(
			format!("{}", err).contains("exactly one transaction kernel"),
			"unexpected error: {}",
			err
		);
	}

	// The receiver signature covers message||challenge while every semantic
	// check reads only message, so shifting amount digits from the message
	// into the challenge used to forge the proven amount without touching the
	// signed bytes. Versioned proofs now require an empty challenge, which
	// makes the signed bytes exactly the checked message.
	#[test]
	fn versioned_proof_rejects_challenge_split_amount_forgery() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut proof, _, _, _, _, _, sender_mqs, sender_secret) = build_compact_tor_proof(&secp);

		// The exact forgery: shift the last 9 digits of the signed amount
		// (5000000000) from the message into the challenge. message||challenge
		// is unchanged, so the receiver signature still verifies; the amount
		// fields and the encrypted slate are doctored to the forged 5 with
		// the key embedded in the proof.
		let split = proof.message.len() - 9;
		proof.challenge = proof.message.get(split..).unwrap().to_string();
		proof.message.truncate(split);
		assert!(proof.message.ends_with('5'));
		proof.amount = 5;
		rewrite_encrypted_slate(&secp, &mut proof, &sender_mqs, &sender_secret, |plain| {
			let suffix = plain.get(plain.len() - 59..).unwrap().to_string();
			plain.truncate(plain.len() - 59);
			let mut json: serde_json::Value = serde_json::from_str(plain).unwrap();
			json["amount"] = serde_json::json!(5u64);
			*plain = format!("{}{}", json, suffix);
		});

		let err = verify_tx_proof(0, &proof, &secp)
			.err()
			.expect("the challenge-split amount forgery must be rejected");
		assert!(
			format!("{}", err).contains("empty challenge"),
			"unexpected error: {}",
			err
		);
	}

	// Legacy Tor proofs (no sender attestation) must keep verifying, but the
	// reported sender is the authenticated MQS address, never the
	// unauthenticated onion metadata.
	#[test]
	fn legacy_tor_proof_reports_authenticated_mqs_sender() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let (mut proof, sender_onion, _, _, _, _, sender_mqs, _) = build_compact_tor_proof(&secp);
		assert!(proof.tor_sender_signature.is_some());

		proof.tor_sender_signature = None;
		let result = verify_tx_proof_wrapper(0, &proof, &secp)
			.expect("a legacy tor proof without attestation must still verify");
		assert_eq!(result.sender_address, sender_mqs.public_key);
		assert_ne!(result.sender_address, sender_onion);
	}

	// A proof holder rewriting the onion sender must fail: the consistency
	// check catches a naive field swap, a consistent rewrite of both the
	// encrypted slate suffix and the field breaks the sender's attestation,
	// and a fresh attestation from an unrelated key is no better.
	#[test]
	fn tor_sender_address_spoof_is_rejected() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let victim_onion = mwc_util::OnionV3Address::from_private(&[9u8; 32])
			.unwrap()
			.to_ov3_str();

		// Naive swap of the unsigned field only. Note verify_tx_proof wraps
		// verify_extract errors, so assert on the sender-mismatch message.
		let (mut proof, _, _, _, _, _, _, _) = build_compact_tor_proof(&secp);
		proof.tor_sender_address = Some(victim_onion.clone());
		let err = verify_tx_proof_wrapper(0, &proof, &secp)
			.err()
			.expect("a naive onion swap must be rejected");
		assert!(
			format!("{}", err).contains("unable to verify sender address"),
			"unexpected error: {}",
			err
		);

		// The audit's attack: rewrite the encrypted slate suffix and the field
		// consistently with the key embedded in the proof. The attestation
		// still covers the original onion, so verification must fail.
		let (mut proof, _, _, _, _, _, sender_mqs, sender_secret) = build_compact_tor_proof(&secp);
		rewrite_encrypted_slate(&secp, &mut proof, &sender_mqs, &sender_secret, |plain| {
			plain.truncate(plain.len() - 59);
			*plain = format!("{}{}tor", plain, victim_onion);
		});
		proof.tor_sender_address = Some(victim_onion.clone());
		let err = verify_tx_proof_wrapper(0, &proof, &secp)
			.err()
			.expect("a consistently rewritten onion must fail the attestation");
		assert!(
			format!("{}", err).contains("ignature"),
			"unexpected error: {}",
			err
		);

		// A fresh attestation made with an unrelated key must fail as well:
		// it does not match the MQS key the receiver signed for.
		let (mut proof, _, _, _, _, _, sender_mqs, sender_secret) = build_compact_tor_proof(&secp);
		rewrite_encrypted_slate(&secp, &mut proof, &sender_mqs, &sender_secret, |plain| {
			plain.truncate(plain.len() - 59);
			*plain = format!("{}{}tor", plain, victim_onion);
		});
		proof.tor_sender_address = Some(victim_onion.clone());
		proof.tor_sender_signature = Some(
			crypto::sign_challenge(
				&victim_onion,
				&SecretKey::from_slice(&secp, &[9u8; 32]).unwrap(),
				&secp,
			)
			.unwrap()
			.to_hex(&secp)
			.unwrap(),
		);
		verify_tx_proof_wrapper(0, &proof, &secp)
			.err()
			.expect("an attestation from an unrelated key must be rejected");
	}

	// Tor sender metadata has no meaning outside Tor proofs; injecting it
	// into a version2 proof is rejected before any other check.
	#[test]
	fn non_tor_proof_rejects_tor_sender_metadata() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
		let mut proof = build_tor_tx_proof(&signing_key.verifying_key(), "00".repeat(64));
		proof.version = Some("version2".to_string());
		proof.tor_sender_address = Some(
			mwc_util::OnionV3Address::from_private(&[9u8; 32])
				.unwrap()
				.to_ov3_str(),
		);
		let err = proof
			.verify_extract(0, &secp, None)
			.err()
			.expect("tor metadata on a non-tor proof must be rejected");
		assert!(
			format!("{}", err).contains("only valid for tor proofs"),
			"unexpected error: {}",
			err
		);
	}
}
