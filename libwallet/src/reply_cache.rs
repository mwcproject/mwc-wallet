// Copyright 2026 The MWC Developers
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

//! Short-lived, process-memory cache for transaction replies.
//!
//! A reply is reusable only by the same authenticated peer over the same
//! transport and only while this wallet remains open. Nothing in this module
//! is persisted. Plain Slatepacks and plain Foreign API requests therefore
//! never acquire replay authority.
//!
//! Like [`crate::slate_process`], this cache relies on the wallet lifecycle
//! invariant that one wallet data directory has only one opened backend.
//! Multiple processes or backend instances over the same wallet directory are
//! unsupported and are not coordinated here.

use crate::{Error, Slate, SlatePurpose, SlateVersion, VersionedSlate};
use mwc_wallet_util::mwc_crates::blake2_rfc::blake2b::blake2b;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::serde::{self, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Replies remain eligible for a retry for fifteen minutes.
pub const REPLY_LIFETIME: Duration = Duration::from_secs(15 * 60);

const IN_FLIGHT_LIFETIME: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 512;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 2 * 1024 * 1024;
const FINGERPRINT_KEY: &[u8] = b"mwc-wallet-reply-request-v1";

/// Authenticated peer and transport to which a reply may be returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyBinding {
	channel: ReplyChannel,
	peer: ReplyPeer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReplyChannel {
	ForeignRpc,
	File,
	Mqs,
	Library,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReplyPeer {
	EncryptedSlatepack([u8; 32]),
	Mqs(String),
}

impl ReplyBinding {
	/// Bind an encrypted Foreign API Slatepack to its verified sender key.
	pub fn foreign_rpc(sender: &ed25519_dalek::VerifyingKey) -> Self {
		Self::encrypted_slatepack(ReplyChannel::ForeignRpc, sender)
	}

	/// Bind an encrypted file Slatepack to its verified sender key.
	pub fn file(sender: &ed25519_dalek::VerifyingKey) -> Self {
		Self::encrypted_slatepack(ReplyChannel::File, sender)
	}

	/// Bind an encrypted embedded-library Slatepack to its verified sender key.
	pub fn library(sender: &ed25519_dalek::VerifyingKey) -> Self {
		Self::encrypted_slatepack(ReplyChannel::Library, sender)
	}

	/// Bind an MWCMQS reply to the authenticated sender address.
	pub fn mqs(sender: String) -> Self {
		Self {
			channel: ReplyChannel::Mqs,
			peer: ReplyPeer::Mqs(sender),
		}
	}

	fn encrypted_slatepack(channel: ReplyChannel, sender: &ed25519_dalek::VerifyingKey) -> Self {
		Self {
			channel,
			peer: ReplyPeer::EncryptedSlatepack(*sender.as_bytes()),
		}
	}
}

/// Immutable request fingerprint and authenticated reply binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyRequest {
	context_id: u32,
	fingerprint: [u8; 32],
	binding: ReplyBinding,
}

#[derive(Serialize)]
#[serde(crate = "serde")]
struct CanonicalRequest<'a> {
	operation: &'static str,
	slate: VersionedSlate,
	destination_account: Option<&'a str>,
	message: Option<&'a str>,
}

impl ReplyRequest {
	/// Fingerprint a receive request before the wallet adds its contribution.
	pub fn receive(
		context_id: u32,
		slate: &Slate,
		binding: ReplyBinding,
		destination_account: Option<&str>,
		message: Option<&str>,
	) -> Result<Self, Error> {
		Self::new(
			context_id,
			slate,
			binding,
			"receive",
			destination_account,
			message,
		)
	}

	/// Fingerprint an invoice response before the wallet finalizes it.
	pub fn finalize_invoice(
		context_id: u32,
		slate: &Slate,
		binding: ReplyBinding,
	) -> Result<Self, Error> {
		Self::new(context_id, slate, binding, "finalize_invoice", None, None)
	}

	fn new(
		context_id: u32,
		slate: &Slate,
		binding: ReplyBinding,
		operation: &'static str,
		destination_account: Option<&str>,
		message: Option<&str>,
	) -> Result<Self, Error> {
		let canonical = CanonicalRequest {
			operation,
			slate: VersionedSlate::into_version_plain(context_id, slate, SlateVersion::V3)?,
			destination_account,
			message,
		};
		let bytes = serde_json::to_vec(&canonical).map_err(|e| {
			Error::SlateSer(format!(
				"Unable to serialize reply request fingerprint, {}",
				e
			))
		})?;
		let digest = blake2b(32, FINGERPRINT_KEY, &bytes);
		let mut fingerprint = [0u8; 32];
		fingerprint.copy_from_slice(digest.as_bytes());
		Ok(Self {
			context_id,
			fingerprint,
			binding,
		})
	}
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplyKey {
	slate_id: Uuid,
	purpose: u8,
}

impl ReplyKey {
	fn new(slate_id: Uuid, purpose: &SlatePurpose) -> Self {
		Self {
			slate_id,
			purpose: purpose.to_int(),
		}
	}
}

enum CacheEntry {
	InFlight {
		request: ReplyRequest,
		started: Instant,
		owner: Arc<()>,
	},
	Ready {
		request: ReplyRequest,
		reply: Slate,
		created: Instant,
		expires: Instant,
		bytes: usize,
	},
}

#[derive(Default)]
struct CacheState {
	entries: HashMap<ReplyKey, CacheEntry>,
	total_bytes: usize,
}

/// Result of reserving a request in the reply cache.
pub enum ReserveResult {
	/// The exact reply is already available for this authenticated request.
	Cached(Slate),
	/// This caller owns the in-flight slot and may build the first reply.
	Reserved(ReplyReservation),
	/// The bounded cache is currently occupied by other in-flight requests.
	Uncached,
}

/// Shared memory cache owned by one opened wallet backend.
pub struct ReplyCache {
	state: Mutex<CacheState>,
}

impl Default for ReplyCache {
	fn default() -> Self {
		Self::new()
	}
}

impl ReplyCache {
	/// Create an empty reply cache.
	pub fn new() -> Self {
		Self {
			state: Mutex::new(CacheState::default()),
		}
	}

	/// Return an existing reply or reserve this request while it is processed.
	pub fn reserve(
		self: &Arc<Self>,
		slate_id: Uuid,
		purpose: SlatePurpose,
		request: ReplyRequest,
	) -> Result<ReserveResult, Error> {
		self.reserve_at(slate_id, purpose, request, Instant::now())
	}

	fn reserve_at(
		self: &Arc<Self>,
		slate_id: Uuid,
		purpose: SlatePurpose,
		request: ReplyRequest,
		now: Instant,
	) -> Result<ReserveResult, Error> {
		let key = ReplyKey::new(slate_id, &purpose);
		let mut state = self.state.lock();
		purge_expired(&mut state, now);

		if let Some(entry) = state.entries.get(&key) {
			return match entry {
				CacheEntry::Ready {
					request: original,
					reply,
					..
				} if *original == request => Ok(ReserveResult::Cached(reply.clone())),
				CacheEntry::InFlight {
					request: original, ..
				} if *original == request => Err(Error::ReceiveReplyInProgress(slate_id.to_string())),
				_ => Err(Error::ReceiveResponseMismatch(slate_id.to_string())),
			};
		}

		if state.entries.len() >= MAX_ENTRIES && !evict_one_oldest_ready(&mut state) {
			return Ok(ReserveResult::Uncached);
		}

		let owner = Arc::new(());
		let context_id = request.context_id;
		state.entries.insert(
			key.clone(),
			CacheEntry::InFlight {
				request: request.clone(),
				started: now,
				owner: Arc::clone(&owner),
			},
		);
		Ok(ReserveResult::Reserved(ReplyReservation {
			cache: Arc::clone(self),
			key,
			request,
			owner,
			context_id,
			active: true,
		}))
	}

	/// Forget every cached and in-flight reply, for example when closing the wallet.
	pub fn clear(&self) {
		let mut state = self.state.lock();
		state.entries.clear();
		state.total_bytes = 0;
	}
}

/// Ownership token for one reply that is currently being built.
pub struct ReplyReservation {
	cache: Arc<ReplyCache>,
	key: ReplyKey,
	request: ReplyRequest,
	owner: Arc<()>,
	context_id: u32,
	active: bool,
}

impl ReplyReservation {
	/// Publish the reply after the corresponding wallet mutation commits.
	///
	/// Oversized or unserializable replies are deliberately not cached; this
	/// never turns a successful first reply into a failed wallet transaction.
	pub fn complete(mut self, reply: &Slate) -> bool {
		let bytes = VersionedSlate::into_version_plain(self.context_id, reply, SlateVersion::V3)
			.and_then(|slate| slate.as_string())
			.ok()
			.and_then(|serialized| {
				// V3 JSON omits compatibility domains, but the cached Slate retains them.
				match reply.payment_proof.as_ref() {
					Some(proof) => serialized
						.len()
						.checked_add(proof.sender_address.domain.len())?
						.checked_add(proof.receiver_address.domain.len()),
					None => Some(serialized.len()),
				}
			});
		self.complete_at(reply, bytes, Instant::now())
	}

	fn complete_at(&mut self, reply: &Slate, bytes: Option<usize>, now: Instant) -> bool {
		let mut state = self.cache.state.lock();
		purge_expired(&mut state, now);
		let owned = matches!(
			state.entries.get(&self.key),
			Some(CacheEntry::InFlight { request, owner, .. })
				if *request == self.request && Arc::ptr_eq(owner, &self.owner)
		);
		if !owned {
			self.active = false;
			return false;
		}
		state.entries.remove(&self.key);

		let Some(bytes) = bytes.filter(|bytes| *bytes <= MAX_ENTRY_BYTES) else {
			self.active = false;
			return false;
		};

		while state
			.total_bytes
			.checked_add(bytes)
			.map(|total| total > MAX_TOTAL_BYTES)
			.unwrap_or(true)
			&& evict_one_oldest_ready(&mut state)
		{}
		if state
			.total_bytes
			.checked_add(bytes)
			.map(|total| total > MAX_TOTAL_BYTES)
			.unwrap_or(true)
		{
			self.active = false;
			return false;
		}

		let expires = now.checked_add(REPLY_LIFETIME).unwrap_or(now);
		state.total_bytes += bytes;
		state.entries.insert(
			self.key.clone(),
			CacheEntry::Ready {
				request: self.request.clone(),
				reply: reply.clone(),
				created: now,
				expires,
				bytes,
			},
		);
		self.active = false;
		true
	}
}

impl Drop for ReplyReservation {
	fn drop(&mut self) {
		if !self.active {
			return;
		}
		let mut state = self.cache.state.lock();
		if matches!(
			state.entries.get(&self.key),
			Some(CacheEntry::InFlight { request, owner, .. })
				if *request == self.request && Arc::ptr_eq(owner, &self.owner)
		) {
			state.entries.remove(&self.key);
		}
	}
}

fn purge_expired(state: &mut CacheState, now: Instant) {
	let expired: Vec<ReplyKey> = state
		.entries
		.iter()
		.filter_map(|(key, entry)| {
			let expired = match entry {
				CacheEntry::InFlight { started, .. } => {
					now.saturating_duration_since(*started) >= IN_FLIGHT_LIFETIME
				}
				CacheEntry::Ready { expires, .. } => now >= *expires,
			};
			expired.then(|| key.clone())
		})
		.collect();
	for key in expired {
		remove_entry(state, &key);
	}
}

fn evict_one_oldest_ready(state: &mut CacheState) -> bool {
	let oldest = state
		.entries
		.iter()
		.filter_map(|(key, entry)| match entry {
			CacheEntry::Ready { created, .. } => Some((key.clone(), *created)),
			CacheEntry::InFlight { .. } => None,
		})
		.min_by_key(|(_, created)| *created)
		.map(|(key, _)| key);
	match oldest {
		Some(key) => {
			remove_entry(state, &key);
			true
		}
		None => false,
	}
}

fn remove_entry(state: &mut CacheState, key: &ReplyKey) {
	if let Some(CacheEntry::Ready { bytes, .. }) = state.entries.remove(key) {
		state.total_bytes = state.total_bytes.saturating_sub(bytes);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::proof::proofaddress::ProvableAddress;
	use crate::slate::PaymentInfo;
	use mwc_wallet_util::mwc_core::global;

	fn request(slate: &Slate, sender_byte: u8) -> Result<ReplyRequest, Error> {
		let sender = ed25519_dalek::SigningKey::from_bytes(&[sender_byte; 32]).verifying_key();
		ReplyRequest::receive(0, slate, ReplyBinding::foreign_rpc(&sender), None, None)
	}

	fn reply_with_domains(sender_bytes: usize, receiver_bytes: usize) -> Result<Slate, Error> {
		let mut reply = Slate::blank(2, false)?;
		reply.payment_proof = Some(PaymentInfo {
			sender_address: ProvableAddress {
				domain: "s".repeat(sender_bytes),
				..ProvableAddress::blank()
			},
			receiver_address: ProvableAddress {
				domain: "r".repeat(receiver_bytes),
				..ProvableAddress::blank()
			},
			receiver_signature: None,
		});
		Ok(reply)
	}

	#[test]
	fn reply_is_bound_to_request_and_sender() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let response = incoming.clone();
		let original = request(&incoming, 7)?;

		let ReserveResult::Reserved(reservation) =
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone())?
		else {
			panic!("first request was not reserved");
		};
		assert!(reservation.complete(&response));

		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone())?,
			ReserveResult::Cached(_)
		));
		assert!(matches!(
			cache.reserve(
				incoming.id,
				SlatePurpose::SendResponse,
				request(&incoming, 8)?
			),
			Err(Error::ReceiveResponseMismatch(_))
		));
		let sender = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
		let other_channel =
			ReplyRequest::receive(0, &incoming, ReplyBinding::file(&sender), None, None)?;
		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, other_channel),
			Err(Error::ReceiveResponseMismatch(_))
		));

		let mut changed = incoming.clone();
		changed.amount = 1;
		assert!(matches!(
			cache.reserve(
				incoming.id,
				SlatePurpose::SendResponse,
				request(&changed, 7)?
			),
			Err(Error::ReceiveResponseMismatch(_))
		));
		Ok(())
	}

	#[test]
	fn reply_expires_after_fixed_fifteen_minutes() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		assert_eq!(REPLY_LIFETIME, Duration::from_secs(900));
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 9)?;
		let started = Instant::now();
		let ReserveResult::Reserved(mut reservation) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original.clone(),
			started,
		)?
		else {
			panic!("first request was not reserved");
		};
		assert!(reservation.complete_at(&incoming, Some(128), started));

		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original.clone(),
				started + REPLY_LIFETIME - Duration::from_secs(1),
			)?,
			ReserveResult::Cached(_)
		));
		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original,
				started + REPLY_LIFETIME,
			)?,
			ReserveResult::Reserved(_)
		));
		Ok(())
	}

	#[test]
	fn dropped_reservation_releases_in_flight_request() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 10)?;
		let reservation =
			match cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone())? {
				ReserveResult::Reserved(reservation) => reservation,
				_ => panic!("first request was not reserved"),
			};
		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone()),
			Err(Error::ReceiveReplyInProgress(_))
		));
		drop(reservation);
		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original)?,
			ReserveResult::Reserved(_)
		));
		Ok(())
	}

	#[test]
	fn expired_reservation_cannot_complete_replacement_slot() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 13)?;
		let started = Instant::now();
		let ReserveResult::Reserved(mut expired) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original.clone(),
			started,
		)?
		else {
			panic!("first request was not reserved");
		};
		let replacement_time = started + IN_FLIGHT_LIFETIME;
		let ReserveResult::Reserved(mut replacement) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original.clone(),
			replacement_time,
		)?
		else {
			panic!("expired request was not replaced");
		};

		assert!(!expired.complete_at(&incoming, Some(128), replacement_time));
		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original.clone(),
				replacement_time,
			),
			Err(Error::ReceiveReplyInProgress(_))
		));
		assert!(replacement.complete_at(&incoming, Some(128), replacement_time));
		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original,
				replacement_time,
			)?,
			ReserveResult::Cached(_)
		));
		Ok(())
	}

	#[test]
	fn expired_reservation_cannot_complete_without_replacement() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 14)?;
		let started = Instant::now();
		let ReserveResult::Reserved(mut reservation) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original.clone(),
			started,
		)?
		else {
			panic!("first request was not reserved");
		};

		let expired = started + IN_FLIGHT_LIFETIME;
		assert!(!reservation.complete_at(&incoming, Some(128), expired));
		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original,
				expired,
			)?,
			ReserveResult::Reserved(_)
		));
		Ok(())
	}

	#[test]
	fn oversized_reply_is_not_cached() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 11)?;
		let ReserveResult::Reserved(mut reservation) =
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone())?
		else {
			panic!("first request was not reserved");
		};
		assert!(!reservation.complete_at(&incoming, Some(MAX_ENTRY_BYTES + 1), Instant::now()));
		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original)?,
			ReserveResult::Reserved(_)
		));
		Ok(())
	}

	#[test]
	fn complete_rejects_oversized_payment_proof_domains() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for (sender_bytes, receiver_bytes) in [
			(MAX_ENTRY_BYTES, 0),
			(0, MAX_ENTRY_BYTES),
			(MAX_ENTRY_BYTES / 2, MAX_ENTRY_BYTES / 2),
		] {
			let cache = Arc::new(ReplyCache::new());
			let reply = reply_with_domains(sender_bytes, receiver_bytes)?;
			let original = request(&reply, 18)?;
			let ReserveResult::Reserved(reservation) =
				cache.reserve(reply.id, SlatePurpose::SendResponse, original.clone())?
			else {
				panic!("first request was not reserved");
			};

			assert!(!reservation.complete(&reply));
			assert_eq!(cache.state.lock().total_bytes, 0);
			assert!(matches!(
				cache.reserve(reply.id, SlatePurpose::SendResponse, original)?,
				ReserveResult::Reserved(_)
			));
		}
		Ok(())
	}

	#[test]
	fn complete_preserves_payment_proof_domains_at_entry_limit() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let mut reply = reply_with_domains(0, 0)?;
		let serialized_bytes = VersionedSlate::into_version_plain(0, &reply, SlateVersion::V3)?
			.as_string()?
			.len();
		let domain_bytes = MAX_ENTRY_BYTES - serialized_bytes;
		let proof = reply.payment_proof.as_mut().unwrap();
		proof.sender_address.domain = "s".repeat(domain_bytes / 2);
		proof.receiver_address.domain = "r".repeat(domain_bytes - domain_bytes / 2);
		let original = request(&reply, 19)?;
		let ReserveResult::Reserved(reservation) =
			cache.reserve(reply.id, SlatePurpose::SendResponse, original.clone())?
		else {
			panic!("first request was not reserved");
		};

		assert!(reservation.complete(&reply));
		assert_eq!(cache.state.lock().total_bytes, MAX_ENTRY_BYTES);
		let ReserveResult::Cached(cached) =
			cache.reserve(reply.id, SlatePurpose::SendResponse, original)?
		else {
			panic!("reply was not cached");
		};
		let original = reply.payment_proof.unwrap();
		let cached = cached.payment_proof.unwrap();
		assert_eq!(cached.sender_address.domain, original.sender_address.domain);
		assert_eq!(
			cached.receiver_address.domain,
			original.receiver_address.domain
		);
		Ok(())
	}

	#[test]
	fn complete_counts_payment_proof_domains_toward_total_limit() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let reply = reply_with_domains(MAX_ENTRY_BYTES / 4, MAX_ENTRY_BYTES / 4)?;
		let mut requests = Vec::new();
		// Each reply retains 1 MiB of domains plus its JSON representation.
		// Sixteen such replies must trigger eviction under the 16 MiB cap.
		for _ in 0..16 {
			let mut reply = reply.clone();
			reply.id = Uuid::new_v4();
			let original = request(&reply, 20)?;
			let ReserveResult::Reserved(reservation) =
				cache.reserve(reply.id, SlatePurpose::SendResponse, original.clone())?
			else {
				panic!("new request was not reserved");
			};
			assert!(reservation.complete(&reply));
			requests.push((reply.id, original));
		}

		assert!(cache.state.lock().total_bytes <= MAX_TOTAL_BYTES);
		let mut cached = 0;
		for (id, original) in requests {
			match cache.reserve(id, SlatePurpose::SendResponse, original)? {
				ReserveResult::Cached(_) => cached += 1,
				ReserveResult::Reserved(_) => {}
				ReserveResult::Uncached => {
					panic!("cache is unexpectedly full of in-flight requests")
				}
			}
		}
		assert_eq!(cached, 15);
		Ok(())
	}

	#[test]
	fn clear_forgets_ready_replies() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 12)?;
		let ReserveResult::Reserved(mut reservation) =
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original.clone())?
		else {
			panic!("first request was not reserved");
		};
		assert!(reservation.complete_at(&incoming, Some(128), Instant::now()));
		cache.clear();
		assert!(matches!(
			cache.reserve(incoming.id, SlatePurpose::SendResponse, original)?,
			ReserveResult::Reserved(_)
		));
		Ok(())
	}

	#[test]
	fn entry_cap_does_not_evict_in_flight_requests() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 15)?;
		let now = Instant::now();
		{
			let mut state = cache.state.lock();
			for _ in 0..MAX_ENTRIES {
				state.entries.insert(
					ReplyKey::new(Uuid::new_v4(), &SlatePurpose::SendResponse),
					CacheEntry::InFlight {
						request: original.clone(),
						started: now,
						owner: Arc::new(()),
					},
				);
			}
		}

		assert!(matches!(
			cache.reserve_at(
				incoming.id,
				SlatePurpose::SendResponse,
				original,
				now,
			)?,
			ReserveResult::Uncached
		));
		assert_eq!(cache.state.lock().entries.len(), MAX_ENTRIES);
		Ok(())
	}

	#[test]
	fn byte_cap_evicts_enough_oldest_ready_replies() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 16)?;
		let started = Instant::now();
		let entry_bytes = 1024 * 1024;
		let mut keys = Vec::new();
		{
			let mut state = cache.state.lock();
			for index in 0..16 {
				let key = ReplyKey::new(Uuid::new_v4(), &SlatePurpose::SendResponse);
				keys.push(key.clone());
				let created = started + Duration::from_secs(index);
				state.entries.insert(
					key,
					CacheEntry::Ready {
						request: original.clone(),
						reply: incoming.clone(),
						created,
						expires: started + REPLY_LIFETIME,
						bytes: entry_bytes,
					},
				);
				state.total_bytes += entry_bytes;
			}
		}

		let completion_time = started + Duration::from_secs(20);
		let ReserveResult::Reserved(mut reservation) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original,
			completion_time,
		)?
		else {
			panic!("new request was not reserved");
		};
		assert!(reservation.complete_at(
			&incoming,
			Some(MAX_ENTRY_BYTES),
			completion_time,
		));

		let state = cache.state.lock();
		assert_eq!(state.total_bytes, MAX_TOTAL_BYTES);
		assert_eq!(state.entries.len(), 15);
		assert!(!state.entries.contains_key(&keys[0]));
		assert!(!state.entries.contains_key(&keys[1]));
		assert!(state.entries.contains_key(&keys[2]));
		Ok(())
	}

	#[test]
	fn reserve_purges_all_expired_entries() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let cache = Arc::new(ReplyCache::new());
		let incoming = Slate::blank(2, false)?;
		let original = request(&incoming, 17)?;
		let started = Instant::now();
		{
			let mut state = cache.state.lock();
			for _ in 0..4 {
				state.entries.insert(
					ReplyKey::new(Uuid::new_v4(), &SlatePurpose::SendResponse),
					CacheEntry::Ready {
						request: original.clone(),
						reply: incoming.clone(),
						created: started,
						expires: started + REPLY_LIFETIME,
						bytes: 128,
					},
				);
				state.total_bytes += 128;
			}
			for _ in 0..3 {
				state.entries.insert(
					ReplyKey::new(Uuid::new_v4(), &SlatePurpose::SendResponse),
					CacheEntry::InFlight {
						request: original.clone(),
						started,
						owner: Arc::new(()),
					},
				);
			}
		}

		let ReserveResult::Reserved(_reservation) = cache.reserve_at(
			incoming.id,
			SlatePurpose::SendResponse,
			original,
			started + REPLY_LIFETIME,
		)?
		else {
			panic!("request was not reserved after expired entries were purged");
		};
		let state = cache.state.lock();
		assert_eq!(state.entries.len(), 1);
		assert_eq!(state.total_bytes, 0);
		Ok(())
	}
}
