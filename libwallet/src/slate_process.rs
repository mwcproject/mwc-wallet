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

//! Serialization for externally supplied Slate UUIDs within an opened wallet.
//!
//! The reservation is deliberately separate from [`crate::types::TxSession`].
//! A transaction session contains only staged wallet state, while this guard
//! coordinates the surrounding request until its exchange and commit finish.
//!
//! Wallet lifecycle invariant: a wallet data directory may be owned by only one
//! opened wallet backend at a time. Opening the same wallet from another process
//! or through a second backend instance is unsupported. Consequently this
//! tracker is intentionally backend-local: it serializes every supported
//! concurrent entry point without pretending to coordinate unsupported duplicate
//! backend instances.

use crate::Error;
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// UUIDs currently being processed by the single backend for an opened wallet.
///
/// The returned guard must remain alive through response publication and the
/// staged wallet commit. Under the wallet lifecycle invariant documented above,
/// that covers every supported request which could process the same UUID.
#[derive(Default)]
pub struct SlateProcessTracker {
	active: Mutex<HashMap<Uuid, Arc<()>>>,
}

impl SlateProcessTracker {
	/// Create an empty tracker.
	pub fn new() -> Self {
		Self::default()
	}

	/// Reserve a Slate UUID until the returned guard is dropped.
	pub fn acquire(self: &Arc<Self>, slate_id: Uuid) -> Result<SlateProcessGuard, Error> {
		let mut active = self.active.lock();
		if active.contains_key(&slate_id) {
			return Err(Error::TransactionInProgress(slate_id.to_string()));
		}
		let owner = Arc::new(());
		active.insert(slate_id, Arc::clone(&owner));
		Ok(SlateProcessGuard {
			tracker: Arc::clone(self),
			slate_id,
			owner,
		})
	}

	/// Reserve the selected inputs under the lifetime of the active Slate guard.
	/// Sessionless invoice processing uses this after signing selection and before
	/// returning the response. A direct caller that did not acquire the UUID first
	/// cannot create an unowned reservation.
	pub(crate) fn reserve_inputs<'a, I>(&self, slate_id: Uuid, commits: I) -> Result<(), Error>
	where
		I: IntoIterator<Item = &'a Commitment>,
	{
		let owner = self.active.lock().get(&slate_id).cloned().ok_or_else(|| {
			Error::GenericError(format!(
				"invoice input reservation requires an active slate guard, slate_id={}",
				slate_id
			))
		})?;
		crate::types::reserve_input_commits(&owner, commits)
	}

	/// Forget all reservations when closing the wallet.
	pub fn clear(&self) {
		self.active.lock().clear();
	}
}

/// RAII ownership of one actively processed Slate UUID.
pub struct SlateProcessGuard {
	tracker: Arc<SlateProcessTracker>,
	slate_id: Uuid,
	owner: Arc<()>,
}

impl Drop for SlateProcessGuard {
	fn drop(&mut self) {
		let mut active = self.tracker.active.lock();
		if active
			.get(&self.slate_id)
			.map(|owner| Arc::ptr_eq(owner, &self.owner))
			.unwrap_or(false)
		{
			active.remove(&self.slate_id);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::{input_is_free, TxSession};
	use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_keychain::Identifier;
	use mwc_wallet_util::mwc_util::ToHex;

	#[test]
	fn duplicate_is_rejected_until_guard_drops() {
		let tracker = Arc::new(SlateProcessTracker::new());
		let slate_id = Uuid::new_v4();
		let guard = tracker.acquire(slate_id).unwrap();

		assert!(matches!(
			tracker.acquire(slate_id),
			Err(Error::TransactionInProgress(id)) if id == slate_id.to_string()
		));
		drop(guard);
		assert!(tracker.acquire(slate_id).is_ok());
	}

	#[test]
	fn different_uuids_can_run_concurrently() {
		let tracker = Arc::new(SlateProcessTracker::new());
		let first = tracker.acquire(Uuid::new_v4()).unwrap();
		let second = tracker.acquire(Uuid::new_v4()).unwrap();

		drop((first, second));
	}

	#[test]
	fn stale_guard_cannot_release_new_reservation_after_clear() {
		let tracker = Arc::new(SlateProcessTracker::new());
		let slate_id = Uuid::new_v4();
		let stale = tracker.acquire(slate_id).unwrap();
		tracker.clear();
		let current = tracker.acquire(slate_id).unwrap();

		drop(stale);
		assert!(matches!(
			tracker.acquire(slate_id),
			Err(Error::TransactionInProgress(id)) if id == slate_id.to_string()
		));
		drop(current);
		assert!(tracker.acquire(slate_id).is_ok());
	}

	#[test]
	fn guard_reservation_conflicts_with_transaction_session_until_drop() {
		let tracker = Arc::new(SlateProcessTracker::new());
		let slate_id = Uuid::new_v4();
		let guard = tracker.acquire(slate_id).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp
			.commit(10, SecretKey::from_slice(&secp, &[41; 32]).unwrap())
			.unwrap();
		tracker.reserve_inputs(slate_id, [&commit]).unwrap();
		assert!(!input_is_free(&commit.to_hex()));

		let mut session = TxSession::new();
		assert!(session
			.set_input_commits(vec![(Identifier::zero(), None, commit.clone(), 10)])
			.is_err());

		drop(guard);
		assert!(input_is_free(&commit.to_hex()));
		session
			.set_input_commits(vec![(Identifier::zero(), None, commit, 10)])
			.unwrap();
	}
}
