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

use super::types::{
	Address, MqsMessageDisposition, MqsMessageResult, MqsResponseWaiterToken, MqsRetryableError,
	Publisher, Subscriber, SubscriptionHandler,
};
use crate::adapters::types::MWCMQSAddress;
use crate::error::Error;
use mwc_wallet_libwallet::proof::crypto;
use mwc_wallet_libwallet::proof::crypto::Hex;
use mwc_wallet_libwallet::types::escape_for_display;
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::nanoid;
use mwc_wallet_util::mwc_crates::parking_lot::Condvar;
use mwc_wallet_util::mwc_crates::reqwest;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid;

use crate::SlateSender;
#[cfg(feature = "swaps")]
use crate::SwapMessageSender;
use mwc_wallet_libwallet::proof::message::EncryptedMessage;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::proof::tx_proof::{TxProof, prune_expired_proofs};
use mwc_wallet_libwallet::slatepack::SlatePurpose;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::Message;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::SwapMessage;
use mwc_wallet_libwallet::{Slate, SlateCtx, SlateVersion, VersionedSlate};
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_core::core::amount_to_hr_string;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::log::{error, info, warn};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Secp256k1};
use std::collections::{HashMap, hash_map::Entry};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
use std::thread;
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type MqsListenerHandle = JoinHandle<Result<(), Error>>;
const MQS_WORKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_MWCMQS_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Final state of one exact MQS listener instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MqsTermination {
	/// The listener stopped after an explicit shutdown request.
	Stopped,
	/// The listener terminated unexpectedly after startup.
	Failed(String),
}

/// Cloneable result published after the listener's unique `JoinHandle` has
/// either been joined or the worker has completed without a remaining joiner.
#[derive(Clone, Debug, Eq, PartialEq)]
enum MqsJoinOutcome {
	Clean,
	Failed(String),
}

impl MqsJoinOutcome {
	fn from_worker_result(result: &Result<(), Error>) -> Self {
		match result {
			Ok(()) => Self::Clean,
			Err(e) => Self::Failed(e.to_string()),
		}
	}

	fn from_join_result(result: thread::Result<Result<(), Error>>) -> Self {
		match result {
			Ok(result) => Self::from_worker_result(&result),
			Err(_) => Self::Failed("MWCMQS listener thread panicked".to_string()),
		}
	}

	fn unreported() -> Self {
		if thread::panicking() {
			Self::Failed("MWCMQS listener thread panicked".to_string())
		} else {
			Self::Failed("MWCMQS listener terminated without reporting a result".to_string())
		}
	}

	fn into_result(self) -> Result<(), Error> {
		match self {
			Self::Clean => Ok(()),
			Self::Failed(message) => Err(Error::MqsGenericError(message)),
		}
	}
}

enum MqsJoinPhase {
	Empty,
	Joinable(MqsListenerHandle),
	Joining { worker_id: ThreadId },
	Complete(MqsJoinOutcome),
}

struct MqsJoinInner {
	phase: MqsJoinPhase,
	/// Recorded by the worker cleanup even when another thread still owns the
	/// join. This lets a failed reaper spawn safely restore or detach the handle
	/// without losing completion or leaving the stopping marker stuck forever.
	worker_outcome: Option<MqsJoinOutcome>,
	/// Reentrant stop returns before its worker can exit. In that case the join
	/// owner, rather than the reset caller, must release the stopping marker.
	release_stop_marker_on_completion: bool,
}

struct MqsJoinControl {
	context_id: u32,
	instance_id: u64,
	inner: Mutex<MqsJoinInner>,
	completed: Condvar,
}

impl MqsJoinControl {
	fn new(context_id: u32, instance_id: u64) -> Self {
		Self {
			context_id,
			instance_id,
			inner: Mutex::new(MqsJoinInner {
				phase: MqsJoinPhase::Empty,
				worker_outcome: None,
				release_stop_marker_on_completion: false,
			}),
			completed: Condvar::new(),
		}
	}

	/// Claim the unique handle while retaining completion in shared state. This
	/// is called by the synchronous controller before it releases the lifecycle
	/// lock, so reset cannot steal the handle during the ownership handoff.
	fn claim_wait(self: &Arc<Self>) -> Result<MqsListenerWait, Error> {
		let mut inner = self.inner.lock();
		let phase = std::mem::replace(&mut inner.phase, MqsJoinPhase::Empty);
		match phase {
			MqsJoinPhase::Joinable(handle) => {
				let worker_id = handle.thread().id();
				inner.phase = MqsJoinPhase::Joining { worker_id };
				Ok(MqsListenerWait {
					control: self.clone(),
					handle: Some(handle),
				})
			}
			phase @ (MqsJoinPhase::Joining { .. } | MqsJoinPhase::Complete(_)) => {
				inner.phase = phase;
				Ok(MqsListenerWait {
					control: self.clone(),
					handle: None,
				})
			}
			MqsJoinPhase::Empty => {
				inner.phase = MqsJoinPhase::Empty;
				Err(Error::MqsGenericError(
					"MWCMQS listener thread handle is missing".to_string(),
				))
			}
		}
	}

	fn worker_status(&self) -> (bool, bool) {
		let current_id = thread::current().id();
		match &self.inner.lock().phase {
			MqsJoinPhase::Joinable(handle) => (true, handle.thread().id() == current_id),
			MqsJoinPhase::Joining { worker_id } => (true, *worker_id == current_id),
			MqsJoinPhase::Empty | MqsJoinPhase::Complete(_) => (false, false),
		}
	}

	fn is_pending(&self) -> bool {
		matches!(
			self.inner.lock().phase,
			MqsJoinPhase::Joinable(_) | MqsJoinPhase::Joining { .. }
		)
	}

	fn release_stop_marker_on_completion(&self) {
		let already_complete = {
			let mut inner = self.inner.lock();
			inner.release_stop_marker_on_completion = true;
			matches!(inner.phase, MqsJoinPhase::Complete(_))
		};
		if already_complete {
			end_mwcmqs_stop(self.context_id, self.instance_id);
		}
	}

	fn join_or_wait(self: &Arc<Self>) -> Result<(), Error> {
		loop {
			let ticket = {
				let mut inner = self.inner.lock();
				match &inner.phase {
					MqsJoinPhase::Empty => return Ok(()),
					MqsJoinPhase::Complete(outcome) => {
						return outcome.clone().into_result();
					}
					MqsJoinPhase::Joining { worker_id } => {
						if *worker_id == thread::current().id() {
							return Err(Error::MqsGenericError(
								"MWCMQS listener cannot join itself".to_string(),
							));
						}
						self.completed.wait(&mut inner);
						continue;
					}
					MqsJoinPhase::Joinable(_) => {}
				}

				let phase = std::mem::replace(&mut inner.phase, MqsJoinPhase::Empty);
				let MqsJoinPhase::Joinable(handle) = phase else {
					unreachable!("joinable phase changed while its lock was held");
				};
				let worker_id = handle.thread().id();
				inner.phase = MqsJoinPhase::Joining { worker_id };
				MqsListenerWait {
					control: self.clone(),
					handle: Some(handle),
				}
			};

			return ticket.wait();
		}
	}

	/// A stop invoked by the listener thread cannot wait for itself. If no other
	/// owner is already joining, hand the handle to a reaper. The shared phase
	/// remains `Joining` until that reaper publishes the result.
	fn defer_current_join(self: &Arc<Self>) -> Result<(), Error> {
		let ticket = {
			let mut inner = self.inner.lock();
			match &inner.phase {
				MqsJoinPhase::Empty => return Ok(()),
				MqsJoinPhase::Complete(outcome) => {
					return outcome.clone().into_result();
				}
				MqsJoinPhase::Joining { worker_id } if *worker_id == thread::current().id() => {
					return Ok(());
				}
				MqsJoinPhase::Joining { .. } => {
					drop(inner);
					return self.join_or_wait();
				}
				MqsJoinPhase::Joinable(handle)
					if handle.thread().id() != thread::current().id() =>
				{
					drop(inner);
					return self.join_or_wait();
				}
				MqsJoinPhase::Joinable(_) => {}
			}

			let phase = std::mem::replace(&mut inner.phase, MqsJoinPhase::Empty);
			let MqsJoinPhase::Joinable(handle) = phase else {
				unreachable!("joinable phase changed while its lock was held");
			};
			let worker_id = handle.thread().id();
			inner.phase = MqsJoinPhase::Joining { worker_id };
			MqsListenerWait {
				control: self.clone(),
				handle: Some(handle),
			}
		};

		// Keep the ticket recoverable until the new thread has actually started.
		// `Builder::spawn` drops its closure on failure, so moving the ticket
		// directly into that closure would otherwise detach the worker silently.
		let ticket_slot = Arc::new(Mutex::new(Some(ticket)));
		let reaper_ticket_slot = ticket_slot.clone();
		match thread::Builder::new()
			.name(format!("mwcmqs-reaper-{}", self.context_id))
			.spawn(move || {
				if let Some(ticket) = reaper_ticket_slot.lock().take() {
					if let Err(e) = ticket.wait() {
						error!("MQS listener failed during reentrant shutdown: {}", e);
					}
				}
			}) {
			Ok(_) => Ok(()),
			Err(e) => {
				// Dropping the recovered ticket restores the handle to shared state.
				// Worker cleanup will publish completion even if no later joiner exists.
				drop(ticket_slot.lock().take());
				Err(Error::MqsGenericError(format!(
					"Unable to spawn MQS reaper thread: {}",
					e
				)))
			}
		}
	}

	fn complete_join(&self, worker_id: ThreadId, outcome: MqsJoinOutcome) {
		let release_stop_marker = {
			let mut inner = self.inner.lock();
			match &inner.phase {
				MqsJoinPhase::Joining {
					worker_id: expected,
				} if *expected == worker_id => {
					inner.phase = MqsJoinPhase::Complete(outcome);
					Some(inner.release_stop_marker_on_completion)
				}
				MqsJoinPhase::Complete(_) => None,
				_ => {
					error!("MWCMQS listener join completed from an unexpected lifecycle state");
					inner.phase = MqsJoinPhase::Complete(outcome);
					Some(inner.release_stop_marker_on_completion)
				}
			}
		};
		if let Some(release_stop_marker) = release_stop_marker {
			self.completed.notify_all();
			if release_stop_marker {
				end_mwcmqs_stop(self.context_id, self.instance_id);
			}
		}
	}

	fn restore_joinable(&self, handle: MqsListenerHandle) {
		let worker_id = handle.thread().id();
		let mut handle = Some(handle);
		let completion = {
			let mut inner = self.inner.lock();
			match &inner.phase {
				MqsJoinPhase::Joining {
					worker_id: expected,
				} if *expected == worker_id => {
					if let Some(outcome) = inner.worker_outcome.clone() {
						// The worker is already done; dropping its completed handle is
						// equivalent to a detached join for lifecycle purposes.
						drop(handle.take());
						inner.phase = MqsJoinPhase::Complete(outcome);
						Some(inner.release_stop_marker_on_completion)
					} else {
						inner.phase = MqsJoinPhase::Joinable(
							handle.take().expect("join handle is available"),
						);
						None
					}
				}
				_ => {
					error!("Unable to restore MWCMQS listener handle after join cancellation");
					None
				}
			}
		};
		drop(handle);
		self.completed.notify_all();
		if matches!(completion, Some(true)) {
			end_mwcmqs_stop(self.context_id, self.instance_id);
		}
	}

	fn worker_finished(&self, outcome: MqsJoinOutcome) {
		let completion = {
			let mut inner = self.inner.lock();
			inner.worker_outcome = Some(outcome.clone());
			if matches!(inner.phase, MqsJoinPhase::Empty | MqsJoinPhase::Joinable(_)) {
				// No joiner owns the handle. All wallet-facing worker work is now
				// complete, so retain the outcome and detach the finished handle.
				inner.phase = MqsJoinPhase::Complete(outcome);
				Some(inner.release_stop_marker_on_completion)
			} else {
				None
			}
		};
		if let Some(release_stop_marker) = completion {
			self.completed.notify_all();
			if release_stop_marker {
				end_mwcmqs_stop(self.context_id, self.instance_id);
			}
		}
	}
}

/// A claim on the listener's unique join handle. Dropping an unconsumed claim
/// restores it to shared state, while `wait` publishes one result to all stop
/// and synchronous-wait callers.
pub struct MqsListenerWait {
	control: Arc<MqsJoinControl>,
	handle: Option<MqsListenerHandle>,
}

impl MqsListenerWait {
	pub fn wait(mut self) -> Result<(), Error> {
		let Some(handle) = self.handle.take() else {
			return self.control.join_or_wait();
		};
		let worker_id = handle.thread().id();
		if worker_id == thread::current().id() {
			// Preserve the unique handle so Drop can restore it to shared state.
			self.handle = Some(handle);
			return Err(Error::MqsGenericError(
				"MWCMQS listener cannot join itself".to_string(),
			));
		}
		let outcome = MqsJoinOutcome::from_join_result(handle.join());
		self.control.complete_join(worker_id, outcome.clone());
		outcome.into_result()
	}
}

impl Drop for MqsListenerWait {
	fn drop(&mut self) {
		if let Some(handle) = self.handle.take() {
			self.control.restore_joinable(handle);
		}
	}
}

struct MqsObservedState {
	instance_id: u64,
	termination: Option<MqsTermination>,
}

struct MqsTerminalRecorder {
	context_id: u32,
	instance_id: u64,
	completed: bool,
}

impl MqsTerminalRecorder {
	fn new(context_id: u32, instance_id: u64) -> Self {
		Self {
			context_id,
			instance_id,
			completed: false,
		}
	}

	fn complete(&mut self, result: &Result<(), Error>) {
		let termination = match result {
			Ok(()) => MqsTermination::Stopped,
			Err(e) => MqsTermination::Failed(e.to_string()),
		};
		record_mwcmqs_termination(self.context_id, self.instance_id, termination);
		self.completed = true;
	}

	fn finish_if_needed(&mut self) {
		if !self.completed {
			let message = if thread::panicking() {
				"MWCMQS listener thread panicked"
			} else {
				"MWCMQS listener terminated without reporting a result"
			};
			record_mwcmqs_termination(
				self.context_id,
				self.instance_id,
				MqsTermination::Failed(message.to_string()),
			);
			self.completed = true;
		}
	}
}

impl Drop for MqsTerminalRecorder {
	fn drop(&mut self) {
		self.finish_if_needed();
	}
}

struct MqsWorkerCleanup {
	context_id: u32,
	instance_id: u64,
	broker: Arc<MWCMQSBroker>,
	join_control: Arc<MqsJoinControl>,
	terminal: MqsTerminalRecorder,
	outcome: Option<MqsJoinOutcome>,
}

impl MqsWorkerCleanup {
	fn complete(&mut self, result: &Result<(), Error>) {
		self.terminal.complete(result);
		self.outcome = Some(MqsJoinOutcome::from_worker_result(result));
	}
}

impl Drop for MqsWorkerCleanup {
	fn drop(&mut self) {
		// Persist the terminal state before unregistering this listener. The
		// shared join state may outlive the registry, so cleanup must not make the
		// worker result or panic unobservable to a stop or synchronous waiter.
		self.terminal.finish_if_needed();
		self.broker.finish();
		reset_mwcmqs_brocker_if_current(self.context_id, self.instance_id);
		self.join_control.worker_finished(
			self.outcome
				.take()
				.unwrap_or_else(MqsJoinOutcome::unreported),
		);
	}
}

// MQS enforced to have a single instance. And different compoments migth manage
// instances separatlly.
// Also all dependent components want to use MQS and they need interface.
// Since instance is single, interface will be global
lazy_static! {
	static ref MWCMQS_BROKER: RwLock<HashMap<u32, (Arc<MWCMQPublisher>, MWCMQSubscriber)>> =
		RwLock::new(HashMap::new());
	static ref MWCMQS_TERMINAL_STATES: RwLock<HashMap<u32, MqsObservedState>> =
		RwLock::new(HashMap::new());
	static ref MWCMQS_LIFECYCLE: Mutex<()> = Mutex::new(());
	/// Contexts whose listener stop has begun but whose worker join is still
	/// pending outside the lifecycle lock, either on a reaper or a synchronous
	/// listener owner. Retaining the join control lets concurrent reset callers
	/// wait for that exact worker and observe the same outcome.
	static ref MWCMQS_STOPPING: Mutex<HashMap<u32, Arc<MqsJoinControl>>> =
		Mutex::new(HashMap::new());
}

/// Proof that the caller owns the global MQS lifecycle lock.
///
/// Registration accepts this guard explicitly so checking the stopping state
/// and publishing a replacement cannot race a lifecycle operation that begins
/// stopping the previous listener. The private field ensures callers obtain a
/// valid guard from [`lock_mwcmqs_lifecycle`] rather than an unrelated mutex.
#[must_use = "dropping the MQS lifecycle guard releases lifecycle serialization"]
pub struct MqsLifecycleGuard {
	_guard: mwc_wallet_util::mwc_crates::parking_lot::MutexGuard<'static, ()>,
}

fn begin_mwcmqs_observation(context_id: u32, instance_id: u64) {
	MWCMQS_TERMINAL_STATES.write().insert(
		context_id,
		MqsObservedState {
			instance_id,
			termination: None,
		},
	);
}

fn record_mwcmqs_termination(context_id: u32, instance_id: u64, termination: MqsTermination) {
	let mut states = MWCMQS_TERMINAL_STATES.write();
	if let Some(state) = states.get_mut(&context_id) {
		if state.instance_id == instance_id && state.termination.is_none() {
			state.termination = Some(termination);
		}
	}
}

#[cfg(test)]
fn clear_mwcmqs_termination(context_id: u32) {
	MWCMQS_TERMINAL_STATES.write().remove(&context_id);
}

fn clear_mwcmqs_termination_if_current(context_id: u32, instance_id: u64) {
	let mut states = MWCMQS_TERMINAL_STATES.write();
	if states
		.get(&context_id)
		.is_some_and(|state| state.instance_id == instance_id)
	{
		states.remove(&context_id);
	}
}

fn take_mwcmqs_termination(context_id: u32) -> Option<MqsTermination> {
	MWCMQS_TERMINAL_STATES
		.write()
		.remove(&context_id)
		.and_then(|state| state.termination)
}

/// Return the retained terminal state of the most recently started listener.
///
/// This state is independent of the active broker registry and therefore
/// remains available after a failed worker unregisters itself. Starting a new
/// listener replaces the previous state.
pub fn get_mwcmqs_listener_termination(context_id: u32) -> Option<MqsTermination> {
	MWCMQS_TERMINAL_STATES
		.read()
		.get(&context_id)
		.and_then(|state| state.termination.clone())
}

/// Serialize MQS start/stop with wallet open/close operations.
pub fn lock_mwcmqs_lifecycle() -> MqsLifecycleGuard {
	MqsLifecycleGuard {
		_guard: MWCMQS_LIFECYCLE.lock(),
	}
}

/// Record that a listener stop is in progress for the context. The marker is
/// set while the lifecycle lock is held but released only after the worker
/// join completes, which can happen on a reaper thread (see
/// MWCMQSubscriber::stop). A replacement listener must not start while the
/// marker is present.
fn begin_mwcmqs_stop(context_id: u32, join_control: Arc<MqsJoinControl>) {
	MWCMQS_STOPPING.lock().insert(context_id, join_control);
}

/// Release the stopping marker, but only if it still refers to this instance.
fn end_mwcmqs_stop(context_id: u32, instance_id: u64) {
	let mut stopping = MWCMQS_STOPPING.lock();
	if stopping
		.get(&context_id)
		.is_some_and(|control| control.instance_id == instance_id)
	{
		stopping.remove(&context_id);
	}
}

fn mwcmqs_stop_in_progress(context_id: u32) -> bool {
	MWCMQS_STOPPING.lock().contains_key(&context_id)
}

fn mwcmqs_stopping_control(context_id: u32) -> Option<Arc<MqsJoinControl>> {
	MWCMQS_STOPPING.lock().get(&context_id).cloned()
}

fn mwcmqs_stop_matches(context_id: u32, instance_id: u64) -> bool {
	MWCMQS_STOPPING
		.lock()
		.get(&context_id)
		.is_some_and(|control| control.instance_id == instance_id)
}

/// Init mwc mqs objects for the access.
pub fn init_mwcmqs_access_data(
	_lifecycle_guard: &MqsLifecycleGuard,
	context_id: u32,
	publisher: Arc<MWCMQPublisher>,
	subscriber: MWCMQSubscriber,
) -> Result<(), Error> {
	if context_id != publisher.context_id
		|| context_id != subscriber.context_id
		|| !Arc::ptr_eq(&publisher.address, &subscriber.address)
		|| !Arc::ptr_eq(&publisher.broker, &subscriber.broker)
		|| !Arc::ptr_eq(&publisher.secret_key, &subscriber.secret_key)
	{
		return Err(Error::MqsGenericError(
			"MWCMQS publisher and subscriber do not belong to the requested context".to_string(),
		));
	}

	if mwcmqs_stop_in_progress(context_id) {
		// The previous listener's join is still owned by a reaper or synchronous
		// waiter. Starting a replacement now would run two pollers for the same
		// address and race the old worker's cleanup; the caller can retry once the
		// stop completes. `MWCMQSubscriber::start` requires this exact join control
		// to be registered, so a rejected candidate cannot own a worker that needs
		// stopping here while the lifecycle guard is held.
		return Err(Error::MqsGenericError(
			"MWCMQS listener stop is still in progress".to_string(),
		));
	}
	let inserted = {
		let mut brokers = MWCMQS_BROKER.write();
		match brokers.entry(context_id) {
			Entry::Vacant(entry) => {
				entry.insert((publisher, subscriber.clone()));
				true
			}
			Entry::Occupied(_) => false,
		}
	};

	if !inserted {
		// Do not stop while `_lifecycle_guard` is live: stopping can join a worker
		// whose receive callback is waiting for this same lifecycle lock. An exact
		// registered clone may already be active; every other candidate is prevented
		// from starting by the registration identity check in `Subscriber::start`.
		Err(Error::MqsGenericError(
			"MWCMQS listener is already running".to_string(),
		))
	} else {
		Ok(())
	}
}

/// Init mwc mqs objects for the access.
pub fn get_mwcmqs_brocker(context_id: u32) -> Option<(Arc<MWCMQPublisher>, MWCMQSubscriber)> {
	MWCMQS_BROKER.read().get(&context_id).cloned()
}

/// Reset Broker (listener is stopped)
/// stop_existing call if already running we want to stop.
pub fn reset_mwcmqs_brocker(context_id: u32) -> Result<(), Error> {
	// Remove the registration under the lifecycle lock, but release the lock
	// before stopping: receive callbacks execute on the listener thread and can
	// re-enter lifecycle-guarded APIs, so joining the worker while holding the
	// lock can deadlock.
	enum ResetState {
		Active(MWCMQSubscriber),
		Stopping(Arc<MqsJoinControl>),
		Inactive(Option<MqsTermination>),
	}

	let reset_state = {
		let _lifecycle_guard = lock_mwcmqs_lifecycle();
		let removed = MWCMQS_BROKER.write().remove(&context_id);
		match removed {
			Some((_publisher, subscriber)) => {
				begin_mwcmqs_stop(context_id, subscriber.subscribe_thread.clone());
				ResetState::Active(subscriber)
			}
			None => match mwcmqs_stopping_control(context_id) {
				Some(control) => ResetState::Stopping(control),
				// A concurrent start installs its observation while holding this same
				// lifecycle lock. Acknowledge the prior terminal state before releasing
				// the lock so this reset cannot remove the replacement's observation.
				None => ResetState::Inactive(take_mwcmqs_termination(context_id)),
			},
		}
	};

	match reset_state {
		ResetState::Active(mut subscriber) => {
			let instance_id = subscriber.instance_id();
			let stop_result = subscriber.stop(false);
			let completed_instance = (!subscriber.is_join_pending()).then_some(instance_id);
			// An explicit reset acknowledges any retained terminal state. Check the
			// instance because another reset may finish the join and admit a replacement
			// before this caller resumes.
			clear_mwcmqs_termination_if_current(context_id, instance_id);
			if let Some(instance_id) = completed_instance {
				end_mwcmqs_stop(context_id, instance_id);
			}
			stop_result
		}
		ResetState::Stopping(control) => {
			let instance_id = control.instance_id;
			let stop_result = control.join_or_wait();
			if !control.is_pending() {
				clear_mwcmqs_termination_if_current(context_id, instance_id);
				end_mwcmqs_stop(context_id, instance_id);
			}
			stop_result
		}
		ResetState::Inactive(termination) => match termination {
			Some(MqsTermination::Failed(message)) => Err(Error::MqsGenericError(format!(
				"MWCMQS listener previously terminated: {}",
				message
			))),
			_ => Ok(()),
		},
	}
}

pub fn reset_mwcmqs_brocker_if_current(context_id: u32, instance_id: u64) {
	let _removed = {
		let mut brokers = MWCMQS_BROKER.write();
		let is_current = brokers
			.get(&context_id)
			.is_some_and(|(_, subscriber)| subscriber.instance_id() == instance_id);
		if is_current {
			brokers.remove(&context_id)
		} else {
			None
		}
	};
}

/// Atomically remove and stop the identified broker instance.
///
/// The identity check prevents a stale owner/listener cleanup from stopping a
/// replacement that has already been registered for the same wallet context.
pub fn stop_mwcmqs_brocker_if_current(context_id: u32, instance_id: u64) -> Result<bool, Error> {
	// Same locking discipline as reset_mwcmqs_brocker: the identity check and
	// the registry removal happen under the lifecycle lock; the stop (which
	// notifies the server and joins the worker) runs after it is released.
	let removed = {
		let _lifecycle_guard = lock_mwcmqs_lifecycle();
		let removed = {
			let mut brokers = MWCMQS_BROKER.write();
			let is_current = brokers
				.get(&context_id)
				.is_some_and(|(_, subscriber)| subscriber.instance_id() == instance_id);
			if is_current {
				brokers.remove(&context_id)
			} else {
				None
			}
		};
		if let Some((_, subscriber)) = &removed {
			begin_mwcmqs_stop(context_id, subscriber.subscribe_thread.clone());
		}
		removed
	};

	if let Some((_, mut subscriber)) = removed {
		let stop_result = subscriber.stop(false);
		let join_pending = subscriber.is_join_pending();
		// SECURITY/AUDIT POLICY: reentrant shutdown from the listener thread is
		// deliberately best effort because that thread cannot join itself. In that
		// path, Ok means the stop was accepted and join ownership was transferred to
		// an existing waiter or a reaper; it does not promise a successful eventual
		// worker result. A late failure is observed by that waiter or logged by the
		// reaper. This API intentionally acknowledges the terminal observation once
		// the stop request is accepted instead of retaining or returning that later
		// asynchronous result.
		if stop_result.is_ok() {
			clear_mwcmqs_termination_if_current(context_id, instance_id);
		}
		if !join_pending {
			// A reentrant join releases this marker from shared completion.
			end_mwcmqs_stop(context_id, instance_id);
		}
		stop_result?;
		Ok(true)
	} else {
		Ok(false)
	}
}

pub struct MwcMqsChannel {
	context_id: u32,
	des_address: String,
}

fn expected_mqs_response_purpose(request: &SlatePurpose) -> Result<SlatePurpose, Error> {
	match request {
		SlatePurpose::SendInitial => Ok(SlatePurpose::SendResponse),
		SlatePurpose::InvoiceInitial => Ok(SlatePurpose::InvoiceResponse),
		SlatePurpose::InvoiceResponse => Ok(SlatePurpose::FullSlate),
		other => Err(Error::MqsGenericError(format!(
			"MWCMQS request has unsupported slate purpose {:?}",
			other
		))),
	}
}

impl MwcMqsChannel {
	pub fn new(context_id: u32, des_address: String) -> Self {
		Self {
			context_id,
			des_address: des_address,
		}
	}

	fn send_tx_to_mqs(
		slate: &Slate,
		des_address: &MWCMQSAddress,
		mwcmqs_publisher: &MWCMQPublisher,
		rx_slate: Receiver<Slate>,
		secp: &Secp256k1,
	) -> Result<Slate, Error> {
		mwcmqs_publisher
			.post_slate(&slate, des_address, secp)
			.map_err(|e| {
				Error::MqsGenericError(format!(
					"MQS unable to transfer slate {} to the worker, {}",
					slate.id, e
				))
			})?;

		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"slate [{}] for [{}] MWCs sent to [{}]",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false),
				des_address,
			);
		} else {
			info!(
				"slate [{}] for [{}] MWCs sent to [{}]",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false),
				des_address,
			);
		}

		//expect to get slate back.
		let slate_returned = rx_slate
			.recv_timeout(Duration::from_secs(120))
			.map_err(|e| {
				Error::MqsGenericError(format!("MQS unable to process slate {}, {}", slate.id, e))
			})?;
		return Ok(slate_returned);
	}

	#[cfg(feature = "swaps")]
	fn send_swap_to_mqs(
		&self,
		swap_message: &Message,
		mwcmqs_publisher: &MWCMQPublisher,
		_rs_message: Receiver<Message>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let des_address = MWCMQSAddress::from_str(secp, self.context_id, self.des_address.as_ref())
			.map_err(|e| Error::MqsGenericError(format!("Invalid destination address, {}", e)))?;
		mwcmqs_publisher
			.post_take(swap_message, &des_address, secp)
			.map_err(|e| {
				Error::MqsGenericError(format!(
					"MQS unable to transfer swap message {} to the worker, {}",
					swap_message.id, e
				))
			})?;
		Ok(())
	}
}

impl SlateSender for MwcMqsChannel {
	fn check_other_wallet_version(
		&self,
		_destination_address: &String,
		_show_error: bool,
	) -> Result<Option<(SlateVersion, Option<String>)>, Error> {
		Ok(None)
	}

	// MQS doesn't do encryption because of backward compability. In any case it is not critical, the whole slate is encrypted and the size of slate is not important
	fn send_tx(
		&self,
		send_tx: bool, // false if invoice, true if send operation
		slate: &Slate,
		slate_content: SlatePurpose,
		_slatepack_secret: &ed25519_dalek::SigningKey,
		_recipients: Option<ed25519_dalek::VerifyingKey>,
		_other_wallet_version: Option<(SlateVersion, Option<String>)>,
		secp: &Secp256k1,
	) -> Result<Slate, Error> {
		if !send_tx {
			if global::is_mainnet(self.context_id) {
				return Err(Error::MqsGenericError(
					"MWCMQS doesn't support invoice transactions".into(),
				));
			}
		}

		let des_address = MWCMQSAddress::from_str(secp, self.context_id, self.des_address.as_ref())
			.map_err(|e| Error::MqsGenericError(format!("Invalid destination address, {}", e)))?;
		let expected_response = expected_mqs_response_purpose(&slate_content)?;

		if let Some((mwcmqs_publisher, mwcmqs_subscriber)) = get_mwcmqs_brocker(self.context_id) {
			// Creating channels for notification
			let (tx_slate, rx_slate) = channel(); //this chaneel is used for listener thread to send message to other thread

			let waiter_token = mwcmqs_subscriber.set_notification_channels(
				&slate.id,
				slate.clone(),
				des_address.address.public_key.clone(),
				expected_response,
				tx_slate,
			)?;
			let res = Self::send_tx_to_mqs(slate, &des_address, &mwcmqs_publisher, rx_slate, secp);
			mwcmqs_subscriber.reset_notification_channels(&slate.id, &waiter_token);
			res
		} else {
			return Err(Error::MqsGenericError(format!(
				"MQS is not started, not able to send the slate {}",
				slate.id
			)));
		}
	}
}

#[cfg(feature = "swaps")]
impl SwapMessageSender for MwcMqsChannel {
	/// Send a swap message. Return true is message delivery acknowledge can be set (message was delivered and procesed)
	fn send_swap_message(&self, message: &Message, secp: &Secp256k1) -> Result<bool, Error> {
		if let Some((mwcmqs_publisher, _mwcmqs_subscriber)) = get_mwcmqs_brocker(self.context_id) {
			let (_ts_message, rs_message) = channel();
			self.send_swap_to_mqs(message, &mwcmqs_publisher, rs_message, &secp)?;
			// MQS is async protocol, message might never be delivered, so no ack can be granted.
			Ok(false)
		} else {
			return Err(Error::MqsGenericError(format!(
				"MQS is not started, not able to send the swap message {}",
				message.id
			)));
		}
	}
}

#[derive(Clone)]
pub struct MWCMQPublisher {
	context_id: u32,
	address: Arc<MWCMQSAddress>,
	broker: Arc<MWCMQSBroker>,
	secret_key: Arc<SecretKey>,
}

impl MWCMQPublisher {
	// Note, Publisher must initialize controller with self
	pub fn new(
		context_id: u32,
		address: MWCMQSAddress,
		secret_key: &SecretKey,
		mwcmqs_domain: String,
		mwcmqs_port: u16,
		print_to_log: bool,
		handler: Box<dyn SubscriptionHandler>,
	) -> Result<Self, Error> {
		Ok(Self {
			context_id,
			address: Arc::new(address),
			broker: Arc::new(MWCMQSBroker::new(
				context_id,
				mwcmqs_domain,
				mwcmqs_port,
				print_to_log,
				handler,
			)?),
			secret_key: Arc::new(secret_key.clone()),
		})
	}
}
impl Publisher for MWCMQPublisher {
	fn post_slate(&self, slate: &Slate, to: &dyn Address, secp: &Secp256k1) -> Result<(), Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(secp, self.context_id, &to_address_raw)?;
		self.broker
			.post_slate(slate, &to_address, &self.address, &self.secret_key, secp)?;
		Ok(())
	}

	fn encrypt_slate(
		&self,
		slate: &Slate,
		to: &dyn Address,
		secp: &Secp256k1,
	) -> Result<String, Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(secp, self.context_id, &to_address_raw)?;
		self.broker
			.encrypt_slate(slate, &to_address, &self.address, &self.secret_key, secp)
	}

	fn decrypt_slate(
		&self,
		from: String,
		mapmessage: String,
		signature: String,
		source_address: &ProvableAddress,
		secp: &Secp256k1,
	) -> Result<String, Error> {
		let r1 = str::replace(&mapmessage, "%22", "\"");
		let r2 = str::replace(&r1, "%7B", "{");
		let r3 = str::replace(&r2, "%7D", "}");
		let r4 = str::replace(&r3, "%3A", ":");
		let r5 = str::replace(&r4, "%2C", ",");
		let r5 = r5.trim().to_string();

		let from = MWCMQSAddress::from_str(secp, self.context_id, &from)?;

		let (slate, _tx_proof) = TxProof::from_response(
			self.context_id,
			&from.address,
			r5.clone(),
			"".to_string(),
			signature.clone(),
			&self.secret_key,
			&source_address,
			secp,
		)
		.map_err(|e| {
			Error::MqsGenericError(format!("Unable to build txproof from the payload, {}", e))
		})?;

		let slate = serde_json::to_string(&SlateCtx {
			slate: slate,
			network_name: Some(global::get_network_name(self.context_id)),
		})
		.map_err(|e| Error::MqsGenericError(format!("Unable convert Slate to Json, {}", e)))?;
		Ok(slate)
	}

	#[cfg(feature = "swaps")]
	fn post_take(
		&self,
		message: &Message,
		to: &dyn Address,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let to_address_raw = format!("mwcmqs://{}", to.get_stripped());
		let to_address = MWCMQSAddress::from_str(secp, self.context_id, &to_address_raw)?;
		self.broker
			.post_take(message, &to_address, &self.address, &self.secret_key, secp)?;
		Ok(())
	}

	// Address of this publisher (from address)
	fn get_publisher_address(&self) -> Result<Box<dyn Address>, Error> {
		Ok(Box::new((*self.address).clone()))
	}
}

#[derive(Clone)]
pub struct MWCMQSubscriber {
	context_id: u32,
	address: Arc<MWCMQSAddress>,
	broker: Arc<MWCMQSBroker>,
	secret_key: Arc<SecretKey>,
	subscribe_thread: Arc<MqsJoinControl>,
}

impl MWCMQSubscriber {
	pub fn new(publisher: &MWCMQPublisher) -> Self {
		let subscribe_thread = Arc::new(MqsJoinControl::new(
			publisher.context_id,
			publisher.broker.instance_id,
		));
		Self {
			context_id: publisher.context_id,
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
			subscribe_thread,
		}
	}

	pub fn claim_subscribe_thread(&self) -> Result<MqsListenerWait, Error> {
		self.subscribe_thread.claim_wait()
	}

	/// Compatibility wrapper for callers that still expect a `JoinHandle`.
	///
	/// The returned handle belongs to a small proxy waiter; the real listener
	/// join remains represented by shared `Joining`/`Complete` state so reset can
	/// still cancel it, wait for it and observe its result.
	pub fn take_subscribe_thread(&self) -> Option<MqsListenerHandle> {
		let ticket = self.claim_subscribe_thread().ok()?;
		let ticket_slot = Arc::new(Mutex::new(Some(ticket)));
		let waiter_ticket_slot = ticket_slot.clone();
		match thread::Builder::new()
			.name(format!("mwcmqs-waiter-{}", self.context_id))
			.spawn(move || -> Result<(), Error> {
				waiter_ticket_slot.lock().take().ok_or_else(|| {
					Error::MqsGenericError("MWCMQS listener wait claim is missing".to_string())
				})?
				.wait()
			}) {
			Ok(waiter) => Some(waiter),
			Err(e) => {
				// Restore the real handle if the proxy could not be started.
				drop(ticket_slot.lock().take());
				error!("Unable to spawn MWCMQS listener waiter: {}", e);
				None
			}
		}
	}

	pub fn instance_id(&self) -> u64 {
		self.broker.instance_id
	}

	/// Only the subscriber whose exact join control is in the broker registry may
	/// create the listener worker. A broker instance id is insufficient here:
	/// calling `MWCMQSubscriber::new` twice for one publisher reuses the broker id
	/// but intentionally creates two different join controls.
	fn matches_registered_listener(
		&self,
		publisher: &MWCMQPublisher,
		subscriber: &MWCMQSubscriber,
	) -> bool {
		Arc::ptr_eq(&publisher.broker, &self.broker)
			&& Arc::ptr_eq(&subscriber.broker, &self.broker)
			&& Arc::ptr_eq(&subscriber.subscribe_thread, &self.subscribe_thread)
	}

	#[cfg(test)]
	fn is_registered_listener(&self) -> bool {
		MWCMQS_BROKER
			.read()
			.get(&self.context_id)
			.is_some_and(|(publisher, subscriber)| {
				self.matches_registered_listener(publisher, subscriber)
			})
	}

	pub fn is_mqs_running(&self) -> bool {
		self.broker.is_running()
	}

	pub fn is_mqs_healthy(&self) -> bool {
		self.broker.is_running() && self.broker.is_healthy()
	}

	fn is_join_pending(&self) -> bool {
		self.subscribe_thread.is_pending()
	}
}

/// Build every MQS HTTP client with the same transport boundary.
fn mwcmqs_client_builder(timeout: Duration) -> reqwest::blocking::ClientBuilder {
	// MQS requests carry wallet addresses, signatures, and encrypted form
	// bodies. Never let a broker redirect them to another origin or downgrade
	// them to plaintext HTTP. Returning a 3xx response is safe: every caller
	// below already treats non-success statuses as protocol errors.
	reqwest::blocking::Client::builder()
		.timeout(timeout)
		.https_only(true)
		.redirect(reqwest::redirect::Policy::none())
}

fn build_mwcmqs_client(timeout: Duration) -> Result<reqwest::blocking::Client, reqwest::Error> {
	mwcmqs_client_builder(timeout).build()
}

/// Notify the MQS server that this address is going offline so it can drop the
/// long-poll session instead of waiting for the connection to time out.
fn send_mqs_stop_notification(broker: &MWCMQSBroker, address: &MWCMQSAddress) {
	// For good bay  cancelling call low timeout make sense. If connectio os good
	// That will pass. If connection is bad, we dont't want wait for a while, the brocker cycle will
	// exit itsenf on average of 10 secoinds.
	match build_mwcmqs_client(Duration::from_secs(10)) {
		Ok(client) => {
			let mut params = HashMap::new();
			params.insert("mapmessage", "nil");
			match client
				.post(&format!(
					"https://{}:{}/sender?address={}",
					broker.mwcmqs_domain,
					broker.mwcmqs_port,
					str::replace(&address.get_stripped(), "@", "%40")
				))
				.form(&params)
				.send()
			{
				Ok(response) if !response.status().is_success() => error!(
					"MQS server rejected the stopping notification: {}",
					response.status()
				),
				Err(e) => error!("Unable to notify MQS server about stopping: {}", e),
				Ok(_) => {}
			}
		}
		Err(e) => error!("Unable to create MQS shutdown client: {}", e),
	}
}

impl Subscriber for MWCMQSubscriber {
	fn start(&mut self) -> Result<(), Error> {
		let mut join_inner = self.subscribe_thread.inner.lock();

		if !matches!(join_inner.phase, MqsJoinPhase::Empty) {
			return Err(Error::MqsGenericError(
				"MQS listener is already running".into(),
			));
		}
		// Keep the registry read guard until the worker handle is published. This
		// prevents an instance-checked cleanup from removing the registration in the
		// gap between validation and thread creation, which would otherwise leave an
		// active worker with no registered owner.
		let registration_guard = MWCMQS_BROKER.read();
		let is_registered =
			registration_guard
				.get(&self.context_id)
				.is_some_and(|(publisher, subscriber)| {
					self.matches_registered_listener(publisher, subscriber)
				});
		if !is_registered {
			return Err(Error::MqsGenericError(
				"MWCMQS subscriber must be registered before startup".into(),
			));
		}

		let address = self.address.address.clone();
		self.broker.begin_start()?;

		let context_id = self.context_id;
		let broker = self.broker.clone();
		let secret_key = self.secret_key.clone();
		let join_control = self.subscribe_thread.clone();
		let instance_id = self.instance_id();
		begin_mwcmqs_observation(context_id, instance_id);
		let (startup_sender, startup_receiver) = sync_channel(1);

		let thread = match thread::Builder::new()
			.name(format!("mwcmqs-broker-{}", self.context_id))
			.spawn(move || -> Result<(), Error> {
				let mut cleanup = MqsWorkerCleanup {
					context_id,
					instance_id,
					broker: broker.clone(),
					join_control,
					terminal: MqsTerminalRecorder::new(context_id, instance_id),
					outcome: None,
				};
				let result = (|| -> Result<(), Error> {
					// A secp context is not Send, so the worker must create its own context.
					let secp = match Secp256k1::new() {
						Ok(secp) => secp,
						Err(e) => {
							let error = Error::from(e);
							let _ = startup_sender.send(Err(error.to_string()));
							return Err(error);
						}
					};
					let mut startup_sender = Some(startup_sender);
					broker.subscribe(&address, &secret_key, &secp, &mut startup_sender);
					if let Some(startup_sender) = startup_sender.take() {
						let _ = startup_sender.send(Err(
							"MWCMQS subscriber stopped before becoming ready".to_string(),
						));
					}
					if broker.stop_requested() {
						Ok(())
					} else {
						Err(Error::MqsGenericError(
							"MWCMQS subscriber stopped unexpectedly".to_string(),
						))
					}
				})();
				cleanup.complete(&result);
				result
			}) {
			Ok(thread) => thread,
			Err(e) => {
				let error = Error::GenericError(format!("Unable to start mwcmqs broker, {}", e));
				record_mwcmqs_termination(
					context_id,
					instance_id,
					MqsTermination::Failed(error.to_string()),
				);
				self.broker.finish();
				return Err(error);
			}
		};

		join_inner.phase = MqsJoinPhase::Joinable(thread);
		drop(registration_guard);
		drop(join_inner);

		match startup_receiver.recv_timeout(MQS_WORKER_STARTUP_TIMEOUT) {
			Ok(Ok(())) if self.broker.is_running() && self.broker.is_healthy() => Ok(()),
			Ok(Ok(())) => {
				if let Err(e) = self.stop(false) {
					error!("Unable to stop unhealthy MWCMQS startup: {}", e);
				}
				Err(Error::MqsGenericError(
					"MWCMQS subscriber stopped or became unhealthy during startup".to_string(),
				))
			}
			Ok(Err(e)) => {
				if let Err(stop_error) = self.stop(false) {
					error!("Unable to stop failed MWCMQS startup: {}", stop_error);
				}
				Err(Error::MqsGenericError(format!(
					"Unable to initialize MWCMQS subscriber: {}",
					e
				)))
			}
			Err(RecvTimeoutError::Timeout) => {
				if let Err(e) = self.stop(false) {
					error!("Unable to stop timed-out MWCMQS startup: {}", e);
				}
				Err(Error::MqsGenericError(
					"Timed out waiting for MWCMQS subscriber startup".to_string(),
				))
			}
			Err(RecvTimeoutError::Disconnected) => {
				if let Err(e) = self.stop(false) {
					error!("Unable to stop disconnected MWCMQS startup: {}", e);
				}
				Err(Error::MqsGenericError(
					"MWCMQS subscriber terminated before reporting startup".to_string(),
				))
			}
		}
	}

	fn stop(&mut self, call_reset_mwcmqs_brocker: bool) -> Result<(), Error> {
		let (worker_pending, called_from_worker) = self.subscribe_thread.worker_status();
		let first_stop_request = self.broker.stop();

		// Waking the blocking request is cancellation, not join bookkeeping. In
		// particular, an external synchronous waiter may already own the handle.
		// When stop is reentrant the worker is executing this call, so it cannot
		// simultaneously be blocked in a listener request and needs no wake-up.
		if first_stop_request && worker_pending && !called_from_worker {
			send_mqs_stop_notification(&self.broker, &self.address);
		}

		let result = if called_from_worker {
			// This caller cannot wait for itself, so completion must release any
			// marker installed by reset after the callback returns.
			if mwcmqs_stop_matches(self.context_id, self.instance_id()) {
				self.subscribe_thread.release_stop_marker_on_completion();
			}
			self.subscribe_thread.defer_current_join()
		} else {
			self.subscribe_thread.join_or_wait()
		};

		if call_reset_mwcmqs_brocker && !self.subscribe_thread.is_pending() {
			reset_mwcmqs_brocker_if_current(self.context_id, self.instance_id());
		}
		result
	}

	fn is_running(&self) -> bool {
		self.broker.is_running()
	}

	fn set_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		original_slate: Slate,
		expected_peer_public_key: String,
		expected_response: SlatePurpose,
		slate_send_channel: Sender<Slate>,
	) -> Result<MqsResponseWaiterToken, Error> {
		self.broker.handler.set_notification_channels(
			slate_id,
			original_slate,
			expected_peer_public_key,
			expected_response,
			slate_send_channel,
		)
	}

	fn reset_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		waiter_token: &MqsResponseWaiterToken,
	) {
		self.broker
			.handler
			.reset_notification_channels(slate_id, waiter_token);
	}
}

#[derive(Clone)]
struct MWCMQSBroker {
	instance_id: u64,
	context_id: u32,
	running: Arc<AtomicBool>,
	healthy: Arc<AtomicBool>,
	stop_requested: Arc<AtomicBool>,
	pub mwcmqs_domain: String,
	pub mwcmqs_port: u16,
	pub print_to_log: bool,
	// Handler methods use their own fine-grained synchronization. Keeping a
	// non-reentrant mutex here would hold it across `on_slate`, including the
	// application receive callback; a callback that starts another MQS operation
	// would then deadlock while trying to register its notification channel.
	pub handler: Arc<dyn SubscriptionHandler>,
}

#[derive(Debug, PartialEq, Eq)]
enum MqsListenerReply {
	Ready,
	Messages { messages: Vec<MqsListenerMessage> },
	CloseNewLogin,
}

#[derive(Debug, PartialEq, Eq)]
struct MqsListenerMessage {
	id: String,
	body: String,
}

/// Number of redeliveries allowed after the first failed processing attempt.
///
/// SECURITY/AUDIT RATIONALE:
/// MWCMQS `delTo` is a cumulative acknowledgement, so leaving one message
/// unacknowledged also holds every later message in the queue. Retrying forever
/// lets a deterministic poison message block the wallet; acknowledging on the
/// first failure can instead lose an authenticated message after a transient
/// local failure (including failures whose broad error variant has lost its
/// original RNG, storage, or network provenance).
///
/// The broker therefore does not maintain an error-variant allowlist. Every
/// outcome other than `Processed` gets exactly three redeliveries. If the
/// initial attempt and all three retries fail, the fourth failure is logged and
/// acknowledged so later messages can proceed. This explicitly trades delivery
/// of that one persistently failing message for bounded availability of the
/// queue. The counter is deliberately in-memory: restarting the listener grants
/// a fresh bounded retry budget rather than adding durable transport state to
/// the wallet database.
const MAX_MQS_MESSAGE_RETRIES: u8 = 3;

#[derive(Debug, Eq, PartialEq)]
enum MqsMessageAttemptDecision {
	AcknowledgeProcessed,
	Retry { retry_number: u8, reason: String },
	AcknowledgeAfterRetries { reason: String },
}

/// Tracks only the head message because the cumulative acknowledgement policy
/// stops processing the batch as soon as that message is scheduled for retry.
#[derive(Debug, Default, Eq, PartialEq)]
struct MqsMessageRetryTracker {
	failed_message_id: Option<String>,
	failures: u8,
}

impl MqsMessageRetryTracker {
	fn record_attempt(
		&mut self,
		message_id: &str,
		result: MqsMessageResult,
	) -> MqsMessageAttemptDecision {
		match result {
			Ok(MqsMessageDisposition::Processed) => {
				self.failed_message_id = None;
				self.failures = 0;
				MqsMessageAttemptDecision::AcknowledgeProcessed
			}
			Ok(MqsMessageDisposition::Rejected) => self.record_failure(
				message_id,
				"message handler rejected the message".to_string(),
			),
			Err(error) => self.record_failure(message_id, error.to_string()),
		}
	}

	fn record_failure(&mut self, message_id: &str, reason: String) -> MqsMessageAttemptDecision {
		if self.failed_message_id.as_deref() != Some(message_id) {
			self.failed_message_id = Some(message_id.to_string());
			self.failures = 0;
		}

		self.failures = self.failures.saturating_add(1);

		if self.failures <= MAX_MQS_MESSAGE_RETRIES {
			MqsMessageAttemptDecision::Retry {
				retry_number: self.failures,
				reason,
			}
		} else {
			self.failed_message_id = None;
			self.failures = 0;
			MqsMessageAttemptDecision::AcknowledgeAfterRetries { reason }
		}
	}
}

enum MqsListenerRecord<'a> {
	Ready,
	Message {
		message_id: &'a str,
		message: &'a str,
	},
	CloseNewLogin,
}

/// Preserve the legacy MQS listener wire format used by secp256k1-zkp 0.7.x.
///
/// The old `Signature` debug representation was `Signature(<raw-64-byte-hex>)`,
/// and the MQS adapter removed that wrapper before sending the value. Serialize
/// the same raw bytes directly so Rust wrapper names such as `EcdsaSignature`
/// cannot leak into or otherwise change the protocol value.
fn serialize_mqs_listener_signature(signature: &EcdsaSignature) -> String {
	mwc_wallet_util::mwc_util::to_hex(&signature[..])
}

fn parse_mqs_sender_response(status: reqwest::StatusCode, response: &str) -> Result<u64, Error> {
	// The response body comes from a remote MQS endpoint. Escape control
	// characters so a malicious or compromised server cannot inject terminal
	// escape sequences or forged log lines through the displayed error.
	let response = &escape_for_display(response);
	if !status.is_success() {
		return Err(Error::MqsInvalidRespose(
			"mwcmqs".to_string(),
			format!("HTTP status {}: {}", status, response),
		));
	}

	let mut fields = response.split_whitespace();
	let status_token = fields
		.next()
		.ok_or_else(|| Error::MqsInvalidRespose("mwcmqs".to_string(), response.to_string()))?;
	let last_seen = fields
		.next()
		.ok_or_else(|| Error::MqsInvalidRespose("mwcmqs".to_string(), response.to_string()))?;
	if fields.next().is_some() || status_token != "lastSeen:" {
		return Err(Error::MqsInvalidRespose(
			"mwcmqs".to_string(),
			response.to_string(),
		));
	}
	last_seen
		.parse::<u64>()
		.map_err(|_| Error::MqsInvalidRespose("mwcmqs".to_string(), response.to_string()))
}

fn parse_mqs_listener_record(record: &str) -> Result<MqsListenerRecord<'_>, String> {
	match record {
		"mapmessage=nil" | "message: mapmessage=nil" => {
			return Ok(MqsListenerRecord::Ready);
		}
		"closenewlogin" | "message: closenewlogin" => {
			return Ok(MqsListenerRecord::CloseNewLogin);
		}
		_ => {}
	}

	let (message_id, message) = record
		.split_once(';')
		.ok_or_else(|| "message id expected".to_string())?;
	if message_id.is_empty()
		|| !message_id
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
	{
		return Err("listener response contains an invalid message id".to_string());
	}
	if message.is_empty() {
		return Err("listener response contains an empty message".to_string());
	}

	if matches!(message, "closenewlogin" | "message: closenewlogin") {
		return Ok(MqsListenerRecord::CloseNewLogin);
	}

	Ok(MqsListenerRecord::Message {
		message_id,
		message,
	})
}

fn parse_mqs_listener_reply(response: &str) -> Result<MqsListenerReply, String> {
	let response = response.trim_end_matches(['\r', '\n']);
	if response.is_empty() {
		return Err("mwcmqs listener returned an empty response".to_string());
	}

	if let Some(header_and_messages) = response.strip_prefix("messagelist: ") {
		let mut lines = header_and_messages.lines();
		let expected_messages = lines
			.next()
			.ok_or_else(|| "mwcmqs listener response is missing its message count".to_string())?
			.parse::<usize>()
			.map_err(|_| "mwcmqs listener returned an invalid message count".to_string())?;
		let message_lines: Vec<&str> = lines.collect();
		if message_lines.len() != expected_messages {
			return Err(format!(
				"mwcmqs listener declared {} messages but returned {}",
				expected_messages,
				message_lines.len()
			));
		}

		let mut messages = Vec::with_capacity(expected_messages);
		for line in message_lines {
			let record = line
				.strip_prefix("message[")
				.ok_or_else(|| "mwcmqs listener returned an invalid message wrapper".to_string())?;
			let (declared_len, record) = record
				.split_once("]: ")
				.ok_or_else(|| "mwcmqs listener returned an invalid message wrapper".to_string())?;
			let declared_len = declared_len
				.parse::<usize>()
				.map_err(|_| "mwcmqs listener returned an invalid message length".to_string())?;
			if record.len() != declared_len {
				return Err(format!(
					"mwcmqs listener declared a message length of {} but returned {} bytes",
					declared_len,
					record.len()
				));
			}

			match parse_mqs_listener_record(record)? {
				MqsListenerRecord::Ready => {}
				MqsListenerRecord::Message {
					message_id,
					message,
				} => {
					messages.push(MqsListenerMessage {
						id: message_id.to_string(),
						body: message.to_string(),
					});
				}
				MqsListenerRecord::CloseNewLogin => {
					return Ok(MqsListenerReply::CloseNewLogin);
				}
			}
		}

		return if messages.is_empty() {
			Ok(MqsListenerReply::Ready)
		} else {
			Ok(MqsListenerReply::Messages { messages })
		};
	}

	let record = response
		.strip_prefix("message: ")
		.ok_or_else(|| "mwcmqs listener returned an unexpected response".to_string())?;
	match parse_mqs_listener_record(record)? {
		MqsListenerRecord::Ready => Ok(MqsListenerReply::Ready),
		MqsListenerRecord::Message {
			message_id,
			message,
		} => Ok(MqsListenerReply::Messages {
			messages: vec![MqsListenerMessage {
				id: message_id.to_string(),
				body: message.to_string(),
			}],
		}),
		MqsListenerRecord::CloseNewLogin => Ok(MqsListenerReply::CloseNewLogin),
	}
}

impl MWCMQSBroker {
	fn new(
		context_id: u32,
		mwcmqs_domain: String,
		mwcmqs_port: u16,
		print_to_log: bool,
		handler: Box<dyn SubscriptionHandler>,
	) -> Result<Self, Error> {
		let instance_id = NEXT_MWCMQS_INSTANCE_ID
			.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				current.checked_add(1)
			})
			.map_err(|_| {
				Error::DataOverflow(
					"MWCMQS listener instance identifier space exhausted".to_string(),
				)
			})?;
		Ok(Self {
			instance_id,
			context_id,
			running: Arc::new(AtomicBool::new(false)),
			healthy: Arc::new(AtomicBool::new(false)),
			stop_requested: Arc::new(AtomicBool::new(false)),
			mwcmqs_domain,
			mwcmqs_port,
			print_to_log,
			handler: Arc::from(handler),
		})
	}

	fn begin_start(&self) -> Result<(), Error> {
		if self.stop_requested.load(Ordering::Acquire) {
			return Err(Error::MqsGenericError(
				"MWCMQS subscriber was stopped before startup".to_string(),
			));
		}
		self.running
			.compare_exchange(false, true, Ordering::SeqCst, Ordering::Acquire)
			.map_err(|_| Error::MqsGenericError("MQS listener is already running".into()))?;
		Ok(())
	}

	fn finish(&self) {
		self.healthy.store(false, Ordering::Release);
		self.running.store(false, Ordering::SeqCst);
	}

	fn stop_requested(&self) -> bool {
		self.stop_requested.load(Ordering::Acquire)
	}

	fn encrypt_slate(
		&self,
		slate: &Slate,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> Result<String, Error> {
		let pkey = to.address.public_key(secp, self.context_id).map_err(|e| {
			Error::LibWallet(format!(
				"Unable to parse address public key {}, {}",
				to.address.public_key, e
			))
		})?;
		let skey = secret_key.clone();
		let version = slate.lowest_version();
		let slate = VersionedSlate::into_version_plain(self.context_id, slate, version)
			.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?;
		let serde_json = serde_json::to_string(&slate)
			.map_err(|e| Error::MqsGenericError(format!("Unable convert Slate to Json, {}", e)))?;

		let message = EncryptedMessage::new(
			serde_json,
			&to.address,
			&pkey,
			&skey,
			secp,
			#[cfg(feature = "test-support")]
			false,
		)
		.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			Error::MqsGenericError(format!("Unable convert Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key, secp)
			.map_err(|e| Error::LibWallet(format!("Unable to sign challenge, {}", e)))?;
		let signature = signature.to_hex(secp).map_err(|e| {
			Error::LibWallet(format!("Unable to serialize challenge signature, {}", e))
		})?;

		let mser: &str = &message_ser;
		let mser: &str = &str::replace(mser, "{", "%7B");
		let mser: &str = &str::replace(mser, "}", "%7D");
		let mser: &str = &str::replace(mser, ":", "%3A");
		let mser: &str = &str::replace(mser, ",", "%2C");
		let mser: &str = &str::replace(mser, "\"", "%22");
		let mser: &str = &mser.trim().to_string();

		let fromstripped = from.get_stripped();

		Ok(format!(
			"mapmessage={}&from={}&signature={}",
			mser, &fromstripped, &signature
		))
	}

	fn post_slate(
		&self,
		slate: &Slate,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(Error::ClosedListener("mwcmqs".to_string()));
		}
		let pkey = to.address.public_key(secp, self.context_id).map_err(|e| {
			Error::LibWallet(format!(
				"Unable to parse address public key {}, {}",
				to.address.public_key, e
			))
		})?;
		let skey = secret_key.clone();
		let version = slate.lowest_version();
		let slate = VersionedSlate::into_version_plain(self.context_id, slate, version)
			.map_err(|e| Error::LibWallet(format!("Unable to process slate, {}", e)))?;

		let message = EncryptedMessage::new(
			serde_json::to_string(&slate).map_err(|e| {
				Error::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
			})?,
			&to.address,
			&pkey,
			&skey,
			secp,
			#[cfg(feature = "test-support")]
			false,
		)
		.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			Error::MqsGenericError(format!("Unable convert Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key, secp)
			.map_err(|e| Error::LibWallet(format!("Unable to sign challenge, {}", e)))?;
		let signature = signature.to_hex(secp).map_err(|e| {
			Error::LibWallet(format!("Unable to serialize challenge signature, {}", e))
		})?;

		let client = build_mwcmqs_client(Duration::from_secs(120))
			.map_err(|e| Error::GenericError(format!("Failed to build a client, {}", e)))?;

		let mser: &str = &message_ser;
		let fromstripped = from.get_stripped();

		let mut params = HashMap::new();
		params.insert("mapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let url = format!(
			"https://{}:{}/sender?address={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			&str::replace(&to.get_stripped(), "@", "%40")
		);
		let response = client.post(&url).form(&params).send();

		let mut response = response.map_err(|e| {
			Error::MqsInvalidRespose(format!("mwcmqs connection error, {}", e), "".into())
		})?;
		let response_status = response.status();
		let mut resp_str = "".to_string();
		response
			.read_to_string(&mut resp_str)
			.map_err(|e| Error::MqsInvalidRespose(format!("mwcmqs i/o error, {}", e), "".into()))?;

		let last_seen = parse_mqs_sender_response(response_status, &resp_str)?;
		if last_seen > 3600000 {
			self.do_log_warn(format!("\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the slate.",
									 to.get_stripped()));
		} else if last_seen > 150000 {
			let seconds = last_seen / 1000;
			self.do_log_warn(format!("\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the slate.",
											 to.get_stripped(), seconds));
		}

		Ok(())
	}

	#[cfg(feature = "swaps")]
	fn post_take(
		&self,
		swapmessage: &Message,
		to: &MWCMQSAddress,
		from: &MWCMQSAddress,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		if !self.is_running() {
			return Err(Error::ClosedListener("mwcmqs".to_string()));
		}
		let pkey = to.address.public_key(secp, self.context_id).map_err(|e| {
			Error::LibWallet(format!(
				"Unable to parse address public key {}, {}",
				to.address.public_key, e
			))
		})?;
		let skey = secret_key.clone();

		let message = EncryptedMessage::new(
			serde_json::to_string(&swapmessage).map_err(|e| {
				Error::MqsGenericError(format!("Unable convert Slate to Json, {}", e))
			})?,
			&to.address,
			&pkey,
			&skey,
			secp,
			#[cfg(feature = "test-support")]
			false,
		)
		.map_err(|e| Error::GenericError(format!("Unable encrypt slate, {}", e)))?;

		let message_ser = &serde_json::to_string(&message).map_err(|e| {
			Error::MqsGenericError(format!("Unable to convert Swap Message to Json, {}", e))
		})?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, secret_key, secp)
			.map_err(|e| Error::MqsGenericError(format!("sign_challenge error, {}", e)))?;
		let signature = signature.to_hex(secp).map_err(|e| {
			Error::MqsGenericError(format!("Unable to serialize challenge signature, {}", e))
		})?;

		let client = build_mwcmqs_client(Duration::from_secs(60)).map_err(|e| {
			Error::GenericError(format!("Failed to build a client for post_take, {}", e))
		})?;

		let mser: &str = &message_ser;
		let fromstripped = from.get_stripped();

		let mut params = HashMap::new();
		params.insert("swapmessage", mser);
		params.insert("from", &fromstripped);
		params.insert("signature", &signature);

		let url = format!(
			"https://{}:{}/sender?address={}",
			self.mwcmqs_domain,
			self.mwcmqs_port,
			&str::replace(&to.get_stripped(), "@", "%40")
		);
		let response = client.post(&url).form(&params).send();

		let mut response = response.map_err(|e| {
			Error::MqsInvalidRespose(format!("mwcmqs connection error, {}", e), "".into())
		})?;
		let response_status = response.status();
		let mut resp_str = "".to_string();
		response
			.read_to_string(&mut resp_str)
			.map_err(|e| Error::MqsInvalidRespose(format!("mwcmqs i/o error, {}", e), "".into()))?;

		let last_seen = parse_mqs_sender_response(response_status, &resp_str)?;
		if last_seen > 3600000 {
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the swap message.",
					to.get_stripped()
				);
			} else {
				info!(
					"\nWARNING: [{}] has not been connected to mwcmqs recently. This user might not receive the swap message.",
					to.get_stripped()
				);
			}
		} else if last_seen > 150000 {
			let seconds = last_seen / 1000;
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the swap message.",
					to.get_stripped(),
					seconds
				);
			} else {
				info!(
					"\nWARNING: [{}] has not been connected to mwcmqs for {} seconds. This user might not receive the swap message.",
					to.get_stripped(),
					seconds
				);
			}
		}

		Ok(())
	}

	fn process_listener_message(
		&self,
		message: &str,
		source_address: &ProvableAddress,
		secret_key: &SecretKey,
		secp: &Secp256k1,
	) -> MqsMessageResult {
		if matches!(
			message,
			"message: mapmessage=nil\n" | "mapmessage=nil" | "mapmessage=nil\n"
		) {
			return Ok(MqsMessageDisposition::Processed);
		}

		let fields_text = message
			.split_whitespace()
			.nth(1)
			.or_else(|| message.split_whitespace().next());
		let Some(fields_text) = fields_text else {
			self.do_log_error("Rejecting empty MWCMQS message".to_string());
			return Ok(MqsMessageDisposition::Rejected);
		};
		let fields: Vec<&str> = fields_text.split('&').collect();
		if fields.len() != 3 {
			self.do_log_error(format!(
				"Rejecting malformed MWCMQS message with {} fields",
				fields.len()
			));
			return Ok(MqsMessageDisposition::Rejected);
		}

		let from = fields
			.iter()
			.find_map(|field| field.strip_prefix("from="))
			.map(|value| str::replace(value.trim(), "%40", "@"));
		let signature = fields
			.iter()
			.find_map(|field| field.strip_prefix("signature="))
			.map(str::trim)
			.map(str::to_string);
		let message_value = fields.iter().find_map(|field| {
			field
				.strip_prefix("mapmessage=")
				.map(|value| ("slate", value))
				.or_else(|| {
					field
						.strip_prefix("swapmessage=")
						.map(|value| ("swap", value))
				})
		});
		let (Some(from), Some(signature), Some((message_kind, message_value))) =
			(from, signature, message_value)
		else {
			self.do_log_error(
				"Rejecting MWCMQS message with missing sender, signature, or payload".to_string(),
			);
			return Ok(MqsMessageDisposition::Rejected);
		};

		let decoded = str::replace(message_value, "%22", "\"");
		let decoded = str::replace(&decoded, "%7B", "{");
		let decoded = str::replace(&decoded, "%7D", "}");
		let decoded = str::replace(&decoded, "%3A", ":");
		let decoded = str::replace(&decoded, "%2C", ",");
		let decoded = decoded.trim().to_string();

		let from = match MWCMQSAddress::from_str(secp, self.context_id, &from) {
			Ok(from) => from,
			Err(e) => {
				self.do_log_error(format!(
					"Rejecting MWCMQS message with invalid sender: {}",
					e
				));
				return Ok(MqsMessageDisposition::Rejected);
			}
		};

		if message_kind == "slate" {
			let (mut slate, tx_proof) = match TxProof::from_response(
				self.context_id,
				&from.address,
				decoded,
				"".to_string(),
				signature,
				secret_key,
				source_address,
				secp,
			) {
				Ok(value) => value,
				Err(e) => {
					// Mark the attempt rejected. The broker deliberately gives every
					// failure the same bounded retry budget, then acknowledges it so a
					// poison message cannot block the cumulative queue forever.
					self.do_log_error(format!("Rejecting invalid MWCMQS slate: {}", e));
					return Ok(MqsMessageDisposition::Rejected);
				}
			};
			// The controller owns the outstanding-response state. Pass the
			// authenticated proof with the slate so the same state-first route
			// decides whether the proof has a sender-side consumer.
			return self
				.handler
				.on_slate(&from, &mut slate, tx_proof)
				.map_err(|e| {
					MqsRetryableError::new(format!("Unable to process incoming slate, {}", e))
				});
		}

		#[cfg(feature = "swaps")]
		{
			let swap_message = match SwapMessage::from_received(
				self.context_id,
				&from.address,
				decoded,
				"".to_string(),
				signature,
				secret_key,
				secp,
			) {
				Ok(message) => message,
				Err(e) => {
					self.do_log_error(format!("Rejecting invalid MWCMQS swap message: {}", e));
					return Ok(MqsMessageDisposition::Rejected);
				}
			};
			if let Some(ack_message) = self.handler.on_swap_message(&from, swap_message)? {
				let mqs_channel = MwcMqsChannel::new(self.context_id, from.to_string());
				mqs_channel
					.send_swap_message(&ack_message, secp)
					.map_err(|e| {
						MqsRetryableError::new(format!(
							"Unable to send swap acknowledgement, {}",
							e
						))
					})?;
			}
		}
		#[cfg(not(feature = "swaps"))]
		self.do_log_warn("Ignoring MWCMQS swap message because swaps are disabled".to_string());

		Ok(MqsMessageDisposition::Processed)
	}

	fn print_error(&self, messages: Vec<&str>, error: &str, code: i16) {
		self.do_log_error(format!(
			"ERROR: messages=[{:?}] produced error: {} (code={})",
			messages, error, code
		));
	}
	fn do_log_info(&self, message: String) {
		if self.print_to_log {
			info!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn do_log_warn(&self, message: String) {
		if self.print_to_log {
			warn!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn do_log_error(&self, message: String) {
		if self.print_to_log {
			error!("{}", message);
		} else {
			println!("{}", message);
		}
	}

	fn subscribe(
		&self,
		source_address: &ProvableAddress,
		secret_key: &SecretKey,
		secp: &Secp256k1,
		startup_sender: &mut Option<SyncSender<Result<(), String>>>,
	) -> () {
		let address = MWCMQSAddress::new(
			source_address.clone(),
			Some(self.mwcmqs_domain.clone()),
			Some(self.mwcmqs_port),
		);

		let nanoid = nanoid::nanoid!();
		'subscribe: loop {
			self.healthy.store(false, Ordering::Release);
			if self.stop_requested() || !self.running.load(Ordering::SeqCst) {
				break;
			}

			let secret_key = secret_key.clone();
			let cloned_address = address.clone();
			let mut is_in_warning = false;
			let mut subscription_established = false;

			let secs = 20;
			let cl = build_mwcmqs_client(Duration::from_secs(secs));
			let client = match cl {
				Ok(c) => c,
				Err(_) => {
					self.print_error([].to_vec(), "couldn't instantiate client", -101);
					thread::sleep(Duration::from_millis(1000));
					continue;
				}
			};

			let resp_result = client
				.get(&format!(
					"https://{}:{}/timenow?address={}",
					self.mwcmqs_domain,
					self.mwcmqs_port,
					str::replace(&cloned_address.get_stripped(), "@", "%40"),
				))
				.send();
			if self.stop_requested() {
				break 'subscribe;
			}

			// get time from server
			let time_now = match resp_result {
				Ok(mut resp) => {
					if !resp.status().is_success() {
						let startup_error = format!(
							"mwcmqs timenow request failed with HTTP status {}",
							resp.status()
						);
						self.do_log_error(startup_error.clone());
						report_mqs_startup(startup_sender, Err(startup_error));
						break 'subscribe;
					}
					let mut resp_str = "".to_string();
					let read_resp = resp.read_to_string(&mut resp_str);
					if self.stop_requested() {
						break 'subscribe;
					}
					if !read_resp.is_ok() {
						self.print_error([].to_vec(), "couldn't contact mwcmqs server", -10);
						thread::sleep(Duration::from_millis(1000));
						continue;
					} else {
						resp_str
					}
				}
				Err(_) => {
					if self.stop_requested() {
						break 'subscribe;
					}
					self.print_error([].to_vec(), "couldn't contact mwcmqs server", -10);
					thread::sleep(Duration::from_millis(1000));
					continue;
				}
			};
			if self.stop_requested() {
				break 'subscribe;
			}

			// SECURITY/AUDIT NOTE:
			// `/timenow` is controlled by the configured MQS broker, and this MQS
			// key is also used by other wallet protocols. Signing an unrestricted
			// response would create a chosen-message signing oracle and could allow
			// a broker to request a message usable as an ownership-proof transcript.
			//
			// The deployed broker protocol verifies a signature over the exact raw
			// `/timenow` response. We intentionally do not change or domain-separate
			// that signed message because doing so would change the MQS protocol and
			// require a coordinated broker upgrade. Instead, the wallet signs only
			// responses that parse as fresh integer timestamps. Ownership proofs also
			// use a versioned, domain-separated canonical transcript, so an accepted
			// timestamp signature cannot be reused as an ownership attestation.
			let time_now_valid = time_now
				.trim()
				.parse::<u64>()
				.map(|ts| {
					let now = SystemTime::now()
						.duration_since(UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0);
					ts.abs_diff(now) <= 300
				})
				.unwrap_or(false);
			if !time_now_valid {
				if self.stop_requested() {
					break 'subscribe;
				}
				self.print_error(
					[].to_vec(),
					"mwcmqs server returned an invalid or stale time_now value",
					-12,
				);
				thread::sleep(Duration::from_millis(1000));
				continue;
			}
			if self.stop_requested() {
				break 'subscribe;
			}

			let time_now_signature = crypto::sign_challenge(&time_now, &secret_key, secp)
				.map(|signature| serialize_mqs_listener_signature(&signature))
				.unwrap_or_default();

			if time_now_signature.is_empty() {
				self.print_error([].to_vec(), "Unable to sign starting message", -11);
				thread::sleep(Duration::from_millis(1000));
				continue;
			}

			let mut url = String::from(&format!(
				"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
				self.mwcmqs_domain,
				self.mwcmqs_port,
				str::replace(&cloned_address.get_stripped(), "@", "%40"),
				"nil".to_string(),
				time_now,
				time_now_signature
			));

			let first_url = String::from(&format!(
				"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}&first=true",
				self.mwcmqs_domain,
				self.mwcmqs_port,
				str::replace(&cloned_address.get_stripped(), "@", "%40"),
				"nil".to_string(),
				time_now,
				time_now_signature
			));
			let mut message_retry_tracker = MqsMessageRetryTracker::default();

			loop {
				let cloned_cloned_address = cloned_address.clone();
				// This existing long-poll loop owns every production path that can
				// cache an MQS transport proof. Reuse it for TTL maintenance rather
				// than keeping a separate proof-cache thread alive.
				prune_expired_proofs();

				if self.stop_requested() || !self.running.load(Ordering::SeqCst) {
					break;
				}

				let resp_result = if !subscription_established {
					client.get(&*first_url).send()
				} else {
					client.get(&*url).send()
				};
				if self.stop_requested() {
					break 'subscribe;
				}

				match resp_result {
					Err(e) => {
						if self.stop_requested() {
							break 'subscribe;
						}
						let connect_err = e.is_connect();
						let timeout_err = e.is_timeout();
						if timeout_err && !connect_err {
							// The broker holds established listener requests open. A
							// timeout may preserve an already-healthy subscription, but
							// cannot establish or restore health by itself.
							continue;
						}

						if self.healthy.swap(false, Ordering::AcqRel) {
							is_in_warning = true;
							self.do_log_warn(format!("\nWARNING: mwcmqs listener [{}] lost connection. Will try to restore in the background. tid=[{}]",
														 cloned_cloned_address.get_stripped(), nanoid));
						}
						thread::sleep(Duration::from_millis(5000));
					}
					Ok(mut resp) => {
						if !resp.status().is_success() {
							let response_error = format!(
								"mwcmqs listener request failed with HTTP status {}",
								resp.status()
							);
							self.healthy.store(false, Ordering::Release);
							self.do_log_error(response_error.clone());
							if startup_sender.is_some() {
								report_mqs_startup(startup_sender, Err(response_error));
								break 'subscribe;
							}
							is_in_warning = true;
							thread::sleep(Duration::from_millis(5000));
							continue;
						}

						let mut resp_str = "".to_string();
						let read_resp = resp.read_to_string(&mut resp_str);
						if self.stop_requested() {
							break 'subscribe;
						}
						if !read_resp.is_ok() {
							self.do_log_info(format!(
								"io error occured while trying to connect to {}. Will sleep for 5 second and will reconnect.",
								&format!("https://{}:{}", self.mwcmqs_domain, self.mwcmqs_port)
							));
							let response_error = format!("Error: {:?}", read_resp);
							self.healthy.store(false, Ordering::Release);
							self.do_log_error(response_error.clone());
							if startup_sender.is_some() {
								report_mqs_startup(startup_sender, Err(response_error));
								break 'subscribe;
							}
							is_in_warning = true;
							thread::sleep(Duration::from_millis(5000));
							continue;
						}

						let listener_reply = match parse_mqs_listener_reply(&resp_str) {
							Ok(reply) => reply,
							Err(parse_error) => {
								self.healthy.store(false, Ordering::Release);
								self.do_log_error(parse_error.clone());
								if startup_sender.is_some() {
									report_mqs_startup(startup_sender, Err(parse_error));
									break 'subscribe;
								}
								is_in_warning = true;
								thread::sleep(Duration::from_millis(5000));
								continue;
							}
						};
						if self.stop_requested() {
							break 'subscribe;
						}

						let messages = match listener_reply {
							MqsListenerReply::Ready => None,
							MqsListenerReply::Messages { messages } => Some(messages),
							MqsListenerReply::CloseNewLogin => {
								let close_error =
									"new login detected. mwcmqs listener will stop!".to_string();
								if self.running.load(Ordering::SeqCst) {
									self.do_log_error(format!("\nERROR: {}", close_error));
								}
								self.healthy.store(false, Ordering::Release);
								report_mqs_startup(startup_sender, Err(close_error));
								self.running.store(false, Ordering::SeqCst);
								break 'subscribe;
							}
						};
						if self.stop_requested() {
							break 'subscribe;
						}

						let was_healthy = self.healthy.swap(true, Ordering::AcqRel);
						if !subscription_established {
							self.do_log_warn(format!(
								"\nmwcmqs listener started for [{}] tid=[{}]",
								cloned_cloned_address.get_stripped(),
								nanoid
							));
						} else if !was_healthy && is_in_warning {
							self.do_log_warn(format!(
								"INFO: listener [{}] reestablished connection.",
								cloned_cloned_address.get_stripped()
							));
							is_in_warning = false;
						}
						subscription_established = true;
						report_mqs_startup(startup_sender, Ok(()));

						let Some(messages) = messages else {
							continue;
						};
						for message in messages {
							if self.stop_requested() {
								break 'subscribe;
							}
							let decision = message_retry_tracker.record_attempt(
								&message.id,
								self.process_listener_message(
									&message.body,
									source_address,
									&secret_key,
									secp,
								),
							);
							if self.stop_requested() {
								break 'subscribe;
							}

							let acknowledge = match decision {
								MqsMessageAttemptDecision::AcknowledgeProcessed => true,
								MqsMessageAttemptDecision::Retry {
									retry_number,
									reason,
								} => {
									self.do_log_error(format!(
										"MWCMQS message [{}] failed: {}. Leaving it unacknowledged for retry {}/{}; later messages remain pending because delTo is cumulative.",
										message.id,
										escape_for_display(&reason),
										retry_number,
										MAX_MQS_MESSAGE_RETRIES
									));
									false
								}
								MqsMessageAttemptDecision::AcknowledgeAfterRetries { reason } => {
									self.do_log_error(format!(
										"MWCMQS message [{}] still failed after its initial attempt and {} retries: {}. Advancing the cumulative acknowledgement so one failed message cannot permanently block the queue.",
										message.id,
										MAX_MQS_MESSAGE_RETRIES,
										escape_for_display(&reason)
									));
									true
								}
							};

							if !acknowledge {
								// `delTo` acknowledges a prefix, so processing a later
								// message here could accidentally acknowledge the failed one.
								break;
							}

							url = format!(
								"https://{}:{}/listener?address={}&delTo={}&time_now={}&signature={}",
								self.mwcmqs_domain,
								self.mwcmqs_port,
								str::replace(&cloned_address.get_stripped(), "@", "%40"),
								message.id,
								time_now,
								time_now_signature
							);
						}
					}
				}
			}
			self.healthy.store(false, Ordering::Release);
		}

		self.do_log_info(format!(
			"\nmwcmqs listener [{}] stopped. tid=[{}]",
			address.get_stripped(),
			nanoid
		));

		self.finish();
	}

	fn stop(&self) -> bool {
		let first_request = !self.stop_requested.swap(true, Ordering::AcqRel);
		self.running.store(false, Ordering::SeqCst);
		first_request
	}

	fn is_running(&self) -> bool {
		self.running.load(Ordering::SeqCst)
	}

	fn is_healthy(&self) -> bool {
		self.healthy.load(Ordering::Acquire)
	}
}

fn report_mqs_startup(
	startup_sender: &mut Option<SyncSender<Result<(), String>>>,
	result: Result<(), String>,
) {
	if let Some(sender) = startup_sender.take() {
		let _ = sender.send(result);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::adapters::types::CloseReason;
	use mwc_wallet_util::mwc_crates::secp::Message as SecpMessage;
	use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
	use std::io::{ErrorKind, Read as IoRead, Write as IoWrite};
	use std::net::TcpListener;
	use std::sync::atomic::AtomicU32;

	static NEXT_TEST_CONTEXT: AtomicU32 = AtomicU32::new(u32::MAX);

	struct NoopSubscriptionHandler;

	#[test]
	fn listener_signature_keeps_legacy_raw_hex_wire_format() {
		let secp = Secp256k1::new().unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1u8; 32]).unwrap();
		let message = SecpMessage::from_slice(&[2u8; 32]).unwrap();
		let signature = secp.sign(&message, &secret_key).unwrap();

		assert_eq!(
			serialize_mqs_listener_signature(&signature),
			"c13cffb80c4f281908f2753ab3def2161a57af9ebfb27b0fd125ad3e2330ef976026ad1eea7a1e5835689f26de1c690217006f8677dcb413c199019405ca7048"
		);
	}

	impl SubscriptionHandler for NoopSubscriptionHandler {
		fn on_open(&self) {}

		fn on_slate(
			&self,
			_from: &dyn Address,
			_slate: &mut Slate,
			_tx_proof: TxProof,
		) -> MqsMessageResult {
			Ok(MqsMessageDisposition::Processed)
		}

		fn on_close(&self, _result: CloseReason) {}

		fn on_dropped(&self) {}

		fn on_reestablished(&self) {}

		#[cfg(feature = "swaps")]
		fn on_swap_message(
			&self,
			_from: &dyn Address,
			_swap: Message,
		) -> Result<Option<Message>, MqsRetryableError> {
			Ok(None)
		}

		fn set_notification_channels(
			&self,
			_slate_id: &uuid::Uuid,
			_original_slate: Slate,
			_expected_peer_public_key: String,
			_expected_response: SlatePurpose,
			_slate_send_channel: Sender<Slate>,
		) -> Result<MqsResponseWaiterToken, Error> {
			MqsResponseWaiterToken::try_new()
		}

		fn reset_notification_channels(
			&self,
			_slate_id: &uuid::Uuid,
			_waiter_token: &MqsResponseWaiterToken,
		) {
		}
	}

	#[test]
	fn mqs_waiters_record_the_expected_response_purpose() {
		assert_eq!(
			expected_mqs_response_purpose(&SlatePurpose::SendInitial).unwrap(),
			SlatePurpose::SendResponse
		);
		assert_eq!(
			expected_mqs_response_purpose(&SlatePurpose::InvoiceInitial).unwrap(),
			SlatePurpose::InvoiceResponse
		);
		assert_eq!(
			expected_mqs_response_purpose(&SlatePurpose::InvoiceResponse).unwrap(),
			SlatePurpose::FullSlate
		);
		assert!(expected_mqs_response_purpose(&SlatePurpose::FullSlate).is_err());
	}

	#[test]
	fn mqs_message_policy_retries_rejections_and_errors_three_times() {
		let mut tracker = MqsMessageRetryTracker::default();
		let failed_attempts = [
			Ok(MqsMessageDisposition::Rejected),
			Err(MqsRetryableError::new("temporary local RNG failure")),
			Ok(MqsMessageDisposition::Rejected),
		];

		for (result, expected_retry) in failed_attempts.into_iter().zip(1..) {
			assert!(matches!(
				tracker.record_attempt("message-1", result),
				MqsMessageAttemptDecision::Retry { retry_number, .. }
					if retry_number == expected_retry
			));
		}

		assert!(matches!(
			tracker.record_attempt("message-1", Err(MqsRetryableError::new("still failing")),),
			MqsMessageAttemptDecision::AcknowledgeAfterRetries { .. }
		));
		assert_eq!(tracker, MqsMessageRetryTracker::default());
	}

	#[test]
	fn mqs_message_policy_clears_retry_count_after_success() {
		let mut tracker = MqsMessageRetryTracker::default();
		assert!(matches!(
			tracker.record_attempt("message-1", Ok(MqsMessageDisposition::Rejected)),
			MqsMessageAttemptDecision::Retry {
				retry_number: 1,
				..
			}
		));
		assert_eq!(
			tracker.record_attempt("message-1", Ok(MqsMessageDisposition::Processed)),
			MqsMessageAttemptDecision::AcknowledgeProcessed
		);
		assert!(matches!(
			tracker.record_attempt("message-2", Err(MqsRetryableError::new("new failure")),),
			MqsMessageAttemptDecision::Retry {
				retry_number: 1,
				..
			}
		));
	}

	fn test_publisher(context_id: u32) -> MWCMQPublisher {
		let secp = Secp256k1::new().unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let address = MWCMQSAddress::new(
			ProvableAddress::blank(),
			Some("localhost".to_string()),
			Some(443),
		);
		MWCMQPublisher::new(
			context_id,
			address,
			&secret_key,
			"localhost".to_string(),
			443,
			true,
			Box::new(NoopSubscriptionHandler),
		)
		.unwrap()
	}

	fn register_test_broker(
		context_id: u32,
		publisher: Arc<MWCMQPublisher>,
		subscriber: MWCMQSubscriber,
	) -> Result<(), Error> {
		let lifecycle_guard = lock_mwcmqs_lifecycle();
		init_mwcmqs_access_data(&lifecycle_guard, context_id, publisher, subscriber)
	}

	#[test]
	fn mqs_instance_id_exhaustion_does_not_wrap() {
		let counter = AtomicU64::new(u64::MAX - 1);

		assert_eq!(
			counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				current.checked_add(1)
			}),
			Ok(u64::MAX - 1)
		);
		assert_eq!(
			counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				current.checked_add(1)
			}),
			Err(u64::MAX)
		);
		assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
	}

	#[test]
	fn listener_reply_parser_accepts_expected_protocol_responses() {
		assert_eq!(
			parse_mqs_listener_reply("message: mapmessage=nil"),
			Ok(MqsListenerReply::Ready)
		);

		let message = "mapmessage=value&from=sender&signature=sig";
		assert_eq!(
			parse_mqs_listener_reply(&format!("message: message_id;{}\n", message)),
			Ok(MqsListenerReply::Messages {
				messages: vec![MqsListenerMessage {
					id: "message_id".to_string(),
					body: message.to_string(),
				}],
			})
		);

		let first = "first_id;mapmessage=one&from=sender&signature=sig";
		let second = "second_id;swapmessage=two&from=sender&signature=sig";
		let batch = format!(
			"messagelist: 2\nmessage[{}]: {}\nmessage[{}]: {}\n",
			first.len(),
			first,
			second.len(),
			second
		);
		assert_eq!(
			parse_mqs_listener_reply(&batch),
			Ok(MqsListenerReply::Messages {
				messages: vec![
					MqsListenerMessage {
						id: "first_id".to_string(),
						body: "mapmessage=one&from=sender&signature=sig".to_string(),
					},
					MqsListenerMessage {
						id: "second_id".to_string(),
						body: "swapmessage=two&from=sender&signature=sig".to_string(),
					},
				],
			})
		);
	}

	#[test]
	fn listener_reply_parser_recognizes_all_close_new_login_forms() {
		assert_eq!(
			parse_mqs_listener_reply("message: closenewlogin\n"),
			Ok(MqsListenerReply::CloseNewLogin)
		);

		let close = "closenewlogin";
		let batch = format!("messagelist: 1\nmessage[{}]: {}\n", close.len(), close);
		assert_eq!(
			parse_mqs_listener_reply(&batch),
			Ok(MqsListenerReply::CloseNewLogin)
		);
	}

	#[test]
	fn listener_reply_parser_rejects_semicolon_and_malformed_batch_responses() {
		assert!(parse_mqs_listener_reply("upstream; failure").is_err());
		assert_eq!(
			parse_mqs_listener_reply("message: missing-delimiter"),
			Err("message id expected".to_string())
		);
		assert!(
			parse_mqs_listener_reply("message: ;mapmessage=value&from=sender&signature=sig")
				.is_err()
		);
		assert!(parse_mqs_listener_reply("messagelist: 2\nmessage[13]: closenewlogin\n").is_err());
		assert!(parse_mqs_listener_reply("messagelist: 1\nmessage[99]: closenewlogin\n").is_err());
	}

	#[test]
	fn sender_response_requires_success_status_and_exact_last_seen_grammar() {
		assert_eq!(
			parse_mqs_sender_response(reqwest::StatusCode::OK, "lastSeen: 0").unwrap(),
			0
		);
		assert_eq!(
			parse_mqs_sender_response(reqwest::StatusCode::CREATED, "lastSeen: 150001").unwrap(),
			150001
		);
		assert!(
			parse_mqs_sender_response(reqwest::StatusCode::BAD_REQUEST, "lastSeen: 0").is_err()
		);
		assert!(
			parse_mqs_sender_response(reqwest::StatusCode::TEMPORARY_REDIRECT, "lastSeen: 0")
				.is_err()
		);
		assert!(parse_mqs_sender_response(reqwest::StatusCode::OK, "error 0").is_err());
		assert!(parse_mqs_sender_response(reqwest::StatusCode::OK, "lastSeen: -1").is_err());
		assert!(
			parse_mqs_sender_response(reqwest::StatusCode::OK, "lastSeen: 0 trailing").is_err()
		);

		// Control characters from a malicious endpoint must not reach the
		// displayed error verbatim.
		let err =
			parse_mqs_sender_response(reqwest::StatusCode::OK, "bad \u{1b}[2J\nforged log line")
				.unwrap_err();
		let msg = format!("{}", err);
		assert!(!msg.chars().any(char::is_control));
		assert!(msg.contains("\\u001b"));
	}

	#[test]
	fn mqs_client_rejects_plain_http_before_connecting() {
		let target = TcpListener::bind("127.0.0.1:0").unwrap();
		target.set_nonblocking(true).unwrap();
		let target_url = format!("http://{}/", target.local_addr().unwrap());
		let client = mwcmqs_client_builder(Duration::from_secs(2))
			.no_proxy()
			.build()
			.unwrap();

		assert!(client.get(target_url).send().is_err());
		assert!(matches!(
			target.accept(),
			Err(ref error) if error.kind() == ErrorKind::WouldBlock
		));
	}

	#[test]
	fn mqs_client_returns_redirect_without_forwarding_post_body() {
		let target = TcpListener::bind("127.0.0.1:0").unwrap();
		target.set_nonblocking(true).unwrap();
		let target_url = format!("http://{}/internal", target.local_addr().unwrap());

		let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
		let redirector_url = format!("http://{}/sender", redirector.local_addr().unwrap());
		let redirect_thread = thread::spawn(move || {
			let (mut stream, _) = redirector.accept().unwrap();
			stream
				.set_read_timeout(Some(Duration::from_secs(2)))
				.unwrap();
			let mut request = [0u8; 4096];
			let _ = IoRead::read(&mut stream, &mut request).unwrap();
			let response = format!(
				"HTTP/1.1 307 Temporary Redirect\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
				target_url
			);
			IoWrite::write_all(&mut stream, response.as_bytes()).unwrap();
		});

		// The production builder is HTTPS-only. Override only that setting so the
		// no-redirect policy itself can be exercised with a local raw HTTP server.
		let client = mwcmqs_client_builder(Duration::from_secs(2))
			.https_only(false)
			.no_proxy()
			.build()
			.unwrap();
		let response = client
			.post(redirector_url)
			.body("signed-encrypted-form-body")
			.send()
			.unwrap();
		redirect_thread.join().unwrap();

		assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
		assert!(matches!(
			target.accept(),
			Err(ref error) if error.kind() == ErrorKind::WouldBlock
		));
	}

	#[test]
	fn worker_terminal_state_retains_returned_error() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let instance_id = 1;
		begin_mwcmqs_observation(context_id, instance_id);
		let mut recorder = MqsTerminalRecorder::new(context_id, instance_id);
		let result: Result<(), Error> =
			Err(Error::MqsGenericError("fatal worker result".to_string()));
		recorder.complete(&result);
		drop(recorder);

		assert!(matches!(
			get_mwcmqs_listener_termination(context_id),
			Some(MqsTermination::Failed(message)) if message.contains("fatal worker result")
		));
		clear_mwcmqs_termination(context_id);
	}

	#[test]
	fn worker_terminal_state_retains_panic() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let instance_id = 1;
		begin_mwcmqs_observation(context_id, instance_id);
		let worker = thread::spawn(move || {
			let _recorder = MqsTerminalRecorder::new(context_id, instance_id);
			panic!("fatal worker panic");
		});

		assert!(worker.join().is_err());
		assert!(matches!(
			get_mwcmqs_listener_termination(context_id),
			Some(MqsTermination::Failed(message)) if message.contains("panicked")
		));
		clear_mwcmqs_termination(context_id);
	}

	#[test]
	fn worker_cleanup_unregisters_broker_without_losing_failure() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let broker = publisher.broker.clone();
		let subscriber = MWCMQSubscriber::new(&publisher);
		let join_control = subscriber.subscribe_thread.clone();
		let instance_id = subscriber.instance_id();
		register_test_broker(context_id, Arc::new(publisher), subscriber).unwrap();
		begin_mwcmqs_observation(context_id, instance_id);

		{
			let mut cleanup = MqsWorkerCleanup {
				context_id,
				instance_id,
				broker,
				join_control,
				terminal: MqsTerminalRecorder::new(context_id, instance_id),
				outcome: None,
			};
			let result: Result<(), Error> =
				Err(Error::MqsGenericError("fatal cleanup result".to_string()));
			cleanup.complete(&result);
		}

		assert!(get_mwcmqs_brocker(context_id).is_none());
		assert!(matches!(
			get_mwcmqs_listener_termination(context_id),
			Some(MqsTermination::Failed(message)) if message.contains("fatal cleanup result")
		));
		assert!(reset_mwcmqs_brocker(context_id).is_err());
		assert_eq!(get_mwcmqs_listener_termination(context_id), None);
	}

	#[test]
	fn stale_worker_cannot_overwrite_new_listener_state() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		begin_mwcmqs_observation(context_id, 1);
		let mut stale_recorder = MqsTerminalRecorder::new(context_id, 1);
		begin_mwcmqs_observation(context_id, 2);

		let stale_result: Result<(), Error> =
			Err(Error::MqsGenericError("stale failure".to_string()));
		stale_recorder.complete(&stale_result);

		assert_eq!(get_mwcmqs_listener_termination(context_id), None);
		clear_mwcmqs_termination(context_id);
	}

	#[test]
	fn broker_registry_rejects_duplicate_and_ignores_stale_cleanup() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let first_publisher = test_publisher(context_id);
		let first_subscriber = MWCMQSubscriber::new(&first_publisher);
		let first_id = first_subscriber.instance_id();
		register_test_broker(context_id, Arc::new(first_publisher), first_subscriber).unwrap();

		let stale_publisher = test_publisher(context_id);
		let stale_subscriber = MWCMQSubscriber::new(&stale_publisher);
		let stale_id = stale_subscriber.instance_id();
		assert!(
			register_test_broker(context_id, Arc::new(stale_publisher), stale_subscriber)
				.is_err()
		);

		reset_mwcmqs_brocker_if_current(context_id, stale_id);
		assert_eq!(
			get_mwcmqs_brocker(context_id).unwrap().1.instance_id(),
			first_id
		);
		assert!(!stop_mwcmqs_brocker_if_current(context_id, stale_id).unwrap());
		assert!(stop_mwcmqs_brocker_if_current(context_id, first_id).unwrap());

		assert!(get_mwcmqs_brocker(context_id).is_none());
	}

	#[test]
	fn duplicate_registration_of_subscriber_clone_does_not_stop_active_listener() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = Arc::new(test_publisher(context_id));
		let subscriber = MWCMQSubscriber::new(&publisher);

		register_test_broker(context_id, publisher.clone(), subscriber.clone()).unwrap();
		subscriber.broker.begin_start().unwrap();

		let duplicate_result =
			register_test_broker(context_id, publisher, subscriber.clone());
		assert!(matches!(
			duplicate_result,
			Err(Error::MqsGenericError(message))
				if message.contains("already running")
		));
		assert!(subscriber.is_mqs_running());
		assert!(!subscriber.broker.stop_requested());

		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn subscriber_start_requires_the_exact_registered_join_control() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = Arc::new(test_publisher(context_id));
		let subscriber = MWCMQSubscriber::new(&publisher);

		let mut unregistered = subscriber.clone();
		let error = unregistered.start().unwrap_err().to_string();
		assert!(error.contains("must be registered before startup"));
		assert!(!publisher.broker.is_running());

		register_test_broker(context_id, publisher.clone(), subscriber.clone()).unwrap();
		assert!(subscriber.is_registered_listener());

		// `new` shares the broker and instance id, but creates a distinct join
		// control. It must not be allowed to create an untracked listener worker.
		let mut independent_subscriber = MWCMQSubscriber::new(&publisher);
		assert_eq!(
			independent_subscriber.instance_id(),
			subscriber.instance_id()
		);
		assert!(!independent_subscriber.is_registered_listener());
		let error = independent_subscriber.start().unwrap_err().to_string();
		assert!(error.contains("must be registered before startup"));
		assert!(!publisher.broker.is_running());

		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn duplicate_registration_does_not_stop_candidate_under_lifecycle_lock() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = Arc::new(test_publisher(context_id));
		let subscriber = MWCMQSubscriber::new(&publisher);
		register_test_broker(context_id, publisher, subscriber).unwrap();

		let candidate_publisher = Arc::new(test_publisher(context_id));
		let candidate_broker = candidate_publisher.broker.clone();
		let mut candidate_subscriber = MWCMQSubscriber::new(&candidate_publisher);
		let duplicate_result = register_test_broker(
			context_id,
			candidate_publisher,
			candidate_subscriber.clone(),
		);
		assert!(matches!(
			duplicate_result,
			Err(Error::MqsGenericError(message))
				if message.contains("already running")
		));
		assert!(!candidate_broker.stop_requested());

		// The candidate remains harmless because an unregistered join control
		// cannot start after the lifecycle guard is released.
		let error = candidate_subscriber.start().unwrap_err().to_string();
		assert!(error.contains("must be registered before startup"));

		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn registration_rejects_mismatched_publisher_and_subscriber() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = Arc::new(test_publisher(context_id));
		let other_publisher = test_publisher(context_id);
		let other_broker = other_publisher.broker.clone();
		let other_subscriber = MWCMQSubscriber::new(&other_publisher);

		let result = register_test_broker(context_id, publisher, other_subscriber);
		assert!(matches!(
			result,
			Err(Error::MqsGenericError(message))
				if message.contains("do not belong to the requested context")
		));
		assert!(get_mwcmqs_brocker(context_id).is_none());
		assert!(!other_broker.stop_requested());
	}

	fn wait_for_stop_marker_release(context_id: u32) {
		let deadline = SystemTime::now() + Duration::from_secs(10);
		while mwcmqs_stop_in_progress(context_id) {
			assert!(
				SystemTime::now() < deadline,
				"stopping marker was not released for context {}",
				context_id
			);
			thread::sleep(Duration::from_millis(10));
		}
	}

	fn install_test_worker(subscriber: &MWCMQSubscriber, worker: MqsListenerHandle) {
		let mut inner = subscriber.subscribe_thread.inner.lock();
		assert!(matches!(inner.phase, MqsJoinPhase::Empty));
		inner.phase = MqsJoinPhase::Joinable(worker);
	}

	#[test]
	fn listener_wait_rejects_self_join_and_restores_handle() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);
		let (ticket_sender, ticket_receiver) = channel();
		let (result_sender, result_receiver) = channel();
		let (release_sender, release_receiver) = channel();

		let worker = thread::spawn(move || -> Result<(), Error> {
			let ticket: MqsListenerWait = ticket_receiver.recv().unwrap();
			let result = ticket.wait().map_err(|e| e.to_string());
			result_sender.send(result).unwrap();
			release_receiver.recv().unwrap();
			Ok(())
		});
		install_test_worker(&subscriber, worker);

		let ticket = subscriber.claim_subscribe_thread().unwrap();
		ticket_sender.send(ticket).unwrap();
		let error = result_receiver
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		assert!(error.contains("cannot join itself"));
		assert!(matches!(
			subscriber.subscribe_thread.inner.lock().phase,
			MqsJoinPhase::Joinable(_)
		));

		release_sender.send(()).unwrap();
		subscriber.subscribe_thread.join_or_wait().unwrap();
		assert!(!subscriber.is_join_pending());
	}

	#[test]
	fn init_rejected_while_stop_in_progress() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let broker = publisher.broker.clone();
		let stopping_subscriber = MWCMQSubscriber::new(&publisher);
		let instance_id = stopping_subscriber.instance_id();

		begin_mwcmqs_stop(context_id, stopping_subscriber.subscribe_thread.clone());
		let subscriber = MWCMQSubscriber::new(&publisher);
		assert!(register_test_broker(context_id, Arc::new(publisher), subscriber).is_err());
		// The rejected registration attempt must not disturb the marker.
		assert!(mwcmqs_stop_in_progress(context_id));
		assert!(!broker.stop_requested());

		// A stale instance must not release another instance's marker.
		end_mwcmqs_stop(context_id, instance_id + 1);
		assert!(mwcmqs_stop_in_progress(context_id));

		end_mwcmqs_stop(context_id, instance_id);
		assert!(!mwcmqs_stop_in_progress(context_id));

		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);
		register_test_broker(context_id, Arc::new(publisher), subscriber).unwrap();
		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn reset_from_listener_thread_defers_join_to_reaper() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);
		register_test_broker(context_id, Arc::new(publisher), subscriber.clone()).unwrap();

		// Emulate the async-listener setup: the shared slot holds the handle of
		// the very thread that stops the broker from a receive callback.
		let (go_sender, go_receiver) = channel();
		let (done_sender, done_receiver) = channel();
		let (exit_sender, exit_receiver) = channel();
		let worker = thread::spawn(move || -> Result<(), Error> {
			go_receiver.recv().unwrap();
			let stopped = reset_mwcmqs_brocker(context_id).is_ok();
			let _ = done_sender.send(stopped);
			exit_receiver.recv().unwrap();
			Ok(())
		});
		install_test_worker(&subscriber, worker);
		go_sender.send(()).unwrap();

		// Before the fix this deadlocked: stop() joined the current thread.
		assert_eq!(
			done_receiver.recv_timeout(Duration::from_secs(10)),
			Ok(true)
		);
		assert!(get_mwcmqs_brocker(context_id).is_none());
		assert!(subscriber.is_join_pending());
		assert!(mwcmqs_stop_in_progress(context_id));

		// The reaper releases the stopping marker once the join completes, and
		// a replacement listener may register afterwards.
		exit_sender.send(()).unwrap();
		wait_for_stop_marker_release(context_id);
		let replacement_publisher = test_publisher(context_id);
		let replacement_subscriber = MWCMQSubscriber::new(&replacement_publisher);
		register_test_broker(
			context_id,
			Arc::new(replacement_publisher),
			replacement_subscriber,
		)
		.unwrap();
		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn reset_from_other_thread_joins_inline_and_releases_marker() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);
		register_test_broker(context_id, Arc::new(publisher), subscriber.clone()).unwrap();

		// A stand-in worker that exits once the stop signal lands.
		let broker = subscriber.broker.clone();
		let worker = thread::spawn(move || -> Result<(), Error> {
			while !broker.stop_requested() {
				thread::sleep(Duration::from_millis(5));
			}
			Ok(())
		});
		install_test_worker(&subscriber, worker);

		reset_mwcmqs_brocker(context_id).unwrap();

		// The join happened inline, so the marker is already released and a
		// replacement may register immediately.
		assert!(!subscriber.is_join_pending());
		assert!(!mwcmqs_stop_in_progress(context_id));
		assert!(get_mwcmqs_brocker(context_id).is_none());
	}

	#[test]
	fn reset_waits_for_external_join_and_propagates_worker_failure() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);
		let broker = subscriber.broker.clone();
		register_test_broker(context_id, Arc::new(publisher), subscriber.clone()).unwrap();

		let (release_sender, release_receiver) = channel();
		let worker = thread::spawn(move || -> Result<(), Error> {
			release_receiver.recv().unwrap();
			Err(Error::MqsGenericError(
				"externally owned join failure".to_string(),
			))
		});
		install_test_worker(&subscriber, worker);

		// Emulate `wait_for_thread=true`: the synchronous controller owns the
		// unique handle, but the registry clone retains shared completion state.
		let listener_wait = subscriber.claim_subscribe_thread().unwrap();
		let (wait_sender, wait_receiver) = channel();
		thread::spawn(move || {
			let _ = wait_sender.send(listener_wait.wait().map_err(|e| e.to_string()));
		});

		let (reset_sender, reset_receiver) = channel();
		thread::spawn(move || {
			let _ = reset_sender.send(reset_mwcmqs_brocker(context_id).map_err(|e| e.to_string()));
		});

		let deadline = SystemTime::now() + Duration::from_secs(10);
		while !broker.stop_requested() {
			assert!(
				SystemTime::now() < deadline,
				"reset did not request listener shutdown"
			);
			thread::sleep(Duration::from_millis(10));
		}
		assert!(mwcmqs_stop_in_progress(context_id));
		assert!(reset_receiver.try_recv().is_err());

		// Once the first reset removes the registry entry, another reset must join
		// the same stopping worker rather than treating the absent entry as stopped.
		let (concurrent_reset_sender, concurrent_reset_receiver) = channel();
		thread::spawn(move || {
			let _ = concurrent_reset_sender
				.send(reset_mwcmqs_brocker(context_id).map_err(|e| e.to_string()));
		});
		assert!(concurrent_reset_receiver.try_recv().is_err());

		// A replacement remains forbidden until the externally owned join
		// publishes completion.
		let replacement_publisher = test_publisher(context_id);
		let replacement_subscriber = MWCMQSubscriber::new(&replacement_publisher);
		let replacement_result = register_test_broker(
			context_id,
			Arc::new(replacement_publisher),
			replacement_subscriber,
		);
		assert!(matches!(
			replacement_result,
			Err(Error::MqsGenericError(message))
				if message.contains("stop is still in progress")
		));

		release_sender.send(()).unwrap();
		let wait_error = wait_receiver
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		let reset_error = reset_receiver
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		let concurrent_reset_error = concurrent_reset_receiver
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		assert!(wait_error.contains("externally owned join failure"));
		assert!(reset_error.contains("externally owned join failure"));
		assert!(concurrent_reset_error.contains("externally owned join failure"));
		assert!(!mwcmqs_stop_in_progress(context_id));

		let replacement_publisher = test_publisher(context_id);
		let replacement_subscriber = MWCMQSubscriber::new(&replacement_publisher);
		register_test_broker(
			context_id,
			Arc::new(replacement_publisher),
			replacement_subscriber,
		)
		.unwrap();
		reset_mwcmqs_brocker(context_id).unwrap();
	}

	#[test]
	fn external_join_publishes_worker_panic_to_other_waiters() {
		let context_id = NEXT_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed);
		let publisher = test_publisher(context_id);
		let subscriber = MWCMQSubscriber::new(&publisher);

		let (release_sender, release_receiver) = channel();
		let worker = thread::spawn(move || -> Result<(), Error> {
			release_receiver.recv().unwrap();
			panic!("externally owned join panic");
		});
		install_test_worker(&subscriber, worker);

		let listener_wait = subscriber.claim_subscribe_thread().unwrap();
		let observer_control = subscriber.subscribe_thread.clone();
		let (observer_sender, observer_receiver) = channel();
		thread::spawn(move || {
			let _ = observer_sender.send(observer_control.join_or_wait().map_err(|e| e.to_string()));
		});

		release_sender.send(()).unwrap();
		let owner_error = listener_wait.wait().unwrap_err().to_string();
		let observer_error = observer_receiver
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		assert!(owner_error.contains("panicked"));
		assert!(observer_error.contains("panicked"));
	}
}
