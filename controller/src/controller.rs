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

//! Controller for wallet.. instantiates and handles listeners (or single-run
//! invocations) as needed.

use crate::Error;
use mwc_wallet_api::JsonId;
use mwc_wallet_libwallet::{
	InitTxArgs, MWC_BLOCK_HEADER_VERSION, NodeClient, NodeVersionInfo, Slate, VersionedSlate,
	WalletInst, WalletLCProvider,
};
use mwc_wallet_util::mwc_api::{
	ApiServer, BasicAuthMiddleware, HandlerObj, ResponseFuture, Router, TLSConfig,
};
use mwc_wallet_util::mwc_crates::bytes::{Bytes, BytesMut};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::http_body_util::Full;
use mwc_wallet_util::mwc_crates::hyper;
use mwc_wallet_util::mwc_crates::hyper::header::HeaderValue;
use mwc_wallet_util::mwc_crates::hyper::{Request, Response, StatusCode};
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::qr_code::QrCode;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::serde::{Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid;
use mwc_wallet_util::mwc_p2p;
use mwc_wallet_util::mwc_util::to_base64;
use mwc_wallet_util::mwc_util::{OnionV3Address, StopState};

use mwc_wallet_impls::{
	Address, CloseReason, MWCMQPublisher, MWCMQSAddress, MWCMQSubscriber, MqsMessageDisposition,
	MqsMessageResult, MqsResponseWaiterToken, MqsRetryableError, Publisher, Subscriber,
	SubscriptionHandler,
};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::message::Message;
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_util::mwc_core::core;

use crate::foreign::{ForeignApiServer, ForeignRequestAccess, is_valid_mining_node_ip};
use mwc_wallet_api::{
	EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign, ForeignCheckMiddleware,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpcV2, OwnerRpcV3, Token,
};
use mwc_wallet_config::MQSConfig;
use mwc_wallet_impls::tor;
use mwc_wallet_libwallet::proof::crypto;
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::proof::tx_proof::{
	ProofInsertResult, TxProof, clear_proofs_for_context_generation, next_proof_cache_generation,
	push_proof_for_slate, remove_proof_for_slate,
};
use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_libwallet::types::{
	TxSession, U64_DATA_IDX_ADDRESS_INDEX, bounded_escape_for_display,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::{
	Error as RpcError, Handler, InvalidArgs, MaybeReply, Params as RpcParams,
};
use mwc_wallet_util::mwc_crates::log::Level;
use mwc_wallet_util::mwc_crates::log::{debug, error, info, log_enabled, warn};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use mwc_wallet_util::mwc_crates::zeroize::{Zeroize, Zeroizing, optimization_barrier};
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_p2p::{PeerAddr, TorConfig};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SendError, Sender, SyncSender, sync_channel};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Duration;

const LISTENER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(feature = "swaps")]
const MAX_SWAP_MESSAGE_ERROR_DISPLAY_BYTES: usize = 2_048;
#[cfg(feature = "swaps")]
const MAX_SWAP_MESSAGE_SENDER_DISPLAY_BYTES: usize = 256;

#[cfg(feature = "swaps")]
fn bounded_swap_message_error(error: &Error) -> String {
	bounded_escape_for_display(&error.to_string(), MAX_SWAP_MESSAGE_ERROR_DISPLAY_BYTES)
}

/// Maximum time a foreign-API request waits for the wallet lifecycle read
/// guard before failing the request. Must stay well below the 30s transport
/// timeout used by the HTTP slate senders so a co-hosted `init_send_tx`
/// unwinds with a proper error instead of a deadlock; see
/// `with_stable_wallet_mask` for the full scenario.
const WALLET_LIFECYCLE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time a V3 `open_wallet`/`close_wallet` waits to acquire the wallet
/// lifecycle write guard before failing with "wallet busy". parking_lot
/// blocks new readers while a writer is queued, so an unbounded writer wait
/// starves every owner/foreign request behind a long-running batch.
const WALLET_LIFECYCLE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound dedicated worker threads created for Foreign API requests. Foreign
/// wallet operations frequently serialize on wallet locks, so additional
/// threads would consume resources without increasing useful throughput.
const MAX_FOREIGN_API_THREADS: usize = 32;
type ListenerStartupResult = Result<(), String>;
type ListenerStartupReportResult = Result<(), SendError<ListenerStartupResult>>;

#[derive(Clone)]
struct ListenerStartupSignal {
	sender: Arc<Mutex<Option<SyncSender<ListenerStartupResult>>>>,
}

/// Handles listener-initiated shutdown without attempting to join the listener
/// from its own thread.
///
/// This guard is dropped on the listener thread. It therefore cannot call
/// `ForeignApiServer::stop()` synchronously: `stop()` consumes the stored listener
/// handles and would try to join the thread which is currently running this
/// destructor. That thread cannot finish until the destructor returns, so such a
/// self-join can deadlock or panic.
///
/// Instead, the first exiting listener atomically leaves its server registered as
/// `Stopping` and schedules a non-listener reaper. Keeping the registry entry
/// prevents context release or replacement registration from treating the server
/// as gone. The reaper can safely join both listeners and all connection workers,
/// then remove the matching generation from the registry.
struct ForeignListenerCleanup {
	context_id: u32,
	instance_id: u64,
	stop_state: Arc<StopState>,
}

impl Drop for ForeignListenerCleanup {
	fn drop(&mut self) {
		self.stop_state.stop();
		// `true` elects exactly one listener to schedule teardown. A sibling or an
		// explicit stop which already sees `Stopping` must not start another reaper.
		if let Some((server, true)) =
			transition_foreign_api_server_to_stopping_if_current(self.context_id, self.instance_id)
		{
			schedule_foreign_api_server_reaper(self.context_id, self.instance_id, server);
		}
	}
}

impl ListenerStartupSignal {
	fn channel() -> (Self, Receiver<ListenerStartupResult>) {
		let (sender, receiver) = sync_channel(1);
		(
			Self {
				sender: Arc::new(Mutex::new(Some(sender))),
			},
			receiver,
		)
	}

	fn ready(&self) -> ListenerStartupReportResult {
		self.report(Ok(()))
	}

	fn failed(&self, error: String) -> ListenerStartupReportResult {
		self.report(Err(error))
	}

	fn report(&self, result: ListenerStartupResult) -> ListenerStartupReportResult {
		let sender = self.sender.lock().take();
		match sender {
			Some(sender) => sender.send(result),
			None => Ok(()),
		}
	}
}

fn wait_for_listener_startup(
	receiver: Receiver<ListenerStartupResult>,
	listener_name: &str,
) -> Result<(), Error> {
	match receiver.recv_timeout(LISTENER_STARTUP_TIMEOUT) {
		Ok(Ok(())) => Ok(()),
		Ok(Err(e)) => Err(Error::ListenerError(format!(
			"{} foreign listener failed to start: {}",
			listener_name, e
		))),
		Err(RecvTimeoutError::Timeout) => Err(Error::ListenerError(format!(
			"Timed out waiting for {} foreign listener startup",
			listener_name
		))),
		Err(RecvTimeoutError::Disconnected) => Err(Error::ListenerError(format!(
			"{} foreign listener terminated before reporting startup",
			listener_name
		))),
	}
}

static NEXT_OWNER_API_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_COHOSTED_FOREIGN_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

struct CoHostedForeignApi {
	instance_id: u64,
	owner_instance_id: u64,
	requests: Arc<ApiAvailabilityMiddleware>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForeignTorListenerReadiness {
	instance_id: u64,
	healthy: bool,
	onion_address: Option<String>,
}

enum ForeignApiEntry {
	Standalone(Arc<ForeignApiServer>),
	Stopping(Arc<ForeignApiServer>),
	CoHosted(CoHostedForeignApi),
}

#[derive(Clone)]
enum OwnerApiEntry {
	Starting {
		instance_id: u64,
	},
	Running {
		instance_id: u64,
		server: Arc<OwnerApiServer>,
	},
}

struct OwnerApiServer {
	requests: Arc<ApiAvailabilityMiddleware>,
	shutdown: Mutex<OwnerApiShutdown>,
}

enum OwnerApiShutdown {
	Running {
		api_server: ApiServer,
		api_thread: thread::JoinHandle<()>,
		request_completion: Receiver<()>,
		join_result_sender: Sender<OwnerApiJoinResult>,
	},
	Joined(OwnerApiJoinResult),
}

type OwnerApiJoinResult = Result<(), String>;

#[derive(Clone, Copy)]
enum OwnerApiExitReason {
	RequestedShutdown,
	UnexpectedTermination,
}

struct OwnerApiReservation {
	context_id: u32,
	instance_id: u64,
	active: bool,
}

struct CoHostedForeignRegistration {
	context_id: u32,
	instance_id: u64,
}

impl Drop for CoHostedForeignRegistration {
	fn drop(&mut self) {
		remove_cohosted_foreign_api_if_current(self.context_id, self.instance_id);
	}
}

impl OwnerApiReservation {
	fn reserve(context_id: u32) -> Result<Self, Error> {
		match OWNER_API.write().entry(context_id) {
			Entry::Vacant(entry) => {
				let instance_id = NEXT_OWNER_API_INSTANCE_ID
					.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
						current.checked_add(1)
					})
					.map_err(|_| {
						Error::DataOverflow(
							"Owner API instance identifier space exhausted".to_string(),
						)
					})?;
				entry.insert(OwnerApiEntry::Starting { instance_id });
				Ok(Self {
					context_id,
					instance_id,
					active: true,
				})
			}
			Entry::Occupied(_) => Err(Error::GenericError(
				"Owner API is already up and running".to_string(),
			)),
		}
	}

	fn promote(
		&mut self,
		api_server: ApiServer,
		api_thread: thread::JoinHandle<()>,
		requests: &Arc<ApiAvailabilityMiddleware>,
		join_result_sender: Sender<OwnerApiJoinResult>,
	) -> Result<(), (ApiServer, thread::JoinHandle<()>)> {
		let mut servers = OWNER_API.write();
		let is_current = matches!(
			servers.get(&self.context_id),
			Some(OwnerApiEntry::Starting { instance_id }) if *instance_id == self.instance_id
		);
		if !is_current {
			return Err((api_server, api_thread));
		}
		// Publish registration and request admission under the registry lock:
		// cleanup cannot miss this server once requests can reach it.
		let request_completion = requests.open();
		servers.insert(
			self.context_id,
			OwnerApiEntry::Running {
				instance_id: self.instance_id,
				server: Arc::new(OwnerApiServer {
					requests: requests.clone(),
					shutdown: Mutex::new(OwnerApiShutdown::Running {
						api_server,
						api_thread,
						request_completion,
						join_result_sender,
					}),
				}),
			},
		);
		self.active = false;
		Ok(())
	}
}

impl Drop for OwnerApiReservation {
	fn drop(&mut self) {
		if !self.active {
			return;
		}
		let mut servers = OWNER_API.write();
		let is_current = matches!(
			servers.get(&self.context_id),
			Some(OwnerApiEntry::Starting { instance_id }) if *instance_id == self.instance_id
		);
		if is_current {
			servers.remove(&self.context_id);
		}
	}
}

lazy_static! {
	pub static ref MWC_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_static("Basic realm=MWC-OwnerAPI");

	// Standalone and Stopping foreign entries retain ownership of their listener
	// and connection JoinHandles until teardown has synchronously joined them.
	// Owner entries remain registered until the API thread and all admitted
	// requests have drained, including HTTP/2 streams whose connections ended.
	static ref FOREIGN_API: RwLock<HashMap<u32, ForeignApiEntry>> = RwLock::new(HashMap::new());
	static ref OWNER_API: RwLock<HashMap<u32, OwnerApiEntry>> = RwLock::new(HashMap::new());

	static ref FOREIGN_API_HEALTH: RwLock<HashMap<u32, bool>> = RwLock::new(HashMap::new());
	// Primary Tor-listener state is generation-bound and independent from the
	// aggregate foreign-API health flag. In particular, a healthy secondary
	// plain-HTTP socket must not make an unhealthy Onion service appear ready.
	static ref FOREIGN_TOR_LISTENER_READINESS: RwLock<HashMap<u32, ForeignTorListenerReadiness>> =
		RwLock::new(HashMap::new());
}

pub fn get_foreign_api_health(context_id: u32) -> bool {
	FOREIGN_API_HEALTH
		.read()
		.get(&context_id)
		.cloned()
		.unwrap_or(false)
}

pub fn set_foreign_api_health(context_id: u32, healthy: bool) {
	FOREIGN_API_HEALTH.write().insert(context_id, healthy);
}

pub fn reset_foreign_api_health(context_id: u32) {
	FOREIGN_API_HEALTH.write().remove(&context_id);
}

/// Return the active OnionV3 identity only when the current standalone
/// foreign server's primary Tor listener is healthy and still accepting work.
pub fn get_healthy_foreign_tor_address(context_id: u32) -> Option<String> {
	let servers = FOREIGN_API.read();
	let server = match servers.get(&context_id) {
		Some(ForeignApiEntry::Standalone(server)) if !server.stop_state.is_stopped() => server,
		_ => return None,
	};
	let readiness = FOREIGN_TOR_LISTENER_READINESS.read();
	let readiness = readiness.get(&context_id)?;
	if readiness.instance_id != server.instance_id() || !readiness.healthy {
		return None;
	}
	readiness.onion_address.clone()
}

fn clear_foreign_tor_listener_if_current(context_id: u32, instance_id: u64) {
	let mut readiness = FOREIGN_TOR_LISTENER_READINESS.write();
	if readiness
		.get(&context_id)
		.is_some_and(|readiness| readiness.instance_id == instance_id)
	{
		readiness.remove(&context_id);
	}
}

/// Stop and join every HTTP listener capable of using this wallet context.
///
/// Context release is an external lifecycle operation. Calling it from one of
/// this context's own HTTP handlers would attempt to join the current request and
/// is unsupported, just like racing a direct library call with context release.
pub fn foreign_owner_api_clean_context(context_id: u32) {
	stop_foreign_api_running(context_id);

	let prev_owner_api = {
		let mut servers = OWNER_API.write();
		match servers.get(&context_id) {
			Some(OwnerApiEntry::Starting { .. }) => servers.remove(&context_id),
			entry => entry.cloned(),
		}
	};
	if let Some(owner_api) = prev_owner_api {
		// Intentionally diagnostic-only: this helper joins the thread, logs any
		// failure and sends the result to the owner_listener waiter. Context
		// cleanup must continue; it does not require a second error-reporting path.
		let _ = join_owner_api_entry(context_id, owner_api, OwnerApiExitReason::RequestedShutdown);
	}
}

pub fn is_foreign_api_running(context_id: u32) -> bool {
	FOREIGN_API.read().contains_key(&context_id)
}

pub fn is_owner_api_running(context_id: u32) -> bool {
	OWNER_API.read().contains_key(&context_id)
}

pub fn stop_foreign_api_running(context_id: u32) {
	let api = {
		let mut servers = FOREIGN_API.write();
		let api = match servers.remove(&context_id) {
			Some(ForeignApiEntry::Standalone(server)) | Some(ForeignApiEntry::Stopping(server)) => {
				servers.insert(context_id, ForeignApiEntry::Stopping(server.clone()));
				Some(ForeignApiEntry::Stopping(server))
			}
			Some(ForeignApiEntry::CoHosted(server)) => {
				// Close request admission before releasing the registry lock. Once the
				// vacant slot is observable, no request may enter through the old route.
				server.requests.close();
				Some(ForeignApiEntry::CoHosted(server))
			}
			None => None,
		};
		if api.is_some() {
			set_foreign_api_health(context_id, false);
			tor::status::set_tor_address(context_id, None);
			match &api {
				Some(ForeignApiEntry::Standalone(server))
				| Some(ForeignApiEntry::Stopping(server)) => {
					clear_foreign_tor_listener_if_current(context_id, server.instance_id())
				}
				Some(ForeignApiEntry::CoHosted(_)) => {
					FOREIGN_TOR_LISTENER_READINESS.write().remove(&context_id);
				}
				None => {}
			}
		}
		api
	};

	if let Some(api) = api {
		match api {
			ForeignApiEntry::Standalone(_) => unreachable!(),
			ForeignApiEntry::Stopping(server) => {
				let instance_id = server.instance_id();
				server.stop();
				finish_stopping_foreign_api_server_if_current(context_id, instance_id);
			}
			ForeignApiEntry::CoHosted(_) => {}
		}
	}
}

pub fn reset_foreign_api_server(context_id: u32) {
	stop_foreign_api_running(context_id);
}

pub fn set_foreign_api_server(
	context_id: u32,
	api_server: Option<Arc<ForeignApiServer>>,
) -> Result<(), Error> {
	stop_foreign_api_running(context_id);
	if let Some(server) = api_server {
		if let Err(e) = register_foreign_api_server(context_id, server.clone()) {
			server.stop();
			return Err(e);
		}
	}
	Ok(())
}

fn transition_foreign_api_server_to_stopping_if_current(
	context_id: u32,
	instance_id: u64,
) -> Option<(Arc<ForeignApiServer>, bool)> {
	let mut servers = FOREIGN_API.write();
	let (server, newly_stopping) = match servers.get(&context_id) {
		Some(ForeignApiEntry::Standalone(server)) if server.instance_id() == instance_id => {
			(server.clone(), true)
		}
		Some(ForeignApiEntry::Stopping(server)) if server.instance_id() == instance_id => {
			(server.clone(), false)
		}
		_ => return None,
	};
	if newly_stopping {
		servers.insert(context_id, ForeignApiEntry::Stopping(server.clone()));
	}
	// Mark the endpoint unavailable immediately. Generation-aware callbacks below
	// ignore Stopping entries, and final teardown repeats this cleanup while the
	// registry is still locked before making the slot vacant.
	set_foreign_api_health(context_id, false);
	tor::status::set_tor_address(context_id, None);
	clear_foreign_tor_listener_if_current(context_id, instance_id);
	Some((server, newly_stopping))
}

fn finish_stopping_foreign_api_server_if_current(context_id: u32, instance_id: u64) -> bool {
	let mut servers = FOREIGN_API.write();
	let is_current = matches!(
		servers.get(&context_id),
		Some(ForeignApiEntry::Stopping(server)) if server.instance_id() == instance_id
	);
	if is_current {
		// Keep replacement registration excluded until both status stores are clean.
		// A stale reaper therefore cannot erase a newer generation's status.
		set_foreign_api_health(context_id, false);
		tor::status::set_tor_address(context_id, None);
		clear_foreign_tor_listener_if_current(context_id, instance_id);
		servers.remove(&context_id);
	}
	is_current
}

fn stop_foreign_api_server_instance(
	context_id: u32,
	instance_id: u64,
	server: &Arc<ForeignApiServer>,
) {
	let is_current =
		transition_foreign_api_server_to_stopping_if_current(context_id, instance_id).is_some();
	server.stop();
	if is_current {
		finish_stopping_foreign_api_server_if_current(context_id, instance_id);
	}
}

fn schedule_foreign_api_server_reaper(
	context_id: u32,
	instance_id: u64,
	server: Arc<ForeignApiServer>,
) {
	let result = thread::Builder::new()
		.name(format!("wallet-foreign-reaper-{}", context_id))
		.spawn(move || {
			server.stop();
			finish_stopping_foreign_api_server_if_current(context_id, instance_id);
		});
	match result {
		Ok(reaper) => {
			// Detach intentionally; correctness depends on the retained Stopping entry
			// and shutdown coordination, not on another owner joining this helper.
			drop(reaper);
		}
		Err(e) => {
			// Fail closed: retaining Stopping prevents context reuse. A later explicit
			// context cleanup can still synchronously finish this server's teardown.
			error!(
				"Unable to start foreign API reaper for context {}: {}; server remains stopping",
				context_id, e
			);
		}
	}
}

fn register_foreign_api_server(
	context_id: u32,
	server: Arc<ForeignApiServer>,
) -> Result<(), Error> {
	match FOREIGN_API.write().entry(context_id) {
		Entry::Vacant(entry) => {
			let instance_id = server.instance_id();
			entry.insert(ForeignApiEntry::Standalone(server));
			FOREIGN_TOR_LISTENER_READINESS.write().insert(
				context_id,
				ForeignTorListenerReadiness {
					instance_id,
					healthy: false,
					onion_address: None,
				},
			);
			Ok(())
		}
		Entry::Occupied(_) => Err(Error::GenericError(
			"Foreign API is already up and running".to_string(),
		)),
	}
}

fn update_foreign_api_health_if_current(context_id: u32, instance_id: u64, healthy: bool) -> bool {
	let servers = FOREIGN_API.read();
	let is_current = matches!(
		servers.get(&context_id),
		Some(ForeignApiEntry::Standalone(server)) if server.instance_id() == instance_id
	);
	if is_current {
		set_foreign_api_health(context_id, healthy);
	}
	is_current
}

fn update_foreign_tor_health_if_current(context_id: u32, instance_id: u64, healthy: bool) -> bool {
	let servers = FOREIGN_API.read();
	let is_current = matches!(
		servers.get(&context_id),
		Some(ForeignApiEntry::Standalone(server)) if server.instance_id() == instance_id
	);
	if is_current {
		set_foreign_api_health(context_id, healthy);
		if let Some(readiness) = FOREIGN_TOR_LISTENER_READINESS.write().get_mut(&context_id)
			&& readiness.instance_id == instance_id
		{
			readiness.healthy = healthy;
		}
	}
	is_current
}

fn set_foreign_api_tor_address_if_current(
	context_id: u32,
	instance_id: u64,
	address: Option<String>,
) -> bool {
	let servers = FOREIGN_API.read();
	let is_current = matches!(
		servers.get(&context_id),
		Some(ForeignApiEntry::Standalone(server)) if server.instance_id() == instance_id
	);
	if is_current {
		tor::status::set_tor_address(context_id, address.clone());
		if let Some(readiness) = FOREIGN_TOR_LISTENER_READINESS.write().get_mut(&context_id)
			&& readiness.instance_id == instance_id
		{
			readiness.onion_address = address;
		}
	}
	is_current
}

fn is_foreign_api_server_current(context_id: u32, instance_id: u64) -> bool {
	FOREIGN_API.read().get(&context_id).is_some_and(|server| {
		matches!(
			server,
			ForeignApiEntry::Standalone(server) if server.instance_id() == instance_id
		)
	})
}

fn register_cohosted_foreign_api(
	context_id: u32,
	owner_instance_id: u64,
	requests: Arc<ApiAvailabilityMiddleware>,
) -> Result<u64, Error> {
	match FOREIGN_API.write().entry(context_id) {
		Entry::Vacant(entry) => {
			let instance_id = NEXT_COHOSTED_FOREIGN_INSTANCE_ID
				.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
					current.checked_add(1)
				})
				.map_err(|_| {
					Error::DataOverflow(
						"Co-hosted foreign API instance identifier space exhausted".to_string(),
					)
				})?;
			entry.insert(ForeignApiEntry::CoHosted(CoHostedForeignApi {
				instance_id,
				owner_instance_id,
				requests,
			}));
			FOREIGN_TOR_LISTENER_READINESS.write().remove(&context_id);
			Ok(instance_id)
		}
		Entry::Occupied(_) => Err(Error::GenericError(
			"Foreign API is already up and running".to_string(),
		)),
	}
}

fn enable_cohosted_foreign_api_if_current(
	context_id: u32,
	instance_id: u64,
	owner_instance_id: u64,
) -> bool {
	let servers = FOREIGN_API.read();
	let Some(ForeignApiEntry::CoHosted(server)) = servers.get(&context_id) else {
		return false;
	};
	if server.instance_id != instance_id || server.owner_instance_id != owner_instance_id {
		return false;
	}
	// The owner's outer middleware drains hosted requests. This gate only
	// controls availability of the foreign route, so it needs no drain waiter.
	drop(server.requests.open());
	true
}

fn remove_cohosted_foreign_api_if_current(context_id: u32, instance_id: u64) {
	let mut servers = FOREIGN_API.write();
	let is_current = matches!(
		servers.get(&context_id),
		Some(ForeignApiEntry::CoHosted(server)) if server.instance_id == instance_id
	);
	let removed = if is_current {
		servers.remove(&context_id)
	} else {
		None
	};
	if let Some(ForeignApiEntry::CoHosted(server)) = removed {
		server.requests.close();
		set_foreign_api_health(context_id, false);
		tor::status::set_tor_address(context_id, None);
		FOREIGN_TOR_LISTENER_READINESS.write().remove(&context_id);
	}
	drop(servers);
}

fn owner_api_if_current(
	context_id: u32,
	instance_id: u64,
	require_finished: bool,
) -> Option<OwnerApiEntry> {
	let entry = OWNER_API.read().get(&context_id).cloned()?;
	let OwnerApiEntry::Running {
		instance_id: current_id,
		server,
	} = &entry
	else {
		return None;
	};
	if *current_id != instance_id {
		return None;
	}
	// Never hold the registry lock while waiting for another shutdown caller.
	if require_finished {
		let shutdown = server.shutdown.lock();
		if let OwnerApiShutdown::Running { api_thread, .. } = &*shutdown {
			if !api_thread.is_finished() {
				return None;
			}
		}
	}
	Some(entry)
}

fn owner_api_panic_message(panic: Box<dyn std::any::Any + Send + 'static>) -> String {
	if let Some(message) = panic.downcast_ref::<&str>() {
		(*message).to_string()
	} else if let Some(message) = panic.downcast_ref::<String>() {
		message.clone()
	} else {
		"unknown panic payload".to_string()
	}
}

fn join_owner_api_thread(
	mut api_server: ApiServer,
	api_thread: thread::JoinHandle<()>,
	exit_reason: OwnerApiExitReason,
) -> OwnerApiJoinResult {
	let mut errors = Vec::new();
	match exit_reason {
		OwnerApiExitReason::RequestedShutdown => {
			if !api_server.stop() {
				errors.push("Unable to signal Owner API shutdown".to_string());
			}
		}
		OwnerApiExitReason::UnexpectedTermination => {
			errors.push("Owner API thread terminated unexpectedly".to_string());
		}
	}

	if let Err(panic) = api_thread.join() {
		errors.push(format!(
			"Owner API thread panicked: {}",
			owner_api_panic_message(panic)
		));
	}

	if errors.is_empty() {
		Ok(())
	} else {
		Err(errors.join("; "))
	}
}

fn cancel_owner_api_startup(api_server: ApiServer, api_thread: thread::JoinHandle<()>) -> Error {
	let cancellation = "Owner API startup was cancelled before registration";
	match join_owner_api_thread(
		api_server,
		api_thread,
		OwnerApiExitReason::RequestedShutdown,
	) {
		Ok(()) => Error::GenericError(cancellation.to_string()),
		Err(cleanup_error) => Error::GenericError(format!(
			"{}; cleanup failed: {}",
			cancellation, cleanup_error
		)),
	}
}

/// Join one registry-owned Owner API thread.
///
/// `RequestedShutdown` is the context-release path: close request admission,
/// ask Hyper to shut down gracefully, join the stored handle, and drain all
/// admitted requests. HTTP/2 stream tasks can outlive the API thread.
/// `UnexpectedTermination` means the API thread has already ended, but its
/// outstanding requests must still drain. The result channel unblocks the synchronous
/// `owner_listener` caller; it is not the lifecycle completion barrier.
fn join_owner_api_entry(
	context_id: u32,
	owner_api: OwnerApiEntry,
	exit_reason: OwnerApiExitReason,
) -> Option<OwnerApiJoinResult> {
	let OwnerApiEntry::Running {
		instance_id,
		server,
	} = owner_api
	else {
		// Listener startup is a direct call and is documented as externally
		// serialized against context release. There is no thread handle to join yet.
		return None;
	};

	server.requests.close();
	let result = {
		// Serialize joiners while retaining the registry entry. A context cleanup
		// racing the listener's reaper must wait for the same completion barrier.
		let mut shutdown = server.shutdown.lock();
		let previous = std::mem::replace(&mut *shutdown, OwnerApiShutdown::Joined(Ok(())));
		let result = match previous {
			OwnerApiShutdown::Running {
				api_server,
				api_thread,
				request_completion,
				join_result_sender,
			} => {
				let result = join_owner_api_thread(api_server, api_thread, exit_reason);
				// No messages are sent. Disconnection means every admitted request
				// dropped its sender after completing or joining its cancelled worker.
				while request_completion.recv().is_ok() {}
				if let Err(error) = &result {
					error!("{}", error);
				}
				if join_result_sender.send(result.clone()).is_err() {
					debug!("Owner API join result receiver was already dropped");
				}
				result
			}
			OwnerApiShutdown::Joined(result) => result,
		};
		*shutdown = OwnerApiShutdown::Joined(result.clone());
		result
	};
	let mut servers = OWNER_API.write();
	if matches!(servers.get(&context_id), Some(OwnerApiEntry::Running { instance_id: current, .. }) if *current == instance_id)
	{
		servers.remove(&context_id);
	}
	Some(result)
}

fn stop_owner_api_if_current(context_id: u32, instance_id: u64) -> Option<OwnerApiJoinResult> {
	let owner_api = owner_api_if_current(context_id, instance_id, false)?;
	join_owner_api_entry(context_id, owner_api, OwnerApiExitReason::RequestedShutdown)
}

fn wait_for_owner_api_join(
	context_id: u32,
	instance_id: u64,
	join_result_receiver: Receiver<OwnerApiJoinResult>,
) -> Result<(), Error> {
	loop {
		match join_result_receiver.recv_timeout(Duration::from_millis(100)) {
			Ok(result) => {
				return result.map_err(Error::GenericError);
			}
			Err(RecvTimeoutError::Timeout) => {
				// Normally context cleanup stops, joins and removes this entry. Polling
				// also reaps an API thread which terminated unexpectedly on its own.
				if let Some(owner_api) = owner_api_if_current(context_id, instance_id, true) {
					let _ = join_owner_api_entry(
						context_id,
						owner_api,
						OwnerApiExitReason::UnexpectedTermination,
					);
				}
			}
			Err(RecvTimeoutError::Disconnected) => {
				return Err(Error::GenericError(
					"Owner API join result channel disconnected".to_string(),
				));
			}
		}
	}
}

// This function has to use libwallet errors because of callback and runs on libwallet side
fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), mwc_wallet_libwallet::Error> {
	match name {
		// allow coinbases to be built regardless
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			let mut bhv = 2;
			if let Some(n) = node_version_info {
				bhv = n.block_header_version;
			}
			if let Some(s) = slate {
				if bhv > 3 && s.version_info.block_header_version < MWC_BLOCK_HEADER_VERSION {
					Err(mwc_wallet_libwallet::Error::Compatibility(
						"Incoming Slate is not compatible with this wallet. \
						 Please upgrade the node or use a different one."
							.into(),
					))?;
				}
			}
			Ok(())
		}
	}
}

/// get the tor address
pub fn get_tor_address<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
) -> Result<String, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mask = keychain_mask.lock();
	// eventually want to read a list of service config keys

	wallet_lock!(wallet, w_inst);

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let k = w_inst.keychain(&secp, (&mask).as_ref())?;
	let context_id = w_inst.get_context_id();
	let address_index: u32 = {
		let mut batch = w_inst.batch(&secp, (&mask).as_ref())?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"controller::get_tor_address, stored wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	let sec_key =
		proofaddress::payment_proof_address_dalek_secret(&secp, context_id, &k, address_index)
			.map_err(|e| {
				Error::TorConfig(format!("Unable to build key for onion address, {}", e))
			})?;
	let onion_addr = OnionV3Address::from_private(sec_key.as_bytes())
		.map_err(|e| Error::GenericError(format!("Unable to build Onion address, {}", e)))?;
	Ok(format!("{}", onion_addr))
}

/// Instantiate wallet Owner API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn owner_single_use<L, F, C, K, R>(
	wallet: Option<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>>,
	keychain_mask: Option<&SecretKey>,
	api_context: Option<&mut Owner<L, C, K>>,
	f: F,
) -> Result<R, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	F: FnOnce(&mut Owner<L, C, K>, Option<&SecretKey>) -> Result<R, Error>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let res = match api_context {
		Some(c) => f(c, keychain_mask)?,
		None => {
			let wallet = match wallet {
				Some(w) => w,
				None => {
					return Err(Error::GenericError(format!(
						"Instantiated wallet or Owner API context must be provided"
					)));
				}
			};
			let context_id = {
				wallet_lock!(wallet, w);
				w.get_context_id()
			};
			f(
				&mut Owner::new(context_id, wallet, None)?,
				keychain_mask,
			)?
		}
	};
	Ok(res)
}

/// Instantiate wallet Foreign API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn foreign_single_use<'a, L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	F: FnOnce(&mut Foreign<'a, L, C, K>) -> Result<(), Error>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	f(&mut Foreign::new(
		wallet,
		keychain_mask,
		Some(check_middleware),
	))?;
	Ok(())
}

//The following methods are added to support the mqs feature

fn controller_derive_address_key<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<SecretKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet, w);
	let k = w.keychain(secp, keychain_mask)?;
	let address_index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"controller::controller_derive_address_key, stored wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	let sec_addr_key =
		proofaddress::payment_proof_address_secret(secp, w.get_context_id(), &k, address_index)?;
	Ok(sec_addr_key)
}

#[derive(Clone)]
struct SlateResponseWaiter {
	registration_token: MqsResponseWaiterToken,
	sender: Sender<Slate>,
	original_slate: Slate,
	expected_peer_public_key: String,
	expected_response: SlatePurpose,
}

fn remove_slate_response_waiter_if_current(
	waiters: &mut HashMap<uuid::Uuid, SlateResponseWaiter>,
	slate_id: &uuid::Uuid,
	registration_token: &MqsResponseWaiterToken,
) -> bool {
	if waiters
		.get(slate_id)
		.is_some_and(|waiter| waiter.registration_token == *registration_token)
	{
		waiters.remove(slate_id);
		true
	} else {
		false
	}
}

fn register_slate_response_waiter(
	waiters: &mut HashMap<uuid::Uuid, SlateResponseWaiter>,
	slate_id: &uuid::Uuid,
	waiter: SlateResponseWaiter,
) -> Result<(), mwc_wallet_impls::Error> {
	match waiters.entry(slate_id.clone()) {
		Entry::Vacant(entry) => {
			entry.insert(waiter);
			Ok(())
		}
		Entry::Occupied(_) => Err(mwc_wallet_impls::Error::MqsGenericError(format!(
			"MQS exchange for slate {} is already in progress",
			slate_id
		))),
	}
}

/// Clear wallet-scoped transport proofs when the final clone of an MQS
/// controller goes away. A shared guard is required because `Controller`
/// itself is cloned for the publisher/handler wiring; clearing from every
/// clone's `Drop` would race an otherwise live controller.
///
/// The clear is scoped to this controller's listener generation: worker-held
/// or cloned publisher/subscriber Arcs can keep the lease alive after the
/// broker registry entry is gone, so a replacement listener for the same
/// wallet context may already be running (and caching proofs) when this
/// destructor finally runs. Context-wide clearing is reserved for
/// synchronized wallet-context release.
struct ProofCacheLease {
	context_id: u32,
	generation: u64,
}

impl Drop for ProofCacheLease {
	fn drop(&mut self) {
		clear_proofs_for_context_generation(self.context_id, self.generation);
	}
}

fn validate_mqs_waiter_response(
	waiter: &SlateResponseWaiter,
	response: &mut Slate,
) -> Result<(), Error> {
	match &waiter.expected_response {
		SlatePurpose::SendResponse => waiter
			.original_slate
			.validate_send_response(response)
			.map_err(|e| Error::GenericError(format!("invalid MQS send response slate: {}", e))),
		SlatePurpose::InvoiceResponse => {
			Slate::compare_slates_invoice(&waiter.original_slate, response).map_err(|e| {
				Error::GenericError(format!("invalid MQS invoice response slate: {}", e))
			})?;
			response.validate_response_participants().map_err(|e| {
				Error::GenericError(format!("invalid MQS invoice response participants: {}", e))
			})
		}
		SlatePurpose::FullSlate => waiter
			.original_slate
			.validate_invoice_response(response)
			.map_err(|e| Error::GenericError(format!("invalid MQS full slate: {}", e))),
		other => Err(Error::GenericError(format!(
			"invalid MQS response waiter purpose {:?}",
			other
		))),
	}
}

#[derive(Clone)]
pub struct Controller<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	context_id: u32,
	name: String,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,

	// Weak on purpose: the publisher's broker holds this controller as its
	// subscription handler, so a strong reference here would create a
	// controller -> publisher -> broker.handler -> controller cycle that keeps
	// the wallet, keychain mask and MQS secret key alive forever.
	publisher: Arc<Mutex<Option<Weak<dyn Publisher + Send + Sync>>>>,

	// mwc-wallet doesn have this field allways None. we don't want mwc-wallet to be able to process them.
	// Autoinvoice
	max_auto_accept_invoice: Option<u64>,

	slate_send_channel: Arc<Mutex<HashMap<uuid::Uuid, SlateResponseWaiter>>>,
	proof_cache_lease: Arc<ProofCacheLease>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	// what to do with logs. Print them to console or into the logs
	print_to_log: bool,
}

impl<L, C, K> Controller<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub fn new(
		name: &str,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		max_auto_accept_invoice: Option<u64>,
		print_to_log: bool,
	) -> Result<Self, Error>
	where
		L: WalletLCProvider<'static, C, K>,
		C: NodeClient + 'static,
		K: Keychain + 'static,
	{
		let context_id = {
			wallet_lock!(wallet, w);
			w.get_context_id()
		};

		if max_auto_accept_invoice.is_some() && global::is_mainnet(context_id) {
			return Err(Error::GenericError(
				"Auto invoicing must be disabled for the mainnet".to_owned(),
			));
		}
		let proof_cache_generation = next_proof_cache_generation()?;

		Ok(Self {
			context_id,
			name: name.to_string(),
			wallet,
			publisher: Arc::new(Mutex::new(None)),
			max_auto_accept_invoice,
			slate_send_channel: Arc::new(Mutex::new(HashMap::new())),
			proof_cache_lease: Arc::new(ProofCacheLease {
				context_id,
				generation: proof_cache_generation,
			}),
			keychain_mask,
			print_to_log,
		})
	}

	pub fn clone(&self) -> Self {
		Self {
			context_id: self.context_id,
			name: self.name.clone(),
			wallet: self.wallet.clone(),
			publisher: self.publisher.clone(),
			max_auto_accept_invoice: self.max_auto_accept_invoice.clone(),
			slate_send_channel: self.slate_send_channel.clone(),
			proof_cache_lease: self.proof_cache_lease.clone(),
			keychain_mask: self.keychain_mask.clone(),
			print_to_log: self.print_to_log,
		}
	}

	pub fn set_publisher(&self, publisher: Arc<dyn Publisher + Send + Sync>) {
		self.publisher.lock().replace(Arc::downgrade(&publisher));
	}

	fn mqs_receive_failure(
		&self,
		slate_id: &uuid::Uuid,
		operation: &str,
		error: mwc_wallet_libwallet::Error,
	) -> MqsMessageResult {
		// Do not classify broad libwallet error variants here. Some variants can
		// represent either peer-invalid input or a transient local RNG/storage/
		// network failure after lower layers have erased the origin. The broker
		// applies one documented three-retry budget to every failed attempt.
		Err(MqsRetryableError::new(format!(
			"Unable to process incoming slate {}, {} failed, {}",
			slate_id, operation, error
		)))
	}

	fn process_incoming_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		tx_proof: TxProof,
		dest_acct_name: &Option<String>,
		secp: &Secp256k1,
	) -> MqsMessageResult {
		// The transaction body is peer-controlled. Bound and structurally validate
		// it before waiter comparison, proof caching, cloning, wallet locking, or
		// signing. Full validation is inappropriate for a partially signed slate.
		if let Err(error) = slate.validate_transaction_read(self.context_id) {
			self.do_log_warn(format!(
				"Rejecting slate [{}] with an invalid transaction body: {}",
				slate.id, error
			));
			return Ok(MqsMessageDisposition::Rejected);
		}

		// A live locally-created exchange is authoritative for this UUID. Peer
		// controlled participant counts must never redirect its response into
		// the receive path.
		//
		// Bind the guard so the failed-send cleanup below reuses it. An unnamed
		// guard in the if-let scrutinee would stay alive for the whole body, and
		// re-locking this non-reentrant mutex there would deadlock this thread.
		let mut waiters = self.slate_send_channel.lock();
		if let Some(waiter) = waiters.get(&slate.id).cloned() {
			let authenticated_peer = match from.get_public_key() {
				Some(public_key) => public_key,
				None => {
					self.do_log_warn(format!(
						"Ignoring slate [{}] for an MQS response waiter from an address without an authenticated public key",
						slate.id
					));
					return Ok(MqsMessageDisposition::Rejected);
				}
			};
			if authenticated_peer != waiter.expected_peer_public_key {
				self.do_log_warn(format!(
					"Ignoring slate [{}] from unexpected MQS peer [{}]",
					slate.id,
					from.get_stripped()
				));
				return Ok(MqsMessageDisposition::Rejected);
			}
			if let Err(e) = validate_mqs_waiter_response(&waiter, slate) {
				self.do_log_warn(format!(
					"Ignoring invalid {:?} slate [{}] from expected MQS peer: {}",
					waiter.expected_response, slate.id, e
				));
				return Ok(MqsMessageDisposition::Rejected);
			}

			// Send and invoice responses are finalized locally and consume the
			// transport proof there. A FullSlate is already finalized by the
			// counterparty, so retaining its proof would leave it cached until
			// expiry.
			let proof_cached = if waiter.expected_response == SlatePurpose::FullSlate {
				drop(tx_proof);
				false
			} else {
				match push_proof_for_slate(
					self.context_id,
					self.proof_cache_lease.generation,
					&slate.id,
					tx_proof,
				) {
					ProofInsertResult::Inserted => {}
					ProofInsertResult::Duplicate => {
						self.do_log_warn(format!(
							"Ignoring duplicate MWCMQS proof for slate {}",
							slate.id
						));
						return Ok(MqsMessageDisposition::Rejected);
					}
					ProofInsertResult::Full => {
						return Err(MqsRetryableError::new(format!(
							"MWCMQS proof cache is full; leaving slate {} unacknowledged for retry",
							slate.id
						)));
					}
				}
				true
			};

			if let Err(e) = waiter.sender.send(slate.clone()) {
				if proof_cached {
					remove_proof_for_slate(self.context_id, &slate.id);
				}
				remove_slate_response_waiter_if_current(
					&mut waiters,
					&slate.id,
					&waiter.registration_token,
				);
				self.do_log_warn(format!(
					"Rejecting {:?} slate [{}] because its local response waiter is closed: {}",
					waiter.expected_response, slate.id, e
				));
				return Ok(MqsMessageDisposition::Rejected);
			}
			return Ok(MqsMessageDisposition::Processed);
		}
		// Release the waiter registry before the receive path, matching the
		// lifetime the scrutinee guard had before.
		drop(waiters);

		// New inbound requests have no sender-side consumer for the MQS proof.
		// Dropping it here zeroizes its message-decryption key.
		drop(tx_proof);

		// The receive path signs the slate's claimed payment-proof sender
		// address, so it must be bound to the MQS-authenticated peer. Without a
		// usable authenticated key this wallet must refuse to sign.
		let authenticated_sender = match from.get_public_key() {
			Some(public_key) => {
				match ProvableAddress::from_str(secp, self.context_id, public_key)
					.and_then(|address| address.public_key(secp, self.context_id))
				{
					Ok(key) => Some(key),
					Err(e) => {
						self.do_log_warn(format!(
							"Rejecting slate [{}] from an MQS peer with an invalid address public key: {}",
							slate.id, e
						));
						return Ok(MqsMessageDisposition::Rejected);
					}
				}
			}
			None => {
				self.do_log_warn(format!(
					"Rejecting slate [{}] from an MQS peer without an authenticated public key",
					slate.id
				));
				return Ok(MqsMessageDisposition::Rejected);
			}
		};

		// Keep one mask snapshot for the complete receive/persist operation. Wallet
		// switching is blocked while this MQS controller is live, so the snapshot
		// belongs to the same wallet for both backend accesses.
		let keychain_mask = self.keychain_mask.lock().clone();
		let foreign_api = Foreign::new(self.wallet.clone(), keychain_mask.clone(), None);

		if slate.num_participants > slate.participant_data.len() {
			let mut tx_session = TxSession::new();
			//TODO: this needs to be changed to properly figure out if this slate is an invoice or a send
			let tx = match slate.tx_or_err() {
				Ok(tx) => tx,
				Err(error) => {
					return self.mqs_receive_failure(&slate.id, "transaction extraction", error);
				}
			};
			if tx.inputs().len() == 0 {
				// mwc-wallet doesn't support invoices
				self.do_log_warn(format!(
					"Rejecting unsupported MWCMQS invoice slate [{}]",
					slate.id
				));
				return Ok(MqsMessageDisposition::Rejected);
			}

			let receive_result = match foreign_api.receive_tx(
				&mut tx_session,
				slate,
				Some(ReplyBinding::mqs(from.get_full_name())),
				Some(from.get_full_name()),
				authenticated_sender,
				dest_acct_name,
				None,
				true,
			) {
				Ok(result) => result,
				Err(
					mwc_wallet_libwallet::Error::ReceiveResponseUnavailable(id)
					| mwc_wallet_libwallet::Error::ReceiveResponseMismatch(id),
				) => {
					// The wallet mutation completed, but the short-lived
					// reply is gone or belongs to another authenticated
					// request. Mark this attempt rejected; the broker still applies
					// the uniform bounded retry policy before acknowledging it.
					// This path never inserts a proof into the cache, so it must
					// not remove one either: an entry with this UUID can belong to
					// an outgoing exchange whose finalization has not popped it yet.
					self.do_log_warn(format!(
							"MWCMQS slate [{}] was already received, but its reply cannot be returned safely; marking the duplicate rejected",
							id
						));
					return Ok(MqsMessageDisposition::Rejected);
				}
				Err(e) => {
					return self.mqs_receive_failure(&slate.id, "receive_tx", e);
				}
			};
			*slate = receive_result.slate;
			let _processing_guard = receive_result.processing_guard;
			let reply_reservation = receive_result.reply_reservation;
			let receive_data = receive_result.receive_data;

			if tx_session.get_context_participant().is_some() {
				self.do_log_error(format!(
						"Rejecting MWCMQS slate [{}]: receive_tx returned an already initialized transaction session participant",
						slate.id
					));
				return Ok(MqsMessageDisposition::Rejected);
			}
			if let Err(error) = tx_session.validate_tx_log_entry_size() {
				return self.mqs_receive_failure(&slate.id, "transaction log validation", error);
			}

			let publisher = match self
				.publisher
				.lock()
				.as_ref()
				.and_then(|weak| weak.upgrade())
			{
				Some(publisher) => publisher,
				None => {
					return Err(MqsRetryableError::new(
						"Publisher is not set, call set_publisher() method!!!",
					));
				}
			};
			publisher
				.post_slate(slate, from, secp)
				.map_err(|e| MqsRetryableError::new(format!("Unable to send slate back, {}", e)))?;

			// The response exchange succeeded. Commit the staged receiver state,
			// then make the exact reply available for a short MQS retry.
			// Accepted risk (see TxSession::save_tx_data): the response is
			// published before the state is durable, so a failure of the
			// save below can leave the originator finalizing a transaction
			// whose receiver output and log entry were never recorded; a
			// post_slate error is likewise ambiguous, since the originator
			// may have received the response anyway. Persisting before
			// publishing would close this window, at the cost of a durable
			// private context; we deliberately do not.
			if !tx_session.is_empty() {
				let save_result: Result<(), mwc_wallet_libwallet::Error> = (|| {
					wallet_lock!(self.wallet, w);
					tx_session.save_tx_data(secp, &mut **w, keychain_mask.as_ref(), &slate.id)
				})();
				save_result.map_err(|e| {
					MqsRetryableError::new(format!(
						"Unable to persist received slate {}, {}",
						slate.id, e
					))
				})?;
			}
			if let Some(reservation) = reply_reservation {
				reservation.complete(&*slate);
			}
			if let Some(receive_data) = receive_data {
				mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
			}
			self.do_log_info(format!(
				"slate [{}] sent back to [{}] successfully",
				slate.id.to_string(),
				from.get_stripped()
			));
			return Ok(MqsMessageDisposition::Processed);
		} else {
			let message = format!(
				"Slate {} arrived without an active notification waiter",
				slate.id
			);
			self.do_log_warn(message);
			// There is no consumer and the proof has already been dropped.
			// Acknowledging a late or unsolicited completed slate prevents it
			// from permanently blocking the cumulative MQS queue.
			Ok(MqsMessageDisposition::Rejected)
		}
	}

	#[cfg(feature = "swaps")]
	fn process_incoming_swap_message(
		&self,
		from: &dyn Address,
		swapmessage: Message,
	) -> Result<Option<Message>, Error> {
		let owner_api = Owner::new(self.context_id, self.wallet.clone(), None)?;
		let mask = self.keychain_mask.lock().clone();
		let authenticated_sender = from
			.get_public_key()
			.ok_or_else(|| {
				Error::ProcessSwapMessageError(
					"MWCMQS transport did not provide an authenticated sender key".to_string(),
				)
			})?
			.to_string();

		let msg_str = serde_json::to_string(&swapmessage).map_err(|e| {
			Error::ProcessSwapMessageError(format!(
				"Error in processing incoming swap message from mqs, {}",
				e
			))
		})?;
		let ack_msg = owner_api
			.swap_income_message((&mask).as_ref(), msg_str, Some(authenticated_sender))
			.map_err(|e| match e {
				// Keep the transient/deterministic distinction that the
				// libwallet boundary preserved; everything else flattens the
				// same way the blanket From conversion would.
				// Only the typed swap classification may request redelivery. A
				// generic secp error has lost provenance and is commonly a
				// deterministic result of peer-controlled keys or signatures.
				mwc_wallet_libwallet::Error::SwapTransient(message) => {
					Error::TransientSwapMessageError(message)
				}
				other => Error::LibWallet(format!("{}", other)),
			})?;

		Ok(ack_msg)
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
}

impl<L, C, K> SubscriptionHandler for Controller<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn on_open(&self) {
		self.do_log_warn(format!("listener started for [{}]", self.name));
	}

	fn on_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		tx_proof: TxProof,
	) -> MqsMessageResult {
		let display_from = from.get_stripped();

		if slate.num_participants > slate.participant_data.len() {
			// Don't print anything, the receive foreign API will do that.
		} else {
			self.do_log_info(format!(
				"slate [{}] received back from [{}] for [{}] MWCs",
				slate.id.to_string(),
				display_from,
				core::amount_to_hr_string(slate.amount, false)
			));
		};

		let secp = match Secp256k1::with_caps(ContextFlag::Commit) {
			Ok(secp) => secp,
			Err(e) => {
				return Err(MqsRetryableError::new(format!(
					"Unable to initialize secp context, {}",
					e
				)));
			}
		};

		self.process_incoming_slate(from, slate, tx_proof, &None, &secp)
	}

	#[cfg(feature = "swaps")]
	fn on_swap_message(
		&self,
		from: &dyn Address,
		swap: Message,
	) -> Result<Option<Message>, MqsRetryableError> {
		let swap_id = swap.id;
		match self.process_incoming_swap_message(from, swap) {
			Ok(message) => Ok(message),
			// Transient local failure: leave the message unacknowledged so the
			// broker redelivers it under its bounded retry budget.
			Err(Error::TransientSwapMessageError(message)) => Err(MqsRetryableError::new(message)),
			// Deterministic rejection: log and acknowledge via Ok(None) so a
			// poison message cannot block the cumulative queue.
			Err(e) => {
				self.do_log_error(format!(
					"Rejected incoming swap message {} from {}: {}",
					swap_id,
					bounded_escape_for_display(
						&from.get_stripped(),
						MAX_SWAP_MESSAGE_SENDER_DISPLAY_BYTES
					),
					bounded_swap_message_error(&e)
				));
				Ok(None)
			}
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => self.do_log_info(format!("listener [{}] stopped", self.name)),
			CloseReason::Abnormal(error) => self.do_log_error(format!(
				"ERROR: listener [{}] stopped unexpectedly: {}",
				self.name, error
			)),
		}
	}

	fn on_dropped(&self) {
		self.do_log_info(format!("WARNING: listener [{}] lost connection. it will keep trying to restore connection in the background.", self.name))
	}

	fn on_reestablished(&self) {
		self.do_log_info(format!(
			"INFO: listener [{}] reestablished connection.",
			self.name
		))
	}

	fn set_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		original_slate: Slate,
		expected_peer_public_key: String,
		expected_response: SlatePurpose,
		slate_send_channel: Sender<Slate>,
	) -> Result<MqsResponseWaiterToken, mwc_wallet_impls::Error> {
		let registration_token = MqsResponseWaiterToken::try_new()?;
		register_slate_response_waiter(
			&mut self.slate_send_channel.lock(),
			slate_id,
			SlateResponseWaiter {
				registration_token,
				sender: slate_send_channel,
				original_slate,
				expected_peer_public_key,
				expected_response,
			},
		)?;
		Ok(registration_token)
	}

	fn reset_notification_channels(
		&self,
		slate_id: &uuid::Uuid,
		registration_token: &MqsResponseWaiterToken,
	) {
		remove_slate_response_waiter_if_current(
			&mut self.slate_send_channel.lock(),
			slate_id,
			registration_token,
		);
	}
}

/// Identity of the exact MQS listener registered by a start call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MqsListenerInstance {
	pub context_id: u32,
	pub instance_id: u64,
}

pub fn init_start_mwcmqs_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	mqs_config: MQSConfig,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	wait_for_thread: bool,
) -> Result<MqsListenerInstance, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	warn!("Starting MWCMQS Listener");

	//start mwcmqs listener
	start_mwcmqs_listener(wallet, mqs_config, wait_for_thread, keychain_mask, true)
		.map_err(|e| Error::GenericError(format!("cannot start mqs listener, {}", e)))
}

/// Start the mqs listener
pub fn start_mwcmqs_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	mqs_config: MQSConfig,
	wait_for_thread: bool,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	print_to_log: bool,
) -> Result<MqsListenerInstance, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let context_id = {
		wallet_lock!(wallet, w);
		w.get_context_id()
	};
	let mqs_lifecycle_guard = mwc_wallet_impls::lock_mwcmqs_lifecycle();

	if mwc_wallet_impls::adapters::get_mwcmqs_brocker(context_id).is_some() {
		return Err(Error::GenericError(
			"mwcmqs listener is already running".to_string(),
		));
	}

	// make sure wallet is not locked, if it is try to unlock with no passphrase

	info!(
		"starting mwcmqs listener for {}:{}...",
		mqs_config.mwcmqs_domain, mqs_config.mwcmqs_port
	);

	let mwcmqs_domain = mqs_config.mwcmqs_domain;
	let mwcmqs_port = mqs_config.mwcmqs_port;

	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let mwcmqs_secret_key =
		controller_derive_address_key(wallet.clone(), &secp, keychain_mask.lock().as_ref())?;
	let mwc_pub_key = crypto::public_key_from_secret_key(&secp, &mwcmqs_secret_key)?;

	let mwcmqs_address = MWCMQSAddress::new(
		proofaddress::ProvableAddress::from_pub_key(&secp, context_id, &mwc_pub_key)?,
		Some(mwcmqs_domain.clone()),
		Some(mwcmqs_port),
	);

	let controller = Controller::new(
		&mwcmqs_address.get_stripped(),
		wallet.clone(),
		keychain_mask,
		None,
		print_to_log,
	)?;

	// The broker registry (MWCMQS_BROKER) is the strong owner of this Arc.
	// The controller keeps only a Weak reference to it, so removing the broker
	// from the registry drops publisher -> broker -> handler -> controller and
	// frees the wallet, keychain mask and MQS secret key instead of leaking
	// them through a strong-reference cycle.
	let mwcmqs_publisher = Arc::new(MWCMQPublisher::new(
		context_id,
		mwcmqs_address.clone(),
		&mwcmqs_secret_key,
		mwcmqs_domain,
		mwcmqs_port,
		print_to_log,
		Box::new(controller.clone()),
	)?);
	// Weak cross reference; does not keep the publisher alive on its own
	controller.set_publisher(mwcmqs_publisher.clone());

	let mut mwcmqs_subscriber = MWCMQSubscriber::new(&mwcmqs_publisher);
	let subscriber_instance_id = mwcmqs_subscriber.instance_id();

	mwc_wallet_impls::init_mwcmqs_access_data(
		&mqs_lifecycle_guard,
		context_id,
		mwcmqs_publisher,
		mwcmqs_subscriber.clone(),
	)?;
	if let Err(e) = mwcmqs_subscriber.start() {
		mwc_wallet_impls::reset_mwcmqs_brocker_if_current(context_id, subscriber_instance_id);
		error!("Unable to start mwcmqs controller, {}", e);
		return Err(Error::GenericError(format!(
			"Unable to start mwcmqs broker, {}",
			e
		)));
	}
	// subscriber_is_current closes a startup race between the worker becoming ready and start_mwcmqs_listener() returning.
	let subscriber_is_current =
		mwc_wallet_impls::get_mwcmqs_brocker(context_id).is_some_and(|(_, subscriber)| {
			subscriber.instance_id() == subscriber_instance_id && subscriber.is_mqs_running()
		});
	if !subscriber_is_current {
		if let Err(e) = mwcmqs_subscriber.stop(false) {
			error!(
				"Unable to stop MWCMQS listener after startup cancellation: {}",
				e
			);
		}
		mwc_wallet_impls::reset_mwcmqs_brocker_if_current(context_id, subscriber_instance_id);
		return Err(Error::GenericError(
			"MWCMQS listener stopped during startup".to_string(),
		));
	}
	// Claim the synchronous join before releasing the lifecycle lock. The
	// registry clone still observes the shared `Joining` state, so a concurrent
	// reset can wake the worker and wait for this owner to publish completion.
	let listener_wait = if wait_for_thread {
		Some(mwcmqs_subscriber.claim_subscribe_thread())
	} else {
		None
	};

	// The broker is now published. Wallet lifecycle calls will observe it and
	// reject switching until the matching stop operation completes.
	drop(mqs_lifecycle_guard);

	if let Some(listener_wait) = listener_wait {
		let listener_wait = match listener_wait {
			Ok(listener_wait) => listener_wait,
			Err(e) => {
				if let Err(stop_error) = mwcmqs_subscriber.stop(false) {
					error!(
						"Unable to stop MWCMQS listener with missing handle: {}",
						stop_error
					);
				}
				mwc_wallet_impls::reset_mwcmqs_brocker_if_current(
					context_id,
					subscriber_instance_id,
				);
				return Err(Error::GenericError(e.to_string()));
			}
		};
		let result = listener_wait.wait();
		mwc_wallet_impls::reset_mwcmqs_brocker_if_current(context_id, subscriber_instance_id);
		result?;
	}

	Ok(MqsListenerInstance {
		context_id,
		instance_id: subscriber_instance_id,
	})
}

/// Build a Basic authentication header while keeping intermediate credential
/// material in zeroizing allocations.
fn build_basic_auth_header_value(
	basic_auth_key: &str,
	api_secret: &Zeroizing<String>,
) -> Zeroizing<String> {
	let mut credentials = Zeroizing::new(String::with_capacity(
		basic_auth_key.len() + 1 + api_secret.len(),
	));
	credentials.push_str(basic_auth_key);
	credentials.push(':');
	credentials.push_str(api_secret.as_str());

	let encoded_credentials = Zeroizing::new(to_base64(credentials.as_str()));
	let mut header_value = Zeroizing::new(String::with_capacity(
		"Basic ".len() + encoded_credentials.len(),
	));
	header_value.push_str("Basic ");
	header_value.push_str(encoded_credentials.as_str());
	header_value
}

struct ApiAvailabilityMiddleware {
	// Every admitted response holds a sender clone. Closing this gate prevents
	// new clones; the receiver disconnects only after all responses are dropped.
	request_sender: Mutex<Option<Sender<()>>>,
	unavailable_status: StatusCode,
}

impl ApiAvailabilityMiddleware {
	fn new(unavailable_status: StatusCode) -> Self {
		Self {
			request_sender: Mutex::new(None),
			unavailable_status,
		}
	}

	fn open(&self) -> Receiver<()> {
		let (sender, receiver) = std::sync::mpsc::channel();
		*self.request_sender.lock() = Some(sender);
		receiver
	}

	fn close(&self) {
		self.request_sender.lock().take();
	}
}

struct TrackedApiResponse {
	// Fields drop in declaration order. Drop the response (which joins cancelled
	// RunHandlerInThread workers) before releasing its completion sender.
	response: ResponseFuture,
	_completion: Sender<()>,
}

impl std::future::Future for TrackedApiResponse {
	type Output = <ResponseFuture as std::future::Future>::Output;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Self::Output> {
		self.get_mut().response.as_mut().poll(cx)
	}
}

impl mwc_wallet_util::mwc_api::Handler for ApiAvailabilityMiddleware {
	fn call(
		&self,
		req: Request<Bytes>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		let completion = self.request_sender.lock().clone();
		if let Some(completion) = completion {
			let response = match handlers.next() {
				Some(handler) => handler.call(req, handlers),
				None => {
					let mut response = Response::new(Full::new(Bytes::new()));
					*response.status_mut() = StatusCode::NOT_FOUND;
					Box::pin(async move { Ok(response) })
				}
			};
			return Box::pin(TrackedApiResponse {
				response,
				_completion: completion,
			});
		}

		let mut response = Response::new(Full::new(Bytes::from_static(
			b"API listener is not available",
		)));
		*response.status_mut() = self.unavailable_status;
		Box::pin(async move { Ok(response) })
	}
}

/// Start the Owner API listener.
///
/// `api_secret == None` intentionally disables HTTP Basic authentication. This
/// is a supported, explicit deployment choice: callers may provide their own
/// authentication, process isolation, firewall, proxy, or other access control.
/// Without such controls, every client able to reach this listener, including a
/// browser origin able to reach loopback, can invoke state-changing Owner RPCs.
pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<Zeroizing<String>>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
	tor_config: Option<TorConfig>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut running_foreign = false;
	if owner_api_include_foreign.unwrap_or(false) {
		running_foreign = true;
	}

	let context_id = { wallet.lock().lc_provider()?.get_context_id() };
	let mut owner_reservation = OwnerApiReservation::reserve(context_id)?;
	let requests = Arc::new(ApiAvailabilityMiddleware::new(
		StatusCode::SERVICE_UNAVAILABLE,
	));
	let foreign_requests = Arc::new(ApiAvailabilityMiddleware::new(StatusCode::NOT_FOUND));
	let cohosted_foreign = if running_foreign {
		Some(CoHostedForeignRegistration {
			context_id,
			instance_id: register_cohosted_foreign_api(
				context_id,
				owner_reservation.instance_id,
				foreign_requests.clone(),
			)?,
		})
	} else {
		None
	};

	//I don't know why but it seems the warn message in controller.rs will get printed to console.
	warn!("owner listener started {}", addr);
	let mut router = Router::new();
	router.add_middleware(requests.clone());
	// Absence of a secret deliberately means that no authentication middleware
	// is installed. Keep this branch optional: deployments which select this
	// mode are responsible for enforcing their chosen access policy outside the
	// wallet process.
	if let Some(api_secret) = api_secret {
		let api_basic_auth = build_basic_auth_header_value("mwc", &api_secret);
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth.to_string(),
			&MWC_OWNER_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}

	let wallet_lifecycle_lock = Arc::new(RwLock::new(()));
	let api_handler_v2 = OwnerAPIHandlerV2::new(
		context_id,
		wallet.clone(),
		tor_config.clone(),
		wallet_lifecycle_lock.clone(),
	)?;
	let api_handler_v3 = OwnerAPIHandlerV3::new(
		context_id,
		wallet.clone(),
		keychain_mask.clone(),
		tor_config,
		wallet_lifecycle_lock.clone(),
	)?;

	router
		.add_route("/v2/owner", Arc::new(api_handler_v2))
		.map_err(|e| Error::GenericError(format!("Router failed to add route /v2/owner, {}", e)))?;

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|e| Error::GenericError(format!("Router failed to add route /v3/owner, {}", e)))?;

	// If so configured, add the foreign API to the same port
	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 =
			ForeignAPIHandlerV2::new(wallet, keychain_mask, wallet_lifecycle_lock);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|e| {
				Error::GenericError(format!("Router failed to add route /v2/foreign, {}", e))
			})?
			.add_middleware(foreign_requests);
	}
	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr
		.parse()
		.map_err(|e| Error::ArgumentError(format!("Invalid listen address {}, {}", addr, e)))?;
	let api_thread = match apis.start(socket_addr, router, tls_config) {
		Ok(api_thread) => api_thread,
		Err(e) => {
			return Err(Error::GenericError(format!(
				"API thread failed to start, {}",
				e
			)));
		}
	};
	let (join_result_sender, join_result_receiver) = std::sync::mpsc::channel();

	if let Err((unregistered_server, api_thread)) =
		owner_reservation.promote(apis, api_thread, &requests, join_result_sender)
	{
		return Err(cancel_owner_api_startup(unregistered_server, api_thread));
	}

	if let Some(cohosted) = cohosted_foreign.as_ref() {
		if !enable_cohosted_foreign_api_if_current(
			context_id,
			cohosted.instance_id,
			owner_reservation.instance_id,
		) {
			let cancellation = "Co-hosted Foreign API startup was cancelled before registration";
			let cleanup_result =
				stop_owner_api_if_current(context_id, owner_reservation.instance_id);
			return Err(match cleanup_result {
				Some(Err(cleanup_error)) => Error::GenericError(format!(
					"{}; cleanup failed: {}",
					cancellation, cleanup_error
				)),
				Some(Ok(())) | None => Error::GenericError(cancellation.to_string()),
			});
		}
	}
	warn!("HTTP Owner listener started.");
	wait_for_owner_api_join(
		context_id,
		owner_reservation.instance_id,
		join_result_receiver,
	)
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
/// Start a Foreign listener with an additional IP authorized to call the
/// mining-only `build_coinbase` RPC. Loopback IPs are always authorized, while
/// origins reported by the transport as Tor or unknown are denied that method.
pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: Option<String>,
	tor_config: &TorConfig,
	enable_secondary_socket_listener: bool,
	mining_node_ip: Option<IpAddr>,
) -> Result<Arc<ForeignApiServer>, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	if let Some(ip) = mining_node_ip
		&& !is_valid_mining_node_ip(ip)
	{
		return Err(Error::ArgumentError(format!(
			"Invalid mining_node_ip {}; expected a unicast source IP that is not link-local",
			ip
		)));
	}

	let socket_addr = match addr {
		Some(addr) => Some(addr.parse::<SocketAddr>().map_err(|e| {
			Error::ArgumentError(format!("Invalid foreign listen address {}, {}", addr, e))
		})?),
		None => None,
	};
	let secondary_required = enable_secondary_socket_listener && tor_config.is_tor_enabled();
	if (!tor_config.is_tor_enabled() || secondary_required) && socket_addr.is_none() {
		return Err(Error::ArgumentError(
			"A foreign listen address is required for the requested socket listener".to_string(),
		));
	}

	// Check if wallet has been opened first, get slatepack public key
	let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let (slatepack_secret, slatepack_pk, context_id) = {
		let mask = keychain_mask.lock().clone();
		wallet_lock!(wallet, w);
		let keychain = w.keychain(&secp, mask.as_ref())?;
		let context_id = w.get_context_id();
		let address_index: u32 = {
			let mut batch = w.batch(&secp, mask.as_ref())?;
			let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
			u32::try_from(index).map_err(|e| {
				Error::DataOverflow(format!(
					"controller::foreign_listener, stored wallet address index exceeds u32, index={} error={}",
					index, e
				))
			})?
		};
		let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
			&secp,
			context_id,
			&keychain,
			address_index,
		)?;
		let slatepack_pk = ed25519_dalek::VerifyingKey::from(&slatepack_secret);
		(slatepack_secret, slatepack_pk, context_id)
	};

	if is_foreign_api_running(context_id) {
		return Err(Error::GenericError(
			"Foreign API is already up and running".to_string(),
		));
	}

	warn!("Starting HTTP Foreign listener API server.");

	if mwc_wallet_util::mwc_util::is_console_output_enabled() {
		let address = ProvableAddress::from_tor_pub_key(&slatepack_pk)?;
		let qr_string = match QrCode::new(address.public_key.clone()) {
			Ok(qr) => qr.to_string(false, 3),
			Err(_) => "Failed to generate QR code!".to_string(),
		};
		warn!(
			"Slatepack Address is: {}\n{}",
			address.public_key, qr_string
		);
	}

	let keypair = Keypair::from_bytes(&slatepack_secret.as_bytes());
	let exp_key = ExpandedKeypair::from(&keypair);
	let onion_expanded_key = Zeroizing::new(exp_key.to_secret_key_bytes());

	let need_start_arti = tor_config.need_start_arti();

	let mut router = Router::new();
	let api_handler_v2 = ForeignAPIHandlerV2::new(
		wallet.clone(),
		keychain_mask.clone(),
		Arc::new(RwLock::new(())),
	);
	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|e| {
			Error::GenericError(format!("Router failed to add route /v2/foreign, {}", e))
		})?;

	let server = Arc::new(ForeignApiServer::new(router)?);
	register_foreign_api_server(context_id, server.clone())?;
	let server_instance_id = server.instance_id();

	let connection_counter = Arc::new(AtomicU64::new(0));
	let stop_state = server.stop_state.clone();
	let server2 = server.clone();
	let handle_new_connection_callback =
		move |stream: TcpDataStream, peer_address: Option<PeerAddr>| {
			let mut stream = stream;
			let connection_id = match connection_counter
				.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
					current.checked_add(1)
				})
				.map_err(|_| {
					Error::DataOverflow(
						"Foreign API connection identifier space exhausted".to_string(),
					)
				}) {
				Ok(connection_id) => connection_id,
				Err(e) => {
					error!("{}; stopping the Foreign API", e);
					// This callback runs on a listener thread, so only signal the shared
					// stop state here. Calling server.stop() could self-join the listener.
					server2.stop_state.stop();
					if let Err(shutdown_error) = stream.shutdown() {
						debug!(
							"Unable to shut down Foreign API connection rejected after identifier exhaustion: {}",
							shutdown_error
						);
					}
					return;
				}
			};
			stream.set_read_timeout(Duration::from_secs(30)); // 30 seconds to match the request client.
			stream.set_write_timeout(Duration::from_secs(30));
			let connection_name = format!("Foreign_connection_{}", connection_id);
			let request_access =
				ForeignRequestAccess::from_peer(peer_address.as_ref(), mining_node_ip);
			server2.accept_connection(connection_name, stream, request_access);
		};

	let (primary_startup, primary_startup_receiver) = ListenerStartupSignal::channel();
	let primary_started = primary_startup.clone();
	let primary_ready_stop_state = stop_state.clone();
	let service_started_callback = move |onion_address: Option<String>| {
		set_foreign_api_tor_address_if_current(
			context_id,
			server_instance_id,
			onion_address.clone(),
		);
		match onion_address {
			Some(addr) => info!("Foreign API is started at {}", addr),
			None => info!("Foreign API is started"),
		}
		if let Err(e) = primary_started.ready() {
			error!("Unable to report primary foreign listener startup: {}", e);
			primary_ready_stop_state.stop();
		}
	};
	let primary_failed = primary_startup.clone();
	let primary_failed_stop_state = stop_state.clone();
	let service_failed_callback = move |e: &mwc_p2p::Error| {
		if let Err(send_error) = primary_failed.failed(e.to_string()) {
			error!(
				"Unable to report primary foreign listener startup failure: {}",
				send_error
			);
			primary_failed_stop_state.stop();
			return true;
		}
		if need_start_arti {
			warn!(
				"Unable to start foreign listener, will retry soon. Error: {}",
				e
			);
			false
		} else {
			warn!("Unable to start foreign listener. Error: {}", e);
			true
		}
	};

	let context_id2 = context_id;
	let service_status_callback = move |healthy: bool| {
		update_foreign_tor_health_if_current(context_id2, server_instance_id, healthy);
	};

	let tor_config2 = tor_config.clone();
	let socket_addr2 = socket_addr;
	let handle_new_connection_callback2 = handle_new_connection_callback.clone();
	let primary_stop_state = stop_state.clone();
	let primary_terminal_signal = primary_startup.clone();

	let api_thread_primary = match thread::Builder::new()
		.name(format!("wallet-foreign-listener-{}", context_id))
		.spawn(move || -> Result<(), String> {
			let _cleanup = ForeignListenerCleanup {
				context_id,
				instance_id: server_instance_id,
				stop_state: primary_stop_state.clone(),
			};
			let res = mwc_wallet_util::mwc_p2p::listen(
				context_id,
				primary_stop_state.clone(),
				Some(tor_config2),
				socket_addr2,
				Some(onion_expanded_key),
				Some(service_started_callback),
				Some(service_failed_callback),
				Some(service_status_callback),
				handle_new_connection_callback2,
			);

			let result = match res {
				Ok(()) if primary_stop_state.is_stopped() => Ok(()),
				Ok(()) => Err("Primary foreign listener stopped unexpectedly".to_string()),
				Err(e) => Err(e.to_string()),
			};
			match &result {
				Ok(()) => {
					if let Err(e) = primary_terminal_signal.failed(
						"Primary foreign listener stopped before becoming ready".to_string(),
					) {
						error!(
							"Unable to report primary foreign listener termination: {}",
							e
						);
					}
				}
				Err(e) => {
					error!("Error starting foreign listener: {}", e);
					if let Err(send_error) = primary_terminal_signal.failed(e.clone()) {
						error!(
							"Unable to report primary foreign listener startup failure: {}",
							send_error
						);
					}
					primary_stop_state.stop();
				}
			}

			result
		}) {
		Ok(thread) => thread,
		Err(e) => {
			stop_foreign_api_server_instance(context_id, server_instance_id, &server);
			return Err(Error::ListenerError(format!(
				"Failed to start foreign listener thread, {}",
				e
			)));
		}
	};

	if let Err(e) = server.set_listener_thread_primary(api_thread_primary) {
		stop_foreign_api_server_instance(context_id, server_instance_id, &server);
		return Err(e.into());
	}
	if let Err(e) = wait_for_listener_startup(primary_startup_receiver, "primary") {
		stop_foreign_api_server_instance(context_id, server_instance_id, &server);
		return Err(e);
	}
	if server.stop_state.is_stopped()
		|| !is_foreign_api_server_current(context_id, server_instance_id)
	{
		stop_foreign_api_server_instance(context_id, server_instance_id, &server);
		return Err(Error::ListenerError(
			"Primary foreign listener stopped during startup".to_string(),
		));
	}

	if secondary_required {
		let socket_addr = socket_addr.ok_or_else(|| {
			Error::ArgumentError("Secondary foreign listener address is missing".to_string())
		})?;
		let (secondary_startup, secondary_startup_receiver) = ListenerStartupSignal::channel();
		let secondary_started = secondary_startup.clone();
		let secondary_ready_stop_state = server.stop_state.clone();
		let secondary_service_started = move |_address: Option<String>| {
			info!("Secondary socket foreign API is started at {}", socket_addr);
			if let Err(e) = secondary_started.ready() {
				error!("Unable to report secondary foreign listener startup: {}", e);
				secondary_ready_stop_state.stop();
			}
		};
		let secondary_failed = secondary_startup.clone();
		let secondary_failed_stop_state = server.stop_state.clone();
		let secondary_service_failed = move |e: &mwc_p2p::Error| {
			if let Err(send_error) = secondary_failed.failed(e.to_string()) {
				error!(
					"Unable to report secondary foreign listener startup failure: {}",
					send_error
				);
				secondary_failed_stop_state.stop();
			}
			warn!("Unable to start secondary foreign listener. Error: {}", e);
			true
		};
		let secondary_status_context = context_id;
		let secondary_service_status = move |healthy: bool| {
			update_foreign_api_health_if_current(
				secondary_status_context,
				server_instance_id,
				healthy,
			);
		};
		let secondary_stop_state = server.stop_state.clone();
		let secondary_terminal_signal = secondary_startup.clone();

		let api_thread_secondary = match thread::Builder::new()
			.name(format!("wallet-foreign-ip-listener-{}", context_id))
			.spawn(move || -> Result<(), String> {
				let _cleanup = ForeignListenerCleanup {
					context_id,
					instance_id: server_instance_id,
					stop_state: secondary_stop_state.clone(),
				};
				let listen_result = mwc_wallet_util::mwc_p2p::listen(
					context_id,
					secondary_stop_state.clone(),
					None,
					Some(socket_addr),
					None,
					Some(secondary_service_started),
					Some(secondary_service_failed),
					Some(secondary_service_status),
					handle_new_connection_callback,
				);
				let result = match listen_result {
					Ok(()) if secondary_stop_state.is_stopped() => Ok(()),
					Ok(()) => Err("Secondary foreign listener stopped unexpectedly".to_string()),
					Err(e) => Err(e.to_string()),
				};

				match &result {
					Ok(()) => {
						if let Err(e) = secondary_terminal_signal.failed(
							"Secondary foreign listener stopped before becoming ready".to_string(),
						) {
							error!(
								"Unable to report secondary foreign listener termination: {}",
								e
							);
						}
					}
					Err(e) => {
						error!("Error starting secondary foreign listener: {}", e);
						if let Err(send_error) = secondary_terminal_signal.failed(e.clone()) {
							error!(
								"Unable to report secondary foreign listener startup failure: {}",
								send_error
							);
						}
						secondary_stop_state.stop();
					}
				}
				result
			}) {
			Ok(thread) => thread,
			Err(e) => {
				stop_foreign_api_server_instance(context_id, server_instance_id, &server);
				return Err(Error::ListenerError(format!(
					"Failed to start secondary foreign listener thread, {}",
					e
				)));
			}
		};

		if let Err(e) = server.set_listener_thread_secondary(api_thread_secondary) {
			stop_foreign_api_server_instance(context_id, server_instance_id, &server);
			return Err(e.into());
		}
		if let Err(e) = wait_for_listener_startup(secondary_startup_receiver, "secondary") {
			stop_foreign_api_server_instance(context_id, server_instance_id, &server);
			return Err(e);
		}
		if server.stop_state.is_stopped()
			|| !is_foreign_api_server_current(context_id, server_instance_id)
		{
			stop_foreign_api_server_instance(context_id, server_instance_id, &server);
			return Err(Error::ListenerError(
				"Secondary foreign listener stopped during startup".to_string(),
			));
		}
	}

	Ok(server)
}

/// V2 API Handler/Wrapper for owner functions
pub struct OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Shared Owner instance for the whole listener lifetime.
	owner_api: Arc<Owner<L, C, K>>,
	/// Prevents open_wallet or close_wallet from replacing the backend while a
	/// V2 request is performing a multi-step wallet operation.
	wallet_lifecycle_lock: Arc<RwLock<()>>,
}

fn with_wallet_lifecycle_read<T>(
	wallet_lifecycle_lock: &RwLock<()>,
	use_wallet: impl FnOnce() -> T,
) -> T {
	let _wallet_lifecycle_guard = wallet_lifecycle_lock.read();
	use_wallet()
}

fn json_rpc_id_log_metadata(id: Option<&serde_json::Value>) -> String {
	match id {
		None => "<notification>".to_owned(),
		Some(serde_json::Value::Null) => "null".to_owned(),
		Some(serde_json::Value::String(id)) => bounded_escape_for_display(id, 128),
		Some(serde_json::Value::Number(id)) => id.to_string(),
		Some(_) => "<invalid>".to_owned(),
	}
}

/// Return bounded JSON-RPC envelope metadata suitable for debug logs without
/// rendering `params`, which can contain passwords or API credentials.
fn owner_api_request_log_metadata(value: &serde_json::Value) -> String {
	match value {
		serde_json::Value::Object(request) => {
			let method = request
				.get("method")
				.and_then(serde_json::Value::as_str)
				.unwrap_or("<invalid>");
			format!(
				"method={} id={}",
				bounded_escape_for_display(method, 128),
				json_rpc_id_log_metadata(request.get("id"))
			)
		}
		serde_json::Value::Array(requests) => format!("batch_size={}", requests.len()),
		_ => "invalid_envelope".to_string(),
	}
}

fn owner_api_response_outcome(value: &serde_json::Value) -> &'static str {
	let serde_json::Value::Object(response) = value else {
		return "invalid";
	};
	if response.contains_key("error") {
		return "rpc_error";
	}
	match response.get("result") {
		Some(serde_json::Value::Object(result)) if result.contains_key("Err") => {
			"application_error"
		}
		Some(_) => "success",
		None => "invalid",
	}
}

/// Describe only the response envelope. In particular, never render `result`,
/// `error.message`, or `error.data`: owner results can contain private keys.
fn owner_api_response_log_metadata(value: &serde_json::Value) -> String {
	match value {
		serde_json::Value::Object(response) => format!(
			"id={} outcome={}",
			json_rpc_id_log_metadata(response.get("id")),
			owner_api_response_outcome(value)
		),
		serde_json::Value::Array(responses) => {
			let mut success = 0;
			let mut application_error = 0;
			let mut rpc_error = 0;
			let mut invalid = 0;
			for response in responses {
				match owner_api_response_outcome(response) {
					"success" => success += 1,
					"application_error" => application_error += 1,
					"rpc_error" => rpc_error += 1,
					_ => invalid += 1,
				}
			}
			format!(
				"batch_size={} success={} application_error={} rpc_error={} invalid={}",
				responses.len(),
				success,
				application_error,
				rpc_error,
				invalid
			)
		}
		_ => "invalid_envelope".to_owned(),
	}
}

struct ZeroizingOwnerRpcParams(RpcParams);

/// Temporary owner-RPC string whose allocation is always erased unless it is
/// moved directly into another zeroizing owner. This is used for passwords,
/// mnemonics, and other secret strings while the remaining RPC arguments are
/// still being parsed and can fail.
struct ZeroizingOwnerRpcString(Option<String>);

impl<'de> Deserialize<'de> for ZeroizingOwnerRpcString {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: mwc_wallet_util::mwc_crates::serde::Deserializer<'de>,
	{
		String::deserialize(deserializer).map(|value| Self(Some(value)))
	}
}

impl Zeroize for ZeroizingOwnerRpcString {
	fn zeroize(&mut self) {
		if let Some(value) = self.0.as_mut() {
			value.zeroize();
		}
	}
}

impl Drop for ZeroizingOwnerRpcString {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl ZeroizingOwnerRpcString {
	fn into_string(mut self) -> String {
		self.0
			.take()
			.expect("zeroizing owner RPC string is always initialized")
	}
}

impl ZeroizingOwnerRpcParams {
	fn new(
		params: RpcParams,
		argument_names: &[&'static str],
	) -> Result<ZeroizingOwnerRpcParams, RpcError> {
		let params = ZeroizingOwnerRpcParams(params);
		match &params.0 {
			RpcParams::Positional(values) if values.len() != argument_names.len() => {
				return Err(InvalidArgs::WrongNumberOfArgs {
					expected: argument_names.len(),
					actual: values.len(),
				}
				.into());
			}
			RpcParams::Named(values) => {
				if let Some(extra_name) = values
					.keys()
					.find(|name| !argument_names.contains(&name.as_str()))
					.cloned()
				{
					return Err(InvalidArgs::ExtraNamedParameter { name: extra_name }.into());
				}
			}
			_ => {}
		}
		Ok(params)
	}
}

impl Drop for ZeroizingOwnerRpcParams {
	fn drop(&mut self) {
		match &mut self.0 {
			RpcParams::Positional(values) => {
				for value in values {
					zeroize_json_value(value);
				}
			}
			RpcParams::Named(values) => {
				for value in values.values_mut() {
					zeroize_json_value(value);
				}
			}
		}
	}
}

fn deserialize_zeroizing_owner_argument<T>(
	params: &ZeroizingOwnerRpcParams,
	argument_name: &'static str,
	argument_index: usize,
) -> Result<T, RpcError>
where
	for<'de> T: Deserialize<'de>,
{
	let missing_value = serde_json::Value::Null;
	let value = match &params.0 {
		RpcParams::Positional(values) => values
			.get(argument_index)
			.expect("sensitive RPC argument count was validated"),
		RpcParams::Named(values) => values.get(argument_name).unwrap_or(&missing_value),
	};

	// Deserialize from a reference so serde cannot consume and discard the
	// non-zeroizing JSON allocation. The enclosing parameter guard scrubs every
	// argument on both success and error; the resulting sensitive Rust type owns
	// a separate allocation and applies its own Drop/Zeroize implementation.
	//
	// Serde can also create field temporaries before rejecting an invalid
	// argument. Those failure-only temporaries are intentionally outside this
	// project's zeroization guarantee: their bytes come solely from rejected,
	// caller-supplied input, and recovering them already requires a separate
	// process-memory disclosure. This policy applies consistently to every RPC
	// argument type, including secret-bearing types; do not add custom
	// deserializers solely to scrub partially constructed values on parse error.
	// It does not exempt successfully constructed values, wallet-derived secrets,
	// or code which ignores a deserialization error from normal zeroization rules.
	T::deserialize(value).map_err(|_| {
		InvalidArgs::invalid_arg_structure(
			argument_name,
			argument_index,
			"parsing error".to_owned(),
		)
		.into()
	})
}

/// Decorate the generated Owner V2 handler only where arguments contain
/// secrets. Other methods retain the generated dispatch implementation.
struct ZeroizingOwnerRpcV2Handler<'a, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	api: &'a Owner<L, C, K>,
}

impl<L, C, K> Handler for ZeroizingOwnerRpcV2Handler<'_, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn handle(&self, method: &str, params: RpcParams) -> Result<serde_json::Value, RpcError> {
		match method {
			"init_send_tx" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["args"])?;
				let args =
					deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 0)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV2>::init_send_tx(self.api, args);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"process_invoice_tx" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["slate", "args"])?;
				let slate = deserialize_zeroizing_owner_argument::<VersionedSlate>(
					&params, "slate", 0,
				)?;
				let args =
					deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 1)?;
				drop(params);
				let result =
					<Owner<L, C, K> as OwnerRpcV2>::process_invoice_tx(self.api, slate, args);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"verify_payment_proof" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["proof"])?;
				let proof =
					deserialize_zeroizing_owner_argument::<TxProof>(&params, "proof", 0)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV2>::verify_payment_proof(self.api, proof);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			_ => {
				let api: &dyn OwnerRpcV2 = self.api;
				<dyn OwnerRpcV2 as Handler>::handle(api, method, params)
			}
		}
	}
}

/// Decorate the generated Owner V3 handler where arguments contain API
/// credentials, wallet passwords or mnemonic material, rewind capability, or a
/// payment-proof message-decryption key. The generated handler consumes its JSON
/// arguments, which can free secret-bearing JSON storage without first
/// overwriting it. Retain those arguments in a zeroizing guard until
/// deserialization has made typed copies that apply their own secret-erasure
/// policy.
///
/// This is intentionally not a general request/response zeroization layer.
/// Most RPC data is not secret, and duplicating all generated dispatch code
/// solely to scrub it would add complexity and maintenance risk without a
/// meaningful security benefit. Add targeted handling only for JSON values
/// that contain sensitive material requiring zeroization.
struct ZeroizingOwnerRpcV3Handler<'a, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	api: &'a Owner<L, C, K>,
}

impl<L, C, K> Handler for ZeroizingOwnerRpcV3Handler<'_, L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn handle(&self, method: &str, params: RpcParams) -> Result<serde_json::Value, RpcError> {
		match method {
			"init_send_tx" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["token", "args"])?;
				let token = deserialize_zeroizing_owner_argument::<Token>(&params, "token", 0)?;
				let args = deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 1)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::init_send_tx(self.api, token, args);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"process_invoice_tx" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["token", "slate", "args"])?;
				let token = deserialize_zeroizing_owner_argument::<Token>(&params, "token", 0)?;
				let slate =
					deserialize_zeroizing_owner_argument::<VersionedSlate>(&params, "slate", 1)?;
				let args = deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 2)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::process_invoice_tx(
					self.api, token, slate, args,
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"verify_payment_proof" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["token", "proof"])?;
				let token = deserialize_zeroizing_owner_argument::<Token>(&params, "token", 0)?;
				let proof = deserialize_zeroizing_owner_argument::<TxProof>(&params, "proof", 1)?;
				drop(params);
				let result =
					<Owner<L, C, K> as OwnerRpcV3>::verify_payment_proof(self.api, token, proof);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"scan_rewind_hash" => {
				let params =
					ZeroizingOwnerRpcParams::new(params, &["rewind_hash", "start_height"])?;
				let rewind_hash = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params,
					"rewind_hash",
					0,
				)?;
				let start_height = deserialize_zeroizing_owner_argument::<Option<u64>>(
					&params,
					"start_height",
					1,
				)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::scan_rewind_hash(
					self.api,
					rewind_hash.into_string(),
					start_height,
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"create_wallet" => {
				let params = ZeroizingOwnerRpcParams::new(
					params,
					&["name", "mnemonic", "mnemonic_length", "password"],
				)?;
				let name =
					deserialize_zeroizing_owner_argument::<Option<String>>(&params, "name", 0)?;
				let mnemonic = deserialize_zeroizing_owner_argument::<
					Option<ZeroizingOwnerRpcString>,
				>(&params, "mnemonic", 1)?;
				let mnemonic_length =
					deserialize_zeroizing_owner_argument::<u32>(&params, "mnemonic_length", 2)?;
				let password = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params, "password", 3,
				)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::create_wallet(
					self.api,
					name,
					mnemonic.map(ZeroizingOwnerRpcString::into_string),
					mnemonic_length,
					password.into_string(),
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"open_wallet" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["name", "password"])?;
				let name =
					deserialize_zeroizing_owner_argument::<Option<String>>(&params, "name", 0)?;
				let password = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params, "password", 1,
				)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::open_wallet(
					self.api,
					name,
					password.into_string(),
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"get_mnemonic" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["name", "password"])?;
				let name =
					deserialize_zeroizing_owner_argument::<Option<String>>(&params, "name", 0)?;
				let password = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params, "password", 1,
				)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::get_mnemonic(
					self.api,
					name,
					password.into_string(),
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			"change_password" => {
				let params = ZeroizingOwnerRpcParams::new(params, &["name", "old", "new"])?;
				let name =
					deserialize_zeroizing_owner_argument::<Option<String>>(&params, "name", 0)?;
				let old = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params, "old", 1,
				)?;
				let new = deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(
					&params, "new", 2,
				)?;
				drop(params);
				let result = <Owner<L, C, K> as OwnerRpcV3>::change_password(
					self.api,
					name,
					old.into_string(),
					new.into_string(),
				);
				mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc::try_serialize(&result)
			}
			_ => {
				let api: &dyn OwnerRpcV3 = self.api;
				<dyn OwnerRpcV3 as Handler>::handle(api, method, params)
			}
		}
	}
}

impl<L, C, K> OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler, sharing one Owner across all requests
	pub fn new(
		context_id: u32,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		tor_config: Option<TorConfig>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> Result<OwnerAPIHandlerV2<L, C, K>, Error> {
		let owner_api = Arc::new(Owner::new(context_id, wallet, tor_config)?);
		Ok(OwnerAPIHandlerV2 {
			owner_api,
			wallet_lifecycle_lock,
		})
	}

	async fn call_api(
		req: Request<Bytes>,
		api: Arc<Owner<L, C, K>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> Result<serde_json::Value, Error> {
		let val: serde_json::Value = parse_body(req).await?;
		let request_log_metadata =
			log_enabled!(Level::Debug).then(|| owner_api_request_log_metadata(&val));

		if let Some(metadata) = &request_log_metadata {
			debug!("OwnerAPI request: {}", metadata);
		}

		// Parsing happens before taking the read lock so a slow HTTP client cannot
		// block a lifecycle transition. The synchronous RPC dispatch, including
		// all wallet mutations and final TxSession persistence, is protected.
		// Only valid owner RPC method parameters are treated as secret-bearing.
		// Malformed or rejected requests are treated as untrusted garbage, not as
		// secrets requiring memory zeroization.
		let reply = with_wallet_lifecycle_read(&wallet_lifecycle_lock, || {
			ZeroizingOwnerRpcV2Handler { api: &api }.handle_request(val)
		});

		match reply {
			MaybeReply::Reply(r) => {
				if log_enabled!(Level::Debug) {
					debug!(
						"OwnerAPI response: request=({}) {}",
						request_log_metadata.as_deref().unwrap_or("unavailable"),
						owner_api_response_log_metadata(&r)
					);
				}
				Ok(r)
			}
			MaybeReply::DontReply => {
				if log_enabled!(Level::Debug) {
					debug!(
						"OwnerAPI response: request=({}) outcome=notification",
						request_log_metadata.as_deref().unwrap_or("unavailable")
					);
				}
				// Since it's http, we need to return something. We return [] because jsonrpc
				// clients will parse it as an empty batch response.
				Ok(serde_json::json!([]))
			}
		}
	}

	async fn handle_post_request(
		req: Request<Bytes>,
		api: Arc<Owner<L, C, K>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> Result<Response<Full<Bytes>>, Error> {
		//Here is a wrapper to call future from that.
		// Issue that we can't call future form future
		let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
		let future = Self::call_api(req, api, wallet_lifecycle_lock);
		Box::pin(future)
	};
		let res = crate::executor::RunHandlerInThread::new(handler)?.await?;

		// Values intentionally returned by this API are disclosed to the caller and are no
		// longer treated as wallet secrets, so the serialized response need not be zeroized.
		Ok(json_response_pretty(&res)?)
	}
}

impl<L, C, K> mwc_wallet_util::mwc_api::Handler for OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let api = self.owner_api.clone();
		let wallet_lifecycle_lock = self.wallet_lifecycle_lock.clone();
		Box::pin(async move {
			match Self::handle_post_request(req, api, wallet_lifecycle_lock).await {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async {
			let res = match create_ok_response("{}") {
				Ok(r) => r,
				Err(e) => create_error_response(e),
			};
			Ok(res)
		})
	}
}

/// V3 API Handler/Wrapper for owner functions, which include a secure
/// mode + lifecycle functions
pub struct OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,

	/// Handle to Owner API
	owner_api: Arc<Owner<L, C, K>>,

	/// ECDH shared key
	shared_key: Arc<Mutex<Option<SecretKey>>>,

	/// Serializes session re-keying with decrypt/dispatch/encrypt.
	request_lock: Arc<Mutex<()>>,

	/// Keeps the active wallet backend and its shared mask stable for co-hosted
	/// Owner V2 and Foreign V2 requests while open_wallet or close_wallet runs.
	wallet_lifecycle_lock: Arc<RwLock<()>>,

	/// Nonces authenticated in the current secure session.
	seen_nonces: Arc<Mutex<HashSet<[u8; 12]>>>,

	/// Keychain mask shared with MQS and any co-hosted foreign API.
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
}

const MAX_SECURE_SESSION_NONCES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecureNonceError {
	Replay,
	SessionExhausted,
}

fn record_secure_session_nonce(
	seen_nonces: &Mutex<HashSet<[u8; 12]>>,
	nonce: [u8; 12],
) -> Result<(), SecureNonceError> {
	let mut seen = seen_nonces.lock();
	if seen.contains(&nonce) {
		return Err(SecureNonceError::Replay);
	}
	if seen.len() >= MAX_SECURE_SESSION_NONCES {
		return Err(SecureNonceError::SessionExhausted);
	}
	seen.insert(nonce);
	Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleCall {
	None,
	InitSecureApi,
	OpenWallet,
	CloseWallet,
}

pub struct OwnerV3Helpers;

impl OwnerV3Helpers {
	fn lifecycle_method(method: Option<&str>) -> LifecycleCall {
		match method {
			Some("init_secure_api") => LifecycleCall::InitSecureApi,
			Some("open_wallet") => LifecycleCall::OpenWallet,
			Some("close_wallet") => LifecycleCall::CloseWallet,
			_ => LifecycleCall::None,
		}
	}

	fn inspect_lifecycle_request(
		val: &serde_json::Value,
	) -> Result<LifecycleCall, serde_json::Value> {
		if let Some(calls) = val.as_array() {
			let contains_lifecycle = calls.iter().any(|call| {
				Self::lifecycle_method(call.get("method").and_then(serde_json::Value::as_str))
					!= LifecycleCall::None
			});
			if contains_lifecycle {
				return Err(Self::invalid_request(
					"Wallet and secure-session lifecycle methods cannot be used in a batch",
				));
			}
			return Ok(LifecycleCall::None);
		}

		let lifecycle =
			Self::lifecycle_method(val.get("method").and_then(serde_json::Value::as_str));
		if lifecycle != LifecycleCall::None && val.get("id").is_none() {
			return Err(Self::invalid_request(
				"Wallet and secure-session lifecycle methods cannot be notifications",
			));
		}
		Ok(lifecycle)
	}

	fn invalid_request(message: &str) -> serde_json::Value {
		serde_json::json!({
			"jsonrpc": "2.0",
			"id": serde_json::Value::Null,
			"error": {
				"code": -32600,
				"message": message,
			}
		})
	}

	/// Checks whether a request is an encrypted request
	pub fn is_encrypted_request(val: &serde_json::Value) -> bool {
		matches!(val["method"].as_str(), Some("encrypted_request_v3"))
	}

	/// Update the mask shared by every service attached to this wallet.
	pub fn update_mask(
		mask: Arc<Mutex<Option<SecretKey>>>,
		val: &serde_json::Value,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		{
			// open_wallet may have switched the active wallet already. Fail closed while
			// validating its new mask instead of retaining a mask for the old wallet.
			let mut shared_mask = mask.lock();
			*shared_mask = None;
		}

		let encoded_mask = val
			.get("result")
			.and_then(serde_json::Value::as_object)
			.and_then(|result| result.get("Ok"))
			.and_then(serde_json::Value::as_str)
			.ok_or_else(|| {
				Error::Format("open_wallet returned a malformed successful response".to_string())
			})?;
		let key_bytes = mwc_wallet_util::mwc_util::decode_secret_key_hex::<32>(encoded_mask)
			.map_err(|e| {
				Error::Format(format!(
					"open_wallet returned an invalid keychain mask encoding: {}",
					e
				))
			})?;
		let secret_key = SecretKey::from_slice(secp, &*key_bytes)?;

		let mut shared_mask = mask.lock();
		*shared_mask = Some(secret_key);
		Ok(())
	}

	/// Decrypt an encrypted request
	pub fn decrypt_request(
		shared_key: &SecretKey,
		req: serde_json::Value,
	) -> Result<(JsonId, [u8; 12], serde_json::Value), serde_json::Value> {
		let enc_req: EncryptedRequest = serde_json::from_value(req).map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted request format error: {}", e),
			)
			.as_json_value()
		})?;
		let id = enc_req.id.clone();
		let nonce = enc_req.params.nonce_bytes().map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Invalid nonce: {}", e))
				.as_json_value()
		})?;
		let res = enc_req.decrypt(shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Decryption error: {}", e))
				.as_json_value()
		})?;
		Ok((id, nonce, res))
	}

	/// Encrypt a response
	///
	/// Security note: the legacy v3 response AAD is bound to the session key and
	/// JSON-RPC id, but not to the encrypted request nonce. A captured response
	/// can therefore be replayed if an id is reused in the same secure session.
	/// We intentionally avoid complicating the legacy wire protocol with
	/// request/response nonce binding. The Owner API is expected to run in a
	/// protected environment, so this residual replay risk is accepted. A fresh
	/// secret for every secure session prevents cross-session replay; callers that
	/// also need protection within a multi-request session must keep request ids
	/// unique, or establish a new secure session for every request.
	pub fn encrypt_response(
		shared_key: &SecretKey,
		id: &JsonId,
		res: &serde_json::Value,
	) -> Result<serde_json::Value, serde_json::Value> {
		let enc_res = EncryptedResponse::from_json(id, res, shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32003, &format!("Encryption Error: {}", e))
				.as_json_value()
		})?;
		let res = enc_res.as_json_value().map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted response format error: {}", e),
			)
			.as_json_value()
		})?;
		Ok(res)
	}

	/// Preserve dispatcher errors or convert an application error to JSON-RPC.
	pub fn error_response(val: &serde_json::Value) -> Option<serde_json::Value> {
		// Dispatcher failures are already standard JSON-RPC error responses.
		// Preserve them so callers can distinguish invalid params/version/etc.,
		// and so lifecycle handling never mistakes them for successful calls.
		if val.get("error").is_some() {
			return Some(val.clone());
		}

		let Some(error_value) = val
			.get("result")
			.and_then(serde_json::Value::as_object)
			.and_then(|result| result.get("Err"))
		else {
			return None;
		};

		let message = match error_value {
			serde_json::Value::String(message) => message.clone(),
			serde_json::Value::Object(fields) => fields
				.iter()
				.map(|(name, value)| {
					let value = value
						.as_str()
						.map(ToOwned::to_owned)
						.unwrap_or_else(|| value.to_string());
					format!("{}: {}", name, value)
				})
				.collect::<Vec<_>>()
				.join(", "),
			other => other.to_string(),
		};
		Some(serde_json::json!({
				"jsonrpc": "2.0",
				"id": val["id"],
				"error": {
					"message": message,
					"code": -32099
			}
		}))
	}
}

// `serde_json::Number` is currently a flat, non-owning value. A volatile
// replacement below would leak owned storage if the `arbitrary_precision`
// feature (which represents numbers as `String`) were ever enabled, so fail
// compilation instead of silently weakening zeroization in that configuration.
const _: () = assert!(
	!std::mem::needs_drop::<serde_json::Number>(),
	"JSON number zeroization requires a non-owning serde_json::Number",
);

fn zeroize_json_number(value: &mut serde_json::Number) {
	*value = serde_json::Number::from(0);
	optimization_barrier(value);
}

fn zeroize_json_value(value: &mut serde_json::Value) {
	match value {
		serde_json::Value::String(value) => value.zeroize(),
		serde_json::Value::Number(value) => zeroize_json_number(value),
		serde_json::Value::Bool(value) => value.zeroize(),
		serde_json::Value::Array(values) => {
			for value in values {
				zeroize_json_value(value);
			}
		}
		serde_json::Value::Object(values) => {
			for value in values.values_mut() {
				zeroize_json_value(value);
			}
		}
		_ => {}
	}
}

impl<L, C, K> OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		context_id: u32,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		tor_config: Option<TorConfig>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> Result<OwnerAPIHandlerV3<L, C, K>, Error> {
		let owner_api = Owner::new(context_id, wallet.clone(), tor_config.clone())?;
		owner_api.set_tor_config(tor_config);
		let owner_api = Arc::new(owner_api);
		Ok(OwnerAPIHandlerV3 {
			wallet,
			owner_api,
			shared_key: Arc::new(Mutex::new(None)),
			request_lock: Arc::new(Mutex::new(())),
			wallet_lifecycle_lock,
			seen_nonces: Arc::new(Mutex::new(HashSet::new())),
			keychain_mask: keychain_mask,
		})
	}

	async fn call_api(
		req: Request<Bytes>,
		key: Arc<Mutex<Option<SecretKey>>>,
		request_lock: Arc<Mutex<()>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
		seen_nonces: Arc<Mutex<HashSet<[u8; 12]>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		api: Arc<Owner<L, C, K>>,
	) -> Result<serde_json::Value, Error> {
		let mut val: serde_json::Value = parse_body(req).await?;
		// This guard spans decrypt, dispatch, response encryption, and any re-key.
		// It makes the session key immutable for the complete operation.
		// Owner API callers are expected to account for this serialization: normally
		// one Owner command runs while any additional commands wait for it to finish.
		let _request_guard = request_lock.lock();

		let outer_lifecycle = match OwnerV3Helpers::inspect_lifecycle_request(&val) {
			Ok(lifecycle) => lifecycle,
			Err(error) => {
				zeroize_json_value(&mut val);
				return Ok(error);
			}
		};
		let was_encrypted = OwnerV3Helpers::is_encrypted_request(&val);
		if !was_encrypted && outer_lifecycle != LifecycleCall::InitSecureApi {
			zeroize_json_value(&mut val);
			return Ok(EncryptionErrorResponse::new(
				1,
				-32001,
				"Encryption must be enabled. Please call 'init_secure_api' first",
			)
			.as_json_value());
		}

		let mut encrypted_req_id = None;
		let mut request_key = None;
		if was_encrypted {
			let shared_key = match key.lock().clone() {
				Some(shared_key) => shared_key,
				None => {
					return Ok(EncryptionErrorResponse::new(
						1,
						-32001,
						"Encryption must be enabled. Please call 'init_secure_api' first",
					)
					.as_json_value());
				}
			};
			let (request_id, nonce, mut decrypted) =
				match OwnerV3Helpers::decrypt_request(&shared_key, val) {
					Ok(decrypted) => decrypted,
					Err(error) => return Ok(error),
				};

			let replay_error = match record_secure_session_nonce(&seen_nonces, nonce) {
				Ok(()) => None,
				Err(SecureNonceError::Replay) => Some(OwnerV3Helpers::invalid_request(
					"Encrypted request nonce has already been used in this session",
				)),
				Err(SecureNonceError::SessionExhausted) => Some(OwnerV3Helpers::invalid_request(
					"Secure session nonce limit reached; initialize a new secure session",
				)),
			};
			if let Some(mut error) = replay_error {
				zeroize_json_value(&mut decrypted);
				let response = OwnerV3Helpers::encrypt_response(&shared_key, &request_id, &error);
				zeroize_json_value(&mut error);
				return Ok(response.unwrap_or_else(|error| error));
			}

			val = decrypted;
			encrypted_req_id = Some(request_id);
			request_key = Some(shared_key);
		}

		let lifecycle = match OwnerV3Helpers::inspect_lifecycle_request(&val) {
			Ok(lifecycle) => lifecycle,
			Err(mut error) => {
				zeroize_json_value(&mut val);
				if let (Some(shared_key), Some(request_id)) =
					(request_key.as_ref(), encrypted_req_id.as_ref())
				{
					let response = OwnerV3Helpers::encrypt_response(shared_key, request_id, &error);
					zeroize_json_value(&mut error);
					return Ok(response.unwrap_or_else(|error| error));
				}
				return Ok(error);
			}
		};

		let _mqs_lifecycle_guard = matches!(
			lifecycle,
			LifecycleCall::OpenWallet | LifecycleCall::CloseWallet
		)
		.then(mwc_wallet_impls::lock_mwcmqs_lifecycle);
		if matches!(
			lifecycle,
			LifecycleCall::OpenWallet | LifecycleCall::CloseWallet
		) && mwc_wallet_impls::get_mwcmqs_brocker(api.context_id).is_some()
		{
			zeroize_json_value(&mut val);
			let mut error = OwnerV3Helpers::invalid_request(
				"open_wallet and close_wallet are disabled while the MQS listener is running",
			);
			if let (Some(shared_key), Some(request_id)) =
				(request_key.as_ref(), encrypted_req_id.as_ref())
			{
				let response = OwnerV3Helpers::encrypt_response(shared_key, request_id, &error);
				zeroize_json_value(&mut error);
				return Ok(response.unwrap_or_else(|error| error));
			}
			return Ok(error);
		}

		// Bound the writer wait: while a writer is queued, parking_lot blocks
		// every new reader behind it, and readers can hold the lock for an
		// entire JSON-RPC batch. An unbounded wait would starve all owner and
		// foreign traffic for the duration of the slowest in-flight batch
		// (and historically participated in the deadlock documented on
		// `with_stable_wallet_mask`). Fail the lifecycle request instead so
		// the caller can retry once the wallet is idle.
		let _wallet_lifecycle_guard = match matches!(
			lifecycle,
			LifecycleCall::OpenWallet | LifecycleCall::CloseWallet
		) {
			true => match wallet_lifecycle_lock.try_write_for(WALLET_LIFECYCLE_WRITE_TIMEOUT) {
				Some(guard) => Some(guard),
				None => {
					zeroize_json_value(&mut val);
					let mut error = OwnerV3Helpers::invalid_request(
						"wallet is busy serving other requests; retry the lifecycle request",
					);
					if let (Some(shared_key), Some(request_id)) =
						(request_key.as_ref(), encrypted_req_id.as_ref())
					{
						let response =
							OwnerV3Helpers::encrypt_response(shared_key, request_id, &error);
						zeroize_json_value(&mut error);
						return Ok(response.unwrap_or_else(|error| error));
					}
					return Ok(error);
				}
			},
			false => None,
		};

		// Values returned through the Owner API have crossed the wallet security
		// boundary and are no longer treated as wallet-held secrets, so discarded
		// JSON-RPC response values do not require zeroization here.
		match (ZeroizingOwnerRpcV3Handler { api: &api }).handle_request(val) {
			MaybeReply::Reply(mut r) => {
				let mut converted_error = OwnerV3Helpers::error_response(&r);
				let was_error = converted_error.is_some();

				if lifecycle == LifecycleCall::OpenWallet && !was_error {
					let secp = match Secp256k1::with_caps(ContextFlag::None) {
						Ok(secp) => secp,
						Err(error) => {
							zeroize_json_value(&mut r);
							if let Some(error_response) = converted_error.as_mut() {
								zeroize_json_value(error_response);
							}
							return Err(error.into());
						}
					};
					if let Err(error) = OwnerV3Helpers::update_mask(mask.clone(), &r, &secp) {
						zeroize_json_value(&mut r);
						if let Some(error_response) = converted_error.as_mut() {
							zeroize_json_value(error_response);
						}
						return Err(error);
					}
				}
				if lifecycle == LifecycleCall::CloseWallet && !was_error {
					*mask.lock() = None;
				}

				let mut next_session_key = None;
				if lifecycle == LifecycleCall::InitSecureApi {
					if was_error {
						api.shared_key.lock().take();
					} else {
						let valid_response = r
							.get("result")
							.and_then(serde_json::Value::as_object)
							.and_then(|result| result.get("Ok"))
							.and_then(serde_json::Value::as_str)
							.is_some();
						if !valid_response {
							*key.lock() = None;
							seen_nonces.lock().clear();
							api.shared_key.lock().take();
							zeroize_json_value(&mut r);
							return Err(Error::Format(
								"init_secure_api returned a malformed successful response"
									.to_string(),
							));
						}
						next_session_key = api.shared_key.lock().take();
						if next_session_key.is_none() {
							*key.lock() = None;
							seen_nonces.lock().clear();
							zeroize_json_value(&mut r);
							return Err(Error::GenericError(
								"init_secure_api succeeded without installing a shared secret"
									.to_string(),
							));
						}
					}
				}

				let output = if let (Some(shared_key), Some(request_id)) =
					(request_key.as_ref(), encrypted_req_id.as_ref())
				{
					let plaintext = converted_error.as_ref().unwrap_or(&r);
					let encrypted =
						OwnerV3Helpers::encrypt_response(shared_key, request_id, plaintext);
					zeroize_json_value(&mut r);
					if let Some(error_response) = converted_error.as_mut() {
						zeroize_json_value(error_response);
					}
					match encrypted {
						Ok(encrypted) => encrypted,
						Err(error) => {
							if lifecycle == LifecycleCall::InitSecureApi {
								*key.lock() = None;
								seen_nonces.lock().clear();
							}
							return Ok(error);
						}
					}
				} else if let Some(error_response) = converted_error {
					zeroize_json_value(&mut r);
					error_response
				} else {
					r
				};

				if let Some(next_session_key) = next_session_key {
					*key.lock() = Some(next_session_key);
					seen_nonces.lock().clear();
				}
				Ok(output)
			}
			MaybeReply::DontReply => {
				// Since it's http, we need to return something. We return [] because jsonrpc
				// clients will parse it as an empty batch response.
				let empty_response = serde_json::json!([]);
				if let (Some(shared_key), Some(request_id)) =
					(request_key.as_ref(), encrypted_req_id.as_ref())
				{
					return Ok(OwnerV3Helpers::encrypt_response(
						shared_key,
						request_id,
						&empty_response,
					)
					.unwrap_or_else(|error| error));
				}
				Ok(empty_response)
			}
		}
	}

	async fn handle_post_request(
		req: Request<Bytes>,
		key: Arc<Mutex<Option<SecretKey>>>,
		request_lock: Arc<Mutex<()>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
		seen_nonces: Arc<Mutex<HashSet<[u8; 12]>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		api: Arc<Owner<L, C, K>>,
	) -> Result<Response<Full<Bytes>>, Error> {
		// Owner calls may perform blocking wallet work, so each admitted request is
		// moved to a dedicated thread. Multiple requests can therefore wait on
		// `request_lock`, but this is not an unauthenticated admission path:
		// `owner_listener` installs `BasicAuthMiddleware` before this handler when an
		// API secret is configured, and the default listener address is loopback-only.
		// Running with `api_secret == None` is an explicit, documented deployment
		// choice that delegates access control to the caller (see `owner_listener`). A
		// client admitted here is consequently inside the privileged Owner API trust
		// boundary and can already invoke state-changing wallet RPCs. Limiting
		// concurrency for such trusted clients is operational hardening, rather than
		// an authorization guarantee provided by this handler.
		let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
		let future = Self::call_api(
			req,
			key,
			request_lock,
			wallet_lifecycle_lock,
			seen_nonces,
			mask,
			api,
		);
		Box::pin(future)
	};
		let res = crate::executor::RunHandlerInThread::new(handler)?.await?;

		//let res = Self::call_api(req, key, mask, running_foreign, api).await?;
		let res = match json_response_pretty(&res) {
			Ok(r) => r,
			Err(e) => create_error_response(e),
		};
		Ok(res)
	}
}

impl<L, C, K> mwc_wallet_util::mwc_api::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let key = self.shared_key.clone();
		let request_lock = self.request_lock.clone();
		let wallet_lifecycle_lock = self.wallet_lifecycle_lock.clone();
		let seen_nonces = self.seen_nonces.clone();
		let mask = self.keychain_mask.clone();
		let api = self.owner_api.clone();

		Box::pin(async move {
			match Self::handle_post_request(
				req,
				key,
				request_lock,
				wallet_lifecycle_lock,
				seen_nonces,
				mask,
				api,
			)
			.await
			{
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async {
			let res = match create_ok_response("{}") {
				Ok(r) => r,
				Err(e) => create_error_response(e),
			};
			Ok(res)
		})
	}
}
/// V2 API Handler/Wrapper for foreign functions
pub struct ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	/// Prevents wallet lifecycle transitions while a co-hosted foreign request
	/// is using a backend/mask pair.
	wallet_lifecycle_lock: Arc<RwLock<()>>,
	/// Number of dedicated Foreign API workers currently running.
	active_worker_threads: Arc<AtomicUsize>,
}

struct ForeignApiThreadPermit {
	active_worker_threads: Arc<AtomicUsize>,
}

impl ForeignApiThreadPermit {
	fn try_acquire(active_worker_threads: Arc<AtomicUsize>) -> Option<Self> {
		active_worker_threads
			.try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
				(active < MAX_FOREIGN_API_THREADS).then_some(active + 1)
			})
			.ok()?;
		Some(Self {
			active_worker_threads,
		})
	}
}

impl Drop for ForeignApiThreadPermit {
	fn drop(&mut self) {
		self.active_worker_threads.fetch_sub(1, Ordering::AcqRel);
	}
}

fn with_stable_wallet_mask<T>(
	wallet_lifecycle_lock: &RwLock<()>,
	keychain_mask: &Mutex<Option<SecretKey>>,
	use_mask: impl FnOnce(Option<SecretKey>) -> T,
) -> Result<T, Error> {
	let _wallet_lifecycle_guard = wallet_lifecycle_lock
		.try_read_for(WALLET_LIFECYCLE_READ_TIMEOUT)
		.ok_or_else(|| {
			Error::GenericError(
				"wallet lifecycle transition in progress, retry the request".to_string(),
			)
		})?;
	let mask = keychain_mask.lock().clone();
	Ok(use_mask(mask))
}

impl<L, C, K> ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			keychain_mask,
			wallet_lifecycle_lock,
			active_worker_threads: Arc::new(AtomicUsize::new(0)),
		}
	}

	async fn call_api(
		req: Request<Bytes>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
	) -> Result<serde_json::Value, Error> {
		let request_access = req
			.extensions()
			.get::<ForeignRequestAccess>()
			.copied()
			.unwrap_or_else(ForeignRequestAccess::deny_build_coinbase);
		let val: serde_json::Value = parse_body(req).await?;
		let middleware: ForeignCheckMiddleware = if request_access.allows_build_coinbase() {
			check_middleware
		} else {
			|name, node_version_info, slate| match name {
				ForeignCheckMiddlewareFn::BuildCoinbase => {
					Err(mwc_wallet_libwallet::Error::GenericError(
						"build_coinbase is restricted to loopback or the configured mining_node_ip"
							.to_string(),
					))
				}
				name => check_middleware(name, node_version_info, slate),
			}
		};

		with_stable_wallet_mask(&wallet_lifecycle_lock, &keychain_mask, |mask| {
			let api = Foreign::new(wallet, mask, Some(middleware));

			if log_enabled!(Level::Debug) {
				debug!(
					"ForeignAPI request: {}",
					bounded_escape_for_display(&val.to_string(), 4096)
				);
			}

			match <dyn ForeignRpc>::handle_request(&api, val) {
				MaybeReply::Reply(r) => {
					if log_enabled!(Level::Debug) {
						debug!(
							"ForeignAPI response: {}",
							bounded_escape_for_display(&r.to_string(), 4096)
						);
					}
					Ok(r)
				}
				MaybeReply::DontReply => {
					// Since it's http, we need to return something. We return [] because jsonrpc
					// clients will parse it as an empty batch response.
					Ok(serde_json::json!([]))
				}
			}
		})?
	}

	async fn handle_post_request(
		req: Request<Bytes>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		wallet_lifecycle_lock: Arc<RwLock<()>>,
		active_worker_threads: Arc<AtomicUsize>,
	) -> Result<Response<Full<Bytes>>, Error> {
		let Some(thread_permit) = ForeignApiThreadPermit::try_acquire(active_worker_threads)
		else {
			return response(
				StatusCode::TOO_MANY_REQUESTS,
				"Foreign API is busy; retry the request later",
			);
		};

		// Hold the permit inside the worker future so it is released on every
		// completion, panic, spawn failure, or cancellation path.
		let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
			Box::pin(async move {
				let _thread_permit = thread_permit;
				Self::call_api(req, wallet, keychain_mask, wallet_lifecycle_lock).await
			})
		};
		let res = crate::executor::RunHandlerInThread::new(handler)?.await?;
		Ok(json_response_pretty(&res)?)
	}
}

impl<L, C, K> mwc_wallet_util::mwc_api::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let wallet = self.wallet.clone();
		let keychain_mask = self.keychain_mask.clone();
		let wallet_lifecycle_lock = self.wallet_lifecycle_lock.clone();
		let active_worker_threads = self.active_worker_threads.clone();

		Box::pin(async move {
			match Self::handle_post_request(
				req,
				wallet,
				keychain_mask,
				wallet_lifecycle_lock,
				active_worker_threads,
			)
			.await
			{
				Ok(v) => Ok(v),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async {
			let res = match create_ok_response("{}") {
				Ok(r) => r,
				Err(e) => create_error_response(e),
			};
			Ok(res)
		})
	}
}

// Utility to serialize a struct into JSON and produce a sensible Response
// out of it.
fn _json_response<T>(s: &T) -> Result<Response<Full<Bytes>>, Error>
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(e) => response(
			StatusCode::INTERNAL_SERVER_ERROR,
			format!("Unable to parse response object, {}", e),
		),
	}
}

// pretty-printed version of above
fn json_response_pretty<T>(s: &T) -> Result<Response<Full<Bytes>>, Error>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(e) => response(
			StatusCode::INTERNAL_SERVER_ERROR,
			format!("Unable to parse response object, {}", e),
		),
	}
}

fn create_error_response(e: Error) -> Response<Full<Bytes>> {
	let mut response = Response::new(format!("{}", e).into());
	*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
	response
		.headers_mut()
		.insert("access-control-allow-origin", HeaderValue::from_static("*"));
	response.headers_mut().insert(
		"access-control-allow-headers",
		HeaderValue::from_static("Content-Type, Authorization"),
	);
	response
}

fn create_ok_response(json: &str) -> Result<Response<Full<Bytes>>, Error> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(Full::new(Bytes::from(json.to_string())))
		.map_err(|e| Error::IO(format!("Unable to build a response, {}", e)))
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<Bytes>>(status: StatusCode, text: T) -> Result<Response<Full<Bytes>>, Error> {
	let mut builder = Response::builder()
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	builder
		.body(Full::new(text.into()))
		.map_err(|e| Error::IO(format!("Unable to build a response, {}", e)))
}

async fn parse_body<T>(req: Request<Bytes>) -> Result<T, Error>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	struct ZeroizingRequestBody(BytesMut);

	impl Drop for ZeroizingRequestBody {
		fn drop(&mut self) {
			self.0.as_mut().zeroize();
		}
	}

	// API deserialization memory policy: owned wire buffers are scrubbed on every
	// path, and successfully constructed secret-bearing values must scrub their
	// own storage on Drop. Serde may create ordinary field temporaries before it
	// rejects invalid caller-supplied input; failure-only temporaries are out of
	// scope because exposing them requires an independent process-memory read.
	// Apply this policy consistently to owner, foreign, and other API/RPC DTOs;
	// custom deserialization is not required solely to zeroize partial values on
	// parse failure. This exception does not cover wallet-derived secrets or
	// ignored deserialization errors.
	//
	// `Request<Bytes>` does not guarantee unique backing storage. In
	// particular, Hyper can provide a body that is a slice of its shared
	// connection buffer. Reuse uniquely owned storage when possible; otherwise
	// copy the body into mutable storage that this function can safely scrub.
	let body = match req.into_body().try_into_mut() {
		Ok(body) => body,
		Err(body) => BytesMut::from(body.as_ref()),
	};
	let body = ZeroizingRequestBody(body);
	serde_json::from_slice(body.0.as_ref()).map_err(|e| {
		Error::GenericError(format!(
			"Invalid request body ({:?} at line {}, column {})",
			e.classify(),
			e.line(),
			e.column()
		))
	})
}

#[cfg(test)]
mod owner_v3_helpers_tests {
	use super::*;
	use mwc_wallet_libwallet::ParticipantData;
	use mwc_wallet_util::mwc_crates::secp::{AggSigSignature, PublicKey};
	use std::sync::atomic::{AtomicBool, AtomicU32};
	use std::sync::mpsc;

	static NEXT_LISTENER_TEST_CONTEXT: AtomicU32 = AtomicU32::new(u32::MAX);

	fn listener_test_context() -> u32 {
		NEXT_LISTENER_TEST_CONTEXT.fetch_sub(1, Ordering::Relaxed)
	}

	fn assert_owner_requests_closed(requests: Arc<ApiAvailabilityMiddleware>) {
		use mwc_wallet_util::mwc_api::Handler;
		let response = mwc_wallet_util::mwc_crates::futures::executor::block_on(
			requests.call(Request::new(Bytes::new()), Box::new(std::iter::empty())),
		)
		.unwrap();
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn incoming_swap_error_display_is_bounded_and_escaped() {
		let marker = "peer-payload-past-the-bound";
		let error = Error::LibWallet(format!(
			"invalid peer value\n{}{}",
			"x".repeat(MAX_SWAP_MESSAGE_ERROR_DISPLAY_BYTES * 2),
			marker
		));

		let rendered = bounded_swap_message_error(&error);
		assert!(rendered.ends_with("...[truncated]"));
		assert!(rendered.contains("\\u000a"));
		assert!(!rendered.contains('\n'));
		assert!(!rendered.contains(marker));
		assert!(rendered.len() <= MAX_SWAP_MESSAGE_ERROR_DISPLAY_BYTES + 32);
	}

	#[test]
	fn owner_api_request_log_metadata_omits_secret_params() {
		let secret = "receiver-wallet-api-secret";
		let request = serde_json::json!({
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"id": 1,
			"params": {
				"args": {
					"send_args": {
						"apisecret": secret
					}
				}
			}
		});

		let metadata = owner_api_request_log_metadata(&request);
		assert_eq!(metadata, "method=init_send_tx id=1");
		assert!(!metadata.contains(secret));
		assert!(!metadata.contains("params"));
	}

	#[test]
	fn owner_api_batch_log_metadata_omits_request_bodies() {
		let requests = serde_json::json!([
			{"method": "accounts", "params": {}},
			{"method": "init_send_tx", "params": {"apisecret": "secret"}}
		]);

		assert_eq!(owner_api_request_log_metadata(&requests), "batch_size=2");
	}

	#[test]
	fn owner_api_response_log_metadata_omits_result_and_error_data() {
		let secret = "private-proof-decryption-key";
		let success = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 7,
			"result": {"Ok": {"key": secret}}
		});
		let application_error = serde_json::json!({
			"jsonrpc": "2.0",
			"id": "request-id",
			"result": {"Err": secret}
		});
		let rpc_error = serde_json::json!({
			"jsonrpc": "2.0",
			"id": null,
			"error": {"code": -32600, "message": secret, "data": secret}
		});

		let success_metadata = owner_api_response_log_metadata(&success);
		assert_eq!(success_metadata, "id=7 outcome=success");
		assert!(!success_metadata.contains(secret));
		assert_eq!(
			owner_api_response_log_metadata(&application_error),
			"id=request-id outcome=application_error"
		);
		assert_eq!(
			owner_api_response_log_metadata(&rpc_error),
			"id=null outcome=rpc_error"
		);
	}

	#[test]
	fn owner_api_batch_response_log_metadata_only_counts_outcomes() {
		let secret = "private-proof-decryption-key";
		let responses = serde_json::json!([
			{"id": 1, "result": {"Ok": {"key": secret}}},
			{"id": 2, "result": {"Err": secret}},
			{"id": 3, "error": {"message": secret}},
			{"id": 4}
		]);

		let metadata = owner_api_response_log_metadata(&responses);
		assert_eq!(
			metadata,
			"batch_size=4 success=1 application_error=1 rpc_error=1 invalid=1"
		);
		assert!(!metadata.contains(secret));
	}

	#[test]
	fn parse_body_accepts_owned_storage_and_sanitizes_errors() {
		use mwc_wallet_util::mwc_crates::futures::executor::block_on;

		let parsed: serde_json::Value = block_on(parse_body(Request::new(Bytes::from(
			br#"{"id":1,"method":"accounts"}"#.to_vec(),
		))))
		.unwrap();
		assert_eq!(parsed["method"], "accounts");

		let secret = "request-secret-must-not-appear-in-errors";
		let malformed = Request::new(Bytes::from(
			format!(r#"{{"secret":"{}","unterminated":"#, secret).into_bytes(),
		));
		let error = block_on(parse_body::<serde_json::Value>(malformed)).unwrap_err();
		assert!(!error.to_string().contains(secret));
	}

	#[test]
	fn parse_body_accepts_shared_storage() {
		use mwc_wallet_util::mwc_crates::futures::executor::block_on;

		let json = br#"{"id":1}"#;
		let mut connection_buffer = BytesMut::from(&br#"{"id":1}next-request"#[..]);
		let body = connection_buffer.split_to(json.len()).freeze();
		assert!(!body.is_unique());

		let parsed = block_on(parse_body::<serde_json::Value>(Request::new(body))).unwrap();
		assert_eq!(parsed["id"], 1);
		assert_eq!(connection_buffer.as_ref(), b"next-request");
	}

	#[test]
	fn foreign_api_thread_permit_enforces_limit_and_releases_capacity() {
		let active_worker_threads = Arc::new(AtomicUsize::new(0));
		let mut permits = (0..MAX_FOREIGN_API_THREADS)
			.map(|_| ForeignApiThreadPermit::try_acquire(active_worker_threads.clone()).unwrap())
			.collect::<Vec<_>>();

		assert_eq!(
			active_worker_threads.load(Ordering::Acquire),
			MAX_FOREIGN_API_THREADS
		);
		assert!(ForeignApiThreadPermit::try_acquire(active_worker_threads.clone()).is_none());

		drop(permits.pop());
		let replacement =
			ForeignApiThreadPermit::try_acquire(active_worker_threads.clone()).unwrap();
		assert_eq!(
			active_worker_threads.load(Ordering::Acquire),
			MAX_FOREIGN_API_THREADS
		);

		drop(replacement);
		drop(permits);
		assert_eq!(active_worker_threads.load(Ordering::Acquire), 0);
	}

	#[test]
	fn owner_rpc_secret_string_erases_its_allocation() {
		let mut secret = ZeroizingOwnerRpcString(Some("wallet-password".to_owned()));

		secret.zeroize();

		assert_eq!(secret.0.as_deref(), Some(""));
	}

	#[test]
	fn owner_rpc_secret_string_moves_directly_into_zeroing_storage() {
		let secret = "wallet-password";
		let mut values = serde_json::Map::new();
		values.insert("password".to_owned(), serde_json::json!(secret));
		let params = ZeroizingOwnerRpcParams::new(RpcParams::Named(values), &["password"]).unwrap();
		let password =
			deserialize_zeroizing_owner_argument::<ZeroizingOwnerRpcString>(&params, "password", 0)
				.unwrap();
		drop(params);

		let password =
			mwc_wallet_util::mwc_util::ZeroingString::from(password.into_string());
		assert_eq!(&*password, secret);
	}

	#[test]
	fn parsed_wallet_secret_is_zeroizing_when_a_later_argument_fails() {
		let params = RpcParams::Positional(vec![
			serde_json::Value::Null,
			serde_json::json!("abandon abandon abandon"),
			serde_json::json!("not-a-number"),
			serde_json::json!("wallet-password"),
		]);
		let params = ZeroizingOwnerRpcParams::new(
			params,
			&["name", "mnemonic", "mnemonic_length", "password"],
		)
		.unwrap();
		let _name =
			deserialize_zeroizing_owner_argument::<Option<String>>(&params, "name", 0).unwrap();
		let mnemonic = deserialize_zeroizing_owner_argument::<Option<ZeroizingOwnerRpcString>>(
			&params, "mnemonic", 1,
		)
		.unwrap();

		let error = deserialize_zeroizing_owner_argument::<u32>(&params, "mnemonic_length", 2)
			.expect_err("invalid mnemonic length unexpectedly deserialized");
		assert!(mnemonic.is_some());
		assert!(!error.to_string().contains("abandon"));
		assert!(!error.to_string().contains("wallet-password"));
	}

	#[test]
	fn sensitive_owner_argument_deserializes_without_consuming_json_storage() {
		let secret = "receiver-wallet-api-secret";
		let mut params = serde_json::Map::new();
		params.insert(
			"args".to_owned(),
			serde_json::json!({
				"amount": "1",
				"send_args": {
					"method": "http",
					"dest": "http://127.0.0.1:3415",
					"apisecret": secret
				}
			}),
		);

		let params =
			ZeroizingOwnerRpcParams::new(RpcParams::Named(params), &["args"]).unwrap();
		let args = deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 0).unwrap();
		assert_eq!(
			args.send_args
				.as_ref()
				.and_then(|send| send.apisecret.as_ref().map(|secret| secret.as_str())),
			Some(secret)
		);
	}

	#[test]
	fn multiple_sensitive_owner_arguments_deserialize_without_consuming_json_storage() {
		let secret = "receiver-wallet-api-secret";
		let mut params = serde_json::Map::new();
		params.insert("slate".to_owned(), serde_json::json!({"opaque": "slate"}));
		params.insert(
			"args".to_owned(),
			serde_json::json!({
				"amount": "1",
				"send_args": {
					"method": "http",
					"dest": "http://127.0.0.1:3415",
					"apisecret": secret
				}
			}),
		);

		let params =
			ZeroizingOwnerRpcParams::new(RpcParams::Named(params), &["slate", "args"])
				.unwrap();
		let slate = deserialize_zeroizing_owner_argument::<serde_json::Value>(
			&params, "slate", 0,
		)
		.unwrap();
		let args = deserialize_zeroizing_owner_argument::<InitTxArgs>(&params, "args", 1).unwrap();
		assert_eq!(slate, serde_json::json!({"opaque": "slate"}));
		assert_eq!(
			args.send_args
				.as_ref()
				.and_then(|send| send.apisecret.as_ref().map(|secret| secret.as_str())),
			Some(secret)
		);
	}

	#[test]
	fn multiple_sensitive_owner_arguments_scrub_after_malformed_first_argument() {
		let secret = "receiver-wallet-api-secret";
		let params = RpcParams::Positional(vec![
			serde_json::json!({}),
			serde_json::json!({
				"amount": "1",
				"send_args": {
					"method": "http",
					"dest": "http://127.0.0.1:3415",
					"apisecret": secret
				}
			}),
		]);

		let params = ZeroizingOwnerRpcParams::new(params, &["slate", "args"]).unwrap();
		let error = deserialize_zeroizing_owner_argument::<VersionedSlate>(&params, "slate", 0)
			.expect_err("malformed slate unexpectedly deserialized");
		assert!(!error.to_string().contains(secret));
	}

	#[test]
	fn zeroize_json_value_overwrites_string_and_numeric_secrets() {
		let mut value = serde_json::json!({
			"apisecret": "receiver-wallet-api-secret",
			"key": [9, 8, 7],
			"enabled": true
		});

		zeroize_json_value(&mut value);

		assert_eq!(value["apisecret"], "");
		assert_eq!(value["key"], serde_json::json!([0, 0, 0]));
		assert_eq!(value["enabled"], false);
	}

	fn mqs_waiter_token() -> MqsResponseWaiterToken {
		MqsResponseWaiterToken::try_new().unwrap()
	}

	#[test]
	fn listener_startup_signal_reports_disconnected_receiver() {
		let (signal, receiver) = ListenerStartupSignal::channel();
		drop(receiver);

		assert!(signal.ready().is_err());
	}

	#[test]
	fn listener_startup_signal_only_reports_once() {
		let (signal, receiver) = ListenerStartupSignal::channel();

		assert!(signal.ready().is_ok());
		assert_eq!(receiver.recv(), Ok(Ok(())));
		assert!(signal.failed("late failure".to_string()).is_ok());
		assert!(matches!(
			receiver.try_recv(),
			Err(mpsc::TryRecvError::Disconnected)
		));
	}

	#[test]
	fn foreign_connection_id_exhaustion_does_not_wrap() {
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

	fn mqs_test_participant(id: u64, complete: bool) -> ParticipantData {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let secret_key = SecretKey::from_slice(&secp, &[(id as u8) + 1; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		ParticipantData {
			id,
			public_blind_excess: public_key,
			public_nonce: public_key,
			part_sig: complete.then(AggSigSignature::blank),
			message: None,
			message_sig: None,
		}
	}

	#[test]
	fn mqs_waiter_registration_rejects_duplicate_without_replacing_first() {
		let original_slate = Slate::blank(2, true).unwrap();
		let slate_id = original_slate.id;
		let (first_sender, first_receiver) = mpsc::channel();
		let mut waiters = HashMap::new();

		register_slate_response_waiter(
			&mut waiters,
			&slate_id,
			SlateResponseWaiter {
				registration_token: mqs_waiter_token(),
				sender: first_sender,
				original_slate: original_slate.clone(),
				expected_peer_public_key: "first-peer".to_string(),
				expected_response: SlatePurpose::SendResponse,
			},
		)
		.unwrap();

		let (second_sender, second_receiver) = mpsc::channel();
		let error = register_slate_response_waiter(
			&mut waiters,
			&slate_id,
			SlateResponseWaiter {
				registration_token: mqs_waiter_token(),
				sender: second_sender,
				original_slate: original_slate.clone(),
				expected_peer_public_key: "second-peer".to_string(),
				expected_response: SlatePurpose::SendResponse,
			},
		)
		.unwrap_err();

		assert!(matches!(error, mwc_wallet_impls::Error::MqsGenericError(_)));
		assert_eq!(waiters.len(), 1);
		let first_waiter = waiters.get(&slate_id).unwrap();
		assert_eq!(first_waiter.expected_peer_public_key, "first-peer");
		first_waiter.sender.send(original_slate).unwrap();
		assert_eq!(first_receiver.recv().unwrap().id, slate_id);
		assert!(matches!(
			second_receiver.try_recv(),
			Err(mpsc::TryRecvError::Disconnected)
		));
	}

	#[test]
	fn stale_mqs_waiter_cleanup_does_not_remove_same_slate_retry() {
		let original_slate = Slate::blank(2, true).unwrap();
		let slate_id = original_slate.id;
		let old_token = mqs_waiter_token();
		let retry_token = mqs_waiter_token();
		let (old_sender, _old_receiver) = mpsc::channel();
		let mut waiters = HashMap::new();

		register_slate_response_waiter(
			&mut waiters,
			&slate_id,
			SlateResponseWaiter {
				registration_token: old_token,
				sender: old_sender,
				original_slate: original_slate.clone(),
				expected_peer_public_key: "peer".to_string(),
				expected_response: SlatePurpose::SendResponse,
			},
		)
		.unwrap();

		// A failed response send removes the old registration before that
		// operation's final timeout cleanup gets to run.
		assert!(remove_slate_response_waiter_if_current(
			&mut waiters,
			&slate_id,
			&old_token,
		));

		let (retry_sender, retry_receiver) = mpsc::channel();
		register_slate_response_waiter(
			&mut waiters,
			&slate_id,
			SlateResponseWaiter {
				registration_token: retry_token,
				sender: retry_sender,
				original_slate: original_slate.clone(),
				expected_peer_public_key: "peer".to_string(),
				expected_response: SlatePurpose::SendResponse,
			},
		)
		.unwrap();

		assert!(!remove_slate_response_waiter_if_current(
			&mut waiters,
			&slate_id,
			&old_token,
		));
		let retry_waiter = waiters.get(&slate_id).unwrap();
		assert_eq!(retry_waiter.registration_token, retry_token);
		retry_waiter.sender.send(original_slate).unwrap();
		assert_eq!(retry_receiver.recv().unwrap().id, slate_id);

		assert!(remove_slate_response_waiter_if_current(
			&mut waiters,
			&slate_id,
			&retry_token,
		));
		assert!(!waiters.contains_key(&slate_id));
	}

	#[test]
	fn mqs_send_waiter_rejects_a_reflected_initial_slate() {
		let mut original_slate = Slate::blank(2, true).unwrap();
		original_slate
			.participant_data
			.push(mqs_test_participant(0, false));
		let (sender, _receiver) = mpsc::channel();
		let waiter = SlateResponseWaiter {
			registration_token: mqs_waiter_token(),
			sender,
			original_slate: original_slate.clone(),
			expected_peer_public_key: "peer".to_string(),
			expected_response: SlatePurpose::SendResponse,
		};

		assert!(validate_mqs_waiter_response(&waiter, &mut original_slate).is_err());

		let mut valid_response = original_slate;
		valid_response
			.participant_data
			.push(mqs_test_participant(1, true));
		assert!(validate_mqs_waiter_response(&waiter, &mut valid_response).is_ok());
	}

	#[test]
	fn mqs_invoice_waiter_rejects_a_reflected_initial_slate() {
		let mut original_slate = Slate::blank(2, false).unwrap();
		original_slate
			.participant_data
			.push(mqs_test_participant(0, false));
		let (sender, _receiver) = mpsc::channel();
		let waiter = SlateResponseWaiter {
			registration_token: mqs_waiter_token(),
			sender,
			original_slate: original_slate.clone(),
			expected_peer_public_key: "peer".to_string(),
			expected_response: SlatePurpose::InvoiceResponse,
		};

		let mut reflected_initial = original_slate.clone();
		assert!(validate_mqs_waiter_response(&waiter, &mut reflected_initial).is_err());

		let mut incomplete_response = original_slate.clone();
		incomplete_response
			.participant_data
			.push(mqs_test_participant(1, false));
		assert!(validate_mqs_waiter_response(&waiter, &mut incomplete_response).is_err());

		let mut valid_response = original_slate;
		valid_response
			.participant_data
			.push(mqs_test_participant(1, true));
		assert!(validate_mqs_waiter_response(&waiter, &mut valid_response).is_ok());
	}

	#[test]
	fn mqs_full_slate_waiter_enforces_stage_and_transcript() {
		let mut invoice_response = Slate::blank(2, false).unwrap();
		invoice_response
			.participant_data
			.push(mqs_test_participant(0, false));
		invoice_response
			.participant_data
			.push(mqs_test_participant(1, true));
		let (sender, _receiver) = mpsc::channel();
		let waiter = SlateResponseWaiter {
			registration_token: mqs_waiter_token(),
			sender,
			original_slate: invoice_response.clone(),
			expected_peer_public_key: "peer".to_string(),
			expected_response: SlatePurpose::FullSlate,
		};

		let mut empty_response = invoice_response.clone();
		empty_response.participant_data.clear();
		assert!(validate_mqs_waiter_response(&waiter, &mut empty_response).is_err());

		let mut reflected_response = invoice_response.clone();
		assert!(validate_mqs_waiter_response(&waiter, &mut reflected_response).is_err());

		let mut altered_response = invoice_response.clone();
		altered_response.participant_data[0].part_sig = Some(AggSigSignature::blank());
		altered_response.participant_data[1].message = Some("altered payer".to_string());
		assert!(validate_mqs_waiter_response(&waiter, &mut altered_response).is_err());

		let mut valid_response = invoice_response;
		valid_response.participant_data[0].part_sig = Some(AggSigSignature::blank());
		assert!(validate_mqs_waiter_response(&waiter, &mut valid_response).is_ok());
	}

	#[test]
	fn mqs_full_slate_waiter_restores_compact_payer_record() {
		let mut invoice_response = Slate::blank(2, true).unwrap();
		invoice_response
			.participant_data
			.push(mqs_test_participant(0, false));
		invoice_response
			.participant_data
			.push(mqs_test_participant(1, true));
		let expected_payer = invoice_response.participant_data[1].clone();
		let (sender, _receiver) = mpsc::channel();
		let waiter = SlateResponseWaiter {
			registration_token: mqs_waiter_token(),
			sender,
			original_slate: invoice_response.clone(),
			expected_peer_public_key: "peer".to_string(),
			expected_response: SlatePurpose::FullSlate,
		};

		let mut compact_response = invoice_response;
		compact_response.participant_data[0].part_sig = Some(AggSigSignature::blank());
		compact_response.participant_data.remove(1);

		assert!(validate_mqs_waiter_response(&waiter, &mut compact_response).is_ok());
		assert_eq!(compact_response.participant_data.len(), 2);
		assert_eq!(compact_response.participant_data[1], expected_payer);
	}

	#[test]
	fn basic_auth_header_matches_standard_encoding() {
		let secret = Zeroizing::new("secret".to_owned());

		assert_eq!(
			build_basic_auth_header_value("mwc", &secret).as_str(),
			"Basic bXdjOnNlY3JldA=="
		);
	}

	#[test]
	fn update_mask_rejects_invalid_hex_and_clears_stale_mask() {
		let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let stale_mask = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let mask = Arc::new(Mutex::new(Some(stale_mask)));
		let response = serde_json::json!({"result": {"Ok": "not-hex"}});

		let result = OwnerV3Helpers::update_mask(mask.clone(), &response, &secp);

		assert!(matches!(result, Err(Error::Format(_))));
		assert!(mask.lock().is_none());
	}

	#[test]
	fn update_mask_rejects_malformed_success_and_clears_stale_mask() {
		let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let stale_mask = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let mask = Arc::new(Mutex::new(Some(stale_mask)));
		let response = serde_json::json!({"result": {"Ok": 7}});

		let result = OwnerV3Helpers::update_mask(mask.clone(), &response, &secp);

		assert!(matches!(result, Err(Error::Format(_))));
		assert!(mask.lock().is_none());
	}

	#[test]
	fn error_response_preserves_non_string_errors() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 7,
			"result": {"Err": ["invalid", 42]}
		});

		let converted = OwnerV3Helpers::error_response(&response).unwrap();

		assert_eq!(converted["error"]["code"], -32099);
		assert_eq!(converted["error"]["message"], "[\"invalid\",42]");
	}

	#[test]
	fn error_response_preserves_dispatcher_errors() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 7,
			"error": {
				"code": -32602,
				"message": "Invalid params",
				"data": "MissingNamedParameter password"
			}
		});

		assert_eq!(OwnerV3Helpers::error_response(&response), Some(response));
	}

	#[test]
	fn owner_v2_dispatch_holds_lifecycle_read_lock_until_completion() {
		let wallet_lifecycle_lock = Arc::new(RwLock::new(()));
		let backend_generation = Arc::new(AtomicU64::new(0));
		let (dispatch_started_sender, dispatch_started_receiver) = mpsc::channel();
		let (finish_dispatch_sender, finish_dispatch_receiver) = mpsc::channel();
		let (observed_sender, observed_receiver) = mpsc::channel();

		let request_lock = wallet_lifecycle_lock.clone();
		let request_generation = backend_generation.clone();
		let request = thread::spawn(move || {
			let observed = with_wallet_lifecycle_read(&request_lock, || {
				dispatch_started_sender.send(()).unwrap();
				let before = request_generation.load(Ordering::Acquire);
				finish_dispatch_receiver.recv().unwrap();
				let after = request_generation.load(Ordering::Acquire);
				(before, after)
			});
			observed_sender.send(observed).unwrap();
		});

		dispatch_started_receiver.recv().unwrap();
		let (writer_started_sender, writer_started_receiver) = mpsc::channel();
		let (transition_finished_sender, transition_finished_receiver) = mpsc::channel();
		let transition_lock = wallet_lifecycle_lock.clone();
		let transition_generation = backend_generation.clone();
		let transition = thread::spawn(move || {
			writer_started_sender.send(()).unwrap();
			let _guard = transition_lock.write();
			transition_generation.store(1, Ordering::Release);
			transition_finished_sender.send(()).unwrap();
		});

		writer_started_receiver.recv().unwrap();
		assert!(matches!(
			transition_finished_receiver.recv_timeout(Duration::from_millis(50)),
			Err(RecvTimeoutError::Timeout)
		));
		finish_dispatch_sender.send(()).unwrap();

		assert_eq!(
			observed_receiver
				.recv_timeout(Duration::from_secs(2))
				.unwrap(),
			(0, 0)
		);
		transition_finished_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("lifecycle writer remained blocked after V2 dispatch completed");

		request.join().unwrap();
		transition.join().unwrap();
	}

	#[test]
	fn stable_wallet_mask_waits_for_lifecycle_commit() {
		let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let old_mask = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let new_mask = SecretKey::from_slice(&secp, &[2_u8; 32]).unwrap();
		let expected_mask = new_mask.clone();
		let wallet_lifecycle_lock = Arc::new(RwLock::new(()));
		let keychain_mask = Arc::new(Mutex::new(Some(old_mask)));
		let backend_generation = Arc::new(AtomicU64::new(0));
		let (backend_switched_sender, backend_switched_receiver) = mpsc::channel();
		let (finish_transition_sender, finish_transition_receiver) = mpsc::channel();

		let transition_lock = wallet_lifecycle_lock.clone();
		let transition_mask = keychain_mask.clone();
		let transition_generation = backend_generation.clone();
		let transition = thread::spawn(move || {
			let _guard = transition_lock.write();
			transition_generation.store(1, Ordering::Release);
			backend_switched_sender.send(()).unwrap();
			finish_transition_receiver.recv().unwrap();
			*transition_mask.lock() = Some(new_mask);
		});

		backend_switched_receiver.recv().unwrap();

		let foreign_lock = wallet_lifecycle_lock.clone();
		let foreign_mask = keychain_mask.clone();
		let foreign_generation = backend_generation.clone();
		let (observed_sender, observed_receiver) = mpsc::channel();
		let foreign = thread::spawn(move || {
			let observed = with_stable_wallet_mask(&foreign_lock, &foreign_mask, |mask| {
				(foreign_generation.load(Ordering::Acquire), mask)
			});
			observed_sender.send(observed).unwrap();
		});

		assert!(matches!(
			observed_receiver.recv_timeout(Duration::from_millis(50)),
			Err(RecvTimeoutError::Timeout)
		));
		finish_transition_sender.send(()).unwrap();

		let (generation, mask) = observed_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("foreign mask snapshot remained blocked after lifecycle commit")
			.expect("foreign mask snapshot failed after lifecycle commit");
		assert_eq!(generation, 1);
		assert_eq!(mask, Some(expected_mask));

		transition.join().unwrap();
		foreign.join().unwrap();
	}

	#[test]
	fn lifecycle_methods_are_rejected_in_batches_and_notifications() {
		let batch = serde_json::json!([
			{"jsonrpc": "2.0", "id": 1, "method": "accounts", "params": {}},
			{"jsonrpc": "2.0", "id": 2, "method": "open_wallet", "params": {}}
		]);
		assert!(OwnerV3Helpers::inspect_lifecycle_request(&batch).is_err());

		let notification = serde_json::json!({
			"jsonrpc": "2.0",
			"method": "close_wallet",
			"params": {}
		});
		assert!(OwnerV3Helpers::inspect_lifecycle_request(&notification).is_err());
	}

	#[test]
	fn secure_session_nonce_can_only_be_recorded_once() {
		let seen_nonces = Mutex::new(HashSet::new());
		let nonce = [7u8; 12];

		assert_eq!(record_secure_session_nonce(&seen_nonces, nonce), Ok(()));
		assert_eq!(
			record_secure_session_nonce(&seen_nonces, nonce),
			Err(SecureNonceError::Replay)
		);
	}

	#[test]
	fn owner_reservation_is_atomic_and_stale_cleanup_is_identity_safe() {
		let context_id = listener_test_context();
		let stale = OwnerApiReservation::reserve(context_id).unwrap();
		assert!(OwnerApiReservation::reserve(context_id).is_err());

		foreign_owner_api_clean_context(context_id);
		let replacement = OwnerApiReservation::reserve(context_id).unwrap();
		drop(stale);
		assert!(is_owner_api_running(context_id));

		drop(replacement);
		assert!(!is_owner_api_running(context_id));
	}

	#[test]
	fn unexpected_owner_api_thread_exit_is_reported_to_listener() {
		use mwc_wallet_util::mwc_api::Handler;

		let context_id = listener_test_context();
		let mut reservation = OwnerApiReservation::reserve(context_id).unwrap();
		let instance_id = reservation.instance_id;
		let requests = Arc::new(ApiAvailabilityMiddleware::new(
			StatusCode::SERVICE_UNAVAILABLE,
		));
		let (join_result_sender, join_result_receiver) = mpsc::channel();
		assert!(
			reservation
				.promote(
					ApiServer::new(),
					thread::spawn(|| {}),
					&requests,
					join_result_sender,
				)
				.is_ok()
		);
		let stale_entry = owner_api_if_current(context_id, instance_id, false).unwrap();
		let release = ReleaseApiRequests(Arc::new(AtomicBool::new(false)));
		let (started_sender, started_receiver) = mpsc::channel();
		let finished = Arc::new(AtomicUsize::new(0));
		let handler: HandlerObj = Arc::new(BlockingApiRequest {
			started: started_sender,
			release: release.0.clone(),
			finished: finished.clone(),
		});
		let response = requests.call(
			Request::post("/v2/owner").body(Bytes::new()).unwrap(),
			Box::new(std::iter::once(handler)),
		);
		let request = thread::spawn(move || {
			mwc_wallet_util::mwc_crates::futures::executor::block_on(response).unwrap();
		});
		started_receiver
			.recv_timeout(Duration::from_secs(5))
			.unwrap();
		let reaper = thread::spawn(move || {
			wait_for_owner_api_join(context_id, instance_id, join_result_receiver)
		});

		// The reaper also briefly locks shutdown while checking whether the API
		// thread finished. Wait for request admission to close as well, so we
		// observe request draining rather than that earlier status check.
		let OwnerApiEntry::Running { server, .. } = &stale_entry else {
			unreachable!()
		};
		let deadline = std::time::Instant::now() + Duration::from_secs(5);
		while (requests.request_sender.lock().is_some() || server.shutdown.try_lock().is_some())
			&& std::time::Instant::now() < deadline
		{
			thread::sleep(Duration::from_millis(1));
		}
		assert!(server.shutdown.try_lock().is_none());
		assert!(OwnerApiReservation::reserve(context_id).is_err());
		assert_owner_requests_closed(requests.clone());
		let (cleanup_done_sender, cleanup_done_receiver) = mpsc::channel();
		let cleanup = thread::spawn(move || {
			foreign_owner_api_clean_context(context_id);
			cleanup_done_sender.send(()).unwrap();
		});
		let completed_early = cleanup_done_receiver.recv_timeout(Duration::from_millis(100));
		drop(release);
		if completed_early.is_err() {
			cleanup_done_receiver
				.recv_timeout(Duration::from_secs(5))
				.unwrap();
		}
		cleanup.join().unwrap();
		request.join().unwrap();
		let Error::GenericError(message) = reaper.join().unwrap().unwrap_err() else {
			panic!("unexpected owner listener error");
		};
		assert_eq!(message, "Owner API thread terminated unexpectedly");
		assert!(matches!(completed_early, Err(RecvTimeoutError::Timeout)));
		assert_eq!(finished.load(Ordering::Acquire), 1);
		assert!(!is_owner_api_running(context_id));

		let replacement = OwnerApiReservation::reserve(context_id).unwrap();
		assert!(
			join_owner_api_entry(
				context_id,
				stale_entry,
				OwnerApiExitReason::RequestedShutdown
			)
			.unwrap()
			.is_err()
		);
		assert!(is_owner_api_running(context_id));
		drop(replacement);
	}

	#[test]
	fn owner_api_shutdown_signal_failure_is_reported_to_listener() {
		let context_id = listener_test_context();
		let requests = Arc::new(ApiAvailabilityMiddleware::new(
			StatusCode::SERVICE_UNAVAILABLE,
		));
		let request_completion = requests.open();
		let (join_result_sender, join_result_receiver) = mpsc::channel();
		let owner_api = OwnerApiEntry::Running {
			instance_id: 1,
			server: Arc::new(OwnerApiServer {
				requests,
				shutdown: Mutex::new(OwnerApiShutdown::Running {
					// An unstarted server has no shutdown sender, forcing stop() to fail.
					api_server: ApiServer::new(),
					api_thread: thread::spawn(|| {}),
					request_completion,
					join_result_sender,
				}),
			}),
		};

		let result =
			join_owner_api_entry(context_id, owner_api, OwnerApiExitReason::RequestedShutdown)
				.unwrap();
		assert_eq!(
			result,
			Err("Unable to signal Owner API shutdown".to_string())
		);
		assert_eq!(join_result_receiver.recv().unwrap(), result);
	}

	#[test]
	fn cancelled_owner_startup_preserves_stop_and_join_failures() {
		let error = cancel_owner_api_startup(
			ApiServer::new(),
			thread::spawn(|| panic!("startup cleanup panic")),
		);
		let Error::GenericError(message) = error else {
			panic!("unexpected cancellation error variant");
		};

		assert!(message.contains("Owner API startup was cancelled before registration"));
		assert!(message.contains("Unable to signal Owner API shutdown"));
		assert!(message.contains("Owner API thread panicked: startup cleanup panic"));
	}

	#[test]
	fn owner_cleanup_stops_and_joins_running_api_thread() {
		use mwc_wallet_util::mwc_crates::hyper_util::rt::{TokioExecutor, TokioIo};
		use mwc_wallet_util::mwc_crates::tokio;

		mwc_wallet_util::mwc_util::init_global_runtime().unwrap();
		let runtime = mwc_wallet_util::mwc_util::global_runtime().unwrap();
		let context_id = listener_test_context();
		let mut reservation = OwnerApiReservation::reserve(context_id).unwrap();
		let requests = Arc::new(ApiAvailabilityMiddleware::new(
			StatusCode::SERVICE_UNAVAILABLE,
		));
		let release = ReleaseApiRequests(Arc::new(AtomicBool::new(false)));
		let finished = Arc::new(AtomicUsize::new(0));
		let (started_sender, started_receiver) = mpsc::channel();
		let handler = Arc::new(BlockingApiRequest {
			started: started_sender,
			release: release.0.clone(),
			finished: finished.clone(),
		});
		let mut router = Router::new();
		router.add_middleware(requests.clone());
		let paths = ["/v2/owner", "/v3/owner", "/v2/foreign"];
		for path in paths {
			router.add_route(path, handler.clone()).unwrap();
		}

		// Reserve an unused local port for the real ApiServer and HTTP/2 client.
		let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let address = socket.local_addr().unwrap();
		drop(socket);
		let mut api_server = ApiServer::new();
		let api_thread = api_server.start(address, router, None).unwrap();
		let (join_result_sender, join_result_receiver) = mpsc::channel();
		assert!(
			reservation
				.promote(api_server, api_thread, &requests, join_result_sender)
				.is_ok()
		);

		let instance_id = reservation.instance_id;
		let listener_scope = thread::spawn(move || {
			let result = wait_for_owner_api_join(context_id, instance_id, join_result_receiver);
			drop(reservation);
			result
		});

		let connections = runtime.block_on(async {
			let mut connections = Vec::new();
			for path in paths {
				let stream = tokio::net::TcpStream::connect(address).await.unwrap();
				let (mut sender, connection) = hyper::client::conn::http2::handshake::<
					_,
					_,
					Full<Bytes>,
				>(TokioExecutor::new(), TokioIo::new(stream))
				.await
				.unwrap();
				let connection = tokio::spawn(connection);
				let request = Request::post(format!("http://{}{}", address, path))
					.body(Full::new(Bytes::from_static(b"{}")))
					.unwrap();
				let response = tokio::spawn(async move { sender.send_request(request).await });
				connections.push((connection, response));
			}
			connections
		});
		for _ in paths {
			started_receiver
				.recv_timeout(Duration::from_secs(5))
				.unwrap();
		}
		runtime.block_on(async {
			for (connection, response) in connections {
				connection.abort();
				let _ = connection.await;
				response.abort();
				let _ = response.await;
			}
		});

		let (cleanup_started_sender, cleanup_started_receiver) = mpsc::channel();
		let (cleanup_done_sender, cleanup_done_receiver) = mpsc::channel();
		let cleanup = thread::spawn(move || {
			cleanup_started_sender.send(()).unwrap();
			foreign_owner_api_clean_context(context_id);
			cleanup_done_sender.send(()).unwrap();
		});
		cleanup_started_receiver
			.recv_timeout(Duration::from_secs(5))
			.unwrap();
		let completed_early = cleanup_done_receiver.recv_timeout(Duration::from_millis(100));
		let retained_registration = is_owner_api_running(context_id);
		let finished_early = finished.load(Ordering::Acquire);

		drop(release);
		if completed_early.is_err() {
			cleanup_done_receiver
				.recv_timeout(Duration::from_secs(5))
				.unwrap();
		}
		cleanup.join().unwrap();
		assert!(matches!(completed_early, Err(RecvTimeoutError::Timeout)));
		assert!(retained_registration);
		assert_eq!(finished_early, 0);
		assert_eq!(finished.load(Ordering::Acquire), paths.len());
		listener_scope.join().unwrap().unwrap();
		assert_owner_requests_closed(requests);
		assert!(!is_owner_api_running(context_id));
	}

	struct BlockingApiRequest {
		started: Sender<()>,
		release: Arc<AtomicBool>,
		finished: Arc<AtomicUsize>,
	}

	impl mwc_wallet_util::mwc_api::Handler for BlockingApiRequest {
		fn post(&self, _request: Request<Bytes>) -> ResponseFuture {
			let started = self.started.clone();
			let release = self.release.clone();
			let finished = self.finished.clone();
			Box::pin(async move {
				crate::executor::RunHandlerInThread::new(move || {
					Box::pin(async move {
						started.send(()).unwrap();
						while !release.load(Ordering::Acquire) {
							thread::sleep(Duration::from_millis(1));
						}
						finished.fetch_add(1, Ordering::AcqRel);
						Ok(serde_json::Value::Null)
					})
				})
				.unwrap()
				.await
				.unwrap();
				Ok(Response::new(Full::new(Bytes::new())))
			})
		}
	}

	// Also unblock workers if an assertion fails before the explicit release.
	struct ReleaseApiRequests(Arc<AtomicBool>);

	impl Drop for ReleaseApiRequests {
		fn drop(&mut self) {
			self.0.store(true, Ordering::Release);
		}
	}
	#[test]
	fn stopping_cohosted_foreign_api_disables_the_real_route_gate() {
		let context_id = listener_test_context();
		let requests = Arc::new(ApiAvailabilityMiddleware::new(StatusCode::NOT_FOUND));
		let instance_id = register_cohosted_foreign_api(context_id, 99, requests.clone()).unwrap();
		assert!(enable_cohosted_foreign_api_if_current(
			context_id,
			instance_id,
			99
		));
		assert!(requests.request_sender.lock().is_some());

		stop_foreign_api_running(context_id);
		assert!(requests.request_sender.lock().is_none());
		assert!(!is_foreign_api_running(context_id));
	}

	#[test]
	fn healthy_foreign_tor_address_requires_primary_tor_readiness() {
		let context_id = listener_test_context();
		let requests = Arc::new(ApiAvailabilityMiddleware::new(StatusCode::NOT_FOUND));
		drop(requests.open());
		register_cohosted_foreign_api(context_id, 41, requests).unwrap();
		set_foreign_api_health(context_id, true);
		tor::status::set_tor_address(context_id, Some("cohosted.onion".to_string()));
		assert!(get_healthy_foreign_tor_address(context_id).is_none());
		stop_foreign_api_running(context_id);

		let server = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		let instance_id = server.instance_id();
		register_foreign_api_server(context_id, server).unwrap();
		assert!(get_healthy_foreign_tor_address(context_id).is_none());

		assert!(set_foreign_api_tor_address_if_current(
			context_id,
			instance_id,
			Some("primary.onion".to_string())
		));
		assert!(update_foreign_api_health_if_current(
			context_id,
			instance_id,
			true
		));
		// Aggregate health can come from a plain-HTTP listener and is not enough.
		assert!(get_healthy_foreign_tor_address(context_id).is_none());

		assert!(update_foreign_tor_health_if_current(
			context_id,
			instance_id,
			true
		));
		assert_eq!(
			get_healthy_foreign_tor_address(context_id).as_deref(),
			Some("primary.onion")
		);
		// A secondary listener changing aggregate health cannot overwrite the
		// primary Tor listener's generation-bound readiness.
		assert!(update_foreign_api_health_if_current(
			context_id,
			instance_id,
			false
		));
		assert_eq!(
			get_healthy_foreign_tor_address(context_id).as_deref(),
			Some("primary.onion")
		);

		assert!(
			transition_foreign_api_server_to_stopping_if_current(context_id, instance_id).is_some()
		);
		assert!(get_healthy_foreign_tor_address(context_id).is_none());
		assert!(finish_stopping_foreign_api_server_if_current(
			context_id,
			instance_id
		));
	}

	#[test]
	fn foreign_registry_rejects_duplicate_and_ignores_stale_cleanup() {
		let context_id = listener_test_context();
		let current = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		let stale = Arc::new(ForeignApiServer::new(Router::new()).unwrap());

		register_foreign_api_server(context_id, current.clone()).unwrap();
		assert!(register_foreign_api_server(context_id, stale.clone()).is_err());
		set_foreign_api_health(context_id, true);
		assert!(
			transition_foreign_api_server_to_stopping_if_current(context_id, stale.instance_id())
				.is_none()
		);
		assert!(is_foreign_api_running(context_id));
		assert!(get_foreign_api_health(context_id));

		stop_foreign_api_server_instance(context_id, current.instance_id(), &current);
		assert!(!is_foreign_api_running(context_id));
		assert!(!get_foreign_api_health(context_id));
	}

	#[test]
	fn unexpected_foreign_listener_exit_reaps_before_registry_removal() {
		let context_id = listener_test_context();
		let server = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		let instance_id = server.instance_id();
		register_foreign_api_server(context_id, server.clone()).unwrap();

		let (exit_primary_sender, exit_primary_receiver) = mpsc::channel();
		let (primary_cleaned_sender, primary_cleaned_receiver) = mpsc::channel();
		let primary_stop_state = server.stop_state.clone();
		let primary = thread::spawn(move || {
			{
				let _cleanup = ForeignListenerCleanup {
					context_id,
					instance_id,
					stop_state: primary_stop_state,
				};
				exit_primary_receiver.recv().unwrap();
			}
			primary_cleaned_sender.send(()).unwrap();
			Err("unexpected primary exit".to_string())
		});
		server.set_listener_thread_primary(primary).unwrap();

		let (secondary_stopping_sender, secondary_stopping_receiver) = mpsc::channel();
		let (release_secondary_sender, release_secondary_receiver) = mpsc::channel();
		let (secondary_finished_sender, secondary_finished_receiver) = mpsc::channel();
		let secondary_stop_state = server.stop_state.clone();
		let secondary = thread::spawn(move || {
			let _cleanup = ForeignListenerCleanup {
				context_id,
				instance_id,
				stop_state: secondary_stop_state.clone(),
			};
			while !secondary_stop_state.is_stopped() {
				thread::yield_now();
			}
			secondary_stopping_sender.send(()).unwrap();
			release_secondary_receiver.recv().unwrap();
			secondary_finished_sender.send(()).unwrap();
			Ok(())
		});
		server.set_listener_thread_secondary(secondary).unwrap();

		let (worker_stopping_sender, worker_stopping_receiver) = mpsc::channel();
		let (release_worker_sender, release_worker_receiver) = mpsc::channel();
		let (worker_finished_sender, worker_finished_receiver) = mpsc::channel();
		let worker_stop_state = server.stop_state.clone();
		let worker = thread::spawn(move || {
			while !worker_stop_state.is_stopped() {
				thread::yield_now();
			}
			worker_stopping_sender.send(()).unwrap();
			release_worker_receiver.recv().unwrap();
			worker_finished_sender.send(()).unwrap();
		});
		server.add_connection_thread_for_test("blocking worker".to_string(), worker);

		assert!(update_foreign_api_health_if_current(
			context_id,
			instance_id,
			true
		));
		assert!(set_foreign_api_tor_address_if_current(
			context_id,
			instance_id,
			Some("old-generation.onion".to_string())
		));

		exit_primary_sender.send(()).unwrap();
		primary_cleaned_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("primary cleanup did not complete");
		secondary_stopping_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("secondary listener did not observe shutdown");
		worker_stopping_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("connection worker did not observe shutdown");

		assert!(matches!(
			FOREIGN_API.read().get(&context_id),
			Some(ForeignApiEntry::Stopping(current)) if current.instance_id() == instance_id
		));
		assert!(!get_foreign_api_health(context_id));
		assert!(tor::status::get_tor_address(context_id).is_none());
		assert!(!update_foreign_api_health_if_current(
			context_id,
			instance_id,
			true
		));
		assert!(!set_foreign_api_tor_address_if_current(
			context_id,
			instance_id,
			Some("stale.onion".to_string())
		));
		let replacement = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		assert!(register_foreign_api_server(context_id, replacement.clone()).is_err());

		release_secondary_sender.send(()).unwrap();
		secondary_finished_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("secondary listener did not finish");
		assert!(matches!(
			FOREIGN_API.read().get(&context_id),
			Some(ForeignApiEntry::Stopping(current)) if current.instance_id() == instance_id
		));

		release_worker_sender.send(()).unwrap();
		worker_finished_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("connection worker did not finish");
		let deadline = std::time::Instant::now() + Duration::from_secs(2);
		while is_foreign_api_running(context_id) && std::time::Instant::now() < deadline {
			thread::sleep(Duration::from_millis(1));
		}
		assert!(!is_foreign_api_running(context_id));

		register_foreign_api_server(context_id, replacement.clone()).unwrap();
		let replacement_id = replacement.instance_id();
		assert!(update_foreign_api_health_if_current(
			context_id,
			replacement_id,
			true
		));
		assert!(set_foreign_api_tor_address_if_current(
			context_id,
			replacement_id,
			Some("replacement.onion".to_string())
		));
		assert!(!finish_stopping_foreign_api_server_if_current(
			context_id,
			instance_id
		));
		assert!(get_foreign_api_health(context_id));
		assert_eq!(
			tor::status::get_tor_address(context_id).as_deref(),
			Some("replacement.onion")
		);
		stop_foreign_api_running(context_id);
	}

	#[test]
	fn foreign_replacement_does_not_join_while_registry_is_locked() {
		let context_id = listener_test_context();
		let old = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		let old_id = old.instance_id();
		let stop_state = old.stop_state.clone();
		let listener = thread::spawn(move || {
			let _cleanup = ForeignListenerCleanup {
				context_id,
				instance_id: old_id,
				stop_state: stop_state.clone(),
			};
			while !stop_state.is_stopped() {
				thread::sleep(Duration::from_millis(1));
			}
			Ok(())
		});
		old.set_listener_thread_primary(listener).unwrap();
		register_foreign_api_server(context_id, old).unwrap();

		let replacement = Arc::new(ForeignApiServer::new(Router::new()).unwrap());
		let replacement_id = replacement.instance_id();
		let (done_sender, done_receiver) = mpsc::channel();
		thread::spawn(move || {
			set_foreign_api_server(context_id, Some(replacement)).unwrap();
			let _ = done_sender.send(());
		});

		done_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("foreign server replacement deadlocked");
		assert!(is_foreign_api_server_current(context_id, replacement_id));
		stop_foreign_api_running(context_id);
	}
}
