// Copyright 2025 The MWC Developers
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

use mwc_wallet_impls::Error;
use mwc_wallet_impls::http_parser::http_request::{read_http_request, send_http_response};
use mwc_wallet_util::mwc_api::Router;
use mwc_wallet_util::mwc_crates::futures;
use mwc_wallet_util::mwc_crates::hyper::service::Service;
use mwc_wallet_util::mwc_crates::log::{debug, error, info, warn};
use mwc_wallet_util::mwc_p2p::PeerAddr;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_util::StopState;
use mwc_wallet_util::{Mutex, RwLock};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub type ForeignListenerResult = Result<(), String>;
pub type ForeignListenerHandle = JoinHandle<ForeignListenerResult>;

const MAX_FOREIGN_API_CONNECTIONS: usize = 64;
/// Limit the work a busy keep-alive connection can perform while it owns one
/// of the limited foreign API connection permits.
const MAX_REQUESTS_PER_CONNECTION: usize = 32;
/// A per-request read timeout is not enough to bound a connection lifetime:
/// a slow client can send another request before every timeout and retain its
/// connection permit indefinitely.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(120);
static NEXT_FOREIGN_API_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_foreign_api_instance_id(counter: &AtomicU64) -> Result<u64, Error> {
	counter
		.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			current.checked_add(1)
		})
		.map_err(|_| {
			Error::DataOverflow("Foreign API instance identifier space exhausted".to_string())
		})
}

/// Server-derived request capabilities for the Foreign RPC handler.
///
/// This value is inserted into the request extensions after accepting the
/// transport. It must never be populated from HTTP headers: a reverse proxy
/// header is caller-controlled unless the proxy itself is part of the trusted
/// boundary.
///
/// Loopback access to `build_coinbase` is intentionally unauthenticated for
/// compatibility with the normal local mining setup, which does not provide a
/// separate wallet credential. `build_coinbase` cannot spend wallet funds or
/// disclose wallet secrets, but a local caller can repeatedly request fresh
/// coinbase candidates. Each fresh candidate can advance the wallet derivation
/// index and persist an unconfirmed output. We accept that state-growth risk and
/// treat each authorized host, rather than an individual process on that host,
/// as the trusted boundary. Consequently every process able to originate a
/// connection from loopback or `mining_node_ip` is trusted, including a local
/// browser carrying a request initiated by web content; HTTP headers are not an
/// authentication boundary. Deployments that need process-level isolation, or
/// that forward this listener through a proxy, must enforce an equivalent
/// mining-only access policy outside this handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForeignRequestAccess {
	allow_build_coinbase: bool,
}

impl ForeignRequestAccess {
	pub(crate) fn deny_build_coinbase() -> Self {
		Self {
			allow_build_coinbase: false,
		}
	}

	pub(crate) fn from_peer(
		peer_address: Option<&PeerAddr>,
		mining_node_ip: Option<IpAddr>,
	) -> Self {
		let peer_ip = match peer_address {
			Some(PeerAddr::Ip(address)) => canonical_ip(address.ip()),
			Some(PeerAddr::Onion(_)) | None => return Self::deny_build_coinbase(),
		};
		// Keep capability derivation fail-closed even if a caller bypasses listener
		// configuration validation.
		let configured_ip = mining_node_ip
			.filter(|ip| is_valid_mining_node_ip(*ip))
			.map(canonical_ip);

		Self {
			allow_build_coinbase: peer_ip.is_loopback() || configured_ip == Some(peer_ip),
		}
	}

	pub(crate) fn allows_build_coinbase(self) -> bool {
		self.allow_build_coinbase
	}
}

/// A link-local `IpAddr` lacks the interface scope required to identify one
/// link unambiguously, so it is not safe to use as an authorization key.
/// Canonicalize first so IPv4-mapped IPv6 addresses cannot bypass the IPv4
/// source-address checks.
pub(crate) fn is_valid_mining_node_ip(ip: IpAddr) -> bool {
	let ip = canonical_ip(ip);
	!ip.is_unspecified()
		&& !ip.is_multicast()
		&& match ip {
			IpAddr::V4(ipv4) => !ipv4.is_link_local() && !ipv4.is_broadcast(),
			IpAddr::V6(ipv6) => !ipv6.is_unicast_link_local(),
		}
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(ipv6) => ipv6
			.to_ipv4_mapped()
			.map(IpAddr::V4)
			.unwrap_or(IpAddr::V6(ipv6)),
		ip => ip,
	}
}

struct ConnectionPermit {
	active_connections: Arc<AtomicUsize>,
}

impl ConnectionPermit {
	fn try_acquire(active_connections: Arc<AtomicUsize>, limit: usize) -> Option<Self> {
		active_connections
			.try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
				(active < limit).then_some(active.saturating_add(1))
			})
			.ok()?;
		Some(Self { active_connections })
	}
}

impl Drop for ConnectionPermit {
	fn drop(&mut self) {
		self.active_connections.fetch_sub(1, Ordering::AcqRel);
	}
}

/// Foreign API can be listen on sockets level, that is why we can't use a regular Webserver.
/// Seckets could come from ip bind, or tor streams
pub struct ForeignApiServer {
	instance_id: u64,
	pub stop_state: Arc<StopState>,
	connections: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
	active_connections: Arc<AtomicUsize>,
	connection_limit: usize,
	handlers: Arc<Mutex<Router>>,
	shutdown_lock: Mutex<()>,
	listener_thread_primary: Mutex<Option<ForeignListenerHandle>>,
	listener_thread_secondary: Mutex<Option<ForeignListenerHandle>>,
}

impl ForeignApiServer {
	pub fn new(router: Router) -> Result<Self, Error> {
		Self::new_with_connection_limit(router, MAX_FOREIGN_API_CONNECTIONS)
	}

	fn new_with_connection_limit(router: Router, connection_limit: usize) -> Result<Self, Error> {
		Ok(ForeignApiServer {
			instance_id: allocate_foreign_api_instance_id(&NEXT_FOREIGN_API_INSTANCE_ID)?,
			stop_state: Arc::new(StopState::new()),
			connections: Arc::new(RwLock::new(HashMap::new())),
			active_connections: Arc::new(AtomicUsize::new(0)),
			connection_limit,
			handlers: Arc::new(Mutex::new(router)),
			shutdown_lock: Mutex::new(()),
			listener_thread_primary: Mutex::new(None),
			listener_thread_secondary: Mutex::new(None),
		})
	}

	pub fn instance_id(&self) -> u64 {
		self.instance_id
	}

	#[cfg(test)]
	pub(crate) fn add_connection_thread_for_test(
		&self,
		connection_name: String,
		connection: JoinHandle<()>,
	) {
		self.connections.write().insert(connection_name, connection);
	}

	pub(crate) fn accept_connection(
		&self,
		connection_name: String,
		mut stream: TcpDataStream,
		request_access: ForeignRequestAccess,
	) {
		if self.stop_state.is_stopped() {
			warn!(
				"Dropping income foreign API connection {} because server is in close state",
				connection_name
			);
			return;
		}

		let Some(connection_permit) =
			ConnectionPermit::try_acquire(self.active_connections.clone(), self.connection_limit)
		else {
			warn!(
				"Dropping foreign API connection {} because the {} connection limit was reached",
				connection_name, self.connection_limit
			);
			if let Err(e) = stream.shutdown() {
				debug!(
					"Unable to shut down rejected foreign API connection {}: {}",
					connection_name, e
				);
			}
			return;
		};

		info!("Accepted new foreign api connection {}", connection_name);

		let connection_name2 = connection_name.clone();
		let stop_state = self.stop_state.clone();
		let handlers = self.handlers.clone();

		let connections = self.connections.clone();
		let close_connection_callback = move |connection_name| {
			let _ = connections.write().remove(&connection_name);
			info!("Foreign api connection {} is closed", connection_name);
		};

		// Lock before creating the thread to gurantee that we will be able
		// to write handler before thread can be finished
		let mut connections_locked = self.connections.write();
		if self.stop_state.is_stopped() {
			drop(connections_locked);
			if let Err(e) = stream.shutdown() {
				debug!(
					"Unable to shut down foreign API connection {} during server stop: {}",
					connection_name, e
				);
			}
			return;
		}
		let connection_slot = match connections_locked.entry(connection_name.clone()) {
			Entry::Vacant(connection_slot) => connection_slot,
			Entry::Occupied(_) => {
				// A duplicate name must never replace the registry-owned JoinHandle:
				// dropping that handle would detach a still-running connection worker.
				self.stop_state.stop();
				drop(connections_locked);
				error!(
					"Rejecting duplicate foreign API connection identifier {}; stopping the server",
					connection_name
				);
				if let Err(e) = stream.shutdown() {
					debug!(
						"Unable to shut down duplicate foreign API connection {}: {}",
						connection_name, e
					);
				}
				return;
			}
		};

		let handler = thread::Builder::new()
			.name(connection_name2.clone())
			.spawn(move || {
				let _connection_permit = connection_permit;
				let mut buf: Vec<u8> = Vec::new();

				// For reaction to the stop request, want check every second
				let try_time_interval = Duration::from_secs(1);
				// Reading body timeout. Matching 30 sec that client have
				let response_read_timeout = Duration::from_secs(30);
				// The request count makes busy keep-alive clients release their permit,
				// while the elapsed-time limit covers slow clients which may never reach
				// the request limit. Both are measured for the entire connection because
				// its permit is retained until this worker exits.
				let connection_started = Instant::now();
				let mut request_count = 0usize;

				while !stop_state.is_stopped()
					&& connection_started.elapsed() < MAX_CONNECTION_LIFETIME
					&& request_count < MAX_REQUESTS_PER_CONNECTION
				{
					match read_http_request(
						&mut buf,
						&mut stream,
						&try_time_interval,
						&response_read_timeout,
						&|| {
							stop_state.is_stopped()
								|| connection_started.elapsed() >= MAX_CONNECTION_LIFETIME
						},
					) {
						Ok((mut request, close_connection)) => {
							// Shutdown may have begun after the final body byte was
							// read. Never dispatch a wallet operation after that point.
							if stop_state.is_stopped() {
								break;
							}
							request.extensions_mut().insert(request_access);
							request_count += 1;
							// Complete the current parsed request, but close its connection
							// instead of allowing another request after either limit is met.
							let close_connection = close_connection
								|| request_count >= MAX_REQUESTS_PER_CONNECTION
								|| connection_started.elapsed() >= MAX_CONNECTION_LIFETIME;

							// Response need to send back in any case, even if it is error
							let res = { handlers.lock().call(request) };

							let response = futures::executor::block_on(res);
							let response = match response {
								Ok(response) => response,
								Err(e) => {
									error!("Unable to process Foreign API request, {}", e);
									break;
								}
							};

							if let Err(e) = send_http_response(&mut stream, response, close_connection) {
								warn!("Unable to send foreign API response: {}", e);
								break;
							}
							if close_connection {
								break;
							}
						}
						Err(e) => {
							debug!("Closing conneciton because of request read error: {}", e);
							break;
						}
					}
				}
				if let Err(e) = stream.shutdown() {
					warn!("Unable to shut down foreign API stream: {}", e);
				}
				close_connection_callback(connection_name2)
			});

		match handler {
			Ok(handler) => {
				connection_slot.insert(handler);
			}
			Err(e) => error!(
				"Failed to start handler thread for {}, {}",
				connection_name, e
			),
		}
	}

	pub fn set_listener_thread_primary(
		&self,
		listener_handle: ForeignListenerHandle,
	) -> Result<(), Error> {
		// Serialize publication of the handle with stop(). Without this lock,
		// teardown could observe an empty slot, return, and then have startup
		// publish a detached listener for the released context.
		let shutdown_guard = self.shutdown_lock.lock();
		if self.stop_state.is_stopped() {
			drop(shutdown_guard);
			if let Err(e) = join_listener("Rejected primary", listener_handle) {
				debug!("Rejected primary foreign listener stopped with an error: {}", e);
			}
			return Err(Error::ClosedListener(
				"ForeignAPIHandlerV2::set_listener_thread_primary, server is stopped".to_string(),
			));
		}
		let mut listener_thread = self.listener_thread_primary.lock();
		if listener_thread.is_some() {
			self.stop_state.stop();
			drop(listener_thread);
			drop(shutdown_guard);
			if let Err(e) = join_listener("Rejected primary", listener_handle) {
				debug!("Rejected primary foreign listener stopped with an error: {}", e);
			}
			self.stop();
			return Err(Error::ClosedListener(
				"ForeignAPIHandlerV2::set_listener_thread_primary, listener is already set"
					.to_string(),
			));
		}
		*listener_thread = Some(listener_handle);
		Ok(())
	}

	pub fn set_listener_thread_secondary(
		&self,
		listener_handle: ForeignListenerHandle,
	) -> Result<(), Error> {
		let shutdown_guard = self.shutdown_lock.lock();
		if self.stop_state.is_stopped() {
			drop(shutdown_guard);
			if let Err(e) = join_listener("Rejected secondary", listener_handle) {
				debug!("Rejected secondary foreign listener stopped with an error: {}", e);
			}
			return Err(Error::ClosedListener(
				"ForeignAPIHandlerV2::set_listener_thread_secondary, server is stopped".to_string(),
			));
		}
		let mut listener_thread = self.listener_thread_secondary.lock();
		if listener_thread.is_some() {
			self.stop_state.stop();
			drop(listener_thread);
			drop(shutdown_guard);
			if let Err(e) = join_listener("Rejected secondary", listener_handle) {
				debug!("Rejected secondary foreign listener stopped with an error: {}", e);
			}
			self.stop();
			return Err(Error::ClosedListener(
				"ForeignAPIHandlerV2::set_listener_thread_secondary, listener is already set"
					.to_string(),
			));
		}
		*listener_thread = Some(listener_handle);
		Ok(())
	}

	pub fn wait_for_listeners(&self, secondary_required: bool) -> ForeignListenerResult {
		// A foreground waiter temporarily owns the listener handles. Serialize it
		// with stop() so another teardown path cannot observe empty handle slots and
		// treat the server as quiesced before this waiter has joined the threads.
		let _shutdown_guard = self.shutdown_lock.lock();
		let primary = self.listener_thread_primary.lock().take();
		let secondary = self.listener_thread_secondary.lock().take();

		// Shared shutdown can make both listeners report errors. Keep reporting
		// simple and deterministic: propagate the first error we observe and log
		// any later error. The first error is enough for debugging, and collecting
		// multiple errors would overcomplicate this string-based result.
		let Some(primary) = primary else {
			self.stop_state.stop();
			if let Some(secondary) = secondary
				&& let Err(e) = join_listener("Secondary", secondary)
			{
				error!(
					"Secondary foreign API listener also failed after the primary listener handle was found missing: {}",
					e
				);
			}
			if let Err(e) = self.join_connections() {
				error!("Connection shutdown also failed: {}", e);
			}
			return Err("Primary foreign API listener handle is missing".to_string());
		};
		if secondary_required && secondary.is_none() {
			self.stop_state.stop();
			if let Err(e) = join_listener("Primary", primary) {
				error!(
					"Primary foreign API listener also failed after the secondary listener handle was found missing: {}",
					e
				);
			}
			if let Err(e) = self.join_connections() {
				error!("Connection shutdown also failed: {}", e);
			}
			return Err("Secondary foreign API listener handle is missing".to_string());
		}

		let primary_result = join_listener("Primary", primary);
		// Either listener is required for the service. Ensure the sibling can
		// terminate even if the primary returned or panicked unexpectedly.
		self.stop_state.stop();

		let secondary_result = match secondary {
			Some(secondary) => join_listener("Secondary", secondary),
			None => Ok(()),
		};

		let listener_result = match primary_result {
			Err(primary_error) => {
				if let Err(e) = secondary_result {
					error!(
						"Additional secondary foreign API listener error after '{}': {}",
						primary_error, e
					);
				}
				Err(primary_error)
			}
			Ok(()) => secondary_result,
		};
		let connection_result = self.join_connections();
		match (listener_result, connection_result) {
			(Err(listener_error), Err(connection_error)) => {
				error!(
					"Connection shutdown also failed after listener error '{}': {}",
					listener_error, connection_error
				);
				Err(listener_error)
			}
			(Err(listener_error), Ok(())) => Err(listener_error),
			(Ok(()), connection_result) => connection_result,
		}
	}

	/// Stop and join all owned listener and connection threads.
	/// Shutdown failures are intentionally logged while all remaining joins
	/// continue. Even when a worker panics, joining it confirms that it has
	/// terminated. Log-based diagnostics are sufficient for
	/// this cleanup API, so no error result is returned.
	pub fn stop(&self) {
		// Signal before waiting for the shutdown coordinator. wait_for_listeners()
		// may hold the lock while blocked in a listener join and needs this signal
		// in order to make progress.
		self.stop_state.stop();
		let _shutdown_guard = self.shutdown_lock.lock();

		if let Some(thr) = self.listener_thread_primary.lock().take()
			&& let Err(e) = join_listener("Primary", thr)
		{
			error!("Primary foreign API listener stopped with an error: {}", e);
		}

		if let Some(thr) = self.listener_thread_secondary.lock().take()
			&& let Err(e) = join_listener("Secondary", thr)
		{
			error!(
				"Secondary foreign API listener stopped with an error: {}",
				e
			);
		}

		if let Err(e) = self.join_connections() {
			error!("Foreign API connection shutdown failed: {}", e);
		}
	}

	fn join_connections(&self) -> ForeignListenerResult {
		let connections = {
			let mut connections = self.connections.write();
			std::mem::take(&mut *connections)
		};
		let mut first_error = None;
		for (connection_name, connection) in connections {
			if connection.join().is_err() {
				let error = format!("Foreign API connection {} panicked", connection_name);
				if first_error.is_none() {
					first_error = Some(error);
				} else {
					error!("{}", error);
				}
			}
		}
		match first_error {
			Some(error) => Err(error),
			None => Ok(()),
		}
	}
}

fn join_listener(name: &str, handle: ForeignListenerHandle) -> ForeignListenerResult {
	handle
		.join()
		.map_err(|_| format!("{} foreign API listener thread panicked", name))?
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn connection_permit_enforces_limit_and_releases_capacity() {
		let active = Arc::new(AtomicUsize::new(0));
		let first = ConnectionPermit::try_acquire(active.clone(), 2).unwrap();
		let second = ConnectionPermit::try_acquire(active.clone(), 2).unwrap();
		assert!(ConnectionPermit::try_acquire(active.clone(), 2).is_none());
		assert_eq!(active.load(Ordering::Acquire), 2);

		drop(first);
		assert!(ConnectionPermit::try_acquire(active.clone(), 2).is_some());
		drop(second);
	}

	#[test]
	fn foreign_api_instances_have_distinct_ids() {
		let first = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		let second = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		assert_ne!(first.instance_id(), second.instance_id());
	}

	#[test]
	fn foreign_api_instance_id_exhaustion_does_not_wrap() {
		let counter = AtomicU64::new(u64::MAX - 1);
		assert_eq!(
			allocate_foreign_api_instance_id(&counter).unwrap(),
			u64::MAX - 1
		);
		assert!(matches!(
			allocate_foreign_api_instance_id(&counter),
			Err(Error::DataOverflow(_))
		));
		assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
	}

	#[test]
	fn coinbase_access_allows_loopback_and_configured_ip_only() {
		let ipv4_loopback = PeerAddr::Ip("127.0.0.1:3415".parse().unwrap());
		let ipv6_loopback = PeerAddr::Ip("[::1]:3415".parse().unwrap());
		let configured = "192.0.2.10".parse().unwrap();
		let configured_peer = PeerAddr::Ip("192.0.2.10:3415".parse().unwrap());
		let configured_ipv6 = "2001:db8::10".parse().unwrap();
		let configured_ipv6_peer = PeerAddr::Ip("[2001:db8::10]:3415".parse().unwrap());
		let other_peer = PeerAddr::Ip("192.0.2.11:3415".parse().unwrap());

		assert!(
			ForeignRequestAccess::from_peer(Some(&ipv4_loopback), None)
				.allows_build_coinbase()
		);
		assert!(
			ForeignRequestAccess::from_peer(Some(&ipv6_loopback), None)
				.allows_build_coinbase()
		);
		assert!(
			ForeignRequestAccess::from_peer(Some(&configured_peer), Some(configured))
				.allows_build_coinbase()
		);
		assert!(
			ForeignRequestAccess::from_peer(Some(&configured_ipv6_peer), Some(configured_ipv6))
				.allows_build_coinbase()
		);
		assert!(
			!ForeignRequestAccess::from_peer(Some(&other_peer), Some(configured))
				.allows_build_coinbase()
		);
	}

	#[test]
	fn coinbase_access_rejects_tor_and_unknown_origins() {
		let onion = PeerAddr::Onion(
			"exampleexampleexampleexampleexampleexampleexampleexample.onion".to_string(),
		);

		assert!(!ForeignRequestAccess::from_peer(Some(&onion), None).allows_build_coinbase());
		assert!(!ForeignRequestAccess::from_peer(None, None).allows_build_coinbase());
	}

	#[test]
	fn coinbase_access_rejects_ipv6_link_local_mining_node_ip() {
		let configured: IpAddr = "fe80::1234".parse().unwrap();
		let peer = PeerAddr::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
			match configured {
				IpAddr::V6(ipv6) => ipv6,
				IpAddr::V4(_) => unreachable!(),
			},
			3415,
			0,
			3,
		)));

		assert!(!is_valid_mining_node_ip(configured));
		assert!(
			!ForeignRequestAccess::from_peer(Some(&peer), Some(configured))
				.allows_build_coinbase()
		);
	}

	#[test]
	fn coinbase_access_rejects_ipv4_link_local_mining_node_ip() {
		let configured: IpAddr = "169.254.10.20".parse().unwrap();
		let peer = PeerAddr::Ip("169.254.10.20:3415".parse().unwrap());

		assert!(!is_valid_mining_node_ip(configured));
		assert!(
			!ForeignRequestAccess::from_peer(Some(&peer), Some(configured))
				.allows_build_coinbase()
		);
	}

	#[test]
	fn mining_node_ip_validation_rejects_invalid_source_addresses() {
		for configured in [
			"0.0.0.0",
			"224.0.0.1",
			"255.255.255.255",
			"::ffff:0.0.0.0",
			"::ffff:224.0.0.1",
			"::ffff:255.255.255.255",
			"::ffff:169.254.10.20",
		] {
			let configured: IpAddr = configured.parse().unwrap();
			assert!(
				!is_valid_mining_node_ip(configured),
				"{} should not be a mining-node authorization address",
				configured
			);
		}

		let configured: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
		assert!(is_valid_mining_node_ip(configured));
	}

	#[test]
	fn stop_waits_for_active_connection_workers() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		let stop_state = server.stop_state.clone();
		let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
		let worker_finished = finished.clone();
		let worker = thread::spawn(move || {
			while !stop_state.is_stopped() {
				thread::yield_now();
			}
			worker_finished.store(true, Ordering::Release);
		});
		server
			.connections
			.write()
			.insert("test connection".to_string(), worker);

		server.stop();

		assert!(finished.load(Ordering::Acquire));
		assert!(server.connections.read().is_empty());
	}

	#[test]
	fn listener_published_after_stop_is_joined_before_rejection() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		server.stop();

		let stop_state = server.stop_state.clone();
		let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
		let listener_finished = finished.clone();
		let listener = thread::spawn(move || {
			while !stop_state.is_stopped() {
				thread::yield_now();
			}
			listener_finished.store(true, Ordering::Release);
			Ok(())
		});

		assert!(server.set_listener_thread_primary(listener).is_err());
		assert!(finished.load(Ordering::Acquire));
	}

	#[test]
	fn listener_error_stops_sibling_and_is_returned() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		let sibling_stop_state = server.stop_state.clone();
		server
			.set_listener_thread_primary(thread::spawn(|| Err("bind failed".to_string())))
			.unwrap();
		server
			.set_listener_thread_secondary(thread::spawn(move || {
				while !sibling_stop_state.is_stopped() {
					thread::yield_now();
				}
				Ok(())
			}))
			.unwrap();

		let error = server.wait_for_listeners(true).unwrap_err();
		assert_eq!(error, "bind failed");
	}

	#[test]
	fn stop_coordinates_with_foreground_listener_waiter() {
		let server = Arc::new(
			ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap(),
		);
		let listener_stop_state = server.stop_state.clone();
		let (listener_stopping_sender, listener_stopping_receiver) = std::sync::mpsc::channel();
		let (release_listener_sender, release_listener_receiver) = std::sync::mpsc::channel();
		server
			.set_listener_thread_primary(thread::spawn(move || {
				while !listener_stop_state.is_stopped() {
					thread::yield_now();
				}
				listener_stopping_sender.send(()).unwrap();
				release_listener_receiver.recv().unwrap();
				Ok(())
			}))
			.unwrap();

		let waiter_server = server.clone();
		let waiter = thread::spawn(move || waiter_server.wait_for_listeners(false));
		let deadline = Instant::now() + Duration::from_secs(2);
		while server.listener_thread_primary.lock().is_some() && Instant::now() < deadline {
			thread::yield_now();
		}
		assert!(server.listener_thread_primary.lock().is_none());

		let stopper_server = server.clone();
		let (stopper_done_sender, stopper_done_receiver) = std::sync::mpsc::channel();
		thread::spawn(move || {
			stopper_server.stop();
			stopper_done_sender.send(()).unwrap();
		});
		listener_stopping_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("stop() did not signal the listener while the waiter held the shutdown lock");
		assert!(matches!(
			stopper_done_receiver.try_recv(),
			Err(std::sync::mpsc::TryRecvError::Empty)
		));

		release_listener_sender.send(()).unwrap();
		waiter.join().unwrap().unwrap();
		stopper_done_receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("stop() did not wait for the foreground listener join");
	}

	#[test]
	fn first_listener_error_is_returned_when_both_listeners_fail() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		server
			.set_listener_thread_primary(thread::spawn(|| Err("primary failed".to_string())))
			.unwrap();
		server
			.set_listener_thread_secondary(thread::spawn(|| Err("secondary failed".to_string())))
			.unwrap();

		let error = server.wait_for_listeners(true).unwrap_err();
		assert_eq!(error, "primary failed");
	}

	#[test]
	fn listener_error_is_preserved_when_connection_worker_panics() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		server
			.set_listener_thread_primary(thread::spawn(|| Err("listener failed".to_string())))
			.unwrap();
		server.connections.write().insert(
			"panicking connection".to_string(),
			thread::spawn(|| panic!("connection failed")),
		);

		let error = server.wait_for_listeners(false).unwrap_err();
		assert_eq!(error, "listener failed");
		assert!(server.connections.read().is_empty());
	}

	#[test]
	fn missing_handle_error_is_returned_before_remaining_listener_error() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		server
			.set_listener_thread_secondary(thread::spawn(|| Err("secondary failed".to_string())))
			.unwrap();
		assert_eq!(
			server.wait_for_listeners(true).unwrap_err(),
			"Primary foreign API listener handle is missing"
		);

		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		server
			.set_listener_thread_primary(thread::spawn(|| Err("primary failed".to_string())))
			.unwrap();
		assert_eq!(
			server.wait_for_listeners(true).unwrap_err(),
			"Secondary foreign API listener handle is missing"
		);
	}

	#[test]
	fn required_missing_secondary_handle_is_returned_without_waiting_forever() {
		let server = ForeignApiServer::new_with_connection_limit(Router::new(), 1).unwrap();
		let primary_stop_state = server.stop_state.clone();
		server
			.set_listener_thread_primary(thread::spawn(move || {
				while !primary_stop_state.is_stopped() {
					thread::yield_now();
				}
				Ok(())
			}))
			.unwrap();

		let error = server.wait_for_listeners(true).unwrap_err();
		assert_eq!(error, "Secondary foreign API listener handle is missing");
	}
}
