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

use hyper::service::Service;
use mwc_wallet_impls::http_parser::http_request::{read_http_request, send_http_response};
use mwc_wallet_impls::Error;
use mwc_wallet_util::mwc_api::Router;
use mwc_wallet_util::mwc_p2p::tor::tcp_data_stream::TcpDataStream;
use mwc_wallet_util::mwc_util::StopState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Foreign API can be listen on sockets level, that is why we can't use a regular Webserver.
/// Seckets could come from ip bind, or tor streams
pub struct ForeignApiServer {
	pub stop_state: Arc<StopState>,
	connections: Arc<RwLock<HashMap<String, JoinHandle<()>>>>,
	handlers: Arc<Mutex<Router>>,
	listener_thread: Mutex<Option<JoinHandle<()>>>,
}

impl ForeignApiServer {
	pub fn new(router: Router) -> Self {
		ForeignApiServer {
			stop_state: Arc::new(StopState::new()),
			connections: Arc::new(RwLock::new(HashMap::new())),
			handlers: Arc::new(Mutex::new(router)),
			listener_thread: Mutex::new(None),
		}
	}

	pub fn accept_connection(&self, connection_name: String, mut stream: TcpDataStream) {
		if self.stop_state.is_stopped() {
			warn!(
				"Dropping income foreign API connection {} because server is in close state",
				connection_name
			);
			return;
		}

		info!("Accepted new foreign api connection {}", connection_name);

		let connection_name2 = connection_name.clone();
		let stop_state = self.stop_state.clone();
		let handlers = self.handlers.clone();

		let connections = self.connections.clone();
		let close_connection_callback = move |connection_name| {
			let _ = connections
				.write()
				.unwrap_or_else(|e| e.into_inner())
				.remove(&connection_name);
			info!("Foreign api connection {} is closed", connection_name);
		};

		// Lock before creating the thread to gurantee that we will be able
		// to write handler before thread can be finished
		let mut connections_locked = self.connections.write().unwrap_or_else(|e| e.into_inner());

		let handler = thread::Builder::new()
			.name(connection_name2.clone())
			.spawn(move || {
				let mut buf: Vec<u8> = Vec::new();

				// For reaction to the stop request, want check every second
				let try_time_interval = Duration::from_secs(1);
				// Reading body timeout. Matching 30 sec that client have
				let response_read_timeout = Duration::from_secs(30);

				while !stop_state.is_stopped() {
					match read_http_request(
						&mut buf,
						&mut stream,
						&try_time_interval,
						&response_read_timeout,
					) {
						Ok((request, close_connection)) => {
							// request is here, so we should be able to process it.
							// Response need to send back in any case, even if it is error
							let res = {
								handlers
									.lock()
									.unwrap_or_else(|e| e.into_inner())
									.call(request)
							};

							let response = futures::executor::block_on(res);
							let response = match response {
								Ok(response) => response,
								Err(e) => {
									error!("Unable to process Foreign API request, {}", e);
									break;
								}
							};

							let ok =
								send_http_response(&mut stream, response, close_connection).is_ok();
							if close_connection || !ok {
								let _ = stream.shutdown();
								break;
							}
						}
						Err(Error::ConnectionError(reason)) => {
							if reason.contains("timeout") {
								continue;
							} else {
								debug!(
									"Closing conneciton because of request read error: {}",
									reason
								);
								break;
							}
						}
						Err(e) => {
							debug!("Closing conneciton because of request read error: {}", e);
							break;
						}
					}
				}
				close_connection_callback(connection_name2)
			});

		match handler {
			Ok(handler) => {
				let _ = connections_locked.insert(connection_name, handler);
			}
			Err(e) => error!(
				"Failed to start handler thread for {}, {}",
				connection_name, e
			),
		}
	}

	pub fn set_listener_thread(&self, listener_handle: JoinHandle<()>) {
		debug_assert!(!self.stop_state.is_stopped());
		debug_assert!(self
			.listener_thread
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.is_none());
		*self
			.listener_thread
			.lock()
			.unwrap_or_else(|e| e.into_inner()) = Some(listener_handle);
	}

	pub fn take_listener_thread(&self) -> Option<JoinHandle<()>> {
		self.listener_thread
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.take()
	}

	pub fn stop(&self) {
		self.stop_state.stop();
		// Waiting for all connections to close
		while self
			.connections
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.len() > 0
		{
			thread::sleep(Duration::from_millis(200));
		}

		if let Some(thr) = self
			.listener_thread
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.take()
		{
			let _ = thr.join();
		}
	}
}
