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

//! A threaded persistent Updater that can be controlled by a mwc wallet
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::mwc_keychain::Keychain;
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::Mutex;

use crate::api_impl::owner;
use crate::types::NodeClient;
use crate::{wallet_lock, Error};
use crate::{WalletInst, WalletLCProvider};
use std::thread::JoinHandle;

const MESSAGE_QUEUE_MAX_LEN: usize = 10_000;

/// Update status messages which can be returned to listening clients
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusMessage {
	/// Wallet is performing a regular update, matching the UTXO set against
	/// current wallet outputs
	UpdatingOutputs(bool, String),
	/// Warning that the wallet is about to perform a full UTXO scan
	FullScanWarn(String),
	/// Status and percentage complete messages returned during the
	/// scanning process
	Scanning(bool, String, u8),
	/// UTXO scanning is complete
	ScanningComplete(bool, String),
	/// Warning of issues that may have occured during an update
	Warning(String),
	/// Generic info message
	Info(String),
}

/// Helper function that starts a simple log thread for updater messages
/// Note! This loop will never end
pub fn start_updater_log_thread(
	rx: Receiver<StatusMessage>,
	queue: Arc<Mutex<Vec<StatusMessage>>>,
	running_state: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, Error> {
	let handle = thread::Builder::new()
		.name("wallet-updater-status".to_string())
		.spawn(move || {
			let mut updated_percent: u8 = 250;
			loop {
				let running = running_state.load(Ordering::Relaxed);
				while let Ok(m) = rx.try_recv() {
					// save to our message queue to be read by other consumers
					{
						let mut q = queue.lock();
						q.insert(0, m.clone());
						while q.len() > MESSAGE_QUEUE_MAX_LEN {
							q.pop();
						}
					}
					match m {
						StatusMessage::UpdatingOutputs(_show_progress, s) => info!("{}", s),
						StatusMessage::FullScanWarn(s) => warn!("{}", s),
						StatusMessage::Scanning(show_progress, s, m) => {
							info!("{}", s);
							if updated_percent != m {
								if show_progress {
									warn!("Scanning - {}% complete", m);
								} else {
									info!("Scanning - {}% complete", m);
								}
								updated_percent = m;
							}
						}
						StatusMessage::ScanningComplete(show_progress, s) => {
							if show_progress {
								warn!("{}", s);
							} else {
								info!("{}", s);
							}
						}
						StatusMessage::Warning(s) => warn!("{}", s),
						StatusMessage::Info(s) => info!("{}", s),
					}
				}
				if !running {
					// Need to check first, then read, and exit
					break;
				}
				thread::sleep(Duration::from_millis(100));
			}
		})?;

	Ok(handle)
}

/// Helper function that starts a simple console printing thread for updater messages
/// Used by mwc713. This loop MUST end
pub fn start_updater_console_thread(
	rx: Receiver<StatusMessage>,
	running_state: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, Error> {
	let handle = thread::Builder::new()
		.name("wallet-console-updater-status".to_string())
		.spawn(move || {
			loop {
				let running = running_state.load(Ordering::Relaxed);
				while let Ok(m) = rx.try_recv() {
					match m {
						StatusMessage::UpdatingOutputs(show_progress, s) => {
							if show_progress {
								println!("{}", s)
							}
						}
						StatusMessage::FullScanWarn(s) => println!("{}", s),
						StatusMessage::Scanning(show_progress, s, m) => {
							if show_progress {
								println!("{}, {}% complete", s, m);
							}
						}
						StatusMessage::ScanningComplete(show_progress, s) => {
							if show_progress {
								println!("{}", s)
							}
						}
						StatusMessage::Warning(s) => println!("Warning: {}", s),
						StatusMessage::Info(s) => println!("Info: {}", s),
					}
				}
				if !running {
					// Need to check first, then read, and exit
					break;
				}
				thread::sleep(Duration::from_millis(100));
			}
			()
		})?;

	Ok(handle)
}

/// Handles and launches a background update thread
pub struct Updater<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	is_running: Arc<AtomicBool>,
}

impl<'a, L, C, K> Updater<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// create a new updater
	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		is_running: Arc<AtomicBool>,
	) -> Self {
		is_running.store(false, Ordering::Relaxed);
		Updater {
			wallet_inst,
			is_running,
		}
	}

	/// Start the updater at the given frequency
	pub fn run(
		&self,
		frequency: Duration,
		keychain_mask: Option<SecretKey>,
		status_send_channel: &Option<Sender<StatusMessage>>,
	) -> Result<(), Error> {
		self.is_running.store(true, Ordering::Relaxed);
		loop {
			let wallet_opened = {
				let mut w_lock = self.wallet_inst.lock();
				let w_provider = w_lock.lc_provider()?;
				w_provider.wallet_inst().is_ok()
			};

			let sec = if wallet_opened {
				// Business goes here
				wallet_lock!(self.wallet_inst, w);
				owner::update_wallet_state(
					&mut **w,
					(&keychain_mask).as_ref(),
					status_send_channel,
				)?;
				frequency.as_secs()
			} else {
				1
			};

			for _ in 0..sec {
				if !self.is_running.load(Ordering::Relaxed) {
					return Ok(());
				}
				thread::sleep(Duration::from_secs(1));
			}
		}
	}
}
