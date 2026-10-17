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

//! Test client that acts against a local instance of a node so that wallet APIs
//! can be fully exercised. It operates directly on a chain instance and is not
//! the production HTTP node client.
//!
//! Requests, responses, recipients, and channels in this module are built and
//! owned by one in-process test fixture. Deliberate `unwrap`, `expect`, and
//! `panic!` sites assert that private fixture protocol: malformed messages,
//! disconnected participants, or an unusable local chain are test setup or
//! programming failures for which continuing would hide the original cause.
//! Production transports must validate untrusted input and propagate failures.
//!
//! The fixture contract permits only one outstanding request for a registered
//! wallet ID and requires test code to mutate/mine the local chain only between
//! wallet operations. `LocalWalletClient` is `Clone + Send + Sync` to satisfy the
//! wallet traits and test ownership needs, not to model a multiplexed transport.
//! Concurrent requests under one ID or concurrent chain mutation are invalid
//! test topology, not production behaviors this fixture is intended to support.

use mwc_wallet_libwallet;
use mwc_wallet_libwallet::api_impl::foreign;
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::slate_versions::v3::SlateV3;
use mwc_wallet_libwallet::types::{TxSession, U64_DATA_IDX_ADDRESS_INDEX};
use mwc_wallet_libwallet::SlateCtx;
use mwc_wallet_libwallet::{
	HeaderInfo, NodeClient, NodeHeaderLink, NodeOutputDetails, NodeVersionInfo, Slate, WalletInst,
	WalletLCProvider,
};
use mwc_wallet_util::mwc_api::{self, LocatedTxKernel};
use mwc_wallet_util::mwc_chain::types::NoopAdapter;
use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core::core::hash::{Hash, Hashed};
use mwc_wallet_util::mwc_core::core::BlockHeader;
use mwc_wallet_util::mwc_core::core::{Transaction, TxKernel};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::global::{set_local_chain_type, set_local_nrd_enabled, ChainTypes};
use mwc_wallet_util::mwc_core::pow;
use mwc_wallet_util::mwc_crates::log::{error, info, trace};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_wallet_util::mwc_util;
use mwc_wallet_util::mwc_util::ToHex;
use mwc_wallet_util::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Controls and joins a wallet proxy thread.
pub struct WalletProxyHandle {
	running: Arc<AtomicBool>,
	thread: Option<thread::JoinHandle<Result<(), mwc_wallet_libwallet::Error>>>,
}

impl WalletProxyHandle {
	/// Stop the proxy and wait for its thread to release the chain and LMDB environment.
	pub fn stop(mut self) -> Result<(), mwc_wallet_libwallet::Error> {
		self.stop_and_join()
	}

	fn stop_and_join(&mut self) -> Result<(), mwc_wallet_libwallet::Error> {
		self.running.store(false, Ordering::Release);
		match self.thread.take() {
			Some(thread) => thread.join().map_err(|_| {
				mwc_wallet_libwallet::Error::GenericError(
					"WalletProxyHandle::stop_and_join, wallet proxy thread panicked".to_owned(),
				)
			})?,
			None => Ok(()),
		}
	}
}

impl Drop for WalletProxyHandle {
	fn drop(&mut self) {
		if let Err(e) = self.stop_and_join() {
			error!("Unable to stop wallet proxy thread: {}", e);
		}
	}
}

/// Messages to simulate wallet requests/responses
#[derive(Clone, Debug)]
pub struct WalletProxyMessage {
	/// sender ID
	pub sender_id: String,
	/// destination wallet (or server)
	pub dest: String,
	/// method (like a GET url)
	pub method: String,
	/// payload (json body)
	pub body: String,
}

fn height_range_request_to_json(
	start_height: u64,
	end_height: Option<u64>,
) -> Result<String, serde_json::Error> {
	serde_json::to_string(&(start_height, end_height))
}

fn height_range_request_from_json(
	body: &str,
) -> Result<(u64, Option<u64>), serde_json::Error> {
	serde_json::from_str(body)
}

fn pmmr_output_request_to_json(
	start_index: u64,
	end_index: Option<u64>,
	max_outputs: u64,
) -> Result<String, serde_json::Error> {
	serde_json::to_string(&(start_index, end_index, max_outputs))
}

fn pmmr_output_request_from_json(body: &str) -> Result<(u64, Option<u64>, u64), serde_json::Error> {
	serde_json::from_str(body)
}

fn kernel_request_to_json(
	excess: &str,
	min_height: Option<u64>,
	max_height: Option<u64>,
) -> Result<String, serde_json::Error> {
	serde_json::to_string(&(excess, min_height, max_height))
}

fn kernel_request_from_json(
	body: &str,
) -> Result<(String, Option<u64>, Option<u64>), serde_json::Error> {
	serde_json::from_str(body)
}

fn output_listing_from_json(
	context_id: u32,
	body: &str,
) -> Result<mwc_api::OutputListing, mwc_wallet_libwallet::Error> {
	let value: serde_json::Value = serde_json::from_str(body).map_err(|e| {
		mwc_wallet_libwallet::Error::ClientCallback(format!(
			"Unable to parse output listing response, {}",
			e
		))
	})?;

	let highest_index = value
		.get("highest_index")
		.and_then(|v| v.as_u64())
		.ok_or_else(|| {
			mwc_wallet_libwallet::Error::ClientCallback(
				"Output listing missing highest_index".to_string(),
			)
		})?;
	let last_retrieved_index = value
		.get("last_retrieved_index")
		.and_then(|v| v.as_u64())
		.ok_or_else(|| {
			mwc_wallet_libwallet::Error::ClientCallback(
				"Output listing missing last_retrieved_index".to_string(),
			)
		})?;
	let outputs = value
		.get("outputs")
		.and_then(|v| v.as_array())
		.ok_or_else(|| {
			mwc_wallet_libwallet::Error::ClientCallback(
				"Output listing missing outputs".to_string(),
			)
		})?
		.iter()
		.map(|output| {
			let output_json = serde_json::to_string(output).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Unable to encode output listing item, {}",
					e
				))
			})?;
			let mut deserializer = serde_json::Deserializer::from_str(&output_json);
			mwc_api::OutputPrintable::deserialize_with_context(context_id, &mut deserializer)
				.map_err(|e| {
					mwc_wallet_libwallet::Error::ClientCallback(format!(
						"Unable to parse output listing item, {}",
						e
					))
				})
		})
		.collect::<Result<Vec<_>, _>>()?;

	Ok(mwc_api::OutputListing {
		last_retrieved_index,
		highest_index,
		outputs,
	})
}

fn block_printables_from_json(
	context_id: u32,
	body: &str,
) -> Result<Vec<mwc_api::BlockPrintable>, mwc_wallet_libwallet::Error> {
	let values: Vec<serde_json::Value> = serde_json::from_str(body).map_err(|e| {
		mwc_wallet_libwallet::Error::ClientCallback(format!(
			"Unable to parse block response, {}",
			e
		))
	})?;

	values
		.into_iter()
		.map(|block| {
			let header = serde_json::from_value(block.get("header").cloned().ok_or_else(|| {
				mwc_wallet_libwallet::Error::ClientCallback(
					"Block response missing header".to_string(),
				)
			})?)
			.map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Unable to parse block header, {}",
					e
				))
			})?;
			let inputs = serde_json::from_value(block.get("inputs").cloned().ok_or_else(|| {
				mwc_wallet_libwallet::Error::ClientCallback(
					"Block response missing inputs".to_string(),
				)
			})?)
			.map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Unable to parse block inputs, {}",
					e
				))
			})?;
			let outputs = block
				.get("outputs")
				.and_then(|v| v.as_array())
				.ok_or_else(|| {
					mwc_wallet_libwallet::Error::ClientCallback(
						"Block response missing outputs".to_string(),
					)
				})?
				.iter()
				.map(|output| {
					let output_json = serde_json::to_string(output).map_err(|e| {
						mwc_wallet_libwallet::Error::ClientCallback(format!(
							"Unable to encode block output, {}",
							e
						))
					})?;
					let mut deserializer = serde_json::Deserializer::from_str(&output_json);
					mwc_api::OutputPrintable::deserialize_with_context(
						context_id,
						&mut deserializer,
					)
					.map_err(|e| {
						mwc_wallet_libwallet::Error::ClientCallback(format!(
							"Unable to parse block output, {}",
							e
						))
					})
				})
				.collect::<Result<Vec<_>, _>>()?;
			let kernels =
				serde_json::from_value(block.get("kernels").cloned().ok_or_else(|| {
					mwc_wallet_libwallet::Error::ClientCallback(
						"Block response missing kernels".to_string(),
					)
				})?)
				.map_err(|e| {
					mwc_wallet_libwallet::Error::ClientCallback(format!(
						"Unable to parse block kernels, {}",
						e
					))
				})?;

			Ok(mwc_api::BlockPrintable {
				header,
				inputs,
				outputs,
				kernels,
			})
		})
		.collect()
}

fn post_tx_response_from_json(body: &str) -> Result<(), mwc_wallet_libwallet::Error> {
	// A successful post_tx handler returns an empty body. The proxy dispatch loop
	// serializes handler failures as a JSON string, which must be propagated to the
	// client rather than mistaken for a successful submission.
	if body.is_empty() {
		return Ok(());
	}

	let error: String = serde_json::from_str(body).map_err(|e| {
		mwc_wallet_libwallet::Error::ClientCallback(format!(
			"Unable to parse post_tx response, {}",
			e
		))
	})?;
	Err(mwc_wallet_libwallet::Error::ClientCallback(format!(
		"post_tx rejected: {}",
		error
	)))
}

/// communicates with a chain instance or other wallet
/// listener APIs via message queues
pub struct WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// directory to create the chain in
	pub chain_dir: String,
	/// handle to chain itself
	pub chain: Arc<Chain>,
	/// list of interested wallets
	pub wallets: HashMap<
		String,
		(
			Sender<WalletProxyMessage>,
			Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
			Option<SecretKey>,
		),
	>,
	/// simulate json send to another client
	/// address, method, payload (simulate HTTP request)
	pub tx: Sender<WalletProxyMessage>,
	/// simulate json receiving
	pub rx: Receiver<WalletProxyMessage>,
	/// queue control
	pub running: Arc<AtomicBool>,

	// transaction pool
	tx_pool: Arc<Mutex<Vec<Transaction>>>,
	// Optional production weight limit for size tests using automated mining.
	max_block_weight: Option<u64>,
}

impl<'a, L, C, K> WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new client that will communicate with the given mwc node
	pub fn new(chain_dir: String, tx_pool: Arc<Mutex<Vec<Transaction>>>) -> Self {
		set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_max_block_weight(None);
		// These are fixture-construction preconditions. Without a secp context,
		// deterministic test genesis, and local Chain, no usable proxy can be
		// returned, so fail immediately at the failed setup step.
		let secp =
			Secp256k1::with_caps(ContextFlag::Commit).expect("secp context initialization failed");
		let genesis_block =
			global::get_genesis_block(&secp, 0).expect("automated testing genesis failed");
		let dir_name = format!("{}/.mwc", chain_dir);
		let c = Chain::init(
			&secp,
			0,
			dir_name,
			Arc::new(NoopAdapter {}),
			genesis_block,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();
		let (tx, rx) = channel();
		WalletProxy {
			chain_dir: chain_dir,
			chain: Arc::new(c),
			tx: tx,
			rx: rx,
			wallets: HashMap::new(),
			running: Arc::new(AtomicBool::new(false)),
			tx_pool,
			max_block_weight: None,
		}
	}

	/// Use the same weight limit on the calling wallet thread and proxy thread.
	/// Mining parameters and the other automated-chain rules stay in effect.
	pub fn with_max_block_weight(mut self, max_block_weight: u64) -> Self {
		global::set_local_max_block_weight(Some(max_block_weight));
		self.max_block_weight = Some(max_block_weight);
		self
	}

	/// Add wallet with a given "address"
	pub fn add_wallet(
		&mut self,
		addr: &str,
		tx: Sender<WalletProxyMessage>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
		keychain_mask: Option<SecretKey>,
	) {
		self.wallets
			.insert(addr.to_owned(), (tx, wallet, keychain_mask));
	}

	pub fn stop(&mut self) {
		self.running.store(false, Ordering::Release);
	}

	/// Start the proxy on a thread that can be stopped and joined.
	pub fn start(mut self) -> WalletProxyHandle
	where
		'a: 'static,
		L: 'static,
		C: 'static,
		K: 'static,
	{
		let running = self.running.clone();
		running.store(true, Ordering::Release);
		let thread = thread::spawn(move || {
			set_local_chain_type(ChainTypes::AutomatedTesting);
			global::set_local_max_block_weight(self.max_block_weight);
			set_local_nrd_enabled(true);
			global::set_local_accept_fee_base(
				mwc_wallet_util::mwc_core::consensus::MILLI_MWC / 100,
			)
			.expect("test fee policy");
			self.run_until_stopped()
		});
		WalletProxyHandle {
			running,
			thread: Some(thread),
		}
	}

	/// Start a shared proxy after its wallets have been populated by another thread.
	pub fn start_shared(proxy: Arc<Mutex<Self>>) -> WalletProxyHandle
	where
		'a: 'static,
		L: 'static,
		C: 'static,
		K: 'static,
	{
		let running = proxy.lock().running.clone();
		running.store(true, Ordering::Release);
		let thread = thread::spawn(move || {
			set_local_chain_type(ChainTypes::AutomatedTesting);
			set_local_nrd_enabled(true);
			global::set_local_accept_fee_base(
				mwc_wallet_util::mwc_core::consensus::MILLI_MWC / 100,
			)
			.expect("test fee policy");
			let mut proxy = proxy.lock();
			global::set_local_max_block_weight(proxy.max_block_weight);
			proxy.run_until_stopped()
		});
		WalletProxyHandle {
			running,
			thread: Some(thread),
		}
	}

	/// Run the incoming message queue and respond more or less
	/// synchronously
	pub fn run(&mut self) -> Result<(), mwc_wallet_libwallet::Error> {
		// We run the wallet_proxy within a spawned thread in tests.
		// We set the local chain_type here within the thread.
		set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_max_block_weight(self.max_block_weight);
		set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(mwc_wallet_util::mwc_core::consensus::MILLI_MWC / 100)
			.expect("test fee policy");
		self.running.store(true, Ordering::Release);
		self.run_until_stopped()
	}

	fn run_until_stopped(&mut self) -> Result<(), mwc_wallet_libwallet::Error> {
		loop {
			thread::sleep(Duration::from_millis(10));
			if !self.running.load(Ordering::Acquire) {
				info!("Proxy stopped");
				return Ok(());
			}

			// read queue
			let m = match self.rx.recv_timeout(Duration::from_millis(10)) {
				Ok(m) => m,
				Err(RecvTimeoutError::Timeout) => continue,
				Err(RecvTimeoutError::Disconnected) => {
					info!("Proxy request channel disconnected");
					return Ok(());
				}
			};
			trace!("Wallet Client Proxy Received: {:?}", m);
			let err_sender_id = m.dest.clone();
			let err_dest = m.sender_id.clone();
			let err_method = m.method.clone();
			// Method names are emitted only by LocalWalletClient below. An unknown
			// selector is therefore a fixture programming error, not remote input.
			let resp = match m.method.as_ref() {
				"get_chain_tip" => self.get_chain_tip(m),
				"get_header_info" => self.get_header_info(m),
				"get_header_by_hash" => self.get_header_by_hash(m),
				"get_output_details_from_node" => self.get_output_details_from_node(m),
				"get_outputs_by_pmmr_index" => self.get_outputs_by_pmmr_index(m),
				"height_range_to_pmmr_indices" => self.height_range_to_pmmr_indices(m),
				"send_tx_slate" => self.send_tx_slate(m),
				"post_tx" => self.post_tx(m),
				"testmempoolaccept" => self.test_mempool_accept(m),
				"get_kernel" => self.get_kernel(m),
				"get_blocks_by_height" => self.get_blocks_by_height(m),
				_ => panic!("Unknown Wallet Proxy Message"),
			};
			let resp = match resp {
				Ok(resp) => resp,
				Err(e) => WalletProxyMessage {
					sender_id: err_sender_id,
					dest: err_dest,
					method: err_method,
					body: serde_json::to_string(&format!("Error: {}", e)).unwrap_or_else(|serr| {
						format!("\"Error serializing proxy error response: {}\"", serr)
					}),
				},
			};

			self.respond(resp);
		}
	}

	/// Return a message to a registered wallet client.
	///
	/// Registration and a live response receiver are invariants of this
	/// in-process fixture. Panicking exposes a broken test topology immediately;
	/// there is no remote peer or production request to recover for.
	/// Each wallet ID has exactly one outstanding request by fixture contract, so
	/// its single response channel deliberately has no per-request correlation ID.
	fn respond(&mut self, m: WalletProxyMessage) {
		if let Some(s) = self.wallets.get_mut(&m.dest) {
			if let Err(e) = s.0.send(m.clone()) {
				panic!("Error sending response from proxy: {:?}, {}", m, e);
			}
		} else {
			panic!("Unknown wallet recipient for response message: {:?}", m);
		}
	}

	fn test_mempool_accept(
		&self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		let request = serde_json::from_str(&m.body)
			.map_err(|e| mwc_wallet_libwallet::Error::Node(e.to_string()))?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let response = self
			.chain
			.test_mempool_accept(&request, &[], &secp)
			.map_err(|e| mwc_wallet_libwallet::Error::Node(e.to_string()))?;
		Ok(WalletProxyMessage {
			sender_id: "node".into(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&response)
				.map_err(|e| mwc_wallet_libwallet::Error::Node(e.to_string()))?,
		})
	}

	/// post transaction to the chain (and mine it, taking the reward)
	fn post_tx(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		let tx: Transaction = serde_json::from_str(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Error parsing Transaction, {}", e))
		})?;

		self.tx_pool.lock().push(tx);

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: "".to_owned(),
		})
	}

	/// send tx slate
	fn send_tx_slate(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		let slate: SlateV3 = serde_json::from_str(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Error parsing Transaction, {}", e))
		})?;
		let slate = slate.to_slate(Some(global::get_network_name(0)), false)?;
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;

		// The in-process proxy knows which registered wallet submitted the
		// request. Model an authenticated test transport by resolving that wallet's
		// MQS key independently instead of trusting the address carried by the
		// slate. Production transports must establish this identity themselves.
		let authenticated_sender = if slate.payment_proof.is_some() {
			let (_, sender_wallet, sender_mask) = self.wallets.get(&m.sender_id).ok_or_else(|| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Unknown wallet sender for send_tx_slate: {}",
					m.sender_id
				))
			})?;
			let mut sender_lock = sender_wallet.lock();
			let sender = sender_lock.lc_provider()?.wallet_inst()?;
			let keychain = sender.keychain(&secp, sender_mask.as_ref())?;
			let address_index: u32 = {
				let mut batch = sender.batch(&secp, sender_mask.as_ref())?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					mwc_wallet_libwallet::Error::DataOverflow(format!(
						"WalletProxy::send_tx_slate, address index exceeds u32, index={} error={}",
						index, e
					))
				})?
			};
			Some(proofaddress::payment_proof_address_pubkey(
				&secp,
				sender.get_context_id(),
				&keychain,
				address_index,
			)?)
		} else {
			None
		};

		let dest_wallet = self.wallets.get_mut(&m.dest);
		// LocalWalletClient can address only wallets registered in this fixture.
		// An unknown destination means the test topology was assembled incorrectly.
		let wallet = match dest_wallet {
			None => panic!("Unknown wallet destination for send_tx_slate: {:?}", m),
			Some(w) => w,
		};

		let (response_body, receive_data) = {
			let mut w_lock = wallet.1.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			let mask = wallet.2.clone();
			// receive tx
			let mut tx_session = TxSession::new();
			let (slate, receive_data) = match foreign::receive_tx(
				&mut **w,
				&mut secp,
				(&mask).as_ref(),
				&mut tx_session,
				&slate,
				Some(String::from(m.dest.clone())),
				authenticated_sender,
				None,
				&None,
				None,
				#[cfg(feature = "test-support")]
				false,
				false,
			) {
				Err(e) => {
					// Serializing an owned String as JSON is infallible for this in-memory
					// fixture (apart from process-wide allocation failure). Preserve the
					// original receive error as the response.
					return Ok(WalletProxyMessage {
						sender_id: m.dest,
						dest: m.sender_id,
						method: m.method,
						body: serde_json::to_string(&format!("Error: {}", e)).unwrap(),
					});
				}
				Ok((s, _context, receive_data)) => (s, receive_data),
			};
			debug_assert!(tx_session.get_context_participant().is_none());
			let response_body = serde_json::to_string(&SlateV3::from(&SlateCtx {
				slate: slate.clone(),
				network_name: Some(global::get_network_name(0)),
			}))
			.map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Error serializing transaction response, {}",
					e
				))
			})?;
			tx_session.save_tx_data(
				&secp,
				&mut **w,
				(&mask).as_ref(),
				&slate.id,
			)?;
			(response_body, receive_data)
		};

		let response = WalletProxyMessage {
			sender_id: m.dest,
			dest: m.sender_id,
			method: m.method,
			body: response_body,
		};
		foreign::dispatch_receive_callback(receive_data);
		Ok(response)
	}

	// The node-side handlers below consume only the private request format emitted
	// by LocalWalletClient. Their parsing/indexing and response-serialization
	// unwraps intentionally assert that fixture protocol. A malformed request or
	// response value indicates a test programming error, not untrusted network
	// input. Local-chain unwraps likewise expose a broken fixture immediately.

	/// get chain height
	fn get_chain_tip(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// The proxy constructor creates this local chain before any request can be
		// handled. An unreadable head means the fixture is unusable, so fail here.
		// Test mining/chain mutation is serialized between wallet operations by the
		// module contract, so the head cannot change between these fixture reads.
		// Production node handlers obtain and return a coherent tip independently.
		let height = self.chain.head().unwrap().height;
		let hash = self.chain.head().unwrap().last_block_h.to_hex();

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: format!("{},{}", height, hash),
		})
	}

	/// get header hash, version e.t.c
	fn get_header_info(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// LocalWalletClient emits this body from a u64, and its requested fixture
		// height must exist. These unwraps assert those two test-only invariants.
		let height = m.body.parse::<u64>().unwrap();

		let hdr: BlockHeader = self.chain.get_header_by_height(height).unwrap();

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: format!(
				"{},{},{},{},{},{}",
				hdr.height,
				hdr.hash(self.chain.get_context_id())?.to_hex(),
				hdr.version.0,
				hdr.pow.nonce,
				hdr.total_difficulty(),
				hdr.timestamp.to_rfc3339()
			),
		})
	}

	/// Fetch a stored header even if it is outside the selected header chain.
	fn get_header_by_hash(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		let hash = Hash::from_hex(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Invalid header hash, {}", e))
		})?;
		let header = self.chain.get_block_header(&hash).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Get header by hash, {}", e))
		})?;
		let body = serde_json::to_string(&(
			header.height,
			header.hash(self.chain.get_context_id())?.to_hex(),
			header.prev_hash.to_hex(),
		))
		.map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Serialize header by hash, {}", e))
		})?;
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body,
		})
	}

	/// Get API output details.
	fn get_output_details_from_node(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// The matching in-process client encodes validated commitments as hex. A
		// decode or response-serialization failure is a broken fixture protocol.
		let split = m.body.split(',');
		let mut outputs: Vec<mwc_api::Output> = vec![];
		for o in split {
			if o.is_empty() {
				continue;
			}
			let c = mwc_util::from_hex(o).unwrap();
			let commit = Commitment::from_vec(c)?;
			let out = super::get_output_local(&self.chain, commit).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Unable to get output details from chain, {}",
					e
				))
			})?;
			if let Some(output) = out {
				outputs.push(output);
			}
		}
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&outputs).unwrap(),
		})
	}

	/// get api outputs
	fn get_outputs_by_pmmr_index(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// Preserve the Option discriminator so the bounded value Some(0) is not
		// confused with an unbounded request.
		let (start_index, end_index, max) =
			pmmr_output_request_from_json(&m.body).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Error parsing PMMR output request, {}",
					e
				))
			})?;
		let start_index = std::cmp::max(start_index, 1);
		let ol =
			super::get_outputs_by_pmmr_index_local(self.chain.clone(), start_index, end_index, max);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&ol).unwrap(),
		})
	}

	/// get api outputs by height
	fn height_range_to_pmmr_indices(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// Preserve the Option discriminator so the valid height Some(0) is not
		// confused with an unbounded range.
		let (start_height, end_height) = height_range_request_from_json(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Error parsing height range request, {}",
				e
			))
		})?;
		let ol = super::height_range_to_pmmr_indices_local(
			self.chain.clone(),
			start_height,
			end_height,
		);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&ol).unwrap(),
		})
	}

	/// Get blocks by range of heights
	fn get_blocks_by_height(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// The matching client emits an ordered pair of decimal u64 heights. A bad
		// body or unencodable local result is a fixture programming failure.
		let split = m.body.split(",").collect::<Vec<&str>>();
		let start_height = split[0].parse::<u64>().unwrap();
		let end_height = split[1].parse::<u64>().unwrap();
		debug_assert!(start_height <= end_height);

		let ol = super::get_blocks_by_height_local(self.chain.clone(), start_height, end_height);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&ol).unwrap(),
		})
	}

	/// get kernel
	fn get_kernel(
		&self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, mwc_wallet_libwallet::Error> {
		// Preserve each Option discriminator so the valid height Some(0) is not
		// confused with an unbounded range.
		let (excess, min, max) = kernel_request_from_json(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Error parsing kernel request, {}",
				e
			))
		})?;
		let commit_bytes = mwc_util::from_hex(&excess).unwrap();
		let commit = pedersen::Commitment::from_vec(commit_bytes)?;
		let k = super::get_kernel_local(self.chain.clone(), &commit, min, max);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&k).unwrap(),
		})
	}
}

#[derive(Clone)]
pub struct LocalWalletClient {
	/// wallet identifier for the proxy queue
	pub id: String,
	/// proxy's tx queue (receive messages from other wallets or node
	pub proxy_tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
	/// my rx queue
	pub rx: Arc<Mutex<Receiver<WalletProxyMessage>>>,
	/// my tx queue
	pub tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
}

impl LocalWalletClient {
	/// new
	pub fn new(id: &str, proxy_rx: Sender<WalletProxyMessage>) -> Self {
		let (tx, rx) = channel();
		LocalWalletClient {
			id: id.to_owned(),
			proxy_tx: Arc::new(Mutex::new(proxy_rx)),
			rx: Arc::new(Mutex::new(rx)),
			tx: Arc::new(Mutex::new(tx)),
		}
	}

	/// get an instance of the send queue for other senders
	pub fn get_send_instance(&self) -> Sender<WalletProxyMessage> {
		self.tx.lock().clone()
	}

	/// Send the slate to a listening wallet instance
	pub fn send_tx_slate_direct(
		&self,
		dest: &str,
		slate: &Slate,
	) -> Result<Slate, mwc_wallet_libwallet::Error> {
		let body = serde_json::to_string(&SlateV3::from(&SlateCtx {
			slate: slate.clone(),
			network_name: Some(global::get_network_name(0)),
		}))
		.map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Serialize send_tx_slate request, {}",
				e
			))
		})?;
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: dest.to_owned(),
			method: "send_tx_slate".to_owned(),
			body,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!("Send TX Slate, {}", e))
			})?;
		}
		let r = self.rx.lock();
		let m = r.recv_timeout(Duration::from_secs(60)).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Timed out waiting for send_tx_slate response, {}",
				e
			))
		})?;
		trace!("Received send_tx_slate response: {:?}", m.clone());
		let slate: SlateV3 = serde_json::from_str(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Parsing send_tx_slate response, {}",
				e
			))
		})?;
		Ok(slate.to_slate(Some(global::get_network_name(0)), false)?)
	}
}

impl NodeClient for LocalWalletClient {
	// This implementation is a synchronous in-process test transport. After a
	// request is sent, a disconnected response channel means the WalletProxy
	// fixture has failed and the test cannot continue meaningfully. The matching
	// handlers above construct every response body. Accordingly, recv, parsing,
	// indexing, and serialization unwraps below are deliberate assertions of the
	// fixture protocol; the production HTTP NodeClient does not use this path.
	/*	fn increase_index(&self) {}
	fn node_url(&self) -> Result<String, mwc_wallet_libwallet::Error> {
		Ok("node".to_string())
	}
	fn node_api_secret(&self) -> &Option<String> {
		&None
	}
	fn set_node_url(&mut self, _node_url: Vec<String>) {}*/
	fn set_node_index(&mut self, _node_index: u8) {}
	fn get_node_index(&self) -> u8 {
		0
	}
	//fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {}
	fn reset_cache(&self) {}
	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		None
	}

	fn test_mempool_accept(
		&self,
		request: &mwc_wallet_libwallet::transaction_preflight::MempoolAcceptRequest,
	) -> Result<
		mwc_wallet_libwallet::transaction_preflight::MempoolAcceptResponse,
		mwc_wallet_libwallet::Error,
	> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".into(),
			method: "testmempoolaccept".into(),
			body: serde_json::to_string(request)
				.map_err(|e| mwc_wallet_libwallet::Error::Node(e.to_string()))?,
		};
		self.proxy_tx
			.lock()
			.send(m)
			.map_err(|e| mwc_wallet_libwallet::Error::Node(e.to_string()))?;
		let response = self.rx.lock().recv().unwrap();
		serde_json::from_str(&response.body).map_err(|e| {
			mwc_wallet_libwallet::Error::Node(format!(
				"Preflight response: {} ({})",
				response.body, e
			))
		})
	}

	fn post_tx(
		&self,
		tx: &Transaction,
		_fluff: bool,
		receipt: mwc_wallet_libwallet::transaction_preflight::PreflightReceipt,
	) -> Result<(), mwc_wallet_libwallet::Error> {
		receipt.check(self, tx)?;
		// Transaction serialization and a live proxy response are invariants of this
		// synchronous in-process fixture; either failure makes the test unusable.
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "post_tx".to_owned(),
			body: serde_json::to_string(tx).unwrap(),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!("post_tx send, {}", e))
			})?;
		}
		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		trace!("Received post_tx response: {:?}", m);
		post_tx_response_from_json(&m.body)
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String, u64), mwc_wallet_libwallet::Error> {
		// The registered proxy must reply on its owned channel with the exact
		// "height,hash" format it constructs above. Unwraps assert that invariant.
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_chain_tip".to_owned(),
			body: "".to_owned(),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!("Get chain height send, {}", e))
			})?;
		}
		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		trace!("Received get_chain_tip response: {:?}", m.clone());
		let res = m.body.parse::<String>().map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Parsing get_height response, {}",
				e
			))
		})?;
		let split: Vec<&str> = res.split(",").collect();
		// This test-only client does not model chain-work selection, so total
		// difficulty is intentionally a fixed placeholder. Production node clients
		// return the node's actual total difficulty.
		Ok((split[0].parse::<u64>().unwrap(), split[1].to_owned(), 1))
	}

	/// Return header info by height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, mwc_wallet_libwallet::Error> {
		// The registered proxy must reply on its owned channel with the six fields
		// it constructs above. Parsing and the height assertion fail a broken test
		// protocol at its source rather than accepting inconsistent fixture data.
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_header_info".to_owned(),
			body: format!("{}", height),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get chain header info send, {}",
					e
				))
			})?;
		}
		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		trace!("Received get_header_info response: {:?}", m.clone());
		let res = m.body.parse::<String>().map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Parsing get_header_info response, {}",
				e
			))
		})?;
		let split: Vec<&str> = res.split(",").collect();

		let r_height = split[0].parse::<u64>().unwrap();
		let r_hash = String::from(split[1]);
		let r_version = split[2].parse::<i32>().unwrap();
		let r_nonce = split[3].parse::<u64>().unwrap();
		let r_total_difficulty = split[4].parse::<u64>().unwrap();

		assert!(r_height == height);

		Ok(HeaderInfo {
			height: r_height,
			hash: r_hash,
			confirmed_time: split[5].to_owned(),
			version: r_version,
			nonce: r_nonce,
			total_difficulty: r_total_difficulty,
		})
	}

	fn get_header_by_hash(
		&self,
		hash: &str,
	) -> Result<NodeHeaderLink, mwc_wallet_libwallet::Error> {
		let message = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_owned(),
			method: "get_header_by_hash".to_owned(),
			body: hash.to_owned(),
		};
		self.proxy_tx.lock().send(message).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!("Get header by hash send, {}", e))
		})?;
		let response = self.rx.lock().recv().map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Get header by hash receive, {}",
				e
			))
		})?;
		let (height, returned_hash, previous): (u64, String, String) =
			serde_json::from_str(&response.body).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!("Decode header by hash, {}", e))
			})?;
		if returned_hash != hash {
			return Err(mwc_wallet_libwallet::Error::Node(format!(
				"LocalWalletClient::get_header_by_hash, requested hash {}, received {}",
				hash, returned_hash
			)));
		}
		Ok(NodeHeaderLink {
			height,
			hash: returned_hash,
			previous,
		})
	}

	/// Return Connected peers
	fn get_connected_peer_info(
		&self,
	) -> Result<Vec<PeerInfoDisplayLegacy>, mwc_wallet_libwallet::Error> {
		trace!("get_connected_peer_info called at the test client. Skipped.");
		return Ok(Vec::new());
	}

	/// Retrieve output details from node.
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, NodeOutputDetails>,mwc_wallet_libwallet::Error> {
		// The response channel and JSON body are owned by the matching handler in
		// this fixture. Disconnect or malformed JSON means the proxy test failed.
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| commit.as_ref().to_hex())
			.collect();
		let query_str = query_params.join(",");
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_output_details_from_node".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get outputs from node send, {}",
					e
				))
			})?;
		}
		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		// The matching handler serializes this concrete type from validated fixture
		// data, so malformed JSON is a private-protocol programming failure.
		let outputs: Vec<mwc_api::Output> = serde_json::from_str(&m.body).unwrap();
		let mut api_outputs = HashMap::new();
		for out in outputs {
			api_outputs.insert(
				out.commit.commit(),
				NodeOutputDetails {
					commit: out.commit.to_hex(),
					height: out.height,
					mmr_index: out.mmr_index,
				},
			);
		}
		Ok(api_outputs)
	}

	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, mwc_wallet_libwallet::Error> {
		// Once this in-process request is sent, a response-channel disconnect means
		// the fixture worker failed and there is no meaningful fallback response.
		let excess_hex = excess.0.as_ref().to_hex();
		let query = kernel_request_to_json(&excess_hex, min_height, max_height).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Error serializing kernel request, {}",
				e
			))
		})?;

		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_kernel".to_owned(),
			body: query,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get outputs from node by PMMR index send, {}",
					e
				))
			})?;
		}
		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		let res: Option<LocatedTxKernel> = serde_json::from_str(&m.body).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Get transaction kernels send, {}",
				e
			))
		})?;
		match res {
			Some(k) => Ok(Some((k.tx_kernel, k.height, k.mmr_index))),
			None => Ok(None),
		}
	}

	fn get_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		mwc_wallet_libwallet::Error,
	> {
		// The matching handler owns this synchronous response channel. A disconnect
		// is a fixture failure; response contents themselves are parsed as Results.
		let query_str =
			pmmr_output_request_to_json(start_index, end_index, max_outputs).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Error serializing PMMR output request, {}",
					e
				))
			})?;
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_outputs_by_pmmr_index".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get outputs from node by PMMR index send, {}",
					e
				))
			})?;
		}

		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		let o = output_listing_from_json(0, &m.body)?;

		let mut api_outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)> =
			Vec::new();

		for out in o.outputs {
			let is_coinbase = match out.output_type {
				mwc_api::OutputType::Coinbase => true,
				mwc_api::OutputType::Transaction => false,
			};
			let range_proof = match out.range_proof() {
				Ok(r) => r,
				Err(e) => {
					let msg = format!(
						"Unexpected error in returned output (missing range proof): {:?}. {:?}, {}",
						out.commit, out, e
					);
					return Err(mwc_wallet_libwallet::Error::ClientCallback(msg));
				}
			};
			let block_height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!(
						"Unexpected error in returned output (missing block height): {:?}. {:?}",
						out.commit, out
					);
					return Err(mwc_wallet_libwallet::Error::ClientCallback(msg));
				}
			};
			api_outputs.push((
				out.commit,
				range_proof,
				is_coinbase,
				block_height,
				out.mmr_index,
			));
		}
		Ok((o.highest_index, o.last_retrieved_index, api_outputs))
	}

	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), mwc_wallet_libwallet::Error> {
		// The matching handler owns this synchronous response channel. A disconnect
		// is a fixture failure; response contents themselves are parsed as Results.
		let query_str = height_range_request_to_json(start_height, end_height).map_err(|e| {
			mwc_wallet_libwallet::Error::ClientCallback(format!(
				"Error serializing height range request, {}",
				e
			))
		})?;
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "height_range_to_pmmr_indices".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get outputs within height range send, {}",
					e
				))
			})?;
		}

		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		let o = output_listing_from_json(0, &m.body)?;
		Ok((o.last_retrieved_index, o.highest_index))
	}

	fn get_blocks_by_height(
		&self,
		start_height: u64,
		end_height: u64,
		_threads_number: usize,
	) -> Result<Vec<mwc_api::BlockPrintable>, mwc_wallet_libwallet::Error> {
		// The matching handler owns this synchronous response channel. A disconnect
		// is a fixture failure; response contents themselves are parsed as Results.
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_string(),
			method: "get_blocks_by_height".to_owned(),
			body: format!("{},{}", start_height, end_height),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).map_err(|e| {
				mwc_wallet_libwallet::Error::ClientCallback(format!(
					"Get blocks by height range send, {}",
					e
				))
			})?;
		}

		let r = self.rx.lock();
		// Intentional fail-fast: disconnect means the in-process proxy worker failed.
		let m = r.recv().unwrap();
		block_printables_from_json(0, &m.body)
	}
}
#[cfg(test)]
mod tests {
	use super::{
		height_range_request_from_json, height_range_request_to_json, kernel_request_from_json,
		kernel_request_to_json, pmmr_output_request_from_json, pmmr_output_request_to_json,
		post_tx_response_from_json, WalletProxyHandle,
	};
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;
	use std::thread;

	#[test]
	fn height_range_request_preserves_zero_end_height() {
		let bounded = height_range_request_to_json(0, Some(0)).unwrap();
		let unbounded = height_range_request_to_json(0, None).unwrap();

		assert_ne!(bounded, unbounded);
		assert_eq!(
			height_range_request_from_json(&bounded).unwrap(),
			(0, Some(0))
		);
		assert_eq!(
			height_range_request_from_json(&unbounded).unwrap(),
			(0, None)
		);
	}

	#[test]
	fn pmmr_output_request_preserves_zero_end_index() {
		let bounded = pmmr_output_request_to_json(1, Some(0), 1000).unwrap();
		let unbounded = pmmr_output_request_to_json(1, None, 1000).unwrap();

		assert_ne!(bounded, unbounded);
		assert_eq!(
			pmmr_output_request_from_json(&bounded).unwrap(),
			(1, Some(0), 1000)
		);
		assert_eq!(
			pmmr_output_request_from_json(&unbounded).unwrap(),
			(1, None, 1000)
		);
	}

	#[test]
	fn kernel_request_preserves_zero_height_options() {
		let bounded = kernel_request_to_json("kernel-excess", Some(0), Some(0)).unwrap();
		let unbounded = kernel_request_to_json("kernel-excess", None, None).unwrap();

		assert_ne!(bounded, unbounded);
		assert_eq!(
			kernel_request_from_json(&bounded).unwrap(),
			("kernel-excess".to_owned(), Some(0), Some(0))
		);
		assert_eq!(
			kernel_request_from_json(&unbounded).unwrap(),
			("kernel-excess".to_owned(), None, None)
		);
	}

	#[test]
	fn post_tx_response_propagates_proxy_error() {
		assert!(post_tx_response_from_json("").is_ok());

		let err = post_tx_response_from_json(r#""Error: rejected transaction""#).unwrap_err();
		match err {
			mwc_wallet_libwallet::Error::ClientCallback(message) => {
				assert_eq!(message, "post_tx rejected: Error: rejected transaction");
			}
			other => panic!("unexpected post_tx error: {}", other),
		}
	}

	#[test]
	fn proxy_handle_stops_and_joins_worker() -> Result<(), mwc_wallet_libwallet::Error> {
		let running = Arc::new(AtomicBool::new(true));
		let worker_running = running.clone();
		let exited = Arc::new(AtomicBool::new(false));
		let worker_exited = exited.clone();
		let thread = thread::spawn(move || {
			while worker_running.load(Ordering::Acquire) {
				thread::yield_now();
			}
			worker_exited.store(true, Ordering::Release);
			Ok(())
		});
		let handle = WalletProxyHandle {
			running,
			thread: Some(thread),
		};

		handle.stop()?;
		assert!(exited.load(Ordering::Acquire));
		Ok(())
	}
}
