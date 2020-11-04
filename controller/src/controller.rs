// Copyright 2019 The Grin Developers
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
use crate::api::{self, ApiServer, BasicAuthMiddleware, ResponseFuture, Router, TLSConfig};
use crate::libwallet::{
	NodeClient, NodeVersionInfo, Slate, WalletInst, WalletLCProvider,
	GRIN_BLOCK_HEADER_VERSION,
};
use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, to_base64, Mutex};
use crate::{Error, ErrorKind};
use grin_wallet_api::JsonId;
use grin_wallet_util::OnionV3Address;
use hyper::body;
use hyper::header::HeaderValue;
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;

use grin_wallet_impls::{Address, CloseReason, MWCMQPublisher, MWCMQSAddress, MWCMQSubscriber, Publisher,
						Subscriber, SubscriptionHandler};
use grin_wallet_libwallet::wallet_lock;
use grin_wallet_libwallet::swap::message::Message;
use grin_wallet_util::grin_core::core;

use crate::apiwallet::{
	EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc, OwnerRpcS,
};
use crate::config::{MQSConfig, TorConfig};
use crate::core::global;
use crate::impls::tor::config as tor_config;
use crate::impls::tor::process as tor_process;
use crate::keychain::Keychain;
use easy_jsonrpc_mw::{Handler, MaybeReply};
use grin_wallet_libwallet::proof::crypto;
use grin_wallet_libwallet::proof::proofaddress;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;

lazy_static! {
	pub static ref MWC_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_str("Basic realm=MWC-OwnerAPI").unwrap();

	static ref FOREIGN_API_RUNNING: RwLock<bool> = RwLock::new(false);
	static ref OWNER_API_RUNNING: RwLock<bool> = RwLock::new(false);
	// Current address that is tor is listening on
	static ref TOR_ONION_ADDRESS: RwLock<Option<String>> = RwLock::new(None);
}

pub fn is_foreign_api_running() -> bool {
	*FOREIGN_API_RUNNING.read().unwrap()
}

pub fn is_owner_api_running() -> bool {
	*OWNER_API_RUNNING.read().unwrap()
}

pub fn get_current_tor_address() -> Option<String> {
	(*TOR_ONION_ADDRESS.read().unwrap()).clone()
}

// This function has to use libwallet errots because of callback and runs on libwallet side
fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), crate::libwallet::Error> {
	match name {
		// allow coinbases to be built regardless
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			let mut bhv = 2;
			if let Some(n) = node_version_info {
				bhv = n.block_header_version;
			}
			if let Some(s) = slate {
				if bhv > 3 && s.version_info.block_header_version < GRIN_BLOCK_HEADER_VERSION {
					Err(crate::libwallet::ErrorKind::Compatibility(
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
	let mut w_lock = wallet.lock();
	let lc = w_lock.lc_provider()?;
	let w_inst = lc.wallet_inst()?;
	let k = w_inst.keychain((&mask).as_ref())?;
	let sec_key = proofaddress::payment_proof_address_secret(&k).map_err(|e| {
		ErrorKind::TorConfig(format!("Unable to build key for onion address, {}", e))
	})?;
	let onion_addr = OnionV3Address::from_private(&sec_key.0).map_err(|e| ErrorKind::GenericError(format!("Unable to build Onion address, {}", e)))?;
	Ok(format!("{}", onion_addr))
}

/// initiate the tor listener
pub fn init_tor_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tor_base: Option<&str>,
) -> Result<tor_process::TorProcess, Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	let mut process = tor_process::TorProcess::new();
	let mask = keychain_mask.lock();
	// eventually want to read a list of service config keys
	let mut w_lock = wallet.lock();
	let lc = w_lock.lc_provider()?;
	let w_inst = lc.wallet_inst()?;
	let k = w_inst.keychain((&mask).as_ref())?;
	let tor_dir = if tor_base.is_some() {
		format!("{}/tor/listener", tor_base.unwrap())
	} else {
		format!("{}/tor/listener", lc.get_top_level_directory()?)
	};

	let sec_key = proofaddress::payment_proof_address_secret(&k ).map_err(|e| {
		ErrorKind::TorConfig(format!("Unable to build key for onion address, {}", e))
	})?;
	let onion_address = OnionV3Address::from_private(&sec_key.0)
		.map_err(|e| ErrorKind::TorConfig(format!("Unable to build onion address, {}", e)))?;
	warn!(
		"Starting TOR Hidden Service for API listener at address {}, binding to {}",
		onion_address, addr
	);

	tor_config::output_tor_listener_config(&tor_dir, addr, &vec![sec_key])
		.map_err(|e| ErrorKind::TorConfig(format!("Failed to configure tor, {}", e).into()))?;
	// Start TOR process
	let tor_path = format!("{}/torrc", tor_dir);
	process
		.torrc_path(&tor_path)
		.working_dir(&tor_dir)
		.timeout(200)
		.completion_percent(100)
		.launch()
		.map_err(|e| {
			ErrorKind::TorProcess(format!("Unable to start tor at {}, {}", tor_path, e).into())
		})?;

	TOR_ONION_ADDRESS.write().unwrap().replace( format!("{}", onion_address) );

	Ok(process)
}

/// Instantiate wallet Owner API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn owner_single_use<L, F, C, K>(
	wallet: Option<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>>,
	keychain_mask: Option<&SecretKey>,
	api_context: Option<&mut Owner<L, C, K>>,
	f: F,
) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		F: FnOnce(&mut Owner<L, C, K>, Option<&SecretKey>) -> Result<(), Error>,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	match api_context {
		Some(c) => f(c, keychain_mask)?,
		None => {
			let wallet = match wallet {
				Some(w) => w,
				None => {
					return Err(ErrorKind::GenericError(format!(
						"Instantiated wallet or Owner API context must be provided"
					))
						.into())
				}
			};
			f(&mut Owner::new(wallet, None, None), keychain_mask)?
		}
	}
	Ok(())
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
	keychain_mask: Option<&SecretKey>
) -> Result<SecretKey, Error>
	where
		L: WalletLCProvider<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
{
	wallet_lock!(wallet, w);
	let k = w.keychain(keychain_mask)?;
	let sec_addr_key = proofaddress::payment_proof_address_secret(&k)?;
	Ok(sec_addr_key)
}

#[derive(Clone)]
pub struct Controller<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	/// Wallet instance
	name: String,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,

	publisher: Arc<Mutex<Option<Box<dyn Publisher + Send>>>>,

	// mwc-wallet doesn have this field allways None. we don't want mwc-wallet to be able to process them.
	// Autoinvoice
	max_auto_accept_invoice: Option<u64>,

	slate_send_channel: Arc<Mutex< HashMap< uuid::Uuid, Sender<Slate>>>>,
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
	) -> Self
		where
			L: WalletLCProvider<'static, C, K>,
			C: NodeClient + 'static,
			K: Keychain + 'static,
	{
		if max_auto_accept_invoice.is_some() && global::is_mainnet() {
			panic!("Auto invoicing must be disabled for the mainnet");
		}

		Self {
			name: name.to_string(),
			wallet,
			publisher: Arc::new(Mutex::new(None)),
			max_auto_accept_invoice,
			slate_send_channel: Arc::new(Mutex::new(HashMap::new())),
			keychain_mask,
			print_to_log,
		}
	}

	pub fn clone(&self) -> Self {
		Self {
			name: self.name.clone(),
			wallet: self.wallet.clone(),
			publisher: self.publisher.clone(),
			max_auto_accept_invoice: self.max_auto_accept_invoice.clone(),
			slate_send_channel: self.slate_send_channel.clone(),
			keychain_mask: self.keychain_mask.clone(),
			print_to_log: self.print_to_log,
		}
	}

	pub fn set_publisher(&self, publisher: Box<dyn Publisher + Send>) {
		self.publisher.lock().replace(publisher);
	}

	fn process_incoming_slate(
		&self,
		from: &dyn Address,
		slate: &mut Slate,
		dest_acct_name: Option<&str>,
	) -> Result<(), Error> {
		let owner_api = Owner::new(self.wallet.clone(), None, None);
		let foreign_api = Foreign::new(self.wallet.clone(), None, None);
		let mask = self.keychain_mask.lock().clone();

		if slate.num_participants > slate.participant_data.len() {
			//TODO: this needs to be changed to properly figure out if this slate is an invoice or a send
			if slate.tx.inputs().len() == 0 {
				// mwc-wallet doesn't support invoices
				Err(ErrorKind::DoesNotAcceptInvoices)?;

				// reject by default unless wallet is set to auto accept invoices under a certain threshold

				let max_auto_accept_invoice = self
					.max_auto_accept_invoice
					.ok_or(ErrorKind::DoesNotAcceptInvoices)?;

				if slate.amount > max_auto_accept_invoice {
					Err(ErrorKind::InvoiceAmountTooBig(slate.amount))?;
				}

				if global::is_mainnet() {
					panic!("Auto invoicing must be disabled for the mainnet");
				}

				//create the args
				let params = grin_wallet_libwallet::InitTxArgs {
					src_acct_name: None, //it will be set in the implementation layer.
					amount: slate.amount,
					minimum_confirmations: 10,
					max_outputs: 500,
					num_change_outputs: 1,
					/// If `true`, attempt to use up as many outputs as
					/// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
					/// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
					/// minimizes fees. This will generally result in many inputs and a large change output(s),
					/// usually much larger than the amount being sent. If `false`, the transaction will include
					/// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
					/// value outputs.
					selection_strategy_is_use_all: false,
					message: None,
					/// Optionally set the output target slate version (acceptable
					/// down to the minimum slate version compatible with the current. If `None` the slate
					/// is generated with the latest version.
					target_slate_version: None,
					/// Number of blocks from current after which TX should be ignored
					ttl_blocks: None,
					/// If set, require a payment proof for the particular recipient
					payment_proof_recipient_address: None,
					address: Some(from.get_full_name()),
					/// If true, just return an estimate of the resulting slate, containing fees and amounts
					/// locked without actually locking outputs or creating the transaction. Note if this is set to
					/// 'true', the amount field in the slate will contain the total amount locked, not the provided
					/// transaction amount
					estimate_only: None,
					exclude_change_outputs: Some(false),
					minimum_confirmations_change_outputs: 1,
					/// Sender arguments. If present, the underlying function will also attempt to send the
					/// transaction to a destination and optionally finalize the result
					send_args: None,
					outputs: None,
				};

				*slate = owner_api.process_invoice_tx((&mask).as_ref(), slate, params)?;

				owner_api.tx_lock_outputs((&mask).as_ref(), slate, Some(from.get_full_name()), 1)?;
			} else {
				let s = foreign_api
					.receive_tx(slate, Some(from.get_full_name()), dest_acct_name, None)
					.map_err(|e| {
						ErrorKind::LibWallet(format!(
							"Unable to process incoming slate, receive_tx failed, {}",
							e
						))
					})?;
				*slate = s;
			}

			// Send slate back
			self.publisher
				.lock()
				.as_ref()
				.expect("call set_publisher() method!!!")
				.post_slate(slate, from)
				.map_err(|e| {
					self.do_log_error(format!("ERROR: Unable to send slate back, {}", e));
					e
				})?;

			self.do_log_info(format!(
				"slate [{}] sent back to [{}] successfully",
				slate.id.to_string(),
				from.get_stripped()
			));

			Ok(())
		} else {
			//request may come to here from owner api or send command

			if let Some(slate_sender) = self.slate_send_channel.lock().get(&slate.id) {
				//this happens when the request is from sender. Sender just want have a respond back
				let slate_immutable = slate.clone();
				let _ = slate_sender.send(slate_immutable);
			} else {
				// Report error. We are not processing any finalization transactions if nobody waiting for that
				self.do_log_warn(format!("Get back slate {}. Because slate arrive too late, wallet not processing it", slate.id));
			}

			Ok(())
		}
	}

	fn process_incoming_swap_message(
		&self,
		swapmessage: Message
	) -> Result<Option<Message>, Error> {
		let owner_api = Owner::new(self.wallet.clone(), None, None);
		let mask = self.keychain_mask.lock().clone();

		let msg_str = serde_json::to_string(&swapmessage).map_err(|e| {
			ErrorKind::ProcessSwapMessageError(format!(
				"Error in processing incoming swap message from mqs, {}", e
			))
		})?;
		let ack_msg = owner_api.swap_income_message((&mask).as_ref(), msg_str)?;

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

	fn on_slate(&self, from: &dyn Address, slate: &mut Slate) {
		let display_from = from.get_stripped();

		if slate.num_participants > slate.participant_data.len() {
			let message = &slate.participant_data[0].message;
			if message.is_some() {
				self.do_log_info(format!(
					"slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
					slate.id.to_string(),
					display_from,
					core::amount_to_hr_string(slate.amount, false),
					message.clone().unwrap()
				));
			} else {
				self.do_log_info(format!(
					"slate [{}] received from [{}] for [{}] MWCs.",
					slate.id.to_string(),
					display_from,
					core::amount_to_hr_string(slate.amount, false)
				));
			}
		} else {
			self.do_log_info(format!(
				"slate [{}] received back from [{}] for [{}] MWCs",
				slate.id.to_string(),
				display_from,
				core::amount_to_hr_string(slate.amount, false)
			));
		};

		let result = self
			.process_incoming_slate(from, slate, None);

		//send the message back
		match result {
			Ok(()) => {}
			Err(e) => self.do_log_error(format!("Unable to process incoming slate, {}", e)),
		}
	}

	fn on_swap_message(&self, swap: Message) -> Option<Message> {
		let result = self.process_incoming_swap_message(swap);

		match result {
			Ok(message) => return message,
			Err(e) => { self.do_log_error(format!("{}", e)); None }
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => self.do_log_info(format!("listener [{}] stopped", self.name)),
			CloseReason::Abnormal(_) => self.do_log_error(format!(
				"ERROR: listener [{}] stopped unexpectedly",
				self.name
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
		slate_send_channel: Sender<Slate>,
	) {
		self.slate_send_channel.lock().insert(slate_id.clone(), slate_send_channel);
	}

	fn reset_notification_channels(&self, slate_id: &uuid::Uuid) {
		let _ = self.slate_send_channel.lock().remove(slate_id);
	}
}

pub fn init_start_mwcmqs_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	mqs_config: MQSConfig,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	wait_for_thread: bool,
) -> Result<(MWCMQPublisher, MWCMQSubscriber), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	warn!("Starting MWCMQS Listener");

	//start mwcmqs listener
	start_mwcmqs_listener(
		wallet,
		mqs_config,
		wait_for_thread,
		keychain_mask,
		true,
	)
		.map_err(|e| ErrorKind::GenericError(format!("cannot start mqs listener, {}", e)).into())
}

/// Start the mqs listener
pub fn start_mwcmqs_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	mqs_config: MQSConfig,
	wait_for_thread: bool,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	print_to_log: bool,
) -> Result<(MWCMQPublisher, MWCMQSubscriber), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	if grin_wallet_impls::adapters::get_mwcmqs_brocker().is_some() {
		return Err(ErrorKind::GenericError("mwcmqs listener is already running".to_string()).into());
	}

	// make sure wallet is not locked, if it is try to unlock with no passphrase

	info!(
		"starting mwcmqs listener for {}:{}...",
		mqs_config.mwcmqs_domain, mqs_config.mwcmqs_port
	);
	info!("the addres index is {}... ", proofaddress::get_address_index() );

	let mwcmqs_domain = mqs_config.mwcmqs_domain;
	let mwcmqs_port = mqs_config.mwcmqs_port;

	let mwcmqs_secret_key = controller_derive_address_key(
		wallet.clone(),
		keychain_mask.lock().as_ref(),
	)?;
	let mwc_pub_key = crypto::public_key_from_secret_key(&mwcmqs_secret_key)?;

	let mwcmqs_address = MWCMQSAddress::new(
		proofaddress::ProvableAddress::from_pub_key(&mwc_pub_key),
		Some(mwcmqs_domain.clone()),
		Some(mwcmqs_port),
	);

	let controller = Controller::new(
		&mwcmqs_address.get_stripped(),
		wallet.clone(),
		keychain_mask,
		None,
		print_to_log,
	);

	let mwcmqs_publisher = MWCMQPublisher::new(
		mwcmqs_address.clone(),
		&mwcmqs_secret_key,
		mwcmqs_domain,
		mwcmqs_port,
		print_to_log,
		Box::new(controller.clone()),
	);
	// Cross reference, need to setup the secondary pointer
	controller.set_publisher(Box::new(mwcmqs_publisher.clone()));

	let mwcmqs_subscriber = MWCMQSubscriber::new(&mwcmqs_publisher);

	let mut cloned_subscriber = mwcmqs_subscriber.clone();

	let thread = thread::Builder::new()
		.name("mwcmqs-broker".to_string())
		.spawn(move || {
			if let Err(e) = cloned_subscriber.start() {
				let err_str = format!("Unable to start mwcmqs controller, {}", e);
				error!("{}", err_str);
				panic!("{}", err_str);
			}
		})
		.map_err(|e| ErrorKind::GenericError(format!("Unable to start mwcmqs broker, {}", e)))?;

	// Publishing this running MQS service
	crate::impls::init_mwcmqs_access_data(mwcmqs_publisher.clone(), mwcmqs_subscriber.clone());

	if wait_for_thread {
		let _ = thread.join();
	}

	Ok((mwcmqs_publisher, mwcmqs_subscriber))
}


/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
/// Note keychain mask is only provided here in case the foreign listener is also being used
/// in the same wallet instance
pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<String>,
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

	if *OWNER_API_RUNNING.read().unwrap() {
		return Err( ErrorKind::GenericError("Owner API is already up and running".to_string()).into() );
	}
	if running_foreign && *FOREIGN_API_RUNNING.read().unwrap() {
		return Err( ErrorKind::GenericError("Foreign API is already up and running".to_string()).into() );
	}

	//I don't know why but it seems the warn message in controller.rs will get printed to console.
	warn!("owner listener started {}", addr);
	let mut router = Router::new();
	if api_secret.is_some() {
		let api_basic_auth =
			"Basic ".to_string() + &to_base64(&("mwc:".to_string() + &api_secret.unwrap()));
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth,
			&MWC_OWNER_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}

	let api_handler_v2 = OwnerAPIHandlerV2::new(wallet.clone(), tor_config.clone());
	let api_handler_v3 = OwnerAPIHandlerV3::new(
		wallet.clone(),
		keychain_mask.clone(),
		tor_config,
		running_foreign,
	);

	router
		.add_route("/v2/owner", Arc::new(api_handler_v2))
		.map_err(|e| {
			ErrorKind::GenericError(format!("Router failed to add route /v2/owner, {}", e))
		})?;

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|e| {
			ErrorKind::GenericError(format!("Router failed to add route /v3/owner, {}", e))
		})?;

	// If so configured, add the foreign API to the same port
	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|e| {
				ErrorKind::GenericError(format!("Router failed to add route /v2/foreign, {}", e))
			})?;
	}

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread = apis
		.start(socket_addr, router, tls_config)
		.map_err(|e| ErrorKind::GenericError(format!("API thread failed to start, {}", e)))?;
	warn!("HTTP Owner listener started.");

	*OWNER_API_RUNNING.write().unwrap() = true;
	if running_foreign {
		*FOREIGN_API_RUNNING.write().unwrap() = true;
	}

	let res = api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into());

	*OWNER_API_RUNNING.write().unwrap() = false;
	if running_foreign {
		*FOREIGN_API_RUNNING.write().unwrap() = false;
	}

	res
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
	use_tor: bool,
) -> Result<(), Error>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	if *FOREIGN_API_RUNNING.read().unwrap() {
		return Err( ErrorKind::GenericError("Foreign API is already up and running".to_string()).into() );
	}

	// Check if wallet has been opened first
	{
		let mut w_lock = wallet.lock();
		let lc = w_lock.lc_provider()?;
		let _ = lc.wallet_inst()?;
	}
	// need to keep in scope while the main listener is running
	let _tor_process = match use_tor {
		true => match init_tor_listener(wallet.clone(), keychain_mask.clone(), addr, None) {
			Ok(tp) => Some(tp),
			Err(e) => {
				warn!("Unable to start TOR listener; Check that TOR executable is installed and on your path");
				warn!("Tor Error: {}", e);
				warn!("Listener will be available via HTTP only");
				None
			}
		},
		false => None,
	};

	let api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
	let mut router = Router::new();

	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|e| {
			ErrorKind::GenericError(format!("Router failed to add route /v2/foreign, {}", e))
		})?;

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Foreign listener API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread = apis
		.start(socket_addr, router, tls_config)
		.map_err(|e| ErrorKind::GenericError(format!("API thread failed to start, {}", e)))?;

	warn!("HTTP Foreign listener started.");
	*FOREIGN_API_RUNNING.write().unwrap() = true;

	let res = api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into());

	*FOREIGN_API_RUNNING.write().unwrap() = false;

	res
}

/// V2 API Handler/Wrapper for owner functions
pub struct OwnerAPIHandlerV2<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	pub tor_config: Option<TorConfig>,
}

impl<L, C, K> OwnerAPIHandlerV2<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		tor_config: Option<TorConfig>,
	) -> OwnerAPIHandlerV2<L, C, K> {
		OwnerAPIHandlerV2 { wallet, tor_config }
	}

	async fn call_api(req: Request<Body>, api: Owner<L, C, K>) -> Result<serde_json::Value, Error> {
	let val: serde_json::Value = parse_body(req).await?;
	match OwnerRpc::handle_request(&api, val) {
		MaybeReply::Reply(r) => Ok(r),
		MaybeReply::DontReply => {
			// Since it's http, we need to return something. We return [] because jsonrpc
			// clients will parse it as an empty batch response.
			Ok(serde_json::json!([]))
		}
	}
}

async fn handle_post_request(
	req: Request<Body>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	tor_config: Option<TorConfig>,
) -> Result<Response<Body>, Error> {
	let api = Owner::new(wallet, None, tor_config);

	//Here is a wrapper to call future from that.
	// Issue that we can't call future form future
	let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
		let future = Self::call_api(req, api);
		Box::pin(future)
	};
	let res = crate::executor::RunHandlerInThread::new(handler).await?;

	Ok(json_response_pretty(&res))
}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV2<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let wallet = self.wallet.clone();
		let tor_config = self.tor_config.clone();
		Box::pin(async move {
			match Self::handle_post_request(req, wallet, tor_config).await {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
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
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,

	/// Keychain mask (to change if also running the foreign API)
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,

	/// Whether we're running the foreign API on the same port, and therefore
	/// have to store the mask in-process
	pub running_foreign: bool,
}

pub struct OwnerV3Helpers;

impl OwnerV3Helpers {
	/// Checks whether a request is to init the secure API
	pub fn is_init_secure_api(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"init_secure_api" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is to open the wallet
	pub fn is_open_wallet(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"open_wallet" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is an encrypted request
	pub fn is_encrypted_request(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"encrypted_request_v3" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// whether encryption is enabled
	pub fn encryption_enabled(key: Arc<Mutex<Option<SecretKey>>>) -> bool {
		let share_key_ref = key.lock();
		share_key_ref.is_some()
	}

	/// If incoming is an encrypted request, check there is a shared key,
	/// Otherwise return an error value
	pub fn check_encryption_started(
		key: Arc<Mutex<Option<SecretKey>>>,
	) -> Result<(), serde_json::Value> {
		match OwnerV3Helpers::encryption_enabled(key) {
			true => Ok(()),
			false => Err(EncryptionErrorResponse::new(
				1,
				-32001,
				"Encryption must be enabled. Please call 'init_secure_api` first",
			)
				.as_json_value()),
		}
	}

	/// Update the statically held owner API shared key
	pub fn update_owner_api_shared_key(
		key: Arc<Mutex<Option<SecretKey>>>,
		val: &serde_json::Value,
		new_key: Option<SecretKey>,
	) {
		if let Some(_) = val["result"]["Ok"].as_str() {
			let mut share_key_ref = key.lock();
			*share_key_ref = new_key;
		}
	}

	/// Update the shared mask, in case of foreign API being run
	pub fn update_mask(mask: Arc<Mutex<Option<SecretKey>>>, val: &serde_json::Value) {
		if let Some(key) = val["result"]["Ok"].as_str() {
			let key_bytes = match from_hex(key) {
				Ok(k) => k,
				Err(_) => return,
			};
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			let sk = match SecretKey::from_slice(&secp, &key_bytes) {
				Ok(s) => s,
				Err(_) => return,
			};

			let mut shared_mask_ref = mask.lock();
			*shared_mask_ref = Some(sk);
		}
	}

	/// Decrypt an encrypted request
	pub fn decrypt_request(
		key: Arc<Mutex<Option<SecretKey>>>,
		req: &serde_json::Value,
	) -> Result<(JsonId, serde_json::Value), serde_json::Value> {
		let share_key_ref = key.lock();
		if share_key_ref.is_none() {
			return Err(EncryptionErrorResponse::new(
				1,
				-32002,
				"Encrypted request internal error",
			)
				.as_json_value());
		}
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_req: EncryptedRequest = serde_json::from_value(req.clone()).map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted request format error: {}", e),
			)
				.as_json_value()
		})?;
		let id = enc_req.id.clone();
		let res = enc_req.decrypt(&shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Decryption error: {}", e.kind()))
				.as_json_value()
		})?;
		Ok((id, res))
	}

	/// Encrypt a response
	pub fn encrypt_response(
		key: Arc<Mutex<Option<SecretKey>>>,
		id: &JsonId,
		res: &serde_json::Value,
	) -> Result<serde_json::Value, serde_json::Value> {
		let share_key_ref = key.lock();
		if share_key_ref.is_none() {
			return Err(EncryptionErrorResponse::new(
				1,
				-32002,
				"Encrypted response internal error",
			)
				.as_json_value());
		}
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_res = EncryptedResponse::from_json(id, res, &shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32003, &format!("Encryption Error: {}", e.kind()))
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

	/// convert an internal error (if exists) as proper JSON-RPC
	pub fn check_error_response(val: &serde_json::Value) -> (bool, serde_json::Value) {
		// check for string first. This ensures that error messages
		// that are just strings aren't given weird formatting
		let err_string = if val["result"]["Err"].is_object() {
			let mut retval;
			let hashed: Result<HashMap<String, String>, serde_json::Error> =
				serde_json::from_value(val["result"]["Err"].clone());
			retval = match hashed {
				Err(e) => {
					debug!("Can't cast value to Hashmap<String> {}", e);
					None
				}
				Ok(h) => {
					let mut r = "".to_owned();
					for (k, v) in h.iter() {
						r = format!("{}: {}", k, v);
					}
					Some(r)
				}
			};
			// Otherwise, see if error message is a map that needs
			// to be stringified (and accept weird formatting)
			if retval.is_none() {
				let hashed: Result<HashMap<String, serde_json::Value>, serde_json::Error> =
					serde_json::from_value(val["result"]["Err"].clone());
				retval = match hashed {
					Err(e) => {
						debug!("Can't cast value to Hashmap<Value> {}", e);
						None
					}
					Ok(h) => {
						let mut r = "".to_owned();
						for (k, v) in h.iter() {
							r = format!("{}: {}", k, v);
						}
						Some(r)
					}
				}
			}
			retval
		} else if val["result"]["Err"].is_string() {
			let parsed = serde_json::from_value::<String>(val["result"]["Err"].clone());
			match parsed {
				Ok(p) => Some(p),
				Err(_) => None,
			}
		} else {
			None
		};
		match err_string {
			Some(s) => {
				return (
					true,
					serde_json::json!({
						"jsonrpc": "2.0",
						"id": val["id"],
						"error": {
							"message": s,
							"code": -32099
						}
					}),
				)
			}
			None => (false, val.clone()),
		}
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
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		tor_config: Option<TorConfig>,
		running_foreign: bool,
	) -> OwnerAPIHandlerV3<L, C, K> {
		let owner_api = Owner::new(wallet.clone(), None, tor_config.clone());
		owner_api.set_tor_config(tor_config);
		let owner_api = Arc::new(owner_api);
		OwnerAPIHandlerV3 {
			wallet,
			owner_api,
			shared_key: Arc::new(Mutex::new(None)),
			keychain_mask: keychain_mask,
			running_foreign,
		}
	}

	async fn call_api(
	req: Request<Body>,
	key: Arc<Mutex<Option<SecretKey>>>,
	mask: Arc<Mutex<Option<SecretKey>>>,
	running_foreign: bool,
	api: Arc<Owner<L, C, K>>,
) -> Result<serde_json::Value, Error> {
	let mut val: serde_json::Value = parse_body(req).await?;
	let mut is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
	let mut was_encrypted = false;
	let mut encrypted_req_id = JsonId::StrId(String::from(""));
	if !is_init_secure_api {
		if let Err(v) = OwnerV3Helpers::check_encryption_started(key.clone()) {
			return Ok(v);
		}
		let res = OwnerV3Helpers::decrypt_request(key.clone(), &val);
		match res {
			Err(e) => return Ok(e),
			Ok(v) => {
				encrypted_req_id = v.0.clone();
				val = v.1;
			}
		}
		was_encrypted = true;
	}
	// check again, in case it was an encrypted call to init_secure_api
	is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
	// also need to intercept open/close wallet requests
	let is_open_wallet = OwnerV3Helpers::is_open_wallet(&val);
	match OwnerRpcS::handle_request(&*api, val) {
		MaybeReply::Reply(mut r) => {
			let (_was_error, unencrypted_intercept) =
				OwnerV3Helpers::check_error_response(&r.clone());
			if is_open_wallet && running_foreign {
				OwnerV3Helpers::update_mask(mask, &r.clone());
			}
			if was_encrypted {
				let res = OwnerV3Helpers::encrypt_response(
					key.clone(),
					&encrypted_req_id,
					&unencrypted_intercept,
				);
				r = match res {
					Ok(v) => v,
					Err(v) => return Ok(v),
				}
			}
			// intercept init_secure_api response (after encryption,
			// in case it was an encrypted call to 'init_api_secure')
			if is_init_secure_api {
				OwnerV3Helpers::update_owner_api_shared_key(
					key.clone(),
					&unencrypted_intercept,
					api.shared_key.lock().clone(),
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
}

	async fn handle_post_request(
	req: Request<Body>,
	key: Arc<Mutex<Option<SecretKey>>>,
	mask: Arc<Mutex<Option<SecretKey>>>,
	running_foreign: bool,
	api: Arc<Owner<L, C, K>>,
) -> Result<Response<Body>, Error> {
	//Here is a wrapper to call future from that.
	// Issue that we can't call future form future
	let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
		let future = Self::call_api(req, key, mask, running_foreign, api);
		Box::pin(future)
	};
	let res = crate::executor::RunHandlerInThread::new(handler).await?;

	//let res = Self::call_api(req, key, mask, running_foreign, api).await?;
	Ok(json_response_pretty(&res))
}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV3<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		let api = self.owner_api.clone();

		Box::pin(async move {
			match Self::handle_post_request(req, key, mask, running_foreign, api).await {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
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
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			keychain_mask,
		}
	}

	async fn call_api(
	req: Request<Body>,
	api: Foreign<'static, L, C, K>,
) -> Result<serde_json::Value, Error> {
	let val: serde_json::Value = parse_body(req).await?;
	match ForeignRpc::handle_request(&api, val) {
		MaybeReply::Reply(r) => Ok(r),
		MaybeReply::DontReply => {
			// Since it's http, we need to return something. We return [] because jsonrpc
			// clients will parse it as an empty batch response.
			Ok(serde_json::json!([]))
		}
	}
}

async fn handle_post_request(
	req: Request<Body>,
	mask: Option<SecretKey>,
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
) -> Result<Response<Body>, Error> {
	let api = Foreign::new(wallet, mask, Some(check_middleware));

	//Here is a wrapper to call future from that.
	// Issue that we can't call future form future
	let handler = move || -> Pin<Box<dyn std::future::Future<Output=Result<serde_json::Value, Error>>>> {
		let future = Self::call_api(req, api);
		Box::pin(future)
	};
	let res = crate::executor::RunHandlerInThread::new(handler).await?;
	Ok(json_response_pretty(&res))
}
}

impl<L, C, K> api::Handler for ForeignAPIHandlerV2<L, C, K>
	where
		L: WalletLCProvider<'static, C, K> + 'static,
		C: NodeClient + 'static,
		K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let mask = self.keychain_mask.lock().clone();
		let wallet = self.wallet.clone();

		Box::pin(async move {
			match Self::handle_post_request(req, mask, wallet).await {
				Ok(v) => Ok(v),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}

// Utility to serialize a struct into JSON and produce a sensible Response
// out of it.
fn _json_response<T>(s: &T) -> Response<Body>
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
fn json_response_pretty<T>(s: &T) -> Response<Body>
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

fn create_error_response(e: Error) -> Response<Body> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(format!("{}", e).into())
		.unwrap()
}

fn create_ok_response(json: &str) -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(json.to_string().into())
		.unwrap()
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
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

	builder.body(text.into()).unwrap()
}

async fn parse_body<T>(req: Request<Body>) -> Result<T, Error>
	where
			for<'de> T: Deserialize<'de> + Send + 'static,
{
	let body = body::to_bytes(req.into_body())
		.await
		.map_err(|e| ErrorKind::GenericError(format!("Failed to read request, {}", e)))?;

	serde_json::from_reader(&body[..])
		.map_err(|e| ErrorKind::GenericError(format!("Invalid request body, {}", e)).into())
}
