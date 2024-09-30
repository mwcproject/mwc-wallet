// Copyright 2021 The Grin Developers
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

//! Owner API External Definition

use chrono::prelude::*;
use ed25519_dalek::PublicKey as DalekPublicKey;
use uuid::Uuid;

use crate::config::{MQSConfig, TorConfig, WalletConfig};
use crate::core::core::OutputFeatures;
use crate::core::core::Transaction;
use crate::core::global;
use crate::impls::create_sender;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner_updater::{start_updater_log_thread, StatusMessage};
use crate::libwallet::api_impl::{owner, owner_eth, owner_swap, owner_updater};
use crate::libwallet::proof::proofaddress;
use crate::libwallet::proof::tx_proof::TxProof;
use crate::libwallet::swap::fsm::state::{StateEtaInfo, StateId, StateProcessRespond};
use crate::libwallet::swap::types::{Action, Currency, SwapTransactionsConfirmations};
use crate::libwallet::swap::{message::Message, swap::Swap, swap::SwapJournalRecord};
use crate::libwallet::{
	AcctPathMapping, BuiltOutput, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeHeightResult, OutputCommitMapping, PaymentProof, Slate, SlatePurpose, SlateVersion,
	SwapStartArgs, TxLogEntry, VersionedSlate, ViewWallet, WalletInfo, WalletInst,
	WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, Mutex, ZeroingString};
use grin_wallet_util::grin_util::secp::key::PublicKey;
use grin_wallet_util::grin_util::static_secp_instance;
use libwallet::{OwnershipProof, OwnershipProofValidation, RetrieveTxQueryArgs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Main interface into all wallet API functions.
/// Wallet APIs are split into two seperate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// * The 'Owner' API is intended to expose methods that are to be
/// used by the wallet owner only. It is vital that this API is not
/// exposed to anyone other than the owner of the wallet (i.e. the
/// person with access to the seed and password.
///
/// Methods in both APIs are intended to be 'single use', that is to say each
/// method will 'open' the wallet (load the keychain with its master seed), perform
/// its operation, then 'close' the wallet (unloading references to the keychain and master
/// seed).

pub struct Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// contain all methods to manage the wallet
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	/// retail TLD during doctest
	pub doctest_retain_tld: bool,
	/// Share ECDH key
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,
	/// Update thread
	updater: Arc<Mutex<owner_updater::Updater<'static, L, C, K>>>,
	/// Stop state for update thread
	pub updater_running: Arc<AtomicBool>,
	/// Sender for update messages
	status_tx: Mutex<Option<Sender<StatusMessage>>>,
	/// Holds all update and status messages returned by the
	/// updater process
	updater_messages: Arc<Mutex<Vec<StatusMessage>>>,
	/// Optional TOR configuration, holding address of sender and
	/// data directory
	tor_config: Mutex<Option<TorConfig>>,

	/// updater log thread. Expected to be removed at next rebase
	updater_log_thread: Option<JoinHandle<()>>,
	// Atomic to stop the thread
	updater_log_running_state: Arc<AtomicBool>,
}

// Owner need to release the resources. We have a thread that is running in background
impl<L, C, K> Drop for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient,
	K: Keychain,
{
	/// We have a start_updater_log_thread running in the background.
	/// We neeed to stop it on the exit. Note, we don't like this design but it is how
	/// grin implement it. We are keeping it with smaller number of changes and
	/// really hope to get a better solution with a next fix
	fn drop(&mut self) {
		if let Some(thr_info) = self.updater_log_thread.take() {
			self.updater_log_running_state
				.store(false, Ordering::Relaxed);
			let _ = thr_info.join();
		}
	}
}

impl<L, C, K> Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient,
	K: Keychain,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed,) perform its operation, then close the keychain
	/// with a call to [`close`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// * `custom_channel` - A custom MPSC Tx/Rx pair to capture status
	/// updates
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use grin_wallet_util::grin_keychain as keychain;
	/// use grin_wallet_util::grin_util as util;
	/// use grin_wallet_util::grin_core;
	/// use grin_wallet_api as api;
	/// use grin_wallet_config as config;
	/// use grin_wallet_impls as impls;
	/// use grin_wallet_libwallet as libwallet;
	///
	/// use grin_core::global;
	/// use keychain::ExtKeychain;
	/// use tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use util::{Mutex, ZeroingString};
	///
	/// use api::Owner;
	/// use config::WalletConfig;
	/// use impls::{DefaultWalletImpl, DefaultLCProvider, HTTPNodeClient};
	/// use libwallet::WalletInst;
	/// use config::parse_node_address_string;
	///
	/// global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	///
	/// let mut wallet_config = WalletConfig::default();
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// # wallet_config.data_file_dir = dir.to_owned();
	///
	/// // A NodeClient must first be created to handle communication between
	/// // the wallet and the node.
	/// let node_list = parse_node_address_string(wallet_config.check_node_api_http_addr.clone());
	/// let node_client = HTTPNodeClient::new(node_list, None).unwrap();
	///
	/// // impls::DefaultWalletImpl is provided for convenience in instantiating the wallet
	/// // It contains the LMDBBackend, DefaultLCProvider (lifecycle) and ExtKeychain used
	/// // by the reference wallet implementation.
	/// // These traits can be replaced with alternative implementations if desired
	///
	/// let mut wallet = Box::new(DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap())
	///     as Box<WalletInst<'static, DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>>;
	///
	/// // Wallet LifeCycle Provider provides all functions init wallet and work with seeds, etc...
	/// let lc = wallet.lc_provider().unwrap();
	///
	/// // The top level wallet directory should be set manually (in the reference implementation,
	/// // this is provided in the WalletConfig)
	/// let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	///
	/// // Wallet must be opened with the password (TBD)
	/// let pw = ZeroingString::from("wallet_password");
	/// lc.open_wallet(None, pw, false, false, None);
	///
	/// // All wallet functions operate on an Arc::Mutex to allow multithreading where needed
	/// let mut wallet = Arc::new(Mutex::new(wallet));
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
		custom_channel: Option<Sender<StatusMessage>>,
		tor_config: Option<TorConfig>,
	) -> Self {
		let updater_running = Arc::new(AtomicBool::new(false));
		let updater = Arc::new(Mutex::new(owner_updater::Updater::new(
			wallet_inst.clone(),
			updater_running.clone(),
		)));
		let updater_messages = Arc::new(Mutex::new(vec![]));

		let running = Arc::new(AtomicBool::new(true));
		let (tx, handle) = match custom_channel {
			Some(c) => (c, None),
			None => {
				let (tx, rx) = channel();
				let handle =
					start_updater_log_thread(rx, updater_messages.clone(), running.clone())
						.unwrap();
				(tx, Some(handle))
			}
		};

		Owner {
			wallet_inst,
			doctest_mode: false,
			doctest_retain_tld: false,
			shared_key: Arc::new(Mutex::new(None)),
			updater,
			updater_running,
			status_tx: Mutex::new(Some(tx)),
			updater_messages,
			tor_config: Mutex::new(tor_config),
			updater_log_thread: handle,
			updater_log_running_state: running,
		}
	}

	/// Set the TOR configuration for this instance of the OwnerAPI, used during
	/// `init_send_tx` when send args are present and a TOR address is specified
	///
	/// # Arguments
	/// * `tor_config` - The optional [TorConfig](#) to use
	/// # Returns
	/// * Nothing

	pub fn set_tor_config(&self, tor_config: Option<TorConfig>) {
		let mut lock = self.tor_config.lock();
		*lock = tor_config;
	}

	/// Returns a list of accounts stored in the wallet (i.e. mappings between
	/// user-specified labels and BIP32 derivation paths.
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * Result Containing:
	/// * A Vector of [`AcctPathMapping`](../grin_wallet_libwallet/types/struct.AcctPathMapping.html) data
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * A wallet should always have the path with the label 'default' path defined,
	/// with path m/0/0
	/// * This method does not need to use the wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let result = api_owner.accounts(None);
	///
	/// if let Ok(accts) = result {
	///     //...
	/// }
	/// ```

	pub fn accounts(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Vec<AcctPathMapping>, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::accounts(&mut **w)
	}

	/// Creates a new 'account', which is a mapping of a user-specified
	/// label to a BIP32 path
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `label` - A human readable label to which to map the new BIP32 Path
	///
	/// # Returns
	/// * Result Containing:
	/// * A [Keychain Identifier](../grin_keychain/struct.Identifier.html) for the new path
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallets should be initialised with the 'default' path mapped to `m/0/0`
	/// * Each call to this function will increment the first element of the path
	/// so the first call will create an account at `m/1/0` and the second at
	/// `m/2/0` etc. . .
	/// * The account path is used throughout as the parent key for most key-derivation
	/// operations. See [`set_active_account`](struct.Owner.html#method.set_active_account) for
	/// further details.
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let result = api_owner.create_account_path(None, "account1");
	///
	/// if let Ok(identifier) = result {
	///     //...
	/// }
	/// ```

	pub fn create_account_path(
		&self,
		keychain_mask: Option<&SecretKey>,
		label: &str,
	) -> Result<Identifier, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::create_account_path(&mut **w, keychain_mask, label)
	}

	/// Sets the wallet's currently active account. This sets the
	/// BIP32 parent path used for most key-derivation operations.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `label` - The human readable label for the account. Accounts can be retrieved via
	/// the [`account`](struct.Owner.html#method.accounts) method
	///
	/// # Returns
	/// * Result Containing:
	/// * `Ok(())` if the path was correctly set
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallet parent paths are 2 path elements long, e.g. `m/0/0` is the path
	/// labelled 'default'. Keys derived from this parent path are 3 elements long,
	/// e.g. the secret keys derived from the `m/0/0` path will be  at paths `m/0/0/0`,
	/// `m/0/0/1` etc...
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let result = api_owner.create_account_path(None, "account1");
	///
	/// if let Ok(identifier) = result {
	///     // set the account active
	///     let result2 = api_owner.set_active_account(None, "account1");
	/// }
	/// ```

	pub fn set_active_account(
		&self,
		keychain_mask: Option<&SecretKey>,
		label: &str,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::set_active_account(&mut **w, label)
	}

	/// Returns a list of outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `include_spent` - If `true`, outputs that have been marked as 'spent'
	/// in the wallet will be returned. If `false`, spent outputs will omitted
	/// from the results.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * `(bool, Vec<OutputCommitMapping>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains a vector of
	/// [OutputCommitMapping](../grin_wallet_libwallet/types/struct.OutputCommitMapping.html)
	/// of which each element is a mapping between the wallet's internal
	/// [OutputData](../grin_wallet_libwallet/types/struct.Output.html)
	/// and the Output commitment as identified in the chain's UTXO set
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(None, show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, output_mappings)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_outputs(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			include_spent,
			refresh_from_node,
			tx_id,
		)
	}

	/// Returns a list of [Transaction Log Entries](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)`, only return the transactions associated with
	/// the transaction log entry of id `i`.
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html) uuid.
	/// * `tx_query_args` - If provided, use advanced query arguments as documented in
	/// (../grin_wallet_libwallet/types.struct.RetrieveTxQueryArgs.html). If either
	/// `tx_id` or `tx_slate_id` is provided in the same call, this argument is ignored
	///
	/// # Returns
	/// * `(bool, Vec<TxLogEntry)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the set of retrieved
	/// [TxLogEntries](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id, None);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_txs(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		tx_query_args: Option<RetrieveTxQueryArgs>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		let mut res = owner::retrieve_txs(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			tx_id,
			tx_slate_id,
			tx_query_args,
		)?;
		if self.doctest_mode {
			res.1 = res
				.1
				.into_iter()
				.map(|mut t| {
					t.confirmation_ts = Some(Utc.with_ymd_and_hms(2019, 1, 15, 16, 1, 26).unwrap());
					t.creation_ts = Utc.with_ymd_and_hms(2019, 1, 15, 16, 1, 26).unwrap();
					t
				})
				.collect();
		}
		Ok(res)
	}

	/// Returns summary information from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have before it's included in the 'amount_currently_spendable' total
	///
	/// # Returns
	/// * (`bool`, [`WalletInfo`](../grin_wallet_libwallet/types/struct.WalletInfo.html)) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the Summary [`WalletInfo`](../grin_wallet_libwallet/types/struct.WalletInfo.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let update_from_node = true;
	/// let minimum_confirmations=10;
	///
	/// // Return summary info for active account
	/// let result = api_owner.retrieve_summary_info(None, update_from_node, minimum_confirmations);
	///
	/// if let Ok((was_updated, summary_info)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_summary_info(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_summary_info(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			minimum_confirmations,
		)
	}

	/// Initiates a new transaction as the sender, creating a new
	/// [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html) object containing
	/// the sender's inputs, change outputs, and public signature data. This slate can
	/// then be sent to the recipient to continue the transaction via the
	/// [Foreign API's `receive_tx`](struct.Foreign.html#method.receive_tx) method.
	///
	/// When a transaction is created, the wallet must also lock inputs (and create unconfirmed
	/// outputs) corresponding to the transaction created in the slate, so that the wallet doesn't
	/// attempt to re-spend outputs that are already included in a transaction before the transaction
	/// is confirmed. This method also returns a function that will perform that locking, and it is
	/// up to the caller to decide the best time to call the lock function
	/// (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) method).
	/// If the exchange method is intended to be synchronous (such as via a direct http call,)
	/// then the lock call can wait until the response is confirmed. If it is asynchronous, (such
	/// as via file transfer,) the lock call should happen immediately (before the file is sent
	/// to the recipient).
	///
	/// If the `send_args` [`InitTxSendArgs`](../grin_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../grin_wallet_libwallet/types/struct.InitTxArgs.html), field is Some, this
	/// function will attempt to perform a synchronous send to the recipient specified in the `dest`
	/// field according to the `method` field, and will also finalize and post the transaction if
	/// the `finalize` field is set.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `args` - [`InitTxArgs`](../grin_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * a result containing:
	/// * The transaction [Slate](../grin_wallet_libwallet/slate/struct.Slate.html),
	/// which can be forwarded to the recieving party by any means. Once the caller is relatively
	/// certain that the transaction has been sent to the recipient, the associated wallet
	/// transaction outputs should be locked via a call to
	/// [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs). This must be called before calling
	/// [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method requires an active connection to a node, and will fail with error if a node
	/// cannot be contacted to refresh output statuses.
	/// * This method will store a partially completed transaction in the wallet's transaction log,
	/// which will be updated on the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	///
	/// # Example
	/// Set up as in [new](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// // Attempt to create a transaction using the 'default' account
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 2,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Have some Grins. Love, Yeastplume".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	/// 	// Send slate somehow
	/// 	// ...
	/// 	// Lock our outputs if we're happy the slate was (or is being) sent
	/// 	api_owner.tx_lock_outputs(None, &slate, None, 0);
	/// }
	/// ```

	pub fn init_send_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		args: &InitTxArgs,
		routputs: usize, // Number of resulting outputs. Normally it is 1
	) -> Result<Slate, Error> {
		let address = args.address.clone();

		owner::update_wallet_state(self.wallet_inst.clone(), keychain_mask, &None)?;
		let send_args = args.send_args.clone();
		//minimum_confirmations cannot be zero.
		let minimum_confirmations = args.minimum_confirmations.clone();
		if minimum_confirmations < 1 {
			return Err(Error::ClientCallback(
				"Minimum_confirmations can not be smaller than 1".to_owned(),
			));
		}

		match args.send_args.clone() {
			Some(sa) => {
				if sa.post_tx && !sa.finalize {
					return Err(Error::ClientCallback(
						"Transcations can not be posted without being finalized!".to_owned(),
					));
				}
			}
			None => {}
		}

		let mut recipient: Option<DalekPublicKey> = None;
		if let Some(r) = &args.slatepack_recipient {
			recipient = Some(r.tor_public_key()?);
		}

		let mut args = args.clone();

		// Creating sender ahead because of slatepacks. We need to know the another wallet version so
		// we can decide on the slate format (compact slate or not)
		let sender_info = if let Some(sa) = &send_args {
			match sa.method.as_ref() {
				"http" | "mwcmqs" => {
					let tor_config_lock = self.tor_config.lock();
					let comm_adapter =
						create_sender(&sa.method, &sa.dest, &sa.apisecret, tor_config_lock.clone())
							.map_err(|e| {
								Error::GenericError(format!("Unable to create a sender, {}", e))
							})?;

					let other_wallet_version = comm_adapter
						.check_other_wallet_version(&sa.dest, true)
						.map_err(|e| {
							Error::GenericError(format!("Unable to get other wallet info, {}", e))
						})?;

					if let Some(other_wallet_version) = &other_wallet_version {
						if args.target_slate_version.is_none() {
							args.target_slate_version =
								Some(other_wallet_version.0.to_numeric_version() as u16);
						}
					}
					Some((comm_adapter, other_wallet_version))
				}
				_ => None,
			}
		} else {
			None
		};

		let mut slate = {
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			owner::init_send_tx(&mut **w, keychain_mask, &args, self.doctest_mode, routputs)?
		};

		match send_args {
			Some(sa) => {
				let original_slate = slate.clone();

				match sender_info {
					Some((sender, other_wallet_info)) => {
						let (slatepack_secret, height, secp) = {
							let mut w_lock = self.wallet_inst.lock();
							let w = w_lock.lc_provider()?.wallet_inst()?;
							let keychain = w.keychain(keychain_mask)?;
							let (height, _, _) = w.w2n_client().get_chain_tip()?;
							let slatepack_secret =
								proofaddress::payment_proof_address_dalek_secret(&keychain, None)?;
							(slatepack_secret, height, keychain.secp().clone())
						};

						slate = sender
							.send_tx(
								true,
								&slate,
								SlatePurpose::SendInitial,
								&slatepack_secret,
								recipient,
								other_wallet_info,
								height,
								&secp,
							)
							.map_err(|e| {
								Error::ClientCallback(format!(
									"Unable to send slate {} with {}, {}",
									slate.id, sa.method, e
								))
							})?;
					}
					None => {
						error!("unsupported payment method: {}", sa.method);
						return Err(Error::ClientCallback(
							"unsupported payment method".to_owned(),
						));
					}
				};

				// Restore back ttl, because it can be gone
				slate.ttl_cutoff_height = original_slate.ttl_cutoff_height.clone();
				// Checking is sender didn't do any harm to slate
				Slate::compare_slates_send(&original_slate, &slate)?;

				self.verify_slate_messages(keychain_mask, &slate)
					.map_err(|e| {
						error!(
							"Unable to validate participant messages at slate {}: {}",
							slate.id, e
						);
						e
					})?;

				self.tx_lock_outputs(keychain_mask, &slate, address, 0)?;
				slate = match sa.finalize {
					true => self.finalize_tx(keychain_mask, &slate)?,
					false => slate,
				};
				println!(
					"slate [{}] finalized successfully in owner_api",
					slate.id.to_string()
				);

				if sa.post_tx {
					self.post_tx(keychain_mask, slate.tx_or_err()?, sa.fluff)?;
				}
				println!(
					"slate [{}] posted successfully in owner_api",
					slate.id.to_string()
				);
				Ok(slate)
			}
			None => Ok(slate),
		}
	}

	/// Issues a new invoice transaction slate, essentially a `request for payment`.
	/// The slate created by this function will contain the amount, an output for the amount,
	/// as well as round 1 of singature creation complete. The slate should then be send
	/// to the payer, who should add their inputs and signature data and return the slate
	/// via the [Foreign API's `finalize_invoice_tx`](struct.Foreign.html#method.finalize_invoice_tx) method.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `args` - [`IssueInvoiceTxArgs`](../grin_wallet_libwallet/types/struct.IssueInvoiceTxArgs.html),
	/// invoice transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let args = IssueInvoiceTxArgs {
	///     amount: 60_000_000_000,
	///     ..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(None, &args);
	///
	/// if let Ok(slate) = result {
	///     // if okay, send to the payer to add their inputs
	///     // . . .
	/// }
	/// ```
	pub fn issue_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		args: &IssueInvoiceTxArgs,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::issue_invoice_tx(&mut **w, keychain_mask, args, self.doctest_mode, 1)
	}

	/// Processes an invoice tranaction created by another party, essentially
	/// a `request for payment`. The incoming slate should contain a requested
	/// amount, an output created by the invoicer convering the amount, and
	/// part 1 of signature creation completed. This function will add inputs
	/// equalling the amount + fees, as well as perform round 1 and 2 of signature
	/// creation.
	///
	/// Callers should note that no prompting of the user will be done by this function
	/// it is up to the caller to present the request for payment to the user
	/// and verify that payment should go ahead.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
	/// * `args` - [`InitTxArgs`](../grin_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// // . . .
	/// // The slate has been recieved from the invoicer, somehow
	/// # let slate = Slate::blank(2, false);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: slate.amount,
	///     minimum_confirmations: 2,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	///
	/// let result = api_owner.process_invoice_tx(None, &slate, &args);
	///
	/// if let Ok(slate) = result {
	/// // If result okay, send back to the invoicer
	/// // . . .
	/// }
	/// ```

	pub fn process_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		args: &InitTxArgs,
	) -> Result<Slate, Error> {
		owner::update_wallet_state(self.wallet_inst.clone(), keychain_mask, &None)?;

		//minimum_confirmations cannot be zero.
		let minimum_confirmations = args.minimum_confirmations.clone();
		if minimum_confirmations < 1 {
			return Err(Error::ClientCallback(
				"minimum_confirmations can not smaller than 1".to_owned(),
			));
		}
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::process_invoice_tx(
			&mut **w,
			keychain_mask,
			slate,
			args,
			self.doctest_mode,
			true,
		)
	}

	/// Locks the outputs associated with the inputs to the transaction in the given
	/// [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html),
	/// making them unavailable for use in further transactions. This function is called
	/// by the sender, (or more generally, all parties who have put inputs into the transaction,)
	/// and must be called before the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx)
	/// that completes the transaction.
	///
	/// Outputs will generally remain locked until they are removed from the chain,
	/// at which point they will become `Spent`. It is commonplace for transactions not to complete
	/// for various reasons over which a particular wallet has no control. For this reason,
	/// [`cancel_tx`](struct.Owner.html#method.cancel_tx) can be used to manually unlock outputs
	/// and return them to the `Unspent` state.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). All
	/// * `participant_id` - The participant id, generally 0 for the party putting in funds, 1 for the
	/// party receiving.
	/// elements in the `input` vector of the `tx` field that are found in the wallet's currently
	/// active account will be set to status `Locked`
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Remember to lock this when we're happy this is sent".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(None, &slate, None, 0);
	/// }
	/// ```

	pub fn tx_lock_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		address: Option<String>,
		participant_id: usize,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::tx_lock_outputs(
			&mut **w,
			keychain_mask,
			slate,
			address,
			participant_id,
			self.doctest_mode,
		)
	}

	/// Finalizes a transaction, after all parties
	/// have filled in both rounds of Slate generation. This step adds
	/// all participants partial signatures to create the final signature,
	/// resulting in a final transaction that is ready to post to a node.
	///
	/// Note that this function DOES NOT POST the transaction to a node
	/// for validation. This is done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	/// Plus it check if proof is available. If it is - it will store it as well.
	/// Currently proffs are generated by MQS only.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). All
	/// participants must have filled in both rounds, and the sender should have locked their
	/// outputs (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) function).
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the new finalized slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Finalize this tx now".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, &slate, None, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(None, &slate);
	/// }
	/// ```

	pub fn finalize_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let (slate_res, _context) =
			owner::finalize_tx(&mut **w, keychain_mask, slate, true, self.doctest_mode)?;

		Ok(slate_res)
	}

	/// Posts a completed transaction to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx` - A completed [`Transaction`](../grin_core/core/transaction/struct.Transaction.html),
	/// typically the `tx` field in the transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	/// * `fluff` - Instruct the node whether to use the Dandelion protocol when posting the
	/// transaction. If `true`, the node should skip the Dandelion phase and broadcast the
	/// transaction to all peers immediately. If `false`, the node will follow dandelion logic and
	/// initiate the stem phase.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Post this tx".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, &slate, None, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(None, &slate);
	///		let res = api_owner.post_tx(None, slate.tx_or_err().unwrap(), true);
	/// }
	/// ```

	pub fn post_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx: &Transaction,
		fluff: bool,
	) -> Result<(), Error> {
		let client = {
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(keychain_mask)?;
			w.w2n_client().clone()
		};
		owner::post_tx(&client, tx, fluff)
	}

	/// Cancels a transaction. This entails:
	/// * Setting the transaction status to either `TxSentCancelled` or `TxReceivedCancelled`
	/// * Deleting all change outputs or recipient outputs associated with the transaction
	/// * Setting the status of all assocatied inputs from `Locked` to `Spent` so they can be
	/// used in new transactions.
	///
	/// Transactions can be cancelled by transaction log id or slate id (call with either set to
	/// Some, not both)
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx_id` - If present, cancel by the [`TxLogEntry`](../grin_wallet_libwallet/types/struct.TxLogEntry.html) id
	/// for the transaction.
	///
	/// * `tx_slate_id` - If present, cancel by the Slate id.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Cancel this tx".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, &slate, None, 0);
	///		//
	///		// We didn't get the slate back, or something else went wrong
	///		//
	///		let res = api_owner.cancel_tx(None, None, Some(slate.id.clone()));
	/// }
	/// ```

	pub fn cancel_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		owner::cancel_tx(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			tx_id,
			tx_slate_id,
		)
	}

	/// Retrieves the stored transaction associated with a TxLogEntry. Can be used even after the
	/// transaction has completed.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx_log_entry` - A [`TxLogEntry`](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Returns
	/// * Ok with the stored  [`Transaction`](../grin_core/core/transaction/struct.Transaction.html)
	/// if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id, None);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///     let stored_tx = api_owner.get_stored_tx(None, &tx_log_entries[0]).unwrap();
	///     //...
	/// }
	/// ```

	// TODO: Should be accepting an id, not an entire entry struct
	pub fn get_stored_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_log_entry: &TxLogEntry,
	) -> Result<Option<Transaction>, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::get_stored_tx(&**w, tx_log_entry)
	}

	/// Loads a stored transaction from a file
	pub fn load_stored_tx(&self, file: &String) -> Result<Transaction, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::load_stored_tx(&**w, file)
	}

	/// Verifies all messages in the slate match their public keys.
	///
	/// The optional messages themselves are part of the `participant_data` field within the slate.
	/// Messages are signed with the same key used to sign for the paricipant's inputs, and can thus be
	/// verified with the public key found in the `public_blind_excess` field. This function is a
	/// simple helper to returns whether all signatures in the participant data match their public
	/// keys.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	///
	/// # Returns
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Just verify messages".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, &slate, None, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.verify_slate_messages(None, &slate);
	/// }
	/// ```
	pub fn verify_slate_messages(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
	) -> Result<(), Error> {
		{
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(keychain_mask)?;
		}
		owner::verify_slate_messages(slate)
	}

	/// Return the rewind hash of the wallet.
	/// The rewind hash when shared, help third-party to retrieve informations (outputs, balance, ...) that belongs to this wallet.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * `Ok(String)` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.scan(
	///     None,
	///     Some(20000),
	///     false,
	/// );
	///
	/// if let Ok(_) = result {
	///     // Wallet outputs should be consistent with what's on chain
	///     // ...
	/// }
	/// ```

	pub fn get_rewind_hash(&self, keychain_mask: Option<&SecretKey>) -> Result<String, Error> {
		owner::get_rewind_hash(self.wallet_inst.clone(), keychain_mask)
	}

	/// Scans the entire UTXO set from the node, identify which outputs belong to the given rewind hash view wallet.
	///
	/// This function can be used to retrieve outputs informations (outputs, balance, ...) from a rewind hash view wallet.
	///
	/// This operation scans the entire chain, and is expected to be time intensive. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// # Arguments
	///
	/// * `rewind_hash` - Rewind hash of a wallet, used to retrieve the output of a third-party wallet.
	/// * `start_height` - If provided, the height of the first block from which to start scanning.
	/// The scan will start from block 1 if this is not provided.
	///
	/// # Returns
	/// * `Ok(ViewWallet)` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.scan(
	///     None,
	///     Some(20000),
	///     false,
	/// );
	///
	/// if let Ok(_) = result {
	///     // Wallet outputs should be consistent with what's on chain
	///     // ...
	/// }
	/// ```

	pub fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		owner::scan_rewind_hash(self.wallet_inst.clone(), rewind_hash, start_height, &tx)
	}

	/// Scans the entire UTXO set from the node, identify which outputs belong to the given wallet
	/// update the wallet state to be consistent with what's currently in the UTXO set.
	///
	/// This function can be used to repair wallet state, particularly by restoring outputs that may
	/// be missing if the wallet owner has cancelled transactions locally that were then successfully
	/// posted to the chain.
	///
	/// This operation scans the entire chain, and is expected to be time intensive. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// When an output is found that doesn't exist in the wallet, a corresponding
	/// [TxLogEntry](../grin_wallet_libwallet/types/struct.TxLogEntry.html) is created.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `start_height` - If provided, the height of the first block from which to start scanning.
	/// The scan will start from block 1 if this is not provided.
	/// * `delete_unconfirmed` - if `false`, the scan process will be non-destructive, and
	/// mostly limited to restoring missing outputs. It will leave unconfirmed transaction logs entries
	/// and unconfirmed outputs intact. If `true`, the process will unlock all locked outputs,
	/// restore all missing outputs, and mark any outputs that have been marked 'Spent' but are still
	/// in the UTXO set as 'Unspent' (as can happen during a fork). It will also attempt to cancel any
	/// transaction log entries associated with any locked outputs or outputs incorrectly marked 'Spent'.
	/// Note this completely removes all outstanding transactions, so users should be very aware what
	/// will happen if this flag is set. Note that if transactions/outputs are removed that later
	/// confirm on the chain, another call to this function will restore them.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.scan(
	///     None,
	///     Some(20000),
	///     false,
	/// );
	///
	/// if let Ok(_) = result {
	///     // Wallet outputs should be consistent with what's on chain
	///     // ...
	/// }
	/// ```

	pub fn scan(
		&self,
		keychain_mask: Option<&SecretKey>,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		owner::scan(
			self.wallet_inst.clone(),
			keychain_mask,
			start_height,
			delete_unconfirmed,
			&tx,
			true,
		)
	}

	/// Dump wallet data (outputs,transactions) into the logs
	pub fn dump_wallet_data(&self, file_name: Option<String>) -> Result<(), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};

		owner::dump_wallet_data(self.wallet_inst.clone(), &tx.unwrap(), file_name)
	}

	/// Retrieves the last known height known by the wallet. This is determined as follows:
	/// * If the wallet can successfully contact its configured node, the reported node
	/// height is returned, and the `updated_from_node` field in the response is `true`
	/// * If the wallet cannot contact the node, this function returns the maximum height
	/// of all outputs contained within the wallet, and the `updated_from_node` fields
	/// in the response is set to false.
	///
	/// Clients should generally ensure the `updated_from_node` field is returned as
	/// `true` before assuming the height for any operation.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * Ok with a  [`NodeHeightResult`](../grin_wallet_libwallet/types/struct.NodeHeightResult.html)
	/// if successful. If the height result was obtained from the configured node,
	/// `updated_from_node` will be set to `true`
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.node_height(None);
	///
	/// if let Ok(node_height_result) = result {
	///     if node_height_result.updated_from_node {
	///          //we can assume node_height_result.height is relatively safe to use
	///
	///     }
	///     //...
	/// }
	/// ```

	pub fn node_height(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<NodeHeightResult, Error> {
		{
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(keychain_mask)?;
		}
		let mut res = owner::node_height(self.wallet_inst.clone(), keychain_mask)?;
		if self.doctest_mode {
			// return a consistent hash for doctest
			res.header_hash =
				"d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d".to_owned();
		}
		Ok(res)
	}

	// LIFECYCLE FUNCTIONS

	/// Retrieve the top-level directory for the wallet. This directory should contain the
	/// `mwc-wallet.toml` file and the `wallet_data` directory that contains the wallet
	/// seed + data files. Future versions of the wallet API will support multiple wallets
	/// within the top level directory.
	///
	/// The top level directory defaults to (in order of precedence):
	///
	/// 1) The current directory, from which `mwc-wallet` or the main process was run, if it
	/// contains a `mwc-wallet.toml` file.
	/// 2) ~/.grin/<chaintype>/ otherwise
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok with a String value representing the full path to the top level wallet dierctory
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.get_top_level_directory();
	///
	/// if let Ok(dir) = result {
	///     println!("Top level directory is: {}", dir);
	///     //...
	/// }
	/// ```

	pub fn get_top_level_directory(&self) -> Result<String, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		if self.doctest_mode && !self.doctest_retain_tld {
			Ok("/doctest/dir".to_owned())
		} else {
			lc.get_top_level_directory()
		}
	}

	/// Set the top-level directory for the wallet. This directory can be empty, and will be created
	/// during a subsequent calls to [`create_config`](struct.Owner.html#method.create_config)
	///
	/// Set [`get_top_level_directory`](struct.Owner.html#method.get_top_level_directory) for a
	/// description of the top level directory and default paths.
	///
	/// # Arguments
	///
	/// * `dir`: The new top-level directory path (either relative to current directory or
	/// absolute.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let result = api_owner.set_top_level_directory(dir);
	///
	/// if let Ok(dir) = result {
	///    //...
	/// }
	/// ```

	pub fn set_top_level_directory(&self, dir: &str) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.set_top_level_directory(dir)
	}

	/// Create a `mwc-wallet.toml` configuration file in the top-level directory for the
	/// specified chain type.
	/// A custom [`WalletConfig`](../grin_wallet_config/types/struct.WalletConfig.html)
	/// and/or grin `LoggingConfig` may optionally be provided, otherwise defaults will be used.
	///
	/// Paths in the configuration file will be updated to reflect the top level directory, so
	/// path-related values in the optional configuration structs will be ignored.
	///
	/// # Arguments
	///
	/// * `chain_type`: The chain type to use in creation of the configuration file. This can be
	///     * `AutomatedTesting`
	///     * `UserTesting`
	///     * `Floonet`
	///     * `Mainnet`
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None, None, None, None );
	///
	/// if let Ok(_) = result {
	///    //...
	/// }
	/// ```

	pub fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		mqs_config: Option<MQSConfig>,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.create_config(
			chain_type,
			"mwc-wallet.toml",
			wallet_config,
			logging_config,
			tor_config,
			mqs_config,
		)
	}

	/// Creates a new wallet seed and empty wallet database in the `wallet_data` directory of
	/// the top level directory.
	///
	/// Paths in the configuration file will be updated to reflect the top level directory, so
	/// path-related values in the optional configuration structs will be ignored.
	///
	/// The wallet files must not already exist, and ~The `mwc-wallet.toml` file must exist
	/// in the top level directory (can be created via a call to
	/// [`create_config`](struct.Owner.html#method.create_config))
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `mnemonic`: If present, restore the wallet seed from the given mnemonic instead of creating
	/// a new random seed.
	/// * `mnemonic_length`: Desired length of mnemonic in bytes (16 or 32, either 12 or 24 words).
	/// Use 0 if mnemonic isn't being used.
	/// * `password`: The password used to encrypt/decrypt the `wallet.seed` file
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // note that the WalletInst struct does not necessarily need to contain an
	/// // instantiated wallet
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet,None,  None, None, None);
	///
	///	// create new wallet wirh random seed
	///	let pw = ZeroingString::from("my_password");
	/// let result = api_owner.create_wallet(None, None, 0, pw, None);
	///
	/// if let Ok(r) = result {
	///     //...
	/// }
	/// ```

	pub fn create_wallet(
		&self,
		name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: u32,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.create_wallet(
			name,
			mnemonic,
			mnemonic_length as usize,
			password,
			self.doctest_mode,
			wallet_data_dir,
		)
	}

	/// `Opens` a wallet, populating the internal keychain with the encrypted seed, and optionally
	/// returning a `keychain_mask` token to the caller to provide in all future calls.
	/// If using a mask, the seed will be stored in-memory XORed against the `keychain_mask`, and
	/// will not be useable if the mask is not provided.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `password`: The password to use to open the wallet
	/// a new random seed.
	/// * `use_mask`: Whether to create and return a mask which much be provided in all future
	/// API calls.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // note that the WalletInst struct does not necessarily need to contain an
	/// // instantiated wallet
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None,  None, None, None);
	///
	///	// create new wallet wirh random seed
	///	let pw = ZeroingString::from("my_password");
	/// let _ = api_owner.create_wallet(None, None, 0, pw.clone(), None);
	///
	/// let result = api_owner.open_wallet(None, pw, true, None);
	///
	/// if let Ok(m) = result {
	///     // use this mask in all subsequent calls
	///     let mask = m;
	/// }
	/// ```

	pub fn open_wallet(
		&self,
		name: Option<&str>,
		password: ZeroingString,
		use_mask: bool,
		wallet_data_dir: Option<&str>,
	) -> Result<Option<SecretKey>, Error> {
		// just return a representative string for doctest mode
		if self.doctest_mode {
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			return Ok(Some(SecretKey::from_slice(
				&secp,
				&from_hex("d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868")
					.unwrap(),
			)?));
		}
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.open_wallet(name, password, use_mask, self.doctest_mode, wallet_data_dir)
	}

	/// `Close` a wallet, removing the master seed from memory.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.close_wallet(None);
	///
	/// if let Ok(_) = res {
	///     // ...
	/// }
	/// ```

	pub fn close_wallet(&self, name: Option<&str>) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.close_wallet(name)
	}

	/// Return the BIP39 mnemonic for the given wallet. This function will decrypt
	/// the wallet's seed file with the given password, and thus does not need the
	/// wallet to be open.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `password`: The password used to encrypt the seed file.
	///
	/// # Returns
	/// * Ok(BIP-39 mneminc) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	///	let pw = ZeroingString::from("my_password");
	/// let res = api_owner.get_mnemonic(None, pw, None);
	///
	/// if let Ok(mne) = res {
	///     // ...
	/// }
	/// ```
	pub fn get_mnemonic(
		&self,
		name: Option<&str>,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<ZeroingString, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.get_mnemonic(name, password, wallet_data_dir)
	}

	/// Changes a wallet's password, meaning the old seed file is decrypted with the old password,
	/// and a new seed file is created with the same mnemonic and encrypted with the new password.
	///
	/// This function temporarily backs up the old seed file until a test-decryption of the new
	/// file is confirmed to contain the same seed as the original seed file, at which point the
	/// backup is deleted. If this operation fails for an unknown reason, the backup file will still
	/// exist in the wallet's data directory encrypted with the old password.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `old`: The password used to encrypt the existing seed file (i.e. old password)
	/// * `new`: The password to be used to encrypt the new seed file
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	///	let old = ZeroingString::from("my_password");
	///	let new = ZeroingString::from("new_password");
	/// let res = api_owner.change_password(None, old, new, None);
	///
	/// if let Ok(mne) = res {
	///     // ...
	/// }
	/// ```
	pub fn change_password(
		&self,
		name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.change_password(name, old, new, wallet_data_dir)
	}

	/// Deletes a wallet, removing the config file, seed file and all data files.
	/// Obviously, use with extreme caution and plenty of user warning
	///
	/// Highly recommended that the wallet be explicitly closed first via the `close_wallet`
	/// function.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.delete_wallet(None);
	///
	/// if let Ok(_) = res {
	///     // ...
	/// }
	/// ```

	pub fn delete_wallet(&self, name: Option<&str>) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.delete_wallet(name)
	}

	/// Starts a background wallet update thread, which performs the wallet update process
	/// automatically at the frequency specified.
	///
	/// The updater process is as follows:
	///
	/// * Reconcile the wallet outputs against the node's current UTXO set, confirming
	/// transactions if needs be.
	/// * Look up transactions by kernel in cases where it's necessary (for instance, when
	/// there are no change outputs for a transaction and transaction status can't be
	/// inferred from the output state.
	/// * Incrementally perform a scan of the UTXO set, correcting outputs and transactions
	/// where their local state differs from what's on-chain. The wallet stores the last
	/// position scanned, and will scan back 100 blocks worth of UTXOs on each update, to
	/// correct any differences due to forks or otherwise.
	///
	/// Note that an update process can take a long time, particularly when the entire
	/// UTXO set is being scanned for correctness. The wallet status can be determined by
	/// calling the [`get_updater_messages`](struct.Owner.html#method.get_updater_messages).
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `frequency`: The frequency at which to call the update process. Note this is
	/// time elapsed since the last successful update process. If calling via the JSON-RPC
	/// api, this represents milliseconds.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	/// ```

	pub fn start_updater(
		&self,
		keychain_mask: Option<&SecretKey>,
		frequency: Duration,
	) -> Result<(), Error> {
		let updater_inner = self.updater.clone();
		let tx_inner = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let keychain_mask = match keychain_mask {
			Some(m) => Some(m.clone()),
			None => None,
		};
		let _ = thread::Builder::new()
			.name("wallet-updater".to_string())
			.spawn(move || {
				let u = updater_inner.lock();
				if let Err(e) = u.run(frequency, keychain_mask, &tx_inner) {
					error!("Wallet state updater failed with error: {}", e);
				}
			})?;
		Ok(())
	}

	/// Stops the background update thread. If the updater is currently updating, the
	/// thread will stop after the next update
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// let res = api_owner.stop_updater();
	/// ```

	pub fn stop_updater(&self) -> Result<(), Error> {
		self.updater_running.store(false, Ordering::Relaxed);
		Ok(())
	}

	/// Retrieve messages from the updater thread, up to `count` number of messages.
	/// The resulting array will be ordered newest messages first. The updater will
	/// store a maximum of 10,000 messages, after which it will start removing the oldest
	/// messages as newer ones are created.
	///
	/// Messages retrieved via this method are removed from the internal queue, so calling
	/// this function at a specified interval should result in a complete message history.
	///
	/// # Arguments
	///
	/// * `count` - The number of messages to retrieve.
	///
	/// # Returns
	/// * Ok with a Vec of [`StatusMessage`](../grin_wallet_libwallet/api_impl/owner_updater/enum.StatusMessage.html)
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// let messages = api_owner.get_updater_messages(10000);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_updater_messages(&self, count: usize) -> Result<Vec<StatusMessage>, Error> {
		let mut q = self.updater_messages.lock();
		let index = q.len().saturating_sub(count);
		Ok(q.split_off(index))
	}

	/// Retrieve the MQS address associated with the wallet. This address can be changed with
	/// address index. In this case it will affect all wallet public addresses
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	///
	/// # Returns
	/// * Ok with a PublicKey that representing the address for MQS
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.get_mqs_address(None);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_mqs_address(&self, keychain_mask: Option<&SecretKey>) -> Result<PublicKey, Error> {
		owner::get_mqs_address(self.wallet_inst.clone(), keychain_mask)
	}

	/// Retrieve the Tor or wallet public address associated with the wallet. This address can be changed with
	/// address index. In this case it will affect all wallet public addresses
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	///
	/// # Returns
	/// * Ok(DalekPublicKey) representing the public key associated with the address, if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the address provided is invalid
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None, None);
	///
	/// let res = api_owner.get_wallet_public_address(None);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_wallet_public_address(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<DalekPublicKey, Error> {
		owner::get_wallet_public_address(self.wallet_inst.clone(), keychain_mask)
	}

	/// Returns a single, exportable [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)
	/// from a completed transaction within the wallet.
	///
	/// The transaction must have been created with a payment proof, and the transaction must be
	/// complete in order for a payment proof to be returned. Either the `tx_id` or `tx_slate_id`
	/// argument must be provided, or the function will return an error.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)` return the proof associated with the transaction with id `i`
	/// * `tx_slate_id` - If `Some(uuid)`, return the proof associated with the transaction with the
	/// given `uuid`
	///
	/// # Returns
	/// * Ok([PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the proof is not present or complete
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap());
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_payment_proof(None, update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok(p) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_payment_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_payment_proof(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
	}

	pub fn get_stored_tx_proof(
		&self,
		_keychain_mask: Option<&SecretKey>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<TxProof, Error> {
		owner::get_stored_tx_proof(self.wallet_inst.clone(), tx_id, tx_slate_id)
	}

	/// Verifies a [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)
	/// This process entails:
	///
	/// * Ensuring the kernel identified by the proof's stored excess commitment exists in the kernel set
	/// * Reproducing the signed message `amount|kernel_commitment|sender_address`
	/// * Validating the proof's `recipient_sig` against the message using the recipient's
	/// address as the public key and
	/// * Validating the proof's `sender_sig` against the message using the senders's
	/// address as the public key
	///
	/// This function also checks whether the sender or recipient address belongs to the currently
	/// open wallet, and returns 2 booleans indicating whether the address belongs to the sender and
	/// whether the address belongs to the recipient respectively
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `proof` A [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html))
	///
	/// # Returns
	/// * Ok((bool, bool)) if the proof is valid. The first boolean indicates whether the sender
	/// address belongs to this wallet, the second whether the recipient address belongs to this
	/// wallet
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the proof is not present or complete
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None, None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap());
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_payment_proof(None, update_from_node, tx_id, tx_slate_id);
	///
	/// // The proof will likely be exported as JSON to be provided to another party
	///
	/// if let Ok(p) = result {
	///     let valid = api_owner.verify_payment_proof(None, &p);
	///     if let Ok(_) = valid {
	///       //...
	///     }
	/// }
	/// ```

	pub fn verify_payment_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		proof: &PaymentProof,
	) -> Result<(bool, bool), Error> {
		owner::verify_payment_proof(self.wallet_inst.clone(), keychain_mask, proof)
	}

	pub fn retrieve_ownership_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		message: String,
		include_public_root_key: bool,
		include_tor_address: bool,
		include_mqs_address: bool,
	) -> Result<OwnershipProof, Error> {
		owner::generate_ownership_proof(
			self.wallet_inst.clone(),
			keychain_mask,
			message,
			include_public_root_key,
			include_tor_address,
			include_mqs_address,
		)
	}

	pub fn validate_ownership_proof(
		&self,
		proof: OwnershipProof,
	) -> Result<OwnershipProofValidation, Error> {
		owner::validate_ownership_proof(proof)
	}

	/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
	pub fn swap_start(
		&self,
		keychain_mask: Option<&SecretKey>,
		params: &SwapStartArgs,
	) -> Result<String, Error> {
		// Updating wallet state first because we need to select outputs.
		owner::update_wallet_state(self.wallet_inst.clone(), keychain_mask, &None)?;
		owner_swap::swap_start(self.wallet_inst.clone(), keychain_mask, params)
			.map_err(|e| e.into())
	}

	pub fn swap_create_from_offer(
		&self,
		keychain_mask: Option<&SecretKey>,
		message_filename: String,
	) -> Result<String, Error> {
		owner_swap::swap_create_from_offer(
			self.wallet_inst.clone(),
			keychain_mask,
			message_filename,
		)
		.map_err(|e| e.into())
	}

	/// List all available swap operations. SwapId & Status
	pub fn swap_list(
		&self,
		keychain_mask: Option<&SecretKey>,
		do_check: bool,
	) -> Result<(Vec<owner_swap::SwapListInfo>, Vec<Swap>), Error> {
		owner_swap::swap_list(self.wallet_inst.clone(), keychain_mask, do_check)
			.map_err(|e| e.into())
	}

	/// Delete swap trade
	pub fn swap_delete(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<(), Error> {
		owner_swap::swap_delete(self.wallet_inst.clone(), keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}
	/// Retrieve swap trade
	pub fn swap_get(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<Swap, Error> {
		owner_swap::swap_get(self.wallet_inst.clone(), keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}

	/// Adjust the sate of swap trade.
	/// method & destination required for adjust_cmd='destination'
	pub fn swap_adjust(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
		adjust_cmd: String,
		method: Option<String>,
		destination: Option<String>,
		secondary_address: Option<String>, // secondary address to adjust
		secondary_fee: Option<f32>,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_infura_project_id: Option<String>,
		tag: Option<String>,
	) -> Result<(StateId, Action), Error> {
		owner_swap::swap_adjust(
			self.wallet_inst.clone(),
			keychain_mask,
			&swap_id,
			&adjust_cmd,
			method,
			destination,
			secondary_address,
			secondary_fee,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_infura_project_id,
			tag,
		)
		.map_err(|e| e.into())
	}

	/// Dump swap file content
	pub fn swap_dump(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<String, Error> {
		owner_swap::swap_dump(self.wallet_inst.clone(), keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}

	/// dump ethereum info
	pub fn eth_info(&self, currency: Currency) -> Result<(String, String, String), Error> {
		owner_eth::info(self.wallet_inst.clone(), currency).map_err(|e| e.into())
	}

	/// ethereum transfer
	pub fn eth_transfer(
		&self,
		dest: Option<String>,
		currency: Currency,
		amount: Option<String>,
	) -> Result<(), libwallet::swap::Error> {
		owner_eth::transfer(self.wallet_inst.clone(), currency, dest, amount)
	}

	/// Refresh and get a status and current expected action for the swap.
	/// return: <state>, <Action>, <time limit>, <Roadmap lines>, <Journal records>, <last error> , <mkt place cancelled trades>
	/// time limit shows when this action will be expired
	pub fn update_swap_status_action(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_swap_contract_address: Option<String>,
		erc20_swap_contract_address: Option<String>,
		eth_infura_project_id: Option<String>,
	) -> Result<
		(
			StateId,
			Action,
			Option<i64>,
			Vec<StateEtaInfo>,
			Vec<SwapJournalRecord>,
			Option<String>,
			Vec<Swap>,
		),
		Error,
	> {
		owner_swap::update_swap_status_action(
			self.wallet_inst.clone(),
			keychain_mask,
			&swap_id,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
			false,
		)
		.map_err(|e| e.into())
	}

	/// Get a status of the transactions that involved into the swap.
	pub fn get_swap_tx_tstatus(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_swap_contract_address: Option<String>,
		erc20_swap_contract_address: Option<String>,
		eth_infura_project_id: Option<String>,
	) -> Result<SwapTransactionsConfirmations, Error> {
		owner_swap::get_swap_tx_tstatus(
			self.wallet_inst.clone(),
			keychain_mask,
			&swap_id,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
		)
		.map_err(|e| e.into())
	}

	pub fn swap_process<F>(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: &str,
		message_sender: F,
		message_file_name: Option<String>,
		buyer_refund_address: Option<String>,
		secondary_fee: Option<f32>,
		secondary_address: Option<String>,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_infura_project_id: Option<String>,
	) -> Result<(StateProcessRespond, Vec<Swap>), Error>
	where
		F: FnOnce(Message, String, String) -> Result<(bool, String), libwallet::swap::Error>
			+ 'static,
	{
		owner_swap::swap_process(
			self.wallet_inst.clone(),
			keychain_mask,
			swap_id,
			message_sender,
			message_file_name,
			buyer_refund_address,
			secondary_fee,
			secondary_address,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_infura_project_id,
			false,
		)
		.map_err(|e| e.into())
	}

	/// Process swap income message
	pub fn swap_income_message(
		&self,
		keychain_mask: Option<&SecretKey>,
		message: String,
	) -> Result<Option<Message>, Error> {
		owner_swap::swap_income_message(self.wallet_inst.clone(), keychain_mask, &message, None)
			.map_err(|e| e.into())
	}

	// decryipt income slate. It is the common routine for most API calls that accept the slates
	// Note, the merge case if not covered by this API.
	pub fn decrypt_versioned_slate(
		&self,
		keychain_mask: Option<&SecretKey>,
		in_slate: VersionedSlate,
	) -> Result<(Slate, Option<SlatePurpose>, Option<DalekPublicKey>), Error> {
		let (slate_from, content, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender, _receiver) = self
				.decrypt_slatepack(keychain_mask, in_slate, None)
				.map_err(|e| {
					Error::SlatepackDecodeError(format!("Unable to decrypt a slatepack, {}", e))
				})?;
			(slate_from, Some(content), sender)
		} else {
			let slate_from = in_slate.into_slate_plain(false)?;
			(slate_from, None, None)
		};
		Ok((slate_from, content, sender))
	}

	// Utility method, not expected to be called from Owner API directly.
	pub fn decrypt_slatepack(
		&self,
		keychain_mask: Option<&SecretKey>,
		encrypted_slate: VersionedSlate,
		address_index: Option<u32>,
	) -> Result<
		(
			Slate,
			SlatePurpose,
			Option<DalekPublicKey>,
			Option<DalekPublicKey>,
		),
		Error,
	> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		foreign::decrypt_slate(&mut **w, keychain_mask, encrypted_slate, address_index)
	}

	// Encrypt slate to send back.
	pub fn encrypt_slate(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		version: Option<SlateVersion>,
		content: SlatePurpose,
		slatepack_recipient: Option<DalekPublicKey>,
		address_index: Option<u32>,
		use_test_rng: bool,
	) -> Result<VersionedSlate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		foreign::encrypt_slate(
			&mut **w,
			keychain_mask,
			slate,
			version,
			content,
			slatepack_recipient,
			address_index,
			use_test_rng,
		)
	}

	/// Builds an output
	pub fn build_output(
		&self,
		keychain_mask: Option<&SecretKey>,
		features: OutputFeatures,
		amount: u64,
	) -> Result<BuiltOutput, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::build_output(&mut **w, keychain_mask, features, amount)
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env {
	($wallet:ident, $wallet_config:ident) => {
		use grin_wallet_api as api;
		use grin_wallet_config as config;
		use grin_wallet_impls as impls;
		use grin_wallet_libwallet as libwallet;
		use grin_wallet_util::grin_core;
		use grin_wallet_util::grin_keychain as keychain;
		use grin_wallet_util::grin_util as util;

		use grin_core::global;

		use keychain::ExtKeychain;
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::{Mutex, ZeroingString};

		use api::{Foreign, Owner};
		use config::{parse_node_address_string, WalletConfig};
		use impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
		use libwallet::{BlockFees, InitTxArgs, IssueInvoiceTxArgs, Slate, WalletInst};

		use uuid::Uuid;

		// Set our local chain_type for testing.
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		// don't run on windows CI, which gives very inconsistent results
		if cfg!(windows) {
			return;
		}

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();
		let mut wallet_config = WalletConfig::default();
		wallet_config.data_file_dir = dir.to_owned();
		let pw = ZeroingString::from("");

		let node_list = parse_node_address_string(wallet_config.check_node_api_http_addr.clone());
		let node_client = HTTPNodeClient::new(node_list, None).unwrap();
		let mut wallet = Box::new(
			DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap(),
		)
			as Box<
				WalletInst<
					'static,
					DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
					HTTPNodeClient,
					ExtKeychain,
				>,
			>;
		let lc = wallet.lc_provider().unwrap();
		let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
		lc.open_wallet(None, pw, false, false, None);
		let mut $wallet = Arc::new(Mutex::new(wallet));
	};
}

/*#[test]
#[allow(unused_mut)]
fn test_api() {
	use crate as grin_wallet_api;
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	let mut api_owner = Owner::new(wallet.clone(), None, None);

	let proof = api_owner.retrieve_ownership_proof(None,
														 "my message to sign".to_string(),
														 true,
														 true,
														 true).unwrap();

	let valiation = api_owner.validate_ownership_proof(proof).unwrap();

	assert_eq!(valiation.network, "floonet");
	assert_eq!(valiation.message, "my message to sign".to_string());
	assert!(valiation.viewing_key.is_some());
	assert!(valiation.tor_address.is_some());
	assert!(valiation.mqs_address.is_some());
}*/
