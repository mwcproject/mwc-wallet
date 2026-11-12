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

//! Owner API External Definition

#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::chrono::prelude::*;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use std::path::Path;

use mwc_wallet_config::{MQSConfig, WalletConfig};
use mwc_wallet_impls::create_sender;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::SwapStartArgs;
use mwc_wallet_libwallet::api_impl::foreign;
use mwc_wallet_libwallet::api_impl::owner;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::api_impl::{owner_eth, owner_swap};
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::proof::tx_proof::TxProof;
use mwc_wallet_libwallet::slate_process::SlateProcessGuard;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::fsm::state::{StateEtaInfo, StateId, StateProcessRespond};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::types::{Action, Currency, SwapTransactionsConfirmations};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::{message::Message, swap::Swap, swap::SwapJournalRecord};
use mwc_wallet_libwallet::{
	AcctPathMapping, BuiltOutput, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeHeightResult, OutputCommitMapping, Slate, SlatePurpose, SlateVersion, StoredTxLocator,
	TxLogEntry, VersionedSlate, ViewWallet, WalletInfo, WalletInst, WalletLCProvider,
};
use mwc_wallet_util::mwc_core::core::OutputFeatures;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain};

use mwc_wallet_libwallet::proof::tx_proof;
use mwc_wallet_libwallet::proof::tx_proof::VerifyProofResult;
use mwc_wallet_libwallet::types::{TxSession, U64_DATA_IDX_ADDRESS_INDEX};
use mwc_wallet_libwallet::{
	Context, OwnershipProof, OwnershipProofValidation, RetrieveTxQueryArgs, wallet_lock,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_crates::log::{error, info};
use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::ZeroingString;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_util::from_hex;
use mwc_wallet_util::mwc_util::logger::LoggingConfig;
use std::convert::TryFrom;
use std::sync::Arc;

lazy_static! {
	// Flag that send call is in the progress. init_send_tx is not atomic because we don't want
	// wallet to be blocked during send attempt that can take up to 2 minutes is we are using mwcmqs and other wallet is offline.
	// Also we don't want to lock outputs before send and cancel on failure.
	// That is we are introducing a simple flag for the send. Only one instance will be ready to go through
	// send workflow with owner API. Ownser API ans command can act together, in worst case it will throw lock error
	// Also Finalize need to use this lock as well, because if might use 'lock_later' that does the locking
	// Note, keeping it as a global because we are not expecting activly multiple wallets run in parallel
	pub static ref INIT_SEND_FINALIZE_TX_LOCK: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
}

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
	pub context_id: u32,
	/// contain all methods to manage the wallet
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	#[cfg(feature = "test-support")]
	pub doctest_mode: bool,
	/// retail TLD during doctest
	#[cfg(feature = "test-support")]
	pub doctest_retain_tld: bool,
	/// Share ECDH key
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,
	/// Optional TOR configuration, holding address of sender and
	/// data directory
	tor_config: Mutex<Option<TorConfig>>,
}

/// Result of processing an invoice request.
///
/// Keep `processing_guard` alive until `tx_lock_outputs`, the response exchange,
/// optional post, and transaction-session save have finished.
pub struct ProcessInvoiceTxResult {
	/// Invoice response Slate.
	pub slate: Slate,
	/// Process-local ownership of this externally supplied Slate UUID.
	pub processing_guard: SlateProcessGuard,
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
	/// Each method will call the [`WalletBackend`](../mwc_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../mwc_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed,) perform its operation, then close the keychain
	/// with a call to [`close`](../mwc_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../mwc_wallet_libwallet/types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use mwc_wallet_util::mwc_keychain as keychain;
	/// use mwc_wallet_api as api;
	/// use mwc_wallet_config as config;
	/// use mwc_wallet_impls as impls;
	///
	/// use mwc_wallet_util::mwc_core::global;
	/// use keychain::ExtKeychain;
	/// use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	///
	/// use mwc_wallet_util::Mutex;
	/// use std::sync::Arc;
	/// use mwc_wallet_util::mwc_util::ZeroingString;
	///
	/// use api::Owner;
	/// use config::WalletConfig;
	/// use impls::{DefaultWalletImpl, DefaultLCProvider, HTTPNodeClient};
	/// use mwc_wallet_libwallet::WalletInst;
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
	/// let node_list = parse_node_address_string(wallet_config.check_node_api_http_addr.clone().unwrap_or("http://127.0.0.1:13413".into()));
	/// let node_client = HTTPNodeClient::new(0, node_list, None).unwrap();
	///
	/// // impls::DefaultWalletImpl is provided for convenience in instantiating the wallet
	/// // It contains the LMDBBackend, DefaultLCProvider (lifecycle) and ExtKeychain used
	/// // by the reference wallet implementation.
	/// // These traits can be replaced with alternative implementations if desired
	///
	/// let mut wallet = Box::new(DefaultWalletImpl::<'static, HTTPNodeClient>::new(0, node_client.clone()))
	///     as Box<dyn WalletInst<'static, DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>>;
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
	/// let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
	///     mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
	/// ).unwrap();
	/// lc.open_wallet(
	///     &secp,
	///     None,
	///     pw,
	///     false,
	///     # #[cfg(feature = "test-support")]
	///     false,
	///     None,
	/// );
	///
	/// // All wallet functions operate on an Arc::Mutex to allow multithreading where needed
	/// let mut wallet = Arc::new(Mutex::new(wallet));
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(
		context_id: u32,
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
		tor_config: Option<TorConfig>,
	) -> Result<Self, Error> {
		Ok(Owner {
			context_id,
			wallet_inst,
			#[cfg(feature = "test-support")]
			doctest_mode: false,
			#[cfg(feature = "test-support")]
			doctest_retain_tld: false,
			shared_key: Arc::new(Mutex::new(None)),
			tor_config: Mutex::new(tor_config),
		})
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
	/// * A Vector of [`AcctPathMapping`](../mwc_wallet_libwallet/types/struct.AcctPathMapping.html) data
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
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
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(&secp, keychain_mask)?;
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
	/// * A [Keychain Identifier](../mwc_keychain/struct.Identifier.html) for the new path
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
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
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		owner::create_account_path(&mut **w, &secp, keychain_mask, label)
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
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
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(&secp, keychain_mask)?;
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
	/// a node (via the [`NodeClient`](../mwc_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * `(bool, Vec<OutputCommitMapping>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains a vector of
	/// [OutputCommitMapping](../mwc_wallet_libwallet/types/struct.OutputCommitMapping.html)
	/// of which each element is a mapping between the wallet's internal
	/// [OutputData](../mwc_wallet_libwallet/types/struct.Output.html)
	/// and the Output commitment as identified in the chain's UTXO set
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(None, show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, refresh_anchor_height, output_mappings)) = result {
	///     //...
	/// }
	/// ```
	///
	/// When `update_from_node` is set and the node update succeeds,
	/// `refresh_anchor_height` is the node tip the wallet state was
	/// reconciled against; use that same snapshot for any displayed height or
	/// confirmation count. Otherwise it is 0.

	pub fn retrieve_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, u64, Vec<OutputCommitMapping>), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::retrieve_outputs(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			include_spent,
			refresh_from_node,
			tx_id,
		)
	}

	/// Returns a list of [Transaction Log Entries](../mwc_wallet_libwallet/types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../mwc_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the transactions associated with
	/// the transaction log entry of id `i`.
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html) uuid.
	/// * `tx_query_args` - If provided, use advanced query arguments as documented in
	/// (../mwc_wallet_libwallet/types.struct.RetrieveTxQueryArgs.html). If either
	/// `tx_id` or `tx_slate_id` is provided in the same call, this argument is ignored
	/// * `show_last_four_days` - If true, show transactions within approximately four
	/// days of the node tip, plus outstanding transactions of any age. Entries with
	/// no confirmation height, including cancelled transactions, use their creation
	/// timestamp for the four-day window. Cancellation time is not recorded.
	/// On chains younger than four days, this filter keeps all entries.
	///
	/// # Returns
	/// * `(bool, Option<u64>, Vec<TxLogEntry>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element is the chain tip height against which the wallet state
	/// was refreshed, `Some` only when the first element is `true`. Data displayed
	/// alongside the returned transactions (e.g. confirmation counts) should use
	/// this anchor rather than an independently sampled node height, which may
	/// come from a stale cache or a different node.
	/// * The third element contains the set of retrieved
	/// [TxLogEntries](../mwc_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return recent TxLogEntries, including recent cancellations, plus outstanding entries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id, None, Some(true));
	///
	/// if let Ok((was_updated, anchor_height, tx_log_entries)) = result {
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
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Option<u64>, Vec<TxLogEntry>), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let res = owner::retrieve_txs(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			refresh_from_node,
			tx_id,
			tx_slate_id,
			tx_query_args,
			show_last_four_days,
		)?;
		#[cfg(feature = "test-support")]
		let mut res = res;
		#[cfg(feature = "test-support")]
		if self.doctest_mode {
			res.2 = res
				.2
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
	/// a node (via the [`NodeClient`](../mwc_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have before it's included in the 'amount_currently_spendable' total
	///
	/// # Returns
	/// * (`bool`, [`WalletInfo`](../mwc_wallet_libwallet/types/struct.WalletInfo.html)) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the Summary [`WalletInfo`](../mwc_wallet_libwallet/types/struct.WalletInfo.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::retrieve_summary_info(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			refresh_from_node,
			minimum_confirmations,
		)
	}

	/// Initiates a new transaction as the sender, creating a new
	/// [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html) object containing
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
	/// If the `send_args` [`InitTxSendArgs`](../mwc_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../mwc_wallet_libwallet/types/struct.InitTxArgs.html), field is Some, this
	/// function will attempt to perform a synchronous send to the recipient specified in the `dest`
	/// field according to the `method` field, and will also finalize and post the transaction if
	/// the `finalize` field is set.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `args` - [`InitTxArgs`](../mwc_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * a result containing:
	/// * The transaction [Slate](../mwc_wallet_libwallet/slate/struct.Slate.html),
	/// which can be forwarded to the recieving party by any means. Once the caller is relatively
	/// certain that the transaction has been sent to the recipient, the associated wallet
	/// transaction outputs should be locked via a call to
	/// [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs). This must be called before calling
	/// [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
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
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// // Attempt to create a transaction using the 'default' account
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 2,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     message: Some("Have some Mwcs. Love, Yeastplume".to_owned()),
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	/// 	None,
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	/// 	// Send slate somehow
	/// 	// ...
	/// 	// Lock our outputs if we're happy the slate was (or is being) sent
	/// 	api_owner.tx_lock_outputs(None, None, &slate, None, 0);
	/// }
	/// ```

	pub fn init_send_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		mut tx_session: Option<&mut TxSession>,
		args: &InitTxArgs,
		routputs: usize, // Number of resulting outputs. Normally it is 1
	) -> Result<Slate, Error> {
		let address = args.address.clone();

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
						"Transaction can not be posted without being finalized!".to_owned(),
					));
				}
			}
			None => {}
		}

		let mut recipient: Option<ed25519_dalek::VerifyingKey> = None;
		if let Some(r) = &args.slatepack_recipient {
			recipient = Some(r.tor_public_key()?);
		}

		let mut args = args.clone();

		// Creating sender ahead because of slatepacks. We need to know the another wallet version so
		// we can decide on the slate format (compact slate or not)
		let sender_info = if let Some(sa) = &send_args {
			match sa.method.as_ref() {
				"http" | "mwcmqs" => {
					let (base_path, context_id) = {
						wallet_lock!(self.wallet_inst, w);
						(w.get_data_file_dir().to_string(), w.get_context_id())
					};
					let tor_config_lock = self.tor_config.lock();
					let comm_adapter = create_sender(
						context_id,
						&sa.method,
						&sa.dest,
						&sa.apisecret.as_ref().map(|s| Arc::new(s.clone())),
						tor_config_lock.as_ref(),
						Path::new(&base_path),
					)
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
							args.target_slate_version = Some(
							u16::try_from(other_wallet_version.0.to_numeric_version())
								.map_err(|e| {
									Error::DataOverflow(format!(
										"Owner::init_send_tx, peer returned an invalid slate version, numeric_version={} error={}",
										other_wallet_version.0.to_numeric_version(), e
									))
									})?,
							);
						}
					}
					Some((comm_adapter, other_wallet_version))
				}
				_ => None,
			}
		} else {
			None
		};

		// Using it as a global lock for the API
		// Without usage it still works until the end of the block
		let _send_lock = INIT_SEND_FINALIZE_TX_LOCK.lock();

		let (mut slate, slatepack_secret, mut secp) = {
			wallet_lock!(self.wallet_inst, w);
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			let (validated, _tip) =
				owner::update_wallet_state(&mut **w, &mut secp, keychain_mask, None)?;
			// update_wallet_state reports Ok(false) when it could not validate the
			// wallet state against a node tip (e.g. the node has no headers yet).
			// Never select outputs or build a slate from unvalidated state.
			if !validated {
				return Err(Error::GenericError(
					"Unable to validate wallet state against the node, cannot init send tx"
						.to_string(),
				));
			}

			let slate = {
				owner::init_send_tx(
					&mut **w,
					&mut secp,
					keychain_mask,
					&mut tx_session,
					&args,
					#[cfg(feature = "test-support")]
					self.doctest_mode,
					routputs,
				)?
			};

			let address_index: u32 = {
				let mut batch = w.batch(&secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"Owner::init_send_tx, address index does not fit into u32, index={} error={}",
						index, e
					))
				})?
			};

			let keychain = w.keychain(&secp, keychain_mask)?;
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				&secp,
				w.get_context_id(),
				&keychain,
				address_index,
			)?;
			(slate, slatepack_secret, secp)
		};

		let res = match send_args {
			Some(sa) => {
				let original_slate = slate.clone();

				match sender_info {
					Some((sender, other_wallet_info)) => {
						slate = sender
							.send_tx(
								true,
								&slate,
								SlatePurpose::SendInitial,
								&slatepack_secret,
								recipient,
								other_wallet_info,
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
				original_slate.validate_send_response(&slate)?;

				owner::verify_slate_messages(&slate, &secp).map_err(|e| {
					error!(
						"Unable to validate participant messages at slate {}: {}",
						slate.id, e
					);
					e
				})?;

				let w2n_client = {
					wallet_lock!(self.wallet_inst, w);

					owner::tx_lock_outputs(
						&mut **w,
						&mut secp,
						keychain_mask,
						&mut tx_session,
						&slate,
						address,
						0,
						#[cfg(feature = "test-support")]
						self.doctest_mode,
					)?;

					slate = match sa.finalize {
						true => {
							let (slate_res, _context) = owner::finalize_tx(
								&mut **w,
								&mut secp,
								keychain_mask,
								&mut tx_session,
								&slate,
								true,
								#[cfg(feature = "test-support")]
								self.doctest_mode,
								args.payment_proof_recipient_address.is_some(),
							)?;
							slate_res
						}
						false => slate,
					};
					if let Some(tx_session) = tx_session.as_deref() {
						tx_session.validate_tx_log_entry_size()?;
					}

					if mwc_wallet_util::mwc_util::is_console_output_enabled() {
						println!(
							"slate [{}] finalized successfully in owner_api",
							slate.id.to_string()
						);
					} else {
						info!(
							"slate [{}] finalized successfully in owner_api",
							slate.id.to_string()
						);
					}

					w.w2n_client().clone()
				};

				if sa.post_tx {
					owner::post_tx(self.context_id, &w2n_client, slate.tx_or_err()?, sa.fluff)?;
				}
				if mwc_wallet_util::mwc_util::is_console_output_enabled() {
					println!(
						"slate [{}] posted successfully in owner_api",
						slate.id.to_string()
					);
				} else {
					info!(
						"slate [{}] posted successfully in owner_api",
						slate.id.to_string()
					);
				}
				Ok(slate)
			}
			None => Ok(slate),
		};

		res
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
	/// * `args` - [`IssueInvoiceTxArgs`](../mwc_wallet_libwallet/types/struct.IssueInvoiceTxArgs.html),
	/// invoice transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../mwc_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	///
	/// let args = IssueInvoiceTxArgs {
	///     amount: 60_000_000_000,
	///     ..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(None, None, &args);
	///
	/// if let Ok(slate) = result {
	///     // if okay, send to the payer to add their inputs
	///     // . . .
	/// }
	/// ```
	pub fn issue_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_session: Option<&mut TxSession>,
		args: &IssueInvoiceTxArgs,
	) -> Result<Slate, Error> {
		// Using it as a global lock for the API
		// Without usage it still works until the end of the block
		let mut _send_lock = INIT_SEND_FINALIZE_TX_LOCK.lock();

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		owner::issue_invoice_tx(
			&mut **w,
			&mut secp,
			keychain_mask,
			tx_session,
			args,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			1,
		)
	}

	pub fn generate_invoice_slate(
		&self,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		tx_session: Option<&mut TxSession>,
	) -> Result<(Slate, Context), Error> {
		// Using it as a global lock for the API
		// Without usage it still works until the end of the block
		let _send_lock = INIT_SEND_FINALIZE_TX_LOCK.lock();

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		owner::generate_invoice_slate(&mut **w, &mut secp, keychain_mask, amount, tx_session)
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
	/// With a transaction session, this function only stages wallet state. The caller should
	/// exchange and optionally post the completed transaction before saving the session.
	///
	/// `estimate_only: Some(true)` is rejected. For a fee estimate, call `init_send_tx`
	/// with the invoice amount and `estimate_only: Some(true)`. When `outputs` is provided,
	/// only those outputs may fund the invoice, including its fees.
	/// `payment_proof_recipient_address: Some(_)` is rejected because invoice payment
	/// proofs are unsupported.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
	/// * `args` - [`InitTxArgs`](../mwc_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * `Ok(ProcessInvoiceTxResult)` if successful, containing the updated slate and a
	/// process-local UUID guard that must remain alive through exchange and session save.
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	///
	/// // . . .
	/// // The slate has been recieved from the invoicer, somehow
	/// # let Ok(slate) = Slate::blank(2, false) else { return; };
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
	/// let result = api_owner.process_invoice_tx(None, None, &slate, &args);
	///
	/// if let Ok(result) = result {
	/// // If result okay, send back to the invoicer
	/// let slate = result.slate;
	/// // . . .
	/// }
	/// ```

	pub fn process_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		mut tx_session: Option<&mut TxSession>,
		slate: &Slate,
		args: &InitTxArgs,
	) -> Result<ProcessInvoiceTxResult, Error> {
		owner::validate_invoice_tx_args(args)?;

		// Using it as a global lock for the API
		// Without usage it still works until the end of the block
		let mut _send_lock = INIT_SEND_FINALIZE_TX_LOCK.lock();

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		let processing_guard = w.slate_process_tracker().acquire(slate.id)?;

		let (validated, _tip) =
			owner::update_wallet_state(&mut **w, &mut secp, keychain_mask, None)?;
		// update_wallet_state reports Ok(false) when it could not validate the
		// wallet state against a node tip (e.g. the node has no headers yet).
		// Never select outputs or sign an invoice response from unvalidated state.
		if !validated {
			return Err(Error::GenericError(
				"Unable to validate wallet state against the node, cannot process invoice"
					.to_string(),
			));
		}

		//minimum_confirmations cannot be zero.
		let minimum_confirmations = args.minimum_confirmations.clone();
		if minimum_confirmations < 1 {
			return Err(Error::ClientCallback(
				"minimum_confirmations can not smaller than 1".to_owned(),
			));
		}
		let slate = owner::process_invoice_tx(
			&mut **w,
			&mut secp,
			keychain_mask,
			&mut tx_session,
			slate,
			args,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			true,
		)?;
		Ok(ProcessInvoiceTxResult {
			slate,
			processing_guard,
		})
	}

	/// Locks the outputs associated with the inputs to the transaction in the given
	/// [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html),
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
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html). All
	/// * `participant_id` - The participant id, generally 0 for the party putting in funds, 1 for the
	/// party receiving.
	/// elements in the `input` vector of the `tx` field that are found in the wallet's currently
	/// active account will be set to status `Locked`
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(None, None, &slate, None, 0);
	/// }
	/// ```

	pub fn tx_lock_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		mut tx_session: Option<&mut TxSession>,
		slate: &Slate,
		address: Option<String>,
		participant_id: usize,
	) -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		owner::tx_lock_outputs(
			&mut **w,
			&mut secp,
			keychain_mask,
			&mut tx_session,
			slate,
			address,
			participant_id,
			#[cfg(feature = "test-support")]
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
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html). All
	/// participants must have filled in both rounds, and the sender should have locked their
	/// outputs (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) function).
	///
	/// # Returns
	/// * ``Ok([`slate`](../mwc_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the new finalized slate.
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	///     None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, None, &slate, None, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(None, None, &slate, true);
	/// }
	/// ```

	pub fn finalize_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_session: Option<&mut TxSession>,
		slate: &Slate,
		do_proof: bool,
	) -> Result<Slate, Error> {
		self.finalize_tx_with_output_version(keychain_mask, tx_session, slate, do_proof, None)
	}

	/// Finalize for the specified response format, checking the SP size budget
	/// before committing late locks or consuming the signing context.
	pub fn finalize_tx_with_output_version(
		&self,
		keychain_mask: Option<&SecretKey>,
		mut tx_session: Option<&mut TxSession>,
		slate: &Slate,
		do_proof: bool,
		output_version: Option<SlateVersion>,
	) -> Result<Slate, Error> {
		// Using it as a global lock for the API
		// Without usage it still works until the end of the block
		let _send_lock = INIT_SEND_FINALIZE_TX_LOCK.lock();

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		let (slate_res, _context) = owner::finalize_tx_with_output_version(
			&mut **w,
			&mut secp,
			keychain_mask,
			&mut tx_session,
			slate,
			true,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			do_proof,
			output_version,
		)?;

		Ok(slate_res)
	}

	/// Posts a completed transaction to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx` - A completed [`Transaction`](../mwc_core/core/transaction/struct.Transaction.html),
	/// typically the `tx` field in the transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html).
	/// * `fluff` - Instruct the node whether to use the Dandelion protocol when posting the
	/// transaction. If `true`, the node should skip the Dandelion phase and broadcast the
	/// transaction to all peers immediately. If `false`, the node will follow dandelion logic and
	/// initiate the stem phase.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	///     None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, None, &slate, None, 0);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(None, None, &slate, false);
	///		let res = api_owner.post_tx(None, slate.tx_or_err().unwrap(), true);
	/// }
	/// ```

	pub fn post_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx: &Transaction,
		fluff: bool,
	) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let client = {
			wallet_lock!(self.wallet_inst, w);
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(&secp, keychain_mask)?;
			w.w2n_client().clone()
		};
		owner::post_tx(self.context_id, &client, tx, fluff)
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
	/// Cancellation is idempotent. If the selected transaction is already cancelled, this method
	/// returns `Ok(())`. This is important because the wallet refresh performed by this method can
	/// cancel a TTL-expired transaction before the explicit cancellation step runs. Missing,
	/// confirmed, and otherwise non-cancellable transactions still return an error.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx_id` - If present, cancel by the [`TxLogEntry`](../mwc_wallet_libwallet/types/struct.TxLogEntry.html) id
	/// for the transaction.
	///
	/// * `tx_slate_id` - If present, cancel by the Slate id.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	///     None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, None, &slate, None, 0);
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
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::cancel_tx(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			tx_id,
			tx_slate_id,
		)
	}

	/// Retrieves the stored transaction identified by a [`StoredTxLocator`]. Can
	/// be used even after the transaction has completed.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `locator` - A wallet-local transaction ID, Slate UUID, stored transaction filename, or a
	/// matching combination of those fields.
	///
	/// # Returns
	/// * Ok with the stored  [`Transaction`](../mwc_core/core/transaction/struct.Transaction.html)
	/// if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id, None, None);
	///
	/// if let Ok((was_updated, _, tx_log_entries)) = result {
	///     let locator = mwc_wallet_api::StoredTxLocator::from(&tx_log_entries[0]);
	///     let stored_tx = api_owner.get_stored_tx(None, &locator).unwrap();
	///     //...
	/// }
	/// ```

	pub fn get_stored_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		locator: &StoredTxLocator,
	) -> Result<Option<Transaction>, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(&secp, keychain_mask)?;
		owner::get_stored_tx(&mut **w, keychain_mask, locator)
	}

	/// Loads a stored transaction from a file
	pub fn load_stored_tx(&self, file: &String) -> Result<Transaction, Error> {
		wallet_lock!(self.wallet_inst, w);
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
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html).
	///
	/// # Returns
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// 	None,
	/// 	&args,
	/// 	1,
	/// );
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(None, None, &slate, None, 0);
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		{
			wallet_lock!(self.wallet_inst, w);
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(&secp, keychain_mask)?;
		}
		owner::verify_slate_messages(slate, &secp)
	}

	/// Return the rewind hash of the wallet.
	///
	/// This is a viewing credential: sharing it lets a third party inspect
	/// matching output values. It does not provide spend authority.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * `Ok(Zeroizing<String>)` if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let result = api_owner.get_rewind_hash(None);
	///
	/// if let Ok(rewind_hash) = result {
	///     // Share the rewind hash with a view-only wallet
	///     // ...
	/// }
	/// ```

	pub fn get_rewind_hash(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Zeroizing<String>, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::get_rewind_hash(self.wallet_inst.clone(), &secp, keychain_mask)
	}

	/// Scans the entire UTXO set for outputs matching the given rewind hash.
	///
	/// A match proves only that the rangeproof used the supplied rewind
	/// credential. It does not prove spend ownership: anyone who knows the
	/// rewind hash can create an unrelated valid output that also matches it.
	/// Therefore `ViewWallet::total_balance` is a view-only estimate, not an
	/// authenticated wallet balance.
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let rewind_hash = String::from("<rewind hash shared by the wallet owner>");
	/// let result = api_owner.scan_rewind_hash(rewind_hash, Some(20000));
	///
	/// if let Ok(view_wallet) = result {
	///     // Inspect the outputs visible through the rewind hash
	///     // ...
	/// }
	/// ```

	pub fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		// Move the capability into zeroizing storage before the first fallible
		// operation so context-construction errors cannot drop it as a plain String.
		let rewind_hash = Zeroizing::new(rewind_hash);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::scan_rewind_hash(
			self.wallet_inst.clone(),
			&mut secp,
			rewind_hash,
			start_height,
			None,
			None,
		)
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
	/// [TxLogEntry](../mwc_wallet_libwallet/types/struct.TxLogEntry.html) is created.
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let result = api_owner.scan(
	///     None,
	///     Some(20000),
	/// 	None,
	///     false,
	/// );
	///
	/// if let Ok(_) = result {
	///     // Wallet outputs should be consistent with what's on chain
	///     // ...
	/// }
	/// ```

	/// Scans the UTXO set like [`Owner::scan`](#method.scan), additionally
	/// accepting a relative lookback.
	///
	/// When `backwards_from_tip` is provided it takes precedence over
	/// `start_height`, and the scan start is resolved as that many blocks back
	/// from the chain tip that is freshly fetched and verified when the scan's
	/// node read session starts. The requested range therefore always refers
	/// to the same tip the scan itself authenticates against, rather than a
	/// possibly cached or locally derived earlier sample.
	pub fn scan(
		&self,
		keychain_mask: Option<&SecretKey>,
		start_height: Option<u64>,
		backwards_from_tip: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<u64, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::scan(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			start_height,
			backwards_from_tip,
			delete_unconfirmed,
			true,
			None,
		)
	}

	/// Dump wallet data (outputs and transactions) into a file.
	pub fn dump_wallet_data(
		&self,
		keychain_mask: Option<&SecretKey>,
		file_name: String,
	) -> Result<(), Error> {
		owner::dump_wallet_data(self.wallet_inst.clone(), keychain_mask, file_name)
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
	/// * Ok with a  [`NodeHeightResult`](../mwc_wallet_libwallet/types/struct.NodeHeightResult.html)
	/// if successful. If the height result was obtained from the configured node,
	/// `updated_from_node` will be set to `true`
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		{
			wallet_lock!(self.wallet_inst, w);
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(&secp, keychain_mask)?;
		}
		let res = owner::node_height(self.wallet_inst.clone(), &mut secp, keychain_mask)?;
		#[cfg(feature = "test-support")]
		let mut res = res;
		#[cfg(feature = "test-support")]
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
	/// 2) ~/.mwc/<chaintype>/ otherwise
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok with a String value representing the full path to the top level wallet dierctory
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
		#[cfg(feature = "test-support")]
		if self.doctest_mode && !self.doctest_retain_tld {
			return Ok("/doctest/dir".to_owned());
		}
		lc.get_top_level_directory()
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
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
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// A custom [`WalletConfig`](../mwc_wallet_config/types/struct.WalletConfig.html)
	/// and/or mwc `LoggingConfig` may optionally be provided, otherwise defaults will be used.
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
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
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// * `mnemonic_length`: Desired entropy length for a new mnemonic in bytes. Supported values
	/// are 16, 20, 24, 28, and 32 (12, 15, 18, 21, and 24 words respectively). This value is
	/// ignored when `mnemonic` supplies a recovery phrase.
	/// * `password`: The password used to encrypt/decrypt the `wallet.seed` file
	///
	/// # Returns
	/// * Ok with mnemonic phrase if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
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
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet,None,  None, None, None);
	///
	///	// create new wallet wirh random seed
	///	let pw = ZeroingString::from("my_password");
	/// let result = api_owner.create_wallet(None, None, 0, pw, None, true);
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
		show_seed: bool,
	) -> Result<ZeroingString, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		let mnemonic_length = usize::try_from(mnemonic_length).map_err(|e| {
			Error::DataOverflow(format!(
				"Owner::create_wallet, mnemonic length does not fit usize, mnemonic_length={} error={}",
				mnemonic_length, e
			))
		})?;
		lc.create_wallet(
			name,
			mnemonic,
			mnemonic_length,
			password,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			wallet_data_dir,
			show_seed,
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
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
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None,  None, None, None);
	///
	///	// create new wallet wirh random seed
	///	let pw = ZeroingString::from("my_password");
	/// let _ = api_owner.create_wallet(None, None, 0, pw.clone(), None, true);
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		// just return a representative string for doctest mode
		#[cfg(feature = "test-support")]
		if self.doctest_mode {
			return Ok(Some(SecretKey::from_slice(
				&secp,
				&from_hex("d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868")
					.map_err(|e| {
						Error::GenericError(format!("Unable to decode doctest key, {}", e))
					})?,
			)?));
		}
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.open_wallet(
			&secp,
			name,
			password,
			use_mask,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			wallet_data_dir,
		)
	}

	/// `Close` a wallet, removing the master seed from memory.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	/// The wallet must be explicitly closed first via the `close_wallet` function.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	///
	/// api_owner.close_wallet(None).unwrap();
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

	/// Retrieve the MQS address associated with the wallet. This address can be changed with
	/// address index. In this case it will affect all wallet public addresses
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	///
	/// # Returns
	/// * Ok with a PublicKey that representing the address for MQS
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	///
	/// let res = api_owner.get_mqs_address(None);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_mqs_address(&self, keychain_mask: Option<&SecretKey>) -> Result<PublicKey, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::get_mqs_address(self.wallet_inst.clone(), &secp, keychain_mask)
	}

	/// Retrieve the Tor or wallet public address associated with the wallet. This address can be changed with
	/// address index. In this case it will affect all wallet public addresses
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	///
	/// # Returns
	/// * Ok(ed25519_dalek::VerifyingKey) representing the public key associated with the address, if successful
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the address provided is invalid
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use mwc_wallet_util::mwc_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
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
	) -> Result<ed25519_dalek::VerifyingKey, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::get_wallet_public_address(self.wallet_inst.clone(), &secp, keychain_mask)
	}

	/// Retrieve a stored payment proof after validating the wallet's keychain mask.
	///
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap());
	///
	/// // Return the stored payment proof
	/// let result = api_owner.get_stored_tx_proof(None, tx_id, tx_slate_id);
	/// if let Ok(p) = result {
	///     //...
	/// }
	/// ```
	pub fn get_stored_tx_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<TxProof, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::get_stored_tx_proof(
			self.wallet_inst.clone(),
			&secp,
			keychain_mask,
			tx_id,
			tx_slate_id,
		)
	}

	pub fn verify_tx_proof(&self, proof: &TxProof) -> Result<VerifyProofResult, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let context_id = {
			wallet_lock!(self.wallet_inst, w);
			w.get_context_id()
		};
		tx_proof::verify_tx_proof_wrapper(context_id, &proof, &secp)
	}

	pub fn retrieve_ownership_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		message: String,
		include_public_root_key: bool,
		include_tor_address: bool,
		include_mqs_address: bool,
	) -> Result<OwnershipProof, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner::generate_ownership_proof(
			self.wallet_inst.clone(),
			&secp,
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let context_id = {
			wallet_lock!(self.wallet_inst, w);
			w.get_context_id()
		};
		owner::validate_ownership_proof(&secp, context_id, proof)
	}

	/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
	#[cfg(feature = "swaps")]
	pub fn swap_start(
		&self,
		keychain_mask: Option<&SecretKey>,
		params: &SwapStartArgs,
	) -> Result<String, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_start(self.wallet_inst.clone(), &mut secp, keychain_mask, params)
			.map_err(|e| e.into())
	}

	#[cfg(feature = "swaps")]
	pub fn swap_create_from_offer(
		&self,
		keychain_mask: Option<&SecretKey>,
		message_filename: String,
	) -> Result<String, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_create_from_offer(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			message_filename,
		)
		.map_err(|e| e.into())
	}

	/// List all available swap operations. SwapId & Status
	#[cfg(feature = "swaps")]
	pub fn swap_list(
		&self,
		keychain_mask: Option<&SecretKey>,
		do_check: bool,
	) -> Result<
		(
			Vec<owner_swap::SwapListInfo>,
			Vec<owner_swap::MarketplaceCancelNotification>,
		),
		Error,
	> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_list(self.wallet_inst.clone(), &mut secp, keychain_mask, do_check)
			.map_err(|e| e.into())
	}

	/// Delete swap trade
	#[cfg(feature = "swaps")]
	pub fn swap_delete(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_delete(self.wallet_inst.clone(), &secp, keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}
	/// Retrieve swap trade
	#[cfg(feature = "swaps")]
	pub fn swap_get(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<Swap, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_get(self.wallet_inst.clone(), &secp, keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}

	/// Adjust the sate of swap trade.
	/// method & destination required for adjust_cmd='destination'
	#[cfg(feature = "swaps")]
	pub fn swap_adjust(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
		adjust_cmd: String,
		method: Option<String>,
		destination: Option<String>,
		secondary_address: Option<String>, // secondary address to adjust
		secondary_fee: Option<String>,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_infura_project_id: Option<String>,
		tag: Option<String>,
	) -> Result<(StateId, Action), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_adjust(
			self.wallet_inst.clone(),
			&mut secp,
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
	#[cfg(feature = "swaps")]
	pub fn swap_dump(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: String,
	) -> Result<String, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_dump(self.wallet_inst.clone(), &secp, keychain_mask, &swap_id)
			.map_err(|e| e.into())
	}

	/// dump ethereum info
	#[cfg(feature = "swaps")]
	pub fn eth_info(
		&self,
		keychain_mask: Option<&SecretKey>,
		currency: Currency,
	) -> Result<(String, String, String), Error> {
		owner_eth::info(self.wallet_inst.clone(), keychain_mask, currency).map_err(|e| e.into())
	}

	/// ethereum transfer
	#[cfg(feature = "swaps")]
	pub fn eth_transfer(
		&self,
		keychain_mask: Option<&SecretKey>,
		dest: String,
		currency: Currency,
		amount: &String,
	) -> Result<mwc_wallet_util::mwc_web3::types::H256, mwc_wallet_libwallet::swap::Error> {
		owner_eth::transfer(
			self.wallet_inst.clone(),
			keychain_mask,
			currency,
			dest,
			amount,
		)
	}

	/// Retry a direct ETH/ERC20 transfer retained by the running wallet process.
	/// Any original or replacement hash identifies the same payment. None keeps
	/// its current fee budget; Some authorizes a maximum fee budget in gwei.
	#[cfg(feature = "swaps")]
	pub fn eth_retry_transfer(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_hash: mwc_wallet_util::mwc_web3::types::H256,
		gas_budget_gwei: Option<u64>,
	) -> Result<mwc_wallet_util::mwc_web3::types::H256, mwc_wallet_libwallet::swap::Error> {
		owner_eth::retry_transfer(
			self.wallet_inst.clone(),
			keychain_mask,
			tx_hash,
			gas_budget_gwei,
		)
	}

	/// Refresh and get a status and current expected action for the swap.
	/// Supplied Ethereum contract addresses must match the immutable addresses
	/// pinned in the trade; a different address returns an error.
	/// return: <state>, <Action>, <time limit>, <Roadmap lines>, <Journal records>, <last error> , <marketplace cancellation notifications>
	/// time limit shows when this action will be expired
	#[cfg(feature = "swaps")]
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
			Vec<owner_swap::MarketplaceCancelNotification>,
		),
		Error,
	> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::update_swap_status_action(
			self.wallet_inst.clone(),
			&mut secp,
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
	/// Supplied Ethereum contract addresses must match the immutable addresses
	/// pinned in the trade; a different address returns an error.
	#[cfg(feature = "swaps")]
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
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::get_swap_tx_tstatus(
			self.wallet_inst.clone(),
			&secp,
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

	#[cfg(feature = "swaps")]
	pub fn swap_process<F>(
		&self,
		keychain_mask: Option<&SecretKey>,
		swap_id: &str,
		message_sender: F,
		message_file_name: Option<String>,
		buyer_refund_address: Option<String>,
		secondary_fee: Option<String>,
		secondary_address: Option<String>,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_infura_project_id: Option<String>,
	) -> Result<
		(
			StateProcessRespond,
			Vec<owner_swap::MarketplaceCancelNotification>,
		),
		Error,
	>
	where
		F: FnOnce(
				Message,
				String,
				String,
				&Secp256k1,
			) -> Result<(bool, String), mwc_wallet_libwallet::swap::Error>
			+ 'static,
	{
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		owner_swap::swap_process(
			self.wallet_inst.clone(),
			&mut secp,
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

	/// Process a swap message received over the network. The optional sender must
	/// be authenticated by the MQS transport; unauthenticated delivery cannot
	/// update an existing MQS trade. Owner-selected files use the file import APIs.
	#[cfg(feature = "swaps")]
	pub fn swap_income_message(
		&self,
		keychain_mask: Option<&SecretKey>,
		message: String,
		authenticated_sender: Option<String>,
	) -> Result<Option<Message>, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(|e| {
			// Preserve the transient/deterministic classification: SysRngFailure
			// and AllocationError are local, recoverable conditions and must
			// surface as SwapTransient so the broker redelivers instead of
			// dropping the message.
			Error::from(mwc_wallet_libwallet::swap::error::Error::Secp(e))
		})?;
		owner_swap::swap_income_message(
			self.wallet_inst.clone(),
			&mut secp,
			keychain_mask,
			&message,
			authenticated_sender.as_deref(),
		)
		.map_err(|e| e.into())
	}

	// decryipt income slate. It is the common routine for most API calls that accept the slates
	// Note, the merge case if not covered by this API.
	pub fn decrypt_versioned_slate(
		&self,
		keychain_mask: Option<&SecretKey>,
		in_slate: VersionedSlate,
	) -> Result<
		(
			Slate,
			Option<SlatePurpose>,
			Option<ed25519_dalek::VerifyingKey>,
		),
		Error,
	> {
		let (slate_from, content, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender, _receiver) = self
				.decrypt_slatepack(keychain_mask, in_slate, None)
				.map_err(|e| {
					Error::SlatepackDecodeError(format!("Unable to decrypt a slatepack, {}", e))
				})?;
			(slate_from, Some(content), sender)
		} else {
			let context_id = {
				wallet_lock!(self.wallet_inst, w);
				w.get_context_id()
			};
			let slate_from = in_slate.into_slate_plain(context_id, false)?;
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
			Option<ed25519_dalek::VerifyingKey>,
			Option<ed25519_dalek::VerifyingKey>,
		),
		Error,
	> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		// Owner flows also process this wallet's own outgoing slatepacks (e.g.
		// tx_lock_outputs after a send), so the local key may be the sender.
		foreign::decrypt_slate(
			&mut **w,
			&secp,
			keychain_mask,
			encrypted_slate,
			address_index,
			false,
		)
	}

	// Encrypt slate to send back.
	pub fn encrypt_slate(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		version: Option<SlateVersion>,
		content: SlatePurpose,
		slatepack_recipient: Option<ed25519_dalek::VerifyingKey>,
		address_index: Option<u32>,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<VersionedSlate, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		foreign::encrypt_slate(
			&mut **w,
			&secp,
			keychain_mask,
			slate,
			version,
			content,
			slatepack_recipient,
			address_index,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)
	}

	/// Builds an output
	/// For plain outputs, sync the wallet first so its last confirmed height is nonzero.
	pub fn build_output(
		&self,
		keychain_mask: Option<&SecretKey>,
		features: OutputFeatures,
		amount: u64,
	) -> Result<BuiltOutput, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		owner::build_output(&mut **w, &mut secp, keychain_mask, features, amount)
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env {
	($wallet:ident, $wallet_config:ident) => {
		use mwc_wallet_util::mwc_core;
		use mwc_wallet_util::mwc_core::global;

		use mwc_wallet_util::mwc_crates::tempfile::tempdir;
		use mwc_wallet_util::mwc_keychain::ExtKeychain;

		use mwc_wallet_util::Mutex;
		use mwc_wallet_util::mwc_util::ZeroingString;
		use std::sync::Arc;

		use mwc_wallet_api::{Foreign, Owner};
		use mwc_wallet_config::{WalletConfig, parse_node_address_string};
		use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
		use mwc_wallet_libwallet::{BlockFees, InitTxArgs, IssueInvoiceTxArgs, Slate, WalletInst};

		use mwc_wallet_util::mwc_crates::uuid::Uuid;

		// Set our local chain_type for testing.
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE)
			.expect("Failed to set doctest fee base");

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

		let node_list = parse_node_address_string(
			wallet_config
				.check_node_api_http_addr
				.clone()
				.unwrap_or("http://127.0.0.1:13413".into()),
		);
		let node_client = HTTPNodeClient::new(0, node_list, None).unwrap();
		let mut wallet = Box::new(DefaultWalletImpl::<'static, HTTPNodeClient>::new(
			0,
			node_client.clone(),
		))
			as Box<
				dyn WalletInst<
						'static,
						DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
						HTTPNodeClient,
						ExtKeychain,
					>,
			>;
		let lc = wallet.lc_provider().unwrap();
		lc.set_top_level_directory(&wallet_config.data_file_dir)
			.expect("Failed to set doctest wallet directory");
		// Opening a wallet requires a seed file in the temporary directory.
		drop(
			lc.create_wallet(
				None,
				None,
				32,
				pw.clone(),
				#[cfg(feature = "test-support")]
				false,
				None,
				false,
			)
			.expect("Failed to create doctest wallet"),
		);
		let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
			mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
		)
		.unwrap();
		lc.open_wallet(
			&secp,
			None,
			pw,
			false,
			#[cfg(feature = "test-support")]
			false,
			None,
		)
		.expect("Failed to open doctest wallet");
		let $wallet = Arc::new(Mutex::new(wallet));
	};
}

/*#[test]
fn owner_doc_test() {
	use crate as mwc_wallet_api;
}*/
