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

//! Foreign API External Definition

use mwc_wallet_libwallet::api_impl::foreign;
use mwc_wallet_libwallet::reply_cache;
use mwc_wallet_libwallet::slate_process::SlateProcessGuard;
use mwc_wallet_libwallet::types::{ReceiveData, TxSession};
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_libwallet::{
	BlockFees, CbData, Error, NodeClient, NodeVersionInfo, Slate, SlatePurpose, SlateVersion,
	TxLogEntryType, VersionInfo, VersionedSlate, WalletBackend, WalletInst, WalletLCProvider,
};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::Mutex;
use std::sync::Arc;

/// Check wallet-wide durable receive state independently of the active account.
fn durable_receive_exists<'a, T: ?Sized, C, K>(
	wallet: &T,
	slate_id: &mwc_wallet_util::mwc_crates::uuid::Uuid,
	finalized_only: bool,
) -> Result<bool, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let found = wallet
		.tx_log_iter()?
		.chain(wallet.tx_log_archive_iter()?)
		.any(|tx| {
			tx.tx_type == TxLogEntryType::TxReceived
				&& tx.tx_slate_id == Some(*slate_id)
				&& (!finalized_only || tx.stored_tx.is_some())
		});
	Ok(found)
}

/// ForeignAPI Middleware Check callback
/// `BuildCoinbase` runs before wallet access and receives `None` for both the
/// node version and slate; coinbase construction does not require a node lookup.
pub type ForeignCheckMiddleware =
	fn(ForeignCheckMiddlewareFn, Option<NodeVersionInfo>, Option<&Slate>) -> Result<(), Error>;

/// Middleware Identifiers for each function
pub enum ForeignCheckMiddlewareFn {
	/// check_version
	CheckVersion,
	/// build_coinbase
	BuildCoinbase,
	/// verify_slate_messages
	VerifySlateMessages,
	/// receive_tx
	ReceiveTx,
	/// finalize_invoice_tx
	FinalizeInvoiceTx,
}

/// Result of staging a received transaction.
///
/// The caller finishes the response exchange first, then saves the supplied
/// `TxSession`, completes the reply reservation and dispatches the notification.
pub struct ReceiveTxResult {
	/// Slate containing the receiver's contribution.
	pub slate: Slate,
	/// Keeps this Slate UUID serialized across every supported concurrent entry
	/// point until the caller finishes the exchange and persists or abandons the
	/// transaction session. The wallet lifecycle permits only one backend for a
	/// wallet data directory, so this backend-local guard is the intended
	/// serialization boundary.
	pub processing_guard: SlateProcessGuard,
	/// In-flight reply slot to publish only after the wallet commit succeeds.
	pub reply_reservation: Option<reply_cache::ReplyReservation>,
	/// Notification to dispatch only after the wallet commit succeeds.
	pub receive_data: Option<ReceiveData>,
}

/// Result of finalizing an invoice transaction.
pub struct FinalizeInvoiceTxResult {
	/// Finalized Slate.
	pub slate: Slate,
	/// Keeps this Slate UUID serialized until the caller finishes the exchange
	/// and persists or abandons the transaction session.
	pub processing_guard: SlateProcessGuard,
	/// In-flight reply slot to publish only after a deferred wallet commit succeeds.
	pub reply_reservation: Option<reply_cache::ReplyReservation>,
}

/// Main interface into all wallet API functions.
/// Wallet APIs are split into two seperate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// * The 'Foreign' API contains methods that other wallets will
/// use to interact with the owner's wallet. This API can be exposed
/// to the outside world, with the consideration as to how that can
/// be done securely up to the implementor.
///
/// Methods in both APIs are intended to be 'single use', that is to say each
/// method will 'open' the wallet (load the keychain with its master seed), perform
/// its operation, then 'close' the wallet (unloading references to the keychain and master
/// seed).

pub struct Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Wallet instance
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	#[cfg(feature = "test-support")]
	pub doctest_mode: bool,
	/// foreign check middleware
	middleware: Option<ForeignCheckMiddleware>,
	/// Stored keychain mask (in case the stored wallet seed is tokenized)
	pub(crate) keychain_mask: Option<SecretKey>,
}

impl<'a, L, C, K> Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../mwc_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../mwc_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed), perform its operation, then close the keychain
	/// with a call to [`close`](../mwc_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../mwc_wallet_libwallet/types/trait.WalletBackend.html) trait.
	/// * `keychain_mask` - Mask value stored internally to use when calling a wallet
	/// whose seed has been XORed with a token value (such as when running the foreign
	/// and owner listeners in the same instance)
	/// * middleware - Option middleware which containts the NodeVersionInfo and can call
	/// a predefined function with the slate to check if the operation should continue
	///
	/// # Returns
	/// * An instance of the ForeignApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use mwc_wallet_util::mwc_keychain as keychain;
	/// use mwc_wallet_api as api;
	/// use mwc_wallet_config as config;
	/// use mwc_wallet_impls as impls;
	///
	/// use keychain::ExtKeychain;
	/// use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use mwc_wallet_util::mwc_util::ZeroingString;
	/// use mwc_wallet_util::Mutex;
	///
	/// use mwc_wallet_util::mwc_core::global;
	///
	/// use api::Foreign;
	/// use config::WalletConfig;
	/// use impls::{DefaultWalletImpl, DefaultLCProvider, HTTPNodeClient};
	/// use mwc_wallet_libwallet::WalletInst;
	/// use mwc_wallet_config::parse_node_address_string;
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
	/// let node_list = parse_node_address_string(wallet_config.check_node_api_http_addr.clone().unwrap_or("http://127.0.0.1:13413".to_owned()));
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
	/// let wallet = Arc::new(Mutex::new(wallet));
	///
	/// let api_foreign = Foreign::new(wallet.clone(), None, None);
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		keychain_mask: Option<SecretKey>,
		middleware: Option<ForeignCheckMiddleware>,
	) -> Self {
		Foreign {
			wallet_inst,
			#[cfg(feature = "test-support")]
			doctest_mode: false,
			middleware,
			keychain_mask,
		}
	}

	/// Return the version capabilities of the running ForeignApi Node
	/// # Arguments
	/// None
	/// # Returns
	/// * [`VersionInfo`](../mwc_wallet_libwallet/api_impl/types/struct.VersionInfo.html)
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None);
	///
	/// let version_info = api_foreign.check_version();
	/// // check and proceed accordingly
	/// ```

	pub fn check_version(&self) -> Result<VersionInfo, Error> {
		if let Some(m) = self.middleware.as_ref() {
			// Keep request cache and failover updates without holding the wallet lock.
			let mut node_client = {
				wallet_lock!(self.wallet_inst, w);
				w.w2n_client().clone_for_request()
			};
			let version_info = node_client.get_version_info();
			m(ForeignCheckMiddlewareFn::CheckVersion, version_info, None)?;
		}
		foreign::check_version()
	}

	/// Return the tor proof address
	/// # Arguments
	/// None
	/// # Returns
	/// * [`String`]
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None);
	///
	/// let tor_proof_address = api_foreign.get_proof_address();
	/// # assert!(tor_proof_address.is_ok());
	/// // check and proceed accordingly
	/// ```

	pub fn get_proof_address(&self) -> Result<String, Error> {
		wallet_lock!(self.wallet_inst, w);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		foreign::get_proof_address(&mut **w, &secp, (&self.keychain_mask).as_ref())
	}

	/// Build an unconfirmed Coinbase output and S2C kernel at any height.
	/// Rewards use the active wallet account and ordinary recovery metadata.
	/// Access is restricted to authorized mining callers.
	///
	/// The mining node supplies the exact template's binding digest and verifies
	/// the returned opening. It includes that opening in the block only after
	/// consensus activation. No legacy mining fallback is supported.
	///
	/// `fees` is the sum of transaction fees, `height` is the candidate block
	/// height, and `binding_digest` is a 32-byte hash
	/// encoded as hexadecimal. An optional `key_id` requests reuse of an existing
	/// unconfirmed Coinbase candidate. Ineligible keys are left untouched and
	/// replaced with a newly allocated key.
	///
	/// The output remains unconfirmed until found on chain during a wallet update,
	/// and remains unspendable until Coinbase maturity.
	///
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	/// let api_foreign = Foreign::new(wallet.clone(), None, None);
	/// let block_fees = BlockFees {
	///     fees: 0,
	///     height: 3,
	///     key_id: None,
	///     // Example only: the mining node calculates this from its actual template.
	///     binding_digest: "01".repeat(32),
	/// };
	/// let coinbase = api_foreign.build_coinbase(&block_fees).unwrap();
	/// assert!(coinbase.key_id.is_some());
	/// ```

	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		// The mining caller may be a different node from the wallet's configured
		// node, so that node's version does not describe the caller. Check mining
		// access without querying the configured node.
		if let Some(m) = self.middleware.as_ref() {
			m(ForeignCheckMiddlewareFn::BuildCoinbase, None, None)?;
		}
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		foreign::build_coinbase(&mut **w, &mut secp, self.keychain_mask.as_ref(), block_fees)
	}

	/// Verifies all messages in the slate match their public keys.
	///
	/// The option messages themselves are part of the `participant_data` field within the slate.
	/// Messages are signed with the same key used to sign for the paricipant's inputs, and can thus be
	/// verified with the public key found in the `public_blind_excess` field. This function is a
	/// simple helper to returns whether all signatures in the participant data match their public
	/// keys.
	///
	/// # Arguments
	///
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html).
	///
	/// # Returns
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None);
	///
	/// # let Ok(slate) = Slate::blank(2, false) else { return; };
	/// // Receive a slate via some means
	///
	/// let res = api_foreign.verify_slate_messages(&slate);
	///
	/// if let Err(e) = res {
	///     // Messages don't validate, likely return an error
	///     // ...
	/// } else {
	///     // Slate messages are fine
	/// }
	///
	///
	/// ```

	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		if let Some(m) = self.middleware.as_ref() {
			let version_info = {
				wallet_lock!(self.wallet_inst, w);
				w.w2n_client().get_version_info()
			};
			m(
				ForeignCheckMiddlewareFn::VerifySlateMessages,
				version_info,
				Some(slate),
			)?;
		}
		let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly)?;
		foreign::verify_slate_messages(slate, &secp)
	}

	/// Recieve a tranaction created by another party, returning the modified
	/// [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html) object, modified with
	/// the recipient's output for the transaction amount, and public signature data. This slate can
	/// then be sent back to the sender to finalize the transaction via the
	/// [Owner API's `finalize_tx`](struct.Owner.html#method.finalize_tx) method.
	///
	/// This function creates a single output for the full amount, set to a status of
	/// 'Awaiting finalization'. It will remain in this state until the wallet finds the
	/// corresponding output on the chain, at which point it will become 'Unspent'. The slate
	/// will be updated with the results of Signing round 1 and 2, adding the recipient's public
	/// nonce, public excess value, and partial signature to the slate.
	///
	/// Also creates a corresponding [Transaction Log Entry](../mwc_wallet_libwallet/types/struct.TxLogEntry.html)
	/// in the wallet's transaction log.
	///
	/// # Arguments
	/// * `tx_session` - Stages every wallet mutation until the caller commits with
	/// [`TxSession::save_tx_data`]. Making the session mandatory prevents an accidental
	/// lower-level commit while the reply is still being constructed. Only after that
	/// commit succeeds may the caller complete the returned reply reservation.
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html).
	/// The slate should contain the results of the sender's round 1 (e.g, public nonce and public
	/// excess value).
	/// * `reply_binding` - The authenticated sender and transport allowed to retry this request.
	/// Supply this only for MQS or an encrypted Slatepack; plain requests must use `None`.
	/// * `authenticated_sender` - The secp256k1 public key independently authenticated by the
	/// sender transport. A slate requesting a payment proof is rejected when this is `None` or
	/// does not match its claimed MQS sender. An encrypted Slatepack sender is Ed25519 and cannot
	/// populate this argument without a verified cross-key attestation.
	/// * `dest_acct_name` - The name of the account into which the slate should be received. If
	/// `None`, the default account is used.
	/// * `message` - An optional participant message to include alongside the recipient's public
	/// ParticipantData within the slate. This message will include a signature created with the
	/// recipient's private excess value, and will be publically verifiable. Note this message is for
	/// the convenience of the participants during the exchange; it is not included in the final
	/// transaction sent to the chain. The message will be truncated to 256 characters.
	/// Validation of this message is optional.
	/// * `validate_with_node` - Whether to preflight a newly created response with the node
	/// before returning it. Set to `false` for offline exchanges. Local validation always
	/// runs, and the completed transaction still requires node preflight before publication.
	///
	/// # Returns
	/// * `Ok(ReceiveTxResult)` if successful, containing the updated Slate, its
	/// process-local UUID guard, and the post-commit reply/callback data.
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method only stages a partially completed transaction. After the
	/// response exchange succeeds, the caller saves `tx_session`, then completes
	/// `reply_reservation`.
	///
	/// # Example
	/// Set up as in [new](struct.Foreign.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None);
	/// # let Ok(slate) = Slate::blank(2, false) else { return; };
	/// let mut tx_session = TxSession::new();
	///
	/// // . . .
	/// // Obtain a sent slate somehow
	/// let result = api_foreign.receive_tx(
	///     &mut tx_session, &slate, None, None, None, &None, None, true,
	/// );
	///
	/// if let Ok(result) = result {
	///     // Publish the response, then commit tx_session.
	///     let slate = result.slate;
	///     // Send back to recipient somehow
	///     // ...
	/// }
	/// ```

	pub fn receive_tx(
		&self,
		tx_session: &mut TxSession,
		slate: &Slate,
		reply_binding: Option<reply_cache::ReplyBinding>,
		address: Option<String>,
		authenticated_sender: Option<PublicKey>,
		dest_acct_name: &Option<String>,
		message: Option<String>,
		validate_with_node: bool,
	) -> Result<ReceiveTxResult, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let (slate, receive_data, reply_reservation, processing_guard, context_id, node_client) = {
			wallet_lock!(self.wallet_inst, w);
			// Reject an oversized or structurally invalid peer transaction before
			// reserving process state or serializing the full slate for reply-cache
			// fingerprinting.
			slate.validate_transaction_read(w.get_context_id())?;
			// The wallet lifecycle guarantees one backend per wallet data
			// directory. Holding this returned guard through exchange and commit
			// therefore excludes every supported concurrent receive of this UUID;
			// no cross-process protocol is required for unsupported duplicate
			// backend instances.
			let processing_guard = w.slate_process_tracker().acquire(slate.id)?;
			if let Some(m) = self.middleware.as_ref() {
				m(
					ForeignCheckMiddlewareFn::ReceiveTx,
					w.w2n_client().get_version_info(),
					Some(slate),
				)?;
			}

			let reply_request = reply_binding
				.map(|binding| {
					reply_cache::ReplyRequest::receive(
						w.get_context_id(),
						slate,
						binding,
						dest_acct_name.as_deref(),
						message.as_deref(),
					)
				})
				.transpose()?;
			let reply_reservation = if let Some(request) = reply_request {
				let cache = w.reply_cache();
				let reservation =
					match cache.reserve(slate.id, SlatePurpose::SendResponse, request)? {
						reply_cache::ReserveResult::Cached(reply) => {
							return Ok(ReceiveTxResult {
								slate: reply,
								processing_guard,
								reply_reservation: None,
								receive_data: None,
							});
						}
						reply_cache::ReserveResult::Reserved(reservation) => Some(reservation),
						reply_cache::ReserveResult::Uncached => None,
					};
				if durable_receive_exists(&**w, &slate.id, false)? {
					return Err(Error::ReceiveResponseUnavailable(slate.id.to_string()));
				}
				reservation
			} else {
				None
			};

			let (slate, _context, receive_data) = foreign::receive_tx(
				&mut **w,
				&mut secp,
				(&self.keychain_mask).as_ref(),
				tx_session,
				slate,
				address,
				authenticated_sender,
				None,
				dest_acct_name,
				message,
				#[cfg(feature = "test-support")]
				self.doctest_mode,
				true,
			)?;
			(
				slate,
				receive_data,
				reply_reservation,
				processing_guard,
				w.get_context_id(),
				w.w2n_client().clone_for_request(),
			)
		};

		if validate_with_node {
			mwc_wallet_libwallet::transaction_preflight::check_slate(
				context_id,
				&node_client,
				&slate,
				&secp,
				!slate.compact_slate,
			)?;
		}

		Ok(ReceiveTxResult {
			slate,
			processing_guard,
			reply_reservation,
			receive_data: Some(receive_data),
		})
	}

	/// Finalizes an invoice transaction initiated by this wallet's Owner api.
	/// This step assumes the paying party has completed round 1 and 2 of slate
	/// creation, and added their partial signatures. The invoicer will verify
	/// and add their partial sig, then create the finalized transaction,
	/// ready to post to a node.
	///
	/// Note that this function DOES NOT POST the transaction to a node
	/// for validation. This is done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `tx_session` - When supplied, stages finalization and leaves the wallet commit to the
	/// caller via [`TxSession::save_tx_data`]. This is used by the faucet workflow, whose
	/// invoice state is not yet durable. With `None`, this method uses the normal persisted
	/// invoice path and commits finalization directly.
	/// * `slate` - The transaction [`Slate`](../mwc_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
	///
	/// # Returns
	/// * `Ok(FinalizeInvoiceTxResult)` if successful, containing the finalized Slate,
	/// its process-local UUID guard, and any deferred reply reservation.
	/// * or [`mwc_wallet_libwallet::Error`](../mwc_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # mwc_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(0, wallet.clone(), None).unwrap();
	/// let api_foreign = Foreign::new(wallet.clone(), None, None);
	///
	/// // . . .
	/// // Issue the invoice tx via the owner API
	/// let args = IssueInvoiceTxArgs {
	///     amount: 10_000_000_000,
	///     ..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(None, None, &args);
	///
	/// // If result okay, send to payer, who will apply the transaction via their
	/// // owner API, then send back the slate
	/// // ...
	/// # let Ok(slate) = Slate::blank(2, false) else { return; };
	///
	/// let result = api_foreign.finalize_invoice_tx(None, &slate, None);
	/// // if okay, then post via the owner API
	/// ```

	pub fn finalize_invoice_tx(
		&self,
		tx_session: Option<&mut TxSession>,
		slate: &Slate,
		reply_binding: Option<reply_cache::ReplyBinding>,
	) -> Result<FinalizeInvoiceTxResult, Error> {
		self.finalize_invoice_tx_with_output_version(tx_session, slate, reply_binding, None)
	}

	/// Finalize for the specified response format, checking the restored SP size
	/// before binding the signing nonce or consuming the invoice context.
	pub fn finalize_invoice_tx_with_output_version(
		&self,
		mut tx_session: Option<&mut TxSession>,
		slate: &Slate,
		reply_binding: Option<reply_cache::ReplyBinding>,
		output_version: Option<SlateVersion>,
	) -> Result<FinalizeInvoiceTxResult, Error> {
		let deferred_commit = tx_session.is_some();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		let processing_guard = w.slate_process_tracker().acquire(slate.id)?;
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::FinalizeInvoiceTx,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		let reply_request = reply_binding
			.map(|binding| {
				reply_cache::ReplyRequest::finalize_invoice(w.get_context_id(), slate, binding)
			})
			.transpose()?;

		let reply_reservation = if let Some(request) = reply_request {
			let cache = w.reply_cache();
			let reservation = match cache.reserve(slate.id, SlatePurpose::FullSlate, request)? {
				reply_cache::ReserveResult::Cached(reply) => {
					return Ok(FinalizeInvoiceTxResult {
						slate: reply,
						processing_guard,
						reply_reservation: None,
					});
				}
				reply_cache::ReserveResult::Reserved(reservation) => Some(reservation),
				reply_cache::ReserveResult::Uncached => None,
			};
			if durable_receive_exists(&**w, &slate.id, true)? {
				return Err(Error::ReceiveResponseUnavailable(slate.id.to_string()));
			}
			reservation
		} else {
			None
		};

		let out_slate = foreign::finalize_invoice_tx_with_output_version(
			&mut **w,
			&mut secp,
			(&self.keychain_mask).as_ref(),
			&mut tx_session,
			slate,
			true,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
			output_version,
		)?;
		let mut reply_reservation = reply_reservation;
		if !deferred_commit {
			if let Some(reservation) = reply_reservation.take() {
				reservation.complete(&out_slate);
			}
		}
		Ok(FinalizeInvoiceTxResult {
			slate: out_slate,
			processing_guard,
			reply_reservation,
		})
	}

	#[cfg(feature = "swaps")]
	pub fn receive_swap_message(&self, swap_message: &String) -> Result<(), Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		foreign::receive_swap_message(
			self.wallet_inst.clone(),
			&mut secp,
			(&self.keychain_mask).as_ref(),
			swap_message,
		)
	}

	// Processing marketplace message. Currently we can notify QT wallet that offer is accepted.
	// And we can notify that offers are dropped.
	#[cfg(feature = "swaps")]
	pub fn marketplace_message(&self, message: &String) -> Result<String, Error> {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		foreign::marketplace_message(
			self.wallet_inst.clone(),
			&mut secp,
			(&self.keychain_mask).as_ref(),
			message,
		)
	}

	// Utility method, not expected to be called from Foreign API.
	// Used by inbound receive paths, so an encrypted slatepack must name this
	// wallet as its recipient.
	pub fn decrypt_slate(
		&self,
		encrypted_slate: VersionedSlate,
		address_index: Option<u32>,
	) -> Result<(Slate, SlatePurpose, Option<ed25519_dalek::VerifyingKey>), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		let (slate, content, sender, _receiver) = foreign::decrypt_slate(
			&mut **w,
			&secp,
			(&self.keychain_mask).as_ref(),
			encrypted_slate,
			address_index,
			true,
		)?;
		Ok((slate, content, sender))
	}

	// Utility method, not expected to be called from Foreign API.
	pub fn encrypt_slate(
		&self,
		slate: &Slate,
		version: Option<SlateVersion>,
		content: SlatePurpose,
		slatepack_recipient: Option<ed25519_dalek::VerifyingKey>,
		address_index: Option<u32>,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<VersionedSlate, Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		wallet_lock!(self.wallet_inst, w);
		let vslate = foreign::encrypt_slate(
			&mut **w,
			&secp,
			(&self.keychain_mask).as_ref(),
			slate,
			version,
			content,
			slatepack_recipient,
			address_index,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;
		Ok(vslate)
	}
}

#[cfg(test)]
mod coinbase_tests {
	use super::*;
	use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
	use mwc_wallet_util::mwc_keychain::ExtKeychain;

	#[test]
	fn build_coinbase_rejects_before_wallet_access() {
		// No opened wallet or configured node is needed to reject mining access.
		let node_client = HTTPNodeClient::new(0, Vec::new(), None).unwrap();
		let wallet: Box<
			dyn WalletInst<
					'static,
					DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
					HTTPNodeClient,
					ExtKeychain,
				>,
		> = Box::new(DefaultWalletImpl::new(0, node_client));
		let api = Foreign::new(
			Arc::new(Mutex::new(wallet)),
			None,
			Some(|name, node_version, slate| {
				assert!(matches!(name, ForeignCheckMiddlewareFn::BuildCoinbase));
				assert!(node_version.is_none());
				assert!(slate.is_none());
				Err(Error::GenericError("mining access denied".to_owned()))
			}),
		);
		let request = BlockFees {
			fees: 0,
			height: 3,
			key_id: None,
			binding_digest: "01".repeat(32),
		};

		assert!(matches!(
			api.build_coinbase(&request),
			Err(Error::GenericError(message)) if message == "mining access denied"
		));
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env_foreign {
	($wallet:ident, $wallet_config:ident) => {
		use mwc_wallet_util::mwc_core;

		use mwc_wallet_util::mwc_core::global;
		use mwc_wallet_util::mwc_crates::tempfile::tempdir;
		use mwc_wallet_util::mwc_keychain::ExtKeychain;

		use mwc_wallet_util::mwc_util::ZeroingString;
		use mwc_wallet_util::Mutex;
		use std::sync::Arc;

		use mwc_wallet_api::{Foreign, Owner};
		use mwc_wallet_config::{parse_node_address_string, WalletConfig};
		use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
		use mwc_wallet_libwallet::types::TxSession;
		use mwc_wallet_libwallet::{BlockFees, IssueInvoiceTxArgs, Slate, WalletInst};

		// don't run on windows CI, which gives very inconsistent results
		if cfg!(windows) {
			return;
		}

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

//#[test]
//fn foreign_doc_test() {
//	use crate as mwc_wallet_api;
//}
