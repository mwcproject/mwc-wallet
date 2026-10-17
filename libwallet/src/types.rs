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

//! Types and traits that should be provided by a wallet
//! implementation

use crate::error::Error;
use crate::slate::ParticipantMessages;
#[cfg(feature = "test-support")]
use crate::step_rng::StepRng;
#[cfg(feature = "swaps")]
use crate::swap::ethereum::EthereumWallet;
use crate::LateLockArgs;
use crate::Slate;
use mwc_wallet_config::{MQSConfig, WalletConfig};
use mwc_wallet_util::mwc_api;
use mwc_wallet_util::mwc_core::core::hash::Hash;
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::core::KernelFeatures;
use mwc_wallet_util::mwc_core::core::{Output, Transaction, TxKernel};
use mwc_wallet_util::mwc_core::libtx::{aggsig, secp_ser};
use mwc_wallet_util::mwc_core::{global, ser};
use mwc_wallet_util::mwc_crates::chrono::prelude::*;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::rand::TryRng;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey, ZERO_KEY};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::{pedersen, Secp256k1};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;

use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::{Identifier, Keychain};
use mwc_wallet_util::mwc_p2p;
use mwc_wallet_util::mwc_p2p::TorConfig;
use mwc_wallet_util::mwc_util::logger::LoggingConfig;
use mwc_wallet_util::mwc_util::{ToHex, ZeroingString};
use mwc_wallet_util::sensitive;
use mwc_wallet_util::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Combined trait to allow dynamic wallet dispatch
pub trait WalletInst<'a, L, C, K>: Send + Sync
where
	L: WalletLCProvider<'a, C, K> + Send + Sync,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Return the stored instance
	fn lc_provider(&mut self) -> Result<&mut (dyn WalletLCProvider<'a, C, K> + 'a), Error>;
}

/// Trait for a provider of wallet lifecycle methods.
///
/// A wallet data directory must have at most one opened backend. Callers must
/// close the current wallet before opening that directory through another
/// provider, process, or backend instance. Runtime coordination such as Slate
/// UUID serialization and authenticated reply caching deliberately lives in
/// that single backend and is not an inter-process locking protocol.
///
/// Within the wallet workflow, one allocated `context_id` represents one wallet
/// session for its complete lifetime. Reopening a backend in that session is not
/// a wallet switch: selecting another wallet requires releasing the old context
/// and allocating a new one. Context release synchronously stops and joins every
/// context-owned listener before context-id-keyed registries are cleared or the
/// numeric id can be reused. Direct library calls, including listener startup,
/// are outside that lifecycle and callers must serialize them against context
/// release.
pub trait WalletLCProvider<'a, C, K>: Send + Sync
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Sets the top level system wallet directory
	/// default is assumed to be ~/.mwc/main/wallet_data (or floonet equivalent)
	fn set_top_level_directory(&mut self, dir: &str) -> Result<(), Error>;

	/// Sets the top level system wallet directory
	/// default is assumed to be ~/.mwc/main/wallet_data (or floonet equivalent)
	fn get_top_level_directory(&self) -> Result<String, Error>;

	/// Output a mwc-wallet.toml file into the current top-level system wallet directory
	fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		file_name: &str,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		mqs_config: Option<MQSConfig>,
	) -> Result<(), Error>;

	/// Create a new wallet, returns mnemonic phrase
	fn create_wallet(
		&mut self,
		name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: usize,
		password: ZeroingString,
		#[cfg(feature = "test-support")] test_mode: bool,
		wallet_data_dir: Option<&str>,
		show_seed: bool,
	) -> Result<ZeroingString, Error>;

	/// Open the sole backend for the selected wallet data directory.
	///
	/// Opening the same directory concurrently through another lifecycle
	/// provider or process is unsupported.
	fn open_wallet(
		&mut self,
		secp: &Secp256k1,
		name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		wallet_data_dir: Option<&str>,
	) -> Result<Option<SecretKey>, Error>;

	///
	fn close_wallet(&mut self, name: Option<&str>) -> Result<(), Error>;

	/// whether a wallet exists at the given directory
	fn wallet_exists(
		&self,
		name: Option<&str>,
		wallet_data_dir: Option<&str>,
	) -> Result<bool, Error>;

	/// return mnemonic of given wallet
	fn get_mnemonic(
		&self,
		name: Option<&str>,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<ZeroingString, Error>;

	/// Check whether a provided mnemonic string is valid
	fn validate_mnemonic(&self, mnemonic: ZeroingString) -> Result<(), Error>;

	/// Recover a seed from phrase, without destroying existing data
	/// should back up seed
	/// The wallet must be closed before recovery so an in-memory keychain cannot
	/// remain associated with the seed being replaced.
	fn recover_from_mnemonic(
		&self,
		mnemonic: ZeroingString,
		password: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error>;

	/// changes password
	fn change_password(
		&self,
		name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error>;

	/// Deletes the wallet. The wallet must be closed first.
	fn delete_wallet(&self, name: Option<&str>) -> Result<(), Error>;

	/// return wallet instance
	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error>;

	/// Access to the wallet-session context id.
	fn get_context_id(&self) -> u32;
}

/// TODO:
/// Wallets should implement this backend for their storage. All functions
/// here expect that the wallet instance has instantiated itself or stored
/// whatever credentials it needs
pub trait WalletBackend<'ck, C, K>: Send + Sync
where
	C: NodeClient + 'ck,
	K: Keychain + 'ck,
{
	/// Wallet-session context id. Its lifetime, rather than an individual backend
	/// allocation, is the identity boundary for this wallet.
	fn get_context_id(&self) -> u32;

	/// data file directory. tor & mwc713 needs it
	fn get_data_file_dir(&self) -> &str;

	/// Set the keychain, which should already be initialized
	/// Optionally return a token value used to XOR the stored
	/// key value
	fn set_keychain(
		&mut self,
		secp: &Secp256k1,
		k: Box<K>,
		mask: bool,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error>;

	/// Close wallet and remove any stored credentials (TBD)
	fn close(&mut self) -> Result<(), Error>;

	/// Shared, in-memory reply cache for this sole opened wallet backend.
	fn reply_cache(&self) -> Arc<crate::reply_cache::ReplyCache>;

	/// Serialize externally supplied Slate UUIDs across every supported
	/// concurrent entry point using this sole opened backend.
	fn slate_process_tracker(&self) -> Arc<crate::slate_process::SlateProcessTracker>;

	/// Return the keychain being used. Ensure a cloned copy so it will be dropped
	/// and zeroized by the caller
	/// Can optionally take a mask value
	fn keychain(&self, secp: &Secp256k1, mask: Option<&SecretKey>) -> Result<K, Error>;

	/// Return the client being used to communicate with the node
	fn w2n_client(&mut self) -> &mut C;

	/// return the commit for caching if allowed, none otherwise
	fn calc_commit(
		&self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Commitment, Error>;

	/// Set parent key id by stored account name
	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error>;

	/// The BIP32 path of the parent path to use for all output-related
	/// functions, (essentially 'accounts' within a wallet.
	fn set_parent_key_id(&mut self, _: Identifier);

	/// return the parent path
	fn parent_key_id(&self) -> Identifier;

	/// Iterate over all output data stored by the backend
	fn iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = OutputData> + 'a>, Error>;

	/// Get output data by id
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;

	/// Iterate over archive outputs data stored by the backend
	fn archive_iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = OutputData> + 'a>, Error>;

	/// Retrieves the private context associated with a given slate id.
	/// Implementations return [`Error::PrivateContextNotFound`] only when the
	/// requested record is absent and preserve all other failures.
	fn get_private_context(
		&mut self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<Context, Error>;

	/// Iterate over all output data stored by the backend
	fn tx_log_iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = TxLogEntry> + 'a>, Error>;

	/// Iterate over all output data stored by the backend
	fn tx_log_archive_iter<'a>(
		&'a self,
	) -> Result<Box<dyn Iterator<Item = TxLogEntry> + 'a>, Error>;

	/// Iterate over all stored account paths
	fn acct_path_iter<'a>(
		&'a self,
	) -> Result<Box<dyn Iterator<Item = AcctPathMapping> + 'a>, Error>;

	/// Gets an account path for a given label
	fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error>;

	/// Stores a transaction
	fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error>;

	/// Retrieves a stored transaction from a TxLogEntry
	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, Error>;

	/// Load transaction by UUID. Needed for mwc713
	fn get_stored_tx_by_uuid(&self, uuid: &str, archived: bool) -> Result<Transaction, Error>;

	/// Load a txn from specified file
	fn load_stored_tx(&self, path: &str) -> Result<Transaction, Error>;

	/// Create a new write batch to update or remove output data
	fn batch<'a>(
		&'a mut self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	/// Batch for use when keychain isn't available or required
	fn batch_no_mask<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	/// Return the current child Index
	fn current_child_index(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;

	/// Next child ID when we want to create a new output, based on current parent
	fn next_child(&mut self, parent_key_id: Option<&Identifier>) -> Result<Identifier, Error>;

	/// Last verified height for the wallet as a whole.
	fn last_confirmed_height(&mut self) -> Result<u64, Error>;

	/// last block scanned during scan or restore
	fn last_scanned_blocks(&mut self) -> Result<Vec<ScannedBlockInfo>, Error>;

	/// set ethereum wallet instance
	#[cfg(feature = "swaps")]
	fn set_ethereum_wallet(
		&mut self,
		secp: &Secp256k1,
		ethereum_wallet: Option<EthereumWallet>,
		keychain_mask: Option<&SecretKey>,
	) -> Result<(), Error>;

	/// Get the Ethereum wallet instance, unmasking it only for a caller that
	/// supplies the wallet session's keychain mask.
	#[cfg(feature = "swaps")]
	fn get_ethereum_wallet(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<EthereumWallet, Error>;
}

/// New wallet with empty seed mark. Needed to skip first long scan
pub const FLAG_NEW_WALLET: u64 = 1;
/// Need to clean private context on the first wallet run
pub const FLAG_CONTEXT_CLEARED: u64 = 2;
/// Need to correct outputs root_key_id values to recover from prev bug
pub const FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION: u64 = 3;
/// Legacy height-bearing identifiers have been canonicalized in stored wallet data
pub const FLAG_LEGACY_HEIGHT_IDENTIFIERS_MIGRATED: u64 = 4;
/// Durable private contexts have been rewritten without legacy API request data.
pub const FLAG_PRIVATE_CONTEXTS_SANITIZED: u64 = 5;
/// Private transaction context masks bind the participant id.
pub const FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT: u64 = 6;

/// Last working node data
pub const U64_DATA_IDX_LAST_WORKING_NODE_INDEX: u64 = 1;

/// Proof & MQS address index
pub const U64_DATA_IDX_ADDRESS_INDEX: u64 = 2;

/// Wallet-global scan watermark. Singleton wallet metadata shares the existing
/// U64 data namespace instead of allocating another database prefix.
pub const U64_DATA_IDX_LAST_CONFIRMED_HEIGHT: u64 = 3;

/// Batch trait to update the output data backend atomically. Trying to use a
/// batch after commit MAY result in a panic. Due to this being a trait, the
/// commit method can't take ownership.
/// TODO: Should these be split into separate batch objects, for outputs,
/// tx_log entries and meta/details?
pub trait WalletOutputBatch<K>
where
	K: Keychain,
{
	/// Return the keychain being used
	fn keychain(&mut self) -> Result<&mut K, Error>;

	/// Add or update data about an output and atomically ensure its child key
	/// cannot be allocated again by the backend.
	fn save(&mut self, out: OutputData) -> Result<(), Error>;

	/// Gets output data by id
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;

	/// Iterate over all output data stored by the backend
	fn iter(&self) -> Result<Box<dyn Iterator<Item = OutputData>>, Error>;

	/// Delete data about an output from the backend
	fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error>;

	/// Move output into archive
	fn archive_output(&mut self, out: &OutputData) -> Result<(), Error>;

	/// Save last stored child index of a given parent
	fn save_child_index(&mut self, parent_key_id: &Identifier, child_n: u32) -> Result<(), Error>;

	/// Save the last confirmed height for the wallet as a whole.
	fn save_last_confirmed_height(&mut self, height: u64) -> Result<(), Error>;

	/// Save the last PMMR index that was scanned via a scan operation
	fn save_last_scanned_blocks(
		&mut self,
		first_scanned_block_height: u64,
		block: &Vec<ScannedBlockInfo>,
	) -> Result<(), Error>;

	/// Save safe flag into DB
	fn save_flag(&mut self, flag: u64) -> Result<(), Error>;

	/// Load and optionally delete the flag from DB
	fn load_flag(&mut self, flag: u64, delete: bool) -> Result<bool, Error>;

	/// Canonicalize identifiers persisted by wallets that stored anti-replay
	/// height metadata below the declared BIP32 path depth.
	fn migrate_legacy_height_identifiers(&mut self) -> Result<(), Error>;

	/// Re-encrypt legacy private transaction contexts in place with masks that
	/// bind the participant id. Call only while the corresponding migration
	/// marker is absent because this transformation is not idempotent.
	fn migrate_private_context_xor_keys(&mut self, secp: &Secp256k1) -> Result<(), Error>;

	/// Rewrite private transaction contexts using the current minimal schema.
	/// This removes transport-only fields that older versions embedded in
	/// late-lock contexts.
	fn sanitize_private_contexts(&mut self) -> Result<(), Error>;

	/// Save the last used good node index
	fn save_u64(&mut self, index: u64, value: u64) -> Result<(), Error>;

	/// get the last used good node index
	fn load_u64(&mut self, index: u64, default: u64) -> Result<u64, Error>;

	/// Persist the address index selected for a marketplace bid before its Swap
	/// Deal exists. `binding_key` is the domain-separated digest of the offer id
	/// and peer address.
	#[cfg(feature = "swaps")]
	fn save_marketplace_signing_address_index(
		&mut self,
		binding_key: &[u8; 32],
		address_index: u32,
	) -> Result<(), Error>;

	/// Load the address index previously selected for a marketplace bid.
	#[cfg(feature = "swaps")]
	fn load_marketplace_signing_address_index(
		&mut self,
		binding_key: &[u8; 32],
	) -> Result<Option<u32>, Error>;

	/// get next tx log entry for the parent
	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;

	/// Iterate over tx log data stored by the backend
	fn tx_log_iter(&self) -> Result<Box<dyn Iterator<Item = TxLogEntry>>, Error>;

	/// Iterate over tx log archived data
	fn tx_log_archive_iter(&self) -> Result<Box<dyn Iterator<Item = TxLogEntry>>, Error>;

	/// Move transaction into archive
	fn archive_transaction(&mut self, tx: &TxLogEntry) -> Result<(), Error>;

	/// save a tx log entry
	fn save_tx_log_entry(&mut self, t: TxLogEntry, parent_id: &Identifier) -> Result<(), Error>;

	/// Delete tx log entry.
	fn delete_tx_log_entry(&mut self, tx_id: u32, parent_id: &Identifier) -> Result<(), Error>;

	/// rename account, old_name -> new_name
	fn rename_acct_path(
		&mut self,
		accounts: Vec<AcctPathMapping>,
		old_name: &str,
		new_name: &str,
	) -> Result<(), Error>;

	/// save an account label -> path mapping
	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error>;

	/// Iterate over account names stored in backend
	fn acct_path_iter(&self) -> Result<Box<dyn Iterator<Item = AcctPathMapping>>, Error>;

	/// Save an output as locked in the backend
	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error>;

	/// Iterate through all private context. Return tx uuid from the key and the Context
	fn private_context_iter(&self) -> Result<Box<dyn Iterator<Item = (Vec<u8>, Context)>>, Error>;

	/// Saves the private context associated with a slate id
	fn save_private_context(
		&mut self,
		secp: &Secp256k1,
		slate_id: &[u8],
		participant_id: usize,
		ctx: &Context,
	) -> Result<(), Error>;

	/// Delete the private context associated with the slate id
	fn delete_private_context(
		&mut self,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<(), Error>;

	/// Store a transaction body while this backend write batch holds the
	/// serialization boundary for the corresponding wallet state.
	fn store_tx(&mut self, uuid: &str, tx: &Transaction) -> Result<(), Error>;

	/// Write the wallet data to backend file
	fn commit(&self) -> Result<(), Error>;
}

/// Identifies one selected node for the lifetime of a request sequence.
///
/// `generation` changes whenever the client changes its selected node, including
/// when it later rotates back to the same `node_index`. Implementations may wrap
/// the counter after exhausting its range, provided they invalidate cached data.
/// Implementations that derive `node_index` from this counter must return both
/// fields from the same counter snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NodeConnectionId {
	/// Index of the selected node in the configured node list.
	pub node_index: u8,
	/// Raw connection counter used to distinguish successive selections.
	pub generation: u64,
}

/// Node metadata for an unspent output.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeOutputDetails {
	/// Hex-encoded output commitment.
	pub commit: String,
	/// Block height at which the output was created.
	pub height: u64,
	/// Output position in the node's PMMR.
	pub mmr_index: u64,
}

/// Encapsulates wallet-node communication so libwallet does not depend on transport details.
pub trait NodeClient: Send + Sync + Clone {
	/// Obtain a client for requests performed after releasing the wallet lock.
	/// Implementations with connection state or caches can share them with this
	/// handle so request updates survive its drop. Configuration changes must not
	/// let requests using the old configuration populate the new caches.
	/// The default preserves the existing behavior of custom clients.
	fn clone_for_request(&self) -> Self {
		self.clone()
	}

	/// Set the node index
	fn set_node_index(&mut self, index: u8);

	/// Set the node index
	fn get_node_index(&self) -> u8;

	/// Return an identifier that changes whenever the selected node changes.
	///
	/// Clients without automatic failover can use the default implementation.
	fn get_node_connection_id(&self) -> NodeConnectionId {
		NodeConnectionId {
			node_index: self.get_node_index(),
			generation: 0,
		}
	}

	/// Reset cache data
	fn reset_cache(&self);

	/// Validate only unsigned metadata. Unsupported nodes fail closed.
	fn test_mempool_accept(
		&self,
		request: &crate::transaction_preflight::MempoolAcceptRequest,
	) -> Result<crate::transaction_preflight::MempoolAcceptResponse, Error>;

	/// Publish a transaction validated by the wallet's preflight helper.
	/// Transports must consume and check this receipt before sending any signing data.
	fn post_tx(
		&self,
		tx: &Transaction,
		fluff: bool,
		receipt: crate::transaction_preflight::PreflightReceipt,
	) -> Result<(), Error>;

	/// Returns the api version string and block header version as reported
	/// by the node. Result can be cached for later use
	fn get_version_info(&mut self) -> Option<NodeVersionInfo>;

	/// retrieves the current tip (height, hash) from the specified mwc node
	/// (<height>, <hash>, <total difficulty>)
	fn get_chain_tip(&self) -> Result<(u64, String, u64), Error>;

	/// retrieves the current tip bypassing any cached value. Used where a
	/// stale tip affects correctness, e.g. TTL cutoff enforcement. Clients
	/// that cache tips must override this method; the default is for clients
	/// whose `get_chain_tip` already fetches fresh data.
	fn get_chain_tip_fresh(&self) -> Result<(u64, String, u64), Error> {
		self.get_chain_tip()
	}

	/// Return header info by height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, Error>;

	/// Return header info by height, bypassing any cached value. Clients that
	/// cache headers must override this method; clearing the cache first is
	/// insufficient because an in-flight request can repopulate it.
	fn get_header_info_fresh(&self, height: u64) -> Result<HeaderInfo, Error> {
		self.get_header_info(height)
	}

	/// Fetch a header and its parent by hash, independently of the selected
	/// header chain. The returned hash must match the request. This lookup must
	/// not use or populate a cache keyed only by height: the block may be on a
	/// different fork from the header chain while its body is being processed.
	fn get_header_by_hash(&self, hash: &str) -> Result<NodeHeaderLink, Error>;

	/// Return Connected peers
	fn get_connected_peer_info(&self) -> Result<Vec<mwc_p2p::types::PeerInfoDisplayLegacy>, Error>;

	/// Get a kernel and the height of the block it's included in. Returns
	/// (tx_kernel, height, mmr_index)
	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error>;

	/// Retrieve details for unspent outputs from the specified MWC node.
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, NodeOutputDetails>, Error>;

	/// Get a list of outputs from the node by traversing the UTXO
	/// set in PMMR index order.
	/// Returns
	/// (last available output index, last insertion index retrieved,
	/// outputs(commit, proof, is_coinbase, height, mmr_index))
	fn get_outputs_by_pmmr_index(
		&self,
		start_height: u64,
		end_height: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		Error,
	>;

	/// Return the pmmr indices representing the outputs between a given
	/// set of block heights
	/// (start pmmr index, end pmmr index)
	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), Error>;

	/// Get blocks for height range. end_height is included.
	/// Note, single block required singe request. Don't abuse it much because mwc713 wallets using the same node
	/// threads_number - how many requests to do in parallel
	fn get_blocks_by_height(
		&self,
		start_height: u64,
		end_height: u64,
		threads_number: usize,
	) -> Result<Vec<mwc_api::BlockPrintable>, Error>;
}

/// Node version info
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct NodeVersionInfo {
	/// Semver version string
	pub node_version: String,
	/// block header verson
	pub block_header_version: u16,
	/// Whether this version info was successfully verified from a node
	pub verified: Option<bool>,
}

/// Information about an output that's being tracked by the wallet. Must be
/// enough to reconstruct the commitment associated with the ouput when the
/// root private key is known.

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[serde(crate = "serde")]
pub struct OutputData {
	/// Root key_id that the key for this output is derived from
	pub root_key_id: Identifier,
	/// Derived key for this output
	pub key_id: Identifier,
	/// How many derivations down from the root key
	pub n_child: u32,
	/// The actual commit, optionally stored
	pub commit: Option<String>,
	/// PMMR Index, used on restore in case of duplicate wallets using the same
	/// key_id (2 wallets using same seed, for instance
	#[serde(with = "secp_ser::opt_string_or_u64")]
	pub mmr_index: Option<u64>,
	/// Value of the output, necessary to rebuild the commitment
	#[serde(with = "secp_ser::string_or_u64")]
	pub value: u64,
	/// Current status of the output
	pub status: OutputStatus,
	/// Height of the output
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Height we are locked until
	#[serde(with = "secp_ser::string_or_u64")]
	pub lock_height: u64,
	/// Is this a coinbase output? Is it subject to coinbase locktime?
	pub is_coinbase: bool,
	/// Optional corresponding internal entry in tx entry log
	pub tx_log_entry: Option<u32>,
}

impl ser::Writeable for OutputData {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let output_vct = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("OutputData to json conversion failed, {}", e))
		})?;
		if output_vct.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Output data length is {}",
				output_vct.len()
			)));
		}
		writer.write_bytes(&output_vct)
	}
}

impl ser::Readable for OutputData {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<OutputData, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..])
			.map_err(|e| ser::Error::CorruptedData(format!("json to OutputData failed, {}", e)))
	}
}

impl OutputData {
	/// Lock a given output to avoid conflicting use
	pub fn lock(&mut self) {
		self.status = OutputStatus::Locked;
	}

	/// How many confirmations has this output received?
	/// If height == 0 then we are either Unconfirmed or the output was
	/// cut-through
	/// so we do not actually know how many confirmations this output had (and
	/// never will).
	pub fn num_confirmations(&self, current_height: u64) -> u64 {
		if self.height > current_height {
			return 0;
		}
		if self.status == OutputStatus::Unconfirmed || self.status == OutputStatus::Reverted {
			0
		} else {
			// if an output has height n and we are at block n
			// then we have a single confirmation (the block it originated in)
			// self.height <= current_height above. MWC's one-block-per-minute protocol makes
			// current_height == u64::MAX physically unreachable on supported deployments.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "height ordering is checked and protocol block heights cannot approach u64::MAX"
			)]
			{
				current_height - self.height + 1
			}
		}
	}

	/// Check if output is eligible to spend based on state and height and
	/// confirmations
	pub fn eligible_to_spend(&self, current_height: u64, minimum_confirmations: u64) -> bool {
		if [OutputStatus::Spent, OutputStatus::Locked].contains(&self.status)
			|| self.status == OutputStatus::Unconfirmed && self.is_coinbase
			|| self.lock_height > current_height
		{
			false
		} else {
			if (self.status == OutputStatus::Unspent
				&& self.num_confirmations(current_height) >= minimum_confirmations)
				|| self.status == OutputStatus::Unconfirmed && minimum_confirmations == 0
			{
				// Eligible, but also let's check accross all TxSessions that can be alive
				match &self.commit {
					Some(commit) => input_is_free(commit),
					None => true,
				}
			} else {
				false
			}
		}
	}

	/// Marks this output as unspent if it was previously unconfirmed
	pub fn mark_unspent(&mut self) {
		match self.status {
			OutputStatus::Unconfirmed | OutputStatus::Reverted => {
				self.status = OutputStatus::Unspent
			}
			_ => {}
		}
	}

	/// Mark an output as spent
	pub fn mark_spent(&mut self) {
		match self.status {
			OutputStatus::Unspent | OutputStatus::Locked => self.status = OutputStatus::Spent,
			_ => (),
		}
	}

	/// Mark an output as reverted
	pub fn mark_reverted(&mut self) {
		match self.status {
			OutputStatus::Unspent => self.status = OutputStatus::Reverted,
			_ => (),
		}
	}

	/// Check if this output is potentionally spendable
	pub fn is_spendable(&self) -> bool {
		match self.status {
			OutputStatus::Unspent => true,
			OutputStatus::Locked => true,
			_ => false,
		}
	}
}
/// Status of an output that's being tracked by the wallet. Can either be
/// unconfirmed, spent, unspent, or locked (when it's been used to generate
/// a transaction but we don't have confirmation that the transaction was
/// broadcasted or mined).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[serde(crate = "serde")]
pub enum OutputStatus {
	/// Unconfirmed
	Unconfirmed,
	/// Unspent
	Unspent,
	/// Locked
	Locked,
	/// Spent
	Spent,
	/// Reverted
	Reverted,
}

impl fmt::Display for OutputStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			OutputStatus::Unconfirmed => write!(f, "Unconfirmed"),
			OutputStatus::Unspent => write!(f, "Unspent"),
			OutputStatus::Locked => write!(f, "Locked"),
			OutputStatus::Spent => write!(f, "Spent"),
			OutputStatus::Reverted => write!(f, "Reverted"),
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "serde")]
/// Holds the context for a single aggsig transaction
pub struct Context {
	/// Parent key id
	pub parent_key_id: Identifier,
	/// Secret key (of which public is shared)
	pub sec_key: SecretKey,
	/// Secret nonce (of which public is shared)
	/// (basically a SecretKey)
	pub sec_nonce: SecretKey,
	/// only used if self-sending an invoice
	pub initial_sec_key: SecretKey,
	/// as above
	pub initial_sec_nonce: SecretKey,
	/// store my outputs + amounts between invocations
	/// Id, mmr_index (if known), amount
	pub output_ids: Vec<(Identifier, Option<u64>, u64)>,
	/// Original rangeproof height for each output. Rebuilding the same commitment
	/// with a different height reuses deterministic alpha/rho masks across different
	/// proof messages and can expose the amount. Keep this separate from OutputData's
	/// height, which changes during locking and confirmation.
	#[serde(default)]
	pub output_build_heights: Vec<(Identifier, u64)>,
	/// store my inputs
	/// Id, mmr_index (if known), amount
	pub input_ids: Vec<(Identifier, Option<u64>, u64)>,
	/// store the transaction amount
	#[serde(default)]
	pub amount: u64,
	/// store the calculated fee
	pub fee: u64,
	/// keep track of the participant id
	pub participant_id: usize,
	/// Payment proof sender address derivation path, if needed
	pub payment_proof_derivation_index: Option<u32>,
	/// Address (public key string) of the payment proof recipient that was
	/// requested when this transaction was initiated, if any. Persisted so
	/// the proof on the returned slate can be validated against the
	/// originally requested recipient.
	#[serde(default)]
	pub payment_proof_recipient_address: Option<String>,
	/// Output commitments, mwc713 payment proof support.
	#[serde(default)]
	pub output_commits: Vec<Commitment>,
	/// Input commitments, mwc713 payment proof support.
	#[serde(default)]
	pub input_commits: Vec<Commitment>,
	/// If late-locking, store only the transaction construction preferences
	/// needed later. Transport arguments and credentials are deliberately
	/// excluded from this durable context.
	#[serde(default)]
	pub late_lock_args: Option<LateLockArgs>,
	/// for invoice I2 Only, store the tx excess so we can
	/// remove it from the slate on return
	pub calculated_excess: Option<pedersen::Commitment>,
	/// Slate message that was added from this participant.
	pub message: Option<String>,
	/// Kernel Lock height, used for response slate validation
	#[serde(default)]
	pub lock_height: u64,
	/// kernel_features, used for response slate validation
	#[serde(default)]
	pub kernel_features: u8,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs, used for response slate validation
	#[serde(default)]
	pub ttl_cutoff_height: Option<u64>,
	/// Type of slate - compact or legacy. That affects the build Tx workflow. Let's keep it
	/// Used for response slate validation
	#[serde(default = "default_true")]
	pub compact_slate: bool,
	/// Domain-separated fingerprint of the aggregate signing request to which
	/// this context's secret nonce has been committed. Persisted before signing
	/// so a retry cannot reuse the nonce under a different Schnorr challenge.
	#[serde(default)]
	pub aggsig_challenge: Option<[u8; 32]>,
	/// Version of the persisted security invariants carried by this context.
	/// Version zero is the serde default for legacy contexts and does not prove
	/// that an unbound aggregate-signature nonce is unused.
	#[serde(default)]
	pub(crate) context_version: u32,
}

/// Context version one introduced durable aggregate-signature nonce binding.
const NONCE_BINDING_CONTEXT_VERSION: u32 = 1;
/// Latest context invariant version understood by this wallet.
pub(crate) const CURRENT_CONTEXT_VERSION: u32 = NONCE_BINDING_CONTEXT_VERSION;

fn default_true() -> bool {
	true
}

impl Context {
	/// Create a new context, the secret will be generated. It is a normal way of context cretion since
	/// Lock later & compact slate was introduced
	pub fn new(
		secp: &secp::Secp256k1,
		parent_key_id: &Identifier,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		#[cfg(feature = "test-support")] is_initiator: bool,
		participant_id: usize,
		amount: u64,
		fee: u64,
		message: Option<String>,
		lock_height: u64,
		kernel_features: u8,
		ttl_cutoff_height: Option<u64>,
		compact_slate: bool,
	) -> Result<Context, Error> {
		#[cfg(feature = "test-support")]
		let sec_key = if use_test_rng {
			// allow for consistent test results
			let mut test_rng = if is_initiator {
				StepRng::new(1_234_567_890_u64, 1)
			} else {
				StepRng::new(1_234_567_891_u64, 1)
			};
			let mut bytes = [0u8; secp::constants::SECRET_KEY_SIZE];
			test_rng.try_fill_bytes(&mut bytes).map_err(|e| {
				Error::GenericError(format!("Unable to generate test secret key, {}", e))
			})?;
			SecretKey::from_slice(secp, &bytes)?
		} else {
			SecretKey::new(secp, &mut SysRng)?
		};
		#[cfg(not(feature = "test-support"))]
		let sec_key = SecretKey::new(secp, &mut SysRng)?;
		Self::with_excess(
			secp,
			sec_key,
			parent_key_id,
			#[cfg(feature = "test-support")]
			use_test_rng,
			participant_id,
			amount,
			fee,
			message,
			lock_height,
			kernel_features,
			ttl_cutoff_height,
			compact_slate,
		)
	}

	/// Create a new context from pregenerated secret key. Normal case for tests only.
	pub fn with_excess(
		secp: &secp::Secp256k1,
		sec_key: SecretKey,
		parent_key_id: &Identifier,
		#[cfg(feature = "test-support")] use_test_rng: bool,
		participant_id: usize,
		amount: u64,
		fee: u64,
		message: Option<String>,
		lock_height: u64,
		kernel_features: u8,
		ttl_cutoff_height: Option<u64>,
		compact_slate: bool,
	) -> Result<Context, Error> {
		#[cfg(feature = "test-support")]
		let sec_nonce = if use_test_rng {
			SecretKey::from_slice(secp, &[1; 32])?
		} else {
			aggsig::create_secnonce(secp)?
		};
		#[cfg(not(feature = "test-support"))]
		let sec_nonce = aggsig::create_secnonce(secp)?;
		Ok(Context {
			parent_key_id: parent_key_id.clone(),
			sec_key: sec_key.clone(),
			sec_nonce: sec_nonce.clone(),
			initial_sec_key: sec_key.clone(),
			initial_sec_nonce: sec_nonce.clone(),
			input_ids: vec![],
			output_ids: vec![],
			output_build_heights: vec![],
			amount,
			fee,
			participant_id: participant_id,
			payment_proof_derivation_index: None,
			payment_proof_recipient_address: None,
			output_commits: vec![],
			input_commits: vec![],
			late_lock_args: None,
			calculated_excess: None,
			message,
			lock_height,
			kernel_features,
			ttl_cutoff_height,
			compact_slate,
			aggsig_challenge: None,
			context_version: CURRENT_CONTEXT_VERSION,
		})
	}

	/// Call it if you really understand what you are doing. This method will not be able to
	/// construct valid context. Currently it is used for processing lock for non standard slates.
	pub fn from_send_slate(
		slate: &Slate,
		nonce: SecretKey,
		input_ids: Vec<(Identifier, Option<u64>, u64)>,
		output_ids: Vec<(Identifier, Option<u64>, u64)>,
		parent_key_id: Identifier,
		participant_id: usize,
	) -> Result<Context, Error> {
		Ok(Context {
			parent_key_id,
			initial_sec_key: ZERO_KEY, // Not needed
			initial_sec_nonce: nonce.clone(),
			sec_key: ZERO_KEY, // Not needed
			sec_nonce: nonce.clone(),
			// Id, mmr_index (if known), amount
			input_ids,
			output_ids,
			output_build_heights: vec![],
			amount: slate.amount,
			fee: slate.fee,
			participant_id,
			payment_proof_derivation_index: None,
			payment_proof_recipient_address: None,
			output_commits: slate
				.tx_or_err()?
				.body
				.outputs_committed()?
				.collect::<Result<Vec<_>, _>>()?,
			input_commits: slate
				.tx_or_err()?
				.body
				.inputs_committed()?
				.collect::<Result<Vec<_>, _>>()?,
			calculated_excess: None,
			late_lock_args: None,
			message: None,
			lock_height: slate.get_lock_height(),
			kernel_features: slate.get_kernel_features(),
			ttl_cutoff_height: slate.ttl_cutoff_height,
			compact_slate: slate.compact_slate,
			aggsig_challenge: None,
			// This constructor accepts a caller-supplied nonce and is not used for
			// aggregate signing, so it cannot assert the version-one nonce invariant.
			context_version: 0,
		})
	}
}

impl Context {
	/// Commit this context's secret signing nonce to one aggregate Schnorr
	/// challenge. Rebinding the same challenge is an idempotent success.
	pub(crate) fn bind_aggsig_challenge(&mut self, challenge: [u8; 32]) -> Result<(), Error> {
		if self.context_version > CURRENT_CONTEXT_VERSION {
			return Err(Error::SlateValidation(format!(
				"transaction context version {} is newer than supported version {}",
				self.context_version, CURRENT_CONTEXT_VERSION
			)));
		}

		match self.aggsig_challenge {
			Some(existing) if existing == challenge => {
				// A stored matching challenge proves safe reuse even for a version-zero
				// context. Upgrade that legacy representation to the current invariant.
				if self.context_version == 0 {
					self.context_version = NONCE_BINDING_CONTEXT_VERSION;
				}
				Ok(())
			}
			Some(_) => Err(Error::SlateValidation(
				"transaction signing nonce is already bound to a different aggregate challenge"
					.to_owned(),
			)),
			None
				if (NONCE_BINDING_CONTEXT_VERSION..=CURRENT_CONTEXT_VERSION)
					.contains(&self.context_version) =>
			{
				self.aggsig_challenge = Some(challenge);
				Ok(())
			}
			None => Err(Error::SlateValidation(
				"transaction signing nonce has unknown legacy usage; restart the transaction with a fresh context"
					.to_owned(),
			)),
		}
	}

	/// Validate is Slate params a valid. It is not expected that other peer changing the slate params.
	/// slate - response slate to process
	pub fn validate_slate(&self, slate: &Slate) -> Result<(), Error> {
		if slate.compact_slate != self.compact_slate {
			return Err(Error::SlateValidation(
				"compact_slate flag mismatch".to_string(),
			));
		}

		if self.compact_slate {
			if !(slate.amount == 0 || slate.amount == self.amount) {
				return Err(Error::SlateValidation("amount mismatch".to_string()));
			}
			if !(slate.fee == 0 || slate.fee == self.fee) {
				return Err(Error::SlateValidation("fee mismatch".to_string()));
			}
		} else {
			if slate.amount != self.amount {
				return Err(Error::SlateValidation("amount mismatch".to_string()));
			}
			if slate.fee != self.fee {
				return Err(Error::SlateValidation("fee mismatch".to_string()));
			}
			// Checking transaction...
			// Inputs must match exactly

			// Checking transaction...
			// Inputs must match exactly
			let mut slate_inputs = slate
				.tx_or_err()?
				.body
				.inputs_committed()?
				.collect::<Result<Vec<_>, _>>()?;
			slate_inputs.sort_unstable();
			let mut context_inputs = self.input_commits.clone();
			context_inputs.sort_unstable();

			if slate_inputs != context_inputs {
				return Err(Error::SlateValidation("inputs mismatch".to_string()));
			}

			// Respond outputs must include send_slate's change outputs. Expected that some was added
			let slate_outputs: Vec<Commitment> = slate
				.tx_or_err()?
				.body
				.outputs
				.clone()
				.into_iter()
				.map(|o| o.identifier.commit)
				.collect();

			for output in &self.output_commits {
				if !slate_outputs.contains(output) {
					return Err(Error::SlateValidation("outputs mismatch".to_string()));
				}
			}

			// Kernels must match exactly
			let kernels = &slate.tx_or_err()?.body.kernels;
			if kernels.len() != 1 {
				return Err(Error::SlateValidation(
					"kernels num mismatch, expecting one kernel".to_string(),
				));
			}

			let kernel = kernels.first().ok_or_else(|| {
				Error::SlateValidation("transaction kernel is missing".to_string())
			})?;
			match kernel.features {
				KernelFeatures::Plain { fee } => {
					if fee.fee() != self.fee {
						return Err(Error::SlateValidation("kernels fee mismatch".to_string()));
					}
				}
				_ => return Err(Error::SlateValidation("kernels type mismatch".to_string())),
			}
		}

		if slate.get_kernel_features() != self.kernel_features {
			return Err(Error::SlateValidation(
				"kernel_features mismatch".to_string(),
			));
		}
		if slate.get_lock_height() != self.lock_height {
			return Err(Error::SlateValidation("lock_height mismatch".to_string()));
		}
		if slate.ttl_cutoff_height != self.ttl_cutoff_height {
			return Err(Error::SlateValidation("ttl_cutoff mismatch".to_string()));
		}

		Ok(())
	}

	/// Validate an invoice response slate against this (issuer's) context.
	/// Unlike [`Context::validate_slate`], inputs, outputs, fee and kernels are
	/// not compared: for an invoice the payer legitimately adds them. What must
	/// not change is the exchange metadata fixed at issuance — the kernel
	/// policy the issuer is about to sign under.
	/// slate - response slate to process
	pub fn validate_invoice_slate(&self, slate: &Slate) -> Result<(), Error> {
		if slate.compact_slate != self.compact_slate {
			return Err(Error::SlateValidation(
				"compact_slate flag mismatch".to_string(),
			));
		}

		if self.compact_slate {
			// Compact slates may have the amount stripped in transit.
			if !(slate.amount == 0 || slate.amount == self.amount) {
				return Err(Error::SlateValidation("amount mismatch".to_string()));
			}
		} else if slate.amount != self.amount {
			return Err(Error::SlateValidation("amount mismatch".to_string()));
		}

		if slate.get_kernel_features() != self.kernel_features {
			return Err(Error::SlateValidation(
				"kernel_features mismatch".to_string(),
			));
		}
		if slate.get_lock_height() != self.lock_height {
			return Err(Error::SlateValidation("lock_height mismatch".to_string()));
		}
		if slate.ttl_cutoff_height != self.ttl_cutoff_height {
			return Err(Error::SlateValidation("ttl_cutoff mismatch".to_string()));
		}

		Ok(())
	}

	/// Tracks an output contributing to my excess value (if it needs to
	/// be kept between invocations
	pub fn add_output(&mut self, output_id: &Identifier, mmr_index: &Option<u64>, amount: u64) {
		self.output_ids
			.push((output_id.clone(), *mmr_index, amount));
	}

	/// Returns all stored outputs
	pub fn get_outputs(&self) -> Vec<(Identifier, Option<u64>, u64)> {
		self.output_ids.clone()
	}

	/// Tracks IDs of my inputs into the transaction
	/// be kept between invocations
	pub fn add_input(&mut self, input_id: &Identifier, mmr_index: &Option<u64>, amount: u64) {
		self.input_ids.push((input_id.clone(), *mmr_index, amount));
	}

	/// Returns all stored input identifiers
	pub fn get_inputs(&self) -> Vec<(Identifier, Option<u64>, u64)> {
		self.input_ids.clone()
	}

	/// Returns private key, private nonce
	pub fn get_private_keys(&self) -> (SecretKey, SecretKey) {
		(self.sec_key.clone(), self.sec_nonce.clone())
	}

	/// Returns public key, public nonce
	pub fn get_public_keys(&self, secp: &Secp256k1) -> Result<(PublicKey, PublicKey), Error> {
		Ok((
			PublicKey::from_secret_key(secp, &self.sec_key)?,
			PublicKey::from_secret_key(secp, &self.sec_nonce)?,
		))
	}
}

impl ser::Writeable for Context {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = sensitive::serialize_json(self).map_err(|e| {
			ser::Error::CorruptedData(format!("Context to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Context data length is {}",
				data.len()
			)));
		}

		writer.write_bytes(&data[..])
	}
}

impl ser::Readable for Context {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Context, ser::Error> {
		let data = Zeroizing::new(reader.read_bytes_len_prefix()?);
		serde_json::from_slice(data.as_slice()).map_err(|e| {
			ser::Error::CorruptedData(format!("json to Context conversion failed, {}", e))
		})
	}
}

/// Block Identifier
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct BlockIdentifier(pub Hash);

impl BlockIdentifier {
	/// return hash
	pub fn hash(&self) -> Hash {
		self.0
	}

	/// convert to hex string
	pub fn from_hex(hex: &str) -> Result<BlockIdentifier, Error> {
		let hash = Hash::from_hex(hex).map_err(|e| {
			Error::GenericError(format!("BlockIdentifier Invalid hex {}, {}", hex, e))
		})?;
		Ok(BlockIdentifier(hash))
	}
}

impl serde::ser::Serialize for BlockIdentifier {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> serde::de::Deserialize<'de> for BlockIdentifier {
	fn deserialize<D>(deserializer: D) -> Result<BlockIdentifier, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		deserializer.deserialize_str(BlockIdentifierVisitor)
	}
}

struct BlockIdentifierVisitor;

impl<'de> serde::de::Visitor<'de> for BlockIdentifierVisitor {
	type Value = BlockIdentifier;

	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("a block hash")
	}

	fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
	where
		E: serde::de::Error,
	{
		let block_hash = Hash::from_hex(s)
			.map_err(|e| serde::de::Error::custom(format!("Unable build Hash from HEX, {}", e)))?;
		Ok(BlockIdentifier(block_hash))
	}
}

/// a contained wallet info struct, so automated tests can parse wallet info
/// can add more fields here over time as needed
#[derive(Serialize, Eq, PartialEq, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct WalletInfo {
	/// height from which info was taken
	#[serde(with = "secp_ser::string_or_u64")]
	pub last_confirmed_height: u64,
	/// Minimum number of confirmations for an output to be treated as "spendable".
	#[serde(with = "secp_ser::string_or_u64")]
	pub minimum_confirmations: u64,
	/// total amount in the wallet
	#[serde(with = "secp_ser::string_or_u64")]
	pub total: u64,
	/// amount awaiting finalization
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_awaiting_finalization: u64,
	/// amount awaiting confirmation
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_awaiting_confirmation: u64,
	/// coinbases waiting for lock height
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_immature: u64,
	/// amount currently spendable
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_currently_spendable: u64,
	/// amount locked via previous transactions
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_locked: u64,
	/// amount previously confirmed, now reverted
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_reverted: u64,
}

/// Types of transactions that can be contained within a TXLog entry
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(crate = "serde")]
pub enum TxLogEntryType {
	/// A coinbase transaction becomes confirmed
	ConfirmedCoinbase,
	/// Outputs created when a transaction is received
	TxReceived,
	/// Inputs locked + change outputs when a transaction is created
	TxSent,
	/// Received transaction that was rolled back by user
	TxReceivedCancelled,
	/// Sent transaction that was rolled back by user
	TxSentCancelled,
	/// Received transaction that was reverted on-chain
	TxReverted,
}

impl fmt::Display for TxLogEntryType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			TxLogEntryType::ConfirmedCoinbase => write!(f, "Confirmed \nCoinbase"),
			TxLogEntryType::TxReceived => write!(f, "Received Tx"),
			TxLogEntryType::TxSent => write!(f, "Sent Tx"),
			TxLogEntryType::TxReceivedCancelled => write!(f, "Received Tx\n- Cancelled"),
			TxLogEntryType::TxSentCancelled => write!(f, "Sent Tx\n- Cancelled"),
			TxLogEntryType::TxReverted => write!(f, "Received Tx\n- Reverted"),
		}
	}
}

/// Identifies a wallet transaction whose stored transaction data should be loaded.
///
/// At least one field must be supplied. If multiple fields are supplied, they
/// must identify the same authoritative transaction-log entry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(crate = "serde")]
pub struct StoredTxLocator {
	/// Wallet-local numeric transaction-log ID.
	#[serde(default)]
	pub id: Option<u32>,
	/// Slate UUID associated with the transaction.
	#[serde(default)]
	pub tx_slate_id: Option<Uuid>,
	/// Stored transaction filename, never a path to open directly.
	#[serde(default)]
	pub stored_tx: Option<String>,
}

/// Optional transaction information, recorded when an event happens
/// to add or remove funds from a wallet. One Transaction log entry
/// maps to one or many outputs
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct TxLogEntry {
	/// BIP32 account path used for creating this tx
	pub parent_key_id: Identifier,
	/// Local id for this transaction (distinct from a slate transaction id)
	pub id: u32,
	/// Slate transaction this entry is associated with, if any
	pub tx_slate_id: Option<Uuid>,
	/// Transaction type (as above)
	pub tx_type: TxLogEntryType,
	/// Address of the other party
	#[serde(default)]
	pub address: Option<String>,
	/// Time this tx entry was created
	/// #[serde(with = "tx_date_format")]
	pub creation_ts: DateTime<Utc>,
	/// Time this tx was confirmed (by this wallet)
	/// #[serde(default, with = "opt_tx_date_format")]
	pub confirmation_ts: Option<DateTime<Utc>>,
	/// Whether the inputs+outputs involved in this transaction have been
	/// confirmed (In all cases either all outputs involved in a tx should be
	/// confirmed, or none should be; otherwise there's a deeper problem)
	pub confirmed: bool,
	/// height of confirmed output.
	/// Users want to see that in there transaction list
	#[serde(default = "TxLogEntry::default_output_height")]
	pub output_height: u64,
	/// number of inputs involved in TX
	pub num_inputs: usize,
	/// number of outputs involved in TX
	pub num_outputs: usize,
	/// Amount credited via this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_credited: u64,
	/// Amount debited via this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_debited: u64,
	/// Fee
	#[serde(with = "secp_ser::opt_string_or_u64")]
	pub fee: Option<u64>,
	/// Cutoff block height
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_cutoff_height: Option<u64>,
	/// Message data, stored as json
	pub messages: Option<ParticipantMessages>,
	/// Location of the store transaction, (reference or resending)
	pub stored_tx: Option<String>,
	/// Associated kernel excess, for later lookup if necessary
	#[serde(with = "secp_ser::option_commitment_serde")]
	#[serde(default)]
	pub kernel_excess: Option<pedersen::Commitment>,
	/// Associated kernel offset, for later lookup if necessary
	#[serde(with = "secp_ser::option_commitment_serde")]
	#[serde(default)]
	pub kernel_offset: Option<pedersen::Commitment>,
	/// Height reported when transaction was created, if lookup
	/// of kernel is necessary
	#[serde(default)]
	pub kernel_lookup_min_height: Option<u64>,
	/// Input commits as Strings, defined by send
	#[serde(default = "TxLogEntry::default_commits")]
	pub input_commits: Vec<pedersen::Commitment>,
	/// Output commits as Strings, defined for send & recieve
	#[serde(default = "TxLogEntry::default_commits")]
	pub output_commits: Vec<pedersen::Commitment>,
	/// Track the time it took for a transaction to get reverted
	#[serde(with = "option_duration_as_secs", default)]
	pub reverted_after: Option<Duration>,
}

impl From<&TxLogEntry> for StoredTxLocator {
	fn from(entry: &TxLogEntry) -> Self {
		Self {
			id: Some(entry.id),
			tx_slate_id: entry.tx_slate_id,
			stored_tx: entry.stored_tx.clone(),
		}
	}
}

impl TxLogEntry {
	fn serialized_for_storage(&self) -> Result<Vec<u8>, ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("TxLogEntry to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"TxLogEntry data length is {}",
				data.len()
			)));
		}
		Ok(data)
	}
}

impl ser::Writeable for TxLogEntry {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = self.serialized_for_storage()?;
		writer.write_bytes(&data)
	}
}

impl ser::Readable for TxLogEntry {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<TxLogEntry, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to TxLogEntry conversion failed, {}", e))
		})
	}
}

impl TxLogEntry {
	/// Return a new blank with TS initialised with next entry
	pub fn new(parent_key_id: Identifier, t: TxLogEntryType, id: u32) -> Self {
		TxLogEntry {
			parent_key_id: parent_key_id,
			tx_type: t,
			address: None,
			id: id,
			tx_slate_id: None,
			creation_ts: Utc::now(),
			confirmation_ts: None,
			confirmed: false,
			output_height: 0,
			amount_credited: 0,
			amount_debited: 0,
			num_inputs: 0,
			num_outputs: 0,
			fee: None,
			ttl_cutoff_height: None,
			messages: None,
			stored_tx: None,
			kernel_excess: None,
			kernel_offset: None,
			kernel_lookup_min_height: None,
			input_commits: vec![],
			output_commits: vec![],
			reverted_after: None,
		}
	}

	/// Build a new instance from the data. Needed for
	pub fn new_from_data(
		parent_key_id: Identifier,
		id: u32,
		tx_slate_id: Option<Uuid>,
		tx_type: TxLogEntryType,
		address: Option<String>,
		creation_ts: DateTime<Utc>,
		confirmation_ts: Option<DateTime<Utc>>,
		confirmed: bool,
		output_height: u64,
		num_inputs: usize,
		num_outputs: usize,
		amount_credited: u64,
		amount_debited: u64,
		fee: Option<u64>,
		ttl_cutoff_height: Option<u64>,
		messages: Option<ParticipantMessages>,
		stored_tx: Option<String>,
		kernel_excess: Option<pedersen::Commitment>,
		kernel_offset: Option<pedersen::Commitment>,
		kernel_lookup_min_height: Option<u64>,
		input_commits: Vec<pedersen::Commitment>,
		output_commits: Vec<pedersen::Commitment>,
	) -> Self {
		TxLogEntry {
			parent_key_id,
			tx_type,
			address,
			id,
			tx_slate_id,
			creation_ts,
			confirmation_ts,
			confirmed,
			output_height,
			amount_credited,
			amount_debited,
			num_inputs,
			num_outputs,
			fee,
			ttl_cutoff_height,
			messages,
			stored_tx,
			kernel_excess,
			kernel_offset,
			kernel_lookup_min_height,
			input_commits,
			output_commits,
			reverted_after: None,
		}
	}

	/// Given a vec of TX log entries, return credited + debited sums
	pub fn sum_confirmed(txs: &[TxLogEntry]) -> Result<(u64, u64), Error> {
		let mut credited: u64 = 0;
		let mut debited: u64 = 0;
		for tx in txs.iter().filter(|tx| tx.confirmed) {
			credited = credited.checked_add(tx.amount_credited).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxLogEntry::sum_confirmed, confirmed credited amount overflow, credited={} amount_credited={}",
					credited, tx.amount_credited
				))
			})?;
			debited = debited.checked_add(tx.amount_debited).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxLogEntry::sum_confirmed, confirmed debited amount overflow, debited={} amount_debited={}",
					debited, tx.amount_debited
				))
			})?;
		}
		Ok((credited, debited))
	}

	/// Update confirmation TS with now
	pub fn update_confirmation_ts(&mut self, time: String) -> Result<(), Error> {
		//
		if time.is_empty() {
			self.confirmation_ts = Some(Utc::now());
		} else {
			//sample time string: 2020-10-07T23:57:00+00:00
			let time_converted = DateTime::parse_from_rfc3339(&time).map_err(|e| {
				Error::GenericError(format!("Invalid time to parse: {}, {}", time, e))
			})?;
			let time_stamp = time_converted.timestamp();
			let confirmed_t = Utc.timestamp_opt(time_stamp, 0).single().ok_or_else(|| {
				Error::GenericError(format!("Invalid UNIX timestamp: {}", time_stamp))
			})?;
			self.confirmation_ts = Some(confirmed_t);
		}
		Ok(())
	}

	/// Return zero height - mean unknown. Needed for backward compatibility
	pub fn default_output_height() -> u64 {
		0
	}

	/// Return empty vector for older TxLog transactions
	pub fn default_commits() -> Vec<pedersen::Commitment> {
		vec![]
	}

	/// Return true if transaction cancelled
	pub fn is_cancelled(&self) -> bool {
		return self.tx_type == TxLogEntryType::TxReceivedCancelled
			|| self.tx_type == TxLogEntryType::TxSentCancelled;
	}

	/// Return true if transaction cancelled or reverted ()
	pub fn is_cancelled_reverted(&self) -> bool {
		return self.tx_type == TxLogEntryType::TxReceivedCancelled
			|| self.tx_type == TxLogEntryType::TxSentCancelled
			|| self.tx_type == TxLogEntryType::TxReverted;
	}

	/// Un Cancel transaction
	pub fn uncancel_unrevert(&mut self) {
		self.tx_type = match &self.tx_type {
			TxLogEntryType::TxReverted | TxLogEntryType::TxReceivedCancelled => {
				self.reverted_after = None;
				TxLogEntryType::TxReceived
			}
			TxLogEntryType::TxSentCancelled => TxLogEntryType::TxSent,
			any => any.clone(),
		};
		self.ttl_cutoff_height = None;
	}

	/// Append message from the slate.
	pub fn update_messages(&mut self, messages: &ParticipantMessages) {
		match &self.messages {
			None => self.messages = Some(messages.clone()),
			Some(exist_messages_obj) => {
				let exist_messages = &exist_messages_obj.messages;
				let mut messages = messages.clone();
				for msg in exist_messages {
					if !messages.messages.iter().any(|m| {
						m.message.as_ref().map(|m| m.len()).unwrap_or(0) > 0 && m.id == msg.id
					}) {
						messages.messages.push(msg.clone());
					}
				}
				messages.messages.sort_by_key(|m| m.id);
				self.messages = Some(messages.clone());
			}
		}
	}
}

/// Map of named accounts to BIP32 paths
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct AcctPathMapping {
	/// label used by user
	pub label: String,
	/// Corresponding parent BIP32 derivation path
	pub path: Identifier,
}

impl ser::Writeable for AcctPathMapping {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("AcctPathMapping to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"AcctPathMapping data length is {}",
				data.len()
			)));
		}
		writer.write_bytes(&data)
	}
}

impl ser::Readable for AcctPathMapping {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<AcctPathMapping, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to AcctPathMapping conversion failed, {}", e))
		})
	}
}

/// Store details of the last scanned block
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct ScannedBlockInfo {
	/// Node chain height (corresponding to the last PMMR index scanned)
	pub height: u64,
	/// Hash of tip
	pub hash: String,
}

impl ScannedBlockInfo {
	/// Create new Block info
	pub fn new(height: u64, hash: String) -> ScannedBlockInfo {
		ScannedBlockInfo { height, hash }
	}
	/// Create empty instance of the scanned Block info
	pub fn empty() -> ScannedBlockInfo {
		ScannedBlockInfo::new(0, String::new())
	}
}

impl ser::Writeable for ScannedBlockInfo {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!(
				"ScannedBlockInfo for json conversion failed, {}",
				e
			))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"ScannedBlockInfo data length is {}",
				data.len()
			)));
		}
		writer.write_bytes(&data)
	}
}

impl ser::Readable for ScannedBlockInfo {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<ScannedBlockInfo, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to ScannedBlockInfo conversion failed, {}", e))
		})
	}
}

/// Mining response with an ordinary reward output and an S2C-bound kernel.
/// The opening is mandatory, including before consensus activation.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct CbData {
	/// Output
	pub output: Output,
	/// Kernel
	pub kernel: TxKernel,
	/// Key Id
	pub key_id: Option<Identifier>,
	/// Compressed S2C opening, serialized as exactly 66 hexadecimal characters.
	pub coinbase_opening: secp::s2c::Opening,
}

/// Header Info data, used by HTTP client
#[derive(Clone)]
pub struct HeaderInfo {
	/// Height of the header
	pub height: u64,
	/// Header Hash
	pub hash: String,
	/// Header timestamp
	pub confirmed_time: String,
	/// Header version
	pub version: i32,
	/// Header nonce
	pub nonce: u64,
	/// total chain difficulty for this header
	pub total_difficulty: u64,
}

/// A chain height bound together with the hash of the header at that height.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainTip {
	/// Height of the anchored header.
	pub height: u64,
	/// Hash of the anchored header.
	pub hash: String,
}

/// Hash-linked header metadata for checking a body tip's ancestry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeHeaderLink {
	/// Height of the requested block.
	pub height: u64,
	/// Hash of the requested block.
	pub hash: String,
	/// Hash of its parent block.
	pub previous: String,
}

/// Utility struct for return values from below
#[derive(Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct ViewWallet {
	/// Rewind Hash used to retrieve the outputs. A viewing credential: it
	/// discloses the wallet's outputs and balance, so it is zeroized on drop.
	pub rewind_hash: Zeroizing<String>,
	/// Outputs whose rangeproofs match the rewind hash. A match does not prove
	/// that the wallet knows the output blinding factor or can spend the output.
	pub output_result: Vec<ViewWalletOutputResult>,
	/// Sum of the rewind-matched output values; not an authenticated wallet balance.
	pub total_balance: u64,
	/// last pmmr index
	pub last_pmmr_index: u64,
}
/// Utility struct for return values from below
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct ViewWalletOutputResult {
	///
	pub commit: String,
	///
	pub value: u64,
	///
	pub height: u64,
	///
	pub mmr_index: u64,
	///
	pub is_coinbase: bool,
	///
	pub lock_height: u64,
}

impl ViewWalletOutputResult {
	/// Return number of confirmations.
	pub fn num_confirmations(&self, tip_height: u64) -> u64 {
		if self.height > tip_height {
			return 0;
		} else {
			// self.height <= tip_height above. Protocol block heights cannot approach u64::MAX.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "height ordering is checked and protocol block heights cannot approach u64::MAX"
			)]
			{
				tip_height - self.height + 1
			}
		}
	}
}

/// Data delivered to a receive callback after the receive becomes durable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct ReceiveData {
	/// Wallet context that received the transaction.
	pub(crate) context_id: u32,
	/// Received slate UUID.
	pub(crate) tx_uuid: String,
	/// Display form of the sender.
	pub(crate) from: String,
	/// Received amount.
	pub(crate) amount: u64,
	/// Optional participant message.
	pub(crate) message: Option<String>,
}

/// Transaction session. Used to handle online single session transaction. Idea that
/// we don't want Tx Private context be permanent and open the door for some manipulations.
/// Thoretically if Tx Private context, transaction can be finished. If it is not sored, nothing can be done.
pub struct TxSession {
	// Context & participant Id. Note there is a single participant. For self transaciton create two sessions for both hands.
	context: Option<(Context, usize)>,
	// Log entry
	tx_log_entry: Option<TxLogEntry>,
	// Outputs to create in the storage
	outputs: Vec<OutputData>,
	// Input commits to lock and assign to this transaction (id, mmr, commit, amount)
	input_commits: Vec<(Identifier, Option<u64>, Commitment, u64)>,
	// Transacxtion to store in the wallet
	transaction: Option<Transaction>,
	// Identity whose lifetime owns this session's process-local input reservations.
	reservation_owner: Arc<()>,
}

lazy_static! {
	// No need to have context_id because commits are unique. TxSession and the
	// sessionless invoice processing guard share this collection.
	static ref TX_INPUT_RESERVATIONS: RwLock<HashMap<String, Weak<()>>> =
		RwLock::new(HashMap::new());
}

/// Atomically reserve commitments for one live transaction owner. Validate the
/// complete set before inserting anything so a conflict cannot leave a partial
/// reservation behind.
pub(crate) fn reserve_input_commits<'a, I>(owner: &Arc<()>, commits: I) -> Result<(), Error>
where
	I: IntoIterator<Item = &'a Commitment>,
{
	let commits = commits
		.into_iter()
		.map(|commit| commit.to_hex())
		.collect::<Vec<_>>();
	let mut used_inputs = TX_INPUT_RESERVATIONS.write();
	// Locked or spent outputs stop consulting input_is_free, so reclaim stale
	// entries here as well as on direct lookup to keep this map bounded.
	used_inputs.retain(|_, weak| weak.strong_count() > 0);
	for commit in &commits {
		if let Some(existing) = used_inputs.get(commit).and_then(|weak| weak.upgrade()) {
			if !Arc::ptr_eq(&existing, owner) {
				return Err(Error::GenericError(format!(
					"input {} is already reserved by another live transaction",
					commit
				)));
			}
		}
	}
	for commit in commits {
		used_inputs.insert(commit, Arc::downgrade(owner));
	}
	Ok(())
}

/// Returns `true` if the given commitment is **not** reserved by a live
/// transaction session or Slate processing guard.
pub fn input_is_free(commit: &String) -> bool {
	let mut map = TX_INPUT_RESERVATIONS.write();
	// Look up the commitment.
	match map.get(commit) {
		Some(weak) => {
			if weak.upgrade().is_some() {
				false // still locked, can't be used
			} else {
				map.remove(commit);
				true // prev allocator is dead, can be used
			}
		}
		None => true, // not present, so can be used
	}
}

impl TxSession {
	/// Create new empty instance
	pub fn new() -> Self {
		TxSession {
			context: None,
			tx_log_entry: None,
			outputs: Vec::new(),
			input_commits: Vec::new(),
			transaction: None,
			reservation_owner: Arc::new(()),
		}
	}

	/// Check if context is empty
	pub fn is_empty(&self) -> bool {
		self.context.is_none()
			&& self.tx_log_entry.is_none()
			&& self.transaction.is_none()
	}

	/// Get Context & participant Id. Note there is a single participant. For self transaciton create two sessions for both hands.
	pub fn get_context_participant(&self) -> &Option<(Context, usize)> {
		&self.context
	}

	/// Set Context & participant Id
	pub fn set_context_participant(&mut self, context: Context, participant_id: usize) {
		self.context = Some((context, participant_id));
	}

	/// Clean context data
	pub fn clear_context_participant(&mut self) {
		self.context = None;
	}

	/// Get Log entry
	pub fn get_tx_log_entry(&self) -> &Option<TxLogEntry> {
		&self.tx_log_entry
	}

	/// Get mutable log entry
	pub fn get_mut_tx_log_entry(&mut self) -> &mut Option<TxLogEntry> {
		&mut self.tx_log_entry
	}

	/// Set log entry data
	pub fn set_tx_log_entry(&mut self, log_entry: TxLogEntry) {
		self.tx_log_entry = Some(log_entry);
	}

	/// Validate the deterministic TxLogEntry serialization before publishing
	/// the staged transaction or response. Use the largest possible persisted
	/// log id so assigning the real id cannot cross the storage-size boundary.
	pub fn validate_tx_log_entry_size(&self) -> Result<(), Error> {
		if let Some(tx_log_entry) = &self.tx_log_entry {
			let mut tx_log_entry = tx_log_entry.clone();
			tx_log_entry.id = u32::MAX;
			tx_log_entry.serialized_for_storage()?;
		}
		Ok(())
	}

	/// Get Outputs to create in the storage
	pub fn get_outputs(&self) -> &Vec<OutputData> {
		&self.outputs
	}

	/// Set transaction's outputs
	pub fn set_outputs(&mut self, outputs: Vec<OutputData>) {
		self.outputs = outputs;
	}

	/// Input commits to lock and assign to this transaction (id, mmr, commit, amount)
	pub fn get_input_commits(&self) -> &Vec<(Identifier, Option<u64>, Commitment, u64)> {
		&self.input_commits
	}
	/// Se locked inputs
	pub fn set_input_commits(
		&mut self,
		inputs: Vec<(Identifier, Option<u64>, Commitment, u64)>,
	) -> Result<(), Error> {
		reserve_input_commits(
			&self.reservation_owner,
			inputs.iter().map(|(_id, _mmr, commit, _amount)| commit),
		)?;
		self.input_commits = inputs;
		Ok(())
	}

	/// Re-read every staged input from persistent wallet storage and ensure it
	/// still identifies the same spendable output. A live-session reservation
	/// prevents new in-process selections, but it is not authoritative once a
	/// competing session has committed or another wallet process has changed the
	/// database.
	pub fn validate_inputs<'a, T: ?Sized, C, K>(
		&self,
		wallet: &T,
		slate_id: &Uuid,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		validate_deferred_inputs(wallet, &self.input_commits, slate_id)
	}

	/// Get Transacxtion to store in the wallet
	pub fn get_transaction(&self) -> &Option<Transaction> {
		&self.transaction
	}

	/// Set transaction data
	pub fn set_transaction(&mut self, transaction: Transaction) {
		self.transaction = Some(transaction);
	}

	/// Save transaction session data after every transaction step succeeded.
	///
	/// Most callers persist the session LAST by design, only after the step that
	/// makes the transaction real has succeeded: the response slate was handed
	/// to the counterparty, or the node acknowledged the finalized
	/// transaction. The motivation is TxSession's core invariant (see the
	/// struct documentation): the private context must not become durable for
	/// a transaction that never completed.
	///
	/// A finalized, context-free transaction may instead be persisted before node
	/// submission when a failed post should leave an ordinary pending transaction
	/// for the user to repost or cancel. Replay-mitigation self-sends use that
	/// ordering so their inputs remain locked after an ambiguous node response.
	///
	/// This ordering is a deliberate trade-off, NOT a correctness guarantee.
	/// An error from the publication step does not prove that nothing happened
	/// externally: a transport failure can occur after a node or the
	/// counterparty accepted the data, and the persistence step itself can
	/// fail after a successful publication. In those cases the wallet keeps no
	/// record of a transaction that may be live, and no local state remains to
	/// recover it from. Persisting first would retain that private state when
	/// publication actually succeeded, but `TxSession` does not durably store
	/// the exchange Slate for re-export. A genuine delivery failure would
	/// therefore leave a pending transaction that must be cancelled instead
	/// of allowing a clean retry. The wallet deliberately favors retryable
	/// error semantics and a smaller durable secret footprint; ambiguous
	/// post-publication failures remain an accepted risk. Avoiding both
	/// outcomes requires workflow-specific recovery semantics.
	pub fn save_tx_data<'a, T: ?Sized, C, K>(
		&mut self,
		secp: &Secp256k1,
		wallet: &mut T,
		keychain_mask: Option<&SecretKey>,
		slate_id: &Uuid,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		let mut batch = wallet.batch(secp, keychain_mask)?;
		self.save_tx_data_into_batch(&mut *batch, secp, slate_id)?;
		batch.commit()
	}

	/// Persist this session's transaction log entry, outputs, input locks and
	/// private context into an already-open backend batch, without committing
	/// it. Use this to persist several sessions (e.g. both sides of a
	/// self-send) atomically: write them all into one batch and commit once.
	///
	/// The ordering contract described by [`TxSession::save_tx_data`] applies.
	/// In particular, a save-first caller must have cleared private contexts and
	/// accept that a failed publication leaves a normal pending transaction.
	pub fn save_tx_data_into_batch<K>(
		&mut self,
		batch: &mut dyn WalletOutputBatch<K>,
		secp: &Secp256k1,
		slate_id: &Uuid,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		if let Some(tx_log_entry) = &self.tx_log_entry {
			if tx_log_entry.tx_type == TxLogEntryType::TxReceived {
				let existing_txs = batch.tx_log_iter()?.chain(batch.tx_log_archive_iter()?);
				validate_deferred_receive(tx_log_entry, existing_txs)?;
			}
		}

		if let Some(tx_log_entry) = &mut self.tx_log_entry {
			let log_id = batch.next_tx_log_id(&tx_log_entry.parent_key_id)?;
			tx_log_entry.id = log_id;
			batch.save_tx_log_entry(tx_log_entry.clone(), &tx_log_entry.parent_key_id)?;

			for out in &mut self.outputs {
				out.tx_log_entry = Some(log_id);
				batch.save(out.clone())?;
			}

			for (id, mmr, commit, amount) in &self.input_commits {
				let mut coin = batch.get(&id, &mmr)?;
				validate_deferred_input(&coin, commit, *amount, slate_id, None)?;
				coin.tx_log_entry = Some(log_id);
				batch.lock_output(&mut coin)?;
			}
		}

		if let Some((context, participant_id)) = &self.context {
			batch.save_private_context(secp, slate_id.as_bytes(), *participant_id, context)?;
		}

		// Store the finalized transaction only after every other fallible batch
		// operation, while the backend write transaction still serializes
		// competing requests. The file must exist before the LMDB log which
		// references it is committed.
		if let (Some(tx_log_entry), Some(transaction)) = (&self.tx_log_entry, &self.transaction) {
			batch.store_tx(
				&tx_log_entry
					.tx_slate_id
					.ok_or(Error::GenericError("Tx UUID is expected".into()))?
					.to_string(),
				transaction,
			)?;
		}

		Ok(())
	}
}

/// Validate one input selected by a deferred transaction session.
///
/// `locked_by_tx_log_id` is used only by the durable, sessionless lock path to
/// make repeated locking of the same transaction idempotent. Deferred sessions
/// must always observe an available persistent output before finalizing.
pub(crate) fn validate_deferred_input(
	coin: &OutputData,
	expected_commit: &Commitment,
	expected_amount: u64,
	slate_id: &Uuid,
	locked_by_tx_log_id: Option<u32>,
) -> Result<(), Error> {
	let available = coin.status == OutputStatus::Unspent
		|| (coin.status == OutputStatus::Unconfirmed && !coin.is_coinbase);
	let already_locked_by_this_tx = coin.status == OutputStatus::Locked
		&& locked_by_tx_log_id.is_some()
		&& coin.tx_log_entry == locked_by_tx_log_id;
	let expected_commit_hex = expected_commit.to_hex();
	let stored_commit_changed = coin
		.commit
		.as_deref()
		.map(|commit| commit != expected_commit_hex.as_str())
		.unwrap_or(false);

	if (!available && !already_locked_by_this_tx)
		|| coin.value != expected_amount
		|| stored_commit_changed
	{
		return Err(Error::TransactionInputConflict(slate_id.to_string()));
	}
	Ok(())
}

/// Re-read a deferred session's inputs from the authoritative wallet backend.
pub(crate) fn validate_deferred_inputs<'a, T: ?Sized, C, K>(
	wallet: &T,
	inputs: &[(Identifier, Option<u64>, Commitment, u64)],
	slate_id: &Uuid,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for (id, mmr, commit, amount) in inputs {
		let coin = wallet.get(id, mmr)?;
		validate_deferred_input(&coin, commit, *amount, slate_id, None)?;
	}
	Ok(())
}

/// Revalidate a deferred receive against the transaction-log snapshot belonging
/// to the write batch that will persist it. Doing this before allocating a log
/// ID or writing outputs closes the check-to-commit race in `receive_tx`.
fn validate_deferred_receive<I>(pending: &TxLogEntry, existing_txs: I) -> Result<(), Error>
where
	I: Iterator<Item = TxLogEntry>,
{
	let slate_id = pending.tx_slate_id.ok_or_else(|| {
		Error::GenericError("A received transaction must have a slate UUID".to_owned())
	})?;

	for existing in existing_txs.filter(|tx| tx.tx_slate_id == Some(slate_id)) {
		// A slate UUID identifies one receive across the entire wallet. Accounts
		// are storage subdivisions, not independent UUID namespaces.
		if existing.tx_type == TxLogEntryType::TxReceived {
			return Err(Error::TransactionAlreadyReceived(slate_id.to_string()));
		}

		// A self-send legitimately has a TxSent in one account and a TxReceived
		// in another with the same UUID and offset. Preserve the established
		// account-local offset check while making receive uniqueness wallet-wide.
		if existing.parent_key_id != pending.parent_key_id {
			continue;
		}

		if let Some(existing_offset) = existing.kernel_offset {
			let Some(pending_offset) = pending.kernel_offset.as_ref() else {
				return Err(Error::SlateValidation(format!(
					"Transaction {} has a zero offset but a stored kernel offset exists",
					slate_id
				)));
			};

			if &existing_offset == pending_offset {
				return Err(Error::TransactionWithSameOffsetAlreadyReceived(
					existing_offset.to_hex(),
				));
			}
		}
	}

	Ok(())
}

/// Truncate `s` to at most `max_len` bytes, rounding the cut point down to a
/// UTF-8 character boundary. `String::truncate` panics when the byte index
/// splits a multibyte character, so untrusted or user-supplied messages must
/// go through this helper instead.
pub fn truncate_to_char_boundary(s: &mut String, max_len: usize) {
	if s.len() > max_len {
		let mut idx = max_len;
		while !s.is_char_boundary(idx) {
			idx -= 1;
		}
		s.truncate(idx);
	}
}

/// Escape control characters using JSON-compatible `\uXXXX` sequences so that
/// untrusted text (e.g. slate participant messages) is safe to write to logs,
/// the terminal, or an already-serialized JSON string. Newlines would forge
/// log entries and ANSI/OSC escape sequences can alter terminal state.
/// Unicode Bidi_Control format characters are escaped as well: they are
/// general category Cf, which `char::is_control` does not report, but
/// terminals apply them and can visually reorder or conceal peer-controlled
/// text (Trojan Source style spoofing).
/// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are escaped too: they
/// are categories Zl and Zp rather than controls, but Unicode-aware log and
/// terminal viewers can render them as line breaks.
pub fn escape_for_display(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		if c.is_control()
			|| is_bidi_control(c)
			|| matches!(c, '\u{2028}' | '\u{2029}')
		{
			// Every character filtered here is in the BMP, so one four-digit
			// JSON escape represents it.
			out.push_str(&format!("\\u{:04x}", c as u32));
		} else {
			out.push(c);
		}
	}
	out
}

/// Produce a bounded representation of untrusted text for logs and terminal
/// output. The input is truncated at a UTF-8 boundary before escaping so a
/// hostile value cannot cause unbounded display or log output.
pub fn bounded_escape_for_display(s: &str, max_len: usize) -> String {
	let mut end = s.len().min(max_len);
	while !s.is_char_boundary(end) {
		end = end.saturating_sub(1);
	}

	let mut out = escape_for_display(&s[..end]);
	if end < s.len() {
		out.push_str("...[truncated]");
	}
	out
}

/// The Unicode Bidi_Control property set (DerivedCoreProperties.txt): the
/// LRM/RLM/ALM marks, the embedding/override controls U+202A..U+202E, and
/// the isolate controls U+2066..U+2069.
fn is_bidi_control(c: char) -> bool {
	matches!(
		c,
		'\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
	)
}

/// Serializes an Option<Duration> to and from a string
pub mod option_duration_as_secs {
	use mwc_wallet_util::mwc_crates::serde::de::Error;
	use mwc_wallet_util::mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use std::time::Duration;

	///
	pub fn serialize<S>(dur: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match dur {
			Some(dur) => serializer.serialize_str(&format!("{}", dur.as_secs())),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
	where
		D: Deserializer<'de>,
	{
		match Option::<String>::deserialize(deserializer)? {
			Some(s) => {
				let secs = s
					.parse::<u64>()
					.map_err(|err| Error::custom(err.to_string()))?;
				Ok(Some(Duration::from_secs(secs)))
			}
			None => Ok(None),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InitTxArgs, InitTxSendArgs};
	use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
	use mwc_wallet_util::mwc_crates::serde_json::{self, Value};
	use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
	use mwc_wallet_util::mwc_keychain::ExtKeychainPath;

	#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
	#[serde(crate = "serde")]
	struct TestSer {
		#[serde(with = "option_duration_as_secs", default)]
		dur: Option<Duration>,
	}

	#[test]
	fn stored_tx_locator_preserves_each_optional_locator() {
		let slate_id = Uuid::new_v4();
		let locator: StoredTxLocator = serde_json::from_value(serde_json::json!({
			"stored_tx": "transaction.mwctx",
			"tx_slate_id": slate_id,
			"confirmed": true,
		}))
		.unwrap();

		assert_eq!(locator.id, None);
		assert_eq!(locator.tx_slate_id, Some(slate_id));
		assert_eq!(locator.stored_tx.as_deref(), Some("transaction.mwctx"));

		let locator: StoredTxLocator =
			serde_json::from_value(serde_json::json!({ "id": 0 })).unwrap();
		assert_eq!(locator.id, Some(0));
		assert_eq!(locator.tx_slate_id, None);
		assert_eq!(locator.stored_tx, None);
	}

	#[test]
	fn legacy_late_lock_context_drops_transport_credentials_when_rewritten() {
		const API_SECRET: &str = "late-lock-api-secret-sentinel";
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let context = Context::new(
			&secp,
			&Identifier::zero(),
			#[cfg(feature = "test-support")]
			false,
			#[cfg(feature = "test-support")]
			true,
			0,
			25,
			1,
			Some("late lock".to_owned()),
			0,
			0,
			None,
			true,
		)
		.unwrap();
		let legacy_args = InitTxArgs {
			amount: 25,
			minimum_confirmations: 3,
			max_outputs: 17,
			num_change_outputs: 2,
			selection_strategy_is_use_all: true,
			message: Some("late lock".to_owned()),
			target_slate_version: Some(4),
			ttl_blocks: Some(12),
			late_lock: Some(true),
			address: Some("receiver.example".to_owned()),
			exclude_change_outputs: Some(true),
			minimum_confirmations_change_outputs: 4,
			outputs: Some(["0300000000000000000000000000000000".to_owned()].into()),
			min_fee: Some(9),
			send_args: Some(InitTxSendArgs {
				method: "http".to_owned(),
				dest: "https://receiver.example/v2/foreign".to_owned(),
				apisecret: Some(Zeroizing::new(API_SECRET.to_owned())),
				finalize: false,
				post_tx: false,
				fluff: false,
			}),
			..InitTxArgs::default()
		};
		let projected = LateLockArgs::from(&legacy_args);
		assert_eq!(projected.minimum_confirmations, 3);
		assert_eq!(projected.max_outputs, 17);
		assert_eq!(projected.num_change_outputs, 2);
		assert!(projected.selection_strategy_is_use_all);
		assert_eq!(projected.ttl_blocks, Some(12));
		assert_eq!(projected.exclude_change_outputs, Some(true));
		assert_eq!(projected.minimum_confirmations_change_outputs, 4);
		assert_eq!(projected.outputs.as_ref().map(|outputs| outputs.len()), Some(1));
		assert_eq!(projected.min_fee, Some(9));
		let projected_json = serde_json::to_vec(&projected).unwrap();
		assert!(!projected_json
			.windows(API_SECRET.len())
			.any(|window| window == API_SECRET.as_bytes()));

		// Model a record written by the old Context schema by inserting the
		// complete InitTxArgs object into an otherwise current Context value.
		let mut legacy_value = serde_json::to_value(&context).unwrap();
		legacy_value["late_lock_args"] = serde_json::to_value(&legacy_args).unwrap();
		let legacy_json = serde_json::to_vec(&legacy_value).unwrap();
		assert!(legacy_json
			.windows(API_SECRET.len())
			.any(|window| window == API_SECRET.as_bytes()));

		// Unknown legacy fields are accepted, but only LateLockArgs survives.
		let restored: Context = serde_json::from_slice(&legacy_json).unwrap();
		let late_lock_args = restored.late_lock_args.as_ref().unwrap();
		assert_eq!(late_lock_args.address.as_deref(), Some("receiver.example"));
		assert_eq!(late_lock_args.message.as_deref(), Some("late lock"));

		let rewritten_json = serde_json::to_vec(&restored).unwrap();
		assert!(!rewritten_json
			.windows(API_SECRET.len())
			.any(|window| window == API_SECRET.as_bytes()));
		assert!(!String::from_utf8(rewritten_json)
			.unwrap()
			.contains("send_args"));
	}

	#[test]
	fn sum_confirmed_rejects_amount_overflow() {
		let mut first = TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxReceived, 1);
		first.confirmed = true;
		first.amount_credited = u64::MAX;
		let mut second = TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxReceived, 2);
		second.confirmed = true;
		second.amount_credited = 1;

		match TxLogEntry::sum_confirmed(&[first, second]) {
			Err(Error::DataOverflow(message)) => {
				assert!(message.contains("TxLogEntry::sum_confirmed"));
				assert!(message.contains(&format!("credited={}", u64::MAX)));
				assert!(message.contains("amount_credited=1"));
			}
			other => panic!("expected operand-rich DataOverflow error, got {:?}", other),
		}
	}

	#[test]
	fn staged_tx_log_size_is_rejected_before_persistence() {
		let mut entry =
			TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxSent, 0);
		entry.address = Some("x".repeat(ser::READ_CHUNK_LIMIT));
		let mut session = TxSession::new();
		session.set_tx_log_entry(entry);

		assert!(matches!(
			session.validate_tx_log_entry_size(),
			Err(Error::Deser(ser::Error::TooLargeWriteErr(_)))
		));
	}

	#[test]
	fn deferred_input_validation_rejects_changed_persistent_state() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let commit = secp
			.commit(10, SecretKey::from_slice(&secp, &[21; 32]).unwrap())
			.unwrap();
		let slate_id = Uuid::new_v4();
		let mut coin = OutputData {
			root_key_id: Identifier::zero(),
			key_id: Identifier::zero(),
			n_child: 0,
			commit: Some(commit.to_hex()),
			mmr_index: Some(1),
			value: 10,
			status: OutputStatus::Unspent,
			height: 1,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(3),
		};

		assert!(validate_deferred_input(&coin, &commit, 10, &slate_id, None).is_ok());

		coin.status = OutputStatus::Locked;
		assert!(matches!(
			validate_deferred_input(&coin, &commit, 10, &slate_id, None),
			Err(Error::TransactionInputConflict(id)) if id == slate_id.to_string()
		));
		// The durable sessionless path remains idempotent for an output already
		// locked by this same transaction log entry.
		assert!(validate_deferred_input(&coin, &commit, 10, &slate_id, Some(3)).is_ok());

		coin.status = OutputStatus::Unspent;
		coin.value = 11;
		assert!(matches!(
			validate_deferred_input(&coin, &commit, 10, &slate_id, None),
			Err(Error::TransactionInputConflict(_))
		));
	}

	#[test]
	fn used_inputs_of_dead_sessions_are_pruned() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let commit1 = secp
			.commit(10, SecretKey::from_slice(&secp, &[1; 32]).unwrap())
			.unwrap();
		let commit2 = secp
			.commit(20, SecretKey::from_slice(&secp, &[2; 32]).unwrap())
			.unwrap();
		let stale_commit = secp
			.commit(30, SecretKey::from_slice(&secp, &[3; 32]).unwrap())
			.unwrap();

		// A live session holds its input; dropping the session leaves a stale entry.
		{
			let mut session = TxSession::new();
			session
				.set_input_commits(vec![(Identifier::zero(), None, commit1.clone(), 10)])
				.unwrap();
			assert!(!input_is_free(&commit1.to_hex()));
		}
		// The lazy path reclaims a stale entry only when that commit is queried.
		assert!(input_is_free(&commit1.to_hex()));

		// A stale entry whose output became Locked/Spent is never queried again;
		// the next set_input_commits call must sweep it to keep the map bounded.
		{
			let mut session = TxSession::new();
			session
				.set_input_commits(vec![(Identifier::zero(), None, stale_commit.clone(), 30)])
				.unwrap();
		}
		let mut session = TxSession::new();
		session
			.set_input_commits(vec![(Identifier::zero(), None, commit2.clone(), 20)])
			.unwrap();

		{
			let map = TX_INPUT_RESERVATIONS.read();
			assert!(map.contains_key(&commit2.to_hex()));
			assert!(!map.contains_key(&stale_commit.to_hex()));
		}
		// The live session's input is still reserved.
		assert!(!input_is_free(&commit2.to_hex()));
	}

	#[test]
	fn set_input_commits_rejects_conflicts_with_live_sessions() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let commit1 = secp
			.commit(10, SecretKey::from_slice(&secp, &[11; 32]).unwrap())
			.unwrap();
		let commit2 = secp
			.commit(20, SecretKey::from_slice(&secp, &[12; 32]).unwrap())
			.unwrap();

		let mut session1 = TxSession::new();
		session1
			.set_input_commits(vec![(Identifier::zero(), None, commit1.clone(), 10)])
			.unwrap();

		// A different live session must not silently take over the reservation.
		let mut session2 = TxSession::new();
		assert!(session2
			.set_input_commits(vec![(Identifier::zero(), None, commit1.clone(), 10)])
			.is_err());
		assert!(input_is_free(&commit2.to_hex()));

		// An unreserved commit is accepted.
		session2
			.set_input_commits(vec![(Identifier::zero(), None, commit2.clone(), 20)])
			.unwrap();

		// Re-registering its own commits is idempotent (tx_lock_outputs
		// re-registers what process_invoice_tx reserved at signing time).
		session1
			.set_input_commits(vec![(Identifier::zero(), None, commit1.clone(), 10)])
			.unwrap();
	}

	#[test]
	fn duration_serde() {
		let some = TestSer {
			dur: Some(Duration::from_secs(100)),
		};
		let val = serde_json::to_value(some.clone()).unwrap();
		if let Value::Object(o) = &val {
			if let Value::String(s) = o.get("dur").unwrap() {
				assert_eq!(s, "100");
			} else {
				panic!("Invalid type");
			}
		} else {
			panic!("Invalid type")
		}
		assert_eq!(some, serde_json::from_value(val).unwrap());

		let none = TestSer { dur: None };
		let val = serde_json::to_value(none.clone()).unwrap();
		if let Value::Object(o) = &val {
			if let Value::Null = o.get("dur").unwrap() {
				// ok
			} else {
				panic!("Invalid type");
			}
		} else {
			panic!("Invalid type")
		}
		assert_eq!(none, serde_json::from_value(val).unwrap());

		let none2 = serde_json::from_str::<TestSer>("{}").unwrap();
		assert_eq!(none, none2);
	}

	#[test]
	fn deferred_receive_revalidation_rejects_duplicate_slate() {
		let slate_id = Uuid::new_v4();
		let pending_parent = ExtKeychainPath::new(2, 0, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let existing_parent = ExtKeychainPath::new(2, 1, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let mut pending = TxLogEntry::new(pending_parent, TxLogEntryType::TxReceived, 0);
		pending.tx_slate_id = Some(slate_id);
		let mut existing = TxLogEntry::new(existing_parent, TxLogEntryType::TxReceived, 1);
		existing.tx_slate_id = Some(slate_id);

		assert!(matches!(
			validate_deferred_receive(&pending, vec![existing].into_iter()),
			Err(Error::TransactionAlreadyReceived(id)) if id == slate_id.to_string()
		));
	}

	#[test]
	fn deferred_receive_revalidation_allows_cross_account_self_send() {
		let secp = Secp256k1::new().unwrap();
		let slate_id = Uuid::new_v4();
		let pending_parent = ExtKeychainPath::new(2, 0, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let existing_parent = ExtKeychainPath::new(2, 1, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let secret = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let public = PublicKey::from_secret_key(&secp, &secret).unwrap();
		let offset = Commitment::from_pubkey(&secp, &public).unwrap();

		let mut pending = TxLogEntry::new(pending_parent, TxLogEntryType::TxReceived, 0);
		pending.tx_slate_id = Some(slate_id);
		pending.kernel_offset = Some(offset);
		let mut existing = TxLogEntry::new(existing_parent, TxLogEntryType::TxSent, 1);
		existing.tx_slate_id = Some(slate_id);
		existing.kernel_offset = Some(offset);

		assert!(validate_deferred_receive(&pending, vec![existing].into_iter()).is_ok());
	}

	#[test]
	fn deferred_receive_revalidation_rejects_duplicate_offset() {
		let secp = Secp256k1::new().unwrap();
		let slate_id = Uuid::new_v4();
		let parent = Identifier::zero();
		let secret = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let public = PublicKey::from_secret_key(&secp, &secret).unwrap();
		let offset = Commitment::from_pubkey(&secp, &public).unwrap();

		let mut pending = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceived, 0);
		pending.tx_slate_id = Some(slate_id);
		pending.kernel_offset = Some(offset);
		let mut existing = TxLogEntry::new(parent, TxLogEntryType::TxSent, 1);
		existing.tx_slate_id = Some(slate_id);
		existing.kernel_offset = Some(offset);

		assert!(matches!(
			validate_deferred_receive(&pending, vec![existing].into_iter()),
			Err(Error::TransactionWithSameOffsetAlreadyReceived(_))
		));
	}

	#[test]
	fn display_escaping_replaces_terminal_controls() {
		assert_eq!(
			escape_for_display("before\n\u{1b}]52;c;payload\u{7}after"),
			"before\\u000a\\u001b]52;c;payload\\u0007after"
		);
	}

	#[test]
	fn display_escaping_replaces_c1_terminal_controls() {
		assert_eq!(
			escape_for_display("before\u{9b}2J\u{9d}52;c;payload\u{9c}after"),
			"before\\u009b2J\\u009d52;c;payload\\u009cafter"
		);
	}

	#[test]
	fn display_escaping_replaces_bidi_controls() {
		assert_eq!(
			escape_for_display("pay\u{202e}moc.evaw\u{202c} \u{2066}hidden\u{2069}\u{200f}"),
			"pay\\u202emoc.evaw\\u202c \\u2066hidden\\u2069\\u200f"
		);
	}

	#[test]
	fn display_escaping_replaces_unicode_line_separators() {
		assert_eq!(
			escape_for_display("before\u{2028}middle\u{2029}after"),
			"before\\u2028middle\\u2029after"
		);
	}

	#[test]
	fn display_escaping_preserves_serialized_json() {
		let original = Value::String(
			"before\u{9b}2J pay\u{202e}moc.evaw\u{202c} \u{2066}hidden\u{2069}".to_owned(),
		);
		let serialized = serde_json::to_string(&original).unwrap();
		let escaped = escape_for_display(&serialized);

		assert!(!escaped.contains('\u{9b}'));
		assert!(!escaped.contains('\u{202e}'));
		assert!(escaped.contains("\\u009b"));
		assert!(escaped.contains("\\u202e"));
		assert_eq!(serde_json::from_str::<Value>(&escaped).unwrap(), original);
	}

	#[test]
	fn bounded_display_escaping_is_terminal_safe_and_utf8_aware() {
		let hostile = format!(
			"before\n\u{1b}]52;c;payload\u{7}\u{202e}{}éafter",
			"x".repeat(32)
		);
		let safe = bounded_escape_for_display(&hostile, 58);

		assert!(safe.contains("\\u000a"));
		assert!(safe.contains("\\u001b"));
		assert!(safe.contains("\\u0007"));
		assert!(safe.contains("\\u202e"));
		assert!(safe.ends_with("...[truncated]"));
		assert!(!safe.chars().any(char::is_control));
		assert!(!safe.contains('\u{202e}'));
	}
}
