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

use super::swap::ethereum::EthereumWallet;
use crate::config::{MQSConfig, TorConfig, WalletConfig};
use crate::error::Error;
use crate::mwc_api::{Libp2pMessages, Libp2pPeers};
use crate::mwc_core::core::hash::Hash;
use crate::mwc_core::core::Committed;
use crate::mwc_core::core::{Output, Transaction, TxKernel};
use crate::mwc_core::libtx::{aggsig, secp_ser};
use crate::mwc_core::{global, ser};
use crate::mwc_keychain::{Identifier, Keychain};
use crate::mwc_util::logger::LoggingConfig;
use crate::mwc_util::secp::key::{PublicKey, SecretKey, ZERO_KEY};
use crate::mwc_util::secp::pedersen::Commitment;
use crate::mwc_util::secp::{self, pedersen, Secp256k1};
use crate::mwc_util::{ToHex, ZeroingString};
use crate::proof::proofaddress::ProvableAddress;
use crate::slate::ParticipantMessages;
use crate::InitTxArgs;
#[cfg(feature = "libp2p")]
use crate::IntegrityContext;
use crate::Slate;
use chrono::prelude::*;
use rand::rngs::mock::StepRng;
use rand::thread_rng;
use serde;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use uuid::Uuid;

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

/// Trait for a provider of wallet lifecycle methods
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

	///
	fn create_wallet(
		&mut self,
		name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: usize,
		password: ZeroingString,
		test_mode: bool,
		wallet_data_dir: Option<&str>,
	) -> Result<(), Error>;

	///
	fn open_wallet(
		&mut self,
		name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		use_test_rng: bool,
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

	/// deletes wallet
	fn delete_wallet(&self, name: Option<&str>) -> Result<(), Error>;

	/// return wallet instance
	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error>;
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
	/// data file directory. mwc713 needs it
	fn get_data_file_dir(&self) -> &str;

	/// Set the keychain, which should already be initialized
	/// Optionally return a token value used to XOR the stored
	/// key value
	fn set_keychain(
		&mut self,
		k: Box<K>,
		mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error>;

	/// Close wallet and remove any stored credentials (TBD)
	fn close(&mut self) -> Result<(), Error>;

	/// Return the keychain being used. Ensure a cloned copy so it will be dropped
	/// and zeroized by the caller
	/// Can optionally take a mask value
	fn keychain(&self, mask: Option<&SecretKey>) -> Result<K, Error>;

	/// Return the client being used to communicate with the node
	fn w2n_client(&mut self) -> &mut C;

	/// return the commit for caching if allowed, none otherwise
	fn calc_commit_for_cache(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Option<String>, Error>;

	/// Set parent key id by stored account name
	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error>;

	/// The BIP32 path of the parent path to use for all output-related
	/// functions, (essentially 'accounts' within a wallet.
	fn set_parent_key_id(&mut self, _: Identifier);

	/// return the parent path
	fn parent_key_id(&mut self) -> Identifier;

	/// Iterate over all output data stored by the backend
	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = OutputData> + 'a>;

	/// Get output data by id
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;

	/// Iterate over archive outputs data stored by the backend
	fn archive_iter<'a>(&'a self) -> Box<dyn Iterator<Item = OutputData> + 'a>;

	/// Retrieves the private context associated with a given slate id
	fn get_private_context(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<Context, Error>;

	/// Iterate over all output data stored by the backend
	fn tx_log_iter<'a>(&'a self) -> Box<dyn Iterator<Item = TxLogEntry> + 'a>;

	/// Iterate over all output data stored by the backend
	fn tx_log_archive_iter<'a>(&'a self) -> Box<dyn Iterator<Item = TxLogEntry> + 'a>;

	/// Iterate over all stored account paths
	fn acct_path_iter<'a>(&'a self) -> Box<dyn Iterator<Item = AcctPathMapping> + 'a>;

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
		keychain_mask: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	/// Batch for use when keychain isn't available or required
	fn batch_no_mask<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	/// Return the current child Index
	fn current_child_index(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;

	/// Next child ID when we want to create a new output, based on current parent
	fn next_child(
		&mut self,
		parent_key_id: Option<&Identifier>,
		height: Option<u64>,
	) -> Result<Identifier, Error>;

	/// last verified height of outputs directly descending from the given parent key
	fn last_confirmed_height(&mut self) -> Result<u64, Error>;

	/// last block scanned during scan or restore
	fn last_scanned_blocks(&mut self) -> Result<Vec<ScannedBlockInfo>, Error>;

	/// set ethereum wallet instance
	fn set_ethereum_wallet(&mut self, ethereum_wallet: Option<EthereumWallet>)
		-> Result<(), Error>;

	/// get ethereum wallet instance
	fn get_ethereum_wallet(&self) -> Result<EthereumWallet, Error>;
}

/// New wallet with empty seed mark. Needed to skip first long scan
pub const FLAG_NEW_WALLET: u64 = 1;
/// Need to clean private context on the first wallet run
pub const FLAG_CONTEXT_CLEARED: u64 = 2;
/// Need to correct outputs root_key_id values to recover from prev bug
pub const FLAG_OUTPUTS_ROOT_KEY_ID_CORRECTION: u64 = 3;

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
	fn keychain(&mut self) -> &mut K;

	/// Add or update data about an output to the backend
	fn save(&mut self, out: OutputData) -> Result<(), Error>;

	/// Gets output data by id
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;

	/// Iterate over all output data stored by the backend
	fn iter(&self) -> Box<dyn Iterator<Item = OutputData>>;

	/// Delete data about an output from the backend
	fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error>;

	/// Move output into archive
	fn archive_output(&mut self, out: &OutputData) -> Result<(), Error>;

	/// Save last stored child index of a given parent
	fn save_child_index(&mut self, parent_key_id: &Identifier, child_n: u32) -> Result<(), Error>;

	/// Save last confirmed height of outputs for a given parent
	fn save_last_confirmed_height(
		&mut self,
		parent_key_id: &Identifier,
		height: u64,
	) -> Result<(), Error>;

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

	/// Save the last used good node index
	fn save_last_working_node_index(&mut self, node_index: u8) -> Result<(), Error>;

	/// get the last used good node index
	fn get_last_working_node_index(&mut self) -> Result<u8, Error>;

	/// get next tx log entry for the parent
	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;

	/// Iterate over tx log data stored by the backend
	fn tx_log_iter(&self) -> Box<dyn Iterator<Item = TxLogEntry>>;

	/// Iterate over tx log archived data
	fn tx_log_archive_iter(&self) -> Box<dyn Iterator<Item = TxLogEntry>>;

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
	fn acct_path_iter(&self) -> Box<dyn Iterator<Item = AcctPathMapping>>;

	/// Save an output as locked in the backend
	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error>;

	/// Iterate through all private context. Return tx uuid from the key and the Context
	fn private_context_iter(&self) -> Box<dyn Iterator<Item = (Vec<u8>, Context)>>;

	/// Saves the private context associated with a slate id
	fn save_private_context(
		&mut self,
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

	/// Write the wallet data to backend file
	fn commit(&self) -> Result<(), Error>;

	/// Save integrity transaction private context.
	#[cfg(feature = "libp2p")]
	fn save_integrity_context(
		&mut self,
		slate_id: &[u8],
		ctx: &IntegrityContext,
	) -> Result<(), Error>;

	/// Read integrity transaction private context.
	#[cfg(feature = "libp2p")]
	fn load_integrity_context(&mut self, slate_id: &[u8]) -> Result<IntegrityContext, Error>;
}

/// Encapsulate all wallet-node communication functions. No functions within libwallet
/// should care about communication details
pub trait NodeClient: Send + Sync + Clone {
	///we have a list of nodes for failover, point the index to the next one.
	fn increase_index(&self);

	/// Return the URL of the check node
	fn node_url(&self) -> Result<String, Error>;

	/// Set the node URL
	fn set_node_url(&mut self, node_url: Vec<String>);

	/// Set the node index
	fn set_node_index(&mut self, index: u8);

	/// Set the node index
	fn get_node_index(&self) -> u8;

	/// Return the node api secret
	fn node_api_secret(&self) -> &Option<String>;

	/// Change the API secret
	fn set_node_api_secret(&mut self, node_api_secret: Option<String>);

	/// Reset cache data
	fn reset_cache(&self);

	/// Posts a transaction to a mwc node
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), Error>;

	/// Returns the api version string and block header version as reported
	/// by the node. Result can be cached for later use
	fn get_version_info(&mut self) -> Option<NodeVersionInfo>;

	/// retrieves the current tip (height, hash) from the specified mwc node
	/// (<height>, <hash>, <total difficulty>)
	fn get_chain_tip(&self) -> Result<(u64, String, u64), Error>;

	/// Return header info by height
	fn get_header_info(&self, height: u64) -> Result<HeaderInfo, Error>;

	/// Return Connected peers
	fn get_connected_peer_info(
		&self,
	) -> Result<Vec<crate::mwc_p2p::types::PeerInfoDisplayLegacy>, Error>;

	/// Get a kernel and the height of the block it's included in. Returns
	/// (tx_kernel, height, mmr_index)
	fn get_kernel(
		&self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error>;

	/// retrieve a list of outputs from the specified mwc node
	/// need "by_height" and "by_id" variants
	/// Result value: Commit, Height, MMR
	fn get_outputs_from_node(
		&self,
		wallet_outputs: &Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, Error>;

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
	) -> Result<Vec<crate::mwc_api::BlockPrintable>, Error>;

	/// Get Node Tor address
	fn get_libp2p_peers(&self) -> Result<Libp2pPeers, Error>;

	/// Get collected messages by the node. Can be used for bootstraping. Please note, called doesn't control
	/// listening topics. Topics are part of setup
	fn get_libp2p_messages(&self) -> Result<Libp2pMessages, Error>;
}

/// Node version info
#[derive(Serialize, Deserialize, Debug, Clone)]
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
			1 + (current_height - self.height)
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
			(self.status == OutputStatus::Unspent
				&& self.num_confirmations(current_height) >= minimum_confirmations)
				|| self.status == OutputStatus::Unconfirmed && minimum_confirmations == 0
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
	/// Output commitments, mwc713 payment proof support.
	#[serde(default)]
	pub output_commits: Vec<Commitment>,
	/// Input commitments, mwc713 payment proof support.
	#[serde(default)]
	pub input_commits: Vec<Commitment>,
	/// If late-locking, store my tranasction creation prefs
	/// for later
	pub late_lock_args: Option<InitTxArgs>,
	/// for invoice I2 Only, store the tx excess so we can
	/// remove it from the slate on return
	pub calculated_excess: Option<pedersen::Commitment>,
	/// Slate message that was added from this participant.
	pub message: Option<String>,
}

impl Context {
	/// Create a new context, the secret will be generated. It is a normal way of context cretion since
	/// Lock later & compact slate was introduced
	pub fn new(
		secp: &secp::Secp256k1,
		parent_key_id: &Identifier,
		use_test_rng: bool,
		is_initiator: bool,
		participant_id: usize,
		amount: u64,
		fee: u64,
		message: Option<String>,
	) -> Context {
		let sec_key = match use_test_rng {
			false => SecretKey::new(secp, &mut thread_rng()),
			true => {
				// allow for consistent test results
				let mut test_rng = if is_initiator {
					StepRng::new(1_234_567_890_u64, 1)
				} else {
					StepRng::new(1_234_567_891_u64, 1)
				};
				SecretKey::new(secp, &mut test_rng)
			}
		};
		Self::with_excess(
			secp,
			sec_key,
			parent_key_id,
			use_test_rng,
			participant_id,
			amount,
			fee,
			message,
		)
	}

	/// Create a new context from pregenerated secret key. Normal case for tests only.
	pub fn with_excess(
		secp: &secp::Secp256k1,
		sec_key: SecretKey,
		parent_key_id: &Identifier,
		use_test_rng: bool,
		participant_id: usize,
		amount: u64,
		fee: u64,
		message: Option<String>,
	) -> Context {
		let sec_nonce = match use_test_rng {
			false => aggsig::create_secnonce(secp).unwrap(),
			true => SecretKey::from_slice(secp, &[1; 32]).unwrap(),
		};
		Context {
			parent_key_id: parent_key_id.clone(),
			sec_key: sec_key.clone(),
			sec_nonce: sec_nonce.clone(),
			initial_sec_key: sec_key.clone(),
			initial_sec_nonce: sec_nonce.clone(),
			input_ids: vec![],
			output_ids: vec![],
			amount,
			fee,
			participant_id: participant_id,
			payment_proof_derivation_index: None,
			output_commits: vec![],
			input_commits: vec![],
			late_lock_args: None,
			calculated_excess: None,
			message,
		}
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
			amount: slate.amount,
			fee: slate.fee,
			participant_id,
			payment_proof_derivation_index: None,
			output_commits: slate.tx_or_err()?.body.outputs_committed(),
			input_commits: slate.tx_or_err()?.body.inputs_committed(),
			calculated_excess: None,
			late_lock_args: None,
			message: None,
		})
	}
}

impl Context {
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
	pub fn get_public_keys(&self, secp: &Secp256k1) -> (PublicKey, PublicKey) {
		(
			PublicKey::from_secret_key(secp, &self.sec_key).unwrap(),
			PublicKey::from_secret_key(secp, &self.sec_nonce).unwrap(),
		)
	}
}

impl ser::Writeable for Context {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("Context to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Context data length is {}",
				data.len()
			)));
		}

		writer.write_bytes(&data)
	}
}

impl ser::Readable for Context {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Context, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
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

/// Optional transaction information, recorded when an event happens
/// to add or remove funds from a wallet. One Transaction log entry
/// maps to one or many outputs
#[derive(Serialize, Deserialize, Debug, Clone)]
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
	/// Additional info needed to stored payment proof
	#[serde(default)]
	pub payment_proof: Option<StoredProofInfo>,
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

impl ser::Writeable for TxLogEntry {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("TxLogEntry to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"TxLogEntry data length is {}",
				data.len()
			)));
		}
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
			payment_proof: None,
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
		payment_proof: Option<StoredProofInfo>,
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
			payment_proof,
			input_commits,
			output_commits,
			reverted_after: None,
		}
	}

	/// Given a vec of TX log entries, return credited + debited sums
	pub fn sum_confirmed(txs: &[TxLogEntry]) -> (u64, u64) {
		txs.iter().fold((0, 0), |acc, tx| match tx.confirmed {
			true => (acc.0 + tx.amount_credited, acc.1 + tx.amount_debited),
			false => acc,
		})
	}

	/// Update confirmation TS with now
	pub fn update_confirmation_ts(&mut self, time: String) {
		//
		if time.is_empty() {
			self.confirmation_ts = Some(Utc::now());
		} else {
			//sample time string: 2020-10-07T23:57:00+00:00
			let time_converted = DateTime::parse_from_rfc3339(&time);
			let time_stamp = time_converted.unwrap().timestamp();
			let confirmed_t = Utc.timestamp_opt(time_stamp, 0).unwrap();
			self.confirmation_ts = Some(confirmed_t);
		}
		//query the node to get the confirmation time
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
}

/// Payment proof information. Differs from what is sent via
/// the slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredProofInfo {
	/// receiver address
	pub receiver_address: ProvableAddress,
	/// receiver signature
	pub receiver_signature: Option<String>,
	/// sender address derivation path index
	pub sender_address_path: u32,
	/// sender address
	pub sender_address: ProvableAddress,
	/// sender signature
	pub sender_signature: Option<String>,
}

impl ser::Writeable for StoredProofInfo {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("StoredProofInfo to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"StoredProofInfo data length is {}",
				data.len()
			)));
		}
		writer.write_bytes(&data)
	}
}

impl ser::Readable for StoredProofInfo {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<StoredProofInfo, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to StoredProofInfo conversion failed, {}", e))
		})
	}
}

/// Map of named accounts to BIP32 paths
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Wrapper for reward output and kernel used when building a coinbase for a mining node.
/// Note: Not serializable, must be converted to necesssary "versioned" representation
/// before serializing to json to ensure compatibility with mining node.
/// NOTE2!!! Serialize, Deserialize needed for mwc713, even no version is present. Json should ease the problem
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CbData {
	/// Output
	pub output: Output,
	/// Kernel
	pub kernel: TxKernel,
	/// Key Id
	pub key_id: Option<Identifier>,
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

/// Utility struct for return values from below
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewWallet {
	/// Rewind Hash used to retrieve the outputs
	pub rewind_hash: String,
	/// All outputs information that belongs to the rewind hash
	pub output_result: Vec<ViewWalletOutputResult>,
	/// total balance
	pub total_balance: u64,
	/// last pmmr index
	pub last_pmmr_index: u64,
}
/// Utility struct for return values from below
#[derive(Debug, Clone, Serialize, Deserialize)]
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
			1 + (tip_height - self.height)
		}
	}
}

/// Serializes an Option<Duration> to and from a string
pub mod option_duration_as_secs {
	use serde::de::Error;
	use serde::{Deserialize, Deserializer, Serializer};
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
	use serde_json::Value;

	#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
	struct TestSer {
		#[serde(with = "option_duration_as_secs", default)]
		dur: Option<Duration>,
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
}
