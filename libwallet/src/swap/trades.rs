// Copyright 2020 The MWC Developers
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

use super::{Error, CURRENT_VERSION};
use crate::swap::types::{Context, Currency};
use crate::swap::Swap;
use mwc_wallet_util::file::replace_owner_only_file_with;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::base64::{engine::general_purpose::STANDARD, Engine as _};
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::rand::{rngs::SysRng, TryRng};
use mwc_wallet_util::mwc_crates::ring::aead;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_util::{from_hex, to_hex};
use mwc_wallet_util::sensitive;
use mwc_wallet_util::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Weak};

/// Location of the swaps states
pub const SWAP_DEAL_SAVE_DIR: &'static str = "saved_swap_deal";
/// Location of the normal deleted swap trades
pub const SWAP_DEAL_DELETED_DIR: &'static str = "deleted";
/// Location of the marketplace not started swap trades.
pub const SWAP_DEAL_MKT_DELETED_DIR: &'static str = "deleted_mkt";
const CURRENT_SWAP_RECORD_VERSION: u8 = 2;

// Genecic becasue C,S can be Context, Swap  or &Context, &Swap
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
struct StoredSwapRecord<C, S> {
	format_version: u8,
	context: C,
	swap: S,
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
	File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
	// Windows and other non-Unix platforms intentionally skip directory syncing:
	// Rust std has no portable API for it. Swap file contents are synchronized
	// before rename, but Ok(()) here does not guarantee that save/archive renames
	// survive a power loss or OS crash. Recovery may find an older swap record or
	// fail to find its expected filename even after a successful save. This weaker
	// directory durability is an accepted platform limitation.
	Ok(())
}

lazy_static! {
	static ref TRADE_DEALS_PATH: RwLock<HashMap<u32,PathBuf>> = RwLock::new(HashMap::new());
	static ref ELECTRUM_X_URI: RwLock<HashMap<u32,BTreeMap<String, String>>> = RwLock::new(HashMap::new());
	static ref ETH_SWAP_CONTRACT_ADDR: RwLock<HashMap<u32,String>> = RwLock::new(HashMap::new());
	static ref ERC20_SWAP_CONTRACT_ADDR: RwLock<HashMap<u32,String>> = RwLock::new(HashMap::new());
	static ref ETH_INFURA_PROJECTID: RwLock<HashMap<u32,String>> = RwLock::new(HashMap::new());
	// Weak entries prevent arbitrary lookups from growing a process-wide cache
	// forever. Context is part of the key so wallet cleanup can evict its locks.
	static ref SWAP_LOCKS: RwLock<HashMap<(u32, String), Weak<Mutex<()>>>> =
		RwLock::new(HashMap::new());
	// Serializes discovery and persistence of resource-bearing swaps for one wallet
	// context. A UUID lock cannot provide this guarantee because competing creations
	// intentionally use different UUIDs.
	static ref SWAP_CREATION_LOCKS: RwLock<HashMap<u32, Weak<Mutex<()>>>> =
		RwLock::new(HashMap::new());
}

/// Clear context-id-keyed swap storage and configuration.
///
/// Lifecycle teardown must synchronously stop and join every context-owned
/// listener before calling this function. Direct swap calls are not owned by the
/// listener lifecycle and must be externally serialized against context release.
pub fn trades_clean_context(context_id: u32) {
	let _ = TRADE_DEALS_PATH.write().remove(&context_id);
	let _ = ELECTRUM_X_URI.write().remove(&context_id);
	let _ = ETH_SWAP_CONTRACT_ADDR.write().remove(&context_id);
	let _ = ERC20_SWAP_CONTRACT_ADDR.write().remove(&context_id);
	let _ = ETH_INFURA_PROJECTID.write().remove(&context_id);
	SWAP_LOCKS
		.write()
		.retain(|(lock_context_id, _), lock| {
			*lock_context_id != context_id || lock.strong_count() > 0
		});
	SWAP_CREATION_LOCKS
		.write()
		.retain(|lock_context_id, lock| {
			*lock_context_id != context_id || lock.strong_count() > 0
		});
}

/// Parse a swap identifier and return its one canonical spelling.
pub fn canonical_swap_id(swap_id: &str) -> Result<String, Error> {
	Uuid::parse_str(swap_id)
		.map(|id| id.to_string())
		.map_err(|_| Error::InvalidMessageData("Swap id must be a valid UUID".to_string()))
}

fn swap_trade_path(context_id: u32, swap_id: &str) -> Result<(String, PathBuf), Error> {
	let swap_id = canonical_swap_id(swap_id)?;
	// This mapping is intentionally context scoped and mutable across context
	// lifetimes. Context release joins every listener before cleanup; direct API
	// callers must finish before initiating release.
	let trade_dir = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?;
	Ok((swap_id.clone(), trade_dir.join(format!("{}.swap", swap_id))))
}

/// Init for file storage for saving swap deals
pub fn init_swap_trade_backend(
	context_id: u32,
	data_file_dir: &str,
	electrumx_config_uri: &Option<BTreeMap<String, String>>,
	eth_swap_contract_addr: &Option<String>,
	erc20_swap_contract_addr: &Option<String>,
	eth_infura_projectid: &Option<String>,
) -> Result<(), Error> {
	let stored_swap_deal_path = Path::new(data_file_dir).join(SWAP_DEAL_SAVE_DIR);
	fs::create_dir_all(&stored_swap_deal_path).map_err(|e| {
		Error::IO(format!(
			"Could not create swap deal storage directory {}, {}",
			stored_swap_deal_path.to_string_lossy(),
			e
		))
	})?;

	let deleted_trades = stored_swap_deal_path.join(SWAP_DEAL_DELETED_DIR);
	fs::create_dir_all(&deleted_trades).map_err(|e| {
		Error::IO(format!(
			"Could not create deleted trades directory {}, {}",
			deleted_trades.to_string_lossy(),
			e
		))
	})?;

	let deleted_mkts = stored_swap_deal_path.join(SWAP_DEAL_MKT_DELETED_DIR);
	fs::create_dir_all(&deleted_mkts).map_err(|e| {
		Error::IO(format!(
			"Could not create deleted maketplace deals directory {}, {}",
			deleted_mkts.to_string_lossy(),
			e
		))
	})?;

	TRADE_DEALS_PATH
		.write()
		.insert(context_id, stored_swap_deal_path);
	if let Some(electrumx_config_uri) = electrumx_config_uri {
		ELECTRUM_X_URI
			.write()
			.insert(context_id, electrumx_config_uri.clone());
	}

	{
		// Update the contract pair under both locks. Trade creation resolves the
		// pair under the corresponding read locks, so it cannot capture one address
		// from the old configuration and one from the new configuration.
		let mut eth_addresses = ETH_SWAP_CONTRACT_ADDR.write();
		let mut erc20_addresses = ERC20_SWAP_CONTRACT_ADDR.write();
		if let Some(eth_swap_contract_addr) = eth_swap_contract_addr {
			eth_addresses.insert(context_id, eth_swap_contract_addr.clone());
		}
		if let Some(erc20_swap_contract_addr) = erc20_swap_contract_addr {
			erc20_addresses.insert(context_id, erc20_swap_contract_addr.clone());
		}
	}

	if let Some(eth_infura_projectid) = eth_infura_projectid {
		ETH_INFURA_PROJECTID
			.write()
			.insert(context_id, eth_infura_projectid.clone());
	}
	Ok(())
}

/// Get ElextrumX URL.
pub fn get_electrumx_uri(
	context_id: u32,
	currency: &Currency,
	swap_electrum_node_uri1: &Option<String>,
	swap_electrum_node_uri2: &Option<String>,
) -> Result<(String, String), Error> {
	let network = if global::is_mainnet(context_id) {
		"main"
	} else {
		"test"
	};

	let map = ELECTRUM_X_URI.read();
	let sec_coin = currency.to_string().to_lowercase();

	// unwrap_or/unwrap_or_else  doesn't work because we don't wanle evaluate else part and else part can report error.
	let uri1 = match swap_electrum_node_uri1.clone() {
		Some(s) => s,
		None => map
			.get(&context_id)
			.map(|uri_map| uri_map.get(&format!("{}_{}_1", sec_coin, network)))
			.ok_or(Error::UndefinedElectrumXURI("primary".to_string()))?
			.ok_or(Error::UndefinedElectrumXURI("primary".to_string()))?
			.clone(),
	};
	let uri2 = match swap_electrum_node_uri2.clone() {
		Some(s) => s,
		None => map
			.get(&context_id)
			.as_ref()
			.map(|uri_map| uri_map.get(&format!("{}_{}_2", sec_coin, network)))
			.ok_or(Error::UndefinedElectrumXURI("secondary".to_string()))?
			.ok_or(Error::UndefinedElectrumXURI("secondary".to_string()))?
			.clone(),
	};

	Ok((uri1, uri2))
}

/// Get etherum contract addr.
pub fn get_eth_swap_contract_address(
	context_id: u32,
	_currency: &Currency,
	eth_swap_contract_addr: &Option<String>,
) -> Result<String, Error> {
	let swap_contract_addresss = ETH_SWAP_CONTRACT_ADDR.read().get(&context_id).cloned();

	match eth_swap_contract_addr.clone() {
		Some(s) => Ok(s),
		None => match swap_contract_addresss {
			Some(s) => Ok(s),
			None => swap_contract_addresss.ok_or(Error::UndefinedEthSwapContractAddress),
		},
	}
}

/// Get erc20 contract addr.
pub fn get_erc20_swap_contract_address(
	context_id: u32,
	_currency: &Currency,
	erc20_swap_contract_addr: &Option<String>,
) -> Result<String, Error> {
	let swap_contract_addresss = ERC20_SWAP_CONTRACT_ADDR.read().get(&context_id).cloned();

	match erc20_swap_contract_addr.clone() {
		Some(s) => Ok(s),
		None => match swap_contract_addresss {
			Some(s) => Ok(s),
			None => swap_contract_addresss.ok_or(Error::UndefinedERC20SwapContractAddress),
		},
	}
}

/// Resolve the effective Ethereum and ERC20 contract addresses as one pair.
///
/// Trade creation uses this instead of two independent lookups so concurrent
/// backend configuration cannot produce a torn pair. The returned owned values
/// must be persisted into the new trade before the first durable write.
pub fn get_eth_swap_contract_addresses(
	context_id: u32,
	_currency: &Currency,
	eth_swap_contract_addr: &Option<String>,
	erc20_swap_contract_addr: &Option<String>,
) -> Result<(String, String), Error> {
	let eth_addresses = ETH_SWAP_CONTRACT_ADDR.read();
	let erc20_addresses = ERC20_SWAP_CONTRACT_ADDR.read();
	let eth = eth_swap_contract_addr
		.clone()
		.or_else(|| eth_addresses.get(&context_id).cloned())
		.ok_or(Error::UndefinedEthSwapContractAddress)?;
	let erc20 = erc20_swap_contract_addr
		.clone()
		.or_else(|| erc20_addresses.get(&context_id).cloned())
		.ok_or(Error::UndefinedERC20SwapContractAddress)?;
	Ok((eth, erc20))
}

/// Get etherum infura project id.
pub fn get_eth_infura_projectid(
	context_id: u32,
	_currency: &Currency,
	eth_infura_projectid: &Option<String>,
) -> Result<String, Error> {
	let infura_project_id = ETH_INFURA_PROJECTID.read().get(&context_id).cloned();

	match eth_infura_projectid.clone() {
		Some(s) => Ok(s),
		None => match infura_project_id {
			Some(s) => Ok(s),
			None => infura_project_id.ok_or(Error::UndefinedInfuraProjectId),
		},
	}
}

/// List available swap trades.
pub fn list_swap_trades(context_id: u32) -> Result<Vec<String>, Error> {
	let mut result: Vec<String> = Vec::new();

	let path = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?;

	for entry in fs::read_dir(path)? {
		let entry = entry?;
		if let Some(name) = entry.file_name().to_str() {
			if let Some(stem) = name.strip_suffix(".swap") {
				if let Ok(canonical) = canonical_swap_id(stem) {
					// Records are always written under their canonical UUID. Ignore
					// lookalike filenames instead of turning them into path inputs.
					if canonical == stem {
						result.push(canonical);
					}
				}
			}
		}
	}
	result.sort_unstable();
	Ok(result)
}

/// Restore allowances and reserved transaction nonces before any Ethereum submission.
/// Call before taking the target trade lock: the scan takes one trade lock at a
/// time, and includes cancelled records whose last transaction may still mine.
pub(crate) fn restore_ethereum_resources(
	context_id: u32,
	target: Option<&str>,
	dec_key: &SecretKey,
) -> Result<(), Error> {
	if let Some(target) = target {
		let lock = get_swap_lock(context_id, target)?;
		let _guard = lock.lock();
		let (_, swap) = get_swap_trade(context_id, target, dec_key, &lock)?;
		if !swap.secondary_currency.is_ethereum_family() {
			return Ok(());
		}
	}
	for id in list_swap_trades(context_id)? {
		let lock = get_swap_lock(context_id, &id)?;
		let _guard = lock.lock();
		match get_swap_trade(context_id, &id, dec_key, &lock) {
			Ok((_, swap)) => {
				super::ethereum::funding::record_swap(&swap);
				super::ethereum::recovery::record_swap(&swap);
			}
			// Deletion may finish between listing and acquiring this trade lock.
			Err(Error::TradeNotFound(_)) => (),
			Err(error) => return Err(error),
		}
	}
	// Deleting a cancelled swap archives its encrypted record. Its pending
	// transaction can still mine, so include archives in restart reconciliation.
	let root = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?;
	for directory in [SWAP_DEAL_DELETED_DIR, SWAP_DEAL_MKT_DELETED_DIR] {
		for entry in fs::read_dir(root.join(directory))? {
			let entry = entry?;
			let name = entry.file_name();
			let Some(id) = name
				.to_str()
				.and_then(|name| name.strip_suffix(".swap.del"))
			else {
				continue;
			};
			if canonical_swap_id(id).ok().as_deref() != Some(id) {
				continue;
			}
			let lock = get_swap_lock(context_id, id)?;
			let _guard = lock.lock();
			// An explicitly restored active record supersedes its old archive.
			if root.join(format!("{}.swap", id)).try_exists()? {
				continue;
			}
			let (_, swap) = read_swap_data_from_file(context_id, &entry.path(), dec_key)?;
			if swap.id.to_string() != id {
				return Err(Error::InvalidMessageData(
					"Archived swap id does not match its filename".into(),
				));
			}
			super::ethereum::funding::record_swap(&swap);
			super::ethereum::recovery::record_swap(&swap);
		}
	}
	Ok(())
}

/// Caller suppose to lock the swap object first before call other swap related functions.
///
/// Lock ordering contract:
/// - The wallet mutex is a LEAF lock: never acquire a swap trade lock while holding it.
/// - A swap trade lock MAY be held while the wallet mutex is acquired (swap -> wallet).
/// - At most ONE swap trade lock may be held at a time.
pub fn get_swap_lock(context_id: u32, swap_id: &str) -> Result<Arc<Mutex<()>>, Error> {
	let swap_id = canonical_swap_id(swap_id)?;
	let mut swap_lock_hash = SWAP_LOCKS.write();
	swap_lock_hash.retain(|_, lock| lock.strong_count() > 0);
	let key = (context_id, swap_id);
	if let Some(lock) = swap_lock_hash.get(&key).and_then(Weak::upgrade) {
		return Ok(lock);
	}
	let lock = Arc::new(Mutex::new(()));
	swap_lock_hash.insert(key, Arc::downgrade(&lock));
	Ok(lock)
}

/// Serialize creation/import and marketplace group membership snapshots that
/// span more than one trade record.
///
/// Lock ordering:
/// - acquire this lock while holding neither the wallet mutex nor a trade lock;
/// - while held, trade locks may be acquired one at a time;
/// - the wallet mutex remains a leaf lock.
pub fn get_swap_creation_lock(context_id: u32) -> Arc<Mutex<()>> {
	let mut creation_locks = SWAP_CREATION_LOCKS.write();
	creation_locks.retain(|_, lock| lock.strong_count() > 0);
	if let Some(lock) = creation_locks.get(&context_id).and_then(Weak::upgrade) {
		return lock;
	}
	let lock = Arc::new(Mutex::new(()));
	creation_locks.insert(context_id, Arc::downgrade(&lock));
	lock
}

/// Remove swap trade record.
/// Note! You don't want to remove the non compelete deal. You can loose funds because of that.
/// `discard_pending_marketplace_cancel` must only be true for an explicit,
/// destructive owner request.
pub fn delete_swap_trade(
	context_id: u32,
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
	discard_pending_marketplace_cancel: bool,
) -> Result<(), Error> {
	if lock.try_lock().is_some() {
		return Err(Error::Generic(format!(
			"delete_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let (_context, swap) = get_swap_trade(context_id, swap_id, dec_key, lock)?;
	if !swap.state.is_final_state() {
		return Err(Error::Generic(format!(
			"Swap {} is still in the progress. Please finish or cancel this trade",
			swap_id
		)));
	}
	if (swap.marketplace_cancel_notification.is_some()
		|| swap.pending_marketplace_cancel_notification)
		&& !discard_pending_marketplace_cancel
	{
		return Err(Error::Generic(format!(
			"Swap {} has a pending marketplace cancellation notification. Retry delivery before removing it, or explicitly discard it",
			swap_id
		)));
	}

	let (swap_id, target_path) = swap_trade_path(context_id, swap_id)?;

	let del_dir = if swap.tag.is_some()
		&& (swap.state.is_initial_state() || swap.state.is_cancelled_no_refund())
	{
		SWAP_DEAL_MKT_DELETED_DIR
	} else {
		SWAP_DEAL_DELETED_DIR
	};

	let deleted_path = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?
		.join(del_dir)
		.join(format!("{}.swap.del", swap_id));

	fs::rename(&target_path, &deleted_path).map_err(|e| {
		Error::TradeIoError(swap_id.clone(), format!("Unable to delete, {}", e))
	})?;
	let source_dir = target_path.parent().ok_or_else(|| {
		Error::TradeIoError(
			swap_id.to_string(),
			"Swap trade path has no parent directory".to_string(),
		)
	})?;
	let deleted_dir = deleted_path.parent().ok_or_else(|| {
		Error::TradeIoError(
			swap_id.to_string(),
			"Deleted swap trade path has no parent directory".to_string(),
		)
	})?;
	// Make the archived name durable before making removal of the active name
	// durable. If the second sync fails or the process exits between the two,
	// recovery can leave both names but cannot lose the only durable name.
	sync_directory(deleted_dir).map_err(|e| {
		Error::TradeIoError(
			swap_id.to_string(),
			format!("Unable to sync deleted swap trade directory, {}", e),
		)
	})?;
	sync_directory(source_dir).map_err(|e| {
		Error::TradeIoError(
			swap_id.to_string(),
			format!("Unable to sync swap trade directory after deletion, {}", e),
		)
	})?;
	Ok(())
}

/// Get swap trade from the storage.
/// Mutex is provided for the locking. We want to restrict an access to it
pub fn get_swap_trade(
	context_id: u32,
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(Context, Swap), Error> {
	if lock.try_lock().is_some() {
		return Err(Error::Generic(format!(
			"get_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let (canonical_swap_id, path) = swap_trade_path(context_id, swap_id)?;
	let trade_exists = path.try_exists().map_err(|e| {
		Error::TradeIoError(
			swap_id.to_string(),
			format!(
				"Unable to check whether swap trade file {} exists, {}",
				path.to_str().unwrap_or("<INVALID PATH>"),
				e
			),
		)
	})?;
	if !trade_exists {
		return Err(Error::TradeNotFound(canonical_swap_id));
	}

	let record = read_swap_data_from_file(context_id, path.as_path(), dec_key)?;
	if record.1.id.to_string() != canonical_swap_id {
		return Err(Error::InvalidMessageData(format!(
			"Swap record id {} does not match requested id {}",
			record.1.id, canonical_swap_id
		)));
	}
	Ok(record)
}

/// Load the active record an import must preserve while the canonical trade lock is held.
///
/// Import recovery intentionally does not cross-check deleted copies in either
/// archive directory, leaving trade and archive management under user control.
/// Without an active record, the user-selected backup supplies the recovery data.
/// Restoring an older backup that lacks later transaction recovery data is an
/// accepted tradeoff of this policy for both BTC and Ethereum trades.
pub(crate) fn get_swap_trades_for_import(
	context_id: u32,
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<Vec<Swap>, Error> {
	match get_swap_trade(context_id, swap_id, dec_key, lock) {
		Ok((_, swap)) => Ok(vec![swap]),
		Err(Error::TradeNotFound(_)) => Ok(Vec::new()),
		Err(error) => Err(error),
	}
}

/// Explicit Ethereum recovery may load a cancelled archive. Saving the result
/// creates an active record which supersedes the archive during restoration.
/// Deposit recovery can discover late funds and resume the refund workflow.
///
/// Recovery intentionally does not cross-check the selected record against other
/// deleted copies, leaving trade and archive management under user control. The
/// active record takes precedence; otherwise the first archive below is used.
/// Selecting an older snapshot that lacks later transaction recovery data is an
/// accepted tradeoff of this policy.
pub(crate) fn get_swap_trade_for_ethereum_recovery(
	context_id: u32,
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(Context, Swap), Error> {
	let id = match get_swap_trade(context_id, swap_id, dec_key, lock) {
		Ok(record) => return Ok(record),
		Err(Error::TradeNotFound(id)) => id,
		Err(error) => return Err(error),
	};
	let root = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?;
	for directory in [SWAP_DEAL_DELETED_DIR, SWAP_DEAL_MKT_DELETED_DIR] {
		let path = root.join(directory).join(format!("{}.swap.del", id));
		if !path.try_exists()? {
			continue;
		}
		let record = read_swap_data_from_file(context_id, &path, dec_key)?;
		if record.1.id.to_string() != id || !record.1.state.is_final_state() {
			return Err(Error::InvalidMessageData(
				"Invalid archived swap for Ethereum recovery".into(),
			));
		}
		return Ok(record);
	}
	Err(Error::TradeNotFound(id))
}

fn read_swap_content(path: &Path, dec_key: &SecretKey) -> Result<Zeroizing<String>, Error> {
	let mut swap_deal_f = File::open(path).map_err(|e| {
		Error::IO(format!(
			"Unable to open file {}, {}",
			path.to_str().unwrap_or("<INVALID PATH>"),
			e
		))
	})?;
	let mut content = String::new();
	swap_deal_f.read_to_string(&mut content).map_err(|e| {
		Error::IO(format!(
			"Unable to read data from {}, {}",
			path.to_str().unwrap_or("<INVALID PATH>"),
			e
		))
	})?;
	let enc_swap_content: EncryptedSwap = serde_json::from_str(&content)?;
	let dec_swap_content = enc_swap_content.decrypt(&dec_key)?;

	Ok(dec_swap_content)
}

fn read_swap_data_from_file(
	context_id: u32,
	path: &Path,
	dec_key: &SecretKey,
) -> Result<(Context, Swap), Error> {
	let dec_swap_content = read_swap_content(path, dec_key)?;

	// Only the structured record envelope is accepted. Legacy
	// `Context JSON <#> Swap JSON` plaintext is deliberately incompatible and
	// fails this deserialization instead of entering a fallback parser.
	let record: StoredSwapRecord<Context, Swap> =
		serde_json::from_str(dec_swap_content.as_str()).map_err(|e| {
			Error::IO(format!(
				"Unable to parse structured swap data from file {}, {}",
				path.to_str().unwrap_or("<INVALID PATH>"),
				e
			))
		})?;
	if record.format_version != CURRENT_SWAP_RECORD_VERSION {
		return Err(Error::IO(format!(
			"Unsupported swap record format version {} in file {}",
			record.format_version,
			path.to_str().unwrap_or("<INVALID PATH>")
		)));
	}
	let (context, swap) = (record.context, record.swap);

	if swap.version != CURRENT_VERSION {
		return Err(Error::IncompatibleVersion(swap.version, CURRENT_VERSION));
	}
	swap.validate_secondary_fee_units()?;
	swap.validate_confirmation_requirements()?;
	swap.validate_network(context_id)?;
	swap.validate_processed_incoming_messages()?;

	Ok((context, swap))
}

/// Store swap deal to a file
pub fn store_swap_trade(
	context_id: u32,
	context: &Context,
	swap: &Swap,
	enc_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<(), Error> {
	if lock.try_lock().is_some() {
		return Err(Error::Generic(format!(
			"store_swap_trade processing unlocked instance {}",
			swap.id
		)));
	}
	if swap.version != CURRENT_VERSION {
		return Err(Error::IncompatibleVersion(swap.version, CURRENT_VERSION));
	}
	swap.validate_secondary_fee_units()?;
	swap.validate_confirmation_requirements()?;
	swap.validate_processed_incoming_messages()?;

	// Writing to bak file. We don't want to loose the data in case of failure. It least the prev step will be left
	let swap_id = swap.id.to_string();
	let mut suffix = [0u8; 8];
	SysRng
		.try_fill_bytes(&mut suffix)
		.map_err(|e| Error::Generic(format!("Unable to generate swap backup suffix, {}", e)))?;
	let r = u64::from_be_bytes(suffix);
	let trade_dir = TRADE_DEALS_PATH
		.read()
		.get(&context_id)
		.cloned()
		.ok_or(Error::UndefinedTradeDealsPath)?;
	let path = trade_dir.join(format!("{}.swap_{}.bak", swap_id, r));
	{
		let mut stored_swap = File::create(&path).map_err(|e| {
			Error::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to create the file {} to store swap trade, {}",
					path.to_str().unwrap_or("<INVALID PATH>"),
					e
				),
			)
		})?;

		// Context and Swap both contain secret signing nonces. Serialize them into
		// one fixed, zeroizing allocation so buffer growth cannot leave plaintext
		// prefixes in freed heap allocations. A structured envelope also avoids
		// delimiter framing.
		let record = StoredSwapRecord {
			format_version: CURRENT_SWAP_RECORD_VERSION,
			context,
			swap,
		};
		let plaintext = sensitive::serialize_json(&record).map_err(|e| {
			Error::TradeIoError(
				swap_id.clone(),
				format!("Unable to serialize swap record, {}", e),
			)
		})?;
		let plaintext = std::str::from_utf8(&plaintext[..]).map_err(|e| {
			Error::TradeIoError(
				swap_id.clone(),
				format!("Serialized swap record is not valid UTF-8, {}", e),
			)
		})?;
		let encrypted_swap = EncryptedSwap::from_json(plaintext, enc_key)?;

		// The envelope contains only a public nonce and ciphertext, so it can be
		// serialized directly to its destination without a sensitive buffer.
		serde_json::to_writer(&mut stored_swap, &encrypted_swap).map_err(|e| {
			Error::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to write encrypted swap deal to file {}, {}",
					path.to_str().unwrap_or("<INVALID PATH>"),
					e
				),
			)
		})?;
		stored_swap.sync_all().map_err(|e| {
			Error::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to sync file {} all after writing swap deal, {}",
					path.to_str().unwrap_or("<INVALID PATH>"),
					e
				),
			)
		})?;
	}

	let path_target = trade_dir.join(format!("{}.swap", swap.id));
	fs::rename(&path, &path_target).map_err(|e| {
		Error::TradeIoError(
			swap_id.clone(),
			format!("Unable to finalize writing, rename failed with error {}", e),
		)
	})?;
	sync_directory(&trade_dir).map_err(|e| {
		Error::TradeIoError(
			swap_id,
			format!("Unable to sync swap trade directory after rename, {}", e),
		)
	})?;
	super::ethereum::funding::record_swap(swap);
	super::ethereum::recovery::record_swap(swap);

	Ok(())
}

/// Dump the content of swap file
pub fn dump_swap_trade(
	context_id: u32,
	swap_id: &str,
	dec_key: &SecretKey,
	lock: &Mutex<()>,
) -> Result<String, Error> {
	if lock.try_lock().is_some() {
		return Err(Error::Generic(format!(
			"dump_swap_trade processing unlocked instance {}",
			swap_id
		)));
	}

	let (canonical_swap_id, path) = swap_trade_path(context_id, swap_id)?;
	if !path.try_exists()? {
		return Err(Error::TradeNotFound(canonical_swap_id));
	}

	// Explicit plaintext dump API: the decrypted content is handed to the
	// caller as a plain String by design.
	Ok(read_swap_content(path.as_path(), dec_key)?.to_string())
}

/// Export encrypted trade data into the file
pub fn export_trade(
	context_id: u32,
	swap_id: &str,
	export_file_name: &str,
	lock: &Mutex<()>,
) -> Result<(), Error> {
	if lock.try_lock().is_some() {
		return Err(Error::Generic(format!(
			"export_trade processing unlocked instance {}",
			swap_id
		)));
	}
	let (canonical_swap_id, path) = swap_trade_path(context_id, swap_id)?;

	if !path.try_exists()? {
		return Err(Error::TradeNotFound(canonical_swap_id));
	}

	let export_path = Path::new(export_file_name);
	replace_owner_only_file_with(export_path, |replacement| {
		// Open and close the live record inside the write callback so even an
		// export onto the active path has released its source handle before the
		// temporary file is atomically installed.
		let mut source = File::open(&path)?;
		io::copy(&mut source, replacement)?;
		Ok(())
	})
	.map_err(|e| {
		Error::IO(format!(
			"Unable to export trade data into the file {}, {}",
			export_file_name, e
		))
	})?;

	Ok(())
}

/// Read and validate an encrypted trade backup without persisting it.
/// The caller can then acquire the canonical target-id lock before writing.
pub fn read_imported_trade(
	context_id: u32,
	trade_file_name: &str,
	dec_key: &SecretKey,
) -> Result<(Context, Swap), Error> {
	let src_path = Path::new(trade_file_name);
	if !src_path.exists() {
		return Err(Error::IO(format!("Not found file {}", trade_file_name)));
	}

	read_swap_data_from_file(context_id, src_path, dec_key)
}

/// Encrypt and decrypt swap files
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct EncryptedSwap {
	/// nonce used for encryption
	pub nonce: String,
	/// Encrypted base64 body swap + context
	pub body_enc: String,
}

impl EncryptedSwap {
	/// Encrypts and encodes json as base 64
	pub fn from_json(json_in: &str, enc_key: &SecretKey) -> Result<Self, Error> {
		// Preserve the legacy JSON-string payload format, but serialize it into a
		// fixed allocation so no ordinary growable String owns the plaintext.
		let mut to_encrypt = sensitive::serialize_json(json_in).map_err(|e| {
			Error::TradeEncDecError(format!("EncryptSwap Enc: unable to encode Json, {}", e))
		})?;

		let mut nonce = [0u8; 12];
		SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
			Error::EntropyError(format!("Unable to generate swap encryption nonce, {}", e))
		})?;
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &enc_key.0)
			.map_err(|e| Error::Generic(format!("Unable to build a key, {}", e)))?;
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let tag = sealing_key
			.seal_in_place_separate_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut to_encrypt[..],
			)
			.map_err(|e| {
				Error::TradeEncDecError(format!("EncryptedSwap Enc: Encryption failed, {}", e))
			})?;

		// Encryption has replaced the plaintext in place. It is now safe to join
		// the ciphertext and tag in an ordinary growable buffer for Base64 output.
		let tag_bytes: &[u8] = tag.as_ref();
		let sealed_len = to_encrypt
			.len()
			.checked_add(tag_bytes.len())
			.ok_or_else(|| {
				Error::DataOverflow("Encrypted swap payload length overflow".to_string())
			})?;
		let mut sealed = Vec::with_capacity(sealed_len);
		sealed.extend_from_slice(&to_encrypt);
		sealed.extend_from_slice(tag_bytes);

		Ok(EncryptedSwap {
			nonce: to_hex(&nonce),
			body_enc: STANDARD.encode(sealed),
		})
	}

	/// Decrypts and returns the original swap+context
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Zeroizing<String>, Error> {
		let mut to_decrypt = Zeroizing::new(STANDARD.decode(&self.body_enc).map_err(|e| {
			Error::TradeEncDecError(format!(
				"EncryptedSwap Dec: Encrypted swap contains invalid Base64, {}",
				e
			))
		})?);

		let nonce = from_hex(&self.nonce).map_err(|e| {
			Error::TradeEncDecError(format!(
				"EncryptedSwap Dec: Encrypted request contains invalid nonce, {}",
				e
			))
		})?;
		if nonce.len() != 12 {
			return Err(Error::TradeEncDecError(
				"EncryptedSwap Dec: Invalid Nonce length".to_string(),
			));
		}

		let n: [u8; 12] = nonce.try_into().map_err(|_| {
			Error::TradeEncDecError("EncryptedSwap Dec: Invalid Nonce length".to_string())
		})?;
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &dec_key.0)
			.map_err(|e| Error::Generic(format!("Unable to build a key, {}", e)))?;
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);

		let plaintext_len = opening_key
			.open_in_place(aead::Nonce::assume_unique_for_key(n), aad, &mut to_decrypt)
			.map_err(|e| {
				Error::TradeEncDecError(format!("EncryptedSwap Dec: Decryption failed, {}", e))
			})?
			.len();
		to_decrypt.truncate(plaintext_len);

		let decrypted = Zeroizing::new(String::from_utf8(to_decrypt.to_vec()).map_err(|_| {
			Error::TradeEncDecError("EncryptedSwap Dec: Invalid UTF-8".to_string())
		})?);

		// Accepted security tradeoff: legacy payloads contain a JSON-encoded string.
		// Serde unescaping can leave plaintext in an unzeroized scratch allocation;
		// Zeroizing protects our buffers and the returned String, not that copy.
		// Recovering these residual secrets requires an independent memory disclosure.
		// A custom JSON/Unicode decoder would add parsing and maintenance risk, so
		// this hardening improvement is deferred. Revisit with a versioned format
		// that encrypts the JSON object directly and migrates existing records.
		Ok(Zeroizing::new(serde_json::from_str(&decrypted).map_err(
			|e| Error::TradeEncDecError(format!("EncryptedSwap Dec: Invalid JSON, {}", e)),
		)?))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;

	#[test]
	fn encrypted_swap_roundtrip_and_nonce_length_validation() -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let key = SecretKey::from_slice(&secp, &[7; 32])?;
		let plaintext = "swap payload".to_owned();
		let encrypted = EncryptedSwap::from_json(&plaintext, &key)?;
		assert_eq!(encrypted.decrypt(&key)?.as_str(), plaintext.as_str());

		let mut long_nonce = encrypted.clone();
		long_nonce.nonce.push_str("00");
		assert!(long_nonce.decrypt(&key).is_err());

		let mut short_nonce = encrypted;
		short_nonce.nonce.truncate(22);
		assert!(short_nonce.decrypt(&key).is_err());
		Ok(())
	}

	#[test]
	fn structured_record_rejects_legacy_delimiter_framing() {
		let record = r#"{"context":1}<#>{"tag":"offer<#>tag"}"#;
		assert!(serde_json::from_str::<StoredSwapRecord<Context, Swap>>(record).is_err());
	}

	#[test]
	fn swap_ids_are_canonicalized_and_path_components_are_rejected() {
		let id = Uuid::parse_str("550E8400-E29B-41D4-A716-446655440000").unwrap();
		assert_eq!(
			canonical_swap_id("550E8400-E29B-41D4-A716-446655440000").unwrap(),
			id.to_string()
		);
		assert!(canonical_swap_id("./550e8400-e29b-41d4-a716-446655440000").is_err());
		assert!(canonical_swap_id("../550e8400-e29b-41d4-a716-446655440000").is_err());
		assert!(canonical_swap_id("/tmp/550e8400-e29b-41d4-a716-446655440000").is_err());
	}

	#[test]
	fn canonical_spellings_share_one_context_scoped_lock() {
		let upper = "550E8400-E29B-41D4-A716-446655440000";
		let lower = "550e8400-e29b-41d4-a716-446655440000";
		let first = get_swap_lock(71, upper).unwrap();
		let same = get_swap_lock(71, lower).unwrap();
		let other_context = get_swap_lock(72, lower).unwrap();

		assert!(Arc::ptr_eq(&first, &same));
		assert!(!Arc::ptr_eq(&first, &other_context));
		assert!(get_swap_lock(71, &format!("./{}", lower)).is_err());

		trades_clean_context(71);
		trades_clean_context(72);
	}

	#[test]
	fn export_trade_atomically_replaces_self_and_existing_backup() -> Result<(), Error> {
		let storage = tempdir().map_err(|e| Error::IO(e.to_string()))?;
		let context_id = 73_001;
		init_swap_trade_backend(
			context_id,
			storage.path().to_str().unwrap(),
			&None,
			&None,
			&None,
			&None,
		)?;

		let swap_id = "550e8400-e29b-41d4-a716-446655440000";
		let source = storage
			.path()
			.join(SWAP_DEAL_SAVE_DIR)
			.join(format!("{}.swap", swap_id));
		let contents = b"nonempty encrypted swap record";
		fs::write(&source, contents).map_err(|e| Error::IO(e.to_string()))?;

		let swap_lock = get_swap_lock(context_id, swap_id)?;
		let _guard = swap_lock.lock();
		export_trade(
			context_id,
			swap_id,
			source.to_str().unwrap(),
			&*swap_lock,
		)?;
		assert_eq!(fs::read(&source)?, contents);

		let backup = storage.path().join("trade.backup");
		fs::write(&backup, b"previous valid backup")?;
		export_trade(
			context_id,
			swap_id,
			backup.to_str().unwrap(),
			&*swap_lock,
		)?;
		assert_eq!(fs::read(&backup)?, contents);

		drop(_guard);
		trades_clean_context(context_id);
		Ok(())
	}
}
