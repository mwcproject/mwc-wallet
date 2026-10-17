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

#[cfg(any(feature = "swaps", feature = "test-support"))]
use mwc_wallet_util::mwc_crates::rand::TryRng;
use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::{fs, path};

// for writing stored transaction files
use std::fs::File;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::zeroizing_blake2b::zeroizing_blake2b;

#[cfg(feature = "swaps")]
use mwc_wallet_util::mwc_crates::chacha20poly1305::{
	ChaCha20Poly1305,
	aead::{AeadInOut, KeyInit},
};
#[cfg(feature = "swaps")]
use mwc_wallet_util::mwc_crates::serde_json;
#[cfg(feature = "swaps")]
use mwc_wallet_util::sensitive;

use mwc_wallet_libwallet::internal::keys::canonicalize_stored_identifier;
use mwc_wallet_libwallet::reply_cache::ReplyCache;
use mwc_wallet_libwallet::slate_process::SlateProcessTracker;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::ethereum::EthereumWallet;
use mwc_wallet_libwallet::types::U64_DATA_IDX_LAST_CONFIRMED_HEIGHT;
use mwc_wallet_libwallet::{
	AcctPathMapping, Context, Error, NodeClient, OutputData, ScannedBlockInfo, TxLogEntry, TxProof,
	WalletBackend, WalletOutputBatch,
};
use mwc_wallet_util::file::replace_owner_only_file_with;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::ser;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::constants::SECRET_KEY_SIZE;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_keychain::{
	ChildNumber, ExtKeychain, Identifier, Keychain, SwitchCommitmentType,
};
use mwc_wallet_util::mwc_store::{self, option_to_not_found, to_key, to_key_u64, u64_to_key};
use mwc_wallet_util::mwc_util;
use mwc_wallet_util::mwc_util::ToHex;

#[cfg(feature = "test-support")]
use mwc_wallet_libwallet::step_rng::StepRng;
use mwc_wallet_util::mwc_core::ser::Readable;
use mwc_wallet_util::mwc_crates::log::{debug, error};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;

pub const DB_DIR: &str = "db";
pub const TX_SAVE_DIR: &str = "saved_txs";
pub const TX_ARCHIVE_DIR: &str = "archived_txs";
pub const STORED_TX_PROTOCOL_VERSION: ser::ProtocolVersion = ser::ProtocolVersion(3);

const OUTPUT_PREFIX: u8 = b'o';
const OUTPUT_ARCHIVE_PREFIX: u8 = b'O';
const DERIV_PREFIX: u8 = b'd';
// Older versions used b'c' for account-scoped confirmed heights; those records
// are intentionally ignored because the scan watermark describes one wallet-wide
// node view, not the currently selected account.
// Was b'p' before all four secret Context fields were masked. Contexts written
// with that old scheme (initial_sec_key/initial_sec_nonce in cleartext) remain
// intentionally unreadable; such transactions are pending only and can be
// cancelled and recreated.
//
// b'P' originally masked all four fields without binding participant_id. A
// one-time migration re-encrypts those records in place; the database marker
// records which mask derivation applies to this prefix.
const PRIVATE_TX_CONTEXT_PREFIX: u8 = b'P';
const PRIVATE_CTX_MASK_KDF_DOMAIN: &[u8] = b"mwc-wallet/private-context-mask/v2";
#[cfg(feature = "swaps")]
const ETHEREUM_WALLET_MASK_KDF_DOMAIN: &[u8] = b"mwc-wallet/ethereum-wallet-mask/v1";
#[cfg(feature = "swaps")]
const ETHEREUM_WALLET_MASK_AAD: &[u8] = b"mwc-wallet/ethereum-wallet/v1";
const TX_LOG_ENTRY_PREFIX: u8 = b't';
const TX_ARCHIVE_LOG_ENTRY_PREFIX: u8 = b'T';
const TX_LOG_ID_PREFIX: u8 = b'i';
const ACCOUNT_PATH_MAPPING_PREFIX: u8 = b'a';
const LAST_SCANNED_BLOCK: u8 = b'm'; // pre v3.0 was l
									 // Single u64 values. See U64_DATA_IDX_ for available indexes
const U64_DATA: u8 = b'n';
const FLAGS: u8 = b'f'; // pre v3.0 was l
/// Address indexes pinned before marketplace bids become Swap Deals.
#[cfg(feature = "swaps")]
const MARKETPLACE_SIGNING_INDEX_PREFIX: u8 = b'b';

/// Ethereum spend material retained by an open backend. A masked wallet keeps
/// only authenticated ciphertext; plaintext exists only in the short-lived
/// value returned to an operation that supplies the correct session mask.
#[cfg(feature = "swaps")]
enum StoredEthereumWallet {
	Unmasked(EthereumWallet),
	Masked {
		nonce: [u8; 12],
		ciphertext: Zeroizing<Vec<u8>>,
	},
}

#[cfg(feature = "swaps")]
impl StoredEthereumWallet {
	fn encryption_key(mask: &SecretKey) -> Zeroizing<Vec<u8>> {
		zeroizing_blake2b(
			SECRET_KEY_SIZE,
			&mask.0,
			ETHEREUM_WALLET_MASK_KDF_DOMAIN,
		)
	}

	fn new(
		wallet: EthereumWallet,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Self, Error> {
		let Some(mask) = keychain_mask else {
			return Ok(Self::Unmasked(wallet));
		};

		let mut plaintext = sensitive::serialize_json(&wallet).map_err(|e| {
			Error::APIEncryption(format!(
				"Unable to serialize Ethereum wallet for in-memory protection, {}",
				e
			))
		})?;
		let key = Self::encryption_key(mask);
		let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|e| {
			Error::APIEncryption(format!(
				"Unable to initialize Ethereum wallet in-memory protection, {}",
				e
			))
		})?;
		let mut nonce = [0u8; 12];
		SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
			Error::GenericError(format!(
				"Unable to generate Ethereum wallet protection nonce, {}",
				e
			))
		})?;
		let tag = cipher
			.encrypt_inout_detached(
				(&nonce).into(),
				ETHEREUM_WALLET_MASK_AAD,
				(&mut plaintext[..]).into(),
			)
			.map_err(|e| {
				Error::APIEncryption(format!(
					"Unable to protect Ethereum wallet in memory, {}",
					e
				))
			})?;

		// The fixed buffer now contains only ciphertext.
		Ok(Self::Masked {
			nonce,
			ciphertext: Zeroizing::new([&plaintext[..], tag.as_slice()].concat()),
		})
	}

	fn expose(&self, keychain_mask: Option<&SecretKey>) -> Result<EthereumWallet, Error> {
		match (self, keychain_mask) {
			(Self::Unmasked(wallet), None) => Ok(wallet.clone()),
			(Self::Unmasked(_), Some(_)) | (Self::Masked { .. }, None) => {
				Err(Error::InvalidKeychainMask)
			}
			(
				Self::Masked { nonce, ciphertext },
				Some(mask),
			) => {
				let key = Self::encryption_key(mask);
				let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
					.map_err(|_| Error::InvalidKeychainMask)?;
				let mut plaintext = ciphertext.clone();
				cipher
					.decrypt_in_place(
						(&*nonce).into(),
						ETHEREUM_WALLET_MASK_AAD,
						&mut *plaintext,
					)
					.map_err(|_| Error::InvalidKeychainMask)?;
				serde_json::from_slice(plaintext.as_slice()).map_err(|e| {
					Error::APIEncryption(format!(
						"Unable to deserialize protected Ethereum wallet, {}",
						e
					))
				})
			}
		}
	}
}

/// test to see if database files exist in the current directory. If so,
/// use a DB backend for all operations
pub fn wallet_db_exists(data_file_dir: &str) -> bool {
	let db_path = path::Path::new(data_file_dir).join(DB_DIR);
	db_path.exists()
}

/// Derive the masks used by the legacy b'P' private-context format. This must
/// remain byte for byte compatible with the previous derivation so those
/// records can be migrated once.
fn legacy_private_ctx_xor_keys<K>(
	secp: &Secp256k1,
	keychain: &K,
	slate_id: &[u8],
) -> Result<Zeroizing<[[u8; SECRET_KEY_SIZE]; 4]>, Error>
where
	K: Keychain,
{
	let root_key =
		keychain.derive_key(secp, 0, &K::root_key_id()?, SwitchCommitmentType::Regular)?;

	// derive XOR values for storing secret values in DB
	// h(root_key|slate_id|domain)
	let mut ret = Zeroizing::new([[0u8; SECRET_KEY_SIZE]; 4]);
	for (mask, domain) in ret.iter_mut().zip(
		[
			&b"blind"[..],
			&b"nonce"[..],
			&b"initial_blind"[..],
			&b"initial_nonce"[..],
		]
		.iter(),
	) {
		let preimage_len = root_key
			.0
			.len()
			.checked_add(slate_id.len())
			.and_then(|len| len.checked_add(domain.len()))
			.ok_or_else(|| {
				Error::DataOverflow(
					"private_ctx_xor_keys, Blake2b preimage length overflow".to_owned(),
				)
			})?;
		let mut preimage = Zeroizing::new(Vec::with_capacity(preimage_len));
		preimage.extend_from_slice(&root_key.0);
		preimage.extend_from_slice(slate_id);
		preimage.extend_from_slice(domain);

		let digest = zeroizing_blake2b(SECRET_KEY_SIZE, &[], preimage.as_slice());
		mask.copy_from_slice(digest.as_slice());
	}

	Ok(ret)
}

/// Helper to derive XOR keys for storing private transaction keys in the DB.
/// Returns one mask per secret Context field, in the order sec_key, sec_nonce,
/// initial_sec_key, initial_sec_nonce. The participant id and framed slate id
/// make every persisted participant/field pair use an independent keyed-BLAKE2b
/// mask. Masks, hash inputs and hash state remain in zeroizing storage.
fn private_ctx_xor_keys<K>(
	secp: &Secp256k1,
	keychain: &K,
	slate_id: &[u8],
	participant_id: u64,
) -> Result<Zeroizing<[[u8; SECRET_KEY_SIZE]; 4]>, Error>
where
	K: Keychain,
{
	let root_key =
		keychain.derive_key(secp, 0, &K::root_key_id()?, SwitchCommitmentType::Regular)?;
	let slate_id_len = u64::try_from(slate_id.len()).map_err(|e| {
		Error::DataOverflow(format!(
			"private_ctx_xor_keys, slate id length does not fit u64, length={} error={}",
			slate_id.len(),
			e
		))
	})?;

	let mut ret = Zeroizing::new([[0u8; SECRET_KEY_SIZE]; 4]);
	for (mask, field_domain) in ret.iter_mut().zip(
		[
			&b"blind"[..],
			&b"nonce"[..],
			&b"initial_blind"[..],
			&b"initial_nonce"[..],
		]
		.iter(),
	) {
		let preimage_len = PRIVATE_CTX_MASK_KDF_DOMAIN
			.len()
			.checked_add(std::mem::size_of::<u64>())
			.and_then(|len| len.checked_add(slate_id.len()))
			.and_then(|len| len.checked_add(std::mem::size_of::<u64>()))
			.and_then(|len| len.checked_add(field_domain.len()))
			.ok_or_else(|| {
				Error::DataOverflow(
					"private_ctx_xor_keys, Blake2b preimage length overflow".to_owned(),
				)
			})?;
		let mut preimage = Zeroizing::new(Vec::with_capacity(preimage_len));
		preimage.extend_from_slice(PRIVATE_CTX_MASK_KDF_DOMAIN);
		preimage.extend_from_slice(&slate_id_len.to_be_bytes());
		preimage.extend_from_slice(slate_id);
		preimage.extend_from_slice(&participant_id.to_be_bytes());
		preimage.extend_from_slice(field_domain);

		let digest = zeroizing_blake2b(SECRET_KEY_SIZE, &root_key.0, preimage.as_slice());
		mask.copy_from_slice(digest.as_slice());
	}

	Ok(ret)
}

fn xor_private_context_secret_fields(ctx: &mut Context, xor_keys: &[[u8; SECRET_KEY_SIZE]; 4]) {
	for (secret, mask) in [
		&mut ctx.sec_key.0,
		&mut ctx.sec_nonce.0,
		&mut ctx.initial_sec_key.0,
		&mut ctx.initial_sec_nonce.0,
	]
	.into_iter()
	.zip(xor_keys.iter())
	{
		for (secret_byte, mask_byte) in secret.iter_mut().zip(mask.iter()) {
			*secret_byte ^= *mask_byte;
		}
	}
}

fn private_context_key_parts(ctx_key: &[u8], prefix: u8) -> Result<(&[u8], u64), Error> {
	const PREFIX_LEN: usize = 2;
	const PARTICIPANT_SUFFIX_LEN: usize = std::mem::size_of::<u64>();

	let expected_prefix = [prefix, b':'];
	if ctx_key.get(..PREFIX_LEN) != Some(expected_prefix.as_slice()) {
		return Err(Error::Backend(format!(
			"Private context key has an invalid prefix, key={:x?}",
			ctx_key
		)));
	}
	if ctx_key.len() <= PREFIX_LEN + PARTICIPANT_SUFFIX_LEN {
		return Err(Error::Backend(format!(
			"Private context key is too short, key_len={} minimum_len={}",
			ctx_key.len(),
			PREFIX_LEN + PARTICIPANT_SUFFIX_LEN + 1
		)));
	}

	let slate_id_end = ctx_key
		.len()
		.checked_sub(PARTICIPANT_SUFFIX_LEN)
		.ok_or_else(|| Error::Backend("Private context key suffix underflow".to_owned()))?;
	let slate_id = ctx_key
		.get(PREFIX_LEN..slate_id_end)
		.ok_or_else(|| Error::Backend("Private context key has invalid boundaries".to_owned()))?;
	let participant_bytes: [u8; PARTICIPANT_SUFFIX_LEN] = ctx_key
		.get(slate_id_end..)
		.ok_or_else(|| {
			Error::Backend("Private context key is missing its participant id".to_owned())
		})?
		.try_into()
		.map_err(|_| {
			Error::Backend("Private context participant id has invalid length".to_owned())
		})?;

	Ok((slate_id, u64::from_be_bytes(participant_bytes)))
}

fn canonicalize_identifier_field(identifier: &mut Identifier) -> Result<bool, Error> {
	let (canonical, _) = canonicalize_stored_identifier(identifier)?;
	if canonical == *identifier {
		Ok(false)
	} else {
		*identifier = canonical;
		Ok(true)
	}
}

fn output_db_key(prefix: u8, output: &OutputData) -> Result<Vec<u8>, Error> {
	match output.mmr_index {
		Some(mmr_index) => Ok(to_key_u64(prefix, output.key_id.to_bytes(), mmr_index)?),
		None => Ok(to_key(prefix, output.key_id.to_bytes())),
	}
}

// Decode the established wallet formats without trying to enrich commitment-only
// inputs. A stored transaction must remain readable offline and after its inputs
// have been spent; at that point a node UTXO lookup cannot provide their features.
// The core commitment-only form is sufficient for direct reposting. Only callers
// that export it through the legacy TransactionV3 schema need a documented Plain
// placeholder for that schema's mandatory feature field.
fn read_stored_tx(mut tx_file: File, context_id: u32) -> Result<Transaction, Error> {
	let mut content = String::new();
	tx_file.read_to_string(&mut content)?;
	let tx_bin = mwc_util::from_hex(&content).map_err(|e| {
		Error::StoredTransactionError(format!("Unable to decode the data, {}", e))
	})?;
	for version in [
		STORED_TX_PROTOCOL_VERSION,
		ser::ProtocolVersion(2),
		ser::ProtocolVersion(1),
	] {
		if let Ok(tx) = ser::deserialize_strict(&mut &tx_bin[..], version, context_id, true) {
			return Ok(tx);
		}
	}
	Err(Error::StoredTransactionError(
		"Unable to deserialize the data with supported protocol versions".to_string(),
	))
}

/// Stored transaction references are filenames, never paths. Rejecting every
/// component other than one normal filename prevents absolute-path replacement
/// and parent-directory traversal when the name is joined to the wallet's
/// saved/archived transaction directories.
fn checked_stored_tx_filename(filename: &str) -> Result<&Path, Error> {
	let path = Path::new(filename);
	let mut components = path.components();
	match (components.next(), components.next()) {
		(Some(Component::Normal(_)), None) => Ok(path),
		_ => Err(Error::StoredTransactionError(
			"stored transaction reference must be a single filename".to_string(),
		)),
	}
}

fn stored_tx_files_equal(first_path: &Path, second_path: &Path) -> io::Result<bool> {
	if fs::metadata(first_path)?.len() != fs::metadata(second_path)?.len() {
		return Ok(false);
	}

	let mut first = File::open(first_path)?;
	let mut second = File::open(second_path)?;
	let mut first_buffer = [0u8; 65_536];
	let mut second_buffer = [0u8; 65_536];

	loop {
		let first_len = first.read(&mut first_buffer)?;
		let second_len = second.read(&mut second_buffer)?;
		if first_len != second_len
			|| first_buffer.get(..first_len) != second_buffer.get(..second_len)
		{
			return Ok(false);
		}
		if first_len == 0 {
			return Ok(true);
		}
	}
}

/// Run an installation whose destination was verified absent. The secure file
/// replacement helper can report a directory-sync error after publishing the
/// destination, so remove any possibly published file before returning failure.
fn install_new_tx_archive_with_cleanup<F>(destination: &Path, install: F) -> Result<(), Error>
where
	F: FnOnce() -> io::Result<()>,
{
	if let Err(install_error) = install() {
		match fs::remove_file(destination) {
			Ok(()) => {}
			Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => {}
			Err(cleanup_error) => {
				return Err(Error::IO(format!(
					"Unable to install stored transaction archive {}: {}; additionally unable to remove the possibly installed archive: {}",
					destination.display(),
					install_error,
					cleanup_error
				)));
			}
		}
		return Err(install_error.into());
	}

	Ok(())
}

struct PreparedTxArchive {
	source: PathBuf,
	destination: PathBuf,
	destination_created: bool,
}

pub struct LMDBBackend<'ck, C, K>
where
	C: NodeClient + 'ck,
	K: Keychain + 'ck,
{
	context_id: u32,
	db: mwc_store::Store,
	data_file_dir: String,
	/// Keychain kept in its original stable heap allocation.
	pub keychain: Option<Box<K>>,
	/// Check value for XORed keychain seed
	pub master_checksum: Box<Option<Zeroizing<Vec<u8>>>>,
	/// Parent path to use by default for output operations
	parent_key_id: Identifier,
	/// wallet to node client
	w2n_client: C,
	/// Short-lived replies for authenticated retrying peers.
	///
	/// This state is backend-local because opening a second backend for the
	/// same wallet data directory is outside the supported lifecycle.
	reply_cache: Arc<ReplyCache>,
	/// Externally supplied Slate UUIDs currently being processed by this
	/// wallet's sole supported backend instance.
	slate_process_tracker: Arc<SlateProcessTracker>,
	/// ethereum wallet instance
	#[cfg(feature = "swaps")]
	ethereum_wallet: Option<StoredEthereumWallet>,
	///phantom
	_phantom: &'ck PhantomData<C>,
}

impl<'ck, C, K> LMDBBackend<'ck, C, K>
where
	C: NodeClient + 'ck,
	K: Keychain + 'ck,
{
	pub fn new(context_id: u32, data_file_dir: &str, n_client: C) -> Result<Self, Error> {
		// `LMDBBackend` is not a multi-instance coordination boundary. Wallet
		// lifecycle code must ensure that this is the only live backend for
		// `data_file_dir`; per-wallet guards and caches below rely on that
		// invariant.
		let db_path = path::Path::new(data_file_dir).join(DB_DIR);
		fs::create_dir_all(&db_path).map_err(|e| {
			Error::Backend(format!(
				"Couldn't create wallet backend directory {}, {}",
				db_path.to_string_lossy(),
				e
			))
		})?;
		let stored_tx_path = path::Path::new(data_file_dir).join(TX_SAVE_DIR);
		fs::create_dir_all(&stored_tx_path).map_err(|e| {
			Error::Backend(format!(
				"Couldn't create wallet backend tx storage directory {}, {}",
				stored_tx_path.to_string_lossy(),
				e
			))
		})?;
		let stored_tx_path = path::Path::new(data_file_dir).join(TX_ARCHIVE_DIR);
		fs::create_dir_all(&stored_tx_path).map_err(|e| {
			Error::Backend(format!(
				"Couldn't create wallet backend tx storage directory {}, {}",
				stored_tx_path.to_string_lossy(),
				e
			))
		})?;

		let store = mwc_store::Store::new(
			context_id,
			db_path
				.to_str()
				.ok_or(Error::Backend("Couldn't build db_path value".into()))?,
			None,
			Some(DB_DIR),
			None,
		)?;

		// Make sure default wallet derivation path always exists
		// as well as path (so it can be retrieved by batches to know where to store
		// completed transactions, for reference
		let default_account = AcctPathMapping {
			label: "default".to_owned(),
			path: LMDBBackend::<C, K>::default_path()?,
		};
		let acct_key = to_key(
			ACCOUNT_PATH_MAPPING_PREFIX,
			&mut default_account.label.as_bytes().to_vec(),
		);

		{
			let batch = store.batch_write()?;
			batch.put_ser(&acct_key, &default_account)?;
			batch.commit()?;
		}

		TxProof::init_proof_backend(data_file_dir)?;

		let res = LMDBBackend {
			context_id,
			db: store,
			data_file_dir: data_file_dir.to_owned(),
			keychain: None,
			master_checksum: Box::new(None),
			parent_key_id: LMDBBackend::<C, K>::default_path()?,
			w2n_client: n_client,
			reply_cache: Arc::new(ReplyCache::new()),
			slate_process_tracker: Arc::new(SlateProcessTracker::new()),
			#[cfg(feature = "swaps")]
			ethereum_wallet: None,
			_phantom: &PhantomData,
		};
		Ok(res)
	}

	fn default_path() -> Result<Identifier, Error> {
		// return the default parent wallet path, corresponding to the default account
		// in the BIP32 spec. Parent is account 0 at level 2, child output identifiers
		// are all at level 3
		Ok(ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?)
	}

	/// Just test to see if database files exist in the current directory. If
	/// so, use a DB backend for all operations. Returns an error if the file
	/// system cannot determine whether the database path exists.
	pub fn exists(data_file_dir: &str) -> Result<bool, Error> {
		let db_path = path::Path::new(data_file_dir).join(DB_DIR);
		db_path.try_exists().map_err(|e| {
			Error::IO(format!(
				"Unable to check wallet database path {}, {}",
				db_path.to_string_lossy(),
				e
			))
		})
	}

	fn iter_impl<'a, T: Readable + 'a>(
		&'a self,
		prefix: u8,
	) -> Result<Box<dyn Iterator<Item = T> + 'a>, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self.db.iter(&[prefix], move |_, mut v| {
			ser::deserialize_strict(&mut v, protocol_version, self.context_id, true).map_err(From::from)
		});
		let values = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(Box::new(values.into_iter()))
	}

	fn prepare_mwctx_archive(&self, tx: &TxLogEntry) -> Result<Option<PreparedTxArchive>, Error> {
		let filename = match tx.stored_tx.clone() {
			Some(f) => f,
			None => match tx.tx_slate_id {
				Some(uuid) => format!("{}.mwctx", uuid),
				None => return Ok(None),
			},
		};
		let filename = checked_stored_tx_filename(&filename)?;

		let path_from = path::Path::new(&self.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);

		if !path_from.try_exists()? {
			return Ok(None);
		}

		let path_to = path::Path::new(&self.data_file_dir)
			.join(TX_ARCHIVE_DIR)
			.join(filename);

		let destination_created = if path_to.try_exists()? {
			if !stored_tx_files_equal(&path_from, &path_to)? {
				return Err(Error::StoredTransactionError(format!(
					"Stored transaction archive destination {} already exists with different contents",
					path_to.display()
				)));
			}
			false
		} else {
			install_new_tx_archive_with_cleanup(&path_to, || {
				replace_owner_only_file_with(&path_to, |archived_tx| {
					let mut saved_tx = File::open(&path_from)?;
					io::copy(&mut saved_tx, archived_tx)?;
					Ok(())
				})
			})?;
			true
		};

		Ok(Some(PreparedTxArchive {
			source: path_from,
			destination: path_to,
			destination_created,
		}))
	}

	pub fn archive_mwctx_data(&self, tx: &TxLogEntry) -> Result<(), Error> {
		if let Some(prepared) = self.prepare_mwctx_archive(tx)? {
			match fs::remove_file(prepared.source) {
				Ok(()) => {}
				Err(e) if e.kind() == io::ErrorKind::NotFound => {}
				Err(e) => return Err(e.into()),
			}
		}

		Ok(())
	}
}

impl<'ck, C, K> WalletBackend<'ck, C, K> for LMDBBackend<'ck, C, K>
where
	C: NodeClient + 'ck,
	K: Keychain + 'ck,
{
	fn get_context_id(&self) -> u32 {
		self.context_id
	}

	/// data file directory. mwc713 needs it
	fn get_data_file_dir(&self) -> &str {
		&self.data_file_dir
	}

	/// Set the keychain, which should already have been opened
	fn set_keychain(
		&mut self,
		secp: &Secp256k1,
		mut k: Box<K>,
		mask: bool,
		#[cfg(feature = "test-support")] use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error> {
		// store hash of master key, so it can be verified later after unmasking
		let root_key = k.derive_key(secp, 0, &K::root_key_id()?, SwitchCommitmentType::Regular)?;
		self.master_checksum = Box::new(Some(zeroizing_blake2b(SECRET_KEY_SIZE, &[], &root_key.0[..])));

		let mask_value = {
			match mask {
				true => {
					// Random value that must be XORed against the stored wallet seed
					// before it is used
					#[cfg(feature = "test-support")]
					let mask_value = if use_test_rng {
						let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
						let mut key_bytes = [0u8; SECRET_KEY_SIZE];
						match test_rng.try_fill_bytes(&mut key_bytes) {
							Ok(()) => {}
							Err(e) => match e {},
						}
						SecretKey::from_slice(secp, &key_bytes)?
					} else {
						SecretKey::new(secp, &mut SysRng)?
					};
					#[cfg(not(feature = "test-support"))]
					let mask_value = SecretKey::new(secp, &mut SysRng)?;
					k.mask_master_key(&mask_value)?;
					Some(mask_value)
				}
				false => None,
			}
		};

		self.keychain = Some(k);
		Ok(mask_value)
	}

	/// Close wallet
	fn close(&mut self) -> Result<(), Error> {
		self.reply_cache.clear();
		self.slate_process_tracker.clear();
		self.keychain = None;
		*self.master_checksum = None;
		#[cfg(feature = "swaps")]
		{
			self.ethereum_wallet = None;
		}
		Ok(())
	}

	fn reply_cache(&self) -> Arc<ReplyCache> {
		Arc::clone(&self.reply_cache)
	}

	fn slate_process_tracker(&self) -> Arc<SlateProcessTracker> {
		Arc::clone(&self.slate_process_tracker)
	}

	/// Return the keychain being used, cloned with XORed token value
	/// for temporary use
	fn keychain(&self, secp: &Secp256k1, mask: Option<&SecretKey>) -> Result<K, Error> {
		match self.keychain.as_ref() {
			Some(k) => {
				let mut k_masked = k.as_ref().clone();
				if let Some(m) = mask {
					k_masked.mask_master_key(m)?;
				}
				// Check if master seed is what is expected (especially if it's been xored)
				let root_key = k_masked.derive_key(
					secp,
					0,
					&K::root_key_id()?,
					SwitchCommitmentType::Regular,
				)?;
				let checksum = zeroizing_blake2b(SECRET_KEY_SIZE, &[], &root_key.0[..]);
				if (*self.master_checksum).as_ref().map(|c| &c[..]) != Some(&checksum[..]) {
					error!("Supplied keychain mask is invalid");
					return Err(Error::InvalidKeychainMask);
				}
				Ok(k_masked)
			}
			None => Err(Error::KeychainDoesntExist),
		}
	}

	/// Return the node client being used
	fn w2n_client(&mut self) -> &mut C {
		&mut self.w2n_client
	}

	/// return the version of the commit for caching
	fn calc_commit(
		&self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Commitment, Error> {
		Ok(self.keychain(secp, keychain_mask)?.commit(
			secp,
			amount,
			&id,
			SwitchCommitmentType::Regular,
		)?)
	}

	/// Set parent path by account name
	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error> {
		let label = label.to_owned();
		let res = self.acct_path_iter()?.find(|l| l.label == label);
		if let Some(a) = res {
			self.set_parent_key_id(a.path);
			Ok(())
		} else {
			Err(Error::UnknownAccountLabel(label))
		}
	}

	/// set parent path
	fn set_parent_key_id(&mut self, id: Identifier) {
		self.parent_key_id = id;
	}

	fn parent_key_id(&self) -> Identifier {
		self.parent_key_id.clone()
	}

	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i)?,
			None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
		};
		option_to_not_found(self.db.get_ser(&key), || format!("Key Id: {}", id)).map_err(|e| {
			if e.store_error_is_not_found() {
				Error::OutputNotFound(e.to_string())
			} else {
				e.into()
			}
		})
	}

	fn iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = OutputData> + 'a>, Error> {
		self.iter_impl(OUTPUT_PREFIX)
	}

	fn archive_iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = OutputData> + 'a>, Error> {
		self.iter_impl(OUTPUT_ARCHIVE_PREFIX)
	}

	fn tx_log_iter<'a>(&'a self) -> Result<Box<dyn Iterator<Item = TxLogEntry> + 'a>, Error> {
		self.iter_impl(TX_LOG_ENTRY_PREFIX)
	}

	fn tx_log_archive_iter<'a>(
		&'a self,
	) -> Result<Box<dyn Iterator<Item = TxLogEntry> + 'a>, Error> {
		self.iter_impl(TX_ARCHIVE_LOG_ENTRY_PREFIX)
	}

	fn get_private_context(
		&mut self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<Context, Error> {
		let participant_id = u64::try_from(participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"LMDBBackend::get_private_context, participant id does not fit u64, participant_id={} error={}",
				participant_id, e
			))
		})?;
		let ctx_key = to_key_u64(PRIVATE_TX_CONTEXT_PREFIX, slate_id, participant_id)?;
		let xor_keys = private_ctx_xor_keys(
			secp,
			&self.keychain(secp, keychain_mask)?,
			slate_id,
			participant_id,
		)?;

		let mut ctx: Context = option_to_not_found(self.db.get_ser(&ctx_key), || {
			format!("Slate id: {:x?}", slate_id.to_vec())
		})
		.map_err(|e| {
			if e.store_error_is_not_found() {
				Error::PrivateContextNotFound(format!(
					"slate_id={:x?}, participant_id={}, source={}",
					slate_id, participant_id, e
				))
			} else {
				e.into()
			}
		})?;

		xor_private_context_secret_fields(&mut ctx, &xor_keys);

		Ok(ctx)
	}

	fn acct_path_iter<'a>(
		&'a self,
	) -> Result<Box<dyn Iterator<Item = AcctPathMapping> + 'a>, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self
			.db
			.iter(&[ACCOUNT_PATH_MAPPING_PREFIX], move |_, mut v| {
				ser::deserialize_strict(&mut v, protocol_version, self.context_id, true)
				.map_err(From::from)
			});
		let values = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(Box::new(values.into_iter()))
	}

	fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error> {
		let acct_key = to_key(ACCOUNT_PATH_MAPPING_PREFIX, &mut label.as_bytes().to_vec());
		self.db.get_ser(&acct_key).map_err(|e| e.into())
	}

	fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error> {
		// `uuid` is an already-validated Slate UUID string, not a filename or path:
		// every supported caller obtains it by formatting a typed `Uuid`.
		let filename = format!("{}.mwctx", uuid);
		let path = path::Path::new(&self.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(&filename);
		let tx_hex = ser::ser_vec(self.context_id, tx, STORED_TX_PROTOCOL_VERSION, true)?.to_hex();
		replace_owner_only_file_with(&path, |stored_tx| stored_tx.write_all(tx_hex.as_bytes()))?;
		Ok(())
	}

	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, Error> {
		let filename = match entry.stored_tx.clone() {
			Some(f) => f,
			None => match entry.tx_slate_id {
				Some(uuid) => format!("{}.mwctx", uuid),
				None => return Ok(None),
			},
		};
		let filename = checked_stored_tx_filename(&filename)?;

		let path_save = path::Path::new(&self.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);

		let path_archive = path::Path::new(&self.data_file_dir)
			.join(TX_ARCHIVE_DIR)
			.join(filename);

		match File::open(&path_save) {
			Ok(tx_file) => return Ok(Some(read_stored_tx(tx_file, self.context_id)?)),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => return Err(e.into()),
		}

		Ok(Some(read_stored_tx(
			File::open(path_archive)?,
			self.context_id,
		)?))
	}

	// mwc need to suport extentions mwctx and grintx because 2.4 version has grintx, 3.0 mwctx
	fn get_stored_tx_by_uuid(&self, uuid: &str, archived: bool) -> Result<Transaction, Error> {
		let get_stored_tx_by_uuid_ext =
			|uuid: &str, extention: &str| -> Result<Transaction, Error> {
				let filename = format!("{}.{}", uuid, extention);
				let filename = checked_stored_tx_filename(&filename)?;

				let dir = if archived {
					TX_ARCHIVE_DIR
				} else {
					TX_SAVE_DIR
				};

				let path = path::Path::new(&self.data_file_dir)
					.join(dir)
					.join(filename);

				let tx_file = match File::open(&path) {
					Ok(f) => f,
					Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
						return Err(Error::TransactionNotFound(path.display().to_string()));
					}
					Err(e) => return Err(e.into()),
				};
				read_stored_tx(tx_file, self.context_id)
			};

		// Falling back to the other extension only makes sense when the first
		// file is absent; a real read or decode failure must not be masked.
		match get_stored_tx_by_uuid_ext(uuid, "mwctx") {
			Err(Error::TransactionNotFound(_)) => get_stored_tx_by_uuid_ext(uuid, "grintx"),
			res => res,
		}
	}

	fn load_stored_tx(&self, path: &str) -> Result<Transaction, Error> {
		let tx_file = Path::new(&path).to_path_buf();
		read_stored_tx(File::open(tx_file)?, self.context_id)
	}

	fn batch<'a>(
		&'a mut self,
		secp: &Secp256k1,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error> {
		Ok(Box::new(Batch {
			store: self,
			db: RefCell::new(Some(self.db.batch_write()?)),
			keychain: Some(self.keychain(secp, keychain_mask)?),
			pending_tx_archives: RefCell::new(Vec::new()),
			db_committed: Cell::new(false),
		}))
	}

	fn batch_no_mask<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error> {
		Ok(Box::new(Batch {
			store: self,
			db: RefCell::new(Some(self.db.batch_write()?)),
			keychain: None,
			pending_tx_archives: RefCell::new(Vec::new()),
			db_committed: Cell::new(false),
		}))
	}

	fn current_child_index<'a>(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		let index = {
			let batch = self.db.batch_read()?;
			let deriv_key = to_key(DERIV_PREFIX, &mut parent_key_id.to_bytes().to_vec());
			match batch.get_ser(&deriv_key)? {
				Some(idx) => idx,
				None => 0,
			}
		};
		Ok(index)
	}

	fn next_child<'a>(&mut self, parent_key_id: Option<&Identifier>) -> Result<Identifier, Error> {
		let parent_key_id = parent_key_id.unwrap_or(&self.parent_key_id).clone();
		// Locking DB to the read - update - write workflow. Need make it atomic, so no child duplicaiton will be possible
		let batch = self.db.batch_write()?;
		let child_db_key = to_key(DERIV_PREFIX, &mut parent_key_id.to_bytes().to_vec());
		let mut deriv_idx = {
			match batch.get_ser(&child_db_key)? {
				Some(idx) => idx,
				None => 0,
			}
		};
		let mut return_path = parent_key_id.to_path()?;
		return_path.depth = return_path.depth.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"LMDBBackend::next_child, unable to allocate child path, depth overflow, parent_depth={} increment=1",
				return_path.depth
			))
		})?;
		if usize::from(return_path.depth) > return_path.path.len() {
			return Err(Error::GenericError(
				"Unable to allocate child path, maximum depth exceeded".to_string(),
			));
		}
		// The successful increment above makes depth nonzero.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "return_path.depth was successfully incremented from a valid u8"
		)]
		let child_position = usize::from(return_path.depth) - 1;
		*return_path.path.get_mut(child_position).ok_or_else(|| {
			Error::GenericError("Unable to allocate child path component".to_owned())
		})? = ChildNumber::from(deriv_idx);
		deriv_idx = deriv_idx.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"LMDBBackend::next_child, unable to allocate child path, child index overflow, derivation_index={} increment=1",
				deriv_idx
			))
		})?;
		batch.put_ser(&child_db_key, &deriv_idx)?;
		batch.commit()?;
		Ok(Identifier::from_path(&return_path)?)
	}

	fn last_confirmed_height<'a>(&mut self) -> Result<u64, Error> {
		let batch = self.db.batch_read()?;
		let height_key = u64_to_key(U64_DATA, U64_DATA_IDX_LAST_CONFIRMED_HEIGHT)?;
		match batch.get_ser(&height_key)? {
			Some(height) => Ok(height),
			None => Ok(0),
		}
	}

	fn last_scanned_blocks<'a>(&mut self) -> Result<Vec<ScannedBlockInfo>, Error> {
		let batch = self.db.batch_read()?;
		let protocol_version = self.db.protocol_version();
		let context_id = self.context_id;
		let mut blocks: Vec<ScannedBlockInfo> = batch
			.iter(&[LAST_SCANNED_BLOCK], move |k, mut v| {
				ser::deserialize_strict(&mut v, protocol_version, context_id, true)
					.map(|pos: ScannedBlockInfo| (k.to_vec(), pos))
					.map_err(mwc_store::Error::from)
			})?
			.map(|o| o.map(|(_, block)| block))
			.collect::<Result<Vec<_>, _>>()?;

		blocks.sort_by(|a, b| b.height.cmp(&a.height));

		debug!("last_scanned_blocks: {:?}", blocks);

		Ok(blocks)
	}

	/// set ethereum wallet instance
	#[cfg(feature = "swaps")]
	fn set_ethereum_wallet(
		&mut self,
		secp: &Secp256k1,
		ethereum_wallet: Option<EthereumWallet>,
		keychain_mask: Option<&SecretKey>,
	) -> Result<(), Error> {
		// Keep the representation coupled to the keychain state: a masked
		// keychain cannot accidentally be paired with a plaintext Ethereum wallet,
		// and an unrelated mask cannot make the wallet permanently inaccessible.
		let _ = self.keychain(secp, keychain_mask)?;
		self.ethereum_wallet = match ethereum_wallet {
			Some(wallet) => Some(StoredEthereumWallet::new(wallet, keychain_mask)?),
			None => None,
		};
		Ok(())
	}

	/// get ethereum wallet instance
	#[cfg(feature = "swaps")]
	fn get_ethereum_wallet(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<EthereumWallet, Error> {
		self.ethereum_wallet
			.as_ref()
			.ok_or(Error::SwapError("Ethereum Wallet Not Generated!!!".into()))?
			.expose(keychain_mask)
	}
}

/// An atomic batch in which all changes can be committed all at once or
/// discarded on error.
pub struct Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	store: &'a LMDBBackend<'a, C, K>,
	db: RefCell<Option<mwc_store::Batch<'a>>>,
	/// Keychain
	keychain: Option<K>,
	/// Stored transaction copies prepared for this batch. Their live copies are
	/// retained until the LMDB transaction commits.
	pending_tx_archives: RefCell<Vec<PreparedTxArchive>>,
	db_committed: Cell<bool>,
}

impl<'a, C, K> Drop for Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	fn drop(&mut self) {
		if self.db_committed.get() {
			return;
		}

		for prepared in self.pending_tx_archives.get_mut().drain(..) {
			if !prepared.destination_created {
				continue;
			}
			if let Err(e) = fs::remove_file(&prepared.destination)
				&& e.kind() != io::ErrorKind::NotFound
			{
				error!(
					"Unable to remove uncommitted stored transaction archive {}: {}",
					prepared.destination.display(),
					e
				);
			}
		}
	}
}

impl<'a, C, K> Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	fn iter_impl<T: Readable + 'static>(
		&self,
		prefix: u8,
	) -> Result<Box<dyn Iterator<Item = T>>, Error> {
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let protocol_version = db.protocol_version();
		let context_id = self.store.get_context_id();
		let prefix_iter = db.iter(&[prefix], move |_, mut v| {
			ser::deserialize_strict(&mut v, protocol_version, context_id, true).map_err(From::from)
		});
		let values = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(Box::new(values.into_iter()))
	}

	fn keyed_iter_impl<T: Readable>(&self, prefix: u8) -> Result<Vec<(Vec<u8>, T)>, Error> {
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let protocol_version = db.protocol_version();
		let context_id = self.store.get_context_id();
		let values = db
			.iter(&[prefix], move |key, mut value| {
				ser::deserialize_strict(&mut value, protocol_version, context_id, true)
					.map(|value| (key.to_vec(), value))
					.map_err(mwc_store::Error::from)
			})?
			.collect::<Result<Vec<_>, _>>()?;
		Ok(values)
	}

	fn migrate_output_prefix(&self, prefix: u8) -> Result<(), Error> {
		// Compatibility assumption: account/parent identifiers used for child
		// allocation already have zero unused components, including path[3].
		// DERIV_PREFIX keys contain the parent bytes, not the output key_id.
		// Under this assumption, clearing a legacy output height leaves the
		// counter key and value unchanged, so counter migration is unnecessary.
		// Historical restored wallets with a nonzero trailing height in their
		// parent/counter identifiers are outside the supported compatibility scope.
		let records = self.keyed_iter_impl::<OutputData>(prefix)?;
		let existing_keys: HashSet<Vec<u8>> = records.iter().map(|(key, _)| key.clone()).collect();
		let mut planned_targets = HashSet::new();
		let mut updates = Vec::new();

		for (old_key, mut output) in records {
			let mut changed = canonicalize_identifier_field(&mut output.key_id)?;
			changed |= canonicalize_identifier_field(&mut output.root_key_id)?;
			let new_key = output_db_key(prefix, &output)?;

			if new_key != old_key {
				if existing_keys.contains(&new_key) || !planned_targets.insert(new_key.clone()) {
					return Err(Error::Backend(format!(
						"Legacy identifier migration would overwrite an existing output, key_id={} mmr_index={:?}",
						output.key_id, output.mmr_index
					)));
				}
				changed = true;
			}

			if changed {
				updates.push((old_key, new_key, output));
			}
		}

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		for (old_key, new_key, output) in updates {
			if old_key != new_key {
				db.delete(&old_key)?;
			}
			db.put_ser(&new_key, &output)?;
		}
		Ok(())
	}

	fn migrate_private_context_identifiers(&self) -> Result<(), Error> {
		let contexts = self.keyed_iter_impl::<Context>(PRIVATE_TX_CONTEXT_PREFIX)?;
		let mut updates = Vec::new();

		for (key, mut context) in contexts {
			let mut changed = canonicalize_identifier_field(&mut context.parent_key_id)?;
			for (identifier, _, _) in &mut context.output_ids {
				changed |= canonicalize_identifier_field(identifier)?;
			}
			for (identifier, _, _) in &mut context.input_ids {
				changed |= canonicalize_identifier_field(identifier)?;
			}
			if changed {
				updates.push((key, context));
			}
		}

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		for (key, context) in updates {
			// Context secret fields are already XOR-encrypted in this raw record.
			// Write it directly so migration does not encrypt them a second time.
			db.put_ser(&key, &context)?;
		}
		Ok(())
	}

	fn rewrite_private_contexts(&self) -> Result<(), Error> {
		// Context deserialization accepts the legacy, larger late_lock_args object
		// but retains only LateLockArgs. Re-serializing every raw record therefore
		// removes transport destinations and credentials without decrypting or
		// re-encrypting the four already-masked secp fields.
		//
		// "Removes" here means from LMDB's live keyspace. Because LMDB uses
		// copy-on-write, superseded record bytes can remain in free pages until
		// those pages are reused. Deliberately do not rebuild and replace the whole
		// environment here: the cryptographic fields in legacy records were already
		// XOR-masked, current wallet deployments leave send_args.apisecret unset,
		// and the remaining transport metadata has little value after its pending
		// transaction finishes. A database replacement would make this otherwise
		// atomic schema migration substantially more complex and crash-sensitive.
		// Revisit that tradeoff if a supported deployment starts persisting a
		// non-None transport credential.
		let contexts = self.keyed_iter_impl::<Context>(PRIVATE_TX_CONTEXT_PREFIX)?;
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		for (key, context) in contexts {
			db.put_ser(&key, &context)?;
		}
		Ok(())
	}
}

#[allow(missing_docs)]
impl<'a, C, K> WalletOutputBatch<K> for Batch<'a, C, K>
where
	C: NodeClient,
	K: Keychain,
{
	fn keychain(&mut self) -> Result<&mut K, Error> {
		Ok(self
			.keychain
			.as_mut()
			.ok_or(Error::Backend("keychain is not set".into()))?)
	}

	fn save(&mut self, out: OutputData) -> Result<(), Error> {
		// An output and the allocator state which makes its key unavailable are one
		// persistence invariant. In particular, scan recovery commits outputs before
		// later reconciliation steps which may fail; leaving DERIV_PREFIX stale in
		// that case could let next_child issue the recovered key again.
		let key = match out.mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut out.key_id.to_bytes().to_vec(), i)?,
			None => to_key(OUTPUT_PREFIX, &mut out.key_id.to_bytes().to_vec()),
		};
		let deriv_key = to_key(DERIV_PREFIX, &mut out.root_key_id.to_bytes().to_vec());
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let current_child_index = db.get_ser(&deriv_key)?.unwrap_or(0_u32);
		if out.n_child >= current_child_index {
			let next_child_index = out.n_child.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Batch::save, unable to reserve saved output key, child index overflow, n_child={} increment=1",
					out.n_child
				))
			})?;
			db.put_ser(&deriv_key, &next_child_index)?;
		}
		db.put_ser(&key, &out)?;

		Ok(())
	}

	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i)?,
			None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
		};
		option_to_not_found(
			self.db
				.borrow()
				.as_ref()
				.ok_or(Error::Backend("db is not initialized".into()))?
				.get_ser(&key),
			|| format!("Key ID: {}", id),
		)
		.map_err(|e| {
			if e.store_error_is_not_found() {
				Error::OutputNotFound(e.to_string())
			} else {
				e.into()
			}
		})
	}

	fn iter(&self) -> Result<Box<dyn Iterator<Item = OutputData>>, Error> {
		self.iter_impl(OUTPUT_PREFIX)
	}

	fn archive_output(&mut self, out: &OutputData) -> Result<(), Error> {
		let mut key = match out.mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, out.key_id.to_bytes().to_vec(), i)?,
			None => to_key(OUTPUT_PREFIX, out.key_id.to_bytes().to_vec()),
		};

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;

		db.delete(&key)?;

		key[0] = OUTPUT_ARCHIVE_PREFIX;
		db.put_ser(&key, &out)?;

		Ok(())
	}

	fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error> {
		// Delete the output data.
		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_PREFIX, &mut id.to_bytes().to_vec(), *i)?,
			None => to_key(OUTPUT_PREFIX, &mut id.to_bytes().to_vec()),
		};
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		if let Err(e) = db.delete(&key) {
			// An output may reside in either the live or archive namespace.
			if !e.store_error_is_not_found() {
				return Err(e.into());
			}
		}

		let key = match mmr_index {
			Some(i) => to_key_u64(OUTPUT_ARCHIVE_PREFIX, &mut id.to_bytes().to_vec(), *i)?,
			None => to_key(OUTPUT_ARCHIVE_PREFIX, &mut id.to_bytes().to_vec()),
		};
		if let Err(e) = db.delete(&key) {
			// Missing is expected when the output was in the other namespace (live outputs/archived outputs).
			if !e.store_error_is_not_found() {
				return Err(e.into());
			}
		}

		Ok(())
	}

	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		let tx_id_key = to_key(TX_LOG_ID_PREFIX, &mut parent_key_id.to_bytes().to_vec());
		let last_tx_log_id: u32 = match self
			.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.get_ser(&tx_id_key)?
		{
			Some(t) => t,
			None => 0,
		};
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(
				&tx_id_key,
				&last_tx_log_id
					.checked_add(1)
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"Batch::next_tx_log_id, transaction log id overflow, last_tx_log_id={} increment=1",
							last_tx_log_id
						))
					})?,
			)?;
		Ok(last_tx_log_id)
	}

	fn tx_log_iter(&self) -> Result<Box<dyn Iterator<Item = TxLogEntry>>, Error> {
		self.iter_impl(TX_LOG_ENTRY_PREFIX)
	}

	fn tx_log_archive_iter(&self) -> Result<Box<dyn Iterator<Item = TxLogEntry>>, Error> {
		self.iter_impl(TX_ARCHIVE_LOG_ENTRY_PREFIX)
	}

	/// Move transaction into archive
	fn archive_transaction(&mut self, tx: &TxLogEntry) -> Result<(), Error> {
		let mut tx_log_key = to_key_u64(
			TX_LOG_ENTRY_PREFIX,
			tx.parent_key_id.to_bytes().to_vec(),
			u64::from(tx.id),
		)?;

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;

		db.delete(&tx_log_key)?;

		tx_log_key[0] = TX_ARCHIVE_LOG_ENTRY_PREFIX;
		db.put_ser(&tx_log_key, &tx)?;

		if let Some(prepared) = self.store.prepare_mwctx_archive(tx)? {
			let mut pending = self.pending_tx_archives.borrow_mut();
			if let Some(existing) = pending
				.iter_mut()
				.find(|existing| existing.source == prepared.source)
			{
				existing.destination_created |= prepared.destination_created;
			} else {
				pending.push(prepared);
			}
		}

		Ok(())
	}

	fn save_last_confirmed_height(&mut self, height: u64) -> Result<(), Error> {
		self.save_u64(U64_DATA_IDX_LAST_CONFIRMED_HEIGHT, height)
	}

	fn save_last_scanned_blocks(
		&mut self,
		first_scanned_block_height: u64,
		block_info: &Vec<ScannedBlockInfo>,
	) -> Result<(), Error> {
		if let Some((first, last)) = block_info.first().zip(block_info.last()) {
			if first.height < last.height {
				return Err(Error::Backend(format!(
					"LMDBBackend::save_last_scanned_blocks, scanned blocks are not in descending order, first_height={} last_height={}",
					first.height, last.height
				)));
			}
		}

		let br = self.db.borrow();
		let db = br
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let protocol_version = db.protocol_version();
		let context_id = self.store.get_context_id();

		// Cleaning up the head blocks...
		let mut heights: Vec<u64> = db
			.iter(&[LAST_SCANNED_BLOCK], move |k, mut v| {
				ser::deserialize_strict(&mut v, protocol_version, context_id, true)
					.map(|pos: ScannedBlockInfo| (k.to_vec(), pos))
					.map_err(mwc_store::Error::from)
			})?
			.map(|o| o.map(|(_, block)| block.height))
			.collect::<Result<Vec<_>, _>>()?;

		for h in &heights {
			if *h >= first_scanned_block_height {
				db.delete(&u64_to_key(LAST_SCANNED_BLOCK, *h)?)?;
			}
		}

		heights.retain(|h| *h < first_scanned_block_height);

		// Inserting the new data
		for bl_info in block_info {
			let scan_block_key = u64_to_key(LAST_SCANNED_BLOCK, bl_info.height)?;
			db.put_ser(&scan_block_key, bl_info)?;

			// A replay rescan can reuse a retained checkpoint; track its height once.
			// Linear search is cheap: pruning doubles the required checkpoint gap,
			// and callers sample new checkpoints similarly, keeping both lists small.
			if !heights.contains(&bl_info.height) {
				heights.push(bl_info.height);
			}
		}

		heights.sort();

		let mut step = 4;
		let mut start = heights.pop().unwrap_or(1);

		while let Some(h) = heights.pop() {
			debug_assert!(h < start);
			// heights is sorted and popped from the end, so h <= start.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the sorted heights are popped in descending order"
			)]
			let distance = start - h;
			if distance < step {
				db.delete(&u64_to_key(LAST_SCANNED_BLOCK, h)?)?;
			} else {
				start = h;
				step = step.checked_mul(2).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Batch::save_last_scanned_blocks, stored scan block step overflow, step={} multiplier=2",
						step
					))
				})?;
			}
		}

		Ok(())
	}

	/// Save safe flag into DB
	fn save_flag(&mut self, flag: u64) -> Result<(), Error> {
		let key = u64_to_key(FLAGS, flag)?;

		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&key, &flag)?;

		Ok(())
	}

	/// Load and optionally delete the flag from DB
	fn load_flag(&mut self, flag: u64, delete: bool) -> Result<bool, Error> {
		let br = self.db.borrow();
		let db = br
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;

		let key = u64_to_key(FLAGS, flag)?;
		let index: Option<u64> = db.get_ser(&key)?;

		let has_flag = index.is_some();

		if has_flag & delete {
			db.delete(&key)?;
		}
		Ok(has_flag)
	}

	fn migrate_legacy_height_identifiers(&mut self) -> Result<(), Error> {
		self.migrate_output_prefix(OUTPUT_PREFIX)?;
		self.migrate_output_prefix(OUTPUT_ARCHIVE_PREFIX)?;
		self.migrate_private_context_identifiers()?;
		Ok(())
	}

	fn migrate_private_context_xor_keys(&mut self, secp: &Secp256k1) -> Result<(), Error> {
		let contexts = self.keyed_iter_impl::<Context>(PRIVATE_TX_CONTEXT_PREFIX)?;
		if contexts.is_empty() {
			return Ok(());
		}

		let keychain = self
			.keychain
			.as_ref()
			.ok_or(Error::Backend("keychain is not set".into()))?;
		let mut updates = Vec::with_capacity(contexts.len());

		for (key, mut context) in contexts {
			let (slate_id, participant_id) =
				private_context_key_parts(&key, PRIVATE_TX_CONTEXT_PREFIX)?;
			let context_participant_id = u64::try_from(context.participant_id).map_err(|e| {
				Error::DataOverflow(format!(
					"Batch::migrate_private_context_xor_keys, stored participant id does not fit u64, participant_id={} error={}",
					context.participant_id, e
				))
			})?;
			if context_participant_id != participant_id {
				return Err(Error::Backend(format!(
					"Private context participant id does not match its database key, context_participant_id={} key_participant_id={}",
					context_participant_id, participant_id
				)));
			}

			// Derive both masks before exposing plaintext in memory so every
			// fallible KDF operation completes first. Applying the legacy mask
			// decrypts the fields; applying the current mask immediately re-encrypts
			// them for the participant-bound format.
			let legacy_xor_keys = legacy_private_ctx_xor_keys(secp, keychain, slate_id)?;
			let current_xor_keys = private_ctx_xor_keys(secp, keychain, slate_id, participant_id)?;
			xor_private_context_secret_fields(&mut context, &legacy_xor_keys);
			xor_private_context_secret_fields(&mut context, &current_xor_keys);
			updates.push((key, context));
		}

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		for (key, context) in updates {
			db.put_ser(&key, &context)?;
		}
		Ok(())
	}

	fn sanitize_private_contexts(&mut self) -> Result<(), Error> {
		self.rewrite_private_contexts()
	}

	/// Save the last used good node index
	fn save_u64(&mut self, index: u64, value: u64) -> Result<(), Error> {
		let node_index_key = u64_to_key(U64_DATA, index)?;
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&node_index_key, &value)?;
		Ok(())
	}

	/// Save the last used good node index
	fn load_u64(&mut self, index: u64, default: u64) -> Result<u64, Error> {
		let node_index_key = u64_to_key(U64_DATA, index)?;

		let index: Option<u64> = self
			.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.get_ser(&node_index_key)?;
		let last_working_node_index = match index {
			Some(ind) => ind, //the normal index started from 1. 0 is error
			None => default,
		};
		Ok(last_working_node_index)
	}

	#[cfg(feature = "swaps")]
	fn save_marketplace_signing_address_index(
		&mut self,
		binding_key: &[u8; 32],
		address_index: u32,
	) -> Result<(), Error> {
		let key = to_key(MARKETPLACE_SIGNING_INDEX_PREFIX, binding_key);
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&key, &address_index)?;
		Ok(())
	}

	#[cfg(feature = "swaps")]
	fn load_marketplace_signing_address_index(
		&mut self,
		binding_key: &[u8; 32],
	) -> Result<Option<u32>, Error> {
		let key = to_key(MARKETPLACE_SIGNING_INDEX_PREFIX, binding_key);
		Ok(self
			.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.get_ser(&key)?)
	}

	fn save_child_index(&mut self, parent_id: &Identifier, child_n: u32) -> Result<(), Error> {
		let deriv_key = to_key(DERIV_PREFIX, &mut parent_id.to_bytes().to_vec());
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&deriv_key, &child_n)?;
		Ok(())
	}

	fn save_tx_log_entry(
		&mut self,
		tx_in: TxLogEntry,
		parent_id: &Identifier,
	) -> Result<(), Error> {
		let tx_log_key = to_key_u64(
			TX_LOG_ENTRY_PREFIX,
			&mut parent_id.to_bytes().to_vec(),
			u64::from(tx_in.id),
		)?;
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&tx_log_key, &tx_in)?;
		Ok(())
	}

	fn delete_tx_log_entry(&mut self, tx_id: u32, parent_id: &Identifier) -> Result<(), Error> {
		let active_tx_log_key = to_key_u64(
			TX_LOG_ENTRY_PREFIX,
			&mut parent_id.to_bytes().to_vec(),
			u64::from(tx_id),
		)?;
		let archived_tx_log_key = to_key_u64(
			TX_ARCHIVE_LOG_ENTRY_PREFIX,
			&mut parent_id.to_bytes().to_vec(),
			u64::from(tx_id),
		)?;

		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;

		// A transaction can reside in either namespace, so absence from one is
		// expected. Preserve the original strict behavior when it is absent from
		// both, but never hide a substantive database error.
		let active_not_found = match db.delete(&active_tx_log_key) {
			Ok(()) => None,
			Err(e) if e.store_error_is_not_found() => Some(e),
			Err(e) => return Err(e.into()),
		};

		match db.delete(&archived_tx_log_key) {
			Ok(()) => Ok(()),
			Err(e) if !e.store_error_is_not_found() => Err(e.into()),
			Err(_) => match active_not_found {
				Some(e) => Err(e.into()),
				None => Ok(()),
			},
		}
	}

	fn rename_acct_path(
		&mut self,
		accounts: Vec<AcctPathMapping>,
		old_name: &str,
		new_name: &str,
	) -> Result<(), Error> {
		for acc in accounts {
			if acc.label == old_name {
				let mut nacc = acc.clone();
				let old_key = to_key(
					ACCOUNT_PATH_MAPPING_PREFIX,
					&mut acc.label.as_bytes().to_vec(),
				);
				self.db
					.borrow()
					.as_ref()
					.ok_or(Error::Backend("db is not initialized".into()))?
					.delete(&old_key)?;
				nacc.label = new_name.to_string();
				let acct_key = to_key(
					ACCOUNT_PATH_MAPPING_PREFIX,
					&mut nacc.label.as_bytes().to_vec(),
				);
				self.db
					.borrow()
					.as_ref()
					.ok_or(Error::Backend("db is not initialized".into()))?
					.put_ser(&acct_key, &nacc)?;

				break;
			}
		}
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!("rename acct from '{}' to '{}'", old_name, new_name);
		}
		Ok(())
	}

	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error> {
		let acct_key = to_key(
			ACCOUNT_PATH_MAPPING_PREFIX,
			&mut mapping.label.as_bytes().to_vec(),
		);
		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&acct_key, &mapping)?;
		Ok(())
	}

	fn acct_path_iter(&self) -> Result<Box<dyn Iterator<Item = AcctPathMapping>>, Error> {
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let protocol_version = db.protocol_version();
		let context_id = self.store.get_context_id();

		let prefix_iter = db.iter(&[ACCOUNT_PATH_MAPPING_PREFIX], move |_, mut v| {
			ser::deserialize_strict(&mut v, protocol_version, context_id, true).map_err(From::from)
		});
		let values = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(Box::new(values.into_iter()))
	}

	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error> {
		out.lock();
		self.save(out.clone())
	}

	fn save_private_context(
		&mut self,
		secp: &Secp256k1,
		slate_id: &[u8],
		participant_id: usize,
		ctx: &Context,
	) -> Result<(), Error> {
		let participant_id = u64::try_from(participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"Batch::save_private_context, participant id does not fit u64, participant_id={} error={}",
				participant_id, e
			))
		})?;
		let ctx_key = to_key_u64(PRIVATE_TX_CONTEXT_PREFIX, slate_id, participant_id)?;
		let xor_keys = private_ctx_xor_keys(secp, self.keychain()?, slate_id, participant_id)?;

		let mut s_ctx = ctx.clone();
		xor_private_context_secret_fields(&mut s_ctx, &xor_keys);

		self.db
			.borrow()
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?
			.put_ser(&ctx_key, &s_ctx)?;
		Ok(())
	}

	fn delete_private_context(
		&mut self,
		slate_id: &[u8],
		participant_id: usize,
	) -> Result<(), Error> {
		let participant_id = u64::try_from(participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"Batch::delete_private_context, participant id does not fit u64, participant_id={} error={}",
				participant_id, e
			))
		})?;
		let ctx_key = to_key_u64(PRIVATE_TX_CONTEXT_PREFIX, slate_id, participant_id)?;
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		match db.delete(&ctx_key) {
			Ok(()) => Ok(()),
			Err(e) if e.store_error_is_not_found() => {
				Err(Error::PrivateContextNotFound(format!(
					"slate_id={:x?}, participant_id={}, source={}",
					slate_id, participant_id, e
				)))
			}
			Err(e) => Err(e.into()),
		}
	}

	fn store_tx(&mut self, uuid: &str, tx: &Transaction) -> Result<(), Error> {
		self.store.store_tx(uuid, tx)
	}

	fn private_context_iter(&self) -> Result<Box<dyn Iterator<Item = (Vec<u8>, Context)>>, Error> {
		let db = self.db.borrow();
		let db = db
			.as_ref()
			.ok_or(Error::Backend("db is not initialized".into()))?;
		let protocol_version = db.protocol_version();
		let context_id = self.store.get_context_id();

		let prefix_iter = db.iter(&[PRIVATE_TX_CONTEXT_PREFIX], move |ctx_key, mut v| {
			let prefix_len: usize = 2;
			let suffix_len: usize = 8;
			if ctx_key.len() <= suffix_len + prefix_len {
				return Err(mwc_store::Error::OtherErr(format!(
					"Batch::private_context_iter, private context key is shorter than its suffix, key_len={} suffix_len={}",
					ctx_key.len(), suffix_len
				)));
			}
			// The preceding malformed-key check proves the suffix subtraction is safe.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "ctx_key.len() is checked to be at least suffix_len"
			)]
			let slate_id_end = ctx_key.len() - suffix_len;
			let slate_id = ctx_key
				.get(prefix_len..slate_id_end)
				.ok_or_else(|| {
					mwc_store::Error::OtherErr(
						"Private context key has invalid boundaries".to_owned(),
					)
				})?
				.to_vec();

			let context = ser::deserialize_strict(&mut v, protocol_version, context_id, true)?;
			Ok((slate_id, context))
		});
		let values = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(Box::new(values.into_iter()))
	}

	fn commit(&self) -> Result<(), Error> {
		let db = self.db.replace(None);
		db.ok_or(Error::Backend("db is not initialized".into()))?
			.commit()?;
		self.db_committed.set(true);

		let pending = self.pending_tx_archives.replace(Vec::new());
		let mut cleanup_error = None;
		for prepared in pending {
			if let Err(e) = fs::remove_file(&prepared.source)
				&& e.kind() != io::ErrorKind::NotFound
				&& cleanup_error.is_none()
			{
				cleanup_error = Some((prepared.source, e));
			}
		}

		if let Some((source, e)) = cleanup_error {
			return Err(Error::IO(format!(
				"Wallet database commit succeeded, but unable to remove active stored transaction {}: {}",
				source.display(),
				e
			)));
		}
		Ok(())
	}
}

#[cfg(all(test, feature = "swaps", feature = "test-support"))]
#[path = "swap_recovery_tests.rs"]
mod swap_recovery_tests;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::node_clients::HTTPNodeClient;
	use mwc_wallet_libwallet::types::FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT;
	use mwc_wallet_libwallet::{OutputStatus, StoredTxLocator, TxLogEntryType};
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::secp::ContextFlag;
	use mwc_wallet_util::mwc_crates::uuid::Uuid;
	use std::path::{Path, PathBuf};

	pub(super) struct TestWalletDir(PathBuf);

	impl TestWalletDir {
		pub(super) fn new() -> Result<Self, Error> {
			let path =
				std::env::temp_dir().join(format!("mwc-wallet-id-migration-{}", Uuid::new_v4()));
			fs::create_dir_all(&path)?;
			Ok(Self(path))
		}

		fn path(&self) -> &Path {
			&self.0
		}
	}

	impl Drop for TestWalletDir {
		fn drop(&mut self) {
			let _ = fs::remove_dir_all(&self.0);
		}
	}

	#[cfg(unix)]
	#[test]
	fn exists_propagates_filesystem_errors() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let non_directory = directory.path().join("not-a-directory");
		fs::write(&non_directory, b"")?;
		let non_directory = non_directory
			.to_str()
			.ok_or_else(|| Error::GenericError("Test path is not valid UTF-8".to_owned()))?;

		assert!(
			LMDBBackend::<HTTPNodeClient, ExtKeychain>::exists(non_directory).is_err(),
			"filesystem errors must not be reported as a missing database"
		);
		Ok(())
	}

	#[cfg(unix)]
	#[test]
	fn archive_mwctx_data_propagates_filesystem_errors() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let wallet = test_wallet(&directory)?;
		let saved_txs_path = directory.path().join(TX_SAVE_DIR);
		fs::remove_dir(&saved_txs_path)?;
		fs::write(&saved_txs_path, b"")?;

		let entry = build_stored_tx_entry("transaction.mwctx".to_owned());
		assert!(
			wallet.archive_mwctx_data(&entry).is_err(),
			"filesystem errors must not be reported as a missing stored transaction"
		);
		Ok(())
	}

	fn with_legacy_component(
		identifier: &Identifier,
		legacy_component: u32,
	) -> Result<Identifier, Error> {
		let mut bytes = identifier.to_bytes();
		bytes[13..17].copy_from_slice(&legacy_component.to_be_bytes());
		Ok(Identifier::from_bytes(&bytes)?)
	}

	pub(super) fn test_wallet(
		directory: &TestWalletDir,
	) -> Result<LMDBBackend<'static, HTTPNodeClient, ExtKeychain>, Error> {
		let context_id = 0;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let client = HTTPNodeClient::new(context_id, vec!["http://127.0.0.1:0".to_owned()], None)
			.map_err(|e| {
				Error::GenericError(format!("Unable to create test node client, {}", e))
			})?;
		LMDBBackend::new(
			context_id,
			directory.path().to_str().ok_or_else(|| {
				Error::GenericError("Test wallet path is not valid UTF-8".to_owned())
			})?,
			client,
		)
	}

	fn build_stored_tx_entry(filename: String) -> TxLogEntry {
		let mut entry = TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxSent, 1);
		entry.stored_tx = Some(filename);
		entry
	}

	fn store_transaction_for_archive(
		wallet: &mut LMDBBackend<'static, HTTPNodeClient, ExtKeychain>,
		id: u32,
	) -> Result<(TxLogEntry, String), Error> {
		let tx_uuid = Uuid::new_v4();
		let tx_uuid_string = tx_uuid.to_string();
		wallet.store_tx(&tx_uuid_string, &Transaction::empty())?;

		let parent_key_id = wallet.parent_key_id();
		let mut entry = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, id);
		entry.tx_slate_id = Some(tx_uuid);
		entry.stored_tx = Some(format!("{}.mwctx", tx_uuid));
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.save_tx_log_entry(entry.clone(), &parent_key_id)?;
			batch.commit()?;
		}

		Ok((entry, tx_uuid_string))
	}

	#[test]
	fn failed_new_archive_installation_removes_published_destination() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let archive_path = directory.path().join("published-before-error.mwctx");

		let result = install_new_tx_archive_with_cleanup(&archive_path, || {
			fs::write(&archive_path, b"published archive")?;
			Err(io::Error::new(
				io::ErrorKind::Other,
				"injected directory sync failure",
			))
		});

		match result {
			Err(Error::IO(message)) => {
				assert!(message.contains("injected directory sync failure"));
			}
			other => panic!("expected archive installation error, got {:?}", other),
		}
		assert!(!archive_path.try_exists()?);
		Ok(())
	}

	#[test]
	fn aborted_archive_batch_retains_live_transaction_file() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let (entry, tx_uuid) = store_transaction_for_archive(&mut wallet, 11)?;
		let filename = format!("{}.mwctx", tx_uuid);
		let active_path = directory.path().join(TX_SAVE_DIR).join(&filename);
		let archive_path = directory.path().join(TX_ARCHIVE_DIR).join(&filename);

		{
			let mut batch = wallet.batch_no_mask()?;
			batch.archive_transaction(&entry)?;
			assert!(active_path.try_exists()?);
			assert!(archive_path.try_exists()?);
			// Dropping this batch simulates any later error before commit.
		}

		assert!(active_path.try_exists()?);
		assert!(!archive_path.try_exists()?);
		assert_eq!(wallet.tx_log_iter()?.count(), 1);
		assert_eq!(wallet.tx_log_archive_iter()?.count(), 0);
		Ok(())
	}

	#[test]
	fn committed_archive_batch_removes_live_copy_after_db_commit() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let (entry, tx_uuid) = store_transaction_for_archive(&mut wallet, 12)?;
		let filename = format!("{}.mwctx", tx_uuid);
		let active_path = directory.path().join(TX_SAVE_DIR).join(&filename);
		let archive_path = directory.path().join(TX_ARCHIVE_DIR).join(&filename);

		{
			let mut batch = wallet.batch_no_mask()?;
			batch.archive_transaction(&entry)?;
			assert!(active_path.try_exists()?);
			assert!(archive_path.try_exists()?);
			batch.commit()?;
		}

		assert!(!active_path.try_exists()?);
		assert!(archive_path.try_exists()?);
		assert_eq!(wallet.tx_log_iter()?.count(), 0);
		assert_eq!(wallet.tx_log_archive_iter()?.count(), 1);
		let loaded = wallet.get_stored_tx_by_uuid(&tx_uuid, true)?;
		assert!(loaded.eq_by_hash(0, &Transaction::empty())?);
		Ok(())
	}

	#[test]
	fn archive_batch_rejects_conflicting_archive_file() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let (entry, tx_uuid) = store_transaction_for_archive(&mut wallet, 13)?;
		let filename = format!("{}.mwctx", tx_uuid);
		let active_path = directory.path().join(TX_SAVE_DIR).join(&filename);
		let archive_path = directory.path().join(TX_ARCHIVE_DIR).join(&filename);
		fs::write(&archive_path, b"different stored transaction")?;

		{
			let mut batch = wallet.batch_no_mask()?;
			assert!(matches!(
				batch.archive_transaction(&entry),
				Err(Error::StoredTransactionError(_))
			));
		}

		assert!(active_path.try_exists()?);
		assert_eq!(fs::read(&archive_path)?, b"different stored transaction");
		assert_eq!(wallet.tx_log_iter()?.count(), 1);
		assert_eq!(wallet.tx_log_archive_iter()?.count(), 0);
		Ok(())
	}

	#[test]
	fn delete_tx_log_entry_checks_live_and_archive_namespaces() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let parent_key_id = wallet.parent_key_id();

		let live_entry = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 7);
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.save_tx_log_entry(live_entry, &parent_key_id)?;
			batch.commit()?;
		}
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.delete_tx_log_entry(7, &parent_key_id)?;
			batch.commit()?;
		}
		assert!(wallet.tx_log_iter()?.all(|entry| entry.id != 7));

		let archived_entry =
			TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 8);
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.save_tx_log_entry(archived_entry.clone(), &parent_key_id)?;
			batch.archive_transaction(&archived_entry)?;
			batch.commit()?;
		}
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.delete_tx_log_entry(8, &parent_key_id)?;
			batch.commit()?;
		}
		assert!(wallet
			.tx_log_archive_iter()?
			.all(|entry| entry.id != 8));

		let mut batch = wallet.batch_no_mask()?;
		assert!(batch.delete_tx_log_entry(9, &parent_key_id).is_err());
		Ok(())
	}

	#[test]
	fn close_removes_all_stored_credentials() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[11u8; 32], false)?;
		wallet.set_keychain(
			&secp,
			Box::new(keychain),
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;
		assert!(wallet.keychain.is_some());
		assert!(wallet.master_checksum.is_some());

		#[cfg(feature = "swaps")]
		{
			let mut ethereum_wallet = EthereumWallet::default();
			ethereum_wallet.password = Some("wallet password".to_owned());
			ethereum_wallet.mnemonic = Some("wallet mnemonic".to_owned());
			ethereum_wallet.private_key = Some("wallet private key".to_owned());
			wallet.set_ethereum_wallet(&secp, Some(ethereum_wallet), None)?;
			assert!(wallet.get_ethereum_wallet(None).is_ok());
		}

		wallet.close()?;

		assert!(wallet.keychain.is_none());
		assert!(wallet.master_checksum.is_none());
		#[cfg(feature = "swaps")]
		assert!(wallet.get_ethereum_wallet(None).is_err());
		Ok(())
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn masked_ethereum_wallet_requires_matching_keychain_mask() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[21u8; 32], false)?;
		let mask = wallet
			.set_keychain(
				&secp,
				Box::new(keychain),
				true,
				#[cfg(feature = "test-support")]
				false,
			)?
			.ok_or_else(|| Error::GenericError("Test keychain mask is missing".to_owned()))?;

		let mut ethereum_wallet = EthereumWallet::default();
		ethereum_wallet.mnemonic = Some("secret recovery phrase".to_owned());
		ethereum_wallet.private_key = Some("secret ethereum private key".to_owned());
		// Exercise serialized data larger than the old 16 KiB reservation.
		let password = "long test password\n\"é".repeat(1024);
		ethereum_wallet.password = Some(password.clone());
		assert!(
			wallet
				.set_ethereum_wallet(&secp, Some(ethereum_wallet.clone()), None)
				.is_err()
		);
		wallet.set_ethereum_wallet(&secp, Some(ethereum_wallet), Some(&mask))?;

		let stored = wallet
			.ethereum_wallet
			.as_ref()
			.ok_or_else(|| Error::GenericError("Test Ethereum wallet is missing".to_owned()))?;
		let StoredEthereumWallet::Masked { ciphertext, .. } = stored else {
			return Err(Error::GenericError(
				"Masked keychain retained a plaintext Ethereum wallet".to_owned(),
			));
		};
		assert!(!ciphertext
			.windows(b"secret recovery phrase".len())
			.any(|window| window == b"secret recovery phrase"));
		assert!(matches!(
			wallet.get_ethereum_wallet(None),
			Err(Error::InvalidKeychainMask)
		));

		let wrong_mask = SecretKey::from_slice(&secp, &[3u8; SECRET_KEY_SIZE])?;
		assert!(matches!(
			wallet.get_ethereum_wallet(Some(&wrong_mask)),
			Err(Error::InvalidKeychainMask)
		));

		let restored = wallet.get_ethereum_wallet(Some(&mask))?;
		assert_eq!(restored.password.as_deref(), Some(password.as_str()));
		assert_eq!(
			restored.mnemonic.as_deref(),
			Some("secret recovery phrase")
		);
		assert_eq!(
			restored.private_key.as_deref(),
			Some("secret ethereum private key")
		);
		Ok(())
	}

	#[test]
	fn set_keychain_retains_original_box_allocation() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = Box::new(ExtKeychain::from_seed(&secp, &[12u8; 32], false)?);
		let original_allocation = std::ptr::from_ref(keychain.as_ref());

		wallet.set_keychain(
			&secp,
			keychain,
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;

		let stored_allocation = std::ptr::from_ref(
			wallet
				.keychain
				.as_deref()
				.ok_or(Error::KeychainDoesntExist)?,
		);
		assert_eq!(stored_allocation, original_allocation);
		Ok(())
	}

	#[cfg(feature = "swaps")]
	#[test]
	fn marketplace_signing_address_index_is_persisted_in_wallet_db() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let first_binding = [7u8; 32];
		let second_binding = [8u8; 32];

		{
			let mut batch = wallet.batch_no_mask()?;
			assert_eq!(
				batch.load_marketplace_signing_address_index(&first_binding)?,
				None
			);
			batch.save_marketplace_signing_address_index(&first_binding, 11)?;
			batch.save_marketplace_signing_address_index(&second_binding, 12)?;
			batch.commit()?;
		}

		let mut batch = wallet.batch_no_mask()?;
		assert_eq!(
			batch.load_marketplace_signing_address_index(&first_binding)?,
			Some(11)
		);
		assert_eq!(
			batch.load_marketplace_signing_address_index(&second_binding)?,
			Some(12)
		);
		Ok(())
	}

	#[test]
	fn confirmed_height_is_wallet_global_and_ignores_legacy_account_records() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let default_parent = wallet.parent_key_id();

		// The old b'c'/account record must not seed the new global watermark.
		let legacy_key = to_key(b'c', default_parent.to_bytes().to_vec());
		let legacy_batch = wallet.db.batch_write()?;
		legacy_batch.put_ser(&legacy_key, &999_u64)?;
		legacy_batch.commit()?;
		assert_eq!(wallet.last_confirmed_height()?, 0);

		{
			let mut batch = wallet.batch_no_mask()?;
			batch.save_last_confirmed_height(42)?;
			batch.commit()?;
		}
		assert_eq!(wallet.last_confirmed_height()?, 42);

		let other_parent = ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?;
		wallet.set_parent_key_id(other_parent);
		assert_eq!(
			wallet.last_confirmed_height()?,
			42,
			"changing the active account must not change the wallet watermark"
		);
		Ok(())
	}

	#[test]
	fn saved_output_key_is_not_reissued_after_a_later_batch_failure() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let parent_key_id = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let recovered_key_id = ExtKeychain::derive_key_id(3, 0, 0, 0, 0)?;
		let recovered_output = OutputData {
			root_key_id: parent_key_id.clone(),
			key_id: recovered_key_id.clone(),
			n_child: 0,
			commit: None,
			mmr_index: Some(1),
			value: 42,
			status: OutputStatus::Unspent,
			height: 1,
			lock_height: 1,
			is_coinbase: false,
			tx_log_entry: Some(1),
		};

		{
			let mut restore_batch = wallet.batch_no_mask()?;
			restore_batch.save(recovered_output.clone())?;
			restore_batch.commit()?;
		}

		{
			let mut later_scan_batch = wallet.batch_no_mask()?;
			later_scan_batch.save_last_confirmed_height(1)?;
			// Dropping this transaction models a later scan step returning an error.
		}

		assert_eq!(
			wallet.get(&recovered_key_id, &recovered_output.mmr_index)?,
			recovered_output
		);
		assert_eq!(
			wallet.last_confirmed_height()?,
			0,
			"the simulated later scan transaction must be rolled back"
		);
		assert_eq!(wallet.current_child_index(&parent_key_id)?, 1);

		let newly_allocated = wallet.next_child(Some(&parent_key_id))?;
		assert_eq!(
			newly_allocated,
			ExtKeychain::derive_key_id(3, 0, 0, 1, 0)?
		);
		assert_ne!(newly_allocated, recovered_key_id);
		Ok(())
	}

	#[test]
	fn s2c_coinbase_reuses_only_pending_keys_and_keeps_ordinary_recovery() -> Result<(), Error> {
		use mwc_wallet_libwallet::{internal::updater, BlockFees, CbData};
		use mwc_wallet_util::mwc_core::{
			core::hash::Hash,
			libtx::{coinbase_binding::verify_coinbase_binding_digest, proof},
		};
		use mwc_wallet_util::mwc_crates::serde_json;
		use mwc_wallet_util::mwc_node_workflow::context::{allocate_new_context, release_context};
		let context = allocate_new_context(global::ChainTypes::AutomatedTesting, None, None)
			.map_err(|e| Error::GenericError(e.to_string()))?;
		let result = (|| {
			let directory = TestWalletDir::new()?;
			let client = HTTPNodeClient::new(context, vec!["http://127.0.0.1:0".into()], None)
				.map_err(|e| Error::GenericError(e.to_string()))?;
			let mut wallet = LMDBBackend::new(context, directory.path().to_str().unwrap(), client)?;
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			wallet.set_keychain(
				&secp,
				Box::new(ExtKeychain::from_seed(&secp, &[81u8; 32], false)?),
				false,
				#[cfg(feature = "test-support")]
				false,
			)?;
			let parent = wallet.parent_key_id();
			let digest = Hash::from_vec(&[1u8; 32]);
			let mut request = BlockFees {
				fees: 13,
				height: 4,
				key_id: None,
				binding_digest: digest.to_hex(),
			};
			assert_eq!(wallet.current_child_index(&parent)?, 0);
			assert!(wallet.iter()?.next().is_none());
			// Hex validation belongs to the RPC handler and must finish before
			// reserving a child key or saving a pending Coinbase output.
			for invalid in [
				String::new(),
				"00".repeat(31),
				"00".repeat(33),
				"g".repeat(64),
				"a".repeat(63),
			] {
				let mut bad_request = request.clone();
				bad_request.binding_digest = invalid;
				let error = updater::build_coinbase(&mut wallet, &mut secp, None, &bad_request)
					.unwrap_err();
				assert!(matches!(
					error,
					Error::GenericError(message) if message.contains("Invalid Coinbase binding digest")
				));
				assert_eq!(wallet.current_child_index(&parent)?, 0);
				assert!(wallet.iter()?.next().is_none());
			}
			let first = updater::build_coinbase(&mut wallet, &mut secp, None, &request)?;
			let key = first.key_id.clone().unwrap();
			assert_eq!(wallet.get(&key, &None)?.root_key_id, parent);
			assert_eq!(wallet.current_child_index(&parent)?, 1);
			first.kernel.verify(context, &secp)?;
			verify_coinbase_binding_digest(
				context,
				&secp,
				&first.kernel,
				&first.coinbase_opening,
				digest,
			)?;
			// Recovery needs only the wallet seed and ordinary output data.
			let restored = ExtKeychain::from_seed(&secp, &[81u8; 32], false)?;
			let builder = proof::ProofBuilder::new(&secp, &restored)?;
			let recovered = proof::rewind(
				&mut secp,
				&builder,
				first.output.commitment(),
				None,
				first.output.proof,
			)?
			.unwrap();
			assert_eq!(recovered.1, key);
			assert_eq!(recovered.0, wallet.get(&key, &None)?.value);
			let encoded = serde_json::to_value(&first).unwrap();
			assert_eq!(encoded["coinbase_opening"].as_str().unwrap().len(), 66);
			let decoded: CbData = serde_json::from_value(encoded.clone()).unwrap();
			assert_eq!(decoded.coinbase_opening, first.coinbase_opening);
			for invalid in [
				serde_json::Value::Null,
				serde_json::json!("00".repeat(33)),
				serde_json::json!("02"),
				serde_json::json!("gg".repeat(33)),
			] {
				let mut bad = encoded.clone();
				bad["coinbase_opening"] = invalid;
				assert!(serde_json::from_value::<CbData>(bad).is_err());
			}
			let mut missing = encoded;
			missing.as_object_mut().unwrap().remove("coinbase_opening");
			assert!(serde_json::from_value::<CbData>(missing).is_err());
			request.key_id = Some(key.clone());
			request.binding_digest = Hash::from_vec(&[2u8; 32]).to_hex();
			let second = updater::build_coinbase(&mut wallet, &mut secp, None, &request)?;
			assert_eq!(first.key_id, second.key_id);
			assert_eq!(first.output, second.output);
			assert_ne!(first.kernel.excess_sig, second.kernel.excess_sig);
			assert_ne!(first.coinbase_opening, second.coinbase_opening);
			assert_eq!(wallet.current_child_index(&parent)?, 1);
			let repeated = updater::build_coinbase(&mut wallet, &mut secp, None, &request)?;
			assert_eq!(repeated.kernel.excess, second.kernel.excess);
			assert_eq!(repeated.kernel.excess_sig, second.kernel.excess_sig);
			assert_eq!(repeated.coinbase_opening, second.coinbase_opening);
			// A key associated with another transaction cannot be overwritten.
			let mut occupied = wallet.get(&key, &None)?;
			occupied.tx_log_entry = Some(7);
			{
				let mut batch = wallet.batch(&secp, None)?;
				batch.save(occupied.clone())?;
				batch.commit()?;
			}
			let replacement = updater::build_coinbase(&mut wallet, &mut secp, None, &request)?;
			assert_ne!(replacement.key_id, Some(key.clone()));
			assert_eq!(wallet.get(&key, &None)?, occupied);
			assert_eq!(wallet.current_child_index(&parent)?, 2);
			// Upgraded nodes already request and verify S2C before activation.
			request.height = 3;
			request.key_id = None;
			let before_activation =
				updater::build_coinbase(&mut wallet, &mut secp, None, &request)?;
			before_activation.kernel.verify(context, &secp)?;
			verify_coinbase_binding_digest(
				context,
				&secp,
				&before_activation.kernel,
				&before_activation.coinbase_opening,
				Hash::from_hex(&request.binding_digest).unwrap(),
			)?;
			assert_eq!(wallet.current_child_index(&parent)?, 3);
			Ok(())
		})();
		release_context(context).map_err(|e| Error::GenericError(e.to_string()))?;
		result
	}

	#[test]
	fn stored_tx_falls_back_to_archive_only_when_active_file_is_missing() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let wallet = test_wallet(&directory)?;
		let tx_id = Uuid::new_v4().to_string();
		let filename = format!("{}.mwctx", tx_id);
		let tx = Transaction::empty();
		wallet.store_tx(&tx_id, &tx)?;

		let active_path = directory.path().join(TX_SAVE_DIR).join(&filename);
		let archive_path = directory.path().join(TX_ARCHIVE_DIR).join(&filename);
		fs::rename(&active_path, &archive_path)?;

		let loaded = wallet
			.get_stored_tx(&build_stored_tx_entry(filename))?
			.ok_or_else(|| {
				Error::StoredTransactionError("transaction was not loaded".to_owned())
			})?;
		assert!(loaded.eq_by_hash(0, &tx)?);
		Ok(())
	}

	#[test]
	fn stored_tx_rejects_path_components_outside_a_single_filename() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let wallet = test_wallet(&directory)?;
		let absolute = directory.path().join("outside.mwctx");
		let invalid_names = [
			absolute.to_string_lossy().into_owned(),
			"../outside.mwctx".to_string(),
			"nested/transaction.mwctx".to_string(),
			"./transaction.mwctx".to_string(),
			".".to_string(),
			String::new(),
		];

		for filename in invalid_names {
			assert!(matches!(
				wallet.get_stored_tx(&build_stored_tx_entry(filename)),
				Err(Error::StoredTransactionError(_))
			));
		}
		Ok(())
	}

	#[test]
	fn stored_tx_by_uuid_rejects_path_components_outside_transaction_directory() -> Result<(), Error>
	{
		let directory = TestWalletDir::new()?;
		let wallet = test_wallet(&directory)?;
		let absolute = directory.path().join("outside");
		let invalid_uuids = [
			absolute.to_string_lossy().into_owned(),
			"../outside".to_string(),
			"nested/transaction".to_string(),
			"./transaction".to_string(),
		];

		for uuid in invalid_uuids {
			for archived in [false, true] {
				assert!(matches!(
					wallet.get_stored_tx_by_uuid(&uuid, archived),
					Err(Error::StoredTransactionError(_))
				));
			}
		}
		Ok(())
	}

	#[test]
	fn stored_tx_locator_is_resolved_from_wallet_state() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let slate_id = Uuid::new_v4();
		let tx = Transaction::empty();
		wallet.store_tx(&slate_id.to_string(), &tx)?;

		let parent_key_id = wallet.parent_key_id();
		let mut entry = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxSent, 7);
		entry.tx_slate_id = Some(slate_id);
		entry.stored_tx = Some(format!("{}.mwctx", slate_id));
		{
			let mut batch = wallet.batch_no_mask()?;
			batch.save_tx_log_entry(entry, &parent_key_id)?;
			batch.commit()?;
		}

		let loaded = mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
			&mut wallet,
			None,
			&StoredTxLocator {
				id: Some(7),
				tx_slate_id: Some(slate_id),
				stored_tx: Some(format!("{}.mwctx", slate_id)),
			},
		)?
		.ok_or_else(|| Error::StoredTransactionError("transaction was not loaded".to_string()))?;
		assert!(loaded.eq_by_hash(0, &tx)?);

		let loaded = mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
			&mut wallet,
			None,
			&StoredTxLocator {
				id: Some(7),
				..Default::default()
			},
		)?
		.ok_or_else(|| Error::StoredTransactionError("transaction was not loaded".to_string()))?;
		assert!(loaded.eq_by_hash(0, &tx)?);

		let loaded = mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
			&mut wallet,
			None,
			&StoredTxLocator {
				tx_slate_id: Some(slate_id),
				..Default::default()
			},
		)?
		.ok_or_else(|| Error::StoredTransactionError("transaction was not loaded".to_string()))?;
		assert!(loaded.eq_by_hash(0, &tx)?);

		let stored_tx = format!("{}.mwctx", slate_id);
		let loaded = mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
			&mut wallet,
			None,
			&StoredTxLocator {
				stored_tx: Some(stored_tx),
				..Default::default()
			},
		)?
		.ok_or_else(|| Error::StoredTransactionError("transaction was not loaded".to_string()))?;
		assert!(loaded.eq_by_hash(0, &tx)?);

		assert!(matches!(
			mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
				&mut wallet,
				None,
				&StoredTxLocator {
					id: Some(7),
					tx_slate_id: Some(Uuid::new_v4()),
					stored_tx: None,
				},
			),
			Err(Error::TransactionDoesntExist(_))
		));

		let unregistered_slate_id = Uuid::new_v4();
		wallet.store_tx(&unregistered_slate_id.to_string(), &Transaction::empty())?;
		let unregistered_filename = format!("{}.mwctx", unregistered_slate_id);
		assert!(matches!(
			mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
				&mut wallet,
				None,
				&StoredTxLocator {
					stored_tx: Some(unregistered_filename.clone()),
					..Default::default()
				},
			),
			Err(Error::TransactionDoesntExist(_))
		));
		assert!(matches!(
			mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
				&mut wallet,
				None,
				&StoredTxLocator {
					id: Some(7),
					tx_slate_id: Some(slate_id),
					stored_tx: Some(unregistered_filename),
				},
			),
			Err(Error::TransactionDoesntExist(_))
		));
		assert!(matches!(
			mwc_wallet_libwallet::api_impl::owner::get_stored_tx(
				&mut wallet,
				None,
				&StoredTxLocator::default(),
			),
			Err(Error::StoredTransactionError(_))
		));
		Ok(())
	}

	#[test]
	fn stored_tx_does_not_mask_corrupt_active_file_with_archive() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let wallet = test_wallet(&directory)?;
		let tx_id = Uuid::new_v4().to_string();
		let filename = format!("{}.mwctx", tx_id);
		wallet.store_tx(&tx_id, &Transaction::empty())?;

		let active_path = directory.path().join(TX_SAVE_DIR).join(&filename);
		let archive_path = directory.path().join(TX_ARCHIVE_DIR).join(&filename);
		fs::copy(&active_path, &archive_path)?;
		fs::write(&active_path, b"not valid transaction hex")?;

		match wallet.get_stored_tx(&build_stored_tx_entry(filename)) {
			Err(Error::StoredTransactionError(message)) => {
				assert!(message.contains("decode"));
			}
			other => panic!("expected active-file decode error, got {:?}", other),
		}
		Ok(())
	}

	#[test]
	fn migration_rekeys_outputs_and_preserves_context_encryption() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let context_id = 0;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let client = HTTPNodeClient::new(context_id, vec!["http://127.0.0.1:0".to_owned()], None)
			.map_err(|e| {
				Error::GenericError(format!("Unable to create test node client, {}", e))
			})?;
		let mut wallet = LMDBBackend::<HTTPNodeClient, ExtKeychain>::new(
			context_id,
			directory.path().to_str().ok_or_else(|| {
				Error::GenericError("Test wallet path is not valid UTF-8".to_owned())
			})?,
			client,
		)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[9u8; 32], false)?;
		wallet.set_keychain(
			&secp,
			Box::new(keychain),
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;

		let canonical_parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let legacy_parent = with_legacy_component(&canonical_parent, 400_000)?;
		let canonical_key = ExtKeychain::derive_key_id(3, 0, 0, 7, 0)?;
		let legacy_key = with_legacy_component(&canonical_key, 400_000)?;
		let live_output = OutputData {
			root_key_id: legacy_parent.clone(),
			key_id: legacy_key.clone(),
			n_child: 7,
			commit: None,
			mmr_index: Some(1),
			value: 50,
			status: OutputStatus::Unspent,
			height: 400_001,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: None,
		};
		let mut archived_output = live_output.clone();
		archived_output.mmr_index = Some(2);
		archived_output.status = OutputStatus::Spent;

		let slate_id = Uuid::new_v4();
		let mut context = Context::new(
			&secp,
			&legacy_parent,
			#[cfg(feature = "test-support")]
			false,
			#[cfg(feature = "test-support")]
			true,
			0,
			50,
			1,
			None,
			0,
			0,
			None,
			true,
		)?;
		context.add_output(&legacy_key, &Some(1), 50);
		let expected_private_keys = context.get_private_keys();

		{
			let mut batch = wallet.batch(&secp, None)?;
			batch.save(live_output)?;
			batch.save(archived_output.clone())?;
			batch.archive_output(&archived_output)?;
			batch.save_private_context(&secp, slate_id.as_bytes(), 0, &context)?;
			batch.commit()?;
		}

		{
			let mut batch = wallet.batch(&secp, None)?;
			batch.migrate_legacy_height_identifiers()?;
			batch.commit()?;
		}

		let migrated_live = wallet.get(&canonical_key, &Some(1))?;
		assert_eq!(migrated_live.key_id, canonical_key);
		assert_eq!(migrated_live.root_key_id, canonical_parent);
		assert!(wallet.get(&legacy_key, &Some(1)).is_err());

		let archived = wallet.archive_iter()?.collect::<Vec<_>>();
		assert_eq!(archived.len(), 1);
		assert_eq!(archived[0].key_id, canonical_key);
		assert_eq!(archived[0].root_key_id, canonical_parent);

		let migrated_context = wallet.get_private_context(&secp, None, slate_id.as_bytes(), 0)?;
		assert_eq!(migrated_context.parent_key_id, canonical_parent);
		assert_eq!(migrated_context.output_ids[0].0, canonical_key);
		assert_eq!(migrated_context.get_private_keys(), expected_private_keys);
		Ok(())
	}

	#[test]
	fn migrates_legacy_private_context_masks_in_place() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[8u8; 32], false)?;
		wallet.set_keychain(
			&secp,
			Box::new(keychain),
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;

		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let slate_id = Uuid::new_v4();
		let participant_zero_context = Context::new(
			&secp,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			#[cfg(feature = "test-support")]
			true,
			0,
			50,
			1,
			None,
			0,
			0,
			None,
			true,
		)?;
		let mut participant_one_context = participant_zero_context.clone();
		participant_one_context.participant_id = 1;

		let keychain = wallet.keychain(&secp, None)?;
		let legacy_xor_keys = legacy_private_ctx_xor_keys(&secp, &keychain, slate_id.as_bytes())?;
		let mut legacy_participant_zero = participant_zero_context.clone();
		let mut legacy_participant_one = participant_one_context.clone();
		xor_private_context_secret_fields(&mut legacy_participant_zero, &legacy_xor_keys);
		xor_private_context_secret_fields(&mut legacy_participant_one, &legacy_xor_keys);
		// The legacy format reused each field mask for both participants.
		assert_eq!(
			legacy_participant_zero.sec_key.0,
			legacy_participant_one.sec_key.0
		);
		assert_eq!(
			legacy_participant_zero.sec_nonce.0,
			legacy_participant_one.sec_nonce.0
		);

		let zero_key = to_key_u64(PRIVATE_TX_CONTEXT_PREFIX, slate_id.as_bytes(), 0)?;
		let one_key = to_key_u64(PRIVATE_TX_CONTEXT_PREFIX, slate_id.as_bytes(), 1)?;
		{
			let batch = wallet.db.batch_write()?;
			batch.put_ser(&zero_key, &legacy_participant_zero)?;
			batch.put_ser(&one_key, &legacy_participant_one)?;
			batch.commit()?;
		}

		{
			let mut batch = wallet.batch(&secp, None)?;
			assert!(!batch.load_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT, false)?);
			batch.migrate_private_context_xor_keys(&secp)?;
			batch.save_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT)?;
			batch.commit()?;
		}

		let stored_zero: Context = wallet
			.db
			.get_ser(&zero_key)?
			.ok_or(Error::Backend("migrated participant zero is missing".into()))?;
		let stored_one: Context = wallet
			.db
			.get_ser(&one_key)?
			.ok_or(Error::Backend("migrated participant one is missing".into()))?;
		assert_ne!(stored_zero.sec_key.0, legacy_participant_zero.sec_key.0);
		assert_ne!(stored_one.sec_key.0, legacy_participant_one.sec_key.0);
		assert_ne!(stored_zero.sec_key.0, stored_one.sec_key.0);
		assert_ne!(stored_zero.sec_nonce.0, stored_one.sec_nonce.0);

		let restored_zero = wallet.get_private_context(&secp, None, slate_id.as_bytes(), 0)?;
		let restored_one = wallet.get_private_context(&secp, None, slate_id.as_bytes(), 1)?;
		assert_eq!(restored_zero.sec_key.0, participant_zero_context.sec_key.0);
		assert_eq!(
			restored_zero.sec_nonce.0,
			participant_zero_context.sec_nonce.0
		);
		assert_eq!(
			restored_zero.initial_sec_key.0,
			participant_zero_context.initial_sec_key.0
		);
		assert_eq!(
			restored_zero.initial_sec_nonce.0,
			participant_zero_context.initial_sec_nonce.0
		);
		assert_eq!(restored_one.sec_key.0, participant_one_context.sec_key.0);
		assert_eq!(
			restored_one.sec_nonce.0,
			participant_one_context.sec_nonce.0
		);

		// Exercise the same marker guard used by open_wallet. A second open must
		// not apply the in-place transformation again.
		{
			let mut batch = wallet.batch(&secp, None)?;
			if !batch.load_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT, false)? {
				batch.migrate_private_context_xor_keys(&secp)?;
				batch.save_flag(FLAG_PRIVATE_CONTEXT_MASKS_PARTICIPANT)?;
			}
			batch.commit()?;
		}
		let reopened = wallet.get_private_context(&secp, None, slate_id.as_bytes(), 0)?;
		assert_eq!(reopened.sec_key.0, participant_zero_context.sec_key.0);
		Ok(())
	}

	#[test]
	fn private_context_masks_all_secret_fields() -> Result<(), Error> {
		let directory = TestWalletDir::new()?;
		let context_id = 0;
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let client = HTTPNodeClient::new(context_id, vec!["http://127.0.0.1:0".to_owned()], None)
			.map_err(|e| {
				Error::GenericError(format!("Unable to create test node client, {}", e))
			})?;
		let mut wallet = LMDBBackend::<HTTPNodeClient, ExtKeychain>::new(
			context_id,
			directory.path().to_str().ok_or_else(|| {
				Error::GenericError("Test wallet path is not valid UTF-8".to_owned())
			})?,
			client,
		)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[7u8; 32], false)?;
		wallet.set_keychain(
			&secp,
			Box::new(keychain),
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;

		let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?;
		let slate_id = Uuid::new_v4();
		let mut context = Context::new(
			&secp,
			&parent,
			#[cfg(feature = "test-support")]
			false,
			#[cfg(feature = "test-support")]
			true,
			0,
			50,
			1,
			None,
			0,
			0,
			None,
			true,
		)?;
		context.aggsig_challenge = Some([42u8; 32]);
		let mut participant_one_context = context.clone();
		participant_one_context.participant_id = 1;

		let ctx_key = to_key_u64(
			PRIVATE_TX_CONTEXT_PREFIX,
			slate_id.as_bytes(),
			0,
		)?;
		let participant_one_ctx_key = to_key_u64(
			PRIVATE_TX_CONTEXT_PREFIX,
			slate_id.as_bytes(),
			1,
		)?;

		{
			let mut batch = wallet.batch(&secp, None)?;
			batch.save_private_context(&secp, slate_id.as_bytes(), 0, &context)?;
			batch.save_private_context(&secp, slate_id.as_bytes(), 1, &participant_one_context)?;
			batch.commit()?;
		}

		// The stored value must not contain any of the four secret fields in
		// cleartext.
		let stored: Context = wallet
			.db
			.get_ser(&ctx_key)?
			.ok_or(Error::Backend("private context was not stored".into()))?;
		assert_ne!(stored.sec_key.0, context.sec_key.0);
		assert_ne!(stored.sec_nonce.0, context.sec_nonce.0);
		assert_ne!(stored.initial_sec_key.0, context.initial_sec_key.0);
		assert_ne!(stored.initial_sec_nonce.0, context.initial_sec_nonce.0);
		assert_eq!(stored.aggsig_challenge, context.aggsig_challenge);
		let participant_one_stored: Context =
			wallet
				.db
				.get_ser(&participant_one_ctx_key)?
				.ok_or(Error::Backend(
					"participant-one private context was not stored".into(),
				))?;
		assert_ne!(stored.sec_key.0, participant_one_stored.sec_key.0);
		assert_ne!(stored.sec_nonce.0, participant_one_stored.sec_nonce.0);
		assert_ne!(
			stored.initial_sec_key.0,
			participant_one_stored.initial_sec_key.0
		);
		assert_ne!(
			stored.initial_sec_nonce.0,
			participant_one_stored.initial_sec_nonce.0
		);

		// Reading the context back must restore all four secret fields.
		let restored = wallet.get_private_context(&secp, None, slate_id.as_bytes(), 0)?;
		assert_eq!(restored.sec_key.0, context.sec_key.0);
		assert_eq!(restored.sec_nonce.0, context.sec_nonce.0);
		assert_eq!(restored.initial_sec_key.0, context.initial_sec_key.0);
		assert_eq!(restored.initial_sec_nonce.0, context.initial_sec_nonce.0);
		assert_eq!(restored.aggsig_challenge, context.aggsig_challenge);
		let participant_one_restored =
			wallet.get_private_context(&secp, None, slate_id.as_bytes(), 1)?;
		assert_eq!(
			participant_one_restored.sec_key.0,
			participant_one_context.sec_key.0
		);
		assert_eq!(
			participant_one_restored.sec_nonce.0,
			participant_one_context.sec_nonce.0
		);

		// Strict deletion succeeds for an existing context and reports absence
		// through the typed wallet error after it has been removed.
		{
			let mut batch = wallet.batch(&secp, None)?;
			batch.delete_private_context(slate_id.as_bytes(), 0)?;
			batch.commit()?;
		}
		{
			let mut batch = wallet.batch(&secp, None)?;
			assert!(matches!(
				batch.delete_private_context(slate_id.as_bytes(), 0),
				Err(Error::PrivateContextNotFound(_))
			));
		}
		assert!(matches!(
			wallet.get_private_context(&secp, None, slate_id.as_bytes(), 0),
			Err(Error::PrivateContextNotFound(_))
		));
		Ok(())
	}
}
