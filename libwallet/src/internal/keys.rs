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

//! Wallet key management functions
use crate::error::Error;
use crate::types::{AcctPathMapping, NodeClient, WalletBackend};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{
	ChildNumber, Error as KeychainError, ExtKeychain, Identifier, Keychain,
};
use std::collections::HashSet;
use std::convert::TryFrom;

/// Get next available key in the wallet for a given parent
pub fn next_available_key<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	parent_key_id: Option<&Identifier>,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let child = wallet.next_child(parent_key_id)?;
	Ok(child)
}

/// Canonicalize an identifier by clearing components beyond its declared depth.
///
/// Wallet output keys use depth three. Their unused fourth component is zero in
/// current wallet records, while rangeproof messages, including newly created
/// proofs, use that slot for the anti-replay height. Older wallets also persisted
/// the height in the identifier itself. This helper handles both those older
/// records and decoded proof messages, returning any nonzero depth-three height
/// separately from the canonical derivation identifier.
pub fn canonicalize_stored_identifier(
	identifier: &Identifier,
) -> Result<(Identifier, Option<u32>), Error> {
	const IDENTIFIER_SIZE: usize = 17;
	const PATH_COMPONENT_SIZE: usize = 4;
	const LEGACY_HEIGHT_START: usize = 13;
	const LEGACY_HEIGHT_END: usize = 17;

	let mut bytes = identifier.to_bytes();
	let depth = usize::from(bytes[0]);
	if depth > 4 {
		return Err(KeychainError::InvalidDepth(bytes[0]).into());
	}

	let legacy_height = if depth == 3 {
		let mut height_bytes = [0u8; PATH_COMPONENT_SIZE];
		height_bytes.copy_from_slice(&bytes[LEGACY_HEIGHT_START..LEGACY_HEIGHT_END]);
		match u32::from_be_bytes(height_bytes) {
			0 => None,
			height => Some(height),
		}
	} else {
		None
	};

	let used_end = 1usize
		.checked_add(depth.checked_mul(PATH_COMPONENT_SIZE).ok_or_else(|| {
			Error::DataOverflow(format!(
				"keys::canonicalize_stored_identifier, path length overflow, depth={}",
				depth
			))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"keys::canonicalize_stored_identifier, identifier length overflow, depth={}",
				depth
			))
		})?;
	bytes
		.get_mut(used_end..IDENTIFIER_SIZE)
		.ok_or_else(|| Error::GenericError("Stored identifier has invalid boundaries".to_owned()))?
		.fill(0);

	let canonical = Identifier::from_bytes(&bytes)?;
	// Validate both the declared depth and all encoded child numbers before the
	// repaired identifier is used for derivation or written back to the wallet.
	canonical.to_path()?;
	Ok((canonical, legacy_height))
}

/// Return the wallet child derivation index for a stored output key id.
pub fn output_child_index(key_id: &Identifier) -> Result<u32, Error> {
	let path = key_id.to_path()?;
	let child_index = match path.depth {
		0 => return Ok(0),
		4 => 2,
		depth => {
			// The zero-depth case returned above, so subtracting one cannot underflow.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the zero-depth path returned before this subtraction"
			)]
			{
				usize::from(depth) - 1
			}
		}
	};
	let child = path.path.get(child_index).copied().ok_or_else(|| {
		Error::GenericError("Output key path depth exceeds its component count".to_owned())
	})?;

	u32::try_from(child).map_err(|e| {
		Error::DataOverflow(format!(
			"keys::output_child_index, invalid output key path component, child={:?} error={}",
			child, e
		))
	})
}

/// Return the wallet account path for a stored output key id.
pub fn output_parent_key_id(key_id: &Identifier) -> Result<Identifier, Error> {
	let mut path = key_id.to_path()?;
	if path.depth == 4 {
		path.depth = 2;
		path.path[2] = ChildNumber::from(0);
	} else {
		path = key_id.parent_path()?.to_path()?;
	}
	path.path[3] = ChildNumber::from(0);
	Ok(Identifier::from_path(&path)?)
}

/// Returns a list of account to BIP32 path mappings
pub fn accounts<'a, T: ?Sized, C, K>(wallet: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	Ok(wallet.acct_path_iter()?.collect())
}

/// Renames an account path with a new label
pub fn rename_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	accounts: Vec<AcctPathMapping>,
	old_label: &str,
	label: &str,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_string();
	if let Some(_) = wallet.acct_path_iter()?.find(|l| l.label == label) {
		return Err(Error::AccountLabelAlreadyExists(label.clone()));
	}

	let old_label = old_label.to_string();
	if old_label == "default" {
		return Err(Error::AccountDefaultCannotBeRenamed);
	}

	let found = wallet
		.acct_path_iter()?
		.find(|l| l.label == old_label)
		.is_some();

	if found {
		let mut batch = wallet.batch(secp, keychain_mask)?;
		batch.rename_acct_path(accounts, &old_label, &label)?;
		batch.commit()?;
	} else {
		return Err(Error::AccountLabelNotExists(old_label.clone()));
	}

	Ok(())
}

/// Adds an new parent account path with a given label
pub fn new_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_owned();
	// Account creation is serialized by the supported wallet lifecycle: public
	// entry points hold the wallet instance mutex for this entire call, and a
	// wallet data directory may have only one opened backend (see the
	// `WalletLCProvider` lifecycle invariant). Consequently these reads cannot
	// race another supported account creator before the write batch is opened.
	// Direct callers must likewise retain exclusive access and obey that
	// single-backend invariant.
	if wallet.acct_path_iter()?.any(|l| l.label == label) {
		return Err(Error::AccountLabelAlreadyExists(label));
	}

	// We're always using paths at m/k/0 for parent keys for output derivations
	// We try to find the first available index. Maximum will not work because there we can use reserved accounts
	let mut acc_ids: HashSet<u32> = HashSet::new();
	for acc in wallet.acct_path_iter()? {
		let path = acc.path.to_path()?;
		let child =
			path.path.first().copied().ok_or_else(|| {
				Error::GenericError("Account key path has no components".to_owned())
			})?;
		let id = u32::try_from(child).map_err(|e| {
			Error::DataOverflow(format!(
				"keys::new_acct_path, account key path component does not fit u32, child={:?} error={}",
				child, e
			))
		})?;
		acc_ids.insert(id);
	}

	let id = (1..65536)
		.filter(|v| !acc_ids.contains(v))
		.next()
		.ok_or(Error::GenericError(
			"Unable create a new account. Too many already exist".to_string(),
		))?;

	let template_account = wallet.acct_path_iter()?.next();

	let return_id = {
		if let Some(e) = template_account {
			let mut p = e.path.to_path()?;
			p.path[0] = ChildNumber::from_normal_idx(id).map_err(KeychainError::from)?;
			p.to_identifier()?
		} else {
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?
		}
	};

	let save_path = AcctPathMapping {
		label: label,
		path: return_id.clone(),
	};

	let mut batch = wallet.batch(secp, keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(return_id)
}

/// Adds/sets a particular account path with a given label
pub fn set_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	label: &str,
	path: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_owned();
	let mut batch = wallet.batch(secp, keychain_mask)?;
	let existing = batch
		.acct_path_iter()?
		.find(|mapping| mapping.label == label);
	if existing.is_some_and(|mapping| mapping.path != *path) {
		return Err(Error::AccountLabelAlreadyExists(label));
	}

	let save_path = AcctPathMapping {
		label,
		path: path.clone(),
	};

	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn canonicalizes_legacy_height_identifier() -> Result<(), Error> {
		let canonical = ExtKeychain::derive_key_id(3, 1, 2, 3, 0)?;
		let mut legacy_bytes = canonical.to_bytes();
		legacy_bytes[13..17].copy_from_slice(&321_654u32.to_be_bytes());
		let legacy = Identifier::from_bytes(&legacy_bytes)?;

		let (repaired, height) = canonicalize_stored_identifier(&legacy)?;

		assert_eq!(repaired, canonical);
		assert_eq!(height, Some(321_654));
		Ok(())
	}

	#[test]
	fn canonical_identifier_is_unchanged() -> Result<(), Error> {
		let canonical = ExtKeychain::derive_key_id(3, 4, 5, 6, 0)?;

		let (repaired, height) = canonicalize_stored_identifier(&canonical)?;

		assert_eq!(repaired, canonical);
		assert_eq!(height, None);
		Ok(())
	}
}
