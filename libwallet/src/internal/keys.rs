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
use crate::mwc_keychain::{ChildNumber, ExtKeychain, Identifier, Keychain};
use crate::mwc_util::secp::key::SecretKey;
use crate::types::{AcctPathMapping, NodeClient, WalletBackend};
use std::collections::HashSet;

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
	let child = wallet.next_child(parent_key_id, None)?;
	Ok(child)
}

/// Retrieve an existing key from a wallet
pub fn retrieve_existing_key<'a, T: ?Sized, C, K>(
	wallet: &T,
	key_id: Identifier,
	mmr_index: Option<u64>,
) -> Result<(Identifier, u32), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let existing = wallet.get(&key_id, &mmr_index)?;
	let key_id = existing.key_id.clone();
	let derivation = existing.n_child;
	Ok((key_id, derivation))
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
		let mut batch = wallet.batch(keychain_mask)?;
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
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let label = label.to_owned();
	if wallet.acct_path_iter()?.any(|l| l.label == label) {
		return Err(Error::AccountLabelAlreadyExists(label));
	}

	// We're always using paths at m/k/0 for parent keys for output derivations
	// We try to find the first available index. Maximum will not work because there we can use reserved accounts
	let mut acc_ids: HashSet<u32> = HashSet::new();
	for acc in wallet.acct_path_iter()? {
		let id = u32::from(acc.path.to_path()?.path[0]);
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
			p.path[0] = ChildNumber::from(id);
			p.to_identifier()?
		} else {
			ExtKeychain::derive_key_id(2, 0, 0, 0, 0)?
		}
	};

	let save_path = AcctPathMapping {
		label: label,
		path: return_id.clone(),
	};

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(return_id)
}

/// Adds/sets a particular account path with a given label
pub fn set_acct_path<'a, T: ?Sized, C, K>(
	wallet: &mut T,
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
	let save_path = AcctPathMapping {
		label: label,
		path: path.clone(),
	};

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_acct_path(save_path)?;
	batch.commit()?;
	Ok(())
}
