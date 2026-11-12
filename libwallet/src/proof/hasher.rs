// Copyright 2025 The MWC Developers
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

use mwc_wallet_util::mwc_crates::ripemd::Ripemd160;
use mwc_wallet_util::mwc_crates::sha2::{Digest, Sha256};

use mwc_wallet_util::mwc_core::global::is_floonet;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_keychain;
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_keychain::SwitchCommitmentType;
use mwc_wallet_util::mwc_keychain::extkey_bip32::{
	BIP32Hasher, BIP32HmacOutput, ChildNumber, ExtendedPrivKey,
};
use mwc_wallet_util::mwc_keychain::zeroizing_hmac_sha512::ZeroizingHmacSha512;
use std::fmt;

use crate::Error;

#[derive(Clone)]
///BIP32MwcboxHasher
pub struct BIP32MwcboxHasher {
	is_floonet: bool,
	hmac_sha512: Option<ZeroizingHmacSha512>,
}

impl fmt::Debug for BIP32MwcboxHasher {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BIP32MwcboxHasher")
			.field("is_floonet", &self.is_floonet)
			.field("hmac_sha512", &self.hmac_sha512.is_some())
			.finish()
	}
}

impl BIP32MwcboxHasher {
	/// New empty hasher
	pub fn new(is_floonet: bool) -> Self {
		Self {
			is_floonet,
			hmac_sha512: None,
		}
	}
}

impl BIP32Hasher for BIP32MwcboxHasher {
	fn network_priv(&self) -> [u8; 4] {
		match self.is_floonet {
			true => [42, 0, 0, 42],
			false => [42, 1, 0, 42],
		}
	}
	fn network_pub(&self) -> [u8; 4] {
		match self.is_floonet {
			true => [42, 0, 1, 42],
			false => [42, 1, 1, 42],
		}
	}
	fn master_seed() -> [u8; 12] {
		b"Grinbox_seed".to_owned()
	}
	fn init_sha512(
		&mut self,
		seed: &[u8],
	) -> Result<(), mwc_wallet_util::mwc_keychain::extkey_bip32::Error> {
		self.hmac_sha512 = Some(ZeroizingHmacSha512::new(seed)?);
		Ok(())
	}

	fn append_sha512(
		&mut self,
		value: &[u8],
	) -> Result<(), mwc_wallet_util::mwc_keychain::extkey_bip32::Error> {
		let hmac_sha512 = self.hmac_sha512.as_mut().ok_or_else(|| {
			mwc_keychain::extkey_bip32::Error::Generic("sha512 is not initialized".into())
		})?;
		hmac_sha512.update(value);
		Ok(())
	}

	fn result_sha512(
		&mut self,
		output: &mut BIP32HmacOutput,
	) -> Result<(), mwc_wallet_util::mwc_keychain::extkey_bip32::Error> {
		let hmac_sha512 = self.hmac_sha512.as_mut().ok_or_else(|| {
			mwc_keychain::extkey_bip32::Error::Generic("sha512 is not initialized".into())
		})?;
		hmac_sha512.finalize_into(output);

		// Drop the secret-bearing HMAC state in place. Moving it out with take()
		// could leave an unwiped copy in the field's former storage.
		self.hmac_sha512 = None;
		Ok(())
	}
	fn sha_256(&self, input: &[u8]) -> [u8; 32] {
		let mut sha2_res = [0; 32];
		let mut sha2 = Sha256::new();
		sha2.update(input);
		sha2_res.copy_from_slice(sha2.finalize().as_slice());
		sha2_res
	}
	fn ripemd_160(&self, input: &[u8]) -> [u8; 20] {
		let mut ripemd_res = [0; 20];
		let mut ripemd = Ripemd160::new();
		ripemd.update(input);
		ripemd_res.copy_from_slice(ripemd.finalize().as_slice());
		ripemd_res
	}
}

///this derive_address_key will used in both mwc-wallet and wallet713 to derive the key.
pub fn derive_address_key<K: Keychain>(
	secp: &Secp256k1,
	context_id: u32,
	keychain: &K,
	index: u32,
) -> Result<SecretKey, Error> {
	let root = keychain
		.derive_key(secp, 713, &K::root_key_id()?, SwitchCommitmentType::Regular)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	let mut hasher = BIP32MwcboxHasher::new(is_floonet(context_id));
	let master = ExtendedPrivKey::new_master(secp, &mut hasher, &root.0)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	let child_number = ChildNumber::from_normal_idx(index)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	let private_key = master
		.ckd_priv(secp, &mut hasher, child_number)
		.map_err(|e| Error::DeriveKeyError(format!("Derive key error, {}", e)))?;
	Ok(private_key.secret_key)
}
