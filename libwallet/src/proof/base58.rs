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

use crate::error::{Error, ErrorKind};
use crate::grin_keychain::base58;
use crate::grin_util::secp::key::PublicKey;
use grin_wallet_util::grin_util::secp::{ContextFlag, Secp256k1};

///
pub trait Base58<T> {
	///need to add documentation
	fn from_base58_check(str: &str, version_bytes: Vec<u8>) -> Result<T, Error>;
	///need to add documentation
	fn to_base58_check(&self, version: Vec<u8>) -> String;
}

///
fn to_base58_check(data: &[u8], version: Vec<u8>) -> String {
	let payload: Vec<u8> = version.iter().chain(data.iter()).map(|x| *x).collect();
	base58::check_encode_slice(payload.as_slice())
}

///
fn from_base58_check(data: &str, version_bytes: usize) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let payload: Vec<u8> = base58::from_check(data).map_err(|e| {
		ErrorKind::Base58Error(format!("Unable decode base58 string {}, {}", data, e))
	})?;
	Ok((
		payload[..version_bytes].to_vec(),
		payload[version_bytes..].to_vec(),
	))
}

///
pub fn serialize_public_key(secp: &Secp256k1, public_key: &PublicKey) -> Vec<u8> {
	let ser = public_key.serialize_vec(secp, true);
	ser[..].to_vec()
}

impl Base58<PublicKey> for PublicKey {
	fn from_base58_check(str: &str, version_expect: Vec<u8>) -> Result<PublicKey, Error> {
		let n_version = version_expect.len();
		let (version_actual, key_bytes) = from_base58_check(str, n_version)?;
		if version_actual != version_expect {
			return Err(
				ErrorKind::Base58Error("Address belong to another network".to_string()).into(),
			);
		}
		let secp = Secp256k1::with_caps(ContextFlag::None);
		PublicKey::from_slice(&secp, &key_bytes).map_err(|e| {
			ErrorKind::Base58Error(format!("Unable to build key from Base58, {}", e)).into()
		})
	}

	fn to_base58_check(&self, version: Vec<u8>) -> String {
		let secp = Secp256k1::with_caps(ContextFlag::None);
		to_base58_check(serialize_public_key(&secp, self).as_slice(), version)
	}
}
