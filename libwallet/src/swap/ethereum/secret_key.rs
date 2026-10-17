// Copyright 2026 The MWC Developers
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

use mwc_wallet_util::mwc_web3;
use std::ops::Deref;

/// Keep signing keys in erasing storage and borrow them when signing.
pub(super) struct SecretKeyGuard(Box<mwc_web3::signing::SecretKey>);

impl SecretKeyGuard {
	pub(super) fn from_bytes(bytes: &[u8; 32]) -> Result<Self, mwc_web3::Error> {
		let mut key = mwc_web3::signing::SecretKey::from_byte_array(*bytes).map_err(|e| {
			mwc_web3::Error::InvalidResponse(format!("Invalid Ethereum private key: {}", e))
		})?;
		let guarded = Self(Box::new(key));
		// SecretKey is Copy, so erase the temporary used to initialize the box too.
		key.non_secure_erase();
		Ok(guarded)
	}
}

impl Deref for SecretKeyGuard {
	type Target = mwc_web3::signing::SecretKey;

	fn deref(&self) -> &Self::Target {
		self.0.as_ref()
	}
}

impl Drop for SecretKeyGuard {
	fn drop(&mut self) {
		self.0.as_mut().non_secure_erase();
	}
}
