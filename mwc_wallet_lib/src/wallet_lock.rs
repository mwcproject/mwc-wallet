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

/// Helper for taking a lock on the wallet instance
#[macro_export]
macro_rules! wallet_lock {
	($wallet_inst: expr, $wallet: ident) => {
		let inst = $wallet_inst.clone();
		let mut w_lock = inst.lock().expect("Mutex failure");
		let w_provider = w_lock
			.lc_provider()
			.map_err(|e| format!("Wallet is not initialized, {}", e))?;
		let $wallet = w_provider
			.wallet_inst()
			.map_err(|e| format!("Wallet is not initialized, {}", e))?;
	};
}
