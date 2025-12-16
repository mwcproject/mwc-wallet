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

use crate::mwc_wallet_calls::call_mwc_wallet_request;
use safer_ffi::prelude::*;

/// Process mwc-wallet related call.
/// Input: json stirng param
/// return: json string as a result. Call free_wallet_lib_string to release the memory
#[ffi_export]
fn process_mwc_wallet_request(input: char_p::Ref<'_>) -> char_p::Box {
	let input = input.to_str();

	let resposne: String = call_mwc_wallet_request(input.to_string());
	resposne.try_into().expect("Safer FFI failure")
}
