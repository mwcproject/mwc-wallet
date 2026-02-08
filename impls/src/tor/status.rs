// Copyright 2021 The MWC Developers
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

//! Tor status for the wallet. That data can be sharable by many components. We just
//! need to know how it is running.

use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
	// Current address that is tor is listening on (also mean that listener is running)
	static ref TOR_ONION_ADDRESS: RwLock<HashMap<u32,String>> = RwLock::new(HashMap::new());

	// Flag if listener tor process is running. (we want to keep listener and sender separately)
	// And we want to have them single socks port to use. That is why the tor starting process args
	// can be adjusted
	static ref TOR_SENDER_RUNNING: RwLock<HashMap<u32,bool>> = RwLock::new(HashMap::new());
}

pub fn tor_status_clean_context(context_id: u32) {
	TOR_ONION_ADDRESS
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.remove(&context_id);
	TOR_SENDER_RUNNING
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.remove(&context_id);
}

pub fn set_tor_address(context_id: u32, address: Option<String>) {
	match address {
		Some(address) => TOR_ONION_ADDRESS
			.write()
			.unwrap_or_else(|e| e.into_inner())
			.insert(context_id, address),
		None => TOR_ONION_ADDRESS
			.write()
			.unwrap_or_else(|e| e.into_inner())
			.remove(&context_id),
	};
}

pub fn get_tor_address(context_id: u32) -> Option<String> {
	TOR_ONION_ADDRESS
		.read()
		.unwrap_or_else(|e| e.into_inner())
		.get(&context_id)
		.cloned()
}

pub fn set_tor_sender_running(context_id: u32, running: bool) {
	TOR_SENDER_RUNNING
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.insert(context_id, running);
}

pub fn get_tor_sender_running(context_id: u32) -> bool {
	TOR_SENDER_RUNNING
		.read()
		.unwrap_or_else(|e| e.into_inner())
		.get(&context_id)
		.cloned()
		.unwrap_or(false)
}
