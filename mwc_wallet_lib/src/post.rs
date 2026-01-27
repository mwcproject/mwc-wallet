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

use crate::wallet_lock;
use mwc_wallet_libwallet::NodeClient;
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_core::ser;
use mwc_wallet_util::mwc_core::ser::DeserializationMode;
use mwc_wallet_util::mwc_util::from_hex;
use std::fs::File;
use std::io::Read;

pub fn post(context_id: u32, input_path: String, fluff: Option<bool>) -> Result<(), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	#[cfg(not(target_os = "android"))]
	let home_dir = dirs::home_dir()
		.map(|p| p.to_str().map(|s| s.to_string()))
		.flatten()
		.unwrap_or("~".to_string());

	#[cfg(target_os = "android")]
	let home_dir = std::env::current_exe() //  dirs::home_dir()
		.map(|p| {
			let mut p = p.clone();
			p.pop();
			p.to_str().map(|s| s.to_string())
		})
		.flatten()
		.unwrap_or("~".to_string());

	let mut file = File::open(input_path.replace("~", &home_dir))
		.map_err(|e| format!("Unable to open {}, {}", input_path, e))?;
	let mut txn_file = String::new();
	file.read_to_string(&mut txn_file)
		.map_err(|e| format!("Unable to read from {}, {}", input_path, e))?;
	if txn_file.len() < 3 {
		return Err(format!("File {} is empty", input_path));
	}

	let tx_bin = from_hex(&txn_file)
		.map_err(|_s| format!("Unable to parse the content of the file {}", input_path))?;

	let tx: Transaction = ser::deserialize(
		&mut &tx_bin[..],
		ser::ProtocolVersion(1),
		context_id,
		DeserializationMode::default(),
	)
	.map_err(|e| format!("Unable deserealize transaction from {}, {}", input_path, e))?;

	let client = {
		wallet_lock!(wallet, w);
		w.w2n_client().clone()
	};
	client
		.post_tx(&tx, fluff.unwrap_or(false))
		.map_err(|e| format!("Unable to post transaction, {}", e))?;
	Ok(())
}
