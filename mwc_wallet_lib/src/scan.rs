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
use mwc_wallet_libwallet::{owner, StatusMessage, ViewWallet};
use mwc_wallet_util::mwc_node_lib::ffi::LIB_CALLBACKS;
use serde_json::json;
use std::ffi::CString;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::thread::JoinHandle;
// progress_callback: Box<dyn Fn(StatusMessage) + Send + Sync>,

fn start_update_thread(
	response_callback: String,
	response_id: String,
) -> Result<(Sender<StatusMessage>, JoinHandle<Result<(), String>>), String> {
	let (cb_fn, cb_context) = match LIB_CALLBACKS
		.read()
		.unwrap_or_else(|e| e.into_inner())
		.get(&response_callback)
	{
		Some(cb) => cb.clone(),
		None => {
			return Err(format!(
				"response_callback function {} not found",
				response_callback
			))
		}
	};

	let (tx, rx) = channel();

	let update_thread = thread::spawn(move || {
		loop {
			match rx.recv() {
				Ok(msg) => {
					let status = serde_json::to_value(&msg)
						.map_err(|e| format!("Unable encode as a json message {:?}, {}", msg, e))?;

					let status = json!({
						"response_id" : response_id,
						"status" : status,
					});
					let status = status.to_string();
					let c_status =
						CString::new(status).expect("Unable convert string into C format");
					let c_compatible_ref: *const libc::c_char = c_status.as_c_str().as_ptr();
					cb_fn(cb_context as *mut std::ffi::c_void, c_compatible_ref);
				}
				Err(_) => break,
			}
		}
		Ok(())
	});

	Ok((tx, update_thread))
}

pub fn scan(
	context_id: u32,
	delete_unconfirmed: bool,
	response_callback: String,
	response_id: String,
) -> Result<u64, String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let (tx, update_thread) = start_update_thread(response_callback, response_id)?;
	let tx = Some(tx);

	let height = owner::scan(wallet, None, None, delete_unconfirmed, &tx, true)
		.map_err(|e| format!("Blockchain scan error, {}", e))?;
	drop(tx);

	update_thread
		.join()
		.map_err(|_| "update thread runtime error".to_string())??;

	Ok(height)
}

pub fn scan_rewind_hash(
	context_id: u32,
	rewind_hash: String,
	response_callback: String,
	response_id: String,
) -> Result<ViewWallet, String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let (tx, update_thread) = start_update_thread(response_callback, response_id)?;
	let tx = Some(tx);

	let result = owner::scan_rewind_hash(wallet, rewind_hash, None, &tx)
		.map_err(|e| format!("Rewind hash scan error, {}", e))?;
	drop(tx);

	update_thread
		.join()
		.map_err(|_| "update thread runtime error".to_string())??;

	Ok(result)
}

pub fn update_wallet_state(
	context_id: u32,
	response_callback: String,
	response_id: String,
) -> Result<(bool, u64), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let (tx, update_thread) = start_update_thread(response_callback, response_id)?;
	let tx = Some(tx);

	let (validated, height) = {
		wallet_lock!(wallet, w);
		let (validated, height) = owner::update_wallet_state(&mut **w, None, &tx)
			.map_err(|e| format!("Update wallet state scan error, {}", e))?;
		drop(tx);
		(validated, height)
	};

	update_thread
		.join()
		.map_err(|_| "update thread runtime error".to_string())??;

	Ok((validated, height))
}
