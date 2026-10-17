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
use mwc_wallet_util::mwc_crates::libc;
use mwc_wallet_util::mwc_crates::log::error;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::serde_json::json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_node_lib::ffi::LIB_CALLBACKS;
use std::ffi::CString;

fn ensure_status_callback_registered(response_callback: &str) -> Result<(), String> {
	if LIB_CALLBACKS
		.read_recursive()
		.contains_key(response_callback)
	{
		Ok(())
	} else {
		Err(format!(
			"response_callback function {} not found",
			response_callback
		))
	}
}

fn encode_status_callback(response_id: &str, status: &StatusMessage) -> Result<CString, String> {
	let status = serde_json::to_value(status)
		.map_err(|e| format!("Unable to encode scan status {:?}: {}", status, e))?;
	let payload = json!({
		"response_id": response_id,
		"status": status,
	});
	CString::new(payload.to_string())
		.map_err(|e| format!("Unable to convert scan status to a C string: {}", e))
}

fn dispatch_status_callback(response_callback: &str, response_id: &str, status: StatusMessage) {
	let payload = match encode_status_callback(response_id, &status) {
		Ok(payload) => payload,
		Err(e) => {
			error!("{}", e);
			return;
		}
	};

	let callbacks = LIB_CALLBACKS.read_recursive();
	if let Some((callback, context)) = callbacks.get(response_callback) {
		// Keep the registry read lock until the callback returns so unregistering
		// cannot free or reuse its caller-owned context during this invocation.
		let _ = callback(
			*context as *mut std::ffi::c_void,
			payload.as_c_str().as_ptr() as *const libc::c_char,
		);
	}
}

pub fn scan(
	context_id: u32,
	delete_unconfirmed: bool,
	response_callback: String,
	response_id: String,
) -> Result<u64, String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)
		.map_err(|e| format!("Unable to initialize secp context, {}", e))?;
	ensure_status_callback_registered(&response_callback)?;
	let status_callback = |status| {
		dispatch_status_callback(&response_callback, &response_id, status);
	};

	let height = owner::scan(
		wallet,
		&mut secp,
		None,
		None,
		None,
		delete_unconfirmed,
		true,
		Some(&status_callback),
	)
	.map_err(|e| format!("Blockchain scan error, {}", e))?;

	Ok(height)
}

pub fn scan_rewind_hash(
	context_id: u32,
	rewind_hash: String,
	response_callback: String,
	response_id: String,
) -> Result<ViewWallet, String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)
		.map_err(|e| format!("Unable to initialize secp context, {}", e))?;
	ensure_status_callback_registered(&response_callback)?;
	let status_callback = |status| {
		dispatch_status_callback(&response_callback, &response_id, status);
	};

	let result = owner::scan_rewind_hash(
		wallet,
		&mut secp,
		Zeroizing::new(rewind_hash),
		None,
		None,
		Some(&status_callback),
	)
	.map_err(|e| format!("Rewind hash scan error, {}", e))?;

	Ok(result)
}

pub fn update_wallet_state(
	context_id: u32,
	response_callback: String,
	response_id: String,
) -> Result<(bool, u64), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)
		.map_err(|e| format!("Unable to initialize secp context, {}", e))?;
	ensure_status_callback_registered(&response_callback)?;
	let status_callback = |status| {
		dispatch_status_callback(&response_callback, &response_id, status);
	};

	let (validated, height) = {
		wallet_lock!(wallet, w);
		let (validated, height) =
			owner::update_wallet_state(&mut **w, &mut secp, None, Some(&status_callback))
				.map_err(|e| format!("Update wallet state scan error, {}", e))?;
		(validated, height)
	};

	Ok((validated, height))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::ffi::CStr;
	use std::sync::Mutex;

	static CAPTURED_STATUS: Mutex<Option<String>> = Mutex::new(None);

	extern "C" fn capture_status_callback(
		_context: *mut std::ffi::c_void,
		message: *const libc::c_char,
	) -> *const libc::c_char {
		if message.is_null() {
			return std::ptr::null();
		}

		let message = unsafe { CStr::from_ptr(message) }
			.to_string_lossy()
			.into_owned();
		if let Ok(mut captured) = CAPTURED_STATUS.lock() {
			*captured = Some(message);
		}
		std::ptr::null()
	}

	#[test]
	fn synchronous_status_payload_keeps_response_id_and_legacy_status_shape() {
		let payload = encode_status_callback(
			"scan-17",
			&StatusMessage::Scanning(true, "Checking outputs".to_owned(), 42),
		)
		.expect("status callback payload should encode");
		let value: serde_json::Value = serde_json::from_slice(payload.as_bytes())
			.expect("status callback payload should be JSON");

		assert_eq!(
			value,
			json!({
				"response_id": "scan-17",
				"status": {"Scanning": [true, "Checking outputs", 42]},
			})
		);
	}

	#[test]
	fn registered_status_callback_is_called_before_dispatch_returns() {
		const CALLBACK_NAME: &str = "wallet_scan_inline_status_test";
		*CAPTURED_STATUS.lock().expect("capture lock") = None;
		LIB_CALLBACKS.write().insert(
			CALLBACK_NAME.to_owned(),
			(
				capture_status_callback,
				std::ptr::null_mut::<std::ffi::c_void>() as usize,
			),
		);

		dispatch_status_callback(
			CALLBACK_NAME,
			"scan-18",
			StatusMessage::ScanningComplete(true, "Scanning Complete".to_owned()),
		);

		LIB_CALLBACKS.write().remove(CALLBACK_NAME);
		let payload = CAPTURED_STATUS
			.lock()
			.expect("capture lock")
			.take()
			.expect("callback should run inline");
		let value: serde_json::Value =
			serde_json::from_str(&payload).expect("callback payload should be JSON");
		assert_eq!(
			value,
			json!({
				"response_id": "scan-18",
				"status": {"ScanningComplete": [true, "Scanning Complete"]},
			})
		);
	}
}
