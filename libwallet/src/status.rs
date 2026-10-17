// Copyright 2019 The Grin Developers
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

//! Synchronous wallet-operation status notifications.

use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};

/// Status messages emitted while a wallet operation is running.
///
/// The serialized representation is retained for compatibility with native
/// library scan callbacks. Emitting a message does not create or communicate
/// with a background updater thread.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum StatusMessage {
	/// Wallet is matching the UTXO set against its current outputs.
	UpdatingOutputs(bool, String),
	/// Warning that the wallet is about to perform a full UTXO scan.
	FullScanWarn(String),
	/// UTXO scan progress and percentage complete.
	Scanning(bool, String, u8),
	/// UTXO scanning is complete.
	ScanningComplete(bool, String),
	/// Warning produced while repairing wallet state.
	Warning(String),
	/// Informational wallet-operation message.
	Info(String),
}

/// Callback invoked synchronously from the wallet operation that emits a
/// status message.
pub type StatusCallback<'a> = dyn Fn(StatusMessage) + 'a;

pub(crate) fn send_status(status_callback: Option<&StatusCallback<'_>>, message: StatusMessage) {
	if let Some(callback) = status_callback {
		callback(message);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::serde_json;
	use std::cell::RefCell;

	#[test]
	fn status_callback_runs_inline() {
		let observed = RefCell::new(Vec::new());
		let callback = |message| observed.borrow_mut().push(message);

		send_status(
			Some(&callback),
			StatusMessage::Info("inline status".to_owned()),
		);

		assert_eq!(
			observed.into_inner(),
			vec![StatusMessage::Info("inline status".to_owned())]
		);
	}

	#[test]
	fn scan_status_keeps_the_native_callback_wire_format() {
		let value = serde_json::to_value(StatusMessage::Scanning(
			true,
			"Checking outputs".to_owned(),
			42,
		))
		.expect("scan status should serialize");

		assert_eq!(
			value,
			serde_json::json!({"Scanning": [true, "Checking outputs", 42]})
		);
	}
}
