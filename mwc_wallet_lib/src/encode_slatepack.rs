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
use ed25519_dalek::PublicKey as DalekPublicKey;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::{foreign, SlatePurpose, SlateVersion, VersionedSlate};

pub fn encode_slatepack(
	context_id: u32,
	slate: VersionedSlate,
	recipient: Option<String>,
	content: SlatePurpose,
	address_index: Option<u32>,
) -> Result<String, String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	// Expected Slate in Json (plain) format
	let slate = slate
		.into_slate_plain(context_id, false)
		.map_err(|e| format!("Expected to get slate in Json format, {}", e))?;

	let recipient: Option<DalekPublicKey> = match recipient {
		Some(recipient) => {
			let recipient = ProvableAddress::from_str(context_id, &recipient)
				.map_err(|e| format!("Invalid recipient address, {}", e))?;
			let recipient = recipient
				.tor_public_key()
				.map_err(|e| format!("Invalid recipient address, {}", e))?;
			Some(recipient)
		}
		None => None,
	};

	wallet_lock!(wallet, w);
	let res_slate = foreign::encrypt_slate(
		&mut **w,
		None,
		&slate,
		Some(SlateVersion::SP),
		content,
		recipient,
		address_index,
		false,
	)
	.map_err(|e| format!("Slate encryption error, {}", e))?;

	if let VersionedSlate::SP(message) = res_slate {
		Ok(message)
	} else {
		Err("Unable to encode the slate, internal error".to_string())
	}
}
