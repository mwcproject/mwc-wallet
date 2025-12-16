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
use log::info;
use mwc_wallet_impls::{PathToSlateGetter, SlateGetter};
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::types::U64_DATA_IDX_ADDRESS_INDEX;
use mwc_wallet_libwallet::{foreign, owner, SlatePurpose};
use mwc_wallet_util::mwc_keychain::Keychain;

pub fn finalize(
	context_id: u32,
	slatepack: String,
	fluff: Option<bool>,
	nopost: Option<bool>,
) -> Result<(), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let (slatepack_secret, secp, context_id, client) = {
		wallet_lock!(wallet, w);
		let keychain = w
			.keychain(None)
			.map_err(|e| format!("Keychain access error, {}", e))?;
		let address_index: u32 = {
			let mut batch = w
				.batch(None)
				.map_err(|e| format!("Batch access error, {}", e))?;
			let index = batch
				.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)
				.map_err(|e| format!("Db load error, {}", e))?;
			index as u32
		};
		let slatepack_secret =
			proofaddress::payment_proof_address_dalek_secret(context_id, &keychain, address_index)
				.map_err(|e| format!("Payment address access error, {}", e))?;
		(
			slatepack_secret,
			keychain.secp().clone(),
			context_id,
			w.w2n_client().clone(),
		)
	};

	let slate_pkg = PathToSlateGetter::build_form_str(context_id, slatepack)
		.get_tx(Some(&slatepack_secret), &secp)
		.map_err(|e| format!("slatepack decoding error, {}", e))?;

	let (slate, _sender, _recipient, content, _slatepack_format) = slate_pkg
		.to_slate()
		.map_err(|e| format!("slatepack decoding error, {}", e))?;

	if !(content == SlatePurpose::FullSlate || content == SlatePurpose::SendResponse) {
		return Err(format!(
			"Wrong slate content. Expecting SendResponse, get {:?}",
			content
		));
	}

	foreign::verify_slate_messages(&slate).map_err(|e| format!("Invalid slate, {}", e))?;

	let slate_res = {
		wallet_lock!(wallet, w);
		let (slate_res, _context) =
			owner::finalize_tx(&mut **w, None, &None, &slate, true, false, true)
				.map_err(|e| format!("Unable to finalze, {}", e))?;
		slate_res
	};

	if !nopost.unwrap_or(false) {
		owner::post_tx(&client,
                       slate_res.tx_or_err()
                           .map_err(|e| format!("Not able extract transaction from the slate, {}", e))?,
                       fluff.unwrap_or(false))
            .map_err(|e| format!("Unable to port thransaction {}, please report when network will be stable. Error: {}", slate_res.id, e))?;

		info!(
			"Transaction {} sent successfully, check the wallet again for confirmation.",
			slate_res.id
		);
	}
	Ok(())
}
