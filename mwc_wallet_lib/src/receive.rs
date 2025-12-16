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
use mwc_wallet_impls::{PathToSlateGetter, PathToSlatePutter, SlateGetter, SlatePutter};
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::types::U64_DATA_IDX_ADDRESS_INDEX;
use mwc_wallet_libwallet::{foreign, SlatePurpose};
use mwc_wallet_util::mwc_keychain::Keychain;
use uuid::Uuid;

/// Receive Slatepack data.
/// Return: (response SP , txUUID)
pub fn receive(
	context_id: u32,
	slatepack: String,
	message: Option<String>,
	account: Option<String>,
) -> Result<(String, Uuid), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;

	let (slatepack_secret, secp, context_id) = {
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
		(slatepack_secret, keychain.secp().clone(), context_id)
	};

	let slate_pkg = PathToSlateGetter::build_form_str(context_id, slatepack)
		.get_tx(Some(&slatepack_secret), &secp)
		.map_err(|e| format!("slatepack decoding error, {}", e))?;

	let (slate, sender, _recipient, content, slatepack_format) = slate_pkg
		.to_slate()
		.map_err(|e| format!("slatepack decoding error, {}", e))?;

	if !(content == SlatePurpose::FullSlate || content == SlatePurpose::SendInitial) {
		return Err(format!(
			"Wrong slate content. Expecting SendInitial, get {:?}",
			content
		));
	}

	foreign::verify_slate_messages(&slate).map_err(|e| format!("Invalid slate, {}", e))?;

	let slate = {
		wallet_lock!(wallet, w);
		let (slate, _) = foreign::receive_tx(
			&mut **w,
			None,
			&None,
			&slate,
			sender.map(|p| ProvableAddress::from_tor_pub_key(&p).public_key),
			None,
			None,
			&account,
			message,
			false,
			true,
		)
		.map_err(|e| format!("Failed to receive transaction. {}", e))?;
		slate
	};

	let slatepack_str = PathToSlatePutter::build_encrypted(
		context_id,
		None,
		SlatePurpose::SendResponse,
		DalekPublicKey::from(&slatepack_secret),
		sender,
		slatepack_format,
	)
	.put_tx(&slate, Some(&slatepack_secret), false, &secp)
	.map_err(|e| format!("Unable encrypt slatepack, {}", e))?;

	Ok((slatepack_str, slate.id))
}
