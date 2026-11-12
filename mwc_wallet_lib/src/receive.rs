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
use mwc_wallet_api::Foreign;
use mwc_wallet_impls::{PathToSlateGetter, PathToSlatePutter, SlateGetter, SlatePutter};
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::slatepack::validate_slatepack_receive_direction;
use mwc_wallet_libwallet::types::{TxSession, U64_DATA_IDX_ADDRESS_INDEX};
use mwc_wallet_libwallet::{foreign, SlatePurpose};
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use std::convert::TryFrom;

/// Receive Slatepack data.
/// Return: (response SP , txUUID)
pub fn receive(
	context_id: u32,
	slatepack: String,
	message: Option<String>,
	account: Option<String>,
) -> Result<(String, Uuid), String> {
	let wallet = crate::mwc_wallet_calls::get_wallet_instance(context_id)?;
	let secp = Secp256k1::with_caps(ContextFlag::Commit)
		.map_err(|e| format!("Unable to initialize secp context, {}", e))?;

	let (slatepack_secret, secp, context_id) = {
		wallet_lock!(wallet, w);
		let keychain = w
			.keychain(&secp, None)
			.map_err(|e| format!("Keychain access error, {}", e))?;
		let address_index: u32 = {
			let mut batch = w
				.batch(&secp, None)
				.map_err(|e| format!("Batch access error, {}", e))?;
			let index = batch
				.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)
				.map_err(|e| format!("Db load error, {}", e))?;
			u32::try_from(index).map_err(|e| {
				format!(
					"receive, address index does not fit u32, index={} error={}",
					index, e
				)
			})?
		};
		let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
			&secp,
			context_id,
			&keychain,
			address_index,
		)
		.map_err(|e| format!("Payment address access error, {}", e))?;
		(slatepack_secret, secp, context_id)
	};

	let slate_pkg = PathToSlateGetter::build_form_str(context_id, slatepack)
		.get_tx(Some(&slatepack_secret), &secp)
		.map_err(|e| format!("slatepack decoding error, {}", e))?;

	let (slate, sender, recipient, content, slatepack_format) = slate_pkg
		.to_slate()
		.map_err(|e| format!("slatepack decoding error, {}", e))?;
	validate_slatepack_receive_direction(
		sender.as_ref(),
		recipient.as_ref(),
		&slatepack_secret.verifying_key(),
	)
	.map_err(|e| format!("slatepack direction error, {}", e))?;

	if !(content == SlatePurpose::FullSlate || content == SlatePurpose::SendInitial) {
		return Err(format!(
			"Wrong slate content. Expecting SendInitial, get {:?}",
			content
		));
	}

	foreign::verify_slate_messages(&slate, &secp).map_err(|e| format!("Invalid slate, {}", e))?;

	let sender_public_key = sender
		.as_ref()
		.map(ProvableAddress::from_tor_pub_key)
		.transpose()
		.map_err(|e| format!("Sender address error, {}", e))?
		.map(|p| p.public_key);
	let foreign_api = Foreign::new(wallet.clone(), None, None);
	let mut tx_session = TxSession::new();
	let reply_binding = sender
		.as_ref()
		.filter(|_| slatepack_format)
		.map(ReplyBinding::library);
	let receive_result = foreign_api
		.receive_tx(
			&mut tx_session,
			&slate,
			reply_binding,
			sender_public_key,
			None,
			&account,
			message,
			false,
		)
		.map_err(|e| format!("Failed to receive transaction. {}", e))?;
	let slate = receive_result.slate;
	let _processing_guard = receive_result.processing_guard;
	let reply_reservation = receive_result.reply_reservation;
	let receive_data = receive_result.receive_data;
	let slatepack_str = PathToSlatePutter::build_encrypted(
		context_id,
		None,
		SlatePurpose::SendResponse,
		ed25519_dalek::VerifyingKey::from(&slatepack_secret),
		sender,
		slatepack_format,
	)
	.put_tx(
		&slate,
		Some(&slatepack_secret),
		#[cfg(feature = "test-support")]
		false,
		&secp,
	)
	.map_err(|e| format!("Unable encrypt slatepack, {}", e))?;

	// Persist only after response construction succeeds. Saving last is
	// intentional: a reported error must mean no transaction was created
	// (see TxSession::save_tx_data).
	if !tx_session.is_empty() {
		{
			wallet_lock!(wallet, w);
			tx_session
				.save_tx_data(&secp, &mut **w, None, &slate.id)
				.map_err(|e| format!("Failed to save received transaction. {}", e))?;
			}
	}
	if let Some(reservation) = reply_reservation {
		reservation.complete(&slate);
	}
	if let Some(receive_data) = receive_data {
		foreign::dispatch_receive_callback(receive_data);
	}

	Ok((slatepack_str, slate.id))
}
