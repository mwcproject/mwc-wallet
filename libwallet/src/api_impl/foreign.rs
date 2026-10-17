// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

//! Generic implementation of owner API functions

use crate::api_impl::owner::check_ttl;
use crate::internal::selection;
use crate::internal::{tx, updater};
use crate::proof::crypto::Hex;
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProofAddressType;
use crate::proof::proofaddress::ProvableAddress;
use crate::slate_versions::{SlateVersion, validate_slatepack_recipient_version};
use crate::slatepack::{validate_slatepack_receive_direction, validate_slatepack_size};
pub use crate::types::ReceiveData;
use crate::types::{TxSession, U64_DATA_IDX_ADDRESS_INDEX};
use crate::Context;
use crate::{
	BlockFees, CbData, Error, NodeClient, Slate, SlatePurpose, TxLogEntryType, VersionInfo,
	VersionedSlate, WalletBackend,
};
#[cfg(feature = "swaps")]
use crate::{WalletInst, WalletLCProvider};
use mwc_wallet_util::mwc_core::core::amount_to_hr_string;
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::lazy_static::lazy_static;
use mwc_wallet_util::mwc_crates::log::{debug, info};
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::Commitment;
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::Identifier;
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_util::OnionV3Address;
#[cfg(feature = "swaps")]
use mwc_wallet_util::Mutex;
use mwc_wallet_util::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
const FOREIGN_API_VERSION: u16 = 2;
const USER_MESSAGE_MAX_LEN: usize = 256;

lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref RECV_ACCOUNT:   RwLock< HashMap<u32,Identifier>> = RwLock::new(HashMap::new());

	static ref RECEIVE_CALLBACK: RwLock<Option<Arc<dyn Fn(ReceiveData) + Send + Sync>>> =
		RwLock::new(None);
}

/// Clean up context
pub fn foreign_clean_context(context_id: u32) {
	let _ = RECV_ACCOUNT.write().remove(&context_id);
}

/// get current receive account name
pub fn get_receive_account(context_id: u32) -> Option<Identifier> {
	RECV_ACCOUNT.read().get(&context_id).cloned()
}

/// Set receive tx callback. Used in library mode
pub fn set_receive_callback(cb: Box<dyn Fn(ReceiveData) + Send + Sync>) {
	*RECEIVE_CALLBACK.write() = Some(Arc::from(cb));
}

/// Clean the callback
pub fn clean_receive_callback() {
	*RECEIVE_CALLBACK.write() = None;
}

/// Invoke the receive callback without retaining the callback registry lock.
pub fn dispatch_receive_callback(data: ReceiveData) {
	let callback = RECEIVE_CALLBACK.read().clone();
	if let Some(callback) = callback {
		callback(data);
	}
}

/// get tor proof address
pub fn get_proof_address<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
) -> Result<String, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = w.keychain(secp, keychain_mask)?;

	let index: u32 = {
		let mut batch = w.batch(secp, keychain_mask)?;
		let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
		u32::try_from(index).map_err(|e| {
			Error::DataOverflow(format!(
				"foreign::get_proof_address, wallet address index exceeds u32, index={} error={}",
				index, e
			))
		})?
	};

	let provable_address = proofaddress::payment_proof_address(
		secp,
		w.get_context_id(),
		&keychain,
		ProofAddressType::Onion,
		index,
	)
	.map_err(|e| {
		Error::PaymentProofAddress(format!(
			"Error occurred in getting payment proof address, {}",
			e
		))
	})?;
	Ok(provable_address.public_key)
}

///
pub fn set_receive_account(context_id: u32, account_path: Identifier) {
	let _ = RECV_ACCOUNT.write().insert(context_id, account_path);
}

/// Return the version info
pub fn check_version() -> Result<VersionInfo, Error> {
	// Proof address will be the onion address (Dalec Paublic Key). It is exactly what we need
	Ok(VersionInfo {
		foreign_api_version: FOREIGN_API_VERSION,
		supported_slate_versions: SlateVersion::iter().collect(),
	})
}

/// Build a coinbase bound to the supplied candidate digest.
pub fn build_coinbase<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
) -> Result<CbData, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	updater::build_coinbase(
		w,
		secp,
		keychain_mask,
		block_fees,
	)
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate, secp: &Secp256k1) -> Result<(), Error> {
	slate.verify_messages(secp)
}

fn bind_payment_proof_receiver_to_signing_key(
	payment_proof: &mut crate::slate::PaymentInfo,
	signing_key: &SecretKey,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<(), Error> {
	// File proofs use sender == receiver as the legacy on-wire marker. Replace
	// that placeholder before enforcing the normal address/signing-key binding.
	if payment_proof.sender_address.public_key == payment_proof.receiver_address.public_key {
		debug!("file proof, replace the receiver address with the local Onion address");
		let onion_address = OnionV3Address::from_private(&signing_key.0)?;
		payment_proof.receiver_address =
			ProvableAddress::from_str(secp, context_id, &onion_address.to_ov3_str())?;
	}

	tx::validate_payment_proof_receiver_binding(
		&payment_proof.receiver_address,
		signing_key,
		secp,
		context_id,
	)
}

/// Receive a tx as recipient
///
/// Wallet mutations are always staged in `tx_session`. Requiring the session
/// here prevents lower-level callers from selecting the old immediate-commit
/// path before the response Slate has been completed.
/// Note: output_amounts is needed for secure claims, mwc713.
pub fn receive_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut TxSession,
	slate: &Slate,
	address: Option<String>,
	authenticated_sender: Option<PublicKey>,
	output_amounts: Option<Vec<u64>>,
	dest_acct_name: &Option<String>,
	message: Option<String>,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	refresh_from_node: bool,
) -> Result<(Slate, Context, ReceiveData), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// This lower-level function is public and has direct callers. Keep the
	// transaction validation invariant here as well, before cloning the slate or
	// performing any wallet, commitment, or signing work.
	slate.validate_transaction_read(w.get_context_id())?;

	let display_from = address.clone().unwrap_or("http listener".to_string());
	let slate_message: &Option<String> = &slate
		.participant_data
		.first()
		.ok_or_else(|| {
			Error::SlateValidation(format!(
				"foreign::receive_tx, slate has no participant data, participant_count={}",
				slate.participant_data.len()
			))
		})?
		.message;
	let address_for_logging = address.clone().unwrap_or("http".to_string());

	// The shared transaction helpers still support the established invoice
	// path where no session is supplied. Adapt the mandatory receive session
	// once at this boundary; `receive_tx` itself can no longer commit early.
	let mut tx_session = Some(tx_session);
	let mut ret_slate = slate.clone();
	// The receive slate is counterparty-controlled. Require the two-party
	// initial set this wallet implements before any key allocation or
	// signing: excess or duplicate participant records would enter the
	// aggregate nonce and blind sums used for the receiver's partial
	// signature.
	ret_slate.validate_send_initial()?;
	// Authenticate participant messages before allocating keys, signing or
	// staging wallet changes, even when the transport authenticated the sender.
	ret_slate.verify_messages(secp)?;
	check_ttl(w, &ret_slate, refresh_from_node)?;

	let payment_proof_signing_key = if let Some(payment_proof) = &mut ret_slate.payment_proof {
		let context_id = w.get_context_id();
		let sender_key = payment_proof
			.sender_address
			.validate_mqs(secp, context_id)
			.map_err(|e| {
				Error::PaymentProof(format!("Invalid payment-proof sender address, {}", e))
			})?;
		// The receiver signature attributes this transaction to sender_address.
		// A syntactically valid address is not proof that the peer controls it.
		// When the transport authenticated the sender (MQS), the slate's claimed
		// payment-proof sender must be that identity; otherwise an authenticated
		// sender could name an arbitrary third party and obtain this wallet's
		// signature attributing the payment to them.
		//
		// When the transport does not authenticate the sender (plain JSON-RPC,
		// slate files), the proof is still signed on request. This is intended
		// behavior: payment proofs must remain generatable over these channels,
		// and the wallet operator is expected to review the slate details —
		// sender address, recipient address and amount — before submitting or
		// accepting it, exactly as they review any other transaction detail.
		if let Some(authenticated_sender) = authenticated_sender {
			if sender_key != authenticated_sender {
				return Err(Error::PaymentProof(
					"Payment-proof sender address does not match the authenticated sender"
						.to_owned(),
				));
			}
		}
		ProvableAddress::from_str(secp, context_id, &payment_proof.receiver_address.public_key)
			.map_err(|e| {
				Error::PaymentProof(format!("Invalid payment-proof receiver address, {}", e))
			})?;

		let address_index: u32 = {
			let mut batch = w.batch(secp, keychain_mask)?;
			let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
			u32::try_from(index).map_err(|e| {
				Error::DataOverflow(format!(
					"foreign::receive_tx, wallet address index exceeds u32, index={} error={}",
					index, e
				))
			})?
		};
		let keychain = w.keychain(secp, keychain_mask)?;
		let signing_key =
			proofaddress::payment_proof_address_secret(secp, context_id, &keychain, address_index)?;
		bind_payment_proof_receiver_to_signing_key(payment_proof, &signing_key, secp, context_id)?;
		Some(signing_key)
	} else {
		None
	};

	let mut parent_key_id = get_receive_account(w.get_context_id()).unwrap_or(w.parent_key_id());
	if let Some(dest_acct_name) = dest_acct_name {
		// An explicitly named destination account must exist. Silently falling
		// back to the receive account would post the transaction to an
		// unintended account (e.g. a misspelled self-send --dest).
		match w.get_acct_path(dest_acct_name.clone())? {
			Some(path) => parent_key_id = path.path,
			None => return Err(Error::UnknownAccountLabel(dest_acct_name.clone())),
		}
	}

	// Reject a repeated receive across the whole wallet. A slate UUID is not
	// namespaced by account.
	let existing_txs = w.tx_log_iter()?.chain(w.tx_log_archive_iter()?);
	for t in existing_txs.filter(|tx| tx.tx_slate_id == Some(ret_slate.id)) {
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(Error::TransactionAlreadyReceived(ret_slate.id.to_string()));
		}

		// Keep offset reuse account-local: a cross-account self-send has a
		// legitimate TxSent record with the same slate UUID and offset.
		if t.parent_key_id != parent_key_id {
			continue;
		}

		if let Some(offset) = t.kernel_offset {
			let slate_offset = slate.tx_or_err()?.offset.clone();
			if slate_offset.is_zero() {
				return Err(Error::SlateValidation(format!(
					"Transaction {} has a zero offset but a stored kernel offset exists",
					ret_slate.id
				)));
			}

			let offset_skey = slate_offset.secret_key(&secp)?;
			let offset_pubkey = PublicKey::from_secret_key(&secp, &offset_skey)?;
			let offset_commit = Commitment::from_pubkey(&secp, &offset_pubkey)?;
			if offset == offset_commit {
				return Err(Error::TransactionWithSameOffsetAlreadyReceived(
					offset_commit.to_hex(secp)?,
				));
			}
		}
	}

	let message = match message {
		Some(mut m) => {
			crate::types::truncate_to_char_boundary(&mut m, USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let num_outputs = match &output_amounts {
		Some(v) => v.len(),
		None => 1,
	};

	// The receiver output is tagged with the wallet's last confirmed height for
	// replay detection. This must stay a local read: receive_tx also runs inside
	// the wallet proxy message handler, where a node call would deadlock. A fresh
	// wallet (including one upgraded from the former account-scoped key prefix)
	// therefore reports 0 until its next successful scan.
	let height = w.last_confirmed_height()?;

	// Note: output_amounts is needed for secure claims, mwc713.
	let mut context = tx::add_output_to_slate(
		&mut *w,
		secp,
		keychain_mask,
		&mut tx_session,
		&mut ret_slate,
		height,
		Some(address_for_logging),
		output_amounts,
		&parent_key_id,
		1,
		message,
		false,
		#[cfg(feature = "test-support")]
		use_test_rng,
		num_outputs,
	)?;

	let keychain = w.keychain(secp, keychain_mask)?;

	if slate.compact_slate {
		// Add our contribution to the offset
		ret_slate.adjust_offset(&secp, &keychain, &mut context)?;
	}

	tx::update_message(&mut *w, secp, keychain_mask, &mut tx_session, &ret_slate)?;

	let excess = ret_slate.calc_excess(&secp)?;

	if let Some(ref mut p) = ret_slate.payment_proof {
		let signing_key = payment_proof_signing_key.ok_or_else(|| {
			Error::PaymentProof("Payment-proof signing key is unavailable".to_owned())
		})?;
		let sig = tx::create_payment_proof_signature(
			ret_slate.amount,
			&excess,
			p.sender_address.clone(),
			p.receiver_address.clone(),
			signing_key,
			secp,
			w.get_context_id(),
		)?;

		p.receiver_signature = Some(sig);
	}

	// that means it's not mqs so need to print it. The message comes from an
	// untrusted slate, so escape control characters before writing it to the
	// terminal or the log.
	match slate_message {
		Some(slate_message) => {
			let slate_message = crate::types::escape_for_display(slate_message);
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false),
					slate_message
				);
			} else {
				info!(
					"slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false),
					slate_message
				);
			}
		}
		None => {
			if mwc_wallet_util::mwc_util::is_console_output_enabled() {
				println!(
					"slate [{}] received from [{}] for [{}] MWCs.",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false)
				);
			} else {
				info!(
					"slate [{}] received from [{}] for [{}] MWCs.",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false)
				);
			}
		}
	}

	let receive_data = ReceiveData {
		context_id: w.get_context_id(),
		tx_uuid: slate.id.to_string(),
		from: display_from,
		amount: slate.amount,
		message: slate_message.clone(),
	};

	Ok((ret_slate, context, receive_data))
}

fn map_invoice_context_load_error(slate_id: &Uuid, error: Error) -> Error {
	match error {
		Error::PrivateContextNotFound(_) => {
			Error::TransactionWasFinalizedOrCancelled(slate_id.to_string())
		}
		error => error,
	}
}

/// Finalize an invoice transaction issued by this wallet.
///
/// A supplied session owns its ephemeral context and the caller commits the
/// staged result. Without a session, finalization updates durable wallet state
/// directly and removes the no-longer-needed private context.
pub fn finalize_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	refresh_from_node: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	finalize_invoice_tx_with_output_version(
		w,
		secp,
		keychain_mask,
		tx_session,
		slate,
		refresh_from_node,
		#[cfg(feature = "test-support")]
		use_test_rng,
		None,
	)
}

/// Finalize an invoice for a known response format. Check the rebuilt SP size
/// before binding the signing nonce or committing finalized wallet state.
/// None leaves the output format to the caller of the unversioned API.
pub fn finalize_invoice_tx_with_output_version<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	tx_session: &mut Option<&mut TxSession>,
	slate: &Slate,
	refresh_from_node: bool,
	#[cfg(feature = "test-support")] use_test_rng: bool,
	output_version: Option<SlateVersion>,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	// Participant id 0 for mwc713 compatibility
	let mut context = match tx_session {
		Some(tx) => {
			let (context, participant_id) = tx
				.get_context_participant()
				.as_ref()
				.ok_or_else(|| Error::TransactionWasFinalizedOrCancelled(sl.id.to_string()))?;
			if *participant_id != 0 {
				return Err(Error::SlateValidation(format!(
					"invoice transaction session participant mismatch, expected=0 actual={}",
					participant_id
				)));
			}

			let session_slate_id = tx
				.get_tx_log_entry()
				.as_ref()
				.and_then(|entry| entry.tx_slate_id.as_ref())
				.ok_or_else(|| {
					Error::SlateValidation(
						"invoice transaction session is missing its slate id".to_owned(),
					)
				})?;
			if session_slate_id != &sl.id {
				return Err(Error::SlateValidation(format!(
					"invoice response slate id does not match transaction session, expected={} actual={}",
					session_slate_id, sl.id
				)));
			}

			context.clone()
		}
		None => w
			.get_private_context(secp, keychain_mask, sl.id.as_bytes(), 0)
			.map_err(|error| map_invoice_context_load_error(&sl.id, error))?,
	};

	// The response slate is counterparty-controlled. Before any signature
	// work, bind the immutable invoice metadata fixed at issuance (the kernel
	// policy we are about to sign under) and enforce the two-party
	// participant invariants against the persisted issuer context.
	// Participant ids and num_participants are not covered by partial
	// signatures, so without these checks a relabeled payer record would be
	// signed and stored as a transcript outside the implemented two-party
	// protocol. Inputs, outputs, fee and kernels are intentionally not
	// compared: unlike the send flow (Context::validate_slate), for an
	// invoice the payer legitimately adds them.
	context.validate_invoice_slate(&sl)?;
	sl.validate_invoice_response_context(secp, &context)?;
	// Do not perform the node request until this response has been bound to a
	// locally stored invoice context and its participant data has been verified.
	check_ttl(w, &sl, refresh_from_node)?;

	let mut slate_message = String::new();
	for participant_data in &slate.participant_data {
		if let Some(msg2) = &participant_data.message {
			if !slate_message.is_empty() {
				slate_message.push_str(", ");
			}
			slate_message.push_str(msg2);
		}
	}

	// Participant messages are signed but still counterparty-controlled. Escape
	// the combined value before sending it to either output sink.
	if !slate_message.is_empty() {
		let slate_message = crate::types::escape_for_display(&slate_message);
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"Get invoice slate [{}] to finalize for [{}] MWCs. Message: [\"{}\"], processing...",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false),
				slate_message
			);
		} else {
			info!(
				"Get invoice slate [{}] to finalize for [{}] MWCs. Message: [\"{}\"], processing...",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false),
				slate_message
			);
		}
	} else {
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"Get invoice finalize slate [{}] for [{}] MWCs, processing...",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false)
			);
		} else {
			info!(
				"Get invoice finalize slate [{}] for [{}] MWCs, processing...",
				slate.id.to_string(),
				amount_to_hr_string(slate.amount, false)
			);
		}
	}

	debug!(
		"foreign just finalize_invoice_tx just got slate = {:?}",
		slate
	);

	if slate.compact_slate {
		// Add our contribution to the offset
		sl.adjust_offset(secp, &w.keychain(secp, keychain_mask)?, &context)?;

		// Slate can  be 'compact'  - it is mean some of the data can be gone
		let mut temp_ctx = context.clone();
		temp_ctx.sec_key = context.initial_sec_key.clone();
		temp_ctx.sec_nonce = context.initial_sec_nonce.clone();
		selection::repopulate_tx(
			&mut *w,
			secp,
			keychain_mask,
			tx_session,
			&mut sl,
			&temp_ctx,
			false,
			None,
			#[cfg(feature = "test-support")]
			use_test_rng,
		)?;
	}

	// InvoiceResponse omits the issuer output and participant record. Budget
	// the restored FullSlate before signing or consuming the invoice context,
	// so an oversized response leaves both durable and staged invoices retryable.
	validate_slatepack_size(&sl, output_version.as_ref(), 0, 0)?;

	// The compact body and local participant have now been restored.
	if refresh_from_node {
		crate::transaction_preflight::check_slate(
			w.get_context_id(),
			w.w2n_client(),
			&sl,
			secp,
			true,
		)?;
	}

	// Participant id 0 for mwc713 compatibility.
	tx::complete_tx(
		&mut *w,
		secp,
		keychain_mask,
		tx_session,
		&mut sl,
		0,
		&mut context,
	)?;
	tx::update_stored_tx(
		&mut *w,
		secp,
		keychain_mask,
		tx_session,
		&mut sl,
		true,
	)?;
	tx::update_message(&mut *w, secp, keychain_mask, tx_session, &sl)?;
	match tx_session {
		Some(tx) => tx.clear_context_participant(),
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;
			// Participant id 0 is used for mwc713 compatibility.
			batch.delete_private_context(sl.id.as_bytes(), 0)?;
			batch.commit()?;
		}
	}

	if mwc_wallet_util::mwc_util::is_console_output_enabled() {
		println!(
			"Invoice slate [{}] for [{}] MWCs was processed and sent back for posting.",
			slate.id.to_string(),
			amount_to_hr_string(slate.amount, false)
		);
	} else {
		info!(
			"Invoice slate [{}] for [{}] MWCs was processed and sent back for posting.",
			slate.id.to_string(),
			amount_to_hr_string(slate.amount, false)
		);
	}

	Ok(sl)
}

/// Process the incoming swap message received from TOR
#[cfg(feature = "swaps")]
pub fn receive_swap_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	message: &String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parsed_message = crate::swap::message::Message::from_json(message)?;
	if matches!(
		parsed_message.inner,
		crate::swap::message::Update::MessageAcknowledge(_)
	) {
		return Err(crate::swap::Error::InvalidMessageData(
			"Swap acknowledgements require an authenticated asynchronous transport".to_string(),
		)
		.into());
	}
	// HTTP/Tor does not authenticate the sender. The shared receive path enforces
	// an existing trade's MQS identity while holding its trade lock, before replay
	// acknowledgements or state-machine processing.
	crate::swap::owner_swap::swap_income_message(wallet_inst, secp, keychain_mask, message, None)?;
	Ok(())
}

/// Process swap marketplace message. Please note. Wallet does a minor role here,
/// The marketplace workflow and managed by QT wallet.
#[cfg(feature = "swaps")]
pub fn marketplace_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	secp: &mut Secp256k1,
	keychain_mask: Option<&SecretKey>,
	message: &String,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let response =
		crate::swap::owner_swap::marketplace_message(wallet_inst, secp, keychain_mask, &message)?;
	Ok(response)
}

/// Utility method to decrypt the slate pack for receive operation.
/// Returns: slate, content, sender PK, recipient Pk
///
/// When `require_local_recipient` is set, an encrypted slatepack must name
/// this wallet as its recipient. Inbound receive paths (e.g. the foreign
/// API) require this so that a reflected or misdirected request is rejected.
/// Owner-side flows pass `false`: they legitimately process slatepacks this
/// wallet sent, such as `tx_lock_outputs` on its own outgoing slatepack or
/// paying its own invoice request, where the wallet is the sender rather
/// than the recipient.
pub fn decrypt_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	encrypted_slate: VersionedSlate,
	address_index: Option<u32>,
	require_local_recipient: bool,
) -> Result<
	(
		Slate,
		SlatePurpose,
		Option<ed25519_dalek::VerifyingKey>,
		Option<ed25519_dalek::VerifyingKey>,
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = w.keychain(secp, keychain_mask)?;

	let address_index: u32 = match address_index {
		Some(n) => n,
		None => {
			let mut batch = w.batch(secp, keychain_mask)?;
			let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
			u32::try_from(index).map_err(|e| {
				Error::DataOverflow(format!(
					"foreign::decrypt_slate, wallet address index exceeds u32, index={} error={}",
					index, e
				))
			})?
		}
	};

	let sec_key = proofaddress::payment_proof_address_dalek_secret(
		secp,
		w.get_context_id(),
		&keychain,
		address_index,
	)
	.map_err(|e| Error::SlatepackDecodeError(format!("Unable to build key to decrypt, {}", e)))?;
	let sp = encrypted_slate.into_slatepack(w.get_context_id(), &sec_key, secp)?;
	let sender = sp.get_sender();
	let recipient = sp.get_recipient();
	if require_local_recipient {
		validate_slatepack_receive_direction(
			sender.as_ref(),
			recipient.as_ref(),
			&sec_key.verifying_key(),
		)?;
	}
	let content = sp.get_content();
	let slate = sp.to_result_slate();
	Ok((slate, content, sender, recipient))
}

/// Utility method to conver Slate into the Versioned Slate.
pub fn encrypt_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	secp: &Secp256k1,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	version: Option<SlateVersion>,
	content: SlatePurpose,
	slatepack_recipient: Option<ed25519_dalek::VerifyingKey>,
	address_index: Option<u32>,
	#[cfg(feature = "test-support")] use_test_rng: bool,
) -> Result<VersionedSlate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if let Some(version) = version.as_ref() {
		validate_slatepack_recipient_version(version, slatepack_recipient.is_some())?;
	}
	let slatepack_format = slatepack_recipient.is_some() || version == Some(SlateVersion::SP);

	if slatepack_format {
		let address_index: u32 = match address_index {
			Some(n) => n,
			None => {
				let mut batch = w.batch(secp, keychain_mask)?;
				let index = batch.load_u64(U64_DATA_IDX_ADDRESS_INDEX, 0u64)?;
				u32::try_from(index).map_err(|e| {
					Error::DataOverflow(format!(
						"foreign::encrypt_slate, wallet address index exceeds u32, index={} error={}",
						index, e
					))
				})?
			}
		};

		// Can be not encrypted slate binary if slatepack_recipient is_none
		let (slatepack_secret, slatepack_pk) = {
			let keychain = w.keychain(secp, keychain_mask)?;
			let slatepack_secret = proofaddress::payment_proof_address_dalek_secret(
				secp,
				w.get_context_id(),
				&keychain,
				address_index,
			)?;
			let slatepack_pk = slatepack_secret.verifying_key();
			(slatepack_secret, slatepack_pk)
		};

		Ok(VersionedSlate::into_version(
			w.get_context_id(),
			slate.clone(),
			version.unwrap_or(SlateVersion::SP),
			content,
			slatepack_pk,
			slatepack_recipient,
			&slatepack_secret,
			#[cfg(feature = "test-support")]
			use_test_rng,
			secp,
		)?)
	} else {
		// Plain slate format
		let version = version.unwrap_or(slate.lowest_version());
		Ok(
			VersionedSlate::into_version_plain(w.get_context_id(), slate, version).map_err(
				|e| Error::SlatepackEncodeError(format!("Unable to build a slate, {}", e)),
			)?,
		)
	}
}

#[cfg(test)]
mod tests {
	use super::{
		ReceiveData, bind_payment_proof_receiver_to_signing_key, clean_receive_callback,
		dispatch_receive_callback, map_invoice_context_load_error, set_receive_callback,
	};
	use crate::proof::proofaddress::ProvableAddress;
	use crate::slate::PaymentInfo;
	use crate::Error;
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_crates::secp::Secp256k1;
	use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_wallet_util::mwc_crates::uuid::Uuid;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	#[test]
	fn receive_callback_can_replace_registry_without_deadlock() {
		clean_receive_callback();
		let calls = Arc::new(AtomicUsize::new(0));
		let callback_calls = calls.clone();
		set_receive_callback(Box::new(move |_| {
			callback_calls.fetch_add(1, Ordering::SeqCst);
			clean_receive_callback();
		}));

		let receive_data = ReceiveData {
			context_id: 0,
			tx_uuid: "slate-id".to_string(),
			from: "sender".to_string(),
			amount: 1,
			message: None,
		};
		dispatch_receive_callback(receive_data.clone());
		dispatch_receive_callback(receive_data);

		assert_eq!(calls.load(Ordering::SeqCst), 1);
		clean_receive_callback();
	}

	#[test]
	fn invoice_context_load_only_translates_not_found() {
		let slate_id = Uuid::new_v4();
		assert!(matches!(
			map_invoice_context_load_error(
				&slate_id,
				Error::PrivateContextNotFound("missing".to_owned()),
			),
			Error::TransactionWasFinalizedOrCancelled(id) if id == slate_id.to_string()
		));
		assert!(matches!(
			map_invoice_context_load_error(
				&slate_id,
				Error::Backend("database failure".to_owned()),
			),
			Error::Backend(message) if message == "database failure"
		));
	}

	#[test]
	fn file_payment_proof_rewrites_receiver_before_key_binding() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let secp = Secp256k1::new().unwrap();
		let sender_secret = SecretKey::from_slice(&secp, &[1_u8; 32]).unwrap();
		let receiver_secret = SecretKey::from_slice(&secp, &[2_u8; 32]).unwrap();
		let sender_public = PublicKey::from_secret_key(&secp, &sender_secret).unwrap();
		let sender_address = ProvableAddress::from_pub_key(&secp, 0, &sender_public).unwrap();
		let mut payment_proof = PaymentInfo {
			sender_address: sender_address.clone(),
			receiver_address: sender_address.clone(),
			receiver_signature: None,
		};

		bind_payment_proof_receiver_to_signing_key(&mut payment_proof, &receiver_secret, &secp, 0)
			.unwrap();

		let expected_receiver = ProvableAddress::from_tor_pub_key(
			&mwc_wallet_util::mwc_crates::ed25519_dalek::SigningKey::from_bytes(&receiver_secret.0)
				.verifying_key(),
		)
		.unwrap();
		assert_eq!(
			payment_proof.sender_address.public_key,
			sender_address.public_key
		);
		assert_eq!(
			payment_proof.receiver_address.public_key,
			expected_receiver.public_key
		);
		assert!(payment_proof.receiver_signature.is_none());
	}
}
