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

//! Transaction building functions

use uuid::Uuid;

use crate::internal::{selection, updater};
use crate::mwc_core::consensus::valid_header_version;
use crate::mwc_core::core::HeaderVersion;
use crate::mwc_keychain::{Identifier, Keychain};
use crate::mwc_util as util;
use crate::mwc_util::secp::key::SecretKey;
use crate::mwc_util::secp::{pedersen, Signature};
use crate::mwc_util::Mutex;
use crate::proof::crypto;
use crate::proof::crypto::Hex;
use crate::proof::proofaddress;
use crate::proof::proofaddress::{get_address_index, ProvableAddress};
use crate::proof::tx_proof::{push_proof_for_slate, TxProof};
use crate::slate::Slate;
use crate::types::{Context, NodeClient, StoredProofInfo, TxLogEntryType, WalletBackend};
use crate::Error;
use crate::InitTxArgs;
use ed25519_dalek::Keypair as DalekKeypair;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Signer, Verifier};
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use mwc_wallet_util::OnionV3Address;
use std::convert::TryFrom;

// static for incrementing test UUIDs
lazy_static! {
	static ref SLATE_COUNTER: Mutex<u8> = Mutex::new(0);
}

/// Creates a new slate for a transaction, can be called by anyone involved in
/// the transaction (sender(s), receiver(s))
pub fn new_tx_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	num_participants: usize,
	use_test_rng: bool,
	ttl_blocks: Option<u64>,
	compact_slate: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;
	let mut slate = Slate::blank(num_participants, compact_slate);
	if let Some(b) = ttl_blocks {
		slate.ttl_cutoff_height = Some(current_height + b);
	}
	if use_test_rng {
		{
			let sc = SLATE_COUNTER.lock();
			let bytes = [4, 54, 67, 12, 43, 2, 98, 76, 32, 50, 87, 5, 1, 33, 43, *sc];
			slate.id = Uuid::from_slice(&bytes).unwrap();
		}
		*SLATE_COUNTER.lock() += 1;
	}
	slate.amount = amount;
	slate.height = current_height;

	if valid_header_version(current_height, HeaderVersion(1)) {
		slate.version_info.block_header_version = 1;
	}

	if valid_header_version(current_height, HeaderVersion(2)) {
		slate.version_info.block_header_version = 2;
	}

	if valid_header_version(current_height, HeaderVersion(3)) {
		slate.version_info.block_header_version = 3;
	}

	// Set the lock_height explicitly to 0 here.
	// Set the features explicitly to 0 here.
	// This will generate a Plain kernel (rather than a HeightLocked kernel).
	slate.reset_lock_height();

	Ok(slate)
}

/// Estimates locked amount and fee for the transaction without creating one
/// Caller is responsible for data refresh!!!!
pub fn estimate_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	amount_includes_fee: bool,
	min_fee: &Option<u64>,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	outputs: &Option<Vec<String>>, // outputs to include into the transaction
	routputs: usize,               // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
) -> Result<
	(
		u64, // total
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Get lock height
	let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;
	// ensure outputs we're selecting are up to date

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let (_coins, total, _amount, fee) = selection::select_coins_and_fee(
		wallet,
		amount,
		amount_includes_fee,
		min_fee,
		current_height,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		parent_key_id,
		outputs,
		routputs,
		exclude_change_outputs,
		change_output_minimum_confirmations,
	)?;
	Ok((total, fee))
}

/// Add inputs to the slate (effectively becoming the sender)
/// Caller is responsible for wallet refresh
pub fn add_inputs_to_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	min_fee: &Option<u64>,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	participant_id: usize,
	message: Option<String>,
	is_initator: bool,
	use_test_rng: bool,
	outputs: &Option<Vec<String>>, // outputs to include into the transaction
	routputs: usize,               // Number of resulting outputs. Normally it is 1
	exclude_change_outputs: bool,
	change_output_minimum_confirmations: u64,
	amount_includes_fee: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(keychain_mask)?;

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let mut context = selection::build_send_tx(
		wallet,
		&keychain,
		keychain_mask,
		slate,
		min_fee,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		parent_key_id.clone(),
		participant_id,
		use_test_rng,
		is_initator,
		outputs,  // outputs to include into the transaction
		routputs, // Number of resulting outputs. Normally it is 1
		exclude_change_outputs,
		change_output_minimum_confirmations,
		message.clone(),
		amount_includes_fee,
	)?;

	// Generate a kernel offset and subtract from our context's secret key. Store
	// the offset in the slate's transaction kernel, and adds our public key
	// information to the slate
	slate.fill_round_1(
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		message,
		use_test_rng,
	)?;

	context.initial_sec_key = context.sec_key.clone();

	if !is_initator {
		// perform partial sig
		slate.fill_round_2(
			keychain.secp(),
			&context.sec_key,
			&context.sec_nonce,
			participant_id,
		)?;
	}

	Ok(context)
}

/// Add receiver output to the slate
/// Note: key_id & output_amounts needed for secure claims, mwc713.
pub fn add_output_to_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	address: Option<String>,
	key_id_opt: Option<&str>,
	output_amounts: Option<Vec<u64>>,
	parent_key_id: &Identifier,
	participant_id: usize,
	message: Option<String>,
	is_initiator: bool,
	use_test_rng: bool,
	num_outputs: usize, // Number of outputs for this transaction. Normally it is 1
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(keychain_mask)?;

	// create an output using the amount in the slate
	let (_, mut context, mut tx) = selection::build_recipient_output(
		wallet,
		keychain_mask,
		slate,
		current_height,
		address,
		parent_key_id.clone(),
		participant_id,
		key_id_opt,
		output_amounts,
		use_test_rng,
		is_initiator,
		num_outputs, // Number of outputs for this transaction. Normally it is 1
		message.clone(),
	)?;

	// fill public keys
	slate.fill_round_1(
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		message,
		use_test_rng,
	)?;

	context.initial_sec_key = context.sec_key.clone();

	if !is_initiator {
		// perform partial sig
		slate.fill_round_2(
			keychain.secp(),
			&context.sec_key,
			&context.sec_nonce,
			participant_id,
		)?;

		// update excess in stored transaction
		let mut batch = wallet.batch(keychain_mask)?;
		tx.kernel_excess =
			Some(slate.calc_excess(keychain.secp(), Some(&keychain), current_height)?);
		batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
		batch.commit()?;
	}

	Ok(context)
}

/// Create context, without adding inputs to slate
pub fn create_late_lock_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	init_tx_args: &InitTxArgs,
	parent_key_id: &Identifier,
	use_test_rng: bool,
	participant_id: usize,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Expected to work for compact slate model only
	debug_assert!(slate.compact_slate);

	// we're just going to run a selection to get the potential fee,
	// but this won't be locked
	let (_coins, _total, _amount, fee) = selection::select_coins_and_fee(
		wallet,
		init_tx_args.amount,
		init_tx_args.amount_includes_fee.unwrap_or(false),
		&init_tx_args.min_fee,
		current_height,
		init_tx_args.minimum_confirmations,
		init_tx_args.max_outputs as usize,
		init_tx_args.num_change_outputs as usize,
		init_tx_args.selection_strategy_is_use_all,
		&parent_key_id,
		&init_tx_args.outputs,
		1,
		init_tx_args.exclude_change_outputs.clone().unwrap_or(false),
		init_tx_args.minimum_confirmations_change_outputs,
	)?;

	slate.fee = fee;

	let keychain = wallet.keychain(keychain_mask)?;

	// Create our own private context
	let mut context = Context::new(
		keychain.secp(),
		&parent_key_id,
		use_test_rng,
		true,
		participant_id,
		slate.amount,
		slate.fee,
		init_tx_args.message.clone(),
	);
	context.late_lock_args = Some(init_tx_args.clone());

	// Generate a blinding factor for the tx and add
	//  public key info to the slate
	slate.fill_round_1(
		&keychain,
		&mut context.sec_key,
		&context.sec_nonce,
		participant_id,
		init_tx_args.message.clone(),
		use_test_rng,
	)?;

	Ok(context)
}

/// Complete a transaction
pub fn complete_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	participant_id: usize,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// when self sending invoice tx, use initiator nonce to finalize
	let (sec_key, sec_nonce) = if slate.compact_slate {
		{
			if context.initial_sec_key != context.sec_key
				&& context.initial_sec_nonce != context.sec_nonce
			{
				(&context.initial_sec_key, &context.initial_sec_nonce)
			} else {
				(&context.sec_key, &context.sec_nonce)
			}
		}
	} else {
		// Legacy - just use context.sec_key & context.sec_nonce,
		(&context.sec_key, &context.sec_nonce)
	};

	let keychain = wallet.keychain(keychain_mask)?;
	slate.fill_round_2(keychain.secp(), sec_key, sec_nonce, participant_id)?;

	let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;

	// Final transaction can be built by anyone at this stage
	trace!("Slate to finalize is: {:?}", slate);
	slate.finalize(&keychain, current_height)?;
	Ok(())
}

/// Rollback outputs associated with a transaction in the wallet
pub fn cancel_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx_id_string = if let Some(tx_id) = tx_id {
		tx_id.to_string()
	} else if let Some(tx_slate_id) = tx_slate_id {
		tx_slate_id.to_string()
	} else {
		return Err(Error::TransactionCancellationError(
			"Transaction is not defined. Please specify tx_id or tx_slate_id fields.",
		));
	};

	let tx_vec = updater::retrieve_txs(
		wallet,
		keychain_mask,
		tx_id,
		tx_slate_id,
		None,
		Some(&parent_key_id),
		false,
		None,
		None,
		None,
	)?;
	if tx_vec.is_empty() {
		return Err(Error::TransactionDoesntExist(tx_id_string));
	}
	// there are can be several transactions with a same txid (send file to self).
	// In such case we need to cancel all of them
	for tx in tx_vec {
		match tx.tx_type {
			TxLogEntryType::TxSent | TxLogEntryType::TxReceived | TxLogEntryType::TxReverted => {}
			_ => return Err(Error::TransactionNotCancellable(tx_id_string)),
		}
		if tx.confirmed {
			return Err(Error::TransactionNotCancellable(tx_id_string));
		}
		// get outputs associated with tx
		let res = updater::retrieve_outputs(
			wallet,
			keychain_mask,
			false,
			Some(&tx),
			&parent_key_id,
			None,
			None,
		)?;
		let outputs = res.iter().map(|m| m.output.clone()).collect();
		updater::cancel_tx_and_outputs(wallet, keychain_mask, tx, outputs, parent_key_id)?;
	}
	Ok(())
}

/// Update the stored transaction (this update needs to happen when the TX is finalized)
pub fn update_stored_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
	is_invoiced: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// finalize command
	let tx_vec = updater::retrieve_txs(
		wallet,
		keychain_mask,
		None,
		Some(slate.id),
		None,
		None,
		false,
		None,
		None,
		None,
	)?;
	let mut tx = None;
	// don't want to assume this is the right tx, in case of self-sending
	for t in tx_vec {
		if t.tx_type == TxLogEntryType::TxSent && !is_invoiced {
			tx = Some(t);
			break;
		}
		if t.tx_type == TxLogEntryType::TxReceived && is_invoiced {
			tx = Some(t);
			break;
		}
	}
	let mut tx = match tx {
		Some(t) => t,
		None => return Err(Error::TransactionDoesntExist(slate.id.to_string())),
	};

	if tx.tx_slate_id.is_none() {
		return Err(Error::GenericError(
			"Transaction doesn't have stored tx slate id".to_string(),
		));
	}

	wallet.store_tx(&format!("{}", tx.tx_slate_id.unwrap()), slate.tx_or_err()?)?;
	let parent_key = tx.parent_key_id.clone();

	let keychain = wallet.keychain(keychain_mask)?;

	let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;

	if slate.compact_slate {
		tx.kernel_excess =
			Some(slate.calc_excess(keychain.secp(), Some(&keychain), current_height)?);
	} else {
		tx.kernel_excess = Some(slate.tx_or_err()?.body.kernels[0].excess);
	}

	if let Some(ref p) = slate.clone().payment_proof {
		let derivation_index = match context.payment_proof_derivation_index {
			Some(i) => i,
			None => get_address_index(),
		};
		let excess = slate.calc_excess(keychain.secp(), Some(&keychain), current_height)?;
		//sender address.
		let sender_address_secret_key =
			proofaddress::payment_proof_address_secret(&keychain, Some(derivation_index))?;
		// MQS because normal public key is needed
		let sender_a = proofaddress::payment_proof_address_from_index(
			&keychain,
			derivation_index,
			proofaddress::ProofAddressType::MQS,
		)?;

		let sig = create_payment_proof_signature(
			slate.amount,
			&excess,
			p.sender_address.clone(),
			p.receiver_address.clone(),
			sender_address_secret_key,
			keychain.secp(),
		)?;
		tx.payment_proof = Some(StoredProofInfo {
			receiver_address: p.receiver_address.clone(),
			receiver_signature: p.receiver_signature.clone(),
			sender_address_path: derivation_index,
			sender_address: sender_a,
			sender_signature: Some(sig),
		})
	}

	wallet.store_tx(&format!("{}", slate.id), slate.tx_or_err()?)?;

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_tx_log_entry(tx, &parent_key)?;
	batch.commit()?;
	Ok(())
}

/// Update the transaction participant messages
pub fn update_message<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx_vec = updater::retrieve_txs(
		wallet,
		keychain_mask,
		None,
		Some(slate.id),
		None,
		None,
		false,
		None,
		None,
		None,
	)?;
	if tx_vec.is_empty() {
		return Err(Error::TransactionDoesntExist(slate.id.to_string()));
	}
	let mut batch = wallet.batch(keychain_mask)?;
	for mut tx in tx_vec.into_iter() {
		tx.messages = Some(slate.participant_messages());
		let parent_key = tx.parent_key_id.clone();
		batch.save_tx_log_entry(tx, &parent_key)?;
	}
	batch.commit()?;
	Ok(())
}

/// Generate proof record
pub fn payment_proof_message(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address_publickey: String,
) -> Result<String, Error> {
	let mut message = String::new();
	debug!("the kernel excess is {:?}", kernel_commitment.0.to_vec());
	debug!("the sender public key is {}", &sender_address_publickey);
	message.push_str(&util::to_hex(&kernel_commitment.0));
	message.push_str(&sender_address_publickey);
	message.push_str(&amount.to_string());
	Ok(message)
}

/// decode proof message
//pub fn _decode_payment_proof_message(
//	msg: &[u8],
//) -> Result<(u64, pedersen::Commitment, DalekPublicKey), Error> {
//	let mut rdr = Cursor::new(msg);
//	let amount = rdr.read_u64::<BigEndian>()?;
//	let mut commit_bytes = [0u8; 33];
//	for i in 0..33 {
//		commit_bytes[i] = rdr.read_u8()?;
//	}
//	let mut sender_address_bytes = [0u8; 32];
//	for i in 0..32 {
//		sender_address_bytes[i] = rdr.read_u8()?;
//	}
//
//	Ok((
//		amount,
//		pedersen::Commitment::from_vec(commit_bytes.to_vec()),
//		DalekPublicKey::from_bytes(&sender_address_bytes)
//			.map_err(|e| Error::Signature(format!("Failed to build public key, {}", e)))?,
//	))
//}

/// create a payment proof
/// To make it compatible with mwc713, here we are using the implementation of wallet713.
pub fn create_payment_proof_signature(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address: ProvableAddress,
	receiver_address: ProvableAddress,
	sec_key: SecretKey,
	secp: &Secp256k1,
) -> Result<String, Error> {
	let message_ser = payment_proof_message(amount, kernel_commitment, sender_address.public_key)?;
	if receiver_address.public_key.len() == 52 {
		//this is mqs address
		let mut challenge = String::new();
		challenge.push_str(&message_ser);
		let signature = crypto::sign_challenge(&challenge, &sec_key, secp)?;
		let signature = signature.to_hex();
		Ok(signature)
	} else {
		//this is tor oninion address and the length should be 56
		let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
			Ok(k) => k,
			Err(e) => {
				return Err(Error::ED25519Key(format!("{}", e)));
			}
		};
		let pub_key: DalekPublicKey = (&d_skey).into();
		let keypair = DalekKeypair {
			public: pub_key,
			secret: d_skey,
		};
		let signature = keypair.sign(&message_ser.as_bytes());
		//let signature_string = util::to_hex(signature.to_bytes());
		let signature_vec = signature.to_bytes().to_vec();
		Ok(util::to_hex(&signature_vec))
	}
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn verify_slate_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx_vec = updater::retrieve_txs(
		wallet,
		keychain_mask,
		None,
		Some(slate.id),
		None,
		None,
		false,
		None,
		None,
		None,
	)?;

	if tx_vec.is_empty() {
		return Err(Error::PaymentProof(
			"TxLogEntry with original proof info not found (is account correct?)".to_owned(),
		));
	}

	let orig_proof_info = tx_vec[0].clone().payment_proof;

	if orig_proof_info.is_some() && slate.payment_proof.is_none() {
		return Err(Error::PaymentProof(
			"Expected Payment Proof for this Transaction is not present".to_owned(),
		));
	}

	if let Some(ref p) = slate.clone().payment_proof {
		let orig_proof_info = match orig_proof_info {
			Some(p) => p.clone(),
			None => {
				return Err(Error::PaymentProof(
					"Original proof info not stored in tx".to_owned(),
				));
			}
		};
		let keychain = wallet.keychain(keychain_mask)?;
		let index = match context.payment_proof_derivation_index {
			Some(i) => i,
			None => {
				return Err(Error::PaymentProof(
					"Payment proof derivation index required".to_owned(),
				));
			}
		};
		// Normal public key is needed
		let orig_sender_a = proofaddress::payment_proof_address_from_index(
			&keychain,
			index,
			proofaddress::ProofAddressType::MQS,
		)?;

		if p.sender_address.public_key != orig_sender_a.public_key {
			return Err(Error::PaymentProof(
				"Sender address on slate does not match original sender address".to_owned(),
			));
		}

		if orig_proof_info.receiver_address.public_key != p.receiver_address.public_key
			&& orig_proof_info.receiver_address.public_key != p.sender_address.public_key
		{
			return Err(Error::PaymentProof(
				"Recipient address on slate does not match original recipient address".to_owned(),
			));
		}

		let (current_height, _, _) = wallet.w2n_client().get_chain_tip()?;

		//build the message which was used to generated receiver signature.
		let msg = payment_proof_message(
			slate.amount,
			&slate.calc_excess(keychain.secp(), Some(&keychain), current_height)?,
			orig_sender_a.public_key.clone(),
		)?;
		let sig = match p.clone().receiver_signature {
			Some(s) => s,
			None => {
				return Err(Error::PaymentProof(
					"Recipient did not provide requested proof signature".to_owned(),
				));
			}
		};
		//verify the proof signature
		if p.receiver_address.public_key.len() == 52 {
			let signature_ser = util::from_hex(&sig).map_err(|e| {
				Error::TxProofGenericError(format!(
					"Unable to build signature from HEX {}, {}",
					&sig, e
				))
			})?;
			let signature = Signature::from_der(keychain.secp(), &signature_ser).map_err(|e| {
				Error::TxProofGenericError(format!("Unable to build signature, {}", e))
			})?;
			debug!(
				"the receiver pubkey is {}",
				p.receiver_address.clone().public_key
			);
			let receiver_pubkey = p.receiver_address.public_key().map_err(|e| {
				Error::TxProofGenericError(format!("Unable to get receiver address, {}", e))
			})?;
			crypto::verify_signature(&msg, &signature, &receiver_pubkey, keychain.secp())
				.map_err(|e| Error::TxProofVerifySignature(format!("{}", e)))?;
		} else {
			//the signature is generated using Dalek public key

			let dalek_sig_vec = util::from_hex(&sig).map_err(|e| {
				Error::TxProofGenericError(format!(
					"Unable to deserialize tor payment proof signature, {}",
					e
				))
			})?;

			let dalek_sig_vec: &[u8] = &dalek_sig_vec;
			let dalek_sig = DalekSignature::try_from(dalek_sig_vec).map_err(|e| {
				Error::TxProofGenericError(format!(
					"Unable to deserialize tor payment proof receiver signature, {}",
					e
				))
			})?;

			let receiver_dalek_pub_key = p.receiver_address.tor_public_key().map_err(|e| {
				Error::TxProofGenericError(format!(
					"Unable to deserialize tor payment proof receiver address, {}",
					e
				))
			})?;
			if let Err(e) = receiver_dalek_pub_key.verify(&msg.as_bytes(), &dalek_sig) {
				return Err(Error::PaymentProof(format!(
					"Invalid proof signature, {}",
					e
				)))?;
			};
		}

		////add an extra step of generating and save proof.
		//generate the sender secret key
		let sender_address_secret_key =
			proofaddress::payment_proof_address_secret(&keychain, Some(index))?;
		let mut onion_address_str = None;
		if p.receiver_address.public_key.len() == 56 {
			//this should be a tor sending
			let onion_address = OnionV3Address::from_private(&sender_address_secret_key.0)
				.map_err(|e| {
					Error::TxProofGenericError(format!(
						"Unable to generate onion address for sender address, {}",
						e
					))
				})?;
			onion_address_str = Some(onion_address.to_ov3_str());
		}
		let tx_proof = TxProof::from_slate(
			msg,
			slate,
			&sender_address_secret_key,
			&orig_sender_a,
			onion_address_str,
			keychain.secp(),
		)
		.map_err(|e| {
			Error::TxProofVerifySignature(format!("Cannot create tx_proof using slate, {}", e))
		})?;

		debug!("tx_proof = {:?}", tx_proof);
		push_proof_for_slate(&slate.id, tx_proof);
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use crate::mwc_core::core::KernelFeatures;
	use crate::mwc_core::libtx::{build, ProofBuilder};
	use crate::mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain};
	use mwc_wallet_util::mwc_core::core::FeeFields;

	#[test]
	// demonstrate that input.commitment == referenced output.commitment
	// based on the public key and amount begin spent
	fn output_commitment_equals_input_commitment_on_spend() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();

		let tx1 = build::transaction(
			KernelFeatures::Plain {
				fee: FeeFields::zero(),
			},
			&[build::output(105, key_id1.clone())],
			&keychain,
			&builder,
		)
		.unwrap();
		let tx2 = build::transaction(
			KernelFeatures::Plain {
				fee: FeeFields::zero(),
			},
			&[build::input(105, key_id1.clone())],
			&keychain,
			&builder,
		)
		.unwrap();

		let inputs: Vec<_> = tx2.inputs().into();
		assert_eq!(tx1.outputs()[0].commitment(), inputs[0].commitment());
	}

	/*
	#[test]
	fn payment_proof_construction() {
		let identifier = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let sender_address_secret_key =
			address::address_from_derivation_path(&keychain, &identifier, 0).unwrap();
		let public_key = crypto::public_key_from_secret_key(&sender_address_secret_key).unwrap();

		let kernel_excess = {
			let keychain = ExtKeychain::from_random_seed(true).unwrap();
			let switch = SwitchCommitmentType::Regular;
			let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
			let id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
			let skey1 = keychain.derive_key(0, &id1, switch).unwrap();
			let skey2 = keychain.derive_key(0, &id2, switch).unwrap();
			let blinding_factor = keychain
				.blind_sum(
					&BlindSum::new()
						.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
						.add_blinding_factor(BlindingFactor::from_secret_key(skey2)),
				)
				.unwrap();
			keychain
				.secp()
				.commit(0, blinding_factor.secret_key(&keychain.secp()).unwrap())
				.unwrap()
		};

		let amount = 1_234_567_890_u64;
		let sender_address_string = ProvableAddress::from_pub_key(&public_key).public_key;
		let msg = payment_proof_message(amount, &kernel_excess, sender_address_string).unwrap();
		println!("payment proof message is (len {}): {:?}", msg.len(), msg);

		//todo don't know know to get PublicKey from bytes same as DalekPublicKey
		//		let decoded = _decode_payment_proof_message(&msg).unwrap();
		//		assert_eq!(decoded.0, amount);
		//		assert_eq!(decoded.1, kernel_excess);
		//		assert_eq!(decoded.2, address);
		let provable_address =
			proofaddress::payment_proof_address(&keychain, &identifier, 0).unwrap();

		let sig = create_payment_proof_signature(
			amount,
			&kernel_excess,
			provable_address,
			sender_address_secret_key,
		)
		.unwrap();

		let signature = util::from_hex(&sig).unwrap();
		let signature = Signature::from_der(&secp, &signature).unwrap();
		assert!(crypto::verify_signature(&msg, &signature, &public_key).is_ok());
	}
	*/
}
