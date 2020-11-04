// Copyright 2019 The vault713 Developers
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

#[cfg(test)]
use super::is_test_mode;
use super::message::*;
use super::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use super::swap;
use super::swap::{signature_as_secret, tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{ErrorKind, Keychain, CURRENT_VERSION};
use crate::swap::fsm::state::StateId;
use crate::{ParticipantData as TxParticipant, Slate, SlateVersion, VersionedSlate};
use chrono::{DateTime, NaiveDateTime, Utc};
use grin_core::libtx::{build, proof, tx_fee};
use grin_keychain::{BlindSum, BlindingFactor};
use grin_util::secp::aggsig;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use rand::thread_rng;

#[cfg(test)]
use uuid::Uuid;

/// Seller API. Bunch of methods that cover seller action for MWC swap
/// This party is Selling MWC and buying BTC
pub struct SellApi {}

impl SellApi {
	/// Start a swap
	/// This will create an object to track the swap state,
	/// as well as an offer to send to the counterparty
	/// It assumes that the Context has already been populated with
	/// the correct values for key derivation paths and nonces
	pub fn create_swap_offer<K: Keychain>(
		keychain: &K,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		height: u64,
		seller_lock_first: bool,
		mwc_confirmations: u64,
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
		communication_method: String,
		buyer_destination_address: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
	) -> Result<Swap, ErrorKind> {
		#[cfg(test)]
		let test_mode = is_test_mode();
		let scontext = context.unwrap_seller()?;
		let multisig = MultisigBuilder::new(
			2,
			primary_amount,
			false,
			0,
			context.multisig_nonce.clone(),
			None,
		);

		let now_ts = swap::get_cur_time();
		let started = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(now_ts, 0), Utc);

		let ls = Slate::blank(2);

		#[cfg(test)]
		let id = if test_mode {
			Uuid::parse_str("4fc16adb-9f32-4441-b0c1-b4de076a1972").unwrap()
		} else {
			ls.id.clone()
		};

		#[cfg(not(test))]
		let id = ls.id.clone();

		let network = Network::current_network()?;
		let secondary_fee = secondary_currency.get_default_fee(&network);

		let mut swap = Swap {
			id,
			version: CURRENT_VERSION,
			network,
			role: Role::Seller("".to_string(), 0), // will be updated later
			communication_method,
			communication_address: buyer_destination_address,
			seller_lock_first,
			started,
			state: StateId::SellerOfferCreated,
			primary_amount,
			secondary_amount,
			secondary_currency,
			secondary_data: SecondaryData::Empty,
			redeem_public: None,
			participant_id: 0,
			multisig,
			lock_slate: ls,
			refund_slate: Slate::blank(2),
			redeem_slate: Slate::blank(2),
			redeem_kernel_updated: false,
			adaptor_signature: None,
			mwc_confirmations,
			secondary_confirmations,
			message_exchange_time_sec,
			redeem_time_sec,
			message1: None,
			message2: None,
			posted_msg1: None,
			posted_msg2: None,
			posted_lock: None,
			posted_redeem: None,
			posted_refund: None,
			journal: Vec::new(),
			secondary_fee,
			electrum_node_uri1,
			electrum_node_uri2,
		};

		swap.add_journal_message("Swap offer is created".to_string());

		let mwc_lock_time = swap.get_time_mwc_lock();
		let start_time = swap.get_time_start();

		// Lock slate
		let mut lock_slate = &mut swap.lock_slate;

		#[cfg(test)]
		if test_mode {
			lock_slate.id = Uuid::parse_str("55b79f54-c40d-45e1-9544-a52dcf426db2").unwrap();
		}

		lock_slate.fee = tx_fee(scontext.inputs.len(), 2, 1, None);
		lock_slate.amount = primary_amount;
		lock_slate.height = height;

		// Refund slate
		let mut refund_slate = &mut swap.refund_slate;
		#[cfg(test)]
		if test_mode {
			refund_slate.id = Uuid::parse_str("703fac15-913c-4e66-a7c2-5f648ca4ca7d").unwrap();
		}
		refund_slate.fee = tx_fee(1, 1, 1, None);
		if primary_amount <= refund_slate.fee {
			return Err(ErrorKind::Generic(
				"MWC amount to trade is too low, it doesn't cover the fees".to_string(),
			)
			.into());
		}

		refund_slate.height = height;
		// Calculating lock height from locking time. For MWC the mining speed is about 1 minute
		refund_slate.lock_height = height + (mwc_lock_time - start_time) as u64 / 60 + 1;
		refund_slate.amount = primary_amount.saturating_sub(refund_slate.fee);

		// Don't lock for more than 30 days.
		let max_lock_time = 1440 * 30;

		if refund_slate.lock_height - refund_slate.height > max_lock_time {
			return Err(ErrorKind::Generic(
				"MWC locking time interval exceed 4 weeks. Is it a scam or mistake?".to_string(),
			));
		}

		// Redeem slate
		let mut redeem_slate = &mut swap.redeem_slate;
		#[cfg(test)]
		if test_mode {
			redeem_slate.id = Uuid::parse_str("fc750aae-035f-4c6c-bb0c-05aabc764f8e").unwrap();
		}
		redeem_slate.amount = refund_slate.amount;
		redeem_slate.height = refund_slate.height;
		redeem_slate.fee = refund_slate.fee;

		// Make sure we have enough funds
		let mut sum_in = 0;
		for (_, _, input_amount) in &scontext.inputs {
			sum_in += *input_amount;
		}

		// TODO: no change output if amounts match up exactly
		if sum_in <= primary_amount + lock_slate.fee {
			return Err(ErrorKind::InsufficientFunds(
				primary_amount + lock_slate.fee + 1,
				sum_in,
			));
		}
		let change = sum_in - primary_amount - lock_slate.fee;

		secondary_currency.validate_address(&secondary_redeem_address)?;
		swap.role = Role::Seller(secondary_redeem_address, change);

		Self::build_multisig(keychain, &mut swap, context)?;
		Self::build_lock_slate(keychain, &mut swap, context)?;
		Self::build_refund_slate(keychain, &mut swap, context)?;
		Self::build_redeem_participant(keychain, &mut swap, context)?;

		Ok(swap)
	}

	/// Process 'accepted offer' message from the buyer
	pub fn accepted_offer<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		accept_offer: AcceptOfferUpdate,
	) -> Result<(), ErrorKind> {
		assert!(swap.is_seller());

		// Finalize multisig proof
		let proof = Self::finalize_multisig(keychain, swap, context, accept_offer.multisig)?;

		// Update slates
		let commit = swap.multisig.commit(keychain.secp())?;
		Self::finalize_lock_slate(
			keychain,
			swap,
			context,
			commit.clone(),
			proof,
			accept_offer.lock_participant,
		)?;
		Self::finalize_refund_slate(
			keychain,
			swap,
			context,
			commit.clone(),
			accept_offer.refund_participant,
		)?;

		swap.redeem_public = Some(accept_offer.redeem_public);

		Ok(())
	}

	/// Seller initializing the redeem slate. At that moment Both BTC and MWC are expected to be at
	/// the locked slated published and get enough confirmations.
	/// Result:
	/// 	swap.redeem_slate
	// 	 	swap.adaptor_signature
	pub fn init_redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		init_redeem: InitRedeemUpdate,
	) -> Result<(), ErrorKind> {
		assert!(swap.is_seller());

		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(ErrorKind::OneShot(
				"Seller Fn init_redeem() multisig is empty".to_string(),
			)
			.into());
		}

		let mut redeem_slate: Slate = init_redeem.redeem_slate.into();

		// Validate adaptor signature
		let (pub_nonce_sum, _, message) = swap.redeem_tx_fields(keychain.secp(), &redeem_slate)?;
		// Calculate sum of blinding factors from in- and outputs so we know we can use this excess
		// later to find the on-chain signature and calculate the redeem secret
		let pub_blind_sum =
			Self::redeem_excess(keychain, &mut redeem_slate)?.to_pubkey(keychain.secp())?;
		if !aggsig::verify_single(
			keychain.secp(),
			&init_redeem.adaptor_signature,
			&message,
			Some(&pub_nonce_sum),
			&redeem_slate.participant_data[swap.other_participant_id()].public_blind_excess,
			Some(&pub_blind_sum),
			Some(&swap.redeem_public.ok_or(ErrorKind::UnexpectedAction(
				"Seller Fn init_redeem() redeem pub key is empty".to_string(),
			))?),
			true,
		) {
			return Err(ErrorKind::InvalidAdaptorSignature);
		}

		swap.redeem_slate = redeem_slate;
		swap.adaptor_signature = Some(init_redeem.adaptor_signature);

		Self::sign_redeem_slate(keychain, swap, context)?;

		Ok(())
	}

	/// Calculating the secret that allow to redeem BTC.
	/// At this point Buyer already get his MWC, so now Seller should get a revealed secret and get BTCs
	pub fn calculate_redeem_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
	) -> Result<SecretKey, ErrorKind> {
		let secp = keychain.secp();

		let adaptor_signature = signature_as_secret(
			secp,
			&swap.adaptor_signature.ok_or(ErrorKind::UnexpectedAction(
				"Seller Fn calculate_redeem_secret() multisig is empty".to_string(),
			))?,
		)?;
		let signature = signature_as_secret(
			secp,
			&swap
				.redeem_slate
				.tx
				.kernels()
				.get(0)
				.ok_or(ErrorKind::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, no kernels found".to_string()))?
				.excess_sig,
		)?;
		let seller_signature = signature_as_secret(
			secp,
			&swap
				.redeem_slate
				.participant_data
				.get(swap.participant_id)
				.ok_or(ErrorKind::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, participant not found".to_string()))?
				.part_sig
				.ok_or(ErrorKind::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, participant signature not found".to_string()))?,
		)?;

		let redeem = secp.blind_sum(vec![adaptor_signature, seller_signature], vec![signature])?;
		let redeem_pub = PublicKey::from_secret_key(keychain.secp(), &redeem)?;
		if swap.redeem_public != Some(redeem_pub) {
			// If this happens - mean that swap is broken, somewhere there is a security flaw. Probably didn't check something.
			return Err(ErrorKind::Generic(
				"Redeem secret doesn't match - this should never happen".into(),
			));
		}

		Ok(redeem)
	}

	/// Generate Offer message.
	/// Note: from_address need to be update by the caller because only caller knows about communication layer.
	pub fn offer_message(
		swap: &Swap,
		secondary_update: SecondaryUpdate,
	) -> Result<Message, ErrorKind> {
		assert!(swap.is_seller());
		swap.message(
			Update::Offer(OfferUpdate {
				start_time: swap.started,
				version: swap.version,
				communication_method: swap.communication_method.clone(),
				from_address: "Fix me".to_string(),
				network: swap.network,
				seller_lock_first: swap.seller_lock_first,
				primary_amount: swap.primary_amount,
				secondary_amount: swap.secondary_amount,
				secondary_currency: swap.secondary_currency,
				multisig: swap.multisig.export()?,
				lock_slate: VersionedSlate::into_version(
					swap.lock_slate.clone(),
					SlateVersion::V2, // V2 should satify our needs, dont adding extra
				),
				refund_slate: VersionedSlate::into_version(
					swap.refund_slate.clone(),
					SlateVersion::V2, // V2 should satify our needs, dont adding extra
				),
				redeem_participant: swap.redeem_slate.participant_data[swap.participant_id].clone(),
				mwc_confirmations: swap.mwc_confirmations,
				secondary_confirmations: swap.secondary_confirmations,
				message_exchange_time_sec: swap.message_exchange_time_sec,
				redeem_time_sec: swap.redeem_time_sec,
			}),
			secondary_update,
		)
	}

	/// Generate redeem message
	pub fn redeem_message(swap: &Swap) -> Result<Message, ErrorKind> {
		assert!(swap.is_seller());
		swap.message(
			Update::Redeem(RedeemUpdate {
				redeem_participant: swap.redeem_slate.participant_data[swap.participant_id].clone(),
			}),
			SecondaryUpdate::Empty,
		)
	}

	// ----------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let multisig_secret = swap.multisig_secret(keychain, context)?;
		let multisig = &mut swap.multisig;

		// Round 1
		multisig.create_participant(keychain.secp(), &multisig_secret)?;
		multisig.round_1(keychain.secp(), &multisig_secret)?;

		Ok(())
	}

	fn finalize_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<RangeProof, ErrorKind> {
		let sec_key = swap.multisig_secret(keychain, context)?;
		let secp = keychain.secp();

		// Import
		let multisig = &mut swap.multisig;
		multisig.import_participant(1, &part)?;
		multisig.round_1_participant(1, &part)?;
		multisig.round_2_participant(1, &part)?;

		// Round 2 + finalize
		let common_nonce = swap.common_nonce(secp)?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(secp, &sec_key)?;
		let proof = multisig.finalize(secp, &sec_key)?;

		Ok(proof)
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let scontext = context.unwrap_seller()?;
		let (_, change) = swap.unwrap_seller()?;
		let mut sum = BlindSum::new();

		// Input(s)
		for (input_identifier, _, input_amount) in &scontext.inputs {
			sum = sum.sub_key_id(input_identifier.to_value_path(*input_amount));
		}

		// Change output, partial multisig output, offset
		sum = sum
			.add_key_id(scontext.change_output.to_value_path(change))
			.add_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.lock_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let (_, change) = swap.unwrap_seller()?;
		let scontext = context.unwrap_seller()?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot(
				"Seller Fn build_lock_slate() lock slate is already initialized".to_string(),
			)
			.into());
		}

		// Build lock slate
		// The multisig output is missing because it is not yet fully known
		let mut elems = Vec::new();
		for (input_identifier, _, input_amount) in &scontext.inputs {
			elems.push(build::input(*input_amount, input_identifier.clone()));
		}
		elems.push(build::output(change, scontext.change_output.clone()));
		slate.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?;
		slate.tx.offset =
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()));

		#[cfg(test)]
		if is_test_mode() {
			slate.tx.offset = BlindingFactor::from_hex(
				"d9da697c9c8bf7ff85116dd401f53e4d58bc0155fb6db56b15a99aa8884a44e9",
			)
			.unwrap()
		}

		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.lock_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		proof: RangeProof,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Seller Fn finalize_lock_slate() lock slate is already initialized".to_string(),
			)
			.into());
		}

		// Add participant to slate
		slate.participant_data.push(part);

		// Add multisig output to slate
		tx_add_output(slate, commit, proof);

		// Sign + finalize slate
		slate.fill_round_2(keychain, &sec_key, &context.lock_nonce, swap.participant_id)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let scontext = context.unwrap_seller()?;

		// Partial multisig input, refund output, offset
		let sum = BlindSum::new()
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.add_key_id(scontext.refund_output.to_value_path(swap.refund_amount()))
			.sub_blinding_factor(swap.refund_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let scontext = context.unwrap_seller()?;
		let refund_amount = swap.refund_amount();

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot(
				"Seller Fn build_refund_slate() refund slate is already initialized".to_string(),
			));
		}

		// Build refund slate
		// The multisig input is missing because it is not yet fully known
		let mut elems = Vec::new();
		elems.push(build::output(refund_amount, scontext.refund_output.clone()));
		slate
			.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?
			.secret_key(keychain.secp())?;
		slate.tx.offset =
			BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()));

		#[cfg(test)]
		if is_test_mode() {
			slate.tx.offset = BlindingFactor::from_hex(
				"53ac7d0ad9833568cf63dfa8aa607e2b27be525111b1e0de92aa0caa50f838ae",
			)
			.unwrap();
		}

		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.refund_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	fn finalize_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Seller Fn finalize_refund_slate() refund slate is already initialized".to_string(),
			)
			.into());
		}

		// Add participant to slate
		slate.participant_data.push(part);

		// Add multisig input to slate
		tx_add_input(slate, commit);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn redeem_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig input
		let sum = BlindSum::new().sub_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_participant<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 0 {
			return Err(ErrorKind::OneShot(
				"Seller Fn build_redeem_participant() redeem slate is already initialized"
					.to_string(),
			));
		}

		// Build participant
		let participant = TxParticipant {
			id: swap.participant_id as u64,
			public_blind_excess: PublicKey::from_secret_key(keychain.secp(), &sec_key)?,
			public_nonce: PublicKey::from_secret_key(keychain.secp(), &context.redeem_nonce)?,
			part_sig: None,
			message: None,
			message_sig: None,
		};
		slate.participant_data.push(participant);

		Ok(())
	}

	fn redeem_excess<K: Keychain>(
		keychain: &K,
		redeem_slate: &mut Slate,
	) -> Result<Commitment, ErrorKind> {
		let excess = redeem_slate.calc_excess(keychain)?;
		redeem_slate.tx.kernels_mut()[0].excess = excess.clone();
		Ok(excess)
	}

	fn sign_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let id = swap.participant_id;
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data[id].is_complete() {
			return Err(ErrorKind::OneShot("Seller Fn sign_redeem_slate() redeem slate participant data is already initilaized".to_string()));
		}

		// Sign slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}
}
