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
use super::swap;
use super::swap::{tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{ErrorKind, Keychain, CURRENT_VERSION};
use crate::swap::bitcoin::BtcData;
use crate::swap::fsm::state::StateId;
use crate::swap::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use crate::{NodeClient, ParticipantData as TxParticipant, Slate, SlateVersion, VersionedSlate};
use grin_core::core::KernelFeatures;
use grin_core::libtx::{build, proof, tx_fee};
use grin_keychain::{BlindSum, BlindingFactor, SwitchCommitmentType};
use grin_util::secp::aggsig;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::pedersen::RangeProof;
use rand::thread_rng;
use std::mem;
use uuid::Uuid;

/// Buyer API. Bunch of methods that cover buyer action for MWC swap
/// This party is Buying MWC and selling BTC
pub struct BuyApi {}

impl BuyApi {
	/// Accepting Seller offer and create Swap instance
	pub fn accept_swap_offer<C: NodeClient, K: Keychain>(
		keychain: &K,
		context: &Context,
		id: Uuid,
		offer: OfferUpdate,
		secondary_update: SecondaryUpdate,
		node_client: &C,
	) -> Result<Swap, ErrorKind> {
		if offer.version != CURRENT_VERSION {
			return Err(ErrorKind::IncompatibleVersion(
				offer.version,
				CURRENT_VERSION,
			));
		}

		// Checking if the network match expected value
		if offer.network != Network::current_network()? {
			return Err(ErrorKind::UnexpectedNetwork(format!(
				", get offer for wrong network {:?}",
				offer.network
			)));
		}

		context.unwrap_buyer()?;

		let now_ts = swap::get_cur_time();

		// Tolerating 15 seconds clock difference. We don't want surprises with clocks.
		if offer.start_time.timestamp() > (now_ts + 15) {
			return Err(ErrorKind::InvalidMessageData(
				"Buyer/Seller clock are out of sync".to_string(),
			));
		}

		// Multisig tx needs to be unlocked and valid. Let's take a look at what we get.
		let lock_slate: Slate = offer.lock_slate.into();
		if lock_slate.lock_height > 0 {
			return Err(ErrorKind::InvalidLockHeightLockTx);
		}
		if lock_slate.amount != offer.primary_amount {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate amount doesn't match offer".to_string(),
			));
		}
		if lock_slate.fee
			!= tx_fee(
				lock_slate.tx.body.inputs.len(),
				lock_slate.tx.body.outputs.len() + 1,
				1,
				None,
			) {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate fee doesn't match expected value".to_string(),
			));
		}
		if lock_slate.num_participants != 2 {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate participans doesn't match expected value".to_string(),
			));
		}

		if lock_slate.tx.body.kernels.len() != 1 {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate invalid kernels".to_string(),
			));
		}
		match lock_slate.tx.body.kernels[0].features {
			KernelFeatures::Plain { fee } => {
				if fee != lock_slate.fee {
					return Err(ErrorKind::InvalidMessageData(
						"Lock Slate invalid kernel fee".to_string(),
					));
				}
			}
			_ => {
				return Err(ErrorKind::InvalidMessageData(
					"Lock Slate invalid kernel feature".to_string(),
				))
			}
		}

		// Let's check inputs. They must exist, we want real inspent coins. We can't check amount, that will be later when we cound validate the sum.
		// Height of the inputs is not important, we are relaying on locking transaction confirmations that is weaker.
		if lock_slate.tx.body.inputs.is_empty() {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate empty inputs".to_string(),
			));
		}
		let res = node_client
			.get_outputs_from_node(&lock_slate.tx.body.inputs.iter().map(|i| i.commit).collect())?;
		if res.len() != lock_slate.tx.body.inputs.len() {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate inputs are not found at the chain".to_string(),
			));
		}
		let height = node_client.get_chain_tip()?.0;
		if lock_slate.height > height {
			return Err(ErrorKind::InvalidMessageData(
				"Lock Slate height is invalid".to_string(),
			));
		}

		// Checking Refund slate.
		// Refund tx needs to be locked until exactly as offer specify. For MWC we are expecting one block every 1 minute.
		// So numbers should match with accuracy of few blocks.
		// Note!!! We can't valiry exact number because we don't know what height seller get when he created the offer
		let refund_slate: Slate = offer.refund_slate.into();
		// expecting at least half of the interval

		// Lock_height will be verified later
		if refund_slate.tx.body.kernels.len() != 1 {
			return Err(ErrorKind::InvalidMessageData(
				"Refund Slate invalid kernel".to_string(),
			));
		}
		match refund_slate.tx.body.kernels[0].features {
			KernelFeatures::HeightLocked { fee, lock_height } => {
				if fee != refund_slate.fee || lock_height != refund_slate.lock_height {
					return Err(ErrorKind::InvalidMessageData(
						"Refund Slate invalid kernel fee or height".to_string(),
					));
				}
			}
			_ => {
				return Err(ErrorKind::InvalidMessageData(
					"Refund Slate invalid kernel feature".to_string(),
				))
			}
		}
		if refund_slate.num_participants != 2 {
			return Err(ErrorKind::InvalidMessageData(
				"Refund Slate participans doesn't match expected value".to_string(),
			));
		}
		if refund_slate.amount + refund_slate.fee != lock_slate.amount {
			return Err(ErrorKind::InvalidMessageData(
				"Refund Slate amount doesn't match offer".to_string(),
			));
		}
		if refund_slate.fee != tx_fee(1, 1, 1, None) {
			return Err(ErrorKind::InvalidMessageData(
				"Refund Slate fee doesn't match expected value".to_string(),
			));
		}

		// Checking Secondary data. Focus on timing issues
		if offer.secondary_currency != Currency::Btc && offer.secondary_currency != Currency::Bch {
			return Err(ErrorKind::InvalidMessageData(
				"Unexpected currency value".to_string(),
			));
		}
		// Comparing BTC lock time with expected
		let btc_data = BtcData::from_offer(
			keychain,
			secondary_update.unwrap_btc()?.unwrap_offer()?,
			context.unwrap_buyer()?.unwrap_btc()?,
		)?;

		// Start redeem slate
		let mut redeem_slate = Slate::blank(2);

		#[cfg(test)]
		if is_test_mode() {
			redeem_slate.id = Uuid::parse_str("78aa5af1-048e-4c49-8776-a2e66d4a460c").unwrap()
		}

		redeem_slate.fee = tx_fee(1, 1, 1, None);
		redeem_slate.height = height;
		redeem_slate.amount = offer.primary_amount.saturating_sub(redeem_slate.fee);

		redeem_slate.participant_data.push(offer.redeem_participant);

		let multisig = MultisigBuilder::new(
			2,
			offer.primary_amount, // !!! It is amount that will be put into transactions. It is primary what need to be validated
			false,
			1,
			context.multisig_nonce.clone(),
			None,
		);

		let started = offer.start_time.clone();
		let secondary_fee = offer.secondary_currency.get_default_fee(&offer.network);
		let mut swap = Swap {
			id,
			version: CURRENT_VERSION,
			network: offer.network,
			role: Role::Buyer(None),
			communication_method: offer.communication_method,
			communication_address: offer.from_address,
			seller_lock_first: offer.seller_lock_first,
			started,
			state: StateId::BuyerOfferCreated,
			primary_amount: offer.primary_amount,
			secondary_amount: offer.secondary_amount,
			secondary_currency: offer.secondary_currency,
			secondary_data: SecondaryData::Btc(btc_data),
			redeem_public: None,
			participant_id: 1,
			multisig,
			lock_slate,
			refund_slate,
			redeem_slate,
			redeem_kernel_updated: false,
			adaptor_signature: None,
			mwc_confirmations: offer.mwc_confirmations,
			secondary_confirmations: offer.secondary_confirmations,
			message_exchange_time_sec: offer.message_exchange_time_sec,
			redeem_time_sec: offer.redeem_time_sec,
			message1: None,
			message2: None,
			posted_msg1: None,
			posted_msg2: None,
			posted_lock: None,
			posted_redeem: None,
			posted_refund: None,
			journal: Vec::new(),
			secondary_fee,
			electrum_node_uri1: None, // User need to review the offer first. Then to electrumX uri can be updated
			electrum_node_uri2: None,
		};
		swap.add_journal_message("Get a Swap offer".to_string());

		// Minimum mwc heights
		let expected_lock_height = height + (swap.get_time_mwc_lock() - now_ts) as u64 / 60;

		if swap.refund_slate.lock_height < expected_lock_height * 9 / 10 {
			return Err(ErrorKind::InvalidMessageData(
				"Refund lock slate doesn't meet required number of confirmations".to_string(),
			));
		}

		swap.redeem_public = Some(PublicKey::from_secret_key(
			keychain.secp(),
			&Self::redeem_secret(keychain, context)?,
		)?);

		Self::build_multisig(keychain, &mut swap, context, offer.multisig)?;
		Self::sign_lock_slate(keychain, &mut swap, context)?;
		Self::sign_refund_slate(keychain, &mut swap, context)?;

		Ok(swap)
	}

	/// Buyer builds swap.redeem_slate
	pub fn init_redeem<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		assert!(!swap.is_seller());
		Self::build_redeem_slate(keychain, swap, context)?;
		Self::calculate_adaptor_signature(keychain, swap, context)?;

		Ok(())
	}

	/// Generate 'Accept offer' massage
	pub fn accept_offer_message(
		swap: &Swap,
		inner_secondary: SecondaryUpdate,
	) -> Result<Message, ErrorKind> {
		let id = swap.participant_id;
		swap.message(
			Update::AcceptOffer(AcceptOfferUpdate {
				multisig: swap.multisig.export()?,
				redeem_public: swap
					.redeem_public
					.clone()
					.ok_or(ErrorKind::Generic("redeem_public is empty".to_string()))?,
				lock_participant: swap.lock_slate.participant_data[id].clone(),
				refund_participant: swap.refund_slate.participant_data[id].clone(),
			}),
			inner_secondary,
		)
	}

	/// Generate 'InitRedeem' slate message
	pub fn init_redeem_message(swap: &Swap) -> Result<Message, ErrorKind> {
		swap.message(
			Update::InitRedeem(InitRedeemUpdate {
				redeem_slate: VersionedSlate::into_version(
					swap.redeem_slate.clone(),
					SlateVersion::V2, // V2 should satify our needs, dont adding extra
				),
				adaptor_signature: swap.adaptor_signature.ok_or(ErrorKind::UnexpectedAction(
					"Buyer Fn init_redeem_message(), multisig is empty".to_string(),
				))?,
			}),
			SecondaryUpdate::Empty,
		)
	}

	/// Secret that unlocks the funds on both chains
	pub fn redeem_secret<K: Keychain>(
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;
		let sec_key = keychain.derive_key(0, &bcontext.redeem, SwitchCommitmentType::None)?;

		Ok(sec_key)
	}

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<(), ErrorKind> {
		let multisig_secret = swap.multisig_secret(keychain, context)?;
		let multisig = &mut swap.multisig;

		// Import participant
		multisig.import_participant(0, &part)?;
		multisig.create_participant(keychain.secp(), &multisig_secret)?;
		multisig.round_1_participant(0, &part)?;

		// Round 1 + round 2
		multisig.round_1(keychain.secp(), &multisig_secret)?;
		let common_nonce = swap.common_nonce(keychain.secp())?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(keychain.secp(), &multisig_secret)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		// Partial multisig output
		let sum = BlindSum::new().add_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(keychain, context)?,
		));
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn sign_lock_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Buyer Fn sign_lock_slate(), lock slate participant data is already initialized"
					.to_string(),
			)
			.into());
		}

		// Add multisig output to slate (with invalid proof)
		let mut proof = RangeProof::zero();
		proof.plen = grin_util::secp::constants::MAX_PROOF_SIZE;

		tx_add_output(slate, swap.multisig.commit(keychain.secp())?, proof);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(keychain, &sec_key, &context.lock_nonce, swap.participant_id)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
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

	fn sign_refund_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let commit = swap.multisig.commit(keychain.secp())?;
		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot("Buyer Fn sign_refund_slate(), refund slate participant data is already initialized".to_string()).into());
		}

		// Add multisig input to slate
		tx_add_input(slate, commit);

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the redeem slate
	pub fn redeem_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// Partial multisig input, redeem output, offset
		let sum = BlindSum::new()
			.add_key_id(bcontext.output.to_value_path(swap.redeem_slate.amount))
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.redeem_slate.tx.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		let bcontext = context.unwrap_buyer()?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 1 {
			return Err(ErrorKind::OneShot(
				"Buyer Fn build_redeem_slate(), redeem slate participant data is not empty"
					.to_string(),
			));
		}

		// Build slate
		slate.fee = tx_fee(1, 1, 1, None);
		slate.amount = swap.primary_amount - slate.fee;
		let mut elems = Vec::new();
		elems.push(build::output(slate.amount, bcontext.output.clone()));
		slate
			.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?
			.secret_key(keychain.secp())?;

		#[cfg(test)]
		{
			slate.tx.offset = if is_test_mode() {
				BlindingFactor::from_hex(
					"90de4a3812c7b78e567548c86926820d838e7e0b43346b1ba63066cd5cc7d999",
				)
				.unwrap()
			} else {
				BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()))
			};
		}

		// Release Doesn't have any tweaking
		#[cfg(not(test))]
		{
			slate.tx.offset =
				BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()));
		}

		// Add multisig input to slate
		tx_add_input(slate, swap.multisig.commit(keychain.secp())?);

		let mut sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let slate = &mut swap.redeem_slate;

		// Add participant to slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.redeem_nonce,
			swap.participant_id,
			None,
			false,
		)?;

		Ok(())
	}

	/// Finalize redeem slate with a data from the message
	pub fn finalize_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: TxParticipant,
	) -> Result<(), ErrorKind> {
		let id = swap.participant_id;
		let other_id = swap.other_participant_id();
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate
			.participant_data
			.get(id)
			.ok_or(ErrorKind::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for this party".to_string()))?
			.is_complete()
		{
			return Err(ErrorKind::OneShot("Buyer Fn finalize_redeem_slate() redeem slate is already initialized".to_string()).into());
		}

		// Replace participant
		let _ = mem::replace(
			slate
				.participant_data
				.get_mut(other_id)
				.ok_or(ErrorKind::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for other party".to_string()))?,
			part,
		);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;
		slate.finalize(keychain)?;

		Ok(())
	}

	fn calculate_adaptor_signature<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(ErrorKind::OneShot(
				"Buyer calculate_adaptor_signature(), miltisig is already initialized".to_string(),
			));
		}

		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let (pub_nonce_sum, pub_blind_sum, message) =
			swap.redeem_tx_fields(keychain.secp(), &swap.redeem_slate)?;

		let adaptor_signature = aggsig::sign_single(
			keychain.secp(),
			&message,
			&sec_key,
			Some(&context.redeem_nonce),
			Some(&Self::redeem_secret(keychain, context)?),
			Some(&pub_nonce_sum),
			Some(&pub_blind_sum),
			Some(&pub_nonce_sum),
		)?;
		swap.adaptor_signature = Some(adaptor_signature);

		Ok(())
	}
}
