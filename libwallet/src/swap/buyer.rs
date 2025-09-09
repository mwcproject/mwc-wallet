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
use super::{Error, Keychain, CURRENT_VERSION};
use crate::api_impl::owner_eth::get_eth_balance;
use crate::mwc_core::core::Committed;
use crate::mwc_core::core::KernelFeatures;
use crate::mwc_core::libtx::{build, proof, tx_fee};
use crate::mwc_keychain::{BlindSum, BlindingFactor, SwitchCommitmentType};
use crate::mwc_util::secp::aggsig;
use crate::mwc_util::secp::key::{PublicKey, SecretKey};
use crate::mwc_util::secp::pedersen::RangeProof;
use crate::swap::bitcoin::BtcData;
use crate::swap::ethereum::{EthData, EthereumWallet};
use crate::swap::fsm::state::StateId;
use crate::swap::multisig::{Builder as MultisigBuilder, ParticipantData as MultisigParticipant};
use crate::{NodeClient, ParticipantData as TxParticipant, Slate, SlateVersion, VersionedSlate};
use rand::thread_rng;
use std::mem;
use uuid::Uuid;

/// Buyer API. Bunch of methods that cover buyer action for MWC swap
/// This party is Buying MWC and selling BTC
pub struct BuyApi {}

impl BuyApi {
	/// Accepting Seller offer and create Swap instance
	pub fn accept_swap_offer<C: NodeClient, K: Keychain>(
		ethereum_wallet: Option<EthereumWallet>,
		keychain: &K,
		context: &Context,
		id: Uuid,
		offer: OfferUpdate,
		secondary_update: SecondaryUpdate,
		node_client: &C,
	) -> Result<Swap, Error> {
		if offer.version != CURRENT_VERSION {
			return Err(Error::IncompatibleVersion(offer.version, CURRENT_VERSION));
		}

		// Checking if the network match expected value
		if offer.network != Network::current_network()? {
			return Err(Error::UnexpectedNetwork(format!(
				", get offer for wrong network {:?}",
				offer.network
			)));
		}

		context.unwrap_buyer()?;

		let now_ts = swap::get_cur_time();

		// Tolerating 15 seconds clock difference. We don't want surprises with clocks.
		if offer.start_time.timestamp() > (now_ts + 15) {
			return Err(Error::InvalidMessageData(
				"Buyer/Seller clock are out of sync".to_string(),
			));
		}

		// Multisig tx needs to be unlocked and valid. Let's take a look at what we get.
		let lock_slate: Slate = offer.lock_slate.into_slate_plain(true)?;
		if lock_slate.get_lock_height() > 0 {
			return Err(Error::InvalidLockHeightLockTx);
		}
		if lock_slate.amount != offer.primary_amount {
			return Err(Error::InvalidMessageData(
				"Lock Slate amount doesn't match offer".to_string(),
			));
		}
		if lock_slate.fee
			!= tx_fee(
				lock_slate.tx_or_err()?.body.inputs.len(),
				lock_slate.tx_or_err()?.body.outputs.len() + 1,
				1,
			) {
			return Err(Error::InvalidMessageData(
				"Lock Slate fee doesn't match expected value".to_string(),
			));
		}
		if lock_slate.num_participants != 2 {
			return Err(Error::InvalidMessageData(
				"Lock Slate participans doesn't match expected value".to_string(),
			));
		}

		if lock_slate.tx_or_err()?.body.kernels.len() != 1 {
			return Err(Error::InvalidMessageData(
				"Lock Slate invalid kernels".to_string(),
			));
		}

		let (current_height, _, _) = node_client.get_chain_tip()?;

		match lock_slate.tx_or_err()?.body.kernels[0].features {
			KernelFeatures::Plain { fee } => {
				if fee.fee() != lock_slate.fee {
					return Err(Error::InvalidMessageData(
						"Lock Slate invalid kernel fee".to_string(),
					));
				}
			}
			_ => {
				return Err(Error::InvalidMessageData(
					"Lock Slate invalid kernel feature".to_string(),
				))
			}
		}

		// Let's check inputs. They must exist, we want real inspent coins. We can't check amount, that will be later when we cound validate the sum.
		// Height of the inputs is not important, we are relaying on locking transaction confirmations that is weaker.
		if lock_slate.tx_or_err()?.body.inputs.is_empty() {
			return Err(Error::InvalidMessageData(
				"Lock Slate empty inputs".to_string(),
			));
		}
		let res = node_client.get_outputs_from_node(&lock_slate.tx_or_err()?.inputs_committed())?;
		if res.len() != lock_slate.tx_or_err()?.body.inputs.len() {
			return Err(Error::InvalidMessageData(
				"Lock Slate inputs are not found at the chain".to_string(),
			));
		}
		if lock_slate.height > current_height {
			return Err(Error::InvalidMessageData(
				"Lock Slate height is invalid".to_string(),
			));
		}

		// Checking Refund slate.
		// Refund tx needs to be locked until exactly as offer specify. For MWC we are expecting one block every 1 minute.
		// So numbers should match with accuracy of few blocks.
		// Note!!! We can't verify exact number because we don't know what height seller get when he created the offer
		let refund_slate: Slate = offer.refund_slate.into_slate_plain(true)?;
		// expecting at least half of the interval

		// Lock_height will be verified later
		if refund_slate.tx_or_err()?.body.kernels.len() != 1 {
			return Err(Error::InvalidMessageData(
				"Refund Slate invalid kernel".to_string(),
			));
		}
		match refund_slate.tx_or_err()?.body.kernels[0].features {
			KernelFeatures::HeightLocked { fee, lock_height } => {
				if fee.fee() != refund_slate.fee
					|| lock_height != refund_slate.get_lock_height_check()?
				{
					return Err(Error::InvalidMessageData(
						"Refund Slate invalid kernel fee or height".to_string(),
					));
				}
			}
			_ => {
				return Err(Error::InvalidMessageData(
					"Refund Slate invalid kernel feature".to_string(),
				))
			}
		}
		if refund_slate.num_participants != 2 {
			return Err(Error::InvalidMessageData(
				"Refund Slate participants doesn't match expected value".to_string(),
			));
		}
		if refund_slate.amount + refund_slate.fee != lock_slate.amount {
			return Err(Error::InvalidMessageData(
				"Refund Slate amount doesn't match offer".to_string(),
			));
		}
		if refund_slate.fee != tx_fee(1, 1, 1) {
			return Err(Error::InvalidMessageData(
				"Refund Slate fee doesn't match expected value".to_string(),
			));
		}

		// Checking Secondary data. Focus on timing issues
		match offer.secondary_currency {
			Currency::Btc
			| Currency::Bch
			| Currency::Ltc
			| Currency::Dash
			| Currency::ZCash
			| Currency::Doge
			| Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Wbtc
			| Currency::Usdt
			| Currency::Usdc
			| Currency::Trx
			| Currency::Tst => (),
		}

		// Start redeem slate
		let mut redeem_slate = Slate::blank(2, false);

		#[cfg(test)]
		if is_test_mode() {
			redeem_slate.id = Uuid::parse_str("78aa5af1-048e-4c49-8776-a2e66d4a460c").unwrap()
		}

		redeem_slate.fee = tx_fee(1, 1, 1);
		redeem_slate.height = current_height;
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
		if !offer.secondary_currency.is_btc_family() {
			let balance_gwei = get_eth_balance(ethereum_wallet.unwrap())?;
			if secondary_fee > balance_gwei as f32 {
				return Err(Error::Generic(
					"No enough ether as gas for swap".to_string(),
				));
			}
		}

		let mut swap = match offer.secondary_currency.is_btc_family() {
			true => {
				let btc_data = BtcData::from_offer(
					keychain,
					secondary_update.unwrap_btc()?.unwrap_offer()?,
					context.unwrap_buyer()?.unwrap_btc()?,
				)?;
				let redeem_public = Some(PublicKey::from_secret_key(
					keychain.secp(),
					&Self::redeem_secret(keychain, context)?,
				)?);
				Swap {
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
					redeem_public,
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
					posted_secondary_height: None,
					journal: Vec::new(),
					secondary_fee,
					electrum_node_uri1: None, // User need to review the offer first. Then to electrumX uri can be updated
					electrum_node_uri2: None,
					eth_swap_contract_address: None,
					erc20_swap_contract_address: None,
					eth_infura_project_id: None,
					eth_redirect_to_private_wallet: Some(false),
					last_process_error: None,
					last_check_error: None,
					wait_for_backup1: false,
					tag: None,
					other_lock_first_done: false,
				}
			}
			_ => {
				let eth_data = EthData::from_offer(
					secondary_update.unwrap_eth()?.unwrap_offer()?,
					context.unwrap_buyer()?.unwrap_eth()?,
				)?;
				let redeem_public = Some(PublicKey::from_secret_key(
					keychain.secp(),
					&Self::redeem_secret(keychain, context)?,
				)?);

				Swap {
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
					secondary_data: SecondaryData::Eth(eth_data),
					redeem_public,
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
					posted_secondary_height: None,
					journal: Vec::new(),
					secondary_fee,
					electrum_node_uri1: None, // User need to review the offer first. Then to electrumX uri can be updated
					electrum_node_uri2: None,
					eth_swap_contract_address: None,
					erc20_swap_contract_address: None,
					eth_infura_project_id: None,
					eth_redirect_to_private_wallet: Some(false),
					last_process_error: None,
					last_check_error: None,
					wait_for_backup1: false,
					tag: None,
					other_lock_first_done: false,
				}
			}
		};

		swap.add_journal_message("Received a swap offer".to_string());

		// Minimum mwc heights
		let expected_lock_height = current_height + (swap.get_time_mwc_lock() - now_ts) as u64 / 60;

		if swap.refund_slate.get_lock_height_check()? < expected_lock_height * 9 / 10 {
			return Err(Error::InvalidMessageData(
				"Refund lock slate doesn't meet required number of confirmations".to_string(),
			));
		}

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
	) -> Result<(), Error> {
		assert!(!swap.is_seller());
		Self::build_redeem_slate(keychain, swap, context)?;
		Self::calculate_adaptor_signature(keychain, swap, context)?;

		Ok(())
	}

	/// Generate 'Accept offer' massage
	pub fn accept_offer_message(
		swap: &Swap,
		inner_secondary: SecondaryUpdate,
	) -> Result<Message, Error> {
		let id = swap.participant_id;
		swap.message(
			Update::AcceptOffer(AcceptOfferUpdate {
				multisig: swap.multisig.export()?,
				redeem_public: swap
					.redeem_public
					.clone()
					.ok_or(Error::Generic("redeem_public is empty".to_string()))?,
				lock_participant: swap.lock_slate.participant_data[id].clone(),
				refund_participant: swap.refund_slate.participant_data[id].clone(),
			}),
			inner_secondary,
		)
	}

	/// Generate 'InitRedeem' slate message
	pub fn init_redeem_message(swap: &Swap) -> Result<Message, Error> {
		swap.message(
			Update::InitRedeem(InitRedeemUpdate {
				redeem_slate: VersionedSlate::into_version_plain(
					swap.redeem_slate.clone(),
					SlateVersion::V2, // V2 should satify our needs, dont adding extra
				)?,
				adaptor_signature: swap.adaptor_signature.ok_or(Error::UnexpectedAction(
					"Buyer Fn init_redeem_message(), multisig is empty".to_string(),
				))?,
			}),
			SecondaryUpdate::Empty,
		)
	}

	/// Secret that unlocks the funds on both chains
	pub fn redeem_secret<K: Keychain>(keychain: &K, context: &Context) -> Result<SecretKey, Error> {
		let bcontext = context.unwrap_buyer()?;
		let sec_key = keychain.derive_key(0, &bcontext.redeem, SwitchCommitmentType::None)?;

		Ok(sec_key)
	}

	fn build_multisig<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: MultisigParticipant,
	) -> Result<(), Error> {
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
	) -> Result<SecretKey, Error> {
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
	) -> Result<(), Error> {
		let mut sec_key = Self::lock_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Buyer Fn sign_lock_slate(), lock slate participant data is already initialized"
					.to_string(),
			));
		}

		// Add multisig output to slate (with invalid proof)
		let mut proof = RangeProof::zero();
		proof.plen = crate::mwc_util::secp::constants::MAX_PROOF_SIZE;

		tx_add_output(slate, swap.multisig.commit(keychain.secp())?, proof)?;

		// Sign slate
		slate.fill_round_1(
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			false,
		)?;
		slate.fill_round_2(
			keychain.secp(),
			&sec_key,
			&context.lock_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
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
	) -> Result<(), Error> {
		let commit = swap.multisig.commit(keychain.secp())?;
		let mut sec_key = Self::refund_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot("Buyer Fn sign_refund_slate(), refund slate participant data is already initialized".to_string()));
		}

		// Add multisig input to slate
		tx_add_input(slate, commit)?;

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
			keychain.secp(),
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
	) -> Result<SecretKey, Error> {
		let bcontext = context.unwrap_buyer()?;

		// Partial multisig input, redeem output, offset
		let sum = BlindSum::new()
			.add_key_id(bcontext.output.to_value_path(swap.redeem_slate.amount))
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(keychain, context)?,
			))
			.sub_blinding_factor(swap.redeem_slate.tx_or_err()?.offset.clone());
		let sec_key = keychain.blind_sum(&sum)?.secret_key(keychain.secp())?;

		Ok(sec_key)
	}

	fn build_redeem_slate<K: Keychain>(
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let bcontext = context.unwrap_buyer()?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Buyer Fn build_redeem_slate(), redeem slate participant data is not empty"
					.to_string(),
			));
		}

		// Build slate
		slate.fee = tx_fee(1, 1, 1);
		slate.amount = swap.primary_amount - slate.fee;
		let mut elems = Vec::new();
		elems.push(build::output(slate.amount, bcontext.output.clone()));
		slate.add_transaction_elements(keychain, &proof::ProofBuilder::new(keychain), elems)?;

		#[cfg(test)]
		{
			slate.tx_or_err_mut()?.offset = if is_test_mode() {
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
			slate.tx_or_err_mut()?.offset =
				BlindingFactor::from_secret_key(SecretKey::new(keychain.secp(), &mut thread_rng()));
		}

		// Add multisig input to slate
		tx_add_input(slate, swap.multisig.commit(keychain.secp())?)?;

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
	) -> Result<(), Error> {
		let id = swap.participant_id;
		let other_id = swap.other_participant_id();
		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate;
		if slate
			.participant_data
			.get(id)
			.ok_or(Error::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for this party".to_string()))?
			.is_complete()
		{
			return Err(Error::OneShot("Buyer Fn finalize_redeem_slate() redeem slate is already initialized".to_string()));
		}

		// Replace participant
		let _ = mem::replace(
			slate
				.participant_data
				.get_mut(other_id)
				.ok_or(Error::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for other party".to_string()))?,
			part,
		);

		// Sign + finalize slate
		slate.fill_round_2(
			keychain.secp(),
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
	) -> Result<(), Error> {
		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(Error::OneShot(
				"Buyer calculate_adaptor_signature(), miltisig is already initialized".to_string(),
			));
		}

		let sec_key = Self::redeem_tx_secret(keychain, swap, context)?;
		let (pub_nonce_sum, pub_blind_sum, message) =
			swap.redeem_tx_fields(&swap.redeem_slate, keychain.secp())?;

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
