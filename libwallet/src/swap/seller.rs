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

#[cfg(feature = "test-support")]
use super::is_test_mode;
use super::message::*;
use super::multisig;
use super::swap;
use super::swap::{signature_as_secret, tx_add_input, tx_add_output, Swap, SwapTradeTransport};
use super::types::*;
use super::{Error, Keychain, CURRENT_VERSION};
use crate::swap::fsm::state::StateId;
use crate::{NodeClient, Slate, SlateVersion, VersionedSlate};
use mwc_wallet_util::mwc_core::libtx::{build, proof, tx_fee};
use mwc_wallet_util::mwc_crates::chrono::{TimeZone, Utc};
use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
use mwc_wallet_util::mwc_crates::secp::aggsig;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_keychain::{BlindSum, BlindingFactor};

use crate::slate::SlateCtx;
use mwc_wallet_util::mwc_core::global;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::uuid::Uuid;

/// Seller API. Bunch of methods that cover seller action for MWC swap
/// This party is Selling MWC and buying BTC
pub struct SellApi {}

impl SellApi {
	/// Start a swap
	/// This will create an object to track the swap state,
	/// as well as an offer to send to the counterparty
	/// It assumes that the Context has already been populated with
	/// the correct values for key derivation paths and nonces
	pub fn create_swap_offer<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		mwc_anchor_height: u64,
		seller_lock_first: bool,
		mwc_confirmations: u64,
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
		communication_method: String,
		buyer_destination_address: String,
		electrum_node_uri1: Option<String>,
		electrum_node_uri2: Option<String>,
		eth_swap_contract_address: Option<String>,
		erc20_swap_contract_address: Option<String>,
		eth_infura_project_id: Option<String>,
		eth_redirect_to_private_wallet: Option<bool>,
		dry_run: bool,
		tag: Option<String>,
		node_client: &C,
	) -> Result<Swap, Error> {
		validate_confirmation_requirements(mwc_confirmations, secondary_confirmations)?;
		// Persist and negotiate the allowance using the existing timing field, so
		// both peers use identical deadline arithmetic and old trades keep theirs.
		let secondary_confirmations = if secondary_currency.is_ethereum_family() {
			secondary_confirmations.max(super::ethereum::ETH_FINALITY_PLANNING_SLOTS)
		} else {
			secondary_confirmations
		};
		#[cfg(feature = "test-support")]
		let test_mode = is_test_mode();
		let scontext = context.unwrap_seller()?;
		let multisig = multisig::Builder::new(
			2,
			primary_amount,
			false,
			0,
			context.multisig_nonce.clone(),
			None,
		);

		let now_ts = swap::get_cur_time();
		let started = Utc
			.timestamp_opt(now_ts, 0)
			.single()
			.ok_or_else(|| Error::Generic(format!("Invalid UNIX timestamp: {}", now_ts)))?;

		let ls = Slate::blank(2, false)?;

		#[cfg(feature = "test-support")]
		let id = if test_mode {
			Uuid::parse_str("4fc16adb-9f32-4441-b0c1-b4de076a1972").unwrap()
		} else {
			ls.id.clone()
		};

		#[cfg(not(feature = "test-support"))]
		let id = ls.id.clone();

		let network = Network::current_network(context_id)?;
		let secondary_fee_units = secondary_currency.get_default_fee(&network);
		let swap_trade_transport = Some(SwapTradeTransport::from_selection(
			&communication_method,
			buyer_destination_address.clone(),
		)?);

		let mut swap = Swap {
			id,
			version: CURRENT_VERSION,
			network,
			role: Role::Seller("".to_string(), 0), // will be updated later
			communication_method,
			communication_address: buyer_destination_address,
			swap_trade_transport,
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
			lock_slate: SlateCtx {
				slate: ls,
				network_name: Some(global::get_network_name(context_id)),
			},
			refund_slate: SlateCtx {
				slate: Slate::blank(2, false)?,
				network_name: Some(global::get_network_name(context_id)),
			},
			redeem_slate: SlateCtx {
				slate: Slate::blank(2, false)?,
				network_name: Some(global::get_network_name(context_id)),
			},
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
			posted_secondary_height: None,
			journal: Vec::new(),
			secondary_fee_units,
			electrum_node_uri1,
			electrum_node_uri2,
			eth_swap_contract_address,
			erc20_swap_contract_address,
			eth_infura_project_id,
			eth_redirect_to_private_wallet,
			last_process_error: None,
			last_check_error: None,
			wait_for_backup1: false,
			tag,
			other_lock_first_done: false,
			marketplace_winner_lease_expires_at: None,
			received_offer_fingerprint: None,
			received_offer_content_fingerprint: None,
			processed_incoming_ack1: None,
			processed_incoming_ack2: None,
			marketplace_cancel_notification: None,
			pending_marketplace_cancel_notification: false,
			marketplace_cancel_notification_nonce: None,
			marketplace_signing_address_index: None,
			marketplace_received_cancel_nonce: None,
		};

		swap.add_journal_message("Swap offer created".to_string());

		let mwc_lock_time = swap.get_time_mwc_lock()?;
		let start_time = swap.get_time_start();
		// Apply the same absolute deadline policy used by incoming offer
		// validation and the BTC/ETH builders. This keeps the wallet from creating
		// an offer that its counterparty must reject at deposit time.
		swap::validate_secondary_lock_time(swap.get_time_secondary_lock_script()?, start_time)?;

		// Lock slate
		let lock_slate = &mut swap.lock_slate.slate;

		#[cfg(feature = "test-support")]
		if test_mode {
			lock_slate.id = Uuid::parse_str("55b79f54-c40d-45e1-9544-a52dcf426db2").unwrap();
		}

		lock_slate.fee = tx_fee(context_id, scontext.inputs.len(), 2, 1)?;
		lock_slate.amount = primary_amount;
		lock_slate.height = mwc_anchor_height;

		// Refund slate
		let refund_slate = &mut swap.refund_slate.slate;
		#[cfg(feature = "test-support")]
		if test_mode {
			refund_slate.id = Uuid::parse_str("703fac15-913c-4e66-a7c2-5f648ca4ca7d").unwrap();
		}
		refund_slate.fee = tx_fee(context_id, 1, 1, 1)?;
		if !(dry_run && primary_amount == 0) {
			if primary_amount <= refund_slate.fee {
				return Err(Error::Generic(
					"MWC amount to trade is too low, it doesn't cover the fees".to_string(),
				));
			}
		}

		refund_slate.height = mwc_anchor_height;
		// Calculating lock height from locking time. For MWC the mining speed is about 1 minute
		if mwc_lock_time < start_time {
			return Err(Error::InvalidMessageData(format!(
				"MWC lock time precedes swap start time, mwc_lock_time={} start_time={}",
				mwc_lock_time, start_time
			)));
		}
		// The time ordering check proves this subtraction cannot underflow.
		// lock_height = mwc_anchor_height + (mwc_lock_time - start_time) as u64 / 60 + 1
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "mwc_lock_time is checked not to precede start_time"
		)]
		let lock_seconds = mwc_lock_time - start_time;
		let lock_seconds = u64::try_from(lock_seconds).map_err(|e| {
			Error::DataOverflow(format!(
				"SellApi::create_swap_offer, MWC lock duration does not fit u64, lock_seconds={} error={}",
				lock_seconds, e
			))
		})?;
		let lock_height_without_buffer = mwc_anchor_height
			.checked_add(lock_seconds / 60)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"SellApi::create_swap_offer, MWC refund lock height overflow, height={} lock_seconds={} seconds_per_block=60",
					mwc_anchor_height, lock_seconds
				))
			})?;
		let lock_height = lock_height_without_buffer.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"SellApi::create_swap_offer, MWC refund lock height buffer overflow, lock_height={} buffer_blocks=1",
				lock_height_without_buffer
			))
		})?;
		refund_slate.set_lock_height(lock_height)?;
		refund_slate.amount = primary_amount.checked_sub(refund_slate.fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"SellApi::create_swap_offer, primary amount is smaller than refund fee, primary_amount={} refund_fee={}",
				primary_amount, refund_slate.fee
			))
		})?;

		let checked_lock_height = refund_slate.get_lock_height_check()?;
		let lock_blocks = checked_lock_height.checked_sub(refund_slate.height).ok_or_else(|| {
			Error::DataOverflow(format!(
				"SellApi::create_swap_offer, refund lock height precedes slate height, lock_height={} slate_height={}",
				checked_lock_height, refund_slate.height
			))
		})?;
		if lock_blocks > swap::MAX_MWC_REFUND_LOCK_BLOCKS {
			return Err(Error::Generic(
				"MWC locking time interval exceeds 30 days. Is it a scam or mistake?".to_string(),
			));
		}

		// Redeem slate
		let redeem_slate = &mut swap.redeem_slate.slate;
		#[cfg(feature = "test-support")]
		if test_mode {
			redeem_slate.id = Uuid::parse_str("fc750aae-035f-4c6c-bb0c-05aabc764f8e").unwrap();
		}
		redeem_slate.amount = refund_slate.amount;
		redeem_slate.height = refund_slate.height;
		redeem_slate.fee = refund_slate.fee;

		// Make sure we have enough funds
		let mut sum_in: u64 = 0;
		for input in &scontext.inputs {
			sum_in = sum_in.checked_add(input.amount).ok_or_else(|| {
				Error::DataOverflow(format!(
					"SellApi::create_swap_offer, swap input amount overflow, accumulated_input={} input_amount={}",
					sum_in, input.amount
				))
			})?;
		}

		// TODO: no change output if amounts match up exactly
		let change = if !(dry_run && primary_amount == 0) {
			let required = primary_amount.checked_add(lock_slate.fee).ok_or_else(|| {
				Error::DataOverflow(format!(
					"SellApi::create_swap_offer, swap required amount overflow, primary_amount={} lock_fee={}",
					primary_amount, lock_slate.fee
				))
			})?;
			if sum_in <= required {
				return Err(Error::InsufficientFunds(required.saturating_add(1), sum_in));
			}
			// change
			// The insufficient-funds branch returned unless sum_in > required.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "the preceding branch returns when sum_in <= required"
			)]
			{
				sum_in - required
			}
		} else {
			0
		};

		// The redeem address is always needed for BTC-family swaps. For Ethereum-family
		// swaps it is used when the proceeds are redirected to the seller's private
		// wallet; validate it upfront in that case (includes the EIP-55 checksum).
		if secondary_currency.is_btc_family() || eth_redirect_to_private_wallet == Some(true) {
			secondary_currency.validate_address(context_id, &secondary_redeem_address)?;
		}
		swap.role = Role::Seller(secondary_redeem_address, change);

		if !dry_run {
			Self::build_multisig(secp, keychain, &mut swap, context)?;
			Self::build_lock_slate(context_id, secp, keychain, &mut swap, context)?;
			Self::build_refund_slate(context_id, secp, keychain, &mut swap, context)?;
			Self::build_redeem_participant(secp, keychain, &mut swap, context)?;
			let lock = swap
				.lock_slate
				.slate
				.node_preflight_transaction(context_id, secp, false)?;
			let mut refund = swap
				.refund_slate
				.slate
				.node_preflight_transaction(context_id, secp, false)?;
			refund.allow_future_height = true;
			crate::transaction_preflight::check_request(
				node_client,
				&crate::transaction_preflight::MempoolAcceptRequest {
					transactions: vec![lock, refund],
					expected_tip: None,
				},
			)?;
		}

		Ok(swap)
	}

	/// Process 'accepted offer' message from the buyer
	pub fn accepted_offer<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		accept_offer: AcceptOfferUpdate,
		node_client: &C,
	) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"Seller accepted_offer called for buyer swap".to_string(),
			));
		}
		let marketplace_winner_lease_expires_at = accept_offer.marketplace_winner_lease_expires_at;

		// Validate every peer-controlled participant before multisig finalization
		// or slate mutation. Partial transaction signatures do not authenticate
		// participant ids or optional signed messages.
		swap::validate_swap_slate_participants(
			secp,
			&swap.lock_slate.slate,
			&[(0, false)],
			"Stored seller lock slate",
		)?;
		swap::validate_swap_slate_participants(
			secp,
			&swap.refund_slate.slate,
			&[(0, false)],
			"Stored seller refund slate",
		)?;
		swap::validate_swap_participant(
			secp,
			&accept_offer.lock_participant,
			1,
			true,
			"Accepted-offer lock slate",
		)?;
		swap::validate_swap_participant(
			secp,
			&accept_offer.refund_participant,
			1,
			true,
			"Accepted-offer refund slate",
		)?;

		let mut staged_swap = swap.clone();
		// Finalize multisig proof
		let proof = Self::finalize_multisig(
			secp,
			keychain,
			&mut staged_swap,
			context,
			accept_offer.multisig,
		)?;

		// Update slates
		let commit = staged_swap.multisig.commit(secp)?;
		Self::finalize_lock_slate(
			context_id,
			secp,
			keychain,
			&mut staged_swap,
			context,
			commit.clone(),
			proof,
			accept_offer.lock_participant,
		)?;
		Self::finalize_refund_slate(
			context_id,
			secp,
			keychain,
			&mut staged_swap,
			context,
			commit.clone(),
			accept_offer.refund_participant,
		)?;

		staged_swap.redeem_public = Some(accept_offer.redeem_public);
		staged_swap.marketplace_winner_lease_expires_at = marketplace_winner_lease_expires_at;
		staged_swap.validate_lock_and_refund_slates(context_id, node_client, secp)?;
		*swap = staged_swap;

		Ok(())
	}

	/// Seller initializing the redeem slate. At that moment Both BTC and MWC are expected to be at
	/// the locked slated published and has enough confirmations.
	/// Result:
	/// 	swap.redeem_slate
	// 	 	swap.adaptor_signature
	pub fn init_redeem<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		init_redeem: InitRedeemUpdate,
		node_client: &C,
	) -> Result<(), Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"Seller init_redeem called for buyer swap".to_string(),
			));
		}

		// This function should only be called once
		if swap.adaptor_signature.is_some() {
			return Err(Error::OneShot(
				"Seller Fn init_redeem() multisig is empty".to_string(),
			));
		}

		let mut redeem_slate: Slate = init_redeem
			.redeem_slate
			.into_slate_plain(context_id, true)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"SellApi::init_redeem, redeem slate cannot be decoded: {}",
					error
				))
			})?;

		// Bind the exact unsigned {0, 1} participant transcript, transaction
		// excess, and Plain kernel message before verifying or creating any
		// signature. The returned aggregate is the single challenge key used by
		// both the adaptor signature and round 2.
		let redeem_fields = swap.redeem_tx_fields(context_id, &redeem_slate, secp)?;
		let buyer_participant = redeem_slate
			.participant_data
			.iter()
			.find(|participant| participant.id == 1)
			.ok_or_else(|| {
				Error::InvalidMessageData(
					"SellApi::init_redeem, buyer participant 1 is missing".to_string(),
				)
			})?;
		if !aggsig::verify_single(
			secp,
			&init_redeem.adaptor_signature,
			&redeem_fields.message,
			Some(&redeem_fields.pub_nonce_sum),
			&buyer_participant.public_blind_excess,
			&redeem_fields.pub_blind_sum,
			Some(&swap.redeem_public.ok_or(Error::UnexpectedAction(
				"Seller Fn init_redeem() redeem pub key is empty".to_string(),
			))?),
			true,
		)
		.map_err(|error| {
			Error::InvalidMessageData(format!(
				"SellApi::init_redeem, adaptor signature uses invalid peer data: {}",
				error
			))
		})? {
			return Err(Error::InvalidAdaptorSignature);
		}
		// Store exactly the body-derived excess that was proven equal to the
		// participant aggregate. Recalculating an unbound value here would reopen
		// the adaptor/partial-signature mismatch.
		Self::set_redeem_excess(&mut redeem_slate, redeem_fields.tx_excess)?;

		let mut staged_swap = swap.clone();
		staged_swap.redeem_slate.slate = redeem_slate;
		staged_swap.adaptor_signature = Some(init_redeem.adaptor_signature);
		Self::sign_redeem_slate(context_id, secp, keychain, &mut staged_swap, context)?;

		// A partial adaptor verification binds the challenge, but not the buyer's
		// declared nonce or its sign. Combine with our still-private partial
		// signature, then verify against the declared aggregate nonce in full
		// signature mode. This also enforces the aggregate nonce's Jacobi sign.
		// Do not publish or commit staged_swap until this check succeeds.
		let seller_signature = staged_swap
			.redeem_slate
			.slate
			.participant_with_id(staged_swap.participant_id)
			.and_then(|participant| participant.part_sig)
			.ok_or_else(|| {
				Error::UnexpectedAction(
					"SellApi::init_redeem, seller partial signature is missing".to_string(),
				)
			})?;
		let combined_adaptor = aggsig::add_signatures_single(
			secp,
			vec![&init_redeem.adaptor_signature, &seller_signature],
			&redeem_fields.pub_nonce_sum,
		)
		.map_err(|_| Error::InvalidAdaptorSignature)?;
		if !aggsig::verify_single(
			secp,
			&combined_adaptor,
			&redeem_fields.message,
			Some(&redeem_fields.pub_nonce_sum),
			&redeem_fields.pub_blind_sum,
			&redeem_fields.pub_blind_sum,
			// The existing adaptor check above requires this key to be present.
			swap.redeem_public.as_ref(),
			false,
		)
		.map_err(|_| Error::InvalidAdaptorSignature)?
		{
			return Err(Error::InvalidAdaptorSignature);
		}
		crate::transaction_preflight::check_slate(
			context_id,
			node_client,
			&staged_swap.redeem_slate.slate,
			secp,
			true,
		)?;
		*swap = staged_swap;

		Ok(())
	}

	/// Calculating the secret that allow to redeem BTC.
	/// At this point Buyer already get his MWC, so now Seller should get a revealed secret and get BTCs
	pub fn calculate_redeem_secret(secp: &Secp256k1, swap: &Swap) -> Result<SecretKey, Error> {
		let adaptor_signature = signature_as_secret(
			secp,
			&swap.adaptor_signature.ok_or(Error::UnexpectedAction(
				"Seller Fn calculate_redeem_secret() multisig is empty".to_string(),
			))?,
		)?;
		let signature = signature_as_secret(secp,
			&swap
				.redeem_slate
				.slate
				.tx_or_err()?
				.kernels()
				.get(0)
				.ok_or(Error::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, no kernels found".to_string()))?
				.excess_sig,
		)?;
		let seller_signature = signature_as_secret(secp,
				&swap
					.redeem_slate
					.slate
					.participant_with_id(swap.participant_id)
					.ok_or(Error::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, participant not found".to_string()))?
				.part_sig
				.ok_or(Error::UnexpectedAction("Seller Fn calculate_redeem_secret() redeem slate is not initialized, participant signature not found".to_string()))?,
		)?;

		let redeem = secp.blind_sum(vec![adaptor_signature, seller_signature], vec![signature])?;
		let redeem_pub = PublicKey::from_secret_key(secp, &redeem)?;
		if swap.redeem_public != Some(redeem_pub) {
			// If this happens - mean that swap is broken, somewhere there is a security flaw. Probably didn't check something.
			return Err(Error::Generic(
				"Redeem secret doesn't match - this should never happen".into(),
			));
		}

		Ok(redeem)
	}

	/// Generate Offer message.
	/// Note: from_address need to be update by the caller because only caller knows about communication layer.
	pub fn offer_message(
		context_id: u32,
		swap: &Swap,
		secondary_update: SecondaryUpdate,
	) -> Result<Message, Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"SellApi::offer_message, swap role is not seller".to_string(),
			));
		}
		let redeem_participant = swap
			.redeem_slate
			.slate
			.participant_with_id(swap.participant_id)
			.ok_or_else(|| {
				Error::UnexpectedAction(format!(
					"SellApi::offer_message, seller participant is missing, participant_id={} participant_count={}",
					swap.participant_id,
					swap.redeem_slate.slate.participant_data.len()
				))
			})?;
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
				lock_slate: VersionedSlate::into_version_plain(
					context_id,
					&swap.lock_slate.slate,
					SlateVersion::V2, // V2 should satisfy our needs, dont adding extra
				)?,
				refund_slate: VersionedSlate::into_version_plain(
					context_id,
					&swap.refund_slate.slate,
					SlateVersion::V2, // V2 should satisfy our needs, dont adding extra
				)?,
				redeem_participant,
				mwc_confirmations: swap.mwc_confirmations,
				secondary_confirmations: swap.secondary_confirmations,
				message_exchange_time_sec: swap.message_exchange_time_sec,
				redeem_time_sec: swap.redeem_time_sec,
			}),
			secondary_update,
		)
	}

	/// Generate redeem message
	pub fn redeem_message(swap: &Swap) -> Result<Message, Error> {
		if !swap.is_seller() {
			return Err(Error::UnexpectedAction(
				"SellApi::redeem_message, swap role is not seller".to_string(),
			));
		}
		if swap.secondary_currency.is_btc_family() {
			swap.secondary_data
				.unwrap_btc()?
				.accepted_redeem_inputs(swap.secondary_amount)?;
		}
		let redeem_participant = swap
			.redeem_slate
			.slate
			.participant_with_id(swap.participant_id)
			.ok_or_else(|| {
				Error::UnexpectedAction(format!(
					"SellApi::redeem_message, seller participant is missing, participant_id={} participant_count={}",
					swap.participant_id,
					swap.redeem_slate.slate.participant_data.len()
				))
			})?;
		swap.message(
			Update::Redeem(RedeemUpdate { redeem_participant }),
			SecondaryUpdate::Empty,
		)
	}

	// ----------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------
	// ----------------------------------------------------------------------------------------------

	fn build_multisig<K: Keychain>(
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let multisig_secret = swap.multisig_secret(secp, keychain, context)?;
		let multisig = &mut swap.multisig;

		// Round 1
		multisig.create_participant(secp, &multisig_secret)?;
		multisig.round_1(secp, &multisig_secret)?;

		Ok(())
	}

	fn finalize_multisig<K: Keychain>(
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: multisig::ParticipantData,
	) -> Result<RangeProof, Error> {
		let sec_key = swap.multisig_secret(secp, keychain, context)?;

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
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let scontext = context.unwrap_seller()?;
		let (_, change) = swap.unwrap_seller()?;
		let mut sum = BlindSum::new();

		// Input(s)
		for input in &scontext.inputs {
			sum = sum.sub_key_id(input.key_id.to_value_path(input.amount)?);
		}

		// Change output, partial multisig output, offset
		sum = sum
			.add_key_id(scontext.change_output.to_value_path(change)?)
			.add_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(secp, keychain, context)?,
			))
			.sub_blinding_factor(swap.lock_slate.slate.tx_or_err()?.offset.clone());
		let sec_key = keychain.blind_sum(secp, &sum)?.secret_key(secp)?;

		Ok(sec_key)
	}

	fn build_lock_slate<K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let (_, change) = swap.unwrap_seller()?;
		let scontext = context.unwrap_seller()?;

		// This function should only be called once
		let slate = &mut swap.lock_slate.slate;
		if slate.participant_data.len() > 0 {
			return Err(Error::OneShot(
				"Seller Fn build_lock_slate() lock slate is already initialized".to_string(),
			));
		}

		// Build lock slate
		// The multisig output is missing because it is not yet fully known
		let mut elems = Vec::new();
		for input in &scontext.inputs {
			elems.push(build::feature_input(
				input.amount,
				input.features,
				input.key_id.clone(),
			));
		}
		// The seller's change output is wallet-generated: tag its rangeproof with
		// the anti-replay build height like every other wallet output.
		elems.push(build::height_tagged_output(
			change,
			scontext.change_output.clone(),
			slate.height,
		));
		let proof_builder = proof::ProofBuilder::new(secp, keychain)?;
		slate.add_transaction_elements(context_id, secp, keychain, &proof_builder, elems)?;
		slate.tx_or_err_mut()?.offset =
			BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?);

		#[cfg(feature = "test-support")]
		if is_test_mode() {
			slate.tx_or_err_mut()?.offset = BlindingFactor::from_hex(
				"d9da697c9c8bf7ff85116dd401f53e4d58bc0155fb6db56b15a99aa8884a44e9",
			)
			.unwrap()
		}

		let mut sec_key = Self::lock_tx_secret(secp, keychain, swap, context)?;
		let slate = &mut swap.lock_slate.slate;

		// Add participant to slate
		slate.fill_round_1(
			secp,
			keychain,
			&mut sec_key,
			&context.lock_nonce,
			swap.participant_id,
			None,
			#[cfg(feature = "test-support")]
			false,
		)?;

		Ok(())
	}

	fn finalize_lock_slate<K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		proof: RangeProof,
		part: crate::ParticipantData,
	) -> Result<(), Error> {
		let sec_key = Self::lock_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate.slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Seller Fn finalize_lock_slate() lock slate is already initialized".to_string(),
			));
		}

		// Add participant to slate
		slate.participant_data.push(part);
		swap::validate_swap_slate_participants(
			secp,
			slate,
			&[(0, false), (1, true)],
			"Accepted-offer lock slate",
		)?;

		// Add multisig output to slate
		tx_add_output(context_id, slate, commit, proof)?;

		// Sign + finalize slate
		slate
			.fill_round_2(
				context_id,
				secp,
				&sec_key,
				&context.lock_nonce,
				swap.participant_id,
			)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Accepted-offer lock participant has an invalid partial signature: {}",
					error
				))
			})?;
		slate.finalize(context_id, secp).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Accepted-offer lock slate cannot be finalized: {}",
				error
			))
		})?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let scontext = context.unwrap_seller()?;

		// Partial multisig input, refund output, offset
		let sum = BlindSum::new()
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(secp, keychain, context)?,
			))
			.add_key_id(
				scontext
					.refund_output
					.to_value_path(swap.refund_amount()?)?,
			)
			.sub_blinding_factor(swap.refund_slate.slate.tx_or_err()?.offset.clone());
		let sec_key = keychain.blind_sum(secp, &sum)?.secret_key(secp)?;

		Ok(sec_key)
	}

	fn build_refund_slate<K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let scontext = context.unwrap_seller()?;
		let refund_amount = swap.refund_amount()?;

		// This function should only be called once
		let slate = &mut swap.refund_slate.slate;
		if slate.participant_data.len() > 0 {
			return Err(Error::OneShot(
				"Seller Fn build_refund_slate() refund slate is already initialized".to_string(),
			));
		}

		// Build refund slate
		// The multisig input is missing because it is not yet fully known
		let mut elems = Vec::new();
		// The seller's refund output is wallet-generated: tag its rangeproof with
		// the anti-replay build height like every other wallet output.
		elems.push(build::height_tagged_output(
			refund_amount,
			scontext.refund_output.clone(),
			slate.height,
		));
		let proof_builder = proof::ProofBuilder::new(secp, keychain)?;
		slate.add_transaction_elements(context_id, secp, keychain, &proof_builder, elems)?;
		slate.tx_or_err_mut()?.offset =
			BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?);

		#[cfg(feature = "test-support")]
		if is_test_mode() {
			slate.tx_or_err_mut()?.offset = BlindingFactor::from_hex(
				"53ac7d0ad9833568cf63dfa8aa607e2b27be525111b1e0de92aa0caa50f838ae",
			)
			.unwrap();
		}

		let mut sec_key = Self::refund_tx_secret(secp, keychain, swap, context)?;
		let slate = &mut swap.refund_slate.slate;

		// Add participant to slate
		slate.fill_round_1(
			secp,
			keychain,
			&mut sec_key,
			&context.refund_nonce,
			swap.participant_id,
			None,
			#[cfg(feature = "test-support")]
			false,
		)?;

		Ok(())
	}

	fn finalize_refund_slate<K: Keychain>(
		context_id: u32,
		secp: &mut Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		commit: Commitment,
		part: crate::ParticipantData,
	) -> Result<(), Error> {
		let sec_key = Self::refund_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate.slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Seller Fn finalize_refund_slate() refund slate is already initialized".to_string(),
			));
		}

		// Add participant to slate
		slate.participant_data.push(part);
		swap::validate_swap_slate_participants(
			secp,
			slate,
			&[(0, false), (1, true)],
			"Accepted-offer refund slate",
		)?;

		// Add multisig input to slate
		tx_add_input(context_id, slate, commit)?;

		// Sign + finalize slate
		slate
			.fill_round_2(
				context_id,
				secp,
				&sec_key,
				&context.refund_nonce,
				swap.participant_id,
			)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Accepted-offer refund participant has an invalid partial signature: {}",
					error
				))
			})?;
		slate.finalize(context_id, secp).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Accepted-offer refund slate cannot be finalized: {}",
				error
			))
		})?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn redeem_tx_secret<K: Keychain>(
		secp: &Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
		// Partial multisig input
		let sum = BlindSum::new().sub_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(secp, keychain, context)?,
		));
		let sec_key = keychain.blind_sum(secp, &sum)?.secret_key(secp)?;

		Ok(sec_key)
	}

	fn build_redeem_participant<K: Keychain>(
		secp: &Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let sec_key = Self::redeem_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate.slate;
		if slate.participant_data.len() > 0 {
			return Err(Error::OneShot(
				"Seller Fn build_redeem_participant() redeem slate is already initialized"
					.to_string(),
			));
		}

		// Build participant
		let participant_id = u64::try_from(swap.participant_id).map_err(|e| {
			Error::DataOverflow(format!(
				"SellApi::build_redeem_participant, participant id does not fit u64, participant_id={} error={}",
				swap.participant_id, e
			))
		})?;
		let participant = crate::ParticipantData {
			id: participant_id,
			public_blind_excess: PublicKey::from_secret_key(secp, &sec_key)?,
			public_nonce: PublicKey::from_secret_key(secp, &context.redeem_nonce)?,
			part_sig: None,
			message: None,
			message_sig: None,
		};
		slate.participant_data.push(participant);

		Ok(())
	}

	fn set_redeem_excess(redeem_slate: &mut Slate, excess: Commitment) -> Result<(), Error> {
		redeem_slate
			.tx_or_err_mut()?
			.body
			.kernels
			.first_mut()
			.ok_or_else(|| {
				Error::InvalidMessageData(
					"SellApi::set_redeem_excess, redeem transaction kernel is missing".into(),
				)
			})?
			.excess = excess;
		Ok(())
	}

	fn sign_redeem_slate<K: Keychain>(
		context_id: u32,
		secp: &Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let id = swap.participant_id;
		let sec_key = Self::redeem_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate.slate;
		let participant = slate
			.participant_data
			.iter()
			.find(|participant| participant.id == id as u64)
			.ok_or_else(|| {
			Error::UnexpectedAction(format!(
				"SellApi::sign_redeem_slate, seller participant is missing, participant_id={} participant_count={}",
				id,
				slate.participant_data.len()
			))
		})?;
		if participant.is_complete() {
			return Err(Error::OneShot("Seller Fn sign_redeem_slate() redeem slate participant data is already initilaized".to_string()));
		}

		// Sign slate
		slate.fill_round_2(
			context_id,
			secp,
			&sec_key,
			&context.redeem_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}
}
