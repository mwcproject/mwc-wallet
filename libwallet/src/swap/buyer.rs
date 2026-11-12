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
use super::swap;
use super::swap::{tx_add_input, tx_add_output, Swap};
use super::types::*;
use super::{Error, Keychain, CURRENT_VERSION};
use crate::slate::SlateCtx;
use crate::swap::bitcoin::{BtcData, BtcUpdate};
use crate::swap::ethereum::{EthData, EthUpdate, EthereumWallet};
use crate::swap::fsm::state::StateId;
use crate::swap::multisig;
use crate::swap::owner_eth::get_eth_balance;
use crate::{NodeClient, Slate, SlateVersion, VersionedSlate};
use mwc_wallet_util::mwc_core::core::Committed;
use mwc_wallet_util::mwc_core::core::KernelFeatures;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_core::libtx::{build, proof, tx_fee};
use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
use mwc_wallet_util::mwc_crates::secp;
use mwc_wallet_util::mwc_crates::secp::aggsig;
use mwc_wallet_util::mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_wallet_util::mwc_crates::secp::pedersen::RangeProof;
use mwc_wallet_util::mwc_crates::uuid::Uuid;
use mwc_wallet_util::mwc_keychain::{BlindSum, BlindingFactor, SwitchCommitmentType};
use mwc_wallet_util::mwc_util::to_hex;
use std::collections::HashSet;

/// Buyer API. Bunch of methods that cover buyer action for MWC swap
/// This party is Buying MWC and selling BTC
pub struct BuyApi {}

pub(crate) struct StaticallyValidatedOffer {
	offer: OfferUpdate,
	secondary_update: SecondaryUpdate,
	lock_slate: Slate,
	refund_slate: Slate,
	remaining_lock_seconds: u64,
	mwc_lock_time: i64,
}

pub(crate) struct ValidatedOffer {
	offer: OfferUpdate,
	secondary_update: SecondaryUpdate,
	lock_slate: Slate,
	refund_slate: Slate,
	final_tip_height: u64,
	mwc_lock_time: i64,
}

impl StaticallyValidatedOffer {
	/// Hex-encoded commitments of the offer's MWC lock inputs, for cheap set
	/// comparison against stored trades. Two active trades cannot share lock
	/// inputs: only one lock transaction can ever confirm.
	pub(crate) fn lock_input_commitments(&self) -> Result<HashSet<String>, Error> {
		let mut commits = HashSet::new();
		for input in self.lock_slate.tx_or_err()?.inputs_committed()? {
			commits.insert(to_hex(&input?.0));
		}
		Ok(commits)
	}
}

impl ValidatedOffer {
	pub(crate) fn offer(&self) -> &OfferUpdate {
		&self.offer
	}

	pub(crate) fn ensure_not_expired(&self) -> Result<(), Error> {
		let now = swap::get_cur_time();
		if self.mwc_lock_time <= now {
			return Err(Error::InvalidMessageData(format!(
				"MWC lock time is already expired, lock_time={} now={}",
				self.mwc_lock_time, now
			)));
		}
		Ok(())
	}
}

impl BuyApi {
	fn validate_refund_lock_height(
		current_height: u64,
		remaining_lock_seconds: u64,
		refund_lock_height: u64,
	) -> Result<(), Error> {
		if refund_lock_height <= current_height {
			return Err(Error::InvalidMessageData(format!(
				"Refund lock height must be above the current chain tip, lock_height={} current_height={}",
				refund_lock_height, current_height
			)));
		}
		let maximum_lock_height = current_height
			.checked_add(swap::MAX_MWC_REFUND_LOCK_BLOCKS)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::accept_swap_offer, maximum refund lock height overflow, current_height={} maximum_blocks={}",
					current_height,
					swap::MAX_MWC_REFUND_LOCK_BLOCKS
				))
			})?;
		if refund_lock_height > maximum_lock_height {
			return Err(Error::InvalidMessageData(format!(
				"Refund lock height exceeds the 30-day protocol limit, lock_height={} maximum_lock_height={}",
				refund_lock_height, maximum_lock_height
			)));
		}

		// The tolerance applies only to the estimated number of blocks still to
		// be mined. Applying it to the absolute height would subtract 10% of the
		// entire chain history and could make an already-mature refund acceptable.
		let expected_future_blocks = remaining_lock_seconds / 60;
		let _expected_lock_height = current_height
			.checked_add(expected_future_blocks)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::accept_swap_offer, expected lock height overflow, current_height={} expected_future_blocks={}",
					current_height, expected_future_blocks
				))
			})?;
		let minimum_future_blocks = expected_future_blocks.checked_mul(9).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::accept_swap_offer, minimum future lock interval overflow, expected_future_blocks={} multiplier=9",
				expected_future_blocks
			))
		})? / 10;
		let minimum_lock_height = current_height
			.checked_add(minimum_future_blocks)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::accept_swap_offer, minimum lock height overflow, current_height={} minimum_future_blocks={}",
					current_height, minimum_future_blocks
				))
			})?;

		if refund_lock_height < minimum_lock_height {
			return Err(Error::InvalidMessageData(format!(
				"Refund lock slate doesn't preserve the required safety window, lock_height={} minimum_lock_height={}",
				refund_lock_height, minimum_lock_height
			)));
		}

		Ok(())
	}

	fn validate_offer_slate_participant(
		secp: &secp::Secp256k1,
		slate: &Slate,
		slate_name: &str,
	) -> Result<(), Error> {
		let stage = format!("{} offer slate", slate_name);
		swap::validate_swap_slate_participants(secp, slate, &[(0, false)], &stage)
	}

	fn validate_secondary_offer(
		offer: &OfferUpdate,
		secondary_update: &SecondaryUpdate,
	) -> Result<(), Error> {
		if offer.secondary_currency.is_btc_family() {
			if matches!(secondary_update, SecondaryUpdate::BTC(BtcUpdate::Offer(_))) {
				return Ok(());
			}
		} else {
			match secondary_update {
				SecondaryUpdate::ETH(EthUpdate::Offer(update))
					if update.redeem_address.is_some() =>
				{
					return Ok(());
				}
				SecondaryUpdate::ETH(EthUpdate::Offer(_)) => {
					return Err(Error::InvalidMessageData(
						"Ethereum swap offer is missing the required redeem address".to_string(),
					));
				}
				_ => {}
			}
		}
		Err(Error::InvalidMessageData(
			"Swap offer secondary payload does not match its currency or message type".to_string(),
		))
	}

	/// Validate every context-free property of an incoming offer: version,
	/// network, confirmation thresholds, slate structure, and timing. Runs
	/// without chain access, wallet state, or RPC, so it can be executed before
	/// acquiring swap locks or allocating durable HD child indices; a stream of
	/// unique invalid offers then cannot monopolize swap creation or burn
	/// derivation indices.
	///
	/// Returns a typed validation token to be passed to `validate_offer_node`.
	pub(crate) fn validate_offer_static(
		context_id: u32,
		secp: &secp::Secp256k1,
		offer: OfferUpdate,
		secondary_update: SecondaryUpdate,
	) -> Result<StaticallyValidatedOffer, Error> {
		if offer.version != CURRENT_VERSION {
			return Err(Error::IncompatibleVersion(offer.version, CURRENT_VERSION));
		}
		validate_confirmation_requirements(offer.mwc_confirmations, offer.secondary_confirmations)?;

		// Checking if the network match expected value
		if offer.network != Network::current_network(context_id)? {
			return Err(Error::UnexpectedNetwork(format!(
				", get offer for wrong network {:?}",
				offer.network
			)));
		}
		Self::validate_secondary_offer(&offer, &secondary_update)?;

		let now_ts = swap::get_cur_time();

		// Tolerating 15 seconds clock difference. We don't want surprises with clocks.
		let tolerated_now = now_ts.checked_add(15).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::validate_offer_static, clock tolerance timestamp overflow, now_timestamp={} tolerance_seconds=15",
				now_ts
			))
		})?;
		if offer.start_time.timestamp() > tolerated_now {
			return Err(Error::InvalidMessageData(
				"Buyer/Seller clock are out of sync".to_string(),
			));
		}

		// Multisig tx needs to be unlocked and valid. Let's take a look at what we get.
		let lock_slate: Slate = offer
			.lock_slate
			.into_slate_plain(context_id, true)
			.map_err(|error| {
				Error::InvalidMessageData(format!("Lock slate cannot be decoded: {}", error))
			})?;
		// Swap confirmation tracking requires non-compact slates to derive
		// the kernel excess from each transaction body.
		if lock_slate.compact_slate {
			return Err(Error::InvalidMessageData(
				"Swap offers require a non-compact lock slate".to_string(),
			));
		}
		lock_slate
			.validate_transaction_read(context_id)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Lock slate transaction failed lightweight validation: {}",
					error
				))
			})?;
		if lock_slate.get_lock_height() > 0 {
			return Err(Error::InvalidLockHeightLockTx);
		}
		if lock_slate.amount != offer.primary_amount {
			return Err(Error::InvalidMessageData(
				"Lock Slate amount doesn't match offer".to_string(),
			));
		}
		let lock_tx = lock_slate.tx_or_err()?;
		let output_count = lock_tx.body.outputs.len();
		let expected_output_count = output_count.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::validate_offer_static, lock slate output count overflow, output_count={} expected_additional_outputs=1",
				output_count
			))
		})?;
		if lock_slate.fee
			!= tx_fee(
				context_id,
				lock_tx.body.inputs.len(),
				expected_output_count,
				1,
			)? {
			return Err(Error::InvalidMessageData(
				"Lock Slate fee doesn't match expected value".to_string(),
			));
		}
		if lock_slate.num_participants != 2 {
			return Err(Error::InvalidMessageData(
				"Lock Slate participans doesn't match expected value".to_string(),
			));
		}

		if lock_tx.body.kernels.len() != 1 {
			return Err(Error::InvalidMessageData(
				"Lock Slate invalid kernels".to_string(),
			));
		}

		let lock_kernel = lock_tx.body.kernels.first().ok_or_else(|| {
			Error::InvalidMessageData("Lock Slate transaction kernel is missing".to_string())
		})?;
		match lock_kernel.features {
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
				));
			}
		}

		// Inputs must be present. Their on-chain existence is verified by
		// validate_offer_node.
		if lock_tx.body.inputs.is_empty() {
			return Err(Error::InvalidMessageData(
				"Lock Slate empty inputs".to_string(),
			));
		}

		// Checking Refund slate.
		// Refund tx needs to be locked until exactly as offer specify. For MWC we are expecting one block every 1 minute.
		// So numbers should match with accuracy of few blocks.
		// Note!!! We can't verify exact number because we don't know what height seller get when he created the offer
		let refund_slate: Slate = offer
			.refund_slate
			.into_slate_plain(context_id, true)
			.map_err(|error| {
				Error::InvalidMessageData(format!("Refund slate cannot be decoded: {}", error))
			})?;
		if refund_slate.compact_slate {
			return Err(Error::InvalidMessageData(
				"Swap offers require a non-compact refund slate".to_string(),
			));
		}
		refund_slate
			.validate_transaction_read(context_id)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Refund slate transaction failed lightweight validation: {}",
					error
				))
			})?;
		// expecting at least half of the interval

		let refund_tx = refund_slate.tx_or_err()?;
		// The offered refund is partial: the buyer adds the one multisig input
		// after accepting it. Before that step it must contain no inputs, exactly
		// one seller refund output, and one HeightLocked kernel.
		if !refund_tx.body.inputs.is_empty()
			|| refund_tx.body.outputs.len() != 1
			|| refund_tx.body.kernels.len() != 1
		{
			return Err(Error::InvalidMessageData(format!(
				"Refund slate must contain no inputs, exactly one output, and one kernel; found inputs={} outputs={} kernels={}",
				refund_tx.body.inputs.len(),
				refund_tx.body.outputs.len(),
				refund_tx.body.kernels.len()
			)));
		}
		let refund_kernel = refund_tx.body.kernels.first().ok_or_else(|| {
			Error::InvalidMessageData("Refund Slate transaction kernel is missing".to_string())
		})?;
		let refund_lock_height = refund_slate.get_lock_height_check().map_err(|error| {
			Error::InvalidMessageData(format!(
				"Refund slate has invalid lock-height fields: {}",
				error
			))
		})?;
		match refund_kernel.features {
			KernelFeatures::HeightLocked { fee, lock_height } => {
				if fee.fee() != refund_slate.fee || lock_height != refund_lock_height {
					return Err(Error::InvalidMessageData(
						"Refund Slate invalid kernel fee or height".to_string(),
					));
				}
			}
			_ => {
				return Err(Error::InvalidMessageData(
					"Refund Slate invalid kernel feature".to_string(),
				));
			}
		}
		if refund_slate.num_participants != 2 {
			return Err(Error::InvalidMessageData(
				"Refund Slate participants doesn't match expected value".to_string(),
			));
		}
		if refund_slate
			.amount
			.checked_add(refund_slate.fee)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::validate_offer_static, refund slate amount overflow, refund_amount={} refund_fee={}",
					refund_slate.amount, refund_slate.fee
				))
			})? != lock_slate.amount
		{
			return Err(Error::InvalidMessageData(
				"Refund Slate amount doesn't match offer".to_string(),
			));
		}
		if refund_slate.fee != tx_fee(context_id, 1, 1, 1)? {
			return Err(Error::InvalidMessageData(
				"Refund Slate fee doesn't match expected value".to_string(),
			));
		}

		Self::validate_offer_slate_participant(secp, &lock_slate, "Lock")?;
		Self::validate_offer_slate_participant(secp, &refund_slate, "Refund")?;
		// Unlike lock/refund participants this record is carried standalone, so
		// validate it through the same bounded message and stage policy explicitly.
		swap::validate_swap_participant(secp, &offer.redeem_participant, 0, false, "Redeem offer")?;
		offer.multisig.validate_revealed_round_1(secp)?;

		let redeem_fee = tx_fee(context_id, 1, 1, 1)?;
		offer.primary_amount.checked_sub(redeem_fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::validate_offer_static, primary amount is smaller than redeem slate fee, primary_amount={} redeem_fee={}",
				offer.primary_amount, redeem_fee
			))
		})?;

		// Minimum mwc heights. The deadline arithmetic mirrors
		// Swap::get_time_mwc_lock and the Swap::get_time_* chain behind it,
		// computed from offer fields because no Swap instance exists yet.
		let (mwc_lock_time, secondary_lock_time) = Self::offer_lock_times(&offer)?;
		if mwc_lock_time <= now_ts {
			return Err(Error::InvalidMessageData(format!(
				"MWC lock time is already expired, lock_time={} now={}",
				mwc_lock_time, now_ts
			)));
		}
		// The secondary builders enforce this same limit much later. Enforce it
		// while the offer is still untrusted so malformed offers never consume
		// durable context keys or become persisted, unusable trades.
		swap::validate_secondary_lock_time(secondary_lock_time, now_ts)?;
		// The expiry check proves this subtraction is positive and fits i64.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "mwc_lock_time is checked greater than now_ts"
		)]
		let remaining_lock_seconds = mwc_lock_time - now_ts;
		let remaining_lock_seconds = u64::try_from(remaining_lock_seconds).map_err(|e| {
			Error::DataOverflow(format!(
				"BuyApi::validate_offer_static, remaining MWC lock time does not fit u64, remaining_seconds={} error={}",
				remaining_lock_seconds, e
			))
		})?;

		Ok(StaticallyValidatedOffer {
			offer,
			secondary_update,
			lock_slate,
			refund_slate,
			remaining_lock_seconds,
			mwc_lock_time,
		})
	}

	/// Validate the chain-dependent properties of an incoming offer: lock
	/// inputs exist on chain, heights are sane, and the refund lock height
	/// preserves the required safety window. Must run after the
	/// duplicate/replay checks (inputs of an already accepted offer are
	/// legitimately spent by its published lock transaction) but before
	/// endpoint RPC validation and durable key allocation.
	///
	/// Returns the validated chain tip height.
	pub(crate) fn validate_offer_node<C: NodeClient>(
		context_id: u32,
		validated_offer: StaticallyValidatedOffer,
		node_client: &C,
	) -> Result<ValidatedOffer, Error> {
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let lock = validated_offer.lock_slate.node_preflight_transaction(
			context_id,
			&secp,
			false,
		)?;
		let mut refund = validated_offer.refund_slate.node_preflight_transaction(
			context_id,
			&secp,
			false,
		)?;
		refund.allow_future_height = true;
		let checked = crate::transaction_preflight::check_request(
			node_client,
			&crate::transaction_preflight::MempoolAcceptRequest {
				transactions: vec![lock, refund],
				expected_tip: None,
			},
		)?;
		let final_tip_height = checked.checked_height;
		if validated_offer.lock_slate.height > final_tip_height {
			return Err(Error::InvalidMessageData(
				"Lock Slate height is invalid".into(),
			));
		}

		let refund_lock_height = validated_offer.refund_slate.get_lock_height_check()?;
		Self::validate_refund_lock_height(
			final_tip_height,
			validated_offer.remaining_lock_seconds,
			refund_lock_height,
		)?;

		Ok(ValidatedOffer {
			offer: validated_offer.offer,
			secondary_update: validated_offer.secondary_update,
			lock_slate: validated_offer.lock_slate,
			refund_slate: validated_offer.refund_slate,
			final_tip_height,
			mwc_lock_time: validated_offer.mwc_lock_time,
		})
	}

	/// Compute the MWC lock deadline from offer fields. Must stay in sync with
	/// Swap::get_time_mwc_lock and the Swap::get_time_* helper chain behind it;
	/// it exists because offer validation runs before any Swap instance is
	/// created.
	fn offer_lock_times(offer: &OfferUpdate) -> Result<(i64, i64), Error> {
		// Swap::get_time_message_offers
		let msg_exchange = i64::try_from(offer.message_exchange_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, message exchange interval exceeds i64 seconds, message_exchange_time_sec={} error={}",
				offer.message_exchange_time_sec, e
			))
		})?;
		let offers_deadline = offer
			.start_time
			.timestamp()
			.checked_add(msg_exchange)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::offer_mwc_lock_time, offer message deadline overflow, start_time={} interval={}",
					offer.start_time.timestamp(),
					msg_exchange
				))
			})?;

		// Swap::get_timeinterval_mwc_lock, adding extra 10% for chain instability
		let mwc_confirmations = i64::try_from(offer.mwc_confirmations).map_err(|e| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, MWC confirmation count exceeds i64, confirmations={} error={}",
				offer.mwc_confirmations, e
			))
		})?;
		let mwc_lock_interval = mwc_confirmations.checked_mul(60 * 11).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, MWC confirmation interval overflow, confirmations={}",
				mwc_confirmations
			))
		})? / 10;

		// Swap::get_timeinterval_secondary_lock, adding extra 10% for chain instability
		let secondary_confirmations = i64::try_from(offer.secondary_confirmations).map_err(|e| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, secondary confirmation count exceeds i64, confirmations={} error={}",
				offer.secondary_confirmations, e
			))
		})?;
		let block_period = offer.secondary_currency.block_time_period_sec();
		let secondary_seconds =
			secondary_confirmations
				.checked_mul(block_period)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"BuyApi::offer_mwc_lock_time, secondary confirmation interval overflow, confirmations={} block_time_period_sec={}",
						secondary_confirmations, block_period
					))
				})?;
		let secondary_lock_interval = secondary_seconds.checked_mul(11).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, secondary confirmation safety interval overflow, seconds={} multiplier=11",
				secondary_seconds
			))
		})? / 10;

		// Swap::get_time_locking
		let locking_deadline = offers_deadline
			.checked_add(std::cmp::max(mwc_lock_interval, secondary_lock_interval))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::offer_mwc_lock_time, swap locking deadline overflow, offers_deadline={}",
					offers_deadline
				))
			})?;

		// Swap::get_time_message_redeem
		let message_redeem_deadline =
			locking_deadline
				.checked_add(msg_exchange)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"BuyApi::offer_mwc_lock_time, redeem message deadline overflow, locking_deadline={} interval={}",
						locking_deadline, msg_exchange
					))
				})?;

		// Swap::get_time_mwc_redeem
		let redeem_interval = i64::try_from(offer.redeem_time_sec).map_err(|e| {
			Error::DataOverflow(format!(
				"BuyApi::offer_mwc_lock_time, redeem interval exceeds i64 seconds, redeem_time_sec={} error={}",
				offer.redeem_time_sec, e
			))
		})?;
		let mwc_redeem_deadline = message_redeem_deadline
			.checked_add(redeem_interval)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::offer_mwc_lock_time, MWC redeem deadline overflow, redeem_message_deadline={} interval={}",
					message_redeem_deadline, redeem_interval
				))
			})?;

		// Swap::get_time_mwc_lock
		let mwc_lock_time = mwc_redeem_deadline
			.checked_add(mwc_lock_interval)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::offer_lock_times, MWC lock deadline overflow, redeem_deadline={} lock_interval={}",
					mwc_redeem_deadline, mwc_lock_interval
				))
			})?;

		// Mirror Swap::get_time_mwc_refund and
		// Swap::get_time_secondary_lock_script. This is the timestamp consumed by
		// both BTC script construction and the Ethereum deposit path.
		let refund_deadline = mwc_lock_time.checked_add(redeem_interval).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::offer_lock_times, MWC refund deadline overflow, lock_deadline={} redeem_interval={}",
				mwc_lock_time, redeem_interval
			))
		})?;
		let secondary_lock_time = refund_deadline
			.checked_add(redeem_interval)
			.and_then(|time| time.checked_add(mwc_lock_interval))
			.and_then(|time| time.checked_add(secondary_lock_interval))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BuyApi::offer_lock_times, secondary lock deadline overflow, refund_deadline={} redeem_interval={} mwc_interval={} secondary_interval={}",
					refund_deadline,
					redeem_interval,
					mwc_lock_interval,
					secondary_lock_interval
				))
			})?;

		Ok((mwc_lock_time, secondary_lock_time))
	}

	pub(crate) fn validate_offer_gas(
		context_id: u32,
		offer: &OfferUpdate,
		ethereum_wallet: Option<&EthereumWallet>,
	) -> Result<(), Error> {
		if offer.secondary_currency.is_btc_family() {
			return Ok(());
		}
		let ethereum_wallet = ethereum_wallet.ok_or_else(|| {
			Error::Generic("invalid accept_swap_offer params, ethereum_wallet is not set".into())
		})?;
		let secondary_fee_units = offer.secondary_currency.get_default_fee(&offer.network);
		let required_gwei = offer
			.secondary_currency
			.secondary_fee_gwei(secondary_fee_units)?;
		let balance_gwei = get_eth_balance(context_id, ethereum_wallet.clone())?;
		if required_gwei > balance_gwei {
			return Err(Error::Generic(
				"No enough ether as gas for swap".to_string(),
			));
		}
		Ok(())
	}

	/// Validate and accept a seller offer for callers that already own a buyer
	/// context. Resource-bearing ingress paths should validate first and call
	/// `accept_validated_swap_offer` only after allocating that context.
	pub fn accept_swap_offer<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		ethereum_wallet: Option<EthereumWallet>,
		keychain: &K,
		context: &Context,
		id: Uuid,
		offer: OfferUpdate,
		secondary_update: SecondaryUpdate,
		node_client: &C,
	) -> Result<Swap, Error> {
		let statically_validated =
			Self::validate_offer_static(context_id, secp, offer, secondary_update)?;
		let validated_offer =
			Self::validate_offer_node(context_id, statically_validated, node_client)?;
		Self::validate_offer_gas(
			context_id,
			validated_offer.offer(),
			ethereum_wallet.as_ref(),
		)?;
		validated_offer.ensure_not_expired()?;
		Self::accept_validated_swap_offer(
			context_id,
			secp,
			keychain,
			context,
			id,
			validated_offer,
			node_client,
		)
	}

	pub(crate) fn accept_validated_swap_offer<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		context: &Context,
		id: Uuid,
		validated_offer: ValidatedOffer,
		node_client: &C,
	) -> Result<Swap, Error> {
		let ValidatedOffer {
			offer,
			secondary_update,
			lock_slate,
			refund_slate,
			final_tip_height,
			mwc_lock_time: _,
		} = validated_offer;

		context.unwrap_buyer()?;

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
		let mut redeem_slate = Slate::blank(2, false)?;

		#[cfg(feature = "test-support")]
		if is_test_mode() {
			redeem_slate.id = Uuid::parse_str("78aa5af1-048e-4c49-8776-a2e66d4a460c").unwrap()
		}

		redeem_slate.fee = tx_fee(context_id, 1, 1, 1)?;
		redeem_slate.height = final_tip_height;
		redeem_slate.amount = offer.primary_amount.checked_sub(redeem_slate.fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::accept_swap_offer, primary amount is smaller than redeem slate fee, primary_amount={} redeem_fee={}",
				offer.primary_amount, redeem_slate.fee
			))
		})?;

		redeem_slate.participant_data.push(offer.redeem_participant);

		let multisig = multisig::Builder::new(
			2,
			offer.primary_amount, // !!! It is amount that will be put into transactions. It is primary what need to be validated
			false,
			1,
			context.multisig_nonce.clone(),
			None,
		);

		let started = offer.start_time.clone();
		let secondary_fee_units = offer.secondary_currency.get_default_fee(&offer.network);

		// An offer's return address is a peer-controlled network hint. A file
		// address is different: it names an object in our local filesystem, so it
		// must be discarded and selected through the wallet owner interface.
		let communication_method = offer.communication_method.clone();
		let communication_address = if communication_method == "file" {
			String::new()
		} else {
			offer.from_address.clone()
		};

		let mut swap = match offer.secondary_currency.is_btc_family() {
			true => {
				let btc_data = BtcData::from_offer(
					secp,
					keychain,
					secondary_update.unwrap_btc()?.unwrap_offer()?,
					context.unwrap_buyer()?.unwrap_btc()?,
				)?;
				let redeem_public = Some(PublicKey::from_secret_key(
					secp,
					&Self::redeem_secret(secp, keychain, context)?,
				)?);
				Swap {
					id,
					version: CURRENT_VERSION,
					network: offer.network,
					role: Role::Buyer(None),
					communication_method: communication_method.clone(),
					communication_address: communication_address.clone(),
					swap_trade_transport: None,
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
					lock_slate: SlateCtx {
						slate: lock_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
					refund_slate: SlateCtx {
						slate: refund_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
					redeem_slate: SlateCtx {
						slate: redeem_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
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
					secondary_fee_units,
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
				}
			}
			_ => {
				let eth_data = EthData::from_offer(
					secondary_update.unwrap_eth()?.unwrap_offer()?,
					context.unwrap_buyer()?.unwrap_eth()?,
				)?;
				let redeem_public = Some(PublicKey::from_secret_key(
					secp,
					&Self::redeem_secret(secp, keychain, context)?,
				)?);

				Swap {
					id,
					version: CURRENT_VERSION,
					network: offer.network,
					role: Role::Buyer(None),
					communication_method,
					communication_address,
					swap_trade_transport: None,
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
					lock_slate: SlateCtx {
						slate: lock_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
					refund_slate: SlateCtx {
						slate: refund_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
					redeem_slate: SlateCtx {
						slate: redeem_slate,
						network_name: Some(global::get_network_name(context_id)),
					},
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
					secondary_fee_units,
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
				}
			}
		};

		swap.add_journal_message("Received a swap offer".to_string());

		Self::build_multisig(secp, keychain, &mut swap, context, offer.multisig)?;
		Self::sign_lock_slate(context_id, secp, keychain, &mut swap, context)?;
		Self::sign_refund_slate(context_id, secp, keychain, &mut swap, context)?;
		swap.validate_lock_and_refund_slates(context_id, node_client, secp)?;

		Ok(swap)
	}

	/// Buyer builds swap.redeem_slate
	pub fn init_redeem<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		node_client: &C,
	) -> Result<(), Error> {
		if swap.is_seller() {
			return Err(Error::UnexpectedRole(
				"Buyer init_redeem called for seller swap".to_string(),
			));
		}

		// Slate construction is incremental and contains several fallible operations
		// after the transaction and participant list have already been modified. Keep
		// those mutations private until both the slate and adaptor signature are
		// complete so every caller, not only the owner FSM, gets rollback on error.
		let mut staged_swap = swap.clone();
		Self::build_redeem_slate(context_id, secp, keychain, &mut staged_swap, context)?;
		Self::calculate_adaptor_signature(context_id, secp, keychain, &mut staged_swap, context)?;
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

	/// Generate 'Accept offer' massage
	pub fn accept_offer_message(
		swap: &Swap,
		inner_secondary: SecondaryUpdate,
	) -> Result<Message, Error> {
		let id = swap.participant_id;
		swap.message(
			Update::AcceptOffer(AcceptOfferUpdate {
				marketplace_winner_lease_expires_at: swap
					.marketplace_winner_lease_expires_at,
				multisig: swap.multisig.export()?,
				redeem_public: swap
					.redeem_public
					.clone()
					.ok_or(Error::Generic("redeem_public is empty".to_string()))?,
				lock_participant: swap.lock_slate.slate.participant_with_id(id).ok_or_else(
					|| Error::UnexpectedAction("Lock participant is missing".to_string()),
				)?,
				refund_participant: swap.refund_slate.slate.participant_with_id(id).ok_or_else(
					|| Error::UnexpectedAction("Refund participant is missing".to_string()),
				)?,
			}),
			inner_secondary,
		)
	}

	/// Generate 'InitRedeem' slate message
	pub fn init_redeem_message(context_id: u32, swap: &Swap) -> Result<Message, Error> {
		swap.message(
			Update::InitRedeem(InitRedeemUpdate {
				redeem_slate: VersionedSlate::into_version_plain(
					context_id,
					&swap.redeem_slate.slate,
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
	pub fn redeem_secret<K: Keychain>(
		secp: &secp::Secp256k1,
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let bcontext = context.unwrap_buyer()?;
		let sec_key = keychain.derive_key(secp, 0, &bcontext.redeem, SwitchCommitmentType::None)?;

		Ok(sec_key)
	}

	fn build_multisig<K: Keychain>(
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: multisig::ParticipantData,
	) -> Result<(), Error> {
		let multisig_secret = swap.multisig_secret(secp, keychain, context)?;
		let multisig = &mut swap.multisig;

		// Import participant
		multisig.import_participant(0, &part)?;
		multisig.create_participant(secp, &multisig_secret)?;
		multisig.round_1_participant(0, &part)?;

		// Round 1 + round 2
		multisig.round_1(secp, &multisig_secret)?;
		let common_nonce = swap.common_nonce(secp)?;
		let multisig = &mut swap.multisig;
		multisig.common_nonce = Some(common_nonce);
		multisig.round_2(secp, &multisig_secret)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the lock slate
	fn lock_tx_secret<K: Keychain>(
		secp: &secp::Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
		// Partial multisig output
		let sum = BlindSum::new().add_blinding_factor(BlindingFactor::from_secret_key(
			swap.multisig_secret(secp, keychain, context)?,
		));
		let sec_key = keychain.blind_sum(secp, &sum)?.secret_key(secp)?;

		Ok(sec_key)
	}

	fn sign_lock_slate<K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let mut sec_key = Self::lock_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.lock_slate.slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Buyer Fn sign_lock_slate(), lock slate participant data is already initialized"
					.to_string(),
			));
		}

		// Add multisig output to slate (with invalid proof)
		let proof = RangeProof::from_bytes(&[0; secp::constants::MAX_PROOF_SIZE])?;

		tx_add_output(context_id, slate, swap.multisig.commit(secp)?, proof)?;

		// Sign slate
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
		slate.fill_round_2(
			context_id,
			secp,
			&sec_key,
			&context.lock_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the refund slate
	fn refund_tx_secret<K: Keychain>(
		secp: &secp::Secp256k1,
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

	fn sign_refund_slate<K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let commit = swap.multisig.commit(secp)?;
		let mut sec_key = Self::refund_tx_secret(secp, keychain, swap, context)?;

		// This function should only be called once
		let slate = &mut swap.refund_slate.slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot("Buyer Fn sign_refund_slate(), refund slate participant data is already initialized".to_string()));
		}

		// Add multisig input to slate
		tx_add_input(context_id, slate, commit)?;

		// Sign slate
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
		slate.fill_round_2(
			context_id,
			secp,
			&sec_key,
			&context.refund_nonce,
			swap.participant_id,
		)?;

		Ok(())
	}

	/// Convenience function to calculate the secret that is used for signing the redeem slate
	pub fn redeem_tx_secret<K: Keychain>(
		secp: &secp::Secp256k1,
		keychain: &K,
		swap: &Swap,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let bcontext = context.unwrap_buyer()?;

		// Partial multisig input, redeem output, offset
		let sum = BlindSum::new()
			.add_key_id(
				bcontext
					.output
					.to_value_path(swap.redeem_slate.slate.amount)?,
			)
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				swap.multisig_secret(secp, keychain, context)?,
			))
			.sub_blinding_factor(swap.redeem_slate.slate.tx_or_err()?.offset.clone());
		let sec_key = keychain.blind_sum(secp, &sum)?.secret_key(secp)?;

		Ok(sec_key)
	}

	fn build_redeem_slate<K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), Error> {
		let bcontext = context.unwrap_buyer()?;

		// This function should only be called once
		let slate = &mut swap.redeem_slate.slate;
		if slate.participant_data.len() > 1 {
			return Err(Error::OneShot(
				"Buyer Fn build_redeem_slate(), redeem slate participant data is not empty"
					.to_string(),
			));
		}

		// Build slate
		slate.fee = tx_fee(context_id, 1, 1, 1)?;
		slate.amount = swap.primary_amount.checked_sub(slate.fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BuyApi::build_redeem_slate, primary amount is smaller than redeem slate fee, primary_amount={} redeem_fee={}",
				swap.primary_amount, slate.fee
			))
		})?;
		let mut elems = Vec::new();
		// The buyer's redeem output is wallet-generated: tag its rangeproof with
		// the anti-replay build height like every other wallet output.
		elems.push(build::height_tagged_output(
			slate.amount,
			bcontext.output.clone(),
			slate.height,
		));
		let proof_builder = proof::ProofBuilder::new(secp, keychain)?;
		slate.add_transaction_elements(context_id, secp, keychain, &proof_builder, elems)?;

		#[cfg(feature = "test-support")]
		{
			slate.tx_or_err_mut()?.offset = if is_test_mode() {
				BlindingFactor::from_hex(
					"90de4a3812c7b78e567548c86926820d838e7e0b43346b1ba63066cd5cc7d999",
				)
				.unwrap()
			} else {
				BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?)
			};
		}

		// Release Doesn't have any tweaking
		#[cfg(not(feature = "test-support"))]
		{
			slate.tx_or_err_mut()?.offset =
				BlindingFactor::from_secret_key(SecretKey::new(secp, &mut SysRng)?);
		}

		// Add multisig input to slate
		tx_add_input(context_id, slate, swap.multisig.commit(secp)?)?;

		let mut sec_key = Self::redeem_tx_secret(secp, keychain, swap, context)?;
		let slate = &mut swap.redeem_slate.slate;

		// Add participant to slate
		slate.fill_round_1(
			secp,
			keychain,
			&mut sec_key,
			&context.redeem_nonce,
			swap.participant_id,
			None,
			#[cfg(feature = "test-support")]
			false,
		)?;

		Ok(())
	}

	/// Finalize redeem slate with a data from the message
	pub fn finalize_redeem_slate<C: NodeClient, K: Keychain>(
		context_id: u32,
		secp: &mut secp::Secp256k1,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		part: crate::ParticipantData,
		node_client: &C,
	) -> Result<(), Error> {
		let id = swap.participant_id;
		let other_id = swap.other_participant_id();
		let local_participant = swap
			.redeem_slate
			.slate
			.participant_data
			.iter()
			.find(|participant| participant.id == id as u64)
			.ok_or(Error::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for this party".to_string()))?;
		// This function should only be called once.
		if local_participant.is_complete() {
			return Err(Error::OneShot(
				"Buyer Fn finalize_redeem_slate() redeem slate is already initialized".to_string(),
			));
		}

		// The seller may only add its partial signature to the exact round-one
		// record sent in the offer. Validate before replacement because participant
		// ids and messages are not covered by the transaction partial signature.
		swap::validate_swap_slate_participants(
			secp,
			&swap.redeem_slate.slate,
			&[(0, false), (1, false)],
			"Stored buyer redeem slate",
		)?;
		swap::validate_swap_participant(secp, &part, other_id as u64, true, "Redeem response")?;
		let expected_peer = swap
			.redeem_slate
			.slate
			.participant_data
			.iter()
			.find(|participant| participant.id == other_id as u64)
			.ok_or(Error::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for other party".to_string()))?;
		swap::validate_swap_participant_binding(expected_peer, &part, "Redeem response")?;

		let sec_key = Self::redeem_tx_secret(secp, keychain, swap, context)?;
		// Work on a clone so an invalid peer partial signature cannot leave the
		// durable in-memory trade with a replaced participant after an error.
		let mut staged_slate = swap.redeem_slate.slate.clone();
		let peer_index = staged_slate
			.participant_data
			.iter()
			.position(|participant| participant.id == other_id as u64)
			.ok_or(Error::UnexpectedAction("Buyer Fn finalize_redeem_slate() redeem slate participant data is not initialized for other party".to_string()))?;
		staged_slate.participant_data[peer_index] = part;

		// Sign + finalize only after all peer-controlled metadata is validated.
		staged_slate
			.fill_round_2(
				context_id,
				secp,
				&sec_key,
				&context.redeem_nonce,
				swap.participant_id,
			)
			.map_err(|error| {
				Error::InvalidMessageData(format!(
					"Redeem response has an invalid partial signature: {}",
					error
				))
			})?;
		staged_slate.finalize(context_id, secp).map_err(|error| {
			Error::InvalidMessageData(format!(
				"Redeem response cannot finalize the transaction: {}",
				error
			))
		})?;
		crate::transaction_preflight::check_slate(
			context_id,
			node_client,
			&staged_slate,
			secp,
			true,
		)?;
		swap.redeem_slate.slate = staged_slate;

		Ok(())
	}

	fn calculate_adaptor_signature<K: Keychain>(
		context_id: u32,
		secp: &secp::Secp256k1,
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

		let sec_key = Self::redeem_tx_secret(secp, keychain, swap, context)?;
		let redeem_fields = swap.redeem_tx_fields(context_id, &swap.redeem_slate.slate, secp)?;

		let adaptor_signature = aggsig::sign_single(
			secp,
			&redeem_fields.message,
			&sec_key,
			Some(&context.redeem_nonce),
			Some(&Self::redeem_secret(secp, keychain, context)?),
			Some(&redeem_fields.pub_nonce_sum),
			&redeem_fields.pub_blind_sum,
			Some(&redeem_fields.pub_nonce_sum),
		)?;
		swap.adaptor_signature = Some(adaptor_signature);

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::core::{CommitWrapper, Inputs, OutputFeatures};
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::chrono::{TimeZone, Utc};
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serde_json;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::serial_test::serial;

	#[test]
	fn refund_lock_tolerance_applies_only_to_future_blocks() {
		let current_height = 1_000_000;
		let remaining_lock_seconds = 100 * 60;

		assert!(matches!(
			BuyApi::validate_refund_lock_height(
				current_height,
				remaining_lock_seconds,
				current_height
			),
			Err(Error::InvalidMessageData(_))
		));
		assert!(matches!(
			BuyApi::validate_refund_lock_height(
				current_height,
				remaining_lock_seconds,
				current_height + 89
			),
			Err(Error::InvalidMessageData(_))
		));
		assert!(BuyApi::validate_refund_lock_height(
			current_height,
			remaining_lock_seconds,
			current_height + 90
		)
		.is_ok());
	}

	#[test]
	fn refund_lock_must_be_above_tip_when_interval_rounds_to_zero_blocks() {
		let current_height = 1_000_000;

		assert!(BuyApi::validate_refund_lock_height(current_height, 59, current_height).is_err());
		assert!(
			BuyApi::validate_refund_lock_height(current_height, 59, current_height + 1).is_ok()
		);
	}

	#[test]
	fn refund_lock_height_rejects_more_than_thirty_days() {
		let current_height = 1_000_000;
		let maximum_height = current_height + swap::MAX_MWC_REFUND_LOCK_BLOCKS;
		assert!(BuyApi::validate_refund_lock_height(current_height, 60, maximum_height).is_ok());
		assert!(matches!(
			BuyApi::validate_refund_lock_height(current_height, 60, maximum_height + 1),
			Err(Error::InvalidMessageData(_))
		));
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn accept_offer_message_carries_marketplace_winner_lease() -> Result<(), Error> {
		let mut swap: Swap =
			serde_json::from_str(include_str!("../../swap_test/swap_buy_1.json"))?;
		let expires_at = 1_567_632_752;
		swap.marketplace_winner_lease_expires_at = Some(expires_at);

		let message = BuyApi::accept_offer_message(&swap, SecondaryUpdate::Empty)?;
		let (_, accept_offer, _) = message.unwrap_accept_offer()?;
		assert_eq!(
			accept_offer.marketplace_winner_lease_expires_at,
			Some(expires_at)
		);
		Ok(())
	}

	#[cfg(feature = "test-support")]
	fn current_btc_offer() -> Result<(OfferUpdate, SecondaryUpdate), Error> {
		let message = Message::from_json(include_str!("../../swap_test/message_1.json"))?;
		let (_, mut offer, secondary_update) = message.unwrap_offer()?;
		// Follow the swap test clock rather than wall time; other swap tests use a
		// deterministic timestamp and may run concurrently with these checks.
		offer.start_time = Utc
			.timestamp_opt(swap::get_cur_time(), 0)
			.single()
			.ok_or_else(|| Error::Generic("Test swap clock is outside chrono range".to_string()))?;
		Ok((offer, secondary_update))
	}

	#[cfg(feature = "test-support")]
	fn configure_offer_test_chain() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(true);
		global::set_local_accept_fee_base(
			mwc_wallet_util::mwc_core::consensus::MILLI_MWC / 100,
		)
		.unwrap();
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_accepts_the_complete_offer_fixture() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (offer, secondary_update) = current_btc_offer()?;

		BuyApi::validate_offer_static(0, &secp, offer, secondary_update)?;
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_compact_lock_slate() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		let mut lock_slate = offer.lock_slate.into_slate_plain(0, false)?;
		// Keep the full transaction body: a compact flag alone must reject the offer.
		lock_slate.compact_slate = true;
		offer.lock_slate = VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3)?;

		let error = match BuyApi::validate_offer_static(0, &secp, offer, secondary_update) {
			Ok(_) => panic!("compact lock slate must be rejected"),
			Err(error) => error,
		};
		assert!(matches!(
			&error,
			Error::InvalidMessageData(message) if message == "Swap offers require a non-compact lock slate"
		));
		assert!(!error.is_transient());
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_compact_refund_slate() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		let mut refund_slate = offer.refund_slate.into_slate_plain(0, false)?;
		refund_slate.compact_slate = true;
		offer.refund_slate =
			VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3)?;

		let error = match BuyApi::validate_offer_static(0, &secp, offer, secondary_update) {
			Ok(_) => panic!("compact refund slate must be rejected"),
			Err(error) => error,
		};
		assert!(matches!(
			&error,
			Error::InvalidMessageData(message) if message == "Swap offers require a non-compact refund slate"
		));
		assert!(!error.is_transient());
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_coinbase_lock_output_as_peer_data() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		let mut lock_slate = offer.lock_slate.into_slate_plain(0, false)?;
		lock_slate.tx_or_err_mut()?.body.outputs[0]
			.identifier
			.features = OutputFeatures::Coinbase;
		offer.lock_slate = VersionedSlate::into_version_plain(0, &lock_slate, SlateVersion::V3)?;

		let error = match BuyApi::validate_offer_static(0, &secp, offer, secondary_update) {
			Ok(_) => panic!("coinbase lock output must be rejected"),
			Err(error) => error,
		};
		assert!(matches!(error, Error::InvalidMessageData(_)));
		assert!(!error.is_transient());
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_refund_with_peer_supplied_input() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		let mut refund_slate = offer.refund_slate.into_slate_plain(0, false)?;
		let unexpected_input = CommitWrapper::from(secp.commit_value(1)?);
		refund_slate.tx_or_err_mut()?.body.inputs = Inputs::CommitOnly(vec![unexpected_input]);
		offer.refund_slate =
			VersionedSlate::into_version_plain(0, &refund_slate, SlateVersion::V3)?;

		let error = match BuyApi::validate_offer_static(0, &secp, offer, secondary_update) {
			Ok(_) => panic!("offered refund input must be rejected"),
			Err(error) => error,
		};
		assert!(matches!(error, Error::InvalidMessageData(_)));
		assert!(!error.is_transient());
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_secondary_payload_mismatch() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (offer, _) = current_btc_offer()?;

		assert!(matches!(
			BuyApi::validate_offer_static(0, &secp, offer, SecondaryUpdate::Empty),
			Err(Error::InvalidMessageData(_))
		));
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_incomplete_multisig_round() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let mut json: serde_json::Value =
			serde_json::from_str(include_str!("../../swap_test/message_1.json"))?;
		json["inner"]["Offer"]["multisig"]
			.as_object_mut()
			.expect("fixture multisig must be an object")
			.remove("t_1");
		let message: Message = serde_json::from_value(json)?;
		let (_, mut offer, secondary_update) = message.unwrap_offer()?;
		offer.start_time = mwc_wallet_util::mwc_crates::chrono::Utc::now();

		assert!(BuyApi::validate_offer_static(0, &secp, offer, secondary_update).is_err());
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_oversized_standalone_participant_message(
	) -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		offer.redeem_participant.message = Some("x".repeat(crate::MAX_PARTICIPANT_MESSAGE_LEN + 1));

		assert!(matches!(
			BuyApi::validate_offer_static(0, &secp, offer, secondary_update),
			Err(Error::InvalidMessageData(_))
		));
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	#[serial]
	fn static_offer_validation_rejects_far_future_secondary_lock() -> Result<(), Error> {
		configure_offer_test_chain();
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit)?;
		let (mut offer, secondary_update) = current_btc_offer()?;
		offer.message_exchange_time_sec =
			u64::try_from(swap::MAX_SWAP_LOCK_INTERVAL_SECONDS).unwrap();

		assert!(matches!(
			BuyApi::validate_offer_static(0, &secp, offer, secondary_update),
			Err(Error::InvalidMessageData(_))
		));
		Ok(())
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn ethereum_secondary_offer_requires_redeem_address() -> Result<(), Error> {
		let (mut offer, _) = current_btc_offer()?;
		offer.secondary_currency = Currency::Ether;
		let secondary_update: SecondaryUpdate =
			serde_json::from_str(r#"{"ETH":{"Offer":{"redeem_address":null}}}"#)?;

		assert!(matches!(
			BuyApi::validate_secondary_offer(&offer, &secondary_update),
			Err(Error::InvalidMessageData(_))
		));
		Ok(())
	}
}
