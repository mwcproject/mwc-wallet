// Copyright 2026 The MWC Developers
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

//! Durable, bounded buyer refunds.
//!
//! The first preparation freezes the observed deposit inventory, including
//! unconfirmed deposits. The seller's 32-output admission limit does not limit
//! the total refund. Each newly signed batch has at most 32 inputs, including
//! any input carrying the preceding batch's balance.
//!
//! `buyer_build_refund_tx` prepares one transaction per call. The owner workflow
//! saves it before broadcasting, then waits for the swap's required confirmation
//! depth before preparing the next batch. Intermediate batches pay a P2SH output
//! controlled by the buyer's refund key. Its balance supplies later batches'
//! fees. The last batch of currently confirmed deposits pays the refund address;
//! unconfirmed deposits stay pending without delaying that payout. Deposits
//! arriving after the inventory snapshot are outside this plan.
//!
//! Before signing, unsigned deposits whose value does not exceed their
//! incremental spending fee are excluded. The estimate includes the serialized
//! input's script prefixes and maximum DER signature size, with upward fee
//! rounding. Transaction overhead and minimum output amounts are checked
//! separately. A flat transaction fee is not charged again for each input.
//!
//! Excluded deposits remain in `BtcRefundPlan::unrefunded`, with their outpoints,
//! values, fee settings and incremental fee estimates. The journal and completion
//! description report their count and total as unrefunded. A fee decrease does
//! not automatically reintroduce them; their records remain available for a
//! separate recovery attempt. This module does not add a recovery command.
//! Unconfirmed pending deposits also remain recorded and prevent completion.
//!
//! Replacements preserve the signed input set. Every attempt is retained,
//! including ambiguous broadcasts. Confirmation polling checks all saved hashes
//! against one backend. If no saved hash is known, confirmed input spends are
//! checked for scriptSig-only variants of saved attempts. The confirmed bytes
//! and actual carry outpoint are retained before preparing a child. A child
//! spends the parent attempt that actually confirmed, and pins that parent
//! once signed. A reorg retry rebroadcasts the pinned bytes; a conflicting
//! confirmed parent is an error, not evidence that the child is funded.
//!
//! Legacy single-transaction refunds are imported unchanged as a batch.
//! `BtcData::refund_transaction` mirrors the prepared broadcast, while `refund_tx`
//! remains the last successfully broadcast hash. Broadcasting never signs a new
//! transaction. Fee preflight uses checked arithmetic and preserves the inventory
//! when fees or minimum output amounts prevent building a transaction. Fees and
//! confirmation availability are checked again before each new batch.

use super::client::{BtcNodeClient, Output};
use super::recovery::recover_confirmed_variant;
use super::types::{minimum_output, BtcData, BtcRefundTransaction, BtcTtansaction};
use crate::swap::types::Currency;
use crate::swap::Error;
use crate::SecondaryFeeUnits;
use bitcoin::blockdata::{opcodes::all::OP_CHECKSIG, script::Builder};
use bitcoin::consensus::Encodable;
use bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use mwc_wallet_util::bitcoin_hashes::sha256d;
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_crates::secp::{
	key::{PublicKey, SecretKey},
	Message, Secp256k1,
};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use std::collections::HashSet;

/// Refund batching is independent of the seller's funding admission limit.
pub const MAX_REFUND_INPUTS: usize = 32;

/// A fixed refund inventory, including unconfirmed deposits seen at preparation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct BtcRefundPlan {
	/// Original deposits not yet assigned to a signed batch. Never silently dropped.
	pub pending: Vec<Output>,
	/// Deposits excluded because spending them would not increase the refund.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub unrefunded: Vec<BtcUnrefundedOutput>,
	/// Signed batches, in dependency order, retained through completion and restart.
	pub batches: Vec<BtcRefundBatch>,
}

/// An unspent deposit, with the fee estimate that caused it to be skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct BtcUnrefundedOutput {
	/// Original outpoint and amount, retained for a future recovery attempt.
	pub output: Output,
	/// Fee setting when this deposit was excluded.
	pub fee_units: SecondaryFeeUnits,
	/// Conservative additional fee for one fully signed swap input.
	pub incremental_fee: u64,
}

/// One immutable input set and all of its signed replacement attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct BtcRefundBatch {
	/// The first input spends the preceding batch's buyer-only carry script.
	pub spends_carry: bool,
	/// Every transaction that may have reached a node, including ambiguous posts.
	pub attempts: Vec<BtcRefundTransaction>,
	/// Older records retained a broadcast hash without retaining its signed bytes.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub legacy_txid: Option<sha256d::Hash>,
	/// Saved before a broadcast attempt, so a crash also preserves retry timing.
	pub last_broadcast_attempt: Option<i64>,
}

/// Fresh chain progress, separate from the legacy single-transaction counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtcRefundProgress {
	/// All existing batches confirmed; another batch can now be prepared.
	NextBatch {
		/// Number of batches covered by this chain observation.
		completed_batches: usize,
	},
	/// Recorded deposits are still unconfirmed; the inventory is not complete.
	WaitingForFunding,
	/// Retry or wait for this batch. Ancestors with signed children are pinned.
	Pending {
		/// Index into the persisted plan.
		batch: usize,
		/// None means the backend does not know any applicable attempt.
		confirmations: Option<u64>,
		/// Last persisted broadcast attempt time.
		last_broadcast_attempt: Option<i64>,
		/// False when changing this transaction would invalidate a signed child.
		replacement_allowed: bool,
		/// Whether the prepared attempt (or pinned parent) is known to the node.
		candidate_known: bool,
	},
	/// All selected deposits and the final payment have reached the required depth.
	/// Excluded deposits remain explicitly recorded in `BtcRefundPlan::unrefunded`.
	Complete,
}

pub(super) struct BatchObservation {
	pub confirmations: Option<u64>,
	pub txid: Option<sha256d::Hash>,
	pub candidate_known: bool,
}

impl BtcRefundBatch {
	/// A legacy scriptSig can change without invalidating the signatures. Only
	/// adopt a confirmed spend with exactly the same signed transaction fields
	/// as one of our attempts; a seller redemption or other spend is not a refund.
	fn recover_confirmed_attempt<B: BtcNodeClient>(
		&self,
		client: &mut B,
	) -> Result<Option<(BtcRefundTransaction, u64)>, Error> {
		let Some(found) = recover_confirmed_variant(
			client,
			self.attempts.iter().map(|attempt| &attempt.transaction),
			"refund",
		)? else {
			return Ok(None);
		};
		let transaction = found.transaction;
		let txid = transaction.txid()?;
		let mut recovered = self.attempts[found.attempt_index].clone();
		recovered.transaction = BtcTtansaction {
			txid: sha256d::Hash::from_byte_array(txid.to_byte_array()),
			tx: bitcoin::consensus::serialize(&transaction)?,
		};
		if let Some(carry) = &mut recovered.carry_output {
			let index = usize::try_from(carry.out_point.vout)
				.map_err(|_| Error::DataOverflow("Refund carry output index".into()))?;
			let output = transaction.output.get(index).ok_or_else(|| {
				Error::Generic("Confirmed refund is missing its carry output".into())
			})?;
			if output.value != carry.value {
				return Err(Error::Generic(
					"Confirmed refund carry amount differs".into(),
				));
			}
			carry.out_point.txid = txid;
		}
		Ok(Some((recovered, found.confirmations)))
	}
}

impl BtcRefundPlan {
	pub(super) fn new(mut outputs: Vec<Output>) -> Result<Self, Error> {
		let mut seen = HashSet::new();
		let mut total = 0_u64;
		for output in &outputs {
			if !seen.insert(output.out_point) {
				return Err(Error::Generic("Duplicate refund deposit".into()));
			}
			total = total
				.checked_add(output.value)
				.ok_or_else(|| Error::DataOverflow("Refund inventory amount overflow".into()))?;
		}
		// Large deposits supply fees for later batches. Outpoints break ties stably.
		outputs.sort_by(|a, b| {
			b.value
				.cmp(&a.value)
				.then_with(|| a.out_point.cmp(&b.out_point))
		});
		Ok(Self {
			pending: outputs,
			unrefunded: Vec::new(),
			batches: Vec::new(),
		})
	}

	/// Recheck only unsigned deposits. Signed attempts must keep their input set.
	pub(super) fn skip_uneconomic(
		&mut self,
		currency: Currency,
		fee: SecondaryFeeUnits,
		script: &Script,
	) -> Result<usize, Error> {
		let incremental_fee = incremental_input_fee(currency, fee, script)?;
		let before = self.unrefunded.len();
		self.pending.retain(|output| {
			if output.value <= incremental_fee {
				self.unrefunded.push(BtcUnrefundedOutput {
					output: output.clone(),
					fee_units: fee,
					incremental_fee,
				});
				false
			} else {
				true
			}
		});
		Ok(self.unrefunded.len() - before)
	}

	/// Total explicitly excluded amount, in the currency's atomic units.
	pub fn unrefunded_amount(&self) -> Result<u64, Error> {
		self.unrefunded.iter().try_fold(0_u64, |total, skipped| {
			total
				.checked_add(skipped.output.value)
				.ok_or_else(|| Error::DataOverflow("Unrefunded amount overflow".into()))
		})
	}

	/// Read every candidate and recover confirmed scriptSig variants from one
	/// backend. Call on a clone so a failed read/failover cannot persist partial
	/// observations or combine independent chain views.
	pub(super) fn observe<B: BtcNodeClient>(
		&mut self,
		client: &mut B,
	) -> Result<Vec<BatchObservation>, Error> {
		let mut result = Vec::with_capacity(self.batches.len());
		for index in 0..self.batches.len() {
			// A signed child commits to exactly one parent txid. Following another
			// replacement would falsely declare the child's funding confirmed.
			let pinned = self
				.batches
				.get(index + 1)
				.filter(|child| child.spends_carry)
				.and_then(|child| child.attempts.first())
				.and_then(|attempt| attempt.inputs.first())
				.map(|input| sha256d::Hash::from_byte_array(input.out_point.txid.to_byte_array()));
			let batch = &mut self.batches[index];
			let current = pinned.or_else(|| batch.attempts.last().map(|a| a.transaction.txid));
			let mut observation = BatchObservation {
				confirmations: None,
				txid: None,
				candidate_known: false,
			};
			let mut hashes: Vec<_> = batch.attempts.iter().map(|a| a.transaction.txid).collect();
			if let Some(hash) = batch.legacy_txid {
				if !hashes.contains(&hash) {
					hashes.push(hash);
				}
			}
			for hash in hashes {
				let confirmations = client
					.transaction_confirmations(&Txid::from_byte_array(hash.to_byte_array()))?;
				if Some(hash) == current {
					observation.candidate_known = confirmations.is_some();
				}
				if pinned.is_some() && pinned != Some(hash) {
					if confirmations.unwrap_or(0) > 0 {
						return Err(Error::Generic("A refund parent replacement conflicts with a saved child; recovery requires the original parent chain".into()));
					}
					continue;
				}
				if confirmations > observation.confirmations {
					observation.confirmations = confirmations;
					observation.txid = Some(hash);
				}
			}
			if observation.confirmations.is_none() {
				if let Some((recovered, confirmations)) = batch.recover_confirmed_attempt(client)? {
					let hash = recovered.transaction.txid;
					if pinned.is_some() && pinned != Some(hash) {
						return Err(Error::Generic("A confirmed refund variant conflicts with a saved child; recovery requires the original parent chain".into()));
					}
					if !batch
						.attempts
						.iter()
						.any(|attempt| attempt.transaction.txid == hash)
					{
						batch.attempts.push(recovered);
					}
					observation.confirmations = Some(confirmations);
					observation.txid = Some(hash);
					observation.candidate_known = true;
				}
			}
			result.push(observation);
		}
		Ok(result)
	}

	pub(super) fn progress(
		&self,
		observations: &[BatchObservation],
		unspent: &[Output],
		tip: u64,
		required: u64,
	) -> Result<BtcRefundProgress, Error> {
		if required == 0 || observations.len() != self.batches.len() {
			return Err(Error::Generic(
				"Invalid refund confirmation snapshot".into(),
			));
		}
		for (index, (batch, observation)) in self.batches.iter().zip(observations).enumerate() {
			if observation.confirmations.unwrap_or(0) < required {
				return Ok(BtcRefundProgress::Pending {
					batch: index,
					confirmations: observation.confirmations,
					last_broadcast_attempt: batch.last_broadcast_attempt,
					// Only a child spending this batch's carry pins its transaction.
					replacement_allowed: !self
						.batches
						.get(index + 1)
						.is_some_and(|child| child.spends_carry),
					candidate_known: observation.candidate_known,
				});
			}
		}
		if !self.pending.is_empty() {
			if self.available(unspent, tip)?.is_empty() {
				if self.carry(observations)?.is_some() {
					return Ok(BtcRefundProgress::NextBatch {
						completed_batches: self.batches.len(),
					});
				}
				return Ok(BtcRefundProgress::WaitingForFunding);
			}
			return Ok(BtcRefundProgress::NextBatch {
				completed_batches: self.batches.len(),
			});
		}
		// A fee increase can exclude every remaining deposit. The previously
		// confirmed carry still needs a final payment to the user's destination.
		if self.batches.last().is_some() && self.carry(observations)?.is_some() {
			return Ok(BtcRefundProgress::NextBatch {
				completed_batches: self.batches.len(),
			});
		}
		if self.batches.is_empty() && self.unrefunded.is_empty() {
			return Err(Error::Generic("No outputs available to refund".into()));
		}
		Ok(BtcRefundProgress::Complete)
	}

	pub(super) fn available(&self, unspent: &[Output], tip: u64) -> Result<Vec<Output>, Error> {
		let by_outpoint: std::collections::HashMap<_, _> =
			unspent.iter().map(|o| (o.out_point, o)).collect();
		let mut available = Vec::new();
		for saved in &self.pending {
			let output = match by_outpoint.get(&saved.out_point) {
				Some(output) => output,
				// A mempool deposit can be replaced or evicted. Keep its record,
				// but do not hold up recovery of already confirmed buyer funds.
				None if saved.height == 0 => continue,
				None => {
					return Err(Error::Generic(format!(
						"Recorded refund deposit {} is missing; it has not been marked refunded",
						saved.out_point
					)))
				}
			};
			if output.value != saved.value {
				return Err(Error::Generic(format!(
					"Refund deposit amount changed for {}",
					saved.out_point
				)));
			}
			if output.height > 0 && output.height <= tip {
				available.push((*output).clone());
			}
		}
		Ok(available)
	}

	pub(super) fn carry(&self, observations: &[BatchObservation]) -> Result<Option<Output>, Error> {
		let Some(batch) = self.batches.last() else {
			return Ok(None);
		};
		let hash = observations
			.last()
			.and_then(|o| o.txid)
			.ok_or_else(|| Error::Generic("Refund parent is not confirmed".into()))?;
		// Legacy refunds paid the external address and did not create a carry.
		if batch.legacy_txid == Some(hash)
			&& !batch.attempts.iter().any(|a| a.transaction.txid == hash)
		{
			return Ok(None);
		}
		let attempt = batch
			.attempts
			.iter()
			.find(|a| a.transaction.txid == hash)
			.ok_or_else(|| Error::Generic("Confirmed refund attempt is missing".into()))?;
		Ok(attempt.carry_output.clone())
	}
}

/// Buyer-only carry script. No seller key or timelock is needed to recover it.
pub(super) fn carry_script(secp: &Secp256k1, key: &SecretKey) -> Result<Script, Error> {
	Ok(Builder::new()
		.push_slice(&PublicKey::from_secret_key(secp, key)?.serialize_vec(secp, true)?)?
		.push_opcode(OP_CHECKSIG)
		.into_script())
}

fn script_sig(signature: &[u8], script: &Script, carry: bool) -> Result<Script, Error> {
	let builder = Builder::new().push_slice(signature)?;
	let builder = if carry {
		builder
	} else {
		builder.push_opcode(bitcoin::blockdata::opcodes::OP_TRUE)
	};
	Ok(builder.push_slice(script.as_bytes())?.into_script())
}

/// Upper bound on the marginal fee, including the script's CompactSize prefix.
/// Batches have at most 32 inputs, so adding an input cannot widen their count
/// prefix. Maximum DER length and upward rounding match transaction sizing.
pub(super) fn incremental_input_fee(
	currency: Currency,
	fee: SecondaryFeeUnits,
	script: &Script,
) -> Result<u64, Error> {
	currency.validate_secondary_fee_units(fee)?;
	if matches!(fee, SecondaryFeeUnits::FlatAtomic(_)) {
		return Ok(0);
	}
	let input = TxIn {
		previous_output: OutPoint::null(),
		script_sig: script_sig(&[0; 73], script, false)?,
		sequence: 0,
		witness: Vec::new(),
	};
	let size = input
		.consensus_encode(&mut std::io::sink())
		.map_err(|e| Error::Generic(format!("Unable to size refund input: {e}")))?;
	currency.secondary_fee_amount(
		fee,
		u64::try_from(size)
			.map_err(|_| Error::DataOverflow("Refund input size overflow".into()))?,
	)
}

/// Unsigned template with maximum DER lengths for a conservative fee estimate.
fn template(
	currency: Currency,
	inputs: &[Output],
	spends_carry: bool,
	output_script: &Script,
	lock_script: &Script,
	carry_script: &Script,
	fee: SecondaryFeeUnits,
	lock_time: i64,
) -> Result<Transaction, Error> {
	// New selections are bounded by MAX_REFUND_INPUTS. An imported, previously
	// signed refund may be larger and must retain its inputs when replaced.
	if inputs.is_empty() {
		return Err(Error::Generic("Refund batch has no inputs".into()));
	}
	let lock_time = lock_time
		.checked_add(1)
		.filter(|_| lock_time > 0)
		.and_then(|n| u32::try_from(n).ok())
		.ok_or_else(|| {
			Error::DataOverflow("Refund lock time exceeds the supported timestamp range".into())
		})?;
	let mut total = 0_u64;
	let mut seen = HashSet::new();
	let mut input = Vec::with_capacity(inputs.len());
	for (index, output) in inputs.iter().enumerate() {
		if !seen.insert(output.out_point) {
			return Err(Error::Generic("Duplicate refund input".into()));
		}
		total = total
			.checked_add(output.value)
			.ok_or_else(|| Error::DataOverflow("Refund input amount overflow".into()))?;
		let carry = spends_carry && index == 0;
		input.push(TxIn {
			previous_output: output.out_point,
			script_sig: script_sig(
				&[0; 73],
				if carry { carry_script } else { lock_script },
				carry,
			)?,
			sequence: 0,
			witness: Vec::new(),
		});
	}
	let mut tx = Transaction {
		version: 2,
		lock_time,
		input,
		output: vec![TxOut {
			value: total,
			script_pubkey: output_script.clone(),
		}],
	};
	let size = u64::try_from(tx.get_weight()? / 4)
		.map_err(|_| Error::DataOverflow("Refund size overflow".into()))?;
	let fee_amount = currency.secondary_fee_amount(fee, size)?;
	let minimum = minimum_output(currency, output_script)?;
	let value = total.checked_sub(fee_amount).filter(|value| *value >= minimum)
		.ok_or_else(|| Error::Generic(format!("Refund funds cannot cover fees and a spendable output: inputs={total}, fee={fee_amount}, minimum_output={minimum}; all remaining deposits are retained")))?;
	tx.output[0].value = value;
	Ok(tx)
}

/// Check the selected batch and subsequent batches funded by its carry output.
/// `ordered` starts with the selected deposits, followed by other confirmed
/// inventory only when the first batch creates a carry output.
pub(super) fn check_remaining_fees(
	currency: Currency,
	ordered: &[Output],
	carry: Option<Output>,
	first_count: usize,
	first_output_is_carry: bool,
	destination: &Script,
	lock_script: &Script,
	carry_script: &Script,
	fee: SecondaryFeeUnits,
	lock_time: i64,
) -> Result<(), Error> {
	if ordered.is_empty() {
		let carry = carry.ok_or_else(|| Error::Generic("No refund inputs".into()))?;
		template(
			currency,
			&[carry],
			true,
			destination,
			lock_script,
			carry_script,
			fee,
			lock_time,
		)?;
		return Ok(());
	}
	let mut carry = carry;
	let mut rest = ordered;
	let mut first = true;
	while !rest.is_empty() {
		let capacity = MAX_REFUND_INPUTS - usize::from(carry.is_some());
		let count = if first {
			first_count
		} else {
			capacity.min(rest.len())
		};
		if count == 0 || (!first && count > capacity) || count > rest.len() {
			return Err(Error::Generic("Invalid refund fee plan".into()));
		}
		let mut inputs = Vec::with_capacity(count + usize::from(carry.is_some()));
		if let Some(output) = &carry {
			inputs.push(output.clone());
		}
		inputs.extend_from_slice(&rest[..count]);
		rest = &rest[count..];
		let creates_carry = if first {
			first_output_is_carry
		} else {
			!rest.is_empty()
		};
		let output_script = if creates_carry {
			carry_script.to_p2sh()
		} else {
			destination.clone()
		};
		let tx = template(
			currency,
			&inputs,
			carry.is_some(),
			&output_script,
			lock_script,
			carry_script,
			fee,
			lock_time,
		)?;
		carry = if creates_carry {
			Some(Output {
				out_point: OutPoint::new(tx.txid()?, 0),
				value: tx.output[0].value,
				height: 0,
			})
		} else {
			None
		};
		first = false;
	}
	if let Some(carry) = carry {
		template(
			currency,
			&[carry],
			true,
			destination,
			lock_script,
			carry_script,
			fee,
			lock_time,
		)?;
	}
	Ok(())
}

pub(super) fn build_batch(
	context_id: u32,
	currency: Currency,
	address: &String,
	inputs: Vec<Output>,
	spends_carry: bool,
	creates_carry: bool,
	lock_script: &Script,
	carry_script: &Script,
	fee: SecondaryFeeUnits,
	lock_time: i64,
	key: &SecretKey,
	secp: &Secp256k1,
) -> Result<BtcRefundTransaction, Error> {
	if !matches!(
		currency,
		Currency::Btc | Currency::Bch | Currency::Ltc | Currency::Dash | Currency::Doge
	) {
		return Err(Error::UnexpectedCoinType);
	}
	let output_script = if creates_carry {
		carry_script.to_p2sh()
	} else {
		currency.address_2_script_pubkey(context_id, address)?
	};
	let mut tx = template(
		currency,
		&inputs,
		spends_carry,
		&output_script,
		lock_script,
		carry_script,
		fee,
		lock_time,
	)?;
	let bch_tx = if currency == Currency::Bch {
		Some(BtcData::convert_tx_to_bch(&tx)?)
	} else {
		None
	};
	let mut bch_cache = mwc_wallet_util::mwc_bch::transaction::sighash::SigHashCache::new();
	for (index, input) in inputs.iter().enumerate() {
		let carry = spends_carry && index == 0;
		let script = if carry { carry_script } else { lock_script };
		let msg = if let Some(bch_tx) = &bch_tx {
			let amount = i64::try_from(input.value)
				.map_err(|_| Error::DataOverflow("BCH refund input exceeds i64".into()))?;
			let hash = mwc_wallet_util::mwc_bch::transaction::sighash::sighash(
				bch_tx,
				index,
				script.as_bytes(),
				mwc_wallet_util::mwc_bch::util::Amount(amount),
				0x41,
				&mut bch_cache,
			)
			.map_err(|e| Error::BchError(format!("Refund sighash failed: {e}")))?;
			Message::from_slice(&hash.0)?
		} else {
			Message::from_slice(tx.signature_hash(index, script, 0x01)?.as_ref())?
		};
		let mut signature = secp.sign(&msg, key)?;
		tx.input[index].script_sig = if carry {
			// Signing already emits low-S; the carry has no refund branch selector.
			let mut bytes = signature.serialize_der(secp)?;
			bytes.push(if currency == Currency::Bch {
				0x41
			} else {
				0x01
			});
			script_sig(&bytes, script, true)?
		} else {
			BtcData::refund_script_sig(&currency, &mut signature, script, secp)?
		};
	}
	let weight = tx.get_weight()?;
	if weight > 400_000 {
		return Err(Error::SecondaryTransactionTooHeavy {
			actual: weight,
			maximum: 400_000,
		});
	}
	let txid = tx.txid()?;
	let carry_output = creates_carry.then(|| Output {
		out_point: OutPoint::new(txid, 0),
		value: tx.output[0].value,
		height: 0,
	});
	let mut bytes = Vec::new();
	tx.consensus_encode(&mut bytes)
		.map_err(|e| Error::Generic(format!("Unable to encode refund batch: {e}")))?;
	Ok(BtcRefundTransaction {
		transaction: BtcTtansaction {
			txid: sha256d::Hash::from_byte_array(txid.to_byte_array()),
			tx: bytes,
		},
		inputs,
		address: address.clone(),
		fee_units: fee,
		carry_output,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::blockdata::script::Instruction;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, EcdsaSignature};

	#[test]
	fn refund_incremental_fee_boundary_and_compact_size() {
		// A long script forces the input's CompactSize prefix to expand.
		let script = Script::from(vec![0; 300]);
		let fee = SecondaryFeeUnits::RatePerKvb(1_400);
		assert_eq!(
			incremental_input_fee(Currency::Btc, fee, &script).unwrap(),
			590
		);
		let outputs = [589, 590, 591]
			.iter()
			.enumerate()
			.map(|(i, value)| Output {
				out_point: OutPoint::new(Txid::from_byte_array([1; 32]), i as u32),
				value: *value,
				height: 1,
			})
			.collect();
		let mut plan = BtcRefundPlan::new(outputs).unwrap();
		assert_eq!(
			plan.skip_uneconomic(Currency::Btc, fee, &script).unwrap(),
			2
		);
		assert_eq!(plan.pending[0].value, 591);
		assert_eq!(plan.unrefunded_amount().unwrap(), 1_179);
		assert!(plan
			.unrefunded
			.iter()
			.all(|o| o.incremental_fee == 590 && o.fee_units == fee));
		assert_eq!(
			plan.skip_uneconomic(Currency::Btc, fee, &script).unwrap(),
			0
		);
		// A per-transaction flat fee must not be charged again per input.
		assert_eq!(
			incremental_input_fee(
				Currency::Doge,
				SecondaryFeeUnits::FlatAtomic(1_000_000),
				&script
			)
			.unwrap(),
			0
		);
	}

	#[test]
	fn refund_bch_mixed_carry_and_swap_signatures() {
		mwc_wallet_util::mwc_core::global::set_local_chain_type(
			mwc_wallet_util::mwc_core::global::ChainTypes::Floonet,
		);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let key = SecretKey::from_slice(&secp, &[7; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &key).unwrap();
		let carry_script = carry_script(&secp, &key).unwrap();
		// A distinct locking script is sufficient to verify that each input uses
		// its own script and amount in the BCH signature hash.
		let lock_script = Builder::new()
			.push_opcode(bitcoin::blockdata::opcodes::all::OP_DROP)
			.push_slice(&public_key.serialize_vec(&secp, true).unwrap())
			.unwrap()
			.push_opcode(OP_CHECKSIG)
			.into_script();
		let address = mwc_wallet_util::mwc_bch::address::cashaddr_encode(
			&[9; 20],
			mwc_wallet_util::mwc_bch::address::AddressType::P2SH,
			mwc_wallet_util::mwc_bch::network::Network::Testnet,
		)
		.unwrap();
		let inputs: Vec<_> = (0..4)
			.map(|index| Output {
				out_point: OutPoint::new(Txid::from_byte_array([3; 32]), index),
				value: 100_000 + u64::from(index),
				height: 1,
			})
			.collect();
		let batch = build_batch(
			0,
			Currency::Bch,
			&address,
			inputs.clone(),
			true,
			false,
			&lock_script,
			&carry_script,
			SecondaryFeeUnits::RatePerKvb(1_400),
			1_600_000_000,
			&key,
			&secp,
		)
		.unwrap();
		let tx: Transaction = bitcoin::consensus::deserialize(&batch.transaction.tx).unwrap();
		let bch = BtcData::convert_tx_to_bch(&tx).unwrap();
		for (index, input) in inputs.iter().enumerate() {
			let mut cache = mwc_wallet_util::mwc_bch::transaction::sighash::SigHashCache::new();
			let script = if index == 0 {
				&carry_script
			} else {
				&lock_script
			};
			let hash = mwc_wallet_util::mwc_bch::transaction::sighash::sighash(
				&bch,
				index,
				script.as_bytes(),
				mwc_wallet_util::mwc_bch::util::Amount(input.value as i64),
				0x41,
				&mut cache,
			)
			.unwrap();
			let pushes = tx.input[index]
				.script_sig
				.instructions_minimal()
				.collect::<Result<Vec<_>, _>>()
				.unwrap();
			let signature = match pushes[0] {
				Instruction::PushBytes(bytes) => bytes,
				_ => panic!("signature missing"),
			};
			assert_eq!(signature.last(), Some(&0x41));
			let signature =
				EcdsaSignature::from_der(&secp, &signature[..signature.len() - 1]).unwrap();
			secp.verify(
				&Message::from_slice(&hash.0).unwrap(),
				&signature,
				&public_key,
			)
			.unwrap();
		}
		let fee = inputs.iter().map(|o| o.value).sum::<u64>() - tx.output[0].value;
		assert!(
			fee >= Currency::Bch
				.secondary_fee_amount(
					SecondaryFeeUnits::RatePerKvb(1_400),
					batch.transaction.tx.len() as u64
				)
				.unwrap()
		);
	}
}
