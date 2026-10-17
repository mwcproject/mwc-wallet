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

use super::client::Output;
use crate::swap::message::SecondaryUpdate;
use crate::swap::ser::*;
use crate::swap::swap;
use crate::swap::types::{Currency, Network, SecondaryData};
use crate::swap::{Error, Keychain};
use crate::SecondaryFeeUnits;
use bitcoin::blockdata::opcodes::{all::*, OP_FALSE, OP_TRUE};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::Encodable;
use bitcoin::network::constants;
#[cfg(test)]
#[cfg(all(test, feature = "test-support"))]
use bitcoin::OutPoint;
use bitcoin::{Address, Script, Transaction, TxIn, TxOut, VarInt};
use mwc_wallet_util::bitcoin_hashes::{hash160, sha256d};
use mwc_wallet_util::mwc_bch;
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
use mwc_wallet_util::mwc_crates::secp::{EcdsaSignature, Message};
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_keychain::{Identifier, SwitchCommitmentType};
use std::io::Cursor;

use mwc_wallet_util::mwc_crates::secp::Secp256k1;

/// Maximum number of funding outputs accepted before authorizing MWC redemption.
pub const MAX_SWAP_FUNDING_OUTPUTS: usize = 32;
/// Bitcoin Core's standard transaction weight limit (including signed inputs).
const MAX_BTC_TRANSACTION_WEIGHT: usize = 400_000;

/// Minimum spendable output under default relay policy, in atomic units.
/// Bitcoin/Dash use 3,000 per kB, Litecoin 30,000; BCH uses the legacy 3x rule.
/// Dogecoin uses 0.01 DOGE to avoid its soft dust surcharge.
/// Node policy may be stricter.
pub(super) fn minimum_output(currency: Currency, script: &Script) -> Result<u64, Error> {
	if currency == Currency::Doge {
		return Ok(1_000_000);
	}
	let len = u64::try_from(script.len())
		.map_err(|_| Error::DataOverflow("Secondary output script length".into()))?;
	let prefix = u64::try_from(VarInt(len).len())
		.map_err(|_| Error::DataOverflow("Secondary output script prefix".into()))?;
	let spend_size = if script.is_witness_program() { 67 } else { 148 };
	let multiplier = if currency == Currency::Ltc { 30 } else { 3 };
	len.checked_add(prefix)
		.and_then(|n| n.checked_add(8 + spend_size))
		.and_then(|n| n.checked_mul(multiplier))
		.ok_or_else(|| Error::DataOverflow("Secondary output dust threshold overflow".into()))
}

/// BTC transaction ready to post (any type). Here it is a redeem tx
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct BtcTtansaction {
	pub txid: sha256d::Hash, // keep it is a hash for data compatibility.
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}

/// Prepared buyer refund, retained for rebroadcast and fee replacement.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct BtcRefundTransaction {
	/// Signed transaction ready to broadcast.
	pub transaction: BtcTtansaction,
	/// Original funding outputs, including the amounts needed to sign again.
	pub inputs: Vec<Output>,
	/// Destination used to construct this transaction.
	pub address: String,
	/// Fee setting used to construct this transaction.
	pub fee_units: SecondaryFeeUnits,
	/// Intermediate output owned only by the buyer, used to fund the next batch.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub carry_output: Option<Output>,
}

/// BTC operations context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct BtcData {
	/// Key owned by seller. Private key: keychain + BtcSellerContext::cosign
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
	/// Key owned by buyer
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	pub refund: Option<PublicKey>,
	/// Refund transaction Hash
	pub refund_tx: Option<sha256d::Hash>, // keep it as a hash for data compatibility.
	/// Prepared refund survives mempool spends, restarts and ambiguous broadcasts.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub refund_transaction: Option<BtcRefundTransaction>,
	/// Complete refund inventory and all signed batch/replacement transactions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub refund_plan: Option<super::refund::BtcRefundPlan>,
	/// BTX redeem transaction hash, needed for checking if it is posted
	pub redeem_tx: Option<sha256d::Hash>, // keep it as a hash for data compatibility.
	/// Other redemption hashes that may have been broadcast, including attempts
	/// whose responses were lost and predecessors of fee replacements.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub redeem_tx_candidates: Vec<sha256d::Hash>,
	/// Signed redemption attempts, retained to recognize confirmed scriptSig variants.
	/// Older records contain only hashes until a signing operation retains the bytes;
	/// past replacement transactions cannot be reconstructed from their hashes alone.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub redeem_attempts: Vec<BtcTtansaction>,
	/// Seller's accepted funding outputs. Frozen before releasing the MWC redeem
	/// message so later deposits cannot enlarge redemption or fee replacements.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub redeem_inputs: Option<Vec<Output>>,
	/// Last transaction fee used for BTC, with explicit integer units.
	/// The renamed field deliberately rejects the old float-based schema.
	pub tx_fee_units: Option<SecondaryFeeUnits>,
}

impl BtcData {
	/// Validate the complete funding set; never silently truncate swap funds.
	pub(crate) fn validate_funding_outputs(outputs: &[Output], amount: u64) -> Result<(), Error> {
		if outputs.len() > MAX_SWAP_FUNDING_OUTPUTS {
			return Err(Error::TooManySecondaryOutputs {
				actual: outputs.len(),
				maximum: MAX_SWAP_FUNDING_OUTPUTS,
			});
		}
		if outputs.is_empty() {
			return Err(Error::Generic(
				"Swap funding outputs are missing".to_string(),
			));
		}
		let mut outpoints = std::collections::HashSet::new();
		let mut total = 0_u64;
		for output in outputs {
			if output.value == 0 || !outpoints.insert(output.out_point) {
				return Err(Error::Generic(
					"Invalid or duplicate swap funding output".to_string(),
				));
			}
			total = total
				.checked_add(output.value)
				.ok_or_else(|| Error::DataOverflow("Swap funding amount overflow".to_string()))?;
		}
		if total != amount {
			return Err(Error::Generic(format!(
				"Swap funding amount mismatch: expected {amount}, found {total}"
			)));
		}
		Ok(())
	}

	/// Require the funding set saved before the seller exposed its redeem signature.
	pub(crate) fn accepted_redeem_inputs(&self, amount: u64) -> Result<&Vec<Output>, Error> {
		let outputs = self.redeem_inputs.as_ref().ok_or_else(|| {
			Error::Generic("Accepted swap funding outputs have not been recorded".to_string())
		})?;
		Self::validate_funding_outputs(outputs, amount)?;
		Ok(outputs)
	}

	/// Create seller BTC data (party that receive BTC).
	pub(crate) fn new<K>(
		secp: &Secp256k1,
		keychain: &K,               // Private key
		context: &BtcSellerContext, // Derivarive index
	) -> Result<Self, Error>
	where
		K: Keychain,
	{
		let cosign = PublicKey::from_secret_key(
			secp,
			&keychain.derive_key(secp, 0, &context.cosign, SwitchCommitmentType::None)?,
		)?;

		Ok(Self {
			cosign,
			refund: None,
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		})
	}

	/// Create buyer BTC data (party that sell BTC)
	pub(crate) fn from_offer<K>(
		secp: &Secp256k1,
		keychain: &K,
		offer: BtcOfferUpdate,
		context: &BtcBuyerContext,
	) -> Result<Self, Error>
	where
		K: Keychain,
	{
		let key = keychain.derive_key(secp, 0, &context.refund, SwitchCommitmentType::None)?;

		Ok(Self {
			cosign: offer.cosign,
			refund: Some(PublicKey::from_secret_key(secp, &key)?),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		})
	}

	/// Seller applies accepted offer message from the buyer
	pub(crate) fn accepted_offer(
		&mut self,
		accepted_offer: BtcAcceptOfferUpdate,
	) -> Result<(), Error> {
		self.refund = Some(accepted_offer.refund);
		Ok(())
	}
	/// Return BTC related data
	pub(crate) fn wrap(self) -> SecondaryData {
		SecondaryData::Btc(self)
	}

	/// Generate the multisig-with-timelocked-refund script
	pub fn script(
		&self,
		redeem: &PublicKey,
		btc_lock_time: u64,
		secp: &Secp256k1,
	) -> Result<Script, Error> {
		let current_time = swap::get_cur_time();
		// Keep the maximum check at the script-construction boundary even though
		// new offers are rejected at ingress. Legacy/imported persisted swaps can
		// bypass today's offer validator, so the final lock-bearing artifact needs
		// its own defense-in-depth assurance.
		let max_lock_time = u64::try_from(current_time)
			.ok()
			.and_then(|time| {
				u64::try_from(swap::MAX_SWAP_LOCK_INTERVAL_SECONDS)
					.ok()
					.and_then(|interval| time.checked_add(interval))
			})
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"BtcData::script, maximum BTC lock time overflow, current_time={current_time}"
				))
			})?;
		if btc_lock_time > max_lock_time {
			return Err(Error::Generic(
				"BTC locking time interval exceeds 30 days. Rejecting, looks like a scam."
					.to_string(),
			));
		}

		let lock_time = i64::try_from(btc_lock_time).map_err(|error| {
			Error::DataOverflow(format!(
				"BtcData::script, BTC locking time exceeds i64, btc_lock_time={} error={}",
				btc_lock_time, error
			))
		})?;
		let btc_lock_time = swap::validate_secondary_lock_time(lock_time, current_time)?;

		// Locking for the past is very expected. We build this script every time when we need to calculate hash for the address.

		let refund = self
			.refund
			.ok_or(Error::SecondaryDataIncomplete)?
			.serialize_vec(secp, true)?;
		let cosign = self.cosign.serialize_vec(secp, true)?;
		let redeem = redeem.serialize_vec(secp, true)?;

		let builder = Builder::new()
			.push_opcode(OP_IF) // Refund path
			// CLTV uses signed-magnitude Script numbers, including five-byte timestamps.
			.push_int(i64::from(btc_lock_time))?
			.push_opcode(OP_CLTV) // Check transaction lock time
			.push_opcode(OP_DROP)
			.push_slice(refund.as_slice())?
			.push_opcode(OP_CHECKSIG) // Check signature
			.push_opcode(OP_ELSE) // Redeem path
			.push_opcode(OP_PUSHNUM_2)
			.push_slice(cosign.as_slice())?
			.push_slice(redeem.as_slice())?
			.push_opcode(OP_PUSHNUM_2)
			.push_opcode(OP_CHECKMULTISIG) // Check 2-of-2 multisig
			.push_opcode(OP_ENDIF);

		Ok(builder.into_script())
	}

	/// Generate the P2SH address for the script
	pub fn address(
		&self,
		currency: Currency,
		script: &Script,
		network: Network,
	) -> Result<Vec<String>, Error> {
		match currency {
			Currency::Btc => {
				let address = Address::new_btc().p2sh(script, btc_network(network));
				Ok(vec![address.to_string()])
			}
			Currency::Bch => {
				// Bch Address
				let script_hash = hash160::Hash::hash(&script[..]);
				let address = mwc_bch::address::cashaddr_encode(
					script_hash.as_byte_array(),
					mwc_bch::address::AddressType::P2SH,
					bch_network(network),
				)
				.map_err(|e| {
					Error::BchError(format!(
						"Unable to encode BCH address from script hash, {}",
						e
					))
				})?;
				// Legacy BCH address is BTC address, some might like it as well
				let legacy_address = mwc_bch::address::legacyaddr_encode(
					script_hash.as_byte_array(),
					mwc_bch::address::AddressType::P2SH,
					bch_network(network),
				)
				.map_err(|e| {
					Error::BchError(format!("Unable to encode legacy BCH address, {}", e))
				})?;
				Ok(vec![address, legacy_address])
			}
			Currency::Ltc => {
				let address = Address::new_ltc().p2sh(script, btc_network(network));
				Ok(vec![address.to_string()])
			}
			/*			Currency::Bsv => {
				// Bsv deleted pay to script hash, so we need a script instead
				// https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki
				let mut script_res = Vec::new();
				script_res.push(1); // version
				match network {
					Network::Mainnet => {
						script_res.push(1); // mainnet: 1
					}
					Network::Floonet => {
						script_res.push(2); // testnet: 1
					}
				}
				script_res.append(&mut script.to_bytes().to_vec());

				let mut script_res = format!("bitcoin-script:{}", to_hex(&script_res));

				let checksum = crate::slatepack::generate_check(script_res.as_bytes())?;
				debug_assert!(checksum.len() == 4);

				script_res.push_str(&to_hex(&checksum));
				Ok(script_res)
			}*/
			Currency::Dash => {
				let address = Address::new_dash().p2sh(script, btc_network(network));
				Ok(vec![address.to_string()])
			}
			Currency::ZCash => {
				let address = Address::new_zec().p2sh(script, btc_network(network));
				Ok(vec![address.to_string()])
			}
			Currency::Doge => {
				let address = Address::new_doge().p2sh(script, btc_network(network));
				Ok(vec![address.to_string()])
			}
			_ => return Err(Error::UnexpectedCoinType),
		}
	}

	// Build input/output for redeem or refund btc transaciton
	// Inputs need to have amounts for BCH signature
	fn build_input_outputs(
		context_id: u32,
		currency: &Currency,
		redeem_address: &String,
		conf_outputs: &Vec<Output>,
	) -> Result<(Vec<(TxIn, u64)>, Vec<TxOut>, u64), Error> {
		// Input(s)
		let mut input = Vec::with_capacity(conf_outputs.len());
		let mut total_amount = 0_u64;
		for o in conf_outputs {
			total_amount = total_amount.checked_add(o.value).ok_or_else(|| {
				Error::DataOverflow(format!(
					"BtcData::build_input_outputs, secondary transaction input amount overflow, total_amount={total_amount} output_value={}",
					o.value
				))
			})?;
			input.push((
				TxIn {
					previous_output: o.out_point.clone(),
					script_sig: Script::new(),
					sequence: 0,
					witness: Vec::new(),
				},
				o.value,
			));
		}

		if input.is_empty() {
			return Err(Error::Generic(
				"Unable to build refund transaction, no inputs are found".to_string(),
			));
		}
		// Output
		let mut output = Vec::with_capacity(1);
		output.push(TxOut {
			value: total_amount, // Will be overwritten later
			script_pubkey: currency.address_2_script_pubkey(context_id, redeem_address)?,
		});

		Ok((input, output, total_amount))
	}

	// Because BCH library can calculate the hash, but for the core we are using BTC, that is
	// why we have this ugly solution. In any case it is better then have 2 separate implemenattions.
	pub(super) fn convert_tx_to_bch(tx: &Transaction) -> Result<mwc_bch::messages::Tx, Error> {
		let mut inputs: Vec<mwc_bch::messages::TxIn> = vec![];
		let mut outputs: Vec<mwc_bch::messages::TxOut> = vec![];

		for tx_in in &tx.input {
			let mut sig_script = mwc_bch::script::Script::new();
			sig_script.append_slice(tx_in.script_sig.as_bytes());

			let prev_output = mwc_bch::messages::OutPoint {
				hash: mwc_bch::util::Hash256::decode(
					tx_in.previous_output.txid.to_string().as_str(),
				)
				.map_err(|e| {
					Error::Generic(format!("Unable to decode transaction outputs, {}", e))
				})?,
				index: tx_in.previous_output.vout,
			};

			inputs.push(mwc_bch::messages::TxIn {
				prev_output,
				// Signature script for confirming authorization
				sig_script,
				sequence: tx_in.sequence,
			})
		}

		for tx_out in &tx.output {
			outputs.push(mwc_bch::messages::TxOut {
				amount: mwc_bch::util::Amount(i64::try_from(tx_out.value).map_err(|_| {
					Error::DataOverflow(format!(
						"BtcData::convert_tx_to_bch, transaction output value exceeds BCH signed range, output_value={}",
						tx_out.value
					))
				})?),
				// Public key script to claim the output
				pk_script: mwc_bch::script::Script(tx_out.script_pubkey.to_bytes()),
			})
		}

		Ok(mwc_bch::messages::Tx {
			lock_time: tx.lock_time,
			version: u32::try_from(tx.version).map_err(|_| {
				Error::DataOverflow(format!(
					"BtcData::convert_tx_to_bch, transaction version is outside u32, version={}",
					tx.version
				))
			})?,
			inputs,
			outputs,
		})
	}

	pub(crate) fn redeem_script_sig(
		currency: &Currency,
		input_script: &Script,
		cosign_signature: &mut EcdsaSignature,
		redeem_signature: &mut EcdsaSignature,
		secp: &Secp256k1,
	) -> Result<Script, Error> {
		let (cosign_ser, redeem_ser) = match currency {
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::ZCash | Currency::Doge => {
				let mut cosign_ser = cosign_signature.serialize_der(secp)?;
				cosign_ser.push(0x01); // SIGHASH_ALL

				let mut redeem_ser = redeem_signature.serialize_der(secp)?;
				redeem_ser.push(0x01); // SIGHASH_ALL

				(cosign_ser, redeem_ser)
			}
			Currency::Bch => {
				cosign_signature.normalize_s(&secp)?;
				let mut cosign_ser = cosign_signature.serialize_der(secp)?;
				cosign_ser.push(0x41); // SIGHASH_ALL

				redeem_signature.normalize_s(&secp)?;
				let mut redeem_ser = redeem_signature.serialize_der(secp)?;
				redeem_ser.push(0x41); // SIGHASH_ALL

				(cosign_ser, redeem_ser)
			}
			Currency::Ether
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
			| Currency::Tst => {
				return Err(Error::Generic(
					"Ether/Erc20-token is not supported".to_string(),
				));
			}
		};

		let script_sig = Builder::new()
			.push_opcode(OP_FALSE) // Bitcoin multisig bug
			.push_slice(&cosign_ser)?
			.push_slice(&redeem_ser)?
			.push_opcode(OP_FALSE) // Choose redeem path in original script
			.push_slice(input_script.as_bytes())?
			.into_script();

		Ok(script_sig)
	}

	/// Use the signer's full transaction sizing, including every accepted input,
	/// to calculate a proposed redemption fee before signing or changing its rate.
	pub(crate) fn redeem_fee(
		context_id: u32,
		currency: &Currency,
		address: &String,
		input_script: &Script,
		fee_units: SecondaryFeeUnits,
		conf_outputs: &Vec<Output>,
	) -> Result<u64, Error> {
		let (input, output, _) =
			Self::build_input_outputs(context_id, currency, address, conf_outputs)?;
		let tx = Transaction {
			version: 2,
			lock_time: 0,
			input: input.into_iter().map(|i| i.0).collect(),
			output,
		};
		let (fee, _) =
			Self::spend_lock_transaction_fee(currency, &tx, input_script, fee_units, true)?;
		Ok(fee)
	}

	fn spend_lock_transaction_fee(
		currency: &Currency,
		tx: &Transaction,
		input_script: &Script,
		fee_units: SecondaryFeeUnits,
		redeem: bool,
	) -> Result<(u64, usize), Error> {
		// Size a copy with maximum DER signatures plus their sighash bytes. The
		// serializer counts every input, script push, CompactSize prefix and output.
		let max_signature = [0u8; 72 + 1];
		let builder = if redeem {
			Builder::new()
				.push_opcode(OP_FALSE)
				.push_slice(&max_signature)?
				.push_slice(&max_signature)?
				.push_opcode(OP_FALSE)
		} else {
			Builder::new()
				.push_slice(&max_signature)?
				.push_opcode(OP_TRUE)
		};
		let size_script = builder.push_slice(input_script.as_bytes())?.into_script();
		let mut sizing_tx = tx.clone();
		for input in &mut sizing_tx.input {
			input.script_sig = size_script.clone();
		}
		// These transactions have no witness, so bytes and vbytes are equal.
		let tx_size = sizing_tx.get_size()?;
		let tx_vbytes = u64::try_from(tx_size).map_err(|_| {
			Error::DataOverflow(format!(
				"BtcData::spend_lock_transaction_fee, transaction size exceeds u64, tx_size={tx_size}"
			))
		})?;
		Ok((currency.secondary_fee_amount(fee_units, tx_vbytes)?, tx_size))
	}

	/// Apply the same affordability and dust rules before authorizing MWC
	/// redemption and when constructing the signed secondary transaction.
	pub(super) fn spend_lock_output_value(
		currency: &Currency,
		output_script: &Script,
		total_amount: u64,
		fee: u64,
	) -> Result<u64, Error> {
		let output_value = total_amount.checked_sub(fee).ok_or_else(|| {
			Error::DataOverflow(format!(
				"BtcData::spend_lock_transaction, secondary transaction fee exceeds input amount, total_amount={total_amount} fee={fee}"
			))
		})?;
		// A nonnegative remainder can still be dust and fail relay. Check the
		// actual destination script before invoking the signing callback.
		let minimum = minimum_output(*currency, output_script)?;
		if output_value < minimum {
			return Err(Error::Generic(format!(
				"Secondary transaction output is below the dust threshold after fees: output={output_value}, minimum_output={minimum}, inputs={total_amount}, fee={fee}"
			)));
		}
		Ok(output_value)
	}

	/// Build BTC Spend Lock transaction. That can be redeem transactrion or Refund. It depend on
	/// script_sig method. That can be  BtcData::refund_script_sig  or BtcData::redeem_script_sig
	/// btc_lock_time must be 0 for redeem and btc_lock_time for refund
	/// Return:  Options values must be defined for BTC only. They can be used for tests only
	pub(crate) fn spend_lock_transaction(
		context_id: u32,
		currency: &Currency,
		address: &String, // refund or
		input_script: &Script,
		fee_units: SecondaryFeeUnits,
		btc_lock_time: i64,
		conf_outputs: &Vec<Output>,
		script_sig: impl Fn(&Message) -> Result<Script, Error>,
	) -> Result<
		(
			BtcTtansaction,
			Option<Transaction>,
			Option<usize>,
			Option<usize>,
		),
		Error,
	> {
		let (input, output, total_amount) =
			Self::build_input_outputs(context_id, currency, address, conf_outputs)?;
		if btc_lock_time < 0 {
			return Err(Error::DataOverflow(format!(
				"BtcData::spend_lock_transaction, BTC lock time is negative, btc_lock_time={btc_lock_time}"
			)));
		}
		let lock_time = if btc_lock_time == 0 {
			0
		} else {
			btc_lock_time
				.checked_add(1)
				.and_then(|lock_time| u32::try_from(lock_time).ok())
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"BtcData::spend_lock_transaction, adjusted BCH lock time exceeds u32, btc_lock_time={btc_lock_time} adjustment=1"
					))
				})?
		};
		let mut tx = Transaction {
			version: 2,
			lock_time, // lock time must be larger for BCH
			input: input.iter().map(|i| i.0.clone()).collect(),
			output,
		};

		// Subtract the checked integer fee from the output. Per-vbyte rates are
		// stored per 1,000 vbytes and rounded upward to avoid underpaying miners.
		let (fee, tx_size) = Self::spend_lock_transaction_fee(
			currency,
			&tx,
			input_script,
			fee_units,
			btc_lock_time == 0,
		)?;

		let output = tx
			.output
			.get_mut(0)
			.ok_or_else(|| Error::Generic("Secondary transaction has no output".to_owned()))?;
		output.value =
			Self::spend_lock_output_value(currency, &output.script_pubkey, total_amount, fee)?;

		match currency {
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::Doge => {
				// Sign for inputs
				for idx in 0..tx.input.len() {
					let hash = tx.signature_hash(idx, input_script, 0x01)?;
					let msg = Message::from_slice(hash.as_ref())?;

					tx.input
						.get_mut(idx)
						.ok_or(Error::Generic("Not found expected input".to_string()))?
						.script_sig = script_sig(&msg)?;
				}
			}
			Currency::Bch => {
				let bch_tx = Self::convert_tx_to_bch(&tx)?;

				// Sign for inputs
				for idx in 0..tx.input.len() {
					// Actually BCH team doesn't allow to reuse the cache. REALLY?  WHY?
					let mut cache = mwc_bch::transaction::sighash::SigHashCache::new();
					let input_value = input
						.get(idx)
						.ok_or_else(|| {
							Error::BchError("Transaction input index is missing".to_owned())
						})?
						.1;
					let input_value = i64::try_from(input_value).map_err(|_| {
						Error::DataOverflow(format!(
							"BtcData::spend_lock_transaction, transaction input value exceeds BCH signed range, input_value={input_value}"
						))
					})?;

					let sighash_type = mwc_bch::transaction::sighash::SIGHASH_ALL
						| mwc_bch::transaction::sighash::SIGHASH_FORKID;
					let hash = mwc_bch::transaction::sighash::sighash(
						&bch_tx,
						idx,
						input_script.as_bytes(),
						mwc_bch::util::Amount(input_value),
						sighash_type,
						&mut cache,
					)
					.map_err(|e| Error::BchError(format!("sighash failed, {}", e)))?;

					let msg = Message::from_slice(&hash.0)?;

					tx.input
						.get_mut(idx)
						.ok_or(Error::Generic("Not found expected input".to_string()))?
						.script_sig = script_sig(&msg)?;
				}
			}
			Currency::ZCash => {
				return Err(Error::Generic(
					"ZCash is not supported. Don't use it.".to_string(),
				));

				// We are builddinbg TransactionData directly from the data. Seems like it is the best option for now.
				// The issue that librustzcash => zcash_primitive doesn't even support the inputs from scripts.
				// But furtunatelly it is expected to be BTC compatible. So we can just copy the data form the Bitcoin
				// TransactionData is smart enough to sign everything and provide the binary data that will act like BTC Tx.
				/*
				let mut zcash_tx_data = mwc_zcash_primitives::transaction::TransactionData::new();
				zcash_tx_data.lock_time = tx.lock_time;
				//zcash_tx_data.expiry_height = mwc_zcash_primitives::consensus::BlockHeight::from_u32(1266946 + 20);
				for inp in &tx.input {
					zcash_tx_data
						.vin
						.push(mwc_zcash_primitives::transaction::components::TxIn {
							prevout: mwc_zcash_primitives::transaction::components::OutPoint::new(
								inp.previous_output.txid.as_hash().into_inner(),
								inp.previous_output.vout,
							),
							script_sig: mwc_zcash_primitives::legacy::Script::default(),
							sequence: inp.sequence,
						});
				}
				for out in &tx.output {
					zcash_tx_data
						.vout
						.push(mwc_zcash_primitives::transaction::components::TxOut {
							value: mwc_zcash_primitives::transaction::components::Amount::from_u64(
								out.value,
							)
							.map_err(|_| {
								Error::Generic("Unable convert amount for ZCash".to_string())
							})?,
							script_pubkey: mwc_zcash_primitives::legacy::Script(
								out.script_pubkey.to_bytes(),
							),
						});
				}

				// Sign inputs ZCash way. Zcash massages are uniques, we have to mainatain it's own branch for that
				let mut sighash = [0u8; 32];
				for idx in 0..zcash_tx_data.vin.len() {
					let input_value = input.get(idx).ok_or_else(|| {
						Error::Generic(format!(
							"BtcData::spend_lock_transaction, Zcash input is missing, input_index={} input_count={} vin_count={}",
							idx,
							input.len(),
							zcash_tx_data.vin.len()
						))
					})?.1;
					sighash.copy_from_slice(
						&mwc_zcash_primitives::transaction::signature_hash_data(
							&zcash_tx_data,
							mwc_zcash_primitives::consensus::BranchId::Canopy,
							mwc_zcash_primitives::transaction::SIGHASH_ALL,
							mwc_zcash_primitives::transaction::SignableInput::transparent(
								idx,
								&mwc_zcash_primitives::legacy::Script(input_script.to_bytes()),
								mwc_zcash_primitives::transaction::components::Amount::from_u64(
									input_value,
								)
								.map_err(|_| Error::Generic("Invalid input amount".to_string()))?,
							),
						),
					);

					let msg = Message::from_slice(&sighash).map_err(|e| {
						Error::Generic(format!(
							"ZCash, unable to build a message from sighash (32 bytes), {}",
							e
						))
					})?;

					let vin_count = zcash_tx_data.vin.len();
					zcash_tx_data
						.vin
						.get_mut(idx)
						.ok_or_else(|| {
							Error::Generic(format!(
								"BtcData::spend_lock_transaction, Zcash transaction input is missing, input_index={} vin_count={}",
								idx, vin_count
							))
						})?
						.script_sig =
						mwc_zcash_primitives::legacy::Script(script_sig(&msg)?.to_bytes());
				}

				let zcash_tx = zcash_tx_data.freeze()?;
				let mut raw_tx = vec![];
				zcash_tx.write(&mut raw_tx)?;

				return Ok((
					BtcTtansaction {
						txid: sha256d::Hash::from_slice(&zcash_tx.txid().0).map_err(|e| {
							Error::Generic(format!("Unable to convert Hash data for ZCash, {}", e))
						})?,
						tx: raw_tx,
					},
					None,
					None,
					None,
				));*/
			}
			Currency::Ether
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
			| Currency::Tst => {
				return Err(Error::Generic(
					"Ether/Erc20-tonken is not supported".to_string(),
				));
			}
		};

		// DER lengths vary per input. Enforce relay policy on the fully signed transaction.
		if *currency == Currency::Btc {
			let weight = tx.get_weight()?;
			if weight > MAX_BTC_TRANSACTION_WEIGHT {
				return Err(Error::SecondaryTransactionTooHeavy {
					actual: weight,
					maximum: MAX_BTC_TRANSACTION_WEIGHT,
				});
			}
		}
		let mut cursor = Cursor::new(Vec::with_capacity(tx_size));
		let actual_size = tx
			.consensus_encode(&mut cursor)
			.map_err(|e| Error::Generic(format!("Unable to encode redeem tx, {}", e)))?;
		let actual_vbytes = u64::try_from(actual_size).map_err(|_| {
			Error::DataOverflow(format!(
				"BtcData::spend_lock_transaction, signed transaction size exceeds u64, actual_size={actual_size}"
			))
		})?;
		let required_fee = currency.secondary_fee_amount(fee_units, actual_vbytes)?;
		if fee < required_fee {
			return Err(Error::Generic(format!(
				"Secondary transaction fee below required rate: fee={fee} required_fee={required_fee} actual_vbytes={actual_vbytes}"
			)));
		}

		Ok((
			BtcTtansaction {
				txid: sha256d::Hash::from_byte_array(tx.txid()?.to_byte_array()),
				tx: cursor.into_inner(),
			},
			Some(tx),
			Some(tx_size),
			Some(actual_size),
		))
	}

	pub(crate) fn refund_script_sig(
		currency: &Currency,
		signature: &mut EcdsaSignature,
		input_script: &Script,
		secp: &Secp256k1,
	) -> Result<Script, Error> {
		let sign_ser = match currency {
			Currency::Bch => {
				signature.normalize_s(secp)?;
				let mut sign_ser = signature.serialize_der(secp)?;
				sign_ser.push(0x41); // SIGHASH_ALL
				sign_ser
			}
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::ZCash | Currency::Doge => {
				let mut sign_ser = signature.serialize_der(secp)?;
				sign_ser.push(0x01); // SIGHASH_ALL
				sign_ser
			}
			Currency::Ether
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
			| Currency::Tst => {
				return Err(Error::Generic(
					"Ether/Erc20-token is not supported".to_string(),
				));
			}
		};

		let script_sig = Builder::new()
			.push_slice(&sign_ser)?
			.push_opcode(OP_TRUE) // Choose refund path in original script
			.push_slice(input_script.as_bytes())?
			.into_script();

		Ok(script_sig)
	}

	/// Seller init BTC offer for buyer
	pub(crate) fn offer_update(&self) -> BtcUpdate {
		BtcUpdate::Offer(BtcOfferUpdate {
			cosign: self.cosign.clone(), // Buyer part of Schnorr multisig.
		})
	}

	/// Seller apply respond for the Buyer.
	pub(crate) fn accept_offer_update(&self) -> Result<BtcUpdate, Error> {
		Ok(BtcUpdate::AcceptOffer(BtcAcceptOfferUpdate {
			refund: self
				.refund
				.ok_or(Error::Generic(
					"BTC refund pubkey is not defined at BtcAcceptOfferUpdate payload".into(),
				))?
				.clone(),
		}))
	}
}

/// Context for the Seller (party that receive BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct BtcSellerContext {
	/// Seller, cosign index for derivative key.
	pub cosign: Identifier,
}

/// Context for the Buyer (party that sell BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct BtcBuyerContext {
	/// Buyer refund index for derivative key
	pub refund: Identifier,
}

/// Messages regarding BTC part of the deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "serde")]
pub enum BtcUpdate {
	/// Seller send offer to Buyer. Here is details about BTC deal
	Offer(BtcOfferUpdate),
	/// Buyer message back to Seller. Offer is accepted
	AcceptOffer(BtcAcceptOfferUpdate),
}

impl BtcUpdate {
	/// Unwrap BtcOfferUpdate  with data type verification
	pub fn unwrap_offer(self) -> Result<BtcOfferUpdate, Error> {
		match self {
			BtcUpdate::Offer(u) => Ok(u),
			_ => Err(Error::UnexpectedMessageType(
				"Fn unwrap_offer() expecting BtcUpdate::Offer".to_string(),
			)),
		}
	}

	/// Unwrap BtcAcceptOfferUpdate  with data type verification
	pub fn unwrap_accept_offer(self) -> Result<BtcAcceptOfferUpdate, Error> {
		match self {
			BtcUpdate::AcceptOffer(u) => Ok(u),
			_ => Err(Error::UnexpectedMessageType(
				"Fn unwrap_accept_offer() expecting BtcUpdate::AcceptOffer".to_string(),
			)),
		}
	}

	/// Wrap thos BTC object into SecondaryUpdate message.
	pub fn wrap(self) -> SecondaryUpdate {
		SecondaryUpdate::BTC(self)
	}
}

/// Seller send offer to Buyer. Here is details about BTC deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "serde")]
pub struct BtcOfferUpdate {
	/// Public key to do cosign with Schnorr signature.
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
}

/// Buyer message back to Seller. Offer is accepted
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "serde")]
pub struct BtcAcceptOfferUpdate {
	/// Buyer public key for refund
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub refund: PublicKey,
}

/// Map MWC network to matched BTC network
fn btc_network(network: Network) -> constants::Network {
	match network {
		Network::Floonet => constants::Network::Testnet,
		Network::Mainnet => constants::Network::Bitcoin,
	}
}

fn bch_network(network: Network) -> mwc_bch::network::Network {
	match network {
		Network::Floonet => mwc_bch::network::Network::Testnet,
		Network::Mainnet => mwc_bch::network::Network::Mainnet,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[cfg(feature = "test-support")]
	use bitcoin::util::address::Payload;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::global;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_core::global::ChainTypes;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::rand::rngs::SysRng;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::rand::{rng, RngExt};
	use mwc_wallet_util::mwc_crates::secp::key::PublicKey;
	#[cfg(feature = "test-support")]
	use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
	use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_wallet_util::mwc_util::from_hex;
	#[cfg(feature = "test-support")]
	use std::collections::HashMap;

	#[test]
	fn btc_transaction_fee_rejects_the_legacy_field() {
		let legacy = r#"{
			"cosign": "02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef",
			"refund": null,
			"refund_tx": null,
			"redeem_tx": null,
			"tx_fee": 1.4
		}"#;
		assert!(mwc_wallet_util::mwc_crates::serde_json::from_str::<BtcData>(legacy).is_err());
	}

	#[test]
	/// Test vector from the PoC
	fn test_lock_script() {
		let lock_time = 1541355813;

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let data = BtcData {
			cosign: PublicKey::from_slice(
				&secp,
				&from_hex(
					"02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef".into(),
				)
				.unwrap(),
			)
			.unwrap(),
			refund: Some(
				PublicKey::from_slice(
					&secp,
					&from_hex(
						"022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2".into(),
					)
					.unwrap(),
				)
				.unwrap(),
			),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		};

		let input_script = data
			.script(
				&PublicKey::from_slice(
					&secp,
					&from_hex(
						"03cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c".into(),
					)
					.unwrap(),
				)
				.unwrap(),
				lock_time,
				&secp,
			)
			.unwrap();
		let script_ref = from_hex("63042539df5bb17521022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2ac67522102b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef2103cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c52ae68".into()).unwrap();
		assert_eq!(input_script.clone().to_bytes(), script_ref);

		assert_eq!(
			format!(
				"{}",
				data.address(Currency::Btc, &input_script, Network::Floonet)
					.unwrap()[0]
			),
			String::from("2NEwEAG9VyFYt2sjLpuHrU4Abb7nGJfc7PR")
		);
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn test_redeem_script() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let network = Network::Floonet;
		swap::set_testing_cur_time(1567632152);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let rng = &mut rng();
		let mut sys_rng = SysRng;

		let cosign = SecretKey::new(&secp, &mut sys_rng).unwrap();
		let refund = SecretKey::new(&secp, &mut sys_rng).unwrap();
		let redeem = SecretKey::new(&secp, &mut sys_rng).unwrap();

		let lock_time = swap::get_cur_time() as u64;

		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		};
		let input_script = data
			.script(
				&PublicKey::from_secret_key(&secp, &redeem).unwrap(),
				lock_time,
				&secp,
			)
			.unwrap();
		let lock_address = data.address(Currency::Btc, &input_script, network).unwrap();
		let lock_script_pubkey = Currency::Btc
			.address_2_script_pubkey(0, &lock_address[0])
			.unwrap();

		// Create a bunch of funding transactions
		let count = rng.random_range(3..7);
		let mut funding_txs = HashMap::with_capacity(count);

		let mut confirmed_outputs = Vec::new();

		for i in 0..count {
			let value = (i as u64 + 1) * 1_000_000;

			// Generate a bunch of trash P2PKH and P2SH outputs
			let vout = rng.random_range(0usize..5);
			let mut output = Vec::with_capacity(vout + 1);
			for _ in 0..vout {
				let mut hash = [0_u8; 20];
				rng.fill(&mut hash);
				let payload = if rng.random_bool(0.5) {
					Payload::PubkeyHash(bitcoin::PubkeyHash::from_byte_array(hash))
				} else {
					Payload::ScriptHash(bitcoin::ScriptHash::from_byte_array(hash))
				};
				let script_pubkey = payload.script_pubkey().unwrap();
				output.push(TxOut {
					value: rng.random(),
					script_pubkey,
				});
			}
			output.push(TxOut {
				value,
				script_pubkey: lock_script_pubkey.clone(),
			});

			let tx = Transaction {
				version: 2,
				lock_time: lock_time as u32 - 1,
				input: vec![],
				output,
			};

			let txid = tx.txid().unwrap();
			confirmed_outputs.push(Output {
				out_point: OutPoint {
					txid: txid.clone(),
					vout: vout as u32,
				},
				value,
				height: 1,
			});
			funding_txs.insert(tx.txid().unwrap(), tx);
		}

		let redeem_address = Address::new_btc()
			.p2pkh(
				&secp,
				&bitcoin::util::key::PublicKey {
					compressed: true,
					key: PublicKey::from_secret_key(
						&secp,
						&SecretKey::new(&secp, &mut sys_rng).unwrap(),
					)
					.unwrap(),
				},
				btc_network(network),
			)
			.unwrap();

		let redeem_script_sig = |msg: &Message| {
			let mut cosign_signature = secp.sign(msg, &cosign)?;
			let mut redeem_signature = secp.sign(msg, &redeem)?;
			secp.verify(msg, &cosign_signature, &data.cosign)?;
			secp.verify(
				msg,
				&redeem_signature,
				&PublicKey::from_secret_key(&secp, &redeem)?,
			)?;
			BtcData::redeem_script_sig(
				&Currency::Btc,
				&input_script,
				&mut cosign_signature,
				&mut redeem_signature,
				&secp,
			)
		};

		// Generate redeem transaction
		let (_btc_tx, tx, est_size, actual_size) = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&redeem_address.to_string(),
			&input_script,
			SecondaryFeeUnits::RatePerKvb(10_000),
			0,
			&confirmed_outputs,
			redeem_script_sig,
		)
		.unwrap();
		let actual_size = actual_size.unwrap();
		assert!(est_size.unwrap() >= actual_size);

		// The in-memory node validates that every input exists and value is conserved.
		let verify_fn = |out_point: &OutPoint| match funding_txs.get(&out_point.txid) {
			Some(tx) => match tx.output.get(out_point.vout as usize) {
				Some(out) => Some(out.clone()),
				None => None,
			},
			None => None,
		};
		let tx = tx.unwrap();
		let input_value = tx
			.input
			.iter()
			.try_fold(0_u64, |total, input| {
				let output = verify_fn(&input.previous_output).unwrap();
				total.checked_add(output.value)
			})
			.unwrap();
		let output_value = tx
			.output
			.iter()
			.try_fold(0_u64, |total, output| total.checked_add(output.value))
			.unwrap();
		assert!(output_value <= input_value);
		let required_fee = Currency::Btc
			.secondary_fee_amount(
				SecondaryFeeUnits::RatePerKvb(10_000),
				u64::try_from(actual_size).unwrap(),
			)
			.unwrap();
		assert!(input_value.checked_sub(output_value).unwrap() >= required_fee);
	}

	#[cfg(not(feature = "test-support"))]
	#[test]
	fn test_redeem_script() {
		panic!("test-support feature is required to run the tests");
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn spend_lock_transaction_rejects_dust_before_signing() {
		global::set_local_chain_type(ChainTypes::Mainnet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let cosign = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let redeem = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		let refund = SecretKey::from_slice(&secp, &[3; 32]).unwrap();
		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		};
		let lock_time = 1_541_355_813;
		let script = data
			.script(
				&PublicKey::from_secret_key(&secp, &redeem).unwrap(),
				lock_time,
				&secp,
			)
			.unwrap();
		let destinations = [
			(
				Script::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([4; 20])),
				546,
			),
			(
				Script::new_p2sh(&bitcoin::ScriptHash::from_byte_array([4; 20])),
				540,
			),
			(
				Builder::new()
					.push_int(0)
					.unwrap()
					.push_slice(&[4; 20])
					.unwrap()
					.into_script(),
				294,
			),
			(
				Builder::new()
					.push_int(0)
					.unwrap()
					.push_slice(&[4; 32])
					.unwrap()
					.into_script(),
				330,
			),
			(
				Builder::new()
					.push_int(1)
					.unwrap()
					.push_slice(&[4; 32])
					.unwrap()
					.into_script(),
				330,
			),
		];
		for currency in [
			Currency::Btc,
			Currency::Bch,
			Currency::Ltc,
			Currency::Dash,
			Currency::Doge,
		] {
			for (destination, btc_minimum) in &destinations {
				if destination.is_witness_program()
					&& !matches!(currency, Currency::Btc | Currency::Ltc)
				{
					continue;
				}
				let minimum = match currency {
					Currency::Ltc => btc_minimum * 10,
					Currency::Doge => 1_000_000,
					_ => *btc_minimum,
				};
				let address = match currency {
					Currency::Ltc => Address::new_ltc(),
					Currency::Dash => Address::new_dash(),
					Currency::Doge => Address::new_doge(),
					_ => Address::new_btc(), // BCH accepts legacy BTC-format addresses.
				}
				.from_script(destination, btc_network(Network::Mainnet))
				.unwrap()
				.to_string();
				currency.validate_address(0, &address).unwrap();
				for btc_lock_time in [0, i64::try_from(lock_time).unwrap()] {
					let build = |amount: u64, must_not_sign: bool| {
						let inputs = vec![Output {
							out_point: OutPoint {
								txid: bitcoin::Txid::from_byte_array([5; 32]),
								vout: 0,
							},
							value: amount,
							height: 1,
						}];
						BtcData::spend_lock_transaction(
							0,
							&currency,
							&address,
							&script,
							currency.get_default_fee(&Network::Mainnet),
							btc_lock_time,
							&inputs,
							|message| {
								assert!(
									!must_not_sign,
									"Insufficient outputs must be rejected before signing"
								);
								if btc_lock_time == 0 {
									BtcData::redeem_script_sig(
										&currency,
										&script,
										&mut secp.sign(message, &cosign)?,
										&mut secp.sign(message, &redeem)?,
										&secp,
									)
								} else {
									BtcData::refund_script_sig(
										&currency,
										&mut secp.sign(message, &refund)?,
										&script,
										&secp,
									)
								}
							},
						)
					};
					// Establish the fee using ample funds, then vary only the remainder.
					let (_, tx, _, _) = build(1_000_000_000, false).unwrap();
					let fee = 1_000_000_000 - tx.unwrap().output[0].value;
					assert!(matches!(build(fee - 1, true), Err(Error::DataOverflow(_))));
					for remainder in [0, 1, minimum - 1] {
						let error = build(fee + remainder, true).unwrap_err();
						assert!(
							matches!(error, Error::Generic(ref message)
							if message.contains("below the dust threshold")
								&& message.contains(&format!("minimum_output={minimum}"))),
							"{error}"
						);
					}
					for remainder in [minimum, minimum + 1] {
						let (raw, tx, _, _) = build(fee + remainder, false).unwrap();
						let tx = tx.unwrap();
						assert_eq!(tx.output[0].value, remainder);
						assert_eq!(&tx.output[0].script_pubkey, destination);
						assert_eq!(
							bitcoin::consensus::deserialize::<Transaction>(&raw.tx).unwrap(),
							tx
						);
					}
				}
			}
		}
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn spend_lock_transaction_fees_cover_signed_size() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let cosign = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let redeem = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		let refund = SecretKey::from_slice(&secp, &[3; 32]).unwrap();
		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		};
		let lock_time = 1_541_355_813;
		let script = data
			.script(
				&PublicKey::from_secret_key(&secp, &redeem).unwrap(),
				lock_time,
				&secp,
			)
			.unwrap();
		let destination = Script::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([4; 20]));
		// This legacy testnet address is also supported by BCH.
		let address = Address::new_btc()
			.from_script(&destination, btc_network(Network::Floonet))
			.unwrap()
			.to_string();
		let outputs: Vec<_> = (3..35)
			.map(|vout| Output {
				out_point: OutPoint {
					txid: bitcoin::Txid::from_byte_array([5; 32]),
					vout,
				},
				value: 1_000_000,
				height: 1,
			})
			.collect();

		// The single-input BTC redemption at 1 sat/vB previously paid 352 sats
		// for 353 bytes. Exercise refunds and the maximum accepted input count too.
		for currency in [Currency::Btc, Currency::Bch] {
			for input_count in [1, MAX_SWAP_FUNDING_OUTPUTS] {
				let inputs = outputs[..input_count].to_vec();
				let total: u64 = inputs.iter().map(|input| input.value).sum();
				for btc_lock_time in [0, i64::try_from(lock_time).unwrap()] {
					for fee_units in [
						SecondaryFeeUnits::RatePerKvb(1_000),
						SecondaryFeeUnits::RatePerKvb(1_400),
					] {
						let (raw, tx, estimated, actual) = BtcData::spend_lock_transaction(
							0,
							&currency,
							&address,
							&script,
							fee_units,
							btc_lock_time,
							&inputs,
							|message| {
								if btc_lock_time == 0 {
									BtcData::redeem_script_sig(
										&currency,
										&script,
										&mut secp.sign(message, &cosign)?,
										&mut secp.sign(message, &redeem)?,
										&secp,
									)
								} else {
									BtcData::refund_script_sig(
										&currency,
										&mut secp.sign(message, &refund)?,
										&script,
										&secp,
									)
								}
							},
						)
						.unwrap();
						let tx = tx.unwrap();
						let actual = actual.unwrap();
						assert_eq!(actual, raw.tx.len());
						assert_eq!(actual, tx.get_weight().unwrap() / 4);
						assert!(estimated.unwrap() >= actual);
						let paid_fee = total.checked_sub(tx.output[0].value).unwrap();
						let required_fee = currency
							.secondary_fee_amount(fee_units, u64::try_from(actual).unwrap())
							.unwrap();
						assert!(paid_fee >= required_fee);
					}
				}
			}
		}

		// A callback producing a larger script than the selected spend path must
		// fail the final fee check, even if the transaction meets the weight limit.
		let result = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&address,
			&script,
			SecondaryFeeUnits::RatePerKvb(1_000),
			i64::try_from(lock_time).unwrap(),
			&outputs[..1].to_vec(),
			|message| {
				BtcData::redeem_script_sig(
					&Currency::Btc,
					&script,
					&mut secp.sign(message, &cosign)?,
					&mut secp.sign(message, &redeem)?,
					&secp,
				)
			},
		);
		assert!(matches!(result, Err(Error::Generic(message))
			if message.contains("fee below required rate")));
	}

	// Exercise the transaction builder directly, independently of the 32-input
	// acceptance gate. Sign real redeem and refund scripts: a 32-input redemption
	// must fit, the reported 400-input redemption must return a weight error, and
	// the smaller 400-input refund must still fit the same relay-weight limit.
	#[cfg(feature = "test-support")]
	#[test]
	fn completed_bitcoin_redemption_enforces_standard_weight() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let cosign = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let redeem = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &redeem).unwrap()),
			refund_tx: None,
			refund_transaction: None,
			refund_plan: None,
			redeem_tx: None,
			redeem_tx_candidates: Vec::new(),
			redeem_attempts: Vec::new(),
			redeem_inputs: None,
			tx_fee_units: None,
		};
		let script = data
			.script(&data.refund.unwrap(), 1_541_355_813, &secp)
			.unwrap();
		let address = "my3RJuHrqhuCzVyft13VYRjGRQM51xg9rr".to_string();
		let outputs: Vec<_> = (0..400)
			.map(|vout| Output {
				out_point: OutPoint {
					txid: bitcoin::Txid::from_byte_array([3; 32]),
					vout,
				},
				value: 100_000,
				height: 1,
			})
			.collect();
		let sign = |message: &Message| {
			BtcData::redeem_script_sig(
				&Currency::Btc,
				&script,
				&mut secp.sign(message, &cosign)?,
				&mut secp.sign(message, &redeem)?,
				&secp,
			)
		};
		// The largest input set allowed by the new acceptance policy is redeemable.
		let (_, tx, _, _) = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&address,
			&script,
			SecondaryFeeUnits::RatePerKvb(10_000),
			0,
			&outputs[..32].to_vec(),
			&sign,
		)
		.unwrap();
		assert!(tx.unwrap().get_weight().unwrap() <= MAX_BTC_TRANSACTION_WEIGHT);
		// Bypass admission deliberately to verify the final signed-weight guard.
		// The builder must return an error instead of an oversized transaction.
		let result = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&address,
			&script,
			SecondaryFeeUnits::RatePerKvb(10_000),
			0,
			&outputs,
			sign,
		);
		assert!(
			matches!(result, Err(Error::SecondaryTransactionTooHeavy { actual, maximum })
			if actual > maximum && maximum == 400_000)
		);
		// The same 400 outputs remain refundable: the acceptance limit belongs
		// before the seller's signature, not in the shared refund constructor.
		let (_, refund, _, _) = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&address,
			&script,
			SecondaryFeeUnits::RatePerKvb(10_000),
			1_541_355_813,
			&outputs,
			|message| {
				BtcData::refund_script_sig(
					&Currency::Btc,
					&mut secp.sign(message, &redeem)?,
					&script,
					&secp,
				)
			},
		)
		.unwrap();
		assert!(refund.unwrap().get_weight().unwrap() <= MAX_BTC_TRANSACTION_WEIGHT);
	}
}
