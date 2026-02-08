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
use crate::mwc_keychain::{Identifier, SwitchCommitmentType};
use crate::mwc_util::secp::key::PublicKey;
use crate::mwc_util::secp::{Message, Signature};
use crate::swap::message::SecondaryUpdate;
use crate::swap::ser::*;
use crate::swap::swap;
use crate::swap::types::{Currency, Network, SecondaryData};
use crate::swap::{Error, Keychain};
use bitcoin::blockdata::opcodes::{all::*, OP_FALSE, OP_TRUE};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::Encodable;
use bitcoin::network::constants::Network as BtcNetwork;
#[cfg(test)]
use bitcoin::OutPoint;
use bitcoin::{Address, Script, Transaction, TxIn, TxOut, VarInt};
use bitcoin_hashes::sha256d;
use byteorder::{ByteOrder, LittleEndian};
use std::io::Cursor;
use std::ops::Deref;

use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{hash160, Hash};
use mwc_bch::messages::{Tx as BchTx, TxIn as BchTxIn, TxOut as BchTxOut};

use mwc_wallet_util::mwc_util::secp::Secp256k1;
use mwc_zcash_primitives::transaction as zcash_tx;

/// BTC transaction ready to post (any type). Here it is a redeem tx
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcTtansaction {
	pub txid: sha256d::Hash, // keep it is a hash for data compatibility.
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}

/// BTC operations context
#[derive(Serialize, Deserialize, Debug, Clone)]
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
	/// BTX redeem transaction hash, needed for checking if it is posted
	pub redeem_tx: Option<sha256d::Hash>, // keep it as a hash for data compatibility.
	/// Last transaction fee that was used for BTC. Needed to detect the fact that it is changed.
	pub tx_fee: Option<f32>,
}

impl BtcData {
	/// Create seller BTC data (party that receive BTC).
	pub(crate) fn new<K>(
		keychain: &K,               // Private key
		context: &BtcSellerContext, // Derivarive index
	) -> Result<Self, Error>
	where
		K: Keychain,
	{
		let cosign = PublicKey::from_secret_key(
			keychain.secp(),
			&keychain.derive_key(0, &context.cosign, SwitchCommitmentType::None)?,
		)?;

		Ok(Self {
			cosign,
			refund: None,
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		})
	}

	/// Create buyer BTC data (party that sell BTC)
	pub(crate) fn from_offer<K>(
		keychain: &K,
		offer: BtcOfferUpdate,
		context: &BtcBuyerContext,
	) -> Result<Self, Error>
	where
		K: Keychain,
	{
		let key = keychain.derive_key(0, &context.refund, SwitchCommitmentType::None)?;

		Ok(Self {
			cosign: offer.cosign,
			refund: Some(PublicKey::from_secret_key(keychain.secp(), &key)?),
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
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
		// Don't lock for more than 4 weeks. 4 weeks + 2 day, because max locking is expecting 2 weeks and 1 day to do the swap and 1 extra day for Byer
		if btc_lock_time > (swap::get_cur_time() + 3600 * 24 * (7 * 4 + 2)) as u64 {
			return Err(Error::Generic(
				"BTC locking time interval is larger than 4 weeks. Rejecting, looks like a scam."
					.to_string(),
			));
		}

		if btc_lock_time >= u32::MAX as u64 {
			return Err(Error::Generic(
				"BTC locking time is out of range. Rejecting, looks like a scam.".to_string(),
			));
		}

		// Locking for the past is very expected. We build this script every time when we need to calculate hash for the address.

		let mut time = [0; 4];
		let btc_lock_time: u32 = btc_lock_time as u32;
		LittleEndian::write_u32(&mut time, btc_lock_time);

		let refund = self
			.refund
			.ok_or(Error::SecondaryDataIncomplete)?
			.serialize_vec(secp, true);
		let cosign = self.cosign.serialize_vec(secp, true);
		let redeem = redeem.serialize_vec(secp, true);

		let builder = Builder::new()
			.push_opcode(OP_IF) // Refund path
			.push_slice(&time)
			.push_opcode(OP_CLTV) // Check transaction lock time
			.push_opcode(OP_DROP)
			.push_slice(refund.as_slice())
			.push_opcode(OP_CHECKSIG) // Check signature
			.push_opcode(OP_ELSE) // Redeem path
			.push_opcode(OP_PUSHNUM_2)
			.push_slice(cosign.as_slice())
			.push_slice(redeem.as_slice())
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
					&script_hash,
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
					&script_hash,
					mwc_bch::address::AddressType::P2SH,
					bch_network(network),
				);
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
		let mut total_amount = 0;
		for o in conf_outputs {
			total_amount += o.value;
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
	fn convert_tx_to_bch(tx: &Transaction) -> Result<BchTx, Error> {
		let mut inputs: Vec<BchTxIn> = vec![];
		let mut outputs: Vec<BchTxOut> = vec![];

		for tx_in in &tx.input {
			let mut sig_script = mwc_bch::script::Script::new();
			sig_script.append_slice(tx_in.script_sig.as_bytes());

			let prev_output = mwc_bch::messages::OutPoint {
				hash: mwc_bch::util::Hash256::decode(tx_in.previous_output.txid.to_hex().as_str())
					.map_err(|e| {
						Error::Generic(format!("Unable to decode transaction outputs, {}", e))
					})?,
				index: tx_in.previous_output.vout,
			};

			inputs.push(BchTxIn {
				prev_output,
				// Signature script for confirming authorization
				sig_script,
				sequence: tx_in.sequence,
			})
		}

		for tx_out in &tx.output {
			outputs.push(BchTxOut {
				amount: mwc_bch::util::Amount(tx_out.value as i64),
				// Public key script to claim the output
				pk_script: mwc_bch::script::Script(tx_out.script_pubkey.to_bytes()),
			})
		}

		Ok(BchTx {
			lock_time: tx.lock_time,
			version: tx.version as u32,
			inputs,
			outputs,
		})
	}

	pub(crate) fn redeem_script_sig(
		currency: &Currency,
		input_script: &Script,
		cosign_signature: &mut Signature,
		redeem_signature: &mut Signature,
		secp: &Secp256k1,
	) -> Result<Script, Error> {
		let (cosign_ser, redeem_ser) = match currency {
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::ZCash | Currency::Doge => {
				let mut cosign_ser = cosign_signature.serialize_der(secp);
				cosign_ser.push(0x01); // SIGHASH_ALL

				let mut redeem_ser = redeem_signature.serialize_der(secp);
				redeem_ser.push(0x01); // SIGHASH_ALL

				(cosign_ser, redeem_ser)
			}
			Currency::Bch => {
				cosign_signature.normalize_s(&secp);
				let mut cosign_ser = cosign_signature.serialize_der(secp);
				cosign_ser.push(0x41); // SIGHASH_ALL

				redeem_signature.normalize_s(&secp);
				let mut redeem_ser = redeem_signature.serialize_der(secp);
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
			.push_slice(&cosign_ser)
			.push_slice(&redeem_ser)
			.push_opcode(OP_FALSE) // Choose redeem path in original script
			.push_slice(input_script.as_bytes())
			.into_script();

		Ok(script_sig)
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
		fee: f32,
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
		let mut tx = Transaction {
			version: 2,
			lock_time: if btc_lock_time == 0 {
				0
			} else {
				(btc_lock_time + 1) as u32
			}, // lock time must be larger for BCH
			input: input.iter().map(|i| i.0.clone()).collect(),
			output,
		};

		let number_of_signatures = if btc_lock_time > 0 { 1 } else { 2 };

		// Calculate tx size
		let mut script_sig_size = input_script.len();
		script_sig_size += VarInt(script_sig_size as u64).len();
		script_sig_size += number_of_signatures * (1 + 72 + 1); // Signature (uno for refund)
		script_sig_size += number_of_signatures; // Opcodes (by accident they match number of signatures)
		let tx_size = tx.get_weight() / 4 + script_sig_size * tx.input.len();

		// Subtract fee from output
		let (_, k, is_per_byte) = currency.get_fee_units();
		let fee = if is_per_byte {
			(tx_size as f32 * fee * k as f32 + 0.5) as u64
		} else {
			(fee * k as f32 + 0.5) as u64
		};

		tx.output[0].value = total_amount.saturating_sub(fee);

		match currency {
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::Doge => {
				// Sign for inputs
				for idx in 0..tx.input.len() {
					let hash = tx.signature_hash(idx, input_script, 0x01);
					let msg = Message::from_slice(hash.deref())?;

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

					let sighash_type = mwc_bch::transaction::sighash::SIGHASH_ALL
						| mwc_bch::transaction::sighash::SIGHASH_FORKID;
					let hash = mwc_bch::transaction::sighash::sighash(
						&bch_tx,
						idx,
						input_script.as_bytes(),
						mwc_bch::util::Amount(input[idx].1 as i64),
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
				// We are builddinbg TransactionData directly from the data. Seems like it is the best option for now.
				// The issue that librustzcash => zcash_primitive doesn't even support the inputs from scripts.
				// But furtunatelly it is expected to be BTC compatible. So we can just copy the data form the Bitcoin
				// TransactionData is smrt enough to sign everything and provide the binary data that will act like BTC Tx.

				let mut zcash_tx_data = zcash_tx::TransactionData::new();
				zcash_tx_data.lock_time = tx.lock_time;
				//zcash_tx_data.expiry_height = mwc_zcash_primitives::consensus::BlockHeight::from_u32(1266946 + 20);
				for inp in &tx.input {
					zcash_tx_data.vin.push(zcash_tx::components::TxIn {
						prevout: zcash_tx::components::OutPoint::new(
							inp.previous_output.txid.as_hash().into_inner(),
							inp.previous_output.vout,
						),
						script_sig: mwc_zcash_primitives::legacy::Script::default(),
						sequence: inp.sequence,
					});
				}
				for out in &tx.output {
					zcash_tx_data.vout.push(zcash_tx::components::TxOut {
						value: zcash_tx::components::Amount::from_u64(out.value).map_err(|_| {
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
					sighash.copy_from_slice(&zcash_tx::signature_hash_data(
						&zcash_tx_data,
						mwc_zcash_primitives::consensus::BranchId::Canopy,
						zcash_tx::SIGHASH_ALL,
						zcash_tx::SignableInput::transparent(
							idx,
							&mwc_zcash_primitives::legacy::Script(input_script.to_bytes()),
							zcash_tx::components::Amount::from_u64(input[idx].1)
								.map_err(|_| Error::Generic("Invalid input amount".to_string()))?,
						),
					));

					let msg = Message::from_slice(&sighash).map_err(|e| {
						Error::Generic(format!(
							"ZCash, unable to build a message from sighash (32 bytes), {}",
							e
						))
					})?;

					zcash_tx_data.vin[idx].script_sig =
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
				));
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

		let mut cursor = Cursor::new(Vec::with_capacity(tx_size));
		let actual_size = tx
			.consensus_encode(&mut cursor)
			.map_err(|e| Error::Generic(format!("Unable to encode redeem tx, {}", e)))?;

		// By some reasons length is floating, probably encoding can do some optimization . Let'e keep an eye on it, we don't want to calcucate fee badly.
		debug_assert!(actual_size <= tx_size + 4);
		debug_assert!(actual_size >= tx_size - 5);

		Ok((
			BtcTtansaction {
				txid: tx.txid().as_hash(),
				tx: cursor.into_inner(),
			},
			Some(tx),
			Some(tx_size),
			Some(actual_size),
		))
	}

	pub(crate) fn refund_script_sig(
		currency: &Currency,
		signature: &mut Signature,
		input_script: &Script,
		secp: &Secp256k1,
	) -> Result<Script, Error> {
		let sign_ser = match currency {
			Currency::Bch => {
				signature.normalize_s(secp);
				let mut sign_ser = signature.serialize_der(secp);
				sign_ser.push(0x41); // SIGHASH_ALL
				sign_ser
			}
			Currency::Btc | Currency::Ltc | Currency::Dash | Currency::ZCash | Currency::Doge => {
				let mut sign_ser = signature.serialize_der(secp);
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
			.push_slice(&sign_ser)
			.push_opcode(OP_TRUE) // Choose refund path in original script
			.push_slice(input_script.as_bytes())
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
pub struct BtcSellerContext {
	/// Seller, cosign index for derivative key.
	pub cosign: Identifier,
}

/// Context for the Buyer (party that sell BTC)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcBuyerContext {
	/// Buyer refund index for derivative key
	pub refund: Identifier,
}

/// Messages regarding BTC part of the deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
pub struct BtcOfferUpdate {
	/// Public key to do cosign with Schnorr signature.
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub cosign: PublicKey,
}

/// Buyer message back to Seller. Offer is accepted
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BtcAcceptOfferUpdate {
	/// Buyer public key for refund
	#[serde(serialize_with = "pubkey_to_hex", deserialize_with = "pubkey_from_hex")]
	pub refund: PublicKey,
}

/// Map MWC network to matched BTC network
fn btc_network(network: Network) -> BtcNetwork {
	match network {
		Network::Floonet => BtcNetwork::Testnet,
		Network::Mainnet => BtcNetwork::Bitcoin,
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
	use crate::mwc_core::global;
	use crate::mwc_core::global::ChainTypes;
	use crate::mwc_util::from_hex;
	use crate::mwc_util::secp::key::{PublicKey, SecretKey};
	use crate::mwc_util::secp::{ContextFlag, Secp256k1};
	use bitcoin::util::address::Payload;
	use bitcoin::util::key::PublicKey as BTCPublicKey;
	use mwc_wallet_util::mwc_util::static_secp_instance;
	use rand::{thread_rng, Rng, RngCore};
	use std::collections::HashMap;

	#[test]
	/// Test vector from the PoC
	fn test_lock_script() {
		let lock_time = 1541355813;

		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock().unwrap_or_else(|e| e.into_inner());

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
			redeem_tx: None,
			tx_fee: None,
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

	#[test]
	fn test_redeem_script() {
		global::set_local_chain_type(ChainTypes::Floonet);
		let network = Network::Floonet;
		swap::set_testing_cur_time(1567632152);

		let secp = Secp256k1::with_caps(ContextFlag::Commit);
		let rng = &mut thread_rng();

		let cosign = SecretKey::new(&secp, rng);
		let refund = SecretKey::new(&secp, rng);
		let redeem = SecretKey::new(&secp, rng);

		let lock_time = swap::get_cur_time() as u64;

		let data = BtcData {
			cosign: PublicKey::from_secret_key(&secp, &cosign).unwrap(),
			refund: Some(PublicKey::from_secret_key(&secp, &refund).unwrap()),
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
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
		let count = rng.gen_range(3, 7);
		let mut funding_txs = HashMap::with_capacity(count);

		let mut confirmed_outputs = Vec::new();

		for i in 0..count {
			let value = (i as u64 + 1) * 1_000_000;

			// Generate a bunch of trash P2PKH and P2SH outputs
			let vout = rng.gen_range(0usize, 5);
			let mut output = Vec::with_capacity(vout + 1);
			for _ in 0..vout {
				let mut hash: Vec<u8> = vec![0; 20];
				rng.fill_bytes(&mut hash);
				let hash = hash160::Hash::from_slice(&hash).unwrap();
				let payload = if rng.gen_bool(0.5) {
					Payload::PubkeyHash(hash.into())
				} else {
					Payload::ScriptHash(hash.into())
				};
				let script_pubkey = payload.script_pubkey();
				output.push(TxOut {
					value: rng.gen(),
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

			let txid = tx.txid();
			confirmed_outputs.push(Output {
				out_point: OutPoint {
					txid: txid.clone(),
					vout: vout as u32,
				},
				value,
				height: 1,
			});
			funding_txs.insert(tx.txid(), tx);
		}

		let redeem_address = Address::new_btc().p2pkh(
			&secp,
			&BTCPublicKey {
				compressed: true,
				key: PublicKey::from_secret_key(&secp, &SecretKey::new(&secp, rng)).unwrap(),
			},
			btc_network(network),
		);

		let redeem_script_sig = |msg: &Message| {
			BtcData::redeem_script_sig(
				&Currency::Btc,
				&input_script,
				&mut secp.sign(msg, &cosign)?,
				&mut secp.sign(msg, &redeem)?,
				&secp,
			)
		};

		// Generate redeem transaction
		let (_btc_tx, tx, est_size, actual_size) = BtcData::spend_lock_transaction(
			0,
			&Currency::Btc,
			&redeem_address.to_string(),
			&input_script,
			10.0,
			0,
			&confirmed_outputs,
			redeem_script_sig,
		)
		.unwrap();
		let diff = (est_size.unwrap() as i64 - actual_size.unwrap() as i64).abs() as usize;
		assert!(diff <= count); // Our size estimation should be very close to the real size

		// Moment of truth: our redeem tx should be valid
		let verify_fn = |out_point: &OutPoint| match funding_txs.get(&out_point.txid) {
			Some(tx) => match tx.output.get(out_point.vout as usize) {
				Some(out) => Some(out.clone()),
				None => None,
			},
			None => None,
		};
		tx.unwrap().verify(verify_fn).unwrap();
	}
}
