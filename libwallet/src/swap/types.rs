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

use super::bitcoin::{BtcBuyerContext, BtcData, BtcSellerContext};
use super::ethereum::{EthBuyerContext, EthData, EthSellerContext};
use super::ser::*;
use super::Error;
use crate::swap::message::Message;
use crate::SecondaryFeeUnits;
use bitcoin::Address;
use mwc_wallet_util::mwc_bch;
use mwc_wallet_util::mwc_bitcoin as bitcoin;
use mwc_wallet_util::mwc_core::core::OutputFeatures;
use mwc_wallet_util::mwc_core::global::ChainTypes;
use mwc_wallet_util::mwc_core::{global, ser};
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::zeroize::Zeroizing;
use mwc_wallet_util::mwc_keychain::Identifier;
use mwc_wallet_util::mwc_wagyu_ethereum::EthereumAddress;
use mwc_wallet_util::mwc_web3;
use mwc_wallet_util::sensitive;
use mwc_web3::types::H160;
use std::convert::TryInto;
use std::fmt;
use std::{convert::TryFrom, str::FromStr};

/// MWC Network where SWAP happens.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum Network {
	/// Floonet (testnet)
	Floonet,
	/// Mainnet (production)
	Mainnet,
}

impl Network {
	/// Construct from current chaintype
	pub fn current_network(context_id: u32) -> Result<Self, Error> {
		Ok(Self::from_chain_type(global::get_chain_type(context_id))?)
	}

	/// Constructor from mwc-node ChainTypes
	pub fn from_chain_type(chain_type: ChainTypes) -> Result<Self, Error> {
		match chain_type {
			ChainTypes::Floonet => Ok(Network::Floonet),
			ChainTypes::Mainnet => Ok(Network::Mainnet),
			_ => Err(Error::UnexpectedNetwork(format!("{:?}", chain_type))),
		}
	}
	/// To mwc-node ChainType
	pub fn to_chain_type(&self) -> ChainTypes {
		match self {
			Network::Floonet => ChainTypes::Floonet,
			Network::Mainnet => ChainTypes::Mainnet,
		}
	}
}

impl PartialEq<ChainTypes> for Network {
	fn eq(&self, other: &ChainTypes) -> bool {
		self.to_chain_type() == *other
	}
}

impl PartialEq<Network> for ChainTypes {
	fn eq(&self, other: &Network) -> bool {
		*self == other.to_chain_type()
	}
}

/// Roles of MWC swap participants
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum Role {
	/// Seller - sell MWC for BTC. Params: (<Secondary redeem address>, <change amount>)
	Seller(String, u64),
	/// Buyer  - buy MWC for BTC. Params: (<Refund Address for Secondary>)
	Buyer(Option<String>),
}

/// Secondary currency that swap supports
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(crate = "serde")]
pub enum Currency {
	/// Bitcoin Segwit
	Btc,
	/// Bitcoin Cash
	Bch,
	/// Litecoin, the BTC clone
	Ltc,
	/// Dash
	Dash,
	/// ZCash
	ZCash,
	/// Dogecoin
	Doge,
	/// Ether
	Ether,
	/// Tether USD
	Usdt,
	/// Binance USD
	Busd,
	/// Binance Token
	Bnb,
	/// USD Coin
	Usdc,
	/// ChainLink
	Link,
	/// TRON
	Trx,
	/// Dai Stablecoin
	Dai,
	/// True USD
	Tusd,
	/// Paxos Standard
	Usdp,
	/// Wrapped BTC
	Wbtc,
	/// Test Standard Token (Ropsten)
	Tst,
}

impl Currency {
	/// Satoshi to 1 conversion; Gwei to 1 ether conversion for ETH/Tst ...
	pub fn exponent(&self) -> usize {
		match self {
			Currency::Btc
			| Currency::Bch
			| Currency::Ltc
			| Currency::Dash
			| Currency::ZCash
			| Currency::Doge => 8,
			Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Tst => 9, // 18 is too big , shrink to 9
			Currency::Wbtc => 8,
			Currency::Usdt | Currency::Usdc | Currency::Trx => 6,
		}
	}

	/// Block period for this coin (seconds)
	pub fn block_time_period_sec(&self) -> i64 {
		match self {
			Currency::Btc | Currency::Bch => 10 * 60,
			Currency::Ltc => 60 * 2 + 30,  // Blocks period is 2.5 minutes
			Currency::Dash => 60 * 2 + 39, // 2.65 Minutes
			Currency::ZCash => 75,
			Currency::Doge => 60,
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
			| Currency::Tst => 12, // Ethereum proof-of-stake slot duration.
		}
	}

	/// Print amount in nano coins normally
	pub fn amount_to_hr_string(&self, amount: u64, truncate: bool) -> String {
		let exp = self.exponent();
		let a = format!("{}", amount);
		let len = a.len();
		let pos = len.saturating_sub(exp);
		// `a` is an ASCII decimal rendering and pos is bounded by its byte length,
		// so pos is necessarily a UTF-8 boundary accepted by split_at.
		let (whole, fractional) = a.split_at(pos);
		let (characteristic, mantissa_prefix) = if pos > 0 {
			(whole, String::new())
		} else {
			// The branch is reached only when len <= exp.
			#[allow(
				clippy::arithmetic_side_effects,
				reason = "pos == 0 implies len <= exp, so exp - len cannot underflow"
			)]
			("0", "0".repeat(exp - len))
		};
		let mut mantissa = fractional;
		if truncate {
			mantissa = mantissa.trim_end_matches('0');
			if mantissa.is_empty() {
				mantissa = "0";
			}
		}
		format!("{}.{}{}", characteristic, mantissa_prefix, mantissa)
	}

	/// Convert string amount to Satoshi amount
	pub fn amount_from_hr_string(&self, hr: &str) -> Result<u64, Error> {
		if hr.find(",").is_some() {
			return Err(Error::InvalidAmountString(hr.to_string()));
		}

		let exp = self.exponent();

		let (characteristic, mantissa) = match hr.find(".") {
			Some(pos) => {
				let (c, m) = hr.split_at(pos);
				(parse_characteristic(c)?, parse_mantissa(&m[1..], exp)?)
			}
			None => (parse_characteristic(hr)?, 0),
		};

		// Currency::exponent is at most 9, so 10^exp is at most 1_000_000_000.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the currency exponent is at most 9, so 10_u64.pow(exp) fits u64"
		)]
		let scale = 10_u64.pow(exp as u32);
		let scaled_characteristic = characteristic.checked_mul(scale).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Currency::amount_from_hr_string, amount characteristic scaling overflow, characteristic={} scale={}",
				characteristic, scale
			))
		})?;
		let amount = scaled_characteristic.checked_add(mantissa).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Currency::amount_from_hr_string, amount mantissa addition overflow, scaled_characteristic={} mantissa={}",
				scaled_characteristic, mantissa
			))
		})?;
		if amount == 0 {
			return Err(Error::InvalidAmountString("zero amoount".to_string()));
		}

		Ok(amount)
	}

	fn bch_network(context_id: u32) -> mwc_bch::network::Network {
		if global::is_mainnet(context_id) {
			mwc_bch::network::Network::Mainnet
		} else {
			mwc_bch::network::Network::Testnet
		}
	}

	fn validate_address_network(
		context_id: u32,
		addr: &Address,
		coin_name: &str,
	) -> Result<(), Error> {
		match addr.network {
			bitcoin::network::constants::Network::Bitcoin => {
				if !global::is_mainnet(context_id) {
					return Err(Error::Generic(format!(
						"Address is from main {} network, expected test network",
						coin_name
					)));
				}
			}
			bitcoin::network::constants::Network::Testnet => {
				if global::is_mainnet(context_id) {
					return Err(Error::Generic(format!(
						"Address is from test {} network, expected main network",
						coin_name
					)));
				}
			}
			_ => {
				return Err(Error::Generic(format!(
					"Address is from invalid {} network",
					coin_name
				)));
			}
		}
		Ok(())
	}

	/// Validate the secondary address
	pub fn validate_address(&self, context_id: u32, address: &String) -> Result<(), Error> {
		match self {
			Currency::Btc => {
				let addr = Address::new_btc().from_str(address).map_err(|e| {
					Error::Generic(format!("Unable to parse BTC address {}, {}", address, e))
				})?;
				Self::validate_address_network(context_id, &addr, "BTC")?;
			}
			Currency::Bch => {
				let nw = Self::bch_network(context_id);
				let (v, _addr_type) = match mwc_bch::address::cashaddr_decode(&address, nw) {
					Err(e) => {
						// Try legacy address
						// Intentionally return error from first call. Legacy address error is not interesting much
						let (hash, addr_type) = mwc_bch::address::legacyaddr_decode(&address, nw)
							.map_err(|_| {
							Error::Generic(format!(
								"Unable to parse BCH address {}, {}",
								address, e
							))
						})?;
						(hash.0.to_vec(), addr_type)
					}
					Ok((v, addr_type)) => (v, addr_type),
				};
				if v.len() != 160 / 8 {
					return Err(Error::Generic(
						"Swap supports only Legacy of 160 bit BCH addresses".to_string(),
					));
				}
			}
			Currency::Ltc => {
				let addr = Address::new_ltc().from_str(address).map_err(|e| {
					Error::Generic(format!("Unable to parse LTC address {}, {}", address, e))
				})?;
				Self::validate_address_network(context_id, &addr, "LTC")?;
			}
			Currency::Dash => {
				let addr = Address::new_dash().from_str(address).map_err(|e| {
					Error::Generic(format!("Unable to parse Dash address {}, {}", address, e))
				})?;
				Self::validate_address_network(context_id, &addr, "Dash")?;

				match &addr.payload {
					bitcoin::util::address::Payload::PubkeyHash(_)
					| bitcoin::util::address::Payload::ScriptHash(_) => (),
					_ => {
						// Dash doesn't have Segwit
						return Err(Error::Generic(
							"Address is not supported by Dash".to_string(),
						));
					}
				}
			}
			Currency::ZCash => {
				let addr = Address::new_zec().from_str(address).map_err(|e| {
					Error::Generic(format!(
						"Unable to parse ZCash transparent address {}, {}",
						address, e
					))
				})?;
				Self::validate_address_network(context_id, &addr, "ZCash")?;

				match &addr.payload {
					bitcoin::util::address::Payload::PubkeyHash(_)
					| bitcoin::util::address::Payload::ScriptHash(_) => (),
					_ => {
						// Dash doesn't have Segwit
						return Err(Error::Generic(
							"Address is not supported by ZCash".to_string(),
						));
					}
				}
			}
			Currency::Doge => {
				let addr = Address::new_doge().from_str(address).map_err(|e| {
					Error::Generic(format!(
						"Unable to parse Dogecoin address {}, {}",
						address, e
					))
				})?;
				Self::validate_address_network(context_id, &addr, "Doge")?;

				match &addr.payload {
					bitcoin::util::address::Payload::PubkeyHash(_)
					| bitcoin::util::address::Payload::ScriptHash(_) => (),
					_ => {
						// Dash doesn't have Segwit
						return Err(Error::Generic(
							"Address is not supported by DOgecoin".to_string(),
						));
					}
				}
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
				EthereumAddress::from_str(address.as_str()).map_err(|e| {
					Error::Generic(format!(
						"Unable to parse Ethereum address {}, {}",
						address, e
					))
				})?;
			}
		}
		Ok(())
	}

	/// Generate a script for this address. Address MUST be Hash160
	pub fn address_2_script_pubkey(
		&self,
		context_id: u32,
		address: &String,
	) -> Result<bitcoin::Script, Error> {
		let addr_str = match self {
			Currency::Btc => address.clone(),
			Currency::Bch => {
				// With BCH problem that it doesn't have functionality to build scripts for pay to pubkey
				// That is why we will use BTC library to do that.
				// In order to do that, we need to have legacy address.
				match mwc_bch::address::cashaddr_decode(&address, Self::bch_network(context_id)) {
					Err(_) => {
						// Legacy address - that is what we need
						address.clone()
					}
					Ok((v, addr_type)) => {
						if v.len() != 160 / 8 {
							return Err(Error::Generic(
								"Swap supporting only Legacy of 160 bit BCH addresses".to_string(),
							));
						}

						let ba: Box<[u8; 20]> = v.into_boxed_slice().try_into().map_err(|_| {
							Error::Generic(
								"Internal error. Failed to convert address to hash".to_string(),
							)
						})?;
						let hash_dt: [u8; 20] = *ba;

						let hash160 = mwc_bch::util::Hash160(hash_dt);
						// Converting into legacy address that is equal to BTC.
						mwc_bch::address::legacyaddr_encode(
							&hash160.0,
							addr_type,
							Self::bch_network(context_id),
						)
						.map_err(|e| {
							Error::BchError(format!("Unable to encode legacy BCH address, {}", e))
						})?
					}
				}
			}
			Currency::Ltc => {
				// Converting to BTC address
				let addr = Address::new_ltc().from_str(&address).map_err(|e| {
					Error::Generic(format!("Unable to parse LTC address {}, {}", address, e))
				})?;
				addr.to_btc().to_string()
			}
			Currency::Dash => {
				// Converting to BTC address
				let addr = Address::new_dash().from_str(&address).map_err(|e| {
					Error::Generic(format!("Unable to parse Dash address {}, {}", address, e))
				})?;
				addr.to_btc().to_string()
			}
			Currency::ZCash => {
				// Converting to BTC address
				let addr = Address::new_zec().from_str(&address).map_err(|e| {
					Error::Generic(format!("Unable to parse ZCash address {}, {}", address, e))
				})?;
				addr.to_btc().to_string()
			}
			Currency::Doge => {
				// Converting to BTC address
				let addr = Address::new_doge().from_str(&address).map_err(|e| {
					Error::Generic(format!(
						"Unable to parse Dogecoin address {}, {}",
						address, e
					))
				})?;
				addr.to_btc().to_string()
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
				//todo
				"".to_string()
			}
		};

		let addr = Address::new_btc().from_str(&addr_str).map_err(|e| {
			Error::Generic(format!("Unable to parse BTC address {}, {}", address, e))
		})?;
		Ok(addr.script_pubkey()?)
	}

	/// Return default fee for this coin
	pub fn get_default_fee(&self, network: &Network) -> SecondaryFeeUnits {
		match self {
			Currency::Btc => SecondaryFeeUnits::RatePerKvb(match network {
				Network::Floonet => 1_400,
				Network::Mainnet => 26_000,
			}),
			Currency::Bch => SecondaryFeeUnits::RatePerKvb(match network {
				Network::Floonet => 1_400,
				Network::Mainnet => 24_000,
			}),
			Currency::Ltc => SecondaryFeeUnits::RatePerKvb(match network {
				Network::Floonet => 1_400,
				Network::Mainnet => 100_000,
			}),
			Currency::Dash => SecondaryFeeUnits::RatePerKvb(match network {
				Network::Floonet => 1_400,
				Network::Mainnet => 26_000,
			}),
			Currency::ZCash => SecondaryFeeUnits::FlatAtomic(match network {
				Network::Floonet => 10_000,
				Network::Mainnet => 10_000,
			}),
			Currency::Doge => SecondaryFeeUnits::FlatAtomic(match network {
				Network::Floonet => 100_000_000,
				Network::Mainnet => 300_000_000,
			}),
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
				// Default values
				SecondaryFeeUnits::EthereumGwei(match network {
					Network::Floonet => 5_500_000, // gwei
					Network::Mainnet => 5_500_000,
				})
			}
		}
	}

	/// Convert an API/CLI decimal fee into canonical integer units.
	pub fn normalize_secondary_fee(&self, fee: &str) -> Result<SecondaryFeeUnits, Error> {
		let fee = match self {
			Currency::Btc | Currency::Bch | Currency::Ltc | Currency::Dash => {
				SecondaryFeeUnits::RatePerKvb(parse_secondary_fee_scaled(fee, 3)?)
			}
			Currency::ZCash | Currency::Doge => {
				SecondaryFeeUnits::FlatAtomic(parse_secondary_fee_scaled(fee, 8)?)
			}
			_ => SecondaryFeeUnits::EthereumGwei(parse_secondary_fee_scaled(fee, 0)?),
		};
		self.validate_secondary_fee_units(fee)?;
		Ok(fee)
	}

	/// Validate that a persisted fee uses the units required by this currency.
	pub fn validate_secondary_fee_units(&self, fee: SecondaryFeeUnits) -> Result<(), Error> {
		let value = match (self, fee) {
			(
				Currency::Btc | Currency::Bch | Currency::Ltc | Currency::Dash,
				SecondaryFeeUnits::RatePerKvb(value),
			) => value,
			(Currency::ZCash | Currency::Doge, SecondaryFeeUnits::FlatAtomic(value)) => value,
			(_, SecondaryFeeUnits::EthereumGwei(value)) if !self.is_btc_family() => value,
			_ => return Err(Error::UnexpectedCoinType),
		};
		if value == 0 {
			return Err(Error::Generic(
				"Secondary transaction fee must be greater than zero".to_string(),
			));
		}
		Ok(())
	}

	/// Return a validated BTC-family fee amount in atomic units.
	pub fn secondary_fee_amount(
		&self,
		fee: SecondaryFeeUnits,
		tx_vbytes: u64,
	) -> Result<u64, Error> {
		const VBYTES_PER_KVB: u128 = 1_000;

		self.validate_secondary_fee_units(fee)?;
		match fee {
			SecondaryFeeUnits::RatePerKvb(rate_per_kvb) => {
				// The API rate is expressed per vbyte. RatePerKvb is merely its
				// exact fixed-point representation: 1.4 atomic units/vB becomes
				// 1,400 atomic units/kvB. Convert it back while calculating the
				// transaction fee, rounding upward so the resulting integer fee
				// never falls below the requested per-vbyte rate.
				let scaled_fee = u128::from(rate_per_kvb)
					.checked_mul(u128::from(tx_vbytes))
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"Secondary fee multiplication overflow, rate_per_kvb={} tx_vbytes={}",
							rate_per_kvb, tx_vbytes
						))
					})?;
				let whole_atomic_units = scaled_fee / VBYTES_PER_KVB;
				let fee_atomic_units = if scaled_fee % VBYTES_PER_KVB == 0 {
					whole_atomic_units
				} else {
					whole_atomic_units.checked_add(1).ok_or_else(|| {
						Error::DataOverflow("Secondary fee rounding overflow".to_string())
					})?
				};
				u64::try_from(fee_atomic_units).map_err(|_| {
					Error::DataOverflow(format!(
						"Secondary transaction fee exceeds u64, fee={}",
						fee_atomic_units
					))
				})
			}
			SecondaryFeeUnits::FlatAtomic(value) => Ok(value),
			SecondaryFeeUnits::EthereumGwei(_) => Err(Error::UnexpectedCoinType),
		}
	}

	/// Increase a fee by a rational factor, rounding upward in integer units.
	pub fn bump_secondary_fee(
		&self,
		fee: SecondaryFeeUnits,
		numerator: u64,
		denominator: u64,
	) -> Result<SecondaryFeeUnits, Error> {
		self.validate_secondary_fee_units(fee)?;
		if numerator == 0 || denominator == 0 {
			return Err(Error::Generic(
				"Invalid secondary fee multiplier".to_string(),
			));
		}
		let value = match fee {
			SecondaryFeeUnits::RatePerKvb(value)
			| SecondaryFeeUnits::FlatAtomic(value)
			| SecondaryFeeUnits::EthereumGwei(value) => value,
		};
		let scaled = u128::from(value)
			.checked_mul(u128::from(numerator))
			.and_then(|value| value.checked_add(u128::from(denominator) - 1))
			.ok_or_else(|| Error::DataOverflow("Secondary fee bump overflow".to_string()))?
			/ u128::from(denominator);
		let scaled = u64::try_from(scaled)
			.map_err(|_| Error::DataOverflow("Secondary fee bump exceeds u64".to_string()))?;
		Ok(match fee {
			SecondaryFeeUnits::RatePerKvb(_) => SecondaryFeeUnits::RatePerKvb(scaled),
			SecondaryFeeUnits::FlatAtomic(_) => SecondaryFeeUnits::FlatAtomic(scaled),
			SecondaryFeeUnits::EthereumGwei(_) => SecondaryFeeUnits::EthereumGwei(scaled),
		})
	}

	/// Return a validated Ethereum-family gas budget in whole gwei.
	pub fn secondary_fee_gwei(&self, fee: SecondaryFeeUnits) -> Result<u64, Error> {
		self.validate_secondary_fee_units(fee)?;
		match fee {
			SecondaryFeeUnits::EthereumGwei(value) => Ok(value),
			_ => Err(Error::UnexpectedCoinType),
		}
	}

	/// Fee units for this coin
	/// - Unit String
	/// - Unit multiplier
	/// - true: size-based rate, false: flat fee
	pub fn get_fee_units(&self) -> (String, u64, bool) {
		match self {
			Currency::Btc | Currency::Bch => {
				("satoshi per virtual byte (sat/vB)".to_string(), 1, true)
			}
			Currency::Ltc => ("litoshi per virtual byte".to_string(), 1, true),
			Currency::Dash => ("duff per virtual byte".to_string(), 1, true),
			Currency::ZCash => ("flat fee in ZEC".to_string(), 100_000_000, false),
			Currency::Doge => ("flat fee in DOGE".to_string(), 100_000_000, false),
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
			| Currency::Tst => ("total gas budget in gwei".to_string(), 1, true),
		}
	}

	/// Transaction at the first block. That transaction confirmation number must match the height of the chain
	pub fn get_block1_tx_hash(&self, testnet: bool) -> String {
		// Bch is clone of BTC, so even the same transaction does exist. For other alts that will not be true
		if testnet {
			match self {
				Currency::Btc | Currency::Bch => {
					"f0315ffc38709d70ad5647e22048358dd3745f3ce3874223c80a7c92fab0c8ba".to_string()
				}
				Currency::Ltc => {
					"f7a718f20ea4529351892e70a563f1c58af5e720798e475cc677302ebef92513".to_string()
				}
				Currency::Dash => {
					"b4fd581bc4bfe51a5a66d8b823bd6ee2b492f0ddc44cf7e820550714cedc117f".to_string()
				}
				Currency::ZCash => {
					"f37e9f691fffb635de0999491d906ee85ba40cd36dae9f6e5911a8277d7c5f75".to_string()
				}
				Currency::Doge => {
					"6b591fe460c9cfb75d4406c3787c913022be1caa8641415932ee8c5228ff2e3b".to_string()
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
					"f37e9f691fffb635de0999491d906ee85ba40cd36dae9f6e5911a8277d7c5f75".to_string()
				}
			}
		} else {
			match self {
				Currency::Btc | Currency::Bch => {
					"0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098".to_string()
				}
				Currency::Ltc => {
					"fa3906a4219078364372d0e2715f93e822edd0b47ce146c71ba7ba57179b50f6".to_string()
				}
				Currency::Dash => {
					"ef3ee42b51e2a19c4820ef182844a36db1201c61eb0dec5b42f84be4ad1a1ca7".to_string()
				}
				Currency::ZCash => {
					"851bf6fbf7a976327817c738c489d7fa657752445430922d94c983c0b9ed4609".to_string()
				}
				Currency::Doge => {
					"5f7e779f7600f54e528686e91d5891f3ae226ee907f461692519e549105f521c".to_string()
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
					"f37e9f691fffb635de0999491d906ee85ba40cd36dae9f6e5911a8277d7c5f75".to_string()
				}
			}
		}
	}

	/// check is btc family
	pub fn is_btc_family(&self) -> bool {
		match self {
			Currency::Btc
			| Currency::Bch
			| Currency::Ltc
			| Currency::Dash
			| Currency::ZCash
			| Currency::Doge => true,
			_ => false,
		}
	}

	/// Check whether this currency is supported by the Ethereum wallet surface.
	pub fn is_ethereum_family(&self) -> bool {
		matches!(self, Currency::Ether) || self.is_erc20()
	}

	/// check is erc20 tokens
	pub fn is_erc20(&self) -> bool {
		match self {
			Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Wbtc
			| Currency::Usdt
			| Currency::Usdc
			| Currency::Trx
			| Currency::Tst => true,
			_ => false,
		}
	}

	/// get erc20 token contract address
	pub fn erc20_token_address(&self) -> Result<H160, Error> {
		let address = match self {
			Currency::Usdt => "dac17f958d2ee523a2206206994597c13d831ec7",
			Currency::Busd => "4fabb145d64652a948d72533023f6e7a623c7c53",
			Currency::Bnb => "B8c77482e45F1F44dE1745F52C74426C631bDD52",
			Currency::Usdc => "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			Currency::Link => "514910771af9ca656af840dff83e8264ecf986ca",
			Currency::Trx => "e1be5d3f34e89de342ee97e6e90d405884da6c67",
			Currency::Dai => "6b175474e89094c44da98b954eedeac495271d0f",
			Currency::Tusd => "0000000000085d4780B73119b644AE5ecd22b376",
			Currency::Usdp => "8e870d67f660d95d5be530380d0ec0bd388289e1",
			Currency::Wbtc => "2260fac5e5542a773aa44fbcfedf7c193bc2c599",
			Currency::Tst => "722dd3F80BAC40c951b51BdD28Dd19d435762180",
			_ => return Err(Error::EthUnsupportedERC20TokenError(format!("{}", self))),
		};
		H160::from_str(address).map_err(|e| {
			Error::Generic(format!(
				"Invalid built-in ERC20 token address {}: {}",
				address, e
			))
		})
	}

	/// check if token decimals shrinked from 18 to 9
	pub fn is_expo_shrinked18to9(&self) -> bool {
		match self {
			Currency::Ether
			| Currency::Busd
			| Currency::Bnb
			| Currency::Link
			| Currency::Dai
			| Currency::Tusd
			| Currency::Usdp
			| Currency::Tst => true,
			_ => false,
		}
	}
}

impl fmt::Display for Currency {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let disp = match &self {
			Currency::Btc => "BTC",
			Currency::Bch => "BCH",
			Currency::Ltc => "LTC",
			Currency::Dash => "Dash",
			Currency::ZCash => "ZCash",
			Currency::Doge => "Doge",
			Currency::Ether => "Ether",
			Currency::Busd => "Busd",
			Currency::Bnb => "Bnb",
			Currency::Link => "Link",
			Currency::Dai => "Dai",
			Currency::Tusd => "Tusd",
			Currency::Usdp => "Usdp",
			Currency::Wbtc => "Wbtc",
			Currency::Usdt => "Usdt",
			Currency::Usdc => "Usdc",
			Currency::Trx => "Trx",
			Currency::Tst => "Tst",
		};
		write!(f, "{}", disp)
	}
}

impl TryFrom<&str> for Currency {
	type Error = Error;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		match value.to_lowercase().as_str() {
			"btc" => Ok(Currency::Btc),
			"bch" => Ok(Currency::Bch),
			"ltc" => Ok(Currency::Ltc),
			"dash" => Ok(Currency::Dash),
			"zec" | "zcash" => Ok(Currency::ZCash),
			"doge" => Ok(Currency::Doge),
			"ether" => Ok(Currency::Ether),
			"busd" => Ok(Currency::Busd),
			"bnb" => Ok(Currency::Bnb),
			"link" => Ok(Currency::Link),
			"dai" => Ok(Currency::Dai),
			"tusd" => Ok(Currency::Tusd),
			"usdp" => Ok(Currency::Usdp),
			"wbtc" => Ok(Currency::Wbtc),
			"usdt" => Ok(Currency::Usdt),
			"usdc" => Ok(Currency::Usdc),
			"trx" => Ok(Currency::Trx),
			"tst" => Ok(Currency::Tst),
			_ => Err(Error::InvalidCurrency(value.to_string())),
		}
	}
}

fn parse_characteristic(characteristic: &str) -> Result<u64, Error> {
	if characteristic.len() == 0 {
		return Ok(0);
	}

	characteristic
		.parse()
		.map_err(|_| Error::InvalidAmountString(characteristic.to_string()))
}

fn parse_mantissa(mantissa: &str, exp: usize) -> Result<u64, Error> {
	// Reject excess precision instead of silently truncating it
	if mantissa.len() > exp {
		return Err(Error::InvalidAmountString(format!(
			"Too many digits in fractional part {}, maximum supported digits {}",
			mantissa, exp
		)));
	}
	// Reject anything that is not an ASCII digit. Besides being malformed input,
	// multibyte characters make byte-based truncation panic off a char boundary.
	if !mantissa.bytes().all(|b| b.is_ascii_digit()) {
		return Err(Error::InvalidAmountString(format!(
			"Invalid fractional part {}, expected digits only",
			mantissa
		)));
	}

	format!("{:0<w$}", mantissa, w = exp)
		.parse::<u64>()
		.map_err(|e| {
			Error::InvalidAmountString(format!(
				"Unable to parse fractional part {}, {}",
				mantissa, e
			))
		})
}

fn parse_secondary_fee_scaled(value: &str, decimal_places: u32) -> Result<u64, Error> {
	let (characteristic, mantissa) = match value.split_once('.') {
		Some((characteristic, mantissa)) => (characteristic, mantissa),
		None => (value, ""),
	};
	let has_digit = !characteristic.is_empty() || !mantissa.is_empty();
	let is_decimal = has_digit
		&& characteristic.bytes().all(|byte| byte.is_ascii_digit())
		&& mantissa.bytes().all(|byte| byte.is_ascii_digit());
	if !is_decimal {
		return Err(Error::InvalidAmountString(format!(
			"Invalid secondary fee {}, expected an unsigned ASCII decimal without a unit suffix",
			value
		)));
	}
	let characteristic = if characteristic.is_empty() {
		0_u128
	} else {
		characteristic
			.parse::<u128>()
			.map_err(|_| Error::InvalidAmountString(format!("Invalid secondary fee {}", value)))?
	};
	let significant_mantissa = mantissa.trim_end_matches('0');
	if significant_mantissa.len() > decimal_places as usize {
		return Err(Error::InvalidAmountString(format!(
			"Secondary fee {} has more than {} decimal places for this currency",
			value, decimal_places
		)));
	}
	let mantissa = if significant_mantissa.is_empty() {
		0_u128
	} else {
		significant_mantissa
			.parse::<u128>()
			.map_err(|_| Error::InvalidAmountString(format!("Invalid secondary fee {}", value)))?
	};
	let scale = 10_u128.pow(decimal_places);
	let mantissa_scale = 10_u128.pow(
		decimal_places
			.checked_sub(significant_mantissa.len() as u32)
			.ok_or_else(|| Error::InvalidAmountString(value.to_string()))?,
	);
	let scaled = characteristic
		.checked_mul(scale)
		.and_then(|value| {
			mantissa
				.checked_mul(mantissa_scale)
				.and_then(|m| value.checked_add(m))
		})
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Secondary fee conversion overflow, fee={} decimal_places={}",
				value, decimal_places
			))
		})?;
	u64::try_from(scaled).map_err(|_| {
		Error::DataOverflow(format!(
			"Secondary fee exceeds u64, fee={} scaled_fee={}",
			value, scaled
		))
	})
}

/// Secondary currency related data
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum SecondaryData {
	/// None
	Empty,
	/// Bitcoin data
	Btc(BtcData),
	/// Ether data
	Eth(EthData),
}

impl SecondaryData {
	/// To BTC data
	pub fn unwrap_btc(&self) -> Result<&BtcData, Error> {
		match self {
			SecondaryData::Btc(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
	/// To BTC data
	pub fn unwrap_btc_mut(&mut self) -> Result<&mut BtcData, Error> {
		match self {
			SecondaryData::Btc(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
	/// To ETH data
	pub fn unwrap_eth(&self) -> Result<&EthData, Error> {
		match self {
			SecondaryData::Eth(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
	/// To ETH data
	pub fn unwrap_eth_mut(&mut self) -> Result<&mut EthData, Error> {
		match self {
			SecondaryData::Eth(d) => Ok(d),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
}

/// Buyer/Seller single deal context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct Context {
	/// Multisig key. Both Buyer and Seller using it
	pub multisig_key: Identifier,
	/// Multisig nonce. Both Buyer and Seller using it
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub multisig_nonce: SecretKey,
	/// Nonce that is Required to build a lock slate. Both sides need it.
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub lock_nonce: SecretKey,
	/// Nonce that is Required to build a refund slate. Both sides need it.
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub refund_nonce: SecretKey,
	/// Nonce that is Required to build a redeem slate. Both sides need it.
	#[serde(serialize_with = "seckey_to_hex", deserialize_with = "seckey_from_hex")]
	pub redeem_nonce: SecretKey,
	/// Specific Buyer or Seller context
	pub role_context: RoleContext,
}

impl Context {
	/// To Seller Context
	pub fn unwrap_seller(&self) -> Result<&SellerContext, Error> {
		match &self.role_context {
			RoleContext::Seller(c) => Ok(c),
			RoleContext::Buyer(_) => Err(Error::UnexpectedRole(
				"Context Fn unwrap_seller()".to_string(),
			)),
		}
	}

	/// To Buyer Context
	pub fn unwrap_buyer(&self) -> Result<&BuyerContext, Error> {
		match &self.role_context {
			RoleContext::Seller(_) => Err(Error::UnexpectedRole(
				"Context Fn unwrap_seller()".to_string(),
			)),
			RoleContext::Buyer(c) => Ok(c),
		}
	}
}

impl ser::Writeable for Context {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// Keep the secret nonces in one fixed allocation that is wiped on every exit path.
		let data = sensitive::serialize_json(self).map_err(|e| {
			ser::Error::CorruptedData(format!("OutputData to json conversion failed, {}", e))
		})?;
		writer.write_bytes(&data[..])
	}
}

impl ser::Readable for Context {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Context, ser::Error> {
		let data = Zeroizing::new(reader.read_bytes_len_prefix()?);
		serde_json::from_slice(data.as_slice()).map_err(|e| {
			ser::Error::CorruptedData(format!("Json to OutputData conversion failed, {}", e))
		})
	}
}

/// Context specfic to the swap party role
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum RoleContext {
	/// Seller role
	Seller(SellerContext),
	/// Buyer role
	Buyer(BuyerContext),
}

/// One MWC output selected as an input to the seller's lock transaction.
///
/// The output feature is part of the output identifier and must survive the
/// conversion from wallet `OutputData` into the persisted swap context.  Older
/// contexts stored these values as a three-item tuple and implicitly treated
/// every input as plain, so deserialization retains that representation as a
/// compatibility fallback.
#[derive(Debug, Clone, PartialEq)]
pub struct SellerInput {
	/// Wallet derivation identifier.
	pub key_id: Identifier,
	/// PMMR index, when known.
	pub mmr_index: Option<u64>,
	/// Input value.
	pub amount: u64,
	/// Consensus-relevant output feature.
	pub features: OutputFeatures,
}

impl SellerInput {
	/// Build a seller input from a wallet output.
	pub fn new(key_id: Identifier, mmr_index: Option<u64>, amount: u64, is_coinbase: bool) -> Self {
		Self {
			key_id,
			mmr_index,
			amount,
			features: if is_coinbase {
				OutputFeatures::Coinbase
			} else {
				OutputFeatures::Plain
			},
		}
	}
}

impl Serialize for SellerInput {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		(&self.key_id, self.mmr_index, self.amount, self.features).serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for SellerInput {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(crate = "serde", untagged)]
		enum SellerInputWire {
			FeaturePreserving((Identifier, Option<u64>, u64, OutputFeatures)),
			Legacy((Identifier, Option<u64>, u64)),
		}

		match SellerInputWire::deserialize(deserializer)? {
			SellerInputWire::FeaturePreserving((key_id, mmr_index, amount, features)) => Ok(Self {
				key_id,
				mmr_index,
				amount,
				features,
			}),
			SellerInputWire::Legacy((key_id, mmr_index, amount)) => Ok(Self {
				key_id,
				mmr_index,
				amount,
				features: OutputFeatures::Plain,
			}),
		}
	}
}

/// Context for the seller party
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct SellerContext {
	/// Seller account. Both lock and redeem will go to the same account (not receive)
	pub parent_key_id: Identifier,
	/// MWC inputs that the seller agrees to spend in the lock transaction.
	pub inputs: Vec<SellerInput>,
	/// MWC Change outputs from the lock slate (Derivative ID)
	pub change_output: Identifier,
	/// Lock slate change amount
	pub change_amount: u64,
	/// MWC refund output  (Derivative ID)
	pub refund_output: Identifier,
	/// Secondary currency (BTC/ETH) related context
	pub secondary_context: SecondarySellerContext,
}

impl SellerContext {
	/// Retreive BTC data
	pub fn unwrap_btc(&self) -> Result<&BtcSellerContext, Error> {
		match &self.secondary_context {
			SecondarySellerContext::Btc(c) => Ok(c),
			_ => Err(Error::UnexpectedCoinType),
		}
	}

	/// Retreive ETH data
	pub fn unwrap_eth(&self) -> Result<&EthSellerContext, Error> {
		match &self.secondary_context {
			SecondarySellerContext::Eth(c) => Ok(c),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
}

/// Context for the Buyer party
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct BuyerContext {
	/// Buyer recieve account
	pub parent_key_id: Identifier,
	/// Derivative ID for lock slate output. Buyer part of multisig
	pub output: Identifier,
	/// Secret that unlocks the funds on both chains (Derivative ID)
	pub redeem: Identifier,
	/// Secondary currency (BTC/ETH) related context
	pub secondary_context: SecondaryBuyerContext,
}

impl BuyerContext {
	/// To BTC context
	pub fn unwrap_btc(&self) -> Result<&BtcBuyerContext, Error> {
		match &self.secondary_context {
			SecondaryBuyerContext::Btc(c) => Ok(c),
			_ => Err(Error::UnexpectedCoinType),
		}
	}

	/// To ETH context
	pub fn unwrap_eth(&self) -> Result<&EthBuyerContext, Error> {
		match &self.secondary_context {
			SecondaryBuyerContext::Eth(c) => Ok(c),
			_ => Err(Error::UnexpectedCoinType),
		}
	}
}

/// Seller Secondary currency spepicif context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum SecondarySellerContext {
	/// BTC context
	Btc(BtcSellerContext),
	/// ETH context
	Eth(EthSellerContext),
}

/// Buyer secondary currency context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum SecondaryBuyerContext {
	/// BTC context
	Btc(BtcBuyerContext),
	/// ETH context
	Eth(EthBuyerContext),
}

/// Action or step of the swap process
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub enum Action {
	/// No further action required
	None,
	/// Seller Send a message to the counterparty
	SellerSendOfferMessage(Message),
	/// Buyer send accpet offer back to Sender
	BuyerSendAcceptOfferMessage(Message),

	/// Wait for a message from the counterparty
	SellerWaitingForOfferMessage,
	/// Buyer send to seller Init redeem message
	BuyerSendInitRedeemMessage(Message),
	/// Seller waiting for Init Redeem messgae
	SellerWaitingForInitRedeemMessage,
	/// Seller sending InitRedeemMessage
	SellerSendRedeemMessage(Message),
	/// Buyer waiting for Redeem Message
	BuyerWaitingForRedeemMessage,
	/// Waiting for the backup is done by user
	WaitingForTradeBackup,
	/// Seller Publishing an MWC lock transaction to the network
	SellerPublishMwcLockTx,
	/// Seller Publishing BTC redeem transaction to the network
	SellerPublishTxSecondaryRedeem {
		/// Type of secondary currency (BTC)
		currency: Currency,
		/// Redeem Address
		address: String,
	},
	/// Seller transferring redeemed Ethereum-family funds from the shared
	/// internal account to the private destination recorded by this swap.
	SellerTransferSecondary {
		/// Ethereum-family currency being transferred.
		currency: Currency,
		/// Owner-selected destination address.
		address: String,
		/// Amount in the currency's canonical integer units.
		amount: u64,
	},
	/// Seller waiting for the recorded private-wallet redirect transaction to
	/// receive a successful receipt.
	SellerWaitForSecondaryTransferConfirmations {
		/// Ethereum-family currency being transferred.
		currency: Currency,
		/// Owner-selected destination address.
		address: String,
	},
	/// Deposit secondary currency
	DepositSecondary {
		/// Type of currency (BTC)
		currency: Currency,
		/// Amount
		amount: u64,
		/// Address to deposit. Here is vector because some coins might have legacy and new addresses that mean the same
		address: Vec<String>,
	},
	/// Deposit secondary currency
	BuyerDepositToContractAccount,
	/// Wait for sufficient confirmations. Lock transaction on MWC network
	WaitForMwcConfirmations {
		/// What exactly are we waiting for.
		name: String,
		/// Required number of confirmations
		required: u64,
		/// Actual number of confirmations
		actual: u64,
	},
	/// Wait for sufficient confirmations on the secondary currency
	WaitForSecondaryConfirmations {
		/// What exactly are we waiting for.
		name: String,
		/// Expected amount to be posted
		expected_to_be_posted: u64,
		/// Type of currency (BTC)
		currency: Currency,
		/// Address to deposit. Array because for BCH locking, we might have legacy and BCH addresses
		address: Vec<String>,
		/// Required number of confirmations
		required: u64,
		/// Actual number of confirmations
		actual: u64,
	},
	/// Wait for sufficient confirmations. Lock transaction on MWC network
	WaitForLockConfirmations {
		/// Required number of confirmations
		mwc_required: u64,
		/// Actual number of confirmations
		mwc_actual: u64,
		/// Type of secondary currency (BTC)
		currency: Currency,
		/// Address to deposit. Array because for BCH locking, it might have legacy and BCH addresses
		address: Vec<String>,
		/// Expected amount to be posted
		sec_expected_to_be_posted: u64,
		/// Required number of confirmations for secondary
		sec_required: u64,
		/// Actual number of confirmations for secondary. None if secondary not posted
		sec_actual: Option<u64>,
	},
	/// Wait for the MWC redeem tx to be mined
	SellerWaitForBuyerRedeemPublish {
		/// Current mwc tip height
		mwc_tip: u64,
		/// Locking height
		lock_height: u64,
	},
	/// Wait for the MWC redeem tx to be mined
	WaitForMwcRefundUnlock {
		/// Current mwc tip height
		mwc_tip: u64,
		/// Locking height
		lock_height: u64,
	},

	/// Buyer publishing MWC redeem transaction and reveal the secret.
	BuyerPublishMwcRedeemTx,

	/// Seller Publishing MWC Refund Tx to the network
	SellerPublishMwcRefundTx,

	/// Buyer publishing refund transaction
	BuyerPublishSecondaryRefundTx {
		/// Type of currency (BTC)
		currency: Currency,
		/// Address for refund
		address: String,
	},
	/// Waiting for btc refund to pass through
	WaitingForBtcRefund {
		/// Type of currency (BTC)
		currency: Currency,
		/// Address for refund
		address: String,
		/// Required time (tiemstamp)
		required: u64,
		/// Current (tiemstamp)
		current: u64,
	},
}

impl Action {
	/// Return if this Action is None
	pub fn is_none(&self) -> bool {
		match &self {
			Action::None => true,
			_ => false,
		}
	}

	/// Return true if this action require execution (swap --process) from the user.
	pub fn can_execute(&self) -> bool {
		match &self {
			Action::SellerSendOfferMessage(_)
			| Action::BuyerSendAcceptOfferMessage(_)
			| Action::BuyerDepositToContractAccount
			| Action::BuyerSendInitRedeemMessage(_)
			| Action::SellerSendRedeemMessage(_)
			| Action::SellerPublishMwcLockTx
			| Action::SellerPublishTxSecondaryRedeem {
				currency: _,
				address: _,
			}
			| Action::SellerTransferSecondary { .. }
			| Action::BuyerPublishMwcRedeemTx
			| Action::SellerPublishMwcRefundTx
			| Action::BuyerPublishSecondaryRefundTx {
				currency: _,
				address: _,
			} => true,
			_ => false,
		}
	}

	/// Convert action to a name string
	pub fn get_id_str(&self) -> String {
		let res = match &self {
			Action::None => "None",
			Action::SellerSendOfferMessage(_) => "SellerSendOfferMessage",
			Action::BuyerSendAcceptOfferMessage(_) => "BuyerSendAcceptOfferMessage",
			Action::SellerWaitingForOfferMessage => "SellerWaitForOfferMessage",
			Action::BuyerSendInitRedeemMessage(_) => "BuyerSendInitRedeemMessage",
			Action::SellerWaitingForInitRedeemMessage => "SellerWaitingForInitRedeemMessage",
			Action::SellerSendRedeemMessage(_) => "SellerSendRedeemMessage",
			Action::BuyerWaitingForRedeemMessage => "BuyerWaitingForRedeemMessage",
			Action::WaitingForTradeBackup => "WaitingForTradeBackup",
			Action::SellerPublishMwcLockTx => "SellerPublishMwcLockTx",
			Action::SellerPublishTxSecondaryRedeem {
				currency: _,
				address: _,
			} => "SellerPublishTxSecondaryRedeem",
			Action::SellerTransferSecondary { .. } => "SellerTransferSecondary",
			Action::SellerWaitForSecondaryTransferConfirmations { .. } => {
				"SellerWaitForSecondaryTransferConfirmations"
			}
			Action::DepositSecondary {
				currency: _,
				amount: _,
				address: _,
			} => "DepositSecondary",
			Action::BuyerDepositToContractAccount => "BuyerDepositToContractAccount",
			Action::WaitForMwcConfirmations {
				name: _,
				required: _,
				actual: _,
			} => "WaitForMwcConfirmations",
			Action::WaitForSecondaryConfirmations {
				name: _,
				expected_to_be_posted: _,
				currency: _,
				address: _,
				required: _,
				actual: _,
			} => "WaitForSecondaryConfirmations",
			Action::WaitForLockConfirmations {
				mwc_required: _,
				mwc_actual: _,
				currency: _,
				address: _,
				sec_expected_to_be_posted: _,
				sec_required: _,
				sec_actual: _,
			} => "WaitForLockConfirmations",
			Action::SellerWaitForBuyerRedeemPublish {
				mwc_tip: _,
				lock_height: _,
			} => "SellerWaitForBuyerRedeemPublish",
			Action::WaitForMwcRefundUnlock {
				mwc_tip: _,
				lock_height: _,
			} => "WaitForMwcRefundUnlock",
			Action::BuyerPublishMwcRedeemTx => "BuyerPublishMwcRedeemTx",
			Action::SellerPublishMwcRefundTx => "SellerPublishMwcRefundTx",
			Action::BuyerPublishSecondaryRefundTx {
				currency: _,
				address: _,
			} => "BuyerPublishSecondaryRefundTx",
			Action::WaitingForBtcRefund {
				currency: _,
				address: _,
				required: _,
				current: _,
			} => "WaitingForBtcRefund",
		};
		res.to_string()
	}
}

impl fmt::Display for Action {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let disp = match &self {
			Action::None => "None".to_string(),
			Action::SellerSendOfferMessage(_) => "Sending Offer message".to_string(),
			Action::BuyerSendAcceptOfferMessage(_) => "Sending Accept Offer message".to_string(),
			Action::SellerWaitingForOfferMessage => "Waiting for Accept Offer message, please make sure that your listener is running".to_string(),
			Action::BuyerSendInitRedeemMessage(_) => "Sending Init Redeem Message".to_string(),
			Action::SellerWaitingForInitRedeemMessage => {
				"Waiting for Init Redeem Message, please make sure that your listener is running".to_string()
			}
			Action::SellerSendRedeemMessage(_) => "Sending Finalize Redeem Message".to_string(),
			Action::BuyerWaitingForRedeemMessage => {
				"Waiting for Redeem response message from Seller".to_string()
			}
			Action::WaitingForTradeBackup => "Backup trade data".to_string(),
			Action::SellerPublishMwcLockTx => "Posting MWC lock transaction".to_string(),
			Action::SellerPublishTxSecondaryRedeem { currency, address } => {
				if !currency.is_btc_family()
					&& address.as_str() == "0x0000000000000000000000000000000000000000"
				{
					let address = &"Internal Ethereum Wallet Address!".to_string();
					format!("Posting {} redeem transaction to {}", currency, address)
				} else {
					format!("Posting {} redeem transaction to {}", currency, address)
				}
			}
			Action::DepositSecondary {
				currency,
				amount,
				address,
			} => {
				debug_assert!(address.len()>0);
				debug_assert!(address.len()<=2);
				format!(
					"Please deposit exactly {} {} to {}",
					currency.amount_to_hr_string(*amount, true),
					currency,
					address.join(" or ")
				)
			},
			Action::SellerTransferSecondary {
				currency,
				address,
				amount,
			} => format!(
				"Transferring {} {} from the internal Ethereum wallet to {}",
				currency.amount_to_hr_string(*amount, true),
				currency,
				address
			),
			Action::SellerWaitForSecondaryTransferConfirmations { currency, address } => {
				format!(
					"Waiting for the {} transfer from the internal Ethereum wallet to {} to confirm",
					currency, address
				)
			}
			Action::BuyerDepositToContractAccount => "Buyer Depositing Secondary Currency to Contract Account".to_string(),
			Action::WaitForMwcConfirmations {
				name,
				required,
				actual,
			} => format!(
				"{}, waiting for confirmations. MWC {}/{}",
				name, actual, required
			),
			Action::WaitForSecondaryConfirmations {
				name,
				expected_to_be_posted,
				currency,
				address,
				required,
				actual,
			} => {
				debug_assert!(address.len()>0);
				debug_assert!(address.len()<=2);
				if *expected_to_be_posted == 0 {
                    if !currency.is_btc_family() {
                        if *actual >= 1 {
                            format!("{}, waiting for confirmations for {} address {} locked", name, currency, address.join(","))
                        } else {
                            format!("{}, waiting for confirmations for {} address {} locking", name, currency, address.join(","))
                        }
                    } else {
                        format!("{}, waiting for confirmations for {} address {} {}/{}", name, currency, address.join(","), actual, required)
                    }
                }
				else {
					let posted_str = currency.amount_to_hr_string(*expected_to_be_posted, true);
					format!("{}, waiting for {} {} to be sent to {}", name, posted_str, currency, address.join(" or "))
				}
			}
			Action::WaitForLockConfirmations {
				mwc_required,
				mwc_actual,
				currency,
				address,
				sec_expected_to_be_posted,
				sec_required,
				sec_actual,
			} => {
				let mwc_str = if mwc_actual >= mwc_required {
					"MWC are locked".to_string()
				}
				else {
					format!("MWC {}/{}", mwc_actual, mwc_required)
				};

				let sec_str = if *sec_expected_to_be_posted==0 {
					if let Some(sec_actual) = sec_actual {
						if currency.is_btc_family() {
							if *sec_actual == 0 {
								format!("{} {} are in memory pool", currency, address.join(","))
							} else if *sec_actual >= *sec_required {
								format!("{} {}, are locked", currency, address.join(","))
							} else {
								format!("{} {}, {}/{}", currency, address.join(","), sec_actual, sec_required)
							}
						} else {
							if *sec_actual == 0 {
								format!("{} {}, waiting for Ethereum finality", currency, address.join(","))
							} else {
								format!("{} {}, are locked", currency, address.join(","))
							}
						}
					} else {
						format!("{} {}, hasn't been posted", currency, address.join(","))
					}
				} else {
					let sec_posted_str = currency.amount_to_hr_string(*sec_expected_to_be_posted, true);
					debug_assert!(address.len()>0);
					debug_assert!(address.len()<=2);
					format!("Waiting for {} {} to be sent to {}", sec_posted_str, currency, address.join(" or "))
				};

				format!("Locking, waiting for confirmations. {}; {}", mwc_str, sec_str)
			}
			Action::SellerWaitForBuyerRedeemPublish {
				mwc_tip,
				lock_height,
			} => format!(
				"Waiting for Buyer to redeem MWC. If we do not receive a response, a refund will be posted in {} minutes",
				// This is a display-only countdown; a tip beyond the lock height means zero remains.
				(lock_height.saturating_sub(*mwc_tip))
			),
			Action::WaitForMwcRefundUnlock {
				mwc_tip,
				lock_height,
			} => {
				// This is a display-only countdown; a tip beyond the lock height means zero remains.
				let blocks_left = lock_height.saturating_sub(*mwc_tip);
				let hours = blocks_left / 60;
				let minutes = blocks_left % 60;
				format!(
					"Waiting for locked MWC to be refunded ({} hour{} and {} minute{} remaining)",
					hours,
					if hours == 1 { "" } else { "s" },
					minutes,
					if minutes == 1 { "" } else { "s" }
				)
			}
			Action::BuyerPublishMwcRedeemTx => "Posting MWC redeem transaction".to_string(),
			Action::SellerPublishMwcRefundTx => "Posting MWC refund transaction".to_string(),
			Action::BuyerPublishSecondaryRefundTx { currency, address } => {
				format!("Sending {} refund to {}", currency, address)
			}
			Action::WaitingForBtcRefund {
				currency,
				address,
				required,
				current,
			} => {
				// This is display-only: expired deadlines clamp to zero and the rounding
				// allowance clamps at u64::MAX instead of affecting workflow decisions.
				let time_left_sec = required.saturating_sub(*current).saturating_add(30); // 30 seconds for rounding
				let hours = time_left_sec / 3600;
				let minutes = (time_left_sec % 3600) / 60;
				format!(
					"Waiting for locked {} to be refunded to {}. ({} hour{} and {} minute{} remaining)",
					currency,
					address,
					hours,
					if hours == 1 { "" } else { "s" },
					minutes,
					if minutes == 1 { "" } else { "s" }
				)
			}
		};
		write!(f, "{}", disp)
	}
}

/// Status of the transactions that can be published.
///  None for confirmations - Unable to verify, probably Transaction data is not here.
pub struct SwapTransactionsConfirmations {
	/// False when MWC is unavailable during independent secondary recovery.
	/// MWC fields then carry no observations.
	pub mwc_observed: bool,
	/// False when only MWC was queried for seller refund recovery. Secondary
	/// fields then carry no observations and must not drive state transitions.
	pub secondary_observed: bool,
	/// MWC node tip
	pub mwc_tip: u64,
	/// Number of confirmations for the lock transaction
	pub mwc_lock_conf: Option<u64>,
	/// Number of confirmations for MWC redeem transaction
	pub mwc_redeem_conf: Option<u64>,
	/// Number of confirmations for refund transaction
	pub mwc_refund_conf: Option<u64>,
	/// BTC/ETH node tip
	pub secondary_tip: u64,
	/// For ETH locks: 1 means valid and finalized; 0 means not yet accepted.
	/// BTC/ETH lock (multisug account) number of confirmations
	pub secondary_lock_conf: Option<u64>,
	/// How much is locked. This process is manual, so Buyer might make a mistake
	pub secondary_lock_amount: u64,
	/// BTC/ETH redeem number of confirmations
	pub secondary_redeem_conf: Option<u64>,
	/// BTC/ETH  refund transaciton number of confirmations
	pub secondary_refund_conf: Option<u64>,
	/// BTC refund-plan progress; account-based currencies use the single counter.
	pub secondary_refund_progress: Option<crate::swap::bitcoin::BtcRefundProgress>,
}

impl SwapTransactionsConfirmations {
	/// A verified MWC snapshot with explicitly unobserved secondary-chain data.
	pub(crate) fn mwc_only(
		mwc_tip: u64,
		mwc_lock_conf: Option<u64>,
		mwc_redeem_conf: Option<u64>,
		mwc_refund_conf: Option<u64>,
	) -> Self {
		Self {
			mwc_observed: true,
			secondary_observed: false,
			mwc_tip,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
			secondary_tip: 0,
			secondary_lock_conf: None,
			secondary_lock_amount: 0,
			secondary_redeem_conf: None,
			secondary_refund_conf: None,
			secondary_refund_progress: None,
		}
	}

	/// Add the verified MWC observations to a secondary snapshot.
	pub(crate) fn with_mwc(mut self, mwc: Self) -> Self {
		self.mwc_observed = mwc.mwc_observed;
		self.mwc_tip = mwc.mwc_tip;
		self.mwc_lock_conf = mwc.mwc_lock_conf;
		self.mwc_redeem_conf = mwc.mwc_redeem_conf;
		self.mwc_refund_conf = mwc.mwc_refund_conf;
		self
	}

	/// Check that the current state has the chain observations it needs.
	///
	/// Recovery can use one chain, but the FSM may advance through several
	/// states with the same snapshot. For example, an MWC refund check can
	/// discover a buyer redemption and switch toward secondary redemption.
	/// Checking at entry and after each transition stops processing until the
	/// required observations are available, so unobserved `None`/`0` fields
	/// cannot be mistaken for absent transactions or an empty balance.
	pub(crate) fn supports_state(&self, swap: &super::Swap) -> bool {
		(self.mwc_observed || swap.can_use_secondary_confirmations())
			&& (self.secondary_observed || (swap.is_seller() && swap.state.is_seller_refund()))
			&& (self.mwc_observed || self.secondary_observed)
	}
}

/// Reconciliation status for the seller's Ethereum private-wallet redirect.
/// The transaction hash itself is stored in [`crate::swap::ethereum::EthData`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryTransferStatus {
	/// No redirect transaction hash has been recorded yet.
	NotPosted,
	/// A hash is recorded, but no mined receipt is available yet.
	Pending,
	/// The recorded transaction has a successful mined receipt.
	Confirmed,
	/// The recorded transaction was mined with a failed receipt.
	Failed,
}

/// Validate the chain confirmation requirements carried by a swap offer.
///
/// Zero is not a meaningful security threshold: it would let an absent
/// transaction satisfy `actual >= required` checks.
pub fn validate_confirmation_requirements(
	mwc_confirmations: u64,
	secondary_confirmations: u64,
) -> Result<(), Error> {
	if mwc_confirmations < 30 {
		return Err(Error::InvalidMessageData(
			"Required at least 30 confirmations for MWC".to_string(),
		));
	}
	if secondary_confirmations < 3 {
		return Err(Error::InvalidMessageData(
			"Required at least 3 confirmations for secondary currency".to_string(),
		));
	}
	Ok(())
}

/// Return whether an observed secondary transaction is confirmed.
///
/// BTC-family swaps honor the negotiated confirmation count. Account-based
/// chains use an acceptance marker: a lock marker is set only after finality.
/// A positive negotiated threshold and an observed transaction are still required.
pub fn check_txs_confirmed(
	currency: Currency,
	actual: Option<u64>,
	required: u64,
) -> bool {
	if required == 0 {
		return false;
	}
	let Some(actual) = actual else {
		return false;
	};

	match currency {
		Currency::Btc
		| Currency::Bch
		| Currency::Ltc
		| Currency::Dash
		| Currency::ZCash
		| Currency::Doge => actual >= required,
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
		| Currency::Tst => actual >= 1,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn context_write_preserves_encoding_and_propagates_short_writes() {
		for fixture in [
			include_str!("../../swap_test/context_buy.json"),
			include_str!("../../swap_test/context_sell.json"),
		] {
			let context: Context = serde_json::from_str(fixture).unwrap();
			let json = serde_json::to_vec(&context).unwrap();
			let mut encoded = Vec::new();
			ser::serialize_default(0, &mut encoded, &context, true).unwrap();
			assert_eq!(&encoded[..8], &(json.len() as u64).to_be_bytes());
			assert_eq!(&encoded[8..], &json);

			let decoded: Context = ser::deserialize_default(0, &mut &encoded[..], true).unwrap();
			assert_eq!(serde_json::to_vec(&decoded).unwrap(), json);

			// Fail while writing either the length prefix or the JSON body.
			for length in [0, 7, 8, 64] {
				let mut short = vec![0u8; length];
				let error =
					ser::serialize_default(0, &mut short.as_mut_slice(), &context, true).unwrap_err();
				assert!(
					matches!(error, ser::Error::IOErr(e) if e.kind() == std::io::ErrorKind::WriteZero)
				);
			}
		}
	}

	#[test]
	fn seller_input_preserves_features_and_reads_legacy_contexts() {
		let key_id = Identifier::from_hex("0200000000000000010000000000000000").unwrap();
		let legacy = serde_json::to_value((key_id.clone(), None::<u64>, 42u64)).unwrap();
		let legacy: SellerInput = serde_json::from_value(legacy).unwrap();
		assert_eq!(legacy.key_id, key_id);
		assert_eq!(legacy.amount, 42);
		assert_eq!(legacy.features, OutputFeatures::Plain);

		let coinbase = SellerInput::new(key_id, Some(7), 43, true);
		let encoded = serde_json::to_value(&coinbase).unwrap();
		assert_eq!(encoded.as_array().unwrap().len(), 4);
		let decoded: SellerInput = serde_json::from_value(encoded).unwrap();
		assert_eq!(decoded, coinbase);
		assert_eq!(decoded.features, OutputFeatures::Coinbase);
	}

	#[test]
	fn confirmation_checks_reject_zero_requirements_and_missing_transactions() {
		assert!(validate_confirmation_requirements(30, 3).is_ok());
		assert!(validate_confirmation_requirements(0, 3).is_err());
		assert!(validate_confirmation_requirements(30, 0).is_err());

		assert!(!check_txs_confirmed(Currency::Btc, None, 1));
		assert!(!check_txs_confirmed(Currency::Btc, Some(0), 0));
		assert!(!check_txs_confirmed(Currency::Btc, Some(1), 2));
		assert!(check_txs_confirmed(Currency::Btc, Some(2), 2));
		assert!(!check_txs_confirmed(Currency::Ether, None, 1));
		assert!(check_txs_confirmed(Currency::Ether, Some(1), 1));
	}

	#[test]
	fn test_amounts_to_hr() {
		let c = Currency::Btc;
		assert_eq!(&c.amount_to_hr_string(1, false), "0.00000001");
		assert_eq!(&c.amount_to_hr_string(100, false), "0.00000100");
		assert_eq!(&c.amount_to_hr_string(713, false), "0.00000713");
		assert_eq!(&c.amount_to_hr_string(100_000, false), "0.00100000");
		assert_eq!(&c.amount_to_hr_string(10_000_000, false), "0.10000000");
		assert_eq!(&c.amount_to_hr_string(12_345_678, false), "0.12345678");
		assert_eq!(&c.amount_to_hr_string(100_000_000, false), "1.00000000");
		assert_eq!(&c.amount_to_hr_string(100_200_300, false), "1.00200300");
		assert_eq!(&c.amount_to_hr_string(102_030_405, false), "1.02030405");
		assert_eq!(&c.amount_to_hr_string(110_000_000, false), "1.10000000");
		assert_eq!(&c.amount_to_hr_string(123_456_789, false), "1.23456789");
		assert_eq!(&c.amount_to_hr_string(1_000_000_000, false), "10.00000000");
		assert_eq!(&c.amount_to_hr_string(1_020_304_050, false), "10.20304050");
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_000, false),
			"100.00000000"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_001, false),
			"100.00000001"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_010, false),
			"100.00000010"
		);
		assert_eq!(
			&c.amount_to_hr_string(10_000_000_100, false),
			"100.00000100"
		);

		assert_eq!(&c.amount_to_hr_string(1, true), "0.00000001");
		assert_eq!(&c.amount_to_hr_string(100, true), "0.000001");
		assert_eq!(&c.amount_to_hr_string(713, true), "0.00000713");
		assert_eq!(&c.amount_to_hr_string(100_000, true), "0.001");
		assert_eq!(&c.amount_to_hr_string(10_000_000, true), "0.1");
		assert_eq!(&c.amount_to_hr_string(12_345_678, true), "0.12345678");
		assert_eq!(&c.amount_to_hr_string(100_000_000, true), "1.0");
		assert_eq!(&c.amount_to_hr_string(100_200_300, true), "1.002003");
		assert_eq!(&c.amount_to_hr_string(102_030_405, true), "1.02030405");
		assert_eq!(&c.amount_to_hr_string(110_000_000, true), "1.1");
		assert_eq!(&c.amount_to_hr_string(123_456_789, true), "1.23456789");
		assert_eq!(&c.amount_to_hr_string(1_000_000_000, true), "10.0");
		assert_eq!(&c.amount_to_hr_string(1_020_304_050, true), "10.2030405");
		assert_eq!(&c.amount_to_hr_string(10_000_000_000, true), "100.0");
		assert_eq!(&c.amount_to_hr_string(10_000_000_001, true), "100.00000001");
		assert_eq!(&c.amount_to_hr_string(10_000_000_010, true), "100.0000001");
		assert_eq!(&c.amount_to_hr_string(10_000_000_100, true), "100.000001");
	}

	#[test]
	fn ethereum_family_is_an_explicit_allowlist() {
		for currency in [
			Currency::Ether,
			Currency::Busd,
			Currency::Bnb,
			Currency::Link,
			Currency::Dai,
			Currency::Tusd,
			Currency::Usdp,
			Currency::Wbtc,
			Currency::Usdt,
			Currency::Usdc,
			Currency::Trx,
			Currency::Tst,
		] {
			assert!(currency.is_ethereum_family(), "{}", currency);
		}

		for currency in [
			Currency::Btc,
			Currency::Bch,
			Currency::Ltc,
			Currency::Dash,
			Currency::ZCash,
			Currency::Doge,
		] {
			assert!(!currency.is_ethereum_family(), "{}", currency);
		}
	}

	#[test]
	fn test_amounts_from_hr() {
		let c = Currency::Btc;
		assert!(c.amount_from_hr_string("").is_err());
		assert!(c.amount_from_hr_string(".").is_err());
		assert!(c.amount_from_hr_string("0").is_err());
		assert!(c.amount_from_hr_string("0.").is_err());
		assert!(c.amount_from_hr_string("0.0").is_err());
		assert!(c.amount_from_hr_string("0.000000001").is_err());
		assert_eq!(c.amount_from_hr_string("0.00000001").unwrap(), 1);
		assert_eq!(c.amount_from_hr_string(".00000001").unwrap(), 1);
		assert_eq!(c.amount_from_hr_string("0.00000713").unwrap(), 713);
		assert_eq!(c.amount_from_hr_string(".00000713").unwrap(), 713);
		assert_eq!(c.amount_from_hr_string("0.0001").unwrap(), 10_000);
		assert_eq!(c.amount_from_hr_string("0.1").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string("0.10").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string(".1").unwrap(), 10_000_000);
		assert_eq!(c.amount_from_hr_string(".10").unwrap(), 10_000_000);
		// Excess precision is rejected, not silently truncated
		assert!(c.amount_from_hr_string("0.123456789").is_err());
		// Trailing junk past the exponent is rejected, not truncated away
		assert!(c.amount_from_hr_string("0.12345678junk").is_err());
		// Multibyte characters are rejected (previously panicked in String::truncate)
		assert!(c.amount_from_hr_string("0.0000000\u{1F4A3}").is_err());
		assert_eq!(c.amount_from_hr_string("1").unwrap(), 100_000_000);
		assert_eq!(c.amount_from_hr_string("1.").unwrap(), 100_000_000);
		assert_eq!(c.amount_from_hr_string("1.0").unwrap(), 100_000_000);
		assert_eq!(
			c.amount_from_hr_string("123456.789").unwrap(),
			12_345_678_900_000
		);
	}

	#[test]
	fn amount_from_hr_rejects_overflow_with_operands() {
		let amount = "184467440737.09551616";
		match Currency::Btc.amount_from_hr_string(amount) {
			Err(Error::DataOverflow(message)) => {
				assert!(message.contains("Currency::amount_from_hr_string"));
				assert!(message.contains("scaled_characteristic=18446744073700000000"));
				assert!(message.contains("mantissa=9551616"));
			}
			other => panic!("expected operand-rich DataOverflow error, got {:?}", other),
		}
	}

	#[test]
	fn ethereum_fees_are_integer_gwei() {
		assert_eq!(
			Currency::Ether
				.normalize_secondary_fee("5500000")
				.unwrap(),
			SecondaryFeeUnits::EthereumGwei(5_500_000)
		);
		assert!(Currency::Ether
			.normalize_secondary_fee("5500000.5")
			.is_err());
		assert_eq!(
			Currency::Ether.get_default_fee(&Network::Mainnet),
			SecondaryFeeUnits::EthereumGwei(5_500_000)
		);
		assert!(Currency::Ether
			.secondary_fee_gwei(SecondaryFeeUnits::EthereumGwei(0))
			.is_err());
	}

	#[test]
	fn btc_family_fees_use_checked_fixed_point_units() {
		let fee = Currency::Btc
			.normalize_secondary_fee("1.400")
			.unwrap();
		assert_eq!(fee, SecondaryFeeUnits::RatePerKvb(1_400));
		// 1.4 atomic units/vB * 300 vB is exactly 420 atomic units.
		assert_eq!(Currency::Btc.secondary_fee_amount(fee, 300).unwrap(), 420);
		// 1.4 atomic units/vB * 301 vB is 421.4, so pay 422 rather than
		// falling below the requested rate.
		assert_eq!(Currency::Btc.secondary_fee_amount(fee, 301).unwrap(), 422);
		// Even a fractional result below one half rounds upward because a fee
		// rate is a lower bound, not a nearest-value measurement.
		assert_eq!(Currency::Btc.secondary_fee_amount(fee, 1).unwrap(), 2);
		assert!(Currency::Btc
			.normalize_secondary_fee("1.4001")
			.is_err());
		assert_eq!(
			Currency::ZCash
				.normalize_secondary_fee("0.0001")
				.unwrap(),
			SecondaryFeeUnits::FlatAtomic(10_000)
		);
	}

	#[test]
	fn secondary_fee_strings_reject_invalid_syntax() {
		for invalid in ["", ".", "+1", "-1", "1e3", "1.2.3", " 1.4", "1 gwei"] {
			assert!(
				Currency::Btc.normalize_secondary_fee(invalid).is_err(),
				"fee input unexpectedly accepted: {:?}",
				invalid
			);
		}
	}

	#[test]
	fn secondary_fee_bump_uses_a_rounded_up_rational() {
		assert_eq!(
			Currency::Btc
				.bump_secondary_fee(SecondaryFeeUnits::RatePerKvb(1_401), 6, 5)
				.unwrap(),
			SecondaryFeeUnits::RatePerKvb(1_682)
		);
	}

	#[test]
	fn test_bch_address_parsers() {
		global::set_local_chain_type(ChainTypes::Floonet);

		let bch_q_address = "bchtest:qr972p5km7a9rdwtsnuqjfnm8epm48mhkgcgt6dprl".to_string();
		let bch_legacy = "mz73pyxw6hpnyb8HHnPrTe5DikC2xYrfPX".to_string();

		let btc_script = Currency::Btc
			.address_2_script_pubkey(0, &bch_legacy)
			.unwrap();
		let bch_legacy_script = Currency::Bch
			.address_2_script_pubkey(0, &bch_legacy)
			.unwrap();
		let bch_q_script = Currency::Bch
			.address_2_script_pubkey(0, &bch_q_address)
			.unwrap();

		let script_sz = btc_script.len();

		assert_eq!(script_sz, bch_legacy_script.len());
		assert_eq!(script_sz, bch_q_script.len());

		for i in 0..script_sz {
			assert_eq!(btc_script.as_bytes()[i], bch_legacy_script.as_bytes()[i]);
			assert_eq!(btc_script.as_bytes()[i], bch_q_script.as_bytes()[i]);
		}
	}
}
