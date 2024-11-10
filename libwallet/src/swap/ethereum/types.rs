// Copyright 2021 The MWC Developers
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

use crate::mwc_util::to_hex;
use crate::swap::message::SecondaryUpdate;
use crate::swap::ser::*;
use crate::swap::types::SecondaryData;
use crate::swap::Error;
use regex::Regex;
use mwc_web3::types::{Address, H256};

/// ETH transaction ready to post (any type). Here it is a redeem tx
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthTransaction {
	pub txid: H256, // keep it is a hash for data compatibility.
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}

/// ETH operations context
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthData {
	/// Redeem Address owned by mwc seller
	pub redeem_address: Option<Address>,
	/// Address for swap offer index in swap contract address
	pub address_from_secret: Option<Address>,
	/// ERC20 Approve transaction hash
	pub erc20_approve_tx: Option<H256>,
	/// Lock transaction Hash
	pub lock_tx: Option<H256>,
	/// Refund transaction Hash
	pub refund_tx: Option<H256>, // keep it as a hash for data compatibility.
	/// ETH redeem transaction hash, needed for checking if it is posted
	pub redeem_tx: Option<H256>, // keep it as a hash for data compatibility.
	/// Last transaction fee that was used for ETH. Needed to detect the fact that it is changed.
	pub tx_fee: Option<f32>,
}

impl EthData {
	/// Create seller ETH data (party that receive ETH).
	pub(crate) fn new(context: &EthSellerContext, // Derivarive index
	) -> Result<Self, Error> {
		Ok(Self {
			redeem_address: context.redeem_address,
			address_from_secret: None,
			erc20_approve_tx: None,
			lock_tx: None,
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		})
	}

	/// Create buyer ETH data (party that sell ETH)
	pub(crate) fn from_offer(
		offer: EthOfferUpdate,
		context: &EthBuyerContext,
	) -> Result<Self, Error> {
		Ok(Self {
			redeem_address: offer.redeem_address,
			address_from_secret: context.address_from_secret,
			erc20_approve_tx: None,
			lock_tx: None,
			refund_tx: None,
			redeem_tx: None,
			tx_fee: None,
		})
	}

	/// Seller applies accepted offer message from the buyer
	pub(crate) fn accepted_offer(
		&mut self,
		accepted_offer: EthAcceptOfferUpdate,
	) -> Result<(), Error> {
		self.lock_tx = accepted_offer.lock_tx;
		self.address_from_secret = accepted_offer.address_from_secret;
		Ok(())
	}
	/// Return ETH related data
	pub(crate) fn wrap(self) -> SecondaryData {
		SecondaryData::Eth(self)
	}

	/// Seller init ETH offer for buyer
	pub(crate) fn offer_update(&self) -> EthUpdate {
		EthUpdate::Offer(EthOfferUpdate {
			redeem_address: self.redeem_address.clone(), // Buyer redeem eth address
		})
	}

	/// Seller apply respond for the Buyer.
	pub(crate) fn accept_offer_update(&self) -> EthUpdate {
		EthUpdate::AcceptOffer(EthAcceptOfferUpdate {
			lock_tx: self.lock_tx.clone(),
			address_from_secret: self.address_from_secret.clone(),
		})
	}
}

/// Context for the Seller (party that receive ETH)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthSellerContext {
	/// Seller, redeem addres.
	pub redeem_address: Option<Address>,
}

/// Context for the Buyer (party that sell ETH)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthBuyerContext {
	/// Buyer swap offer index in swap contract account
	pub address_from_secret: Option<Address>,
}

/// Messages regarding ETH part of the deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum EthUpdate {
	/// Seller send offer to Buyer. Here is details about ETH deal
	Offer(EthOfferUpdate),
	/// Buyer message back to Seller. Offer is accepted
	AcceptOffer(EthAcceptOfferUpdate),
}

impl EthUpdate {
	/// Unwrap EthOfferUpdate  with data type verification
	pub fn unwrap_offer(self) -> Result<EthOfferUpdate, Error> {
		match self {
			EthUpdate::Offer(u) => Ok(u),
			_ => Err(Error::UnexpectedMessageType(
				"Fn unwrap_offer() expecting EthUpdate::Offer".to_string(),
			)),
		}
	}

	/// Unwrap EthAcceptOfferUpdate  with data type verification
	pub fn unwrap_accept_offer(self) -> Result<EthAcceptOfferUpdate, Error> {
		match self {
			EthUpdate::AcceptOffer(u) => Ok(u),
			_ => Err(Error::UnexpectedMessageType(
				"Fn unwrap_accept_offer() expecting BtcUpdate::AcceptOffer".to_string(),
			)),
		}
	}

	/// Wrap thos ETH object into SecondaryUpdate message.
	pub fn wrap(self) -> SecondaryUpdate {
		SecondaryUpdate::ETH(self)
	}
}

/// Seller send offer to Buyer. Here is details about ETH deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EthOfferUpdate {
	/// Address to redeem eth.
	pub redeem_address: Option<Address>,
}

/// Buyer message back to Seller. Offer is accepted
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EthAcceptOfferUpdate {
	/// Eth Lock Transaction Id
	pub lock_tx: Option<H256>,
	/// Buyer swap contract index
	pub address_from_secret: Option<Address>,
}

/// to web3 Address
pub fn to_eth_address(address: String) -> Result<Address, Error> {
	let regex = Regex::new(r"^0x").unwrap();
	let address = address.to_lowercase();
	let address = regex.replace_all(&address, "").to_string();

	if address.len() != 40 {
		return Err(Error::InvalidEthAddress);
	}
	let mut address_slice = [0u8; 20];
	address_slice.copy_from_slice(hex::decode(address).unwrap().as_slice());
	Ok(Address::from(address_slice))
}

/// Address to String
pub fn eth_address(address: Address) -> String {
	let addr_str = to_hex(address.as_bytes());
	let mut address_in_str = "0x".to_string();
	address_in_str.push_str(addr_str.as_str());

	address_in_str
}

/// to eth transaction hash
pub fn to_eth_tx_hash(tx_hash: String) -> Result<H256, Error> {
	let regex = Regex::new(r"^0x").unwrap();
	let hash = regex.replace_all(&tx_hash, "").to_string();

	if hash.len() != 64 {
		return Err(Error::InvalidTxHash);
	}
	let mut hash_slice = [0u8; 32];
	hash_slice.copy_from_slice(hex::decode(hash).unwrap().as_slice());

	Ok(H256::from(hash_slice))
}
