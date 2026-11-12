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

use crate::swap::Error;
use crate::swap::message::SecondaryUpdate;
use crate::swap::types::SecondaryData;
use mwc_wallet_util::mwc_crates::hex;
use mwc_wallet_util::mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_wallet_util::mwc_util::to_hex;
use mwc_wallet_util::mwc_wagyu_ethereum::EthereumAddress;
use mwc_wallet_util::mwc_web3;
use mwc_web3::types::{Address, Bytes, H256, U256};
use std::str::FromStr;

/// ETH transaction ready to post (any type). Here it is a redeem tx
/*#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthTransaction {
	pub txid: H256, // keep it is a hash for data compatibility.
	#[serde(serialize_with = "bytes_to_hex", deserialize_with = "bytes_from_hex")]
	pub tx: Vec<u8>,
}*/

/// Identity of an allowance shared by swaps using the same Ethereum account.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct Erc20AllowanceKey {
	/// Ethereum chain identifier.
	pub chain_id: u64,
	/// Account granting the allowance.
	pub owner: Address,
	/// ERC20 token contract.
	pub token: Address,
	/// Swap custody contract spending the allowance.
	pub spender: Address,
}

/// Persisted progress while one swap owns an ERC20 allowance.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum Erc20FundingPhase {
	/// No transaction is outstanding; inspect the current allowance.
	CheckAllowance,
	/// Waiting for an approval of zero.
	ResetPending(H256),
	/// Waiting for approval of the swap amount.
	ApprovalPending(H256),
	/// Waiting for the swap deposit to finish consuming its allowance.
	DepositPending(H256),
	/// The deposit succeeded when last checked; reconcile its receipt before reuse.
	Complete,
	/// The deposit nonce was consumed without funding when last checked. Recheck on recovery.
	DepositCancelled,
}

/// Explicit recovery never starts a new deposit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositRecoveryMode {
	/// Retry the recorded deposit of an active trade.
	RetryOriginal,
	/// Replace the deposit with a zero-value self-transfer at its original nonce.
	Cancel,
}

/// Original approval arguments, preserved independently of the funding phase.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(crate = "serde")]
pub enum Erc20ApprovalKind {
	/// Approval of zero.
	Reset,
	/// Approval amount in wallet units.
	Approve(u64),
}

/// A mined approval can disappear in a reorg until its block is finalized.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct Erc20ApprovalRecovery {
	/// The original operation and amount.
	pub kind: Erc20ApprovalKind,
	/// Signed candidates sharing the original nonce.
	pub transaction: EthTransactionRecovery,
}

/// The reservation is persisted with the encrypted swap record, including on
/// ambiguous submission errors. No mutex is held between processing calls.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct Erc20Funding {
	/// Shared allowance reserved by this swap.
	pub key: Erc20AllowanceKey,
	/// Outstanding operation, if any.
	pub phase: Erc20FundingPhase,
}

/// Signed transaction retained for rebroadcast and replacement at the same nonce.
/// Swaps persist it in encrypted trades; direct transfers retain it in memory.
/// Debug omits calldata and signed bytes. Every attempted hash remains eligible
/// for confirmation.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct EthTransactionRecovery {
	/// Network on which the transaction was signed.
	pub chain_id: u64,
	/// Account paying for the transaction.
	pub sender: Address,
	/// Account nonce reserved until a transaction at this nonce is mined.
	pub nonce: U256,
	/// Pinned destination: recipient, token, custody contract, or cancellation sender.
	pub to: Address,
	/// Native value attached to the call.
	pub value: U256,
	/// Original contract call and arguments.
	pub data: Bytes,
	/// Estimated execution gas, preserved by fee replacements.
	pub gas_limit: U256,
	/// Gas price of the latest signed attempt, in wei.
	pub gas_price: U256,
	/// Budget authorizing the latest signed attempt, in gwei.
	pub gas_budget_gwei: u64,
	/// Latest signed transaction, ready for exact rebroadcast.
	pub raw_transaction: Bytes,
	/// Original hash followed by hashes of signed replacements.
	pub attempted_hashes: Vec<H256>,
	/// Time of the last broadcast attempt, including failed submissions.
	pub last_attempt_at: i64,
	/// After an exact rebroadcast, the next timed retry raises the gas price.
	pub rebroadcasted: bool,
}

impl std::fmt::Debug for EthTransactionRecovery {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("EthTransactionRecovery")
			.field("chain_id", &self.chain_id)
			.field("sender", &self.sender)
			.field("nonce", &self.nonce)
			.field("attempted_hashes", &self.attempted_hashes)
			.finish_non_exhaustive()
	}
}

/// Compatibility name for the recovery record originally used only by redeems.
pub type EthRedeemRecovery = EthTransactionRecovery;

/// ETH operations context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct EthData {
	/// Redeem Address owned by mwc seller
	pub redeem_address: Option<Address>,
	/// Address for swap offer index in swap contract address
	pub address_from_secret: Option<Address>,
	/// ERC20 Approve transaction hash
	pub erc20_approve_tx: Option<H256>,
	/// ERC20 approval/reset/deposit progress and allowance reservation.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub erc20_funding: Option<Erc20Funding>,
	/// Recoverable reset or approval and all replacements sharing its nonce.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub erc20_approval_recovery: Option<EthTransactionRecovery>,
	/// Mined resets and approvals retained until canonical finality is verified.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub erc20_approval_history: Vec<Erc20ApprovalRecovery>,
	/// Lock transaction Hash
	pub lock_tx: Option<H256>,
	/// Recoverable deposit and all replacements sharing its nonce.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lock_recovery: Option<EthTransactionRecovery>,
	/// Cancellation candidates are separate: their success is not a successful deposit.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lock_cancel_recovery: Option<EthTransactionRecovery>,
	/// Refund transaction Hash
	pub refund_tx: Option<H256>, // keep it as a hash for data compatibility.
	/// Recoverable refund and all replacements sharing its nonce.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub refund_recovery: Option<EthTransactionRecovery>,
	/// ETH redeem transaction hash, needed for checking if it is posted
	pub redeem_tx: Option<H256>, // keep it as a hash for data compatibility.
	/// Recoverable redeem and all replacements sharing its nonce.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub redeem_recovery: Option<EthTransactionRecovery>,
	/// Seller's transfer from the shared internal account to the private
	/// destination after the contract redeem has confirmed.
	///
	/// This is a deliberately simplified reconciliation marker, not a durable
	/// Ethereum submission outbox. It is written immediately after submission
	/// returns (including a typed ambiguous result). A process crash or durable
	/// storage failure between node acceptance and that write can still lose the
	/// hash; that residual duplicate-transfer risk is an accepted operational
	/// assumption documented in `doc/atomic_swaps.md`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub redirect_tx: Option<H256>,
	/// Original and replacement redirect hashes copied from direct-transfer recovery.
	/// Keep the original redirect_tx stable for replay protection when importing backups.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub redirect_tx_candidates: Vec<H256>,
	/// Last transaction gas budget used for ETH, in whole gwei.
	/// The renamed field deliberately rejects the old float-based schema.
	pub tx_fee_gwei: Option<u64>,
}

impl EthData {
	/// Create seller ETH data (party that receive ETH).
	pub(crate) fn new(context: &EthSellerContext, // Derivarive index
	) -> Result<Self, Error> {
		Ok(Self {
			redeem_address: context.redeem_address,
			address_from_secret: None,
			erc20_approve_tx: None,
			erc20_funding: None,
			erc20_approval_recovery: None,
			erc20_approval_history: Vec::new(),
			lock_tx: None,
			lock_recovery: None,
			lock_cancel_recovery: None,
			refund_tx: None,
			refund_recovery: None,
			redeem_tx: None,
			redeem_recovery: None,
			redirect_tx: None,
			redirect_tx_candidates: Vec::new(),
			tx_fee_gwei: None,
		})
	}

	/// Create buyer ETH data (party that sell ETH)
	pub(crate) fn from_offer(
		offer: EthOfferUpdate,
		context: &EthBuyerContext,
	) -> Result<Self, Error> {
		// The seller address is required when buyer_deposit constructs the
		// contract call. Rejecting it here prevents an unusable trade from being
		// accepted and durably stored before that later operation fails.
		let redeem_address = offer.redeem_address.ok_or_else(|| {
			Error::InvalidMessageData(
				"Ethereum swap offer is missing the required redeem address".to_string(),
			)
		})?;
		Ok(Self {
			redeem_address: Some(redeem_address),
			address_from_secret: Some(context.address_from_secret),
			erc20_approve_tx: None,
			erc20_funding: None,
			erc20_approval_recovery: None,
			erc20_approval_history: Vec::new(),
			lock_tx: None,
			lock_recovery: None,
			lock_cancel_recovery: None,
			refund_tx: None,
			refund_recovery: None,
			redeem_tx: None,
			redeem_recovery: None,
			redirect_tx: None,
			redirect_tx_candidates: Vec::new(),
			tx_fee_gwei: None,
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
#[serde(crate = "serde")]
pub struct EthSellerContext {
	/// Seller, redeem addres.
	pub redeem_address: Option<Address>,
}

/// Context for the Buyer (party that sell ETH)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct EthBuyerContext {
	/// Buyer swap offer index in swap contract account
	pub address_from_secret: Address,
}

/// Messages regarding ETH part of the deal
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "serde")]
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
#[serde(crate = "serde")]
pub struct EthOfferUpdate {
	/// Address to redeem eth.
	pub redeem_address: Option<Address>,
}

/// Buyer message back to Seller. Offer is accepted
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "serde")]
pub struct EthAcceptOfferUpdate {
	/// Eth Lock Transaction Id
	pub lock_tx: Option<H256>,
	/// Buyer swap contract index
	pub address_from_secret: Option<Address>,
}

/// to web3 Address
pub fn to_eth_address(address: String) -> Result<Address, Error> {
	// Validate before the lowercasing below destroys the EIP-55 checksum.
	// wagyu verifies the checksum for mixed-case addresses; all-lowercase and
	// all-uppercase input carries no checksum and is accepted as plain HEX.
	EthereumAddress::from_str(&address).map_err(|e| {
		Error::Generic(format!(
			"Unable to parse Ethereum address {}, {}",
			address, e
		))
	})?;
	let address = address.to_lowercase();
	let address = address.strip_prefix("0x").unwrap_or(&address);

	if address.len() != 40 {
		return Err(Error::InvalidEthAddress);
	}
	let address_bytes = hex::decode(address)
		.map_err(|e| Error::Generic(format!("Unable to decode ETH address {}, {}", address, e)))?;
	let address_slice: [u8; 20] = address_bytes
		.try_into()
		.map_err(|_| Error::InvalidEthAddress)?;
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
	let hash = tx_hash.strip_prefix("0x").unwrap_or(&tx_hash);

	if hash.len() != 64 {
		return Err(Error::InvalidTxHash);
	}
	let hash_bytes =
		hex::decode(hash).map_err(|e| Error::Generic(format!("Invalid hash {}, {}", hash, e)))?;
	let hash_slice: [u8; 32] = hash_bytes.try_into().map_err(|_| Error::InvalidTxHash)?;

	Ok(H256::from(hash_slice))
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_util::mwc_crates::serde_json;

	#[test]
	fn eth_transaction_fee_rejects_the_legacy_field() {
		let legacy = r#"{
			"redeem_address": null,
			"address_from_secret": null,
			"erc20_approve_tx": null,
			"lock_tx": null,
			"refund_tx": null,
			"redeem_tx": null,
			"tx_fee": 5500000.5
		}"#;
		assert!(serde_json::from_str::<EthData>(legacy).is_err());
	}

	#[test]
	fn buyer_eth_data_rejects_offer_without_redeem_address() {
		let offer = EthOfferUpdate {
			redeem_address: None,
		};
		let context = EthBuyerContext {
			address_from_secret: Address::zero(),
		};
		assert!(matches!(
			EthData::from_offer(offer, &context),
			Err(Error::InvalidMessageData(_))
		));
	}

	// Workflow: Load historical JSON without redirect or recovery fields, then
	// add an original redirect hash and a replacement and serialize/reload it.
	// Expected: Missing fields default to unset or empty values; the round trip
	// preserves the original marker and the complete candidate hash list.
	#[test]
	fn redirect_hash_is_backward_compatible_and_round_trips() {
		let historical = r#"{
			"redeem_address": null,
			"address_from_secret": null,
			"erc20_approve_tx": null,
			"lock_tx": null,
			"refund_tx": null,
			"redeem_tx": null,
			"tx_fee_gwei": null
		}"#;
		let mut data: EthData = serde_json::from_str(historical).unwrap();
		assert_eq!(data.redirect_tx, None);
		assert!(data.redirect_tx_candidates.is_empty());
		assert_eq!(data.erc20_funding, None);
		assert!(data.erc20_approval_recovery.is_none());
		assert!(data.redeem_recovery.is_none());

		let redirect_tx = H256::from_low_u64_be(42);
		data.redirect_tx = Some(redirect_tx);
		data.redirect_tx_candidates = vec![redirect_tx, H256::from_low_u64_be(43)];
		let restored: EthData =
			serde_json::from_str(&serde_json::to_string(&data).unwrap()).unwrap();
		assert_eq!(restored.redirect_tx, Some(redirect_tx));
		assert_eq!(restored.redirect_tx_candidates, data.redirect_tx_candidates);
	}

	#[test]
	fn to_eth_address_validates_eip55_checksum() {
		// Correctly checksummed mixed-case address is accepted
		assert!(to_eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string()).is_ok());
		// Same address with a corrupted checksum (one letter case flipped) is rejected
		assert!(to_eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD".to_string()).is_err());
		assert!(to_eth_address("0x5aaeB6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string()).is_err());
		// All-lowercase and all-uppercase input carries no checksum, accepted as plain HEX
		assert!(to_eth_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".to_string()).is_ok());
		assert!(to_eth_address("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".to_string()).is_ok());
		// Malformed input is rejected
		assert!(to_eth_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1bea".to_string()).is_err());
		assert!(to_eth_address("0xZZeb6053f3e94c9b9a09f33669435e7ef1beaed".to_string()).is_err());
		assert!(to_eth_address("".to_string()).is_err());
	}
}
