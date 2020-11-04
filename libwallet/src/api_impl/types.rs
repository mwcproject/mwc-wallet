// Copyright 2019 The Grin Developers
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

//! Types specific to the wallet api, mostly argument serialization

use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::Identifier;
use crate::grin_util::secp::pedersen;
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProvableAddress;
use crate::slate_versions::SlateVersion;
use crate::types::OutputData;

/// Send TX API Args
// TODO: This is here to ensure the legacy V1 API remains intact
// remove this when v1 api is removed
#[derive(Clone, Serialize, Deserialize)]
pub struct SendTXArgs {
	/// amount to send
	pub amount: u64,
	/// minimum confirmations
	pub minimum_confirmations: u64,
	/// payment method
	pub method: String,
	/// destination url
	pub dest: String,
	/// Max number of outputs
	pub max_outputs: usize,
	/// Number of change outputs to generate
	pub num_change_outputs: usize,
	/// whether to use all outputs (combine)
	pub selection_strategy_is_use_all: bool,
	/// Optional message, that will be signed
	pub message: Option<String>,
	/// Optional slate version to target when sending
	pub target_slate_version: Option<u16>,
}

/// V2 Init / Send TX API Args
#[derive(Clone, Serialize, Deserialize)]
pub struct InitTxArgs {
	/// The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	///
	#[serde(default)]
	pub src_acct_name: Option<String>,
	#[serde(with = "secp_ser::string_or_u64")]
	/// The amount to send, in nanogrins. (`1 G = 1_000_000_000nG`)
	pub amount: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	/// The minimum number of confirmations an output
	/// should have in order to be included in the transaction.
	#[serde(default = "InitTxArgs::default_minimum_confirmations")]
	pub minimum_confirmations: u64,
	/// By default, the wallet selects as many inputs as possible in a
	/// transaction, to reduce the Output set and the fees. The wallet will attempt to spend
	/// include up to `max_outputs` in a transaction, however if this is not enough to cover
	/// the whole amount, the wallet will include more outputs. This parameter should be considered
	/// a soft limit.
	#[serde(default = "InitTxArgs::default_max_outputs")]
	pub max_outputs: u32,
	/// The target number of change outputs to create in the transaction.
	/// The actual number created will be `num_change_outputs` + whatever remainder is needed.
	#[serde(default = "InitTxArgs::default_num_change_outputs")]
	pub num_change_outputs: u32,
	/// If `true`, attempt to use up as many outputs as
	/// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
	/// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
	/// minimizes fees. This will generally result in many inputs and a large change output(s),
	/// usually much larger than the amount being sent. If `false`, the transaction will include
	/// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
	/// value outputs.
	#[serde(default = "InitTxArgs::default_selection_strategy_is_use_all")]
	pub selection_strategy_is_use_all: bool,
	/// An optional participant message to include alongside the sender's public
	/// ParticipantData within the slate. This message will include a signature created with the
	/// sender's private excess value, and will be publically verifiable. Note this message is for
	/// the convenience of the participants during the exchange; it is not included in the final
	/// transaction sent to the chain. The message will be truncated to 256 characters.
	#[serde(default)]
	pub message: Option<String>,
	/// Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
	#[serde(default)]
	pub target_slate_version: Option<u16>,
	/// Number of blocks from current after which TX should be ignored
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_blocks: Option<u64>,
	/// If set, require a payment proof for the particular recipient
	#[serde(
		serialize_with = "proofaddress::option_as_string",
		deserialize_with = "proofaddress::option_proof_address_from_string"
	)]
	#[serde(default)]
	pub payment_proof_recipient_address: Option<ProvableAddress>,
	/// address of another party to store in tx history.
	#[serde(default)]
	pub address: Option<String>,
	/// If true, just return an estimate of the resulting slate, containing fees and amounts
	/// locked without actually locking outputs or creating the transaction. Note if this is set to
	/// 'true', the amount field in the slate will contain the total amount locked, not the provided
	/// transaction amount
	#[serde(default)]
	pub estimate_only: Option<bool>,
	/// If true, exclude change outputs from minimum_confirmation settings. Instead --min_conf_change_outputs
	/// will be used for the minimum_confirmation value for all change_outputs. All non change outputs will continue
	/// to use the --min_conf parameter.
	#[serde(default)]
	pub exclude_change_outputs: Option<bool>,
	/// The minimum number of confirmations an output that is a change output
	/// should have in order to be included in the transaction.
	/// This parameter is only used if exclude_change_outputs is true.
	#[serde(default = "InitTxArgs::default_change_output_minimum_confirmations")]
	pub minimum_confirmations_change_outputs: u64,
	/// Sender arguments. If present, the underlying function will also attempt to send the
	/// transaction to a destination and optionally finalize the result
	#[serde(default)]
	pub send_args: Option<InitTxSendArgs>,
	/// Selected outputs. If none, will use all outputs
	pub outputs: Option<Vec<String>>, // outputs to include into the transaction
}

/// Send TX API Args, for convenience functionality that inits the transaction and sends
/// in one go
#[derive(Clone, Serialize, Deserialize)]
pub struct InitTxSendArgs {
	/// The transaction method. Can currently be 'http' .
	pub method: String,
	/// The destination, contents will depend on the particular method
	pub dest: String,
	/// receiver wallet apisecret. Applicable to http/https address only
	#[serde(default)]
	pub apisecret: Option<String>,
	/// Whether to finalize the result immediately if the send was successful
	#[serde(default = "InitTxSendArgs::default_finalize")]
	pub finalize: bool,
	/// Whether to post the transasction if the send and finalize were successful
	#[serde(default = "InitTxSendArgs::default_post_tx")]
	pub post_tx: bool,
	/// Whether to use dandelion when posting. If false, skip the dandelion relay
	#[serde(default = "InitTxSendArgs::default_fluff")]
	pub fluff: bool,
}

impl Default for InitTxArgs {
	fn default() -> InitTxArgs {
		InitTxArgs {
			src_acct_name: None,
			amount: 0,
			minimum_confirmations: 10,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			message: None,
			target_slate_version: None,
			ttl_blocks: None,
			estimate_only: Some(false),
			payment_proof_recipient_address: None,
			address: None,
			exclude_change_outputs: Some(false),
			minimum_confirmations_change_outputs: 1,
			send_args: None,
			outputs: None,
		}
	}
}

impl InitTxArgs {
	fn default_change_output_minimum_confirmations() -> u64 {
		1
	}
	fn default_minimum_confirmations() -> u64 {
		10
	}
	fn default_max_outputs() -> u32 {
		500
	}
	fn default_num_change_outputs() -> u32 {
		1
	}
	fn default_selection_strategy_is_use_all() -> bool {
		false
	}
}

impl InitTxSendArgs {
	fn default_finalize() -> bool {
		true
	}
	fn default_post_tx() -> bool {
		true
	}
	fn default_fluff() -> bool {
		true
	}
}

/// V2 Issue Invoice Tx Args
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueInvoiceTxArgs {
	/// The human readable account name to which the received funds should be added
	/// overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	#[serde(default)]
	pub dest_acct_name: Option<String>,
	/// The invoice amount in nanogrins. (`1 G = 1_000_000_000nG`)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Optional message, that will be signed
	#[serde(default)]
	pub message: Option<String>,
	/// Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
	#[serde(default)]
	pub target_slate_version: Option<u16>,
	/// recipient address
	#[serde(default)]
	pub address: Option<String>,
}

impl Default for IssueInvoiceTxArgs {
	fn default() -> IssueInvoiceTxArgs {
		IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount: 0,
			message: None,
			target_slate_version: None,
			address: None,
		}
	}
}

/// Fees in block to use for coinbase amount calculation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockFees {
	/// fees
	#[serde(with = "secp_ser::string_or_u64")]
	pub fees: u64,
	/// height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// key id
	pub key_id: Option<Identifier>,
}

impl BlockFees {
	/// return key id
	pub fn key_id(&self) -> Option<Identifier> {
		self.key_id.clone()
	}
}

/// Map Outputdata to commits
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputCommitMapping {
	/// Output Data
	pub output: OutputData,
	/// The commit
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: pedersen::Commitment,
}

/// Node height result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeHeightResult {
	/// Last known height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Hash
	pub header_hash: String,
	/// Whether this height was updated from the node
	pub updated_from_node: bool,
}

/// Version request result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionInfo {
	/// API version
	pub foreign_api_version: u16,
	/// Slate version
	pub supported_slate_versions: Vec<SlateVersion>,
}

/// Packaged Payment Proof
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentProof {
	/// Amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Kernel Excess
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: pedersen::Commitment,
	/// Recipient Wallet Address
	pub recipient_address: ProvableAddress,
	/// Recipient Signature
	pub recipient_sig: String,
	/// Sender Wallet Address
	pub sender_address: ProvableAddress,
	/// Sender Signature
	pub sender_sig: String,
}

/// Init swap operation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapStartArgs {
	/// MWC to send
	pub mwc_amount: u64,
	/// Secondary currency
	pub secondary_currency: String,
	/// BTC to recieve
	pub secondary_amount: String,
	/// Secondary currency redeem address
	pub secondary_redeem_address: String,
	/// Locking order (True, seller does locking first)
	pub seller_lock_first: bool,
	/// Minimum confirmation number for the inputs to spend
	pub minimum_confirmations: Option<u64>,
	/// Required confirmations for MWC Locking
	pub mwc_confirmations: u64,
	/// Required confirmations for BTC Locking
	pub secondary_confirmations: u64,
	/// Time interval for message exchange session.
	pub message_exchange_time_sec: u64,
	/// Time interval needed to redeem or execute a refund transaction.
	pub redeem_time_sec: u64,
	/// Method how we are sending message to the buyer
	pub buyer_communication_method: String,
	/// Buyer destination address
	pub buyer_communication_address: String,
	/// ElectrumX URI1
	pub electrum_node_uri1: Option<String>,
	/// ElectrumX failover URI2
	pub electrum_node_uri2: Option<String>,
}
