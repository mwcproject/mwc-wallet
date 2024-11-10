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

use super::message::*;
use super::multisig::{Builder as MultisigBuilder, Hashed};
use super::ser::*;
use super::types::*;
use super::{Error, Keychain};
use crate::mwc_core::core::{
	transaction as tx, CommitWrapper, Inputs, KernelFeatures, OutputIdentifier, TxKernel, Weighting,
};
use crate::mwc_core::libtx::secp_ser;
use crate::mwc_keychain::{Identifier, SwitchCommitmentType};
use crate::mwc_util::secp::key::{PublicKey, SecretKey};
use crate::mwc_util::secp::pedersen::{Commitment, RangeProof};
use crate::mwc_util::secp::{Message as SecpMessage, Secp256k1, Signature};
use crate::swap::fsm::state::StateId;
use crate::{NodeClient, Slate};
use chrono::{DateTime, Utc};
use std::convert::TryInto;
use uuid::Uuid;

#[cfg(test)]
use crate::mwc_util::RwLock;

/// Dummy wrapper for the hex-encoded serialized transaction.
#[derive(Serialize, Deserialize)]
pub struct TxWrapper {
	/// hex representation of transaction
	pub tx_hex: String,
}

/// Swap event
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapJournalRecord {
	/// Unix timestamp, when event happens
	pub time: i64,
	/// Description with what happens at that time.
	pub message: String,
}

/// Primary SWAP state. Both Seller and Buyer are using it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Swap {
	/// Swap session uuid
	pub id: Uuid,
	/// Swap engine version. Both party are expected to have the same version
	pub version: u8,
	/// Network for the swap session (mainnet/floonet)
	pub network: Network,
	/// Role of the party (Byer or Seller)
	pub role: Role,
	/// Method how we are sending message to other party
	pub communication_method: String,
	/// destination address of the other party
	pub communication_address: String,
	/// Flag that specify the Locking fund order (Will wait for the fact that transaction is publishing, not for all confirmations).
	///    true: Seller lock MWC first, then Buyer BTC.
	///    false: Buyer lock BTC first, then Seller does lock.
	pub seller_lock_first: bool,
	/// Time when we started swap session
	pub started: DateTime<Utc>,
	/// Current state for this swap session
	pub state: StateId,
	/// MWC amount that Seller offer
	#[serde(with = "secp_ser::string_or_u64")]
	pub primary_amount: u64,
	/// BTC amount that Buyer pay
	#[serde(with = "secp_ser::string_or_u64")]
	pub secondary_amount: u64,
	/// units for BTC
	pub secondary_currency: Currency,
	/// Data associated with BTC deal
	pub secondary_data: SecondaryData,
	#[serde(
		serialize_with = "option_pubkey_to_hex",
		deserialize_with = "option_pubkey_from_hex"
	)]
	/// Buyer Redeem slate public key
	pub(super) redeem_public: Option<PublicKey>,
	/// Schnorr multisig this party participant id
	pub(super) participant_id: usize,
	/// Schnorr multisig builder and holder
	pub(super) multisig: MultisigBuilder,
	/// MWC Lock Slate
	#[serde(deserialize_with = "slate_deser")]
	pub lock_slate: Slate,
	/// MWC Refund Slate
	#[serde(deserialize_with = "slate_deser")]
	pub refund_slate: Slate,
	#[serde(deserialize_with = "slate_deser")]
	/// MWC redeem slate
	pub redeem_slate: Slate,
	/// Redeem slate was updated. Seller spot it on the blockchain and get the kernel updated.
	pub redeem_kernel_updated: bool,
	/// Signature that is done with multisig
	#[serde(
		serialize_with = "option_sig_to_hex",
		deserialize_with = "option_sig_from_hex"
	)]
	/// Multisig signature
	pub(super) adaptor_signature: Option<Signature>,
	/// Required confirmations for MWC Locking
	pub mwc_confirmations: u64,
	/// Required confirmations for BTC Locking
	pub secondary_confirmations: u64,
	/// Time interval for message exchange session.
	pub message_exchange_time_sec: u64,
	/// Time interval needed to redeem or execute a refund transaction.
	pub redeem_time_sec: u64,
	/// First message that was sent, keep for retry operations
	pub message1: Option<Message>,
	/// Second message that was sent, keep for retry operations
	pub message2: Option<Message>,
	/// timestamp when message 1 was send
	pub posted_msg1: Option<i64>,
	/// timestamp when message 2 was send
	pub posted_msg2: Option<i64>,
	/// timestamp when lock transaction was posted
	pub posted_lock: Option<i64>,
	/// timestamp when redeem transaction was posted
	pub posted_redeem: Option<i64>,
	/// timestamp when refund transaction was posted
	pub posted_refund: Option<i64>,
	/// At what height the secondary redeem transaction was posted. Secondary refund doesn't use
	/// that because timing is not critical.
	pub posted_secondary_height: Option<u64>,
	/// Last error message if --check was failed. Note, error will be very generic
	pub last_check_error: Option<String>,
	/// Last error message if --process was failed. Note, error will be very generic
	pub last_process_error: Option<(StateId, String)>,
	/// Event log for this swap trade.
	pub journal: Vec<SwapJournalRecord>,
	/// Secondary fee as it comes from the parameters or default value.
	/// Fee units might be changed from Currency to Currency
	pub secondary_fee: f32,
	/// ElectrumX URI1
	pub electrum_node_uri1: Option<String>,
	/// ElectrumX failover URI2
	pub electrum_node_uri2: Option<String>,
	/// Ethereum Swap Contract Address
	pub eth_swap_contract_address: Option<String>,
	/// ERC20 Swap Contract Address
	pub erc20_swap_contract_address: Option<String>,
	/// Ethereum Infura Project Id
	pub eth_infura_project_id: Option<String>,
	/// Ethereum transfer to users' wallet directly
	pub eth_redirect_to_private_wallet: Option<bool>,

	// --------------------------------
	// Additional non stored params for the trade. They good for a single call, not for all sessions
	/// For the step 1 backup. The QT wallet will take care about the backup. Here we should wait until
	/// it is done by user
	#[serde(skip)]
	#[serde(default = "default_false")]
	pub wait_for_backup1: bool,
	/// Tag for the swap. Using for swap marketplace automation process.
	pub tag: Option<String>,
	/// Flag that other party locking is confirmed. Utility flag for swap marketplace
	#[serde(default = "default_false")]
	pub other_lock_first_done: bool,
}

fn default_false() -> bool {
	false
}

impl Swap {
	/// Return true for Seller
	pub fn is_seller(&self) -> bool {
		match self.role {
			Role::Seller(_, _) => true,
			Role::Buyer(_) => false,
		}
	}

	/// Get MWC lock slate, change outputs
	pub fn change_output<K: Keychain>(
		&self,
		keychain: &K,
		context: &Context,
	) -> Result<(Identifier, u64, Commitment), Error> {
		assert!(self.is_seller());
		let scontext = context.unwrap_seller()?;

		let identifier = scontext.change_output.clone();
		let amount = scontext
			.inputs
			.iter()
			.fold(0, |acc, (_, _, value)| acc + *value)
			.saturating_sub(self.primary_amount);
		let commit = keychain.commit(amount, &identifier, SwitchCommitmentType::Regular)?;

		Ok((identifier, amount, commit))
	}

	/// Return Seller specific data
	pub fn unwrap_seller(&self) -> Result<(String, u64), Error> {
		match &self.role {
			Role::Seller(address, change) => {
				match address == "0x0000000000000000000000000000000000000000" {
					true => Ok(("Internal Ethereum Wallet".to_string(), *change)),
					_ => Ok((address.clone(), *change)),
				}
			}
			_ => Err(Error::UnexpectedRole("Swap call unwrap_seller".to_string())),
		}
	}

	/// Return buyer specific data
	pub fn unwrap_buyer(&self) -> Result<Option<String>, Error> {
		match &self.role {
			Role::Buyer(address) => match address {
				Some(address) => match address == "0x0000000000000000000000000000000000000000" {
					true => Ok(Some("Internal Ethereum Wallet".to_string())),
					_ => Ok(Some(address.clone())),
				},
				_ => Ok(address.clone()),
			},
			_ => Err(Error::UnexpectedRole("Swap call unwrap_buyer".to_string())),
		}
	}

	/// Update secondary address. Depend on role, updates redeem or refund secondary currency address
	pub fn update_secondary_address(&mut self, secondary_address: String) {
		let mut sec_addr: String = secondary_address;
		if !self.secondary_currency.is_btc_family() {
			if sec_addr.as_str() == "0x0000000000000000000000000000000000000000" {
				sec_addr = "Internal Ethereum Wallet Address!".to_string()
			}
		}

		match &mut self.role {
			Role::Buyer(address) => {
				address.replace(sec_addr);
			}
			Role::Seller(address, _) => {
				*address = sec_addr;
			}
		};
	}

	/// Get secondary address. Depend on role, returns redeem or refund secondary currency address
	pub fn get_secondary_address(&self) -> String {
		match &self.role {
			Role::Buyer(address) => address.clone().unwrap_or(String::new()),
			Role::Seller(address, _) => address.clone(),
		}
	}

	pub(super) fn message(
		&self,
		inner: Update,
		inner_secondary: SecondaryUpdate,
	) -> Result<Message, Error> {
		Ok(Message::new(self.id.clone(), inner, inner_secondary))
	}

	pub(super) fn multisig_secret<K: Keychain>(
		&self,
		keychain: &K,
		context: &Context,
	) -> Result<SecretKey, Error> {
		let sec_key = keychain.derive_key(
			self.primary_amount,
			&context.multisig_key,
			SwitchCommitmentType::None,
		)?;

		Ok(sec_key)
	}

	pub(super) fn refund_amount(&self) -> u64 {
		self.primary_amount - self.refund_slate.fee
	}

	pub(super) fn redeem_tx_fields(
		&self,
		redeem_slate: &Slate,
		secp: &Secp256k1,
	) -> Result<(PublicKey, PublicKey, SecpMessage), Error> {
		let pub_nonces = redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		let pub_nonce_sum = PublicKey::from_combination(secp, pub_nonces)?;
		let pub_blinds = redeem_slate
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		let pub_blind_sum = PublicKey::from_combination(secp, pub_blinds)?;

		let features = KernelFeatures::Plain {
			fee: redeem_slate
				.fee
				.try_into()
				.map_err(|e| Error::Generic(format!("Invalid fee, {}", e)))?,
		};
		let message = features
			.kernel_sig_msg()
			.map_err(|e| Error::Generic(format!("Unable to generate message, {}", e)))?;

		Ok((pub_nonce_sum, pub_blind_sum, message))
	}

	pub(super) fn find_redeem_kernel<C: NodeClient>(
		&self,
		node_client: &C,
	) -> Result<Option<(TxKernel, u64)>, Error> {
		let excess = &self
			.redeem_slate
			.tx_or_err()?
			.kernels()
			.get(0)
			.ok_or(Error::UnexpectedAction(
				"Swap Fn find_redeem_kernel() redeem slate is not initialized, not found kernel"
					.to_string(),
			))?
			.excess;

		let res = node_client
			.get_kernel(excess, None, None)?
			.map(|(kernel, height, _)| (kernel, height));

		Ok(res)
	}

	pub(super) fn other_participant_id(&self) -> usize {
		(self.participant_id + 1) % 2
	}

	/// Common nonce for the BulletProof is sum_i H(C_i) where C_i is the commitment of participant i
	pub(super) fn common_nonce(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		let hashed_nonces: Vec<SecretKey> = self
			.multisig
			.participants
			.iter()
			.filter_map(|p| p.partial_commitment.as_ref().map(|c| c.hash()))
			.filter_map(|h| h.ok().map(|h| h.to_secret_key(secp)))
			.filter_map(|s| s.ok())
			.collect();
		if hashed_nonces.len() != 2 {
			return Err(super::multisig::Error::MultiSigIncomplete.into());
		}
		let sec_key = secp.blind_sum(hashed_nonces, Vec::new())?;

		Ok(sec_key)
	}

	/// Receive acknowledge for message 1
	pub fn ack_msg1(&mut self) {
		if self.posted_msg1.is_some() {
			self.posted_msg1 = Some(u32::MAX as i64);
		}
	}
	/// Receive acknowledge for message 2
	pub fn ack_msg2(&mut self) {
		if self.posted_msg2.is_some() {
			self.posted_msg2 = Some(u32::MAX as i64);
		}
	}

	/// Add a journal message for this swap trade
	pub fn add_journal_message(&mut self, msg: String) {
		self.journal.push(SwapJournalRecord {
			time: get_cur_time(),
			message: msg,
		});
		// We want to limit journal to 1000 items because of the performance.
		while self.journal.len() > 1000 {
			self.journal.remove(0);
		}
	}

	/// Append to the last message.
	pub fn append_to_last_message(&mut self, msg: &String) {
		if let Some(last) = self.journal.last_mut() {
			last.message.push_str(msg.as_str());
		}
	}

	// Time management functions

	/// Trade starting time
	pub fn get_time_start(&self) -> i64 {
		self.started.timestamp()
	}

	/// Offer message exchange session time limit
	pub fn get_time_message_offers(&self) -> i64 {
		self.get_time_start() + self.message_exchange_time_sec as i64
	}

	/// When locking need to be started
	pub fn get_time_start_lock(&self) -> i64 {
		// We can get 5% from the total lock time. We have to post fast
		self.get_time_message_offers()
			+ std::cmp::max(
				self.get_timeinterval_mwc_lock(),
				self.get_timeinterval_secondary_lock(),
			) / 20
	}

	/// When locking time will be expired
	pub fn get_time_locking(&self) -> i64 {
		// for confirmation adding 10% for possible network slow down.
		self.get_time_message_offers()
			+ std::cmp::max(
				self.get_timeinterval_mwc_lock(),
				self.get_timeinterval_secondary_lock(),
			)
	}

	/// Second period of the message exchange
	pub fn get_time_message_redeem(&self) -> i64 {
		self.get_time_locking() + self.message_exchange_time_sec as i64
	}

	/// MWC redeem time
	pub fn get_time_mwc_redeem(&self) -> i64 {
		self.get_time_message_redeem() + self.redeem_time_sec as i64
	}

	/// MWC locking time
	pub fn get_time_mwc_lock(&self) -> i64 {
		// Add 10% for network instability
		self.get_time_mwc_redeem() + self.get_timeinterval_mwc_lock()
	}

	/// mwc refund time
	pub fn get_time_mwc_refund(&self) -> i64 {
		// Add 10% for network instability
		self.get_time_mwc_lock() + self.redeem_time_sec as i64
	}

	/// BTC/ETH lock time for script
	pub fn get_time_secondary_lock_script(&self) -> i64 {
		self.get_time_mwc_refund()
			+ self.redeem_time_sec as i64
			+ self.get_timeinterval_mwc_lock()
			+ self.get_timeinterval_secondary_lock()
	}

	/// BTC/ETH lock time publish
	pub fn get_time_secondary_lock_publish(&self) -> i64 {
		// Here is what BTC node said:
		// Only accept nLockTime-using transactions that can be mined in the next
		// block; we don't want our mempool filled up with transactions that can't
		// be mined yet.
		//
		// As a result we have to wait guarantee 1 block. To be safe, we will wait time for 5 blocks before we try to publish
		// 5 is a large number, but accordign the testnet, it is needed.
		self.get_time_secondary_lock_script() + self.secondary_currency.block_time_period_sec() * 5
	}

	/// btc redeem time limit
	pub fn get_time_btc_redeem_limit(&self) -> i64 {
		// Using script time as lowest possible value
		self.get_time_secondary_lock_script() - self.get_timeinterval_secondary_lock()
	}

	////////////////////////////////////////////////////////////
	// Time periof functions

	/// MWC locking time interval
	pub fn get_timeinterval_mwc_lock(&self) -> i64 {
		// adding extra 10% for chain instability
		self.mwc_confirmations as i64 * 60 * 11 / 10
	}

	/// BTC/ETH locking time interval
	pub fn get_timeinterval_secondary_lock(&self) -> i64 {
		// adding extra 10% for chain instability
		self.secondary_confirmations as i64 * self.secondary_currency.block_time_period_sec() * 11
			/ 10
	}

	/// Latest error message. Check has higher priority because it is normally done first
	pub fn get_last_error(&self) -> Option<String> {
		if self.last_check_error.is_some() {
			self.last_check_error.clone()
		} else {
			if let Some((state, err)) = self.last_process_error.clone() {
				// Error is reportable only if it happend for the current state. If state was changed,
				// th error is not applicable any more.
				if state == self.state {
					Some(err)
				} else {
					None
				}
			} else {
				None
			}
		}
	}
}

/*impl ser::Writeable for Swap {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("OutputData to json conversion failed, {}", e))
		})?)
	}
}

impl ser::Readable for Swap {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Swap, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("Json to outputData conversion failed, {}", e))
		})
	}
}*/

/// Add an input to a tx at the appropriate position
pub fn tx_add_input(slate: &mut Slate, commit: Commitment) -> Result<(), Error> {
	match &mut slate.tx_or_err_mut()?.body.inputs {
		Inputs::FeaturesAndCommit(inputs) => {
			let input = tx::Input {
				features: tx::OutputFeatures::Plain,
				commit,
			};
			inputs
				.binary_search(&input)
				.err()
				.map(|e| inputs.insert(e, input));
		}
		Inputs::CommitOnly(commits) => {
			let cmt = CommitWrapper::from(commit);
			commits
				.binary_search(&cmt)
				.err()
				.map(|e| commits.insert(e, cmt));
		}
	}
	Ok(())
}

/// Add an output to a tx at the appropriate position
pub fn tx_add_output(
	slate: &mut Slate,
	commit: Commitment,
	proof: RangeProof,
) -> Result<(), Error> {
	let output = tx::Output {
		identifier: OutputIdentifier {
			features: tx::OutputFeatures::Plain,
			commit,
		},
		proof,
	};
	let outputs = &mut slate.tx_or_err_mut()?.body.outputs;
	outputs
		.binary_search(&output)
		.err()
		.map(|e| outputs.insert(e, output));
	Ok(())
}

/// Interpret the final 32 bytes of the signature as a secret key
pub fn signature_as_secret(secp: &Secp256k1, signature: &Signature) -> Result<SecretKey, Error> {
	let ser = signature.to_raw_data();
	let key = SecretKey::from_slice(secp, &ser[32..])?;
	Ok(key)
}

/// Serialize a transaction and submit it to the network
pub fn publish_transaction<C: NodeClient>(
	node_client: &C,
	tx: &tx::Transaction,
	fluff: bool,
) -> Result<(), Error> {
	let (height, _, _) = node_client.get_chain_tip()?;
	tx.validate(Weighting::AsTransaction, height)
		.map_err(|e| Error::UnexpectedAction(format!("slate is not valid, {}", e)))?;

	node_client.post_tx(tx, fluff)?;
	Ok(())
}

#[cfg(test)]
lazy_static! {
	static ref CURRENT_TEST_TIME: RwLock<Option<i64>> = RwLock::new(None);
}

#[cfg(test)]
/// Test current time as a timestamp for testing. Pleas ebe carefull, in production it is never called.
pub fn set_testing_cur_time(cur_time: i64) {
	CURRENT_TEST_TIME.write().replace(cur_time.clone());
}

#[cfg(test)]
/// Remove test timer control for swaps. Will use current system time instead
pub fn reset_testing_cur_time() {
	CURRENT_TEST_TIME.write().take();
}

#[cfg(test)]
/// Current time. In release it is just a current time. In debug it is a test controlled time that allows us to validate the edge cases
pub fn get_cur_time() -> i64 {
	match *CURRENT_TEST_TIME.read() {
		Some(time) => time,
		None => Utc::now().timestamp(),
	}
}

#[cfg(not(test))]
/// Current time for relase allways returns fair value
pub fn get_cur_time() -> i64 {
	Utc::now().timestamp()
}

/// Print how much time left from the time limit
pub fn left_from_time_limit(time_limit: &Option<i64>) -> String {
	match time_limit {
		Some(time_limit) => {
			let left_sec = time_limit - get_cur_time();
			if left_sec <= 0 {
				"expired".to_string()
			} else {
				if left_sec > 3600 {
					format!(
						"expired in {} hours {} minutes",
						left_sec / 3600,
						(left_sec % 3600) / 60
					)
				} else if left_sec > 60 {
					format!("expired in {} minutes", left_sec / 60)
				} else {
					format!("expired in {} seconds", left_sec)
				}
			}
		}
		None => "".to_string(),
	}
}
