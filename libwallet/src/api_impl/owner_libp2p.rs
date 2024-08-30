// Copyright 2020 The MWC Develope;
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

//! Generic implementation libp2p related communication functionality

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::api_impl::{foreign, owner};
use crate::grin_core::core::hash::Hash;
use crate::grin_core::libtx::tx_fee;
use crate::grin_core::ser;
use crate::grin_keychain::Keychain;
use crate::grin_keychain::{ExtKeychainPath, Identifier};
use crate::grin_p2p::libp2p_connection;
use crate::grin_util::secp;
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::grin_util::secp::{Message, PublicKey};
use crate::internal::{keys, updater};
use crate::types::NodeClient;
use crate::{wallet_lock, WalletInst, WalletLCProvider};
use crate::{AcctPathMapping, InitTxArgs, OutputCommitMapping, OutputStatus};
use crate::{Context, Error};
use ed25519_dalek::PublicKey as DalekPublicKey;
use grin_wallet_util::grin_util::secp::Secp256k1;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Identity Index for integrity account. Let's put it at the end, so we can be sure that it exist
pub const INTEGRITY_ACCOUNT_ID: u32 = 65536;
/// account name for integrity outputs
pub const INTEGRITY_ACCOUNT_NAME: &str = "integrity";
/// Number of blocks to identity output can be used. Mitigating network nodes update time
pub const INTEGRITY_FEE_MIN_CONFIRMATIONS: u64 = 2;

/// Integral fee proof data. It build form the both contexts and a transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntegrityContext {
	/// Sender account id. Might be needed to request a transaction detail
	pub sender_parent_key_id: Identifier,
	/// Transaction details
	pub tx_uuid: Uuid,
	/// Fee that was paid to miners
	pub fee: u64,
	/// Expiration height (until what height the context is valid)
	pub expiration_height: u64,

	/// Secret key to sign the tx kernel. It is sum of partial secrets from the single transaction
	pub sec_key: SecretKey,
}

impl IntegrityContext {
	// context0 - sender context, participant id 0
	// context1 - receiver context, participant id 1
	/// Build context needed to generate signature for the kernel excess (public key)
	pub fn build(
		tx_uuid: &Uuid,
		fee: u64,
		context0: &Context,
		context1: &Context,
		tip_height: u64,
		secp: &Secp256k1,
	) -> Result<Self, Error> {
		let mut sec_key = context0.sec_key.clone();
		sec_key.add_assign(secp, &context1.sec_key)?;

		Ok(Self {
			sender_parent_key_id: context0.parent_key_id.clone(),
			tx_uuid: tx_uuid.clone(),
			fee,
			sec_key,
			expiration_height: tip_height + libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS,
		})
	}

	// see for details: pub fn calc_excess<K>(&self, keychain: Option<&K>) -> Result<Commitment, Error>
	/// Calculate a kernel commit for this context, sign the message that can be verifiable with this context
	pub fn calc_kernel_excess(
		&self,
		secp: &secp::Secp256k1,
		tor_pk: &DalekPublicKey,
	) -> Result<(Commitment, Signature), Error> {
		let msg_hash = Hash::from_vec(tor_pk.as_bytes());
		let message = Message::from_slice(msg_hash.as_bytes())?;

		let pk = PublicKey::from_secret_key(&secp, &self.sec_key)?;
		let signature = secp::aggsig::sign_single(
			&secp,
			&message,
			&self.sec_key,
			None,
			None,
			None,
			Some(&pk),
			None, //Some(&pub_nonce_sum),
		)?;

		#[cfg(debug_assertions)]
		{
			// Sanity check
			crate::grin_core::libtx::aggsig::verify_completed_sig(
				secp,
				&signature,
				&pk,
				Some(&pk),
				&message,
			)?;
		}

		let kernel_excess = Commitment::from_pubkey(secp, &pk)?;
		Ok((kernel_excess, signature))
	}
}

impl ser::Writeable for IntegrityContext {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let data = serde_json::to_vec(self).map_err(|e| {
			ser::Error::CorruptedData(format!("IntegrityContext to json conversion failed, {}", e))
		})?;
		if data.len() > ser::READ_CHUNK_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"IntegrityContext data length is {}",
				data.len()
			)));
		}

		writer.write_bytes(&data)
	}
}

impl ser::Readable for IntegrityContext {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<IntegrityContext, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|e| {
			ser::Error::CorruptedData(format!("json to IntegrityContext conversion failed, {}", e))
		})
	}
}

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
/// Return <integrity account>, <unspent outputs>, <tip height>, <(best valid fee context, confirmed)>
pub fn get_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<
	(
		Option<AcctPathMapping>,
		Vec<OutputCommitMapping>,
		u64,
		Vec<(IntegrityContext, bool)>,
	),
	Error,
>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let tip_height = {
		let client = w.w2n_client();
		client.get_chain_tip()?.0
	};

	let integrity_account = w
		.acct_path_iter()
		.filter(|a| {
			u32::from(ExtKeychainPath::from_identifier(&a.path).path[0]) == INTEGRITY_ACCOUNT_ID
		})
		.next();
	if integrity_account.is_none() {
		return Ok((None, vec![], tip_height, vec![]));
	}

	let integrity_account = integrity_account.unwrap();
	let mut outputs = updater::retrieve_outputs(
		&mut **w,
		keychain_mask,
		false,
		None,
		&integrity_account.path,
		None,
		None,
	)?;

	outputs.retain(|o| {
		o.output.status == OutputStatus::Unspent
			|| o.output.status == OutputStatus::Unconfirmed
			|| o.output.status == OutputStatus::Reverted
	});

	// Let's check if fee already paid.
	let log_entry = updater::retrieve_txs(
		&mut **w,
		keychain_mask,
		None,
		None,
		None,
		Some(&integrity_account.path),
		false,
		None,
		None,
	)?;

	let mut tx_uuid: HashMap<Uuid, (bool, u64)> = HashMap::new();

	// Checking log entry in THIS side only. But we still need to handle receive transactions because of the fees.
	// And we need to provide both contexts for every transaction.
	// Note in case of receive transaction, we will return the send from another account.
	// Reason: Tx Kernel & fees.
	for log_entry in log_entry {
		let height = if log_entry.confirmed {
			log_entry.output_height
		} else {
			log_entry.kernel_lookup_min_height.unwrap_or(0)
		};
		if log_entry.tx_slate_id.is_none()
			|| height < tip_height.saturating_sub(libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS)
			|| log_entry.is_cancelled_reverted()
		{
			continue;
		}

		tx_uuid.insert(
			log_entry.tx_slate_id.unwrap(),
			(log_entry.confirmed, height),
		);
	}

	let mut integrity_tx: Vec<(IntegrityContext, bool)> = Vec::new();
	for (uuid, (confirmed, height)) in tx_uuid {
		// Requesting both contexts...
		let integrity_context = {
			let mut batch = w.batch(keychain_mask)?;
			match batch.load_integrity_context(uuid.as_bytes()) {
				Ok(ctx) => {
					let mut ctx = ctx;
					ctx.expiration_height = height + libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS;
					ctx
				}
				Err(_) => continue,
			}
		};
		integrity_tx.push((
			integrity_context,
			confirmed && height + INTEGRITY_FEE_MIN_CONFIRMATIONS < tip_height,
		));
	}

	// Sorting by height
	integrity_tx.sort_by(|i1, i2| {
		i1.0.expiration_height
			.partial_cmp(&i2.0.expiration_height)
			.unwrap()
	});

	Ok((Some(integrity_account), outputs, tip_height, integrity_tx))
}

/// Create integral kernel if needed. Return back the fee and height.
/// Height will be none if transaction note mined yet.
/// Return: Integrity context, confirmed flag
pub fn create_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	fee: &Vec<u64>, // We might have several message threads that runs in parallel. The fee need to be paid for each of them
	account_from: &Option<String>,
) -> Result<Vec<(Option<IntegrityContext>, bool)>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let max_fee = *fee.iter().max().unwrap_or(&0);
	let amount = std::cmp::max(max_fee * 2, amount);

	let (account, outputs, tip_height, mut transactions) =
		get_integral_balance(wallet_inst.clone(), keychain_mask)?;

	// Let's try to satisfy the requirements..
	let mut results: Vec<(Option<IntegrityContext>, bool)> = Vec::new();
	// Sorting because we want to apply the best choice (minimal fee that is needed) first
	transactions.sort_by(|t1, t2| t1.0.fee.partial_cmp(&t2.0.fee).unwrap());

	// We want to fill fees starting from the largest value, and apply least transaction
	let mut fee = fee.clone();
	fee.sort_by(|f1, f2| f2.partial_cmp(f1).unwrap());

	for f in &fee {
		match transactions.iter().position(|tx| tx.0.fee >= *f) {
			Some(idx) => {
				let (c, conf) = transactions.remove(idx);
				results.push((Some(c), conf));
			}
			None => results.push((None, false)),
		}
	}

	// Check if integrity outputs still in the waiting state
	if outputs
		.iter()
		.find(|o| {
			o.output.status == OutputStatus::Unconfirmed
				|| o.output.status == OutputStatus::Reverted
		})
		.is_some()
	{
		return Ok(results);
	}

	for i in 0..fee.len() {
		if results[i].0.is_some() {
			continue;
		}

		let fee = fee[i];

		// Found that some fee we can pay now. Will process only one transaction

		// We can't keep wallet locked on post. Test environment doesn't work this way
		let tx_to_post = {
			wallet_lock!(wallet_inst.clone(), w);

			let keychain = w.keychain(keychain_mask)?;

			if account.is_none() {
				// Creating integrity account
				let path = ExtKeychainPath::new(2, INTEGRITY_ACCOUNT_ID, 0, 0, 0).to_identifier();
				let label = INTEGRITY_ACCOUNT_NAME.to_string();
				keys::set_acct_path(&mut **w, keychain_mask, &label, &path)?;
			};

			let total_amount: u64 = outputs.iter().map(|o| o.output.value).sum();
			let mut amount = amount;
			let (src_account_name, tx_comment) = if total_amount < fee {
				// Need move some coins here
				(
					account_from.clone().unwrap_or("default".to_string()),
					"Integrity fee reserve",
				)
			} else {
				amount = total_amount;
				(INTEGRITY_ACCOUNT_NAME.to_string(), "Integrity fee")
			};

			let mut args = InitTxArgs::default();
			args.src_acct_name = Some(src_account_name.clone());
			args.amount = amount - fee;
			args.minimum_confirmations = 1;
			args.target_slate_version = Some(4); // Need Compact slate
			args.address = Some(tx_comment.to_string());
			args.min_fee = Some(fee);
			args.ttl_blocks = Some(3);
			args.late_lock = Some(true);
			args.selection_strategy_is_use_all = false;

			let slate = owner::init_send_tx(&mut **w, keychain_mask, &args, false, 1)?;

			owner::tx_lock_outputs(
				&mut **w,
				keychain_mask,
				&slate,
				args.address.clone(),
				0,
				false,
			)?;

			let (slate, context1) = foreign::receive_tx(
				&mut **w,
				keychain_mask,
				&slate,
				args.address.clone(),
				None,
				None,
				&Some(INTEGRITY_ACCOUNT_NAME.into()),
				None,
				false,
				false,
			)?;

			let (slate, context0) =
				owner::finalize_tx(&mut **w, keychain_mask, &slate, false, false)?;

			// Build and store integral fee data...
			let integrity_context = IntegrityContext::build(
				&slate.id,
				slate.fee,
				&context0,
				&context1,
				tip_height,
				keychain.secp(),
			)?;
			{
				let mut batch = w.batch(keychain_mask)?;
				batch.save_integrity_context(slate.id.as_bytes(), &integrity_context)?;
				batch.commit()?;
			}

			results[i] = (Some(integrity_context), false);

			slate.tx_or_err()?.clone()
		};

		// Posting transaction...
		let client = {
			wallet_lock!(wallet_inst, w);
			w.w2n_client().clone()
		};

		owner::post_tx(&client, &tx_to_post, false)?;

		break; // Processing only one iteration at a time
	}

	Ok(results)
}

/// Move all integral coins back to some account.
pub fn withdraw_integral_balance<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	account_withdraw_to: &String,
) -> Result<u64, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (_account, outputs, _tip_height, _transactions) =
		get_integral_balance(wallet_inst.clone(), keychain_mask)?;

	if outputs.is_empty() {
		return Ok(0);
	}

	wallet_lock!(wallet_inst, w);

	let total_amount: u64 = outputs.iter().map(|o| o.output.value).sum();
	let fee = tx_fee(outputs.len(), 1, 1);
	if total_amount <= fee {
		return Err(Error::GenericError("Reserved amount for Integrity fees is smaller then a transaction fee. It is impossible to move dust funds.".to_string()));
	}

	let mut args = InitTxArgs::default();
	args.src_acct_name = Some(INTEGRITY_ACCOUNT_NAME.to_string());
	args.amount = total_amount - fee;
	args.minimum_confirmations = 1;
	args.target_slate_version = Some(4); // Need Compact slate
	args.address = Some("Withdraw Integrity funds".to_string());
	args.ttl_blocks = Some(3);
	args.late_lock = Some(true);

	let slate = owner::init_send_tx(&mut **w, keychain_mask, &args, false, 1)?;

	let (slate, _context2) = foreign::receive_tx(
		&mut **w,
		keychain_mask,
		&slate,
		args.address.clone(),
		None,
		None,
		&Some(account_withdraw_to.clone()),
		None,
		false,
		false,
	)?;

	// Lock is skipped because we have lock later flag

	let (slate, _context1) = owner::finalize_tx(&mut **w, keychain_mask, &slate, false, false)?;

	// Posting transaction...
	owner::post_tx(w.w2n_client(), slate.tx_or_err()?, false)?;

	Ok(args.amount)
}
