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

//! Generic implementation of owner API functions
use crate::api_impl::owner::check_ttl;
use crate::api_impl::owner_swap;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;
use crate::internal::{tx, updater};
use crate::proof::proofaddress;
use crate::proof::proofaddress::ProofAddressType;
use crate::proof::proofaddress::ProvableAddress;
use crate::slate_versions::SlateVersion;
use crate::{
	BlockFees, CbData, Error, ErrorKind, NodeClient, Slate, TxLogEntryType, VersionInfo,
	WalletBackend, WalletInst, WalletLCProvider,
};
use grin_core::core::amount_to_hr_string;
use grin_wallet_util::OnionV3Address;
use std::sync::Arc;
use std::sync::RwLock;
use strum::IntoEnumIterator;

const FOREIGN_API_VERSION: u16 = 2;
const USER_MESSAGE_MAX_LEN: usize = 256;

lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref RECV_ACCOUNT:   RwLock<Option<String>>  = RwLock::new(None);
}

/// get current receive account name
pub fn get_receive_account() -> Option<String> {
	RECV_ACCOUNT.read().unwrap().clone()
}

/// get tor proof address
pub fn get_proof_address<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
) -> Result<String, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = w.keychain(keychain_mask)?;
	let provable_address = proofaddress::payment_proof_address(&keychain, ProofAddressType::Onion)
		.map_err(|e| {
			ErrorKind::PaymentProofAddress(format!(
				"Error occurred in getting payment proof address, {}",
				e
			))
		})?;
	Ok(provable_address.public_key)
}

///
pub fn set_receive_account(account: String) {
	RECV_ACCOUNT.write().unwrap().replace(account.to_string());
}

/// Return the version info
pub fn check_version() -> VersionInfo {
	VersionInfo {
		foreign_api_version: FOREIGN_API_VERSION,
		supported_slate_versions: SlateVersion::iter().collect(),
	}
}

/// Build a coinbase transaction
pub fn build_coinbase<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	block_fees: &BlockFees,
	test_mode: bool,
) -> Result<CbData, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	updater::build_coinbase(&mut *w, keychain_mask, block_fees, test_mode)
}

/// verify slate messages
pub fn verify_slate_messages(slate: &Slate) -> Result<(), Error> {
	slate.verify_messages()
}

/// Receive a tx as recipient
/// Note: key_id & output_amounts needed for secure claims, mwc713.
pub fn receive_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	address: Option<String>,
	key_id_opt: Option<&str>,
	output_amounts: Option<Vec<u64>>,
	dest_acct_name: Option<&str>,
	message: Option<String>,
	use_test_rng: bool,
	refresh_from_node: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let display_from = "http listener";
	let slate_message = &slate.participant_data[0].message;
	let mut address_for_logging = address.clone();

	check_ttl(w, &slate, refresh_from_node)?;

	if address.is_none() {
		// that means it's not mqs so need to print it
		if slate_message.is_some() {
			println!(
				"{}",
				format!(
					"slate [{}] received from [{}] for [{}] MWCs. Message: [\"{}\"]",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false),
					slate_message.clone().unwrap()
				)
				.to_string()
			);
		} else {
			println!(
				"{}",
				format!(
					"slate [{}] received from [{}] for [{}] MWCs.",
					slate.id.to_string(),
					display_from,
					amount_to_hr_string(slate.amount, false)
				)
				.to_string()
			);
		}

		// if address is none, it must be an http send. file doesn't go here. so let's set it for tx_log
		// purposes
		address_for_logging = Some("http".to_string());
	}
	debug!("foreign just received_tx just got slate = {:?}", slate);
	let mut ret_slate = slate.clone();
	check_ttl(w, &ret_slate, refresh_from_node)?;

	let mut dest_acct_name = dest_acct_name.map(|s| s.to_string());
	if dest_acct_name.is_none() {
		dest_acct_name = get_receive_account();
	}

	let parent_key_id = match dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.to_owned())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		&mut *w,
		keychain_mask,
		None,
		Some(ret_slate.id),
		Some(&parent_key_id),
		use_test_rng,
		None,
		None,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxReceived {
			return Err(ErrorKind::TransactionAlreadyReceived(ret_slate.id.to_string()).into());
		}
	}

	let message = match message {
		Some(mut m) => {
			m.truncate(USER_MESSAGE_MAX_LEN);
			Some(m)
		}
		None => None,
	};

	let num_outputs = match &output_amounts {
		Some(v) => v.len(),
		None => 1,
	};

	// Note: key_id & output_amounts needed for secure claims, mwc713.
	tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut ret_slate,
		address_for_logging,
		key_id_opt,
		output_amounts,
		&parent_key_id,
		1,
		message,
		false,
		use_test_rng,
		num_outputs,
	)?;
	tx::update_message(&mut *w, keychain_mask, &ret_slate)?;

	let keychain = w.keychain(keychain_mask)?;
	let excess = ret_slate.calc_excess(&keychain)?;

	if let Some(ref mut p) = ret_slate.payment_proof {
		if p.sender_address
			.public_key
			.eq(&p.receiver_address.public_key)
		{
			debug!("file proof, replace the receiver address with its address");
			let sec_key = proofaddress::payment_proof_address_secret(&keychain)?;
			let onion_address = OnionV3Address::from_private(&sec_key.0)?;
			let dalek_pubkey = onion_address.to_ov3_str();
			p.receiver_address = ProvableAddress::from_str(&dalek_pubkey)?;
		}
		let sig = tx::create_payment_proof_signature(
			ret_slate.amount,
			&excess,
			p.sender_address.clone(),
			p.receiver_address.clone(),
			proofaddress::payment_proof_address_secret(&keychain)?,
		)?;

		p.receiver_signature = Some(sig);
	}

	Ok(ret_slate)
}

/// Receive an tx that this wallet has issued
pub fn finalize_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	refresh_from_node: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	check_ttl(w, &sl, refresh_from_node)?;
	// Participant id 0 for mwc713 compatibility
	let context = w.get_private_context(keychain_mask, sl.id.as_bytes(), 0)?;
	// Participant id 0 for mwc713 compatibility
	tx::complete_tx(&mut *w, keychain_mask, &mut sl, 0, &context)?;
	tx::update_stored_tx(&mut *w, keychain_mask, &context, &sl, true)?;
	tx::update_message(&mut *w, keychain_mask, &sl)?;
	{
		let mut batch = w.batch(keychain_mask)?;
		// Participant id 0 for mwc713 compatibility
		batch.delete_private_context(sl.id.as_bytes(), 0)?;
		batch.commit()?;
	}
	Ok(sl)
}

/// Process the incoming swap message received from TOR
pub fn receive_swap_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	message: &String,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	owner_swap::swap_income_message(wallet_inst, keychain_mask, &message, None).map_err(|e| {
		ErrorKind::SwapError(format!(
			"Error occurred in receiving the swap message by TOR, {}",
			e
		))
	})?;
	Ok(())
}
