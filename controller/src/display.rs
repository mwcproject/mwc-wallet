// Copyright 2019 The Grin Developers
// Copyright 2024 The Mwc Developers
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

#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::fsm::state::StateEtaInfo;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::swap;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::types::{Action, Currency, Role};
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::types::bounded_escape_for_display;
use mwc_wallet_libwallet::types::escape_for_display;
use mwc_wallet_libwallet::{
	AcctPathMapping, Error, OutputCommitMapping, OutputStatus, TxLogEntry, ViewWallet, WalletInfo,
};
use mwc_wallet_util::mwc_core::core::{self, amount_to_hr_string};
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::prettytable;
use mwc_wallet_util::mwc_crates::term;

#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::swap::SwapJournalRecord;
#[cfg(feature = "swaps")]
use mwc_wallet_libwallet::swap::types::SwapTransactionsConfirmations;
#[cfg(feature = "swaps")]
use mwc_wallet_util::mwc_crates::chrono::prelude::*;
#[cfg(feature = "swaps")]
use mwc_wallet_util::mwc_crates::chrono::Local;
use mwc_wallet_util::mwc_crates::colored::*;
use mwc_wallet_util::mwc_crates::prettytable::{row, table};
use mwc_wallet_util::mwc_crates::secp::Secp256k1;
use mwc_wallet_util::mwc_util::{to_hex, ToHex};

#[cfg(feature = "swaps")]
const MAX_SWAP_DISPLAY_FIELD_BYTES: usize = 1_024;
#[cfg(feature = "swaps")]
const MAX_SWAP_DISPLAY_MESSAGE_BYTES: usize = 4_096;

/// Display outputs in a pretty way
pub fn outputs(
	account: &Option<String>,
	cur_height: u64,
	validated: bool,
	outputs: Vec<OutputCommitMapping>,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	println!();
	println!(
		"{}",
		format!(
			"Wallet Outputs - Account '{}' - Block Height: {}",
			account.as_deref().unwrap_or("default"),
			cur_height
		)
		.magenta()
	);

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"MMR Index",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Status",
		bMG->"Coinbase?",
		bMG->"# Confirms",
		bMG->"Value",
		bMG->"Tx"
	]);

	for m in outputs {
		let commit = format!("{}", m.commit.as_ref().to_hex());
		let index = match m.output.mmr_index {
			None => "None".to_owned(),
			Some(t) => t.to_string(),
		};
		let height = format!("{}", m.output.height);
		let lock_height = format!("{}", m.output.lock_height);
		let is_coinbase = format!("{}", m.output.is_coinbase);

		// Mark unconfirmed coinbase outputs as "Mining" instead of "Unconfirmed"
		let status = match m.output.status {
			OutputStatus::Unconfirmed if m.output.is_coinbase => "Mining".to_string(),
			_ => format!("{}", m.output.status),
		};

		let num_confirmations = format!("{}", m.output.num_confirmations(cur_height));
		let value = format!("{}", core::amount_to_hr_string(m.output.value, false));
		let tx = match m.output.tx_log_entry {
			None => "".to_owned(),
			Some(t) => t.to_string(),
		};

		if dark_background_color_scheme {
			table.add_row(row![
				bFC->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFR->status,
				bFY->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
				bFC->tx,
			]);
		} else {
			table.add_row(row![
				bFD->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFR->status,
				bFD->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
				bFD->tx,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `mwc server` offline or broken?)"
		);
	}
	Ok(())
}

/// Display transaction log in a pretty way
fn txs_titles(show_full_info: bool) -> prettytable::Row {
	if show_full_info {
		row![
			bMG->"Id",
			bMG->"Type",
			bMG->"Shared Transaction Id",
			bMG->"Address",
			bMG->"Creation Time",
			bMG->"TTL Cutoff Height",
			bMG->"Confirmed?",
			bMG->"Height",
			bMG->"Confirmation Time",
			bMG->"Num. \nInputs",
			bMG->"Num. \nOutputs",
			bMG->"Amount \nCredited",
			bMG->"Amount \nDebited",
			bMG->"Fee",
			bMG->"Net \nDifference",
			bMG->"Payment \nProof",
			bMG->"Kernel",
			bMG->"Tx \nData",
		]
	} else {
		// 'short' format is used by mwc 713 wallet
		row![
			bMG->"Id",
			bMG->"Type",
			bMG->"TXID", // short 'Shared Transaction Id' value
			bMG->"Address",
			bMG->"Creation Time",
			bMG->"Confirmed?",
			bMG->"Height",
			bMG->"Confirmation Time",
			bMG->"Net \nDifference",
			bMG->"Proof?",
		]
	}
}

/// Build a single transaction log row. The cell count must always match
/// `txs_titles` for the same `show_full_info` value: prettytable pads short
/// rows silently, so a missing cell shifts every subsequent value one column
/// away from its heading.
fn txs_data_row<F>(
	t: &TxLogEntry,
	dark_background_color_scheme: bool,
	show_full_info: bool,
	has_proof: &F,
) -> Result<prettytable::Row, Error>
where
	F: Fn(&TxLogEntry) -> Result<bool, Error>,
{
	let id = format!("{}", t.id);
	let slate_id = match t.tx_slate_id {
		Some(m) => format!("{}", m),
		None => "None".to_owned(),
	};
	// mwc713 (short) representation of ID
	let short_slate_id = match t.tx_slate_id {
		Some(m) => to_hex(&m.as_bytes()[..4]),
		None => String::from(""),
	};

	let address = match &t.address {
		Some(addr) => escape_for_display(addr),
		None => String::new(),
	};
	let entry_type = format!("{}", t.tx_type);
	let creation_ts = format!("{}", t.creation_ts.format("%Y-%m-%d %H:%M:%S"));
	let ttl_cutoff_height = match t.ttl_cutoff_height {
		Some(b) => format!("{}", b),
		None => "None".to_owned(),
	};
	let confirmation_ts = match t.confirmation_ts {
		Some(m) => format!("{}", m.format("%Y-%m-%d %H:%M:%S")),
		None => "None".to_owned(),
	};
	let confirmed = format!("{}", t.confirmed);
	let height = if t.confirmed && t.output_height > 0 {
		format!("{}", t.output_height)
	} else {
		"".to_string()
	};
	let num_inputs = format!("{}", t.num_inputs);
	let num_outputs = format!("{}", t.num_outputs);
	let amount_debited_str = core::amount_to_hr_string(t.amount_debited, true);
	let amount_credited_str = core::amount_to_hr_string(t.amount_credited, true);
	let fee = match t.fee {
		Some(f) => format!("{}", core::amount_to_hr_string(f, true)),
		None => "None".to_owned(),
	};
	let net_diff = if t.amount_credited >= t.amount_debited {
		// The branch condition proves this subtraction cannot underflow.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the branch checks amount_credited >= amount_debited"
		)]
		core::amount_to_hr_string(t.amount_credited - t.amount_debited, true)
	} else {
		// The else branch proves this subtraction cannot underflow.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the else branch implies amount_debited > amount_credited"
		)]
		let debit = t.amount_debited - t.amount_credited;
		format!("-{}", core::amount_to_hr_string(debit, true))
	};
	let tx_data = match t.stored_tx {
		Some(_) => "Yes".to_owned(),
		None => "None".to_owned(),
	};
	let kernel_excess = match t.kernel_excess {
		Some(e) => e.0.as_ref().to_hex(),
		None => "None".to_owned(),
	};
	let payment_proof = if has_proof(t)? {
		"Yes".to_owned()
	} else {
		"None".to_owned()
	};

	let row = if show_full_info {
		if dark_background_color_scheme {
			row![
				bFC->id,
				bFC->entry_type,
				bFC->slate_id,
				bFC->address,
				bFB->creation_ts,
				bFB->ttl_cutoff_height,
				bFC->confirmed,
				bFC->height,
				bFB->confirmation_ts,
				bFC->num_inputs,
				bFC->num_outputs,
				bFG->amount_credited_str,
				bFR->amount_debited_str,
				bFR->fee,
				bFY->net_diff,
				bfG->payment_proof,
				bFB->kernel_excess,
				bFb->tx_data,
			]
		} else {
			if t.confirmed {
				row![
					bFD->id,
					bFb->entry_type,
					bFD->slate_id,
					bFD->address,
					bFB->creation_ts,
					bFB->ttl_cutoff_height,
					bFg->confirmed,
					bFg->height,
					bFB->confirmation_ts,
					bFD->num_inputs,
					bFD->num_outputs,
					bFG->amount_credited_str,
					bFD->amount_debited_str,
					bFD->fee,
					bFG->net_diff,
					bfG->payment_proof,
					bFB->kernel_excess,
					bFB->tx_data,
				]
			} else {
				row![
					bFD->id,
					bFb->entry_type,
					bFD->slate_id,
					bFD->address,
					bFB->creation_ts,
					bFB->ttl_cutoff_height,
					bFR->confirmed,
					bFR->height,
					bFB->confirmation_ts,
					bFD->num_inputs,
					bFD->num_outputs,
					bFG->amount_credited_str,
					bFD->amount_debited_str,
					bFD->fee,
					bFG->net_diff,
					bfG->payment_proof,
					bFB->kernel_excess,
					bFB->tx_data,
				]
			}
		}
	} else {
		// Short supports only dark scheme, we really don't need more
		row![
			bFC->id,
			bFC->entry_type,
			bFB->short_slate_id,
			bFC->address,
			bFB->creation_ts,
			bFG->confirmed,
			bFG->height,
			bFB->confirmation_ts,
			bFY->net_diff,
			bFG->payment_proof,
		]
	};
	Ok(row)
}

pub fn txs(
	account: &Option<String>,
	cur_height: u64,
	validated: bool,
	txs: &[TxLogEntry],
	include_status: bool,
	dark_background_color_scheme: bool,
	show_full_info: bool,
	has_proof: impl Fn(&TxLogEntry) -> Result<bool, Error>,
) -> Result<(), Error> {
	println!();
	println!(
		"{}",
		format!(
			"Transaction Log - Account '{}' - Block Height: {}",
			account.as_deref().unwrap_or("default"),
			cur_height
		)
		.magenta()
	);

	let mut table = table!();
	table.set_titles(txs_titles(show_full_info));

	for t in txs {
		table.add_row(txs_data_row(
			t,
			dark_background_color_scheme,
			show_full_info,
			&has_proof,
		)?);
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	if !validated && include_status {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `mwc server` offline or broken?)"
		);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_wallet_libwallet::TxLogEntryType;
	use mwc_wallet_util::mwc_keychain::Identifier;

	fn sample_tx(confirmed: bool) -> TxLogEntry {
		let mut tx = TxLogEntry::new(Identifier::zero(), TxLogEntryType::TxSent, 1);
		tx.confirmed = confirmed;
		tx
	}

	// The header and every row variant must have the same cell count;
	// prettytable pads short rows silently, shifting values under wrong headings.
	#[test]
	fn txs_header_and_row_column_counts_match() {
		for show_full_info in &[true, false] {
			let titles = txs_titles(*show_full_info);
			for dark_scheme in &[true, false] {
				for confirmed in &[true, false] {
					let tx = sample_tx(*confirmed);
					let row =
						txs_data_row(&tx, *dark_scheme, *show_full_info, &|_| Ok(false)).unwrap();
					assert_eq!(
						titles.len(),
						row.len(),
						"txs table column mismatch: show_full_info={} dark={} confirmed={}",
						show_full_info,
						dark_scheme,
						confirmed
					);
				}
			}
		}
	}

	#[test]
	fn txs_address_is_escaped_for_terminal_display() {
		let mut tx = sample_tx(false);
		tx.address = Some("peer\u{1b}[2J\n\u{202e}address".to_owned());
		let expected = "peer\\u001b[2J\\u000a\\u202eaddress";

		for show_full_info in &[true, false] {
			for dark_scheme in &[true, false] {
				let row = txs_data_row(&tx, *dark_scheme, *show_full_info, &|_| Ok(false)).unwrap();
				assert_eq!(row.get_cell(3).unwrap().get_content(), expected);
			}
		}
	}
}

pub fn view_wallet_balance(w: &ViewWallet, cur_height: u64, dark_background_color_scheme: bool) {
	// `rewind_hash` is the value the operator supplied to the view-wallet scan,
	// not a credential newly retrieved from the local wallet. Echo it intentionally
	// so the human-readable report identifies the scan input it summarizes.
	println!(
		"\n____ View Wallet Summary Info - Block Height: {} ____\n Rewind Hash - {}\n Warning: outputs and total are rewind matches, not proof that this wallet can spend them.\n",
		cur_height,
		w.rewind_hash.as_str()
	);
	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Rewind-Matched Total",
			FG->amount_to_hr_string(w.total_balance, false)
		]);
	} else {
		table.add_row(row![
			bFG->"Rewind-Matched Total",
			FG->amount_to_hr_string(w.total_balance, false)
		]);
	};
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

pub fn view_wallet_output(
	view_wallet: &ViewWallet,
	cur_height: u64,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	println!();
	let title = format!("View Wallet Outputs - Block Height: {}", cur_height);

	let mut t = match term::stdout() {
		Some(t) => t,
		None => {
			println!("Could not open terminal");
			return Ok(());
		}
	};

	t.fg(term::color::MAGENTA)
		.map_err(|e| Error::IO(format!("Terminal error: {}", e)))?;
	writeln!(t, "{}", title)?;
	t.reset()
		.map_err(|e| Error::IO(format!("Terminal error: {}", e)))?;

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"MMR Index",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Coinbase?",
		bMG->"# Confirms",
		bMG->"Value",
	]);

	for m in &view_wallet.output_result {
		let commit = format!("{}", m.commit);
		let index = m.mmr_index;
		let height = format!("{}", m.height);
		let lock_height = format!("{}", m.lock_height);
		let is_coinbase = format!("{}", m.is_coinbase);
		let num_confirmations = format!("{}", m.num_confirmations(cur_height));
		let value = format!("{}", core::amount_to_hr_string(m.value, false));

		if dark_background_color_scheme {
			table.add_row(row![
				bFC->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFY->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
			]);
		} else {
			table.add_row(row![
				bFD->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFD->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();
	Ok(())
}

/// Display summary info in a pretty way
pub fn info(
	context_id: u32,
	account: &Option<String>,
	wallet_info: &WalletInfo,
	validated: bool,
	dark_background_color_scheme: bool,
) {
	println!(
		"\n____ Wallet Summary Info - Account '{}' as of height {} ____\n",
		account.as_deref().unwrap_or("default"),
		wallet_info.last_confirmed_height,
	);

	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Confirmed Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		if wallet_info.amount_reverted > 0 {
			table.add_row(row![
				Fr->format!("Reverted"),
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFY->format!("Immature Coinbase (< {})", global::coinbase_maturity(context_id)),
				FY->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFY->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FY->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			bFB->format!("Awaiting Finalization"),
			FB->amount_to_hr_string(wallet_info.amount_awaiting_finalization, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	} else {
		table.add_row(row![
			bFG->"Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		if wallet_info.amount_reverted > 0 {
			table.add_row(row![
				Fr->format!("Reverted"),
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFB->format!("Immature Coinbase (< {})", global::coinbase_maturity(context_id)),
				FB->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFB->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FB->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	};
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data against a live chain. \
			 The above is from local cache and only valid up to the given height! \
			 (is your `mwc server` offline or broken?)"
		);
	}
}

/// Display summary info in a pretty way
pub fn estimate(
	amount: u64,
	strategies: Vec<(
		&str, // strategy
		u64,  // total amount to be locked
		u64,  // fee
	)>,
	dark_background_color_scheme: bool,
) {
	println!(
		"\nEstimation for sending {}:\n",
		amount_to_hr_string(amount, false)
	);

	let mut table = table!();

	table.set_titles(row![
		bMG->"Selection strategy",
		bMG->"Fee",
		bMG->"Will be locked",
	]);

	for (strategy, total, fee) in strategies {
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->strategy,
				FR->amount_to_hr_string(fee, false),
				FY->amount_to_hr_string(total, false),
			]);
		} else {
			table.add_row(row![
				bFD->strategy,
				FR->amount_to_hr_string(fee, false),
				FY->amount_to_hr_string(total, false),
			]);
		}
	}
	table.printstd();
	println!();
}

/// Display list of wallet accounts in a pretty way
pub fn accounts(acct_mappings: Vec<AcctPathMapping>) {
	println!("\n____ Wallet Accounts ____\n",);
	let mut table = table!();

	table.set_titles(row![
		mMG->"Name",
		bMG->"Parent BIP-32 Derivation Path",
	]);
	for m in acct_mappings {
		table.add_row(row![
			bFC->m.label,
			bGC->m.path.to_bip_32_string().unwrap_or("<INVALID_PATH>".to_string()),
		]);
	}
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

/// Display transaction log messages
pub fn tx_messages(
	tx: &TxLogEntry,
	dark_background_color_scheme: bool,
	secp: &Secp256k1,
) -> Result<(), Error> {
	println!();
	println!(
		"{}",
		format!("Transaction Messages - Transaction '{}'", tx.id,).magenta()
	);

	let msgs = match tx.messages.clone() {
		None => {
			println!("None");
			return Ok(());
		}
		Some(m) => m.clone(),
	};

	if msgs.messages.is_empty() {
		println!("None");
		return Ok(());
	}

	let mut table = table!();

	table.set_titles(row![
		bMG->"Participant Id",
		bMG->"Message",
		bMG->"Public Key",
		bMG->"Signature",
	]);

	for m in msgs.messages {
		let id = format!("{}", m.id);
		let public_key = format!("{}", m.public_key.serialize_vec(secp, true)?.to_hex());
		let message = match m.message {
			Some(message) => escape_for_display(&message),
			None => "None".to_owned(),
		};
		let message_sig = match m.message_sig {
			Some(signature) => signature.serialize_raw(secp)?.to_hex(),
			None => "None".to_owned(),
		};
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->id,
				bFC->message,
				bFC->public_key,
				bFB->message_sig,
			]);
		} else {
			table.add_row(row![
				bFD->id,
				bFb->message,
				bFD->public_key,
				bFB->message_sig,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	Ok(())
}

/// Display list of wallet accounts in a pretty way
#[cfg(feature = "swaps")]
pub fn swap_trades(trades: Vec<(String, String)>) {
	println!("\n____ Swap trades ____\n",);
	let mut table = table!();

	table.set_titles(row![
		mMG->"Swap ID",
		bMG->"Status",
	]);
	for m in trades {
		table.add_row(row![
			bFC->m.0,
			bGC->m.1,
		]);
	}
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

/// Display list of wallet accounts in a pretty way
#[cfg(feature = "swaps")]
pub fn swap_trade(
	swap: &swap::Swap,
	action: &Action,
	time_limit: &Option<i64>,
	tx_conf: &SwapTransactionsConfirmations,
	roadmap: &Vec<StateEtaInfo>,
	journal_records: &Vec<SwapJournalRecord>,
	show_requied_action: bool,
) -> Result<(), Error> {
	println!("");
	println!("    Swap ID: {}", swap.id.to_string().bold().bright_white());
	if swap.is_seller() {
		println!(
			"    Selling {} MWC for {} {}",
			core::amount_to_hr_string(swap.primary_amount, true)
				.bold()
				.yellow(),
			swap.secondary_currency
				.amount_to_hr_string(swap.secondary_amount, true)
				.bold()
				.yellow(),
			swap.secondary_currency,
		);
	} else {
		println!(
			"    Buying {} MWC for {} {}",
			core::amount_to_hr_string(swap.primary_amount, true)
				.bold()
				.yellow(),
			swap.secondary_currency
				.amount_to_hr_string(swap.secondary_amount, true)
				.bold()
				.yellow(),
			swap.secondary_currency,
		);
	}

	println!(
		"    Required lock confirmations: {} for MWC and {} for {}",
		swap.mwc_confirmations.to_string().bold().yellow(),
		swap.secondary_confirmations.to_string().bold().yellow(),
		swap.secondary_currency
	);

	let s1 = format!("{} minutes", swap.message_exchange_time_sec / 60);
	let s2 = format!("{} minutes", swap.redeem_time_sec / 60);

	println!(
		"    Time limits: {} for messages to be exchanged and {} for redeem/refund",
		s1.bold().yellow(),
		s2.bold().yellow()
	);

	let lock_str = if swap.seller_lock_first {
		format!("{}", "Seller lock MWC first".yellow())
	} else {
		format!("Buyer lock {} first", swap.secondary_currency)
	};
	println!("    Locking order: {}", lock_str.bold().yellow());

	let lock_height = swap.refund_slate.slate.get_lock_height_check()?;
	if !tx_conf.mwc_observed {
		println!("    MWC lock status is currently unavailable");
	} else if tx_conf.mwc_tip < lock_height {
		// The surrounding branch proves lock_height > mwc_tip.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the branch checks mwc_tip < lock_height"
		)]
		let remaining_blocks = lock_height - tx_conf.mwc_tip;
		let mwc_lock_sec = remaining_blocks.checked_mul(60).ok_or_else(|| {
			Error::DataOverflow(format!(
					"display::swap_trade, MWC lock duration overflow, remaining_blocks={} seconds_per_block=60",
					remaining_blocks
				))
		})?;
		// Both time-unit divisors are fixed nonzero constants.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the hour and minute divisors are fixed nonzero constants"
		)]
		let sel_lock_h = mwc_lock_sec / 3600;
		let sel_lock_m = (mwc_lock_sec % 3600) / 60;
		let est_time_str = format!("{} hours and {} minutes", sel_lock_h, sel_lock_m);
		println!(
			"    MWC funds will be locked until block {}, and are expected to be mined in {}",
			swap.refund_slate
				.slate
				.get_lock_height()
				.to_string()
				.bold()
				.yellow(),
			est_time_str.bold().yellow(),
		);
	} else {
		println!("    MWC Lock expired");
	}

	let now_ts = Utc::now().timestamp();
	let btc_lock_time = swap.get_time_secondary_lock_publish()?;
	if now_ts < btc_lock_time {
		let buyer_lock_time = btc_lock_time.checked_sub(now_ts).ok_or_else(|| {
			Error::DataOverflow(format!(
				"display::swap_trade, secondary lock duration overflow, lock_time={} current_time={}",
				btc_lock_time, now_ts
			))
		})?;
		// Both time-unit divisors are fixed nonzero constants.
		#[allow(
			clippy::arithmetic_side_effects,
			reason = "the hour and minute divisors are fixed nonzero constants"
		)]
		let buy_lock_h = buyer_lock_time / 3600;
		let buy_lock_m = (buyer_lock_time % 3600) / 60;
		let est_time_str = format!("{} hours and {} minutes", buy_lock_h, buy_lock_m);
		println!(
			"    {} funds will be locked for {}",
			swap.secondary_currency,
			est_time_str.bold().yellow()
		);
	} else {
		println!("    {} Lock expired", swap.secondary_currency);
	}

	match &swap.role {
		Role::Seller(address, _) => {
			let safe_address =
				bounded_escape_for_display(address, MAX_SWAP_DISPLAY_FIELD_BYTES);
			if !swap.secondary_currency.is_btc_family()
				&& address == "0x0000000000000000000000000000000000000000"
			{
				println!(
					"    {} redeem address: {}",
					"Internal Eth Wallet Address",
					safe_address.bold().yellow()
				);
			} else {
				println!(
					"    {} redeem address: {}",
					swap.secondary_currency,
					safe_address.bold().yellow()
				);
			}
		}
		Role::Buyer(address) => match address {
			Some(address) => {
				let safe_address =
					bounded_escape_for_display(address, MAX_SWAP_DISPLAY_FIELD_BYTES);
				if !swap.secondary_currency.is_btc_family()
					&& address == "0x0000000000000000000000000000000000000000"
				{
					println!(
						"    {} refund address: {}",
						"Internal Eth Wallet Address",
						safe_address.bold().yellow()
					);
				} else {
					println!(
						"    {} refund address: {}",
						swap.secondary_currency,
						safe_address.bold().yellow()
					);
				}
			}
			None => {
				println!("    {} refund address: Not Set", swap.secondary_currency);
			}
		},
	}
	println!(
		"    Current {} transaction fee: {} {}",
		swap.secondary_currency,
		swap.secondary_fee_units.to_string().bold().yellow(),
		swap.secondary_currency.get_fee_units().0
	);

	println!("");
	let communication_method = bounded_escape_for_display(
		&swap.communication_method,
		MAX_SWAP_DISPLAY_FIELD_BYTES,
	);
	let communication_address = bounded_escape_for_display(
		&swap.communication_address,
		MAX_SWAP_DISPLAY_FIELD_BYTES,
	);
	if swap.is_seller() {
		println!(
			"    Buyer address: {}, {}",
			communication_method, communication_address
		);
	} else {
		println!(
			"    Seller address: {}, {}",
			communication_method, communication_address
		);
	}

	let expired_str = swap::left_from_time_limit(time_limit);
	let action_str = if expired_str.is_empty() {
		format!("{}", action)
	} else {
		format!("{}, {}", action, expired_str)
	};
	let action_str = bounded_escape_for_display(&action_str, MAX_SWAP_DISPLAY_MESSAGE_BYTES);

	// Status info
	println!("");
	println!("-------- Execution plan --------");
	for eta in roadmap {
		let eta_name = bounded_escape_for_display(&eta.name, MAX_SWAP_DISPLAY_FIELD_BYTES);
		if eta.active {
			print!("{}{:40}", "--> ".yellow(), eta_name.bold().yellow());
		} else {
			print!("{}{:40}", "    ", eta_name);
		}

		if let Some(t) = eta.start_time {
			print!("  started {}", timestamp_to_local_time(t));
		}
		if let Some(t) = eta.end_time {
			print!("  required by {}", timestamp_to_local_time(t));
		}
		println!("");
		if eta.active && !action.is_none() {
			// prining action below...
			println!("        {}", action_str.bold().cyan());
		}
	}

	println!("");
	println!("-------- Trade Journal --------");
	for j in journal_records {
		println!(
			"    {:20} {}",
			timestamp_to_local_time(j.time),
			bounded_escape_for_display(&j.message, MAX_SWAP_DISPLAY_MESSAGE_BYTES)
		);
	}

	if show_requied_action {
		if action.can_execute() {
			println!("");
			println!("-------- Required Action --------");
			println!("    {}", action_str.bold().cyan());
		}
	}
	println!("");

	Ok(())
}

#[cfg(feature = "swaps")]
fn timestamp_to_local_time(timestamp: i64) -> String {
	match Local.timestamp_opt(timestamp, 0).single() {
		Some(dt) => dt.format("%B %e %H:%M:%S").to_string(),
		None => format!("TS: {}", timestamp),
	}
}

/// Display summary eth info in a pretty way
#[cfg(feature = "swaps")]
pub fn eth_info(account: String, height: String, balance: String, currency: Currency) {
	println!(
		"\n____ Ethereum Wallet Summary Info - Account '{}' as of height {} ____\n",
		account, height,
	);

	let mut table = table!();

	table.add_row(row![
		bFG->format!("{} Balance", currency).as_str(),
		FG->balance
	]);

	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}
