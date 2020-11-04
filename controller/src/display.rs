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

use crate::core::core::{self, amount_to_hr_string};
use crate::core::global;
use crate::libwallet::swap::fsm::state::StateEtaInfo;
use crate::libwallet::swap::swap;
use crate::libwallet::swap::types::{Action, Role};
use crate::libwallet::{
	AcctPathMapping, Error, OutputCommitMapping, OutputStatus, TxLogEntry, WalletInfo,
};

use crate::util;
use chrono::prelude::*;
use chrono::Local;
use colored::*;
use grin_wallet_libwallet::swap::swap::SwapJournalRecord;
use grin_wallet_libwallet::swap::types::SwapTransactionsConfirmations;
use prettytable;

/// Display outputs in a pretty way
pub fn outputs(
	account: &str,
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
			account, cur_height
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
		let commit = format!("{}", util::to_hex(m.commit.as_ref().to_vec()));
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
pub fn txs(
	account: &str,
	cur_height: u64,
	validated: bool,
	txs: &Vec<TxLogEntry>,
	include_status: bool,
	dark_background_color_scheme: bool,
	show_full_info: bool,
	has_proof: impl Fn(&TxLogEntry) -> bool,
) -> Result<(), Error> {
	println!();
	println!(
		"{}",
		format!(
			"Transaction Log - Account '{}' - Block Height: {}",
			account, cur_height
		)
		.magenta()
	);

	let mut table = table!();

	if show_full_info {
		table.set_titles(row![
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
		]);
	} else {
		// 'short' format is used by mwc 713 wallet
		table.set_titles(row![
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
		]);
	}

	for t in txs {
		let id = format!("{}", t.id);
		let slate_id = match t.tx_slate_id {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};
		// mwc713 (short) representation of ID
		let short_slate_id = match t.tx_slate_id {
			Some(m) => util::to_hex(m.as_bytes()[..4].to_vec()),
			None => String::from(""),
		};

		let address = match &t.address {
			Some(addr) => addr,
			None => "",
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
			core::amount_to_hr_string(t.amount_credited - t.amount_debited, true)
		} else {
			format!(
				"-{}",
				core::amount_to_hr_string(t.amount_debited - t.amount_credited, true)
			)
		};
		let tx_data = match t.stored_tx {
			Some(_) => "Yes".to_owned(),
			None => "None".to_owned(),
		};
		let kernel_excess = match t.kernel_excess {
			Some(e) => util::to_hex(e.0.to_vec()),
			None => "None".to_owned(),
		};
		let payment_proof = if has_proof(t) {
			"Yes".to_owned()
		} else {
			"None".to_owned()
		};

		if show_full_info {
			if dark_background_color_scheme {
				table.add_row(row![
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
				]);
			} else {
				if t.confirmed {
					table.add_row(row![
						bFD->id,
						bFb->entry_type,
						bFD->slate_id,
						bFD->address,
						bFB->creation_ts,
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
					]);
				} else {
					table.add_row(row![
						bFD->id,
						bFb->entry_type,
						bFD->slate_id,
						bFD->address,
						bFB->creation_ts,
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
					]);
				}
			}
		} else {
			// Short supports only dark scheme, we really don't need more
			table.add_row(row![
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
			]);
		}
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
/// Display summary info in a pretty way
pub fn info(
	account: &str,
	wallet_info: &WalletInfo,
	validated: bool,
	dark_background_color_scheme: bool,
) {
	println!(
		"\n____ Wallet Summary Info - Account '{}' as of height {} ____\n",
		account, wallet_info.last_confirmed_height,
	);

	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Confirmed Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFY->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
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
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFB->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
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
			bGC->m.path.to_bip_32_string(),
		]);
	}
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

/// Display transaction log messages
pub fn tx_messages(tx: &TxLogEntry, dark_background_color_scheme: bool) -> Result<(), Error> {
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

	let secp = util::static_secp_instance();
	let secp_lock = secp.lock();

	for m in msgs.messages {
		let id = format!("{}", m.id);
		let public_key = format!(
			"{}",
			util::to_hex(m.public_key.serialize_vec(&secp_lock, true).to_vec())
		);
		let message = match m.message {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};
		let message_sig = match m.message_sig {
			Some(s) => format!("{}", util::to_hex(s.serialize_der(&secp_lock))),
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

/// Display individual Payment Proof
pub fn payment_proof(tx: &TxLogEntry) -> Result<(), Error> {
	println!();
	println!(
		"{}",
		format!("Payment Proof - Transaction '{}'", tx.id,).magenta()
	);

	let pp = match &tx.payment_proof {
		None => {
			println!("None");
			return Ok(());
		}
		Some(p) => p.clone(),
	};

	println!();
	let receiver_signature = match pp.receiver_signature {
		Some(s) => util::to_hex(s.as_bytes().to_vec()),
		None => "None".to_owned(),
	};
	let fee = match tx.fee {
		Some(f) => f,
		None => 0,
	};
	let amount = if tx.amount_credited >= tx.amount_debited {
		core::amount_to_hr_string(tx.amount_credited - tx.amount_debited, true)
	} else {
		format!(
			"{}",
			core::amount_to_hr_string(tx.amount_debited - tx.amount_credited - fee, true)
		)
	};

	let sender_signature = match pp.sender_signature {
		Some(s) => util::to_hex(s.as_bytes().to_vec()),
		None => "None".to_owned(),
	};
	let kernel_excess = match tx.kernel_excess {
		Some(e) => util::to_hex(e.0.to_vec()),
		None => "None".to_owned(),
	};

	println!("Receiver Address: {}", pp.receiver_address.public_key);
	println!("Receiver Signature: {}", receiver_signature);
	println!("Amount: {}", amount);
	println!("Kernel Excess: {}", kernel_excess);
	println!("Sender Address: {}", pp.sender_address.public_key);
	println!("Sender Signature: {}", sender_signature);

	println!();

	Ok(())
}

/// Display list of wallet accounts in a pretty way
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
		"    Requied lock confirmations: {} for MWC and {} for {}",
		swap.mwc_confirmations.to_string().bold().yellow(),
		swap.secondary_confirmations.to_string().bold().yellow(),
		swap.secondary_currency
	);

	let s1 = format!("{} minutes", swap.message_exchange_time_sec / 60);
	let s2 = format!("{} minutes", swap.redeem_time_sec / 60);

	println!(
		"    Time limits: {} for messages exchange and {} for redeem/refund",
		s1.bold().yellow(),
		s2.bold().yellow()
	);

	let lock_str = if swap.seller_lock_first {
		format!("{}", "Seller lock MWC first".yellow())
	} else {
		format!("Buyer lock {} first", swap.secondary_currency)
	};
	println!("    Locking order: {}", lock_str.bold().yellow());

	if tx_conf.mwc_tip < swap.refund_slate.lock_height {
		let mwc_lock_sec = (swap.refund_slate.lock_height - tx_conf.mwc_tip) * 60;
		let sel_lock_h = mwc_lock_sec / 3600;
		let sel_lock_m = (mwc_lock_sec % 3600) / 60;
		let est_time_str = format!("{} hours and {} minutes", sel_lock_h, sel_lock_m);
		println!(
			"    MWC funds locked until block {}, expected to be mined in {}",
			swap.refund_slate.lock_height.to_string().bold().yellow(),
			est_time_str.bold().yellow(),
		);
	} else {
		println!("    MWC Lock expired");
	}

	let now_ts = Utc::now().timestamp();
	let btc_lock_time = swap.get_time_btc_lock();
	if now_ts < btc_lock_time {
		let buyer_lock_time = btc_lock_time - now_ts;
		let buy_lock_h = buyer_lock_time / 3600;
		let buy_lock_m = (buyer_lock_time % 3600) / 60;
		let est_time_str = format!("{} hours and {} minutes", buy_lock_h, buy_lock_m);
		println!(
			"    {} funds locked for {}",
			swap.secondary_currency,
			est_time_str.bold().yellow()
		);
	} else {
		println!("    {} Lock expired", swap.secondary_currency);
	}

	match &swap.role {
		Role::Seller(address, _) => {
			println!(
				"    {} redeem address: {}",
				swap.secondary_currency,
				address.bold().yellow()
			);
		}
		Role::Buyer(address) => match address {
			Some(address) => {
				println!(
					"    {} refund address: {}",
					swap.secondary_currency,
					address.bold().yellow()
				);
			}
			None => {
				println!("    {} refund address: Not Set", swap.secondary_currency);
			}
		},
	}
	println!(
		"    Current {} transaction fee: {} {}",
		swap.secondary_currency,
		swap.secondary_fee.to_string().bold().yellow(),
		swap.secondary_currency.get_fee_units()
	);

	println!("");
	if swap.is_seller() {
		println!(
			"    Buyer address: {}, {}",
			swap.communication_method, swap.communication_address
		);
	} else {
		println!(
			"    Seller address: {}, {}",
			swap.communication_method, swap.communication_address
		);
	}

	let expired_str = swap::left_from_time_limit(time_limit);
	let action_str = if expired_str.is_empty() {
		format!("{}", action)
	} else {
		format!("{}, {}", action, expired_str)
	};

	// Status info
	println!("");
	println!("-------- Execution plan --------");
	for eta in roadmap {
		if eta.active {
			print!("{}{:40}", "--> ".yellow(), eta.name.bold().yellow());
		} else {
			print!("{}{:40}", "    ", eta.name);
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
		println!("    {:20} {}", timestamp_to_local_time(j.time), j.message);
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

fn timestamp_to_local_time(timestamp: i64) -> String {
	let dt = Local.timestamp(timestamp, 0);
	dt.format("%B %e %H:%M:%S").to_string()
}
