// Copyright 2026 The MWC Developers
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

//! Discover confirmed scriptSig variants of locally signed BTC-family transactions.

use super::client::BtcNodeClient;
use super::types::BtcTtansaction;
use crate::swap::Error;
use bitcoin::blockdata::script::Instruction;
use bitcoin::{Script, Transaction};
use mwc_wallet_util::mwc_bitcoin as bitcoin;

pub(super) struct RecoveredTransaction {
	pub attempt_index: usize,
	pub transaction: Transaction,
	pub confirmations: u64,
}

fn same_signed_fields(actual: &Transaction, saved: &Transaction) -> bool {
	actual.version == saved.version
		&& actual.lock_time == saved.lock_time
		&& actual.output == saved.output
		&& actual.input.len() == saved.input.len()
		&& actual.input.iter().zip(&saved.input).all(|(a, b)| {
			a.previous_output == b.previous_output
				&& a.sequence == b.sequence
				&& a.witness == b.witness
		})
}

/// Attempts must share their input set. Only scriptSig differences are allowed;
/// a refund, redemption, or unrelated spend cannot stand in for another payment.
/// All reads use the supplied backend and errors propagate to its caller's
/// complete-operation failover. Confirmation counts must still be checked at
/// the final tip of that operation.
pub(super) fn recover_confirmed_variant<'a, B: BtcNodeClient>(
	client: &mut B,
	attempts: impl Iterator<Item = &'a BtcTtansaction>,
	kind: &str,
) -> Result<Option<RecoveredTransaction>, Error> {
	let mut attempts = attempts.enumerate().peekable();
	let Some((_, first_attempt)) = attempts.peek() else {
		return Ok(None);
	};
	let saved: Transaction = bitcoin::consensus::deserialize(&first_attempt.tx)?;
	let first_input = saved
		.input
		.first()
		.ok_or_else(|| Error::Generic(format!("Saved {kind} transaction has no inputs")))?;
	// The final push is the P2SH redeem script, also for buyer-only refund carries.
	let script_pubkey = match first_input.script_sig.instructions().last().transpose()? {
		Some(Instruction::PushBytes(script)) => Script::from(script.to_vec()).to_p2sh(),
		_ => {
			return Err(Error::Generic(format!(
				"Saved {kind} input has no redeem script"
			)));
		}
	};
	let Some((transaction, confirmations)) =
		client.confirmed_spend(&first_input.previous_output, &script_pubkey)?
	else {
		return Ok(None);
	};
	if confirmations == 0 {
		return Ok(None);
	}
	for (attempt_index, attempt) in attempts {
		let expected: Transaction = bitcoin::consensus::deserialize(&attempt.tx)?;
		if same_signed_fields(&transaction, &expected) {
			return Ok(Some(RecoveredTransaction {
				attempt_index,
				transaction,
				confirmations,
			}));
		}
	}
	Err(Error::Generic(format!(
		"Input {} was spent by a confirmed transaction that does not match any saved {kind} attempt",
		first_input.previous_output
	)))
}
