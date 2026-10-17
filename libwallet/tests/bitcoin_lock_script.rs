// Copyright 2026 The Mwc Developers
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

#![cfg(all(feature = "swaps", feature = "test-support"))]

use mwc_wallet_libwallet::swap::{bitcoin::BtcData, swap};
use mwc_wallet_util::mwc_bitcoin::blockdata::{
	opcodes::all::{OP_CLTV, OP_IF},
	script::Instruction,
};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1, key::PublicKey};
use mwc_wallet_util::mwc_util::from_hex;

// This integration-test binary isolates its future clock from other swap tests.
struct ResetClock;

impl Drop for ResetClock {
	fn drop(&mut self) {
		swap::reset_testing_cur_time();
	}
}

#[test]
fn refund_lock_script_encodes_positive_timestamps_across_2038() {
	let _reset_clock = ResetClock;
	swap::set_testing_cur_time(2_147_483_000);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let public_key =
		|hex: &str| PublicKey::from_slice(&secp, &from_hex(hex.into()).unwrap()).unwrap();
	let data = BtcData {
		cosign: public_key("02b4e59070d367a364a31981a71fc5ab6c5034d0e279eecec19287f3c95db84aef"),
		refund: Some(public_key(
			"022fd8c0455bede249ad3b9a9fb8159829e8cfb2c360863896e5309ea133d122f2",
		)),
		refund_tx: None,
		refund_transaction: None,
		refund_plan: None,
		redeem_tx: None,
		redeem_tx_candidates: Vec::new(),
		redeem_attempts: Vec::new(),
		redeem_inputs: None,
		tx_fee_units: None,
	};
	let redeem = public_key("03cf15041579b5fb7accbac2997fb2f3e1001e9a522a19c83ceabe5ae51a596c7c");

	// BIP 65 permits five-byte Script numbers for CLTV. A trailing zero keeps
	// the sign positive when the timestamp's highest bit becomes set.
	let cases: &[(u64, &[u8])] = &[
		(2_147_483_647, &[0xff, 0xff, 0xff, 0x7f]),
		(2_147_483_648, &[0x00, 0x00, 0x00, 0x80, 0x00]),
		(2_147_483_649, &[0x01, 0x00, 0x00, 0x80, 0x00]),
	];
	for &(deadline, expected) in cases {
		let script = data.script(&redeem, deadline, &secp).unwrap();
		let mut instructions = script.instructions_minimal();
		assert_eq!(
			instructions.next().unwrap().unwrap(),
			Instruction::Op(OP_IF)
		);
		assert_eq!(
			instructions.next().unwrap().unwrap(),
			Instruction::PushBytes(expected),
			"refund deadline {deadline} must use positive Script-number encoding"
		);
		assert_eq!(
			instructions.next().unwrap().unwrap(),
			Instruction::Op(OP_CLTV)
		);
	}
}
