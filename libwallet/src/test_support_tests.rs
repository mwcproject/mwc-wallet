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

use crate::Context;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::Identifier;

fn new_context() -> Context {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	Context::new(
		&secp,
		&Identifier::zero(),
		#[cfg(feature = "test-support")]
		false,
		#[cfg(feature = "test-support")]
		true,
		0,
		1,
		1,
		None,
		0,
		0,
		None,
		true,
	)
	.unwrap()
}

#[cfg(feature = "test-support")]
fn new_deterministic_context() -> Context {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	Context::new(
		&secp,
		&Identifier::zero(),
		true,
		true,
		0,
		1,
		1,
		None,
		0,
		0,
		None,
		true,
	)
	.unwrap()
}

#[test]
fn secure_context_generation_is_the_default() {
	let first = new_context();
	let second = new_context();

	assert_ne!(first.sec_key, second.sec_key);
	assert_ne!(first.sec_nonce, second.sec_nonce);
}

#[cfg(feature = "test-support")]
#[test]
fn deterministic_context_obeys_test_support_boundary() {
	let first = new_deterministic_context();
	let second = new_deterministic_context();
	let mut expected_key = [0u8; 32];
	for (chunk, value) in expected_key.chunks_exact_mut(8).zip(1_234_567_890_u64..) {
		chunk.copy_from_slice(&value.to_le_bytes());
	}

	assert_eq!(first.sec_key, second.sec_key);
	assert_eq!(first.sec_key.0, expected_key);
	assert_eq!(first.sec_nonce.0, [1; 32]);
}

#[cfg(not(feature = "test-support"))]
#[test]
fn deterministic_context_obeys_test_support_boundary() {
	panic!("test-support feature is required to run the tests");
}

#[cfg(not(feature = "test-support"))]
#[test]
fn deterministic_stream_requires_test_support() {
	panic!("test-support feature is required to run the tests");
}
