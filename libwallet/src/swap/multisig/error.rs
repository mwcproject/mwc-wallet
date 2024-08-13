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

use crate::grin_util::secp;

/// Multisig error
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// Reveal phase error
	#[error("Multisig Invalid reveal")]
	Reveal,
	/// Not expected hash length, expected is 32
	#[error("Multisig Invalid hash length")]
	HashLength,
	/// Participant already exists
	#[error("Multisig Participant already exists")]
	ParticipantExists,
	/// Expected participant doesn't exist
	#[error("Multisig Participant doesn't exist")]
	ParticipantDoesntExist,
	/// Participant created in the wrong order
	#[error("Multisig Participant created in the wrong order")]
	ParticipantOrdering,
	/// Participant invalid
	#[error("Multisig Participant invalid")]
	ParticipantInvalid,
	/// Multisig incomplete
	#[error("Multisig incomplete")]
	MultiSigIncomplete,
	/// Common nonce missing
	#[error("Multisig Common nonce missing")]
	CommonNonceMissing,
	/// Round 1 missing field
	#[error("Multisig Round 1 missing field")]
	Round1Missing,
	/// Round 2 missing field
	#[error("Multisig Round 2 missing field")]
	Round2Missing,
	/// Secp error
	#[error("Multisig Secp: {0}")]
	Secp(#[from] secp::Error),
}
