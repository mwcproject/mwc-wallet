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

use failure::Fail;
use grin_util::secp;
use std::error::Error as StdError;

/// Multisig error
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// Reveal phase error
	#[fail(display = "Multisig Invalid reveal")]
	Reveal,
	/// Not expected hash length, expected is 32
	#[fail(display = "Multisig Invalid hash length")]
	HashLength,
	/// Participant already exists
	#[fail(display = "Multisig Participant already exists")]
	ParticipantExists,
	/// Expected participant doesn't exist
	#[fail(display = "Multisig Participant doesn't exist")]
	ParticipantDoesntExist,
	/// Participant created in the wrong order
	#[fail(display = "Multisig Participant created in the wrong order")]
	ParticipantOrdering,
	/// Participant invalid
	#[fail(display = "Multisig Participant invalid")]
	ParticipantInvalid,
	/// Multisig incomplete
	#[fail(display = "Multisig incomplete")]
	MultiSigIncomplete,
	/// Common nonce missing
	#[fail(display = "Multisig Common nonce missing")]
	CommonNonceMissing,
	/// Round 1 missing field
	#[fail(display = "Multisig Round 1 missing field")]
	Round1Missing,
	/// Round 2 missing field
	#[fail(display = "Multisig Round 2 missing field")]
	Round2Missing,
	/// Secp error
	#[fail(display = "Multisig Secp: {}", _0)]
	Secp(String),
}

// we have to use e.description  because of the bug at rust-secp256k1-zkp
#[allow(deprecated)]

impl From<secp::Error> for ErrorKind {
	fn from(error: secp::Error) -> ErrorKind {
		// secp::Error to_string is broken, in past biilds.
		ErrorKind::Secp(format!("{}", error.description()))
	}
}
