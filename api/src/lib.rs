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

//! Higher level wallet functions which can be used by callers to operate
//! on the wallet, as well as helpers to invoke and instantiate wallets
//! and listeners

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

mod foreign;
mod foreign_rpc;

mod owner;
mod owner_rpc_v2;
mod owner_rpc_v3;

mod types;

pub use crate::foreign::{Foreign, ForeignCheckMiddleware, ForeignCheckMiddlewareFn};
pub use crate::foreign_rpc::ForeignRpc;
pub use crate::owner::Owner;
pub use crate::owner_rpc_v2::OwnerRpcV2;
pub use crate::owner_rpc_v3::OwnerRpcV3;

pub use crate::foreign_rpc::run_doctest_foreign;
pub use crate::owner_rpc_v2::run_doctest_owner;

pub use types::{
	ECDHPubkey, EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, JsonId, PubAddress,
	Token, TxLogEntryAPI,
};
