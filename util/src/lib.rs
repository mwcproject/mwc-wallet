// Copyright 2021 The Mwc Developers
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

//! Utilities and re-exports

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate serde_derive;

mod ov3;
mod tokio_runtime;

pub use ov3::OnionV3Address;
pub use ov3::OnionV3Error as OnionV3AddressError;
pub use tokio_runtime::RUNTIME;

pub use mwc_api;
pub use mwc_chain;
pub use mwc_core;
pub use mwc_keychain;
pub use mwc_p2p;
pub use mwc_store;
pub use mwc_util;
