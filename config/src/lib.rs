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

//! Crate wrapping up the Mwc binary and configuration file

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate serde_derive;

use mwc_wallet_util::mwc_core as core;
use mwc_wallet_util::mwc_util as util;

mod comments;
pub mod config;
#[allow(missing_docs)]
pub mod types;

pub use crate::config::{
	config_file_exists, initial_setup_wallet, MWC_WALLET_DIR, WALLET_CONFIG_FILE_NAME,
};
pub use crate::types::{
	parse_node_address_string, ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers,
	MQSConfig, TorConfig, WalletConfig,
};
