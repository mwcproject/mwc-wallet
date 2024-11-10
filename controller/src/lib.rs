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

//! Library module for the main wallet functionalities provided by Mwc.

#[macro_use]
extern crate prettytable;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
use mwc_wallet_api as apiwallet;
use mwc_wallet_config as config;
use mwc_wallet_impls as impls;
use mwc_wallet_libwallet as libwallet;
use mwc_wallet_util::mwc_api as api;
use mwc_wallet_util::mwc_core as core;
use mwc_wallet_util::mwc_keychain as keychain;
use mwc_wallet_util::mwc_util as util;

pub mod command;
pub mod controller;
pub mod display;
mod error;
pub mod executor;

pub use crate::error::Error;
