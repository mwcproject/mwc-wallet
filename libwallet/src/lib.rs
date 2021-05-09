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

//! Higher level wallet functions which can be used by callers to operate
//! on the wallet, as well as helpers to invoke and instantiate wallets
//! and listeners

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

use grin_wallet_config as config;
use grin_wallet_util::grin_api;
use grin_wallet_util::grin_core;
use grin_wallet_util::grin_keychain;
use grin_wallet_util::grin_p2p;
use grin_wallet_util::grin_store;
use grin_wallet_util::grin_util;

use grin_wallet_util as util;

use blake2_rfc as blake2;

use failure;
extern crate failure_derive;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

extern crate strum;
#[macro_use]
extern crate strum_macros;

extern crate hex;
extern crate signature;

extern crate crc;

pub mod address;
pub mod api_impl;
/// Ring prev version internals that are needed for our internal encription functionality
mod error;
pub mod internal;
pub mod proof;
mod slate;
pub mod slate_versions;
pub mod slatepack;
/// Atomic Swap library
pub mod swap;
mod types;
extern crate bitcoin as bitcoin_lib;
extern crate bitcoin_hashes;
extern crate zcash_primitives as zcash;

pub use crate::slatepack::{SlatePurpose, Slatepack, SlatepackArmor, Slatepacker};

pub use bitcoin::Address as BitcoinAddress;

pub use crate::error::{Error, ErrorKind};
pub use crate::slate::{ParticipantData, ParticipantMessageData, ParticipantMessages, Slate};
pub use crate::slate_versions::{
	SlateVersion, VersionedCoinbase, VersionedSlate, CURRENT_SLATE_VERSION,
	GRIN_BLOCK_HEADER_VERSION,
};
pub use api_impl::foreign;
pub use api_impl::owner;
pub use api_impl::owner_eth;
pub use api_impl::owner_libp2p;
pub use api_impl::owner_swap;
pub use api_impl::owner_updater::StatusMessage;
pub use api_impl::types::{
	BlockFees, InitTxArgs, InitTxSendArgs, IssueInvoiceTxArgs, NodeHeightResult,
	OutputCommitMapping, PaymentProof, ReplayMitigationConfig, SendTXArgs, SwapStartArgs,
	VersionInfo,
};
pub use internal::scan::{scan, set_replay_config};
pub use proof::tx_proof::TxProof;
pub use proof::tx_proof::{proof_ok, verify_tx_proof_wrapper};
pub use slate_versions::ser as dalek_ser;
pub use types::{
	AcctPathMapping, BlockIdentifier, CbData, Context, HeaderInfo, NodeClient, NodeVersionInfo,
	OutputData, OutputStatus, ScannedBlockInfo, StoredProofInfo, TxLogEntry, TxLogEntryType,
	WalletBackend, WalletInfo, WalletInst, WalletLCProvider, WalletOutputBatch,
};

pub use api_impl::foreign::{get_receive_account, set_receive_account};

pub use api_impl::owner_libp2p::IntegrityContext;

/// Helper for taking a lock on the wallet instance
#[macro_export]
macro_rules! wallet_lock {
	($wallet_inst: expr, $wallet: ident) => {
		let inst = $wallet_inst.clone();
		let mut w_lock = inst.lock();
		let w_provider = w_lock.lc_provider()?;
		let $wallet = w_provider.wallet_inst()?;
	};
}
