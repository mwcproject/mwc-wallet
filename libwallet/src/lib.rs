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
#![warn(missing_docs)]

pub mod address;
pub mod api_impl;
/// Ring prev version internals that are needed for our internal encription functionality
mod error;
mod error_serde;
pub mod internal;
pub mod proof;
pub mod reply_cache;
mod slate;
pub mod slate_process;
pub mod slate_versions;
pub mod slatepack;
pub mod status;
/// Atomic Swap library
#[cfg(feature = "swaps")]
pub mod swap;
pub mod transaction_preflight;
pub mod types;

#[cfg(test)]
mod test_support_tests;

/// Legacy deterministic RNG implementation used by wallet tests.
#[cfg(feature = "test-support")]
pub mod step_rng;

pub use crate::slatepack::{SlatePurpose, Slatepack, SlatepackArmor, Slatepacker};

pub use crate::error::Error;
pub use crate::slate::{
	ParticipantData, ParticipantMessageData, ParticipantMessages, Slate, SlateCtx,
	MAX_PARTICIPANT_MESSAGE_LEN, MAX_SEND_PARTICIPANTS,
};
pub use crate::slate_versions::{
	SlateVersion, VersionedSlate, CURRENT_SLATE_VERSION,
	MWC_BLOCK_HEADER_VERSION,
};
pub use crate::status::{StatusCallback, StatusMessage};
pub use api_impl::foreign;
pub use api_impl::owner;
pub use api_impl::types::{
	Amount, BlockFees, BuiltOutput, InitTxArgs, InitTxSendArgs, IssueInvoiceTxArgs, LateLockArgs,
	NodeHeightResult, OutputCommitMapping, OwnershipProof, OwnershipProofValidation,
	PubKeySignature, ReplayMitigationConfig, RetrieveTxQueryArgs, RetrieveTxQuerySortField,
	RetrieveTxQuerySortOrder, SecondaryFeeUnits, SendTXArgs, SwapStartArgs,
	VersionInfo,
};
#[cfg(feature = "swaps")]
pub use api_impl::{owner_eth, owner_swap};
#[cfg(feature = "test-support")]
pub use internal::scan::set_replay_height_gap_for_tests;
pub use internal::scan::set_replay_config;
pub use proof::tx_proof::TxProof;
pub use proof::tx_proof::{proof_ok, verify_tx_proof_wrapper};
pub use slate_versions::ser;
pub use types::{
	AcctPathMapping, BlockIdentifier, CbData, ChainTip, Context, HeaderInfo, NodeClient,
	NodeConnectionId, NodeHeaderLink, NodeOutputDetails, NodeVersionInfo, OutputData, OutputStatus,
	ScannedBlockInfo, StoredTxLocator, TxLogEntry, TxLogEntryType, ViewWallet, WalletBackend,
	WalletInfo, WalletInst, WalletLCProvider, WalletOutputBatch,
};

pub use api_impl::foreign::{get_receive_account, set_receive_account};

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

/// Helper for taking a lock on the wallet instance for tests. Using unwrap instead of error reporting
#[macro_export]
macro_rules! wallet_lock_test {
	($wallet_inst: expr, $wallet: ident) => {
		let inst = $wallet_inst.clone();
		let mut w_lock = inst.lock();
		let w_provider = w_lock.lc_provider().unwrap();
		let $wallet = w_provider.wallet_inst().unwrap();
	};
}
