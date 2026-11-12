// Copyright 2021 The MWC Developers
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

mod api;
mod client;
mod decimal_convert;
mod erc20_contract;
mod erc20_swap_contract;
mod ethereum;
pub(crate) mod funding;
mod infura;
pub(crate) mod recovery;
mod secret_key;
mod swap_contract;
mod types;

#[cfg(all(test, feature = "test-support"))]
mod redirect_tests;

pub use api::EthSwapApi;
pub use client::*;
pub use decimal_convert::{to_gnorm, to_norm};
pub use erc20_contract::ERC20_TOKEN_CONTRACT;
pub use erc20_swap_contract::ERC20_SWAP_CONTRACT;
pub use ethereum::*;
pub use infura::InfuraNodeClient;
pub use swap_contract::ETH_SWAP_CONTRACT;
pub use types::{
	eth_address, to_eth_address, to_eth_tx_hash, DepositRecoveryMode, Erc20AllowanceKey,
	Erc20ApprovalKind, Erc20ApprovalRecovery, Erc20Funding, Erc20FundingPhase, EthBuyerContext,
	EthData, EthRedeemRecovery, EthSellerContext, EthTransactionRecovery, EthUpdate,
};

/// Scheduling allowance for finality on new Ethereum-family swap offers.
/// The existing deadline formula adds its normal 10% margin. Acceptance always
/// checks finalized chain state and never infers finality from elapsed time.
pub(crate) const ETH_FINALITY_PLANNING_SLOTS: u64 = 75; // 15 minutes at 12 seconds per slot.
