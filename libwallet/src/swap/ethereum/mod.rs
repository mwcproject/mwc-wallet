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

pub use mwc_wagyu_ethereum::{
	wordlist::*, EthereumAddress, EthereumAmount, EthereumDerivationPath,
	EthereumExtendedPrivateKey, EthereumExtendedPublicKey, EthereumFormat, EthereumMnemonic,
	EthereumNetwork, EthereumPrivateKey, EthereumPublicKey, EthereumTransaction,
	EthereumTransactionParameters, Goerli, Kovan, Mainnet, Rinkeby, Ropsten,
};

mod api;
mod client;
mod decimal_convert;
mod erc20_contract;
mod erc20_swap_contract;
mod ethereum;
mod infura;
mod swap_contract;
mod types;

pub use api::EthSwapApi;
pub use client::*;
pub use decimal_convert::{to_gnorm, to_norm};
pub use erc20_contract::ERC20_TOKEN_CONTRACT;
pub use erc20_swap_contract::ERC20_SWAP_CONTRACT;
pub use ethereum::*;
pub use infura::InfuraNodeClient;
pub use swap_contract::ETH_SWAP_CONTRACT;
pub use types::{
	eth_address, to_eth_address, to_eth_tx_hash, EthBuyerContext, EthData, EthSellerContext,
	EthUpdate,
};
