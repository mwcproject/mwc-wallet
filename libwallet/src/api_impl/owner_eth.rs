// Copyright 2021 The MWC Develope;
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

//! Generic implementation of owner API eth functions

use crate::grin_keychain::Keychain;
use crate::grin_util::Mutex;
use crate::types::NodeClient;
use crate::{wallet_lock, WalletInst, WalletLCProvider};
use grin_wallet_util::grin_core::global;
use std::sync::Arc;

use crate::swap::ethereum::InfuraNodeClient;
use crate::swap::ethereum::*;
use crate::swap::trades;
use crate::swap::types::Currency;
use crate::swap::Error;

/// Show Wallet Info
pub fn info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	currency: Currency,
) -> Result<(String, String, String), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let ethereum_wallet = w.get_ethereum_wallet()?;

	let eth_infura_project_id = trades::get_eth_infura_projectid(&Currency::Ether, &None).unwrap();
	let chain = if global::is_mainnet() {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	let eth_node_client = InfuraNodeClient::new(
		eth_infura_project_id,
		chain,
		ethereum_wallet.clone(),
		"".to_string(),
		"".to_string(),
	)?;
	let height = eth_node_client.height()?;
	let balance = eth_node_client.balance(currency)?;

	Ok((
		ethereum_wallet.address.clone().unwrap(),
		format!("{}", height),
		balance.0,
	))
}

/// get eth balance
pub fn get_eth_balance(ethereum_wallet: EthereumWallet) -> Result<u64, Error> {
	let eth_infura_project_id = trades::get_eth_infura_projectid(&Currency::Ether, &None).unwrap();
	let chain = if global::is_mainnet() {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	let eth_node_client = InfuraNodeClient::new(
		eth_infura_project_id,
		chain,
		ethereum_wallet.clone(),
		"".to_string(),
		"".to_string(),
	)?;

	let balance = eth_node_client.balance(Currency::Ether)?;

	Ok(balance.1)
}

/// transfer ethereum coins out
pub fn transfer<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	currency: Currency,
	dest: Option<String>,
	amount: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let ethereum_wallet = w.get_ethereum_wallet()?;

	let eth_infura_project_id = trades::get_eth_infura_projectid(&Currency::Ether, &None).unwrap();
	let chain = if global::is_mainnet() {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	let eth_node_client = InfuraNodeClient::new(
		eth_infura_project_id,
		chain,
		ethereum_wallet.clone(),
		"".to_string(),
		"".to_string(),
	)?;

	let to = to_eth_address(dest.unwrap())?;
	let amounts = to_gnorm(amount.unwrap().as_str(), "1");
	let amounts_u64 = amounts.parse::<u64>();
	info!(
		"currency: {}, to: {}, amounts: {}, amounts_u64: {}",
		currency,
		to,
		amounts,
		amounts_u64.clone().unwrap()
	);

	let result = eth_node_client.transfer(currency, to, amounts_u64.unwrap());
	match result {
		Ok(_tx_hash) => Ok(()),
		Err(e) => Err(e),
	}
}
