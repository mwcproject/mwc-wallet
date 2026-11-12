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

use crate::types::NodeClient;
use crate::{WalletInst, WalletLCProvider, wallet_lock};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_core::global;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_keychain::Keychain;
use std::sync::Arc;

use crate::swap::Error;
use crate::swap::ethereum::InfuraNodeClient;
use crate::swap::ethereum::*;
use crate::swap::trades;
use crate::swap::types::Currency;
use mwc_wallet_util::mwc_crates::log::info;
use mwc_wallet_util::mwc_web3::types::{Address, H256};

fn ensure_ethereum_currency(currency: Currency) -> Result<(), Error> {
	if currency.is_ethereum_family() {
		Ok(())
	} else {
		Err(Error::UnexpectedCoinType)
	}
}

fn parse_transfer_amount(currency: Currency, amount: &str) -> Result<u64, Error> {
	ensure_ethereum_currency(currency)?;
	currency.amount_from_hr_string(amount)
}

fn parse_transfer_destination(dest: String) -> Result<Address, Error> {
	let address = to_eth_address(dest)?;
	if address == Address::zero() {
		return Err(Error::ZeroEthTransferAddress);
	}
	Ok(address)
}

/// Show Wallet Info
pub fn info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	currency: Currency,
) -> Result<(String, String, String), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	ensure_ethereum_currency(currency)?;
	let (ethereum_wallet, ethereum_address, context_id) = {
		wallet_lock!(wallet_inst, w);
		let ethereum_wallet = w.get_ethereum_wallet(keychain_mask)?;
		let ethereum_address = ethereum_wallet.address.clone().ok_or(Error::Generic(
			"Eth internal error, ethereum_wallet.address is empty".into(),
		))?;
		(ethereum_wallet, ethereum_address, w.get_context_id())
	};
	let eth_infura_project_id =
		trades::get_eth_infura_projectid(context_id, &Currency::Ether, &None)?;
	let chain = if global::is_mainnet(context_id) {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	let eth_node_client =
		InfuraNodeClient::new_account(eth_infura_project_id, chain, ethereum_wallet)?;
	let height = eth_node_client.height()?;
	let balance = eth_node_client.balance(currency)?;

	Ok((ethereum_address, format!("{}", height), balance.0))
}

/// get eth balance
pub fn get_eth_balance(context_id: u32, ethereum_wallet: EthereumWallet) -> Result<u64, Error> {
	let eth_infura_project_id =
		trades::get_eth_infura_projectid(context_id, &Currency::Ether, &None)?;
	let chain = if global::is_mainnet(context_id) {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	let eth_node_client =
		InfuraNodeClient::new_account(eth_infura_project_id, chain, ethereum_wallet)?;

	let balance = eth_node_client.balance(Currency::Ether)?;

	Ok(balance.1)
}

fn account_transfer_client<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<InfuraNodeClient, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secp = mwc_wallet_util::mwc_crates::secp::Secp256k1::with_caps(
		mwc_wallet_util::mwc_crates::secp::ContextFlag::Commit,
	)?;
	let (ethereum_wallet, context_id, storage_key) = {
		wallet_lock!(wallet_inst, w);
		let keychain = w.keychain(&secp, keychain_mask)?;
		let storage_key = super::owner_swap::get_swap_storage_key(&secp, &keychain)?;
		(
			w.get_ethereum_wallet(keychain_mask)?,
			w.get_context_id(),
			storage_key,
		)
	};
	// Release the wallet lock before scanning individually locked swap records.
	trades::restore_ethereum_resources(context_id, None, &storage_key)?;

	let eth_infura_project_id =
		trades::get_eth_infura_projectid(context_id, &Currency::Ether, &None)?;
	let chain = if global::is_mainnet(context_id) {
		"mainnet".to_string()
	} else {
		"ropsten".to_string()
	};
	InfuraNodeClient::new_account(eth_infura_project_id, chain, ethereum_wallet)
}

/// transfer ethereum coins out
pub fn transfer<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	currency: Currency,
	dest: String,
	amount: &String,
) -> Result<H256, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	ensure_ethereum_currency(currency)?;
	let to = parse_transfer_destination(dest)?;
	let amount_units = parse_transfer_amount(currency, amount)?;
	let eth_node_client = account_transfer_client(wallet_inst, keychain_mask)?;

	info!(
		"currency: {}, to: {}, amount: {}, amount_units: {}",
		currency, to, amount, amount_units,
	);

	eth_node_client.transfer(currency, to, amount_units)
}

/// Retry a direct transfer retained by this process, identified by any of its
/// transaction hashes. None keeps its existing fee budget; Some supplies gwei.
pub fn retry_transfer<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	tx_hash: H256,
	gas_budget_gwei: Option<u64>,
) -> Result<H256, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	account_transfer_client(wallet_inst, keychain_mask)?.retry_transfer(tx_hash, gas_budget_gwei)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn transfer_amount_uses_currency_exponent_and_rejects_zero() {
		assert_eq!(
			parse_transfer_amount(Currency::Ether, "1").unwrap(),
			1_000_000_000
		);
		assert_eq!(
			parse_transfer_amount(Currency::Wbtc, "1").unwrap(),
			100_000_000
		);
		assert_eq!(
			parse_transfer_amount(Currency::Usdt, "1").unwrap(),
			1_000_000
		);
		assert_eq!(
			parse_transfer_amount(Currency::Usdc, "0.000001").unwrap(),
			1
		);
		assert_eq!(
			parse_transfer_amount(Currency::Trx, "1").unwrap(),
			1_000_000
		);
		assert!(parse_transfer_amount(Currency::Usdt, "0.0000001").is_err());
		assert!(parse_transfer_amount(Currency::Usdt, "0").is_err());
	}

	#[test]
	fn transfer_amount_rejects_non_ethereum_currency() {
		for currency in [
			Currency::Btc,
			Currency::Bch,
			Currency::Ltc,
			Currency::Dash,
			Currency::ZCash,
			Currency::Doge,
		] {
			assert!(matches!(
				parse_transfer_amount(currency, "1"),
				Err(Error::UnexpectedCoinType)
			));
		}
	}

	#[test]
	fn transfer_destination_rejects_zero_address() {
		assert!(matches!(
			parse_transfer_destination("0x0000000000000000000000000000000000000000".to_string()),
			Err(Error::ZeroEthTransferAddress)
		));
		assert_eq!(
			parse_transfer_destination("0x0000000000000000000000000000000000000001".to_string())
				.unwrap(),
			Address::from_low_u64_be(1)
		);
	}
}
