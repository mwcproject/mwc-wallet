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

extern crate ether_converter;

use super::client::*;
use super::*;
use crate::grin_util::from_hex;
#[cfg(test)]
use crate::swap::is_test_mode;
#[cfg(test)]
use crate::swap::set_test_mode;
use crate::swap::types::Currency;
use crate::swap::ErrorKind;
use crossbeam_utils::thread::scope;
use rand::thread_rng;
use secp256k1::SecretKey;
#[cfg(test)]
use std::sync::RwLock;
use std::u64;
use tokio::runtime::Builder;
use web3::{
	api::{Accounts, Namespace},
	contract::{Contract, Options},
	signing,
	signing::SecretKeyRef,
	types::{Address, Bytes, SignedData, TransactionParameters, TransactionReceipt, H256, U256},
};

// const TRANSACTION_DEFAULT_GAS_PRICE: u64 = 2_000_000_000u64;
const TRANSACTION_DEFAULT_GAS: u64 = 5_500_000_u64;
const TRANSACTION_DEFAULT_GAS_LIMIT: u64 = 11_000_000_000_000_000_u64;

#[cfg(test)]
lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref REDEEM_WALLET:   RwLock<Option<EthereumWallet>>  = RwLock::new(None);
}

macro_rules! web3_handle {
	($chain: expr, $projectid: expr) => {{
		let url = format!("wss://{}.infura.io/ws/v3/{}", $chain, $projectid);
		let transport = web3::transports::WebSocket::new(url.as_str())
			.await
			.unwrap();
		web3::Web3::new(transport)
		}};
}

/// Infura Ethereum node client
pub struct InfuraNodeClient {
	/// Infura URI
	pub project_id: String,
	/// Chain
	pub chain: String,
	/// Wallet Inst
	pub wallet: EthereumWallet,
	/// Contract Address
	pub contract_addr: String,
}

impl InfuraNodeClient {
	/// Create a new instance.
	pub fn new(
		project_id: String,
		chain: String,
		wallet: EthereumWallet,
		contract_addr: String,
	) -> Result<Self, ErrorKind> {
		let client = Self {
			project_id,
			chain,
			wallet,
			contract_addr,
		};

		Ok(client)
	}
}

impl EthNodeClient for InfuraNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		"Infura Node".to_string()
	}

	/// Fetch the current chain height
	fn height(&self) -> Result<u64, ErrorKind> {
		let task = async move {
			let web3 = web3_handle!(self.chain, self.project_id);
			web3.eth().block_number().await.unwrap().as_u64()
		};

		let block_number = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		})
		.unwrap();

		Ok(block_number)
	}

	/// get wallet balance
	fn balance(&self, _currency: Currency) -> Result<(String, u64), ErrorKind> {
		let task = async move {
			let account = to_eth_address(self.wallet.address.clone().unwrap()).unwrap();
			let web3 = web3_handle!(self.chain, self.project_id);
			web3.eth().balance(account, None).await.unwrap().as_u64()
		};

		let balance_wei = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		})
		.unwrap();

		let balance = ether_converter::to_ether(balance_wei.to_string().as_str(), "wei");
		Ok((format!("{}", balance.with_scale(4)), balance_wei))
	}

	/// Retrieve transaction receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, ErrorKind> {
		let task = async move {
			let web3 = web3_handle!(self.chain, self.project_id);
			web3.eth().transaction_receipt(tx_hash).await.unwrap()
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res {
			Ok(receipt) => match receipt {
				Some(res) => Ok(res),
				_ => Err(ErrorKind::EthRetrieveTransReciptError),
			},
			_ => Err(ErrorKind::EthRetrieveTransReciptError),
		}
	}

	/// Send coins
	fn transfer(&self, to: Address, value: u64) -> Result<H256, ErrorKind> {
		// check if balance enough to transfer
		let balance = self.balance(Currency::Ether)?;
		if balance.1 < value + TRANSACTION_DEFAULT_GAS_LIMIT {
			return Err(ErrorKind::EthBalanceNotEnough);
		}
		let task = async move {
			// get web3 handle
			let web3 = web3_handle!(self.chain, self.project_id);
			let key = secp256k1::SecretKey::from_slice(
				&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
			)
			.unwrap();
			let accounts_sign = Accounts::new(web3.eth().transport().clone());
			let nonce = web3
				.eth()
				.transaction_count(
					to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
					None,
				)
				.await
				.unwrap();
			let gas_price = web3.eth().gas_price().await.unwrap();
			let tx = TransactionParameters {
				nonce: Some(nonce),
				to: Some(to),
				gas: U256::from(TRANSACTION_DEFAULT_GAS),
				gas_price: Some(gas_price),
				value: U256::from(value),
				data: Bytes::default(),
				chain_id: None,
			};
			let signed = accounts_sign.sign_transaction(tx, &key).await.unwrap();
			web3.eth()
				.send_raw_transaction(signed.raw_transaction)
				.await
				.unwrap()
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res {
			Ok(hash) => Ok(hash),
			_ => Err(ErrorKind::EthContractCallError),
		}
	}

	/// initiate swap offer
	fn initiate(
		&self,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
	) -> Result<H256, ErrorKind> {
		let balance = self.balance(Currency::Ether).unwrap();
		if balance.1 < value + TRANSACTION_DEFAULT_GAS_LIMIT {
			return Err(ErrorKind::EthBalanceNotEnough);
		}
		let task = async move {
			// get web3 handle
			let web3 = web3_handle!(self.chain, self.project_id);
			// Accessing existing contract
			let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
			let contract =
				Contract::from_json(web3.eth(), contract_address, ETH_SWAP_CONTRACT.as_bytes())
					.unwrap();

			let latest = web3.eth().block_number().await.unwrap();
			let refund_block = latest.as_u64() + refund_time;
			// let nonce = web3
			// 	.eth()
			// 	.transaction_count(
			// 		to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
			// 		Some(BlockNumber::Pending),
			// 	)
			// 	.await
			// 	.unwrap();
			// options.nonce = Some(nonce + 100);

			let gas_price = web3.eth().gas_price().await.unwrap();
			let mut options = Options::default();
			options.value = Some(U256::from(value));
			options.gas_price = Some(gas_price);
			options.gas = Some(U256::from(TRANSACTION_DEFAULT_GAS));

			let key = secp256k1::SecretKey::from_slice(
				&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
			)
			.unwrap();
			contract
				.signed_call_with_confirmations(
					"initiate",
					(refund_block, address_from_secret, participant),
					options,
					2,
					SecretKeyRef::new(&key),
				)
				.await
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res.unwrap() {
			Ok(receipt) => Ok(receipt.transaction_hash),
			Err(e) => {
				warn!("initiate error: --- {:?}", e);
				Err(ErrorKind::EthContractCallError)
			}
		}
	}

	/// ether buyer redeem
	fn redeem(
		&self,
		address_from_secret: Address,
		secret_key: SecretKey,
	) -> Result<H256, ErrorKind> {
		let balance = self.balance(Currency::Ether).unwrap();
		if balance.1 < TRANSACTION_DEFAULT_GAS_LIMIT {
			return Err(ErrorKind::EthBalanceNotEnough);
		}
		let task = async move {
			// get web3 handle
			let web3 = web3_handle!(self.chain, self.project_id);
			// Accessing existing contract
			let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
			let contract =
				Contract::from_json(web3.eth(), contract_address, ETH_SWAP_CONTRACT.as_bytes())
					.unwrap();

			let swap_details: (u64, Address, Address, u64) = contract
				.query(
					"getSwapDetails",
					address_from_secret,
					None,
					Options::default(),
					None,
				)
				.await
				.unwrap();
			// let nonce = web3
			// 	.eth()
			// 	.transaction_count(
			// 		to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
			// 		None,
			// 	)
			// 	.await
			// 	.unwrap();
			let gas_price = web3.eth().gas_price().await.unwrap();
			let mut options = Options::default();
			// options.nonce = Some(nonce);
			// options.value = None;
			options.gas_price = Some(gas_price);
			options.gas = Some(U256::from(TRANSACTION_DEFAULT_GAS));

			//keccak256
			let address_bytes = [
				address_from_secret.as_bytes(),
				swap_details.2.as_bytes(),
				swap_details.1.as_bytes(),
				&[0u8; 24],
				&swap_details.0.to_be_bytes(),
			]
			.concat();
			let accounts_sign = Accounts::new(web3.eth().transport().clone());
			let hashed_message = signing::keccak256(&address_bytes);
			let signed_data: SignedData = accounts_sign.sign(hashed_message, &secret_key);

			//call redeem function
			let mut key = secp256k1::SecretKey::new(&mut thread_rng());
			key = secp256k1::SecretKey::from_slice(
				&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
			)
			.unwrap();

			#[cfg(test)]
			{
				let test_mode = is_test_mode();
				if test_mode {
					key = secp256k1::SecretKey::from_slice(
						&from_hex(
							REDEEM_WALLET
								.read()
								.unwrap()
								.clone()
								.unwrap()
								.private_key
								.unwrap()
								.as_str(),
						)
						.unwrap(),
					)
					.unwrap();
				}
			}

			contract
				.signed_call_with_confirmations(
					"redeem",
					(
						address_from_secret,
						signed_data.r,
						signed_data.s,
						signed_data.v,
					),
					options,
					2,
					SecretKeyRef::new(&key),
				)
				.await
				.unwrap()
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res {
			Ok(receipt) => Ok(receipt.transaction_hash),
			Err(e) => {
				warn!("redeem error: --- {:?}", e);
				Err(ErrorKind::EthContractCallError)
			}
		}
	}

	/// refund ether
	fn refund(&self, address_from_secret: Address) -> Result<H256, ErrorKind> {
		let balance = self.balance(Currency::Ether).unwrap();
		if balance.1 < TRANSACTION_DEFAULT_GAS_LIMIT {
			return Err(ErrorKind::EthBalanceNotEnough);
		}
		let task = async move {
			// get web3 handle
			let web3 = web3_handle!(self.chain, self.project_id);
			// Accessing existing contract
			let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
			let contract =
				Contract::from_json(web3.eth(), contract_address, ETH_SWAP_CONTRACT.as_bytes())
					.unwrap();

			// let nonce = web3
			// 	.eth()
			// 	.transaction_count(
			// 		to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
			// 		None,
			// 	)
			// 	.await
			// 	.unwrap();
			let gas_price = web3.eth().gas_price().await.unwrap();
			let mut options = Options::default();
			// options.nonce = Some(nonce);
			// options.value = None;
			options.gas_price = Some(gas_price);
			options.gas = Some(U256::from(TRANSACTION_DEFAULT_GAS));

			let key = secp256k1::SecretKey::from_slice(
				&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
			)
			.unwrap();
			contract
				.signed_call_with_confirmations(
					"refund",
					address_from_secret,
					options,
					2,
					SecretKeyRef::new(&key),
				)
				.await
				.unwrap()
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res {
			Ok(receipt) => Ok(receipt.transaction_hash),
			Err(e) => {
				warn!("refund error: --- {:?}", e);
				Err(ErrorKind::EthContractCallError)
			}
		}
	}

	/// get swap info
	fn get_swap_details(
		&self,
		address_from_secret: Address,
	) -> Result<(u64, Address, Address, u64), ErrorKind> {
		let task = async move {
			// get web3 handle
			let web3 = web3_handle!(self.chain, self.project_id);
			// Accessing existing contract
			let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
			let contract =
				Contract::from_json(web3.eth(), contract_address, ETH_SWAP_CONTRACT.as_bytes())
					.unwrap();

			let res: (u64, Address, Address, u64) = contract
				.query(
					"getSwapDetails",
					address_from_secret,
					None,
					Options::default(),
					None,
				)
				.await
				.unwrap();
			res
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.unwrap();
				let res = rt.block_on(task);
				res
			});
			handle.join().unwrap()
		});

		match res {
			Ok(result) => Ok(result),
			_ => Err(ErrorKind::InfuraNodeClient(
				"get_swap_details failed!".to_string(),
			)),
		}
	}
}

/// Infura client error response.
#[derive(Serialize, Deserialize, Debug)]
struct InfuraResponseError {
	code: i64,
	pub message: String,
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{thread, time};

	const MNMENOIC: &str = "square social wall upgrade owner flat razor across enable idea mirror autumn rescue pottery total seat confirm dizzy fabric couple reveal relief lucky session";
	const REDEEM_MNMENOIC: &str = "chef bunker radar park canal run manage regular clarify drop display retreat wool brisk olympic recall cash sample slender fruit tell lunar young unusual";
	const WALLET_PATH: &str = "m/44'/0'/0'/0";
	const PASSWORD: &str = "zqd123";
	const PROJECT_ID: &str = "d00e825c599c45a19b18dc4003626bee";
	const CHAIN: &str = "ropsten";
	const CONTRACT_ADDR: &str = "A21b2c034dF046a3DB790dd20b0C5C0040a74c67";

	macro_rules! get_infura_client {
		($project_id: expr, $chain: expr, $mnmenoic: expr, $password: expr, $path: expr, $contract_addr: expr) => {{
			let wallet = generate_ethereum_wallet($chain, $mnmenoic, $password, $path).unwrap();
			InfuraNodeClient::new(
				$project_id.to_string(),
				$chain.to_string(),
				wallet,
				$contract_addr.to_string(),
				)
			.unwrap()
			}};
	}

	// #[test]
	// fn test_infura() {
	// 	let nc = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);
	// 	let balance = nc.balance(Currency::Ether).unwrap();
	// 	println!("balance: {}", balance.0);

	// 	let height = nc.height().unwrap();
	// 	println!("height: {}", height);
	// }

	// #[test]
	// fn test_transfer_funds() {
	// 	let c = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);
	// 	let res = c.transfer(
	// 		to_eth_address("Aa7937998d2f417EaC0524ad6E15c9C5e40efBA9".to_string()).unwrap(),
	// 		1_000_000_000_000_000_000_u64,
	// 	);
	// 	println!("transfer result: {:?}", res);
	// }

	// #[test]
	// fn test_retrieve_trans_receipt() {
	// 	let c = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);
	// 	let res = c.retrieve_receipt(
	// 		to_eth_tx_hash(
	// 			"0x193342ec1fc85fb075d8c09006b954c5dc8b015606c72e57e8759f43b7191ea6".to_string(),
	// 		)
	// 		.unwrap(),
	// 	);
	// 	println!("test_retrieve_trans_receipt result: {:?}", res.unwrap());
	// }

	// #[test]
	// fn test_initiate_swap() {
	// 	let nc = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);
	// 	let wallet_rand = EthereumWallet::new(&mut thread_rng()).unwrap();
	// 	let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();
	// 	let res = nc.initiate(
	// 		2700,
	// 		address_from_secret,
	// 		to_eth_address("Aa7937998d2f417EaC0524ad6E15c9C5e40efBA8".to_string()).unwrap(),
	// 		2000,
	// 	);
	// 	println!("initiate_swap result: {:?}", res);
	// }

	// // wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("4651f24db5971c714d854df5ea5a68f2fccce96a24b8c41c619f4c9d49cd96e2"), public_key: Some("6673c66071c3fed37fc29b22bc55b723dc183f746c5170f432de35326cb7e2e07d9aa0096943d901d753af0a0f314712eae7c759a1ae3b3e0dea3054d3ae65ba"), address: Some("0x3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692"), transaction_id: None, network: None, transaction_hex: None }
	// #[test]
	// fn test_get_swap_details() {
	// 	let c = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);

	// 	let address_from_secret =
	// 		to_eth_address("3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692".to_string()).unwrap();
	// 	let res = c.get_swap_details(address_from_secret);
	// 	println!("test_get_swap_details result: {:?}", res.unwrap());
	// }

	// // // wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("64b0699526f9ed457cafb6cd27dbffe7ea8196a602b23354e0303521d0c1e265"), public_key: Some("cff6fc214ee02f9fb2def6908b605e84e2e2aaa5b0b484426d3997cb123dbba037c1b9d86fb76477c5c0df9750f7ba222adc80549e164affe68c6d2b75008942"), address: Some("0xDed1df8d3ea680C314bF9D7B9D0577c8F2eE980C"), transaction_id: None, network: None, transaction_hex: None }
	// #[test]
	// fn test_redeem() {
	// 	set_test_mode(true);
	// 	let c = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);

	// 	//generate rand address for swap index
	// 	let wallet_rand = EthereumWallet::new(&mut thread_rng()).unwrap();
	// 	let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();

	// 	//generate participant wallet
	// 	let redeem_wallet =
	// 		generate_ethereum_wallet(CHAIN, REDEEM_MNMENOIC, PASSWORD, WALLET_PATH).unwrap();
	// 	REDEEM_WALLET
	// 		.write()
	// 		.unwrap()
	// 		.replace(redeem_wallet.clone());

	// 	//initiate swap offer
	// 	let res = c.initiate(
	// 		720,
	// 		address_from_secret,
	// 		to_eth_address(redeem_wallet.address.clone().unwrap()).unwrap(),
	// 		1000,
	// 	);
	// 	println!("initiate_swap result: {}", res.unwrap());

	// 	// delay 100s , then refund
	// 	let ten_secs = time::Duration::from_secs(100);
	// 	thread::sleep(ten_secs);

	// 	// redeem now
	// 	//call redeem function
	// 	let key = secp256k1::SecretKey::from_slice(
	// 		&from_hex(wallet_rand.private_key.clone().unwrap().as_str()).unwrap(),
	// 	)
	// 	.unwrap();
	// 	let res = c.redeem(address_from_secret, key);
	// 	println!("test_redeem result: {:?}", res.unwrap());
	// }

	// #[test]
	// fn test_refund() {
	// 	let c = get_infura_client!(
	// 		PROJECT_ID,
	// 		CHAIN,
	// 		MNMENOIC,
	// 		PASSWORD,
	// 		WALLET_PATH,
	// 		CONTRACT_ADDR
	// 	);

	// 	//generate rand address for swap index
	// 	let wallet_rand = EthereumWallet::new(&mut thread_rng()).unwrap();
	// 	let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();

	// 	//generate participant walletc
	// 	let redeem_wallet =
	// 		generate_ethereum_wallet(CHAIN, REDEEM_MNMENOIC, PASSWORD, WALLET_PATH).unwrap();
	// 	REDEEM_WALLET
	// 		.write()
	// 		.unwrap()
	// 		.replace(redeem_wallet.clone());

	// 	//initiate swap offer
	// 	let res = c.initiate(
	// 		5,
	// 		address_from_secret,
	// 		to_eth_address("a25F8893278191875d863adE80BE6A38eDF9542d".to_string()).unwrap(),
	// 		1000,
	// 	);
	// 	println!("initiate_swap result: {}", res.unwrap());

	// 	// delay 100s , then refund
	// 	let ten_secs = time::Duration::from_secs(100);
	// 	thread::sleep(ten_secs);

	// 	// refund now
	// 	let res = c.refund(address_from_secret);
	// 	println!("test_refund result: {:?}", res.unwrap());
	// }
}
