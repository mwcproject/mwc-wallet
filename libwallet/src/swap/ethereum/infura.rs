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

use super::client::*;
use super::*;
use crate::mwc_util::from_hex;
#[cfg(test)]
use crate::swap::is_test_mode;
#[cfg(test)]
use crate::swap::set_test_mode;
use crate::swap::types::Currency;
use crate::swap::Error;
use crossbeam_utils::thread::scope;
use mwc_web3::{
	api::{Accounts, Namespace},
	contract::{Contract, Options},
	signing,
	signing::SecretKeyRef,
	types::{Address, Bytes, SignedData, TransactionParameters, TransactionReceipt, H256, U256},
};
#[cfg(test)]
use std::sync::RwLock;
use std::u64;
use tokio::runtime::Builder;

const TRANSACTION_DEFAULT_GAS_LIMIT: u64 = 5_500_000u64;

#[cfg(test)]
lazy_static! {
	/// Recieve account can be specified separately and must be allpy to ALL receive operations
	static ref REDEEM_WALLET:   RwLock<Option<EthereumWallet>>  = RwLock::new(None);
}

// macro_rules! mwc_web3_handle {
// 	($chain: expr, $projectid: expr) => {{
// 		let url = format!("wss://{}.infura.io/ws/v3/{}", $chain, $projectid);
// 		let transport = mwc_web3::transports::WebSocket::new(url.as_str())
// 			.await
// 			.unwrap();
// 		mwc_web3::Web3::new(transport)
// 		}};
// }

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
	/// ERC20 Contract Address
	pub erc20_contract_addr: String,
}

impl InfuraNodeClient {
	/// Create a new instance.
	pub fn new(
		project_id: String,
		chain: String,
		wallet: EthereumWallet,
		contract_addr: String,
		erc20_contract_addr: String,
	) -> Result<Self, Error> {
		let client = Self {
			project_id,
			chain,
			wallet,
			contract_addr,
			erc20_contract_addr,
		};

		Ok(client)
	}

	/// get ether balance
	pub fn ether_balance(&self) -> Result<(String, u64), Error> {
		let task = async move {
			let account = to_eth_address(self.wallet.address.clone().unwrap()).unwrap();
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					mwc_web3.eth().balance(account, None).await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(balance) => {
						let balance_gwei = balance / U256::exp10(9);
						let balance = to_norm(balance_gwei.to_string().as_str(), "9");
						Ok((format!("{}", balance.with_scale(6)), balance_gwei.as_u64()))
					}
					_ => Err(Error::EthContractCallError(
						"Get Ether Balance Failed!".to_string(),
					)),
				},
				_ => Err(Error::EthContractCallError(
					"Get Ether Balance Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Get Ether Balance Failed!".to_string(),
			)),
		}
	}

	/// get erc20 token balance
	pub fn erc20_balance(&self, currency: Currency) -> Result<(String, u64), Error> {
		let token_address = currency.erc20_token_address()?;
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract = Contract::from_json(
						mwc_web3.eth(),
						token_address,
						ERC20_TOKEN_CONTRACT.as_bytes(),
					)
					.unwrap();

					let res = contract
						.query(
							"balanceOf",
							(to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),),
							None,
							Options::default(),
							None,
						)
						.await;
					res
				}
				Err(e) => Err(mwc_web3::contract::Error::InvalidOutputType(format!(
					"erc20_balance error, {}",
					e
				))),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::contract::Error::InvalidOutputType(
						"erc20_balance error".to_string(),
					)),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(balance) => {
						let balance: U256 = match currency.is_expo_shrinked18to9() {
							true => balance / U256::exp10(9),
							false => balance,
						};
						let balance_norm = to_norm(
							balance.to_string().as_str(),
							currency.exponent().to_string().as_str(),
						);
						Ok((format!("{}", balance_norm), balance.as_u64()))
					}
					_ => Err(Error::EthContractCallError(
						"Get ERC20 Token Balance Of Failed!".to_string(),
					)),
				},
				_ => Err(Error::EthContractCallError(
					"Get ERC20 Token Balance Of Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Get ERC20 Token Balance Of Failed!".to_string(),
			)),
		}
	}

	/// ether transfer
	fn ether_transfer(&self, to: Address, value: U256, gas_limit: U256) -> Result<H256, Error> {
		let task = async move {
			// get mwc_web3 handle
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					let accounts_sign = Accounts::new(mwc_web3.eth().transport().clone());
					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let tx = TransactionParameters {
						nonce: Some(nonce),
						to: Some(to),
						gas: gas_limit / gas_price,
						gas_price: Some(gas_price),
						value,
						data: Bytes::default(),
						chain_id: None,
						transaction_type: None,
						access_list: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					};
					let signed = accounts_sign.sign_transaction(tx, &key).await.unwrap();
					mwc_web3
						.eth()
						.send_raw_transaction(signed.raw_transaction)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => Ok(rt.block_on(task)),
					_ => Err(Box::new("ether_transfer -- failed")),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(res) => match res {
						Ok(tx_hash) => Ok(tx_hash),
						_ => Err(Error::EthContractCallError(
							"eth transfer failure!".to_string(),
						)),
					},
					_ => Err(Error::EthContractCallError(
						"eth transfer failure!".to_string(),
					)),
				},
				Err(e) => {
					warn!("transfer error: --- {:?}", e);
					Err(Error::EthContractCallError(
						"eth transfer failure!".to_string(),
					))
				}
			},
			_ => Err(Error::EthContractCallError(
				"eth transfer failure!".to_string(),
			)),
		}
	}

	/// erc20 transfer
	fn erc20_transfer(
		&self,
		currency: Currency,
		to: Address,
		value: U256,
		gas_limit: U256,
	) -> Result<H256, Error> {
		let token_address = currency.erc20_token_address()?;
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract = Contract::from_json(
						mwc_web3.eth(),
						token_address,
						ERC20_TOKEN_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					contract
						.signed_call("transfer", (to, value), options, SecretKeyRef::new(&key))
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("erc20_transfer error: --- {:?}", e);
						Err(Error::EthContractCallError(
							"ERC20 Transfer Failed!".to_string(),
						))
					}
				},
				_ => Err(Error::EthContractCallError(
					"ERC20 Transfer Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"ERC20 Transfer Failed!".to_string(),
			)),
		}
	}

	/// ether initiate swap offer
	fn ether_initiate(
		&self,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: U256,
		gas_limit: U256,
	) -> Result<H256, Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
					let contract = Contract::from_json(
						mwc_web3.eth(),
						contract_address,
						ETH_SWAP_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.value = Some(value);
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					contract
						.signed_call(
							"initiate",
							(refund_time, address_from_secret, participant),
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("ether initiate error: --- {:?}", e);
						Err(Error::EthContractCallError(
							"Buyer Initiate Ether Swap Trade Failed!".to_string(),
						))
					}
				},
				_ => Err(Error::EthContractCallError(
					"Buyer Initiate Ether Swap Trade Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Buyer Initiate Ether Swap Trade Failed!".to_string(),
			)),
		}
	}

	/// erc20 initiate swap offer
	fn erc20_initiate(
		&self,
		currency: Currency,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: U256,
		gas_limit: U256,
	) -> Result<H256, Error> {
		let token_address = currency.erc20_token_address()?;
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address =
						to_eth_address(self.erc20_contract_addr.clone()).unwrap();
					let contract = Contract::from_json(
						mwc_web3.eth(),
						contract_address,
						ERC20_SWAP_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					contract
						.signed_call(
							"initiate",
							(
								refund_time,
								address_from_secret,
								participant,
								token_address,
								value,
							),
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("erc20 initiate error: --- {:?}", e);
						Err(Error::EthContractCallError(format!(
							"Buyer Initiate {} Swap Trade Failed!",
							Currency::Btc
						)))
					}
				},
				_ => Err(Error::EthContractCallError(format!(
					"Buyer Initiate {} Swap Trade Failed!",
					Currency::Ether
				))),
			},
			_ => Err(Error::EthContractCallError(format!(
				"Buyer Initiate {} Swap Trade Failed!",
				Currency::Usdc
			))),
		}
	}

	/// ether buyer redeem
	fn ether_redeem(
		&self,
		address_from_secret: Address,
		secret_key: mwc_web3::signing::SecretKey,
		gas_limit: U256,
	) -> Result<H256, Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address = to_eth_address(self.contract_addr.clone()).unwrap();
					let contract = Contract::from_json(
						mwc_web3.eth(),
						contract_address,
						ETH_SWAP_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();

					//0: refundTimeInBlocks, 1: initiator, 2: participant, 3: value
					let swap_details: (U256, Address, Address, U256) = contract
						.query(
							"getSwapDetails",
							address_from_secret,
							None,
							Options::default(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					//keccak256
					let mut refund_blocks = [0u8; 32];
					swap_details.0.to_big_endian(&mut refund_blocks);
					let address_bytes = [
						address_from_secret.as_bytes(),
						swap_details.2.as_bytes(),
						swap_details.1.as_bytes(),
						refund_blocks.as_ref(),
					]
					.concat();
					let accounts_sign = Accounts::new(mwc_web3.eth().transport().clone());
					let hashed_message = signing::keccak256(&address_bytes);
					let signed_data: SignedData = accounts_sign.sign(hashed_message, &secret_key);

					#[allow(unused_mut)]
					let mut key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();

					#[cfg(test)]
					{
						let test_mode = is_test_mode();
						if test_mode {
							key = mwc_web3::signing::SecretKey::from_slice(
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
						.signed_call(
							"redeem",
							(
								address_from_secret,
								signed_data.r,
								signed_data.s,
								signed_data.v,
							),
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("redeem error: --- {:?}", e);
						Err(Error::EthContractCallError(
							"Seller Redeem Ether Failed!".to_string(),
						))
					}
				},
				_ => Err(Error::EthContractCallError(
					"Seller Redeem Ether Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Seller Redeem Ether Failed!".to_string(),
			)),
		}
	}

	/// erc20 buyer redeem
	fn erc20_redeem(
		&self,
		address_from_secret: Address,
		secret_key: mwc_web3::signing::SecretKey,
		gas_limit: U256,
	) -> Result<H256, Error> {
		// let token_address = currency.erc20_token_address()?;
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address =
						to_eth_address(self.erc20_contract_addr.clone()).unwrap();
					let contract = Contract::from_json(
						mwc_web3.eth(),
						contract_address,
						ERC20_SWAP_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					//0: refundBlock, 1: contractAddress, 2: initiator, 3: participant, 4: value
					let swap_details: (U256, Address, Address, Address, U256) = contract
						.query(
							"getSwapDetails",
							address_from_secret,
							None,
							Options::default(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);
					let mut refund_blocks = [0u8; 32];
					swap_details.0.to_big_endian(&mut refund_blocks);
					//keccak256
					let address_bytes = [
						address_from_secret.as_bytes(),
						swap_details.3.as_bytes(),
						swap_details.2.as_bytes(),
						refund_blocks.as_ref(),
						swap_details.1.as_bytes(),
					]
					.concat();
					let accounts_sign = Accounts::new(mwc_web3.eth().transport().clone());
					let hashed_message = signing::keccak256(&address_bytes);
					let signed_data: SignedData = accounts_sign.sign(hashed_message, &secret_key);

					#[allow(unused_mut)]
					let mut key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();

					#[cfg(test)]
					{
						let test_mode = is_test_mode();
						if test_mode {
							key = mwc_web3::signing::SecretKey::from_slice(
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
						.signed_call(
							"redeem",
							(
								address_from_secret,
								signed_data.r,
								signed_data.s,
								signed_data.v,
							),
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("redeem error: --- {:?}", e);
						Err(Error::EthContractCallError(
							"Seller Redeem ERC20-Token Failed!".to_string(),
						))
					}
				},
				_ => Err(Error::EthContractCallError(
					"Seller Redeem ERC20-Token Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Seller Redeem ERC20-Token Failed!".to_string(),
			)),
		}
	}
}

impl EthNodeClient for InfuraNodeClient {
	/// Name of this client. Normally it is URL
	fn name(&self) -> String {
		"Infura Node".to_string()
	}

	/// Fetch the current chain height
	fn height(&self) -> Result<u64, Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					mwc_web3.eth().block_number().await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(block_number) => Ok(block_number.as_u64()),
					_ => Err(Error::EthContractCallError(
						"Get Ethereum Height Failed!".to_string(),
					)),
				},
				_ => Err(Error::EthContractCallError(
					"Get Ethereum Height Failed!".to_string(),
				)),
			},
			_ => Err(Error::EthContractCallError(
				"Get Ethereum Height Failed!".to_string(),
			)),
		}
	}

	/// get wallet balance
	fn balance(&self, currency: Currency) -> Result<(String, u64), Error> {
		if !currency.is_erc20() {
			self.ether_balance()
		} else {
			self.erc20_balance(currency)
		}
	}

	/// Retrieve transaction receipt
	fn retrieve_receipt(&self, tx_hash: H256) -> Result<TransactionReceipt, Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					mwc_web3.eth().transaction_receipt(tx_hash).await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => Some(rt.block_on(task)),
					_ => None,
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Some(res) => match res {
						Ok(res) => match res {
							Some(receipt) => Ok(receipt),
							_ => Err(Error::EthRetrieveTransReciptError),
						},
						_ => Err(Error::EthRetrieveTransReciptError),
					},
					_ => Err(Error::EthRetrieveTransReciptError),
				},
				_ => Err(Error::EthRetrieveTransReciptError),
			},
			_ => Err(Error::EthRetrieveTransReciptError),
		}
	}

	/// Send coins
	fn transfer(&self, currency: Currency, to: Address, value: u64) -> Result<H256, Error> {
		let gas_limit = U256::from(TRANSACTION_DEFAULT_GAS_LIMIT * 1000_000_000u64);
		let balance_ether = self.balance(Currency::Ether)?;
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if !currency.is_erc20() {
			let value = U256::from(value) * U256::exp10(9);
			if balance_ether < gas_limit + value {
				return Err(Error::EthBalanceNotEnough);
			}
			self.ether_transfer(to, value, gas_limit)
		} else {
			if balance_ether < gas_limit {
				return Err(Error::EthBalanceNotEnough);
			}

			let balance_token = self.balance(currency)?;
			let balance_token = U256::from(balance_token.1);
			let balance_token = match currency.is_expo_shrinked18to9() {
				true => balance_token * U256::exp10(9),
				false => balance_token,
			};
			let value = match currency.is_expo_shrinked18to9() {
				true => U256::from(value) * U256::exp10(9),
				false => U256::from(value),
			};

			if balance_token < value {
				return Err(Error::ERC20TokenBalanceNotEnough(format!("{}", currency)));
			}

			self.erc20_transfer(currency, to, value, gas_limit)
		}
	}

	/// erc20 approve swap offer
	fn erc20_approve(&self, currency: Currency, value: u64, gas: f32) -> Result<H256, Error> {
		let gas_limit = U256::from(gas as u64) * 1000_000_000u64;
		let balance_ether = self.balance(Currency::Ether)?;
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		let balance_token = self.balance(currency)?;
		let balance_token = U256::from(balance_token.1);
		let balance_token = match currency.is_expo_shrinked18to9() {
			true => balance_token * U256::exp10(9),
			false => balance_token,
		};

		let value = match currency.is_expo_shrinked18to9() {
			true => U256::from(value) * U256::exp10(9),
			false => U256::from(value),
		};

		if balance_token < value {
			return Err(Error::ERC20TokenBalanceNotEnough(format!("{}", currency)));
		}

		let token_address = currency.erc20_token_address()?;
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_swap_address =
						to_eth_address(self.erc20_contract_addr.clone()).unwrap();
					let contract_token = Contract::from_json(
						mwc_web3.eth(),
						token_address,
						ERC20_TOKEN_CONTRACT.as_bytes(),
					)
					.unwrap();

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					contract_token
						.signed_call(
							"approve",
							(contract_swap_address, value),
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("erc20 approve error: --- {:?}", e);
						Err(Error::EthContractCallError(format!(
							"{}:  ERC20 ApproveFailed!",
							currency
						)))
					}
				},
				_ => Err(Error::EthContractCallError(format!(
					"{}:  ERC20 ApproveFailed!",
					currency
				))),
			},
			_ => Err(Error::EthContractCallError(format!(
				"{}:  ERC20 ApproveFailed!",
				currency
			))),
		}
	}

	/// initiate swap offer
	fn initiate(
		&self,
		currency: Currency,
		refund_time: u64,
		address_from_secret: Address,
		participant: Address,
		value: u64,
		gas: f32,
	) -> Result<H256, Error> {
		let gas_limit = U256::from(gas as u64) * 1000_000_000u64;
		let balance_ether = self.balance(Currency::Ether)?;
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);

		if !currency.is_erc20() {
			let value = U256::from(value) * U256::exp10(9);
			if balance_ether < gas_limit + value {
				return Err(Error::EthBalanceNotEnough);
			}

			self.ether_initiate(
				refund_time,
				address_from_secret,
				participant,
				value,
				gas_limit,
			)
		} else {
			// one gas_limit for approve, the other one for initiate
			if balance_ether < gas_limit {
				return Err(Error::EthBalanceNotEnough);
			}

			let value = match currency.is_expo_shrinked18to9() {
				true => U256::from(value) * U256::exp10(9),
				_ => U256::from(value),
			};

			self.erc20_initiate(
				currency,
				refund_time,
				address_from_secret,
				participant,
				U256::from(value),
				gas_limit,
			)
		}
	}

	/// buyer redeem
	fn redeem(
		&self,
		currency: Currency,
		address_from_secret: Address,
		secret_key: mwc_web3::signing::SecretKey,
		gas_limit: f32,
	) -> Result<H256, Error> {
		let gas_limit = U256::from(gas_limit as u64) * 1000_000_000u64;
		let balance_ether = self.balance(Currency::Ether)?;
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);
		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		if !currency.is_erc20() {
			self.ether_redeem(address_from_secret, secret_key, gas_limit)
		} else {
			self.erc20_redeem(address_from_secret, secret_key, gas_limit)
		}
	}

	/// refund ether
	fn refund(
		&self,
		currency: Currency,
		address_from_secret: Address,
		gas_limit: f32,
	) -> Result<H256, Error> {
		let gas_limit = U256::from(gas_limit as u64) * U256::exp10(9);
		let balance_ether = self.balance(Currency::Ether)?;
		let balance_ether = U256::from(balance_ether.1) * U256::exp10(9);
		if balance_ether < gas_limit {
			return Err(Error::EthBalanceNotEnough);
		}

		let height = self.height()?;
		let swap_details = self.get_swap_details(currency, address_from_secret)?;
		let refund_time_blocks = swap_details.0;
		if mwc_wallet_util::mwc_util::is_console_output_enabled() {
			println!(
				"refund: hegiht = {}, refund_time_blocks = {}",
				height, refund_time_blocks
			);
		}
		if height < refund_time_blocks {
			return Err(Error::EthRefundTimeNotArrived);
		}

		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address = match currency.is_erc20() {
						true => to_eth_address(self.erc20_contract_addr.clone()).unwrap(),
						_ => to_eth_address(self.contract_addr.clone()).unwrap(),
					};

					let contract = match currency.is_erc20() {
						true => Contract::from_json(
							mwc_web3.eth(),
							contract_address,
							ERC20_SWAP_CONTRACT.as_bytes(),
						)
						.unwrap(),
						_ => Contract::from_json(
							mwc_web3.eth(),
							contract_address,
							ETH_SWAP_CONTRACT.as_bytes(),
						)
						.unwrap(),
					};

					let nonce = mwc_web3
						.eth()
						.transaction_count(
							to_eth_address(self.wallet.address.clone().unwrap()).unwrap(),
							None,
						)
						.await
						.unwrap();
					let gas_price = mwc_web3.eth().gas_price().await.unwrap();
					let gas_price = gas_price + gas_price / 2;
					let mut options = Options::default();
					options.gas_price = Some(gas_price);
					options.gas = Some(gas_limit / gas_price);
					options.nonce = Some(nonce);

					let key = mwc_web3::signing::SecretKey::from_slice(
						&from_hex(self.wallet.private_key.clone().unwrap().as_str()).unwrap(),
					)
					.unwrap();
					contract
						.signed_call(
							"refund",
							address_from_secret,
							options,
							SecretKeyRef::new(&key),
						)
						.await
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => rt.block_on(task),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(res) => match res {
					Ok(tx_hash) => Ok(tx_hash),
					Err(e) => {
						warn!("refund error: --- {:?}", e);
						Err(Error::EthContractCallError(format!(
							"Buyer Refund {} Failed!",
							currency
						)))
					}
				},
				_ => Err(Error::EthContractCallError(format!(
					"Buyer Refund {} Failed!",
					currency
				))),
			},
			_ => Err(Error::EthContractCallError(format!(
				"Buyer Refund {} Failed!",
				currency
			))),
		}
	}

	/// get swap info
	fn get_swap_details(
		&self,
		currency: Currency,
		address_from_secret: Address,
	) -> Result<(u64, Option<Address>, Address, Address, u64), Error> {
		let task = async move {
			let url = format!("wss://{}.infura.io/ws/v3/{}", self.chain, self.project_id);
			let transport = mwc_web3::transports::WebSocket::new(url.as_str()).await;
			match transport {
				Ok(tx_socket) => {
					let mwc_web3 = mwc_web3::Web3::new(tx_socket);
					let contract_address = match currency.is_erc20() {
						true => to_eth_address(self.erc20_contract_addr.clone()).unwrap(),
						_ => to_eth_address(self.contract_addr.clone()).unwrap(),
					};

					let contract = match currency.is_erc20() {
						true => Contract::from_json(
							mwc_web3.eth(),
							contract_address,
							ERC20_SWAP_CONTRACT.as_bytes(),
						)
						.unwrap(),
						_ => Contract::from_json(
							mwc_web3.eth(),
							contract_address,
							ETH_SWAP_CONTRACT.as_bytes(),
						)
						.unwrap(),
					};

					//0: refundBlock, 1: contractAddress<Option>, 2: initiator, 3: participant, 4: value
					if !currency.is_erc20() {
						let res: (U256, Address, Address, U256) = contract
							.query(
								"getSwapDetails",
								address_from_secret,
								None,
								Options::default(),
								None,
							)
							.await
							.unwrap();
						Ok((res.0, None, res.1, res.2, res.3))
					} else {
						let res: (U256, Address, Address, Address, U256) = contract
							.query(
								"getSwapDetails",
								address_from_secret,
								None,
								Options::default(),
								None,
							)
							.await
							.unwrap();
						Ok((res.0, Some(res.1), res.2, res.3, res.4))
					}
				}
				_ => Err(mwc_web3::Error::Internal),
			}
		};

		let res = scope(|s| {
			let handle = s.spawn(|_| {
				let rt = Builder::new_current_thread().enable_all().build();
				match rt {
					Ok(rt) => Ok(rt.block_on(task)),
					_ => Err(mwc_web3::Error::Internal),
				}
			});
			handle.join()
		});

		match res {
			Ok(res) => match res {
				Ok(result) => match result {
					Ok(result) => match result {
						Ok(result) => {
							let balance: U256 = match currency.is_expo_shrinked18to9() {
								true => result.4 / U256::exp10(9),
								false => result.4,
							};

							Ok((
								result.0.as_u64(),
								result.1,
								result.2,
								result.3,
								balance.as_u64(),
							))
						}
						_ => Err(Error::InfuraNodeClient(format!(
							"Get Swap Details {} Failed!",
							currency
						))),
					},
					_ => Err(Error::InfuraNodeClient(format!(
						"Get Swap Details {} Failed!",
						currency
					))),
				},
				_ => Err(Error::InfuraNodeClient(format!(
					"Get Swap Details {} Failed!",
					currency
				))),
			},
			_ => Err(Error::InfuraNodeClient(format!(
				"Get Swap Details {} Failed!",
				currency
			))),
		}
	}
}

/// Infura client error response.
/*#[derive(Serialize, Deserialize, Debug)]
struct InfuraResponseError {
	code: i64,
	pub message: String,
}*/

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
	const ERC20_CONTRACT_ADDR: &str = "8955539Ea48A5d9196cdB2f8a7F67eB0dC7d15df";

	macro_rules! get_infura_client {
		($project_id: expr, $chain: expr, $mnmenoic: expr, $password: expr, $path: expr, $contract_addr: expr, $erc20_contract_addr: expr) => {{
			let wallet = generate_ethereum_wallet($chain, $mnmenoic, $password, $path).unwrap();
			InfuraNodeClient::new(
				$project_id.to_string(),
				$chain.to_string(),
				wallet,
				$contract_addr.to_string(),
				$erc20_contract_addr.to_string(),
			)
			.unwrap()
		}};
	}

	#[test]
	#[ignore]
	fn test_infura() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		println!("wallet address: {}", nc.wallet.address.clone().unwrap());

		let balance = nc.balance(Currency::Ether).unwrap();
		println!("balance: {}", balance.0);

		let height = nc.height().unwrap();
		println!("height: {}", height);
	}

	#[test]
	#[ignore]
	fn test_transfer_funds() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let res = c.transfer(
			Currency::Ether,
			to_eth_address("0xAa7937998d2f417EaC0524ad6E15c9C5e40efBA9".to_string()).unwrap(),
			1000u64,
		);
		println!("transfer result: {:?}", res);
	}

	#[test]
	#[ignore]
	fn test_retrieve_trans_receipt() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let res = c.retrieve_receipt(
			to_eth_tx_hash(
				"0x193342ec1fc85fb075d8c09006b954c5dc8b015606c72e57e8759f43b7191ea6".to_string(),
			)
			.unwrap(),
		);
		println!("test_retrieve_trans_receipt result: {:?}", res.unwrap());
	}

	#[test]
	#[ignore]
	fn test_initiate_swap() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);
		let wallet_rand = EthereumWallet::new(&mut rand::thread_rng()).unwrap();
		let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();
		let height = nc.height().unwrap();
		let res = nc.initiate(
			Currency::Tst,
			height + 2700,
			address_from_secret,
			to_eth_address("Aa7937998d2f417EaC0524ad6E15c9C5e40efBA8".to_string()).unwrap(),
			10,
			5500000.0,
		);
		println!("initiate_swap result: {:?}", res);
	}

	// wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("4651f24db5971c714d854df5ea5a68f2fccce96a24b8c41c619f4c9d49cd96e2"), public_key: Some("6673c66071c3fed37fc29b22bc55b723dc183f746c5170f432de35326cb7e2e07d9aa0096943d901d753af0a0f314712eae7c759a1ae3b3e0dea3054d3ae65ba"), address: Some("0x3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692"), transaction_id: None, network: None, transaction_hex: None }
	#[test]
	#[ignore]
	fn test_get_swap_details() {
		let c = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		let address_from_secret =
			to_eth_address("3b6C3dF492a9cf58ca3f52CAA68bA9D09391E692".to_string()).unwrap();
		let res = c.get_swap_details(Currency::Ether, address_from_secret);
		println!("test_get_swap_details result: {:?}", res);
	}

	// // wallet: EthereumWallet { path: None, password: None, mnemonic: None, extended_private_key: None, extended_public_key: None, private_key: Some("64b0699526f9ed457cafb6cd27dbffe7ea8196a602b23354e0303521d0c1e265"), public_key: Some("cff6fc214ee02f9fb2def6908b605e84e2e2aaa5b0b484426d3997cb123dbba037c1b9d86fb76477c5c0df9750f7ba222adc80549e164affe68c6d2b75008942"), address: Some("0xDed1df8d3ea680C314bF9D7B9D0577c8F2eE980C"), transaction_id: None, network: None, transaction_hex: None }
	#[test]
	#[ignore]
	fn test_redeem() {
		set_test_mode(true);
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		//generate rand address for swap index
		let wallet_rand = EthereumWallet::new(&mut rand::thread_rng()).unwrap();
		let address_from_secret = to_eth_address(wallet_rand.address.clone().unwrap()).unwrap();

		//generate participant wallet
		let redeem_wallet =
			generate_ethereum_wallet(CHAIN, REDEEM_MNMENOIC, PASSWORD, WALLET_PATH).unwrap();
		REDEEM_WALLET
			.write()
			.expect("RwLock failure")
			.replace(redeem_wallet.clone());

		//initiate swap offer
		let res = nc.initiate(
			Currency::Tst,
			720,
			address_from_secret,
			to_eth_address(redeem_wallet.address.clone().unwrap()).unwrap(),
			10,
			5500000.0,
		);
		println!("initiate_swap result: {:?}", res.unwrap());

		// delay 300s , then redeem
		let secs = time::Duration::from_secs(3 * 10);
		thread::sleep(secs);

		// redeem now
		//call redeem function
		let key = mwc_web3::signing::SecretKey::from_slice(
			&from_hex(wallet_rand.private_key.clone().unwrap().as_str()).unwrap(),
		)
		.unwrap();
		let res = nc.redeem(Currency::Tst, address_from_secret, key, 5500000.0);
		println!("test_redeem result: {:?}", res.unwrap());
	}

	#[test]
	#[ignore]
	fn test_refund() {
		let nc = get_infura_client!(
			PROJECT_ID,
			CHAIN,
			MNMENOIC,
			PASSWORD,
			WALLET_PATH,
			CONTRACT_ADDR,
			ERC20_CONTRACT_ADDR
		);

		let res = nc.refund(
			Currency::Tst,
			to_eth_address("1d8d33f1e9b5a2d3af9c46957b8b21d7e15b4d0e".to_string()).unwrap(),
			5500000.0,
		);
		println!("test_refund result: {:?}", res);
	}
}
