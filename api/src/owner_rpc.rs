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

//! JSON-RPC Stub generation for the Owner API
// allow for json_rpc
#![allow(deprecated)]
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v3::TransactionV3;
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, Slate, TxLogEntry, VersionedSlate, WalletInfo, WalletLCProvider,
};
use crate::types::TxLogEntryAPI;
use crate::util;
use crate::util::secp::pedersen;
use crate::util::Mutex;
use crate::{Owner, OwnerRpcS};
use easy_jsonrpc_mw;
use grin_wallet_libwallet::proof::proofaddress::ProvableAddress;
use std::sync::Arc;

/// Public definition used to generate Owner jsonrpc api.
/// * When running `mwc-wallet owner_api` with defaults, the V2 api is available at
/// `localhost:3420/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpc: Sync + Send {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , false, 4, false, false, false, false);
	```
	*/
	#[deprecated(
		since = "3.0.0",
		note = "The V2 Owner API (OwnerRpc) will be removed in mwc-wallet 4.0.0. Please migrate to the V3 (OwnerRpcS) API as soon as possible."
	)]
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,false, 4, false, false, false, false);
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , false, 4, false, false, false, false);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"include_spent": false,
			"refresh_from_node": true,
			"tx_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
			  "output": {
				"commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
				"height": "1",
				"is_coinbase": true,
				"key_id": "0300000000000000000000000000000000",
				"lock_height": "4",
				"mmr_index": null,
				"n_child": 0,
				"root_key_id": "0200000000000000000000000000000000",
				"status": "Unspent",
				"tx_log_entry": 0,
				"value": "2380952380"
			  }
			},
			{
			  "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
			  "output": {
				"commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
				"height": "2",
				"is_coinbase": true,
				"key_id": "0300000000000000000000000100000000",
				"lock_height": "5",
				"mmr_index": null,
				"n_child": 1,
				"root_key_id": "0200000000000000000000000000000000",
				"status": "Unspent",
				"tx_log_entry": 1,
				"value": "2380952380"
			  }
			}
		  ]
		]
	  }
	}
	# "#
	# , false, 2, false, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": [
			  true,
			  [
				{
				  "address": null,
				  "amount_credited": "2380952380",
				  "amount_debited": "0",
				  "confirmation_ts": "2019-01-15T16:01:26Z",
				  "confirmed": true,
				  "creation_ts": "2019-01-15T16:01:26Z",
				  "fee": null,
				  "id": 0,
				  "input_commits": [],
				  "kernel_excess": "099beea8f814120ac8c559027e55cb26986ae40e279e3093a7d4a52d827a23f0e7",
				  "kernel_lookup_min_height": 1,
				  "messages": null,
				  "num_inputs": 0,
				  "num_outputs": 1,
				  "output_commits": [
					"0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03"
				  ],
				  "output_height": 1,
				  "parent_key_id": "0200000000000000000000000000000000",
				  "payment_proof": null,
				  "stored_tx": null,
				  "ttl_cutoff_height": null,
				  "tx_slate_id": null,
				  "tx_type": "ConfirmedCoinbase"
				},
				{
				  "address": null,
				  "amount_credited": "2380952380",
				  "amount_debited": "0",
				  "confirmation_ts": "2019-01-15T16:01:26Z",
				  "confirmed": true,
				  "creation_ts": "2019-01-15T16:01:26Z",
				  "fee": null,
				  "id": 1,
				  "input_commits": [],
				  "kernel_excess": "09f7677adc7caf8bb44a4ee27d27dfe9ffa1010847a18b182bbb7100bb02f9259e",
				  "kernel_lookup_min_height": 2,
				  "messages": null,
				  "num_inputs": 0,
				  "num_outputs": 1,
				  "output_commits": [
					"098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c"
				  ],
				  "output_height": 2,
				  "parent_key_id": "0200000000000000000000000000000000",
				  "payment_proof": null,
				  "stored_tx": null,
				  "ttl_cutoff_height": null,
				  "tx_slate_id": null,
				  "tx_type": "ConfirmedCoinbase"
				}
			  ]
			]
		  }
		}
	# "#
	# , false, 2, false, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  {
			"amount_awaiting_confirmation": "0",
			"amount_awaiting_finalization": "0",
			"amount_currently_spendable": "2380952380",
			"amount_immature": "7142857140",
			"amount_locked": "0",
			"last_confirmed_height": "4",
			"minimum_confirmations": "1",
			"total": "9523809520"
		  }
		]
	  }
	}
	# "#
	# ,false, 4, false, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	// 	Case with Minimal and full number of arguments.
	//  Minimal test doesn't have funds because defailt numbers of confirmations is 10, so funds are not available yet

	/**
		Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"args": {
					"amount": "200000000"

				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Err": {
			  "NotEnoughFunds": {
				"available": 0,
				"available_disp": "0.0",
				"needed": 209000000,
				"needed_disp": "0.209"
			  }
			}
		  }
		}
		# "#
		# ,false, 4, false, false, false, false);

			# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
			# r#"
			{
				"jsonrpc": "2.0",
				"method": "init_send_tx",
				"params": {
					"args": {
						"src_acct_name": "default",
						"amount": "200000000",
						"minimum_confirmations": 2,
						"max_outputs": 500,
						"num_change_outputs": 2,
						"selection_strategy_is_use_all": false,
						"message": "my message",
						"target_slate_version": 3,
						"payment_proof_recipient_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
						"ttl_blocks": 3,
						"outputs": null,
						"send_args": null
					}
				},
				"id": 1
			}
			# "#
			# ,
			# r#"
			{
			  "id": 1,
			  "jsonrpc": "2.0",
			  "result": {
				"Ok": {
				  "amount": "200000000",
				  "fee": "12000000",
				  "height": "4",
				  "id": "0436430c-2b02-624c-2032-570501212b01",
				  "lock_height": "0",
				  "num_participants": 2,
				  "participant_data": [
					{
					  "id": "0",
					  "message": "my message",
					  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba3566c0013d1990238520857ef3fef423ca5b162a9f252f7e7e886bb403ba011",
					  "part_sig": null,
					  "public_blind_excess": "021f8d31340ce1230d2ddd2562dfc39bb487c6086bb8ec2d59230c491cfe5c25f1",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				  ],
				  "payment_proof": {
					"receiver_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
					"receiver_signature": null,
					"sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
				  },
				  "ttl_cutoff_height": "7",
				  "tx": {
					"body": {
					  "inputs": [
						{
						  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
						  "features": "Coinbase"
						}
					  ],
					  "kernels": [
						{
						  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
						  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						  "features": "Plain",
						  "fee": "12000000",
						  "lock_height": "0"
						}
					  ],
					  "outputs": [
						{
						  "commit": "08fdf5a2ea8ccd62e11f752c2dd8c0c7a96524181ebf9525be5fd376b74aa4f8d5",
						  "features": "Plain",
						  "proof": "e29d4f503199c188cde73f7e485bd90cf2128612dbc5fb31eed9573aacd9339a1b50d68d169ee58cf4adca417fbfa35a689857a341a330d280f31415b75ea682082f38347203a25d984791be37b5c6ce17304ebb99fa1c6ce3b4489608513bb90f4b3a868a5d000e9e39df876b6716d42d5027afe413333f4e75e13c06a52d4a0c9e17cd061931d65a2bc40c9ba487cd1e96109529342c6670d9c04b9cb98a0ca411652700633acdad6c118d46654a3c6b9f54d8aeccecd3abea48710443415579877ec62daf1604d80c8c65eaf232fec4398394ee94f915b5fd9844ffa49843d38d6ca29ff641b8ab447514e0dcf8e97d744e4d615ea8a67922e43d6d71475154193bc21ca975e7452e1f548acd54550af8ff781ca6df264cc243fc629ce4cbcbdc36b9f9b17a4f922c9402fd6d1a1bdb0f2647e9dd237e0c7e26f96998057ad1dc31e62af460e0c456b0d18d3b0c718ad60684fc8f4050b3e9a9c6d09d6b98d5e40234e325dfa017442208f5074e412f220bfeb8b14c1338ce0006bff98000539362aeb5695a56000e673725e54144ca8f4c7b0762157d62f49c870b6526d5d1a54062de2881b22d78448e0fcc2370d49fd0f03e7bd1a3dd7706350a2849ac2a85c166f5ebb3d6f7082c45cd8fa22a7c05a7e9ce50bfe151fb87035bcae8c5bf9aa90ec1b47c2d9c0dd8adee8ad95d6969361091cc6a57c142b077f7bc81bdac6972d9556521c3fecab449834fba30df250340c9547864f7b735a330b96fa9558af5f37fbcb801c505adc61a30740510ad8326f6f6dbc01cfab93618c12b71493992c1ae3cfa36e247f9483e1346835f48b02aa7bbba70412d26a70418ebbef45c7f214bcd27d500e32eb05c880ea19370bede577eb443943de8af302ef691877b902f73b31145780e8a2c05bf33184998fe03fb550ddbcf458879999b80b1e860bf"
						},
						{
						  "commit": "091ccfefabdd674c57e26da0dd6ba6738cffdd0ab01f3ff4f7498497e734284ee3",
						  "features": "Plain",
						  "proof": "451449f1f89e4fb42b788e7deece52f0826768f66e3f769b48df6ac2e05e38e369b5733aa5de3ba20698166575afd0d46546a14dd480ecb355f54f7aadd3d2f409c92b6d3087682c39bfd279612747a3e883357cc05b22609c2df8e5fd43fbcdf78cad76bc6ad7bf0d28c2ff7e530621189e96c29da048bc844ebeef74a6e66879ff67fa67e38962c3652b409ad7a41993adf5ce2b3eda77dd3b02db207877712096650c418bcae09ee3a73917069e933d521e78c2ed130c19151995d80bc69538ffff469b3a966c63467363d855a6577cc4f2b05e66f9bbc8b0fa46633c3acbfcb534fd55e3daaf35adbaa3c59d8c033778de20664c36b92360ecdc6304f78a9b794ac960691e01976b5ebf943d7345c77e40926a9c779a38a33783e6fb2cdd578650136f05f345e4028f7f635254cb7442342916f1a44b37e9b7c78ce4a5d84a02e512a2658afe9f452cfc4b919cf38c3e2446307010864651f43c9e7a345064190357934e53663b0df84b05d6d9c3e9f5ad66c46b8e754183bd1111fa6abde38bb22b928dbc74a8c254efbffb5407bf75438ef000fe2c16bc8fe533526923911aa8bdbe61ea6e5955ef4480520e54af1e9d5c33dd600015c43e642147da44afc8855ffd463326f1a0b993255faa98fb9c044a9a5ffb663c126c4ca0f62f94feb0c44bc5f440d18600b1e7bcb41f3f7fe78e93459082ee15012ac82b16bc21aae1e3cd0506bb27b367be006aa2389e0cf99e07e55a9dde2b5e92e89c7375c387351267b7340cc90d8c3c027b6294bc62e247825692ef776e5a815496f30cb0b3de399820e836e37389058985c1751ca770acd242aa8a871544d26ab2722f1568a505731ecb09f3508e6b5bd24ed6ec169b9d0ad1fc28f55364c68655c242004d22eb5609466f8d15d993121015e559084e409f569681b7029590b28caf1c657ee90e"
						}
					  ]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				  },
				  "version_info": {
					"block_header_version": 1,
					"orig_version": 3,
					"version": 3
				  }
				}
			  }
			}
			# "#
			# ,false, 4, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# // Minimal list of arguments
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"args": {
					"amount": "2000000000"
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": {
			  "amount": "2000000000",
			  "fee": "0",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b00",
			  "lock_height": "0",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": null,
				  "message_sig": null,
				  "part_sig": null,
				  "public_blind_excess": "0306daab7bd7c36e23dd6fe32b83827abc350129467094ba855820b3d0a2b13d51",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "tx": {
				"body": {
				  "inputs": [],
				  "kernels": [
					{
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					  "features": "Plain",
					  "fee": "0",
					  "lock_height": "0"
					}
				  ],
				  "outputs": [
					{
					  "commit": "088119ed65640d33407d84da4992850eb6a5c2b68ad2ff2323dee51495599bc42d",
					  "features": "Plain",
					  "proof": "5035e8cc9a8f35353bf73124ef12b3f7cff7dbcfcc8476c796f62bdf48000e7c87a0a70f2deb44f502bf3be08302d2affb51ae9b7b7d21b96752dc9bd22932520c46311cc0492b1a8e5bcd5c12df5eda2a05860c9db2ac178a2c1c5c01acf3859b068c927a300a4d883b03f03a062dd8475174d8d1770dca2d24e60a8899907b8b425346f1c75c8febaf4b21d81666d9fb6af62f8059f55677a8cef90e64be362d6c7232e009209fbe4a1b1918211109d3d16f08fc018b1a3d3bd11be9495a6a40cbb433130f74b2e0fd4d97da78e623f329922e07a791aab6c93a477449c04894cfdba37a3748fd7fd7203b93e73b00299e367efa5411cd5da70104dc25fda3497c3c99bda84f3bce4c205cb27d72979bdcbfa495599d9804cba3096319c3c5c4aaeeadbda2b185196a3b5785c3e68de0ec260cb1450cfbe0934c78f61a4df8632018e731016aa82dab83f09670534e04c044d20eaa2b9281bdf6d3677be6fab54203b95701c8a962638e78706b3024c61994b420705934f9f7fdd36bc00431cea462edbabbef2aea62cf422a736f02f8852c53996d0e663648f67838b2f084db39b115de1dc05047803071e1ac2ce25e5d2ecf41a83f12adb88ee336ba6e04b52a59fe138245ed2a2ff46ff38221ee7fcf311bb330947766d8f695ec990efe63df358bd17d15d825c42b8de93cf740a22a0328781e76e92f210ba0ae989c4290f3035b208b27a616076b6873e851f3b5b74ad8bbd01cbebcc7b5d0c0d7c4604136106d1086f71b467d06c7c91caf913fc2bc588762fd63ce4ed2f85b1befdd4fa29ae073b943fc00fc9a675a676d6d3be03e1b7ac351379966fc5bcf8584508b975974fd98c3062861e588453a96296fae97488f42662f55af630389a436707940a673a36e19fc720c859660eabc9de31b4e48cef26b88b8a3af462c8ad62f461714"
					}
				  ]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
			  },
			  "version_info": {
				"block_header_version": 1,
				"orig_version": 3,
				"version": 2
			  }
			}
		  }
		}
		# "#
		# ,false, 4, false, false, false, false);
		#
		# // Full number of arguments
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"args": {
					"amount": "2100000000",
					"message": "Please give me your coins",
					"dest_acct_name": "deafult",
					"target_slate_version": 2,
					"address" : "My address to store in the slate"
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": {
			  "amount": "2100000000",
			  "fee": "0",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b01",
			  "lock_height": "0",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": "Please give me your coins",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdbef9a347351338e8e17651406c85ba131cf27af58fedcc14d63a0cc4ae17adb",
				  "part_sig": null,
				  "public_blind_excess": "0330724cb1977c5a1256a639d8b8b124bb9fbbf83fddb7cc20e3c17534f6ca6c54",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "tx": {
				"body": {
				  "inputs": [],
				  "kernels": [
					{
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					  "features": "Plain",
					  "fee": "0",
					  "lock_height": "0"
					}
				  ],
				  "outputs": [
					{
					  "commit": "099210eb73958b9ff3249af117e1b41799834b219be9bfe92e47d112f797edff18",
					  "features": "Plain",
					  "proof": "edc3c76e588f3b5b76e3c511a559ecd5873d470b5902b41cee059fd027c781099ce59abec58571d4a98d1ae510d423dce5742138f897dccb268d3acbfc66f3a40eb5c3273300bd3fe2f068bd998b49d1ff2ca2c458548a4b2895a4094fe8208c9204b35dbb04bc0f475ad288928aa62cd64095c2b46db068355c8c67c2aa1591cfedfcf29474a9b6d54fd42cbcff89af6be74be0113d1d6ae2c5722e9d44677fa49e8163b40cd7fe42cd8353d9316dfe01a80e455b872ca3e07653673147b5d4f9ff6d7d4ffd505e393b91bd271e407f9ae8ecd2311dcd62e9193278a0743559048227d8a95e6b011256239b7cacf2e0b3c57709b6c0e55f1b08e8599479f23547da2df00ac4692d34d315bf740dde3c23044a848e4603b54a1398c5fcd92e81afe20a653809c979a03b844946c4d16cbc05f20009cd14819ace50319c14b3002445c36bfdf270c2add62aa611390aca92ce89ec24e0c4df8948fad4d95d6e9036180378be0ef87a020e4715c4f79ba1ec520d44eedd8beaf9b69587950cf5c65beb3a90376a3386e409c3f8dbc7a747690a8ced27d469254edc1e3f369736e53651eedd123e70988b9f956026f50e87949796864e60ce8e58150f2d58c6d0c52eda766faee23b4dd012145e9d6932a443643809766363a88a07719c9dbb72a723fbc8b857327f256227b6ef9587cd1ecf60a9d55b9b3a3642764354194eb35e0285207913e88c839a77cc8f33627d66ade0e6d27c40d50d55d084a8660b65f4a897cf3bd86fe6282bda247ff2a23e1ab9fcfe8e50614979681e0afae319f23216d2b44d3662a43a6d2b0dce5461b040b98414d82c62db88102e4b6a8a42f3b5d3475c46e61898e34fed3fc4772323eb28f685d4b2e56ccc5022ccd80c043bf23d1b985f9c7c9512c387233aa967a40938a91b9cc13f68e9e3653adc21a7d0d4a1ad4c"
					}
				  ]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
			  },
			  "version_info": {
				"block_header_version": 1,
				"orig_version": 2,
				"version": 2
			  }
			}
		  }
		}
		# "#
		# ,false, 4, false, false, false, false);
	```
	*/

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# // NOTE!!! Second InitTxArgs is not complete, using default values
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": [
				{
					  "amount": "2100000000",
					  "fee": "0",
					  "height": "4",
					  "id": "0436430c-2b02-624c-2032-570501212b01",
					  "lock_height": "0",
					  "num_participants": 2,
					  "participant_data": [
						{
						  "id": "0",
						  "message": "Please give me your coins",
						  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdbef9a347351338e8e17651406c85ba131cf27af58fedcc14d63a0cc4ae17adb",
						  "part_sig": null,
						  "public_blind_excess": "0330724cb1977c5a1256a639d8b8b124bb9fbbf83fddb7cc20e3c17534f6ca6c54",
						  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					  ],
					  "tx": {
						"body": {
						  "inputs": [],
						  "kernels": [
							{
							  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
							  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							  "features": "Plain",
							  "fee": "0",
							  "lock_height": "0"
							}
						  ],
						  "outputs": [
							{
							  "commit": "099210eb73958b9ff3249af117e1b41799834b219be9bfe92e47d112f797edff18",
							  "features": "Plain",
							  "proof": "edc3c76e588f3b5b76e3c511a559ecd5873d470b5902b41cee059fd027c781099ce59abec58571d4a98d1ae510d423dce5742138f897dccb268d3acbfc66f3a40eb5c3273300bd3fe2f068bd998b49d1ff2ca2c458548a4b2895a4094fe8208c9204b35dbb04bc0f475ad288928aa62cd64095c2b46db068355c8c67c2aa1591cfedfcf29474a9b6d54fd42cbcff89af6be74be0113d1d6ae2c5722e9d44677fa49e8163b40cd7fe42cd8353d9316dfe01a80e455b872ca3e07653673147b5d4f9ff6d7d4ffd505e393b91bd271e407f9ae8ecd2311dcd62e9193278a0743559048227d8a95e6b011256239b7cacf2e0b3c57709b6c0e55f1b08e8599479f23547da2df00ac4692d34d315bf740dde3c23044a848e4603b54a1398c5fcd92e81afe20a653809c979a03b844946c4d16cbc05f20009cd14819ace50319c14b3002445c36bfdf270c2add62aa611390aca92ce89ec24e0c4df8948fad4d95d6e9036180378be0ef87a020e4715c4f79ba1ec520d44eedd8beaf9b69587950cf5c65beb3a90376a3386e409c3f8dbc7a747690a8ced27d469254edc1e3f369736e53651eedd123e70988b9f956026f50e87949796864e60ce8e58150f2d58c6d0c52eda766faee23b4dd012145e9d6932a443643809766363a88a07719c9dbb72a723fbc8b857327f256227b6ef9587cd1ecf60a9d55b9b3a3642764354194eb35e0285207913e88c839a77cc8f33627d66ade0e6d27c40d50d55d084a8660b65f4a897cf3bd86fe6282bda247ff2a23e1ab9fcfe8e50614979681e0afae319f23216d2b44d3662a43a6d2b0dce5461b040b98414d82c62db88102e4b6a8a42f3b5d3475c46e61898e34fed3fc4772323eb28f685d4b2e56ccc5022ccd80c043bf23d1b985f9c7c9512c387233aa967a40938a91b9cc13f68e9e3653adc21a7d0d4a1ad4c"
							}
						  ]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					  },
					  "version_info": {
						"block_header_version": 1,
						"orig_version": 3,
						"version": 2
					  }
				},
				{
					"amount": "0",
					"minimum_confirmations": 2,
					"message": "Ok, here are your coins"
				}
			],
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": {
			  "amount": "2100000000",
			  "fee": "8000000",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b01",
			  "lock_height": "0",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": "Please give me your coins",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdbef9a347351338e8e17651406c85ba131cf27af58fedcc14d63a0cc4ae17adb",
				  "part_sig": null,
				  "public_blind_excess": "0330724cb1977c5a1256a639d8b8b124bb9fbbf83fddb7cc20e3c17534f6ca6c54",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				},
				{
				  "id": "1",
				  "message": "Ok, here are your coins",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b79729d8c6c49b777afa756772228b648d4093d2fc3899a47dd43fe0407bf45bc",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b9eff89ca02e15d91c7081062570b61dc60dd5727a35cc2fa329528eb30c86532",
				  "public_blind_excess": "03b3041e0521339d1f47a5684a391b6185174e020274d02dffea0cc16ddb6b188b",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "tx": {
				"body": {
				  "inputs": [
					{
					  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
					  "features": "Coinbase"
					}
				  ],
				  "kernels": [
					{
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					  "features": "Plain",
					  "fee": "8000000",
					  "lock_height": "0"
					}
				  ],
				  "outputs": [
					{
					  "commit": "091f456fb46ebae63bb4b6a492de022b85fee662a720e84f9efd7fe2ddd43dfe80",
					  "features": "Plain",
					  "proof": "e0d6e1c08b353c63d05e7ba8fef0115deb9e9dd45f3240c472d157f8b4c184d642bc0599687932d992e7b8a7d23d53403fa63d9cc6faac62f811197d0c413d68018b970dc185c8ce8a6ea479b6cfead4e59d1e8481c02f83fdae4030450394c4558e8ec6f3d025b3563628f0b3146939a9ae6ac4a36af004fb46f7073b5af9ceeae1f5cf01700e241f291b146b9e98b3029589d20d535efbe669175257926014bc0c24b7ee83316f97e7f09fff39917bc7fcbe87f5ef8020f1e93883a89ef8d485513cd9a4a917ad4235e4a4b63be8e07a4fc24399183a6264bfe5fad9a03d8fc5b41baf0bd6b7e5f7dacb511ec4eb8850f89ccda0f33381878be016fa01cb0964432009e4742c2a0b9266fe054273d1fb1bb4d2d4b00a81c224eeab65cfb8eee3f13ecfb587ef3f3883fc93c7fea521ca594d3514dc70faac7ab30bcd3b56f5d3cc5705f43d82ea7ebb7164173dee2365d8bade785a820b113d6a7e64845e336131032fb9441a31770473e3e32c87e06176d85054b9e7a5b8a93ed95e3f70894b170ba74e742eb862e890b1211bb63983ed7980712321ce6b24d503e78d9a603989a41dd5ae243419cbf7918176481ea37b0b177e5ba42b7843abcebd1149a4abe377a2f1c8626312c867f611f0cc9c9be52da772a46f36838e9885e0d3050e622f2d985ff91f74df156ad28f8356ccaa3890f02473c6914c5017cb96826c144aa835dbefb427b61474547874ac00bc602d3a303a141c56719d6dea13965e537ba39191b72bd28bca2f040a711c831ab18b7e1e2b5bf70f8dd4b93b44cca4711ce38921f57da5eb1d6b014d9c40b75c36160b30603c642b816637070c826a500e7fa3f972e719a2a79f5a4be899adb8c572def853926a0eaa89362b99d5467ec6aeaf0018e0a6fb2e34616b6269da8e778ee64bfb34f6f272c950e923cb9dee557f9f"
					},
					{
					  "commit": "099210eb73958b9ff3249af117e1b41799834b219be9bfe92e47d112f797edff18",
					  "features": "Plain",
					  "proof": "edc3c76e588f3b5b76e3c511a559ecd5873d470b5902b41cee059fd027c781099ce59abec58571d4a98d1ae510d423dce5742138f897dccb268d3acbfc66f3a40eb5c3273300bd3fe2f068bd998b49d1ff2ca2c458548a4b2895a4094fe8208c9204b35dbb04bc0f475ad288928aa62cd64095c2b46db068355c8c67c2aa1591cfedfcf29474a9b6d54fd42cbcff89af6be74be0113d1d6ae2c5722e9d44677fa49e8163b40cd7fe42cd8353d9316dfe01a80e455b872ca3e07653673147b5d4f9ff6d7d4ffd505e393b91bd271e407f9ae8ecd2311dcd62e9193278a0743559048227d8a95e6b011256239b7cacf2e0b3c57709b6c0e55f1b08e8599479f23547da2df00ac4692d34d315bf740dde3c23044a848e4603b54a1398c5fcd92e81afe20a653809c979a03b844946c4d16cbc05f20009cd14819ace50319c14b3002445c36bfdf270c2add62aa611390aca92ce89ec24e0c4df8948fad4d95d6e9036180378be0ef87a020e4715c4f79ba1ec520d44eedd8beaf9b69587950cf5c65beb3a90376a3386e409c3f8dbc7a747690a8ced27d469254edc1e3f369736e53651eedd123e70988b9f956026f50e87949796864e60ce8e58150f2d58c6d0c52eda766faee23b4dd012145e9d6932a443643809766363a88a07719c9dbb72a723fbc8b857327f256227b6ef9587cd1ecf60a9d55b9b3a3642764354194eb35e0285207913e88c839a77cc8f33627d66ade0e6d27c40d50d55d084a8660b65f4a897cf3bd86fe6282bda247ff2a23e1ab9fcfe8e50614979681e0afae319f23216d2b44d3662a43a6d2b0dce5461b040b98414d82c62db88102e4b6a8a42f3b5d3475c46e61898e34fed3fc4772323eb28f685d4b2e56ccc5022ccd80c043bf23d1b985f9c7c9512c387233aa967a40938a91b9cc13f68e9e3653adc21a7d0d4a1ad4c"
					}
				  ]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
			  },
			  "version_info": {
				"block_header_version": 1,
				"orig_version": 3,
				"version": 2
			  }
			}
		  }
		}
	# "#
	# ,false, 4, false, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": [ {
			  "version_info": {
				"version": 2,
				"orig_version": 3,
				"block_header_version": 1
			  },
			  "num_participants": 2,
			  "id": "0436430c-2b02-624c-2032-570501212b00",
			  "tx": {
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"body": {
				  "inputs": [
					{
					  "features": "Coinbase",
					  "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c"
					},
					{
					  "features": "Coinbase",
					  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03"
					}
				  ],
				  "outputs": [
					{
					  "features": "Plain",
					  "commit": "096e1669267c22ecb38c466d73b8578261d8e91c14dd66702dd5bf34f4232e10db",
					  "proof": "7d567b0895a1103d19446929da8b98f2086819507ddce4b9dbb5ce6327107744e74aba59ef1834937da1b86eb7c1c1b0bc11d1c5d5ec79d25bc1e52aed1656f60d46f6878ba5ca8639efdbb9203e378e91171c11527c4a34713f06dc22f58ca4a08e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b30fb4e45d817a5053b682dcf591481a3c8174cfbba81e31aa525d5b884ca7a016713178f26c0fe8ae1f88b5382f8e70c4d91fb3828c0f307d828aa028281d3551525e68d20827ab0e6785c6b5747e895dcd38429b44e62b7f6c1c921d87ae954a9dd6e967ac52e6cd13a1d4bb2f1434da25a0723ef9c869cc573019577552dd0e0f808f8cc57723b041320025f6433779fe907998a4ec7606bf884b2199253b502065bed8e0625c2df858d6508c1aa44deddc68d06d00d81e97720e23e15a3464ed4733fc547e9fb772e563a1dbcd27ac55e40f674f9006e7dd4465444f3eb7527cb01905dee69a51cf2fc1810c861dd0834e7649d594c3e1740d85343a6b63c8a9e0a0f63059031899b38dfd9a192034d54029bd35e683ccab46282519b26cae20d398b754357abe1cf0370890f2897b5d8ada4fb3da777a8f8f1daa4197a380e6734504117dd2a92ea1917f174c44c59e0b50c6b7a5f9eb14e6d96cb6b3e5dbcb3d0eaf0e4aac1b6616d674bb708b7559e37de608e8a828bee7f25f627e2f06d9a87e8d651ade39e1e65db7204b94abc0b7ca6fdd75aadeeac6a876b6297e38039734ebdfa9a555152b4293cb00e423a66d64f827afa4748dd6fdc1dc33332bffb820dacbf5a6d347042db985bbd9cf476dceb45d6978035ba03d25612243fc164c0a902017ce7ffd632d041fa3c56554739e78c6d725ecbfdaa0739d3649239fb53294b7a46ee6ed403bf3815f6c78f06a8ca4e3c9b066234f7574fb6ea8f17d199"
					}
				  ],
				  "kernels": [
					{
					  "features": "Plain",
					  "fee": "7000000",
					  "lock_height": "0",
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					}
				  ]
				}
			  },
			  "amount": "2000000000",
			  "fee": "7000000",
			  "height": "5",
			  "lock_height": "0",
			  "participant_data": [
				{
				  "id": "0",
				  "public_blind_excess": "03ad559b009e8231fcc2a06d40b7341322974c9b13a52000ca2462df2de60aba9f",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				}
			  ]
			},
			0
		]
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,false, 5 ,true, false, false, false);

	```
	 */
	fn tx_lock_outputs(
		&self,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": [
		{
		  "version_info": {
			"version": 2,
			"orig_version": 3,
			"block_header_version": 1
		  },
		  "num_participants": 2,
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "tx": {
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"body": {
			  "inputs": [
				{
				  "features": "Coinbase",
				  "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c"
				},
				{
				  "features": "Coinbase",
				  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03"
				}
			  ],
			  "outputs": [
				{
				  "features": "Plain",
				  "commit": "082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9",
				  "proof": "828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9"
				},
				{
				  "features": "Plain",
				  "commit": "096e1669267c22ecb38c466d73b8578261d8e91c14dd66702dd5bf34f4232e10db",
				  "proof": "7d567b0895a1103d19446929da8b98f2086819507ddce4b9dbb5ce6327107744e74aba59ef1834937da1b86eb7c1c1b0bc11d1c5d5ec79d25bc1e52aed1656f60d46f6878ba5ca8639efdbb9203e378e91171c11527c4a34713f06dc22f58ca4a08e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b30fb4e45d817a5053b682dcf591481a3c8174cfbba81e31aa525d5b884ca7a016713178f26c0fe8ae1f88b5382f8e70c4d91fb3828c0f307d828aa028281d3551525e68d20827ab0e6785c6b5747e895dcd38429b44e62b7f6c1c921d87ae954a9dd6e967ac52e6cd13a1d4bb2f1434da25a0723ef9c869cc573019577552dd0e0f808f8cc57723b041320025f6433779fe907998a4ec7606bf884b2199253b502065bed8e0625c2df858d6508c1aa44deddc68d06d00d81e97720e23e15a3464ed4733fc547e9fb772e563a1dbcd27ac55e40f674f9006e7dd4465444f3eb7527cb01905dee69a51cf2fc1810c861dd0834e7649d594c3e1740d85343a6b63c8a9e0a0f63059031899b38dfd9a192034d54029bd35e683ccab46282519b26cae20d398b754357abe1cf0370890f2897b5d8ada4fb3da777a8f8f1daa4197a380e6734504117dd2a92ea1917f174c44c59e0b50c6b7a5f9eb14e6d96cb6b3e5dbcb3d0eaf0e4aac1b6616d674bb708b7559e37de608e8a828bee7f25f627e2f06d9a87e8d651ade39e1e65db7204b94abc0b7ca6fdd75aadeeac6a876b6297e38039734ebdfa9a555152b4293cb00e423a66d64f827afa4748dd6fdc1dc33332bffb820dacbf5a6d347042db985bbd9cf476dceb45d6978035ba03d25612243fc164c0a902017ce7ffd632d041fa3c56554739e78c6d725ecbfdaa0739d3649239fb53294b7a46ee6ed403bf3815f6c78f06a8ca4e3c9b066234f7574fb6ea8f17d199"
				}
			  ],
			  "kernels": [
				{
				  "features": "Plain",
				  "fee": "7000000",
				  "lock_height": "0",
				  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
				  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
				}
			  ]
			}
		  },
		  "amount": "2000000000",
		  "fee": "7000000",
		  "height": "5",
		  "lock_height": "0",
		  "participant_data": [
			{
			  "id": "0",
			  "public_blind_excess": "03ad559b009e8231fcc2a06d40b7341322974c9b13a52000ca2462df2de60aba9f",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
			  "part_sig": null,
			  "message": null,
			  "message_sig": null
			},
			{
			  "id": "1",
			  "public_blind_excess": "0256ebbe7886197266fbd2d039ec1cb8b551655bf58508dcb5c6a0179e640bafcd",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b9a1789a4e65def9f7d1aa4415b7bbca3defd6a6446bd699dccb1200748aae9f1",
			  "message": null,
			  "message_sig": null
			}
		  ]
		}
		]
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": {
		  "amount": "2000000000",
		  "fee": "7000000",
		  "height": "5",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc643703a6c817f7ed81ddff03a6fdd1d55ba27819a2dd19d0a456be257c82956",
			  "public_blind_excess": "03ad559b009e8231fcc2a06d40b7341322974c9b13a52000ca2462df2de60aba9f",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b9a1789a4e65def9f7d1aa4415b7bbca3defd6a6446bd699dccb1200748aae9f1",
			  "public_blind_excess": "0256ebbe7886197266fbd2d039ec1cb8b551655bf58508dcb5c6a0179e640bafcd",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "tx": {
			"body": {
			  "inputs": [
				{
				  "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
				  "features": "Coinbase"
				},
				{
				  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
				  "features": "Coinbase"
				}
			  ],
			  "kernels": [
				{
				  "excess": "08b3b8b83c622f630141a66c9cad96e19c78f745e4e2ddea85439f05d14a404640",
				  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d1f1ac30ec6809c5e1a983a83af0deb0635b892e5e0ea3a3bd7f68be99f721348",
				  "features": "Plain",
				  "fee": "7000000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9",
				  "features": "Plain",
				  "proof": "828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9"
				},
				{
				  "commit": "096e1669267c22ecb38c466d73b8578261d8e91c14dd66702dd5bf34f4232e10db",
				  "features": "Plain",
				  "proof": "7d567b0895a1103d19446929da8b98f2086819507ddce4b9dbb5ce6327107744e74aba59ef1834937da1b86eb7c1c1b0bc11d1c5d5ec79d25bc1e52aed1656f60d46f6878ba5ca8639efdbb9203e378e91171c11527c4a34713f06dc22f58ca4a08e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b30fb4e45d817a5053b682dcf591481a3c8174cfbba81e31aa525d5b884ca7a016713178f26c0fe8ae1f88b5382f8e70c4d91fb3828c0f307d828aa028281d3551525e68d20827ab0e6785c6b5747e895dcd38429b44e62b7f6c1c921d87ae954a9dd6e967ac52e6cd13a1d4bb2f1434da25a0723ef9c869cc573019577552dd0e0f808f8cc57723b041320025f6433779fe907998a4ec7606bf884b2199253b502065bed8e0625c2df858d6508c1aa44deddc68d06d00d81e97720e23e15a3464ed4733fc547e9fb772e563a1dbcd27ac55e40f674f9006e7dd4465444f3eb7527cb01905dee69a51cf2fc1810c861dd0834e7649d594c3e1740d85343a6b63c8a9e0a0f63059031899b38dfd9a192034d54029bd35e683ccab46282519b26cae20d398b754357abe1cf0370890f2897b5d8ada4fb3da777a8f8f1daa4197a380e6734504117dd2a92ea1917f174c44c59e0b50c6b7a5f9eb14e6d96cb6b3e5dbcb3d0eaf0e4aac1b6616d674bb708b7559e37de608e8a828bee7f25f627e2f06d9a87e8d651ade39e1e65db7204b94abc0b7ca6fdd75aadeeac6a876b6297e38039734ebdfa9a555152b4293cb00e423a66d64f827afa4748dd6fdc1dc33332bffb820dacbf5a6d347042db985bbd9cf476dceb45d6978035ba03d25612243fc164c0a902017ce7ffd632d041fa3c56554739e78c6d725ecbfdaa0739d3649239fb53294b7a46ee6ed403bf3815f6c78f06a8ca4e3c9b066234f7574fb6ea8f17d199"
				}
			  ]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
			"block_header_version": 1,
			"orig_version": 3,
			"version": 2
		  }
		}
	  }
	}
	# "#
	# , false, 5, true, true, false, false);
	```
	 */
	fn finalize_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": [
		{
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"body": {
				"inputs": [
					{
					  "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
					  "features": "Coinbase"
					},
					{
					  "commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
					  "features": "Coinbase"
					}
				],
				"outputs": [
					{
					  "commit": "082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9",
					  "features": "Plain",
					  "proof": "828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9"
					},
					{
					  "commit": "096e1669267c22ecb38c466d73b8578261d8e91c14dd66702dd5bf34f4232e10db",
					  "features": "Plain",
					  "proof": "7d567b0895a1103d19446929da8b98f2086819507ddce4b9dbb5ce6327107744e74aba59ef1834937da1b86eb7c1c1b0bc11d1c5d5ec79d25bc1e52aed1656f60d46f6878ba5ca8639efdbb9203e378e91171c11527c4a34713f06dc22f58ca4a08e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b30fb4e45d817a5053b682dcf591481a3c8174cfbba81e31aa525d5b884ca7a016713178f26c0fe8ae1f88b5382f8e70c4d91fb3828c0f307d828aa028281d3551525e68d20827ab0e6785c6b5747e895dcd38429b44e62b7f6c1c921d87ae954a9dd6e967ac52e6cd13a1d4bb2f1434da25a0723ef9c869cc573019577552dd0e0f808f8cc57723b041320025f6433779fe907998a4ec7606bf884b2199253b502065bed8e0625c2df858d6508c1aa44deddc68d06d00d81e97720e23e15a3464ed4733fc547e9fb772e563a1dbcd27ac55e40f674f9006e7dd4465444f3eb7527cb01905dee69a51cf2fc1810c861dd0834e7649d594c3e1740d85343a6b63c8a9e0a0f63059031899b38dfd9a192034d54029bd35e683ccab46282519b26cae20d398b754357abe1cf0370890f2897b5d8ada4fb3da777a8f8f1daa4197a380e6734504117dd2a92ea1917f174c44c59e0b50c6b7a5f9eb14e6d96cb6b3e5dbcb3d0eaf0e4aac1b6616d674bb708b7559e37de608e8a828bee7f25f627e2f06d9a87e8d651ade39e1e65db7204b94abc0b7ca6fdd75aadeeac6a876b6297e38039734ebdfa9a555152b4293cb00e423a66d64f827afa4748dd6fdc1dc33332bffb820dacbf5a6d347042db985bbd9cf476dceb45d6978035ba03d25612243fc164c0a902017ce7ffd632d041fa3c56554739e78c6d725ecbfdaa0739d3649239fb53294b7a46ee6ed403bf3815f6c78f06a8ca4e3c9b066234f7574fb6ea8f17d199"
					}
				],
				"kernels": [
					{
					  "excess": "08b3b8b83c622f630141a66c9cad96e19c78f745e4e2ddea85439f05d14a404640",
					  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d1f1ac30ec6809c5e1a983a83af0deb0635b892e5e0ea3a3bd7f68be99f721348",
					  "features": "Plain",
					  "fee": "7000000",
					  "lock_height": "0"
					}
				]
			}
		},
		false
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , false, 5, true, true, true, false);
	```
	 */

	fn post_tx(&self, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , false, 5, true, true, false, false);
	#
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"tx_id": 5,
			"tx_slate_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , false, 5, true, true, false, false);
	```
	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# // Short form
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": [
			{
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.mwctx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
				"tx_type": "TxSent"
			}
		]
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": {
		  "body": {
			"inputs": [
			  {
				"commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
				"features": "Coinbase"
			  },
			  {
				"commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
				"features": "Coinbase"
			  }
			],
			"kernels": [
			  {
				"excess": "000000000000000000000000000000000000000000000000000000000000000000",
				"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"features": "Plain",
				"fee": "7000000",
				"lock_height": "0"
			  }
			],
			"outputs": [
			  {
				"commit": "082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9",
				"features": "Plain",
				"proof": "828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9"
			  },
			  {
				"commit": "096e1669267c22ecb38c466d73b8578261d8e91c14dd66702dd5bf34f4232e10db",
				"features": "Plain",
				"proof": "7d567b0895a1103d19446929da8b98f2086819507ddce4b9dbb5ce6327107744e74aba59ef1834937da1b86eb7c1c1b0bc11d1c5d5ec79d25bc1e52aed1656f60d46f6878ba5ca8639efdbb9203e378e91171c11527c4a34713f06dc22f58ca4a08e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b30fb4e45d817a5053b682dcf591481a3c8174cfbba81e31aa525d5b884ca7a016713178f26c0fe8ae1f88b5382f8e70c4d91fb3828c0f307d828aa028281d3551525e68d20827ab0e6785c6b5747e895dcd38429b44e62b7f6c1c921d87ae954a9dd6e967ac52e6cd13a1d4bb2f1434da25a0723ef9c869cc573019577552dd0e0f808f8cc57723b041320025f6433779fe907998a4ec7606bf884b2199253b502065bed8e0625c2df858d6508c1aa44deddc68d06d00d81e97720e23e15a3464ed4733fc547e9fb772e563a1dbcd27ac55e40f674f9006e7dd4465444f3eb7527cb01905dee69a51cf2fc1810c861dd0834e7649d594c3e1740d85343a6b63c8a9e0a0f63059031899b38dfd9a192034d54029bd35e683ccab46282519b26cae20d398b754357abe1cf0370890f2897b5d8ada4fb3da777a8f8f1daa4197a380e6734504117dd2a92ea1917f174c44c59e0b50c6b7a5f9eb14e6d96cb6b3e5dbcb3d0eaf0e4aac1b6616d674bb708b7559e37de608e8a828bee7f25f627e2f06d9a87e8d651ade39e1e65db7204b94abc0b7ca6fdd75aadeeac6a876b6297e38039734ebdfa9a555152b4293cb00e423a66d64f827afa4748dd6fdc1dc33332bffb820dacbf5a6d347042db985bbd9cf476dceb45d6978035ba03d25612243fc164c0a902017ce7ffd632d041fa3c56554739e78c6d725ecbfdaa0739d3649239fb53294b7a46ee6ed403bf3815f6c78f06a8ca4e3c9b066234f7574fb6ea8f17d199"
			  }
			]
		  },
		  "offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		}
	  }
	}
	# "#
	# , false, 5, true, true, false, false);
	```
	 */
	fn get_stored_tx(&self, tx: &TxLogEntryAPI) -> Result<Option<TransactionV3>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": [ {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
				"payment_proof": null,
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,false, 0 ,false, false, false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": [null, false],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , false, 1, false, false, false, false);
	```
	 */
	fn scan(&self, start_height: Option<u64>, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , false, 5, false, false, false, false);
	```
	 */
	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind>;
}

impl<'a, L, C, K> OwnerRpc for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self, None).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, None, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, None, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(self, None, include_spent, refresh_from_node, tx_id)
			.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), ErrorKind> {
		Owner::retrieve_txs(self, None, refresh_from_node, tx_id, tx_slate_id)
			.map_err(|e| e.kind())
			.map(|(b, tx)| {
				(
					b,
					tx.iter()
						.map(|t| TxLogEntryAPI::from_txlogemtry(t))
						.collect(),
				)
			})
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(self, None, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, None, args, 1).map_err(|e| e.kind())?;
		let version = slate.lowest_version();
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, None, args).map_err(|e| e.kind())?;
		let version = slate.lowest_version();
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn process_invoice_tx(
		&self,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::process_invoice_tx(self, None, &Slate::from(in_slate), args)
			.map_err(|e| e.kind())?;
		let version = out_slate.lowest_version();
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let out_slate =
			Owner::finalize_tx(self, None, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		let version = out_slate.lowest_version();
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn tx_lock_outputs(
		&self,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(self, None, &Slate::from(slate), None, participant_id)
			.map_err(|e| e.kind())
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, None, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, tx: &TxLogEntryAPI) -> Result<Option<TransactionV3>, ErrorKind> {
		Owner::get_stored_tx(
			self,
			None,
			&TxLogEntry::new_from_data(
				tx.parent_key_id.clone(),
				tx.id.clone(),
				tx.tx_slate_id.clone(),
				tx.tx_type.clone(),
				tx.address.clone(),
				tx.creation_ts.clone(),
				tx.confirmation_ts.clone(),
				tx.confirmed.clone(),
				tx.output_height.clone(),
				tx.num_inputs.clone(),
				tx.num_outputs.clone(),
				tx.amount_credited.clone(),
				tx.amount_debited.clone(),
				tx.fee.clone(),
				tx.ttl_cutoff_height.clone(),
				tx.messages.clone(),
				tx.stored_tx.clone(),
				tx.kernel_excess.clone(),
				tx.kernel_lookup_min_height.clone(),
				tx.payment_proof.clone(),
				tx.input_commits
					.iter()
					.map(|s| util::from_hex(s))
					.filter(|s| s.is_ok())
					.map(|s| pedersen::Commitment::from_vec(s.unwrap()))
					.collect(),
				tx.output_commits
					.iter()
					.map(|s| util::from_hex(s))
					.filter(|s| s.is_ok())
					.map(|s| pedersen::Commitment::from_vec(s.unwrap()))
					.collect(),
			),
		)
		.map(|x| x.map(TransactionV3::from))
		.map_err(|e| e.kind())
	}

	fn post_tx(&self, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(self, None, &Transaction::from(tx), fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, None, &Slate::from(slate)).map_err(|e| e.kind())
	}

	fn scan(&self, start_height: Option<u64>, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		Owner::scan(self, None, start_height, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self, None).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
	payment_proof: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 = util::ZeroingString::from(
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch",
	);
	let empty_string = util::ZeroingString::from("");

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client1.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet1.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet1", test_dir));
	lc.create_wallet(
		None,
		Some(rec_phrase_1),
		32,
		empty_string.clone(),
		false,
		None,
	)
	.unwrap();
	let mask1 = lc
		.open_wallet(None, empty_string.clone(), use_token, true, None)
		.unwrap();
	let wallet1 = Arc::new(Mutex::new(wallet1));

	if mask1.is_some() {
		println!("WALLET 1 MASK: {:?}", mask1.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1.clone(),
	);

	let mut slate_outer = Slate::blank(2);

	let rec_phrase_2 = util::ZeroingString::from(
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile",
	);
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let mut wallet2 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client2.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet2.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet2", test_dir));
	lc.create_wallet(
		None,
		Some(rec_phrase_2),
		32,
		empty_string.clone(),
		false,
		None,
	)
	.unwrap();
	let mask2 = lc
		.open_wallet(None, empty_string, use_token, true, None)
		.unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	if mask2.is_some() {
		println!("WALLET 2 MASK: {:?}", mask2.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			1 as usize,
			false,
		);
		//update local outputs after each block, so transaction IDs stay consistent
		let (wallet_refreshed, _) = api_impl::owner::retrieve_summary_info(
			wallet1.clone(),
			(&mask1).as_ref(),
			&None,
			true,
			1,
		)
		.unwrap();
		assert!(wallet_refreshed);
	}

	let proof_address_pubkey =
		api_impl::owner::get_public_proof_address(wallet2.clone(), (&mask2).as_ref()).unwrap();
	//println!("owner_rpc Wallet 2 proof_address is ============: {}", proof_address);
	let public_proof_address = ProvableAddress::from_pub_key(&proof_address_pubkey);
	println!("public_proof address {}", public_proof_address.public_key);

	if perform_tx {
		api_impl::owner::update_wallet_state(wallet1.clone(), (&mask1).as_ref(), &None).unwrap();

		let amount = 2_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let proof_address = match payment_proof {
			true => {
				//let address = "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2";
				Some(public_proof_address)
			}
			false => None,
		};
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			address: Some(String::from("testW2")),
			payment_proof_recipient_address: proof_address,
			..Default::default()
		};
		let mut slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true, 1).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w_lock = wallet2.lock();
			let w2 = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			slate = api_impl::foreign::receive_tx(
				&mut **w2,
				(&mask2).as_ref(),
				&slate,
				Some(String::from("testW1")),
				None,
				None,
				None,
				None,
				true,
				false,
			)
			.unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			api_impl::owner::tx_lock_outputs(
				&mut **w,
				(&mask2).as_ref(),
				&slate,
				Some(String::from("testW2")),
				0,
			)
			.unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut **w, (&mask2).as_ref(), &slate, true)
				.unwrap()
				.0;
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
		slate_outer = slate;
	}

	if payment_proof {
		api_impl::owner::post_tx(&client1, &slate_outer.tx, true).unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			3 as usize,
			false,
		);
	}

	let mut api_owner = Owner::new(wallet1, None, None);
	api_owner.doctest_mode = true;
	let res = if use_token {
		let owner_api = &api_owner as &dyn OwnerRpcS;
		owner_api.handle_request(request).as_option()
	} else {
		let owner_api = &api_owner as &dyn OwnerRpc;
		owner_api.handle_request(request).as_option()
	};
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr, $payment_proof:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.

		// These cause LMDB to run out of disk space on CircleCI
		// disable for now on windows
		// TODO: Fix properly
		#[cfg(not(target_os = "windows"))]
			{
			use grin_wallet_api::run_doctest_owner;
			use serde_json;
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
			let dir = dir
				.path()
				.to_str()
				.ok_or("Failed to convert tmpdir path to string.".to_owned())
				.unwrap();

			let request_val: Value = serde_json::from_str($request).unwrap();
			let expected_response: Value = serde_json::from_str($expected_response).unwrap();

			let response = run_doctest_owner(
				request_val,
				dir,
				$use_token,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
				$payment_proof,
				)
			.unwrap()
			.unwrap();

			if response != expected_response {
				panic!(
					"(left != right) \nleft: {}\nright: {}",
					serde_json::to_string_pretty(&response).unwrap(),
					serde_json::to_string_pretty(&expected_response).unwrap()
				);
				}
			}
	};
}
