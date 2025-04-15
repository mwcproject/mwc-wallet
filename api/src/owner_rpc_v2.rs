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

//! JSON-RPC Stub generation for the Owner API
// allow for json_rpc
#![allow(deprecated)]
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v3::TransactionV3;
use crate::libwallet::{
	AcctPathMapping, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, PaymentProof, Slate, SlatePurpose, SlateVersion, StatusMessage,
	TxLogEntry, VersionedSlate, WalletInfo, WalletLCProvider,
};
use crate::types::{SlatepackInfo, TxLogEntryAPI};
use crate::util;
use crate::util::secp::pedersen;
use crate::util::Mutex;
use crate::{Owner, OwnerRpcV3};
use easy_jsonrpc_mwc;
use ed25519_dalek::PublicKey as DalekPublicKey;
use libwallet::wallet_lock_test;
use mwc_wallet_libwallet::proof::proofaddress::{self, ProvableAddress};
use mwc_wallet_util::mwc_util::secp::Secp256k1;
use std::convert::TryFrom;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// * When running `mwc-wallet owner_api` with defaults, the V2 api is available at
/// `localhost:3420/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mwc::rpc]
pub trait OwnerRpcV2: Sync + Send {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {},
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
	# , false, 4, false, false, false, false, true);
	```
	*/
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, Error>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": {
			"label" : "another account"
		},
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
	# ,false, 4, false, false, false, false, true);

	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, Error>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": {
			"label" : "default"
		},
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
	# , false, 4, false, false, false, false, true);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), Error>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
				"mmr_index": "1",
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
				"mmr_index": "2",
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
	# , false, 2, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {},
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
				"mmr_index": "1",
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
				"mmr_index": "2",
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
	# , false, 2, false, false, false, false, true);
	```
	*/
	fn retrieve_outputs(
		&self,
		include_spent: Option<bool>,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null,
				"show_last_four_days": true
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
				  "kernel_offset": null,
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
				  "reverted_after": null,
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
				  "kernel_offset": null,
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
				  "reverted_after": null,
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
	# , false, 2, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {},
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
				  "kernel_offset": null,
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
				  "reverted_after": null,
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
				  "kernel_offset": null,
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
				  "reverted_after": null,
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
	# , false, 2, false, false, false, false, true);
	```
	*/

	fn retrieve_txs(
		&self,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), Error>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
			"amount_reverted": "0",
			"last_confirmed_height": "4",
			"minimum_confirmations": "1",
			"total": "9523809520"
		  }
		]
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {},
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
			"amount_reverted": "0",
			"last_confirmed_height": "4",
			"minimum_confirmations": "1",
			"total": "9523809520"
		  }
		]
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, true);
	```
	 */

	fn retrieve_summary_info(
		&self,
		refresh_from_node: Option<bool>,
		minimum_confirmations: Option<u64>,
	) -> Result<(bool, WalletInfo), Error>;

	// 	Case with Minimal and full number of arguments.
	//  Minimal test doesn't have funds because defailt numbers of confirmations is 10, so funds are not available yet

	/**
	Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
	# // Full data request
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"args": {
				"src_acct_name": null,
				"amount": "200000000",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": true,
				"message": "my message",
				"target_slate_version": null,
				"payment_proof_recipient_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
				"ttl_blocks": null,
				"address": null,
				"estimate_only": false,
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
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "coin_type": "mwc",
		  "ttl_cutoff_height": null,
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b819534bbb4989713140b17ea203041a0260bb74e17ddecdf0b2fa80d410df5cd",
			  "part_sig": null,
			  "public_blind_excess": "02e6c0bb62e283ea33814bc85cd8ca9cd400860137f7c2f1a2b84bbfc4638a1ddc",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": {
			"receiver_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			"receiver_signature": null,
			"sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
		  },
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
				  "commit": "086e1e9e6247b3816a8a9104f4f47b2bea016702a6b2e84b1025a0c9652114bf9f",
				  "features": "Plain",
				  "proof": "5cbe0375e698bcda7147409239a0fef34f426915599085d0f6088460783337bd8d3d0ecab54d0cb5b05666df2e12bd0130ff14b56a5b02469ffa0fc0b8951fa705114f432d3cccb45fe9b42c1e5ccb5991de59d44e428ee3d82a03dc0a7bb407eedb483710a187a396992bdfa214ce4f0d09771b5bbfb21839fcb5aa16c0b02e10c5680c3f06d22e59505acdf356ba45026846e2b631793de29b6a6a705b991889f27a0fbfb2eb8982787ae82b4991a18e15b332deaaabcebd2b1234c556d2c0bdc1ef133890b83f84344e766e7dc13ee3f46363bb9e4847f415621baf4a6929f41ee9b016453ace4d6847d254e774026e5d71ae05636ed40718b449ecf76431a84cb835f71b59f569b984a967eb45ffcf7f0969e986209b9037f2c2a7e51b4412c30796b6604543a71a40d8bac984d2df0fd66200f6798e5bdcc2c11b524fdeb2233708dbb2d9ba0983640402454a8216cfe6b1c046463b8f58cf71adb23f41917e028dfa7ff9de53f0b13e99b7b8bb18c81d2b3ef9c320b93d849f5c00dc703db2e0d0fc5949755aca090fd1f5ae622a8dbbc85d895baca50bf97cb6fb9f0c84f204be2e498a692dd9bd941c1f42a45e36b1d68999ba4ce0fae9054962da994cb7da12a0e095ea8711c14b39e7ff596c3deeff18a7751a5fa38377fddb8d26c7639a76312c962bbef49fe2414f24f6aa6c33e22cf45898bbb55feae12891df986229a97098e9ee315a9f7beff9e0f6c87af3d70f922f678c7bcc0f1f025a8dfe77b4adbc4e287269adb947786eee193a8b666640be02cbb61617f916c9563481f5cebf6ae531b1e493a6f570a898e36d461bc101e517db0487a92efc1e42e7af9d2e06f10847a23e78f8e90c62820bf250c299eac1d7798210434697774ba9d7e2c5853fff28614a5d408266b8924f72202153c01a477ebe2f68eb3813572869aca1"
				}
			  ]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
			"block_header_version": 2,
			"orig_version": 3,
			"version": 3
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, false);
	#
	# // Short request. minimum_confirmations is optional but we put it, otherwise there will be not enough funds for default value 10
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"args": {
				"amount": "200000000",
				"minimum_confirmations": 2
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
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b01",
		  "lock_height": "0",
		  "num_participants": 2,
		  "coin_type": "mwc",
		  "network_type": "automatedtests",
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": null,
			  "public_blind_excess": "02e6c0bb62e283ea33814bc85cd8ca9cd400860137f7c2f1a2b84bbfc4638a1ddc",
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
				  "commit": "086e1e9e6247b3816a8a9104f4f47b2bea016702a6b2e84b1025a0c9652114bf9f",
				  "features": "Plain",
				  "proof": "5cbe0375e698bcda7147409239a0fef34f426915599085d0f6088460783337bd8d3d0ecab54d0cb5b05666df2e12bd0130ff14b56a5b02469ffa0fc0b8951fa705114f432d3cccb45fe9b42c1e5ccb5991de59d44e428ee3d82a03dc0a7bb407eedb483710a187a396992bdfa214ce4f0d09771b5bbfb21839fcb5aa16c0b02e10c5680c3f06d22e59505acdf356ba45026846e2b631793de29b6a6a705b991889f27a0fbfb2eb8982787ae82b4991a18e15b332deaaabcebd2b1234c556d2c0bdc1ef133890b83f84344e766e7dc13ee3f46363bb9e4847f415621baf4a6929f41ee9b016453ace4d6847d254e774026e5d71ae05636ed40718b449ecf76431a84cb835f71b59f569b984a967eb45ffcf7f0969e986209b9037f2c2a7e51b4412c30796b6604543a71a40d8bac984d2df0fd66200f6798e5bdcc2c11b524fdeb2233708dbb2d9ba0983640402454a8216cfe6b1c046463b8f58cf71adb23f41917e028dfa7ff9de53f0b13e99b7b8bb18c81d2b3ef9c320b93d849f5c00dc703db2e0d0fc5949755aca090fd1f5ae622a8dbbc85d895baca50bf97cb6fb9f0c84f204be2e498a692dd9bd941c1f42a45e36b1d68999ba4ce0fae9054962da994cb7da12a0e095ea8711c14b39e7ff596c3deeff18a7751a5fa38377fddb8d26c7639a76312c962bbef49fe2414f24f6aa6c33e22cf45898bbb55feae12891df986229a97098e9ee315a9f7beff9e0f6c87af3d70f922f678c7bcc0f1f025a8dfe77b4adbc4e287269adb947786eee193a8b666640be02cbb61617f916c9563481f5cebf6ae531b1e493a6f570a898e36d461bc101e517db0487a92efc1e42e7af9d2e06f10847a23e78f8e90c62820bf250c299eac1d7798210434697774ba9d7e2c5853fff28614a5d408266b8924f72202153c01a477ebe2f68eb3813572869aca1"
				}
			  ]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
			"block_header_version": 2,
			"orig_version": 3,
			"version": 2
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, false);
	#
	# // Compact slate request that will be ready for compacting to slatepack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"args": {
				"src_acct_name": null,
				"amount": "200000000",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": true,
				"message": "my message",
				"target_slate_version": null,
				"payment_proof_recipient_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
				"ttl_blocks": null,
				"address": null,
				"estimate_only": false,
				"send_args": null,
				"slatepack_recipient" : {
					"domain": "",
					"port": null,
					"public_key": "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd"
				},
				"late_lock" : true
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
		  "coin_type": "mwc",
		  "compact_slate": true,
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b02",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b7f9d23b4293ae333244716b93f8c85153042fe7e3375eab56ceccb786c66c917",
			  "part_sig": null,
			  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": {
			"receiver_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			"receiver_signature": null,
			"sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
		  },
		  "ttl_cutoff_height": null,
		  "tx": {
			"body": {
			  "inputs": [],
			  "kernels": [],
			  "outputs": []
			},
			"offset": "0000000000000000000000000000000000000000000000000000000000000000"
		  },
		  "version_info": {
			"block_header_version": 2,
			"orig_version": 3,
			"version": 3
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, true);
	#
	# // Producing compact slate that can be converted into the slatepack with target_slate_version = 4.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"args": {
				"amount": "200000000",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": true,
				"target_slate_version": 4,
				"exclude_change_outputs": true,
				"minimum_confirmations_change_outputs": 1
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
		  "coin_type": "mwc",
		  "compact_slate": true,
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b03",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": null,
			  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": null,
		  "ttl_cutoff_height": null,
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
				  "commit": "086e1e9e6247b3816a8a9104f4f47b2bea016702a6b2e84b1025a0c9652114bf9f",
				  "features": "Plain",
				  "proof": "5cbe0375e698bcda7147409239a0fef34f426915599085d0f6088460783337bd8d3d0ecab54d0cb5b05666df2e12bd0130ff14b56a5b02469ffa0fc0b8951fa705114f432d3cccb45fe9b42c1e5ccb5991de59d44e428ee3d82a03dc0a7bb407eedb483710a187a396992bdfa214ce4f0d09771b5bbfb21839fcb5aa16c0b02e10c5680c3f06d22e59505acdf356ba45026846e2b631793de29b6a6a705b991889f27a0fbfb2eb8982787ae82b4991a18e15b332deaaabcebd2b1234c556d2c0bdc1ef133890b83f84344e766e7dc13ee3f46363bb9e4847f415621baf4a6929f41ee9b016453ace4d6847d254e774026e5d71ae05636ed40718b449ecf76431a84cb835f71b59f569b984a967eb45ffcf7f0969e986209b9037f2c2a7e51b4412c30796b6604543a71a40d8bac984d2df0fd66200f6798e5bdcc2c11b524fdeb2233708dbb2d9ba0983640402454a8216cfe6b1c046463b8f58cf71adb23f41917e028dfa7ff9de53f0b13e99b7b8bb18c81d2b3ef9c320b93d849f5c00dc703db2e0d0fc5949755aca090fd1f5ae622a8dbbc85d895baca50bf97cb6fb9f0c84f204be2e498a692dd9bd941c1f42a45e36b1d68999ba4ce0fae9054962da994cb7da12a0e095ea8711c14b39e7ff596c3deeff18a7751a5fa38377fddb8d26c7639a76312c962bbef49fe2414f24f6aa6c33e22cf45898bbb55feae12891df986229a97098e9ee315a9f7beff9e0f6c87af3d70f922f678c7bcc0f1f025a8dfe77b4adbc4e287269adb947786eee193a8b666640be02cbb61617f916c9563481f5cebf6ae531b1e493a6f570a898e36d461bc101e517db0487a92efc1e42e7af9d2e06f10847a23e78f8e90c62820bf250c299eac1d7798210434697774ba9d7e2c5853fff28614a5d408266b8924f72202153c01a477ebe2f68eb3813572869aca1"
				}
			  ]
			},
			"offset": "0000000000000000000000000000000000000000000000000000000000000000"
		  },
		  "version_info": {
			"block_header_version": 2,
			"orig_version": 3,
			"version": 3
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, false);
	#
	# // Testing low 'max_outputs' value. Expecting to get error that slate is too large
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"args": {
				"amount": "20000000",
				"minimum_confirmations": 2,
				"max_outputs": 2
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
		  "TooLargeSlate": 2
		}
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
	# // Minimal list of arguments
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
		  "coin_type": "mwc",
		  "fee": "0",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "network_type": "automatedtests",
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
			"block_header_version": 2,
			"orig_version": 3,
			"version": 2
		  }
		}
	  }
	}
	# "#
	# ,false , 4, false, false, false, false, false);
	#
	# // Full list of arguments
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "issue_invoice_tx",
		"params": {
			"args": {
				"amount": "2000000000",
				"message": "Please give me your coins",
				"dest_acct_name": null,
				"target_slate_version": null
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
		  "coin_type": "mwc",
		  "fee": "0",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b01",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": "Please give me your coins",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba7ff367e448dc20229c8ba07f8835d22cc48d9e153077ae58fb7ba92622469cb",
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
			"block_header_version": 2,
			"orig_version": 3,
			"version": 2
		  }
		}
	  }
	}
	# "#
	# , false, 4, false, false, false, false, false);
	#
	# // Compact Slate, can be converted into the slatepack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	# {
		"jsonrpc": "2.0",
		"method": "issue_invoice_tx",
		"params": {
			"args": {
				"amount": "2000000000",
				"message": "Please give me your coins",
				"dest_acct_name": null,
				"target_slate_version": null,
				"slatepack_recipient" : {
					"domain": "",
					"port": null,
					"public_key": "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd"
				}
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
		"Ok": "BEGINSLATEPACK. CD7MfBUbThCtDiA cdRUEr4KKm4Uwn4 z1LzfJ29o61nKAW Qc8WjGcpXHfn6po dYi5seYKNurEkMf MDJyLEQN9mUXDvy ModjyEmuTtpEDF1 xE286XvRdYPNkjM BnXg7sdzuHK1xVL iK5srPup1vAyEhM GJDGcLxFP4dyWdN zVqNsa6pMy8WJzv QPtF784fKDzPh7Z BPDvNXzvAz5nSkL 1c2FFvQzrvZudCy 1x33VwLDER6UzyD kpFFfxGqx5NLeTG Qy19AHrEUes1ecR wqPBSiGd3t8mdAB 44muWRz9AcriAbH ntZWUzgzyWVH5m2 nMQzau7fmpZbRqi PpZERxsVWxPksh1 UfrgtULqitKWVQ8 rD9NCbj5czuXf. ENDSLATEPACK."
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, true);
	```
	*/

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "process_invoice_tx",
		"params": {
			"slate": {
				  "amount": "2100000000",
				  "fee": "0",
				  "height": "4",
				  "id": "0436430c-2b02-624c-2032-570501212b01",
				  "lock_height": "0",
				  "coin_type": null,
				  "network_type": null,
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
					"block_header_version": 2,
					"orig_version": 3,
					"version": 2
				  }
			},
			"args": {
				"src_acct_name": null,
				"amount": "0",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": true,
				"message": "Ok, here are your mwcs",
				"target_slate_version": null,
				"payment_proof_recipient_address": null,
				"ttl_blocks": null,
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
		  "amount": "2100000000",
		  "coin_type": "mwc",
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b01",
		  "lock_height": "0",
		  "network_type": "automatedtests",
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
			  "message": "Ok, here are your mwcs",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bcf011cad082b7f92cee5cc4546688760c1ec1af07b81d572c8548f39dece9344",
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
				  "proof": "a96040e55beee3c77b0c916372085e75dc984d1b7a0354e7516c3e4b5072266072ef111a03c68f643ea4f0d967f1e04ae4ec601185470b0ab8a636497667f0e405b52a57043a76508b3f5631545ae00d43db1c2a05a656142159676629d941027d8e8ec6f3d025b3563628f0b3146939a9ae6ac4a36af004fb46f7073b5af9ceeab81607219858108ad86f57c11b708b911d366890d798846a0ade70c8d2ee065ad2b9382f236867a9c8f9febdd8d6a0f91b64b9c7ca96dca9a68263eeb1d726f2c01bd94678d54a30879e873738ed3fd87d13b6f5586aa5168cdae12c2ef72614f3bc0504770c74276d4e35d5f80115c97b1774a3fba01e8cc113b1391c1bbea599db0987b80f995e0b6ceb69e706561cac276b9055c99f8418328e779b017ee0e3001dddd284d447a846ac1b88326af8baea6918cd77b16f3b7ddf8d79b4d145a20cdc0d66b56ad9ae121c6f8fa1fdd7207af69034ceedcfec6c1166b9d92967e703a1de7e081e35d724898796a49b6cc15ca88750b8decf468a9b0384390d5a8852f122155c61400e608fe87c3a2b5eae74284897ca26047feaa72349752c0be8ea9229e00821d02592c6ab3ab489e2f0553b0aac0f8cb6813e8f1e496ee267a0d6520f3a71ef6f0a8916a59a998b1b5154f76b0575cfe7da95c4348d8f631f03ddecd264d027b671240c2230ade342e75a7d0a814045e61db93cdb8b5228c1831abe67dccb4d2075b36c91af0c449da96540582b7f1b805a9dd6b32198093af9cc999575e9898d28a0e3589a59b71a284fd6c8a777c7a8dd7a96604c097cd10b83de9de0efa5a4d2a54b6b586453b88f8b1ceff9b55db04f020554d53c346f6229d30a5c87d766fc92a9480cb9f6a9384e79fc4e5de093611cdaf405f691837d4e41fbce291ea19d95cb426c5d216b397d645c0bfaf4cd2614d4532b1ea00d07e1"
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
			"block_header_version": 2,
			"orig_version": 3,
			"version": 2
		  }
		}
	  }
	}
	# "#
	# , false, 4, false, false, false, false, false);
	#
	# // Compact slate processing, V3
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"slate": {
				  "amount": "2000000000",
				  "some_data_to_check_that_it_will_be_skipped" : 4,
				  "coin_type": "mwc",
				  "compact_slate": true,
				  "fee": "0",
				  "height": "4",
				  "id": "0436430c-2b02-624c-2032-570501212b00",
				  "lock_height": "0",
				  "num_participants": 2,
				  "participant_data": [
					{
					  "id": "0",
					  "message": "Please give me your coins",
					  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b8e466fa4596adb9436b38e35feb34c4af52bdf913034b7ae425a35437d521c07",
					  "part_sig": null,
					  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
					  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				  ],
				  "payment_proof": null,
				  "ttl_cutoff_height": null,
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
					"offset": "0000000000000000000000000000000000000000000000000000000000000000"
				  },
				  "version_info": {
					"block_header_version": 2,
					"orig_version": 3,
					"version": 3
				  }
				},
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "Ok, here are your mwcs",
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
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
			  "amount": "2000000000",
			  "coin_type": "mwc",
			  "compact_slate": true,
			  "fee": "8000000",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b00",
			  "lock_height": "0",
			  "network_type": "automatedtests",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": "Please give me your coins",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b8e466fa4596adb9436b38e35feb34c4af52bdf913034b7ae425a35437d521c07",
				  "part_sig": null,
				  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				},
				{
				  "id": "1",
				  "message": "Ok, here are your mwcs",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba6b472f5cbc5ef2745dfc68c43b829dc46ca5a4ea308338c82e42404621a0762",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb431617fb560348f12fb9a288fd758a3189958a50d5cea436417539314b235f9",
				  "public_blind_excess": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "payment_proof": null,
			  "ttl_cutoff_height": null,
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
					  "commit": "08060fd6fb7d5ccb0fba022908480bfd63a3697e8ea6ac37bc030f8f79bfd456f9",
					  "features": "Plain",
					  "proof": "612f1a1680b0a0aa3be975e7d240f6d241f879fc2dbfc4f012986e907438364002c3614fd2fa286e411679234fe1f5d7875b75ad003bf1d1f51125ccc922287501c7b3d688a66a9454b01d85d96246075846a2ff352bc88f0b5910b19aa4a199ea006518bdd287245774532861c023c080fc4dc15f388f8d36f0caec75e2cef9c36212a67a0b87f797079e1d3f2c569f8d572ece50a6ba58fba196c3295d5a37edfdba943ad26214d8a7434c48bd7b7c8490d54b96a7efbe7662c5a87ebd8f206c84533d757a485901c942fde40c6062e6d93ff926b42cf387f2e251965da40943b740db465c3dd7cb541e7684c9cd574d2e53d9cab534622ea0f299f6cb731fb3a4d76d9e86b2584306393ee3a9d9de88095782179a9285dad7f6a19ce5179f3ef1e4e163f56fe03519cfa76d0412eac135f850ecca7f131547a053bf956534542749c15ab697ca40323116174862ee510942b5955aaa1ce7cb82db6387e3b8f74b018ef2ce2f38716f5962a630b28026a5b242309355d8055abdba3046e4c68e737e852c014ac4cc31f6d8386a724ae99fbf407685c5478343f0cf283eea5c3c4104a440ab2b738478592da08f18d70b85fdface7ce649f8b9e86e8658f8517df888a0d1a2b5a892af63fed7194c84b58e38b665091ca672c8e557a539b8f454e722665c861bfaa87519ea3e6c9e31b98b72f9a164d6f192e8ac5798d90f7cf843479534ec7d2cc292736a3b8eb47282ca5d93cd1c74306e2957c72c2e35ad0488014361cd4a8f3f2108c794914b907314ef307002db9449f04ccf84d91a97c6c98b7dedb5231bb638fc05ab946a204ae2a49d6000201af197bbded8df64e3daa8478ae955e0dc364f673c95a25f315cfafba437e763d8aff5deaa453e6ce11a997cd6810a843658f85f070cfefab95f530f7aadd76e0a2a224a9a5a0f2b69e9e05c"
					  },
					{
					  "commit": "088119ed65640d33407d84da4992850eb6a5c2b68ad2ff2323dee51495599bc42d",
					  "features": "Plain",
					  "proof": "5035e8cc9a8f35353bf73124ef12b3f7cff7dbcfcc8476c796f62bdf48000e7c87a0a70f2deb44f502bf3be08302d2affb51ae9b7b7d21b96752dc9bd22932520c46311cc0492b1a8e5bcd5c12df5eda2a05860c9db2ac178a2c1c5c01acf3859b068c927a300a4d883b03f03a062dd8475174d8d1770dca2d24e60a8899907b8b425346f1c75c8febaf4b21d81666d9fb6af62f8059f55677a8cef90e64be362d6c7232e009209fbe4a1b1918211109d3d16f08fc018b1a3d3bd11be9495a6a40cbb433130f74b2e0fd4d97da78e623f329922e07a791aab6c93a477449c04894cfdba37a3748fd7fd7203b93e73b00299e367efa5411cd5da70104dc25fda3497c3c99bda84f3bce4c205cb27d72979bdcbfa495599d9804cba3096319c3c5c4aaeeadbda2b185196a3b5785c3e68de0ec260cb1450cfbe0934c78f61a4df8632018e731016aa82dab83f09670534e04c044d20eaa2b9281bdf6d3677be6fab54203b95701c8a962638e78706b3024c61994b420705934f9f7fdd36bc00431cea462edbabbef2aea62cf422a736f02f8852c53996d0e663648f67838b2f084db39b115de1dc05047803071e1ac2ce25e5d2ecf41a83f12adb88ee336ba6e04b52a59fe138245ed2a2ff46ff38221ee7fcf311bb330947766d8f695ec990efe63df358bd17d15d825c42b8de93cf740a22a0328781e76e92f210ba0ae989c4290f3035b208b27a616076b6873e851f3b5b74ad8bbd01cbebcc7b5d0c0d7c4604136106d1086f71b467d06c7c91caf913fc2bc588762fd63ce4ed2f85b1befdd4fa29ae073b943fc00fc9a675a676d6d3be03e1b7ac351379966fc5bcf8584508b975974fd98c3062861e588453a96296fae97488f42662f55af630389a436707940a673a36e19fc720c859660eabc9de31b4e48cef26b88b8a3af462c8ad62f461714"
					}
				  ]
				},
				"offset": "b371a7ddba22c34a82655137fcd088ed7f130080aac0b2e3c933e6262c970313"
			  },
			  "version_info": {
				"block_header_version": 2,
				"orig_version": 3,
				"version": 3
			  }
			}
		  }
		}
	# "#
	# , false, 4, false, false, false, false, true);
	#
	# // Slatepack payload
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"slate": "BEGINSLATEPACK. CD7MfBUbThCtDiA cdRUEr4KKm4Uwn4 z1LzfJ29o61nKAW Qc8WjGcpXHfn6po dYi5seYKNurEkMf MDJyLEQN9mUXDvy ModjyEmuTtpEDF1 xE286XvRdYPNkjM BnXg7sdzuHK1xVL iK5srPup1vAyEhM GJDGcLxFP4dyWdN zVqNsa6pMy8WJzv QPtF784fKDzPh7Z BPDvNXzvAz5nSkL 1c2FFvQzrvZudCy 1x33VwLDER6UzyD kpFFfxGqx5NLeTG Qy19AHrEUes1ecR wqPBSiGd3t8mdAB 44muWRz9AcriAbH ntZWUzgzyWVH5m2 nMQzau7fmpZbRqi PpZERxsVWxPksh1 UfrgtULqitKWVQ8 rD9NCbj5czuXf. ENDSLATEPACK.",
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "Ok, here are your mwcs",
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
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
			"Ok": "BEGINSLATEPACK. Sm4xZGYS8duoYWS pt8JCkYPxnShZp3 o91CusaUNkuaAGt WEm5MG2HayRfZ9j RshWAUnxuSsp1AH 62xMedzxR3ueMru f2qLubPQm7Y3c7M 6qQsLkH8cGMRjLC jqpRgoDbujKavMH dTtJxi6JDMrsaj9 ZieNjJayy7Bz7f6 oVkaCGnCwjEX58C sJM4Yb45qXSgmZp A3qbBduCgEmBnMg AocCXC1tHM62uza BUwfY79FZuzYjSS nF3zRGDcHaahPkS KhFr4nLPxejRNtB RxjfGTfMCEP1MKL C7PyQipqth68SpK dL2eSdnV9m7JrYD 8hXL1mpuMT6Wgud kejmnk19K6Yq1Gz kGPveW8U8FSSEm9 oD7MipfCy7ZKuAa e4QbTsnCaTgb8vU Xi8FReExfFgys6i P7nhNyBRx63LGzy iCPJ8GG4qK5NXYe dwtJRjyuHkr7nud 2JNtvAYzFoFivNm CDvutm5Jt1Z7s6h v6m1Z3gg3iD3DTn Hbpj37WAHXzRWJD XpBXrZxPgXdu3qJ t2pU3TzikieNgHH kza6NepbrjN3Jcn xeZY9DBRdWFSLGk xeGqs5GzdxQAdky Z5mC59xwfcU7QGB RxuX66ZKwb5Dhi2 iLrTsGGcQCtB2bn 7uVge6PEa9qhpKz VoeoCMAs6mYypCX 6VzfCmJngvsiGXT uAusyqTG218ZT5J XGJYTu6yfavHf3X HgqQjf7e28y8Ump AirrEbnV8JEpXCs 5cqBwJUY13Jqd7z 2WcZ14Zcxex7cN6 EtXTQTaG17LGk2y Nys4yxYgnq537Cq LMte581nFzPpSNE kvYMtCJ6E4Mj59c zB4XLNmfPYWoP8o gp7zcRUJq6rNgeX jxJsbuUWfNDXZvs RNNMG9HjKztTpF1 RhNSZLQPLUv7oCq 3TKZWCqXEEntsTn X1wFJu8EbvE5J5Z 97DTUedeCGVm2R6 RMNFagqTYhvvzbY 1eyX91qCwrkTNfb zBFtE8j2X6PLi2U TPnTk9sXhoWrHYA iXdm9nzfgGsYMTB Mvhvpg6TsgjcDmg Vz7oVXuqstLjCXz ZY2YRjmv9bwUWNc 3pimJKyFUP9xA5z X2hmxPkCYzMB2gg M9uqmJpJnfF7Mnv urYpvyPA5fBQ2Ee k93kjMBaazT5eEb r5rB9GCg4jMkwEH tVhqfSu7NaUDJiX pt5oWaRCB4Q1cSD oYfA83Qdvs2add4 jVHzjHxhCnY3DP5 zFUTT622jU8GJqC HcuWuMcpRTf21EQ G7PbUorQ21KsJ6K GHJZjXLMLCBErhW rKUTys6ofwRo8Dg 5TY1zQpu7ZuVhdk LCTa58UgJaWJj9j ucU383xqqMwiQFJ 1n8G1JnNmZ9dopC uR1trzDixRauXQB QmYewp3NmuBJ2Yz 1h98s155sqTqTY7 3q89hARR4S1zaYg rQcU37q1E5g1Mvu Wk6fkLwpK1dWPDT qQueq2hBt1XvjQy JVWS6JfRTARZNXb cCGBmMRertgmsPL GryY9ebc6J36ELC 2UHeaQU2Yzb5PXm RbMwhKeUMhEYbcX ee3u2hzA3K3USzh yzCuGpbMs4jtB8f gUVYssTw4Dxj5G1 wmiuPVsF3V2GoED PsfjrFEMfQGCh3Y KwzJfzfLeRbqjth 22qFEFvvVVnpcd5 cqyFWYWo6D9rXLK h1Gi. ENDSLATEPACK."
		}
		}
	# "#
	# , false, 4, false, false, false, false, true);
	```
	*/

	fn process_invoice_tx(
		&self,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"slate": {
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
			  "coin_type": "mwc",
			  "network_type": "automatedtests",
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
			"participant_id": 0
		}
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
	# , false, 5 ,true, false, false, false, false);
	#
	# // test for compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"slate": {
			  "amount": "200000000",
			  "coin_type": "mwc",
			  "compact_slate": true,
			  "fee": "8000000",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b01",
			  "lock_height": "0",
			  "network_type": "automatedtests",
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": "my message",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b7f9d23b4293ae333244716b93f8c85153042fe7e3375eab56ceccb786c66c917",
				  "part_sig": null,
				  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "ttl_cutoff_height": null,
			  "tx": {
				"body": {
				  "inputs": [],
				  "kernels": [],
				  "outputs": []
				},
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "version_info": {
				"block_header_version": 2,
				"orig_version": 3,
				"version": 3
			  }
			},
			"participant_id": 0
		}
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
	# , false, 5 ,true, false, false, false, true);
	#
	# // Slatepack processing
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"slate": "BEGINSLATEPACK. 78D5yXBmC2t4fQ5 ZNwtM3YncAH1bZZ 19fotVi4TM2mY7E AbDHZVyiX6zhNFW UZmyL5AbufF5kyP Q6ekjrhm5J5R7wv r4cdUTpbttyytAf p6x6M8SSoTT5qSP YwbhBta78KtSz6J 9rx8xisfw7T2Rh1 W2nRpB6TCnS8h15 ArsUfK6ppY8ZCsW Ny2gxC7jQJj7yWi 72j514HZwSs7qbX 8BvCWH7f2k29K7E 8mM4gv2fYkbbaUT hv9z4oU3ixnocFd YrYr25PNyp6n5ar JPCbXNGZV82zJZh WTXZ4XNY17jJc5S Y6pS8MNGB1EjG2H 1gqBANTaTwrkLXE 5N42xskNEhtAFwp RqcZaEzcEgtCadU wrz5ba8F3Aa3g9n Fm9XbHGD3qJsbCu X7dg5eunEvubDpP nbqXeZsGu4eMBhJ aEw9LN4FiTxZZKv D7rQJM67UcH44ou Hx4B5pRVd7bbopf BGmG23uwhh9ASUU 5vx2NkGGH8coRUW vJnKsxB2DNKdv3V ZhJPRq98QtFqTw8 ZpHj3XCYsxzrZ6D MeZXNmFC1BFR7ew zCRobkFFVvXiZ56 NoKqFxVydSzyPVw 2Sy9y1yFxXnWaZz 9ji1oUQQVSSozjS M42WhZaf8rHEGSs jkL4fBrZ12oBaNN K2KUbiHdngtS4bd r12QgT2nPamqizj au8yMNqHLhYFC2A R89a38gbJtwaFrX x4KVqRyXXYTijFu dXfrgB4A39ePyQr ZrPoBmcp4AHDUdf yGmfX83rLVtednY dVULZ63TNTzC393 CDffkNxSt3JKjoV GVTv4BMxSu4YDcv YEvBkoVkdABYkyH M8SKCeLgHMfYRM7 GHcKPauzo636oR5 JjZndjphUfPUpAR Ejj4UAdYqDWvkPV YnbfUHrYjsdszmB 2TAWSyNk6npe1h7 HKwnddyWJzxm1DE WgEVTLCTb2qsMm1 8viMY1UsdYYfMiy 1ytoqZqAPWwWxR4 qHEFYhU63Aq2pjm 4KiLVtkr1LNygFb eFCb6ZeVqu9xKGT 71NnR5j7B5sGuKm YSfX8LopuHV7Ewk aBdrtxpkSzQfr7d 8x6GZPh2pxPg9xW UywhYxDoRbts1Q9 D4m63djAfA9jPYu MEQWiDhnDf1v4CD s7CcYyiyi3MX1Gk JbHyBLaKfkNyA6p e6LWmFm5dJusfco Ej2CyYyC632fE8Z PfxWgiCNEphe1kX W7F529X8NRVKEj8 qUccuviVC7GR94q EecQ8hVK1TbrTAQ MM1QYFxSTrA1qEg PTvKdwxAs1Qb6Ej 8Jkb7nrXALDzSct edf6i5QygNRnZup VYKdBeznoSYpG7D rjTPQJBNLtJ4t46 7sD2FZL5edzb4Ah LZ3zPmpXeLDemU2 NJ6qRXJbPpZQbWW hZ3rFMd4UMfm2Zc BVrfgjeqskCVAtu 6hvxm9eY91xuYzu JWMQUYSZWENQqcU mfd6RgrPFH7wtpm cB4Sv1o9C6LXidR v2srdppm3gTQyMV 9V5NXFykMbqpcJX iWrDVwWi2DELt1P N4NvdkdTxq6LNup okimDBoCYKbH4Va zYgzdJeZ872Jp3M Mg4qUGLFd8SHZED PJsx7B7jmZ62fPq UAi39HU8nRH5GYS y2iZB2rH8j8GD4Q hZ5wUSSi7jq46WZ 4KVY6iuCpLrgYwU Hn6DCbNVmNrNK9t bSBXEJQYqbXkHwQ bTccv3LJ3b5dtEa NzwvwUv833FdpxK hvh5e6zd2Gph7Ms ELhd19sPYfvFmWH RvqWrYgbdUjs7Rf WEeM998zqL7RjM2 trmizdfVMjxCrKk pp94TnVyyPfDBgE LtYwquWnzsjUDqh 8Wm9cV1dcAzuZyr pDsqQ5i89vieieN ZAtqhJb1agE6XC3 zwzVAdMuGvLLZVf MB2XrtWWcRxks9H AvqgVUxtRrS8e8f tNTw5aJxP8fJksZ UXXq68BGcV9wt3w T8NoAetqxKeL22c QyFg1VHoeNHczML NtY49ip3LKQ1vL6 yKrjAQ12TY7vZVj f3DnAHFDb5DeA6t RYwnhCamBubygiK KvYYTV5Y8RDW551 Xqp2kmWKr6tBrJ2 QBVgP4G5JcWrCRp jgR4Dq3crmnR9o4 5vgT5UFrLYydsYX 5NWKCdkkJ66KVPE cEgpqYo5eBoyade fSgXhv4CvRVYtk2 HQRcjbUVrFS2KJ1 RdJuxr8dY6QgihK ZNwCqDQHRx3NCGv aW2V2QzAqbSMQsK cnuZUYwWFZ9nZWs kD8uxYre9jwe9Wp DNpP8iB3AWuP1Kx AUu2Hu4c3PnXSi5 uDPUGmDjcWtUxUv pUj3yNE1XzBJxPH nqstVEP5PqLjUAr 8afecWyaCeNaXq3 KtmWe8fzyEYQ7TJ QSe5QKYAKjUfiCE 4zJofoamEthP9LE wwwXDGpSq8sUb8Y owWi6BVY6MCTCX6 yixBxPgWrtqSYwk BUi5wNA7ybCtMY5 a17ovnwkSbrCoZD dyHCSYTrs7zq5jP FNRK. ENDSLATEPACK.",
			"participant_id": 0
		}
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
	# , false, 5 ,true, false, false, false, true);
	```
	 */
	fn tx_lock_outputs(&self, slate: VersionedSlate, participant_id: usize) -> Result<(), Error>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"slate": {
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
			  "coin_type": "mwc",
			  "network_type": "automatedtests",
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
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
		"Ok": {
			  "amount": "2000000000",
			  "fee": "7000000",
			  "height": "5",
			  "id": "0436430c-2b02-624c-2032-570501212b00",
			  "lock_height": "0",
			  "coin_type": "mwc",
			  "network_type": "automatedtests",
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
	# , false, 5, true, true, false, false, false);
	#
	# // Compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"slate": {
			  "version_info": {
				"version": 3,
				"orig_version": 3,
				"block_header_version": 2
			  },
			  "num_participants": 2,
			  "id": "0436430c-2b02-624c-2032-570501212b01",
			  "tx": {
				"offset": "97e0fccd0b805d10065a4f8ca46aa6cc73f0962e829c7f13836e2c8371da6293",
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
			  "ttl_cutoff_height": null,
			  "coin_type": "mwc",
			  "network_type": "automatedtests",
			  "participant_data": [
				{
				  "id": "0",
				  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				},
				{
				  "id": "1",
				  "public_blind_excess": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb9128fbee3070329b28c635090138e2b78fe1fbb840117b2f65777508179be0a",
				  "message": null,
				  "message_sig": null
				}
			  ],
			  "payment_proof": null,
			  "compact_slate": true
			}
		}
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
		  "coin_type": "mwc",
		  "compact_slate": true,
		  "fee": "7000000",
		  "height": "5",
		  "id": "0436430c-2b02-624c-2032-570501212b01",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be4f05245454b9681075ed2f92baefea88971d1b8192abdc79d08683e9ef18c98",
			  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb9128fbee3070329b28c635090138e2b78fe1fbb840117b2f65777508179be0a",
			  "public_blind_excess": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": null,
		  "ttl_cutoff_height": null,
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
				  "excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
				  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4d9d03e203295399aab9ea354abcc18cd40170f1739e2bd4799460df8e1f6b4ba3",
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
			"offset": "e88c17b8cdcb6606c3d263a8fb4be8fd6bd9d435852c6ff78602385bb31a8849"
		  },
		  "version_info": {
			"block_header_version": 2,
			"orig_version": 3,
			"version": 3
		  }
		}
	  }
	}
	# "#
	# , false, 5, true, true, false, false, true);
	#
	# // Slatepack processing
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"slate": "BEGINSLATEPACK. 78D5yXBmC2t4fQ5 ZNwtM3YncAH1bZZ 19fotVi4TM2mY7E AbDHZVyiX6zhNFW UZmyL5AbufF5kyP Q6ekjrhm5J5R7wv r4cdUTpbttyytAf p6x6M8SSoTT5qSP YwbhBta78KtSz6J 9rx8xisfw7T2Rh1 W2nRpB6TCnS8h15 ArsUfK6ppY8ZCsW Ny2gxC7jQJj7yWi 72j514HZwSs7qbX 8BvCWH7f2k29K7E 8mM4gv2fYkbbaUT hv9z4oU3ixnocFd YrYr25PNyp6n5ar JPCbXNGZV82zJZh WTXZ4XNY17jJc5S Y6pS8MNGB1EjG2H 1gqBANTaTwrkLXE 5N42xskNEhtAFwp RqcZaEzcEgtCadU wrz5ba8F3Aa3g9n Fm9XbHGD3qJsbCu X7dg5eunEvubDpP nbqXeZsGu4eMBhJ aEw9LN4FiTxZZKv D7rQJM67UcH44ou Hx4B5pRVd7bbopf BGmG23uwhh9ASUU 5vx2NkGGH8coRUW vJnKsxB2DNKdv3V ZhJPRq98QtFqTw8 ZpHj3XCYsxzrZ6D MeZXNmFC1BFR7ew zCRobkFFVvXiZ56 NoKqFxVydSzyPVw 2Sy9y1yFxXnWaZz 9ji1oUQQVSSozjS M42WhZaf8rHEGSs jkL4fBrZ12oBaNN K2KUbiHdngtS4bd r12QgT2nPamqizj au8yMNqHLhYFC2A R89a38gbJtwaFrX x4KVqRyXXYTijFu dXfrgB4A39ePyQr ZrPoBmcp4AHDUdf yGmfX83rLVtednY dVULZ63TNTzC393 CDffkNxSt3JKjoV GVTv4BMxSu4YDcv YEvBkoVkdABYkyH M8SKCeLgHMfYRM7 GHcKPauzo636oR5 JjZndjphUfPUpAR Ejj4UAdYqDWvkPV YnbfUHrYjsdszmB 2TAWSyNk6npe1h7 HKwnddyWJzxm1DE WgEVTLCTb2qsMm1 8viMY1UsdYYfMiy 1ytoqZqAPWwWxR4 qHEFYhU63Aq2pjm 4KiLVtkr1LNygFb eFCb6ZeVqu9xKGT 71NnR5j7B5sGuKm YSfX8LopuHV7Ewk aBdrtxpkSzQfr7d 8x6GZPh2pxPg9xW UywhYxDoRbts1Q9 D4m63djAfA9jPYu MEQWiDhnDf1v4CD s7CcYyiyi3MX1Gk JbHyBLaKfkNyA6p e6LWmFm5dJusfco Ej2CyYyC632fE8Z PfxWgiCNEphe1kX W7F529X8NRVKEj8 qUccuviVC7GR94q EecQ8hVK1TbrTAQ MM1QYFxSTrA1qEg PTvKdwxAs1Qb6Ej 8Jkb7nrXALDzSct edf6i5QygNRnZup VYKdBeznoSYpG7D rjTPQJBNLtJ4t46 7sD2FZL5edzb4Ah LZ3zPmpXeLDemU2 NJ6qRXJbPpZQbWW hZ3rFMd4UMfm2Zc BVrfgjeqskCVAtu 6hvxm9eY91xuYzu JWMQUYSZWENQqcU mfd6RgrPFH7wtpm cB4Sv1o9C6LXidR v2srdppm3gTQyMV 9V5NXFykMbqpcJX iWrDVwWi2DELt1P N4NvdkdTxq6LNup okimDBoCYKbH4Va zYgzdJeZ872Jp3M Mg4qUGLFd8SHZED PJsx7B7jmZ62fPq UAi39HU8nRH5GYS y2iZB2rH8j8GD4Q hZ5wUSSi7jq46WZ 4KVY6iuCpLrgYwU Hn6DCbNVmNrNK9t bSBXEJQYqbXkHwQ bTccv3LJ3b5dtEa NzwvwUv833FdpxK hvh5e6zd2Gph7Ms ELhd19sPYfvFmWH RvqWrYgbdUjs7Rf WEeM998zqL7RjM2 trmizdfVMjxCrKk pp94TnVyyPfDBgE LtYwquWnzsjUDqh 8Wm9cV1dcAzuZyr pDsqQ5i89vieieN ZAtqhJb1agE6XC3 zwzVAdMuGvLLZVf MB2XrtWWcRxks9H AvqgVUxtRrS8e8f tNTw5aJxP8fJksZ UXXq68BGcV9wt3w T8NoAetqxKeL22c QyFg1VHoeNHczML NtY49ip3LKQ1vL6 yKrjAQ12TY7vZVj f3DnAHFDb5DeA6t RYwnhCamBubygiK KvYYTV5Y8RDW551 Xqp2kmWKr6tBrJ2 QBVgP4G5JcWrCRp jgR4Dq3crmnR9o4 5vgT5UFrLYydsYX 5NWKCdkkJ66KVPE cEgpqYo5eBoyade fSgXhv4CvRVYtk2 HQRcjbUVrFS2KJ1 RdJuxr8dY6QgihK ZNwCqDQHRx3NCGv aW2V2QzAqbSMQsK cnuZUYwWFZ9nZWs kD8uxYre9jwe9Wp DNpP8iB3AWuP1Kx AUu2Hu4c3PnXSi5 uDPUGmDjcWtUxUv pUj3yNE1XzBJxPH nqstVEP5PqLjUAr 8afecWyaCeNaXq3 KtmWe8fzyEYQ7TJ QSe5QKYAKjUfiCE 4zJofoamEthP9LE wwwXDGpSq8sUb8Y owWi6BVY6MCTCX6 yixBxPgWrtqSYwk BUi5wNA7ybCtMY5 a17ovnwkSbrCoZD dyHCSYTrs7zq5jP FNRK. ENDSLATEPACK."
		}
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": "BEGINSLATEPACK. 7VTS9vHFwa1MRY5 grkEmpRKKvzQFJZ 4xrb1s4tjJctVB7 7FsGCy6XTNsAUrF WcPaqru7ieyBnVD tVMkge4Fb9wWk2E R7CJyV7Um4rnBSs zBdaaZpzuvSCVTE oakhHcyrA6xfue4 Z7EBtGAb2KZmQjz e7twk6XAfPF2cdJ f15sDPkCDzsvPCW iTB5ZkwDKKeNoCJ 7QxCPLNjruJHVQk UyeazyAYnWgiCmd 7giVtd5sYXuaiqA 6XE4J7Keyjd9zcw 7YsyckrggbXecoP nUQ8L6twszZwfpz 9patemw25ncrZo5 tBK7AokGk86X9HC jz21E1Zx4hq1SvD cEFdACjZ5AdFh45 hRMQrJyjWkjaGM4 8ejrFE8anxMXjzk bHgsfF7FwQwLCWk P6yCf2cE6EnChGu x7SYZyQRuPpAmzy FdYYbvoTEfRp2vK 5Tsp5C2MexhyHex nZifzD37vgg2f76 ux27gvvM8EUD3dM 7p1uoB498gLVzYA ai8Mx24XFNxNEnD jyM3iohgu8MRzvG BCFzGMDEFrVoKuN iu3Xu8NPFejf7dB FjHT69cbCzNKfoH yqEkLX6zfCacwBh M956CvEznE7xSf1 oA7kcfkLbrvkVqZ wXYQH8Wy784oqnF zCEtNVNbSt4pq1K MZcLcZxs3dCtkif XmqBfH99DisQQD7 zbSoK55JxerDLNe j5buWEYW5Q9nBgP acVJgijCgDaxcAz DUB47bDnpPrEFp2 mw8ruaB5nEKVstQ xt3sY4d6fMyHnfd JDft71w3uGxa87y UD3ZTCGBBpyCtJV 4YfWscGcU8aniBH WPcUHLZ28MAYoXv 7MWsymcPmdmr1ry JcRTWGJaoRni5H6 15BUr51vYE9iVDU sBW7Soh7RojXscV kgyjQwXsGsXHYRG KEH7DtdVn7NtUjL AAU8AZc5rNgnHCW gA9sqejSaTXyQ6Y H73SnA7xo4QrZTb nukg3Qj1pzVaB4t HdFxu7AGyxEZzvX 8pZDVPELVBTJpij 5A5sFbCU6u822ci LLpxgTxp9pkWYXF cNLpzCgHVyurTMu 4w2ZLSiCERVsF6C zy6AosJG5kuFnQ9 3QoxhHyALtASw68 mUdtca4k6jgHaVY E99g7iMLQSkjjRF xgq8bvn2T97bX1v sin5QyB2uNjqFn1 VXcqXcqAE5MVwor gnE3a3Q5VfcV399 h2639vRWQyMzdZo qJbwrRQV4tEBh4d KkNNSuDJRUsdZih 1p73hiNS68fNKBq YAQJQMoQrvzakFB umrusgGaai4MXMu DHYBVMS6k7ajgnC BzqxXPHqbeU9Kxe vNZqEu5bAP1W2Wi vPDaxs4cLP9zQe2 1EwMNuN1JWyAQfk 4wAv8w9LomFLnqR 2nVs5aYuHWgEL4n XpkzwZVhShBQTEc VAb9iFnfzGYfjfc d34RB9RAf3wybJ7 RGhL1JcDmd4o8pU zG4oyBdjNAr3Usc uPa3tBiNREpyDVg kxhf5CQHdGB9ok8 oPoSihfUsM9pao1 KuaGJojzfQtgKGM krShRj3caz2sNEC THb8Z2Rcjir8FMB 3H4DXL7xXvSDhhj 7kpgAYfc4kZXJ6y 7fRKHUGJuuYz5Fs dHT7VMg1Lhi88H3 9cXBFYDh7CEPgBz 5MVFBPz5i6UfecT FHWqcQ2TZo5HQiM ZYQ357Jxges8tJN 3XGynnHHXVfmTKy 3H26peXy2AQQXMo szkt6hNHzAgN1ey xKDd9Te3ktBnqhY 5VQd1SZg6Px96oS oiKbzkKZm3Pr8TT yGJSNReYtSR3xFr RN6r6LN8TbU8xjw d8Vo8ZYumnPmbZv cs4c1176WaNbfUC 9eZNA82m8fz1uhf UoVGMb4Z4QfZqsu 2uTHC5tTvjYNPFD d2oxKV2VtdpFaiz bKWQVd2X9XTpbfw Bbw4HJJ8S57SwGb 2BJN7EqtMM891yt oP6UHmjnd9hrxRA wYg9fHYTfSaEkDF q6W2g92XkWK2LcF 91ueo9E6S8WBgWu RAUU3TFP6tiU8UW xB6PMWVhMekTe3x gwCDrgFLxeiitrV cKHWVWWVHF8DV6f PddjpCMuLXzDq7m bKeYth8yzHRhvnc d9xoq6KBkUE14Xq EHfsq71ZzFEJ8WY ET9aScd41sxR29F 8x8wDayKvDnMKK3 prBcyXm32vxb2WL Y2KhdwHEzePcxRr RHghMxsXmQn5e7A GsPWY8j9CZkLFCC jA5arDxSETJz7hy nwg8atvsQZnJKFB qxEaHbAZwZ6ebWh JTurazK5ih8vFxw 8mMjxZD1SrYVaeD APy2vTDV3vb6Fh6 mEwCXKgqNEUQcHv 3Fhj6cotsUxsjNC JT7Age7hS3Ljeb9 zgKq1VLo6SUgUUH 7gpZ6WyzaD2Aqkz kZ36sFKonjan3vq a9hJVFhVRA1eCPj 3rqhXkQsF15vLav jpGYTyZQs97HYjM notUvmsBRjibVyf mrAbURXiQoPSqdn fsibAwvWhhb5UB9 9Qd69nPWNXNsvyi 9VFRAK1uApZjCN5 mqavxaQ5fVY2gpx SzT2paAJsJNYTgn SiswZXA2sbQ2pd4 Wrq9HtmKkyhjDom 5B6dbhywxd45ai7 5abLFHw6jKeekfz wrrh6SrnmQu5i1o hXxWQYomP1uNUVn hwH5JDVs3UiBXjt uzTpnGw2KdZXNxU Q68fk7qbZ3RELao JRmXqA6gYYSyHbz gqMv2cVPsBJ7rTd MFe3LhYQ25yCUKx wEsEpKFTEv7rhUA LTxnCSbv7y38nPX BeDeN2Dpdk. ENDSLATEPACK."
	  }
	}
	# "#
	# , false, 5, true, true, false, false, true);
	```
	 */
	fn finalize_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	# , false, 5, true, true, true, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
		  "tx": {
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
		}
	  }
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
	# , false, 5, true, true, true, false, true);
	```
	 */

	fn post_tx(&self, tx: TransactionV3, fluff: Option<bool>) -> Result<(), Error>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
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
	# , false, 5, true, true, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"tx_id": 5
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
	# , false, 5, true, true, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {},
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
				 "TransactionCancellationError": "Transaction is not defined. Please specify tx_id or tx_slate_id fields."
			   }
		}
	}
	# "#
	# , false, 5, true, true, false, false, true);
	```
	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# // Short form
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": [
			{
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.mwctx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
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
				"proof": "bdb629cdbaa68943426d977eb6fa804de99b3962ab4e1055aa49607ee2b2a08b69713b915b803812587de635002354fa96884f8bb0732b4fd7e700b4b132f0080d1890f042091247c09d7becd1ac8f0e0bae3b5efebdfd4c3e4ce1249da42d246f8e68d83ff897e61cfc145fe376fa428b55e25cf20d15f10b9054778229798b301d4436c39a07d65fb2adfb8095d804a062bdcd10b769abb7ce9f4cbb9d9fbcbe08b56264fc295c3facb6dfa4dfac41a6ee056b29b1af9bf3ce6223f125a274b563c0b2599214208d6b4f109158eb11b06875a8fcbb3ed95fd8fb23e23186cd0353498436a940bd0acec8c5b93c45a299771e0b3f5cc7e8af034d3717700cc05e73932287f1bf2c1dc71abe5f0a6c6e84839c3cd18e77b8dc93c40f6b86b42808d5eaf98cc4597cfc8f4b56aae06cf2478bce60119556d0e0900b43e02426c8b9b0b5a6fd739a30deb2f67563512ad95e82ec88e18d303cbbc39dd1455b4dbb9b010174bfd7db92c8f56f3286f97e18601eb922e268822de30332d6fcf614a1c9012c317bcbf808ef836377b21437f9023a646cd4696a0ab7a544ee8e9692df50288e4765fff311543070d6623b4c5508d10f25ddbd130f56bbb5458ab8a6af519ec2c9d24b19c9b55e8024abb8193e4e3bf455986c38cca230ac0a6d05543a870a7fccd6a4fa507516f2fe344f1343e2a5dbdd5962121dd69106d80283f704c9a2211b6cbbe547075ab23d2c7962443a0749635505fcedd9740b7eaee7ae9c653fb0b55167eec7570ad27d7a0e5df21ccea82f986aa6650adc0659d5a1b9fc6131248ebfc08edcbd4a7fd88c8a882d6f8bf4fb59be82aec2740afdae5c424c83238a146cbf9210fafcf7b4eaecfb5cef3087a1710cc47a1ca703aaa811a90bbab9281ada7b27e9d5b67452bb2f9e9351ae63a4ccff826545382e7398dcf7743e0525"
			}
			]
		  },
		  "offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		}
	  }
	}
	# "#
	# , false, 5, true, true, false, false, false);
	```
	 */
	fn get_stored_tx(&self, tx: &TxLogEntryAPI) -> Result<Option<TransactionV3>, Error>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	# ,false, 0 ,false, false, false, false, true);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), Error>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"start_height": null,
			"delete_unconfirmed": false
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
	# , false, 1, false, false, false, false, true);
	#
		# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {},
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
	# , false, 1, false, false, false, false, true);
	```
	 */
	fn scan(
		&self,
		start_height: Option<u64>,
		delete_unconfirmed: Option<bool>,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": null,
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
	# , false, 5, false, false, false, false, true);
	```
	 */
	fn node_height(&self) -> Result<NodeHeightResult, Error>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"frequency": 30000
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
	# , false, 0, false, false, false, false, true);
	```
	*/

	fn start_updater(&self, frequency: u32) -> Result<(), Error>;

	/**
	Networked version of [Owner::stop_updater](struct.Owner.html#method.stop_updater).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "stop_updater",
		"params": null,
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
	# , false, 0, false, false, false, false, true);
	```
	*/
	fn stop_updater(&self) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_updater_messages](struct.Owner.html#method.get_updater_messages).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {
			"count": 1
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
			"Ok": []
		}
	}
	# "#
	# , false, 0, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": []
		}
	}
	# "#
	# , false, 0, false, false, false, false, true);
	```
	*/

	fn get_updater_messages(&self, count: Option<u32>) -> Result<Vec<StatusMessage>, Error>;

	/**
	Networked version of [Owner::get_mqs_address](struct.Owner.html#method.get_mqs_address).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mqs_address",
		"params": null,
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
		  "public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
			"domain": "",
		  "port": null
		}
	  }
	}
	# "#
	# , false, 0, false, false, false, false, true);
	```
	*/

	fn get_mqs_address(&self) -> Result<ProvableAddress, Error>;

	/**
	Networked version of [Owner::get_wallet_public_address](struct.Owner.html#method.get_wallet_public_address).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_wallet_public_address",
		"params": null,
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
		  "public_key": "fffqrotuelaodwjblwmifg36xjedjw4azbwvfexmxmmzsb6xvzbkhuqd",
		   "domain": "",
		  "port": null
		}
	  }
	}
	# "#
	# , false, 0, false, false, false, false, true);
	```
	*/

	fn get_wallet_public_address(&self) -> Result<ProvableAddress, Error>;

	/**
	Networked version of [Owner::retrieve_payment_proof](struct.Owner.html#method.retrieve_payment_proof).
	```
	# // Legacy non compact case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"refresh_from_node": true,
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
		"Ok": {
		  "amount": "2000000000",
		  "excess": "08b3b8b83c622f630141a66c9cad96e19c78f745e4e2ddea85439f05d14a404640",
		  "recipient_address": {
			"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			"domain": "",
			"port": null
		  },
		  "recipient_sig": "30440220050ccd7244a8e1bcad8724a26bef6e0bc3df85f09dfc41870635711627955c4c02202b3d3599a7371bcc685315876c54cdf956a8c990ce6526f6be8e50591bde3be2",
		  "sender_address": {
			"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
			"domain": "",
			"port": null
		  },
		  "sender_sig": "3045022100945b57de1e8b9f7863c4f4c5698d5617ffa55748c80a8324729f98ce5ef86509022063f6bc511d80046f6f21c9476344ed8d948234cc32a0b022d720161798e09861"
		}
	  }
	}
	# "#
	# , false, 5, true, true, true, true, false);
	#
	# // Compact slate case, kernel is different now.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"refresh_from_node": true,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b01"
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
		  "excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
		  "recipient_address": {
			"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			"domain": "",
			"port": null
		  },
		  "recipient_sig": "304402204417c3b64709c7e38197103b6979dacee4e41c3ee44d89ea75191f553e2bbcc2022044c52df100fffd080c95575c92329b6ddbd0c77545e31ee439112655918fe0ee",
		  "sender_address": {
			"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
			"domain": "",
			"port": null
		  },
		  "sender_sig": "3044022001d10e4e1fd303748120a45cfcdedcd8b1abc1ffe8ff59d35ddb2ec5b7c2e1a902207dab490bd26d16784933724c559e5a1e4dc56a6c0941f4dd70a22b0c4cfbcc40"
		}
	  }
	}
	# "#
	# , false, 5, true, true, true, true, true);
	#
	#
	# // Compact slate case, kernel is different now.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {},
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
			 "PaymentProofRetrieval": "Transaction ID or Slate UUID must be specified"
		 }
	  }
	}
	# "#
	# , false, 5, true, true, true, true, true);
	```
	*/

	fn retrieve_payment_proof(
		&self,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error>;

	/**
	Networked version of [Owner::verify_payment_proof](struct.Owner.html#method.verify_payment_proof).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"proof": {
			  "amount": "2000000000",
			  "excess": "08b3b8b83c622f630141a66c9cad96e19c78f745e4e2ddea85439f05d14a404640",
			  "recipient_address": {
				"domain": "",
				"port": null,
				"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2"
				},
			  "recipient_sig": "30440220050ccd7244a8e1bcad8724a26bef6e0bc3df85f09dfc41870635711627955c4c02202b3d3599a7371bcc685315876c54cdf956a8c990ce6526f6be8e50591bde3be2",
			  "sender_address": {
				"domain": "",
				"port": null,
				"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
				},
			   "sender_sig": "3045022100945b57de1e8b9f7863c4f4c5698d5617ffa55748c80a8324729f98ce5ef86509022063f6bc511d80046f6f21c9476344ed8d948234cc32a0b022d720161798e09861"
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
			"Ok": [
				true,
				false
			]
		}
	}
	# "#
	# , false, 5, true, true, true, true, false);
	#
	# // Compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"proof": {
				  "amount": "2000000000",
				  "excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
				  "recipient_address": {
					"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
					"domain": "",
					"port": null
				  },
				  "recipient_sig": "304402204417c3b64709c7e38197103b6979dacee4e41c3ee44d89ea75191f553e2bbcc2022044c52df100fffd080c95575c92329b6ddbd0c77545e31ee439112655918fe0ee",
				  "sender_address": {
					"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
					"domain": "",
					"port": null
				  },
				  "sender_sig": "3044022001d10e4e1fd303748120a45cfcdedcd8b1abc1ffe8ff59d35ddb2ec5b7c2e1a902207dab490bd26d16784933724c559e5a1e4dc56a6c0941f4dd70a22b0c4cfbcc40"
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
			"Ok": [
				true,
				false
			]
		}
	}
	# "#
	# , false, 5, true, true, true, true, true);
	```
	*/

	fn verify_payment_proof(&self, proof: PaymentProof) -> Result<(bool, bool), Error>;

	/**
	Networked version of [Owner::encode_slatepack_message](struct.Owner.html#method.encode_slatepack_message).
	```
	# // Compact slate processing, V3
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "encode_slatepack_message",
		"params": {
			"recipient": {
					"public_key" : "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
					"domain": "",
					"port": null
				},
			"content" : "InvoiceInitial",
			"slate": {
			  "amount": "2000000000",
			  "coin_type": null,
			  "compact_slate": true,
			  "fee": "0",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b02",
			  "lock_height": "0",
			  "network_type": null,
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": "Please give me your coins",
				  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b8e466fa4596adb9436b38e35feb34c4af52bdf913034b7ae425a35437d521c07",
				  "part_sig": null,
				  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "payment_proof": null,
			  "ttl_cutoff_height": null,
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
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "version_info": {
				"block_header_version": 2,
				"orig_version": 3,
				"version": 3
			  }
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
		"Ok": "BEGINSLATEPACK. CD7MfBUbThCtDiA cdRUEr4KKm4Uwn4 z1LzfJ29o61nKAW Qc8WjGcpXHfn6po dYi5seYKNurEkMf MDJyLEQN9mUXDvy ModjyEmuTtpEDF1 xE286XvRdYPNkjM BnXg7sdzuHK1xVL iK5srPup1vAyEhM GJDGcLxFP4dyWdN zVqNsa6pMy8WJzv QPtF784fKDzPh7Z BPDvNXzvAz5nSkL 1c2FFvQzrvZudCy 1x33VwLDER6UzyD kpFFfxGqx5NLeTG Qy19AHrEUes1ecR wqPBSiGd3t8mdAB 44muWRz9AcriAbH ntZWUzgzyWVH5m2 nMQzau7fmpZbRqi PpZERxsVWxPksh1 UfrgtULqitKWVQ8 rD9NCbj5czuXf. ENDSLATEPACK."
	  }
	}
	# "#
	# ,false, 4, false, false, false, false, true);

	#
	# // Converting slate into non encrypted binary, recipient is null
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "encode_slatepack_message",
		"params": {
			"recipient": null,
			"content" : "InvoiceInitial",
			"address_index" : null,
			"slate": {
			  "amount": "2000000000",
			  "coin_type": null,
			  "compact_slate": true,
			  "fee": "0",
			  "height": "4",
			  "id": "0436430c-2b02-624c-2032-570501212b02",
			  "lock_height": "0",
			  "network_type": null,
			  "num_participants": 2,
			  "participant_data": [
				{
				  "id": "0",
				  "message": null,
				  "message_sig": null,
				  "part_sig": null,
				  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
			  ],
			  "payment_proof": null,
			  "ttl_cutoff_height": null,
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
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "version_info": {
				"block_header_version": 2,
				"orig_version": 3,
				"version": 3
			  }
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
		"Ok": "BEGINSLATE_BIN. 9ahjQefP9gsCcVt 25Po4VP34y95yxE wMmTzzckUkh1tu3 y7WwT5j1ZTL7UyC 4byFhRQM4BmhM92 Y1ukWPJ8BVdpEGU MAJUrU2YbXFLAYT tdqamYotCv4Co3z keD8RdPpX4b. ENDSLATE_BIN."
	  }
	}
	# "#
	# , false, 4, false, false, false, false, true);
	```
	*/

	fn encode_slatepack_message(
		&self,
		slate: VersionedSlate,
		content: SlatePurpose,
		recipient: Option<ProvableAddress>,
		address_index: Option<u32>,
	) -> Result<String, Error>;

	/**
	Networked version of [Owner::decode_slatepack_message](struct.Owner.html#method.decode_slatepack_message).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "decode_slatepack_message",
		"params": {
			"address_index": null,
			"message": "BEGINSLATEPACK. BMPbuLeVjyFSo36 NvoGhFVYSFxK58D 7ENH2twNyFzuukP mHsGxDrNnBRg5Vd fbKWgneT6YxtUR2 nSmKgFrokk1NEYY qA5cHKVdKaRaKCA J9oX86S4ToB2GEC yHKuKQRe8mwgxn3 PnjdLhtxvuLvXaD 5G8FAqEdWF2RNy1 jAH2xaUsus2onwt 1QM8oENbqUXSSP1 rxo54eupY5ECeiP RW9NY4tM1M6DEf1 BDRhK13rkJRyBzV o2fyjddd4HftuFe d3eHyC1ZEhSxitC 3mi5CmPYzV1JmMp bjwDKGH3jonnxfr 7Ah3ysctRymaXUM 4dH1Ln6UVvD5umC nyam9s4XusiCAky x7VaZGR36MmLzyw eMHSNXBYi12hmq3 D4iouD74YEcPSKD 2JoV5YqZGueBRH4 p8c47hboNujhko2 SPqzY2LiecEfkSK CojyRCQH1C5TE2K QbqNVMniZQQjmN4 TxZNr2kx1D7GFGH CriBfZDoDyDHtYk S4bE6TqA8WGE7oA 9AM2XMoCsZpVyS9 TYTM6wAwXAPhMZU ELo5bZBpMC5GnwN 3LDyFAxuPjxj2Bw eVQNKhLNtUpcstW x1gkYDTNtQTaXyD n8s9oTE7cuJZ5YK 1oooXzP9T31Mmzf kahNCcmtEZipQVb 8e1ba7ormFGegug RS7TTutor3EfxDC yCBRZBuwxFf3Uxq B55wb7yZN53fAMm Zn8SBTxNBzuZiX8 16GyVZx9xbrcB64 krz7XigXGf7hWFd wmuvYqzj7yqson1 hrNftRpEhJbvk3h QFJd7AcxwHwJH2L GdT2xe3DAqBtW4e zgSkQjNnoPhPhii JXBZay4z4eaKBie 1J9KFb6YcXHtcsH dffsHHgXs6GQRZG 71od7BKQVzTWuwv r95CZp6kSpYMqfd G5MfFpjBcD9v9bq WvkoYPuWN6Jf7dA S2fXznZReqLmZzt TGtcahQF5iPLmTr MoE15UceR5bNMBY MAN3AzctE3Vr2fa BDmaMrpHvRCb7pw Y2QUv2R6ZoztGtW Tssap8D7KJtp3g9 fg7kByVQSceSvQE opCAtY7VACJdyag 9D2jmuXZLCawnLM cH3E7MuLqNADMcj PebyUeKE93ttcmW JYGifAGr6cS7WYC Ujwrzg9EhhfjVSd KpArBHx1wvXUzdP kZojuqo2cr7DVqD zQGfUDWGXMbHYbX UJuLtbwFnkQt7Cg rjnn4kj4HZfx7fj uLeS3VaBtMyxLGF 5yECTWgQ2HcGnSK iRDMM9dqncWR6rc 1nXYww6LfUzZxj7 WB1ioS9kAD3XZXw SQX8VZ54tvPbBJ3 pGz3q9RxdvbhcS2 cgxj8K4qCMjJfoM AxDNdcpD2gXuy79 whZfDJ4H6gYvTsp uUfQazqTD46yudj UhXn5X1tZgcExVx FwDUVMTHUTmqmjT 9iJ4Xox2K9HDytN XuJoEk7nH2DCQyi NgPGg4FTibENxZv DB22bb2FQR7W8mu 2hjsx8CWnqWJ56u oyYCXkqynhcKLtb G18knjmUYx3xjyN BVe1u5XHw8HJak5 C9goSRBv29hbf6z Mm4hH7waqL5kAVC vo3vwBrVPeA8K8X QE2JoJ8vuVCFXbM GWJRLnAiYTcUxtq i5aNtAgViPt6GRA 7K5rYdxRAeTc6Ym NZDeoGHoPKrLHwF D5cb8YB7JkmEtnR puX22WD1pagcRph uZJ8xw2gt6RQFQN ypXgHrDFv6W8HNX jNRDvFHpbrmceRR DTBPeWwdpYoTogg E7gnQE1U1ULRi3R XLJJLY5fAVKesTN HyutbMxBvJ3DUz3 CfWDXrRZgG6vQDM 8CboKtLz7dAs5Ui GTLbS5ZYXxpKQbY TXmfDW4wVNXS5G2 NA8gokJPRZ9phXt tYhDG3E9pfVK4mK 8Gmf9Mt6iPRxzvf aQkwRY81peGzJSz ZpPVXAhNFXjnENN MTW8pvTVfYH4Dxt Sabo3XdiBusHygj A8PbFAon6fCAySo jworMXbsSKrrFyA eM7whDYiZJVYFwR SJnqGPTnMtJy9pZ JzsUoTLJFUegFXr YVeHFDTcBJ3qniU Kbc9RsmRrTv512C HajdTQmdrVDR9c7 wC4wcRm7rmXTqny xMYLL6v62RhWcPz C315C3PZtXyxzke WhsCxvctHcS4Wd7 sVLRNvFsxfbN7be FkAjdTLP7oo2Aq9 6bn3GWTypxAdQyZ kWDxEaq8jcBDgR1 EpSLVeJJ7Vd4CrN PxMNvhhTdJs5nUp WzuZNfRNZhajTNZ FLgjbUTUnyk3u92 9PLbPmhSLvVZZHU Yw5PPiaKWWgx1AZ EpY2TxjvgMFRXJy CTFHhms1FAjDE7Q LNizD7TPNyCSbM2 Ha3RZHxPHt8gqSJ ZVbVpFdPJcWWNrQ ms9hr66LU144dgo KLKJedbLSg1sLMo vW8GA5e8hyCMQZG 3JqJKCXnfh7dyjP 5zNRzKYd9FdiR71 gSQBgVEVRavCpJV aXKco2M8kNWdPtw ZNgX. ENDSLATEPACK."
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
		  "content": "SendResponse",
		  "recipient": {
			"public_key": "fffqrotuelaodwjblwmifg36xjedjw4azbwvfexmxmmzsb6xvzbkhuqd",
			"domain": "",
			"port": null
		  },
		  "sender": {
			"public_key": "7rky2tvk763cq5kvhyxv7zkjxfytmao3qttqvoc6fsiawo4kzgii7bqd",
			"domain": "",
			"port": null
		  },
		  "slate": {
			"amount": "0",
			"coin_type": "mwc",
			"compact_slate": true,
			"fee": "0",
			"height": "5",
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"lock_height": "0",
			"network_type": "automatedtests",
			"num_participants": 2,
			"participant_data": [
			  {
				"id": "1",
				"message": null,
				"message_sig": null,
				"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb9128fbee3070329b28c635090138e2b78fe1fbb840117b2f65777508179be0a",
				"public_blind_excess": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
				"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			  }
			],
			"payment_proof": null,
			"ttl_cutoff_height": null,
			"tx": {
			  "body": {
				"inputs": [],
				"kernels": [
				  {
					"excess": "08e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
					"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"features": "Plain",
					"fee": "0",
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
			  "offset": "97e0fccd0b805d10065a4f8ca46aa6cc73f0962e829c7f13836e2c8371da6293"
			},
			"version_info": {
			  "block_header_version": 1,
			  "orig_version": 3,
			  "version": 3
			}
		  }
		}
	  }
	}
	# "#
	# , false, 0, false, false, false, false, true);
	#
	# // Decode not encrypted slate pack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "decode_slatepack_message",
		"params": {
			"message": "BEGINSLATE_BIN. 9ahjQefP9gsCcVt 25Po4VP34y95yxE wMmTzzckUkh1tu3 y7WwT5j1ZTL7UyC 4byFhRQM4BmhM92 Y1ukWPJ8BVdpEGU MAJUrU2YbXFLAYT tdqamYotCv4Co3z keD8RdPpX4b. ENDSLATE_BIN."
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
		  "content": "InvoiceInitial",
		  "recipient": null,
		  "sender": null,
		  "slate": {
			"amount": "2000000000",
			"coin_type": "mwc",
			"compact_slate": true,
			"fee": "0",
			"height": "4",
			"id": "0436430c-2b02-624c-2032-570501212b02",
			"lock_height": "0",
			"network_type": "automatedtests",
			"num_participants": 2,
			"participant_data": [
			  {
				"id": "0",
				"message": null,
				"message_sig": null,
				"part_sig": null,
				"public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
				"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			  }
			],
			"payment_proof": null,
			"ttl_cutoff_height": null,
			"tx": {
			  "body": {
				"inputs": [],
				"kernels": [
				  {
					"excess": "09e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
					"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"features": "Plain",
					"fee": "0",
					"lock_height": "0"
				  }
				],
				"outputs": []
			  },
			  "offset": "0000000000000000000000000000000000000000000000000000000000000000"
			},
			"version_info": {
			  "block_header_version": 1,
			  "orig_version": 3,
			  "version": 3
			}
		  }
		}
	  }
	}
	# "#
	# , false, 0, false, false, false, false, true);
	```
	*/

	fn decode_slatepack_message(
		&self,
		message: String,
		address_index: Option<u32>,
	) -> Result<SlatepackInfo, Error>;
}

impl<'a, L, C, K> OwnerRpcV2 for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, Error> {
		Owner::accounts(self, None)
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, Error> {
		Owner::create_account_path(self, None, label)
	}

	fn set_active_account(&self, label: &String) -> Result<(), Error> {
		Owner::set_active_account(self, None, label)
	}

	fn retrieve_outputs(
		&self,
		include_spent: Option<bool>,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		Owner::retrieve_outputs(
			self,
			None,
			include_spent.unwrap_or(false),
			refresh_from_node.unwrap_or(true),
			tx_id,
		)
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), Error> {
		Owner::retrieve_txs(
			self,
			None,
			refresh_from_node.unwrap_or(true),
			tx_id,
			tx_slate_id,
			None,
			show_last_four_days,
		)
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
		refresh_from_node: Option<bool>,
		minimum_confirmations: Option<u64>,
	) -> Result<(bool, WalletInfo), Error> {
		Owner::retrieve_summary_info(
			self,
			None,
			refresh_from_node.unwrap_or(true),
			minimum_confirmations.unwrap_or(1),
		)
	}

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let slate = Owner::init_send_tx(self, None, &args, 1)?;

		// Return plain slate. If caller don't want sent slate with this API, than probvably caller want
		// handle the workflow in lower level.
		// If caller did send with thius API - then the slate is just for logging. For logging it is
		// better to have plain slate so it can be readable.
		let version = slate.lowest_version();
		Ok(VersionedSlate::into_version_plain(slate, version)
			.map_err(|e| Error::SlatepackEncodeError(format!("{}", e)))?)
	}

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, Error> {
		let slate = Owner::issue_invoice_tx(self, None, &args)?;

		let vslate = Owner::encrypt_slate(
			&self,
			None,
			&slate,
			None,
			SlatePurpose::InvoiceInitial,
			args.slatepack_recipient
				.map(|a| a.tor_public_key())
				.filter(|a| a.is_ok())
				.map(|a| a.unwrap()),
			None,
			self.doctest_mode,
		)?;

		Ok(vslate)
	}

	fn process_invoice_tx(
		&self,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (slate_from, content, sender) = Owner::decrypt_versioned_slate(self, None, in_slate)
			.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		if let Some(content) = &content {
			if *content != SlatePurpose::InvoiceInitial {
				return Err(Error::SlatepackDecodeError(format!(
					"Expecting InvoiceInitial slate content, get {:?}",
					content
				)));
			}
		}

		let out_slate = Owner::process_invoice_tx(self, None, &slate_from, &args)?;

		let vslate = Owner::encrypt_slate(
			&self,
			None,
			&out_slate,
			Some(version),
			SlatePurpose::InvoiceResponse,
			sender,
			None,
			self.doctest_mode,
		)?;

		Ok(vslate)
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (slate_from, _content, sender) =
			Owner::decrypt_versioned_slate(self, None, in_slate)
				.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		// Not checking content. If slate good enough to finalize, there is not problem with a content
		let out_slate = Owner::finalize_tx(self, None, &slate_from)?;

		let vslate = Owner::encrypt_slate(
			&self,
			None,
			&out_slate,
			Some(version),
			SlatePurpose::FullSlate,
			sender,
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			Error::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;

		Ok(vslate)
	}

	fn tx_lock_outputs(&self, slate: VersionedSlate, participant_id: usize) -> Result<(), Error> {
		let (slate_from, _content, _sender) = Owner::decrypt_versioned_slate(self, None, slate)
			.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;
		Owner::tx_lock_outputs(self, None, &slate_from, None, participant_id)
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), Error> {
		Owner::cancel_tx(self, None, tx_id, tx_slate_id)
	}

	fn get_stored_tx(&self, tx: &TxLogEntryAPI) -> Result<Option<TransactionV3>, Error> {
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
				tx.kernel_offset.clone(),
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
	}

	fn post_tx(&self, tx: TransactionV3, fluff: Option<bool>) -> Result<(), Error> {
		Owner::post_tx(
			self,
			None,
			&Transaction::try_from(tx).map_err(|e| {
				Error::GenericError(format!("Unable convert V3 transaction, {}", e))
			})?,
			fluff.unwrap_or(false),
		)
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), Error> {
		if slate.is_slatepack() {
			return Err(Error::SlatepackDecodeError(
				"verify_slate_messages is not applicable for slatepack".to_string(),
			));
		}
		let slate = slate
			.into_slate_plain(true)
			.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		Owner::verify_slate_messages(self, None, &slate)
	}

	fn scan(
		&self,
		start_height: Option<u64>,
		delete_unconfirmed: Option<bool>,
	) -> Result<(), Error> {
		Owner::scan(
			self,
			None,
			start_height,
			delete_unconfirmed.unwrap_or(false),
		)
	}

	fn node_height(&self) -> Result<NodeHeightResult, Error> {
		Owner::node_height(self, None)
	}

	fn start_updater(&self, frequency: u32) -> Result<(), Error> {
		Owner::start_updater(self, None, Duration::from_millis(frequency as u64))
	}

	fn stop_updater(&self) -> Result<(), Error> {
		Owner::stop_updater(self)
	}

	fn get_updater_messages(&self, count: Option<u32>) -> Result<Vec<StatusMessage>, Error> {
		Owner::get_updater_messages(self, count)
	}

	fn get_mqs_address(&self) -> Result<ProvableAddress, Error> {
		let address = Owner::get_mqs_address(self, None)?;
		let public_proof_address = ProvableAddress::from_pub_key(&address);
		println!("mqs_address address {}", public_proof_address.public_key);
		Ok(public_proof_address)
	}

	fn get_wallet_public_address(&self) -> Result<ProvableAddress, Error> {
		let address = Owner::get_wallet_public_address(self, None)?;
		let address = ProvableAddress::from_tor_pub_key(&address);
		println!("wallet_public_address address {}", address.public_key);
		Ok(address)
	}

	fn retrieve_payment_proof(
		&self,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		Owner::retrieve_payment_proof(
			self,
			None,
			refresh_from_node.unwrap_or(true),
			tx_id,
			tx_slate_id,
		)
	}

	fn verify_payment_proof(&self, proof: PaymentProof) -> Result<(bool, bool), Error> {
		Owner::verify_payment_proof(self, None, &proof)
	}

	fn encode_slatepack_message(
		&self,
		slate: VersionedSlate,
		content: SlatePurpose,
		recipient: Option<ProvableAddress>,
		address_index: Option<u32>,
	) -> Result<String, Error> {
		// Expected Slate in Json (plain) format
		let slate = slate.into_slate_plain(false).map_err(|e| {
			Error::SlatepackDecodeError(format!("Expected to get slate in Json format, {}", e))
		})?;

		let recipient: Option<DalekPublicKey> = match recipient {
			Some(recipient) => Some(recipient.tor_public_key().map_err(|e| {
				Error::SlatepackEncodeError(format!("Expecting recipient tor address, {}", e))
			})?),
			None => None,
		};

		let vslate = Owner::encrypt_slate(
			&self,
			None,
			&slate,
			Some(SlateVersion::SP),
			content,
			recipient,
			address_index,
			self.doctest_mode,
		)?;

		if let VersionedSlate::SP(message) = vslate {
			return Ok(message);
		} else {
			return Err(Error::SlatepackEncodeError(
				"Unable to encode the slate, internal error".to_string(),
			));
		}
	}

	fn decode_slatepack_message(
		&self,
		message: String,
		address_index: Option<u32>,
	) -> Result<SlatepackInfo, Error> {
		let (slate, content, sender, recipient) =
			Owner::decrypt_slatepack(&self, None, VersionedSlate::SP(message), address_index)?;

		let slate_version = slate.lowest_version();

		let vslate = VersionedSlate::into_version_plain(slate, slate_version)
			.map_err(|e| Error::SlatepackDecodeError(format!("Unable to convert slate, {}", e)))?;

		Ok(SlatepackInfo {
			slate: vslate,
			sender: sender.map(|pk| ProvableAddress::from_tor_pub_key(&pk)),
			recipient: recipient.map(|pk| ProvableAddress::from_tor_pub_key(&pk)),
			content,
		})
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
	compact_slate: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mwc::Handler;
	use mwc_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use mwc_wallet_libwallet::{api_impl, WalletInst};
	use mwc_wallet_util::mwc_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir.into(), tx_pool.clone());
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

	let mut slate_outer = Slate::blank(2, false);

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
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
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
			tx_pool.lock().deref_mut(),
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
		api_impl::owner::get_mqs_address(wallet2.clone(), (&mask2).as_ref()).unwrap();
	//println!("owner_rpc Wallet 2 proof_address is ============: {}", proof_address);
	let public_proof_address = ProvableAddress::from_pub_key(&proof_address_pubkey);
	println!("public_proof address {}", public_proof_address.public_key);

	let (w1_tor_secret, w1_tor_pubkey) = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain((&mask1).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&k, None).unwrap();
		let tor_pk = DalekPublicKey::from(&secret);
		(secret, tor_pk)
	};
	let _w1_slatepack_address = ProvableAddress::from_tor_pub_key(&w1_tor_pubkey);

	let (w2_tor_secret, w2_tor_pubkey) = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain((&mask2).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&k, None).unwrap();
		let tor_pk = DalekPublicKey::from(&secret);
		(secret, tor_pk)
	};
	let w2_slatepack_address = ProvableAddress::from_tor_pub_key(&w2_tor_pubkey);

	if perform_tx {
		{
			wallet_lock_test!(wallet1, w);
			api_impl::owner::update_wallet_state(&mut **w, (&mask1).as_ref(), &None).unwrap();
		}

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
		let mut args = InitTxArgs {
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

		if compact_slate {
			// Address of this wallet. Self and encrypt to self is totally valid case
			args.slatepack_recipient = Some(w2_slatepack_address);
		}

		let mut slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), &args, true, 1).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());

		let secp = Secp256k1::new();

		if compact_slate {
			let vslate = VersionedSlate::into_version(
				slate.clone(),
				SlateVersion::SP,
				SlatePurpose::SendInitial,
				w1_tor_pubkey.clone(),
				Some(w2_tor_pubkey.clone()),
				&w1_tor_secret,
				true,
				&secp,
			)
			.unwrap();
			println!(
				"Slatepack: {}",
				serde_json::to_string_pretty(&vslate).unwrap()
			);
		}

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
				&None,
				None,
				true,
				false,
			)
			.unwrap()
			.0;
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
				true,
			)
			.unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if compact_slate {
			let vslate = VersionedSlate::into_version(
				slate.clone(),
				SlateVersion::SP,
				SlatePurpose::SendResponse,
				w2_tor_pubkey.clone(),
				Some(w1_tor_pubkey.clone()),
				&w2_tor_secret,
				true,
				&secp,
			)
			.unwrap();
			println!(
				"Slatepack: {}",
				serde_json::to_string_pretty(&vslate).unwrap()
			);
		}

		if finalize_tx {
			// wallet1
			slate = api_impl::owner::finalize_tx(&mut **w, (&mask1).as_ref(), &slate, true, true)
				.unwrap()
				.0;
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());

			if compact_slate {
				let vslate = VersionedSlate::into_version(
					slate.clone(),
					SlateVersion::SP,
					SlatePurpose::FullSlate,
					w2_tor_pubkey.clone(),
					Some(w1_tor_pubkey.clone()),
					&w2_tor_secret,
					true,
					&secp,
				)
				.unwrap();
				println!(
					"Slatepack: {}",
					serde_json::to_string_pretty(&vslate).unwrap()
				);
			}
		}
		slate_outer = slate;
	}

	if payment_proof {
		api_impl::owner::post_tx(&client1, slate_outer.tx_or_err().unwrap(), true).unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			3 as usize,
			false,
			tx_pool.lock().deref_mut(),
		);
	}

	let mut api_owner = Owner::new(wallet1, None, None);
	api_owner.doctest_mode = true;
	let res = if use_token {
		let owner_api = &api_owner as &dyn OwnerRpcV3;
		owner_api.handle_request(request).as_option()
	} else {
		let owner_api = &api_owner as &dyn OwnerRpcV2;
		owner_api.handle_request(request).as_option()
	};
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr, $payment_proof:expr, $compact_slate:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.

		// These cause LMDB to run out of disk space on CircleCI
		// disable for now on windows
		// TODO: Fix properly
		#[cfg(not(target_os = "windows"))]
		{
			use mwc_wallet_api::run_doctest_owner;
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
				$compact_slate,
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

// Keeping as a placeholder for doc tests
#[test]
fn owner_api_v2_test() {
	// use crate as mwc_wallet_api;
}
