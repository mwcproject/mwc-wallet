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
	OutputCommitMapping, Slate, SlatePurpose, SlateVersion, StatusMessage, TxLogEntry,
	VersionedSlate, WalletInfo, WalletLCProvider,
};

#[cfg(feature = "grin_proof")]
use crate::libwallet::PaymentProof;

use crate::types::{SlatepackInfo, TxLogEntryAPI};
use crate::util;
use crate::util::secp::pedersen;
use crate::util::Mutex;
use crate::{Owner, OwnerRpcV3};
use easy_jsonrpc_mwc;
use ed25519_dalek::PublicKey as DalekPublicKey;
use libwallet::proof::tx_proof::VerifyProofResult;
use libwallet::{wallet_lock_test, TxProof};
use mwc_wallet_libwallet::proof::proofaddress::{self, ProvableAddress};
use mwc_wallet_util::mwc_core::consensus;
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
			  "kernel_lookup_min_height": 1,
			  "kernel_offset": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "output_commits": [
				"0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03"
			  ],
			  "output_height": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
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
			  "kernel_lookup_min_height": 2,
			  "kernel_offset": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "output_commits": [
				"098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c"
			  ],
			  "output_height": 2,
			  "parent_key_id": "0200000000000000000000000000000000",
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
			  "kernel_lookup_min_height": 1,
			  "kernel_offset": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "output_commits": [
				"0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03"
			  ],
			  "output_height": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
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
			  "kernel_lookup_min_height": 2,
			  "kernel_offset": null,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "output_commits": [
				"098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c"
			  ],
			  "output_height": 2,
			  "parent_key_id": "0200000000000000000000000000000000",
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
		  "coin_type": "mwc",
		  "fee": "80000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bbb08d6eefbbf221687ae5002a77386fdffd62c5f93716cb31f73f410e052a5a1",
			  "part_sig": null,
			  "public_blind_excess": "02c15f5909a602ffbf542580b937269a49afff967dbf9d0950e7e9199f7685e676",
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
				  "fee": "80000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "0909a3bfb9baba12ec17b331c4aef5598b02d674002f7e83f560910b26067b55ba",
				  "features": "Plain",
				  "proof": "654ed70c6afc94d1d335b761073711b56cc6c93651d7ea1bb95a428e089b11efe74d766a7cda043de32c128441c5aef5273b8534685c90715c3c4c1d476aa028088d88eda293bca115e1e4ce25a94ac27cf4ee1824fd5494f1f6e65120d1cc2040ea3dff8a9bcb1a524a7ed1e326e9c2cba520620f83bf36983495bc83c6d785a2ea0e8fa3b79744892ed4d3e2c74f0f323f48f5f90062b98e957a5ccf7485ed3f3f16356bb31177861280187ba25d68b36d6c36ae9fd4dcd4e0e8a5997ea62daae67a25bb90059a1f378cef21c7772be06c251a52ce7c68e7064cdb9f93a35c57e2e9c3a0de2229a188b2bd070172bfc57d5c2f826746c5fd277dbaadc5bdd552d136475fbe1cdf39589967cca604a0d064fe5b81e8a5d3864b915ea4f92697c55082bde32f9d069027637cdb17b4c4075acdad13f9cd80fec67db6394db0027003bdcabe23466a48e38e5ac71a01654eac95128e88e03ea2abbabe4af69ba6a78903b4906f63fe623e308c239c9836f42a7efea0ea00c375827f7606482373648b31bfadbe8515158781175b0d4f950a5454d2ce5fb8b00c7388a56382f21dd6407a2b447eba14d402f774201b0e53578ce5fc1121ed90487c858d1a014f8e64765c6db2901a33f9a37a2eb23246fa8a2d3dcf7a15e105ce4ad2e8355c121895c4e207e7d7435479787f1b9cf294bb6508b3a480135444e1e8062d9986784d90fef26ea145fd736cac9f53cd59a5d0195c50cbc728237a2e2950cf50743ec7f8de8d32b3edc726d2fe2f50c1881c5e31055fe7f80f6da02c6a8d26839135e10e6184e8bfcefcac83237335b79ffac61744e2a00401d3a22bb0e6d7bed91a8573e6b6279e2de7b67240363084bb6edc722a46775589e3bc0bb31241c3f802fac699a2a28d73b2aafc9bf0f1b8266e7ca2bc6484699705007b514807ac3bb306c98382"
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
		  "coin_type": "mwc",
		  "fee": "80000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b01",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": null,
			  "public_blind_excess": "02c15f5909a602ffbf542580b937269a49afff967dbf9d0950e7e9199f7685e676",
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
				  "fee": "80000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "0909a3bfb9baba12ec17b331c4aef5598b02d674002f7e83f560910b26067b55ba",
				  "features": "Plain",
				  "proof": "654ed70c6afc94d1d335b761073711b56cc6c93651d7ea1bb95a428e089b11efe74d766a7cda043de32c128441c5aef5273b8534685c90715c3c4c1d476aa028088d88eda293bca115e1e4ce25a94ac27cf4ee1824fd5494f1f6e65120d1cc2040ea3dff8a9bcb1a524a7ed1e326e9c2cba520620f83bf36983495bc83c6d785a2ea0e8fa3b79744892ed4d3e2c74f0f323f48f5f90062b98e957a5ccf7485ed3f3f16356bb31177861280187ba25d68b36d6c36ae9fd4dcd4e0e8a5997ea62daae67a25bb90059a1f378cef21c7772be06c251a52ce7c68e7064cdb9f93a35c57e2e9c3a0de2229a188b2bd070172bfc57d5c2f826746c5fd277dbaadc5bdd552d136475fbe1cdf39589967cca604a0d064fe5b81e8a5d3864b915ea4f92697c55082bde32f9d069027637cdb17b4c4075acdad13f9cd80fec67db6394db0027003bdcabe23466a48e38e5ac71a01654eac95128e88e03ea2abbabe4af69ba6a78903b4906f63fe623e308c239c9836f42a7efea0ea00c375827f7606482373648b31bfadbe8515158781175b0d4f950a5454d2ce5fb8b00c7388a56382f21dd6407a2b447eba14d402f774201b0e53578ce5fc1121ed90487c858d1a014f8e64765c6db2901a33f9a37a2eb23246fa8a2d3dcf7a15e105ce4ad2e8355c121895c4e207e7d7435479787f1b9cf294bb6508b3a480135444e1e8062d9986784d90fef26ea145fd736cac9f53cd59a5d0195c50cbc728237a2e2950cf50743ec7f8de8d32b3edc726d2fe2f50c1881c5e31055fe7f80f6da02c6a8d26839135e10e6184e8bfcefcac83237335b79ffac61744e2a00401d3a22bb0e6d7bed91a8573e6b6279e2de7b67240363084bb6edc722a46775589e3bc0bb31241c3f802fac699a2a28d73b2aafc9bf0f1b8266e7ca2bc6484699705007b514807ac3bb306c98382"
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
		  "fee": "80000",
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
	# // Testing specification of slatepack_recipient as strign address
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
				"slatepack_recipient" : "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
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
		  "fee": "80000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b03",
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
		  "fee": "80000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b04",
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
				  "fee": "80000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "0909a3bfb9baba12ec17b331c4aef5598b02d674002f7e83f560910b26067b55ba",
				  "features": "Plain",
				  "proof": "654ed70c6afc94d1d335b761073711b56cc6c93651d7ea1bb95a428e089b11efe74d766a7cda043de32c128441c5aef5273b8534685c90715c3c4c1d476aa028088d88eda293bca115e1e4ce25a94ac27cf4ee1824fd5494f1f6e65120d1cc2040ea3dff8a9bcb1a524a7ed1e326e9c2cba520620f83bf36983495bc83c6d785a2ea0e8fa3b79744892ed4d3e2c74f0f323f48f5f90062b98e957a5ccf7485ed3f3f16356bb31177861280187ba25d68b36d6c36ae9fd4dcd4e0e8a5997ea62daae67a25bb90059a1f378cef21c7772be06c251a52ce7c68e7064cdb9f93a35c57e2e9c3a0de2229a188b2bd070172bfc57d5c2f826746c5fd277dbaadc5bdd552d136475fbe1cdf39589967cca604a0d064fe5b81e8a5d3864b915ea4f92697c55082bde32f9d069027637cdb17b4c4075acdad13f9cd80fec67db6394db0027003bdcabe23466a48e38e5ac71a01654eac95128e88e03ea2abbabe4af69ba6a78903b4906f63fe623e308c239c9836f42a7efea0ea00c375827f7606482373648b31bfadbe8515158781175b0d4f950a5454d2ce5fb8b00c7388a56382f21dd6407a2b447eba14d402f774201b0e53578ce5fc1121ed90487c858d1a014f8e64765c6db2901a33f9a37a2eb23246fa8a2d3dcf7a15e105ce4ad2e8355c121895c4e207e7d7435479787f1b9cf294bb6508b3a480135444e1e8062d9986784d90fef26ea145fd736cac9f53cd59a5d0195c50cbc728237a2e2950cf50743ec7f8de8d32b3edc726d2fe2f50c1881c5e31055fe7f80f6da02c6a8d26839135e10e6184e8bfcefcac83237335b79ffac61744e2a00401d3a22bb0e6d7bed91a8573e6b6279e2de7b67240363084bb6edc722a46775589e3bc0bb31241c3f802fac699a2a28d73b2aafc9bf0f1b8266e7ca2bc6484699705007b514807ac3bb306c98382"
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
	#
	# // Compact Slate, slatepack_recipient as a string
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
				"target_slate_version": null,
				"slatepack_recipient" : "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd"
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
		"Ok": "BEGINSLATEPACK. 9SYQwwdmVkpFdxf gffatdijA2xEfzz Qm6RCcqQL1ih2m1 ehDnr39fMrNoEKp R7LbqjgJXq7YKMX ghE6KXQktXySAw9 3vSYHzeY3Z2nVZT SjohiV2njUcnKhD M6bW8iv6PDAUMYF BtbsWuXZYsrq5nw y2svoZR1qEGNKMN 8R1kGWQnqjGGmW6 d6rCyWWkgAxaq3g Js4RPM5WBFDGfyo gCgExbtiP9mCpXn jDWngzwvMHxyBwC uYAzF4ZWdC5sGRa NeQCpeX57wJ6acG 6nHP1uBATtKqEyK 1vsUYN53ihkaadx WndZigH8SoV8wuT srXto65QrW1tUQF 3mdk3e9a7EYEdao qD3exj4xnYwNGuq tkAR9dpjwywMJ. ENDSLATEPACK."
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
		  "fee": "80000",
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
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc07c1b899aac6e4d5b44f3dde53f1c8031cdc191bf25c2cadbc0aefa57ae335e",
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b7d6992795676892256df4fc1ab11902a9f5b827e0c01fe157bc655a58d725f9b",
			  "public_blind_excess": "026f382590590b854a8c85ccd7933d6deaaa0568ddad12bf5201811bd49d82d15e",
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
				  "fee": "80000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "0948a8c60d54a8f23863509f351c5d1d39f030688cc933e87f4b2869983a8f69c5",
				  "features": "Plain",
				  "proof": "760aa6096960b9f50d2fab99c1f11d527571cb485bb7953538b0583667be30e97f71dc399b752f160f655c1399b151814ccfa4530b05c99555556994a9110c880be0f37e1c1b7d7d04f83c52289d043e5b532c6023860f0afb15d65baea7d043ec559fc76ba5764c1fbfe8a1cfbbb27b85cd917d55c56f43c9d828c4f9c6a2999811979a6017a4ac682a1f97c913767e8b68a954d747fe80039e211e36aa268057a9163d5ccd28887d4e16debd4f3260ecde029baeb0f0afd0e96fa834f25c8197e3df98c9ec70e724fdaca062959e3fd91b8c085de7db0efcb7c0e4794bbb431fe9beada4b715c24261025d09c6bacd4650f1021d62fea73dcf535760b5f3c4999c7eab87454f2c8817b9fa511c3be89530afd2bab52d14f9997c859dd0701dfa893709144a0c1fd16f18c24adc27c17884da6fbc6087c05d704167be62ba1fc1fe03791c0a9ac272cd735ce00a9b221bb3701c3b97e71320f54d124f157556c8a3029ec830563fac384f8a3326bc61721b502e1f376df06639ae016e73820f26d6ff6baf6df600908152e9f21cbc4989ff0c63114af3e6cbcaee9b5f009c85f5aed892c8c90f519742df461332899510e6537474feb9bd4ecd212879bf9ece5d0bc8574f198f7fcaf1e3c6028136cee826aba7460986ec1c564e894dbc584553be9d552e8c1dd27e3f289f6be8c04fdd562c008589e0067a2b5353e4ab94bb4f8e393fc54ff3cf46f57707ef81b4e7e6acb3c41f3223014dc7627d4dc9737fbefef46dc1f62eda405edda4b637338f0c2781830ec4c84dba822e8e9a0009c286dc4038d2518b5491fcd5562eaf753868914fd38cade2bc51f34e2cb1ca8b4a6b623d8777b1f2492c9957196e1a443139828cfebdff70e7bd5375335605eff13bfd7384a13665738dfef0e374257e7dfedef570169a27bcd05d70ff0445e014d2435d"
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
			  "fee": "80000",
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
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc9ae9dba21a046e980ba1607c74bd717b501feb67597ce551951061152f16ace",
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
					  "fee": "80000",
					  "lock_height": "0"
					}
				  ],
				  "outputs": [
					{
					  "commit": "088b2538249614278dd45416eca661fb9e0454d0a5e95bc2164a585097bb0db54f",
					  "features": "Plain",
					  "proof": "eab33ba40cc1263ba109654dd911e6654ebaea53e904ebf8e8ab288fcbe0036bd286519ac5146fad043bd673df76787dab7a1e7aa54dcb30dbc9cc9d45ee1d0202ec22c2ef6eaddc85df385dfc309f47fc39de2988eb2a41774c2b0c7618f6810db53c16c85629e76a1a7aa0ce709d08b0882eb32f0235241363b8cb3e94a59b9c3f4262edc08efbaf7b857524b31de3cc711e5d01ca5ecf459e365b556c089bac5b56b407a918e7abf415d4f331608666114cb57a5cd388cef72adb0db0d868dd68b4af754c85748ca9e4ea3c7ee2638a677f7802658b312e08c39bead82fee0fadd96a4333e3ef4cd83419ab227f0c4d164af88be96bd9f643d9ff677141a87c9386728b4f67c103b808a42d561d07d88ad1ed56e826226a1f20a2bcbfa4188b5d05a6f01bdd2bc8b1a2eee5172cba35a5ee996d25adc9fad3b9db46a1d8a13fcfc6e4c9c37e69c0ee608601f3329098d41c207e1bcaaaf23dd76fa8c3f6d66fd200f83b11b4f402459af7009f245a5f6f6a4bcb902d941fd6326aaaa3d2d8583ecedd35943e5b24ce7ba5bb6cab3282143f4651824c6fa160d748b9d37d38f34c8b9d082725b600ff5a1452a585042daa9b673e2f8d8ac09ad55f735f3f6d4266a1684e5f03f8f7f6dc5c673c7399fff94f6f1f6273fc0226aafbc8b589223aa62e76473130ed7eeefb179462176f858fbf76d11fb145c802b89dccd13907ba6e34ed58579e57b45c32f95362e98d3cd3a795622cae2b070b3e07c854b8a23ab279358f18c13df308bf82574b28ec5f12ce1c59fb3bf5c379274ce2401318b6ee3888d0fbf157285bd066aa83e77c00b01dbcd089f741b153f2ab4d7f2d3f417e5cabd0a52ed7d3502760f2252880626a66d8dcbcc19c7d5f9a5a5e4adb2a6706d1467a3e9cd8afb6e028b10a57acd8c0aeeebed0884c9f3ca5e04cea406ae68586"
					},
					{
					  "commit": "088119ed65640d33407d84da4992850eb6a5c2b68ad2ff2323dee51495599bc42d",
					  "features": "Plain",
					  "proof": "5035e8cc9a8f35353bf73124ef12b3f7cff7dbcfcc8476c796f62bdf48000e7c87a0a70f2deb44f502bf3be08302d2affb51ae9b7b7d21b96752dc9bd22932520c46311cc0492b1a8e5bcd5c12df5eda2a05860c9db2ac178a2c1c5c01acf3859b068c927a300a4d883b03f03a062dd8475174d8d1770dca2d24e60a8899907b8b425346f1c75c8febaf4b21d81666d9fb6af62f8059f55677a8cef90e64be362d6c7232e009209fbe4a1b1918211109d3d16f08fc018b1a3d3bd11be9495a6a40cbb433130f74b2e0fd4d97da78e623f329922e07a791aab6c93a477449c04894cfdba37a3748fd7fd7203b93e73b00299e367efa5411cd5da70104dc25fda3497c3c99bda84f3bce4c205cb27d72979bdcbfa495599d9804cba3096319c3c5c4aaeeadbda2b185196a3b5785c3e68de0ec260cb1450cfbe0934c78f61a4df8632018e731016aa82dab83f09670534e04c044d20eaa2b9281bdf6d3677be6fab54203b95701c8a962638e78706b3024c61994b420705934f9f7fdd36bc00431cea462edbabbef2aea62cf422a736f02f8852c53996d0e663648f67838b2f084db39b115de1dc05047803071e1ac2ce25e5d2ecf41a83f12adb88ee336ba6e04b52a59fe138245ed2a2ff46ff38221ee7fcf311bb330947766d8f695ec990efe63df358bd17d15d825c42b8de93cf740a22a0328781e76e92f210ba0ae989c4290f3035b208b27a616076b6873e851f3b5b74ad8bbd01cbebcc7b5d0c0d7c4604136106d1086f71b467d06c7c91caf913fc2bc588762fd63ce4ed2f85b1befdd4fa29ae073b943fc00fc9a675a676d6d3be03e1b7ac351379966fc5bcf8584508b975974fd98c3062861e588453a96296fae97488f42662f55af630389a436707940a673a36e19fc720c859660eabc9de31b4e48cef26b88b8a3af462c8ad62f461714"
					}
				  ]
				},
				"offset": "01ed09a32ecd31908d634fa722c0773fe1c6b23c431a8f0b078f2b0fd6244520"
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
			"Ok": "BEGINSLATEPACK. ChMr2zxMBYoQzt5 dPUaWxEu6nMDXpB V5fdbSRER68nx94 1Pcksp6ymXqE61o GqXUhqNFWkvdv3M TfvNquRPNoN9qPP 4rNszCMD9f3u2pW CNHTiB9dj8cPDsW VDdzQgMLVjq1fab yAybLrrRapaiHyR fGTpEktHY7mzXPC FVnQfXMMShq37jZ s6cG3p1EqjeGskq BcLGMGwn6i5cmqx Uz7HT9DR8o5n4eF XCo2TqSACaKkYHQ 5gAoPYhpdtxWGw5 AtcQfWcd5iTD5Ey juEstYWMz211ukc QSJ3CQowFF8u3eH hAVbCx2PxutJpiH PcRLT4GHrnwwi1Y VGsuwrbEu8ikEJd z4hzBU75dNwyE4P WiVTyv45KKmUenF uEjre5kbMjmhmn5 VYympdUmJSEs2Ho TruZ4ob35JRBMpj fVjA7roYSrjLbRJ LkoTGeAKZKD1MLY F4Ao4A3eEttQWVZ rL8TJw8RYL5xWiV WiSBwW1bUkWJFQq nMmAK4ur8tQvmD1 h7qVs9iQZ9zjJgJ 2B26QPZfvEucPu9 AFgZF77br1N13mG RadWfmLVFg9UDBU tnB1VeNSzJP7aM1 Z5z81UcWKkiiXGp XnzkJp1hckFoNhP mdPLRJCzL33Asw2 n9zREwSFwrhvFr4 anJkKyFUWqEcnQK DgDXrarFgrxQyEU uZn4n7pQ1dypqhj yhmiTTBWgJPo2vi 19VmM7MGnFipykd 3jxWQeFBBiirU1X QUGDEXJ2AT2JsZ9 GrFWfKx977wz8uf KR7YWQiUkPg4EmC eLZQngBfxKoLfjN PteAwJJFAmQx7kW 6htEAmv5yZC1Ejp 7uESpewwUxFoJ1g FXCDJg1ck8AqY2j TE8tiGSMNbbBZ8L N9Db6q7MJRtrkT4 2LoTrnuCBxx9sJA NVGMtm9DWhojvFP q95B3YxwYhoB9xQ yJDXCu7ocx2KQcU cSzTQUaBL3JyoKX RbYEqpFkD9Nnct3 ivHadiVETyc6uff vrBLNbEMpgoSX7V 4pKKke6rVu81TcL pcvgG76n19UcoN5 HFYVwEAF837WQnq TVQUy1j1UQ7d2pP SUEJHqNo2QyySCB 79hQU2WdnR4EJY4 AHgKG5zTAV8Gah5 jDGgYFRgwjLLEWq pkHY2Jhsd3cgKbS ZvQn2UtUMGySwZ2 SYqKVprdfv65naE avXCr4MT6uZHky7 iEXwB9Myh4x4WKK i976ffw28yGDmRN osj53XCAcvjsii4 j2E7qkUXyNSkGRm bZM4GzameEPiDNe 8FXerPBTEvuzgLH mv7sPMsevEcfPb7 k4eXk13kQMwD3vX Ew1nyCaaUb9Qmwy NVVmU9R8C8Rv1G2 V1do6CnTRo8oAtv oqpDmeGv2yiGs8T GujGsTRKgdUN3gp XpjcCRg1ZHPuSgF EBTBSF3MEWipPMZ daLXKcgXr8T82kP zcqYggrFxYP2QD4 HuJn9TMt3n8xxiN ay3rxUPQUdnJ7Dz byQV8CHxoK2QGgt x7NTr42eB8gSPpB rPpvxWshUKQ6U7B i93UKMrAK2xiLnH Hez8jFCDTqNZCp9 qB8dzTkfavQRxV5 nD3tHxKqtx2Yphk 4Xv5eJzF8gXafMt stcrLngZjvrgmdV ZjY1w7bwPixHCqQ hs9LLm6mEJmS97w SotoAjSpffqxTC2 HeX8. ENDSLATEPACK."
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
				"version": 3,
				"orig_version": 3,
				"block_header_version": 2
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
					  "commit": "0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3",
					  "proof": "6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4"
					}
				  ],
				  "kernels": [
					{
					  "features": "Plain",
					  "fee": "70000",
					  "lock_height": "0",
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					}
				  ]
				}
			  },
			  "amount": "2000000000",
			  "fee": "70000",
			  "height": "5",
			  "lock_height": "0",
			  "ttl_cutoff_height": null,
			  "coin_type": "mwc",
			  "network_type": "automatedtests",
			  "participant_data": [
				{
				  "id": "0",
				  "public_blind_excess": "0321d743d91cdd8b126cadb76b1b7c6b6073385be37625fea2a8a891354672fc41",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": null,
				  "message": null,
				  "message_sig": null
				},
				{
				  "id": "1",
				  "public_blind_excess": "0256ebbe7886197266fbd2d039ec1cb8b551655bf58508dcb5c6a0179e640bafcd",
				  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bbd23a1489fb9d4d0bbf66bb600ab9f6326a6c9dbfdb6b8bf8d4f22f97e94fc4e",
				  "message": null,
				  "message_sig": null
				}
			  ],
			  "payment_proof": null
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
		  "fee": "70000",
		  "height": "5",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "network_type": "automatedtests",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2a583da5028b12519136554f860b1c773d0160fd15f6f62687cd7b8d852e1831",
			  "public_blind_excess": "0321d743d91cdd8b126cadb76b1b7c6b6073385be37625fea2a8a891354672fc41",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bbd23a1489fb9d4d0bbf66bb600ab9f6326a6c9dbfdb6b8bf8d4f22f97e94fc4e",
			  "public_blind_excess": "0256ebbe7886197266fbd2d039ec1cb8b551655bf58508dcb5c6a0179e640bafcd",
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
				  "excess": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97",
				  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4de77bdeeda144e7214d2dc10587b6bbda63a729d913adafe6141d9e8604c31480",
				  "features": "Plain",
				  "fee": "70000",
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
				  "commit": "0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3",
				  "features": "Plain",
				  "proof": "6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4"
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
					  "commit": "0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3",
					  "proof": "6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4"
					}
				  ],
				  "kernels": [
					{
					  "features": "Plain",
					  "fee": "70000",
					  "lock_height": "0",
					  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
					  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
					}
				  ]
				}
			  },
			  "amount": "2000000000",
			  "fee": "70000",
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
				  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc55e87a5a5316a4ca06dac37f29a9d99cb5a85d60e6799e24db155a6d257f2c3",
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
		  "fee": "70000",
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
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2146d6fdeddd778ca38567318cd043670358adfe111b3f7d1fc8adb261f56464",
			  "public_blind_excess": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc55e87a5a5316a4ca06dac37f29a9d99cb5a85d60e6799e24db155a6d257f2c3",
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
				  "excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da56327d306b10f190853cbb9978e3246d0b232d52082d85f6d790359344d5728",
				  "features": "Plain",
				  "fee": "70000",
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
				  "commit": "0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3",
				  "features": "Plain",
				  "proof": "6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4"
				}
			  ]
			},
			"offset": "363c8f5afec3cf7ded8b38ef912de23ea601da01cc6ac25c3d0625f1af9ecf4b"
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
			"slate": "BEGINSLATEPACK. ELfyzktRtes9GFB Ww2ZeKJcfwbJJtT G39gGoXEAWkd8PD 1Yk72PSi2foXgYu 2YXfY3r3ALDnwfY XgFf78LkHNUtoDr rHTHsKAVH4KoiNh WFPYoEALfCrW1e6 KWHKNZqLpQnwJie ZvrXJAErEJqguok Ft42GmV7cB3xQgq 9oKZZ3U3RKJSuP8 npksdwPccMovJwH mznvqApwJK6BSNM qQuhvvvb27R5VDm udN4Wr2Lx7RviUH xwkgsGtTkBWiXKu Mra1zCGgZyeW5XQ Hv8ZkgwB6E8BL9R pJGfrwuixvJ5j2B yUfvF5uwQQfKics fyVnGu5bjojk6Vf ABdMJTFP3onXzRD hkXtVBruC7QnWLS JXXVC4VgCVUqbNd 3avz4x6M5HnsC1f dSBdrjAtqksUCJS RPQM7h7rbaTQYmD 6vSSFEKVbFjdpPY XwDCnyGcaMtbJrM kGTXnogwqw7WyMx jofjZjDLU1Y7gFe wWaap49nxxpum5m a2HGHkAmjYZJhWN M3r4jY7Ym1EPALU StkiT6EaHJRwb1w LQGvJ8E2q98seyf 6mqSt4DbLDfZwnW BXkgEBP9k2mp8E8 BN5pZzgWpkJWcnc MtnSGLSDmcC6Sca UNYoYLsbUksz7di m8xjTDtnvfS5ypC tTCWwkLjD7P9SJf Qz9TkdiWdYeBpeu iMHsb5UBTrz7gkC tUa86WDCdGCj9tq t6bySmZoEkanftk x3Dd58Zpcn6xsRH C5Xm5f8XC5dU7RD b2tYrPbzQFT7Q63 3XHPrFoEzQXRHoH UguC5XB2hPneL76 YXjn1YCXQQyTano BMBHWuf1gHbC8Dx 8uxVjTTVdXxUbVN CYW66uFsjN9voFd K8CtQNGnrRsESbp zAy2Crnq8mud8oU eX9nFkswFdGv9V7 pqWe1C5qkXEh7YU HEXp6QxTh8ZSjYx 77Txk8CiokYgXrW DMpmoVi1ZNCD8p4 isk9PZx4jRjjUVk oDbg9AUosHqoCgZ v48mFWRg9dGTJo5 xTeDWAobiDZZK3v 3R9F78YipTCPDzy 6Mav5WwfXw3GSRx gpefZgtLehXs1pK r1kZEJpzFgkveho ELwNS7rky5aV72T yZN8dX4LoD7pqNv 9NHfkHqrfG4iQF8 dCVofJ9eHj5HPKm CjURa53denpPtzY t9Jze7M3q67XpVf it1bEnjxoFBdWR7 wJB7rMANZriwWPd hCPMiWeEC8CfFHA tBzgLWuX7dYSFx9 CiJm2tb1mjmSCpT TtT4gCfNogbstWx fgUGZp3FQWByFr9 KfL9R1dUr1TN3g9 Aafoj5ryxX7kSZF jNYLe5nnyZmdfxg rCzPMfDZvCWVhu9 8UMmTJ5RbywkHYt 8Lsg6KAfuYrrTLR KFjLv4FHayuTyJD apQYPEYuFQSz8PU HeDtGg34om8Kmcj FD4bu5yPYNgff6P YYe1MQVPKs874oo zQymBZ3DZMQHUZ5 xfBPyE115bV8B87 dkZ2EdsEnF9dCWN xTQwqRFT6SYx4XD hvjeTTmv1bBtfcT HkFzadLA2CNC7Jd aiMu6d4Ly8cEorw mAqa9sXaxp1gZWL E236JZDkxsTfGM6 E6zYMnZrj3cNqr2 VpruWaxBAa4Yze9 L2hrPpNyH36Gqhc EWz6emMigckLXFa 7qJJQF7iy4zqYpf WuFGs1ebshGZnsE 1LQFFzKoq9T3KAy izmvrMKEiu1jReu xpUEKjtppnmfaUq s7iL9rArewpEbkM 5vivNqSb4G4NSqG fNAQJ1Sbi3tYpSC TMpopHAZKvJFA5T sQrBLxBtYKpNkoo 6Z9YYKMQmTnLxdL huxaB4vkRZfd3qB y9symQkKMAxJaHC WJ1wLtKRnPCLBWP rudDftbAJoLngEQ Rm5yqApeTW6Fkd9 9shVjBYco37Fybr GkUnZ6KLrYWFLhj dqHZ2HwLkgSnF75 uHSM3jdzGzcKugo ioEKbeaDMni7ehL Lc6eVT8WXwtZthS DCns74Vi1ELBzEL GTn7542ZiZj6cvZ YRz9ycaDjMZ89y7 4qSYw1QbfgR7JBx Mjr5C1ttwCEWymR KNe4t9CFPkn78TS A9gViN3BHaNCvW2 bP62L5SSQiEDUkS m13rkqyt47cpRCZ LWG1YXjN7AcuASD HpndWSxwxUV5GJA drTF4o1bTPUxRbS SG1v1iQ3P8fYDgV GdDvfBC9zaRA3mR pVHeGqPrYNW8TY6 mTjyER6UJqheyvb eQQQtysJespsXSk 5b4L1EfjbXfusw5 SNdWkyAcYDKcN4m RnGYAW35zz8i2wS aRTRn7dtsnvkuJX toPgCKcj6hNytDE bHgFGB2jTRxvbUB f5fqHgar6ff3kuo QoaoV8H6o1NADGS BiDtqf5823mEsNt xYox8QkUJ1DVFTH MFe8ERsN1EsvWxi fUodcW9otyJbUV1 tHgi6YRpiXuqZgs LqxvxXXqsNAEswx kiu9AjfdXYEtJWS oU3AaVB5PkTc9W5 8rJo. ENDSLATEPACK."
		}
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": "BEGINSLATEPACK. 5UhKHeyjHydk8xA tzhrQRM9ARWQbbj hWybToXxqE1ZbfX vXGGRuripFL6yM6 sfuPDhAcvPPc2se qi7C5LS2aBf6s9s 2CrSvRX1sDmSYNe PMpXjAwQrtSsx4D 9QN2FxcWhsUa1nd 6CkaxgDTu811GYZ pCirtuSqeDGRFyf 9ajaR5wbVj8HMgR NJwDYaXZL8pnoKz untwz3kRtoQzZH7 DZv8ntMg75TJGMT A3RAMLFvL2Qd2Du 9MW2dCH2C5ysi6J qeQArK9fM8RMJ9t 3K3tuQjgqFUawDW Z7EtkTGC8YMnABC ZZ3DFLN8Ait7Rw7 thq6natUM5yWaaz 6SDhGsu6ZPxzpCP c8jcxrQBup7xn9o c22uQ5UjX468bp4 xRwpKsM32wcwFgQ PX9T5UQ6BSkFMhy XNNiXE5dPgBQTbj 1LwcASTdmDW3hFd zq4aFNdNHaHPU1x Vzx3Deb4UCGSVCu bWvi3HjwtNdMpy7 w8iWLwkYRW6SUV7 T42T8yU42WQqP9n xNvHg9zFbt5yh2h Yso17HZMdEpMcAG x6QqwuqWehtCw1D 5TjYDo9xcshQ8wJ 4x22FEkkP76mJCs XDLVkYAy55jAhwF 8mZy1ddBQsVBPKe JqTKUrNrWNHxcqm jXj73npDYqsfoSY PAmzUjcscyqpq5S 67iix6WEpvBR4Jt sFikz69pP8UEQyo YfxNfn9fPMeJa2L 7dn8xNNFZYd5Bgo ADBdaacVE7JcqG1 ufKmfKgor1tSdSF He1iFyxRjKYz2SY A4XwBpf1LGwSQXa SdoQxL6Y2TZQs29 55dVFk6PrZUxD7t YwaFBCjWotUTbpd 2sVvEsSzHgPGdfi Lftgtdzwop3mGzi xdTQ5TnzcwuhY5y 5xU8tKVnLPCCN4N YpvqQXM8RiNeEAH KefTM1CguL7ACtg WoZ6pw67AmbEeBS RmRrqp6hx9dQRnx dLST7G6sb6AGFrg 8dCgL1moaJjqbCK eMDx8ZT3BV1SY6Q mydm3DwEUXnqwW4 kt211LQnwKqQ9Zj a7HXzaUxkk2cm4T pPbC2BqKXfPW4H8 oom7XwM2XYosCn4 n3GpUjb9YP6eZgE cAju7iJDTpweCJF 3YcW3qcbrwhrzdR nsVF9HW4yWYFF8b G89rCpXEgXWt7vM NszNM6sassovZ5K 7xcsJyiYC6mqu2H xxhEXYbRvv77veo dG4joyCSN9tGtQm 5CWyBbhY8uXi3QN 5x1rSVXPaT4ivXS 2521gjdX8ax7kz7 VyJrcseDD1UC6eY fS1aG8fGh9SeEoG 5cF6MZDmZcvMEDu LvwpztoVN79CXrb G1EL1FqnJ2Rr9yr Rz3F2fwQaZvXwND SoUGC6kz2skSjk3 Cx89eQDjmUF43MF Uw4MKQ6dkpo2mdi mXcC1LyeN8gMbgh 2pDBA3hhzPUT6yU 4oATmSgXiMBQuvA PtnMJMvHyDyeouE 1oSd2dPVQEVxFSR bQey1vTR7kDvJum oPQAE8C69BfY8Tc hdY55twjmmyC5o7 rtVYSrLuh5wyLVn UdW6agZd2iYoWgY eWW1aeHsfRcEr1B yT1RtsUtrrizcyf 2MWRnt6k45JwoAy jkNjqT33HzSQzRn TqJSj68HW9tLdPD MqvDwWKMu4CZREF opE76RYHa7JEfED agwwCUTQ5NwyQ19 MivCVZoHzYikcHx aBcnpXGTfbZkgph T1ww8AybJhcigNw C5RMnrPo6B2f8wL MdPLdFY2NsGFgc8 hdZNyBu9F2Prjjp DYgAB2XwgWRM1Gv LvZLq8t86zx7TWN 74rFye3rsVu4rh8 H4F9YhjundwEpYq ivS2MXfX2kAx2tc cNbVtHxh4vc47iw L1mbmyzugStfxbQ Vs5NY3zWWY8nXQR GshQts2S3s4dnBa qiKMTf8xo34j6AZ 3KcscyEoQRqWzvM RANTgVLWf18Q5KK BKJk17975xbHcRJ DNX6BXGTTdKNDH3 hK4kwjH1QVgULHS 99NxY8veoJnjTRH 4wiY6TUeam1DCt2 yYt9ond4cUGhbGm dqxCxKS84q53TuH CeoWAZuJrT76av7 4RMDp4NaL1EwHoV Cs8jYbiekd1TUCH hVro8r8ViD5GkE4 zvdNBC6wXbjgHaN MswvySGYtG24CDa QZeK3gGUSRvDnyt 8QWAisvtsLRqxtA wNJ892TnMcE73Yy S8FW18BZFKw6bym 46GGpc5sTWeJZWv okHqTbZSAUEr4rz cqDu73AkPyNJxTb apCH7WUfjkAJ9Ch V4QNLTe4FXsACQr V5yCF5Wvh2AaghB VpgPDNn9J4PSwRJ MX1i4hHdLNE3ygL iJ1ga2KtebUMZnx upZMop5spekkQ1A M9Mozmf6wamS88o KAcjYBjdvJerFDm JZsCjbsZtjmuNPL v8XC853wXQhXUrX brLg5feNJrEZKwQ 7wiSv1zJgXUrKxX 6aPyAEHJMLd2KVW qBXvbNRFiXBsJtA WDZAhpZM7bZJwYd 32zxkYAoftaDPTt VKNYxVDLoNq4cLp fbbfS3i3VakDGiy rkrsxBWrJDrjKkU 9T7mguSG6fsBEAQ sLTRoMAzBXEy9cX vE5aEtMF23G84g3 Ps773teAbhnLJJM K7zkemNQHN4MqSe mGxpv3QKN2rbYv7 uUZxhJmAYw7cTu9 QrXyGXudWSmSig9 Zvn4L2fUQ2K8azY 27txnXGWLYtBXxi UC7nRQM2TQdSYBQ joXyxWazoHCqLDX fm1sfwGqnBSq5GE tywxgWbZYMbDcQP smWArhiNxh. ENDSLATEPACK."
	  }
	}
	"#
	, false, 5, true, true, false, false, true);
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
				"fee": "70000",
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
				"commit": "0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3",
				"features": "Plain",
				"proof": "6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4"
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
		  "address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
		  "amount": 2000000000,
		  "challenge": "",
		  "fee": 70000,
		  "inputs": [[9,135,120,206,34,67,250,52,229,135,108,140,183,246,219,187,214,165,100,156,21,97,151,58,128,122,104,17,148,28,18,54,60],[9,16,193,117,33,0,115,59,174,73,232,119,40,104,53,170,183,109,88,86,239,129,57,182,198,227,245,23,152,170,70,27,3]],
		  "key": [178,214,169,41,51,242,104,31,198,94,249,72,242,14,219,56,98,255,165,45,172,150,214,162,224,22,108,170,88,110,184,180],
		  "message": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw52000000000",
		  "outputs": [[9,137,213,46,23,205,7,178,37,46,67,23,165,226,249,47,116,234,213,78,155,170,173,75,18,215,102,193,65,246,38,218,211]],
		  "signature": [68, 175, 196, 85, 201, 228, 112, 2, 167, 97, 186, 39, 196, 250, 146, 156, 239, 61, 35, 152, 24, 216, 221, 104, 120, 139, 149, 23, 146, 223, 16, 50, 100, 28, 62, 114, 68, 215, 49, 42, 65, 82, 234, 130, 184, 231, 76, 108, 88, 18, 94, 206, 33, 64, 54, 33, 150, 190, 112, 211, 94, 54, 161, 169],
		  "slate_message": "{\"destination\":{\"public_key\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"domain\":\"\",\"port\":null},\"encrypted_message\":\"2e14c3e33f4c7948811f706469d8081aec26e4fa002456a97ad4e98527ed1618dc7ba693697f8849ebd4576d2d73a55ec81aa0508750b34a804f54531c91f7c94f69dca0679471cb61520515d8b02993f8d1d27b0cb3aebb1bed5fb4e06753d14b40fbcd9d9d22391fdf83fa1a8bd471e15d83e9af83ae3dfd09715e7d7ac353dc4a66486279d6911d9490d9417be9dd6837ac85e603bc50e04b35047c8cc6f27eac6681f514f0dd654cb4d3d0c84eedfd54cbf7d23818fa63fd5736376135ec5c9e5f95c619def8acd9788cf786ea966ab816ea668aed15c5bc063a0a8780aa040c2d2f92e4849f5ff897200092d654f59a169572e886ee6dd60c9937d1b6742b5d893ed395fb794911334ded61339f3e07a85aab598b002d51db412dc16e99dedf57e050697356a907bff460bcf6bca41fb9ad4a29215fb2ce994457a92ac7f8d894036db723be0961d290b675dd11a8bf44596ecf65e7270a5c22271ece96c2ae22e1f65917867750ecb46a3855a6ebae2bb8731304abee14d1ee1595a81625f2350d27b389703114efec85915c7ba0ab7406695c205431bca9764d5378a55cce52ab027627a59509792625bee934453569d04a54a18f8d8f33a596b1e0b65fbf7cd166de7268cf3fda3227fa308665553b69b62b95031d5ca46ab3d536da09e90e21d82eb2921dcabf3ffc46ac68ec8c2b1c5e4119545c5b9ff956553f166e8580775e2e3c5646e880d4c41f43206de7e2d2ccb8145406f404681fadca647f9b5b62d76f5ff4375f7eed7033591f17317fef2198c7c6b708fbf4dd4da34e5b7bdef8309bb49dc568d7a3d5a6b1346661c1b3fe0aefdaa1657197eb5659c35587f3c732e59657eb5f1ae52e8c84972f945aaa32ad33a9a917257d661fb0efcf0d09e7000039d91886e1126b8cdddbcf021ed07ebb6f8b57a546efdc1b09830feed99f192171a299b064123f290088cd3fa187c9c847fb5b9f1bd84c3e2f7741a591bf7a889b9b75efd75749d5fd90865ee149abaabf7784d9dd19277ca45ff89ce6c2fd298158baf706b944b7d411e530d1f93d4ef640d43dbef3dd71192fc200beb191ad158c69729ace15a7e7cd0861033e1027edc7212cd50c5b494193f5e11f38cf522284ef48aa680f006d06afdafd5de6ccef6500b223e28fc891b72e089d09b33e7dda7409389ad3cbed2919e569242cb1714c538cc7a7bfc3a1fecef8888c2cf9eabc33f75da2202801364c8f99eef4a4accaa1b9be7bab31fd58b9db56e622bc21ddbc0bced3e2141ebbc72ef777e0901064c0d27b11cfd121d9703736109944e318ee9dded5a7c51d5c8cf46eb1f1fada2912d0e404c604ba74de974544e25b6435111083d9d3871e06d592527d51c043552d9074a5810d2ac0cc73af4239034eaec08f79190753dc020d6464916ec752d930283ad347615f95d5378362b33e8914cde7d0713939773ee39534c565261074df694e139749366fc10470fc23e326fbd58adbb2b4dc75bd2866969ade7b697627d6a3737458e6bf433cb147fc7dde57f965939253c79b7d6d6b9c52a1caf38a3241c1959fa1f85de60479285fa01a37de5a4dd9f88635cad41b7f346bb36999047a9f6e79936e153c700b3618f2bd881978671bccbc78551eede4dae28d648ed701466c528c56bb4f62cff5312c785addb218ccd7798742cdde2f2958fb7bb6ed8e7cd4a406ad8b933250abead39d6267c38f9fa8254805f262588c367e3f4e289245a9796e43c0c6b9243d37c1c7c150e7adb23c074489cf7c2e556871aacb5cc124184f9494412950b9e530158e574b62f91e5145841f4a0107ec2ea36e23dfaf36f4ce3bd88b73347a1cafc8965f6aa5feadea13159e60c800a9ef79eeb3ac5c35bb1102dc264117702facc37cd257a915c9819b98e548dfc8f0b9eba3565a27ed78afad4da7b7cf34207fcaea7797b84ec738c7a98bc7b94778c35f7f7054c3b2501eb9e01d9e0a6c78b0fed897129cca148eb95f2664c712adaa345486359fa09920e4965752137d5a01a2212a307f1771cb28e83b9dde774755fd6b1342ff193a52988a33dea7bb8134b8c8a312e09c74bd3523ea8ab97f091f8f472af1eaaf8dcced3360b9ce4dfe6c0ba9571e206f402b661c575ceaa1ae53c2100d4914df2fc501f0c1d91393ef34bbafd1c4547ef997f756b9161e9fb3332b29ab5f2ce82a7f077d1ef1da59d0a1f77b38daa150ee9bf3227a72b4bf20913d5f9003b312fabd9be7512033fdc5d43a70a655ad97a53bd56e9850d684ec9160508d397b185f55581f93d60c0c7f52cd08c4ded24707c103573e527c1e79925a53e3747a0263c5e4d81a49dec13f10b497e371f32875fa38d6e33f4fa240a66003db075420f822870f79f6512441a52966f1bdd3af0108c831ad1c02be00bedcbd39b55b0c9af843e64f905d86e4ad88a1e3f489ba18004fd77c08077295e6a00baf566e0bb48a7400778e9f2893cf3f4c052d128cdc94c6378e82603c5e2e0bf2dd00650e719961878ababaaf768c7f9dd54ee5d4697280a28aa3c59b70d89b8c6b1e78e535b6502229e25f014f4ab326a65f9afa8d393cf18f7ddca848b9d6272214139b736e32a130503c3c7a172f7a426174b1fdc1b3438c88fe90fcd1e423474da105cc4f4e373ca5e084d4535ea25f7fe3cf0a57c79a0a042f4df9f036f4c3263dbba92794b8f029d904864870f9ba4e5fd045a1661617d7fc3fe78e0c70f21588722e551fc4fc5fa04d2f05b203dbe626bdd42019e50b75b91ff94fdcbb943b127067a0876bb1c1be9578ca5e55d5b161c6b30e77452ca0096ada434d39534399ecdaa5597e6271268fb0f2b83fea8285f7abd9c3e212c7ca3dc8622beedb1de611a0de94d6066e0f9579dd736164982a3d743ffbe5d7d66c9f43f5c5cfddeaca141be180aa7c3317477c00c4cee654ab9a9f421deec909f6892cfe52577f1f919e30391546b4024e6c0b06cbeb98637eb666262d0df2346d032df2ed4f6928ba9423104f4894d0a22bd44f96b4de9e53fecf78bba347702b71ce2e080b04b3caebb76076aaa7b1d28fdad52fc0f06f736aa0fa334b35a816c8cd1629f7e035dfe9e8738087b408724ff4b2572011ee54ea3ff97dba5531a5a7fc3a3f4e9e4cfca3348dc929ff856036464f6e8aa7a10f0e744a435d501cdaf41a2e0a16f8c396ba5d15b576be1478cc90a8718f1fd435e556e4b4b6f86cfae2aa4536a38f2dd4bd6cdfc2c6d171e9b53e7c41ce190e912402415b69f72f64be33a69a6c163e00012c1c035c3a3083742036047b606d114e8ab844c02c697a97b09283d1fd7540d85f6b09b14a34f985a7f8cd3b70fc3ea38d2faf958f4d3c7698261a37ba1db3387f235bf1a7a39098a36e2c6666b76041a9006af750ed9dd0677e2b9df00d4148bd2f1818c0b125bc934892bbb29c931ab2af37d4f3fdcffab631e965be93f3bada4d9ed30cef1e0feb99739c35fe69a0041db29fb35f324dc363c76d0d2b2a6ba9f219f1d1b7ade03f01804656df86caa936b2895b6e988afc5c7f51b76f7888f1b3c7b00617abb3f2185a5c8a38d273f62e35e9767f7705573ce778d0b6d3184bd8628f0fd906ae9f55859fbb577a29940790c5375aa2a236bbea90e59a7762b06b0d8bf8fcbd989d35481617d70a9b94e5db9daf5e68591cf19252fe0184369cf3b294329aea728f71f6e0f0baaf1521239bfda24396da109a83581c48b005960fe335a7ff9f00544f50b0151cfe586bb954134b254288e0b024a108909a7a7b4c31c442bf43fb42ea643a9b3bc84b5deaf6bab5a0d9a4fd03a566fe917a770c2a3e0fdcb50a913e2682207b28db789f3f56f1a27ad1aea4dfcfeeeb9057721f4855ab80c6e8997530b607dbc11a873c23dc534464a5641e494dc37dc9e6e2b30f053c0419a6d323105de2da807aa41e4829b6e9c897d20eccb80d90419e6ae13ceff6974c986a590c6cd7ab5a19f661f86cf65ea473ef774a4aa72c4875fa8e4e45e7d70a1d062b71c373a33fa65ca95940d88b758e8c1a007d64cf539940d4d2f0785097c72c576611a30af70d0bf3eeaf22a31b5033d767573f0c7e3b3299ab9b7cb944798f9727a47ee7f27d20b52468cf4172ec7fa77c8aa3c415b5e319619f726d58bc8041498664b4435d07b95cf0641541d35a24669802bdb9615fcdf9ac92e6fc808d2917265e64facc8561d01e56739e0b7dadeeae8b1b918ac05f0a3068c24cdbf716ce860ddc40136c8aebdffcab943230fd853fef269477673192939d3ef1e3792a91b3598f4d10fbd37f5a92effa9c44916fd43fad768f22b8c4e6fa93500b88949292ecfe848938478dd19f3d610599033b267a563fb7279080bbc92e092c72867f806bf86edc901b3fc8c203c46fe516f493527eb08c6fc5153811b25aa27b57a32f1fb5933c84d28bdf3a847151051e8eb38f775a51247ff27ac532eaf41a001c0af37f242cb26186846268855975b8e0566ec8aae7545077096792feeed03db23b1c1057870769a250205ceecc737a5a8f2ef014ccc4dae9c8a35a0f81be3c00119f72e61138ef19072d1cd7e9a713fdf4d8f75c96b591cfddc0bb13515d23d5a1c6a45bf6693faaa5870c1e15951f7de5ee07db4de4c22c9ca10660d9c55a8786fc0a5c143e07b2e5cea1ecb20dd8f01779d2d7ea66e4c3601fabe2a818e51dbcd5677ec7b7f898037fb6ecc35a7cb7ec4aeeb4aba462eece7ba995266ddd995d3fd1953ac66bc0f70abc846608153e55ca50ea44d1182ac7ff31f44a9da46321f033e21f623195c66fc288b4f786cedc43efcd6af6aa912de3d4d3a9ce44ae8f35a745b739cd7469be4f9e5cf188ed4bca89b0994d67bc2118bca91686fc0638cae1b1d2e93ed97ec603c9293c015cfc4e51988cbe511ba090111c600355a9f4a39e1e419fa186f733f6531470b2ad38f79d104acdbc930f2a4c2c1cf7736c443fc277387a6f0a75cec35eb7cea5dd930b5789e1912f07faab45341e83cb68f8caca1651c00212221938f461bbfc5b6ee5b2bbab368965352677f31cfd4033941d2f47705a5d8b07b70a3da15fda8d65fc0b8996cf5c998d1c12720a81059b4c57c6d9d48a835896c815413b7f9564e0fce38d07dbeb742d822c0f4011d58796e6b7a752098723b80ac08bdc36db326718b87ba6da3ce050d7b35d826654ce8c52fda834136015d148d73ff78743107511e27459024a5d056efd7210bf0079cfd53836276d41a8f8727d3f9873d387384072fa711689fe9b29b2586c4f61f4de5c8ffd65e9c1a63bf039ea8aeebbf3149e73c1ab2ac5505f5b019af9d9859f3b832a50e8b43109c33904a8b6f85355ba56e8c3faf416148357c94b8893fe3aea15e10b80df0269ce97c729516fa5c29410dd1bf4f96617ae72ccc0c5f4e6b8a9011a46c1521bf1116073006430b49c53589a65eda0508b46683c5c88adb267d04e1864aa54daea4775751c4900ed46e548bd59269cac179fca9ecad75bcdf0b940ce4bc301ee8b4b44c3061798bf936aebfeed19c66babb9f8f15dd1f09ce45985271b0b44b8fdedc41f93189a5c2dacd2f026ed00861500a8266aba5b1e862d9a84be48a4038cdb48be228d194f06b9c07b96ec00ea181ab8884d36dff15187d8cbd39f376e0c261df365f1598ed238df34f8c3b6e9f0991d0d91baad8442870b75f9c8d6e7db21b50c3aafc0c867c8d174b64d5478f29bd78ece430f6e55bf190a1ee847ed7312f3eb625ab569759ec5f43ecfbf163ed0d903de1e35edd088213c8a64ab29c49e2e6277132b4a613f4037e1fbe5607e8139f9c8a16952bfc80f8b345297979bfe28fa01f65b8bb7833cff5e85a9fa7d4befb115a312bab1207caaf9848aeee0fd73e07b5aa2d858a90953fd3dfa8c52f1d64a742161d2d573abc6d2074701a13b5dc301a66b9ca9e28a38b1a4df96b2b2c537565ca383024490e5805fca97d4a66b564a6080d41f6581a3bb2b82f2b2d19d134d47ef62c4dbe3056c922ae75a994ec4d83ea3c14c8319a8b2da3c4c3aec7ba220f410e10dfae20229d5febe5671a99501d5ecc15cf4133d2789dfce825df42babfc7b05ce782b41019799afa375909e0618d26eca8c95bad5d167464ff8f8541f331e6c0d77c91b65d76473f9b60988bd27f19a43e4c575d51f92a6723586d555c7e11c261d0edbabf8c36fb89bf2d32001849adb7538be9567c9d0e6c3529ab2cfe5595b8f8d1d28206162fea6f710c1fa0090fe87e960e5ce159fa453b78ff80569914f07d055f0ceba2ef0de76f34875f6ee1e2b20930387195dc6fec5f0cb4735a7ec84a779f038736fc679f0abf1f3a1f9c6a42a131bd18f132de24d81d126b5f6253f9e698fddd4ed9aa8c86852e95e3cc3b344fe694f7984b4481f0a3ddd58cf7451ef51a235ea0fc9684cea495012600c9ee2d353fe895932b972c23b05911733d0aaf79ba41a4b3e7ce65a177024d8cec021eef3585238baeeeab2ff051471b2222d64292b16e0e9761e590f9e2fb90a0efa340cd1f2b4439bf916ba05725d12d5192dc22bf447167050b562bb014bfce93f66ffbfa3fe0ded225ef7c87536e06fe0efeba1a2578010a6d16a546945e05f15aeb3497517d8c4bed8da1b3eed576d90592501d2e25488bc1e0185246873889e5d74e4b411f1984229aeee051f10738536bd5355f29af8de2eb5921b2ed0c2c3b12cbe8ef73f958990049367c6baa1e80254a24c012626d4f52dc596548546039d221dd176ea8a2b7cf70204493e496ccd44642bbe1000552f56ec6fa06e1cf235d3c17beda3a9e30b339f0f462566f67c99a0e61f7166fc107debe73da6b01dd0695359f49edd9c80729a68617bc706bed99c68ffa44e96a4875c8dbf189023b9dcd77696c2d6\",\"salt\":\"d3d4d5d6d7d8d9da\",\"nonce\":\"dbdcdddedfe0e1e2e3e4e5e6\"}",
		  "tor_proof_signature": null,
		  "tor_sender_address": null,
		  "version": "version2"
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
		  "address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
		  "amount": 2000000000,
		  "challenge": "",
		  "fee": 70000,
		  "inputs": [[9, 135, 120, 206, 34, 67, 250, 52, 229, 135, 108, 140, 183, 246, 219, 187, 214, 165, 100, 156, 21, 97, 151, 58, 128, 122, 104, 17, 148, 28, 18, 54, 60], [9, 16, 193, 117, 33, 0, 115, 59, 174, 73, 232, 119, 40, 104, 53, 170, 183, 109, 88, 86, 239, 129, 57, 182, 198, 227, 245, 23, 152, 170, 70, 27, 3]],
		  "key": [178, 214, 169, 41, 51, 242, 104, 31, 198, 94, 249, 72, 242, 14, 219, 56, 98, 255, 165, 45, 172, 150, 214, 162, 224, 22, 108, 170, 88, 110, 184, 180],
		  "message": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0afxmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw52000000000",
		  "outputs": [[9, 137, 213, 46, 23, 205, 7, 178, 37, 46, 67, 23, 165, 226, 249, 47, 116, 234, 213, 78, 155, 170, 173, 75, 18, 215, 102, 193, 65, 246, 38, 218, 211]],
		  "signature": [68, 23, 195, 182, 71, 9, 199, 227, 129, 151, 16, 59, 105, 121, 218, 206, 228, 228, 28, 62, 228, 77, 137, 234, 117, 25, 31, 85, 62, 43, 188, 194, 68, 197, 45, 241, 0, 255, 253, 8, 12, 149, 87, 92, 146, 50, 155, 109, 219, 208, 199, 117, 69, 227, 30, 228, 57, 17, 38, 85, 145, 143, 224, 238],
		  "slate_message": "{\"destination\":{\"public_key\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"domain\":\"\",\"port\":null},\"encrypted_message\":\"2e14c3e33f4c7948811f706469d8081aec26e4fa002456a97ad4e98527ed1618dc7ba693697f8849ebd4576d2d73a55ec81aa0508750b34a804f54531c91f7c94f69dca0679471cb61520515d8b02993f8d1d27b0cb3aebb1bed5fb4e06753d14b40fbcd9d9d22391fdf83fa1a8bd471e15d83e9af83ae3dfd09715e7d7ac353dc4a66486279d7911d9490d9417be9dd6837ac85e603bc50e01c31072d8d96f326fa33d2f647a6da314de3db80c240bca25dcaf5866d1af936f85536343c62e854cd0c93974adcfdff8e298cf38de9c462e940e333d9bb1197bc063a0a8780aa040c2d2f92e4849f5ff897200092d654f59a169572e886ee6dd60c9937d1b6742b5d893ed395fb794911334ded61339f3e07a85aab598b002d51db412dc16e99dedf57e050697356a907bff460bcf6bca41fb9ad4a29215fb2ce994457a92ac7f8d894036db723be0961d290b675dd11a8bf44596ecf65e7270a5c22271ece96c2ae22e1f65917867750ecb46a3855a6ebae2bb8731304abee14d1ee1595a81625f2350d27b389703114efec85915c7ba0ab7406695c205431bca9764d5378a55cce52ab027627a59509792625bee934453569d04a54a18f8d8f33a596b1e0b65fbf7cd166de7268cf3fda3227fa308665553b69b62b95031d5ca46ab3d536da09e90e21d82eb2921dcabf3ffc46ac68ec8c2b1c5e4119545c5b9ff956553f166e8580775e2e3c5646e880d4c41f43206de7e2d2ccb8145406f404681fadca647f9b5b62d76f5ff4375f7eed7033591f17317fef2198c7c6b708fbf4dd4da34e5b7bdef8309bb49dc568d7a3d5a6b1346661c1b3fe0aefdaa1657197eb5659c35587f3c732e59657eb5f1ae52e8c84972f945aaa32ad33a9a917257d661fb0efcf0d09e7000039d91886e1126b8cdddbcf021ed07ebb6f8b57a546efdc1b09830feed99f192171a299b064123f290088cd3fa187c9c847fb5b9f1bd84c3e2f7741a591bf7a889b9b75efd75749d5fd90865ee149abaabf7784d9dd19277ca45ff89ce6c2fd298158baf706b944b7d411e530d1f93d4ef640d43dbef3dd71192fc200beb191ad158c69729ace15a7e7cd0861033e1027edc7212cd50c5b494193f5e11f38cf522284ef48aa680f006d06afdafd5de6ccef6500b223e28fc891b72e089d09b33e7dda7409389ad3cbed2919e569242cb1714c538cc7a7bfc3a1fecef8888c2cf9eabc33f75da2202801364c8f99eef4a4accaa1b9be7bab31fd58b9db56e622bc21ddbc0bced3e2141ebbc72ef777e0901064c0d27b11cfd121d9703736109944e318ee9dded5a7c51d5c8cf46eb1f1fada2912d0e404c604ba74de974544e25b6435111083d9d3871e06d592527d51c043552d9074a5810d2ac0cc73af4239034eaec08f79190753dc020d6464916ec752d930283ad347615f95d5378362b33e8914cde7d0713939773ee39534c565261074df694e139749366fc10470fc23e326fbd58adbb2b4dc75bd2866969ade7b697627d6a3737458e6bf433cb147fc7dde57f965939253c79b7d6d6b9c52a1caf38a3241c1959fa1f85de60479285fa01a37de5a4dd9f88635cad41b7f346bb36999047a9f6e79936e153c700b3618f2bd881978671bccbc78551eede4dae28d648ed701466c528c56bb4f62cff5312c785addb218ccd7798742cdde2f2958fb7bb6ed8e7cd4a406ad8b933250abead39d6267c38f9fa8254805f262588c367e3f4e289245a9796e43c0c6b9243d37c1c7c150e7adb23c074489cf7c2e556871aacb5cc124184f9494412950b9e530158e574b62f91e5145841f4a0107ec2ea36e23dfaf36f4ce3bd88b73347a1cafc8965f6aa5feadea13159e60c800a9ef79eeb3ac5c35bb1102dc264117702facc37cd257a915c9819b98e548dfc8f0b9eba3565a27ed78afad4da7b7cf34207fcaea7797b84ec738c7a98bc7b94778c35f7f7054c3b2501eb9e01d9e0a6c78b0fed897129cca148eb95f2664c712adaa345486359fa09920e4965752137d5a01a2212a307f1771cb28e83b9dde774755fd6b1342ff193a52988a33dea7bb8134b8c8a312e09c74bd3523ea8ab97f091f8f472af1eaaf8dcced3360b9ce4dfe6c0ba9571e206f402b661c575ceaa1ae53c2100d4914df2fc501f0c1d91393ef34bbafd1c4547ef997f756b9161e9fb3332b29ab5f2ce82a7f077d1ef1da59d0a1f77b38daa150ee9bf3227a72b4bf20913d5f9003b312fabd9be7512033fdc5d43a70a655ad97a53bd56e9850d684ec9160508d397b185f55581f93d60c0c7f52cd08c4ded24707c103573e527c1e79925a53e3747a0263c5e4d81a49dec13f10b497e371f32875fa38d6e33f4fa240a66003db075420f822870f79f6512441a52966f1bdd3af0108c831ad1c02be00bedcbd39b55b0c9af843e64f905d86e4ad88a1e3f489ba18004fd77c08077295e6a00baf566e0bb48a7400778e9f2893cf3f4c052d128cdc94c6378e82603c5e2e0bf2dd00650e719961878ababaaf768c7f9dd54ee5d4697280a28aa3c59b70d89b8c6b1e78e535b6502229e25f014f4ab326a65f9afa8d393cf18f7ddca848b9d6272214139b736e32a130503c3c7a172f7a426174b1fdc1b3438c88fe90fcd1e423474da105cc4f4e373ca5e084d4535ea25f7fe3cf0a57c79a0a042f4df9f036f4c3263dbba92794b8f029d904864870f9ba4e5fd045a1661617d7fc3fe78e0c70f21588722e551fc4fc5fa04d2f05b203dbe626bdd42019e50b75b91ff94fdcbb943b127067a0876bb1c1be9578ca5e55d5b161c6b30e77452ca0096ada434d39534399ecdaa5597e6271268fb0f2b83fea8285f7abd9c3e212c7ca3dc8622beedb1de611a0de94d6066e0f9579dd736164982a3d743ffbe5d7d66c9f43f5c5cfddeaca141be180aa7c3317477c00c4cee654ab9a9f421deec909f6892cfe52577f1f919e30391546b4024e6c0b06cbeb98637eb666262d0df2346d032df2ed4f6928ba9423104f4894d0a22bd44f96b4de9e53fecf78bba347702b71ce2e080b04b3caebb76076aaa7b1d28fdad52fc0f06f736aa0fa334b35a816c8cd1629f7e035dfe9e8738087b408724ff4b2572011ee54ea3ff97dba5531a5a7fc3a3f4e9e4cfca3348dc929ff856036464f6e8aa7a10f0e744a435d501cdaf41a2e0a16f8c396ba5d15b576be1478cc90a8718f1fd435e556e4b4b6f86cfae2aa4536a38f2dd4bd6cdfc2c6d171e9b53e7c41ce190e912402415b69f72f64be33a69a6c163e00012c1c035c3a3083742036047b606d114e8ab844c02c697a97b09283d1fd7540d85f6b09b14a34f985a7f8cd3b70fc3ea38d2faf958f4d3c7698261a37ba1db3387f235bf1a7a39098a36e2c6666b76041a9006af750ed9dd0677e2b9df00d4148bd2f1818c0b125bc934892bbb29c931ab2af37d4f3fdcffab631e965be93f3bada4d9ed30cef1e0feb99739c35fe69a0041db29fb35f324dc363c76d0d2b2a6ba9f219f1d1b7ade03f01804656df86caa936b2895b6e988afc5c7f51b76f7888f1b3c7b00617abb3f2185a5c8a38d273f62e35e9767f7705573ce778d0b6d3184bd8628f0fd906ae9f55859fbb577a29940790c5375aa2a236bbea90e59a7762b06b0d8bf8fcbd989d35481617d70a9b94e5db9daf5e68591cf19252fe0184369cf3b294329aea728f71f6e0f0baaf1521239bfda24396da109a83581c48b005960fe335a7ff9f00544f50b0151cfe586bb954134b254288e0b024a108909a7a7b4c31c442bf43fb42ea643a9b3bc84b5deaf6bab5a0d9a4fd03a566fe917a770c2a3e0fdcb50a913e2682207b28db789f3f56f1a27ad1aea4dfcfeeeb9057721f4855ab80c6e8997530b607dbc11a873c23dc534464a5641e494dc37dc9e6e2b30f053c0419a6d323105de2da807aa41e4829b6e9c897d20eccb80d90419e6ae13ceff6974c986a590c6cd7ab5a19f661f86cf65ea473ef774a4aa72c4875fa8e4e45e7d70a1d062b71c373a33fa65ca95940d88b758e8c1a007d64cf539940d4d2f0785097c72c576611a30af70d0bf3eeaf22a31b5033d767573f0c7e3b3299ab9b7cb944798f9727a47ee7f27d20b52468cf4172ec7fa77c8aa3c415b5e319619f726d58bc8041498664b4435d07b95cf0641541d35a24669802bdb9615fcdf9ac92e6fc808d2917265e64facc8561d01e56739e0b7dadeeae8b1b918ac05f0a3068c24cdbf716ce860ddc40136c8aebdffcab943230fd853fef269477673192939d3ef1e3792a91b3598f4d10fbd37f5a92effa9c44916fd43fad768f22b8c4e6fa93500b88949292ecfe848938478dd19f3d610599033b267a563fb7279080bbc92e092c72867f806bf86edc901b3fc8c203c46fe516f493527eb08c6fc5153811b25aa27b57a32f1fb5933c84d28bdf3a847151051e8eb38f775a51247ff27ac532eaf41a001c0af37f242cb26186846268855975b8e0566ec8aae7545077096792feeed03db23b1c1057870769a250205ceecc737a5a8f2ef014ccc4dae9c8a35a0f81be3c00119f72e61138ef19072d1cd7e9a713fdf4d8f75c96b591cfddc0bb13515d23d5a1c6a45bf6693faaa5870c1e15951f7de5ee07db4de4c22c9ca10660d9c55a8786fc0a5c143e07b2e5cea1ecb20dd8f01779d2d7ea66e4c3601fabe2a818e51dbcd5677ec7b7f898037fb6ecc35a7cb7ec4aeeb4aba462eece7ba995266ddd995d3fd1953ac66bc0f70abc846608153e55ca50ea44d1182ac7ff31f44a9da46321f033e21f623195c66fc288b4f786cedc43efcd6af6aa912de3d4d3a9ce44ae8f35a745b739cd7469be4f9e5cf188ed4bca89b09e4e61b9221fb1af4182f9046a9fbdb0d3bd6fd62c920dce2e625506f51e579ed8ec5149a5924449615600fcf5f6cb4e4497f7d1a162fe074427e2aa38a2c5414acdbc930f2a4c2c1cf7736c443fc277387a6f0a75cec35eb7cea5dd930b5789e1912f07faab45341e83cb68f8caca1651c00212221938f461bbfc5b6ee5b2bbab368965352677f31cfd4033941d2f4774585cda51e50b6af0588c8830ad088192935bce8d4f407e0b815fc81d07968e8689805d97c3154d387ccc32e5a2b3dd008bed2924d42100431182d092e5bdaf52098723b80ac08bdc36db326718b87ba6da3ce050d7b35d826654ce8c52fda834136015d148d73ff78743107511e27459024a5d056efd7210bf0079cfd53836276d41a8f8727d3f9873d387384072fa711689fe9b29b2586c4f61f4de5c8ffd65e9c1a63bf039ea8aeebbf3149e73c1ab2ac5505f5b019af9d9859f3b832a50e8b43109c33904a8b6f85355ba56e8c3faf416148357c94b8893fe3aea15e10b80df0269ce97c729516fa5c29410dd1bf4f96617ae72ccc0c5f4e6b8a9011a46c1521bf1116073006430b5cb5a05ce32bbf05d831c6d3b558fa5e23387164462fc0081be162477481205be12e24be608779dad16cac89fcd8208c6a3e411c614c650bd8d4a41c5594dc9ed936aebfeed19c66babb9f8f15dd1f09ce45985271b0b44b8fdedc41f93189a5c2dacd2f026ed00861500a8266aba5b1e862d9a84be48a4038cdb48be228d194f06b9c07b96ec00ea181ab8884d36dff15187d8cbd39f376e0c261df365f1598ed238df34f8c3b6e9f0991d0d91baad8442870b75f9c8d6e7db21b50c3aafc0c867c8d174b64d5478f29bd78ece430f6e55bf190a1ee847ed7312f3eb625ab569759ec5a43fc1e84439818c55821833e8ddda793e8167a82bc3c92e3723412e1a603f4360e4f2b2347e8039fd9ff53c02ba9a06da340ec191c1a826fe55a65c87b2863cff5e85a9fa7d4befb115a312bab1207caaf9848aeee0fd73e07b5aa2d858a90953fd3dfa8c52f1d64a742161d2d573abc6d2074701a13b5dc301a66b9ca9e28a38b1a4df96b2b29532500ff3de50489be58457cd90d2a03b05183481821f3adda1b87a82fbe587c9124a47bc3492d9b8083f9f2de2019a4ecb893babc743d54ca4b58b651861ee7ba220f410e10dfae20229d5febe5671a99501d5ecc15cf4133d2789dfce825df42babfc7b05ce782b41019799afa375909e0618d26eca8c95bad5d167464ff8f8541f331e6c0d77c91b65d76473f9b60988bd27f19a43e4c575d51f92a6723586d555c7e11c261d0edbabf8c36fb89bf2d32001849adb7538be9567c9d0e6c3529ab2cfe5595b8f8d1d28206162fea6f710c1fa0090fe87e960e5ce159fa453b78ff9546ec716018558a89deb26a28b26a04b27a6bc492a71925585415ec6fccafa9a1361f0b788a72da639276e9d78f7fffdf3f7aec1a32d1c488683102db31ad7d126b5f6253f9e698fddd4ed9aa8c86852e95e3cc3b344fe694f7984b4481f0a3ddd58cf7451ef51a235ea0fc9684cea495012600c9ee2d353fe895932b972c23b05911733d0aaf79ba41a4b3e7ce65a177024d8cec021eef3585238baeeeab2ff051471b2222d64292b16e0e9761e590f9e2fb90a0efa340cd1f2b4439bf916ba05725d12d5192dc22bf447167050b562bb014bfce93f66ffbfa3fe0ded225ef7c87536e06fe0efeba1a2578010a6d16a546945e05f15aeb3497517d8c4bed8da1b3eed576d90592501d2e25488bc1e0185246873889e5d74e4b411f1984229aeee051f10738536bd0304f29dafdd79bbc7167ad797c2e82ab188a46e94dcc509c23f9be9fbee0206f41c02762c89a12195ca08d8155a9d2f148a7eb98e2976a054001a6d196ccd44642bbc1052032e57bd6ca46a1ea36086c322e9f1a5e45b65925e1d2f30f37198a0e14e2b33fe462fbfb73ba2e11ed23a045cfe918ec88574cb6e6d2fcc56bad89834ffa41f1014a238460e68c529d891c37f5f04d48c3f01e024bc5f347ddec051f914c98e87d1ba753f\",\"salt\":\"d3d4d5d6d7d8d9da\",\"nonce\":\"dbdcdddedfe0e1e2e3e4e5e6\"}",
		  "tor_proof_signature": null,
		  "tor_sender_address": null,
		  "version": "version2"
		}
	  }
	}
	# "#
	# , false, 5, true, true, true, true, true);
	#
	# // Invalid params
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
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<TxProof, Error>;

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
			  "address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			  "amount": 2000000000,
			  "challenge": "",
			  "fee": 70000,
			  "inputs": [[9,135,120,206,34,67,250,52,229,135,108,140,183,246,219,187,214,165,100,156,21,97,151,58,128,122,104,17,148,28,18,54,60],[9,16,193,117,33,0,115,59,174,73,232,119,40,104,53,170,183,109,88,86,239,129,57,182,198,227,245,23,152,170,70,27,3]],
			  "key": [178,214,169,41,51,242,104,31,198,94,249,72,242,14,219,56,98,255,165,45,172,150,214,162,224,22,108,170,88,110,184,180],
			  "message": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw52000000000",
			  "outputs": [[9,137,213,46,23,205,7,178,37,46,67,23,165,226,249,47,116,234,213,78,155,170,173,75,18,215,102,193,65,246,38,218,211]],
			  "signature": [68, 175, 196, 85, 201, 228, 112, 2, 167, 97, 186, 39, 196, 250, 146, 156, 239, 61, 35, 152, 24, 216, 221, 104, 120, 139, 149, 23, 146, 223, 16, 50, 100, 28, 62, 114, 68, 215, 49, 42, 65, 82, 234, 130, 184, 231, 76, 108, 88, 18, 94, 206, 33, 64, 54, 33, 150, 190, 112, 211, 94, 54, 161, 169],
			  "slate_message": "{\"destination\":{\"public_key\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"domain\":\"\",\"port\":null},\"encrypted_message\":\"2e14c3e33f4c7948811f706469d8081aec26e4fa002456a97ad4e98527ed1618dc7ba693697f8849ebd4576d2d73a55ec81aa0508750b34a804f54531c91f7c94f69dca0679471cb61520515d8b02993f8d1d27b0cb3aebb1bed5fb4e06753d14b40fbcd9d9d22391fdf83fa1a8bd471e15d83e9af83ae3dfd09715e7d7ac353dc4a66486279d6911d9490d9417be9dd6837ac85e603bc50e04b35047c8cc6f27eac6681f514f0dd654cb4d3d0c84eedfd54cbf7d23818fa63fd5736376135ec5c9e5f95c619def8acd9788cf786ea966ab816ea668aed15c5bc063a0a8780aa040c2d2f92e4849f5ff897200092d654f59a169572e886ee6dd60c9937d1b6742b5d893ed395fb794911334ded61339f3e07a85aab598b002d51db412dc16e99dedf57e050697356a907bff460bcf6bca41fb9ad4a29215fb2ce994457a92ac7f8d894036db723be0961d290b675dd11a8bf44596ecf65e7270a5c22271ece96c2ae22e1f65917867750ecb46a3855a6ebae2bb8731304abee14d1ee1595a81625f2350d27b389703114efec85915c7ba0ab7406695c205431bca9764d5378a55cce52ab027627a59509792625bee934453569d04a54a18f8d8f33a596b1e0b65fbf7cd166de7268cf3fda3227fa308665553b69b62b95031d5ca46ab3d536da09e90e21d82eb2921dcabf3ffc46ac68ec8c2b1c5e4119545c5b9ff956553f166e8580775e2e3c5646e880d4c41f43206de7e2d2ccb8145406f404681fadca647f9b5b62d76f5ff4375f7eed7033591f17317fef2198c7c6b708fbf4dd4da34e5b7bdef8309bb49dc568d7a3d5a6b1346661c1b3fe0aefdaa1657197eb5659c35587f3c732e59657eb5f1ae52e8c84972f945aaa32ad33a9a917257d661fb0efcf0d09e7000039d91886e1126b8cdddbcf021ed07ebb6f8b57a546efdc1b09830feed99f192171a299b064123f290088cd3fa187c9c847fb5b9f1bd84c3e2f7741a591bf7a889b9b75efd75749d5fd90865ee149abaabf7784d9dd19277ca45ff89ce6c2fd298158baf706b944b7d411e530d1f93d4ef640d43dbef3dd71192fc200beb191ad158c69729ace15a7e7cd0861033e1027edc7212cd50c5b494193f5e11f38cf522284ef48aa680f006d06afdafd5de6ccef6500b223e28fc891b72e089d09b33e7dda7409389ad3cbed2919e569242cb1714c538cc7a7bfc3a1fecef8888c2cf9eabc33f75da2202801364c8f99eef4a4accaa1b9be7bab31fd58b9db56e622bc21ddbc0bced3e2141ebbc72ef777e0901064c0d27b11cfd121d9703736109944e318ee9dded5a7c51d5c8cf46eb1f1fada2912d0e404c604ba74de974544e25b6435111083d9d3871e06d592527d51c043552d9074a5810d2ac0cc73af4239034eaec08f79190753dc020d6464916ec752d930283ad347615f95d5378362b33e8914cde7d0713939773ee39534c565261074df694e139749366fc10470fc23e326fbd58adbb2b4dc75bd2866969ade7b697627d6a3737458e6bf433cb147fc7dde57f965939253c79b7d6d6b9c52a1caf38a3241c1959fa1f85de60479285fa01a37de5a4dd9f88635cad41b7f346bb36999047a9f6e79936e153c700b3618f2bd881978671bccbc78551eede4dae28d648ed701466c528c56bb4f62cff5312c785addb218ccd7798742cdde2f2958fb7bb6ed8e7cd4a406ad8b933250abead39d6267c38f9fa8254805f262588c367e3f4e289245a9796e43c0c6b9243d37c1c7c150e7adb23c074489cf7c2e556871aacb5cc124184f9494412950b9e530158e574b62f91e5145841f4a0107ec2ea36e23dfaf36f4ce3bd88b73347a1cafc8965f6aa5feadea13159e60c800a9ef79eeb3ac5c35bb1102dc264117702facc37cd257a915c9819b98e548dfc8f0b9eba3565a27ed78afad4da7b7cf34207fcaea7797b84ec738c7a98bc7b94778c35f7f7054c3b2501eb9e01d9e0a6c78b0fed897129cca148eb95f2664c712adaa345486359fa09920e4965752137d5a01a2212a307f1771cb28e83b9dde774755fd6b1342ff193a52988a33dea7bb8134b8c8a312e09c74bd3523ea8ab97f091f8f472af1eaaf8dcced3360b9ce4dfe6c0ba9571e206f402b661c575ceaa1ae53c2100d4914df2fc501f0c1d91393ef34bbafd1c4547ef997f756b9161e9fb3332b29ab5f2ce82a7f077d1ef1da59d0a1f77b38daa150ee9bf3227a72b4bf20913d5f9003b312fabd9be7512033fdc5d43a70a655ad97a53bd56e9850d684ec9160508d397b185f55581f93d60c0c7f52cd08c4ded24707c103573e527c1e79925a53e3747a0263c5e4d81a49dec13f10b497e371f32875fa38d6e33f4fa240a66003db075420f822870f79f6512441a52966f1bdd3af0108c831ad1c02be00bedcbd39b55b0c9af843e64f905d86e4ad88a1e3f489ba18004fd77c08077295e6a00baf566e0bb48a7400778e9f2893cf3f4c052d128cdc94c6378e82603c5e2e0bf2dd00650e719961878ababaaf768c7f9dd54ee5d4697280a28aa3c59b70d89b8c6b1e78e535b6502229e25f014f4ab326a65f9afa8d393cf18f7ddca848b9d6272214139b736e32a130503c3c7a172f7a426174b1fdc1b3438c88fe90fcd1e423474da105cc4f4e373ca5e084d4535ea25f7fe3cf0a57c79a0a042f4df9f036f4c3263dbba92794b8f029d904864870f9ba4e5fd045a1661617d7fc3fe78e0c70f21588722e551fc4fc5fa04d2f05b203dbe626bdd42019e50b75b91ff94fdcbb943b127067a0876bb1c1be9578ca5e55d5b161c6b30e77452ca0096ada434d39534399ecdaa5597e6271268fb0f2b83fea8285f7abd9c3e212c7ca3dc8622beedb1de611a0de94d6066e0f9579dd736164982a3d743ffbe5d7d66c9f43f5c5cfddeaca141be180aa7c3317477c00c4cee654ab9a9f421deec909f6892cfe52577f1f919e30391546b4024e6c0b06cbeb98637eb666262d0df2346d032df2ed4f6928ba9423104f4894d0a22bd44f96b4de9e53fecf78bba347702b71ce2e080b04b3caebb76076aaa7b1d28fdad52fc0f06f736aa0fa334b35a816c8cd1629f7e035dfe9e8738087b408724ff4b2572011ee54ea3ff97dba5531a5a7fc3a3f4e9e4cfca3348dc929ff856036464f6e8aa7a10f0e744a435d501cdaf41a2e0a16f8c396ba5d15b576be1478cc90a8718f1fd435e556e4b4b6f86cfae2aa4536a38f2dd4bd6cdfc2c6d171e9b53e7c41ce190e912402415b69f72f64be33a69a6c163e00012c1c035c3a3083742036047b606d114e8ab844c02c697a97b09283d1fd7540d85f6b09b14a34f985a7f8cd3b70fc3ea38d2faf958f4d3c7698261a37ba1db3387f235bf1a7a39098a36e2c6666b76041a9006af750ed9dd0677e2b9df00d4148bd2f1818c0b125bc934892bbb29c931ab2af37d4f3fdcffab631e965be93f3bada4d9ed30cef1e0feb99739c35fe69a0041db29fb35f324dc363c76d0d2b2a6ba9f219f1d1b7ade03f01804656df86caa936b2895b6e988afc5c7f51b76f7888f1b3c7b00617abb3f2185a5c8a38d273f62e35e9767f7705573ce778d0b6d3184bd8628f0fd906ae9f55859fbb577a29940790c5375aa2a236bbea90e59a7762b06b0d8bf8fcbd989d35481617d70a9b94e5db9daf5e68591cf19252fe0184369cf3b294329aea728f71f6e0f0baaf1521239bfda24396da109a83581c48b005960fe335a7ff9f00544f50b0151cfe586bb954134b254288e0b024a108909a7a7b4c31c442bf43fb42ea643a9b3bc84b5deaf6bab5a0d9a4fd03a566fe917a770c2a3e0fdcb50a913e2682207b28db789f3f56f1a27ad1aea4dfcfeeeb9057721f4855ab80c6e8997530b607dbc11a873c23dc534464a5641e494dc37dc9e6e2b30f053c0419a6d323105de2da807aa41e4829b6e9c897d20eccb80d90419e6ae13ceff6974c986a590c6cd7ab5a19f661f86cf65ea473ef774a4aa72c4875fa8e4e45e7d70a1d062b71c373a33fa65ca95940d88b758e8c1a007d64cf539940d4d2f0785097c72c576611a30af70d0bf3eeaf22a31b5033d767573f0c7e3b3299ab9b7cb944798f9727a47ee7f27d20b52468cf4172ec7fa77c8aa3c415b5e319619f726d58bc8041498664b4435d07b95cf0641541d35a24669802bdb9615fcdf9ac92e6fc808d2917265e64facc8561d01e56739e0b7dadeeae8b1b918ac05f0a3068c24cdbf716ce860ddc40136c8aebdffcab943230fd853fef269477673192939d3ef1e3792a91b3598f4d10fbd37f5a92effa9c44916fd43fad768f22b8c4e6fa93500b88949292ecfe848938478dd19f3d610599033b267a563fb7279080bbc92e092c72867f806bf86edc901b3fc8c203c46fe516f493527eb08c6fc5153811b25aa27b57a32f1fb5933c84d28bdf3a847151051e8eb38f775a51247ff27ac532eaf41a001c0af37f242cb26186846268855975b8e0566ec8aae7545077096792feeed03db23b1c1057870769a250205ceecc737a5a8f2ef014ccc4dae9c8a35a0f81be3c00119f72e61138ef19072d1cd7e9a713fdf4d8f75c96b591cfddc0bb13515d23d5a1c6a45bf6693faaa5870c1e15951f7de5ee07db4de4c22c9ca10660d9c55a8786fc0a5c143e07b2e5cea1ecb20dd8f01779d2d7ea66e4c3601fabe2a818e51dbcd5677ec7b7f898037fb6ecc35a7cb7ec4aeeb4aba462eece7ba995266ddd995d3fd1953ac66bc0f70abc846608153e55ca50ea44d1182ac7ff31f44a9da46321f033e21f623195c66fc288b4f786cedc43efcd6af6aa912de3d4d3a9ce44ae8f35a745b739cd7469be4f9e5cf188ed4bca89b0994d67bc2118bca91686fc0638cae1b1d2e93ed97ec603c9293c015cfc4e51988cbe511ba090111c600355a9f4a39e1e419fa186f733f6531470b2ad38f79d104acdbc930f2a4c2c1cf7736c443fc277387a6f0a75cec35eb7cea5dd930b5789e1912f07faab45341e83cb68f8caca1651c00212221938f461bbfc5b6ee5b2bbab368965352677f31cfd4033941d2f47705a5d8b07b70a3da15fda8d65fc0b8996cf5c998d1c12720a81059b4c57c6d9d48a835896c815413b7f9564e0fce38d07dbeb742d822c0f4011d58796e6b7a752098723b80ac08bdc36db326718b87ba6da3ce050d7b35d826654ce8c52fda834136015d148d73ff78743107511e27459024a5d056efd7210bf0079cfd53836276d41a8f8727d3f9873d387384072fa711689fe9b29b2586c4f61f4de5c8ffd65e9c1a63bf039ea8aeebbf3149e73c1ab2ac5505f5b019af9d9859f3b832a50e8b43109c33904a8b6f85355ba56e8c3faf416148357c94b8893fe3aea15e10b80df0269ce97c729516fa5c29410dd1bf4f96617ae72ccc0c5f4e6b8a9011a46c1521bf1116073006430b49c53589a65eda0508b46683c5c88adb267d04e1864aa54daea4775751c4900ed46e548bd59269cac179fca9ecad75bcdf0b940ce4bc301ee8b4b44c3061798bf936aebfeed19c66babb9f8f15dd1f09ce45985271b0b44b8fdedc41f93189a5c2dacd2f026ed00861500a8266aba5b1e862d9a84be48a4038cdb48be228d194f06b9c07b96ec00ea181ab8884d36dff15187d8cbd39f376e0c261df365f1598ed238df34f8c3b6e9f0991d0d91baad8442870b75f9c8d6e7db21b50c3aafc0c867c8d174b64d5478f29bd78ece430f6e55bf190a1ee847ed7312f3eb625ab569759ec5f43ecfbf163ed0d903de1e35edd088213c8a64ab29c49e2e6277132b4a613f4037e1fbe5607e8139f9c8a16952bfc80f8b345297979bfe28fa01f65b8bb7833cff5e85a9fa7d4befb115a312bab1207caaf9848aeee0fd73e07b5aa2d858a90953fd3dfa8c52f1d64a742161d2d573abc6d2074701a13b5dc301a66b9ca9e28a38b1a4df96b2b2c537565ca383024490e5805fca97d4a66b564a6080d41f6581a3bb2b82f2b2d19d134d47ef62c4dbe3056c922ae75a994ec4d83ea3c14c8319a8b2da3c4c3aec7ba220f410e10dfae20229d5febe5671a99501d5ecc15cf4133d2789dfce825df42babfc7b05ce782b41019799afa375909e0618d26eca8c95bad5d167464ff8f8541f331e6c0d77c91b65d76473f9b60988bd27f19a43e4c575d51f92a6723586d555c7e11c261d0edbabf8c36fb89bf2d32001849adb7538be9567c9d0e6c3529ab2cfe5595b8f8d1d28206162fea6f710c1fa0090fe87e960e5ce159fa453b78ff80569914f07d055f0ceba2ef0de76f34875f6ee1e2b20930387195dc6fec5f0cb4735a7ec84a779f038736fc679f0abf1f3a1f9c6a42a131bd18f132de24d81d126b5f6253f9e698fddd4ed9aa8c86852e95e3cc3b344fe694f7984b4481f0a3ddd58cf7451ef51a235ea0fc9684cea495012600c9ee2d353fe895932b972c23b05911733d0aaf79ba41a4b3e7ce65a177024d8cec021eef3585238baeeeab2ff051471b2222d64292b16e0e9761e590f9e2fb90a0efa340cd1f2b4439bf916ba05725d12d5192dc22bf447167050b562bb014bfce93f66ffbfa3fe0ded225ef7c87536e06fe0efeba1a2578010a6d16a546945e05f15aeb3497517d8c4bed8da1b3eed576d90592501d2e25488bc1e0185246873889e5d74e4b411f1984229aeee051f10738536bd5355f29af8de2eb5921b2ed0c2c3b12cbe8ef73f958990049367c6baa1e80254a24c012626d4f52dc596548546039d221dd176ea8a2b7cf70204493e496ccd44642bbe1000552f56ec6fa06e1cf235d3c17beda3a9e30b339f0f462566f67c99a0e61f7166fc107debe73da6b01dd0695359f49edd9c80729a68617bc706bed99c68ffa44e96a4875c8dbf189023b9dcd77696c2d6\",\"salt\":\"d3d4d5d6d7d8d9da\",\"nonce\":\"dbdcdddedfe0e1e2e3e4e5e6\"}",
			  "tor_proof_signature": null,
			  "tor_sender_address": null,
			  "version": "version2"
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
		  "amount": 2000000000,
		  "kernel": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97",
		  "outputs": [
			"082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9"
		  ],
		  "reciever_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
		  "sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
		  "slate": "{\"version_info\":{\"version\":3,\"orig_version\":3,\"block_header_version\":2},\"num_participants\":2,\"id\":\"0436430c-2b02-624c-2032-570501212b00\",\"tx\":{\"offset\":\"d202964900000000d302964900000000d402964900000000d502964900000000\",\"body\":{\"inputs\":[{\"features\":\"Coinbase\",\"commit\":\"098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c\"},{\"features\":\"Coinbase\",\"commit\":\"0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03\"}],\"outputs\":[{\"features\":\"Plain\",\"commit\":\"082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9\",\"proof\":\"828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9\"},{\"features\":\"Plain\",\"commit\":\"0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3\",\"proof\":\"6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4\"}],\"kernels\":[{\"features\":\"Plain\",\"fee\":\"70000\",\"lock_height\":\"0\",\"excess\":\"09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97\",\"excess_sig\":\"66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4de77bdeeda144e7214d2dc10587b6bbda63a729d913adafe6141d9e8604c31480\"}]}},\"amount\":\"2000000000\",\"fee\":\"70000\",\"height\":\"5\",\"lock_height\":\"0\",\"ttl_cutoff_height\":null,\"coin_type\":\"mwc\",\"network_type\":\"automatedtests\",\"participant_data\":[{\"id\":\"0\",\"public_blind_excess\":\"0321d743d91cdd8b126cadb76b1b7c6b6073385be37625fea2a8a891354672fc41\",\"public_nonce\":\"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f\",\"part_sig\":\"8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2a583da5028b12519136554f860b1c773d0160fd15f6f62687cd7b8d852e1831\",\"message\":null,\"message_sig\":null},{\"id\":\"1\",\"public_blind_excess\":\"0256ebbe7886197266fbd2d039ec1cb8b551655bf58508dcb5c6a0179e640bafcd\",\"public_nonce\":\"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f\",\"part_sig\":\"8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bbd23a1489fb9d4d0bbf66bb600ab9f6326a6c9dbfdb6b8bf8d4f22f97e94fc4e\",\"message\":null,\"message_sig\":null}],\"payment_proof\":{\"sender_address\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"receiver_address\":\"xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2\",\"receiver_signature\":\"3044022044afc455c9e47002a761ba27c4fa929cef3d239818d8dd68788b951792df10320220641c3e7244d7312a4152ea82b8e74c6c58125ece2140362196be70d35e36a1a9\"}}"
		}
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
			  "address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			  "amount": 2000000000,
			  "challenge": "",
			  "fee": 70000,
			  "inputs": [[9, 135, 120, 206, 34, 67, 250, 52, 229, 135, 108, 140, 183, 246, 219, 187, 214, 165, 100, 156, 21, 97, 151, 58, 128, 122, 104, 17, 148, 28, 18, 54, 60], [9, 16, 193, 117, 33, 0, 115, 59, 174, 73, 232, 119, 40, 104, 53, 170, 183, 109, 88, 86, 239, 129, 57, 182, 198, 227, 245, 23, 152, 170, 70, 27, 3]],
			  "key": [178, 214, 169, 41, 51, 242, 104, 31, 198, 94, 249, 72, 242, 14, 219, 56, 98, 255, 165, 45, 172, 150, 214, 162, 224, 22, 108, 170, 88, 110, 184, 180],
			  "message": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0afxmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw52000000000",
			  "outputs": [[9, 137, 213, 46, 23, 205, 7, 178, 37, 46, 67, 23, 165, 226, 249, 47, 116, 234, 213, 78, 155, 170, 173, 75, 18, 215, 102, 193, 65, 246, 38, 218, 211]],
			  "signature": [68, 23, 195, 182, 71, 9, 199, 227, 129, 151, 16, 59, 105, 121, 218, 206, 228, 228, 28, 62, 228, 77, 137, 234, 117, 25, 31, 85, 62, 43, 188, 194, 68, 197, 45, 241, 0, 255, 253, 8, 12, 149, 87, 92, 146, 50, 155, 109, 219, 208, 199, 117, 69, 227, 30, 228, 57, 17, 38, 85, 145, 143, 224, 238],
			  "slate_message": "{\"destination\":{\"public_key\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"domain\":\"\",\"port\":null},\"encrypted_message\":\"2e14c3e33f4c7948811f706469d8081aec26e4fa002456a97ad4e98527ed1618dc7ba693697f8849ebd4576d2d73a55ec81aa0508750b34a804f54531c91f7c94f69dca0679471cb61520515d8b02993f8d1d27b0cb3aebb1bed5fb4e06753d14b40fbcd9d9d22391fdf83fa1a8bd471e15d83e9af83ae3dfd09715e7d7ac353dc4a66486279d7911d9490d9417be9dd6837ac85e603bc50e01c31072d8d96f326fa33d2f647a6da314de3db80c240bca25dcaf5866d1af936f85536343c62e854cd0c93974adcfdff8e298cf38de9c462e940e333d9bb1197bc063a0a8780aa040c2d2f92e4849f5ff897200092d654f59a169572e886ee6dd60c9937d1b6742b5d893ed395fb794911334ded61339f3e07a85aab598b002d51db412dc16e99dedf57e050697356a907bff460bcf6bca41fb9ad4a29215fb2ce994457a92ac7f8d894036db723be0961d290b675dd11a8bf44596ecf65e7270a5c22271ece96c2ae22e1f65917867750ecb46a3855a6ebae2bb8731304abee14d1ee1595a81625f2350d27b389703114efec85915c7ba0ab7406695c205431bca9764d5378a55cce52ab027627a59509792625bee934453569d04a54a18f8d8f33a596b1e0b65fbf7cd166de7268cf3fda3227fa308665553b69b62b95031d5ca46ab3d536da09e90e21d82eb2921dcabf3ffc46ac68ec8c2b1c5e4119545c5b9ff956553f166e8580775e2e3c5646e880d4c41f43206de7e2d2ccb8145406f404681fadca647f9b5b62d76f5ff4375f7eed7033591f17317fef2198c7c6b708fbf4dd4da34e5b7bdef8309bb49dc568d7a3d5a6b1346661c1b3fe0aefdaa1657197eb5659c35587f3c732e59657eb5f1ae52e8c84972f945aaa32ad33a9a917257d661fb0efcf0d09e7000039d91886e1126b8cdddbcf021ed07ebb6f8b57a546efdc1b09830feed99f192171a299b064123f290088cd3fa187c9c847fb5b9f1bd84c3e2f7741a591bf7a889b9b75efd75749d5fd90865ee149abaabf7784d9dd19277ca45ff89ce6c2fd298158baf706b944b7d411e530d1f93d4ef640d43dbef3dd71192fc200beb191ad158c69729ace15a7e7cd0861033e1027edc7212cd50c5b494193f5e11f38cf522284ef48aa680f006d06afdafd5de6ccef6500b223e28fc891b72e089d09b33e7dda7409389ad3cbed2919e569242cb1714c538cc7a7bfc3a1fecef8888c2cf9eabc33f75da2202801364c8f99eef4a4accaa1b9be7bab31fd58b9db56e622bc21ddbc0bced3e2141ebbc72ef777e0901064c0d27b11cfd121d9703736109944e318ee9dded5a7c51d5c8cf46eb1f1fada2912d0e404c604ba74de974544e25b6435111083d9d3871e06d592527d51c043552d9074a5810d2ac0cc73af4239034eaec08f79190753dc020d6464916ec752d930283ad347615f95d5378362b33e8914cde7d0713939773ee39534c565261074df694e139749366fc10470fc23e326fbd58adbb2b4dc75bd2866969ade7b697627d6a3737458e6bf433cb147fc7dde57f965939253c79b7d6d6b9c52a1caf38a3241c1959fa1f85de60479285fa01a37de5a4dd9f88635cad41b7f346bb36999047a9f6e79936e153c700b3618f2bd881978671bccbc78551eede4dae28d648ed701466c528c56bb4f62cff5312c785addb218ccd7798742cdde2f2958fb7bb6ed8e7cd4a406ad8b933250abead39d6267c38f9fa8254805f262588c367e3f4e289245a9796e43c0c6b9243d37c1c7c150e7adb23c074489cf7c2e556871aacb5cc124184f9494412950b9e530158e574b62f91e5145841f4a0107ec2ea36e23dfaf36f4ce3bd88b73347a1cafc8965f6aa5feadea13159e60c800a9ef79eeb3ac5c35bb1102dc264117702facc37cd257a915c9819b98e548dfc8f0b9eba3565a27ed78afad4da7b7cf34207fcaea7797b84ec738c7a98bc7b94778c35f7f7054c3b2501eb9e01d9e0a6c78b0fed897129cca148eb95f2664c712adaa345486359fa09920e4965752137d5a01a2212a307f1771cb28e83b9dde774755fd6b1342ff193a52988a33dea7bb8134b8c8a312e09c74bd3523ea8ab97f091f8f472af1eaaf8dcced3360b9ce4dfe6c0ba9571e206f402b661c575ceaa1ae53c2100d4914df2fc501f0c1d91393ef34bbafd1c4547ef997f756b9161e9fb3332b29ab5f2ce82a7f077d1ef1da59d0a1f77b38daa150ee9bf3227a72b4bf20913d5f9003b312fabd9be7512033fdc5d43a70a655ad97a53bd56e9850d684ec9160508d397b185f55581f93d60c0c7f52cd08c4ded24707c103573e527c1e79925a53e3747a0263c5e4d81a49dec13f10b497e371f32875fa38d6e33f4fa240a66003db075420f822870f79f6512441a52966f1bdd3af0108c831ad1c02be00bedcbd39b55b0c9af843e64f905d86e4ad88a1e3f489ba18004fd77c08077295e6a00baf566e0bb48a7400778e9f2893cf3f4c052d128cdc94c6378e82603c5e2e0bf2dd00650e719961878ababaaf768c7f9dd54ee5d4697280a28aa3c59b70d89b8c6b1e78e535b6502229e25f014f4ab326a65f9afa8d393cf18f7ddca848b9d6272214139b736e32a130503c3c7a172f7a426174b1fdc1b3438c88fe90fcd1e423474da105cc4f4e373ca5e084d4535ea25f7fe3cf0a57c79a0a042f4df9f036f4c3263dbba92794b8f029d904864870f9ba4e5fd045a1661617d7fc3fe78e0c70f21588722e551fc4fc5fa04d2f05b203dbe626bdd42019e50b75b91ff94fdcbb943b127067a0876bb1c1be9578ca5e55d5b161c6b30e77452ca0096ada434d39534399ecdaa5597e6271268fb0f2b83fea8285f7abd9c3e212c7ca3dc8622beedb1de611a0de94d6066e0f9579dd736164982a3d743ffbe5d7d66c9f43f5c5cfddeaca141be180aa7c3317477c00c4cee654ab9a9f421deec909f6892cfe52577f1f919e30391546b4024e6c0b06cbeb98637eb666262d0df2346d032df2ed4f6928ba9423104f4894d0a22bd44f96b4de9e53fecf78bba347702b71ce2e080b04b3caebb76076aaa7b1d28fdad52fc0f06f736aa0fa334b35a816c8cd1629f7e035dfe9e8738087b408724ff4b2572011ee54ea3ff97dba5531a5a7fc3a3f4e9e4cfca3348dc929ff856036464f6e8aa7a10f0e744a435d501cdaf41a2e0a16f8c396ba5d15b576be1478cc90a8718f1fd435e556e4b4b6f86cfae2aa4536a38f2dd4bd6cdfc2c6d171e9b53e7c41ce190e912402415b69f72f64be33a69a6c163e00012c1c035c3a3083742036047b606d114e8ab844c02c697a97b09283d1fd7540d85f6b09b14a34f985a7f8cd3b70fc3ea38d2faf958f4d3c7698261a37ba1db3387f235bf1a7a39098a36e2c6666b76041a9006af750ed9dd0677e2b9df00d4148bd2f1818c0b125bc934892bbb29c931ab2af37d4f3fdcffab631e965be93f3bada4d9ed30cef1e0feb99739c35fe69a0041db29fb35f324dc363c76d0d2b2a6ba9f219f1d1b7ade03f01804656df86caa936b2895b6e988afc5c7f51b76f7888f1b3c7b00617abb3f2185a5c8a38d273f62e35e9767f7705573ce778d0b6d3184bd8628f0fd906ae9f55859fbb577a29940790c5375aa2a236bbea90e59a7762b06b0d8bf8fcbd989d35481617d70a9b94e5db9daf5e68591cf19252fe0184369cf3b294329aea728f71f6e0f0baaf1521239bfda24396da109a83581c48b005960fe335a7ff9f00544f50b0151cfe586bb954134b254288e0b024a108909a7a7b4c31c442bf43fb42ea643a9b3bc84b5deaf6bab5a0d9a4fd03a566fe917a770c2a3e0fdcb50a913e2682207b28db789f3f56f1a27ad1aea4dfcfeeeb9057721f4855ab80c6e8997530b607dbc11a873c23dc534464a5641e494dc37dc9e6e2b30f053c0419a6d323105de2da807aa41e4829b6e9c897d20eccb80d90419e6ae13ceff6974c986a590c6cd7ab5a19f661f86cf65ea473ef774a4aa72c4875fa8e4e45e7d70a1d062b71c373a33fa65ca95940d88b758e8c1a007d64cf539940d4d2f0785097c72c576611a30af70d0bf3eeaf22a31b5033d767573f0c7e3b3299ab9b7cb944798f9727a47ee7f27d20b52468cf4172ec7fa77c8aa3c415b5e319619f726d58bc8041498664b4435d07b95cf0641541d35a24669802bdb9615fcdf9ac92e6fc808d2917265e64facc8561d01e56739e0b7dadeeae8b1b918ac05f0a3068c24cdbf716ce860ddc40136c8aebdffcab943230fd853fef269477673192939d3ef1e3792a91b3598f4d10fbd37f5a92effa9c44916fd43fad768f22b8c4e6fa93500b88949292ecfe848938478dd19f3d610599033b267a563fb7279080bbc92e092c72867f806bf86edc901b3fc8c203c46fe516f493527eb08c6fc5153811b25aa27b57a32f1fb5933c84d28bdf3a847151051e8eb38f775a51247ff27ac532eaf41a001c0af37f242cb26186846268855975b8e0566ec8aae7545077096792feeed03db23b1c1057870769a250205ceecc737a5a8f2ef014ccc4dae9c8a35a0f81be3c00119f72e61138ef19072d1cd7e9a713fdf4d8f75c96b591cfddc0bb13515d23d5a1c6a45bf6693faaa5870c1e15951f7de5ee07db4de4c22c9ca10660d9c55a8786fc0a5c143e07b2e5cea1ecb20dd8f01779d2d7ea66e4c3601fabe2a818e51dbcd5677ec7b7f898037fb6ecc35a7cb7ec4aeeb4aba462eece7ba995266ddd995d3fd1953ac66bc0f70abc846608153e55ca50ea44d1182ac7ff31f44a9da46321f033e21f623195c66fc288b4f786cedc43efcd6af6aa912de3d4d3a9ce44ae8f35a745b739cd7469be4f9e5cf188ed4bca89b09e4e61b9221fb1af4182f9046a9fbdb0d3bd6fd62c920dce2e625506f51e579ed8ec5149a5924449615600fcf5f6cb4e4497f7d1a162fe074427e2aa38a2c5414acdbc930f2a4c2c1cf7736c443fc277387a6f0a75cec35eb7cea5dd930b5789e1912f07faab45341e83cb68f8caca1651c00212221938f461bbfc5b6ee5b2bbab368965352677f31cfd4033941d2f4774585cda51e50b6af0588c8830ad088192935bce8d4f407e0b815fc81d07968e8689805d97c3154d387ccc32e5a2b3dd008bed2924d42100431182d092e5bdaf52098723b80ac08bdc36db326718b87ba6da3ce050d7b35d826654ce8c52fda834136015d148d73ff78743107511e27459024a5d056efd7210bf0079cfd53836276d41a8f8727d3f9873d387384072fa711689fe9b29b2586c4f61f4de5c8ffd65e9c1a63bf039ea8aeebbf3149e73c1ab2ac5505f5b019af9d9859f3b832a50e8b43109c33904a8b6f85355ba56e8c3faf416148357c94b8893fe3aea15e10b80df0269ce97c729516fa5c29410dd1bf4f96617ae72ccc0c5f4e6b8a9011a46c1521bf1116073006430b5cb5a05ce32bbf05d831c6d3b558fa5e23387164462fc0081be162477481205be12e24be608779dad16cac89fcd8208c6a3e411c614c650bd8d4a41c5594dc9ed936aebfeed19c66babb9f8f15dd1f09ce45985271b0b44b8fdedc41f93189a5c2dacd2f026ed00861500a8266aba5b1e862d9a84be48a4038cdb48be228d194f06b9c07b96ec00ea181ab8884d36dff15187d8cbd39f376e0c261df365f1598ed238df34f8c3b6e9f0991d0d91baad8442870b75f9c8d6e7db21b50c3aafc0c867c8d174b64d5478f29bd78ece430f6e55bf190a1ee847ed7312f3eb625ab569759ec5a43fc1e84439818c55821833e8ddda793e8167a82bc3c92e3723412e1a603f4360e4f2b2347e8039fd9ff53c02ba9a06da340ec191c1a826fe55a65c87b2863cff5e85a9fa7d4befb115a312bab1207caaf9848aeee0fd73e07b5aa2d858a90953fd3dfa8c52f1d64a742161d2d573abc6d2074701a13b5dc301a66b9ca9e28a38b1a4df96b2b29532500ff3de50489be58457cd90d2a03b05183481821f3adda1b87a82fbe587c9124a47bc3492d9b8083f9f2de2019a4ecb893babc743d54ca4b58b651861ee7ba220f410e10dfae20229d5febe5671a99501d5ecc15cf4133d2789dfce825df42babfc7b05ce782b41019799afa375909e0618d26eca8c95bad5d167464ff8f8541f331e6c0d77c91b65d76473f9b60988bd27f19a43e4c575d51f92a6723586d555c7e11c261d0edbabf8c36fb89bf2d32001849adb7538be9567c9d0e6c3529ab2cfe5595b8f8d1d28206162fea6f710c1fa0090fe87e960e5ce159fa453b78ff9546ec716018558a89deb26a28b26a04b27a6bc492a71925585415ec6fccafa9a1361f0b788a72da639276e9d78f7fffdf3f7aec1a32d1c488683102db31ad7d126b5f6253f9e698fddd4ed9aa8c86852e95e3cc3b344fe694f7984b4481f0a3ddd58cf7451ef51a235ea0fc9684cea495012600c9ee2d353fe895932b972c23b05911733d0aaf79ba41a4b3e7ce65a177024d8cec021eef3585238baeeeab2ff051471b2222d64292b16e0e9761e590f9e2fb90a0efa340cd1f2b4439bf916ba05725d12d5192dc22bf447167050b562bb014bfce93f66ffbfa3fe0ded225ef7c87536e06fe0efeba1a2578010a6d16a546945e05f15aeb3497517d8c4bed8da1b3eed576d90592501d2e25488bc1e0185246873889e5d74e4b411f1984229aeee051f10738536bd0304f29dafdd79bbc7167ad797c2e82ab188a46e94dcc509c23f9be9fbee0206f41c02762c89a12195ca08d8155a9d2f148a7eb98e2976a054001a6d196ccd44642bbc1052032e57bd6ca46a1ea36086c322e9f1a5e45b65925e1d2f30f37198a0e14e2b33fe462fbfb73ba2e11ed23a045cfe918ec88574cb6e6d2fcc56bad89834ffa41f1014a238460e68c529d891c37f5f04d48c3f01e024bc5f347ddec051f914c98e87d1ba753f\",\"salt\":\"d3d4d5d6d7d8d9da\",\"nonce\":\"dbdcdddedfe0e1e2e3e4e5e6\"}",
			  "tor_proof_signature": null,
			  "tor_sender_address": null,
			  "version": "version2"
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
		  "amount": 2000000000,
		  "kernel": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
		  "outputs": [
			"082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9",
			"0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3"
		  ],
		  "reciever_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
		  "sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
		  "slate": "{\"version_info\":{\"version\":3,\"orig_version\":3,\"block_header_version\":2},\"num_participants\":2,\"id\":\"0436430c-2b02-624c-2032-570501212b01\",\"tx\":{\"offset\":\"363c8f5afec3cf7ded8b38ef912de23ea601da01cc6ac25c3d0625f1af9ecf4b\",\"body\":{\"inputs\":[{\"features\":\"Coinbase\",\"commit\":\"098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c\"},{\"features\":\"Coinbase\",\"commit\":\"0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03\"}],\"outputs\":[{\"features\":\"Plain\",\"commit\":\"082967b3fe580cd110355010ef45450314fb067720db01b0e6873bb083d76708c9\",\"proof\":\"828bb24121aa0332c872062a42a8333c3ef81f8ae37d24053d953217368b3cada90410a50509a0b9fcbb5aded41397fc00ca1ff5acdac20d48afb0a3281d21e7026d32fdc6c5157461a35f98a809ffa09187c1e170ea24652ad213b7e4c9878654ac3dd9a8915eaf742db53182fcb42d2d341fbdfe8bd31bd001f4ff2c1ca9f9b1531da29137214f211edb7a5eb8f494cb8945f8527dd25bf7e698515043db4249540720008a708db5342230d05b069c094688ccb7c07d4a4a2293ea76cf999c555dc0ddc757891c360db1901bbb4dc20cae997f875f8de482d8160e05d60f9b0135e0fc313d8f953db78f1ea252449dd81cfa22dd895512ed39d566f0924542b543d25fc9fc7a819d228f3b0ee5e381f088f54893e86437dafc49dd923b3e6dff956ca843f951910379531fac9bb5fd01a182dd32a4c597f92da3c01af37cb9b0ec984500884438e74e54d7e76fa1ae7241d5050b13376310b24761634a6f6eb7cf000082f50ed7c1899d7918023d4f877586f964932a7af72e7a4984ddecfdd1921a2e1b80b00d6bd2e64a3f4cb6915a27a8d17a69d163cf45220a13fcddd15dc2bb91ae4f1b6a67224ab3b23e8d7d785df178ec78a84cf42cea086426f563822c8a4271a0b89bb21f84b643dbf1de21b6395039d673a376492767199fa36ccd9a13628ce61695424091acc16059450d59bc59fa7879e7306f5727217211b0264a6a560f886d520e41406ef45b1668805b88d246c5b2ca5a1762042c85be34fcd420ac3843f32236d079b4bd57d6b8d8013d9d18f8efb55e8e443cd9e1af9b144e7a56c8c6be0138af3b4a6c99bee9109bed2bce2e5145e736b125a2ec19aaf3fff713f6897fdd4158ce2ab04706b062ca2847bf70259c0fc4b0d390dc7fdaf0362047f775a912bd22da9d40f04d9790bcd5ece4b36b74c6c340b48c2926b916e8a9\"},{\"features\":\"Plain\",\"commit\":\"0989d52e17cd07b2252e4317a5e2f92f74ead54e9baaad4b12d766c141f626dad3\",\"proof\":\"6f9368ccc85c67cbe63c343816667d60dd756619f6c7a531c6086183c74be557974e535d82f3a59bacc2bba17393266bee8e2853d2b6522b1320900e55ec4eaa06d9c3da0242fbf3269af9b7988e3004dc6dfefcede0405d7c8fd43e1b7312d2c36a71bcfe3ce478b1f364d7cbb077cb990115e0d24b3873c3d7c3eb7111ce2a37b595edd2b44990dc96c4a56feb1bb9f598335d95e35d3025ca8282e340f3795a7a07b90329b5f5563fa48fe666827c140f5f8031e8d251e5ab0dff1c28437ed4013a39c7c61e34fbb34830e48ff2362443c2350bbe2fdc75f17f67a0285dd886041832957c0e62926bed15aeb2736387b3f89a15a624133eff824f5ad6c6a6680daabfb796760cada8bf9f91d1dbacfc2404c96cddd01860eb2572d64955d476ed976ae56c34fb2ada8f0e39086c772e951c0008d8c2e354681e69184106bc2d48680767b8b0ffb8ff3fe9e1b12f359a313678cc87413cc04b389eecd8ce52ed0702c48b39cde55a883298eed487ea7d747d7f638ea65fd31f4b38dd611d4e60d5e790425f8bc09f3b26b845a37c4525d166a7af7aa0f32590dc843362a783f937033f0be33337367328ce7b9ad7a06ac1c752019d761c8e34e3668cfa75dfdb0a4508eb594ac022f15a40a8722d6c7a6ccd13b6d1f37fe8a173b27cc4918c88b58a8604004624ce32100ae5784fd67d68dce8e42bf9826d1d1f7335b5e972536973c358ba12c80efc5798a6276d813a47e9f3d1e4a84fbf4acc1f26d916babd632077cd1df97e23fbf03b82621f8a0fc461e7b2df4299f987bb87fcfab202c80b79d3c0f572d3cd2bc9afde75e609522fe10bb7a33d2d9b6402a425becfc336a99b74c7c0f3a34f894a76f6ac246e72e74ff9acd06c6ab703d4f183b49143e7748652493396db021a3b3d7926196ec3fa55006697f0a025471eeb4e97fc5f854fb4\"}],\"kernels\":[{\"features\":\"Plain\",\"fee\":\"70000\",\"lock_height\":\"0\",\"excess\":\"09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af\",\"excess_sig\":\"66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da56327d306b10f190853cbb9978e3246d0b232d52082d85f6d790359344d5728\"}]}},\"amount\":\"2000000000\",\"fee\":\"70000\",\"height\":\"5\",\"lock_height\":\"0\",\"ttl_cutoff_height\":null,\"coin_type\":\"mwc\",\"network_type\":\"automatedtests\",\"participant_data\":[{\"id\":\"0\",\"public_blind_excess\":\"02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec\",\"public_nonce\":\"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f\",\"part_sig\":\"8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2146d6fdeddd778ca38567318cd043670358adfe111b3f7d1fc8adb261f56464\",\"message\":null,\"message_sig\":null},{\"id\":\"1\",\"public_blind_excess\":\"02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f\",\"public_nonce\":\"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f\",\"part_sig\":\"8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc55e87a5a5316a4ca06dac37f29a9d99cb5a85d60e6799e24db155a6d257f2c3\",\"message\":null,\"message_sig\":null}],\"payment_proof\":{\"sender_address\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"receiver_address\":\"xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2\",\"receiver_signature\":\"304402204417c3b64709c7e38197103b6979dacee4e41c3ee44d89ea75191f553e2bbcc2022044c52df100fffd080c95575c92329b6ddbd0c77545e31ee439112655918fe0ee\"},\"compact_slate\":true}"
		}
	  }
	}
	# "#
	# , false, 5, true, true, true, true, true);
	#
	# // Invalid proof slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"proof": {
			  "address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			  "amount": 3000000000,
			  "challenge": "",
			  "fee": 70000,
			  "inputs": [[9, 135, 120, 206, 34, 67, 250, 52, 229, 135, 108, 140, 183, 246, 219, 187, 214, 165, 100, 156, 21, 97, 151, 58, 128, 122, 104, 17, 148, 28, 18, 54, 60], [9, 16, 193, 117, 33, 0, 115, 59, 174, 73, 232, 119, 40, 104, 53, 170, 183, 109, 88, 86, 239, 129, 57, 182, 198, 227, 245, 23, 152, 170, 70, 27, 3]],
			  "key": [178, 214, 169, 41, 51, 242, 104, 31, 198, 94, 249, 72, 242, 14, 219, 56, 98, 255, 165, 45, 172, 150, 214, 162, 224, 22, 108, 170, 88, 110, 184, 180],
			  "message": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0afxmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw52000000000",
			  "outputs": [[9, 137, 213, 46, 23, 205, 7, 178, 37, 46, 67, 23, 165, 226, 249, 47, 116, 234, 213, 78, 155, 170, 173, 75, 18, 215, 102, 193, 65, 246, 38, 218, 211]],
			  "signature": [68, 23, 195, 182, 71, 9, 199, 227, 129, 151, 16, 59, 105, 121, 218, 206, 228, 228, 28, 62, 228, 77, 137, 234, 117, 25, 31, 85, 62, 43, 188, 194, 68, 197, 45, 241, 0, 255, 253, 8, 12, 149, 87, 92, 146, 50, 155, 109, 219, 208, 199, 117, 69, 227, 30, 228, 57, 17, 38, 85, 145, 143, 224, 238],
			  "slate_message": "{\"destination\":{\"public_key\":\"xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5\",\"domain\":\"\",\"port\":null},\"encrypted_message\":\"2e14c3e33f4c7948811f706469d8081aec26e4fa002456a97ad4e98527ed1618dc7ba693697f8849ebd4576d2d73a55ec81aa0508750b34a804f54531c91f7c94f69dca0679471cb61520515d8b02993f8d1d27b0cb3aebb1bed5fb4e06753d14b40fbcd9d9d22391fdf83fa1a8bd471e15d83e9af83ae3dfd09715e7d7ac353dc4a66486279d7911d9490d9417be9dd6837ac85e603bc50e01c31072d8d96f326fa33d2f647a6da314de3db80c240bca25dcaf5866d1af936f85536343c62e854cd0c93974adcfdff8e298cf38de9c462e940e333d9bb1197bc063a0a8780aa040c2d2f92e4849f5ff897200092d654f59a169572e886ee6dd60c9937d1b6742b5d893ed395fb794911334ded61339f3e07a85aab598b002d51db412dc16e99dedf57e050697356a907bff460bcf6bca41fb9ad4a29215fb2ce994457a92ac7f8d894036db723be0961d290b675dd11a8bf44596ecf65e7270a5c22271ece96c2ae22e1f65917867750ecb46a3855a6ebae2bb8731304abee14d1ee1595a81625f2350d27b389703114efec85915c7ba0ab7406695c205431bca9764d5378a55cce52ab027627a59509792625bee934453569d04a54a18f8d8f33a596b1e0b65fbf7cd166de7268cf3fda3227fa308665553b69b62b95031d5ca46ab3d536da09e90e21d82eb2921dcabf3ffc46ac68ec8c2b1c5e4119545c5b9ff956553f166e8580775e2e3c5646e880d4c41f43206de7e2d2ccb8145406f404681fadca647f9b5b62d76f5ff4375f7eed7033591f17317fef2198c7c6b708fbf4dd4da34e5b7bdef8309bb49dc568d7a3d5a6b1346661c1b3fe0aefdaa1657197eb5659c35587f3c732e59657eb5f1ae52e8c84972f945aaa32ad33a9a917257d661fb0efcf0d09e7000039d91886e1126b8cdddbcf021ed07ebb6f8b57a546efdc1b09830feed99f192171a299b064123f290088cd3fa187c9c847fb5b9f1bd84c3e2f7741a591bf7a889b9b75efd75749d5fd90865ee149abaabf7784d9dd19277ca45ff89ce6c2fd298158baf706b944b7d411e530d1f93d4ef640d43dbef3dd71192fc200beb191ad158c69729ace15a7e7cd0861033e1027edc7212cd50c5b494193f5e11f38cf522284ef48aa680f006d06afdafd5de6ccef6500b223e28fc891b72e089d09b33e7dda7409389ad3cbed2919e569242cb1714c538cc7a7bfc3a1fecef8888c2cf9eabc33f75da2202801364c8f99eef4a4accaa1b9be7bab31fd58b9db56e622bc21ddbc0bced3e2141ebbc72ef777e0901064c0d27b11cfd121d9703736109944e318ee9dded5a7c51d5c8cf46eb1f1fada2912d0e404c604ba74de974544e25b6435111083d9d3871e06d592527d51c043552d9074a5810d2ac0cc73af4239034eaec08f79190753dc020d6464916ec752d930283ad347615f95d5378362b33e8914cde7d0713939773ee39534c565261074df694e139749366fc10470fc23e326fbd58adbb2b4dc75bd2866969ade7b697627d6a3737458e6bf433cb147fc7dde57f965939253c79b7d6d6b9c52a1caf38a3241c1959fa1f85de60479285fa01a37de5a4dd9f88635cad41b7f346bb36999047a9f6e79936e153c700b3618f2bd881978671bccbc78551eede4dae28d648ed701466c528c56bb4f62cff5312c785addb218ccd7798742cdde2f2958fb7bb6ed8e7cd4a406ad8b933250abead39d6267c38f9fa8254805f262588c367e3f4e289245a9796e43c0c6b9243d37c1c7c150e7adb23c074489cf7c2e556871aacb5cc124184f9494412950b9e530158e574b62f91e5145841f4a0107ec2ea36e23dfaf36f4ce3bd88b73347a1cafc8965f6aa5feadea13159e60c800a9ef79eeb3ac5c35bb1102dc264117702facc37cd257a915c9819b98e548dfc8f0b9eba3565a27ed78afad4da7b7cf34207fcaea7797b84ec738c7a98bc7b94778c35f7f7054c3b2501eb9e01d9e0a6c78b0fed897129cca148eb95f2664c712adaa345486359fa09920e4965752137d5a01a2212a307f1771cb28e83b9dde774755fd6b1342ff193a52988a33dea7bb8134b8c8a312e09c74bd3523ea8ab97f091f8f472af1eaaf8dcced3360b9ce4dfe6c0ba9571e206f402b661c575ceaa1ae53c2100d4914df2fc501f0c1d91393ef34bbafd1c4547ef997f756b9161e9fb3332b29ab5f2ce82a7f077d1ef1da59d0a1f77b38daa150ee9bf3227a72b4bf20913d5f9003b312fabd9be7512033fdc5d43a70a655ad97a53bd56e9850d684ec9160508d397b185f55581f93d60c0c7f52cd08c4ded24707c103573e527c1e79925a53e3747a0263c5e4d81a49dec13f10b497e371f32875fa38d6e33f4fa240a66003db075420f822870f79f6512441a52966f1bdd3af0108c831ad1c02be00bedcbd39b55b0c9af843e64f905d86e4ad88a1e3f489ba18004fd77c08077295e6a00baf566e0bb48a7400778e9f2893cf3f4c052d128cdc94c6378e82603c5e2e0bf2dd00650e719961878ababaaf768c7f9dd54ee5d4697280a28aa3c59b70d89b8c6b1e78e535b6502229e25f014f4ab326a65f9afa8d393cf18f7ddca848b9d6272214139b736e32a130503c3c7a172f7a426174b1fdc1b3438c88fe90fcd1e423474da105cc4f4e373ca5e084d4535ea25f7fe3cf0a57c79a0a042f4df9f036f4c3263dbba92794b8f029d904864870f9ba4e5fd045a1661617d7fc3fe78e0c70f21588722e551fc4fc5fa04d2f05b203dbe626bdd42019e50b75b91ff94fdcbb943b127067a0876bb1c1be9578ca5e55d5b161c6b30e77452ca0096ada434d39534399ecdaa5597e6271268fb0f2b83fea8285f7abd9c3e212c7ca3dc8622beedb1de611a0de94d6066e0f9579dd736164982a3d743ffbe5d7d66c9f43f5c5cfddeaca141be180aa7c3317477c00c4cee654ab9a9f421deec909f6892cfe52577f1f919e30391546b4024e6c0b06cbeb98637eb666262d0df2346d032df2ed4f6928ba9423104f4894d0a22bd44f96b4de9e53fecf78bba347702b71ce2e080b04b3caebb76076aaa7b1d28fdad52fc0f06f736aa0fa334b35a816c8cd1629f7e035dfe9e8738087b408724ff4b2572011ee54ea3ff97dba5531a5a7fc3a3f4e9e4cfca3348dc929ff856036464f6e8aa7a10f0e744a435d501cdaf41a2e0a16f8c396ba5d15b576be1478cc90a8718f1fd435e556e4b4b6f86cfae2aa4536a38f2dd4bd6cdfc2c6d171e9b53e7c41ce190e912402415b69f72f64be33a69a6c163e00012c1c035c3a3083742036047b606d114e8ab844c02c697a97b09283d1fd7540d85f6b09b14a34f985a7f8cd3b70fc3ea38d2faf958f4d3c7698261a37ba1db3387f235bf1a7a39098a36e2c6666b76041a9006af750ed9dd0677e2b9df00d4148bd2f1818c0b125bc934892bbb29c931ab2af37d4f3fdcffab631e965be93f3bada4d9ed30cef1e0feb99739c35fe69a0041db29fb35f324dc363c76d0d2b2a6ba9f219f1d1b7ade03f01804656df86caa936b2895b6e988afc5c7f51b76f7888f1b3c7b00617abb3f2185a5c8a38d273f62e35e9767f7705573ce778d0b6d3184bd8628f0fd906ae9f55859fbb577a29940790c5375aa2a236bbea90e59a7762b06b0d8bf8fcbd989d35481617d70a9b94e5db9daf5e68591cf19252fe0184369cf3b294329aea728f71f6e0f0baaf1521239bfda24396da109a83581c48b005960fe335a7ff9f00544f50b0151cfe586bb954134b254288e0b024a108909a7a7b4c31c442bf43fb42ea643a9b3bc84b5deaf6bab5a0d9a4fd03a566fe917a770c2a3e0fdcb50a913e2682207b28db789f3f56f1a27ad1aea4dfcfeeeb9057721f4855ab80c6e8997530b607dbc11a873c23dc534464a5641e494dc37dc9e6e2b30f053c0419a6d323105de2da807aa41e4829b6e9c897d20eccb80d90419e6ae13ceff6974c986a590c6cd7ab5a19f661f86cf65ea473ef774a4aa72c4875fa8e4e45e7d70a1d062b71c373a33fa65ca95940d88b758e8c1a007d64cf539940d4d2f0785097c72c576611a30af70d0bf3eeaf22a31b5033d767573f0c7e3b3299ab9b7cb944798f9727a47ee7f27d20b52468cf4172ec7fa77c8aa3c415b5e319619f726d58bc8041498664b4435d07b95cf0641541d35a24669802bdb9615fcdf9ac92e6fc808d2917265e64facc8561d01e56739e0b7dadeeae8b1b918ac05f0a3068c24cdbf716ce860ddc40136c8aebdffcab943230fd853fef269477673192939d3ef1e3792a91b3598f4d10fbd37f5a92effa9c44916fd43fad768f22b8c4e6fa93500b88949292ecfe848938478dd19f3d610599033b267a563fb7279080bbc92e092c72867f806bf86edc901b3fc8c203c46fe516f493527eb08c6fc5153811b25aa27b57a32f1fb5933c84d28bdf3a847151051e8eb38f775a51247ff27ac532eaf41a001c0af37f242cb26186846268855975b8e0566ec8aae7545077096792feeed03db23b1c1057870769a250205ceecc737a5a8f2ef014ccc4dae9c8a35a0f81be3c00119f72e61138ef19072d1cd7e9a713fdf4d8f75c96b591cfddc0bb13515d23d5a1c6a45bf6693faaa5870c1e15951f7de5ee07db4de4c22c9ca10660d9c55a8786fc0a5c143e07b2e5cea1ecb20dd8f01779d2d7ea66e4c3601fabe2a818e51dbcd5677ec7b7f898037fb6ecc35a7cb7ec4aeeb4aba462eece7ba995266ddd995d3fd1953ac66bc0f70abc846608153e55ca50ea44d1182ac7ff31f44a9da46321f033e21f623195c66fc288b4f786cedc43efcd6af6aa912de3d4d3a9ce44ae8f35a745b739cd7469be4f9e5cf188ed4bca89b09e4e61b9221fb1af4182f9046a9fbdb0d3bd6fd62c920dce2e625506f51e579ed8ec5149a5924449615600fcf5f6cb4e4497f7d1a162fe074427e2aa38a2c5414acdbc930f2a4c2c1cf7736c443fc277387a6f0a75cec35eb7cea5dd930b5789e1912f07faab45341e83cb68f8caca1651c00212221938f461bbfc5b6ee5b2bbab368965352677f31cfd4033941d2f4774585cda51e50b6af0588c8830ad088192935bce8d4f407e0b815fc81d07968e8689805d97c3154d387ccc32e5a2b3dd008bed2924d42100431182d092e5bdaf52098723b80ac08bdc36db326718b87ba6da3ce050d7b35d826654ce8c52fda834136015d148d73ff78743107511e27459024a5d056efd7210bf0079cfd53836276d41a8f8727d3f9873d387384072fa711689fe9b29b2586c4f61f4de5c8ffd65e9c1a63bf039ea8aeebbf3149e73c1ab2ac5505f5b019af9d9859f3b832a50e8b43109c33904a8b6f85355ba56e8c3faf416148357c94b8893fe3aea15e10b80df0269ce97c729516fa5c29410dd1bf4f96617ae72ccc0c5f4e6b8a9011a46c1521bf1116073006430b5cb5a05ce32bbf05d831c6d3b558fa5e23387164462fc0081be162477481205be12e24be608779dad16cac89fcd8208c6a3e411c614c650bd8d4a41c5594dc9ed936aebfeed19c66babb9f8f15dd1f09ce45985271b0b44b8fdedc41f93189a5c2dacd2f026ed00861500a8266aba5b1e862d9a84be48a4038cdb48be228d194f06b9c07b96ec00ea181ab8884d36dff15187d8cbd39f376e0c261df365f1598ed238df34f8c3b6e9f0991d0d91baad8442870b75f9c8d6e7db21b50c3aafc0c867c8d174b64d5478f29bd78ece430f6e55bf190a1ee847ed7312f3eb625ab569759ec5a43fc1e84439818c55821833e8ddda793e8167a82bc3c92e3723412e1a603f4360e4f2b2347e8039fd9ff53c02ba9a06da340ec191c1a826fe55a65c87b2863cff5e85a9fa7d4befb115a312bab1207caaf9848aeee0fd73e07b5aa2d858a90953fd3dfa8c52f1d64a742161d2d573abc6d2074701a13b5dc301a66b9ca9e28a38b1a4df96b2b29532500ff3de50489be58457cd90d2a03b05183481821f3adda1b87a82fbe587c9124a47bc3492d9b8083f9f2de2019a4ecb893babc743d54ca4b58b651861ee7ba220f410e10dfae20229d5febe5671a99501d5ecc15cf4133d2789dfce825df42babfc7b05ce782b41019799afa375909e0618d26eca8c95bad5d167464ff8f8541f331e6c0d77c91b65d76473f9b60988bd27f19a43e4c575d51f92a6723586d555c7e11c261d0edbabf8c36fb89bf2d32001849adb7538be9567c9d0e6c3529ab2cfe5595b8f8d1d28206162fea6f710c1fa0090fe87e960e5ce159fa453b78ff9546ec716018558a89deb26a28b26a04b27a6bc492a71925585415ec6fccafa9a1361f0b788a72da639276e9d78f7fffdf3f7aec1a32d1c488683102db31ad7d126b5f6253f9e698fddd4ed9aa8c86852e95e3cc3b344fe694f7984b4481f0a3ddd58cf7451ef51a235ea0fc9684cea495012600c9ee2d353fe895932b972c23b05911733d0aaf79ba41a4b3e7ce65a177024d8cec021eef3585238baeeeab2ff051471b2222d64292b16e0e9761e590f9e2fb90a0efa340cd1f2b4439bf916ba05725d12d5192dc22bf447167050b562bb014bfce93f66ffbfa3fe0ded225ef7c87536e06fe0efeba1a2578010a6d16a546945e05f15aeb3497517d8c4bed8da1b3eed576d90592501d2e25488bc1e0185246873889e5d74e4b411f1984229aeee051f10738536bd0304f29dafdd79bbc7167ad797c2e82ab188a46e94dcc509c23f9be9fbee0206f41c02762c89a12195ca08d8155a9d2f148a7eb98e2976a054001a6d196ccd44642bbc1052032e57bd6ca46a1ea36086c322e9f1a5e45b65925e1d2f30f37198a0e14e2b33fe462fbfb73ba2e11ed23a045cfe918ec88574cb6e6d2fcc56bad89834ffa41f1014a238460e68c529d891c37f5f04d48c3f01e024bc5f347ddec051f914c98e87d1ba753f\",\"salt\":\"d3d4d5d6d7d8d9da\",\"nonce\":\"dbdcdddedfe0e1e2e3e4e5e6\"}",
			  "tor_proof_signature": null,
			  "tor_sender_address": null,
			  "version": "version2"
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
		  "TxProofVerify": "amount value doesn't match slate"
		}
	  }
	}
	# "#
	# , false, 5, true, true, true, true, true);
	```
	*/

	fn verify_payment_proof(&self, proof: TxProof) -> Result<VerifyProofResult, Error>;

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
	#
	# // Compact slate processing, recipient as a string
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "encode_slatepack_message",
		"params": {
			"recipient": "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
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
				#[cfg(feature = "grin_proof")]
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
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<TxProof, Error> {
		Owner::get_stored_tx_proof(self, None, tx_id, tx_slate_id)
	}

	fn verify_payment_proof(&self, proof: TxProof) -> Result<VerifyProofResult, Error> {
		Owner::verify_tx_proof(self, &proof)
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
	global::set_local_accept_fee_base(consensus::MILLI_MWC / 100);

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
