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
use uuid::Uuid;

use crate::config::{MQSConfig, TorConfig, WalletConfig};
use crate::core::core::OutputFeatures;
use crate::core::core::Transaction;
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v3::TransactionV3;
use crate::libwallet::{
	AcctPathMapping, Amount, BuiltOutput, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeHeightResult, OutputCommitMapping, PaymentProof, Slate, SlatePurpose, SlateVersion,
	StatusMessage, TxLogEntry, VersionedSlate, ViewWallet, WalletInfo, WalletLCProvider,
};
use crate::types::{SlatepackInfo, TxLogEntryAPI};
use crate::util;
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen;
use crate::util::{static_secp_instance, ZeroingString};
use crate::{ECDHPubkey, Owner, Token};
use easy_jsonrpc_mwc;
use ed25519_dalek::PublicKey as DalekPublicKey;
use libwallet::RetrieveTxQueryArgs;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use rand::thread_rng;
use std::convert::TryFrom;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// Secure version containing wallet lifecycle functions. All calls to this API must be encrypted.
/// See [`init_secure_api`](#tymethod.init_secure_api) for details of secret derivation
/// and encryption.

#[easy_jsonrpc_mwc::rpc]
pub trait OwnerRpcV3 {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
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
	# , true, 4, false, false, false, false, true);
	```
	*/
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "account1"
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
	# ,true, 4, false, false, false, false, true);
	```
	 */
	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "default"
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
	# , true, 4, false, false, false, false, true);
	```
	 */
	fn set_active_account(&self, token: Token, label: &String) -> Result<(), Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 2, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
	# , true, 2, false, false, false, false, true);
	```
	*/

	fn retrieve_outputs(
		&self,
		token: Token,
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
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
				  "reverted_after": null,
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
				  "reverted_after": null,
				  "tx_slate_id": null,
				  "tx_type": "ConfirmedCoinbase"
				}
			  ]
			]
		  }
		}
	# "#
	# , true, 2, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
				  "reverted_after": null,
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
				  "reverted_after": null,
				  "tx_slate_id": null,
				  "tx_type": "ConfirmedCoinbase"
				}
			  ]
			]
		  }
		}
	# "#
	# , true, 2, false, false, false, false, true);
	```

	 */

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), Error>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs), which passes only the `tx_query_args`
	parameter. See  (../mwc_wallet_libwallet/types.struct.RetrieveTxQueryArgs.html)

	```
		# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "query_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"show_last_four_days": true,
				"query": {
					"min_id": 0,
					"max_id": 100,
					"min_amount": "0",
					"max_amount": "60000000000",
					"sort_field": "Id",
					"sort_order": "Asc"
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
	# , true, 2, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "query_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"query": {
					"min_id": 0,
					"max_id": 100,
					"min_amount": "0",
					"max_amount": "60000000000",
					"sort_field": "Id",
					"sort_order": "Asc"
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
	# , true, 2, false, false, false, false, true);
	```

	*/

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		query: RetrieveTxQueryArgs,
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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
	# ,true, 4, false, false, false, false, true);
	```
	 */

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		minimum_confirmations: Option<u64>,
	) -> Result<(bool, WalletInfo), Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, false);
	#
	# // Short request. minimum_confirmations is optional but we put it, otherwise there will be not enough funds for default value 10
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, false);
	#
	# // Compact slate request that will be ready for compacting to slatepack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
					"public_key": "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
					"domain": "",
					"port": null
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
	# ,true, 4, false, false, false, false, true);
	#
	# // Producing compact slate that can be converted into the slatepack with target_slate_version = 4.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "init_send_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"args": {
				"amount": "200000000",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": true,
				"target_slate_version": 4
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
	# ,true, 4, false, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, false);
	#
	# // Full list of arguments
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "issue_invoice_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, false);
	#
	# // Compact Slate, can be converted into the slatepack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	# {
		"jsonrpc": "2.0",
		"method": "issue_invoice_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"args": {
				"amount": "2000000000",
				"message": "Please give me your coins",
				"dest_acct_name": null,
				"target_slate_version": null,
				"slatepack_recipient" : {
					"public_key": "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
					"domain": "",
					"port": null
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
	# ,true, 4, false, false, false, false, true);
	```
	*/

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::get_rewind_hash](struct.Owner.html#method.get_rewind_hash).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_rewind_hash",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id":1,
		"jsonrpc":"2.0",
		"result":{
			"Ok":"c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de"
		}
	}
	# "#
	# ,true, 0, false, false, false, false, false);
	```
	 */
	fn get_rewind_hash(&self, token: Token) -> Result<String, Error>;

	/**
	Networked version of [Owner::scan_rewind_hash](struct.Owner.html#method.scan_rewind_hash).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan_rewind_hash",
		"params": {
			"rewind_hash": "c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de",
			"start_height": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id":1,
		"jsonrpc":"2.0",
		"result":{
			"Ok":{
				"last_pmmr_index":8,
				"output_result": [
				  {
					"commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
					"height": 1,
					"is_coinbase": true,
					"lock_height": 4,
					"mmr_index": 1,
					"value": 2380952380
				 },
			   {
				 "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
				 "height": 2,
				 "is_coinbase": true,
				 "lock_height": 5,
				 "mmr_index": 2,
				 "value": 2380952380
			   },
			   {
				 "commit": "09c22771c700c9ccc1feea8fb151b4e496607bb442f1e1e7bb93992f6422886954",
				 "height": 3,
				 "is_coinbase": true,
				 "lock_height": 6,
				 "mmr_index": 4,
				 "value": 2380952380
			   },
			   {
				 "commit": "0834ced7ae2dbf08f2008ff99fe0f447863405c0622233ece68d39e2ae02f7bf0c",
				 "height": 4,
				 "is_coinbase": true,
				 "lock_height": 7,
				 "mmr_index": 5,
				 "value": 2380952380
			   },
			   {
				 "commit": "08e0404fe044830d8f5be9953be5c70b5b7d525e4ecd3973437d9d6005ea5cd2bc",
				 "height": 5,
				 "is_coinbase": true,
				 "lock_height": 8,
				 "mmr_index": 8,
				 "value": 2380952380
			   }
			 ],
			 "rewind_hash": "c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de",
			 "total_balance": 11904761900
			}
		}
	 }
	# "#
	# ,true, 5, false, false, false, false, false);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan_rewind_hash",
		"params": {
			"rewind_hash": "c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id":1,
		"jsonrpc":"2.0",
		"result":{
			"Ok":{
				"last_pmmr_index":8,
				"output_result": [
				  {
					"commit": "0910c1752100733bae49e877286835aab76d5856ef8139b6c6e3f51798aa461b03",
					"height": 1,
					"is_coinbase": true,
					"lock_height": 4,
					"mmr_index": 1,
					"value": 2380952380
				 },
			   {
				 "commit": "098778ce2243fa34e5876c8cb7f6dbbbd6a5649c1561973a807a6811941c12363c",
				 "height": 2,
				 "is_coinbase": true,
				 "lock_height": 5,
				 "mmr_index": 2,
				 "value": 2380952380
			   },
			   {
				 "commit": "09c22771c700c9ccc1feea8fb151b4e496607bb442f1e1e7bb93992f6422886954",
				 "height": 3,
				 "is_coinbase": true,
				 "lock_height": 6,
				 "mmr_index": 4,
				 "value": 2380952380
			   },
			   {
				 "commit": "0834ced7ae2dbf08f2008ff99fe0f447863405c0622233ece68d39e2ae02f7bf0c",
				 "height": 4,
				 "is_coinbase": true,
				 "lock_height": 7,
				 "mmr_index": 5,
				 "value": 2380952380
			   },
			   {
				 "commit": "08e0404fe044830d8f5be9953be5c70b5b7d525e4ecd3973437d9d6005ea5cd2bc",
				 "height": 5,
				 "is_coinbase": true,
				 "lock_height": 8,
				 "mmr_index": 8,
				 "value": 2380952380
			   }
			 ],
			 "rewind_hash": "c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de",
			 "total_balance": 11904761900
			}
		}
	 }
	# "#
	# ,true, 5, false, false, false, false, false);
	```
	 */
	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error>;

	/**
	Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "process_invoice_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, false);
	#
	# // Compact slate processing, V3
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, true);
	#
	# // Slatepack payload
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, true);
	```
	*/

	fn process_invoice_tx(
		&self,
		token: Token,
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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 5 ,true, false, false, false, false);
	#
	# // test for compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 5 ,true, false, false, false, true);
	#
	# // Slatepack processing
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 5 ,true, false, false, false, true);
	```
	 */
	fn tx_lock_outputs(
		&self,
		token: Token,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, false, false, false);
	#
	# // Compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, false, false, true);
	#
	# // Slatepack processing
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# "#
	# , true, 5, true, true, false, false, true);
	```
	 */
	fn finalize_tx(&self, token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
			},
			"fluff": false
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
	# , true, 5, true, true, true, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, true, false, true);
	```
	 */

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: Option<bool>) -> Result<(), Error>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, false, false, true);
	```
	 */
	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.mwctx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
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
	# , true, 5, true, true, false, false, false);
	```
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
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
	# , true, 5, true, true, false, false, false);
	```
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.mwctx"
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
	# , true, 5, true, true, false, false, false);
	```
	 */
	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntryAPI,
	) -> Result<Option<TransactionV3>, Error>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
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
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"payment_proof": null
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
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
			"Ok": null
		}
	}
	# "#
	# ,true, 0 ,false, false, false, false, true);
	```
	*/
	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), Error>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"start_height": 1,
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
	# , true, 1, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
	# , true, 1, false, false, false, false, true);
	```
	 */
	fn scan(
		&self,
		token: Token,
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
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , true, 5, false, false, false, false, true);
	```
	 */
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error>;

	/**
		Initializes the secure JSON-RPC API. This function must be called and a shared key
		established before any other OwnerAPI JSON-RPC function can be called.

		The shared key will be derived using ECDH with the provided public key on the secp256k1 curve. This
		function will return its public key used in the derivation, which the caller should multiply by its
		private key to derive the shared key.

		Once the key is established, all further requests and responses are encrypted and decrypted with the
		following parameters:
		* AES-256 in GCM mode with 128-bit tags and 96 bit nonces
		* 12 byte nonce which must be included in each request/response to use on the decrypting side
		* Empty vector for additional data
		* Suffix length = AES-256 GCM mode tag length = 16 bytes
		*

		Fully-formed JSON-RPC requests (as documented) should be encrypted using these parameters, encoded
		into base64 and included with the one-time nonce in a request for the `encrypted_request_v3` method
		as follows:

		```
		# let s = r#"
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_request_v3",
			 "id": "1",
			 "params": {
					"nonce": "ef32...",
					"body_enc": "e0bcd..."
			 }
		}
		# "#;
		```

		With a typical response being:

		```
		# let s = r#"{
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_response_v3",
			 "id": "1",
			 "Ok": {
					"nonce": "340b...",
					"body_enc": "3f09c..."
			 }
		}
		# }"#;
		```

	*/

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error>;

	/**
	Networked version of [Owner::get_top_level_directory](struct.Owner.html#method.get_top_level_directory).

	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_top_level_directory",
		"params": {
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
			"Ok": "/doctest/dir"
		}
	}
	# "#
	# , true, 5, false, false, false, false, true);
	```
	*/

	fn get_top_level_directory(&self) -> Result<String, Error>;

	/**
	Networked version of [Owner::set_top_level_directory](struct.Owner.html#method.set_top_level_directory).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_top_level_directory",
		"params": {
			"dir": "/home/wallet_user/my_wallet_dir"
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
	# , true, 5, false, false, false, false, true);
	```
	*/

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error>;

	/**
	Networked version of [Owner::create_config](struct.Owner.html#method.create_config).

	The `wallet_config` ,`logging_config` and `mqs_config` parameters can be `null`, the examples
	below are for illustration. Note that the values provided for `log_file_path` and `data_file_dir`
	will be ignored and replaced with the actual values based on the value of `get_top_level_directory`
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_config",
		"params": {
			"chain_type": "Mainnet",
			"wallet_config": {
				"chain_type": null,
				"api_listen_interface": "127.0.0.1",
				"api_listen_port": 3415,
				"api_listen_port": 3418,
				"owner_api_listen_port": 3420,
				"api_secret_path": null,
				"node_api_secret_path": null,
				"check_node_api_http_addr": "http://127.0.0.1:3413",
				"owner_api_include_foreign": false,
				"data_file_dir": "/path/to/data/file/dir",
				"no_commit_cache": null,
				"tls_certificate_file": null,
				"tls_certificate_key": null,
				"dark_background_color_scheme": null
			},
			"logging_config": {
				"log_to_stdout": false,
				"stdout_log_level": "Info",
				"log_to_file": true,
				"file_log_level": "Debug",
				"log_file_path": "/path/to/log/file",
				"log_file_append": true,
				"log_max_size": null,
				"log_max_files": null,
				"tui_running": null
			},
			"tor_config" : {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:9050",
				"send_config_dir": ".",
				"socks_running": false
			},
			"mqs_config" : {
				"mwcmqs_domain": "mqs.mwc.mw",
				"mwcmqs_port": 443
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
			"Ok": null
		}
	}
	# "#
	# , true, 5, false, false, false, false, true);
	```
	*/
	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		mqs_config: Option<MQSConfig>,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::create_wallet](struct.Owner.html#method.create_wallet).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_wallet",
		"params": {
			"name": null,
			"mnemonic": null,
			"mnemonic_length": 32,
			"password": "my_secret_password"
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
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::open_wallet](struct.Owner.html#method.open_wallet).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "my_secret_password"
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
			"Ok": "d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868"
		}
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error>;

	/**
	Networked version of [Owner::close_wallet](struct.Owner.html#method.close_wallet).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
		"params": {
			"name": null
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
	# , true, 0, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
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
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_mnemonic](struct.Owner.html#method.get_mnemonic).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"name": null,
			"password": ""
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
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , true, 0, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"password": ""
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
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error>;

	/**
	Networked version of [Owner::change_password](struct.Owner.html#method.change_password).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"name": null,
			"old": "",
			"new": "new_password"
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
	# , true, 0, false, false, false, false, true);
	#
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"old": "",
			"new": "new_password"
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
	# , true, 0, false, false, false, false, true);
	```
	*/
	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error>;

	/**
	Networked version of [Owner::delete_wallet](struct.Owner.html#method.delete_wallet).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
		"params": {
			"name": null
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
	# , true, 0, false, false, false, false, true);
	#
		# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
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
	# , true, 0, false, false, false, false, true);
	```
	*/
	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error>;

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
	# , true, 0, false, false, false, false, true);
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
	# , true, 0, false, false, false, false, true);
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
	# , true, 0, false, false, false, false, true);
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
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
		  "public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
			"domain": "",
		  "port": null
		}
	  }
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn get_mqs_address(&self, token: Token) -> Result<ProvableAddress, Error>;

	/**
	Networked version of [Owner::get_wallet_public_address](struct.Owner.html#method.get_wallet_public_address).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_wallet_public_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
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
		  "public_key": "fffqrotuelaodwjblwmifg36xjedjw4azbwvfexmxmmzsb6xvzbkhuqd",
		  "domain": "",
		  "port": null
		}
	  }
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn get_wallet_public_address(&self, token: Token) -> Result<ProvableAddress, Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
		  "excess": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97",
		  "recipient_address": {
			"domain": "",
			"port": null,
			"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2"
		  },
		  "recipient_sig": "3044022044afc455c9e47002a761ba27c4fa929cef3d239818d8dd68788b951792df10320220641c3e7244d7312a4152ea82b8e74c6c58125ece2140362196be70d35e36a1a9",
		  "sender_address": {
			"domain": "",
			"port": null,
			"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
		  },
		  "sender_sig": "3045022100cd79c09fd39b2ed64bbcd3952b926a824f4be569d35f22af44990b91dc98729202204614e0514826c894d7dec594df6e50890c46d279dbd82692d06d4ec2d166026b"
		}
	  }
	}
	# "#
	# , true, 5, true, true, true, true, false);
	#
	# // Compact slate case, kernel is different now.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"tx_id": null,
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
	# , true, 5, true, true, true, true, true);
	```
	```
	# // Compact slate case, kernel is different now.
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, true, true, true);
	```
	*/

	fn retrieve_payment_proof(
		&self,
		token: Token,
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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"proof": {
			  "amount": "2000000000",
			  "excess": "09bbe0e251ebd77edd17c6407778e816112433a31eed6a740278d4471fcacaee97",
			  "recipient_address": {
				"domain": "",
				"port": null,
				"public_key": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2"
			  },
			  "recipient_sig": "3044022044afc455c9e47002a761ba27c4fa929cef3d239818d8dd68788b951792df10320220641c3e7244d7312a4152ea82b8e74c6c58125ece2140362196be70d35e36a1a9",
			  "sender_address": {
				"domain": "",
				"port": null,
				"public_key": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
			  },
			  "sender_sig": "3045022100cd79c09fd39b2ed64bbcd3952b926a824f4be569d35f22af44990b91dc98729202204614e0514826c894d7dec594df6e50890c46d279dbd82692d06d4ec2d166026b"
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
	# , true, 5, true, true, true, true, false);
	#
	# // Compact slate case
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 5, true, true, true, true, true);
	```
	*/

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error>;

	/**
	Networked version of [Owner::set_tor_config](struct.Owner.html#method.set_tor_config).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_tor_config",
		"params": {
			"tor_config": {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:59050",
				"send_config_dir": ".",
				"socks_running": false
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
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	*/
	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), Error>;

	/**
	Networked version of [Owner::build_output](struct.Owner.html#method.build_output).
	```
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_output",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"features": "Plain",
			"amount":  "60000000000"
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
				"blind": "089705aa74b638ee391e295d227c534a50dd58e603bca97a4404747cf8a5a189",
				"key_id": "0300000000000000000000000000000000",
				"output": {
					"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					"features": "Plain",
					"proof": "4b5d6fb1b4d143fc50c83aef61c5410be760a395ed71f3424f7746bf5ee0539ae299569d99b73ea6583b1057834551faa0ac8cfe34c75431b86d6f37dec1ff070fc01f44babf0d3446781564ff7a143242ea67cb4ff7b11fe399735695c3fe70b40b71f31b04cf73b1d1f3430fb53a8c9f990fae48c09b42f8212d60a2d3ce0b8ea4dc0d37a82c3f328162ab8d50f48c28cb9a721a87a40aa3915bf9fffc0cd820e15b758e8565ad7fbf22d03711dc83f98e7c9f955d9398a1c75bc96df2ee64751592953cced38527b3f68282d2ca2fdf2994fbd93a1642fb9d265d57c3cf7df01501da569f2b4e606a1c3084c807a39947a3e1fd41b0647891e1f64842a2b98e694b93857e30691e0b0bca7bc49dec9d6af1003a40b3431ae0bcae8454a438523d066dcac4f194d8370c5ba6567830f302e1ec2607b8d1720bb6c6c57c549f1a3ef7ad2b54dfdd0178329e0723b8a55b438a1e43a984c072d6505aa5e193042d9703484c8383e78d9553684fad5e399f11f8ae6577e4ac4e3c2478e3fd8df0164600b4816b2167c2bf5b9fd7dd29cc1041fccbf1392240fd7c1dc39dd1ebc86b882a383dfe683e9f029d40b2829e3bf56b9760e1d81b7ad4a9066b1c01ccbea6b196154443cacedaccd5ff4fd25cbd9a8f0d271d5688bbe4b956fd34d3413d0478ac9400f6f1ff3890dea10be072d2d48bfa69a6e1e1b6fffaa9db4663eb1ecc26da331072877eb6d4a05a41584d44ed5d2a96a98727563bf180768940c99a15e9183ae927f47f2c0e13d9c00d7ebf0dacb1b6c139d3e18701d10c9d1ef300eeeab756eaa4584c3f5fb42793f7c2517601ae31d887c177eec8bce35c0aa16ba6991fd885deb9ff7b44ffd489f8e9e9d0717141501143c027d33e8a4baf6d85c859ff8a04d1aafbb3d1a97dc6c8ee3642ec41b8e43a137b43c8e60d69a6f19eb9749e"
				}
			}
		}
	}
	# "#
	# , true, 0, false, false, false, false, true);
	```
	 */
	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error>;

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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"recipient": {
					"public_key" : "3zvywmzxtlm5db6kud3sc3sjjeet4hdr3crcoxpul6h3fnlecvevepqd",
					"domain": "",
					"port": null
				},
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
	# ,true, 4, false, false, false, false, true);
	#
	# // Converting slate into non encrypted binary, recipient is null
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "encode_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# ,true, 4, false, false, false, false, true);
	```
	*/

	fn encode_slatepack_message(
		&self,
		token: Token,
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
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 0, false, false, false, false, true);
	#
	# // Decode not encrypted slate pack
	# mwc_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "decode_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
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
	# , true, 0, false, false, false, false, true);
	```
	*/

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		address_index: Option<u32>,
	) -> Result<SlatepackInfo, Error>;
}

impl<L, C, K> OwnerRpcV3 for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error> {
		Owner::accounts(self, (&token.keychain_mask).as_ref())
	}

	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, Error> {
		Owner::create_account_path(self, (&token.keychain_mask).as_ref(), label)
	}

	fn set_active_account(&self, token: Token, label: &String) -> Result<(), Error> {
		Owner::set_active_account(self, (&token.keychain_mask).as_ref(), label)
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: Option<bool>,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		Owner::retrieve_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			include_spent.unwrap_or(false),
			refresh_from_node.unwrap_or(true),
			tx_id,
		)
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), Error> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
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

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		query: RetrieveTxQueryArgs,
		show_last_four_days: Option<bool>,
	) -> Result<(bool, Vec<TxLogEntryAPI>), Error> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node.unwrap_or(true),
			None,
			None,
			Some(query),
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
		token: Token,
		refresh_from_node: Option<bool>,
		minimum_confirmations: Option<u64>,
	) -> Result<(bool, WalletInfo), Error> {
		Owner::retrieve_summary_info(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node.unwrap_or(true),
			minimum_confirmations.unwrap_or(1),
		)
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let slate = Owner::init_send_tx(self, (&token.keychain_mask).as_ref(), &args, 1)?;
		// Return plain slate. If caller don't want sent slate with this API, than probvably caller want
		// handle the workflow in lower level.
		// If caller did send with thius API - then the slate is just for logging. For logging it is
		// better to have plain slate so it can be readable.
		let version = slate.lowest_version();
		Ok(VersionedSlate::into_version_plain(slate, version)
			.map_err(|e| Error::SlatepackEncodeError(format!("{}", e)))?)
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error> {
		let slate = Owner::issue_invoice_tx(self, (&token.keychain_mask).as_ref(), &args)?;

		// Invoice slate respond does a slatepack encoding if recipient is defined.

		let res_slate = Owner::encrypt_slate(
			self,
			(&token.keychain_mask).as_ref(),
			&slate,
			None,
			SlatePurpose::InvoiceInitial,
			args.slatepack_recipient
				.map(|a| a.tor_public_key())
				.filter(|a| a.is_ok())
				.map(|a| a.unwrap()), // sending back to the sender
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			Error::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;
		Ok(res_slate)
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (slate_from, content, sender) =
			Owner::decrypt_versioned_slate(self, (&token.keychain_mask).as_ref(), in_slate)
				.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		if let Some(content) = &content {
			if *content != SlatePurpose::InvoiceInitial {
				return Err(Error::SlatepackDecodeError(format!(
					"Expecting InvoiceInitial slate content, get {:?}",
					content
				)));
			}
		}

		let out_slate =
			Owner::process_invoice_tx(self, (&token.keychain_mask).as_ref(), &slate_from, &args)?;

		let res_slate = Owner::encrypt_slate(
			self,
			(&token.keychain_mask).as_ref(),
			&out_slate,
			Some(version),
			SlatePurpose::InvoiceResponse,
			sender, // sending back to the sender
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			Error::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;
		Ok(res_slate)
	}

	fn finalize_tx(&self, token: Token, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (slate_from, _content, sender) =
			Owner::decrypt_versioned_slate(self, (&token.keychain_mask).as_ref(), in_slate)
				.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		let out_slate = Owner::finalize_tx(self, (&token.keychain_mask).as_ref(), &slate_from)?;

		let res_slate = Owner::encrypt_slate(
			self,
			(&token.keychain_mask).as_ref(),
			&out_slate,
			Some(version),
			SlatePurpose::FullSlate,
			sender, // sending back to the sender
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			Error::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;
		Ok(res_slate)
	}

	fn tx_lock_outputs(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), Error> {
		let (slate_from, _content, _sender) =
			Owner::decrypt_versioned_slate(self, (&token.keychain_mask).as_ref(), in_slate)
				.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		Owner::tx_lock_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			&slate_from,
			None, // RPC doesn't support address
			participant_id,
		)
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		Owner::cancel_tx(self, (&token.keychain_mask).as_ref(), tx_id, tx_slate_id)
	}

	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntryAPI,
	) -> Result<Option<TransactionV3>, Error> {
		Owner::get_stored_tx(
			self,
			(&token.keychain_mask).as_ref(),
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

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: Option<bool>) -> Result<(), Error> {
		Owner::post_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Transaction::try_from(tx).map_err(|e| {
				Error::GenericError(format!("Unable convert V3 transaction, {}", e))
			})?,
			fluff.unwrap_or(false),
		)
	}

	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), Error> {
		if slate.is_slatepack() {
			return Err(Error::SlatepackDecodeError(
				"verify_slate_messages is not applicable for slatepack".to_string(),
			));
		}
		let slate = slate
			.into_slate_plain(true)
			.map_err(|e| Error::SlatepackDecodeError(format!("{}", e)))?;

		Owner::verify_slate_messages(self, (&token.keychain_mask).as_ref(), &Slate::from(slate))
	}

	fn get_rewind_hash(&self, token: Token) -> Result<String, Error> {
		Owner::get_rewind_hash(self, (&token.keychain_mask).as_ref())
	}

	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		Owner::scan_rewind_hash(self, rewind_hash, start_height)
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: Option<bool>,
	) -> Result<(), Error> {
		Owner::scan(
			self,
			(&token.keychain_mask).as_ref(),
			start_height,
			delete_unconfirmed.unwrap_or(false),
		)
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error> {
		Owner::node_height(self, (&token.keychain_mask).as_ref())
	}

	// we have to use e.description  because of the bug at rust-secp256k1-zkp
	#[allow(deprecated)]

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());

		let mut shared_pubkey = ecdh_pubkey.ecdh_pubkey;
		shared_pubkey
			.mul_assign(&secp, &sec_key)
			.map_err(|e| Error::Secp(format!("{}", e)))?;

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		let shared_key = SecretKey::from_slice(&secp, &x_coord[1..])
			.map_err(|e| Error::Secp(format!("{}", e)))?;
		{
			let mut s = self.shared_key.lock();
			*s = Some(shared_key);
		}

		let pub_key = PublicKey::from_secret_key(&secp, &sec_key)
			.map_err(|e| Error::Secp(format!("{}", e)))?;

		Ok(ECDHPubkey {
			ecdh_pubkey: pub_key,
		})
	}

	#[warn(deprecated)]

	fn get_top_level_directory(&self) -> Result<String, Error> {
		Owner::get_top_level_directory(self)
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error> {
		Owner::set_top_level_directory(self, &dir)
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
		mqs_config: Option<MQSConfig>,
	) -> Result<(), Error> {
		Owner::create_config(
			self,
			&chain_type,
			wallet_config,
			logging_config,
			tor_config,
			mqs_config,
		)
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let m = match mnemonic {
			Some(s) => Some(ZeroingString::from(s)),
			None => None,
		};
		Owner::create_wallet(
			self,
			n,
			m,
			mnemonic_length,
			ZeroingString::from(password),
			None,
		)
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let sec_key = Owner::open_wallet(self, n, ZeroingString::from(password), true, None)?;
		Ok(Token {
			keychain_mask: sec_key,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::close_wallet(self, n)
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let res = Owner::get_mnemonic(self, n, ZeroingString::from(password), None)?;
		Ok((&*res).to_string())
	}

	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::change_password(
			self,
			n,
			ZeroingString::from(old),
			ZeroingString::from(new),
			None,
		)
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::delete_wallet(self, n)
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error> {
		Owner::start_updater(
			self,
			(&token.keychain_mask).as_ref(),
			Duration::from_millis(frequency as u64),
		)
	}

	fn stop_updater(&self) -> Result<(), Error> {
		Owner::stop_updater(self)
	}

	fn get_updater_messages(&self, count: Option<u32>) -> Result<Vec<StatusMessage>, Error> {
		Owner::get_updater_messages(self, count)
	}

	fn get_mqs_address(&self, token: Token) -> Result<ProvableAddress, Error> {
		let address = Owner::get_mqs_address(self, (&token.keychain_mask).as_ref())?;
		let public_proof_address = ProvableAddress::from_pub_key(&address);
		println!("mqs_address address {}", public_proof_address.public_key);
		Ok(public_proof_address)
	}

	fn get_wallet_public_address(&self, token: Token) -> Result<ProvableAddress, Error> {
		let address = Owner::get_wallet_public_address(self, (&token.keychain_mask).as_ref())?;
		let address = ProvableAddress::from_tor_pub_key(&address);
		println!("wallet_public_address address {}", address.public_key);
		Ok(address)
	}

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: Option<bool>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		Owner::retrieve_payment_proof(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node.unwrap_or(true),
			tx_id,
			tx_slate_id,
		)
	}

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error> {
		Owner::verify_payment_proof(self, (&token.keychain_mask).as_ref(), &proof)
	}

	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), Error> {
		Owner::set_tor_config(self, tor_config);
		Ok(())
	}

	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error> {
		Owner::build_output(self, (&token.keychain_mask).as_ref(), features, amount.0)
	}

	fn encode_slatepack_message(
		&self,
		token: Token,
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
			(&token.keychain_mask).as_ref(),
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
		token: Token,
		message: String,
		address_index: Option<u32>,
	) -> Result<SlatepackInfo, Error> {
		let (slate, content, sender, recipient) = Owner::decrypt_slatepack(
			&self,
			(&token.keychain_mask).as_ref(),
			VersionedSlate::SP(message),
			address_index,
		)?;

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

// Keeping as a placeholder for doc tests
#[test]
fn owner_api_v3_test() {
	// use crate as mwc_wallet_api;
}
