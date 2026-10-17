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

//! JSON-RPC Stub generation for the Foreign API

use crate::Foreign;
#[cfg(feature = "test-support")]
use crate::ForeignCheckMiddlewareFn;
#[cfg(feature = "test-support")]
use mwc_wallet_libwallet::proof::proofaddress;
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::reply_cache::ReplyBinding;
use mwc_wallet_libwallet::slatepack::SlatePurpose;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::{
	BlockFees, CbData, Error, NodeClient, VersionInfo, VersionedSlate, WalletLCProvider,
};
#[cfg(feature = "test-support")]
use mwc_wallet_libwallet::{
	self, InitTxArgs, IssueInvoiceTxArgs, NodeVersionInfo, Slate, SlateCtx, SlateVersion, wallet_lock_test,
};
use mwc_wallet_libwallet::wallet_lock;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_core::consensus;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_core::core::Transaction;
use mwc_wallet_util::mwc_crates::easy_jsonrpc_mwc;
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::ed25519_dalek;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
#[cfg(feature = "test-support")]
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_keychain::Keychain;
#[cfg(feature = "test-support")]
use std::ops::DerefMut;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `mwc-wallet listen` with defaults, the V2 api is available at
/// `localhost:3415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mwc::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"foreign_api_version": 2,
				"supported_slate_versions": [
					"SP",
					"V3B",
					"V3",
					"V2"
				]
			}
		}
	}
	# "#
	# ,false, 0, false, false, true);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, Error>;

	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_proof_address",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "fffqrotuelaodwjblwmifg36xjedjw4azbwvfexmxmmzsb6xvzbkhuqd"
		}
	}
	# "#
	# ,false, 0, false, false, true);
	```
	*/
	fn get_proof_address(&self) -> Result<String, Error>;

	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	Build an S2C-bound Coinbase at every height. The request requires a
	hexadecimal `binding_digest`; the response requires `coinbase_opening`.
	Nodes and wallets must both support this contract before mining.

	The digest below is a fixed example. A mining node calculates the actual
	digest from its block template and parent chain state.

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": {
			"block_fees": {
				"fees": 0,
				"height": 5,
				"key_id": null,
				"binding_digest": "0101010101010101010101010101010101010101010101010101010101010101"
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
		  "coinbase_opening": "02626f1ca3f9546933a070e8a1dcb81c6ec541e7c11a3f49abe1714c530ba65bcd",
		  "kernel": {
			"excess": "089a8a18ed18efe07dbd33538579c16b688277bb3ba499324bffe45567ebe791eb",
			"excess_sig": "3e7db784a18ac94b118df352c3c4301c1e1095883bf35729e66e92896d2da877472fee28cce087b1ad3f73a7c0ae84c9e2b03cd18c12cfd349cd2625816fc1cb",
			"features": "Coinbase"
		  },
		  "key_id": "0300000000000000000000000400000000",
		  "output": {
			"commit": "08e0404fe044830d8f5be9953be5c70b5b7d525e4ecd3973437d9d6005ea5cd2bc",
			"features": "Coinbase",
			"proof": "a03e6000ebe145adc2407db184c9ade875353391b2dea245d2ca23b3b92a5e667a25a7602490052990dc871e62f7f9b838420ba1881bf1efee03d3ff8209a29c04278a12c44b0f08be5df70d61bff84849bca6d778a3ff6abc4e7a24753ac613427f4a0574165fb63b914591492ed4ff7b72d683207b5602d61b0e2f840a2bb906a7249fc15e1b40ae078fe53a601dd6913f32bfcfea79222faaef58a0ca00107a30f878e28655c71a30ef7ec6c69cca8eca6d80b3200e571624358745a283b3d2c7bb37f072542260312c50d283d89687a374e2609172b7353591df920a9ddc6a5474de763992d5f4d9d5e9b8cf84000ee8362bffb3830a2235f0b4a380a88e2d0ddcd9059f3fe7da666199589826bdb7da0c5edc7fcc3fcd579b8367c06724e872fa5c146e3e0b783e6b03c9da1167b478119c4b55964d8222e786096978fe3ef9b5c536783cc2f51fb0438ae877c4248201377b745f5f1f7c9b43542307f0092b0262fb751643d4d2a583a578d74c499fb70c72084493d4b9ec7407b34d60bb388dee19a1a82e98836db98e7e1752a3c47b64b24787a0c8bfce83ac76acbfd271c1396845d104d97b6058f3c24c378a33fb175a13cb088c55ea50862332db212671be3f85e1d1dde2570d299f9b8d5a2116847eb0ffa195bef02ca53106527d173ecf6086f3c040a2f72e208b7730e214f835309a7ad4b1b2b0d67b84827dec2dff7aad2abfcbfb25acb4559e8744165297cfc0d34a2cdb1eb8a7e854a7b1f5751243928b6ac91da7f5262f1612099e8ed58bfe2dbfc8cc459df676d0e9fe73f4923b794b2665cbe5cdcf903489f90cd9e97d9b2d78ae9ae1261f4caaadcdcf879eafa983b7beefdf2b11284a90679f664d7f00cad0f605f3e430cd16ac14ace95d14b30a6af0500f02cd726bed19aa2d8db37f2283d39d39fd7ecf0d660be6563a"
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, true);
	```
	*/

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
				"lock_height": "5",
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
							"lock_height": "5"
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
					"version": 2,
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
	# ,false, 1 ,false, false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), Error>;

	/**
	Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
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
		  "coin_type": null,
		  "network_type": null,
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
		null,
		"Thanks, Yeastplume"
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
		  "coin_type": "mwc",
		  "fee": "7000000",
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
			  "part_sig": null,
			  "public_blind_excess": "03ad559b009e8231fcc2a06d40b7341322974c9b13a52000ca2462df2de60aba9f",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": "Thanks, Yeastplume",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b6c6cb87c1977029547b80c450a5eede38c274ee790e6f255e4a64f5ae16e208f",
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd69568a703555f97b8a6bb1b3a03b9bfe4b58ef802ce78a9dbe3dcd6c1ce6e75",
			  "public_blind_excess": "02bfee5e0a52d4feb86e9477ed6771b2fde100d7919771d2ebe0d08c5227537390",
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
				  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
				  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				  "features": "Plain",
				  "fee": "7000000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "09b07b9c83da767a3ad7d052705258c2697970a403e53101e63eb9c3d11e9a0e9a",
				  "features": "Plain",
				  "proof": "90e28b550da2fb2f4b934889067b4350695be9edb19fdd0342083a83cedc3d36cdd1796fd1ad89d1d4d5f38c2f975f4903dcebcc6ebe7c0186a6696c8d8aa71a05e1d31a0cd7be333ea82d950b362d7cf13a5e4278e8e04814b9fe571c942d9289bc804964d58fe0a71c2f31ecba86bd6c8eef37cddc9382471015114ac1d91132a40a9172be439b6ba1250b302db37dea134812d058e13a8f82f6e54b1ce320e3b5819743eba2c507404420557372f754c1103ad943b250473a4c6494af1c6d0664be3a873076a1ee93ab8971e6d7362d2b8d66b8eedb031955427b6223e8a2845f3e0369b522ffe28d622bfcdcc94e2ac6038ee51a827246c351404b128d5ee621ab21554a8d0dd861a86390b98fd4212e3e5ccd688cae12b2bb7d1c172d7bacccdb4fd00745a246e5e640b8b0a02d87400c0959bcb0e600f09619fdc479d830caeb5e401dd7a5a3f8b4271e14f615d46f62fd19f7cd2048016836219b4ae20f7b02e9e2fff0b6004ef81dc158303b275e229295e9107098044b8ab732b92b5797f080e92fa3e289dcb542b2e75d2a69336b2ac64a5cf75973e7b3bcf01ff34d434bc54fde58be6f15bf3db217c2744e53d5feeb39603af0be60e82d4068dcf2ffe7b050ae08789a3a0df732fbdbe14da55262fb15c57ee3d264628e06685c025ff0b90957ca7c266143ca5b216e397fee59e5c4922bc89876eca14963d131065a3e15473aa30484050f0afd59c3c9d82065a5633d0b2e413dbfdd136554842f70e4d62392fc865731824a6dce071a216a9bc0daadcf25cc3050faa82dc2219eb0ffa250939d8ebace5c88beb21e86243f0a1defb2048298077872517abd6e124045ad03b77b9a79c86cf054cdfdb5014b5a7461d072de72775d985efb4a15b04c1cfaaaf0c28651b0a6bab35de9bf11669d0108134e2ac61364808618e3792ac2d7"
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
	# ,false, 5, true, false, false);
	```
	```
	# // Compact slate processing case
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"id": 1,
		"params": [
		{
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
				"receiver_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
				"receiver_signature": null,
				"sender_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2"
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
		},
		null,
		"Thanks, Yeastplume"
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
			},
			{
			  "id": "1",
			  "message": "Thanks, Yeastplume",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b93661746d9134e57780d435545a8d78399fc74b135b313c350c6086f90fd2fe5",
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bb431617fb560348f12fb9a288fd758a3189958a50d5cea436417539314b235f9",
			  "public_blind_excess": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "payment_proof": {
			"receiver_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5",
			"receiver_signature": "304402202ab74d4cb3cac5620390167461c8cba1e1132e356a051873271accbe16f3f7c0022032d66e50bec99dff0e0934cb3fcfce4a5da9753c9c807bf02983280d29fe7b97",
			"sender_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2"
		  },
		  "ttl_cutoff_height": null,
		  "tx": {
			"body": {
			  "inputs": [],
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
				  "commit": "08f722ae0f34741fe91c65f5afc20c75f68df2d54fb1706b2be64b8e04c2827a7b",
				  "features": "Plain",
				  "proof": "59da9c60424cec0d4ea52a548f7aa5cfd9a65619f54198c99ae58d41be4022aea1761a0c7a2d262f62850a1daafbf9ac76480fb9f8f3ceb68c7ec306335332b00ca4c6b4bd926152f969f3059da44eb4840d21fe5cb0c5c316f6bf76ce17eae8644166f75ca0f561672befe8b5d0ca4be6b9a3fab1177ef003fa20f9a53df2ae63253b315054a693965b0a74afe266026ffab3e0b16e354fe0c20a9abb1f5023572f4641b508bd112024a9fd51dea686a8aad32a73feb51b22dd6d08fec102db429ba341ec1fc3464d354939512624eca7f1bfa2d7a0fd711efaa07388a76d6ee700c04483793779f66b5201f0d824c600d4e091460a59b39ec5c9d1908400c08e6fb944465d3b296967681459adc13c64b18a16186ebdfac04dad0ef26f2935b8be68680ad3043d39b220fd383a66f402fc9f6f5205a2d5930293d8a0097cfd12038e228618131205de1f3babbdadbf535f18410207fdf6ca211da630f2c86e4dbe017103713e3137f94f5ad08b3f4a4e60f972fefce23410dba9a19ad9311ebb5cd5a0d964ab60344a793339ffa1058bb876729ff2a5f1c2933abf7dd4d4a04003e68ceaac1a92273ddfe2e77b37d045640105fa0a8af30ce1c3c6b61abb792f68a9e4e9449f61c278245789420738bce75b8ae8328a986bfe19a1e85b1e545ad276702849119a2c458c99c8673e2029079cb54226edfb7bfe64cc69d629ecd5ae073c6655e8c9e16357ac1ec137cc2b3a4a8716ea09c0008cd2ef8b120e9db19e0de52789c97ac134e416c3069db9d4279cca4605320bd2c37ef367aa845e8d74db5dbcd93a243cc24779fd650300cce6871ed73ce4fa67ac36ee5dd10bafaee81add88763ec6e946293bb8b1d00d85a30ea0512bf0cf353aa515b0143106b3b5a5c8b115c97f30225d81b7071677ce25e4b1aab3bd79527f3c58490e246482c778"
				}
			  ]
			},
			"offset": "dd6abf5dbf217f680e98b18853c7ebe96259731dd943d64781efec6abbbb575f"
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
	# ,false, 5, true, false, true);
	```
	```
	# // Using Slatepacks for interaction
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"id": 1,
		"params": [
			"BEGINSLATEPACK. 7CbrcQV3Dt8raU4 7KCxgqEWohqSjBn UMCzWJ4A7xx4DKF T7jgS4MBLb8j1Kc ZJe5vhfxLiN2Q5A ddDQbMYFWxXm1Sp 3mVoe8PYrHG1ZEd HfamrNB7ow9PNeq ykJyEC6bb7UhR1q NFpmDXNTUhDDRRB PSqqqGNFHogbN9g A5sHNhgKR5Zpg73 v5zrXDdPdMPXbJp HQy1c4xcKXv4W8w kULgseEZEqvm6V1 wjfKkWWvtWjG3RQ GZ5fi7rXht3A1MN Xgt6zmPfQz. ENDSLATEPACK.",
			null,
			"Thanks, Yeastplume"
		]
	}
	# "#
	# ,
	# r#"
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": "BEGINSLATEPACK. MTu4Q1paWJHENZL ZK9Q9UXsHgsKqof inVSjN62C1yfBkm BLenmeN5tcAuEEH HhsJJiz7KgMcsck JcA9GAoyYkcQZLC VuwpGU3WgNxHgZC U8ee6NjWvUVqxad N6UgruiiEwzdicn Et6jTxtMN29doKw bJW6aCQb62TsDr7 sFeMSg9FxZFWasE 4B4Ros2HUvPjomY 1awVqGnUCPUCDLZ e63brbqkpEiUvhZ z3bvUisBDkRmV2r 3LCQ987WBUzpxML K72o9RfMH9BVrYQ wQEEGn7wugzwmk3 R6Ef3ktNjKBm7W5 Fzp8PW4nJxvubwr 1U8BWcmkqdAVm8a bmiLNpMw63YEuB1 mfazkFHcdCPsjab AYAgsnG2jubi3cY NPtBh3XNfmNrbdr 2NoRjgek7VL4qM3 WMKL6brBtCHuQqr o151NMSPux4c84F KE2YX2mJmU1SPv5 XDRrL8d3CdUSDvA 1Uikx69SNPBjcxm hStkAoLV7YudQjv vHWk6RjCYSwBb5Z W8WgpPXR9xQexCp MN3jAXfkmWpXSpp aassVZqZkJBigHk 4ZfLHQoV9PR3pFz yUdEbrpiGmd4Ymc hPnj3FPPhhUX7X9 hBSEe8iyA3srCay MFFDVYp8M8hRQeT ZHAYCYmfbR499BR n2HTLEPbRAVss6F czxDxv8VHGPcpJV fsUvfSyEdwckDdb SKAqD2HQ3spiQi5 Ee1ByHyNPCDAFZP TRb8N7hB8hutmTi QqfFpHQHR4cbw6S srVosjDDded1S4k aUxyMp4QsNmVXRZ imhngis6XFH2Hze v8Q9k7qWJdjzzBQ iHeaJEUmMe1iuEy CuAbTwNCntrXqk9 tPKCoa6pMuPXes1 kfAqvKsVmwGxnbD M5wBug1ztiQ44FX azWczcrUHsEP6DW vbWLvCp7t3sqfVn 7Fyarr5g3nVdBch R2vHSqk734x8uSs zwkT8EMyyziFVKe KCUS1FLD8ANBRRZ XfH3amuzxVCGtBm dNt6J298oLgHaWG J1QBGbGBNKeis7s UA77ZNrgbZRCrTw Ni7Mqn8hZmhQLim 2qqMMMNXz4r4iTi jdZrEU6xCj54Xe8 Qkn3FrSWSMuuoJR WnX32XH4kA84HfJ Eu18kqUkp4CTvbs 9VpHgbJpJL8tBGG aXkf6wk64tyACfP eN2MHkrhKkubnGD m86dXunXPF6kYwE V2a9snugHwfX3mF WjoZqyt5fgyKo8g m1cBjCzr14ggPDJ UGGU7xsjwxZxdBW 7je5Dk7cCwNnG8b 7rXwWFKsRqyFhvH MCDS3t6ikKuGqYY x4TZKKUS7kKBRx9 kBmn54EQVKPEMTx ucReSESBTtfVEUE 6ohHFTDLQCZZnaU 8mwDevokBvMMKZF JBHDn9QXaCB2N3e EAanLxSYXanWyrP nN8BgRKwFjCJQ8S EyzPM6VAC6y8tVK 2G6wf7ikrkCuVZY tdQnekzqbfXhgxd LQh3FdBajXmVAVd zzibEKqef63pgzJ uyyd6aTpmFfPAWR R2X75dYYR1HJstR oUf7wLWC87Jjco2 hauvPRrW7dHtu4h sU4qFzWHMxHH6x2 BusQrdGLQE66DCq y1CFFc8V8aXjTv8 xrSeYLKbtdM67AQ U. ENDSLATEPACK."
	  }
	}
	# "#
	# ,false, 5, true, false, true);
	```
	*/
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, Error>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	```
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [{
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
		  "coin_type":"mwc",
		  "network_type": "automatedtests",
		  "participant_data": [
			{
			  "id": "0",
			  "public_blind_excess": "0269d5903f404e0e6d844ed9c9e78e72fd2f69bb43c2d6fad6ff03c6c637a323fb",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
			  "part_sig": null,
			  "message": null,
			  "message_sig": null
			},
			{
			  "id": "1",
			  "public_blind_excess": "02ca0730ab4f619253c2507c82c82c9438569b14a6baaba7db695c69d6130374bc",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b069b8580fb79de922f344c2aaaa7b8820d91b34db114f37a5d11629727e216c5",
			  "message": null,
			  "message_sig": null
			}
		  ]
		}]
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
		  "fee": "7000000",
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
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b5ac0735e5765908b26043708ec42e13e2627df972fd647c079e529527890fc82",
			  "public_blind_excess": "0269d5903f404e0e6d844ed9c9e78e72fd2f69bb43c2d6fad6ff03c6c637a323fb",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			},
			{
			  "id": "1",
			  "message": null,
			  "message_sig": null,
			  "part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b069b8580fb79de922f344c2aaaa7b8820d91b34db114f37a5d11629727e216c5",
			  "public_blind_excess": "02ca0730ab4f619253c2507c82c82c9438569b14a6baaba7db695c69d6130374bc",
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
	# ,false, 5, false, true, false);
	```
	```
	# // Compact slate test case
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [{
		  "version_info": {
			"version": 3,
			"orig_version": 3,
			"block_header_version": 2
		  },
		  "num_participants": 2,
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "tx": {
			"offset": "4fab1aebc24b08f6bc78141c56e14230f6e93e07028ff0e401940bd8414025b6",
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
			  "coin_type": "mwc",
			  "compact_slate": true,
			  "fee": "7000000",
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
	# ,false, 5, false, true, true);
	```
	```
	# // Slatepack input/outputs test
	# mwc_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [
			"BEGINSLATEPACK. LvPf4wqFUuB8M3g aaNzvKb37KqfVFr 6jpq8kmuqbPVaQz sDENZBy3iG8b9Yd nVNDcfaq9k7XWV3 FxdSpnKAbA5NEQu 8CyFLxvWrjxoCiN Af1FrDumnURdmTq LzX6gr8b5D3jGxS ySB8E9ZJPPpJkTc xFLx4ZaFJFR5cE2 ansyD47Gm27UtH5 s1tBmUimic4fYAa HpQg17AehGfsyGw KDtr4iefPeSX4rZ C43a1JjStsKh1D1 DtF4NCfvQgAKcHR ZgTPYu5ydkWFdUh Jzi2Fyo6GVeWjRs bRNJWY65MGyRJEg 1w8GKmfnzcDSuLS c6ydDnD8jggpsbY ppbRkQLEZAviA21 PQ5o1HQTbzAaWhw 3Kew6arGvqzeqb3 Uya3Gz4ZEvmSctX LYueKexF8F3BgGF 44HWEisMMBrZc1E bePZAvj3CRTgghp ooeHmXJrr2ArnDd d9hrv76TjE1qhJM DHg7hdZiTEUFsKv FZYDkxfLPnBiup7 ELxE8Q6gjDGAA6g SJLBkCjpMuNhvqV uqejrzdUbuDqmjr NMVgS7xxLVumhra ExDSt9VYwsUXr5T rcqp9u9rbM1x276 ioxNvB27mZEckKp KkGaQE5ER6n73DL odWQo1feFE75G9V m5TLfkceg17wskY cnr3VWQKtVevvMm TPzGQWCgRMsz4dy r4pk3E1W5u7Li7u QEhKavgibXCxLkm imxvaNX8SqFWDPx vieyFjKjL3vQKCo bJ21DFpJEuXUM5G t4CMiM3SjyPwzMQ TxufrTfRNVC3TJU nfqntgL7jHzConR UsB4PprYA66NAY4 FtcdQb97BpK5RJt YLqrnYBGohgWu7K uEN2UcuU51DBrzg sg5GDWm6qQKX8Bb EntaFR5PjXXRP9C sisxy4AVmzVzxwk PZXjJVhwrb2tZiq UFRHMUo3hY5uEWH afaQZTC819AUU2e JjoPKqNPjwQLQTk tr5tyKSbLHKaA2u RqfzDddAxzdCyVd VbcvrvP6tHmtNWa jn7ZMMWAMevG2D7 g7iz23JzkVbS1Ae ijGQYenDMrJMSdw 5vAntPTFkVGkaH6 5AoP1ea2dXRXjiJ vTYfkkh6HyDVZyS 4hjt7Bv65urXomi SFb3hru4fVVztd4 6D7obuQTKzMp88C qAorxgc8hU89sb4 XMza55dbasVRkcf qyeBJ6Brjnbs6Mg CTSjnjX5U4bHm2H P2BUKvL3q81CDEt Df8UVyAaWdNbjHS qgbBfb6wjGAE9vK bDgARAMUzXR1qBq aGoMEtoeCjzre2b nrFDzJbXrhc1bUe TsRzDzEsLVdacx2 zg6gmwc5g11mSfx qKWvmmVBtvtsEz6 xyjpWYtQronDsSx dvxkGwr4tYHi3w4 qsMT5ynFY5rN6Uf nMfUL4YnHQewT2A DHdq2i8EAtmmZaW 4jgfnCSspjkpeUC m8gKSNyUmHzAmue KTzr9xvPWPEHPjd 71p3ivEdVYVJUGc PjcgitcixwmCNfR sjDoKuaGDdDRkHL W9yQBydWT2p6EwA YGaoshM46mUufm8 RvbAXf8JBh6fa5o JHQufEnXw8QooEe WgJNoD1aLLEUnv1 Eq3HHBmgYJS8K1a YCL34WFwhFXqng4 qJCk7j8cpXAzmcL h9bjx8dTrqLoFsB b7zuwcyf6xV9BoY diUpeJ988dQz4cA uEbBcmFXzcFttXA uhup2sa6PWZgDwo m14769GB7znUFvL GjWNXpswRe5cig9 G2GKXBubiDUmh2p xCSKasttCBCRx7J MdQCZn2u5S7uAzz N8tPVAR5ZDK7647 e4XoPxNKYXi7xp9 bzr3Ft7ieEkn67h JwwM9PMj4CsqSRH 5stAyu37oNp8p4j X9zZkrwDav8QVz5 fMShDDXVmHCrDyt C21nutrMmG7QtDw tDE44d5TVTsQXzk 37H9BKshGnjgm8G 1NXG1s2Mqh1h33y KPetA8TByPfNDgv jK9N85TM1a1e9fU kESEf7QaQ4dEjHQ VXivVhXgiFa1Fvx JXDZTVDxpaPPPkF 9kavi845vZ5mF4y XGTancPuajYU9iK Bu8DbPa1z8bfjCe LGdnRhzwBz1k3o7 7seBdjz312uQ5no Nrq9Hq6MBGZFToc HtrZGcCAjcNYKJj SshfMYoZbau7RMX 7pzPV24Qk2PnkMt Tyr5y7oB4ww4GRE AMw3DefxMbtVrVi bP6vBZ2gcX7LfFw Xns4KUPFAiwJG2U tsKg2mguiBzhQgR URNkpDpoJHhjqDW hEavtM8f5drLhKq MyMSXEPvoyGrDGD xZVPs9zzT6GaUKw re7xbS9ruiH32b4 AESBaRA2ghJWJGi xqWbkci6aBrpAvj 8w7UeUqsrjR8eoh QYdm9iSE1AbhCyh PjwWoGXNobte6ED EBEp7EEw9LQ2GMh 5aJ9cZS3wSLYMju b4aXSraUjWYkmeL 9HskSNAVX945CZ1 UCbrssJBq8z8yXx gLHXUcBJJPgb1vx rNVEuezTDuQvDDa vkrFC3y5a3w4DH3 5JrSFoobxCh4zTW NfufAJULWr5uKYN 9RcJoLpzop2b9vi 1HDU89XFiwAXVEK rrRNjHQZB. ENDSLATEPACK."
		]
	}
	# "#
	# ,
	# r#"
		{
		  "id": 1,
		  "jsonrpc": "2.0",
		  "result": {
			"Ok": "BEGINSLATEPACK. 7LoYEkkmDC5HfWa 47hMisjgDaGFZcT 6CvYfuqbMHNCH72 x4uxtLQujK7kUhk b5y65XPkfRSmGEB yVZp36dx4NQdyor hxo6WhU62k5TF3K VbG4V19jSzZimqK KwWXHo2MnawU9kv bHn8CorPTQV1oey bpUEczcQeRqdXDF yTGz7YbKu6VNZwH UYNzcvYQ9BhgWrG QrfdAG8muUvtYUT k7AKZvgHuLvxPrq keDFxCNbtBUChNf 3EbtUmTvf2RT1yz xEXoattRqG1Ei7z 7fCNFngAK85gWgN qwCo75GfmAF91Vb sGA4JvbG6q5KCXe dzr865igjiuadMn GF2BrB3beZzWwF6 VYTfvqf3DxGvwf1 5oUY7uKFGKMegMs b9rRX31AKXMQZSK 56jW2eeqLVtEYUL jJsABaQtRE2xD4T 2SUzhKzpQNVx4JM t5PcShaguHX2otg aCJj7Ch3JKo1KPy pstULk3auy7rnKK jZpPWEYK5ntDnYi xDGPTVCtyG6UcPN Phaq6vkr9PsrAxN jLQGkCEFCnH8EmQ UhoZJyEwVmEvrHJ riiG6o5zEmuKPXR h9vQxGG2GHiYFjn zEFprxqJrsKSmez Tp74H9iDdZ9DNUJ RUdK9VHX6Axtck7 whcp3pvdto8Jvp8 v424mQ9YyMoB9Uy cePBE3oJML8WmhT VzhT9K7wp27w1K8 cuZ2XjyJofLQkof 8dHNWa5HgeoLrJL YzMdF5wVAvAzuHb UyBenHRqmiMwHYc LPNSFzFfSLQP2zC MYea9U4y2KhFtPM XpcZTxbM7hURcgf JvzGVigbGWDL7ar S48w5gEtspL4fjk 24SBKE1tUo2rgjN Veb3nFzs4xxrxKp VBbdV7yNxEuXNHu HWN3utpTR5FsNP1 1HGbb8BacoGQCLh Jzmc4o9xeRsvJLu LR7jhsgSZNPt8XX TYGY7sw5EKAqUzV GWxBVLsvHyb5DS4 MiBafcQC9x6bWcb J2kocdkHeM4zN2A BJNcRJttBNYxivV ecyJTUyd3Hh2xR3 dinCwPgHnCxrFha kBtFm3wnzWwRKnM 8UXAKvSiULiXvYs f4P2wjcTbH6Rmyu K3PeHen3zV77pvG AW4p7fsobHd1qGo DnfEPJvFUHF4mLB mzn91QjDu8sMpkn wD6xjcf1Jgafsyd 9hVBwSL7MozEdY9 o36UCtQWc3Mhwvk 7VbfUVqrgBwNJ5P EYjWriYfDEQXkdV YyKQmUq8aNNv6A2 byxgcyzJVFXnu9e uWPQhRC29eZ7TkJ ckpE51UsMqDgszv BcZfAKmuCDms2Ad JrfiWnVahdUuLHa 79xdAYufT82Sswg YfEdM2oWwCVDyzJ c5C7rcbMQQZYceX vUm8z51ZCE8ousG jao6bTByZuxT2Co HquXhdUusrZUJh5 QLPphgknaJNbske ptwNUDSktKLVNcv dBRWDLAS2vTdgwB jzWmLoa8rvWVa8C m2yQUWqoR8qMnBW 8PmfyakcxMgbZkv x7U2gHm4jPcYrBD N5uTJXeHys7r5Mv m3RaHH3zBkxFrDs 9o7nJp3FuHeYRhz qGaNHcxawFR68Rj MaruQT61Zc3U283 DMwept1jbLKAW97 zM83jki5xZ9MZQ3 hw6XLFJmCRhUFv5 UTJSrCZ7ZJ7kBd4 2ipBQX81isDnWGc gYN1AB4iqZmteLH uMZGS7DWvQ2ideV f1QdA9AXps1SVGg caWZaSjoJJnYy1S kVXmq2paaG9FH5D mmrkc89UU6dmYDZ XKUhmm8Z6RMbSWD 4DPHkE22qmGM7Vw LmGUJX5Sx5QC5nu 33Mm7hAeyPx8Tfy C3WhL9YSXXmwUKk xWi2hQkkJjYv7x8 HDTL9nZuYkgGTMR M4eVZtSv2AreYyy vHmCTCkBsxx8GWr SqKxb8RvZktDJ6z gb2TjtPkg721WSy EVtmFQLGAB4BjVj t5eEHJw83WLPPG7 wzWwNDhCx6CoyXa 5wasVXbzP6rdvMt SzLoGcKmjvnMM16 AFFXFwwmxELjF3X nQbzpT1gFVTraai B37EVKwqaPkaDoF 5UGehnMbmSxLVtR RvxarUrJcD8NDe5 3426yqD98DMVeHw z625MwRXio56ezF xAF4UXgMdCjE1pQ FaquMh4oACvy5iN PHv4chvUkFGkG5K mzbqfn7RJYhkXVW UwjyRw4aiHJHyUF DdN27xSByrx1c5J VnGiLRjjAuEnqeR eaAajmFJs52njjp x9gqvb1x42tXua9 DKEMAx5HmcnE4V5 1mpqxdQSGqdfyMb yDfzVLAoitMYjX2 FaNJytC6eJVmcsW Bhijd3FyPLjxyVV 6JSp9Sw6bYXuY1B GvMiX15igrNnuU1 igrhPWBv1Q5ph4B jX9U8zZ1PsEfxt7 pBZXCJkf8ivStrY 3kWHr93tCYbPL7W 1tEUCo4Hb3oF4F1 pQV6V4urp5kgkPa oHZuFtVyyTAemWC Fi77iaPbCNsWKCM reKP93Eh4rJCFMC P5A63sQm3Zdyu7S Hhf8X4u8mwYesYs c67HPZAtdUWbdxV 1p26PABewf2yryy VSxw6X2xWhdjvNt WbDa8eXx9Xfhf8g 5U48MyCXYp77aom 96xqd2cRuJGv7Yn fSMtwY1KqzdnKju YTsA5ybRiWYhSAp WqVRr1ccgW38DcN xJxk8JvWKXkzxEp NjHUDzV4CYx9wSN jy2z1g93eFAojML XoPpE3116JukTre aqNWVurZUMmSJdP UdenCiDrN4L2qs8 69kv79VxfSR6XmX 4ZfRmzGx7A. ENDSLATEPACK."
		  }
		}
	# "#
	# ,false, 5, false, true, true);
	```
	*/
	fn finalize_invoice_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Foreign::receive_swap_message](struct.Foreign.html#method.receive_swap_message).

	# Json rpc example
	*/
	fn receive_swap_message(&self, message: String) -> Result<(), Error>;

	/**
	Networked version of [Foreign::marketplace_message](struct.Foreign.html#method.marketplace_message).
	# Json rpc example
	*/
	fn marketplace_message(&self, accept_offer_message: &String) -> Result<String, Error>;
}

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, Error> {
		Foreign::check_version(self)
	}

	fn get_proof_address(&self) -> Result<String, Error> {
		Foreign::get_proof_address(self)
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		Foreign::build_coinbase(self, block_fees)
	}

	// verify_slate_messages doesn't make sense for the slate pack. That is why supporting only plain slates
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), Error> {
		let context_id = {
			wallet_lock!(self.wallet_inst, w);
			w.get_context_id()
		};

		Foreign::verify_slate_messages(self, &slate.into_slate_plain(context_id, true)?)
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (slate_from, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender) = Foreign::decrypt_slate(self, in_slate, None)?;

			if content != SlatePurpose::SendInitial {
				return Err(Error::SlatepackDecodeError(format!(
					"Expecting SendInitial content of the slatepack, get {:?}",
					content
				)));
			}
			(slate_from, sender)
		} else {
			let context_id = {
				wallet_lock!(self.wallet_inst, w);
				w.get_context_id()
			};
			let slate_from = in_slate.into_slate_plain(context_id, false)?;
			(slate_from, None)
		};
		let sender_public_key = sender
			.as_ref()
			.map(ProvableAddress::from_tor_pub_key)
			.transpose()?
			.map(|p| p.public_key);
		let mut tx_session = TxSession::new();
		let reply_binding = sender.as_ref().map(ReplyBinding::foreign_rpc);
		let receive_result = Foreign::receive_tx(
			self,
			&mut tx_session,
			&slate_from,
			reply_binding,
			sender_public_key,
			None,
			&dest_acct_name,
			message,
			true,
		)?;
		let out_slate = receive_result.slate;
		let _processing_guard = receive_result.processing_guard;
		let reply_reservation = receive_result.reply_reservation;
		let receive_data = receive_result.receive_data;
		let res_slate = Foreign::encrypt_slate(
			self,
			&out_slate,
			Some(version),
			SlatePurpose::SendResponse,
			sender, // sending back to the sender
			None,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
		)?;

		// Persist only after every fallible response-construction step succeeds.
		// Saving last is intentional: a reported error must mean no transaction
		// was created (see TxSession::save_tx_data).
		if !tx_session.is_empty() {
			let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
			{
				wallet_lock!(self.wallet_inst, w);
				tx_session.save_tx_data(
					&secp,
					&mut **w,
					self.keychain_mask.as_ref(),
					&out_slate.id,
				)?;
			}
		}
		if let Some(reservation) = reply_reservation {
			reservation.complete(&out_slate);
		}
		if let Some(receive_data) = receive_data {
			mwc_wallet_libwallet::foreign::dispatch_receive_callback(receive_data);
		}

		Ok(res_slate)
	}

	fn finalize_invoice_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let (in_slate, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender) = Foreign::decrypt_slate(self, in_slate, None)?;

			if content != SlatePurpose::InvoiceResponse {
				return Err(Error::SlatepackDecodeError(format!(
					"Expecting InvoiceResponse content of the slatepack, get {:?}",
					content
				)));
			}

			(slate_from, sender)
		} else {
			let context_id = {
				wallet_lock!(self.wallet_inst, w);
				w.get_context_id()
			};
			let slate_from = in_slate.into_slate_plain(context_id, false)?;
			(slate_from, None)
		};

		let reply_binding = sender.as_ref().map(ReplyBinding::foreign_rpc);
		// Check the known response format's size before finalization commits state.
		// Keep finalization before response encoding. Finalization durably binds the
		// one-time signing nonce, stores the finalized transaction, and removes the
		// private context; encoding first would leave a crash window in which signing
		// material could be reused after restart. If encoding the FullSlate fails, the
		// wallet owner can recover the saved transaction by slate ID with `get_stored_tx`
		// and submit it with `post_tx`. An exact authenticated retry may also recover
		// the finalized Slate from the in-memory reply cache. Therefore an encoding
		// error after this call is an intentional, recoverable outcome, not evidence
		// that finalization was rolled back. See `tx::complete_tx` for the
		// persist-before-sign invariant.
		let finalize_result = Foreign::finalize_invoice_tx_with_output_version(
			self,
			None,
			&in_slate,
			reply_binding,
			Some(version.clone()),
		)?;

		let res_slate = Foreign::encrypt_slate(
			self,
			&finalize_result.slate,
			Some(version),
			SlatePurpose::FullSlate,
			sender, // sending back to the sender
			None,
			#[cfg(feature = "test-support")]
			self.doctest_mode,
		)?;
		Ok(res_slate)
	}

	fn receive_swap_message(&self, message: String) -> Result<(), Error> {
		#[cfg(feature = "swaps")]
		{
			Foreign::receive_swap_message(self, &message)
		}
		#[cfg(not(feature = "swaps"))]
		{
			let _ = message;
			Err(Error::GenericError("Swaps are disabled".into()))
		}
	}

	fn marketplace_message(&self, message: &String) -> Result<String, Error> {
		#[cfg(feature = "swaps")]
		{
			let res = Foreign::marketplace_message(&self, &message)?;
			Ok(res)
		}
		#[cfg(not(feature = "swaps"))]
		{
			let _ = message;
			Err(Error::GenericError("Swaps are disabled".into()))
		}
	}
}

#[cfg(all(test, feature = "test-support"))]
#[test]
fn build_coinbase_rpc_requires_digest_and_returns_bound_opening() {
	use mwc_wallet_util::mwc_core::{
		core::hash::Hash, libtx::coinbase_binding::verify_coinbase_binding_digest,
	};
	use mwc_wallet_util::mwc_crates::tempfile::tempdir;
	use mwc_wallet_util::mwc_util::ToHex;

	let directory = tempdir().unwrap();
	let mut requests = vec![serde_json::json!({
		"jsonrpc": "2.0", "method": "build_coinbase", "id": 1,
		"params": { "block_fees": { "fees": "13", "height": "3", "key_id": null } }
	})];
	// The wallet signs the supplied digest before and after activation. This
	// test exercises the actual RPC dispatch and response serialization.
	for height in [3u8, 4] {
		requests.push(serde_json::json!({
			"jsonrpc": "2.0", "method": "build_coinbase", "id": height,
			"params": { "block_fees": {
				"fees": "13", "height": height.to_string(), "key_id": null,
				"binding_digest": Hash::from_vec(&[height; 32]).to_hex()
			} }
		}));
	}
	let response = run_doctest_foreign(
		serde_json::Value::Array(requests),
		directory.path().to_str().unwrap(),
		false,
		0,
		false,
		false,
		true,
	)
	.unwrap()
	.unwrap();
	let responses = response.as_array().unwrap();
	assert_eq!(responses.len(), 3);
	let legacy = responses.iter().find(|item| item["id"] == 1).unwrap();
	assert_eq!(legacy["error"]["code"], -32602);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	for height in [3u8, 4] {
		let response = responses.iter().find(|item| item["id"] == height).unwrap();
		let coinbase: CbData = serde_json::from_value(response["result"]["Ok"].clone()).unwrap();
		assert!(coinbase.key_id.is_some());
		coinbase.kernel.verify(0, &secp).unwrap();
		verify_coinbase_binding_digest(
			0,
			&secp,
			&coinbase.kernel,
			&coinbase.coinbase_opening,
			Hash::from_vec(&[height; 32]),
		)
		.unwrap();
	}
}

#[cfg(feature = "test-support")]
fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), Error> {
	// TODO: Implement checks
	// return Err(Error::GenericError("Test Rejection".into()))?
	Ok(())
}

/// Helper to set up a real environment to run integrated doctests.
#[cfg(feature = "test-support")]
#[allow(
	clippy::unwrap_used,
	reason = "this function is an integration-doctest harness whose unwraps turn fixture setup failures into test failures"
)]
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
	compact_slate: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mwc::Handler;
	use mwc_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use mwc_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use mwc_wallet_libwallet::{api_impl, WalletInst};
	use mwc_wallet_util::mwc_core::global;
	use mwc_wallet_util::mwc_core::global::ChainTypes;
	use mwc_wallet_util::mwc_keychain::ExtKeychain;
	use mwc_wallet_util::mwc_util;

	use mwc_wallet_util::Mutex;
	use std::sync::Arc;

	use std::fs;

	mwc_util::init_test_logger().map_err(|e| e.to_string())?;
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(|e| e.to_string())?;
	if let Err(e) = fs::remove_dir_all(test_dir) {
		if e.kind() != std::io::ErrorKind::NotFound {
			return Err(format!(
				"Unable to clean doctest directory {}: {}",
				test_dir, e
			));
		}
	}
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).map_err(|e| e.to_string())?;
	global::set_local_nrd_enabled(true);

	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir.into(), tx_pool.clone());
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 = mwc_util::ZeroingString::from(
		"fat twenty mean degree forget shell check candy immense awful \
     flame next during february bulb bike sun wink theory day kiwi embrace peace lunch",
	);
	let empty_string = mwc_util::ZeroingString::from("");
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(
		0,
		client1.clone(),
	))
		as Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet1.lc_provider().unwrap();
	lc.set_top_level_directory(&format!("{}/wallet1", test_dir))
		.map_err(|e| e.to_string())?;
	drop(
		lc.create_wallet(
			None,
			Some(rec_phrase_1),
			32,
			empty_string.clone(),
			false,
			None,
			true,
		)
		.map_err(|e| e.to_string())?,
	);
	let mask1 = lc
		.open_wallet(&secp, None, empty_string.clone(), use_token, true, None)
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

	let rec_phrase_2 = mwc_util::ZeroingString::from(
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
     sell finish magic kid tiny wage stand panther inside settle feed song hole exile",
	);
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let mut wallet2 = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(
		0,
		client2.clone(),
	))
		as Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet2.lc_provider().unwrap();
	lc.set_top_level_directory(&format!("{}/wallet2", test_dir))
		.map_err(|e| e.to_string())?;
	drop(
		lc.create_wallet(
			None,
			Some(rec_phrase_2),
			32,
			empty_string.clone(),
			false,
			None,
			true,
		)
		.map_err(|e| e.to_string())?,
	);
	let mask2 = lc
		.open_wallet(&secp, None, empty_string, use_token, true, None)
		.unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	let proxy_handle = wallet_proxy.start();

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			1 as usize,
			false,
			tx_pool.lock().deref_mut(),
		)
		.map_err(|e| e.to_string())?;
		//update local outputs after each block, so transaction IDs stay consistent
		let (wallet_refreshed, _) = api_impl::owner::retrieve_summary_info(
			wallet1.clone(),
			&mut secp,
			(&mask1).as_ref(),
			true,
			1,
		)
		.unwrap();
		assert!(wallet_refreshed);
	}

	let (w1_tor_secret, w1_tor_pubkey) = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain(&secp, (&mask1).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&secp, 0, &k, 0).unwrap();
		let tor_pk = ed25519_dalek::VerifyingKey::from(&secret);
		(secret, tor_pk)
	};
	let w1_slatepack_address =
		ProvableAddress::from_tor_pub_key(&w1_tor_pubkey).map_err(|e| e.to_string())?;

	let (w2_tor_secret, w2_tor_pubkey) = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain(&secp, (&mask2).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&secp, 0, &k, 0).unwrap();
		let tor_pk = ed25519_dalek::VerifyingKey::from(&secret);
		(secret, tor_pk)
	};
	let w2_slatepack_address =
		ProvableAddress::from_tor_pub_key(&w2_tor_pubkey).map_err(|e| e.to_string())?;

	if init_invoice_tx {
		let amount = 2_000_000_000;
		let mut tx_session1 = TxSession::new();
		let mut tx_session2 = TxSession::new();
		let mut slate = {
			let mut w_lock = wallet2.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let mut args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};

			if compact_slate {
				// Address of this wallet. Self and encrypt to self is totally valid case
				args.slatepack_recipient = Some(w1_slatepack_address.clone());
			}

			let slate = api_impl::owner::issue_invoice_tx(
				&mut **w,
				&mut secp,
				(&mask2).as_ref(),
				Some(&mut tx_session1),
				&args,
				true,
				1,
			)
			.unwrap();

			tx_session1
				.save_tx_data(&secp, &mut **w, (&mask1).as_ref(), &slate.id)
				.unwrap();
			slate
		};
		if compact_slate {
			// Exercise the same InvoiceInitial transport as the real exchange.
			// It omits the issuer output until finalization, when the issuer
			// restores it and contributes its share of the transaction offset.
			slate = VersionedSlate::into_version(
				0,
				slate,
				SlateVersion::SP,
				SlatePurpose::InvoiceInitial,
				w2_tor_pubkey.clone(),
				Some(w1_tor_pubkey.clone()),
				&w2_tor_secret,
				true,
				&secp,
			)
			.unwrap()
			.into_slatepack(0, &w1_tor_secret, &secp)
			.unwrap()
			.to_result_slate();
		}
		{
			wallet_lock_test!(wallet1.clone(), w1);
			api_impl::owner::update_wallet_state(
				&mut **w1,
				&mut secp,
				(&mask1).as_ref(),
				None,
			)
			.unwrap();
		}
		slate = {
			let mut w_lock = wallet1.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			let slate = api_impl::owner::process_invoice_tx(
				&mut **w,
				&mut secp,
				(&mask1).as_ref(),
				&mut Some(&mut tx_session2),
				&slate,
				&args,
				true,
				true,
			)
			.unwrap();
			// participants ids are expected to be different
			tx_session2
				.save_tx_data(&secp, &mut **w, (&mask1).as_ref(), &slate.id)
				.unwrap();
			slate
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!(
			"{}",
			serde_json::to_string_pretty(&SlateCtx {
				slate: slate.clone(),
				network_name: Some(global::get_network_name(0)),
			})
			.unwrap()
		);
		if compact_slate {
			let vslate = VersionedSlate::into_version(
				0,
				slate,
				SlateVersion::SP,
				SlatePurpose::InvoiceResponse,
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
	}

	{
		wallet_lock_test!(wallet1.clone(), w1);
		api_impl::owner::update_wallet_state(
			&mut **w1,
			&mut secp,
			(&mask1).as_ref(),
			None,
		)
		.unwrap();
	}
	if init_tx {
		let amount = 2_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let mut args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};

		if compact_slate {
			// Address of this wallet. Self and encrypt to self is totally valid case
			args.slatepack_recipient = Some(w2_slatepack_address.clone());
		}

		let slate = api_impl::owner::init_send_tx(
			&mut **w,
			&mut secp,
			(&mask1).as_ref(),
			&mut None,
			&args,
			true,
			1,
		)
		.unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!(
			"{}",
			serde_json::to_string_pretty(&SlateCtx {
				slate: slate.clone(),
				network_name: Some(global::get_network_name(0)),
			})
			.unwrap()
		);

		if compact_slate {
			let vslate = VersionedSlate::into_version(
				0,
				slate,
				SlateVersion::SP,
				SlatePurpose::SendInitial,
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

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1, mask1, Some(test_check_middleware)),
		true => Foreign::new(wallet2, mask2, Some(test_check_middleware)),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	let res = foreign_api.handle_request(request).as_option();
	proxy_handle.stop().map_err(|e| e.to_string())?;
	drop(api_foreign);
	drop(chain);
	fs::remove_dir_all(test_dir)
		.map_err(|e| format!("Unable to remove doctest directory {}: {}", test_dir, e))?;
	Ok(res)
}
#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr, $compact_slate:expr) => {
		#[cfg(not(feature = "test-support"))]
		panic!("test-support feature is required to run the tests");

		#[cfg(feature = "test-support")]
		{
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use mwc_wallet_util::mwc_crates::serde_json::Value;
		use mwc_wallet_util::mwc_crates::tempfile::tempdir;
		use $crate::run_doctest_foreign;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();

		let request_val: Value =
			mwc_wallet_util::mwc_crates::serde_json::from_str($request).unwrap();
		let expected_response: Value =
			mwc_wallet_util::mwc_crates::serde_json::from_str($expected_response).unwrap();

		let response = run_doctest_foreign(
			request_val,
			dir,
			$use_token,
			$blocks_to_mine,
			$init_tx,
			$init_invoice_tx,
			$compact_slate,
		)
		.unwrap()
		.unwrap();

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				mwc_wallet_util::mwc_crates::serde_json::to_string_pretty(&response).unwrap(),
				mwc_wallet_util::mwc_crates::serde_json::to_string_pretty(&expected_response)
					.unwrap()
			);
		}
		}
	};
}

// placeholder for doc tests.
#[test]
fn foreign_api_v3_test() {
	// use crate as mwc_wallet_api;
}
