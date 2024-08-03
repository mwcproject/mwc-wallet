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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	self, BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeVersionInfo, Slate, SlateVersion, VersionInfo, VersionedCoinbase, VersionedSlate,
	WalletLCProvider,
};
use crate::{Foreign, ForeignCheckMiddlewareFn};
use easy_jsonrpc_mw;
use ed25519_dalek::PublicKey as DalekPublicKey;
use grin_wallet_libwallet::proof::proofaddress::{self, ProvableAddress};
use libwallet::slatepack::SlatePurpose;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `mwc-wallet listen` with defaults, the V2 api is available at
/// `localhost:3415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	fn get_proof_address(&self) -> Result<String, ErrorKind>;

	/**
	Networked Legacy (non-secure token) version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
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
		  "kernel": {
			"excess": "095987fa1274901ab624386e9f76b39c6c27a6f5d11782bb06e3a55361d925e418",
			"excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b49e2040e02da3d79a3bd694d522754f118a064d62f076e87a161059222141c2c",
			"features": "Coinbase",
			"fee": "0",
			"lock_height": "0"
		  },
		  "key_id": "0300000000000000000000000400000000",
		  "output": {
			"commit": "08f9451ff0b17a7d3b905efacc1b51ded6a77dc17aedd4959d46f6509c3298b8c7",
			"features": "Coinbase",
			"proof": "d00084fe7929cd897b3b6cc28b7e8c9bee8ccccae3189ea0713f90a10e2a8011f5cb0fd1d5ea057c126485a66002a0a283238dd2157bb6747f77202701a1350104e35c2aed5f79ab73e0195d39a320d95dd5fb2294eb2093f4495377d51a74e94b9972431d5159e7c5ac90ed2278deae16c485dba52356e7ee08e08574b37a2e1c1e276ea5d0b8ec07408b1cae285c5c3bbdd123c5a17ee971979f86a0b70b9e404292b97f75fd336b7f510deeed9b6465a48a346f48f9529a1b38b46b99976ed96c0e92ac35ab75bff2afda5ff0f7ad865dd20c17ed7940c4a162e7d83d04becc4075dde76d791ccf9a09b924e7edcf01355260c3e26e23cb88cb49e5b2a38a008eb584dac92635bcc6d6bfaa6bda233d965f8cb8d688cfb7f2c9bd4f2a298b95ac906ef4878ad4bc6a1a71c18e60bac79566031bbba89f62b8890f393787bd9197924d21e14e21936da721fbf0c50c4eef71c3f9fe6041ab07159770ca322afaf903397097bb4054b54069006799847db18415736cd931aced1f2320769c32ed2e1bce06ed3b3ccc002b026abf9e1771cf10f7759922ce4a2cfae3ce8d83ee3fcb8e065a80db6f465562034aac2ce91defe82a3c9e4104c00c565403deab54256f5d01cc63518fba667e23d1c417a82310264724315890fe0455134ed00a702dcf06832edc6b81dab03f611e95486f2cf4139b0ea777081f19b037c356902d44afcd06f5bf5a86ec5b09b138b384c4119e101c0d6f7d2119691ce8b15642bb90fc13a617731d55022d5749baa19283c638b25c451070c21a7adeff73f4710d59f2422869c3bcc01e981483c57c2092f2b5ae014f6737a51ab90c770623a7154d619342ccda0d888fd7721231c6d1bbd56fbd5053d93c15e7cc0758b82edf343ff874e69e2dc6af6c4b16321f6ce9fb386ff042c62af965e8c37e65fd619e7d74c3a4"
		  }
		}
	  }
	}
	# "#
	# ,false, 4, false, false, true);
	```
	*/

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
				  "proof": "dd695dd3a1000fd7805d5e3ee1df3b3221bb749b60685758cfbc33259e3cf861792dcb02a7b340d29ccb5bb4ddc99d1686874960b02856b882fc3e336226194a0cd15b5760f04172ff268e438d6e29507f23bd1f3180de974cd63b957d654ae08fbc804964d58fe0a71c2f31ecba86bd6c8eef37cddc9382471015114ac1d91132d2e78712e740682b2c7140c6a3b97fc1b93b38d90ebd0e74760f84dc6d9e44e36e9806189c65a2ce4c8257983ca255952f1ba66e24312d4b34498f91b4218adf6e43c25ff9eec1fa7ce457004f1e7df12d28a2d8d6395cdcb97387c2fd51e133953e73e2124cdec100abfa25d0210bdf2bbd6d389ababfe2a930c8973cd1f3ba767b25aec4586540fa73081e385247af8834cf8172a3e2a5de55eb1afa363cf5abd26f1a7317600fb80f742a7e8e87a93bcc5c59e1c106cb7af5cb76d9d00a9b4d77aff325db73c87594d970e7654fd8b95b0dcf9c09c314608b3f8719634e6705013560e2478facbc35478d26a109eaecafd478c934dbdb3663c094126c4b4da77e1ab509bc160253e30175774b501aba223cda549f3d4680ab047320687638e17399901da27932b198eb96c8756446f295f1d625ac63c03119ad9261f492a5ebdbece1d9c15fd769778cd71c3cc99574ad9e903c4cd312c8af6830d624b524d7f398e301ade464e42e5facc1d628c65829b826cf461578cf890d4e3f68e3f3fcbae74794b44f9b2e9491dcc6ea6626107d3e8629c73657f606d8776150798d028849c66a91c4a3ce5fbe43fcf75d2a381ebd5ad9a7b9c8662ba46e8a27c1fcba89c8fa6beecdb7b918772db69c241c54c7ba70b92a919ba90d8318266b246fd1d5432367b1d5085b4e7419c814300a9dd7ccc7dfe6d5e6262d11f18ef0ae7b328a0ab1c8e02392e3a1d905bb069621a6ecf81950d16a9cb3b04ff6ee8b5546caa8"
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
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
			"receiver_address": "xmgceW7Z2phenRwaBeKvTRZkPMJarwLFa8h5LW5bdHKucaKTeuE2",
			"receiver_signature": "3045022100ce8823c1824ffb8cc4f600541f6d043c11ce3558bb53bab86a01f75702c36a4602207c4fb147c1683a5148f2bb84074bb8f2ff980aa88089bde0e29150f528086bfa",
			"sender_address": "xmgwbyjMEMBojnVadEkwVi1GyL1WPiVE5dziQf3TLedHdrVBPGw5"
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
				  "proof": "ef998812683edb4f1a0db39374cf22da6f9163f39eca5765ffd20857044df8b0681701581dce5146ee3e36c663c330e3095ee9461c1684b5268772385ff78b84090f54b0d5d2b312ce08e03c5694b6556020c26bf9d82cc48f1192051046c6d1cf4166f75ca0f561672befe8b5d0ca4be6b9a3fab1177ef003fa20f9a53df2ae635d0241cccb5c7d366a0dc75f0cacad2bcfd057161320fbf4c95de2e3238b730c55d5ec31bac85e5ede7c8caddb1db8cb73e2d3f275508e141b9f4413015305198e8d7483fed3be1f692d41c70aab7537822ecbc25aff17ad40c2301ca7a272d427ac0e8d237ff73c3226c1b4d2b7c287c3850683af0d519dd5da7c9fc23dea940ef48e185fbf65eb9ee5b4295de493f741fabf36c447de5551b791664c15688d64048ddb081d391e181e7b6377f3c7349fb9dea631f54d9ad0fdd4844bc3b1a1e5b4582ac4d802ee043989020e1e62b2b698a42ade36cb023bb0dd05936f2f41bc010cb5633c9856e1136a6f60f6ac2205b0e549a061d6c56c17d012ebb8fea7062e01b10931b1c250b8c3a4984ee8f9b3ca732250a5419b6a830519d0583fb5511495c6a64e5e2a6e3fa0aeb91094d8beb76ac78f9ab9059ab79c8aa96ff88249ba6a63f351bfe3458038c1979e4cab7b971ce510f410770f17904fbb20de7ca9a7f719680945476b47eefbb9057e8209866f1c60e0dbc190a4449f0b4f19fd096636e1ad9370b4e49867396c0a2e8cb17c5cf103895d0a60b843680fedf4be083e05e838245191db0965a0ab3a621c0708bb1300562c5695e39607deb28ea7cf6ff62ee381e586c58ce1dfabec5fa14a6df8ef5b6de324d01b530ff10e746ef8cae9687f6eb480e735a2c7c568c94b5b9dbe80220dd5ccf164287a957a777b65006c14e17f908deff9565dec15249e2097c02e49e20cdfaeb3d47f00f8838c6180"
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
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
		"Ok": "BEGINSLATEPACK. 8aGE2J78VABJ3Pq ct4SvrqjjLSiNVv uCyzW51GAwQKCjN 4zufsY9VK63rjsy qr89amJHmVVmQh6 eKihPoAYiEbojc2 WXr8dAA519JFdQP WNqBzcHN3xnBcPa wsgqYnmxyvRXyaf FGQeV8ekqVKYDGh YH21bGQY3mVAsBw M9cQgLVu1Dqt5Ry Kbdqk9jB6euHPgr fC8aENHKaCQFG8z a2ntSBMHhe1r4vf CBgJSYvbATaJUUY q9gPq5bJyfNC6mU qxb4F2To1ZTJhLa p89tSxcPHtX8z2g uuG7WsGKNLh44w7 qCRMRe8cHgmYjxj ZPD8m6i9hJrJRn6 1C4jBqFnJx8FmPy u2W5Zs4F1kepk9c SFwX9UFkNSTYwn2 R64RejC2Eobogs7 CH2Dq3SZXC2kG43 Ri3hTLVYJzATHSV td9bz8rE92gteLA joxoUVGe1T2rVq6 6CJCbMyS9NJdGBx iNGbg7h5mmV1fUT aH6nXDHjznMFmZo PwES2Htv7RALrVS v4ndYjboZMVZ76F Yu9usuEt2FbpXpq rm3JELYBWjLHzgP mAKsWAsfFnApdMh FoKfo9ppM4rjnpq uZqeoDpwjB6kcBU vYN2GZvjUZdzUZ6 BMaBa6yCPngch77 FuH4yuidd3paaEM eUrnk55DgwMuerp 3iqbDfENqm1aKjr wkbg1tyFqgWykpA BzpgckaseAMqDr5 mdNETY45gKPDkni E41UvPp9J52BBEm ZGMRtt78gYhWNBL vp45NDNzzXirV7f f5kQeyTLNhV4oqn cDqemVsdyP3sRpT oWD18EGyLn4Wg5P V2hXpt3NLqfzozs gT9WMC3hw2Xb6pU Faxufmstx7bEKFD sH5ridXjfmof8oc H7pdedtzYSYeVKN UyLUMhhEbw9GVZN JNjzCbQV586Q968 ro91AeCWS5zDACR B4971ynhb6zUQQp mZRKDRuRsRurgbB AFXqwz3JSAK6TP4 7GhLsBSB4QW3az9 HrYsdcw72nXhUvo ndAQw6qb2yB9o5L MBy18qrwYMm9xWo Bhj9i2tZMNtCkXP CpHiTSeVkVTuApN oscmgyraWhbDhoj Sw4s4A3EWzQJ2dB VMPhZsRPVYZFcpH tE56dSnxQghzBMC soxJeqn3o6JnZX7 ABeVqSCUZEJ34Nx F88DrCgmGSGCfiR mK9GfwSbHyCW9Gd Ljm58xgVKRrRSfa ei7VbS2kqnLCihQ bwZ7xJQyVzVYcKX E2EAtap7uV5YqhN fzFtZi1hVne5KqG rhiSgooMeuSDBVK QxDEzTdonj2pex3 3DXzC54j8ndfAh8 TK8L59j4PeMHmvb DWK8PEvWmQgKmFV pebK7G19z5nnbym NQeoUTfLTA53bKM kpRbqe9UhRMcSDQ wKfj4D64epNxqv1 48BckGU6gi1eKyb 7U9dinqNhtgSe4v GWtcT3ntevCcgU1 Mfxxg6p3mzTEZAF KKHdtSZ7BeDaU5T LZNXsY588UkwfG2 uY94ZLEgYgwHb6r LwWReKDFnwSwhrs xxepjEnpUX2fiPb hoad1aMokXTGtGR UFcmigyraMUM4xW 2wFmeCxpSGmdz7X ESuErLmgH2YSZEX WBNMzhHLoXWoP5E s. ENDSLATEPACK."
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
	) -> Result<VersionedSlate, ErrorKind>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	fn finalize_invoice_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Foreign::receive_swap_message](struct.Foreign.html#method.receive_swap_message).

	# Json rpc example
	*/
	fn receive_swap_message(&self, message: String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Foreign::marketplace_message](struct.Foreign.html#method.marketplace_message).
	# Json rpc example
	*/
	fn marketplace_message(&self, accept_offer_message: &String) -> Result<String, ErrorKind>;
}

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn get_proof_address(&self) -> Result<String, ErrorKind> {
		Foreign::get_proof_address(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind> {
		let cb: CbData = Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())?;
		Ok(VersionedCoinbase::into_version(cb, SlateVersion::V2))
	}

	// verify_slate_messages doesn't make sense for the slate pack. That is why supporting only plain slates
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(
			self,
			&slate.into_slate_plain().map_err(|e| {
				ErrorKind::Compatibility(format!("Expected non ecrypted slate only, {}", e))
			})?,
		)
		.map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let (slate_from, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender) =
				Foreign::decrypt_slate(self, in_slate).map_err(|e| {
					ErrorKind::SlatepackDecodeError(format!("Unable to decrypt a slatepack, {}", e))
				})?;

			if content != SlatePurpose::SendInitial {
				return Err(ErrorKind::SlatepackDecodeError(format!(
					"Expecting SendInitial content of the slatepack, get {:?}",
					content
				)));
			}

			(slate_from, sender)
		} else {
			let slate_from = in_slate.into_slate_plain().map_err(|e| e.kind())?;
			(slate_from, None)
		};
		let out_slate = Foreign::receive_tx(
			self,
			&slate_from,
			sender.map(|p| ProvableAddress::from_tor_pub_key(&p).public_key), // We don't want to change RPC. New fields required new version
			dest_acct_name.as_ref().map(String::as_str),
			message,
			true,
		)
		.map_err(|e| e.kind())?;

		let res_slate = Foreign::encrypt_slate(
			self,
			&out_slate,
			Some(version),
			SlatePurpose::SendResponse,
			sender, // sending back to the sender
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			ErrorKind::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;

		Ok(res_slate)
	}

	fn finalize_invoice_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let (in_slate, sender) = if in_slate.is_slatepack() {
			let (slate_from, content, sender) =
				Foreign::decrypt_slate(self, in_slate).map_err(|e| {
					ErrorKind::SlatepackDecodeError(format!("Unable to decrypt a slatepack, {}", e))
				})?;

			if content != SlatePurpose::InvoiceResponse {
				return Err(ErrorKind::SlatepackDecodeError(format!(
					"Expecting InvoiceResponse content of the slatepack, get {:?}",
					content
				)));
			}

			(slate_from, sender)
		} else {
			let slate_from = in_slate.into_slate_plain().map_err(|e| e.kind())?;
			(slate_from, None)
		};

		let out_slate = Foreign::finalize_invoice_tx(self, &in_slate).map_err(|e| e.kind())?;

		let res_slate = Foreign::encrypt_slate(
			self,
			&out_slate,
			Some(version),
			SlatePurpose::FullSlate,
			sender, // sending back to the sender
			None,
			self.doctest_mode,
		)
		.map_err(|e| {
			ErrorKind::SlatepackEncodeError(format!("Unable to encode the slatepack, {}", e))
		})?;
		Ok(res_slate)
	}

	fn receive_swap_message(&self, message: String) -> Result<(), ErrorKind> {
		Foreign::receive_swap_message(&self, &message).map_err(|e| {
			ErrorKind::SwapError(format!("Error encountered receiving swap message, {}", e))
		})?;
		Ok(())
	}

	fn marketplace_message(&self, message: &String) -> Result<String, ErrorKind> {
		let res = Foreign::marketplace_message(&self, &message).map_err(|e| {
			ErrorKind::SwapError(format!("Error encountered receiving swap message, {}", e))
		})?;
		Ok(res)
	}
}

fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	// TODO: Implement checks
	// return Err(ErrorKind::GenericError("Test Rejection".into()))?
	Ok(())
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
	compact_slate: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_wallet_util::grin_util as util;

	use std::sync::Arc;
	use util::Mutex;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

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
		None,
	)
	.unwrap();
	let mask2 = lc
		.open_wallet(None, empty_string, use_token, true, None)
		.unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
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

	let (w1_tor_secret, w1_tor_pubkey) = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain((&mask1).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&k, None).unwrap();
		let tor_pk = DalekPublicKey::from(&secret);
		(secret, tor_pk)
	};
	let w1_slatepack_address = ProvableAddress::from_tor_pub_key(&w1_tor_pubkey);

	let (w2_tor_secret, w2_tor_pubkey) = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let k = w.keychain((&mask2).as_ref()).unwrap();
		let secret = proofaddress::payment_proof_address_dalek_secret(&k, None).unwrap();
		let tor_pk = DalekPublicKey::from(&secret);
		(secret, tor_pk)
	};
	let w2_slatepack_address = ProvableAddress::from_tor_pub_key(&w2_tor_pubkey);

	if init_invoice_tx {
		let amount = 2_000_000_000;
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

			api_impl::owner::issue_invoice_tx(&mut **w, (&mask2).as_ref(), &args, true, 1, true)
				.unwrap()
		};
		api_impl::owner::update_wallet_state(wallet1.clone(), (&mask1).as_ref(), &None).unwrap();
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
			api_impl::owner::process_invoice_tx(
				&mut **w,
				(&mask1).as_ref(),
				&slate,
				&args,
				true,
				true,
			)
			.unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());

		if compact_slate {
			let vslate = VersionedSlate::into_version(
				slate,
				SlateVersion::SP,
				SlatePurpose::InvoiceResponse,
				w1_tor_pubkey.clone(),
				Some(w2_tor_pubkey.clone()),
				&w1_tor_secret,
				true,
			)
			.unwrap();
			println!(
				"Slatepack: {}",
				serde_json::to_string_pretty(&vslate).unwrap()
			);
		}
	}

	api_impl::owner::update_wallet_state(wallet1.clone(), (&mask1).as_ref(), &None).unwrap();
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

		let slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), &args, true, 1).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());

		if compact_slate {
			let vslate = VersionedSlate::into_version(
				slate,
				SlateVersion::SP,
				SlatePurpose::SendInitial,
				w2_tor_pubkey.clone(),
				Some(w1_tor_pubkey.clone()),
				&w2_tor_secret,
				true,
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
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr, $compact_slate:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest_foreign;
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
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
			);
		}
	};
}

// placeholder for doc tests.
#[test]
fn foreign_api_v3_test() {
	// use crate as grin_wallet_api;
}
