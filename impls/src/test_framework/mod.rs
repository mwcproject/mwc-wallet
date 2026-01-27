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

use crate::api;
use crate::api::BlockPrintable;
use crate::chain;
use crate::chain::Chain;
use crate::core;
use crate::core::core::hash::Hashed;
use crate::core::core::{Output, Transaction, TxKernel};
use crate::core::{consensus, global, pow};
use crate::keychain;
use crate::libwallet;
use crate::libwallet::api_impl::{foreign, owner};
use crate::libwallet::{
	BlockFees, InitTxArgs, NodeClient, WalletInfo, WalletInst, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::secp::pedersen;
use chrono::Duration;
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_util::mwc_core::consensus::HeaderDifficultyInfo;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

mod testclient;

pub use self::{testclient::LocalWalletClient, testclient::WalletProxy};

/// Get an output from the chain locally and present it back as an API output
fn get_output_local(chain: &chain::Chain, commit: pedersen::Commitment) -> Option<api::Output> {
	if chain.get_unspent(commit).unwrap().is_some() {
		let block_height = chain.get_header_for_output(commit).unwrap().height;
		let output_pos = chain.get_output_pos(&commit).unwrap_or(0);
		Some(api::Output::new(&commit, block_height, output_pos))
	} else {
		None
	}
}

/// Get a kernel from the chain locally
fn get_kernel_local(
	chain: Arc<chain::Chain>,
	excess: &pedersen::Commitment,
	min_height: Option<u64>,
	max_height: Option<u64>,
) -> Option<api::LocatedTxKernel> {
	chain
		.get_kernel_height(&excess, min_height, max_height)
		.unwrap()
		.map(|(tx_kernel, height, mmr_index)| api::LocatedTxKernel {
			tx_kernel,
			height,
			mmr_index,
		})
}

/// get output listing traversing pmmr from local
fn get_outputs_by_pmmr_index_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	end_index: Option<u64>,
	max: u64,
) -> api::OutputListing {
	let outputs = chain
		.unspent_outputs_by_pmmr_index(start_index, max, end_index)
		.unwrap();
	api::OutputListing {
		last_retrieved_index: outputs.0,
		highest_index: outputs.1,
		outputs: outputs
			.2
			.iter()
			.map(|x| api::OutputPrintable::from_output(x, &chain, None, true, false).unwrap())
			.collect(),
	}
}

/// get output listing in a given block range
fn height_range_to_pmmr_indices_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	end_index: Option<u64>,
) -> api::OutputListing {
	let indices = chain
		.block_height_range_to_pmmr_indices(start_index, end_index)
		.unwrap();
	api::OutputListing {
		last_retrieved_index: indices.0,
		highest_index: indices.1,
		outputs: vec![],
	}
}

/// Get blocks by heights
fn get_blocks_by_height_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	end_index: u64,
) -> Vec<BlockPrintable> {
	let mut res: Vec<BlockPrintable> = Vec::new();

	for height in start_index..=end_index {
		let hash = chain.get_header_by_height(height).unwrap().hash().unwrap();
		let block = chain.get_block(&hash).unwrap();
		res.push(BlockPrintable::from_block(&block, &chain, true, false).unwrap());
	}
	res
}

fn create_block_with_reward(
	context_id: u32,
	chain: &Chain,
	prev: core::core::BlockHeader,
	txs: &[Transaction],
	reward_output: Output,
	reward_kernel: TxKernel,
) -> core::core::Block {
	let mut cache_values: VecDeque<HeaderDifficultyInfo> = VecDeque::new();
	let next_header_info = consensus::next_difficulty(
		context_id,
		prev.height + 1,
		chain.difficulty_iter().unwrap(),
		&mut cache_values,
	);
	let mut b = core::core::Block::new(
		context_id,
		&prev,
		txs,
		next_header_info.clone().difficulty,
		(reward_output, reward_kernel),
		chain.secp(),
	)
	.unwrap();
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.secondary_scaling = next_header_info.secondary_scaling;
	chain.set_txhashset_roots(&mut b).unwrap();
	pow::pow_size(
		context_id,
		&mut b.header,
		next_header_info.difficulty,
		global::proofsize(context_id),
		global::min_edge_bits(context_id),
	)
	.unwrap();
	b
}

/// Adds a block with a given reward to the chain and mines it
pub fn add_block_with_reward(
	context_id: u32,
	chain: &Chain,
	txs: &[Transaction],
	reward_output: Output,
	reward_kernel: TxKernel,
) {
	let prev = chain.head_header().unwrap();
	let block =
		create_block_with_reward(context_id, chain, prev, txs, reward_output, reward_kernel);
	process_block(chain, block);
}

/// adds a reward output to a wallet, includes that reward in a block
/// and return the block
pub fn create_block_for_wallet<'a, L, C, K>(
	chain: &Chain,
	prev: core::core::BlockHeader,
	txs: &[Transaction],
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<core::core::Block, libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	// build block fees
	let fee_amt = txs.iter().map(|tx| tx.fee()).sum();
	let block_fees = BlockFees {
		fees: fee_amt,
		key_id: None,
		height: prev.height + 1,
	};
	// build coinbase (via api) and add block
	let (coinbase_tx, context_id) = {
		let mut w_lock = wallet.lock().unwrap_or_else(|e| e.into_inner());
		let w = w_lock.lc_provider()?.wallet_inst()?;
		(
			foreign::build_coinbase(&mut **w, keychain_mask, &block_fees, false)?,
			w.get_context_id(),
		)
	};
	let block = create_block_with_reward(
		context_id,
		chain,
		prev,
		txs,
		coinbase_tx.output,
		coinbase_tx.kernel,
	);
	Ok(block)
}

/// adds a reward output to a wallet, includes that reward in a block, mines
/// the block and adds it to the chain, with option transactions included.
/// Helpful for building up precise wallet balances for testing.
pub fn award_block_to_wallet<'a, L, C, K>(
	chain: &Chain,
	txs: &[Transaction],
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let prev = chain.head_header().unwrap();
	let block = create_block_for_wallet(chain, prev, txs, wallet, keychain_mask)?;
	process_block(chain, block);
	Ok(())
}

pub fn process_block(chain: &Chain, block: core::core::Block) {
	chain.process_block(block, chain::Options::MINE).unwrap();
	chain.validate(false).unwrap();
}

/// Award a blocks to a wallet directly
pub fn award_blocks_to_wallet<'a, L, C, K>(
	chain: &Chain,
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
	number: usize,
	pause_between: bool,
	tx_pool: &mut Vec<Transaction>,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	for _ in 0..number {
		award_block_to_wallet(chain, &tx_pool, wallet.clone(), keychain_mask)?;
		tx_pool.clear();
		if pause_between {
			thread::sleep(std::time::Duration::from_millis(100));
		}
	}
	Ok(())
}

/// send an amount to a destination
pub fn send_to_dest<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	client: LocalWalletClient,
	dest: &str,
	amount: u64,
	test_mode: bool,
	outputs: Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                  // Number of resulting outputs. Normally it is 1
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let mut tx_session = TxSession::new();
	let (slate, client) = {
		wallet_lock!(wallet, w);
		// Caller need to update the wallet first
		owner::update_wallet_state(&mut **w, keychain_mask, &None)?;

		let slate = {
			let args = InitTxArgs {
				src_acct_name: None,
				amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				outputs,
				..Default::default()
			};
			let slate_i = owner::init_send_tx(
				&mut **w,
				keychain_mask,
				&mut Some(&mut tx_session),
				&args,
				test_mode,
				routputs,
			)?;
			let slate = client.send_tx_slate_direct(dest, &slate_i)?;
			owner::tx_lock_outputs(
				&mut **w,
				keychain_mask,
				&mut Some(&mut tx_session),
				&slate,
				Some(String::from(dest)),
				0,
				true,
			)?;
			let (slate, _) = owner::finalize_tx(
				&mut **w,
				keychain_mask,
				&mut Some(&mut tx_session),
				&slate,
				false,
				true,
				true,
			)?;
			slate
		};
		let client = { w.w2n_client().clone() };
		(slate, client)
	};
	owner::post_tx(&client, slate.tx_or_err()?, false)?; // mines a block

	{
		debug_assert!(tx_session.get_context_participant().is_none());
		wallet_lock!(wallet, w);
		tx_session.save_tx_data(&mut **w, keychain_mask, &slate.id)?;
	}
	Ok(())
}

/// get wallet info totals
pub fn wallet_info<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<WalletInfo, libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let (wallet_refreshed, wallet_info) =
		owner::retrieve_summary_info(wallet, keychain_mask, &None, true, 1)?;
	assert!(wallet_refreshed);
	Ok(wallet_info)
}
