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

//! In-process wallet/node fixtures used by integration tests.
//!
//! This module is not used by the production HTTP node client. Where a helper
//! deliberately unwraps a fixture setup or local-chain result, failure means
//! the test topology or data is invalid and the test cannot continue
//! meaningfully. Those sites fail at the invariant violation instead of
//! imitating production recovery; production paths return their errors.

use mwc_wallet_libwallet;
use mwc_wallet_libwallet::api_impl::{foreign, owner};
use mwc_wallet_libwallet::types::TxSession;
use mwc_wallet_libwallet::wallet_lock;
use mwc_wallet_libwallet::{
	BlockFees, InitTxArgs, NodeClient, WalletInfo, WalletInst, WalletLCProvider,
};
use mwc_wallet_util::Mutex;
use mwc_wallet_util::mwc_api;
use mwc_wallet_util::mwc_api::BlockPrintable;
use mwc_wallet_util::mwc_chain;
use mwc_wallet_util::mwc_chain::Chain;
use mwc_wallet_util::mwc_core;
use mwc_wallet_util::mwc_core::core::{Output, Transaction, TxKernel};
use mwc_wallet_util::mwc_core::{consensus, global, pow};
use mwc_wallet_util::mwc_crates::chrono::Duration;
use mwc_wallet_util::mwc_crates::secp::key::SecretKey;
use mwc_wallet_util::mwc_crates::secp::pedersen;
use mwc_wallet_util::mwc_crates::secp::s2c::Opening;
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::Keychain;
use mwc_wallet_util::mwc_util::ToHex;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

mod testclient;

pub use self::{
	testclient::LocalWalletClient, testclient::WalletProxy, testclient::WalletProxyHandle,
};

/// Get an output from the chain locally and present it back as an API output
fn get_output_local(
	chain: &Chain,
	commit: pedersen::Commitment,
) -> Result<Option<mwc_api::Output>, mwc_chain::Error> {
	let Some((output, pos)) = chain.get_unspent(commit)? else {
		return Ok(None);
	};

	Ok(Some(mwc_api::Output::new(
		&output.commitment(),
		pos.height,
		pos.pos,
	)))
}

/// Get a kernel from the chain locally
fn get_kernel_local(
	chain: Arc<Chain>,
	excess: &pedersen::Commitment,
	min_height: Option<u64>,
	max_height: Option<u64>,
) -> Option<mwc_api::LocatedTxKernel> {
	chain
		.get_kernel_height(&excess, min_height, max_height)
		// Intentional test-framework fail-fast: a chain lookup error means the test
		// setup or local chain state is invalid and must not be reported as "not found".
		// Production node handlers propagate this Result instead.
		.unwrap()
		.map(|(tx_kernel, height, mmr_index)| mwc_api::LocatedTxKernel {
			tx_kernel,
			height,
			mmr_index,
		})
}

/// Get an output listing by traversing the local PMMR in the test framework.
///
/// This helper is used only by `LocalWalletClient`/`WalletProxy`, not by the
/// production node client. The `unwrap()` calls intentionally fail the test
/// immediately when its in-process chain cannot be read or formatted. It also
/// does not provide one snapshot across listing and formatting, so tests using
/// it must not mutate the chain concurrently; production code must use the
/// node API's coherent-snapshot implementation instead.
fn get_outputs_by_pmmr_index_local(
	chain: Arc<Chain>,
	start_index: u64,
	end_index: Option<u64>,
	max: u64,
) -> mwc_api::OutputListing {
	let outputs = chain
		.unspent_outputs_by_pmmr_index(start_index, max, end_index)
		.unwrap();
	mwc_api::OutputListing {
		last_retrieved_index: outputs.0,
		highest_index: outputs.1,
		outputs: outputs
			.2
			.iter()
			.map(|x| {
				mwc_api::OutputPrintable::from_output(x, &chain, None, true, false).unwrap()
			})
			.collect(),
	}
}

/// get output listing in a given block range
fn height_range_to_pmmr_indices_local(
	chain: Arc<Chain>,
	start_index: u64,
	end_index: Option<u64>,
) -> mwc_api::OutputListing {
	// This local test-framework helper intentionally fails fast: an invalid height
	// range or broken test chain is a test setup failure, not a production error
	// path. Keep the unwrap so tests abort at the source of the invalid fixture.
	let indices = chain
		.block_height_range_to_pmmr_indices(start_index, end_index)
		.unwrap();
	mwc_api::OutputListing {
		last_retrieved_index: indices.0,
		highest_index: indices.1,
		outputs: vec![],
	}
}

/// Get blocks by height from the in-process test chain.
///
/// This private helper is used only by `LocalWalletClient`/`WalletProxy`, not by
/// the production node client. Its unwraps deliberately fail the test when a
/// requested fixture block is absent, the local chain cannot be read, or a
/// validated block cannot be formatted. Turning those invariant failures into a
/// simulated node response would let the test continue past a broken fixture;
/// production node handlers instead return these failures as errors.
/// Each block is read independently, so tests must not mutate/reorg the fixture
/// chain concurrently while this helper is running.
fn get_blocks_by_height_local(
	chain: Arc<Chain>,
	start_index: u64,
	end_index: u64,
) -> Vec<BlockPrintable> {
	let mut res: Vec<BlockPrintable> = Vec::new();

	for height in start_index..=end_index {
		let header = chain
			.get_header_by_height(height)
			.unwrap();
		let block = chain.get_block_for_header(&header).unwrap();
		res.push(BlockPrintable::from_block(&block, &chain, true, false).unwrap());
	}
	res
}

/// Builds and mines a block for the in-process test framework.
///
/// `prev` must be a valid header from the same bounded test chain. This is not
/// a production block-building error boundary: fixture read failures deliberately
/// abort the test, and synthetic headers at numeric or timestamp limits are
/// outside this helper's contract.
fn create_block_with_reward(
	secp: &Secp256k1,
	context_id: u32,
	chain: &Chain,
	prev: mwc_core::core::BlockHeader,
	txs: &[Transaction],
	reward_output: Output,
	reward_kernel: TxKernel,
	coinbase_opening: Option<Opening>,
) -> Result<mwc_core::core::Block, mwc_chain::Error> {
	let mut cache_values = consensus::DifficultyCache::new();
	let next_header_info = consensus::next_difficulty(
		context_id,
		// Intentional test-fixture arithmetic: `prev` comes from the bounded
		// in-process chain and therefore cannot be at `u64::MAX`.
		prev.height + 1,
		// Intentional test-framework fail-fast: failure to construct the
		// difficulty iterator means the in-process test chain is not a valid
		// initialized fixture. Production mining paths propagate this error.
		chain.difficulty_iter().unwrap(),
		&mut cache_values,
	)
	.map_err(|e| mwc_chain::Error::Other(format!("Unable to calculate difficulty, {}", e)))?;
	let mut b = mwc_core::core::Block::new(
		context_id,
		&prev,
		txs,
		next_header_info.difficulty,
		(reward_output, reward_kernel),
		secp,
	)?;
	b.coinbase_opening = coinbase_opening;
	// Intentional test-fixture arithmetic: harness-created timestamps remain far
	// inside Chrono's range; an out-of-range value is an invalid synthetic fixture.
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.secondary_scaling = next_header_info.secondary_scaling;
	chain.set_txhashset_roots(secp, &mut b)?;
	pow::pow_size(
		context_id,
		&mut b.header,
		next_header_info.difficulty,
		global::proofsize(context_id),
		global::min_edge_bits(context_id),
	)?;
	Ok(b)
}

/// Adds a block with a given reward and its optional S2C opening to the chain and mines it
pub fn add_block_with_reward(
	context_id: u32,
	chain: &Chain,
	txs: &[Transaction],
	reward_output: Output,
	reward_kernel: TxKernel,
	coinbase_opening: Option<Opening>,
) -> Result<(), mwc_chain::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(mwc_chain::Error::Secp)?;
	// Intentional test-framework fail-fast: this helper requires an initialized,
	// readable in-process chain. A missing or unreadable head is a broken test
	// fixture and should abort the test immediately; production paths propagate it.
	let prev = chain.head_header().unwrap();
	let block = create_block_with_reward(
		&secp,
		context_id,
		chain,
		prev,
		txs,
		reward_output,
		reward_kernel,
		coinbase_opening,
	)?;
	process_block(chain, block)
}

/// adds a reward output to a wallet, includes that reward in a block
/// and return the block
///
/// This is a test-fixture helper, not a production block-building boundary.
/// `prev` must be a valid header from the same bounded in-process test chain;
/// untrusted or synthetic headers at numeric limits are outside its contract.
pub fn create_block_for_wallet<'a, L, C, K>(
	chain: &Chain,
	prev: mwc_core::core::BlockHeader,
	txs: &[Transaction],
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<mwc_core::core::Block, mwc_wallet_libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	// build block fees
	let fee_amt = txs.iter().try_fold(0u64, |acc, tx| {
		let fee = tx.fee()?;
		acc.checked_add(fee).ok_or_else(|| {
			mwc_wallet_libwallet::Error::DataOverflow(format!(
				"test_framework::create_block_for_wallet, transaction fee sum overflow, accumulated_fee={} transaction_fee={}",
				acc, fee
			))
		})
	})?;
	// Use the final cut-through input set and the actual parent state, just as
	// production mining does. Ordinary integration tests now cross activation.
	let (reward_output, reward_kernel, opening, context_id) = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let context_id = w.get_context_id();
		let aggregate = mwc_core::core::transaction::aggregate(context_id, txs, &secp)?;
		let binding = chain
			.coinbase_binding_for_template(&secp, &prev, &aggregate.body)
			.map_err(|e| mwc_wallet_libwallet::Error::GenericError(e.to_string()))?;
		let digest = binding.digest()?;
		let request = BlockFees {
			fees: fee_amt,
			height: prev.height + 1,
			key_id: None,
			binding_digest: digest.to_hex(),
		};
		let coinbase = foreign::build_coinbase(&mut **w, &mut secp, keychain_mask, &request)?;
		mwc_core::libtx::coinbase_binding::verify_coinbase_binding_digest(
			context_id,
			&secp,
			&coinbase.kernel,
			&coinbase.coinbase_opening,
			digest,
		)?;
		let opening = consensus::is_coinbase_binding_enabled(context_id, request.height)
			.then_some(coinbase.coinbase_opening);
		(coinbase.output, coinbase.kernel, opening, context_id)
	};
	let block = create_block_with_reward(
		&secp,
		context_id,
		chain,
		prev,
		txs,
		reward_output,
		reward_kernel,
		opening,
	)
	.map_err(|e| {
		mwc_wallet_libwallet::Error::GenericError(format!("Unable to create block, {}", e))
	})?;
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
) -> Result<(), mwc_wallet_libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Intentional test-framework fail-fast: awarding a block requires a readable
	// head on the initialized in-process chain. Without it there is no valid
	// fixture state on which this helper can continue.
	let prev = chain.head_header().unwrap();
	let block = create_block_for_wallet(chain, prev, txs, wallet, keychain_mask)?;
	process_block(chain, block).map_err(|e| {
		mwc_wallet_libwallet::Error::GenericError(format!("Unable to process block, {}", e))
	})?;
	Ok(())
}

pub fn process_block(chain: &Chain, block: mwc_core::core::Block) -> Result<(), mwc_chain::Error> {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(mwc_chain::Error::Secp)?;
	chain.process_block(&mut secp, block, mwc_chain::Options::MINE, HashSet::new())?;
	chain.validate(&secp, false)?;
	Ok(())
}

/// Award a blocks to a wallet directly
pub fn award_blocks_to_wallet<'a, L, C, K>(
	chain: &Chain,
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
	number: usize,
	pause_between: bool,
	tx_pool: &mut Vec<Transaction>,
) -> Result<(), mwc_wallet_libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
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

/// Send an amount to a destination in wallet integration tests.
///
/// This helper is compiled only with the `test-support` feature and communicates
/// with a trusted, in-process [`LocalWalletClient`] test proxy. The proxy is
/// assumed to return the response for the slate it was just given, and the test
/// fixtures are assumed to be small enough to persist. Consequently, this helper
/// intentionally does not duplicate the production send path's response-identity
/// and pre-post transaction-log-size checks. It must not be used to send real
/// funds or communicate with an untrusted destination; production callers must
/// use the normal wallet API send workflow and its validation safeguards.
pub fn send_to_dest<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	client: LocalWalletClient,
	dest: &str,
	amount: u64,
	#[cfg(feature = "test-support")] test_mode: bool,
	outputs: Option<HashSet<String>>, // outputs to include into the transaction
	routputs: usize,                  // Number of resulting outputs. Normally it is 1
) -> Result<(), mwc_wallet_libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut tx_session = TxSession::new();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let (slate, client, context_id) = {
		wallet_lock!(wallet, w);
		// A successful refresh can still report an unvalidated wallet state.
		let (validated, _) = owner::update_wallet_state(&mut **w, &mut secp, keychain_mask, None)?;
		if !validated {
			return Err(mwc_wallet_libwallet::Error::GenericError(
				"Unable to validate wallet state against the node, cannot send transaction"
					.to_string(),
			));
		}

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
				&mut secp,
				keychain_mask,
				&mut Some(&mut tx_session),
				&args,
				#[cfg(feature = "test-support")]
				test_mode,
				routputs,
			)?;
			let slate = client.send_tx_slate_direct(dest, &slate_i)?;
			owner::tx_lock_outputs(
				&mut **w,
				&mut secp,
				keychain_mask,
				&mut Some(&mut tx_session),
				&slate,
				Some(String::from(dest)),
				0,
				#[cfg(feature = "test-support")]
				true,
			)?;
			let (slate, _) = owner::finalize_tx(
				&mut **w,
				&mut secp,
				keychain_mask,
				&mut Some(&mut tx_session),
				&slate,
				false,
				#[cfg(feature = "test-support")]
				true,
				true,
			)?;
			slate
		};
		let client = { w.w2n_client().clone() };
		(slate, client, w.get_context_id())
	};
	owner::post_tx(context_id, &client, slate.tx_or_err()?, false)?; // mines a block

	{
		debug_assert!(tx_session.get_context_participant().is_none());
		wallet_lock!(wallet, w);
		tx_session.save_tx_data(&secp, &mut **w, keychain_mask, &slate.id)?;
	}
	Ok(())
}

/// get wallet info totals
pub fn wallet_info<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<WalletInfo, mwc_wallet_libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	let (wallet_refreshed, wallet_info) =
		owner::retrieve_summary_info(wallet, &mut secp, keychain_mask, true, 1)?;
	if !wallet_refreshed {
		return Err(mwc_wallet_libwallet::Error::GenericError(
			"Unable to validate wallet state against the node, cannot retrieve wallet info"
				.to_string(),
		));
	}
	Ok(wallet_info)
}
