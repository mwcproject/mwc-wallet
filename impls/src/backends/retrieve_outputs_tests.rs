// Copyright 2026 The Mwc Developers
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

use super::{
	LMDBBackend, TX_ARCHIVE_LOG_ENTRY_PREFIX,
	tests::{TestWalletDir, test_wallet},
};
use crate::node_clients::HTTPNodeClient;
use mwc_wallet_libwallet::internal::updater;
use mwc_wallet_libwallet::{
	Error, OutputCommitMapping, OutputData, OutputStatus, TxLogEntry, TxLogEntryType, WalletBackend,
};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_keychain::{ExtKeychain, Keychain};
use mwc_wallet_util::mwc_store::to_key_u64;

struct Fixture {
	wallet: LMDBBackend<'static, HTTPNodeClient, ExtKeychain>,
	secp: Secp256k1,
	_directory: TestWalletDir,
}

impl Fixture {
	fn new() -> Result<Self, Error> {
		let directory = TestWalletDir::new()?;
		let mut wallet = test_wallet(&directory)?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let keychain = ExtKeychain::from_seed(&secp, &[9u8; 32], false)?;
		wallet.set_keychain(
			&secp,
			Box::new(keychain),
			false,
			#[cfg(feature = "test-support")]
			false,
		)?;
		Ok(Self {
			wallet,
			secp,
			_directory: directory,
		})
	}

	fn output(&self, status: OutputStatus, tx_id: u32) -> Result<OutputData, Error> {
		Ok(OutputData {
			root_key_id: self.wallet.parent_key_id(),
			key_id: ExtKeychain::derive_key_id(3, 0, 0, tx_id, 0)?,
			n_child: tx_id,
			commit: None,
			mmr_index: None,
			value: 50,
			status,
			height: 0,
			lock_height: 0,
			is_coinbase: false,
			tx_log_entry: Some(tx_id),
		})
	}

	fn retrieve(
		&mut self,
		show_spent: bool,
		tx: Option<&TxLogEntry>,
	) -> Result<Vec<OutputCommitMapping>, Error> {
		let parent = self.wallet.parent_key_id();
		updater::retrieve_outputs(
			&mut self.wallet,
			&self.secp,
			None,
			show_spent,
			tx,
			&parent,
			None,
			None,
		)
	}
}

#[test]
fn cancelled_outputs_remain_hidden_after_archival() -> Result<(), Error> {
	for (status, cancelled_type) in [
		(
			OutputStatus::Unconfirmed,
			TxLogEntryType::TxReceivedCancelled,
		),
		(OutputStatus::Reverted, TxLogEntryType::TxSentCancelled),
	] {
		let mut fixture = Fixture::new()?;
		let parent = fixture.wallet.parent_key_id();
		let output = fixture.output(status, 7)?;
		let mut tx = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceived, 7);
		{
			let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
			batch.save(output.clone())?;
			batch.save_tx_log_entry(tx.clone(), &parent)?;
			batch.commit()?;
		}
		assert_eq!(fixture.retrieve(false, Some(&tx))?.len(), 1);

		tx.tx_type = cancelled_type;
		{
			let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
			batch.save_tx_log_entry(tx.clone(), &parent)?;
			batch.commit()?;
		}
		for show_spent in [false, true] {
			assert!(fixture.retrieve(show_spent, Some(&tx))?.is_empty());
		}

		{
			let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
			batch.archive_output(&output)?;
			batch.commit()?;
		}
		for show_spent in [false, true] {
			assert!(fixture.retrieve(show_spent, Some(&tx))?.is_empty());
		}

		{
			let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
			batch.archive_transaction(&tx)?;
			batch.commit()?;
		}
		for show_spent in [false, true] {
			assert!(
				fixture.retrieve(show_spent, Some(&tx))?.is_empty(),
				"archiving the cancelled log must not expose its {:?} output",
				output.status,
			);
		}
	}
	Ok(())
}

#[test]
fn non_cancelled_archived_outputs_remain_visible() -> Result<(), Error> {
	let mut fixture = Fixture::new()?;
	let parent = fixture.wallet.parent_key_id();
	let output = fixture.output(OutputStatus::Reverted, 7)?;
	let tx = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReverted, 7);
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		batch.save(output.clone())?;
		batch.archive_output(&output)?;
		batch.save_tx_log_entry(tx.clone(), &parent)?;
		batch.archive_transaction(&tx)?;
		batch.commit()?;
	}
	for show_spent in [false, true] {
		assert_eq!(fixture.retrieve(show_spent, Some(&tx))?.len(), 1);
	}
	Ok(())
}

#[test]
fn archived_cancellation_is_account_scoped_and_live_records_take_precedence() -> Result<(), Error> {
	let mut fixture = Fixture::new()?;
	let parent = fixture.wallet.parent_key_id();
	let other_parent = ExtKeychain::derive_key_id(2, 1, 0, 0, 0)?;
	let output = fixture.output(OutputStatus::Unconfirmed, 7)?;
	let other_tx = TxLogEntry::new(other_parent.clone(), TxLogEntryType::TxReceivedCancelled, 7);
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		batch.save(output)?;
		batch.save_tx_log_entry(other_tx.clone(), &other_parent)?;
		batch.archive_transaction(&other_tx)?;
		batch.commit()?;
	}
	assert_eq!(fixture.retrieve(false, None)?.len(), 1);

	// Resolve the live output's cancellation from its own account's archive.
	let mut tx = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceivedCancelled, 7);
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		batch.save_tx_log_entry(tx.clone(), &parent)?;
		batch.archive_transaction(&tx)?;
		batch.commit()?;
	}
	assert!(fixture.retrieve(false, None)?.is_empty());

	// A current log entry must override its historical copy even when another
	// output still needs the archive lookup and has no matching transaction.
	tx.tx_type = TxLogEntryType::TxReceived;
	let unresolved_output = fixture.output(OutputStatus::Unconfirmed, 8)?;
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		batch.save(unresolved_output)?;
		batch.save_tx_log_entry(tx, &parent)?;
		batch.commit()?;
	}
	assert_eq!(fixture.retrieve(false, None)?.len(), 2);
	Ok(())
}

#[test]
fn archive_errors_propagate_only_when_cancellation_lookup_needs_the_archive() -> Result<(), Error> {
	let mut fixture = Fixture::new()?;
	let parent = fixture.wallet.parent_key_id();
	let output = fixture.output(OutputStatus::Unconfirmed, 7)?;
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		batch.save(output)?;
		batch.commit()?;
	}
	// Inject a decode failure into the isolated test database.
	{
		let key = to_key_u64(TX_ARCHIVE_LOG_ENTRY_PREFIX, parent.to_bytes().to_vec(), 7)?;
		let batch = fixture.wallet.db.batch_write()?;
		batch.put(&key, b"invalid transaction record")?;
		batch.commit()?;
	}
	assert!(matches!(
		fixture.retrieve(false, None),
		Err(Error::Backend(_))
	));

	// A resolved live record avoids reading the archive at all.
	{
		let mut batch = fixture.wallet.batch(&fixture.secp, None)?;
		let tx = TxLogEntry::new(parent.clone(), TxLogEntryType::TxReceived, 7);
		batch.save_tx_log_entry(tx, &parent)?;
		batch.commit()?;
	}
	assert_eq!(fixture.retrieve(false, None)?.len(), 1);
	Ok(())
}
