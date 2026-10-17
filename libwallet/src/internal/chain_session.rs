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

use crate::{ChainTip, Error, NodeClient, NodeConnectionId};

/// Identifies the node and chain prefix used by a compound read operation.
/// Body tips bypass caches: clearing them cannot prevent an in-flight request
/// from repopulating them with pre-reorg data. Ancestry is followed by hash,
/// independently of the node's potentially different header chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NodeReadSession {
	/// Node identity and connection generation serving this session.
	pub(crate) connection: NodeConnectionId,
	/// Chain header that all reads in this session must descend from.
	pub(crate) anchor: ChainTip,
}

impl NodeReadSession {
	/// Start a compound read from a freshly fetched chain tip.
	pub(crate) fn start<C>(client: &C, operation: &str) -> Result<Self, Error>
	where
		C: NodeClient,
	{
		client.reset_cache();
		let (height, hash, _) = client.get_chain_tip_fresh()?;
		let connection = client.get_node_connection_id();
		let session = Self {
			connection,
			anchor: ChainTip { height, hash },
		};
		session.ensure_connection(client, operation)?;
		session.verify_anchor(client, operation)?;
		Ok(session)
	}

	/// Bind a caller-provided anchor to the node currently serving requests.
	pub(crate) fn bind<C>(client: &C, anchor: ChainTip, operation: &str) -> Result<Self, Error>
	where
		C: NodeClient,
	{
		client.reset_cache();
		let header = client.get_header_info_fresh(anchor.height)?;
		let connection = client.get_node_connection_id();
		let session = Self { connection, anchor };
		session.ensure_connection(client, operation)?;
		if header.hash != session.anchor.hash {
			return Err(Error::Node(format!(
				"{} chain anchor changed at height {}; expected hash {}, received {}",
				operation, session.anchor.height, session.anchor.hash, header.hash
			)));
		}
		session.verify_anchor(client, operation)?;
		Ok(session)
	}

	/// Fail if transparent HTTP failover changed the serving node.
	pub(crate) fn ensure_connection<C>(&self, client: &C, operation: &str) -> Result<(), Error>
	where
		C: NodeClient,
	{
		let actual = client.get_node_connection_id();
		if actual != self.connection {
			return Err(Error::Node(format!(
				"{} changed node while reading chain state; expected {:?}, current {:?}. Partial results were discarded",
				operation, self.connection, actual
			)));
		}
		Ok(())
	}

	/// Verify the original anchor against the fresh body tip's ancestry without
	/// requiring the live tip height to remain fixed.
	///
	/// This proves *header* integrity only: the scanned chain prefix is
	/// unchanged (no reorg) and the tip did not move behind the anchor. It does
	/// NOT prove *result* integrity. Node reads such as `get_unspent_outputs`
	/// bound results by PMMR insertion position but evaluate spent/unspent
	/// against the node's live UTXO set, so a chain extension accepted here can
	/// still have changed which outputs a paged scan sees: an output spent after
	/// the anchor disappears from the result while its replacement sits above
	/// the anchored PMMR bound and is excluded as well. Callers that merge
	/// anchor-bounded output reads must tolerate or compensate for that:
	/// - the regular wallet scan compensates through the `update_wallet_state`
	///   refresh fixpoint (it saves `last_scanned_blocks` at the anchor, so
	///   the next pass re-scans exactly the delta above it), and
	/// - the view-wallet scan accepts the single-pass result: it is an
	///   on-demand report whose operator knows the wallet's pending
	///   transactions, so movement inside the scan window is expected and
	///   tolerable (see `owner::scan_rewind_hash_with_anchor`).
	pub(crate) fn verify_anchor<C>(&self, client: &C, operation: &str) -> Result<(), Error>
	where
		C: NodeClient,
	{
		self.verified_body_tip(client, operation).map(|_| ())
	}

	/// Follow immutable parent links from the body tip. Height lookups select
	/// the header chain, which can be on another fork during header-first sync.
	/// This takes one header request per block between the tip and anchor.
	fn verified_body_tip<C>(&self, client: &C, operation: &str) -> Result<ChainTip, Error>
	where
		C: NodeClient,
	{
		self.ensure_connection(client, operation)?;
		client.reset_cache();
		let (height, hash, _) = client.get_chain_tip_fresh()?;
		self.ensure_connection(client, operation)?;
		if height < self.anchor.height {
			return Err(Error::Node(format!(
				"{} node tip moved behind the operation anchor; anchor height {}, current height {}",
				operation, self.anchor.height, height
			)));
		}
		let tip = ChainTip { height, hash };
		let mut cursor = tip.clone();
		while cursor.height > self.anchor.height {
			let header = client.get_header_by_hash(&cursor.hash)?;
			self.ensure_connection(client, operation)?;
			if header.hash != cursor.hash || header.height != cursor.height {
				return Err(Error::Node(format!(
					"{} returned an inconsistent ancestry header; expected {} at height {}, received {} at height {}",
					operation, cursor.hash, cursor.height, header.hash, header.height
				)));
			}
			cursor.height = cursor
				.height
				.checked_sub(1)
				.ok_or_else(|| Error::Node(format!("{} invalid ancestry height", operation)))?;
			cursor.hash = header.previous;
		}
		if cursor.hash != self.anchor.hash {
			return Err(Error::Node(format!(
				"{} body chain changed at height {}; expected hash {}, received {}. Partial results were discarded",
				operation, self.anchor.height, self.anchor.hash, cursor.hash
			)));
		}
		self.ensure_connection(client, operation)?;
		Ok(tip)
	}

	/// Fetch a fresh final tip and prove that it still descends from the original
	/// anchor. A normal chain extension is accepted.
	#[cfg(feature = "swaps")]
	pub(crate) fn fresh_tip<C>(&self, client: &C, operation: &str) -> Result<ChainTip, Error>
	where
		C: NodeClient,
	{
		self.verified_body_tip(client, operation)
	}
}
