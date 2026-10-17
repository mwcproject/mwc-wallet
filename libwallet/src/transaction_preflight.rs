// Copyright 2026 The Mwc Developers
// Licensed under the Apache License, Version 2.0.

//! Disclosure checks shared by every node transport and publication path.

use crate::{Error, NodeClient, NodeConnectionId};
use mwc_wallet_util::mwc_core::core::{Transaction, Weighting};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json;

pub use mwc_wallet_util::mwc_core::core::transaction_preflight::{
	MempoolAcceptRequest, MempoolAcceptResponse, PreflightInput, PreflightKernel, PreflightOutput,
	PreflightTransaction,
};

/// An ephemeral, single-use authorization to disclose one exact transaction to
/// the selected node for the same wallet. Not serializable or clonable.
pub struct PreflightReceipt {
	transaction: Vec<u8>,
	connection: NodeConnectionId,
}

impl PreflightReceipt {
	/// Check again at the transport boundary, before serializing a network request.
	pub fn check<C: NodeClient>(self, client: &C, tx: &Transaction) -> Result<(), Error> {
		if self.connection != client.get_node_connection_id()
			|| self.transaction != serde_json::to_vec(tx).map_err(|e| Error::Node(e.to_string()))?
		{
			return Err(Error::Node(
				"Transaction or node changed after preflight; retry validation".into(),
			));
		}
		Ok(())
	}
}

/// Require an explicit result for the exact requested validation scope.
pub fn require_preflight(
	request: &MempoolAcceptRequest,
	response: &MempoolAcceptResponse,
) -> Result<(), Error> {
	if response.transactions.len() != request.transactions.len()
		|| response.checks_passed != response.transactions.iter().all(|tx| tx.checks_passed)
		|| request
			.transactions
			.iter()
			.zip(&response.transactions)
			.any(|(request, result)| {
				result.is_complete != request.is_complete
					|| result.checks_passed != result.failures.is_empty()
			}) {
		return Err(Error::Node(
			"Node returned an inconsistent preflight result".into(),
		));
	}
	if !response.checks_passed {
		let rejected: Vec<_> = response
			.transactions
			.iter()
			.enumerate()
			.flat_map(|(index, result)| {
				result.failures.iter().map(move |failure| {
					format!(
						"transaction {} {}: {}",
						index, failure.check, failure.reason
					)
				})
			})
			.collect();
		return Err(Error::Node(format!(
			"Transaction preflight rejected: {}",
			rejected.join("; ")
		)));
	}
	for (request, result) in request.transactions.iter().zip(&response.transactions) {
		if result.balance_checked != request.is_complete
			|| (!request.allow_future_height
				&& result.valid_from_height > response.checked_height.saturating_add(1))
		{
			return Err(Error::Node(
				"Node returned an inconsistent preflight scope result".into(),
			));
		}
	}
	Ok(())
}

/// Full cryptographic checks stay local. Only the unsigned allowlisted fields
/// reach the node; an error never authorizes submission or signature exposure.
pub fn prepare_transaction<C: NodeClient>(
	context_id: u32,
	client: &C,
	tx: &Transaction,
) -> Result<PreflightReceipt, Error> {
	prepare_transaction_with_related(context_id, client, tx, &[])
}

/// Check the publication transaction and its dependents in one node snapshot.
pub(crate) fn prepare_transaction_with_related<C: NodeClient>(
	context_id: u32,
	client: &C,
	tx: &Transaction,
	related: &[PreflightTransaction],
) -> Result<PreflightReceipt, Error> {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	tx.validate(context_id, Weighting::AsTransaction, &mut secp)?;
	let mut request = MempoolAcceptRequest::single(PreflightTransaction::from_transaction(
		context_id, tx, true,
	)?);
	request.transactions.extend_from_slice(related);
	let connection = client.get_node_connection_id();
	check_request(client, &request)?;
	if connection != client.get_node_connection_id() {
		return Err(Error::Node(
			"Node changed during transaction preflight".into(),
		));
	}
	Ok(PreflightReceipt {
		transaction: serde_json::to_vec(tx).map_err(|e| Error::Node(e.to_string()))?,
		connection,
	})
}

/// Validate all requested transactions on one selected node connection.
pub fn check_request<C: NodeClient>(
	client: &C,
	request: &MempoolAcceptRequest,
) -> Result<MempoolAcceptResponse, Error> {
	let connection = client.get_node_connection_id();
	let response = client.test_mempool_accept(request)?;
	if client.get_node_connection_id() != connection {
		return Err(Error::Node(
			"Node changed during transaction preflight".into(),
		));
	}
	require_preflight(request, &response)?;
	Ok(response)
}

/// Check the available slate body before releasing an online response. Compact
/// messages with omitted transaction elements must use partial validation.
pub fn check_slate<C: NodeClient>(
	context_id: u32,
	client: &C,
	slate: &crate::Slate,
	secp: &Secp256k1,
	complete: bool,
) -> Result<MempoolAcceptResponse, Error> {
	let transaction = slate.node_preflight_transaction(context_id, secp, complete)?;
	check_request(client, &MempoolAcceptRequest::single(transaction))
}
