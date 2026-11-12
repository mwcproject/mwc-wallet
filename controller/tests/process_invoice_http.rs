// Copyright 2026 The Mwc Developers
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

//! HTTP invoice payments must persist the finalized transaction for reposting.

#![cfg(feature = "test-support")]

use mwc_wallet_api::{Foreign, ForeignRpc, Owner};
use mwc_wallet_controller::command::{process_invoice, ProcessInvoiceArgs};
use mwc_wallet_impls::test_framework::{self, LocalWalletClient};
use mwc_wallet_libwallet::proof::proofaddress::ProvableAddress;
use mwc_wallet_libwallet::{IssueInvoiceTxArgs, SlatePurpose, SlateVersion};
use mwc_wallet_util::mwc_core::core::{Transaction, Weighting};
use mwc_wallet_util::mwc_core::{consensus, global, ser};
use mwc_wallet_util::mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_wallet_util::mwc_crates::serde_json::{self, json, Value};
use mwc_wallet_util::Mutex;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::{ops::DerefMut, sync::Arc, thread, time::Duration};

#[macro_use]
mod common;

fn read_request(stream: &mut BufReader<TcpStream>) -> Value {
	let mut line = String::new();
	stream.read_line(&mut line).unwrap();
	assert!(line.starts_with("POST /v2/foreign HTTP/1.1"));
	let mut content_length = None;
	loop {
		line.clear();
		assert!(stream.read_line(&mut line).unwrap() > 0);
		if line == "\r\n" {
			break;
		}
		let (name, value) = line.split_once(':').unwrap();
		if name.eq_ignore_ascii_case("content-length") {
			content_length = Some(value.trim().parse::<usize>().unwrap());
		}
	}
	let mut body = vec![0; content_length.unwrap()];
	stream.read_exact(&mut body).unwrap();
	serde_json::from_slice(&body).unwrap()
}

#[test]
fn compact_http_invoice_saves_finalized_transaction() -> Result<(), mwc_wallet_controller::Error> {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let destination = format!("http://{}", listener.local_addr().unwrap());
	let test_dir = "test_output/compact_http_invoice";
	common::setup(test_dir);
	mwc_wallet_util::mwc_util::init_global_runtime().unwrap();
	let tx_pool: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
	let mut proxy = common::create_wallet_proxy(test_dir.into(), tx_pool.clone());
	let chain = proxy.chain.clone();
	create_wallet_and_add!(
		payer_client,
		payer_wallet,
		payer_mask,
		test_dir,
		"payer",
		None,
		&mut proxy,
		true
	);
	create_wallet_and_add!(
		issuer_client,
		issuer_wallet,
		issuer_mask,
		test_dir,
		"issuer",
		None,
		&mut proxy,
		true
	);
	let proxy_handle = proxy.start();
	test_framework::award_blocks_to_wallet(
		&chain,
		payer_wallet.clone(),
		payer_mask.as_ref(),
		10,
		false,
		tx_pool.lock().deref_mut(),
	)?;
	let mut payer = Owner::new(0, payer_wallet.clone(), None)?;
	let issuer = Owner::new(0, issuer_wallet.clone(), None)?;
	let payer_address = payer.get_wallet_public_address(payer_mask.as_ref())?;
	let initial = issuer.issue_invoice_tx(
		issuer_mask.as_ref(),
		None,
		&IssueInvoiceTxArgs {
			amount: 1_000_000_000,
			slatepack_recipient: Some(ProvableAddress::from_tor_pub_key(&payer_address)?),
			..Default::default()
		},
	)?;
	let input = issuer.encrypt_slate(
		issuer_mask.as_ref(),
		&initial,
		Some(SlateVersion::SP),
		SlatePurpose::InvoiceInitial,
		Some(payer_address),
		None,
		false,
	)?;

	// Use the real foreign RPC methods behind a small HTTP fixture so the
	// controller performs its normal version negotiation and Slatepack exchange.
	let server = thread::spawn(move || {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_accept_fee_base(consensus::MILLI_MWC / 100).unwrap();
		global::set_local_nrd_enabled(true);
		let foreign = Foreign::new(issuer_wallet, issuer_mask, None);
		let (socket, _) = listener.accept().unwrap();
		socket
			.set_read_timeout(Some(Duration::from_secs(30)))
			.unwrap();
		socket
			.set_write_timeout(Some(Duration::from_secs(30)))
			.unwrap();
		let mut stream = BufReader::new(socket);
		for method in ["check_version", "get_proof_address", "finalize_invoice_tx"] {
			let request = read_request(&mut stream);
			assert_eq!(request["method"], method);
			let result = match method {
				"check_version" => json!(ForeignRpc::check_version(&foreign).unwrap()),
				"get_proof_address" => json!(ForeignRpc::get_proof_address(&foreign).unwrap()),
				_ => {
					let slate = serde_json::from_value(request["params"][0].clone()).unwrap();
					json!(ForeignRpc::finalize_invoice_tx(&foreign, slate).unwrap())
				}
			};
			let body = serde_json::to_vec(&json!({
				"jsonrpc": "2.0", "id": request["id"], "result": { "Ok": result }
			}))
			.unwrap();
			let connection = if method == "finalize_invoice_tx" {
				"close"
			} else {
				"keep-alive"
			};
			write!(
				stream.get_mut(),
				"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
				body.len(),
				connection
			)
			.unwrap();
			stream.get_mut().write_all(&body).unwrap();
			stream.get_mut().flush().unwrap();
		}
	});
	process_invoice(
		&mut payer,
		payer_mask.as_ref(),
		None,
		ProcessInvoiceArgs {
			message: None,
			minimum_confirmations: 2,
			selection_strategy: "all".into(),
			method: "http".into(),
			dest: destination,
			max_outputs: 500,
			input_file: None,
			input_slatepack_message: Some(input.as_string()?),
			estimate_selection_strategies: false,
			slatepack_qr: false,
		},
		false,
	)?;
	server.join().unwrap();

	let posted = {
		let mut pool = tx_pool.lock();
		assert_eq!(pool.len(), 1);
		pool.pop().unwrap()
	};
	let stored = {
		wallet_inst!(payer_wallet, w);
		w.get_stored_tx_by_uuid(&initial.id.to_string(), false)?
	};
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
	posted.validate(0, Weighting::AsTransaction, &mut secp)?;
	stored.validate(0, Weighting::AsTransaction, &mut secp)?;
	assert_eq!(
		ser::ser_vec(0, &stored, ser::ProtocolVersion::local(), true).unwrap(),
		ser::ser_vec(0, &posted, ser::ProtocolVersion::local(), true).unwrap(),
		"the saved transaction must match the transaction that was posted"
	);
	// Simulate eviction from the node's pending pool and repost the disk copy.
	payer.post_tx(payer_mask.as_ref(), &stored, true)?;
	assert_eq!(tx_pool.lock().len(), 1);
	proxy_handle.stop()?;
	common::clean_output_dir(test_dir);
	Ok(())
}
