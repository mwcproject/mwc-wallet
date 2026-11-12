//! Mining rewards must be spendable before the seller exposes its MWC signature.

use super::*;

fn coinbase_funding(
	api: &BtcSwapApi<'_, TestNodeClient, TestBtcNodeClient>,
	swap: &Swap,
	secp: &Secp256k1,
	height: u64,
) -> BitcoinTransaction {
	let script = api.script(swap, secp).unwrap();
	let address = swap
		.secondary_data
		.unwrap_btc()
		.unwrap()
		.address(Currency::Btc, &script, swap.network)
		.unwrap();
	BitcoinTransaction {
		version: 2,
		lock_time: 0,
		input: vec![bitcoin_lib::TxIn {
			previous_output: bitcoin_lib::OutPoint::null(),
			script_sig: bitcoin_lib::blockdata::script::Builder::new()
				.push_int(i64::try_from(height).unwrap())
				.unwrap()
				.into_script(),
			sequence: u32::MAX,
			witness: vec![],
		}],
		output: vec![TxOut {
			value: swap.secondary_amount,
			script_pubkey: Currency::Btc
				.address_2_script_pubkey(0, &address[0])
				.unwrap(),
		}],
	}
}

#[test]
#[serial]
fn coinbase_maturity_gates_redeem_message_and_rechecks_saved_inputs() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (mut swap, context, kc, nc, btc_nc) = funding_limit_fixture(&secp, 1);
	swap.secondary_confirmations = 6;
	swap::set_testing_cur_time(swap.started.timestamp());
	swap.state = StateId::SellerSendingInitRedeemMessage;
	swap.redeem_kernel_updated = false;
	swap.message2 = None;
	swap.posted_msg2 = None;
	let api = BtcSwapApi::new_test(Arc::new(nc), Arc::new(Mutex::new(btc_nc.clone())));
	let funding_height = btc_nc.get_state().height;
	let coinbase = coinbase_funding(&api, &swap, &secp, funding_height);
	assert!(coinbase.is_coin_base());
	btc_nc.clean();
	btc_nc.push_transaction(&coinbase).unwrap();
	btc_nc.mine_blocks_no_pending(5);
	let mut confirmations = api.request_tx_confirmations(&secp, &kc, &swap).unwrap();
	confirmations.mwc_lock_conf = Some(swap.mwc_confirmations);
	let mut fsm = api.get_fsm(&kc, &swap);
	let before = serde_json::to_value(&swap).unwrap();
	for depth in [6, 99] {
		assert_eq!(btc_nc.get_state().height - funding_height + 1, depth);
		let error = fsm
			.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap_err();
		assert!(error.to_string().contains("immature coinbase"), "{error}");
		assert_eq!(serde_json::to_value(&swap).unwrap(), before);
		assert!(SellApi::redeem_message(&swap).is_err());
		if depth == 6 {
			btc_nc.mine_blocks_no_pending(93);
		}
	}
	btc_nc.mine_blocks_no_pending(1);
	let response = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap();
	let message = match response.action {
		Some(Action::SellerSendRedeemMessage(message)) => message,
		other => panic!("Expected redeem message at maturity, got {other:?}"),
	};
	assert_eq!(
		swap.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_inputs
			.as_ref()
			.unwrap()[0]
			.out_point
			.txid,
		coinbase.txid().unwrap()
	);

	// A saved message/input set must not bypass maturity checks after a reorg.
	swap.message2 = Some(message);
	swap = serde_json::from_str(&serde_json::to_string(&swap).unwrap()).unwrap();
	let mut fsm = api.get_fsm(&kc, &swap);
	let mut reorg = btc_nc.get_state();
	reorg.height -= 1;
	btc_nc.set_state(&reorg);
	let before = serde_json::to_value(&swap).unwrap();
	let error = fsm
		.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
		.unwrap_err();
	assert!(error.to_string().contains("immature coinbase"), "{error}");
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);

	// Extra immature deposits cannot change or block an already accepted set.
	btc_nc.mine_blocks_no_pending(1);
	let extra = coinbase_funding(&api, &swap, &secp, btc_nc.get_state().height);
	btc_nc.push_transaction(&extra).unwrap();
	assert!(matches!(
		fsm.process(Input::Check, &mut swap, &context, &confirmations, &mut secp)
			.unwrap()
			.action,
		Some(Action::SellerSendRedeemMessage(_))
	));
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);
	swap::reset_testing_cur_time();
}

#[derive(Clone)]
struct CoinbaseLookupClient {
	inner: TestBtcNodeClient,
	fail_lookup: bool,
	calls: Arc<Mutex<Vec<&'static str>>>,
}

impl BtcNodeClient for CoinbaseLookupClient {
	fn name(&self) -> String {
		"coinbase-test".into()
	}
	fn height(&mut self) -> Result<u64, Error> {
		self.calls.lock().push("height");
		self.inner.height()
	}
	fn unspent(
		&mut self,
		context_id: u32,
		currency: Currency,
		address: &String,
	) -> Result<Vec<Output>, Error> {
		self.calls.lock().push("unspent");
		self.inner.unspent(context_id, currency, address)
	}
	fn post_tx(&mut self, tx: Vec<u8>) -> Result<(), Error> {
		self.inner.post_tx(tx)
	}
	fn transaction(&mut self, hash: &bitcoin_lib::Txid) -> Result<Option<u64>, Error> {
		self.inner.transaction(hash)
	}
	fn transaction_is_coinbase(&mut self, hash: &bitcoin_lib::Txid) -> Result<bool, Error> {
		self.calls.lock().push("coinbase");
		if self.fail_lookup {
			return Err(Error::ElectrumNodeClient(
				"injected coinbase lookup failure".into(),
			));
		}
		self.inner.transaction_is_coinbase(hash)
	}
}

#[test]
#[serial]
fn coinbase_lookup_failure_retries_the_whole_funding_read_and_fails_closed() {
	set_test_mode(true);
	global::set_local_chain_type(ChainTypes::Floonet);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let (original, _context, _kc, nc, btc_nc) = funding_limit_fixture(&secp, 2);
	swap::set_testing_cur_time(original.started.timestamp());
	let primary = Arc::new(Mutex::new(CoinbaseLookupClient {
		inner: btc_nc.clone(),
		fail_lookup: true,
		calls: Arc::new(Mutex::new(vec![])),
	}));
	let secondary = Arc::new(Mutex::new(CoinbaseLookupClient {
		inner: btc_nc.clone(),
		fail_lookup: false,
		calls: Arc::new(Mutex::new(vec![])),
	}));
	let api = BtcSwapApi::new(
		0,
		Currency::Btc,
		Arc::new(nc),
		primary.clone(),
		secondary.clone(),
	);
	let api: &dyn SwapApi<ExtKeychain> = &api;
	let mut swap = original.clone();
	api.prepare_secondary_redeem(&mut swap, &secp).unwrap();
	for client in [&primary, &secondary] {
		assert_eq!(
			*client.lock().calls.lock(),
			vec!["unspent", "height", "coinbase"]
		);
	}
	assert_eq!(
		swap.secondary_data
			.unwrap_btc()
			.unwrap()
			.redeem_inputs
			.as_ref()
			.unwrap()
			.len(),
		2
	);
	// Both outputs share a funding transaction, so only one lookup is needed.
	secondary.lock().fail_lookup = true;
	let mut swap = original;
	let before = serde_json::to_value(&swap).unwrap();
	let error = api.prepare_secondary_redeem(&mut swap, &secp).unwrap_err();
	assert!(error
		.to_string()
		.contains("injected coinbase lookup failure"));
	assert_eq!(serde_json::to_value(&swap).unwrap(), before);
	swap::reset_testing_cur_time();
}
