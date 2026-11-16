// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const { inputJson, readJson } = require('./cli_io');

// Named parameters in OwnerRpcV3. Tests compare this list with the Rust trait.
// Nested structures (args, query, slate, config, etc.) pass through unchanged.
const RPC_PARAMETERS = {
	accounts: ['token'],
	create_account_path: ['token', 'label'],
	set_active_account: ['token', 'label'],
	retrieve_outputs: ['token', 'include_spent', 'refresh_from_node', 'tx_id'],
	retrieve_txs: ['token', 'refresh_from_node', 'tx_id', 'tx_slate_id', 'show_last_four_days'],
	query_txs: ['token', 'refresh_from_node', 'query', 'show_last_four_days'],
	retrieve_summary_info: ['token', 'refresh_from_node', 'minimum_confirmations'],
	init_send_tx: ['token', 'args'],
	issue_invoice_tx: ['token', 'args'],
	get_rewind_hash: ['token'],
	scan_rewind_hash: ['rewind_hash', 'start_height'],
	process_invoice_tx: ['token', 'slate', 'args'],
	tx_lock_outputs: ['token', 'slate', 'participant_id'],
	finalize_tx: ['token', 'slate'],
	post_tx: ['token', 'tx', 'fluff'],
	cancel_tx: ['token', 'tx_id', 'tx_slate_id'],
	get_stored_tx: ['token', 'tx'],
	verify_slate_messages: ['token', 'slate'],
	scan: ['token', 'start_height', 'delete_unconfirmed'],
	node_height: ['token'],
	init_secure_api: ['ecdh_pubkey'],
	get_top_level_directory: [],
	set_top_level_directory: ['dir'],
	create_config: ['chain_type', 'wallet_config', 'logging_config', 'tor_config', 'mqs_config'],
	create_wallet: ['name', 'mnemonic', 'mnemonic_length', 'password'],
	open_wallet: ['name', 'password'],
	close_wallet: ['name'],
	get_mnemonic: ['name', 'password'],
	change_password: ['name', 'old', 'new'],
	delete_wallet: ['name'],
	get_mqs_address: ['token'],
	get_wallet_public_address: ['token'],
	retrieve_payment_proof: ['token', 'tx_id', 'tx_slate_id'],
	verify_payment_proof: ['token', 'proof'],
	set_tor_config: ['tor_config'],
	build_output: ['token', 'features', 'amount'],
	encode_slatepack_message: ['token', 'slate', 'content', 'recipient', 'address_index'],
	decode_slatepack_message: ['token', 'message', 'address_index'],
};

function rpcParameters(method, options) {
	if (options.params !== undefined && options['params-json'] !== undefined) {
		throw new Error('Use --params FILE or --params-json JSON, not both.');
	}
	const params = options.params !== undefined ? readJson(options.params) :
		options['params-json'] !== undefined ? inputJson(options['params-json']) : {};
	if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('RPC parameters must be a JSON object.');
	const check = name => {
		if (name === 'token') throw new Error('Omit token: the CLI supplies its current wallet token.');
		if (!RPC_PARAMETERS[method].includes(name)) throw new Error(`Unknown parameter for ${method}. Use help rpc ${method}.`);
	};
	Object.keys(params).forEach(check);
	for (const entry of options.param || []) {
		const equals = entry.indexOf('=');
		if (equals < 1) throw new Error('Use --param NAME=JSON, for example --param refresh_from_node=true.');
		const name = entry.slice(0, equals);
		check(name);
		if (Object.hasOwn(params, name)) throw new Error('Specify each API parameter only once, including parameters from a JSON object or file.');
		params[name] = inputJson(entry.slice(equals + 1));
	}
	return params;
}

module.exports = { RPC_PARAMETERS, rpcParameters };
