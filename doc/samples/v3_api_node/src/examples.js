// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

'use strict';

// Each function makes exactly one API call. Importing this module runs nothing.
// Supply complex Rust API structures (args, slate, proof, tx, config) as JSON.
// The README includes complete query and transaction-construction examples.
function invoke(client, method, params) {
	if (Object.values(params).some(value => value === undefined)) {
		throw new Error(`Missing a required parameter for ${method}.`);
	}
	return client.call(method, params);
}

exports.init_secure_api = client => client.connect();

exports.accounts = (client, { token } = {}) =>
	invoke(client, 'accounts', { token });

exports.create_account_path = (client, { token, label } = {}) =>
	invoke(client, 'create_account_path', { token, label });

exports.set_active_account = (client, { token, label } = {}) =>
	invoke(client, 'set_active_account', { token, label });

exports.retrieve_outputs = (client, { token, include_spent = false, refresh_from_node = false, tx_id = null } = {}) =>
	invoke(client, 'retrieve_outputs', { token, include_spent, refresh_from_node, tx_id });

exports.retrieve_txs = (client, { token, refresh_from_node = false, tx_id = null, tx_slate_id = null, show_last_four_days = false } = {}) =>
	invoke(client, 'retrieve_txs', { token, refresh_from_node, tx_id, tx_slate_id, show_last_four_days });

exports.query_txs = (client, { token, refresh_from_node = false, query, show_last_four_days = false } = {}) =>
	invoke(client, 'query_txs', { token, refresh_from_node, query, show_last_four_days });

exports.retrieve_summary_info = (client, { token, refresh_from_node = false, minimum_confirmations = 10 } = {}) =>
	invoke(client, 'retrieve_summary_info', { token, refresh_from_node, minimum_confirmations });

exports.init_send_tx = (client, { token, args } = {}) =>
	invoke(client, 'init_send_tx', { token, args });

exports.issue_invoice_tx = (client, { token, args } = {}) =>
	invoke(client, 'issue_invoice_tx', { token, args });

exports.get_rewind_hash = (client, { token } = {}) =>
	invoke(client, 'get_rewind_hash', { token });

exports.scan_rewind_hash = (client, { rewind_hash, start_height = null } = {}) =>
	invoke(client, 'scan_rewind_hash', { rewind_hash, start_height });

exports.process_invoice_tx = (client, { token, slate, args } = {}) =>
	invoke(client, 'process_invoice_tx', { token, slate, args });

exports.tx_lock_outputs = (client, { token, slate, participant_id } = {}) =>
	invoke(client, 'tx_lock_outputs', { token, slate, participant_id });

exports.finalize_tx = (client, { token, slate } = {}) =>
	invoke(client, 'finalize_tx', { token, slate });

exports.post_tx = (client, { token, tx, fluff = null } = {}) =>
	invoke(client, 'post_tx', { token, tx, fluff });

exports.cancel_tx = (client, { token, tx_id = null, tx_slate_id = null } = {}) =>
	invoke(client, 'cancel_tx', { token, tx_id, tx_slate_id });

exports.get_stored_tx = (client, { token, tx } = {}) =>
	invoke(client, 'get_stored_tx', { token, tx });

exports.verify_slate_messages = (client, { token, slate } = {}) =>
	invoke(client, 'verify_slate_messages', { token, slate });

exports.scan = (client, { token, start_height = null, delete_unconfirmed = false } = {}) =>
	invoke(client, 'scan', { token, start_height, delete_unconfirmed });

exports.node_height = (client, { token } = {}) =>
	invoke(client, 'node_height', { token });

exports.get_top_level_directory = client => invoke(client, 'get_top_level_directory', {});

exports.set_top_level_directory = (client, { dir } = {}) =>
	invoke(client, 'set_top_level_directory', { dir });

exports.create_config = (client, { chain_type, wallet_config = null, logging_config = null, tor_config = null, mqs_config = null } = {}) =>
	invoke(client, 'create_config', { chain_type, wallet_config, logging_config, tor_config, mqs_config });

exports.create_wallet = (client, { name = null, mnemonic = null, mnemonic_length, password } = {}) =>
	invoke(client, 'create_wallet', { name, mnemonic, mnemonic_length, password });

exports.open_wallet = (client, { name = null, password } = {}) =>
	invoke(client, 'open_wallet', { name, password });

exports.close_wallet = (client, { name = null } = {}) =>
	invoke(client, 'close_wallet', { name });

exports.get_mnemonic = (client, { name = null, password } = {}) =>
	invoke(client, 'get_mnemonic', { name, password });

exports.change_password = (client, { name = null, old, new: newPassword } = {}) =>
	invoke(client, 'change_password', { name, old, new: newPassword });

exports.delete_wallet = (client, { name = null } = {}) =>
	invoke(client, 'delete_wallet', { name });

exports.get_mqs_address = (client, { token } = {}) =>
	invoke(client, 'get_mqs_address', { token });

exports.get_wallet_public_address = (client, { token } = {}) =>
	invoke(client, 'get_wallet_public_address', { token });

exports.retrieve_payment_proof = (client, { token, tx_id = null, tx_slate_id = null } = {}) =>
	invoke(client, 'retrieve_payment_proof', { token, tx_id, tx_slate_id });

exports.verify_payment_proof = (client, { token, proof } = {}) =>
	invoke(client, 'verify_payment_proof', { token, proof });

exports.set_tor_config = (client, { tor_config = null } = {}) =>
	invoke(client, 'set_tor_config', { tor_config });

exports.build_output = (client, { token, features, amount } = {}) =>
	invoke(client, 'build_output', { token, features, amount });

exports.encode_slatepack_message = (client, { token, slate, content, recipient = null, address_index = null } = {}) =>
	invoke(client, 'encode_slatepack_message', { token, slate, content, recipient, address_index });

exports.decode_slatepack_message = (client, { token, message, address_index = null } = {}) =>
	invoke(client, 'decode_slatepack_message', { token, message, address_index });
