// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const { parseArgs } = require('node:util');
const { createHash } = require('node:crypto');
const api = require('./examples');
const { integer, amount, formatAmount, inputJson, contentText, OutputFile, display } = require('./cli_io');
const { RPC_PARAMETERS, rpcParameters } = require('./cli_rpc');

const string = short => ({ type: 'string', ...(short ? { short } : {}) });
const boolean = short => ({ type: 'boolean', ...(short ? { short } : {}) });
const common = { help: boolean(), yes: boolean('y'), out: string() };
const selection = { min_conf: string('c'), change_outputs: string('o'), selection: string('s'), message: string('g'),
	max_outputs: string(), min_fee: string() };
const selector = { id: string('i'), txid: string('t') };
const slateInput = { file: string('f'), content: string('c') };

const COMMANDS = {
	help: { usage: 'help [COMMAND] [RPC_METHOD]', description: 'Show command help; help rpc METHOD lists API parameters.', max: 2 },
	open: { usage: 'open [--account LABEL] [--name NAME]', description: 'Open the wallet with a hidden password prompt.', options: { account: string(), name: string() } },
	close: { usage: 'close [--name NAME]', description: 'Close this session’s wallet.', options: { name: string() } },
	exit: { usage: 'exit', description: 'Close the wallet and exit.' },
	info: { usage: 'info [--min_conf N] [--no-refresh]', description: 'Show balances in MWC and refresh status.', wallet: true, options: { min_conf: string('c'), 'no-refresh': boolean() } },
	outputs: { usage: 'outputs [--show_spent] [--no-refresh]', description: 'Show wallet outputs.', wallet: true, options: { show_spent: boolean('s'), 'no-refresh': boolean() } },
	txs: { usage: 'txs [--id N | --txid UUID] [--count N] [--no-refresh]', description: 'Show transaction history; use --show_last_four_days for recent/pending entries.', wallet: true, options: { ...selector, count: string('c'), show_last_four_days: boolean(), 'no-refresh': boolean() } },
	account: { usage: 'account [--create LABEL | --switch LABEL]', description: 'List, create, or select an account.', wallet: true, options: { create: string('c'), switch: string() } },
	address: { usage: 'address', description: 'Show Slatepack and MQS public addresses.', wallet: true },
	node_height: { usage: 'node_height', description: 'Show the node height and node-contact result.', wallet: true },
	send: { usage: 'send AMOUNT --dest FILE --slatepack_recipient ADDRESS [--late-lock]', description: 'Create an encrypted Slatepack withdrawal; --estimate only estimates fees.', wallet: true, min: 1, max: 1,
		options: { ...selection, ttl_blocks: string(), amount_includes_fee: boolean(), dest: string('d'), slatepack_recipient: string(), 'late-lock': boolean('l'), estimate: boolean('e') } },
	unpack: { usage: 'unpack (--file FILE | --content TEXT) [--out FILE]', description: 'Decode a Slatepack or inspect a JSON slate.', wallet: true, options: { ...slateInput, address_index: string() } },
	finalize: { usage: 'finalize (--file RESPONSE | --content TEXT) --dest FINALIZED [--nopost] [--fluff]', description: 'Finalize a send response and post it unless --nopost is specified.', wallet: true,
		options: { ...slateInput, dest: string('d'), nopost: boolean('n'), fluff: boolean('l') } },
	post: { usage: 'post (--input FILE | --content JSON) [--fluff]', description: 'Post a finalized transaction JSON or finalized slate.', wallet: true, options: { input: string('i'), content: string('c'), fluff: boolean('f') } },
	repost: { usage: 'repost --id N [--dumpfile FILE] [--fluff]', description: 'Post a stored transaction, or export its JSON with --dumpfile.', wallet: true, options: { ...selector, dumpfile: string('m'), fluff: boolean('f') } },
	cancel: { usage: 'cancel --id N | --txid UUID', description: 'Cancel an unconfirmed transaction.', wallet: true, options: selector },
	invoice: { usage: 'invoice AMOUNT --dest FILE --slatepack_recipient ADDRESS', description: 'Create an encrypted Slatepack invoice.', wallet: true, min: 1, max: 1,
		options: { dest: string('d'), slatepack_recipient: string(), message: string('g') } },
	pay: { usage: 'pay (--file INVOICE | --content TEXT) --dest RESPONSE [--min_conf N]', description: 'Fund an invoice and export the Slatepack response.', wallet: true,
		options: { ...selection, ...slateInput, content: string(), dest: string('d') } },
	scan: { usage: 'scan [--start_height N] [--delete_unconfirmed]', description: 'Reconcile wallet outputs with the node.', wallet: true, options: { start_height: string('h'), delete_unconfirmed: boolean('d') } },
	export_proof: { usage: 'export_proof FILE --id N | --txid UUID', description: 'Save a transaction payment proof.', wallet: true, min: 1, max: 1, options: selector },
	verify_proof: { usage: 'verify_proof [FILE | --content JSON]', description: 'Verify an exported payment proof.', wallet: true, max: 1, options: { content: string('c') } },
	recover: { usage: 'recover --out FILE [--name NAME]', description: 'Export the recovery phrase to a new private file.', options: { name: string() } },
	rewind_hash: { usage: 'rewind_hash --out FILE', description: 'Export the wallet’s private viewing credential.', wallet: true },
	rpc: { usage: 'rpc METHOD [--params FILE | --params-json JSON] [--param NAME=JSON ...] [--out FILE]', description: 'Call an owner API method with every supported parameter, including nested JSON.', min: 1, max: 1,
		options: { params: string(), 'params-json': string(), param: { type: 'string', multiple: true } } },
};

const TOKEN_METHODS = new Set(['accounts', 'create_account_path', 'set_active_account', 'retrieve_outputs', 'retrieve_txs',
	'query_txs', 'retrieve_summary_info', 'init_send_tx', 'issue_invoice_tx', 'get_rewind_hash', 'process_invoice_tx',
	'tx_lock_outputs', 'finalize_tx', 'post_tx', 'cancel_tx', 'get_stored_tx', 'verify_slate_messages', 'scan', 'node_height',
	'get_mqs_address', 'get_wallet_public_address', 'retrieve_payment_proof', 'verify_payment_proof', 'build_output',
	'encode_slatepack_message', 'decode_slatepack_message']);
const READ_METHODS = new Set(['accounts', 'retrieve_outputs', 'retrieve_txs', 'query_txs', 'retrieve_summary_info',
	'get_rewind_hash', 'scan_rewind_hash', 'get_stored_tx', 'verify_slate_messages', 'node_height', 'get_top_level_directory',
	'get_mnemonic', 'get_mqs_address', 'get_wallet_public_address', 'retrieve_payment_proof', 'verify_payment_proof',
	'encode_slatepack_message', 'decode_slatepack_message']);
const PRIVATE_RESULTS = new Set(['get_mnemonic', 'get_rewind_hash', 'build_output']);
const CLOSED_METHODS = new Set(['set_top_level_directory', 'create_config', 'create_wallet', 'change_password', 'delete_wallet']);

function parseCommand(argv) {
	let [name = 'help', ...args] = argv;
	if (name === '--help') name = 'help';
	if (name === 'quit') name = 'exit';
	if (!Object.hasOwn(COMMANDS, name)) throw new Error('Unknown command. Use help to list owner API commands.');
	const definition = COMMANDS[name];
	const options = { ...common, ...(definition.wallet ? { account: string() } : {}), ...definition.options };
	if (['help', 'open', 'close', 'exit', 'export_proof'].includes(name)) delete options.out;
	let parsed;
	try { parsed = parseArgs({ args, options, allowPositionals: true, strict: true, tokens: true }); }
	catch { throw new Error(`Invalid options. Use: help ${name}`); }
	const seen = new Set();
	for (const token of parsed.tokens.filter(token => token.kind === 'option')) {
		if (seen.has(token.name) && !options[token.name].multiple) throw new Error('Specify each option only once.');
		seen.add(token.name);
	}
	if (parsed.values.help) return { name: 'help', values: {}, positionals: name === 'rpc' ? [name, ...parsed.positionals] : [name] };
	if (parsed.positionals.length < (definition.min || 0) || parsed.positionals.length > (definition.max || 0)) {
		throw new Error(`Usage: ${definition.usage}`);
	}
	if (parsed.values.out && parsed.values.dest) throw new Error('Use only one output destination.');
	if (name === 'rpc' && (!Object.hasOwn(api, parsed.positionals[0]) || parsed.positionals[0] === 'init_secure_api')) {
		throw new Error('The secure handshake is automatic; rpc accepts the other methods listed by help rpc.');
	}
	return { name, values: parsed.values, positionals: parsed.positionals };
}

function help(name, method) {
	if (name && !Object.hasOwn(COMMANDS, name)) throw new Error('Unknown help topic.');
	if (method !== undefined && (name !== 'rpc' || !Object.hasOwn(RPC_PARAMETERS, method))) throw new Error('Use help rpc METHOD for a supported owner API method.');
	if (method !== undefined) return [method, 'API parameters:', ...RPC_PARAMETERS[method].map(field =>
		`  ${field}${field === 'token' ? ' (supplied by the CLI)' : ''}`),
		'Use --params-json JSON, --params FILE, or repeat --param NAME=JSON.',
		'Nested objects and arrays are passed unchanged. JSON strings need double quotes.',
		...(method === 'init_secure_api' ? ['ECDH keys and the handshake are generated by the client.'] : [])].join('\n');
	if (!name) return ['MWC Owner API CLI', ...Object.values(COMMANDS).map(command => `  ${command.usage}\n    ${command.description}`),
		'Use help COMMAND for options. Mutations prompt for confirmation; --yes allows scripted execution.',
		'Commands use only the owner API. receive/finalize_invoice/listeners/mining require other APIs.'].join('\n');
	const command = COMMANDS[name];
	const options = { ...common, ...(command.wallet ? { account: string() } : {}), ...command.options };
	if (['help', 'open', 'close', 'exit', 'export_proof'].includes(name)) delete options.out;
	return [command.usage, command.description, 'Options:', ...Object.entries(options).map(([key, value]) =>
		`  --${key}${value.short ? ` (-${value.short})` : ''}${value.type === 'string' ? ' VALUE' : ''}`),
		...(name === 'rpc' ? ['Methods:', ...Object.keys(api).filter(method => method !== 'init_secure_api').map(method => `  ${method}`),
			'Use help rpc METHOD for parameter names. Omit token; the CLI supplies its current token.',
			'RPC open_wallet/close_wallet keep session state in sync. Secret results require --out.'] : [])].join('\n');
}

function transactionSelector(values, required = true) {
	if (values.id !== undefined && values.txid !== undefined) throw new Error('Specify either --id or --txid.');
	if (required && values.id === undefined && values.txid === undefined) throw new Error('Specify --id or --txid.');
	if (values.txid !== undefined && !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(values.txid)) throw new Error('Invalid transaction UUID.');
	return { tx_id: values.id === undefined ? null : integer(values.id, 'id', 0xffffffff), tx_slate_id: values.txid || null };
}

function sendArgs(value, options) {
	if (options.selection && !['all', 'smallest'].includes(options.selection)) throw new Error('Selection must be all or smallest.');
	return { amount: value, amount_includes_fee: Boolean(options.amount_includes_fee),
		minimum_confirmations: String(integer(options.min_conf ?? '10', 'min_conf')),
		max_outputs: integer(options.max_outputs ?? '500', 'max_outputs'),
		num_change_outputs: integer(options.change_outputs ?? '1', 'change_outputs'),
		selection_strategy_is_use_all: options.selection === 'all', message: options.message || null,
		target_slate_version: 4, ttl_blocks: options.ttl_blocks === undefined ? null : String(integer(options.ttl_blocks, 'ttl_blocks')),
		payment_proof_recipient_address: null, address: options.slatepack_recipient || null,
		estimate_only: Boolean(options.estimate), exclude_change_outputs: false, minimum_confirmations_change_outputs: 10,
		send_args: null, outputs: null, slatepack_recipient: null, late_lock: Boolean(options['late-lock']),
		min_fee: options.min_fee === undefined ? null : integer(options.min_fee, 'min_fee') };
}

function recipient(address) {
	if (typeof address !== 'string' || !/^[a-z2-7]{56}$/.test(address)) throw new Error('Provide a canonical 56-character Slatepack address with --slatepack_recipient.');
	const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
	const decoded = [];
	let bits = 0, accumulator = 0;
	for (const char of address) {
		accumulator = (accumulator << 5) | alphabet.indexOf(char);
		bits += 5;
		if (bits >= 8) { bits -= 8; decoded.push((accumulator >>> bits) & 255); accumulator &= (1 << bits) - 1; }
	}
	const bytes = Buffer.from(decoded);
	const checksum = createHash('sha3-256').update('.onion checksum').update(bytes.subarray(0, 32)).update(Buffer.from([3])).digest();
	if (bytes[34] !== 3 || !bytes.subarray(32, 34).equals(checksum.subarray(0, 2))) throw new Error('Slatepack address checksum is invalid.');
	return address;
}

class WalletSession {
	#client;
	#token;
	#opened = false;
	#name = null;
	#password;
	#confirm;
	#progress;
	constructor(client, { password, confirm, progress = () => {} }) {
		this.#client = client; this.#password = password; this.#confirm = confirm; this.#progress = progress;
	}
	get opened() { return this.#opened; }
	async call(method, params = {}) {
		this.#progress(`Requesting ${method}...`);
		return this.#client.call(method, params);
	}
	async open(account, name = null, password) {
		if (this.#opened) throw new Error('Wallet is already open.');
		if (name !== null && typeof name !== 'string') throw new Error('Wallet name must be a string or null.');
		if (password === undefined) password = await this.#password();
		if (typeof password !== 'string') throw new Error('Wallet password must be a string.');
		this.#token = await this.call('open_wallet', { name, password });
		this.#opened = true;
		this.#name = name;
		if (account) await this.call('set_active_account', { token: this.#token, label: account });
		return { wallet: 'open' };
	}
	async close(name = this.#name) {
		if (this.#opened && name !== this.#name) throw new Error('Close the wallet name opened by this session.');
		if (!this.#opened) return { wallet: 'closed' };
		await this.call('close_wallet', { name });
		this.#token = undefined; this.#opened = false;
		this.#name = null;
		return { wallet: 'closed' };
	}
	async shutdown() {
		try { await this.close(); }
		finally { this.#token = undefined; this.#client.dispose(); }
	}
	needsWallet(command) { return Boolean(COMMANDS[command.name].wallet || (command.name === 'rpc' && TOKEN_METHODS.has(command.positionals[0]))); }
	async approve(message, yes) {
		if (!yes && !(await this.#confirm(message))) throw new Error('Command cancelled.');
	}
	async output(file, action, text = false) {
		const target = new OutputFile(file);
		try { const result = await action(); target.write(result, text); return { saved: target.path }; }
		finally { target.close(); }
	}
	async decoded(options, expected) {
		let text = contentText(options.file, options.content).trim();
		if (text.startsWith('"')) {
			text = inputJson(text);
			if (typeof text !== 'string') throw new Error('Expected a Slatepack string.');
		}
		if (text.startsWith('{')) {
			const slate = inputJson(text);
			if (!slate.id || !slate.version_info) throw new Error('Expected a versioned slate JSON object.');
			return { slate, content: null, sender: null, recipient: null };
		}
		const data = await this.call('decode_slatepack_message', { token: this.#token, message: text,
			address_index: options.address_index === undefined ? null : integer(options.address_index, 'address_index', 0xffffffff) });
		if (expected && data.content !== expected && data.content !== 'FullSlate') throw new Error(`Expected Slatepack purpose ${expected}.`);
		if (expected && (data.recipient || data.sender)) {
			const own = await this.call('get_wallet_public_address', { token: this.#token });
			if (!data.sender || data.recipient?.public_key !== own.public_key || data.sender.public_key === own.public_key) {
				throw new Error('The Slatepack is not an incoming message addressed to this wallet.');
			}
		}
		return data;
	}
	async staged(file, action) {
		const target = new OutputFile(file);
		let recovery;
		try {
			recovery = new OutputFile(`${file}.recovery.json`);
			const result = await action(value => recovery.write(value));
			target.write(result, typeof result === 'string');
			return { saved: target.path, recovery: recovery.path };
		} catch (error) {
			if (recovery) this.#progress(`Inspect the recovery file before retrying: ${display(recovery.path)}`);
			throw error;
		} finally { target.close(); recovery?.close(); }
	}
	async execute(command) {
		const { name, values: v, positionals: p } = command;
		if (name === 'help') return help(...p);
		if (name === 'exit') return { exit: true };
		if (name === 'open') return this.open(v.account, v.name);
		if (name === 'close') return this.close(v.name);
		if (this.needsWallet(command) && !this.#opened) throw new Error('Wallet is closed. Use open first.');
		if (v.out && !['send', 'finalize', 'invoice', 'pay', 'recover', 'rewind_hash', 'rpc'].includes(name)) {
			return this.output(v.out, () => this.execute({ ...command, values: { ...v, out: undefined } }));
		}
		const token = this.#token;
		if (v.account) await this.call('set_active_account', { token, label: v.account });
		let result;
		switch (name) {
		case 'info': {
			const [refreshed, value] = await this.call('retrieve_summary_info', { token, refresh_from_node: !v['no-refresh'], minimum_confirmations: integer(v.min_conf ?? '10', 'min_conf') });
			result = { refreshed, height: value.last_confirmed_height, minimum_confirmations: value.minimum_confirmations,
				total_mwc: formatAmount(value.total), spendable_mwc: formatAmount(value.amount_currently_spendable),
				locked_mwc: formatAmount(value.amount_locked), awaiting_confirmation_mwc: formatAmount(value.amount_awaiting_confirmation) };
			break;
		}
		case 'outputs': result = await this.call('retrieve_outputs', { token, include_spent: Boolean(v.show_spent), refresh_from_node: !v['no-refresh'], tx_id: null }); break;
		case 'txs': {
			const ids = transactionSelector(v, false);
			if (v.count !== undefined && (ids.tx_id !== null || ids.tx_slate_id !== null)) throw new Error('Use --count for a list, or select one transaction by ID.');
			const base = { token, refresh_from_node: !v['no-refresh'], show_last_four_days: Boolean(v.show_last_four_days) };
			result = v.count === undefined ? await this.call('retrieve_txs', { ...base, ...ids }) :
				await this.call('query_txs', { ...base, query: { limit: integer(v.count, 'count', 0xffffffff), sort_field: 'Id', sort_order: 'Desc' } });
			break;
		}
		case 'account':
			if (v.create && v.switch) throw new Error('Use --create or --switch.');
			if (v.create) { await this.approve(`Create account ${display(v.create)}?`, v.yes); result = await this.call('create_account_path', { token, label: v.create }); }
			else if (v.switch) result = await this.call('set_active_account', { token, label: v.switch });
			else result = await this.call('accounts', { token });
			break;
		case 'address': result = { slatepack: await this.call('get_wallet_public_address', { token }), mqs: await this.call('get_mqs_address', { token }) }; break;
		case 'node_height': result = await this.call('node_height', { token }); break;
		case 'send': {
			const args = sendArgs(amount(p[0]), v);
			if (v.estimate) { result = await this.call('init_send_tx', { token, args }); break; }
			const address = recipient(v.slatepack_recipient);
			await this.approve(`Create withdrawal of ${formatAmount(args.amount)} MWC to ${address}${v['late-lock'] ? ' with late locking' : ' and lock inputs'}?`, v.yes);
			return this.staged(v.dest || v.out, async save => {
				const slate = await this.call('init_send_tx', { token, args });
				save({ operation: 'send', slate, recipient: address, late_lock: args.late_lock });
				if (!args.late_lock) await this.call('tx_lock_outputs', { token, slate, participant_id: 0 });
				return this.call('encode_slatepack_message', { token, slate, content: 'SendInitial', recipient: address, address_index: null });
			});
		}
		case 'unpack': result = await this.decoded(v); break;
		case 'finalize': {
			const decoded = await this.decoded(v, 'SendResponse');
			const [, history] = await this.call('retrieve_txs', { token, refresh_from_node: false, tx_id: null, tx_slate_id: decoded.slate.id, show_last_four_days: false });
			const original = history.find(tx => tx.tx_slate_id === decoded.slate.id && tx.tx_type === 'TxSent');
			if (!original || original.confirmed) throw new Error('Expected an outstanding send transaction for this slate UUID.');
			if (original.address && /^[a-z2-7]{56}$/.test(original.address) && decoded.sender?.public_key !== original.address) {
				throw new Error('Expected an encrypted Slatepack reply from the stored withdrawal recipient.');
			}
			await this.approve(`Finalize transaction ${display(decoded.slate.id)} for ${formatAmount(decoded.slate.amount)} MWC${v.nopost ? ' without posting' : ' and broadcast it'}?`, v.yes);
			const saved = await this.staged(v.dest || v.out, async save => {
				await this.call('verify_slate_messages', { token, slate: decoded.slate });
				const finalized = await this.call('finalize_tx', { token, slate: decoded.slate });
				save({ operation: 'finalize', slate: finalized });
				return finalized;
			});
			if (!v.nopost) {
				const tx = await this.call('get_stored_tx', { token, tx: { tx_slate_id: decoded.slate.id } });
				if (!tx) throw new Error('No stored transaction was returned; finalized slate was saved.');
				await this.call('post_tx', { token, tx, fluff: Boolean(v.fluff) });
			}
			return { ...saved, tx_slate_id: decoded.slate.id, posted: !v.nopost };
		}
		case 'post': {
			const data = inputJson(contentText(v.input, v.content, '--input'));
			const tx = data.tx || data;
			if (!tx.body || typeof tx.offset !== 'string') throw new Error('Expected finalized transaction JSON or a slate containing tx.');
			await this.approve('Broadcast the finalized transaction from this file?', v.yes);
			result = await this.call('post_tx', { token, tx, fluff: Boolean(v.fluff) }); break;
		}
		case 'repost': {
			const ids = transactionSelector(v);
			const fetch = async () => {
				const tx = await this.call('get_stored_tx', { token, tx: { id: ids.tx_id, tx_slate_id: ids.tx_slate_id } });
				if (!tx) throw new Error('No stored transaction was found.');
				return tx;
			};
			if (v.dumpfile) return this.output(v.dumpfile, fetch);
			await this.approve(`Rebroadcast transaction ${display(ids)}?`, v.yes);
			result = await this.call('post_tx', { token, tx: await fetch(), fluff: Boolean(v.fluff) }); break;
		}
		case 'cancel': {
			const ids = transactionSelector(v);
			await this.approve(`Cancel unconfirmed transaction ${display(ids)}?`, v.yes);
			result = await this.call('cancel_tx', { token, ...ids }); break;
		}
		case 'invoice': {
			const value = amount(p[0]), address = recipient(v.slatepack_recipient);
			await this.approve(`Create an invoice for ${formatAmount(value)} MWC addressed to ${address}?`, v.yes);
			return this.staged(v.dest || v.out, async save => {
				const slate = await this.call('issue_invoice_tx', { token, args: {
					amount: value, message: v.message || null, target_slate_version: 4, slatepack_recipient: address,
				} });
				save({ operation: 'invoice', slate, recipient: address });
				return typeof slate === 'string' ? slate : this.call('encode_slatepack_message', { token, slate, content: 'InvoiceInitial', recipient: address, address_index: null });
			});
		}
		case 'pay': {
			const data = await this.decoded(v, 'InvoiceInitial');
			const args = sendArgs(String(data.slate.amount), v);
			await this.approve(`Pay invoice ${display(data.slate.id)} for ${formatAmount(args.amount)} MWC?`, v.yes);
			return this.staged(v.dest || v.out, async save => {
				await this.call('verify_slate_messages', { token, slate: data.slate });
				const response = await this.call('process_invoice_tx', { token, slate: data.slate, args });
				save({ operation: 'pay', slate: response, recipient: data.sender });
				await this.call('tx_lock_outputs', { token, slate: response, participant_id: 1 });
				if (data.sender) return this.call('encode_slatepack_message', { token, slate: response, content: 'InvoiceResponse', recipient: data.sender, address_index: null });
				return response;
			});
		}
		case 'scan':
			await this.approve(v.delete_unconfirmed ? 'Scan and delete unconfirmed wallet records/unlock their outputs?' : 'Scan and reconcile wallet data?', v.yes);
			result = await this.call('scan', { token, start_height: integer(v.start_height ?? '1', 'start_height'), delete_unconfirmed: Boolean(v.delete_unconfirmed) }); break;
		case 'export_proof': return this.output(p[0], () => this.call('retrieve_payment_proof', { token, ...transactionSelector(v) }));
		case 'verify_proof': result = await this.call('verify_payment_proof', { token, proof: inputJson(contentText(p[0], v.content, 'FILE')) }); break;
		case 'recover': return this.output(v.out, async () => this.call('get_mnemonic', { name: v.name ?? this.#name, password: await this.#password() }), true);
		case 'rewind_hash': return this.output(v.out, () => this.call('get_rewind_hash', { token }), true);
		case 'rpc': {
			const method = p[0];
			if (CLOSED_METHODS.has(method) && this.#opened) throw new Error('Close the wallet before this lifecycle method.');
			const params = rpcParameters(method, v);
			if (method === 'open_wallet' || method === 'close_wallet') {
				const action = () => method === 'open_wallet' ? this.open(undefined, params.name, params.password) : this.close(params.name);
				return v.out ? this.output(v.out, action) : action();
			}
			if (TOKEN_METHODS.has(method)) params.token = token;
			if (PRIVATE_RESULTS.has(method) && !v.out) throw new Error('This secret-bearing response requires --out to a new private file.');
			if (!READ_METHODS.has(method)) await this.approve(`Execute owner API mutation ${method}?`, v.yes);
			if (v.out) return this.output(v.out, () => this.call(method, params));
			return this.call(method, params);
		}
		default: throw new Error('Command is not implemented.');
		}
		return result ?? { ok: true };
	}
}

module.exports = { COMMANDS, TOKEN_METHODS, parseCommand, help, sendArgs, transactionSelector, recipient, WalletSession };
