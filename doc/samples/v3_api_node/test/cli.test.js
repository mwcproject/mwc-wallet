// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { PassThrough } = require('node:stream');
const { splitLine, amount, formatAmount, OutputFile, Terminal, InputClosed } = require('../src/cli_io');
const { COMMANDS, TOKEN_METHODS, parseCommand, recipient, WalletSession } = require('../src/cli_commands');
const { RPC_PARAMETERS, rpcParameters } = require('../src/cli_rpc');
const { mockWallet } = require('./mock_wallet');

const UUID = '12345678-1234-1234-1234-123456789abc';
const slate = { id: UUID, version_info: { version: 3 }, amount: '1000000000', fee: '1000000', tx: null };
const transaction = { offset: '00'.repeat(32), body: { inputs: [], outputs: [], kernels: [] } };
// Real, public test onion addresses with valid checksums.
function onion(byte) {
	const publicKey = Buffer.alloc(32, byte);
	const hash = crypto.createHash('sha3-256').update('.onion checksum').update(publicKey).update(Buffer.from([3])).digest();
	const bytes = Buffer.concat([publicKey, hash.subarray(0, 2), Buffer.from([3])]);
	const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
	let bits = 0, value = 0, text = '';
	for (const byte of bytes) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; text += alphabet[(value >>> bits) & 31]; value &= (1 << bits) - 1; } }
	return text;
}
const RECIPIENT = onion(1), OWN = onion(2);

function temp(t) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mwc-owner-cli-test-'));
	t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
	return dir;
}
function session(options = {}) {
	const calls = [];
	const client = { connected: true, dispose() { this.connected = false; }, async call(method, params) {
		calls.push({ method, params });
		if (options.call) return options.call(method, params);
		if (method === 'open_wallet') return 'private-wallet-token';
		return null;
	} };
	const cli = new WalletSession(client, { password: async () => 'private-password', confirm: async () => true, ...options });
	return { cli, calls, client, execute: args => cli.execute(parseCommand(args)) };
}

const balance = { total: '1000000001', amount_currently_spendable: '1000000000', amount_locked: '0', amount_awaiting_confirmation: '1', last_confirmed_height: '25', minimum_confirmations: '10' };

test('amounts use exact nanoMWC arithmetic and reject unsafe/ambiguous input', () => {
	assert.equal(amount('1.000000001'), '1000000001');
	assert.equal(amount('18446744073.709551615'), '18446744073709551615');
	assert.equal(formatAmount('1000000001'), '1.000000001');
	for (const value of ['-1', '0', '1e3', 'NaN', '1.0000000001', '18446744073.709551616', 'max']) assert.throws(() => amount(value));
});

test('interactive tokenization supports quoted paths without shell execution', () => {
	assert.deepEqual(splitLine('account --create "exchange deposits"'), ['account', '--create', 'exchange deposits']);
	assert.deepEqual(splitLine("unpack --file '/tmp/slate reply'"), ['unpack', '--file', '/tmp/slate reply']);
	assert.deepEqual(splitLine('help $(touch /tmp/nope)'), ['help', '$(touch', '/tmp/nope)']);
	assert.throws(() => splitLine('open "unfinished'));
});

test('unsupported commands and duplicate/unknown options are rejected', () => {
	for (const args of [['receive'], ['listen'], ['finalize_invoice'], ['info', '--typo'], ['info', '--min_conf', '1', '--min_conf', '2'], ['open', '--password', 'secret'], ['rpc', '__proto__'], ['rpc', 'init_secure_api']]) assert.throws(() => parseCommand(args));
	assert.equal(parseCommand(['info', '--help']).name, 'help');
});

test('pay rejects options the invoice API rejects or does not apply', () => {
	for (const args of [['--ttl_blocks', '10'], ['--amount_includes_fee'], ['--estimate'], ['--late-lock']]) {
		assert.throws(() => parseCommand(['pay', '--file', 'invoice', '--dest', 'response', ...args]));
	}
});

test('wallet lifecycle keeps token private and queries require an open wallet', async () => {
	const s = session({ call: async method => method === 'open_wallet' ? 'private-token' : method === 'retrieve_summary_info' ? [false, balance] : null });
	await assert.rejects(s.execute(['info']), /closed/);
	assert.deepEqual(await s.execute(['open']), { wallet: 'open' });
	const result = await s.execute(['info', '--no-refresh', '--min_conf', '1440']);
	assert.equal(result.total_mwc, '1.000000001');
	assert.equal(result.refreshed, false);
	assert.equal(s.calls[1].params.minimum_confirmations, 1440);
	assert.equal(s.calls[1].params.token, 'private-token');
	await s.cli.shutdown();
	assert.deepEqual(s.calls.at(-1), { method: 'close_wallet', params: { name: null } });
	assert.equal(s.client.connected, false);
});

test('wrong password never triggers a close of someone else’s wallet', async () => {
	const s = session({ call: async () => { throw new Error('wrong password'); } });
	await assert.rejects(s.execute(['open']), /wrong password/);
	await s.cli.shutdown();
	assert.deepEqual(s.calls.map(call => call.method), ['open_wallet']);
});

test('cancel declined by user makes no mutation call', async () => {
	const s = session({ confirm: async () => false });
	await s.execute(['open']);
	await assert.rejects(s.execute(['cancel', '--id', '3']), /cancelled/);
	assert.deepEqual(s.calls.map(call => call.method), ['open_wallet']);
});

test('output files are private, exclusive, and reject symlinks', t => {
	const dir = temp(t), file = path.join(dir, 'result.json');
	const out = new OutputFile(file); out.write({ ok: true }); out.close();
	if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
	assert.throws(() => new OutputFile(file), /new filename/);
	fs.symlinkSync(file, path.join(dir, 'link'));
	assert.throws(() => new OutputFile(path.join(dir, 'link')), /new filename/);
});

test('send rejects a mistyped onion checksum before creating a transaction', async t => {
	const s = session(); await s.execute(['open']);
	assert.equal(recipient(RECIPIENT), RECIPIENT);
	await assert.rejects(s.execute(['send', '1', '--dest', path.join(temp(t), 'send'), '--slatepack_recipient', 'a'.repeat(56), '--yes']), /checksum/);
	assert.equal(s.calls.length, 1);
});

for (const late of [false, true]) test(`send uses ${late ? 'late' : 'early'} locking and saves a recoverable slate`, async t => {
	const s = session({ call: async method => ({ open_wallet: 'token', init_send_tx: slate, encode_slatepack_message: 'BEGINSLATEPACK. example .ENDSLATEPACK.' })[method] ?? null });
	await s.execute(['open']);
	const dest = path.join(temp(t), 'send.slatepack');
	const result = await s.execute(['send', '1', '--dest', dest, '--slatepack_recipient', RECIPIENT, '--change_outputs', '3', '--min_conf', '1440', '--yes', ...(late ? ['--late-lock'] : [])]);
	assert.equal(result.saved, dest);
	assert.equal(s.calls.find(call => call.method === 'init_send_tx').params.args.amount, '1000000000');
	assert.equal(s.calls.find(call => call.method === 'init_send_tx').params.args.num_change_outputs, 3);
	assert.deepEqual(s.calls.map(call => call.method), ['open_wallet', 'init_send_tx', ...(late ? [] : ['tx_lock_outputs']), 'encode_slatepack_message']);
	assert.equal(JSON.parse(fs.readFileSync(`${dest}.recovery.json`)).slate.id, UUID);
	assert.match(fs.readFileSync(dest, 'utf8'), /BEGINSLATEPACK/);
});

test('existing send output is rejected before the mutation', async t => {
	const s = session(); await s.execute(['open']);
	const dest = path.join(temp(t), 'already-exists'); fs.writeFileSync(dest, 'keep');
	await assert.rejects(s.execute(['send', '1', '--dest', dest, '--slatepack_recipient', RECIPIENT, '--yes']), /new filename/);
	assert.equal(s.calls.length, 1);
	assert.equal(fs.readFileSync(dest, 'utf8'), 'keep');
});

test('generic and raw mutation output conflicts are rejected before changing wallet state', async t => {
	const s = session(); await s.execute(['open']);
	const dest = path.join(temp(t), 'existing.json'); fs.writeFileSync(dest, 'keep');
	for (const args of [['cancel', '--id', '1'], ['rpc', 'cancel_tx']]) {
		await assert.rejects(s.execute([...args, '--out', dest, '--yes']), /new filename/);
	}
	assert.deepEqual(s.calls.map(call => call.method), ['open_wallet']);
	assert.equal(fs.readFileSync(dest, 'utf8'), 'keep');
});

test('partial send failure retains the slate and makes no automatic retry or cancellation', async t => {
	const s = session({ call: async method => { if (method === 'init_send_tx') return slate; if (method === 'encode_slatepack_message') throw new Error('transport timeout'); return 'token'; } });
	await s.execute(['open']); const dest = path.join(temp(t), 'send');
	await assert.rejects(s.execute(['send', '1', '--dest', dest, '--slatepack_recipient', RECIPIENT, '--late-lock', '--yes']), /timeout/);
	assert.equal(JSON.parse(fs.readFileSync(`${dest}.recovery.json`)).slate.id, UUID);
	assert.deepEqual(s.calls.map(call => call.method), ['open_wallet', 'init_send_tx', 'encode_slatepack_message']);
});

for (const inline of [false, true]) for (const nopost of [false, true]) test(`finalize ${inline ? 'inline' : 'file'} response ${nopost ? 'saves without posting' : 'posts only after saving the finalized slate'}`, async t => {
	const dir = temp(t), input = path.join(dir, 'reply'), dest = path.join(dir, 'finalized.json');
	fs.writeFileSync(input, 'BEGINSLATEPACK. reply .ENDSLATEPACK.');
	const s = session({ call: async (method, params) => {
		switch (method) {
			case 'open_wallet': return 'token';
			case 'decode_slatepack_message': return { slate, content: 'SendResponse', sender: { public_key: RECIPIENT }, recipient: { public_key: OWN } };
			case 'get_wallet_public_address': return { public_key: OWN };
			case 'retrieve_txs': return [false, [{ tx_slate_id: UUID, tx_type: 'TxSent', address: RECIPIENT, confirmed: false }]];
			case 'finalize_tx': return { ...slate, tx: transaction };
			case 'get_stored_tx': return transaction;
			case 'post_tx': assert.equal(JSON.parse(fs.readFileSync(dest)).id, UUID); assert.deepEqual(params.tx, transaction); return null;
			default: return null;
		}
	} });
	await s.execute(['open']);
	const result = await s.execute(['finalize', ...(inline ? ['--content', 'BEGINSLATEPACK. reply .ENDSLATEPACK.'] : ['--file', input]), '--dest', dest, '--yes', ...(nopost ? ['--nopost'] : [])]);
	assert.equal(result.posted, !nopost);
	assert.equal(s.calls.some(call => call.method === 'post_tx'), !nopost);
});

for (const problem of ['purpose', 'direction', 'sender']) test(`finalize rejects a response with incorrect ${problem}`, async t => {
	const input = path.join(temp(t), 'reply'); fs.writeFileSync(input, 'BEGINSLATEPACK. reply .ENDSLATEPACK.');
	const s = session({ call: async method => {
		if (method === 'decode_slatepack_message') return { slate, content: problem === 'purpose' ? 'InvoiceInitial' : 'SendResponse', sender: { public_key: problem === 'direction' ? OWN : RECIPIENT }, recipient: { public_key: OWN } };
		if (method === 'get_wallet_public_address') return { public_key: OWN };
		if (method === 'retrieve_txs') return [false, [{ tx_slate_id: UUID, tx_type: 'TxSent', address: onion(3), confirmed: false }]];
		return 'token';
	} });
	await s.execute(['open']);
	await assert.rejects(s.execute(['finalize', '--file', input, '--dest', `${input}.final`, '--yes']));
	assert.equal(s.calls.some(call => call.method === 'finalize_tx'), false);
});

test('invoice accepts both plain and already encoded owner responses', async t => {
	const dir = temp(t);
	for (const encoded of [false, true]) {
		const s = session({ call: async method => method === 'issue_invoice_tx' ? (encoded ? 'BEGINSLATEPACK. invoice' : slate) : method === 'encode_slatepack_message' ? 'BEGINSLATEPACK. encoded invoice' : 'token' });
		await s.execute(['open']); const dest = path.join(dir, String(encoded));
		await s.execute(['invoice', '1', '--dest', dest, '--slatepack_recipient', RECIPIENT, '--yes']);
		assert.match(fs.readFileSync(dest, 'utf8'), /^BEGINSLATEPACK/);
	}
});

test('pay signs the invoice, locks participant 1 and returns a response without posting', async t => {
	const dir = temp(t), input = path.join(dir, 'invoice'); fs.writeFileSync(input, 'BEGINSLATEPACK. invoice');
	const s = session({ call: async method => {
		if (method === 'decode_slatepack_message') return { slate, content: 'InvoiceInitial', sender: { public_key: RECIPIENT }, recipient: { public_key: OWN } };
		if (method === 'get_wallet_public_address') return { public_key: OWN };
		if (method === 'process_invoice_tx') return slate;
		if (method === 'encode_slatepack_message') return 'BEGINSLATEPACK. response';
		return 'token';
	} });
	await s.execute(['open']);
	await s.execute(['pay', '--content', fs.readFileSync(input, 'utf8'), '-c', '1440', '--dest', path.join(dir, 'response'), '--yes']);
	assert.equal(s.calls.find(call => call.method === 'tx_lock_outputs').params.participant_id, 1);
	assert.equal(s.calls.find(call => call.method === 'process_invoice_tx').params.args.minimum_confirmations, '1440');
	assert.equal(s.calls.some(call => call.method === 'post_tx'), false);
});

test('raw API injects the current token and confines secret results to files', async t => {
	const dir = temp(t), params = path.join(dir, 'params.json'); fs.writeFileSync(params, '{}');
	const s = session(); await s.execute(['open']);
	await s.execute(['rpc', 'accounts', '--params', params]);
	assert.equal(s.calls.at(-1).params.token, 'private-wallet-token');
	await assert.rejects(s.execute(['rpc', 'get_rewind_hash']), /requires --out/);
	fs.writeFileSync(params, '{"token":"different-wallet"}');
	await assert.rejects(s.execute(['rpc', 'accounts', '--params', params]), /Omit token/);
	await assert.rejects(s.execute(['rpc', 'delete_wallet', '--yes']), /Close the wallet/);
});

test('token-method coverage matches Rust owner signatures', () => {
	const source = fs.readFileSync(path.resolve(__dirname, '../../../../api/src/owner_rpc_v3.rs'), 'utf8').split('impl<')[0];
	const methods = [...source.matchAll(/\n\s*fn (\w+)\(([\s\S]*?)\)\s*->[^;]*;/g)].filter(match => /\btoken:\s*Token/.test(match[2])).map(match => match[1]);
	assert.deepEqual([...TOKEN_METHODS].sort(), methods.sort());
});

test('every declared v3 method and parameter is available to rpc', async t => {
	const source = fs.readFileSync(path.resolve(__dirname, '../../../../api/src/owner_rpc_v3.rs'), 'utf8').split('impl<')[0];
	const methods = [...source.matchAll(/\n\s*fn (\w+)\(([\s\S]*?)\)\s*->[^;]*;/g)];
	assert.deepEqual(Object.keys(RPC_PARAMETERS).sort(), methods.map(match => match[1]).sort());
	const dir = temp(t);
	for (const [, method, signature] of methods) {
		const names = [...signature.matchAll(/(\w+):\s*[^,\n]+/g)].map(match => match[1]);
		assert.deepEqual(RPC_PARAMETERS[method], names);
		if (['init_secure_api', 'open_wallet', 'close_wallet'].includes(method)) continue;
		const params = Object.fromEntries(names.filter(name => name !== 'token').map(name => [name, `test-${name}`]));
		const s = session();
		if (TOKEN_METHODS.has(method)) await s.execute(['open']);
		await s.execute(['rpc', method, '--params-json', JSON.stringify(params), '--out', path.join(dir, method), '--yes']);
		assert.deepEqual(s.calls.at(-1), { method, params: { ...params, ...(TOKEN_METHODS.has(method) ? { token: 'private-wallet-token' } : {}) } });
	}
});

test('rpc accepts all nested send arguments and merges distinct named JSON values', async t => {
	const dir = temp(t), file = path.join(dir, 'params.json');
	fs.writeFileSync(file, '{"refresh_from_node":false}');
	assert.deepEqual(rpcParameters('retrieve_outputs', { params: file, param: ['include_spent=true', 'tx_id=23'] }),
		{ refresh_from_node: false, include_spent: true, tx_id: 23 });
	const args = { src_acct_name: 'exchange', amount: '1000000001', minimum_confirmations: '1440',
		max_outputs: 20, num_change_outputs: 3, selection_strategy_is_use_all: false, outputs: ['output-1'],
		exclude_change_outputs: true, minimum_confirmations_change_outputs: 10, min_fee: 123,
		payment_proof_recipient_address: RECIPIENT, message: 'test', send_args: { method: 'file', dest: 'test', finalize: false, post_tx: false } };
	const s = session(); await s.execute(['open']);
	await s.execute(['rpc', 'init_send_tx', '--param', `args=${JSON.stringify(args)}`, '--yes']);
	assert.deepEqual(s.calls.at(-1).params.args, args);
	const big = rpcParameters('init_send_tx', { 'params-json': '{"args":{"amount":18446744073709551615}}' });
	assert.equal(big.args.amount, '18446744073709551615');
});

test('rpc rejects ambiguous, misspelled or caller-supplied session parameters', () => {
	for (const options of [
		{ params: 'unused', 'params-json': '{}' }, { 'params-json': '[]' }, { 'params-json': '{"token":"secret"}' },
		{ param: ['tx_id=1', 'tx_id=2'] }, { 'params-json': '{"tx_id":1}', param: ['tx_id=2'] },
		{ param: ['tx_id=invalid'] }, { param: ['__proto__={}'] }, { param: ['id=1'] },
		{ param: ['minimum_confirmations=10'] }, { param: ['tx_id'] },
	]) assert.throws(() => rpcParameters('retrieve_outputs', options));
});

test('rpc lifecycle honors name/password and keeps token and close state private', async () => {
	const s = session();
	assert.deepEqual(await s.execute(['rpc', 'open_wallet', '--params-json', '{"name":"test-wallet","password":"supplied-password"}']), { wallet: 'open' });
	assert.deepEqual(s.calls[0].params, { name: 'test-wallet', password: 'supplied-password' });
	await s.execute(['rpc', 'accounts']);
	assert.equal(s.calls.at(-1).params.token, 'private-wallet-token');
	await assert.rejects(s.execute(['rpc', 'close_wallet', '--param', 'name="different"']), /wallet name/);
	assert.equal(s.cli.opened, true);
	await s.execute(['rpc', 'close_wallet', '--param', 'name="test-wallet"']);
	assert.equal(s.cli.opened, false);
	assert.deepEqual(s.calls.at(-1).params, { name: 'test-wallet' });
});

test('inline Slatepacks and JSON slates use the same decoding path as files', async t => {
	const s = session({ call: async method => method === 'decode_slatepack_message' ? { slate, content: 'FullSlate' } : 'token' });
	await s.execute(['open']);
	for (const content of ['BEGINSLATEPACK. message .ENDSLATEPACK.', JSON.stringify('BEGINSLATEPACK. message .ENDSLATEPACK.')]) {
		await s.execute(['unpack', '--content', content, '--address_index', '7']);
		assert.deepEqual(s.calls.at(-1).params, { token: 'token', message: 'BEGINSLATEPACK. message .ENDSLATEPACK.', address_index: 7 });
	}
	assert.deepEqual((await s.execute(['unpack', '--content', JSON.stringify(slate)])).slate, slate);
	const file = path.join(temp(t), 'slate.json'); fs.writeFileSync(file, JSON.stringify(slate));
	assert.deepEqual((await s.execute(['unpack', '--file', file])).slate, slate);
	const before = s.calls.length;
	for (const argv of [['unpack'], ['unpack', '--file', file, '--content', 'ambiguous'], ['post', '--input', file, '--content', '{}', '--yes'], ['verify_proof', file, '--content', '{}']]) {
		await assert.rejects(s.execute(argv), /exactly one/);
	}
	assert.equal(s.calls.length, before);
});

test('inline transaction and proof JSON are forwarded unchanged', async () => {
	const s = session(); await s.execute(['open']);
	await s.execute(['post', '--content', JSON.stringify(transaction), '--yes']);
	assert.deepEqual(s.calls.at(-1), { method: 'post_tx', params: { token: 'private-wallet-token', tx: transaction, fluff: false } });
	const proof = { amount: '123', note: 'test proof' };
	await s.execute(['verify_proof', '--content', JSON.stringify(proof)]);
	assert.deepEqual(s.calls.at(-1).params.proof, proof);
});

test('command prompt is displayed and multiline quoted pastes are preserved', async () => {
	const input = new PassThrough(), output = new PassThrough(); let rendered = '';
	output.on('data', value => { rendered += value; });
	const terminal = new Terminal(input, output);
	try {
		const answer = terminal.command();
		assert.ok(rendered.includes('mwc-wallet> '));
		input.write('unpack --content "BEGINSLATEPACK.\nabc\n.ENDSLATEPACK."\n');
		assert.deepEqual(await answer, ['unpack', '--content', 'BEGINSLATEPACK.\nabc\n.ENDSLATEPACK.']);
		const next = terminal.command();
		input.write('help\n');
		assert.deepEqual(await next, ['help']);
		assert.ok(rendered.includes('...> '));
	} finally { terminal.close(); }
});

test('hidden password prompt does not echo the password', async () => {
	const input = new PassThrough(), output = new PassThrough(); let rendered = '';
	output.on('data', value => { rendered += value; });
	const terminal = new Terminal(input, output);
	const answer = terminal.ask('Wallet password: ', true);
	input.write('super-secret-password\r');
	assert.equal(await answer, 'super-secret-password');
	terminal.close();
	assert.equal(rendered.includes('super-secret-password'), false);
	assert.ok(rendered.includes('Wallet password:'));
});

test('EOF during a password prompt rejects promptly', async () => {
	const input = new PassThrough(), output = new PassThrough();
	const terminal = new Terminal(input, output);
	const answer = terminal.ask('Password: ', true);
	input.end();
	await assert.rejects(answer, InputClosed);
});

async function childCli(t, args, mock) {
	const dir = temp(t), secret = path.join(dir, 'secret'); fs.writeFileSync(secret, mock.secret, { mode: 0o600 });
	const child = spawn(process.execPath, [path.resolve(__dirname, '../src/cli.js'), ...args], {
		env: { ...process.env, MWC_OWNER_API_URL: mock.url, MWC_OWNER_API_SECRET_FILE: secret, MWC_WALLET_PASSWORD: 'mock-password', MWC_API_DEBUG: '0' },
	});
	let stdout = '', stderr = '';
	child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
	child.stdin.end();
	const [code] = await once(child, 'close');
	return { code, stdout, stderr };
}

test('single-command CLI performs encrypted open/query/close and prints redacted JSON requests by default', async t => {
	const mock = await mockWallet(t, { result: request => request.method === 'open_wallet' ? 'mock-token' : request.method === 'retrieve_summary_info' ? [true, balance] : null });
	const result = await childCli(t, ['info', '--min_conf', '1440'], mock);
	assert.equal(result.code, 0, result.stderr);
	assert.equal(JSON.parse(result.stdout).spendable_mwc, '1.000000000');
	assert.deepEqual(mock.requests.map(request => request.method), ['open_wallet', 'retrieve_summary_info', 'close_wallet']);
	assert.match(result.stderr, /Requesting retrieve_summary_info/);
	assert.equal(result.stdout.includes('mock-token'), false);
	const records = result.stderr.split('\n').filter(line => line.startsWith('[wallet-api] ')).map(line => JSON.parse(line.slice('[wallet-api] '.length)));
	assert.deepEqual(records.map(record => record.method), ['init_secure_api', 'open_wallet', 'retrieve_summary_info', 'close_wallet']);
	assert.ok(records.every(record => record.direction === 'request'));
	assert.equal(records[2].body.params.minimum_confirmations, 1440);
	assert.equal(records[2].body.params.token, '[REDACTED]');
	for (const secret of ['mock-password', 'mock-token', mock.secret]) assert.equal(result.stderr.includes(secret), false);
});

test('single-command account selection happens once before querying', async t => {
	const mock = await mockWallet(t, { result: request => request.method === 'open_wallet' ? 'mock-token' : request.method === 'retrieve_summary_info' ? [true, balance] : null });
	const result = await childCli(t, ['info', '--account', 'exchange'], mock);
	assert.equal(result.code, 0, result.stderr);
	assert.deepEqual(mock.requests.map(request => request.method), ['open_wallet', 'set_active_account', 'retrieve_summary_info', 'close_wallet']);
	assert.equal(mock.requests[1].params.label, 'exchange');
});

test('noninteractive mutation requires --yes and closes the wallet on refusal', async t => {
	const mock = await mockWallet(t, { result: () => 'mock-token' });
	const result = await childCli(t, ['cancel', '--id', '1'], mock);
	assert.equal(result.code, 1);
	assert.match(result.stderr, /--yes/);
	assert.deepEqual(mock.requests.map(request => request.method), ['open_wallet', 'close_wallet']);
});
