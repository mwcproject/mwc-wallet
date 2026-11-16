// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { inspect } = require('node:util');
const { spawn } = require('node:child_process');
const { OwnerClient, RpcError, encrypt, decrypt, parseJson } = require('../src/client');
const { traceLine } = require('../src/logging');
const examples = require('../src/examples');
const fixture = require('./fixtures/wire.json');

const { mockWallet } = require('./mock_wallet');

test('wire encryption matches Rust-generated fixture; Rust response decrypts', () => {
	const key = Buffer.from(fixture.key_hex, 'hex');
	// Rust serde_json emits sorted object keys; encrypt the same JSON order.
	const sort = value => value && !Array.isArray(value) && typeof value === 'object'
		? Object.fromEntries(Object.keys(value).sort().map(key => [key, sort(value[key])])) : value;
	assert.deepEqual(encrypt(key, '7', sort(fixture.request_value), Buffer.from(fixture.request.params.nonce, 'hex')), fixture.request.params);
	assert.deepEqual(decrypt(key, '7', fixture.response.result.Ok), fixture.response_value);
});

test('Basic auth, ECDH, encrypted open/query/close and unique IDs/nonces', async t => {
	const { client, requests } = await mockWallet(t);
	await client.connect();
	await examples.open_wallet(client, { password: 'mock-password' });
	const result = await examples.retrieve_txs(client, { token: 'mock-token', show_last_four_days: true });
	assert.equal(result.params.show_last_four_days, true);
	await examples.close_wallet(client);
	assert.deepEqual(requests.map(item => item.method), ['open_wallet', 'retrieve_txs', 'close_wallet']);
	assert.equal(inspect(client).includes('mock-owner-secret'), false);
});

test('HTTP authentication failure is reported', async t => {
	const { client } = await mockWallet(t, { client: { secret: 'wrong' } });
	await assert.rejects(client.connect(), /HTTP status 401/);
});

for (const [name, outer, inner] of [
	['changed outer ID', value => ({ ...value, id: 'wrong' })],
	['changed outer version', value => ({ ...value, jsonrpc: '1.0' })],
	['short nonce', value => { value.result.Ok.nonce = '00'; return value; }],
	['malformed base64', value => { value.result.Ok.body_enc += '!'; return value; }],
	['changed ciphertext/tag', value => { const data = Buffer.from(value.result.Ok.body_enc, 'base64'); data[0] ^= 1; value.result.Ok.body_enc = data.toString('base64'); return value; }],
	['wrong inner ID', null, value => ({ ...value, id: 'wrong' })],
	['ambiguous inner response', null, value => ({ ...value, error: { code: -1 } })],
	['unexpected result shape', null, value => ({ ...value, result: { unexpected: true } })],
]) {
	test(`rejects ${name} and discards the session`, async t => {
		const { client } = await mockWallet(t, { outer, inner });
		await client.connect();
		await assert.rejects(client.call('accounts', { token: null }));
		await assert.rejects(client.call('accounts', { token: null }), /connect\(\)/);
	});
}

test('rejects response reflected as a request, wrong key, and replay under a new ID', () => {
	const key = Buffer.from(fixture.key_hex, 'hex');
	assert.throws(() => decrypt(key, '7', fixture.request.params), /authentication/);
	assert.throws(() => decrypt(Buffer.alloc(32, 1), '7', fixture.response.result.Ok), /authentication/);
	assert.throws(() => decrypt(key, '8', fixture.response.result.Ok), /authentication/);
});

test('encrypted RPC error reports code without disclosing the server message', async t => {
	const { client } = await mockWallet(t, { inner: value => ({ jsonrpc: '2.0', id: value.id, error: { code: -32099, message: 'secret-password\u001b[31m' } }) });
	await client.connect();
	await assert.rejects(client.call('open_wallet', { password: 'secret-password' }), error => {
		assert.ok(error instanceof RpcError);
		assert.equal(error.code, -32099);
		assert.equal(inspect(error).includes('secret-password'), false);
		return true;
	});
});

test('rejects concurrent calls and use after disposal', async t => {
	const { client } = await mockWallet(t);
	await client.connect();
	const first = client.call('accounts', { token: null });
	await assert.rejects(client.call('accounts', { token: null }), /previous wallet request/);
	await first;
	client.dispose();
	await assert.rejects(client.call('accounts'), /disposed/);
});

test('refuses unsafe connection settings before network activity', () => {
	for (const url of ['http://example.com/v3/owner', 'http://localhost/v3/owner', 'ftp://127.0.0.1/v3/owner', 'https://user:pass@example.com/v3/owner', 'https://example.com/v3/owner?secret=x', 'https://example.com/wrong']) {
		assert.throws(() => new OwnerClient({ url, secret: 'mock' }));
	}
	assert.throws(() => new OwnerClient({ url: 'http://127.0.0.1/v3/owner', secret: '' }));
	assert.throws(() => new OwnerClient({ url: 'http://127.0.0.1/v3/owner', secret: 'mock', timeoutMs: NaN }));
});

test('invalid curve point fails the handshake', async t => {
	const { client } = await mockWallet(t, { publicKey: `02${'ff'.repeat(32)}` });
	await assert.rejects(client.connect(), /ECDH/);
});

test('redirects are refused', async t => {
	const { client } = await mockWallet(t, { http: (request, response) => response.writeHead(302, { Location: 'http://127.0.0.1:1/stolen' }).end() });
	await assert.rejects(client.connect(), /HTTP status 302/);
});

test('timeout is bounded and no request is retried', async t => {
	let calls = 0;
	const { client } = await mockWallet(t, { client: { timeoutMs: 50 }, http: () => { calls++; } });
	await assert.rejects(client.connect(), /timed out/);
	assert.equal(calls, 1);
});

test('response size is bounded', async t => {
	const { client } = await mockWallet(t, { client: { maxResponseBytes: 1024 }, http: (request, response) => response.end('x'.repeat(2048)) });
	await assert.rejects(client.connect(), /size limit/);
});

test('invalid JSON is rejected without reflecting its contents', async t => {
	const { client } = await mockWallet(t, { http: (request, response) => response.end('private-secret invalid JSON') });
	await assert.rejects(client.connect(), error => /Invalid JSON/.test(error.message) && !error.message.includes('private-secret'));
});

test('large returned integers retain all digits; unsafe outgoing amounts fail', async t => {
	assert.equal(parseJson('{"amount":18446744073709551615}').amount, '18446744073709551615');
	const { client, requests } = await mockWallet(t);
	await client.connect();
	await assert.rejects(client.call('init_send_tx', { args: { amount: Number.MAX_SAFE_INTEGER + 1 } }), /decimal strings/);
	assert.equal(requests.length, 0);
});

test('every current OwnerRpcV3 method and parameter has an example', async () => {
	const source = fs.readFileSync(path.resolve(__dirname, '../../../../api/src/owner_rpc_v3.rs'), 'utf8').split('impl<')[0];
	const methods = [...source.matchAll(/\n\s*fn (\w+)\(([\s\S]*?)\)\s*->[^;]*;/g)];
	assert.deepEqual(Object.keys(examples).sort(), methods.map(match => match[1]).sort());
	for (const [, method, signature] of methods) {
		if (method === 'init_secure_api') continue;
		const names = [...signature.matchAll(/(\w+):\s*[^,\n]+/g)].map(match => match[1]);
		const params = Object.fromEntries(names.map(name => [name, `example-${name}`]));
		let calls = 0;
		await examples[method]({ call: async (actualMethod, actualParams) => {
			calls++;
			assert.equal(actualMethod, method);
			assert.deepEqual(actualParams, params);
		} }, params);
		assert.equal(calls, 1);
	}
});

for (const { fail, customLog } of [{ fail: false }, { fail: true }, { fail: true, customLog: true }]) {
test(`CLI ${fail ? 'RPC failure' : 'queries'} over HTTP${customLog ? ' with custom log path' : ''} keeps credentials out of output`, async t => {
	const mock = await mockWallet(t, {
		inner: fail ? (value, request) => request.method === 'retrieve_summary_info' ? {
			jsonrpc: '2.0', id: value.id,
			error: { code: -32099, message: 'Node unreachable; mock-sensitive-token mock-owner-secret' },
		} : value : undefined,
		result: request => {
		switch (request.method) {
			case 'open_wallet': return 'mock-sensitive-token';
			case 'close_wallet': return null;
			case 'accounts': return [{ label: 'default' }];
			case 'node_height': return { height: '123', updated_from_node: true };
			case 'retrieve_summary_info': return [true, { total: '100', amount_currently_spendable: '100' }];
			default: return [false, []];
		}
	} });
	const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'mwc-nodejs-test-'));
	t.after(() => fs.rmSync(dir, { recursive: true }));
	const secretFile = path.join(dir, 'secret');
	fs.writeFileSync(secretFile, mock.secret, { mode: 0o600 });
	const child = spawn(process.execPath, [path.resolve(__dirname, '../src/index.js')], {
		env: { ...process.env, MWC_OWNER_API_URL: mock.url, MWC_OWNER_API_SECRET_FILE: secretFile,
			MWC_WALLET_PASSWORD: 'mock-password', MWC_API_DEBUG: fail ? '1' : '0',
			MWC_WALLET_LOG_FILE: customLog ? '/custom/wallet.log' : '' },
	});
	let output = '';
	child.stdout.on('data', data => { output += data; });
	child.stderr.on('data', data => { output += data; });
	const [code] = await once(child, 'close');
	assert.equal(code, fail ? 1 : 0, output);
	assert.match(output, /Wallet closed/);
	if (fail) {
		assert.ok(output.includes(customLog ? '/custom/wallet.log' : path.join(dir, 'mwc-wallet.log')), output);
		assert.ok(output.includes(customLog ? 'Wallet log:' : 'Wallet log (default location):'));
		assert.ok(output.includes('"direction":"request","method":"retrieve_summary_info"'));
		assert.ok(output.includes('"direction":"response","method":"retrieve_summary_info"'));
		assert.match(output, /Node unreachable/);
	} else {
		assert.match(output, /"wallet_refreshed": true/);
		assert.equal(output.includes('[wallet-api]'), false);
	}
	for (const secret of ['mock-password', 'mock-sensitive-token', mock.secret]) assert.equal(output.includes(secret), false);
	assert.deepEqual(mock.requests.map(request => request.method), ['open_wallet', 'accounts', 'node_height', 'retrieve_summary_info', ...(fail ? [] : ['retrieve_outputs', 'retrieve_txs', 'query_txs']), 'close_wallet']);
});
}

test('trace redacts secret-bearing methods and nested credentials without modifying bodies', () => {
	for (const method of ['open_wallet', 'create_wallet', 'get_mnemonic', 'change_password', 'create_config', 'set_tor_config']) {
		const body = { params: { unexpected: 'private-value' } };
		const line = traceLine('request', method, body, body.params, 'api-secret');
		assert.equal(line.includes('private-value'), false);
		assert.equal(body.params.unexpected, 'private-value');
	}
	for (const method of ['open_wallet', 'get_mnemonic', 'get_rewind_hash', 'build_output']) {
		assert.equal(traceLine('response', method, { result: { Ok: 'private-value' } }, {}, '').includes('private-value'), false);
	}
	const params = { token: 'private-token', args: { private_key: 'private-key', mnemonic: 'private-phrase' } };
	const body = { error: { message: 'api-secret private-token private-key private-phrase\u001b[31m\u202e' } };
	const line = traceLine('response', 'retrieve_summary_info', body, params, 'api-secret');
	for (const secret of ['api-secret', 'private-token', 'private-key', 'private-phrase', '\u001b', '\u202e']) assert.equal(line.includes(secret), false);
	assert.ok(line.includes('[REDACTED]'));
	assert.ok(line.includes('\\u202e'));
});

test('large request traces remain bounded valid JSON with secrets redacted', () => {
	const params = { token: 'hidden-token', args: { message: Array.from({ length: 100 }, () => 'x'.repeat(2000)) } };
	const line = traceLine('request', 'init_send_tx', { jsonrpc: '2.0', id: '12', method: 'init_send_tx', params }, params, 'secret');
	const record = JSON.parse(line.slice('[wallet-api] '.length));
	assert.equal(record.body.id, '12');
	assert.equal(record.body.truncated, true);
	assert.equal(line.includes('hidden-token'), false);
	assert.ok(line.length < 16384);
});

test('a failed trace sink cannot turn a successful RPC into a failure', async t => {
	const { client } = await mockWallet(t, { client: { trace: () => { throw new Error('sensitive logger error'); } } });
	const errors = [];
	t.mock.method(console, 'error', value => errors.push(value));
	await client.connect();
	const result = await client.call('accounts', { token: null });
	assert.equal(result.method, 'accounts');
	assert.deepEqual(errors, ['Wallet API trace disabled because its logger failed.']);
});
