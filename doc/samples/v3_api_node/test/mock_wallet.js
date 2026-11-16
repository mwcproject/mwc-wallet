// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { once } = require('node:events');
const { OwnerClient } = require('../src/client');

// Deliberately independent of the client's encryption/AAD helpers.
function serverAad(direction, id) {
	const parts = [];
	for (const text of ['mwc-owner-api-v3', direction, '2.0', `encrypted_${direction}_v3`, 'string', id]) {
		const data = Buffer.from(text);
		const length = Buffer.alloc(8);
		length.writeBigUInt64BE(BigInt(data.length));
		parts.push(length, data);
	}
	return Buffer.concat(parts);
}

async function mockWallet(t, options = {}) {
	let key;
	const requests = [];
	const ids = new Set();
	const nonces = new Set();
	const failures = [];
	const secret = 'mock-owner-secret';
	const server = http.createServer(async (request, response) => {
		try {
			assert.equal(request.url, '/v3/owner');
			assert.equal(request.method, 'POST');
			if (request.headers.authorization !== `Basic ${Buffer.from(`mwc:${secret}`).toString('base64')}`) {
				response.writeHead(401).end();
				return;
			}
			const chunks = [];
			for await (const chunk of request) chunks.push(chunk);
			const outer = JSON.parse(Buffer.concat(chunks));
			if (options.http) return options.http(outer, response);
			if (outer.method === 'init_secure_api') {
				const ecdh = crypto.createECDH('secp256k1');
				ecdh.generateKeys();
				key = ecdh.computeSecret(outer.params.ecdh_pubkey, 'hex');
				response.end(JSON.stringify({ jsonrpc: '2.0', id: outer.id, result: { Ok: options.publicKey || ecdh.getPublicKey('hex', 'compressed') } }));
				return;
			}
			assert.equal(outer.method, 'encrypted_request_v3');
			assert.equal(ids.has(outer.id), false);
			assert.equal(nonces.has(outer.params.nonce), false);
			ids.add(outer.id);
			nonces.add(outer.params.nonce);
			const bytes = Buffer.from(outer.params.body_enc, 'base64');
			const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(outer.params.nonce, 'hex'));
			decipher.setAAD(serverAad('request', outer.id));
			decipher.setAuthTag(bytes.subarray(-16));
			const inner = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(0, -16)), decipher.final()]));
			assert.equal(inner.id, outer.id);
			requests.push(inner);
			let value = options.result ? options.result(inner) : { method: inner.method, params: inner.params };
			let result = { jsonrpc: '2.0', id: inner.id, result: { Ok: value } };
			if (options.inner) result = options.inner(result, inner);
			const nonce = crypto.randomBytes(12);
			const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
			cipher.setAAD(serverAad('response', outer.id));
			const body = Buffer.concat([cipher.update(JSON.stringify(result)), cipher.final(), cipher.getAuthTag()]);
			let envelope = { jsonrpc: '2.0', id: outer.id, result: { Ok: { nonce: nonce.toString('hex'), body_enc: body.toString('base64') } } };
			if (options.outer) envelope = options.outer(envelope);
			response.end(JSON.stringify(envelope));
		} catch (error) {
			failures.push(error);
			response.destroy();
		}
	});
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	t.after(async () => {
		server.closeAllConnections();
		await new Promise(resolve => server.close(resolve));
		assert.deepEqual(failures, []);
	});
	const url = `http://127.0.0.1:${server.address().port}/v3/owner`;
	const client = new OwnerClient({ url, secret, ...options.client });
	t.after(() => client.dispose());
	return { client, url, secret, requests };
}

module.exports = { mockWallet };
