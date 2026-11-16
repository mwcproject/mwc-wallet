// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
// Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const { traceLine } = require('./logging');

class RpcError extends Error {
	constructor(method, code) {
		// Server messages can contain request values; keep them out of logs.
		super(`Wallet RPC ${method} failed (code ${Number.isSafeInteger(code) ? code : 'unknown'}). Check the wallet log.`);
		this.name = 'RpcError';
		this.code = Number.isSafeInteger(code) ? code : undefined;
	}
}

function parseJson(text) {
	try {
		return JSON.parse(text, (key, value, context) => {
			if (typeof value === 'number' && !Number.isSafeInteger(value)) {
				// Node >= 22 supplies the number text before Number rounding.
				if (context && /^-?\d+$/.test(context.source)) return context.source;
				throw new Error('Unsupported JSON number');
			}
			return value;
		});
	} catch {
		throw new Error('Invalid JSON response or unsupported numeric value.');
	}
}

function stringify(value) {
	return JSON.stringify(value, (key, item) => {
		if (typeof item === 'number' && !Number.isSafeInteger(item)) {
			throw new Error('Use decimal strings for amounts and integers outside the safe Number range.');
		}
		return item;
	});
}

function aad(direction, id) {
	// Matches rpc_aad in api/src/types.rs. This client uses string IDs.
	const fields = ['mwc-owner-api-v3', direction, '2.0', `encrypted_${direction}_v3`, 'string', id];
	return Buffer.concat(fields.flatMap(field => {
		const bytes = Buffer.from(field, 'utf8');
		const size = Buffer.alloc(8);
		size.writeBigUInt64BE(BigInt(bytes.length));
		return [size, bytes];
	}));
}

function encrypt(key, id, value, nonce) {
	const plaintext = Buffer.from(stringify(value), 'utf8');
	try {
		const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
		cipher.setAAD(aad('request', id));
		const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
		return { nonce: nonce.toString('hex'), body_enc: body.toString('base64') };
	} finally {
		plaintext.fill(0);
	}
}

function decrypt(key, id, body) {
	if (!body || typeof body.nonce !== 'string' || !/^[0-9a-fA-F]{24}$/.test(body.nonce) ||
		typeof body.body_enc !== 'string') throw new Error('Invalid encrypted response body.');
	const data = Buffer.from(body.body_enc, 'base64');
	if (data.length < 16 || data.toString('base64') !== body.body_enc) {
		throw new Error('Invalid encrypted response encoding.');
	}
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(body.nonce, 'hex'), { authTagLength: 16 });
	decipher.setAAD(aad('response', id));
	decipher.setAuthTag(data.subarray(-16));
	let plaintext;
	let final;
	try {
		plaintext = decipher.update(data.subarray(0, -16));
		try { final = decipher.final(); }
		catch { throw new Error('Response authentication failed; secure session discarded.'); }
		// Authentication must succeed before plaintext is parsed or returned.
		const combined = Buffer.concat([plaintext, final]);
		try { return parseJson(combined.toString('utf8')); }
		finally { combined.fill(0); }
	} finally {
		plaintext?.fill(0);
		final?.fill(0);
	}
}

function unwrap(response, id, method) {
	if (!response || response.jsonrpc !== '2.0' || response.id !== id) {
		throw new Error('Unexpected JSON-RPC version or response ID.');
	}
	if (Object.hasOwn(response, 'error')) {
		if (Object.hasOwn(response, 'result')) throw new Error('Ambiguous JSON-RPC response.');
		throw new RpcError(method, response.error?.code);
	}
	const result = response.result;
	if (!result || typeof result !== 'object' || Object.keys(result).length !== 1 || !Object.hasOwn(result, 'Ok')) {
		throw new Error('Expected a wallet result.Ok response.');
	}
	return result.Ok;
}

class OwnerClient {
	#url;
	#authorization;
	#key;
	#noncePrefix;
	#counter = 0;
	#busy = false;
	#disposed = false;
	#pending;
	#timeoutMs;
	#maxResponseBytes;
	#walletLogFile;
	#walletLogFileIsDefault;
	#trace;
	#traceSecret;

	get connected() { return !this.#disposed && Boolean(this.#key); }

	constructor({ url, secret, timeoutMs = 60000, maxResponseBytes = 8 * 1024 * 1024,
		walletLogFile, walletLogFileIsDefault = false, trace }) {
		this.#url = new URL(url);
		const loopback = ['127.0.0.1', '[::1]'].includes(this.#url.hostname);
		if (!['http:', 'https:'].includes(this.#url.protocol) ||
			(this.#url.protocol === 'http:' && !loopback)) {
			throw new Error('Use HTTPS, or HTTP with a literal loopback address (127.0.0.1 or [::1]).');
		}
		if (this.#url.username || this.#url.password || this.#url.search || this.#url.hash || this.#url.pathname !== '/v3/owner') {
			throw new Error('Use a /v3/owner URL without credentials, query parameters or fragments.');
		}
		if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS certificate verification must be enabled.');
		if (typeof secret !== 'string' || !secret.trim() || /[\r\n]/.test(secret) || secret.length > 4096) {
			throw new Error('A nonempty owner API secret is required.');
		}
		if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647 ||
			!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 64 * 1024 * 1024) {
			throw new Error('Invalid timeout or response-size limit.');
		}
		this.#authorization = `Basic ${Buffer.from(`mwc:${secret}`).toString('base64')}`;
		this.#timeoutMs = timeoutMs;
		this.#maxResponseBytes = maxResponseBytes;
		if (walletLogFile !== undefined && typeof walletLogFile !== 'string') throw new Error('walletLogFile must be a path string.');
		if (trace !== undefined && typeof trace !== 'function') throw new Error('trace must be a logging function.');
		this.#walletLogFile = walletLogFile;
		this.#walletLogFileIsDefault = walletLogFileIsDefault;
		this.#trace = trace;
		this.#traceSecret = trace ? secret : undefined;
	}

	async #exclusive(action) {
		if (this.#disposed) throw new Error('Client has been disposed.');
		if (this.#busy) throw new Error('Await the previous wallet request before starting another.');
		this.#busy = true;
		try { return await action(); }
		catch (error) {
			if (error instanceof RpcError && this.#walletLogFile) {
				const label = this.#walletLogFileIsDefault ? 'Wallet log (default location)' : 'Wallet log';
				error.message = error.message.replace('Check the wallet log.', `${label}: ${JSON.stringify(this.#walletLogFile)}.`);
			}
			throw error;
		}
		finally { this.#busy = false; }
	}

	#log(direction, method, body, params) {
		if (!this.#trace) return;
		try { this.#trace(traceLine(direction, method, body, params, this.#traceSecret), direction); }
		catch {
			// A failed diagnostic sink must not turn a completed mutation into an API failure.
			this.#trace = undefined;
			this.#traceSecret = undefined;
			console.error('Wallet API trace disabled because its logger failed.');
		}
	}

	#clearKey() {
		this.#key?.fill(0);
		this.#key = undefined;
	}

	#post(envelope) {
		const payload = Buffer.from(stringify(envelope));
		if (payload.length > this.#maxResponseBytes) throw new Error('Request exceeds the configured size limit.');
		return new Promise((resolve, reject) => {
			const transport = this.#url.protocol === 'https:' ? https : http;
			const request = transport.request(this.#url, {
				method: 'POST', agent: false, rejectUnauthorized: true,
				headers: {
					Authorization: this.#authorization,
					'Content-Type': 'application/json', Accept: 'application/json',
					'Content-Length': payload.length,
				},
			});
			this.#pending = request;
			let finished = false;
			const finish = (error, value) => {
				if (finished) return;
				finished = true;
				clearTimeout(timer);
				this.#pending = undefined;
				payload.fill(0);
				if (error) reject(error); else resolve(value);
			};
			const timer = setTimeout(() => {
				finish(new Error('Wallet request timed out; its outcome may be unknown. No automatic retry was made.'));
				request.destroy();
			}, this.#timeoutMs);
			request.on('error', () => finish(new Error('Wallet connection failed; check the listener, URL and TLS trust.')));
			request.on('close', () => finish(new Error('Wallet connection closed before a complete response.')));
			request.on('response', response => {
				// Never follow redirects; credentials stay at the configured endpoint.
				if (response.statusCode !== 200) {
					finish(new Error(`Owner API HTTP status ${response.statusCode}.`));
					response.destroy();
					return;
				}
				const chunks = [];
				let size = 0;
				response.on('data', chunk => {
					size += chunk.length;
					if (size > this.#maxResponseBytes) {
						finish(new Error('Wallet response exceeds the configured size limit; use smaller queries.'));
						response.destroy();
					} else chunks.push(chunk);
				});
				response.on('error', () => finish(new Error('Wallet response was interrupted.')));
				response.on('end', () => {
					if (finished) return;
					try { finish(null, parseJson(Buffer.concat(chunks).toString('utf8'))); }
					catch (error) { finish(error); }
				});
			});
			request.end(payload);
		});
	}

	async connect() {
		return this.#exclusive(async () => {
			if (this.#key) throw new Error('This client already has a secure session.');
			const ecdh = crypto.createECDH('secp256k1');
			ecdh.generateKeys();
			const id = 'handshake';
			const request = {
				jsonrpc: '2.0', id, method: 'init_secure_api',
				params: { ecdh_pubkey: ecdh.getPublicKey('hex', 'compressed') },
			};
			this.#log('request', request.method, request, request.params);
			const response = await this.#post(request);
			const publicKey = unwrap(response, id, 'init_secure_api');
			if (this.#disposed) throw new Error('Client has been disposed.');
			if (typeof publicKey !== 'string' || !/^(02|03)[0-9a-fA-F]{64}$/.test(publicKey)) throw new Error('Invalid server ECDH public key.');
			try { this.#key = ecdh.computeSecret(publicKey, 'hex'); }
			catch { throw new Error('Invalid server ECDH public key.'); }
			this.#log('response', request.method, response, request.params);
			this.#noncePrefix = crypto.randomBytes(4);
			this.#counter = 0;
		});
	}

	async call(method, params = {}) {
		return this.#exclusive(async () => {
			if (!this.#key) throw new Error('Establish a secure session with connect() first.');
			if (typeof method !== 'string' || !/^[a-z][a-z0-9_]*$/.test(method) ||
				['init_secure_api', 'encrypted_request_v3'].includes(method)) throw new Error('Invalid encrypted wallet method.');
			if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('Use named JSON-RPC parameters.');
			if (this.#counter >= 65536) throw new Error('Secure session request limit reached; establish a new session.');
			const id = String(++this.#counter);
			const nonce = Buffer.alloc(12);
			this.#noncePrefix.copy(nonce);
			nonce.writeBigUInt64BE(BigInt(this.#counter), 4);
			const request = { jsonrpc: '2.0', id, method, params };
			const encrypted = encrypt(this.#key, id, request, nonce);
			this.#log('request', method, request, params);
			let inner;
			try {
				const response = await this.#post({ jsonrpc: '2.0', id, method: 'encrypted_request_v3', params: encrypted });
				inner = decrypt(this.#key, id, unwrap(response, id, method));
				if (!inner || inner.jsonrpc !== '2.0' || inner.id !== id) throw new Error('Unexpected inner response ID or version.');
				this.#log('response', method, inner, params);
			} catch (error) {
				this.#clearKey();
				throw error;
			}
			try { return unwrap(inner, id, method); }
			catch (error) {
				if (!(error instanceof RpcError)) this.#clearKey();
				throw error;
			}
		});
	}

	dispose() {
		this.#disposed = true;
		this.#pending?.destroy();
		this.#clearKey();
		this.#authorization = '';
		this.#trace = undefined;
		this.#traceSecret = undefined;
	}
}

module.exports = { OwnerClient, RpcError, aad, encrypt, decrypt, parseJson };
