// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0

'use strict';

const REDACTED = '[REDACTED]';
const sensitiveField = /password|passphrase|mnemonic|token|secret|seed|keychain_mask|private_key|rewind_hash|blinding|^blind$|^old$|^new$|authorization/i;
const privateRequests = new Set(['open_wallet', 'create_wallet', 'get_mnemonic', 'change_password', 'create_config', 'set_tor_config']);
const privateResponses = new Set(['open_wallet', 'get_mnemonic', 'get_rewind_hash', 'build_output']);

// Work from copies, never alter the request being sent or response being returned.
function traceLine(direction, method, body, params, apiSecret) {
	const secrets = new Set([apiSecret]);
	function collect(value, hidden = false, depth = 0) {
		if (depth > 16 || value === null) return;
		if (typeof value === 'string') {
			if (hidden && value) secrets.add(value);
		} else if (typeof value === 'object') {
			for (const [key, item] of Object.entries(value)) collect(item, hidden || sensitiveField.test(key), depth + 1);
		}
	}
	collect(params);
	collect(body);
	function scrub(value, depth = 0) {
		if (depth > 12) return '[TRUNCATED]';
		if (typeof value === 'string') {
			for (const secret of secrets) if (secret) value = value.split(secret).join(REDACTED);
			return value.length > 2048 ? value.slice(0, 2048) + '[TRUNCATED]' : value;
		}
		if (Array.isArray(value)) return value.slice(0, 100).map(item => scrub(item, depth + 1)).concat(value.length > 100 ? ['[TRUNCATED]'] : []);
		if (value && typeof value === 'object') {
			return Object.fromEntries(Object.entries(value).slice(0, 100).map(([key, item]) => [scrub(key, depth + 1), sensitiveField.test(key) ? REDACTED : scrub(item, depth + 1)]));
		}
		return value;
	}
	let safe = body;
	if (direction === 'request' && privateRequests.has(method)) safe = { ...body, params: REDACTED };
	if (direction === 'response' && privateResponses.has(method) && Object.hasOwn(body, 'result')) safe = { ...body, result: REDACTED };
	// Errors for secret-management calls may include credentials in free-form text.
	if (direction === 'response' && (privateRequests.has(method) || privateResponses.has(method)) && body.error) {
		safe = { ...body, error: { code: body.error.code, message: REDACTED } };
	}
	const record = { direction, method, body: scrub(safe) };
	let text = JSON.stringify(record)
		.replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
	// Keep even a bounded diagnostic valid JSON, so CLI consumers can parse it.
	if (text.length > 16384) text = JSON.stringify({ direction, method,
		body: { jsonrpc: body.jsonrpc, id: body.id, method: body.method, truncated: true, preview: text.slice(0, 2048) } });
	return `[wallet-api] ${text}`;
}

module.exports = { traceLine };
