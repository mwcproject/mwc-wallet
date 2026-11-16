// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { Writable } = require('node:stream');
const { parseJson } = require('./client');

const MAX_FILE_BYTES = 8 * 1024 * 1024;

function splitLine(line) {
	const words = [];
	let word = '', quote = '', escaped = false, started = false;
	for (const char of line) {
		if (escaped) { word += char; escaped = false; started = true; }
		else if (char === '\\' && quote !== "'") { escaped = true; started = true; }
		else if (quote) { if (char === quote) quote = ''; else word += char; }
		else if (char === '"' || char === "'") { quote = char; started = true; }
		else if (/\s/.test(char)) { if (started) { words.push(word); word = ''; started = false; } }
		else { word += char; started = true; }
	}
	if (quote || escaped) {
		const error = new Error('Unclosed quote or trailing backslash.');
		error.code = 'INCOMPLETE_COMMAND';
		throw error;
	}
	if (started) words.push(word);
	return words;
}

function integer(value, label, max = Number.MAX_SAFE_INTEGER) {
	if (!/^\d+$/.test(String(value))) throw new Error(`${label} must be a nonnegative whole number.`);
	const number = Number(value);
	if (!Number.isSafeInteger(number) || number > max) throw new Error(`${label} is out of range.`);
	return number;
}

function amount(value) {
	if (typeof value !== 'string' || !/^\d+(\.\d{1,9})?$/.test(value)) {
		throw new Error('Amount must be a positive MWC decimal with at most 9 fractional digits.');
	}
	const [whole, fraction = ''] = value.split('.');
	const nano = BigInt(whole) * 1000000000n + BigInt(fraction.padEnd(9, '0'));
	if (nano === 0n || nano > 18446744073709551615n) throw new Error('Amount is outside the supported positive u64 range.');
	return nano.toString();
}

function formatAmount(nano) {
	if (!/^\d+$/.test(String(nano))) throw new Error('Invalid wallet amount.');
	const value = BigInt(nano);
	return `${value / 1000000000n}.${String(value % 1000000000n).padStart(9, '0')}`;
}

function readText(file) {
	let fd;
	try {
		fd = fs.openSync(file, 'r');
		const stat = fs.fstatSync(fd);
		if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error();
		// Bound the read even if another process grows the file after fstat.
		const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
		try {
			let size = 0, count;
			while (size < buffer.length && (count = fs.readSync(fd, buffer, size, buffer.length - size, null))) size += count;
			if (size > MAX_FILE_BYTES) throw new Error();
			return buffer.toString('utf8', 0, size);
		}
		finally { buffer.fill(0); }
	} catch {
		throw new Error('Cannot read input: use an existing regular file of at most 8 MiB.');
	} finally { if (fd !== undefined) fs.closeSync(fd); }
}

function inputText(text) {
	if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES) throw new Error('Input must be text of at most 8 MiB.');
	return text;
}

function inputJson(text) {
	try { return parseJson(inputText(text)); }
	catch { throw new Error('Invalid JSON input. Quote JSON strings and use whole numbers or decimal strings for integers.'); }
}

function readJson(file) { return inputJson(readText(file)); }

function contentText(file, content, fileOption = '--file') {
	if ((file !== undefined) === (content !== undefined)) throw new Error(`Specify exactly one of ${fileOption} or --content.`);
	return content !== undefined ? inputText(content) : readText(file);
}

// Reserve the output before any mutation; never overwrite files or follow symlinks.
class OutputFile {
	#fd;
	constructor(file) {
		if (!file) throw new Error('Specify an output file.');
		this.path = path.resolve(file);
		try { this.#fd = fs.openSync(this.path, 'wx', 0o600); }
		catch { throw new Error('Cannot create output: choose a new filename in a writable directory.'); }
	}
	write(value, text = false) {
		const content = text ? String(value) + '\n' : JSON.stringify(value, null, 2) + '\n';
		fs.ftruncateSync(this.#fd, 0);
		// Position is explicit because a recovery checkpoint may be replaced later.
		const buffer = Buffer.from(content);
		try {
			let offset = 0;
			while (offset < buffer.length) offset += fs.writeSync(this.#fd, buffer, offset, buffer.length - offset, offset);
			fs.fsyncSync(this.#fd);
		} finally { buffer.fill(0); }
	}
	close() { if (this.#fd !== undefined) { fs.closeSync(this.#fd); this.#fd = undefined; } }
}

function display(value) {
	// JSON encoding escapes terminal control bytes in wallet/peer-supplied text.
	return JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g,
		char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

class InputClosed extends Error { constructor() { super('Input closed.'); } }

class Terminal {
	#muted = false;
	#rl;
	#output;
	#lines = [];
	#queuedBytes = 0;
	closed = false;
	constructor(input = process.stdin, output = process.stderr, commands = []) {
		this.#output = output;
		const sink = new Writable({ write: (chunk, encoding, done) => {
			if (!this.#muted) output.write(chunk, encoding);
			done();
		} });
		// History is disabled so a password or recovery phrase never enters it.
		this.#rl = readline.createInterface({ input, output: sink, terminal: true, historySize: 0,
			completer: line => [commands.filter(command => command.startsWith(line)), line] });
		// Preserve lines from one multiline paste while the next prompt is being set up.
		this.#rl.on('line', line => {
			this.#queuedBytes += Buffer.byteLength(line, 'utf8') + 1;
			if (this.#queuedBytes > MAX_FILE_BYTES) { this.#lines = []; this.close(); return; }
			this.#lines.push(line);
		});
		this.#rl.on('close', () => { this.closed = true; this.#muted = false; });
		this.#rl.on('SIGINT', () => this.close());
	}
	async ask(prompt, secret = false) {
		if (this.closed) throw new InputClosed();
		if (this.#lines.length) {
			if (secret) {
				this.#lines = []; this.#queuedBytes = 0;
				throw new Error('Enter the password separately at its hidden prompt. Buffered pasted input was discarded.');
			}
			this.#output.write(prompt);
			const line = this.#lines.shift();
			this.#queuedBytes -= Buffer.byteLength(line, 'utf8') + 1;
			return line;
		}
		if (secret) this.#output.write(prompt);
		this.#muted = secret;
		try {
			return await new Promise((resolve, reject) => {
				const closed = () => reject(new InputClosed());
				this.#rl.once('close', closed);
				this.#rl.question(secret ? '' : prompt, answer => {
					this.#rl.removeListener('close', closed);
					resolve(answer);
				});
			});
		} finally {
			this.#muted = false;
			if (secret) this.#output.write('\n');
		}
	}
	async command() {
		let line = inputText(await this.ask('mwc-wallet> '));
		while (true) {
			try { return splitLine(line); }
			catch (error) {
				if (error.code !== 'INCOMPLETE_COMMAND') throw error;
				line += '\n' + await this.ask('...> ');
				inputText(line);
			}
		}
	}
	close() { this.#rl.close(); }
}

module.exports = { splitLine, integer, amount, formatAmount, readText, readJson, inputText, inputJson, contentText, OutputFile, display, Terminal, InputClosed };
