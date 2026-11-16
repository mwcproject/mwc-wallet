// Copyright 2024 The Mwc Developers
// Licensed under the Apache License, Version 2.0. See http://www.apache.org/licenses/LICENSE-2.0
'use strict';

const { OwnerClient } = require('./client');
const { configuration } = require('./index');
const { COMMANDS, parseCommand, help, WalletSession } = require('./cli_commands');
const { Terminal, InputClosed, display } = require('./cli_io');

async function main(argv = process.argv.slice(2), env = process.env) {
	const interactive = argv.length === 0;
	const command = interactive ? null : parseCommand(argv);
	if (command?.name === 'help') { console.log(help(...command.positionals)); return; }
	if (interactive && !process.stdin.isTTY) throw new Error('Interactive mode needs a terminal. For scripts, supply a command, for example: npm run cli -- info.');
	const config = configuration(env, { requirePassword: false });
	config.options.trace = (line, direction) => {
		if (env.MWC_API_DEBUG === '1' || (direction === 'request' && env.MWC_API_REQUESTS !== '0')) console.error(line);
	};
	const client = new OwnerClient(config.options);
	config.options.secret = '';
	let terminal;
	let failure;
	const getTerminal = () => {
		if (!process.stdin.isTTY) throw new Error('A terminal is required for this prompt. Supply MWC_WALLET_PASSWORD for scripts and --yes for intentional mutations.');
		terminal ||= new Terminal(process.stdin, process.stderr, Object.keys(COMMANDS));
		return terminal;
	};
	const session = new WalletSession(client, {
		password: async () => {
			if (config.password !== undefined) {
				const password = config.password;
				config.password = undefined;
				return password;
			}
			return getTerminal().ask('Wallet password: ', true);
		},
		confirm: async message => {
			if (!process.stdin.isTTY) throw new Error('This command changes wallet state. Review it and supply --yes for scripted execution.');
			return (await getTerminal().ask(`${message}\nType yes to continue: `)).trim().toLowerCase() === 'yes';
		},
		progress: message => console.error(message),
	});
	try {
		console.error('Connecting to the owner API...');
		await client.connect();
		if (interactive) {
			console.error('Connected. Type open to unlock the wallet, help for commands, or exit to close.');
			const prompt = getTerminal();
			while (!prompt.closed) {
				try {
					const args = await prompt.command();
					if (!args.length) continue;
					const next = parseCommand(args);
					if (next.name === 'exit') break;
					const result = await session.execute(next);
					console.log(next.name === 'help' ? result : display(result));
				} catch (error) {
					if (error instanceof InputClosed) break;
					console.error(error.message);
					if (!client.connected) {
						throw new Error('Secure session lost. Check the wallet and transaction state before reconnecting; the last request may have completed.');
					}
				}
			}
		} else {
			if (session.needsWallet(command)) await session.open();
			const result = await session.execute(command);
			console.log(display(result));
		}
	} catch (error) {
		if (!(error instanceof InputClosed)) failure = error;
	} finally {
		config.password = undefined;
		terminal?.close();
		try {
			const wasOpen = session.opened;
			await session.shutdown();
			if (wasOpen) console.error('Wallet closed.');
		}
		catch (error) {
			console.error('Wallet close was not confirmed; inspect the dedicated listener before reusing it.');
			failure ||= error;
		}
	}
	if (failure) throw failure;
}

if (require.main === module) main().catch(error => {
	console.error(error.message);
	process.exitCode = 1;
});

module.exports = { main };
