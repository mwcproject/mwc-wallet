/* Sample Code for connecting to the V3 Secure API via Node
 * With thanks to xiaojay of Niffler Wallet:
 * https://github.com/mwcfans/Niffler/blob/gw3/src/shared/walletv3.js
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { OwnerClient } = require('./client');
const examples = require('./examples');

function configuration(env = process.env, { requirePassword = true } = {}) {
	if (!env.MWC_OWNER_API_SECRET_FILE) throw new Error('Set MWC_OWNER_API_SECRET_FILE to the owner API secret file.');
	if (requirePassword && typeof env.MWC_WALLET_PASSWORD !== 'string') {
		throw new Error('Set MWC_WALLET_PASSWORD, including an explicit empty value for an empty password.');
	}
	const password = env.MWC_WALLET_PASSWORD;
	delete env.MWC_WALLET_PASSWORD;
	let secret;
	try { secret = fs.readFileSync(env.MWC_OWNER_API_SECRET_FILE, 'utf8').trim(); }
	catch { throw new Error('Cannot read MWC_OWNER_API_SECRET_FILE.'); }
	return {
		password,
		options: {
			url: env.MWC_OWNER_API_URL || 'http://127.0.0.1:13420/v3/owner',
			secret,
			timeoutMs: Number(env.MWC_API_TIMEOUT_MS || 60000),
			walletLogFile: env.MWC_WALLET_LOG_FILE || path.join(path.dirname(path.resolve(env.MWC_OWNER_API_SECRET_FILE)), 'mwc-wallet.log'),
			walletLogFileIsDefault: !env.MWC_WALLET_LOG_FILE,
			trace: env.MWC_API_DEBUG === '1' ? line => console.error(line) : undefined,
		},
	};
}

async function main() {
	const config = configuration();
	const client = new OwnerClient(config.options);
	config.options.secret = '';
	let opened = false;
	let failure;
	try {
		await client.connect();
		const token = await examples.open_wallet(client, { password: config.password });
		opened = true;
		config.password = '';
		console.log('Secure session established; wallet opened.');
		const accounts = await examples.accounts(client, { token });
		const height = await examples.node_height(client, { token });
		const [refreshed, summary] = await examples.retrieve_summary_info(client, {
			token, refresh_from_node: true, minimum_confirmations: 10,
		});
		// Reuse the refreshed wallet data for the remaining queries.
		const [, outputs] = await examples.retrieve_outputs(client, { token });
		const [, txs] = await examples.retrieve_txs(client, { token, show_last_four_days: true });
		const [, recent] = await examples.query_txs(client, {
			token, query: { limit: 10, sort_field: 'Id', sort_order: 'Desc' },
		});
		// Never print passwords, tokens, keys or full RPC envelopes.
		console.log(JSON.stringify({
			account_count: accounts.length,
			node_height: height.height,
			node_contacted: height.updated_from_node,
			wallet_refreshed: refreshed,
			total_nanomwc: summary.total,
			spendable_nanomwc: summary.amount_currently_spendable,
			unspent_output_count: outputs.length,
			txs_last_four_days: txs.length,
			recent_query_count: recent.length,
		}, null, 2));
	} catch (error) {
		failure = error;
	} finally {
		config.password = '';
		if (opened) {
			try {
				await examples.close_wallet(client);
				console.log('Wallet closed.');
			} catch (error) {
				console.error('Wallet close was not confirmed; check the dedicated owner listener.');
				failure ||= error;
			}
		}
		client.dispose();
	}
	if (failure) throw failure;
}

if (require.main === module) {
	main().catch(error => {
		console.error(error.message);
		process.exitCode = 1;
	});
}

module.exports = { configuration, main };
