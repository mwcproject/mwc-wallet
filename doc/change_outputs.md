# Confirmation thresholds for change outputs

Change outputs return the remainder of a send transaction to the sending
wallet. The CLI and owner API can select a separate minimum confirmation
threshold for these outputs.

- `send -c N` / `--min_conf N`: ordinary minimum confirmations.
- `send -x` / `--exclude_change_outputs`: use the separate threshold for change.
- `send -r N` / `--minimum_confirmations_change_outputs N`: that threshold,
  default 1; requires `-x`.

Here “exclude” means exclude change from the ordinary threshold, not exclude
change from coin selection. Locked, spent and immature outputs are still
subject to the wallet's eligibility checks. A lower threshold does not make
change immune to chain reorganizations or conflicts in its ancestor transaction.

These examples initiate a 10 MWC file transaction, requiring 5100 confirmations
for ordinary inputs and 1 or 20 for change, respectively:

```sh
mwc-wallet send -x -c 5100 -m file -d tx.tx 10
mwc-wallet send -x -r 20 -c 5100 -m file -d tx.tx 10
```

For owner API `init_send_tx`, set the corresponding fields within `args`:

```json
{
  "amount": "10000000000",
  "minimum_confirmations": 5100,
  "exclude_change_outputs": true,
  "minimum_confirmations_change_outputs": 20
}
```

This is an argument fragment, not a complete request. Amounts are nanocoins:
1 MWC = 1,000,000,000 nanocoins. Supply the remaining `InitTxArgs` and transport
parameters required by your API version. The owner API implementations are in
`api/src/owner_rpc_v2.rs` and `api/src/owner_rpc_v3.rs`; the v3 endpoint uses its
secure-session handshake and encrypted request wrapper. Do not send a plain
v2 request to `/v3/owner`.
