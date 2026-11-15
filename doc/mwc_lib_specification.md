# MWC Wallet Library Specification

This document specifies how to build and use `mwc_wallet_lib`, including its C interface and every JSON method handled in the wallet request dispatcher.

## Build

Run from repository root:

```bash
cargo build --release --locked --package mwc_wallet_lib --lib
```

`mwc_wallet_lib` is built as `rlib`, `cdylib`, and `staticlib` (see `crate-type` in [mwc_wallet_lib/Cargo.toml](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/Cargo.toml)).

## C Interface

The C interface is defined in:

- [mwc_wallet_lib/c_header/mwc_wallet_interface.h](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/c_header/mwc_wallet_interface.h)

Main wallet request dispatcher is implemented in:

- [mwc_wallet_lib/src/mwc_wallet_calls.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/mwc_wallet_calls.rs)

Wallet FFI entry point is implemented in:

- [mwc_wallet_lib/src/ffi.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/ffi.rs)

Exported functions:

- Check exported functions from [mwc-node specification](https://github.com/mwcproject/mwc-node/blob/master/doc/mwc_lib_specification.md)
all those methods are supported and will be used for the wallet calls as well.  

- `char *process_mwc_wallet_request(char const *input);`
  - Main wallet API entry point.
  - `input` is a JSON string with `{ "method": "...", "params": {...} }`.
  - Returns a separately allocated UTF-8 JSON C string. Treat it as read-only; it remains valid until you call `free_lib_string` 
  exactly once. Copy/parse it before freeing it; do not use `free` or `delete`.


Important callback lifetime rules:

- Caller-owned callback context must be safe for the threads that invoke it and remain alive until `unregister_lib_callback` returns for that exact name. Unregister waits for in-flight callbacks; free the context afterward.
- Callbacks must not synchronously register or unregister callbacks: dispatch holds the registry read lock. Use unique names; registering a duplicate does not replace the existing callback.
- A response callback must not return a pointer to a destroyed local string. Keep its response storage valid until Rust copies it, including under concurrent callbacks.

- Callback message pointers are temporary and must not be stored on the C side. Copy data during callback execution.
- Notification callbacks may return null. A `node_client_callback` must synchronously return a valid JSON-RPC response
  C string; the wallet copies it before returning from the callback call.
- Scan and wallet-update progress callbacks run inline before the request returns. They must return promptly and must not
  synchronously re-enter wallet APIs or register/unregister library callbacks.

Before `release_wallet`, stop submitting work and wait for outstanding direct requests using that context. `stop_running_scan` requests interruption; it is not a join barrier. Release listeners/wallet resources before unregistering their callbacks.

## Wallet session sequence

`create_new_wallet`, `restore_new_wallet` and `open_wallet` each register a
wallet instance for the context. Only one such instance may be created per
context: another call returns `Wallet already created for context ...`.
After creation/restoration, release that context, call `init_wallet` with the
same data path, then open the saved wallet. Likewise, after a failed open or
`close_wallet`, release/reinitialize before another `open_wallet` attempt.
`close_wallet` closes the seed provider but does not remove the registered
instance or free the context. Qt follows this sequence when provisioning and
retrying login. Use `validate_password` for a UI unlock on an already open
wallet instead of calling `open_wallet` again.

## JSON Request/Response Contract

`process_mwc_wallet_request` receives a JSON string with this shape:

```json
{
  "method": "init_wallet",
  "params": {
    "config": {
      "wallet": { "chain_type": "Floonet", "data_file_dir": "/absolute/path/test-wallet" }
    }
  }
}
```

Success response (the result depends on the method; `init_wallet` returns `context_id`):

```json
{
  "success": true,
  "result": {}
}
```

Error response:

```json
{
  "success": false,
  "error": "error details"
}
```

Pointer returned by `process_mwc_wallet_request` must be released with `free_lib_string`.

## API Calls supported by process_mwc_wallet_request

All methods below are dispatched in:
[mwc_wallet_lib/src/mwc_wallet_calls.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/mwc_wallet_calls.rs)

### 1) `register_receive_slate_callback`

- Params:
  - `callback_name` (required): `string` (registered callback name) - The name of callback as it was registered at register_lib_callback
- Result:
  - `{}`
- Notes:
  - Registers callback for receive-slate notifications. Expected that you show user that slate received through online connection.
  Note, the transaciton is not finalized yet. Recieve slate mean that somebody started transaction.

### 2) `clean_receive_slate_callback`

- Params:
  - none
- Result:
  - `{}`
- Notes:
  - Clears receive-slate callback registration.

### 3) `init_wallet`

- Params:
  - `config` (required): `GlobalWalletConfigMembers` JSON
- Result:
  - `{ "context_id": <u32> }`
- Notes:
  - Allocates wallet context and stores wallet config.
  - `config.wallet.data_file_dir` and `config.wallet.wallet_data_dir` together select the wallet's storage location, as explained below.
  - This `context_id` identify wallet instance, it will be required for all wallet related operations.

#### Configuration settings used by the embedded API

The shared configuration type also contains standalone CLI settings. Accepting
a field in JSON does not mean the embedded API uses it. The following settings
affect `init_wallet` or subsequent operations on its context:

| JSON path | Purpose                                                                                                               | Behavior when omitted or `null` |
| --- |-----------------------------------------------------------------------------------------------------------------------| --- |
| `config.wallet.chain_type` | Selects chain parameters: `Mainnet` or `Floonet`. | `Mainnet` |
| `config.wallet.data_file_dir` | Base directory for seed/database storage.                                                                             | Required when the `wallet` object is supplied; `null` is invalid. See the default-object distinction below. |
| `config.wallet.wallet_data_dir` | Relative storage subdirectory under the base. Qt uses `"."`.                                                          | `"wallet_data"` |
| `config.wallet.tx_fee_base` | Sets the context's fee base in nanomwc per transaction weight unit.                                                   | `1000` |
| `config.tor.tor_enabled` | Allows Tor use by the embedded listener and outgoing Tor operations. Initialization itself does not start Tor.        | `true` |
| `config.tor.tor_bridge` | Optional explicit Tor bridge/transport/upstream-proxy configuration.                                                  | Direct connection to the Tor network |

When the entire `config.wallet` object is omitted, Serde constructs
`WalletConfig::default()`, whose `data_file_dir` is `"."`. When a `wallet`
object is supplied, its fields are deserialized individually: `data_file_dir`
is required, and omitted optional fields become `None`. The Rust `Default`
implementation is not a set of per-field JSON defaults.

The optional `config.tor.tor_bridge` object supports all of these fields:

| Field within `tor_bridge` | Purpose and default |
| --- | --- |
| `bridges` | Array of Tor bridge-line strings; defaults to `[]`. |
| `proxy` | Upstream proxy URI, such as `socks4://127.0.0.1:1080`, `socks5://127.0.0.1:1080`, or `http://127.0.0.1:8080`. Requires an IP address and explicit port; omitted/`null` means no upstream proxy. |
| `transports` | Array of pluggable-transport configurations; defaults to `[]`. Requires at least one bridge. |
| `transports[].protocols` | Required, non-empty array of protocol names, such as `["obfs4"]`. Each protocol may be assigned only once. |
| `transports[].path` | Absolute executable path of a managed transport helper. Specify exactly one of `path` or `proxy_addr`. |
| `transports[].arguments` | Array of helper arguments, passed without a shell; defaults to `[]`. Applies to managed helpers. |
| `transports[].run_on_startup` | Whether to launch a managed helper immediately; defaults to Arti's `false` (launch on demand). |
| `transports[].proxy_addr` | IP:port of an already-running SOCKS5 transport. Cannot be combined with `path`, non-empty `arguments`, `run_on_startup`, or the upstream `proxy` setting. |

Omit `tor_bridge` for direct Tor. An explicit empty object is invalid when Tor
starts: provide at least one bridge or a proxy. A bridge using a pluggable
transport needs a matching entry in `transports`. Invalid explicit routes do
not fall back to direct Tor. Tor objects reject unknown fields.

Setting `tor_enabled` to `false` does not configure an HTTP listener as a
replacement. The C ABI's `start_tor_listener` supplies no TCP listen address,
so that call fails when Tor is disabled.

The following shared settings are accepted but do not configure the current
embedded wallet operations:

| Settings | Embedded API behavior |
| --- | --- |
| `config.wallet.api_listen_interface`, `api_listen_port`, `mining_node_ip` | `start_tor_listener` supplies its own listener arguments and does not read these fields. |
| `config.wallet.owner_api_listen_port`, `api_secret_path`, `owner_api_include_foreign`, `owner_api_include_mqs_listener` | No owner HTTP server is started by `init_wallet`. |
| `config.wallet.check_node_api_http_addr`, `node_api_secret_path` | Node access uses the registered `node_client_callback` supplied to create/restore/open calls. |
| `config.wallet.tls_certificate_file`, `tls_certificate_key`, `dark_background_color_scheme` | These CLI/server presentation settings are not read by the embedded dispatcher. |
| `config.mqs.mwcmqs_domain`, `mwcmqs_port` | Stored, but the embedded MQS listener and send calls use `MQSConfig::default()` (`mqs.mwc.mw:443`) instead. Custom values currently have no effect. |
| `config.logging` | Stored; `init_wallet` does not initialize logging from it. |
| `config.config_file_version` | Stored; the C ABI does not perform the standalone config-file migration/version checks. |

The optional swap fields (`eth_swap_contract_address`,
`erc20_swap_contract_address`, `eth_infura_project_id`, and
`swap_electrumx_addr`) belong to the `swaps` feature. The normal
`mwc_wallet_lib` build does not enable it, and this dispatcher does not use
these fields. Unknown wallet fields are accepted, so a successful
`init_wallet` response alone does not demonstrate that a setting is supported.

Qt currently supplies only `chain_type`, `data_file_dir`, and
`wallet_data_dir`; fee and Tor behavior use the defaults described above.

#### Wallet storage paths

For the **`init_wallet` C ABI**, the fields have these roles:

| Field | Purpose | Default |
| --- | --- | --- |
| `config.wallet.data_file_dir` | Base directory supplied by the embedding application. Later create/open calls pass it to the lifecycle provider as its top-level directory. Use an absolute path to make the location independent of the process's working directory. | Required inside a supplied `wallet` object. If the whole object is omitted, its default uses `"."` (the process's working directory). |
| `config.wallet.wallet_data_dir` | Relative subdirectory within that base where the seed and wallet backend are stored. This selects the directory layout under the base. | Omitted or `null` means `"wallet_data"` |

The effective wallet storage directory is:

```text
data_file_dir / (wallet_data_dir, or "wallet_data" when omitted/null)
```

The encrypted `wallet.seed`, the `db` directory and `saved_txs` directory all
belong under this effective location. The two settings do not split the seed
and database into separate locations.

For example, with `data_file_dir = "/wallets/alice"`:

| `wallet_data_dir` | Effective storage directory | Seed file |
| --- | --- | --- |
| Omitted, `null`, or `"wallet_data"` | `/wallets/alice/wallet_data` | `/wallets/alice/wallet_data/wallet.seed` |
| `"."` | `/wallets/alice` | `/wallets/alice/wallet.seed` |
| `"accounts/savings"` | `/wallets/alice/accounts/savings` | `/wallets/alice/accounts/savings/wallet.seed` |

Qt uses the selected instance directory as `data_file_dir` and sets
`wallet_data_dir` to `"."`. This preserves Qt's existing layout, with the seed,
database and saved transactions directly in that instance directory. Omitting
`wallet_data_dir` would add a `wallet_data` level and look for a different seed.

Example using the Qt layout:

```json
{
  "method": "init_wallet",
  "params": {
    "config": {
      "wallet": {
        "chain_type": "Floonet",
        "data_file_dir": "/wallets/alice",
        "wallet_data_dir": "."
      }
    }
  }
}
```

`wallet_data_dir` must be non-empty and relative. `"."` and nested relative
paths are allowed. Lifecycle validation uses the host platform's path rules
and rejects root components, drive prefixes and any `..` component. Use an absolute path in
`data_file_dir`, not in `wallet_data_dir`. An empty string is not equivalent
to omitting the field.

`init_wallet` only allocates a context and stores this configuration; it does
not create a seed, open the database, generate a CLI configuration file or
validate the storage path. Directory validation and storage access occur in
the subsequent lifecycle operations. Creation, restoration, opening, mnemonic
reads and password changes must use the same effective directory. When
reinitializing a context for an existing wallet, preserve both field values;
changing them selects another location and does not move existing data.

This path composition describes the C ABI request. A configuration generated
for the standalone CLI can already contain a resolved data path in
`data_file_dir`; check its layout before reusing it as an `init_wallet` base,
or the default subdirectory could be appended twice.

Implementation: [request dispatcher](../mwc_wallet_lib/src/mwc_wallet_calls.rs),
[lifecycle path composition](../impls/src/lifecycle/default.rs),
[path validation](../config/src/config.rs), and
[backend directories](../impls/src/backends/lmdb.rs).

### 4) `stop_running_scan`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Interrupts active scan for context. Full scan is a long process, use this method if it needs interruption.

### 5) `release_wallet`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Releases wallet and resources. After this call you can't use context_id value any more. 

### 6) `create_new_wallet`

- Params:
  - `context_id` (required): `u32`
  - `node_client_callback` (required): `string` (registered callback name) - Very critical method. Wallet will use this callback to 
    interact with a node and expects the callback to return the node JSON-RPC response synchronously. It is expected that
    this call will be redirected to embedded or public node.
  - `mnemonic_length` (required): `usize` (in words) : The length of mnemonic phrase. Supported 12, 15, 18, 21, 24 words.
  - `password` (required): `string` : User password for this wallet. Password will be required to open the wallet.
- Result:
  - `{ "mnemonic": "..." }`
- Notes:
  - Creates brand-new wallet and returns mnemonic phrase.

### 7) `restore_new_wallet`

- Params:
  - `context_id` (required): `u32`
  - `node_client_callback` (required): `string` (registered callback name) - Very critical method. Wallet will use this callback to
    interact with a node and expects the callback to return the node JSON-RPC response synchronously. It is expected that
    this call will be redirected to embedded or public node.
  - `mnemonic` (required): `string` - mnemonic phrase, words should be separate with space
  - `password` (required): `string` - User password for this wallet. Password will be required to open the wallet.
- Result:
  - `{}`
- Notes:
  - Creates wallet from provided mnemonic.

### 8) `open_wallet`

- Params:
  - `context_id` (required): `u32`
  - `node_client_callback` (required): `string` (registered callback name) - Very critical method. Wallet will use this callback to
    interact with a node and expects the callback to return the node JSON-RPC response synchronously. It is expected that
    this call will be redirected to embedded or public node.
  - `password` (required): `string` - User password assigned to this wallet before.
- Result:
  - `{}`
- Notes:
  - Opens existing wallet.

### 9) `close_wallet`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Closes wallet for the context.

### 10) `get_mnemonic`

- Params:
  - `context_id` (required): `u32`
  - `password` (required): `string` - User password assigned to this wallet before.
- Result:
  - `{ "mnemonic": "..." }`
- Notes:
  - Reads mnemonic from wallet seed data.

### 11) `validate_password`

- Params:
  - `context_id` (required): `u32`
  - `password` (required): `string` - Password to validate.
- Result:
  - `{ "valid": <bool> }`
- Notes:
  - Verifies password against wallet seed.

### 12) `change_password`

- Params:
  - `context_id` (required): `u32`
  - `old_password` (required): `string`
  - `new_password` (required): `string`
- Result:
  - `{}`
- Notes:
  - Changes wallet password.

### 13) `start_tor_listener`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts Tor foreign API listener. Note, it is expected that 'start_tor' is already called.

### 14) `get_tor_listener_status`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "running": <bool>, "healthy": <bool> }`
- Notes:
  - Reports Tor listener running and health state. 
  - Use Tor 'healthy' result for monitoring and notifications. Wallet library will restore connection to the tor if possible.
  - Note that this method is different from 'tor_status'.  tor_status is related to Tor core. 'get_tor_listener_status' is related to 
  this wallet onion service. Responses from those methods might be different. 

### 15) `stop_tor_listener`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Stops Tor listener.

### 16) `start_mqs_listener`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts MQS listener.

### 17) `get_mqs_listener_status`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "running": <bool>, "healthy": <bool>, "error": <string|null> }`
- Notes:
  - Reports MQS listener running and health state.
  - `error` retains a fatal worker error or panic after the failed listener has removed itself from the active broker registry. It is cleared when a new listener starts or the terminated state is explicitly reset.
  - Use MQS `healthy` for connection monitoring and `error` for terminal listener failure.

### 18) `stop_mqs_listener`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Stops MQS listener.
  - Returns an API error if the listener worker failed or panicked, including a failure retained after the worker unregistered itself.

### 19) `set_address_index`

- Params:
  - `context_id` (required): `u32`
  - `address_index` (required): `u32` - index value should be in the range from 0 to 0xFFFF
- Result:
  - `{}`
- Notes:
  - Sets address index used for Tor/Slatepack/MQS address derivation. As a result the MQS and Slatepack/Tor 
  addresses will be changed. It is expected that MQS and Tor listeners will be restarted by the caller.

### 20) `get_address_index`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "address_index": <u32> }`
- Notes:
  - Returns current address index.

### 21) `rewind_hash`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "rewind_hash": "..." }`
- Notes:
  - Returns the wallet's rewind-only viewing credential. Share it only with intended viewers.
  - The credential reveals values and metadata for matching outputs, but does not grant spending authority.

### 22) `scan_rewind_hash`

- Params:
  - `context_id` (required): `u32`
  - `rewind_hash` (required): `string` - Rewind hash from another wallet.
  - `response_callback` (required): `string` (registered callback name) - Callback that receives progress updates.
  - `response_id` (required): `string` - Identifier included in every callback payload so one callback can serve multiple scans.
- Result:
  - Serialized `ViewWallet` object
- Notes:
  - Performs a rewind-hash scan. A successful rewind proves only that an output used the supplied rewind credential; it does not prove that the wallet can spend the output.
  - Anyone who knows the rewind hash can create an unrelated valid output using the same rewind scheme. Such an output is included in the result and can increase the reported total.
  - Treat the returned outputs and total as a view-only estimate, not an ownership or balance attestation.
  - Progress callbacks are invoked synchronously during the scan as `{ "response_id": "...", "status": <StatusMessage> }`.

### 23) `generate_ownership_proof`

- Params:
  - `context_id` (required): `u32`
  - `message` (required): `string` - Message that will be signed for a proof. Normally whoever requesting a proof should provide this message.
  - `include_rewind_hash` (optional): `bool` (default `true`) - If the rewind hash will be included in the proof.
  - `include_tor_address` (optional): `bool` (default `true`) - If Tor (Slatepack) address will be included in the proof.
  - `include_mqs_address` (optional): `bool` (default `true`) - If MQS address will be included in the proof.
- Result:
  - Serialized `OwnershipProof` object
- Notes:
  - Creates ownership proof record. Message 'message' will be signed with all public key that represent proved data.
  - A signed wallet-root public key authenticates that key. A rewind hash derived from it remains a rewind-only viewing credential and does not turn scan matches into proof of spend ownership.

### 24) `validate_ownership_proof`

- Params:
  - `context_id` (required): `u32`
  - `ownership_proof` (required): `OwnershipProof` JSON
- Result:
  - Serialized `OwnershipProofValidation` object
- Notes:
  - Validates ownership proof content/signature.
  - If validation returns a viewing key, it is a rewind hash. Output matches found with it are not proof of spend ownership.

### 25) `create_account`

- Params:
  - `context_id` (required): `u32`
  - `account_name` (required): `string` - Account name can include only charcters with ASCII code less than 127
- Result:
  - `{ "account_path": <Identifier> }`
- Notes:
  - Creates a new account and return it path.

### 26) `list_accounts`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "accounts": [ <AcctPathMapping> ] }` - List of json representaiton of AcctPathMapping object. Includes account name and path
- Notes:
  - Lists wallet accounts, sorted by path.

### 27) `rename_account`

- Params:
  - `context_id` (required): `u32`
  - `account_path` (required): `string` - Account path as a HEX string to rename.
  - `account_name` (required): `string` - New account name for that path
- Result:
  - `{}`
- Notes:
  - Renames account defined by 'account_path'.

### 28) `current_account`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "account_path": <Identifier> }`
- Notes:
  - Returns currently selected account path.

### 29) `switch_account`

- Params:
  - `context_id` (required): `u32`
  - `account_path` (required): `string` - Account path to set as default 
- Result:
  - `{}`
- Notes:
  - Sets active account path. Active account is used for account related operations (send, list transaciton, list outputs e.t.c.) if it is not defined.

### 30) `receive_account`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "account_path": <Identifier> }`
- Notes:
  - Request receive account path. All receive coins will be applied to this account.
  
### 31) `switch_receive_account`

- Params:
  - `context_id` (required): `u32`
  - `account_path` (required): `string` - Account to apply recieve transactions.
- Result:
  - `{}`
- Notes:
  - Sets receive account path.

### 32) `send`

- Params:
  - `context_id` (required): `u32`
  - `send_args` (required): `SendArgs` JSON
- Result:
  - `{ "tx_uuid": "..." }` - Transaction UUID that can be used to request transaction details.
- Notes:
  - Builds and sends transaction using owner API. See SendArgs for details. This method provide functionaly for 
  online and slatepack support.

### 33) `encode_slatepack`

- Params:
  - `context_id` (required): `u32`
  - `slate` (required): `VersionedSlate` JSON - Slate to encode.
  - `content` (required): `SlatePurpose` - Tyoe pf the slate.
  - `recipient` (optional): `string` - Recipient Slatepack address to encrypt the slatepack.
  - `address_index` (optional): `u32` - Address index to use as a reciever address. Same index will ned to be used for decoding respose slatepack.
- Result:
  - `{ "slatepack": "..." }`  - Slatepack string.
- Notes:
  - Encodes slate to slatepack.

### 34) `decode_slatepack`

- Params:
  - `context_id` (required): `u32`
  - `slatepack` (required): `string` - Slatepack to decode
  - `address_index` (optional): `u32` - Address index for this wallet to use. In not provided, the current one will used.
- Result:
  - `{ "slate": ..., "content": ..., "sender": ..., "recipient": ... }`
- Notes:
  - Decrypts/decodes slatepack and returns parsed values.

### 35) `receive`

- Params:
  - `context_id` (required): `u32`
  - `slatepack` (required): `string` - Slatepack to recieve
  - `message` (optional): `string` - Message for recipient 
  - `account` (optional): `string` - Account name (not a path) to apply received coins. By default will be used account 
that was set with 'switch_receive_account'
- Result:
  - `{ "reply": "...", "tx_uuid": "..." }`
- Notes:
  - Receives incoming slatepack and returns response slatepack with transaction UUID.

### 36) `has_finalized_data`

- Params:
  - `context_id` (required): `u32`
  - `tx_id` (required): `string` - Transaction UUID to check
- Result:
  - `{ "finalized": <bool> }`
- Notes:
  - Checks whether finalized transaction data exists.

### 37) `finalize`

- Params:
  - `context_id` (required): `u32`
  - `slatepack` (required): `string` - Slatepack to finalize
  - `fluff` (optional): `bool` - True if post transaction imediatelly without dandellion protocol. Default is false.
  - `nopost` (optional): `bool` - True if we don't want post transaction. Default value if 'False' 
- Result:
  - `{}`
- Notes:
  - Finalizes tx from slatepack.
  - Posts transaction unless `nopost` is `true`.

### 38) `info`

- Params:
  - `context_id` (required): `u32`
  - `confirmations` (required): `u64` - Number of confirmations for outputs in order they can be spent. 
  - `account_path` (required): `string` - Account to get the balance.
  - `manually_locked_outputs` (required): `array<string>` - List of manually locked outputs.
- Result:
  - Serialized `WalletInfo` object
- Notes:
  - Returns wallet summary for account.

### 39) `outputs`

- Params:
  - `context_id` (required): `u32`
  - `account_path` (required): `string` - Account to view the outputs
  - `include_spent` (optional): `bool` - Flag if spent outputs needs to be included (default `false`)
- Result:
  - `{ "outputs": [ ... ], "height": <u64> }`
- Notes:
  - Returns output list and current blockchain height.

### 40) `transactions`

- Params:
  - `context_id` (required): `u32`
  - `account_path` (required): `string` - Account to view the transacitons
- Result:
  - `{ "transactions": [ ... ], "height": <u64> }`
- Notes:
  - Returns `TxLogEntryAPI` list and blockchain height.

### 41) `transaction_by_uuid`

- Params:
  - `context_id` (required): `u32`
  - `tx_uuid` (required): `string` - Transaction UUID to view.
- Result:
  - `{}` if not found, otherwise serialized `TxLogEntryAPI`
- Notes:
  - Looks up one transaction by UUID.

### 42) `tx_proof`

- Params:
  - `context_id` (required): `u32`
  - `tx_id` (required): `string` - Transaction UUID to check the proof.
- Result:
  - `{ "has_proof": <bool> }`
- Notes:
  - Checks if a stored tx proof exists for tx id. Note, only 'Send' transaction might have a proof.

### 43) `post`

- Params:
  - `context_id` (required): `u32`
  - `input_path` (required): `string` - Path to transaction file to post.
  - `fluff` (optional): `bool` - True if post transaction imediatelly without dandellion protocol. Default is false. 
- Result:
  - `{}`
- Notes:
  - Posts transaction from file (cold-wallet/cold-node use case).

### 44) `repost`

- Params:
  - `context_id` (required): `u32`
  - `tx_id` (required): `string` - Transaction UUID to repost.
  - `fluff` (optional): `bool` - True if post transaction imediatelly without dandellion protocol. Default is false.
- Result:
  - `{}`
- Notes:
  - Reposts already finalized transaction.

### 45) `cancel`

- Params:
  - `context_id` (required): `u32`
  - `tx_id` (required): `string` - Transaction UUID to cancel. 
- Result:
  - `{}`
- Notes:
  - Cancels transaction by UUID. If it is impossible to cancel transaction, respond with error.

### 46) `get_proof`

- Params:
  - `context_id` (required): `u32`
  - `tx_id` (required): `string` - Transaction UUID to get the proof.
- Result:
  - Serialized `TxProof` object
- Notes:
  - Returns stored transaction proof. If proof doesn't exist, error will be returned.

### 47) `verify_proof`

- Params:
  - `context_id` (required): `u32`
  - `proof` (required): `string` (JSON-serialized `TxProof`) - Proof to verify.
- Result:
  - Serialized VerifyProofResult object
- Notes:
  - Verifies supplied tx proof. Result will have all details about the transaction.

### 48) `mqs_address`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "mqs_addr": "..." }`
- Notes:
  - Returns MQS address.

### 49) `tor_address`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "tor_addr": "..." }`
- Notes:
  - Returns Tor/Slatepack address.

### 50) `scan`

- Params:
  - `context_id` (required): `u32`
  - `delete_unconfirmed` (required): `bool` - True is we want automatically cancel not confirmed transacitons. Scan normally used to recover account after some mess.
  - `response_callback` (required): `string` (registered callback name) - Callback that receives progress updates.
  - `response_id` (required): `string` - Identifier included in every callback payload.
- Result:
  - `{ "height": <u64> }` - Blockchain height until the scan was done.
- Notes:
  - Performs full wallet scan.
  - Progress callbacks are invoked synchronously during the scan as `{ "response_id": "...", "status": <StatusMessage> }`.

### 51) `update_wallet_state`

- Params:
  - `context_id` (required): `u32`
  - `response_callback` (required): `string` (registered callback name) - Callback that receives progress updates.
  - `response_id` (required): `string` - Identifier included in every callback payload.
- Result:
  - `{ "validated": <bool>, "height": <u64> }`
- Notes:
  - validation flag if anything was neede to validate and blockchian height until validation was done.
  - Progress callbacks are invoked synchronously while wallet state is being scanned.

### 52) `request_receiver_proof_address`

- Params:
  - `context_id` (required): `u32`
  - `url` (required): `string` - Request proof address of peer through http(s) connection. 
  - `apisecret` (optional): `string` - recipient wallet api secret if it is set (normally it is not set and not needed) 
- Result:
  - `{ "proof_address": "..." }`
- Notes:
  - Request HTTP wallet for a proof address. Expected that a Slatepack address will be returned.

### 53) `zip_file`

- Params:
  - `src_file` (required): `string` - file name to zip
  - `dst_file` (required): `string` - file name of the zip archive (example: my_archive.zip)
  - `dst_file_name` (required): `string` - name of the file insize the archive (example: mwc-wallet.log)
- Result:
  - `{}`
- Notes:
  - Writes `src_file` into a new zip archive `dst_file` with internal entry name `dst_file_name`.

### 54) `check_wallet_busy`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{ "busy": <bool> }`
- Notes:
  - Returns lock availability state for current wallet instance. Note, mwc-wallet using a single lock for wallet related 
 commands. That is why nong operations like 'scan' can lock the wallet for a long time.  

### 55) `faucet_request`

- Params:
  - `context_id` (required): `u32`
  - `amount` (required): `u64` - request MWC from Floonet faucet.  
- Result:
  - `{}`
- Notes:
  - Requests faucet funds for this wallet context. This method works only for Floonet.

## Important JSON Types and Sources

- `GlobalWalletConfigMembers`:
  - [config/src/types.rs](https://github.com/mwcproject/mwc-wallet/blob/master/config/src/types.rs)
- `SendArgs`:
  - [controller/src/command.rs](https://github.com/mwcproject/mwc-wallet/blob/master/controller/src/command.rs)
- `OwnershipProof` and `OwnershipProofValidation`:
  - [libwallet/src/api_impl/types.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/api_impl/types.rs)
- `TxProof`:
  - [libwallet/src/proof/tx_proof.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/proof/tx_proof.rs)
- `VersionedSlate`:
  - [libwallet/src/slate_versions/mod.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/slate_versions/mod.rs)
- `SlatePurpose`:
  - [libwallet/src/slatepack/slatepack.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/slatepack/slatepack.rs)
- `ViewWallet`:
  - [libwallet/src/types.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/types.rs)
- `WalletInfo`:
  - [libwallet/src/types.rs](https://github.com/mwcproject/mwc-wallet/blob/master/libwallet/src/types.rs)
- `TxLogEntryAPI`:
  - [api/src/types.rs](https://github.com/mwcproject/mwc-wallet/blob/master/api/src/types.rs)

## Additional Source Links

- Wallet request dispatcher:
  - [mwc_wallet_lib/src/mwc_wallet_calls.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/mwc_wallet_calls.rs)
- Callback node client transport:
  - [mwc_wallet_lib/src/callback_node_client.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/callback_node_client.rs)
- Scan/update callback handling:
  - [mwc_wallet_lib/src/scan.rs](https://github.com/mwcproject/mwc-wallet/blob/master/mwc_wallet_lib/src/scan.rs)

# Example of the usage

This library is used for MWC-QT-Wallet. Please use it as an example of integration with a C++ applicaiton with QT library. 

## Usage of the node
- [mwc-qt-wallet/node/MwcNodeApi.h](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/MwcNodeApi.h)
- [mwc-qt-wallet/node/MwcNodeApi.cpp](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/MwcNodeApi.cpp)

## Node client that select usage of public or embedded nodes
- [mwc-qt-wallet/node/node_client.h](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/node_client.h)
- [mwc-qt-wallet/node/node_client.cpp](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/node_client.cpp)

## Usage of the wallet
 - [API](https://github.com/mwcproject/mwc-qt-wallet/blob/master/wallet/api)
 - [Long running tasks](https://github.com/mwcproject/mwc-qt-wallet/blob/master/wallet/tasks)
 - [Wallet and API objects definitions](https://github.com/mwcproject/mwc-qt-wallet/blob/master/wallet)
