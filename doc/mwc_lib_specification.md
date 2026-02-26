# MWC Wallet Library Specification

This document specifies how to build and use `mwc_wallet_lib`, including its C interface and every JSON method handled in the wallet request dispatcher.

## Build

Run from repository root:

```bash
cargo build --package mwc_wallet_lib --lib
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
  - Return value is a C string containing JSON response. Note, that string is managed in library side.
    Use this string as a read only, don't store it in you code. When you copy, release it by calling 'free_node_lib_string'


Important callback lifetime rule:

- Callback message pointers are temporary and must not be stored on the C side. Copy data during callback execution.

## JSON Request/Response Contract

`process_mwc_wallet_request` receives a JSON string with this shape:

```json
{
  "method": "init_wallet",
  "params": {}
}
```

Success response:

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
  - This `context_id` identify wallet instance, it will be required for all wallet related operations.

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
interract with a node. It is expected that this call will be redirected to embedded or public node.
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
    interract with a node. It is expected that this call will be redirected to embedded or public node.
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
    interract with a node. It is expected that this call will be redirected to embedded or public node.
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
  - `{ "running": <bool>, "healthy": <bool> }`
- Notes:
  - Reports MQS listener running and health state.
  - Use MQS 'healthy' result for monitoring and notifications. Wallet library will restore connection to the tor if possible.

### 18) `stop_mqs_listener`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Stops MQS listener.

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
  - Returns wallet rewind hash.

### 22) `scan_rewind_hash`

- Params:
  - `context_id` (required): `u32`
  - `rewind_hash` (required): `string` - Revind hash from another wallet 
  - `response_callback` (required): `string` (registered callback name) - callback to get updates about the progress. 
  Scan might take a while, it is expected that the progress should be shown to user.
  - `response_id` (required): `string` - This id will be a part of the response_callback feed. So single callback can be used for all scan calls.
- Result:
  - Serialized `ViewWallet` object
- Notes:
  - Performs rewind-hash scan. 
  - Sends progress updates to callback as JSON:
  - `{ "response_id": <response_id>, "status": <StatusMessage> }`

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

### 24) `validate_ownership_proof`

- Params:
  - `context_id` (required): `u32`
  - `ownership_proof` (required): `OwnershipProof` JSON
- Result:
  - Serialized `OwnershipProofValidation` object
- Notes:
  - Validates ownership proof content/signature.

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
  - `response_callback` (required): `string` (registered callback name) - Callback function to receive the progress related messages. 
  - `response_id` (required): `string` - response_id values for the the callback.
- Result:
  - `{ "height": <u64> }` - Blockchain height until the scan was done.
- Notes:
  - Performs full wallet scan.
  - Sends progress updates to callback as JSON:
  - `{ "response_id": "...", "status": <StatusMessage> }`

### 51) `update_wallet_state`

- Params:
  - `context_id` (required): `u32`
  - `response_callback` (required): `string` (registered callback name) - Callback function to receive the progress related messages.
  - `response_id` (required): `string` - response_id values for the the callback.
- Result:
  - `{ "validated": <bool>, "height": <u64> }`
- Notes:
  - validation flag if anything was neede to validate and blockchian height until validation was done.
  - Sends progress updates to callback.

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