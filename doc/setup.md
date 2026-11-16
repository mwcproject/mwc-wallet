# Building and setting up MWC Wallet

## Build

Use a Rust toolchain supporting edition 2024, a C/C++ toolchain, CMake and the
native dependencies needed by the selected target. Keep `Cargo.lock` under
version control. From the wallet repository:

```sh
cargo build --release --locked --bin mwc-wallet
```

This checkout uses the sibling `../mwc-node` repository through
`util/Cargo.toml`; the root manifest also patches `tor-ptmgr` to
`../mwc-node/vendor/tor-ptmgr`. Keep both source selections consistent. After
intentionally changing dependencies, update the lockfile before using `--locked`.
Add `--offline` only when the locked dependencies are already cached.

The default feature set does not include atomic swaps. To build the CLI with
that optional functionality:

```sh
cargo build --release --locked --bin mwc-wallet --features swaps
```

For a desktop application embedding the wallet, build only the library:

```sh
cargo build --release --locked -p mwc_wallet_lib --lib
```

This produces static and dynamic library artifacts under `target/release`.
The Qt wallet consumes `libmwc_wallet_lib.a` on Unix/macOS. With the local node
manifests, Cursive/pancurses belong to the optional `mwc_crates/tui` feature;
this library build does not require ncurses. The standalone node executable
enables that feature for its terminal interface. See the
[library specification](mwc_lib_specification.md) for the C ABI and callbacks.

## Initialize a wallet

```sh
./target/release/mwc-wallet init
# Or, for test coins on Floonet:
./target/release/mwc-wallet --floonet init
```

Follow the password and recovery-phrase prompts. Use `init --help` for options;
`init --here` creates the configuration in the current directory. The short
form `init -h` means `--here`, not help. `--top_level_dir` selects an explicit
wallet configuration directory. Defaults are `~/.mwc/main` and `~/.mwc/floo`.
Back up the recovery phrase before relying on the wallet.

## Connect to a node

The wallet requires a node on the same network to scan outputs and publish
transactions. Configure `[wallet].check_node_api_http_addr` in
`mwc-wallet.toml`. It accepts semicolon-separated node URLs for failover.
The default local mainnet endpoint is `http://127.0.0.1:3413`; Floonet uses 13413.
Use endpoints operated by you or supplied by your node operator; an old list
of public hosts is not evidence of current availability.

`node_api_secret_path` identifies the secret for the node's **foreign API**,
by default `.foreign_api_secret`. It must match the node you connect to.
`api_secret_path`, by default `.owner_api_secret`, protects the wallet's
owner API. These are different credentials; there is no `.api_seed` setting.
Changing a node URL does not obtain that node's password automatically.

## Entry points and data

`mwc-wallet --help` and each subcommand's `--help` describe the CLI.
The interactive shell is `mwc-wallet cli`; services start through `listen` or
`owner_api`, not simply by opening a wallet. With Tor enabled, `listen -m http`
uses the onion listener. To expose an HTTP socket, configure both
`api_listen_interface` and `api_listen_port` (unset by default), then use
`--no_tor` or `--listen_on_socket_with_tor` as appropriate.
The seed and wallet database live below the configured wallet data directory.
Use a separate directory and Floonet for tests.

See [Tor](tor_for_exchanges_pools.md), [TLS](tls-setup.md),
[change-output selection](change_outputs.md), and
[the implementation map](design/design.md).
