# Tor transport in the current wallet

The wallet uses the node workspace's embedded **Arti** implementation. It does
not spawn a separate `tor` executable for each send. The old `socks_running`,
`socks_proxy_addr`, `send_config_dir` and `use_tor_listener` examples described
an earlier implementation and are not current `TorConfig` fields.

The wallet's `mwc-wallet.toml` uses:

```toml
[tor]
tor_enabled = true
```

If omitted, `TorConfig::is_tor_enabled()` defaults to true. With Tor enabled, the CLI's
`listen -m http` starts the onion listener. Add `--listen_on_socket_with_tor`
to also start the HTTP socket, or use `--no_tor` for a socket without Tor.
Socket mode requires explicit `[wallet].api_listen_interface` and
`api_listen_port`; both are unset by default. A Tor service address and a
normal HTTP socket are distinct transports. Sending to an onion address requires a bootstrapped Tor runtime.

`tor_bridge` is an optional structured configuration shared with the node. It
supports bridge lines, managed transport helpers, existing transport SOCKS5
endpoints and an upstream proxy. See the node's
[Tor configuration guide](https://github.com/mwcproject/mwc-node/blob/master/doc/tor_inbound_feature.md)
and `TorConfig`, `TorBridgeConfig`, `TorTransportConfig` in its `p2p/src/types.rs`.
A managed transport such as webtunnel needs its helper executable installed;
that is separate from the embedded Tor runtime.

For C ABI integrations, start the process-wide Tor runtime with `start_tor`
before `start_tor_listener`. `tor_status` describes the runtime;
`get_tor_listener_status` describes this wallet's onion listener. Check both
startup errors and ongoing health. `shutdown_tor` requests process-wide
shutdown and is intended for application exit, not a restart toggle.
