# Wallet documentation

- [Build, configuration and CLI setup](setup.md)
- [Architecture and workflow](design/design.md)
- [Embedded C ABI and callbacks](mwc_lib_specification.md)
- [Tor transport](tor_for_exchanges_pools.md)
- [HTTP listener TLS](tls-setup.md)
- [Slatepack format](slatepack_data_format.md)
- [Change-output confirmations](change_outputs.md)
- [Floonet faucet command](floonet_faucet.md)
- [v3 owner API sample](samples/v3_api_node/readme.md)

[Atomic swaps](atomic_swaps.md) require the optional `swaps` feature. The
secondary-node/ElectrumX setup notes are historical test procedures, not current
upstream installation guides. Archived Ethereum contract sources and bytecode
under `swap/ethereum-contracts/` are versioned fixtures and must not be rewritten
to resemble a different deployed contract. See their [provenance](swap/ethereum-contracts/README.md).

The [earlier architecture diagram](design/wallet-arch.png) and
[versioned release notes](releases/release-7.0.0.md) preserve historical context.
Live faucet/service availability and external deployments require separate checks.
