# Ethereum swap contract snapshots

This directory contains explorer-verified source snapshots for the two default
Ethereum mainnet swap contract addresses configured by `mwc-wallet`.

## Native ETH swap

- Address: `0x2FA243fC8f9EAF014f8d6E909157B6A48cEE0bdC`
- Contract: `SwapContractAggregateSignature`
- Verification source: Etherscan
- Explorer: <https://etherscan.io/address/0x2FA243fC8f9EAF014f8d6E909157B6A48cEE0bdC#code>

## ERC20 swap

- Address: `0xDd62a95626453F54E686cF0531bCbf6766150794`
- Contract: `ERC20SwapContractAggregateSignature`
- Verification source: Blockscout
- Explorer: <https://eth.blockscout.com/address/0xDd62a95626453F54E686cF0531bCbf6766150794?tab=contract>

Each address directory includes the verified Solidity sources and dependencies,
ABI, compiler settings, standard compiler input, creation bytecode, and deployed
runtime bytecode. `manifest.json` records provenance and SHA-256 hashes.

These are mainnet snapshots. The wallet configuration can override both contract
addresses, so an individual saved trade may use a different deployment.
