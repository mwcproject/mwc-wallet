# Wallet HTTP listener TLS

`mwc-wallet` supports HTTPS on its **owner API listener**, using Rustls. The
`tls_certificate_file` and `tls_certificate_key` settings also cover the Foreign
API when it is hosted on that same listener. Tor's onion transport and TLS used
to contact a remote node are configured separately.

## Configure the owner listener

In `[wallet]` of `mwc-wallet.toml` (normally under `~/.mwc/main` or `~/.mwc/floo`),
set both PEM files:

```toml
[wallet]
owner_api_listen_port = 3420
tls_certificate_file = "/absolute/path/fullchain.pem"
tls_certificate_key = "/absolute/path/privkey.pem"
```

Use a certificate valid for the hostname clients connect to, with the leaf
certificate followed by its intermediate certificates in `fullchain.pem`.
Obtain and renew it using your certificate provider's instructions. The private
key must be an unencrypted PEM key that Rustls can load. The wallet process must
be able to read both files.

On macOS and Linux, the server **rejects private keys with any group or other
permission bits**. Restrict the individual key file to its owning service account:

```sh
chmod 600 /absolute/path/privkey.pem
```

Start the listener using the wallet's configuration:

```sh
mwc-wallet owner_api
# For a Floonet wallet, use: mwc-wallet --floonet owner_api
```

The owner port defaults to 3420 on mainnet and 13420 on Floonet. An explicit
`owner_api_listen_port` overrides that default. Restart the listener after
replacing its certificate or key; certificates are loaded at startup.

The CLI owner listener binds to **127.0.0.1**. `--external` changes the standalone
Foreign socket configuration, not this owner binding. For access from another
machine, use a controlled tunnel or reverse proxy with access restricted to the
intended clients. Preserve owner authentication: Basic username `mwc`, password
from `api_secret_path` (normally `.owner_api_secret`).

## Verify HTTPS

For a certificate issued to `wallet.example.com`, this command connects locally
while checking that hostname. Replace the CA file with the CA that issued your
certificate; omit `--cacert` when it is already trusted by your system.

```sh
curl --include \
  --resolve wallet.example.com:3420:127.0.0.1 \
  --cacert /absolute/path/ca.pem \
  https://wallet.example.com:3420/v3/owner
```

With owner authentication configured, expect `401 Unauthorized`: the TLS
handshake succeeded and the listener requested credentials. A certificate error
means the hostname, trust chain, validity dates, or configured certificate needs
attention. This check does not open the wallet or start an encrypted API session.

The [Node.js owner API sample](samples/v3_api_node/readme.md) performs authenticated
v3 requests over HTTPS. For a private CA, set `NODE_EXTRA_CA_CERTS` to its PEM file
before starting Node.js. Keep certificate and hostname verification enabled.

## Foreign listener and mining connections

`mwc-wallet listen -m http --no_tor` starts the standalone Foreign HTTP socket.
That path does **not** use the certificate settings above: its socket remains
plain HTTP. Configure both `api_listen_interface` and `api_listen_port` for it;
they are unset by default. `--listen_on_socket_with_tor` enables this additional
socket alongside Tor, and `--external` requests an external socket bind.

To host the Foreign API on the TLS-enabled owner listener, set
`owner_api_include_foreign = true` and use its `/v2/foreign` endpoint and owner
port. The Foreign route is exempt from owner Basic authentication, so restrict
access to that listener appropriately. The wallet must be open to serve wallet
operations; this configuration prompts for its password at startup.

Use the standalone Foreign socket for Stratum coinbase requests. The co-hosted
Foreign route currently lacks the source-address access context and rejects
`build_coinbase`, including local requests.

For a node and standalone wallet listener on the same machine, configure the
wallet socket as `api_listen_interface = "127.0.0.1"` and
`api_listen_port = 3415`. Set the node's matching endpoint:

```toml
[server.stratum_mining_config]
wallet_listener_url = "http://127.0.0.1:3415"
```

For a remote mining connection that requires HTTPS, terminate TLS at a controlled
proxy in front of the standalone socket and point `wallet_listener_url` to that
proxy's HTTPS URL. The node must trust its issuing CA. Restrict the proxy to the
intended mining node: forwarded traffic can appear to originate from the proxy's
local address and receive loopback coinbase access. The standalone wallet also
supports `mining_node_ip` for direct connections from an authorized remote node.

See [wallet configuration](../config/src/types.rs),
[listener startup](../controller/src/command.rs), and
[owner/Foreign routing](../controller/src/controller.rs) for the implementation.
