# Release 7.0.0

## Addressed audit comments

### mwc-wallet

**.ci/release.yml**
- remove the Tor webunnel client build

**.ci/test.yml**
- update all build scripts with `--features "swaps test-support"`, so tests will run for swaps, even theye are not part of the current build.

**.ci/windows-release.yml**
- remove the Tor webunnel client build

**.github/workflows/ci.yaml**
- update tests with a `--features "swaps test-support"` where it is needed.
- add the Ubuntu `feature-checks` job to validate the workspace library and binary targets with production defaults and with the `swaps` feature, 
run the swap output-proof creation and recovery tests in `mwc_wallet_libwallet`, compile all targets with both `swaps` and `test-support`. 
This separates production-feature validation from test-only coverage and catches missing feature wiring.

**azure-pipelines.yml**
- remove `golang` installation. Not needed because we don't build webtunnel any more.

**doc/atomic_swaps.md**
- The documentation has been updated to reflect major improvements in swap concurrency, Ethereum transaction safety, and crash recovery. 
Auto-swap now operates step-by-step instead of running in the background, while enhanced marketplace locking, backup restoration safeguards, 
Ethereum finality checks, nonce management, and transaction retry mechanisms improve reliability. Additional ERC20 approval, deposit, 
and cancellation recovery procedures help prevent conflicting transactions and preserve funds during failures or blockchain reorganizations.

**doc/setup.md**
- remove the `Build webtunnel client` instructions.

**doc/slatepack_data_format.md**
- Update document with a found protocol limitations about zero elemets representaiton.

**doc/swap/ethereum-contracts
- Add ethreum contacts used for swaps, so users could evaluate them.

**src/bin/mwc-wallet.rs**
- Malformed YAML and an unexpectedly empty document list now produce clear stdout diagnostics and return a failure status instead of panicking.
- replace the panic used when `mwc-wallet init --here` cannot determine the current directory with appropriate error handling.
- validate the configured chain type with an explicit match before allocating the node context. A missing value now prints and logs a 
clear error, returns failure instead of panic.
- check both wallet-listener shutdown and node-context release results.

**src/bin/mwc-wallet.yml**
- clean up libp2p related parameters.
- remove integrity payments functionality
- update descriptions, add parameters description to match changes in API

**src/cli/cli.rs**
- report IO stdout errors.
- isolate testing parameters with the `test-support` feature.
- replace compile-time YAML and crate-version macros with explicit parsing of the embedded CLI schema, handle yaml parsing errors.

**src/cmd/wallet.rs**
- handle `HTTPNodeClient::set_node_url` as a fallible operation. An invalid configured node list now produces an actionable error.
- add a regression test using a newline, OSC escape sequence, bell character, Unicode directional isolate, and oversized payload.

**src/cmd/wallet_args.rs**
- make optional-number parsing distinguish an absent value from an invalid supplied value, report errors, zeroize secret values.
- isolate testing parameters with the `test-support` feature.
- zoroize sensitive data.
- validate, reject and report invalid argument formats and values
- switch to safe math operaitons, report overflow errors
- explicitly validate both node versions for swap case, ask for the updated nodes to work with.
- clean up 'integrity' and 'messaging' commands.

**tests/owner_v3_lifecycle.rs**
- remove tests for retired 'start_updater' and 'get_updater_messages' owner API. 


### api

**Cargo.toml**
- add a `test-support` feature, needed to add extra functionality for test.

**src/foreign.rs**
- Add `durable_receive_exists`, helper to searches both live and archived wallet transaction logs.
- Add `ReceiveTxResult` and `FinalizeInvoiceTxResult`. These results carry the response Slate together with a per-Slate processing guard and reply-cache reservation.
- Rewrite the Coinbase contract and example for S2C-bound mining templates.
- Redesign `receive_tx` as a staged, authenticated, replay-safe operation.New reply-binding and independently authenticated secp256k1 sender inputs bind retries to their transport identity and support payment-proof validation. 
- Extend invoice finalization with documented staged-commit semantics, reply binding, `FinalizeInvoiceTxResult`, and a `finalize_invoice_tx_with_output_version` entry point that can validate the restored response format before signing state is consumed.
Finalization now holds a per-Slate guard, performs authenticated cache reservation/replay, checks durable finalized receive history.
- Add a regression test proving denied Coinbase requests invoke middleware with no node/slate metadata and fail before an unopened wallet or unconfigured node is accessed.
- Add `validate_with_node` to `receive_tx`. Online RPC, MQS, and self-receive paths preflight newly created responses after releasing the wallet lock; compact responses use partial validation. File and C-library receive paths can skip this node check for offline exchange, while local validation and preflight before publication remain required.

**src/foreign_rpc.rs**
- Replace the legacy Coinbase RPC contract and doctest with the mandatory S2C-bound form: requests now carry a 32-byte hexadecimal `binding_digest`, responses expose `coinbase_opening`, and the method returns `CbData` directly instead of a V2 `VersionedCoinbase`. This binds Coinbase construction to the node's block template and makes the security-critical opening available for verification.
- Make `receive_tx` authenticated, replay-safe, and atomic from the caller's perspective. 
- Bind invoice-finalization retries to the authenticated Slatepack sender. Finalization still durably stores the transaction and destroys one-time signing material before response encoding to prevent nonce reuse after a crash.
- Add an RPC-level Coinbase regression tests.

**src/owner.rs**
- Reduce `Owner` to wallet, shared-key, and Tor state, compile doctest controls only with `test-support`, remove all background-updater fields.
- Add `ProcessInvoiceTxResult`, which returns the invoice Slate together with a per-Slate processing guard.
- `Owner::new` no longer accepts a status channel or starts an updater-log thread, now returns `Result<Self, Error>`.
- Remove the owner-level background updater lifecycle and message queue—`start_updater`, `stop_updater`, and `get_updater_messages`—together with their long-lived thread and status buffering.
- Add `eth_retry_transfer` for retrying a retained ETH/ERC20 payment by any original or replacement hash with an optional maximum gas budget. This gives callers verifiable submission status and controlled fee-bump recovery.
- Fix `show_last_four_days` to include recent cancelled or reverted transactions without a confirmation height, using their creation time. Outstanding transactions remain visible at any age, and chains younger than four days retain the full history.

**src/owner_rpc_v2.rs**
- Remove the V2 `start_updater`, `stop_updater`, and `get_updater_messages` methods and their doctests.
- Refresh payment-proof fixtures for the extended proof format, including regenerated encrypted slate messages and explicit `tor_sender_signature` fields in retrieval and verification examples.
- Update the doc tests to match functionality changes.
- Update integrated owner doctest harness so match updated functionality.

**src/owner_rpc_v3.rs**
- Mirror changes from src/owner_rpc_v2.rs.  

**src/types.rs**
- Add `slatepack_recipient_public_key`, which preserves the distinction between no recipient and an explicitly supplied invalid Slatepack address by transposing address-conversion errors instead of silently treating them as absence.
- Add an unambiguous, length-prefixed AAD encoding that domain-separates the owner API protocol and authenticates message direction, JSON-RPC version, method, and the RPC ID's type and value.
- Remove the feature-gated never used grin's `payment_proof` field from `TxLogEntryAPI` and stop copying it from `TxLogEntry`, completing removal of the retired `grin_proof` API surface.
- Add regression coverage that preserves the ciphertext-plus-tag wire format, round-trips complex JSON, and rejects wrong AAD, short or overlong nonces, altered request IDs or methods, and altered response IDs. Update the existing encryption test to use a fresh fallible Secp256k1 context, and add a test proving that an invalid explicit Slatepack recipient returns an error while an absent recipient remains `None`.

**tests/swap_message_authentication.rs**
- Add a regression test that changes an existing trade's MQS destination from one peer to another, then submits a protocol-valid acceptance associated with the former peer. 
- Construct a previously accepted MQS offer, persist it with the current peer, and verify that the unauthenticated foreign RPC rejects even this exact replay before returning the replay acknowledgement. 

### config

**src/comments.rs**
- Add generated-config guidance for `mining_node_ip`, documenting that `build_coinbase` is restricted to loopback.
- Remove the obsolete `libp2p_listen_port` comment-map entry.
- Update Tor comment-map entry. Generated wallet configuration now follows the node stack's current Tor options without maintaining a stale local copy.
- Update config migration. It should recognize and report config errors during migraiton. 
- Add regression tests for table/key classification with bracket-bearing values, migration across formatting changes, quoted hashes and inline comments, keys without canned comments, rejection of altered or dropped settings, permitted new sections and obsolete unknown keys, and rejection of changes to an existing optional section.

**src/config.rs**
- Introduce `validate_wallet_data_dir`. The validator rejects empty, absolute, platform-prefixed, and parent-traversing paths so a configured data directory cannot escape the wallet root when appended.
- Harden wallet-root discovery and preparation.
- Replace the legacy thread-local random generator, zeroizing secret storage, and owner-only file writes.
- Expand API-secret validation from merely checking for a readable first line to enforcing safe file access and usable content.
- Replace direct whole-structure TOML serialization with bridge-aware serialization that removes `tor_bridge` from a clone and serializes the remaining configuration.
- Replace unrestricted whole-string log-level substitutions with line- and field-aware rewriting limited to exact quoted values of `stdout_log_level` and `file_log_level`.
- Add focused tests for forward and backward log-level compatibility.
- Add coverage for network-specific default node endpoints and verify that automated-testing configuration has no node endpoint.
- Add Tor serialization and generated-comment regression tests.
- Add secure wallet-root tests for missing-path behavior, rejection of group/other-writable directories.
- Add version-handling tests proving that the current version is accepted.
- Add Unix regression coverage showing that group/other-readable or writable configuration files are rejected before use and left untouched.
- Add isolated API-secret fixtures and Unix tests for owner-only creation, permission repair during explicit initialization.
- Add direct and integration-level tests for wallet-data containment.

### controller

**src/command.rs**
- Clean up autoswap functionality because mwc-wallet automatic swaps weren't usable (too complicated), let's target owner API or QT wallet for automatic swaps implementation.  
- Zeroize the supplied rewind hash; clear cached node metadata and require a freshly reached node.
- Redesign `send` around staged `TxSession` state and explicit cryptographic contexts. Maximum-amount sends now fail if wallet refresh was not node-validated.
- Add `GeneratedSlateFiles`, a best-effort rollback guard for destination and backup files emitted before a staged transaction session becomes durable.
- Make `show_slatepack` return its backup path for staged-workflow tracking.
- Harden slate receive processing with explicit cryptographic state, checked address indexes, encrypted-Slatepack direction validation, etc.
- Harder slate finalize, reject malformed or oversized response-participant sets before signature work, bind invoice replies to their authenticated file sender.
- Harden `repost` by requiring a node-validated refresh and an existing matching log entry. Actual reposting now rejects confirmed, cancelled, TTL-expired, missing/incomplete, and blank-kernel transactions.
- Add bounded terminal-safe rendering for swap-start, swap-operation, and offer-import failures; centralize nonempty MWCMQS/Tor/file destination validation.
- Swap marketplace messages now carry the exact swap UUID, stable retry nonce, and pinned signing-address index.
- Replace detached best-effort marketplace-cancellation threads with a synchronous durable outbox flow.
- Replace separately loaded swap/check data with a coherent status snapshot and return cancellation records for durable delivery.
- Replace background autoswap workers with one synchronous state refresh and at most one executable state-machine step per invocation.
- Remove libp2p integrity-balance and gossip messaging command implementations.
- Add regression tests for marketplace command/listener requirements and strict acknowledgements; bounded escaping of cancellation, scan, swap, file-name, and Unicode/control-character errors.

**src/controller.rs**
- Introduce a one-shot startup signal that distinguishes readiness, failure, timeout, and premature termination.
- Replace the untyped Owner/Foreign server maps with generation-tagged starting, running, stopping, standalone, and co-hosted entries.
- Redesign Foreign API cleanup, registration, replacement, health, Onion-address, and co-hosted-route management around instance identities.
- Add coordinated Owner API stop/join handling that closes admission, gracefully stops and joins the thread, waits for all detached streams—to finish, preserves shutdown and panic diagnostics.
- Replace bare Slate response channels with tokenized waiters bound to the original Slate, expected authenticated peer, and expected protocol stage.
- Rewrite incoming MQS Slate processing around explicit processed/rejected/retry dispositions.
- Remove the libp2p listener, kernel-validation cache, gossip-node restart loop, and its Tor/Foreign-listener startup and shutdown plumbing.
- Redesign standalone Foreign listener startup and access control.
- Make Owner V2 share one fallibly constructed Owner instance and hold a wallet-lifecycle read guard across complete multi-step dispatches.
- Add targeted zeroizing Owner V2/V3 dispatch wrappers for secret-bearing arguments.
- Add recursive JSON-value erasure for discarded string, numeric, Boolean, array, and object data, with a compile-time guard against a heap-owning `serde_json::Number`.
- Rebuild Owner V3 request processing so decrypt, dispatch, response encryption, and re-keying are serialized under one session key.
- Harden Foreign V2 dispatch with a 32-thread permit that returns HTTP 429 when saturated and always releases capacity on completion, panic, spawn failure, or cancellation. Hold a bounded lifecycle read guard while snapshotting and using the keychain mask, preventing backend/mask mismatches and breaking the documented co-hosted self-send deadlock; enforce `build_coinbase` only for loopback or the configured mining IP; and bound/escape debug rendering of peer-controlled requests and responses.
- Add regression tests for bounded swap diagnostics.
- Add MQS waiter tests covering duplicate-registration refusal, identity-safe stale cleanup, rejection of reflected or incomplete send/invoice Slates.
- Add tests for zeroizing Basic-auth construction, fail-closed keychain-mask updates, preservation of non-string application and dispatcher errors, Owner/Foreign lifecycle-lock consistency, rejection of lifecycle batches and notifications, and secure-session nonce replay detection.

**src/executor.rs**
- Add `join_cancelled_worker`, which joins unfinished workers when cancellation occurs on a multithreaded runtime, avoiding runtime starvation or shutdown deadlock when the RPC worker itself needs Tokio.
- Add bounded regression tests proving that panics during handler construction and future polling still publish completion and are returned as the existing worker-death error rather than hanging the caller.
- Add a two-waker regression test proving that completion wakes only the task associated with the executor's most recent poll, covering movement between executors or task contexts.
- Add a single-worker Tokio regression test proving that cancellation waits for the RPC worker to finish, does not complete before the worker is released, and can join without deadlocking the runtime thread.

**src/foreign.rs**
- Add server-derived `ForeignRequestAccess` capabilities and mining-source validation for `build_coinbase`.
- Add an atomic RAII `ConnectionPermit` that admits a worker only below its configured connection limit and automatically restores capacity when the worker, rejected spawn closure, or other owning path is dropped.
- Extend `ForeignApiServer` with its unique instance ID, active-connection counter and limit.
- Add unit coverage for connection-limit enforcement and permit release, uniqueness of Foreign API instance IDs.
- Add authorization tests covering IPv4 and IPv6 loopback, configured IPv4 and IPv6 peers, unrelated peers, Tor and unknown origins.
- Add lifecycle tests.
- Add concurrency tests proving that a listener failure stops its sibling and reaches the caller.
- Add deterministic failure-ordering and missing-handle tests.

### controller/tests

Add regression coverage for authenticated MQS participant-message tampering and corrected retries, replay rejection 
before late-lock persistence or publication, rejection of invoice payment-proof requests without wallet mutation, 
and recent cancellation filtering across basic and advanced queries.

### impls

**src/adapters/http.rs**
- Add structured HTTP-404 recognition and a common foreign-API response parser that requires a JSON-RPC 2.0.
- Add an encrypted Slatepack response policy and shared response decoder. For encrypted requests, derive the only valid response purpose, require the response sender to be the requested remote recipient, require the response recipient to be the local wallet, reject a purpose mismatch, and refuse a plaintext response; legacy exchanges without an encryption policy retain plaintext compatibility. This prevents response substitution, direction/purpose confusion, and encryption downgrade while centralizing sanitized deserialization failures.
- Harden direct HTTP construction by parsing and extending the base URL, rejecting unsafe query/fragment-bearing forms.
- Add regression tests covering structured 404 classification; safe foreign-API URL composition and query/fragment rejection.

**src/adapters/mod.rs**
- Harden `create_sender` by accepting the API secret as a shared `Arc<Zeroizing<String>>`, escaping and bounding the method, destination, and nested error in invalid-destination diagnostics.
- Add regressions proving that malformed, checksum-invalid, overlong, and suffix-bearing Onion-like HTTP destinations are rejected.

**src/adapters/mwcmq.rs**
- Add a shared listener join state machine, cloneable completion outcomes, and `MqsListenerWait` ownership tickets so exactly one owner joins the worker while concurrent stop/wait callers observe the same result.
- Add global, non-poisoning registries for per-instance terminal observations, serialized lifecycle operations, and contexts whose worker join is still pending.
- Make broker registration fallible and require the lifecycle guard, matching context IDs, shared address/broker/key identity, an empty registry slot, and no stop already in progress.
- Replace the subscriber's mutex-wrapped optional thread handle with the shared join controller. Add direct claim/wait support, preserve the real handle if proxy creation fails, expose the listener instance ID.
- Harden subscriber startup by requiring the exact registration through thread-handle publication, atomically beginning the broker, waiting for an explicit ready/error signal with a bounded timeout.
- Give each broker a unique instance ID and independent running, healthy, and stop-requested atomics.
- Add protocol-specific serializers and strict parsers. Preserve the legacy raw 64-byte listener-signature wire format without relying on a Rust wrapper.
- Extract incoming-message processing into a typed result path that requires exactly one sender, signature, and slate-or-swap payload, validates the sender address and authenticated envelope.
- Add regression tests for legacy listener-signature bytes; request/response-purpose binding; bounded rejection/error retries and counter reset; non-wrapping instance IDs; strict single, batch, close-login, sender-response, and hostile-control-text parsing.

**src/adapters/types.rs**
- Add explicit processed/rejected MQS message dispositions, a typed retryable processing error, and their shared result alias.
- Add unit regressions proving that HTTP and HTTPS inputs are canonicalized, non-web schemes, credential-bearing and syntactically ambiguous URLs are rejected.

**src/backends/lmdb.rs**
- Add `StoredEthereumWallet`, which keeps swap-wallet passwords, mnemonics, and private keys as ChaCha20-Poly1305 authenticated ciphertext whenever the MWC keychain is masked.
- Replace the two-field private-context XOR scheme with zeroizing, checked KDF helpers for all four secret fields.
- Redesign stored-transaction archiving as a prepare/install/remove sequence.
- Extend `Batch` with rollback-aware archive tracking: an uncommitted batch removes only archive files it created while retaining the live source.
- Add archive-atomicity regressions proving a failed late installation removes its published destination, an aborted LMDB batch retains the live file and rolls back its new archive.
- Add regressions proving wallet close removes every retained credential, masked Ethereum spend material is ciphertext and requires the matching mask even for payloads larger than the old fixed reservation.
- Add regressions proving confirmed height is wallet-global and ignores legacy per-account records, and that saving a recovered output atomically reserves its child index even when a later scan batch rolls back, preventing accidental key reuse.
- Add end-to-end S2C Coinbase coverage: malformed binding digests must fail before reserving keys or outputs.
- Add stored-transaction regressions for archive fallback only on absence, rejection of path components in both log references and UUID lookups.
- Add a migration regression proving legacy height-bearing identifiers are rekeyed in both live and archived outputs and rewritten inside private contexts without damaging the encrypted transaction secrets.

**src/backends/swap_recovery_tests.rs**
- Add a reusable fixture that creates a temporary Floonet wallet with a deterministic keychain, loads the seller swap/context fixtures, positions the swap immediately before its lock deadline.
- Add regression tests tocove swaps recovery functionality.

**src/client_utils/json_rpc.rs**
- Add response-version and request-ID validators.
- Add regressions for a valid success value, the required null payload for unit success, mismatched IDs, missing results across nullable and unit targets.

**src/client_utils/mod.rs**
- Add a shared URL-path builder that parses the base as a hierarchical URL, rejects query or fragment components, removes an empty trailing segment, and appends endpoint segments through the URL API. This preserves proxy path prefixes while preventing endpoint text from being appended after a query or fragment and routed to an unintended handler.
- Add node- and recipient-controlled text/error formatters with a single-line display escaper with the appropriate size limit.
- Add regressions proving endpoint segments are appended correctly with and without base-path/trailing slashes; query-bearing, fragment-bearing, and nonhierarchical bases are rejected.

**src/http_parser/http_request.rs**
- Redefine request reading around bounded, interruptible parsing.
- Add `append_response_headers`, which preserves ordinary response headers but suppresses caller-provided `Content-Length`, `Transfer-Encoding`, and `Connection` before the sender emits its computed length and selected connection policy.
- Add a regression test proving the managed framing and connection headers are omitted while an unrelated application header is preserved, locking in the response-smuggling hardening.

**src/http_parser/parse_utils.rs**
- Replace the unbounded `read_headers` helper and full-buffer delimiter scan with an interruptible, size- and deadline-aware reader.
- Add a single strict body-framing parser that rejects every `Transfer-Encoding`, duplicate `Content-Length` fields, invalid or overflowing lengths, and bodies above 10 MiB.
- Replace the blocking `read_exact` body helper with a deadline-aware, cancellation-aware exact reader.
- Strengthen status-line parsing by using ASCII whitespace only, accepting only HTTP/1.0 or HTTP/1.1 responses.
- Add regressions for invalid, duplicate, transfer-encoded, and oversized body lengths.

**src/http_parser/post.rs**
- Add checked capacity calculation and a Basic-authentication header builder that preallocates exact-size buffers for the network-specific username, API secret, Base64 value, and final header.
- Replace `format!`-based request assembly with an exact-capacity, checked builder returning a zeroizing string.
- Replace `post_auth` with `post_auth_with_timeout`, start one caller-supplied timeout budget before authentication work.
- Add a regression proving Basic authentication and a large JSON body are assembled exactly through the preallocated zeroizing buffers.
- Add local-server coverage for DNS names, IPv4, IPv6, explicit non-default ports, default ports, and URL user information.
- Add a delayed-header/delayed-body regression proving both response phases share one deadline and return `HttpReadTimeout` within the overall bound rather than each receiving an independent full timeout.

**src/lifecycle/seed.rs**
- Validate entropy lengths before generation, wrap imported bytes and generated mnemonics in zeroizing containers, remove the unused plain-hex conversion methods and obsolete Blake2-based key derivation.
- Add shared seed-target and persistence helpers that create or tighten the wallet directory to owner-only access, unconditionally reject overwriting an existing production wallet.
- Redesign seed backup to read encrypted data into zeroizing memory, atomically reserve the first available owner-only `.bak` name without a check-then-write race, use checked suffix increments, and synchronize the complete backup before durably removing the original and syncing its parent.
- Harden mnemonic recovery by requiring and securing an existing owner-only wallet directory, distinguishing a missing wallet with actionable UX guidance.
- Secure the wallet directory before loading, open the seed directly so missing-file UX remains distinct from permission and I/O failures.
- Define the current Argon2id profile (64 MiB, three iterations, four lanes), the supported-cost ceilings, and the legacy PBKDF2 iteration count; add serialized `KdfParams` metadata while keeping it optional for backward compatibility.
- Make new seed encryption use Argon2id and a 16-byte salt while retaining an explicit PBKDF2 path for legacy compatibility.
- Decrypt ciphertext in zeroizing storage, derive the key through the validated current-or-legacy KDF path, require the nonce to contain exactly 12 bytes instead of slicing and potentially panicking.
- Add regressions proving the ChaCha20-Poly1305 key type zeroizes on drop, mnemonic conversion returns a zeroing string and round-trips, and the RustCrypto AEAD implementation remains byte-for-byte interoperable with legacy Ring encryption and decryption.
- Adapt the encryption regression to fallible seed creation.
- Add an end-to-end migration regression that writes a legacy PBKDF2 seed, loads and verifies it, confirms the on-disk file was upgraded to Argon2id without changing the entropy.

**src/node_clients/http.rs**
- Add `JsonRequestError` so transport failures retain an optional structured HTTP status, and add common node-URL construction and configuration validation.
- Add context-aware decoders for output vectors, PMMR output listings, and block responses. 
- Replace the unbounded shared `HashMap` cache with independently cloneable, non-poisoning bounded LRU caches.
- Implement shared-state `clone_for_request`, expose atomic `NodeConnectionId` generation, and include version data in the connection-scoped cache/reset path.
- Add unsigned `testmempoolaccept` requests and require a matching preflight receipt before sending a signed transaction. Pin publication to the validated endpoint and remove automatic submission retries and node failover; retrying publication requires fresh validation. Rejected or unsupported preflight calls never send `push_transaction`.
- Add unit and concurrency coverage for LRU eviction, eager expiry removal, the 256-URL limit.

**src/tor/config.rs**
- Add a three-way Tor destination classifier and host-recognition helpers that distinguish a valid normalized Onion endpoint, a malformed Onion-like endpoint, and an ordinary non-Onion HTTP destination.
- Replace permissive address validation and lowercase string rewriting with one strict parser shared by `is_tor_address` and `complete_tor_address`.
- Expand completion tests to verify HTTPS and mixed-case normalization with a trailing slash, rejection of the legacy 64-character raw public-key form.
- Add a regression proving that newline, terminal escape, and bell characters in an invalid address are rendered as escaped text and that the resulting error contains no control characters.
- Add classification regressions proving valid identities normalize to Tor destinations, checksum-invalid or component-bearing Onion hosts.

### libwallet

**src/address.rs**
- Update hexadecimal public-key parsing to the current `VerifyingKey` API, require the decoded value to be exactly 32 bytes before parsing, and explicitly reject weak/small-order Ed25519 keys.
- Replace manual uppercasing, global string replacement, Base32 decoding, byte truncation, and re-encoding checks with strict Onion v3 host parsing.
- Replace the hand-written SHA-3 checksum, version-byte assembly, and Base32 encoding with Tor's `HsId` formatter. Render the public identity explicitly through the safe-log unredacted wrapper.
- Add regressions proving that raw small-order keys, checksum-valid Onion identities containing a weak key, and checksum-valid identities containing a noncanonical Edwards encoding are rejected.

**src/api_impl/foreign.rs**
- Add a payment-proof helper that rewrites the legacy file-proof sender-equals-receiver placeholder to the wallet's Onion address and then verifies that the advertised receiver address is actually bound to the wallet signing key, preventing signatures for an unrelated receiver identity.
- Harden receive-side payment proofs by validating the claimed sender as an MQS identity, requiring it to match the transport-authenticated sender when one is available.
- Verify participant-message signatures before key allocation, signing, or staged receive changes, including when MQS has already authenticated the transport. Altered messages, missing signatures, and signatures without messages are rejected without consuming the receive attempt.
- Preflight online invoice finalization after restoring the compact transaction body and local participant, before completing the transaction or consuming its signing context.
- Add regression tests proving that a receive callback can clear its registry without deadlocking and is not called again, invoice-context mapping preserves non-not-found backend errors, and the legacy file-payment-proof placeholder is rewritten to the wallet receiver address before signing-key binding is enforced.

**src/api_impl/owner.rs**
- Add shared context-safety and invoice-validation helpers. Only `PrivateContextNotFound` is treated as absence or translated to finalized/cancelled; backend failures propagate unchanged. Ephemeral contexts must match both the expected participant and Slate UUID, self-invoice issuer contexts must describe no inputs and exactly the expected plain outputs unless compact transport omitted them, and unsupported invoice `estimate_only`, TTL, or `payment_proof_recipient_address` options are rejected before refresh or wallet mutation.
- Validate invoice participant shape and signed messages before selecting keys, reject unknown payer accounts, and search both live and archived logs for prior paid or cancelled uses of the Slate UUID.
- Bind output locking to a context with the matching participant and Slate UUID while preserving non-not-found backend errors, then centralize locking in `lock_tx_outputs_with_context`.
- Retain `finalize_tx` as an unversioned wrapper and add `finalize_tx_with_output_version` so rebuilt responses can be checked against their actual Slate/Slatepack format. Finalization uses one fresh tip for TTL and late-lock decisions, binds the sender context to participant zero and the response UUID.
- Preflight online invoice payments and send finalization against the node after reconstructing the available body. Late-lock sends run this check before saving the selected context, input locks, change outputs, or transaction log, so rejected transactions remain retryable.
- Require local transaction validation and node preflight in `post_tx`, covering ordinary posts, reposts, scan-generated replay protection, swaps, and C-library publication. Nodes without `testmempoolaccept` support now return an error before the signed transaction is submitted.
- Resolve `backwards_from_tip` against that scan's own fresh anchor, guard subtraction and exponential-step overflow, verify connection continuity and the final anchor.
- Add regression tests proving that only a genuinely missing private context is converted to absence/finalized state, backend errors survive unchanged, and transaction-session contexts cannot be reused across participant IDs or Slate UUIDs.

**src/api_impl/types.rs**
- Add `LateLockArgs` and its conversion from `InitTxArgs`, preserving only the input-selection, change, message, TTL, address, output, and fee preferences required when a late-lock send is finalized.
- Add regression tests proving that custom blinding-factor serialization preserves the hexadecimal JSON format, numeric JSON swap fees are rejected in favor of strings.

**src/error_serde.rs**
- Add a serializable mirror of the legacy `io::ErrorKind` set plus bidirectional conversions.
- Add serialization and deserialization adapters for every current core serialization error variant, including nested Secp256k1 errors and structured unexpected-data payloads.
- Add JSON regression coverage with a shared round-trip helper, including the lifetime accommodation required by two legacy `&'static str` wallet-error variants.

**src/internal/chain_session.rs**
- Define `NodeReadSession`, which records both the serving node's connection identity/generation and the chain-tip anchor for a compound read.

**src/internal/keys.rs**
- Replace the generic `retrieve_existing_key` lookup helper with `canonicalize_stored_identifier`. The new helper validates the declared path depth, recovers the historical anti-replay height stored in the fourth component of legacy depth-three output identifiers.
- Add `output_child_index`, which derives an output's child index from its validated path, handles zero-depth identifiers.
- Add `output_parent_key_id`, which derives the account path from a stored output identifier.
- Add regression tests proving that a legacy depth-three identifier with an encoded anti-replay height is restored to its canonical form while returning that height.

**src/internal/output_proof.rs**
- Add `existing_output`, which reuses an output's original rangeproof when a legacy transaction context has no saved construction height instead of guessing a height and regenerating a proof with the same alpha/rho masks.
- Add `rewind_with_height`, which verifies a rangeproof before rewinding it and recovers the anti-replay construction height from the unused fourth component of the historical depth-three proof identifier.
- Add regression coverage for the new functionality.

**src/internal/scan.rs**
- Migrate the process-global scan-interruption registry to the shared non-poisoning `RwLock` and make `interrupt_scan` fallible.
- Replace the obsolete lightweight self-spend output structure with a shared node-output alias, explicit unbounded/capped/exact PMMR-end semantics, and the stateful `PmmrPageValidator`.
- Split ordinary PMMR collection into a public capped wrapper and a connection-bound internal collector used by anchored scans. The collector rejects failover between pages, applies the shared PMMR validator, uses checked progress calculations and the callback status interface.
- Add a coordinated replay-recovery workflow that first restores absent candidates or reactivates spent records at their current PMMR positions, preserves candidates already protected by active transactions, 
groups the remainder by their recovered account.
- Add immediate history-based replay evidence and legacy commitment repair. Confirmed live transactions and confirmed archived logs/stored transactions contribute their input commitments, with only a genuinely missing stored transaction tolerated.
- Harden the short-range block-scan strategy with checked depth, span, batching, and progress calculations plus connection checks after node reads. Returned blocks must have the exact count and endpoints, consecutive heights, linked parent hashes, and the anchored terminal hash.
- Detect duplicate wallet records sharing one commitment and reconcile them explicitly after chain data is available. The live MMR position, or a transaction-linked deterministic fallback, selects the canonical record.
- Replace the standalone public scan routine with crate-private `scan_with_session`, which requires an explicit cryptographic context and pre-established anchor.
- Restore account labels before account-directed replay transactions, persist the ordinary reconciled snapshot before creating defensive self-sends, and verify the anchor around label, replay, and completion writes.
- Count transaction activity by logical Slate UUID so a partially cancelled self-send remains active and missing bookkeeping fails safe instead of unlocking funds.
- Introduce explicit `Confirmed`, `Unconfirmed`, and `Unknown` evidence for legacy transactions without kernels. Only a currently observed chain output can newly confirm one.
- Add regressions for allocated/released interruption contexts, best-effort skipping of unsupported switch commitments, recovery of an ordinary account key from an S2C Coinbase proof, collision-free restored labels, and PMMR pagination.
- Add focused tests for fail-closed duplicate-output repair, derivation and caching of missing commitments, deterministic duplicate-Coinbase selection, logical self-send activity, retention of pending no-change reservations during archive.
- Add transaction-history repair tests proving that creator selection is account-local and independent of stored-transaction output sharing, creator and spender associations remain distinct, pending spenders survive Coinbase reconstruction and reorg state changes.
- Add a controllable node client and end-to-end consistency regressions for body-chain reorganization, independent header-first forks, malformed or missing ancestry, mid-read failover, genesis and unchanged tips, stale-cache refill, rollback, and initial anchor establishment after failover.

**src/internal/selection.rs**
- Harden sender construction by compiling deterministic nonce/initiator controls only with `test-support`, and rejecting non-Plain kernel policies.
- Add `input_commits_from_context`, a shared fallible conversion from saved input identifiers and amounts to commitments.
- Add the shared `change_output_count` policy used by both construction and Slatepack-size budgeting. It rejects zero requested outputs when change exists, safely converts the small-change calculation to `usize`, and reports the actual reduced output count rather than assuming a single output.
- Make input/change assembly account-aware and overflow-safe.
- Add a production-consensus upper bound for `max_outputs`, cap the preferred input count at the hard limit, and centralize output eligibility.
- Harden the sliding-window coin selector by validating its limit, classifying only confirmed sent outputs as change, applying the common eligibility check.
- Add `validate_context_input_features` for legacy V2/V3 slates that encode input features. It verifies saved input values and commitments against wallet records and rejects a returned Slate that removes an input or changes it between `Plain` and `Coinbase`.
- Avoid duplicating inputs/outputs already present in the Slate, preserve input features, distinguish an expected missing output from backend failure, validate staged outputs, and reconstruct outputs with their saved original height.
- Add regressions for small-change output budgeting, rejection of an unbounded `usize::MAX` output limit, capping the optimal input target, and enforcing the change-confirmation policy even when a change output is explicitly selected.

**src/internal/tx.rs**
- Add invoice-Slate validation that derives the local public blind and nonce from the saved context and verifies the fully adjusted transaction and participant record before round-2 signing; deterministic controls remain test-only.
- Add helpers that select the exact self-invoice/finalizer signing keys, calculate the aggregate-signature challenge, verify peer partial signatures, and validate all peer-controlled transaction data before local signing.
- Make cancellation active-log-only, idempotent, dependency-aware, and atomic. Resolve and validate every same-Slate transaction before mutation, skip already-cancelled members.
- Document and preserve the mwc713 payment-proof wire format while adding canonical sender validation and a receiver-address/signing-key binding check for both MQS/secp256k1 and OnionV3/Ed25519 proofs.
- Redesign completed payment-proof verification into a side-effect-free validation phase followed by explicit `TxProof` construction.
- Add regressions for rejecting an oversized but consensus-valid Slatepack before finalization, cross-transaction cancellation-lock rejection and same-group acceptance, preservation of the legacy payment-proof message, bounded/control-safe display of malformed signatures and addresses.

**src/internal/updater.rs**
- Extend advanced transaction filtering with an optional parent-account constraint while preserving the original public unscoped wrapper, use the scoped implementation from account-aware callers. 
- Add an active-log-only transaction lookup helper. Cancellation and other mutation-sensitive callers can now avoid accidentally resolving an archived record with the same ID or Slate UUID, while the general retrieval path retains its deliberate archive fallback.
- Refactor cancellation to stage its transaction and output changes into a caller-owned `WalletOutputBatch` rather than opening and committing a private batch, allowing a higher-level cancellation group to commit atomically.
- Add manual-lock classification that uses a cached commitment when present and derives a missing commitment for legacy or restored outputs when necessary. 
- Replace legacy/test-mode Coinbase construction with mandatory S2C-bound construction.
- Add strict Coinbase-key eligibility checks and distinguish retryable key conflicts from other failures. A caller-supplied key may be reused only for a live, unindexed, unconfirmed, transaction-unassociated Coinbase candidate whose stored and derived account/child metadata match the active account.
- Construct and store a bound Coinbase for one validated key with checked maturity-height arithmetic and fallible reward calculation. Validate key eligibility both before construction and again inside the write batch, build the complete S2C output/kernel/opening before persistence.
- Orchestrate safe Coinbase-key selection and retries: try an eligible requested key first, advance to fresh keys after reuse failures or stale-index collisions, warn on each rejected candidate, and immediately return non-key-related errors.
- Add serialization regressions requiring an explicit string binding digest in Coinbase requests.
- Add focused regressions for cached and derived manual-lock commitments, propagation of derivation failures, rejection of the former empty-string false match, correct spent/non-spent archive selection, and rejection of zero pagination lengths.

**src/proof/base58.rs**
- Add a checked calculation for the maximum plausible Base58-encoded public-key length, conservatively allowing the largest SEC1 representation plus the version and checksum.
- Add regression tests proving that a payload shorter than its version is rejected without a panic, oversized public-key strings are rejected before decoding, decode errors do not echo newline or terminal-escape-bearing input.

**src/proof/crypto.rs**
- Update Secp256k1 public-key hexadecimal conversion to use the caller's context, sanitize malformed-input errors, and propagate fallible compressed-key serialization through the Base58 helper.
- Migrate ECDSA signature hexadecimal conversion to `EcdsaSignature`, use the caller's Secp256k1 context for DER parsing and serialization.
- Migrate Ed25519 public-key conversion from the legacy `PublicKey` API to `VerifyingKey`, require an exact 32-byte decoded value, and explicitly reject weak/small-order keys.
- Migrate Ed25519 signature conversion to the current API, require decoded signatures to be exactly 64 bytes before construction, sanitize decode errors, and expose fallible trait-compatible encoding.
- Decode secret keys through the fixed-size secret-key helper, use the caller's Secp256k1 context, and return encoded secrets as `Zeroizing<String>`.
- Make commitment parsing use the caller's Secp256k1 context, sanitize hexadecimal errors, propagate structural construction failures, and explicitly validate the decoded commitment before accepting it.
- Add regressions confirming that every hexadecimal parser rejects a terminal-control payload without echoing it or emitting control characters, weak Ed25519 verification keys are rejected.

**src/proof/message.rs**
- Add `secure_salt_and_nonce`, which fills the encryption salt and ChaCha20-Poly1305 nonce through the fallible OS-backed `SysRng` and propagates entropy-source failures instead of relying on the previous thread-local RNG.
- Centralize the legacy wire-compatible ECDH/PBKDF2 derivation in `derive_message_key`. The shared point, its serialized representation, and the derived key are held in zeroizing storage.
- Add regression tests proving that the zeroizing ECDH key path stays compatible with the legacy derivation fixture, only the canonical 12-byte nonce encoding is accepted.

**src/proof/proofaddress.rs**
- Make address parsing strictly distinguish canonical 52-character MQS addresses from canonical 56-character OnionV3 addresses. MQS input goes through the new network-aware canonical validator; Onion input must parse, convert to an Ed25519 key, and round-trip to the identical text.
- Add `validate_mqs`, which enforces the fixed 52-character boundary, active-network prefix, valid compressed key encoding, and exact Base58Check round trip.
- Add a regression test that constructs and validates a canonical 52-character MQS address.

**src/proof/tx_proof.rs**
- Replace the UUID-only global proof map with cache entries keyed by wallet context and Slate UUID. Each entry keeps the proof in a stable, reference-counted slot, records reservation state, expiry, and listener generation.
- Add explicit `Inserted`, `Duplicate`, and `Full` insertion outcomes, prune expired unreserved entries, expose periodic maintenance, and bound the cache at 10,240 entries.
- Add `ProofCacheReservation` for exclusive, rollback-safe finalization without holding the global cache lock during file I/O.
- Harden proof extraction and authentication. Versioned proofs must use an empty challenge; Tor metadata is rejected on non-Tor proofs; Tor signatures are mandatory, exactly 64 bytes, checked against a canonical receiver, and verified with strict Ed25519 rules.
- Secure stored-proof persistence. Create owner-only directories, require identifiers to parse as UUIDs before deriving filenames, distinguish missing files from permission/I/O failures.
- Add shared test fixtures for isolated proof-cache contexts.
- Add proof-cache regressions covering checked generation exhaustion, reservation rollback after persistence failure, commit removal, stable decryption-key allocation.
- Add persistence and Tor-signature regressions.
- Add hostile-input regressions proving response and Slate construction bound and escape terminal-control-bearing signatures, encrypted messages, salts, and receiver fields.
- Add an end-to-end compact Tor-proof fixture and security regressions for the complete verification path.

**src/reply_cache.rs**
- Add `ReplyBinding`, private channel and peer enums, and constructors for encrypted Foreign RPC, file, embedded-library, and authenticated MWCMQS traffic.
- Add `ReplyRequest` and its canonical serialized form for receive and invoice-finalization requests.
- Add the cache key, entry states, and reservation result model.
- Implement the mutex-protected `ReplyCache`, default construction, reservation, and lifecycle clearing. 
- Add the `ReplyReservation` ownership guard and completion path.
- Add reply-cache fixtures and a regression proving that an exact authenticated retry returns its cached Slate while a different sender, transport channel, or request body for the same Slate UUID is rejected as a response mismatch.
- Add timing and ownership regressions proving replies expire exactly at 15 minutes, dropping a reservation immediately releases its in-flight slot.
- Add memory-boundary regressions for oversized replies and payment-proof domains.
- Add a cleanup regression that fills the cache with expired ready and in-flight entries, performs a new reservation at the expiry boundary, and verifies all stale state and its byte accounting are removed before the new slot is admitted.

**src/slate.rs**
- Add reusable per-participant message verification. It rejects oversized messages and mismatched message/signature presence, verifies signed text, propagates cryptographic failures, and terminal-escapes peer-controlled text in logs.
- Add strict validation for send responses and returned finalized invoices against the locally sent Slate. These checks bind the UUID and compact mode, enforce the supported two-party declaration and unique IDs, reject extra, missing, incomplete, or altered participant records and oversized messages.
- Validate initial send and invoice Slates before key allocation or signing by requiring exactly participant 0 in a two-party exchange. Initial invoices additionally bound message sizes and restrict the kernel to the implemented plain policy.
- Add saved-context validation for standalone send and invoice response flows.
- Strengthen legacy invoice comparison by binding compact mode, participant declaration, kernel feature, and lock height.
- Add a keyed Blake2b fingerprint over the Slate UUID, chain context, participant ID, local and aggregate public keys/nonces, and kernel message for durable aggregate-signature challenge binding.
- Add a comprehensive pre-signing validation stage that binds the local participant to its signing keys, performs lightweight consensus checks, requires one kernel matching the Slate policy.
- Add send-response context regressions covering valid and compact flows plus stripped messages, wrong declarations, excess or duplicate records, unexpected IDs, missing or incomplete parties, altered initiator keys, and oversized messages.
- Add invoice initial/response fixtures and regressions that enforce issuer-context binding, immutable metadata, two-party structure, message limits, plain-kernel policy, UUID and compact-mode identity.
- Add standalone response and invoice-context tests for required counterparties, unique in-range IDs, compact omissions, context-bound issuer data, complete participants, bounded messages.
- Add aggregate-signature challenge persistence tests proving that the same challenge can be retried, a changed aggregate nonce is rejected.
- Add consensus and conversion regressions proving read validation rejects overweight and cut-through transactions.

**src/slate_process.rs**
- Add `SlateProcessTracker` with a mutex-protected map from active Slate UUIDs to unique ownership tokens.
- Add sessionless invoice-input reservation under the active Slate guard's ownership token.
- Add lifecycle clearing and identity-safe RAII release.
- Add concurrency and lifecycle regressions proving a duplicate UUID remains blocked until its guard drops.
- Add an input-reservation integration regression proving a Slate guard blocks a `TxSession` from claiming the same commitment.

**src/slate_versions/mod.rs**
- Replace derived untagged deserialization of `VersionedSlate` with declared-version dispatch.
- Add regression coverage that rejects non-null TTL metadata on a declared V2 Slate, accepts an explicitly null TTL for compatibility, and returns `SlatepackEncodeError` when a recipient is paired with a plain V3 representation.

**src/slate_versions/ser.rs**
- Add focused deserialization fixtures and a regression test for 31- and 33-byte optional public keys plus 63- and 65-byte required and optional signatures.

**src/slate_versions/v2.rs**
- Remove the obsolete `CoinbaseV2` wrapper and its `CbData` conversion through V3 output and kernel types. Coinbase response conversion no longer belongs to the legacy Slate-version layer after the bound-Coinbase API redesign.
- Add a regression test that round-trips a valid V2 output and then verifies that peer-supplied JSON.

**src/slate_versions/v3.rs**
- Add an explicit legacy blank commitment, and introduce shared kernel and optional-participant signature serializers.
- Add regression tests for byte-for-byte legacy compact-signature round trips, rejection of short and cryptographically invalid signatures, all-zero blank kernel compatibility, oversized range-proof rejection, maximum-length valid range-proof round trips, and refusal to downgrade TTL- or payment-proof-bearing V3 Slates to V2.

**src/slatepack/armor.rs**
- Harden slatepack armoring code, add multile checks.
- Add regressions proving that an armored payload decoding to fewer than four checksum bytes is rejected and that oversized input is rejected with the new maximum-size error before parsing.

**src/slatepack/packer.rs**
- Add `validate_slatepack_receive_direction` to validate decoded header roles before an inbound request is processed.
- Before serialization, validate `SendInitial` and `InvoiceInitial` against the actual selected wire version and expected participant growth, rejecting an oversized initial Slate before signing or transport work.
- Add receive-direction regressions proving that encrypted requests addressed to the local wallet and encrypted self-sends are accepted, requests addressed to another wallet are rejected, plain Slates remain valid, and one-sided sender metadata fails as inconsistent.

**src/slatepack/slatepack.rs**
- Add `validate_slatepack_size`. For SP output, the validator conservatively budgets the completed transaction—including expected inputs and outputs, a kernel, two maximum-size participant records, payment proof, checksum, rejecting transactions that cannot fit before signing or transport while leaving V3/V3B output unaffected.
- Embed the immutable reference Smaz codebook and build its reverse lookup table locally. This removes the obsolete `smaz` dependency.
- Implement a reference-compatible local Smaz compressor, verbatim-run encoder, and decoder.
- Move the existing compression test to the local codec and add regressions for SP size budgeting and arithmetic overflow, rejection of oversized participant messages.
- Add cryptographic-header regressions proving that encrypted Slatepacks reject weak sender or recipient keys, headers in which neither identity belongs to the supplied wallet, encoding with a sender that does not match the encryption key, and weak peers that produce non-contributory key exchanges.

**src/status.rs**
- Add the serializable `StatusMessage` enum with output-update, full-scan warning, scan-progress, scan-completion, repair-warning, and informational variants.
- Define a lifetime-aware `StatusCallback` function trait and add `send_status`, which invokes an optional callback immediately on the wallet operation's thread.

**src/step_rng.rs**
- Define the cloneable `StepRng` state and constructor around a current value and fixed increment, explicitly documenting that this legacy predictable generator exists only for compatibility with existing tests.
- Implement the current fallible `TryRng` interface with an uninhabited error type.

**src/swap/bitcoin/api.rs**
- Add coherent secondary-chain snapshot helpers. Unspent outputs are read before the tip so forward movement is conservative.
- Add `read_btc_with_fallback`, which runs an entire multi-field read while holding one backend and, on failure, reruns the complete operation against the fallback backend.
- Harden balance reads by reporting a missing derived address, reading outputs and tip atomically per backend, treating zero or future output heights as pending, calculating depth through the shared conservative helper, and using checked additions for pending and confirmed amounts.
- Freezing the exact inputs keeps retries and fee replacements stable after a mempool spend hides them and prevents later unsolicited deposits from changing the authorized transaction.
- Replace the single all-input refund builder with a durable `BtcRefundPlan`. The builder observes plan attempts and funding through one backend, migrates an existing saved refund, retains inventory before later failures.
- Separate refund preparation from broadcast. A non-posting call constructs the next transaction for durable owner storage.
- Replace output-based MWC confirmation inference with bounded kernel confirmation lookup.
- Add the seller's pre-redemption funding-acceptance gate. It validates role, amount and input-count bounds, required confirmations, per-chain coinbase maturity, configured redemption-fee affordability, and destination dust rules against one backend before releasing the MWC redeem signature.
- Harden seller redemption publication with explicit-context signing and a reported role error instead of an assertion.
- Split MWC confirmation polling from secondary-chain polling so recovery states can observe either chain independently.
- Rebuild secondary confirmation polling around one complete backend snapshot. Deduplicate every current, candidate, and retained redemption ID.
- Add an explicit refund-preparation hook that validates the configured buyer address and builds the next durable refund transaction before posting.
- Add a recording BTC-client fixture and regressions proving that a secondary snapshot reads transaction confirmations and unspent outputs from one client, reads the tip last, converts confirmations inconsistent with that tip to zero, and treats a future-height lock output conservatively.

**src/swap/bitcoin/client.rs**
- Add `secondary_confirmations_at_tip`, which reports mempool height zero as unconfirmed and uses checked subtraction and addition for mined transactions.
- Extend `BtcNodeClient` with coinbase identification, confirmation-count, and confirmed-spend lookup contracts.
- Posting now rejects unknown inputs, checked-sums all input and output values, reports arithmetic overflow, rejects transactions that create value, and retains the existing duplicate-confirmed-transaction check before entering the mempool.
- Implement the new operations for the test backend.
- Add regressions proving that `unspent` removes an output consumed by a pending transaction and keeps it removed after mining.

**src/swap/bitcoin/electrum.rs**
- Add the Electrum `blockchain.scripthash.get_history` request, providing the transaction history needed to locate a confirmed transaction that spent a swap output.
- Centralize UTXO conversion in `outputs_from_utxos`. Reject invalid transaction hashes instead of silently dropping them, deduplicate by the complete outpoint rather than transaction ID so sibling outputs are retained.
- Extend verbose Electrum transactions with optional input metadata, add the input and history response models, and implement strict coinbase classification. 
- Harden `bitcoin-script:` address parsing with checked checksum removal and validated payload boundaries before subtracting or slicing.
- Implement the Electrum backend's coinbase and direct-confirmation queries. Missing funding transactions and malformed input classifications now fail explicitly, while known transactions without a positive confirmation count report zero.
- Implement confirmed-spend recovery for swap outputs. Skip history while the requested outpoint remains unspent.
- Add a scripted local JSON-RPC fixture and coinbase-classification regressions covering valid reward and ordinary transactions.
- Add confirmed-spend recovery regressions covering history filtering, confirmed-spender discovery, raw transaction/hash/input validation, unconfirmed candidates.
- Add a connection-cache regression proving that a failed socket write marks the cached client disconnected and forces an immediate reconnect attempt rather than reusing it until the 30-second idle timeout.
- Add UTXO regressions proving exact duplicate removal, preservation and deterministic ordering of sibling outputs, correct aggregate value, and rejection of conflicting duplicate metadata.

**src/swap/bitcoin/recovery.rs**
- Add `RecoveredTransaction` to return the matched saved-attempt index, actual confirmed transaction, and confirmation count.
- Add the documented generic `recover_confirmed_variant` helper over a caller-supplied BTC backend and iterator of saved attempts.

**src/swap/bitcoin/refund.rs**
- Add strict serializable state for `BtcRefundPlan`, explicitly retained uneconomic outputs, immutable-input refund batches with every signed attempt and legacy hash, and the `BtcRefundProgress` state machine.
- Initialize a deterministic refund inventory by rejecting duplicate outpoints, checking total-value overflow, and sorting larger deposits first with stable outpoint tie-breaking so they can fund later fees.
- Add unsigned refund-template construction with nonempty and duplicate-input validation, checked lock-time and amount arithmetic, carry-aware input scripts, and a single destination or carry output.
- Build and sign refund batches for BTC, BCH, LTC, Dash, and Dogecoin, selecting either the buyer carry P2SH or validated refund destination.
- Add regressions for marginal-fee boundary handling, CompactSize-aware fee estimation, retention and reporting of deposits equal to or below their spending cost, idempotent exclusion, and flat-fee behavior.

**src/swap/bitcoin/rpc.rs**
- Add a shared ten-second RPC timeout and a `DeadlineTcpStream` wrapper for both TLS and plaintext transports.
- Handle timeout errors better with error reporting and counting whole read/write session to a single timeout. 
- Add regressions proving that plaintext and TLS write failures and missing writers all mark the stream disconnected, while a successful write preserves an already buffered response.
- Add deadline regressions for a slowly trickled plaintext JSON response, incomplete trickled TLS records during both reads and handshake-triggering writes.

**src/swap/bitcoin/types.rs**
- Add strict `BtcRefundTransaction` persisted state containing the signed transaction, original inputs, destination, typed fee, and optional buyer-owned carry output; and make `BtcData` reject unknown fields.
- Harden swap-script construction by deriving the maximum lock time from the shared 30-day policy with checked conversions and addition, revalidating the secondary lock time at the final artifact boundary for legacy or imported swaps.
- Add shared redemption-fee calculation and conservative full-transaction sizing using maximum-length DER signatures, every input, CompactSize prefixes, and the actual output.
- Rework locked-output transaction construction around typed fee units and checked arithmetic.
- Fail Zcash spends explicitly and retain the former implementation only as disabled reference code, reflecting that this transaction path is unsupported.
- Add cross-currency dust-boundary regressions for BTC, BCH, LTC, Dash, and Dogecoin across P2PKH, P2SH, and supported witness destinations, exercising both redeem and refund paths.
- Add BTC/BCH signed-size fee regressions for one input and the full 32-input accepted set, for both redeem and refund scripts and multiple per-kilovbyte rates.
- Add standard-weight boundary coverage proving that the maximum admitted 32-input Bitcoin redemption remains relayable.

**src/swap/buyer.rs**
- Add typed `StaticallyValidatedOffer` and `ValidatedOffer` tokens so offer processing can prove which validation phase has completed before allocating durable wallet resources.
- Add shared fail-closed validators for refund height, participant records, and secondary payloads. 
- Strengthen refund-slate and participant validation. The partial refund must decode as a non-compact, lightweight-valid transaction with no peer-supplied inputs, exactly one output and one height-locked kernel.
- Validate the offered lock and future refund together through unsigned node preflight on one selected connection.
- Add a checked reconstruction of the offer's complete MWC and secondary deadline chain, including confirmation safety margins, message exchanges, redeem periods, refund time, and currency block periods.
- Extract Ethereum gas validation into a pre-allocation step using integer, unit-tagged secondary fees and explicit conversion to required gwei.
- Make `accept_swap_offer` orchestrate static validation, anchored node validation, gas validation, and a final expiry check before delegating to `accept_validated_swap_offer`.
- Validate the stored redeem participant set, the seller response's expected ID and completion stage, and its binding to the originally offered round-one record before accepting a peer partial signature.
- Add unit coverage for refund-height safety.
- Add a marketplace-message regression proving the winner lease is carried in the acceptance.
- Add static-offer regression coverage for a valid complete fixture and rejection of compact lock/refund slates, coinbase lock outputs, peer-supplied refund inputs.

**src/swap/ethereum/api.rs**
- Add helpers that retain a locally signed transaction hash from either success or an ambiguous submission error and represent observed Ethereum lock amount, term acceptance, and finality independently.
- Rebuild Ethereum refund-height and deposit construction around validated deadlines and a coherent chain tip.
- Replace output-based MWC confirmation inference with bounded kernel lookup. 
- Add finalized Ethereum receipt handling and a secondary-only confirmation snapshot. Successful redeem/refund receipts count only after their canonical block is finalized, while missing, pending, or reverted transactions remain eligible for recovery.
- Rewrite lock inspection to retain the on-chain amount even when the deposit has wrong terms, allowing recovery paths to see refundable funds.
- Make seller redeem publication role-safe, import-safe, and recoverable. Replace the seller assertion with a reported error.
- Split primary-chain, secondary-chain, normal, secondary-only, and cancellation confirmation polling. Anchor all three MWC kernel reads to one `NodeReadSession`, verify the connection between reads, calculate depths at a fresh final tip, and merge them with a separate Ethereum snapshot.
- Apply the redeem publication safeguards to buyer refunds.
- Add an explicit ERC20 approval-recovery hook, including for completed buyer trades.
- Add controlled ERC20 deposit retry and cancellation recovery. Restrict retrying finished trades and cancelling after redemption/refund has begun.
- Harden secondary lock publication with a reported buyer-role error, route ERC20 locks through the coordinated reset/approval/deposit state machine, and give native ETH deposits the same receipt reconciliation and durable signed-recovery behavior as redeem/refund.
- Add a lock-failure query that treats pending receipts as still live and reports failure only when a reverted receipt is finalized.
- Make private-wallet redirection idempotent and observable. Replace the seller assertion with a reported error, refuse to create a second transfer while a hash awaits reconciliation.

**src/swap/ethereum/client.rs**
- Add `EthChainTip`, which couples a mined block's height and timestamp in one observation, and `EthSwapDetails`, whose refund block uses `U256`. These types prevent deadline calculations from mixing different tip reads.
- Extend `EthNodeClient` with coherent chain-tip reads, an explicitly finalized block hash, and chain-plus-custody-contract validation.
- Update Eth testing clients with support of extended functionality.

**src/swap/ethereum/ethereum.rs**
- Implement `Zeroize`, `Drop`, and `ZeroizeOnDrop` for `EthereumWallet`, clearing every optional string field when explicitly erased or dropped. Add a custom `Debug` implementation that preserves useful public metadata but hide sensitive data from logging.
- Add display regressions covering an empty wallet, the complete established layout, explicit zeroization, empty values, Unicode, and embedded newlines.
- Add custom writers proving secret values are borrowed from their original wallet buffers rather than copied and that every possible formatter failure is returned immediately without subsequent writes.
- Add a deterministic derivation regression proving `generate_ethereum_wallet` matches mnemonic derivation without a BIP39 passphrase, differs from derivation using the wallet password as a passphrase, and retains no password.
- Add regressions requiring the wallet to implement drop-time zeroization, confirming debug output excludes the password, mnemonic, and private key, and verifying that recovery-material disposal removes only the password, mnemonic, and extended private key while preserving the runtime signing key.

**src/swap/ethereum/funding.rs**
- Add per-trade `Reservation` snapshots containing funding phase, cancellation state, approval history, and deposit/cancellation recovery records.
- Add `record_swap` to rebuild or refresh buyer-side Ethereum allowance reservations from persisted trade data after load/save.
- Add the top-level funding advance coordinator. It binds saved state to the current allowance identity, validates the Ethereum chain and contracts, restores legacy pending phases from saved hashes.
- Add the one-transaction-at-a-time ERC20 funding state machine.
- Add an explicit approval-recovery entry point for pending reset or approval work, including cancelled trades. 
- Add pending-approval reconciliation. Mined attempts move their signed records into ordered history, retain the authoritative successful approval hash only for a successful non-reset approval.
- Add nonce-ordered approval-history reconciliation before later account transactions. Signed records are retained until their receipts are canonically finalized.
- Add explicit same-transaction deposit retry and same-nonce cancellation recovery under the allowance lock.
- Add a shared approval/reset submission helper that preserves a locally signed or ambiguously submitted transaction hash, transitions to the correct pending phase.
- Add a deposit submission helper that persists every candidate hash—including hashes recovered from ambiguous failures or signed replacement history—together with its pending phase and effective gas budget.

**src/swap/ethereum/infura.rs**
- Add typed native/ERC20 contract classification, restrict accepted runtime hashes to explicitly supported chain/contract combinations, reject malformed or zero custody addresses, and validate nonempty deployed bytecode against the audited runtime hashes.
- Centralize synchronous-to-async execution and Web3 error handling. Worker creation, Tokio runtime construction, panics, RPC calls, contract calls, signing calls, and ERC20 allowance queries now retain their operation and original error source.
- Map configured networks to fixed chain IDs and verify `eth_chainId` before safety-sensitive operations.
- Add a process-wide submission lock per chain/account and classify raw-transaction submission failures and timeouts as ambiguous while preserving the locally computed hash.
- Add same-nonce transaction recovery. Fee replacements increase by at least 20%, signed deposits can be cancelled with a separately recoverable zero-value self-transfer at the original nonce.
- Add explicit legacy-transaction construction and local ABI encoding for ERC20 transfers and arbitrary contract calls. Replace fixed `budget / gas_price` gas limits with `eth_estimateGas`, a checked 20% execution margin, the lesser of the current block limit and the EIP-7825 mainnet cap.
- Rebuild native and ERC20 direct transfers around verified chain IDs, pending-state gas estimates, reservation-aware pending nonces, explicit local chain IDs, local token calldata, and retain-before-broadcast recovery records.
- Replace public string custody-address fields with private, already parsed `SwapContracts`; validate the configured network and both nonzero addresses during construction; and add an account-only constructor for balance and direct-transfer use.
- Consolidate contract mutation submission into one locked path that verifies the chain, locally ABI-encodes calldata, estimates and bounds gas, allocates a reserved nonce, signs locally, records recovery, and broadcasts the exact raw transaction.
- Rewrite Ether/ERC20 balance and direct-transfer helpers to use the common timeout/error/runtime paths, checked wallet-address and `U256` conversions, accurate human-readable formatting, and explicit Ethereum/ERC20 type validation.
- Route native and ERC20 initiation and redemption through the common recoverable submission path with integer fee budgets and mutable signed recovery.
- Expand the Eth node-client implementation with coherent chain-tip reads, explicit mainnet finalized-block support, and full endpoint/custody validation.
- Make balance dispatch reject non-Ethereum currencies before network access, preserve a missing receipt as a pending transaction while propagating RPC failures, reject zero transfer destinations before wallet or endpoint access.
- Implement recoverable deposit retry and same-nonce ERC20 deposit cancellation, validating the original and cancellation records before use.
- Add end-to-end recovery regressions for native/ERC20 initiate, redeem, refund, approval/reset, and cancellation calls.
- Add finality regressions requiring an explicit mined finalized block, pinning finalized lock queries to its block hash, propagating unavailable or malformed RPC responses, and accepting a receipt only when its block remains canonical at or below the finalized height.
- Add native-transfer gas regressions showing that low prices no longer inflate the declared gas limit, contract recipients receive the estimated work plus margin.
- Add boundary tests for unexpected ERC20 token contracts, full-width refund blocks, remote balance overflow, exact integer-gwei conversion, and the distinction between account-only and swap-capable clients.
- Add gas-policy regressions for 1.5-times node pricing, rounded 20% estimate margins, exact maximum-fee enforcement, overflow/zero estimates, real native/ERC20 initiation calldata, pending-block estimation, and mainnet transaction limits.
- Add balance-format and native/ERC20 direct-transfer recovery coverage. Tests verify pending nonces and explicit EIP-155 chain IDs, retain recovery before either successful or ambiguous submission.
- Add regressions for per-chain/account lock identity, compatibility of the existing double-hash redeem authorization, fixed network-to-chain mapping, nonzero parsed contract addresses.
- Add error, shutdown, and input-validation regressions proving RPC errors retain their operation and source, worker panics retain bounded diagnostic meaning.

**src/swap/ethereum/recovery.rs**
- Add atomic retention of a freshly signed direct transfer before broadcast.
- Add account-scoped direct-transfer lookup by any attempted original or replacement hash, returning a cloned recovery record or an explicit missing-recovery error.
- Add redirect tracking and durable-candidate refresh.
- Add guarded direct-transfer replacement updates and an account-level presence query.
- Add finalized direct-transfer cleanup that retains records from other accounts/chains, unfinalized nonces, and redirects whose candidate hashes have not all reached durable swap storage.
- Add swap restoration that reserves every persisted approval, redeem, refund, deposit, cancellation, and approval-history nonce without deleting concurrent trades' reservations.
- Add multi-attempt transaction status and receipt reconciliation.
- Add distinct deposited, reverted, and cancelled outcomes. 

**src/swap/ethereum/redirect_tests.rs**
- Add a reusable ETH/ERC20 seller fixture that starts from a confirmed secondary redemption, retains a signed direct-transfer recovery record, executes exactly one private-wallet redirect through the real seller state.
- Add exhaustive ETH and USDT coverage for either the original redirect or its same-nonce replacement winning with either a successful or reverted receipt while the other lookup times out.
- Add receipt-validation regressions for a pending lookup, a receipt without a mined block, a mined receipt without status, and a receipt whose transaction hash does not match the requested replacement.

**src/swap/ethereum/secret_key.rs**
- Add fixed-width private-key construction that validates the 32-byte value with Web3.

**src/swap/ethereum/types.rs**
- Add the strict, serializable `Erc20AllowanceKey` and the persisted `Erc20FundingPhase` state machine.
- Add explicit deposit retry/cancellation modes, preserved approval operation/amount metadata, finalized-approval recovery history, and the persisted funding reservation tying.
- Add strict serializable `EthTransactionRecovery` state containing the chain, sender, nonce, pinned destination/value/calldata/gas, current fee budget, signed bytes, every attempted hash, retry time, and rebroadcast status.
- Extend `EthData` encrypted persisted state with ERC20 funding/approval history; separate recovery records for approval, deposit, cancellation, refund, and redeem.
- Add regressions proving the legacy floating-point fee field is rejected, buyer offers without a redeem address fail.

**src/swap/fsm/buyer_swap.rs**
- Centralize safe MWC redemption and preparation. The new logic records observed publication, continues recovery after signature exposure regardless of elapsed wall time or a disappearing secondary lock.
- Add a non-cancellable state that suspends MWC redeem retries while a competing seller refund confirms and resumes recovery if a reorganization removes it.
- Make secondary recovery after a confirmed competing MWC refund outcome-aware.
- Add persisted Bitcoin refund-plan dispatch and completion reporting.

**src/swap/fsm/seller_swap.rs**
- Make the buyer-lock ETA chain-aware and failure-aware.
- Add integer-based Bitcoin redeem fee replacement that starts from the greater current or posted rate, applies both the proportional bump and minimum incremental relay increase.
- Use the shared chain-aware confirmation predicate and Bitcoin fee-bump helper while waiting for redemption.

**src/swap/message.rs**
- Add the strict `MarketplaceMessage` envelope, rejecting unknown fields and carrying a version, command, canonical sender and recipient OnionV3 addresses.
- Harden incoming MQS swap-message processing by parsing and verifying the sender's signature over the serialized encrypted envelope before decryption, then deriving the local public identity and rejecting envelopes addressed to another wallet.
- Add regressions proving valid signed swap messages are accepted while missing, malformed, wrong-key, reflected, tampered-destination, and correctly re-signed but wrongly addressed envelopes are rejected.
- Add hostile-deserialization and wrong-update regressions proving error text is bounded, strips control and bidirectional-override characters.
- Add marketplace-envelope regression coverage proving a valid signature verifies and that changing the offer, recipient, network, or validity time causes verification to fail.

**src/swap/mod.rs**
- Expand the simulated MWC node with chain-tip and post-accept failure injection, submission and kernel-lookup counters, bounded lookup failure, deterministic header ancestry, and current node-output details.
- Add Bitcoin-family regressions proving lock and refund confirmation derives the kernel from the actual non-compact Slate body.
- Add a regression proving seller lock-Slate construction preserves each selected input's `Coinbase` or `Plain` feature rather than flattening all commitments to plain inputs, maintaining maturity enforcement for Coinbase funds.
- Migrate the complete Bitcoin swap happy-path test to explicit cryptographic contexts, fallible transaction APIs, integer secondary-fee units, current confirmation snapshots, and semantic golden-fixture comparison.
- Add recovery tests showing a finalized buyer redeem resumes after either chain temporarily loses and then regains required lock confirmations, even after the message deadline.
- Add an Electrum-compatible failure-injection client and seller-redeem recovery suite. Rejected broadcasts, accepted transactions with lost replies, restart, fallback-node success.
- Add persistent buyer-refund fixtures and regressions for partial funding, pre-broadcast preparation, restart, lost responses, backend rejection, and fee replacement.
- Add legacy-script malleability and hostile-backend refund tests. The wallet can recover a selector-mutated but signature-equivalent confirmed parent or final payment and pin dependent children to the actual parent transaction ID, while rejecting confirmed spends whose signed fields or witness do not match; incomplete primary-node observations cannot overwrite durable state, and a reorganization to a conflicting parent is reported rather than silently invalidating a signed child.
- Add durable multi-batch Bitcoin refund-plan coverage for hundreds of economical deposits, standard input/weight limits, carry outputs, skipped dust, unconfirmed inventory, late deposits, independent batches, fee-bump eligibility, parent replacements, reorganization replay.
- Add a final seller-funding validation regression requiring the accepted input set to be both fully confirmed and equal to the negotiated amount.
- Add storage and marketplace regressions that reject the legacy floating-point fee schema, preserve the record delimiter inside user tags.
- Add Ethereum receipt and submission-recovery regressions for native ETH and ERC20 deposit, redeem, and refund operations.
- Verify each Ethereum swap API uses its own configured node for gas balance, then mirror the Bitcoin kernel-identity tests for ETH and ERC20 swaps.
- Add buyer cancellation tests for pending or ambiguously submitted Ethereum deposits. Cancellation, timeout, serialization, and restart retain deposit recovery until late-mined funds can be refunded.
- Add stale-snapshot and UX roadmap tests. The funding state waits for a fresh balance snapshot instead of looping or duplicating a newly observed deposit, timeout recovery preserves funds seen by either of two reads.
- Add shared Ethereum recovery/funding fixtures and deposit-deadline tests proving RPC validation latency and skipped or fractional 12-second slots cannot shorten the negotiated refund window.
- Add ERC20 allowance and deposit coordination coverage across concurrent swaps sharing an account.
- Add restart/archive recovery tests for ambiguous ERC20 resets, approvals, deposits, direct transfers, and deposit cancellations.
- Greatly expand the Ethereum refund-lock test for ETH and ERC20 finality and deadline safety. 

**src/swap/multisig/types.rs**
- Re-enable and modernize the previously commented-out two-party commit/reveal test.

**src/swap/owner_eth.rs**
- Add shared validation helpers that accept only Ethereum-family currencies, parse transfer amounts with each currency's own decimal exponent and checked nonzero amount rules, and reject the Ethereum zero address explicitly.
- Factor common direct-transfer client setup into `account_transfer_client`.
- Add `retry_transfer`, which locates a process-retained direct payment by any attempted transaction hash, preserves its recorded fee budget or accepts an optional replacement budget in gwei.
- Add regressions for currency-specific ETH, WBTC, USDT, USDC, and TRX amount exponents.

**src/swap/owner_swap.rs**
- Add bounded marketplace display output, the ten-minute winner lease, domain-separated message fingerprints, and strict MWCMQS identity validation.
- Add canonical resolution and pinning for the native and ERC20 swap-contract pair.
- Add import guards for processed-message receipts and complete Ethereum/Bitcoin transaction recovery. A backup cannot discard or replace acknowledged message effects, Ethereum hashes, signed nonce/allowance/deposit recovery, BTC refund plans, frozen redeem inputs, candidate hashes, or signed redemption attempts.
- Reconcile a same-UUID import against the live trade before storage. Imports now preserve seller lock exposure and redeem signing data, observed redeem kernels, buyer redeem exposure, accepted marketplace cancellations, winner leases, durable outbox identity, offer fingerprints, and Ethereum redirect hashes.
- Harden seller swap creation with an explicit cryptographic context and a wallet-context creation lock spanning reservation discovery, selection, gas validation, and storage.
- Add `SwapStatusSnapshot` for state, action, roadmap, trade, and confirmations derived from one coherent check.
- Refactor dump/import around short wallet-lock scopes and explicit cryptographic contexts.
- Add a durable marketplace-cancellation outbox API with partial scan results.
- Centralize outbound message delivery at a validated transport sink and persist sensitive pre-send state before exposure.
- Add safe seller-lock accounting and cleanup.
- Add idempotent receive-accounting creation keyed by kernel excess and replace indexing/assertion assumptions with structured validation.
- Harden the marketplace request handler with required typed fields, command/offer length limits, bounded escaped diagnostics, and short wallet-lock scope.
- Add authenticated sender provenance and replay-safe processing to incoming swaps.
- Add regression coverage for RFC 4122 v4 marketplace nonces and entropy failure, strict MQS address/sender binding and file-versus-network provenance, signing-index stability and unambiguous binding keys.
- Add tests proving failed staged checks do not mutate live swaps; mempool locks count as marketplace progress; ten-minute leases serialize concurrent replacements; late or visible funding blocks unsafe replacement.
- Add import regressions for Ethereum redirect replacement history, seller lock exposure, seller signing and observed-redeem state, buyer redeem exposure, received cancellation nonces, winner leases, legacy and current outbox identities, completion replay, and stale acknowledgements.
- Add contract-pinning regressions proving configuration changes do not alter a trade's captured contracts, different native or ERC20 contracts are rejected atomically, equivalent case/prefix spellings are accepted.

**src/swap/seller.rs**
- Replace the accepted-offer role assertion with a reported error, validate the seller's stored lock/refund participants and both peer-controlled participants before cryptographic finalization, and perform multisig and Slate finalization on a cloned trade.
- Comprehensively bind redeem initialization to the intended two-party transaction transcript. Decode failures are classified as invalid message data.

**src/swap/swap.rs**
- Add reusable swap-participant validation that enforces the declared two-party limit, exact participant count, unique expected IDs, expected partial-signature state, and valid participant messages before performing aggregate cryptography.
- Add an immutable, idempotency-keyed marketplace cancellation notification and durable incoming-message receipts that validate acknowledgement groups and recreate the corresponding acknowledgement.
- Extend persisted swap state with the marketplace winner lease, exact and content-only offer fingerprints, two durable incoming-message receipts, immutable pending-cancellation identity and nonce, bid-signing derivation index, and last accepted cancellation nonce.
- Add helpers that invalidate a cached offer when its locally selected transport changes; replay an exact already-processed message with its persisted acknowledgement while rejecting a conflicting payload in the same protocol group.
- Preflight complete lock and refund Slates in one request. Require the refund to spend exactly the negotiated plain multisig output from the lock transaction, and allow its future lock height while still requiring every node check to pass.
- Add explicit predicates for a buyer's potentially exposed MWC redeem signature and for states whose secondary-chain recovery no longer depends on a fresh MWC observation.
- Stop replacing Ethereum's zero-address sentinel with a human-readable label when updating persisted secondary addresses.
- Comprehensively validate a redeem Slate before deriving an adaptor-signature challenge.
- Make every derived swap deadline and confirmation interval fallible, converting unsigned durations explicitly and using checked addition, subtraction, and multiplication.
- Add outbound-transport resolution and regressions covering transport changes, peer-supplied file paths, owner-authorized file output, legacy seller compatibility, and inconsistent persisted transport data.
- Add regressions proving participant validation is ID-based but rejects duplicate, oversized, or rebound records.

**src/swap/trades.rs**
- Add Ethereum resource restoration before transaction submission.
- Harden active-record loading with canonical path resolution, fallible existence checks, and verification that the decrypted swap ID matches the requested filename.
- Harden persistence by validating the swap version and security-sensitive invariants before writing.
- Add regressions for encrypted-record round trips and rejection of short or long nonces, rejection of legacy delimiter framing, canonical UUID normalization and path-component rejection.

**src/swap/types.rs**
- Add the canonical secondary-fee pipeline. Decimal API/CLI input is normalized into the unit required by its currency, zero and mismatched persisted units are rejected.
- Harden decimal parsing. Fractional currency amounts now reject excess precision, non-ASCII digits, trailing junk, and multibyte input.
- Replace seller lock inputs' three-item tuples with `SellerInput`, which persists the consensus-relevant `OutputFeatures` alongside key ID, PMMR index, and amount.
- Add `SecondaryTransferStatus` to distinguish an unposted Ethereum private-wallet redirect from a pending, confirmed, or failed recorded transaction.
- Add regressions for byte-compatible context serialization and short-write propagation, seller-input feature preservation and legacy decoding, minimum/missing confirmation handling.

**src/transaction_preflight.rs**
- Add a non-clonable, single-use `PreflightReceipt` bound to the exact transaction and selected node connection.
- Centralize local cryptographic validation and unsigned `testmempoolaccept` checks. Send transaction metadata without rangeproofs or signatures, require consistent results for every requested transaction and its complete/partial scope.

**src/types.rs**
- Add `NodeConnectionId` with a selection generation, typed `NodeOutputDetails`, a request-safe client clone hook, fresh tip/header reads, and hash-linked header lookup for anchored chain operations.
- Add one-time aggregate-signature challenge binding. Reusing the same challenge is idempotent and can upgrade a matching legacy record.
- Add authoritative deferred-input validation of status, amount, stored commitment, and optional idempotent same-log lock ownership, plus a whole-session helper.
- Add UTF-8-boundary-safe truncation and bounded display escaping for peer-controlled text.
- Add regressions for independently optional stored-transaction locators and for migrating a legacy late-lock context.
- Add regressions that confirmed-balance summation reports overflow with both operands, oversized staged transaction logs fail before persistence.
- Add reservation regressions proving dead transaction owners are pruned, live commitments remain unavailable, two live sessions cannot claim the same input, unrelated inputs remain usable after a conflict.
- Add within-batch receive regressions that reject a duplicate received Slate UUID across accounts, allow a cross-account self-send with the same UUID and offset, and reject duplicate offsets in the same account.
- Add display-safety regressions for newline/ANSI/OSC and C1 controls, bidi overrides and isolates, Unicode line separators, JSON round trips, and bounded UTF-8 truncation.

### mwc_wallet_lib

**src/callback_node_client.rs**
- Add context-aware decoders for output vectors, PMMR output listings, and block responses.
- Implement hash-linked header lookup for anchored chain operations.
- Add regressions proving by-hash header lookup returns the parent only for the requested hash, exact kernel absence is distinguished from a method error.
- Add a concurrency regression proving dispatch holds the callback-registry read lock until the callback response has been copied, then confirms that dispatch after unregister returns a clear error.

**src/mwc_wallet_calls.rs**
- Add a regression test proving library Tor operations retain initialized bridge and `tor_enabled` settings for both enabled and disabled configurations.
- Add synchronized callback fixtures plus regressions proving invalid scan contexts return an error without entering the interruption registry, an unregistered receive callback is not invoked through a cached closure, and callback dispatch holds the registry lock until the caller-owned context is no longer in use.

**src/receive.rs**
- Retain the decoded Slatepack recipient and validate the sender/recipient direction against this wallet's verifying key before processing the Slate.
- Save the deferred transaction only after encrypted response construction succeeds, then complete the authenticated reply-cache reservation and dispatch the receive callback.

**src/scan.rs**
- Replace the background channel and callback thread with helpers that serialize the existing `response_id`/`status` JSON shape, re-resolve the currently registered callback for every message, and invoke it synchronously.
- Add regressions that verify synchronous status encoding retains the legacy JSON schema and response ID, and that a registry-backed C callback has already run when dispatch returns.

### util

**Cargo.toml**
- exclude zcash primitives because of security issues. That is why swaps are not supporting zcash now. 

**src/file.rs**
- Add `remove_file_and_sync_parent`, which removes a file and then synchronizes its containing directory on Unix.
- Add `remove_dir_all_and_sync_parent`, applying the same error propagation and Unix parent-directory synchronization to recursive directory removal so deleted wallet trees are made durable rather than relying only on an in-memory directory update.
- Add `replace_owner_only_file_with`, which streams replacement contents into a temporary file in the destination directory, sets Unix permissions to owner-only `0600` before exposing the file to the caller, synchronizes the completed file.
- Add platform-specific parent synchronization and path normalization helpers.
- Add tests proving that both durable-removal helpers delete their file or directory-tree targets successfully before returning from parent synchronization.
- Add a failure-injection regression test proving that an error after a partial temporary-file write is propagated, the original destination contents remain unchanged, and the temporary file is cleaned up rather than leaving sensitive partial data behind.

**src/sensitive.rs**
- Add `JsonSizeCounter`, a non-retaining `Write` implementation that counts the first serialization pass with checked arithmetic. It reports an invalid-data error if the byte count overflows and otherwise consumes each write without storing sensitive plaintext.
- Add `serialize_json`, which first counts the JSON output, then serializes it into one exactly sized boxed slice owned by `Zeroizing`.
- Add an adversarial `GrowingSerialization` test fixture whose second serialization pass emits a longer string, modeling a stateful serializer that violates the fixed-size assumption.
- Add a regression proving second-pass growth is rejected instead of reallocating the sensitive output buffer, preserving the single-zeroizing-allocation security guarantee for inconsistent serializers.

### wallet_workflow

**src/wallet.rs**
- Reorder release so the foreign/Owner HTTP API is stopped and joined before resetting and joining MQS, retain the MQS result for later return, and clear transaction proofs only after both listener paths have drained.
- Clear the remaining caller-owned wallet, swap, scan, Tor, health, and scan-interrupt context state only after the context-owned listeners have terminated.
