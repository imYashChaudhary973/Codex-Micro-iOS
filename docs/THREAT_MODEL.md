# Codex Micro — Local Pairing and Networking Threat Model

**Status:** Accepted — direct-LAN Phase 2 baseline

**Date:** 2026-08-02

**Scope:** Direct same-LAN pairing and authenticated companion sessions only. Tailnet, proxy-terminated TLS, public networking, relay, and APNs are later phases.

## 1. Security objective and claim

Phase 2 introduces the first untrusted network boundary in Codex Micro. Its primary security claim is:

> An untrusted LAN peer receives no application metadata before authentication. An authenticated device receives and can mutate only data authorized by the Mac's current persisted grant. Network code cannot bypass the centralized command gateway, and authorization or storage failure never broadens access.

The Mac remains authoritative for repositories, Codex/provider credentials, Codex configuration, projects, tools, sandbox and approval policy, device grants, revocation, event filtering, command idempotency, and all execution.

This threat model does not claim protection after compromise of the macOS kernel/root account, the signed-in Mac user account, the trusted Codex executable, or the iOS kernel. It also does not hide listener presence, IP addresses, packet timing, packet sizes, or service availability from the local network.

## 2. System and data flow

```text
Mac user
  │ LAN enablement, pairing/SAS confirmation, grants, revocation
  ▼
CodexMicroBridge (menu-bar app)
  │
  ├── MacBridgeServer
  │     TLS/WSS listener, connection/session actors, limits, Bonjour
  │
  ├── CompanionCrypto
  │     canonical transcripts, signatures, ECDH/HKDF/AEAD, state machines
  │
  └── MacBridgeCore
        authoritative grants → filtered snapshots/replay
        command gateway → durable ledger → Codex executor
                                      │
                                      ▼
                              codex app-server

Signed iOS acceptance host / future iPhone app
  Secure Enclave/Keychain identity
  │
  └──────────── untrusted same-LAN network ────────────┘
```

### 2.1 LAN startup

1. The Mac user explicitly enables LAN access.
2. The bridge loads and validates host/TLS identity, grant authority, network/resource policy, and supported Codex compatibility.
3. The listener binds only to eligible direct-LAN interfaces.
4. Bonjour publishes only after listener startup succeeds.
5. Any advertisement failure rolls back the listener.

### 2.2 Pairing

1. The Mac creates a memory-only pairing session and exactly 256-bit CSPRNG bootstrap secret with a five-minute lifetime.
2. The Mac presents a QR containing the normalized direct-LAN endpoint, pairing session ID, secret, exact protocol/features, host identity fingerprint, and current TLS SPKI fingerprint.
3. The device connects over pinned TLS.
4. The bridge compares the secret in constant time and atomically claims it before signature processing. A completed claim consumes it regardless of outcome.
5. Both endpoints sign a versioned, length-delimited canonical transcript.
6. Each endpoint independently derives and displays the same six-word, 66-bit transcript-bound SAS.
7. Both users confirm locally. Peer-supplied confirmation is never a substitute.
8. The Mac persists an explicit grant; default capability is `observe` with an empty project allowlist.

### 2.3 Normal authentication

1. TLS validates the current pin or a valid host-identity-signed rotation statement.
2. Both endpoints generate fresh ephemeral P-256 ECDH keys and nonces.
3. Both long-term identities sign the exact session transcript.
4. The Mac loads the current persisted device grant/revision, authorized-view epoch, and host generation.
5. Both endpoints derive separate client-to-server and server-to-client application keys.
6. The bridge registers one active authenticated session for the device and closes the previous one.
7. Every post-handshake payload is independently AEAD-sealed with an authenticated header and exactly-next directional counter.

### 2.4 Observe and replay

1. `MacBridgeCore` filters state against the current device grant before enqueue.
2. It assigns sequence values only within that device's authorized-view namespace.
3. The sealed cursor envelope is `(deviceID, grantRevision, authorizedViewEpoch, journalEpoch, sequence)`.
4. `MacBridgeServer` publishes only the already-authorized batches returned by the core; it never receives an unfiltered journal.
5. Current cursors replay retained authorized events. Older revision/view, foreign epoch, or retention-stale cursors receive a filtered snapshot. Device mismatch, ahead sequence, rollback, overflow, or malformed values fail closed.

### 2.5 Semantic mutation

1. The connection actor authenticates and decrypts the frame.
2. The gateway checks current session, Mac-stored grant/revision, revocation, strict schema, and stable `(deviceID, commandID)` identity.
3. A matching terminal ledger result may be returned after current disclosure authorization, even if the original freshness window elapsed or Codex is currently degraded.
4. A new command passes freshness, project scope, capability, mobile profile, runtime readiness, and ledger availability checks.
5. The gateway commits the durable claim before one external call.
6. A crash-ambiguous claim becomes `outcomeUnknown` and is never automatically resent.

Phase 2 P0 enables only `markThreadRead` and `interruptTurn`. It rejects approvals, attachments, agent-running commands, unknown commands, raw Codex RPC, shell, filesystem, and arbitrary MCP operations.

### 2.6 Revocation, reduction, expiry, and restart

- Authority changes are linearizable: persist the new revision/tombstone, publish it to all checks, stop new work under the old revision, purge unauthorized queued output and undisclosed results, advance the authorized-view epoch when scope changes, then close or reauthenticate all affected connections.
- Runtime degradation never queues a mutation.
- Bridge restart creates a fresh journal epoch, marks ambiguous ledger work unknown, reruns the Codex compatibility gate, and rebuilds domain state from authoritative reads without replaying commands.

## 3. Assets and generated-secret inventory

### 3.1 Protected assets

- Mac execution authority: repositories, tools, Codex/provider credentials, configuration, sandbox and approval policy.
- Device grants: public keys, capabilities, project allowlists, profiles, revisions, expiries, revocation tombstones, authorized-view epochs, and host generation.
- Companion state: filtered snapshots/events, prompts/results, approval metadata, opaque identifiers, replay cursors, acknowledgements, and queued output.
- Durable command-ledger integrity, confidentiality, and idempotency history.
- User intent: LAN enablement, QR presentation, SAS confirmation, grant edits, and revocation.
- Availability of grant authority, ledger, runtime, listener, and discovery.
- Application logs, system-library logs, diagnostics, Bonjour fields, and TLS certificate fields.

### 3.2 Existing generated material

| Material | Classification and lifecycle |
|---|---|
| Ledger database key | 256-bit CSPRNG key from `SecRandomCopyBytes`; Keychain service `com.codexmicro.command-ledger`, account `database-key-v1`, `AfterFirstUnlockThisDeviceOnly`. Generated secret, device-only, never backed up or logged. Missing/corrupt key with an existing database denies mutation; it never resets ledger history silently. Rotation/reset remains an explicit future design. |
| AES-GCM nonce and tag | CryptoKit-generated per record save; nonce is not secret but must be unique per key. Combined ciphertext stores nonce/tag. Command ID is associated data. |
| Ledger index metadata | Command ID and update timestamp remain plaintext SQLite index metadata. Privacy-relevant but not authentication secrets; retention and diagnostics must acknowledge them. |

### 3.3 Phase 2 app-managed material

| Material | Classification and lifecycle |
|---|---|
| Mac host-signing private key | **Secure Enclave required** ([ADR §6](PHASE_2_TRANSPORT_ADR.md)): P-256 `kSecAttrTokenIDSecureEnclave` key with `privateKeyUsage`-only access control, `AfterFirstUnlockThisDeviceOnly`, Data Protection Keychain, ThisDeviceOnly — never synced or backed up. Software Data Protection Keychain keys are rejected: the spike proved them exportable by the creating process. Macs without a Secure Enclave fail closed. Persistent; no silent rotation; loss while grants exist disables LAN and requires explicit reset/re-pairing. Normal reconnect never prompts for biometrics. |
| Host ID | Random non-secret identifier stored with the host identity. Possession never authenticates. Not logged or published in Bonjour. |
| TLS private key and certificate | Separate Secure Enclave P-256 key with the same attribute profile (ADR §6). Certificate fields/serial are public and content-neutral (ADR §7): 30-day validity, same-key renewal at two-thirds lifetime, SPKI pinned by clients. Key rotation requires a host-signed, generation-monotonic anti-rollback statement delivered over an authenticated session before activation (ADR §7). |
| Grant-store encryption key | **Not applicable** — decided in ADR §10: authority records live as a single versioned bounded canonical blob directly in the device-only Data Protection Keychain behind one actor, with atomic whole-blob replacement. No file-backed store and no separate encryption key exist. Missing/duplicate/undecodable/rolled-back blob disables LAN. |
| iPhone device-signing key | **Secure Enclave required** (ADR §6), with the same attribute profile: `privateKeyUsage`-only access control, `AfterFirstUnlockThisDeviceOnly`, ThisDeviceOnly, no backup/sync, no biometric prompt for normal reconnect. No Keychain software fallback — devices without a Secure Enclave fail closed. Reinstall creates a new identity and requires re-pairing. Provisional until Step 2.14 proves the lifecycle on a physical signed iPhone. |
| Device ID | Random non-secret identifier. Never accepted as proof of identity. |
| Pairing bootstrap secret | Exactly 256 CSPRNG bits, memory-only, five-minute lifetime, single-use, constant-time comparison, atomically claimed and consumed regardless of pairing outcome. Present only in the QR and first pairing request. |
| Pairing session ID | Random non-secret lookup identifier; not a credential. |
| Pairing client/server nonces | Exactly 256 random bits each (ADR §11), attempt-local, transcript-bound, destroyed after completion. |
| SAS phrase | Derived, not stored, and not a credential. Exactly six words from 66 uniformly derived bits and a fixed versioned 2,048-word list. Never persisted or logged. |
| Journal epoch | Fresh 128-bit random value on each bridge-process start. Non-secret, mandatory in every replay cursor. |
| Grant/view/host/rotation generations | Persistent unsigned 64-bit anti-rollback counters. Non-secret. Overflow disables the affected authority instead of wrapping. |

### 3.4 Session and stack-managed material

- Fresh application P-256 ephemeral private keys and ECDH shared secret.
- Pairing/session transcript hashes and exact HKDF labels.
- Separate 256-bit client-to-server and server-to-client application-frame keys.
- Connection/session IDs; non-secret and non-bearer.
- Exactly-next directional counters and the deterministic 96-bit AEAD nonce encoding (4-byte direction prefix plus 8-byte big-endian counter, ADR §11) under fresh directional keys.
- Network.framework-managed TLS handshake ephemeral secrets and IVs. TLS 1.3 only with the single `AES_128_GCM_SHA256` suite; tickets, resumption, 0-RTT, False Start, fallback, fast-open, peer-to-peer, and multipath are disabled and proven so (ADR §5). No stack-managed ticket/PSK state exists to inventory.
- WebSocket client masking keys.

TLS resumption is **disabled and proven disabled** (ADR §5); the previously conditional ticket/PSK inventory is closed as not applicable.

## 4. Actors and attacker capabilities

### Authorized actors

- Mac owner enabling LAN access, confirming pairing/SAS, editing grants, and revoking devices.
- Authorized paired-device user operating within the current Mac grant.

### Adversaries and faults

- Unpaired LAN peer able to discover, connect, send arbitrary bytes, flood, delay, replay, fragment, spoof Bonjour, and attempt active MITM.
- Attacker who photographs, screen-captures, or remotely obtains a pairing QR during its validity window.
- Compromised paired phone able to use its legitimate key and every granted capability, mutate protocol messages, reuse IDs, and attempt cross-project access.
- Thief with a locked or unlocked phone or Mac.
- Malicious repository/model/Codex content controlling text, identifiers, errors, terminal sequences, and approval descriptions.
- Storage corruption, Keychain lock/unavailability, partial writes, process crash, power loss, clock changes, and interface changes as fault adversaries.

### Cryptographic assumptions

Standard P-256, ECDH, ECDSA, HKDF-SHA256, ChaCha20-Poly1305, AES-GCM, SHA-256, Keychain, Secure Enclave, TLS, and trusted Apple cryptographic implementations are assumed not cryptographically broken.

## 5. Trust boundaries

1. Mac user action → LAN enablement, pairing confirmation, and grant administration.
2. iOS app/Secure Enclave → untrusted LAN.
3. Unauthenticated TCP/TLS/WSS peer → pairing or session state machine.
4. Authenticated session → current Mac grant authority.
5. `MacBridgeServer` → `MacBridgeCore` filtered-data and command-gateway APIs.
6. Command gateway → durable ledger → typed Codex executor.
7. Grant/ledger stores → Keychain-held keys and local files.
8. Codex app-server/repository/model content → normalized domain state, phone renderer, and logs.
9. Application diagnostics → unified logging and system-library logging.

## 6. Threats and required controls

| Threat | Required control |
|---|---|
| Authorization/executor bypass | Network receives authenticated session context, never caller-asserted identity. All mutations pass one gateway. Executors are inaccessible to `MacBridgeServer`. |
| Identity/grant rollback or silent reset | Never regenerate host identity while grants exist. Missing/corrupt/wrong-key/duplicate/rollback/overflow authority state disables LAN. |
| Pairing MITM or QR reuse | Pinned TLS, exact 256-bit secret, atomic claim/consume, transcript signatures, six-word/66-bit SAS, dual local confirmation, exact endpoint/mode/version binding. |
| Duplicate/crash executes a second action | Device-bound command identity, semantic digest, durable claim before external call, current authorization before result disclosure, `outcomeUnknown` without automatic resend. |
| Revocation/scope-change race | Linearizable persist/publish/purge/close sequence, active-expiry timer, concurrent enqueue/command regression tests. |
| Cross-project disclosure or cursor side channel | Per-device project-filtered snapshots/replay and authorized-view sequence namespace; scope change advances view epoch and forces filtered snapshot. |
| TLS-key extraction or unsafe rotation | Stack selected and proven (ADR §4/§6): NIOTS over Network.framework TLS with a Secure Enclave `SecIdentity`; export denial asserted at every retrieval. Same-key certificate renewal; host-signed anti-rollback SPKI rotation delivered before activation (ADR §7). |
| Downgrade/parser confusion/cross-connection replay | Strict unknown-field/type rejection, exact features, fresh ECDH per connection, directional keys, exactly-next counters, close on any violation. |
| Unauthenticated resource exhaustion | Eligible-interface policy, connection/per-source caps, handshake deadlines, pairing rate limits, exact HTTP/WSS route/subprotocol rules, bounded headers/frames/fragments/queues, no compression. |
| Logs/system frameworks leak content | Closed application log vocabulary, no raw errors/URLs/bytes/IDs, system-library logging inventory, no diagnostic bundle inclusion by default. |
| Stolen or compromised phone | Secure Enclave/Keychain, passcode requirement, narrow grants, empty project scope, one active session, expiry, immediate revocation, no phone approvals. |
| Discovery/traffic analysis | Content-neutral certificate and exact Bonjour allowlist. Accept residual visibility of service presence, IP, timing, and ciphertext size. |

## 7. Fail-closed startup and runtime matrix

| Condition | Listener and Bonjour | Authenticated behavior |
|---|---|---|
| Fresh install or LAN toggle disabled | Both off | Local bridge may run; no network access |
| First enable with valid empty grant authority | Listener starts only after identities, policy, limits, direct-LAN configuration, and supported Codex checks; pairing-only surface | No observation or commands before pairing/grant completion |
| Host identity missing while grants exist | Both off; never generate replacement | Explicit reset and re-pairing required |
| TLS identity/certificate/rotation invalid | Both off unless same-key certificate renewal succeeds | Invalid rotation rejected; never silently repin |
| Grant authority missing, locked, corrupt, wrong-key, rolled back, duplicated, or overflowed | Remove advertisement, stop listener, close sessions | Deny pairing completion, authentication, observation, and commands |
| Network/interface or resource policy invalid | Both off | No wildcard/degraded-interface fallback |
| Unsupported or unavailable Codex during initial enable | Both off | No network mode |
| Ledger unavailable during initial enable | Both off until a mechanically separate observation-only startup mode is implemented and tested | Never allow mutation |
| Ledger fails after successful startup | Observation may remain only through a separate read-only mode | Deny every new mutation; never queue; disclose known result only if readable and currently authorized |
| Codex runtime degrades after successful startup | Listener may remain for safe observation/degraded state | Deny and never queue new mutation |
| Entropy or journal-epoch generation fails | Do not start new network sessions/replay namespace | No new pairing/authentication |
| Pairing-secret generation fails | Existing authenticated sessions may remain | Pairing disabled; display no partial QR |
| Bonjour publication fails after listener starts | Roll back and stop listener | No undiscoverable user-enabled listener |
| User disables LAN | Remove Bonjour first; close listener and sessions | No reconnect |
| Logger/sink fails | Never switch to raw logging | Safely drop closed events; logging failure grants nothing |

## 8. Privacy, logging, and diagnostics

- Application-generated logs contain closed reason codes and numeric counts only.
- Never log URLs, IPs, host/device names, IDs, fingerprints, certificate fields, QR contents, secrets, frame headers/bytes/counters, prompts, paths, commands, diffs, approval details, request digests, or RPC error strings.
- Pre-auth problems are collapsed so they do not reveal whether a device, grant, project, or session exists.
- Bonjour and certificate subjects use exact content-neutral allowlists.
- Diagnostic bundles exclude raw unified logs, packet captures, SQLite files, Keychain metadata, and process stderr by default.
- Inventory Network.framework/URLSession/TLS/SecTrust/Bonjour/Security/WebSocket logging and local-network errors before listener merge.
- Existing raw Codex process stderr is outside `RedactedLogger`; it must be isolated from exported diagnostics and resolved before claiming all bridge output is redacted.
- Terminal ledger retention purge must be scheduled by the app lifecycle; a test-only API is insufficient.

## 9. Residual risks and non-goals

### Non-goals

- Tailnet/proxy/public listener, relay, accounts, APNs, or internet discovery.
- Phone approval resolution or any phone boolean as user-presence proof.
- Attachments/downloads/screenshots/audio/file transfer/offline content cache.
- Raw Codex RPC, shell, process, filesystem, configuration, or arbitrary MCP access.
- Polished iOS UI or always-connected background operation.
- Multi-user/team authorization.
- Perfect exactly-once execution across arbitrary crash boundaries.
- Identity backup/migration or transparent recovery after identity loss.
- Protection from compromised kernel/root/signed-in user/trusted Codex binary.
- Hiding service/IP/timing/size metadata from the LAN.

### Residual risks

- A compromised paired phone can exercise all capabilities and read all projects currently granted.
- Secure Enclave prevents ordinary key extraction but cannot make an authorized compromised device harmless.
- Users can confirm a mismatched SAS or expose a QR through screen sharing/photography.
- Revocation cannot retract content already displayed or captured.
- Swift/system frameworks provide limited guarantees about immediate memory zeroization.
- OS/framework vulnerabilities and denial-of-service remain possible.
- Crash ambiguity remains `outcomeUnknown` and requires Mac-side review.
- `AfterFirstUnlockThisDeviceOnly` allows ledger-key use after first unlock; this is an explicit at-rest availability/security trade-off.

## 10. Existing evidence, gaps, and validation requirements

### Evidence carried forward

- Strict command type/field rejection in `Sources/CompanionProtocol/ClientCommand.swift`.
- Encrypted ledger, wrong-key rejection, `outcomeUnknown` recovery, and content-leak checks in `Tests/MacBridgeCoreTests/ApprovalAndPersistentLedgerTests.swift`.
- Closed logger vocabulary and sentinel injection in `Tests/MacBridgeCoreTests/RedactedLoggingTests.swift`.
- Idempotent approval execution with no automatic resend in `Sources/MacBridgeCore/ApprovalResolutionExecutor.swift`.
- Compatibility-gated recovery without command replay in `Sources/MacBridgeCore/CodexRuntimeRecovery.swift`.

These are baseline core controls, not LAN/TLS/pairing/authentication/revocation evidence.

### Current gaps

- No **production** listener, WSS/TLS stack, Bonjour, pairing/session state machine, host/device identity store, or persisted device-grant authority exists. The merged transport spike (`a445f81`/`531d972`/`c6577b7`) is isolated feasibility evidence, imports no production target, and is not production code.
- `CapabilityPolicy` has no production network command-gateway call site.
- Current snapshots and journal sequences are global and unsafe for direct per-device exposure.
- Protocol compatibility accepts any matching major; generic envelopes/snapshots are not strict unknown-field decoders.
- Recovery ignores `markInFlightOutcomesUnknown` persistence failure via `try?`; Phase 2 mutation must not continue after this failure.
- Raw app-server stderr bypasses `RedactedLogger`.
- Ledger lookup is command-ID keyed with a device consistency check; the Phase 2 contract requires explicit `(deviceID, commandID)` authority and current authorization before result disclosure.

### Required evidence

- Independent crypto golden vectors and every-field mutation tests.
- Selected transport stack proving non-exportable host/TLS key lifecycle — **provided** for the Mac by the merged spike (signed-Mac Secure Enclave create/retrieve/export-denied/mismatch/cleanup proof, ADR §6); the production adapters in Step 2.4a must reproduce it, and the iPhone half remains outstanding until Step 2.14.
- Keychain lock/missing/corrupt/reinstall/rollback/identity-loss tests.
- Concurrent pairing claim/expiry/cancellation/SAS tests.
- TLS/WSS loopback tests for zero pre-auth application metadata and resource bounds.
- Per-device project filtering and unauthorized-sequence side-channel tests.
- Concurrent enqueue/command versus revocation/reduction/expiry tests.
- Command crash-boundary and storage-failure tests proving one external call maximum.
- Logging sentinels through QR/certificate/endpoint/upgrade/TLS/frame/grant/revocation/system-error paths.
- Signed physical-iPhone evidence against the exact candidate SHA.

## 11. Stop conditions

### Before Step 2.2 — all resolved

Every Step 2.1 stop condition is resolved by [the accepted transport ADR](PHASE_2_TRANSPORT_ADR.md):

- [x] TLS stack and non-exportable-key support — ADR §4, proof in §6.
- [x] TLS version, 0-RTT, resumption, certificate, and rotation policy — ADR §5, §7.
- [x] Keychain accessibility, loss, reset, and backup semantics for long-term keys — ADR §6.
- [x] Grant-authority format and encryption-key lifecycle — ADR §10 (Keychain-resident blob; no separate key).
- [x] Direct-LAN interface eligibility and path changes — ADR §8.
- [x] Canonical transcript and pairing claim/consume ordering — ADR §11 with the claim/consume ordering in §2.2 above.
- [x] HTTP/WebSocket route, subprotocol, origin, compression, header, frame, connection, and deadline rules — ADR §9.
- [x] Complete secret/identifier inventory including stack-generated TLS material — §3 above with ADR §5/§6/§13.

### Before any listener merge

Block merge if:

- Security/control decoding is permissive or negotiation remains major-only.
- Host identity can regenerate while grants exist.
- Global snapshots/sequences or unfiltered journal data are network reachable.
- Network code can access an executor outside the command gateway.
- Approval, attachments, raw RPC, paths, shell, filesystem, or MCP operations are reachable.
- Grant-authority failure leaves sessions active or permits authentication.
- Ledger/runtime failure permits or queues a new mutation.
- Revocation is not linearizable with enqueue and external calls.
- Bonjour can remain advertised after listener failure or publishes identifying content.
- Raw content can reach application-generated logs or configured system-library logs.

### Before Phase 2 acceptance

Do not accept or tag Phase 2 without a signed physical iPhone passing the full matrix on the exact tested `main` SHA. Physical behavior overrides simulator, source-only, generic-device, and loopback evidence.

## References

- [Phase 2 transport/TLS ADR](PHASE_2_TRANSPORT_ADR.md)
- [Product status](STATUS.md)
- [Phase 2 plan (archive)](archive/PHASE_2_PLAN.md)
- [System architecture (archive)](archive/IOS_COMPANION_ARCHITECTURE.md)
