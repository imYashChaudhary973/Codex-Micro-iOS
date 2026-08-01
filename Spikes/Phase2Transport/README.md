# Phase 2 Transport Feasibility Spike — Stages 1–2: Identity and Transport

Isolated, test-only Swift package. It imports no production Codex Micro target and exposes no pairing, grant, session, command, approval, Codex, or user-data path. The listener is one-shot, created only by test/probe code, and cannot restart after stop or partial startup failure.

Stacked evidence PRs:

1. **Merged** — non-exportable Secure Enclave identity, content-neutral certificates, same-key renewal SPKI continuity, and canonical host-signed rotation statements.
2. **This PR** — interface policy plus the hardened NIOTS TLS 1.3 WebSocket listener and pinned client.
3. Signed probe app, provisioning scripts, Keychain/Bonjour/LAN runs, and the full sanitized evidence report (`EVIDENCE.md`).

## Stage 2 findings: interface containment

- `InterfaceBinding` has no public arbitrary initializer. Production bindings come from discovery; loopback has one explicit test-only factory.
- Binding creation and server startup independently require an active allowed interface and revalidate a numeric address.
- Hostnames, wildcard/unspecified, public, multicast, IPv4/IPv6 link-local, and disallowed loopback addresses are rejected.
- Only private IPv4 or IPv6 ULA addresses on Wi-Fi/Ethernet are eligible outside tests.
- NIOTS binds a pre-parsed `SocketAddress`, verifies the bound local address matches, requires the corresponding Network.framework interface type, and has no DNS or wildcard fallback.

## Stage 2 findings: TLS and WebSocket

- Network.framework TLS is fixed to TLS 1.3 and the public `AES_128_GCM_SHA256` cipher suite.
- Tickets, resumption, False Start, fallback mode, and TCP/Network.framework Fast Open are disabled. Peer-to-peer and multipath are disabled.
- HTTP limits are 16 fields, 8 KiB total, and 4 KiB per field.
- Upgrade requires HTTP/1.1 `GET`, exact path without query, single required headers, exact Origin/subprotocol, WebSocket version 13, a valid key, and a header-name allowlist.
- `URLSessionWebSocketTask` offers `permessage-deflate` without a public suppression switch. The server permits only that exact offer, omits it from the response, and rejects RSV bits; compression is not negotiated.
- The decoder frame cap is 16 KiB. The binary-message cap is 64 KiB and eight fragments. Tests cover unexpected continuation, new messages during fragmentation, tiny fragments, fragment-count and aggregate-size overflow, reserved bits on fragments, and control-frame interleaving.
- The pinned client records and surfaces an exact `.pinMismatch` result instead of relying on a generic URLSession error.
- The observed loopback pin closure is feasibility evidence only; whether this exact trust-override design is acceptable for production remains an ADR/security-review decision.

## Stage 2 findings: transport lifecycle

- `NIOTSTLSWebSocketServer` is an actor backed by an explicit `idle → starting → running → publishing → stopping → terminated` one-shot state machine.
- Concurrent start, start/stop, duplicate stop, invalid-bind, publication/stop, late-child, and nonrestart transitions fail closed or join teardown.
- Cleanup attempts publication removal, every tracked child close, server close, and event-loop-group shutdown even if an earlier step fails. Sanitized snapshots expose only phase, child count, publication state, and group-shutdown state.
- The child registry rejects and closes children arriving after stopping starts.
- Bonjour registration uses a cancellable timeout; success cancels the timer, losing callbacks cannot mutate the service, and remove-after-success triggers server termination. Positive signed Bonjour/LAN evidence lands with stage 3.
- `ListenerLifecycleState` fails closed before `UInt64` generation overflow and never wraps. It is a standalone authentication-generation model, not yet integrated with the server.
- Application log APIs accept only a closed `SpikeLogCode` and nonnegative integer count; no free-form error, endpoint, name, path, certificate, fingerprint, frame, or payload can be passed.

## Key findings in this stage

- **Software Data Protection Keychain keys are exportable.** `kSecAttrIsSensitive`/`kSecAttrIsExtractable: false` do not stop `SecKeyCopyExternalRepresentation` for a software key held by the creating process. The non-exportable Mac identity therefore requires a **Secure Enclave** P-256 key (`kSecAttrTokenIDSecureEnclave`, `privateKeyUsage` access control, `AfterFirstUnlockThisDeviceOnly`, Data Protection Keychain). Macs without a Secure Enclave fail closed.
- `swift-certificates` signs content-neutral self-signed certificates directly through the non-exportable `SecKey`; `SecCertificate`/`SecIdentity` construction and SPKI equality checks pass.
- Same-key renewal preserves the SPKI; a new key changes it.
- Rotation statements are canonically encoded, role-separated (`.host` signs, `.tls` serves), bound to the expected current SPKI and the presented next SPKI, and covered by a fixed 97-byte canonical fixture with mutation, wrong-role, wrong-pin, rollback, expiry, and signature-tamper tests.
- Creation uses an atomic claim; post-create validation rolls back on failure; cleanup verifies absence and aggregates errors.

The persistent Data Protection Keychain test is explicitly skipped in an unsigned SwiftPM host (`errSecMissingEntitlement`). The positive signed proof runs with the stage-3 probe app.

## Verification

```sh
swift package resolve --package-path Spikes/Phase2Transport
swift build --package-path Spikes/Phase2Transport
swift test --package-path Spikes/Phase2Transport
swift build --package-path Spikes/Phase2Transport -c release
swift format lint --strict --recursive \
  Spikes/Phase2Transport/Sources \
  Spikes/Phase2Transport/Tests \
  Spikes/Phase2Transport/Package.swift
```

Pinned dependencies: `apple/swift-nio` 2.101.3, `apple/swift-nio-transport-services` 1.28.0, and `apple/swift-certificates` 1.19.4 (transitives: `swift-atomics` 1.3.1, `swift-collections` 1.6.0, `swift-system` 1.7.5, `swift-crypto` 4.5.1, `swift-asn1` 1.7.1). No NIOSSL. Never commit keys, certificates, Keychain exports, raw logs, addresses, or identity material.
