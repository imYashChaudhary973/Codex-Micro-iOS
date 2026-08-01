# Phase 2 Transport Feasibility Spike

Delivered as three stacked evidence PRs: identity/certificates (#8), hardened NIOTS TLS/WSS transport (#9), and this final stage with the signed probe app, provisioning scripts, Keychain/Bonjour/LAN runs, and the sanitized evidence report (`EVIDENCE.md`).

This is an isolated, test-only Swift package. It imports no production Codex Micro target and exposes no pairing, grant, session, command, approval, Codex, or user-data path.

The listener is one-shot and explicit. It is created only by a test/probe command and cannot restart after stop or partial startup failure.

## Verified toolchain and pins

```text
Swift driver: 1.168.5
Swift: 6.4 (swiftlang-6.4.0.27.1, clang-2100.3.27.1)
Target: arm64-apple-macosx27.0.0
Xcode: 27.0 (27A5228h)
macOS: 27.0 (26A5388g)
Package deployment target: macOS 14+
```

Direct pins:

- `apple/swift-nio` 2.101.3
- `apple/swift-nio-transport-services` 1.28.0
- `apple/swift-certificates` 1.19.4

Authorized transitive pins in `Package.resolved`:

- `apple/swift-atomics` 1.3.1
- `apple/swift-collections` 1.6.0
- `apple/swift-system` 1.7.5
- `apple/swift-crypto` 4.5.1
- `apple/swift-asn1` 1.7.1

No other repository is declared or resolved by the nested package.

## Implemented findings

### Keychain identities

- Private keys are **Secure Enclave** P-256 keys (`kSecAttrTokenIDSecureEnclave`) with `privateKeyUsage` access control, `AfterFirstUnlockThisDeviceOnly` accessibility, the Data Protection Keychain, and an ASCII-only namespace below `com.codexmicro.phase2transport.spike`.
- Software Data Protection Keychain keys were tried first and **failed the export assertion**: `kSecAttrIsSensitive`/`kSecAttrIsExtractable: false` do not stop `SecKeyCopyExternalRepresentation` for a software key held by the creating process. Non-exportability therefore requires the Secure Enclave token; Macs without a Secure Enclave fail closed.
- Creation first acquires an atomic generic-password claim keyed by namespace and role. A duplicate claim with no key fails as incomplete creation rather than stealing an in-progress/orphaned claim.
- Post-create validation requires exactly one claim and one matching key. Failure rolls back the newly created key and claim.
- Retrieval rejects missing claims, incomplete creation, multiplicity, wrong attributes, wrong expected SPKI, and exportable private keys.
- Cleanup attempts both roles across the caller namespace and all fixed certificate-probe namespaces, deletes keys and claims, verifies absence, aggregates failures, and deletes the proof file only after Keychain cleanup succeeds.
- The real persistent-Keychain test is explicitly skipped unless an entitled test host is requested. Ordinary `swift test` no longer reports that row as a pass.

### Certificates and rotation

- `swift-certificates` public `Certificate.PrivateKey.init(_ secKey:)` signs through the non-exportable `SecKey`.
- Certificate creation requires a `.tls` identity. Rotation signing and verification require `.host`.
- Certificates use static content-neutral subject/SAN fields and ECDSA/SHA-256 server-auth/digital-signature extensions.
- `SecCertificate` and `SecIdentity` are constructed with the original key and checked for SPKI equality.
- Same-key renewal preserves SPKI; a new key changes it.
- Rotation verification binds the signed statement to the expected current SPKI and the actually presented next certificate SPKI, in addition to validity, generation, and signature checks.
- Tests include a fixed 97-byte canonical fixture, field mutations, wrong roles, wrong current/next pins, rollback, expiry, and signature mutation.

### Interface containment

- `InterfaceBinding` has no public arbitrary initializer. Production bindings come from discovery; loopback has one explicit test-only factory.
- Binding creation and server startup independently require an active allowed interface and revalidate a numeric address.
- Hostnames, wildcard/unspecified, public, multicast, IPv4/IPv6 link-local, and disallowed loopback addresses are rejected.
- Only private IPv4 or IPv6 ULA addresses on Wi-Fi/Ethernet are eligible outside tests.
- NIOTS binds a pre-parsed `SocketAddress`, verifies the bound local address matches, requires the corresponding Network.framework interface type, and has no DNS or wildcard fallback.

### TLS and WebSocket

- Network.framework TLS is fixed to TLS 1.3 and the public `AES_128_GCM_SHA256` cipher suite.
- Tickets, resumption, False Start, fallback mode, and TCP/Network.framework Fast Open are disabled. Peer-to-peer and multipath are disabled.
- HTTP limits are 16 fields, 8 KiB total, and 4 KiB per field.
- Upgrade requires HTTP/1.1 `GET`, exact path without query, single required headers, exact Origin/subprotocol, WebSocket version 13, a valid key, and a header-name allowlist.
- `URLSessionWebSocketTask` offers `permessage-deflate` without a public suppression switch. The server permits only that exact offer, omits it from the response, and rejects RSV bits; compression is not negotiated.
- The decoder frame cap is 16 KiB. The binary-message cap is 64 KiB and eight fragments. Tests cover unexpected continuation, new messages during fragmentation, tiny fragments, fragment-count and aggregate-size overflow, reserved bits on fragments, and control-frame interleaving.
- The pinned client records and surfaces an exact `.pinMismatch` result instead of relying on a generic URLSession error.

The observed loopback pin closure is feasibility evidence only. Whether this exact trust-override design is acceptable for production remains an ADR/security-review decision.

### Transport and Bonjour lifecycle

- `NIOTSTLSWebSocketServer` is an actor backed by an explicit `idle → starting → running → publishing → stopping → terminated` one-shot state machine.
- Concurrent start, start/stop, duplicate stop, invalid-bind, publication/stop, late-child, and nonrestart transitions fail closed or join teardown.
- Cleanup attempts publication removal, every tracked child close, server close, and event-loop-group shutdown even if an earlier step fails. Sanitized snapshots expose only phase, child count, publication state, and group-shutdown state.
- The child registry rejects and closes children arriving after stopping starts.
- Bonjour registration uses a cancellable timeout. Success cancels the timer; losing timeout/add callbacks cannot mutate the service. Remove-after-success triggers server termination.
- Pure tests prove timeout/add/stop/remove winner behavior and that a losing timeout does not remove a published service.

An early basic-signed run timed out during Bonjour registration and rolled back. After automatic provisioning and the waiter race fixes, one signed LAN run published successfully and completed the pinned exchange; stability and multi-network behavior remain unproven.

### Separate lifecycle-generation model

`ListenerLifecycleState` now fails closed before `UInt64` generation overflow and never wraps. It remains a standalone authentication-generation model. It is **not** integrated with `NIOTSTLSWebSocketServer`, which has no real pairing/authentication boundary in this spike. Its tests do not prove runtime connection reauthentication.

### Logging

Application log APIs accept only a closed `SpikeLogCode` and nonnegative integer count. Interface eligibility now has a distinct `interface_eligible` code. Missing Keychain entitlement is reported as `keychain_unavailable` with exit status 77. No free-form error, endpoint, name, path, certificate, fingerprint, frame, or payload can be passed to the application logger.

## Commands

Run from the repository root.

### SwiftPM verification

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

The ordinary suite reports the persistent Data Protection Keychain test as skipped with an explicit entitlement reason.

### Basic development-signed observation app

```sh
CODE_SIGN_IDENTITY='Apple Development' \
  Spikes/Phase2Transport/Scripts/build-signed-probe.sh
```

The script signs and verifies a complete staging app, moves it to an immutable ignored generation, then atomically replaces `.build/current-signed-probe` with a symlink. Previous verified generations and the former legacy app are retained for cleanup fallback.

This basic signature does not prove Data Protection Keychain access.

### Xcode automatic provisioning path

A minimal project exists at:

`Spikes/Phase2Transport/SigningProbe/Phase2TransportSigningProbe.xcodeproj`

The exact authorized main-session command is:

```sh
xcodebuild \
  -project Spikes/Phase2Transport/SigningProbe/Phase2TransportSigningProbe.xcodeproj \
  -scheme Phase2TransportSigningProbe \
  -configuration Debug \
  -destination 'platform=macOS' \
  -derivedDataPath Spikes/Phase2Transport/.build/XcodeSigningProbe \
  -clonedSourcePackagesDirPath Spikes/Phase2Transport/.build/XcodePackages \
  DEVELOPMENT_TEAM='<team-id>' \
  -allowProvisioningUpdates \
  build

Spikes/Phase2Transport/Scripts/publish-xcode-signed-probe.sh
Spikes/Phase2Transport/Scripts/run-keychain-proof.sh manual-proof
```

That command is scoped to `com.codexmicro.phase2transport.spike`. The user explicitly authorized the automatic provisioning action and it was executed from the main session with `-allowProvisioningDeviceRegistration` (Xcode also had to register this Mac), `ENABLE_DEBUG_DYLIB=NO` (single executable instead of the preview debug-dylib layout), and `OTHER_CODE_SIGN_FLAGS='--deep'` (the copied SwiftPM resource bundles are otherwise unsigned and fail the seal). The SigningProbe target uses its own `Info.plist` with `$(EXECUTABLE_NAME)` so the bundle's declared executable matches the built product; the proof/cleanup scripts resolve the executable through `CFBundleExecutable`.

### Strict cleanup

```sh
Spikes/Phase2Transport/Scripts/cleanup-keychain.sh manual-proof
```

Cleanup resolves and verifies one immutable app generation. If no verified cleanup app exists, it fails and leaves the proof file in place; it never claims cleanup based only on deleting a file.

### Signed LAN observation

```sh
APP='Spikes/Phase2Transport/.build/current-signed-probe/Contents/MacOS/phase2-transport-probe'
"$APP" interface-inventory
"$APP" transport-lan
```

The LAN command uses only content-neutral bytes. Publication failure or teardown failure produces a closed failure result. It does not change TCC, router, firewall, or network configuration.

## Remaining adoption blockers

1. Bonjour registration and the pinned LAN exchange passed once on one machine/LAN; stability, IP-change, and multi-network behavior remain unproven.
2. The proven identity path is Mac Secure Enclave only; iPhone Secure Enclave, reinstall, and physical Wi-Fi evidence remain Step 2.14 scope.
3. Exact live `NWInterface` object pinning is not implemented; the spike uses an exact local address plus required interface type.
4. No per-connection message/byte rate limiter is implemented.
5. No bounded slow-consumer/non-writable timeout policy is implemented.
6. No post-upgrade application idle expiry is implemented.
7. No server-originated ping cadence and matching-pong deadline is implemented.
8. Lifecycle generation is model-only and not connected to authentication.
9. `NWListener.service` is public, but NIOTS warns that arbitrary underlying-listener modification is unsupported; continued physical evidence is required before production adoption.

See `EVIDENCE.md` for the sanitized result classification. The signed evidence chain was re-run from the tree squash-merged as c6577b7 (#10). No Phase 2 acceptance claim is made; physical-iPhone evidence remains Step 2.14 scope.
