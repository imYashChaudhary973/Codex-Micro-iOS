# Phase 2 — Secure Local Pairing and Networking Status

**Status:** Step 2.2 implemented (pending review/merge) — Step 2.3 (crypto contract + golden vectors) is next

**Snapshot:** 2026-08-02

## Current objective

Step 2.1 resolved the Phase 2 trust model and every transport/TLS decision before any production session protocol types, cryptography targets, dependencies, listeners, discovery, pairing endpoints, or network command paths are added. Step 2.2 then delivered the strict secure-session wire contracts and the journal-epoch replay cursor in `CompanionProtocol` as pure data types. The next work is **Step 2.3 only**: the `CompanionCrypto` target with canonical transcript encoding and golden crypto vectors.

The accepted implementation order is defined in [the Phase 2 plan](PHASE_2_PLAN.md). This status document records evidence and limitations incrementally; it never treats source-only, loopback, generic-device, simulator, or Mac-only evidence as physical-iPhone proof.

## Step 2.1 outcome

### Accepted decision documents

- [Local pairing and networking threat model](THREAT_MODEL.md) — accepted as the direct-LAN Phase 2 baseline, with the generated-secret inventory updated for Secure Enclave keys and stack-managed TLS material and every Step 2.1 stop condition resolved.
- [Phase 2 transport/TLS ADR](PHASE_2_TRANSPORT_ADR.md) — accepted: NIO Transport Services listener over Network.framework TLS with a Secure Enclave `SecIdentity`, NIOHTTP1/NIOWebSocket exact upgrade control, swift-certificates content-neutral certificates, and an SPKI-pinned `URLSessionWebSocketTask` client. Pure Network.framework WebSockets, NIOSSL, custom framing, and exportable software Keychain keys are rejected with recorded reasons.

### Merged evidence spike

The transport feasibility spike merged to `main` as three stacked evidence PRs before this docs step:

```text
a445f81  feat(spike): prove non-exportable identity and certificate lifecycle (#8)
531d972  feat(spike): prove hardened NIOTS TLS 1.3 WebSocket transport (#9)
c6577b7  feat(spike): add signed probe with Keychain, Bonjour, and LAN evidence (#10)
```

The spike package (`Spikes/Phase2Transport`) is **isolated evidence, not production code**: it imports no production Codex Micro target and exposes no pairing, grant, session, command, approval, Codex, or user-data path. Its sanitized results live in `Spikes/Phase2Transport/EVIDENCE.md`; the positive signed-Mac proof was re-run from the merged `c6577b7` tree.

Decisive findings encoded in the ADR:

- Software Data Protection Keychain keys are exportable by the creating process; the non-exportable identity **requires** Secure Enclave keys, and machines without one fail closed.
- Positive signed-Mac proof: Secure Enclave create / separate-process retrieve / export-denied / mismatch-fail-closed / certificate-renewal-rotation / verified cleanup; eligible private-interface binding with unforgeable numeric-address validation; the one-shot listener state machine with complete teardown; and one successful content-neutral Bonjour publication plus pinned WSS binary exchange on a real LAN on one machine. This is signed-Mac observation evidence only — not stability, multi-network, or physical-iPhone proof.

### Pins and toolchain

User-authorized dependency pins fixed by the ADR for production adoption in Steps 2.4a/2.7 (any change re-triggers feasibility proof):

```text
swift-nio 2.101.3
swift-nio-transport-services 1.28.0
swift-certificates 1.19.4
swift-atomics 1.3.1 (transitive)
swift-collections 1.6.0 (transitive)
swift-system 1.7.5 (transitive)
swift-crypto 4.5.1 (transitive)
swift-asn1 1.7.1 (transitive)
```

Swift tools 6.2+; toolchain evidence tuple Swift 6.4 (swiftlang-6.4.0.27.1), Xcode 27.0 (27A5228h), macOS 27.0 (26A5388g).

## Resolved Step 2.1 gates

Every gate that blocked Step 2.1 completion is resolved in the accepted ADR:

| Gate | Resolution |
|---|---|
| TLS stack and proof of non-exportable Keychain/SecKey server identity | ADR §4 (decision), §6 (Secure Enclave proof) |
| TLS version, 0-RTT, resumption, cipher/API, and certificate policy | ADR §5, §7 |
| Same-key renewal plus host-signed, anti-rollback TLS key rotation and delivery | ADR §7 (two-phase rotation) |
| Exact direct-LAN interface/address eligibility and path-change behavior | ADR §8 |
| HTTP upgrade method/path/subprotocol/origin/header limits, compression policy, frame/fragment limits, deadlines, connection caps, and rate limits | ADR §9 (proven constants plus Step 2.7 ceilings) |
| Keychain accessibility, backup, loss, reset, and reinstall semantics for long-term material | ADR §6 |
| Grant-authority format and encryption-key lifecycle | ADR §10 (Keychain-resident canonical blob; no separate key) |
| Canonical transcript and application-frame header/nonce encoding | ADR §11 |
| System-library logging inventory and accepted residual metadata | ADR §13 |

**Unresolved listener-blocking questions: none.**

## Step 2.2 outcome — strict wire contracts and journal epoch

### Implemented scope (production `CompanionProtocol`, data-only)

- Strict secure-session wire schemas: `SecurePairingRequest`/`SecurePairingResponse`, `SecureSessionAuthRequest`/`SecureSessionAuthResponse`, `SecureObservationSubscribe`/`SecureObservationAcknowledgement`, `SecureObservationDelivery` (opaque bounded payload), `SecureCommandResult`, and `SecureProblemNotice`/`SecureCloseNotice`. Every security/control decoder rejects unknown fields and wrong types and enforces explicit bounds on every string/data/collection field; validating initializers keep out-of-bounds values unrepresentable on the encode side as well.
- Exact minor/feature negotiation: `SecureProtocolSelection` plus `SecureProtocolNegotiation` accept only the exact supported `(major, minor, feature set)` — no unconditional future-minor acceptance. Unknown, duplicate, and empty feature sets fail closed, and the closed `SecureProtocolFeature` vocabulary deliberately defines **no approval feature**.
- Sealed replay-cursor envelope `ReplayCursorEnvelope` with exactly `(deviceID, grantRevision, authorizedViewEpoch, journalEpoch, sequence)`, `JournalEpoch` modeled as exactly 16 raw bytes, and `evaluate(against:)` semantics: matching current values may replay; older revision/view, foreign journal epoch, or retention-stale cursors force a filtered snapshot; mismatched device, ahead sequence, rollback (revision/view ahead of authority), counter overflow, or malformed values fail closed.
- ADR §9 constants in the single `SecureTransportLimits` namespace (16 KiB frame, 64 KiB message, 8 fragments, header caps, deadlines, connection/rate/queue ceilings) plus the Step 2.2 wire-field bounds; every ADR value is asserted by test.
- Closed, content-free `SecureProblemReason`/`SecureCloseReason`/`SecureCommandDenialReason` vocabularies — no free-form string payload exists on any wire diagnostic path.
- The `ClientCommand` strict-decoding helper was extracted into a shared internal utility now used by every secure decoder; `ClientCommand` behavior is unchanged and its existing rejection tests still pass.

### Step 2.2 verification

- Golden JSON fixtures for every message type (14 fixtures) with byte-exact encode/decode/re-encode round trips against the canonical sorted-keys encoder.
- 65 new deterministic tests covering unknown field/type, downgrade attempts (major/minor/pairing mode), unsupported feature/minor, duplicate/empty feature sets, malformed sizes (secret/nonce/public key/signature/journal epoch), empty/oversized/control-character strings, oversized payloads, denial-reason consistency, and full cursor semantics (mismatched device, stale revision/view, foreign epoch, retention, ahead/rollback/overflow, inverted retention window).

### Honest limitations

- **JSON schema only:** no cryptography, no canonical binary transcript encoding, and no sealed-frame carriage — the AEAD-sealed frames that transport these messages arrive with Steps 2.3/2.7. Nothing in Step 2.2 proves confidentiality, authenticity, or replay protection.
- No listener, socket, Bonjour, pairing endpoint, Keychain, storage, executor, or policy logic was added. `SecureTransportLimits` values are named declarations for later enforcement (Steps 2.3/2.7), not enforced behavior.
- The pairing pair covers the initial request/response schema only; SAS confirmation and the remaining pairing choreography are Step 2.5 scope and may add message types there.
- `SecureObservationDelivery` carries an opaque bounded payload; binding filtered snapshot/event content schemas to it is Step 2.8 scope. The pre-existing `CompanionEnvelope`/`CompanionStateSnapshot` types remain non-strict application-data types outside the security/control surface.
- Source-only evidence: no loopback, simulator, generic-device, or physical-device claims are made by this step.

## Current verification evidence

```text
Root swift test: 145 passed, 0 failed (MacBridgeCoreTests 127, CodexAppServerTests 18)
Root release build (swift build -c release): passed
Root strict format lint (Sources, Tests): passed
git diff --check: clean
Spike package (merged main, separate pins): 31 tests passed at Step 2.1; not re-run in Step 2.2
Phase 2 production listener added: no
Phase 2 production dependencies added: no
Production pairing endpoint or Bonjour added: no
Network command path added: no
```

The four production negatives above are explicit: no production target gained a listener, dependency, Bonjour advertisement, pairing endpoint, or command path in Steps 2.1–2.2. The spike package is isolated evidence with its own pinned dependencies and is not part of the production build.

## Deferred beyond Steps 2.1–2.2

- Any production code or dependency implementing cryptography, identity storage, pairing state machines, sessions, listener, WebSocket, Bonjour, grants, revocation, or command transport — these begin at Step 2.3 in plan order, adopting the ADR's exact pins at Steps 2.4a/2.7. Step 2.2 added only data-only strict wire schemas to `CompanionProtocol`.
- The spike's deferred implementation gaps (rate limiting, slow-consumer policy, idle expiry, ping/pong deadlines, live `NWInterface` pinning, lifecycle-generation integration, `NWListener.service` physical re-verification, app-level connection caps, registry-based teardown) — owned by named steps in ADR §16.
- Phone approval execution or approval assertion types — rejected throughout Phase 2; Phase 4 scope.
- Physical-device claims — only at the post-provisional Phase 2 acceptance gate (Step 2.14).
