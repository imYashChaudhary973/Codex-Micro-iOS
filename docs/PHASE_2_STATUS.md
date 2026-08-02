# Phase 2 — Secure Local Pairing and Networking Status

**Status:** Step 2.4a implemented (pending review/merge) — Step 2.4b (device-grant authority) is next

**Snapshot:** 2026-08-02

## Current objective

Step 2.1 resolved the Phase 2 trust model and every transport/TLS decision before any production session protocol types, cryptography targets, dependencies, listeners, discovery, pairing endpoints, or network command paths are added. Step 2.2 then delivered the strict secure-session wire contracts and the journal-epoch replay cursor in `CompanionProtocol` as pure data types. Step 2.3 added the `CompanionCrypto` target: the canonical statement encoding contract, P-256/ECDH/HKDF/AEAD primitives, SPKI fingerprints, SAS derivation, and rotation-statement verification, all pinned by golden vectors. Step 2.4a added the `MacBridgeServer` target with the Mac host/TLS Secure Enclave identity adapters, the content-neutral certificate lifecycle, and anti-rollback TLS rotation state under the ADR's exact dependency pins. The next work is **Step 2.4b only**: the authoritative device-grant store per ADR §10.

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

## Step 2.3 outcome — CompanionCrypto primitives and golden vectors

### Implemented scope (new `CompanionCrypto` target, pure primitives)

- **Target:** new `CompanionCrypto` library plus `CompanionCryptoTests` in the root package. It depends only on `CompanionProtocol` and the system CryptoKit/Foundation frameworks — no external dependency, no Keychain, no sockets, platforms unchanged. Package pins are untouched; the ADR's dependency adoption remains Steps 2.4a/2.7.
- **Canonical statement encoding (ADR §11):** every statement leads with the version byte and a length-prefixed ASCII domain separator; fields follow in one fixed order per statement type; integers are fixed-width big-endian; every variable byte/UTF-8 field carries a big-endian `UInt16` byte-length prefix; optionals encode an explicit presence byte. Six distinct versioned contexts exist: pairing transcript, session transcript, rotation statement, the two HKDF frame-key directions, and SAS.
- **Transcripts:** `PairingTranscript` (pairing session, mode, endpoint origin, exact protocol tuple, bootstrap secret, both 256-bit nonces, both 65-byte X9.63 long-term keys, host ID, current TLS SPKI fingerprint) and `SessionTranscript` (session/device IDs, exact tuple, both ephemeral keys and nonces, grant revision, authorized-view epoch, host generation) with validating initializers reusing the Step 2.2 `SecureTransportLimits` bounds; encoding cannot fail after construction.
- **P-256 operations:** strict X9.63 65-byte conversions (wrong length, compressed tag, and off-curve points fail closed); transcript signatures produced and consumed as exactly 64 raw `r||s` bytes — DER or any other length never verifies; ephemeral `P256.KeyAgreement` ECDH against validated peer keys.
- **HKDF-SHA256 key schedule:** input key material is the ECDH shared secret, the salt is the SHA-256 hash of the canonical session transcript, and each direction's info label is the canonical encoding of its domain separator plus the exact negotiated `(major, minor, features)` tuple. Output is two independent 32-byte ChaCha20-Poly1305 directional keys.
- **AEAD frame codec:** 33-byte clear header (version, 4-byte direction prefix, connection ID, big-endian `UInt64` counter, ciphertext length) authenticated in full as additional data; deterministic 96-bit nonce = direction prefix plus big-endian counter; counters start at 0 and receivers accept exactly the next counter. Duplicates, gaps, reflection, unknown direction prefixes, cross-connection frames, header/ciphertext/tag tamper, truncation, trailing bytes, zero-length and oversized payloads, and wrong keys are rejected with closed reason codes; the sealer refuses to seal past `UInt64.max - 1` and both codec halves fail closed permanently after any violation — counters never wrap.
- **SPKI fingerprints:** SHA-256 over the P-256 SubjectPublicKeyInfo DER of a strictly validated key (clean reimplementation; no spike code imported).
- **SAS derivation:** HKDF-SHA256 with its own versioned canonical label over the pairing-transcript hash; nine output bytes of which exactly the first 66 bits are consumed as six big-endian 11-bit indices — each uniform over `0..<2048` with no modulo bias — rendered as canonical zero-padded four-digit decimal groups (for example `1810-0125-1393-2037-1338-1258`).
- **Rotation statements:** canonical encoding with strict decoding (wrong version, wrong domain, wrong field lengths, truncation, and trailing bytes fail closed) and pure fail-closed verification in fixed order: host signature over the canonical bytes, current-SPKI pin binding, strict generation monotonicity above the caller's last accepted generation, then the inclusive validity interval at an injected epoch-seconds time. Persistence of pins and generations stays with later steps.

### Recorded decision — SAS word-list rendering deferred to Step 2.13

The plan fixes the SAS as six words from a fixed versioned 2,048-word list. Step 2.3 fixes everything security-relevant about it — the 66-bit uniform derivation, the versioned `codex-micro/sas/v1` context, and the six final 11-bit indices — and exposes the canonical decimal-group rendering. Binding the indices to the fixed versioned word list is recorded as a Step 2.13 UI concern (shared with the Step 2.14 acceptance host) so that a complete, reviewed word list ships once rather than a hand-assembled one. Adding the word list later changes display only; the derived indices and their golden vectors are already final.

### Step 2.3 verification

- 93 new deterministic tests in `CompanionCryptoTests` (root suite total 238): golden vectors are byte-exact hex fixtures for the pairing/session/rotation canonical encodings and hashes, HKDF directional keys, sealed frames for counters 0 and 1, SAS indices/display, the ECDH shared secret, and the SPKI fingerprint; recorded host signatures verify against the fixtures.
- Client and server roles are exercised independently throughout: transcripts built on each side are byte-identical, one role signs while the other verifies, ECDH and the key schedule agree across roles, and one role seals while the other opens.
- Every pairing-transcript, session-transcript, and rotation-statement field mutated independently fails signature verification (and every pairing mutation changes the SAS); `mode` is the one unmutatable field because its Phase 2 vocabulary has a single case.
- Adversarial frame coverage: every one of the 33 header bytes tampered individually plus per-region closed-reason checks, ciphertext and tag tamper, reflection, wrong-direction key, grafted header (AAD binding), duplicate, gap, cross-connection replay, sender and receiver counter exhaustion before wrap, overflow-sentinel counter, truncation, trailing bytes, oversized declared length, zero-length payload, wrong key, wrong key length, and permanent fail-closed latching.
- Non-canonical decodes rejected: rotation statements with trailing bytes, truncation, bad version, foreign domain, and patched field-length prefixes; X9.63 keys with wrong lengths, compressed tags, or off-curve points; signatures with DER or any non-64-byte form.
- The SPKI golden fingerprint was cross-checked outside the codebase: the identical SubjectPublicKeyInfo DER parses as a valid EC key under OpenSSL and its independent SHA-256 digest matches the fixture.

### Honest limitations

- **Pure primitives only.** No Keychain, Secure Enclave, storage, socket, listener, Bonjour, pairing endpoint, or command path was added; nothing in this step transports real traffic or holds authority. Integration arrives with Steps 2.4a–2.7.
- **No choreography.** Which endpoint signs which transcript-bound statement at which protocol step, claim/consume ordering, and confirmation flows are Step 2.5/2.6 scope; those steps may add further domain-separated statement types under this contract without changing the existing layouts.
- **SAS word-list rendering deferred** per the recorded decision above; devices compare decimal groups until Step 2.13 ships the versioned word list.
- ECDSA signing is randomized, so signature fixtures pin verification, not signing bytes; encodings, HKDF outputs, sealed frames, and SAS indices are byte-deterministic.
- The frame codec enforces per-frame bounds (sealed frame ≤ 64 KiB message cap); WebSocket-level limits, rate ceilings, and deadlines remain named declarations until Step 2.7 enforces them.
- Rotation verification is a pure function; anti-rollback persistence of accepted generations and delivery wire messages are Step 2.4a scope.
- Source-only evidence: no loopback, simulator, generic-device, or physical-device claims. The generic iOS device build of `CompanionProtocol`/`CompanionCrypto` was not run in this environment and remains required merge evidence.

## Step 2.4a outcome — host/TLS Secure Enclave identities and certificate lifecycle

### Dependency adoption (ADR §4 pins)

The root package adopted its first Phase 2 production dependency, exactly as pinned by the ADR:

```text
swift-certificates 1.19.4 (direct; revision 449dbbecd0f31e82b510ada227ca152caa8b5e98)
swift-crypto       4.5.1  (transitive; revision 47d3869a7291f085c1fb9fb1e6d3b97a793f45c6)
swift-asn1         1.7.1  (transitive; revision a9a5efd40eaf558a2bcd48d64b1d1646be686008)
```

The resolved revisions are byte-identical to the merged spike's `Package.resolved`, so the ADR §4 feasibility rows remain valid — no pin or toolchain changed. `swift-nio` and `swift-nio-transport-services` are **not** declared; their adoption point is Step 2.7.

### Implemented scope (new `MacBridgeServer` target)

- **Target:** new `MacBridgeServer` library plus `MacBridgeServerTests` in the root package, depending on `CompanionProtocol`, `CompanionCrypto`, and `X509`, linking the Security framework. It contains no socket, listener, Bonjour, pairing, grant, executor, or logging code.
- **Identity adapters (ADR §6):** `BridgeIdentityStore` implements the proven spike lifecycle for roles `.host` and `.tls` against a `SecureIdentityBackend` seam — atomic claim-before-creation with verified post-create state and rollback of both key and claim on any failure; strict retrieval validating claim/key cardinality, the non-exportable attribute profile, the expected SPKI fingerprint (constant-time), and the export-denial assertion in fixed order; closed content-free error vocabulary throughout. `loadOrCreate` distinguishes fresh creation from existing state and never replaces an identity: an expected-but-missing identity surfaces `identityLost` (LAN-disable), and destruction happens only through `reset`, gated by an injected "no grants exist" policy callback with verified cleanup.
- **Production backend:** `SecureEnclaveIdentityBackend` reproduces the spike's proven pattern in the production namespace — Secure Enclave P-256 (`kSecAttrTokenIDSecureEnclave`), `privateKeyUsage`-only access control, `AfterFirstUnlockThisDeviceOnly`, `kSecUseDataProtectionKeychain`, ThisDeviceOnly semantics, no software fallback. OSStatus values never leave the backend; failures map to the closed vocabulary.
- **Certificate lifecycle (ADR §7):** `BridgeCertificateFactory` issues content-neutral self-signed certificates from the `.tls` identity via swift-certificates, signing through the backend (production `SecKey`; test CryptoKit): fixed static subject/SAN, ECDSA P-256/SHA-256, critical `digitalSignature` key usage, `serverAuth` EKU, critical not-a-CA constraint, random serial, exactly 30-day validity from an injected clock. Same-key renewal preserves the pinned SPKI and fails closed on any mismatch; `isRenewalDue` implements the two-thirds-lifetime rule. `BridgeTLSIdentityAssembly` assembles the `SecCertificate`/`SecIdentity` pair for the Step 2.7 listener and requires the Keychain-backed key.
- **Rotation state (ADR §7/§11):** `TLSRotationAuthority` owns the persisted anti-rollback record — rotation generation plus current/previous SPKI fingerprints — as a small versioned canonical blob behind an injectable storage seam; the production `FileBackedRotationStateStore` lives under Application Support with a `0700` directory, `0600` file, atomic replacement, and backup exclusion. The authority produces host-signed rotation statements (reusing `SecureRotationStatement`/`SecureRotationVerifier` from `CompanionCrypto`, `.host` role enforced) and applies them with strict generation monotonicity, persisting the accepted generation before it becomes visible; rollback, replay, pin mismatch, bad signatures, out-of-window statements, corrupt/truncated state, and generation overflow all fail closed, and identity-continuity mismatch surfaces a closed `identityLost` state that callers must treat as LAN-disable.

### Step 2.4a verification

- 77 new deterministic tests in `MacBridgeServerTests` (root suite total 315), all through injected fakes (software CryptoKit keys and an in-memory item store behind the production seams): creation/load round trips and 64-byte raw-signature checks; duplicate claim, orphan claim, unclaimed key, incomplete creation; rollback on exportable/wrong-attribute/multiplicity post-create failures including rollback-failure surfacing; wrong/missing/corrupt/multiplicity/lookup-error retrieval; SPKI mismatch ordering; `loadOrCreate` created/existing distinction, identity-loss on expected-but-missing, and no-replacement over corrupt or mismatched state; reset refusal while grants exist (and on policy failure) plus verified-cleanup failure; certificate profile golden checks, 30-day validity from the injected clock, SPKI-to-identity binding, wrong-role rejection, renewal SPKI continuity, different-key rejection, new-key SPKI change, renewal-due boundary logic, and `SecCertificate` assembly round trip; rotation baseline/once-only initialization, statement production binding, valid apply, tampered-signature/wrong-key/wrong-pin/stale-generation/expired/not-yet-valid/replay rejection, anti-rollback persistence across store reopen, write-failure atomicity, corrupt/truncated/oversized state failing closed at open, generation-overflow refusal, and identity-continuity checks; blob-codec round trips with every-byte truncation, trailing bytes, wrong version/domain, and file-store permission/backup-exclusion assertions.

### Honest limitations

- **Secure Enclave/Data Protection Keychain positive paths run only in entitled contexts.** The unit suite exercises the production lifecycle logic exclusively through injected fakes; `SecureEnclaveIdentityBackend` compiles and mirrors the spike's proven pattern, but no test in this environment created, retrieved, or destroyed a real Secure Enclave key. The entitled positive proof exists as the merged spike evidence (`a445f81`/`c6577b7`, re-run signed-Mac) and is re-proven on-device at Step 2.14.
- **No listener and no served certificate.** Nothing binds a socket, advertises Bonjour, opens a pairing endpoint, or presents the generated certificate over TLS; the `SecIdentity` assembly is consumed first by the Step 2.7 listener. Rotation-statement delivery over an authenticated session is Step 2.6+ scope — this step only produces, verifies, and persists them.
- **No grant authority.** The reset gate takes an injected policy callback; the authoritative "no grants exist" answer arrives with the Step 2.4b grant store.
- Source-only evidence: no loopback, simulator, generic-device, or physical-device claims. The generic iOS device build of `CompanionProtocol`/`CompanionCrypto` (and the `MacBridgeServer` cross-platform declaration) was not run in this environment and remains required merge evidence.

## Current verification evidence

```text
Root swift test: 315 passed, 0 failed
  (MacBridgeCoreTests 127, CompanionCryptoTests 93, MacBridgeServerTests 77,
   CodexAppServerTests 18)
Root release build (swift build -c release): passed
Root strict format lint (Sources, Tests): passed
git diff --check: clean
Spike package (merged main, separate pins): 31 tests passed at Step 2.1; not re-run since
Phase 2 production listener added: no
Phase 2 production dependencies added: yes — exactly the ADR §4 Step 2.4a pins
  (swift-certificates 1.19.4 direct; swift-crypto 4.5.1 + swift-asn1 1.7.1 transitive)
Production pairing endpoint or Bonjour added: no
Network command path added: no
Keychain, Secure Enclave, or key-storage code added: yes — MacBridgeServer identity
  adapters and rotation state only; entitled positive paths not exercised by unit tests
```

The remaining production negatives are explicit: no production target gained a listener, Bonjour advertisement, pairing endpoint, or command path in Steps 2.1–2.4a. `CompanionCrypto` is pure computation over caller-supplied material, and `MacBridgeServer` holds identity/certificate/rotation lifecycle only. The spike package is isolated evidence with its own pinned dependencies and is not part of the production build.

## Deferred beyond Steps 2.1–2.4a

- Any production code or dependency implementing grant authority, pairing/session state machines, listener, WebSocket, Bonjour, revocation, or command transport — these continue at Step 2.4b in plan order, with the remaining ADR pins (`swift-nio`, `swift-nio-transport-services`) adopted at Step 2.7. Step 2.4a added only identity, certificate, and rotation lifecycle to the new `MacBridgeServer` target under the swift-certificates pin.
- The spike's deferred implementation gaps (rate limiting, slow-consumer policy, idle expiry, ping/pong deadlines, live `NWInterface` pinning, lifecycle-generation integration, `NWListener.service` physical re-verification, app-level connection caps, registry-based teardown) — owned by named steps in ADR §16.
- Phone approval execution or approval assertion types — rejected throughout Phase 2; Phase 4 scope.
- Physical-device claims — only at the post-provisional Phase 2 acceptance gate (Step 2.14).
