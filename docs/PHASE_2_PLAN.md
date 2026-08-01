# Phase 2 — Secure Local Pairing and Networking Plan

**Status:** Phase 2 approved; execution plan ready

**Priority:** Security contracts before any listener or usable command path

**Scope:** Native local-LAN pairing, authenticated encrypted sessions, semantic command transport, discovery, revocation, and reconnect/replay. No iOS product UI and no public/relay networking.

## 1. Objective and completion definition

Phase 2 creates the first network security boundary for Codex Micro. A Mac bridge that is disabled by default will pair a device on the same LAN, authenticate it with long-term device identity plus a fresh session handshake, seal every post-handshake application frame, and expose only the capabilities in the Mac-authoritative device grant.

Phase 2 is complete only when all of the following are true:

- A fresh installation exposes no listener and advertises no Bonjour service until LAN access is explicitly enabled on the Mac. Step 2.7 may enable the listener only inside deterministic/loopback tests; user-accessible enablement does not ship until the Mac controls in Step 2.13.
- An unpaired or unauthenticated client receives no application metadata such as thread state, Codex status, project descriptors, grant data, or event cursors; only the content-neutral TCP/TLS/WSS handshake surface and a closed protocol reason may be observable.
- Pairing uses a five-minute, single-use bootstrap secret, pinned transport identity, mutual long-term signatures, dual verification-phrase confirmation, and an explicit Mac-side initial grant.
- Normal sessions use fresh ephemeral ECDH keys, transcript signatures, separate directional keys, authenticated frame headers, and exactly-next per-direction counters.
- An authenticated `observe` device can receive a current filtered snapshot and bounded replay using the sealed, device-bound replay cursor envelope defined in Section 9.
- Revocation is persisted before the affected active session is closed, and remains effective after bridge restart.
- One lower-risk state-changing command—`interruptTurn`—passes through the centralized session/grant/policy/ledger gateway and produces at most one app-server request across retries and reconnects.
- `sendPrompt` and `steerTurn` are available only after the P0 observe-and-interrupt slice is complete and only behind explicit `runAgent` grants plus mobile-action-profile intersection.
- A minimally signed iOS acceptance host proves Secure Enclave/Keychain identity, SPKI pinning, pairing, reconnect, and immediate revocation over physical Wi-Fi. Without this evidence the phase may be described only as **Mac/protocol complete**, not accepted end to end.

Phase 2 does **not** make phone approvals production-ready and defines no negotiated approval feature. The network command gateway rejects `resolveApproval` throughout this phase. Phase 4 defines the device-bound user-presence assertion only after the recorded live `serverRequest/resolved` probe and informed-review threat model are complete.

## 2. Non-negotiable security invariants

1. **Mac authority:** The bridge authenticates against its current stored device grant. A grant presented by the phone is evidence, not authorization authority.
2. **Listener fail-closed:** Missing host/TLS identity, inaccessible or corrupt grant storage, invalid network configuration, unavailable authorization policy, or unsupported Codex disables the listener and Bonjour advertisement. Ledger or runtime unavailability after otherwise successful initialization may leave authenticated observation available, but every state-changing command is denied.
3. **Identity continuity:** Host-identity loss while paired-device records exist requires re-pairing. The bridge never silently creates a replacement host identity.
4. **Observe is scoped:** Pairing creates no implicit `runAgent`, `approve`, `interrupt`, or project permission. The default initial grant has `observe` capability with an empty project allowlist unless the Mac user explicitly selects projects and additional capabilities.
5. **Scoped disclosure and cursors:** Every descriptor, snapshot, event, replay result, acknowledgement, queued frame, ledger-result disclosure, and read-cursor mutation is checked against the current Mac-stored project scope before enqueue or disclosure. Cursors are bound to device and grant revision; scope reduction purges queued data, advances that device's authorized-view epoch, and forces a fresh filtered snapshot. Wire-visible sequence values must not reveal unauthorized-project activity.
6. **Strict security decoding:** Pairing, handshake, authentication, frame-header, grant, rotation, and command-wrapper messages reject unknown fields and unsupported message types. Protocol negotiation binds an exact supported minor/feature set rather than accepting every future minor.
7. **Strong single-use pairing:** The bootstrap secret has at least 128 CSPRNG bits and is compared in constant time. Atomic `available → claimed` occurs before signature processing; a completed claim consumes the secret regardless of pairing success. Expired, losing concurrent, cancelled, reused, endpoint/mode/version-mismatched, signature-invalid, or incompletely confirmed attempts store no grant. The transcript-bound SAS has at least 20 uniformly derived bits from a fixed versioned word list, and each endpoint requires its own local confirmation.
8. **Pinned transport identity:** Pairing binds both the long-term host identity and the current TLS SPKI. TLS key rotation is accepted only through a host-identity-signed, anti-rollback rotation statement.
9. **Application-frame protection:** TLS is not the authorization layer. Every post-handshake payload is independently sealed with directional keys and a header authenticated as additional data.
10. **Exact counters:** Because WebSocket is ordered, a receiver accepts exactly the next counter. Duplicate, skipped, wrong-direction, altered, oversized, overflowed, or cross-connection frames close the session.
11. **Linearizable authorization changes:** Revocation, grant reduction, project-scope reduction, expiry, and host-generation changes are committed before the new revision becomes visible to all authorization checks. Unauthorized queued output and undisclosed ledger results are purged, and every affected pairing, handshaking, and authenticated connection is closed or reauthenticated. A concurrent operation either completes under the prior authorization before the commit or is denied without a new external call after it.
12. **Central command gateway and durable replay:** Network code never calls bridge executors directly. For every authenticated mutation, the gateway first verifies the current session, Mac-stored grant/revision, revocation, strict schema, and stable device-bound command identity. The ledger key is `(deviceID, commandID)` and its semantic digest covers command type, normalized target, payload, and effective policy while excluding session IDs and frame counters.
13. **Known result before new execution:** If a matching terminal ledger entry exists, the gateway may return it after current disclosure authorization succeeds even when the original freshness window elapsed or Codex is currently degraded. Reusing the same device/command ID with a different digest fails closed. Only a new command proceeds through freshness, project scope, capability, mobile profile, runtime readiness, and ledger claim before one external call. Crash-ambiguous claims become `outcomeUnknown`; automatic transport retries are disabled.
14. **No degraded queue:** New state-changing commands are denied while Codex is degraded, unsupported, or restarting. They are never queued for later execution.
15. **Storage failure denies authority:** Grant-store failure denies authentication. Ledger failure denies new state-changing commands. Neither falls back to memory-only authority.
16. **No undeveloped attachments:** Nonempty `attachmentIDs` are rejected until a device-bound, TTL/ownership/size-limited attachment service exists.
17. **Approval closed:** `resolveApproval` is rejected by the Phase 2 network gateway. No approval assertion or phone boolean is accepted as user-presence proof.
18. **One active authenticated session per device:** A newly authenticated session replaces and closes the previous authenticated session for that device; authorization changes also close pairing/handshake connections attributable to it.
19. **Redacted observability:** Codex Micro's application-generated structured logs contain only closed reason codes and numeric counts. They never contain endpoint URLs, IPs, host/device names, key material, fingerprints, QR content, frame bytes, opaque IDs, prompts, paths, commands, diffs, or approval details. System-library logging is inventoried separately and must not be configured with user-derived values.

## 3. Priority model and dependency graph

### Priority definitions

| Priority | Meaning | Merge rule |
|---|---|---|
| **P0 — secure network boundary** | Required to establish pairing, authenticated observe-only networking, revocation, and the centralized low-risk command path | Implement in dependency order; no bypasses or P1 feature work ahead of an unmet P0 gate |
| **P1 — provisional functional completion** | Required before Phase 2 can be called Mac/protocol complete, except conditional `startThread` | Runs only after Step 2.9 is merged and green; remains disabled by default until its own grant/policy/ledger tests pass |
| **P2 — explicitly deferred** | Valuable later but increases attack surface or is not required for the LAN milestone | Must not enter a Phase 2 implementation PR |

### Milestones

1. **P0 network boundary complete:** Steps 2.1–2.9 are merged and all applicable deterministic and loopback gates pass. This is not Phase 2 acceptance and does not yet expose user-accessible LAN controls.
2. **Mac/protocol complete (provisional):** Steps 2.1–2.13 are complete, with Step 2.12 either implemented or explicitly deferred by product decision, and every non-physical exit gate passes.
3. **Phase 2 accepted:** Step 2.14's acceptance-host/tooling PR is squash-merged last; the resulting `main` SHA is frozen and then passes every non-physical and physical gate. Only that exact tested SHA may receive the `phase-2-accepted` tag.

Priorities and milestones are distinct: Steps 2.1–2.9 constitute P0 implementation. Step 2.14 is not part of that P0 slice; it is the mandatory post-provisional acceptance gate.

### Dependency chain

```text
2.1 Threat model + transport ADR
 └─▶ 2.2 Strict wire contracts + journal epoch
      └─▶ 2.3 Crypto contract + golden vectors
           └─▶ 2.4a Host/TLS identities
                └─▶ 2.4b Device-grant authority
                     └─▶ 2.5 Pairing state machine
                          └─▶ 2.6 Authenticated session state machine
                               └─▶ 2.7 Hardened WSS listener (test-only enablement)
                                    └─▶ 2.8 Scoped observe/replay + revocation
                                         └─▶ 2.9 Central gateway + interrupt/read cursor
                                              └─▶ 2.10 sendPrompt
                                                   └─▶ 2.11 steerTurn
                                                        └─▶ 2.12 startThread decision
                                                             └─▶ 2.13 Mac controls + Bonjour
                                                                  └─▶ 2.14 physical acceptance
```

No implementation PR may skip an unmet predecessor. In particular, no listener lands with pairing, cryptography, authorization, or resource limits represented only as TODOs. Step 2.7's listener is reachable only through internal test configuration; user-accessible LAN enablement arrives in Step 2.13 after the secure boundary and command gateway are complete.

### Target ownership

Keep the number of new runtime targets small and authority unambiguous:

- `CompanionProtocol`: data-only strict wire schemas, reason enums, fixed-width protocol identifiers, and version/feature negotiation. It owns no keys, storage, sockets, policy, or executors.
- `CompanionCrypto` (new): pure canonical encodings and cryptographic operations plus transport-independent pairing/session state machines. It owns no Keychain adapters, grant authority, sockets, or Codex policy.
- `MacBridgeServer` (new): Mac host/TLS Keychain adapters, certificate and signed-SPKI-rotation lifecycle, TLS/WSS listener, connection actors, session registry, interface policy, resource limits, publication of already-authorized snapshot/replay batches returned by `MacBridgeCore`, and Bonjour.
- `MacBridgeCore`: authoritative device-grant store, grant revisions/revocation tombstones, project/capability policy, per-device authorized-view sequencing, construction of filtered snapshot/replay batches, command gateway, durable ledger, Codex runtime/executors, and authorization-change coordination.
- `CodexMicroBridge`: user-driven LAN enablement, pairing/SAS confirmation, grant and revocation administration, and redacted diagnostics. It does not implement cryptography or duplicate authorization decisions.
- The minimal iOS acceptance host supplies iOS Keychain/Secure Enclave and network adapters to `CompanionCrypto`; it contains no independent protocol or authorization implementation and becomes the technical foundation for Phase 3.

The transport ADR may revise these boundaries if the selected Apple TLS APIs require a different seam, but it must preserve the ownership rules above and justify any third new runtime target.

## 4. PR execution plan

The planning PR containing this document merges before implementation. Each step below is then one squash-merged PR unless the change exceeds roughly 500 non-generated lines; oversized steps split into stacked PRs without weakening the listed merge gate.

| Step / suggested branch | Priority | Deliverable | Required merge evidence |
|---|---:|---|---|
| **2.1 — `docs/phase-2-security-decisions`** | P0 | Documentation-only focused threat model, generated-secret inventory, `PHASE_2_STATUS.md`, Git-workflow scopes, and transport ADR. Fix TLS stack/API, minimum TLS/cipher policy, 0-RTT prohibition, resumption behavior, WebSocket origin/subprotocol/method/path/header limits, compression prohibition, direct-LAN interface eligibility/change behavior, content-neutral certificate fields, certificate renewal/rotation delivery, canonical transcript encoding, dependency policy, and mandatory application-layer AEAD. If checked-in spike code is required, use a separately stacked `feat/spike-phase-2-transport` PR and merge its conclusions back into the ADR. | Written decision with rejected alternatives; non-exportable key lifecycle proven; every listener-blocking question resolved; docs branch contains no executable/dependency code; no production listener. |
| **2.2 — `feat/protocol-secure-session-contracts`** | P0 | Strict pairing, authentication, subscription, snapshot/event, command-result, acknowledgement, and problem messages in `CompanionProtocol`. Exact minor/feature negotiation, frame-size constants, closed reason enums, and the sealed replay cursor envelope `(deviceID, grantRevision, authorizedViewEpoch, journalEpoch, sequence)`. Security/control decoders reject unknown fields. | Golden JSON fixtures; unknown-field/type, downgrade, unsupported feature/minor, malformed size, mismatched device, stale revision/view/epoch, ahead/rollback/overflow cursor tests; generic iOS build. |
| **2.3 — `feat/crypto-session-primitives`** | P0 | Add `CompanionCrypto`: length-delimited canonical transcript encoding, P-256 signatures/ECDH, HKDF labels, separate client→server/server→client keys, ChaCha20-Poly1305 frame codec, deterministic nonces, exact-next counters, SPKI fingerprints, SAS derivation, and rotation-statement signing. | Independent client/server golden vectors; every transcript field mutation fails verification; direction reflection, tamper, duplicate/gap/overflow/cross-connection replay tests; no Keychain or socket code. |
| **2.4a — `feat/server-host-tls-identities`** | P0 | Mac host-identity and TLS-identity Keychain adapters, content-neutral certificate generation/renewal, host-signed SPKI rotation statements, monotonic rotation generation, validity interval, anti-rollback storage, and identity-loss behavior. | Keychain/certificate round trips; non-exportable private keys; wrong/missing/corrupt identity and rollback tests; valid/invalid/expired rotation vectors; host identity is never silently replaced while grants exist. |
| **2.4b — `feat/bridge-device-grant-authority`** | P0 | Authoritative device public keys, capabilities, empty-by-default project scope, per-device grant revision/authorized-view epoch, expiry timers, revocation tombstones, and host-wide generation in encrypted storage. Define the single API used by session authentication and command authorization. | Store round trips; corruption/wrong-key/duplicate/rollback tests; linearizable concurrent grant/revocation/expiry tests; grant-store failure disables LAN; one device cannot read or mutate another device's authority. |
| **2.5 — `feat/crypto-pairing-state-machine`** | P0 | Transport-independent pairing state machine: normalized direct-LAN endpoint, five-minute session, constant-time bootstrap secret with ≥128 CSPRNG bits, atomic claim-before-verification and consume-after-claim semantics, nonces, mutual transcript signatures, fixed/versioned SAS with ≥20 derived bits, dual local confirmation, cancellation, and explicit initial grant (`observe` plus empty project scope by default). | Injectable clock/random/store; entropy/vector checks; expiry, rate-limited concurrent claim, reuse, cancellation, endpoint/mode mismatch, downgrade, signature/SAS mismatch, and one-sided confirmation tests; failed pairing stores no grant. |
| **2.6 — `feat/crypto-authenticated-session`** | P0 | Transport-independent normal-session handshake: fresh ephemeral ECDH, signed transcript, exact version/features, current Mac-stored grant revision/authorized-view epoch and host generation, session ID, directional frame keys/counters, and reconnect isolation. Phase 2 negotiates no approval feature. | Revoked/expired/reduced/stale-grant tests; active-session expiry; counter/replay/tamper/reflection tests; reconnect produces fresh connection/key/counter spaces; phone-presented grant cannot override Mac authority. |
| **2.7 — `feat/network-hardened-wss-listener`** | P0 | Add `MacBridgeServer` and the selected TLS/WSS stack. Listener and Bonjour remain off by default; only internal test configuration may enable the listener in this step. Bind only ADR-approved direct-LAN interfaces, expose only the closed pairing/authentication message allowlist before authentication, and enforce HTTP upgrade/subprotocol/origin rules, connection caps, handshake deadlines, frame caps, no compression, fragmentation rules, and per-source/session rate limits. Include a deterministic loopback client. | Non-paired client receives no application metadata; pin mismatch/invalid rotation/timeout/oversize/malformed fragmentation/flood tests; listener fails to start on identity/grant-store/network-config/policy/unsupported-Codex failure; no Codex command path or user-facing enable control exists. |
| **2.8 — `feat/network-observe-sync-revocation`** | P0 | Connect authenticated `observe` sessions to project-filtered `CodexBridgeAssembly` snapshots and replay. Add fresh-process `journalEpoch`, device/grant-revision-bound cursors, strict acknowledgements, bounded queues, slow-consumer snapshot fallback, and the storage model (not a network mutation yet) for each device's monotonic read cursor. Implement linearizable revocation/reduction/expiry: commit authority, purge unauthorized queued data, then close/reauthenticate all affected connections. `selectThread` remains phone-local UI state. | Current/stale/foreign-epoch reconnect; cross-device/cross-project/stale-grant cursor rejection; unauthorized project activity does not change the device-visible cursor; scope reduction forces filtered snapshot and purges queued data; concurrent enqueue/command vs revocation; active expiry; revocation survives restart; no network mutation or Codex request exists. |
| **2.9 — `feat/network-command-gateway-interrupt`** | P0 | Add the sole network→core semantic mutation gateway. After current-session/grant/schema/device-bound identity checks, matching terminal ledger results may replay after current disclosure authorization even if stale or runtime-degraded; new commands then pass freshness, project, capability/profile, runtime, and ledger-claim checks. Enable exactly `interruptTurn` and `markThreadRead`: interrupt requires explicit capability and may call Codex once; read-cursor mutation is device-own, scoped, monotonic, and never calls Codex. Reject every other command, approvals, and attachments. | One `turn/interrupt` maximum across duplicate/reconnect; stale/degraded known-result replay; cross-device command-ID reuse and digest collision rejection; crash boundaries before/after external call; scoped/monotonic `markThreadRead`; revoked/cross-project/new-stale/degraded/ledger-failure denials; executor bypass impossible. |
| **2.10 — `feat/network-send-prompt`** | P1 | Add `sendPrompt` through the same gateway, with explicit `runAgent` capability, allowlisted project/thread context resolved on the Mac, and effective `runReadOnly`/`runWorkspace` profile intersection. Nonempty attachments remain rejected. | Fake app-server happy path, profile-ceiling, revoked/cross-project/degraded, duplicate command, and crash-ambiguity tests; disabled unless the Mac grant explicitly enables `runAgent`. |
| **2.11 — `feat/network-steer-turn`** | P1 | Add `steerTurn` separately. Deny steering when the existing turn's effective policy is broader than the device's current mobile action profile or cannot be proven from authoritative state. | Explicit-policy-match tests; more-permissive/unknown-policy denial; duplicate/reconnect/crash-ambiguity coverage; one external call maximum. |
| **2.12 — `feat/network-start-thread`** | P1 conditional | Product-decision checkpoint: if v1 allows new threads, add `startThread` behind an explicit Mac feature toggle, `startThread` capability, opaque allowlisted project ID, forced mobile profile, and no phone-supplied path/sandbox/policy. Otherwise move this entire PR to a later phase. | User decision recorded; feature off by default; opaque project resolution, policy ceiling, replay, and crash-ambiguity tests. If deferred by recorded decision, this step is not required for P0 completion, provisional completion, or Phase 2 acceptance. |
| **2.13 — `feat/macapp-connections-bonjour`** | P1 | Mac menu controls for LAN enable/disable, pairing-session creation/QR presentation, dual SAS confirmation, device/grant editing, fingerprints, last-seen, expiry, and revocation. Add Bonjour only after direct endpoint pairing is secure, with an exact service-instance/TXT-key allowlist. Add redacted connection metrics. | Enable listener first and advertise only after successful startup; advertisement failure rolls back the listener. Disable removes advertisement before closing the listener. No advertisement while unavailable/disabled; QR/bootstrap data never logged; Bonjour/IP-change tests; grant reduction closes or reauthenticates the affected session. |
| **2.14 — `test/phase-2-device-acceptance`** | Acceptance gate — mandatory after provisional completion | Merge the minimal signed iOS acceptance host and runnable acceptance-matrix tooling. This PR proves development-signed compilation and deterministic readiness only; it does not claim physical acceptance. After squash merge, freeze the resulting `main` SHA and run every gate on that exact commit. | Before merge: acceptance host builds with development signing; matrix is runnable; full tests/release/lint/generic iOS build pass. After merge: physical results are stored as immutable sanitized SHA-keyed evidence; interrupt uses fake app-server unless live Codex is separately approved; tag the same tested SHA only if every gate passes. |

Steps 2.10–2.13 begin only after Step 2.9 establishes a merged and green P0 network boundary. They are sequenced because they share the command gateway, status, and protocol surfaces. Step 2.12 is implemented or closed by a recorded deferral. Step 2.14's implementation PR merges last; physical acceptance then runs on the resulting squash-merged `main` SHA, which is the only commit eligible for the acceptance tag. No two active branches may edit `PHASE_2_STATUS.md` or the same gateway/security-contract file.

## 5. Commit, review, and merge cadence

`docs/GIT_WORKFLOW.md` remains authoritative. Phase 2 adds the following security-specific rules:

- **One plan step per PR.** Use the branch names above or the same scope/purpose convention. The Step 2.1 docs PR contains no checked-in spike code; any required spike is a separately stacked `feat/spike-phase-2-transport` PR. Never combine protocol types with cryptography, cryptography with secure storage, pairing with the WSS listener, or the command gateway with all powerful executors.
- **Sequential phase chain.** Steps 2.1–2.14 merge in the documented order (with 2.4a before 2.4b and 2.12 optionally closed by a deferral decision). Begin each branch only from the freshly merged predecessor on `origin/main`.
- **Small buildable commits.** Commit a logical unit only when it compiles and its deterministic tests pass. Protocol behavior and its strict-decoding/golden-fixture tests land together; cryptographic behavior and vectors land together.
- **No security TODO on an enabled path.** A listener, message type, capability, or command stays disabled until all authorization, bounds, storage, logging, and failure behavior required by that PR are implemented and tested.
- **PR size ceiling.** Target under roughly 500 changed lines of non-generated code. Split mechanics from behavior with stacked PRs when necessary; do not reduce tests to fit the ceiling.
- **Required PR description:** What, Why/plan step, exact verification, threat-model impact, new stored secrets/identifiers, log-data impact, failure behavior, and explicitly disabled paths.
- **Required review pass:** full diff top-to-bottom plus a security check of trust boundaries, state transitions, replay/idempotency, storage failure, decoder strictness, logging, and resource bounds. Crypto/transcript changes require golden-vector review.
- **Merge only green and current:** `swift test`, `swift build -c release`, strict format lint, relevant generic iOS build, and the PR-specific adversarial suite all pass after rebasing on `main`.
- **Squash merge and delete branch.** The squash title uses a professional Conventional Commit message such as `feat(crypto): add transcript-bound pairing state machine`.
- **Evidence in the same PR.** Update `docs/PHASE_2_STATUS.md` (created in Step 2.1) with implemented scope, test counts, and honest limitations. Never call loopback, source-only, simulator-only, or generic-device-build evidence physical-device proof. Step 2.14 is the exception: physical evidence is necessarily produced after its squash merge and is stored as an immutable SHA-keyed artifact or annotated tag; a later docs-only PR may mirror it without moving the tag or claiming its own SHA was device-tested.
- **Phase tag:** after Step 2.14 is merged, freeze that `main` SHA, run every acceptance gate, then annotate and push `phase-2-accepted` pointing to the same tested SHA. The tag message contains or links the immutable evidence snapshot.

## 6. Verification matrix

Every implementation PR runs the existing full suite and its relevant rows below.

| Layer | Required verification |
|---|---|
| Protocol | Golden JSON fixtures; strict unknown-field/type rejection; exact minor/feature negotiation; downgrade/malformed-size cases; full replay-envelope device/revision/view/epoch/sequence validation across restart, scope change, retention, rollback, overflow, and cross-device use |
| Crypto | Shared client/server golden vectors; canonical length-delimited transcript; every field mutated independently; P-256 signature/ECDH; HKDF label separation; directional-key separation; nonce uniqueness; tamper/reflection/duplicate/gap/overflow/cross-connection replay rejection; SAS and SPKI fixtures |
| Secure storage | Host/TLS/device/grant round trips; missing/corrupt/wrong-key/duplicate/rollback data; Keychain locked/unavailable; identity loss; revocation persistence; no silent identity replacement; generated-key inventory and backup/accessibility properties |
| Pairing | CSPRNG entropy and constant-time comparison, claim/consumption semantics, rate-limited concurrent claims, expiry/cancellation/reuse, normalized IPv4/IPv6/default-port origins, mode/endpoint/version mismatch, signature failure, SAS entropy/mismatch/one-sided confirmation, observe-with-empty-scope default, and zero persisted grant on failure |
| Session | Current Mac-stored grant/revision/authorized-view epoch/host generation; revoked/expired/reduced grants including active-session expiry; one active authenticated session per device; fresh connection IDs/ephemeral keys/counters; old-frame cross-connection rejection; exact-next behavior; reconnect authentication |
| Listener | Off-by-default/test-only enablement before Step 2.13; configured-interface binding; non-paired zero-application-metadata behavior; closed pre-auth message allowlist; TLS/SPKI mismatch; valid/invalid/expired/rolled-back rotation; HTTP-upgrade/handshake timeout; frame/connection/rate caps; no compression; malformed fragmentation; flood handling; no Bonjour on startup failure |
| Observe/replay | Project-filtered snapshots/events; device+grant-revision cursor binding; current/stale/foreign-epoch behavior; cross-device cursor rejection; unauthorized activity does not affect visible sequence; bridge restart; slow consumer; bounded queues; scope-reduction purge/snapshot; linearizable revocation/reduction/expiry |
| Command gateway | Device-bound `(deviceID, commandID)` and semantic digest; current disclosure authorization before known-result replay; stale/degraded known duplicates; digest/cross-device collision rejection; new-command freshness/project/capability/profile/runtime/ledger checks; scoped monotonic read cursor; crash boundaries; one external call maximum |
| Logging | Sentinel injection through QR/pairing, TLS, handshake, frame, connection, grant, revocation, and command failures. Codex Micro structured logs contain only allowlisted codes/counts; system-library logging is inventoried and is not configured with user-derived certificate, endpoint, frame, or payload values |
| Loopback integration | Real TLS/WSS pairing and authentication; observe snapshot/replay; pinning and rotation; revocation; reconnect; duplicate `interruptTurn`; connection and rate limits; all against fake app-server execution |
| iOS compilation | `CompanionProtocol` and `CompanionCrypto` generic iOS device builds on every relevant PR; the acceptance host builds with development signing before device testing |
| Physical device | Exact candidate commit; Secure Enclave/Keychain identity and reinstall; pinned self-signed WSS; real Wi-Fi pairing/Bonjour; IP change; foreground/background reauth; Mac restart; Keychain lock/reboot; TLS rotation; filtered observe/replay; immediate revocation; fake-app-server idempotent interrupt unless live Codex is separately approved |
| Baseline | `swift test`, `swift build -c release`, and `swift format lint --strict --recursive Sources Tests` remain green in every PR |

Testing uses injectable clocks, randomness, key stores, transports, and network policy. Deterministic tests must not depend on wall-clock sleeps or live Bonjour timing. Network Link Conditioner and physical-device tests supplement deterministic/loopback contracts; they never replace them.

Live Codex turns or approvals remain opt-in because they may consume allowance or execute actions. Phase 2 command-path contracts use the fake app-server by default. Any live probe requires explicit confirmation and reports separately.

## 7. Phase 2 exit gates

Phase 2 is accepted only when every gate passes:

1. **Default-off boundary:** a fresh install, failed host/TLS identity, unavailable/corrupt grant authority, invalid network configuration, unavailable policy, disabled LAN toggle, or unsupported Codex exposes no listener and no Bonjour advertisement. Runtime/ledger loss after startup never permits a new state-changing command.
2. **Zero pre-auth application disclosure:** an unpaired, revoked, expired, malformed, pin-mismatched, or unauthenticated client receives no thread/project/Codex/grant/journal application metadata; only the allowlisted content-neutral transport handshake and closed reason are observable.
3. **Pairing replay resistance:** weak/malformed, expired, reused, losing-concurrent, altered, downgraded, endpoint/mode-mismatched, signature-invalid, SAS-mismatched, or incompletely confirmed attempts are rejected and persist no grant.
4. **Session/frame integrity:** replayed, non-exact-next, reflected, wrong-direction, cross-connection, altered, oversized, overflowed, or unauthenticated frames are rejected and close the connection.
5. **Identity and TLS lifecycle:** valid TLS-key rotation requires the paired host identity and advances anti-rollback state; invalid/expired/rolled-back rotation is rejected; host-identity rotation/loss requires re-pairing.
6. **Scoped observation:** the default grant discloses no project until explicitly selected; every snapshot/event/replay/cursor/result is current-grant filtered; cross-device/project cursors fail; scope reduction purges queued data, advances the authorized-view epoch, and forces a filtered snapshot without leaking unauthorized activity through sequence changes.
7. **Linearizable revocation and expiry:** revocation/reduction/expiry persists first, publishes the new revision to all checks, purges unauthorized queued/results, closes or reauthenticates every affected connection immediately, does not affect unrelated devices, and survives restart. Concurrent operations cannot begin a new external call after the authority commit.
8. **Reconnect correctness:** a replay envelope matching the authenticated device and current grant revision, authorized-view epoch, and journal epoch replays retained authorized events. Older revision/view, foreign epoch, or retention-stale envelopes receive a filtered snapshot; mismatched device, ahead sequence, rollback, overflow, or malformed values fail closed; restart does not replay commands.
9. **Central authorization and known-result replay:** no network path bypasses the gateway. Current session/grant/revision/schema/device-command identity and disclosure authorization precede matching terminal-result replay; only new commands pass freshness/project/capability/profile/runtime/ledger-claim checks.
10. **Idempotent P0 mutations:** `markThreadRead` is scoped, monotonic, and device-own; repeated `interruptTurn` across reconnect produces one app-server request maximum and returns the durable result. Digest collisions fail; crash ambiguity becomes `outcomeUnknown` and is not resent.
11. **Bounded untrusted input:** frame sizes, connections, upgrade/handshake duration, pairing attempts, command rate, queued output, and slow consumers are bounded and adversarially tested.
12. **Content-free diagnostics and discovery:** sentinel tests cover every new application log path; Bonjour uses an exact allowlist and contains no user content/secret. System-library logging is inventoried and not configured with user-derived values.
13. **Physical-device proof:** on the exact candidate commit, a signed real iPhone passes the full Step 2.14 matrix: Secure Enclave/Keychain identity and reinstall, pinned self-signed WSS, pairing/Bonjour, IP change, foreground/background reauth, Mac restart, Keychain lock/reboot, TLS rotation, filtered observe/replay, immediate revocation, and fake-app-server idempotent interrupt over Wi-Fi unless live Codex is separately approved. Without it no acceptance tag is created.

## 8. Explicitly deferred scope

The following are not Phase 2 work:

- Polished iPhone product UI, six-agent dashboard, timeline, composer, approval sheets, accessibility polish, haptics, and app-store onboarding (Phase 3/4).
- Phone approval execution, including `approveOnce`, decline, or cancel, and the associated device-bound user-presence assertion format. Phase 4 defines both only after the live `serverRequest/resolved` probe and informed-review security design pass.
- Session-wide grants or any approval-policy amendment.
- Attachments, short-lived download endpoints, screenshots, audio, and file transfer.
- Tailscale/tailnet mode, TLS-terminating proxies, public listeners, router forwarding, or internet discovery (Phase 6).
- Product relay, accounts, queued ciphertext, APNs, and background wake-up delivery (Phase 7).
- Always-connected iOS background behavior; the Phase 2 acceptance client closes/reauthenticates honestly around lifecycle transitions.
- Offline content cache, durable event bodies, transcript persistence, and cloud diagnostics.
- Voice, transcription, media processing, and pasteboard integrations.
- Multi-user/team roles and shared authorization.
- App-store/TestFlight release UX, notarized distribution, updater/rollback, and production support flows, except development signing needed for real Keychain/Secure Enclave device evidence.
- Performance tuning beyond conservative measured caps and correctness fixes.
- `startThread` if the product decision in Step 2.12 is to keep v1 read/respond/control-only.

## 9. Decisions fixed for Phase 2

These defaults are fixed unless a later ADR explicitly replaces them:

- **Network mode:** direct same-LAN only. No tailnet, proxy-terminated TLS, relay, or public endpoint.
- **Platforms:** provisional iOS 17+ and macOS 14+, matching Phase 1 until release targeting changes.
- **Availability:** listener and Bonjour are off by default and require explicit Mac enablement.
- **Initial authorization:** paired devices default to `observe` with an empty project allowlist; the Mac user selects project scope and separately grants run/interrupt/start capabilities.
- **Transport layering:** WSS plus transcript-bound pinning and mutual identity signatures; post-handshake application payloads remain AEAD-sealed.
- **Wire encoding:** strict Codable JSON inside sealed frames; no binary/protobuf/compression until profiling proves a need.
- **Versioning:** exact supported minor/feature negotiation for security/control messages; no unconditional future-minor acceptance.
- **Frame order:** exactly-next per-direction counters; any gap or duplicate closes the session.
- **Replay cursor envelope and ownership:** the sealed wire cursor is `(deviceID, grantRevision, authorizedViewEpoch, journalEpoch, sequence)`. `MacBridgeCore` alone assigns sequence values within each device's authorized-view namespace and returns already-authorized batches; sequence advances only for data visible to that device. `MacBridgeServer` only publishes those batches and never receives an unfiltered journal. Matching current values may replay retained events; older revision/view, foreign epoch, or retention-stale values receive a filtered snapshot; mismatched device, ahead sequence, rollback, overflow, or malformed values fail closed.
- **Counter widths:** `journalEpoch` is a fresh 128-bit random value on every bridge-process start. Sequence, per-device grant revision, authorized-view epoch, TLS rotation generation, and host generation are unsigned 64-bit values. Before sequence overflow the bridge rotates epoch and forces snapshots; malformed, rolled-back, or overflowing authority counters disable the affected authority rather than wrap.
- **Authorization versioning:** every device grant/scope/revocation mutation increments that device's revision; scope-affecting changes also advance its authorized-view epoch. Host generation changes only for global invalidation.
- **Pairing:** five-minute, single-use ≥128-bit bootstrap secret; normalized direct-LAN endpoint; versioned SAS with ≥20 derived bits; dual local confirmation; observe with empty project scope by default.
- **Session cardinality:** one active authenticated session per device; successful reauthentication closes the previous session.
- **P0 semantic mutation allowlist:** exactly `markThreadRead` (scoped monotonic device-local cursor, no Codex call) and `interruptTurn` (explicit capability, one Codex call maximum). `selectThread` is phone-local; `sendPrompt`/`steerTurn` are P1; `startThread` is conditional; approvals, attachments, and unknown commands are denied.
- **Runtime/storage failure:** grant-authority failure denies authentication and disables LAN. Ledger/runtime failure after startup may leave authenticated observation available but denies every new state-changing command.
- **Dependencies:** Step 2.1 chooses the TLS stack only after proving the non-exportable Keychain/SecKey lifecycle. Prefer Apple Network.framework/SecIdentity if the proposed NIOSSL path would require exporting the private key.
- **Target growth:** add only `CompanionCrypto` and `MacBridgeServer` unless the ADR proves a third runtime target is necessary.
- **Acceptance:** physical signed-iPhone evidence is mandatory for full Phase 2 acceptance; generic iOS compilation is not equivalent.

## 10. Risks and stop conditions

| Risk | Required response / stop condition |
|---|---|
| Selected TLS stack cannot sign with a non-exportable Keychain/SecKey identity or cannot express the pinned rotation lifecycle | Stop before dependency adoption or listener implementation; select a stack/API that preserves the identity contract and update the ADR |
| No signed iOS host or Apple development team is available for Secure Enclave, entitlement, and SPKI-pinning validation | Continue deterministic and loopback work, but mark status Mac/protocol complete only; do not accept/tag Phase 2 |
| Sequence-only replay appears anywhere after Step 2.2 | Block merge; every persisted/reconnect cursor must include the journal epoch |
| Security/control Codable types silently accept unknown fields or future message types | Block merge; strict decoding is required before listener exposure |
| Listener starts when host/TLS identity, grant authority, network configuration, policy, or supported Codex is unavailable | Block merge and disable LAN/Bonjour; no degraded unauthenticated mode. Separately block any state-changing command accepted while ledger/runtime is unavailable |
| Network code can access `CodexBridgeAssembly.resolveApproval` or another executor outside the centralized gateway | Block merge; executor visibility/seams must make bypass impossible |
| Host identity is regenerated while paired devices exist | Treat as identity loss, disable LAN, require re-pairing, and add regression coverage |
| Revocation/reduction/expiry is not linearizable with enqueue and command execution | Block merge; commit authority, publish revision, purge unauthorized queues/results, and close/reauthenticate every affected connection; add concurrent-race tests |
| Counter gaps are tolerated, authority counters wrap, or cursor values are not device/revision bound | Block merge; exact-next and fixed-width anti-rollback semantics are Phase 2 rules |
| App-layer AEAD, strict bounds, rate limits, decoder adversarial tests, redaction tests, or the focused threat model are proposed for Phase 4 | Reject the deferral; minimum versions are Phase 2 P0 because this phase opens an untrusted-LAN boundary |
| Attachment IDs, approval decisions, raw paths, sandbox settings, shell/RPC methods, or arbitrary MCP calls become reachable | Disable/reject the path and split it into a separately reviewed later-phase design |
| A PR grows too large to review confidently | Split into stacked mechanical/behavior PRs while keeping the feature disabled until the complete security contract merges |
| Physical tests disagree with simulator/loopback behavior | Physical evidence wins; Phase 2 remains unaccepted until the root cause and regression test are resolved |

## 11. Immediate next action

Begin **Step 2.1 only**: the documentation-only focused threat model and transport ADR. If the TLS decision requires checked-in executable evidence, create the separately stacked `feat/spike-phase-2-transport` PR; do not put code or dependencies on the `docs/*` branch. The first production-code PR is Step 2.2. Neither PR may add a production listener, Bonjour advertisement, pairing endpoint, or network command path.
