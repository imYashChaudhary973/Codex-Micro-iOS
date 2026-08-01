# Phase 1 — Mac Bridge Core Status

**Status:** Accepted

**Snapshot:** 2026-08-01

## Product decision

The iPhone companion will display and control the same IDE-hosted Codex sessions that app-server reports with source `vscode`, including T3/Codex workspace conversations. The Mac remains the authoritative execution host.

The first distribution and platform assumptions are provisional: personal/TestFlight, iOS 17+, and macOS 14+. They do not authorize public distribution, a product relay, or an exposed network listener.

## Implemented in this increment

- Shared `CompanionProtocol` Swift target usable by iOS and macOS.
- Protocol version with major-version compatibility checks. This major-only check is an internal Phase 1 convenience; it is insufficient for Phase 2 network security messages, which require the exact minor/feature negotiation defined by the Phase 2 plan and transport ADR.
- Versioned generic companion envelope.
- Semantic command allowlist:
  - select thread,
  - start thread by opaque project ID,
  - send prompt,
  - steer turn,
  - interrupt turn,
  - resolve approval,
  - mark thread read.
- No phone-controlled filesystem path, sandbox, approval-policy, shell, process, or raw RPC field.
- Strict command decoding that rejects unknown command types and unknown fields.
- Boundary validation for opaque IDs, prompt size/content, attachment count, and approval digests.
- One-minute command age window with limited future clock skew.
- Device capabilities, project allowlists, revocation, and least-permissive mobile-profile intersection.
- In-memory bounded event journal with monotonic sequences, cursor replay, stale-cursor snapshot fallback, and ahead-cursor rejection. These sequences are an internal-only global namespace; Phase 2 never exposes them to the network and instead assigns per-device authorized-view sequences with the sealed replay cursor envelope.
- Agent-slot state derivation with `inputRequired` precedence.
- Exact Codex compatibility gate for CLI `0.146.0`:
  - one resolved absolute executable is used for both verification and launch,
  - version-specific app-server schemas are generated at runtime,
  - JSON is recursively canonicalized before SHA-256 hashing,
  - unsupported versions or changed schemas are blocked before app-server startup.
- Codex runtime supervisor states for compatibility checking, startup, ready, unsupported, degraded, and stopped.
- Runtime event forwarding and fail-closed degradation when the app-server connection ends unexpectedly.
- Deterministic event router that binds every turn to an explicit thread from a Codex event, turn response, or authoritative thread snapshot and rejects conflicting or unknown routes.
- Actor-isolated domain store that rebuilds authoritative thread snapshots and applies only explicitly routed lifecycle events.
- Versioned, content-free companion snapshots containing opaque IDs and normalized closed thread/turn statuses; raw prompts, items, paths, and errors are not serialized.
- Companion protocol 1.1 pending-approval summaries with legacy 1.0 snapshot decoding.
- Normalized command, file-change, managed-network, and permission approval kinds.
- Canonical SHA-256 approval digests bound to the JSON-RPC ID, method, and complete Codex request params.
- Two-minute approval expiry, constant-time digest checks, duplicate/collision protection, and single-resolution state transitions.
- Approve-once requires a fresh user-presence proof bound to the exact request digest; decline and cancel never require authentication.
- Host `LocalAuthentication` authenticator for device-owner verification. Phone-side device-bound proof transport remains Phase 2 work.
- Codex response mapping that excludes session-wide grants:
  - command/file/network approve-once maps only to `accept`,
  - permission approve-once grants only the requested profile for the current turn,
  - permission decline grants an empty profile,
  - permission cancel grants nothing and instructs the executor to interrupt the exact turn.
- In-memory content-free command ledger prototype:
  - SHA-256 request fingerprint,
  - idempotent replay for matching command IDs,
  - collision rejection for changed requests,
  - explicit lifecycle transitions,
  - `outcomeUnknown` after restart,
  - closed result-code enum rather than arbitrary log text.
- Persistent SQLite command ledger:
  - AES-GCM encryption for every content-free record,
  - command ID and update timestamp remain plaintext SQLite index metadata,
  - record ciphertext is authenticated against its command ID,
  - Keychain key provider using `AfterFirstUnlockThisDeviceOnly`,
  - `0600` database permissions, backup exclusion, secure deletion, bounded ciphertext size, and schema-version checks,
  - startup converts all nonterminal records to durable `outcomeUnknown`,
  - terminal-record retention purge.
- Deterministic fake app-server test harness (`CodexTestSupport` target):
  - scripted JSON-RPC replies behind the `JSONLineTransport` seam with a fail-closed method-not-found default for unstubbed methods,
  - sanitized fixtures for every consumed notification and all four approval kinds (command, network, file-change, permissions),
  - adversarial malformed-line, methodless, unknown-notification, unknown-server-request, invalid-approval, and expired-approval shapes,
  - crash, clean-close, and request-timeout simulation,
  - contract tests that drive the real app-server client, domain store, and runtime supervisor through every scenario and assert that no server request is ever answered automatically.
- Approval-response executor (`ApprovalResolutionExecutor`) wiring prepared approval resolutions to the app-server client:
  - ledger lifecycle around every send: `submitting` → policy-gated preparation → single send → `submitted` → `serverRequest/resolved` reconciliation → terminal outcome,
  - policy rejections (missing user presence, digest mismatch, expiry, not pending) terminate as `declined`/`rejectedByPolicy` before anything is sent,
  - a response is sent at most once; missing confirmation becomes durable `outcomeUnknown` with a `confirmationTimedOut` result code and is never resent,
  - send failures on a dead connection terminate as `failed`/`codexUnavailable` with the approval surfaced for Mac-side review,
  - permissions-cancel sends the turn-scoped empty grant and interrupts the exact recorded turn,
  - idempotent replay returns the recorded result for a repeated command ID without re-executing,
  - per-command `outcomeUnknown` transitions and a shared `CommandLedgering` protocol on both the in-memory and encrypted persistent ledgers.
- Automatic degraded-state recovery (`CodexRuntimeRecoveryCoordinator`):
  - watches supervisor states and reacts only to degraded states; `unsupported` remains terminal and is never retried,
  - surfaces all in-flight ledger work as `outcomeUnknown` before any restart so nothing is mistaken for re-executable work,
  - restarts through the full compatibility gate with capped exponential backoff,
  - rebuilds thread state only from authoritative `thread/read` snapshots and drops threads that cannot be re-read instead of guessing,
  - never replays state-changing commands during recovery,
  - forwards runtime states and content-free recovery milestones on one observable stream.
- Redacted structured logger (`RedactedLogger`):
  - a closed log-event vocabulary whose associated values are enums and integers only; free-form strings cannot enter an entry without adding a reviewed case,
  - raw app-server events map through a method allowlist; unknown method names and all params/warning text are discarded, never logged,
  - recovery events reduce thread IDs to counts; no thread, turn, request, prompt, command, path, or error text reaches log bytes,
  - unified-logging production sink plus a sink seam for tests,
  - sentinel-injection content-leak tests over every raw-event surface and the whole vocabulary.
- Bridge composition root (`CodexBridgeAssembly`) and the `codex-micro-bridge` menu-bar shell:
  - one supervised runtime with automatic recovery, the actor-isolated domain store, the bounded event journal, approval execution, and redacted logging behind a small start/stop/suspend/resume lifecycle,
  - the assembly is the single consumer of supervisor and recovery streams; the app observes one content-free `updates` stream,
  - events for unknown threads trigger lazy authoritative `thread/read` rebuilds; journal sequences back companion snapshots and cursor replay,
  - the Keychain-backed encrypted ledger resolves to the user's Application Support path (`CodexMicro/command-ledger.sqlite`),
  - a SwiftPM SwiftUI `MenuBarExtra` shell wires launch, system sleep (clean pause without recovery), wake, and quit; menu content is fixed status labels and counts only.

## Verification

```text
CompanionProtocol/MacBridgeCore tests: 62 passed, 0 failed
CodexAppServer tests: 18 passed, 0 failed
Total Swift tests: 80 passed, 0 failed
Generic iOS 17 arm64 CompanionProtocol build: passed
macOS release build: passed
Swift format lint: passed
Live compatibility probe: Codex CLI 0.146.0 and canonical schema digest supported
Third-party runtime dependencies added: none
Network listener added: no
User/provider credentials stored: no
Generated device-only secrets stored: one Keychain ledger encryption key
```

## Security properties currently enforced

- Unknown state-changing command types and fields fail closed.
- Reusing a command ID with different content is rejected.
- Crash-ambiguous work is surfaced as unknown and is not registered as new work.
- A revoked device cannot issue commands.
- A device cannot cross its project allowlist.
- Natural-language prompts require both the `runAgent` capability and an effective agent-running profile.
- Host policy and device policy intersect at the more restrictive profile.
- Ledger records cannot accept prompt text, command output, paths, or arbitrary result strings.
- The compatibility check and app-server launch use the same resolved executable rather than separate `PATH` lookups.
- Unknown Codex versions, changed schemas, unknown turns, and conflicting turn-to-thread routes fail closed.
- Companion snapshots cannot contain raw thread item content.
- Approval mutation, replay, expiry, cross-request user-presence reuse, and second resolution fail closed.
- An approval response is sent at most once; unconfirmed or unsendable responses become terminal `outcomeUnknown`/`failed` records and are never retried automatically.
- Automatic recovery restarts only through the full compatibility gate, rebuilds only from authoritative thread reads, drops unreadable threads instead of guessing, and never replays state-changing commands; an unsupported Codex blocks recovery terminally.
- Log entries are content-free by construction: only allowlisted method names, closed reason codes, and numeric counts can be serialized, verified by sentinel-injection leak tests.
- Session-wide approval decisions and policy amendments are not representable through the companion protocol.
- Persistent records are authenticated ciphertext; wrong keys, tampering, oversized records, and unknown database schema versions fail closed.
- Prompts, command text, paths, thread IDs, and turn IDs do not appear in plaintext ledger bytes.

## Exit-gate verification

The four Phase 1 exit gates from the architecture plan are met, re-verified on 2026-08-01:

1. **Contract tests cover every consumed event and approval type.** The fake app-server harness drives the real client, domain store, supervisor, executor, recovery coordinator, and assembly through every consumed notification, all four approval kinds, and every decision path; the log method allowlist is test-pinned to exactly the consumed protocol surface.
2. **Unknown or experimental messages cannot accidentally trigger an action.** Unknown notifications, unknown server requests, unknown methods, unknown command types/fields, malformed lines, methodless messages, and field-incomplete or expired approvals all fail closed in contract tests, and unstubbed fake methods fail closed by default.
3. **The bridge survives Codex crash/restart and reports degraded state.** Automatic recovery restarts through the compatibility gate with backoff, converts in-flight work to `outcomeUnknown`, rebuilds only from authoritative reads, and reports every transition on a content-free stream; verified for crash, repeated startup failure, unsupported-after-restart, and clean suspend/resume.
4. **A phone cannot steer or start work above its granted mobile action ceiling.** Capability tests cover grant/profile intersection, cross-project denial, revoked devices, observe-profile natural-language denial, and stale-command rejection.

## Deferred beyond Phase 1

- App-bundle packaging, signing, and notarization of the menu-bar shell — release-phase work; the SwiftPM `codex-micro-bridge` executable already wires the full production lifecycle.
- Live-probe verification that installed Codex emits `serverRequest/resolved` for bridge-resolved approvals — belongs before or within **Phase 4**, which owns phone-originated approvals; Phase 2 rejects `resolveApproval` throughout, so this probe is not a Phase 2 prerequisite. The reconciliation contract is proven against the fake app-server only.
- Device-bound phone user-presence assertions — **Phase 4** approval-hardening work, not Phase 2; a boolean claimed by the phone is not sufficient.
- Simulator and physical-device integration — the minimal signed iOS **acceptance host** arrives at Phase 2 Step 2.14 solely to prove identity/pairing/transport acceptance; the product iOS UI and its device integration remain Phase 3. The shared protocol already passes a generic iOS device build.

Networking, pairing, Bonjour, WSS, and the iOS interface remain Phase 2 and Phase 3 work. They are intentionally not part of this increment.
