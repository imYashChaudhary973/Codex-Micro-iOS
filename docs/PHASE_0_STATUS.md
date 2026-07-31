# Phase 0 — Feasibility Status

**Status:** Accepted

**Snapshot:** 2026-08-01

## Outcome so far

The first constrained Codex app-server integration is working on this Mac. It proves that a native Swift process can initialize the installed app-server, inspect authentication state, list and read threads, start an ephemeral read-only turn, stream sanitized lifecycle events, and interrupt an active turn without exposing raw credentials or approving an action.

The product owner confirmed on 2026-08-01 that the IDE-hosted sessions reported with source `vscode` are the exact conversations the iPhone app should display and control. The custom companion route is therefore approved for Phase 1.

## Implemented

- Swift 6 package with no third-party runtime dependencies.
- `codex app-server --stdio` process transport using newline-delimited JSON.
- Required `initialize` request followed by `initialized` notification.
- Request ID correlation, ten-second timeouts, JSON-RPC error propagation, and process-exit handling.
- Generic notification and server-request events.
- Server approval requests are surfaced but never answered automatically.
- Read-only `account/read`, `thread/list`, and `thread/read` probes.
- Redacted thread output by default; previews require an explicit CLI flag.
- Explicitly confirmed `thread/start` and `turn/start` probes using:
  - ephemeral thread storage,
  - `untrusted` approval policy,
  - read-only sandboxing,
  - network access disabled.
- Sanitized turn summaries containing event names/counts, final status, and generated character count rather than model text.
- Event-synchronized interruption: `turn/interrupt` is sent only after the matching `turn/started` notification.
- Fail-closed handling for event timeouts, protocol warnings, and any server approval request.
- Explicit command approval cancellation using the installed schema's `decision: cancel` response; the expected request is matched to its turn and every other server request still fails closed.
- Equivalent file-change cancellation with a before/after SHA-256 check proving the requested file stayed unchanged.
- Guarded `thread/resume` verification using a `thread/read` baseline; identity and `updatedAt` remain unchanged and no turn is started.
- Restart-safe `ThreadRuntimeSnapshot` reconstruction from full `thread/read` data, explicit event routing, and idempotent duplicate lifecycle handling.
- Live bridge-restart probe using one persisted read-only test thread; a fresh client recovered one interrupted turn without sending another `turn/start`, then archived the test thread.
- Sanitized deterministic fixtures for plan, command/tool, diff, and failed-turn events retain only event counts and final status.
- Best-effort turn interruption and `thread/unsubscribe` cleanup on every probe failure.
- Explicit process shutdown after every CLI command.

## Verification evidence

```text
Installed Codex: codex-cli 0.146.0
Swift unit tests: 14 passed, 0 failed
Debug build: passed
Release build: passed
Swift format lint: passed
Live initialize handshake: passed
Live account/read: passed
Live thread/list: 20 recent threads returned
Live thread/read: passed with includeTurns=false
Live ephemeral thread/start: passed
Live read-only turn/start: passed
Live completion status: completed
Live agent delta events: 8 sanitized events, 22 characters total
Live immediate interruption status: interrupted
Live interrupted model output: 0 characters
Live command approval request: item/commandExecution/requestApproval
Live approval decision: cancel
Live approval result: command rejected before execution; turn status interrupted
Live file-change approval: cancel
Live file verification: README SHA-256 unchanged
Live thread/resume identity: verified
Live thread/resume timestamp: unchanged against immediate thread/read baseline
Live thread/resume turn/start: not sent
Live restart recovered turns: 1
Live restart recovered last status: interrupted
Live restart duplicate turn/start: not sent
Live restart cleanup: disposable test thread archived
Observed source classification: vscode
Observed runtime state: notLoaded
Orphaned spike app-server processes after exit: none
```

The live counts and classifications are a point-in-time development snapshot, not a release guarantee. A configured Apify MCP also emitted a missing-authentication startup warning during one completion probe; the warning was unrelated to the app-server transport and did not block the isolated turn.

## Commands

```bash
swift test
swift build -c release
swift run codex-micro-spike doctor
swift run codex-micro-spike threads --limit 6
swift run codex-micro-spike resume-recent --confirm-existing-thread
swift run codex-micro-spike smoke-turn --confirm-live-turn
swift run codex-micro-spike smoke-turn --confirm-live-turn --interrupt-immediately
swift run codex-micro-spike smoke-turn --confirm-live-turn --approval-cancel
swift run codex-micro-spike smoke-turn --confirm-live-turn --file-approval-cancel
swift run codex-micro-spike restart-probe --confirm-persisted-test-thread
```

Use `threads --include-preview` only when printing local thread titles or prompt previews is intentional.

## Phase 0 closure

- Text, command approval, file-change approval, completion, interruption, resume, and restart behavior were verified live.
- Plan, command/tool, diff, and failed-turn shapes have deterministic sanitized fixtures.
- A live diff notification was intentionally not forced because doing so would require approving a repository write solely for the test. This is a recorded safety limitation, not release evidence.
- Phase 1 contract tests must continue covering protocol drift before any phone-originated action is enabled.

All additional live-turn probes can consume Codex allowance. They must remain read-only, use disposable threads, and never auto-approve a tool or permission request.
