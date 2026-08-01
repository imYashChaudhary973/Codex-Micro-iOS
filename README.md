# Codex Micro

Native iPhone companion work for Codex on a Mac. The Mac remains the authoritative execution host; the phone will be a controlled client.

## Current implementation

Phase 0 verified the installed Codex app-server and the intended IDE-hosted `vscode` session workflow. Phase 1 now includes shared native `CompanionProtocol` and `MacBridgeCore` libraries for semantic phone commands, strict validation, capability/project policy, mobile action profiles, bounded event replay, slot-status derivation, exact Codex compatibility checks, supervised runtime state, deterministic event routing, phone-safe state snapshots, digest-bound pending approvals, an encrypted persistent command ledger, single-send approval-response execution reconciled against `serverRequest/resolved`, automatic degraded-state recovery that rebuilds from authoritative thread reads without replaying commands, and a redacted structured logger whose entries are content-free by construction. A deterministic fake app-server harness (`CodexTestSupport`) contract-tests every consumed notification and approval type, plus malformed and unknown messages, without live Codex turns.

```bash
swift test
swift run codex-micro-spike compatibility
swift run codex-micro-spike doctor
swift run codex-micro-spike threads --limit 6
swift run codex-micro-spike resume-recent --confirm-existing-thread
swift run codex-micro-spike smoke-turn --confirm-live-turn
swift run codex-micro-spike smoke-turn --confirm-live-turn --interrupt-immediately
swift run codex-micro-spike smoke-turn --confirm-live-turn --approval-cancel
swift run codex-micro-spike smoke-turn --confirm-live-turn --file-approval-cancel
swift run codex-micro-spike restart-probe --confirm-persisted-test-thread
```

Thread previews are redacted by default. Add `--include-preview` only when you intentionally want local titles or prompt previews printed in the terminal.
Live smoke turns consume Codex allowance and therefore require `--confirm-live-turn`. They are ephemeral, use the `untrusted` approval policy, force a read-only sandbox with network access disabled, and print event types/counts instead of model text. Server requests fail closed by default. The dedicated cancellation probes answer only their expected command or file-change request with the installed schema's explicit `cancel` decision; all other request types still fail closed.

The resume probe loads no turn and redacts thread content. The restart probe creates one persisted read-only test thread, stops the first app-server after `turn/started`, rebuilds state with a fresh client, verifies that no duplicate turn was sent, and archives the test thread afterward.

The compatibility probe resolves one absolute Codex executable, canonicalizes its generated JSON schema bundle, and checks the exact version and digest against the Phase 1 allowlist before a supervised bridge session may start.

The implementation does not yet expose a network listener, pair a phone, or include the iOS UI. Approval transport execution and device-bound phone user-presence proofs are not wired yet. The existing CLI probes remain development-only and require explicit confirmation for live turns.

See [the system architecture](docs/IOS_COMPANION_ARCHITECTURE.md) for the full design and phased delivery plan.
Branching, commit, PR, and merge conventions are defined in [the Git workflow](docs/GIT_WORKFLOW.md).
Current evidence and unresolved feasibility gates are tracked in [the Phase 0 status](docs/PHASE_0_STATUS.md).
Current Mac bridge work is tracked in [the Phase 1 status](docs/PHASE_1_STATUS.md).
