# Codex Micro

Native iPhone companion work for Codex on a Mac. The Mac remains the authoritative execution host; the phone will be a controlled client.

## Current implementation

Phase 0 verified the installed Codex app-server and the intended IDE-hosted `vscode` session workflow. Phase 1 (the Mac bridge core) is accepted and includes shared native `CompanionProtocol` and `MacBridgeCore` libraries for semantic phone commands, strict validation, capability/project policy, mobile action profiles, bounded event replay, slot-status derivation, exact Codex compatibility checks, supervised runtime state, deterministic event routing, phone-safe state snapshots, digest-bound pending approvals, an encrypted persistent command ledger, single-send approval-response execution reconciled against `serverRequest/resolved`, automatic degraded-state recovery that rebuilds from authoritative thread reads without replaying commands, and a redacted structured logger whose entries are content-free by construction. `CodexBridgeAssembly` composes the full pipeline behind one lifecycle, and `codex-micro-bridge` is the development menu-bar shell that hosts it (it runs the live compatibility probe and app-server on launch). A deterministic fake app-server harness (`CodexTestSupport`) contract-tests every consumed notification and approval type, plus malformed and unknown messages, without live Codex turns.

```bash
swift test
swift run codex-micro-bridge
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

The implementation does not yet expose a production network listener, pair a phone, or include the iOS UI. The phone approval path is closed for all of Phase 2 — the network gateway rejects `resolveApproval`, and approval transport plus device-bound user-presence proofs are Phase 4 work. The existing CLI probes remain development-only and require explicit confirmation for live turns.

See [the system architecture](docs/IOS_COMPANION_ARCHITECTURE.md) for the full design and phased delivery plan.
Branching, commit, PR, and merge conventions are defined in [the Git workflow](docs/GIT_WORKFLOW.md).
Accepted Phase 0 evidence and recorded limitations are tracked in [the Phase 0 status](docs/PHASE_0_STATUS.md).
Phase 1 Mac bridge evidence is tracked in [the Phase 1 status](docs/PHASE_1_STATUS.md).
Phase 2 follows [the secure pairing and networking execution plan](docs/PHASE_2_PLAN.md): P0 security contracts and observe-only networking first, then individually gated semantic commands. Step 2.1 is accepted — [the threat model](docs/THREAT_MODEL.md) and [transport/TLS ADR](docs/PHASE_2_TRANSPORT_ADR.md) are the Phase 2 baseline, with evidence in [the Phase 2 status](docs/PHASE_2_STATUS.md) — and Step 2.2 (strict wire contracts) is next. The transport decisions rest on the merged evidence spike at `Spikes/Phase2Transport`, an isolated non-production package that proved the Secure Enclave identity and hardened NIOTS TLS/WSS stack on a signed Mac.
