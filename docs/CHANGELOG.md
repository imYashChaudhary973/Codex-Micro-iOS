# Changelog

This log tracks phase acceptance and major milestones for Codex Micro.

## Phase 0 — Feasibility

- **Accepted:** 2026-08-01
- Proved a native Swift process can start `codex app-server`, complete the initialize handshake, list/read threads, start read-only turns, stream sanitized lifecycle events, and interrupt active turns without exposing credentials or auto-approving actions.
- Evidence: `docs/archive/PHASE_0_STATUS.md`

## Phase 1 — Mac Bridge Core

- **Accepted:** 2026-08-01
- Established `CompanionProtocol`, semantic command allowlist, strict decoding, device grants, capability profiles, event journal, Codex compatibility gate, runtime supervisor, approval executor, encrypted persistent command ledger, redacted logging, and the menu-bar bridge assembly.
- Evidence: `docs/archive/PHASE_1_STATUS.md`

## Phase 2 — Secure Local Pairing and Networking

- **Status:** Mac/protocol complete (provisional). Physical signed-iPhone acceptance (Step 2.14) pending Apple provisioning.
- Accepted threat model and transport/TLS ADR. Built `CompanionCrypto`, `MacBridgeServer`, host/TLS Secure Enclave identities, pairing and session state machines, hardened WSS listener, scoped observation/replay, revocation, and the network command gateway.
- Evidence: `docs/reference/THREAT_MODEL.md`, `docs/reference/TRANSPORT_ADR.md`, `docs/archive/PHASE_2_STATUS.md`, `Spikes/Phase2Transport/`

## Phase 3 — Device Parity

- **Status:** In progress. Built; physical acceptance pending.
- Goal: make the iPhone the Codex Micro — six agent keys, command keys, reasoning dial, joystick, push-to-talk, remapping, and parity acceptance.
- Plan: `docs/ROADMAP.md`

## Phase 4+ — Future

- Phone approval execution with device-bound user-presence assertions.
- Tailscale/private remote access.
- Product relay, APNs, accounts, internet discovery.
- Multi-model harness (Claude, Ollama, etc.).
- App Store/TestFlight distribution.
