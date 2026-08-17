# Architecture

Codex Micro is a native iPhone app that controls Codex running on a paired Mac. The Mac stays authoritative for repositories, credentials, tool execution, and policy. The phone never holds the OpenAI credential and never runs tools itself.

## System view

```text
┌──────────────────────┐   WSS + AEAD-sealed frames   ┌────────────────────────┐
│ iPhone companion     │◀──────────────────────────────▶│ Mac bridge (menu-bar)  │
│ SwiftUI + Keychain │      direct same-LAN only      │ Swift + Keychain       │
└──────────────────────┘                                └───────────┬────────────┘
                                                                    │ stdio JSON-RPC
                                                                    │ localhost only
                                                        ┌───────────▼────────────┐
                                                        │ codex app-server       │
                                                        │ auth, threads, tools,  │
                                                        │ approvals, persistence │
                                                        └───────────┬────────────┘
                                                                    │
                                                        ┌───────────▼────────────┐
                                                        │ Mac repos and tools    │
                                                        └────────────────────────┘
```

## Design principles

1. **Mac authoritative** — repositories, credentials, Codex config, tools, skills, execution stay on the Mac.
2. **Phone controlled** — every command maps to an allowlisted capability and an independently enforced mobile action ceiling.
3. **Least privilege** — `observe`, `respond`, `runAgent`, `approve`, `interrupt`, and `startThread` are granted separately.
4. **Fail closed** — missing identity, unknown fields, bad sequence numbers, stale grants, unsupported Codex versions cannot trigger actions.
5. **Idempotent controls** — state-changing requests carry a unique command ID; known results replay safely; crash-ambiguous work becomes `outcomeUnknown` and is never retried automatically.
6. **Local first** — LAN operation works without a product backend.

## Package targets

| Target | Responsibility |
|---|---|
| `CompanionProtocol` | Strict wire schemas, reason enums, version negotiation, replay cursor. Data only: no keys, storage, sockets, or executors. |
| `CompanionCrypto` | Canonical encodings, P-256/ECDH/HKDF/AEAD primitives, SPKI fingerprints, SAS derivation, rotation-statement verification. No Keychain or socket code. |
| `MacBridgeCore` | Authoritative grants, revocation, policy, per-device authorized-view sequencing, filtered snapshots/replay, command gateway, durable ledger, Codex runtime/executors. |
| `MacBridgeServer` | Mac host/TLS Secure Enclave adapters, certificate lifecycle, TLS/WSS listener, connection actors, session registry, interface policy, resource limits, Bonjour. |
| `CodexMicroBridge` | Menu-bar app shell: LAN enablement, pairing/SAS confirmation, grant administration, redacted diagnostics. |
| `CodexAppServer` | `codex app-server --stdio` JSON-RPC transport and client. |
| `CodexMicroSpike` | Development feasibility probes and diagnostics. |
| `CodexTestSupport` | Deterministic fake app-server and fixtures for tests. |

## Trust boundaries

1. Mac user action → LAN enablement, pairing confirmation, grant administration.
2. iOS app/Secure Enclave → untrusted LAN.
3. Unauthenticated TCP/TLS/WSS peer → pairing or session state machine.
4. Authenticated session → current Mac grant authority.
5. `MacBridgeServer` → `MacBridgeCore` filtered-data and command-gateway APIs.
6. Command gateway → durable ledger → typed Codex executor.
7. Codex/repository/model content → normalized domain state, phone renderer, and logs.

## Security references

- [Threat model](reference/THREAT_MODEL.md)
- [Transport ADR](reference/TRANSPORT_ADR.md)
