# Security

Codex Micro opens an untrusted LAN boundary between a paired iPhone and a Mac running Codex. This page summarizes the security model. The full evidence lives in the reference documents.

## Primary claim

> An untrusted LAN peer receives no application metadata before authentication. An authenticated device receives and can mutate only data authorized by the Mac's current persisted grant. Network code cannot bypass the centralized command gateway, and authorization or storage failure never broadens access.

## Key mechanisms

| Mechanism | How it works |
|---|---|
| Pairing | QR carries a five-minute single-use 256-bit secret. Pinned TLS + mutual long-term signatures + transcript-bound six-word SAS. Both users confirm locally. |
| Session | Fresh P-256 ECDH per connection, signed transcript, separate directional AEAD keys, exactly-next per-direction counters. |
| Identity | Mac host-identity and TLS keys are Secure Enclave P-256 keys. No software fallback. Reinstall = new identity = re-pair. |
| Grant authority | Single Keychain-resident canonical blob. Atomic whole-blob replacement, anti-rollback generation, fail-closed disable of LAN on any corruption. |
| Command gateway | Every mutation passes session, grant, schema, and ledger checks. `(deviceID, commandID)` identity and semantic digest prevent replay and collision. |
| Revocation | Linearizable: persist new revision, publish to checks, purge unauthorized queues, close or reauthenticate affected connections. |
| Logging | Application logs contain only closed reason codes and counts; never URLs, IPs, IDs, prompts, paths, diffs, or approval details. |

## Non-goals

- Public relay, tailnet/proxy, APNs, accounts, internet discovery.
- Phone approval resolution in v1 (Phase 4 scope).
- Attachments, file transfer, screenshots, audio, offline cache.
- Raw Codex RPC, shell, process, filesystem, or arbitrary MCP access from the phone.
- Multi-user/team authorization.
- Protection from compromised kernel/root/signed-in user/trusted Codex binary.
- Hiding service presence, IP, timing, or packet size from the LAN.

## Fail-closed matrix

| Condition | Behavior |
|---|---|
| LAN disabled or fresh install | No listener, no Bonjour. |
| Missing/corrupt grant authority | LAN disabled; no pairing/auth/commands. |
| Host/TLS identity loss while grants exist | LAN disabled; explicit reset + re-pair required. |
| Unsupported Codex or ledger failure | No new state-changing commands. |
| Scope reduction / revocation | Purge queued data, advance view epoch, close/reauthenticate affected sessions. |
| Crash-ambiguous command | `outcomeUnknown`; never auto-resend. |

## References

- [Threat model](reference/THREAT_MODEL.md)
- [Transport ADR](reference/TRANSPORT_ADR.md)
- [Git workflow](GIT_WORKFLOW.md)
