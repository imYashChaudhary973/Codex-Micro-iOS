# Phase 2 Transport Feasibility Spike — Stage 1: Identity

Isolated, test-only Swift package. It imports no production Codex Micro target and exposes no pairing, grant, session, command, approval, Codex, network, or user-data path.

This is the first of three stacked evidence PRs:

1. **This PR** — non-exportable Secure Enclave identity, content-neutral certificates, same-key renewal SPKI continuity, and canonical host-signed rotation statements.
2. Interface policy plus the hardened NIOTS TLS 1.3 WebSocket listener and pinned client.
3. Signed probe app, provisioning scripts, Keychain/Bonjour/LAN runs, and the full sanitized evidence report (`EVIDENCE.md`).

## Key findings in this stage

- **Software Data Protection Keychain keys are exportable.** `kSecAttrIsSensitive`/`kSecAttrIsExtractable: false` do not stop `SecKeyCopyExternalRepresentation` for a software key held by the creating process. The non-exportable Mac identity therefore requires a **Secure Enclave** P-256 key (`kSecAttrTokenIDSecureEnclave`, `privateKeyUsage` access control, `AfterFirstUnlockThisDeviceOnly`, Data Protection Keychain). Macs without a Secure Enclave fail closed.
- `swift-certificates` signs content-neutral self-signed certificates directly through the non-exportable `SecKey`; `SecCertificate`/`SecIdentity` construction and SPKI equality checks pass.
- Same-key renewal preserves the SPKI; a new key changes it.
- Rotation statements are canonically encoded, role-separated (`.host` signs, `.tls` serves), bound to the expected current SPKI and the presented next SPKI, and covered by a fixed 97-byte canonical fixture with mutation, wrong-role, wrong-pin, rollback, expiry, and signature-tamper tests.
- Creation uses an atomic claim; post-create validation rolls back on failure; cleanup verifies absence and aggregates errors.

The persistent Data Protection Keychain test is explicitly skipped in an unsigned SwiftPM host (`errSecMissingEntitlement`). The positive signed proof runs with the stage-3 probe app.

## Verification

```sh
swift package resolve --package-path Spikes/Phase2Transport
swift build --package-path Spikes/Phase2Transport
swift test --package-path Spikes/Phase2Transport
swift build --package-path Spikes/Phase2Transport -c release
swift format lint --strict --recursive \
  Spikes/Phase2Transport/Sources \
  Spikes/Phase2Transport/Tests \
  Spikes/Phase2Transport/Package.swift
```

Pinned dependency: `apple/swift-certificates` 1.19.4 (transitives: `swift-crypto` 4.5.1, `swift-asn1` 1.7.1). Never commit keys, certificates, Keychain exports, raw logs, addresses, or identity material.
