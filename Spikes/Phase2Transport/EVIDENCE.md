# Phase 2 Transport Spike — Sanitized Evidence

**Snapshot:** 2026-08-01

This file contains only tool versions, dependency versions, closed outcomes, counts, and evidence classifications. It intentionally excludes raw logs, real addresses, interface names, host/device/account names, signing-certificate names, certificate bytes, public-key fingerprints, private keys, Keychain exports, provisioning profiles, frame bytes, and user data.

## Environment

```text
Swift: 6.4 (swiftlang-6.4.0.27.1, clang-2100.3.27.1)
Xcode: 27.0 (27A5228h)
macOS: 27.0 (26A5388g)
Architecture: Apple silicon
Development signing identity available: yes
Matching Data Protection Keychain provisioning context proven: yes
```

The user explicitly authorized Xcode automatic provisioning for the fixed test bundle identifier. Automatic provisioning registered this Mac and produced a wildcard macOS development team profile whose entitlements cover the probe's exact application identifier and Keychain access group.

## Dependency resolution

`swift package resolve --package-path Spikes/Phase2Transport`

```text
result: passed
repositories resolved: 8
unauthorized repositories resolved: 0
```

Resolved pins:

```text
swift-nio 2.101.3
swift-nio-transport-services 1.28.0
swift-certificates 1.19.4
swift-atomics 1.3.1
swift-collections 1.6.0
swift-system 1.7.5
swift-crypto 4.5.1
swift-asn1 1.7.1
```

## Deterministic and loopback verification

Latest completed debug suite:

```text
command: swift test --package-path Spikes/Phase2Transport
result: passed
reported tests: 31 (1 additional conditional test explicitly skipped)
reported failures: 0
runtime NIOTS TLS/WSS listener left running: no
```

Covered behavior includes:

- Explicit interface allow/deny policy and no wildcard fallback.
- Listener lifecycle prerequisite failure and reauthentication generation.
- Closed-code/count-only application logger API.
- Static content-neutral Bonjour descriptor/TXT allowlist.
- Exact HTTP method/path/query/version/header/Origin/subprotocol policy.
- Header count/byte limits, duplicate rejection, and extension rules.
- Explicit decline of URLSession's fixed compression offer.
- Binary-only frames, reserved-bit rejection, message bounds, fragmentation bounds, and connection lease release.
- Non-exportable ephemeral P-256 `SecKey` signing.
- `swift-certificates` self-signed certificate, signature verification, `SecCertificate`, and `SecIdentity` construction.
- Same-key certificate renewal SPKI continuity and new-key SPKI change.
- Canonical host-signed rotation statement, validity, rollback, and signature rejection.
- Real NIOTS + Network.framework TLS 1.3-only loopback WSS exchange.
- Correct SPKI pin acceptance, pin mismatch rejection, and invalid query rejection through `URLSessionWebSocketTask`.
- Listener and accepted-child teardown after positive and negative runtime cases.

The Data Protection Keychain persistence test is conditional. In the ordinary SwiftPM test host, Security returned `errSecMissingEntitlement`; that test body produced no positive persistent-Keychain evidence. The 19/0 test result must not be interpreted as proving that unavailable signed-Keychain row.

Latest strict formatting check:

```text
command: swift format lint --strict --recursive <spike Swift paths>
result: passed
```

Latest release build:

```text
command: swift build --package-path Spikes/Phase2Transport -c release
result: passed
```

## Development-signed probe

Generated app location is ignored under `.build`.

```text
bundle identifier: fixed test-only identifier
Info.plist local-network purpose string: present
Info.plist Bonjour service allowlist: present
codesign development signature: passed
codesign strict verification: passed
committed signed binary/profile: no
```

Signed interface inventory:

```text
code=interface_eligible count=1
code=probe_completed count=1
```

This proves only that the signed probe launched and found one policy-eligible private Wi-Fi/Ethernet binding. No interface name or address was recorded.

## Data Protection Keychain probe

### Decisive negative finding: software keys are exportable

The first provisioned run created software P-256 keys in the Data Protection Keychain with `kSecAttrIsSensitive`/`kSecAttrIsExtractable: false`. The probe's own assertion then **succeeded in exporting the private key**: those attributes do not prevent `SecKeyCopyExternalRepresentation` for a software key held by the creating process. The proof run failed closed and cleaned up.

Consequence for the transport ADR: a non-exportable Mac identity requires a **Secure Enclave** private key (`kSecAttrTokenIDSecureEnclave`); a software Data Protection Keychain key cannot satisfy the non-exportability invariant. The store was changed to Secure Enclave keys with `privateKeyUsage` access control and `AfterFirstUnlockThisDeviceOnly` accessibility.

### Positive Secure Enclave proof

The provisioned, development-signed probe then completed the full proof. Each step is a separate process launch:

```text
create Secure Enclave host/tls keys (export assertion enforced): pass
separate-process retrieval and same-SPKI check: pass
private export failure on retrieved key: pass
mismatch fail-closed on retrieved key: pass
certificate/renewal/rotation probe from retrieved keys: pass
deterministic verified Keychain deletion: pass
code=keychain_proof_complete count=1
```

An unsigned SwiftPM test host still receives `errSecMissingEntitlement`; the conditional test remains explicitly skipped there and the suite result must not be read as covering that row outside the entitled probe.

## Signed LAN and Bonjour run

An earlier basic-signed run reached listener readiness but timed out during Bonjour registration and failed closed; its cause was never isolated. After automatic provisioning, the publish-symlink fix, and the Bonjour waiter race fixes, the explicit signed LAN probe passed once on this machine with content-neutral payloads only:

```text
code=listener_ready count=1
code=listener_stopped count=1
code=probe_completed count=1
```

Interpretation:

- An eligible private-interface TLS 1.3 listener reached readiness with a Secure Enclave-backed ephemeral identity.
- Bonjour registration was requested only after readiness and reported success before any client exchange.
- A pinned `URLSessionWebSocketTask` client completed the exact binary echo exchange against the advertised endpoint.
- Teardown verified terminated phase, zero active children, and event-loop-group shutdown, with the advertisement removed.
- This is one successful signed-Mac observation on one LAN; it is not stability, multi-network, or physical-iPhone evidence.

Post-run cleanup checks:

```text
probe process remaining: no
Swift test process remaining: no
proof digest file remaining: no
persistent service configured: no
router/system network setting changed: no
```

## Application and system logging inventory

| Surface | Application-provided values | Evidence/constraint |
|---|---|---|
| `ConsoleClosedCodeLogger` / `OSClosedCodeLogger` | Closed enum code and integer count only | API accepts no free-form string |
| Upgrade rejection | Closed `WebSocketUpgradeRejection` enum | No header values or endpoint included |
| Keychain failures | Generic probe result code | OSStatus is not printed by the probe |
| Certificate/SPKI | No application log path | Certificate bytes and digests never printed |
| NIOTS / Network.framework | Static TLS/options configuration | Framework diagnostics not enabled; OS may independently retain network metadata |
| URLSession / CFNetwork | Static Origin/subprotocol and content-neutral bytes | Framework diagnostics not enabled; raw errors are not printed by the probe |
| Bonjour / mDNSResponder | Static service name/type/domain/TXT only | No user, host, device, project, interface, or fingerprint field supplied |
| SwiftPM/build/codesign | Tool-generated console output | Raw build/signing logs are not committed as evidence |

Sentinel-oriented tests place sentinel values in rejected query, Origin, subprotocol, unknown header, extension, and oversized-header paths. Assertions inspect only closed rejection values. No application logger can receive the sentinel text.

## Evidence classification

| Evidence | Classification | Acceptance meaning |
|---|---|---|
| Upstream checkout API inspection | Source/API feasibility | Not runtime proof |
| Swift compilation and deterministic tests | Mac source/contract evidence | Not signed-Keychain or physical-LAN proof |
| NIOTS TLS/WSS loopback | Real local runtime evidence | Not LAN/Bonjour/device evidence |
| Software-key export success | Decisive negative security observation | Rules out software DP-Keychain keys for the non-exportable identity |
| Secure Enclave create/retrieve/export-denied/mismatch/cleanup | Positive provisioned signed-Mac proof | Mac-only; not iPhone Secure Enclave evidence |
| Signed LAN listener + Bonjour + pinned exchange + teardown | One positive signed-Mac LAN observation | Not stability, multi-network, or device evidence |
| Physical iPhone/Wi-Fi run | Not performed | No Phase 2 acceptance claim |

## Future sanitized run template

Record only the following fields after an authorized rerun:

```text
candidate commit: <sha only>
toolchain tuple matched: yes/no
resolved pin set matched: yes/no
debug tests: <passed count>/<failed count>
release build: pass/fail
strict format lint: pass/fail
signed bundle verification: pass/fail
Data Protection Keychain create/retrieve/export-denied/mismatch/cleanup: pass/fail per row
certificate renewal/new-key/rotation: pass/fail per row
TLS/WSS positive/pin-negative/policy-negative: pass/fail per row
eligible LAN listener ready: yes/no
Bonjour registration callback: add/not-observed
pinned LAN exchange: pass/not-run
listener/children/advertisement cleanup: pass/fail
remaining Keychain items in spike namespace: 0/nonzero
physical device evidence: not-run/pass/fail
```

Never paste raw command output into this file when it contains local paths, identities, interface data, addresses, certificate material, fingerprints, profiles, or framework diagnostics.
