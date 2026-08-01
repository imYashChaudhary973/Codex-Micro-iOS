# ADR — Phase 2 Local Transport and TLS Stack

**Status:** Accepted

**Date:** 2026-08-02

## 1. Context and scope

Phase 2 opens Codex Micro's first untrusted network boundary: a direct same-LAN TLS/WSS listener on the Mac bridge, paired-device authentication, and AEAD-sealed application frames. [The threat model](THREAT_MODEL.md) requires that the selected stack prove a non-exportable host/TLS key lifecycle, exact TLS and WebSocket policy control, and content-neutral discovery before any production dependency or listener code lands.

This ADR records the accepted transport, TLS, identity, certificate, interface, HTTP/WebSocket, grant-storage, canonical-encoding, discovery-metadata, and logging decisions for Phase 2. Its evidence base is the transport feasibility spike merged to `main` as three stacked evidence PRs — identity/certificates (`a445f81`, #8), hardened NIOTS TLS/WSS transport (`531d972`, #9), and the signed probe with Keychain/Bonjour/LAN evidence (`c6577b7`, #10) — with the sanitized results in `Spikes/Phase2Transport/EVIDENCE.md` and the implementation findings in `Spikes/Phase2Transport/README.md`. The positive signed-Mac proof was re-run from the merged `c6577b7` tree.

Evidence classification is strict throughout: everything below is signed-Mac, loopback, or one-LAN observation evidence. Nothing in this ADR is stability, multi-network, or physical-iPhone proof; those remain Step 2.14 scope.

## 2. Decision drivers

1. **Non-exportable identity is non-negotiable.** The threat model forbids any stack whose server identity requires an exportable private key. The stack must sign TLS handshakes and certificates through a Keychain `SecKey` whose private bytes the bridge process itself cannot read.
2. **Complete TLS policy control.** TLS 1.3 only, one cipher suite, and no tickets, resumption, 0-RTT, False Start, fallback, fast-open, peer-to-peer, or multipath — all expressible through public API, not defaults.
3. **Exact HTTP/WebSocket upgrade control.** Method, path, query, headers, Origin, subprotocol, compression, frame types, and size bounds must be enforceable byte-for-byte before authentication.
4. **Fail-closed lifecycle.** Listener startup, Bonjour publication, interface loss, and teardown must map onto explicit one-shot state transitions with verified cleanup.
5. **Content-neutral surface.** Certificates, Bonjour records, QR payloads, and logs must carry no host, device, user, or project data.
6. **Minimal, pinned, auditable dependencies.** Every resolved repository is explicitly authorized and version-pinned; adoption of unpinned or drifting versions is a stop condition.

## 3. Options evaluated

| Option | Verdict | Rejection reason |
|---|---|---|
| Pure Network.framework WebSocket (`NWProtocolWebSocket`) | **Rejected** | No public control over the HTTP upgrade request line or pre-upgrade headers: method, exact path, query rejection, header count/size limits, and header-name allowlisting cannot be enforced before the upgrade completes. The threat model requires exact pre-authentication HTTP policy. |
| SwiftNIO + NIOSSL (the original architecture recommendation) | **Rejected** | NIOSSL exposes no public server-side control over session tickets and resumption under our policy (tickets/resumption must be provably disabled, not merely unused). It would also require managing raw key material outside the Keychain boundary for the server identity path we require. |
| Custom TCP framing (no WebSocket) | **Rejected** | A bespoke length-prefixed parser replaces a widely reviewed protocol with new hand-written parser attack surface at the most exposed pre-authentication boundary, for no capability we need. |
| Software Data Protection Keychain keys for the server identity | **Rejected outright** | Decisively disproven by the spike: `kSecAttrIsSensitive`/`kSecAttrIsExtractable: false` do **not** prevent `SecKeyCopyExternalRepresentation` for a software key held by the creating process. The probe exported its own "non-exportable" software key and failed closed. Software keys cannot satisfy the non-exportability invariant. |
| **NIO Transport Services listener over Network.framework TLS + NIOHTTP1/NIOWebSocket + swift-certificates + Secure Enclave keys** | **Accepted** | Proven end-to-end on a signed Mac: Secure Enclave identity, TLS 1.3-only policy, exact upgrade enforcement, pinned client exchange, Bonjour lifecycle, and verified teardown. Details in §4. |

## 4. Decision

Phase 2 adopts a hybrid stack:

- **Listener:** NIO Transport Services (`NIOTSListenerBootstrap`) over Network.framework TLS, with the server identity supplied as a `SecIdentity` assembled from the Secure Enclave TLS key and a swift-certificates certificate.
- **HTTP/WebSocket:** `NIOHTTP1` + `NIOWebSocket` channel handlers for exact upgrade-request and frame policy enforcement (§9).
- **Certificates:** `swift-certificates` signing through the non-exportable `SecKey` via the public `Certificate.PrivateKey.init(_ secKey:)` path (§7).
- **Client (acceptance/loopback/iOS):** `URLSessionWebSocketTask` with an SPKI-pinning trust override that surfaces an exact `.pinMismatch` result rather than a generic URLSession error. The client performs no CA or system trust evaluation; trust is exactly the pinned SPKI from pairing or a verified rotation statement. This trust-override design is accepted for production.
- **Identity:** all long-term private keys are Secure Enclave P-256 keys (§6). Machines without a Secure Enclave fail closed; there is no software-key fallback.

### Dependency pins

Exactly these user-authorized pins, as resolved in the spike's `Package.resolved`:

| Repository | Pin | Kind |
|---|---|---|
| `apple/swift-nio` | 2.101.3 | direct |
| `apple/swift-nio-transport-services` | 1.28.0 | direct |
| `apple/swift-certificates` | 1.19.4 | direct |
| `apple/swift-atomics` | 1.3.1 | transitive |
| `apple/swift-collections` | 1.6.0 | transitive |
| `apple/swift-system` | 1.7.5 | transitive |
| `apple/swift-crypto` | 4.5.1 | transitive |
| `apple/swift-asn1` | 1.7.1 | transitive |

No other repository may be declared or resolved. Swift tools 6.2+ is required. The toolchain evidence tuple is Swift 6.4 (swiftlang-6.4.0.27.1), Xcode 27.0 (27A5228h), macOS 27.0 (26A5388g).

### Adoption point

Production adoption occurs in **Step 2.4a** (identity/certificate adapters) and **Step 2.7** (listener). Both must use these exact pins. Any pin or toolchain change before or during adoption invalidates the corresponding feasibility rows in `Spikes/Phase2Transport/EVIDENCE.md`; the affected rows must be re-proven on the new versions before the changed dependency merges.

## 5. TLS policy

| Property | Policy | Evidence class |
|---|---|---|
| Protocol version | TLS 1.3 only (minimum and maximum) | Proven, loopback + signed LAN |
| Cipher suite | `AES_128_GCM_SHA256` only (the public Network.framework constant) | Proven |
| Session tickets | Disabled | Proven configuration |
| Resumption / PSK | Disabled | Proven configuration |
| 0-RTT / early data | Prohibited; no early-data path exists with resumption disabled | By construction |
| False Start | Disabled | Proven configuration |
| Fallback mode | Disabled | Proven configuration |
| TCP / Network.framework Fast Open | Disabled | Proven configuration |
| Peer-to-peer (AWDL) | Disabled | Proven configuration |
| Multipath | Disabled | Proven configuration |
| Renegotiation | Not applicable in TLS 1.3 | — |
| Server identity | `SecIdentity` from the Secure Enclave TLS key + swift-certificates certificate | Proven, signed Mac |
| Client trust | SPKI pinning only; no CA/system evaluation; exact `.pinMismatch` surfaced | Proven, loopback + signed LAN |

Because tickets and resumption are disabled, no stack-managed ticket/PSK state exists to inventory; TLS handshake ephemerals and IVs remain Network.framework-internal and are covered by the logging inventory in §13.

## 6. Identity and Keychain lifecycle

The decisive spike finding: a non-exportable identity **requires** a Secure Enclave key. Software Data Protection Keychain keys are exportable by the creating process regardless of `kSecAttrIsSensitive`/`kSecAttrIsExtractable` (§3) and are rejected outright.

| Key | Store and attributes | Lifecycle |
|---|---|---|
| Mac host-identity signing key (role `.host`) | Secure Enclave P-256 (`kSecAttrTokenIDSecureEnclave`), Data Protection Keychain, `privateKeyUsage`-only access control, `AfterFirstUnlockThisDeviceOnly`, ThisDeviceOnly — never synced or backed up | Persistent. Never silently regenerated. Loss, corruption, duplication, or SPKI mismatch while grants exist disables LAN and requires explicit reset plus re-pairing. |
| Mac TLS key (role `.tls`) | Same attribute profile; separate key, separate role claim | Persistent. Certificate renewal keeps the same key (§7). Key rotation only through host-signed anti-rollback statements (§7). Same fail-closed rules as the host key. |
| iPhone device-signing key | **Provisional:** Secure Enclave on iOS with the same attribute profile | Required, not optional. Provisional until Step 2.14 proves creation, retrieval, export denial, and reinstall behavior on a physical signed iPhone. Reinstall creates a new identity and requires re-pairing. |

Common rules, each proven on the signed Mac from the merged `c6577b7` tree unless marked provisional:

- **Export denial:** the creating process cannot export the private key; retrieval validates non-exportability and the expected SPKI, and a mismatch fails closed (proven: create / separate-process retrieve / export-denied / mismatch-fail-closed / verified cleanup).
- **Atomic creation:** creation first acquires an atomic claim; post-create validation requires exactly one claim and one matching key, with rollback on failure. Missing claims, incomplete creation, multiplicity, wrong attributes, or exportable keys fail retrieval closed.
- **No Secure Enclave, no LAN:** Macs (and iPhones) without a Secure Enclave fail closed. There is no software fallback.
- **Reinstall = new identity:** reinstalling either app creates a new identity and requires re-pairing; there is no identity backup, sync, or migration.
- **No biometric prompt on normal reconnect:** the access control is `privateKeyUsage` only, with no user-presence or biometry constraint, so routine session authentication never prompts. User approval lives at pairing/grant administration, not per-connection.
- **No silent regeneration:** no code path may create a replacement long-term key while grants exist.

## 7. Certificate profile and rotation

### Certificate profile

| Field | Policy |
|---|---|
| Public key / signature | ECDSA P-256, SHA-256 |
| Subject / SAN | Fixed, static, content-neutral values; no host, device, user, or project data |
| Key usage | `digitalSignature` |
| Extended key usage | `serverAuth` |
| Serial | Random, non-identifying |
| Validity | 30 days, chosen conservatively; renewal with the **same key** at two-thirds lifetime (about day 20) |
| Client behavior | Clients pin the **SPKI**, never certificate bytes, so same-key renewal is transparent (proven: same-key renewal preserves SPKI; a new key changes it) |

Certificates are created against a `.tls` identity; rotation statements are signed and verified against `.host` (role separation proven by wrong-role rejection tests).

### Two-phase TLS key rotation

1. **Delivery before activation:** the bridge signs a canonical rotation statement (§11) with the host identity and delivers it over an existing authenticated session **before** the new TLS key is presented. The statement binds the expected current SPKI, the actually presented next-certificate SPKI, a strictly increasing rotation generation, and a validity window.
2. **Activation with anti-rollback:** clients accept the new SPKI only after exact statement verification; both sides persist the rotation generation monotonically. Rollback, expiry, wrong current/next pin, wrong role, field mutation, and signature mutation are rejected (proven by canonical-fixture mutation tests, including the fixed 97-byte fixture).

Devices offline through the delivery window that can no longer verify against the old key must re-pair. There is no silent repin.

## 8. Direct-LAN interface and address policy

As proven by the spike's interface containment and signed LAN run:

- **Eligible:** private IPv4 or IPv6 ULA addresses on Wi-Fi or Ethernet interfaces only.
- **Rejected:** hostnames, wildcard/unspecified, public, multicast, IPv4/IPv6 link-local, and loopback addresses (loopback has one explicit test-only factory). VPN/tunnel, cellular, peer-to-peer, and all other interface types are denied.
- **Unforgeable validation:** `InterfaceBinding` has no public arbitrary initializer; production bindings come only from discovery, and both binding creation and server startup independently revalidate a numeric address on an active allowed interface.
- **Bind discipline:** NIOTS binds a pre-parsed `SocketAddress`, verifies the bound local address matches, requires the corresponding Network.framework interface type, and has no DNS or wildcard fallback.
- **Path changes:** interface loss or path change closes all sessions and terminates the listener. Because the listener is one-shot (§14), recreation is a fresh listener lifecycle, and every device performs full reauthentication; no session survives an interface transition.
- **Deferred:** exact live `NWInterface` object pinning is not implemented in the spike (exact local address plus required interface type is enforced instead); it is a Step 2.7 obligation (§16).

## 9. HTTP and WebSocket policy

### Proven exact constants

| Constant | Value |
|---|---|
| HTTP version / method | HTTP/1.1 `GET` only |
| Upgrade path | Single fixed path; any query string rejected |
| Origin | Exact single value |
| Subprotocol | Exact single value |
| WebSocket version | 13, valid key required |
| Required headers | Single occurrence each; header-name allowlist; duplicates rejected |
| Header field count | 16 maximum |
| Header total size | 8 KiB maximum |
| Single header field | 4 KiB maximum |
| Compression | Never negotiated. `URLSessionWebSocketTask` offers `permessage-deflate` without a public suppression switch; the server permits exactly that offer, omits it from the response, and rejects RSV bits |
| Frame types | Binary application frames only |
| Frame cap | 16 KiB |
| Message cap | 64 KiB |
| Fragments per message | 8 maximum |

Adversarial coverage merged with the spike includes unexpected continuation, new messages during fragmentation, tiny fragments, fragment-count and aggregate-size overflow, reserved bits on fragments, and control-frame interleaving.

### ADR ceilings for Step 2.7

The spike implemented **no** rate limiting, idle expiry, or ping/pong policy. The following values are fixed here as ADR ceilings; Step 2.7 must enforce them (it may tighten but never exceed them without a superseding ADR) and must test them adversarially:

| Ceiling | Value |
|---|---|
| TLS + HTTP upgrade completion deadline | 10 s from TCP accept |
| Authentication handshake deadline | 20 s from upgrade completion |
| Concurrent connections (global) | 16, enforced by an app-level limiter (NIOTS has no native connection cap) |
| Concurrent unauthenticated connections | 4 |
| Per-source new connections | 6 per minute |
| Per-source pairing attempts | 3 per minute |
| Per-connection inbound message rate | 32 messages per second |
| Per-connection inbound byte rate | 1 MiB per second |
| Outbound queue bound | 64 frames or 256 KiB per connection; exceeding the bound or remaining non-writable longer than 10 s closes the connection (Step 2.8 may substitute a filtered-snapshot fallback above the transport layer) |
| Server ping cadence / pong deadline | 30 s cadence; 10 s matching-pong deadline |
| Post-upgrade application idle expiry | 120 s without a valid application frame |

## 10. Grant-authority storage

Device-grant authority is stored as a **single versioned, bounded canonical authority blob** — 64 KiB encoded maximum — in the device-only Data Protection Keychain (`AfterFirstUnlockThisDeviceOnly`, ThisDeviceOnly, never synced or backed up), accessed through exactly one storage actor.

- **Atomic whole-blob replacement:** every authority mutation (grant, revision, revocation tombstone, authorized-view epoch, host generation) rewrites the entire blob in one Keychain item update, so authority state can never be observed partially written. This is the storage substrate for linearizable revocation.
- **Anti-rollback:** the blob carries its own monotonic write generation; a generation regression is rollback and fails closed.
- **Fail closed:** a missing, duplicate, undecodable, oversized, or rolled-back blob disables LAN — no pairing, authentication, observation, or commands.
- **No separate encryption key:** because the blob is Keychain-resident, no file-backed grant store and no grant-store encryption key exist. The corresponding threat-model inventory row is resolved as not applicable.

Encoding follows the canonical contract in §11.

## 11. Canonical encoding contract

All security statements — pairing transcripts, session transcripts, rotation statements, the authority blob, and sealed frame headers — use one canonical encoding contract:

- **Versioned:** every encoding begins with a fixed version and an ASCII domain-separator context string unique to the statement type. No two statement types share a context.
- **Length-delimited, big-endian:** every variable-length field is prefixed with a fixed-width big-endian length; there is no delimiter-based or concatenation-ambiguous encoding.
- **Fixed-width counters:** counters and generations are fixed-width big-endian `UInt64`; epochs are 128-bit. Overflow fails closed before wrapping.
- **Signatures:** raw 64-byte `r||s` P-256 signatures; no DER wrapping.
- **AEAD nonces:** deterministic 96-bit nonces — a 4-byte direction/domain prefix concatenated with the 8-byte big-endian frame counter — injective per key because every direction uses a fresh key and counters never wrap.
- **Exactly-next counters:** a receiver accepts exactly the next counter for the opposite direction; any duplicate, gap, wrong direction, or overflow closes the session.
- **Header as AAD:** the complete clear frame header is authenticated as additional data.
- **Pairing/session nonces:** exactly 256 random bits each, attempt-local, transcript-bound.

Final byte layouts and golden vectors are **Step 2.2** (wire contracts) and **Step 2.3** (crypto primitives) deliverables, bound by this contract. The spike's fixed 97-byte rotation fixture and its field-mutation suite demonstrate the pattern; the production layouts supersede it under the same rules.

## 12. Bonjour, QR, and certificate metadata allowlists

All three surfaces are content-neutral, exact allowlists. Nothing outside the allowlist may be published, encoded, or logged.

| Surface | Allowlisted content | Excluded |
|---|---|---|
| Bonjour | Static allowlisted service-instance name, service type, domain, and TXT keys; published only after listener readiness; removal after success terminates the server | Host/device/user names, identifiers, fingerprints, interface data, project data, secrets |
| QR payload | `version`, exact protocol/feature set, opaque `hostId`, normalized direct-LAN endpoint origin, host-identity fingerprint, **current TLS SPKI fingerprint**, `pairingSessionId`, 256-bit one-time secret, `expiresAt` | **No `hostName`** or any display name; no device/user/project data. The phone verifies the host through the signed pairing transcript and shows a display name only from the authenticated exchange, never from the QR |
| Certificate | Fixed static subject/SAN per §7 | Any host/device/user/project value |

**macOS 15+ local-network privacy:** Bonjour publication and LAN listening require a signed app carrying `NSLocalNetworkUsageDescription` and an `NSBonjourServices` allowlist (proven by the signed probe). The production Mac app must carry both; this is a Step 2.13 obligation.

## 13. System-library logging inventory and accepted residual metadata

Application log APIs accept only a closed code enum and nonnegative integer counts; no free-form error, endpoint, name, path, certificate, fingerprint, frame, or payload can reach the application logger (sentinel-verified). The system-library inventory from the spike evidence:

| Surface | Application-provided values | Constraint |
|---|---|---|
| Closed-code loggers | Closed enum code and integer count only | API accepts no free-form string |
| Upgrade rejection | Closed rejection enum | No header values or endpoints included |
| Keychain failures | Generic probe/result code | OSStatus not printed by the application |
| Certificate/SPKI | No application log path | Certificate bytes and digests never printed |
| NIOTS / Network.framework | Static TLS/options configuration | Framework diagnostics not enabled; the OS may independently retain network metadata |
| URLSession / CFNetwork | Static Origin/subprotocol and content-neutral bytes | Framework diagnostics not enabled; raw errors not printed |
| Bonjour / mDNSResponder | Static service name/type/domain/TXT only | No user, host, device, project, interface, or fingerprint field supplied |
| Build/codesign tooling | Tool-generated console output | Raw build/signing logs are never committed as evidence |

**Accepted residual metadata:** the OS may independently retain network metadata (mDNS caches, connection records), and the LAN necessarily observes service presence, IP addresses, port, packet timing, and ciphertext sizes. These residuals are accepted by the threat model and are not treated as leaks.

## 14. Fail-closed transition mapping

The listener is an actor backed by an explicit **one-shot** state machine — `idle → starting → running → publishing → stopping → terminated` — with no restart after stop or partial startup failure. Proven transitions:

| Condition | Transport response |
|---|---|
| No Secure Enclave, or Secure Enclave key creation/validation fails | LAN unavailable; fail closed |
| Identity missing/duplicate/exportable/SPKI-mismatched | Fail closed; never regenerate while grants exist |
| Grant-authority blob missing/duplicate/undecodable/rolled back | LAN disabled (§10) |
| Invalid bind, concurrent start, start/stop race, duplicate stop | Fail closed or join teardown; no partial listener |
| Interface loss or path change | Close sessions, terminate listener; recreation is a new lifecycle with full reauthentication (§8) |
| Bonjour publication failure after readiness | Roll back advertisement and stop the listener |
| Bonjour removal after successful publication | Server termination |
| Child connection arriving after stopping begins | Rejected and closed by the child registry (NIOTS does not cascade listener close to children; teardown is registry-based) |
| Upgrade policy violation | Closed rejection code; connection closed |
| Frame policy violation | Connection closed |
| Generation/counter overflow | Fail closed before wrap |
| Teardown | Attempts publication removal, every tracked child close, server close, and event-loop-group shutdown even if an earlier step fails; verified terminated phase, zero children, group shutdown |

## 15. Consequences

**Gained:**

- A proven non-exportable server identity: the private key physically cannot leave the Secure Enclave, and the export-denial property is asserted at every retrieval.
- One TLS policy surface (Network.framework) with every prohibited feature disabled through public API, plus exact NIOHTTP1/NIOWebSocket upgrade control.
- OS-managed TLS record layer; no third-party TLS implementation to track for CVEs.
- Content-neutral discovery, certificates, and logging, sentinel-verified.

**Costs and accepted risks:**

- Eight pinned repositories become supply-chain surface; the pin set is closed and any change re-triggers feasibility proof (§4).
- Secure Enclave is a hardware requirement; Macs without one cannot enable LAN. This is accepted as the price of non-exportability.
- NIOTS caveats are inherited: no native connection cap (app-level limiter, §9), no cascade of listener close to children (registry-based teardown, §14), and `NWListener.service` is public but NIOTS warns that arbitrary underlying-listener modification is unsupported — continued physical evidence is required before and during production Bonjour adoption (Steps 2.13/2.14).
- `URLSessionWebSocketTask` cannot suppress its compression offer; the server must keep declining it exactly (§9).
- The client trust override (pin-only, no CA evaluation) concentrates all transport trust in the pairing-time pin and rotation statements; this is intentional and accepted, and pin-mismatch surfacing is exact rather than a generic error.
- The signed LAN observation passed once on one machine and one LAN. Stability, IP-change, multi-network, and physical-iPhone behavior are unproven and remain gated (§16).

## 16. Implementation obligations (Steps 2.2–2.14)

Known gaps deferred from the spike, each owned by a production step below: per-connection message/byte rate limiter; slow-consumer/writability policy; post-upgrade idle expiry; server ping cadence with matching-pong deadline; exact live `NWInterface` object pinning; lifecycle-generation integration with authentication; the NIOTS `NWListener.service` mutation caveat needing continued physical evidence; NIOTS lacking a native connection cap (app-level limiter); no cascade of listener close to children (registry-based teardown).

| Step | Obligations from this ADR |
|---|---|
| 2.2 | Final wire byte layouts and golden fixtures under the §11 contract; exact minor/feature negotiation; sealed replay-cursor envelope encoding. |
| 2.3 | Crypto golden vectors under §11: 96-bit direction-prefix nonces, raw `r||s` signatures, exactly-next counters, transcript/rotation encodings, SAS derivation. |
| 2.4a | Adopt the exact §4 pins. Production Secure Enclave adapters (`.host`/`.tls`) reproducing every spike proof row — create, separate-process retrieve, export-denied, mismatch-fail-closed, verified cleanup — in the production namespace; certificate profile and same-key renewal per §7; rotation statements per §7/§11. Re-prove feasibility rows if any pin or toolchain changes. |
| 2.4b | Authority blob per §10: single actor, atomic whole-blob replacement, bounded size, anti-rollback generation, fail-closed disable of LAN. |
| 2.5 | Pairing per §11/§12: 256-bit secret, claim-before-verification, QR allowlist with no `hostName`, transcript-bound SAS. |
| 2.6 | Session handshake per §11; **integrate the lifecycle-generation model with real authentication** — in the spike it is model-only, proven to fail closed before `UInt64` overflow but not connected to any runtime reauthentication boundary. |
| 2.7 | Adopt the exact §4 pins. Enforce every §9 constant and every §9 ceiling with adversarial tests: rate limiter, slow-consumer/writability policy, idle expiry, ping/pong deadline, deadlines, per-source limits, app-level global/unauthenticated connection caps. Implement live `NWInterface` object pinning (§8) and registry-based teardown (§14). **Step 2.7 adds no production Bonjour**; Step 2.13 owns it. |
| 2.8 | Bounded queues and the filtered-snapshot slow-consumer fallback above the transport-layer close policy (§9). |
| 2.9 | Command traffic remains inside the §9 per-connection rate ceilings; failures surface only closed codes/counts (§13). |
| 2.13 | Production Bonjour per §12: advertise only after readiness, roll back on failure, removal-first disable, exact allowlist; carry `NSLocalNetworkUsageDescription`/`NSBonjourServices` in the signed Mac app; re-verify the NIOTS `NWListener.service` caveat with physical evidence before enabling. |
| 2.14 | Physical signed-iPhone proof: iOS Secure Enclave key lifecycle and reinstall, pinned WSS over real Wi-Fi, IP change, rotation, revocation; plus the stability/multi-network evidence the single signed-Mac LAN observation does not provide. |

## 17. Resolved Step 2.1 stop conditions

Every "before Step 2.2" stop condition in [the threat model](THREAT_MODEL.md) §11 is resolved:

| Threat-model stop condition | Resolving ADR section |
|---|---|
| TLS stack and non-exportable-key support | §4 (decision), §6 (proof) |
| TLS version, 0-RTT, resumption, certificate, and rotation policy | §5, §7 |
| Keychain accessibility, loss, reset, and backup semantics for long-term keys | §6 |
| Grant-authority format and encryption-key lifecycle | §10 |
| Direct-LAN interface eligibility and path changes | §8 |
| Canonical transcript and pairing claim/consume ordering | §11 (encoding); claim/consume ordering per threat model §2.2, restated in §16 (Step 2.5) |
| HTTP/WebSocket route, subprotocol, origin, compression, header, frame, connection, and deadline rules | §9 |
| Complete secret/identifier inventory including stack-generated TLS material | §5 (no ticket/PSK state), §6, §13; inventory updated in threat model §3 |

No unresolved listener-blocking question remains. The "before any listener merge" and "before Phase 2 acceptance" stop conditions in the threat model stay open by design; they gate Steps 2.7+ and 2.14, not Step 2.2.

## 18. References

- Evidence spike, merged to `main` as three stacked evidence PRs:
  - `a445f81` — `feat(spike): prove non-exportable identity and certificate lifecycle (#8)`
  - `531d972` — `feat(spike): prove hardened NIOTS TLS 1.3 WebSocket transport (#9)`
  - `c6577b7` — `feat(spike): add signed probe with Keychain, Bonjour, and LAN evidence (#10)`
- [Spike implementation findings](../Spikes/Phase2Transport/README.md) and [sanitized evidence](../Spikes/Phase2Transport/EVIDENCE.md); the positive signed-Mac proof was re-run from the merged `c6577b7` tree.
- [Threat model](THREAT_MODEL.md) · [Phase 2 plan](PHASE_2_PLAN.md) · [Phase 2 status](PHASE_2_STATUS.md) · [System architecture](IOS_COMPANION_ARCHITECTURE.md)
