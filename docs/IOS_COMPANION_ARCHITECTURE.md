# Codex Micro for iPhone — System Architecture and Build Plan

**Status:** Approved architecture; Phase 0 accepted; Phase 1 accepted; Phase 2 approved and planned — Step 2.1 (threat model and transport ADR) accepted

**Date:** 2026-08-02

**Audience:** Product owner and implementation team

## 1. Executive decision

Build a native iOS companion backed by a small native macOS bridge. The Mac remains the authoritative Codex execution host. The iPhone displays normalized thread state, streams progress, sends prompts, and answers tightly scoped approval requests. It never receives the user's OpenAI credential and never executes repository tools itself.

```text
┌──────────────────────┐   WSS + mandatory app-frame AEAD  ┌────────────────────────┐
│ Codex Micro iPhone   │◀────────────────────────────────▶│ Codex Micro Mac Bridge │
│ SwiftUI + Keychain   │  local LAN or private tailnet    │ Swift + Keychain       │
└──────────────────────┘                                  └───────────┬────────────┘
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

This is deliberately a client for Codex, not a new agent implementation. OpenAI documents `codex app-server` as the interface for rich third-party Codex clients, including authentication, history, approvals, and streamed agent events. Its default `stdio` transport is the correct private boundary between the bridge and Codex. The bridge must not expose raw app-server JSON-RPC to the phone.

OpenAI also already provides **Remote** in the ChatGPT iOS app for controlling a connected Mac. If the only goal is remote Codex access, use that feature and do not build another app. This project is justified only if the Codex Micro-specific six-agent interface, custom controls, private-network operation, or independent product experience is important.

## 2. Product definition

### 2.1 What v1 does

- Pairs one iPhone with one or more explicitly approved Macs.
- Shows six Codex Micro-style agent slots with the familiar states:
  - idle
  - thinking
  - completed with unread output
  - requires input or approval
  - error
  - unassigned
- Lists and opens Codex threads available through the Mac bridge.
- Starts a thread in an explicitly selected project.
- Sends a prompt, sends a follow-up, steers active work, or interrupts a turn.
- Streams agent text, plan progress, tool status, terminal output summaries, diffs, and final results.
- Presents command, file-change, network, permission, and structured-input requests.
- Approves once, declines, or cancels. Session-wide grants are held back until the security phase.
- Uses push-to-talk with on-device transcription when available.
- Connects on the same LAN in the first usable release and through Tailscale in the remote-access release.
- Supports device revocation from the Mac.

### 2.2 What v1 does not do

- It does not put an OpenAI API key, ChatGPT token, Codex session token, SSH key, or repository credential on the phone.
- It does not expose a general remote shell, arbitrary filesystem API, raw MCP tool invocation, app-server `process/*`, or `thread/shellCommand`.
- It does not keep the Mac available while the Mac is asleep or offline.
- It does not promise instant background notifications without an APNs-capable backend.
- It does not provide shared/team access, multi-user authorization, or collaboration roles.
- It does not copy a trademarked hardware enclosure or imply that this is an official OpenAI app. Product naming and visual identity need a separate legal/brand review before public release.

## 3. Product truth and feasibility gate

Two supported routes exist, and they solve different problems:

| Route | Best for | Main limitation |
|---|---|---|
| ChatGPT mobile **Remote** | Using existing ChatGPT/Codex work on a connected Mac with no custom engineering | Cannot deliver a custom Codex Micro interface or independent product behavior |
| Custom app + `codex app-server` | A purpose-built native client with custom state, controls, privacy, and networking | Compatibility and exact visibility of existing desktop-app chats must be proven against the installed Codex version |
| Direct Responses API client | A completely separate cloud coding product | Does not control the user's existing local Codex host, tools, credentials, permissions, or threads |

The project starts with a feasibility spike. Do not build the polished UI until all of these pass on the user's Mac:

1. `codex app-server` starts and completes the required initialize handshake.
2. Stable APIs can list, read, start, and resume the expected local threads.
3. A turn streams text, plan, command, diff, error, and completion events correctly.
4. Command and file approval requests round-trip without weakening Codex policy.
5. Restarting the bridge can reconnect and rebuild state without duplicating a turn or approval.
6. The product owner confirms whether the visible threads match the intended Codex desktop workflow.

If item 6 fails, the honest options are to use official Remote or position this app as a separate client for Codex app-server sessions. Do not reverse-engineer ChatGPT desktop internals.

## 4. Architecture principles

1. **Mac authoritative:** repositories, credentials, Codex configuration, tools, skills, and action execution stay on the Mac.
2. **Phone controlled:** every command from the phone maps to a small allowlisted capability and an independently enforced mobile action ceiling.
3. **Least privilege:** pairing grants `observe`, `respond`, `runAgent`, `approve`, `interrupt`, and `startThread` separately. `runAgent` is intentionally treated as powerful because a prompt can cause tools to run. `approve` and `respond` are Phase 4 capabilities — the Phase 2 network gateway rejects them; `startThread` is conditional on the Step 2.12 product decision.
4. **No credential copying:** Codex and provider authentication remain inside the Mac's existing Codex setup.
5. **Local first:** LAN operation works without a product backend. Remote access initially uses a user-owned private tailnet.
6. **Event-derived UI:** the Mac bridge normalizes app-server events into a stable, versioned companion protocol.
7. **Fail closed:** missing identity, stale approvals, unknown protocol fields, bad sequence numbers, or unsupported Codex versions cannot trigger actions.
8. **Idempotent control where possible:** every state-changing request has a unique command ID. Known results can be replayed safely; crash-ambiguous commands fail closed and are never retried automatically.
9. **No model-as-authority:** model output never grants permission or proves that an action succeeded.
10. **Optimize measured bottlenecks:** JSON and native UI are sufficient for v1; compression, binary frames, or a shared Rust core require profiling evidence.

## 5. Components

### 5.1 iOS app

Responsibilities:

- Pairing QR scanner and host management.
- Secure device identity backed by Secure Enclave when available.
- Foreground WSS connection and reconnect loop.
- Typed protocol decoding and sequence validation.
- In-memory thread/event state and small non-sensitive metadata cache.
- Six-slot dashboard, thread detail, composer, approval sheets, settings, and accessibility.
- Local authentication for high-risk approvals.
- On-device speech-to-text when the device and locale support it.
- Local notifications only while permitted by iOS; APNs comes later.

The app does not understand raw Codex JSON-RPC. It understands only the companion protocol defined by this project.

### 5.2 Mac bridge

Responsibilities:

- Runs as a menu-bar app for setup and a per-user background service for availability.
- Runs as the signed-in user, never as root, and requests no Accessibility or Input Monitoring permission for this architecture.
- Detects the installed Codex binary and checks its version against a compatibility matrix.
- Starts `codex app-server` over `stdio` or connects to its local Unix control socket after that mode is validated.
- Initializes app-server once per connection and subscribes only to required stable events.
- Converts Codex thread, turn, item, diff, and approval messages into companion domain objects.
- Waits for the matching `turn/started` event before issuing turn-scoped controls such as interruption; a successful `turn/start` response alone does not prove the turn is already controllable.
- Maintains a memory-only bounded event journal with monotonically increasing sequence numbers. This Phase 1 journal is an internal global namespace; Phase 2 never exposes it on the network — `MacBridgeCore` assigns per-device sequences only within each device's authorized-view namespace and returns already-filtered batches.
- Enforces device grants, project allowlists, approval scope, rate limits, and replay protection.
- Enforces a `MobileActionProfile` that is never broader than the device grant or the Mac's Codex policy. A phone cannot steer a turn whose effective permissions exceed its profile.
- Publishes LAN discovery with Bonjour after LAN companion access is explicitly enabled by the user.
- Hosts the authenticated WSS endpoint; short-lived attachment downloads are post-Phase 2 scope.
- Stores host identity, paired-device public keys, grants, and revocation state in macOS Keychain or an encrypted local store.
- Redacts logs and provides an exportable diagnostic bundle without prompts, diffs, credentials, or repository contents by default.

The bridge is the security boundary. Even a fully compromised phone must not gain access to capabilities the bridge did not grant.

#### Mobile action profiles

`message` is not modeled as a harmless capability: natural-language instructions can invoke powerful tools. Use these explicit profiles:

- `observe`: thread/event visibility only.
- `respond`: answer an already pending structured user-input request; cannot start or steer an agent turn.
- `runReadOnly`: start a phone-originated turn with bridge-forced read-only sandboxing, no network, and conservative approval policy.
- `runWorkspace`: start a turn only in an allowlisted project with bridge-capped workspace-write roots, network disabled by default, and approvals still enforced. This requires the separate `runAgent` grant.

The bridge intersects the device profile, project policy, managed Codex requirements, and requested turn settings, then applies the most restrictive result. The phone never supplies a path or raw sandbox/approval setting. Steering is denied when an existing turn was created with a more permissive effective policy. Permissive modes such as approval policy `never`, unrestricted filesystem access, or new network access cannot be enabled from the phone in v1.

### 5.3 Codex adapter

The adapter is a module inside the bridge. Its first version uses only this allowlist:

- `initialize` / `initialized`
- `account/read`
- `model/list`
- `thread/list`
- `thread/read`
- `thread/start`
- `thread/resume`
- `thread/unsubscribe`
- `turn/start`
- `turn/steer`
- `turn/interrupt`
- required approval responses
- stable thread, turn, item, diff, plan, warning, and error notifications

Potential later additions require a separate security review. In particular, keep these disabled in the phone path:

- `thread/shellCommand`
- `process/*`
- `command/exec*`
- `fs/*`
- configuration writes
- plugin installation or marketplace mutation
- arbitrary MCP tool calls
- experimental APIs unless a specific feature has no stable alternative and has contract tests

Generate the app-server schema from the exact supported Codex CLI version in CI. Commit the generated schema or derived Swift fixtures so protocol drift is reviewed. Runtime startup reports “Codex update not yet supported” rather than guessing through incompatible messages.

Phase 0 has verified the command-approval `cancel` response against Codex CLI 0.146.0: the bridge matched the request to the active turn, returned only `decision: cancel`, observed the command rejection, and received a final `interrupted` turn status. Production approval handling must preserve this explicit request-to-turn binding and must never infer approval from a prompt or model output.

The same explicit cancellation contract is verified for file-change requests with an unchanged-file hash check. Restart recovery is also verified with a persisted read-only test turn: a fresh app-server client rebuilt one interrupted turn through `thread/read`, did not send another `turn/start`, and archived the test record. The bridge state reducer therefore treats snapshots as authoritative after reconnect and lifecycle events as idempotent updates routed to an explicit thread ID.

### 5.4 Optional relay, not part of the LAN MVP

An optional relay is needed only for polished public remote access and APNs:

- Mac and iPhone both make outbound TLS connections; neither exposes a public inbound port.
- The relay authenticates accounts/devices, routes opaque encrypted frames, tracks connection presence, and sends content-free APNs wake-ups.
- Its separate threat model must design and verify forward-secret, end-to-end encrypted frames between paired devices. Relay confidentiality is an exit criterion, not a property of the LAN design.
- The future design must ensure queued ciphertext has a short TTL and bounded size and that the relay cannot decrypt it; Phase 7 must prove these properties before release.
- APNs payloads contain only an opaque host/event identifier and category such as `attentionRequired`.

Do not build this backend until LAN and Tailscale usage prove the product is valuable.

## 6. Networking design

### 6.1 Mode A — same LAN

- Mac bridge advertises `_codexmicro._tcp` with Bonjour.
- Bonjour uses an exact content-neutral service-instance/TXT-key allowlist. It contains no host/device name, identifier, fingerprint, project data, user content, or secret.
- iPhone connects with `wss://` to the discovered endpoint.
- The TLS host certificate/public-key fingerprint is pinned during QR pairing.
- Discovery never implies authorization; unpaired clients cannot subscribe or invoke commands.

### 6.2 Mode B — Tailscale remote access

Recommended first remote mode:

- The user installs Tailscale on both devices.
- Prefer a bridge-owned WSS listener bound only to the Mac's tailnet interface so the same transport pinning remains end to end. If Tailscale Serve terminates TLS for a loopback bridge, treat that certificate as transport identity only and still verify the bridge's signed application-layer host identity.
- Tailscale supplies the WireGuard network and device access policy; the companion protocol still performs its own paired-device authentication.
- No router port forwarding, public DNS, cloud database, or product-owned relay is required.

This is the smallest privacy-conscious remote architecture. It is suitable for development, TestFlight, and technically comfortable users. It is not the final consumer onboarding experience.

### 6.3 Mode C — product relay

Build only after the optional relay design receives a separate threat model. It is required for:

- reliable APNs alerts while the iOS app is suspended,
- remote access without asking users to install a VPN,
- host presence and reconnect coordination across changing networks.

It does not make a sleeping Mac runnable. The Mac must stay awake, online, signed in, and able to run Codex.

### 6.4 WebSocket behavior

- One foreground socket per selected host.
- Ping every 20–30 seconds while foregrounded; close cleanly on background transition.
- Exponential reconnect with full jitter: approximately 0.5 s, 1 s, 2 s, 4 s, up to 30 s.
- After reconnect, the phone sends a sealed cursor envelope containing device ID, current grant revision, authorized-view epoch, journal epoch, and sequence.
- The bridge replays only retained events in that device's current authorized-view namespace. Older revision/view, foreign epoch, or retention-stale cursors receive a filtered snapshot; mismatched-device, ahead, rolled-back, overflowing, or malformed cursors fail closed.
- State-changing command retry uses the same idempotency key.
- Backpressure is explicit. Terminal deltas are batched, bounded, and may be summarized before ordinary chat events are delayed.
- Large diffs, screenshots, and attachments (post-Phase 2 scope) are represented by short-lived authenticated references rather than placed in a WebSocket frame.

## 7. Pairing and authentication

### 7.1 Long-term identities and TLS lifecycle

- The Mac creates a long-term P-256 host-identity signing key in Keychain and a random `hostId`.
- The WSS listener uses a separate P-256 TLS key and certificate. The QR pins both the long-term host-identity key and the current TLS SPKI fingerprint.
- Routine TLS certificate renewal keeps the same TLS key. A TLS key rotation is accepted only with a rotation statement signed by the already paired host-identity key.
- Rotating or losing the host-identity key requires pairing again; the client never silently repins it.
- The iPhone creates a P-256 device signing key in Secure Enclave where available and a random `deviceId`.
- Private keys never leave their secure stores.
- Reinstalling either app creates a new identity and requires pairing again.

### 7.2 QR payload

The QR code carries exactly the ADR §12 allowlist and nothing else:

```json
{
  "version": 1,
  "protocolFeatures": "exact-supported-set",
  "hostId": "opaque-id",
  "endpoint": "wss://192.0.2.10:48321/pair",
  "hostIdentityFingerprint": "sha256-base64url",
  "tlsSPKIFingerprint": "sha256-base64url",
  "pairingSessionId": "opaque-id",
  "oneTimeSecret": "256-bit-base64url",
  "expiresAt": "2026-08-02T20:15:00Z"
}
```

There is deliberately **no `hostName`** or other display metadata in the QR: the phone pins the current TLS SPKI from the QR, verifies the host through the signed pairing transcript, and learns a display name only from the authenticated exchange. The pairing secret is deliberately a raw **bootstrap credential** inside the QR. It expires after five minutes, is single-use, and is never logged. It is not a Codex, account, or long-lived device credential. Showing the QR requires the user to unlock the Mac app.

### 7.3 Pairing sequence

```text
iPhone                         Mac bridge
   │ scan QR                       │
   │ connect WSS + pin host key    │
   │──────────────────────────────▶│
   │ pairingSession + secret       │
   │ device public key + nonce     │
   │──────────────────────────────▶│
   │                               │ verify unused + unexpired secret
   │                               │ show device/grant confirmation on Mac
   │ host challenge + transcript   │
   │◀──────────────────────────────│
   │ signed transcript             │
   │──────────────────────────────▶│
   │ signed grant + host metadata  │
   │◀──────────────────────────────│
   │ store host grant in Keychain  │ store device grant in Keychain
```

The canonical transcript is:

```text
SHA256(
  CanonicalLengthDelimitedEncoding(
    context: "codex-micro-pair-v1",
    hostId, hostIdentityPublicKey, deviceId, devicePublicKey,
    pairingSessionId, expiresAt, clientNonce, serverNonce,
    exactNegotiatedProtocolAndFeatures, pairingMode,
    normalizedEndpointOrigin, initialTLSSPKIFingerprint
  )
)
```

Phase 2 accepts only `directLAN` pairing mode; tailnet and TLS-terminating proxy modes require later-phase threat models. The normalized endpoint contains scheme, lowercase host, and port with no user info, path variation, query, or fragment. The exactly 256-bit CSPRNG bootstrap secret is compared in constant time and atomically claimed before signature verification; any completed claim consumes it regardless of outcome. The Mac and iPhone sign the versioned, length-delimited canonical transcript with their long-term identity keys. The six-word verification phrase derives from exactly 66 uniformly distributed bits using a fixed versioned 2,048-word list. Both users confirm locally; a peer-supplied confirmation is never a substitute. Pairing completes only after both local confirmations, valid signatures, and transcript-bound transport identity. The signed grant stored on the phone is a **non-authoritative receipt** for display and reconnect bookkeeping; the Mac's stored grant authority is the only authorization source at every authentication and command check, and a phone-presented grant can never override it.

### 7.4 Normal session authentication

1. TLS validates the pinned TLS SPKI or a valid host-identity-signed TLS rotation.
2. Phone and bridge exchange ephemeral P-256 ECDH keys plus fresh nonces.
3. Phone signs the versioned, length-delimited connection transcript containing both ephemeral keys, both nonces, host ID, device ID, exact negotiated protocol/features, the current device grant revision and authorized-view epoch, and host generation.
4. Bridge verifies the paired public key against the current Mac-stored grant/revocation authority, then signs the same transcript.
5. Both sides derive separate client-to-server and server-to-client authenticated-encryption keys with HKDF-SHA256 over the ECDH shared secret and transcript hash.
6. The bridge issues a short-lived session identifier bound to the connection, current device grant revision, authorized-view epoch, and host generation. It is not a bearer credential.
7. Every post-handshake application payload in both directions is sealed with ChaCha20-Poly1305. The clear frame header contains only protocol version, connection ID, direction, and a strictly increasing per-direction counter; that complete header is authenticated as additional data.
8. Every command inside the sealed payload also carries the session ID, command ID, timestamp, and request digest.

Each side accepts exactly the next counter for the opposite direction and closes on any duplicate, gap, wrong direction, overflow, tamper, or unauthenticated frame. A versioned injective 96-bit nonce encoding is fixed by golden vectors under fresh per-direction keys. A reconnect always creates a new connection ID, ECDH keys, and counter spaces, so captured frames cannot cross connections. Handshake frames before key derivation are bound by identity signatures. No long-lived bearer credential is stored on the phone.

### 7.5 Revocation

The Mac's Connections screen shows each device, last seen time, granted capabilities, project scope, grant revision, expiry, and key fingerprint. Revocation/reduction/expiry is linearizable: persist the device revision or tombstone, publish it to every authorization check, purge unauthorized queued data/results, advance the device's authorized-view epoch when scope changes, then close or reauthenticate every affected connection. Ordinary revocation does not invalidate unrelated devices; host generation changes only for intentional host-wide invalidation. The phone removes the host locally when it learns of revocation.

## 8. Companion protocol

Use strict Codable JSON envelopes with exact minor/feature negotiation inside the authenticated-encryption layer. Security/control types reject unknown fields and message types; major-only compatibility is insufficient at this boundary. JSON remains easy to inspect in sanitized development traces, contract-test, and evolve. Production WebSocket payloads after authentication carry a small clear authenticated counter header plus ChaCha20-Poly1305 ciphertext, never plaintext envelope content.

```swift
struct Envelope<Payload: Codable>: Codable {
    let protocolVersion: ProtocolVersion
    let messageId: UUID
    let hostId: UUID
    let sequence: UInt64?
    let sentAt: Date
    let payload: Payload
}
```

Message families:

- `client.hello`
- `server.challenge`
- `client.authenticate`
- `server.authenticated`
- `client.subscribe(replayCursor:)`
- `server.snapshot`
- `server.event`
- `client.command`
- `server.commandAccepted`
- `server.commandResult`
- `server.problem`
- `client.ack`

Commands are semantic, not generic RPC:

- `selectThread` — phone-local UI state, never sent to the Mac
- `startThread(projectId, prompt)` — conditional on the Step 2.12 product decision
- `sendPrompt(threadId, prompt, attachments)` — nonempty `attachmentIDs` are rejected until a post-Phase 2 attachment service exists
- `steerTurn(threadId, turnId, prompt)`
- `interruptTurn(threadId, turnId)`
- `resolveApproval(requestId, decision, requestDigest)` — rejected throughout Phase 2; Phase 4 defines approval transport and the device-bound user-presence assertion
- `markThreadRead(threadId, throughSequence)`

Every command response echoes its idempotency key. Unknown commands fail closed. The bridge rejects project paths from the phone; the phone sends an opaque project ID previously issued by the Mac.

### 8.1 Durable command ledger and ambiguous outcomes

The bridge keeps a small encrypted SQLite command ledger, separate from the memory-only event journal. It contains only command ID, device ID, semantic command type, request digest, lifecycle state, correlated Codex thread/turn/request IDs, and result code—never prompt text, command text, diff content, paths, or output. The database key lives in Keychain; the file is mode `0600`, backup-excluded, and uses bounded retention.

Before an external call, the bridge commits the command as `submitting`. After app-server returns a correlation ID, it records `submitted`, then records the terminal result. A repeated command with a known result receives that result without execution.

There is no honest exactly-once guarantee across a crash between Codex accepting a request and the bridge receiving its correlation ID. Such a ledger row becomes `outcomeUnknown`. On restart the bridge attempts read-only reconciliation against the pending request or recorded thread/turn state. If it cannot prove the outcome, it does not resend. The iPhone shows “Outcome unknown—review on Mac” and the user decides the next action. Approval commands follow the same rule and are never automatically re-approved.

## 9. State model

### 9.1 Connection state

```text
unpaired
  └─▶ pairing ─▶ pairedOffline ─▶ connecting ─▶ authenticating ─▶ syncing ─▶ ready
          │             ▲               │              │            │        │
          └─▶ failed     └───────────────┴──────────────┴────────────┴─▶ degraded
                                                                        │
                                                                   revoked
```

The UI never describes a host as ready until authentication and snapshot synchronization both finish.

### 9.2 Mac-authoritative records

**HostRecord**

- `hostId`
- display name
- host public-key fingerprint
- bridge version
- exact supported protocol minor/feature set
- Codex version and supported schema hash
- connection availability
- host generation

**DeviceGrant**

- `deviceId`
- device name and public key
- granted capabilities
- permitted project IDs
- grant revision and authorized-view epoch
- created, last-seen, and optional expiry timestamps
- revoked timestamp

**ProjectDescriptor**

- opaque `projectId`
- user-facing name
- redacted display path
- repository state summary
- allowed to start new threads

**ThreadSummary**

- `threadId` and `sessionId`
- title or preview
- project ID
- updated time
- runtime state
- unread sequence
- active turn ID
- plan progress
- pending attention category
- final error summary

**PendingApproval**

- `requestId`, `threadId`, `turnId`, and `itemId`
- approval kind
- reason and safe preview
- available decisions
- risk classification
- canonical request digest
- created and expiry timestamps
- resolution and resolving device

**JournalEvent** (internal to the bridge; network clients see only per-device authorized-view sequences)

- monotonic internal sequence
- event type
- domain payload
- creation time
- optional thread and turn scope
- retention class

The v1 journal is an in-memory ring buffer only. After a bridge restart, the bridge rebuilds a current snapshot from app-server rather than recovering sensitive event bodies from disk. Only the content-free command ledger described in §8.1 is durable.

### 9.3 Phone-local state

Persist in Keychain:

- device private key reference
- paired host IDs and pinned public-key fingerprints
- signed device grants (non-authoritative receipts; the Mac's stored authority decides)

Persist as non-sensitive preferences:

- selected host ID
- agent-slot assignments by opaque thread ID
- UI layout, haptics, voice, and accessibility preferences
- last sealed replay cursor envelope per host and device grant revision

Keep in memory by default:

- prompt and response text
- diffs and terminal output
- pending approvals
- screenshots and attachments

An opt-in offline cache can be added later using an encrypted database and iOS Complete File Protection. It is not required for v1.

“In memory” also requires the following platform controls:

- Use an ephemeral `URLSessionConfiguration` with URL cache and credential persistence disabled.
- Place unavoidable upload/transcription temporary files in a Complete File Protection directory, exclude them from backup, use random filenames, and delete them on acknowledgement, cancellation, background expiry, and next launch recovery.
- Never copy sensitive output to the pasteboard automatically.
- Replace sensitive UI with a privacy cover before iOS takes an app-switcher snapshot.
- Keep prompt, response, diff, command, path, approval, and audio content out of crash metadata and signposts.
- Use `PhotosPicker`/document-picker scoped access, copy only the selected item into the protected temporary area, validate type and size, and delete it after the bridge accepts the upload.
- Require on-device speech recognition for the private voice mode. If it is unavailable for the locale, fall back to editable text or ask for explicit consent; never silently switch to cloud transcription.

### 9.4 Agent-slot status derivation

The bridge computes one display state per slot so every client is consistent:

| State | Rule | Color |
|---|---|---|
| `unassigned` | No thread assigned | off / muted |
| `inputRequired` | Unresolved approval or user-input request exists | amber |
| `thinking` | Active turn is in progress | blue |
| `error` | Latest relevant turn failed and is unread | red |
| `completeUnread` | Latest turn completed after read cursor | green |
| `idle` | Assigned with no active or unread work | white |

`inputRequired` outranks `thinking`; the user must never miss an approval behind an activity state.

## 10. iOS information architecture

### 10.1 Home — the phone version of Codex Micro

- Host name, connection state, and one-tap host switcher at the top.
- Six large Agent Keys in a two-column grid.
- Each key shows color/state, thread title, project, elapsed activity, and attention badge.
- Tap opens the thread; long-press opens assignment and quick actions.
- A bottom Command Deck provides:
  - new thread
  - approve or review current request
  - decline
  - interrupt or resume contextually
  - push-to-talk
  - send
- Haptics mirror status transitions without relying on color.

### 10.2 Thread detail

- Compact status header and plan progress.
- Virtualized event timeline, not an unbounded rendered transcript.
- Collapsible command/tool cards with bounded output.
- Diff viewer with file list, line-level colors, and monospaced horizontal scroll.
- Sticky composer with text, voice, attachments, send, steer, and stop.
- Reconnect banner distinguishes cached state from live state.

### 10.3 Approval sheet

- Approval kind and risk label.
- Exact host, project, thread, command/target, and requested scope.
- Human-readable reason.
- Diff or network destination when applicable.
- “Approve once,” “Decline,” and “Cancel.”
- “Approve for session” appears only after the security phase and requires biometric confirmation plus a visible scope summary.
- Destructive or broad requests require Face ID/Touch ID and cannot be actioned from a notification button.

### 10.4 Accessibility

- Dynamic Type through accessibility sizes.
- VoiceOver labels describe state rather than only color.
- Minimum 44×44 pt controls.
- Reduce Motion removes pulse/rotation while preserving status changes.
- Increase Contrast and Differentiate Without Color are supported.
- All drag, swipe, and long-press actions have visible button/menu alternatives.

## 11. Technology stack

### 11.1 Recommended stack

| Layer | Choice | Why |
|---|---|---|
| iOS UI | SwiftUI + Observation | Native performance, accessibility, predictable platform behavior |
| iOS architecture | Small feature modules with unidirectional state and actors | Testable without introducing a large state-management dependency |
| Concurrency | Swift 6 strict concurrency, actors, `AsyncStream` | Safe streaming and reconnect state |
| iOS WebSocket | `URLSessionWebSocketTask` | Native, sufficient, background behavior is honest |
| LAN discovery | Network.framework + Bonjour | Native service discovery and path monitoring |
| Mac bridge | Swift executable + menu-bar SwiftUI shell | Shares protocol/domain code and integrates cleanly with Keychain and launch services |
| Mac server | NIO Transport Services 1.28.0 listener over Network.framework TLS with a Secure Enclave `SecIdentity`, plus swift-nio 2.101.3 (NIOHTTP1/NIOWebSocket) upgrade control and swift-certificates 1.19.4 | Accepted by the transport ADR: proven non-exportable identity, TLS 1.3-only policy, and exact upgrade/frame enforcement. NIOSSL is rejected — no public server ticket/resumption control under our policy |
| Cryptography | CryptoKit / reviewed Apple Security APIs | P-256 signing/ECDH, SHA-256, HKDF, and mandatory ChaCha20-Poly1305 application-frame protection for Phase 2 LAN sessions |
| Secure storage | iOS Secure Enclave/Keychain; macOS Keychain | Keeps device and host identity out of files and preferences |
| Local persistence | None for content in v1; GRDB only if an offline cache is approved | Avoids unnecessary sensitive-data retention |
| Schema/codegen | Codex JSON Schema fixtures + Swift Codable models | Detects app-server drift while keeping the phone protocol stable |
| Testing | Swift Testing, XCTest/XCUITest, Network Link Conditioner, physical devices | Covers domain logic, protocol, reconnection, UI, and real network behavior |
| Dependencies | Swift Package Manager | One native toolchain and reproducible package pins |
| Remote MVP | Tailscale | Private WireGuard access without building a relay |
| Production push | Small relay + APNs, later | Required for reliable background attention alerts |

### 11.2 Why not React Native, Flutter, or a web app

- The product is iOS-first and depends on Keychain, Secure Enclave, QR capture, local authentication, speech, haptics, lifecycle, background limits, and polished accessibility.
- A native Swift implementation removes a cross-platform bridge from the most security-sensitive paths.
- The Mac helper also benefits from native process, Keychain, menu-bar, launch-service, and Network.framework integration.
- Cross-platform UI reuse has little value until Android is a real requirement.

### 11.3 Why not a shared Rust core yet

Rust would be reasonable for a later cross-platform protocol/security core, but it creates an FFI boundary and duplicate build toolchain before the protocol has stabilized. Swift actors and Codable are sufficient for v1. Reconsider Rust only when Android/Windows support is funded or profiling finds a real CPU/memory bottleneck in shared logic.

## 12. Suggested repository layout

```text
Codex-Micro/
├── Apps/
│   ├── iOS/                       # SwiftUI iPhone app target
│   └── macOS/                     # Menu-bar/setup app target
├── Packages/
│   ├── CompanionProtocol/         # Versioned Codable wire types
│   ├── CompanionDomain/           # Thread, turn, slot, approval state
│   ├── CompanionCrypto/           # Key identities and challenge proofs
│   ├── CodexAdapter/              # app-server process + JSON-RPC mapping
│   ├── MacBridgeServer/           # TLS/WSS listener, sessions, limits only
│   └── TestSupport/               # Fixtures, fake clocks, fake transports
├── Schemas/
│   ├── codex/<supported-version>/ # Generated app-server schema snapshot
│   └── companion/v1/              # Protocol examples and JSON Schema
├── Tests/
│   ├── Contract/
│   ├── Integration/
│   ├── Security/
│   └── UI/
├── docs/
│   ├── IOS_COMPANION_ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── PROTOCOL.md
│   └── RELEASE_CHECKLIST.md
└── Package.swift                  # Shared packages; apps remain Xcode targets
```

Start with fewer targets if Xcode maintenance becomes noisy. The architectural seams matter; speculative micro-packages do not. Ownership is fixed by the Phase 2 plan: `MacBridgeServer` owns the listener, TLS/WSS, connection/session actors, interface policy, and resource limits **only** — the event journal, device-grant authority, capability policy, and command gateway stay in `MacBridgeCore`.

## 13. Performance and reliability plan

### 13.1 Event processing

- One actor owns each host connection.
- Decode off the main actor, then publish small normalized state changes.
- Coalesce agent text deltas into 30–60 ms UI updates.
- Batch terminal output for 100–200 ms and cap retained output per command.
- Apply `item/completed` and final plan items as authoritative, matching app-server semantics.
- Use lazy lists and stable event IDs to avoid re-rendering the full thread.

### 13.2 Bounded resources

- WebSocket bounds are fixed by ADR §9: binary frames only, 16 KiB frame cap, 64 KiB message cap, 8 fragments per message, and the connection/deadline/rate ceilings enforced in Step 2.7.
- Inline text/diff cap: truncate with an explicit “Open full output on Mac” state.
- Attachment downloads (post-Phase 2): short TTL, one device, one object, bounded size.
- Event journal: size- and time-bounded, for example last 10,000 normalized events or 24 hours.
- Per-source pairing/connection and per-connection message/byte rate limits per ADR §9.
- Slow consumers receive a fresh filtered snapshot rather than unbounded queued deltas; the transport-layer queue bound in ADR §9 closes the connection when exceeded.

Transport constants come from the ADR and may only tighten without a superseding ADR; the application-level journal/truncation numbers are starting limits — instrument them and adjust after physical-device testing.

### 13.3 Observability

Track locally:

- connection and authentication latency,
- snapshot and replay duration,
- event decode and main-thread publish time,
- dropped/coalesced delta counts,
- reconnect attempts and causes,
- Codex request duration and final status,
- approval creation-to-resolution time,
- memory high-water mark.

Never record prompt text, response text, diffs, paths, command output, tokens, pairing secrets, or approval bodies in analytics. Diagnostics carry closed reason codes and numeric counts only — no opaque IDs, endpoints, or fingerprints.

## 14. Security model

### 14.1 Trust boundaries

1. Untrusted LAN or internet → Mac WSS endpoint.
2. Paired phone → capability policy and project allowlist.
3. Companion command → Codex adapter allowlist.
4. Codex/model/repository content → phone renderer and approval UI.
5. Optional relay/APNs → end-to-end encrypted content boundary.
6. Local process output → logs and diagnostics.

### 14.2 Primary threats and controls

| Threat | Required control |
|---|---|
| LAN interception/MITM | WSS, transcript-bound endpoint/TLS pin, mutual identity signatures, and post-handshake application-frame AEAD |
| Stolen phone | Secure Enclave key, device passcode requirement, biometric confirmation for high-risk approvals, Mac-side revocation |
| QR capture | Five-minute single-use secret plus confirmation and verification phrase on the Mac |
| Replay or duplicate tap | Nonce, timestamp window, monotonic counter, request digest, idempotency key |
| Compromised relay | End-to-end encrypted frames; relay never receives content keys |
| Malicious repository prompt injection | Repository/model text is untrusted; it cannot grant capabilities or auto-approve actions |
| Approval confusion | Bind decision to request ID, item, thread, turn, digest, expiry, host, and visible scope |
| Cross-project access | Phone uses opaque project IDs; bridge resolves them against a local allowlist |
| Terminal escape/control injection | Strip or safely parse ANSI/control sequences; render as native text, never HTML |
| Secret leakage | Keep Codex auth on Mac; redact logs; no content in APNs; no Codex/account/long-lived credential in QR or URLs. The QR intentionally contains one short-lived single-use pairing bootstrap credential |
| Resource exhaustion | Frame caps, rate limits, bounded journals, backpressure, output truncation |
| Protocol downgrade | Pairing and connection signatures bind the exact negotiated minor/feature set; security/control messages never accept a bare minimum-major check |

### 14.3 Approval rules

- Codex's own approval and sandbox policies remain authoritative.
- The bridge may add restrictions but never remove them.
- Phone-originated instructions run only inside the separately granted `MobileActionProfile`; possessing `runAgent` still does not grant `approve`.
- An approval cannot be created by the phone.
- An approval response is accepted only while the exact request is pending.
- Stale, already-resolved, mutated, or digest-mismatched requests fail closed.
- `acceptForSession` is not in the initial release.
- Destructive, credential-related, broad filesystem, or new-network-destination approvals require the full review screen and local authentication.
- Notification actions may open the approval screen but may not approve directly.

## 15. Implementation phases and exit gates

### Phase 0 — feasibility and protocol spike

**Build**

- A command-line Mac prototype that starts installed Codex app-server over stdio.
- Initialize handshake and typed request correlation.
- Thread list/read/start/resume.
- One full turn with text, plan, command, diff, approval, completion, interruption, and failure fixtures.
- Record sanitized fixtures from the installed Codex version.

**Exit gate**

- The intended thread/session workflow is visible and controllable.
- Approval round-trip works without policy bypass.
- Restart and replay do not duplicate actions.
- Crash-ambiguous actions are reconciled or surfaced as unknown and are never retried automatically.
- Product owner chooses official Remote or custom client based on evidence.

### Phase 1 — Mac bridge core

**Build**

- Codex process supervisor and compatibility check.
- Normalized domain store and status derivation.
- Event sequence journal and snapshot/replay.
- Capability/project policy engine.
- Mobile action profiles and effective-policy intersection.
- Redacted structured logging.
- Encrypted, content-free command ledger with `outcomeUnknown` recovery.
- Fake app-server for deterministic tests.

**Current implementation:** Phase 1 is accepted. The shared core has the exact CLI/schema gate for Codex 0.146.0, a runtime supervisor, deterministic thread/turn routing, an actor-isolated domain store, normalized content-free snapshots and pending approvals, bounded replay, capability policy, canonical approval digests/expiry, user-presence gating, an AES-GCM-encrypted SQLite command ledger with a Keychain key provider, single-send approval-response execution reconciled against `serverRequest/resolved`, automatic degraded-state recovery, a redacted structured logger, a deterministic fake app-server contract harness, and the `codex-micro-bridge` menu-bar assembly shell. Evidence and deferred items are recorded in the Phase 1 status document.

**Exit gate**

- Contract tests cover every consumed event and approval type.
- Unknown/experimental messages cannot accidentally trigger an action.
- Bridge survives Codex crash/restart and reports degraded state.
- A phone cannot steer or start work above its granted mobile action ceiling, even when the underlying thread or Mac configuration is more permissive.

### Phase 2 — secure local pairing and networking

**Execution plan:** [Phase 2 secure local pairing and networking plan](PHASE_2_PLAN.md). Security contracts, identity/crypto state machines, and an observe-only boundary precede any state-changing network path.

**Build**

- Host/device keys, QR flow, pinned WSS, signed challenge sessions.
- Bonjour discovery.
- Paired-device management and revocation.
- Idempotent semantic command protocol.
- Per-connection ECDH key agreement, bidirectional ChaCha20-Poly1305 application-frame protection, and strict per-direction counter/nonce validation.

**Exit gate**

- A non-paired LAN client cannot read even thread metadata.
- Replayed/expired pairing requests are rejected. Frames must carry exactly the next per-direction counter; any duplicate, gap, wrong direction, overflow, cross-connection replay, alteration, or authentication failure closes the session.
- TLS key rotation requires the paired host identity; host identity rotation requires re-pairing.
- Revocation closes an active session immediately.
- Network interruption resumes from a cursor or snapshot without state corruption.

### Phase 3 — iPhone Codex Micro experience

**Build**

- Host setup and pairing.
- Six Agent Keys and assignment flow.
- Thread detail, streamed timeline, plan, command cards, diff summary, composer, stop/steer.
- Connection/degraded/offline states.
- Dynamic Type, VoiceOver, contrast, reduced motion, and haptics.

**Exit gate**

- All essential actions work on a physical iPhone over Wi-Fi.
- State is understandable without color.
- Large output does not block scrolling or exceed memory budget.
- Backgrounding and foregrounding reconnect cleanly.

### Phase 4 — approval and security hardening

**Build**

- Full approval sheets for command, file, network, permission, and structured input.
- Request digest binding and expiry.
- Face ID/Touch ID for high-risk decisions.
- Extend the P0 threat model, strict-decoder adversarial tests, rate limits, and log-redaction controls established before the Phase 2 listener; add approval-specific fuzzing and independent security review.

**Exit gate**

- Every state-changing path checks authentication, device grant, project scope, input schema, request freshness, and Codex pending state.
- No credential or user content appears in default logs or notifications.
- Independent review clears all critical/high findings.

### Phase 5 — voice and daily-use polish

**Build**

- Push-to-talk.
- On-device speech recognition where supported; disclose when a locale cannot be processed on device.
- Ephemeral audio handling and immediate deletion.
- Command Deck customization and selected-thread shortcuts.

**Exit gate**

- The privacy mode is visible before recording.
- Audio is not retained or logged.
- Voice failures always leave editable text or a clear retry path.

### Phase 6 — private remote access

**Build**

- Tailscale setup guidance and endpoint configuration.
- Network transition handling across Wi-Fi, cellular, and tailnet paths.
- Mac keep-awake option with clear power implications.

**Exit gate**

- Remote operation works on cellular without exposing a public listener.
- Turning off the tailnet or revoking the device removes access.
- Offline/sleeping host behavior is clear and honest.

### Phase 7 — optional relay and APNs

**Build only after approval**

- Account/device registry.
- Outbound Mac and iPhone relay sessions.
- End-to-end encrypted routing and bounded ciphertext queue.
- Content-free APNs wake-ups.
- Abuse controls, deletion, retention, incident response, and privacy documentation.

**Exit gate**

- Relay compromise cannot reveal prompt, output, diff, command, path, or approval content.
- APNs contains no user content.
- Data deletion and device revocation are verified end to end.

### Phase 8 — TestFlight and release readiness

**Build**

- Signed/notarized Mac helper and signed iOS app.
- Automatic bridge update strategy with compatibility rollback.
- Onboarding, diagnostics, privacy labels, support, and recovery flows.
- TestFlight matrix across supported iPhones, iOS versions, Wi-Fi/cellular transitions, and Mac sleep/restart.

**Exit gate**

- Source tests, simulator tests, physical-device tests, signing, notarization, TestFlight installation, and live remote behavior are reported separately.
- No source-only or simulator-only evidence is called release proof.

## 16. Verification matrix

| Layer | Required verification |
|---|---|
| Domain | Slot precedence, thread state, approval lifecycle, read cursor, reconnect state |
| Protocol | Golden JSON fixtures, unknown fields, version negotiation, malformed frames, idempotency |
| Codex contract | Generated schema diff and integration suite against every supported Codex version |
| Security | Pairing expiry, key mismatch, replay, revocation, cross-project denial, request-digest mismatch, log redaction |
| Networking | Packet loss, latency, Wi-Fi/cellular switch, host IP change, suspension, reconnect, stale cursor |
| UI | Dynamic Type, VoiceOver, Reduce Motion, contrast, long titles, large diffs, rapid events |
| Performance | Launch, pairing, time-to-snapshot, event-to-pixel latency, scrolling FPS, memory, battery |
| Release | Physical iPhone, real Mac, signed helper, notarization, TestFlight, fresh install, update, rollback |

## 17. Product decisions

Resolved:

1. The custom Codex Micro interface is valuable enough to continue beyond the official Remote option.
2. The IDE-hosted Codex sessions reported by app-server with source `vscode` are the intended phone-controlled conversations.

Still to decide before the affected release phase:

3. Is the first release personal/TestFlight, or intended for the public App Store?
4. Is requiring Tailscale acceptable for remote v1?
5. Which minimum iOS and macOS versions should be supported?
6. Should v1 allow starting new threads, or begin read/approve/respond-only for a smaller security surface?
7. Is on-device-only transcription a hard privacy requirement, even when a language/locale is unavailable?

## 18. Recommended immediate next step

Begin Phase 2 **Step 2.2**: strict wire contracts and the journal epoch in `CompanionProtocol`, under the accepted threat model and transport ADR. Keep the phone protocol semantic, enforce the Mac-side capability ceiling independently, and open no listener until the plan's dependency chain reaches Step 2.7 with the ADR's exact pins and constants.

## 19. Official references

- [Codex Micro](https://learn.chatgpt.com/docs/features/codex-micro.md)
- [Remote connections](https://learn.chatgpt.com/docs/remote-connections.md)
- [Codex App Server](https://learn.chatgpt.com/docs/app-server.md)
- [Open-source Codex app-server implementation](https://github.com/openai/codex/tree/main/codex-rs/app-server)
