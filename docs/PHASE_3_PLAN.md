# Phase 3 — Device Parity Plan

**Status:** Approved for execution.

**Goal:** The iPhone becomes the Codex Micro. Same controls, same feedback, same effect on Codex.

**Scope:** The device surface and every control on it — six agent keys, the command keys, the reasoning dial, the joystick, push-to-talk, and remapping. Phase 2's transport is the foundation and is not revisited except where a control needs something the protocol does not yet carry.

---

## 1. What "parity" means here

The device's value is not its layout. It is **peripheral vision and thumb reach**: you see what six agents are doing without reading, and you steer them without moving your hands. A replica that copies the arrangement but loses either property has missed the point.

Two consequences shape every step below.

**Status must be glanceable, not readable.** An agent key communicates by colour and motion before any text is parsed. That constrains the design more than it sounds: it means status has to be correct *continuously*, not on refresh, and a stale key is worse than a blank one because it reports confidently and wrongly.

**A control must act immediately or say why it cannot.** The hardware has no spinner. A key press either does the thing or the key tells you it is unavailable. Anything that leaves the user wondering whether the tap registered is a parity failure even if the command eventually succeeds.

### Visual direction

Hardware-faithful: a 13-key grid with six glowing agent keys, a rotary dial, and a joystick pad, so muscle memory transfers from the device.

```text
┌─────────────────────────┐
│  ●  ●  ●   ← agent keys │
│  ●  ●  ●     (RGB glow) │
│                         │
│  [◀] [▶] [■] [✓]        │
│                         │
│    ◎ dial    ✛ stick    │
└─────────────────────────┘
```

Native iOS sheets are used only where the hardware has no equivalent — prompt text entry, settings, remapping — because inventing a hardware metaphor for typing helps nobody.

---

## 2. Invariants

Phase 2's invariants all still hold. Phase 3 adds five.

1. **A key never lies about state.** An agent key shows what the Mac last told this device, and shows explicitly when that is stale or unknown. It never guesses, never interpolates, and never keeps a colour after the connection drops.
2. **Every control maps to an existing authorization.** A new control is not a new permission. If a device may not do something, its key is visibly unavailable rather than present-and-failing.
3. **The Mac decides, the phone requests.** Unchanged from Phase 2 and extended to the dial: the phone asks for a reasoning level, the Mac clamps it to what the grant permits.
4. **Approval is the highest-privilege action in the product and is treated as such.** It gets its own contracts, its own capability, its own audit trail, and its own acceptance case. It is never bundled into a step with anything else.
5. **Voice input is text by the time it reaches the protocol.** Push-to-talk produces a prompt string on the phone. No audio crosses the wire, and the command path cannot tell the difference.

---

## 3. Dependency chain

```text
3.1 Device shell + agent key grid (observation-driven)
 └─▶ 3.2 Agent key binding
      └─▶ 3.3 Command keys for existing commands
           └─▶ 3.4 Prompt entry + sendPrompt
                └─▶ 3.5 Reasoning depth protocol + live probe
                     └─▶ 3.6 Reasoning dial
                          └─▶ 3.7 Joystick workflows
                               └─▶ 3.8 New chat (reverses the 2.12 deferral)
                                    └─▶ 3.9a Approval contracts + authority
                                         └─▶ 3.9b Approval execution
                                              └─▶ 3.10 Accept / reject keys
                                                   └─▶ 3.11 Push-to-talk
                                                        └─▶ 3.12 Remapping
                                                             └─▶ 3.13 Parity acceptance
```

Nothing skips a predecessor. The ordering is by what unblocks the most, and it deliberately puts every control that already has a working protocol before every control that needs a new one.

---

## 4. Steps

| Step | Branch | What lands | Merge gate |
|---|---|---|---|
| **3.1** | `feat/device-shell` | The 13-key surface, six agent keys driven by the live observation feed, colour per thread status, explicit stale and disconnected states. | Suite green; a key shows stale rather than a held colour when the feed stops. |
| **3.2** | `feat/agent-key-binding` | Six slots bound to threads, surviving reconnect, respecting project scope, sane when a bound thread ends or a seventh appears. | Binding survives a reconnect; an out-of-scope thread can never occupy a slot. |
| **3.3** | `feat/command-keys` | Keys for interrupt, steer, mark-read. Unavailable rather than failing when the grant lacks the capability. | Each key's disabled state matches the device's actual capability set. |
| **3.4** | `feat/prompt-entry` | Prompt sheet over `sendPrompt`, with the selected agent key as target. | A prompt reaches the right thread; a prompt to an unbound key is impossible. |
| **3.5** | `feat/reasoning-protocol` | Reasoning depth on the turn policy, Mac-clamped, plus a **live Codex probe**. | Live probe passes. Written-from-documentation parameters are not trusted — two were wrong. |

**Corrected during 3.5 by reading the app-server's generated schema.** The field is `effort`, not `reasoningEffort`, and it is an opaque string the model advertises rather than a fixed enum — `ReasoningEffort` is documented as "a non-empty reasoning effort value advertised by the model", with each model publishing its own `supportedReasoningEfforts`.

More importantly, **`TurnSteerParams` has no effort field at all.** The hardware's dial is described as turnable mid-task; on this surface, `TurnStartParams.effort` overrides "for this turn and subsequent turns", so a change made while a turn is running takes effect on the next one. The dial must say so rather than implying it retunes the turn in flight. That is a real difference from the hardware and it is recorded rather than papered over.
| **3.6** | `feat/reasoning-dial` | The rotary control, showing the effective level and **when it takes effect**. | Turning past what the host permits is visibly refused rather than silently substituted. |
| **3.7** | `feat/joystick-workflows` | Directional workflows — review PR, debug, refactor — as prompt macros. | Each direction sends the documented prompt to the bound thread. |
| **3.8** | `feat/new-chat` | `startThread` behind the Mac toggle the 2.12 deferral specified. | Mac chooses project and sandbox; the phone supplies only a prompt. |
| **3.9a** | `feat/approval-contracts` | Device-facing approval payloads, an `approve` capability, and the authority rules for what a phone may resolve. **No execution.** | Approval content is scoped like observation; a device without the capability sees nothing. |
| **3.9b** | `feat/approval-execution` | Resolution through the command gateway, idempotent and ledgered like every other command. | A replayed approval executes once. A stale approval is refused. |
| **3.10** | `feat/approval-keys` | Accept and reject keys, with the pending approval visible before the tap. | It is impossible to approve something the screen did not show. |
| **3.11** | `feat/push-to-talk` | On-device speech to text, producing a prompt string. | No audio crosses the wire; the command path is unchanged. |
| **3.12** | `feat/remapping` | Every control remappable, matching the device's 32 keycaps. | A remap cannot grant a capability the device lacks. |
| **3.13** | `test/phase-3-acceptance` | Parity acceptance matrix on the physical iPhone. | Every control exercised against a real Mac over real Wi-Fi. |

---

## 5. The two reversals, recorded

Both were deliberate Phase 2 decisions. Both are reversed here because the device has dedicated keys for them, and a replica missing them is not a replica.

**`startThread` (Step 2.12 → 3.8).** Deferred because v1 might not allow new threads at all. It does now: the device's "new chat" key settles it. The deferral's own terms are honoured — a Mac feature toggle, Mac-chosen project and sandbox, phone supplies only the prompt.

**Approvals (Phase 4 → 3.9a/3.9b/3.10).** Deferred because an approval is the moment a phone tap authorises a real filesystem or network action, and Phase 2 deliberately kept that surface closed while the transport was unproven. The transport is now proven end to end on physical hardware, which removes the original reason to wait but none of the care required. It is split across three steps for the same reason 2.4 was split: contracts and authority land and are reviewed before anything can execute.

---

## 6. Execution

`docs/GIT_WORKFLOW.md` remains authoritative. One squash-merged PR per step, opened and merged in order, each carrying its own tests and a status-doc update. Merge only green: `swift test`, release build, strict format lint, and the relevant device build.

Steps 3.9a, 3.9b, and 3.10 additionally require the Phase 2 security review pass — trust boundaries, state transitions, replay and idempotency, storage failure, decoder strictness, logging, and resource bounds — because they extend the authorization model rather than consume it.

Phase 3 is accepted when 3.13 passes on a frozen `main` SHA. No parity claim before then.

## 7. Step 3.13 status

The matrix and its tooling are merged; **no physical case has been run.**

Eleven cases, each naming an observation a person makes rather than an assertion a machine makes. That split is deliberate: the protocol underneath is covered by over a thousand deterministic tests and a physical Phase 2 acceptance, and a case that could be automated belongs in the unit suite where most of them already are. What no test can answer is whether the *device* behaves like the device — whether a key tells the truth while you are looking at it, whether a control that cannot act says so before you press it, and whether the thing stays usable when the network does not.

The acceptance host is signed and installed on the iPhone 13. The run is blocked on the device being locked: `SBMainWorkspace` refuses to launch an app on a locked phone, which is correct behaviour rather than an obstacle — the device identity is `WhenUnlockedThisDeviceOnly`, so a locked phone could not sign a transcript regardless.

Phase 3 therefore stands as **built and deterministically verified, not accepted.** The distinction is the same one Phase 2 held to, and it is the whole reason the acceptance step exists as its own gate.
