# Codex Micro — Device Parity Specification

**Status:** Product definition. Pad UI and controls are largely **built**; physical parity acceptance is **not** complete. See [STATUS.md](STATUS.md) and [PHASE_3_PLAN.md](PHASE_3_PLAN.md).

**Purpose:** This project replicates **OpenAI's Codex Micro** — a physical macropad, released 15 July 2026, built with Work Louder, priced at $230 and currently sold out — as an iPhone app that controls Codex on a paired Mac. The phone is meant to *be* the device: the same controls, the same feedback, the same effect on Codex.

Phases 0–2 are the secure plumbing. Phase 3 is the device surface. This document is the product specification.

---

## 1. The device

| Control | Count | What it does |
|---|---|---|
| **Agent Keys** | 6 | Frosted keys with RGB LEDs, each bound to one live Codex thread. Colour reports whether that agent is thinking, running, waiting, or finished. Pressing one switches to that conversation. |
| **Command Keys** | 7 (of 13 total switches) | Accept changes, reject output, new chat, push-to-talk, and custom commands. |
| **Rotary dial** | 1 | Adjusts the agent's **reasoning depth**, turnable mid-task — raise it for a hard problem, lower it to stay fast. |
| **Joystick** | 1 | Invokes common workflows: review a pull request, debug, refactor. |
| **Touch sensor** | 1 | Auxiliary input. |

Connects over Bluetooth or USB-C to Windows or macOS. Every control is remappable; the box ships 32 icon keycaps.

The essential idea is **peripheral vision and thumb reach**: you see what six agents are doing without reading anything, and you steer them without moving your hands to the mouse. A replica that loses either property has missed the point, however faithfully it copies the layout.

---

## 2. What already exists

The transport half is complete and physically proven. A real iPhone 13 pairs with the Mac over real Wi-Fi, using its own Secure Enclave key, over TLS 1.3 against a pinned SPKI, and the Mac stores an authoritative grant.

| Device capability | Status | Where |
|---|---|---|
| Connection to the desktop | **Done** — secure LAN bridge replaces BT/USB-C | Phase 2 |
| Live per-thread status | **Done** — filtered observation snapshots and event replay | Step 2.8 |
| Thread status vocabulary | **Done** — `CompanionThreadStatus`, `CompanionTurnStatus` | Step 2.2 |
| Stop / interrupt an agent | **Done** — `interruptTurn` | Step 2.9 |
| Send a prompt | **Done** — `sendPrompt` | Step 2.10 |
| Steer a running turn | **Done** — `steerTurn` | Step 2.11 |
| Mark a thread read | **Done** — `markThreadRead` | Step 2.9 |
| Scoping to permitted projects | **Done** — device grants, revocation, authorized views | Steps 2.4b, 2.8 |

**The status data the Agent Key LEDs need already crosses the wire.** That is the single most valuable thing already in place: the hard part of an ambient status display is a trustworthy, scoped, replay-safe feed, and that exists.

---

## 3. What still needs work (honest inventory)

| Area | State |
|---|---|
| Agent key grid + live status colors | **Built** — needs granted projects + live threads |
| Agent key binding | **Built** — auto-fill, pinned slots |
| Command keys (stop / steer / mark-read) | **Built** — mark-read sequence still buggy |
| Prompt / PTT / joystick | **Built** |
| Reasoning dial UI | **Built** — effort not fully applied on every turn path |
| New chat / startThread | **Gateway ready** — default pad layout may omit New |
| Approvals accept/reject | **Contracts + UI shell** — live pending feed incomplete |
| Remapping | **Sheet stores layout** — pad may not fully apply it |
| Visual pulse / hardware polish | **Partial** |
| Mac grant / project admin | **Built** — required after every pair |
| Physical parity acceptance | **Not done** |

### Still deliberate non-goals for v1

- Full chat transcript / plan text / diffs on the phone (status LEDs only unless a future redacted progress sheet is approved).
- Phone-held credentials or phone-side tool execution.

---

## 4. Sequencing

Ordered by what unblocks the most, not by what is easiest.

1. **Agent Key grid with live status.** Uses the observation feed that already works end to end. This is the first build where the phone looks like the device, and it needs no new protocol.
2. **Command keys for what is already implemented** — interrupt, send prompt, steer, mark read. Also no new protocol.
3. **Reasoning dial.** Needs the protocol change in §3.2 and a live-Codex probe before it can be trusted.
4. **Joystick workflows.** Prompt macros over `sendPrompt`.
5. **New chat**, if the Step 2.12 deferral is reversed.
6. **Approvals**, as Phase 4 already schedules — the accept/reject keys.
7. **Push-to-talk and remapping.**

---

## 5. V2 — a multi-model harness

Recorded, not started, and deliberately out of scope until parity is real.

The intent is to put Claude into the same harness and generalise beyond Codex: Ollama, OpenAI, Claude, and OpenRouter models behind one interface, so the app becomes a full coding environment with skills rather than a remote control for one vendor's agent.

Two things are worth writing down now, while the boundaries are still cheap to move:

- **The command gateway is already model-agnostic in shape.** It speaks semantic commands — interrupt, prompt, steer — not Codex RPC. The Codex specifics live behind `CodexRuntimeSession`. A second backend is a second implementation of that seam, not a rewrite.
- **The authorization model is not vendor-specific and should stay that way.** Grants, project scoping, capability ceilings, and action profiles describe *what a phone may cause to happen*, which is a question independent of which model answers. Nothing about V2 should require weakening them.

The genuinely new work in V2 is model and provider selection, per-provider credentials, and reconciling capability differences — none of which the current design forecloses.

---

## Sources

- [OpenAI × Work Louder — Supply Co-Lab](https://openai.com/supply/co-lab/work-louder/)
- [Axios — Codex Micro is a physical keyboard for AI agents](https://www.axios.com/2026/07/15/openai-keyboard-codex-agents)
- [Tom's Hardware — 13 low-profile keys and a joystick](https://www.tomshardware.com/peripherals/keyboards/openais-first-hardware-device-is-an-rgb-macropod-codex-micro-features-13-low-profile-keys-and-a-joystick-for-controlling-ai-coding-agents)
- [Hackster.io — a $230 physical controller for AI agents](https://www.hackster.io/news/openai-s-codex-micro-is-a-230-physical-controller-for-ai-agents-7cc96d5f63e6)
