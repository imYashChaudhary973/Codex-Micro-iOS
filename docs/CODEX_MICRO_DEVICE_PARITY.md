# Codex Micro — Device Parity Specification

**Status:** Specification. Nothing in this document is implemented as UI yet.

**Purpose:** This project replicates **OpenAI's Codex Micro** — a physical macropad, released 15 July 2026, built with Work Louder, priced at $230 and currently sold out — as an iPhone app that controls Codex on a paired Mac. The phone is meant to *be* the device: the same controls, the same feedback, the same effect on Codex.

Everything built in Phases 0–2 is the plumbing that makes this possible. It is not the product. This document is the product specification, and it exists because that distinction was implicit until now and cost a full phase of framing.

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

## 3. What is missing

### 3.1 The device surface itself

Nothing resembling the macropad exists on the phone. The acceptance host has a pairing screen and an acceptance-matrix checklist. There is no agent-key grid, no dial, no joystick, no command keys.

This is the bulk of the remaining product work and none of it is blocked by anything.

### 3.2 Reasoning depth — the dial's entire function

**No reasoning-level parameter exists anywhere in this codebase.** `PhoneTurnPolicy` resolves sandbox, writable roots, network access, and approval policy — all Mac-decided — and carries nothing about reasoning effort. `turn/start` and `turn/steer` are sent without it.

The dial is the device's most distinctive control and it currently has nothing to talk to. This needs:

- a reasoning-depth field on the turn policy, with the Mac deciding the permitted range;
- the phone able to *request* a level within that range, since the device changes it mid-task;
- verification against a live Codex that `turn/start` and `turn/steer` accept it, because the last two app-server parameters written from documentation alone were both wrong in ways only a live probe found.

### 3.3 Agent Key binding

Six slots must map to six live threads, and the mapping has to survive reconnects, respect the device's project scope, and behave sensibly when a bound thread ends or a seventh appears. None of that exists.

### 3.4 Two capabilities blocked by earlier decisions

Both are visible buttons on the device, and both were deliberately closed off:

- **Accept changes / reject output.** Approvals were rejected throughout Phase 2 and assigned to Phase 4. This is the largest security surface in the product: an approval is the moment a phone tap authorises a real filesystem or network action. The device has two dedicated keys for it.
- **New chat.** `startThread` was deferred at Step 2.12 by explicit decision, behind a Mac feature toggle if v1 allows new threads at all.

Device parity requires revisiting both. Neither should be reopened casually — the Phase 2 reasoning for deferring them was sound — but "the device has a button for it" is a new and legitimate input to those decisions.

### 3.5 Smaller gaps

- **Joystick workflows.** Review-PR, debug, and refactor are canned prompts. Cheap once `sendPrompt` is reachable from a UI.
- **Push-to-talk.** Speech capture and transcription; an entirely new surface.
- **Remapping.** Every control on the device is remappable, and the 32 keycaps exist so the layout matches a workflow. A faithful replica needs the same, which is easier in software than in hardware.

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
