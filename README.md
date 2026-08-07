# Codex Micro

iPhone pad that controls **Codex on your Mac** — same idea as OpenAI’s physical Codex Micro: six glanceable agent keys, command keys, reasoning dial, joystick workflows, push-to-talk. The Mac stays the authoritative host; the phone never holds your OpenAI credential and never runs tools itself.

## Current truth

| Layer | Status |
|---|---|
| Codex app-server integration | Working (pinned CLI/schema gate) |
| Mac bridge core | Accepted |
| Secure LAN pairing + WSS | Built; physical pairing proven |
| Phone device pad UI | Built (not yet formally parity-accepted) |
| **Grant / project admin** | **Required after pair** — use **Grant Project to Phone…** in the Mac menu |
| Physical parity acceptance | Matrix exists; full run pending |

If the phone is connected but all keys stay dark, you almost always need to **grant a project** on the Mac. Pairing alone intentionally grants observe with an empty project list.

## Run it (personal Mac + iPhone)

### Mac

1. Install a supported Codex CLI (bridge gates on the pinned version/schema).
2. Build and run the menu-bar bridge (`codex-micro-bridge` or the Xcode Mac host).
3. Menu → **Enable LAN Access** (off on every launch by design).
4. **Pair a Device…** — show QR; confirm the phrase on both sides.
5. **Grant Project to Phone…** — pick the folder your Codex work lives in.
6. Keep a Codex thread active in that project (IDE or CLI).

### iPhone

1. Install and open the signed AcceptanceHost app (product surface: **Device** tab).
2. **Pair** tab → scan QR → confirm phrase.
3. **Device** tab — agent keys should light for sessions in the granted project.
4. Select a key; use Stop / Steer / Talk / joystick as capabilities allow.

Status line meanings:

- **Not paired** — complete Pair tab first  
- **Connected — grant a project on the Mac** — pair worked; Mac admin step missing  
- **Connected · N session(s)** — observation is live  

### Diagnostics

Mac stderr: `codex-micro: …`  
Phone stderr: `device: …`  

## Development commands

```bash
swift test
swift run codex-micro-bridge
swift run codex-micro-spike compatibility
swift run codex-micro-spike doctor
```

Live smoke turns spend Codex allowance and need explicit confirm flags (see spike help).

## Docs (living)

| Doc | Role |
|---|---|
| [Device parity](docs/CODEX_MICRO_DEVICE_PARITY.md) | What the product is (controls, invariants) |
| [Phase 3 plan](docs/PHASE_3_PLAN.md) | Delivery steps until physical acceptance |
| [Threat model](docs/THREAT_MODEL.md) | Security baseline |
| [Transport ADR](docs/PHASE_2_TRANSPORT_ADR.md) | TLS / WSS / identity decisions |
| [Git workflow](docs/GIT_WORKFLOW.md) | Branch / PR rules |
| [Status](docs/STATUS.md) | One-page snapshot |

Historical phase evidence lives under `docs/archive/` when present, or in git history.

## Architecture in one paragraph

Phone pairs over LAN (QR + short authentication string), pins the Mac TLS SPKI, and opens a sealed session. Observation delivers **status-only** thread projections scoped by Mac grants. Commands go through one gateway (`sendPrompt`, `interrupt`, `steer`, `startThread`, …) with Mac-resolved sandbox and project policy. Approvals remain opt-in and highest privilege.

## Out of scope (for now)

- Full chat transcript / model token stream on the phone  
- Multi-model backends (Claude, Ollama, …)  
- Cloud relay; App Store distribution  
