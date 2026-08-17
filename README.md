:# Codex Micro

iPhone pad that controls **Codex on your Mac** — the same idea as OpenAI's physical Codex Micro: six glanceable agent keys, command keys, a reasoning dial, joystick workflows, and push-to-talk. The Mac stays the authoritative host; the phone never holds your OpenAI credential and never runs tools itself.

## Current state

| Layer | Status |
|---|---|
| Codex app-server integration | Accepted |
| Mac bridge core | Accepted |
| Secure LAN pairing + WSS | Built; physical pairing proven on Mac |
| Phone device pad UI | Built; not yet parity-accepted |
| Grant / project admin | **Required after pair** |
| Phase 3 physical parity acceptance | Matrix ready; full run pending |

If the phone is connected but all keys stay dark, you almost always need to **grant a project** on the Mac. Pairing alone intentionally grants only `observe` with an empty project list.

## Run it (personal Mac + iPhone)

### Mac

1. Install a supported Codex CLI (the bridge gates on a pinned version/schema).
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

- **Not paired** — complete the Pair tab first.
- **Connected — grant a project on the Mac** — pair worked; the Mac admin step is missing.
- **Connected · N session(s)** — observation is live.

### Diagnostics

- Mac stderr: `codex-micro: …`
- Phone stderr: `device: …`

## Development commands

```bash
swift test
swift run codex-micro-bridge
swift run codex-micro-spike compatibility
swift run codex-micro-spike doctor
```

Live smoke turns spend Codex allowance and need explicit confirm flags (see spike help).

## Documentation

| Doc | What it covers |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | Current state and remaining gates |
| [docs/PRODUCT.md](docs/PRODUCT.md) | Product definition: controls, invariants, parity |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phase 3 delivery plan |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System overview and package targets |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model summary |
| [docs/GIT_WORKFLOW.md](docs/GIT_WORKFLOW.md) | Branch, commit, and PR rules |
| [docs/reference/THREAT_MODEL.md](docs/reference/THREAT_MODEL.md) | Accepted Phase 2 threat model |
| [docs/reference/TRANSPORT_ADR.md](docs/reference/TRANSPORT_ADR.md) | Accepted Phase 2 transport/TLS/identity ADR |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Phase acceptance history |

Historical phase evidence lives in `docs/archive/`. See `docs/README.md` for the docs index.

## Architecture in one paragraph

The phone pairs with the Mac over the same LAN (QR + short authentication string), pins the Mac TLS SPKI, and opens a sealed session. The Mac delivers **status-only** thread projections scoped by its grants. Commands flow through a single gateway (`sendPrompt`, `interrupt`, `steer`, `startThread`, …) with Mac-resolved sandbox and project policy. Approvals remain opt-in and the highest-privilege action in the product.

## Out of scope (for now)

- Full chat transcript / model token stream on the phone.
- Multi-model backends (Claude, Ollama, …).
- Cloud relay; App Store distribution.
