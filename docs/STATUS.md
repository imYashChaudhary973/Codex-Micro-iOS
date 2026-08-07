# Codex Micro — Status

**Snapshot:** 2026-08-07  
**Branch focus:** end-to-end usability (grant admin + command path)

## What works

- Mac menu-bar bridge starts Codex runtime and can enable LAN.
- Pairing (QR + SAS) stores a device grant on the Mac and pins on the phone.
- Authenticated sealed session + observation subscribe.
- Phone Device pad: agent keys, commands, dial, joystick, PTT, remapping UI.
- Command gateway can reach live Codex when grants and runtime allow it.
- **Grant Project to Phone…** Mac menu action registers a folder, widens scope, adopts recent threads.

## What users usually hit

| Symptom | Fix |
|---|---|
| Keys dark after pair | Mac → **Grant Project to Phone…** for the work folder |
| Not connected | Enable LAN; same Wi‑Fi; Local Network permission; re-pair if needed |
| Commands greyed | Grant includes `interrupt` / `runAgent` (admin path does); select a lit agent key |
| No agent “progress text” | By design for v1: LEDs show status only, not chat/diffs |

## Not claimed yet

- Formal Phase 3 physical parity acceptance (3.13).
- Host-push observation (phone soft-refreshes while empty as mitigation).
- Live approvals delivery to the phone.
- Durable command ledger in live composition (still in-memory in places).
- Perfect hardware visual polish (pulse, full remapped layout on pad).

## Docs policy

Keep only product-relevant living docs (see README). Phase 0–2 status logs are historical evidence, not the product front door.
