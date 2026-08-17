# Status

**Snapshot:** 2026-08-17  
**Current focus:** Phase 3 device parity acceptance.

## State

| Layer | Status |
|---|---|
| Codex app-server integration | Accepted |
| Mac bridge core | Accepted |
| Secure LAN pairing + WSS | Built; physically proven on Mac |
| Phone device pad UI | Built; not yet parity-accepted |
| Grant / project administration | Required after pair |
| Phase 3 physical parity acceptance | Matrix ready; full run pending |

## Quick fixes

| Symptom | Fix |
|---|---|
| Keys dark after pair | Mac → **Grant Project to Phone…** for the work folder |
| Not connected | Enable LAN; same Wi‑Fi; Local Network permission; re-pair if needed |
| Commands greyed | Grant includes `interrupt` / `runAgent`; select a lit agent key |
| No agent progress text | By design for v1: status LEDs only |

## Remaining gates

- Run the Phase 3 parity acceptance matrix on a physical iPhone.
- Host-push observation (phone currently soft-refreshes when empty).
- Live approvals delivery to the phone.
- Finish durable command ledger in live composition.

## Docs

Living docs live in `docs/`. Historical phase evidence lives in `docs/archive/`. Security references live in `docs/reference/`.
