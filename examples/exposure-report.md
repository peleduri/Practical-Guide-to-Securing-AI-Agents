# Agentic stack exposure report

Generated 2026-07-26 by exposure-report.py (schema v1). Read-only scan; no target binaries executed.

## Summary

- Products present: 2 of 2 watched
- Findings: 1 confirmed, 1 possible
- Actively exploited (KEV-corroborated): 1

## Findings

### CVE-2026-99999 — Ollama — ⚠ ACTIVELY EXPLOITED (CISA KEV, added 2026-06-20)

Remote code execution in Ollama server fixture

- Sources: kev, osv, pulse
- Advisory: <https://example.com/advisory>
- Pulse enrichment: [Ollama zero-day actively exploited (fixture)](https://example.com/pulse)
- Hardening (Ollama): `wiki/part-11-local-open-source-models.md` · control template `templates/detections/local-inference-endpoint.yml`

### CVE-2026-11111 — Cursor — POSSIBLE

Cursor workspace trust bypass (fixture)

- Sources: kev
- Hardening (Cursor): `wiki/part-2-endpoint-hardening-and-policy-playbook.md`

## Products

| Product | Present | Version | State |
|---------|---------|---------|-------|
| Cursor | yes | unknown | matched |
| Ollama | yes | 0.9.2 | matched |

## Coverage (what this scan can and cannot see)

- OSV: replay
- KEV: replay
- PULSE: replay
- Limited coverage (no OSV data; KEV+pulse name-matching only): Cursor
- Not visible to this scan: transitive dependencies, bundled runtimes (Electron/Chromium), install channels not in the watchlist, and products outside it. Absence of findings is **not** absence of risk.

