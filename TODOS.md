# TODOS

Deferred work with enough context to pick up cold. Format: What / Why / Pros / Cons / Context / Depends on.

## Record the 30-second exposure-report demo GIF

- **Priority:** P1
- **What:** Record a terminal GIF of the exposure report finding an actively-exploited CVE, and link it from README.md.
- **Why:** It's the M1 deliverable that makes the tool legible in three seconds to anyone scrolling the repo or a post. The sample report (`examples/exposure-report.md`) carries the same content as text, but a GIF is what travels.
- **Pros:** Turns the front door from "read this" into "watch this"; reusable in a talk or writeup.
- **Cons:** Human capture step (asciinema/terminalizer + gif conversion); needs a re-record whenever the report layout changes materially.
- **Context:** Deferred from the M1 ship (2026-07-26) — a recording is a human step, not code. Everything needed is already deterministic. Record against the fixtures so the demo never depends on live feeds:
  ```bash
  python3 templates/discovery/exposure-report.py \
    --watchlist tests/fixtures/watchlist-fixture.json \
    --inventory tests/fixtures/inventory-fixture.jsonl \
    --osv tests/fixtures/osv-confirmed.json \
    --kev tests/fixtures/kev-fixture.json \
    --feed tests/fixtures/pulse-fixture.json \
    --now 2026-07-26 --out /tmp/demo && cat /tmp/demo/exposure-report.md
  ```
- **Depends on:** nothing — ready to record now.

## NVD or vendor-advisory fallback for proprietary agentic products

- **What:** Add an advisory source covering closed-source products (Cursor, Windsurf) whose CVEs never reach OSV.
- **Why:** OSV covers open-source distribution channels but has no data for closed-source apps, so those products are matched against CISA KEV and the pulse feed only and carry a permanent "limited coverage" note in every report — real CVEs in two flagship examples go unseen.
- **Pros:** Closes the largest honest coverage gap; "limited coverage" notes become rare.
- **Cons:** NVD unauthenticated rate limits pressure the report's <60s no-auth criterion; vendor-advisory scraping is per-vendor maintenance.
- **Context:** Tracked as an open question in the design doc ("Proprietary-product coverage"). Start point: NVD API 2.0 with optional API key, or per-vendor advisory JSON where a vendor publishes one.
- **Depends on:** M1 (exposure-report) shipped, so the source abstraction exists to plug into.

## Scorecard "exposure" dimension

- **What:** Add a live-exposure dimension to the crawl/walk/run maturity scorecard, fed by the exposure report.
- **Why:** Turns the scorecard from "how hardened am I" into "how hardened am I AND am I currently exposed."
- **Pros:** Deepens the repo's front door; enables an "exposure: 0 confirmed" badge story.
- **Cons:** Drags the maturity model, the skill's Control Catalog, and the checklist sync along with it (CLAUDE.md requires keeping those aligned) — deliberately backlogged out of M2 during the 2026-07 eng review for exactly this reason.
- **Context:** Deferred in the design doc's M2 milestone note. Start point: define crawl/walk/run for exposure (e.g., crawl = report exists; walk = zero unresolved confirmed; run = feed-watching cadence in place).
- **Depends on:** M2 feed contract (`agentic-cves.json`).
