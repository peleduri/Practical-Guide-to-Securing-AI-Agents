# TODOS

Deferred work with enough context to pick up cold. Format: What / Why / Pros / Cons / Context / Depends on.

## Record the exposure-report demo

- **Priority:** P1
- **What:** Run `pocu record` against [`examples/demo/demo.toml`](examples/demo/demo.toml), burn or speak the captions, and link the result from README.md.
- **Why:** It's the M1 deliverable that makes the tool legible in seconds to anyone scrolling the repo or a post. The sample report carries the same content as text, but a recording is what travels.
- **Pros:** Turns the front door from "read this" into "watch this"; reusable in a talk or writeup. The spec is declarative, so re-recording after a layout change is one command, not a re-performance.
- **Cons:** `record` needs macOS plus ffmpeg plus Screen Recording permission for the terminal, which is a human grant. Optional spoken narration needs an ElevenLabs key or the on-device fallback.
- **Context:** The spec, the two role scripts, and a README are committed under `examples/demo/`, built with [PoCumentary](https://github.com/pillar-labs/pocumentary). `uv run pocu dryrun examples/demo/demo.toml` already PASSes headless, so the pipeline is proven; only the on-screen take is left. Pane 1 scans the recording machine for real; pane 2 replays advisory feeds from `tests/fixtures/` so every take is identical, and the captions say so on screen. Deliberately a narrated `.mov`/`.webm` rather than a GIF: GitHub renders video inline, and the caption track carries the honesty framing that is the actual product.
- **Depends on:** nothing — the spec is ready; run `record` on a macOS machine with the permission granted.

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
