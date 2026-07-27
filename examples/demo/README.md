# Demo recording — the exposure report, in two terminals

The spec behind the demo recording of [`scripts/assess.sh`](../../scripts/assess.sh)'s
exposure step. Built with [PoCumentary](https://github.com/pillar-labs/pocumentary),
a spec-driven CLI for narrated multi-terminal recordings, so the take is
**reproducible**: the demo is declared in [`demo.toml`](demo.toml) rather than
performed by hand, and captions anchor to demo *events* instead of wall-clock
seconds, so the wording can be reworded without re-recording.

| Pane | What it runs | Real or replayed |
|------|--------------|------------------|
| `1  DISCOVER` | [`inventory-agents.sh --json`](../../templates/discovery/inventory-agents.sh) | **Real** — scans the recording machine, read-only |
| `2  EXPOSURE` | [`exposure-report.py`](../../templates/discovery/exposure-report.py) | **Replayed** advisory feeds, so every take is identical |

## Why the feeds are replayed

The exposure pane passes `--osv/--kev/--feed/--now`, which replay advisory data
from [`tests/fixtures/`](../../tests/fixtures/). Those flags are a shipped
feature, not demo scaffolding: they exist so CI is deterministic and socket-free,
and the identical command without them queries OSV.dev, CISA KEV and
[zero-day-pulse](https://github.com/peleduri/zero-day-pulse) live.

Replaying keeps the recording honest in the other direction too. A live take
would show whatever happens to be true on the recording machine that day, which
is usually nothing — and a demo that has to get lucky to be interesting invites
staging the machine instead. The caption track states on screen that the feeds
are replayed.

## Run it

Requires PoCumentary, plus `ffmpeg` and macOS Screen Recording permission for
the `record` step. Everything except `record` runs anywhere.

```bash
# from a PoCumentary checkout, pointing at this spec
uv run pocu validate <guide>/examples/demo/demo.toml   # schema only, no screen
uv run pocu dryrun   <guide>/examples/demo/demo.toml   # headless; PASSes only if the report renders
uv run pocu record   <guide>/examples/demo/demo.toml   # the take -> .mov + timeline

# then either burn the captions in, or speak them
uv run pocu annotate <guide>/examples/demo/demo.toml exposure-report-demo-<stamp>.mov
uv run pocu narrate  <guide>/examples/demo/demo.toml exposure-report-demo-<stamp>.mov
```

`dryrun` is the cheap loop and the one that matters for maintenance: `[verify]`
expects the `report_ready` signal, which the exposure pane only emits after the
report renders, so a dryrun fails if the pipeline breaks. Re-run it after any
change to discovery, the matcher, or the watchlist — a demo that quietly stopped
working is worse than no demo.

## What the recording shows

Discovery finds the agent CLIs, MCP servers, local model runtimes and extension
supply chain on the machine, changing nothing. The exposure pane then matches
each installed version against the advisory sources and renders the report: one
`confirmed` finding corroborated by CISA KEV (so genuinely exploited in the
wild), with the fix and the guide control that mitigates the class, and one
`possible` finding that is deliberately *not* escalated because KEV carries no
version data. The closing caption lands the actual product: the report never
says "clean", and every run ends by listing what it cannot see.
