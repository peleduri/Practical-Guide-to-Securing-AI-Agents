#!/usr/bin/env bash
# Pane 2: match the inventory against advisory data and render the report.
#
# Advisory feeds are REPLAYED from tests/fixtures via --osv/--kev/--feed so the
# recording is deterministic and shows the same finding every take. Those flags
# are a shipped feature, not demo scaffolding: the identical command without them
# queries OSV.dev, CISA KEV and zero-day-pulse live. The caption track says so
# on screen — a demo of an honesty-first tool should not overstate itself.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
fx="$repo/tests/fixtures"
beat="${DEMO_STEP_DELAY:-1.5}"
out="${DEMO_RUNTIME_DIR:-/tmp}/report"

printf '\033[1m$ python3 exposure-report.py --inventory inventory.jsonl\033[0m\n\n'
sleep "$beat"
printf 'Matching against OSV.dev / CISA KEV / zero-day-pulse (replayed)...\n\n'
sleep "$beat"

python3 "$repo/templates/discovery/exposure-report.py" \
  --watchlist "$fx/watchlist-fixture.json" \
  --inventory "$fx/inventory-fixture.jsonl" \
  --osv "$fx/osv-confirmed.json" \
  --kev "$fx/kev-fixture.json" \
  --feed "$fx/pulse-fixture.json" \
  --now 2026-07-26 --out "$out" >/dev/null 2>&1
rc=$?

# Print the report a line at a time so a viewer can actually read it.
while IFS= read -r line; do printf '%s\n' "$line"; sleep 0.12; done \
  < <(sed -n '1,34p' "$out/exposure-report.md")

printf '\n\033[1mexit code: %s\033[0m  (0 = full scan, 2 = degraded, 3 = no report)\n' "$rc"
touch "${DEMO_RUNTIME_DIR:-/tmp}/report_ready"
sleep 600
