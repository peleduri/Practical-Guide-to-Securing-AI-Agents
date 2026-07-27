#!/usr/bin/env bash
# Pane 1 of the PoCumentary demo: the READ-ONLY discovery scan, run for real on
# whatever machine is recording. Nothing here is faked — this is the same
# templates/discovery/inventory-agents.sh the guide ships.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
beat="${DEMO_STEP_DELAY:-1.5}"

printf '\033[1m$ bash templates/discovery/inventory-agents.sh --json\033[0m\n\n'
sleep "$beat"

inv="${DEMO_RUNTIME_DIR:-/tmp}/inventory.jsonl"
bash "$repo/templates/discovery/inventory-agents.sh" --json > "$inv" 2>/dev/null

printf 'Read-only scan complete. Found on THIS machine:\n\n'
if command -v jq >/dev/null 2>&1; then
  jq -r '.kind' "$inv" 2>/dev/null | sort | uniq -c | sort -rn | head -6 \
    | awk '{printf "    %4d  %s\n", $1, $2}'
else
  printf '    %s findings\n' "$(wc -l < "$inv" | tr -d ' ')"
fi
printf '\n    %s total findings -> inventory.jsonl\n' "$(wc -l < "$inv" | tr -d ' ')"
sleep "$beat"

printf '\nNothing was changed. Nothing was sent.\n'
touch "${DEMO_RUNTIME_DIR:-/tmp}/inventory_ready"
sleep 600   # hold the pane so the finished output stays on screen
