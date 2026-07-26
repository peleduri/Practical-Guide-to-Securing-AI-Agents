#!/usr/bin/env bash
# One-command local assessment. Runs the read-only discovery scan, summarizes it,
# and renders a STARTER posture scorecard — all locally, nothing changed, nothing
# sent, nothing committed. This is the "run it" front door: clone the repo and
#
#   bash scripts/assess.sh
#
# It is deliberately conservative. Discovery can only *measure* a couple of controls
# on its own (that an inventory exists, and whether a managed baseline is present).
# The rest default to "missing" until you confirm them — run the agentic-ai-hardening
# skill for the full assessment, which applies the assess rubric and asks about the
# controls that can't be measured from disk.
#
# PRIVACY: output goes to a LOCAL directory (default ./.agent-assessment, gitignored)
# and reflects THIS machine. Do not commit it. The scorecard itself is posture-only
# (safe to share); the inventory next to it is not.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
disc="$root/templates/discovery/inventory-agents.sh"
card="$root/skill/agentic-ai-hardening/scripts/scorecard.sh"
expo="$root/skill/agentic-ai-hardening/scripts/exposure-report.py"
out="${AGENT_ASSESSMENT_OUT:-$PWD/.agent-assessment}"

# Honest prerequisites: jq (inventory parsing + scorecard) and python3 (exposure
# matching). jq is hard-required; without python3 the exposure step is skipped
# with a loud note, never silently.
command -v jq >/dev/null 2>&1 || { echo "assess.sh: jq is required (brew install jq / apt-get install jq)" >&2; exit 1; }
[ -f "$disc" ] || { echo "assess.sh: discovery script not found at $disc — run this from a clone of the repo" >&2; exit 1; }
[ -f "$card" ] || { echo "assess.sh: scorecard renderer not found at $card" >&2; exit 1; }

mkdir -p "$out"
inv="$out/inventory.jsonl"
posture="$out/posture.json"
html="$out/scorecard.html"

echo "Running read-only discovery — nothing is changed, nothing is sent…" >&2
bash "$disc" --json > "$inv" 2>/dev/null

echo "Inventory written to $inv. Found:" >&2
jq -r '.kind' "$inv" 2>/dev/null | sort | uniq -c | sort -rn | sed 's/^/  /' >&2 || true

# Only what discovery can determine on its own. The managed-baseline probe (Part 2)
# reports PRESENT / PARTIAL / MISSING in its detail string.
baseline_detail="$(jq -r 'select(.kind=="baseline") | .detail' "$inv" 2>/dev/null | head -1)"
case "$baseline_detail" in
  PRESENT*) bstat="present" ;;
  PARTIAL*) bstat="partial" ;;
  *)        bstat="missing" ;;
esac
[ "$bstat" = "present" ] && maturity="walk" || maturity="crawl"

jq -n --arg b "$bstat" --arg m "$maturity" --arg d "$(date +%F)" '{
  maturity: $m,
  date: $d,
  next_control: "Push a managed hardening baseline users cannot loosen (Part 2)",
  controls: [
    { label: "Discovery inventory (agents + MCP servers)", status: "present" },
    { label: "Managed hardening baseline (Part 2)",        status: $b },
    { label: "Sanctioned-agent allowlist",                 status: "missing" },
    { label: "MCP server allowlist",                       status: "missing" },
    { label: "SIEM streaming of agent logs",               status: "missing" },
    { label: "Headless permission gate",                   status: "missing" }
  ]
}' > "$posture"

bash "$card" "$posture" > "$html" 2>/dev/null

# --- exposure step: local agentic inventory × live advisory sources -----------
# READ-ONLY like everything above; talks to OSV/KEV/pulse (or replay fixtures via
# EXPOSURE_REPORT_ARGS, which CI uses). Its exit code is captured and SURFACED:
# this script runs without `set -e`, so an unchecked failure here would otherwise
# be silently followed by a green scorecard — the one thing this step must never do.
expo_rc=0
if [ -f "$expo" ] && command -v python3 >/dev/null 2>&1; then
  echo "Matching the inventory against advisory sources (OSV / CISA KEV / pulse)…" >&2
  # EXPOSURE_REPORT_ARGS: optional extra flags (e.g. --offline, or replay
  # fixtures in CI). Read into an ARRAY and ALLOWLIST each element: an unquoted
  # expansion here would let anything that can set this env var smuggle in
  # --probe-binaries (executing scanned binaries — the one thing the design
  # forbids without a deliberate CLI opt-in) or --watchlist (attacker-chosen
  # probe commands). Those two flags are deliberately not accepted from the
  # environment; pass them on the command line yourself if you mean them.
  expo_extra=()
  if [ -n "${EXPOSURE_REPORT_ARGS:-}" ]; then
    read -r -a _expo_words <<< "$EXPOSURE_REPORT_ARGS"
    _i=0
    while [ "$_i" -lt "${#_expo_words[@]}" ]; do
      _w="${_expo_words[$_i]}"
      _next="${_expo_words[$((_i + 1))]:-}"
      case "$_w" in
        --offline)                                  # takes no value
          expo_extra+=("$_w"); _i=$((_i + 1)) ;;
        --osv|--kev|--feed|--now|--inventory|--out)  # flag + its value
          expo_extra+=("$_w")
          case "$_next" in
            ''|-*) ;;                               # missing value: let py error
            *) expo_extra+=("$_next"); _i=$((_i + 1)) ;;
          esac
          _i=$((_i + 1)) ;;
        --probe-binaries|--watchlist)
          # Refuse the flag AND swallow its value, or the leftover value would
          # arrive as a stray positional and abort the run.
          echo "assess.sh: refusing '$_w' from EXPOSURE_REPORT_ARGS (pass it on the command line if you mean it)" >&2
          case "$_next" in ''|-*) ;; *) _i=$((_i + 1)) ;; esac
          _i=$((_i + 1)) ;;
        *)
          echo "assess.sh: ignoring unrecognized '$_w' in EXPOSURE_REPORT_ARGS" >&2
          _i=$((_i + 1)) ;;
      esac
    done
  fi
  python3 "$expo" --inventory "$inv" --out "$out" "${expo_extra[@]}" || expo_rc=$?
  case "$expo_rc" in
    0) ;;
    2) echo "assess.sh: WARNING — exposure report is DEGRADED (a source was skipped; see its coverage section)" >&2 ;;
    *) echo "assess.sh: WARNING — exposure step FAILED (exit $expo_rc); the scorecard below does NOT cover exposure" >&2 ;;
  esac
elif [ -f "$expo" ]; then
  # Prerequisite missing is a DEGRADED run, not a clean one: the scorecard is
  # real but nothing checked exposure. Exit 2 keeps "never a silent green" true.
  echo "assess.sh: NOTE — python3 not found; exposure step SKIPPED (install python3 for advisory matching)" >&2
  expo_rc=2
fi

if [ -f "$out/exposure-report.md" ]; then
  expo_line="Exposure report:   $out/exposure-report.md (states which sources ran)"
else
  expo_line="Exposure report:   not produced (see the note above)"
fi

cat >&2 <<NOTE

Starter scorecard: $html
Starter posture:   $posture
$expo_line

This is a CONSERVATIVE starting point from what discovery can measure on its own.
The controls it cannot see from disk (allowlists, SIEM streaming, the headless gate)
default to "missing" until you confirm them. Run the agentic-ai-hardening skill for
the full assessment. Everything above stays in $out (local only) — do NOT commit it;
it reflects this machine. The scorecard is posture-only and safe to share.
NOTE

# Surface the exposure step's outcome as this script's exit code:
#   0 = scorecard + full exposure report
#   2 = degraded — report rendered with a source skipped, OR the step was
#       skipped entirely because python3 is missing
#   3 = exposure step could not produce a report at all
# The scorecard above is valid in every case; a nonzero code means exposure
# coverage is incomplete, so a green exit never overstates what was checked.
exit "$expo_rc"
