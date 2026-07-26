#!/usr/bin/env bash
# Python test suite runner: unit tests + fixture E2E for exposure-report.py,
# including the assess.sh regression test. Deterministic — every network input
# is replayed from tests/fixtures/, no sockets are opened. Run from anywhere:
#   bash scripts/test.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

command -v python3 >/dev/null 2>&1 || { echo "test.sh: python3 is required" >&2; exit 1; }
python3 -m unittest discover -s tests -v
