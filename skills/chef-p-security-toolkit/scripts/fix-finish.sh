#!/usr/bin/env bash
# fix-finish.sh -- after fixes: rescan, diff findings vs baseline, run tests, show change summary.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${SEC_OUT:-security-reports}"
[ -f "$OUT/baseline/.base-commit" ] || { echo "No baseline. Run fix-start.sh first."; exit 2; }
rm -rf "$OUT/after"; mkdir -p "$OUT/after"
echo "== rescan =="; SEC_OUT="$OUT/after" "$HERE/scan.sh" static .
echo; echo "== findings: before vs after =="; python3 "$HERE/findings_diff.py" "$OUT/baseline" "$OUT/after"; drc=$?
echo; echo "== tests =="; "$HERE/run-tests.sh" . > "$OUT/after/tests.txt" 2>&1; trc=$?
tail -n 8 "$OUT/after/tests.txt"
echo "tests exit before=$(cat "$OUT/baseline/tests.rc" 2>/dev/null || echo ?) after=$trc"
echo; echo "== change summary =="; git diff --stat "$(cat "$OUT/baseline/.base-commit")"
echo; echo "Done. A HUMAN must review the diff and merge. Never auto-merge."
[ "$drc" -eq 0 ] || echo "WARNING: new findings introduced. Do not merge until explained."
