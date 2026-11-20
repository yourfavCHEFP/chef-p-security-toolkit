#!/usr/bin/env bash
# shellcheck disable=SC1090  # plugins are sourced by design
# verify.sh <tool> <finding-id> [path]
# Re-runs ONE tool scoped to a path and checks whether the finding id (rule id / CVE / GHSA) is still reported.
# exit: 0 = not present, 1 = STILL PRESENT, 4 = inconclusive (tool missing/blocked/failed)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${1:-}"; ID="${2:-}"; TGT="${3:-.}"
[ -n "$TOOL" ] && [ -n "$ID" ] || { echo "usage: verify.sh <tool> <finding-id> [path]"; exit 2; }
[ -e "$TGT" ] || { echo "no such path: $TGT"; exit 2; }
if [ -d "$TGT" ]; then TARGET="$(cd "$TGT" && pwd)"; else TARGET="$(cd "$(dirname "$TGT")" && pwd)/$(basename "$TGT")"; fi
PLUG=""
for f in "$HERE"/tools.d/*.sh; do
  n="$( TOOL_NAME=""; . "$f"; echo "$TOOL_NAME" )"; [ "$n" = "$TOOL" ] && PLUG="$f" && break
done
[ -n "$PLUG" ] || { echo "unknown tool '$TOOL' (see: scan.sh list)"; exit 2; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export TARGET; export OUT="$TMP"
( . "$PLUG"
  tool_installed || exit 11
  if declare -F tool_guard >/dev/null; then tool_guard >/dev/null 2>&1 || exit 12; fi
  tool_run >/dev/null 2>"$TMP/.stderr"; echo $? > "$TMP/.rc" )
st=$?
[ "$st" -eq 11 ] && { echo "INCONCLUSIVE: $TOOL is not installed"; exit 4; }
[ "$st" -eq 12 ] && { echo "INCONCLUSIVE: $TOOL blocked by its guard"; exit 4; }
rc="$(cat "$TMP/.rc" 2>/dev/null || echo 99)"
HITS="$(grep -rlF --exclude='.rc' --exclude='.stderr' --exclude='*.stderr' -- "$ID" "$TMP" 2>/dev/null | wc -l | tr -d ' ')"
if [ "$HITS" -gt 0 ]; then
  echo "STILL PRESENT: '$ID' is still reported by $TOOL for $TGT"
  grep -rcF --exclude='.rc' --exclude='.stderr' --exclude='*.stderr' -- "$ID" "$TMP" | sed "s#$TMP/##" | grep -v ':0$'
  exit 1
fi
if [ -z "$(find "$TMP" -type f ! -name '.rc' ! -name '.stderr' ! -name '*.stderr' -size +0 2>/dev/null)" ] && [ "$rc" -ne 0 ]; then
  echo "INCONCLUSIVE: $TOOL produced no report (exit $rc)"; exit 4
fi
echo "NOT PRESENT: '$ID' no longer reported by $TOOL for $TGT (tool exit $rc)"
exit 0
