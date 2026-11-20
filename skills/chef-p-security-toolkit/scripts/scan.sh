#!/usr/bin/env bash
# shellcheck disable=SC1090  # plugins are sourced by design
# CHEF_P Security Toolkit :: scan orchestrator (plugin-driven, language-agnostic).
# Each tool is a plugin in tools.d/*.sh. Adding a tool = dropping a file there.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-static}"; TARGET="${2:-.}"

usage() { cat <<'U'
usage: scan.sh <mode> [target]
  static [dir]     run every applicable static tool (default)
  zap <url>        passive ZAP baseline (localhost URL, or CONFIRM_OWNED=yes)
  strix <target>   autonomous Strix test (needs STRIX_LLM; owned targets only)
  list             show plugins, modes, ecosystems, availability
  detect [dir]     print detected ecosystems
env: SEC_OUT=<report dir, default security-reports>  SEC_ONLY=a,b  SEC_SKIP=a,b
U
}

detect_ecosystems() {
  local d="$1" found=""
  has() { [ -n "$(find "$d" -maxdepth 5 \( -name .git -o -name node_modules -o -name .venv -o -name venv -o -name target -o -name vendor -o -name __pycache__ \) -prune -o \( "$@" \) -print -quit 2>/dev/null)" ]; }
  has -name '*.py' -o -name 'requirements*.txt' -o -name pyproject.toml -o -name Pipfile -o -name uv.lock -o -name poetry.lock && found+=" python"
  has -name package.json && found+=" node"
  has -name go.mod && found+=" go"
  has -name Cargo.toml && found+=" rust"
  has -name '*.csproj' -o -name '*.fsproj' -o -name '*.sln' && found+=" dotnet"
  has -name pom.xml -o -name 'build.gradle*' && found+=" java"
  has -name Gemfile && found+=" ruby"
  has -name composer.json && found+=" php"
  has -name 'Dockerfile*' -o -name 'docker-compose*.y*ml' && found+=" docker"
  has -name '*.tf' && found+=" terraform"
  [ -d "$d/.github/workflows" ] && found+=" gha"
  has -name '*.pkl' -o -name '*.pickle' -o -name '*.pt' -o -name '*.pth' -o -name '*.ckpt' -o -name '*.joblib' && found+=" mlmodels"
  echo "${found# }"
}

case "$MODE" in
  -h|--help|help) usage; exit 0;;
  detect) D="${2:-.}"; echo "ecosystems: $(detect_ecosystems "$D")"; exit 0;;
  list)
    printf '%-14s %-8s %-28s %s\n' TOOL MODE ECOSYSTEMS STATUS
    for f in "$HERE"/tools.d/*.sh; do
      ( TOOL_NAME=""; TOOL_MODE=""; TOOL_ECOS="any"; . "$f"
        if tool_installed; then s="installed"; else s="not installed"; fi
        printf '%-14s %-8s %-28s %s\n' "$TOOL_NAME" "$TOOL_MODE" "$TOOL_ECOS" "$s" )
    done
    echo; echo "disabled (move into tools.d/ to enable): $(ls "$HERE"/tools.available 2>/dev/null | tr '\n' ' ')"
    exit 0;;
esac

# any other mode must be provided by at least one plugin
MATCH=0
for f in "$HERE"/tools.d/*.sh; do
  m="$( TOOL_MODE=""; . "$f"; echo "$TOOL_MODE" )"; [ "$m" = "$MODE" ] && MATCH=1
done
[ "$MATCH" -eq 1 ] || { usage; exit 2; }

OUT="${SEC_OUT:-security-reports}"; mkdir -p "$OUT" && OUT="$(cd "$OUT" && pwd)"
[ -d "$TARGET" ] && TARGET="$(cd "$TARGET" && pwd)"
export OUT TARGET MODE
DETECTED=""; [ -d "$TARGET" ] && DETECTED="$(detect_ecosystems "$TARGET")"
SUMMARY="$OUT/_summary-$MODE.tsv"; : > "$SUMMARY"
row() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$SUMMARY"; }

ecos_match() {
  local want="$1" e
  [ "$want" = any ] && return 0
  for e in $want; do case " $DETECTED " in *" $e "*) return 0;; esac; done
  return 1
}

run_plugin() {
  (
    TOOL_NAME=""; TOOL_MODE=""; TOOL_ECOS="any"; TOOL_REPORT=""; TOOL_HINT=""
    . "$1"
    [ "$TOOL_MODE" = "$MODE" ] || exit 0
    if [ -n "${SEC_ONLY:-}" ] && [[ ",$SEC_ONLY," != *",$TOOL_NAME,"* ]]; then exit 0; fi
    if [[ ",${SEC_SKIP:-}," == *",$TOOL_NAME,"* ]]; then row "$TOOL_NAME" SKIPPED "disabled via SEC_SKIP"; exit 0; fi
    ecos_match "$TOOL_ECOS" || exit 0
    if ! tool_installed; then row "$TOOL_NAME" SKIPPED "NOT-INSTALLED(check-did-not-run). ${TOOL_HINT}"; exit 0; fi
    if declare -F tool_guard >/dev/null; then
      if ! msg="$(tool_guard 2>&1)"; then row "$TOOL_NAME" BLOCKED "$msg"; exit 0; fi
    fi
    tool_run; rc=$?
    if [ -n "$TOOL_REPORT" ] && [ ! -s "$OUT/$TOOL_REPORT" ] && [ "$rc" -ne 0 ]; then
      row "$TOOL_NAME" FAILED "no report produced (exit $rc)"
    elif [ -n "$TOOL_REPORT" ]; then
      row "$TOOL_NAME" RAN "exit $rc -> $TOOL_REPORT"
    else
      row "$TOOL_NAME" RAN "exit $rc (see tool output / strix_runs/)"
    fi
  )
}

for f in "$HERE"/tools.d/*.sh; do run_plugin "$f"; done

echo; echo "== CHEF_P Security Toolkit :: $MODE :: target=$TARGET =="
[ -n "$DETECTED" ] && echo "ecosystems: $DETECTED"
if [ -s "$SUMMARY" ]; then awk -F'\t' '{printf "%-14s %-9s %s\n",$1,$2,$3}' "$SUMMARY"; else echo "no applicable tool for this mode/target"; fi
T="$(printf '\t')"
if grep -qE "${T}(SKIPPED|BLOCKED|FAILED)${T}" "$SUMMARY" 2>/dev/null; then
  echo; echo "NOTE: SKIPPED/BLOCKED/FAILED checks did NOT run. No findings from them means nothing."
fi
echo "reports: $OUT"
if [ "$MODE" = static ] && [ -d "$TARGET" ] && command -v python3 >/dev/null 2>&1; then
  python3 "$HERE/findings.py" --file "$OUT/findings.json" ingest --reports "$OUT" --target "$TARGET" --summary "$SUMMARY" \
    || echo "(findings ingest failed; the raw reports are still in $OUT)"
fi
grep -qE "${T}(BLOCKED|FAILED)${T}" "$SUMMARY" && exit 3
exit 0
