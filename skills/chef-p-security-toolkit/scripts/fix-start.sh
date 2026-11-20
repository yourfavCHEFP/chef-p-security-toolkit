#!/usr/bin/env bash
# fix-start.sh <slug>  -- begin a fix session: clean-tree check, branch sec/<slug>, baseline scan + baseline tests.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLUG="${1:-}"; [ -n "$SLUG" ] || { echo "usage: fix-start.sh <short-slug>"; exit 2; }
SLUG="${SLUG//[^A-Za-z0-9._-]/-}"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repo. Fixes must be made on a branch; run: git init && git add -A && git commit"; exit 2; }
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Tracked changes present. Commit or stash first so the fix branch is clean."; exit 2; fi
BR="sec/$SLUG"
git switch -c "$BR" 2>/dev/null || git checkout -b "$BR" || { echo "could not create branch $BR"; exit 2; }
OUT="${SEC_OUT:-security-reports}"; rm -rf "$OUT/baseline" "$OUT/after"; mkdir -p "$OUT/baseline"
git rev-parse HEAD > "$OUT/baseline/.base-commit"
echo "== baseline scan =="; SEC_OUT="$OUT/baseline" "$HERE/scan.sh" static .
echo "== baseline tests =="; "$HERE/run-tests.sh" . > "$OUT/baseline/tests.txt" 2>&1; echo $? > "$OUT/baseline/tests.rc"
echo "baseline test exit: $(cat "$OUT/baseline/tests.rc")  (0 pass, 4 none detected, other = failing BEFORE any change)"
echo; echo "On branch $BR. Fix ONE finding, verify with verify.sh, commit, repeat. Then run fix-finish.sh."
echo "Add to .gitignore: $OUT/  strix_runs/"
