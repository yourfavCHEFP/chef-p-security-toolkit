# shellcheck shell=bash disable=SC2034
TOOL_NAME=gitleaks; TOOL_MODE=static; TOOL_ECOS="any"; TOOL_REPORT="gitleaks-worktree.json"
TOOL_HINT="brew install gitleaks"
tool_installed() { command -v gitleaks >/dev/null 2>&1; }
tool_run() {
  gitleaks dir --redact --no-banner --report-format json --report-path "$OUT/gitleaks-worktree.json" "$TARGET"
  local rc=$?
  if git -C "$TARGET" rev-parse --git-dir >/dev/null 2>&1; then
    gitleaks git --redact --no-banner --report-format json --report-path "$OUT/gitleaks-history.json" "$TARGET"
  fi
  return $rc
}
