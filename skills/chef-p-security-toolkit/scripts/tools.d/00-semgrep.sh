# shellcheck shell=bash disable=SC2034
TOOL_NAME=semgrep; TOOL_MODE=static; TOOL_ECOS="any"; TOOL_REPORT="semgrep.sarif"
TOOL_HINT="brew install semgrep  (or pipx install semgrep)"
tool_installed() { command -v semgrep >/dev/null 2>&1; }
tool_run() {
  local ex=(--exclude security-reports --exclude strix_runs) p
  if [ -f "$TARGET/.secignore" ]; then
    while IFS= read -r p; do case "$p" in ""|"#"*) ;; *) p="${p%/**}"; ex+=(--exclude "${p%/}");; esac; done < "$TARGET/.secignore"
  fi
  semgrep scan --quiet --metrics=off --config p/default --config p/owasp-top-ten "${ex[@]}" --sarif -o "$OUT/semgrep.sarif" "$TARGET"
}
