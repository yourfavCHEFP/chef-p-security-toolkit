# shellcheck shell=bash disable=SC2034
TOOL_NAME=bandit; TOOL_MODE=static; TOOL_ECOS="python"; TOOL_REPORT="bandit.json"
TOOL_HINT="pipx install bandit"
tool_installed() { command -v bandit >/dev/null 2>&1; }
tool_run() {
  local ex="*/.venv/*,*/venv/*,*/node_modules/*,*/security-reports/*" p
  if [ -f "$TARGET/.secignore" ]; then
    while IFS= read -r p; do case "$p" in ""|"#"*) ;; *) p="${p%/**}"; ex+=",*/${p%/}/*";; esac; done < "$TARGET/.secignore"
  fi
  bandit -r "$TARGET" -q -f json -o "$OUT/bandit.json" --exclude "$ex"
}
