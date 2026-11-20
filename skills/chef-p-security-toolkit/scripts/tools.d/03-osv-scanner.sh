# shellcheck shell=bash disable=SC2034
TOOL_NAME=osv-scanner; TOOL_MODE=static; TOOL_ECOS="any"; TOOL_REPORT="osv.json"
TOOL_HINT="brew install osv-scanner"
tool_installed() { command -v osv-scanner >/dev/null 2>&1; }
tool_run() {
  osv-scanner scan source --format json --allow-no-lockfiles --recursive "$TARGET" > "$OUT/osv.json" 2> "$OUT/osv.stderr"
  local rc=$?
  if ! head -c1 "$OUT/osv.json" 2>/dev/null | grep -q '{'; then   # older v1 CLI syntax
    osv-scanner --format json -r "$TARGET" > "$OUT/osv.json" 2> "$OUT/osv.stderr"; rc=$?
  fi
  return $rc
}
