# shellcheck shell=bash disable=SC2034
TOOL_NAME=strix; TOOL_MODE=strix; TOOL_ECOS="any"; TOOL_REPORT=""
TOOL_HINT="pipx install strix-agent (needs Docker + Python 3.12+)"
tool_installed() { command -v strix >/dev/null 2>&1; }
tool_guard() {
  [ -n "${STRIX_LLM:-}" ] || { echo "Set STRIX_LLM (and LLM_API_KEY / LLM_API_BASE) first."; return 1; }
  case "$TARGET" in
    http://localhost*|http://127.0.0.1*) ;;
    http*) [ "${CONFIRM_OWNED:-}" = yes ] || { echo "Remote URL target. Set CONFIRM_OWNED=yes ONLY if you own it."; return 1; };;
  esac
}
tool_run() { strix -n -t "$TARGET" --scan-mode quick; }
