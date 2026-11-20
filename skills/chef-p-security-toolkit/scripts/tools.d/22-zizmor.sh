# shellcheck shell=bash disable=SC2034
TOOL_NAME=zizmor; TOOL_MODE=static; TOOL_ECOS="gha"; TOOL_REPORT="zizmor.json"
TOOL_HINT="brew install zizmor  (or pipx install zizmor)"
tool_installed() { command -v zizmor >/dev/null 2>&1; }
tool_run() { zizmor --format json "$TARGET" > "$OUT/zizmor.json"; }
