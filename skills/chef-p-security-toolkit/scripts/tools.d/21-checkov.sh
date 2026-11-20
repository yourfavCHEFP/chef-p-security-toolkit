# shellcheck shell=bash disable=SC2034
TOOL_NAME=checkov; TOOL_MODE=static; TOOL_ECOS="terraform"; TOOL_REPORT="checkov.json"
TOOL_HINT="pipx install checkov"
tool_installed() { command -v checkov >/dev/null 2>&1; }
tool_run() { checkov -d "$TARGET" --quiet -o json > "$OUT/checkov.json"; }
