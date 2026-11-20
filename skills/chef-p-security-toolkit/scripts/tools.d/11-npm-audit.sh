# shellcheck shell=bash disable=SC2034
TOOL_NAME=npm-audit; TOOL_MODE=static; TOOL_ECOS="node"; TOOL_REPORT="npm-audit.json"
TOOL_HINT="install Node.js (npm). Needs a lockfile; audits the root package only"
tool_installed() { command -v npm >/dev/null 2>&1; }
tool_run() { ( cd "$TARGET" && npm audit --json ) > "$OUT/npm-audit.json"; }
