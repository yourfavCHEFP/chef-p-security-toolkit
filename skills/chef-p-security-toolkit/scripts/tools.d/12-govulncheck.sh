# shellcheck shell=bash disable=SC2034
TOOL_NAME=govulncheck; TOOL_MODE=static; TOOL_ECOS="go"; TOOL_REPORT="govulncheck.json"
TOOL_HINT="go install golang.org/x/vuln/cmd/govulncheck@latest"
tool_installed() { command -v govulncheck >/dev/null 2>&1; }
tool_guard() { "$HERE/trust.sh" check "$TARGET" >/dev/null 2>&1 || { echo "UNTRUSTED repo: go build analysis can run project code (cgo, generate). Owner must run trust.sh add <dir> --i-am-the-owner"; return 1; }; }
tool_run() { ( cd "$TARGET" && govulncheck -format json ./... ) > "$OUT/govulncheck.json"; }
