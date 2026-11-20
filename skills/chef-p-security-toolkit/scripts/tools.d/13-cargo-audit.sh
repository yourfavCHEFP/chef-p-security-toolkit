# shellcheck shell=bash disable=SC2034
TOOL_NAME=cargo-audit; TOOL_MODE=static; TOOL_ECOS="rust"; TOOL_REPORT="cargo-audit.json"
TOOL_HINT="cargo install cargo-audit"
tool_installed() { command -v cargo-audit >/dev/null 2>&1; }
tool_run() { ( cd "$TARGET" && cargo audit --json ) > "$OUT/cargo-audit.json"; }
