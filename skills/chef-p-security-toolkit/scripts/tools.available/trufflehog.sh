# shellcheck shell=bash disable=SC2034
# Disabled by default: overlaps gitleaks. Enable with: mv this file into ../tools.d/
# Verification is OFF on purpose: verification makes live calls to providers with the found secret.
TOOL_NAME=trufflehog; TOOL_MODE=static; TOOL_ECOS="any"; TOOL_REPORT="trufflehog.json"
TOOL_HINT="brew install trufflehog"
tool_installed() { command -v trufflehog >/dev/null 2>&1; }
tool_run() { trufflehog filesystem --no-verification --no-update --json "$TARGET" > "$OUT/trufflehog.json"; }
