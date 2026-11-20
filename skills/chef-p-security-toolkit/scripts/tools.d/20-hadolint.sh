# shellcheck shell=bash disable=SC2034
TOOL_NAME=hadolint; TOOL_MODE=static; TOOL_ECOS="docker"; TOOL_REPORT="hadolint.json"
TOOL_HINT="brew install hadolint"
tool_installed() { command -v hadolint >/dev/null 2>&1; }
tool_run() { find "$TARGET" \( -name .git -o -name node_modules \) -prune -o -type f -name 'Dockerfile*' -print0 \
  | xargs -0 hadolint --format json > "$OUT/hadolint.json"; }
