# shellcheck shell=bash disable=SC2034
TOOL_NAME=picklescan; TOOL_MODE=static; TOOL_ECOS="mlmodels"; TOOL_REPORT="picklescan.txt"
TOOL_HINT="pipx install picklescan   (scans model files for unsafe pickle payloads)"
tool_installed() { command -v picklescan >/dev/null 2>&1; }
tool_run() { picklescan --path "$TARGET" > "$OUT/picklescan.txt" 2>&1; }
