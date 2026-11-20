# shellcheck shell=bash disable=SC2034
TOOL_NAME=dotnet-vuln; TOOL_MODE=static; TOOL_ECOS="dotnet"; TOOL_REPORT="dotnet-vulnerable.txt"
TOOL_HINT="install the .NET SDK. Project must be restorable"
tool_installed() { command -v dotnet >/dev/null 2>&1; }
tool_guard() { "$HERE/trust.sh" check "$TARGET" >/dev/null 2>&1 || { echo "UNTRUSTED repo: dotnet restore can run project build code. Owner must run trust.sh add <dir> --i-am-the-owner"; return 1; }; }
tool_run() { ( cd "$TARGET" && dotnet list package --vulnerable --include-transitive ) > "$OUT/dotnet-vulnerable.txt" 2>&1; }
