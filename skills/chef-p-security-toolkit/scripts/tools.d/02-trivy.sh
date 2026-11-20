# shellcheck shell=bash disable=SC2034
TOOL_NAME=trivy; TOOL_MODE=static; TOOL_ECOS="any"; TOOL_REPORT="trivy.json"
TOOL_HINT="brew install trivy  (must NOT be v0.69.4-0.69.6)"
tool_installed() { command -v trivy >/dev/null 2>&1; }
tool_guard() {
  case "$(trivy --version 2>/dev/null | head -1)" in
    *0.69.4*|*0.69.5*|*0.69.6*) echo "Trivy version is from the March 2026 supply-chain compromise. Reinstall a safe version and rotate secrets if it ever ran in CI."; return 1;;
  esac
}
tool_run() { trivy fs --scanners vuln,secret,misconfig --skip-dirs "$OUT" --format json -o "$OUT/trivy.json" "$TARGET"; }
