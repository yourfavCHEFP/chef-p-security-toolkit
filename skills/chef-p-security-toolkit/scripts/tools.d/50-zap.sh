# shellcheck shell=bash disable=SC2034
TOOL_NAME=zap; TOOL_MODE=zap; TOOL_ECOS="any"; TOOL_REPORT="zap.json"
TOOL_HINT="install Docker; image ghcr.io/zaproxy/zaproxy:stable"
tool_installed() { command -v docker >/dev/null 2>&1; }
tool_guard() {
  case "$TARGET" in
    http://localhost*|http://127.0.0.1*|https://localhost*) return 0;;
    http*) [ "${CONFIRM_OWNED:-}" = yes ] || { echo "Non-local target. Set CONFIRM_OWNED=yes ONLY if you own it."; return 1; };;
    *) echo "usage: scan.sh zap <http(s)://url>"; return 1;;
  esac
}
tool_run() {
  local url="${TARGET/localhost/host.docker.internal}"; url="${url/127.0.0.1/host.docker.internal}"
  docker run --rm -v "$OUT:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "$url" -J zap.json
}
