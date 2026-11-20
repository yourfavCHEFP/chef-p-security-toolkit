#!/usr/bin/env bash
# trust.sh check [dir] | add [dir] --i-am-the-owner | list
# Gate for anything that EXECUTES project code (running tests, restoring/building projects).
# Static scanners do not need it. An agent must never mark a repo trusted: `add` needs a human at a terminal.
set -uo pipefail
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/chef-p-security"; LIST="$CFG/trusted-paths"
cmd="${1:-check}"; dir="${2:-.}"
dir="$(cd "$dir" 2>/dev/null && pwd -P)" || { echo "no such directory: ${2:-.}"; exit 2; }
case "$cmd" in
  check)
    [ "${SEC_TRUST:-}" = trusted ] && exit 0
    [ "${SEC_SANDBOX:-}" = 1 ] && exit 0      # you assert this runs inside a disposable sandbox/container/VM
    if [ -f "$LIST" ]; then
      while IFS= read -r p; do [ -n "$p" ] || continue; [ "$dir" = "$p" ] && exit 0; case "$dir" in "$p"/*) exit 0;; esac; done < "$LIST"
    fi
    if [ -n "${SEC_TRUSTED_OWNERS:-}" ]; then
      remote="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
      for o in ${SEC_TRUSTED_OWNERS//,/ }; do case "$remote" in *"/$o/"*|*":$o/"*) exit 0;; esac; done
    fi
    echo "UNTRUSTED: $dir is not marked as your own code. Refusing to execute project code (tests, builds, restores)."
    echo "Static scans still work. To allow execution the OWNER runs, in a terminal: trust.sh add $dir --i-am-the-owner"
    echo "Or run inside a disposable sandbox/VM and set SEC_SANDBOX=1."
    exit 5;;
  add)
    [ "${3:-}" = "--i-am-the-owner" ] || { echo "usage: trust.sh add <dir> --i-am-the-owner"; exit 2; }
    if ! { [ -t 0 ] && [ -t 1 ]; }; then echo "REFUSED: needs an interactive terminal. An agent cannot mark a repo trusted."; exit 5; fi
    printf 'Allow this toolkit to run code from %s? Type the full path to confirm: ' "$dir"; read -r ans
    [ "$ans" = "$dir" ] || { echo "not confirmed"; exit 1; }
    mkdir -p "$CFG"; echo "$dir" >> "$LIST"; echo "trusted: $dir";;
  list) [ -f "$LIST" ] && cat "$LIST" || echo "(no trusted paths)";;
  *) echo "usage: trust.sh check|add|list [dir]"; exit 2;;
esac
