#!/usr/bin/env bash
# incident-check.sh --pkg NAME=BADVER[,BADVER] --action OWNER/REPO --ioc STRING [--target DIR] [--deep]
# Exposure check for a breach / supply-chain advisory. All values are treated as literal data.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 2; }
exec python3 "$HERE/incident_scan.py" "$@"
