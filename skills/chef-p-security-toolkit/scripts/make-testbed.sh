#!/usr/bin/env bash
# make-testbed.sh [dir]  -- creates two INTENTIONALLY VULNERABLE practice repos (local only; all secrets are fake):
#   vuln-app/      Python app with injection, unsafe deserialization, weak hash, fake token, old deps, bad Dockerfile, risky CI
#   incident-sim/  simulated supply-chain incident (bad pinned versions, mutable action tags, harmless IOC file)
# Do NOT push these to GitHub: push protection will (rightly) flag the fake token.
set -euo pipefail
ROOT="${1:-./security-testbed}"; mkdir -p "$ROOT"; ROOT="$(cd "$ROOT" && pwd)"
gitc() { git -c user.name=testbed -c user.email=testbed@example.invalid "$@"; }
# The fake token is assembled at runtime so this script never contains a contiguous token-shaped string
# (GitHub push protection would otherwise block pushing the toolkit repo itself).
TOKEN="ghp""_Zq8Vn3xK7mP2wR5tY9uB4cD6eF1gH0jL3aNs"

# ------------------------------------------------------------------ vuln-app
A="$ROOT/vuln-app"; rm -rf "$A"; mkdir -p "$A/tests" "$A/.github/workflows"; cd "$A"
cat > app.py <<'PY'
import hashlib
import pickle
import sqlite3
import subprocess

API_TOKEN = "__TOKEN__"  # FAKE test token (generated at runtime)


def get_user(conn, name):
    cur = conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'")  # SQL injection
    return cur.fetchall()


def ping(host):
    return subprocess.run("echo pinging " + host, shell=True, capture_output=True, text=True).stdout.strip()  # command injection


def load_blob(data: bytes):
    return pickle.loads(data)  # unsafe deserialization


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # weak hash
PY
sed "s/__TOKEN__/$TOKEN/" app.py > app.py.tmp && mv app.py.tmp app.py
cat > tests/test_app.py <<'PY'
import sqlite3
import app


def _conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return c


def test_get_user_normal():
    assert app.get_user(_conn(), "alice") == [(1, "alice")]


def test_ping_normal():
    assert app.ping("localhost") == "pinging localhost"


def test_hash_is_string():
    assert isinstance(app.hash_password("x"), str)
PY
cat > tests/test_security.py <<'PY'
# These FAIL on the vulnerable code on purpose. A correct fix makes them pass.
import sqlite3
import app


def _conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return c


def test_sec_sql_injection_blocked():
    assert app.get_user(_conn(), "' OR '1'='1") == []


def test_sec_command_injection_blocked():
    # input must be treated as ONE literal argument, never interpreted by a shell
    assert app.ping("x; echo INJECTED") == "pinging x; echo INJECTED"
PY
printf 'requests==2.19.1\npyyaml==5.3\njinja2==2.10\n' > requirements.txt
cat > Dockerfile <<'D'
FROM python:3.8
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
D
cat > .github/workflows/ci.yml <<'Y'
name: ci
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: aquasecurity/trivy-action@0.34.0
Y
printf 'security-reports/\nstrix_runs/\n__pycache__/\n.pytest_cache/\n' > .gitignore
git init -q; git add -A; gitc commit -q -m "vulnerable test app"

# ------------------------------------------------------------------ incident-sim
I="$ROOT/incident-sim"; rm -rf "$I"; mkdir -p "$I/.github/workflows" "$I/fake-site-packages"; cd "$I"
printf 'litellm==1.82.7\nrequests==2.32.3\n' > requirements.txt
cat > uv.lock <<'T'
version = 1

[[package]]
name = "litellm"
version = "1.82.7"

[[package]]
name = "requests"
version = "2.32.3"
T
cat > .github/workflows/scan.yml <<'Y'
name: scan
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: aquasecurity/trivy-action@0.34.0
      - uses: aquasecurity/setup-trivy@v0.2.0
Y
echo "# harmless simulated indicator file" > fake-site-packages/litellm_init.pth
printf 'security-reports/\n' > .gitignore
cat > README.md <<'R'
Simulated incident. Expected: EXPOSED (litellm 1.82.7 pinned, IOC file present) + AT-RISK (mutable action tags).
Run:  incident-check.sh --target . --pkg litellm=1.82.7,1.82.8 --action aquasecurity/trivy-action --action aquasecurity/setup-trivy --ioc litellm_init.pth
R
git init -q; git add -A; gitc commit -q -m "incident simulation"
echo "Testbed ready in $ROOT"
echo "  vuln-app/     try: 'security review this repo' then 'fix the findings'"
echo "  incident-sim/ try: the command in its README.md, or ask Claude to investigate the litellm/trivy incident"
