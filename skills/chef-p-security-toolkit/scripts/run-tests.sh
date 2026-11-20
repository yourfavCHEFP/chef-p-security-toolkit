#!/usr/bin/env bash
# run-tests.sh [dir]  -- detect and run the project's own tests. Override with SEC_TEST_CMD.
# exit: test exit code; 4 = no tests detected (fix NOT test-verified); 5 = repo not trusted (tests not run).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$HERE/trust.sh" check "${1:-.}" || exit 5   # running tests executes project code
cd "${1:-.}" || exit 2
if [ -n "${SEC_TEST_CMD:-}" ]; then echo "+ $SEC_TEST_CMD"; bash -c "$SEC_TEST_CMD"; exit $?; fi
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then echo "+ go test ./..."; go test ./...; exit $?; fi
if [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then echo "+ cargo test"; cargo test; exit $?; fi
if [ -f package.json ] && command -v npm >/dev/null 2>&1 && grep -q '"test"' package.json && ! grep -q 'no test specified' package.json; then
  echo "+ npm test"; npm test --silent; exit $?; fi
if { ls ./*.sln ./*.csproj >/dev/null 2>&1; } && command -v dotnet >/dev/null 2>&1; then echo "+ dotnet test"; dotnet test; exit $?; fi
if [ -f pom.xml ] && command -v mvn >/dev/null 2>&1; then echo "+ mvn -q test"; mvn -q test; exit $?; fi
if command -v python3 >/dev/null 2>&1 && python3 -m pytest --version >/dev/null 2>&1; then
  if [ -d tests ] || [ -d test ] || [ -f pytest.ini ] || [ -f tox.ini ] || ls test_*.py *_test.py >/dev/null 2>&1 || grep -qs 'tool.pytest' pyproject.toml; then
    echo "+ python3 -m pytest -q"; python3 -m pytest -q; rc=$?
    [ "$rc" -eq 5 ] && { echo "NO TESTS COLLECTED"; exit 4; }
    exit $rc
  fi
fi
echo "NO TESTS DETECTED - any fix here is NOT test-verified; say so and require human review."
exit 4
