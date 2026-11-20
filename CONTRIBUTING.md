# Contributing
- Add a scanner: copy `skills/chef-p-security-toolkit/scripts/tools.available/_template.sh.example` into `tools.d/`, add a parser in `findings.py`, a reading guide in `references/tools/`, and a fixture plus assertion in `tests/selftest.sh`.
- Add an attack class: a file in `references/hunt/` (what to look for, method, what kills false positives).
- Run `bash tests/selftest.sh` before every PR. It must stay green and needs no scanners installed.
- Never commit real secrets, real reports, or `security-reports/`. The testbed builds its fake token at runtime on purpose.
- Pin versions in any CI you add, and pin third-party Actions to full commit SHAs you have verified.
- Claims need evidence: new behaviour needs a test; benchmark claims need a results file from `evals/`.
