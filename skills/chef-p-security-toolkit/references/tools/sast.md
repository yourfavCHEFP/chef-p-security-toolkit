# Reading SAST output
Semgrep (`semgrep.sarif`): `runs[].results[]` -> `ruleId`, `message.text`, `locations[].physicalLocation` (file + line), `level`. Trace whether untrusted input reaches the flagged sink and whether sanitization exists. Tests, fixtures, vendored and generated code are usually low priority.
Bandit (`bandit.json`, Python): `results[]` -> `test_id` (B602...), `issue_severity`, `issue_confidence`, `filename`, `line_number`, `issue_text`. HIGH severity + HIGH confidence first. B101 (assert) and B311 (random) are often noise unless used for security.
Finding id for verify.sh: the ruleId / test_id.
