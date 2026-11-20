# Reading secret scans
Gitleaks (`gitleaks-worktree.json`, `gitleaks-history.json`): fields `RuleID`, `File`, `StartLine`, `Commit`, `Author`, `Date`; values are redacted. "worktree" = live in current code; "history" only = removed but recoverable. Likely false positives: placeholders, documented examples, test fixtures; say why.
Trivy secrets appear under `Results[].Secrets[]`. TruffleHog (optional plugin) runs with verification OFF so it makes no live calls.
Handling real leaks: `references/fixes/secrets.md`.
