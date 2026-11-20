# Fix loop (how to make fixes that are proven, not guessed)

## 0. Classify every finding before touching code
- A. Mechanical fix: dependency bump to a FixedVersion, pin an Action to a SHA, parameterize a query, drop `shell=True`, add `USER` to a Dockerfile. Do it.
- B. Needs a design decision: authz model, crypto/format migration, public API or stored-data change. Present 2 options with trade-offs and ask. Do not silently choose.
- C. Not fixable in code: a leaked credential (rotate it), cloud/IAM settings, third-party service config. Give the human the exact steps.
- D. False positive: prove it from the code (the input is constant, the path is unreachable, test-only code). Suppress only with the user's approval, narrowly, with a comment saying why.

## 1. Start
`$SK/fix-start.sh <slug>`: refuses a dirty tree or a non-git folder, creates `sec/<slug>`, stores a baseline scan and baseline test result. Note the baseline test exit: failing BEFORE your change means you cannot blame later failures on yourself. Tests that fail on purpose (security regression tests) are fine; say so.

## 2. Per finding (one finding = one commit)
1. Reproduce: confirm the finding is real in this code path (read the code; trace untrusted input to the sink).
2. Fix with the smallest change that removes the cause. Prefer the recipe in `references/fixes/`. No refactors, no unrelated edits.
3. Prove: `$SK/verify.sh <tool> <finding-id> <file-or-dir>` must print NOT PRESENT. INCONCLUSIVE means the proof did not happen; say so.
4. Tests: run `$SK/run-tests.sh` (exit 5 = repo not trusted: tests were NOT run; exit 4 = no tests). Add a regression test that FAILS on the old code and PASSES on the new code (attack payload in, safe behaviour out). No test framework: write a small one or document a manual proof.
5. Commit: `security(<tool>/<id>): <what changed> [verified: verify.sh + tests]`.
   Then record it: `python3 $SK/findings.py fix-mark <finding-id> --commit <sha> --verify "<the verify.sh NOT PRESENT line>"` (refused unless the text really starts with NOT PRESENT).
6. If the fix cannot be verified or breaks tests: `git revert`/`git checkout -- .` the change and report "could not fix safely" with the reason. Never leave a half-fix.

## 3. Finish
`$SK/fix-finish.sh` rescans and diffs findings vs baseline, reruns tests, prints the change summary.
- FIXED list should contain what you intended.
- NEW list: explain each. Low-severity informational noise created by a correct fix (for example Bandit B603/B607 after replacing `shell=True` with an argv list) is acceptable if you say why. Anything else is a regression: fix or revert.
- Missing report after = a tool failed after the change; investigate.
- A human reviews the diff and merges. Do not merge, push, or open PRs unless asked.

## Dependency vulnerabilities
Read `references/fixes/dependencies.md`. Always: lowest version >= FixedVersion that satisfies constraints, regenerate the lockfile with the project's own tool, rerun tests, read the changelog on major bumps. No fix exists: remove or replace the dependency, mitigate, or record an explicit risk acceptance. Do not run `npm audit fix --force` blindly.

## Secrets
Read `references/fixes/secrets.md`. Order: rotate -> remove from code -> load from env/secret manager -> prevent recurrence -> only then consider history rewrite.

## Stop conditions (ask the human)
Public API / schema / stored-data format change; auth or permission semantics change; more than ~5 files for one finding; tests missing for critical logic; a fix needs a new dependency.

## Fix report template
Finding -> root cause (one line) -> change (files) -> proof (verify output) -> tests (before/after) -> residual risk.
