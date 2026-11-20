# Noise control: .secignore and default suppressions
Create `.secignore` at the repo root to hide code that is not yours or not in scope (third-party skills, vendored code, generated output, benchmarks):
```
# gitignore-like: * ** ? and trailing /
.claude/skills/**
brag-output/
vendor/
**/generated/**
```
Effects: Semgrep and Bandit skip these paths natively; for every other tool the findings are ingested but marked `suppressed: .secignore`, kept in the data, excluded from reports and counts, and the report says how many were suppressed. Recon also skips them.
Default rule: Bandit B101/B311/B105/B106/B404/B603/B607 findings located in test files are suppressed as `test-noise`. Nothing else is suppressed by default. Suppression is visible, never silent.
Do not add a path to `.secignore` to make a real finding go away. Ask the user first; fixing or rejecting with a reason is the honest route.
