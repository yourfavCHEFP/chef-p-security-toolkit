# CI/CD (GitHub Actions first; same ideas elsewhere)
- Pin third-party Actions to a FULL commit SHA with the version in a comment: `uses: org/action@<40-hex> # v1.2.3`. Tags can be re-pointed (this is how the 2026 Trivy action compromise spread). Look up the SHA of the release you trust; do not invent it.
- `permissions:` read-only at workflow top (`contents: read`), widen per job only if needed.
- Never combine `pull_request_target` (or `workflow_run`) with checkout/execution of untrusted PR code.
- Script injection: never put `${{ github.event.* }}` (titles, branch names, bodies) directly in `run:`; pass via `env:` and quote.
- `actions/checkout` with `persist-credentials: false` unless pushing.
- Pin tools you install in CI by exact version (and checksum when offered); do not `curl | bash` unpinned.
- Prefer OIDC federation to long-lived cloud keys; scope tokens narrowly; no secrets to fork PRs.
- Keep Actions current via Dependabot/Renovate that updates SHA pins.
Verify with zizmor ids and `incident-check.sh --action <owner/repo>` for mutable refs.
