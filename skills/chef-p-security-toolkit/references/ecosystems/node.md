# Node / TypeScript
Manifests: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
Tests: `npm test`. Audit: `npm audit`, osv-scanner, trivy.
Upgrade: `npm install NAME@VERSION` (regenerates the lock); transitive: `overrides` (npm), `resolutions` (yarn), `pnpm.overrides`. Use `npm ci` in CI. `npm audit fix` (without `--force`) only after reading what it changes.
Hardening: commit the lockfile; `ignore-scripts` for untrusted installs; exact versions for build tooling.
