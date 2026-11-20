# Vulnerable dependencies
1. Direct or transitive? Find the chain (`npm ls pkg`, `uv tree`/`pipdeptree`, `go mod why`, `cargo tree -i pkg`, `dotnet list package --include-transitive`).
2. Target = lowest version >= the FixedVersion that satisfies constraints. Read the changelog on major bumps.
3. Change the manifest, then regenerate the lockfile with the project's own tool (see `ecosystems/`). Commit manifest + lockfile together.
4. Transitive pin you cannot bump directly: use the ecosystem override (npm `overrides`, yarn `resolutions`, pnpm `pnpm.overrides`, Cargo `[patch]`, Go `replace`, pip constraints file).
5. Run tests. Run `verify.sh osv-scanner <GHSA-or-CVE> .` (or trivy/npm-audit).
6. No fixed version exists: remove or replace the package, mitigate (feature off, input validation), or record an explicit risk acceptance with owner and date. Say which.
Hygiene: commit lockfiles; exact pins for build tools; hash-checking installs where practical (`pip --require-hashes`, `npm ci`); consider a dependency age gate (skip releases newer than ~14 days); `npm config set ignore-scripts true` for untrusted installs.
Do not run `npm audit fix --force` blindly. `osv-scanner fix` is experimental and limited to some ecosystems; commit first and review the diff.
