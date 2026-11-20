# Reading dependency scans
OSV-Scanner (`osv.json`): `results[].packages[]` -> `package.name/version`, `vulnerabilities[]` (`id`, `aliases`, `summary`, severity); fixed versions are in each vulnerability's `affected[].ranges[].events[].fixed`. Covers many lockfile types across languages.
Trivy (`trivy.json`): `Results[].Vulnerabilities[]` -> `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity`; also `Misconfigurations[]` and `Secrets[]`.
npm-audit: `vulnerabilities{}` with `severity`, `fixAvailable`. govulncheck (JSON stream): only findings with a call trace are actually reachable; prioritize those. cargo-audit: `vulnerabilities.list[]`. dotnet-vuln: text table by project/package.
Prioritize: has a fix, runtime (not dev-only) dependency, HIGH/CRITICAL, reachable. Group many CVEs under the one upgrade that fixes them. Do not claim exploitability without evidence of reachability.
