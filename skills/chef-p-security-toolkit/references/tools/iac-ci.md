# Reading Docker / IaC / CI scans
Hadolint (`hadolint.json`): `code` (DL3xxx, SC2xxx), `level`, `file`, `line`. Checkov (`checkov.json`): `results.failed_checks[]` -> `check_id`, `file_path`, `resource`. zizmor (`zizmor.json`): GitHub Actions weaknesses (unpinned actions, dangerous triggers, script injection, excessive permissions). Trivy `Misconfigurations[]` overlaps; dedupe.
Recipes: `references/fixes/docker-iac.md` and `references/fixes/ci-cd.md`.
