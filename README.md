# CHEF_P Security Toolkit

A portable Agent Skill for coding agents (Claude Code, Codex, Gemini CLI, Cursor, Copilot, OpenCode and any agent that reads `SKILL.md` folders; also a Claude Code plugin) that finds, verifies, fixes and responds to security problems in any language, without letting the AI invent vulnerabilities.

**Tools find. Agents hunt. A different agent verifies. Fixes are proven. Reports are generated from data.**

## Why it exists
- **Grounded.** Independent scanners (Semgrep, Gitleaks, Trivy, OSV-Scanner, Bandit, Hadolint, Checkov, zizmor and more) produce findings; the AI interprets them. A tool that did not run is reported as SKIPPED, never as clean.
- **Verified.** Findings found by an agent start as `needs_validation`. Confirming one requires a *different* verifier, an impact statement and a source-to-sink trace. The rules are enforced in code (`findings.py`), not left to the model.
- **Fixed, with proof.** Fixes happen on a `sec/*` branch, one finding per commit, and each must pass `verify.sh` (the finding is gone on rescan) and the project's tests. Nothing auto-merges.
- **Breach-aware.** Give it an advisory or breach write-up; it checks lockfiles, installed packages, CI workflows and indicators for exposure, supports version ranges, and drives containment.

## Install
Pick the route that matches your agent. The skill is a plain Agent Skills folder (`skills/chef-p-security-toolkit/`), so the same files work everywhere; only the folder it is copied to differs. Details and status per agent: `docs/compatibility.md`.

1. **Auto-detect installed agents** (Skills CLI; it downloads and runs npm code, so review what it installs):
   `npx skills add yourfavCHEFP/chef-p-security-toolkit`
2. **This repo's installer** (no npm):
   ```
   git clone https://github.com/yourfavCHEFP/chef-p-security-toolkit && cd chef-p-security-toolkit
   bash install.sh --agent codex            # or claude | gemini | copilot | cursor | opencode | universal | all
   bash install.sh --agent codex --project  # into the current repo (./.agents/skills) so a team shares it
   ```
3. **Claude Code plugin:**
   ```
   /plugin marketplace add yourfavCHEFP/chef-p-security-toolkit
   /plugin install chef-p-security-toolkit@chefp-security
   ```
4. **Agents without skill support:** point them at `AGENTS.md` in this repo (it links the same workflow and hard rules).

Requirements: bash and python3 (3.9+) on macOS, Linux or WSL. Restart the agent, then ask it to list its skills.

Install the scanners you want (each is optional; missing ones are reported):
```
brew install semgrep gitleaks trivy osv-scanner hadolint zizmor
pipx install bandit checkov picklescan        # strix-agent for autonomous testing
```
Pin and check scanner versions. Trivy v0.69.4-0.69.6 were compromised in March 2026; the toolkit refuses to run them.

## Use
Ask Claude Code in your repo:
- `security review this repo` (SCAN)
- `hunt for authorization and AI-agent flaws, then verify them` (HUNT)
- `fix the findings` (FIX, on a branch, with proof)
- `am I affected by <advisory URL or CVE>?` (INCIDENT)

Direct commands live in `skills/chef-p-security-toolkit/scripts/`: `scan.sh`, `recon.py`, `findings.py`, `verify.sh`, `fix-start.sh`, `fix-finish.sh`, `incident-check.sh`, `trust.sh`, `make-testbed.sh`.

## Languages and tools
Detected automatically; only applicable tools run.
| Scope | Tools |
|---|---|
| Any code | Semgrep, Gitleaks, Trivy, OSV-Scanner |
| Python | Bandit |
| Node / Go / Rust / .NET | npm audit, govulncheck, cargo-audit, `dotnet list package --vulnerable` |
| Docker / Terraform / GitHub Actions | Hadolint, Checkov, zizmor |
| ML model files | picklescan |
| Running apps / autonomous | ZAP baseline, Strix (opt-in, owned targets only) |
Lockfile parsing for incidents: pip/uv/poetry/Pipfile, npm/yarn/pnpm, Go, Cargo, Composer, Bundler, NuGet, Maven (best effort for some).

## Safety model
- Static scans never execute project code. Anything that does (tests, builds, restores) needs `trust.sh check` to pass; only a human at a terminal can add trust.
- Advisories, web pages, code comments and scan output are treated as data, not instructions.
- Secrets are redacted in reports and never printed. Rotate first, clean history later.
- Active scanning needs an explicit request; remote targets need ownership confirmation.
- Noise suppression (`.secignore`, test-file rules) is visible in reports, never silent.

## What is tested, and what is not
Tested (`bash tests/selftest.sh`, 91 checks, no scanners needed): Agent Skills spec compliance of `SKILL.md`, multi-agent install paths, path locator, verifier prompt, script syntax, findings ingest/merge/suppression on fixtures, enforced verdict rules, SARIF and report generation, coverage staleness, recon, trust gate, incident exact and range matching, scorer, honest SKIPPED reporting.
Exercised by hand on real runs: Bandit through the full fix loop; Semgrep, Gitleaks, Trivy, OSV-Scanner, Hadolint and zizmor on a practice repo and a real project.
Agent compatibility is by format and documented paths: only Claude Code has been run end to end by the maintainer; Codex, Gemini CLI, Cursor, Copilot and OpenCode are format-compatible but not yet run (see `docs/compatibility.md` for a 5-minute smoke test you can report back). Not yet measured: hunt-mode quality with real LLM runs, and a head-to-head against other audit skills. The harness for both is in `evals/`; results will be published there, including the metrics where this toolkit loses. `claude plugin validate` has not been run in CI yet.

## Benchmark
`bash skills/chef-p-security-toolkit/scripts/make-testbed.sh ~/security-testbed`, run any tool, then `python3 evals/score.py recall ...` and `... fix ...`. See `evals/README.md`.

## Compared with Cloudflare's security-audit-skill
That project is an LLM-driven, multi-phase auditor built to discover new bugs, with a verification stage, machine-readable findings and a strict rule against executing target code without a sandbox. This toolkit borrows those ideas (independent verification, findings as data, coverage ledger, execution gate), written from scratch, and adds deterministic scanner grounding, a verified fix loop, breach/advisory mode and multi-language dependency coverage. Its open-source skill focuses on discovery and reporting; we do not claim our hunt mode finds more novel bugs. That is what the benchmark is for.

## Extending
Add a scanner by dropping a file in `scripts/tools.d/`; add an attack class in `references/hunt/`; see `skills/chef-p-security-toolkit/references/extending.md` and `CONTRIBUTING.md`.

## License and credits
MIT, see `LICENSE`. Hunt-mode design was inspired by Cloudflare's open-source security-audit-skill (MIT); no code or prompt text was copied. The scanners are separate projects with their own licenses; this repo calls them and does not bundle them.
