# Publishing checklist
1. **Dogfood first.** From the repo root: `bash tests/selftest.sh`, `skills/chef-p-security-toolkit/scripts/scan.sh static .`, `gitleaks git --redact .` (must report nothing), `bandit -r skills evals`.
2. **Create the repo** on GitHub named `chef-p-security-toolkit` (public). Enable private vulnerability reporting and secret scanning/push protection in Settings -> Code security.
3. **Push** (stage by name, never blind):
   ```
   cd chef-p-security-toolkit && git init -b main && git add -A && git status   # read the list
   git commit -m "chef-p-security-toolkit 3.0.0" && git remote add origin git@github.com:yourfavCHEFP/chef-p-security-toolkit.git
   git push -u origin main && git tag v3.0.0 && git push origin v3.0.0
   ```
4. **Validate the plugin**: `claude plugin validate .` (and fix anything it reports; this has not been run on this repo yet). Test locally before publishing, then from a clean machine: `/plugin marketplace add yourfavCHEFP/chef-p-security-toolkit` and `/plugin install chef-p-security-toolkit@chefp-security`. Confirm a scan works with `${CLAUDE_SKILL_DIR}` paths.
5. **Self-hosted marketplace** is live as soon as the repo is public (`.claude-plugin/marketplace.json`). For Anthropic's community marketplace, use the submission form described in the current Claude Code publishing docs (https://code.claude.com/docs/en/plugins/publish); the claude.ai form needs a Team or Enterprise organization. Marketplace names that imitate official Anthropic names are rejected; `chefp-security` is fine.
6. **Optional distribution**: `npx skills add yourfavCHEFP/chef-p-security-toolkit` style installs work from the `skills/` folder layout; verify against the current tool before advertising it.
7. **Before announcing**: run the benchmark (`evals/`), commit the results file, and make the README claims match it.
