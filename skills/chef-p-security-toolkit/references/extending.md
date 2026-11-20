# Extending and sharing the toolkit
## Add a scanner (plugin)
1. Copy `scripts/tools.available/_template.sh.example` to `scripts/tools.d/NN-name.sh`.
2. Fill in: `TOOL_NAME`, `TOOL_MODE` (static | zap | strix | your own mode), `TOOL_ECOS` (any, or python node go rust dotnet java ruby php docker terraform gha mlmodels), `TOOL_REPORT`, `TOOL_HINT`, `tool_installed()`, optional `tool_guard()` (version deny-lists, scope checks), `tool_run()` (uses absolute `$TARGET` and `$OUT`).
3. Check: `scan.sh list`, then `scan.sh static <dir>`, then `verify.sh <name> <id> <path>`.
4. Add a reading guide to `references/tools/`. To get the tool's results into `findings.json` (merging, SARIF, reports), add a parser to `PARSERS` in `scripts/findings.py`; for fix-finish diffs add an extractor to `scripts/findings_diff.py`. Tools whose report is not parsed are listed as 'not normalized' in reports, never hidden.
5. If the tool executes or builds project code (restores, builds, tests), add a `tool_guard` that calls `$HERE/trust.sh check "$TARGET"`.
Disabled optional plugins live in `tools.available/`; move one into `tools.d/` to enable it.
## Add a language/ecosystem
Add a detection line in `detect_ecosystems()` in `scan.sh`, a test command in `run-tests.sh`, a lockfile parser in `incident_scan.py` (`parse_file`), and `references/ecosystems/<lang>.md`.
## Add an attack class for hunt mode
New file in `references/hunt/` with: what to look for, the method, and what kills false positives. Mention it in `hunt/method.md`.
## Add a fix recipe
New file in `references/fixes/`, then mention it in `fix-loop.md`. Keep each recipe: signals, fix pattern per language, verify, pitfalls.
## Share it
The folder contains nothing personal: copy or zip `~/.claude/skills/chef-p-security-toolkit/`. Recipients put it in their own `~/.claude/skills/` (or a project's `.claude/skills/`). For wider distribution package it as a Claude Code plugin (skills plus optional MCP servers and commands) and publish through a plugin marketplace; check the current Claude Code plugin docs for the exact manifest. The same SKILL.md folder format can be reused by other agents such as Codex.
Do not ship real reports, keys, or `security-reports/` folders.
