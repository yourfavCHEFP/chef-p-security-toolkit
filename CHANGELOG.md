# Changelog

## 3.1.0
- Portable across coding agents: SKILL.md follows the Agent Skills standard (license, compatibility, metadata; description under 1024 chars), no longer depends on a Claude-only path variable (path locator snippet), and verification works in any agent through `verify-prompt.sh` (fresh-session prompt that omits the finder's reasoning).
- `install.sh --agent claude|codex|gemini|copilot|cursor|opencode|universal|all [--project]`; backups moved out of skills folders; `AGENTS.md` fallback for agents without skills; `docs/compatibility.md`.
- Fixed report generation on Python 3.11, self-test discovery in `run-tests.sh`, and OSV-Scanner behavior when no lockfiles exist.
- Self-test grew to 92 checks (spec compliance, multi-agent install, locator, verifier prompt, and test-runner discovery).

## 3.0.0
- Findings store (`findings.py`): one JSON file, rules enforced in code (verdicts, independent verification, traces, fix proof), cross-tool dedupe by advisory alias and location, generated reports, SARIF export, coverage ledger with staleness.
- Hunt mode: recon, threat-model method, attack-class guides (web/API, auth, AI/LLM apps, supply chain, memory safety, client-side, secrets/config), `security-verifier` subagent.
- Trust gate for anything that executes project code; agents cannot mark a repo trusted.
- `.secignore` and visible default noise suppression; incident version ranges (`--pkg 'certifi<2026.10.18'`).
- Benchmark harness (`evals/`): ground truth, recall and fix-rate scoring, comparison table.
- Packaging as a Claude Code plugin and marketplace; scripts resolve through `${CLAUDE_SKILL_DIR}`.

## 2.0.0
- Plugin-driven multi-language scan orchestrator, fix loop (`fix-start/verify/fix-finish`), incident exposure checker, practice testbed.

## 1.0.0
- Five-tool scan skill (Strix, Semgrep, Gitleaks, ZAP, Trivy).
