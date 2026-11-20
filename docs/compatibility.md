# Compatibility with coding agents
The toolkit is an **Agent Skills** package (open `SKILL.md` format: `name`, `description`, optional `license`, `compatibility`, `metadata`). Scripts are plain bash and Python 3, so they run wherever your agent can run shell commands. Windows: WSL or Git Bash.

| Agent | Project skills folder | User skills folder | Install | Status |
|---|---|---|---|---|
| Claude Code | `.claude/skills` | `~/.claude/skills` (or plugin) | plugin, or `install.sh --agent claude` | Used end to end by the maintainer (scan, fix loop, incident) |
| Codex CLI | `.agents/skills` (cwd up to repo root) | `~/.agents/skills` | `install.sh --agent codex` | Format + paths per OpenAI's Codex skills docs; not yet run in Codex |
| Gemini CLI | `.agents/skills` | `~/.gemini/skills` | `install.sh --agent gemini` | Paths per the Skills CLI docs; not yet run |
| GitHub Copilot | `.agents/skills` | `~/.copilot/skills` | `install.sh --agent copilot` | Paths per the Skills CLI docs; not yet run |
| Cursor | `.agents/skills` | `~/.cursor/skills` | `install.sh --agent cursor` | Paths per the Skills CLI docs; not yet run |
| OpenCode | `.agents/skills` | `~/.config/opencode/skills` | `install.sh --agent opencode` | Paths per the Skills CLI docs; not yet run |
| Amp, Kimi, Replit and others | `.agents/skills` | `~/.config/agents/skills` | `install.sh --agent universal` | Not yet run |
| 40+ more agents | varies | varies | `npx skills add yourfavCHEFP/chef-p-security-toolkit` | Not yet run |
| Agents with no skill support | n/a | n/a | point instructions at `AGENTS.md` | Fallback only |
Folder locations come from OpenAI's Codex docs and the public Skills CLI documentation. Agents change these; if a skill does not appear, check your agent's current docs.

## What differs per agent
- **Independent verifier.** Claude Code gets the `security-verifier` subagent. Everywhere else, hunt mode uses a fresh session fed by `scripts/verify-prompt.sh <finding-id>` (a self-contained prompt that omits the finder's reasoning). The findings store enforces the same rules either way.
- **Plugin systems.** The Claude Code plugin and marketplace manifests are Claude-specific. Codex plugins, Gemini CLI extensions and similar wrappers are not shipped yet; they would wrap this same folder. Contributions welcome.
- **Permission prompts.** Your agent may ask before running scripts. That is expected; read what it runs.
- **Path resolution.** Agents that do not expose the skill's folder use the locator snippet in `SKILL.md`.

## Five-minute smoke test (please report results)
1. Install for your agent, restart it, ask it to list skills; `chef-p-security-toolkit` should appear.
2. `bash scripts/make-testbed.sh ~/security-testbed` (from the installed skill folder), `cd ~/security-testbed/vuln-app`.
3. Ask: "security review this repo". Expect: it resolves the scripts folder, runs `scan.sh`, states which tools ran and which were SKIPPED, and cites rule ids and files.
4. Ask: "fix the findings". Expect a `sec/...` branch, `verify.sh` proof per fix, and no auto-merge. In a repo it does not trust, expect `run-tests.sh` to refuse (exit 5) until you run `trust.sh add <dir> --i-am-the-owner` yourself.
5. Note anything that failed and open an issue with the agent name and version.
