#!/usr/bin/env bash
# install.sh [--agent NAME]... [--project] [--list]
# Installs the skill (an Agent Skills folder) for one or more coding agents.
#   --agent claude|codex|gemini|copilot|cursor|opencode|universal|all   (default: claude)
#   --project   install into the current repo instead of your user folder
#   --list      show where each agent would get it
# Paths follow each tool's published skills locations (via the Agent Skills ecosystem docs); verify for your version.
# Another route that auto-detects installed agents: npx skills add yourfavCHEFP/chef-p-security-toolkit
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; NAME=chef-p-security-toolkit
agents=(); project=0; list=0
while [ $# -gt 0 ]; do case "$1" in
  --agent) agents+=("${2:?--agent needs a value}"); shift 2;; --project) project=1; shift;; --list) list=1; shift;;
  -h|--help) sed -n 2,10p "$0"; exit 0;; *) echo "unknown option: $1"; exit 2;; esac; done
[ ${#agents[@]} -gt 0 ] || agents=(claude)
ALL=(claude codex gemini copilot cursor opencode universal)
if [ "${agents[0]}" = all ]; then agents=("${ALL[@]}"); fi

dest_for() {  # agent -> skills dir
  local a="$1" cfg="${XDG_CONFIG_HOME:-$HOME/.config}"
  if [ "$project" = 1 ]; then
    case "$a" in claude) echo "$PWD/.claude/skills";; codex|gemini|copilot|cursor|opencode|universal) echo "$PWD/.agents/skills";; *) return 1;; esac
  else
    case "$a" in claude) echo "${CLAUDE_HOME:-$HOME/.claude}/skills";; codex) echo "$HOME/.agents/skills";; gemini) echo "$HOME/.gemini/skills";;
      copilot) echo "$HOME/.copilot/skills";; cursor) echo "$HOME/.cursor/skills";; opencode) echo "$cfg/opencode/skills";; universal) echo "$cfg/agents/skills";; *) return 1;; esac
  fi
}
if [ "$list" = 1 ]; then for a in "${ALL[@]}"; do printf '%-10s user: ' "$a"; project=0 dest_for "$a"; done; echo "project: .agents/skills (claude: .claude/skills)"; exit 0; fi

BK="$HOME/.chefp-skill-backups"; done_dirs=" "
for a in "${agents[@]}"; do
  d="$(dest_for "$a")" || { echo "unknown agent '$a' (see --list)"; exit 2; }
  case "$done_dirs" in *" $d "*) echo "[$a] same folder already installed: $d"; continue;; esac
  mkdir -p "$d"; target="$d/$NAME"
  if [ -d "$target" ]; then mkdir -p "$BK"; mv "$target" "$BK/$NAME.$a.$(date +%Y%m%d%H%M%S)"; echo "[$a] previous copy moved to $BK/"; fi
  cp -R "$HERE/skills/$NAME" "$target"; chmod +x "$target"/scripts/*.sh "$target"/scripts/*.py
  echo "[$a] installed: $target"; done_dirs+="$d "
  if [ "$a" = claude ]; then
    ad="$([ "$project" = 1 ] && echo "$PWD/.claude/agents" || echo "${CLAUDE_HOME:-$HOME/.claude}/agents")"; mkdir -p "$ad"; cp "$HERE/agents/security-verifier.md" "$ad/"; echo "[claude] verifier subagent: $ad/security-verifier.md"
  fi
done
echo; echo "Restart your agent, then ask it to list its skills. Missing scanners are reported as SKIPPED, never ignored:"
echo "  brew install semgrep gitleaks trivy osv-scanner hadolint zizmor && pipx install bandit checkov picklescan"
