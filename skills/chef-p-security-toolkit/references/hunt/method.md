# Hunt mode: finding bugs the scanners cannot
Goal: surface real, exploitable flaws (logic, authorization, trust-boundary, AI-specific) with evidence. Scanners already cover known patterns, so hunting starts where they stop. Every candidate is verified by a DIFFERENT agent before it counts.

## 0. Preconditions
- The user owns the code or has permission. Hunt reads code; it does not execute it. Anything that runs project code (tests, PoCs) needs `trust.sh check` to pass (exit 0), otherwise leave the lead as `needs_validation`.
- Ask nothing you can infer. If the target or scope is genuinely unclear, ask ONE question.

## 1. Baseline (cheap, deterministic)
`scan.sh static .` (auto-ingests into `security-reports/findings.json`), then `python3 $SK/recon.py .` for candidate sinks and entry points. Do not re-hunt what a tool already reported; read its finding instead.

## 2. Threat model in five lines (write it into your notes)
Assets (data, money, keys, compute) / attackers (anonymous, user, other tenant, malicious content, insider) / entry points (from recon `entrypoint`) / trust boundaries (where untrusted data enters; where privileges change) / what "game over" means here.

## 3. Coverage plan
List areas (directories, modules, endpoints) ranked by exposure x sensitivity. Work the top of the list. After finishing an area record it:
`python3 $SK/findings.py coverage add --area src/api --depth traced --by agent:hunter --gaps "billing not reviewed"`
Depth means: `tool-only` (only scanners saw it), `skimmed`, `read` (read fully), `traced` (source->sink traced for each lead). Be honest: skimming is not tracing.

## 4. Hunt (per area x attack class)
Load the class files that fit the target (`references/hunt/*.md`). For each lead: find where untrusted data enters, follow it to a sensitive sink, list every check on the way, decide if an attacker still reaches the sink. Use recon leads as starting points only.
Record a candidate only with: title, severity, class, file:line, an impact sentence (what the attacker gains) and the trace so far:
`python3 $SK/findings.py add --title "..." --severity high --class auth --file-path app.py --line 40 --found-by agent:hunter --impact "..." --trace app.py:30:route_param --trace app.py:40:query_without_owner_check`
It starts as `needs_validation`. You may NOT confirm your own finding.

## 5. Verify (independent, fresh context)
For each candidate, run the `security-verifier` subagent (or, without subagents, a new session) with: the finding id, the absolute path of `findings.py`, and nothing about your reasoning. Read `references/hunt/verification.md`. The verifier records `confirmed`, `needs_validation` or `rejected`; the store refuses a confirmation without verifier, trace and impact.

## 6. Report
`python3 $SK/findings.py validate && python3 $SK/findings.py report --out security-reports/REPORT.md`; `sarif` if the user wants GitHub code scanning. The report lists confirmed findings first, unverified candidates separately, rejections with reasons, and the coverage ledger including gaps. Never write "no more vulnerabilities". Say what was covered, at what depth, and what was not.

## 7. Later runs
`findings.py coverage stale` lists areas whose code changed since they were covered. Re-hunt those first. Earlier evidence on changed code does not count.

## Budget and discipline
Hunting is token-hungry. Start from recon's top leads, cap yourself (for example 5 candidates per area), stop an area when two consecutive leads die at the same control. Use a cheaper model for recon/triage and the strongest model for verification. For a slow local model run overnight: one area per pass, small contexts, and rely on `findings.json` and the coverage ledger to resume; never rely on conversation memory.
