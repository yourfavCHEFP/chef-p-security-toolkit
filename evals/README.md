# Benchmark harness
Measures this toolkit, or any other audit tool, against seeded ground truth. Claims in the README must be backed by a results file here.

## Cases
- `cases/vuln-app.truth.json`: ground truth for the practice repo from `make-testbed.sh` (12 seeded issues; 6 have `verify` specs for fix scoring).
- Add real repos by writing a truth file for bugs you have confirmed.

## Run
```
bash skills/chef-p-security-toolkit/scripts/make-testbed.sh ~/security-testbed
cd ~/security-testbed/vuln-app
# 1. run the tool under test (this toolkit: scan, optionally hunt), then:
python3 <repo>/evals/score.py recall --findings security-reports/findings.json --truth <repo>/evals/cases/vuln-app.truth.json --json results-toolkit-recall.json
# 2. after the tool's fixes (on its branch):
SEC_TRUST=trusted python3 <repo>/evals/score.py fix --repo . --truth <repo>/evals/cases/vuln-app.truth.json --json results-toolkit-fix.json
python3 <repo>/evals/score.py compare results-*.json
```
Other tools: convert their output into a plain JSON list of `{title, severity, class, location:{file,line}, sources:[{tool,rule_id}], verdict}` and pass it to `--findings`. Write the adapter yourself and publish it with the results.

## Scorecard (record per run, per model)
Detection recall; fix rate (finding gone on rescan AND tests pass); regressions (new findings or new test failures from fixes); false claims (assertions without evidence, target 0); unverified candidates reported as findings (target 0); incident accuracy; cost (tokens or dollars) and wall time per run. `score.py` computes recall, fix rate and counts; cost and regressions are recorded by hand in `results-template.md`.
Precision needs human adjudication of "unmatched" findings; do it and say so.
Fairness: same repo, same model where possible, same time/cost budget, fresh context, three runs each (single runs are noisy), publish raw outputs.
