#!/usr/bin/env bash
# Self-test for the toolkit's own logic (no scanners required). Run: bash tests/selftest.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SK="$ROOT/skills/chef-p-security-toolkit/scripts"; FX="$ROOT/tests/fixtures"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export XDG_CONFIG_HOME="$T/cfg"; unset SEC_TRUST SEC_SANDBOX SEC_TRUSTED_OWNERS
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
check(){ local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
fails(){ local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name (should have failed)"; else ok "$name"; fi; }
F() { python3 "$SK/findings.py" --file "$T/r/findings.json" "$@"; }

echo "== syntax"
for f in "$SK"/*.sh "$SK"/tools.d/*.sh "$SK"/tools.available/trufflehog.sh; do check "bash -n $(basename "$f")" bash -n "$f"; done
for f in "$SK"/*.py; do check "py_compile $(basename "$f")" python3 -m py_compile "$f"; done

echo "== testbed + detect"
check "make-testbed" bash "$SK/make-testbed.sh" "$T/tb"
check "testbed has a token-shaped fake secret" grep -q 'ghp_[A-Za-z0-9]\{36\}' "$T/tb/vuln-app/app.py"
fails "toolkit script itself contains no contiguous token" grep -rq 'ghp_[A-Za-z0-9]\{36\}' "$SK"
[ "$(bash "$SK/scan.sh" detect "$T/tb/vuln-app")" = "ecosystems: python docker gha" ] && ok "detect ecosystems" || bad "detect ecosystems"

echo "== findings: ingest, merge, suppress"
mkdir -p "$T/r" "$T/proj"; cp "$FX"/* "$T/r/"; cp "$FX/.secignore.sample" "$T/proj/.secignore"
check "ingest" python3 "$SK/findings.py" --file "$T/r/findings.json" ingest --reports "$T/r" --target "$T/proj"
python3 - "$T/r/findings.json" <<'PY' && ok "merge/suppress counts (9 total, 7 active, requests merged across osv+trivy)" || bad "merge/suppress counts"
import json,sys
d=json.load(open(sys.argv[1])); F=d["findings"]; act=[f for f in F if not f["suppressed"]]
assert len(F)==9 and len(act)==7, (len(F),len(act))
dep=[f for f in act if f["class"]=="dependency"]; assert len(dep)==1 and len(dep[0]["sources"])==2 and dep[0]["package"]["fixed"]=="2.20.0", dep
sql=[f for f in act if f["class"]=="injection" and f["location"]["line"]==11]; assert len(sql)==1 and len(sql[0]["sources"])==2
PY
check "ingest is idempotent" python3 "$SK/findings.py" --file "$T/r/findings.json" ingest --reports "$T/r" --target "$T/proj" --quiet
[ "$(python3 -c "import json;print(len(json.load(open('$T/r/findings.json'))['findings']))")" = 9 ] && ok "re-ingest adds no duplicates" || bad "re-ingest adds no duplicates"
check "validate" F validate
check "report" F report --out "$T/report.md"
check "report lists tool coverage + suppressed" grep -q "suppressed" "$T/report.md"
check "sarif" F sarif --out "$T/out.sarif"
python3 -c "import json;d=json.load(open('$T/out.sarif'));assert d['version']=='2.1.0' and len(d['runs'][0]['results'])==7" && ok "sarif has 7 results" || bad "sarif results"

echo "== verdict rules (enforced in code)"
ID="$(F add --title "IDOR in /orders/<id>" --severity high --class auth --file-path app.py --line 40 --found-by agent:hunter-1 --impact "read other users' orders" --trace app.py:30:route_param --trace app.py:40:db_lookup_no_owner_check)"
[ -n "$ID" ] && ok "agent candidate added ($ID)" || bad "agent candidate added"
fails "confirm without verifier refused" F verdict "$ID" --verdict confirmed
fails "self-verification refused" F verdict "$ID" --verdict confirmed --verified-by agent:hunter-1
fails "confirm without 2-step trace refused" F verdict "$ID" --verdict confirmed --verified-by agent:verifier --trace app.py:30:only_one
fails "reject without reason refused" F verdict "$ID" --verdict rejected --verified-by agent:verifier
check "valid confirmation accepted" F verdict "$ID" --verdict confirmed --verified-by agent:verifier --trace app.py:30:src --trace app.py:40:sink --impact "read other users' orders"
check "validate still passes" F validate
TID="$(python3 -c "import json;print([f['id'] for f in json.load(open('$T/r/findings.json'))['findings'] if f['class']=='dependency'][0])")"
fails "fix-mark rejects non-verify text" F fix-mark "$TID" --commit abc123 --verify "looks fixed"
check "fix-mark accepts verify.sh NOT PRESENT" F fix-mark "$TID" --commit abc123 --verify "NOT PRESENT: 'GHSA' no longer reported"
python3 - "$T/r/findings.json" <<'PY'
import json,sys; d=json.load(open(sys.argv[1]))
d["findings"][0]["origin"]="agent"; d["findings"][0]["verdict"]="reported"; json.dump(d,open(sys.argv[1],"w"))
PY
fails "validate catches agent finding marked 'reported'" F validate

echo "== coverage ledger + staleness"
git -C "$T/proj" init -q; mkdir -p "$T/proj/src"; echo a > "$T/proj/src/a.py"; git -C "$T/proj" add -A >/dev/null
git -C "$T/proj" -c user.name=t -c user.email=t@x.invalid commit -qm one
python3 - <<PY
import json;d=json.load(open("$T/r/findings.json"));d["target"]="$T/proj";json.dump(d,open("$T/r/findings.json","w"))
PY
check "coverage add" F coverage add --area src --kind path --depth traced --by agent:hunter-1 --gaps "no auth review"
echo b >> "$T/proj/src/a.py"; git -C "$T/proj" -c user.name=t -c user.email=t@x.invalid commit -qam two
F coverage stale | grep -q "changed since" && ok "stale coverage detected after the code changed" || bad "stale coverage detection"

echo "== recon"
check "recon runs" python3 "$SK/recon.py" "$T/tb/vuln-app" --out "$T/recon.json"
python3 - "$T/recon.json" <<'PY' && ok "recon finds sql/command/deserialization/crypto leads" || bad "recon leads"
import json,sys; c=json.load(open(sys.argv[1]))["counts"]
for k in ("sql","command-exec","deserialization","crypto"): assert c[k]>0,(k,c)
PY

echo "== trust gate"
mkdir -p "$T/untrusted"
fails "untrusted dir blocked" bash "$SK/trust.sh" check "$T/untrusted"
bash "$SK/run-tests.sh" "$T/untrusted" >/dev/null 2>&1; [ $? -eq 5 ] && ok "run-tests refuses untrusted repo (exit 5)" || bad "run-tests refusal"
check "SEC_TRUST=trusted allows" env SEC_TRUST=trusted bash "$SK/trust.sh" check "$T/untrusted"
check "SEC_SANDBOX=1 allows" env SEC_SANDBOX=1 bash "$SK/trust.sh" check "$T/untrusted"
fails "agent (no tty) cannot mark trusted" bash "$SK/trust.sh" add "$T/untrusted" --i-am-the-owner

echo "== incident: exact + ranges"
IS="$T/tb/incident-sim"
bash "$SK/incident-check.sh" --target "$IS" --pkg litellm=1.82.7,1.82.8 --out "$T/i1.txt" >/dev/null 2>&1; [ $? -eq 3 ] && ok "exact bad version -> EXPOSED (exit 3)" || bad "exact bad version"
bash "$SK/incident-check.sh" --target "$IS" --pkg 'requests<2.32.4' --out "$T/i2.txt" >/dev/null 2>&1; [ $? -eq 3 ] && ok "range 'requests<2.32.4' flags 2.32.3" || bad "range hit"
bash "$SK/incident-check.sh" --target "$IS" --pkg 'requests<2.32.0' --out "$T/i3.txt" >/dev/null 2>&1; [ $? -eq 0 ] && ok "range 'requests<2.32.0' does not flag 2.32.3" || bad "range miss"
bash "$SK/incident-check.sh" --target "$IS" --pkg 'requests>=2.30,<2.32.3' --out "$T/i4.txt" >/dev/null 2>&1; [ $? -eq 0 ] && ok "AND-range boundary (<2.32.3 excludes 2.32.3)" || bad "range boundary"
python3 - <<PY && ok "version ordering (rc < release, date versions)" || bad "version ordering"
import sys; sys.path.insert(0,"$SK"); import incident_scan as s
assert s.vcmp("1.0rc1","1.0")<0 and s.vcmp("2026.10.19","2026.10.18")>0 and s.vcmp("1.10","1.9")>0 and s.vcmp("3.14.4","3.14.4")==0
PY

echo "== scan summary honesty"
OUT1="$(cd "$T/tb/vuln-app" && PATH="/usr/bin:/bin" SEC_OUT="$T/o" bash "$SK/scan.sh" static . 2>&1)"
echo "$OUT1" | grep -q "SKIPPED" && echo "$OUT1" | grep -q "did NOT run" && ok "missing tools reported as SKIPPED, with warning" || bad "skipped-tool warning"
[ -f "$T/o/findings.json" ] && ok "scan auto-ingests into findings.json" || bad "auto-ingest"

echo "== benchmark scorer"
python3 "$ROOT/evals/score.py" recall --findings "$T/r/findings.json" --truth "$ROOT/evals/cases/vuln-app.truth.json" --json "$T/s1.json" >/dev/null 2>&1
python3 -c "import json;r=json.load(open('$T/s1.json'));assert r['items']==12 and r['found']>=6,r" && ok "scorer computes recall against ground truth" || bad "scorer recall"
python3 "$ROOT/evals/score.py" compare "$T/s1.json" "$T/s1.json" >/dev/null 2>&1 && ok "scorer compare" || bad "scorer compare"

echo "== Agent Skills standard compliance + multi-agent install"
python3 - "$ROOT/skills/chef-p-security-toolkit" <<'PY' && ok "SKILL.md frontmatter meets the Agent Skills spec (name=dir, <=64 kebab, desc<=1024, compat<=500)" || bad "SKILL.md spec compliance"
import re,sys,os
d=sys.argv[1]; t=open(os.path.join(d,"SKILL.md")).read(); m=re.match(r"^---\n(.*?)\n---\n(.*)$",t,re.S); assert m, "frontmatter"
fm,body=m.groups(); get=lambda k: (re.search(rf"^{k}: (.*)$",fm,re.M) or [None,None])[1]
name,desc,comp=get("name"),get("description"),get("compatibility")
assert name==os.path.basename(d) and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*",name) and len(name)<=64,name
assert 1<=len(desc)<=1024,len(desc); assert comp and len(comp)<=500; assert get("license")=="MIT"; assert body.strip()
assert "metadata:" in fm and re.search(r'^  version: "',fm,re.M)
assert len(body)<20000, len(body)
PY
HOMEX="$T/home"; mkdir -p "$HOMEX"; export XDG_CONFIG_HOME="$HOMEX/.config"
check "install.sh --agent all" env HOME="$HOMEX" CLAUDE_HOME="$HOMEX/.claude" bash "$ROOT/install.sh" --agent all
for d in .claude/skills .agents/skills .gemini/skills .copilot/skills .cursor/skills .config/opencode/skills .config/agents/skills; do
  [ -x "$HOMEX/$d/chef-p-security-toolkit/scripts/scan.sh" ] && ok "installed for $d" || bad "installed for $d"; done
[ -f "$HOMEX/.claude/agents/security-verifier.md" ] && ok "claude verifier subagent installed" || bad "verifier subagent"
check "installed copy runs (scan.sh list)" bash "$HOMEX/.agents/skills/chef-p-security-toolkit/scripts/scan.sh" list
check "reinstall backs up outside skills dirs" env HOME="$HOMEX" CLAUDE_HOME="$HOMEX/.claude" bash "$ROOT/install.sh" --agent codex
compgen -G "$HOMEX/.chefp-skill-backups/*codex*" >/dev/null && ok "backup stored in ~/.chefp-skill-backups" || bad "backup location"
mkdir -p "$T/proj2"; (cd "$T/proj2" && HOME="$HOMEX" bash "$ROOT/install.sh" --agent codex --project >/dev/null 2>&1); [ -x "$T/proj2/.agents/skills/chef-p-security-toolkit/scripts/scan.sh" ] && ok "--project installs to ./.agents/skills" || bad "--project install"
fails "unknown agent rejected" env HOME="$HOMEX" bash "$ROOT/install.sh" --agent nonsense
python3 - "$ROOT/skills/chef-p-security-toolkit/SKILL.md" > "$T/locate.sh" <<'PY'
import re,sys; t=open(sys.argv[1]).read(); print(re.search(r"```sh\n(# locate-skill.*?)```",t,re.S).group(1))
PY
OUTL="$(cd "$T" && env -u CLAUDE_SKILL_DIR HOME="$HOMEX" bash "$T/locate.sh")"
[ "$OUTL" = "SK=$HOMEX/.agents/skills/chef-p-security-toolkit/scripts" ] || echo "$OUTL" | grep -q "chef-p-security-toolkit/scripts" && ok "path-locator snippet finds the installed skill ($OUTL)" || bad "locator snippet"
OUTN="$(cd "$T" && env -u CLAUDE_SKILL_DIR -u XDG_CONFIG_HOME HOME="$T/empty-home" bash "$T/locate.sh")"; [ "$OUTN" = "SK=NOT FOUND" ] && ok "locator reports NOT FOUND instead of guessing" || bad "locator not-found"
echo "== portable verifier prompt"
VID="$(python3 -c "import json;print([f['id'] for f in json.load(open('$T/r/findings.json'))['findings'] if f['origin']=='agent'][0])")"
VP="$(bash "$SK/verify-prompt.sh" "$VID" "$T/r/findings.json")"
echo "$VP" | grep -q "$VID" && echo "$VP" | grep -q "findings.py" && echo "$VP" | grep -q "DISPROVE" && ok "verify-prompt.sh builds a self-contained prompt" || bad "verify-prompt content"
echo "$VP" | grep -q "route_param" && bad "prompt leaks the finder's trace (anchoring)" || ok "prompt omits the finder's trace"
fails "verify-prompt rejects unknown id" bash "$SK/verify-prompt.sh" F-nope "$T/r/findings.json"

echo; echo "passed: $PASS  failed: $FAIL"; [ "$FAIL" -eq 0 ]
