#!/usr/bin/env python3
"""score.py -- measure the toolkit (or any other tool) against seeded ground truth. Stdlib only.

  score.py recall --findings FILE --truth TRUTH [--confirmed-only] [--json OUT]
  score.py fix    --repo DIR --truth TRUTH [--skit PATH] [--json OUT]
  score.py compare RESULT.json RESULT.json ...

FILE is a toolkit findings.json, or a plain JSON list of {title, severity, class, location:{file,line},
sources:[{tool,rule_id}], verdict} so findings from OTHER tools can be scored with the same truth file.
"""
import argparse, json, os, re, subprocess, sys

def load_findings(path):
    d = json.load(open(path))
    if isinstance(d, dict) and "findings" not in d: raise SystemExit(f"{path}: not a findings.json (expected a 'findings' list, or a plain list of finding objects)")
    L = d["findings"] if isinstance(d, dict) else d
    return [f for f in L if not f.get("suppressed") and f.get("verdict") != "rejected"]

def text_of(f):
    parts = [f.get("title", ""), f.get("class", "")] + [s.get("rule_id", "") for s in f.get("sources", [])] + list(f.get("aliases", []))
    if f.get("package"): parts.append(f["package"].get("name", ""))
    return " ".join(str(p) for p in parts)

def matches(item, f):
    loc = (f.get("location") or {}).get("file", "") or ""
    if item.get("file") and item["file"] not in loc and not (f.get("package") and item.get("class") == "dependency"): return False
    if item.get("class") and f.get("class") != item["class"] and item["class"] not in ("any",): return False
    t = text_of(f)
    return any(re.search(rx, t, re.I) for rx in item["any"])

def cmd_recall(a):
    truth = json.load(open(a.truth)); F = load_findings(a.findings)
    if a.confirmed_only: F = [f for f in F if f.get("verdict") in ("confirmed", "fixed")]
    hit, miss, used = [], [], set()
    for it in truth["items"]:
        m = [f for f in F if matches(it, f)]
        if m: hit.append(it["id"]); used |= {f["id"] for f in m if "id" in f}
        else: miss.append(it["id"])
    unmatched = [f for f in F if f.get("id") not in used]
    unverified = [f for f in F if f.get("origin") == "agent" and f.get("verdict") == "needs_validation"]
    res = {"truth": truth["name"], "items": len(truth["items"]), "found": len(hit), "recall": round(len(hit) / len(truth["items"]), 3), "missed": miss,
           "active_findings": len(F), "unmatched_findings": len(unmatched), "unverified_agent_candidates": len(unverified),
           "note": "unmatched findings need human adjudication (true extra vs false positive); precision is not computed automatically"}
    print(f"truth: {res['truth']}  recall: {res['found']}/{res['items']} = {res['recall']}")
    print("missed: " + (", ".join(miss) or "none")); print(f"active findings: {len(F)}  unmatched (adjudicate): {len(unmatched)}  unverified agent candidates: {len(unverified)}")
    for f in unmatched[:15]: print(f"   ? {f.get('id', '')} [{f.get('severity', '')}] {f.get('title', '')[:90]}")
    if a.json: json.dump(res, open(a.json, "w"), indent=2)
    return 0

def cmd_fix(a):
    truth = json.load(open(a.truth)); skit = a.skit or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "chef-p-security-toolkit", "scripts")
    ok = still = inc = 0; rows = []
    for it in truth["items"]:
        v = it.get("verify")
        if not v: continue
        r = subprocess.run(["bash", os.path.join(skit, "verify.sh"), v["tool"], v["id"], v.get("path", ".")], cwd=a.repo, capture_output=True, text=True)
        st = {0: "NOT PRESENT", 1: "STILL PRESENT"}.get(r.returncode, "INCONCLUSIVE"); rows.append((it["id"], st))
        ok += st == "NOT PRESENT"; still += st == "STILL PRESENT"; inc += st == "INCONCLUSIVE"
    t = subprocess.run(["bash", os.path.join(skit, "run-tests.sh"), "."], cwd=a.repo, capture_output=True, text=True)
    tests = {0: "pass", 4: "no tests", 5: "repo not trusted (tests not run)"}.get(t.returncode, "FAIL")
    n = ok + still + inc
    res = {"truth": truth["name"], "verifiable_items": n, "fixed": ok, "still_present": still, "inconclusive": inc, "fix_rate": round(ok / n, 3) if n else None, "tests": tests}
    for i, s in rows: print(f"  {i:18}{s}")
    print(f"fix rate: {ok}/{n}  inconclusive: {inc}  tests: {tests}")
    if a.json: json.dump(res, open(a.json, "w"), indent=2)
    return 0

def cmd_compare(a):
    rs = [json.load(open(p)) for p in a.results]
    keys = ["recall", "found", "items", "active_findings", "unmatched_findings", "unverified_agent_candidates", "fix_rate", "fixed", "tests"]
    print(f"{'metric':32}" + "".join(f"{os.path.basename(p)[:18]:>20}" for p in a.results))
    for k in keys:
        if any(k in r for r in rs): print(f"{k:32}" + "".join(f"{str(r.get(k, '-')):>20}" for r in rs))
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter); sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("recall"); p.add_argument("--findings", required=True); p.add_argument("--truth", required=True); p.add_argument("--confirmed-only", action="store_true"); p.add_argument("--json"); p.set_defaults(fn=cmd_recall)
    p = sp.add_parser("fix"); p.add_argument("--repo", required=True); p.add_argument("--truth", required=True); p.add_argument("--skit"); p.add_argument("--json"); p.set_defaults(fn=cmd_fix)
    p = sp.add_parser("compare"); p.add_argument("results", nargs="+"); p.set_defaults(fn=cmd_compare)
    a = ap.parse_args(); sys.exit(a.fn(a))

if __name__ == "__main__": main()
