#!/usr/bin/env python3
"""findings.py -- the findings store for the CHEF_P Security Toolkit. Stdlib only.

One JSON file (default security-reports/findings.json) holds findings, runs and a coverage ledger.
Reports are GENERATED from it. Rules are enforced here, not left to the model:
  * a finding found by an agent starts as needs_validation
  * 'confirmed' needs a trace (>=2 steps with file+line), an impact, and a verifier different from the finder
  * 'rejected' needs a reason and a verifier
  * 'fixed' needs the commit and the literal verify.sh result 'NOT PRESENT'

commands: ingest | add | verdict | fix-mark | validate | report | sarif | stats | coverage add|list|stale
"""
import argparse, datetime, fnmatch, hashlib, json, os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_secignore, ignored, rel

SCHEMA_VERSION = "1.0"
SEV = ["info", "low", "medium", "high", "critical"]
VERDICTS = ["reported", "needs_validation", "confirmed", "rejected", "fixed"]
CLASSES = ["injection", "deserialization", "secrets", "dependency", "ci-cd", "iac", "crypto", "auth",
           "path-traversal", "xss", "ssrf", "ai-llm", "memory-safety", "config", "other"]
TEST_NOISE_RULES = {"B101", "B311", "B105", "B106", "B404", "B603", "B607"}   # suppressed ONLY under test paths

def now(): return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def git(target, *args):
    try:
        r = subprocess.run(["git", "-C", target, *args], capture_output=True, text=True, timeout=60)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception: return ""

def load(path):
    if not os.path.exists(path):
        return {"schema_version": SCHEMA_VERSION, "tool": "chef-p-security-toolkit", "target": "", "created": now(),
                "updated": now(), "runs": [], "findings": [], "coverage": []}
    with open(path) as f: return json.load(f)

def save(path, d):
    d["updated"] = now()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f: json.dump(d, f, indent=2, sort_keys=False)

def fid(*parts): return "F-" + hashlib.sha1("|".join(str(p) for p in parts).encode(), usedforsecurity=False).hexdigest()[:8]
def sev_max(a, b): return a if SEV.index(a) >= SEV.index(b) else b
def norm_pkg(n): return re.sub(r"[-_.]+", "-", (n or "").strip()).lower()

def classify(tool, rule, text):
    t = f"{rule} {text}".lower()
    pairs = [("injection", r"sql|command|shell|exec|subprocess|injection|template"), ("deserialization", r"pickle|deserial|yaml\.load|marshal|unsafe-load|torch\.load"),
             ("crypto", r"md5|sha1|hash|crypto|random|tls|ssl|cipher|verify=false|certificate"), ("auth", r"auth|jwt|session|csrf|permission|password"),
             ("path-traversal", r"path|traversal|zip-?slip"), ("xss", r"xss|innerhtml|cross-site"), ("ssrf", r"ssrf"),
             ("secrets", r"secret|token|api[-_ ]?key|credential")]
    for c, rx in pairs:
        if re.search(rx, t): return c
    return "other"

# ---------------------------------------------------------------- parsers: report -> normalized dicts
def jload(p):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return None

def p_semgrep(d, target):
    out = []
    for run in (d or {}).get("runs", []):
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", ""); line = (loc.get("region") or {}).get("startLine")
            lvl = r.get("level", "warning"); sev = {"error": "high", "warning": "medium", "note": "low"}.get(lvl, "medium")
            msg = (r.get("message") or {}).get("text", "")
            out.append(dict(tool="semgrep", rule=r.get("ruleId", "?"), severity=sev, title=msg[:160], file=uri, line=line, cls=classify("semgrep", r.get("ruleId", ""), msg)))
    return out

def p_gitleaks(d, target):
    return [dict(tool="gitleaks", rule=x.get("RuleID", "?"), severity="high", title=f"Possible secret ({x.get('RuleID','?')}) - value redacted",
                 file=x.get("File", ""), line=x.get("StartLine"), cls="secrets", extra={"commit": x.get("Commit", "")}) for x in (d or []) if isinstance(x, dict)]

def p_bandit(d, target):
    out = []
    for x in (d or {}).get("results", []):
        out.append(dict(tool="bandit", rule=x.get("test_id", "?"), severity=(x.get("issue_severity") or "MEDIUM").lower(), title=x.get("issue_text", "")[:160],
                        file=x.get("filename", ""), line=x.get("line_number"), cls=classify("bandit", x.get("test_name", ""), x.get("issue_text", ""))))
    return out

def sevmap(s):
    s = (s or "").lower()
    return {"moderate": "medium", "unknown": "info", "negligible": "info"}.get(s, s if s in SEV else "medium")

def p_trivy(d, target):
    out = []
    for res in (d or {}).get("Results", []) or []:
        t = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            out.append(dict(tool="trivy", rule=v.get("VulnerabilityID", "?"), severity=sevmap(v.get("Severity")), title=(v.get("Title") or v.get("VulnerabilityID", ""))[:160],
                            file=t, line=None, cls="dependency", pkg={"name": v.get("PkgName", ""), "version": v.get("InstalledVersion", ""), "fixed": v.get("FixedVersion", "")},
                            aliases=[v.get("VulnerabilityID", "")]))
        for m in res.get("Misconfigurations") or []:
            out.append(dict(tool="trivy", rule=m.get("ID", "?"), severity=sevmap(m.get("Severity")), title=(m.get("Title") or "")[:160], file=t, line=((m.get("CauseMetadata") or {}).get("StartLine")), cls="iac"))
        for s in res.get("Secrets") or []:
            out.append(dict(tool="trivy", rule=s.get("RuleID", "?"), severity=sevmap(s.get("Severity")) if s.get("Severity") else "high", title="Possible secret - value redacted", file=t, line=s.get("StartLine"), cls="secrets"))
    return out

def p_osv(d, target):
    out = []
    for r in (d or {}).get("results", []) or []:
        src = (r.get("source") or {}).get("path", "")
        for p in r.get("packages", []) or []:
            pk = p.get("package") or {}
            for v in p.get("vulnerabilities", []) or []:
                sev = sevmap((v.get("database_specific") or {}).get("severity"))
                fixed = ""
                for a in v.get("affected", []) or []:
                    if norm_pkg((a.get("package") or {}).get("name")) == norm_pkg(pk.get("name")):
                        for rg in a.get("ranges", []) or []:
                            for ev in rg.get("events", []) or []:
                                if ev.get("fixed"): fixed = ev["fixed"]
                out.append(dict(tool="osv-scanner", rule=v.get("id", "?"), severity=sev, title=(v.get("summary") or v.get("id", ""))[:160], file=src, line=None, cls="dependency",
                                pkg={"name": pk.get("name", ""), "version": pk.get("version", ""), "fixed": fixed, "ecosystem": pk.get("ecosystem", "")},
                                aliases=[v.get("id", "")] + list(v.get("aliases") or [])))
    return out

def p_hadolint(d, target):
    m = {"error": "medium", "warning": "low", "info": "info", "style": "info"}
    return [dict(tool="hadolint", rule=x.get("code", "?"), severity=m.get(x.get("level", ""), "low"), title=x.get("message", "")[:160], file=x.get("file", ""), line=x.get("line"), cls="iac")
            for x in (d or []) if isinstance(x, dict)]

def p_checkov(d, target):
    out = []
    for blk in (d if isinstance(d, list) else [d or {}]):
        for c in ((blk.get("results") or {}).get("failed_checks") or []):
            out.append(dict(tool="checkov", rule=c.get("check_id", "?"), severity=sevmap(c.get("severity") or "medium"), title=(c.get("check_name") or "")[:160],
                            file=(c.get("file_path") or "").lstrip("/"), line=(c.get("file_line_range") or [None])[0], cls="iac"))
    return out

def p_npm(d, target):
    return [dict(tool="npm-audit", rule=n, severity=sevmap(v.get("severity")), title=f"{n}: vulnerable dependency (fix available: {bool(v.get('fixAvailable'))})", file="package-lock.json", line=None,
                 cls="dependency", pkg={"name": n, "version": "", "fixed": ""}, aliases=[n]) for n, v in ((d or {}).get("vulnerabilities") or {}).items()]

def p_cargo(d, target):
    out = []
    for v in (((d or {}).get("vulnerabilities") or {}).get("list") or []):
        a, p = v.get("advisory") or {}, v.get("package") or {}
        out.append(dict(tool="cargo-audit", rule=a.get("id", "?"), severity="high", title=(a.get("title") or "")[:160], file="Cargo.lock", line=None, cls="dependency",
                        pkg={"name": p.get("name", ""), "version": p.get("version", ""), "fixed": ", ".join((v.get("versions") or {}).get("patched", []) or [])},
                        aliases=[a.get("id", "")] + list(a.get("aliases") or [])))
    return out

def p_zizmor(d, target):
    out = []
    for x in (d if isinstance(d, list) else []):
        if not isinstance(x, dict) or "ident" not in x: continue
        sev = ((x.get("determinations") or {}).get("severity") or "medium").lower()
        f, line = "", None
        try:
            loc = x["locations"][0]; f = loc["symbolic"]["key"]["Local"]["given_path"]; line = loc["concrete"]["location"]["start_point"]["row"] + 1
        except Exception: pass
        out.append(dict(tool="zizmor", rule=x["ident"], severity=sevmap(sev), title=(x.get("desc") or x["ident"])[:160], file=f, line=line, cls="ci-cd"))
    return out

PARSERS = {"semgrep.sarif": p_semgrep, "gitleaks-worktree.json": p_gitleaks, "gitleaks-history.json": p_gitleaks, "bandit.json": p_bandit,
           "trivy.json": p_trivy, "osv.json": p_osv, "hadolint.json": p_hadolint, "checkov.json": p_checkov, "npm-audit.json": p_npm,
           "cargo-audit.json": p_cargo, "zizmor.json": p_zizmor}
RAW_ONLY = ["govulncheck.json", "dotnet-vulnerable.txt", "picklescan.txt", "zap.json", "trufflehog.json"]

# ---------------------------------------------------------------- store operations
def find_merge(findings, n):
    """Return an existing finding this normalized item should merge into (same fingerprint, shared advisory alias on the same package, or same file+line+class)."""
    key = fid(n["tool"], n["rule"], n.get("file", ""), (n.get("pkg") or {}).get("name", ""), n.get("line") if n["cls"] != "dependency" else "")
    for f in findings:
        if f["id"] == key: return f, key
    if n["cls"] == "dependency" and n.get("pkg"):
        pk, al = norm_pkg(n["pkg"]["name"]), {a.upper() for a in n.get("aliases", []) if a}
        for f in findings:
            if f.get("package") and norm_pkg(f["package"]["name"]) == pk and al & {a.upper() for a in f.get("aliases", [])}: return f, key
    elif n.get("file") and n.get("line"):
        for f in findings:
            L = f.get("location") or {}
            if f["class"] == n["cls"] and L.get("file") == n["file"] and L.get("line") == n["line"] and f["origin"] == "tool": return f, key
    return None, key

def cmd_ingest(a):
    d = load(a.file); target = os.path.abspath(a.target); d["target"] = d.get("target") or target
    pats = load_secignore(target); run_id = f"run-{len(d['runs']) + 1}"; seen = set(); unparsed, parsed = [], []
    for name, fn in PARSERS.items():
        p = os.path.join(a.reports, name)
        if not os.path.exists(p) or os.path.getsize(p) == 0: continue
        items = fn(jload(p), target); parsed.append(f"{name}:{len(items)}")
        for n in items:
            n["file"] = rel(os.path.join(target, n["file"]) if n["file"] and not os.path.isabs(n["file"]) else n["file"], target) if n.get("file") else ""
            f, key = find_merge(d["findings"], n)
            sup = None
            if n.get("file") and ignored(n["file"], pats): sup = ".secignore"
            elif n["tool"] == "bandit" and n["rule"] in TEST_NOISE_RULES and re.search(r"(^|/)(tests?|__tests__)/|test_[^/]*\.py$|_test\.py$", n.get("file", "")): sup = "test-noise (default rule)"
            src = {"tool": n["tool"], "rule_id": n["rule"], "report": name}
            if f is None:
                f = {"id": key, "title": n["title"], "severity": n["severity"], "class": n["cls"], "origin": "tool", "found_by": n["tool"], "verified_by": None, "verdict": "reported",
                     "sources": [src], "location": {"file": n.get("file", ""), "line": n.get("line")} if n.get("file") else None, "package": n.get("pkg"),
                     "aliases": sorted({x for x in n.get("aliases", []) if x}), "impact": "", "trace": [], "suppressed": sup, "first_seen": run_id,
                     "history": [{"at": now(), "event": f"ingested from {n['tool']}", "by": n["tool"]}]}
                d["findings"].append(f)
            else:
                if src not in f["sources"]: f["sources"].append(src)
                f["severity"] = sev_max(f["severity"], n["severity"])
                f["aliases"] = sorted(set(f.get("aliases", [])) | {x for x in n.get("aliases", []) if x})
                if f.get("package") and n.get("pkg") and n["pkg"].get("fixed") and not f["package"].get("fixed"): f["package"]["fixed"] = n["pkg"]["fixed"]
                if f["verdict"] == "fixed": f["verdict"] = "reported"; f["history"].append({"at": now(), "event": "reappeared in scan", "by": n["tool"]})
                if sup and not f.get("suppressed"): f["suppressed"] = sup
            f["last_seen"] = run_id; seen.add(f["id"])
    for name in RAW_ONLY:
        if os.path.exists(os.path.join(a.reports, name)): unparsed.append(name)
    tools = []
    if a.summary and os.path.exists(a.summary):
        for line in open(a.summary):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3: tools.append({"tool": parts[0], "status": parts[1], "detail": parts[2]})
    d["runs"].append({"id": run_id, "at": now(), "kind": "ingest", "commit": git(target, "rev-parse", "--short", "HEAD"), "tools": tools, "parsed": parsed, "not_normalized": unparsed})
    save(a.file, d)
    if not a.quiet:
        live = [f for f in d["findings"] if not f.get("suppressed")]
        print(f"ingested {len(seen)} findings ({len(live)} active, {len(d['findings']) - len(live)} suppressed) -> {a.file}")
        if unparsed: print("not normalized (read raw): " + ", ".join(unparsed))
    return 0

def parse_trace(items):
    out = []
    for t in items or []:
        p = t.split(":", 2)
        try: out.append({"file": p[0], "line": int(p[1]), "note": p[2] if len(p) > 2 else ""})
        except (IndexError, ValueError): raise SystemExit(f"bad --trace '{t}': use file:line:note")
    return out

def get(d, i):
    for f in d["findings"]:
        if f["id"] == i: return f
    raise SystemExit(f"no such finding: {i}")

def cmd_add(a):
    d = load(a.file)
    if not a.found_by.startswith("agent:"): raise SystemExit("--found-by must look like agent:<id>")
    if a.cls not in CLASSES: raise SystemExit(f"--class must be one of {CLASSES}")
    tr = parse_trace(a.trace); loc = {"file": a.file_path, "line": a.line} if a.file_path else None
    f = {"id": fid("agent", a.title, a.file_path, a.line), "title": a.title, "severity": a.severity, "class": a.cls, "origin": "agent", "found_by": a.found_by, "verified_by": None,
         "verdict": "needs_validation", "sources": [{"tool": a.found_by, "rule_id": a.cls, "report": "hunt"}], "location": loc, "package": None, "aliases": [], "impact": a.impact or "",
         "trace": tr, "suppressed": None, "first_seen": f"run-{len(d['runs'])}", "history": [{"at": now(), "event": "candidate added", "by": a.found_by}]}
    if any(x["id"] == f["id"] for x in d["findings"]): raise SystemExit(f"duplicate candidate {f['id']}")
    d["findings"].append(f); save(a.file, d); print(f["id"]); return 0

def check_verdict(f, verdict, verified_by, trace, impact, reason):
    if verdict == "confirmed":
        if not verified_by: return "confirmed needs --verified-by"
        if verified_by == f["found_by"]: return "the verifier must differ from the finder"
        if len([t for t in trace if t.get("file") and t.get("line")]) < 2: return "confirmed needs a trace of >=2 steps (file:line:note), e.g. source -> sink"
        if not impact: return "confirmed needs --impact (what an attacker gains)"
    if verdict == "rejected":
        if not verified_by or not reason: return "rejected needs --verified-by and --reason"
    return None

def cmd_verdict(a):
    d = load(a.file); f = get(d, a.id)
    if a.verdict not in ("confirmed", "needs_validation", "rejected"): raise SystemExit("verdict must be confirmed | needs_validation | rejected")
    tr = f["trace"] if not a.trace else parse_trace(a.trace)
    err = check_verdict(f, a.verdict, a.verified_by, tr, a.impact or f.get("impact"), a.reason)
    if err: print("REFUSED: " + err); return 1
    f["verdict"], f["verified_by"], f["trace"] = a.verdict, a.verified_by, tr
    if a.impact: f["impact"] = a.impact
    if a.reason: f["rejection_reason"] = a.reason
    f["history"].append({"at": now(), "event": f"verdict {a.verdict}", "by": a.verified_by or "n/a"})
    save(a.file, d); print(f"{a.id} -> {a.verdict}"); return 0

def cmd_fix_mark(a):
    d = load(a.file); f = get(d, a.id)
    if a.verify.strip().upper().startswith("NOT PRESENT") is False: print("REFUSED: --verify must be the literal verify.sh result starting with 'NOT PRESENT'"); return 1
    if not a.commit: print("REFUSED: --commit required"); return 1
    f["verdict"] = "fixed"; f["fix"] = {"commit": a.commit, "verify_result": a.verify, "by": a.by, "at": now()}
    f["history"].append({"at": now(), "event": "fixed", "by": a.by}); save(a.file, d); print(f"{a.id} -> fixed"); return 0

def problems(d):
    errs, ids = [], set()
    for f in d["findings"]:
        i = f.get("id", "?")
        if i in ids: errs.append(f"{i}: duplicate id")
        ids.add(i)
        for k in ("title", "severity", "class", "origin", "found_by", "verdict"):
            if not f.get(k): errs.append(f"{i}: missing {k}")
        if f.get("severity") not in SEV: errs.append(f"{i}: bad severity {f.get('severity')}")
        if f.get("verdict") not in VERDICTS: errs.append(f"{i}: bad verdict {f.get('verdict')}")
        if f.get("class") not in CLASSES: errs.append(f"{i}: bad class {f.get('class')}")
        if f.get("origin") == "agent" and f.get("verdict") == "reported": errs.append(f"{i}: agent findings cannot be 'reported'")
        if f.get("verdict") in ("confirmed", "rejected"):
            e = check_verdict(f, f["verdict"], f.get("verified_by"), f.get("trace", []), f.get("impact"), f.get("rejection_reason"))
            if e: errs.append(f"{i}: {e}")
        if f.get("verdict") == "fixed" and not (f.get("fix") or {}).get("commit"): errs.append(f"{i}: fixed without fix.commit")
        if f.get("origin") == "agent" and f.get("severity") not in ("info",) and not f.get("impact") and f.get("verdict") != "rejected": errs.append(f"{i}: agent finding above 'info' needs an impact statement")
    for c in d.get("coverage", []):
        if not c.get("area") or c.get("depth") not in ("tool-only", "skimmed", "read", "traced"): errs.append(f"coverage {c.get('id','?')}: bad area/depth")
    return errs

def cmd_validate(a):
    d = load(a.file); errs = problems(d)
    if errs: print("INVALID:"); [print("  - " + e) for e in errs]; return 1
    print(f"valid: {len(d['findings'])} findings, {len(d.get('coverage', []))} coverage entries"); return 0

def live(d, include_rejected=False):
    return [f for f in d["findings"] if not f.get("suppressed") and (include_rejected or f["verdict"] != "rejected")]

def cmd_stats(a):
    d = load(a.file); L = live(d, True); by = {}
    for f in L: by.setdefault(f["verdict"], {}).setdefault(f["severity"], 0); by[f["verdict"]][f["severity"]] += 1
    print(f"findings: {len(L)} active, {len(d['findings']) - len(L)} suppressed")
    for v in VERDICTS:
        if v in by: print(f"  {v:17}" + "  ".join(f"{s}:{by[v][s]}" for s in reversed(SEV) if s in by[v]))
    last = d["runs"][-1]["id"] if d["runs"] else None
    gone = [f for f in L if f["origin"] == "tool" and f["verdict"] != "fixed" and f.get("last_seen") != last]
    if gone: print(f"  not seen in latest scan (fixed candidates, verify before marking): {len(gone)}")
    return 0

def stale_entries(d, target):
    out, head = [], git(target, "rev-parse", "--short", "HEAD")
    for c in d.get("coverage", []):
        if c.get("kind") == "path" and c.get("commit") and head and c["commit"] != head:
            changed = git(target, "diff", "--name-only", c["commit"], "HEAD").splitlines()
            hit = [x for x in changed if x == c["area"] or x.startswith(c["area"].rstrip("/") + "/")]
            if hit: out.append((c, hit))
    return out

def cmd_coverage(a):
    d = load(a.file); target = d.get("target") or "."
    if a.action == "add":
        if a.depth not in ("tool-only", "skimmed", "read", "traced"): raise SystemExit("--depth: tool-only|skimmed|read|traced")
        c = {"id": f"C-{len(d['coverage']) + 1}", "area": a.area, "kind": a.kind, "depth": a.depth, "by": a.by, "at": now(), "commit": git(target, "rev-parse", "--short", "HEAD"), "note": a.note or "", "gaps": a.gaps or ""}
        d["coverage"].append(c); save(a.file, d); print(c["id"]); return 0
    if a.action == "list":
        stale = {c["id"] for c, _ in stale_entries(d, target)}
        for c in d["coverage"]: print(f"{c['id']:6} {c['kind']:5} {c['depth']:9} {c['area']:34} by={c['by']}{'  STALE' if c['id'] in stale else ''}{('  gaps: ' + c['gaps']) if c.get('gaps') else ''}")
        if not d["coverage"]: print("(no coverage recorded)")
        return 0
    if a.action == "stale":
        s = stale_entries(d, target)
        for c, hit in s: print(f"{c['id']} {c['area']}: {len(hit)} file(s) changed since {c['commit']}, e.g. {hit[0]}")
        if not s: print("no stale coverage")
        return 0
    return 2

def cmd_report(a):
    d = load(a.file); L = live(d, True); target = d.get("target") or "."; o = []
    o.append(f"# Security report\n\nGenerated {now()} from `{os.path.basename(a.file)}`. Target: `{target}`. This file is generated; edit the findings data, not this report.\n")
    if d["runs"]:
        r = d["runs"][-1]; o.append(f"## Tool coverage (latest scan {r['id']}, commit {r.get('commit') or 'n/a'})\n")
        o.append("| Tool | Status | Detail |\n|---|---|---|")
        for t in r.get("tools", []): o.append(f"| {t['tool']} | {t['status']} | {t['detail']} |")
        if r.get("not_normalized"): o.append("\nReports present but not normalized (read raw): " + ", ".join(r["not_normalized"]))
        if any(t["status"] in ("SKIPPED", "BLOCKED", "FAILED") for t in r.get("tools", [])): o.append("\n**Skipped, blocked or failed checks did not run. Missing findings from them mean nothing.**")
    o.append("\n## Summary\n")
    for v in VERDICTS:
        n = [f for f in L if f["verdict"] == v]
        if n: o.append(f"- {v}: {len(n)} ({', '.join(f'{s} {sum(1 for f in n if f['severity']==s)}' for s in reversed(SEV) if any(f['severity']==s for f in n))})")
    sup = len(d["findings"]) - len([f for f in d["findings"] if not f.get("suppressed")])
    if sup: o.append(f"- suppressed (noise rules / .secignore): {sup}")
    def table(title, items):
        if not items: return
        o.append(f"\n## {title}\n"); o.append("| ID | Sev | Class | Location | Finding | Evidence |\n|---|---|---|---|---|---|")
        for f in sorted(items, key=lambda f: -SEV.index(f["severity"])):
            L2 = f.get("location") or {}; loc = (L2.get("file", "") + (f":{L2['line']}" if L2.get("line") else "")) or (f.get("package") or {}).get("name", "")
            ev = ", ".join(f"{s['tool']}:{s['rule_id']}" for s in f["sources"][:3])
            fx = f" (fixed in {f['package']['fixed']})" if f.get("package") and f["package"].get("fixed") else ""
            o.append(f"| {f['id']} | {f['severity']} | {f['class']} | {loc} | {f['title'].replace('|', '/')[:110]}{fx} | {ev} |")
    table("Confirmed (independently verified, with trace)", [f for f in L if f["verdict"] == "confirmed"])
    table("Needs validation (agent candidates, NOT verified)", [f for f in L if f["verdict"] == "needs_validation"])
    table("Reported by tools (not yet triaged by an agent)", [f for f in L if f["verdict"] == "reported"])
    table("Fixed (verified)", [f for f in L if f["verdict"] == "fixed"])
    rej = [f for f in L if f["verdict"] == "rejected"]
    if rej:
        o.append("\n## Rejected (with reasons)\n")
        for f in rej: o.append(f"- {f['id']} {f['title'][:100]}: {f.get('rejection_reason', '')}")
    o.append("\n## Coverage ledger\n")
    stale = {c["id"] for c, _ in stale_entries(d, target)}
    if d["coverage"]:
        o.append("| ID | Kind | Depth | Area | By | Gaps |\n|---|---|---|---|---|---|")
        for c in d["coverage"]: o.append(f"| {c['id']}{' (STALE)' if c['id'] in stale else ''} | {c['kind']} | {c['depth']} | {c['area']} | {c['by']} | {c.get('gaps', '')} |")
    else: o.append("No manual coverage recorded: only tool-based coverage above.")
    text = "\n".join(o) + "\n"
    if a.out: open(a.out, "w").write(text); print(f"report: {a.out}")
    else: print(text)
    return 0

def cmd_sarif(a):
    d = load(a.file); rules, results = {}, []
    lv = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for f in live(d):
        s = f["sources"][0]; rid = s["rule_id"]; rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f["title"][:100]}})
        L = f.get("location") or {}; file = L.get("file") or "README.md"
        res = {"ruleId": rid, "level": lv[f["severity"]], "message": {"text": f"[{f['verdict']}] {f['title']}"},
               "partialFingerprints": {"chefpFindingId": f["id"]}, "properties": {"verdict": f["verdict"], "class": f["class"], "sources": [x["tool"] for x in f["sources"]]},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": L.get("line") or 1}}}]}
        results.append(res)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "chef-p-security-toolkit", "rules": list(rules.values())}}, "results": results}]}
    json.dump(doc, open(a.out, "w"), indent=2); print(f"sarif: {a.out} ({len(results)} results)"); return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="security-reports/findings.json"); sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("ingest"); p.add_argument("--reports", default="security-reports"); p.add_argument("--target", default="."); p.add_argument("--summary"); p.add_argument("--quiet", action="store_true"); p.set_defaults(fn=cmd_ingest)
    p = sp.add_parser("add"); p.add_argument("--title", required=True); p.add_argument("--severity", required=True, choices=SEV); p.add_argument("--class", dest="cls", required=True)
    p.add_argument("--file-path"); p.add_argument("--line", type=int); p.add_argument("--found-by", required=True); p.add_argument("--impact"); p.add_argument("--trace", action="append"); p.set_defaults(fn=cmd_add)
    p = sp.add_parser("verdict"); p.add_argument("id"); p.add_argument("--verdict", required=True); p.add_argument("--verified-by"); p.add_argument("--trace", action="append"); p.add_argument("--impact"); p.add_argument("--reason"); p.set_defaults(fn=cmd_verdict)
    p = sp.add_parser("fix-mark"); p.add_argument("id"); p.add_argument("--commit"); p.add_argument("--verify", required=True); p.add_argument("--by", default="agent"); p.set_defaults(fn=cmd_fix_mark)
    sp.add_parser("validate").set_defaults(fn=cmd_validate); sp.add_parser("stats").set_defaults(fn=cmd_stats)
    p = sp.add_parser("report"); p.add_argument("--out"); p.set_defaults(fn=cmd_report)
    p = sp.add_parser("sarif"); p.add_argument("--out", default="security-reports/findings.sarif"); p.set_defaults(fn=cmd_sarif)
    p = sp.add_parser("coverage"); p.add_argument("action", choices=["add", "list", "stale"]); p.add_argument("--area"); p.add_argument("--kind", default="path", choices=["path", "class"])
    p.add_argument("--depth", default="read"); p.add_argument("--by", default="agent:main"); p.add_argument("--note"); p.add_argument("--gaps"); p.set_defaults(fn=cmd_coverage)
    a = ap.parse_args(); sys.exit(a.fn(a))

if __name__ == "__main__": main()
