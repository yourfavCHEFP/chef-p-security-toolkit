#!/usr/bin/env python3
"""findings_diff.py <before_dir> <after_dir>
Compares finding signatures between two scan report folders (line numbers ignored so edits don't look like new findings).
exit 1 if any NEW finding appears. Stdlib only."""
import json, os, sys

def load(p):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return None

def sarif(d):
    s = set()
    for run in d.get("runs", []):
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            s.add((r.get("ruleId", "?"), loc))
    return s

def gitleaks(d): return {(x.get("RuleID", "?"), x.get("File", "")) for x in (d or []) if isinstance(x, dict)}

def trivy(d):
    s = set()
    for res in (d or {}).get("Results", []) or []:
        t = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []: s.add((v.get("VulnerabilityID", "?"), v.get("PkgName", "")))
        for m in res.get("Misconfigurations") or []: s.add((m.get("ID", "?"), t))
        for x in res.get("Secrets") or []: s.add((x.get("RuleID", "?"), t))
    return s

def osv(d):
    s = set()
    for r in (d or {}).get("results", []) or []:
        for p in r.get("packages", []) or []:
            name = (p.get("package") or {}).get("name", "")
            for v in p.get("vulnerabilities", []) or []: s.add((v.get("id", "?"), name))
    return s

def bandit(d): return {(x.get("test_id", "?"), x.get("filename", "")) for x in (d or {}).get("results", [])}
def hadolint(d): return {(x.get("code", "?"), x.get("file", "")) for x in (d or []) if isinstance(x, dict)}
def npm(d): return {(n, v.get("severity", "")) for n, v in ((d or {}).get("vulnerabilities") or {}).items()}

def checkov(d):
    s = set()
    for blk in (d if isinstance(d, list) else [d or {}]):
        for c in ((blk.get("results") or {}).get("failed_checks") or []):
            s.add((c.get("check_id", "?"), c.get("file_path", "")))
    return s

EXTRACT = {"semgrep.sarif": sarif, "gitleaks-worktree.json": gitleaks, "gitleaks-history.json": gitleaks,
           "trivy.json": trivy, "osv.json": osv, "bandit.json": bandit, "hadolint.json": hadolint,
           "checkov.json": checkov, "npm-audit.json": npm}

def main():
    if len(sys.argv) != 3: print(__doc__); return 2
    b, a = sys.argv[1], sys.argv[2]
    new_total, rows, newl, fixl, notes = 0, [], [], [], []
    for name, fn in EXTRACT.items():
        pb, pa = os.path.join(b, name), os.path.join(a, name)
        eb, ea = os.path.exists(pb), os.path.exists(pa)
        if not eb and not ea: continue
        if eb and not ea: notes.append(f"{name}: present in baseline but MISSING after (tool did not run?)"); continue
        sb = fn(load(pb)) if eb else set()
        sa = fn(load(pa))
        fixed, new = sb - sa, sa - sb
        new_total += len(new)
        rows.append((name, len(sb), len(sa), len(fixed), len(new)))
        fixl += [f"[{name}] {x}" for x in sorted(fixed)]
        newl += [f"[{name}] {x}" for x in sorted(new)]
    if not rows: print("no comparable reports found"); return 0
    print(f"{'report':26}{'before':>8}{'after':>8}{'fixed':>8}{'new':>6}")
    for r in rows: print(f"{r[0]:26}{r[1]:>8}{r[2]:>8}{r[3]:>8}{r[4]:>6}")
    for n in notes: print("NOTE:", n)
    if fixl: print("\nFIXED:"); [print("  ", x) for x in fixl[:60]]
    if newl: print("\nNEW (introduced or newly visible):"); [print("  ", x) for x in newl[:60]]
    return 1 if new_total else 0

if __name__ == "__main__": sys.exit(main())
