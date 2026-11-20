#!/usr/bin/env python3
"""incident_scan.py -- exposure check for a breach / supply-chain advisory. Stdlib only.
All inputs are treated as LITERAL DATA (never executed, never passed to a shell).
  --pkg NAME=BAD1[,BAD2]   package + exact known-bad versions (repeatable)
  --pkg 'NAME<2026.10.18'  package + version RANGE: operators == != < <= > >=, comma = AND (e.g. 'aiohttp>=3.0,<3.14.4').
                           Repeat --pkg for the same name to OR several ranges. Quote it so the shell keeps < and >.
  --action OWNER/REPO      GitHub Action to inspect for mutable (tag) references (repeatable)
  --ioc STRING             file name / domain / hash / string indicator (repeatable)
  --target DIR             project to scan (default .)
  --deep                   also search $HOME for installed packages and IOC file names (slow)
exit: 3 = EXPOSED, 0 = nothing found in scanned locations (NOT proof of safety)."""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

PRUNE = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".cache", "security-reports", "strix_runs"}

def norm(n): return re.sub(r"[-_.]+", "-", n.strip()).lower()
def nver(v): return v.strip().lstrip("v=").strip()

def vkey(v):
    key = []
    for t in re.findall(r"\d+|[A-Za-z]+", v.lower()):
        key.append((1, int(t)) if t.isdigit() else (0, t))   # letters (rc, beta) sort before numbers: 1.0rc1 < 1.0
    return key

def vcmp(a, b):
    ka, kb = vkey(a), vkey(b); n = max(len(ka), len(kb)); pad = (1, 0)
    ka += [pad] * (n - len(ka)); kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)

COND = re.compile(r"(==|!=|<=|>=|<|>)\s*([^,\s]+)")

def parse_pkg(spec):
    m = re.match(r"^([A-Za-z0-9_.\-@/]+?)\s*((?:==|!=|<=|>=|<|>).*)$", spec)
    if m: return norm(m.group(1)), ("range", COND.findall(m.group(2)))
    name, _, vers = spec.partition("=")
    return norm(name), ("exact", {nver(v) for v in vers.split(",") if v.strip()})

def is_bad(specs, ver):
    if not ver: return False
    for kind, val in specs:
        if kind == "exact" and nver(ver) in val: return True
        if kind == "range" and val:
            ok = True
            for op, bv in val:
                c = vcmp(nver(ver), nver(bv))
                ok = ok and {"==": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]
            if ok: return True
    return False

def walk(root, prune=PRUNE):
    for dp, dn, fn in os.walk(root, onerror=lambda e: None):
        dn[:] = [d for d in dn if d not in prune]
        for f in fn: yield Path(dp) / f

def rd(p, limit=5_000_000):
    try:
        if p.stat().st_size > limit: return ""
        return p.read_text(errors="ignore")
    except Exception: return ""

REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*(==|===|~=|>=|<=|>|<|!=)\s*([A-Za-z0-9_.\-+!*]+)")
REQ_BARE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*$")

def p_requirements(t):
    out = []
    for line in t.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"): continue
        m = REQ.match(line)
        if m: out.append((m.group(1), m.group(4), "pinned" if m.group(3) in ("==", "===") else f"range {m.group(3)}{m.group(4)}"))
        else:
            m = REQ_BARE.match(line)
            if m: out.append((m.group(1), "", "unpinned"))
    return out

def p_pyproject(t):
    out = []
    for m in re.finditer(r"""["']([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*((?:==|===|~=|>=|<=|>|<|!=)[^"']*)["']""", t):
        spec = m.group(2).strip(); out.append((m.group(1), spec.lstrip("=") if spec.startswith("==") else "", "pinned" if spec.startswith("==") else f"range {spec}"))
    return out

def p_toml_lock(t):
    out = []
    for blk in t.split("[[package]]")[1:]:
        n = re.search(r'^name\s*=\s*"([^"]+)"', blk, re.M); v = re.search(r'^version\s*=\s*"([^"]+)"', blk, re.M)
        if n and v: out.append((n.group(1), v.group(1), "locked"))
    return out

def p_package_lock(t):
    out = []; d = json.loads(t)
    for path, info in (d.get("packages") or {}).items():
        if not path or not isinstance(info, dict): continue
        name = info.get("name") or path.split("node_modules/")[-1]
        if info.get("version"): out.append((name, info["version"], "locked"))
    def rec(deps):
        for n, i in (deps or {}).items():
            if isinstance(i, dict):
                if i.get("version"): out.append((n, i["version"], "locked"))
                rec(i.get("dependencies"))
    rec(d.get("dependencies")); return out

def p_yarn(t):
    out = []; cur = None
    for line in t.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            m = re.match(r'^"?(@?[^@"\s,]+)@', line); cur = m.group(1) if m else None
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and cur: out.append((cur, m.group(1), "locked")); cur = None
    return out

def p_pnpm(t):
    return [(m.group(1), m.group(2), "locked") for m in re.finditer(r"(?m)^\s{2,4}'?/?((?:@[^/@\s']+/)?[^@\s'/]+)@(\d[^\s:'(]*)", t)]

def p_go(t):
    out = []
    for line in t.splitlines():
        m = re.match(r"^\s*(?:require\s+)?(\S+)\s+(v[0-9][^\s/]*)", line)
        if m: out.append((m.group(1), m.group(2), "locked"))
    return out

def p_pipfile_lock(t):
    d = json.loads(t); out = []
    for sec in ("default", "develop"):
        for n, i in (d.get(sec) or {}).items():
            if isinstance(i, dict) and i.get("version"): out.append((n, i["version"].lstrip("="), "locked"))
    return out

def p_composer(t):
    d = json.loads(t); out = []
    for sec in ("packages", "packages-dev"):
        for i in d.get(sec) or []:
            if i.get("name") and i.get("version"): out.append((i["name"], i["version"].lstrip("v"), "locked"))
    return out

def p_gemlock(t): return [(m.group(1), m.group(2), "locked") for m in re.finditer(r"(?m)^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", t)]
def p_csproj(t): return [(m.group(1), m.group(2), "pinned") for m in re.finditer(r'<PackageReference\s+[^>]*Include="([^"]+)"[^>]*Version="([^"]+)"', t)]
def p_pom(t): return [(m.group(1), m.group(2), "pinned") for m in re.finditer(r"<dependency>.*?<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", t, re.S)]

def p_nuget_lock(t):
    d = json.loads(t); out = []
    for tfm in (d.get("dependencies") or {}).values():
        for n, i in tfm.items():
            if isinstance(i, dict) and i.get("resolved"): out.append((n, i["resolved"], "locked"))
    return out

def parse_file(p):
    n = p.name
    try:
        if re.match(r"^(requirements|constraints).*\.(txt|in)$", n): return p_requirements(rd(p))
        if n == "pyproject.toml": return p_pyproject(rd(p))
        if n in ("uv.lock", "poetry.lock", "Cargo.lock"): return p_toml_lock(rd(p))
        if n == "package-lock.json": return p_package_lock(rd(p))
        if n == "yarn.lock": return p_yarn(rd(p))
        if n == "pnpm-lock.yaml": return p_pnpm(rd(p))
        if n in ("go.sum", "go.mod"): return p_go(rd(p))
        if n == "Pipfile.lock": return p_pipfile_lock(rd(p))
        if n == "composer.lock": return p_composer(rd(p))
        if n == "Gemfile.lock": return p_gemlock(rd(p))
        if n.endswith((".csproj", ".fsproj")): return p_csproj(rd(p))
        if n == "packages.lock.json": return p_nuget_lock(rd(p))
        if n == "pom.xml": return p_pom(rd(p))
    except Exception as e:
        return [("<parse-error>", str(e), n)]
    return None

def site_dirs():
    import site
    ds = []
    try: ds += site.getsitepackages()
    except Exception: pass
    try: ds.append(site.getusersitepackages())
    except Exception: pass
    return [d for d in ds if d and os.path.isdir(d)]

def installed_scan(roots):
    """dist-info / egg-info directories and node_modules package.json files under roots."""
    out, seen = [], set()
    for root in roots:
        for dp, dn, fn in os.walk(root, onerror=lambda e: None):
            real = os.path.realpath(dp)
            if real in seen: dn[:] = []; continue
            seen.add(real)
            dn[:] = [d for d in dn if d != ".git"]
            for d in list(dn):
                m = re.match(r"^(.+?)-(\d[^-]*)\.(dist-info|egg-info)$", d)
                if m: out.append((m.group(1), m.group(2), os.path.join(dp, d))); dn.remove(d)
            if "package.json" in fn:
                parts = Path(dp).parts
                if "node_modules" in parts[-3:-1] or (len(parts) > 1 and parts[-2] == "node_modules"):
                    try:
                        j = json.loads(rd(Path(dp) / "package.json"))
                        if j.get("name") and j.get("version"): out.append((j["name"], j["version"], dp))
                    except Exception: pass
    try:
        import importlib.metadata as md
        for d in md.distributions():
            out.append((d.metadata["Name"] or "", d.version, f"python interpreter {sys.prefix}"))
    except Exception: pass
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pkg", action="append", default=[]); ap.add_argument("--action", action="append", default=[])
    ap.add_argument("--ioc", action="append", default=[]); ap.add_argument("--target", default=".")
    ap.add_argument("--deep", action="store_true"); ap.add_argument("--out", default=None)
    a = ap.parse_args()
    if not (a.pkg or a.action or a.ioc): ap.print_help(); return 2
    target = Path(a.target).resolve()
    bad = {}
    for spec in a.pkg:
        name, parsed = parse_pkg(spec)
        bad.setdefault(name, []).append(parsed)
    L, exposed, at_risk = [], [], []
    def out(s=""): L.append(s)
    out(f"INCIDENT EXPOSURE CHECK  {time.strftime('%Y-%m-%d %H:%M:%S')}  target={target}")
    out("Inputs treated as literal data. This report lists where bad versions/indicators were FOUND; absence is not proof of safety.")

    # ---- manifests and lockfiles
    scanned = []
    if bad:
        out("\n[1] Manifests / lockfiles")
        for p in walk(target):
            res = parse_file(p)
            if res is None: continue
            scanned.append(str(p.relative_to(target)))
            for name, ver, kind in res:
                key = norm(name)
                if key not in bad: continue
                rel = p.relative_to(target)
                if ver and is_bad(bad[key], ver) and not kind.startswith("range"):
                    out(f"  EXPOSED   {rel}: {name} {ver} ({kind}) is a KNOWN-BAD version"); exposed.append(f"{rel}: {name} {ver}")
                elif kind.startswith("range") or kind == "unpinned":
                    out(f"  AT-RISK   {rel}: {name} {kind} (not pinned; an install during the exposure window could have resolved a bad version)"); at_risk.append(f"{rel}: {name} {kind}")
                else:
                    out(f"  ok        {rel}: {name} {ver} ({kind}) not in bad list")
        out(f"  scanned {len(scanned)} manifest/lock files: " + (", ".join(scanned[:12]) + (" ..." if len(scanned) > 12 else "") if scanned else "none found"))

        out("\n[2] Installed copies (virtualenvs, site-packages, node_modules, current interpreter)")
        roots = [target] + site_dirs() + ([Path.home()] if a.deep else [])
        found_inst = 0
        for name, ver, where in installed_scan(roots):
            key = norm(name)
            if key in bad:
                found_inst += 1
                if is_bad(bad[key], ver):
                    out(f"  EXPOSED   installed {name} {ver} at {where}"); exposed.append(f"installed {name} {ver} at {where}")
                else: out(f"  ok        installed {name} {ver} at {where}")
        if not found_inst: out("  no installed copy of the named packages found in scanned roots" + ("" if a.deep else " (use --deep to also search $HOME)"))

    # ---- workflows
    wf_files = [p for p in walk(target) if ".github" in p.parts and "workflows" in p.parts and p.suffix in (".yml", ".yaml")]
    out(f"\n[3] GitHub Actions workflows ({len(wf_files)} files)")
    want = [x.lower().strip("/") for x in a.action]; unpinned_total = 0
    for p in wf_files:
        for i, line in enumerate(rd(p).splitlines(), 1):
            m = re.match(r"""^\s*-?\s*uses:\s*([^\s#]+)""", line)
            if m:
                ref = m.group(1).strip("'\""); 
                if ref.startswith(("./", "docker://")): continue
                name, _, v = ref.partition("@"); pinned = bool(re.fullmatch(r"[0-9a-f]{40}", v)); unpinned_total += (not pinned)
                hit = any(name.lower().startswith(w) for w in want)
                rel = p.relative_to(target)
                if hit and not pinned:
                    out(f"  AT-RISK   {rel}:{i} uses {ref}  <- MUTABLE tag/branch for an affected action (tags can be re-pointed)"); at_risk.append(f"{rel}:{i} {ref}")
                elif hit: out(f"  ok        {rel}:{i} uses {ref} (pinned to a commit SHA; verify the SHA is a known-good one)")
            if "pull_request_target" in line and not line.strip().startswith("#"):
                out(f"  NOTE      {p.relative_to(target)}:{i} uses pull_request_target (high-risk trigger; never check out untrusted PR code with it)")
    out(f"  third-party action references NOT pinned to a full commit SHA: {unpinned_total}")

    # ---- IOCs
    if a.ioc:
        out("\n[4] Indicators of compromise")
        file_roots = [target] + site_dirs() + ([Path.home()] if a.deep else [])
        for ioc in a.ioc:
            hits, low = 0, ioc.lower()
            for root in file_roots:
                for dp, dn, fn in os.walk(root, onerror=lambda e: None):
                    dn[:] = [d for d in dn if d != ".git"]
                    for f in fn + dn:
                        if low in f.lower():
                            out(f"  EXPOSED   file/dir name matches '{ioc}': {os.path.join(dp, f)}"); exposed.append(f"file {os.path.join(dp, f)}"); hits += 1
                            if hits >= 25: break
                    if hits >= 25: break
            th = 0
            for p in walk(target):
                t = rd(p, 2_000_000)
                if ioc in t:
                    out(f"  EXPOSED   text match '{ioc}' in {p.relative_to(target)}"); exposed.append(f"text {p}"); th += 1
                    if th >= 25: break
            try:
                r = subprocess.run(["git", "-C", str(target), "log", "--all", "--oneline", "-S", ioc], capture_output=True, text=True, timeout=120)
                commits = [x for x in r.stdout.splitlines() if x]
                if commits:
                    out(f"  AT-RISK   '{ioc}' appears in git history ({len(commits)} commits touching it), e.g. {commits[0]}"); at_risk.append(f"history {ioc}")
            except Exception: pass
            if not (hits or th): out(f"  none      no match for '{ioc}' in scanned locations")

    out("\n== VERDICT ==")
    if exposed:
        out("EXPOSED: known-bad version(s) or indicator(s) found:"); [out("  - " + x) for x in exposed]
    else: out("No known-bad version or indicator found in the scanned locations.")
    if at_risk: out("AT RISK (needs a human look at install dates / CI logs):"); [out("  - " + x) for x in at_risk]
    out("Still check: CI run logs inside the exposure window, other machines, container images, and which secrets were reachable.")
    text = "\n".join(L); print(text)
    dest = Path(a.out) if a.out else Path("security-reports") / f"incident-{time.strftime('%Y%m%d-%H%M%S')}.txt"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text(text + "\n"); print(f"\nreport: {dest}")
    except Exception: pass
    return 3 if exposed else 0

if __name__ == "__main__": sys.exit(main())
