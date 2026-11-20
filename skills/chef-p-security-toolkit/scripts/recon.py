#!/usr/bin/env python3
"""recon.py [dir] [--include-tests] [--cap N] [--out FILE]
Deterministic reconnaissance for hunt mode: finds CANDIDATE sinks and entry points by pattern, across languages.
These are leads to read, not findings. Output: security-reports/recon.json plus a summary. Stdlib only."""
import argparse, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import DEFAULT_PRUNE, load_secignore, ignored, rel

EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".vue", ".mjs", ".cjs"}
CLASSES = {
 "entrypoint": r"@(app|router|bp|api|blueprint)\.(get|post|put|patch|delete|route)\b|\b(app|router)\.(get|post|put|patch|delete|use)\(|@(Request|Get|Post|Put|Delete)Mapping|http\.HandleFunc|mux\.Handle|\[Http(Get|Post|Put|Delete)|argparse\.ArgumentParser|click\.command|sys\.argv|FastAPI\(|Flask\(",
 "command-exec": r"shell\s*=\s*True|os\.system\(|os\.popen\(|\bsubprocess\.|child_process|\bexecSync\(|Runtime\.getRuntime\(\)\.exec|Process\.Start\(|exec\.Command\(|\bpopen\(|\bsystem\(",
 "sql": r"\.(execute|executemany|raw|query)\(\s*f[\"']|(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*(\+|%)|(SELECT|INSERT|UPDATE|DELETE)\b.*\{[^}]*\}|fmt\.Sprintf\([\"'](SELECT|INSERT|UPDATE|DELETE)",
 "deserialization": r"pickle\.loads?\(|marshal\.loads?\(|yaml\.load\(|torch\.load\(|joblib\.load\(|ObjectInputStream|BinaryFormatter|\bunserialize\(|node-serialize|jsonpickle|\beval\(|\bnew Function\(",
 "file-path": r"send_file\(|send_from_directory\(|os\.path\.join\([^)]*(request|input|param|argv|user)|readFile(Sync)?\([^)]*(req|param|input)|extractall\(|tarfile\.|zipfile\.|\.\./",
 "network-ssrf": r"requests\.(get|post|put|request)\(|urllib\.request|urlopen\(|httpx\.|aiohttp\.ClientSession|\bfetch\(|axios\.|http\.Get\(|HttpClient|WebClient",
 "crypto": r"hashlib\.(md5|sha1)|\bmd5\b|\bsha1\(|\bDES\b|\bRC4\b|\bECB\b|random\.(random|randint|choice)\(|Math\.random\(|verify\s*=\s*False|InsecureSkipVerify|rejectUnauthorized\s*:\s*false|CERT_NONE",
 "auth": r"jwt\.(decode|verify)|algorithms\s*=|verify_signature|login_required|Depends\([^)]*(auth|user|token)|\bauthorize\b|is_admin|\brole\s*==|PermitAll|AllowAnonymous",
 "web-render": r"innerHTML|dangerouslySetInnerHTML|render_template_string|\bMarkup\(|\|\s*safe\b|v-html|document\.write\(|autoescape\s*=\s*False",
 "secrets-handling": r"os\.environ|getenv\(|process\.env\.|logging\.\w+\([^)]*(key|token|secret|password)|print\([^)]*(key|token|secret|password)|console\.log\([^)]*(key|token|secret|password)",
 "memory-unsafe": r"\bstrcpy\(|\bstrcat\(|\bsprintf\(|\bgets\(|\bmemcpy\(|\bunsafe\s*\{",
}
RX = {k: re.compile(v, re.I if k in ("sql", "secrets-handling") else 0) for k, v in CLASSES.items()}
LLM_FILE = re.compile(r"openai|anthropic|litellm|langchain|llama_index|ollama|chat\.completions|messages\s*=|system_prompt|tool_calls|function_call|\bmcp\b", re.I)
LLM_LINE = re.compile(r"(messages|prompt|system|content)\s*[:=].*(\+|f[\"']|\.format\(|\$\{|\{[a-z_]*(user|query|input|message|text)[a-z_]*\})|tool_calls|function_call|(exec|eval|subprocess|requests\.)", re.I)
TEST_DIR = re.compile(r"(^|/)(tests?|__tests__|spec|e2e)(/|$)|(^|/)(test_[^/]*|[^/]*_test\.[a-z]+|[^/]*\.test\.[a-z]+|[^/]*\.spec\.[a-z]+)$")

def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("dir", nargs="?", default="."); ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--cap", type=int, default=60); ap.add_argument("--out", default="security-reports/recon.json"); a = ap.parse_args()
    root = os.path.abspath(a.dir); pats = load_secignore(root); hits = {k: [] for k in list(CLASSES) + ["ai-llm"]}; counts = {k: 0 for k in hits}; nfiles = 0; langs = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in DEFAULT_PRUNE]
        for f in fn:
            ext = os.path.splitext(f)[1].lower()
            if ext not in EXT: continue
            p = os.path.join(dp, f); r = rel(p, root)
            if ignored(r, pats) or (not a.include_tests and TEST_DIR.search(r)): continue
            try:
                if os.path.getsize(p) > 1_000_000: continue
                text = open(p, errors="ignore").read()
            except OSError: continue
            nfiles += 1; langs[ext] = langs.get(ext, 0) + 1; is_llm = bool(LLM_FILE.search(text))
            for i, line in enumerate(text.splitlines(), 1):
                if len(line) > 400: continue
                s = line.strip()
                if not s or s.startswith(("#", "//", "*", "/*")): continue
                for k, rx in RX.items():
                    if rx.search(line):
                        counts[k] += 1
                        if len(hits[k]) < a.cap: hits[k].append({"file": r, "line": i, "snippet": s[:160]})
                if is_llm and LLM_LINE.search(line):
                    counts["ai-llm"] += 1
                    if len(hits["ai-llm"]) < a.cap: hits["ai-llm"].append({"file": r, "line": i, "snippet": s[:160]})
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump({"target": root, "files_scanned": nfiles, "languages": langs, "note": "Candidate leads only, not findings. Capped per class.", "counts": counts, "candidates": hits}, open(a.out, "w"), indent=2)
    print(f"recon: {nfiles} source files; candidate leads per class (capped lists in {a.out}):")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        if v: top = {}; [top.__setitem__(h["file"], top.get(h["file"], 0) + 1) for h in hits[k]]; print(f"  {k:17}{v:5}  top: {', '.join(sorted(top, key=top.get, reverse=True)[:3])}")
    return 0

if __name__ == "__main__": sys.exit(main())
