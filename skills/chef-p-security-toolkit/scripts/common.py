"""Shared helpers: .secignore parsing and path matching. Stdlib only."""
import os, re

DEFAULT_PRUNE = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
                 ".cache", "security-reports", "strix_runs", "dist", "build", ".next"}

def load_secignore(root):
    """Patterns from <root>/.secignore (gitignore-like: * ** ? dir/, '#' comments)."""
    p = os.path.join(root, ".secignore")
    pats = []
    try:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): pats.append(line)
    except OSError:
        pass
    return pats

def _to_regex(pat):
    pat = pat.rstrip("/") if pat.endswith("/") else pat
    out, i = "", 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i): out += "(?:.*/)?"; i += 3; continue
        if pat.startswith("**", i): out += ".*"; i += 2; continue
        if c == "*": out += "[^/]*"
        elif c == "?": out += "[^/]"
        else: out += re.escape(c)
        i += 1
    return out

def ignored(path, patterns):
    """True if a relative path matches any pattern. Patterns without '/' match any path segment."""
    path = path.replace("\\", "/")
    while path.startswith("./"): path = path[2:]   # strip ONLY a leading "./" (lstrip would eat the dot of ".github")
    for pat in patterns:
        rx = _to_regex(pat)
        if "/" not in pat.rstrip("/"):
            if any(re.fullmatch(rx, seg) for seg in path.split("/")): return True
        else:
            if re.fullmatch(rx, path) or re.match(rx + "/", path): return True
    return False

def rel(path, root):
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path
