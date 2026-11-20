# Web: SSRF, path traversal, XSS, CSRF, redirects, XXE, uploads
- SSRF: allow-list destination hosts; resolve DNS then block private, loopback, link-local and cloud-metadata ranges (169.254.169.254); re-check after redirects or disable redirects; only http(s).
- Path traversal: join to a base dir, resolve, and require the result stays inside it (`Path(base, p).resolve().is_relative_to(base.resolve())`; Go `filepath.Clean` + prefix check; use `send_from_directory`/framework helpers). Never trust `..`, absolute paths, or symlinks in uploads/archives (zip-slip: check every entry).
- XSS: context-aware output escaping (keep template autoescape on); avoid `innerHTML`/`dangerouslySetInnerHTML` with user data; add a Content-Security-Policy.
- CSRF: framework CSRF tokens plus SameSite cookies for cookie-auth state-changing requests.
- Open redirect: allow-list redirect targets or accept only relative paths.
- XXE: disable DTD/external entities (Python `defusedxml`; Java secure-processing features).
- Uploads: validate type by content, cap size, random server-side names, store outside the web root, never execute.
- Headers/CORS: no `Access-Control-Allow-Origin: *` with credentials; set HSTS, `X-Content-Type-Options`, frame protections.
