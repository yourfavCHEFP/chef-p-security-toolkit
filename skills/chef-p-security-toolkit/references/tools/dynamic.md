# Dynamic testing: ZAP and Strix
ZAP baseline (`zap.json`) is PASSIVE: headers, cookies, info leaks, obvious misconfig. `site[].alerts[]` -> `riskcode`, `name`, `instances[]`. It does not prove exploitability and does not test logins or business logic. A clean baseline never means "secure".
Strix (`strix_runs/<run>/`): agents try to exploit and validate with proof-of-concepts, so findings carry more evidence; re-check each PoC against the code. Needs STRIX_LLM (+ LLM_API_KEY, or LLM_API_BASE for a local model) and Docker. Slow models make long runs: keep scope narrow.
Active scans and Strix: only the user's own targets, only when asked.
