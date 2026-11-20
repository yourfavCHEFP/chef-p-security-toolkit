# AI / LLM applications, agents, gateways
Look for:
- Prompt injection reaching authority: untrusted text (web pages, emails, PDFs, RAG chunks, tool results, user uploads) placed in a prompt for a model that can call tools or write data. The question is never "can the model be tricked" but "what can it do when tricked".
- Tool/function authority: tool arguments from model output passed to shell, SQL, filesystem, HTTP or `eval` without validation; tools that run with the app's full privileges; no per-user scoping of tools; confirmation steps the model itself can approve.
- MCP and plugin trust: servers or tool descriptions loaded from untrusted sources (tool poisoning, description injection), unpinned servers that can change behaviour later, secrets passed to third-party servers.
- Model/artifact loading: `pickle`/`torch.load` on downloaded weights, `trust_remote_code=True`, unpinned hub revisions, model files from user uploads.
- Secrets and data flow: API keys or system prompts in logs, traces, error messages or client responses; per-tenant keys mixed up (BYOK boundary leaks); prompts/responses cached or stored across tenants; provider keys forwarded to user-chosen base URLs (SSRF and key exfiltration via `api_base`).
- Cost and abuse: no max-token or rate caps (denial of wallet), unauthenticated completion endpoints, retries that multiply spend, streaming responses that bypass accounting.
- Output handling: model output rendered as HTML/markdown with active content, executed as code, or used to build queries or file paths.
- Agent sandboxes: code-execution tools without isolation, network egress open, shared filesystem between sessions.
Method: for every place model output or model-visible text crosses a boundary, write down what an attacker who controls that text can make the system do.
Kills false positives: no tools and no side effects (pure chat with output escaped), strict allow-listed tool arguments, per-user scoped credentials, human confirmation the model cannot satisfy.
