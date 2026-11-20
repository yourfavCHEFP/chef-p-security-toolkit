# Leaked secrets
Order matters:
1. ROTATE/REVOKE the credential at the provider now. Assume it was copied. Check the provider's audit log for use since the leak.
2. Remove it from code; load from environment or a secret manager (`os.environ`, `process.env`, platform secrets). Add `.env` and key files to `.gitignore`; ship `.env.example` with placeholders.
3. Prevent recurrence: pre-commit hook (`gitleaks protect --staged` or `gitleaks git --pre-commit`), CI scan, enable the host's secret scanning/push protection.
4. History: only after rotation. Rewriting (git filter-repo) breaks collaborators, needs a force-push the human approves, and forks/clones/caches keep the old data. A rotated key in history is harmless.
5. Test/placeholder values flagged by scanners: allow-list the exact fingerprint or path with a comment, with the user's approval.
Never print the secret. Reports are redacted; use file, line and rule id to locate it.
