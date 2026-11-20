# Security policy
This project runs security tools and can execute project code on request, so its own safety matters.
- Report vulnerabilities privately through GitHub: Security tab -> "Report a vulnerability" (private vulnerability reporting should be enabled on the repo). Do not open public issues for exploitable bugs.
- In scope: the scripts, the trust gate, the findings store, the skill instructions (for example prompt-injection paths that make an agent run commands or mark a repo trusted).
- Out of scope: vulnerabilities in the third-party scanners this toolkit calls; report those upstream.
- Design guarantees to test against: static scans never execute project code; execution is gated by `trust.sh` and only a human at a terminal can add trust; advisory/report text is treated as data; fixes happen on a branch and never auto-merge; reports redact secrets.
