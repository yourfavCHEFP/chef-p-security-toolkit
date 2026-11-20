# Docker, compose, Terraform, Kubernetes
Dockerfile: run as non-root (`RUN useradd ... && USER app`); pin base images (tag + digest); slim/distroless bases; multi-stage builds; `COPY` not `ADD`; no secrets in `ENV`/`ARG`/layers (use build secrets); clean package caches; `.dockerignore` for `.git`, `.env`.
Compose: no `privileged`, no host network or docker.sock mounts unless essential, read-only root fs where possible, drop capabilities, bind ports to 127.0.0.1 if local only.
Terraform/cloud: encryption at rest, no public buckets, no `0.0.0.0/0` on admin ports, least-privilege IAM (no `*:*`), logging on, remote state encrypted.
Kubernetes: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, resource limits, no `hostPath`, network policies.
Verify with hadolint / checkov / trivy misconfig ids. Behaviour changes (port, user, filesystem) can break the app: run it or its tests.
