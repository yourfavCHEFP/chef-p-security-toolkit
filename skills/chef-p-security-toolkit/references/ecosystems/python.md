# Python
Manifests: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `uv.lock`, `poetry.lock`.
Tests: `python3 -m pytest -q`. Audit: osv-scanner, trivy, bandit (+ pip-audit optional).
Upgrade one package: uv `uv lock --upgrade-package NAME` then `uv sync`; poetry `poetry update NAME`; pip-tools `pip-compile --upgrade-package NAME` (add `--generate-hashes` to harden); plain pip: edit the pin in requirements and `pip install -r`.
Hardening: commit the lockfile; `pip install --require-hashes`; use a venv per project; review packages published in the last ~2 weeks before adopting.
