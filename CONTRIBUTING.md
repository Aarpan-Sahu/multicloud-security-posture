# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest -q
streamlit run app.py   # demo data, no cloud account needed
```

## Adding a check

1. Add a row to the rule catalog in `src/cspm/rules.py` with severity, remediation and control mapping.
2. Emit the finding from the collector in `src/cspm/collectors/`. Wrap each API call so a missing permission
   is recorded as a coverage gap instead of failing the scan.
3. Add a test. AWS checks can run end-to-end against moto; see `tests/test_aws_collector.py`.
4. If the check needs a new permission, it must be read-only. Update the Terraform in `terraform/` if the
   existing roles do not already grant it.

## Pull requests

- Keep changes focused and describe the reason in the PR.
- CI runs lint, tests, Terraform checks, Checkov and gitleaks; all must pass.
- Never commit credentials, `.env`, Terraform state or real scan output.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.
