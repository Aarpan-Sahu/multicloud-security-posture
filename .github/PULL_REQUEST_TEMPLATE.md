## What and why

<!-- What does this change, and what problem does it solve? Link any related issue. -->

## Checklist

- [ ] `ruff check .` and `pytest -q` pass locally
- [ ] New or changed checks have a row in `src/cspm/rules.py` and a test
- [ ] Terraform changes pass `terraform fmt -check` and `terraform validate`
- [ ] No credentials, account IDs, subscription IDs or real scan output in the diff
- [ ] Scanner permissions stay read-only
