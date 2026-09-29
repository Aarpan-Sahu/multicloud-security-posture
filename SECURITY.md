# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
[GitHub security advisories](https://github.com/Aarpan-Sahu/multicloud-security-posture/security/advisories/new).

Include what is affected, how to reproduce it, and the impact you expect. You should get a reply within a week.

## Scope

In scope:

- The dashboard, scanner and AI layer in this repository
- The Terraform modules under `terraform/`, except `terraform/aws/lab`, which is intentionally misconfigured
- The GitHub Actions workflows

Examples of relevant issues: a path that lets the scanner write to or read data from a cloud account, a way to get
unredacted identifiers into an LLM request, or prompt injection through cloud metadata that changes the output.

## Handling scan output

Snapshots (`data/findings.json`) and the nightly workflow artifacts describe weaknesses in real accounts.
Treat them as confidential and never attach them to issues or pull requests.
