"""Data minimization before anything leaves the trust boundary to an LLM.

Two layers:
1. Allowlist: only fields the model needs to reason about the *class* of problem are sent.
   Resource names, ARNs, subscription IDs and project IDs are never sent.
2. Pattern redaction: any free-text value that survives the allowlist is scrubbed of
   identifiers (defense in depth), replaced by stable placeholders so the model's answer
   stays coherent.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding

EVIDENCE_ALLOWLIST = {
    "internet_exposed", "ports", "sources", "disabled_settings", "min_tls", "https_only",
    "engine", "role", "key_count", "age_days", "database_version", "members", "source", "key_slot",
}

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ARN", re.compile(r"arn:aws[\w-]*:[^\s\"',]+")),
    ("AZURE_ID", re.compile(r"/subscriptions/[^\s\"',]+", re.I)),
    ("GUID", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("GCP_PATH", re.compile(r"(?://[\w.]+\.googleapis\.com/|projects/)[^\s\"',]+")),
    ("ACCOUNT", re.compile(r"\b\d{12}\b")),
    # IPv4 addresses/CIDRs, but keep the meaningful "anywhere" range 0.0.0.0/0
    ("IP", re.compile(r"\b(?!0\.0\.0\.0(?:/0)?\b)(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")),
]


class Redactor:
    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def _placeholder(self, kind: str, value: str) -> str:
        if value not in self._map:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._map[value] = f"<{kind}_{self._counts[kind]}>"
        return self._map[value]

    def text(self, s: str) -> str:
        for kind, pat in _PATTERNS:
            s = pat.sub(lambda m, k=kind: self._placeholder(k, m.group(0)), s)
        return s

    def value(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        return v


def sanitize_finding(f: Finding, redactor: Redactor | None = None) -> dict[str, Any]:
    r = redactor or Redactor()
    evidence = {k: v for k, v in f.evidence.items() if k in EVIDENCE_ALLOWLIST}
    # Catalog text (title, description, remediation) is ours and trusted, so it is sent as-is;
    # evidence comes from the customer's cloud and is scrubbed.
    return {
        "provider": f.provider,
        "resource_type": f.resource_type,
        "region": f.region,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.name,
        "category": f.category,
        "description": f.description,
        "baseline_remediation": f.remediation,
        "evidence": r.value(evidence),
    }
