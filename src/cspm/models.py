"""Core data model shared by every collector, the scorer, the AI layer and the UI."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


class Provider:
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALL = (AWS, AZURE, GCP)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    """One failed control on one resource, normalized across clouds."""

    provider: str
    account_id: str  # AWS account / Azure subscription / GCP project
    region: str
    resource_type: str  # normalized, e.g. "Object Storage", "Firewall Rule"
    resource_id: str  # native identifier (ARN, Azure resource ID, GCP self link / name)
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    compliance: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(default_factory=utc_now)
    status: str = "OPEN"

    @property
    def finding_id(self) -> str:
        """Stable ID: same resource + same rule => same finding across scans (enables dedupe/trending)."""
        raw = "|".join([self.provider, self.account_id, self.resource_id, self.rule_id])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def internet_exposed(self) -> bool:
        return bool(self.evidence.get("internet_exposed"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["finding_id"] = self.finding_id
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        data = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        data["severity"] = Severity.parse(data["severity"])
        return cls(**data)


@dataclass
class CollectorError:
    provider: str
    scope: str  # e.g. "s3:list_buckets" or "subscription/1234"
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[CollectorError] = field(default_factory=list)
    scanned_accounts: dict[str, list[str]] = field(default_factory=dict)
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None

    def extend(self, other: ScanResult) -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        for p, accts in other.scanned_accounts.items():
            self.scanned_accounts.setdefault(p, []).extend(accts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanned_accounts": self.scanned_accounts,
            "errors": [asdict(e) for e in self.errors],
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        return cls(
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            errors=[CollectorError(**e) for e in d.get("errors", [])],
            scanned_accounts=d.get("scanned_accounts", {}),
            started_at=d.get("started_at", utc_now()),
            finished_at=d.get("finished_at"),
        )
