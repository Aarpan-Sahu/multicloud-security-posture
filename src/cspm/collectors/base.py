from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any

from ..models import CollectorError, Finding, ScanResult

log = logging.getLogger(__name__)


def merge_evidence(old: Any, new: Any) -> Any:
    """Combine two evidence values for the same key without losing either."""
    if old is None or old == new:
        return new if old is None else old
    if isinstance(old, bool) and isinstance(new, bool):
        return old or new
    merged = list(old) if isinstance(old, list) else [old]
    for x in new if isinstance(new, list) else [new]:
        if x not in merged:
            merged.append(x)
    if all(isinstance(x, int) and not isinstance(x, bool) for x in merged):
        merged.sort()
    return merged


class BaseCollector(ABC):
    """Every collector is read-only and must never raise on a single failed API call.

    A missing permission on one service should degrade coverage, not kill the scan,
    and the gap must be visible to the user (reported as a CollectorError).
    """

    provider: str = ""

    def __init__(self) -> None:
        self.result = ScanResult()
        self._by_id: dict[str, Finding] = {}

    @contextmanager
    def check(self, scope: str):
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - deliberate: isolate each check
            msg = f"{type(exc).__name__}: {exc}"
            log.warning("[%s] %s failed: %s", self.provider, scope, msg)
            self.result.errors.append(CollectorError(self.provider, scope, msg[:500]))

    def add_account(self, account_id: str) -> None:
        self.result.scanned_accounts.setdefault(self.provider, []).append(account_id)

    def emit(self, finding: Finding) -> None:
        """Record a finding. The same rule failing twice on one resource (e.g. SSH and RDP open in two
        separate rules of one security group) has one finding_id, so evidence is merged, not dropped."""
        existing = self._by_id.get(finding.finding_id)
        if existing is None:
            self._by_id[finding.finding_id] = finding
            self.result.findings.append(finding)
            return
        for key, value in finding.evidence.items():
            existing.evidence[key] = merge_evidence(existing.evidence.get(key), value)

    @abstractmethod
    def collect(self) -> ScanResult: ...
