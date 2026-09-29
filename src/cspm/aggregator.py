"""Runs collectors concurrently and merges results into one normalized ScanResult."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .collectors import get_collector
from .config import Settings
from .models import CollectorError, ScanResult, utc_now

log = logging.getLogger(__name__)


def _run_one(provider: str, settings: Settings) -> ScanResult:
    try:
        return get_collector(provider, **settings.collector_kwargs(provider)).collect()
    except Exception as exc:  # auth failure, missing SDK, no projects configured...
        log.error("Collector %s failed to start: %s", provider, exc)
        return ScanResult(errors=[CollectorError(provider, "collector", f"{type(exc).__name__}: {exc}"[:500])])


def run_scan(providers: list[str], settings: Settings | None = None) -> ScanResult:
    settings = settings or Settings()
    merged = ScanResult()
    with ThreadPoolExecutor(max_workers=len(providers) or 1) as pool:
        futures = {pool.submit(_run_one, p, settings): p for p in providers}
        for fut in as_completed(futures):
            merged.extend(fut.result())
    # De-duplicate: identical (provider, account, resource, rule) collapse to one finding.
    unique = {f.finding_id: f for f in merged.findings}
    merged.findings = list(unique.values())
    merged.finished_at = utc_now()
    return merged


def save_snapshot(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result.to_dict(), indent=2, default=str))
    return p


def load_snapshot(path: str | Path) -> ScanResult:
    return ScanResult.from_dict(json.loads(Path(path).read_text()))
