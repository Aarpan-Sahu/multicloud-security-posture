#!/usr/bin/env python
"""Headless scan for cron / CI: writes a JSON snapshot the dashboard can load.

Examples:
  python scripts/scan.py --providers aws azure gcp
  python scripts/scan.py --providers aws --fail-on critical   # non-zero exit for CI gates
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cspm.aggregator import run_scan, save_snapshot  # noqa: E402
from cspm.config import Settings  # noqa: E402
from cspm.models import Severity  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--providers", nargs="+", default=["aws", "azure", "gcp"],
                    choices=["aws", "azure", "gcp", "demo"])
    ap.add_argument("--out", default=None, help="Output path (default: $CSPM_SNAPSHOT or data/findings.json)")
    ap.add_argument("--fail-on", choices=[s.name.lower() for s in Severity], default=None,
                    help="Exit 2 if any finding is at or above this severity")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    settings = Settings()
    result = run_scan(args.providers, settings)
    path = save_snapshot(result, args.out or settings.snapshot_path)

    by_sev = Counter(f.severity.name for f in result.findings)
    print(f"Findings: {len(result.findings)}  " + "  ".join(f"{s.name}={by_sev.get(s.name, 0)}"
                                                           for s in sorted(Severity, reverse=True)))
    print(f"Coverage gaps: {len(result.errors)}   Snapshot: {path}")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
