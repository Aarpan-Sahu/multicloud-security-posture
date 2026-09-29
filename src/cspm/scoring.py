"""Deterministic, explainable risk scoring.

risk(finding) = severity_weight x exposure_multiplier x age_multiplier
posture_score  = 100 x exp(-total_risk / (K x accounts_in_scope))

The exponential keeps the score in (0, 100] and degrades smoothly. It is normalized by the number
of scanned accounts / subscriptions / projects, which does not depend on the findings, so the
score can only go down when a finding is added and only go up when one is fixed.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pandas as pd

from .models import Finding, Severity

SEVERITY_WEIGHT = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 2, Severity.INFO: 0}
EXPOSURE_MULTIPLIER = 1.5
K = 800.0  # risk points per account at which the score reaches ~37 (e^-1)


def age_days(detected_at: str, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    try:
        return max(0, (now - datetime.fromisoformat(detected_at)).days)
    except (TypeError, ValueError):  # unparseable or timezone-naive timestamp
        return 0


def finding_risk(f: Finding, now: datetime | None = None) -> float:
    base = SEVERITY_WEIGHT[f.severity]
    exposure = EXPOSURE_MULTIPLIER if f.internet_exposed else 1.0
    # Findings left open longer are more likely to be discovered by attackers; cap at +50%.
    aging = 1.0 + min(age_days(f.detected_at, now), 30) / 60
    return round(base * exposure * aging, 1)


def posture_score(total_risk: float, account_count: int) -> int:
    if total_risk <= 0:
        return 100
    return round(100 * math.exp(-total_risk / (K * max(account_count, 1))))


def account_scope(scanned_accounts: dict[str, list[str]], df: pd.DataFrame) -> set[tuple[str, str]]:
    """(PROVIDER, account) pairs that were scanned, plus any that appear in findings."""
    scope = {(p.upper(), a) for p, accts in scanned_accounts.items() for a in accts}
    if not df.empty:
        scope |= set(zip(df["provider"], df["account_id"], strict=True))
    return scope


def to_dataframe(findings: list[Finding]) -> pd.DataFrame:
    cols = ["finding_id", "provider", "account_id", "region", "resource_type", "resource_id", "rule_id",
            "title", "severity", "sev_rank", "category", "internet_exposed", "risk", "age_days",
            "detected_at", "status", "description", "remediation", "compliance", "evidence"]
    if not findings:
        return pd.DataFrame(columns=cols)
    now = datetime.now(timezone.utc)
    rows = []
    for f in findings:
        rows.append({
            "finding_id": f.finding_id, "provider": f.provider.upper(), "account_id": f.account_id,
            "region": f.region, "resource_type": f.resource_type, "resource_id": f.resource_id,
            "rule_id": f.rule_id, "title": f.title, "severity": f.severity.name.title(),
            "sev_rank": int(f.severity), "category": f.category, "internet_exposed": f.internet_exposed,
            "risk": finding_risk(f, now), "age_days": age_days(f.detected_at, now),
            "detected_at": f.detected_at, "status": f.status, "description": f.description,
            "remediation": f.remediation, "compliance": ", ".join(f.compliance), "evidence": f.evidence,
        })
    return pd.DataFrame(rows, columns=cols).sort_values(["risk", "sev_rank"], ascending=False, ignore_index=True)


def provider_scores(df: pd.DataFrame, scope: set[tuple[str, str]]) -> pd.DataFrame:
    """One row per provider in scope, including clean providers (score 100)."""
    cols = ["provider", "accounts", "findings", "resources", "risk", "score"]
    providers = sorted({p for p, _ in scope} | set(df["provider"]))
    if not providers:
        return pd.DataFrame(columns=cols)
    g = (df.groupby("provider").agg(findings=("finding_id", "count"), resources=("resource_id", "nunique"),
                                    risk=("risk", "sum"))
         .reindex(providers, fill_value=0).rename_axis("provider").reset_index())
    g["accounts"] = [sum(1 for p, _ in scope if p == prov) for prov in g["provider"]]
    g["score"] = [posture_score(r, n) for r, n in zip(g["risk"], g["accounts"], strict=True)]
    return g[cols]


def overall_score(df: pd.DataFrame, scope: set[tuple[str, str]]) -> int:
    return posture_score(float(df["risk"].sum()) if not df.empty else 0.0, len(scope))
