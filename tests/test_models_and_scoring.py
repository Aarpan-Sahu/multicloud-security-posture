from cspm.collectors import get_collector
from cspm.collectors.base import merge_evidence
from cspm.models import ScanResult, Severity
from cspm.rules import RULES, make_finding
from cspm.scoring import (
    account_scope,
    age_days,
    finding_risk,
    overall_score,
    posture_score,
    provider_scores,
    to_dataframe,
)


def _f(rule="AWS-EC2-001", exposed=True, rid="sg-1"):
    return make_finding(rule, account_id="111122223333", region="us-east-1", resource_id=rid,
                        evidence={"internet_exposed": exposed})


def test_finding_id_is_stable_and_unique():
    assert _f().finding_id == _f().finding_id
    assert _f(rid="sg-1").finding_id != _f(rid="sg-2").finding_id


def test_roundtrip_serialization():
    r = ScanResult(findings=[_f()])
    back = ScanResult.from_dict(r.to_dict())
    assert back.findings[0].finding_id == r.findings[0].finding_id
    assert back.findings[0].severity is Severity.HIGH


def test_exposure_increases_risk():
    assert finding_risk(_f(exposed=True)) > finding_risk(_f(exposed=False))


def test_critical_outranks_medium():
    crit = make_finding("AWS-IAM-001", account_id="a", region="global", resource_id="root")
    med = make_finding("AWS-IAM-004", account_id="a", region="global", resource_id="u")
    assert finding_risk(crit) > finding_risk(med)


def test_posture_score_bounds():
    assert posture_score(0, 10) == 100
    assert 0 <= posture_score(10_000, 1) < 5
    assert overall_score(to_dataframe([]), set()) == 100


def test_more_findings_never_raise_the_score():
    scanned = {"aws": ["111122223333"]}
    one = [_f(rid="sg-0")]
    many = one + [_f(rule="AWS-IAM-004", exposed=False, rid=f"user-{i}") for i in range(10)]
    df_one, df_many = to_dataframe(one), to_dataframe(many)
    score_many = overall_score(df_many, account_scope(scanned, df_many))
    assert score_many < overall_score(df_one, account_scope(scanned, df_one))


def test_provider_scores_include_clean_providers():
    df = to_dataframe([_f()])
    ps = provider_scores(df, account_scope({"aws": ["111122223333"], "gcp": ["proj"]}, df))
    assert dict(zip(ps["provider"], ps["score"], strict=True))["GCP"] == 100
    assert ps.set_index("provider").loc["AWS", "score"] < 100


def test_age_days_tolerates_bad_timestamps():
    assert age_days("not-a-date") == 0
    assert age_days("2020-01-01T00:00:00") == 0  # timezone-naive


def test_merge_evidence_keeps_every_value():
    assert merge_evidence([22], [3389]) == [22, 3389]
    assert merge_evidence("1", "2") == ["1", "2"]
    assert merge_evidence(True, False) is True
    assert merge_evidence(None, [22]) == [22]


def test_every_rule_is_well_formed():
    for rule_id, rule in RULES.items():
        assert rule_id.split("-")[0].lower() in {"aws", "az", "gcp"}
        assert rule.remediation and rule.description
        assert isinstance(rule.severity, Severity)


def test_demo_collector_is_deterministic():
    a = get_collector("demo", seed=7).collect()
    b = get_collector("demo", seed=7).collect()
    assert [f.finding_id for f in a.findings] == [f.finding_id for f in b.findings]
    assert {f.provider for f in a.findings} == {"aws", "azure", "gcp"}
    assert len({f.finding_id for f in a.findings}) == len(a.findings)


def test_dataframe_sorted_by_risk():
    df = to_dataframe(get_collector("demo").collect().findings)
    assert df["risk"].is_monotonic_decreasing
