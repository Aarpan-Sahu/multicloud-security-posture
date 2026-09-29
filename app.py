"""Streamlit front end for the multi-cloud security posture dashboard.

Run:  streamlit run app.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent / "src"))

from cspm.aggregator import load_snapshot, run_scan, save_snapshot  # noqa: E402
from cspm.ai import Advisor  # noqa: E402
from cspm.collectors import get_collector  # noqa: E402
from cspm.config import Settings  # noqa: E402
from cspm.models import Finding, ScanResult  # noqa: E402
from cspm.scoring import account_scope, overall_score, provider_scores, to_dataframe  # noqa: E402

st.set_page_config(page_title="Multi-Cloud Security Posture", page_icon="🛡️", layout="wide")

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_COLORS = {"Critical": "#B42318", "High": "#E0762B", "Medium": "#D9A400", "Low": "#3B82A0", "Info": "#8A94A6"}
PROVIDER_COLORS = {"AWS": "#E68A00", "AZURE": "#1F6FD1", "GCP": "#2E9E5B"}
settings = Settings()


# ---------------------------------------------------------------- data loading
@st.cache_data(show_spinner=False)
def load_demo() -> ScanResult:
    return get_collector("demo").collect()


@st.cache_resource(show_spinner=False)
def get_advisor() -> Advisor:
    return Advisor(model=settings.llm_model, enabled=settings.llm_enabled)


def get_result(source: str) -> ScanResult | None:
    if source == "Demo data":
        return load_demo()
    if source == "Last saved scan":
        path = Path(settings.snapshot_path)
        if not path.exists():
            st.info(f"No saved scan at `{path}`. Run `python scripts/scan.py` or use Live scan.")
            return None
        return load_snapshot(path)
    return st.session_state.get("live_result")


with st.sidebar:
    st.header("Data")
    source = st.radio("Source", ["Demo data", "Last saved scan", "Live scan"],
                      help="Demo data needs no cloud credentials.")
    if source == "Live scan":
        chosen = st.multiselect("Clouds to scan", ["aws", "azure", "gcp"], default=["aws", "azure", "gcp"],
                                format_func=str.upper)
        if st.button("Run scan", type="primary", disabled=not chosen, width="stretch"):
            with st.spinner("Scanning with read-only credentials..."):
                res = run_scan(chosen, settings)
                st.session_state["live_result"] = res
                save_snapshot(res, settings.snapshot_path)
            st.success(f"Scan finished: {len(res.findings)} findings. Saved to {settings.snapshot_path}.")

result = get_result(source)
if result is None:
    st.title("Multi-Cloud Security Posture")
    st.write("Choose **Run scan** in the sidebar to scan your AWS, Azure and GCP accounts.")
    st.stop()

df_all = to_dataframe(result.findings)
findings_by_id: dict[str, Finding] = {f.finding_id: f for f in result.findings}

# ---------------------------------------------------------------- filters
with st.sidebar:
    st.header("Filters")

    def opts(col: str) -> list[str]:
        return sorted(df_all[col].dropna().unique().tolist()) if not df_all.empty else []

    st.caption("Leave a filter empty to include everything.")
    f_prov = st.multiselect("Cloud provider", opts("provider"), placeholder="All clouds")
    f_sev = st.multiselect("Severity", [s for s in SEV_ORDER if s in opts("severity")], placeholder="All severities")
    f_cat = st.multiselect("Category", opts("category"), placeholder="All categories")
    f_type = st.multiselect("Resource type", opts("resource_type"), placeholder="All resource types")
    f_acct = st.multiselect("Account / subscription / project", opts("account_id"), placeholder="All accounts")
    f_exposed = st.toggle("Internet-exposed only")
    f_text = st.text_input("Search resource or rule", placeholder="e.g. payments, S3, 3389")

# The score is normalized by the accounts in view, so only the cloud and account filters change the scope.
scope = {(p, a) for p, a in account_scope(result.scanned_accounts, df_all)
         if (not f_prov or p in f_prov) and (not f_acct or a in f_acct)}

df = df_all
for col, chosen in (("provider", f_prov), ("severity", f_sev), ("category", f_cat),
                    ("resource_type", f_type), ("account_id", f_acct)):
    if chosen:
        df = df[df[col].isin(chosen)]
if f_exposed:
    df = df[df["internet_exposed"]]
if f_text:
    q = f_text.lower()
    mask = df["resource_id"].str.lower().str.contains(q, regex=False) | \
        df["title"].str.lower().str.contains(q, regex=False) | \
        df["rule_id"].str.lower().str.contains(q, regex=False) | \
        df["evidence"].astype(str).str.contains(q, regex=False)
    df = df[mask]

# ---------------------------------------------------------------- header + KPIs
st.title("Multi-Cloud Security Posture")
accounts = sum(len(v) for v in result.scanned_accounts.values())
st.caption(f"Source: {source}. Last scan finished {result.finished_at or 'n/a'} UTC across "
           f"{accounts} accounts, subscriptions and projects.")

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Posture score", f"{overall_score(df, scope)}/100",
          help="100 = no open risk. See scoring.py for the formula.")
k2.metric("Open findings", len(df))
k3.metric("Critical", int((df["severity"] == "Critical").sum()))
k4.metric("Internet-exposed", int(df["internet_exposed"].sum()))
k5.metric("Affected resources", df["resource_id"].nunique())

if result.errors:
    with st.expander(f"Coverage gaps: {len(result.errors)} checks could not run", icon="⚠️"):
        st.write("These checks failed, usually because of a missing read permission. "
                 "Findings for these services may be incomplete.")
        st.dataframe(pd.DataFrame([e.__dict__ for e in result.errors]), hide_index=True, width="stretch")

if df.empty:
    st.success("No findings match these filters.")
    st.stop()

tab_overview, tab_findings, tab_resource, tab_ai = st.tabs(
    ["Overview", "Findings", "Resource drill-down", "AI briefing"])

# ---------------------------------------------------------------- overview
with tab_overview:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Severity by cloud")
        counts = df.groupby(["provider", "severity"]).size().reset_index(name="findings")
        fig = px.bar(counts, x="provider", y="findings", color="severity",
                     category_orders={"severity": SEV_ORDER}, color_discrete_map=SEV_COLORS)
        fig.update_layout(margin=dict(t=10, b=10), legend_title_text="", xaxis_title="", height=360)
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.subheader("Where the risk sits")
        st.caption("Click a segment to zoom in: cloud, then category, then resource type.")
        fig = px.sunburst(df, path=["provider", "category", "resource_type"], values="risk",
                          color="provider", color_discrete_map=PROVIDER_COLORS)
        fig.update_layout(margin=dict(t=10, b=10), height=360)
        st.plotly_chart(fig, width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Resource type by severity")
        pivot = (df.pivot_table(index="resource_type", columns="severity", values="finding_id",
                                aggfunc="count", fill_value=0)
                 .reindex(columns=[s for s in SEV_ORDER if s in df["severity"].unique()]))
        fig = px.imshow(pivot, text_auto=True, aspect="auto", color_continuous_scale="OrRd")
        fig.update_layout(margin=dict(t=10, b=10), height=360, coloraxis_showscale=False,
                          xaxis_title="", yaxis_title="")
        st.plotly_chart(fig, width="stretch")
    with c4:
        st.subheader("Posture score by cloud")
        ps = provider_scores(df, scope)
        fig = px.bar(ps, x="score", y="provider", orientation="h", text="score", range_x=[0, 100],
                     color="provider", color_discrete_map=PROVIDER_COLORS,
                     hover_data=["accounts", "findings", "resources", "risk"])
        fig.update_layout(margin=dict(t=10, b=10), height=360, showlegend=False, yaxis_title="",
                          xaxis_title="Score (100 = no open risk)")
        fig.update_xaxes(range=[0, 100])
        st.plotly_chart(fig, width="stretch")

    st.subheader("Fix these first")
    st.caption("Ranked by risk: severity, internet exposure and how long the finding has been open.")
    top = df.head(10)[["severity", "provider", "title", "resource_type", "resource_id", "risk", "age_days"]]
    st.dataframe(top, hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.ProgressColumn("Risk", min_value=0,
                                                                        max_value=float(df_all["risk"].max()),
                                                                        format="%.0f"),
                                "age_days": st.column_config.NumberColumn("Open (days)"),
                                "severity": "Severity", "provider": "Cloud", "title": "Issue",
                                "resource_type": "Resource type", "resource_id": "Resource"})

# ---------------------------------------------------------------- findings explorer
with tab_findings:
    st.caption("Select a row to see evidence and remediation.")
    view = df[["severity", "provider", "account_id", "region", "resource_type", "title",
               "resource_id", "risk", "internet_exposed", "age_days"]]
    event = st.dataframe(
        view, hide_index=True, width="stretch", height=380,
        on_select="rerun", selection_mode="single-row",
        column_config={"internet_exposed": st.column_config.CheckboxColumn("Exposed"),
                       "risk": st.column_config.NumberColumn("Risk", format="%.0f"),
                       "age_days": st.column_config.NumberColumn("Open (days)"),
                       "severity": "Severity", "provider": "Cloud", "account_id": "Account",
                       "region": "Region", "resource_type": "Resource type", "title": "Issue",
                       "resource_id": "Resource"},
    )
    export = df.drop(columns=["evidence"]).assign(evidence=df["evidence"].map(json.dumps))
    st.download_button("Download filtered findings (CSV)", export.to_csv(index=False).encode(),
                       "findings.csv", "text/csv")

    rows = event.selection.rows if event and event.selection else []
    if rows:
        row = df.iloc[rows[0]]
        f = findings_by_id[row["finding_id"]]
        st.divider()
        st.subheader(f"{row['severity']}: {f.title}")
        a, b = st.columns([3, 2])
        with a:
            st.markdown(f"**Resource:** `{f.resource_id}`")
            st.markdown(f"**Where:** {f.provider.upper()} / {f.account_id} / {f.region}")
            st.markdown(f"**Why it matters:** {f.description}")
            st.markdown(f"**Baseline fix:** {f.remediation}")
            if f.compliance:
                st.markdown("**Mapped controls:** " + ", ".join(f.compliance))
        with b:
            st.markdown("**Evidence**")
            st.json(f.evidence or {"note": "No additional evidence"})
            st.caption(f"Rule {f.rule_id}, finding ID {f.finding_id}, detected {f.detected_at}")

        advisor = get_advisor()
        label = "Explain and plan the fix with AI" if advisor.available else "Show remediation plan"
        if st.button(label, key=f"ai-{f.finding_id}"):
            with st.spinner("Building remediation plan..."):
                plan = advisor.explain(f)
            if plan.source == "llm":
                st.caption("AI-generated from redacted data. Review before applying.")
            st.markdown(f"**Summary:** {plan.summary}")
            if plan.attack_scenario:
                st.markdown(f"**Attack scenario:** {plan.attack_scenario}")
            if plan.business_impact:
                st.markdown(f"**Business impact:** {plan.business_impact}")
            st.markdown("**Steps**")
            st.markdown("\n".join(f"{i}. {s}" for i, s in enumerate(plan.remediation_steps, 1)))
            if plan.terraform_fix:
                st.code(plan.terraform_fix, language="hcl")
            if plan.verification:
                st.markdown(f"**Verify:** {plan.verification}")
            if plan.downtime_risk:
                st.markdown(f"**Downtime risk:** {plan.downtime_risk}")

# ---------------------------------------------------------------- resource drill-down
with tab_resource:
    c1, c2, c3 = st.columns(3)
    prov = c1.selectbox("Cloud", sorted(df["provider"].unique()))
    d1 = df[df["provider"] == prov]
    acct = c2.selectbox("Account", sorted(d1["account_id"].unique()))
    d2 = d1[d1["account_id"] == acct]
    rtype = c3.selectbox("Resource type", sorted(d2["resource_type"].unique()))
    d3 = d2[d2["resource_type"] == rtype]

    per_res = (d3.groupby("resource_id")
               .agg(findings=("finding_id", "count"), risk=("risk", "sum"), worst=("sev_rank", "max"),
                    exposed=("internet_exposed", "any"))
               .sort_values("risk", ascending=False).reset_index())
    per_res["worst"] = per_res["worst"].map(lambda r: SEV_ORDER[4 - r])
    st.dataframe(per_res, hide_index=True, width="stretch",
                 column_config={"exposed": st.column_config.CheckboxColumn("Exposed"),
                                "risk": st.column_config.NumberColumn("Total risk", format="%.0f"),
                                "worst": "Worst severity"})
    res = st.selectbox("Resource", per_res["resource_id"].tolist())
    for _, r in d3[d3["resource_id"] == res].iterrows():
        with st.container(border=True):
            st.markdown(f"**{r['severity']}: {r['title']}** ({r['rule_id']})")
            st.write(r["remediation"])

# ---------------------------------------------------------------- AI briefing
with tab_ai:
    advisor = get_advisor()
    st.write("A summary of the filtered posture for leadership. Only aggregate counts and rule "
             "titles are sent to the model, never resource names or account IDs.")
    top_rules = Counter(zip(df["title"], df["provider"], strict=True))
    stats = {
        "score": overall_score(df, scope), "total": len(df),
        "critical": int((df["severity"] == "Critical").sum()),
        "exposed": int(df["internet_exposed"].sum()),
        "by_provider": df["provider"].value_counts().to_dict(),
        "by_severity": df["severity"].value_counts().to_dict(),
        "by_category": df["category"].value_counts().to_dict(),
        "top_rules": [{"title": t, "provider": p, "count": c} for (t, p), c in top_rules.most_common(8)],
    }
    with st.expander("Exact data sent to the model"):
        st.json(stats)
    if st.button("Generate briefing", type="primary"):
        with st.spinner("Writing briefing..."):
            st.markdown(advisor.executive_briefing(stats))
