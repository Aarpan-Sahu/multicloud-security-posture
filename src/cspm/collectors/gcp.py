"""GCP collector built on google-cloud-* client libraries and Application Default Credentials."""

from __future__ import annotations

import google.auth
from google.cloud import compute_v1, storage
from googleapiclient import discovery

from ..models import ScanResult, utc_now
from ..netutils import ADMIN_PORTS, OPEN_IPV4, is_all_ports, is_open_cidr, parse_port_spec, range_hits
from ..rules import make_finding
from .base import BaseCollector

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}


def firewall_exposure(fw) -> tuple[str | None, list[int] | str | None]:
    """Evaluate a compute_v1.Firewall; return (rule_id, ports) when internet-exposed."""
    if fw.direction != "INGRESS" or fw.disabled or not any(is_open_cidr(r) for r in fw.source_ranges):
        return None, None
    admin_hits: set[int] = set()
    for allowed in fw.allowed:
        proto = allowed.I_p_protocol
        if proto not in ("tcp", "all", "udp"):
            continue
        ranges = [parse_port_spec(p) for p in allowed.ports] or [parse_port_spec("*")]
        if proto == "all" or any(is_all_ports(r) for r in ranges):
            return "GCP-FW-002", "all"
        if proto == "tcp":
            for r in ranges:
                admin_hits |= range_hits(r, ADMIN_PORTS)
    return ("GCP-FW-001", sorted(admin_hits)) if admin_hits else (None, None)


class GCPCollector(BaseCollector):
    provider = "gcp"

    def __init__(self, project_ids: list[str] | None = None) -> None:
        super().__init__()
        self.credentials, default_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        self.project_ids = project_ids or ([default_project] if default_project else [])
        if not self.project_ids:
            raise ValueError("No GCP project configured. Set GCP_PROJECT_IDS.")

    def collect(self) -> ScanResult:
        for project in self.project_ids:
            self.add_account(project)
            with self.check(f"storage:{project}"):
                self._check_buckets(project)
            with self.check(f"firewalls:{project}"):
                self._check_firewalls(project)
            with self.check(f"iam:{project}"):
                self._check_iam(project)
            with self.check(f"sqladmin:{project}"):
                self._check_cloudsql(project)
        self.result.finished_at = utc_now()
        return self.result

    def _emit(self, rule_id, project, region, resource_id, **evidence) -> None:
        self.emit(make_finding(rule_id, account_id=project, region=(region or "global").lower(),
                               resource_id=resource_id, evidence=evidence))

    def _api(self, name: str, version: str):
        return discovery.build(name, version, credentials=self.credentials, cache_discovery=False)

    def _check_buckets(self, project: str) -> None:
        client = storage.Client(project=project, credentials=self.credentials)
        for bucket in client.list_buckets():
            rid = f"//storage.googleapis.com/{bucket.name}"
            with self.check(f"storage:{bucket.name}"):
                policy = bucket.get_iam_policy(requested_policy_version=3)
                public = sorted({m for b in policy.bindings for m in b["members"] if m in PUBLIC_MEMBERS})
                if public:
                    self._emit("GCP-GCS-001", project, bucket.location, rid,
                               internet_exposed=True, members=public)
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    self._emit("GCP-GCS-002", project, bucket.location, rid)

    def _check_firewalls(self, project: str) -> None:
        client = compute_v1.FirewallsClient(credentials=self.credentials)
        for fw in client.list(project=project):
            rule_id, ports = firewall_exposure(fw)
            if rule_id:
                self._emit(rule_id, project, "global", fw.self_link, internet_exposed=True,
                           network=fw.network.rsplit("/", 1)[-1], ports=ports)

    def _check_iam(self, project: str) -> None:
        crm = self._api("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project, body={}).execute()
        proj_rid = f"//cloudresourcemanager.googleapis.com/projects/{project}"
        for binding in policy.get("bindings", []):
            members = binding.get("members", [])
            if PUBLIC_MEMBERS & set(members):
                self._emit("GCP-IAM-003", project, "global", proj_rid, internet_exposed=True, role=binding["role"])
            if binding["role"] in PRIMITIVE_ROLES:
                for m in members:
                    if m.startswith("serviceAccount:"):
                        self._emit("GCP-IAM-002", project, "global", proj_rid,
                                   member=m, role=binding["role"])

        iam = self._api("iam", "v1")
        req = iam.projects().serviceAccounts().list(name=f"projects/{project}")
        while req is not None:
            resp = req.execute()
            for sa in resp.get("accounts", []):
                keys = iam.projects().serviceAccounts().keys().list(
                    name=sa["name"], keyTypes="USER_MANAGED").execute().get("keys", [])
                if keys:
                    self._emit("GCP-IAM-001", project, "global", sa["name"],
                               key_count=len(keys), email=sa["email"])
            req = iam.projects().serviceAccounts().list_next(req, resp)

    def _check_cloudsql(self, project: str) -> None:
        sql = self._api("sqladmin", "v1beta4")
        req = sql.instances().list(project=project)
        while req is not None:
            resp = req.execute()
            for inst in resp.get("items", []):
                nets = inst.get("settings", {}).get("ipConfiguration", {}).get("authorizedNetworks", [])
                if any(n.get("value") == OPEN_IPV4 for n in nets):
                    self._emit("GCP-SQL-001", project, inst.get("region"), inst.get("selfLink", inst["name"]),
                               internet_exposed=True, database_version=inst.get("databaseVersion"))
            req = sql.instances().list_next(req, resp)
