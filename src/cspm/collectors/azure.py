"""Azure collector built on the azure-mgmt-* SDKs and DefaultAzureCredential."""

from __future__ import annotations

from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

from ..models import ScanResult, utc_now
from ..netutils import ADMIN_PORTS, AZURE_OPEN_SOURCES, is_all_ports, parse_port_spec, range_hits
from ..rules import make_finding
from .base import BaseCollector


def resource_group_of(resource_id: str) -> str:
    parts = resource_id.split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("resourcegroups") + 1]


def nsg_rule_exposure(rule) -> tuple[str | None, list[int] | str | None]:
    """Return (rule_id, ports) if an NSG security rule exposes the VM to the internet."""
    if (rule.direction or "").lower() != "inbound" or (rule.access or "").lower() != "allow":
        return None, None
    # ICMP, ESP and AH have no ports; their "*" port range must not read as "all ports open".
    if (rule.protocol or "*").lower() not in ("*", "tcp", "udp"):
        return None, None
    sources = [rule.source_address_prefix] + list(rule.source_address_prefixes or [])
    if not any((s or "").strip().lower() in AZURE_OPEN_SOURCES for s in sources if s):
        return None, None
    specs = [rule.destination_port_range] if rule.destination_port_range else []
    specs += list(rule.destination_port_ranges or [])
    ranges = [parse_port_spec(s) for s in specs] or [parse_port_spec("*")]
    if any(is_all_ports(r) for r in ranges):
        return "AZ-NSG-002", "all"
    hits = set().union(*(range_hits(r, ADMIN_PORTS) for r in ranges))
    return ("AZ-NSG-001", sorted(hits)) if hits else (None, None)


class AzureCollector(BaseCollector):
    provider = "azure"

    def __init__(self, subscription_ids: list[str] | None = None) -> None:
        super().__init__()
        # Works with az login locally, managed identity in Azure, or workload identity in CI.
        self.credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        self.subscription_ids = subscription_ids or [
            s.subscription_id for s in SubscriptionClient(self.credential).subscriptions.list()
        ]

    def collect(self) -> ScanResult:
        for sub in self.subscription_ids:
            self.add_account(sub)
            with self.check(f"storage:{sub}"):
                self._check_storage(sub)
            with self.check(f"nsg:{sub}"):
                self._check_nsgs(sub)
            with self.check(f"sql:{sub}"):
                self._check_sql(sub)
            with self.check(f"keyvault:{sub}"):
                self._check_keyvault(sub)
        self.result.finished_at = utc_now()
        return self.result

    def _emit(self, rule_id, sub, region, resource_id, **evidence) -> None:
        self.emit(make_finding(rule_id, account_id=sub, region=region or "global",
                               resource_id=resource_id, evidence=evidence))

    def _check_storage(self, sub: str) -> None:
        client = StorageManagementClient(self.credential, sub)
        for acct in client.storage_accounts.list():
            # With public network access disabled, only private endpoints can reach the account.
            reachable = (acct.public_network_access or "Enabled") != "Disabled"
            if acct.allow_blob_public_access:
                self._emit("AZ-ST-001", sub, acct.location, acct.id, internet_exposed=reachable)
            tls = acct.minimum_tls_version or "TLS1_0"
            if acct.enable_https_traffic_only is False or tls in ("TLS1_0", "TLS1_1"):
                self._emit("AZ-ST-002", sub, acct.location, acct.id,
                           https_only=acct.enable_https_traffic_only, min_tls=tls)
            rules = acct.network_rule_set
            if reachable and (rules is None or (rules.default_action or "Allow") == "Allow"):
                self._emit("AZ-ST-003", sub, acct.location, acct.id)

    def _check_nsgs(self, sub: str) -> None:
        client = NetworkManagementClient(self.credential, sub)
        for nsg in client.network_security_groups.list_all():
            for rule in nsg.security_rules or []:
                rule_id, ports = nsg_rule_exposure(rule)
                if rule_id:
                    self._emit(rule_id, sub, nsg.location, nsg.id, internet_exposed=True,
                               rule_name=rule.name, priority=rule.priority, ports=ports)

    def _check_sql(self, sub: str) -> None:
        client = SqlManagementClient(self.credential, sub)
        for server in client.servers.list():
            rg = resource_group_of(server.id)
            for fw in client.firewall_rules.list_by_server(rg, server.name):
                if fw.start_ip_address == "0.0.0.0" and fw.end_ip_address == "255.255.255.255":
                    self._emit("AZ-SQL-001", sub, server.location, server.id,
                               internet_exposed=True, firewall_rule=fw.name)
                elif fw.start_ip_address == "0.0.0.0" and fw.end_ip_address == "0.0.0.0":
                    self._emit("AZ-SQL-002", sub, server.location, server.id, firewall_rule=fw.name)

    def _check_keyvault(self, sub: str) -> None:
        client = KeyVaultManagementClient(self.credential, sub)
        for vault in client.vaults.list_by_subscription():
            if not vault.properties.enable_purge_protection:
                self._emit("AZ-KV-001", sub, vault.location, vault.id)
