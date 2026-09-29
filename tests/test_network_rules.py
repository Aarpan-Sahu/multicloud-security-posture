from types import SimpleNamespace as NS

from cspm.collectors.azure import nsg_rule_exposure, resource_group_of
from cspm.collectors.gcp import firewall_exposure
from cspm.netutils import is_all_ports, parse_port_spec, range_hits


def test_port_parsing():
    assert parse_port_spec("22") == (22, 22)
    assert parse_port_spec("20-25") == (20, 25)
    assert parse_port_spec("*") == (0, 65535)
    assert parse_port_spec(None) == (0, 65535)
    assert range_hits((20, 25), {22, 3389}) == {22}
    assert is_all_ports((0, 65535))


def _nsg(**kw):
    base = dict(direction="Inbound", access="Allow", protocol="Tcp", source_address_prefix="*",
                source_address_prefixes=[], destination_port_range="22", destination_port_ranges=[],
                name="r", priority=100)
    base.update(kw)
    return NS(**base)


def test_azure_nsg_admin_port_open():
    assert nsg_rule_exposure(_nsg()) == ("AZ-NSG-001", [22])


def test_azure_nsg_internet_tag_and_ranges():
    rule = _nsg(source_address_prefix="Internet", destination_port_range=None,
                destination_port_ranges=["80", "3380-3390"])
    assert nsg_rule_exposure(rule) == ("AZ-NSG-001", [3389])


def test_azure_nsg_all_ports():
    assert nsg_rule_exposure(_nsg(destination_port_range="*"))[0] == "AZ-NSG-002"


def test_azure_nsg_ignores_deny_private_and_outbound():
    assert nsg_rule_exposure(_nsg(access="Deny")) == (None, None)
    assert nsg_rule_exposure(_nsg(source_address_prefix="10.0.0.0/8")) == (None, None)
    assert nsg_rule_exposure(_nsg(direction="Outbound")) == (None, None)


def test_azure_nsg_icmp_is_not_all_ports():
    assert nsg_rule_exposure(_nsg(protocol="Icmp", destination_port_range="*")) == (None, None)
    assert nsg_rule_exposure(_nsg(protocol="*", destination_port_range="*"))[0] == "AZ-NSG-002"


def test_azure_resource_group_parsing():
    rid = "/subscriptions/x/resourceGroups/rg-Prod/providers/Microsoft.Sql/servers/s1"
    assert resource_group_of(rid) == "rg-Prod"


def _fw(allowed, src=("0.0.0.0/0",), direction="INGRESS", disabled=False):
    return NS(direction=direction, disabled=disabled, source_ranges=list(src),
              allowed=[NS(I_p_protocol=p, ports=ports) for p, ports in allowed])


def test_gcp_firewall_ssh_open():
    assert firewall_exposure(_fw([("tcp", ["22"])])) == ("GCP-FW-001", [22])


def test_gcp_firewall_all():
    assert firewall_exposure(_fw([("all", [])]))[0] == "GCP-FW-002"
    assert firewall_exposure(_fw([("tcp", [])]))[0] == "GCP-FW-002"


def test_gcp_firewall_safe_cases():
    assert firewall_exposure(_fw([("tcp", ["443"])])) == (None, None)
    assert firewall_exposure(_fw([("tcp", ["22"])], src=["35.235.240.0/20"])) == (None, None)
    assert firewall_exposure(_fw([("tcp", ["22"])], disabled=True)) == (None, None)


def test_gcp_firewall_ipv6_open():
    assert firewall_exposure(_fw([("tcp", ["3389"])], src=["::/0"])) == ("GCP-FW-001", [3389])
