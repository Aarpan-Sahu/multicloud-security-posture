"""Provider-agnostic helpers for reasoning about network exposure."""

from __future__ import annotations

from collections.abc import Iterable

ADMIN_PORTS = frozenset({22, 3389})
DATABASE_PORTS = frozenset({1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017})

OPEN_IPV4 = "0.0.0.0/0"
OPEN_IPV6 = "::/0"
# Azure NSG source tokens that mean "anyone on the internet"
AZURE_OPEN_SOURCES = frozenset({"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", "::/0"})


def is_open_cidr(cidr: str | None) -> bool:
    return (cidr or "").strip() in (OPEN_IPV4, OPEN_IPV6)


def parse_port_spec(spec: str | int | None) -> tuple[int, int] | None:
    """Parse '22', '20-25', '*', 22 or None into an inclusive (low, high) range.

    None / '*' / '' means all ports.
    """
    if spec is None:
        return (0, 65535)
    s = str(spec).strip()
    if s in ("", "*", "all", "0-65535"):
        return (0, 65535)
    if "-" in s:
        lo, hi = s.split("-", 1)
        return (int(lo), int(hi))
    return (int(s), int(s))


def range_hits(rng: tuple[int, int], ports: Iterable[int]) -> set[int]:
    lo, hi = rng
    return {p for p in ports if lo <= p <= hi}


def is_all_ports(rng: tuple[int, int]) -> bool:
    return rng[0] <= 1 and rng[1] >= 65535
