"""Testa o matching de rede (CIDR) usado pra resolver customer_prefix — a peça que
permite cadastrar blocos inteiros (rede pública /21 em /24, pool CGNAT /10) em vez
de só IPs exatos."""

from __future__ import annotations

from clientguard import resolve_customer_prefix

CUSTOMERS = [
    {"network": "177.86.16.0/24", "prefix": "177.86.16.0/24"},
    {"network": "100.64.0.0/10", "prefix": "100.64.0.0/10", "name": "CGNAT-A10"},
]


def test_matches_ip_inside_registered_subnet():
    assert resolve_customer_prefix("177.86.16.42", CUSTOMERS) == "177.86.16.0/24"


def test_matches_ip_inside_wide_cgnat_block():
    assert resolve_customer_prefix("100.64.100.121", CUSTOMERS) == "100.64.0.0/10"


def test_no_match_outside_any_registered_network():
    assert resolve_customer_prefix("8.8.8.8", CUSTOMERS) is None


def test_no_match_just_outside_subnet_boundary():
    assert resolve_customer_prefix("177.86.17.1", CUSTOMERS) is None


def test_no_match_just_outside_cgnat_block():
    # 100.64.0.0/10 vai até 100.127.255.255 — 100.128.x.x já está fora
    assert resolve_customer_prefix("100.128.0.1", CUSTOMERS) is None


def test_invalid_ip_returns_none_instead_of_raising():
    assert resolve_customer_prefix("não-é-um-ip", CUSTOMERS) is None


def test_empty_registry_never_matches():
    assert resolve_customer_prefix("177.86.16.42", []) is None
