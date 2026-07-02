"""Testa o matching de rede (CIDR) usado pra resolver customer_prefix — a peça que
permite cadastrar blocos inteiros (rede pública /21 em /24, pool CGNAT /10) em vez
de só IPs exatos."""

from __future__ import annotations

from customer_registry import WhitelistMatcher, classify_client_side, resolve_customer_prefix

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


def test_classify_upload_direction_client_is_src():
    # cliente enviando pra fora — src_ip é o cliente, como sempre foi
    assert classify_client_side("177.86.16.42", "8.8.8.8", CUSTOMERS) == ("177.86.16.42", "8.8.8.8", "177.86.16.0/24")


def test_classify_download_direction_client_is_dst():
    # cliente baixando de um servidor remoto — src_ip é o servidor, dst_ip é o cliente;
    # sem essa checagem dos dois lados, o "cliente" reportado seria o servidor remoto
    assert classify_client_side("8.8.8.8", "177.86.16.42", CUSTOMERS) == ("177.86.16.42", "8.8.8.8", "177.86.16.0/24")


def test_classify_neither_side_is_customer_returns_none():
    assert classify_client_side("8.8.8.8", "1.1.1.1", CUSTOMERS) is None


def test_classify_prefers_src_when_both_sides_are_customers():
    assert classify_client_side("177.86.16.1", "100.64.0.5", CUSTOMERS) == ("177.86.16.1", "100.64.0.5", "177.86.16.0/24")


# --- WhitelistMatcher (IP exato ou bloco CIDR) ---------------------------------

def test_whitelist_matches_exact_ip():
    wl = WhitelistMatcher(["177.86.16.36"])
    assert "177.86.16.36" in wl
    assert "177.86.16.37" not in wl


def test_whitelist_matches_ip_inside_cidr_block():
    # a causa raiz do bug real: um set comum de strings nunca bate um IP individual
    # contra uma entrada em notação CIDR
    wl = WhitelistMatcher(["177.86.17.0/27"])
    assert "177.86.17.10" in wl
    assert "177.86.17.31" in wl
    assert "177.86.17.32" not in wl  # primeiro IP fora do /27


def test_whitelist_mixes_exact_ips_and_cidr_blocks():
    wl = WhitelistMatcher(["177.86.16.36", "177.86.17.40/29", "177.86.17.48/29"])
    assert "177.86.16.36" in wl
    assert "177.86.17.42" in wl
    assert "177.86.17.50" in wl
    assert "177.86.17.60" not in wl


def test_whitelist_invalid_entry_ignored_instead_of_raising():
    wl = WhitelistMatcher(["não-é-um-ip", "177.86.16.36"])
    assert "177.86.16.36" in wl
    assert "não-é-um-ip" not in wl


def test_whitelist_len_counts_exact_and_cidr_entries():
    wl = WhitelistMatcher(["177.86.16.36", "177.86.17.0/27"])
    assert len(wl) == 2
