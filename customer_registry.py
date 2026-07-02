"""Resolução de customer_prefix a partir do src_ip — matching por rede (CIDR), não
IP exato, pra suportar blocos inteiros de clientes (rede pública em /24, pool CGNAT
em /10). Separado do clientguard.py de propósito: essa é lógica pura, sem nenhuma
dependência de captura/scapy/FlowGuard, então testes e outros consumidores (CGI
scripts do portal, se precisarem) podem importar sem arrastar o resto do daemon."""

from __future__ import annotations

import ipaddress


def resolve_customer_prefix(src_ip: str, customers: list[dict]) -> str | None:
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return None
    for c in customers:
        network = c.get("network")
        if not network:
            continue
        try:
            if addr in ipaddress.ip_network(network, strict=False):
                return c.get("prefix")
        except ValueError:
            continue
    return None
