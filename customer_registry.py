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


def classify_client_side(src_ip: str, dst_ip: str, customers: list[dict]) -> tuple[str, str, str] | None:
    """Decide qual lado do flow é o cliente monitorado — pode ser src OU dst dependendo
    da direção: upload (cliente manda) tem src_ip=cliente, download (cliente recebe, a
    maior parte do consumo residencial) tem dst_ip=cliente. Olhar só src_ip (como
    resolve_customer_prefix isolado faz) atribui tráfego de download ao IP do servidor
    remoto em vez do cliente. Retorna (client_ip, other_ip, customer_prefix) na ordem
    canônica — client_ip sempre o lado cadastrado — ou None se nenhum dos dois lados é
    cliente conhecido (tráfego alheio ao provedor, fora do escopo desta ferramenta)."""
    prefix = resolve_customer_prefix(src_ip, customers)
    if prefix is not None:
        return src_ip, dst_ip, prefix
    prefix = resolve_customer_prefix(dst_ip, customers)
    if prefix is not None:
        return dst_ip, src_ip, prefix
    return None


class WhitelistMatcher:
    """src_ip que nunca deve gerar alerta — aceita IP exato ou bloco CIDR (ex.: um /27
    inteiro de appliances de CDN), mesmo padrão exato-vs-rede do ThreatFeed (threat_feed.py).
    Implementa __contains__/__len__ de propósito: é um substituto direto do `set` que
    detector.py já usa via `if src_ip in whitelist`, então nenhum call site dos detectores
    precisa mudar — só a construção (clientguard.py) passa a usar esta classe em vez de
    `set(...)`. Sem isso, uma entrada em notação CIDR num whitelist.yaml vira uma string
    solta num set — nunca bate com nenhum IP real via igualdade exata."""

    def __init__(self, entries: list[str]):
        self._exact: set[str] = set()
        self._networks: list = []
        for entry in entries:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                self._exact.add(str(net.network_address))
            else:
                self._networks.append(net)

    def __contains__(self, ip: str) -> bool:
        if ip in self._exact:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def __len__(self) -> int:
        return len(self._exact) + len(self._networks)
