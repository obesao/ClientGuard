"""Feed de reputação de IPs maliciosos — baixa e mescla listas públicas conhecidas
(Feodo Tracker C2, Spamhaus DROP/EDROP, ipsum) num cache local próprio, refeito
periodicamente. Puramente aditivo: se o download falhar ou uma fonte não responder,
o detector que usa isso simplesmente não encontra nada, nunca derruba o resto do
pipeline. Implementação própria do ClientGuard — o FlowGuard só tem essa seção no
config.yaml (threat_feeds), mas nunca chegou a implementar o download."""

from __future__ import annotations

import ipaddress
import logging
import urllib.request
from pathlib import Path

LOG = logging.getLogger("clientguard.threat_feed")


def _fetch(url: str, timeout: float = 15.0) -> list[str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore").splitlines()
    except Exception:
        LOG.warning("falha ao baixar feed %s", url, exc_info=True)
        return []


def _parse_lines(lines: list[str]) -> set[str]:
    """Extrai IPs/CIDRs de linhas de feeds públicos — ignora comentários (#, ;) e
    colunas extras (ex.: ipsum tem 'ip<TAB>contagem', spamhaus DROP tem 'CIDR ; SBLxxxx')."""
    entries: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split(";")[0].split()[0].strip()
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        entries.add(token)
    return entries


def refresh(sources: list[str], cache_file: str) -> int:
    """Baixa todas as fontes, mescla, grava no cache. Retorna quantas entradas foram salvas."""
    merged: set[str] = set()
    for url in sources:
        merged |= _parse_lines(_fetch(url))
    if not merged:
        LOG.warning("nenhuma entrada obtida das fontes de threat feed — mantendo cache anterior")
        return 0
    Path(cache_file).parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(merged)) + "\n")
    LOG.info("threat feed atualizado: %d entradas (%d fontes)", len(merged), len(sources))
    return len(merged)


class ThreatFeed:
    """single_ips (set) pros feeds de host único (feodotracker, ipsum) — lookup O(1).
    networks (lista) só pros blocos CIDR de fato (spamhaus DROP/EDROP) — poucas
    centenas de entradas, scan linear por dst_ip distinto é barato o bastante."""

    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self._single_ips: set[str] = set()
        self._networks: list = []
        self.load()

    def load(self) -> None:
        single_ips: set[str] = set()
        networks = []
        try:
            with open(self.cache_file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        continue
                    if net.num_addresses == 1:
                        single_ips.add(str(net.network_address))
                    else:
                        networks.append(net)
        except FileNotFoundError:
            pass
        self._single_ips = single_ips
        self._networks = networks
        LOG.info("threat feed carregado: %d IPs únicos, %d blocos CIDR", len(single_ips), len(networks))

    def is_malicious(self, ip: str) -> bool:
        if ip in self._single_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)
