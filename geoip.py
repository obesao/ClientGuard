"""Enriquecimento de ASN/país via Team Cymru IP-to-ASN (bulk whois, whois.cymru.com:43) —
serviço público, gratuito, sem chave de API nem banco MaxMind local (o FlowGuard também
nunca chegou a configurar isso — só tem a seção geoip no config.yaml, sem implementação).
Cache em memória: ASN/país de um IP não muda em escala de horas, então uma consulta por
IP ao longo da vida do processo já basta. Puramente aditivo — falha de rede aqui nunca
atrasa a gravação dos flows além do timeout, e os campos ficam só como NULL."""

from __future__ import annotations

import logging
import socket

LOG = logging.getLogger("clientguard.geoip")

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43


def _bulk_query(ips: list[str], timeout: float = 3.0) -> dict[str, tuple[int | None, str | None]]:
    if not ips:
        return {}
    request = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    try:
        with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=timeout) as sock:
            sock.sendall(request.encode("ascii"))
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8", errors="ignore")
    except OSError:
        LOG.warning("falha ao consultar Team Cymru pra enriquecimento ASN/país", exc_info=True)
        return {}

    results: dict[str, tuple[int | None, str | None]] = {}
    for line in response.splitlines():
        if "AS Name" in line or line.startswith("Bulk mode"):
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) < 4:
            continue
        asn_str, ip, country = fields[0], fields[1], fields[3]
        asn = int(asn_str) if asn_str.isdigit() else None
        results[ip] = (asn, country if country and country != "NA" else None)
    return results


class GeoIPCache:
    def __init__(self):
        self._cache: dict[str, tuple[int | None, str | None]] = {}

    def enrich(self, ips: set[str]) -> None:
        missing = [ip for ip in ips if ip not in self._cache]
        if not missing:
            return
        results = _bulk_query(missing)
        for ip in missing:
            self._cache[ip] = results.get(ip, (None, None))

    def lookup(self, ip: str) -> tuple[int | None, str | None]:
        return self._cache.get(ip, (None, None))
