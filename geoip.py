"""Enriquecimento de ASN/país via Team Cymru IP-to-ASN (bulk whois, whois.cymru.com:43) —
serviço público, gratuito, sem chave de API nem banco MaxMind local (o FlowGuard também
nunca chegou a configurar isso — só tem a seção geoip no config.yaml, sem implementação).
Cache persistido em SQLite (tabela geoip_cache): ASN/país de um IP não muda em escala de
horas, então uma consulta por IP ao longo da vida do sistema já basta — persistir evita
reconsultar tudo de novo a cada restart do daemon. Puramente aditivo — falha de rede aqui
nunca atrasa a gravação dos flows além do timeout, e os campos ficam só como NULL."""

from __future__ import annotations

import logging
import socket
from contextlib import nullcontext

import storage

LOG = logging.getLogger("clientguard.geoip")

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43


def _bulk_query(ips: list[str], timeout: float = 3.0) -> dict[str, tuple[int | None, str | None]] | None:
    """Retorna None em falha de rede (quem chama deve tentar de novo depois, não
    gravar 'sem dado' permanentemente) — diferente de um IP legitimamente ausente
    da resposta (sem ASN conhecido), que vira (None, None) só pra aquele IP."""
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
        return None

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
    def __init__(self, conn=None, db_lock=None):
        self.conn = conn
        self.db_lock = db_lock
        self._cache: dict[str, tuple[int | None, str | None]] = {}
        if conn is not None:
            lock = db_lock or nullcontext()
            with lock:
                self._cache = storage.load_geoip_cache(conn)
            LOG.info("cache de geoip carregado do banco: %d IPs", len(self._cache))

    def enrich(self, ips: set[str]) -> None:
        missing = [ip for ip in ips if ip not in self._cache]
        if not missing:
            return
        results = _bulk_query(missing)
        if results is None:
            return  # falha de rede — tenta de novo no próximo ciclo, não marca nada como "sem dado"

        new_entries = []
        for ip in missing:
            value = results.get(ip, (None, None))
            self._cache[ip] = value
            new_entries.append((ip, value[0], value[1]))

        if self.conn is not None:
            lock = self.db_lock or nullcontext()
            with lock:
                storage.save_geoip_batch(self.conn, new_entries)

    def lookup(self, ip: str) -> tuple[int | None, str | None]:
        return self._cache.get(ip, (None, None))
