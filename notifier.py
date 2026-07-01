"""Envio de alerta via webhook quando um sinal suspeito NOVO é gravado (mesmo padrão
do FlowGuard: POST JSON, timeout de 5s, silencioso em caso de falha — não há retry)."""

from __future__ import annotations

import json
import logging
import urllib.request
from urllib.error import URLError

LOG = logging.getLogger("clientguard.notifier")


def send_webhook(webhook_url: str, payload: dict, timeout: float = 5.0) -> bool:
    req = urllib.request.Request(
        webhook_url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return True
    except (URLError, OSError, ValueError):
        LOG.exception("falha ao enviar webhook de alerta para %s", webhook_url)
        return False
