"""Envio de alerta via webhook/WhatsApp quando um sinal suspeito NOVO é gravado (mesmo
padrão do FlowGuard: request simples, timeout curto, silencioso em caso de falha — não
há retry)."""

from __future__ import annotations

import json
import logging
import sys
import urllib.request
from urllib.error import URLError

LOG = logging.getLogger("clientguard.notifier")

if "/root/evolution-api" not in sys.path:
    sys.path.insert(0, "/root/evolution-api")


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


def send_whatsapp(message: str) -> bool:
    """Mesma Evolution API self-hosted do FlowGuard (flowguard/notifier.py) —
    duplicado aqui de propósito, os dois projetos são deliberadamente
    independentes, mas só existe UMA sessão/destino WhatsApp real (compartilhado
    via /root/evolution-api/notify.yaml, configurável pelo portal)."""
    try:
        import client as evo
    except ImportError:
        LOG.error("client.py da Evolution API não encontrado em /root/evolution-api")
        return False
    dest = evo.load_dest().get("dest")
    if not dest:
        return False
    return evo.send_text(dest, message)
