"""Envio de alerta via webhook/WhatsApp quando um sinal suspeito NOVO é gravado (mesmo
padrão do FlowGuard: request simples, timeout curto, silencioso em caso de falha — não
há retry)."""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from urllib.error import URLError

LOG = logging.getLogger("clientguard.notifier")

CALLMEBOT_URL = "https://api.callmebot.com/whatsapp.php"


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


def send_whatsapp(phone: str, apikey: str, message: str, timeout: float = 10.0) -> bool:
    """Mesmo provedor (CallMeBot) e mesma lógica do FlowGuard (flowguard/notifier.py) —
    duplicado aqui de propósito, os dois projetos são deliberadamente independentes."""
    if not phone or not apikey or not message:
        return False
    params = urllib.parse.urlencode({"phone": phone, "text": message, "apikey": apikey})
    url = f"{CALLMEBOT_URL}?{params}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp.read()
        return True
    except (URLError, OSError, ValueError):
        LOG.exception("falha ao enviar alerta WhatsApp via CallMeBot")
        return False
