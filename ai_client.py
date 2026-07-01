"""Integração opcional com a API da Anthropic: explicação em linguagem natural pra
cada sinal suspeito novo (mesmo padrão do FlowGuard, ver /root/flowguard/ai/client.py,
adaptado pro daemon do ClientGuard, que roda em threads em vez de asyncio — client
síncrono, sem async/await). Nunca deve travar a detecção: qualquer falha aqui só
significa "sem explicação desta vez", loga e segue. A key vem de um .env fora do
repo (ai.env_file no config.yaml), nunca do config.yaml ou do git."""

from __future__ import annotations

import logging
import time
from pathlib import Path

LOG = logging.getLogger("clientguard.ai")

try:
    import anthropic
except ImportError:
    anthropic = None

SIGNAL_LABELS = {
    "port_scan_horizontal": "varredura horizontal de portas (reconhecimento em vários hosts)",
    "port_scan_vertical": "varredura vertical de portas (busca de vulnerabilidade em um host)",
    "amplifier_hosted": "serviço UDP hospedado no cliente sendo abusado como amplificador",
    "spam_bot": "envio de spam/e-mail em massa (host possivelmente comprometido)",
    "malicious_contact": "tráfego com IP de reputação conhecida como maliciosa (C2/malware/spam)",
    "coordinated_destination": "mesmo destino externo (fora de portas web/DNS comuns) contatado por vários "
                                "clientes ao mesmo tempo — possível C2/botnet coordenado",
    "dns_tunneling": "volume anômalo de queries DNS pequenas pro mesmo servidor externo — possível túnel "
                      "DNS/exfiltração de dados via subdomínios codificados",
}


def _load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path:
        return values
    p = Path(path)
    if not p.exists():
        return values
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


class RateLimiter:
    """Janela deslizante de 60s — evita estourar rate_limit_rpm sem sleep."""

    def __init__(self, rpm: int):
        self.rpm = rpm
        self._calls: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - 60
        self._calls = [t for t in self._calls if t > cutoff]
        if len(self._calls) >= self.rpm:
            return False
        self._calls.append(now)
        return True


class AIClient:
    def __init__(self, cfg: dict):
        cfg = cfg or {}
        self.model = cfg.get("model", "claude-haiku-4-5-20251001")
        self.min_confidence = float(cfg.get("min_confidence", 0.0))
        self._limiter = RateLimiter(int(cfg.get("rate_limit_rpm", 5)))
        self._client = None
        self.enabled = bool(cfg.get("enabled")) and anthropic is not None

        if not self.enabled:
            if bool(cfg.get("enabled")) and anthropic is None:
                LOG.warning("ai.enabled=true mas o pacote 'anthropic' não está instalado — IA desativada")
            return

        env = _load_env_file(cfg.get("env_file", ""))
        api_key = env.get("ANTHROPIC_API_KEY")
        if not api_key:
            LOG.warning("ai.enabled=true mas ANTHROPIC_API_KEY não encontrada em %s — IA desativada",
                        cfg.get("env_file"))
            self.enabled = False
            return

        self._client = anthropic.Anthropic(api_key=api_key)
        LOG.info("IA ativada (model=%s, min_confidence=%s)", self.model, self.min_confidence)

    def explain_signal(self, src_ip: str, customer_prefix: str | None, signal_type: str,
                        confidence: float, evidence: dict) -> str | None:
        if not self.enabled or confidence < self.min_confidence:
            return None
        if not self._limiter.allow():
            LOG.warning("rate limit de IA (%s rpm) atingido — pulando explicação deste sinal", self._limiter.rpm)
            return None

        evidence_str = ", ".join(f"{k}={v}" for k, v in evidence.items())
        prompt = (
            "Sinal suspeito detectado por um sistema de monitoramento de clientes de um "
            "provedor de internet (não é um sistema anti-DDoS — o objetivo aqui é identificar "
            "cliente com host comprometido, não ataques ao próprio provedor).\n"
            f"src_ip do cliente: {src_ip}\n"
            f"Rede/prefixo do cliente: {customer_prefix or 'desconhecido'}\n"
            f"Tipo de sinal: {SIGNAL_LABELS.get(signal_type, signal_type)}\n"
            f"Confiança do detector: {confidence * 100:.0f}%\n"
            f"Evidência: {evidence_str}\n\n"
            "Em português, escreva uma explicação factual de até 3 frases, direta, cobrindo: "
            "o que esse padrão de tráfego provavelmente indica sobre o host do cliente, e uma "
            "recomendação objetiva pro NOC (ex.: contatar cliente, isolar, só observar). Não "
            "invente dados que não foram fornecidos acima. Responda em texto simples (sem "
            "markdown, sem título, sem listas), só o parágrafo da explicação."
        )
        try:
            resp = self._client.messages.create(
                model=self.model, max_tokens=250,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception:
            LOG.exception("falha ao chamar IA para explicação de sinal")
            return None
