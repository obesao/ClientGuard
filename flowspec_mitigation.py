"""flowspec_mitigation — mitigação de cliente abusivo via BGP FlowSpec, substitui
edge_mitigation.py (SSH/ACL direto no roteador).

ClientGuard não fala BGP nem tem ExaBGP próprio — só existe UMA sessão com o
roteador, do FlowGuard. Isto é um proxy fino pro socket de controle dele (mesmo
caminho já usado por socket_server._cmd_block_add, o bloqueio manual): manda
{"cmd": "flowspec_add", "rule": {...}, "origin": "clientguard"}, que aciona
BgpManager.flowspec_add -> bgp/speaker.py -> ExaBGP -> sessão BGP real com o
roteador. A regra "de verdade" (TTL, expiração) vive em flowspec_rules do banco
do FlowGuard; aqui só guardamos o suficiente (edge_mitigations.flowspec_rule_id)
pra saber qual rule_id pedir de volta na hora de reverter.

Duas ações por tipo de sinal (auto_mitigate em flowspec_mitigation.yaml):
- "discard": bloqueio total (src_prefix = cliente/32) — pros sinais sem uso
  legítimo parcial (scan, spam quando configurado assim).
- "rate_limit": limita banda em vez de bloquear — pra dns_tunneling e
  amplifier_hosted, o limite é DINÂMICO (baseline EWMA por cliente, ver
  storage.client_traffic_baseline); pra spam_bot (se configurado rate_limit),
  o limite é estático (spam_rate_limit_bps), sem baseline — volume de e-mail
  não varia "naturalmente" por cliente do jeito que DNS varia, não justifica
  a complexidade extra.
- "off": não mitiga automaticamente, só o sinal fica registrado.

edge_mitigation.py (SSH) não é apagado — continua rodando em paralelo só pra
reverter mitigações SSH já ativas de antes desta migração (ver
mechanism='ssh' vs 'flowspec' em storage.edge_mitigations).

**Bug real corrigido 2026-07-03**: o anúncio sempre ia pro peer 'main' (padrão
de BgpManager.flowspec_add quando peer não é passado) — desde que o ClientGuard
passou a capturar só via NE8000-PPPOE (config.yaml capture.bpf_filter), TODO
cliente visto por ele tem o tráfego passando por aquela caixa, não pela
NE8000BGP. Uma regra anunciada só pro peer 'main' nunca chegava no roteador
que de fato carrega o tráfego do cliente — a mitigação "aplicava" (ficava
'active' no banco) mas não tinha efeito nenhum de verdade. Corrigido
forçando peer='pppoe' neste único ponto de anúncio."""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import threading
from contextlib import nullcontext
from pathlib import Path

import yaml

import control
import storage

LOG = logging.getLogger("clientguard.flowspec_mitigation")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "flowspec_mitigation.yaml")

VALID_ACTIONS = {"discard", "rate_limit", "off"}
_SEVERITY = {"discard": 2, "rate_limit": 1}

DEFAULT_CONFIG = {
    "default_ttl_s": 3600,
    "max_active_rules": 20,       # teto PRÓPRIO do ClientGuard — deixa margem no
                                   # orçamento global do FlowGuard (mitigation.max_rules)
                                   # pra ele mitigar ataques de verdade contra prefixos
    "dns_rate_limit_floor_bps": 200_000,
    "spam_rate_limit_bps": 500_000,
    "rate_limit_sigma": 3,
    "auto_mitigate": {
        "port_scan_horizontal": "discard",
        "port_scan_vertical": "discard",
        "spam_bot": "rate_limit",
        "dns_tunneling": "rate_limit",
        "amplifier_hosted": "rate_limit",
        "malicious_contact": "off",
        "coordinated_destination": "off",
    },
}


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))  # cópia funda
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update({k: v for k, v in data.items() if k != "auto_mitigate"})
    merged["auto_mitigate"].update(data.get("auto_mitigate") or {})
    return merged


def save_auto_mitigate(changes: dict, default_ttl_s: int | None = None,
                        path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Read-modify-write atômico da ação por detector + default_ttl_s — mesmo padrão
    de edge_mitigation.save_auto_mitigate. max_active_rules só editável à mão."""
    unknown = sorted(k for k in changes if k not in DEFAULT_CONFIG["auto_mitigate"])
    if unknown:
        raise ValueError(f"detector(es) desconhecido(s): {', '.join(unknown)}")
    bad_actions = sorted(f"{k}={v}" for k, v in changes.items() if v not in VALID_ACTIONS)
    if bad_actions:
        raise ValueError(f"ação(ões) inválida(s): {', '.join(bad_actions)} (válidas: {', '.join(sorted(VALID_ACTIONS))})")
    current = load_config(path)
    current["auto_mitigate"].update(changes)
    if default_ttl_s is not None:
        current["default_ttl_s"] = int(default_ttl_s)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "# flowspec_mitigation.yaml — mitigação via BGP FlowSpec (proxy pro FlowGuard),\n"
            "# substitui o antigo edge_mitigation.py (SSH/ACL). auto_mitigate/default_ttl_s\n"
            "# editáveis pelo portal ou clientguard-cli flowspec auto set; ação por detector é\n"
            "# 'discard' (bloqueio total), 'rate_limit' (limita banda) ou 'off' (não automatiza).\n"
            "# max_active_rules/dns_rate_limit_floor_bps/spam_rate_limit_bps/rate_limit_sigma só\n"
            "# à mão aqui.\n",
        )
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


def _traffic_class_for(signal_type: str, mitigation_match: dict | None) -> str | None:
    if signal_type == "dns_tunneling":
        return "dns_query"
    if signal_type == "amplifier_hosted" and mitigation_match and mitigation_match.get("src_port"):
        return f"amplifier:{mitigation_match['src_port']}"
    return None


def _compute_rate_limit_bps(signal_type: str, src_ip: str, mitigation_match: dict | None,
                             conn: sqlite3.Connection, cfg: dict, baseline_min_samples: int) -> int:
    """allowed_bps = baseline_mean + sigma*std, se a baseline já tem amostras
    suficientes pra confiar (deixa passar o volume histórico NORMAL do cliente,
    corta só o excesso); senão cai no piso fixo (dns_rate_limit_floor_bps) — não
    barra a navegação normal só porque ainda não temos histórico desse cliente."""
    if signal_type == "spam_bot":
        return int(cfg["spam_rate_limit_bps"])
    floor_bps = int(cfg["dns_rate_limit_floor_bps"])
    traffic_class = _traffic_class_for(signal_type, mitigation_match)
    if traffic_class is None:
        return floor_bps
    baseline = storage.get_baseline_for(conn, src_ip, traffic_class)
    if not baseline or baseline["samples"] < baseline_min_samples:
        return floor_bps
    sigma = cfg.get("rate_limit_sigma", 3)
    std = math.sqrt(max(baseline["bps_var"], 0))
    return max(int(baseline["bps_mean"] + sigma * std), floor_bps)


def build_rule(signal_type: str, src_ip: str, mitigation_match: dict | None,
                conn: sqlite3.Connection, cfg: dict, baseline_min_samples: int = 120) -> dict | None:
    """Monta a regra FlowSpec pro sinal — None se a ação configurada for 'off'."""
    action = cfg["auto_mitigate"].get(signal_type, "off")
    if action not in ("discard", "rate_limit"):
        return None
    prefix = f"{src_ip}/32"
    label = f"ClientGuard auto: {signal_type}"
    match = mitigation_match or {}
    if action == "discard":
        # bug real corrigido 2026-07-03: este branch nunca usava mitigation_match —
        # inofensivo enquanto só rate_limit tinha match (amplifier/dns_tunneling),
        # mas quebrava silenciosamente o recorte por dst_port/dst_prefix assim que
        # port_scan_* passou a usar discard (regra saía sem NENHUM campo de match
        # além do src_prefix, voltando a bloquear o cliente inteiro).
        return {"src_prefix": prefix, **match, "action": "discard", "label": label}
    rate_bps = _compute_rate_limit_bps(signal_type, src_ip, mitigation_match, conn, cfg, baseline_min_samples)
    return {"src_prefix": prefix, **match, "action": f"rate-limit:{rate_bps}", "label": label}


def _action_kind(action: str) -> str:
    return "discard" if action == "discard" else "rate_limit"


def _existing_kind(row: dict) -> str:
    return "discard" if row.get("rate_limit_bps") is None else "rate_limit"


def apply_and_record(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int | None,
                      signal_type: str, mitigation_match: dict | None, ttl_s: int | None,
                      trigger_type: str, cfg: dict, fg_socket_path: str,
                      baseline_min_samples: int = 120) -> dict:
    """Idempotente por src_ip, com prioridade: se já existe mitigação FlowSpec ativa
    e a nova é IGUAL OU MENOS severa, só estende o TTL; se a nova é MAIS severa
    (discard > rate_limit), retira a antiga e anuncia a nova. Uma mitigação SSH
    legada ainda ativa pro mesmo IP não é duplicada (loga e sai) — deixa o
    edge_mitigation.py cuidar de reverter aquela."""
    lock = db_lock or nullcontext()
    rule = build_rule(signal_type, src_ip, mitigation_match, conn, cfg, baseline_min_samples)
    if rule is None:
        return {"ok": True, "skipped": "off"}

    with lock:
        existing = storage.get_active_edge_mitigation(conn, src_ip)

    new_kind = _action_kind(rule["action"])
    if existing:
        if existing["mechanism"] == "ssh":
            LOG.info("mitigação SSH legada ainda ativa para %s — não duplica via FlowSpec", src_ip)
            return {"ok": True, "skipped": "ssh_active"}
        if _SEVERITY[_existing_kind(existing)] >= _SEVERITY[new_kind]:
            with lock:
                storage.extend_edge_mitigation(conn, existing["id"], ttl_s)
            return {"ok": True, "id": existing["id"], "already_active": True}
        revert_and_record(conn, db_lock, existing["id"], fg_socket_path)

    with lock:
        active_count = storage.count_active_edge_mitigations(conn, "flowspec")
    if active_count >= cfg["max_active_rules"]:
        LOG.warning("orçamento de regras FlowSpec do ClientGuard atingido (%d/%d) — não mitigando %s",
                    active_count, cfg["max_active_rules"], src_ip)
        return {"ok": False, "error": "orçamento de regras FlowSpec atingido"}

    resp = control.send_command(fg_socket_path, {
        "cmd": "flowspec_add", "rule": rule, "ttl_s": ttl_s, "origin": "clientguard", "peer": "pppoe",
    })
    rate_limit_bps = int(rule["action"].split(":", 1)[1]) if rule["action"].startswith("rate-limit:") else None
    with lock:
        mitigation_id = storage.insert_edge_mitigation(
            conn, src_ip, signal_id, ttl_s, trigger_type,
            status="active" if resp.get("ok") else "failed",
            error=None if resp.get("ok") else resp.get("error"),
            mechanism="flowspec", flowspec_rule_id=resp.get("rule_id"),
            match_json=json.dumps(rule), rate_limit_bps=rate_limit_bps,
        )
    if not resp.get("ok"):
        return {"ok": False, "error": resp.get("error", "falha desconhecida ao anunciar FlowSpec"), "id": mitigation_id}
    return {"ok": True, "id": mitigation_id}


def revert_and_record(conn: sqlite3.Connection, db_lock, mitigation_id: int, fg_socket_path: str) -> dict:
    """"regra já está inativa" não é falha de verdade — é uma corrida legítima entre
    o TTL do lado do FlowGuard (expira e retira a regra sozinho, ver bgp/manager.py
    expire_cycle) e o TTL do lado do ClientGuard (mesmo ttl_s, mas checado no próximo
    ciclo de agregação, não no instante exato). Quando isso acontece o resultado
    desejado (regra fora do ar) já foi alcançado por quem chegou primeiro — tratar
    como sucesso evita marcar 'failed' (alarmante) numa mitigação que funcionou."""
    lock = db_lock or nullcontext()
    with lock:
        row = storage.get_edge_mitigation(conn, mitigation_id)
    if not row:
        return {"ok": False, "error": "mitigação não encontrada"}
    resp = control.send_command(fg_socket_path, {"cmd": "flowspec_del", "rule_id": row["flowspec_rule_id"]})
    already_gone = not resp.get("ok") and "já está inativa" in (resp.get("error") or "")
    with lock:
        storage.mark_edge_reverted(conn, mitigation_id, error=None if (resp.get("ok") or already_gone) else resp.get("error"))
    return resp if resp.get("ok") else ({"ok": True, "already_inactive": True} if already_gone else resp)


def expire_due(conn: sqlite3.Connection, db_lock, fg_socket_path: str) -> int:
    """Chamado periodicamente pelo loop do daemon — só processa mechanism='flowspec'
    (mitigações SSH legadas expiram por conta do edge_mitigation.expire_due)."""
    lock = db_lock or nullcontext()
    with lock:
        due = storage.list_due_edge_mitigations(conn, mechanism="flowspec")
    for row in due:
        revert_and_record(conn, db_lock, row["id"], fg_socket_path)
    return len(due)


def trigger_async(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int,
                   signal_type: str, mitigation_match: dict | None, cfg: dict,
                   fg_socket_path: str, baseline_min_samples: int = 120) -> None:
    """Dispara apply_and_record em thread separada — usado pelo gatilho automático dos
    detectores, que não pode travar o ciclo de agregação esperando o round-trip do
    socket do FlowGuard."""
    def _run() -> None:
        try:
            apply_and_record(conn, db_lock, src_ip, signal_id, signal_type, mitigation_match,
                              cfg.get("default_ttl_s"), "auto", cfg, fg_socket_path, baseline_min_samples)
        except Exception:
            LOG.exception("falha ao aplicar mitigação FlowSpec automática para %s", src_ip)

    threading.Thread(target=_run, daemon=True, name="clientguard-flowspec-auto").start()
