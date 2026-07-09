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

import ipaddress
import json
import logging
import math
import sqlite3
import threading
from contextlib import nullcontext
from pathlib import Path

import yaml

import control
import edge_mitigation
import escalation
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
    # Achado real 2026-07-03: a caixa PPPoE tem uma traffic-policy GLOBAL
    # (P-CGNAT) que redireciona todo tráfego de cliente pro A10 (CGNAT) com
    # precedência MAIOR que o filtro instalado pelo FlowSpec — confirmado com
    # captura real (cliente com regra 'discard' ativa e válida no roteador
    # continuava passando tráfego até o A10). A própria política já tem uma
    # exceção pronta: o classificador C-CGNAT-BYPASS (ACL 3001), precedência
    # mais alta, com comportamento vazio (não redireciona). Quando habilitado,
    # toda vez que uma regra FlowSpec é anunciada/retirada, empurramos (via SSH,
    # reaproveitando warmode.yaml do FlowGuard) uma entrada espelhando o MESMO
    # match da regra FlowSpec nessa ACL — nunca mais amplo, pra não isentar do
    # CGNAT tráfego do cliente que a mitigação não mirava (cliente continua
    # navegando normalmente, só o tráfego já sinalizado como sujo sai do
    # redirecionamento e passa a ser filtrado pelo FlowSpec).
    "pbr_bypass": {
        "enabled": False,
        "warmode_device": "HUAWEI-PPPOE-222",
        "acl_number": 3001,
        "rule_id_base": 50000,
    },
}


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))  # cópia funda
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update({k: v for k, v in data.items() if k not in ("auto_mitigate", "pbr_bypass")})
    merged["auto_mitigate"].update(data.get("auto_mitigate") or {})
    merged["pbr_bypass"].update(data.get("pbr_bypass") or {})
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


# --- exceção na ACL de bypass do CGNAT (achado 2026-07-03) -----------------

def _cidr_to_huawei(prefix: str) -> tuple[str, str]:
    """CIDR -> (endereço, máscara-curinga) na notação de ACL avançada Huawei VRP
    — /32 vira '0' (confirmado no ACL real da caixa: 'destination 177.86.16.9 0'),
    qualquer outro prefixo vira o dotted-quad invertido (wildcard mask)."""
    net = ipaddress.ip_network(prefix, strict=False)
    if net.prefixlen == 32:
        return str(net.network_address), "0"
    return str(net.network_address), str(net.hostmask)


def _bypass_rule_clause(rule: dict, rule_id: int) -> str:
    """Traduz o MESMO match da regra FlowSpec (src_prefix/dst_prefix/protocol/
    dst_port) pra sintaxe de ACL avançada Huawei VRP — deliberadamente nunca mais
    amplo que a regra FlowSpec original: só o tráfego que a mitigação já mirava
    sai do redirecionamento pro CGNAT, o resto do cliente continua navegando
    normalmente através do A10."""
    protocol = rule.get("protocol")
    proto_kw = protocol if protocol in ("tcp", "udp") else "ip"
    src_addr, src_wild = _cidr_to_huawei(rule["src_prefix"])
    parts = [f"rule {rule_id} permit {proto_kw} source {src_addr} {src_wild}"]
    if rule.get("dst_prefix"):
        dst_addr, dst_wild = _cidr_to_huawei(rule["dst_prefix"])
        parts.append(f"destination {dst_addr} {dst_wild}")
    if rule.get("dst_port") and proto_kw in ("tcp", "udp"):
        parts.append(f"destination-port eq {rule['dst_port']}")
    return " ".join(parts)


# Serializa TODO acesso SSH à caixa PPPoE a partir daqui — achado real de revisão:
# duas mitigações disparando no mesmo ciclo (threads independentes via trigger_async)
# abriam duas sessões SSH concorrentes e faziam `commit` ao mesmo tempo no mesmo
# equipamento; no modelo de candidate-config do VRP V8 isso é uma condição de corrida
# real (um commit pode colidir com uma edição pela metade da outra sessão). Único lock
# global é aceitável aqui: só existe UM equipamento/ACL sendo tocado por este módulo,
# e cada push/remove já é uma chamada síncrona de poucos segundos.
_PBR_BYPASS_LOCK = threading.Lock()


def _pbr_bypass_ssh(action: str, rule_src_ip: str, commands_tail: list[str], bypass_cfg: dict,
                     flowguard_path: str) -> dict:
    """Reaproveita edge_mitigation._run_commands (conexão/erro já tratados lá) —
    só monta o device_cfg no formato que aquela função espera e não usa o
    placeholder {ip} (o clause já vem pronto, com tudo embutido). Serializado pelo
    lock acima, e auditado no MESMO log (edge-audit.jsonl) que qualquer outra ação
    SSH do sistema — achado real: chamar _run_commands direto (sem passar por
    apply_block/revert_block) deixava essas ações invisíveis na única trilha de
    auditoria SSH que o sistema já tinha."""
    device_cfg = {"warmode_device": bypass_cfg["warmode_device"], "acl_number": bypass_cfg["acl_number"]}
    templates = ["acl number {acl_number}", *commands_tail, "quit", "commit"]
    # timeout menor que o da CGI do portal (25s) — margem pra CGI não estourar
    # timeout bem na hora em que o SSH estaria terminando com sucesso.
    with _PBR_BYPASS_LOCK:
        result = edge_mitigation._run_commands("", device_cfg, flowguard_path, templates, timeout=20.0)
    edge_mitigation._audit(f"pbr_bypass_{action}", rule_src_ip, result)
    return result


def push_pbr_bypass(rule: dict, flowspec_rule_id: int, cfg: dict, flowguard_path: str) -> dict:
    bypass_cfg = cfg.get("pbr_bypass") or {}
    if not bypass_cfg.get("enabled"):
        return {"ok": True, "skipped": "pbr_bypass_disabled"}
    # só faz sentido pra discard: pra rate_limit o tráfego é pra continuar existindo
    # (só mais devagar), e tirá-lo do redirecionamento pro A10 tira a tradução NAT do
    # IP CGNAT (100.64.0.0/10, não roteável na internet pública) — o fluxo perderia
    # conectividade por completo em vez de só ser limitado, violando a exigência do
    # usuário de que o cliente continue navegando.
    if _action_kind(rule["action"]) != "discard":
        return {"ok": True, "skipped": "pbr_bypass_only_for_discard"}
    rule_id = bypass_cfg["rule_id_base"] + flowspec_rule_id
    clause = _bypass_rule_clause(rule, rule_id)
    result = _pbr_bypass_ssh("apply", rule.get("src_prefix", ""), [clause], bypass_cfg, flowguard_path)
    if not result.get("ok"):
        LOG.error("falha ao empurrar exceção de PBR (ACL %s regra %s) pra %s: %s",
                   bypass_cfg["acl_number"], rule_id, bypass_cfg["warmode_device"], result.get("error"))
    return result


def remove_pbr_bypass(flowspec_rule_id: int, src_ip: str, cfg: dict, flowguard_path: str) -> dict:
    bypass_cfg = cfg.get("pbr_bypass") or {}
    if not bypass_cfg.get("enabled"):
        return {"ok": True, "skipped": "pbr_bypass_disabled"}
    rule_id = bypass_cfg["rule_id_base"] + flowspec_rule_id
    result = _pbr_bypass_ssh("remove", src_ip, [f"undo rule {rule_id}"], bypass_cfg, flowguard_path)
    if not result.get("ok"):
        LOG.error("falha ao remover exceção de PBR (ACL %s regra %s) de %s: %s",
                   bypass_cfg["acl_number"], rule_id, bypass_cfg["warmode_device"], result.get("error"))
    return result


def apply_and_record(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int | None,
                      signal_type: str, mitigation_match: dict | None, ttl_s: int | None,
                      trigger_type: str, cfg: dict, fg_socket_path: str,
                      baseline_min_samples: int = 120, flowguard_path: str = "/root/flowguard") -> dict:
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
        revert_and_record(conn, db_lock, existing["id"], fg_socket_path, cfg, flowguard_path)

    with lock:
        active_count = storage.count_active_edge_mitigations(conn, "flowspec")
    if active_count >= cfg["max_active_rules"]:
        LOG.warning("orçamento de regras FlowSpec do ClientGuard atingido (%d/%d) — não mitigando %s",
                    active_count, cfg["max_active_rules"], src_ip)
        return {"ok": False, "error": "orçamento de regras FlowSpec atingido"}

    resp = control.send_command(fg_socket_path, {
        "cmd": "flowspec_add", "rule": rule, "ttl_s": ttl_s, "origin": "clientguard", "peer": "pppoe",
        "trigger_type": trigger_type,
    })
    rate_limit_bps = int(rule["action"].split(":", 1)[1]) if rule["action"].startswith("rate-limit:") else None

    # Achado real de revisão: o resultado de push_pbr_bypass era descartado — se o
    # FlowSpec fosse anunciado mas o SSH da exceção de PBR falhasse, a mitigação
    # ainda assim ficava gravada/retornada como "active", recriando (numa camada
    # mais funda) o exato bug que esta versão existe pra corrigir. Agora o status
    # gravado reflete os dois passos: só é "active" de verdade se ambos deram certo.
    bypass_error = None
    if resp.get("ok"):
        rule_id = resp.get("rule_id")
        if rule_id is None:
            # nunca deveria acontecer (contrato de BgpManager.flowspec_add é sempre
            # devolver rule_id quando ok=True) — defensivo pra não estourar KeyError
            # nem seguir sem saber qual rule_id casar na exceção de PBR.
            bypass_error = "flowspec_add retornou ok sem rule_id"
        else:
            bypass_result = push_pbr_bypass(rule, rule_id, cfg, flowguard_path)
            if not bypass_result.get("ok"):
                bypass_error = bypass_result.get("error", "falha desconhecida ao aplicar exceção de PBR")

    if not resp.get("ok"):
        status, error = "failed", resp.get("error", "falha desconhecida ao anunciar FlowSpec")
    elif bypass_error:
        status, error = "failed", f"FlowSpec anunciado mas exceção de PBR falhou: {bypass_error}"
    else:
        status, error = "active", None

    with lock:
        mitigation_id = storage.insert_edge_mitigation(
            conn, src_ip, signal_id, ttl_s, trigger_type,
            status=status, error=error,
            mechanism="flowspec", flowspec_rule_id=resp.get("rule_id"),
            match_json=json.dumps(rule), rate_limit_bps=rate_limit_bps,
        )
    if status == "failed":
        return {"ok": False, "error": error, "id": mitigation_id}
    return {"ok": True, "id": mitigation_id}


def revert_and_record(conn: sqlite3.Connection, db_lock, mitigation_id: int, fg_socket_path: str,
                       cfg: dict | None = None, flowguard_path: str = "/root/flowguard") -> dict:
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
    truly_reverted = resp.get("ok") or already_gone

    # Achado real de revisão: antes disso, a exceção de PBR era removida mesmo
    # quando o flowspec_del falhava DE VERDADE (não só a corrida "já está
    # inativa") — a regra FlowSpec continuava ativa protegendo, mas o bypass
    # sumia, e o tráfego voltava a ser redirecionado pro A10 antes do FlowSpec
    # (ainda ativo) ter qualquer chance de agir. Só remove o bypass quando o
    # FlowSpec de fato saiu do ar — e o resultado da remoção agora é refletido
    # no erro gravado, em vez de descartado silenciosamente.
    bypass_error = None
    if truly_reverted and cfg is not None and row.get("flowspec_rule_id") is not None:
        bypass_result = remove_pbr_bypass(row["flowspec_rule_id"], row["src_ip"], cfg, flowguard_path)
        if not bypass_result.get("ok") and not bypass_result.get("skipped"):
            bypass_error = bypass_result.get("error", "falha desconhecida ao remover exceção de PBR")

    if not truly_reverted:
        final_error = resp.get("error")
    elif bypass_error:
        final_error = f"FlowSpec revertido mas exceção de PBR não foi removida: {bypass_error}"
    else:
        final_error = None
    with lock:
        storage.mark_edge_reverted(conn, mitigation_id, error=final_error)

    if not truly_reverted:
        return resp
    if bypass_error:
        return {"ok": False, "error": final_error, "flowspec_reverted": True}
    return {"ok": True, "already_inactive": True} if already_gone else resp


# IDs de edge_mitigations com um revert_and_record em andamento (thread própria,
# ver _revert_async) — evita disparar uma 2ª/3ª reversão pro MESMO id quando ele
# ainda aparece 'active' num ciclo seguinte só porque a reversão anterior (pode
# envolver SSH síncrono de vários segundos pra remover a exceção de PBR, serializado
# por equipamento — ver push_pbr_bypass) ainda não terminou. Achado real: numa
# reconciliação de 19 mitigações de uma vez, sem essa guarda o mesmo id era
# redisparado a cada ciclo de 30s até a reversão original finalmente terminar,
# multiplicando conexões SSH redundantes no roteador pro mesmo trabalho.
_reverting_lock = threading.Lock()
_reverting_ids: set[int] = set()


def _revert_async(conn: sqlite3.Connection, db_lock, mitigation_id: int, fg_socket_path: str,
                   cfg: dict | None, flowguard_path: str, thread_name: str, log_context: str) -> bool:
    """Dispara revert_and_record em thread própria, só se não houver uma reversão
    já em andamento pro mesmo id. Retorna True se disparou, False se pulou (já em
    andamento) — quem chama usa isso pra não contar o mesmo id duas vezes."""
    with _reverting_lock:
        if mitigation_id in _reverting_ids:
            return False
        _reverting_ids.add(mitigation_id)

    def _run() -> None:
        try:
            revert_and_record(conn, db_lock, mitigation_id, fg_socket_path, cfg, flowguard_path)
        except Exception:
            LOG.exception("falha ao reverter (%s) mitigação FlowSpec id=%s", log_context, mitigation_id)
        finally:
            with _reverting_lock:
                _reverting_ids.discard(mitigation_id)

    threading.Thread(target=_run, daemon=True, name=thread_name).start()
    return True


def expire_due(conn: sqlite3.Connection, db_lock, fg_socket_path: str, cfg: dict | None = None,
                flowguard_path: str = "/root/flowguard") -> int:
    """Chamado periodicamente pelo loop do daemon — só processa mechanism='flowspec'
    (mitigações SSH legadas expiram por conta do edge_mitigation.expire_due).

    Achado real de revisão: revert_and_record agora pode envolver uma sessão SSH
    síncrona (remove_pbr_bypass) de vários segundos — rodar isso serialmente na
    MESMA thread que agrega NetFlow a cada ciclo arriscava atrasar (ou até
    estourar a fila interna de captura) o próximo ciclo se várias mitigações
    expirassem juntas. Cada reversão agora roda numa thread própria (mesmo padrão
    fire-and-forget de trigger_async); a contagem retornada continua sendo
    "quantas estavam due", só o trabalho de revert deixou de bloquear o chamador."""
    lock = db_lock or nullcontext()
    with lock:
        due = storage.list_due_edge_mitigations(conn, mechanism="flowspec")
    dispatched = 0
    for row in due:
        if _revert_async(conn, db_lock, row["id"], fg_socket_path, cfg, flowguard_path,
                          "clientguard-flowspec-expire", "TTL vencido"):
            dispatched += 1
    return dispatched


def reconcile_with_flowguard(conn: sqlite3.Connection, db_lock, fg_socket_path: str,
                              cfg: dict | None = None, flowguard_path: str = "/root/flowguard") -> int:
    """Achado real de auditoria (2026-07-04): flowguard.service reiniciar retira
    TODAS as regras FlowSpec/RTBH ativas da borda no shutdown gracioso
    (BgpManager.withdraw_all) — sem avisar o ClientGuard. A mitigação segue
    marcada 'active' aqui até seu próprio TTL local vencer (default_ttl_s, até
    6h), fazendo o operador achar que um cliente abusivo está bloqueado quando
    NADA está sendo filtrado na borda. Pior: apply_and_record só estende o TTL
    local pra uma mitigação "já ativa" (nunca reanuncia), e um sinal que
    continua aberto nunca re-dispara mitigação (ver detector._record_signal) —
    sem isso, o gap não se autocorrige nem quando o cliente continua abusando.
    Confirmado em produção: 20 mitigações sobreviveram a 2 restarts do
    flowguard.service nesta sessão, 32 sinais de scan continuavam abertos pros
    mesmos IPs, alguns escaneando na hora exata da auditoria.

    Roda a cada ciclo de agregação (só faz round-trip ao FlowGuard se houver
    pelo menos 1 mitigação flowspec 'active' aqui). Reaproveita
    revert_and_record pra cada mitigação órfã encontrada — ele já trata "regra
    já está inativa" como sucesso (não é falha, é uma corrida entre os dois
    TTLs) e já cuida de limpar a exceção de PBR associada, mesma lógica usada
    pela expiração normal por TTL; cada revert roda em thread própria pelo
    mesmo motivo de expire_due (pode envolver SSH síncrono de vários segundos)."""
    lock = db_lock or nullcontext()
    with lock:
        active_local = [r for r in storage.list_edge_mitigations(conn, active_only=True)
                         if r["mechanism"] == "flowspec"]
    if not active_local:
        return 0

    resp = control.send_command(fg_socket_path, {"cmd": "rules"})
    if not resp.get("ok"):
        LOG.error("reconciliação flowspec: falha ao consultar regras ativas do FlowGuard: %s", resp.get("error"))
        return 0
    active_fg_ids = {r["id"] for r in resp.get("rules", [])}

    stale = [r for r in active_local if r["flowspec_rule_id"] not in active_fg_ids]
    dispatched = 0
    for row in stale:
        if _revert_async(conn, db_lock, row["id"], fg_socket_path, cfg, flowguard_path,
                          "clientguard-flowspec-reconcile", "reconciliação"):
            LOG.warning(
                "reconciliação: mitigação id=%s (src_ip=%s, flowspec_rule_id=%s) estava 'active' aqui mas "
                "já não existe no FlowGuard — revertendo localmente pra refletir a realidade",
                row["id"], row["src_ip"], row["flowspec_rule_id"],
            )
            dispatched += 1
    return dispatched


# src_ip com um apply_and_record em andamento (thread própria) — mesmo motivo de
# _reverting_ids: push_pbr_bypass serializa SSH por equipamento (lock global), então
# sob carga (muitos gatilhos de uma vez, ex. reconciliação em massa) o tempo entre
# "FlowSpec anunciado" e "linha gravada em edge_mitigations" pode passar de um ciclo
# de detecção inteiro. Achado real: sem essa guarda, o redisparo em sinal contínuo
# (ver detector._record_signal) via get_active_edge_mitigation não encontrava nada
# ainda (insert pendente) e disparava OUTRO apply_and_record pro MESMO src_ip a cada
# ciclo de 30s — 6 regras FlowSpec duplicadas pro mesmo cliente/vítima em produção
# antes dessa guarda existir.
_applying_lock = threading.Lock()
_applying_src_ips: set[str] = set()


def trigger_async(conn: sqlite3.Connection, db_lock, src_ip: str, signal_id: int,
                   signal_type: str, mitigation_match: dict | None, cfg: dict,
                   fg_socket_path: str, baseline_min_samples: int = 120,
                   flowguard_path: str = "/root/flowguard", escalation_cfg: dict | None = None) -> None:
    """Dispara apply_and_record em thread separada — usado pelo gatilho automático dos
    detectores, que não pode travar o ciclo de agregação esperando o round-trip do
    socket do FlowGuard. Não duplica se já houver uma aplicação em andamento pro
    mesmo src_ip (ver _applying_src_ips).

    escalation_cfg (ver escalation.py) faz a duração do bloqueio crescer com
    reincidência do MESMO src_ip — None (ou ausente) mantém o comportamento antigo
    (sempre cfg["default_ttl_s"] fixo). Só afeta o gatilho AUTOMÁTICO; a rota
    manual (socket_server._cmd_block_add -> edge_mitigation.apply_and_record) não
    passa por aqui e continua com TTL escolhido pelo operador."""
    with _applying_lock:
        if src_ip in _applying_src_ips:
            return
        _applying_src_ips.add(src_ip)

    def _run() -> None:
        try:
            if escalation_cfg is not None:
                lock = db_lock or nullcontext()
                with lock:
                    ttl_s = escalation.next_ttl_s(conn, src_ip, escalation_cfg, base_ttl_s=cfg.get("default_ttl_s"))
            else:
                ttl_s = cfg.get("default_ttl_s")
            apply_and_record(conn, db_lock, src_ip, signal_id, signal_type, mitigation_match,
                              ttl_s, "auto", cfg, fg_socket_path,
                              baseline_min_samples, flowguard_path)
        except Exception:
            LOG.exception("falha ao aplicar mitigação FlowSpec automática para %s", src_ip)
        finally:
            with _applying_lock:
                _applying_src_ips.discard(src_ip)

    threading.Thread(target=_run, daemon=True, name="clientguard-flowspec-auto").start()
