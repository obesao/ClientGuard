"""ClientGuard — detectores de esforço baixo: scan horizontal/vertical, amplificador
hospedado no cliente, spam bot, contato com IP malicioso conhecido e destino coordenado
entre clientes. Cada detector lê a janela recente de client_flow_aggs e abre/atualiza
sinais em suspicious_clients (dedup por src_ip+signal_type enquanto o sinal estiver
aberto, ver storage.get_open_signal).

db_lock é opcional e de granularidade fina: protege só as operações no banco (SELECT/
INSERT/UPDATE), nunca as chamadas de rede (IA, webhook) — do contrário, uma explicação
de IA demorada (alguns segundos) travaria consultas via CLI/portal (status, suspicious)
até terminar. Se db_lock for None (uso direto/testes), roda sem lock nenhum."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import nullcontext

import flowspec_mitigation
import notifier
import storage

LOG = logging.getLogger("clientguard.detector")


def _record_signal(conn: sqlite3.Connection, src_ip: str, customer_prefix: str | None,
                    signal_type: str, confidence: float, evidence: dict, webhook_url: str = "",
                    ai_client=None, db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None,
                    mitigation_match: dict = None) -> None:
    lock = db_lock or nullcontext()
    evidence_json = json.dumps(evidence, ensure_ascii=False)
    mitigation_ctx = mitigation_ctx or {}
    mitigation_action = mitigation_ctx.get("cfg", {}).get("auto_mitigate", {}).get(signal_type, "off")
    with lock:
        existing = storage.get_open_signal(conn, src_ip, signal_type)
        if existing:
            storage.touch_signal(conn, existing["id"], evidence_json)
            # Achado real de auditoria: se o cliente continua abusando com o
            # MESMO sinal ainda aberto, o código nunca chegava aqui de novo —
            # apply_and_record só reforça/estende uma mitigação já 'active' (nunca
            # reanuncia), então uma mitigação apagada por fora (ex: restart do
            # flowguard.service, que retira TODAS as regras ativas no shutdown —
            # ver BgpManager.withdraw_all) nunca era refeita enquanto o sinal
            # seguisse aberto: até 6h de abuso contínuo sem qualquer bloqueio
            # real, mesmo com auto_mitigate ligado. Só dispara de novo quando
            # não há mitigação ativa AGORA — não é o caminho comum (a maioria
            # dos ciclos aqui não tem nada pra fazer), só o reparo desse gap.
            if mitigation_action in ("discard", "rate_limit"):
                still_mitigated = storage.get_active_edge_mitigation(conn, src_ip) is not None
                if not still_mitigated:
                    LOG.warning("sinal %s em src_ip=%s continua aberto sem mitigação ativa — redisparando",
                                signal_type, src_ip)
                    flowspec_mitigation.trigger_async(
                        conn, db_lock, src_ip, existing["id"], signal_type, mitigation_match,
                        mitigation_ctx["cfg"], mitigation_ctx["fg_socket_path"],
                        mitigation_ctx.get("baseline_min_samples", 120),
                        mitigation_ctx.get("flowguard_path", "/root/flowguard"),
                    )
            return
        signal_id = storage.insert_suspicious_client(conn, {
            "src_ip": src_ip, "customer_prefix": customer_prefix, "signal_type": signal_type,
            "confidence": confidence, "evidence": evidence_json,
        })
    LOG.warning("sinal novo: %s src_ip=%s prefix=%s evidencia=%s",
                signal_type, src_ip, customer_prefix, evidence_json)

    if mitigation_action in ("discard", "rate_limit"):
        flowspec_mitigation.trigger_async(
            conn, db_lock, src_ip, signal_id, signal_type, mitigation_match,
            mitigation_ctx["cfg"], mitigation_ctx["fg_socket_path"],
            mitigation_ctx.get("baseline_min_samples", 120),
            mitigation_ctx.get("flowguard_path", "/root/flowguard"),
        )

    explanation = None
    if ai_client is not None:
        explanation = ai_client.explain_signal(src_ip, customer_prefix, signal_type, confidence, evidence)
        if explanation:
            with lock:
                storage.save_ai_explanation(conn, signal_id, explanation)

    if webhook_url:
        payload = {
            "signal_id": signal_id, "src_ip": src_ip, "customer_prefix": customer_prefix,
            "signal_type": signal_type, "confidence": confidence, "evidence": evidence,
            "ai_explanation": explanation, "ts_detected": int(time.time()),
        }
        if notifier.send_webhook(webhook_url, payload):
            with lock:
                storage.mark_notified(conn, signal_id)

    wa_cfg = wa_cfg or {}
    if wa_cfg.get("whatsapp") and confidence >= wa_cfg.get("min_confidence_wa", 0.8):
        message = (
            f"⚠️ ClientGuard: sinal {signal_type} em src_ip={src_ip}"
            + (f" (prefixo {customer_prefix})" if customer_prefix else "")
            + f" — confiança {confidence:.2f}"
            + (f"\n{explanation}" if explanation else "")
        )
        notifier.send_whatsapp(message)


def _scaled_threshold(base: float, customer_prefix: str | None, multipliers: dict) -> float:
    """Escala base pelo client_multiplier do prefixo (customers.yaml) — 1 IP visível de
    um pool CGNAT representa várias identidades reais combinadas, então o limiar/volume
    "normal" de 1 cliente não vale pra ele. Sem multiplicador cadastrado (a maioria dos
    prefixos), retorna base sem mudança."""
    return base * multipliers.get(customer_prefix, 1)


def _group_scaled_threshold(base: float, group_prefixes, multipliers: dict) -> float:
    """Mesma escala de _scaled_threshold, mas pra um grupo com vários clientes (ex.:
    coordinated_destination) — usa o maior multiplicador entre os participantes, já que
    basta 1 deles estar atrás de CGNAT pra o grupo poder ser só sobreposição de população
    normal, não coordenação de verdade."""
    return base * max((multipliers.get(p, 1) for p in group_prefixes), default=1)


def detect_scan_horizontal(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set,
                            exclude_ports: list[int] = (), multipliers: dict = None,
                            max_avg_bytes: float = None, webhook_url: str = "", ai_client=None,
                            db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None) -> None:
    """1 src_ip -> N dst_ip distintos, mesma dst_port -> varredura horizontal (reconhecimento).

    exclude_ports precisa cobrir portas de web/CDN (443/80) — sem isso, qualquer navegação
    normal (uma página com dezenas de IPs de borda de CDN) bate o limiar e é indistinguível
    de reconhecimento de rede de verdade.

    multipliers (customer_prefix -> fator) escala o limiar efetivo pra prefixos onde um
    único src_ip visível representa várias identidades reais combinadas (ex.: pool de
    CGNAT, onde 1 IP externo = até dezenas de clientes reais) — sem isso, o volume/
    diversidade combinado de todo mundo atrás do NAT bate o limiar pensado pra 1 cliente.
    A query usa o threshold base como piso (mais barato); o filtro fino por multiplicador
    é feito em Python, já que o fator varia por linha.

    max_avg_bytes filtra tráfego P2P/torrent (muitos hosts distintos, mas com volume real
    de dados por destino) — scan de reconhecimento de verdade manda pacotes pequenos de
    sonda, não centenas de KB por alvo. None desativa o filtro (compara qualquer volume).

    mitigation_match agora recorta a regra FlowSpec pela porta escaneada (+ protocolo,
    quando homogêneo) em vez de bloquear/limitar o cliente inteiro — ver
    flowspec_mitigation.build_rule. Sem isso, "discard" derrubava toda a conexão do
    cliente (falso positivo caro) e "rate_limit" mal freava o scan (sonda é pacote
    pequeno, não volume de banda) — as únicas duas opções ruins que existiam antes."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    query = """SELECT src_ip, customer_prefix, dst_port, protocol, COUNT(DISTINCT dst_ip) AS n_hosts,
                      SUM(bytes) AS total_bytes
               FROM client_flow_aggs WHERE ts >= ?"""
    params: list = [since]
    if exclude_ports:
        query += f" AND dst_port NOT IN ({','.join('?' * len(exclude_ports))})"
        params.extend(exclude_ports)
    query += " GROUP BY src_ip, dst_port, protocol HAVING n_hosts >= ?"
    params.append(threshold)
    with lock:
        rows = conn.execute(query, params).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        effective = _scaled_threshold(threshold, r["customer_prefix"], multipliers)
        if r["n_hosts"] < effective:
            continue
        avg_bytes = r["total_bytes"] / r["n_hosts"]
        if max_avg_bytes is not None and avg_bytes > max_avg_bytes:
            continue
        mitigation_match = {"dst_port": str(r["dst_port"])}
        proto_name = {6: "tcp", 17: "udp"}.get(r["protocol"])
        if proto_name:
            mitigation_match["protocol"] = proto_name
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "port_scan_horizontal",
                        min(1.0, r["n_hosts"] / (effective * 2)),
                        {"dst_port": r["dst_port"], "n_hosts": r["n_hosts"], "avg_bytes": round(avg_bytes),
                         "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx, mitigation_match)


def detect_scan_vertical(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set,
                          multipliers: dict = None, max_avg_bytes: float = None, webhook_url: str = "",
                          ai_client=None, db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None) -> None:
    """1 src_ip -> N dst_port distintas, mesmo dst_ip -> varredura de vulnerabilidade.

    multipliers escala o limiar pra prefixos CGNAT — ver docstring de detect_scan_horizontal.
    max_avg_bytes filtra P2P/torrent (muitas portas, mas volume real por porta) — mesmo
    raciocínio de detect_scan_horizontal.

    mitigation_match recorta a regra FlowSpec pro dst_ip vítima (dst_prefix=vítima/32),
    protocolo-agnóstico (queremos blindar a vítima de QUALQUER porta/protocolo que o
    scanner tente, não só a combinação já vista) — em vez de bloquear/limitar todo o
    tráfego do cliente pra qualquer destino. Efeito: o cliente continua acessando o
    resto da internet normalmente, só não alcança mais aquela vítima específica."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    with lock:
        rows = conn.execute(
            """SELECT src_ip, customer_prefix, dst_ip, COUNT(DISTINCT dst_port) AS n_ports,
                      SUM(bytes) AS total_bytes
               FROM client_flow_aggs WHERE ts >= ?
               GROUP BY src_ip, dst_ip HAVING n_ports >= ?""",
            (since, threshold),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        effective = _scaled_threshold(threshold, r["customer_prefix"], multipliers)
        if r["n_ports"] < effective:
            continue
        avg_bytes = r["total_bytes"] / r["n_ports"]
        if max_avg_bytes is not None and avg_bytes > max_avg_bytes:
            continue
        mitigation_match = {"dst_prefix": f"{r['dst_ip']}/32"}
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "port_scan_vertical",
                        min(1.0, r["n_ports"] / (effective * 2)),
                        {"dst_ip": r["dst_ip"], "n_ports": r["n_ports"], "avg_bytes": round(avg_bytes),
                         "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx, mitigation_match)


def detect_amplifier(conn: sqlite3.Connection, window_s: int, ports: list[int], min_bps: float,
                      whitelist: set, multipliers: dict = None, webhook_url: str = "", ai_client=None,
                      db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None) -> None:
    """src_ip do cliente respondendo (src_port em porta de serviço UDP conhecida) pra
    vários destinos externos em volume alto -> resolver/serviço aberto sendo abusado
    como refletor de amplificação.

    multipliers escala min_bps pra prefixos CGNAT — ver docstring de detect_scan_horizontal."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(ports))
    with lock:
        rows = conn.execute(
            f"""SELECT src_ip, customer_prefix, src_port, SUM(bytes) AS total_bytes,
                       COUNT(DISTINCT dst_ip) AS n_dst
                FROM client_flow_aggs WHERE ts >= ? AND protocol = 17 AND src_port IN ({placeholders})
                GROUP BY src_ip, src_port""",
            (since, *ports),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist or r["n_dst"] < 2:
            continue
        bps = (r["total_bytes"] * 8) / window_s
        effective_min_bps = _scaled_threshold(min_bps, r["customer_prefix"], multipliers)
        if bps < effective_min_bps:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "amplifier_hosted",
                        min(1.0, bps / (effective_min_bps * 4)),
                        {"src_port": r["src_port"], "bps": round(bps), "n_dst": r["n_dst"], "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx,
                        {"protocol": "udp", "src_port": str(r["src_port"])})


def detect_spam(conn: sqlite3.Connection, window_s: int, spam_ports: list[int], min_distinct_dest: int,
                 whitelist: set, multipliers: dict = None, webhook_url: str = "", ai_client=None,
                 db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None) -> None:
    """src_ip do cliente com TCP outbound em porta de e-mail (25/465/587) pra muitos
    destinos distintos -> host comprometido enviando spam.

    multipliers escala o limiar pra prefixos CGNAT — ver docstring de detect_scan_horizontal."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(spam_ports))
    with lock:
        rows = conn.execute(
            f"""SELECT src_ip, customer_prefix, COUNT(DISTINCT dst_ip) AS n_dst
                FROM client_flow_aggs WHERE ts >= ? AND protocol = 6 AND dst_port IN ({placeholders})
                GROUP BY src_ip HAVING n_dst >= ?""",
            (since, *spam_ports, min_distinct_dest),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        effective = _scaled_threshold(min_distinct_dest, r["customer_prefix"], multipliers)
        if r["n_dst"] < effective:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "spam_bot",
                        min(1.0, r["n_dst"] / (effective * 2)),
                        {"n_dst": r["n_dst"], "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx)


def detect_malicious_contact(conn: sqlite3.Connection, window_s: int, threat_feed, whitelist: set,
                              webhook_url: str = "", ai_client=None, db_lock=None, wa_cfg: dict = None,
                              mitigation_ctx: dict = None) -> None:
    """src_ip do cliente troca tráfego com um dst_ip conhecido de C2/malware/spam (feed
    público: Feodo Tracker, Spamhaus DROP/EDROP, ipsum) -> host possivelmente comprometido.
    Detecção por reputação, não por volume/padrão como os outros detectores."""
    if threat_feed is None:
        return
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    with lock:
        dst_rows = conn.execute("SELECT DISTINCT dst_ip FROM client_flow_aggs WHERE ts >= ?", (since,)).fetchall()
    bad_ips = [r["dst_ip"] for r in dst_rows if threat_feed.is_malicious(r["dst_ip"])]
    if not bad_ips:
        return
    placeholders = ",".join("?" * len(bad_ips))
    with lock:
        rows = conn.execute(
            f"""SELECT DISTINCT src_ip, customer_prefix, dst_ip FROM client_flow_aggs
                WHERE ts >= ? AND dst_ip IN ({placeholders})""",
            (since, *bad_ips),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "malicious_contact", 0.9,
                        {"dst_ip": r["dst_ip"], "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx)


def detect_shared_destination(conn: sqlite3.Connection, window_s: int, min_distinct_clients: int,
                               exclude_ports: list[int], whitelist: set, multipliers: dict = None,
                               webhook_url: str = "", ai_client=None, db_lock=None, wa_cfg: dict = None,
                               mitigation_ctx: dict = None) -> None:
    """N clientes distintos (>= min_distinct_clients) falando com o MESMO dst_ip:dst_port
    fora das portas web/DNS comuns (exclude_ports, tráfego normal de internet faz isso o
    tempo todo em CDN/HTTPS/DNS) -> indício de C2/botnet coordenado atingindo vários
    clientes ao mesmo tempo. Diferente dos outros detectores, que olham 1 src_ip por vez,
    este correlaciona entre clientes.

    multipliers (customer_prefix -> fator) eleva o limiar do grupo inteiro quando qualquer
    cliente envolvido está atrás de CGNAT — um punhado de IPs visíveis de um pool CGNAT
    convergindo pra um destino popular não é o mesmo indício de coordenação que o mesmo
    número de clientes com IP próprio, já que cada IP do pool já é várias identidades reais
    combinadas. A query usa min_distinct_clients como piso; o limiar efetivo por grupo é
    recalculado em Python depois de saber quais clientes participaram."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(exclude_ports))
    with lock:
        groups = conn.execute(
            f"""SELECT dst_ip, dst_port, COUNT(DISTINCT src_ip) AS n_clients
                FROM client_flow_aggs WHERE ts >= ? AND dst_port NOT IN ({placeholders})
                GROUP BY dst_ip, dst_port HAVING n_clients >= ?""",
            (since, *exclude_ports, min_distinct_clients),
        ).fetchall()
    for g in groups:
        with lock:
            clients = conn.execute(
                """SELECT DISTINCT src_ip, customer_prefix FROM client_flow_aggs
                   WHERE ts >= ? AND dst_ip = ? AND dst_port = ?""",
                (since, g["dst_ip"], g["dst_port"]),
            ).fetchall()
        effective = _group_scaled_threshold(min_distinct_clients, (c["customer_prefix"] for c in clients),
                                             multipliers)
        if g["n_clients"] < effective:
            continue
        client_ips = [c["src_ip"] for c in clients]
        for c in clients:
            if c["src_ip"] in whitelist:
                continue
            _record_signal(conn, c["src_ip"], c["customer_prefix"], "coordinated_destination",
                            min(1.0, g["n_clients"] / (effective * 2)),
                            {"dst_ip": g["dst_ip"], "dst_port": g["dst_port"], "n_clients": g["n_clients"],
                             "other_clients": [ip for ip in client_ips if ip != c["src_ip"]][:10],
                             "window_s": window_s},
                            webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx)


def detect_dns_tunneling(conn: sqlite3.Connection, window_s: int, min_queries: int, whitelist: set,
                          multipliers: dict = None, webhook_url: str = "", ai_client=None,
                          db_lock=None, wa_cfg: dict = None, mitigation_ctx: dict = None) -> None:
    """src_ip do cliente faz um volume alto de queries DNS (muitos pacotes pequenos, não
    poucos grandes — diferente do amplifier_hosted, que é sobre volume de RESPOSTA) pro
    MESMO servidor externo -> indício de túnel DNS/exfiltração via subdomínios codificados,
    não uso normal de navegação (que gera dezenas de queries por janela, não centenas).

    multipliers escala o limiar pra prefixos CGNAT — ver docstring de detect_scan_horizontal.
    Volume de DNS combinado de várias pessoas atrás do mesmo IP visível pode passar do
    limiar pensado pra 1 cliente sem que ninguém esteja de fato tunelando (distinguível de
    túnel real pelo avg_pkt_bytes: normal fica pequeno, tunelamento estufa o pacote).

    mitigation_match já recortava por protocol=udp/dst_port=53 (não limitava banda
    geral do cliente), mas faltava o dst_ip: sem isso o rate-limit valia pra QUALQUER
    resolver, inclusive os legítimos que o cliente também usa. Adicionado dst_prefix
    do resolver suspeito — agora só a consulta àquele destino específico é limitada."""
    multipliers = multipliers or {}
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    with lock:
        rows = conn.execute(
            """SELECT src_ip, customer_prefix, dst_ip, SUM(packets) AS n_queries, SUM(bytes) AS total_bytes
               FROM client_flow_aggs WHERE ts >= ? AND protocol = 17 AND dst_port = 53
               GROUP BY src_ip, dst_ip HAVING n_queries >= ?""",
            (since, min_queries),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        effective = _scaled_threshold(min_queries, r["customer_prefix"], multipliers)
        if r["n_queries"] < effective:
            continue
        avg_pkt_bytes = round(r["total_bytes"] / r["n_queries"]) if r["n_queries"] else 0
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "dns_tunneling",
                        min(1.0, r["n_queries"] / (effective * 2)),
                        {"dst_ip": r["dst_ip"], "n_queries": r["n_queries"], "avg_pkt_bytes": avg_pkt_bytes,
                         "window_s": window_s},
                        webhook_url, ai_client, db_lock, wa_cfg, mitigation_ctx,
                        {"protocol": "udp", "dst_port": "53", "dst_prefix": f"{r['dst_ip']}/32"})


def run_all(conn: sqlite3.Connection, config: dict, whitelist: set, customers: list[dict] = (),
            ai_client=None, threat_feed=None, db_lock=None, toggles: dict = None,
            mitigation_cfg: dict = None) -> None:
    """toggles (ver configio.DEFAULT_FEATURE_TOGGLES) liga/desliga cada detector
    individualmente, e ai_explanations liga/desliga a explicação de IA pra qualquer
    sinal que dispare nesse ciclo — chave ausente = habilitado, pra não mudar
    comportamento de quem nunca configurou toggles.yaml.

    mitigation_cfg (ver flowspec_mitigation.DEFAULT_CONFIG) liga o gatilho automático
    de mitigação via BGP FlowSpec por tipo de sinal (discard/rate_limit/off) — None
    desativa completamente (nenhum detector dispara mitigação sozinho, só o botão
    manual do portal/CLI funciona). Substitui o antigo edge_cfg (SSH/ACL) como
    caminho de auto-mitigação; edge_mitigation.py continua existindo só pra reverter
    mitigações SSH já ativas de antes desta migração."""
    toggles = toggles or {}

    def on(key: str) -> bool:
        return toggles.get(key, True)

    det = config["detection"]
    alerts_cfg = config.get("alerts", {})
    webhook_url = alerts_cfg.get("webhook_url", "")
    wa_cfg = alerts_cfg
    mitigation_ctx = None
    if mitigation_cfg:
        mitigation_ctx = {
            "cfg": mitigation_cfg,
            "fg_socket_path": config.get("flowguard_socket", "/var/run/flowguard.sock"),
            "baseline_min_samples": config.get("dns_baseline", {}).get("min_samples", 120),
            "flowguard_path": config.get("flowguard_reuse", {}).get("path", "/root/flowguard"),
        }
    # customer_prefix -> fator: quantas identidades reais um único src_ip visível daquele
    # prefixo pode representar (ex.: pool de CGNAT). Default implícito é 1 (sem ajuste).
    multipliers = {c["prefix"]: c["client_multiplier"] for c in customers
                   if c.get("prefix") and c.get("client_multiplier")}
    max_avg_bytes = det.get("scan_max_avg_bytes")
    ai = ai_client if on("ai_explanations") else None
    if on("scan_horizontal"):
        detect_scan_horizontal(conn, det["window_s"], det["scan_horizontal_hosts"], whitelist,
                                det["common_service_ports"], multipliers, max_avg_bytes,
                                webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("scan_vertical"):
        detect_scan_vertical(conn, det["window_s"], det["scan_vertical_ports"], whitelist,
                              multipliers, max_avg_bytes, webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("amplifier"):
        detect_amplifier(conn, det["window_s"], det["amplifier_ports"], det["amplifier_min_bps"], whitelist,
                          multipliers, webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("spam"):
        detect_spam(conn, det["window_s"], det["spam_ports"], det["spam_min_distinct_dest"], whitelist,
                    multipliers, webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("malicious_contact"):
        detect_malicious_contact(conn, det["window_s"], threat_feed, whitelist,
                                  webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("coordinated_destination"):
        detect_shared_destination(conn, det["window_s"], det["coordinated_min_clients"],
                                   det["common_service_ports"], whitelist, multipliers,
                                   webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
    if on("dns_tunneling"):
        detect_dns_tunneling(conn, det["window_s"], det["dns_tunneling_min_queries"], whitelist,
                              multipliers, webhook_url, ai, db_lock, wa_cfg, mitigation_ctx)
