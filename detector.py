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

import notifier
import storage

LOG = logging.getLogger("clientguard.detector")


def _record_signal(conn: sqlite3.Connection, src_ip: str, customer_prefix: str | None,
                    signal_type: str, confidence: float, evidence: dict, webhook_url: str = "",
                    ai_client=None, db_lock=None) -> None:
    lock = db_lock or nullcontext()
    evidence_json = json.dumps(evidence, ensure_ascii=False)
    with lock:
        existing = storage.get_open_signal(conn, src_ip, signal_type)
        if existing:
            storage.touch_signal(conn, existing["id"], evidence_json)
            return
        signal_id = storage.insert_suspicious_client(conn, {
            "src_ip": src_ip, "customer_prefix": customer_prefix, "signal_type": signal_type,
            "confidence": confidence, "evidence": evidence_json,
        })
    LOG.warning("sinal novo: %s src_ip=%s prefix=%s evidencia=%s",
                signal_type, src_ip, customer_prefix, evidence_json)

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


def detect_scan_horizontal(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set,
                            webhook_url: str = "", ai_client=None, db_lock=None) -> None:
    """1 src_ip -> N dst_ip distintos, mesma dst_port -> varredura horizontal (reconhecimento)."""
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    with lock:
        rows = conn.execute(
            """SELECT src_ip, customer_prefix, dst_port, COUNT(DISTINCT dst_ip) AS n_hosts
               FROM client_flow_aggs WHERE ts >= ?
               GROUP BY src_ip, dst_port HAVING n_hosts >= ?""",
            (since, threshold),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "port_scan_horizontal",
                        min(1.0, r["n_hosts"] / (threshold * 2)),
                        {"dst_port": r["dst_port"], "n_hosts": r["n_hosts"], "window_s": window_s},
                        webhook_url, ai_client, db_lock)


def detect_scan_vertical(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set,
                          webhook_url: str = "", ai_client=None, db_lock=None) -> None:
    """1 src_ip -> N dst_port distintas, mesmo dst_ip -> varredura de vulnerabilidade."""
    lock = db_lock or nullcontext()
    since = int(time.time()) - window_s
    with lock:
        rows = conn.execute(
            """SELECT src_ip, customer_prefix, dst_ip, COUNT(DISTINCT dst_port) AS n_ports
               FROM client_flow_aggs WHERE ts >= ?
               GROUP BY src_ip, dst_ip HAVING n_ports >= ?""",
            (since, threshold),
        ).fetchall()
    for r in rows:
        if r["src_ip"] in whitelist:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "port_scan_vertical",
                        min(1.0, r["n_ports"] / (threshold * 2)),
                        {"dst_ip": r["dst_ip"], "n_ports": r["n_ports"], "window_s": window_s},
                        webhook_url, ai_client, db_lock)


def detect_amplifier(conn: sqlite3.Connection, window_s: int, ports: list[int], min_bps: float,
                      whitelist: set, webhook_url: str = "", ai_client=None, db_lock=None) -> None:
    """src_ip do cliente respondendo (src_port em porta de serviço UDP conhecida) pra
    vários destinos externos em volume alto -> resolver/serviço aberto sendo abusado
    como refletor de amplificação."""
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
        if bps < min_bps:
            continue
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "amplifier_hosted",
                        min(1.0, bps / (min_bps * 4)),
                        {"src_port": r["src_port"], "bps": round(bps), "n_dst": r["n_dst"], "window_s": window_s},
                        webhook_url, ai_client, db_lock)


def detect_spam(conn: sqlite3.Connection, window_s: int, spam_ports: list[int], min_distinct_dest: int,
                 whitelist: set, webhook_url: str = "", ai_client=None, db_lock=None) -> None:
    """src_ip do cliente com TCP outbound em porta de e-mail (25/465/587) pra muitos
    destinos distintos -> host comprometido enviando spam."""
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
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "spam_bot",
                        min(1.0, r["n_dst"] / (min_distinct_dest * 2)),
                        {"n_dst": r["n_dst"], "window_s": window_s}, webhook_url, ai_client, db_lock)


def detect_malicious_contact(conn: sqlite3.Connection, window_s: int, threat_feed, whitelist: set,
                              webhook_url: str = "", ai_client=None, db_lock=None) -> None:
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
                        {"dst_ip": r["dst_ip"], "window_s": window_s}, webhook_url, ai_client, db_lock)


def detect_shared_destination(conn: sqlite3.Connection, window_s: int, min_distinct_clients: int,
                               exclude_ports: list[int], whitelist: set, webhook_url: str = "",
                               ai_client=None, db_lock=None) -> None:
    """N clientes distintos (>= min_distinct_clients) falando com o MESMO dst_ip:dst_port
    fora das portas web/DNS comuns (exclude_ports, tráfego normal de internet faz isso o
    tempo todo em CDN/HTTPS/DNS) -> indício de C2/botnet coordenado atingindo vários
    clientes ao mesmo tempo. Diferente dos outros detectores, que olham 1 src_ip por vez,
    este correlaciona entre clientes."""
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
        client_ips = [c["src_ip"] for c in clients]
        for c in clients:
            if c["src_ip"] in whitelist:
                continue
            _record_signal(conn, c["src_ip"], c["customer_prefix"], "coordinated_destination",
                            min(1.0, g["n_clients"] / (min_distinct_clients * 2)),
                            {"dst_ip": g["dst_ip"], "dst_port": g["dst_port"], "n_clients": g["n_clients"],
                             "other_clients": [ip for ip in client_ips if ip != c["src_ip"]][:10],
                             "window_s": window_s},
                            webhook_url, ai_client, db_lock)


def detect_dns_tunneling(conn: sqlite3.Connection, window_s: int, min_queries: int, whitelist: set,
                          webhook_url: str = "", ai_client=None, db_lock=None) -> None:
    """src_ip do cliente faz um volume alto de queries DNS (muitos pacotes pequenos, não
    poucos grandes — diferente do amplifier_hosted, que é sobre volume de RESPOSTA) pro
    MESMO servidor externo -> indício de túnel DNS/exfiltração via subdomínios codificados,
    não uso normal de navegação (que gera dezenas de queries por janela, não centenas)."""
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
        avg_pkt_bytes = round(r["total_bytes"] / r["n_queries"]) if r["n_queries"] else 0
        _record_signal(conn, r["src_ip"], r["customer_prefix"], "dns_tunneling",
                        min(1.0, r["n_queries"] / (min_queries * 2)),
                        {"dst_ip": r["dst_ip"], "n_queries": r["n_queries"], "avg_pkt_bytes": avg_pkt_bytes,
                         "window_s": window_s},
                        webhook_url, ai_client, db_lock)


def run_all(conn: sqlite3.Connection, config: dict, whitelist: set, ai_client=None, threat_feed=None,
            db_lock=None) -> None:
    det = config["detection"]
    webhook_url = config.get("alerts", {}).get("webhook_url", "")
    detect_scan_horizontal(conn, det["window_s"], det["scan_horizontal_hosts"], whitelist,
                            webhook_url, ai_client, db_lock)
    detect_scan_vertical(conn, det["window_s"], det["scan_vertical_ports"], whitelist,
                          webhook_url, ai_client, db_lock)
    detect_amplifier(conn, det["window_s"], det["amplifier_ports"], det["amplifier_min_bps"], whitelist,
                      webhook_url, ai_client, db_lock)
    detect_spam(conn, det["window_s"], det["spam_ports"], det["spam_min_distinct_dest"], whitelist,
                webhook_url, ai_client, db_lock)
    detect_malicious_contact(conn, det["window_s"], threat_feed, whitelist, webhook_url, ai_client, db_lock)
    detect_shared_destination(conn, det["window_s"], det["coordinated_min_clients"],
                               det["coordinated_exclude_ports"], whitelist, webhook_url, ai_client, db_lock)
    detect_dns_tunneling(conn, det["window_s"], det["dns_tunneling_min_queries"], whitelist,
                          webhook_url, ai_client, db_lock)
