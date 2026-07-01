"""ClientGuard — detectores de esforço baixo: scan horizontal/vertical, amplificador
hospedado no cliente e spam bot. Cada detector lê a janela recente de
client_flow_aggs e abre/atualiza sinais em suspicious_clients (dedup por
src_ip+signal_type enquanto o sinal estiver aberto, ver storage.get_open_signal)."""

from __future__ import annotations

import json
import logging
import sqlite3
import time

import storage

LOG = logging.getLogger("clientguard.detector")


def _record_signal(conn: sqlite3.Connection, src_ip: str, customer_prefix: str | None,
                    signal_type: str, confidence: float, evidence: dict) -> None:
    evidence_json = json.dumps(evidence, ensure_ascii=False)
    existing = storage.get_open_signal(conn, src_ip, signal_type)
    if existing:
        storage.touch_signal(conn, existing["id"], evidence_json)
        return
    storage.insert_suspicious_client(conn, {
        "src_ip": src_ip, "customer_prefix": customer_prefix, "signal_type": signal_type,
        "confidence": confidence, "evidence": evidence_json,
    })
    LOG.warning("sinal novo: %s src_ip=%s prefix=%s evidencia=%s",
                signal_type, src_ip, customer_prefix, evidence_json)


def detect_scan_horizontal(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set) -> None:
    """1 src_ip -> N dst_ip distintos, mesma dst_port -> varredura horizontal (reconhecimento)."""
    since = int(time.time()) - window_s
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
                        {"dst_port": r["dst_port"], "n_hosts": r["n_hosts"], "window_s": window_s})


def detect_scan_vertical(conn: sqlite3.Connection, window_s: int, threshold: int, whitelist: set) -> None:
    """1 src_ip -> N dst_port distintas, mesmo dst_ip -> varredura de vulnerabilidade."""
    since = int(time.time()) - window_s
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
                        {"dst_ip": r["dst_ip"], "n_ports": r["n_ports"], "window_s": window_s})


def detect_amplifier(conn: sqlite3.Connection, window_s: int, ports: list[int], min_bps: float,
                      whitelist: set) -> None:
    """src_ip do cliente respondendo (src_port em porta de serviço UDP conhecida) pra
    vários destinos externos em volume alto -> resolver/serviço aberto sendo abusado
    como refletor de amplificação."""
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(ports))
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
                        {"src_port": r["src_port"], "bps": round(bps), "n_dst": r["n_dst"], "window_s": window_s})


def detect_spam(conn: sqlite3.Connection, window_s: int, spam_ports: list[int], min_distinct_dest: int,
                 whitelist: set) -> None:
    """src_ip do cliente com TCP outbound em porta de e-mail (25/465/587) pra muitos
    destinos distintos -> host comprometido enviando spam."""
    since = int(time.time()) - window_s
    placeholders = ",".join("?" * len(spam_ports))
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
                        {"n_dst": r["n_dst"], "window_s": window_s})


def run_all(conn: sqlite3.Connection, config: dict, whitelist: set) -> None:
    det = config["detection"]
    detect_scan_horizontal(conn, det["window_s"], det["scan_horizontal_hosts"], whitelist)
    detect_scan_vertical(conn, det["window_s"], det["scan_vertical_ports"], whitelist)
    detect_amplifier(conn, det["window_s"], det["amplifier_ports"], det["amplifier_min_bps"], whitelist)
    detect_spam(conn, det["window_s"], det["spam_ports"], det["spam_min_distinct_dest"], whitelist)
