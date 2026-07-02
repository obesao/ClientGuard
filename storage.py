"""Camada de acesso ao SQLite do ClientGuard — schema e operações próprias,
independentes do FlowGuard (banco separado, /root/clientguard/db/)."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS client_flow_aggs (
  id              INTEGER PRIMARY KEY,
  ts              INTEGER NOT NULL,
  src_ip          TEXT NOT NULL,
  customer_prefix TEXT,
  src_port        INTEGER NOT NULL DEFAULT 0,
  dst_ip          TEXT NOT NULL,
  dst_port        INTEGER NOT NULL,
  protocol        INTEGER NOT NULL,
  bytes           INTEGER NOT NULL,
  packets         INTEGER NOT NULL,
  dst_asn         INTEGER,
  dst_country     TEXT
);

CREATE TABLE IF NOT EXISTS suspicious_clients (
  id              INTEGER PRIMARY KEY,
  ts_detected     INTEGER NOT NULL,
  ts_last_seen    INTEGER NOT NULL,
  src_ip          TEXT NOT NULL,
  customer_prefix TEXT,
  signal_type     TEXT NOT NULL,
  confidence      REAL,
  evidence        TEXT,
  ai_explanation  TEXT,
  notified        INTEGER DEFAULT 0,
  resolved        INTEGER DEFAULT 0
);

-- Cache persistente de geoip.GeoIPCache — ASN/país de um IP não muda em escala de
-- horas, então persistir evita reconsultar a Team Cymru pra todo IP já visto a cada
-- restart do daemon (antes, o cache era só em memória e se perdia no restart).
CREATE TABLE IF NOT EXISTS geoip_cache (
  ip      TEXT PRIMARY KEY,
  asn     INTEGER,
  country TEXT,
  ts      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_flow_ts ON client_flow_aggs(ts);
CREATE INDEX IF NOT EXISTS idx_client_flow_src ON client_flow_aggs(src_ip, ts);
-- dst_ip líder: serve tanto o lookup exato (dst_ip, dst_port) do detect_shared_destination
-- quanto o "dst_ip IN (...)" do detect_malicious_contact — sem isso, os dois caem pro
-- índice de ts e filtram dst_ip linha a linha, o que piora conforme os 7 dias de
-- retenção acumulam (ver EXPLAIN QUERY PLAN antes desta mudança: USE TEMP B-TREE FOR
-- DISTINCT sobre o resultado de uma SEARCH por ts, não por dst_ip).
CREATE INDEX IF NOT EXISTS idx_client_flow_dst ON client_flow_aggs(dst_ip, dst_port, ts);
CREATE INDEX IF NOT EXISTS idx_suspicious_open ON suspicious_clients(src_ip, signal_type, resolved);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(client_flow_aggs)")}
    if "src_port" not in cols:
        conn.execute("ALTER TABLE client_flow_aggs ADD COLUMN src_port INTEGER NOT NULL DEFAULT 0")
        conn.commit()


def connect(db_path: str, check_same_thread: bool = True) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    return conn


def insert_client_flow_aggs_batch(conn: sqlite3.Connection, rows: list[dict]) -> None:
    if not rows:
        return
    conn.executemany(
        """INSERT INTO client_flow_aggs
           (ts, src_ip, customer_prefix, src_port, dst_ip, dst_port, protocol, bytes, packets, dst_asn, dst_country)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (r["ts"], r["src_ip"], r.get("customer_prefix"), r.get("src_port", 0), r["dst_ip"], r["dst_port"],
             r["protocol"], r["bytes"], r["packets"], r.get("dst_asn"), r.get("dst_country"))
            for r in rows
        ],
    )
    conn.commit()


def prune_old_aggs(conn: sqlite3.Connection, retention_days: int) -> int:
    cutoff = int(time.time()) - retention_days * 86400
    cur = conn.execute("DELETE FROM client_flow_aggs WHERE ts < ?", (cutoff,))
    conn.commit()
    conn.execute("ANALYZE")
    conn.commit()
    return cur.rowcount


def insert_suspicious_client(conn: sqlite3.Connection, row: dict) -> int:
    now = int(time.time())
    cur = conn.execute(
        """INSERT INTO suspicious_clients
           (ts_detected, ts_last_seen, src_ip, customer_prefix, signal_type, confidence, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now, now, row["src_ip"], row.get("customer_prefix"), row["signal_type"],
         row.get("confidence", 1.0), row.get("evidence", "")),
    )
    conn.commit()
    return cur.lastrowid


def get_open_signal(conn: sqlite3.Connection, src_ip: str, signal_type: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM suspicious_clients WHERE src_ip = ? AND signal_type = ? AND resolved = 0",
        (src_ip, signal_type),
    ).fetchone()
    return dict(row) if row else None


def touch_signal(conn: sqlite3.Connection, signal_id: int, evidence: str) -> None:
    conn.execute(
        "UPDATE suspicious_clients SET ts_last_seen = ?, evidence = ? WHERE id = ?",
        (int(time.time()), evidence, signal_id),
    )
    conn.commit()


def mark_notified(conn: sqlite3.Connection, signal_id: int) -> None:
    conn.execute("UPDATE suspicious_clients SET notified = 1 WHERE id = ?", (signal_id,))
    conn.commit()


def save_ai_explanation(conn: sqlite3.Connection, signal_id: int, explanation: str) -> None:
    conn.execute("UPDATE suspicious_clients SET ai_explanation = ? WHERE id = ?", (explanation, signal_id))
    conn.commit()


def list_suspicious_clients(conn: sqlite3.Connection, resolved: bool = False, since_s: int = 86400) -> list[dict]:
    cutoff = int(time.time()) - since_s
    rows = conn.execute(
        "SELECT * FROM suspicious_clients WHERE resolved = ? AND ts_detected >= ? ORDER BY ts_detected DESC",
        (1 if resolved else 0, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]


def resolve_signal(conn: sqlite3.Connection, signal_id: int) -> bool:
    cur = conn.execute(
        "UPDATE suspicious_clients SET resolved = 1 WHERE id = ? AND resolved = 0", (signal_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def clear_open_signals(conn: sqlite3.Connection) -> int:
    """Resolve TODOS os sinais abertos de uma vez (botão "Limpar hosts suspeitos" do
    portal) — marca resolved=1 em vez de apagar a linha, igual resolve_signal, pra manter
    o histórico/evidência/explicação de IA consultável na aba "Resolvidos"."""
    cur = conn.execute("UPDATE suspicious_clients SET resolved = 1 WHERE resolved = 0")
    conn.commit()
    return cur.rowcount


def top_src_ips(conn: sqlite3.Connection, window_s: int, limit: int) -> list[dict]:
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT src_ip, customer_prefix, SUM(bytes) AS bytes, SUM(packets) AS packets, COUNT(*) AS flows
           FROM client_flow_aggs WHERE ts >= ?
           GROUP BY src_ip ORDER BY bytes DESC LIMIT ?""",
        (since, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def daemon_stats(conn: sqlite3.Connection, window_s: int) -> dict:
    since = int(time.time()) - window_s
    flows_window = conn.execute(
        "SELECT COUNT(*) FROM client_flow_aggs WHERE ts >= ?", (since,),
    ).fetchone()[0]
    distinct_src_ips = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM client_flow_aggs WHERE ts >= ?", (since,),
    ).fetchone()[0]
    total_rows = conn.execute("SELECT COUNT(*) FROM client_flow_aggs").fetchone()[0]
    open_signals = conn.execute("SELECT COUNT(*) FROM suspicious_clients WHERE resolved = 0").fetchone()[0]
    return {
        "flows_window": flows_window, "distinct_src_ips": distinct_src_ips,
        "total_rows": total_rows, "open_signals": open_signals,
    }


def load_geoip_cache(conn: sqlite3.Connection) -> dict[str, tuple[int | None, str | None]]:
    rows = conn.execute("SELECT ip, asn, country FROM geoip_cache").fetchall()
    return {r["ip"]: (r["asn"], r["country"]) for r in rows}


def save_geoip_batch(conn: sqlite3.Connection, entries: list[tuple[str, int | None, str | None]]) -> None:
    if not entries:
        return
    now = int(time.time())
    conn.executemany(
        "INSERT OR REPLACE INTO geoip_cache (ip, asn, country, ts) VALUES (?, ?, ?, ?)",
        [(ip, asn, country, now) for ip, asn, country in entries],
    )
    conn.commit()


def client_usage_timeseries(conn: sqlite3.Connection, src_ip: str, window_s: int, bucket_s: int) -> list[dict]:
    """Série temporal de tráfego (bps) de UM cliente — usa idx_client_flow_src
    (src_ip, ts), equality+range, sem precisar de índice novo."""
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT (ts / ?) * ? AS bucket, SUM(bytes) AS bytes
           FROM client_flow_aggs WHERE src_ip = ? AND ts >= ?
           GROUP BY bucket ORDER BY bucket""",
        (bucket_s, bucket_s, src_ip, since),
    ).fetchall()
    return [{"ts": r["bucket"], "bps": (r["bytes"] * 8) / bucket_s} for r in rows]


def client_top_destinations(conn: sqlite3.Connection, src_ip: str, window_s: int, limit: int = 10) -> list[dict]:
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT dst_ip, dst_port, protocol, dst_asn, dst_country,
                  SUM(bytes) AS bytes, SUM(packets) AS packets
           FROM client_flow_aggs WHERE src_ip = ? AND ts >= ?
           GROUP BY dst_ip, dst_port, protocol
           ORDER BY bytes DESC LIMIT ?""",
        (src_ip, since, limit),
    ).fetchall()
    return [dict(r) for r in rows]
