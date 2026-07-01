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

CREATE INDEX IF NOT EXISTS idx_client_flow_ts ON client_flow_aggs(ts);
CREATE INDEX IF NOT EXISTS idx_client_flow_src ON client_flow_aggs(src_ip, ts);
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


def list_suspicious_clients(conn: sqlite3.Connection, resolved: bool = False, since_s: int = 86400) -> list[dict]:
    cutoff = int(time.time()) - since_s
    rows = conn.execute(
        "SELECT * FROM suspicious_clients WHERE resolved = ? AND ts_detected >= ? ORDER BY ts_detected DESC",
        (1 if resolved else 0, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]
