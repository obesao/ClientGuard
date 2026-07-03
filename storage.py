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

-- Mitigação direta na borda (SSH/ACL no roteador) por src_ip — trilha própria,
-- separada de suspicious_clients, porque uma mitigação pode ser reaplicada/estendida
-- (mesmo IP, TTL renovado) sem abrir um novo sinal de detecção.
CREATE TABLE IF NOT EXISTS edge_mitigations (
  id           INTEGER PRIMARY KEY,
  signal_id    INTEGER,
  src_ip       TEXT NOT NULL,
  ts_applied   INTEGER NOT NULL,
  ts_expires   INTEGER,
  ts_reverted  INTEGER,
  status       TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'reverted' | 'failed'
  trigger_type TEXT NOT NULL DEFAULT 'manual',   -- 'auto' | 'manual'
  error        TEXT
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
CREATE INDEX IF NOT EXISTS idx_edge_mitigations_status ON edge_mitigations(status, src_ip);
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


def bucket_client_port(port: int, keep_ports) -> int:
    """Colapsa a porta de origem do CLIENTE (não o dst_port do outro lado) pra 0,
    exceto quando é uma das portas de serviço que detect_amplifier precisa
    distinguir com exatidão (cliente hospedando o serviço, respondendo a partir
    dela). Nenhum outro detector olha src_port — sem isso, cada conexão TCP/UDP do
    cliente vira uma porta de origem efêmera distinta, inflando client_flow_aggs em
    ordens de grandeza sem nenhum valor de detecção (achado real em produção: ~78k
    linhas num ciclo de ~40s, ~41k valores distintos de src_port nesse mesmo ciclo,
    o mesmo (src_ip,dst_ip,dst_port,protocolo) repetido até 63x só pela porta
    efêmera variar) — mesma classe do bug já corrigido no flow_aggs do FlowGuard."""
    return port if port in keep_ports else 0


def compact_client_flow_aggs(conn: sqlite3.Connection, amplifier_ports) -> tuple[int, int]:
    """Reescreve client_flow_aggs agrupando por (ts, src_ip, customer_prefix,
    src_port já bucketizado, dst_ip, dst_port, protocol, dst_asn, dst_country),
    somando bytes/packets — remove só a duplicidade introduzida pela porta efêmera
    do cliente (ver bucket_client_port), preserva o total de bytes/pacotes (soma
    invariante). Rodar com o daemon parado (ver tools/compact_client_flow_aggs.py).
    Retorna (linhas_antes, linhas_depois)."""
    before = conn.execute("SELECT COUNT(*) FROM client_flow_aggs").fetchone()[0]
    keep_ports = ",".join(str(int(p)) for p in amplifier_ports) or "-1"
    conn.execute("DROP TABLE IF EXISTS client_flow_aggs_compact")
    conn.execute(
        """CREATE TABLE client_flow_aggs_compact (
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
           )"""
    )
    conn.execute(
        f"""INSERT INTO client_flow_aggs_compact
              (ts, src_ip, customer_prefix, src_port, dst_ip, dst_port, protocol,
               bytes, packets, dst_asn, dst_country)
            SELECT ts, src_ip, customer_prefix,
                   CASE WHEN src_port IN ({keep_ports}) THEN src_port ELSE 0 END,
                   dst_ip, dst_port, protocol, SUM(bytes), SUM(packets), dst_asn, dst_country
            FROM client_flow_aggs
            GROUP BY ts, src_ip, customer_prefix, 4, dst_ip, dst_port, protocol, dst_asn, dst_country"""
    )
    conn.execute("DROP TABLE client_flow_aggs")
    conn.execute("ALTER TABLE client_flow_aggs_compact RENAME TO client_flow_aggs")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_client_flow_ts ON client_flow_aggs(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_client_flow_src ON client_flow_aggs(src_ip, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_client_flow_dst ON client_flow_aggs(dst_ip, dst_port, ts)")
    # ANALYZE é essencial aqui, não cosmético — achado real: sem estatísticas frescas
    # pra tabela recém-reescrita, o query planner escolheu SCAN completo do índice
    # (src_ip, ts) pra COUNT(DISTINCT src_ip), ~2s mesmo filtrando só os últimos 30s;
    # com ANALYZE, vira SEARCH pelo mesmo índice em ~0.1s. prune_old_aggs já roda
    # ANALYZE depois de cada DELETE, mas isso só acontece de novo ~1x/hora — sem
    # rodar aqui, a tabela fica com plano ruim até o próximo prune periódico.
    conn.execute("ANALYZE client_flow_aggs")
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM client_flow_aggs").fetchone()[0]
    return before, after


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
    """Não inclui total_rows de propósito — um COUNT(*) sem WHERE sobre
    client_flow_aggs é uma varredura da tabela inteira (achado real: ~2.5s sob
    ~26M linhas, chamado a cada poll de status do portal) sem nenhum ganho real
    de precisão sobre manter a contagem incremental em memória no daemon (ver
    ClientGuardDaemon.total_rows em clientguard.py, atualizado a cada
    insert/prune em vez de recontado a cada status)."""
    since = int(time.time()) - window_s
    flows_window = conn.execute(
        "SELECT COUNT(*) FROM client_flow_aggs WHERE ts >= ?", (since,),
    ).fetchone()[0]
    distinct_src_ips = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM client_flow_aggs WHERE ts >= ?", (since,),
    ).fetchone()[0]
    open_signals = conn.execute("SELECT COUNT(*) FROM suspicious_clients WHERE resolved = 0").fetchone()[0]
    return {
        "flows_window": flows_window, "distinct_src_ips": distinct_src_ips,
        "open_signals": open_signals,
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


# --- mitigação direta na borda (SSH/ACL) ----------------------------------

def insert_edge_mitigation(conn: sqlite3.Connection, src_ip: str, signal_id: int | None,
                            ttl_s: int | None, trigger_type: str) -> int:
    now = int(time.time())
    ts_expires = now + ttl_s if ttl_s else None
    cur = conn.execute(
        """INSERT INTO edge_mitigations (signal_id, src_ip, ts_applied, ts_expires, status, trigger_type)
           VALUES (?, ?, ?, ?, 'active', ?)""",
        (signal_id, src_ip, now, ts_expires, trigger_type),
    )
    conn.commit()
    return cur.lastrowid


def get_active_edge_mitigation(conn: sqlite3.Connection, src_ip: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM edge_mitigations WHERE src_ip = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
        (src_ip,),
    ).fetchone()
    return dict(row) if row else None


def get_edge_mitigation(conn: sqlite3.Connection, mitigation_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM edge_mitigations WHERE id = ?", (mitigation_id,)).fetchone()
    return dict(row) if row else None


def extend_edge_mitigation(conn: sqlite3.Connection, mitigation_id: int, ttl_s: int | None) -> None:
    ts_expires = int(time.time()) + ttl_s if ttl_s else None
    conn.execute("UPDATE edge_mitigations SET ts_expires = ? WHERE id = ?", (ts_expires, mitigation_id))
    conn.commit()


def list_edge_mitigations(conn: sqlite3.Connection, active_only: bool = False) -> list[dict]:
    query = "SELECT * FROM edge_mitigations"
    if active_only:
        query += " WHERE status = 'active'"
    query += " ORDER BY ts_applied DESC"
    rows = conn.execute(query).fetchall()
    return [dict(r) for r in rows]


def list_due_edge_mitigations(conn: sqlite3.Connection) -> list[dict]:
    now = int(time.time())
    rows = conn.execute(
        "SELECT * FROM edge_mitigations WHERE status = 'active' AND ts_expires IS NOT NULL AND ts_expires <= ?",
        (now,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_edge_reverted(conn: sqlite3.Connection, mitigation_id: int, error: str | None = None) -> None:
    conn.execute(
        "UPDATE edge_mitigations SET status = ?, ts_reverted = ?, error = ? WHERE id = ?",
        ("failed" if error else "reverted", int(time.time()), error, mitigation_id),
    )
    conn.commit()


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
