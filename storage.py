"""Camada de acesso ao SQLite do ClientGuard — schema e operações próprias,
independentes do FlowGuard (banco separado, /root/clientguard/db/)."""

from __future__ import annotations

import json
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
  resolved        INTEGER DEFAULT 0,
  resolved_reason TEXT   -- 'manual' | 'auto_stale' | NULL (ainda aberto)
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

-- Mitigação na borda por src_ip — trilha própria, separada de suspicious_clients,
-- porque uma mitigação pode ser reaplicada/estendida (mesmo IP, TTL renovado) sem
-- abrir um novo sinal de detecção. mechanism distingue o caminho SSH/ACL original
-- (Netmiko direto no roteador) do caminho FlowSpec/BGP atual (via socket do
-- FlowGuard) — linhas antigas ficam 'ssh' (default), novas mitigações usam
-- 'flowspec'; os dois mecanismos coexistem até a última mitigação SSH expirar
-- (ver flowspec_mitigation.py e o edge_mitigation.py legado).
CREATE TABLE IF NOT EXISTS edge_mitigations (
  id               INTEGER PRIMARY KEY,
  signal_id        INTEGER,
  src_ip           TEXT NOT NULL,
  ts_applied       INTEGER NOT NULL,
  ts_expires       INTEGER,
  ts_reverted      INTEGER,
  status           TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'reverted' | 'failed'
  trigger_type     TEXT NOT NULL DEFAULT 'manual',   -- 'auto' | 'manual'
  error            TEXT,
  mechanism        TEXT NOT NULL DEFAULT 'ssh',      -- 'ssh' | 'flowspec'
  flowspec_rule_id INTEGER,                          -- id em flowspec_rules (banco do FlowGuard)
  match_json       TEXT,                             -- rule FlowSpec efetivamente anunciada
  rate_limit_bps   INTEGER                           -- NULL quando a ação é discard
);

-- Baseline EWMA de tráfego por (cliente, classe de tráfego) — usada só pelo
-- rate-limit dinâmico do FlowSpec (dns_tunneling/amplifier_hosted). traffic_class
-- é 'dns_query' (consultas DNS saindo do cliente) ou 'amplifier:<porta>' (cliente
-- respondendo como se fosse o serviço abusado numa porta de amplificação
-- específica) — uma linha por combinação, nunca uma linha "global" por cliente.
CREATE TABLE IF NOT EXISTS client_traffic_baseline (
  src_ip        TEXT NOT NULL,
  traffic_class TEXT NOT NULL,
  bps_mean      REAL NOT NULL DEFAULT 0,
  bps_var       REAL NOT NULL DEFAULT 0,
  samples       INTEGER NOT NULL DEFAULT 0,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (src_ip, traffic_class)
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

    # pra dar detalhe de "o que exatamente foi mandado pro equipamento" no botão
    # Detalhes do portal — comandos resolvidos (JSON) + saída bruta do Netmiko,
    # separados por etapa (aplicar/reverter) porque uma mitigação pode reverter
    # bem depois de aplicada, e queremos as duas saídas guardadas.
    edge_cols = {row["name"] for row in conn.execute("PRAGMA table_info(edge_mitigations)")}
    for col in ("apply_commands", "apply_output", "revert_commands", "revert_output"):
        if col not in edge_cols:
            conn.execute(f"ALTER TABLE edge_mitigations ADD COLUMN {col} TEXT")
    # colunas do mecanismo FlowSpec — bancos criados antes dele existir não têm
    # essas colunas; linhas antigas (SSH) ficam com mechanism='ssh' via DEFAULT.
    if "mechanism" not in edge_cols:
        conn.execute("ALTER TABLE edge_mitigations ADD COLUMN mechanism TEXT NOT NULL DEFAULT 'ssh'")
    if "flowspec_rule_id" not in edge_cols:
        conn.execute("ALTER TABLE edge_mitigations ADD COLUMN flowspec_rule_id INTEGER")
    if "match_json" not in edge_cols:
        conn.execute("ALTER TABLE edge_mitigations ADD COLUMN match_json TEXT")
    if "rate_limit_bps" not in edge_cols:
        conn.execute("ALTER TABLE edge_mitigations ADD COLUMN rate_limit_bps INTEGER")

    susp_cols = {row["name"] for row in conn.execute("PRAGMA table_info(suspicious_clients)")}
    if "resolved_reason" not in susp_cols:
        # distingue resolução manual (clique em "Resolver"/"Limpar hosts suspeitos")
        # de resolve_stale_signals (sinal sem atualização há muito tempo, com a
        # mitigação associada — se houve — já expirada) — sem isso, um sinal antigo
        # do qual o cliente já desistiu ficava "aberto" pra sempre, exigindo clique
        # manual mesmo depois de a mitigação ter caído há horas.
        conn.execute("ALTER TABLE suspicious_clients ADD COLUMN resolved_reason TEXT")
        conn.execute("UPDATE suspicious_clients SET resolved_reason = 'manual' WHERE resolved = 1")
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


def recent_signal_src_ips(conn: sqlite3.Connection, signal_type: str, since_ts: int) -> set[str]:
    """src_ip flagrados por signal_type neste ciclo (novo ou recorrente — touch_signal
    e insert_suspicious_client sempre atualizam ts_last_seen pro momento em que o
    detector rodou). Usado pra anti-poisoning da baseline de tráfego: exclui do EWMA
    qualquer cliente que o próprio detector já classificou como anômalo agora, senão a
    baseline aprende o ataque como tráfego normal."""
    rows = conn.execute(
        "SELECT DISTINCT src_ip FROM suspicious_clients WHERE signal_type = ? AND ts_last_seen >= ?",
        (signal_type, since_ts),
    ).fetchall()
    return {r["src_ip"] for r in rows}


def resolve_signal(conn: sqlite3.Connection, signal_id: int) -> bool:
    cur = conn.execute(
        "UPDATE suspicious_clients SET resolved = 1, resolved_reason = 'manual' WHERE id = ? AND resolved = 0",
        (signal_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def clear_open_signals(conn: sqlite3.Connection) -> int:
    """Resolve TODOS os sinais abertos de uma vez (botão "Limpar hosts suspeitos" do
    portal) — marca resolved=1 em vez de apagar a linha, igual resolve_signal, pra manter
    o histórico/evidência/explicação de IA consultável na aba "Resolvidos"."""
    cur = conn.execute("UPDATE suspicious_clients SET resolved = 1, resolved_reason = 'manual' WHERE resolved = 0")
    conn.commit()
    return cur.rowcount


def resolve_stale_signals(conn: sqlite3.Connection, stale_s: int) -> list[dict]:
    """Rede de segurança: resolve sozinho um sinal sem atualização (ts_last_seen) há
    mais de stale_s. Os detectores (detector.py) são 100% orientados a evidência nova
    — se a condição parar de bater, o sinal simplesmente não é mais tocado, e sem
    isso ficaria "aberto" pra sempre até um clique manual em "Resolver", mesmo que a
    mitigação associada (se houve) já tenha expirado há muito tempo. Retorna os
    sinais resolvidos (dict completo) pra quem chamar logar/notificar."""
    cutoff = int(time.time()) - stale_s
    rows = conn.execute(
        "SELECT * FROM suspicious_clients WHERE resolved = 0 AND ts_last_seen < ?", (cutoff,),
    ).fetchall()
    if not rows:
        return []
    ids = [row["id"] for row in rows]
    conn.execute(
        f"UPDATE suspicious_clients SET resolved = 1, resolved_reason = 'auto_stale' "
        f"WHERE id IN ({','.join('?' * len(ids))})",
        ids,
    )
    conn.commit()
    return [dict(row) for row in rows]


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
    active_mitigations = conn.execute("SELECT COUNT(*) FROM edge_mitigations WHERE status = 'active'").fetchone()[0]
    return {
        "flows_window": flows_window, "distinct_src_ips": distinct_src_ips,
        "open_signals": open_signals, "active_mitigations": active_mitigations,
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


def network_usage_timeseries(conn: sqlite3.Connection, customer_prefix: str, window_s: int, bucket_s: int) -> list[dict]:
    """Série temporal de tráfego (bps) agregada por REDE inteira (customer_prefix,
    ex: CGNAT) — soma todos os src_ips que caíram nessa rede na ingestão, não só
    um cliente. NÃO tem índice dedicado (customer_prefix não é seletivo pra redes
    grandes como CGNAT, e client_flow_aggs tem 280M+ linhas — ver achado de
    2026-07-08 sobre esse volume); usa o range scan de idx_client_flow_ts, medido
    em produção: 1h~0.6s, 6h~4.2s, 24h+ inviável (minutos, não terminou em teste).
    Por isso o frontend só oferece 1h/6h pra redes do ClientGuard por enquanto —
    ver CHANGELOG. Não usar com window_s grande sem antes resolver o índice/o
    volume da tabela."""
    since = int(time.time()) - window_s
    rows = conn.execute(
        """SELECT (ts / ?) * ? AS bucket, SUM(bytes) AS bytes
           FROM client_flow_aggs WHERE customer_prefix = ? AND ts >= ?
           GROUP BY bucket ORDER BY bucket""",
        (bucket_s, bucket_s, customer_prefix, since),
    ).fetchall()
    return [{"ts": r["bucket"], "bps": (r["bytes"] * 8) / bucket_s} for r in rows]


# --- mitigação direta na borda (SSH/ACL) ----------------------------------

def insert_edge_mitigation(conn: sqlite3.Connection, src_ip: str, signal_id: int | None,
                            ttl_s: int | None, trigger_type: str,
                            apply_commands: list[str] | None = None, apply_output: str | None = None,
                            status: str = "active", error: str | None = None,
                            mechanism: str = "ssh", flowspec_rule_id: int | None = None,
                            match_json: str | None = None, rate_limit_bps: int | None = None) -> int:
    now = int(time.time())
    ts_expires = now + ttl_s if ttl_s else None
    cur = conn.execute(
        """INSERT INTO edge_mitigations
           (signal_id, src_ip, ts_applied, ts_expires, status, trigger_type, apply_commands, apply_output, error,
            mechanism, flowspec_rule_id, match_json, rate_limit_bps)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (signal_id, src_ip, now, ts_expires, status, trigger_type,
         json.dumps(apply_commands) if apply_commands else None, apply_output, error,
         mechanism, flowspec_rule_id, match_json, rate_limit_bps),
    )
    conn.commit()
    return cur.lastrowid


def get_active_edge_mitigation(conn: sqlite3.Connection, src_ip: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM edge_mitigations WHERE src_ip = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
        (src_ip,),
    ).fetchone()
    return dict(row) if row else None


def get_latest_edge_mitigation(conn: sqlite3.Connection, src_ip: str) -> dict | None:
    """Última mitigação (qualquer status — active/reverted/failed) desse src_ip,
    independente de estar em vigor agora ou não. Usado pela aba Sinais Suspeitos
    do portal pra mostrar "esse cliente já foi/está mitigado?" — diferente de
    get_active_edge_mitigation (só active), que é o usado pra decidir se dispara
    uma mitigação nova."""
    row = conn.execute(
        "SELECT * FROM edge_mitigations WHERE src_ip = ? ORDER BY id DESC LIMIT 1",
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


def count_active_edge_mitigations(conn: sqlite3.Connection, mechanism: str) -> int:
    """Orçamento próprio do ClientGuard (max_active_rules em flowspec_mitigation.yaml) —
    contagem local, não depende de listar regras no FlowGuard (que não filtra por
    origin — ver flowspec_mitigation.py)."""
    return conn.execute(
        "SELECT COUNT(*) FROM edge_mitigations WHERE status = 'active' AND mechanism = ?", (mechanism,),
    ).fetchone()[0]


def count_recent_mitigations(conn: sqlite3.Connection, src_ip: str, since_ts: int) -> int:
    """Quantas vezes src_ip já foi mitigado (qualquer mecanismo — ssh ou flowspec,
    qualquer status) desde since_ts — fonte de histórico pro escalonamento
    progressivo (ver escalation.py::next_ttl_s). edge_mitigations nunca deleta
    linha, então isso inclui mitigações já revertidas/expiradas, não só as ativas."""
    return conn.execute(
        "SELECT COUNT(*) FROM edge_mitigations WHERE src_ip = ? AND ts_applied >= ?", (src_ip, since_ts),
    ).fetchone()[0]


def list_due_edge_mitigations(conn: sqlite3.Connection, mechanism: str | None = None) -> list[dict]:
    """mechanism opcional restringe a expiração a um caminho só ('ssh' ou 'flowspec') —
    os dois módulos de mitigação rodam expire_due independentemente, cada um só
    processando o próprio mecanismo (ver flowspec_mitigation.py e edge_mitigation.py)."""
    now = int(time.time())
    query = "SELECT * FROM edge_mitigations WHERE status = 'active' AND ts_expires IS NOT NULL AND ts_expires <= ?"
    params: tuple = (now,)
    if mechanism:
        query += " AND mechanism = ?"
        params += (mechanism,)
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def mark_edge_reverted(conn: sqlite3.Connection, mitigation_id: int, error: str | None = None,
                        revert_commands: list[str] | None = None, revert_output: str | None = None) -> None:
    conn.execute(
        """UPDATE edge_mitigations
           SET status = ?, ts_reverted = ?, error = ?, revert_commands = ?, revert_output = ?
           WHERE id = ?""",
        ("failed" if error else "reverted", int(time.time()), error,
         json.dumps(revert_commands) if revert_commands else None, revert_output, mitigation_id),
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


# --- baseline de tráfego por cliente (pro rate-limit dinâmico do FlowSpec) -----
#
# Mesmo formato EWMA de collector/storage.py (FlowGuard) — prefix_baseline/
# update_baselines/get_baseline —, mas com duas adaptações exigidas pela escala
# (milhares de clientes em vez de 8 prefixos fixos): get_baselines_for busca só
# as chaves ativas no ciclo atual (nunca a tabela inteira, ao contrário do
# list_baselines do FlowGuard), e update_traffic_baselines grava em lote via
# executemany depois de um único SELECT em massa, em vez de 1 SELECT + 1
# UPDATE/INSERT por linha num loop Python.

def get_baselines_for(conn: sqlite3.Connection, src_ips: list[str]) -> dict[tuple[str, str], dict]:
    """Baselines de todas as traffic_class para os src_ips informados — chamar só
    com os IPs que tiveram tráfego relevante no ciclo atual, nunca com a lista
    inteira de clientes cadastrados."""
    if not src_ips:
        return {}
    placeholders = ",".join("?" * len(src_ips))
    rows = conn.execute(
        f"SELECT * FROM client_traffic_baseline WHERE src_ip IN ({placeholders})", src_ips,
    ).fetchall()
    return {(r["src_ip"], r["traffic_class"]): dict(r) for r in rows}


def get_baseline_for(conn: sqlite3.Connection, src_ip: str, traffic_class: str) -> dict | None:
    """Lookup pontual — usado por flowspec_mitigation.build_rule no momento de montar
    a regra (1 cliente por vez), diferente de get_baselines_for (usado em lote pela
    atualização por ciclo)."""
    row = conn.execute(
        "SELECT * FROM client_traffic_baseline WHERE src_ip = ? AND traffic_class = ?",
        (src_ip, traffic_class),
    ).fetchone()
    return dict(row) if row else None


def update_traffic_baselines(conn: sqlite3.Connection, updates: list[tuple]) -> None:
    """updates: lista de (src_ip, traffic_class, bps, alpha, now, prev_row_or_None).
    prev_row vem de get_baselines_for, buscado uma vez em lote pelo chamador — evita
    1 SELECT por linha aqui. Mesma matemática EWMA do FlowGuard: mean += α(x-mean),
    var = (1-α)(var + α(x-mean)²). Chamador já deve ter excluído daqui qualquer
    (src_ip, traffic_class) que gerou sinal neste ciclo (anti-poisoning — senão a
    baseline aprende o próprio ataque como normal)."""
    if not updates:
        return
    rows = []
    for src_ip, traffic_class, bps, alpha, now, prev in updates:
        if prev is None:
            rows.append((src_ip, traffic_class, bps, 0.0, 1, now))
            continue
        new_mean = prev["bps_mean"] + alpha * (bps - prev["bps_mean"])
        new_var = (1 - alpha) * (prev["bps_var"] + alpha * (bps - prev["bps_mean"]) ** 2)
        rows.append((src_ip, traffic_class, new_mean, new_var, prev["samples"] + 1, now))
    conn.executemany(
        """INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(src_ip, traffic_class) DO UPDATE SET
             bps_mean = excluded.bps_mean, bps_var = excluded.bps_var,
             samples = excluded.samples, updated_at = excluded.updated_at""",
        rows,
    )
    conn.commit()


def prune_stale_baselines(conn: sqlite3.Connection, stale_days: int) -> int:
    """Remove baselines de (cliente, classe) sem atualização há stale_days — cliente
    que sumiu/trocou de IP via DHCP. O FlowGuard não precisa disso (8 prefixos fixos,
    nunca somem); o ClientGuard precisa, ou a tabela cresce sem limite."""
    cutoff = int(time.time()) - stale_days * 86400
    cur = conn.execute("DELETE FROM client_traffic_baseline WHERE updated_at < ?", (cutoff,))
    conn.commit()
    return cur.rowcount
