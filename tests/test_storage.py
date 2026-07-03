"""Testa as operações de storage.py isoladamente do resto do pipeline."""

from __future__ import annotations

import time

import storage
from conftest import insert_flow


def test_insert_and_get_open_signal(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.1", "customer_prefix": "177.86.19.0/24",
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    found = storage.get_open_signal(conn, "177.86.19.1", "spam_bot")
    assert found is not None
    assert found["id"] == signal_id
    assert found["resolved"] == 0


def test_get_open_signal_ignores_resolved(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.2", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.resolve_signal(conn, signal_id)
    assert storage.get_open_signal(conn, "177.86.19.2", "spam_bot") is None


def test_resolve_signal_returns_false_when_already_resolved(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.3", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    assert storage.resolve_signal(conn, signal_id) is True
    assert storage.resolve_signal(conn, signal_id) is False


def test_resolve_signal_returns_false_for_unknown_id(conn):
    assert storage.resolve_signal(conn, 999999) is False


def test_clear_open_signals_resolves_only_open_ones(conn):
    already_resolved = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.10", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.resolve_signal(conn, already_resolved)
    open_a = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.11", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    open_b = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.12", "customer_prefix": None,
        "signal_type": "port_scan_horizontal", "confidence": 0.5, "evidence": "{}",
    })
    cleared = storage.clear_open_signals(conn)
    assert cleared == 2
    assert storage.get_open_signal(conn, "177.86.19.11", "spam_bot") is None
    assert storage.get_open_signal(conn, "177.86.19.12", "port_scan_horizontal") is None
    # já resolvido antes não deve ser contado de novo
    assert storage.clear_open_signals(conn) == 0


def test_touch_signal_updates_evidence_and_last_seen(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.4", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{\"n\": 1}",
    })
    before = storage.get_open_signal(conn, "177.86.19.4", "spam_bot")
    storage.touch_signal(conn, signal_id, "{\"n\": 2}")
    after = storage.get_open_signal(conn, "177.86.19.4", "spam_bot")
    assert after["evidence"] == "{\"n\": 2}"
    assert after["ts_last_seen"] >= before["ts_last_seen"]


def test_mark_notified_and_save_ai_explanation(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.5", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.mark_notified(conn, signal_id)
    storage.save_ai_explanation(conn, signal_id, "explicação de teste")
    row = storage.get_open_signal(conn, "177.86.19.5", "spam_bot")
    assert row["notified"] == 1
    assert row["ai_explanation"] == "explicação de teste"


def test_list_suspicious_clients_filters_by_resolved(conn):
    open_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.6", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    resolved_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.7", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.resolve_signal(conn, resolved_id)

    open_ids = {s["id"] for s in storage.list_suspicious_clients(conn, resolved=False)}
    resolved_ids = {s["id"] for s in storage.list_suspicious_clients(conn, resolved=True)}
    assert open_ids == {open_id}
    assert resolved_ids == {resolved_id}


def test_prune_old_aggs_removes_only_expired_rows(conn):
    old_ts = int(time.time()) - 10 * 86400
    insert_flow(conn, "177.86.19.8", "1.2.3.4", 443, protocol=6, ts=old_ts)
    insert_flow(conn, "177.86.19.9", "1.2.3.5", 443, protocol=6)  # ts atual

    pruned = storage.prune_old_aggs(conn, retention_days=7)
    assert pruned == 1
    remaining = conn.execute("SELECT src_ip FROM client_flow_aggs").fetchall()
    assert [r["src_ip"] for r in remaining] == ["177.86.19.9"]


def test_bucket_client_port_keeps_configured_ports(conn):
    assert storage.bucket_client_port(53, {53, 123, 1900, 11211, 389}) == 53
    assert storage.bucket_client_port(11211, {53, 123, 1900, 11211, 389}) == 11211


def test_bucket_client_port_collapses_everything_else(conn):
    assert storage.bucket_client_port(54321, {53, 123, 1900, 11211, 389}) == 0
    assert storage.bucket_client_port(80, {53, 123, 1900, 11211, 389}) == 0


def test_compact_client_flow_aggs_merges_duplicate_ephemeral_ports(conn):
    ts = int(time.time())
    # mesmo (ts,src_ip,dst_ip,dst_port,protocol), 3 portas efêmeras distintas do cliente
    for src_port in (40001, 40002, 40003):
        insert_flow(conn, "177.86.19.20", "1.2.3.4", 443, protocol=6,
                    bytes_=100, packets_=1, src_port=src_port, ts=ts)
    # porta de amplificação real (53) deve permanecer distinta, não some no merge
    insert_flow(conn, "177.86.19.20", "8.8.8.8", 12345, protocol=17,
                bytes_=200, packets_=2, src_port=53, ts=ts)

    before, after = storage.compact_client_flow_aggs(conn, {53, 123, 1900, 11211, 389})
    assert before == 4
    assert after == 2  # as 3 linhas de porta efêmera viram 1; a de amplificação continua separada

    rows = conn.execute("SELECT * FROM client_flow_aggs ORDER BY dst_port").fetchall()
    merged = next(r for r in rows if r["dst_port"] == 443)
    assert merged["src_port"] == 0
    assert merged["bytes"] == 300  # soma preservada (100 * 3)
    assert merged["packets"] == 3

    amp = next(r for r in rows if r["dst_port"] == 12345)
    assert amp["src_port"] == 53  # porta de amplificação preservada, não bucketizada
    assert amp["bytes"] == 200


def test_compact_client_flow_aggs_preserves_total_bytes(conn):
    ts = int(time.time())
    for i in range(10):
        insert_flow(conn, "177.86.19.21", "1.2.3.4", 443, protocol=6,
                    bytes_=50, packets_=1, src_port=30000 + i, ts=ts)
    total_before = conn.execute("SELECT SUM(bytes) FROM client_flow_aggs").fetchone()[0]
    storage.compact_client_flow_aggs(conn, set())
    total_after = conn.execute("SELECT SUM(bytes) FROM client_flow_aggs").fetchone()[0]
    assert total_before == total_after == 500


def test_geoip_cache_roundtrip(conn):
    storage.save_geoip_batch(conn, [("8.8.8.8", 15169, "US"), ("1.1.1.1", 13335, "AU")])
    cached = storage.load_geoip_cache(conn)
    assert cached == {"8.8.8.8": (15169, "US"), "1.1.1.1": (13335, "AU")}


def test_geoip_cache_replace_updates_existing_entry(conn):
    storage.save_geoip_batch(conn, [("8.8.8.8", 15169, "US")])
    storage.save_geoip_batch(conn, [("8.8.8.8", 99999, "ZZ")])
    assert storage.load_geoip_cache(conn) == {"8.8.8.8": (99999, "ZZ")}
