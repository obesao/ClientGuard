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


def test_daemon_stats_counts_only_active_mitigations(conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "manual")
    reverted_id = storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "manual")
    storage.mark_edge_reverted(conn, reverted_id)
    stats = storage.daemon_stats(conn)
    assert stats["active_mitigations"] == 1


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


def test_resolve_signal_sets_reason_manual(conn):
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.20", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.resolve_signal(conn, signal_id)
    row = conn.execute("SELECT resolved_reason FROM suspicious_clients WHERE id = ?", (signal_id,)).fetchone()
    assert row["resolved_reason"] == "manual"


def test_resolve_stale_signals_resolves_only_past_cutoff(conn):
    now = int(time.time())
    stale_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.21", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    conn.execute("UPDATE suspicious_clients SET ts_last_seen = ? WHERE id = ?", (now - 25000, stale_id))
    conn.commit()

    fresh_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.22", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })

    resolved = storage.resolve_stale_signals(conn, stale_s=21600)

    resolved_ids = {row["id"] for row in resolved}
    assert resolved_ids == {stale_id}
    assert storage.get_open_signal(conn, "177.86.19.21", "spam_bot") is None
    assert storage.get_open_signal(conn, "177.86.19.22", "spam_bot")["id"] == fresh_id

    reason = conn.execute("SELECT resolved_reason FROM suspicious_clients WHERE id = ?", (stale_id,)).fetchone()
    assert reason["resolved_reason"] == "auto_stale"


def test_resolve_stale_signals_no_candidates_returns_empty(conn):
    storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.23", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    assert storage.resolve_stale_signals(conn, stale_s=21600) == []


def test_resolve_stale_signals_ignores_already_resolved(conn):
    now = int(time.time())
    signal_id = storage.insert_suspicious_client(conn, {
        "src_ip": "177.86.19.24", "customer_prefix": None,
        "signal_type": "spam_bot", "confidence": 0.8, "evidence": "{}",
    })
    storage.resolve_signal(conn, signal_id)
    conn.execute("UPDATE suspicious_clients SET ts_last_seen = ? WHERE id = ?", (now - 25000, signal_id))
    conn.commit()
    assert storage.resolve_stale_signals(conn, stale_s=21600) == []


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


def test_prune_old_aggs_removes_across_multiple_batches(conn):
    old_ts = int(time.time()) - 10 * 86400
    for i in range(25):
        insert_flow(conn, f"177.86.19.{i}", "1.2.3.4", 443, protocol=6, ts=old_ts)
    insert_flow(conn, "177.86.19.99", "1.2.3.5", 443, protocol=6)  # ts atual, sobrevive

    pruned = storage.prune_old_aggs(conn, retention_days=7, batch_size=10)
    assert pruned == 25
    remaining = conn.execute("SELECT src_ip FROM client_flow_aggs").fetchall()
    assert [r["src_ip"] for r in remaining] == ["177.86.19.99"]


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


# --- baseline de tráfego por cliente (client_traffic_baseline) ---------------

def test_update_traffic_baselines_first_sample(conn):
    now = int(time.time())
    storage.update_traffic_baselines(conn, [("1.2.3.4", "dns_query", 10000, 0.1, now, None)])
    b = storage.get_baseline_for(conn, "1.2.3.4", "dns_query")
    assert b["bps_mean"] == 10000
    assert b["bps_var"] == 0
    assert b["samples"] == 1


def test_update_traffic_baselines_ewma_uses_previous_row(conn):
    now = int(time.time())
    storage.update_traffic_baselines(conn, [("1.2.3.4", "dns_query", 10000, 0.5, now, None)])
    prev = storage.get_baseline_for(conn, "1.2.3.4", "dns_query")
    storage.update_traffic_baselines(conn, [("1.2.3.4", "dns_query", 20000, 0.5, now, prev)])
    b = storage.get_baseline_for(conn, "1.2.3.4", "dns_query")
    assert b["bps_mean"] == 15000  # mean + 0.5*(20000-10000)
    assert b["samples"] == 2


def test_update_traffic_baselines_distinct_traffic_classes_dont_collide(conn):
    now = int(time.time())
    storage.update_traffic_baselines(conn, [
        ("1.2.3.4", "dns_query", 1000, 0.1, now, None),
        ("1.2.3.4", "amplifier:53", 2000, 0.1, now, None),
    ])
    assert storage.get_baseline_for(conn, "1.2.3.4", "dns_query")["bps_mean"] == 1000
    assert storage.get_baseline_for(conn, "1.2.3.4", "amplifier:53")["bps_mean"] == 2000


def test_get_baselines_for_scopes_to_requested_src_ips(conn):
    now = int(time.time())
    storage.update_traffic_baselines(conn, [
        ("1.2.3.4", "dns_query", 1000, 0.1, now, None),
        ("5.6.7.8", "dns_query", 2000, 0.1, now, None),
    ])
    scoped = storage.get_baselines_for(conn, ["1.2.3.4"])
    assert set(scoped.keys()) == {("1.2.3.4", "dns_query")}


def test_get_baselines_for_empty_list_returns_empty(conn):
    assert storage.get_baselines_for(conn, []) == {}


def test_prune_stale_baselines_removes_only_old_entries(conn):
    old_ts = int(time.time()) - 30 * 86400
    recent_ts = int(time.time())
    conn.execute(
        "INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at) "
        "VALUES (?, ?, 0, 0, 1, ?)", ("1.2.3.4", "dns_query", old_ts),
    )
    conn.execute(
        "INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at) "
        "VALUES (?, ?, 0, 0, 1, ?)", ("5.6.7.8", "dns_query", recent_ts),
    )
    conn.commit()
    removed = storage.prune_stale_baselines(conn, stale_days=14)
    assert removed == 1
    assert storage.get_baseline_for(conn, "1.2.3.4", "dns_query") is None
    assert storage.get_baseline_for(conn, "5.6.7.8", "dns_query") is not None


def test_recent_signal_src_ips_filters_by_type_and_time(conn):
    now = int(time.time())
    storage.insert_suspicious_client(conn, {
        "src_ip": "1.2.3.4", "customer_prefix": None, "signal_type": "dns_tunneling",
        "confidence": 1.0, "evidence": "{}",
    })
    storage.insert_suspicious_client(conn, {
        "src_ip": "5.6.7.8", "customer_prefix": None, "signal_type": "spam_bot",
        "confidence": 1.0, "evidence": "{}",
    })
    assert storage.recent_signal_src_ips(conn, "dns_tunneling", now) == {"1.2.3.4"}
    assert storage.recent_signal_src_ips(conn, "dns_tunneling", now + 3600) == set()


def test_count_active_edge_mitigations_filters_by_mechanism(conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="flowspec")
    storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "auto", mechanism="ssh")
    assert storage.count_active_edge_mitigations(conn, "flowspec") == 1
    assert storage.count_active_edge_mitigations(conn, "ssh") == 1


def test_list_due_edge_mitigations_filters_by_mechanism(conn):
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, -10, "auto", mechanism="flowspec")
    storage.insert_edge_mitigation(conn, "5.6.7.8", None, -10, "auto", mechanism="ssh")
    due_flowspec = storage.list_due_edge_mitigations(conn, mechanism="flowspec")
    assert {r["src_ip"] for r in due_flowspec} == {"1.2.3.4"}
    due_all = storage.list_due_edge_mitigations(conn)
    assert {r["src_ip"] for r in due_all} == {"1.2.3.4", "5.6.7.8"}


def test_get_latest_edge_mitigation_returns_none_when_never_mitigated(conn):
    assert storage.get_latest_edge_mitigation(conn, "1.2.3.4") is None


def test_get_latest_edge_mitigation_returns_most_recent_regardless_of_status(conn):
    first_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="flowspec")
    storage.mark_edge_reverted(conn, first_id)
    second_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="ssh")
    latest = storage.get_latest_edge_mitigation(conn, "1.2.3.4")
    assert latest["id"] == second_id
    assert latest["status"] == "active"


def test_get_latest_edge_mitigation_scoped_by_src_ip(conn):
    storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "auto", mechanism="ssh")
    assert storage.get_latest_edge_mitigation(conn, "1.2.3.4") is None
