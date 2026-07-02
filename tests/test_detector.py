"""Testa os 7 detectores diretamente contra um SQLite em memória — mesmos cenários
já validados manualmente em produção com tools/synth_client_flows.py, mas
determinísticos e sem precisar de tráfego de rede real."""

from __future__ import annotations

import detector
import storage
import threat_feed
from conftest import insert_flow

WINDOW_S = 30


def open_signals(conn):
    return storage.list_suspicious_clients(conn, resolved=False, since_s=3600)


def signal_types(conn):
    return {s["signal_type"] for s in open_signals(conn)}


# --- scan horizontal --------------------------------------------------------

def test_scan_horizontal_triggers_above_threshold(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.1", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())
    assert "port_scan_horizontal" in signal_types(conn)


def test_scan_horizontal_below_threshold_no_signal(conn):
    for i in range(10):
        insert_flow(conn, "177.86.19.2", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())
    assert not open_signals(conn)


def test_scan_horizontal_respects_whitelist(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.3", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist={"177.86.19.3"})
    assert not open_signals(conn)


# --- scan vertical -----------------------------------------------------------

def test_scan_vertical_triggers_above_threshold(conn):
    for port in range(30):
        insert_flow(conn, "177.86.19.4", "45.20.30.40", 1 + port, protocol=6)
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=30, whitelist=set())
    assert "port_scan_vertical" in signal_types(conn)


def test_scan_vertical_below_threshold_no_signal(conn):
    for port in range(5):
        insert_flow(conn, "177.86.19.5", "45.20.30.40", 1 + port, protocol=6)
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=30, whitelist=set())
    assert not open_signals(conn)


# --- amplificador hospedado ---------------------------------------------------

def test_amplifier_triggers_above_bps_threshold(conn):
    insert_flow(conn, "177.86.19.6", "198.51.100.1", 33000, protocol=17,
                bytes_=10_000_000, src_port=53)
    insert_flow(conn, "177.86.19.6", "198.51.100.2", 33001, protocol=17,
                bytes_=10_000_000, src_port=53)
    detector.detect_amplifier(conn, WINDOW_S, ports=[53, 123, 1900, 11211, 389],
                               min_bps=5_000_000, whitelist=set())
    assert "amplifier_hosted" in signal_types(conn)


def test_amplifier_needs_at_least_two_distinct_destinations(conn):
    # volume alto, mas pra um único destino — não é amplificação distribuída
    insert_flow(conn, "177.86.19.7", "198.51.100.1", 33000, protocol=17,
                bytes_=50_000_000, src_port=53)
    detector.detect_amplifier(conn, WINDOW_S, ports=[53, 123, 1900, 11211, 389],
                               min_bps=5_000_000, whitelist=set())
    assert not open_signals(conn)


def test_amplifier_ignores_non_service_ports(conn):
    insert_flow(conn, "177.86.19.8", "198.51.100.1", 33000, protocol=17,
                bytes_=10_000_000, src_port=54321)  # porta não está na lista de amplificação
    insert_flow(conn, "177.86.19.8", "198.51.100.2", 33001, protocol=17,
                bytes_=10_000_000, src_port=54321)
    detector.detect_amplifier(conn, WINDOW_S, ports=[53, 123, 1900, 11211, 389],
                               min_bps=5_000_000, whitelist=set())
    assert not open_signals(conn)


# --- spam bot -----------------------------------------------------------------

def test_spam_triggers_above_threshold(conn):
    for i in range(20):
        insert_flow(conn, "177.86.19.9", f"203.0.{i}.1", 25, protocol=6)
    detector.detect_spam(conn, WINDOW_S, spam_ports=[25, 465, 587], min_distinct_dest=20,
                          whitelist=set())
    assert "spam_bot" in signal_types(conn)


def test_spam_ignores_non_spam_ports(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.10", f"203.0.{i}.1", 443, protocol=6)  # HTTPS normal
    detector.detect_spam(conn, WINDOW_S, spam_ports=[25, 465, 587], min_distinct_dest=20,
                          whitelist=set())
    assert not open_signals(conn)


# --- contato com IP malicioso conhecido ---------------------------------------

def test_malicious_contact_triggers_for_known_bad_ip(conn, tmp_path):
    cache_file = tmp_path / "threat_ips.txt"
    cache_file.write_text("198.51.100.99\n203.0.113.0/24\n")
    feed = threat_feed.ThreatFeed(str(cache_file))

    insert_flow(conn, "177.86.19.11", "198.51.100.99", 443, protocol=6)
    detector.detect_malicious_contact(conn, WINDOW_S, feed, whitelist=set())
    assert "malicious_contact" in signal_types(conn)


def test_malicious_contact_matches_cidr_block(conn, tmp_path):
    cache_file = tmp_path / "threat_ips.txt"
    cache_file.write_text("203.0.113.0/24\n")
    feed = threat_feed.ThreatFeed(str(cache_file))

    insert_flow(conn, "177.86.19.12", "203.0.113.55", 443, protocol=6)
    detector.detect_malicious_contact(conn, WINDOW_S, feed, whitelist=set())
    assert "malicious_contact" in signal_types(conn)


def test_malicious_contact_ignores_clean_ip(conn, tmp_path):
    cache_file = tmp_path / "threat_ips.txt"
    cache_file.write_text("198.51.100.99\n")
    feed = threat_feed.ThreatFeed(str(cache_file))

    insert_flow(conn, "177.86.19.13", "8.8.8.8", 443, protocol=6)
    detector.detect_malicious_contact(conn, WINDOW_S, feed, whitelist=set())
    assert not open_signals(conn)


def test_malicious_contact_noop_without_feed(conn):
    insert_flow(conn, "177.86.19.14", "198.51.100.99", 443, protocol=6)
    detector.detect_malicious_contact(conn, WINDOW_S, threat_feed=None, whitelist=set())
    assert not open_signals(conn)


# --- destino coordenado (correlação entre clientes) ---------------------------

def test_shared_destination_triggers_for_all_involved_clients(conn):
    srcs = ["177.86.21.10", "177.86.21.11", "177.86.21.12"]
    for i, src in enumerate(srcs):
        insert_flow(conn, src, "198.51.44.90", 6667, protocol=6, src_port=50000 + i)
    detector.detect_shared_destination(conn, WINDOW_S, min_distinct_clients=3,
                                        exclude_ports=[80, 443, 53], whitelist=set())
    signals = open_signals(conn)
    assert {s["src_ip"] for s in signals} == set(srcs)
    assert all(s["signal_type"] == "coordinated_destination" for s in signals)


def test_shared_destination_excludes_common_web_ports(conn):
    srcs = ["177.86.21.20", "177.86.21.21", "177.86.21.22"]
    for i, src in enumerate(srcs):
        insert_flow(conn, src, "198.51.44.91", 443, protocol=6, src_port=50000 + i)
    detector.detect_shared_destination(conn, WINDOW_S, min_distinct_clients=3,
                                        exclude_ports=[80, 443, 53], whitelist=set())
    assert not open_signals(conn)


def test_shared_destination_below_min_clients_no_signal(conn):
    srcs = ["177.86.21.30", "177.86.21.31"]
    for i, src in enumerate(srcs):
        insert_flow(conn, src, "198.51.44.92", 6667, protocol=6, src_port=50000 + i)
    detector.detect_shared_destination(conn, WINDOW_S, min_distinct_clients=3,
                                        exclude_ports=[80, 443, 53], whitelist=set())
    assert not open_signals(conn)


# --- DNS tunneling --------------------------------------------------------------

def test_dns_tunneling_triggers_above_threshold(conn):
    insert_flow(conn, "177.86.23.40", "203.0.113.53", 53, protocol=17, packets_=25_000)
    detector.detect_dns_tunneling(conn, WINDOW_S, min_queries=20_000, whitelist=set())
    assert "dns_tunneling" in signal_types(conn)


def test_dns_tunneling_below_threshold_no_signal(conn):
    insert_flow(conn, "177.86.23.41", "203.0.113.53", 53, protocol=17, packets_=5_000)
    detector.detect_dns_tunneling(conn, WINDOW_S, min_queries=20_000, whitelist=set())
    assert not open_signals(conn)


def test_dns_tunneling_ignores_non_dns_udp(conn):
    insert_flow(conn, "177.86.23.42", "203.0.113.53", 5353, protocol=17, packets_=25_000)
    detector.detect_dns_tunneling(conn, WINDOW_S, min_queries=20_000, whitelist=set())
    assert not open_signals(conn)


# --- dedup / ciclo de vida do sinal ---------------------------------------------

def test_signal_dedup_touches_instead_of_duplicating(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.50", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())
    first_id = open_signals(conn)[0]["id"]

    for i in range(35):  # mesma origem, mais hosts ainda — deve atualizar, não duplicar
        insert_flow(conn, "177.86.19.50", f"46.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())

    signals = open_signals(conn)
    assert len(signals) == 1
    assert signals[0]["id"] == first_id


def test_resolve_then_new_occurrence_reopens_signal(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.51", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())
    signal_id = open_signals(conn)[0]["id"]

    assert storage.resolve_signal(conn, signal_id)
    assert not open_signals(conn)

    for i in range(30):
        insert_flow(conn, "177.86.19.51", f"47.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())

    reopened = open_signals(conn)
    assert len(reopened) == 1
    assert reopened[0]["id"] != signal_id
