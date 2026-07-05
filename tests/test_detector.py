"""Testa os 7 detectores diretamente contra um SQLite em memória — mesmos cenários
já validados manualmente em produção com tools/synth_client_flows.py, mas
determinísticos e sem precisar de tráfego de rede real."""

from __future__ import annotations

import configio
import detector
import storage
import threat_feed
from conftest import insert_flow

WINDOW_S = 30


def _base_config():
    return {
        "detection": {
            "window_s": WINDOW_S,
            "scan_horizontal_hosts": 5,
            "scan_vertical_ports": 5,
            "scan_max_avg_bytes": None,
            "amplifier_ports": [53],
            "amplifier_min_bps": 1,
            "spam_ports": [25],
            "spam_min_distinct_dest": 5,
            "coordinated_min_clients": 5,
            "dns_tunneling_min_queries": 5,
            "common_service_ports": [],
        },
        "alerts": {"webhook_url": ""},
    }


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


def test_scan_horizontal_ignores_excluded_ports(conn):
    # navegação normal: dezenas de IPs de borda de CDN distintos na mesma porta 443 —
    # sem a exclusão, isso é indistinguível de scan de reconhecimento
    for i in range(50):
        insert_flow(conn, "177.86.19.4", f"93.10.{i}.1", 443, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set(), exclude_ports=[443])
    assert not open_signals(conn)


def test_scan_horizontal_still_triggers_on_non_excluded_port(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.5", f"45.10.{i}.1", 8080, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set(), exclude_ports=[443, 80, 53])
    assert "port_scan_horizontal" in signal_types(conn)


def test_scan_horizontal_multiplier_suppresses_cgnat_pool_traffic(conn):
    # 15 hosts distintos > threshold base (10), mas um IP de pool CGNAT combina o tráfego
    # de várias pessoas reais — com multiplicador 4, o limiar efetivo (40) não é atingido
    for i in range(15):
        insert_flow(conn, "100.64.5.5", f"45.10.{i}.1", 22, protocol=6, customer_prefix="100.64.0.0/10")
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=10, whitelist=set(),
                                     multipliers={"100.64.0.0/10": 4})
    assert not open_signals(conn)


def test_scan_horizontal_multiplier_still_triggers_above_effective_threshold(conn):
    for i in range(45):
        insert_flow(conn, "100.64.5.6", f"45.10.{i}.1", 22, protocol=6, customer_prefix="100.64.0.0/10")
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=10, whitelist=set(),
                                     multipliers={"100.64.0.0/10": 4})
    assert "port_scan_horizontal" in signal_types(conn)


def test_scan_horizontal_ignores_p2p_traffic_with_real_volume(conn):
    # muitos hosts distintos, mas 200KB por host — tráfego P2P/torrent de verdade, não
    # sondas de reconhecimento (que mandam pacotes pequenos)
    for i in range(35):
        insert_flow(conn, "177.86.18.235", f"45.10.{i}.1", 4790, protocol=17, bytes_=200_000)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set(), max_avg_bytes=10_000)
    assert not open_signals(conn)


def test_scan_horizontal_still_triggers_on_low_volume_probes(conn):
    for i in range(30):
        insert_flow(conn, "177.86.19.6", f"45.10.{i}.1", 8080, protocol=6, bytes_=60)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set(), max_avg_bytes=10_000)
    assert "port_scan_horizontal" in signal_types(conn)


def test_scan_horizontal_ignores_icmp(conn):
    # achado real monitorando flow de produção: protocol=1 (ICMP) não tem porta de
    # verdade — o "dst_port" gravado é um artefato do NetFlow (type/code), não uma
    # porta. Praticamente todo cliente gera ICMP variado (traceroute, MTU discovery,
    # unreachable) que batia esse limiar sem ser scan de verdade.
    for i in range(30):
        insert_flow(conn, "177.86.19.20", f"45.10.{i}.1", 771, protocol=1)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=30, whitelist=set())
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


def test_scan_vertical_multiplier_suppresses_cgnat_pool_traffic(conn):
    for port in range(15):
        insert_flow(conn, "100.64.5.7", "45.20.30.40", 1 + port, protocol=6, customer_prefix="100.64.0.0/10")
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=10, whitelist=set(),
                                   multipliers={"100.64.0.0/10": 4})
    assert not open_signals(conn)


def test_scan_vertical_ignores_p2p_traffic_with_real_volume(conn):
    # muitas portas distintas no mesmo peer, mas com megabytes por porta — transferência
    # de dados real (P2P), não varredura de vulnerabilidade
    for port in range(35):
        insert_flow(conn, "177.86.18.66", "168.0.164.242", 32796 + port, protocol=6, bytes_=1_000_000)
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=30, whitelist=set(), max_avg_bytes=10_000)
    assert not open_signals(conn)


def test_scan_vertical_still_triggers_on_low_volume_probes(conn):
    for port in range(30):
        insert_flow(conn, "177.86.19.7", "45.20.30.41", 1 + port, protocol=6, bytes_=60)
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=30, whitelist=set(), max_avg_bytes=10_000)
    assert "port_scan_vertical" in signal_types(conn)


def test_scan_vertical_ignores_icmp(conn):
    # mesmo motivo do horizontal: protocol=1 (ICMP) não tem porta de verdade
    for port in range(30):
        insert_flow(conn, "177.86.19.21", "45.20.30.42", 1 + port, protocol=1)
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


def test_amplifier_multiplier_suppresses_cgnat_pool_traffic(conn):
    # mesmo volume do teste que dispara acima (~5.3 Mbps) — mas atrás de um pool CGNAT
    # (multiplicador 4), o limiar efetivo (20 Mbps) não é atingido
    insert_flow(conn, "100.64.5.8", "198.51.100.1", 33000, protocol=17,
                bytes_=10_000_000, src_port=53, customer_prefix="100.64.0.0/10")
    insert_flow(conn, "100.64.5.8", "198.51.100.2", 33001, protocol=17,
                bytes_=10_000_000, src_port=53, customer_prefix="100.64.0.0/10")
    detector.detect_amplifier(conn, WINDOW_S, ports=[53, 123, 1900, 11211, 389],
                               min_bps=5_000_000, whitelist=set(),
                               multipliers={"100.64.0.0/10": 4})
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


def test_spam_multiplier_suppresses_cgnat_pool_traffic(conn):
    for i in range(25):
        insert_flow(conn, "100.64.5.9", f"203.0.{i}.1", 25, protocol=6, customer_prefix="100.64.0.0/10")
    detector.detect_spam(conn, WINDOW_S, spam_ports=[25, 465, 587], min_distinct_dest=20,
                          whitelist=set(), multipliers={"100.64.0.0/10": 4})
    assert not open_signals(conn)


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


def test_shared_destination_multiplier_suppresses_cgnat_pool_convergence(conn):
    # 5 IPs de pool CGNAT distintos > threshold base (3), mas cada um já combina várias
    # pessoas reais — com multiplicador 4, o limiar efetivo do grupo (12) não é atingido
    srcs = [f"100.64.6.{i}" for i in range(5)]
    for i, src in enumerate(srcs):
        insert_flow(conn, src, "198.51.44.93", 6667, protocol=6, src_port=50000 + i,
                    customer_prefix="100.64.0.0/10")
    detector.detect_shared_destination(conn, WINDOW_S, min_distinct_clients=3,
                                        exclude_ports=[80, 443, 53], whitelist=set(),
                                        multipliers={"100.64.0.0/10": 4})
    assert not open_signals(conn)


def test_shared_destination_multiplier_still_triggers_above_effective_threshold(conn):
    srcs = [f"100.64.7.{i}" for i in range(13)]
    for i, src in enumerate(srcs):
        insert_flow(conn, src, "198.51.44.94", 6667, protocol=6, src_port=50000 + i,
                    customer_prefix="100.64.0.0/10")
    detector.detect_shared_destination(conn, WINDOW_S, min_distinct_clients=3,
                                        exclude_ports=[80, 443, 53], whitelist=set(),
                                        multipliers={"100.64.0.0/10": 4})
    assert "coordinated_destination" in signal_types(conn)


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


def test_dns_tunneling_multiplier_suppresses_cgnat_pool_traffic(conn):
    # volume de DNS combinado de várias pessoas atrás de um pool CGNAT — 25k queries
    # passa do limiar base (20k), mas não do efetivo com multiplicador 4 (80k)
    insert_flow(conn, "100.64.5.10", "8.8.8.8", 53, protocol=17, packets_=25_000,
                customer_prefix="100.64.0.0/10")
    detector.detect_dns_tunneling(conn, WINDOW_S, min_queries=20_000, whitelist=set(),
                                   multipliers={"100.64.0.0/10": 4})
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


# --- toggles (habilita/desabilita via portal) ------------------------------------

def test_run_all_skips_detector_disabled_by_toggle(conn):
    for i in range(10):
        insert_flow(conn, "177.86.19.90", f"45.10.{i}.1", 22, protocol=6)
    toggles = dict(configio.DEFAULT_FEATURE_TOGGLES)
    toggles["scan_horizontal"] = False
    detector.run_all(conn, _base_config(), whitelist=set(), toggles=toggles)
    assert "port_scan_horizontal" not in signal_types(conn)


def test_run_all_runs_detector_when_toggle_missing_defaults_enabled(conn):
    for i in range(10):
        insert_flow(conn, "177.86.19.91", f"45.10.{i}.1", 22, protocol=6)
    detector.run_all(conn, _base_config(), whitelist=set(), toggles={})
    assert "port_scan_horizontal" in signal_types(conn)


def test_run_all_disabling_ai_explanations_passes_none_as_ai_client(conn):
    calls = []

    class FakeAI:
        def explain_signal(self, *args, **kwargs):
            calls.append(True)
            return "explicação"

    for i in range(10):
        insert_flow(conn, "177.86.19.92", f"45.10.{i}.1", 22, protocol=6)
    toggles = dict(configio.DEFAULT_FEATURE_TOGGLES)
    toggles["ai_explanations"] = False
    detector.run_all(conn, _base_config(), whitelist=set(), ai_client=FakeAI(), toggles=toggles)
    assert "port_scan_horizontal" in signal_types(conn)
    assert not calls  # sinal disparou normalmente, mas sem chamar a IA


# --- gatilho de mitigação via FlowSpec (mitigation_match) --------------------

def _mitigation_cfg():
    return {"auto_mitigate": {
        "port_scan_horizontal": "discard", "port_scan_vertical": "discard", "dns_tunneling": "rate_limit",
        "amplifier_hosted": "rate_limit", "malicious_contact": "off",
    }}


def test_dns_tunneling_triggers_mitigation_with_udp_53_match(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    insert_flow(conn, "177.86.19.93", "203.0.113.53", 53, protocol=17, packets_=10)
    cfg = _base_config()
    cfg["detection"]["dns_tunneling_min_queries"] = 5
    detector.detect_dns_tunneling(conn, WINDOW_S, 5, whitelist=set(),
                                   mitigation_ctx={"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"})
    assert len(calls) == 1
    args, _ = calls[0]
    # (conn, db_lock, src_ip, signal_id, signal_type, mitigation_match, cfg, fg_socket_path, min_samples)
    assert args[2] == "177.86.19.93"
    assert args[4] == "dns_tunneling"
    assert args[5] == {"protocol": "udp", "dst_port": "53", "dst_prefix": "203.0.113.53/32"}


def test_amplifier_triggers_mitigation_with_src_port_match(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    insert_flow(conn, "177.86.19.94", "198.51.100.1", 33000, protocol=17, bytes_=10_000_000, src_port=53)
    insert_flow(conn, "177.86.19.94", "198.51.100.2", 33001, protocol=17, bytes_=10_000_000, src_port=53)
    detector.detect_amplifier(conn, WINDOW_S, ports=[53], min_bps=1, whitelist=set(),
                               mitigation_ctx={"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"})
    assert len(calls) == 1
    args, _ = calls[0]
    assert args[4] == "amplifier_hosted"
    assert args[5] == {"protocol": "udp", "src_port": "53"}


def test_scan_horizontal_triggers_mitigation_with_dst_port_match(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    for i in range(5):
        insert_flow(conn, "177.86.19.95", f"45.10.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=5, whitelist=set(),
                                     mitigation_ctx={"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"})
    assert len(calls) == 1
    args, _ = calls[0]
    assert args[4] == "port_scan_horizontal"
    # recorte por porta escaneada + protocolo — não bloqueia/limita o cliente inteiro,
    # só o acesso àquela porta específica (ver detector.py:detect_scan_horizontal)
    assert args[5] == {"dst_port": "22", "protocol": "tcp"}


def test_scan_vertical_triggers_mitigation_with_dst_prefix_match(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    for port in range(5):
        insert_flow(conn, "177.86.19.96", "45.10.0.1", 1000 + port, protocol=6)
    detector.detect_scan_vertical(conn, WINDOW_S, threshold=5, whitelist=set(),
                                   mitigation_ctx={"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"})
    assert len(calls) == 1
    args, _ = calls[0]
    assert args[4] == "port_scan_vertical"
    # recorte pelo dst_ip vítima — não bloqueia/limita o cliente pra qualquer destino,
    # só o acesso àquela vítima específica (ver detector.py:detect_scan_vertical)
    assert args[5] == {"dst_prefix": "45.10.0.1/32"}


def test_off_action_does_not_call_trigger_async(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    feed = threat_feed.ThreatFeed(":memory-nao-existe:")
    feed._single_ips = {"198.51.100.99"}
    insert_flow(conn, "177.86.19.96", "198.51.100.99", 443, protocol=6)
    detector.detect_malicious_contact(conn, WINDOW_S, feed, whitelist=set(),
                                       mitigation_ctx={"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"})
    assert "malicious_contact" in signal_types(conn)
    assert not calls


# --- redispara mitigação em sinal contínuo sem proteção ativa (achado real de
# auditoria, 2026-07-04): flowguard.service reiniciar apaga a mitigação real
# sem avisar o ClientGuard; sem isso, um cliente que continua abusando com o
# MESMO sinal (nunca fecha) nunca era remitigado, porque apply_and_record só
# reforça uma mitigação "já ativa" e a mitigação de sinal já existente nunca
# rechamava trigger_async. ----------------------------------------------------

def test_continued_signal_retriggers_mitigation_when_none_is_active(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    ctx = {"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"}

    for i in range(5):
        insert_flow(conn, "177.86.19.97", f"45.11.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=5, whitelist=set(), mitigation_ctx=ctx)
    assert len(calls) == 1  # sinal novo -> dispara normalmente

    # cliente continua escaneando (mesmo sinal, ainda aberto) e NENHUMA mitigação
    # está de fato ativa (ex: foi apagada por fora) — precisa disparar de novo
    for i in range(5):
        insert_flow(conn, "177.86.19.97", f"45.12.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=5, whitelist=set(), mitigation_ctx=ctx)
    assert len(calls) == 2


def test_continued_signal_does_not_retrigger_when_mitigation_still_active(conn, monkeypatch):
    calls = []
    monkeypatch.setattr("flowspec_mitigation.trigger_async", lambda *a, **k: calls.append((a, k)))
    ctx = {"cfg": _mitigation_cfg(), "fg_socket_path": "/fake.sock"}

    for i in range(5):
        insert_flow(conn, "177.86.19.98", f"45.13.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=5, whitelist=set(), mitigation_ctx=ctx)
    assert len(calls) == 1

    # mitigação real está ativa (registrada no ClientGuard) -> não deve reforçar
    # via trigger_async de novo, mesmo com o sinal ainda aberto e ativo
    storage.insert_edge_mitigation(conn, "177.86.19.98", None, 3600, "auto",
                                    mechanism="flowspec", flowspec_rule_id=1)
    for i in range(5):
        insert_flow(conn, "177.86.19.98", f"45.14.{i}.1", 22, protocol=6)
    detector.detect_scan_horizontal(conn, WINDOW_S, threshold=5, whitelist=set(), mitigation_ctx=ctx)
    assert len(calls) == 1
