"""Testa flowspec_mitigation — mocka control.send_command (nunca fala com o socket
do FlowGuard de verdade). Mesmo padrão de tests/test_edge_mitigation.py."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

import flowspec_mitigation as fm
import storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:", check_same_thread=False)
    yield c
    c.close()


def _cfg(**overrides):
    cfg = fm.load_config("/caminho/que/nao/existe.yaml")  # cai no DEFAULT_CONFIG
    cfg.update(overrides)
    return cfg


def _write_warmode_yaml(tmp_path, device_name="HUAWEI-PPPOE-222"):
    flowguard_dir = tmp_path / "flowguard"
    flowguard_dir.mkdir()
    (flowguard_dir / "warmode.yaml").write_text(
        f"devices:\n  - name: \"{device_name}\"\n    host: 10.0.0.1\n    port: 22\n"
        "    device_type: huawei_vrpv8\n    username: poxnet\n    password: secret\n"
        "    enable_mode: false\n",
        encoding="utf-8",
    )
    return str(flowguard_dir)


# --- load_config / save_auto_mitigate -------------------------------------

def test_load_config_missing_file_returns_defaults(tmp_path):
    cfg = fm.load_config(str(tmp_path / "nao-existe.yaml"))
    assert cfg["auto_mitigate"]["port_scan_horizontal"] == "discard"
    assert cfg["auto_mitigate"]["malicious_contact"] == "off"


def test_save_auto_mitigate_roundtrip(tmp_path):
    path = tmp_path / "flowspec_mitigation.yaml"
    updated = fm.save_auto_mitigate({"malicious_contact": "discard"}, path=str(path))
    assert updated["auto_mitigate"]["malicious_contact"] == "discard"
    reloaded = fm.load_config(str(path))
    assert reloaded["auto_mitigate"]["malicious_contact"] == "discard"
    assert reloaded["auto_mitigate"]["spam_bot"] == "rate_limit"  # não tocado


def test_save_auto_mitigate_unknown_detector_raises(tmp_path):
    path = tmp_path / "flowspec_mitigation.yaml"
    with pytest.raises(ValueError):
        fm.save_auto_mitigate({"nao_existe": "discard"}, path=str(path))
    assert not path.exists()


def test_save_auto_mitigate_invalid_action_raises(tmp_path):
    path = tmp_path / "flowspec_mitigation.yaml"
    with pytest.raises(ValueError):
        fm.save_auto_mitigate({"spam_bot": "banana"}, path=str(path))
    assert not path.exists()


def test_save_auto_mitigate_updates_ttl(tmp_path):
    path = tmp_path / "flowspec_mitigation.yaml"
    updated = fm.save_auto_mitigate({}, default_ttl_s=999, path=str(path))
    assert updated["default_ttl_s"] == 999


# --- build_rule -------------------------------------------------------------

def test_build_rule_discard_without_match_has_no_protocol_or_port(conn):
    cfg = _cfg()
    rule = fm.build_rule("port_scan_horizontal", "1.2.3.4", None, conn, cfg)
    assert rule == {"src_prefix": "1.2.3.4/32", "action": "discard", "label": "ClientGuard auto: port_scan_horizontal"}


def test_build_rule_discard_applies_mitigation_match(conn):
    """Bug real corrigido 2026-07-03: o branch 'discard' descartava mitigation_match
    silenciosamente — port_scan_horizontal/vertical (discard, com match por dst_port/
    dst_prefix) saíam como bloqueio do cliente inteiro em vez do recorte esperado."""
    cfg = _cfg()
    rule = fm.build_rule("port_scan_horizontal", "1.2.3.4", {"dst_port": "22", "protocol": "tcp"}, conn, cfg)
    assert rule == {
        "src_prefix": "1.2.3.4/32", "dst_port": "22", "protocol": "tcp",
        "action": "discard", "label": "ClientGuard auto: port_scan_horizontal",
    }
    rule = fm.build_rule("port_scan_vertical", "1.2.3.4", {"dst_prefix": "45.10.0.1/32"}, conn, cfg)
    assert rule == {
        "src_prefix": "1.2.3.4/32", "dst_prefix": "45.10.0.1/32",
        "action": "discard", "label": "ClientGuard auto: port_scan_vertical",
    }


def test_build_rule_off_returns_none(conn):
    cfg = _cfg()
    assert fm.build_rule("malicious_contact", "1.2.3.4", None, conn, cfg) is None
    assert fm.build_rule("coordinated_destination", "1.2.3.4", None, conn, cfg) is None


def test_build_rule_rate_limit_without_baseline_uses_floor(conn):
    cfg = _cfg()
    rule = fm.build_rule("dns_tunneling", "1.2.3.4", {"protocol": "udp", "dst_port": "53"}, conn, cfg)
    assert rule["action"] == f"rate-limit:{cfg['dns_rate_limit_floor_bps']}"
    assert rule["protocol"] == "udp"
    assert rule["dst_port"] == "53"


def test_build_rule_rate_limit_with_trusted_baseline_scales_above_floor(conn):
    cfg = _cfg()
    now = int(time.time())
    conn.execute(
        "INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at) "
        "VALUES (?, 'dns_query', 1000000, 1600000000, 200, ?)", ("1.2.3.4", now),
    )
    conn.commit()
    rule = fm.build_rule("dns_tunneling", "1.2.3.4", {"protocol": "udp", "dst_port": "53"}, conn, cfg,
                          baseline_min_samples=120)
    # mean(1_000_000) + sigma(3)*std(40_000) = 1_120_000, bem acima do piso (200_000)
    assert rule["action"] == "rate-limit:1120000"


def test_build_rule_rate_limit_baseline_below_min_samples_uses_floor(conn):
    cfg = _cfg()
    now = int(time.time())
    conn.execute(
        "INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at) "
        "VALUES (?, 'dns_query', 5000000, 0, 5, ?)", ("1.2.3.4", now),
    )
    conn.commit()
    rule = fm.build_rule("dns_tunneling", "1.2.3.4", {"protocol": "udp", "dst_port": "53"}, conn, cfg,
                          baseline_min_samples=120)
    assert rule["action"] == f"rate-limit:{cfg['dns_rate_limit_floor_bps']}"


def test_build_rule_spam_bot_uses_static_rate_no_baseline_needed(conn):
    cfg = _cfg()
    rule = fm.build_rule("spam_bot", "1.2.3.4", None, conn, cfg)
    assert rule["action"] == f"rate-limit:{cfg['spam_rate_limit_bps']}"


def test_build_rule_amplifier_uses_port_specific_traffic_class(conn):
    cfg = _cfg()
    now = int(time.time())
    conn.execute(
        "INSERT INTO client_traffic_baseline (src_ip, traffic_class, bps_mean, bps_var, samples, updated_at) "
        "VALUES (?, 'amplifier:123', 500000, 0, 200, ?)", ("1.2.3.4", now),
    )
    conn.commit()
    rule = fm.build_rule("amplifier_hosted", "1.2.3.4", {"protocol": "udp", "src_port": "123"}, conn, cfg,
                          baseline_min_samples=120)
    assert rule["action"] == "rate-limit:500000"
    assert rule["src_port"] == "123"


# --- apply_and_record / prioridade / orçamento / revert / expire -----------

def test_apply_and_record_calls_flowspec_add_and_records_row(conn):
    cfg = _cfg()
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}) as mock:
        result = fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None,
                                      3600, "auto", cfg, "/fake.sock")
    assert result["ok"] is True
    mock.assert_called_once()
    payload = mock.call_args.args[1]
    assert payload["cmd"] == "flowspec_add"
    assert payload["origin"] == "clientguard"
    row = storage.get_active_edge_mitigation(conn, "1.2.3.4")
    assert row["mechanism"] == "flowspec"
    assert row["flowspec_rule_id"] == 1
    assert row["rate_limit_bps"] is None


def test_apply_and_record_off_action_skips_without_calling_socket(conn):
    cfg = _cfg()
    with patch("control.send_command") as mock:
        result = fm.apply_and_record(conn, None, "1.2.3.4", None, "malicious_contact", None,
                                      3600, "auto", cfg, "/fake.sock")
    assert result == {"ok": True, "skipped": "off"}
    assert not mock.called


def test_apply_and_record_idempotent_same_severity_extends_ttl(conn):
    cfg = _cfg()
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}) as mock:
        fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None, 3600, "auto", cfg, "/fake.sock")
        result = fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_vertical", None, 7200, "auto", cfg, "/fake.sock")
    assert result["already_active"] is True
    mock.assert_called_once()  # segunda chamada não anuncia de novo


def test_apply_and_record_more_severe_replaces_existing(conn):
    cfg = _cfg()
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}):
        fm.apply_and_record(conn, None, "1.2.3.4", None, "dns_tunneling", {"protocol": "udp", "dst_port": "53"},
                             3600, "auto", cfg, "/fake.sock")
    with patch("control.send_command", side_effect=[{"ok": True}, {"ok": True, "rule_id": 2}]) as mock:
        result = fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None,
                                      3600, "auto", cfg, "/fake.sock")
    assert result["ok"] is True
    assert mock.call_args_list[0].args[1] == {"cmd": "flowspec_del", "rule_id": 1}
    row = storage.get_active_edge_mitigation(conn, "1.2.3.4")
    assert row["flowspec_rule_id"] == 2
    assert row["rate_limit_bps"] is None  # discard, substituiu o rate-limit anterior


def test_apply_and_record_does_not_duplicate_active_ssh_mitigation(conn):
    cfg = _cfg()
    storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto", mechanism="ssh")
    with patch("control.send_command") as mock:
        result = fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None,
                                      3600, "auto", cfg, "/fake.sock")
    assert result == {"ok": True, "skipped": "ssh_active"}
    assert not mock.called


def test_apply_and_record_respects_rule_budget(conn):
    cfg = _cfg(max_active_rules=1)
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}):
        fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None, 3600, "auto", cfg, "/fake.sock")
    with patch("control.send_command") as mock:
        result = fm.apply_and_record(conn, None, "5.6.7.8", None, "port_scan_horizontal", None,
                                      3600, "auto", cfg, "/fake.sock")
    assert result["ok"] is False
    assert "orçamento" in result["error"]
    assert not mock.called


def test_revert_and_record_marks_reverted(conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=42)
    with patch("control.send_command", return_value={"ok": True}) as mock:
        result = fm.revert_and_record(conn, None, mitigation_id, "/fake.sock")
    assert result["ok"] is True
    assert mock.call_args.args[1] == {"cmd": "flowspec_del", "rule_id": 42}
    assert storage.get_edge_mitigation(conn, mitigation_id)["status"] == "reverted"


def test_revert_and_record_unknown_id(conn):
    result = fm.revert_and_record(conn, None, 999, "/fake.sock")
    assert result["ok"] is False


def test_revert_and_record_already_inactive_counts_as_reverted(conn):
    # corrida legítima: o TTL do lado do FlowGuard já retirou a regra sozinho antes
    # do ClientGuard chamar flowspec_del — resultado desejado já foi alcançado,
    # não é falha de verdade (achado real, ver docstring de revert_and_record)
    mitigation_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=42)
    with patch("control.send_command", return_value={"ok": False, "error": "regra já está inativa"}):
        result = fm.revert_and_record(conn, None, mitigation_id, "/fake.sock")
    assert result["ok"] is True
    row = storage.get_edge_mitigation(conn, mitigation_id)
    assert row["status"] == "reverted"
    assert row["error"] is None


def test_expire_due_only_processes_flowspec_mechanism(conn):
    flowspec_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, -10, "auto",
                                                   mechanism="flowspec", flowspec_rule_id=1)
    ssh_id = storage.insert_edge_mitigation(conn, "5.6.7.8", None, -10, "auto", mechanism="ssh")
    with patch("control.send_command", return_value={"ok": True}) as mock:
        count = fm.expire_due(conn, None, "/fake.sock")
    assert count == 1
    mock.assert_called_once()
    assert storage.get_edge_mitigation(conn, flowspec_id)["status"] == "reverted"
    assert storage.get_edge_mitigation(conn, ssh_id)["status"] == "active"  # não é problema deste módulo


# --- bypass do CGNAT/PBR (achado real 2026-07-03) --------------------------

def test_cidr_to_huawei_host():
    assert fm._cidr_to_huawei("1.2.3.4/32") == ("1.2.3.4", "0")


def test_cidr_to_huawei_network():
    assert fm._cidr_to_huawei("1.2.3.0/24") == ("1.2.3.0", "0.0.0.255")


def test_bypass_rule_clause_ip_only():
    rule = {"src_prefix": "100.64.1.2/32", "action": "discard"}
    assert fm._bypass_rule_clause(rule, 50001) == "rule 50001 permit ip source 100.64.1.2 0"


def test_bypass_rule_clause_mirrors_destination_and_port_never_wider():
    # mesmo escopo exato da regra FlowSpec — nunca mais amplo, senão isenta do
    # CGNAT tráfego do cliente que a mitigação nunca mirou (pedido explícito do
    # usuário: cliente tem que continuar navegando).
    rule = {"src_prefix": "100.64.1.2/32", "dst_prefix": "177.86.16.9/32",
            "protocol": "udp", "dst_port": "25252", "action": "discard"}
    clause = fm._bypass_rule_clause(rule, 50002)
    assert clause == ("rule 50002 permit udp source 100.64.1.2 0 "
                       "destination 177.86.16.9 0 destination-port eq 25252")


def test_bypass_rule_clause_dst_port_ignored_without_tcp_udp():
    rule = {"src_prefix": "100.64.1.2/32", "dst_port": "53", "action": "discard"}
    # sem protocol tcp/udp explícito, "destination-port" não é uma cláusula válida
    # de ACL "ip" — melhor omitir do que gerar um comando que o roteador rejeita
    assert "destination-port" not in fm._bypass_rule_clause(rule, 50003)


def test_push_pbr_bypass_disabled_by_default_skips_ssh(tmp_path):
    cfg = _cfg()
    assert cfg["pbr_bypass"]["enabled"] is False
    with patch("netmiko.ConnectHandler") as mock_handler:
        result = fm.push_pbr_bypass({"src_prefix": "100.64.1.2/32", "action": "discard"}, 1,
                                     cfg, str(tmp_path / "flowguard"))
    assert result == {"ok": True, "skipped": "pbr_bypass_disabled"}
    mock_handler.assert_not_called()


def test_push_pbr_bypass_enabled_sends_expected_commands(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        result = fm.push_pbr_bypass(
            {"src_prefix": "100.64.1.2/32", "dst_prefix": "177.86.16.9/32", "action": "discard"},
            184, cfg, flowguard_path,
        )
    assert result["ok"] is True
    mock_handler.assert_called_once()
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == [
        "acl number 3001",
        "rule 50184 permit ip source 100.64.1.2 0 destination 177.86.16.9 0",
        "quit", "commit",
    ]


def test_remove_pbr_bypass_enabled_sends_undo(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        result = fm.remove_pbr_bypass(184, cfg, flowguard_path)
    assert result["ok"] is True
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == ["acl number 3001", "undo rule 50184", "quit", "commit"]


def test_apply_and_record_pushes_pbr_bypass_when_enabled(tmp_path, conn):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("control.send_command", return_value={"ok": True, "rule_id": 184}), \
         patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        result = fm.apply_and_record(conn, None, "100.64.1.2", None, "port_scan_horizontal",
                                      {"dst_port": "25252", "protocol": "udp"}, 3600, "auto", cfg,
                                      "/fake.sock", flowguard_path=flowguard_path)
    assert result["ok"] is True
    mock_handler.assert_called_once()
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == [
        "acl number 3001",
        "rule 50184 permit udp source 100.64.1.2 0 destination-port eq 25252",
        "quit", "commit",
    ]


def test_apply_and_record_does_not_touch_ssh_when_pbr_bypass_disabled(conn):
    cfg = _cfg()  # pbr_bypass.enabled = False (default)
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}), \
         patch("netmiko.ConnectHandler") as mock_handler:
        fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None,
                             3600, "auto", cfg, "/fake.sock")
    mock_handler.assert_not_called()


def test_revert_and_record_removes_pbr_bypass_when_enabled(tmp_path, conn):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=184)
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("control.send_command", return_value={"ok": True}), \
         patch("netmiko.ConnectHandler", return_value=fake_conn) as mock_handler:
        result = fm.revert_and_record(conn, None, mitigation_id, "/fake.sock", cfg, flowguard_path)
    assert result["ok"] is True
    mock_handler.assert_called_once()
    sent = fake_conn.send_config_set.call_args[0][0]
    assert sent == ["acl number 3001", "undo rule 50184", "quit", "commit"]


def test_revert_and_record_skips_pbr_bypass_when_cfg_not_passed(conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=184)
    with patch("control.send_command", return_value={"ok": True}), \
         patch("netmiko.ConnectHandler") as mock_handler:
        fm.revert_and_record(conn, None, mitigation_id, "/fake.sock")  # sem cfg (compat)
    mock_handler.assert_not_called()
