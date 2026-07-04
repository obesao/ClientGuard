"""Testa flowspec_mitigation — mocka control.send_command (nunca fala com o socket
do FlowGuard de verdade). Mesmo padrão de tests/test_edge_mitigation.py."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

import flowspec_mitigation as fm
import storage


def _wait_until(predicate, timeout_s=2.0, interval_s=0.01):
    """Espera uma condição virar verdadeira — usado só pra sincronizar com o
    trabalho disparado em thread própria por expire_due (fire-and-forget de
    verdade, sem essa espera o teste vira uma corrida com o mock)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condição não satisfeita dentro do timeout")


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


def test_apply_and_record_forwards_trigger_type_to_flowguard(conn):
    # pedido do usuário: aba Regras precisa saber se a regra no FlowGuard foi
    # automática ou manual — sem isso, flowspec_rules.trigger_type sempre caía
    # no default 'manual' de lá, mesmo pra mitigação automática do ClientGuard.
    cfg = _cfg()
    with patch("control.send_command", return_value={"ok": True, "rule_id": 1}) as mock:
        fm.apply_and_record(conn, None, "1.2.3.4", None, "port_scan_horizontal", None,
                             3600, "auto", cfg, "/fake.sock")
    payload = mock.call_args.args[1]
    assert payload["trigger_type"] == "auto"


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
    # expire_due dispara cada revert numa thread própria (achado de revisão: SSH
    # síncrono não pode bloquear o loop principal do daemon) — a contagem
    # retornada é "quantas estavam due", o processamento em si é assíncrono.
    flowspec_id = storage.insert_edge_mitigation(conn, "1.2.3.4", None, -10, "auto",
                                                   mechanism="flowspec", flowspec_rule_id=1)
    ssh_id = storage.insert_edge_mitigation(conn, "5.6.7.8", None, -10, "auto", mechanism="ssh")
    with patch("control.send_command", return_value={"ok": True}) as mock:
        count = fm.expire_due(conn, None, "/fake.sock")
        assert count == 1
        _wait_until(lambda: mock.call_count >= 1)
    mock.assert_called_once()
    assert storage.get_edge_mitigation(conn, flowspec_id)["status"] == "reverted"
    assert storage.get_edge_mitigation(conn, ssh_id)["status"] == "active"  # não é problema deste módulo


# --- reconciliação com o FlowGuard (achado real de auditoria, 2026-07-04) ---
# flowguard.service reiniciar retira TODAS as regras ativas (BgpManager.
# withdraw_all) sem avisar o ClientGuard — reconcile_with_flowguard existe pra
# achar e corrigir esse gap a cada ciclo, em vez de esperar até 6h (default_ttl_s).

def test_reconcile_returns_zero_and_skips_query_when_nothing_active(conn):
    with patch("control.send_command") as mock:
        count = fm.reconcile_with_flowguard(conn, None, "/fake.sock")
    assert count == 0
    assert not mock.called  # nem consulta o FlowGuard se não há nada local pra checar


def test_reconcile_reverts_mitigation_whose_flowguard_rule_is_gone(conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=99)

    def fake_send(sock_path, payload, *args, **kwargs):
        if payload.get("cmd") == "rules":
            return {"ok": True, "rules": []}  # rule_id 99 não está mais ativo no FlowGuard
        if payload.get("cmd") == "flowspec_del":
            return {"ok": False, "error": "regra já está inativa"}
        raise AssertionError(f"comando inesperado: {payload}")

    with patch("control.send_command", side_effect=fake_send):
        count = fm.reconcile_with_flowguard(conn, None, "/fake.sock")
        assert count == 1
        _wait_until(lambda: storage.get_edge_mitigation(conn, mitigation_id)["status"] == "reverted")
    row = storage.get_edge_mitigation(conn, mitigation_id)
    assert row["status"] == "reverted"
    assert row["error"] is None  # "já inativa" conta como sucesso, não falha (ver revert_and_record)


def test_reconcile_leaves_mitigation_alone_when_flowguard_rule_still_active(conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=99)
    with patch("control.send_command", return_value={"ok": True, "rules": [{"id": 99}]}) as mock:
        count = fm.reconcile_with_flowguard(conn, None, "/fake.sock")
    assert count == 0
    mock.assert_called_once()  # só a consulta "rules" — nenhum flowspec_del disparado
    assert storage.get_edge_mitigation(conn, mitigation_id)["status"] == "active"


def test_reconcile_ignores_ssh_mechanism_mitigations(conn):
    ssh_id = storage.insert_edge_mitigation(conn, "5.6.7.8", None, 3600, "auto", mechanism="ssh")
    with patch("control.send_command") as mock:
        count = fm.reconcile_with_flowguard(conn, None, "/fake.sock")
    assert count == 0
    assert not mock.called
    assert storage.get_edge_mitigation(conn, ssh_id)["status"] == "active"


def test_reconcile_handles_flowguard_query_failure_without_reverting(conn):
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=99)
    with patch("control.send_command", return_value={"ok": False, "error": "timeout"}):
        count = fm.reconcile_with_flowguard(conn, None, "/fake.sock")
    assert count == 0
    assert storage.get_edge_mitigation(conn, mitigation_id)["status"] == "active"


# --- guarda de "já em andamento" no trigger_async (achado real de produção,
# 2026-07-04): sob carga, o tempo entre "FlowSpec anunciado" e a linha gravada em
# edge_mitigations pode passar de um ciclo — sem essa guarda, o redisparo em sinal
# contínuo via get_active_edge_mitigation (que ainda não achava nada) disparava
# OUTRO apply_and_record pro MESMO src_ip, criando regras FlowSpec duplicadas.

def test_trigger_async_does_not_duplicate_in_flight_apply_for_same_src_ip(conn):
    import threading
    release = threading.Event()
    calls = []

    def slow_apply(*args, **kwargs):
        calls.append(args[2])  # src_ip
        release.wait(timeout=2.0)
        return {"ok": True}

    with patch("flowspec_mitigation.apply_and_record", side_effect=slow_apply):
        fm.trigger_async(conn, None, "1.2.3.4", 1, "port_scan_horizontal", None,
                          _cfg(), "/fake.sock")
        _wait_until(lambda: len(calls) == 1)
        # 2ª chamada pro MESMO src_ip enquanto a 1ª ainda está "rodando" (presa em
        # release.wait) -> deve ser ignorada, não empilhar outra apply_and_record
        fm.trigger_async(conn, None, "1.2.3.4", 2, "port_scan_horizontal", None,
                          _cfg(), "/fake.sock")
        release.set()
        _wait_until(lambda: "1.2.3.4" not in fm._applying_src_ips)
    assert len(calls) == 1


def test_trigger_async_allows_different_src_ips_concurrently(conn):
    calls = []
    with patch("flowspec_mitigation.apply_and_record",
               side_effect=lambda *a, **k: calls.append(a[2]) or {"ok": True}):
        fm.trigger_async(conn, None, "1.2.3.4", 1, "port_scan_horizontal", None, _cfg(), "/fake.sock")
        fm.trigger_async(conn, None, "5.6.7.8", 2, "port_scan_horizontal", None, _cfg(), "/fake.sock")
        _wait_until(lambda: len(calls) == 2)
    assert sorted(calls) == ["1.2.3.4", "5.6.7.8"]


def test_trigger_async_allows_retry_after_previous_apply_finished(conn):
    calls = []
    with patch("flowspec_mitigation.apply_and_record",
               side_effect=lambda *a, **k: calls.append(a[2]) or {"ok": True}):
        fm.trigger_async(conn, None, "1.2.3.4", 1, "port_scan_horizontal", None, _cfg(), "/fake.sock")
        _wait_until(lambda: len(calls) == 1)
        _wait_until(lambda: "1.2.3.4" not in fm._applying_src_ips)
        fm.trigger_async(conn, None, "1.2.3.4", 2, "port_scan_horizontal", None, _cfg(), "/fake.sock")
        _wait_until(lambda: len(calls) == 2)
    assert calls == ["1.2.3.4", "1.2.3.4"]


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
        result = fm.remove_pbr_bypass(184, "100.64.1.2", cfg, flowguard_path)
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


# --- correções de revisão 2026-07-03: falha de push/remove não pode ficar muda ---

def test_apply_and_record_marks_failed_when_pbr_bypass_push_fails(tmp_path, conn):
    # achado real: antes disso, uma falha no SSH da exceção de PBR era só logada —
    # a mitigação ficava "active" mesmo sem proteção nenhuma de verdade.
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    with patch("control.send_command", return_value={"ok": True, "rule_id": 184}), \
         patch("netmiko.ConnectHandler", side_effect=OSError("conexão recusada")):
        result = fm.apply_and_record(conn, None, "100.64.1.2", None, "port_scan_horizontal",
                                      {"dst_port": "25252", "protocol": "udp"}, 3600, "auto", cfg,
                                      "/fake.sock", flowguard_path=flowguard_path)
    assert result["ok"] is False
    assert "PBR" in result["error"]
    row = storage.get_edge_mitigation(conn, result["id"])
    assert row["status"] == "failed"
    assert row["error"] is not None


def test_apply_and_record_skips_pbr_bypass_for_rate_limit_action(tmp_path, conn):
    # achado real: aplicar o bypass também em rate_limit tira a tradução NAT de um
    # fluxo que deveria só ser desacelerado, não perder conectividade por completo.
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    with patch("control.send_command", return_value={"ok": True, "rule_id": 184}), \
         patch("netmiko.ConnectHandler") as mock_handler:
        result = fm.apply_and_record(conn, None, "100.64.1.2", None, "spam_bot", None,
                                      3600, "auto", cfg, "/fake.sock", flowguard_path=flowguard_path)
    assert result["ok"] is True
    mock_handler.assert_not_called()  # rate_limit nunca deveria abrir SSH nenhum


def test_push_pbr_bypass_skips_rate_limit_action_directly(tmp_path):
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    with patch("netmiko.ConnectHandler") as mock_handler:
        result = fm.push_pbr_bypass({"src_prefix": "100.64.1.2/32", "action": "rate-limit:200000"},
                                     184, cfg, flowguard_path)
    assert result == {"ok": True, "skipped": "pbr_bypass_only_for_discard"}
    mock_handler.assert_not_called()


def test_revert_and_record_does_not_remove_bypass_when_flowspec_del_really_fails(tmp_path, conn):
    # achado real: antes disso, a exceção de PBR era removida mesmo quando o
    # flowspec_del falhava de verdade (não só a corrida "já está inativa") — a
    # regra FlowSpec continuava ativa protegendo, mas o bypass sumia, e o tráfego
    # voltava a ser redirecionado pro A10 antes do FlowSpec (ainda ativo) agir.
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=184)
    with patch("control.send_command", return_value={"ok": False, "error": "timeout ao falar com o daemon"}), \
         patch("netmiko.ConnectHandler") as mock_handler:
        result = fm.revert_and_record(conn, None, mitigation_id, "/fake.sock", cfg, flowguard_path)
    assert result["ok"] is False
    mock_handler.assert_not_called()  # bypass NÃO deve ser tocado — FlowSpec ainda ativo
    row = storage.get_edge_mitigation(conn, mitigation_id)
    assert row["status"] == "failed"


def test_revert_and_record_reports_bypass_removal_failure(tmp_path, conn):
    # achado real: o retorno de remove_pbr_bypass era descartado — se o SSH falhar
    # na hora de tirar a exceção, a entrada fica órfã na ACL pra sempre, sem
    # nenhum sinal disso em lugar nenhum.
    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    mitigation_id = storage.insert_edge_mitigation(conn, "100.64.1.2", None, 3600, "auto",
                                                     mechanism="flowspec", flowspec_rule_id=184)
    with patch("control.send_command", return_value={"ok": True}), \
         patch("netmiko.ConnectHandler", side_effect=OSError("conexão recusada")):
        result = fm.revert_and_record(conn, None, mitigation_id, "/fake.sock", cfg, flowguard_path)
    assert result["ok"] is False
    assert result.get("flowspec_reverted") is True
    row = storage.get_edge_mitigation(conn, mitigation_id)
    assert row["status"] == "failed"
    assert "PBR" in row["error"]


def test_pbr_bypass_actions_are_serialized_by_a_lock(tmp_path):
    # achado real: duas mitigações no mesmo ciclo abriam sessões SSH concorrentes
    # pro mesmo equipamento — sem lock, dois commits podem colidir no modelo de
    # candidate-config do VRP V8. Prova que _pbr_bypass_ssh respeita o lock global:
    # com o lock já preso por fora, uma chamada em thread separada tem que
    # bloquear até o lock ser liberado.
    import threading

    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"

    started = threading.Event()
    finished = threading.Event()

    def _run():
        started.set()
        with patch("netmiko.ConnectHandler", return_value=fake_conn):
            fm.push_pbr_bypass({"src_prefix": "100.64.1.2/32", "action": "discard"}, 1, cfg, flowguard_path)
        finished.set()

    assert fm._PBR_BYPASS_LOCK.acquire(blocking=False)
    try:
        t = threading.Thread(target=_run)
        t.start()
        assert started.wait(timeout=1.0)
        # a thread começou mas não pode ter terminado — está bloqueada no lock
        assert not finished.wait(timeout=0.2)
    finally:
        fm._PBR_BYPASS_LOCK.release()
    t.join(timeout=2.0)
    assert finished.is_set()


def test_push_pbr_bypass_writes_audit_log(tmp_path, monkeypatch):
    # achado real: _pbr_bypass_ssh chamava _run_commands direto, pulando
    # apply_block/revert_block — as únicas funções que gravam em edge-audit.jsonl.
    # Isso deixava toda ação de bypass invisível na trilha de auditoria SSH do
    # sistema. Agora _pbr_bypass_ssh grava no mesmo log via edge_mitigation._audit.
    import edge_mitigation

    flowguard_path = _write_warmode_yaml(tmp_path)
    cfg = _cfg(pbr_bypass={"enabled": True, "warmode_device": "HUAWEI-PPPOE-222",
                            "acl_number": 3001, "rule_id_base": 50000})
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(edge_mitigation, "AUDIT_LOG_PATH", str(audit_path))
    fake_conn = MagicMock()
    fake_conn.send_config_set.return_value = "ok"
    with patch("netmiko.ConnectHandler", return_value=fake_conn):
        fm.push_pbr_bypass({"src_prefix": "100.64.1.2/32", "action": "discard"}, 184, cfg, flowguard_path)
    assert audit_path.exists()
    content = audit_path.read_text(encoding="utf-8")
    assert "pbr_bypass_apply" in content
    assert "100.64.1.2/32" in content
